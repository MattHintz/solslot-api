"""Actual final HTTP ceremony, standard signatures and native dispatch.

Release/security/recovery certificates and all keys are explicit synthetic
fixtures; these tests do not certify a live deployment or recovery drill.
"""
from pathlib import Path
from copy import deepcopy
from types import SimpleNamespace
from dataclasses import replace
from hashlib import sha256
import time
import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from eth_account import Account
from eth_account.messages import encode_typed_data
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import Coin,G2Element,SpendBundle
from chia_rs.sized_ints import uint64
from solslot_api.config import get_settings
from solslot_api.generation_launch import (LaunchCertificate,GenerationLaunchStore,runtime_source_hash,
    GenerationLaunchObserver,prepare_launch_review,prepare_launch_operation,saved_launch)
from solslot_api.generation_genesis_core import GenerationLaunchArtifact
from solslot_api.generation_preparation_store import GenerationPreparationStore
from solslot_api.generation_operations import GenerationOperationJournal,reconcile_saved_operation
from solslot_api.generation_launch_routes import router
import solslot_api.generation_launch_routes as routes
from solslot_api.launch_control import LaunchSession,require_launch_session
from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.generation_storage import generation_path
from tests.test_generation_genesis_core import core
from tests.test_generation_preparation import manifest,signatures,b32
from tests.test_generation_recipient_execution import Node

BASE='/admin/launch/generation/final'

@pytest_asyncio.fixture
async def final(core,tmp_path,monkeypatch):
    # Synthetic receipt tests use a controlled disk probe; the live deployment
    # still checks real headroom, and the explicit disk attack below overrides it.
    monkeypatch.setattr('solslot_api.generation_launch.shutil.disk_usage',
        lambda _:SimpleNamespace(total=100*1024**3,free=20*1024**3))
    c=core;c.sim.pass_time(uint64(int(time.time())-int(c.sim.timestamp)));await c.sim.farm_block();now=int(c.sim.timestamp)-1
    _,accounts=manifest()
    prep=GenerationPreparationStore(str(tmp_path/'prep.db'),c.prep)
    for receipt in c.evidence.recipients:prep.record_confirmation(receipt,now)
    for slot,sig in signatures(c.prep,accounts).items():prep.acknowledge(slot,sig,now)
    raw=c.artifact.model_dump(mode='json',by_alias=True);raw['purpose']='GENERATION_LAUNCH_PREPARATION'
    artifact=GenerationLaunchArtifact.model_validate(raw)
    certificate=LaunchCertificate.model_validate(dict(generationId=c.prep.generation_id,preparationManifest=c.prep.manifest_hash,
        artifactHash=artifact.artifact_hash,sourceCommits=c.prep.source_commits,runtimeSourceHash=runtime_source_hash(),
        releaseManifestHash=b32(94),actionEnvelope='AE-SOLSLOT-SYNTHETIC-LAUNCH',securityReviewHash=b32(93),
        backupReceiptHash=b32(92),restoreReceiptHash=b32(91),verifiedAt=now,expiresAt=now+86400,
        maximumFeeMojos=100,minimumFreeBytes=5*1024**3))
    store=GenerationLaunchStore(str(tmp_path/'launch.db'),prep,artifact,certificate,trusted_certificate_hash=certificate.digest)
    journal=GenerationOperationJournal(str(tmp_path/'ops.db'),c.prep.generation_id)
    c.faucet.bind_generation_preparation(c.prep,trusted_preparation_hash=c.prep.manifest_hash)
    c.faucet.bind_generation_launch(store);c.faucet.add_coin_reservation_source(journal.reserved_input_coin_ids)
    # A real extra owned fee coin; none of the eight reserved parents is fee funding.
    acs=Program.to(1)
    origin=next(r.coin for r in await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent)
    fee=make_spend(origin,acs,Program.to([[51,c.faucet.address_puzzle_hash,100000],[51,acs.get_tree_hash(),int(origin.amount)-100000]]))
    assert await c.client.push_tx(SpendBundle([fee],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    node=Node(c.client)
    funding=ProtocolFundingStore(generation_path(str(tmp_path/'fees.db'),c.prep.generation_id))
    sender=ProtocolBundleSubmitter(provider=node,faucet=c.faucet,funding_store=funding,
        policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,maximum_mojos=100,maximum_funding_coin_mojos=100000,
            native_admission_enabled=True))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=c.prep.generation_id,
        generation_execution_enabled=True,generation_launch_enabled=True)
    session=LaunchSession('synthetic',1,c.prep.administrators[0].wallet,False,9999999999,c.prep.generation_id)
    app=FastAPI();app.include_router(router)
    app.state.generation_launch=store;app.state.generation_operations=journal;app.state.protocol_submitter=sender
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[require_launch_session]=lambda:session
    p=SimpleNamespace(c=c,now=now,store=store,journal=journal,sender=sender,node=node,settings=settings,
        session=session,app=app,accounts=accounts,funding=funding)
    monkeypatch.setattr(routes,'time',SimpleNamespace(time=lambda:p.now))
    yield p
    funding.close()

async def approve(p,client,review,slot):
    session=replace(p.session,slot=slot,wallet=p.c.prep.administrators[slot-1].wallet)
    p.app.dependency_overrides[require_launch_session]=lambda:session
    body={'generationId':review['generationId'],'reviewId':review['reviewId']}
    response=await client.post(BASE+'/consent/prepare',json=body);assert response.status_code==200,response.text
    typed=response.json()['typedData']
    sig='0x'+Account.sign_message(encode_typed_data(full_message=typed),p.accounts[slot-1].key).signature.hex()
    response=await client.post(BASE+'/consent',json={**body,'signature':sig});assert response.status_code==200,response.text
    p.app.dependency_overrides[require_launch_session]=lambda:p.session
    return response.json()

@pytest.mark.asyncio
async def test_final_ui_native_launch_lost_response_restart_exact_grants_and_cached_status(final):
    p=final
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        assert (await client.get(BASE)).json()['nextAction']=='REVIEW_FINAL_LAUNCH'
        assert p.node.pushes==0 and p.node.selections==0
        response=await client.post(BASE+'/review');assert response.status_code==200,response.text
        r=response.json()['review']
        if __import__('os').environ.get('SOLSLOT_WRITE_TEST_FIXTURE')=='1':
            (Path('../admin/src/app/utils/generation-final-launch.fixture.json')).write_text(__import__('json').dumps(response.json(),indent=2)+'\n')
        assert len(response.content)<20000
        assert not r['launchComplete'] and r['expiresAt']-r['issuedAt']==86400
        assert r['supply']==dict(total=1000000,distributed=30000,reserve=970000,quorum=15000)
        body={'generationId':r['generationId'],'reviewId':r['reviewId']}
        assert (await client.post(BASE+'/review')).json()['review']==r
        assert (await client.post(BASE+'/prepare',json=body)).status_code==409
        await approve(p,client,r,1)
        assert (await client.post(BASE+'/prepare',json=body)).status_code==409
        status=await approve(p,client,r,2);assert status['nextAction']=='PREPARE_EXACT_LAUNCH'
        responses=await __import__('asyncio').gather(*(client.post(BASE+'/prepare',json=body) for _ in range(3)))
        assert all(response.status_code==200 for response in responses),[response.text for response in responses]
        response=responses[0]
        assert (await client.get(BASE+'/'+r['reviewId']+'/read-anchor')).status_code==409
        op=response.json()['operation'];assert op['kind']=='INITIALIZE_GENERATION' and op['stage']=='PREPARED'
        assert (await client.post(BASE+'/prepare',json=body)).json()['operation']==op
        assert p.node.pushes==0 and p.node.selections==0
        submit={**body,'operationId':op['operationId'],'intentHash':op['intentHash'],'feeCapMojos':100}
        p.node.lose_response=True
        response=await client.post(BASE+'/submit',json=submit);assert response.status_code==503,response.text
        saved=p.journal.status(op['operationId']);assert saved['transactionId'] and p.node.pushes==1,(response.text,saved,p.node.selections,p.node.pushes)
        counts=(p.node.pushes,p.node.selections)
        p.journal=GenerationOperationJournal(p.journal.path,r['generationId']);p.app.state.generation_operations=p.journal
        response=await client.post(BASE+'/submit',json=submit);assert response.status_code==200,response.text
        assert counts==(p.node.pushes,p.node.selections)
        await p.c.sim.farm_block()
        await reconcile_saved_operation(p.journal,op['operationId'],p.node,clock=lambda:p.now)
        assert not (await client.get(BASE)).json()['review']['launchComplete']
        observer=GenerationLaunchObserver(p.store,p.journal,p.node,clock=lambda:p.now)
        await observer.run_once()
        status=(await client.get(BASE)).json();assert status['review']['launchComplete']
        assert status['operation']['transactionId']==saved['transactionId'] and status['nextAction']=='LAUNCH_CONFIRMED'
        download=await client.get(BASE+'/'+r['reviewId']+'/read-anchor')
        assert download.status_code==200 and download.headers['X-Content-SHA256']==r['readAnchorHash']
        assert '0x'+sha256(download.content).hexdigest()==r['readAnchorHash']
        for output in r['sgtOutputs']:
            row=await p.node.get_coin_record_by_name_primary(output['coinId'])
            assert row['coin']['amount']==output['amount'] and row['coin']['puzzle_hash']==output['puzzleHash']
        class Never:
            def __getattr__(self,name):raise AssertionError('cached/resumed launch called node or signer')
        p.sender.provider=Never();p.sender.faucet=Never()
        for _ in range(3):assert (await client.get(BASE)).json()==status
        assert (await client.post(BASE+'/prepare',json=body)).json()['operation']==status['operation']
        assert (await client.post(BASE+'/submit',json=submit)).json()==status

@pytest.mark.asyncio
@pytest.mark.parametrize('attack',['missing_ack','wrong_network','source','stale_certificate','disk','disabled','other_slot','fee'])
async def test_final_review_rejects_missing_live_gates_without_signing_or_selecting(final,attack,monkeypatch):
    p=final
    if attack=='missing_ack':
        with p.store.preparation_store.db() if hasattr(p.store.preparation_store,'db') else p.store.preparation_store._connect() as db:
            db.execute('DELETE FROM generation_recipient_evidence WHERE slot=3')
    if attack=='wrong_network':p.node.network='mainnet'
    if attack=='source':monkeypatch.setattr('solslot_api.generation_launch.runtime_source_hash',lambda:b32(98))
    if attack=='stale_certificate':p.now=p.store.certificate.expires_at
    if attack=='disk':monkeypatch.setattr('solslot_api.generation_launch.shutil.disk_usage',lambda _:SimpleNamespace(total=100,free=1))
    if attack=='disabled':p.settings.generation_launch_enabled=False
    if attack=='other_slot':p.app.dependency_overrides[require_launch_session]=lambda:replace(p.session,slot=2,wallet=p.c.prep.administrators[1].wallet)
    if attack=='fee':p.sender.policy=replace(p.sender.policy,maximum_mojos=101)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        response=await client.post(BASE+'/review');assert response.status_code in (403,409,503),response.text
    assert p.store.latest() is None and not p.journal.recent() and p.node.pushes==0 and p.node.selections==0

@pytest.mark.asyncio
async def test_wrong_wallet_cross_generation_expiry_and_native_consent_deadline(final):
    p=final
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        r=(await client.post(BASE+'/review')).json()['review'];body={'generationId':r['generationId'],'reviewId':r['reviewId']}
        typed=(await client.post(BASE+'/consent/prepare',json=body)).json()['typedData']
        signature='0x'+Account.sign_message(encode_typed_data(full_message=typed),p.accounts[1].key).signature.hex()
        assert (await client.post(BASE+'/consent',json={**body,'signature':signature})).status_code==409
        assert (await client.post(BASE+'/consent/prepare',json={**body,'generationId':b32(97)})).status_code==409
        await approve(p,client,r,1);await approve(p,client,r,3)
        op=(await client.post(BASE+'/prepare',json=body)).json()['operation']
        bundle=p.journal.protocol_bundle(op['operationId'])
        assert await p.c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
        # Reset the mempool without altering inputs, then advance simulation
        # beyond the native deadline; signatures cannot reopen this launch.
        await p.c.sim.rewind(p.c.sim.block_height)
        p.c.sim.pass_time(uint64(86401));await p.c.sim.farm_block()
        assert (await p.c.client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
        p.now=r['expiresAt']
        assert (await client.post(BASE+'/consent/prepare',json=body)).status_code==409
        assert len(p.journal.recent())==1


@pytest.mark.asyncio
async def test_changed_inputs_block_dispatch_and_confirmed_output_reorg_keeps_receipt_without_resubmit(final):
    p=final
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        r=(await client.post(BASE+'/review')).json()['review'];body={'generationId':r['generationId'],'reviewId':r['reviewId']}
        await approve(p,client,r,1);await approve(p,client,r,2)
        op=(await client.post(BASE+'/prepare',json=body)).json()['operation']
        source=p.node.get_coin_record_by_name_primary
        async def changed(name):
            row=deepcopy(await source(name))
            if name==p.c.prep.sgt_funding_coin_id:row.update(spent=True,spent_block_index=999)
            return row
        p.node.get_coin_record_by_name_primary=changed
        submit={**body,'operationId':op['operationId'],'intentHash':op['intentHash'],'feeCapMojos':100}
        assert (await client.post(BASE+'/submit',json=submit)).status_code==409
        assert p.node.pushes==0 and p.node.selections==0
        p.node.get_coin_record_by_name_primary=source
        assert (await client.post(BASE+'/submit',json=submit)).status_code==200
        await p.c.sim.farm_block();await reconcile_saved_operation(p.journal,op['operationId'],p.node,clock=lambda:p.now)
        observer=GenerationLaunchObserver(p.store,p.journal,p.node,clock=lambda:p.now)
        await observer.run_once();assert p.store.status(r['reviewId'])['launchComplete']
        async def orphan(name):
            row=await source(name)
            if name==r['sgtOutputs'][0]['coinId']:return None
            return row
        p.node.get_coin_record_by_name_primary=orphan
        await observer.run_once()
        state=(await client.get(BASE)).json()
        assert not state['review']['launchComplete'] and state['review']['errorCode']=='LAUNCH_OUTPUTS_UNCONFIRMED'
        assert state['operation']['transactionId'] and state['operation']['stage']=='CONFIRMED'
        assert p.node.pushes==1
        p.node.get_coin_record_by_name_primary=source
        await observer.run_once();assert p.store.status(r['reviewId'])['launchComplete']

@pytest.mark.asyncio
@pytest.mark.parametrize('attack',['certificate','preparation','anchor'])
async def test_retained_launch_cannot_be_rebound_by_mutable_maps_or_changed_anchor(final,attack):
    p=final;r=await prepare_launch_review(p.store,p.journal,p.node,p.c.faucet,clock=lambda:p.now)
    if attack=='certificate':p.store.certificate.source_commits['api']='ee'*20
    if attack=='preparation':p.store.preparation.source_commits['api']='ee'*20
    if attack=='anchor':
        with p.store.db() as db:
            db.execute('UPDATE generation_launch_read_anchors SET document=?',('{"purpose":"changed"}',))
        with pytest.raises(ValueError):p.store.read_anchor(r['reviewId'])
    else:
        with pytest.raises(ValueError):p.store.require_ready(p.now)
        with pytest.raises(ValueError):p.store.status(r['reviewId'])
    assert p.journal.recent()==[] and p.node.pushes==0


@pytest.mark.asyncio
async def test_final_ceremony_upgrade_and_http_mint_complete_in_one_native_history(final,tmp_path,monkeypatch):
    from solslot_api.generation_genesis_core import genesis_launch_funding_requests,assemble_genesis_launch
    from tests.test_generation_genesis_core import standard_spend
    from tests.test_generation_genesis_launch import initialize_and_upgrade
    from tests.test_generation_mint_execution import assert_native_mint_lifecycle
    p=final;c=p.c
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        r=(await client.post(BASE+'/review')).json()['review'];body={'generationId':r['generationId'],'reviewId':r['reviewId']}
        await approve(p,client,r,1);await approve(p,client,r,2)
        op=(await client.post(BASE+'/prepare',json=body)).json()['operation']
        response=await client.post(BASE+'/submit',json={**body,'operationId':op['operationId'],
            'intentHash':op['intentHash'],'feeCapMojos':100})
        assert response.status_code==200,response.text
        await c.sim.farm_block();await reconcile_saved_operation(p.journal,op['operationId'],p.node,clock=lambda:p.now)
        await GenerationLaunchObserver(p.store,p.journal,p.node,clock=lambda:p.now).run_once()
        assert (await client.get(BASE)).json()['review']['launchComplete']
    # Recover the exact original assembly from its saved signature and frozen
    # public construction data. This performs no new signing or initialization.
    coins=dict(c.funding,pool=next(coin for coin in c.parents if '0x'+coin.name().hex()==c.prep.coordinates['pool'].funding_coin_id))
    arguments=dict(preparation=c.prep,artifact=p.store.artifact,evidence=c.evidence,
        trusted_preparation_hash=c.prep.manifest_hash,trusted_artifact_hash=p.store.artifact.artifact_hash,
        consent_issued_at=r['issuedAt'])
    requests=genesis_launch_funding_requests(**arguments,funding_coins=coins)
    saved=p.journal.protocol_bundle(op['operationId'])
    built=assemble_genesis_launch(**arguments,funding_spends={req.name:standard_spend(c.faucet,req.coin,req.conditions) for req in requests},
        aggregated_signature=saved.aggregated_signature)
    assert built.operation.bundle()==saved
    upgrade_path=tmp_path/'upgrade';upgrade_path.mkdir()
    initialized=await initialize_and_upgrade(c,upgrade_path,initialized=built)
    mint_path=tmp_path/'mint';mint_path.mkdir()
    await assert_native_mint_lifecycle(c,mint_path,monkeypatch,'complete',initialized_generation=initialized)
    assert p.node.pushes==1 # The ceremony was never initialized a second time.
