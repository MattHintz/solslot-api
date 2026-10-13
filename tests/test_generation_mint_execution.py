"""Real V4 approval, holder vote, scoped payer and restart-safe test mint."""
import asyncio
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json
import os
import time

import httpx
import pytest
from eth_keys import keys
from fastapi import FastAPI
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import get_settings
from solslot_api.faucet import FaucetSelectionRestricted
from solslot_api.generation_consents import GenerationConsentStore,prepare_consent,sign_consent,prepare_scoped_pause
from solslot_api.generation_holder_ballots import GenerationBallotStore,prepare_holder_ballot,assemble_holder_ballot
from solslot_api.generation_holder_evidence import preparation_custody_anchors
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_mint_execution import MintExecutionRequest,GenerationMintObserver,prepare_mint_execution
from solslot_api.generation_mint_review_routes import router
from solslot_api.generation_mint_reviews import prepare_mint_review,GenerationMintReviewStore,h
from solslot_api.generation_operations import GenerationOperationJournal,reconcile_saved_operation
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
from solslot_puzzles.generation_transactions import anchor_vote,finalize_vote
from tests.test_generation_genesis_core import core
from tests.test_generation_mint_reviews import context
from tests.test_generation_mint_publication import publication,consent_kwargs
from tests.test_generation_holder_ballots import request as holder_request,sign_all
from tests.test_generation_recipient_execution import Node
from tests.test_generation_consents import request as consent_request


async def approved(c,ctx,path):
    now=int(c.sim.timestamp)-1;source=await prepare_mint_review(ctx.request,**{**ctx.kwargs,'clock':lambda:now})
    consents=GenerationConsentStore(path/'consents.db',c.prep.generation_id)
    review=await prepare_consent(publication(ctx,source),**consent_kwargs(ctx,c,consents,now))
    for ch in review['challenges']:
        sig=keys.PrivateKey(bytes([ch['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        await sign_consent(review['packageId'],ch['slot'],sig,anchor=ctx.kwargs['anchor'],provider=c.provider,store=consents,clock=lambda:now)
    ballots=GenerationBallotStore(path/'ballots.db',c.prep.generation_id)
    journal=GenerationOperationJournal(path/'operations.db',c.prep.generation_id)
    b=await prepare_holder_ballot(holder_request(c,ctx.chain,review['proposalId'],[1,2],consent_id=review['packageId']),
        anchor=ctx.kwargs['anchor'],custodies=preparation_custody_anchors(c.prep),provider=c.provider,
        store=ballots,consents=consents,clock=lambda:now)
    await sign_all(c,b,ballots,now)
    op=await assemble_holder_ballot(b['packageId'],anchor=ctx.kwargs['anchor'],provider=c.provider,store=ballots,
        consents=consents,journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(op['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider)
    gov,reg=chain.governance.state,chain.registry.state;clock=await c.client.get_coin_record_by_name(gov.active.clock_id)
    operation,_=anchor_vote(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()),clock.coin,int(clock.timestamp))
    assert await c.client.push_tx(operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();c.sim.pass_time(uint64(3600));await c.sim.farm_block()
    chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider);gov,reg=chain.governance.state,chain.registry.state
    operation,_=finalize_vote(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()))
    assert await c.client.push_tx(operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider)
    # Pausing new proposals must not accidentally pause a mint whose holder
    # vote is already closed. Mint scope 2 stays independently enforceable.
    now=int(c.sim.timestamp)-1
    pause=await prepare_consent(consent_request(ctx.kwargs['anchor'],chain,kind='PAUSE_NEW_OPERATIONS',key='pause-only-proposals',scope=1),
        anchor=ctx.kwargs['anchor'],provider=c.provider,store=consents,clock=lambda:now)
    for ch in pause['challenges']:
        sig=keys.PrivateKey(bytes([ch['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        await sign_consent(pause['packageId'],ch['slot'],sig,anchor=ctx.kwargs['anchor'],provider=c.provider,store=consents,clock=lambda:now)
    paused=await prepare_scoped_pause(pause['packageId'],anchor=ctx.kwargs['anchor'],provider=c.provider,
        store=consents,journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(paused['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider)
    assert chain.registry.state.pause_mask==1
    return source,review['proposalId'],journal,chain


@pytest.mark.asyncio
@pytest.mark.parametrize('genesis_mode',['core','complete'])
async def test_native_mint_lost_response_restart_exact_inventory_and_cached_status(core,tmp_path,monkeypatch,genesis_mode):
    await assert_native_mint_lifecycle(core,tmp_path,monkeypatch,genesis_mode)


async def assert_native_mint_lifecycle(core,tmp_path,monkeypatch,genesis_mode,*,initialized_generation=None):
    c=core
    initialized=initialized_generation
    if genesis_mode=='complete' and initialized is None:
        from tests.test_generation_genesis_launch import initialize_and_upgrade
        initialized=await initialize_and_upgrade(c,tmp_path)
    ctx=await context(c,tmp_path,initialized_generation=initialized)
    source,proposal,journal,chain=await approved(c,ctx,tmp_path)
    node=Node(c.client)
    funding=ProtocolFundingStore(generation_path(str(tmp_path/'fees.db'),c.prep.generation_id))
    sender=ProtocolBundleSubmitter(provider=node,faucet=c.faucet,funding_store=funding,
        policy=ProtocolFeePolicy(enabled=True,native_admission_enabled=True,minimum_mojos=1,maximum_mojos=1000,
            maximum_funding_coin_mojos=10_000_000,mempool_timeout_seconds=.1,mempool_poll_seconds=.001))
    c.faucet.bind_generation_mint_reviews(ctx.store,generation_id=c.prep.generation_id,maximum_parent_mojos=1000)
    c.faucet.add_coin_reservation_source(journal.reserved_input_coin_ids)
    sender.add_fee_coin_reservation_source(ctx.store.reserved_input_coin_ids)
    sender.add_fee_coin_reservation_source(journal.reserved_input_coin_ids)
    settings=ctx.settings.model_copy(update={'generation_execution_enabled':True})
    app=FastAPI();app.include_router(router)
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[require_admin_jwt]=lambda:SimpleNamespace()
    app.state.generation_mint_reviews=ctx.store;app.state.generation_operations=journal
    app.state.generation_index=SimpleNamespace(anchor=ctx.kwargs['anchor']);app.state.coinset=node
    app.state.faucet=c.faucet;app.state.protocol_submitter=sender
    monkeypatch.setattr('solslot_api.generation_mint_review_routes.get_collection_store',lambda s:ctx.collections)
    body=MintExecutionRequest.model_validate({'generationId':c.prep.generation_id,'sourceReviewId':source['packageId'],
        'proposalId':proposal,'feeCapMojos':1000,'expectedInputs':{**{name:h(getattr(chain,name).current.coin.name())
            for name in ('registry','governance','holdings')},'components':{source['mintAuthority']['componentId']:source['mintAuthority']['coinId']}}})
    base='/admin/generation/mint-reviews/'+source['packageId']+'/execution'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        # Generic signing and fake scope cannot touch the retained parents.
        parent=source['funding'][0];coin=(await c.client.get_coin_record_by_name(bytes32.from_hexstr(parent['coinId']))).coin
        from chia.types.blockchain_format.program import Program
        with pytest.raises(FaucetSelectionRestricted):c.faucet.sign_delegated_spend(coin,Program.to([]))
        rejected=body.model_copy(update={'proposal_id':'0x'+'99'*32})
        with pytest.raises(ValueError,match='closed holder approval'):
            await prepare_mint_execution(rejected,settings=settings,collections=ctx.collections,reviews=ctx.store,journal=journal,
                anchor=ctx.kwargs['anchor'],provider=node,faucet=c.faucet,funding_guard=sender.funding_guard)
        settings=settings.model_copy(update={'generation_execution_enabled':False})
        assert (await client.post(base+'/prepare',json=body.model_dump(mode='json',by_alias=True))).status_code==503
        settings=settings.model_copy(update={'generation_execution_enabled':True})
        node.network='mainnet'
        assert (await client.post(base+'/prepare',json=body.model_dump(mode='json',by_alias=True))).status_code in (409,503)
        node.network='testnet11'
        with pytest.raises(FaucetSelectionRestricted):
            c.faucet.bind_generation_mint_reviews(ctx.store,generation_id='0x'+'99'*32,maximum_parent_mojos=1000)
        assert node.pushes==0 and node.selections==0
        response=await client.post(base+'/prepare',json=body.model_dump(mode='json',by_alias=True))
        assert response.status_code==200,response.text
        prepared=response.json();operation=prepared['operation']
        assert operation['kind']=='MINT_COLLECTION' and operation['transactionId'] is None and prepared['inventory']['receipt'] is None
        assert len(journal.protocol_bundle(operation['operationId']).coin_spends)==53
        if target:=os.environ.get('GENERATION_MINT_EXECUTION_VECTOR'):
            Path(target).write_text(json.dumps({'source':source,'execution':prepared},indent=2)+'\n')
        assert (await client.post(base+'/prepare',json=body.model_dump(mode='json',by_alias=True))).json()==prepared
        for mutation in ({'proposalId':'0x'+'99'*32},{'feeCapMojos':1001},{'sourceReviewId':'0x'+'99'*32},{'spendBundle':{}}):
            assert (await client.post(base+'/prepare',json={**body.model_dump(mode='json',by_alias=True),**mutation})).status_code in (409,422)
        submit={'generationId':c.prep.generation_id,'operationId':operation['operationId'],
            'intentHash':operation['intentHash'],'feeCapMojos':1000}
        for mutation in ({'generationId':'0x'+'99'*32},{'operationId':'0x'+'99'*32},{'intentHash':'0x'+'99'*32},
                         {'feeCapMojos':1001},{'spendBundle':{}}):
            assert (await client.post(base+'/submit',json={**submit,**mutation})).status_code in (409,422)
        assert node.pushes==0 and node.selections==0
        node.lose_response=True
        response=await client.post(base+'/submit',json=submit)
        assert response.status_code==503,response.text
        retained=journal.status(operation['operationId']);assert retained['transactionId'] and retained['stage']=='RECONCILING'
        assert node.pushes==1
        selections=node.selections
        journal=GenerationOperationJournal(journal.path,c.prep.generation_id);app.state.generation_operations=journal
        store=GenerationMintReviewStore(ctx.store.path,c.prep.generation_id);app.state.generation_mint_reviews=store
        # No second signature or replacement funding after process restart.
        monkeypatch.setattr(c.faucet,'sign_generation_mint',lambda *a,**k:pytest.fail('retry cannot sign again'))
        assert (await client.post(base+'/prepare',json=body.model_dump(mode='json',by_alias=True))).json()['operation']==retained
        assert (await client.post(base+'/submit',json=submit)).status_code==200
        assert node.pushes==1 and node.selections==selections
        await c.sim.farm_block()
        await reconcile_saved_operation(journal,operation['operationId'],node,clock=time.time)
        observer=GenerationMintObserver(store,journal,node)
        original=node.get_coin_record_by_name_primary
        async def missing(identity):
            return None if identity==source['funding'][0]['inventoryCoinId'] else await original(identity)
        node.get_coin_record_by_name_primary=missing
        await observer.run_once()
        waiting=(await client.get(base)).json()
        assert waiting['operation']['stage']=='CONFIRMED' and waiting['inventory']['receipt'] is None
        assert waiting['inventory']['errorCode']=='MINT_INVENTORY_NOT_CONFIRMED'
        node.get_coin_record_by_name_primary=original
        await observer.run_once()
        confirmed=(await client.get(base)).json()
        assert confirmed['operation']['stage']=='CONFIRMED' and confirmed['inventory']['receipt']['deedCount']==25
        receipt=confirmed['inventory']['receipt'];assert len({r['coinId'] for r in receipt['inventory']})==25
        assert receipt['transactionId']==retained['transactionId'] and receipt['metadataRoot']==source['request']['metadataRoot']
        for row in receipt['inventory']:
            record=await c.client.get_coin_record_by_name(bytes32.from_hexstr(row['coinId']))
            assert record and not record.spent and record.coin.amount==1
        # A confirmed retry is read-only even with node and signer unusable.
        class Never:
            def __getattr__(self,name):raise AssertionError('cached status contacted node or signer')
        app.state.coinset=Never();sender.provider=Never()
        for _ in range(5):assert (await client.get(base)).json()==confirmed
        assert (await client.post(base+'/submit',json=submit)).json()==confirmed
        assert node.pushes==1 and node.selections==selections
        if target:=os.environ.get('GENERATION_MINT_CONFIRMATION_VECTOR'):
            Path(target).write_text(json.dumps({'source':source,'execution':confirmed},indent=2)+'\n')
    ctx.collections.close()
