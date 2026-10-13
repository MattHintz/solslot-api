"""Reserved recipient launch through real signing, native admission and consensus."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import time

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.chia_provider import ChiaProviderError
from solslot_api.config import get_settings
from solslot_api.faucet import Faucet, FaucetSelectionRestricted
from solslot_api.generation_preparation import GenerationPreparation
from solslot_api.generation_preparation_routes import router, preparation_store
from solslot_api.generation_preparation_store import GenerationPreparationStore
from solslot_api.generation_recipient_execution import RecipientLaunchRequest, GenerationRecipientObserver
from solslot_api.generation_operations import GenerationOperationJournal, reconcile_saved_operation
from solslot_api.generation_storage import generation_path
from solslot_api.launch_control import LaunchSession, require_launch_session
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from tests.test_generation_preparation import manifest, bind_custody, bind_identities, signatures, b32
from tests.test_generation_recipient_evidence import Primary
from tests.test_approval_repair import admission_quote

BASE='/admin/launch/generation/recipients'


class Node(Primary):
    def __init__(self, client):
        super().__init__(client)
        self.pushes=0;self.selections=0;self.lose_response=False;self.network='testnet11'
    async def get_network_info_primary(self):return {'network_name':self.network}
    async def get_coin_records_by_puzzle_hash(self, puzzle_hash, **kwargs):
        self.selections+=1
        return [r.to_json_dict() for r in await self.client.get_coin_records_by_puzzle_hash(bytes32.from_hexstr(puzzle_hash), include_spent_coins=False)]
    async def get_fee_estimate(self, **kwargs):return admission_quote()
    async def get_mempool_items_by_coin_name(self, name):
        identity=bytes32.from_hexstr(name)
        return [item for item in (await self.client.get_all_mempool_items()).values()
            if identity in {c.name() for c in item.spend_bundle.removals()}]
    async def observe_exact_protocol_bundle(self, raw):
        bundle=SpendBundle.from_json_dict(raw)
        result={'provider':'local-full-node','observed_at':'synthetic','ambiguous_push':False}
        if await self.client.get_mempool_item_by_tx_id(bundle.name()):return {**result,'status':'MEMPOOL'}
        # Prove the actual non-ephemeral input spends and additions at one height.
        created={c.name() for c in bundle.additions()}
        records=[await self.client.get_coin_record_by_name(c.name()) for c in bundle.removals() if c.name() not in created]
        if not records or any(r is None or not r.spent_block_index for r in records):return None
        height=records[0].spent_block_index
        if any(r.spent_block_index!=height for r in records):return None
        removed={c.name() for c in bundle.removals()}
        outputs=[await self.client.get_coin_record_by_name(c.name()) for c in bundle.additions() if c.name() not in removed]
        if any(r is None or r.confirmed_block_index!=height for r in outputs):return None
        for spend in bundle.coin_spends:
            confirmed=await self.client.get_puzzle_and_solution(spend.coin.name(),height)
            assert bytes(confirmed)==bytes(spend)
        return {**result,'status':'CONFIRMED','confirmed_height':int(height)}
    async def push_tx_confirmed_in_primary_mempool(self, raw, **kwargs):
        self.pushes+=1
        assert await self.client.push_tx(SpendBundle.from_json_dict(raw))==(MempoolInclusionStatus.SUCCESS,None)
        if self.lose_response:raise ChiaProviderError('synthetic response loss after native acceptance')
        return await self.observe_exact_protocol_bundle(raw)


@pytest_asyncio.fixture
async def launch(tmp_path):
    faucet=Faucet.from_seed_hex('04'*32,'testnet11')
    constants=DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=faucet.agg_sig_me_data)
    async with SpendSim.managed(None,defaults=constants) as sim:
        client=SimClient(sim);acs=Program.to(1)
        for _ in range(6):await sim.farm_block(acs.get_tree_hash())
        origins=[r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        parents=[];spends=[]
        for i,origin in enumerate(origins[:12]):
            amount=1000+i if i<11 else 100000
            parents.append(Coin(origin.name(),faucet.address_puzzle_hash,uint64(amount)))
            spends.append(make_spend(origin,acs,Program.to([[51,faucet.address_puzzle_hash,amount],
                [51,acs.get_tree_hash(),int(origin.amount)-amount]])))
        assert await client.push_tx(SpendBundle(spends,G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        original,accounts=manifest();raw=original.model_dump(mode='json',by_alias=True)
        def reserve(coin):return {'fundingCoinId':'0x'+coin.name().hex(),
            'launcherId':'0x'+Coin(coin.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name().hex()}
        for i,k in enumerate(sorted(raw['coordinates'])):raw['coordinates'][k]=reserve(parents[i])
        for i,a in enumerate(raw['administrators']):a['custody']=reserve(parents[7+i])
        raw['sgtFundingCoinId']='0x'+parents[10].name().hex()
        bind_identities(raw);bind_custody(raw);m=GenerationPreparation.model_validate(raw)
        faucet.bind_generation_preparation(m,trusted_preparation_hash=m.manifest_hash)
        journal=GenerationOperationJournal(str(tmp_path/'operations.sqlite3'),m.generation_id)
        faucet.add_coin_reservation_source(journal.reserved_input_coin_ids)
        node=Node(client)
        funding=ProtocolFundingStore(generation_path(str(tmp_path/'fees.sqlite3'),m.generation_id))
        sender=ProtocolBundleSubmitter(provider=node,faucet=faucet,funding_store=funding,
            policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,maximum_mojos=100,
                maximum_funding_coin_mojos=100000,native_admission_enabled=True))
        store=GenerationPreparationStore(str(tmp_path/'preparation.sqlite3'),m)
        settings=SimpleNamespace(network='testnet11',deployment_generation_id=m.generation_id,generation_execution_enabled=True)
        session=LaunchSession('test',1,m.administrators[0].wallet,False,9999999999,m.generation_id)
        app=FastAPI();app.include_router(router)
        app.state.generation_operations=journal;app.state.protocol_submitter=sender;app.state.coinset=node
        app.dependency_overrides[preparation_store]=lambda:store
        app.dependency_overrides[get_settings]=lambda:settings
        app.dependency_overrides[require_launch_session]=lambda:session
        yield SimpleNamespace(sim=sim,client=client,node=node,faucet=faucet,m=m,journal=journal,store=store,
            sender=sender,settings=settings,session=session,app=app,parents=parents,sigs=signatures(m,accounts))
        funding.close()


def request(p, slot=1):
    a=p.m.administrators[slot-1]
    return dict(generationId=p.m.generation_id,preparationManifest=p.m.manifest_hash,administratorSlot=slot,
        fundingCoinId=a.custody.funding_coin_id,recipientVault=a.custody.launcher_id,
        recipientPuzzle=a.sgt_owner_puzzle_hash,feeCapMojos=100)


@pytest.mark.asyncio
async def test_native_ui_launch_lost_response_restart_confirmation_and_consent(launch):
    p=launch
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        first=(await client.get(BASE)).json();assert first['creationAvailable']
        assert all(r['creation'] is None for r in first['recipients']) and p.node.pushes==0
        body=request(p)
        prepared=(await client.post(BASE+'/creation/prepare',json=body)).json()
        saved=prepared['recipients'][0]['creation'];assert saved['stage']=='PREPARED'
        assert (await client.post(BASE+'/creation/prepare',json=body)).json()==prepared
        # Every frozen parent remains unavailable to ordinary selection/signing.
        assert p.faucet.select_coin([r.to_json_dict() for r in await p.client.get_coin_records_by_puzzle_hash(p.faucet.address_puzzle_hash)],
            min_amount=1).name()==p.parents[11].name()
        with pytest.raises(FaucetSelectionRestricted):p.faucet.sign_delegated_spend(p.parents[7],Program.to([]))
        assert p.node.selections==0 and p.node.pushes==0
        submit={'generationId':p.m.generation_id,'preparationManifest':p.m.manifest_hash,
            'operationId':saved['operationId'],'intentHash':saved['intentHash'],'feeCapMojos':100}
        p.node.lose_response=True
        assert (await client.post(BASE+'/creation/submit',json=submit)).status_code==503
        retained=p.journal.status(saved['operationId']);assert retained['transactionId'] and retained['stage']=='RECONCILING'
        assert p.node.pushes==1
        selection_count=p.node.selections
        # Resume from independent reopened stores, never select or sign again.
        p.journal=GenerationOperationJournal(p.journal.path,p.m.generation_id);p.app.state.generation_operations=p.journal
        assert (await client.post(BASE+'/creation/prepare',json=body)).json()['recipients'][0]['creation']==retained
        assert (await client.post(BASE+'/creation/submit',json=submit)).status_code==200
        assert p.node.pushes==1 and p.node.selections==selection_count
        await p.sim.farm_block()
        await reconcile_saved_operation(p.journal,saved['operationId'],p.node,clock=time.time)
        observer=GenerationRecipientObserver(p.store,p.journal,p.node)
        await observer.run_once()
        confirmed=(await client.get(BASE)).json()['recipients'][0]
        assert confirmed['confirmed'] and confirmed['creation']['stage']=='CONFIRMED'
        assert confirmed['creation']['transactionId']==retained['transactionId']
        assert (await client.post(BASE+'/acknowledgement/prepare')).status_code==200
        assert (await client.post(BASE+'/acknowledgement',json={'preparationManifest':p.m.manifest_hash,'signature':p.sigs[1]})).status_code==200
        # Cached UI polling is available with no node or signer at all.
        class Never:
            def __getattr__(self,name):raise AssertionError('cached progress called a node or signer')
        p.app.state.coinset=Never();p.sender.provider=Never();p.sender.faucet=Never()
        for _ in range(5):
            status=(await client.get(BASE)).json()
            assert status['recipients'][0]['acknowledgedAt'] and not status['genesisAuthorized']
        assert p.node.selections==selection_count


@pytest.mark.asyncio
@pytest.mark.parametrize('attack',['other_slot','manifest','generation','parent','destination','fee','extra','disabled','node_network'])
async def test_launch_rejects_scope_substitution_and_unreviewed_writes_before_signing(launch,attack):
    p=launch;body=request(p)
    if attack=='other_slot':body=request(p,2)
    if attack=='manifest':body['preparationManifest']=b32(92)
    if attack=='generation':body['generationId']=b32(92)
    if attack=='parent':body['fundingCoinId']=p.m.administrators[1].custody.funding_coin_id
    if attack=='destination':body['recipientPuzzle']=b32(92)
    if attack=='fee':body['feeCapMojos']=101
    if attack=='extra':body['spendBundle']={}
    if attack=='disabled':p.settings.generation_execution_enabled=False
    if attack=='node_network':p.node.network='mainnet'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        assert (await client.post(BASE+'/creation/prepare',json=body)).status_code in (403,409,422,503)
    assert p.journal.recent()==[] and p.node.selections==0 and p.node.pushes==0


@pytest.mark.asyncio
async def test_other_administrator_cannot_submit_a_saved_recipient_and_changed_fee_cannot_replace_it(launch):
    p=launch
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        body=request(p)
        prepared=(await client.post(BASE+'/creation/prepare',json=body)).json()['recipients'][0]['creation']
        submit=dict(generationId=p.m.generation_id,preparationManifest=p.m.manifest_hash,
            operationId=prepared['operationId'],intentHash=prepared['intentHash'],feeCapMojos=100)
        session=replace(p.session,slot=2,wallet=p.m.administrators[1].wallet)
        p.app.dependency_overrides[require_launch_session]=lambda:session
        assert (await client.post(BASE+'/creation/submit',json=submit)).status_code==409
        p.app.dependency_overrides[require_launch_session]=lambda:p.session
        for edit in ({'intentHash':b32(91)},{'feeCapMojos':101},{'operationId':b32(91)},{'preparationManifest':b32(91)}):
            assert (await client.post(BASE+'/creation/submit',json={**submit,**edit})).status_code==409
        p.sender.policy=replace(p.sender.policy,maximum_mojos=101)
        assert (await client.post(BASE+'/creation/prepare',json={**body,'feeCapMojos':101})).status_code==409
    assert len(p.journal.recent())==1 and p.node.pushes==0 and p.node.selections==0


@pytest.mark.asyncio
async def test_three_assigned_launches_confirm_exact_destinations_without_issuing_sgt(launch):
    p=launch
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        for slot in (1,2,3):
            session=replace(p.session,slot=slot,wallet=p.m.administrators[slot-1].wallet)
            p.app.dependency_overrides[require_launch_session]=lambda:session
            prepared=(await client.post(BASE+'/creation/prepare',json=request(p,slot))).json()['recipients'][slot-1]['creation']
            submitted=await client.post(BASE+'/creation/submit',json=dict(generationId=p.m.generation_id,
                preparationManifest=p.m.manifest_hash,operationId=prepared['operationId'],intentHash=prepared['intentHash'],feeCapMojos=100))
            assert submitted.status_code==200
            await p.sim.farm_block()
            await reconcile_saved_operation(p.journal,prepared['operationId'],p.node,clock=time.time)
            await GenerationRecipientObserver(p.store,p.journal,p.node).run_once()
            assert (await client.post(BASE+'/acknowledgement',json=dict(preparationManifest=p.m.manifest_hash,signature=p.sigs[slot]))).status_code==200
        state=(await client.get(BASE)).json()
        assert state['recipientPreparationComplete'] and not state['genesisAuthorized']
        assert p.node.pushes==3 and len({r['creation']['transactionId'] for r in state['recipients']})==3
        for parent in p.parents[:7]+[p.parents[10]]:
            assert not (await p.client.get_coin_record_by_name(parent.name())).spent_block_index
        from solslot_api.generation_recipient_evidence import verify_recipient_custody,issuance_plan_from_recipients
        from solslot_puzzles.generation_sgt import build_initial_issuance
        evidence=await verify_recipient_custody(p.m,p.store.signatures(),trusted_preparation_hash=p.m.manifest_hash,provider=p.node)
        planned=build_initial_issuance(issuance_plan_from_recipients(p.m,evidence))
        assert [c.amount for c in planned.coins]==[10000,10000,10000,970000]
        assert all(record is None for record in [await p.client.get_coin_record_by_name(c.name()) for c in planned.coins])


@pytest.mark.asyncio
async def test_scoped_signer_rejects_other_runtime_holds_and_rebinding(launch):
    p=launch
    p.faucet.add_coin_reservation_source(lambda:{p.m.administrators[0].custody.funding_coin_id})
    with pytest.raises(FaucetSelectionRestricted):
        p.faucet.sign_generation_recipient(p.parents[7],1,preparation_manifest=p.m.manifest_hash)
    raw=p.m.model_dump(mode='json',by_alias=True);raw['sourceCommits']['api']='56'*20
    changed=GenerationPreparation.model_validate(raw)
    with pytest.raises(FaucetSelectionRestricted):p.faucet.bind_generation_preparation(changed,trusted_preparation_hash=changed.manifest_hash)
    with pytest.raises(FaucetSelectionRestricted):p.faucet.sign_generation_recipient(p.parents[8],1,preparation_manifest=p.m.manifest_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize('attack',['spent','wrong_record','racing_record'])
async def test_primary_parent_must_remain_the_exact_unspent_reserved_input(launch,attack):
    p=launch;read=p.node.get_coin_record_by_name_primary;calls=0
    async def changed(name):
        nonlocal calls
        row=deepcopy(await read(name));calls+=1
        if attack=='spent' or (attack=='racing_record' and calls>1):row.update(spent_block_index=12,spent=True)
        if attack=='wrong_record':row['coin']['amount']+=1
        return row
    p.node.get_coin_record_by_name_primary=changed
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app),base_url='http://test') as client:
        assert (await client.post(BASE+'/creation/prepare',json=request(p))).status_code==409
    assert p.journal.recent()==[] and p.node.pushes==0 and p.node.selections==0
