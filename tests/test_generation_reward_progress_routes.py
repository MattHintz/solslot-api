"""Typed HTTP prepare/submit of confirmed native/CAT reward continuation pages."""
from copy import deepcopy
from types import SimpleNamespace
import time

from fastapi import FastAPI
from httpx import ASGITransport,AsyncClient
import pytest
import pytest_asyncio
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import SpendBundle,G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_ballots import CurrentHoldings
from solslot_puzzles.generation_sgt import ledger_inner
from solslot_puzzles.generation_rewards import start_reward_epoch
from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import get_settings
from solslot_api.faucet import Faucet,AGG_SIG_ME_DATA
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_operation_routes import router
from solslot_api.generation_operations import GenerationOperationJournal,reconcile_saved_operation
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared as source_prepared,Primary
from tests.test_generation_reward_execution import funding
from tests.test_generation_execution import h
from tests.test_approval_repair import admission_quote


@pytest_asyncio.fixture
async def prepared(monkeypatch):
    # The shared structural fixture defaults to mainnet consensus constants.
    # This HTTP test includes a real Testnet11 faucet signature, so give its
    # isolated simulator the matching additional-data domain from the start.
    import tests.test_generation_recipient_evidence as source
    monkeypatch.setattr(source,'DEFAULT_CONSTANTS',source.DEFAULT_CONSTANTS.replace(
        AGG_SIG_ME_ADDITIONAL_DATA=AGG_SIG_ME_DATA['testnet11']))
    async for value in source_prepared.__wrapped__():
        yield value


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[True,False])
async def test_typed_reward_pages_submit_confirm_and_resume_exact_transactions(generation_chain,prepared,tmp_path,native):
    sim,client,_,anchor,_=generation_chain
    custody,fee=await funding(generation_chain,native=native)
    sim.pass_time(uint64(86401));await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=Primary(client));tree,sequence=e.holdings.state
    state=anchor.economic_components[1]
    result=start_reward_epoch(custody,e.governance.state,e.registry.state,
        CurrentHoldings(custody.bindings,tree,sequence,e.holdings.verified_tip(custody.bindings.ledger_launcher_id,
            ledger_inner(custody.bindings,tree,sequence))),state,
        e.economic_components[state.component_id].verified_tip(state.launcher_id,state.inner()),(fee,))
    assert result.continuation
    assert await client.push_tx(result.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    faucet=Faucet.from_seed_hex('01'*32,'testnet11');acs=Program.to(1)
    await sim.farm_block(acs.get_tree_hash())
    origin=(await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[-1].coin
    split=make_spend(origin,acs,Program.to([[51,faucet.address_puzzle_hash,100],
        [51,acs.get_tree_hash(),int(origin.amount)-100]]))
    assert await client.push_tx(SpendBundle([split],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()

    class Node(Primary):
        pushes=0;quotes=0;selections=0;accepted={}
        async def get_fee_estimate(self,**kwargs):
            self.quotes+=1;return admission_quote(estimate=1)
        async def get_coin_records_by_puzzle_hash(self,identity,*,include_spent):
            self.selections+=1
            return [r.to_json_dict() for r in await self.client.get_coin_records_by_puzzle_hash(
                bytes32.from_hexstr(identity),include_spent_coins=include_spent)]
        async def get_mempool_items_by_coin_name(self,*args):return []
        async def push_tx_confirmed_in_primary_mempool(self,value,**kwargs):
            bundle=SpendBundle.from_json_dict(value)
            assert '0x'+bundle.name().hex()==kwargs['required_spend_bundle_id']
            assert await self.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
            self.pushes+=1;self.accepted[bundle.name()]=value
            return {'status':'MEMPOOL','provider':'native-consensus-simulator','observed_at':'2026-10-13T00:00:00Z','ambiguous_push':False}
        async def observe_exact_protocol_bundle(self,value):
            bundle=SpendBundle.from_json_dict(value)
            if self.accepted.get(bundle.name())!=value:return None
            ephemeral={coin.name() for coin in bundle.additions()};heights=[]
            for spend in bundle.coin_spends:
                if spend.coin.name() in ephemeral:continue
                record=await self.client.get_coin_record_by_name(spend.coin.name())
                if not record or not record.spent:
                    return {'status':'MEMPOOL','provider':'native-consensus-simulator','observed_at':'2026-10-13T00:00:00Z','ambiguous_push':False}
                assert await self.client.get_puzzle_and_solution(spend.coin.name(),record.spent_block_index)==spend
                heights.append(record.spent_block_index)
            return {'status':'CONFIRMED','confirmed_height':int(max(heights)),'provider':'native-consensus-simulator','observed_at':'2026-10-13T00:00:00Z','ambiguous_push':False}

    gen=h(anchor.issuance.generation);node=Node(client)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),gen)
    store=ProtocolFundingStore(generation_path(str(tmp_path/'funding.db'),gen))
    sender=ProtocolBundleSubmitter(provider=node,faucet=faucet,policy=ProtocolFeePolicy(enabled=True,
        minimum_mojos=1,maximum_mojos=1000,maximum_funding_coin_mojos=1000,native_admission_enabled=True),funding_store=store)
    app=FastAPI();app.include_router(router);app.state.generation_operations=journal
    app.state.generation_index=SimpleNamespace(anchor=anchor);app.state.coinset=node;app.state.protocol_submitter=sender
    app.dependency_overrides[require_admin_jwt]=lambda:None
    app.dependency_overrides[get_settings]=lambda:SimpleNamespace(network='testnet11',deployment_generation_id=gen,generation_execution_enabled=True)
    progress=result.continuation;claims=[];pages=0
    try:
        async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as http:
            while progress:
                e=await resolve_generation_chain(anchor,provider=node)
                request={'generationId':gen,'requestKey':'reward-page:'+progress.source.coin.name().hex(),
                    'kind':'ADVANCE_SGT_REWARDS','feeCapMojos':1000,
                    'expectedInputs':{name:h(getattr(e,name).current.coin.name()) for name in ('registry','governance','holdings')}|{'components':{}},
                    'rewardProgress':{'assetId':h(custody.asset_id),'statutesLauncherId':h(state.launcher_id),
                        'continuationCoinId':h(progress.source.coin.name())}}
                before=(node.pushes,node.selections)
                forged=deepcopy(request);forged['rewardProgress']['continuationCoinId']='0x'+'ff'*32
                assert (await http.post('/admin/generation/operations/prepare',json=forged)).status_code==409
                assert (node.pushes,node.selections)==before
                response=await http.post('/admin/generation/operations/prepare',json=request)
                assert response.status_code==200,response.text
                saved=response.json();identity=saved['operationId']
                expected,next_progress,page=progress.advance(limit=16)
                assert journal.protocol_bundle(identity)==expected.bundle()
                assert saved['review']['rewardProgress']==request['rewardProgress']
                for _ in range(3):
                    assert (await http.get('/admin/generation/operations/'+identity)).json()==saved
                assert (node.pushes,node.selections)==before
                url='/admin/generation/operations/'+identity+'/submit'
                body={'generationId':gen,'intentHash':saved['intentHash'],'feeCapMojos':1000}
                assert (await http.post(url,json={**body,'feeCapMojos':999})).status_code==409
                sent=await http.post(url,json=body)
                assert sent.status_code==200,sent.text
                assert sent.json()['stage']=='SUBMITTED'
                held=journal.saved_funding(identity)
                pushes=node.pushes;selections=node.selections
                assert (await http.post(url,json=body)).status_code==200
                assert (node.pushes,node.selections)==(pushes,selections)
                await sim.farm_block()
                observed=await node.observe_exact_protocol_bundle(journal.saved_funding(identity)['spendBundle'])
                assert observed and observed['status']=='CONFIRMED',observed
                await reconcile_saved_operation(journal,identity,node,clock=time.time)
                assert journal.status(identity)['stage']=='CONFIRMED'
                # Actual restart and a consumed continuation keep the same receipt,
                # rather than trying to assemble or submit a second page.
                journal=GenerationOperationJournal(str(tmp_path/'operations.db'),gen)
                app.state.generation_operations=journal
                recovered=await http.post('/admin/generation/operations/prepare',json=request)
                assert recovered.status_code==200 and recovered.json()['operationId']==identity
                assert journal.saved_funding(identity)==held
                assert (await http.post(url,json=body)).json()['stage']=='CONFIRMED'
                assert (node.pushes,node.selections)==(pushes,selections)
                claims.extend(page);progress=next_progress;pages+=1
        assert pages==2 and len(claims)==3 and sum(c.amount for c,_ in claims)==90
        assert node.pushes==pages and not journal.pending_ids()
        for claim,source in claims:
            record=await client.get_coin_record_by_name(source.coin.name())
            assert record and not record.spent and record.coin.amount==claim.amount
    finally:store.close()
