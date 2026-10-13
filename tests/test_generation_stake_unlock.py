"""Explicit closed-stake recovery through API prepare and native consensus."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_execution import MaintenanceRequest,prepare_maintenance
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_api.generation_registry_evidence import _spend
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.holdings import HoldingKind
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared,Primary
from tests.test_generation_execution import open_native,body,h


async def close_vote(c,p,journal):
    proposal,_=await open_native(c,p)
    sim,client,provider,anchor,_=c
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE'):
        e=await resolve_generation_chain(anchor,provider=provider)
        saved=await prepare_maintenance(body(anchor,e,kind),anchor=anchor,provider=provider,journal=journal)
        if kind=='FINALIZE_VOTE':sim.pass_time(uint64(3601));await sim.farm_block()
        assert await client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
    return proposal


@pytest.mark.asyncio
async def test_closed_stakes_recover_unchanged_owners_during_pause_with_saved_exact_review(generation_chain,prepared,tmp_path):
    c=generation_chain;sim,client,provider,anchor,_=c
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    proposal=await close_vote(c,prepared,journal)
    e=await resolve_generation_chain(anchor,provider=provider)
    before=e.public_status(100)
    assert before['closedStakeCount']==2 and not before['closedStakesTruncated']
    assert all(row['amount']==10000 and row['proposalId']==h(proposal) for row in before['closedStakes'])
    gov,reg=e.governance.state,e.registry.state
    # Put every pausable operation under a consensus-accepted scoped pause.
    # The existing fixture authority is ACS; separate tests exercise real MIPS
    # owner-plus-one consent. Unlock itself needs neither custody signature.
    records=await client.get_coin_records_by_puzzle_hash(puzzle_for_singleton(reg.administrator_id,Program.to(1)).get_tree_hash(),include_spent_coins=False)
    assert len(records)==1
    authority=records[0].coin
    parent_record=await client.get_coin_record_by_name(authority.parent_coin_info)
    parent=_spend(await provider.get_puzzle_and_solution_primary(h(authority.parent_coin_info),parent_record.spent_block_index),parent_record.coin)
    admin=SingletonTip(reg.administrator_id,Program.to(1),authority,parent)
    tip=e.registry.verified_tip(reg.launcher_id,reg.inner())
    message=Program.to([b'PAUSE_NEW_OPERATIONS',reg.generation,reg.pause_epoch,31]).get_tree_hash()
    consent=admin.spend(Program.to([[66,18,message,tip.coin.puzzle_hash],[51,admin.inner.get_tree_hash(),1]]))
    pause=tip.spend(inner_solution('PAUSE',tip.coin,[admin.inner.get_tree_hash(),31]))
    assert await client.push_tx(SpendBundle([pause,consent],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider)
    assert e.registry.state.pause_mask==31
    ids=[row['coinId'] for row in before['closedStakes']]
    request=body(anchor,e,'UNLOCK_STAKES',stakes={'coinIds':ids})
    saved=await prepare_maintenance(request,anchor=anchor,provider=provider,journal=journal)
    assert saved['review']['stakes']=={'coinIds':ids} and saved['transactionId'] is None
    assert e.public_status(101)['closedStakes']==before['closedStakes'] # preparation is not execution.
    bundle=journal.protocol_bundle(saved['operationId'])
    assert bundle.aggregated_signature==G2Element()
    assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    updated=await resolve_generation_chain(anchor,provider=provider)
    assert updated.registry.state.pause_mask==31
    view=updated.public_status(102)
    assert view['closedStakes']==[] and view['closedStakeCount']==view['supply']['locked']==0
    assert view['supply']['total']==1000000 and view['supply']['distributed']==30000 and view['supply']['nextProposalQuorum']==15000
    old_owners={row['ownerPuzzleHash'] for row in before['closedStakes']}
    new_holdings=[v for v in updated.holdings.state[0].holdings.values() if h(v.owner_hash) in old_owners]
    assert all(v.kind==HoldingKind.HOLDER and not v.lock_id and v.amount==10000 for v in new_holdings)
    # Restart and a lost response resume this reviewed operation even offline.
    restored=GenerationOperationJournal(str(tmp_path/'operations.db'),request.generation_id)
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('cannot rebuild')))
    assert await prepare_maintenance(request,anchor=anchor,provider=offline,journal=restored)==saved
    assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    changed=request.model_copy(update={'stakes':request.stakes.model_copy(update={'coin_ids':tuple(reversed(request.stakes.coin_ids))})})
    with pytest.raises(ValueError,match='retry changes'):
        await prepare_maintenance(changed,anchor=anchor,provider=offline,journal=restored)


@pytest.mark.asyncio
async def test_unlock_rejects_active_stakes_reserve_and_changed_native_parent_evidence(generation_chain,prepared,tmp_path):
    c=generation_chain;sim,client,provider,anchor,_=c
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    await open_native(c,prepared)
    e=await resolve_generation_chain(anchor,provider=provider)
    tree,_=e.holdings.state
    ids=[identity for identity,v in tree.holdings.items() if v.kind==HoldingKind.LOCKED_HOLDER]
    assert e.public_status(100)['closedStakes']==[]
    request=body(anchor,e,'UNLOCK_STAKES',stakes={'coinIds':[h(ids[0])]})
    with pytest.raises(ValueError,match='closed proposal'):
        await prepare_maintenance(request,anchor=anchor,provider=provider,journal=journal)
    # Close the actual one-hour vote, without a clock shortcut in the kernel.
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE'):
        e=await resolve_generation_chain(anchor,provider=provider)
        saved=await prepare_maintenance(body(anchor,e,kind),anchor=anchor,provider=provider,journal=journal)
        if kind=='FINALIZE_VOTE':sim.pass_time(uint64(3601));await sim.farm_block()
        assert await client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider)
    reserve=next(identity for identity,v in e.holdings.state[0].holdings.items() if v.kind==HoldingKind.RESERVE)
    with pytest.raises(ValueError,match='closed proposal'):
        await prepare_maintenance(body(anchor,e,'UNLOCK_STAKES',stakes={'coinIds':[h(reserve)]}),anchor=anchor,provider=provider,journal=journal)
    request=body(anchor,e,'UNLOCK_STAKES',stakes={'coinIds':[h(ids[0])]})
    for fault in ('spent','amount','spent_flag','parent_height','reveal','race'):
        class Bad(Primary):
            def __init__(self,client):super().__init__(client);self.count=0
            async def get_coin_record_by_name_primary(self,name):
                raw=deepcopy(await super().get_coin_record_by_name_primary(name))
                if name==h(ids[0]):
                    self.count+=1
                    if fault=='spent':raw['spent_block_index']=raw['confirmed_block_index'];raw['spent']=True
                    if fault=='amount':raw['coin']['amount']+=1
                    if fault=='spent_flag':raw['spent']=True
                    if fault=='race' and self.count>1:raw['confirmed_block_index']+=1
                if fault=='parent_height' and name==h((await client.get_coin_record_by_name(ids[0])).coin.parent_coin_info):raw['spent_block_index']+=1
                return raw
            async def get_puzzle_and_solution_primary(self,name,height):
                raw=deepcopy(await super().get_puzzle_and_solution_primary(name,height))
                if fault=='reveal' and name==h((await client.get_coin_record_by_name(ids[0])).coin.parent_coin_info):raw['puzzle_reveal']=bytes(Program.to(1)).hex()
                return raw
        with pytest.raises(ValueError):
            await prepare_maintenance(request.model_copy(update={'request_key':fault}),anchor=anchor,provider=Bad(client),journal=journal)
    assert journal.request_status('UNLOCK_STAKES') is None
    assert all(journal.request_status(fault) is None for fault in ('spent','amount','spent_flag','parent_height','reveal','race'))


@pytest.mark.parametrize('coins',[[],['0x'+'11'*32]*2,['0x'+'11'*32]*33,['bad']])
def test_unlock_request_rejects_empty_duplicate_oversized_or_malformed_selection(coins):
    with pytest.raises(ValueError):
        MaintenanceRequest.model_validate(dict(generationId='0x'+'11'*32,requestKey='unlock',kind='UNLOCK_STAKES',
            feeCapMojos=1,expectedInputs={name:'0x'+'22'*32 for name in ('registry','governance','holdings')},stakes={'coinIds':coins}))
