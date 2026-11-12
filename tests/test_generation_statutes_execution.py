"""Actual chain state -> saved typed review -> governed record execution."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia_rs.sized_ints import uint64
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from solslot_puzzles.protocol_statutes_v1 import CollectionStatute
from solslot_api.generation_chain_evidence import resolve_generation_chain,public_bill
from solslot_api.generation_execution import MaintenanceRequest,StatuteIntent,prepare_maintenance
from solslot_api.generation_operations import GenerationOperationJournal
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared
from tests.test_generation_execution import open_native,body,h


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['statutes'],indirect=True)
async def test_exact_statutes_execution_reconstructs_record_roots_and_resumes_without_node(generation_chain,prepared,tmp_path):
    sim,client,provider,anchor,_=generation_chain
    state=anchor.economic_components[1]
    # Synthetic test recap NAV; this does not assert Eastmoreland ownership or
    # substitute its unfinished appraisal/diligence packet.
    record=CollectionStatute(bytes.fromhex('91'*32),75_000_000_000,75_000_000_000,1,0,2**32,1)
    bill,expected,entries=state.record_change('COLLECTION',(),record)
    proposal,_=await open_native(generation_chain,prepared,lambda e:bill)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE'):
        e=await resolve_generation_chain(anchor,provider=provider)
        saved=await prepare_maintenance(body(anchor,e,kind),anchor=anchor,provider=provider,journal=journal)
        if kind=='FINALIZE_VOTE':sim.pass_time(uint64(3601));await sim.farm_block()
        assert await client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider)
    public=e.public_status(100)
    action=public['approvedActions'][0]
    assert action['statutes']==public_bill(bill)['statutes']
    intent=dict(action['statutes'],currentRecords=public['statutesWitnesses'][h(state.component_id)]['COLLECTION'])
    inputs={name:h(getattr(e,name).current.coin.name()) for name in ('registry','governance','holdings')}
    req=MaintenanceRequest.model_validate(dict(generationId=h(state.generation),requestKey='fact',kind='APPLY_STATUTES',
        proposalId=h(proposal),feeCapMojos=1000,expectedInputs=inputs|{'components':{h(state.component_id):h(e.economic_components[state.component_id].current.coin.name())}},statutes=intent))
    for fault in ('root','record','revision','key','witness','proposal','input'):
        raw=deepcopy(req.document());raw['requestKey']=fault
        if fault=='root':raw['statutes']['nextRoot']='0x'+'ff'*32
        if fault=='record':raw['statutes']['record'][1]+=1
        if fault=='revision':raw['statutes']['revision']+=1
        if fault=='key':raw['statutes']['key']='0x'+'ff'*32
        if fault=='witness':raw['statutes']['currentRecords']=[raw['statutes']['record']]
        if fault=='proposal':raw['proposalId']='0x'+'ff'*32
        if fault=='input':raw['expectedInputs']['components']={}
        with pytest.raises(ValueError):
            await prepare_maintenance(MaintenanceRequest.model_validate(raw),anchor=anchor,provider=provider,journal=journal)
    saved=await prepare_maintenance(req,anchor=anchor,provider=provider,journal=journal)
    bundle=journal.protocol_bundle(saved['operationId'])
    assert saved['review']['statutes']==intent
    assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    new=await resolve_generation_chain(anchor,provider=provider)
    assert new.economic_components[state.component_id].state.state()==expected.state()
    assert not new.public_status(101)['approvedActions']
    assert new.public_status(101)['statutesWitnesses'][h(state.component_id)]['COLLECTION']==[intent['record']]
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('cached retry must not rebuild')))
    restored=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    assert await prepare_maintenance(req,anchor=anchor,provider=offline,journal=restored)==saved
    assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS


def test_statutes_intent_rejects_retired_pause_and_voting_mutations():
    base=dict(componentId='0x'+'11'*32,launcherId='0x'+'12'*32,revision=0,key='0x'+'91'*32,
        recordKind='PAUSE',record=['0x'+'91'*32,1,2,'0x'+'13'*32],
        previousRoot='0x'+'14'*32,nextRoot='0x'+'15'*32,currentRecords=[])
    for kind in ('PAUSE','PARAMETER','QUORUM','SUPPLY'):
        with pytest.raises(ValueError):StatuteIntent.model_validate(base|{'recordKind':kind})
