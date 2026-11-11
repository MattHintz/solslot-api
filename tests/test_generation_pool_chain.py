"""Primary-node replay of the actual stable pool authority, not launch approval."""
from dataclasses import replace

import pytest
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element, SpendBundle

from solslot_api.generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['pool'],indirect=True)
async def test_pool_reader_tracks_current_native_output_and_rejects_wrong_initial_binding(generation_chain):
    sim,client,provider,anchor,_=generation_chain
    initial=anchor.economic_components[2]
    chain=await resolve_generation_chain(anchor,provider=provider)
    history=chain.economic_components[initial.component_id]
    tip=history.verified_tip(initial.launcher_id,initial.inner())
    proof=tip.spend(initial.solution(tip.coin,'READ',b'STATE'))
    assert await client.push_tx(SpendBundle([proof],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    assert not await current_evidence_unchanged(chain,provider=provider)
    replay=await resolve_generation_chain(anchor,provider=provider)
    current=replay.economic_components[initial.component_id]
    assert current.parent_spend==proof and current.state.state()==initial.state()
    assert current.current.coin!=tip.coin and len(current.transitions)==1
    assert replay.public_status(123)['componentEvidence']['0x'+initial.component_id.hex()]['transitions']==1
    assert await current_evidence_unchanged(replay,provider=provider)
    for field in ('registry_id','generation'):
        wrong=replace(initial,**{field:type(initial.generation)(b'X'*32)})
        with pytest.raises(ValueError):
            replace(anchor,economic_components=(*anchor.economic_components[:2],wrong))
