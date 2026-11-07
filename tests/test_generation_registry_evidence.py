from copy import deepcopy
from dataclasses import replace

import pytest
import pytest_asyncio
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol, lineage_proof_for_coinsol,
    puzzle_for_singleton, solution_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, SpendBundle, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.generation_registry_evidence import resolve_registry_tip
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import Registry, Component, inner_solution
from tests.test_generation_recipient_evidence import prepared, Primary


@pytest_asyncio.fixture
async def launched(prepared):
    sim,client,primary,manifest,_,origins=prepared
    acs=Program.to(1)
    ids=[Coin(c.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name() for c in origins[:4]]
    component=Component(bytes32(b'c'*32),ids[3],load_puzzle('generation_component_v1.clsp').get_tree_hash(),
        load_puzzle('generation_extension_v1.clsp').get_tree_hash(),1,1)
    initial=Registry(bytes32.from_hexstr(manifest.generation_id),ids[0],ids[1],ids[2],(component,))
    inners=[initial.inner(),acs,acs,initial.component_inner(component,Program.to([]))]
    spends=[];launches=[]
    for origin,inner in zip(origins,inners):
        conditions,launch=launch_conditions_and_coinsol(origin,inner,[],uint64(1))
        conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
        spends.extend([make_spend(origin,acs,Program.to(conditions)),launch]);launches.append(launch)
    assert (await client.push_tx(SpendBundle(spends,G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    yield sim,client,primary,initial,inners,launches


async def pause(fixture):
    sim,client,primary,initial,inners,launches=fixture
    registry,authority=[compute_additions(launches[i])[0] for i in (0,2)]
    spend=make_spend(registry,puzzle_for_singleton(initial.launcher_id,inners[0]),
        solution_for_singleton(lineage_proof_for_coinsol(launches[0]),uint64(1),
            inner_solution('PAUSE',registry,[inners[2].get_tree_hash(),2])))
    approval=make_spend(authority,puzzle_for_singleton(initial.administrator_id,inners[2]),
        solution_for_singleton(lineage_proof_for_coinsol(launches[2]),uint64(1),Program.to([
            [66,18,Program.to([b'PAUSE_NEW_OPERATIONS',initial.generation,0,2]).get_tree_hash(),registry.puzzle_hash],
            [51,inners[2].get_tree_hash(),1]])))
    assert (await client.push_tx(SpendBundle([spend,approval],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    return spend


@pytest.mark.asyncio
async def test_confirmed_reconstruction_advances_past_old_reveal_and_is_read_only(launched):
    sim,client,primary,initial,inners,launches=launched
    first=await resolve_registry_tip(initial,provider=primary)
    assert first.state==initial and first.transition_count==0
    spend=await pause(launched)
    second=await resolve_registry_tip(initial,provider=primary)
    assert second.state==initial.paused(2) and second.transition_count==1
    assert second.current.coin!=spend.coin
    assert second.current.coin.puzzle_hash!=spend.coin.puzzle_hash
    assert await resolve_registry_tip(initial,provider=primary)==second
    assert not (await client.get_coin_record_by_name(second.current.coin.name())).spent
    with pytest.raises(ValueError,match='frozen initial'):
        await resolve_registry_tip(replace(initial,pause_mask=2),provider=primary)


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['mainnet','missing','wrong-reveal','wrong-input','bad-height','race'])
async def test_registry_evidence_rejects_inconsistent_primary_responses(launched,fault):
    _,client,_,initial,_,_=launched
    await pause(launched)
    class Changed(Primary):
        def __init__(self,client):super().__init__(client);self.reads={}
        async def get_network_info_primary(self):return {'network_name':'mainnet' if fault=='mainnet' else 'testnet11'}
        async def get_coin_record_by_name_primary(self,name):
            if fault=='missing':return None
            record=deepcopy(await super().get_coin_record_by_name_primary(name))
            self.reads[name]=self.reads.get(name,0)+1
            if fault=='bad-height' and not record['spent_block_index']:record['confirmed_block_index']+=1
            if fault=='race' and self.reads[name]>1:record['confirmed_block_index']+=1
            return record
        async def get_puzzle_and_solution_primary(self,name,height):
            record=deepcopy(await super().get_puzzle_and_solution_primary(name,height))
            if fault=='wrong-reveal':record['puzzle_reveal']=bytes(Program.to(1)).hex()
            if fault=='wrong-input':record['coin']['amount']=3
            return record
    with pytest.raises(ValueError):await resolve_registry_tip(initial,provider=Changed(client))
