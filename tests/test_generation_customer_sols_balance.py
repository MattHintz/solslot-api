"""Native CAT balance proof: count spendable CATs, reject same-hash dust.

The unit fixture substitutes an always-accept synthetic TAIL, not the deployed
Sols issuer. The public reader always derives its TAIL from native pool state.
"""
from dataclasses import replace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.vault_sols_v1 import puzzle_for_vault_sols_cat, puzzle_for_vault_sols_inner
from solslot_api.generation_customer_portfolio import _sols_balance
from tests.test_generation_customer_routes import customer, core


@pytest.mark.asyncio
async def test_confirmed_valid_cat_counted_but_unspendable_same_hash_dust_rejected(customer):
    p=customer;acs=Program.to(1);tail=Program.to([]);launcher=bytes32(b'x'*32)
    pool=next(h.state for h in p.index.evidence.economic_components.values() if isinstance(h.state,GenerationPool))
    config=replace(pool.config(),permanent_rules=replace(pool.permanent.permanent_rules,sols_tail_hash=tail.get_tree_hash()))
    target=puzzle_for_vault_sols_cat(config=config,vault_launcher_id=launcher).get_tree_hash()
    inner_target=puzzle_for_vault_sols_inner(config=config,vault_launcher_id=launcher).get_tree_hash()
    parents=[r.coin for r in await p.c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent]
    eve_puzzle=construct_cat_puzzle(CAT_MOD,tail.get_tree_hash(),acs)
    eve=Coin(parents[0].name(),eve_puzzle.get_tree_hash(),uint64(7))
    setup=[make_spend(parents[0],acs,Program.to([[51,eve.puzzle_hash,7],[51,acs.get_tree_hash(),int(parents[0].amount)-7]])),
        make_spend(parents[1],acs,Program.to([[51,target,99],[51,target,0],[51,acs.get_tree_hash(),int(parents[1].amount)-99]]))]
    assert await p.c.client.push_tx(SpendBundle(setup,G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await p.c.sim.farm_block()
    cat=SpendableCAT(eve,tail.get_tree_hash(),acs,
        Program.to([[51,inner_target,7],[51,0,-113,tail,[]]]),limitations_program_reveal=tail)
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
    assert await p.c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await p.c.sim.farm_block()
    async def query(puzzle,**kwargs):
        return [r.to_json_dict() for r in await p.c.client.get_coin_records_by_puzzle_hash(
            bytes32.from_hexstr(puzzle),include_spent_coins=False)]
    p.node.get_coin_records_by_puzzle_hash_primary=query
    observed=[]
    total,rejected=await _sols_balance(p.node,config,launcher,observed)
    assert total==7 and rejected==2
    assert len(observed)==2
