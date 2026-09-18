"""Completed governance must retain live policy and owner-preserving SGT lineage."""
from types import SimpleNamespace

import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin
from chia_rs.sized_ints import uint64

from solslot_api.governance_publisher import _idle_tracker_from_parent, _reserve_locked_parent
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    bill_sgt_grant, build_tracker_execute_coin_spend, sgt_free_inner_mod,
    sgt_locked_inner_puzzle,
)
from tests.test_alpha_fresh_lifecycle import B, CONSTANTS, fresh_genesis
from tests.test_alpha_fresh_governance import live, parent_spend
from tests.test_alpha_governance_lifecycle import tracker


@pytest.mark.asyncio
async def test_idle_tracker_recovers_prior_policy_without_changing_immutable_coordinates():
    async with SpendSim.managed(None, defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim, client)
        p = world.plan.protocol
        original = tracker(world)
        module, args = original.uncurry()
        values = list(args.as_iter())
        values[10] = Program.to(6000)
        bill = bill_sgt_grant(grant_id=B(180), sgt_amount=100_000,
            recipient_vault_launcher_id=B(181), reason_hash=B(182),
            reserve_owner_inner_puzzle_hash=p.sgt_reserve_inner_puzzle_hash)
        values[15:] = [Program.to(bill.get_tree_hash()), bill, Program.to(1_000_000), Program.to(300)]
        active = module.curry(*values)
        # This is a CLVM reconstruction control, not a claimed on-chain policy update.
        genesis = await live(client, p.governance_full_puzzle_hash)
        launcher_spend = await parent_spend(client, genesis)
        active_coin = Coin(p.governance_launcher_id, puzzle_for_singleton(p.governance_launcher_id, active).get_tree_hash(), uint64(1))
        executed = build_tracker_execute_coin_spend(tracker_coin=active_coin,
            tracker_inner_puzzle=active, tracker_launcher_id=p.governance_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(launcher_spend))
        successor = compute_additions(executed)[0]
        expected = module.curry(*values[:15], 0, 0, 0, 0)
        assert expected != original
        context = SimpleNamespace(coin=successor, parent_spend=executed)
        assert _idle_tracker_from_parent(context, original, p.governance_launcher_id) == expected
        altered_expected = list(args.as_iter())
        altered_expected[6] = Program.to(B(183))
        with pytest.raises(ValueError, match='immutable coordinates'):
            _idle_tracker_from_parent(context, module.curry(*altered_expected), p.governance_launcher_id)
        changed_child = SimpleNamespace(coin=Coin(successor.parent_coin_info, B(184), uint64(1)), parent_spend=executed)
        with pytest.raises(ValueError, match='did not create'):
            _idle_tracker_from_parent(changed_child, original, p.governance_launcher_id)


def test_locked_parent_only_accepts_canonical_tracker_and_reserve_owner():
    struct, owner = singleton_struct(B(185)), B(186)
    inner = sgt_locked_inner_puzzle(sgt_free_inner_mod().get_tree_hash(), struct, owner, B(187), 1900000000)
    assert _reserve_locked_parent(inner, struct, owner)
    assert not _reserve_locked_parent(inner, singleton_struct(B(188)), owner)
    assert not _reserve_locked_parent(inner, struct, B(189))
    assert not _reserve_locked_parent(Program.to(1), struct, owner)
