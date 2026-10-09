"""Local CLVM evidence: the deployed reserve has no bootstrap cutoff.

These inspect real puzzle outputs, including their required announcements.
They do not claim a second live transaction or replace consensus validation.
"""
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import bill_sgt_grant
from solslot_puzzles.sgt_reserve_driver import SGTReserveMode, sgt_reserve_inner_puzzle


def b32(seed):
    return bytes32(bytes([seed]) * 32)


def conditions(program):
    return [list(item.as_iter()) for item in program.as_iter()]


def opcode(value):
    return int.from_bytes(value.value, "big", signed=True)


def test_remaining_reserve_can_sponsor_another_grant_after_first_allocation():
    puzzle = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=singleton_struct(b32(1)),
        admin_authority_struct=singleton_struct(b32(2)), sgt_tail_hash=b32(3),
        wusdc_b_asset_id=b32(7), company_treasury_puzzle_hash=b32(4),
    )
    owner = bytes32(puzzle.get_tree_hash())
    first_bill = bill_sgt_grant(
        grant_id=b32(70), sgt_amount=10_000,
        recipient_vault_launcher_id=b32(5),
        reason_hash=b32(71), reserve_owner_inner_puzzle_hash=owner,
    )
    first = conditions(puzzle.run(Program.to([
        int(SGTReserveMode.GRANT), 1_000_000, [first_bill, b32(72)],
    ])))
    creates = [c for c in first if c[0].as_int() == opcode(ConditionOpcode.CREATE_COIN)]
    remainder = next(c for c in creates if c[1].as_atom() == bytes(owner))
    assert remainder[2].as_int() == 990_000
    next_bill = bill_sgt_grant(
        grant_id=b32(73), sgt_amount=10_000,
        recipient_vault_launcher_id=b32(74), reason_hash=b32(75),
        reserve_owner_inner_puzzle_hash=owner,
    )
    locked = conditions(puzzle.run(Program.to([
        int(SGTReserveMode.LOCK), remainder[2].as_int(),
        [next_bill.get_tree_hash(), next_bill, 1_900_000_000, b32(76)],
    ])))
    outputs = [c for c in locked if c[0].as_int() == opcode(ConditionOpcode.CREATE_COIN)]
    assert len(outputs) == 1 and outputs[0][2].as_int() == 990_000
    assert any(c[0].as_int() == opcode(ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT)
               for c in locked)
    assert 990_000 * 10_000 >= 5_000 * 1_000_000
