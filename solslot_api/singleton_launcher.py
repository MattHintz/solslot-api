"""Shared signed launcher for standard one-mojo Chia singletons."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    puzzle_for_singleton,
)
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from .faucet import Faucet


SINGLETON_AMOUNT = uint64(1)


@dataclass(frozen=True)
class SignedSingletonLaunch:
    launcher_id: bytes32
    launcher_coin: Coin
    inner_puzzle: Program
    full_puzzle_hash: bytes32
    spend_bundle: SpendBundle

    @property
    def spend_bundle_id(self) -> str:
        return "0x" + self.spend_bundle.name().hex()


def launcher_coin_for_parent(parent_coin: Coin) -> Coin:
    return Coin(
        parent_coin_info=bytes32(parent_coin.name()),
        puzzle_hash=SINGLETON_LAUNCHER_HASH,
        amount=SINGLETON_AMOUNT,
    )


def build_and_sign_singleton_launch(
    *,
    faucet: Faucet,
    parent_coin: Coin,
    inner_puzzle_for_launcher: Callable[[bytes32], Program],
    launcher_memos: Sequence[bytes | bytes32] = (),
    eve_memos: Sequence[bytes | bytes32] = (),
    fee: int = 0,
) -> SignedSingletonLaunch:
    """Create a standard singleton launcher and its eve coin atomically."""
    if parent_coin.puzzle_hash != faucet.address_puzzle_hash:
        raise ValueError(
            "Selected faucet coin has wrong puzzle hash; faucet key and coin record disagree"
        )
    if fee < 0:
        raise ValueError("singleton launch fee cannot be negative")
    if parent_coin.amount < SINGLETON_AMOUNT + fee:
        raise ValueError(
            f"Faucet coin {parent_coin.amount} mojos cannot cover 1 + {fee} fee"
        )

    launcher_coin = launcher_coin_for_parent(parent_coin)
    launcher_id = bytes32(launcher_coin.name())
    inner_puzzle = inner_puzzle_for_launcher(launcher_id)
    full_puzzle = puzzle_for_singleton(launcher_id, inner_puzzle)
    full_puzzle_hash = bytes32(full_puzzle.get_tree_hash())

    change = int(parent_coin.amount) - int(SINGLETON_AMOUNT) - fee
    conditions_list: list[Program] = [
        Program.to(
            [
                51,
                SINGLETON_LAUNCHER_HASH,
                SINGLETON_AMOUNT,
                list(launcher_memos),
            ]
        )
    ]
    launcher_solution = Program.to([full_puzzle_hash, SINGLETON_AMOUNT, list(eve_memos)])
    # Use Chia's native funding-to-launcher announcement commitment. A
    # launcher is signatureless; CREATE_COIN alone does not bind which
    # custody puzzle it launches and permits stripping/redirecting it.
    # All callers receive this invariant; there is no opt-out configuration.
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
    canonical_conditions, bound_launcher = launch_conditions_and_coinsol(
        parent_coin, inner_puzzle, list(eve_memos), SINGLETON_AMOUNT)
    if bound_launcher.coin != launcher_coin or bytes(bound_launcher.solution) != bytes(launcher_solution):
        raise ValueError('bound singleton launcher differs from the reviewed destination')
    conditions_list.append(canonical_conditions[1])
    if change:
        conditions_list.append(Program.to([51, parent_coin.puzzle_hash, change]))
    if fee:
        conditions_list.append(Program.to([52, fee]))
    conditions = Program.to(conditions_list)

    delegated_puzzle = Program.to((1, conditions))
    parent_solution = Program.to([0, delegated_puzzle, Program.to(0)])
    parent_spend = make_spend(parent_coin, faucet.key.puzzle, parent_solution)
    launcher_spend = make_spend(
        launcher_coin,
        SINGLETON_LAUNCHER,
        launcher_solution,
    )
    signature = G2Element.from_bytes(faucet.sign_delegated_spend(parent_coin, conditions))

    return SignedSingletonLaunch(
        launcher_id=launcher_id,
        launcher_coin=launcher_coin,
        inner_puzzle=inner_puzzle,
        full_puzzle_hash=full_puzzle_hash,
        spend_bundle=SpendBundle([parent_spend, launcher_spend], signature),
    )


__all__ = [
    "SINGLETON_AMOUNT",
    "SignedSingletonLaunch",
    "build_and_sign_singleton_launch",
    "launcher_coin_for_parent",
]
