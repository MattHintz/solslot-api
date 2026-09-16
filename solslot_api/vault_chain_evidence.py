"""Canonical, bounded single-owner vault history shared by API and validators.

Only continuations that retain the enrolled owner, release and credential are
eligible. Key rotation or a changed credential requires separate enrollment.
The node supplies confirmed coin records; no coordinator-selected child or
receipt is accepted as a substitute for their parent links.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

MAX_VAULT_HISTORY = 512


class VaultHistoryError(ValueError):
    pass


@dataclass(frozen=True)
class ConfirmedVaultCoin:
    coin: Coin
    confirmed_height: int
    spent_height: int


def read_vault_coin(record: Mapping[str, Any] | None, expected_id: bytes32) -> ConfirmedVaultCoin:
    try:
        if not isinstance(record, Mapping):
            raise ValueError("coin record is unavailable")
        raw = record["coin"]
        amount = raw["amount"]
        confirmed = record["confirmed_block_index"]
        spent = record["spent_block_index"]
        if type(amount) is not int or amount != 1:
            raise ValueError("vault amount must be one mojo")
        if type(confirmed) is not int or confirmed <= 0 or type(spent) is not int or spent < 0:
            raise ValueError("invalid confirmation or spend height")
        if spent and spent < confirmed:
            raise ValueError("spend precedes confirmation")
        if "spent" in record and (type(record["spent"]) is not bool or record["spent"] != bool(spent)):
            raise ValueError("inconsistent spent flag")
        coin = Coin(bytes32.fromhex(raw["parent_coin_info"].removeprefix("0x")),
                    bytes32.fromhex(raw["puzzle_hash"].removeprefix("0x")), uint64(amount))
        if coin.name() != expected_id:
            raise ValueError("coin fields do not match the requested ID")
        return ConfirmedVaultCoin(coin, confirmed, spent)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise VaultHistoryError(f"Invalid vault history: {exc}") from exc


FetchCoin = Callable[[bytes32], Mapping[str, Any] | None]


def verify_enrolled_vault_tip(
    *, tip_id: bytes32, launcher_id: bytes32, unstamped_puzzle_hash: bytes32,
    stamped_puzzle_hash: bytes32, fetch_coin: FetchCoin,
) -> tuple[ConfirmedVaultCoin, bytes32]:
    """Prove a current tip back through its stamp, eve and actual launcher."""
    tip = read_vault_coin(fetch_coin(tip_id), tip_id)
    if tip.spent_height:
        raise VaultHistoryError("The approved vault tip is already spent")
    current = tip
    seen: set[bytes32] = set()
    for _ in range(MAX_VAULT_HISTORY):
        coin = current.coin
        if coin.name() in seen or coin.puzzle_hash != stamped_puzzle_hash:
            raise VaultHistoryError("Vault history changed owner, credential or release")
        seen.add(coin.name())
        parent_id = coin.parent_coin_info
        parent = read_vault_coin(fetch_coin(parent_id), parent_id)
        if parent.spent_height != current.confirmed_height:
            raise VaultHistoryError("Vault history lacks an atomic confirmed parent spend")
        if parent.coin.parent_coin_info == launcher_id:
            if parent.coin.puzzle_hash != unstamped_puzzle_hash:
                raise VaultHistoryError("Vault stamp does not descend from the enrolled eve")
            launcher = read_vault_coin(fetch_coin(launcher_id), launcher_id)
            if (launcher.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH
                    or launcher.spent_height != parent.confirmed_height):
                raise VaultHistoryError("Vault launcher lineage is not confirmed")
            # A spend between the first read and the ancestry check invalidates
            # the claim; callers also recheck inputs immediately before dispatch.
            if read_vault_coin(fetch_coin(tip_id), tip_id) != tip:
                raise VaultHistoryError("Vault tip changed during verification")
            return tip, coin.name()
        current = parent
    raise VaultHistoryError("Vault history exceeds the verification bound")


def resolve_enrolled_vault_tip(
    *, stamp_id: bytes32, launcher_id: bytes32, unstamped_puzzle_hash: bytes32,
    stamped_puzzle_hash: bytes32, fetch_coin: FetchCoin,
) -> tuple[ConfirmedVaultCoin, bytes32]:
    """Follow the unique one-mojo, unchanged-puzzle continuation from the stamp."""
    current_id = stamp_id
    for _ in range(MAX_VAULT_HISTORY):
        current = read_vault_coin(fetch_coin(current_id), current_id)
        if current.coin.puzzle_hash != stamped_puzzle_hash:
            raise VaultHistoryError("Vault history changed owner, credential or release")
        if not current.spent_height:
            tip, proved_stamp = verify_enrolled_vault_tip(
                tip_id=current_id, launcher_id=launcher_id,
                unstamped_puzzle_hash=unstamped_puzzle_hash,
                stamped_puzzle_hash=stamped_puzzle_hash, fetch_coin=fetch_coin,
            )
            if proved_stamp != stamp_id:
                raise VaultHistoryError("Receipt does not identify the original vault stamp")
            return tip, proved_stamp
        # Consensus permits exactly one odd-valued singleton child. Its ID is
        # determined by these fields; an unrelated child cannot become the tip.
        current_id = Coin(current_id, stamped_puzzle_hash, uint64(1)).name()
    raise VaultHistoryError("Vault history exceeds the verification bound")
