"""Vault launcher composition.

Given:
  - a recovered 33-byte compressed secp256k1 pubkey (for EVM) or 48-byte BLS
    G1 (for Chia wallet)
  - the configured faucet (funds 1 mojo + fee)
  - the configured pool_launcher_id

Builds a *signed* SpendBundle that:
  1. Spends one faucet coin → creates (a) the singleton launcher coin
     with the vault's curried puzzle hash and (b) a change output back to
     the faucet.
  2. Spends the launcher coin → creates the vault singleton.

The launcher spend itself carries no AGG_SIG requirement (the launcher
puzzle is `(mod (singleton_full_puzzle_hash amount key_value_list) ...)`
— signatureless).  Only the faucet parent spend needs a BLS signature.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    one_leaf_merkle_root,
    puzzle_for_vault_inner,
    vault_discovery_hint,
)

from .faucet import Faucet
from .singleton_launcher import (
    SINGLETON_AMOUNT,
    build_and_sign_singleton_launch,
    launcher_coin_for_parent,
)

logger = logging.getLogger(__name__)

@dataclass
class LaunchedVault:
    """Result of building + signing a vault launch spend bundle."""

    vault_launcher_id: bytes32
    vault_full_puzhash: bytes32
    p2_vault_puzhash: bytes32  # Derived separately by the driver
    spend_bundle: SpendBundle
    owner_pubkey: bytes
    auth_type: int

    @property
    def spend_bundle_id(self) -> str:
        return "0x" + self.spend_bundle.name().hex()


def build_and_sign_launch(
    *,
    faucet: Faucet,
    faucet_coin_json: dict,
    owner_pubkey: bytes,
    auth_type: int,
    pool_launcher_id: bytes32,
    zkpassport_bridge_policy_hash: bytes32,
    fee: int = 0,
    generation_vault: bool = False,
) -> LaunchedVault:
    """Build and sign the vault launch SpendBundle.

    `faucet_coin_json` is a coin record dict from coinset.org (must match
    `faucet.address_puzzle_hash` and have amount ≥ 1 + fee).
    """
    coin_payload = faucet_coin_json.get("coin") or faucet_coin_json
    parent_coin = Coin(
        parent_coin_info=_bytes32(coin_payload["parent_coin_info"]),
        puzzle_hash=_bytes32(coin_payload["puzzle_hash"]),
        amount=uint64(int(coin_payload["amount"])),
    )
    if parent_coin.puzzle_hash != faucet.address_puzzle_hash:
        raise ValueError(
            "Selected faucet coin has wrong puzzle hash; faucet key and coin record disagree"
        )
    if parent_coin.amount < SINGLETON_AMOUNT + fee:
        raise ValueError(
            f"Faucet coin {parent_coin.amount} mojos cannot cover 1 + {fee} fee"
        )

    members_root = one_leaf_merkle_root(owner_pubkey)
    discovery_hint = vault_discovery_hint(auth_type, owner_pubkey)
    def custody_inner(launcher_id):
        if generation_vault:
            from solslot_puzzles.generation_vault import vault_inner
            return vault_inner(vault_launcher_id=launcher_id,owner_pubkey=owner_pubkey,auth_type=auth_type,
                members_merkle_root=members_root,pool_launcher_id=pool_launcher_id,
                zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash)
        return puzzle_for_vault_inner(launcher_id,owner_pubkey,auth_type,members_root,pool_launcher_id,
            zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash)
    launched = build_and_sign_singleton_launch(
        faucet=faucet,
        parent_coin=parent_coin,
        inner_puzzle_for_launcher=custody_inner,
        launcher_memos=(discovery_hint,),
        fee=fee,
    )

    return LaunchedVault(
        vault_launcher_id=launched.launcher_id,
        vault_full_puzhash=launched.full_puzzle_hash,
        p2_vault_puzhash=bytes32(b"\x00" * 32),  # filled in by caller (driver helper)
        spend_bundle=launched.spend_bundle,
        owner_pubkey=owner_pubkey,
        auth_type=auth_type,
    )


def _launcher_coin_for_parent(parent_coin: Coin) -> Coin:
    """Exact mirror of solslot_puzzles.vault_driver.launcher_coin_for_parent."""
    return launcher_coin_for_parent(parent_coin)


def _agg_sig_message(launcher_coin: Coin) -> bytes:
    """Payload the faucet attests to — the launcher coin id being created."""
    return bytes(launcher_coin.name())


def _bytes32(h: str) -> bytes32:
    clean = h[2:] if h.startswith("0x") else h
    return bytes32.fromhex(clean)


__all__ = [
    "AUTH_TYPE_BLS",
    "AUTH_TYPE_SECP256K1",
    "LaunchedVault",
    "build_and_sign_launch",
]
