"""Confirmed SGT custody, independently of purchase/SmartDeed ID eligibility."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.vault_driver import (
    DEFAULT_IDENTITY_ATTEST_ROOT, one_leaf_merkle_root,
    puzzle_hash_for_p2_vault,
)

from .credential_auth import require_vault_record
from .sols_market import _singleton_tip
from .vault_eligibility import require_current_approved_vault
from .vault_puzzle_hash import puzzle_hash_for_vault_full
from .zkpassport_enrollments import _active_bridge_policy_hash, _active_pool_launcher_id


@dataclass(frozen=True)
class ConfirmedSGTVault:
    launcher_id: str
    p2_puzzle_hash: str
    current_coin_id: str
    identity_attest_root: str
    confirmed_block_index: int


async def require_current_sgt_vault(
    settings: Any, vault_launcher_id: str, provider: Any,
) -> ConfirmedSGTVault:
    """Prove canonical current custody; an unstamped vault can receive/vote SGT.

    Registry membership alone is insufficient. Confirm the actual standard
    launcher, execute its bounded singleton lineage, and match the registered
    owner's active-release puzzle. Stamped vaults retain the existing receipt
    verification; rotations/foreign releases require separate enrollment.
    """
    record = require_vault_record(vault_launcher_id)
    launcher = bytes32(record.launcher_id)
    key = '0x' + launcher.hex()
    p2 = puzzle_hash_for_p2_vault(launcher)
    expected = puzzle_hash_for_vault_full(
        launcher, bytes(record.owner_pubkey), int(record.auth_type),
        one_leaf_merkle_root(bytes(record.owner_pubkey)),
        bytes32.fromhex(_active_pool_launcher_id(settings).removeprefix('0x')),
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            _active_bridge_policy_hash(settings).removeprefix('0x')),
    )
    if record.full_puzhash != expected or record.p2_vault_puzhash != p2:
        raise HTTPException(409, 'Registered SGT vault does not match the active release and owner.')
    tip = await _singleton_tip(provider, key)
    if (tip is None or tip.depth < 1 or tip.live.amount != 1
            or tip.lineage[0].puzzle_hash != '0x' + SINGLETON_LAUNCHER_HASH.hex()
            or tip.lineage[1].puzzle_hash != '0x' + expected.hex()):
        raise HTTPException(409, 'A confirmed, registered protocol vault is required for SGT.')
    identity_root = '0x' + DEFAULT_IDENTITY_ATTEST_ROOT.hex()
    if tip.live.puzzle_hash != '0x' + expected.hex():
        approved = require_current_approved_vault(settings, key)
        if approved.current_coin_id != tip.live.coin_id:
            raise HTTPException(409, 'SGT vault changed during verification.')
        identity_root = approved.identity_attest_root
    return ConfirmedSGTVault(
        launcher_id=key, p2_puzzle_hash='0x' + p2.hex(),
        current_coin_id=tip.live.coin_id, identity_attest_root=identity_root,
        confirmed_block_index=tip.live.confirmed_height,
    )
