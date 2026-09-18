"""Exact vault-owned SGT first stake for selected V2 mint publication."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    sgt_free_inner_puzzle, sgt_free_inner_mod, sgt_locked_inner_mod,
    sgt_locked_inner_puzzle, build_sgt_lock_coin_spend,
)
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, puzzle_for_p2_vault, one_leaf_merkle_root
from solslot_puzzles.vault_v2_driver import (
    build_vault_sgt_lock_spend, puzzle_for_vault_v2_inner,
    inner_solution_for_p2_vault_sgt_lock, sgt_lock_operation_hash,
    eip712_typed_data_for_sgt_lock,
)
from .credential_auth import require_vault_record
from .governance_publisher import _b32, _hex32, _coin, _mapping
from .sols_swaps import _confirmed_coin_and_lineage
from .sgt_lineage import confirmed_sgt_lineage
from .vault_eligibility import require_current_approved_vault
from .mint_publication import MintPublicationContext


@dataclass(frozen=True)
class MintStakeBuild:
    bundle: SpendBundle
    operation_hash: bytes32
    vault_launcher_id: bytes32
    vault_coin_id: bytes32
    owner_inner_hash: bytes32
    vault_auth_type: str
    vault_typed_data: dict | None
    sgt_coin_id: bytes32
    sgt_coin: object
    amount: int
    available_amounts: tuple[int, ...]
    locked_inner_hash: bytes32


async def build_mint_stake(*, context: MintPublicationContext, provider, settings,
    vault_launcher_id: str, stake_amount: int, proposal_hash: bytes32,
    deadline: int, signature_data: bytes | None = None) -> MintStakeBuild:
    if stake_amount < context.statutes.parameters.min_proposal_stake:
        raise ValueError('mint stake is below the current minimum proposal stake')
    plan = _mapping(context.artifact.get('genesisPlan', context.artifact), 'genesisPlan')
    launchers = _mapping(plan.get('launcherIds'), 'launcherIds')
    pool_launcher = _b32(launchers.get('pool'), 'pool launcher')
    sgt_tail = _b32(context.artifact.get('sgtTailHash') or
        _mapping(plan.get('permanentRules'), 'permanentRules').get('sgtTailHash'), 'SGT tail')
    tracker_struct = singleton_struct(context.tracker_launcher)
    approved = require_current_approved_vault(settings, vault_launcher_id)
    vault_record = require_vault_record(approved.launcher_id)
    if vault_record.auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise ValueError("vault owner authorization is unsupported")
    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        provider,
        approved.current_coin_id,
        "approved vault coin",
    )
    vault_launcher = _b32(approved.launcher_id, "approved vault launcher")
    owner_inner = puzzle_for_p2_vault(vault_launcher)
    owner_inner_hash = bytes32(owner_inner.get_tree_hash())
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        owner_inner_hash,
    )
    sgt_full = construct_cat_puzzle(CAT_MOD, sgt_tail, free_inner)
    records = await provider.get_coin_records_by_puzzle_hash(
        _hex32(sgt_full.get_tree_hash()), include_spent=False
    )
    candidates = sorted(
        [
            coin
            for item in records
            if isinstance(item, Mapping)
            and int(item.get("confirmed_block_index") or 0) > 0
            and int(item.get("spent_block_index") or 0) == 0
            and not bool(item.get("spent"))
            and (coin := _coin(item)) is not None
        ],
        key=lambda coin: (int(coin.amount), bytes(coin.name())),
    )
    available = tuple(int(coin.amount) for coin in candidates)
    matches = [coin for coin in candidates if int(coin.amount) == stake_amount]
    if not matches:
        readable = ", ".join(str(value) for value in available) or "none"
        raise ValueError(
            "stake amount must equal one vault-held SGT coin; "
            f"available amounts: {readable}"
        )
    sgt_coin = matches[0]
    if await provider.get_mempool_items_by_coin_name(_hex32(sgt_coin.name())):
        raise ValueError("the selected SGT stake is already pending in the mempool")
    sgt_lineage = await confirmed_sgt_lineage(
        provider=provider,
        coin=sgt_coin,
        expected_inner_hash=bytes32(free_inner.get_tree_hash()),
        expected_tail_hash=sgt_tail,
    )
    locked_inner = sgt_locked_inner_puzzle(
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        tracker_struct,
        owner_inner_hash,
        proposal_hash,
        deadline,
    )
    locked_inner_hash = bytes32(locked_inner.get_tree_hash())
    members_root = one_leaf_merkle_root(bytes(vault_record.owner_pubkey))
    policy_hash = _b32(
        settings.zkpassport_bridge_policy_hash,
        "zkPassport bridge policy hash",
    )
    vault_inner = puzzle_for_vault_v2_inner(
        vault_launcher_id=vault_launcher,
        owner_pubkey=bytes(vault_record.owner_pubkey),
        auth_type=vault_record.auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=pool_launcher,
        identity_attest_root=_b32(
            approved.identity_attest_root,
            "approved vault identity root",
        ),
        zkpassport_bridge_policy_hash=policy_hash,
    )
    vault_spend = build_vault_sgt_lock_spend(
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher,
        owner_pubkey=bytes(vault_record.owner_pubkey),
        auth_type=vault_record.auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=pool_launcher,
        identity_attest_root=_b32(
            approved.identity_attest_root,
            "approved vault identity root",
        ),
        zkpassport_bridge_policy_hash=policy_hash,
        sgt_coin_id=sgt_coin.name(),
        proposal_hash=proposal_hash,
        lock_deadline=deadline,
        locked_inner_puzzle_hash=locked_inner_hash,
        lineage_proof=vault_lineage,
        signature_data=signature_data,
    )
    owner_solution = inner_solution_for_p2_vault_sgt_lock(
        vault_coin_id=vault_coin.name(),
        vault_inner_puzzle_hash=bytes32(vault_inner.get_tree_hash()),
        sgt_coin_id=sgt_coin.name(),
        sgt_free_inner_puzzle_hash=bytes32(free_inner.get_tree_hash()),
        sgt_amount=stake_amount,
        locked_inner_puzzle_hash=locked_inner_hash,
    )
    sgt_spend = build_sgt_lock_coin_spend(
        sgt_coin=sgt_coin,
        voter_inner_puzzle=owner_inner,
        voter_inner_solution=owner_solution,
        proposal_tracker_struct=tracker_struct,
        sgt_tail_hash=sgt_tail,
        lineage_proof=sgt_lineage,
        proposal_hash=proposal_hash,
        deadline=deadline,
    )
    operation_hash = sgt_lock_operation_hash(
        vault_coin_id=vault_coin.name(), sgt_coin_id=sgt_coin.name(),
        proposal_hash=proposal_hash, lock_deadline=deadline,
        locked_inner_puzzle_hash=locked_inner_hash,
    )
    return MintStakeBuild(SpendBundle([vault_spend, sgt_spend], G2Element()),
        operation_hash, vault_launcher, vault_coin.name(), owner_inner_hash,
        'chia_bls' if vault_record.auth_type == AUTH_TYPE_BLS else 'evm',
        eip712_typed_data_for_sgt_lock(operation_hash, vault_coin.name())
            if vault_record.auth_type == AUTH_TYPE_SECP256K1 else None,
        sgt_coin.name(), sgt_coin, stake_amount, available, locked_inner_hash)
