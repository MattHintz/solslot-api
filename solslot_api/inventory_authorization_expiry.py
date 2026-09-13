"""Retire unconfirmed V2 authorizations using authenticated deployment evidence.

This does not execute a timeout, create a successor coin, or refund a payment.
Historical signatures and transaction bytes remain evidence after retirement.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.inventory_activation import validate_inventory_recovery
from solslot_puzzles.mint_publish_driver import deed_singleton_struct
from solslot_puzzles.protocol_deployment import singleton_struct
from .faucet import AGG_SIG_ME_DATA
from .inventory_expiry_clock import prove_expired_unspent_batch
from .inventory_recovery import hx, timeout_items
from .payment_purchase_store import PaymentPurchaseConflict


def expiry_conditions(spend, *, artifact: dict, launcher: str, expires_at: int):
    """Execute the exact V2 puzzle and bind its deadline and deployment."""
    try:
        reveal = Program.from_bytes(bytes(spend.puzzle_reveal))
        mod, outer = reveal.uncurry()
        struct, inner = list(outer.as_iter())
        inner_mod, args = inner.uncurry()
        args = list(args.as_iter())
        expected_struct = deed_singleton_struct(
            deed_launcher_id=bytes32.fromhex(launcher.removeprefix('0x')),
            protocol_did_singleton_struct=singleton_struct(bytes32.fromhex(artifact['launcherIds']['did'].removeprefix('0x'))))
        roster = [bytes.fromhex(k.removeprefix('0x')) for k in artifact['validatorSet']['pubkeys']]
        treasury = bytes.fromhex(artifact['puzzleHashes']['protocolTreasuryPuzzleHash'].removeprefix('0x'))
        if (mod != SINGLETON_MOD or struct != expected_struct or spend.coin.amount != 1
                or reveal.get_tree_hash() != spend.coin.puzzle_hash
                or inner_mod != load_puzzle('mint_offer_inventory_available_v2.clsp')
                or len(args) != 23 or len(roster) != 3 or artifact['validatorSet']['threshold'] != 2
                or args[19].as_atom() != treasury or args[20].as_atom() != treasury
                or [k.as_atom() for k in args[21].as_iter()] != roster):
            raise ValueError('unsupported or mismatched source')
        conditions = conditions_dict_for_solution(reveal, Program.from_bytes(bytes(spend.solution)), 100_000_000)
        deadlines = conditions.get(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE, [])
        if len(deadlines) != 1 or Program.to(deadlines[0].vars[0]).as_int() != expires_at:
            raise ValueError('signed expiry is absent or changed')
        pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA['testnet11'])
        pks, messages = [p[0] for p in pairs], [p[1] for p in pairs]
        if len(pks) != 2 or len(set(bytes(k) for k in pks)) != 2 or any(bytes(k) not in roster for k in pks):
            raise ValueError('incorrect reservation quorum')
        return pks, messages
    except (KeyError, IndexError, TypeError, ValueError, RuntimeError) as exc:
        raise PaymentPurchaseConflict('authorization does not prove the signed V2 expiry and deployment') from exc


async def reconcile_inventory_authorization_expiry(*, store, node, purchase_id: str,
                                                   artifact: dict, environment: str, authorize: Any):
    """Service-only observer. No request may provide chain or retirement evidence."""
    try:
        activation = validate_inventory_recovery(artifact, required=True, environment=environment)
    except ValueError as exc:
        raise PaymentPurchaseConflict(str(exc)) from exc
    authorize()
    stored = store.get(purchase_id)
    if stored.inventory_state == 'AUTHORIZATION_EXPIRED':
        if store.inventory_expiry_evidence(purchase_id) is None:
            raise PaymentPurchaseConflict('expired authorization is missing its retained evidence')
        return stored
    if stored.external_message is not None:
        raise PaymentPurchaseConflict('external payment evidence requires separate settlement or refund reconciliation')
    if stored.inventory_state not in {'PREPARED', 'SUBMITTED'} or stored.inventory_confirmation_height is not None:
        raise PaymentPurchaseConflict('only never-confirmed authorizations may expire; reconcile confirmed timeout separately')
    items = timeout_items(store, purchase_id)
    rows = store.inventory_items(purchase_id)
    bundle = WalletSpendBundle.from_json_dict(stored.inventory_bundle)
    public_keys, messages = [], []
    for item, row in zip(items, rows, strict=True):
        pks, msgs = expiry_conditions(item.reservation_spend, artifact=artifact,
            launcher=item.launcher, expires_at=stored.inventory_expires_at)
        try:
            signature = G2Element.from_bytes(bytes.fromhex(row.signature.removeprefix('0x')))
        except (TypeError, ValueError, AttributeError) as exc:
            raise PaymentPurchaseConflict('retained item signature is malformed') from exc
        if not AugSchemeMPL.aggregate_verify(pks, msgs, signature):
            raise PaymentPurchaseConflict('retained item signature is invalid')
        public_keys.extend(pks); messages.extend(msgs)
    if not AugSchemeMPL.aggregate_verify(public_keys, messages, bundle.aggregated_signature):
        raise PaymentPurchaseConflict('retained reservation signature is invalid')
    proofs = await prove_expired_unspent_batch(node, [item.reservation_spend.coin for item in items],
                                               stored.inventory_expires_at, 'testnet11')
    authorize()
    evidence = dict(schema='solslot.inventory-authorization-expiry.v1', purchaseId=purchase_id,
        artifactHash=artifact['artifactHash'], activation=dict(activation),
        snapshot=asdict(stored), items=[asdict(row) for row in rows], chainProofs=proofs)
    return store.record_inventory_authorization_expired(purchase_id, evidence=evidence)
