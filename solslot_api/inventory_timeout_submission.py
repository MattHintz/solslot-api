"""Durable, per-input timeout dispatch through the existing bounded fee submitter.

Only the primary node is used by the HTTP entry point. No expiry, failed push,
lease expiry or mempool receipt releases purchase locks. Chain reconciliation
remains the sole authority for the atomic batch transition to RELEASED.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Mapping

from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia.types.blockchain_format.program import Program

from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json, purchase_batch_from_json
from .inventory_recovery import (
    MIN_RELEASE_CONFIRMATIONS, TimeoutItem, decode_spend, equivalent_timeout_spend,
    hx, record_coin, reconcile_timeout_release, release_peak, timeout_items,
)
from .payment_purchase_store import PaymentPurchaseConflict, PaymentPurchaseStore


async def canonical_time(node: Any, peak: tuple[int, str]) -> int:
    """Walk a bounded hash-linked ancestry to the latest transaction timestamp."""
    height, digest = peak
    for _ in range(128):
        response = await node.get_block_record(digest)
        try:
            block = response["block_record"]
            if (response.get("success") is not True or type(block["height"]) is not int
                    or block["height"] != height or hx(bytes32.fromhex(block["header_hash"].removeprefix("0x"))) != digest):
                raise ValueError("wrong ancestor")
            timestamp = block["timestamp"]
            if timestamp is not None:
                if type(timestamp) is not int or timestamp <= 0:
                    raise ValueError("invalid transaction time")
                return timestamp
            height -= 1
            digest = hx(bytes32.fromhex(block["prev_hash"].removeprefix("0x")))
        except (KeyError, TypeError, ValueError) as exc:
            raise PaymentPurchaseConflict("canonical timeout clock is unavailable") from exc
    raise PaymentPurchaseConflict("canonical timeout clock exceeds the bounded ancestry window; retry later")


async def inspect_item(node: Any, stored: Any, item: TimeoutItem, peak: tuple[int, str]) -> str:
    """Prove original creation, then classify only an exact canonical timeout."""
    reserved = item.release_spend.coin
    created, spent = record_coin(await node.get_coin_record_by_name(hx(reserved.name())), reserved)
    if (peak[0] - created + 1 < MIN_RELEASE_CONFIRMATIONS
            or (stored.inventory_confirmation_height is not None
                and stored.inventory_confirmation_height != created)):
        raise PaymentPurchaseConflict("reservation confirmation is immature or changed")
    _, source_height = record_coin(
        await node.get_coin_record_by_name(hx(item.reservation_spend.coin.name())), item.reservation_spend.coin)
    source = decode_spend(await node.get_puzzle_and_solution(
        hx(item.reservation_spend.coin.name()), source_height), item.reservation_spend.coin)
    if source_height != created or source != item.reservation_spend:
        raise PaymentPurchaseConflict("reservation creation differs from the retained signed spend")
    if not spent:
        return "UNSPENT"
    canonical = decode_spend(await node.get_puzzle_and_solution(hx(reserved.name()), spent), reserved)
    if not equivalent_timeout_spend(canonical, item.release_spend):
        raise PaymentPurchaseConflict("reserved coin was spent by another operation; manual reconciliation required")
    child_height, child_spent = record_coin(
        await node.get_coin_record_by_name(hx(item.successor.name())), item.successor)
    if spent > peak[0] or child_height != spent or child_spent:
        raise PaymentPurchaseConflict("timeout successor is unavailable or inconsistent")
    return "CONFIRMED" if peak[0] - spent + 1 >= MIN_RELEASE_CONFIRMATIONS else "CONFIRMING"


def validate_prepared(prepared: Mapping[str, Any], item: TimeoutItem) -> None:
    """Reject mutated durable bundles or a submitter returning unrelated inputs."""
    try:
        bundle = SpendBundle.from_json_dict(prepared["spendBundle"])
        spends = bundle.coin_spends
        fee_id = prepared["feeCoinId"]
        if (prepared["spendBundleId"] != hx(bundle.name()) or len(spends) != 2
                or sum(spend == item.release_spend for spend in spends) != 1
                or sum(hx(spend.coin.name()) == fee_id for spend in spends) != 1
                or fee_id == hx(item.release_spend.coin.name())
                or type(prepared["feeMojos"]) is not str or not prepared["feeMojos"].isdigit()
                or int(prepared["feeMojos"]) <= 0):
            raise ValueError("changed timeout bundle")
        # Execute the actual puzzles; fee and release output must match the claim.
        additions = bundle.additions()
        if (sum(coin == item.successor for coin in additions) != 1
                or sum(int(c.amount) for c in bundle.removals()) - sum(int(c.amount) for c in additions)
                != int(prepared["feeMojos"])):
            raise ValueError("changed timeout outputs or fee")
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise PaymentPurchaseConflict("durable timeout bundle is inconsistent") from exc


async def advance_inventory_timeout(*, store: PaymentPurchaseStore, node: Any, submitter: Any,
                                    purchase_id: str, network: str,
                                    release_binding: Mapping[str, Any], authorize: Any) -> dict[str, Any]:
    """Prepare or resume exact releases. Calling again safely advances recovery."""
    authorize()
    if network != "testnet11":
        raise PaymentPurchaseConflict("timeout dispatch is available only on testnet11")
    stored = store.get(purchase_id)
    raw = stored.purchase_artifact
    purchases = (purchase_batch_from_json(raw).artifacts if raw.get("schema") == "solslot.purchase-batch.v1"
                 else (purchase_artifact_v3_from_json(raw),))
    if any(p.network != network for p in purchases):
        raise PaymentPurchaseConflict("timeout network differs from the original purchase")
    if (release_binding.get("network") != network or release_binding.get("adapterVersion") != 1
            or release_binding.get("environment") not in ("staging-alpha", "production-alpha")
            or not isinstance(release_binding.get("sourceShas"), dict)
            or not release_binding["sourceShas"]):
        raise PaymentPurchaseConflict("timeout deployment/release binding is incomplete")
    try:
        bytes32.fromhex(release_binding["artifactHash"].removeprefix("0x"))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise PaymentPurchaseConflict("timeout artifact binding is incomplete") from exc
    if stored.inventory_state == "RELEASED":
        return dict(purchaseId=purchase_id, state="RELEASED", items=[],
                    releaseEvidence=store.inventory_release_evidence(purchase_id))
    items = timeout_items(store, purchase_id)
    # A retained purchase from another deployment must not use this deployment's
    # fee till. Bind the actual source puzzle's treasury and ordered validators.
    try:
        treasury = bytes.fromhex(release_binding["protocolTreasuryPuzzleHash"].removeprefix("0x"))
        validators = [bytes.fromhex(k.removeprefix("0x")) for k in release_binding["validatorPubkeys"]]
        if len(treasury) != 32 or len(validators) != 3 or any(len(k) != 48 for k in validators):
            raise ValueError("incomplete deployment coordinates")
        for item in items:
            _, outer = Program.from_bytes(bytes(item.reservation_spend.puzzle_reveal)).uncurry()
            _, args = list(outer.as_iter())[1].uncurry()
            values = list(args.as_iter())
            if values[19].as_atom() != treasury or values[20].as_atom() != treasury or [k.as_atom() for k in values[21].as_iter()] != validators:
                raise ValueError("reservation belongs to another deployment")
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        raise PaymentPurchaseConflict("timeout source does not match the signed deployment") from exc
    # Validate the complete batch before funding any remaining input.
    peak = await release_peak(node, network)
    statuses = [await inspect_item(node, stored, item, peak) for item in items]
    if any(status == "UNSPENT" for status in statuses):
        if await canonical_time(node, peak) < stored.inventory_expires_at:
            raise PaymentPurchaseConflict("reservation has not expired on the canonical chain")
    if await release_peak(node, network) != peak:
        raise PaymentPurchaseConflict("chain tip changed during timeout preflight; retry later")
    outcomes = []
    for item, status in zip(items, statuses, strict=True):
        if status != "UNSPENT":
            outcomes.append(dict(ordinal=item.ordinal, state=status))
            continue
        binding = dict(release_binding, purchaseId=purchase_id, artifactHashOfPurchase=stored.artifact_hash,
                       reservationBundle=stored.inventory_bundle, ordinal=item.ordinal,
                       reservedCoinId=hx(item.release_spend.coin.name()),
                       availableCoinId=hx(item.successor.name()), expiresAt=stored.inventory_expires_at)
        owner = uuid.uuid4().hex
        prepared = store.claim_inventory_timeout(purchase_id, item.ordinal, binding=binding,
                                                owner=owner, now=int(time.time()))
        receipt = None
        try:
            async def before_push(value=None):
                authorize()
                current = store.get(purchase_id)
                if current.inventory_state not in ("PREPARED", "SUBMITTED", "CONFIRMED"):
                    raise PaymentPurchaseConflict("inventory lifecycle changed before timeout dispatch")
                fresh_peak = await release_peak(node, network)
                if await inspect_item(node, current, item, fresh_peak) != "UNSPENT":
                    raise PaymentPurchaseConflict("timeout input changed before dispatch; reconcile again")
                if await canonical_time(node, fresh_peak) < current.inventory_expires_at:
                    raise PaymentPurchaseConflict("canonical chain time is before reservation expiry")
                if await release_peak(node, network) != fresh_peak:
                    raise PaymentPurchaseConflict("chain tip changed before dispatch; retry later")
                exact = value.to_json() if value is not None else prepared
                validate_prepared(exact, item)
                store.preserve_inventory_timeout(purchase_id, item.ordinal, owner=owner,
                                                 now=int(time.time()), prepared=exact)
            if prepared:
                validate_prepared(prepared, item)
                receipt = await submitter.reconcile_reserved(prepared, before_push=before_push)
            else:
                bundle = SpendBundle([item.release_spend], G2Element())
                receipt = await submitter.submit(bundle.to_json_dict(), before_push=before_push)
            outcomes.append(dict(ordinal=item.ordinal, state="SUBMITTED", transactionId=receipt["spendBundleId"]))
        finally:
            store.finish_inventory_timeout_attempt(purchase_id, item.ordinal, owner=owner, receipt=receipt)
    if all(status == "CONFIRMED" for status in statuses):
        result = await reconcile_timeout_release(store, node, purchase_id, network)
        return dict(purchaseId=purchase_id, state=result.inventory_state, items=outcomes,
                    releaseEvidence=store.inventory_release_evidence(purchase_id))
    return dict(purchaseId=purchase_id, state="RECOVERY_PENDING", items=outcomes, releaseEvidence=None)
