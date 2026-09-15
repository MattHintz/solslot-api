"""Sanitized retained inventory receipts. Reading does not prove current holdings."""
from dataclasses import asdict
import re
from types import SimpleNamespace

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json, purchase_batch_from_json
from .bootstrap_manifest import content_hash
from .inventory_expiry_clock import MAX_CLOCK_HOPS
from .inventory_recovery import decode_spend, equivalent_timeout_spend, hx, timeout_items
from .payment_purchase_store import PaymentPurchaseConflict


def _hex(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]{64}", value):
        raise ValueError("invalid identifier")
    return value


def _positive(value):
    if type(value) is not int or value <= 0:
        raise ValueError("invalid positive integer")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"(sha256:|0x)[0-9a-f]{64}", value):
        raise ValueError("invalid digest")
    return value


def _expiry_activation(receipt, network):
    """Check retained activation content; this does not reauthenticate a release."""
    if _hex(receipt["artifactHash"]) == "0x" + "0" * 64:
        raise ValueError("missing recovery release")
    activation = receipt["activation"]
    expected = dict(schema="solslot.inventory-recovery.v1", network=network,
        inventoryVersion=2, adapterVersion=1, validatorLedgerVersion=10, minConfirmations=3,
        availableModuleHash=hx(load_puzzle("mint_offer_inventory_available_v2.clsp").get_tree_hash()))
    if (set(activation) != set(expected) | {"environment", "deploymentId", "sourceShas", "reviewEvidenceSha256", "historicalArtifactHashes"}
            or any(activation.get(k) != v or type(activation.get(k)) is not type(v) for k, v in expected.items())
            or activation["environment"] not in {"staging-alpha", "production-alpha"}
            or _hex(activation["deploymentId"]) == "0x" + "0" * 64
            or not isinstance(activation["sourceShas"], dict) or not activation["sourceShas"]
            or any(not isinstance(k, str) or not k or not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{40}", v)
                   for k, v in activation["sourceShas"].items())
            or not isinstance(activation["reviewEvidenceSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", activation["reviewEvidenceSha256"])
            or activation["reviewEvidenceSha256"] == "0" * 64):
        raise ValueError("incomplete recovery activation")
    history = activation["historicalArtifactHashes"]
    if (not isinstance(history, list) or len(history) > 32
            or any(_hex(value) == "0x" + "0" * 64 for value in history)
            or len(set(history)) != len(history)):
        raise ValueError("invalid recovery history")


def _expiry_clock(proof, coin, expires_at, network):
    """Validate the retained bounded clock without demanding a live chain tip."""
    peak = _positive(proof["peakHeight"])
    digest = _hex(proof["peakHash"])
    mature_height = peak - 2
    ancestors = proof["ancestors"]
    if (proof["schema"] != "solslot.inventory-expiry-chain.v1" or proof["network"] != network
            or proof["sourceCoin"] != coin.to_json_dict() or proof["sourceCoinId"] != hx(coin.name())
            or _positive(proof["sourceConfirmationHeight"]) > mature_height
            or type(proof["expiresAt"]) is not int or proof["expiresAt"] != expires_at
            or type(proof["minConfirmations"]) is not int or proof["minConfirmations"] != 3
            or _positive(proof["matureTimestamp"]) < expires_at
            or not isinstance(ancestors, list) or not 1 <= len(ancestors) <= MAX_CLOCK_HOPS):
        raise ValueError("invalid expiry chain proof")
    newer_timestamp = None
    for offset, block in enumerate(ancestors):
        height = peak - offset
        if (height < 0 or type(block["height"]) is not int or block["height"] != height
                or block["headerHash"] != digest):
            raise ValueError("broken expiry ancestry")
        digest = _hex(block["previousHash"])
        timestamp = block["timestamp"]
        if timestamp is not None:
            _positive(timestamp)
            if newer_timestamp is not None and timestamp >= newer_timestamp:
                raise ValueError("inconsistent expiry clock")
            newer_timestamp = timestamp
        if height <= mature_height and timestamp is not None:
            if offset != len(ancestors) - 1 or timestamp != proof["matureTimestamp"]:
                raise ValueError("expiry clock did not stop at first mature timestamp")
            return
    raise ValueError("expiry clock lacks a mature timestamp")


def retained_inventory_status(snapshot, *, environment, network, artifact=None):
    """Validate one consistent snapshot without live quote/credential checks.

    Environment describes the observing service. The retained genesis hash
    commits the historical release, which did not record its runtime environment.
    """
    try:
        stored, rows, expired, released = snapshot
        raw, offer = stored.purchase_artifact, stored.offer_artifact
        batch = raw.get("schema") == "solslot.purchase-batch.v1"
        parsed = purchase_batch_from_json(raw) if batch else purchase_artifact_v3_from_json(raw)
        children = raw["artifacts"] if batch else [raw]
        canonical = parsed.artifacts if batch else (parsed,)
        protocol = offer["protocol"]
        state = stored.inventory_state
        expected_hash = hx(parsed.batch_hash if batch else parsed.artifact_hash)
        if (environment not in {"test-alpha", "staging-alpha", "production-alpha"}
                or network != "testnet11" or offer["network"] != network
                or offer.get("kind") != "solslot_protocol_offer"
                or offer.get("protocolVersion") != "solslot-v2"
                or content_hash(offer) != stored.offer_artifact_hash
                or offer.get("purchaseBatchV1" if batch else "purchaseArtifactV3") != raw
                or stored.purchase_id != hx(parsed.purchase_id)
                or stored.artifact_hash != expected_hash
                or protocol["purchaseId"] != stored.purchase_id
                or protocol["purchaseArtifactHash"] != expected_hash
                or protocol["purchaseIntentId"] != stored.purchase_intent_id
                or protocol["rail"] != stored.rail
                or stored.rail not in {"stripe", "base_usdc", "evm_usdc", "chia_xch", "chia_cat"}
                or any(int(c.rail) != {"stripe": 1, "base_usdc": 2, "evm_usdc": 2, "chia_xch": 3, "chia_cat": 4}[stored.rail] for c in canonical)
                or not isinstance(protocol.get("instanceId"), str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", protocol["instanceId"])
                or type(protocol["quantity"]) is not int or protocol["quantity"] != len(rows)
                or not 1 <= len(rows) <= 100 or len(rows) != len(children)
                or tuple(row.deed_launcher_id for row in rows) != stored.deed_launcher_ids
                or protocol["deedLauncherIds"] != list(stored.deed_launcher_ids)
                or len(set(stored.deed_launcher_ids)) != len(rows)
                or any(c.network != network or hx(c.vault_launcher_id) != protocol["vaultLauncherId"] for c in canonical)
                or state not in {"UNRESERVED", "PREPARED", "SUBMITTED", "CONFIRMED", "AUTHORIZATION_EXPIRED", "RELEASED"}):
            raise ValueError("purchase identity mismatch")
        for ordinal, (row, child) in enumerate(zip(rows, children, strict=True)):
            if (row.ordinal != ordinal or row.state != state
                    or row.child_purchase_id != child["purchaseId"]
                    or row.child_artifact_hash != child["artifactHash"]
                    or row.deed_launcher_id != child["deedLauncherId"]):
                raise ValueError("child commitment mismatch")
            if state != "UNRESERVED":
                for value in (row.available_coin_id, row.reserved_coin_id, row.reserved_puzzle_hash):
                    _hex(value)
                if not row.signature or len(row.signer_indices) != 2:
                    raise ValueError("reservation receipt incomplete")
            elif any(v is not None for v in (row.available_coin_id, row.reserved_coin_id, row.reserved_puzzle_hash, row.signature)) or row.signer_indices:
                raise ValueError("unexpected reservation")
        if state != "UNRESERVED":
            _positive(stored.inventory_expires_at)
            if not isinstance(stored.inventory_bundle, dict):
                raise ValueError("missing retained bundle")
            first = rows[0]
            if (stored.inventory_available_coin_id != first.available_coin_id
                    or stored.inventory_reserved_coin_id != first.reserved_coin_id
                    or stored.inventory_reserved_puzzle_hash != first.reserved_puzzle_hash):
                raise ValueError("parent reservation mismatch")
        elif any(v is not None for v in (stored.inventory_expires_at, stored.inventory_bundle, stored.inventory_bundle_id,
                                        stored.inventory_confirmation_height, stored.inventory_available_coin_id,
                                        stored.inventory_reserved_coin_id, stored.inventory_reserved_puzzle_hash)):
            raise ValueError("unexpected parent reservation")
        if stored.inventory_bundle_id is not None:
            _hex(stored.inventory_bundle_id)
        if stored.inventory_confirmation_height is not None:
            _positive(stored.inventory_confirmation_height)
        if state == "PREPARED" and stored.inventory_bundle_id is not None:
            raise ValueError("unexpected submission receipt")
        if state == "SUBMITTED" and not stored.inventory_bundle_id:
            raise ValueError("missing submission receipt")
        if state == "CONFIRMED" and (not stored.inventory_bundle_id or stored.inventory_confirmation_height is None):
            raise ValueError("missing confirmation receipt")
        if state in {"UNRESERVED", "PREPARED", "SUBMITTED", "AUTHORIZATION_EXPIRED"} and stored.inventory_confirmation_height is not None:
            raise ValueError("unexpected confirmation")
        if (expired is not None) != (state == "AUTHORIZATION_EXPIRED") or (released is not None) != (state == "RELEASED"):
            raise ValueError("contradictory recovery receipts")
        receipt = validated_recovery_receipt(snapshot, network=network, artifact=artifact)
        return dict(purchaseId=stored.purchase_id, purchaseIntentId=stored.purchase_intent_id,
            purchaseArtifactHash=stored.artifact_hash, offerArtifactHash=stored.offer_artifact_hash,
            rail=stored.rail, quantity=len(rows), deedLauncherIds=list(stored.deed_launcher_ids),
            vaultLauncherId=_hex(protocol["vaultLauncherId"]), instanceId=protocol["instanceId"],
            observerEnvironment=environment, network=network, adapterVersion=1,
            releaseIdentity=_digest(offer["genesisArtifactHash"]),
            deployment={key: _hex(offer[key]) for key in ("poolLauncherId", "protocolConfigLauncherId", "vaultVersionRegistryLauncherId")},
            state=state, expiresAt=stored.inventory_expires_at, transactionId=stored.inventory_bundle_id,
            confirmationHeight=stored.inventory_confirmation_height, recoveryReceipt=receipt,
            externalPaymentRecorded=stored.external_message is not None)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RuntimeError) as exc:
        raise PaymentPurchaseConflict("Inventory evidence is incomplete or inconsistent. Keep this purchase for review.") from exc


def validated_recovery_receipt(snapshot, *, network, artifact=None):
    """Validate terminal retained evidence for both reads and idempotent observers."""
    try:
        stored, rows, expired, released = snapshot
        state = stored.inventory_state
        if (not rows or any(row.state != state for row in rows)
                or (expired is not None) != (state == "AUTHORIZATION_EXPIRED")
                or (released is not None) != (state == "RELEASED")):
            raise ValueError("contradictory recovery receipts")
        receipt = None
        if released is not None and released.get('schema') == 'solslot.base-checkout-terminal-evidence.v1':
            from .base_checkout_terminals import validate_base_terminal_evidence
            if released.get('kind') != 'RETURNED' or network != 'testnet11':
                raise ValueError('invalid Base inventory return')
            validate_base_terminal_evidence(snapshot, released, artifact)
            return dict(kind='base-payment-return', confirmationHeight=released['claim']['confirmation_height'])
        if released is not None and released.get('schema') == 'solslot.checkout-terminal.v1':
            from .checkout_terminals import validate_terminal_evidence
            if released.get('kind') != 'RETURNED' or network != 'testnet11':
                raise ValueError('invalid checkout inventory return')
            validate_terminal_evidence(snapshot, released, artifact)
            return dict(kind='payment-return', confirmationHeight=released['items'][0]['confirmationHeight'])
        if released is not None:
            # Rebuild retained timeout commitments; do not demand that the
            # successor is still unspent after a later legitimate purchase.
            view = SimpleNamespace(get=lambda _: stored, inventory_items=lambda _: rows)
            expected = timeout_items(view, stored.purchase_id)
            if released["schema"] != "solslot.inventory-timeout-release.v1" or released["network"] != network or len(released["items"]) != len(rows):
                raise ValueError("invalid timeout receipt")
            _hex(released["peakHash"]); _positive(released["peakHeight"])
            heights = []
            for item, row, proof in zip(expected, rows, released["items"], strict=True):
                height = _positive(proof["confirmationHeight"])
                if (type(proof["ordinal"]) is not int or proof["ordinal"] != row.ordinal
                        or proof["deedLauncherId"] != row.deed_launcher_id
                        or proof["reservedCoinId"] != row.reserved_coin_id
                        or proof["availableCoinId"] != hx(item.successor.name())
                        or proof["availablePuzzleHash"] != hx(item.successor.puzzle_hash)
                        or released["peakHeight"] - height + 1 < 3
                        or not equivalent_timeout_spend(decode_spend(proof["releaseSpend"], item.release_spend.coin), item.release_spend)):
                    raise ValueError("timeout receipt differs from reservation")
                heights.append(height)
            receipt = dict(kind="timeout-release", confirmationHeight=max(heights))
        if expired is not None:
            _expiry_activation(expired, network)
            view = SimpleNamespace(get=lambda _: stored, inventory_items=lambda _: rows)
            expected = timeout_items(view, stored.purchase_id)
            previous = expired["snapshot"]
            current = asdict(stored)
            # Payment may arrive later and has its own settlement/refund state.
            current.update(inventory_state=previous["inventory_state"], external_message=previous["external_message"])
            if (expired["schema"] != "solslot.inventory-authorization-expiry.v1"
                    or expired["purchaseId"] != stored.purchase_id
                    or previous["inventory_state"] not in {"PREPARED", "SUBMITTED"}
                    or current != {**previous, "deed_launcher_ids": tuple(previous["deed_launcher_ids"]),
                                   "inventory_signer_indices": tuple(previous["inventory_signer_indices"]),
                                   "inventory_extension_receipts": tuple(previous.get("inventory_extension_receipts", []))}
                    or len(expired["items"]) != len(rows) or len(expired["chainProofs"]) != len(rows)):
                raise ValueError("invalid expiry snapshot")
            for row, old, proof, reservation in zip(rows, expired["items"], expired["chainProofs"], expected, strict=True):
                item = asdict(row); item["state"] = previous["inventory_state"]; item["signer_indices"] = list(item["signer_indices"])
                if item != old:
                    raise ValueError("expiry proof mismatch")
                _expiry_clock(proof, reservation.reservation_spend.coin, stored.inventory_expires_at, network)
                if any(proof[key] != expired["chainProofs"][0][key]
                       for key in ("peakHeight", "peakHash", "ancestors", "matureTimestamp")):
                    raise ValueError("expiry batch clock differs")
            receipt = dict(kind="authorization-expiry", confirmationHeight=None)
        return receipt
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RuntimeError) as exc:
        raise PaymentPurchaseConflict("Retained recovery receipt is incomplete or inconsistent") from exc
