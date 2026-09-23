"""Explicit, ceremony-bound exception for a disposable vault/identity rehearsal.

This is an operator scope decision, never an independent recovery approval.
The ordinary genesis, identity verification, recovery kits and signatures still run.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

PROFILE = "disposable-vault-identity"
REVIEW_CLASS = "internal-engineering-testnet"
CLOSED_FLAGS = (
    "minting_enabled", "presale_enabled", "presale_xch_enabled",
    "sols_bridge_enabled", "sols_liquidity_enabled", "sgt_allocations_enabled",
    "voucher_issuance_worker_enabled", "kos_mint_execute_signer_enabled",
    "funded_redemptions_enabled", "stripe_settlement_enabled",
    "stripe_delivery_worker_enabled", "checkout_lifecycle_worker_enabled",
    "payment_omnichain_enabled", "payment_omnichain_ownership_activation_enabled",
    "collection_minting_enabled",
)


def validate_configuration(settings: Any) -> None:
    cid = settings.disposable_genesis_ceremony_id
    if not cid:
        return
    if not re.fullmatch(r"0x[0-9a-f]{64}", cid):
        raise ValueError("disposable genesis requires an exact ceremony id")
    if settings.network != "testnet11" or settings.launch_genesis_review_class != REVIEW_CLASS:
        raise ValueError("disposable genesis requires internal engineering Testnet11 review")
    enabled = [name for name in CLOSED_FLAGS if getattr(settings, name)]
    if enabled:
        raise ValueError("disposable genesis requires closed capabilities: " + ", ".join(enabled))


def is_disposable(record: Mapping[str, Any]) -> bool:
    return record.get("draft", {}).get("launchProfile") == PROFILE


def require_scope(settings: Any, record: Mapping[str, Any]) -> bool:
    """Fail closed on either half of a mismatched configuration/draft binding."""
    configured = settings.disposable_genesis_ceremony_id
    selected = is_disposable(record)
    if not configured and not selected:
        return False
    validate_configuration(settings)
    draft = record.get("draft", {})
    if (not configured or configured != record.get("ceremony_id") or not selected
            or draft.get("reviewClass") != REVIEW_CLASS
            or draft.get("network") != "testnet11"
            or (record.get("plan") and record["plan"].get("network") != "testnet11")):
        raise ValueError("disposable genesis configuration does not match this ceremony")
    return True


def require_allowed_gate(settings: Any, record: Mapping[str, Any], gate: str) -> None:
    # The persisted scope remains closed even if an operator removes the env flag.
    if is_disposable(record) or settings.disposable_genesis_ceremony_id:
        require_scope(settings, record)
        if gate != "ceremonyBroadcast":
            raise ValueError("This disposable genesis supports vaults and identity only; replace it before sales or bridge testing.")


def scope_receipt(settings: Any, record: Mapping[str, Any]) -> dict[str, Any]:
    if not require_scope(settings, record):
        raise ValueError("disposable genesis scope was not selected")
    kits = record.get("plan_input", {}).get("adminRecoveryKits", [])
    if ([kit.get("slot") for kit in kits] != [0, 1, 2]
            or any(int(kit.get("revision", 0)) < 1 for kit in kits)):
        raise ValueError("disposable genesis still requires all three recovery kits")
    if not record.get("plan_hash") or not record.get("plan"):
        raise ValueError("disposable genesis scope requires an exact plan")
    return {
        "schemaVersion": 1,
        "kind": "solslot-disposable-genesis-scope",
        "launchProfile": PROFILE,
        "network": "testnet11",
        "reviewClass": REVIEW_CLASS,
        "auditStatus": "unaudited",
        "testOnly": True,
        "replaceBeforeBridgeTesting": True,
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "sourceShas": record["draft"]["sourceShas"],
        "releaseEvidenceHash": record["draft"]["releaseEvidenceHash"],
        "recoveryKitCommitments": kits,
        "allowedUses": ["vault-registration", "identity-verification"],
        "deferredRequirements": ["evm-authority-v3-deployment", "independent-recovery-review"],
        "closedCapabilities": list(CLOSED_FLAGS),
    }


def receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    return (json.dumps(dict(receipt), sort_keys=True, indent=2) + "\n").encode("ascii")


def receipt_summary(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": receipt["kind"], "auditStatus": "unaudited",
        "fileSha256": hashlib.sha256(receipt_bytes(receipt)).hexdigest(),
        "deferredRequirements": receipt["deferredRequirements"],
        "replaceBeforeBridgeTesting": True,
    }
