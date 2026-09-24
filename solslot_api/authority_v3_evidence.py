"""Strict loader for Authority V3 governance deployment evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .config import Settings
from .authority_network import authority_chain_id, ceremony_authority_document, validate_authority_network


MAX_EVIDENCE_BYTES = 128 * 1024
AUTHORITY_EVM_CHAIN_ID = 84_532


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key != "artifactHash"
    }
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def load_governance_evidence(settings: Settings) -> dict[str, Any]:
    path_value = settings.authority_v3_governance_evidence_path
    if not path_value:
        raise ValueError(
            "Authority V3 EVM deployment evidence is unavailable"
        )
    path = Path(path_value)
    try:
        stat = path.lstat()
        if (
            not path.is_file()
            or path.is_symlink()
            or stat.st_size <= 0
            or stat.st_size > MAX_EVIDENCE_BYTES
        ):
            raise ValueError(
                "Authority V3 EVM deployment evidence is invalid"
            )
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Authority V3 EVM deployment evidence is unreadable"
        ) from exc
    if (
        not isinstance(evidence, dict)
        or evidence.get("schemaVersion") != 3
        or evidence.get("kind")
        != "solslot-alpha-authority-v3-governance-deployment"
        or evidence.get("authorityRule")
        != "slot0_and_one_of_slot1_slot2"
        or evidence.get("artifactHash") != _canonical_hash(evidence)
    ):
        raise ValueError(
            "Authority V3 EVM deployment evidence is unsupported"
        )
    validate_authority_network(
        evidence, 8453 if settings.eip712_chain_id == 8453 else settings.payment_omnichain_chain_id,
    )
    recovery = evidence.get("recovery")
    safes = evidence.get("safes")
    chia = evidence.get("chiaAuthority")
    hashes = evidence.get("runtimeCodeHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (recovery, safes, chia, hashes)
    ):
        raise ValueError("Authority V3 EVM evidence is incomplete")
    identities = safes.get("identities")
    if (
        not isinstance(identities, list)
        or len(identities) != 3
        or [item.get("slot") for item in identities] != [0, 1, 2]
        or recovery.get("routineDelaySeconds") != "86400"
        or recovery.get("lostKeyDelaySeconds") != "604800"
        or recovery.get("globalFreezeRequired") is not True
        or recovery.get("crossChainConvergenceRequired") is not True
        or recovery.get("replacementAcceptanceRequired") is not True
        or recovery.get("recoveryKitRotationSupported") is not True
        or recovery.get(
            "rollbackRequiresChiaCancellationReceipt"
        ) is not True
    ):
        raise ValueError("Authority V3 EVM recovery policy differs")
    return evidence


def validate_governance_roster(
    record: Mapping[str, Any],
    kits: list[Mapping[str, Any]],
    evidence: Mapping[str, Any],
) -> None:
    validate_authority_network(evidence, authority_chain_id(ceremony_authority_document(record)))
    if [int(item["slot"]) for item in kits] != [0, 1, 2]:
        raise ValueError("all three recovery drills are required")
    invitations = sorted(
        record.get("invitations") or [],
        key=lambda item: int(item.get("slot", 0)),
    )
    administrators = evidence.get("administrators")
    recovery = evidence.get("recovery")
    recovery_identities = (
        recovery.get("identities")
        if isinstance(recovery, Mapping)
        else None
    )
    if (
        len(invitations) != 3
        or not isinstance(administrators, list)
        or len(administrators) != 3
        or not isinstance(recovery_identities, list)
        or len(recovery_identities) != 3
    ):
        raise ValueError(
            "Authority V3 EVM evidence has an incomplete identity roster"
        )
    for slot in range(3):
        invitation = invitations[slot]
        administrator = administrators[slot]
        recovery_record = recovery_identities[slot]
        kit = kits[slot]
        if (
            int(invitation["slot"]) != slot + 1
            or administrator.get("slot") != slot
            or recovery_record.get("slot") != slot
            or str(administrator.get("compressedPubkey") or "").lower()
            != str(invitation.get("compressed_pubkey") or "").lower()
            or str(administrator.get("address") or "").lower()
            != str(invitation.get("wallet_address") or "").lower()
            or str(recovery_record.get("evmGuardian") or "").lower()
            != str(kit["evmGuardian"]).lower()
            or str(recovery_record.get("blsPubkey") or "").lower()
            != str(kit["recoveryBlsPubkey"]).lower()
            or str(recovery_record.get("blsCommitment") or "").lower()
            != str(kit["recoveryBlsCommitment"]).lower()
            or int(recovery_record.get("revision") or 0)
            != int(kit["revision"])
        ):
            raise ValueError(
                f"Authority V3 slot {slot + 1} evidence differs from enrollment"
            )
    plan = record.get("plan")
    if isinstance(plan, Mapping):
        authority = plan.get("adminAuthority")
        launchers = plan.get("launcherIds")
        chia = evidence.get("chiaAuthority")
        if not all(
            isinstance(value, Mapping)
            for value in (authority, launchers, chia)
        ):
            raise ValueError(
                "Authority V3 plan/deployment binding is incomplete"
            )
        if (
            str(chia.get("authorityLauncherId") or "").lower()
            != str(launchers.get("adminAuthority") or "").lower()
            or [
                str(value).lower()
                for value in chia.get("identityLauncherIds", [])
            ]
            != [
                str(
                    launchers.get(f"adminIdentity{slot}") or ""
                ).lower()
                for slot in range(3)
            ]
            or str(chia.get("sourceManifestHash") or "").lower()
            != str(authority.get("sourceManifestHash") or "").lower()
        ):
            raise ValueError(
                "Authority V3 Chia and EVM launch coordinates differ"
            )


__all__ = [
    "AUTHORITY_EVM_CHAIN_ID",
    "MAX_EVIDENCE_BYTES",
    "load_governance_evidence",
    "validate_governance_roster",
]
