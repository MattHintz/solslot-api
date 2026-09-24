"""Export Authority V3 deployment roster evidence from a genesis ledger."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from eth_utils import keccak, to_checksum_address

from .safe_owner_roster import address_from_compressed_pubkey
from .authority_network import authority_chain_id


_CEREMONY_ID = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_PUBKEY = re.compile(r"^0x(?:02|03)[0-9a-fA-F]{64}$")
_BLS_PUBKEY = re.compile(r"^0x[0-9a-fA-F]{96}$")
_CEREMONY_STATES = {
    "planned": "planned",
    "plan_approved": "approved",
    "broadcast": "broadcast",
    "confirmed": "confirmed",
    "artifact_pending": "artifact_pending",
    "artifact_signed": "artifact_signed",
    "locked": "locked",
}


class AuthorityV3RosterError(RuntimeError):
    """The ceremony cannot produce trustworthy Authority V3 roster evidence."""


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityV3RosterError(f"{label} is missing")
    return value


def _ordered_records(
    value: Any,
    label: str,
    expected_slots: list[int],
) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) != len(expected_slots):
        raise AuthorityV3RosterError(f"{label} must contain exactly three records")
    records = [_mapping(item, label) for item in value]
    try:
        slots = [int(item.get("slot", -1)) for item in records]
    except (TypeError, ValueError) as exc:
        raise AuthorityV3RosterError(f"{label} slots are invalid") from exc
    if slots != expected_slots:
        raise AuthorityV3RosterError(f"{label} slots are not canonical")
    return records


def _nonzero_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    normalized = str(value or "").lower()
    if not pattern.fullmatch(normalized):
        raise AuthorityV3RosterError(f"{label} is invalid")
    if not any(bytes.fromhex(normalized[2:])):
        raise AuthorityV3RosterError(f"{label} cannot be zero")
    return normalized


def _iso_timestamp(value: Any, label: str, now: int) -> str:
    try:
        timestamp = int(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityV3RosterError(f"{label} is invalid") from exc
    if timestamp <= 0 or timestamp > now:
        raise AuthorityV3RosterError(f"{label} is invalid")
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _read_snapshot(
    database_path: str | Path,
    ceremony_id: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    candidate = Path(database_path)
    if not candidate.is_file() or candidate.is_symlink():
        raise AuthorityV3RosterError("genesis ceremony database is unavailable")
    path = candidate.resolve()
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        if ceremony_id is not None:
            if not _CEREMONY_ID.fullmatch(ceremony_id):
                raise AuthorityV3RosterError("ceremony id is invalid")
            ceremony = connection.execute(
                "SELECT ceremony_id,network,state,roster_hash,plan_json,"
                "plan_expires_at,updated_at "
                "FROM ceremonies WHERE ceremony_id=?",
                (ceremony_id.lower(),),
            ).fetchone()
        else:
            ceremony = connection.execute(
                "SELECT ceremony_id,network,state,roster_hash,plan_json,"
                "plan_expires_at,updated_at "
                "FROM ceremonies WHERE plan_json IS NOT NULL "
                "ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
        if ceremony is None:
            raise AuthorityV3RosterError(
                "no planned ceremony can produce Authority V3 roster evidence"
            )
        if ceremony["plan_json"] is None:
            raise AuthorityV3RosterError(
                "Authority V3 roster requires a current deterministic ceremony plan"
            )
        members = connection.execute(
            "SELECT slot,wallet_address,compressed_pubkey FROM invitations "
            "WHERE ceremony_id=? AND consumed_at IS NOT NULL ORDER BY slot",
            (ceremony["ceremony_id"],),
        ).fetchall()
        recovery_kits = connection.execute(
            "SELECT slot,revision,evm_guardian,recovery_bls_pubkey,"
            "recovery_bls_commitment,drill_challenge_hash,drill_verified_at,"
            "offline_copy_confirmed,second_device_confirmed "
            "FROM admin_recovery_kits WHERE ceremony_id=? ORDER BY slot",
            (ceremony["ceremony_id"],),
        ).fetchall()
        connection.execute("COMMIT")
    except AuthorityV3RosterError:
        raise
    except (sqlite3.Error, json.JSONDecodeError) as exc:
        raise AuthorityV3RosterError("genesis ceremony database is invalid") from exc
    finally:
        connection.close()
    result = dict(ceremony)
    try:
        result["plan"] = json.loads(str(result.pop("plan_json")))
    except (TypeError, json.JSONDecodeError) as exc:
        raise AuthorityV3RosterError("genesis ceremony plan is invalid") from exc
    return result, [dict(row) for row in members], [dict(row) for row in recovery_kits]


def export_authority_v3_roster(
    database_path: str | Path,
    *,
    ceremony_id: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Return schema-v2 evidence accepted by the Omnichain V3 deployer."""

    ceremony, members, recovery_rows = _read_snapshot(database_path, ceremony_id)
    if ceremony["network"] != "testnet11":
        raise AuthorityV3RosterError("Authority V3 roster must use testnet11")
    evidence_state = _CEREMONY_STATES.get(str(ceremony["state"]))
    if evidence_state is None:
        raise AuthorityV3RosterError(
            "Authority V3 roster requires a current deterministic ceremony plan"
        )
    observed_at = int(time.time()) if now is None else now
    if not isinstance(observed_at, int) or observed_at <= 0:
        raise AuthorityV3RosterError("roster observation time is invalid")
    try:
        plan_expires_at = int(ceremony.get("plan_expires_at") or 0)
    except (TypeError, ValueError) as exc:
        raise AuthorityV3RosterError("ceremony plan expiration is invalid") from exc
    if evidence_state in {"planned", "approved"} and plan_expires_at < observed_at:
        raise AuthorityV3RosterError("Authority V3 ceremony plan has expired")
    if [int(item["slot"]) for item in members] != [1, 2, 3]:
        raise AuthorityV3RosterError(
            "exactly three enrolled administrator slots are required"
        )
    if [int(item["slot"]) for item in recovery_rows] != [1, 2, 3]:
        raise AuthorityV3RosterError(
            "all three completed recovery drills are required"
        )

    plan = _mapping(ceremony["plan"], "genesis ceremony plan")
    try:
        selected_chain = authority_chain_id(plan)
    except ValueError as exc:
        raise AuthorityV3RosterError(str(exc)) from exc
    if (
        str(plan.get("ceremonyId") or "").lower()
        != str(ceremony["ceremony_id"]).lower()
        or plan.get("network") != "testnet11"
    ):
        raise AuthorityV3RosterError(
            "genesis plan ceremony or network binding differs"
        )
    launchers = _mapping(plan.get("launcherIds"), "plan launcher IDs")
    authority = _mapping(plan.get("adminAuthority"), "plan admin authority")
    if authority.get("version") != 3:
        raise AuthorityV3RosterError("genesis plan does not use Authority V3")
    identities = _ordered_records(
        authority.get("identityVaults"),
        "plan identity vaults",
        [0, 1, 2],
    )
    plan_kits = _ordered_records(
        plan.get("adminRecoveryKits"),
        "plan recovery kits",
        [0, 1, 2],
    )
    source_manifest_hash = _nonzero_hex(
        authority.get("sourceManifestHash"),
        _HEX32,
        "source manifest hash",
    )
    roster_hash = _nonzero_hex(
        ceremony.get("roster_hash"),
        _HEX32,
        "frozen roster hash",
    )
    if str(authority.get("adminsHash") or "").lower() != roster_hash:
        raise AuthorityV3RosterError(
            "deterministic plan roster hash differs from the frozen roster"
        )
    authority_launcher_id = _nonzero_hex(
        launchers.get("adminAuthority"),
        _HEX32,
        "authority launcher ID",
    )
    identity_launcher_ids = [
        _nonzero_hex(
            launchers.get(f"adminIdentity{slot}"),
            _HEX32,
            f"identity launcher ID {slot}",
        )
        for slot in range(3)
    ]
    if len(set(identity_launcher_ids)) != 3:
        raise AuthorityV3RosterError("identity launcher IDs must be unique")
    if authority_launcher_id in identity_launcher_ids:
        raise AuthorityV3RosterError("authority and identity launcher IDs must differ")

    administrators: list[dict[str, Any]] = []
    daily_addresses: list[str] = []
    guardian_addresses: list[str] = []
    for slot, (member, recovery, identity, plan_kit) in enumerate(
        zip(members, recovery_rows, identities, plan_kits, strict=True)
    ):
        compressed_pubkey = _nonzero_hex(
            member.get("compressed_pubkey"),
            _PUBKEY,
            f"slot {slot} daily public key",
        )
        plan_pubkeys = authority.get("compressedPubkeys")
        if (
            not isinstance(plan_pubkeys, list)
            or len(plan_pubkeys) != 3
            or str(plan_pubkeys[slot] or "").lower() != compressed_pubkey
        ):
            raise AuthorityV3RosterError(
                f"slot {slot} plan roster differs from enrollment"
            )
        wallet = str(member.get("wallet_address") or "")
        if not _ADDRESS.fullmatch(wallet):
            raise AuthorityV3RosterError(f"slot {slot} daily address is invalid")
        address = address_from_compressed_pubkey(compressed_pubkey)
        if address.lower() != wallet.lower():
            raise AuthorityV3RosterError(
                f"slot {slot} daily public key does not match its wallet"
            )
        if str(identity.get("dailyCompressedPubkey") or "").lower() != compressed_pubkey:
            raise AuthorityV3RosterError(
                f"slot {slot} identity vault differs from enrollment"
            )
        identity_launcher = _nonzero_hex(
            identity.get("launcherId"),
            _HEX32,
            f"slot {slot} identity-vault launcher ID",
        )
        if identity_launcher != identity_launcher_ids[slot]:
            raise AuthorityV3RosterError(
                f"slot {slot} identity launcher binding differs"
            )

        guardian_value = str(recovery.get("evm_guardian") or "")
        if not _ADDRESS.fullmatch(guardian_value):
            raise AuthorityV3RosterError(
                f"slot {slot} recovery guardian is invalid"
            )
        guardian = to_checksum_address(guardian_value)
        bls_pubkey = _nonzero_hex(
            recovery.get("recovery_bls_pubkey"),
            _BLS_PUBKEY,
            f"slot {slot} recovery BLS key",
        )
        bls_commitment = _nonzero_hex(
            recovery.get("recovery_bls_commitment"),
            _HEX32,
            f"slot {slot} recovery BLS commitment",
        )
        drill_challenge_hash = _nonzero_hex(
            recovery.get("drill_challenge_hash"),
            _HEX32,
            f"slot {slot} recovery drill challenge hash",
        )
        if "0x" + keccak(bytes.fromhex(bls_pubkey[2:])).hex() != bls_commitment:
            raise AuthorityV3RosterError(
                f"slot {slot} recovery BLS commitment mismatches"
            )
        try:
            revision = int(recovery.get("revision") or 0)
            plan_revision = int(plan_kit.get("revision") or 0)
        except (TypeError, ValueError) as exc:
            raise AuthorityV3RosterError(
                f"slot {slot} recovery revision is invalid"
            ) from exc
        if revision < 1:
            raise AuthorityV3RosterError(
                f"slot {slot} recovery revision is invalid"
            )
        if not (
            int(recovery.get("offline_copy_confirmed") or 0) == 1
            and int(recovery.get("second_device_confirmed") or 0) == 1
        ):
            raise AuthorityV3RosterError(
                f"slot {slot} recovery readiness is incomplete"
            )
        drill_verified_at = _iso_timestamp(
            recovery.get("drill_verified_at"),
            f"slot {slot} recovery drill timestamp",
            observed_at,
        )

        if (
            str(identity.get("recoveryBlsPubkey") or "").lower() != bls_pubkey
            or str(plan_kit.get("evmGuardian") or "").lower() != guardian.lower()
            or str(plan_kit.get("recoveryBlsPubkey") or "").lower() != bls_pubkey
            or str(plan_kit.get("recoveryBlsCommitment") or "").lower()
            != bls_commitment
            or plan_revision != revision
            or str(plan_kit.get("drillChallengeHash") or "").lower()
            != drill_challenge_hash
        ):
            raise AuthorityV3RosterError(
                f"slot {slot} recovery kit differs from the deterministic plan"
            )
        daily_addresses.append(address.lower())
        guardian_addresses.append(guardian.lower())
        administrators.append(
            {
                "slot": slot,
                "address": address,
                "compressedPubkey": compressed_pubkey,
                "recovery": {
                    "evmGuardian": guardian,
                    "blsPubkey": bls_pubkey,
                    "blsCommitment": bls_commitment,
                    "revision": revision,
                    "drillVerifiedAt": drill_verified_at,
                },
            }
        )

    if len(set(daily_addresses)) != 3:
        raise AuthorityV3RosterError("daily administrator identities must be unique")
    if len(set(guardian_addresses)) != 3 or set(daily_addresses) & set(
        guardian_addresses
    ):
        raise AuthorityV3RosterError(
            "daily and recovery identities must be separate and unique"
        )

    evidence: dict[str, Any] = {
        "schemaVersion": 2,
        "kind": "solslot-alpha-authority-v3-roster",
        "ceremonyId": str(ceremony["ceremony_id"]).lower(),
        "network": "testnet11",
        "ceremonyState": evidence_state,
        "authorityRule": "slot0_and_one_of_slot1_slot2",
        "sourceManifestHash": source_manifest_hash,
        "authorityLauncherId": authority_launcher_id,
        "identityLauncherIds": identity_launcher_ids,
        "administrators": administrators,
    }
    if "paymentChainId" in plan or selected_chain != 84532:
        evidence.update(
            schemaVersion=3,
            paymentChainId=selected_chain,
            evmChainId=plan.get("evmChainId", 11155111),
        )
    return {**evidence, "artifactHash": _canonical_hash(evidence)}


__all__ = [
    "AuthorityV3RosterError",
    "export_authority_v3_roster",
]
