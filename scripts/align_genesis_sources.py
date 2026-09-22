#!/usr/bin/env python3
"""Preview or apply a source-only alignment before a legacy testnet plan exists.

Operator CLI only: no HTTP endpoint, signatures, plan creation or chain writes.
Run with the installed API interpreter and an immutable, verified source-evidence
file. Applying requires the exact preview hash and creates a private DB backup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from types import SimpleNamespace

from solslot_api.genesis_store import SCHEMA_VERSION, canonical_json
from solslot_api.launch_control import _load_release_evidence
from solslot_api.release_metadata import read_release_metadata


def digest(value: object) -> str:
    return "0x" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def connect(database: Path, *, writable: bool = False) -> sqlite3.Connection:
    uri = database.resolve(strict=True).as_uri() + ("?mode=rw" if writable else "?mode=ro")
    db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA synchronous=FULL")
    return db


def target_release(evidence: Path, expected_hash: str, release_tag: str,
                   metadata: Path) -> dict:
    if not re.fullmatch(r"(?:0x)?[0-9a-f]{64}", expected_hash):
        raise ValueError("an exact source evidence SHA256 is required")
    release = _load_release_evidence(SimpleNamespace(
        launch_source_evidence_path=str(evidence),
        launch_source_evidence_sha256=expected_hash,
        launch_release_tag=release_tag,
    ))
    build = read_release_metadata(str(metadata))
    if build is None or (build.apiCommit, build.protocolCommit) != (
        release["sourceShas"]["api"], release["sourceShas"]["protocol"]
    ):
        raise ValueError("target source evidence does not match installed API/protocol")
    return release


def related_records(db: sqlite3.Connection, ceremony_id: str) -> dict:
    """Fingerprint private records in memory; never emit their contents."""
    result = {}
    for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        table = row[0]
        if table in {"ceremonies", "audit_events"} or not re.fullmatch(r"[a-z_]+", table):
            continue
        columns = [column[1] for column in db.execute(f'PRAGMA table_info("{table}")')]
        if "ceremony_id" not in columns:
            continue
        records = [dict(row) for row in db.execute(
            f'SELECT * FROM "{table}" WHERE ceremony_id=?', (ceremony_id,))]
        result[table] = {"count": len(records), "hash": digest(sorted(records, key=canonical_json))}
    return result


def preview(db: sqlite3.Connection, ceremony_id: str, release: dict,
            action_envelope: str, *, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    if not re.fullmatch(r"0x[0-9a-f]{64}", ceremony_id):
        raise ValueError("ceremony ID must be an exact lowercase bytes32")
    if not re.fullmatch(r"AE-SOLSLOT-[A-Za-z0-9-]+", action_envelope):
        raise ValueError("a Solslot action envelope reference is required")
    if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise ValueError("database schema differs from this operator tool")
    row = db.execute("SELECT * FROM ceremonies WHERE ceremony_id=?", (ceremony_id,)).fetchone()
    if row is None or row["state"] not in {"draft", "roster_open"}:
        raise ValueError("source alignment requires an open, unfrozen ceremony")
    for key in ("roster_hash", "plan_input_json", "plan_json", "plan_hash", "plan_expires_at",
                "spend_bundle_id", "broadcast_json", "confirmed_block_index", "artifact_json", "artifact_hash"):
        if row[key] is not None:
            raise ValueError("source alignment is forbidden after planning or execution")
    old = json.loads(row["draft_json"])
    if (row["network"] != "testnet11" or old.get("network") != "testnet11"
            or old.get("evmChainId") != 11155111 or "enrollmentActivation" in old):
        raise ValueError("only the existing legacy Ethereum Sepolia/Testnet11 ceremony is supported")
    if set(old.get("sourceShas", {})) != set(release["sourceShas"]):
        raise ValueError("both releases must bind all nine source components")
    preserved = related_records(db, ceremony_id)
    for table in ("plan_signatures", "artifact_signatures", "launch_gates",
                  "launch_action_intents", "genesis_finalization_reservation"):
        if preserved[table]["count"]:
            raise ValueError(f"source alignment requires no {table}")
    if db.execute("SELECT 1 FROM launch_action_approvals WHERE ceremony_id=? AND expires_at>? LIMIT 1",
                  (ceremony_id, now)).fetchone():
        raise ValueError("wait for outstanding action approvals to expire")
    new = {**old, "sourceShas": release["sourceShas"], "releaseTag": release["releaseTag"],
           "releaseEvidenceHash": release["fileSha256"]}
    if new == old:
        raise ValueError("ceremony already selects the target source release")
    plan = {"schema": "solslot.preplan-source-alignment.v1", "ceremonyId": ceremony_id,
            "actionEnvelopeId": action_envelope, "state": row["state"],
            "beforeDraft": old, "afterDraft": new, "beforeDraftHash": digest(old),
            "afterDraftHash": digest(new), "preservedRecords": preserved,
            "targetManifestHash": release["manifestHash"]}
    return {**plan, "alignmentHash": digest(plan)}


def apply(database: Path, release: dict, ceremony_id: str, action_envelope: str,
          expected_plan_hash: str, backup: Path) -> dict:
    if backup.exists():
        raise ValueError("refusing to overwrite an existing backup")
    db = connect(database, writable=True)
    try:
        db.execute("BEGIN IMMEDIATE")
        plan = preview(db, ceremony_id, release, action_envelope)
        if plan["alignmentHash"] != expected_plan_hash:
            raise ValueError("alignment preview is stale or its hash does not match")
        # A separate reader takes a consistent backup while this connection holds
        # the writer lock. Do not back up the connection with an open transaction.
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        source = connect(database)
        destination = sqlite3.connect(backup)
        try:
            source.backup(destination)
            if destination.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("database backup integrity check failed")
        finally:
            source.close()
            destination.close()
        now = int(time.time())
        db.execute("UPDATE ceremonies SET draft_json=?,updated_at=? WHERE ceremony_id=?",
                   (canonical_json(plan["afterDraft"]), now, ceremony_id))
        if related_records(db, ceremony_id) != plan["preservedRecords"]:
            raise ValueError("a protected ceremony record changed")
        db.execute("INSERT INTO audit_events(ceremony_id,event_type,event_json,created_at) VALUES(?,?,?,?)",
                   (ceremony_id, "source_release_aligned", canonical_json(plan), now))
        db.execute("COMMIT")
        return {"status": "applied", "alignmentHash": expected_plan_hash,
                "backupPath": str(backup), "ceremonyId": ceremony_id,
                "enrollmentsPreserved": True, "recoveryPreserved": True, "fundingPreserved": True,
                "planCreated": False, "signed": False, "broadcast": False}
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--ceremony-id", required=True)
    parser.add_argument("--source-evidence", type=Path, required=True)
    parser.add_argument("--evidence-sha256", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--release-metadata", type=Path, required=True)
    parser.add_argument("--action-envelope", required=True)
    parser.add_argument("--apply-plan-hash")
    parser.add_argument("--backup", type=Path)
    args = parser.parse_args()
    release = target_release(args.source_evidence, args.evidence_sha256,
                             args.release_tag, args.release_metadata)
    if args.apply_plan_hash:
        if args.backup is None:
            parser.error("--backup is required when applying")
        result = apply(args.database, release, args.ceremony_id, args.action_envelope,
                       args.apply_plan_hash, args.backup)
    else:
        db = connect(args.database)
        try:
            db.execute("BEGIN")
            result = {"status": "preview", **preview(db, args.ceremony_id, release, args.action_envelope)}
        finally:
            db.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
