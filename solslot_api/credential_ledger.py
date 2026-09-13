"""Persistent Solslot V2 credential and relayer ledger.

The ledger is deliberately separate from the vault registry. Vault ownership
is durable protocol metadata; this database tracks one-time credential actions,
bridge reservations, public receipts, and sponsored EVM submissions. SQLite
WAL plus ``BEGIN IMMEDIATE`` makes every replay-sensitive transition atomic
across threads and API worker processes.
"""
from __future__ import annotations

import json
import hashlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


SCHEMA_VERSION = 4
OWNER_CHALLENGE_MAX_TTL_SECONDS = 900


class LedgerError(RuntimeError):
    """Base class for fail-closed ledger errors."""


class LedgerConflict(LedgerError):
    """A one-time value or state transition has already been consumed."""


class LedgerRateLimited(LedgerError):
    """A persistent relay budget or owner-challenge capacity is exhausted."""


class LedgerCircuitOpen(LedgerError):
    """Sponsored relay submissions are temporarily disabled."""


@dataclass(frozen=True)
class OwnerChallenge:
    challenge_id: str
    vault_launcher_id: str
    action: str
    payload_hash: str
    nonce: str
    auth_type: str
    expires_at: int


class CredentialLedger:
    """SQLite-backed V2 credential state machine and replay ledger."""

    def __init__(self, path: str | Path, timeout: float = 10.0) -> None:
        self.path = str(path) if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self.path,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._configure()
        self._migrate()
        self._prepare_owner_challenge_retention()

    def _prepare_owner_challenge_retention(self) -> None:
        # Additive index, compatible with existing schema-1 ledgers. Owner
        # challenges are short-lived authorization material, not enrollment,
        # event, bridge or relay replay records; those tables are not pruned.
        with self._lock:
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS owner_challenges_expiry_idx "
                "ON owner_challenges(expires_at)"
            )
            self._prune_expired_owner_challenges(int(time.time()))

    def _prune_expired_owner_challenges(self, now: int) -> None:
        # Keep consumed tombstones through their signed expiry. The strict
        # boundary matches consume_owner_challenge and verify_owner_auth.
        # Once deleted, a replay is still unknown and cannot be authorized.
        self._conn.execute("DELETE FROM owner_challenges WHERE expires_at < ?", (now,))

    def _configure(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA busy_timeout = 10000")
            self._conn.execute("PRAGMA synchronous = FULL")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Credential ledger schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version == SCHEMA_VERSION:
                return
            if version == 0:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE enrollments (
                        vault_launcher_id TEXT PRIMARY KEY,
                        network TEXT NOT NULL,
                        policy_version INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        bridge_coin_id TEXT NOT NULL UNIQUE,
                        owner_key TEXT NOT NULL,
                        record_json TEXT NOT NULL,
                        revision INTEGER NOT NULL DEFAULT 1,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        CHECK (policy_version >= 2),
                        CHECK (status IN (
                            'reserved', 'evm_confirmed', 'stamp_pending',
                            'chia_confirmed', 'receipt_syncing'
                        ))
                    );

                    CREATE TABLE owner_challenges (
                        challenge_id TEXT PRIMARY KEY,
                        vault_launcher_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        nonce TEXT NOT NULL UNIQUE,
                        auth_type TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER,
                        created_at INTEGER NOT NULL,
                        CHECK (auth_type IN ('evm', 'chia_bls'))
                    );
                    CREATE INDEX owner_challenges_vault_idx
                        ON owner_challenges(vault_launcher_id, created_at);

                    CREATE TABLE evm_events (
                        transaction_hash TEXT PRIMARY KEY,
                        vault_launcher_id TEXT NOT NULL UNIQUE,
                        owner_key TEXT NOT NULL,
                        scoped_nullifier TEXT NOT NULL UNIQUE,
                        bridge_coin_id TEXT NOT NULL UNIQUE,
                        block_number INTEGER NOT NULL,
                        recorded_at INTEGER NOT NULL,
                        FOREIGN KEY (vault_launcher_id)
                            REFERENCES enrollments(vault_launcher_id)
                    );

                    CREATE TABLE relay_attempts (
                        request_digest TEXT PRIMARY KEY,
                        vault_launcher_id TEXT NOT NULL,
                        owner_key TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        bridge_coin_id TEXT NOT NULL UNIQUE,
                        forwarder_nonce TEXT NOT NULL,
                        inner_gas INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        tx_hash TEXT,
                        error TEXT,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        UNIQUE (owner_key, forwarder_nonce),
                        FOREIGN KEY (vault_launcher_id)
                            REFERENCES enrollments(vault_launcher_id),
                        CHECK (status IN ('reserved', 'submitted', 'failed'))
                    );
                    CREATE INDEX relay_attempts_ip_idx
                        ON relay_attempts(source_ip, created_at);
                    CREATE INDEX relay_attempts_owner_idx
                        ON relay_attempts(owner_key, created_at);
                    CREATE INDEX relay_attempts_vault_idx
                        ON relay_attempts(vault_launcher_id, created_at);

                    CREATE TABLE relay_circuit (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        consecutive_failures INTEGER NOT NULL DEFAULT 0,
                        open_until INTEGER NOT NULL DEFAULT 0,
                        updated_at INTEGER NOT NULL
                    );
                    INSERT INTO relay_circuit(singleton, updated_at) VALUES (1, 0);
                    PRAGMA user_version = 1;
                    COMMIT;
                    """
                )

            self._conn.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS enrollment_stamp_attempts (
                    vault_launcher_id TEXT PRIMARY KEY REFERENCES enrollments(vault_launcher_id),
                    claim_hash TEXT NOT NULL UNIQUE,
                    claim_json TEXT NOT NULL,
                    expected_coin_json TEXT NOT NULL,
                    bundle_hex TEXT,
                    bundle_id TEXT UNIQUE,
                    dispatch_count INTEGER NOT NULL DEFAULT 0,
                    dispatch_status TEXT NOT NULL DEFAULT 'not_submitted',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    CHECK (dispatch_status IN ('not_submitted', 'unknown', 'submitted', 'rejected'))
                );
                PRAGMA user_version = 2;
                COMMIT;
            """)

            # Existing rows predate durable construction. Mark their origin
            # without inventing a transaction, nonce, signature or outcome.
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                if 'construction_version' not in {row[1] for row in self._conn.execute('PRAGMA table_info(relay_attempts)')}:
                    self._conn.execute('ALTER TABLE relay_attempts ADD COLUMN construction_version INTEGER NOT NULL DEFAULT 0')
                self._conn.execute('COMMIT')
            except Exception:
                self._conn.execute('ROLLBACK')
                raise
            self._conn.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS relay_transactions (
                    request_digest TEXT PRIMARY KEY REFERENCES relay_attempts(request_digest),
                    vault_launcher_id TEXT NOT NULL UNIQUE REFERENCES enrollments(vault_launcher_id),
                    context_json TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    raw_transaction_hex TEXT NOT NULL,
                    tx_hash TEXT NOT NULL UNIQUE,
                    chain_id INTEGER NOT NULL,
                    relayer TEXT NOT NULL,
                    outer_nonce INTEGER NOT NULL,
                    retry_until INTEGER NOT NULL,
                    dispatch_status TEXT NOT NULL DEFAULT 'not_submitted',
                    dispatch_count INTEGER NOT NULL DEFAULT 0,
                    last_dispatch_at INTEGER,
                    created_at INTEGER NOT NULL,
                    UNIQUE(chain_id, relayer, outer_nonce),
                    CHECK(dispatch_status IN ('not_submitted','unknown','submitted'))
                );
                PRAGMA user_version = 3;
                COMMIT;
            """)

            self._conn.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS enrollment_permits (
                    vault_launcher_id TEXT PRIMARY KEY REFERENCES enrollments(vault_launcher_id),
                    permit_id TEXT NOT NULL UNIQUE,
                    permit_hash TEXT NOT NULL UNIQUE,
                    current_vault_coin_id TEXT NOT NULL UNIQUE,
                    bridge_coin_id TEXT NOT NULL UNIQUE,
                    context_json TEXT NOT NULL,
                    permit_json TEXT NOT NULL,
                    issuer_signature TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS permit_issuance_history (
                    id INTEGER PRIMARY KEY,
                    vault_launcher_id TEXT NOT NULL REFERENCES enrollment_permits(vault_launcher_id),
                    attempt_id TEXT NOT NULL,
                    event TEXT NOT NULL CHECK(event IN ('started','issued','unavailable','invalid')),
                    created_at INTEGER NOT NULL,
                    UNIQUE(attempt_id,event)
                );
                CREATE INDEX IF NOT EXISTS permit_history_vault ON permit_issuance_history(vault_launcher_id,id);
                PRAGMA user_version = 4;
                COMMIT;
            """)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def get_enrollment(self, vault_launcher_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT record_json FROM enrollments WHERE vault_launcher_id = ?",
                (vault_launcher_id,),
            ).fetchone()
        return json.loads(row["record_json"]) if row else None

    def get_stamp_attempt(self, vault_launcher_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM enrollment_stamp_attempts WHERE vault_launcher_id=?",
                (vault_launcher_id.lower(),),
            ).fetchone()
        return dict(row) if row else None

    def reserve_stamp_attempt(self, *, claim: dict[str, Any], expected_coin: dict[str, Any]) -> None:
        """Freeze the complete owner/quorum claim before any private signature request.

        A different timestamp/signature is a different attempt, not an implicit
        retry. Historical enrollment, event and bridge input records are never
        deleted, released or silently upgraded by this table.
        """
        from chia_rs import Coin
        vault = str(claim["vault_launcher_id"]).lower()
        encoded = _canonical_json(claim)
        claim_hash = "0x" + hashlib.sha256(encoded.encode("ascii")).hexdigest()
        successor = Coin.from_json_dict(expected_coin)
        if "0x" + successor.parent_coin_info.hex() != claim["current_vault_coin_id"] or successor.amount != 1:
            raise LedgerConflict("Stamp successor is not bound to the authorized current vault coin.")
        expected = _canonical_json(successor.to_json_dict())
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT * FROM enrollments WHERE vault_launcher_id=?", (vault,)).fetchone()
                if not row or row["status"] != "evm_confirmed":
                    raise LedgerConflict("Enrollment is not ready for a new stamp authorization.")
                record = json.loads(row["record_json"])
                receipt = record.get("receipt") or {}
                bindings = {
                    "vault_launcher_id": record["vaultLauncherId"], "network": record["network"],
                    "bridge_coin_id": record["bridgeCoinId"], "owner_key": row["owner_key"],
                    "identity_attest_root": receipt.get("identityAttestRoot"),
                    "validator_message": receipt.get("validatorMessage"),
                    "evm_transaction_hash": receipt.get("evmTxHash"),
                }
                if any(claim.get(k) != v for k, v in bindings.items()):
                    raise LedgerConflict("Stamp claim does not match the reserved enrollment and receipt.")
                prior = self._conn.execute("SELECT * FROM enrollment_stamp_attempts WHERE vault_launcher_id=?", (vault,)).fetchone()
                if prior:
                    if prior["claim_json"] != encoded or prior["expected_coin_json"] != expected:
                        raise LedgerConflict("Stamp authorization is already frozen; recover the existing attempt.")
                else:
                    self._conn.execute("""INSERT INTO enrollment_stamp_attempts
                        (vault_launcher_id,claim_hash,claim_json,expected_coin_json,created_at,updated_at)
                        VALUES (?,?,?,?,?,?)""", (vault, claim_hash, encoded, expected, now, now))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def persist_stamp_bundle(self, *, vault_launcher_id: str, bundle_hex: str) -> dict[str, Any]:
        """Retain exact signed bytes and public reconciliation IDs atomically before push."""
        from chia_rs import Coin, SpendBundle
        vault = vault_launcher_id.lower()
        bundle = SpendBundle.from_bytes(bytes.fromhex(bundle_hex))
        if bytes(bundle).hex() != bundle_hex:
            raise LedgerConflict("Stamp bundle encoding is not canonical.")
        bundle_id = "0x" + bundle.name().hex()
        # CLVM work precedes the DB lock. The frozen context is rechecked below.
        additions = set(bundle.additions())
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                attempt = self._conn.execute("SELECT * FROM enrollment_stamp_attempts WHERE vault_launcher_id=?", (vault,)).fetchone()
                row = self._conn.execute("SELECT * FROM enrollments WHERE vault_launcher_id=?", (vault,)).fetchone()
                if not attempt or not row:
                    raise LedgerConflict("A durable stamp authorization is required before submission.")
                claim = json.loads(attempt["claim_json"])
                expected_coin = Coin.from_json_dict(json.loads(attempt["expected_coin_json"]))
                inputs = ["0x" + cs.coin.name().hex() for cs in bundle.coin_spends]
                if (len(inputs) != 2 or set(inputs) != {claim["bridge_coin_id"], claim["current_vault_coin_id"]}
                        or expected_coin not in additions):
                    raise LedgerConflict("Signed stamp bundle differs from its frozen inputs or successor.")
                if attempt["bundle_hex"] is not None and attempt["bundle_hex"] != bundle_hex:
                    raise LedgerConflict("An exact signed stamp bundle is already retained.")
                if row["status"] not in ("evm_confirmed", "stamp_pending"):
                    raise LedgerConflict("Enrollment is not awaiting stamp submission.")
                record = json.loads(row["record_json"])
                record["receipt"].update(chiaVaultCoinId="0x" + expected_coin.name().hex(),
                    chiaSpendBundleId=bundle_id, confirmedBlockIndex=None)
                record.update(status="stamp_pending", updatedAt=now)
                self._conn.execute("""UPDATE enrollment_stamp_attempts SET bundle_hex=?,bundle_id=?,updated_at=?
                    WHERE vault_launcher_id=?""", (bundle_hex, bundle_id, now, vault))
                self._conn.execute("""UPDATE enrollments SET record_json=?,status='stamp_pending',
                    revision=revision+1,updated_at=? WHERE vault_launcher_id=?""", (_canonical_json(record), now, vault))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return record

    def record_stamp_dispatch(self, vault_launcher_id: str, bundle_id: str, result: str) -> None:
        if result not in {"unknown", "submitted", "rejected"}:
            raise LedgerError("Invalid stamp dispatch result.")
        with self._lock:
            cursor = self._conn.execute("""UPDATE enrollment_stamp_attempts SET dispatch_count=dispatch_count+CASE WHEN ?='unknown' THEN 1 ELSE 0 END,
                dispatch_status=?,updated_at=? WHERE vault_launcher_id=? AND bundle_id=? AND bundle_hex IS NOT NULL""",
                (result, result, int(time.time()), vault_launcher_id.lower(), bundle_id))
            if cursor.rowcount != 1:
                raise LedgerConflict("Stamp dispatch is not bound to a retained signed bundle.")

    def all_enrollments(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT vault_launcher_id, record_json FROM enrollments"
            ).fetchall()
        return {
            str(row["vault_launcher_id"]): json.loads(row["record_json"])
            for row in rows
        }

    def enrollment_bridge_coin_ids(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute("SELECT bridge_coin_id FROM enrollments").fetchall()
        return {str(row["bridge_coin_id"]).lower() for row in rows}

    def reserve_enrollment(
        self,
        *,
        record: dict[str, Any],
        owner_key: str,
        max_pending_per_owner: int = 3,
        permit_context: dict[str, Any] | None = None,
        permit_wire: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        vault = str(record["vaultLauncherId"]).lower()
        bridge_coin = str(record["bridgeCoinId"]).lower()
        now = int(time.time())
        record = dict(record)
        if (permit_context is None) != (permit_wire is None):
            raise LedgerConflict("Permit reservation context is incomplete.")
        if permit_wire is None and any(record.get(k) is not None for k in ('enrollmentPermit','permitIssuerSignature','permitIssuanceStatus')):
            raise LedgerConflict("Permit data requires an atomic permit reservation.")
        if permit_wire is not None:
            from solslot_puzzles.enrollment_permit import EnrollmentPermit, owner_key_hash
            from solslot_puzzles.enrollment_activation import activation_context
            permit = EnrollmentPermit.from_wire(permit_wire)
            if (permit.to_wire()['vaultLauncherId'] != vault or permit.to_wire()['bridgeCoinId'] != bridge_coin
                    or permit.context_hash != activation_context(permit_context['activation']).context_hash
                    or permit.owner_key_hash != owner_key_hash(permit.owner_auth_type, bytes.fromhex(owner_key.removeprefix('0x')))
                    or permit_context['activation']['bridgePolicyHash'] != record['bridgePolicyHash']):
                raise LedgerConflict("Permit does not bind the reserved owner, vault, bridge and deployment.")
            permit.require_live(now)
            record.update(enrollmentPermit=permit.to_wire(),permitIssuerSignature=None,permitIssuanceStatus='pending')
        encoded = _canonical_json(record)
        if type(max_pending_per_owner) is not int or not 1 <= max_pending_per_owner <= 20:
            raise LedgerError("Pending enrollment capacity must be between 1 and 20.")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT record_json FROM enrollments WHERE vault_launcher_id = ?",
                    (vault,),
                ).fetchone()
                if existing:
                    if permit_context is not None:
                        saved=self._conn.execute('SELECT context_json FROM enrollment_permits WHERE vault_launcher_id=?',(vault,)).fetchone()
                        if saved is None or saved['context_json'] != _canonical_json(permit_context):
                            raise LedgerConflict("Existing enrollment cannot be replaced or upgraded to a different permit.")
                    self._conn.execute("COMMIT")
                    return json.loads(existing["record_json"]), False
                pending = self._conn.execute(
                    "SELECT COUNT(*) FROM enrollments WHERE owner_key=? AND status='reserved'",
                    (owner_key.lower(),),
                ).fetchone()[0]
                if pending >= max_pending_per_owner:
                    raise LedgerRateLimited("Finish an existing verification before reserving another vault.")
                self._conn.execute(
                    """
                    INSERT INTO enrollments(
                        vault_launcher_id, network, policy_version, status,
                        bridge_coin_id, owner_key, record_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vault,
                        str(record["network"]),
                        int(record["policyVersion"]),
                        str(record["status"]),
                        bridge_coin,
                        owner_key.lower(),
                        encoded,
                        now,
                        now,
                    ),
                )
                if permit_wire is not None:
                    self._conn.execute("""INSERT INTO enrollment_permits
                        (vault_launcher_id,permit_id,permit_hash,current_vault_coin_id,bridge_coin_id,context_json,permit_json,created_at)
                        VALUES (?,?,?,?,?,?,?,?)""",(vault,permit_wire['permitId'],permit_wire['permitHash'],
                        permit_wire['currentVaultCoinId'],bridge_coin,_canonical_json(permit_context),_canonical_json(permit_wire),now))
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise LedgerConflict("The vault or bridge coin is already reserved.") from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return record, True

    def get_enrollment_permit(self, vault_launcher_id: str) -> dict[str, Any] | None:
        with self._lock:
            row=self._conn.execute('SELECT * FROM enrollment_permits WHERE vault_launcher_id=?',(vault_launcher_id.lower(),)).fetchone()
        return dict(row) if row else None

    def _require_immutable_permit(self, record: dict[str, Any]) -> None:
        """Called inside each enrollment mutation's existing SQL transaction."""
        row=self._conn.execute('SELECT * FROM enrollment_permits WHERE vault_launcher_id=?',(record['vaultLauncherId'].lower(),)).fetchone()
        if row is None:
            if any(record.get(k) is not None for k in ('enrollmentPermit','permitIssuerSignature','permitIssuanceStatus')):
                raise LedgerConflict('A historical enrollment cannot acquire a new permit.')
            return
        expected={'enrollmentPermit':json.loads(row['permit_json']),'permitIssuerSignature':row['issuer_signature'],
            'permitIssuanceStatus':'issued' if row['issuer_signature'] else 'pending'}
        stored=self._conn.execute('SELECT record_json FROM enrollments WHERE vault_launcher_id=?',(record['vaultLauncherId'].lower(),)).fetchone()
        original=json.loads(stored['record_json'])
        for key in ('vaultLauncherId','network','policyVersion','bridgePolicyHash','bridgeParentId','bridgeAmount','bridgeCoinId','createdAt'):
            expected[key]=original.get(key)
        # Python equality aliases True/1 and integer/float timestamps. Preserve
        # the exact JSON representation accepted by the signed wire parser.
        if _canonical_json({k:record.get(k) for k in expected}) != _canonical_json(expected):
            raise LedgerConflict('The original permit, issuer signature and enrollment binding are immutable.')

    def begin_permit_issuance(self, vault: str, context: dict[str, Any]) -> str | None:
        from solslot_puzzles.enrollment_permit import EnrollmentPermit
        now=int(time.time());vault=vault.lower()
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                row=self._conn.execute('SELECT * FROM enrollment_permits WHERE vault_launcher_id=?',(vault,)).fetchone()
                if row is None or row['context_json']!=_canonical_json(context):
                    raise LedgerConflict('Permit issuance requires its original reserved deployment context.')
                if row['issuer_signature']:
                    self._conn.execute('COMMIT');return None
                EnrollmentPermit.from_wire(json.loads(row['permit_json'])).require_live(now)
                history=self._conn.execute("SELECT COUNT(*) AS n,MAX(created_at) AS last FROM permit_issuance_history WHERE vault_launcher_id=? AND event='started'",(vault,)).fetchone()
                if history['n']>=10 or (history['last'] is not None and now-history['last']<5):
                    raise LedgerRateLimited('Saved permit signing is pending or its retry limit was reached.')
                attempt=secrets.token_hex(32)
                self._conn.execute('INSERT INTO permit_issuance_history(vault_launcher_id,attempt_id,event,created_at) VALUES (?,?,?,?)',(vault,attempt,'started',now))
                self._conn.execute('COMMIT');return attempt
            except Exception:
                self._conn.execute('ROLLBACK');raise

    def finish_permit_issuance(self, vault: str, context: dict[str,Any], attempt: str,
            *, signature: str | None = None, failure: str | None = None) -> dict[str,Any]:
        """First valid signature wins; every retry keeps the original authorization."""
        from .enrollment_permit_signing import verify_permit_signature
        now=int(time.time());vault=vault.lower()
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                row=self._conn.execute('SELECT * FROM enrollment_permits WHERE vault_launcher_id=?',(vault,)).fetchone()
                started=self._conn.execute("SELECT 1 FROM permit_issuance_history WHERE vault_launcher_id=? AND attempt_id=? AND event='started'",(vault,attempt)).fetchone()
                finished=self._conn.execute("SELECT 1 FROM permit_issuance_history WHERE attempt_id=? AND event!='started'",(attempt,)).fetchone()
                if row is None or not started or finished or row['context_json']!=_canonical_json(context):
                    raise LedgerConflict('Issuer completion does not match one unfinished reserved attempt.')
                event=failure
                if signature is not None:
                    if failure is not None:raise LedgerConflict('Ambiguous issuer result.')
                    signature=verify_permit_signature(json.loads(row['permit_json']),context['activation'],signature)
                    event='issued'
                    if row['issuer_signature'] is None:
                        record=json.loads(self._conn.execute('SELECT record_json FROM enrollments WHERE vault_launcher_id=?',(vault,)).fetchone()['record_json'])
                        self._require_immutable_permit(record)
                        record.update(permitIssuerSignature=signature,permitIssuanceStatus='issued')
                        self._conn.execute('UPDATE enrollment_permits SET issuer_signature=? WHERE vault_launcher_id=?',(signature,vault))
                        self._conn.execute('UPDATE enrollments SET record_json=?,revision=revision+1,updated_at=? WHERE vault_launcher_id=?',(_canonical_json(record),now,vault))
                elif failure not in ('invalid','unavailable'):
                    raise LedgerConflict('Invalid permit issuer outcome.')
                self._conn.execute('INSERT INTO permit_issuance_history(vault_launcher_id,attempt_id,event,created_at) VALUES (?,?,?,?)',(vault,attempt,event,now))
                result=json.loads(self._conn.execute('SELECT record_json FROM enrollments WHERE vault_launcher_id=?',(vault,)).fetchone()['record_json'])
                self._conn.execute('COMMIT');return result
            except Exception:
                self._conn.execute('ROLLBACK');raise

    def update_enrollment(
        self,
        record: dict[str, Any],
        *,
        expected_statuses: Optional[Iterable[str]] = None,
    ) -> dict[str, Any]:
        vault = str(record["vaultLauncherId"]).lower()
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status FROM enrollments WHERE vault_launcher_id = ?",
                    (vault,),
                ).fetchone()
                if not row:
                    raise LedgerConflict("Enrollment not found.")
                self._require_immutable_permit(record)
                allowed = set(expected_statuses or ())
                if allowed and str(row["status"]) not in allowed:
                    raise LedgerConflict(
                        f"Enrollment state changed from the expected state ({row['status']})."
                    )
                self._conn.execute(
                    """
                    UPDATE enrollments
                    SET status = ?, record_json = ?, revision = revision + 1,
                        updated_at = ?
                    WHERE vault_launcher_id = ?
                    """,
                    (str(record["status"]), _canonical_json(record), now, vault),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return record

    def record_evm_event(
        self,
        *,
        record: dict[str, Any],
        owner_key: str,
        transaction_hash: str,
        scoped_nullifier: str,
        bridge_coin_id: str,
        block_number: int,
    ) -> None:
        vault = str(record["vaultLauncherId"]).lower()
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status, owner_key, bridge_coin_id FROM enrollments "
                    "WHERE vault_launcher_id = ?",
                    (vault,),
                ).fetchone()
                if not row or row["status"] != "reserved":
                    raise LedgerConflict("Enrollment is not awaiting an EVM proof.")
                self._require_immutable_permit(record)
                if str(row["owner_key"]).lower() != owner_key.lower():
                    raise LedgerConflict("EVM event owner does not own this vault enrollment.")
                if str(row["bridge_coin_id"]).lower() != bridge_coin_id.lower():
                    raise LedgerConflict("EVM event bridge coin does not match the reservation.")
                self._conn.execute(
                    """
                    INSERT INTO evm_events(
                        transaction_hash, vault_launcher_id, owner_key,
                        scoped_nullifier, bridge_coin_id, block_number, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transaction_hash.lower(),
                        vault,
                        owner_key.lower(),
                        scoped_nullifier.lower(),
                        bridge_coin_id.lower(),
                        int(block_number),
                        now,
                    ),
                )
                self._conn.execute(
                    """
                    UPDATE enrollments
                    SET status = ?, record_json = ?, revision = revision + 1,
                        updated_at = ?
                    WHERE vault_launcher_id = ?
                    """,
                    (str(record["status"]), _canonical_json(record), now, vault),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise LedgerConflict(
                    "The EVM transaction, vault, nullifier, or bridge coin was already consumed."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def issue_owner_challenge(
        self,
        *,
        vault_launcher_id: str,
        action: str,
        payload_hash: str,
        auth_type: str,
        ttl_seconds: int,
        max_pending: int = 50_000,
    ) -> OwnerChallenge:
        if type(ttl_seconds) is not int or not 0 < ttl_seconds <= OWNER_CHALLENGE_MAX_TTL_SECONDS:
            raise LedgerError("Owner challenge TTL must be between 1 and 900 seconds.")
        if type(max_pending) is not int or max_pending <= 0:
            raise LedgerError("Owner challenge capacity must be a positive integer.")
        now = int(time.time())
        challenge = OwnerChallenge(
            challenge_id=secrets.token_hex(24),
            vault_launcher_id=vault_launcher_id.lower(),
            action=action,
            payload_hash=payload_hash.lower(),
            nonce="0x" + secrets.token_hex(32),
            auth_type=auth_type,
            expires_at=now + int(ttl_seconds),
        )
        with self._lock:
            # The check and insert share the same SQLite write transaction,
            # so workers/restarts cannot each admit up to the global cap.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._prune_expired_owner_challenges(now)
                retained = int(self._conn.execute("SELECT COUNT(*) FROM owner_challenges").fetchone()[0])
                if retained >= max_pending:
                    # Commit safe expiry cleanup even if a lowered cap is
                    # still full. Never evict an outstanding challenge.
                    self._conn.execute("COMMIT")
                    raise LedgerRateLimited("Owner challenge store is at capacity; try again later.")
                self._conn.execute(
                    """
                    INSERT INTO owner_challenges(
                        challenge_id, vault_launcher_id, action, payload_hash,
                        nonce, auth_type, expires_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        challenge.challenge_id,
                        challenge.vault_launcher_id,
                        action,
                        challenge.payload_hash,
                        challenge.nonce,
                        auth_type,
                        challenge.expires_at,
                        now,
                    ),
                )
                self._conn.execute("COMMIT")
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise
        return challenge

    def consume_owner_challenge(
        self,
        *,
        challenge_id: str,
        vault_launcher_id: str,
        action: str,
        payload_hash: str,
    ) -> OwnerChallenge:
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM owner_challenges WHERE challenge_id = ?",
                    (challenge_id,),
                ).fetchone()
                if not row:
                    raise LedgerConflict("Owner challenge is unknown.")
                if row["consumed_at"] is not None:
                    raise LedgerConflict("Owner challenge was already consumed.")
                if int(row["expires_at"]) < now:
                    raise LedgerConflict("Owner challenge expired.")
                expected = (
                    vault_launcher_id.lower(),
                    action,
                    payload_hash.lower(),
                )
                observed = (
                    str(row["vault_launcher_id"]).lower(),
                    str(row["action"]),
                    str(row["payload_hash"]).lower(),
                )
                if observed != expected:
                    raise LedgerConflict("Owner challenge does not match this mutation.")
                self._conn.execute(
                    "UPDATE owner_challenges SET consumed_at = ? WHERE challenge_id = ?",
                    (now, challenge_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return OwnerChallenge(
            challenge_id=str(row["challenge_id"]),
            vault_launcher_id=str(row["vault_launcher_id"]),
            action=str(row["action"]),
            payload_hash=str(row["payload_hash"]),
            nonce=str(row["nonce"]),
            auth_type=str(row["auth_type"]),
            expires_at=int(row["expires_at"]),
        )

    def get_owner_challenge(self, challenge_id: str) -> Optional[OwnerChallenge]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM owner_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        if not row or row["consumed_at"] is not None:
            return None
        return OwnerChallenge(
            challenge_id=str(row["challenge_id"]),
            vault_launcher_id=str(row["vault_launcher_id"]),
            action=str(row["action"]),
            payload_hash=str(row["payload_hash"]),
            nonce=str(row["nonce"]),
            auth_type=str(row["auth_type"]),
            expires_at=int(row["expires_at"]),
        )

    def get_relay_attempt(self, vault_launcher_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM relay_attempts WHERE vault_launcher_id=?",
                (vault_launcher_id.lower(),)).fetchone()
        return dict(row) if row else None

    def get_relay_transaction(self, vault_launcher_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM relay_transactions WHERE vault_launcher_id=?",
                (vault_launcher_id.lower(),)).fetchone()
        return dict(row) if row else None

    def prepare_relay_transaction(self, *, request_digest: str, context: dict[str, Any],
                                  request: dict[str, Any], transaction: dict[str, Any],
                                  sign_transaction: Any, retry_until: int) -> dict[str, Any]:
        """Allocate the outer nonce, sign locally and retain bytes in one SQLite transaction.

        The callback must only sign the supplied transaction; it must not send
        or perform provider work. BEGIN IMMEDIATE serializes every API worker
        and both owner modes. No consumed/ambiguous nonce is ever reused.
        """
        from .evm_relay_transaction import signed_transaction_identity
        encoded_context, encoded_request = _canonical_json(context), _canonical_json(request)
        now = int(time.time())
        if type(retry_until) is not int or not now < retry_until <= now + 3600:
            raise LedgerConflict('Relay retry deadline is invalid.')
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                row = self._conn.execute('SELECT * FROM relay_attempts WHERE request_digest=?',
                    (request_digest.lower(),)).fetchone()
                if not row or row['status'] != 'reserved':
                    raise LedgerConflict('Relay reservation is unavailable for transaction preparation.')
                prior = self._conn.execute('SELECT * FROM relay_transactions WHERE request_digest=?',
                    (request_digest.lower(),)).fetchone()
                if prior:
                    raise LedgerConflict('Relay transaction is already frozen; recover its exact bytes.')
                if (context.get('owner') != row['owner_key'] or context.get('vaultLauncherId') != row['vault_launcher_id']
                        or context.get('bridgeCoinId') != row['bridge_coin_id']):
                    raise LedgerConflict('Relay transaction context does not match its reservation.')
                ambiguous_legacy = self._conn.execute("""SELECT 1 FROM relay_attempts AS a
                    JOIN enrollments AS e ON e.vault_launcher_id=a.vault_launcher_id
                    WHERE a.construction_version=0 AND e.status='reserved' LIMIT 1""").fetchone()
                if ambiguous_legacy:
                    raise LedgerConflict('An unresolved historical relay must be reconciled before allocating any new sponsored transaction nonce.')
                tx = dict(transaction)
                latest = self._conn.execute('SELECT MAX(outer_nonce) FROM relay_transactions WHERE chain_id=? AND relayer=?',
                    (tx['chainId'], tx['from'].lower())).fetchone()[0]
                tx['nonce'] = max(int(tx['nonce']), int(latest) + 1 if latest is not None else 0)
                raw = bytes(sign_transaction(tx).raw_transaction)
                identity = signed_transaction_identity(raw, tx)
                self._conn.execute("""INSERT INTO relay_transactions
                    (request_digest,vault_launcher_id,context_json,request_json,raw_transaction_hex,
                     tx_hash,chain_id,relayer,outer_nonce,retry_until,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (request_digest.lower(),row['vault_launcher_id'],encoded_context,
                    encoded_request,raw.hex(),identity['tx_hash'],identity['chain_id'],identity['relayer'],identity['nonce'],retry_until,now))
                self._conn.execute('UPDATE relay_attempts SET tx_hash=?, updated_at=? WHERE request_digest=?',
                    (identity['tx_hash'],now,request_digest.lower()))
                self._conn.execute('COMMIT')
            except Exception:
                self._conn.execute('ROLLBACK')
                raise
        return self.get_relay_transaction(row['vault_launcher_id'])

    def begin_relay_dispatch(self, request_digest: str) -> dict[str, Any]:
        """Durably record uncertainty before every send; serialize/bound exact retries."""
        now = int(time.time())
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                row = self._conn.execute('SELECT * FROM relay_transactions WHERE request_digest=?',
                    (request_digest.lower(),)).fetchone()
                if not row or now >= row['retry_until']:
                    raise LedgerConflict('Relay authorization expired; check its original transaction receipt.')
                if row['last_dispatch_at'] is not None and now < row['last_dispatch_at'] + 5:
                    raise LedgerRateLimited('A relay submission is already in progress; check its receipt shortly.')
                circuit = self._conn.execute('SELECT open_until FROM relay_circuit WHERE singleton=1').fetchone()
                if circuit and circuit['open_until'] > now:
                    raise LedgerCircuitOpen('The sponsored relay circuit is temporarily open.')
                self._conn.execute("UPDATE relay_transactions SET dispatch_status='unknown', dispatch_count=dispatch_count+1, last_dispatch_at=? WHERE request_digest=?",
                    (now,request_digest.lower()))
                self._conn.execute('COMMIT')
            except Exception:
                self._conn.execute('ROLLBACK')
                raise
        return self.get_relay_transaction(row['vault_launcher_id'])

    def finish_relay_dispatch(self, *, request_digest: str, accepted: bool,
                              failure_threshold: int, cooldown_seconds: int) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                row = self._conn.execute('SELECT * FROM relay_transactions WHERE request_digest=?',
                    (request_digest.lower(),)).fetchone()
                if not row or row['dispatch_count'] < 1:
                    raise LedgerConflict('Relay dispatch was not retained before submission.')
                # An error never clears the hash or implies that bytes were not accepted.
                self._conn.execute('UPDATE relay_transactions SET dispatch_status=? WHERE request_digest=?',
                    ('submitted' if accepted else 'unknown',request_digest.lower()))
                self._conn.execute("UPDATE relay_attempts SET status=?,tx_hash=?,error=?,updated_at=? WHERE request_digest=?",
                    ('submitted' if accepted else 'reserved',row['tx_hash'],None if accepted else 'Provider response unavailable; reconcile retained transaction.',now,request_digest.lower()))
                circuit = self._conn.execute('SELECT consecutive_failures FROM relay_circuit WHERE singleton=1').fetchone()
                failures = 0 if accepted else int(circuit['consecutive_failures']) + 1
                self._conn.execute('UPDATE relay_circuit SET consecutive_failures=?,open_until=?,updated_at=? WHERE singleton=1',
                    (failures,now+cooldown_seconds if failures>=failure_threshold else 0,now))
                self._conn.execute('COMMIT')
            except Exception:
                self._conn.execute('ROLLBACK')
                raise

    def reserve_relay(
        self,
        *,
        request_digest: str,
        vault_launcher_id: str,
        owner_key: str,
        source_ip: str,
        bridge_coin_id: str,
        forwarder_nonce: int,
        inner_gas: int,
        per_ip_per_minute: int,
        per_owner_per_minute: int,
        per_vault_per_hour: int,
        global_gas_per_day: int,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                circuit = self._conn.execute(
                    "SELECT open_until FROM relay_circuit WHERE singleton = 1"
                ).fetchone()
                if circuit and int(circuit["open_until"]) > now:
                    raise LedgerCircuitOpen("The sponsored relay circuit is temporarily open.")

                enrollment = self._conn.execute(
                    "SELECT owner_key, bridge_coin_id, status FROM enrollments "
                    "WHERE vault_launcher_id = ?",
                    (vault_launcher_id.lower(),),
                ).fetchone()
                if not enrollment or enrollment["status"] != "reserved":
                    raise LedgerConflict("Enrollment is not eligible for a relay.")
                if str(enrollment["owner_key"]).lower() != owner_key.lower():
                    raise LedgerConflict("Relay signer does not own the enrollment.")
                if str(enrollment["bridge_coin_id"]).lower() != bridge_coin_id.lower():
                    raise LedgerConflict("Relay bridge coin does not match the enrollment.")

                limits = (
                    ("source_ip", source_ip, now - 60, per_ip_per_minute, "source IP"),
                    ("owner_key", owner_key.lower(), now - 60, per_owner_per_minute, "owner"),
                    (
                        "vault_launcher_id",
                        vault_launcher_id.lower(),
                        now - 3600,
                        per_vault_per_hour,
                        "vault",
                    ),
                )
                for column, value, since, maximum, label in limits:
                    count = int(
                        self._conn.execute(
                            f"SELECT COUNT(*) FROM relay_attempts WHERE {column} = ? "
                            "AND created_at >= ?",
                            (value, since),
                        ).fetchone()[0]
                    )
                    if count >= maximum:
                        raise LedgerRateLimited(f"Relay budget exhausted for this {label}.")

                gas_used = int(
                    self._conn.execute(
                        "SELECT COALESCE(SUM(inner_gas), 0) FROM relay_attempts "
                        "WHERE created_at >= ?",
                        (now - 86400,),
                    ).fetchone()[0]
                )
                if gas_used + int(inner_gas) > global_gas_per_day:
                    raise LedgerRateLimited("The global daily sponsored gas budget is exhausted.")

                self._conn.execute(
                    """
                    INSERT INTO relay_attempts(
                        request_digest, vault_launcher_id, owner_key, source_ip,
                        bridge_coin_id, forwarder_nonce, inner_gas, status,
                        created_at, updated_at, construction_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, 1)
                    """,
                    (
                        request_digest.lower(),
                        vault_launcher_id.lower(),
                        owner_key.lower(),
                        source_ip,
                        bridge_coin_id.lower(),
                        str(forwarder_nonce),
                        int(inner_gas),
                        now,
                        now,
                    ),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise LedgerConflict(
                    "This relay request, nonce, or bridge coin was already consumed."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def finish_relay(
        self,
        *,
        request_digest: str,
        tx_hash: Optional[str],
        error: Optional[str],
        failure_threshold: int,
        cooldown_seconds: int,
    ) -> None:
        now = int(time.time())
        failed = error is not None
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                durable = self._conn.execute('SELECT tx_hash FROM relay_transactions WHERE request_digest=?',
                    (request_digest.lower(),)).fetchone()
                if durable:
                    raise LedgerConflict('Durable relay attempts must use exact dispatch reconciliation.')
                updated = self._conn.execute(
                    """
                    UPDATE relay_attempts
                    SET status = ?, tx_hash = ?, error = ?, updated_at = ?
                    WHERE request_digest = ? AND status = 'reserved'
                    """,
                    (
                        "failed" if failed else "submitted",
                        tx_hash.lower() if tx_hash else None,
                        error,
                        now,
                        request_digest.lower(),
                    ),
                )
                if updated.rowcount != 1:
                    raise LedgerConflict(
                        "The relay reservation is missing or was already finalized."
                    )
                circuit = self._conn.execute(
                    "SELECT consecutive_failures FROM relay_circuit WHERE singleton = 1"
                ).fetchone()
                failures = int(circuit["consecutive_failures"]) if circuit else 0
                failures = failures + 1 if failed else 0
                open_until = now + cooldown_seconds if failures >= failure_threshold else 0
                self._conn.execute(
                    """
                    UPDATE relay_circuit
                    SET consecutive_failures = ?, open_until = ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (failures, open_until, now),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def require_submitted_relay(
        self,
        *,
        transaction_hash: str,
        vault_launcher_id: str,
        owner_key: str,
        bridge_coin_id: str,
    ) -> None:
        """Bind an already independently verified canonical BLS event to authorization.

        A retained signed transaction is sufficient even when its provider
        response was lost. This helper alone never establishes confirmation.
        """

        with self._lock:
            rows = self._conn.execute(
                """
                SELECT vault_launcher_id, owner_key, bridge_coin_id
                FROM relay_attempts
                WHERE tx_hash = ? AND (status = 'submitted' OR EXISTS (
                    SELECT 1 FROM relay_transactions AS durable
                    WHERE durable.request_digest = relay_attempts.request_digest
                    AND durable.tx_hash = relay_attempts.tx_hash))
                """,
                (transaction_hash.lower(),),
            ).fetchall()
        if len(rows) != 1:
            raise LedgerConflict(
                "The BLS attestation event is not bound to one submitted relay."
            )
        row = rows[0]
        expected = (
            vault_launcher_id.lower(),
            owner_key.lower(),
            bridge_coin_id.lower(),
        )
        observed = (
            str(row["vault_launcher_id"]).lower(),
            str(row["owner_key"]).lower(),
            str(row["bridge_coin_id"]).lower(),
        )
        if observed != expected:
            raise LedgerConflict(
                "The submitted BLS relay does not match this vault owner and bridge coin."
            )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


_LEDGERS: dict[str, CredentialLedger] = {}
_LEDGERS_LOCK = threading.Lock()


def get_credential_ledger(settings: Any) -> CredentialLedger:
    path = str(settings.zkpassport_ledger_db_path)
    with _LEDGERS_LOCK:
        ledger = _LEDGERS.get(path)
        if ledger is None:
            ledger = CredentialLedger(path)
            _LEDGERS[path] = ledger
        return ledger


def get_existing_credential_ledger(settings: Any) -> CredentialLedger | None:
    """Open retained recovery state without creating a ledger for a blocked request."""

    path = str(settings.zkpassport_ledger_db_path)
    with _LEDGERS_LOCK:
        ledger = _LEDGERS.get(path)
        if ledger is None and path != ":memory:" and Path(path).is_file():
            ledger = CredentialLedger(path)
            _LEDGERS[path] = ledger
        return ledger


def reset_credential_ledgers_for_tests() -> None:
    with _LEDGERS_LOCK:
        for ledger in _LEDGERS.values():
            ledger.close()
        _LEDGERS.clear()


__all__ = [
    "CredentialLedger",
    "LedgerCircuitOpen",
    "LedgerConflict",
    "LedgerError",
    "LedgerRateLimited",
    "OwnerChallenge",
    "get_credential_ledger",
    "get_existing_credential_ledger",
    "reset_credential_ledgers_for_tests",
]
