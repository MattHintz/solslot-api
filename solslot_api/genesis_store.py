"""Persistent, fail-closed state machine for the Solslot V2 ceremony."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Settings


SCHEMA_VERSION = 13
ADMIN_SLOTS = (1, 2, 3)
TERMINAL_STATES = frozenset({"locked", "abandoned"})
ABANDONABLE_STATES = frozenset(
    {"draft", "roster_open", "roster_frozen", "planned", "plan_approved"}
)
OWNER_SLOT = 1
COADMIN_SLOTS = frozenset({2, 3})


def owner_plus_one_approved(slots: set[int]) -> bool:
    """Ceremony slots are one-based: slot 1 is the permanent owner."""
    return OWNER_SLOT in slots and bool(slots & COADMIN_SLOTS)


def launch_gate_action_id(ceremony_id: str, gate_name: str, payload_hash: str) -> str:
    import hashlib
    return "0x" + hashlib.sha256(
        f"{ceremony_id}:gate:{gate_name}:{payload_hash.lower()}".encode("ascii")
    ).hexdigest()


class GenesisStoreError(RuntimeError):
    """Base class for ceremony persistence errors."""


class GenesisNotFound(GenesisStoreError):
    """The requested ceremony or invitation does not exist."""


class GenesisConflict(GenesisStoreError):
    """A ceremony transition is stale, duplicated, or out of order."""


class GenesisExpired(GenesisStoreError):
    """An invitation or signed plan has expired."""


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class GenesisStore:
    """SQLite-WAL ledger shared by all API workers.

    Every mutation uses ``BEGIN IMMEDIATE``. State transitions and signature
    inserts therefore remain atomic even when administrators submit at the
    same time or the API process restarts between phases.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path) if str(path) == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._memory_connection: sqlite3.Connection | None = None
        if self.path == ":memory:":
            self._memory_connection = sqlite3.connect(
                ":memory:", isolation_level=None, check_same_thread=False
            )
            self._configure(self._memory_connection)
        self._migrate()
        self.validate_pending_broadcast_reservations()

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA synchronous = FULL")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._memory_connection is not None:
            yield self._memory_connection
            return
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self._configure(connection)
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    def _migrate(self) -> None:
        with self._connect() as connection:
            if self.path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Genesis store schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version < 1:
                connection.executescript(
                    """
                BEGIN IMMEDIATE;
                CREATE TABLE ceremonies (
                    ceremony_id TEXT PRIMARY KEY,
                    network TEXT NOT NULL,
                    state TEXT NOT NULL,
                    draft_json TEXT NOT NULL,
                    roster_hash TEXT,
                    plan_input_json TEXT,
                    plan_json TEXT,
                    plan_hash TEXT UNIQUE,
                    plan_expires_at INTEGER,
                    spend_bundle_id TEXT UNIQUE,
                    broadcast_json TEXT,
                    confirmed_block_index INTEGER,
                    artifact_json TEXT,
                    artifact_hash TEXT UNIQUE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    CHECK (network = 'testnet11'),
                    CHECK (state IN (
                        'draft', 'roster_open', 'roster_frozen', 'planned',
                        'plan_approved', 'broadcast', 'confirmed',
                        'artifact_pending', 'artifact_signed', 'locked', 'abandoned'
                    ))
                );

                CREATE TABLE invitations (
                    ceremony_id TEXT NOT NULL,
                    slot INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    nonce TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER,
                    wallet_address TEXT,
                    compressed_pubkey TEXT,
                    enrollment_signature TEXT,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (ceremony_id, slot),
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                    CHECK (slot IN (1, 2, 3))
                );

                CREATE TABLE plan_signatures (
                    ceremony_id TEXT NOT NULL,
                    slot INTEGER NOT NULL,
                    plan_hash TEXT NOT NULL,
                    compressed_pubkey TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL,
                    PRIMARY KEY (ceremony_id, slot),
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                    CHECK (slot IN (1, 2, 3))
                );

                CREATE TABLE artifact_signatures (
                    ceremony_id TEXT NOT NULL,
                    slot INTEGER NOT NULL,
                    artifact_hash TEXT NOT NULL,
                    compressed_pubkey TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL,
                    PRIMARY KEY (ceremony_id, slot),
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                    CHECK (slot IN (1, 2, 3))
                );

                CREATE TABLE audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ceremony_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id)
                );
                CREATE INDEX audit_events_ceremony_idx
                    ON audit_events(ceremony_id, event_id);
                PRAGMA user_version = 1;
                COMMIT;
                """
                )
                version = 1
            if version < 2:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE launch_claims (
                        ceremony_id TEXT PRIMARY KEY,
                        token_hash TEXT NOT NULL UNIQUE,
                        consumed_at INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id)
                    );

                    CREATE TABLE launch_profiles (
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        display_name TEXT NOT NULL,
                        role_label TEXT NOT NULL,
                        email TEXT,
                        timezone TEXT NOT NULL,
                        reminders_enabled INTEGER NOT NULL DEFAULT 1,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, slot),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3)),
                        CHECK (reminders_enabled IN (0, 1))
                    );

                    CREATE TABLE launch_auth_challenges (
                        nonce_hash TEXT PRIMARY KEY,
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        wallet_address TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3))
                    );
                    CREATE INDEX launch_auth_challenges_expiry_idx
                        ON launch_auth_challenges(expires_at, consumed_at);

                    CREATE TABLE launch_action_approvals (
                        ceremony_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        signer_address TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, action_id, slot),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3))
                    );

                    CREATE TABLE launch_gates (
                        ceremony_id TEXT NOT NULL,
                        gate_name TEXT NOT NULL,
                        network TEXT NOT NULL,
                        opens_at INTEGER NOT NULL,
                        closes_at INTEGER NOT NULL,
                        payload_hash TEXT NOT NULL,
                        state TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, gate_name),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (network = 'testnet11'),
                        CHECK (state IN ('pending', 'open', 'closed', 'cancelled')),
                        CHECK (closes_at > opens_at)
                    );

                    CREATE TABLE genesis_funding_receipts (
                        ceremony_id TEXT PRIMARY KEY,
                        plan_json TEXT NOT NULL,
                        plan_hash TEXT NOT NULL UNIQUE,
                        spend_bundle_id TEXT UNIQUE,
                        response_json TEXT,
                        state TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN (
                            'prepared', 'approved', 'broadcast', 'confirmed', 'ambiguous'
                        ))
                    );

                    PRAGMA user_version = 2;
                    COMMIT;
                    """
                )
                version = 2
            if version < 3:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE launch_action_intents (
                        ceremony_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        payload_hash TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        state TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, action_id),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN ('prepared', 'executed', 'cancelled'))
                    );

                    CREATE TABLE launch_settlement_rehearsals (
                        ceremony_id TEXT PRIMARY KEY,
                        job_id TEXT NOT NULL UNIQUE,
                        config_hash TEXT NOT NULL,
                        state TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN (
                            'PREPARED', 'AWAITING_WALLET', 'PAYMENT_SUBMITTED',
                            'VALIDATING', 'SUCCEEDED', 'FAILED'
                        ))
                    );

                    PRAGMA user_version = 3;
                    COMMIT;
                    """
                )
                version = 3
            if version < 4:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE admin_recovery_drills (
                        challenge_id TEXT PRIMARY KEY,
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        challenge_hash TEXT NOT NULL UNIQUE,
                        public_json TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3))
                    );
                    CREATE INDEX admin_recovery_drills_expiry_idx
                        ON admin_recovery_drills(expires_at, consumed_at);

                    CREATE TABLE admin_recovery_kits (
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        revision INTEGER NOT NULL,
                        evm_guardian TEXT NOT NULL,
                        recovery_bls_pubkey TEXT NOT NULL,
                        recovery_bls_commitment TEXT NOT NULL,
                        drill_challenge_hash TEXT NOT NULL,
                        drill_verified_at INTEGER NOT NULL,
                        offline_copy_confirmed INTEGER NOT NULL,
                        second_device_confirmed INTEGER NOT NULL,
                        backup_status TEXT NOT NULL,
                        backup_revision INTEGER,
                        backup_ciphertext_hash TEXT,
                        backup_verified_at INTEGER,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (ceremony_id, slot),
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (slot IN (1, 2, 3)),
                        CHECK (revision >= 1),
                        CHECK (offline_copy_confirmed = 1),
                        CHECK (second_device_confirmed = 1),
                        CHECK (backup_status IN ('NOT_CONFIGURED', 'VERIFIED'))
                    );

                    CREATE TABLE admin_recovery_cases (
                        case_id TEXT PRIMARY KEY,
                        ceremony_id TEXT NOT NULL,
                        authority_slot INTEGER NOT NULL,
                        kind TEXT NOT NULL,
                        state TEXT NOT NULL,
                        intent_hash TEXT NOT NULL UNIQUE,
                        intent_json TEXT NOT NULL,
                        execute_after INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        prepared_by TEXT NOT NULL,
                        chia_transaction_id TEXT,
                        evm_transaction_hash TEXT,
                        chia_receipt_hash TEXT,
                        evm_receipt_hash TEXT,
                        failure_reason TEXT,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (authority_slot IN (0, 1, 2)),
                        CHECK (kind IN ('ROUTINE', 'LOST')),
                        CHECK (state IN (
                            'PREPARED', 'AWAITING_APPROVALS', 'READY',
                            'SUBMITTED', 'PARTIAL', 'COMPLETED',
                            'CANCELLED', 'FAILED'
                        )),
                        CHECK (expires_at > execute_after)
                    );
                    CREATE INDEX admin_recovery_cases_active_idx
                        ON admin_recovery_cases(ceremony_id, state, created_at);

                    CREATE TABLE admin_recovery_approvals (
                        case_id TEXT NOT NULL,
                        actor_role TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        signer_slot INTEGER,
                        signer_address TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, actor_role, actor_id),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (actor_role IN (
                            'PREPARER', 'AUTHORITY', 'PEER',
                            'REPLACEMENT', 'OLD_KEY_VETO'
                        )),
                        CHECK (signer_slot IS NULL OR signer_slot IN (0, 1, 2))
                    );

                    CREATE TABLE admin_recovery_receipts (
                        case_id TEXT NOT NULL,
                        chain TEXT NOT NULL,
                        transaction_id TEXT NOT NULL,
                        receipt_hash TEXT NOT NULL,
                        receipt_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, chain),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (chain IN ('CHIA', 'EVM'))
                    );

                    CREATE TABLE admin_notification_outbox (
                        notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ceremony_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        body TEXT NOT NULL,
                        state TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (state IN ('PENDING', 'SENT', 'FAILED'))
                    );
                    CREATE INDEX admin_notification_outbox_state_idx
                        ON admin_notification_outbox(state, notification_id);

                    PRAGMA user_version = 4;
                    COMMIT;
                    """
                )
                version = 4
            if version < 5:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE admin_recovery_receipts
                        RENAME TO admin_recovery_receipts_v4;

                    CREATE TABLE admin_recovery_receipts (
                        case_id TEXT NOT NULL,
                        chain TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        transaction_id TEXT NOT NULL,
                        receipt_hash TEXT NOT NULL,
                        receipt_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, chain, phase),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (chain IN ('CHIA', 'EVM')),
                        CHECK (phase IN (
                            'PREPARE', 'APPROVE', 'EXECUTE',
                            'CANCEL', 'COMPLETE', 'ROLLBACK'
                        ))
                    );

                    INSERT INTO admin_recovery_receipts(
                        case_id,chain,phase,transaction_id,receipt_hash,
                        receipt_json,observed_at
                    )
                    SELECT
                        case_id,chain,'COMPLETE',transaction_id,receipt_hash,
                        receipt_json,observed_at
                    FROM admin_recovery_receipts_v4;

                    DROP TABLE admin_recovery_receipts_v4;
                    PRAGMA user_version = 5;
                    COMMIT;
                    """
                )
                version = 5
            if version < 6:
                connection.executescript(
                    """
                    PRAGMA foreign_keys = OFF;
                    BEGIN IMMEDIATE;

                    DROP INDEX admin_recovery_cases_active_idx;
                    ALTER TABLE admin_recovery_approvals
                        RENAME TO admin_recovery_approvals_v5;
                    ALTER TABLE admin_recovery_receipts
                        RENAME TO admin_recovery_receipts_v5;
                    ALTER TABLE admin_recovery_cases
                        RENAME TO admin_recovery_cases_v5;

                    CREATE TABLE admin_recovery_cases (
                        case_id TEXT PRIMARY KEY,
                        ceremony_id TEXT NOT NULL,
                        authority_slot INTEGER NOT NULL,
                        kind TEXT NOT NULL,
                        state TEXT NOT NULL,
                        intent_hash TEXT NOT NULL UNIQUE,
                        intent_json TEXT NOT NULL,
                        execute_after INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        prepared_by TEXT NOT NULL,
                        chia_transaction_id TEXT,
                        evm_transaction_hash TEXT,
                        chia_receipt_hash TEXT,
                        evm_receipt_hash TEXT,
                        failure_reason TEXT,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (authority_slot IN (0, 1, 2)),
                        CHECK (kind IN ('ROUTINE', 'LOST', 'RECOVERY_KIT')),
                        CHECK (state IN (
                            'PREPARED', 'AWAITING_APPROVALS', 'READY',
                            'SUBMITTED', 'PARTIAL', 'COMPLETED',
                            'CANCELLED', 'FAILED'
                        )),
                        CHECK (expires_at > execute_after)
                    );
                    INSERT INTO admin_recovery_cases
                    SELECT * FROM admin_recovery_cases_v5;

                    CREATE TABLE admin_recovery_approvals (
                        case_id TEXT NOT NULL,
                        actor_role TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        signer_slot INTEGER,
                        signer_address TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, actor_role, actor_id),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (actor_role IN (
                            'PREPARER', 'AUTHORITY', 'PEER',
                            'REPLACEMENT', 'OLD_KEY_VETO'
                        )),
                        CHECK (signer_slot IS NULL OR signer_slot IN (0, 1, 2))
                    );
                    INSERT INTO admin_recovery_approvals
                    SELECT * FROM admin_recovery_approvals_v5;

                    CREATE TABLE admin_recovery_receipts (
                        case_id TEXT NOT NULL,
                        chain TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        transaction_id TEXT NOT NULL,
                        receipt_hash TEXT NOT NULL,
                        receipt_json TEXT NOT NULL,
                        observed_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, chain, phase),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (chain IN ('CHIA', 'EVM')),
                        CHECK (phase IN (
                            'PREPARE', 'APPROVE', 'EXECUTE',
                            'CANCEL', 'COMPLETE', 'ROLLBACK'
                        ))
                    );
                    INSERT INTO admin_recovery_receipts
                    SELECT * FROM admin_recovery_receipts_v5;

                    DROP TABLE admin_recovery_approvals_v5;
                    DROP TABLE admin_recovery_receipts_v5;
                    DROP TABLE admin_recovery_cases_v5;
                    CREATE INDEX admin_recovery_cases_active_idx
                        ON admin_recovery_cases(ceremony_id, state, created_at);

                    CREATE TABLE admin_recovery_kit_candidates (
                        challenge_id TEXT PRIMARY KEY,
                        ceremony_id TEXT NOT NULL,
                        slot INTEGER NOT NULL,
                        revision INTEGER NOT NULL,
                        evm_guardian TEXT NOT NULL,
                        recovery_bls_pubkey TEXT NOT NULL,
                        recovery_bls_commitment TEXT NOT NULL,
                        drill_challenge_hash TEXT NOT NULL,
                        drill_verified_at INTEGER NOT NULL,
                        offline_copy_confirmed INTEGER NOT NULL,
                        second_device_confirmed INTEGER NOT NULL,
                        backup_status TEXT NOT NULL,
                        backup_revision INTEGER,
                        backup_ciphertext_hash TEXT,
                        backup_verified_at INTEGER,
                        state TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        FOREIGN KEY (challenge_id) REFERENCES admin_recovery_drills(challenge_id),
                        CHECK (slot IN (1, 2, 3)),
                        CHECK (revision >= 2),
                        CHECK (offline_copy_confirmed = 1),
                        CHECK (second_device_confirmed = 1),
                        CHECK (backup_status IN ('NOT_CONFIGURED', 'VERIFIED')),
                        CHECK (state IN ('PENDING', 'ACTIVATED', 'CANCELLED'))
                    );
                    CREATE UNIQUE INDEX admin_recovery_kit_candidate_pending_idx
                        ON admin_recovery_kit_candidates(ceremony_id, slot)
                        WHERE state = 'PENDING';

                    PRAGMA user_version = 6;
                    COMMIT;
                    PRAGMA foreign_keys = ON;
                    """
                )
                version = 6
            if version < 7:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE admin_recovery_chia_signatures (
                        case_id TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        signer_kind TEXT NOT NULL,
                        signer_slot INTEGER,
                        signer_public_key TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, phase, action_id),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (phase IN ('PREPARE', 'CANCEL')),
                        CHECK (signer_kind IN ('EIP712_DAILY', 'BLS_RECOVERY')),
                        CHECK (signer_slot IS NULL OR signer_slot IN (0, 1, 2))
                    );
                    CREATE INDEX admin_recovery_chia_signatures_case_idx
                        ON admin_recovery_chia_signatures(
                            case_id, phase, submitted_at
                        );

                    PRAGMA user_version = 7;
                    COMMIT;
                    """
                )
                version = 7
            if version < 8:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE admin_recovery_evm_safe_signatures (
                        case_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        package_hash TEXT NOT NULL,
                        safe_nonce INTEGER NOT NULL,
                        coadmin_slot INTEGER,
                        signer_slot INTEGER NOT NULL,
                        signer_role TEXT NOT NULL,
                        signer_address TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, action_id, signer_slot),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (safe_nonce >= 0),
                        CHECK (coadmin_slot IS NULL OR coadmin_slot IN (1, 2)),
                        CHECK (signer_slot IN (0, 1, 2)),
                        CHECK (signer_role IN ('OWNER', 'COADMIN', 'PEER'))
                    );
                    CREATE INDEX admin_recovery_evm_safe_signatures_package_idx
                        ON admin_recovery_evm_safe_signatures(
                            case_id, action_id, package_hash, submitted_at
                        );

                    PRAGMA user_version = 8;
                    COMMIT;
                    """
                )
                version = 8
            if version < 9:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE admin_recovery_evm_submissions (
                        case_id TEXT NOT NULL,
                        action_id TEXT NOT NULL,
                        transaction_hash TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL,
                        submitted_by TEXT NOT NULL,
                        submitted_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (case_id, action_id),
                        FOREIGN KEY (case_id) REFERENCES admin_recovery_cases(case_id),
                        CHECK (state IN ('PENDING', 'CONFIRMED'))
                    );
                    CREATE INDEX admin_recovery_evm_submissions_state_idx
                        ON admin_recovery_evm_submissions(
                            case_id, state, submitted_at
                        );

                    PRAGMA user_version = 9;
                    COMMIT;
                    """
                )
                version = 9
            if version < 10:
                approval_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(launch_action_approvals)"
                    ).fetchall()
                }
                if "expires_at" not in approval_columns:
                    connection.execute(
                        "ALTER TABLE launch_action_approvals "
                        "ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0"
                    )
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE INDEX IF NOT EXISTS launch_action_approvals_expiry_idx
                        ON launch_action_approvals(
                            ceremony_id, action_id, expires_at
                        );
                    CREATE TABLE IF NOT EXISTS genesis_finalization_reservation (
                        singleton_slot INTEGER PRIMARY KEY,
                        ceremony_id TEXT NOT NULL UNIQUE,
                        reserved_at INTEGER NOT NULL,
                        FOREIGN KEY (ceremony_id) REFERENCES ceremonies(ceremony_id),
                        CHECK (singleton_slot = 1)
                    );
                    INSERT OR IGNORE INTO genesis_finalization_reservation(
                        singleton_slot, ceremony_id, reserved_at
                    )
                    SELECT 1, ceremony_id, updated_at
                    FROM ceremonies
                    WHERE state='locked'
                    ORDER BY updated_at
                    LIMIT 1;

                    PRAGMA user_version = 10;
                    COMMIT;
                    """
                )
                version = 10
            if version < 11:
                rows = connection.execute(
                    "SELECT ceremony_id,state,broadcast_json FROM ceremonies "
                    "WHERE broadcast_json IS NOT NULL AND state!='locked'"
                ).fetchall()
                incompatible: list[str] = []
                for row in rows:
                    try:
                        self._decode_broadcast_reservation(row["broadcast_json"])
                    except GenesisConflict:
                        incompatible.append(str(row["ceremony_id"]))
                if incompatible:
                    raise RuntimeError(
                        "Genesis schema 11 cannot migrate unreconciled legacy "
                        "broadcast evidence for ceremony IDs: "
                        + ", ".join(incompatible)
                    )
                connection.execute("PRAGMA user_version = 11")
                version = 11
            if version < 12:
                reservation_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(genesis_finalization_reservation)"
                    ).fetchall()
                }
                if "publication_json" not in reservation_columns:
                    connection.execute(
                        "ALTER TABLE genesis_finalization_reservation "
                        "ADD COLUMN publication_json TEXT"
                    )
                connection.execute("PRAGMA user_version = 12")
            if version < 13:
                columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(launch_gates)")}
                if "approval_snapshot_json" not in columns:
                    connection.execute("ALTER TABLE launch_gates ADD COLUMN approval_snapshot_json TEXT")
                connection.execute("PRAGMA user_version = 13")

    def _event(
        self,
        connection: sqlite3.Connection,
        ceremony_id: str,
        event_type: str,
        payload: Any,
        now: int,
    ) -> None:
        connection.execute(
            "INSERT INTO audit_events(ceremony_id,event_type,event_json,created_at) "
            "VALUES(?,?,?,?)",
            (ceremony_id, event_type, canonical_json(payload), now),
        )

    @staticmethod
    def _require_ceremony(
        connection: sqlite3.Connection, ceremony_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM ceremonies WHERE ceremony_id = ?", (ceremony_id,)
        ).fetchone()
        if row is None:
            raise GenesisNotFound("ceremony not found")
        return row

    @staticmethod
    def _require_state(row: sqlite3.Row, *states: str) -> None:
        if row["state"] not in states:
            raise GenesisConflict(
                f"ceremony is {row['state']}; expected " + " or ".join(states)
            )

    def create_draft(
        self,
        ceremony_id: str,
        draft: dict[str, Any],
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        encoded = canonical_json(draft)
        with self._transaction() as connection:
            try:
                connection.execute(
                    "INSERT INTO ceremonies(ceremony_id,network,state,draft_json,created_at,updated_at) "
                    "VALUES(?, 'testnet11', 'draft', ?, ?, ?)",
                    (ceremony_id, encoded, timestamp, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("ceremony id already exists") from exc
            self._event(connection, ceremony_id, "draft_created", draft, timestamp)
        return self.get(ceremony_id)

    def claim_or_create_draft(
        self,
        *,
        token_hash: str,
        ceremony_id: str,
        draft: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        """Atomically consume an owner link and select the one active ceremony."""
        timestamp = int(time.time()) if now is None else now
        encoded = canonical_json(draft)
        selected_id: str
        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM launch_claims WHERE token_hash=?", (token_hash,)
            ).fetchone():
                raise GenesisConflict("owner launch link was already consumed")
            active = connection.execute(
                "SELECT ceremony_id,draft_json FROM ceremonies "
                "WHERE state NOT IN ('locked', 'abandoned') ORDER BY created_at DESC"
            ).fetchall()
            if len(active) > 1:
                raise GenesisConflict(
                    "more than one active ceremony exists; archive the stale launch first"
                )
            if active:
                selected_id = str(active[0]["ceremony_id"])
                if str(active[0]["draft_json"]) != encoded:
                    raise GenesisConflict(
                        "active ceremony does not match the protected launch policy; "
                        "abandon the stale launch before claiming this release"
                    )
            else:
                selected_id = ceremony_id
                try:
                    connection.execute(
                        "INSERT INTO ceremonies("
                        "ceremony_id,network,state,draft_json,created_at,updated_at"
                        ") VALUES(?, 'testnet11', 'draft', ?, ?, ?)",
                        (selected_id, encoded, timestamp, timestamp),
                    )
                except sqlite3.IntegrityError as exc:
                    raise GenesisConflict("ceremony id already exists") from exc
                self._event(
                    connection, selected_id, "draft_created", draft, timestamp
                )
            connection.execute(
                "INSERT INTO launch_claims("
                "ceremony_id,token_hash,consumed_at,created_at"
                ") VALUES(?,?,?,?)",
                (selected_id, token_hash, timestamp, timestamp),
            )
            self._event(
                connection,
                selected_id,
                "owner_link_consumed",
                {"slot": OWNER_SLOT},
                timestamp,
            )
        return self.get(selected_id)

    def issue_invitation(
        self,
        ceremony_id: str,
        *,
        slot: int,
        token_hash: str,
        nonce: str,
        expires_at: int,
        replace_live: bool = False,
        now: int | None = None,
    ) -> dict[str, Any]:
        if slot not in ADMIN_SLOTS:
            raise ValueError("slot must be 1, 2, or 3")
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("invitation expiration must be in the future")
        with self._transaction() as connection:
            row = self._require_ceremony(connection, ceremony_id)
            self._require_state(row, "draft", "roster_open")
            existing = connection.execute(
                "SELECT consumed_at,expires_at FROM invitations "
                "WHERE ceremony_id = ? AND slot = ?",
                (ceremony_id, slot),
            ).fetchone()
            if existing and existing["consumed_at"] is not None:
                raise GenesisConflict("administrator slot is already enrolled")
            if existing and int(existing["expires_at"]) > timestamp and not replace_live:
                raise GenesisConflict("administrator slot already has a live invitation")
            connection.execute(
                "DELETE FROM invitations WHERE ceremony_id = ? AND slot = ?",
                (ceremony_id, slot),
            )
            try:
                connection.execute(
                    "INSERT INTO invitations(ceremony_id,slot,token_hash,nonce,expires_at,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (ceremony_id, slot, token_hash, nonce, expires_at, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("invitation token or nonce was already used") from exc
            connection.execute(
                "UPDATE ceremonies SET state='roster_open',updated_at=? WHERE ceremony_id=?",
                (timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "invitation_issued",
                {"slot": slot, "expiresAt": expires_at},
                timestamp,
            )
        return self.get_invitation(ceremony_id, slot)

    def invitation_for_token(self, token_hash: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM invitations WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        if row is None:
            raise GenesisNotFound("invitation not found")
        return dict(row)

    def get_invitation(self, ceremony_id: str, slot: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM invitations WHERE ceremony_id = ? AND slot = ?",
                (ceremony_id, slot),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("invitation not found")
        return dict(row)

    def consume_invitation(
        self,
        *,
        token_hash: str,
        wallet_address: str,
        compressed_pubkey: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            invitation = connection.execute(
                "SELECT * FROM invitations WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if invitation is None:
                raise GenesisNotFound("invitation not found")
            ceremony_id = str(invitation["ceremony_id"])
            if invitation["consumed_at"] is not None:
                raise GenesisConflict("invitation was already consumed")
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "draft", "roster_open")
            if int(invitation["expires_at"]) < timestamp:
                raise GenesisExpired("invitation expired")
            duplicate = connection.execute(
                "SELECT slot FROM invitations WHERE ceremony_id=? AND consumed_at IS NOT NULL "
                "AND (wallet_address=? OR compressed_pubkey=?)",
                (ceremony_id, wallet_address, compressed_pubkey),
            ).fetchone()
            if duplicate:
                raise GenesisConflict("administrator wallet or key is already enrolled")
            connection.execute(
                "UPDATE invitations SET consumed_at=?,wallet_address=?,compressed_pubkey=?,"
                "enrollment_signature=? WHERE token_hash=? AND consumed_at IS NULL",
                (timestamp, wallet_address, compressed_pubkey, signature, token_hash),
            )
            self._event(
                connection,
                ceremony_id,
                "administrator_enrolled",
                {"slot": int(invitation["slot"]), "wallet": wallet_address},
                timestamp,
            )
        return self.get(ceremony_id)

    def freeze_roster(
        self,
        ceremony_id: str,
        roster_hash: str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "roster_open")
            members = connection.execute(
                "SELECT slot,wallet_address,compressed_pubkey FROM invitations "
                "WHERE ceremony_id=? AND consumed_at IS NOT NULL ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
            if [int(member["slot"]) for member in members] != list(ADMIN_SLOTS):
                raise GenesisConflict("all three administrator slots must be enrolled")
            wallets = {str(member["wallet_address"]) for member in members}
            pubkeys = {str(member["compressed_pubkey"]) for member in members}
            if len(wallets) != 3 or len(pubkeys) != 3:
                raise GenesisConflict("administrator roster keys must be distinct")
            connection.execute(
                "UPDATE ceremonies SET state='roster_frozen',roster_hash=?,updated_at=? "
                "WHERE ceremony_id=?",
                (roster_hash, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "roster_frozen",
                {"rosterHash": roster_hash},
                timestamp,
            )
        return self.get(ceremony_id)

    def set_plan(
        self,
        ceremony_id: str,
        *,
        plan_input: dict[str, Any],
        plan: dict[str, Any],
        plan_hash: str,
        expires_at: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("plan must expire in the future")
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "roster_frozen")
            connection.execute(
                "UPDATE ceremonies SET state='planned',plan_input_json=?,plan_json=?,"
                "plan_hash=?,plan_expires_at=?,updated_at=? WHERE ceremony_id=?",
                (
                    canonical_json(plan_input),
                    canonical_json(plan),
                    plan_hash,
                    expires_at,
                    timestamp,
                    ceremony_id,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "plan_created",
                {"planHash": plan_hash, "expiresAt": expires_at},
                timestamp,
            )
        return self.get(ceremony_id)

    def renew_expired_plan(
        self,
        ceremony_id: str,
        *,
        expected_plan_hash: str,
        plan: dict[str, Any],
        plan_hash: str,
        expires_at: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Atomically renew an expired plan without changing its signed bindings."""

        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("renewed plan must expire in the future")
        if str(plan.get("planHash") or "") != plan_hash:
            raise GenesisConflict("renewed plan hash differs from its payload")
        if int(plan.get("expiresAt") or 0) != expires_at:
            raise GenesisConflict("renewed plan expiration differs from its payload")
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "planned", "plan_approved")
            previous_hash = str(ceremony["plan_hash"] or "")
            if previous_hash != expected_plan_hash:
                raise GenesisConflict("ceremony plan changed before renewal")
            previous_expiry = int(ceremony["plan_expires_at"] or 0)
            if previous_expiry > timestamp:
                raise GenesisConflict("ceremony plan has not expired")
            try:
                previous_plan = json.loads(str(ceremony["plan_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise GenesisConflict("existing ceremony plan is invalid") from exc
            previous_binding = {
                key: value
                for key, value in previous_plan.items()
                if key not in {"expiresAt", "planHash"}
            }
            renewed_binding = {
                key: value
                for key, value in plan.items()
                if key not in {"expiresAt", "planHash"}
            }
            if canonical_json(previous_binding) != canonical_json(renewed_binding):
                raise GenesisConflict(
                    "renewed plan changed immutable ceremony bindings"
                )
            connection.execute(
                "DELETE FROM plan_signatures WHERE ceremony_id=?",
                (ceremony_id,),
            )
            updated = connection.execute(
                "UPDATE ceremonies SET state='planned',plan_json=?,plan_hash=?,"
                "plan_expires_at=?,updated_at=? WHERE ceremony_id=? AND plan_hash=? "
                "AND state IN ('planned','plan_approved') AND plan_expires_at<=?",
                (
                    canonical_json(plan),
                    plan_hash,
                    expires_at,
                    timestamp,
                    ceremony_id,
                    expected_plan_hash,
                    timestamp,
                ),
            )
            if updated.rowcount != 1:
                raise GenesisConflict("ceremony plan changed before renewal")
            self._event(
                connection,
                ceremony_id,
                "plan_renewed",
                {
                    "previousPlanHash": previous_hash,
                    "previousExpiresAt": previous_expiry,
                    "planHash": plan_hash,
                    "expiresAt": expires_at,
                    "signaturesCleared": True,
                },
                timestamp,
            )
        return self.get(ceremony_id)

    def add_plan_signature(
        self,
        ceremony_id: str,
        *,
        slot: int,
        plan_hash: str,
        compressed_pubkey: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "planned", "plan_approved")
            if ceremony["plan_hash"] != plan_hash:
                raise GenesisConflict("signature does not match the current plan")
            if int(ceremony["plan_expires_at"] or 0) <= timestamp:
                raise GenesisExpired("ceremony plan expired")
            member = connection.execute(
                "SELECT compressed_pubkey FROM invitations WHERE ceremony_id=? AND slot=? "
                "AND consumed_at IS NOT NULL",
                (ceremony_id, slot),
            ).fetchone()
            if member is None or member["compressed_pubkey"] != compressed_pubkey:
                raise GenesisConflict("signature key does not match frozen roster slot")
            try:
                connection.execute(
                    "INSERT INTO plan_signatures(ceremony_id,slot,plan_hash,compressed_pubkey,"
                    "signature,submitted_at) VALUES(?,?,?,?,?,?)",
                    (ceremony_id, slot, plan_hash, compressed_pubkey, signature, timestamp),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("roster slot already signed this plan") from exc
            rows = connection.execute(
                "SELECT slot FROM plan_signatures WHERE ceremony_id=? AND plan_hash=?",
                (ceremony_id, plan_hash),
            ).fetchall()
            signed_slots = {int(row["slot"]) for row in rows}
            count = len(signed_slots)
            approved = owner_plus_one_approved(signed_slots)
            state = "plan_approved" if approved else "planned"
            connection.execute(
                "UPDATE ceremonies SET state=?,updated_at=? WHERE ceremony_id=?",
                (state, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "plan_signed",
                {
                    "slot": slot,
                    "planHash": plan_hash,
                    "signatureCount": count,
                    "ownerPlusOneApproved": approved,
                },
                timestamp,
            )
        return self.get(ceremony_id)

    @staticmethod
    def _decode_broadcast_reservation(raw: Any) -> dict[str, Any]:
        try:
            reservation = json.loads(str(raw))
        except (TypeError, json.JSONDecodeError) as exc:
            raise GenesisConflict("persisted broadcast reservation is invalid") from exc
        if not isinstance(reservation, dict):
            raise GenesisConflict("persisted broadcast reservation is invalid")
        if reservation.get("reservationSchemaVersion") != 1:
            raise GenesisConflict("persisted broadcast reservation is invalid")
        if reservation.get("reservationState") not in {"RESERVED", "FINALIZED"}:
            raise GenesisConflict("persisted broadcast reservation is invalid")
        for key in ("planHash", "spendBundleId", "feeCoinId", "feeMojos"):
            if not isinstance(reservation.get(key), str) or not reservation[key]:
                raise GenesisConflict("persisted broadcast reservation is invalid")
        if not isinstance(reservation.get("spendBundle"), dict):
            raise GenesisConflict("persisted broadcast reservation is invalid")
        if type(reservation.get("reservedAt")) is not int:
            raise GenesisConflict("persisted broadcast reservation is invalid")
        evidence = reservation.get("ceremonyEvidence")
        if not isinstance(evidence, dict):
            raise GenesisConflict("persisted broadcast reservation is invalid")
        if not isinstance(evidence.get("auditApproval"), dict):
            raise GenesisConflict("persisted broadcast reservation is invalid")
        if not isinstance(evidence.get("authorityV3ReviewBase64"), str):
            raise GenesisConflict("persisted broadcast reservation is invalid")
        if not isinstance(evidence.get("validatorHealth"), dict):
            raise GenesisConflict("persisted broadcast reservation is invalid")
        return reservation

    def reserve_broadcast(
        self,
        ceremony_id: str,
        *,
        expected_plan_hash: str,
        spend_bundle_id: str,
        spend_bundle: dict[str, Any],
        fee_coin_id: str,
        fee_mojos: int,
        ceremony_evidence: dict[str, Any],
        gate_authorization: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Seal the exact funded bundle before any external submission begins."""

        if not expected_plan_hash:
            raise ValueError("expected plan hash is required")
        if not spend_bundle_id:
            raise ValueError("spend bundle id is required")
        if not isinstance(spend_bundle, dict):
            raise ValueError("spend bundle must be an object")
        if not fee_coin_id:
            raise ValueError("fee coin id is required")
        if type(fee_mojos) is not int or fee_mojos < 0:
            raise ValueError("fee mojos must be a nonnegative integer")
        if not isinstance(ceremony_evidence, dict):
            raise ValueError("ceremony evidence must be an object")
        if not isinstance(ceremony_evidence.get("auditApproval"), dict):
            raise ValueError("ceremony audit approval is required")
        if not isinstance(ceremony_evidence.get("authorityV3ReviewBase64"), str):
            raise ValueError("ceremony Authority V3 review is required")
        if not isinstance(ceremony_evidence.get("validatorHealth"), dict):
            raise ValueError("ceremony validator health is required")
        timestamp = int(time.time()) if now is None else now
        reservation: dict[str, Any] = {
            "reservationSchemaVersion": 1,
            "reservationState": "RESERVED",
            "planHash": expected_plan_hash,
            "spendBundleId": spend_bundle_id,
            "spendBundle": spend_bundle,
            "feeCoinId": fee_coin_id,
            "feeMojos": str(fee_mojos),
            "reservedAt": timestamp,
            "ceremonyEvidence": ceremony_evidence,
        }
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "plan_approved")
            if str(ceremony["plan_hash"] or "") != expected_plan_hash:
                raise GenesisConflict("ceremony plan changed before broadcast reservation")
            if int(ceremony["plan_expires_at"] or 0) <= timestamp:
                raise GenesisExpired("ceremony plan expired before broadcast reservation")

            global_reservation = connection.execute(
                "SELECT ceremony_id FROM genesis_finalization_reservation "
                "WHERE singleton_slot=1"
            ).fetchone()
            if global_reservation is None:
                connection.execute(
                    "INSERT INTO genesis_finalization_reservation("
                    "singleton_slot,ceremony_id,reserved_at) VALUES(1,?,?)",
                    (ceremony_id, timestamp),
                )
            elif str(global_reservation["ceremony_id"]) != ceremony_id:
                raise GenesisConflict(
                    "a different genesis ceremony owns the one-shot broadcast slot"
                )

            if gate_authorization is not None:
                if not isinstance(gate_authorization, dict):
                    raise GenesisConflict("broadcast gate authorization is invalid")
                gate = connection.execute(
                    "SELECT * FROM launch_gates WHERE ceremony_id=? AND gate_name=?",
                    (ceremony_id, "ceremonyBroadcast"),
                ).fetchone()
                if gate is None:
                    raise GenesisConflict("ceremony broadcast gate is unavailable")
                opens_at = int(gate["opens_at"])
                closes_at = int(gate["closes_at"])
                if str(gate["state"]) != "open":
                    raise GenesisConflict("ceremony broadcast gate is not approved")
                if not opens_at <= timestamp < closes_at:
                    raise GenesisConflict("ceremony broadcast gate is closed")
                if (
                    gate_authorization.get("gate") != "ceremonyBroadcast"
                    or gate_authorization.get("payloadHash")
                    != str(gate["payload_hash"])
                    or type(gate_authorization.get("opensAt")) is not int
                    or gate_authorization["opensAt"] != opens_at
                    or type(gate_authorization.get("closesAt")) is not int
                    or gate_authorization["closesAt"] != closes_at
                    or gate_authorization.get("configuredState") != "open"
                    or gate_authorization.get("state") != "open"
                    or gate_authorization.get("approved") is not True
                ):
                    raise GenesisConflict("broadcast gate authorization changed")
                reservation["gateAuthorization"] = gate_authorization

            try:
                updated = connection.execute(
                    "UPDATE ceremonies SET state='broadcast',spend_bundle_id=?,"
                    "broadcast_json=?,updated_at=? WHERE ceremony_id=? "
                    "AND state='plan_approved' AND plan_hash=? "
                    "AND plan_expires_at>?",
                    (
                        spend_bundle_id,
                        canonical_json(reservation),
                        timestamp,
                        ceremony_id,
                        expected_plan_hash,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("spend bundle is already reserved") from exc
            if updated.rowcount != 1:
                raise GenesisConflict("ceremony changed before broadcast reservation")
            self._event(
                connection,
                ceremony_id,
                "bundle_broadcast_reserved",
                {
                    "planHash": expected_plan_hash,
                    "spendBundleId": spend_bundle_id,
                    "feeCoinId": fee_coin_id,
                    "feeMojos": str(fee_mojos),
                    "gateAuthorization": gate_authorization,
                },
                timestamp,
            )
        return self.get(ceremony_id)

    def mark_broadcast(
        self,
        ceremony_id: str,
        *,
        spend_bundle_id: str,
        response: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "broadcast")
            reservation = self._decode_broadcast_reservation(
                ceremony["broadcast_json"]
            )
            stored_bundle_id = str(ceremony["spend_bundle_id"] or "")
            if (
                not stored_bundle_id
                or reservation["spendBundleId"] != stored_bundle_id
                or spend_bundle_id != stored_bundle_id
            ):
                raise GenesisConflict("broadcast response changed the reserved bundle id")
            if not isinstance(response, dict):
                raise GenesisConflict("broadcast response is invalid")
            if response.get("spendBundleId") != stored_bundle_id:
                raise GenesisConflict("broadcast response changed the reserved bundle id")
            if response.get("feeCoinId") != reservation["feeCoinId"]:
                raise GenesisConflict("broadcast response changed the reserved fee coin")
            if str(response.get("feeMojos") or "") != reservation["feeMojos"]:
                raise GenesisConflict("broadcast response changed the reserved fee")
            try:
                bundle_matches = canonical_json(response.get("spendBundle")) == canonical_json(
                    reservation["spendBundle"]
                )
            except (TypeError, ValueError) as exc:
                raise GenesisConflict("broadcast response spend bundle is invalid") from exc
            if not bundle_matches:
                raise GenesisConflict("broadcast response changed the reserved spend bundle")

            if reservation["reservationState"] == "FINALIZED":
                metadata_keys = {
                    "reservationSchemaVersion",
                    "reservationState",
                    "planHash",
                    "reservedAt",
                    "finalizedAt",
                    "gateAuthorization",
                    "ceremonyEvidence",
                    "chainConfirmation",
                }
                finalized_response = {
                    key: value
                    for key, value in reservation.items()
                    if key not in metadata_keys
                }
                if canonical_json(finalized_response) != canonical_json(response):
                    raise GenesisConflict("broadcast response was already finalized")
            else:
                finalized = dict(response)
                finalized.update(
                    {
                        "reservationSchemaVersion": 1,
                        "reservationState": "FINALIZED",
                        "planHash": reservation["planHash"],
                        "spendBundleId": stored_bundle_id,
                        "spendBundle": reservation["spendBundle"],
                        "feeCoinId": reservation["feeCoinId"],
                        "feeMojos": reservation["feeMojos"],
                        "reservedAt": reservation["reservedAt"],
                        "finalizedAt": timestamp,
                        "ceremonyEvidence": reservation["ceremonyEvidence"],
                    }
                )
                if "gateAuthorization" in reservation:
                    finalized["gateAuthorization"] = reservation[
                        "gateAuthorization"
                    ]
                updated = connection.execute(
                    "UPDATE ceremonies SET broadcast_json=?,updated_at=? "
                    "WHERE ceremony_id=? AND state='broadcast' AND spend_bundle_id=? "
                    "AND broadcast_json=?",
                    (
                        canonical_json(finalized),
                        timestamp,
                        ceremony_id,
                        stored_bundle_id,
                        ceremony["broadcast_json"],
                    ),
                )
                if updated.rowcount != 1:
                    raise GenesisConflict(
                        "broadcast reservation changed before finalization"
                    )
                self._event(
                    connection,
                    ceremony_id,
                    "bundle_broadcast",
                    {"spendBundleId": spend_bundle_id, "response": response},
                    timestamp,
                )
        return self.get(ceremony_id)

    def authorize_broadcast_reconciliation(
        self,
        ceremony_id: str,
        *,
        gate_authorization: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        """Bind an exact replay attempt to a fresh owner-approved gate window."""

        if not isinstance(gate_authorization, dict):
            raise GenesisConflict(
                "broadcast reconciliation authorization is invalid"
            )
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "broadcast")
            reservation = self._decode_broadcast_reservation(
                ceremony["broadcast_json"]
            )
            if reservation["reservationState"] != "RESERVED":
                raise GenesisConflict(
                    "broadcast reservation is already reconciled"
                )
            gate = connection.execute(
                "SELECT * FROM launch_gates WHERE ceremony_id=? AND gate_name=?",
                (ceremony_id, "ceremonyBroadcast"),
            ).fetchone()
            if gate is None or str(gate["state"]) != "open":
                raise GenesisConflict("ceremony broadcast gate is not approved")
            opens_at = int(gate["opens_at"])
            closes_at = int(gate["closes_at"])
            if not opens_at <= timestamp < closes_at:
                raise GenesisConflict("ceremony broadcast gate is closed")
            if (
                gate_authorization.get("gate") != "ceremonyBroadcast"
                or gate_authorization.get("payloadHash")
                != str(gate["payload_hash"])
                or gate_authorization.get("opensAt") != opens_at
                or gate_authorization.get("closesAt") != closes_at
                or gate_authorization.get("configuredState") != "open"
                or gate_authorization.get("state") != "open"
                or gate_authorization.get("approved") is not True
            ):
                raise GenesisConflict(
                    "broadcast reconciliation authorization changed"
                )
            self._event(
                connection,
                ceremony_id,
                "bundle_reconciliation_authorized",
                {
                    "spendBundleId": reservation["spendBundleId"],
                    "gateAuthorization": gate_authorization,
                },
                timestamp,
            )
        return self.get(ceremony_id)

    def mark_chain_reconciled_confirmed(
        self,
        ceremony_id: str,
        *,
        spend_bundle_id: str,
        response: dict[str, Any],
        confirmed_block_index: int,
        confirmation_evidence: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        """Atomically finalize a reserved bundle already proven on chain."""

        if confirmed_block_index <= 0:
            raise ValueError("confirmed block index must be positive")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "broadcast")
            reservation = self._decode_broadcast_reservation(
                ceremony["broadcast_json"]
            )
            if reservation["reservationState"] != "RESERVED":
                raise GenesisConflict(
                    "broadcast reservation is already reconciled"
                )
            stored_bundle_id = str(ceremony["spend_bundle_id"] or "")
            if (
                not stored_bundle_id
                or reservation["spendBundleId"] != stored_bundle_id
                or spend_bundle_id != stored_bundle_id
            ):
                raise GenesisConflict(
                    "chain reconciliation changed the reserved bundle id"
                )
            if not isinstance(response, dict):
                raise GenesisConflict("chain reconciliation response is invalid")
            if response.get("spendBundleId") != stored_bundle_id:
                raise GenesisConflict(
                    "chain reconciliation changed the reserved bundle id"
                )
            if response.get("feeCoinId") != reservation["feeCoinId"]:
                raise GenesisConflict(
                    "chain reconciliation changed the reserved fee coin"
                )
            if str(response.get("feeMojos") or "") != reservation["feeMojos"]:
                raise GenesisConflict(
                    "chain reconciliation changed the reserved fee"
                )
            try:
                bundle_matches = canonical_json(
                    response.get("spendBundle")
                ) == canonical_json(reservation["spendBundle"])
            except (TypeError, ValueError) as exc:
                raise GenesisConflict(
                    "chain reconciliation spend bundle is invalid"
                ) from exc
            if not bundle_matches:
                raise GenesisConflict(
                    "chain reconciliation changed the reserved spend bundle"
                )
            if not isinstance(confirmation_evidence, dict):
                raise GenesisConflict(
                    "exact broadcast confirmation evidence is invalid"
                )
            input_coin_ids = confirmation_evidence.get("inputCoinIds")
            if (
                confirmation_evidence.get("schemaVersion") != 1
                or confirmation_evidence.get("exactReservedCoinSpends") is not True
                or confirmation_evidence.get("spendBundleId") != stored_bundle_id
                or confirmation_evidence.get("confirmedBlockIndex")
                != confirmed_block_index
                or not isinstance(input_coin_ids, list)
                or not input_coin_ids
                or any(
                    not isinstance(value, str) or not value
                    for value in input_coin_ids
                )
            ):
                raise GenesisConflict(
                    "exact broadcast confirmation evidence is invalid"
                )

            finalized = dict(response)
            finalized.update(
                {
                    "reservationSchemaVersion": 1,
                    "reservationState": "FINALIZED",
                    "planHash": reservation["planHash"],
                    "spendBundleId": stored_bundle_id,
                    "spendBundle": reservation["spendBundle"],
                    "feeCoinId": reservation["feeCoinId"],
                    "feeMojos": reservation["feeMojos"],
                    "reservedAt": reservation["reservedAt"],
                    "finalizedAt": timestamp,
                    "ceremonyEvidence": reservation["ceremonyEvidence"],
                    "chainConfirmation": confirmation_evidence,
                }
            )
            if "gateAuthorization" in reservation:
                finalized["gateAuthorization"] = reservation[
                    "gateAuthorization"
                ]
            updated = connection.execute(
                "UPDATE ceremonies SET state='confirmed',"
                "confirmed_block_index=?,broadcast_json=?,updated_at=? "
                "WHERE ceremony_id=? AND state='broadcast' "
                "AND spend_bundle_id=? AND broadcast_json=?",
                (
                    confirmed_block_index,
                    canonical_json(finalized),
                    timestamp,
                    ceremony_id,
                    stored_bundle_id,
                    ceremony["broadcast_json"],
                ),
            )
            if updated.rowcount != 1:
                raise GenesisConflict(
                    "broadcast reservation changed before chain reconciliation"
                )
            self._event(
                connection,
                ceremony_id,
                "bundle_chain_reconciled",
                {"spendBundleId": spend_bundle_id, "response": response},
                timestamp,
            )
            self._event(
                connection,
                ceremony_id,
                "bundle_confirmed",
                confirmation_evidence,
                timestamp,
            )
        return self.get(ceremony_id)

    def pending_exact_fee_coin_ids(self) -> set[str]:
        """Return fee coins held by broadcast reservations until confirmation."""

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT spend_bundle_id,broadcast_json FROM ceremonies "
                "WHERE state IN ('broadcast','abandoned') "
                "AND broadcast_json IS NOT NULL"
            ).fetchall()
        reserved: set[str] = set()
        for row in rows:
            reservation = self._decode_broadcast_reservation(row["broadcast_json"])
            if reservation["spendBundleId"] != str(row["spend_bundle_id"] or ""):
                raise GenesisConflict("persisted broadcast reservation is invalid")
            reserved.add(str(reservation["feeCoinId"]))
        return reserved

    def validate_pending_broadcast_reservations(self) -> None:
        """Fail startup if any non-final legacy broadcast lacks exact evidence.

        Locked ceremonies are immutable historical evidence. Schema 11 does
        not reinterpret or rewrite those completed records; every other state
        with broadcast data must use the exact durable reservation format.
        """

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT ceremony_id,spend_bundle_id,broadcast_json FROM ceremonies "
                "WHERE broadcast_json IS NOT NULL AND state!='locked'"
            ).fetchall()
        for row in rows:
            reservation = self._decode_broadcast_reservation(row["broadcast_json"])
            if reservation["spendBundleId"] != str(row["spend_bundle_id"] or ""):
                raise GenesisConflict(
                    "persisted broadcast reservation is invalid for ceremony "
                    + str(row["ceremony_id"])
                )

    def mark_confirmed(
        self,
        ceremony_id: str,
        *,
        confirmed_block_index: int,
        confirmation_evidence: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        if confirmed_block_index <= 0:
            raise ValueError("confirmed block index must be positive")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "broadcast")
            reservation = self._decode_broadcast_reservation(
                ceremony["broadcast_json"]
            )
            if reservation["reservationState"] != "FINALIZED":
                raise GenesisConflict(
                    "broadcast reservation must be reconciled before confirmation"
                )
            if not isinstance(confirmation_evidence, dict):
                raise GenesisConflict("exact broadcast confirmation evidence is invalid")
            input_coin_ids = confirmation_evidence.get("inputCoinIds")
            if (
                confirmation_evidence.get("schemaVersion") != 1
                or confirmation_evidence.get("exactReservedCoinSpends") is not True
                or confirmation_evidence.get("spendBundleId")
                != reservation["spendBundleId"]
                or confirmation_evidence.get("confirmedBlockIndex")
                != confirmed_block_index
                or not isinstance(input_coin_ids, list)
                or not input_coin_ids
                or any(not isinstance(value, str) or not value for value in input_coin_ids)
            ):
                raise GenesisConflict("exact broadcast confirmation evidence is invalid")
            finalized = dict(reservation)
            finalized["chainConfirmation"] = confirmation_evidence
            updated = connection.execute(
                "UPDATE ceremonies SET state='confirmed',confirmed_block_index=?,"
                "broadcast_json=?,updated_at=? WHERE ceremony_id=? AND state='broadcast' "
                "AND broadcast_json=?",
                (
                    confirmed_block_index,
                    canonical_json(finalized),
                    timestamp,
                    ceremony_id,
                    ceremony["broadcast_json"],
                ),
            )
            if updated.rowcount != 1:
                raise GenesisConflict("broadcast changed before confirmation")
            self._event(
                connection,
                ceremony_id,
                "bundle_confirmed",
                confirmation_evidence,
                timestamp,
            )
        return self.get(ceremony_id)

    def set_artifact(
        self,
        ceremony_id: str,
        *,
        artifact: dict[str, Any],
        artifact_hash: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "confirmed")
            connection.execute(
                "UPDATE ceremonies SET state='artifact_pending',artifact_json=?,artifact_hash=?,"
                "updated_at=? WHERE ceremony_id=?",
                (canonical_json(artifact), artifact_hash, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "artifact_created",
                {"artifactHash": artifact_hash},
                timestamp,
            )
        return self.get(ceremony_id)

    def add_artifact_signature(
        self,
        ceremony_id: str,
        *,
        slot: int,
        artifact_hash: str,
        compressed_pubkey: str,
        signature: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "artifact_pending", "artifact_signed")
            finalization = connection.execute(
                "SELECT publication_json FROM genesis_finalization_reservation "
                "WHERE singleton_slot=1 AND ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
            if (
                finalization is not None
                and finalization["publication_json"] is not None
            ):
                raise GenesisConflict(
                    "artifact signatures are frozen by finalization publication"
                )
            if ceremony["artifact_hash"] != artifact_hash:
                raise GenesisConflict("signature does not match the current artifact")
            member = connection.execute(
                "SELECT compressed_pubkey FROM invitations WHERE ceremony_id=? AND slot=? "
                "AND consumed_at IS NOT NULL",
                (ceremony_id, slot),
            ).fetchone()
            if member is None or member["compressed_pubkey"] != compressed_pubkey:
                raise GenesisConflict("signature key does not match frozen roster slot")
            try:
                connection.execute(
                    "INSERT INTO artifact_signatures(ceremony_id,slot,artifact_hash,"
                    "compressed_pubkey,signature,submitted_at) VALUES(?,?,?,?,?,?)",
                    (
                        ceremony_id,
                        slot,
                        artifact_hash,
                        compressed_pubkey,
                        signature,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict("roster slot already signed this artifact") from exc
            rows = connection.execute(
                "SELECT slot FROM artifact_signatures WHERE ceremony_id=? "
                "AND artifact_hash=?",
                (ceremony_id, artifact_hash),
            ).fetchall()
            signed_slots = {int(row["slot"]) for row in rows}
            count = len(signed_slots)
            approved = owner_plus_one_approved(signed_slots)
            state = "artifact_signed" if approved else "artifact_pending"
            connection.execute(
                "UPDATE ceremonies SET state=?,updated_at=? WHERE ceremony_id=?",
                (state, timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "artifact_signed",
                {
                    "slot": slot,
                    "artifactHash": artifact_hash,
                    "signatureCount": count,
                    "ownerPlusOneApproved": approved,
                },
                timestamp,
            )
        return self.get(ceremony_id)

    def mark_locked(
        self, ceremony_id: str, *, now: int | None = None
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "artifact_signed", "locked")
            reservation = connection.execute(
                "SELECT ceremony_id,publication_json "
                "FROM genesis_finalization_reservation "
                "WHERE singleton_slot=1"
            ).fetchone()
            if reservation is None:
                raise GenesisConflict(
                    "finalization publication is not reserved"
                )
            if str(reservation["ceremony_id"]) != ceremony_id:
                raise GenesisConflict(
                    "a different genesis ceremony owns finalization"
                )
            if reservation["publication_json"] is None:
                raise GenesisConflict(
                    "finalization publication is not bound"
                )
            existing = connection.execute(
                "SELECT ceremony_id FROM ceremonies "
                "WHERE state='locked' AND ceremony_id<>? LIMIT 1",
                (ceremony_id,),
            ).fetchone()
            if existing is not None:
                raise GenesisConflict("a different genesis ceremony is already locked")
            if ceremony["state"] == "locked":
                return self.get(ceremony_id)
            connection.execute(
                "UPDATE ceremonies SET state='locked',updated_at=? WHERE ceremony_id=?",
                (timestamp, ceremony_id),
            )
            self._event(connection, ceremony_id, "bootstrap_locked", {}, timestamp)
        return self.get(ceremony_id)

    def reserve_finalization(
        self,
        ceremony_id: str,
        *,
        publication: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any] | None:
        """Reserve and durably bind the exact final publication payload."""

        encoded_publication: str | None = None
        if publication is not None:
            if not isinstance(publication, dict):
                raise ValueError("finalization publication must be an object")
            encoded_publication = canonical_json(publication)
        timestamp = int(time.time()) if now is None else now
        selected_publication: str | None = None
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            self._require_state(ceremony, "artifact_signed", "locked")
            if publication is not None:
                publication_artifact = publication.get("artifact")
                if (
                    not isinstance(publication_artifact, dict)
                    or publication_artifact.get("artifactHash")
                    != ceremony["artifact_hash"]
                    or not isinstance(
                        publication_artifact.get("signatures"), list
                    )
                ):
                    raise GenesisConflict(
                        "finalization artifact signature set is invalid"
                    )
                signature_rows = connection.execute(
                    "SELECT slot,compressed_pubkey,signature "
                    "FROM artifact_signatures WHERE ceremony_id=? "
                    "AND artifact_hash=? ORDER BY slot",
                    (ceremony_id, ceremony["artifact_hash"]),
                ).fetchall()
                persisted_signatures = [
                    {
                        "adminIndex": int(row["slot"]) - 1,
                        "compressedPubkey": str(row["compressed_pubkey"]),
                        "signature": str(row["signature"]),
                    }
                    for row in signature_rows
                ]
                if canonical_json(
                    publication_artifact["signatures"]
                ) != canonical_json(persisted_signatures):
                    raise GenesisConflict(
                        "finalization artifact signature set changed"
                    )
            reservation = connection.execute(
                "SELECT ceremony_id,publication_json "
                "FROM genesis_finalization_reservation "
                "WHERE singleton_slot=1"
            ).fetchone()
            if reservation is not None:
                if str(reservation["ceremony_id"]) != ceremony_id:
                    raise GenesisConflict(
                        "a different genesis ceremony owns finalization"
                    )
                selected_publication = reservation["publication_json"]
                if encoded_publication is not None:
                    if selected_publication is None:
                        connection.execute(
                            "UPDATE genesis_finalization_reservation "
                            "SET publication_json=? WHERE singleton_slot=1 "
                            "AND ceremony_id=? AND publication_json IS NULL",
                            (encoded_publication, ceremony_id),
                        )
                        selected_publication = encoded_publication
                        self._event(
                            connection,
                            ceremony_id,
                            "finalization_publication_reserved",
                            publication,
                            timestamp,
                        )
                    elif selected_publication != encoded_publication:
                        raise GenesisConflict(
                            "finalization publication changed after reservation"
                        )
            else:
                connection.execute(
                    "INSERT INTO genesis_finalization_reservation("
                    "singleton_slot,ceremony_id,reserved_at,publication_json) "
                    "VALUES(1,?,?,?)",
                    (ceremony_id, timestamp, encoded_publication),
                )
                selected_publication = encoded_publication
                self._event(
                    connection,
                    ceremony_id,
                    "finalization_reserved",
                    {"publicationBound": publication is not None},
                    timestamp,
                )
        return (
            json.loads(selected_publication)
            if selected_publication is not None
            else None
        )

    def finalization_publication(
        self, ceremony_id: str
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            reservation = connection.execute(
                "SELECT ceremony_id,publication_json "
                "FROM genesis_finalization_reservation WHERE singleton_slot=1"
            ).fetchone()
        if reservation is None:
            return None
        if str(reservation["ceremony_id"]) != ceremony_id:
            raise GenesisConflict("a different genesis ceremony owns finalization")
        if reservation["publication_json"] is None:
            return None
        try:
            publication = json.loads(str(reservation["publication_json"]))
        except json.JSONDecodeError as exc:
            raise GenesisConflict("finalization publication is invalid") from exc
        if not isinstance(publication, dict):
            raise GenesisConflict("finalization publication is invalid")
        return publication

    def abandon(
        self, ceremony_id: str, reason: str, *, now: int | None = None
    ) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("abandon reason is required")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            if ceremony["state"] in TERMINAL_STATES:
                raise GenesisConflict("ceremony is already terminal")
            if ceremony["state"] not in ABANDONABLE_STATES:
                raise GenesisConflict(
                    "ceremony cannot be abandoned after broadcast reservation"
                )
            connection.execute(
                "UPDATE ceremonies SET state='abandoned',updated_at=? WHERE ceremony_id=?",
                (timestamp, ceremony_id),
            )
            self._event(
                connection,
                ceremony_id,
                "ceremony_abandoned",
                {"reason": reason},
                timestamp,
            )
        return self.get(ceremony_id)

    def list_ceremonies(self, *, limit: int = 50) -> list[dict[str, Any]]:
        if limit < 1 or limit > 200:
            raise ValueError("limit must be between 1 and 200")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT ceremony_id FROM ceremonies ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self.get(str(row["ceremony_id"])) for row in rows]

    def active(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT ceremony_id FROM ceremonies "
                "WHERE state NOT IN ('locked', 'abandoned') "
                "ORDER BY created_at DESC"
            ).fetchall()
        if len(rows) > 1:
            raise GenesisConflict(
                "more than one active ceremony exists; archive the stale launch first"
            )
        return self.get(str(rows[0]["ceremony_id"])) if rows else None

    def audit_events(
        self, ceremony_id: str, *, after_event_id: int = 0, limit: int = 250
    ) -> list[dict[str, Any]]:
        if after_event_id < 0 or limit < 1 or limit > 1000:
            raise ValueError("invalid audit event cursor")
        with self._connect() as connection:
            self._require_ceremony(connection, ceremony_id)
            rows = connection.execute(
                "SELECT event_id,event_type,event_json,created_at FROM audit_events "
                "WHERE ceremony_id=? AND event_id>? ORDER BY event_id LIMIT ?",
                (ceremony_id, after_event_id, limit),
            ).fetchall()
        return [
            {
                "eventId": int(row["event_id"]),
                "type": str(row["event_type"]),
                "details": json.loads(str(row["event_json"])),
                "createdAt": int(row["created_at"]),
            }
            for row in rows
        ]

    def consume_owner_claim(
        self,
        ceremony_id: str,
        *,
        token_hash: str,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT ceremony_id FROM launch_claims WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
            if existing:
                raise GenesisConflict("owner launch link was already consumed")
            connection.execute(
                "INSERT INTO launch_claims(ceremony_id,token_hash,consumed_at,created_at) "
                "VALUES(?,?,?,?)",
                (ceremony_id, token_hash, timestamp, timestamp),
            )
            self._event(
                connection,
                ceremony_id,
                "owner_link_consumed",
                {"slot": OWNER_SLOT},
                timestamp,
            )

    def owner_claim_used(self, token_hash: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM launch_claims WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
        return row is not None

    def set_profile(
        self,
        ceremony_id: str,
        *,
        slot: int,
        display_name: str,
        role_label: str,
        email: str | None,
        timezone: str,
        reminders_enabled: bool,
        now: int | None = None,
    ) -> dict[str, Any]:
        if slot not in ADMIN_SLOTS:
            raise ValueError("slot must be 1, 2, or 3")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            connection.execute(
                """
                INSERT INTO launch_profiles(
                    ceremony_id,slot,display_name,role_label,email,timezone,
                    reminders_enabled,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id,slot) DO UPDATE SET
                    display_name=excluded.display_name,
                    role_label=excluded.role_label,
                    email=excluded.email,
                    timezone=excluded.timezone,
                    reminders_enabled=excluded.reminders_enabled,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    slot,
                    display_name,
                    role_label,
                    email,
                    timezone,
                    int(reminders_enabled),
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "administrator_profile_updated",
                {"slot": slot, "role": role_label},
                timestamp,
            )
        return self.profiles(ceremony_id)[slot]

    def profiles(self, ceremony_id: str) -> dict[int, dict[str, Any]]:
        with self._connect() as connection:
            self._require_ceremony(connection, ceremony_id)
            rows = connection.execute(
                "SELECT * FROM launch_profiles WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
        return {
            int(row["slot"]): {
                "slot": int(row["slot"]),
                "displayName": str(row["display_name"]),
                "role": str(row["role_label"]),
                "email": row["email"],
                "timezone": str(row["timezone"]),
                "remindersEnabled": bool(row["reminders_enabled"]),
                "updatedAt": int(row["updated_at"]),
            }
            for row in rows
        }

    def _launch_authority(self, settings: Settings, ceremony_id: str):
        from .admin_roster import current_launch_authority
        try:
            return current_launch_authority(settings, self, ceremony_id)
        except ValueError as exc:
            raise GenesisConflict(str(exc)) from exc

    def create_auth_challenge(
        self,
        ceremony_id: str,
        *,
        settings: Settings,
        slot: int,
        wallet_address: str,
        nonce_hash: str,
        expires_at: int,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("authentication challenge must expire in the future")
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            authority = self._launch_authority(settings, ceremony_id)
            if authority.wallets.get(slot) != wallet_address.lower():
                raise GenesisConflict("wallet is not the current administrator for this launch slot")
            connection.execute(
                "DELETE FROM launch_auth_challenges WHERE expires_at<? OR consumed_at IS NOT NULL",
                (timestamp,),
            )
            connection.execute(
                "INSERT INTO launch_auth_challenges("
                "nonce_hash,ceremony_id,slot,wallet_address,expires_at,created_at"
                ") VALUES(?,?,?,?,?,?)",
                (
                    nonce_hash,
                    ceremony_id,
                    slot,
                    wallet_address.lower(),
                    expires_at,
                    timestamp,
                ),
            )

    def consume_auth_challenge(
        self,
        *,
        settings: Settings,
        nonce_hash: str,
        wallet_address: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM launch_auth_challenges WHERE nonce_hash=?",
                (nonce_hash,),
            ).fetchone()
            if row is None:
                raise GenesisNotFound("administrator challenge not found")
            if row["consumed_at"] is not None:
                raise GenesisConflict("administrator challenge was already used")
            if int(row["expires_at"]) < timestamp:
                raise GenesisExpired("administrator challenge expired")
            if str(row["wallet_address"]).lower() != wallet_address.lower():
                raise GenesisConflict("administrator challenge wallet changed")
            authority = self._launch_authority(settings, str(row["ceremony_id"]))
            if authority.wallets.get(int(row["slot"])) != wallet_address.lower():
                raise GenesisConflict("wallet is not the current administrator for this launch slot")
            connection.execute(
                "UPDATE launch_auth_challenges SET consumed_at=? WHERE nonce_hash=?",
                (timestamp, nonce_hash),
            )
            self._event(
                connection,
                str(row["ceremony_id"]),
                "administrator_session_started",
                {"slot": int(row["slot"]), "wallet": wallet_address.lower()},
                timestamp,
            )
        return dict(row)

    def auth_challenge(self, nonce_hash: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM launch_auth_challenges WHERE nonce_hash=?",
                (nonce_hash,),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("administrator challenge not found")
        return dict(row)

    def add_action_approval(
        self,
        ceremony_id: str,
        *,
        settings: Settings,
        action_id: str,
        action_type: str,
        payload_hash: str,
        slot: int,
        signer_address: str,
        signature: str,
        expires_at: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        if expires_at < timestamp:
            raise GenesisExpired("launch action signature expired")
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            authority = self._launch_authority(settings, ceremony_id)
            if authority.finalizing or authority.wallets.get(slot) != signer_address.lower():
                raise GenesisConflict("wallet is not the current administrator for this launch slot")
            existing = connection.execute(
                "SELECT * FROM launch_action_approvals "
                "WHERE ceremony_id=? AND action_id=? AND slot=?",
                (ceremony_id, action_id, slot),
            ).fetchone()
            if existing and (int(existing["expires_at"]) < timestamp
                             or str(existing["signer_address"]).lower() != authority.wallets.get(slot)):
                self._event(connection, ceremony_id, "launch_action_approval_superseded",
                            dict(existing), timestamp)
                connection.execute(
                    "DELETE FROM launch_action_approvals "
                    "WHERE ceremony_id=? AND action_id=? AND slot=?",
                    (ceremony_id, action_id, slot),
                )
                existing = None
            if existing:
                if (
                    str(existing["payload_hash"]).lower() == payload_hash.lower()
                    and str(existing["signature"]).lower() == signature.lower()
                    and int(existing["expires_at"]) == expires_at
                ):
                    return self.action_approvals(
                        ceremony_id, action_id, settings=settings, now=timestamp
                    )
                raise GenesisConflict("administrator slot already approved this action")
            connection.execute(
                "INSERT INTO launch_action_approvals("
                "ceremony_id,action_id,action_type,payload_hash,slot,signer_address,"
                "signature,submitted_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    ceremony_id,
                    action_id,
                    action_type,
                    payload_hash.lower(),
                    slot,
                    signer_address.lower(),
                    signature.lower(),
                    timestamp,
                    expires_at,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "launch_action_approved",
                {
                    "actionId": action_id,
                    "actionType": action_type,
                    "payloadHash": payload_hash.lower(),
                    "slot": slot,
                    "expiresAt": expires_at,
                },
                timestamp,
            )
        return self.action_approvals(ceremony_id, action_id, settings=settings, now=timestamp)

    def action_approvals(
        self, ceremony_id: str, action_id: str, *, settings: Settings, now: int | None = None
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM launch_action_approvals "
                "WHERE ceremony_id=? AND action_id=? ORDER BY slot",
                (ceremony_id, action_id),
            ).fetchall()
        authority = self._launch_authority(settings, ceremony_id)
        active_rows = [row for row in rows if not authority.finalizing and int(row["expires_at"]) >= timestamp
                       and authority.wallets.get(int(row["slot"])) == str(row["signer_address"]).lower()]
        slots = {int(row["slot"]) for row in active_rows}
        return {
            "actionId": action_id,
            "approved": owner_plus_one_approved(slots),
            "slots": sorted(slots),
            "approvals": [
                {
                    "slot": int(row["slot"]),
                    "signer": str(row["signer_address"]),
                    "submittedAt": int(row["submitted_at"]),
                    "expiresAt": int(row["expires_at"]),
                    "expired": int(row["expires_at"]) < timestamp,
                    "currentSigner": authority.wallets.get(int(row["slot"])) == str(row["signer_address"]).lower(),
                }
                for row in rows
            ],
        }

    def upsert_gate(
        self,
        ceremony_id: str,
        *,
        gate_name: str,
        opens_at: int,
        closes_at: int,
        payload_hash: str,
        state: str,
        now: int | None = None,
        settings: Settings | None = None,
    ) -> dict[str, Any]:
        if state not in {"pending", "open", "closed", "cancelled"}:
            raise ValueError("invalid launch gate state")
        if closes_at <= opens_at:
            raise ValueError("gate close must be after gate open")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            snapshot = None
            if state == "open" and settings is not None:
                proposal = connection.execute(
                    "SELECT * FROM launch_gates WHERE ceremony_id=? AND gate_name=?",
                    (ceremony_id, gate_name),
                ).fetchone()
                if (proposal is None or str(proposal["payload_hash"]) != payload_hash.lower()
                    or int(proposal["opens_at"]) != opens_at or int(proposal["closes_at"]) != closes_at
                    or proposal["state"] not in {"pending", "open"}):
                    raise GenesisConflict("gate proposal changed before activation")
                action_id = launch_gate_action_id(ceremony_id, gate_name, payload_hash)
                approval = self.action_approvals(ceremony_id, action_id, settings=settings, now=timestamp)
                if not approval["approved"]:
                    raise GenesisConflict("current owner-plus-one gate approval is required")
                rows = connection.execute(
                    "SELECT * FROM launch_action_approvals WHERE ceremony_id=? AND action_id=?",
                    (ceremony_id, action_id),
                ).fetchall()
                snapshot = canonical_json({
                    "schemaVersion": 1, "activatedAt": timestamp,
                    "actionId": action_id, "payloadHash": payload_hash.lower(),
                    "opensAt": opens_at, "closesAt": closes_at,
                    "approvals": [dict(row) for row in rows if int(row["slot"]) in approval["slots"]],
                })
            prior = connection.execute(
                "SELECT approval_snapshot_json FROM launch_gates WHERE ceremony_id=? AND gate_name=?",
                (ceremony_id, gate_name),
            ).fetchone()
            if prior and prior["approval_snapshot_json"] and prior["approval_snapshot_json"] != snapshot:
                self._event(connection, ceremony_id, "launch_gate_activation_superseded",
                            {"gate": gate_name, "approvalSnapshot": json.loads(prior["approval_snapshot_json"])}, timestamp)
            connection.execute(
                """
                INSERT INTO launch_gates(
                    ceremony_id,gate_name,network,opens_at,closes_at,
                    payload_hash,state,updated_at,approval_snapshot_json
                ) VALUES(?,?,'testnet11',?,?,?,?,?,?)
                ON CONFLICT(ceremony_id,gate_name) DO UPDATE SET
                    opens_at=excluded.opens_at,
                    closes_at=excluded.closes_at,
                    payload_hash=excluded.payload_hash,
                    state=excluded.state,
                    updated_at=excluded.updated_at,
                    approval_snapshot_json=excluded.approval_snapshot_json
                """,
                (
                    ceremony_id,
                    gate_name,
                    opens_at,
                    closes_at,
                    payload_hash.lower(),
                    state,
                    timestamp,
                    snapshot,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "launch_gate_updated",
                {
                    "gate": gate_name,
                    "opensAt": opens_at,
                    "closesAt": closes_at,
                    "state": state,
                },
                timestamp,
            )
        return self.gates(ceremony_id)[gate_name]

    def gates(
        self, ceremony_id: str, *, now: int | None = None
    ) -> dict[str, dict[str, Any]]:
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM launch_gates WHERE ceremony_id=? ORDER BY gate_name",
                (ceremony_id,),
            ).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            stored_state = str(row["state"])
            effective_state = stored_state
            if stored_state == "open":
                if timestamp < int(row["opens_at"]):
                    effective_state = "pending"
                elif timestamp >= int(row["closes_at"]):
                    effective_state = "closed"
            result[str(row["gate_name"])] = {
                "name": str(row["gate_name"]),
                "network": str(row["network"]),
                "opensAt": int(row["opens_at"]),
                "closesAt": int(row["closes_at"]),
                "state": effective_state,
                "configuredState": stored_state,
                "payloadHash": str(row["payload_hash"]),
                "updatedAt": int(row["updated_at"]),
            }
        return result

    def authorized_gate(
        self, settings: Settings, ceremony_id: str, gate_name: str, *, now: int | None = None,
    ) -> dict[str, Any]:
        """Revalidate activation-time approvals against today's exact slots.

        Signature expiry limits activation, not the separately approved gate
        duration. Old unsigned rows have no activation proof and fail closed.
        """
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            gate = self.gates(ceremony_id, now=timestamp).get(gate_name)
            if not gate or gate["state"] != "open":
                raise GenesisConflict(f"the signed {gate_name} window is closed")
            row = connection.execute(
                "SELECT approval_snapshot_json FROM launch_gates WHERE ceremony_id=? AND gate_name=?",
                (ceremony_id, gate_name),
            ).fetchone()
            try:
                snapshot = json.loads(row["approval_snapshot_json"] or "null")
                action_id = launch_gate_action_id(ceremony_id, gate_name, gate["payloadHash"])
                if (not isinstance(snapshot, dict) or snapshot.get("schemaVersion") != 1
                    or snapshot.get("actionId") != action_id
                    or snapshot.get("payloadHash") != gate["payloadHash"]
                    or snapshot.get("opensAt") != gate["opensAt"]
                    or snapshot.get("closesAt") != gate["closesAt"]
                    or snapshot.get("activatedAt") != gate["updatedAt"]):
                    raise ValueError("gate activation proof is missing or changed")
                authority = self._launch_authority(settings, ceremony_id)
                if authority.finalizing:
                    raise GenesisConflict("reserved genesis publication must finish before gate use")
                activated = snapshot["activatedAt"]
                slots = set()
                for approval in snapshot["approvals"]:
                    slot = int(approval["slot"])
                    if (approval["ceremony_id"] == ceremony_id
                        and approval["action_id"] == action_id
                        and approval["action_type"] == f"gate:{gate_name}"
                        and approval["payload_hash"] == gate["payloadHash"]
                        and approval["submitted_at"] <= activated <= approval["expires_at"]
                        and authority.wallets.get(slot) == approval["signer_address"].lower()):
                        slots.add(slot)
                if not owner_plus_one_approved(slots):
                    raise ValueError("current owner-plus-one gate approval is required")
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise GenesisConflict(str(exc)) from exc
        return gate

    def set_funding_receipt(
        self,
        ceremony_id: str,
        *,
        plan: dict[str, Any],
        plan_hash: str,
        state: str = "prepared",
        spend_bundle_id: str | None = None,
        response: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        if state not in {"prepared", "approved", "broadcast", "confirmed", "ambiguous"}:
            raise ValueError("invalid funding receipt state")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT plan_hash FROM genesis_funding_receipts WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
            if existing and str(existing["plan_hash"]).lower() != plan_hash.lower():
                raise GenesisConflict("ceremony funding plan is already sealed")
            connection.execute(
                """
                INSERT INTO genesis_funding_receipts(
                    ceremony_id,plan_json,plan_hash,spend_bundle_id,response_json,
                    state,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id) DO UPDATE SET
                    spend_bundle_id=COALESCE(excluded.spend_bundle_id,spend_bundle_id),
                    response_json=COALESCE(excluded.response_json,response_json),
                    state=excluded.state,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    canonical_json(plan),
                    plan_hash.lower(),
                    spend_bundle_id,
                    canonical_json(response) if response is not None else None,
                    state,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "genesis_funding_updated",
                {
                    "planHash": plan_hash.lower(),
                    "state": state,
                    "spendBundleId": spend_bundle_id,
                },
                timestamp,
            )
        receipt = self.funding_receipt(ceremony_id)
        assert receipt is not None
        return receipt

    def funding_receipt(self, ceremony_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM genesis_funding_receipts WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "plan": json.loads(str(row["plan_json"])),
            "planHash": str(row["plan_hash"]),
            "spendBundleId": row["spend_bundle_id"],
            "response": (
                json.loads(str(row["response_json"])) if row["response_json"] else None
            ),
            "state": str(row["state"]),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def set_action_intent(
        self,
        ceremony_id: str,
        *,
        action_id: str,
        action_type: str,
        payload_hash: str,
        payload: dict[str, Any],
        state: str = "prepared",
        now: int | None = None,
    ) -> dict[str, Any]:
        if state not in {"prepared", "executed", "cancelled"}:
            raise ValueError("invalid launch action intent state")
        timestamp = int(time.time()) if now is None else now
        encoded = canonical_json(payload)
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT action_type,payload_hash,payload_json FROM launch_action_intents "
                "WHERE ceremony_id=? AND action_id=?",
                (ceremony_id, action_id),
            ).fetchone()
            if existing and (
                str(existing["action_type"]) != action_type
                or str(existing["payload_hash"]).lower() != payload_hash.lower()
                or str(existing["payload_json"]) != encoded
            ):
                raise GenesisConflict("launch action intent changed after preparation")
            connection.execute(
                """
                INSERT INTO launch_action_intents(
                    ceremony_id,action_id,action_type,payload_hash,payload_json,
                    state,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id,action_id) DO UPDATE SET
                    state=excluded.state,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    action_id,
                    action_type,
                    payload_hash.lower(),
                    encoded,
                    state,
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "launch_action_intent_updated",
                {
                    "actionId": action_id,
                    "actionType": action_type,
                    "payloadHash": payload_hash.lower(),
                    "state": state,
                },
                timestamp,
            )
        intent = self.action_intent(ceremony_id, action_id)
        assert intent is not None
        return intent

    def action_intent(
        self, ceremony_id: str, action_id: str
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM launch_action_intents WHERE ceremony_id=? AND action_id=?",
                (ceremony_id, action_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "actionId": str(row["action_id"]),
            "actionType": str(row["action_type"]),
            "payloadHash": str(row["payload_hash"]),
            "payload": json.loads(str(row["payload_json"])),
            "state": str(row["state"]),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def latest_action_intent(
        self, ceremony_id: str, action_type: str
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT action_id FROM launch_action_intents "
                "WHERE ceremony_id=? AND action_type=? ORDER BY created_at DESC LIMIT 1",
                (ceremony_id, action_type),
            ).fetchone()
        return (
            self.action_intent(ceremony_id, str(row["action_id"]))
            if row is not None
            else None
        )

    def set_settlement_rehearsal(
        self,
        ceremony_id: str,
        *,
        job_id: str,
        config_hash: str,
        state: str,
        payload: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "PREPARED",
            "AWAITING_WALLET",
            "PAYMENT_SUBMITTED",
            "VALIDATING",
            "SUCCEEDED",
            "FAILED",
        }
        state_order = {
            "PREPARED": 0,
            "AWAITING_WALLET": 1,
            "PAYMENT_SUBMITTED": 2,
            "VALIDATING": 3,
            "SUCCEEDED": 4,
        }
        if state not in allowed:
            raise ValueError("invalid settlement rehearsal state")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            existing = connection.execute(
                "SELECT job_id,config_hash,state FROM launch_settlement_rehearsals "
                "WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
            if existing and (
                str(existing["job_id"]) != job_id
                or str(existing["config_hash"]).lower() != config_hash.lower()
            ):
                if str(existing["state"]) != "FAILED" or state != "PREPARED":
                    raise GenesisConflict("settlement rehearsal job is already sealed")
                connection.execute(
                    "DELETE FROM launch_settlement_rehearsals WHERE ceremony_id=?",
                    (ceremony_id,),
                )
                existing = None
            if existing:
                existing_state = str(existing["state"])
                if existing_state in {"SUCCEEDED", "FAILED"} and state != existing_state:
                    raise GenesisConflict("completed settlement rehearsal cannot be replaced")
                if (
                    existing_state in state_order
                    and state in state_order
                    and state_order[state] < state_order[existing_state]
                ):
                    raise GenesisConflict("settlement rehearsal cannot move backwards")
            connection.execute(
                """
                INSERT INTO launch_settlement_rehearsals(
                    ceremony_id,job_id,config_hash,state,payload_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(ceremony_id) DO UPDATE SET
                    state=excluded.state,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    ceremony_id,
                    job_id,
                    config_hash.lower(),
                    state,
                    canonical_json(payload),
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                ceremony_id,
                "settlement_rehearsal_updated",
                {"jobId": job_id, "state": state, "configHash": config_hash.lower()},
                timestamp,
            )
        result = self.settlement_rehearsal(ceremony_id)
        assert result is not None
        return result

    def settlement_rehearsal(self, ceremony_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM launch_settlement_rehearsals WHERE ceremony_id=?",
                (ceremony_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "jobId": str(row["job_id"]),
            "configHash": str(row["config_hash"]),
            "state": str(row["state"]),
            "payload": json.loads(str(row["payload_json"])),
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def create_recovery_drill(
        self,
        ceremony_id: str,
        *,
        challenge_id: str,
        slot: int,
        challenge_hash: str,
        public_payload: dict[str, Any],
        expires_at: int,
        now: int | None = None,
    ) -> dict[str, Any]:
        if slot not in ADMIN_SLOTS:
            raise ValueError("slot must be 1, 2, or 3")
        timestamp = int(time.time()) if now is None else now
        if expires_at <= timestamp:
            raise GenesisExpired("recovery drill challenge must expire in the future")
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            # Completed drills are recovery evidence, including initial kits
            # that retain only the challenge hash. Candidates also retain a
            # foreign key to their drill in every lifecycle state.
            connection.execute(
                "DELETE FROM admin_recovery_drills "
                "WHERE expires_at < ? AND consumed_at IS NULL "
                "AND NOT EXISTS ("
                "SELECT 1 FROM admin_recovery_kit_candidates AS candidate "
                "WHERE candidate.challenge_id = admin_recovery_drills.challenge_id"
                ")",
                (timestamp,),
            )
            try:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_drills(
                        challenge_id,ceremony_id,slot,challenge_hash,public_json,
                        expires_at,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        challenge_id,
                        ceremony_id,
                        slot,
                        challenge_hash.lower(),
                        canonical_json(public_payload),
                        expires_at,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict(
                    "recovery drill challenge was already issued"
                ) from exc
            self._event(
                connection,
                ceremony_id,
                "admin_recovery_drill_prepared",
                {
                    "slot": slot - 1,
                    "challengeId": challenge_id,
                    "expiresAt": expires_at,
                },
                timestamp,
            )
        return self.recovery_drill(challenge_id)

    def recovery_drill(self, challenge_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_recovery_drills WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("recovery drill challenge not found")
        return {
            "challengeId": str(row["challenge_id"]),
            "ceremonyId": str(row["ceremony_id"]),
            "slot": int(row["slot"]),
            "challengeHash": str(row["challenge_hash"]),
            "public": json.loads(str(row["public_json"])),
            "expiresAt": int(row["expires_at"]),
            "consumedAt": (
                int(row["consumed_at"])
                if row["consumed_at"] is not None
                else None
            ),
            "createdAt": int(row["created_at"]),
        }

    def complete_recovery_drill(
        self,
        challenge_id: str,
        *,
        expected_challenge_hash: str,
        backup_status: str,
        backup_revision: int | None,
        backup_ciphertext_hash: str | None,
        now: int | None = None,
    ) -> dict[str, Any]:
        if backup_status not in {"NOT_CONFIGURED", "VERIFIED"}:
            raise ValueError("invalid recovery backup status")
        if backup_status == "VERIFIED" and (
            backup_revision is None
            or backup_revision < 1
            or not backup_ciphertext_hash
        ):
            raise ValueError("verified backup requires revision and ciphertext hash")
        if backup_status == "NOT_CONFIGURED" and (
            backup_revision is not None or backup_ciphertext_hash is not None
        ):
            raise ValueError("unconfigured backup cannot carry backup evidence")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            drill = connection.execute(
                "SELECT * FROM admin_recovery_drills WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            if drill is None:
                raise GenesisNotFound("recovery drill challenge not found")
            if drill["consumed_at"] is not None:
                raise GenesisConflict("recovery drill challenge was already used")
            if int(drill["expires_at"]) < timestamp:
                raise GenesisExpired("recovery drill challenge expired")
            if str(drill["challenge_hash"]).lower() != expected_challenge_hash.lower():
                raise GenesisConflict("recovery drill challenge hash changed")
            public = json.loads(str(drill["public_json"]))
            ceremony_id = str(drill["ceremony_id"])
            slot = int(drill["slot"])
            existing = connection.execute(
                "SELECT revision FROM admin_recovery_kits "
                "WHERE ceremony_id=? AND slot=?",
                (ceremony_id, slot),
            ).fetchone()
            revision = int(public["revision"])
            if existing is not None and revision != int(existing["revision"]) + 1:
                raise GenesisConflict(
                    "replacement recovery kit must be the next revision"
                )
            connection.execute(
                "UPDATE admin_recovery_drills SET consumed_at=? "
                "WHERE challenge_id=? AND consumed_at IS NULL",
                (timestamp, challenge_id),
            )
            values = (
                ceremony_id,
                slot,
                revision,
                str(public["evmGuardian"]).lower(),
                str(public["recoveryBlsPubkey"]).lower(),
                str(public["recoveryBlsCommitment"]).lower(),
                expected_challenge_hash.lower(),
                timestamp,
                backup_status,
                backup_revision,
                (
                    backup_ciphertext_hash.lower()
                    if backup_ciphertext_hash
                    else None
                ),
                timestamp if backup_status == "VERIFIED" else None,
                timestamp,
                timestamp,
            )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_kits(
                        ceremony_id,slot,revision,evm_guardian,
                        recovery_bls_pubkey,recovery_bls_commitment,
                        drill_challenge_hash,drill_verified_at,
                        offline_copy_confirmed,second_device_confirmed,
                        backup_status,backup_revision,backup_ciphertext_hash,
                        backup_verified_at,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,1,1,?,?,?,?,?,?)
                    """,
                    values,
                )
            else:
                try:
                    connection.execute(
                        """
                        INSERT INTO admin_recovery_kit_candidates(
                            challenge_id,ceremony_id,slot,revision,
                            evm_guardian,recovery_bls_pubkey,
                            recovery_bls_commitment,drill_challenge_hash,
                            drill_verified_at,offline_copy_confirmed,
                            second_device_confirmed,backup_status,
                            backup_revision,backup_ciphertext_hash,
                            backup_verified_at,state,created_at,updated_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,1,1,?,?,?,?, 'PENDING',?,?)
                        """,
                        (
                            challenge_id,
                            *values[:8],
                            *values[8:12],
                            *values[12:],
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise GenesisConflict(
                        "a replacement recovery kit is already pending"
                    ) from exc
            self._event(
                connection,
                ceremony_id,
                "admin_recovery_drill_completed",
                {
                    "slot": slot - 1,
                    "revision": revision,
                    "backupStatus": backup_status,
                    "activationRequired": existing is not None,
                },
                timestamp,
            )
        if existing is None:
            return self.recovery_kit(ceremony_id, slot)
        return self.recovery_kit_candidate(challenge_id)

    def recovery_kit(self, ceremony_id: str, slot: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_recovery_kits "
                "WHERE ceremony_id=? AND slot=?",
                (ceremony_id, slot),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("administrator recovery kit not found")
        return {
            "ceremonyId": str(row["ceremony_id"]),
            "slot": int(row["slot"]) - 1,
            "revision": int(row["revision"]),
            "evmGuardian": str(row["evm_guardian"]),
            "recoveryBlsPubkey": str(row["recovery_bls_pubkey"]),
            "recoveryBlsCommitment": str(row["recovery_bls_commitment"]),
            "drillChallengeHash": str(row["drill_challenge_hash"]),
            "drillVerifiedAt": int(row["drill_verified_at"]),
            "offlineCopyConfirmed": bool(row["offline_copy_confirmed"]),
            "secondDeviceConfirmed": bool(row["second_device_confirmed"]),
            "backupStatus": str(row["backup_status"]),
            "backupRevision": (
                int(row["backup_revision"])
                if row["backup_revision"] is not None
                else None
            ),
            "backupCiphertextHash": row["backup_ciphertext_hash"],
            "backupVerifiedAt": (
                int(row["backup_verified_at"])
                if row["backup_verified_at"] is not None
                else None
            ),
            "updatedAt": int(row["updated_at"]),
        }

    def recovery_kits(self, ceremony_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT slot FROM admin_recovery_kits "
                "WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
        return [
            self.recovery_kit(ceremony_id, int(row["slot"])) for row in rows
        ]

    @staticmethod
    def _recovery_kit_candidate_payload(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return {
            "challengeId": str(row["challenge_id"]),
            "ceremonyId": str(row["ceremony_id"]),
            "slot": int(row["slot"]) - 1,
            "revision": int(row["revision"]),
            "evmGuardian": str(row["evm_guardian"]),
            "recoveryBlsPubkey": str(row["recovery_bls_pubkey"]),
            "recoveryBlsCommitment": str(row["recovery_bls_commitment"]),
            "drillChallengeHash": str(row["drill_challenge_hash"]),
            "drillVerifiedAt": int(row["drill_verified_at"]),
            "offlineCopyConfirmed": bool(row["offline_copy_confirmed"]),
            "secondDeviceConfirmed": bool(row["second_device_confirmed"]),
            "backupStatus": str(row["backup_status"]),
            "backupRevision": (
                int(row["backup_revision"])
                if row["backup_revision"] is not None
                else None
            ),
            "backupCiphertextHash": row["backup_ciphertext_hash"],
            "backupVerifiedAt": (
                int(row["backup_verified_at"])
                if row["backup_verified_at"] is not None
                else None
            ),
            "state": str(row["state"]),
            "updatedAt": int(row["updated_at"]),
        }

    def recovery_kit_candidate(
        self,
        challenge_id: str,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_recovery_kit_candidates "
                "WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
        if row is None:
            raise GenesisNotFound("replacement recovery kit not found")
        return self._recovery_kit_candidate_payload(row)

    def pending_recovery_kit_candidate(
        self,
        ceremony_id: str,
        slot: int,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_recovery_kit_candidates "
                "WHERE ceremony_id=? AND slot=? AND state='PENDING'",
                (ceremony_id, slot),
            ).fetchone()
        return (
            self._recovery_kit_candidate_payload(row)
            if row is not None
            else None
        )

    def activate_recovery_kit_candidate(
        self,
        challenge_id: str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            candidate = connection.execute(
                "SELECT * FROM admin_recovery_kit_candidates "
                "WHERE challenge_id=? AND state='PENDING'",
                (challenge_id,),
            ).fetchone()
            if candidate is None:
                raise GenesisConflict(
                    "replacement recovery kit is not pending"
                )
            current = connection.execute(
                "SELECT revision FROM admin_recovery_kits "
                "WHERE ceremony_id=? AND slot=?",
                (candidate["ceremony_id"], candidate["slot"]),
            ).fetchone()
            if (
                current is None
                or int(candidate["revision"]) != int(current["revision"]) + 1
            ):
                raise GenesisConflict(
                    "replacement recovery kit revision is stale"
                )
            connection.execute(
                """
                UPDATE admin_recovery_kits SET
                    revision=?,evm_guardian=?,recovery_bls_pubkey=?,
                    recovery_bls_commitment=?,drill_challenge_hash=?,
                    drill_verified_at=?,offline_copy_confirmed=1,
                    second_device_confirmed=1,backup_status=?,
                    backup_revision=?,backup_ciphertext_hash=?,
                    backup_verified_at=?,updated_at=?
                WHERE ceremony_id=? AND slot=?
                """,
                (
                    candidate["revision"],
                    candidate["evm_guardian"],
                    candidate["recovery_bls_pubkey"],
                    candidate["recovery_bls_commitment"],
                    candidate["drill_challenge_hash"],
                    candidate["drill_verified_at"],
                    candidate["backup_status"],
                    candidate["backup_revision"],
                    candidate["backup_ciphertext_hash"],
                    candidate["backup_verified_at"],
                    timestamp,
                    candidate["ceremony_id"],
                    candidate["slot"],
                ),
            )
            connection.execute(
                "UPDATE admin_recovery_kit_candidates "
                "SET state='ACTIVATED',updated_at=? WHERE challenge_id=?",
                (timestamp, challenge_id),
            )
            self._event(
                connection,
                str(candidate["ceremony_id"]),
                "admin_recovery_kit_activated",
                {
                    "slot": int(candidate["slot"]) - 1,
                    "revision": int(candidate["revision"]),
                    "challengeId": challenge_id,
                },
                timestamp,
            )
            ceremony_id = str(candidate["ceremony_id"])
            slot = int(candidate["slot"])
        return self.recovery_kit(ceremony_id, slot)

    def cancel_recovery_kit_candidate(
        self,
        challenge_id: str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            candidate = connection.execute(
                "SELECT * FROM admin_recovery_kit_candidates "
                "WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            if candidate is None:
                raise GenesisNotFound("replacement recovery kit not found")
            if str(candidate["state"]) == "ACTIVATED":
                raise GenesisConflict(
                    "active recovery kit cannot be canceled"
                )
            connection.execute(
                "UPDATE admin_recovery_kit_candidates "
                "SET state='CANCELLED',updated_at=? WHERE challenge_id=?",
                (timestamp, challenge_id),
            )
            self._event(
                connection,
                str(candidate["ceremony_id"]),
                "admin_recovery_kit_candidate_cancelled",
                {
                    "slot": int(candidate["slot"]) - 1,
                    "revision": int(candidate["revision"]),
                    "challengeId": challenge_id,
                },
                timestamp,
            )
        return self.recovery_kit_candidate(challenge_id)

    def create_recovery_case(
        self,
        ceremony_id: str,
        *,
        case_id: str,
        authority_slot: int,
        kind: str,
        intent_hash: str,
        intent: dict[str, Any],
        execute_after: int,
        expires_at: int,
        prepared_by: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        if authority_slot not in (0, 1, 2):
            raise ValueError("authority slot must be 0, 1, or 2")
        if kind not in {"ROUTINE", "LOST", "RECOVERY_KIT"}:
            raise ValueError("invalid recovery kind")
        timestamp = int(time.time()) if now is None else now
        if execute_after <= timestamp or expires_at <= execute_after:
            raise ValueError("recovery timing is invalid")
        encoded = canonical_json(intent)
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            active = connection.execute(
                "SELECT case_id FROM admin_recovery_cases WHERE ceremony_id=? "
                "AND state NOT IN ('COMPLETED','CANCELLED','FAILED') LIMIT 1",
                (ceremony_id,),
            ).fetchone()
            if active is not None:
                raise GenesisConflict("another administrator key change is active")
            try:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_cases(
                        case_id,ceremony_id,authority_slot,kind,state,intent_hash,
                        intent_json,execute_after,expires_at,prepared_by,
                        created_at,updated_at
                    ) VALUES(?,?,?,?,'AWAITING_APPROVALS',?,?,?,?,?,?,?)
                    """,
                    (
                        case_id,
                        ceremony_id,
                        authority_slot,
                        kind,
                        intent_hash.lower(),
                        encoded,
                        execute_after,
                        expires_at,
                        prepared_by.lower(),
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict(
                    "administrator key-change intent was already used"
                ) from exc
            self._event(
                connection,
                ceremony_id,
                "admin_key_change_prepared",
                {
                    "caseId": case_id,
                    "intentHash": intent_hash.lower(),
                    "kind": kind,
                    "slot": authority_slot,
                    "executeAfter": execute_after,
                },
                timestamp,
            )
        return self.recovery_case(case_id)

    def add_recovery_approval(
        self,
        case_id: str,
        *,
        actor_role: str,
        actor_id: str,
        signer_slot: int | None,
        signer_address: str,
        signature: str,
        message_hash: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            case = connection.execute(
                "SELECT * FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if str(case["state"]) in {"COMPLETED", "CANCELLED", "FAILED"}:
                raise GenesisConflict("administrator recovery case is terminal")
            try:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_approvals(
                        case_id,actor_role,actor_id,signer_slot,signer_address,
                        signature,message_hash,submitted_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        case_id,
                        actor_role,
                        actor_id,
                        signer_slot,
                        signer_address.lower(),
                        signature.lower(),
                        message_hash.lower(),
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict(
                    "this recovery approval was already submitted"
                ) from exc
            self._event(
                connection,
                str(case["ceremony_id"]),
                "admin_key_change_approval_recorded",
                {
                    "caseId": case_id,
                    "actorRole": actor_role,
                    "actorId": actor_id,
                    "signerSlot": signer_slot,
                },
                timestamp,
            )
        return self.recovery_case(case_id)

    def add_recovery_chia_signature(
        self,
        case_id: str,
        *,
        phase: str,
        action_id: str,
        signer_kind: str,
        signer_slot: int | None,
        signer_public_key: str,
        signature: str,
        message_hash: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        if phase not in {"PREPARE", "CANCEL"}:
            raise ValueError("Chia recovery signature phase is invalid")
        if signer_kind not in {"EIP712_DAILY", "BLS_RECOVERY"}:
            raise ValueError("Chia recovery signer kind is invalid")
        if signer_slot is not None and signer_slot not in (0, 1, 2):
            raise ValueError("Chia recovery signer slot is invalid")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            case = connection.execute(
                "SELECT * FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if str(case["state"]) in {"COMPLETED", "CANCELLED", "FAILED"}:
                raise GenesisConflict("administrator recovery case is terminal")
            try:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_chia_signatures(
                        case_id,phase,action_id,signer_kind,signer_slot,
                        signer_public_key,signature,message_hash,submitted_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        case_id,
                        phase,
                        action_id.lower(),
                        signer_kind,
                        signer_slot,
                        signer_public_key.lower(),
                        signature.lower(),
                        message_hash.lower(),
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict(
                    "this Chia recovery action was already signed"
                ) from exc
            self._event(
                connection,
                str(case["ceremony_id"]),
                "admin_key_change_chia_signature_recorded",
                {
                    "caseId": case_id,
                    "phase": phase,
                    "actionId": action_id.lower(),
                    "signerKind": signer_kind,
                    "signerSlot": signer_slot,
                    "messageHash": message_hash.lower(),
                },
                timestamp,
            )
        return self.recovery_case(case_id)

    def recovery_chia_signatures(
        self,
        case_id: str,
        *,
        phase: str | None = None,
        include_signatures: bool = False,
    ) -> list[dict[str, Any]]:
        if phase is not None and phase not in {"PREPARE", "CANCEL"}:
            raise ValueError("Chia recovery signature phase is invalid")
        with self._connect() as connection:
            case = connection.execute(
                "SELECT case_id FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if phase is None:
                rows = connection.execute(
                    "SELECT * FROM admin_recovery_chia_signatures "
                    "WHERE case_id=? ORDER BY submitted_at,phase,action_id",
                    (case_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM admin_recovery_chia_signatures "
                    "WHERE case_id=? AND phase=? "
                    "ORDER BY submitted_at,action_id",
                    (case_id, phase),
                ).fetchall()
        return [
            {
                "phase": str(row["phase"]),
                "actionId": str(row["action_id"]),
                "signerKind": str(row["signer_kind"]),
                "signerSlot": (
                    int(row["signer_slot"])
                    if row["signer_slot"] is not None
                    else None
                ),
                "signerPublicKey": str(row["signer_public_key"]),
                "messageHash": str(row["message_hash"]),
                "submittedAt": int(row["submitted_at"]),
                **(
                    {"signature": str(row["signature"])}
                    if include_signatures
                    else {}
                ),
            }
            for row in rows
        ]

    def add_recovery_evm_safe_signature(
        self,
        case_id: str,
        *,
        action_id: str,
        package_hash: str,
        safe_nonce: int,
        coadmin_slot: int | None,
        signer_slot: int,
        signer_role: str,
        signer_address: str,
        signature: str,
        message_hash: str,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        if safe_nonce < 0:
            raise ValueError("Safe nonce must not be negative")
        if coadmin_slot is not None and coadmin_slot not in (1, 2):
            raise ValueError("Safe coadministrator slot is invalid")
        if signer_slot not in (0, 1, 2):
            raise ValueError("Safe signer slot is invalid")
        if signer_role not in {"OWNER", "COADMIN", "PEER"}:
            raise ValueError("Safe signer role is invalid")
        timestamp = int(time.time()) if now is None else now
        normalized_action = action_id.lower()
        normalized_package = package_hash.lower()
        normalized_signer = signer_address.lower()
        normalized_signature = signature.lower()
        normalized_message = message_hash.lower()
        with self._transaction() as connection:
            case = connection.execute(
                "SELECT * FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if str(case["state"]) in {"COMPLETED", "CANCELLED", "FAILED"}:
                raise GenesisConflict("administrator recovery case is terminal")
            existing = connection.execute(
                "SELECT * FROM admin_recovery_evm_safe_signatures "
                "WHERE case_id=? AND action_id=?",
                (case_id, normalized_action),
            ).fetchall()
            if existing and any(
                str(row["package_hash"]).lower() != normalized_package
                or int(row["safe_nonce"]) != safe_nonce
                or (
                    int(row["coadmin_slot"])
                    if row["coadmin_slot"] is not None
                    else None
                )
                != coadmin_slot
                for row in existing
            ):
                connection.execute(
                    "DELETE FROM admin_recovery_evm_safe_signatures "
                    "WHERE case_id=? AND action_id=?",
                    (case_id, normalized_action),
                )
                self._event(
                    connection,
                    str(case["ceremony_id"]),
                    "admin_key_change_evm_safe_package_invalidated",
                    {
                        "caseId": case_id,
                        "actionId": normalized_action,
                        "replacementPackageHash": normalized_package,
                        "safeNonce": safe_nonce,
                    },
                    timestamp,
                )
                existing = []
            duplicate = next(
                (
                    row
                    for row in existing
                    if int(row["signer_slot"]) == signer_slot
                ),
                None,
            )
            if duplicate is not None:
                if (
                    str(duplicate["signer_role"]) != signer_role
                    or str(duplicate["signer_address"]).lower()
                    != normalized_signer
                    or str(duplicate["signature"]).lower()
                    != normalized_signature
                    or str(duplicate["message_hash"]).lower()
                    != normalized_message
                ):
                    raise GenesisConflict(
                        "this Safe approval conflicts with the recorded signature"
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_evm_safe_signatures(
                        case_id,action_id,package_hash,safe_nonce,coadmin_slot,
                        signer_slot,signer_role,signer_address,signature,
                        message_hash,submitted_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        case_id,
                        normalized_action,
                        normalized_package,
                        safe_nonce,
                        coadmin_slot,
                        signer_slot,
                        signer_role,
                        normalized_signer,
                        normalized_signature,
                        normalized_message,
                        timestamp,
                    ),
                )
                self._event(
                    connection,
                    str(case["ceremony_id"]),
                    "admin_key_change_evm_safe_signature_recorded",
                    {
                        "caseId": case_id,
                        "actionId": normalized_action,
                        "packageHash": normalized_package,
                        "safeNonce": safe_nonce,
                        "coadminSlot": coadmin_slot,
                        "signerSlot": signer_slot,
                        "signerRole": signer_role,
                        "messageHash": normalized_message,
                    },
                    timestamp,
                )
        return self.recovery_evm_safe_signatures(
            case_id,
            action_id=normalized_action,
            package_hash=normalized_package,
            include_signatures=True,
        )

    def recovery_evm_safe_signatures(
        self,
        case_id: str,
        *,
        action_id: str,
        package_hash: str | None = None,
        include_signatures: bool = False,
    ) -> list[dict[str, Any]]:
        normalized_action = action_id.lower()
        with self._connect() as connection:
            case = connection.execute(
                "SELECT case_id FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if package_hash is None:
                rows = connection.execute(
                    "SELECT * FROM admin_recovery_evm_safe_signatures "
                    "WHERE case_id=? AND action_id=? "
                    "ORDER BY submitted_at,signer_slot",
                    (case_id, normalized_action),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM admin_recovery_evm_safe_signatures "
                    "WHERE case_id=? AND action_id=? AND package_hash=? "
                    "ORDER BY submitted_at,signer_slot",
                    (case_id, normalized_action, package_hash.lower()),
                ).fetchall()
        return [
            {
                "actionId": str(row["action_id"]),
                "packageHash": str(row["package_hash"]),
                "safeNonce": int(row["safe_nonce"]),
                "coadminSlot": (
                    int(row["coadmin_slot"])
                    if row["coadmin_slot"] is not None
                    else None
                ),
                "signerSlot": int(row["signer_slot"]),
                "signerRole": str(row["signer_role"]),
                "signerAddress": str(row["signer_address"]),
                "messageHash": str(row["message_hash"]),
                "submittedAt": int(row["submitted_at"]),
                **(
                    {"signature": str(row["signature"])}
                    if include_signatures
                    else {}
                ),
            }
            for row in rows
        ]

    def add_recovery_evm_submission(
        self,
        case_id: str,
        *,
        action_id: str,
        transaction_hash: str,
        submitted_by: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else now
        normalized_action = action_id.lower()
        normalized_transaction = transaction_hash.lower()
        normalized_submitter = submitted_by.lower()
        with self._transaction() as connection:
            case = connection.execute(
                "SELECT * FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if str(case["state"]) in {"COMPLETED", "CANCELLED", "FAILED"}:
                raise GenesisConflict("administrator recovery case is terminal")
            existing = connection.execute(
                "SELECT * FROM admin_recovery_evm_submissions "
                "WHERE case_id=? AND action_id=?",
                (case_id, normalized_action),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["transaction_hash"]).lower()
                    != normalized_transaction
                    or str(existing["submitted_by"]).lower()
                    != normalized_submitter
                ):
                    raise GenesisConflict(
                        "this Base Sepolia action already has a different transaction"
                    )
                return self._recovery_evm_submission_row(existing)
            try:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_evm_submissions(
                        case_id,action_id,transaction_hash,state,submitted_by,
                        submitted_at,updated_at
                    ) VALUES(?,?,?,'PENDING',?,?,?)
                    """,
                    (
                        case_id,
                        normalized_action,
                        normalized_transaction,
                        normalized_submitter,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict(
                    "this Base Sepolia transaction is already assigned"
                ) from exc
            self._event(
                connection,
                str(case["ceremony_id"]),
                "admin_key_change_evm_submission_recorded",
                {
                    "caseId": case_id,
                    "actionId": normalized_action,
                    "transactionHash": normalized_transaction,
                    "submittedBy": normalized_submitter,
                },
                timestamp,
            )
        return self.recovery_evm_submission(case_id, normalized_action)

    def confirm_recovery_evm_submission(
        self,
        case_id: str,
        *,
        transaction_hash: str,
        now: int | None = None,
    ) -> dict[str, Any] | None:
        timestamp = int(time.time()) if now is None else now
        normalized_transaction = transaction_hash.lower()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT s.*,c.ceremony_id FROM admin_recovery_evm_submissions s "
                "JOIN admin_recovery_cases c ON c.case_id=s.case_id "
                "WHERE s.case_id=? AND s.transaction_hash=?",
                (case_id, normalized_transaction),
            ).fetchone()
            if row is None:
                return None
            if str(row["state"]) != "CONFIRMED":
                connection.execute(
                    "UPDATE admin_recovery_evm_submissions "
                    "SET state='CONFIRMED',updated_at=? "
                    "WHERE case_id=? AND transaction_hash=?",
                    (timestamp, case_id, normalized_transaction),
                )
                self._event(
                    connection,
                    str(row["ceremony_id"]),
                    "admin_key_change_evm_submission_confirmed",
                    {
                        "caseId": case_id,
                        "actionId": str(row["action_id"]),
                        "transactionHash": normalized_transaction,
                    },
                    timestamp,
                )
        return self.recovery_evm_submission(case_id, str(row["action_id"]))

    def recovery_evm_submission(
        self,
        case_id: str,
        action_id: str,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_recovery_evm_submissions "
                "WHERE case_id=? AND action_id=?",
                (case_id, action_id.lower()),
            ).fetchone()
            if row is None:
                raise GenesisNotFound(
                    "Base Sepolia recovery submission not found"
                )
        return self._recovery_evm_submission_row(row)

    def recovery_evm_submissions(
        self,
        case_id: str,
        *,
        pending_only: bool = False,
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            case = connection.execute(
                "SELECT case_id FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            if pending_only:
                rows = connection.execute(
                    "SELECT * FROM admin_recovery_evm_submissions "
                    "WHERE case_id=? AND state='PENDING' "
                    "ORDER BY submitted_at,action_id",
                    (case_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM admin_recovery_evm_submissions "
                    "WHERE case_id=? ORDER BY submitted_at,action_id",
                    (case_id,),
                ).fetchall()
        return [self._recovery_evm_submission_row(row) for row in rows]

    @staticmethod
    def _recovery_evm_submission_row(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return {
            "actionId": str(row["action_id"]),
            "transactionHash": str(row["transaction_hash"]),
            "state": str(row["state"]),
            "submittedBy": str(row["submitted_by"]),
            "submittedAt": int(row["submitted_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def update_recovery_case(
        self,
        case_id: str,
        *,
        state: str,
        chia_transaction_id: str | None = None,
        evm_transaction_hash: str | None = None,
        chia_receipt_hash: str | None = None,
        evm_receipt_hash: str | None = None,
        failure_reason: str | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "PREPARED",
            "AWAITING_APPROVALS",
            "READY",
            "SUBMITTED",
            "PARTIAL",
            "COMPLETED",
            "CANCELLED",
            "FAILED",
        }
        if state not in allowed:
            raise ValueError("invalid administrator recovery state")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            case = connection.execute(
                "SELECT * FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            existing_state = str(case["state"])
            if existing_state in {"COMPLETED", "CANCELLED", "FAILED"}:
                if existing_state == state:
                    return self.recovery_case(case_id)
                raise GenesisConflict("administrator recovery case is terminal")
            connection.execute(
                """
                UPDATE admin_recovery_cases SET
                    state=?,
                    chia_transaction_id=COALESCE(?,chia_transaction_id),
                    evm_transaction_hash=COALESCE(?,evm_transaction_hash),
                    chia_receipt_hash=COALESCE(?,chia_receipt_hash),
                    evm_receipt_hash=COALESCE(?,evm_receipt_hash),
                    failure_reason=COALESCE(?,failure_reason),
                    updated_at=?
                WHERE case_id=?
                """,
                (
                    state,
                    chia_transaction_id,
                    evm_transaction_hash,
                    chia_receipt_hash,
                    evm_receipt_hash,
                    failure_reason,
                    timestamp,
                    case_id,
                ),
            )
            self._event(
                connection,
                str(case["ceremony_id"]),
                "admin_key_change_state_updated",
                {"caseId": case_id, "state": state},
                timestamp,
            )
        return self.recovery_case(case_id)

    def add_recovery_receipt(
        self,
        case_id: str,
        *,
        chain: str,
        phase: str,
        transaction_id: str,
        receipt_hash: str,
        receipt: dict[str, Any],
        now: int | None = None,
    ) -> dict[str, Any]:
        if chain not in {"CHIA", "EVM"}:
            raise ValueError("recovery receipt chain must be CHIA or EVM")
        if phase not in {
            "PREPARE",
            "APPROVE",
            "EXECUTE",
            "CANCEL",
            "COMPLETE",
            "ROLLBACK",
        }:
            raise ValueError("recovery receipt phase is invalid")
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            case = connection.execute(
                "SELECT ceremony_id FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise GenesisNotFound("administrator recovery case not found")
            try:
                connection.execute(
                    """
                    INSERT INTO admin_recovery_receipts(
                        case_id,chain,phase,transaction_id,receipt_hash,
                        receipt_json,observed_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        case_id,
                        chain,
                        phase,
                        transaction_id.lower(),
                        receipt_hash.lower(),
                        canonical_json(receipt),
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GenesisConflict(
                    f"{chain} recovery receipt was already recorded"
                ) from exc
            self._event(
                connection,
                str(case["ceremony_id"]),
                "admin_key_change_receipt_recorded",
                {
                    "caseId": case_id,
                    "chain": chain,
                    "phase": phase,
                    "transactionId": transaction_id.lower(),
                },
                timestamp,
            )
        return self.recovery_case(case_id)

    def recovery_case(self, case_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_recovery_cases WHERE case_id=?",
                (case_id,),
            ).fetchone()
            if row is None:
                raise GenesisNotFound("administrator recovery case not found")
            approvals = connection.execute(
                "SELECT * FROM admin_recovery_approvals "
                "WHERE case_id=? ORDER BY submitted_at,actor_role,actor_id",
                (case_id,),
            ).fetchall()
            receipts = connection.execute(
                "SELECT * FROM admin_recovery_receipts "
                "WHERE case_id=? ORDER BY observed_at,chain,phase",
                (case_id,),
            ).fetchall()
            chia_signatures = connection.execute(
                "SELECT phase,action_id,signer_kind,signer_slot,"
                "signer_public_key,message_hash,submitted_at "
                "FROM admin_recovery_chia_signatures "
                "WHERE case_id=? ORDER BY submitted_at,phase,action_id",
                (case_id,),
            ).fetchall()
            evm_submissions = connection.execute(
                "SELECT * FROM admin_recovery_evm_submissions "
                "WHERE case_id=? ORDER BY submitted_at,action_id",
                (case_id,),
            ).fetchall()
        return {
            "caseId": str(row["case_id"]),
            "ceremonyId": str(row["ceremony_id"]),
            "slot": int(row["authority_slot"]),
            "kind": str(row["kind"]),
            "state": str(row["state"]),
            "intentHash": str(row["intent_hash"]),
            "intent": json.loads(str(row["intent_json"])),
            "executeAfter": int(row["execute_after"]),
            "expiresAt": int(row["expires_at"]),
            "preparedBy": str(row["prepared_by"]),
            "chiaTransactionId": row["chia_transaction_id"],
            "evmTransactionHash": row["evm_transaction_hash"],
            "chiaReceiptHash": row["chia_receipt_hash"],
            "evmReceiptHash": row["evm_receipt_hash"],
            "failureReason": row["failure_reason"],
            "approvals": [
                {
                    "actorRole": str(item["actor_role"]),
                    "actorId": str(item["actor_id"]),
                    "signerSlot": (
                        int(item["signer_slot"])
                        if item["signer_slot"] is not None
                        else None
                    ),
                    "signerAddress": str(item["signer_address"]),
                    "messageHash": str(item["message_hash"]),
                    "submittedAt": int(item["submitted_at"]),
                }
                for item in approvals
            ],
            "receipts": [
                {
                    "chain": str(item["chain"]),
                    "phase": str(item["phase"]),
                    "transactionId": str(item["transaction_id"]),
                    "receiptHash": str(item["receipt_hash"]),
                    "receipt": json.loads(str(item["receipt_json"])),
                    "observedAt": int(item["observed_at"]),
                }
                for item in receipts
            ],
            "chiaSignatures": [
                {
                    "phase": str(item["phase"]),
                    "actionId": str(item["action_id"]),
                    "signerKind": str(item["signer_kind"]),
                    "signerSlot": (
                        int(item["signer_slot"])
                        if item["signer_slot"] is not None
                        else None
                    ),
                    "signerPublicKey": str(item["signer_public_key"]),
                    "messageHash": str(item["message_hash"]),
                    "submittedAt": int(item["submitted_at"]),
                }
                for item in chia_signatures
            ],
            "evmSubmissions": [
                self._recovery_evm_submission_row(item)
                for item in evm_submissions
            ],
            "createdAt": int(row["created_at"]),
            "updatedAt": int(row["updated_at"]),
        }

    def recovery_cases(self, ceremony_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT case_id FROM admin_recovery_cases "
                "WHERE ceremony_id=? ORDER BY created_at DESC",
                (ceremony_id,),
            ).fetchall()
        return [self.recovery_case(str(row["case_id"])) for row in rows]

    def active_recovery_cases(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT case_id FROM admin_recovery_cases "
                "WHERE state NOT IN ('COMPLETED','CANCELLED','FAILED') "
                "ORDER BY created_at"
            ).fetchall()
        return [self.recovery_case(str(row["case_id"])) for row in rows]

    def enqueue_admin_notification(
        self,
        ceremony_id: str,
        *,
        event_type: str,
        recipient: str,
        subject: str,
        body: str,
        now: int | None = None,
    ) -> int:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            self._require_ceremony(connection, ceremony_id)
            cursor = connection.execute(
                """
                INSERT INTO admin_notification_outbox(
                    ceremony_id,event_type,recipient,subject,body,state,
                    created_at,updated_at
                ) VALUES(?,?,?,?,?,'PENDING',?,?)
                """,
                (
                    ceremony_id,
                    event_type,
                    recipient.lower(),
                    subject,
                    body,
                    timestamp,
                    timestamp,
                ),
            )
            return int(cursor.lastrowid)

    def pending_admin_notifications(
        self, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 250:
            raise ValueError("notification limit must be between 1 and 250")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM admin_notification_outbox "
                "WHERE state IN ('PENDING','FAILED') "
                "ORDER BY notification_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_admin_notification(
        self,
        notification_id: int,
        *,
        sent: bool,
        error: str | None = None,
        now: int | None = None,
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT attempts FROM admin_notification_outbox "
                "WHERE notification_id=?",
                (notification_id,),
            ).fetchone()
            if row is None:
                raise GenesisNotFound("administrator notification not found")
            attempts = int(row["attempts"]) + 1
            state = "SENT" if sent else "FAILED"
            connection.execute(
                "UPDATE admin_notification_outbox "
                "SET state=?,attempts=?,last_error=?,updated_at=? "
                "WHERE notification_id=?",
                (
                    state,
                    attempts,
                    None if sent else (error or "delivery failed")[:1000],
                    timestamp,
                    notification_id,
                ),
            )

    def get(self, ceremony_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            ceremony = self._require_ceremony(connection, ceremony_id)
            invitations = connection.execute(
                "SELECT slot,expires_at,consumed_at,wallet_address,compressed_pubkey "
                "FROM invitations WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
            plan_signatures = connection.execute(
                "SELECT slot,plan_hash,compressed_pubkey,signature,submitted_at "
                "FROM plan_signatures WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
            artifact_signatures = connection.execute(
                "SELECT slot,artifact_hash,compressed_pubkey,signature,submitted_at "
                "FROM artifact_signatures WHERE ceremony_id=? ORDER BY slot",
                (ceremony_id,),
            ).fetchall()
        result = dict(ceremony)
        for key in ("draft_json", "plan_input_json", "plan_json", "broadcast_json", "artifact_json"):
            result[key.removesuffix("_json")] = (
                json.loads(result[key]) if result.get(key) else None
            )
            result.pop(key, None)
        result["invitations"] = [dict(row) for row in invitations]
        result["plan_signatures"] = [dict(row) for row in plan_signatures]
        result["artifact_signatures"] = [dict(row) for row in artifact_signatures]
        return result


__all__ = [
    "ADMIN_SLOTS",
    "GenesisStore",
    "GenesisStoreError",
    "GenesisNotFound",
    "GenesisConflict",
    "GenesisExpired",
    "OWNER_SLOT",
    "COADMIN_SLOTS",
    "canonical_json",
    "owner_plus_one_approved",
]
