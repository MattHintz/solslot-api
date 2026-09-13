"""Revisioned SQLite-WAL queue for typed governance proposals."""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal


ProposalKind = Literal["SGT_SALE", "SGT_GRANT", "FUNDED_REDEMPTION"]
ProposalState = Literal[
    "DRAFT", "READY", "ACTIVE", "EXECUTED", "FAILED", "CANCELED"
]
SaleOfferStatus = Literal["AVAILABLE", "PENDING", "TAKEN", "EXPIRED", "RETURNED"]


class GovernanceQueueError(ValueError):
    pass


class GovernanceQueueConflict(GovernanceQueueError):
    pass


class GovernanceQueueNotFound(GovernanceQueueError):
    pass


@dataclass(frozen=True)
class GovernanceQueueRecord:
    id: str
    kind: ProposalKind
    state: ProposalState
    title: str
    bill: dict[str, Any]
    bill_clvm_hex: str
    proposal_hash: str
    revision: int
    queue_position: int
    created_by: str
    created_at: int
    updated_at: int
    activated_at: int | None
    completed_at: int | None
    activation_bundle_id: str | None
    proposal_coin_id: str | None
    completion_bundle_id: str | None
    publication_coadmin_slot: int | None
    publication_voting_deadline: int | None
    execution_bundle_id: str | None
    expected_output_coin_ids: tuple[str, ...]
    execution_submitted_at: int | None
    sale_offer_id: str | None
    sale_offer_bech32: str | None
    sale_coin_id: str | None
    sale_offer_status: SaleOfferStatus | None
    sale_offer_published_at: int | None
    sale_offer_confirmed_height: int | None
    sale_offer_spent_height: int | None


@dataclass(frozen=True)
class GovernanceQueueSignature:
    proposal_id: str
    action_id: str
    signer_slot: int
    signer_public_key: str
    message_hash: str
    signature: str
    signed_by: str
    signed_at: int


class GovernanceQueueStore:
    """One durable queue feeding the protocol's one active tracker."""

    def __init__(self, path: str) -> None:
        db_path = Path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
            except Exception:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()
            finally:
                cursor.close()

    def _migrate(self) -> None:
        with self._txn() as cursor:
            existing = cursor.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' "
                "AND name='governance_proposal_queue'"
            ).fetchone()
            if existing is not None and "FUNDED_REDEMPTION" not in str(existing[0]):
                # SQLite cannot widen a CHECK constraint in place. Preserve every
                # queue row and signature while rebuilding only the constrained
                # tables; the audit ledger remains untouched.
                cursor.execute("ALTER TABLE governance_queue_signatures RENAME TO governance_queue_signatures_v1")
                cursor.execute("ALTER TABLE governance_proposal_queue RENAME TO governance_proposal_queue_v1")
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS governance_proposal_queue (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK (
                        kind IN ('SGT_SALE','SGT_GRANT','FUNDED_REDEMPTION')
                    ),
                    state TEXT NOT NULL CHECK (
                        state IN ('DRAFT','READY','ACTIVE','EXECUTED','FAILED','CANCELED')
                    ),
                    title TEXT NOT NULL,
                    bill_json TEXT NOT NULL,
                    bill_clvm_hex TEXT NOT NULL,
                    proposal_hash TEXT NOT NULL UNIQUE,
                    revision INTEGER NOT NULL,
                    queue_position INTEGER NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    activated_at INTEGER,
                    completed_at INTEGER
                    ,activation_bundle_id TEXT
                    ,proposal_coin_id TEXT
                    ,completion_bundle_id TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_governance_one_active
                    ON governance_proposal_queue(state) WHERE state='ACTIVE';
                CREATE INDEX IF NOT EXISTS idx_governance_queue_order
                    ON governance_proposal_queue(state, queue_position, created_at);
                CREATE TABLE IF NOT EXISTS governance_queue_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proposal_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    occurred_at INTEGER NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS governance_queue_signatures (
                    proposal_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    signer_slot INTEGER NOT NULL CHECK (signer_slot IN (0,1,2)),
                    signer_public_key TEXT NOT NULL,
                    message_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signed_by TEXT NOT NULL,
                    signed_at INTEGER NOT NULL,
                    PRIMARY KEY (proposal_id, action_id),
                    FOREIGN KEY (proposal_id)
                        REFERENCES governance_proposal_queue(id)
                );
                """
            )
            if existing is not None and "FUNDED_REDEMPTION" not in str(existing[0]):
                old_columns = {
                    str(row[1])
                    for row in cursor.execute(
                        "PRAGMA table_info(governance_proposal_queue_v1)"
                    ).fetchall()
                }
                new_columns = [
                    str(row[1])
                    for row in cursor.execute(
                        "PRAGMA table_info(governance_proposal_queue)"
                    ).fetchall()
                ]
                shared = [column for column in new_columns if column in old_columns]
                names = ",".join(shared)
                cursor.execute(
                    f"INSERT INTO governance_proposal_queue ({names}) "
                    f"SELECT {names} FROM governance_proposal_queue_v1"
                )
                cursor.execute(
                    "INSERT INTO governance_queue_signatures "
                    "SELECT * FROM governance_queue_signatures_v1"
                )
                cursor.execute("DROP TABLE governance_queue_signatures_v1")
                cursor.execute("DROP TABLE governance_proposal_queue_v1")
                # The original named indexes followed the renamed table and
                # were removed with it, so recreate them on the widened queue.
                cursor.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_governance_one_active "
                    "ON governance_proposal_queue(state) WHERE state='ACTIVE'"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_governance_queue_order "
                    "ON governance_proposal_queue(state, queue_position, created_at)"
                )
            self._ensure_column(cursor, "governance_proposal_queue", "activation_bundle_id", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "proposal_coin_id", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "completion_bundle_id", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "publication_coadmin_slot", "INTEGER")
            self._ensure_column(cursor, "governance_proposal_queue", "publication_voting_deadline", "INTEGER")
            self._ensure_column(cursor, "governance_proposal_queue", "execution_bundle_id", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "expected_output_coin_ids_json", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "execution_submitted_at", "INTEGER")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_offer_id", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_offer_bech32", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_coin_id", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_offer_status", "TEXT")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_offer_published_at", "INTEGER")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_offer_confirmed_height", "INTEGER")
            self._ensure_column(cursor, "governance_proposal_queue", "sale_offer_spent_height", "INTEGER")

    @staticmethod
    def _ensure_column(
        cursor: sqlite3.Cursor,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {
            str(row[1]) for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def create(
        self,
        *,
        kind: ProposalKind,
        title: str,
        bill: dict[str, Any],
        bill_clvm_hex: str,
        proposal_hash: str,
        actor: str,
        now: int | None = None,
    ) -> GovernanceQueueRecord:
        timestamp = int(time.time()) if now is None else now
        proposal_id = "GOV-" + secrets.token_hex(8).upper()
        with self._txn() as cursor:
            row = cursor.execute(
                "SELECT COALESCE(MAX(queue_position), 0) AS value "
                "FROM governance_proposal_queue WHERE state IN ('DRAFT','READY')"
            ).fetchone()
            position = int(row["value"]) + 1
            try:
                cursor.execute(
                    """
                    INSERT INTO governance_proposal_queue (
                        id, kind, state, title, bill_json, bill_clvm_hex,
                        proposal_hash, revision, queue_position, created_by,
                        created_at, updated_at
                    ) VALUES (?, ?, 'DRAFT', ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        proposal_id,
                        kind,
                        title.strip(),
                        _canonical_json(bill),
                        bill_clvm_hex,
                        proposal_hash,
                        position,
                        actor.lower(),
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernanceQueueConflict(
                    "this exact governance bill is already queued"
                ) from exc
            self._audit(cursor, proposal_id, actor, "CREATED", 1, {}, timestamp)
        return self.get(proposal_id)

    def get(self, proposal_id: str) -> GovernanceQueueRecord:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM governance_proposal_queue WHERE id=?",
                (proposal_id,),
            ).fetchone()
        if row is None:
            raise GovernanceQueueNotFound(proposal_id)
        return _record(row)

    def find_executed_redemptions(self, settlement_id: str) -> list[GovernanceQueueRecord]:
        """Find a permanent settlement independently of the queue's display page.

        Return at most two matches so callers can reject ambiguous evidence.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM governance_proposal_queue "
                "WHERE kind='FUNDED_REDEMPTION' AND state='EXECUTED' "
                "AND lower(json_extract(bill_json, '$.settlementId'))=? LIMIT 2",
                (settlement_id.lower(),),
            ).fetchall()
        return [_record(row) for row in rows]

    def list(
        self,
        *,
        public: bool = False,
        limit: int = 100,
    ) -> list[GovernanceQueueRecord]:
        where = "WHERE state IN ('READY','ACTIVE','EXECUTED','FAILED')" if public else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM governance_proposal_queue {where} "
                "ORDER BY CASE state WHEN 'ACTIVE' THEN 0 WHEN 'READY' THEN 1 ELSE 2 END, "
                "queue_position, created_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [_record(row) for row in rows]

    def transition(
        self,
        *,
        proposal_id: str,
        expected_revision: int,
        target: ProposalState,
        actor: str,
        activation_bundle_id: str | None = None,
        proposal_coin_id: str | None = None,
        completion_bundle_id: str | None = None,
        now: int | None = None,
    ) -> GovernanceQueueRecord:
        allowed: dict[str, set[str]] = {
            "DRAFT": {"READY", "CANCELED"},
            "READY": {"ACTIVE", "CANCELED"},
            "ACTIVE": {"EXECUTED", "FAILED"},
        }
        timestamp = int(time.time()) if now is None else now
        with self._txn() as cursor:
            row = cursor.execute(
                "SELECT state, revision, created_by FROM governance_proposal_queue WHERE id=?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise GovernanceQueueNotFound(proposal_id)
            if int(row["revision"]) != expected_revision:
                raise GovernanceQueueConflict(
                    f"stale revision {expected_revision}; current {row['revision']}"
                )
            if target not in allowed.get(str(row["state"]), set()):
                raise GovernanceQueueConflict(
                    f"cannot transition {row['state']} to {target}"
                )
            if target == "READY" and str(row["created_by"]).lower() == actor.lower():
                raise GovernanceQueueConflict(
                    "a different administrator must review this proposal"
                )
            if target == "ACTIVE" and (
                activation_bundle_id is None or proposal_coin_id is None
            ):
                raise GovernanceQueueConflict(
                    "ACTIVE requires a submitted bundle id and proposal coin id"
                )
            if target in {"EXECUTED", "FAILED"} and completion_bundle_id is None:
                raise GovernanceQueueConflict(
                    f"{target} requires a chain completion bundle id"
                )
            revision = expected_revision + 1
            activated_at = timestamp if target == "ACTIVE" else None
            completed_at = timestamp if target in {"EXECUTED", "FAILED", "CANCELED"} else None
            try:
                cursor.execute(
                    """
                    UPDATE governance_proposal_queue
                    SET state=?, revision=?, updated_at=?,
                        activated_at=COALESCE(?, activated_at),
                        completed_at=COALESCE(?, completed_at),
                        activation_bundle_id=COALESCE(?, activation_bundle_id),
                        proposal_coin_id=COALESCE(?, proposal_coin_id),
                        completion_bundle_id=COALESCE(?, completion_bundle_id)
                    WHERE id=?
                    """,
                    (
                        target,
                        revision,
                        timestamp,
                        activated_at,
                        completed_at,
                        activation_bundle_id,
                        proposal_coin_id,
                        completion_bundle_id,
                        proposal_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise GovernanceQueueConflict(
                    "another proposal is already active on the governance tracker"
                ) from exc
            self._audit(
                cursor,
                proposal_id,
                actor,
                f"STATE_{target}",
                revision,
                {
                    "previousState": row["state"],
                    "activationBundleId": activation_bundle_id,
                    "proposalCoinId": proposal_coin_id,
                    "completionBundleId": completion_bundle_id,
                },
                timestamp,
            )
        return self.get(proposal_id)

    def add_signature(
        self,
        *,
        proposal_id: str,
        action_id: str,
        signer_slot: int,
        signer_public_key: str,
        message_hash: str,
        signature: str,
        actor: str,
        now: int | None = None,
    ) -> GovernanceQueueSignature:
        if signer_slot not in (0, 1, 2):
            raise GovernanceQueueConflict("administrator slot is invalid")
        timestamp = int(time.time()) if now is None else now
        with self._txn() as cursor:
            proposal = cursor.execute(
                "SELECT state, revision FROM governance_proposal_queue WHERE id=?",
                (proposal_id,),
            ).fetchone()
            if proposal is None:
                raise GovernanceQueueNotFound(proposal_id)
            if str(proposal["state"]) != "READY":
                raise GovernanceQueueConflict(
                    "only a reviewed proposal can collect publication approvals"
                )
            existing = cursor.execute(
                "SELECT * FROM governance_queue_signatures "
                "WHERE proposal_id=? AND action_id=?",
                (proposal_id, action_id),
            ).fetchone()
            if existing is not None:
                candidate = _signature_record(existing)
                if (
                    candidate.signer_slot != signer_slot
                    or candidate.signer_public_key.lower()
                    != signer_public_key.lower()
                    or candidate.message_hash.lower() != message_hash.lower()
                    or candidate.signature.lower() != signature.lower()
                ):
                    raise GovernanceQueueConflict(
                        "a different signature is already stored for this action"
                    )
                return candidate
            cursor.execute(
                "INSERT INTO governance_queue_signatures "
                "(proposal_id,action_id,signer_slot,signer_public_key,"
                "message_hash,signature,signed_by,signed_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    proposal_id,
                    action_id,
                    signer_slot,
                    signer_public_key.lower(),
                    message_hash.lower(),
                    signature.lower(),
                    actor.lower(),
                    timestamp,
                ),
            )
            self._audit(
                cursor,
                proposal_id,
                actor,
                "PUBLICATION_APPROVED",
                int(proposal["revision"]),
                {"actionId": action_id, "signerSlot": signer_slot},
                timestamp,
            )
        return self.signature(proposal_id, action_id)

    def record_execution_submission(
        self,
        *,
        proposal_id: str,
        expected_revision: int,
        execution_bundle_id: str,
        expected_output_coin_ids: tuple[str, ...],
        actor: str,
        now: int | None = None,
    ) -> GovernanceQueueRecord:
        if not execution_bundle_id or not expected_output_coin_ids:
            raise GovernanceQueueConflict(
                "execution submission requires bundle and output evidence"
            )
        timestamp = int(time.time()) if now is None else now
        output_json = _canonical_json(list(expected_output_coin_ids))
        with self._txn() as cursor:
            row = cursor.execute(
                "SELECT state,revision,execution_bundle_id,"
                "expected_output_coin_ids_json FROM governance_proposal_queue "
                "WHERE id=?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise GovernanceQueueNotFound(proposal_id)
            if str(row["state"]) != "ACTIVE":
                raise GovernanceQueueConflict(
                    "only an active proposal can record execution"
                )
            existing_bundle = row["execution_bundle_id"]
            if existing_bundle is not None:
                if (
                    str(existing_bundle).lower() != execution_bundle_id.lower()
                    or str(row["expected_output_coin_ids_json"] or "") != output_json
                ):
                    raise GovernanceQueueConflict(
                        "different execution evidence is already recorded"
                    )
                return self.get(proposal_id)
            if int(row["revision"]) != expected_revision:
                raise GovernanceQueueConflict(
                    f"stale revision {expected_revision}; current {row['revision']}"
                )
            revision = expected_revision + 1
            cursor.execute(
                "UPDATE governance_proposal_queue SET revision=?,updated_at=?,"
                "execution_bundle_id=?,expected_output_coin_ids_json=?,"
                "execution_submitted_at=? WHERE id=?",
                (
                    revision,
                    timestamp,
                    execution_bundle_id.lower(),
                    output_json,
                    timestamp,
                    proposal_id,
                ),
            )
            self._audit(
                cursor,
                proposal_id,
                actor,
                "EXECUTION_SUBMITTED",
                revision,
                {
                    "executionBundleId": execution_bundle_id.lower(),
                    "expectedOutputCoinIds": list(expected_output_coin_ids),
                },
                timestamp,
            )
        return self.get(proposal_id)

    def bind_publication_coadmin(
        self,
        *,
        proposal_id: str,
        coadmin_slot: int,
        voting_deadline: int,
        actor: str,
        now: int | None = None,
    ) -> GovernanceQueueRecord:
        if coadmin_slot not in (1, 2):
            raise GovernanceQueueConflict("publication coadministrator is invalid")
        timestamp = int(time.time()) if now is None else now
        if voting_deadline <= timestamp:
            raise GovernanceQueueConflict("publication voting deadline must be future")
        with self._txn() as cursor:
            row = cursor.execute(
                "SELECT state, revision, publication_coadmin_slot, "
                "publication_voting_deadline "
                "FROM governance_proposal_queue WHERE id=?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise GovernanceQueueNotFound(proposal_id)
            if str(row["state"]) != "READY":
                raise GovernanceQueueConflict(
                    "only a reviewed proposal can prepare publication"
                )
            existing_slot = row["publication_coadmin_slot"]
            if existing_slot is not None:
                if int(existing_slot) != coadmin_slot:
                    raise GovernanceQueueConflict(
                        "publication coadministrator is already fixed"
                    )
                if row["publication_voting_deadline"] is not None:
                    return self.get(proposal_id)
            cursor.execute(
                "UPDATE governance_proposal_queue SET "
                "publication_coadmin_slot=?, publication_voting_deadline=?, "
                "updated_at=? "
                "WHERE id=?",
                (coadmin_slot, voting_deadline, timestamp, proposal_id),
            )
            self._audit(
                cursor,
                proposal_id,
                actor,
                "PUBLICATION_PREPARED",
                int(row["revision"]),
                {
                    "coadminSlot": coadmin_slot,
                    "votingDeadline": voting_deadline,
                },
                timestamp,
            )
        return self.get(proposal_id)

    def record_sale_offer_snapshot(
        self,
        *,
        proposal_id: str,
        offer_id: str,
        offer_bech32: str,
        sale_coin_id: str,
        status: SaleOfferStatus,
        confirmed_height: int,
        spent_height: int | None,
        actor: str,
        now: int | None = None,
    ) -> GovernanceQueueRecord:
        """Persist immutable offer identity plus chain-derived lifecycle state."""
        if not offer_id.startswith("0x") or len(offer_id) != 66:
            raise GovernanceQueueConflict("sale offer id must be 32-byte hex")
        if not sale_coin_id.startswith("0x") or len(sale_coin_id) != 66:
            raise GovernanceQueueConflict("sale coin id must be 32-byte hex")
        if not offer_bech32.startswith("offer1") or len(offer_bech32) > 2_000_000:
            raise GovernanceQueueConflict("sale offer file is malformed or oversized")
        if status not in {"AVAILABLE", "PENDING", "TAKEN", "EXPIRED", "RETURNED"}:
            raise GovernanceQueueConflict("sale offer status is invalid")
        if confirmed_height <= 0 or (spent_height is not None and spent_height <= 0):
            raise GovernanceQueueConflict("sale offer chain heights are invalid")
        timestamp = int(time.time()) if now is None else now
        with self._txn() as cursor:
            row = cursor.execute(
                "SELECT kind,state,revision,sale_offer_id,sale_offer_bech32,"
                "sale_coin_id,sale_offer_status,sale_offer_confirmed_height,"
                "sale_offer_spent_height FROM governance_proposal_queue WHERE id=?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise GovernanceQueueNotFound(proposal_id)
            if str(row["kind"]) != "SGT_SALE" or str(row["state"]) not in {
                "ACTIVE",
                "EXECUTED",
            }:
                raise GovernanceQueueConflict(
                    "sale offers belong only to active or executed SGT sales"
                )
            existing_offer_id = row["sale_offer_id"]
            if existing_offer_id is not None and (
                str(existing_offer_id).lower() != offer_id.lower()
                or str(row["sale_offer_bech32"]) != offer_bech32
                or str(row["sale_coin_id"]).lower() != sale_coin_id.lower()
            ):
                raise GovernanceQueueConflict(
                    "different immutable sale offer evidence is already recorded"
                )
            if (
                existing_offer_id is not None
                and str(row["sale_offer_status"]) == status
                and int(row["sale_offer_confirmed_height"]) == confirmed_height
                and (
                    int(row["sale_offer_spent_height"])
                    if row["sale_offer_spent_height"] is not None
                    else None
                )
                == spent_height
            ):
                return self.get(proposal_id)
            revision = int(row["revision"]) + 1
            first_publication = existing_offer_id is None
            cursor.execute(
                "UPDATE governance_proposal_queue SET revision=?,updated_at=?,"
                "sale_offer_id=?,sale_offer_bech32=?,sale_coin_id=?,"
                "sale_offer_status=?,sale_offer_published_at=COALESCE("
                "sale_offer_published_at,?),sale_offer_confirmed_height=?,"
                "sale_offer_spent_height=? WHERE id=?",
                (
                    revision,
                    timestamp,
                    offer_id.lower(),
                    offer_bech32,
                    sale_coin_id.lower(),
                    status,
                    timestamp,
                    confirmed_height,
                    spent_height,
                    proposal_id,
                ),
            )
            self._audit(
                cursor,
                proposal_id,
                actor,
                "SALE_OFFER_PUBLISHED" if first_publication else "SALE_OFFER_STATUS_UPDATED",
                revision,
                {
                    "offerId": offer_id.lower(),
                    "saleCoinId": sale_coin_id.lower(),
                    "status": status,
                    "confirmedHeight": confirmed_height,
                    "spentHeight": spent_height,
                },
                timestamp,
            )
        return self.get(proposal_id)

    def signature(
        self,
        proposal_id: str,
        action_id: str,
    ) -> GovernanceQueueSignature:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM governance_queue_signatures "
                "WHERE proposal_id=? AND action_id=?",
                (proposal_id, action_id),
            ).fetchone()
        if row is None:
            raise GovernanceQueueNotFound(action_id)
        return _signature_record(row)

    def signatures(self, proposal_id: str) -> list[GovernanceQueueSignature]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM governance_queue_signatures "
                "WHERE proposal_id=? ORDER BY signer_slot, signed_at",
                (proposal_id,),
            ).fetchall()
        return [_signature_record(row) for row in rows]

    @staticmethod
    def _audit(
        cursor: sqlite3.Cursor,
        proposal_id: str,
        actor: str,
        action: str,
        revision: int,
        details: dict[str, Any],
        occurred_at: int,
    ) -> None:
        cursor.execute(
            "INSERT INTO governance_queue_audit "
            "(proposal_id,actor,action,revision,occurred_at,details_json) "
            "VALUES (?,?,?,?,?,?)",
            (
                proposal_id,
                actor.lower(),
                action,
                revision,
                occurred_at,
                _canonical_json(details),
            ),
        )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _record(row: sqlite3.Row) -> GovernanceQueueRecord:
    return GovernanceQueueRecord(
        id=str(row["id"]),
        kind=str(row["kind"]),  # type: ignore[arg-type]
        state=str(row["state"]),  # type: ignore[arg-type]
        title=str(row["title"]),
        bill=json.loads(str(row["bill_json"])),
        bill_clvm_hex=str(row["bill_clvm_hex"]),
        proposal_hash=str(row["proposal_hash"]),
        revision=int(row["revision"]),
        queue_position=int(row["queue_position"]),
        created_by=str(row["created_by"]),
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
        activated_at=(
            int(row["activated_at"]) if row["activated_at"] is not None else None
        ),
        completed_at=(
            int(row["completed_at"]) if row["completed_at"] is not None else None
        ),
        activation_bundle_id=(
            str(row["activation_bundle_id"])
            if row["activation_bundle_id"] is not None
            else None
        ),
        proposal_coin_id=(
            str(row["proposal_coin_id"])
            if row["proposal_coin_id"] is not None
            else None
        ),
        completion_bundle_id=(
            str(row["completion_bundle_id"])
            if row["completion_bundle_id"] is not None
            else None
        ),
        publication_coadmin_slot=(
            int(row["publication_coadmin_slot"])
            if row["publication_coadmin_slot"] is not None
            else None
        ),
        publication_voting_deadline=(
            int(row["publication_voting_deadline"])
            if row["publication_voting_deadline"] is not None
            else None
        ),
        execution_bundle_id=(
            str(row["execution_bundle_id"])
            if row["execution_bundle_id"] is not None
            else None
        ),
        expected_output_coin_ids=tuple(
            str(value)
            for value in json.loads(
                str(row["expected_output_coin_ids_json"] or "[]")
            )
        ),
        execution_submitted_at=(
            int(row["execution_submitted_at"])
            if row["execution_submitted_at"] is not None
            else None
        ),
        sale_offer_id=(
            str(row["sale_offer_id"]) if row["sale_offer_id"] is not None else None
        ),
        sale_offer_bech32=(
            str(row["sale_offer_bech32"])
            if row["sale_offer_bech32"] is not None
            else None
        ),
        sale_coin_id=(
            str(row["sale_coin_id"]) if row["sale_coin_id"] is not None else None
        ),
        sale_offer_status=(
            str(row["sale_offer_status"])  # type: ignore[arg-type]
            if row["sale_offer_status"] is not None
            else None
        ),
        sale_offer_published_at=(
            int(row["sale_offer_published_at"])
            if row["sale_offer_published_at"] is not None
            else None
        ),
        sale_offer_confirmed_height=(
            int(row["sale_offer_confirmed_height"])
            if row["sale_offer_confirmed_height"] is not None
            else None
        ),
        sale_offer_spent_height=(
            int(row["sale_offer_spent_height"])
            if row["sale_offer_spent_height"] is not None
            else None
        ),
    )


def _signature_record(row: sqlite3.Row) -> GovernanceQueueSignature:
    return GovernanceQueueSignature(
        proposal_id=str(row["proposal_id"]),
        action_id=str(row["action_id"]),
        signer_slot=int(row["signer_slot"]),
        signer_public_key=str(row["signer_public_key"]),
        message_hash=str(row["message_hash"]),
        signature=str(row["signature"]),
        signed_by=str(row["signed_by"]),
        signed_at=int(row["signed_at"]),
    )
