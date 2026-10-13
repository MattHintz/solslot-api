"""Durable, idempotent Stripe-to-protocol-asset delivery operations."""
from __future__ import annotations

from .generation_storage import connect_generation_sqlite

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator, Mapping


PAYMENT_VERIFIED = "PAYMENT_VERIFIED"
RECEIPT_FUNDING_PREPARED = "RECEIPT_FUNDING_PREPARED"
RECEIPT_FUNDING_SUBMITTED = "RECEIPT_FUNDING_SUBMITTED"
RECEIPT_CONFIRMED = "RECEIPT_CONFIRMED"
DELIVERY_PREPARED = "DELIVERY_PREPARED"
DELIVERY_SUBMITTED = "DELIVERY_SUBMITTED"
FINALIZED = "FINALIZED"
EXTERNAL_SETTLEMENT_PENDING = "EXTERNAL_SETTLEMENT_PENDING"
MANUAL_REVIEW = "MANUAL_REVIEW"
PAYMENT_RAIL_STRIPE = "stripe"
PAYMENT_RAIL_BASE_USDC = "base_usdc"
PAYMENT_RAILS = frozenset({PAYMENT_RAIL_STRIPE, PAYMENT_RAIL_BASE_USDC})
DELIVERY_SMARTDEED = "smartdeed"
DELIVERY_SGT = "sgt"
DELIVERY_KINDS = frozenset({DELIVERY_SMARTDEED, DELIVERY_SGT})


class StripeDeliveryNotFound(LookupError):
    pass


class StripeDeliveryConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class StripeDeliveryOperation:
    purchase_id: str
    external_payment_id: str
    payment_rail: str
    delivery_kind: str
    evidence: dict[str, Any]
    receipt_hash: str
    state: str
    receipt_funding_input_coin_id: str | None
    receipt_funding_bundle: dict[str, Any] | None
    receipt_funding_exact_bundle: dict[str, Any] | None
    receipt_funding_bundle_id: str | None
    receipt_coin_id: str | None
    receipt_puzzle_hash: str | None
    receipt_funding_fee_mojos: int | None
    receipt_funding_mempool_observed_at: str | None
    delivery_bundle: dict[str, Any] | None
    delivery_exact_bundle: dict[str, Any] | None
    delivery_bundle_id: str | None
    expected_delivery_output_coin_id: str | None
    expected_delivery_output_coin_ids: tuple[str, ...]
    expected_treasury_output_coin_id: str | None
    expected_treasury_output_coin_ids: tuple[str, ...]
    fee_mojos: int | None
    mempool_observed_at: str | None
    confirmation_height: int | None
    external_settlement_evidence: dict[str, Any] | None
    settlement_authorization_id: str | None
    settlement_authorization: dict[str, Any] | None
    signer_indices: tuple[int, ...]
    attempt_count: int
    last_error: str | None
    created_at: int
    updated_at: int

    @property
    def expected_deed_output_coin_id(self) -> str | None:
        return (
            self.expected_delivery_output_coin_id
            if self.delivery_kind == DELIVERY_SMARTDEED
            else None
        )

    @property
    def expected_deed_output_coin_ids(self) -> tuple[str, ...]:
        return (
            self.expected_delivery_output_coin_ids
            if self.delivery_kind == DELIVERY_SMARTDEED
            else ()
        )

    @property
    def expected_sgt_output_coin_id(self) -> str | None:
        return (
            self.expected_delivery_output_coin_id
            if self.delivery_kind == DELIVERY_SGT
            else None
        )


class StripeDeliveryStore:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS stripe_delivery_operations (
                    purchase_id TEXT PRIMARY KEY,
                    external_payment_id TEXT NOT NULL UNIQUE,
                    payment_rail TEXT NOT NULL DEFAULT 'stripe',
                    delivery_kind TEXT NOT NULL DEFAULT 'smartdeed',
                    evidence_json TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    receipt_funding_input_coin_id TEXT UNIQUE,
                    receipt_funding_bundle_json TEXT,
                    receipt_funding_exact_bundle_json TEXT,
                    receipt_funding_bundle_id TEXT UNIQUE,
                    receipt_coin_id TEXT UNIQUE,
                    receipt_puzzle_hash TEXT,
                    receipt_funding_fee_mojos INTEGER,
                    receipt_funding_mempool_observed_at TEXT,
                    delivery_bundle_json TEXT,
                    delivery_exact_bundle_json TEXT,
                    delivery_bundle_id TEXT UNIQUE,
                    expected_deed_output_coin_id TEXT UNIQUE,
                    expected_delivery_output_coin_id TEXT UNIQUE,
                    expected_delivery_output_coin_ids_json TEXT NOT NULL DEFAULT '[]',
                    expected_treasury_output_coin_id TEXT,
                    expected_treasury_output_coin_ids_json TEXT NOT NULL DEFAULT '[]',
                    fee_mojos INTEGER,
                    mempool_observed_at TEXT,
                    confirmation_height INTEGER,
                    external_settlement_evidence_json TEXT,
                    settlement_authorization_id TEXT UNIQUE,
                    settlement_authorization_json TEXT,
                    signer_indices_json TEXT NOT NULL DEFAULT '[]',
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    lease_owner TEXT,
                    lease_expires_at INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS stripe_delivery_state
                    ON stripe_delivery_operations(state, updated_at);
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(stripe_delivery_operations)"
                ).fetchall()
            }
            if "delivery_kind" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN delivery_kind TEXT NOT NULL DEFAULT 'smartdeed'"
                )
            if "external_payment_id" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN external_payment_id TEXT"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "stripe_delivery_external_payment_once ON "
                    "stripe_delivery_operations(external_payment_id) "
                    "WHERE external_payment_id IS NOT NULL"
                )
            if "payment_rail" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN payment_rail TEXT NOT NULL DEFAULT 'stripe'"
                )
            if "external_settlement_evidence_json" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN external_settlement_evidence_json TEXT"
                )
            if "settlement_authorization_id" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN settlement_authorization_id TEXT"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "stripe_delivery_authorization_once ON "
                    "stripe_delivery_operations(settlement_authorization_id) "
                    "WHERE settlement_authorization_id IS NOT NULL"
                )
            if "settlement_authorization_json" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN settlement_authorization_json TEXT"
                )
            if "expected_delivery_output_coin_id" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN expected_delivery_output_coin_id TEXT"
                )
                connection.execute(
                    "UPDATE stripe_delivery_operations "
                    "SET expected_delivery_output_coin_id="
                    "expected_deed_output_coin_id "
                    "WHERE expected_deed_output_coin_id IS NOT NULL"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "stripe_delivery_output_once ON "
                    "stripe_delivery_operations(expected_delivery_output_coin_id) "
                    "WHERE expected_delivery_output_coin_id IS NOT NULL"
                )
            if "receipt_funding_exact_bundle_json" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN receipt_funding_exact_bundle_json TEXT"
                )
            if "delivery_exact_bundle_json" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN delivery_exact_bundle_json TEXT"
                )
            if "expected_delivery_output_coin_ids_json" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN expected_delivery_output_coin_ids_json "
                    "TEXT NOT NULL DEFAULT '[]'"
                )
                for row in connection.execute(
                    "SELECT purchase_id, expected_delivery_output_coin_id "
                    "FROM stripe_delivery_operations "
                    "WHERE expected_delivery_output_coin_id IS NOT NULL"
                ).fetchall():
                    connection.execute(
                        "UPDATE stripe_delivery_operations "
                        "SET expected_delivery_output_coin_ids_json=? "
                        "WHERE purchase_id=?",
                        (json.dumps([row[1]]), row[0]),
                    )
            if "expected_treasury_output_coin_ids_json" not in columns:
                connection.execute(
                    "ALTER TABLE stripe_delivery_operations "
                    "ADD COLUMN expected_treasury_output_coin_ids_json "
                    "TEXT NOT NULL DEFAULT '[]'"
                )
                for row in connection.execute(
                    "SELECT purchase_id, expected_treasury_output_coin_id "
                    "FROM stripe_delivery_operations "
                    "WHERE expected_treasury_output_coin_id IS NOT NULL"
                ).fetchall():
                    connection.execute(
                        "UPDATE stripe_delivery_operations "
                        "SET expected_treasury_output_coin_ids_json=? "
                        "WHERE purchase_id=?",
                        (json.dumps([row[1]]), row[0]),
                    )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = connect_generation_sqlite(
            self.path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        try:
            yield connection
        finally:
            connection.close()

    def queue(
        self,
        *,
        purchase_id: str,
        evidence: Mapping[str, Any],
        receipt_hash: str,
        payment_rail: str = PAYMENT_RAIL_STRIPE,
        delivery_kind: str = DELIVERY_SMARTDEED,
        now: int | None = None,
    ) -> StripeDeliveryOperation:
        if payment_rail not in PAYMENT_RAILS:
            raise ValueError("payment rail must be stripe or base_usdc")
        if delivery_kind not in DELIVERY_KINDS:
            raise ValueError("delivery kind must be smartdeed or sgt")
        timestamp = int(time.time()) if now is None else now
        evidence_json = _canonical_json(evidence)
        external_payment_id = _external_payment_id(payment_rail, evidence)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is not None:
                existing = _record(row)
                if (
                    _canonical_json(existing.evidence) != evidence_json
                    or existing.external_payment_id != external_payment_id
                    or existing.receipt_hash != receipt_hash
                    or existing.payment_rail != payment_rail
                    or existing.delivery_kind != delivery_kind
                ):
                    connection.execute("ROLLBACK")
                    raise StripeDeliveryConflict(
                        "Stripe purchase is already bound to different settlement evidence"
                    )
                connection.execute("COMMIT")
                return existing
            try:
                connection.execute(
                    """
                    INSERT INTO stripe_delivery_operations(
                        purchase_id,external_payment_id,payment_rail,delivery_kind,
                        evidence_json,receipt_hash,state,
                        created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        purchase_id,
                        external_payment_id,
                        payment_rail,
                        delivery_kind,
                        evidence_json,
                        receipt_hash,
                        PAYMENT_VERIFIED,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise StripeDeliveryConflict(
                    "Stripe settlement receipt is already bound to another purchase"
                ) from exc
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def get(self, purchase_id: str) -> StripeDeliveryOperation:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise StripeDeliveryNotFound("Stripe delivery operation was not found")
        return _record(row)

    def get_by_external_payment_id(
        self,
        external_payment_id: str,
    ) -> StripeDeliveryOperation:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations "
                "WHERE external_payment_id=?",
                (external_payment_id.lower(),),
            ).fetchone()
        if row is None:
            raise StripeDeliveryNotFound("external delivery operation was not found")
        return _record(row)

    def get_by_settlement_authorization_id(
        self,
        authorization_id: str,
    ) -> StripeDeliveryOperation:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations "
                "WHERE settlement_authorization_id=?",
                (authorization_id.lower(),),
            ).fetchone()
        if row is None:
            raise StripeDeliveryNotFound("settlement authorization was not found")
        return _record(row)

    def pending_exact_fee_coin_ids(self) -> set[str]:
        """Return fee coins sealed in exact executions not yet finalized."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT receipt_funding_exact_bundle_json,
                       delivery_exact_bundle_json
                FROM stripe_delivery_operations
                WHERE state != ?
                  AND (receipt_funding_exact_bundle_json IS NOT NULL
                       OR delivery_exact_bundle_json IS NOT NULL)
                """,
                (FINALIZED,),
            ).fetchall()
        reserved: set[str] = set()
        for row in rows:
            for field in (
                "receipt_funding_exact_bundle_json",
                "delivery_exact_bundle_json",
            ):
                raw = row[field]
                if raw is None:
                    continue
                try:
                    exact = json.loads(str(raw))
                    fee_coin_id = _fee_coin_id(str(exact["feeCoinId"]))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise StripeDeliveryConflict(
                        "persisted exact execution has an invalid fee coin"
                    ) from exc
                reserved.add(fee_coin_id)
        return reserved

    def list_pending_external_settlements(
        self,
        *,
        limit: int = 100,
    ) -> list[StripeDeliveryOperation]:
        if limit < 1 or limit > 100:
            raise ValueError("pending settlement limit must be in 1..100")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM stripe_delivery_operations
                WHERE payment_rail = ?
                  AND state = ?
                  AND settlement_authorization_json IS NOT NULL
                  AND external_settlement_evidence_json IS NULL
                ORDER BY updated_at ASC, purchase_id ASC
                LIMIT ?
                """,
                (PAYMENT_RAIL_BASE_USDC, EXTERNAL_SETTLEMENT_PENDING, limit),
            ).fetchall()
        return [_record(row) for row in rows]

    def claim_next(
        self,
        *,
        owner: str,
        lease_seconds: int,
        now: int | None = None,
    ) -> StripeDeliveryOperation | None:
        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM stripe_delivery_operations
                WHERE state IN (?,?,?,?,?,?,?)
                  AND (lease_expires_at IS NULL OR lease_expires_at < ?)
                ORDER BY updated_at, purchase_id
                LIMIT 1
                """,
                (
                    PAYMENT_VERIFIED,
                    RECEIPT_FUNDING_PREPARED,
                    RECEIPT_FUNDING_SUBMITTED,
                    RECEIPT_CONFIRMED,
                    DELIVERY_PREPARED,
                    DELIVERY_SUBMITTED,
                    EXTERNAL_SETTLEMENT_PENDING,
                    timestamp,
                ),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            connection.execute(
                """
                UPDATE stripe_delivery_operations
                SET lease_owner=?,lease_expires_at=?,attempt_count=attempt_count+1,
                    updated_at=?
                WHERE purchase_id=?
                """,
                (owner, timestamp + lease_seconds, timestamp, row["purchase_id"]),
            )
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (row["purchase_id"],),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def claim(
        self,
        purchase_id: str,
        *,
        owner: str,
        lease_seconds: int,
        now: int | None = None,
    ) -> StripeDeliveryOperation | None:
        """Lease one exact operation across API processes before advancing it."""

        timestamp = int(time.time()) if now is None else now
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise StripeDeliveryNotFound(
                    "Stripe delivery operation was not found"
                )
            if str(row["state"]) in {FINALIZED, MANUAL_REVIEW}:
                connection.execute("COMMIT")
                return _record(row)
            lease_owner = row["lease_owner"]
            lease_expires_at = row["lease_expires_at"]
            if (
                lease_owner is not None
                and lease_owner != owner
                and lease_expires_at is not None
                and int(lease_expires_at) >= timestamp
            ):
                connection.execute("COMMIT")
                return None
            connection.execute(
                """
                UPDATE stripe_delivery_operations
                SET lease_owner=?,lease_expires_at=?,attempt_count=attempt_count+1,
                    updated_at=?
                WHERE purchase_id=?
                """,
                (owner, timestamp + lease_seconds, timestamp, purchase_id),
            )
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def record_receipt_funding(
        self,
        purchase_id: str,
        *,
        bundle_id: str,
        receipt_coin_id: str,
        receipt_puzzle_hash: str,
        fee_mojos: int | None,
        mempool_observed_at: str,
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={RECEIPT_FUNDING_PREPARED, RECEIPT_FUNDING_SUBMITTED},
            state=RECEIPT_FUNDING_SUBMITTED,
            values={
                "receipt_funding_bundle_id": bundle_id,
                "receipt_coin_id": receipt_coin_id,
                "receipt_puzzle_hash": receipt_puzzle_hash,
                "receipt_funding_fee_mojos": fee_mojos,
                "receipt_funding_mempool_observed_at": mempool_observed_at,
            },
        )

    def bind_receipt_exact_bundle(
        self,
        purchase_id: str,
        *,
        exact_bundle: Mapping[str, Any],
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={RECEIPT_FUNDING_PREPARED},
            state=RECEIPT_FUNDING_PREPARED,
            values={
                "receipt_funding_exact_bundle_json": _canonical_json(exact_bundle),
            },
            release_lease=False,
        )

    def record_receipt_prepared(
        self,
        purchase_id: str,
        *,
        input_coin_id: str,
        protocol_bundle: Mapping[str, Any],
        receipt_coin_id: str,
        receipt_puzzle_hash: str,
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={PAYMENT_VERIFIED, RECEIPT_FUNDING_PREPARED},
            state=RECEIPT_FUNDING_PREPARED,
            values={
                "receipt_funding_input_coin_id": input_coin_id,
                "receipt_funding_bundle_json": _canonical_json(protocol_bundle),
                "receipt_coin_id": receipt_coin_id,
                "receipt_puzzle_hash": receipt_puzzle_hash,
            },
        )

    def record_receipt_confirmed(
        self,
        purchase_id: str,
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={
                RECEIPT_FUNDING_PREPARED,
                RECEIPT_FUNDING_SUBMITTED,
                RECEIPT_CONFIRMED,
            },
            state=RECEIPT_CONFIRMED,
            values={},
        )

    def record_delivery_submission(
        self,
        purchase_id: str,
        *,
        bundle_id: str,
        delivery_output_coin_id: str | None = None,
        delivery_output_coin_ids: tuple[str, ...] | None = None,
        treasury_output_coin_id: str,
        treasury_output_coin_ids: tuple[str, ...] | None = None,
        signer_indices: tuple[int, ...],
        fee_mojos: int | None,
        mempool_observed_at: str,
        deed_output_coin_id: str | None = None,
    ) -> StripeDeliveryOperation:
        output_coin_ids = _delivery_output_ids(
            delivery_output_coin_id,
            delivery_output_coin_ids,
            deed_output_coin_id,
        )
        treasury_coin_ids = _output_ids(
            treasury_output_coin_id,
            treasury_output_coin_ids,
            "treasury",
        )
        return self._transition(
            purchase_id,
            allowed={DELIVERY_PREPARED, DELIVERY_SUBMITTED},
            state=DELIVERY_SUBMITTED,
            values={
                "delivery_bundle_id": bundle_id,
                "expected_delivery_output_coin_id": output_coin_ids[0],
                "expected_delivery_output_coin_ids_json": json.dumps(
                    list(output_coin_ids)
                ),
                "expected_treasury_output_coin_id": treasury_coin_ids[0],
                "expected_treasury_output_coin_ids_json": json.dumps(
                    list(treasury_coin_ids)
                ),
                "signer_indices_json": json.dumps(list(signer_indices)),
                "fee_mojos": fee_mojos,
                "mempool_observed_at": mempool_observed_at,
            },
        )

    def bind_delivery_exact_bundle(
        self,
        purchase_id: str,
        *,
        exact_bundle: Mapping[str, Any],
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={DELIVERY_PREPARED},
            state=DELIVERY_PREPARED,
            values={
                "delivery_exact_bundle_json": _canonical_json(exact_bundle),
            },
            release_lease=False,
        )

    def record_delivery_prepared(
        self,
        purchase_id: str,
        *,
        protocol_bundle: Mapping[str, Any],
        delivery_output_coin_id: str | None = None,
        delivery_output_coin_ids: tuple[str, ...] | None = None,
        treasury_output_coin_id: str,
        treasury_output_coin_ids: tuple[str, ...] | None = None,
        signer_indices: tuple[int, ...],
        deed_output_coin_id: str | None = None,
    ) -> StripeDeliveryOperation:
        output_coin_ids = _delivery_output_ids(
            delivery_output_coin_id,
            delivery_output_coin_ids,
            deed_output_coin_id,
        )
        treasury_coin_ids = _output_ids(
            treasury_output_coin_id,
            treasury_output_coin_ids,
            "treasury",
        )
        return self._transition(
            purchase_id,
            allowed={RECEIPT_CONFIRMED, DELIVERY_PREPARED},
            state=DELIVERY_PREPARED,
            values={
                "delivery_bundle_json": _canonical_json(protocol_bundle),
                "expected_delivery_output_coin_id": output_coin_ids[0],
                "expected_delivery_output_coin_ids_json": json.dumps(
                    list(output_coin_ids)
                ),
                "expected_treasury_output_coin_id": treasury_coin_ids[0],
                "expected_treasury_output_coin_ids_json": json.dumps(
                    list(treasury_coin_ids)
                ),
                "signer_indices_json": json.dumps(list(signer_indices)),
            },
        )

    def record_finalized(
        self,
        purchase_id: str,
        *,
        confirmation_height: int,
    ) -> StripeDeliveryOperation:
        if self.get(purchase_id).payment_rail != PAYMENT_RAIL_STRIPE:
            raise StripeDeliveryConflict(
                "Base delivery requires confirmed external settlement"
            )
        return self._transition(
            purchase_id,
            allowed={DELIVERY_PREPARED, DELIVERY_SUBMITTED, FINALIZED},
            state=FINALIZED,
            values={"confirmation_height": confirmation_height},
        )

    def record_delivery_confirmed(
        self,
        purchase_id: str,
        *,
        confirmation_height: int,
    ) -> StripeDeliveryOperation:
        operation = self.get(purchase_id)
        if operation.payment_rail == PAYMENT_RAIL_STRIPE:
            return self.record_finalized(
                purchase_id,
                confirmation_height=confirmation_height,
            )
        return self._transition(
            purchase_id,
            allowed={
                DELIVERY_PREPARED,
                DELIVERY_SUBMITTED,
                EXTERNAL_SETTLEMENT_PENDING,
            },
            state=EXTERNAL_SETTLEMENT_PENDING,
            values={"confirmation_height": confirmation_height},
        )

    def record_external_settlement_finalized(
        self,
        purchase_id: str,
        *,
        evidence: Mapping[str, Any],
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={EXTERNAL_SETTLEMENT_PENDING, FINALIZED},
            state=FINALIZED,
            values={
                "external_settlement_evidence_json": _canonical_json(evidence),
            },
        )

    def record_external_settlement_authorization(
        self,
        purchase_id: str,
        *,
        authorization_id: str,
        authorization: Mapping[str, Any],
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={EXTERNAL_SETTLEMENT_PENDING},
            state=EXTERNAL_SETTLEMENT_PENDING,
            values={
                "settlement_authorization_id": authorization_id.lower(),
                "settlement_authorization_json": _canonical_json(authorization),
            },
        )

    def record_manual_review(
        self,
        purchase_id: str,
        *,
        error: str,
    ) -> StripeDeliveryOperation:
        return self._transition(
            purchase_id,
            allowed={
                PAYMENT_VERIFIED,
                RECEIPT_FUNDING_PREPARED,
                RECEIPT_FUNDING_SUBMITTED,
                RECEIPT_CONFIRMED,
                DELIVERY_PREPARED,
                DELIVERY_SUBMITTED,
                EXTERNAL_SETTLEMENT_PENDING,
                MANUAL_REVIEW,
            },
            state=MANUAL_REVIEW,
            values={"last_error": error[:1000]},
        )

    def record_error(
        self,
        purchase_id: str,
        error: str,
    ) -> StripeDeliveryOperation:
        message = error[:1000]
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE stripe_delivery_operations
                SET last_error=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=?
                WHERE purchase_id=?
                """,
                (message, int(time.time()), purchase_id),
            )
        return self.get(purchase_id)

    def release_lease(self, purchase_id: str) -> StripeDeliveryOperation:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE stripe_delivery_operations
                SET lease_owner=NULL,lease_expires_at=NULL,updated_at=?
                WHERE purchase_id=?
                """,
                (int(time.time()), purchase_id),
            )
        return self.get(purchase_id)

    def _transition(
        self,
        purchase_id: str,
        *,
        allowed: set[str],
        state: str,
        values: Mapping[str, Any],
        release_lease: bool = True,
    ) -> StripeDeliveryOperation:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise StripeDeliveryNotFound(
                    "Stripe delivery operation was not found"
                )
            if str(row["state"]) not in allowed:
                connection.execute("ROLLBACK")
                raise StripeDeliveryConflict(
                    f"Stripe delivery cannot move from {row['state']} to {state}"
                )
            for field, value in values.items():
                existing = row[field]
                if (
                    existing is not None
                    and not (
                        field
                        in {
                            "signer_indices_json",
                            "expected_delivery_output_coin_ids_json",
                            "expected_treasury_output_coin_ids_json",
                        }
                        and existing == "[]"
                    )
                    and existing != value
                ):
                    connection.execute("ROLLBACK")
                    raise StripeDeliveryConflict(
                        f"Stripe delivery {field} is already bound"
                    )
            assignments = ["state=?", "updated_at=?"]
            if release_lease:
                assignments.extend(["lease_owner=NULL", "lease_expires_at=NULL"])
            if "last_error" not in values:
                assignments.append("last_error=NULL")
            params: list[Any] = [state, int(time.time())]
            for field, value in values.items():
                assignments.append(f"{field}=?")
                params.append(value)
            params.append(purchase_id)
            connection.execute(
                "UPDATE stripe_delivery_operations SET "
                + ",".join(assignments)
                + " WHERE purchase_id=?",
                tuple(params),
            )
            row = connection.execute(
                "SELECT * FROM stripe_delivery_operations WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

def _record(row: sqlite3.Row) -> StripeDeliveryOperation:
    return StripeDeliveryOperation(
        purchase_id=str(row["purchase_id"]),
        external_payment_id=str(row["external_payment_id"]),
        payment_rail=str(row["payment_rail"]),
        delivery_kind=str(row["delivery_kind"]),
        evidence=json.loads(str(row["evidence_json"])),
        receipt_hash=str(row["receipt_hash"]),
        state=str(row["state"]),
        receipt_funding_input_coin_id=row["receipt_funding_input_coin_id"],
        receipt_funding_bundle=(
            json.loads(str(row["receipt_funding_bundle_json"]))
            if row["receipt_funding_bundle_json"] is not None
            else None
        ),
        receipt_funding_exact_bundle=(
            json.loads(str(row["receipt_funding_exact_bundle_json"]))
            if row["receipt_funding_exact_bundle_json"] is not None
            else None
        ),
        receipt_funding_bundle_id=row["receipt_funding_bundle_id"],
        receipt_coin_id=row["receipt_coin_id"],
        receipt_puzzle_hash=row["receipt_puzzle_hash"],
        receipt_funding_fee_mojos=(
            int(row["receipt_funding_fee_mojos"])
            if row["receipt_funding_fee_mojos"] is not None
            else None
        ),
        receipt_funding_mempool_observed_at=row[
            "receipt_funding_mempool_observed_at"
        ],
        delivery_bundle=(
            json.loads(str(row["delivery_bundle_json"]))
            if row["delivery_bundle_json"] is not None
            else None
        ),
        delivery_exact_bundle=(
            json.loads(str(row["delivery_exact_bundle_json"]))
            if row["delivery_exact_bundle_json"] is not None
            else None
        ),
        delivery_bundle_id=row["delivery_bundle_id"],
        expected_delivery_output_coin_id=row[
            "expected_delivery_output_coin_id"
        ],
        expected_delivery_output_coin_ids=tuple(
            str(value)
            for value in json.loads(
                str(row["expected_delivery_output_coin_ids_json"])
            )
        ),
        expected_treasury_output_coin_id=row["expected_treasury_output_coin_id"],
        expected_treasury_output_coin_ids=tuple(
            str(value)
            for value in json.loads(
                str(row["expected_treasury_output_coin_ids_json"])
            )
        ),
        fee_mojos=(int(row["fee_mojos"]) if row["fee_mojos"] is not None else None),
        mempool_observed_at=row["mempool_observed_at"],
        confirmation_height=(
            int(row["confirmation_height"])
            if row["confirmation_height"] is not None
            else None
        ),
        external_settlement_evidence=(
            json.loads(str(row["external_settlement_evidence_json"]))
            if row["external_settlement_evidence_json"] is not None
            else None
        ),
        settlement_authorization_id=row["settlement_authorization_id"],
        settlement_authorization=(
            json.loads(str(row["settlement_authorization_json"]))
            if row["settlement_authorization_json"] is not None
            else None
        ),
        signer_indices=tuple(
            int(value) for value in json.loads(str(row["signer_indices_json"]))
        ),
        attempt_count=int(row["attempt_count"]),
        last_error=row["last_error"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _delivery_output_ids(
    delivery_output_coin_id: str | None,
    delivery_output_coin_ids: tuple[str, ...] | None,
    deed_output_coin_id: str | None,
) -> tuple[str, ...]:
    values = {
        value
        for value in (delivery_output_coin_id, deed_output_coin_id)
        if value is not None
    }
    if delivery_output_coin_ids is not None:
        if values and values != {delivery_output_coin_ids[0]}:
            raise ValueError("singular delivery output differs from its batch")
        return _output_ids(None, delivery_output_coin_ids, "delivery")
    if len(values) != 1:
        raise ValueError("exactly one delivery output coin ID is required")
    return _output_ids(values.pop(), None, "delivery")


def _output_ids(
    singular: str | None,
    plural: tuple[str, ...] | None,
    label: str,
) -> tuple[str, ...]:
    values = tuple(plural or (() if singular is None else (singular,)))
    if not values or len(values) > 100:
        raise ValueError(f"{label} output manifest must contain 1..100 coin IDs")
    normalized = tuple(value.lower() for value in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} output manifest contains duplicate coin IDs")
    if singular is not None and normalized[0] != singular.lower():
        raise ValueError(f"{label} output manifest changes its primary coin ID")
    return normalized


def _external_payment_id(
    payment_rail: str,
    evidence: Mapping[str, Any],
) -> str:
    field = (
        "paymentIntentId"
        if payment_rail == PAYMENT_RAIL_STRIPE
        else "globalPaymentId"
    )
    value = evidence.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    return value.lower()


def _fee_coin_id(value: str) -> str:
    normalized = value.lower().removeprefix("0x")
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("fee coin ID is not hex") from exc
    if len(raw) != 32:
        raise ValueError("fee coin ID is not bytes32")
    return "0x" + normalized


_stores: dict[str, StripeDeliveryStore] = {}


def get_stripe_delivery_store(path: str) -> StripeDeliveryStore:
    store = _stores.get(path)
    if store is None:
        store = StripeDeliveryStore(path)
        _stores[path] = store
    return store


__all__ = [
    "DELIVERY_SUBMITTED",
    "DELIVERY_PREPARED",
    "DELIVERY_KINDS",
    "DELIVERY_SGT",
    "DELIVERY_SMARTDEED",
    "EXTERNAL_SETTLEMENT_PENDING",
    "FINALIZED",
    "MANUAL_REVIEW",
    "PAYMENT_VERIFIED",
    "PAYMENT_RAIL_BASE_USDC",
    "PAYMENT_RAIL_STRIPE",
    "PAYMENT_RAILS",
    "RECEIPT_FUNDING_PREPARED",
    "RECEIPT_CONFIRMED",
    "RECEIPT_FUNDING_SUBMITTED",
    "StripeDeliveryConflict",
    "StripeDeliveryNotFound",
    "StripeDeliveryOperation",
    "StripeDeliveryStore",
    "get_stripe_delivery_store",
]
