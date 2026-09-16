"""Persistent, idempotent operation ledger for customer Sols swaps."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
import sqlite3
from threading import RLock
from time import time
from typing import Any, Iterator, Mapping

from .sols_swap_execution import hx, validate_execution


@dataclass(frozen=True)
class StoredSolsSwap:
    operation_hash: str
    direction: str
    vault_launcher_id: str
    deed_launcher_id: str
    status: str
    quote_expires_at: int
    pool_input_coin_id: str
    expected_pool_output_coin_id: str
    destination_puzzle_hash: str
    transaction_id: str | None
    fee_mojos: str | None
    fee_target_seconds: int | None
    submission_provider: str | None
    mempool_observed_at: str | None
    created_at: float
    updated_at: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class SolsSwapStore:
    """SQLite-WAL store sharing the Admin Desk database safely."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = RLock()
        if path != ":memory:":
            Path(path).expanduser().resolve().parent.mkdir(
                parents=True,
                exist_ok=True,
            )
        self._memory: sqlite3.Connection | None = None
        if path == ":memory:":
            self._memory = sqlite3.connect(
                ":memory:",
                check_same_thread=False,
                isolation_level=None,
            )
            self._configure(self._memory)
        self._migrate()

    @staticmethod
    def _configure(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA synchronous=FULL")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._memory is not None:
            yield self._memory
            return
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
        )
        self._configure(connection)
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()

    def _migrate(self) -> None:
        with self._lock, self._connect() as connection:
            if self._memory is None:
                connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sols_swap_operations (
                    operation_hash TEXT PRIMARY KEY,
                    direction TEXT NOT NULL
                        CHECK(direction IN ('SOLS_TO_DEED', 'DEED_TO_SOLS')),
                    vault_launcher_id TEXT NOT NULL,
                    deed_launcher_id TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN (
                            'PREPARED', 'SUBMITTED', 'CONFIRMED', 'FAILED'
                        )),
                    quote_expires_at INTEGER NOT NULL,
                    pool_input_coin_id TEXT NOT NULL,
                    expected_pool_output_coin_id TEXT NOT NULL,
                    destination_puzzle_hash TEXT NOT NULL DEFAULT '',
                    transaction_id TEXT,
                    fee_mojos TEXT,
                    fee_target_seconds INTEGER,
                    submission_provider TEXT,
                    mempool_observed_at TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(sols_swap_operations)"
                ).fetchall()
            }
            if "destination_puzzle_hash" not in columns:
                connection.execute(
                    """
                    ALTER TABLE sols_swap_operations
                    ADD COLUMN destination_puzzle_hash TEXT NOT NULL DEFAULT ''
                    """
                )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_sols_swap_vault_updated
                ON sols_swap_operations(vault_launcher_id, updated_at DESC)
                """
            )
            connection.execute("""
                CREATE TABLE IF NOT EXISTS sols_swap_executions (
                    operation_hash TEXT PRIMARY KEY REFERENCES sols_swap_operations(operation_hash),
                    execution_json TEXT NOT NULL,
                    execution_sha256 TEXT NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS sols_swap_input_reservations (
                    coin_id TEXT PRIMARY KEY,
                    operation_hash TEXT NOT NULL REFERENCES sols_swap_executions(operation_hash)
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS sols_swap_funding_reviews (
                    operation_hash TEXT PRIMARY KEY REFERENCES sols_swap_operations(operation_hash),
                    vault_launcher_id TEXT NOT NULL,
                    fee_coin_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    reservation_json TEXT NOT NULL,
                    reservation_sha256 TEXT NOT NULL
                )
            """)

    @staticmethod
    def _expire_funding(connection) -> None:
        # Only private, unsealed fee signatures may expire. An execution has
        # crossed the dispatch boundary and retains its input claims forever
        # until the existing canonical confirmation proof releases them.
        connection.execute("""DELETE FROM sols_swap_funding_reviews
            WHERE expires_at <= ? AND NOT EXISTS (
                SELECT 1 FROM sols_swap_executions e
                WHERE e.operation_hash=sols_swap_funding_reviews.operation_hash)""", (time(),))

    def supersede_unsealed_funding(self, operation_hash: str, vault_launcher_id: str) -> None:
        """An authenticated new quote replaces only private, undispatched holds."""
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                                     (operation_hash,)).fetchone()
            if (row is None or row["vault_launcher_id"] != vault_launcher_id
                    or row["status"] != "PREPARED" or row["transaction_id"] is not None
                    or row["quote_expires_at"] <= time()):
                raise ValueError("replacement funding requires a current prepared operation")
            connection.execute("""DELETE FROM sols_swap_funding_reviews
                WHERE vault_launcher_id=? AND operation_hash<>? AND NOT EXISTS (
                    SELECT 1 FROM sols_swap_executions e
                    WHERE e.operation_hash=sols_swap_funding_reviews.operation_hash)""",
                (vault_launcher_id, operation_hash))

    def reserve_funding(self, operation_hash: str, payload: Mapping[str, Any]) -> None:
        from .sols_swap_funding import canonical, digest, validate_private_hold
        bundle = validate_private_hold(payload)
        review = payload["review"]
        encoded = canonical(payload)
        with self._transaction() as connection:
            self._expire_funding(connection)
            row = connection.execute("SELECT * FROM sols_swap_operations WHERE operation_hash=?", (operation_hash,)).fetchone()
            if (row is None or row["status"] != "PREPARED" or row["transaction_id"] is not None
                    or review["operationHash"] != operation_hash
                    or review["binding"]["vaultLauncherId"] != row["vault_launcher_id"]
                    or review["quoteExpiresAt"] != row["quote_expires_at"] or review["quoteExpiresAt"] <= time()):
                raise ValueError("swap funding does not match a current prepared operation")
            existing = connection.execute("SELECT * FROM sols_swap_funding_reviews WHERE operation_hash=?", (operation_hash,)).fetchone()
            if existing is not None:
                if existing["reservation_json"] != encoded or existing["reservation_sha256"] != digest(payload):
                    raise ValueError("swap already has a different exact funding review")
                return
            fee_id = "0x" + bundle.coin_spends[0].coin.name().hex()
            conflict = connection.execute("""SELECT 1 FROM sols_swap_funding_reviews f
                WHERE (f.fee_coin_id=? OR f.vault_launcher_id=?) AND NOT EXISTS
                (SELECT 1 FROM sols_swap_executions e WHERE e.operation_hash=f.operation_hash)""",
                (fee_id, row["vault_launcher_id"])).fetchone()
            if conflict or connection.execute("SELECT 1 FROM sols_swap_input_reservations WHERE coin_id=?", (fee_id,)).fetchone():
                raise ValueError("funding coin or vault already has an active reservation")
            connection.execute("INSERT INTO sols_swap_funding_reviews VALUES (?, ?, ?, ?, ?, ?)",
                (operation_hash, row["vault_launcher_id"], fee_id, review["quoteExpiresAt"], encoded, digest(payload)))

    def funding(self, operation_hash: str) -> dict[str, Any] | None:
        from .sols_swap_funding import digest, validate_private_hold
        with self._transaction() as connection:
            self._expire_funding(connection)
            row = connection.execute("SELECT * FROM sols_swap_funding_reviews WHERE operation_hash=?", (operation_hash,)).fetchone()
        if row is None:
            return None
        payload = json.loads(row["reservation_json"])
        if (digest(payload) != row["reservation_sha256"]
                or payload["review"]["operationHash"] != operation_hash
                or payload["review"]["binding"]["vaultLauncherId"] != row["vault_launcher_id"]
                or payload["review"]["feeCoinId"] != row["fee_coin_id"]
                or payload["review"]["quoteExpiresAt"] != row["expires_at"]):
            raise ValueError("private swap funding record changed")
        validate_private_hold(payload)
        return payload

    def reserve_execution(self, operation_hash: str, execution: Mapping[str, Any], *, funding_reservation_hash: str | None = None) -> None:
        """Seal a signed funded transaction and claim all its inputs atomically."""
        encoded = json.dumps(dict(execution), sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self._transaction() as connection:
            row = connection.execute("SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                                     (operation_hash,)).fetchone()
            if row is None:
                raise ValueError("prepared Sols swap operation does not exist")
            record = self._record(row)
            bundle = validate_execution(execution, pool_input_id=record.pool_input_coin_id,
                                        pool_output_id=record.expected_pool_output_coin_id)
            existing = connection.execute("SELECT * FROM sols_swap_executions WHERE operation_hash=?",
                                          (operation_hash,)).fetchone()
            if existing is not None:
                if existing["execution_json"] != encoded or existing["execution_sha256"] != digest:
                    raise ValueError("Sols swap already has a different exact execution")
                return
            if record.status != "PREPARED" or record.transaction_id is not None:
                raise ValueError("Sols swap can no longer reserve a new execution")
            hold = connection.execute("SELECT * FROM sols_swap_funding_reviews WHERE operation_hash=?", (operation_hash,)).fetchone()
            if hold is not None or funding_reservation_hash is not None:
                from .sols_swap_funding import digest as funding_digest, validate_private_hold
                if hold is None or hold["expires_at"] <= time():
                    raise ValueError("swap funding review expired before exact execution promotion")
                payload = json.loads(hold["reservation_json"])
                funding_bundle = validate_private_hold(payload)
                if (funding_digest(payload) != hold["reservation_sha256"]
                        or payload["review"]["quoteExpiresAt"] != hold["expires_at"]
                        or hold["expires_at"] != record.quote_expires_at
                        or payload["review"]["operationHash"] != operation_hash
                        or payload["review"]["binding"]["vaultLauncherId"] != record.vault_launcher_id
                        or payload["review"]["feeTargetSeconds"] != execution["feeTargetSeconds"]
                        or payload["review"]["binding"]["network"] != execution["network"]
                        or payload["reservationHash"] != funding_reservation_hash
                        or execution.get("fundingReservationHash") != funding_reservation_hash
                        or payload["review"]["feeCoinId"] != execution["feeCoinId"]
                        or payload["review"]["feeMojos"] != execution["feeMojos"]
                        or payload["review"]["backingMojos"] != execution["backingMojos"]
                        or funding_bundle.coin_spends[0] not in bundle.coin_spends):
                    raise ValueError("signed execution changed its reserved funding")
            for coin in bundle.removals():
                conflict = connection.execute("""SELECT 1 FROM sols_swap_funding_reviews f
                    WHERE f.fee_coin_id=? AND f.operation_hash<>? AND f.expires_at>?
                    AND NOT EXISTS (SELECT 1 FROM sols_swap_executions e WHERE e.operation_hash=f.operation_hash)""",
                    (hx(coin.name()), operation_hash, time())).fetchone()
                if conflict:
                    raise ValueError("execution consumes another operation's reviewed funding")
            connection.execute("INSERT INTO sols_swap_executions VALUES (?, ?, ?)",
                               (operation_hash, encoded, digest))
            try:
                connection.executemany("INSERT INTO sols_swap_input_reservations VALUES (?, ?)",
                                       [(hx(coin.name()), operation_hash) for coin in bundle.removals()])
            except sqlite3.IntegrityError as exc:
                raise ValueError("a Sols swap input is reserved by another execution") from exc
            connection.execute("""
                UPDATE sols_swap_operations SET transaction_id=?, fee_mojos=?,
                    fee_target_seconds=?, updated_at=? WHERE operation_hash=?
            """, (execution["spendBundleId"], execution["feeMojos"], execution["feeTargetSeconds"],
                  time(), operation_hash))

    def execution(self, operation_hash: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            row = connection.execute("""
                SELECT e.*, o.pool_input_coin_id, o.expected_pool_output_coin_id,
                    o.transaction_id, o.fee_mojos, o.fee_target_seconds
                FROM sols_swap_executions e JOIN sols_swap_operations o USING (operation_hash)
                WHERE operation_hash=?
            """, (operation_hash,)).fetchone()
        if row is None:
            return None
        if hashlib.sha256(row["execution_json"].encode()).hexdigest() != row["execution_sha256"]:
            raise ValueError("durable Sols swap execution checksum differs")
        execution = json.loads(row["execution_json"])
        validate_execution(execution, pool_input_id=row["pool_input_coin_id"],
                           pool_output_id=row["expected_pool_output_coin_id"])
        if (execution["spendBundleId"] != row["transaction_id"] or execution["feeMojos"] != row["fee_mojos"]
                or execution["feeTargetSeconds"] != row["fee_target_seconds"]):
            raise ValueError("durable Sols swap execution metadata differs")
        return execution

    def reserved_input_coin_ids(self) -> tuple[str, ...]:
        """Only unsealed private fee holds expire; signed input claims do not."""
        with self._transaction() as connection:
            self._expire_funding(connection)
            rows = connection.execute("""SELECT coin_id FROM sols_swap_input_reservations
                UNION SELECT f.fee_coin_id AS coin_id FROM sols_swap_funding_reviews f
                WHERE NOT EXISTS (SELECT 1 FROM sols_swap_executions e WHERE e.operation_hash=f.operation_hash)
                ORDER BY coin_id""").fetchall()
        return tuple(row["coin_id"] for row in rows)

    def record_prepared(
        self,
        *,
        operation_hash: str,
        direction: str,
        vault_launcher_id: str,
        deed_launcher_id: str,
        quote_expires_at: int,
        pool_input_coin_id: str,
        expected_pool_output_coin_id: str,
        destination_puzzle_hash: str,
    ) -> StoredSolsSwap:
        now = time()
        identity = (
            direction,
            vault_launcher_id,
            deed_launcher_id,
            quote_expires_at,
            pool_input_coin_id,
            expected_pool_output_coin_id,
            destination_puzzle_hash,
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
            if row is not None:
                existing = self._record(row)
                if identity != (
                    existing.direction,
                    existing.vault_launcher_id,
                    existing.deed_launcher_id,
                    existing.quote_expires_at,
                    existing.pool_input_coin_id,
                    existing.expected_pool_output_coin_id,
                    existing.destination_puzzle_hash,
                ):
                    raise ValueError(
                        "operation hash is already bound to another swap"
                    )
                return existing
            connection.execute(
                """
                INSERT INTO sols_swap_operations (
                    operation_hash, direction, vault_launcher_id,
                    deed_launcher_id, status, quote_expires_at,
                    pool_input_coin_id, expected_pool_output_coin_id,
                    destination_puzzle_hash, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'PREPARED', ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_hash,
                    direction,
                    vault_launcher_id,
                    deed_launcher_id,
                    quote_expires_at,
                    pool_input_coin_id,
                    expected_pool_output_coin_id,
                    destination_puzzle_hash,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
        assert row is not None
        return self._record(row)

    def mark_submitted(
        self,
        operation_hash: str,
        *,
        transaction_id: str,
        fee_mojos: str,
        fee_target_seconds: int,
        submission_provider: str,
        mempool_observed_at: str,
    ) -> StoredSolsSwap:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
            if row is None:
                raise ValueError("prepared Sols swap operation does not exist")
            existing = self._record(row)
            if existing.transaction_id is not None and (
                existing.transaction_id != transaction_id or existing.fee_mojos != fee_mojos
                or existing.fee_target_seconds != fee_target_seconds
            ):
                raise ValueError("submission differs from the retained Sols swap execution")
            if existing.status in ("SUBMITTED", "CONFIRMED"):
                if existing.transaction_id != transaction_id:
                    raise ValueError(
                        "operation already has a different transaction"
                    )
                return existing
            if existing.status != "PREPARED":
                raise ValueError("failed Sols swap cannot be resubmitted")
            connection.execute(
                """
                UPDATE sols_swap_operations
                SET status='SUBMITTED', transaction_id=?, fee_mojos=?,
                    fee_target_seconds=?, submission_provider=?,
                    mempool_observed_at=?, updated_at=?
                WHERE operation_hash=?
                """,
                (
                    transaction_id,
                    fee_mojos,
                    fee_target_seconds,
                    submission_provider,
                    mempool_observed_at,
                    time(),
                    operation_hash,
                ),
            )
            row = connection.execute(
                "SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
        assert row is not None
        return self._record(row)

    def mark_confirmed(self, operation_hash: str) -> StoredSolsSwap:
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE sols_swap_operations
                SET status='CONFIRMED', updated_at=?
                WHERE operation_hash=? AND (status='SUBMITTED' OR
                    (status='PREPARED' AND transaction_id IS NOT NULL AND EXISTS (
                        SELECT 1 FROM sols_swap_executions e
                        WHERE e.operation_hash=sols_swap_operations.operation_hash)))
                """,
                (time(), operation_hash),
            )
            row = connection.execute(
                "SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
            if row is not None and row["status"] == "CONFIRMED":
                connection.execute("DELETE FROM sols_swap_input_reservations WHERE operation_hash=?",
                                   (operation_hash,))
        if row is None:
            raise ValueError("Sols swap operation does not exist")
        return self._record(row)

    def get(self, operation_hash: str) -> StoredSolsSwap | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sols_swap_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
        return self._record(row) if row is not None else None

    def list_for_vault(
        self,
        vault_launcher_id: str,
        *,
        limit: int = 50,
    ) -> tuple[StoredSolsSwap, ...]:
        bounded = max(1, min(limit, 100))
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM sols_swap_operations
                WHERE vault_launcher_id=?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (vault_launcher_id, bounded),
            ).fetchall()
        return tuple(self._record(row) for row in rows)

    @staticmethod
    def _record(row: sqlite3.Row) -> StoredSolsSwap:
        return StoredSolsSwap(
            operation_hash=str(row["operation_hash"]),
            direction=str(row["direction"]),
            vault_launcher_id=str(row["vault_launcher_id"]),
            deed_launcher_id=str(row["deed_launcher_id"]),
            status=str(row["status"]),
            quote_expires_at=int(row["quote_expires_at"]),
            pool_input_coin_id=str(row["pool_input_coin_id"]),
            expected_pool_output_coin_id=str(
                row["expected_pool_output_coin_id"]
            ),
            destination_puzzle_hash=str(row["destination_puzzle_hash"]),
            transaction_id=(
                str(row["transaction_id"])
                if row["transaction_id"] is not None
                else None
            ),
            fee_mojos=(
                str(row["fee_mojos"])
                if row["fee_mojos"] is not None
                else None
            ),
            fee_target_seconds=(
                int(row["fee_target_seconds"])
                if row["fee_target_seconds"] is not None
                else None
            ),
            submission_provider=(
                str(row["submission_provider"])
                if row["submission_provider"] is not None
                else None
            ),
            mempool_observed_at=(
                str(row["mempool_observed_at"])
                if row["mempool_observed_at"] is not None
                else None
            ),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )


__all__ = ["SolsSwapStore", "StoredSolsSwap"]
