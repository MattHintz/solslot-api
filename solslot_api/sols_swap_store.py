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

    def reserve_execution(self, operation_hash: str, execution: Mapping[str, Any]) -> None:
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
        """No wall-clock expiry: a signed transaction may already be on chain."""
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT coin_id FROM sols_swap_input_reservations ORDER BY coin_id").fetchall()
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
