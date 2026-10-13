"""Durable, chain-confirmable customer funded-redemption operations."""
from __future__ import annotations

from .generation_storage import connect_generation_sqlite

import json
import sqlite3
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from time import time


@dataclass(frozen=True)
class StoredFundedRedemption:
    operation_hash: str
    settlement_id: str
    deed_launcher_id: str
    vault_launcher_id: str
    payment_amount: str
    funding_coin_id: str
    expected_payment_coin_id: str
    status: str
    transaction_id: str
    fee_mojos: str
    fee_target_seconds: int
    submission_provider: str
    mempool_observed_at: str
    confirmed_height: int | None
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class StoredRedemptionFunding:
    proposal_id: str
    operation_hash: str
    settlement_id: str
    payment_asset_id: str
    payment_amount: str
    recipient_inner_puzzle_hash: str
    expected_funding_coin_id: str
    unsigned_bundle_json: str
    signed_bundle_json: str | None
    input_coin_ids: tuple[str, ...]
    status: str
    transaction_id: str | None
    fee_mojos: str | None
    fee_target_seconds: int | None
    submission_provider: str | None
    mempool_observed_at: str | None
    confirmed_height: int | None
    created_by: str
    created_at: int
    updated_at: int


class FundedRedemptionStore:
    def __init__(self, path: str) -> None:
        db_path = Path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = connect_generation_sqlite(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS funded_redemption_operations (
                operation_hash TEXT PRIMARY KEY,
                settlement_id TEXT NOT NULL,
                deed_launcher_id TEXT NOT NULL,
                vault_launcher_id TEXT NOT NULL,
                payment_amount TEXT NOT NULL,
                funding_coin_id TEXT NOT NULL UNIQUE,
                expected_payment_coin_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK (status IN ('SUBMITTED','CONFIRMED')),
                transaction_id TEXT NOT NULL,
                fee_mojos TEXT NOT NULL,
                fee_target_seconds INTEGER NOT NULL,
                submission_provider TEXT NOT NULL,
                mempool_observed_at TEXT NOT NULL,
                confirmed_height INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS funded_redemption_funding (
                proposal_id TEXT PRIMARY KEY,
                operation_hash TEXT NOT NULL UNIQUE,
                settlement_id TEXT NOT NULL,
                payment_asset_id TEXT NOT NULL,
                payment_amount TEXT NOT NULL,
                recipient_inner_puzzle_hash TEXT NOT NULL,
                expected_funding_coin_id TEXT NOT NULL UNIQUE,
                unsigned_bundle_json TEXT NOT NULL,
                signed_bundle_json TEXT,
                input_coin_ids_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('PREPARED','SUBMITTING','SUBMITTED','CONFIRMED')
                ),
                transaction_id TEXT,
                fee_mojos TEXT,
                fee_target_seconds INTEGER,
                submission_provider TEXT,
                mempool_observed_at TEXT,
                confirmed_height INTEGER,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def record_submitted(
        self,
        *,
        operation_hash: str,
        settlement_id: str,
        deed_launcher_id: str,
        vault_launcher_id: str,
        payment_amount: str,
        funding_coin_id: str,
        expected_payment_coin_id: str,
        transaction_id: str,
        fee_mojos: str,
        fee_target_seconds: int,
        submission_provider: str,
        mempool_observed_at: str,
    ) -> StoredFundedRedemption:
        now = int(time())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO funded_redemption_operations (
                    operation_hash,settlement_id,deed_launcher_id,vault_launcher_id,
                    payment_amount,funding_coin_id,expected_payment_coin_id,status,
                    transaction_id,fee_mojos,fee_target_seconds,submission_provider,
                    mempool_observed_at,confirmed_height,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(operation_hash) DO NOTHING
                """,
                (
                    operation_hash, settlement_id, deed_launcher_id, vault_launcher_id,
                    payment_amount, funding_coin_id, expected_payment_coin_id, "SUBMITTED",
                    transaction_id, fee_mojos, fee_target_seconds, submission_provider,
                    mempool_observed_at, None, now, now,
                ),
            )
            self._conn.commit()
        record = self.get(operation_hash)
        if record is None:
            raise RuntimeError("redemption operation was not persisted")
        immutable = (
            record.settlement_id,
            record.deed_launcher_id,
            record.vault_launcher_id,
            record.payment_amount,
            record.funding_coin_id,
            record.expected_payment_coin_id,
            record.transaction_id,
        )
        supplied = (
            settlement_id, deed_launcher_id, vault_launcher_id, payment_amount,
            funding_coin_id, expected_payment_coin_id, transaction_id,
        )
        if immutable != supplied:
            raise ValueError("redemption operation hash is already bound to different evidence")
        return record

    def get(self, operation_hash: str) -> StoredFundedRedemption | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM funded_redemption_operations WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
        return None if row is None else self._row(row)

    def list_for_vault(self, vault_launcher_id: str) -> tuple[StoredFundedRedemption, ...]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM funded_redemption_operations WHERE vault_launcher_id=? "
                "ORDER BY updated_at DESC, operation_hash",
                (vault_launcher_id,),
            ).fetchall()
        return tuple(self._row(row) for row in rows)

    def mark_confirmed(self, operation_hash: str, height: int) -> StoredFundedRedemption:
        now = int(time())
        with self._lock:
            self._conn.execute(
                "UPDATE funded_redemption_operations SET status='CONFIRMED',"
                "confirmed_height=?,updated_at=? WHERE operation_hash=?",
                (height, now, operation_hash),
            )
            self._conn.commit()
        record = self.get(operation_hash)
        if record is None:
            raise KeyError(operation_hash)
        return record

    def prepare_funding_submission(
        self,
        *,
        proposal_id: str,
        operation_hash: str,
        settlement_id: str,
        payment_asset_id: str,
        payment_amount: str,
        recipient_inner_puzzle_hash: str,
        expected_funding_coin_id: str,
        unsigned_bundle: dict,
        signed_bundle: dict,
        input_coin_ids: tuple[str, ...],
        created_by: str,
    ) -> StoredRedemptionFunding:
        now = int(time())
        unsigned_json = json.dumps(
            unsigned_bundle, sort_keys=True, separators=(",", ":")
        )
        signed_json = json.dumps(
            signed_bundle, sort_keys=True, separators=(",", ":")
        )
        input_json = json.dumps(list(input_coin_ids), separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO funded_redemption_funding (
                    proposal_id,operation_hash,settlement_id,payment_asset_id,
                    payment_amount,recipient_inner_puzzle_hash,
                    expected_funding_coin_id,unsigned_bundle_json,
                    signed_bundle_json,input_coin_ids_json,status,transaction_id,
                    fee_mojos,fee_target_seconds,submission_provider,
                    mempool_observed_at,confirmed_height,created_by,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(proposal_id) DO NOTHING
                """,
                (
                    proposal_id, operation_hash, settlement_id, payment_asset_id,
                    payment_amount, recipient_inner_puzzle_hash,
                    expected_funding_coin_id, unsigned_json, signed_json, input_json,
                    "SUBMITTING", None, None, None, None, None, None, created_by,
                    now, now,
                ),
            )
            self._conn.commit()
        record = self.get_funding(proposal_id)
        if record is None:
            raise RuntimeError("redemption funding intent was not persisted")
        immutable = (
            record.operation_hash,
            record.settlement_id,
            record.payment_asset_id,
            record.payment_amount,
            record.recipient_inner_puzzle_hash,
            record.expected_funding_coin_id,
            record.unsigned_bundle_json,
            record.signed_bundle_json,
            record.input_coin_ids,
        )
        supplied = (
            operation_hash,
            settlement_id,
            payment_asset_id,
            payment_amount,
            recipient_inner_puzzle_hash,
            expected_funding_coin_id,
            unsigned_json,
            signed_json,
            input_coin_ids,
        )
        if immutable != supplied:
            raise ValueError(
                "redemption proposal already has a different funding intent"
            )
        return record

    def get_funding(self, proposal_id: str) -> StoredRedemptionFunding | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM funded_redemption_funding WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
        return None if row is None else self._funding_row(row)

    def get_funding_by_operation(
        self, operation_hash: str
    ) -> StoredRedemptionFunding | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM funded_redemption_funding WHERE operation_hash=?",
                (operation_hash,),
            ).fetchone()
        return None if row is None else self._funding_row(row)

    def mark_funding_submitted(
        self,
        proposal_id: str,
        *,
        transaction_id: str,
        fee_mojos: str,
        fee_target_seconds: int,
        submission_provider: str,
        mempool_observed_at: str,
    ) -> StoredRedemptionFunding:
        now = int(time())
        with self._lock:
            self._conn.execute(
                "UPDATE funded_redemption_funding SET status='SUBMITTED',"
                "transaction_id=?,fee_mojos=?,fee_target_seconds=?,"
                "submission_provider=?,mempool_observed_at=?,updated_at=? "
                "WHERE proposal_id=? AND status IN ('SUBMITTING','SUBMITTED')",
                (
                    transaction_id, fee_mojos, fee_target_seconds,
                    submission_provider, mempool_observed_at, now, proposal_id,
                ),
            )
            self._conn.commit()
        record = self.get_funding(proposal_id)
        if record is None:
            raise KeyError(proposal_id)
        if record.transaction_id != transaction_id:
            raise ValueError("funding submission is already bound to another bundle")
        return record

    def mark_funding_confirmed(
        self, proposal_id: str, height: int
    ) -> StoredRedemptionFunding:
        now = int(time())
        with self._lock:
            self._conn.execute(
                "UPDATE funded_redemption_funding SET status='CONFIRMED',"
                "confirmed_height=?,updated_at=? WHERE proposal_id=?",
                (height, now, proposal_id),
            )
            self._conn.commit()
        record = self.get_funding(proposal_id)
        if record is None:
            raise KeyError(proposal_id)
        return record

    @staticmethod
    def _row(row: sqlite3.Row) -> StoredFundedRedemption:
        return StoredFundedRedemption(
            operation_hash=str(row["operation_hash"]),
            settlement_id=str(row["settlement_id"]),
            deed_launcher_id=str(row["deed_launcher_id"]),
            vault_launcher_id=str(row["vault_launcher_id"]),
            payment_amount=str(row["payment_amount"]),
            funding_coin_id=str(row["funding_coin_id"]),
            expected_payment_coin_id=str(row["expected_payment_coin_id"]),
            status=str(row["status"]),
            transaction_id=str(row["transaction_id"]),
            fee_mojos=str(row["fee_mojos"]),
            fee_target_seconds=int(row["fee_target_seconds"]),
            submission_provider=str(row["submission_provider"]),
            mempool_observed_at=str(row["mempool_observed_at"]),
            confirmed_height=(None if row["confirmed_height"] is None else int(row["confirmed_height"])),
            created_at=int(row["created_at"]),
            updated_at=int(row["updated_at"]),
        )

    @staticmethod
    def _funding_row(row: sqlite3.Row) -> StoredRedemptionFunding:
        input_ids = json.loads(str(row["input_coin_ids_json"]))
        if not isinstance(input_ids, list) or not all(
            isinstance(item, str) for item in input_ids
        ):
            raise ValueError("stored funding input list is malformed")
        return StoredRedemptionFunding(
            proposal_id=str(row["proposal_id"]),
            operation_hash=str(row["operation_hash"]),
            settlement_id=str(row["settlement_id"]),
            payment_asset_id=str(row["payment_asset_id"]),
            payment_amount=str(row["payment_amount"]),
            recipient_inner_puzzle_hash=str(row["recipient_inner_puzzle_hash"]),
            expected_funding_coin_id=str(row["expected_funding_coin_id"]),
            unsigned_bundle_json=str(row["unsigned_bundle_json"]),
            signed_bundle_json=(
                None
                if row["signed_bundle_json"] is None
                else str(row["signed_bundle_json"])
            ),
            input_coin_ids=tuple(input_ids),
            status=str(row["status"]),
            transaction_id=(
                None if row["transaction_id"] is None else str(row["transaction_id"])
            ),
            fee_mojos=None if row["fee_mojos"] is None else str(row["fee_mojos"]),
            fee_target_seconds=(
                None
                if row["fee_target_seconds"] is None
                else int(row["fee_target_seconds"])
            ),
            submission_provider=(
                None
                if row["submission_provider"] is None
                else str(row["submission_provider"])
            ),
            mempool_observed_at=(
                None
                if row["mempool_observed_at"] is None
                else str(row["mempool_observed_at"])
            ),
            confirmed_height=(
                None
                if row["confirmed_height"] is None
                else int(row["confirmed_height"])
            ),
            created_by=str(row["created_by"]),
            created_at=int(row["created_at"]),
            updated_at=int(row["updated_at"]),
        )


@lru_cache(maxsize=4)
def get_funded_redemption_store(path: str) -> FundedRedemptionStore:
    return FundedRedemptionStore(path)


__all__ = [
    "FundedRedemptionStore",
    "StoredFundedRedemption",
    "StoredRedemptionFunding",
    "get_funded_redemption_store",
]
