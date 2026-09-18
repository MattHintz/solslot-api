"""Private fee review and durable customer redemption dispatch records."""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from time import time
from types import SimpleNamespace

from .sols_swap_execution import validate_execution
from chia_rs import SpendBundle
from .sols_swap_funding import canonical, digest, hx, validate_private_hold


class RedemptionReviewStore:
    def __init__(self, path: str):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS redemption_review_operations (
                operation_hash TEXT PRIMARY KEY, vault_launcher_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL, terms_json TEXT NOT NULL, terms_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS redemption_fee_reviews (
                operation_hash TEXT PRIMARY KEY REFERENCES redemption_review_operations(operation_hash),
                fee_coin_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS redemption_exact_executions (
                operation_hash TEXT PRIMARY KEY REFERENCES redemption_review_operations(operation_hash),
                execution_json TEXT NOT NULL, execution_hash TEXT NOT NULL,
                receipt_json TEXT, confirmed_height INTEGER)""")
            db.execute("""CREATE TABLE IF NOT EXISTS redemption_expired_executions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_hash TEXT NOT NULL,
                spend_bundle_id TEXT NOT NULL UNIQUE, archive_json TEXT NOT NULL, archive_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS redemption_input_claims (
                coin_id TEXT PRIMARY KEY, operation_hash TEXT NOT NULL REFERENCES redemption_exact_executions(operation_hash))""")

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _expire(db):
        db.execute("""DELETE FROM redemption_fee_reviews WHERE operation_hash IN (
            SELECT o.operation_hash FROM redemption_review_operations o WHERE expires_at<=?
            AND NOT EXISTS (SELECT 1 FROM redemption_exact_executions e WHERE e.operation_hash=o.operation_hash))""", (time(),))

    @staticmethod
    def _terms(row):
        if row is None:
            raise ValueError("Prepare this redemption before owner signing")
        terms = json.loads(row["terms_json"])
        if digest(terms) != row["terms_hash"] or terms["vaultLauncherId"] != row["vault_launcher_id"]:
            raise ValueError("Retained redemption terms changed")
        return terms

    def prepare(self, operation: str, terms: dict, expires: int) -> int:
        if type(expires) is not int or not time() < expires <= time() + 900:
            raise ValueError("Redemption review expiry is invalid")
        encoded = canonical(terms)
        with self._transaction() as db:
            self._expire(db)
            old = db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone()
            if old:
                if self._terms(old) != terms:
                    raise ValueError("Redemption operation already has different terms")
                if db.execute("SELECT 1 FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone():
                    raise ValueError("Recover the retained redemption execution")
                if old["expires_at"] > time():
                    return old["expires_at"]
                db.execute("UPDATE redemption_review_operations SET expires_at=? WHERE operation_hash=?", (expires, operation))
            else:
                db.execute("INSERT INTO redemption_review_operations VALUES (?,?,?,?,?)",
                           (operation, terms["vaultLauncherId"], expires, encoded, digest(terms)))
        return expires

    def get(self, operation: str):
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone()
            if row is None:
                return None
            terms = self._terms(row)
            execution = db.execute("SELECT * FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()
            transaction = None
            if execution:
                transaction = self._execution(execution, terms)["spendBundleId"]
            return SimpleNamespace(terms=terms, quote_expires_at=row["expires_at"], transaction_id=transaction,
                receipt=json.loads(execution["receipt_json"]) if execution and execution["receipt_json"] else None,
                confirmed_height=execution["confirmed_height"] if execution else None)

    def supersede_unsealed_funding(self, operation: str, vault: str):
        with self._transaction() as db:
            current = db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone()
            if self._terms(current)["vaultLauncherId"] != vault or current["expires_at"] <= time():
                raise ValueError("Redemption review changed")
            db.execute("""DELETE FROM redemption_fee_reviews WHERE operation_hash<>? AND operation_hash IN (
                SELECT operation_hash FROM redemption_review_operations WHERE vault_launcher_id=?)
                AND NOT EXISTS (SELECT 1 FROM redemption_exact_executions e WHERE e.operation_hash=redemption_fee_reviews.operation_hash)""",
                (operation, vault))

    def reserve_funding(self, operation: str, payload: dict):
        private = validate_private_hold(payload)
        review = payload["review"]
        with self._transaction() as db:
            self._expire(db)
            row = db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone()
            terms = self._terms(row)
            if (row["expires_at"] <= time() or review["quoteExpiresAt"] != row["expires_at"]
                    or review["operationHash"] != operation or review["binding"]["vaultLauncherId"] != terms["vaultLauncherId"]
                    or review["protocolCandidateHash"] != terms["candidateHash"]
                    or db.execute("SELECT 1 FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()):
                raise ValueError("Redemption fee review differs from its prepared terms")
            old = db.execute("SELECT * FROM redemption_fee_reviews WHERE operation_hash=?", (operation,)).fetchone()
            if old:
                if old["payload_hash"] != digest(payload) or old["payload_json"] != canonical(payload):
                    raise ValueError("Redemption already has different reviewed funding")
                return
            fee_id = hx(private.coin_spends[0].coin.name())
            if db.execute("SELECT 1 FROM redemption_input_claims WHERE coin_id=?", (fee_id,)).fetchone():
                raise ValueError("Redemption funding coin is already reserved")
            db.execute("INSERT INTO redemption_fee_reviews VALUES (?,?,?,?)", (operation, fee_id, canonical(payload), digest(payload)))

    def funding(self, operation: str):
        with self._transaction() as db:
            self._expire(db)
            row = db.execute("SELECT * FROM redemption_fee_reviews WHERE operation_hash=?", (operation,)).fetchone()
            if row is None:
                return None
            payload = json.loads(row["payload_json"])
            if digest(payload) != row["payload_hash"] or hx(validate_private_hold(payload).coin_spends[0].coin.name()) != row["fee_coin_id"]:
                raise ValueError("Retained redemption funding changed")
            return payload

    @staticmethod
    def _execution(row, terms):
        result = json.loads(row["execution_json"])
        if digest(result) != row["execution_hash"]:
            raise ValueError("Retained redemption execution changed")
        validate_execution(result, pool_input_id=terms["fundingCoinId"], pool_output_id=terms["expectedPaymentCoinId"])
        return result

    def seal_execution(self, operation: str, execution: dict, reservation_hash: str):
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone()
            terms = self._terms(row)
            bundle = validate_execution(execution, pool_input_id=terms["fundingCoinId"], pool_output_id=terms["expectedPaymentCoinId"])
            prior = db.execute("SELECT * FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()
            if prior:
                if self._execution(prior, terms) != execution:
                    raise ValueError("Redemption already has a different exact execution")
                return
            hold = db.execute("SELECT * FROM redemption_fee_reviews WHERE operation_hash=?", (operation,)).fetchone()
            if hold is None or row["expires_at"] <= time():
                raise ValueError("Redemption funding review expired before dispatch")
            payload = json.loads(hold["payload_json"])
            private = validate_private_hold(payload)
            review = payload["review"]
            if (digest(payload) != hold["payload_hash"] or payload["reservationHash"] != reservation_hash
                    or execution.get("fundingReservationHash") != reservation_hash
                    or review["protocolCandidateHash"] != terms["candidateHash"]
                    or review["binding"]["vaultLauncherId"] != terms["vaultLauncherId"]
                    or review["operationHash"] != operation or review["quoteExpiresAt"] != row["expires_at"]
                    or private.coin_spends[0] not in bundle.coin_spends
                    or any(execution[key] != review[key] for key in ("feeCoinId", "feeMojos", "backingMojos", "feeTargetSeconds"))):
                raise ValueError("Redemption execution differs from reviewed funding")
            db.execute("INSERT INTO redemption_exact_executions VALUES (?,?,?,NULL,NULL)", (operation, canonical(execution), digest(execution)))
            for spend in bundle.coin_spends:
                conflict = db.execute("SELECT 1 FROM redemption_fee_reviews WHERE fee_coin_id=? AND operation_hash<>?",
                                      (hx(spend.coin.name()), operation)).fetchone()
                if conflict:
                    raise ValueError("Redemption consumes another reviewed fee coin")
                db.execute("INSERT INTO redemption_input_claims VALUES (?,?)", (hx(spend.coin.name()), operation))

    def execution(self, operation: str):
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()
            if row is None:
                return None
            terms = self._terms(db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone())
            return self._execution(row, terms)

    def mark_submitted(self, operation: str, receipt: dict):
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()
            terms = self._terms(db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone())
            if row is None or receipt["spendBundleId"] != self._execution(row, terms)["spendBundleId"]:
                raise ValueError("Redemption receipt differs from retained execution")
            db.execute("UPDATE redemption_exact_executions SET receipt_json=? WHERE operation_hash=?", (canonical(receipt), operation))

    def mark_confirmed(self, operation: str, height: int, transaction_id: str):
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()
            terms = self._terms(db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone())
            if (type(height) is not int or height <= 0 or row is None
                    or self._execution(row, terms)["spendBundleId"] != transaction_id):
                raise ValueError("Exact redemption confirmation is required")
            db.execute("UPDATE redemption_exact_executions SET confirmed_height=? WHERE operation_hash=?", (height, operation))
            db.execute("DELETE FROM redemption_input_claims WHERE operation_hash=?", (operation,))

    def reconcile_expired(self, operation: str, transaction_id: str, observation: dict):
        """Preserve the signed attempt; release only after current primary proof.

        This is configured-primary reconciliation, not a claim of SPV finality.
        A new attempt always requires a new funding review and owner completion.
        """
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_exact_executions WHERE operation_hash=?", (operation,)).fetchone()
            prepared = db.execute("SELECT * FROM redemption_review_operations WHERE operation_hash=?", (operation,)).fetchone()
            terms = self._terms(prepared)
            if row is None or row["confirmed_height"] is not None:
                raise ValueError("Only an unconfirmed exact execution can be reconciled")
            execution = self._execution(row, terms)
            bundle = SpendBundle.from_json_dict(execution["spendBundle"])
            additions = {coin.name() for coin in bundle.additions()}
            persistent = [spend.coin for spend in bundle.coin_spends if spend.coin.name() not in additions]
            body = {key: value for key, value in observation.items() if key != "snapshotHash"}
            if (execution["spendBundleId"] != transaction_id or digest(body) != observation.get("snapshotHash")
                    or observation.get("status") != "PRIMARY_NODE_OBSERVATION" or observation.get("network") != "testnet11"
                    or observation.get("authority") != "CONFIGURED_PRIMARY_FULL_NODE" or observation.get("consensusInclusionProven") is not False
                    or type(observation.get("transactionTimestamp")) is not int or observation["transactionTimestamp"] < prepared["expires_at"]
                    or not time() < observation.get("expiresAt", 0) <= observation.get("observedAt", 0) + 60
                    or observation.get("binding") != {"operationHash": operation, "spendBundleId": transaction_id,
                        "expiredAt": prepared["expires_at"], "quoteExpiresAt": observation["expiresAt"]}
                    or len(observation.get("inputs", [])) != len(persistent)):
                raise ValueError("Expired execution requires a fresh bound primary observation")
            for actual, coin in zip(observation["inputs"], persistent):
                if (actual.get("coinId") != hx(coin.name()) or actual.get("coin") != {
                        "parentCoinInfo": hx(coin.parent_coin_info), "puzzleHash": hx(coin.puzzle_hash), "amount": str(coin.amount)}
                        or type(actual.get("confirmedHeight")) is not int or actual["confirmedHeight"] <= 0
                        or actual.get("spentHeight") != 0):
                    raise ValueError("Expired execution requires all exact persistent inputs unspent")
            hold = db.execute("SELECT * FROM redemption_fee_reviews WHERE operation_hash=?", (operation,)).fetchone()
            payload = json.loads(hold["payload_json"]) if hold else None
            if payload is None or digest(payload) != hold["payload_hash"]:
                raise ValueError("Expired execution funding evidence is unavailable")
            validate_private_hold(payload)
            archive = {"operationHash": operation, "terms": terms, "expiresAt": prepared["expires_at"],
                "execution": execution, "funding": payload, "receipt": json.loads(row["receipt_json"]) if row["receipt_json"] else None,
                "observation": observation}
            db.execute("INSERT INTO redemption_expired_executions(operation_hash,spend_bundle_id,archive_json,archive_hash) VALUES (?,?,?,?)",
                       (operation, transaction_id, canonical(archive), digest(archive)))
            # The immutable archive above retains every original byte. Only the
            # active attempt and its claims are retired, in this same transaction.
            db.execute("DELETE FROM redemption_input_claims WHERE operation_hash=?", (operation,))
            db.execute("DELETE FROM redemption_fee_reviews WHERE operation_hash=?", (operation,))
            db.execute("DELETE FROM redemption_exact_executions WHERE operation_hash=?", (operation,))

    def expired_execution(self, operation: str):
        with self._transaction() as db:
            row = db.execute("SELECT * FROM redemption_expired_executions WHERE operation_hash=? ORDER BY sequence DESC LIMIT 1", (operation,)).fetchone()
            if row is None:
                return None
            archive = json.loads(row["archive_json"])
            if digest(archive) != row["archive_hash"] or archive["operationHash"] != operation:
                raise ValueError("Retained expired execution changed")
            validate_execution(archive["execution"], pool_input_id=archive["terms"]["fundingCoinId"], pool_output_id=archive["terms"]["expectedPaymentCoinId"])
            return archive

    def reserved_input_coin_ids(self):
        with self._transaction() as db:
            self._expire(db)
            return tuple(row[0] for row in db.execute("""SELECT coin_id FROM redemption_input_claims
                UNION SELECT f.fee_coin_id FROM redemption_fee_reviews f WHERE NOT EXISTS (
                    SELECT 1 FROM redemption_exact_executions e WHERE e.operation_hash=f.operation_hash)"""))

    def list_executions(self, vault: str):
        with self._transaction() as db:
            return tuple(row[0] for row in db.execute("""SELECT o.operation_hash FROM redemption_review_operations o
                WHERE o.vault_launcher_id=? AND (EXISTS (SELECT 1 FROM redemption_exact_executions e WHERE e.operation_hash=o.operation_hash)
                OR EXISTS (SELECT 1 FROM redemption_expired_executions a WHERE a.operation_hash=o.operation_hash))""", (vault,)))
