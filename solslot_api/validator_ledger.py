"""One-time signature ledger for an isolated zkPassport validator."""

from __future__ import annotations

import sqlite3
import json
import threading
import time
from collections.abc import Sequence
from pathlib import Path


SCHEMA_VERSION = 10


class ValidatorLedgerConflict(RuntimeError):
    """A claim attempted to reuse one-time credential evidence."""


class ValidatorLedger:
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

    def _configure(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 10000")
            self._conn.execute("PRAGMA synchronous = FULL")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Validator ledger schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version < 1:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        scoped_nullifier TEXT NOT NULL UNIQUE,
                        bridge_coin_id TEXT NOT NULL UNIQUE,
                        vault_action TEXT NOT NULL UNIQUE,
                        evm_transaction_hash TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 1;
                    COMMIT;
                    """
                )
                version = 1
            if version < 2:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE primary_purchase_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        deed_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 2;
                    COMMIT;
                    """
                )
                version = 2
            if version < 3:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE voucher_issuance_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        global_payment_id TEXT NOT NULL UNIQUE,
                        series_coin_id TEXT NOT NULL UNIQUE,
                        purchase_launcher_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 3;
                    COMMIT;
                    """
                )
                version = 3
            if version < 4:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE voucher_transition_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        global_payment_id TEXT NOT NULL UNIQUE,
                        series_coin_id TEXT NOT NULL UNIQUE,
                        voucher_coin_id TEXT NOT NULL UNIQUE,
                        payment_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 4;
                    COMMIT;
                    """
                )
                version = 4
            if version < 5:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE voucher_series_phase_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        series_coin_id TEXT NOT NULL UNIQUE,
                        transition INTEGER NOT NULL,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 5;
                    COMMIT;
                    """
                )
                version = 5
            if version < 6:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE voucher_transition_signatures
                        ADD COLUMN deed_coin_id TEXT;
                    CREATE UNIQUE INDEX voucher_transition_deed_once
                        ON voucher_transition_signatures(deed_coin_id)
                        WHERE deed_coin_id IS NOT NULL;
                    PRAGMA user_version = 6;
                    COMMIT;
                    """
                )
                version = 6
            if version < 7:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE stripe_settlement_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        payment_intent_id TEXT NOT NULL UNIQUE,
                        receipt_coin_id TEXT NOT NULL UNIQUE,
                        deed_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 7;
                    COMMIT;
                    """
                )
                version = 7
            if version < 8:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE inventory_reservation_signatures (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        available_coin_id TEXT NOT NULL UNIQUE,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 8;
                    COMMIT;
                    """
                )
                version = 8
            if version < 9:
                self._conn.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE stripe_settlement_delivery_locks (
                        delivery_coin_id TEXT PRIMARY KEY,
                        claim_hash TEXT NOT NULL
                    );
                    INSERT OR IGNORE INTO stripe_settlement_delivery_locks(
                        delivery_coin_id, claim_hash
                    )
                    SELECT deed_coin_id, claim_hash
                    FROM stripe_settlement_signatures;
                    PRAGMA user_version = 9;
                    COMMIT;
                    """
                )

                version = 9
            if version < 10:
                # Preserve the entire v9 table as immutable historical evidence.
                # A separate active pointer permits expiry without deleting a
                # signed claim or weakening permanent purchase uniqueness.
                self._conn.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE inventory_reservation_history (
                        claim_hash TEXT PRIMARY KEY,
                        canonical_claim TEXT NOT NULL,
                        purchase_id TEXT NOT NULL UNIQUE,
                        available_coin_id TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        signed_at INTEGER NOT NULL
                    );
                    INSERT INTO inventory_reservation_history
                        SELECT * FROM inventory_reservation_signatures;
                    CREATE TABLE inventory_reservation_active (
                        available_coin_id TEXT PRIMARY KEY,
                        claim_hash TEXT NOT NULL UNIQUE
                    );
                    INSERT INTO inventory_reservation_active
                        SELECT available_coin_id,claim_hash FROM inventory_reservation_signatures;
                    CREATE TABLE inventory_reservation_retirements (
                        claim_hash TEXT PRIMARY KEY,
                        replacement_claim_hash TEXT NOT NULL UNIQUE,
                        evidence_json TEXT NOT NULL,
                        retired_at INTEGER NOT NULL
                    );
                    PRAGMA user_version = 10;
                    COMMIT;
                """)

    def record_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        scoped_nullifier: str,
        bridge_coin_id: str,
        vault_action: str,
        evm_transaction_hash: str,
        signature: str,
    ) -> str:
        """Record one signature or recover an exact idempotent retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT canonical_claim, signature FROM signatures WHERE claim_hash = ?",
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict("Claim hash collides with different evidence.")
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO signatures(
                        claim_hash, canonical_claim, scoped_nullifier,
                        bridge_coin_id, vault_action, evm_transaction_hash,
                        signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        scoped_nullifier,
                        bridge_coin_id,
                        vault_action,
                        evm_transaction_hash,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Nullifier, bridge coin, EVM event, or vault action was already signed."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_stripe_settlement_batch_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        payment_intent_id: str,
        receipt_coin_id: str,
        delivery_coin_ids: Sequence[str],
        signature: str,
    ) -> str:
        """Bind one external payment and receipt to every deed atomically."""

        delivery_ids = tuple(delivery_coin_ids)
        if not delivery_ids or len(delivery_ids) > 100:
            raise ValueError("Stripe batch requires 1..100 delivery coin IDs")
        if len(set(delivery_ids)) != len(delivery_ids):
            raise ValueError("Stripe batch delivery coin IDs must be unique")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM stripe_settlement_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    locked = tuple(
                        str(row[0])
                        for row in self._conn.execute(
                            """
                            SELECT delivery_coin_id
                            FROM stripe_settlement_delivery_locks
                            WHERE claim_hash = ?
                            ORDER BY rowid
                            """,
                            (claim_hash,),
                        ).fetchall()
                    )
                    if (
                        existing["canonical_claim"] != canonical_claim
                        or locked != delivery_ids
                    ):
                        raise ValidatorLedgerConflict(
                            "Stripe batch retry differs from recorded evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO stripe_settlement_signatures(
                        claim_hash, canonical_claim, purchase_id,
                        payment_intent_id, receipt_coin_id, deed_coin_id,
                        signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        payment_intent_id,
                        receipt_coin_id,
                        delivery_ids[0],
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.executemany(
                    """
                    INSERT INTO stripe_settlement_delivery_locks(
                        delivery_coin_id, claim_hash
                    ) VALUES (?, ?)
                    """,
                    ((delivery_id, claim_hash) for delivery_id in delivery_ids),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Stripe payment, receipt, purchase, or delivery coin was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def healthcheck(self) -> bool:
        with self._lock:
            row = self._conn.execute("PRAGMA quick_check").fetchone()
        return bool(row and row[0] == "ok")

    def record_primary_purchase_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        deed_coin_id: str,
        signature: str,
    ) -> str:
        """Record one deed authorization or recover an exact retry."""

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM primary_purchase_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Purchase claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO primary_purchase_signatures(
                        claim_hash, canonical_claim, purchase_id,
                        deed_coin_id, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        deed_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Purchase or SmartDeed coin was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_primary_purchase_batch_or_recover(
        self,
        *,
        claim_hashes: Sequence[str],
        canonical_claims: Sequence[str],
        purchase_ids: Sequence[str],
        deed_coin_ids: Sequence[str],
        signatures: Sequence[str],
    ) -> tuple[str, ...]:
        """Record every deed authorization in one atomic ledger transaction."""

        lengths = {
            len(claim_hashes),
            len(canonical_claims),
            len(purchase_ids),
            len(deed_coin_ids),
            len(signatures),
        }
        if lengths == {0} or len(lengths) != 1:
            raise ValidatorLedgerConflict(
                "Purchase batch authorization evidence is incomplete."
            )
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            recovered: list[str] = []
            try:
                for claim_hash, canonical_claim, purchase_id, deed_coin_id, signature in zip(
                    claim_hashes,
                    canonical_claims,
                    purchase_ids,
                    deed_coin_ids,
                    signatures,
                    strict=True,
                ):
                    existing = self._conn.execute(
                        """
                        SELECT canonical_claim, signature
                        FROM primary_purchase_signatures
                        WHERE claim_hash = ?
                        """,
                        (claim_hash,),
                    ).fetchone()
                    if existing is not None:
                        if existing["canonical_claim"] != canonical_claim:
                            raise ValidatorLedgerConflict(
                                "Purchase batch claim collides with different evidence."
                            )
                        recovered.append(str(existing["signature"]))
                        continue
                    self._conn.execute(
                        """
                        INSERT INTO primary_purchase_signatures(
                            claim_hash, canonical_claim, purchase_id,
                            deed_coin_id, signature, signed_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            claim_hash,
                            canonical_claim,
                            purchase_id,
                            deed_coin_id,
                            signature,
                            int(time.time()),
                        ),
                    )
                    recovered.append(signature)
                self._conn.execute("COMMIT")
                return tuple(recovered)
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Purchase or SmartDeed coin was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def active_inventory_authorization(self, available_coin_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT h.* FROM inventory_reservation_active a "
                "JOIN inventory_reservation_history h ON h.claim_hash=a.claim_hash "
                "WHERE a.available_coin_id=?", (available_coin_id,)).fetchone()
            return dict(row) if row is not None else None

    def inventory_retirement(self, claim_hash: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM inventory_reservation_retirements WHERE claim_hash=?",
                                     (claim_hash,)).fetchone()
            return dict(row) if row is not None else None

    def record_inventory_reservation_or_recover(
        self, *, claim_hash: str, canonical_claim: str, purchase_id: str,
        available_coin_id: str, signature: str,
        retire_claim_hash: str | None = None, retirement_evidence: dict | None = None,
    ) -> str:
        """Atomically retire an independently verified claim and record its successor.

        Retirement evidence is produced by the private signer, never accepted
        from a public request. Every old claim/purchase and signature survives.
        """
        if (retire_claim_hash is None) != (retirement_evidence is None):
            raise ValidatorLedgerConflict('Inventory retirement evidence is incomplete.')
        if retirement_evidence is not None:
            if (retirement_evidence.get('schema') != 'solslot.validator-inventory-retirement.v1'
                    or retirement_evidence.get('claimHash') != retire_claim_hash
                    or retirement_evidence.get('replacementClaimHash') != claim_hash
                    or retirement_evidence.get('sourceCoinId') != available_coin_id):
                raise ValidatorLedgerConflict('Inventory retirement evidence differs from its claim.')
            encoded = json.dumps(retirement_evidence, sort_keys=True, separators=(',', ':'))
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                active = self._conn.execute('SELECT claim_hash FROM inventory_reservation_active WHERE available_coin_id=?',
                                            (available_coin_id,)).fetchone()
                existing = self._conn.execute('SELECT * FROM inventory_reservation_history WHERE claim_hash=?',
                                              (claim_hash,)).fetchone()
                if existing is not None:
                    if (existing['canonical_claim'] != canonical_claim or existing['purchase_id'] != purchase_id
                            or existing['available_coin_id'] != available_coin_id):
                        raise ValidatorLedgerConflict('Reservation claim hash collides with different evidence.')
                    if active is None or active['claim_hash'] != claim_hash:
                        raise ValidatorLedgerConflict('This inventory authorization was retired and cannot be replayed.')
                    self._conn.execute('COMMIT')
                    return str(existing['signature'])
                if active is not None and active['claim_hash'] != retire_claim_hash:
                    raise ValidatorLedgerConflict('Purchase or available SmartDeed coin was already reserved.')
                if active is None and retire_claim_hash is not None:
                    raise ValidatorLedgerConflict('Inventory authorization changed during retirement proof.')
                self._conn.execute('INSERT INTO inventory_reservation_history VALUES (?,?,?,?,?,?)',
                    (claim_hash, canonical_claim, purchase_id, available_coin_id, signature, int(time.time())))
                if active is None:
                    self._conn.execute('INSERT INTO inventory_reservation_active VALUES (?,?)', (available_coin_id,claim_hash))
                else:
                    self._conn.execute('INSERT INTO inventory_reservation_retirements VALUES (?,?,?,?)',
                        (retire_claim_hash, claim_hash, encoded, int(time.time())))
                    changed = self._conn.execute('UPDATE inventory_reservation_active SET claim_hash=? '
                        'WHERE available_coin_id=? AND claim_hash=?', (claim_hash,available_coin_id,retire_claim_hash))
                    if changed.rowcount != 1:
                        raise ValidatorLedgerConflict('Inventory authorization changed during retirement proof.')
                self._conn.execute('COMMIT')
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute('ROLLBACK')
                raise ValidatorLedgerConflict('Purchase or available SmartDeed coin was already reserved.') from exc
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute('ROLLBACK')
                raise

    def record_voucher_issuance_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        global_payment_id: str,
        series_coin_id: str,
        purchase_launcher_coin_id: str,
        signature: str,
    ) -> str:
        """Record one series transition or recover an exact retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM voucher_issuance_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Voucher claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO voucher_issuance_signatures(
                        claim_hash, canonical_claim, global_payment_id,
                        series_coin_id, purchase_launcher_coin_id,
                        signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        global_payment_id,
                        series_coin_id,
                        purchase_launcher_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Payment, series coin, or purchase launcher was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_stripe_settlement_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        purchase_id: str,
        payment_intent_id: str,
        receipt_coin_id: str,
        delivery_coin_id: str | None = None,
        signature: str,
        deed_coin_id: str | None = None,
    ) -> str:
        """Record one exact paid delivery or recover an identical retry."""

        delivery_ids = {
            value
            for value in (delivery_coin_id, deed_coin_id)
            if value is not None
        }
        if len(delivery_ids) != 1:
            raise ValueError("exactly one Stripe delivery coin ID is required")
        canonical_delivery_coin_id = delivery_ids.pop()

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM stripe_settlement_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Stripe claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO stripe_settlement_signatures(
                        claim_hash,canonical_claim,purchase_id,
                        payment_intent_id,receipt_coin_id,deed_coin_id,
                        signature,signed_at
                    ) VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        purchase_id,
                        payment_intent_id,
                        receipt_coin_id,
                        canonical_delivery_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO stripe_settlement_delivery_locks(
                        delivery_coin_id, claim_hash
                    ) VALUES (?, ?)
                    """,
                    (canonical_delivery_coin_id, claim_hash),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Stripe payment, receipt, purchase, or delivery coin was already authorized."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_voucher_transition_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        global_payment_id: str,
        series_coin_id: str,
        voucher_coin_id: str,
        payment_coin_id: str,
        signature: str,
        deed_coin_id: str | None = None,
    ) -> str:
        """Record one terminal voucher transition or recover an exact retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM voucher_transition_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Voucher transition hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO voucher_transition_signatures(
                        claim_hash, canonical_claim, global_payment_id,
                        series_coin_id, voucher_coin_id, payment_coin_id,
                        deed_coin_id, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        global_payment_id,
                        series_coin_id,
                        voucher_coin_id,
                        payment_coin_id,
                        deed_coin_id,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Voucher, payment, series coin, or payment ID was already settled."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def record_voucher_series_phase_or_recover(
        self,
        *,
        claim_hash: str,
        canonical_claim: str,
        series_coin_id: str,
        transition: int,
        signature: str,
    ) -> str:
        """Record one phase advance or recover an exact idempotent retry."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_claim, signature
                    FROM voucher_series_phase_signatures
                    WHERE claim_hash = ?
                    """,
                    (claim_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_claim"] != canonical_claim:
                        raise ValidatorLedgerConflict(
                            "Series phase claim hash collides with different evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO voucher_series_phase_signatures(
                        claim_hash, canonical_claim, series_coin_id,
                        transition, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_hash,
                        canonical_claim,
                        series_coin_id,
                        transition,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ValidatorLedgerConflict(
                    "Series coin was already authorized for a phase transition."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["ValidatorLedger", "ValidatorLedgerConflict"]
