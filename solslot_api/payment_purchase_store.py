"""Persistent canonical purchase-artifact records.

The coordinator is the authority for the purchase artifact a buyer approved.
Bridge relayers look records up by the domain-separated purchase ID and bind
the first authenticated external payment message before fulfillment.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, asdict
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Mapping
from .inventory_extension_store import InventoryExtensionStoreMixin, migrate_extensions
from .inventory_payment_hold_store import InventoryPaymentHoldStoreMixin, migrate_checkout_holds, assert_no_checkout_hold
from .purchase_admission import PurchaseAdmissionStoreMixin, migrate_purchase_admission, close_inventory_admission
from .checkout_terminal_store import CheckoutTerminalStoreMixin, migrate_checkout_terminals
from .checkout_lifecycle_store import CheckoutLifecycleStoreMixin, migrate_lifecycle


class PaymentPurchaseNotFound(LookupError):
    pass


class PaymentPurchaseConflict(ValueError):
    pass


@dataclass(frozen=True)
class StoredPaymentInventoryItem:
    ordinal: int
    deed_launcher_id: str
    child_purchase_id: str
    child_artifact_hash: str
    state: str
    available_coin_id: str | None
    reserved_coin_id: str | None
    reserved_puzzle_hash: str | None
    signer_indices: tuple[int, ...]
    signature: str | None


@dataclass(frozen=True)
class StoredPaymentPurchase:
    purchase_id: str
    artifact_hash: str
    purchase_intent_id: str
    rail: str
    quote_expires_at: int
    offer_artifact_hash: str
    offer_artifact: dict[str, Any]
    purchase_artifact: dict[str, Any]
    external_message: dict[str, Any] | None
    deed_launcher_id: str | None = None
    deed_launcher_ids: tuple[str, ...] = ()
    inventory_state: str = "UNRESERVED"
    inventory_available_coin_id: str | None = None
    inventory_reserved_coin_id: str | None = None
    inventory_reserved_puzzle_hash: str | None = None
    inventory_expires_at: int | None = None
    inventory_bundle: dict[str, Any] | None = None
    inventory_bundle_id: str | None = None
    inventory_signer_indices: tuple[int, ...] = ()
    inventory_signature: str | None = None
    inventory_mempool_observed_at: str | None = None
    inventory_confirmation_height: int | None = None
    inventory_extension_receipts: tuple[dict[str, Any], ...] = ()


class PaymentPurchaseStore(InventoryExtensionStoreMixin, InventoryPaymentHoldStoreMixin, PurchaseAdmissionStoreMixin, CheckoutTerminalStoreMixin, CheckoutLifecycleStoreMixin):
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS payment_purchases (
                    purchase_id TEXT PRIMARY KEY,
                    artifact_hash TEXT NOT NULL UNIQUE,
                    purchase_intent_id TEXT NOT NULL UNIQUE,
                    rail TEXT NOT NULL,
                    quote_expires_at INTEGER NOT NULL,
                    offer_artifact_hash TEXT NOT NULL,
                    offer_artifact_json TEXT NOT NULL,
                    purchase_artifact_json TEXT NOT NULL,
                    external_global_payment_id TEXT UNIQUE,
                    external_transaction_hash TEXT,
                    external_message_json TEXT,
                    deed_launcher_id TEXT,
                    deed_launcher_ids_json TEXT NOT NULL DEFAULT '[]',
                    inventory_state TEXT NOT NULL DEFAULT 'UNRESERVED',
                    inventory_available_coin_id TEXT,
                    inventory_reserved_coin_id TEXT UNIQUE,
                    inventory_reserved_puzzle_hash TEXT,
                    inventory_expires_at INTEGER,
                    inventory_bundle_json TEXT,
                    inventory_bundle_id TEXT UNIQUE,
                    inventory_signer_indices_json TEXT NOT NULL DEFAULT '[]',
                    inventory_signature TEXT,
                    inventory_mempool_observed_at TEXT,
                    inventory_confirmation_height INTEGER,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS payment_purchases_expiry
                    ON payment_purchases(quote_expires_at);
                CREATE TABLE IF NOT EXISTS payment_purchase_inventory_items (
                    purchase_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    deed_launcher_id TEXT NOT NULL,
                    child_purchase_id TEXT NOT NULL UNIQUE,
                    child_artifact_hash TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL DEFAULT 'UNRESERVED',
                    available_coin_id TEXT,
                    reserved_coin_id TEXT UNIQUE,
                    reserved_puzzle_hash TEXT,
                    signer_indices_json TEXT NOT NULL DEFAULT '[]',
                    signature TEXT,
                    PRIMARY KEY (purchase_id, ordinal),
                    UNIQUE (purchase_id, deed_launcher_id),
                    FOREIGN KEY (purchase_id) REFERENCES payment_purchases(purchase_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS payment_inventory_expiries (
                    purchase_id TEXT PRIMARY KEY,
                    evidence_json TEXT NOT NULL,
                    FOREIGN KEY (purchase_id) REFERENCES payment_purchases(purchase_id)
                );
                CREATE TABLE IF NOT EXISTS payment_inventory_releases (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    purchase_id TEXT NOT NULL UNIQUE,
                    evidence_json TEXT NOT NULL,
                    FOREIGN KEY (purchase_id) REFERENCES payment_purchases(purchase_id)
                );
                CREATE TABLE IF NOT EXISTS payment_inventory_timeouts (
                    purchase_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    binding_json TEXT NOT NULL,
                    prepared_json TEXT,
                    fee_coin_id TEXT UNIQUE,
                    state TEXT NOT NULL DEFAULT 'PREPARING',
                    receipt_json TEXT,
                    lease_owner TEXT,
                    lease_until INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (purchase_id, ordinal),
                    FOREIGN KEY (purchase_id, ordinal)
                        REFERENCES payment_purchase_inventory_items(purchase_id, ordinal)
                );
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(payment_purchases)"
                ).fetchall()
            }
            if "external_transaction_hash" not in columns:
                connection.execute(
                    "ALTER TABLE payment_purchases "
                    "ADD COLUMN external_transaction_hash TEXT"
                )
            inventory_columns = {
                "deed_launcher_id": "TEXT",
                "deed_launcher_ids_json": "TEXT NOT NULL DEFAULT '[]'",
                "inventory_state": "TEXT NOT NULL DEFAULT 'UNRESERVED'",
                "inventory_available_coin_id": "TEXT",
                "inventory_reserved_coin_id": "TEXT",
                "inventory_reserved_puzzle_hash": "TEXT",
                "inventory_expires_at": "INTEGER",
                "inventory_bundle_json": "TEXT",
                "inventory_bundle_id": "TEXT",
                "inventory_signer_indices_json": "TEXT NOT NULL DEFAULT '[]'",
                "inventory_signature": "TEXT",
                "inventory_mempool_observed_at": "TEXT",
                "inventory_confirmation_height": "INTEGER",
                "inventory_extension_receipts_json": "TEXT NOT NULL DEFAULT '[]'",
            }
            for name, declaration in inventory_columns.items():
                if name not in columns:
                    cursor = connection.execute(
                        f"ALTER TABLE payment_purchases ADD COLUMN {name} {declaration}"
                    )
            migrate_extensions(connection)
            migrate_checkout_holds(connection)
            migrate_checkout_terminals(connection)
            migrate_purchase_admission(connection)
            migrate_lifecycle(connection)
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_external_transaction "
                "ON payment_purchases(external_transaction_hash)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_inventory_bundle "
                "ON payment_purchases(inventory_bundle_id) "
                "WHERE inventory_bundle_id IS NOT NULL"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_reserved_coin "
                "ON payment_purchases(inventory_reserved_coin_id) "
                "WHERE inventory_reserved_coin_id IS NOT NULL"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchases_active_deed_reservation "
                "ON payment_purchases(deed_launcher_id) "
                "WHERE deed_launcher_id IS NOT NULL AND inventory_state IN "
                "('PREPARED', 'SUBMITTED', 'CONFIRMED')"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "payment_purchase_inventory_active_deed "
                "ON payment_purchase_inventory_items(deed_launcher_id) "
                "WHERE state IN ('PREPARED', 'SUBMITTED', 'CONFIRMED')"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
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

    def save(
        self,
        *,
        purchase_intent_id: str,
        rail: str,
        offer_artifact_hash: str,
        offer_artifact: Mapping[str, Any],
        purchase_artifact: Mapping[str, Any],
        created_at: int,
    ) -> StoredPaymentPurchase:
        purchase_id = _required_string(purchase_artifact, "purchaseId")
        if purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            artifact_hash = _required_string(purchase_artifact, "batchHash")
            children = purchase_artifact.get("artifacts")
            if not isinstance(children, list) or not children:
                raise PaymentPurchaseConflict(
                    "purchase batch must contain canonical child artifacts"
                )
            quote_expires_at = min(
                _required_decimal(child, "quoteExpiresAt")
                for child in children
                if isinstance(child, Mapping)
            )
            deed_launcher_ids = tuple(
                value
                for value in (
                    _optional_nonzero_hex32(child.get("deedLauncherId"))
                    for child in children
                    if isinstance(child, Mapping)
                )
                if value is not None
            )
            if len(deed_launcher_ids) != len(children):
                raise PaymentPurchaseConflict(
                    "purchase batch child deed commitments are incomplete"
                )
            inventory_children = tuple(children)
        else:
            artifact_hash = _required_string(purchase_artifact, "artifactHash")
            quote_expires_at = _required_decimal(
                purchase_artifact,
                "quoteExpiresAt",
            )
            single_launcher = _optional_nonzero_hex32(
                purchase_artifact.get("deedLauncherId")
            )
            deed_launcher_ids = (
                (single_launcher,) if single_launcher is not None else ()
            )
            inventory_children = (
                (purchase_artifact,) if single_launcher is not None else ()
            )
        if len(set(deed_launcher_ids)) != len(deed_launcher_ids):
            raise PaymentPurchaseConflict(
                "purchase contains duplicate SmartDeed launchers"
            )
        deed_launcher_id = deed_launcher_ids[0] if deed_launcher_ids else None
        deed_launcher_ids_json = json.dumps(list(deed_launcher_ids))
        offer_json = _canonical_json(offer_artifact)
        purchase_json = _canonical_json(purchase_artifact)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM payment_purchases
                WHERE purchase_id = ? OR artifact_hash = ?
                   OR purchase_intent_id = ?
                """,
                (purchase_id, artifact_hash, purchase_intent_id),
            ).fetchone()
            if existing is not None:
                record = _record(existing)
                if (
                    record.purchase_id != purchase_id
                    or record.artifact_hash != artifact_hash
                    or record.purchase_intent_id != purchase_intent_id
                    or record.rail != rail
                    or _canonical_json(record.purchase_artifact)
                    != purchase_json
                ):
                    connection.execute("ROLLBACK")
                    raise PaymentPurchaseConflict(
                        "purchase intent is already bound to another artifact"
                    )
                connection.execute("COMMIT")
                return record
            connection.execute(
                """
                INSERT INTO payment_purchases (
                    purchase_id,
                    artifact_hash,
                    purchase_intent_id,
                    rail,
                    quote_expires_at,
                    offer_artifact_hash,
                    offer_artifact_json,
                    purchase_artifact_json,
                    deed_launcher_id,
                    deed_launcher_ids_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    purchase_id,
                    artifact_hash,
                    purchase_intent_id,
                    rail,
                    quote_expires_at,
                    offer_artifact_hash,
                    offer_json,
                    purchase_json,
                    deed_launcher_id,
                    deed_launcher_ids_json,
                    created_at,
                ),
            )
            for ordinal, child in enumerate(inventory_children):
                connection.execute(
                    """
                    INSERT INTO payment_purchase_inventory_items (
                        purchase_id, ordinal, deed_launcher_id,
                        child_purchase_id, child_artifact_hash
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        purchase_id,
                        ordinal,
                        deed_launcher_ids[ordinal],
                        _required_string(child, "purchaseId"),
                        _required_string(child, "artifactHash"),
                    ),
                )
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def inventory_status_snapshot(self, purchase_id: str):
        """Read parent, items and recovery receipts from one SQLite snapshot."""
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM payment_purchases WHERE purchase_id=?", (purchase_id,)).fetchone()
            if row is None:
                raise PaymentPurchaseNotFound("Purchase was not found")
            items = connection.execute("SELECT * FROM payment_purchase_inventory_items WHERE purchase_id=? ORDER BY ordinal", (purchase_id,)).fetchall()
            expired = connection.execute("SELECT evidence_json FROM payment_inventory_expiries WHERE purchase_id=?", (purchase_id,)).fetchone()
            released = connection.execute("SELECT evidence_json FROM payment_inventory_releases WHERE purchase_id=?", (purchase_id,)).fetchone()
            connection.execute("COMMIT")
        try:
            return (_record(row), tuple(_inventory_item(item) for item in items),
                    json.loads(expired[0]) if expired else None, json.loads(released[0]) if released else None)
        except (ValueError, TypeError, KeyError) as exc:
            raise PaymentPurchaseConflict("Inventory evidence is malformed; keep the purchase for review") from exc

    def inventory_items(
        self,
        purchase_id: str,
    ) -> tuple[StoredPaymentInventoryItem, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM payment_purchase_inventory_items
                WHERE purchase_id = ? ORDER BY ordinal
                """,
                (purchase_id,),
            ).fetchall()
        return tuple(_inventory_item(row) for row in rows)

    def claim_inventory_timeout(self, purchase_id: str, ordinal: int, *,
                                binding: Mapping[str, Any], owner: str,
                                now: int, lease_seconds: int = 120) -> dict[str, Any]:
        """Lease one exact input; wall time controls only coordination, never expiry."""
        canonical = _canonical_json(binding)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assert_no_checkout_hold(connection,purchase_id)
            if connection.execute('SELECT 1 FROM payment_inventory_extensions WHERE purchase_id=?', (purchase_id,)).fetchone():
                raise PaymentPurchaseConflict('payment hold requires authoritative terminal reconciliation; timeout cannot release inventory')
            item = connection.execute(
                "SELECT state FROM payment_purchase_inventory_items WHERE purchase_id=? AND ordinal=?",
                (purchase_id, ordinal)).fetchone()
            if item is None or item["state"] not in ("PREPARED", "SUBMITTED", "CONFIRMED"):
                raise PaymentPurchaseConflict("timeout requires retained active inventory")
            connection.execute(
                "INSERT OR IGNORE INTO payment_inventory_timeouts(purchase_id,ordinal,binding_json) VALUES (?,?,?)",
                (purchase_id, ordinal, canonical))
            row = connection.execute(
                "SELECT * FROM payment_inventory_timeouts WHERE purchase_id=? AND ordinal=?",
                (purchase_id, ordinal)).fetchone()
            if row["binding_json"] != canonical:
                raise PaymentPurchaseConflict("timeout network, deployment, release or input binding changed")
            if row["lease_owner"] is not None and row["lease_until"] > now:
                raise PaymentPurchaseConflict("timeout recovery is already in progress; retry later")
            connection.execute(
                "UPDATE payment_inventory_timeouts SET lease_owner=?,lease_until=? WHERE purchase_id=? AND ordinal=?",
                (owner, now + lease_seconds, purchase_id, ordinal))
            connection.execute("COMMIT")
        return json.loads(row["prepared_json"]) if row["prepared_json"] else {}

    def preserve_inventory_timeout(self, purchase_id: str, ordinal: int, *, owner: str,
                                    now: int, prepared: Mapping[str, Any]) -> None:
        """Commit full fee-funded bytes before push. An existing bundle is immutable."""
        canonical = _canonical_json(prepared)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM payment_inventory_timeouts WHERE purchase_id=? AND ordinal=?",
                (purchase_id, ordinal)).fetchone()
            if row is None or row["lease_owner"] != owner or row["lease_until"] <= now:
                raise PaymentPurchaseConflict("timeout lease expired before dispatch")
            if row["prepared_json"] is not None and row["prepared_json"] != canonical:
                raise PaymentPurchaseConflict("the exact timeout bundle cannot be replaced")
            try:
                connection.execute(
                    "UPDATE payment_inventory_timeouts SET prepared_json=?,fee_coin_id=?,state='PREPARED' "
                    "WHERE purchase_id=? AND ordinal=?",
                    (canonical, prepared["feeCoinId"], purchase_id, ordinal))
            except sqlite3.IntegrityError as exc:
                raise PaymentPurchaseConflict("timeout fee coin is already reserved") from exc
            connection.execute("COMMIT")

    def finish_inventory_timeout_attempt(self, purchase_id: str, ordinal: int, *, owner: str,
                                         receipt: Mapping[str, Any] | None = None) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if receipt is not None:
                connection.execute(
                    "UPDATE payment_inventory_timeouts SET state='SUBMITTED',receipt_json=? "
                    "WHERE purchase_id=? AND ordinal=? AND lease_owner=? AND prepared_json IS NOT NULL",
                    (_canonical_json(receipt), purchase_id, ordinal, owner))
            connection.execute(
                "UPDATE payment_inventory_timeouts SET lease_owner=NULL,lease_until=0 "
                "WHERE purchase_id=? AND ordinal=? AND lease_owner=?",
                (purchase_id, ordinal, owner))
            connection.execute("COMMIT")

    def inventory_timeout_operations(self, purchase_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM payment_inventory_timeouts WHERE purchase_id=? ORDER BY ordinal",
                (purchase_id,)).fetchall()
        return [dict(ordinal=row["ordinal"], state=row["state"],
                     binding=json.loads(row["binding_json"]),
                     prepared=json.loads(row["prepared_json"]) if row["prepared_json"] else None,
                     receipt=json.loads(row["receipt_json"]) if row["receipt_json"] else None) for row in rows]

    def pending_timeout_fee_coin_ids(self) -> tuple[str, ...]:
        # Conservatively retain all exact fee inputs, including after an external
        # release. Neither local expiry nor a failed/unknown push authorizes reuse.
        with self._connect() as connection:
            return tuple(row[0] for row in connection.execute(
                "SELECT fee_coin_id FROM payment_inventory_timeouts WHERE fee_coin_id IS NOT NULL"))

    def record_inventory_batch_prepared(
        self,
        purchase_id: str,
        *,
        items: tuple[Mapping[str, Any], ...],
        bundle: Mapping[str, Any],
    ) -> StoredPaymentPurchase:
        """Atomically bind every selected deed to one reservation bundle."""

        if not items:
            raise PaymentPurchaseConflict(
                "reservation manifest must contain at least one SmartDeed"
            )
        bundle_json = _canonical_json(bundle)
        normalized_items: list[dict[str, Any]] = []
        for item in items:
            try:
                signer_indices = tuple(int(value) for value in item["signer_indices"])
                normalized_items.append(
                    {
                        "deed_launcher_id": str(item["deed_launcher_id"]),
                        "available_coin_id": str(item["available_coin_id"]),
                        "reserved_coin_id": str(item["reserved_coin_id"]),
                        "reserved_puzzle_hash": str(item["reserved_puzzle_hash"]),
                        "expires_at": int(item["expires_at"]),
                        "signer_indices_json": json.dumps(list(signer_indices)),
                        "signature": str(item["signature"]),
                    }
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PaymentPurchaseConflict(
                    "reservation manifest is incomplete"
                ) from exc
        expires_at = normalized_items[0]["expires_at"]
        if any(item["expires_at"] != expires_at for item in normalized_items):
            raise PaymentPurchaseConflict(
                "all SmartDeeds in a batch must share one reservation expiry"
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            parent = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            rows = connection.execute(
                """SELECT * FROM payment_purchase_inventory_items
                   WHERE purchase_id = ? ORDER BY ordinal""",
                (purchase_id,),
            ).fetchall()
            if parent is None or not rows:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound("purchase inventory was not found")
            if len(rows) != len(normalized_items):
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "reservation manifest does not match the purchase quantity"
                )
            try:
                for row, item in zip(rows, normalized_items, strict=True):
                    expected_launcher = str(row["deed_launcher_id"])
                    if item["deed_launcher_id"] != expected_launcher:
                        raise PaymentPurchaseConflict(
                            "reservation manifest changes a SmartDeed launcher"
                        )
                    expected_values = {
                        "available_coin_id": item["available_coin_id"],
                        "reserved_coin_id": item["reserved_coin_id"],
                        "reserved_puzzle_hash": item["reserved_puzzle_hash"],
                        "signer_indices_json": item["signer_indices_json"],
                        "signature": item["signature"],
                    }
                    if row["state"] == "PREPARED":
                        if any(row[name] != value for name, value in expected_values.items()):
                            raise PaymentPurchaseConflict(
                                "prepared reservation evidence cannot be changed"
                            )
                        continue
                    if row["state"] != "UNRESERVED":
                        raise PaymentPurchaseConflict(
                            "reservation item is not in a preparable state"
                        )
                    cursor = connection.execute(
                        """
                        UPDATE payment_purchase_inventory_items
                        SET state='PREPARED', available_coin_id=?,
                            reserved_coin_id=?, reserved_puzzle_hash=?,
                            signer_indices_json=?, signature=?
                        WHERE purchase_id=? AND ordinal=?
                          AND state IN ('UNRESERVED', 'PREPARED')
                        """,
                        (
                            item["available_coin_id"],
                            item["reserved_coin_id"],
                            item["reserved_puzzle_hash"],
                            item["signer_indices_json"],
                            item["signature"],
                            purchase_id,
                            int(row["ordinal"]),
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise PaymentPurchaseConflict(
                            "reservation item is not in a preparable state"
                        )
                first = normalized_items[0]
                parent_values = {
                    "inventory_available_coin_id": first["available_coin_id"],
                    "inventory_reserved_coin_id": first["reserved_coin_id"],
                    "inventory_reserved_puzzle_hash": first["reserved_puzzle_hash"],
                    "inventory_expires_at": expires_at,
                    "inventory_bundle_json": bundle_json,
                    "inventory_signer_indices_json": first["signer_indices_json"],
                    "inventory_signature": first["signature"],
                }
                if parent["inventory_state"] == "PREPARED":
                    if any(parent[name] != value for name, value in parent_values.items()):
                        raise PaymentPurchaseConflict(
                            "prepared batch evidence cannot be changed"
                        )
                elif parent["inventory_state"] == "UNRESERVED":
                    parent_cursor = connection.execute(
                        """
                        UPDATE payment_purchases
                        SET inventory_state='PREPARED',
                            inventory_available_coin_id=?,
                            inventory_reserved_coin_id=?,
                            inventory_reserved_puzzle_hash=?,
                            inventory_expires_at=?, inventory_bundle_json=?,
                            inventory_signer_indices_json=?, inventory_signature=?
                        WHERE purchase_id=? AND inventory_state='UNRESERVED'
                        """,
                        (
                            *parent_values.values(),
                            purchase_id,
                        ),
                    )
                    if parent_cursor.rowcount != 1:
                        raise PaymentPurchaseConflict(
                            "reservation batch is not in a preparable state"
                        )
                else:
                    raise PaymentPurchaseConflict(
                        "reservation batch is not in a preparable state"
                    )
            except (
                KeyError,
                TypeError,
                ValueError,
                sqlite3.IntegrityError,
                PaymentPurchaseConflict,
            ) as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "one or more SmartDeeds are already reserved"
                ) from exc
            result = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert result is not None
        return _record(result)

    def record_inventory_prepared(
        self,
        purchase_id: str,
        *,
        available_coin_id: str,
        reserved_coin_id: str,
        reserved_puzzle_hash: str,
        expires_at: int,
        bundle: Mapping[str, Any],
        signer_indices: tuple[int, ...],
        signature: str,
    ) -> StoredPaymentPurchase:
        record = self.get(purchase_id)
        if record.deed_launcher_id is None:
            raise PaymentPurchaseConflict(
                "purchase has no SmartDeed inventory commitment"
            )
        return self.record_inventory_batch_prepared(
            purchase_id,
            items=(
                {
                    "deed_launcher_id": record.deed_launcher_id,
                    "available_coin_id": available_coin_id,
                    "reserved_coin_id": reserved_coin_id,
                    "reserved_puzzle_hash": reserved_puzzle_hash,
                    "expires_at": expires_at,
                    "signer_indices": signer_indices,
                    "signature": signature,
                },
            ),
            bundle=bundle,
        )

    def record_inventory_submitted(
        self,
        purchase_id: str,
        *,
        bundle_id: str,
        mempool_observed_at: str,
    ) -> StoredPaymentPurchase:
        result = self._transition_inventory(
            purchase_id,
            expected_states=("PREPARED", "SUBMITTED"),
            next_state="SUBMITTED",
            values={
                "inventory_bundle_id": bundle_id,
                "inventory_mempool_observed_at": mempool_observed_at,
            },
        )
        return result

    def record_inventory_confirmed(
        self,
        purchase_id: str,
        *,
        confirmation_height: int,
    ) -> StoredPaymentPurchase:
        result = self._transition_inventory(
            purchase_id,
            expected_states=("SUBMITTED", "CONFIRMED"),
            next_state="CONFIRMED",
            values={"inventory_confirmation_height": confirmation_height},
        )
        return result

    def inventory_expiry_evidence(self, purchase_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute('SELECT evidence_json FROM payment_inventory_expiries WHERE purchase_id=?',
                                     (purchase_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def record_inventory_authorization_expired(self, purchase_id: str, *, evidence: Mapping[str, Any]) -> StoredPaymentPurchase:
        """Internal atomic commit of the observer's exact preflight snapshot.

        Keep bundle bytes, input identity, purchase uniqueness and fee records.
        This is not a chain release and must never advance a release cursor.
        """
        encoded = _canonical_json(evidence)
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            assert_no_checkout_hold(connection,purchase_id)
            try:
                row = connection.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
                if row is None:
                    raise PaymentPurchaseNotFound('purchase artifact was not found')
                stored = _record(row)
                old = connection.execute('SELECT evidence_json FROM payment_inventory_expiries WHERE purchase_id=?', (purchase_id,)).fetchone()
                if old is not None:
                    if old[0] != encoded or stored.inventory_state != 'AUTHORIZATION_EXPIRED':
                        raise PaymentPurchaseConflict('authorization expiry evidence cannot be changed')
                    connection.execute('COMMIT')
                    return stored
                rows = connection.execute('SELECT * FROM payment_purchase_inventory_items WHERE purchase_id=? ORDER BY ordinal', (purchase_id,)).fetchall()
                # Read through the same transaction: normal transitions cannot race this compare-and-set.
                current_items = [asdict(_inventory_item(r)) for r in rows]
                if (evidence.get('schema') != 'solslot.inventory-authorization-expiry.v1'
                        or evidence.get('purchaseId') != purchase_id
                        or stored.inventory_state not in {'PREPARED', 'SUBMITTED'}
                        or stored.inventory_confirmation_height is not None or stored.external_message is not None
                        or _canonical_json(evidence.get('snapshot')) != _canonical_json(asdict(stored))
                        or _canonical_json({'items': evidence.get('items')}) != _canonical_json({'items': current_items})
                        or not rows or len(evidence.get('chainProofs', [])) != len(rows)
                        or any(r['state'] != stored.inventory_state for r in rows)
                        or any(p.get('schema') != 'solslot.inventory-expiry-chain.v1'
                            or p.get('network') != 'testnet11' or p.get('sourceCoinId') != r['available_coin_id']
                            or p.get('expiresAt') != stored.inventory_expires_at
                            or type(p.get('matureTimestamp')) is not int or p['matureTimestamp'] < stored.inventory_expires_at
                            for r, p in zip(rows, evidence['chainProofs'], strict=True))):
                    raise PaymentPurchaseConflict('authorization changed during expiry proof')
                connection.execute('INSERT INTO payment_inventory_expiries VALUES (?,?)', (purchase_id, encoded))
                connection.execute("UPDATE payment_purchases SET inventory_state='AUTHORIZATION_EXPIRED' WHERE purchase_id=?", (purchase_id,))
                connection.execute("UPDATE payment_purchase_inventory_items SET state='AUTHORIZATION_EXPIRED' WHERE purchase_id=?", (purchase_id,))
                close_inventory_admission(connection,purchase_id)
                result = connection.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
                connection.execute('COMMIT')
                return _record(result)
            except Exception:
                if connection.in_transaction:
                    connection.execute('ROLLBACK')
                raise

    def inventory_release_evidence(self, purchase_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT evidence_json FROM payment_inventory_releases WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def latest_released_inventory(self, deed_launcher_id: str) -> dict[str, Any] | None:
        """A read cursor only; callers must revalidate its current chain lineage."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT r.evidence_json FROM payment_inventory_releases r "
                "JOIN payment_purchase_inventory_items i ON i.purchase_id=r.purchase_id "
                "WHERE i.deed_launcher_id=? AND i.state='RELEASED' "
                "ORDER BY r.sequence DESC LIMIT 1", (deed_launcher_id,),
            ).fetchone()
        if row is None:
            return None
        return next(item for item in json.loads(row[0])["items"]
                    if item["deedLauncherId"] == deed_launcher_id)

    def record_inventory_released(self, purchase_id: str, *, evidence: Mapping[str, Any],
                                  expected_snapshot: StoredPaymentPurchase | None = None,
                                  expected_items: tuple[StoredPaymentInventoryItem, ...] | None = None) -> StoredPaymentPurchase:
        """Commit a complete, independently reconciled timeout batch and its cursor.

        This internal persistence method accepts only the reconciler's exact
        evidence. Public requests cannot provide release evidence. Original
        artifacts, signed bundles and validator tombstones remain unchanged.
        """
        encoded = _canonical_json(evidence)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assert_no_checkout_hold(connection,purchase_id)
            if connection.execute('SELECT 1 FROM payment_inventory_extensions WHERE purchase_id=?', (purchase_id,)).fetchone():
                raise PaymentPurchaseConflict('payment hold requires authoritative terminal reconciliation; timeout cannot release inventory')
            try:
                parent = connection.execute("SELECT * FROM payment_purchases WHERE purchase_id=?", (purchase_id,)).fetchone()
                rows = connection.execute("SELECT * FROM payment_purchase_inventory_items WHERE purchase_id=? ORDER BY ordinal", (purchase_id,)).fetchall()
                if parent is None:
                    raise PaymentPurchaseNotFound("purchase artifact was not found")
                old = connection.execute("SELECT evidence_json FROM payment_inventory_releases WHERE purchase_id=?", (purchase_id,)).fetchone()
                if old is not None:
                    if (old[0] != encoded or parent["inventory_state"] != "RELEASED"
                            or not rows or any(row["state"] != "RELEASED" for row in rows)):
                        raise PaymentPurchaseConflict("confirmed release evidence cannot be changed")
                    connection.execute("COMMIT")
                    return _record(parent)
                if (expected_snapshot is None or expected_items is None
                        or _record(parent) != expected_snapshot
                        or tuple(_inventory_item(row) for row in rows) != expected_items):
                    raise PaymentPurchaseConflict("reservation changed during timeout proof; retry reconciliation")
                items = evidence.get("items")
                if (evidence.get("schema") != "solslot.inventory-timeout-release.v1"
                        or not isinstance(items, list) or not rows or len(items) != len(rows)
                        or parent["inventory_state"] not in {"PREPARED", "SUBMITTED", "CONFIRMED"}):
                    raise PaymentPurchaseConflict("incomplete or invalid inventory release")
                for row, item in zip(rows, items, strict=True):
                    if (row["state"] != parent["inventory_state"]
                            or item.get("ordinal") != row["ordinal"]
                            or item.get("deedLauncherId") != row["deed_launcher_id"]
                            or item.get("reservedCoinId") != row["reserved_coin_id"]
                            or not item.get("availableCoinId") or not item.get("releaseSpend")
                            or type(item.get("confirmationHeight")) is not int or item["confirmationHeight"] <= 0):
                        raise PaymentPurchaseConflict("release evidence changes the reserved batch")
                connection.execute("INSERT INTO payment_inventory_releases(purchase_id,evidence_json) VALUES (?,?)", (purchase_id, encoded))
                connection.execute("UPDATE payment_purchases SET inventory_state='RELEASED' WHERE purchase_id=?", (purchase_id,))
                connection.execute("UPDATE payment_purchase_inventory_items SET state='RELEASED' WHERE purchase_id=?", (purchase_id,))
                connection.execute("UPDATE payment_inventory_timeouts SET state='CONFIRMED',lease_owner=NULL,lease_until=0 WHERE purchase_id=?", (purchase_id,))
                close_inventory_admission(connection,purchase_id)
                result = connection.execute("SELECT * FROM payment_purchases WHERE purchase_id=?", (purchase_id,)).fetchone()
                connection.execute("COMMIT")
                return _record(result)
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _transition_inventory(
        self,
        purchase_id: str,
        *,
        expected_states: tuple[str, ...],
        next_state: str,
        values: Mapping[str, Any],
    ) -> StoredPaymentPurchase:
        assignments = ["inventory_state = ?", *[f"{name} = ?" for name in values]]
        parameters = [next_state, *values.values(), purchase_id, *expected_states]
        placeholders = ", ".join("?" for _ in expected_states)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    f"UPDATE payment_purchases SET {', '.join(assignments)} "
                    f"WHERE purchase_id = ? AND inventory_state IN ({placeholders})",
                    parameters,
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "SmartDeed inventory is already reserved by another purchase"
                ) from exc
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                    (purchase_id,),
                ).fetchone()
                connection.execute("ROLLBACK")
                if row is None:
                    raise PaymentPurchaseNotFound("purchase artifact was not found")
                record = _record(row)
                if record.inventory_state == next_state and all(
                    row[name] == value for name, value in values.items()
                ):
                    return record
                raise PaymentPurchaseConflict(
                    f"inventory transition {record.inventory_state} -> {next_state} is not allowed"
                )
            item_cursor = connection.execute(
                f"UPDATE payment_purchase_inventory_items SET state=? "
                f"WHERE purchase_id=? AND state IN ({placeholders})",
                (next_state, purchase_id, *expected_states),
            )
            item_total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM payment_purchase_inventory_items "
                    "WHERE purchase_id=?",
                    (purchase_id,),
                ).fetchone()[0]
            )
            if item_total < 1 or item_cursor.rowcount != item_total:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "inventory item transition is incomplete"
                )
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)

    def get(self, purchase_id: str) -> StoredPaymentPurchase:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
        if row is None:
            raise PaymentPurchaseNotFound("purchase artifact was not found")
        return _record(row)

    def bind_external_message(
        self,
        purchase_id: str,
        message: Mapping[str, Any],
    ) -> StoredPaymentPurchase:
        message_json = _canonical_json(message)
        global_payment_id = _required_string(message, "globalPaymentId")
        source = _required_mapping(message, "source")
        transaction_hash = _required_string(source, "transactionHash")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseNotFound(
                    "purchase artifact was not found"
                )
            existing_json = row["external_message_json"]
            if existing_json is not None:
                if existing_json != message_json:
                    connection.execute("ROLLBACK")
                    raise PaymentPurchaseConflict(
                        "purchase is already bound to another external payment"
                    )
                connection.execute("COMMIT")
                return _record(row)
            try:
                connection.execute(
                    """
                    UPDATE payment_purchases
                    SET external_global_payment_id = ?,
                        external_transaction_hash = ?,
                        external_message_json = ?
                    WHERE purchase_id = ?
                    """,
                    (
                        global_payment_id,
                        transaction_hash,
                        message_json,
                        purchase_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise PaymentPurchaseConflict(
                    "external payment is already bound to another purchase"
                ) from exc
            row = connection.execute(
                "SELECT * FROM payment_purchases WHERE purchase_id = ?",
                (purchase_id,),
            ).fetchone()
            connection.execute("COMMIT")
        assert row is not None
        return _record(row)


def _record(row: sqlite3.Row) -> StoredPaymentPurchase:
    external_json = row["external_message_json"]
    inventory_bundle_json = row["inventory_bundle_json"]
    return StoredPaymentPurchase(
        inventory_extension_receipts=tuple(json.loads(row["inventory_extension_receipts_json"])),
        purchase_id=row["purchase_id"],
        artifact_hash=row["artifact_hash"],
        purchase_intent_id=row["purchase_intent_id"],
        rail=row["rail"],
        quote_expires_at=int(row["quote_expires_at"]),
        offer_artifact_hash=row["offer_artifact_hash"],
        offer_artifact=json.loads(row["offer_artifact_json"]),
        purchase_artifact=json.loads(row["purchase_artifact_json"]),
        external_message=(
            json.loads(external_json) if external_json is not None else None
        ),
        deed_launcher_id=row["deed_launcher_id"],
        deed_launcher_ids=tuple(
            str(value) for value in json.loads(row["deed_launcher_ids_json"])
        ),
        inventory_state=row["inventory_state"],
        inventory_available_coin_id=row["inventory_available_coin_id"],
        inventory_reserved_coin_id=row["inventory_reserved_coin_id"],
        inventory_reserved_puzzle_hash=row["inventory_reserved_puzzle_hash"],
        inventory_expires_at=(
            int(row["inventory_expires_at"])
            if row["inventory_expires_at"] is not None
            else None
        ),
        inventory_bundle=(
            json.loads(inventory_bundle_json)
            if inventory_bundle_json is not None
            else None
        ),
        inventory_bundle_id=row["inventory_bundle_id"],
        inventory_signer_indices=tuple(
            int(value)
            for value in json.loads(row["inventory_signer_indices_json"])
        ),
        inventory_signature=row["inventory_signature"],
        inventory_mempool_observed_at=row["inventory_mempool_observed_at"],
        inventory_confirmation_height=(
            int(row["inventory_confirmation_height"])
            if row["inventory_confirmation_height"] is not None
            else None
        ),
    )


def _inventory_item(row: sqlite3.Row) -> StoredPaymentInventoryItem:
    return StoredPaymentInventoryItem(
        ordinal=int(row["ordinal"]),
        deed_launcher_id=str(row["deed_launcher_id"]),
        child_purchase_id=str(row["child_purchase_id"]),
        child_artifact_hash=str(row["child_artifact_hash"]),
        state=str(row["state"]),
        available_coin_id=row["available_coin_id"],
        reserved_coin_id=row["reserved_coin_id"],
        reserved_puzzle_hash=row["reserved_puzzle_hash"],
        signer_indices=tuple(
            int(value) for value in json.loads(row["signer_indices_json"])
        ),
        signature=row["signature"],
    )


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _required_string(value: Mapping[str, Any], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise PaymentPurchaseConflict(f"{field} is required")
    return result


def _required_decimal(value: Mapping[str, Any], field: str) -> int:
    result = value.get(field)
    if isinstance(result, bool):
        raise PaymentPurchaseConflict(f"{field} must be a decimal integer")
    if isinstance(result, int):
        return result
    if isinstance(result, str) and result.isdecimal():
        return int(result)
    raise PaymentPurchaseConflict(f"{field} must be a decimal integer")


def _optional_nonzero_hex32(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise PaymentPurchaseConflict("deedLauncherId is not valid hex") from exc
    if len(raw) != 32:
        raise PaymentPurchaseConflict("deedLauncherId must be 32 bytes")
    return None if raw == bytes(32) else normalized


def _required_mapping(value: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    result = value.get(field)
    if not isinstance(result, Mapping):
        raise PaymentPurchaseConflict(f"{field} must be an object")
    return result


_cached_store: PaymentPurchaseStore | None = None
_cached_store_path: str | None = None


def get_payment_purchase_store(path: str) -> PaymentPurchaseStore:
    global _cached_store, _cached_store_path
    if _cached_store is None or _cached_store_path != path:
        _cached_store = PaymentPurchaseStore(path)
        _cached_store_path = path
    return _cached_store
