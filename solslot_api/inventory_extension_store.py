"""Append-only extension history and exact dispatch journal for current inventory."""
from __future__ import annotations

import json
import sqlite3


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def conflict(message):
    from .payment_purchase_store import PaymentPurchaseConflict
    return PaymentPurchaseConflict(message)


def migrate_extensions(connection):
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS payment_inventory_extensions (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            purchase_id TEXT NOT NULL,
            input_coin_id TEXT NOT NULL UNIQUE,
            claim_json TEXT NOT NULL,
            binding_json TEXT NOT NULL,
            protocol_json TEXT,
            signer_indices_json TEXT,
            prepared_json TEXT,
            fee_coin_id TEXT UNIQUE,
            state TEXT NOT NULL DEFAULT 'PREPARING',
            submission_json TEXT,
            confirmation_json TEXT,
            last_error_json TEXT,
            lease_owner TEXT,
            lease_until INTEGER NOT NULL DEFAULT 0,
            UNIQUE (purchase_id, input_coin_id),
            FOREIGN KEY (purchase_id) REFERENCES payment_purchases(purchase_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS one_pending_inventory_extension
            ON payment_inventory_extensions(purchase_id) WHERE state != 'CONFIRMED';
    """)


def operation(row):
    if row is None:
        return None
    return dict(sequence=row['sequence'], purchaseId=row['purchase_id'], inputCoinId=row['input_coin_id'],
        claim=json.loads(row['claim_json']), binding=json.loads(row['binding_json']),
        protocol=json.loads(row['protocol_json']) if row['protocol_json'] else None,
        signerIndices=json.loads(row['signer_indices_json']) if row['signer_indices_json'] else None,
        prepared=json.loads(row['prepared_json']) if row['prepared_json'] else None,
        state=row['state'], submission=json.loads(row['submission_json']) if row['submission_json'] else None,
        confirmation=json.loads(row['confirmation_json']) if row['confirmation_json'] else None,
        lastError=json.loads(row['last_error_json']) if row['last_error_json'] else None)


class InventoryExtensionStoreMixin:
    def inventory_extension_operations(self, purchase_id):
        with self._connect() as db:
            return [operation(row) for row in db.execute(
                'SELECT * FROM payment_inventory_extensions WHERE purchase_id=? ORDER BY sequence', (purchase_id,))]

    def pending_inventory_extension(self, purchase_id):
        with self._connect() as db:
            return operation(db.execute("SELECT * FROM payment_inventory_extensions WHERE purchase_id=? AND state!='CONFIRMED'",
                                        (purchase_id,)).fetchone())

    def claim_inventory_extension(self, purchase_id, *, claim, binding, owner, now, expected_snapshot):
        """Pin the complete claim before requesting any signature; retries cannot replace it."""
        from .payment_purchase_store import _record
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            if row is None or _record(row) != expected_snapshot or row['inventory_state'] != 'CONFIRMED':
                raise conflict('inventory changed before extension preparation')
            held=db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
            if held:
                hold=json.loads(held['claim_json'])
                if (held['state']!='ARMED' or hold['payment_intent_id']!=claim['payment_intent_id']
                        or hold['payment_method']!=claim['payment_method']):
                    raise conflict('extension cannot replace a partial, canceled or different checkout payment')
            base = db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if base or claim.get('schema_version') == 'solslot.base-inventory-extension.v1':
                from .base_lifecycle_claims import BaseInventoryExtensionClaim
                parsed = BaseInventoryExtensionClaim.model_validate(claim)
                if (base is None or base['state'] != 'ARMED' or base['receipt_json'] is None
                        or base['claim_json'] != canonical(parsed.hold.model_dump(mode='json'))):
                    raise conflict('Base extension needs its original complete checkout hold')
            if len(expected_snapshot.inventory_extension_receipts) >= 128:
                raise conflict('extension history requires review; inventory remains held')
            if db.execute('SELECT 1 FROM payment_inventory_timeouts WHERE purchase_id=?', (purchase_id,)).fetchone():
                raise conflict('a retained timeout operation prevents extension')
            try:
                db.execute('INSERT OR IGNORE INTO payment_inventory_extensions(purchase_id,input_coin_id,claim_json,binding_json) VALUES (?,?,?,?)',
                           (purchase_id, claim['reserved_coin_id'], canonical(claim), canonical(binding)))
            except sqlite3.IntegrityError as exc:
                raise conflict('another extension already holds this inventory') from exc
            current = db.execute('SELECT * FROM payment_inventory_extensions WHERE purchase_id=? AND input_coin_id=?',
                                 (purchase_id, claim['reserved_coin_id'])).fetchone()
            if (current is None or current['claim_json'] != canonical(claim)
                    or current['binding_json'] != canonical(binding) or current['state'] == 'CONFIRMED'):
                raise conflict('extension claim or deployment cannot be replaced')
            if current['lease_owner'] is not None and current['lease_until'] > now:
                raise conflict('extension recovery is already in progress; retry later')
            db.execute('UPDATE payment_inventory_extensions SET lease_owner=?,lease_until=? WHERE sequence=?',
                       (owner, now+120, current['sequence']))
            db.execute('COMMIT')
        return operation(current)

    def preserve_inventory_extension(self, sequence, *, owner, now, protocol=None, signer_indices=None, prepared=None):
        """Preserve both quorum output and funded bytes before any provider dispatch."""
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM payment_inventory_extensions WHERE sequence=?', (sequence,)).fetchone()
            if row is None or row['lease_owner'] != owner or row['lease_until'] <= now or row['state']=='CONFIRMED':
                raise conflict('extension lease is no longer current')
            if protocol is not None:
                if row['protocol_json'] is not None and (row['protocol_json'] != canonical(protocol)
                        or row['signer_indices_json'] != canonical(signer_indices)):
                    raise conflict('the retained extension signature cannot be replaced')
                db.execute('UPDATE payment_inventory_extensions SET protocol_json=?,signer_indices_json=? WHERE sequence=?',
                           (canonical(protocol), canonical(signer_indices), sequence))
            if prepared is not None:
                if row['protocol_json'] is None or (row['prepared_json'] is not None and row['prepared_json'] != canonical(prepared)):
                    raise conflict('the retained funded extension cannot be replaced')
                try:
                    db.execute("UPDATE payment_inventory_extensions SET prepared_json=?,fee_coin_id=?,state='PREPARED' WHERE sequence=?",
                               (canonical(prepared), prepared['feeCoinId'], sequence))
                except sqlite3.IntegrityError as exc:
                    raise conflict('extension fee coin is already reserved') from exc
            db.execute('COMMIT')

    def finish_inventory_extension_attempt(self, sequence, *, owner, receipt=None):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("UPDATE payment_inventory_extensions SET last_error_json=? WHERE sequence=? AND lease_owner=? AND state!='CONFIRMED'",
                (None if receipt is not None else canonical({'code':'EXTENSION_REQUIRES_REVIEW'}), sequence, owner))
            if receipt is not None:
                db.execute("UPDATE payment_inventory_extensions SET state='SUBMITTED',submission_json=? "
                           "WHERE sequence=? AND lease_owner=? AND prepared_json IS NOT NULL AND state!='CONFIRMED'",
                           (canonical(receipt), sequence, owner))
            db.execute('UPDATE payment_inventory_extensions SET lease_owner=NULL,lease_until=0 WHERE sequence=? AND lease_owner=?',
                       (sequence, owner))
            db.execute('COMMIT')

    def confirm_inventory_extension(self, sequence, *, retained, evidence, expected_snapshot):
        """Append a verified successor receipt without changing the initial reservation."""
        from .payment_purchase_store import _record
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM payment_inventory_extensions WHERE sequence=?', (sequence,)).fetchone()
            if row is None:
                raise conflict('extension journal is missing')
            if row['state']=='CONFIRMED':
                if row['confirmation_json'] != canonical(evidence):
                    raise conflict('extension confirmation cannot be replaced')
                db.execute('COMMIT')
                return
            if operation(row) != retained or row['prepared_json'] is None:
                raise conflict('extension execution changed during confirmation')
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (row['purchase_id'],)).fetchone()
            if parent is None or _record(parent) != expected_snapshot or parent['inventory_state']!='CONFIRMED':
                raise conflict('inventory changed during extension confirmation')
            receipt = dict(claim=retained['claim'], binding=retained['binding'],
                           protocol=retained['protocol'], signerIndices=retained['signerIndices'],
                           prepared=retained['prepared'], confirmation=evidence)
            history = [*expected_snapshot.inventory_extension_receipts, receipt]
            db.execute('UPDATE payment_purchases SET inventory_extension_receipts_json=? WHERE purchase_id=?',
                       (canonical(history), row['purchase_id']))
            db.execute("UPDATE payment_inventory_extensions SET state='CONFIRMED',confirmation_json=?,last_error_json=NULL,lease_owner=NULL,lease_until=0 WHERE sequence=?",
                       (canonical(evidence), sequence))
            db.execute('COMMIT')

    def pending_extension_fee_coin_ids(self):
        with self._connect() as db:
            return tuple(row[0] for row in db.execute(
                'SELECT fee_coin_id FROM payment_inventory_extensions WHERE fee_coin_id IS NOT NULL'))
