"""Append-only Base hold journal; generic expiry cannot release this inventory."""
import json
from .base_inventory_hold import BaseInventoryHoldClaim, bind_held_deposit
from .inventory_extension_store import canonical, conflict
from .purchase_admission import require_admitted_checkout


def migrate_base_checkout(db):
    db.execute('''CREATE TABLE IF NOT EXISTS payment_base_inventory_holds (
        purchase_id TEXT PRIMARY KEY REFERENCES payment_purchases(purchase_id),
        global_payment_id TEXT NOT NULL UNIQUE, claim_json TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'ARMING', receipt_json TEXT
    )''')


def base_operation(row):
    if row is None:
        return None
    return dict(purchaseId=row['purchase_id'], state=row['state'], claim=json.loads(row['claim_json']),
                receipt=json.loads(row['receipt_json']) if row['receipt_json'] else None)


def check_base_deposit_binding(db, purchase_id, message):
    row = db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
    if row:
        # A partial/lost acknowledgment remains held for recovery; it cannot
        # authorize delivery. Re-arm the same claim to recover its quorum first.
        if row['state'] != 'ARMED' or row['receipt_json'] is None:
            raise conflict('Base deposit has a partial hold; recover its original quorum')
        bind_held_deposit(BaseInventoryHoldClaim.model_validate_json(row['claim_json']), message)


class BaseInventoryHoldStoreMixin:
    def base_checkout_hold(self, purchase_id):
        with self._connect() as db:
            return base_operation(db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone())

    def claim_base_checkout(self, claim, *, snapshot, now):
        from .payment_purchase_store import _record
        purchase_id = claim.purchase_artifact['purchaseId']
        encoded = canonical(claim.model_dump(mode='json'))
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            require_admitted_checkout(db, purchase_id, claim.activation)
            old = db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if old:
                if old['claim_json'] != encoded or old['state'] not in ('ARMING', 'ARMED'):
                    raise conflict('Base checkout cannot replace its original hold')
                db.execute('COMMIT')
                return base_operation(old)
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            if (parent is None or _record(parent) != snapshot or snapshot.inventory_state != 'CONFIRMED'
                    or snapshot.purchase_artifact != claim.purchase_artifact or snapshot.external_message is not None
                    or snapshot.inventory_reserved_coin_id != claim.reserved_coin_id
                    or snapshot.inventory_reserved_puzzle_hash != claim.reserved_puzzle_hash
                    or snapshot.inventory_expires_at != claim.reservation_expires_at or claim.reservation_expires_at <= now):
                raise conflict('Base hold requires the exact live unpaid original reservation')
            for table in ('payment_checkout_holds', 'payment_inventory_extensions', 'payment_inventory_timeouts', 'payment_inventory_releases'):
                if db.execute(f'SELECT 1 FROM {table} WHERE purchase_id=?', (purchase_id,)).fetchone():
                    raise conflict('Base hold conflicts with an existing inventory operation')
            db.execute('INSERT INTO payment_base_inventory_holds(purchase_id,global_payment_id,claim_json) VALUES (?,?,?)',
                       (purchase_id, claim.global_payment_id, encoded))
            db.execute('COMMIT')
        return self.base_checkout_hold(purchase_id)

    def preserve_base_checkout(self, claim, receipt, artifact):
        from .base_inventory_hold_coordinator import verify_base_hold_receipt
        verify_base_hold_receipt(claim, receipt, artifact)
        purchase_id = claim.purchase_artifact['purchaseId']
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if row is None or row['state'] not in ('ARMING', 'ARMED') or row['claim_json'] != canonical(claim.model_dump(mode='json')):
                raise conflict('Base hold changed before quorum retention')
            if row['receipt_json'] is not None:
                verify_base_hold_receipt(claim, json.loads(row['receipt_json']), artifact)
            else:
                db.execute("UPDATE payment_base_inventory_holds SET state='ARMED',receipt_json=? WHERE purchase_id=?",
                           (canonical(receipt), purchase_id))
            db.execute('COMMIT')
