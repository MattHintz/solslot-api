"""Append-only Base hold journal; generic expiry cannot release this inventory."""
import json
from .base_inventory_hold import parse_base_hold, bind_held_deposit
from .inventory_extension_store import canonical, conflict
from .purchase_admission import require_admitted_checkout


def migrate_base_checkout(db):
    db.execute('''CREATE TABLE IF NOT EXISTS payment_base_inventory_holds (
        purchase_id TEXT PRIMARY KEY REFERENCES payment_purchases(purchase_id),
        global_payment_id TEXT NOT NULL UNIQUE, claim_json TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'ARMING', receipt_json TEXT
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS payment_base_terminal_attempts (
        purchase_id TEXT PRIMARY KEY, claim_json TEXT NOT NULL, quorum_json TEXT
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
        bind_held_deposit(parse_base_hold(json.loads(row['claim_json'])), message)


class BaseInventoryHoldStoreMixin:
    def base_terminal_attempt(self, purchase_id):
        with self._connect() as db:
            row = db.execute('SELECT * FROM payment_base_terminal_attempts WHERE purchase_id=?', (purchase_id,)).fetchone()
            return None if row is None else dict(claim=json.loads(row['claim_json']),
                quorum=json.loads(row['quorum_json']) if row['quorum_json'] else None)

    def claim_base_terminal_attempt(self, purchase_id, claim, snapshot, expected_hold):
        from .payment_purchase_store import _record
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            held = db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if (parent is None or _record(parent) != snapshot[0] or base_operation(held) != expected_hold
                    or held['claim_json'] != canonical(claim.hold.model_dump(mode='json'))
                    or held['state'] not in ('ARMING', 'ARMED', 'TERMINATING') or parent['inventory_state'] != 'CONFIRMED'):
                raise conflict('Base checkout changed before terminal retention')
            old = db.execute('SELECT claim_json FROM payment_base_terminal_attempts WHERE purchase_id=?', (purchase_id,)).fetchone()
            encoded = canonical(claim.model_dump(mode='json'))
            if old is not None and old[0] != encoded:
                raise conflict('Base terminal attempt cannot be replaced')
            db.execute('INSERT OR IGNORE INTO payment_base_terminal_attempts(purchase_id,claim_json) VALUES (?,?)', (purchase_id,encoded))
            db.execute("UPDATE payment_base_inventory_holds SET state='TERMINATING' WHERE purchase_id=?", (purchase_id,))
            db.execute('COMMIT')

    def preserve_base_terminal_quorum(self, purchase_id, claim, receipt, artifact):
        from .payment_start import verify_start_receipt
        verify_start_receipt(claim, receipt, artifact)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM payment_base_terminal_attempts WHERE purchase_id=?', (purchase_id,)).fetchone()
            held = db.execute('SELECT state FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if old is None or old['claim_json'] != canonical(claim.model_dump(mode='json')) or held is None or held[0] != 'TERMINATING':
                raise conflict('Base terminal changed before quorum retention')
            if old['quorum_json'] is None:
                db.execute('UPDATE payment_base_terminal_attempts SET quorum_json=? WHERE purchase_id=?', (canonical(receipt),purchase_id))
            else:
                verify_start_receipt(claim, json.loads(old['quorum_json']), artifact)
            db.execute('COMMIT')

    def record_base_terminal(self, purchase_id, evidence, artifact, snapshot):
        from .base_checkout_terminals import validate_base_terminal_evidence
        from .payment_purchase_store import _record, _inventory_item
        from .purchase_admission import require_admitted_checkout, close_inventory_admission
        encoded = canonical(evidence)
        evidence = json.loads(encoded)
        validate_base_terminal_evidence(snapshot, evidence, artifact)
        claim = evidence['claim']
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT evidence_json FROM payment_checkout_terminals WHERE purchase_id=?', (purchase_id,)).fetchone()
            if old:
                if old[0] != encoded:
                    raise conflict('Base terminal evidence cannot be replaced')
                db.execute('COMMIT')
                return
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            rows = db.execute('SELECT * FROM payment_purchase_inventory_items WHERE purchase_id=? ORDER BY ordinal', (purchase_id,)).fetchall()
            held = db.execute('SELECT * FROM payment_base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            attempt = db.execute('SELECT * FROM payment_base_terminal_attempts WHERE purchase_id=?', (purchase_id,)).fetchone()
            if (parent is None or _record(parent) != snapshot[0] or tuple(_inventory_item(r) for r in rows) != snapshot[1]
                    or held is None or held['state'] != 'TERMINATING' or held['claim_json'] != canonical(claim['hold'])
                    or parent['inventory_state'] != 'CONFIRMED' or attempt is None
                    or attempt['claim_json'] != canonical(claim) or attempt['quorum_json'] != canonical(evidence['quorum'])
                    or db.execute('SELECT 1 FROM payment_inventory_releases WHERE purchase_id=?', (purchase_id,)).fetchone()):
                raise conflict('Base checkout changed before atomic terminal retention')
            if evidence['kind'] == 'RETURNED':
                db.execute('INSERT INTO payment_inventory_releases(purchase_id,evidence_json) VALUES (?,?)', (purchase_id,encoded))
                db.execute("UPDATE payment_purchases SET inventory_state='RELEASED' WHERE purchase_id=?", (purchase_id,))
                db.execute("UPDATE payment_purchase_inventory_items SET state='RELEASED' WHERE purchase_id=?", (purchase_id,))
            db.execute('INSERT INTO payment_checkout_terminals VALUES (?,?,?)', (purchase_id,evidence['kind'],encoded))
            db.execute('UPDATE payment_base_inventory_holds SET state=? WHERE purchase_id=?', (evidence['kind'],purchase_id))
            require_admitted_checkout(db, purchase_id, claim['hold']['activation'])
            close_inventory_admission(db, purchase_id)
            db.execute("UPDATE payment_checkout_jobs SET done=1,status='COMPLETE',owner=NULL,lease_until=0 WHERE purchase_id=?", (purchase_id,))
            db.execute('COMMIT')

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
