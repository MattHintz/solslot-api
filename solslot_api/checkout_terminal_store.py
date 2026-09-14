"""Atomic terminal checkout receipts; history and private tombstones are retained."""
import json

from .inventory_extension_store import canonical, conflict


def migrate_checkout_terminals(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS payment_checkout_returns (
            purchase_id TEXT PRIMARY KEY, claim_json TEXT NOT NULL,
            quorum_json TEXT
        );
        CREATE TABLE IF NOT EXISTS payment_checkout_terminals (
            purchase_id TEXT PRIMARY KEY, kind TEXT NOT NULL, evidence_json TEXT NOT NULL
        );
    ''')


class CheckoutTerminalStoreMixin:
    def checkout_admission_closed(self, purchase_id, activation):
        with self._connect() as db:
            row = db.execute('SELECT state,binding_json FROM payment_purchase_admission WHERE purchase_id=?', (purchase_id,)).fetchone()
            return bool(row and row['state'] == 'CLOSED' and row['binding_json'] == canonical(activation))

    def checkout_return(self, purchase_id):
        with self._connect() as db:
            row = db.execute('SELECT * FROM payment_checkout_returns WHERE purchase_id=?', (purchase_id,)).fetchone()
            return None if row is None else dict(claim=json.loads(row['claim_json']),
                quorum=json.loads(row['quorum_json']) if row['quorum_json'] else None)

    def checkout_terminal(self, purchase_id):
        with self._connect() as db:
            row = db.execute('SELECT evidence_json FROM payment_checkout_terminals WHERE purchase_id=?', (purchase_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def claim_checkout_return(self, purchase_id, *, claim, snapshot, expected_hold):
        from .payment_purchase_store import _record, _inventory_item
        from .inventory_payment_hold_store import hold_operation
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            rows = db.execute('SELECT * FROM payment_purchase_inventory_items WHERE purchase_id=? ORDER BY ordinal', (purchase_id,)).fetchall()
            held = db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if (parent is None or held is None or _record(parent) != snapshot[0]
                    or tuple(_inventory_item(r) for r in rows) != snapshot[1]
                    or hold_operation(held) != expected_hold
                    or parent['inventory_state'] != 'CONFIRMED'
                    or held['state'] not in ('ARMED', 'ABORTED', 'RETURNING')
                    or db.execute('SELECT 1 FROM payment_checkout_terminals WHERE purchase_id=?', (purchase_id,)).fetchone()):
                raise conflict('checkout changed or has unresolved execution; retain it for terminal review')
            encoded = canonical(claim.model_dump(mode='json'))
            old = db.execute('SELECT claim_json FROM payment_checkout_returns WHERE purchase_id=?', (purchase_id,)).fetchone()
            if old and old[0] != encoded:
                raise conflict('terminal checkout claim cannot be replaced')
            db.execute('INSERT OR IGNORE INTO payment_checkout_returns(purchase_id,claim_json) VALUES (?,?)', (purchase_id, encoded))
            db.execute("UPDATE payment_checkout_holds SET state='RETURNING' WHERE purchase_id=?", (purchase_id,))
            db.execute('COMMIT')

    def preserve_checkout_return_quorum(self, purchase_id, *, claim, receipt, artifact):
        from .inventory_payment_holds import verify_hold_receipt
        verify_hold_receipt(claim, receipt, artifact)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM payment_checkout_returns WHERE purchase_id=?', (purchase_id,)).fetchone()
            held = db.execute('SELECT state FROM payment_checkout_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if not row or row['claim_json'] != canonical(claim.model_dump(mode='json')) or not held or held[0] != 'RETURNING':
                raise conflict('terminal checkout claim changed before quorum retention')
            if row['quorum_json'] is None:
                db.execute('UPDATE payment_checkout_returns SET quorum_json=? WHERE purchase_id=?', (canonical(receipt), purchase_id))
            else:
                verify_hold_receipt(claim, json.loads(row['quorum_json']), artifact)
            db.execute('COMMIT')

    def record_checkout_terminal(self, purchase_id, *, evidence, snapshot, artifact, expected_hold):
        from .payment_purchase_store import _record, _inventory_item
        from .inventory_payment_hold_store import hold_operation
        from .checkout_terminals import validate_terminal_evidence
        from .purchase_admission import close_inventory_admission
        # Freeze caller-owned mappings before validation and the writer transaction.
        encoded = canonical(evidence)
        evidence = json.loads(encoded)
        validate_terminal_evidence(snapshot, evidence, artifact)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT evidence_json FROM payment_checkout_terminals WHERE purchase_id=?', (purchase_id,)).fetchone()
            if old:
                if old[0] != encoded:
                    raise conflict('terminal checkout evidence cannot be replaced')
                db.execute('COMMIT')
                return
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            rows = db.execute('SELECT * FROM payment_purchase_inventory_items WHERE purchase_id=? ORDER BY ordinal', (purchase_id,)).fetchall()
            held = db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if (parent is None or held is None or _record(parent) != snapshot[0]
                    or tuple(_inventory_item(r) for r in rows) != snapshot[1]
                    or hold_operation(held) != expected_hold
                    or held['claim_json'] != canonical(evidence['hold'])
                    or parent['inventory_state'] != 'CONFIRMED'
                    or db.execute('SELECT 1 FROM payment_inventory_releases WHERE purchase_id=?', (purchase_id,)).fetchone()):
                raise conflict('checkout changed during terminal proof; retain it for reconciliation')
            if evidence['kind'] == 'RETURNED':
                returned = db.execute('SELECT * FROM payment_checkout_returns WHERE purchase_id=?', (purchase_id,)).fetchone()
                if (held['state'] != 'RETURNING' or returned is None
                        or returned['claim_json'] != canonical(evidence['returnClaim'])
                        or returned['quorum_json'] != canonical(evidence['returnQuorum'])):
                    raise conflict('inventory return lacks its retained exact private quorum')
                db.execute('INSERT INTO payment_inventory_releases(purchase_id,evidence_json) VALUES (?,?)', (purchase_id, encoded))
                db.execute("UPDATE payment_purchases SET inventory_state='RELEASED' WHERE purchase_id=?", (purchase_id,))
                db.execute("UPDATE payment_purchase_inventory_items SET state='RELEASED' WHERE purchase_id=?", (purchase_id,))
            elif held['state'] != 'ARMED' or db.execute('SELECT 1 FROM payment_checkout_returns WHERE purchase_id=?', (purchase_id,)).fetchone():
                raise conflict('paid delivery conflicts with terminal return recovery')
            db.execute('INSERT INTO payment_checkout_terminals VALUES (?,?,?)', (purchase_id, evidence['kind'], encoded))
            db.execute('UPDATE payment_checkout_holds SET state=? WHERE purchase_id=?', (evidence['kind'], purchase_id))
            from .purchase_admission import require_admitted_checkout
            require_admitted_checkout(db, purchase_id, evidence['hold']['activation'])
            close_inventory_admission(db, purchase_id)
            db.execute('COMMIT')
