"""Coordinator journal for exact pre-confirmation holds and partial cancellation.

An abort acknowledgment closes private payment authority. It does not advance
the available-inventory cursor; terminal chain reconciliation owns that step.
"""
import json
import sqlite3

from .inventory_extension_store import canonical, conflict


def migrate_checkout_holds(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS payment_checkout_holds (
            purchase_id TEXT PRIMARY KEY,
            payment_intent_id TEXT NOT NULL UNIQUE,
            claim_json TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'ARMING',
            arm_receipt_json TEXT,
            abort_claim_json TEXT,
            abort_receipt_json TEXT
        );
        CREATE TABLE IF NOT EXISTS payment_checkout_quorum_leases (
            purchase_id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner TEXT,
            lease_until INTEGER NOT NULL DEFAULT 0, retry_after INTEGER NOT NULL DEFAULT 0
        );
    ''')


def hold_operation(row):
    if row is None:return None
    return dict(purchaseId=row['purchase_id'],paymentIntentId=row['payment_intent_id'],state=row['state'],
        claim=json.loads(row['claim_json']),
        armReceipt=json.loads(row['arm_receipt_json']) if row['arm_receipt_json'] else None,
        abortClaim=json.loads(row['abort_claim_json']) if row['abort_claim_json'] else None,
        abortReceipt=json.loads(row['abort_receipt_json']) if row['abort_receipt_json'] else None)


def assert_no_checkout_hold(db,purchase_id):
    if db.execute('SELECT 1 FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone():
        raise conflict('checkout payment hold requires terminal reconciliation; generic expiry cannot release inventory')


class InventoryPaymentHoldStoreMixin:
    def claim_checkout_quorum(self,purchase_id,*,kind,owner,now):
        # One in-flight proof per purchase across processes, with a separate
        # recovery budget so new checkout traffic cannot consume every slot.
        if kind not in ('arm','abort','return'):raise ValueError('unknown checkout quorum lane')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM payment_checkout_quorum_leases WHERE purchase_id=?',(purchase_id,)).fetchone()
            if row and (row['lease_until']>now or (row['kind']==kind and row['retry_after']>now)):
                raise conflict('checkout proof is already running or cooling down; recover the same purchase shortly')
            # Abort and full return share the separately reserved recovery capacity.
            lanes=('arm',) if kind=='arm' else ('abort','return')
            placeholders=','.join('?' for _ in lanes)
            count=db.execute(f'SELECT count(*) FROM payment_checkout_quorum_leases WHERE kind IN ({placeholders}) AND lease_until>?',(*lanes,now)).fetchone()[0]
            if count>=(8 if kind=='arm' else 4):raise conflict('checkout proof capacity is busy; retry the same purchase shortly')
            db.execute('INSERT INTO payment_checkout_quorum_leases(purchase_id,kind,owner,lease_until,retry_after) VALUES (?,?,?,?,?) '
                'ON CONFLICT(purchase_id) DO UPDATE SET kind=excluded.kind,owner=excluded.owner,lease_until=excluded.lease_until,retry_after=excluded.retry_after',
                (purchase_id,kind,owner,now+120,now+5))
            db.execute('COMMIT')

    def finish_checkout_quorum(self,purchase_id,*,owner,now):
        with self._connect() as db:
            db.execute('UPDATE payment_checkout_quorum_leases SET owner=NULL,lease_until=0,retry_after=? WHERE purchase_id=? AND owner=?',
                (now+5,purchase_id,owner))

    def checkout_hold(self,purchase_id):
        with self._connect() as db:
            return hold_operation(db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone())

    def claim_checkout_hold(self,purchase_id,*,claim,expected_snapshot,now):
        from .payment_purchase_store import _record
        from .purchase_admission import require_admitted_checkout
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            require_admitted_checkout(db,purchase_id,claim['activation'])
            parent=db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?',(purchase_id,)).fetchone()
            if (parent is None or _record(parent)!=expected_snapshot or parent['inventory_state']!='CONFIRMED'
                    or claim['purchase_artifact']!=expected_snapshot.purchase_artifact
                    or claim['reserved_coin_id']!=expected_snapshot.inventory_reserved_coin_id
                    or claim['reservation_expires_at']!=expected_snapshot.inventory_expires_at
                    or claim['reservation_expires_at']<=now or expected_snapshot.external_message is not None):
                raise conflict('checkout requires the exact live unpaid initial reservation')
            for table in ('payment_inventory_timeouts','payment_inventory_extensions','payment_inventory_releases'):
                if db.execute(f'SELECT 1 FROM {table} WHERE purchase_id=?',(purchase_id,)).fetchone():
                    raise conflict('checkout conflicts with an existing inventory operation')
            try:
                db.execute('INSERT OR IGNORE INTO payment_checkout_holds(purchase_id,payment_intent_id,claim_json) VALUES (?,?,?)',
                    (purchase_id,claim['payment_intent_id'],canonical(claim)))
            except sqlite3.IntegrityError as exc:
                raise conflict('checkout payment already belongs to another purchase') from exc
            row=db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
            if row is None or row['claim_json']!=canonical(claim) or row['state'] not in ('ARMING','ARMED'):
                raise conflict('checkout hold cannot be replaced or reopened')
            db.execute('COMMIT')
            return hold_operation(row)

    def preserve_checkout_arm(self,purchase_id,*,claim,receipt,artifact,expected_snapshot,now):
        from .inventory_payment_holds import verify_hold_receipt
        from .payment_purchase_store import _record
        verify_hold_receipt(claim,receipt,artifact)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
            parent=db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?',(purchase_id,)).fetchone()
            if (row is None or row['claim_json']!=canonical(claim.model_dump(mode='json'))
                    or row['state'] not in ('ARMING','ARMED') or parent is None or _record(parent)!=expected_snapshot
                    or parent['inventory_state']!='CONFIRMED' or claim.reservation_expires_at<=now):
                raise conflict('checkout changed or expired before quorum was retained')
            # Different valid two-of-three subsets are legitimate retries. Keep
            # the first verified receipt and never replace it with newer bytes.
            if row['arm_receipt_json'] is not None:
                verify_hold_receipt(claim,json.loads(row['arm_receipt_json']),artifact)
            else:
                db.execute("UPDATE payment_checkout_holds SET state='ARMED',arm_receipt_json=? WHERE purchase_id=?",
                    (canonical(receipt),purchase_id))
            db.execute('COMMIT')

    def claim_checkout_abort(self,purchase_id,*,claim):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
            encoded=canonical(claim.model_dump(mode='json'))
            if (row is None or row['claim_json']!=canonical(claim.hold.model_dump(mode='json'))
                    or row['state'] not in ('ARMING','ARMED','ABORTING','ABORTED')
                    or (row['abort_claim_json'] is not None and row['abort_claim_json']!=encoded)
                    or db.execute('SELECT 1 FROM payment_inventory_extensions WHERE purchase_id=?',(purchase_id,)).fetchone()):
                raise conflict('partial cancellation must preserve its original unextended hold')
            if row['state']!='ABORTED':
                db.execute("UPDATE payment_checkout_holds SET state='ABORTING',abort_claim_json=? WHERE purchase_id=?",(encoded,purchase_id))
            db.execute('COMMIT')

    def preserve_checkout_abort(self,purchase_id,*,claim,receipt,artifact):
        from .inventory_payment_holds import verify_hold_receipt
        verify_hold_receipt(claim,receipt,artifact)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
            if (row is None or row['abort_claim_json']!=canonical(claim.model_dump(mode='json'))
                    or row['state'] not in ('ABORTING','ABORTED')):
                raise conflict('partial cancellation changed before its quorum was retained')
            if row['abort_receipt_json'] is not None:
                verify_hold_receipt(claim,json.loads(row['abort_receipt_json']),artifact)
            else:
                db.execute("UPDATE payment_checkout_holds SET state='ABORTED',abort_receipt_json=? WHERE purchase_id=?",
                    (canonical(receipt),purchase_id))
            db.execute('COMMIT')
