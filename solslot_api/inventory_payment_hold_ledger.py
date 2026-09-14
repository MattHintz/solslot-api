"""Append-only private payment hold acknowledgments and release tombstones."""
import sqlite3
import time
from .inventory_extension_store import canonical


def migrate_payment_holds(db):
    db.executescript('''
        BEGIN IMMEDIATE;
        CREATE TABLE inventory_payment_holds (
            claim_hash TEXT PRIMARY KEY, canonical_claim TEXT NOT NULL,
            purchase_id TEXT NOT NULL UNIQUE, payment_intent_id TEXT NOT NULL UNIQUE,
            deed_launcher_id TEXT NOT NULL, reserved_coin_id TEXT NOT NULL UNIQUE,
            signature TEXT NOT NULL, signed_at INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'ARMED', release_claim_json TEXT, release_signature TEXT
        );
        CREATE UNIQUE INDEX one_active_private_payment_hold ON inventory_payment_holds(deed_launcher_id) WHERE state!='RELEASED';
        PRAGMA user_version=12;
        COMMIT;
    ''')


class InventoryPaymentHoldLedgerMixin:
    def inventory_payment_hold(self, purchase_id):
        with self._lock:
            row=self._conn.execute('SELECT * FROM inventory_payment_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
            if row:return dict(row)
            aborted=self._conn.execute('SELECT * FROM inventory_payment_hold_aborts WHERE purchase_id=?',(purchase_id,)).fetchone()
            if aborted:
                return dict(claim_hash=aborted['hold_hash'],canonical_claim=aborted['hold_json'],purchase_id=purchase_id,
                    payment_intent_id=aborted['payment_intent_id'],state='RELEASED',signature=None,
                    release_claim_json=aborted['canonical_claim'],release_signature=aborted['signature'])
            return None

    def _assert_payment_hold_identity(self, purchase_id, payment_intent_id):
        from .validator_ledger import ValidatorLedgerConflict
        if self._conn.execute('SELECT 1 FROM inventory_payment_hold_aborts WHERE purchase_id=?',(purchase_id,)).fetchone():
            raise ValidatorLedgerConflict('This purchase has a terminal payment abort tombstone.')
        hold=self._conn.execute('SELECT * FROM inventory_payment_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
        if hold and (hold['state']=='RELEASED' or hold['payment_intent_id']!=payment_intent_id):
            raise ValidatorLedgerConflict('This purchase has a different or released payment hold.')

    def _assert_no_payment_hold(self, deed_launcher_id):
        from .validator_ledger import ValidatorLedgerConflict
        if self._conn.execute("SELECT 1 FROM inventory_payment_holds WHERE deed_launcher_id=? AND state!='RELEASED'",(deed_launcher_id,)).fetchone():
            raise ValidatorLedgerConflict('This SmartDeed is held before payment; expiry is not payment release authority.')

    def _assert_no_payment_authorization(self, purchase_id, reserved_coin_id):
        from .validator_ledger import ValidatorLedgerConflict
        # An earlier paid authorization may leave the original reserved
        # coin unspent. It must not be retroactively assigned a new PI.
        for table in ('primary_purchase_signatures', 'stripe_settlement_signatures',
                      'inventory_extension_signatures'):
            if self._conn.execute(f'SELECT 1 FROM {table} WHERE purchase_id=?', (purchase_id,)).fetchone():
                raise ValidatorLedgerConflict('This purchase already has a signed payment or extension.')
        for table in ('voucher_issuance_signatures', 'voucher_transition_signatures'):
            if self._conn.execute(f"""SELECT 1 FROM {table} WHERE CASE WHEN json_valid(canonical_claim)
                    THEN lower(json_extract(canonical_claim, '$.purchase_artifact.purchaseId')) END = ?""",
                    (purchase_id,)).fetchone():
                raise ValidatorLedgerConflict('This purchase already has a signed voucher operation.')
        for table,column in [('primary_purchase_signatures','deed_coin_id'),('stripe_settlement_delivery_locks','delivery_coin_id'),
                ('voucher_transition_signatures','deed_coin_id'),('inventory_extension_signatures','reserved_coin_id')]:
            if self._conn.execute(f'SELECT 1 FROM {table} WHERE {column}=?',(reserved_coin_id,)).fetchone():
                raise ValidatorLedgerConflict('Inventory already has a competing signed operation.')

    def record_inventory_payment_hold(self, *, claim, signature, purchase_id, deed_launcher_id):
        from .validator_ledger import ValidatorLedgerConflict
        encoded=canonical(claim.model_dump(mode='json')); digest=claim.canonical_hash()
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                if self._conn.execute('SELECT 1 FROM inventory_payment_hold_aborts WHERE purchase_id=? OR payment_intent_id=? OR reserved_coin_id=?',
                        (purchase_id,claim.payment_intent_id,claim.reserved_coin_id)).fetchone():
                    raise ValidatorLedgerConflict('A terminal payment abort cannot be rearmed or rebound.')
                old=self._conn.execute('SELECT * FROM inventory_payment_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
                if old:
                    if old['canonical_claim']!=encoded or old['claim_hash']!=digest or old['state']=='RELEASED':
                        raise ValidatorLedgerConflict('A payment hold cannot be replaced or reopened.')
                    self._conn.execute('COMMIT');return old['signature']
                self._assert_no_payment_hold(deed_launcher_id)
                # Recheck under the writer lock: an expired proof or a later
                # reservation may have won while this arming request waited.
                if claim.reservation_expires_at <= int(time.time()):
                    raise ValidatorLedgerConflict('Pre-payment reservation expired before durable arming.')
                latest = self._conn.execute("""SELECT purchase_id FROM inventory_reservation_history
                    WHERE CASE WHEN json_valid(canonical_claim)
                    THEN lower(json_extract(canonical_claim, '$.purchase_artifact.deedLauncherId')) END = ?
                    ORDER BY rowid DESC LIMIT 1""", (deed_launcher_id,)).fetchone()
                if latest is not None and latest['purchase_id'] != purchase_id:
                    raise ValidatorLedgerConflict('Another purchase superseded this inventory reservation before arming.')
                self._assert_no_payment_authorization(purchase_id, claim.reserved_coin_id)
                self._conn.execute('INSERT INTO inventory_payment_holds(claim_hash,canonical_claim,purchase_id,payment_intent_id,deed_launcher_id,reserved_coin_id,signature,signed_at) VALUES (?,?,?,?,?,?,?,?)',
                    (digest,encoded,purchase_id,claim.payment_intent_id,deed_launcher_id,claim.reserved_coin_id,signature,int(time.time())))
                self._conn.execute('COMMIT');return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute('ROLLBACK')
                raise ValidatorLedgerConflict('Payment, purchase, or inventory already has a private hold.') from exc
            except Exception:
                self._conn.execute('ROLLBACK');raise

    def record_inventory_payment_hold_release(self, *, claim, signature, purchase_id):
        from .validator_ledger import ValidatorLedgerConflict
        encoded=canonical(claim.model_dump(mode='json'))
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                old=self._conn.execute('SELECT * FROM inventory_payment_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
                if old is None or old['claim_hash']!=claim.hold.canonical_hash():
                    raise ValidatorLedgerConflict('Release has no matching private payment hold.')
                if old['state']=='RELEASED':
                    if old['release_claim_json']!=encoded:
                        raise ValidatorLedgerConflict('Payment release cannot be replaced.')
                    self._conn.execute('COMMIT');return old['release_signature']
                self._conn.execute("UPDATE inventory_payment_holds SET state='RELEASED',release_claim_json=?,release_signature=? WHERE purchase_id=?",
                    (encoded,signature,purchase_id))
                self._conn.execute('COMMIT');return signature
            except Exception:
                self._conn.execute('ROLLBACK');raise


    def record_inventory_payment_hold_abort(self, *, claim, signature, purchase_id, deed_launcher_id):
        from .validator_ledger import ValidatorLedgerConflict
        encoded=canonical(claim.model_dump(mode='json'))
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                old=self._conn.execute('SELECT * FROM inventory_payment_hold_aborts WHERE purchase_id=?',(purchase_id,)).fetchone()
                if old:
                    if old['canonical_claim']!=encoded:raise ValidatorLedgerConflict('Payment abort cannot be replaced.')
                    self._conn.execute('COMMIT');return old['signature']
                held=self._conn.execute('SELECT * FROM inventory_payment_holds WHERE purchase_id=?',(purchase_id,)).fetchone()
                if held and (held['claim_hash']!=claim.hold.canonical_hash() or held['state']=='RELEASED'):
                    raise ValidatorLedgerConflict('Payment abort conflicts with another hold or terminal outcome.')
                if self._conn.execute('SELECT 1 FROM inventory_payment_holds WHERE payment_intent_id=? AND purchase_id!=?',
                        (claim.hold.payment_intent_id,purchase_id)).fetchone():
                    raise ValidatorLedgerConflict('The held payment belongs to another purchase.')
                self._assert_no_payment_authorization(purchase_id,claim.reserved_coin_id)
                self._conn.execute('INSERT INTO inventory_payment_hold_aborts VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (claim.canonical_hash(),encoded,claim.hold.canonical_hash(),canonical(claim.hold.model_dump(mode='json')),
                     purchase_id,claim.hold.payment_intent_id,claim.reserved_coin_id,deed_launcher_id,signature,int(time.time())))
                if held:
                    self._conn.execute("UPDATE inventory_payment_holds SET state='RELEASED',release_claim_json=?,release_signature=? WHERE purchase_id=?",
                        (encoded,signature,purchase_id))
                self._conn.execute('COMMIT');return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute('ROLLBACK');raise ValidatorLedgerConflict('Abort payment or input is already bound.') from exc
            except Exception:
                self._conn.execute('ROLLBACK');raise


def migrate_payment_hold_aborts(db):
    db.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS inventory_payment_hold_aborts (
            claim_hash TEXT PRIMARY KEY, canonical_claim TEXT NOT NULL,
            hold_hash TEXT NOT NULL UNIQUE, hold_json TEXT NOT NULL,
            purchase_id TEXT NOT NULL UNIQUE, payment_intent_id TEXT NOT NULL UNIQUE,
            reserved_coin_id TEXT NOT NULL UNIQUE, deed_launcher_id TEXT NOT NULL,
            signature TEXT NOT NULL, signed_at INTEGER NOT NULL
        );
        PRAGMA user_version=13;
        COMMIT;
    """)
