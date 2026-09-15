"""Private Base exclusions and first verified deposit anchors, never expiry leases."""
import json
import sqlite3
import time

from .base_inventory_hold import parse_base_hold, bind_held_deposit
from .escrow_deposit import same_deposit_message
from .inventory_extension_store import canonical


def migrate_base_holds(db):
    db.executescript('''
        BEGIN IMMEDIATE;
        CREATE TABLE base_inventory_holds (
            purchase_id TEXT PRIMARY KEY, deed_launcher_id TEXT NOT NULL UNIQUE,
            reserved_coin_id TEXT NOT NULL UNIQUE, global_payment_id TEXT NOT NULL UNIQUE,
            claim_json TEXT NOT NULL, signature TEXT NOT NULL, signed_at INTEGER NOT NULL,
            payment_start_json TEXT
        );
        PRAGMA user_version=14;
        COMMIT;
    ''')


class BaseInventoryHoldLedgerMixin:
    def base_inventory_hold(self, purchase_id):
        with self._lock:
            row = self._conn.execute('SELECT * FROM base_inventory_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if row is None:
                row = self._conn.execute('SELECT * FROM base_inventory_hold_generations WHERE purchase_id=?', (purchase_id,)).fetchone()
            return dict(row) if row else None

    def record_base_inventory_hold(self, claim, signature):
        from .validator_ledger import ValidatorLedgerConflict
        raw = claim.purchase_artifact
        purchase_id, deed = raw['purchaseId'], raw['deedLauncherId']
        encoded = canonical(claim.model_dump(mode='json'))
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                self._assert_base_not_terminal(purchase_id)
                old = self.base_inventory_hold(purchase_id)
                if old:
                    if old['claim_json'] != encoded:
                        raise ValidatorLedgerConflict('Base prepayment hold cannot be replaced')
                    self._conn.execute('COMMIT')
                    return old['signature']
                self._assert_no_payment_hold(deed)
                self._assert_no_payment_authorization(purchase_id, claim.reserved_coin_id)
                if self.inventory_payment_hold(purchase_id) is not None:
                    raise ValidatorLedgerConflict('Base hold cannot replace a Stripe hold or terminal tombstone')
                if claim.reservation_expires_at <= int(time.time()):
                    raise ValidatorLedgerConflict('Base reservation expired before durable arming')
                latest = self._conn.execute("""SELECT purchase_id FROM inventory_reservation_history
                    WHERE CASE WHEN json_valid(canonical_claim)
                    THEN lower(json_extract(canonical_claim, '$.purchase_artifact.deedLauncherId')) END = ?
                    ORDER BY rowid DESC LIMIT 1""", (deed,)).fetchone()
                if latest is not None and latest['purchase_id'] != purchase_id:
                    raise ValidatorLedgerConflict('Base reservation was superseded while arming')
                for table in ('base_inventory_holds', 'base_inventory_hold_generations'):
                    if self._conn.execute(f'SELECT 1 FROM {table} WHERE reserved_coin_id=? OR global_payment_id=?',
                            (claim.reserved_coin_id, claim.global_payment_id)).fetchone():
                        raise ValidatorLedgerConflict('Base input or payment already belongs to a prior hold')
                table = ('base_inventory_hold_generations' if self._conn.execute(
                    'SELECT 1 FROM base_inventory_holds WHERE deed_launcher_id=?', (deed,)).fetchone() else 'base_inventory_holds')
                self._conn.execute(f'INSERT INTO {table} VALUES (?,?,?,?,?,?,?,NULL)',
                    (purchase_id, deed, claim.reserved_coin_id, claim.global_payment_id, encoded, signature, int(time.time())))
                self._conn.execute('COMMIT')
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute('ROLLBACK')
                raise ValidatorLedgerConflict('Base payment or inventory already has a private hold') from exc
            except Exception:
                self._conn.execute('ROLLBACK')
                raise

    def retain_base_payment_start(self, purchase_id, evidence):
        """Called only after complete independent deposit/claim verification."""
        from .validator_ledger import ValidatorLedgerConflict
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                self._assert_base_not_terminal(purchase_id)
                held = self.base_inventory_hold(purchase_id)
                if held is None:
                    raise ValidatorLedgerConflict('Base payment has no independently armed reservation')
                claim = parse_base_hold(json.loads(held['claim_json']))
                bind_held_deposit(claim, evidence)
                if held['payment_start_json'] is not None:
                    original = json.loads(held['payment_start_json'])
                    if not same_deposit_message(original, evidence):
                        raise ValidatorLedgerConflict('Base payment start cannot be replaced')
                else:
                    self._conn.execute('UPDATE base_inventory_holds SET payment_start_json=? WHERE purchase_id=?',
                        (canonical(evidence), purchase_id))
                    self._conn.execute('UPDATE base_inventory_hold_generations SET payment_start_json=? WHERE purchase_id=?',
                        (canonical(evidence), purchase_id))
                self._conn.execute('COMMIT')
            except Exception:
                self._conn.execute('ROLLBACK')
                raise
