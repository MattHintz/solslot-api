"""Additive lifecycle evidence; schema-14 exclusions remain original records."""
import json
import time

from .base_lifecycle_claims import BasePaymentStartClaim, BaseInventoryExtensionClaim
from .escrow_deposit import same_deposit_message
from .inventory_extension_store import canonical


def migrate_base_lifecycle(db):
    db.executescript('''
        BEGIN IMMEDIATE;
        CREATE TABLE base_lifecycle_observations (
            claim_hash TEXT PRIMARY KEY, purchase_id TEXT NOT NULL,
            release_identity TEXT NOT NULL, claim_json TEXT NOT NULL,
            signature TEXT NOT NULL, signed_at INTEGER NOT NULL,
            UNIQUE(purchase_id, release_identity)
        );
        CREATE TABLE base_lifecycle_terminals (
            purchase_id TEXT PRIMARY KEY, global_payment_id TEXT NOT NULL UNIQUE,
            claim_json TEXT NOT NULL, signature TEXT NOT NULL, signed_at INTEGER NOT NULL
        );
        CREATE TABLE base_inventory_hold_generations (
            purchase_id TEXT PRIMARY KEY, deed_launcher_id TEXT NOT NULL,
            reserved_coin_id TEXT NOT NULL UNIQUE, global_payment_id TEXT NOT NULL UNIQUE,
            claim_json TEXT NOT NULL, signature TEXT NOT NULL, signed_at INTEGER NOT NULL,
            payment_start_json TEXT
        );
        CREATE INDEX base_hold_generation_deed ON base_inventory_hold_generations(deed_launcher_id);
        PRAGMA user_version=15;
        COMMIT;
    ''')


class BaseLifecycleLedgerMixin:
    def _assert_base_paid_payment(self, purchase_id, payment_id):
        from .validator_ledger import ValidatorLedgerConflict
        self._assert_base_not_terminal(purchase_id)
        held = self.base_inventory_hold(purchase_id)
        observed = self._conn.execute('SELECT 1 FROM base_lifecycle_observations WHERE purchase_id=?', (purchase_id,)).fetchone()
        if (held is None or observed is None or held['payment_start_json'] is None
                or held['global_payment_id'] != payment_id):
            raise ValidatorLedgerConflict('Base paid recovery requires independently reviewed lifecycle evidence')

    def base_lifecycle_terminal(self, purchase_id):
        with self._lock:
            row = self._conn.execute('SELECT * FROM base_lifecycle_terminals WHERE purchase_id=?', (purchase_id,)).fetchone()
            return dict(row) if row else None

    def _assert_base_not_terminal(self, purchase_id):
        from .validator_ledger import ValidatorLedgerConflict
        if self.base_lifecycle_terminal(purchase_id) is not None:
            raise ValidatorLedgerConflict('Base purchase has an immutable terminal tombstone')

    def record_base_lifecycle_terminal(self, claim, signature):
        from .validator_ledger import ValidatorLedgerConflict
        purchase_id = claim.hold.purchase_artifact['purchaseId']
        encoded = canonical(claim.model_dump(mode='json'))
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                old = self.base_lifecycle_terminal(purchase_id)
                if old:
                    if old['claim_json'] != encoded:
                        raise ValidatorLedgerConflict('Base terminal evidence cannot be replaced')
                    self._conn.execute('COMMIT')
                    return old['signature']
                held = self.base_inventory_hold(purchase_id)
                if held:
                    if held['claim_json'] != canonical(claim.hold.model_dump(mode='json')):
                        raise ValidatorLedgerConflict('Base terminal changes the private hold')
                    if held['payment_start_json'] is not None and (claim.payment_evidence is None
                            or not same_deposit_message(json.loads(held['payment_start_json']), claim.payment_evidence)):
                        raise ValidatorLedgerConflict('Base terminal cannot erase verified funding')
                self._conn.execute('INSERT INTO base_lifecycle_terminals VALUES (?,?,?,?,?)',
                    (purchase_id, claim.hold.global_payment_id, encoded, signature, int(time.time())))
                self._conn.execute('COMMIT')
                return signature
            except Exception:
                self._conn.execute('ROLLBACK')
                raise

    def record_base_lifecycle_observation(self, claim, signature):
        from .validator_ledger import ValidatorLedgerConflict
        purchase_id = claim.purchase_artifact['purchaseId']
        # Identity retention is deliberately not spend authority.
        self.retain_base_payment_start(purchase_id, claim.payment_evidence)
        with self._lock:
            self._conn.execute('BEGIN IMMEDIATE')
            try:
                self._assert_base_not_terminal(purchase_id)
                held = self.base_inventory_hold(purchase_id)
                if held['claim_json'] != canonical(claim.hold.model_dump(mode='json')):
                    raise ValidatorLedgerConflict('Base observation changes its original private hold')
                old = self._conn.execute('SELECT * FROM base_lifecycle_observations WHERE purchase_id=? AND release_identity=?',
                    (purchase_id, claim.activation['releaseIdentity'])).fetchone()
                if old:
                    original = BasePaymentStartClaim.model_validate_json(old['claim_json'])
                    if original != claim:
                        raise ValidatorLedgerConflict('Base observation cannot replace its original signed evidence')
                    self._conn.execute('COMMIT')
                    return old['signature']
                self._conn.execute('INSERT INTO base_lifecycle_observations VALUES (?,?,?,?,?,?)',
                    (claim.canonical_hash(), purchase_id, claim.activation['releaseIdentity'],
                     canonical(claim.model_dump(mode='json')), signature, int(time.time())))
                self._conn.execute('COMMIT')
                return signature
            except Exception:
                self._conn.execute('ROLLBACK')
                raise

    def _assert_base_extension_payment(self, purchase_id, raw):
        """Writer-lock recheck shared by every Base extension journal entry."""
        from .validator_ledger import ValidatorLedgerConflict
        try:
            self._assert_base_not_terminal(purchase_id)
            claim = BaseInventoryExtensionClaim.model_validate(raw)
            held = self.base_inventory_hold(purchase_id)
            observed = self._conn.execute('SELECT * FROM base_lifecycle_observations WHERE purchase_id=? AND release_identity=?',
                (purchase_id, claim.activation['releaseIdentity'])).fetchone()
            if held is None or observed is None:
                raise ValueError('missing independently verified Base observation')
            original = BasePaymentStartClaim.model_validate_json(observed['claim_json'])
            if (claim.purchase_artifact['purchaseId'] != purchase_id
                    or claim.hold != original.hold or claim.purchase_artifact != original.purchase_artifact
                    or claim.activation != original.activation or claim.genesis_artifact_hash != original.genesis_artifact_hash
                    or not same_deposit_message(original.payment_evidence, claim.payment_evidence)
                    or held['claim_json'] != canonical(claim.hold.model_dump(mode='json'))):
                raise ValueError('Base extension changes its original observation')
        except (ValueError, KeyError, TypeError) as exc:
            raise ValidatorLedgerConflict('Base extension lacks its exact private payment authority') from exc
