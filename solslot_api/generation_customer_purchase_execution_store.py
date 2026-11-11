"""Durable execution checkpoints in the current checkout's recovered database.

This store grants no signing, fee-selection or broadcast authority. Callers
must reconstruct the typed current reservation/delivery before saving a bundle.
Saved funded bytes survive expiry, reconnects and an uncertain broadcast.
"""
import json
import re

from chia_rs import SpendBundle

from .generation_customer_purchase_store import CurrentCustomerPurchaseStore
from .generation_operations import canonical, bundle_id
from .protocol_submission import PreparedProtocolBundle


class CurrentPurchaseExecutionStore(CurrentCustomerPurchaseStore):
    MAX_EXECUTION_BYTES = 4 * 1024 * 1024

    def __init__(self, path, generation_id):
        super().__init__(path, generation_id)
        with self._connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS current_purchase_execution_policies (
                policy_hash TEXT PRIMARY KEY, maximum_purchases INTEGER NOT NULL,
                fee_cap INTEGER NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS current_purchase_executions (
                intent_id TEXT NOT NULL, phase TEXT NOT NULL,
                protocol_bundle BLOB NOT NULL, original_id TEXT NOT NULL UNIQUE,
                claim_hash TEXT NOT NULL, fee_cap INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, stage TEXT NOT NULL,
                funded_document TEXT, transaction_id TEXT,
                confirmed_height INTEGER, error_code TEXT, updated_at INTEGER NOT NULL,
                PRIMARY KEY(intent_id,phase),
                CHECK(phase IN ('RESERVATION','DELIVERY','RELEASE')),
                FOREIGN KEY(intent_id) REFERENCES current_customer_purchase_reviews(intent_id))''')
            # Preserve every old checkpoint byte for byte when admitting the
            # native timeout phase. No journal or financial cap is reset.
            sql=db.execute("SELECT sql FROM sqlite_master WHERE name='current_purchase_executions'").fetchone()[0]
            if "'RELEASE'" not in sql:
                expected="CHECK(phase IN ('RESERVATION','DELIVERY'))"
                if expected not in sql:raise ValueError('CURRENT_EXECUTION_UNKNOWN_SCHEMA')
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute(sql.replace('current_purchase_executions','current_purchase_executions_next',1).replace(expected,"CHECK(phase IN ('RESERVATION','DELIVERY','RELEASE'))"))
                    db.execute('INSERT INTO current_purchase_executions_next SELECT * FROM current_purchase_executions')
                    db.execute('DROP TABLE current_purchase_executions')
                    db.execute('ALTER TABLE current_purchase_executions_next RENAME TO current_purchase_executions')
                    db.commit()
                except BaseException:db.rollback();raise

    def bind_execution_policy(self, policy_hash, maximum_purchases, fee_cap):
        if (re.fullmatch(r'0x[0-9a-f]{64}', policy_hash or '') is None
                or type(maximum_purchases) is not int or not 1 <= maximum_purchases <= 25
                or type(fee_cap) is not int or not 0 <= fee_cap <= 1_000_000_000):
            raise ValueError('CURRENT_EXECUTION_FINITE_POLICY_REQUIRED')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                if self._collection_binding(db) is not None:
                    raise ValueError('CURRENT_EXECUTION_LEGACY_POLICY_RETIRED')
                row = db.execute('SELECT * FROM current_purchase_execution_policies WHERE policy_hash=?',
                                 (policy_hash,)).fetchone()
                if row is not None:
                    if row['maximum_purchases'] != maximum_purchases or row['fee_cap'] != fee_cap:
                        raise ValueError('CURRENT_EXECUTION_POLICY_LIMIT_IMMUTABLE')
                else:
                    self._execution_capacity(db, 512)
                    db.execute('INSERT INTO current_purchase_execution_policies VALUES (?,?,?)',
                               (policy_hash, maximum_purchases, fee_cap))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @staticmethod
    def _collection_binding(db):
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='current_purchase_collection_execution'").fetchone() is None:
            return None
        row = db.execute('SELECT policy_hash,cutover_hash,fee_cap FROM current_purchase_collection_execution WHERE id=1').fetchone()
        if row is None:
            raise ValueError('CURRENT_EXECUTION_COLLECTION_BINDING_MISSING')
        return tuple(row)

    def require_collection_execution(self, policy_hash, cutover_hash, fee_cap):
        with self._connect() as db:
            if self._collection_binding(db) != (policy_hash, cutover_hash, fee_cap):
                raise ValueError('CURRENT_EXECUTION_COLLECTION_CUTOVER_REQUIRED')

    def _admit_reservation(self, db, identity, claim, *, fee_cap=None, check_inventory=False):
        binding = self._collection_binding(db)
        if binding is not None:
            if binding[0] != claim.issuer_policy_hash or (fee_cap is not None and binding[2] != fee_cap):
                raise ValueError('CURRENT_EXECUTION_BOUND_FEE_POLICY_REQUIRED')
            if check_inventory:
                self._require_unreserved_inventory(db, identity, claim)
            return
        limit = db.execute('SELECT maximum_purchases,fee_cap FROM current_purchase_execution_policies WHERE policy_hash=?',
                           (claim.issuer_policy_hash,)).fetchone()
        if limit is None or (fee_cap is not None and fee_cap != limit['fee_cap']):
            raise ValueError('CURRENT_EXECUTION_BOUND_FEE_POLICY_REQUIRED')
        if check_inventory:
            self._purchase_capacity(db, identity, claim, limit['maximum_purchases'])

    def _require_unreserved_inventory(self, db, identity, claim):
        from .generation_customer_purchase_batch import CurrentReservationBatch, reservation_from_json

        def inputs(value):
            children = value.children if isinstance(value, CurrentReservationBatch) else (value,)
            return {child.available_coin_id for child in children}

        requested = inputs(claim)
        for row in self._active_reservation_rows(db, identity):
            current = reservation_from_json(row['canonical_claim'])
            if (current.issuer_policy_hash == claim.issuer_policy_hash
                    and requested.intersection(inputs(current))
                    and not self._closed_without_preparation(db, row['intent_id'])
                    and not self._expired_unsubmitted_for_capacity(db, row, current)):
                raise ValueError('CURRENT_PRIMARY_DEED_NOT_AVAILABLE')

    @staticmethod
    def _closed_without_preparation(db, identity):
        return db.execute('''SELECT 1 FROM current_purchase_worker_jobs j
            JOIN current_customer_reservation_requests q ON q.intent_id=j.intent_id
            WHERE j.intent_id=? AND j.state='CLOSED' AND j.lease_token IS NULL AND j.lease_until=0
            AND j.expiry_document IS NULL AND j.issuer_document IS NULL
            AND NOT EXISTS(SELECT 1 FROM current_purchase_executions WHERE intent_id=j.intent_id)
            AND NOT EXISTS(SELECT 1 FROM current_customer_purchase_delivery WHERE intent_id=j.intent_id)
            AND NOT EXISTS(SELECT 1 FROM current_customer_purchase_signatures WHERE intent_id=j.intent_id)''',
            (identity,)).fetchone() is not None

    def closed_without_preparation(self, identity, *, browser_hash):
        with self._connect() as db:
            db.execute('BEGIN')
            self._row(db, identity, browser_hash)
            return self._closed_without_preparation(db, identity)

    def _execution(self, db, identity, phase, browser_hash):
        self._row(db, identity, browser_hash)
        if phase not in ('RESERVATION', 'DELIVERY', 'RELEASE'):
            raise ValueError('CURRENT_EXECUTION_PHASE_INVALID')
        row = db.execute('SELECT * FROM current_purchase_executions WHERE intent_id=? AND phase=?',
                         (identity, phase)).fetchone()
        if row is None:
            raise ValueError('CURRENT_EXECUTION_UNAVAILABLE')
        bundle = SpendBundle.from_bytes(row['protocol_bundle'])
        if bytes(bundle) != row['protocol_bundle'] or bundle_id(bundle) != row['original_id']:
            raise ValueError('CURRENT_EXECUTION_SAVED_BYTES_CHANGED')
        return row, bundle

    def _execution_capacity(self, db, additional):
        used = db.execute('''SELECT coalesce(sum(length(protocol_bundle)+
            coalesce(length(CAST(funded_document AS BLOB)),0)+512),0)
            FROM current_purchase_executions''').fetchone()[0]
        if used + additional > self.MAX_CURRENT_RETAINED_BYTES:
            raise ValueError('CURRENT_EXECUTION_RETENTION_FULL')
        self._admit(db, used + additional)

    def _expired_unsubmitted_for_capacity(self,db,row,claim):
        """Verify the retained native proof inside this admission transaction."""
        from .generation_customer_purchase_batch import artifacts
        from .generation_customer_purchase_expiry_proof import valid_expiry_proof
        from .protocol_admission import admission_conditions
        try:
            job=db.execute('SELECT state,lease_token,lease_until,expiry_document,issuer_document FROM current_purchase_worker_jobs WHERE intent_id=?',(row['intent_id'],)).fetchone()
            execution=db.execute("SELECT * FROM current_purchase_executions WHERE intent_id=? AND phase='RESERVATION'",(row['intent_id'],)).fetchone()
            if (job is None or job['state']!='CLOSED' or job['lease_token'] is not None or job['lease_until']!=0 or job['issuer_document'] is not None or not job['expiry_document']
                or len(job['expiry_document'].encode('utf-8'))>4096
                or execution is None or execution['stage']!='PREPARED' or execution['funded_document'] is not None
                or execution['transaction_id'] is not None or execution['confirmed_height'] is not None):return False
            if (db.execute('SELECT 1 FROM current_customer_purchase_delivery WHERE intent_id=?',(row['intent_id'],)).fetchone()
                or db.execute("SELECT 1 FROM current_customer_purchase_signatures WHERE intent_id=? AND phase='delivery'",(row['intent_id'],)).fetchone()
                or db.execute("SELECT 1 FROM current_purchase_executions WHERE intent_id=? AND phase IN ('DELIVERY','RELEASE')",(row['intent_id'],)).fetchone()):return False
            bundle=SpendBundle.from_bytes(execution['protocol_bundle']);proof=json.loads(job['expiry_document'])
            expiry=artifacts(claim)[0].quote_expires_at
            if (bytes(bundle)!=execution['protocol_bundle'] or bundle_id(bundle)!=execution['original_id']
                or row['generation_id']!=self.generation_id or row['claim_hash']!=claim.digest()
                or execution['claim_hash']!=claim.digest() or execution['expires_at']!=expiry):return False
            binding={'schema':'solslot.current-unsubmitted-reservation-expiry.v1','generationId':self.generation_id,
                'intentId':row['intent_id'],'reservationClaimHash':claim.digest(),'bundleId':bundle_id(bundle),
                'absoluteExpiry':expiry,'inputIds':sorted('0x'+coin.name().hex() for coin in bundle.removals())}
            if not valid_expiry_proof(proof,binding):return False
            conditions=admission_conditions(bundle,proof['peakHeight'],'testnet11')
            return conditions.before_seconds_absolute is not None and int(conditions.before_seconds_absolute)==expiry
        except Exception:
            return False

    @staticmethod
    def _active_reservation_rows(db, identity, *, exclude_delivered=True):
        return db.execute('''SELECT r.intent_id,r.generation_id,r.claim_hash,r.canonical_claim FROM current_customer_purchase_reviews r
            WHERE r.intent_id!=?
            AND (?=0 OR NOT EXISTS(SELECT 1 FROM current_purchase_executions sold WHERE sold.intent_id=r.intent_id
                AND sold.phase='DELIVERY' AND sold.stage='CONFIRMED'))
            AND (EXISTS(SELECT 1 FROM current_purchase_executions e
                WHERE e.intent_id=r.intent_id AND e.phase='RESERVATION') OR
                EXISTS(SELECT 1 FROM current_customer_reservation_requests q WHERE q.intent_id=r.intent_id))
            AND NOT EXISTS(SELECT 1 FROM current_purchase_executions released
                WHERE released.intent_id=r.intent_id AND released.phase='RELEASE'
                  AND released.stage='CONFIRMED' AND released.confirmed_height>0
                  AND released.transaction_id IS NOT NULL
                  AND NOT EXISTS(SELECT 1 FROM current_customer_purchase_delivery paid
                      WHERE paid.intent_id=r.intent_id)
                  AND NOT EXISTS(SELECT 1 FROM current_purchase_executions delivery
                      WHERE delivery.intent_id=r.intent_id AND delivery.phase='DELIVERY'))''',(identity, exclude_delivered)).fetchall()

    def _purchase_capacity(self,db,identity,reservation,maximum):
        from .generation_customer_purchase_batch import reservation_from_json,CurrentReservationBatch
        quantity=lambda c:len(c.children)if isinstance(c,CurrentReservationBatch)else 1
        rows = self._active_reservation_rows(db, identity, exclude_delivered=False)
        claims=[(r,reservation_from_json(r['canonical_claim'])) for r in rows]
        used=sum(quantity(c) for r,c in claims if c.issuer_policy_hash==reservation.issuer_policy_hash and not self._expired_unsubmitted_for_capacity(db,r,c))
        if used+quantity(reservation)>maximum:raise ValueError('CURRENT_EXECUTION_POLICY_CAPACITY_EXHAUSTED')

    def reservation_request(self,identity,*,browser_hash):
        with self._connect()as db:
            self._row(db,identity,browser_hash)
            row=db.execute('SELECT requested_at FROM current_customer_reservation_requests WHERE intent_id=?',(identity,)).fetchone()
        return row[0]if row else None

    def unstarted_review(self,identity,*,browser_hash):
        """One read snapshot; partial reservation evidence is never removed."""
        with self._connect()as db:
            db.execute('BEGIN')
            saved=self._saved_document(db,identity,browser_hash)
            replies=saved['retainedSignatures'];claim=saved['reservationClaim']
            if (saved['deliveryClaim']is not None or replies['delivery']
                    or not set(replies['reservation']).issubset(claim.signer_indices)
                    or len(replies['reservation'])>=len(claim.signer_indices)
                    or db.execute('SELECT 1 FROM current_customer_reservation_requests WHERE intent_id=?',(identity,)).fetchone()
                    or db.execute('SELECT 1 FROM current_purchase_executions WHERE intent_id=?',(identity,)).fetchone()):
                raise ValueError('CURRENT_CHECKOUT_REVIEW_RECOVERY_REQUIRED')
            return saved

    def request_reservation(self,identity,*,browser_hash,now):
        """Explicit durable customer intent; reads never enqueue work."""
        from .generation_customer_purchase_batch import artifacts
        with self._connect()as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                _,claim=self._row(db,identity,browser_hash)
                row=db.execute('SELECT requested_at FROM current_customer_reservation_requests WHERE intent_id=?',(identity,)).fetchone()
                if row is not None:
                    db.commit();return row[0]
                if type(now)is not int or not 0<now<artifacts(claim)[0].quote_expires_at:
                    raise ValueError('CURRENT_EXECUTION_PURCHASE_WINDOW_CLOSED')
                self._admit_reservation(db, identity, claim, check_inventory=True)
                self._execution_capacity(db,128)
                db.execute('INSERT INTO current_customer_reservation_requests VALUES(?,?)',(identity,now))
                db.commit();return now
            except BaseException:db.rollback();raise

    def prepare_execution(self, identity, phase, bundle, *, browser_hash, claim_hash,
                          fee_cap, expires_at, now):
        if (not isinstance(bundle, SpendBundle) or phase not in ('RESERVATION', 'DELIVERY', 'RELEASE')
                or type(fee_cap) is not int or not 0 <= fee_cap <= 1_000_000_000
                or type(now) is not int or type(expires_at) is not int
                or not 0 < now < expires_at or not 1 <= len(bundle.coin_spends) <= 256
                or len({s.coin.name() for s in bundle.coin_spends}) != len(bundle.coin_spends)):
            raise ValueError('CURRENT_EXECUTION_BOUNDS_INVALID')
        raw = bytes(bundle)
        if len(raw) > self.MAX_EXECUTION_BYTES:
            raise ValueError('CURRENT_EXECUTION_TOO_LARGE')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                _, reservation = self._row(db, identity, browser_hash)
                self._admit_reservation(db, identity, reservation, fee_cap=fee_cap)
                if phase == 'RESERVATION':
                    expected_claim = reservation.digest()
                elif phase == 'DELIVERY':
                    prior = db.execute('SELECT claim_hash FROM current_customer_purchase_delivery WHERE intent_id=?',
                                       (identity,)).fetchone()
                    if prior is None:
                        raise ValueError('CURRENT_EXECUTION_SAVED_BUYER_REQUIRED')
                    expected_claim = prior['claim_hash']
                    confirmed = db.execute('SELECT stage FROM current_purchase_executions WHERE intent_id=? AND phase=?',
                                           (identity, 'RESERVATION')).fetchone()
                    if confirmed is None or confirmed['stage'] != 'CONFIRMED':
                        raise ValueError('CURRENT_EXECUTION_CONFIRMED_RESERVATION_REQUIRED')
                else:
                    expected_claim=reservation.digest()
                    confirmed=db.execute("SELECT stage FROM current_purchase_executions WHERE intent_id=? AND phase='RESERVATION'",(identity,)).fetchone()
                    if confirmed is None or confirmed['stage']!='CONFIRMED':
                        raise ValueError('CURRENT_EXECUTION_CONFIRMED_RESERVATION_REQUIRED')
                    delivered=db.execute("SELECT stage FROM current_purchase_executions WHERE intent_id=? AND phase='DELIVERY'",(identity,)).fetchone()
                    if delivered is not None and delivered['stage']=='CONFIRMED':
                        raise ValueError('CURRENT_EXECUTION_ALREADY_DELIVERED')
                if claim_hash != expected_claim:
                    raise ValueError('CURRENT_EXECUTION_REVIEW_CHANGED')
                row = db.execute('SELECT * FROM current_purchase_executions WHERE intent_id=? AND phase=?',
                                 (identity, phase)).fetchone()
                if row is not None:
                    if (row['protocol_bundle'] != raw or row['claim_hash'] != claim_hash
                            or row['fee_cap'] != fee_cap or row['expires_at'] != expires_at):
                        raise ValueError('CURRENT_EXECUTION_REPLACEMENT_REJECTED')
                else:
                    if phase == 'RESERVATION':
                        self._admit_reservation(db, identity, reservation, fee_cap=fee_cap, check_inventory=True)
                    self._execution_capacity(db, len(raw) + 512)
                    db.execute('''INSERT INTO current_purchase_executions
                        (intent_id,phase,protocol_bundle,original_id,claim_hash,fee_cap,
                         expires_at,stage,updated_at) VALUES (?,?,?,?,?,?,?,?,?)''',
                        (identity, phase, raw, bundle_id(bundle), claim_hash, fee_cap,
                         expires_at, 'PREPARED', now))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return self.execution_status(identity, phase, browser_hash=browser_hash)

    def execution_bundle(self, identity, phase, *, browser_hash):
        with self._connect() as db:
            return self._execution(db, identity, phase, browser_hash)[1]

    def save_execution_funding(self, identity, phase, prepared, *, browser_hash, now):
        if not isinstance(prepared, PreparedProtocolBundle) or type(now) is not int or now <= 0:
            raise ValueError('CURRENT_EXECUTION_TYPED_FUNDING_REQUIRED')
        document = canonical(prepared.to_json())
        if len(document.encode()) > self.MAX_EXECUTION_BYTES:
            raise ValueError('CURRENT_EXECUTION_FUNDING_TOO_LARGE')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row, original = self._execution(db, identity, phase, browser_hash)
                final = {s.coin.name(): bytes(s) for s in prepared.bundle.coin_spends}
                if (len(final) != len(prepared.bundle.coin_spends) or prepared.backing_mojos != 0
                        or not 0 <= prepared.fee_mojos <= row['fee_cap']
                        or any(final.get(s.coin.name()) != bytes(s) for s in original.coin_spends)):
                    raise ValueError('CURRENT_EXECUTION_FUNDING_CHANGED_PROTOCOL_OR_CAP')
                if row['funded_document'] is not None:
                    if row['funded_document'] != document:
                        raise ValueError('CURRENT_EXECUTION_FUNDED_BYTES_IMMUTABLE')
                else:
                    # Retain the submitter's already reserved bytes even when
                    # its callback arrives after expiry. This method cannot
                    # select fees or broadcast. The dispatcher checks the live
                    # deadline again after this checkpoint and before push.
                    if row['stage'] != 'PREPARED':
                        raise ValueError('CURRENT_EXECUTION_ALREADY_FINAL')
                    self._execution_capacity(db, len(document.encode()))
                    db.execute('''UPDATE current_purchase_executions SET funded_document=?,
                        transaction_id=?,stage='RECONCILING',updated_at=? WHERE intent_id=? AND phase=?''',
                        (document, prepared.spend_bundle_id, now, identity, phase))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def execution_funding(self, identity, phase, *, browser_hash):
        with self._connect() as db:
            row, _ = self._execution(db, identity, phase, browser_hash)
            if row['funded_document'] is None:
                return None
            result = json.loads(row['funded_document'])
            bundle = SpendBundle.from_json_dict(result['spendBundle'])
            if bundle_id(bundle) != row['transaction_id'] or result['spendBundleId'] != row['transaction_id']:
                raise ValueError('CURRENT_EXECUTION_FUNDED_ID_CHANGED')
            return result

    def observe_execution(self, identity, phase, *, browser_hash, transaction_id,
                          status, confirmed_height=None, now):
        if status not in ('MEMPOOL', 'CONFIRMED', 'RECONCILING') or type(now) is not int or now <= 0:
            raise ValueError('CURRENT_EXECUTION_OBSERVATION_INVALID')
        if status == 'CONFIRMED' and (type(confirmed_height) is not int or confirmed_height <= 0):
            raise ValueError('CURRENT_EXECUTION_CONFIRMED_HEIGHT_REQUIRED')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row, _ = self._execution(db, identity, phase, browser_hash)
                if row['transaction_id'] is None or transaction_id != row['transaction_id']:
                    raise ValueError('CURRENT_EXECUTION_EXACT_SAVED_TRANSACTION_REQUIRED')
                if row['stage'] != 'CONFIRMED':
                    db.execute('''UPDATE current_purchase_executions SET stage=?,confirmed_height=?,
                        updated_at=?,error_code=NULL WHERE intent_id=? AND phase=?''',
                        (status, confirmed_height if status == 'CONFIRMED' else None, now, identity, phase))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return self.execution_status(identity, phase, browser_hash=browser_hash)

    def execution_status(self, identity, phase, *, browser_hash):
        with self._connect() as db:
            row, _ = self._execution(db, identity, phase, browser_hash)
        return {'intentId': identity, 'phase': phase, 'stage': row['stage'],
                'transactionId': row['transaction_id'], 'originalBundleId': row['original_id'],
                'feeCapMojos': str(row['fee_cap']), 'expiresAt': row['expires_at'],
                'confirmedHeight': row['confirmed_height'], 'updatedAt': row['updated_at']}
