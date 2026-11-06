"""Durable current checkout work in the existing recovered payment database.

This store is not admission authority. Native evidence, the frozen finite
policy, wallet review and fee admission must still pass before signing or
submission. Reads only recover saved work; they never renew a quote, select
inputs, invoke a signer or cause a broadcast.
"""
from hashlib import sha256
import json
import re

from .generation_context import generation_bytes
from .generation_operations import canonical
from .generation_storage import generation_path, admit_retained_bytes
from .generation_customer_purchase_reservation import CurrentReservationClaim
from .generation_customer_purchase_delivery import CurrentDeliveryClaim
from .payment_purchase_store import PaymentPurchaseStore
from .validator_quorum import ValidatorSignatureResponse


class CurrentCustomerPurchaseStore(PaymentPurchaseStore):
    """Add bounded, immutable review work to the existing payment journal.

    The browser binding is a server-generated digest, never a wallet address
    or a credential. Identical retries retain the same review and signatures.
    Different quotes and signed payer offers cannot overwrite one another.
    """
    MAX_CURRENT_RETAINED_BYTES = 64 * 1024 * 1024
    MAX_CURRENT_REVIEWS = 128

    def __init__(self, path, generation_id):
        generation_bytes(generation_id)
        if path == ':memory:':
            raise ValueError('CURRENT_CHECKOUT_DURABLE_PATH_REQUIRED')
        self.generation_id = generation_id
        super().__init__(generation_path(str(path), generation_id))
        with self._connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS current_customer_purchase_reviews (
                    intent_id TEXT PRIMARY KEY,
                    generation_id TEXT NOT NULL,
                    browser_hash TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    claim_hash TEXT NOT NULL UNIQUE,
                    canonical_claim TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE(generation_id,browser_hash,request_key));
                CREATE TABLE IF NOT EXISTS current_customer_purchase_delivery (
                    intent_id TEXT PRIMARY KEY,
                    claim_hash TEXT NOT NULL UNIQUE,
                    canonical_claim TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(intent_id) REFERENCES current_customer_purchase_reviews(intent_id));
                CREATE TABLE IF NOT EXISTS current_customer_purchase_signatures (
                    intent_id TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK(phase IN ('reservation','delivery')),
                    signer_index INTEGER NOT NULL CHECK(signer_index IN (0,1,2)),
                    canonical_reply TEXT NOT NULL,
                    PRIMARY KEY(intent_id,phase,signer_index),
                    FOREIGN KEY(intent_id) REFERENCES current_customer_purchase_reviews(intent_id));
            ''')

    def _admit(self, db, additional):
        retained = db.execute('''SELECT
            (SELECT coalesce(sum(length(CAST(canonical_claim AS BLOB))+512),0)
                FROM current_customer_purchase_reviews) +
            (SELECT coalesce(sum(length(CAST(canonical_claim AS BLOB))+512),0)
                FROM current_customer_purchase_delivery) +
            (SELECT coalesce(sum(length(CAST(canonical_reply AS BLOB))+128),0)
                FROM current_customer_purchase_signatures)''').fetchone()[0]
        admit_retained_bytes(db, retained, additional, self.MAX_CURRENT_RETAINED_BYTES)

    def _row(self, db, identity, browser_hash):
        if re.fullmatch(r'[0-9a-f]{64}', browser_hash or '') is None:
            raise ValueError('CURRENT_CHECKOUT_BROWSER_BINDING_REQUIRED')
        row = db.execute('''SELECT * FROM current_customer_purchase_reviews
            WHERE intent_id=? AND generation_id=? AND browser_hash=?''',
            (identity, self.generation_id, browser_hash)).fetchone()
        if row is None:
            raise ValueError('CURRENT_CHECKOUT_REVIEW_UNAVAILABLE')
        claim = CurrentReservationClaim.model_validate_json(row['canonical_claim'])
        if claim.generation_id != self.generation_id or claim.digest() != row['claim_hash']:
            raise ValueError('CURRENT_CHECKOUT_SAVED_REVIEW_CHANGED')
        return row, claim

    def save_review(self, claim, *, browser_hash, request_key, now):
        if (not isinstance(claim, CurrentReservationClaim)
                or claim.generation_id != self.generation_id
                or re.fullmatch(r'[0-9a-f]{64}', browser_hash or '') is None
                or not isinstance(request_key, str)
                or re.fullmatch(r'[A-Za-z0-9_:-]{1,128}', request_key) is None
                or type(now) is not int or now <= 0):
            raise ValueError('CURRENT_CHECKOUT_REVIEW_BINDING_INVALID')
        claim = CurrentReservationClaim.model_validate_json(claim.model_dump_json(by_alias=True))
        document, digest = claim.canonical(), claim.digest()
        identity = '0x' + sha256(canonical([
            self.generation_id, browser_hash, request_key]).encode()).hexdigest()
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row = db.execute('SELECT * FROM current_customer_purchase_reviews WHERE intent_id=?',
                    (identity,)).fetchone()
                if row is not None:
                    if row['canonical_claim'] != document or row['claim_hash'] != digest:
                        raise ValueError('CURRENT_CHECKOUT_RETRY_CHANGES_REVIEW')
                else:
                    if db.execute('SELECT count(*) FROM current_customer_purchase_reviews').fetchone()[0] >= self.MAX_CURRENT_REVIEWS:
                        raise ValueError('CURRENT_CHECKOUT_REVIEW_RETENTION_FULL')
                    if db.execute('SELECT 1 FROM current_customer_purchase_reviews WHERE claim_hash=?', (digest,)).fetchone():
                        raise ValueError('CURRENT_CHECKOUT_REVIEW_ALREADY_BOUND')
                    self._admit(db, len(document.encode()) + 512)
                    db.execute('INSERT INTO current_customer_purchase_reviews VALUES (?,?,?,?,?,?,?)',
                        (identity, self.generation_id, browser_hash, request_key, digest, document, now))
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        return identity

    def save_delivery(self, identity, claim, *, browser_hash, now):
        if not isinstance(claim, CurrentDeliveryClaim) or type(now) is not int or now <= 0:
            raise ValueError('CURRENT_CHECKOUT_TYPED_DELIVERY_REQUIRED')
        claim = CurrentDeliveryClaim.model_validate_json(claim.model_dump_json(by_alias=True))
        document, digest = claim.canonical(), claim.digest()
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row, reservation = self._row(db, identity, browser_hash)
                if claim.reservation.canonical() != reservation.canonical():
                    raise ValueError('CURRENT_CHECKOUT_DELIVERY_CHANGES_RESERVATION')
                old = db.execute('SELECT * FROM current_customer_purchase_delivery WHERE intent_id=?', (identity,)).fetchone()
                if old is not None:
                    if old['canonical_claim'] != document or old['claim_hash'] != digest:
                        raise ValueError('CURRENT_CHECKOUT_SIGNED_PAYER_OFFER_ALREADY_BOUND')
                else:
                    self._admit(db, len(document.encode()) + 512)
                    db.execute('INSERT INTO current_customer_purchase_delivery VALUES (?,?,?,?)',
                        (identity, digest, document, now))
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def save_signature(self, identity, phase, index, reply, *, browser_hash):
        """Retain a quorum-verified response before the next network request.

        The quorum collector verifies the actual BLS message before invoking
        this hook, and re-verifies every retained response on recovery.
        """
        if phase not in ('reservation', 'delivery') or type(index) is not int:
            raise ValueError('CURRENT_CHECKOUT_SIGNATURE_PHASE_INVALID')
        reply = ValidatorSignatureResponse.model_validate(reply)
        document = canonical(reply.model_dump(mode='json'))
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row, reservation = self._row(db, identity, browser_hash)
                expected = row['claim_hash']
                if phase == 'delivery':
                    saved = db.execute('SELECT claim_hash FROM current_customer_purchase_delivery WHERE intent_id=?', (identity,)).fetchone()
                    if saved is None:
                        raise ValueError('CURRENT_CHECKOUT_DELIVERY_NOT_SAVED')
                    expected = saved['claim_hash']
                if index not in reservation.signer_indices or reply.signerIndex != index or reply.claimHash != expected:
                    raise ValueError('CURRENT_CHECKOUT_SIGNATURE_BINDING_CHANGED')
                old = db.execute('''SELECT canonical_reply FROM current_customer_purchase_signatures
                    WHERE intent_id=? AND phase=? AND signer_index=?''', (identity, phase, index)).fetchone()
                if old is not None:
                    if old[0] != document:
                        raise ValueError('CURRENT_CHECKOUT_SAVED_SIGNATURE_CHANGED')
                else:
                    self._admit(db, len(document.encode()) + 128)
                    db.execute('INSERT INTO current_customer_purchase_signatures VALUES (?,?,?,?)',
                        (identity, phase, index, document))
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def saved(self, identity, *, browser_hash):
        """Read only; expiry never destroys signed recovery evidence."""
        with self._connect() as db:
            row, reservation = self._row(db, identity, browser_hash)
            delivery = db.execute('SELECT * FROM current_customer_purchase_delivery WHERE intent_id=?', (identity,)).fetchone()
            parsed = CurrentDeliveryClaim.model_validate_json(delivery['canonical_claim']) if delivery else None
            if parsed and (parsed.digest() != delivery['claim_hash'] or parsed.reservation.canonical() != reservation.canonical()):
                raise ValueError('CURRENT_CHECKOUT_SAVED_DELIVERY_CHANGED')
            responses = {'reservation': {}, 'delivery': {}}
            for value in db.execute('SELECT * FROM current_customer_purchase_signatures WHERE intent_id=?', (identity,)):
                responses[value['phase']][value['signer_index']] = json.loads(value['canonical_reply'])
        return {'intentId': identity, 'generationId': self.generation_id,
            'reservationClaim': reservation, 'deliveryClaim': parsed,
            'retainedSignatures': responses, 'createdAt': row['created_at']}

    def review_for_request(self, request_key, *, browser_hash):
        if (not isinstance(request_key,str) or re.fullmatch(r'[A-Za-z0-9_:-]{1,128}',request_key) is None
                or not isinstance(browser_hash,str) or re.fullmatch(r'[0-9a-f]{64}',browser_hash) is None):
            raise ValueError('CURRENT_CHECKOUT_BROWSER_BINDING_REQUIRED')
        with self._connect() as db:
            row=db.execute('''SELECT intent_id FROM current_customer_purchase_reviews
                WHERE generation_id=? AND browser_hash=? AND request_key=?''',
                (self.generation_id,browser_hash,request_key)).fetchone()
        return self.saved(row[0],browser_hash=browser_hash) if row else None

    def request_price_refresh(self, *, now):
        """Coalesce explicit quote requests into one durable generation job."""
        if type(now) is not int or now <= 0:
            raise ValueError('CURRENT_PRICE_REFRESH_CLOCK_INVALID')
        identity = 'price-refresh:' + self.generation_id
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row = db.execute('SELECT * FROM payment_checkout_jobs WHERE purchase_id=? AND lane=?',
                    (identity, 'price-refresh')).fetchone()
                if row is None:
                    db.execute('INSERT INTO payment_checkout_jobs(purchase_id,lane,due_at) VALUES (?,?,?)',
                        (identity, 'price-refresh', now))
                elif row['done'] and row['due_at'] <= now:
                    # Only an explicit new request rearms a terminal job. Its
                    # previous backoff remains effective until due_at.
                    db.execute("UPDATE payment_checkout_jobs SET done=0,owner=NULL,lease_until=0,"
                        "attempts=0,status='WAITING',observed_at=NULL,due_at=? WHERE purchase_id=? AND lane=?",
                        (now, identity, 'price-refresh'))
                row = db.execute('SELECT * FROM payment_checkout_jobs WHERE purchase_id=? AND lane=?',
                    (identity, 'price-refresh')).fetchone()
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        return {'status':row['status'],'done':bool(row['done']),'nextAttemptAt':row['due_at'],'attempts':row['attempts']}

    def price_refresh_job_status(self):
        """Pure read; polling never schedules or executes work."""
        identity = 'price-refresh:' + self.generation_id
        with self._connect() as db:
            row = db.execute('SELECT * FROM payment_checkout_jobs WHERE purchase_id=? AND lane=?',
                (identity, 'price-refresh')).fetchone()
        return None if row is None else {'status':row['status'],'done':bool(row['done']),
            'nextAttemptAt':row['due_at'],'attempts':row['attempts'],'observedAt':row['observed_at']}
