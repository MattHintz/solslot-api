"""Durable lifecycle for exact new-generation native operations.

This module grants no authority and exposes no write route. Admission, wallet
review and the deployment's approved fee policy are external prerequisites.
ProtocolBundleSubmitter owns fee selection and its existing write-once journal;
this journal keeps the UI operation stable across retries and process restarts.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import asyncio
import logging
import time

from chia_rs import SpendBundle
from solslot_puzzles.generation_transactions import NativeOperation
from .generation_context import generation_bytes
from .generation_storage import connect_generation_sqlite, generation_path, admit_retained_bytes, GenerationRetentionFull
from .protocol_submission import PreparedProtocolBundle, ProtocolSubmissionError

KINDS = frozenset({'ANCHOR_VOTE', 'FINALIZE_VOTE', 'RATIFY_UPGRADE', 'ACTIVATE_UPGRADE',
                   'RATIFY_REOPENING', 'REOPEN_OPERATIONS', 'OPEN_PROPOSAL', 'CAST_VOTE', 'UNLOCK_STAKES',
                   'APPLY_PARAMETERS', 'APPLY_STATUTES', 'FUND_REDEMPTION', 'CLOSE_REWARD_EPOCH', 'ADVANCE_SGT_REWARDS','CLAIM_SGT_REWARD', 'CREATE_RECIPIENT_VAULT', 'INITIALIZE_GENERATION', 'PROVE_STATE', 'PAUSE_NEW_OPERATIONS', 'MINT_COLLECTION', 'PRIMARY_SOLS_BATCH'})
# Native mint/allocation builders do not become publicly submit-able merely
# because they exist. Add a journal kind only with its sealed-source review,
# exact UI lifecycle, funding holds, admission and reconciliation integration.
ERRORS = frozenset({'NODE_UNAVAILABLE', 'RECONCILIATION_REQUIRED', 'FEE_CAP_EXCEEDED',
    'CHAIN_WAIT_REQUIRED', 'CHAIN_WINDOW_EXPIRED', 'INPUT_STATE_CHANGED', 'NATIVE_VALIDATION_FAILED'})
MAX_BUNDLE_BYTES = 2_000_000
MAX_FUNDED_DOCUMENT_BYTES = 8_000_000
logger=logging.getLogger(__name__)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def bundle_id(bundle):
    return '0x' + bundle.name().hex()


class GenerationOperationJournal:
    MAX_RETAINED_BYTES = 256 * 1024 * 1024
    MAX_REVIEW_ALIASES = 10000
    def __init__(self, path: str, generation_id: str):
        generation_bytes(generation_id)
        self.generation_id = generation_id
        self.path = generation_path(path, generation_id)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600); os.close(fd)
        with self._db() as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS generation_operations (
                    operation_id TEXT PRIMARY KEY, request_key TEXT UNIQUE NOT NULL,
                    intent_hash TEXT NOT NULL, kind TEXT NOT NULL, protocol_bundle BLOB NOT NULL,
                    original_id TEXT NOT NULL UNIQUE, fee_cap INTEGER NOT NULL,
                    stage TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    funded_document TEXT, transaction_id TEXT, error_code TEXT,
                    confirmed_height INTEGER, last_checked_at INTEGER);
                CREATE TABLE IF NOT EXISTS generation_operation_reviews (
                    request_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
                    operation_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS generation_review_documents (
                    operation_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
                    document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS generation_expiry_proofs (
                    operation_id TEXT PRIMARY KEY, proof TEXT NOT NULL);
            ''')

    @contextmanager
    def _db(self, write=False):
        db = connect_generation_sqlite(self.path, timeout=5, isolation_level=None, generation_id=self.generation_id)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            if write: db.execute('BEGIN IMMEDIATE')
            yield db
            if write: db.execute('COMMIT')
        except BaseException:
            if db.in_transaction: db.execute('ROLLBACK')
            raise
        finally: db.close()

    def _row(self, db, identity):
        row = db.execute('SELECT * FROM generation_operations WHERE operation_id=?', (identity,)).fetchone()
        if row is None: raise ValueError('operation does not exist in this generation')
        return row

    def reviewed_request(self, request_key, request_digest):
        with self._db() as db:
            row=db.execute('SELECT request_digest,operation_id FROM generation_operation_reviews WHERE request_key=?',
                           (request_key,)).fetchone()
        if row and row['request_digest']!=request_digest:
            raise ValueError('retry changes the reviewed request')
        return self.status(row['operation_id']) if row else None

    def request_status(self, request_key):
        """Cached recovery of a deterministic request; never rebuild an action."""
        with self._db() as db:
            row = db.execute('SELECT operation_id FROM generation_operation_reviews WHERE request_key=?', (request_key,)).fetchone()
        return self.status(row[0]) if row else None

    def reserved_input_coin_ids(self):
        with self._db() as db:
            rows = db.execute("SELECT protocol_bundle FROM generation_operations WHERE stage NOT IN ('CONFIRMED','EXPIRED_RECONCILED')").fetchall()
        # Conservative holds survive preparation and dispatch failures. Confirmed
        # coins are already spent; retained inputs are never silently released.
        return {'0x'+coin.name().hex() for row in rows for coin in SpendBundle.from_bytes(row[0]).removals()}

    def prepare(self, operation: NativeOperation, request_key: str, fee_cap: int, now: int, *, request_digest=None, request_document=None):
        if ('0x' + operation.generation.hex() != self.generation_id or operation.kind not in KINDS
                or not isinstance(request_key, str) or not 1 <= len(request_key) <= 128
                or any(not (c.isascii() and (c.isalnum() or c in '-_:')) for c in request_key)
                or type(fee_cap) is not int or not 0 <= fee_cap <= 1_000_000_000
                or type(now) is not int or now <= 0):
            raise ValueError('operation requires exact generation, bounded request key and reviewed fee cap')
        protocol = operation.bundle()
        raw = bytes(protocol)
        if len(raw) > MAX_BUNDLE_BYTES: raise ValueError('native operation exceeds its storage bound')
        intent = '0x' + operation.commitment.hex()
        identity = '0x' + sha256(canonical([self.generation_id, intent, fee_cap]).encode()).hexdigest()
        if request_digest is not None:
            generation_bytes(request_digest)
        document=None
        if operation.kind=='MINT_COLLECTION' and (request_document is None or len(operation.successors)!=3
                or not 1<=len(operation.auxiliary_outputs)<=100
                or len(operation.spends)!=3+2*len(operation.auxiliary_outputs)):
            raise ValueError('mint requires its exact source-backed batch review and outputs')
        if operation.kind=='PRIMARY_SOLS_BATCH' and (request_document is None
                or len(operation.successors)!=3 or not 1<=len(operation.auxiliary_outputs)<=8
                or not request_document.get('batchCommitment') or not request_document.get('primaryCoinId')
                or not 1<=len(request_document.get('primaryCoinIds',()))<=8
                or len(request_document['primaryCoinIds'])!=len(operation.auxiliary_outputs)
                or not 1<=len(request_document.get('orderIds',()))<=32
                or request_document.get('backingCoinId')!='0x'+operation.auxiliary_outputs[0].name().hex()
                or request_document.get('backingCoinIds')!=['0x'+c.name().hex() for c in operation.auxiliary_outputs]
                or not isinstance(request_document.get('issuanceBackingMojos'),str)
                or not request_document['issuanceBackingMojos'].isdigit()
                or not 0<=int(request_document['issuanceBackingMojos'])<2**64):
            raise ValueError('Sols batch requires its exact primary, buyer and reserve review')
        if operation.kind=='INITIALIZE_GENERATION' and (request_document is None or len(operation.successors)!=6
                or len(operation.auxiliary_outputs)!=9 or not request_document.get('certificateHash')
                or not request_document.get('reviewId')):
            raise ValueError('genesis requires its complete source-bound final ceremony')
        if request_document is not None:
            document=canonical(request_document)
            if (len(document)>32768 or request_digest!='0x'+sha256(document.encode()).hexdigest()
                    or request_document.get('generationId')!=self.generation_id
                    or request_document.get('kind')!=operation.kind
                    or request_document.get('requestKey')!=request_key
                    or request_document.get('feeCapMojos')!=fee_cap):
                raise ValueError('saved review must match the exact prepared request')
        with self._db(write=True) as db:
            review=db.execute('SELECT request_digest,operation_id FROM generation_operation_reviews WHERE request_key=?',
                              (request_key,)).fetchone()
            if review and (review['request_digest']!=request_digest or review['operation_id']!=identity):
                raise ValueError('retry changes the reviewed request')
            prior = db.execute('SELECT * FROM generation_operations WHERE request_key=? OR original_id=?',
                               (request_key, bundle_id(protocol))).fetchall()
            if prior:
                if any(p['operation_id'] != identity or p['protocol_bundle'] != raw or p['fee_cap'] != fee_cap for p in prior):
                    raise ValueError('retry changes the saved operation; review a new action explicitly')
                identity=prior[0]['operation_id']
            else:
                # Reserve bounded space for eventual fee attachment before
                # preparation. A full journal must not strand a funded action.
                retained=db.execute('SELECT coalesce(sum(length(protocol_bundle)+coalesce(length(CAST(funded_document AS BLOB)),?)+33792),0) FROM generation_operations',
                    (MAX_FUNDED_DOCUMENT_BYTES,)).fetchone()[0]
                retained+=db.execute('SELECT count(*)*512 FROM generation_operation_reviews').fetchone()[0]
                admit_retained_bytes(db,retained,len(raw)+MAX_FUNDED_DOCUMENT_BYTES+33792,self.MAX_RETAINED_BYTES)
                db.execute('INSERT INTO generation_operations VALUES (?,?,?,?,?,?,?,\'PREPARED\',?,?,NULL,NULL,NULL,NULL,NULL)',
                    (identity, request_key, intent, operation.kind, raw, bundle_id(protocol), fee_cap, now, now))
            if request_digest is not None:
                if review is None:
                    count=db.execute('SELECT count(*) FROM generation_operation_reviews').fetchone()[0]
                    if count>=self.MAX_REVIEW_ALIASES:raise GenerationRetentionFull('operation review alias retention needs archive review')
                    retained=db.execute('SELECT coalesce(sum(length(protocol_bundle)+coalesce(length(CAST(funded_document AS BLOB)),?)+33792),0) FROM generation_operations',
                        (MAX_FUNDED_DOCUMENT_BYTES,)).fetchone()[0]+count*512
                    admit_retained_bytes(db,retained,512,self.MAX_RETAINED_BYTES)
                db.execute('INSERT OR IGNORE INTO generation_operation_reviews VALUES (?,?,?)',
                           (request_key,request_digest,identity))
            if document is not None:
                prior_document=db.execute('SELECT document FROM generation_review_documents WHERE operation_id=?',(identity,)).fetchone()
                if prior_document and prior_document['document']!=document:
                    # Different request keys can identify one identical native
                    # action. Keep the first immutable human-readable review.
                    old=json.loads(prior_document['document']);new=json.loads(document)
                    old.pop('requestKey',None);new.pop('requestKey',None)
                    if old!=new:raise ValueError('saved operation review cannot be replaced')
                db.execute('INSERT OR IGNORE INTO generation_review_documents VALUES (?,?,?)',(identity,request_digest,document))
        return identity

    def protocol_bundle(self, identity):
        with self._db() as db: row = self._row(db, identity)
        raw = row['protocol_bundle']
        bundle = SpendBundle.from_bytes(raw)
        if bytes(bundle) != raw or bundle_id(bundle) != row['original_id']:
            raise ValueError('saved protocol bundle differs from its transaction identity')
        return bundle

    def save_funded(self, identity, prepared: PreparedProtocolBundle, now: int):
        # Called by the existing submitter AFTER its durable fee reservation and
        # BEFORE network I/O. An exact retry cannot change fee inputs or bytes.
        final = prepared.bundle
        if len(bytes(final)) > MAX_BUNDLE_BYTES: raise ValueError('funded operation exceeds its storage bound')
        encoded = canonical(prepared.to_json())
        if len(encoded.encode())>MAX_FUNDED_DOCUMENT_BYTES:raise ValueError('funded document exceeds its reserved storage bound')
        with self._db(write=True) as db:
            row = self._row(db, identity)
            original = SpendBundle.from_bytes(row['protocol_bundle'])
            final_spends = {s.coin.name(): bytes(s) for s in final.coin_spends}
            review = json.loads(db.execute('SELECT document FROM generation_review_documents WHERE operation_id=?', (identity,)).fetchone()[0]) if row['kind']=='PRIMARY_SOLS_BATCH' else {}
            expected_backing = int(review.get('issuanceBackingMojos',0))
            if (len(final_spends) != len(final.coin_spends) or prepared.backing_mojos != expected_backing
                    or not 0 <= prepared.fee_mojos <= row['fee_cap']
                    or any(final_spends.get(s.coin.name()) != bytes(s) for s in original.coin_spends)):
                raise ValueError('fee attachment changes a reviewed protocol spend or exceeds its limit')
            if row['funded_document'] is not None:
                if row['funded_document'] != encoded: raise ValueError('saved funded transaction cannot be replaced')
                return
            if row['stage'] != 'PREPARED': raise ValueError('operation cannot acquire another transaction')
            db.execute('UPDATE generation_operations SET funded_document=?,transaction_id=?,stage=\'DISPATCHING\','
                       'updated_at=?,error_code=NULL WHERE operation_id=?', (encoded, prepared.spend_bundle_id, now, identity))

    def fail(self, identity, code, now):
        if code not in ERRORS: raise ValueError('unknown operation recovery code')
        with self._db(write=True) as db:
            row = self._row(db, identity)
            if row['stage'] in ('CONFIRMED','EXPIRED_RECONCILED'): return
            # With saved bytes, even a timeout before the caller received a
            # response means reconciliation, never a fresh operation.
            stage = 'RECONCILING' if row['transaction_id'] else 'PREPARED'
            db.execute('UPDATE generation_operations SET stage=?,error_code=?,updated_at=? WHERE operation_id=?',
                       (stage, code, max(now, row['updated_at']), identity))

    def observed(self, identity, *, transaction_id, status, now, confirmed_height=None):
        if status not in ('MEMPOOL', 'CONFIRMED'): raise ValueError('observation is not a confirmed submission state')
        if status == 'CONFIRMED' and (type(confirmed_height) is not int or confirmed_height <= 0):
            raise ValueError('confirmation requires exact primary-node chain evidence')
        with self._db(write=True) as db:
            row = self._row(db, identity)
            if not row['funded_document'] or row['transaction_id'] != transaction_id:
                raise ValueError('observation belongs to another transaction')
            if row['stage'] == 'CONFIRMED':
                if status == 'CONFIRMED' and row['confirmed_height'] != confirmed_height:
                    raise ValueError('confirmed transaction history changed; reconcile chain evidence')
                return  # Delayed mempool responses cannot undo confirmed progress.
            if row['stage'] == 'EXPIRED_RECONCILED':
                raise ValueError('expired operation cannot acquire later submission evidence')
            db.execute('UPDATE generation_operations SET stage=?,confirmed_height=?,last_checked_at=?,updated_at=?,error_code=NULL '
                       'WHERE operation_id=?', ('CONFIRMED' if status == 'CONFIRMED' else 'SUBMITTED', confirmed_height,
                       now, max(now, row['updated_at']), identity))

    def saved_funding(self, identity):
        with self._db() as db: row = self._row(db, identity)
        if not row['funded_document']: return None
        document = json.loads(row['funded_document'])
        bundle = SpendBundle.from_json_dict(document['spendBundle'])
        if document['spendBundleId'] != row['transaction_id'] or bundle_id(bundle) != row['transaction_id']:
            raise ValueError('saved funded transaction differs from its identity')
        return document

    def status(self, identity):
        # This read never imports a builder, contacts a node or modifies a row.
        with self._db() as db:
            row = self._row(db, identity)
            review=db.execute('SELECT request_digest,document FROM generation_review_documents WHERE operation_id=?',(identity,)).fetchone()
        if review and '0x'+sha256(review['document'].encode()).hexdigest()!=review['request_digest']:
            raise ValueError('saved operation review differs from its original commitment')
        action = ('REVIEW_NEW_MATCH' if row['stage'] == 'EXPIRED_RECONCILED' else 'COMPLETE' if row['stage'] == 'CONFIRMED' else
                  'CHECK_SAVED_TRANSACTION' if row['transaction_id'] else 'REVIEW_OPERATION')
        return {'generationId': self.generation_id, 'network': 'testnet11', 'operationId': identity,
            'kind': row['kind'], 'intentHash': row['intent_hash'], 'stage': row['stage'],
            'transactionId': row['transaction_id'], 'feeCapMojos': str(row['fee_cap']),
            'createdAt': row['created_at'], 'updatedAt': row['updated_at'], 'lastCheckedAt': row['last_checked_at'],
            'errorCode': row['error_code'], 'confirmedHeight': row['confirmed_height'], 'nextAction': action,
            'review':json.loads(review['document']) if review else None,
            'pollAfterSeconds': 30 if row['stage'] in ('CONFIRMED', 'PREPARED','EXPIRED_RECONCILED') else 5}

    def expiry_proof(self, identity):
        with self._db() as db:
            row=db.execute('SELECT proof FROM generation_expiry_proofs WHERE operation_id=?',(identity,)).fetchone()
        return json.loads(row[0]) if row else None

    def record_batch_expiry(self, identity, proof, *, now):
        """Append primary-node proof. Never overwrite native bytes or reviews."""
        from .protocol_funding_store import valid_expired_input_evidence
        with self._db(write=True) as db:
            row=self._row(db,identity)
            review=json.loads(db.execute('SELECT document FROM generation_review_documents WHERE operation_id=?',(identity,)).fetchone()[0])
            bundle=SpendBundle.from_json_dict(json.loads(row['funded_document'])['spendBundle']) if row['funded_document'] else SpendBundle.from_bytes(row['protocol_bundle'])
            if (row['kind']!='PRIMARY_SOLS_BATCH' or row['stage']=='CONFIRMED'
                    or proof.get('bundleId')!=bundle_id(bundle)
                    or proof.get('inputIds')!=sorted('0x'+c.name().hex() for c in bundle.removals())
                    or type(proof.get('absoluteExpiry')) is not int or proof['absoluteExpiry']>review['expiresAt']
                    or type(proof.get('peakTimestamp')) is not int or proof['peakTimestamp']<review['expiresAt']
                    or (proof.get('allInputsUnspentAndClear') is not True and not valid_expired_input_evidence(bundle,proof))):
                raise ValueError('batch expiry proof does not match the exact saved operation')
            db.execute('INSERT OR IGNORE INTO generation_expiry_proofs VALUES (?,?)',(identity,canonical(proof)))
            db.execute("UPDATE generation_operations SET stage='EXPIRED_RECONCILED',error_code='CHAIN_WINDOW_EXPIRED',last_checked_at=?,updated_at=max(updated_at,?) WHERE operation_id=?",(now,now,identity))

    def batch_operations(self):
        with self._db() as db:
            ids=[row[0] for row in db.execute("SELECT operation_id FROM generation_operations WHERE kind='PRIMARY_SOLS_BATCH' ORDER BY created_at,operation_id")]
        return tuple(self.status(identity) for identity in ids)

    def recent(self, limit=20):
        if type(limit) is not int or not 1<=limit<=50:raise ValueError('operation read limit is out of bounds')
        with self._db() as db:
            ids=[row[0] for row in db.execute('SELECT operation_id FROM generation_operations ORDER BY created_at DESC,operation_id LIMIT ?', (limit,))]
        return [self.status(identity) for identity in ids]

    def pending_ids(self, limit=4):
        if type(limit) is not int or not 1<=limit<=4:raise ValueError('reconciliation batch is out of bounds')
        with self._db() as db:
            return [row[0] for row in db.execute('SELECT operation_id FROM generation_operations '
                "WHERE transaction_id IS NOT NULL AND stage NOT IN ('CONFIRMED','EXPIRED_RECONCILED') ORDER BY updated_at,operation_id LIMIT ?",(limit,))]


async def submit_saved_operation(journal, identity, submitter, *, clock, selection_purpose=None):
    """Explicit write only. Never called by status polling or automatic retry.

    The caller must authorize the exact operation and its fee cap first. The
    existing submitter performs native admission and retains its funded bytes.
    """
    status = journal.status(identity)
    if status['stage']=='EXPIRED_RECONCILED':
        raise ProtocolSubmissionError('The saved price window is proven expired. Review a new match using the retained offers.',code='CHAIN_WINDOW_EXPIRED')
    if selection_purpose is not None and (selection_purpose != 'genesis' or status['kind'] not in ('CREATE_RECIPIENT_VAULT','INITIALIZE_GENERATION')):
        raise ValueError('special funding purpose is restricted to the exact launch ceremony')
    if status['stage'] == 'CONFIRMED': return status
    if (submitter.funding_store is None or not submitter.policy.native_admission_enabled
            or submitter.faucet.network != 'testnet11' or not submitter.policy.enabled
            or submitter.policy.maximum_mojos > int(status['feeCapMojos'])
            or generation_path(submitter.funding_store.path, journal.generation_id) != submitter.funding_store.path):
        raise ValueError('generation dispatch requires durable native admission and the reviewed fee cap')
    expected_backing = int(status['review']['issuanceBackingMojos']) if status['kind']=='PRIMARY_SOLS_BATCH' else 0
    protocol = journal.protocol_bundle(identity)
    document = journal.saved_funding(identity)
    if document is not None:
        retained = submitter.funding_store.lookup('testnet11', bundle_id(protocol),
            {'feeTill': submitter.faucet.address_hex, 'purpose': selection_purpose, 'backingMojos': expected_backing})
        if retained is None or any(retained.get(k) != v for k, v in document.items()):
            raise ValueError('saved dispatch requires its original funding journal; no replacement can be built')
    async def save(prepared): journal.save_funded(identity, prepared, int(clock()))
    try:
        receipt = await submitter.submit(protocol.to_json_dict(), before_push=save, selection_purpose=selection_purpose, expected_backing_mojos=expected_backing)
    except ProtocolSubmissionError as exc:
        code = exc.code if exc.code in ERRORS else 'RECONCILIATION_REQUIRED' if exc.submission_attempted else 'NODE_UNAVAILABLE'
        journal.fail(identity, code, int(clock()))
        raise
    journal.observed(identity, transaction_id=receipt['spendBundleId'], status=receipt['status'],
        confirmed_height=receipt.get('confirmedHeight'), now=int(clock()))
    return journal.status(identity)


async def reconcile_saved_operation(journal, identity, provider, *, clock):
    """Explicit/background read of the EXACT saved transaction; cannot submit."""
    document = journal.saved_funding(identity)
    if document is None: return journal.status(identity)
    try:
        import asyncio
        async with asyncio.timeout(20):
            if (await provider.get_network_info_primary()).get('network_name') != 'testnet11':
                raise ValueError('operation reconciliation requires the primary Testnet11 node')
            receipt = await provider.observe_exact_protocol_bundle(document['spendBundle'])
        if receipt is None:
            journal.fail(identity, 'RECONCILIATION_REQUIRED', int(clock()))
        else:
            journal.observed(identity, transaction_id=document['spendBundleId'], status=receipt['status'],
                confirmed_height=receipt.get('confirmed_height'), now=int(clock()))
    except (ValueError, KeyError, OSError, RuntimeError, TimeoutError,TypeError):
        journal.fail(identity, 'RECONCILIATION_REQUIRED', int(clock()))
    return journal.status(identity)


class GenerationOperationReconciler:
    """Read-only node observer. It has no submitter, keys, builder or faucet."""
    def __init__(self,journal,provider,*,clock=time.time,recipient_observer=None,mint_observer=None,launch_observer=None):
        self.journal,self.provider,self.clock=journal,provider,clock
        self.recipient_observer=recipient_observer
        self.mint_observer=mint_observer
        self.launch_observer=launch_observer
        self._lock=asyncio.Lock()

    async def run_once(self):
        async with self._lock:
            identities=self.journal.pending_ids()
            async def observe(identity):
                try:
                    await reconcile_saved_operation(self.journal,identity,self.provider,clock=self.clock)
                except Exception as exc:
                    logger.error('generation operation observation failed (%s)',type(exc).__name__)
                    self.journal.fail(identity,'RECONCILIATION_REQUIRED',int(self.clock()))
            results=await asyncio.gather(*(observe(identity) for identity in identities),return_exceptions=True)
            for result in results:
                if isinstance(result,asyncio.CancelledError):raise result
                if isinstance(result,Exception):
                    logger.error('generation operation journal unavailable (%s)',type(result).__name__)
            recipient_active = await self.recipient_observer.run_once() if self.recipient_observer is not None else False
            mint_active = await self.mint_observer.run_once() if self.mint_observer is not None else False
            launch_active = await self.launch_observer.run_once() if self.launch_observer is not None else False
            return bool(identities) or recipient_active or mint_active or launch_active

    async def run(self):
        while True:
            active=True
            try:active=await self.run_once()
            except Exception as exc:logger.error('generation operation reconciler unavailable (%s)',type(exc).__name__)
            await asyncio.sleep(5 if active else 30)
