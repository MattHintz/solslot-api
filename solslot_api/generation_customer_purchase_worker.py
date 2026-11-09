"""Finite delivery continuation, distinct from the read-only chain observer.

Only prepared reservations and verified saved payer offers are eligible. This
worker cannot create quotes, select a deed or ask the buyer to sign. A reviewed
issuer transport must be installed separately; there is no default key loader.
SQLite leases, bounded attempts and exact bundle journals survive restarts.
"""
import asyncio
import json
import re
import secrets
import time

from chia_rs import AugSchemeMPL, G2Element
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json
from .generation_customer_purchase_execution import CurrentNativePurchaseExecution, h
from .generation_customer_purchase_expiry_proof import valid_expiry_proof as _valid_expiry_proof
from .generation_operations import canonical
from .generation_customer_purchase_batch import artifacts,CurrentReservationBatch
from .generation_operations import bundle_id
from .generation_storage import generation_path

MAX_WORKER_DOCUMENT_BYTES=4096
MAX_WORKER_RETAINED_BYTES=128*2*MAX_WORKER_DOCUMENT_BYTES


def _worker_document_capacity(db,document):
    size=len(document.encode())
    retained=db.execute('''SELECT coalesce(sum(
        coalesce(length(CAST(issuer_document AS BLOB)),0)+
        coalesce(length(CAST(expiry_document AS BLOB)),0)),0) FROM current_purchase_worker_jobs''').fetchone()[0]
    if size>MAX_WORKER_DOCUMENT_BYTES or retained+size>MAX_WORKER_RETAINED_BYTES:
        raise ValueError('CURRENT_PURCHASE_WORKER_RETENTION_FULL')


def _reservation_unfunded(service,identity,binding):
    """Prove both journals contain no funded transaction; never infer from UI state."""
    saved=service._saved(identity,binding)
    if (saved['deliveryClaim'] is not None or service._existing(identity,'DELIVERY',binding) is not None
            or service._existing(identity,'RELEASE',binding) is not None
            or saved.get('retainedSignatures',{}).get('delivery')):
        return False
    with service.store._connect()as db:
        job=db.execute('SELECT issuer_document FROM current_purchase_worker_jobs WHERE intent_id=?',(identity,)).fetchone()
    if job is not None and job['issuer_document']is not None:return False
    status=service.store.execution_status(identity,'RESERVATION',browser_hash=binding)
    if status['stage']!='PREPARED' or status['transactionId'] is not None:
        return False
    if service.store.execution_funding(identity,'RESERVATION',browser_hash=binding) is not None:
        return False
    submitter=service.submitter
    if (submitter is None or submitter.funding_store is None or submitter.faucet.network!='testnet11'
            or generation_path(submitter.funding_store.path,service.store.generation_id)!=submitter.funding_store.path):
        return False
    original=service.store.execution_bundle(identity,'RESERVATION',browser_hash=binding)
    context={'feeTill':submitter.faucet.address_hex,'purpose':None,'backingMojos':0}
    return submitter.funding_store.lookup('testnet11',bundle_id(original),context) is None


def _expiry_binding(service,identity,binding):
    saved=service._saved(identity,binding);claim=saved['reservationClaim']
    selected=(artifacts(claim)[0]if isinstance(claim,CurrentReservationBatch)
        else purchase_artifact_v3_from_json(claim.purchase_artifact))
    original=service.store.execution_bundle(identity,'RESERVATION',browser_hash=binding)
    return {'schema':'solslot.current-unsubmitted-reservation-expiry.v1',
        'generationId':service.store.generation_id,'intentId':identity,'reservationClaimHash':claim.digest(),
        'bundleId':bundle_id(original),'absoluteExpiry':selected.quote_expires_at,
        'inputIds':sorted(h(coin.name())for coin in original.removals())}


def expired_unsubmitted_reservation(service,identity,binding):
    """Read-only terminal proof for a saved expired reservation, failing closed.

    CLOSED and an ended lease establish no worker action remains in flight.
    The exact original funding journal is checked again, including the gap
    between its durable reservation and the checkout checkpoint callback.
    Saved offers and all original journals remain unchanged.
    """
    try:
        expected=_expiry_binding(service,identity,binding)
        if int(service.clock())<expected['absoluteExpiry']:
            return False
        with service.store._connect()as db:
            job=db.execute('SELECT state,lease_token,lease_until,expiry_document FROM current_purchase_worker_jobs WHERE intent_id=?',
                (identity,)).fetchone()
        if job is None or job['state']!='CLOSED' or job['lease_token'] is not None or job['lease_until']!=0:
            return False
        return (job['expiry_document']is not None and len(job['expiry_document'].encode())<=MAX_WORKER_DOCUMENT_BYTES
            and _valid_expiry_proof(json.loads(job['expiry_document']),expected)
            and _reservation_unfunded(service,identity,binding))
    except Exception:
        # Unavailable/corrupt journals never prove absence of a transaction.
        return False


def issuer_pairs(pair):
    return pair if isinstance(pair[0],tuple)else (pair,)


def issuer_message(pair):
    pairs=issuer_pairs(pair)
    if len({bytes(p[0])for p in pairs})!=1:raise ValueError('CURRENT_EXECUTION_ISSUER_KEY_CHANGED')
    return h(pairs[0][0]),h(pairs[0][1])if len(pairs)==1 else [h(p[1])for p in pairs]


def issuer_valid(signature,pair):
    pairs=issuer_pairs(pair)
    return isinstance(signature,G2Element)and AugSchemeMPL.aggregate_verify([p[0]for p in pairs],[p[1]for p in pairs],signature)


class CurrentPurchaseWorker:
    ACTION_TIMEOUT_SECONDS=90
    LEASE_SECONDS_PER_ACTION=95
    def __init__(self,service,*,issuer_sign,batch_size=2,interval=10,clock=time.time):
        if (not isinstance(service,CurrentNativePurchaseExecution) or not callable(issuer_sign)
                or service.settings.network!='testnet11' or type(batch_size)is not int or not 1<=batch_size<=4
                or type(interval)is not int or not 5<=interval<=60):
            raise ValueError('CURRENT_PURCHASE_FINITE_WORKER_REQUIRED')
        self.service=service;self.store=service.store;self.issuer_sign=issuer_sign
        self.batch_size=batch_size;self.interval=interval;self.clock=clock;self.running=False
        self._action_stage='CONTINUATION'
        with self.store._connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS current_purchase_worker_jobs (
                intent_id TEXT PRIMARY KEY, lease_token TEXT, lease_until INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'WAITING', issuer_document TEXT, error_code TEXT, expiry_document TEXT);
                CREATE TABLE IF NOT EXISTS current_purchase_worker_health (
                generation_id TEXT PRIMARY KEY, document TEXT NOT NULL);''')
            if 'expiry_document'not in {row[1]for row in db.execute('PRAGMA table_info(current_purchase_worker_jobs)')}:
                db.execute('ALTER TABLE current_purchase_worker_jobs ADD COLUMN expiry_document TEXT')

    def health(self):
        with self.store._connect() as db:
            row=db.execute('SELECT document FROM current_purchase_worker_health WHERE generation_id=?',
                (self.store.generation_id,)).fetchone()
        if row is None:return None
        value=json.loads(row[0])
        if (value.get('schema')!='solslot.current-purchase-worker-health.v1'
                or value.get('generationId')!=self.store.generation_id
                or type(value.get('checkedAt'))is not int or type(value.get('cycles'))is not int):
            raise ValueError('CURRENT_PURCHASE_WORKER_HEALTH_CHANGED')
        if int(self.clock())-value['checkedAt']>self.batch_size*self.LEASE_SECONDS_PER_ACTION+2*self.interval:
            return {**value,'status':'STALE'}
        return value

    def _claim(self):
        now=int(self.clock());selected=[]
        with self.store._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            rows=db.execute('''SELECT r.intent_id,r.browser_hash,e.stage AS reservation_stage FROM current_customer_purchase_reviews r
                LEFT JOIN current_purchase_executions e ON e.intent_id=r.intent_id AND e.phase='RESERVATION'
                LEFT JOIN current_customer_reservation_requests q ON q.intent_id=r.intent_id
                LEFT JOIN current_customer_purchase_delivery d ON d.intent_id=r.intent_id
                LEFT JOIN current_purchase_executions f ON f.intent_id=r.intent_id AND f.phase='DELIVERY'
                WHERE r.generation_id=?
                AND (e.intent_id IS NOT NULL OR q.intent_id IS NOT NULL)
                AND (f.stage IS NULL OR f.stage!='CONFIRMED') ORDER BY r.created_at,r.intent_id LIMIT 129''',
                (self.store.generation_id,)).fetchall()
            if len(rows)>128:raise ValueError('CURRENT_PURCHASE_WORKER_CAPACITY_EXCEEDED')
            for row in rows:
                self.store._row(db,row['intent_id'],row['browser_hash'])
                db.execute('INSERT OR IGNORE INTO current_purchase_worker_jobs(intent_id) VALUES(?)',(row['intent_id'],))
                job=db.execute('SELECT * FROM current_purchase_worker_jobs WHERE intent_id=?',(row['intent_id'],)).fetchone()
                if job['state'] in ('COMPLETE','RELEASED','REVIEW_REQUIRED') or job['lease_until']>now or job['next_attempt']>now:continue
                if job['state']=='CLOSED'and(job['expiry_document']is not None or row['reservation_stage']!='PREPARED'):continue
                if job['attempts']>=64:
                    db.execute("UPDATE current_purchase_worker_jobs SET state='REVIEW_REQUIRED' WHERE intent_id=?",(row['intent_id'],));continue
                token=secrets.token_hex(16)
                db.execute('UPDATE current_purchase_worker_jobs SET lease_token=?,lease_until=?,attempts=attempts+1 WHERE intent_id=?',
                    (token,now+self.LEASE_SECONDS_PER_ACTION*self.batch_size+5,row['intent_id']))
                selected.append((row['intent_id'],row['browser_hash'],token))
                if len(selected)==self.batch_size:break
            db.commit()
        return selected

    def _save_issuer(self,identity,token,claim,signature,pair):
        if not issuer_valid(signature,pair):
            raise ValueError('CURRENT_EXECUTION_ISSUER_SIGNATURE_INVALID')
        public,message=issuer_message(pair)
        document=canonical({'claimHash':claim.digest(),'publicKey':public,'message':message,'signature':h(signature)})
        with self.store._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            job=db.execute('SELECT * FROM current_purchase_worker_jobs WHERE intent_id=?',(identity,)).fetchone()
            if job is None or job['lease_token']!=token or job['lease_until']<=int(self.clock()):
                raise ValueError('CURRENT_PURCHASE_WORKER_LEASE_ENDED')
            if job['issuer_document'] is not None and job['issuer_document']!=document:
                raise ValueError('CURRENT_PURCHASE_WORKER_ISSUER_CHANGED')
            if job['issuer_document'] is None:
                _worker_document_capacity(db,document)
                self.store._execution_capacity(db,len(document.encode())+512)
                db.execute('UPDATE current_purchase_worker_jobs SET issuer_document=? WHERE intent_id=?',(document,identity))
            db.commit()

    def _retained_issuer(self,identity,claim,pair):
        with self.store._connect() as db:
            row=db.execute('SELECT issuer_document FROM current_purchase_worker_jobs WHERE intent_id=?',(identity,)).fetchone()
        if row is None or row[0] is None:return None
        document=json.loads(row[0]);signature=G2Element.from_bytes(bytes.fromhex(document['signature'][2:]))
        public,message=issuer_message(pair)
        if (document.get('claimHash')!=claim.digest() or document.get('publicKey')!=public
                or document.get('message')!=message or not issuer_valid(signature,pair)):
            raise ValueError('CURRENT_PURCHASE_WORKER_SAVED_ISSUER_CHANGED')
        return signature

    async def _prove_unsubmitted_expiry(self,identity,binding,token):
        s=self.service;submitter=s.submitter
        guard=getattr(submitter,'funding_guard',None)
        if submitter is None or guard is None or not callable(getattr(submitter,'prove_expired_bundle',None)):
            return False
        # A submit that started before expiry must finish its funding checkpoint
        # before absence can be proved. This lock is the existing funding lock.
        async with guard:
            if not _reservation_unfunded(s,identity,binding):return False
            expected=_expiry_binding(s,identity,binding)
            with self.store._connect()as db:
                retained=db.execute('SELECT expiry_document FROM current_purchase_worker_jobs WHERE intent_id=?',
                    (identity,)).fetchone()
            if retained is not None and retained['expiry_document']is not None:
                if (len(retained['expiry_document'].encode())>MAX_WORKER_DOCUMENT_BYTES
                        or not _valid_expiry_proof(json.loads(retained['expiry_document']),expected)):
                    raise ValueError('CURRENT_PURCHASE_SAVED_EXPIRY_PROOF_CHANGED')
                # A crash after the proof commit must recover those exact
                # bytes, rather than replace its historical primary peak.
                return True
            original=s.store.execution_bundle(identity,'RESERVATION',browser_hash=binding)
            self._action_stage='RESERVATION_EXPIRY_PROOF'
            proof=await submitter.prove_expired_bundle(original)
            proof={**proof,**{k:v for k,v in expected.items()if k in ('schema','generationId','intentId','reservationClaimHash')}}
            if (not _valid_expiry_proof(proof,expected)or _expiry_binding(s,identity,binding)!=expected
                    or not _reservation_unfunded(s,identity,binding)):
                raise ValueError('CURRENT_PURCHASE_EXPIRY_PROOF_CHANGED')
            document=canonical(proof)
            with self.store._connect()as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT lease_token,lease_until,expiry_document FROM current_purchase_worker_jobs WHERE intent_id=?',
                    (identity,)).fetchone()
                if row is None or row['lease_token']!=token or row['lease_until']<=int(self.clock()):
                    raise ValueError('CURRENT_PURCHASE_WORKER_LEASE_ENDED')
                if row['expiry_document']is not None and row['expiry_document']!=document:
                    raise ValueError('CURRENT_PURCHASE_EXPIRY_PROOF_ALREADY_BOUND')
                if row['expiry_document']is None:
                    _worker_document_capacity(db,document)
                    self.store._execution_capacity(db,len(document.encode())+512)
                    db.execute('UPDATE current_purchase_worker_jobs SET expiry_document=? WHERE intent_id=?',
                        (document,identity))
                db.commit()
            return True

    async def _advance(self,identity,binding,token):
        s=self.service;saved=s._saved(identity,binding)
        claim=saved['reservationClaim']
        artifact=(artifacts(claim)[0]if isinstance(claim,CurrentReservationBatch)
            else purchase_artifact_v3_from_json(claim.purchase_artifact))
        with self.store._connect()as db:
            job=db.execute('SELECT state FROM current_purchase_worker_jobs WHERE intent_id=?',(identity,)).fetchone()
        if job is not None and job['state']=='CLOSED':
            # A legacy CLOSED audit can only observe and prove native expiry.
            # It can never reopen financial continuation, even if clocks or
            # newly discovered funding contradict the historical state.
            self._action_stage='RESERVATION_RECONCILIATION'
            await s.reconcile(identity,'RESERVATION',browser_hash=binding)
            if int(self.clock())<artifact.quote_expires_at:return 'REVIEW_REQUIRED'
            return 'CLOSED' if await self._prove_unsubmitted_expiry(identity,binding,token) else 'REVIEW_REQUIRED'
        if s._existing(identity,'RESERVATION',binding)is None:
            if int(self.clock())>=min(artifact.quote_expires_at,s.policy.expires_at):return 'CLOSED'
            s._funding_context()
            self._action_stage='RESERVATION_PREPARATION'
            await s.prepare_reservation(identity,browser_hash=binding)
            # Preparation/quorum and funded dispatch each get their own finite
            # cycle. The next cycle revalidates the exact durable checkpoint.
            return 'WAITING'
        # Reconciliation always precedes a new signature or dispatch, including
        # after expiry. Uncertain broadcasts use the original saved funding.
        self._action_stage='RESERVATION_RECONCILIATION'
        status=await s.reconcile(identity,'RESERVATION',browser_hash=binding)
        if status['stage']!='CONFIRMED':
            if int(self.clock())>=min(artifact.quote_expires_at,s.policy.expires_at):
                return 'CLOSED' if await self._prove_unsubmitted_expiry(identity,binding,token) else 'REVIEW_REQUIRED'
            if status['stage']!='MEMPOOL':
                self._action_stage='RESERVATION_DISPATCH'
                await s.dispatch(identity,'RESERVATION',browser_hash=binding)
            return 'WAITING'
        claim=saved['deliveryClaim']
        current=s._existing(identity,'DELIVERY',binding)
        if current is not None:
            self._action_stage='DELIVERY_RECONCILIATION'
            current=await s.reconcile(identity,'DELIVERY',browser_hash=binding)
            if current['stage']=='CONFIRMED':return 'COMPLETE'
        if int(self.clock())>=s.policy.expires_at:return 'REVIEW_REQUIRED'
        if int(self.clock())>=artifact.quote_expires_at:
            release=s._existing(identity,'RELEASE',binding)
            if release is not None:
                self._action_stage='RELEASE_RECONCILIATION'
                release=await s.reconcile(identity,'RELEASE',browser_hash=binding)
                if release['stage']=='CONFIRMED':return 'RELEASED'
                if release['stage']=='MEMPOOL':return 'WAITING'
            s._funding_context()
            self._action_stage='RELEASE_PREPARATION'
            await s.prepare_timeout(identity,browser_hash=binding)
            self._action_stage='RELEASE_DISPATCH'
            await s.dispatch(identity,'RELEASE',browser_hash=binding)
            return 'WAITING'
        if claim is None or current is not None and current['stage']=='MEMPOOL':return 'WAITING'
        s._funding_context()
        if current is None:
            self._action_stage='DELIVERY_PREPARATION'
            checked,signed,companion,pair=await s.delivery_issuer_review(identity,claim,browser_hash=binding)
            signature=self._retained_issuer(identity,claim,pair)
            if signature is None:
                # The transport receives only exact public evidence. The
                # independently configured issuer reconstructs this itself.
                self._action_stage='DELIVERY_ISSUER'
                signature=await self.issuer_sign({'generationId':self.store.generation_id,
                    'policyHash':s.policy.commitment,'claim':claim.model_dump(mode='json',by_alias=True),
                    'claimHash':claim.digest(),'purchaseBundle':signed.to_json_dict(),
                    'issuerCoinSpend':([spend.to_json_dict()for spend in companion.issuer_signature_spends]
                        if hasattr(companion,'issuer_signature_spends')else companion.issuer_signature_spend.to_json_dict()),
                    'issuerPublicKey':issuer_message(pair)[0],'message':issuer_message(pair)[1]})
                self._save_issuer(identity,token,claim,signature,pair)
            if isinstance(saved['reservationClaim'],CurrentReservationBatch):
                from .generation_customer_purchase_batch_execution import save_reviewed_delivery
                await save_reviewed_delivery(s,identity,claim,signature,binding,checked,signed,companion,pair)
                # A separate durable cycle funds and dispatches this exact
                # checkpoint. Do not repeat the slow private quorum review.
                return 'WAITING'
            await s.prepare_delivery(identity,claim,signature,browser_hash=binding)
        self._action_stage='DELIVERY_DISPATCH'
        await s.dispatch(identity,'DELIVERY',browser_hash=binding)
        return 'WAITING'

    async def tick(self):
        if self.running:raise ValueError('CURRENT_PURCHASE_WORKER_ALREADY_RUNNING')
        self.running=True
        try:
            old=self.health();rows=self._claim();errors=0;complete=0
            for identity,binding,token in rows:
                error=None;self._action_stage='CONTINUATION'
                try:
                    # Finite native batch reconstruction can exceed the scalar
                    # path; the durable lease covers this explicit upper bound.
                    async with asyncio.timeout(self.ACTION_TIMEOUT_SECONDS):state=await self._advance(identity,binding,token)
                    complete+=state=='COMPLETE'
                except asyncio.CancelledError:raise
                except TimeoutError:
                    errors+=1;state='RETRY'
                    error='CURRENT_PURCHASE_'+self._action_stage+'_TIMED_OUT'
                except Exception as exc:
                    errors+=1;state='RETRY';code=str(exc)
                    error=code if re.fullmatch(r'CURRENT_[A-Z_]{1,100}',code)else'CURRENT_PURCHASE_CONTINUATION_UNAVAILABLE'
                with self.store._connect() as db:
                    job=db.execute('SELECT attempts FROM current_purchase_worker_jobs WHERE intent_id=? AND lease_token=?',(identity,token)).fetchone()
                    if job:
                        delay=min(60,self.interval*2**min(job['attempts']-1,3))if error else self.interval
                        db.execute('''UPDATE current_purchase_worker_jobs SET state=?,
                            error_code=CASE WHEN ? IS NULL AND ? IN ('CLOSED','REVIEW_REQUIRED') THEN error_code ELSE ? END,next_attempt=?,
                            lease_token=NULL,lease_until=0 WHERE intent_id=? AND lease_token=?''',
                            (state,error,state,error,int(self.clock())+delay,identity,token))
            with self.store._connect()as db:
                review_required=db.execute("SELECT count(*) FROM current_purchase_worker_jobs WHERE state='REVIEW_REQUIRED'").fetchone()[0]
            value={'schema':'solslot.current-purchase-worker-health.v1','generationId':self.store.generation_id,
                'checkedAt':int(self.clock()),'cycles':(old['cycles']if old else 0)+1,
                'examined':len(rows),'completed':complete,'errors':errors,'nextCheckAt':int(self.clock())+self.interval,
                'reviewRequiredCount':review_required,'status':'DEGRADED'if errors or review_required else'HEALTHY'}
            with self.store._connect() as db:
                db.execute('INSERT INTO current_purchase_worker_health VALUES(?,?) ON CONFLICT(generation_id) DO UPDATE SET document=excluded.document',
                    (self.store.generation_id,canonical(value)))
            return value
        finally:self.running=False

    async def run(self,stop):
        while not stop.is_set():
            try:await self.tick()
            except asyncio.CancelledError:raise
            except Exception:pass  # Old health expires; never reset evidence.
            try:await asyncio.wait_for(stop.wait(),timeout=self.interval)
            except TimeoutError:pass
