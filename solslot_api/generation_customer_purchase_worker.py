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
from .generation_operations import canonical


class CurrentPurchaseWorker:
    def __init__(self,service,*,issuer_sign,batch_size=2,interval=10,clock=time.time):
        if (not isinstance(service,CurrentNativePurchaseExecution) or not callable(issuer_sign)
                or service.settings.network!='testnet11' or type(batch_size)is not int or not 1<=batch_size<=4
                or type(interval)is not int or not 5<=interval<=60):
            raise ValueError('CURRENT_PURCHASE_FINITE_WORKER_REQUIRED')
        self.service=service;self.store=service.store;self.issuer_sign=issuer_sign
        self.batch_size=batch_size;self.interval=interval;self.clock=clock;self.running=False
        with self.store._connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS current_purchase_worker_jobs (
                intent_id TEXT PRIMARY KEY, lease_token TEXT, lease_until INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'WAITING', issuer_document TEXT, error_code TEXT);
                CREATE TABLE IF NOT EXISTS current_purchase_worker_health (
                generation_id TEXT PRIMARY KEY, document TEXT NOT NULL);''')

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
        if int(self.clock())-value['checkedAt']>self.batch_size*50+2*self.interval:
            return {**value,'status':'STALE'}
        return value

    def _claim(self):
        now=int(self.clock());selected=[]
        with self.store._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            rows=db.execute('''SELECT r.intent_id,r.browser_hash FROM current_customer_purchase_reviews r
                JOIN current_purchase_executions e ON e.intent_id=r.intent_id AND e.phase='RESERVATION'
                LEFT JOIN current_customer_purchase_delivery d ON d.intent_id=r.intent_id
                LEFT JOIN current_purchase_executions f ON f.intent_id=r.intent_id AND f.phase='DELIVERY'
                WHERE r.generation_id=?
                AND (f.stage IS NULL OR f.stage!='CONFIRMED') ORDER BY r.created_at,r.intent_id LIMIT 129''',
                (self.store.generation_id,)).fetchall()
            if len(rows)>128:raise ValueError('CURRENT_PURCHASE_WORKER_CAPACITY_EXCEEDED')
            for row in rows:
                self.store._row(db,row['intent_id'],row['browser_hash'])
                db.execute('INSERT OR IGNORE INTO current_purchase_worker_jobs(intent_id) VALUES(?)',(row['intent_id'],))
                job=db.execute('SELECT * FROM current_purchase_worker_jobs WHERE intent_id=?',(row['intent_id'],)).fetchone()
                if job['state'] in ('COMPLETE','RELEASED','CLOSED','REVIEW_REQUIRED') or job['lease_until']>now or job['next_attempt']>now:continue
                if job['attempts']>=64:
                    db.execute("UPDATE current_purchase_worker_jobs SET state='REVIEW_REQUIRED' WHERE intent_id=?",(row['intent_id'],));continue
                token=secrets.token_hex(16)
                db.execute('UPDATE current_purchase_worker_jobs SET lease_token=?,lease_until=?,attempts=attempts+1 WHERE intent_id=?',
                    (token,now+50*self.batch_size+5,row['intent_id']))
                selected.append((row['intent_id'],row['browser_hash'],token))
                if len(selected)==self.batch_size:break
            db.commit()
        return selected

    def _save_issuer(self,identity,token,claim,signature,pair):
        if not isinstance(signature,G2Element) or not AugSchemeMPL.verify(pair[0],pair[1],signature):
            raise ValueError('CURRENT_EXECUTION_ISSUER_SIGNATURE_INVALID')
        document=canonical({'claimHash':claim.digest(),'publicKey':h(pair[0]),'message':h(pair[1]),'signature':h(signature)})
        with self.store._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            job=db.execute('SELECT * FROM current_purchase_worker_jobs WHERE intent_id=?',(identity,)).fetchone()
            if job is None or job['lease_token']!=token or job['lease_until']<=int(self.clock()):
                raise ValueError('CURRENT_PURCHASE_WORKER_LEASE_ENDED')
            if job['issuer_document'] is not None and job['issuer_document']!=document:
                raise ValueError('CURRENT_PURCHASE_WORKER_ISSUER_CHANGED')
            if job['issuer_document'] is None:
                self.store._execution_capacity(db,len(document.encode())+512)
                db.execute('UPDATE current_purchase_worker_jobs SET issuer_document=? WHERE intent_id=?',(document,identity))
            db.commit()

    def _retained_issuer(self,identity,claim,pair):
        with self.store._connect() as db:
            row=db.execute('SELECT issuer_document FROM current_purchase_worker_jobs WHERE intent_id=?',(identity,)).fetchone()
        if row is None or row[0] is None:return None
        document=json.loads(row[0]);signature=G2Element.from_bytes(bytes.fromhex(document['signature'][2:]))
        if (document.get('claimHash')!=claim.digest() or document.get('publicKey')!=h(pair[0])
                or document.get('message')!=h(pair[1]) or not AugSchemeMPL.verify(pair[0],pair[1],signature)):
            raise ValueError('CURRENT_PURCHASE_WORKER_SAVED_ISSUER_CHANGED')
        return signature

    async def _advance(self,identity,binding,token):
        s=self.service;saved=s._saved(identity,binding)
        artifact=purchase_artifact_v3_from_json(saved['reservationClaim'].purchase_artifact)
        # Reconciliation always precedes a new signature or dispatch, including
        # after expiry. Uncertain broadcasts use the original saved funding.
        status=await s.reconcile(identity,'RESERVATION',browser_hash=binding)
        if status['stage']!='CONFIRMED':
            if int(self.clock())>=min(artifact.quote_expires_at,s.policy.expires_at):return 'CLOSED'
            if status['stage']!='MEMPOOL':await s.dispatch(identity,'RESERVATION',browser_hash=binding)
            return 'WAITING'
        claim=saved['deliveryClaim']
        current=s._existing(identity,'DELIVERY',binding)
        if current is not None:
            current=await s.reconcile(identity,'DELIVERY',browser_hash=binding)
            if current['stage']=='CONFIRMED':return 'COMPLETE'
        if int(self.clock())>=s.policy.expires_at:return 'REVIEW_REQUIRED'
        if int(self.clock())>=artifact.quote_expires_at:
            release=s._existing(identity,'RELEASE',binding)
            if release is not None:
                release=await s.reconcile(identity,'RELEASE',browser_hash=binding)
                if release['stage']=='CONFIRMED':return 'RELEASED'
                if release['stage']=='MEMPOOL':return 'WAITING'
            s._funding_context()
            await s.prepare_timeout(identity,browser_hash=binding)
            await s.dispatch(identity,'RELEASE',browser_hash=binding)
            return 'WAITING'
        if claim is None or current is not None and current['stage']=='MEMPOOL':return 'WAITING'
        s._funding_context()
        if current is None:
            _,signed,companion,pair=await s.delivery_issuer_review(identity,claim,browser_hash=binding)
            signature=self._retained_issuer(identity,claim,pair)
            if signature is None:
                # The transport receives only exact public evidence. The
                # independently configured issuer reconstructs this itself.
                signature=await self.issuer_sign({'generationId':self.store.generation_id,
                    'policyHash':s.policy.commitment,'claim':claim.model_dump(mode='json',by_alias=True),
                    'claimHash':claim.digest(),'purchaseBundle':signed.to_json_dict(),
                    'issuerCoinSpend':companion.issuer_signature_spend.to_json_dict(),
                    'issuerPublicKey':h(pair[0]),'message':h(pair[1])})
                self._save_issuer(identity,token,claim,signature,pair)
            await s.prepare_delivery(identity,claim,signature,browser_hash=binding)
        await s.dispatch(identity,'DELIVERY',browser_hash=binding)
        return 'WAITING'

    async def tick(self):
        if self.running:raise ValueError('CURRENT_PURCHASE_WORKER_ALREADY_RUNNING')
        self.running=True
        try:
            old=self.health();rows=self._claim();errors=0;complete=0
            for identity,binding,token in rows:
                error=None
                try:
                    async with asyncio.timeout(45):state=await self._advance(identity,binding,token)
                    complete+=state=='COMPLETE'
                except asyncio.CancelledError:raise
                except Exception as exc:
                    errors+=1;state='RETRY';code=str(exc)
                    error=code if re.fullmatch(r'CURRENT_[A-Z_]{1,100}',code)else'CURRENT_PURCHASE_CONTINUATION_UNAVAILABLE'
                with self.store._connect() as db:
                    job=db.execute('SELECT attempts FROM current_purchase_worker_jobs WHERE intent_id=? AND lease_token=?',(identity,token)).fetchone()
                    if job:
                        delay=min(60,self.interval*2**min(job['attempts']-1,3))if error else self.interval
                        db.execute('''UPDATE current_purchase_worker_jobs SET state=?,error_code=?,next_attempt=?,
                            lease_token=NULL,lease_until=0 WHERE intent_id=? AND lease_token=?''',
                            (state,error,int(self.clock())+delay,identity,token))
            value={'schema':'solslot.current-purchase-worker-health.v1','generationId':self.store.generation_id,
                'checkedAt':int(self.clock()),'cycles':(old['cycles']if old else 0)+1,
                'examined':len(rows),'completed':complete,'errors':errors,'nextCheckAt':int(self.clock())+self.interval,
                'status':'DEGRADED'if errors else'HEALTHY'}
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
