"""Observe already-saved native purchases; never prepare, fund, sign or submit.

The finite cursor and health receipt live in the existing recovered checkout
journal. A browser is not required to reconcile an interrupted broadcast.
"""
import asyncio
import json
import re
import time

from .generation_customer_purchase_execution import CurrentNativePurchaseExecution
from .generation_operations import canonical

class CurrentPurchaseObserver:
    def __init__(self,service,*,batch_size=4,interval=30,clock=time.time):
        if (not isinstance(service,CurrentNativePurchaseExecution)
                or service.settings.network!='testnet11'
                or type(batch_size)is not int or not 1<=batch_size<=8
                or type(interval)is not int or not 15<=interval<=300):
            raise ValueError('CURRENT_PURCHASE_BOUNDED_OBSERVER_REQUIRED')
        self.service=service;self.store=service.store;self.batch_size=batch_size
        self.interval=interval;self.clock=clock;self._running=False
        with self.store._connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS current_purchase_observer_health (
                generation_id TEXT PRIMARY KEY, document TEXT NOT NULL)''')

    def health(self):
        with self.store._connect() as db:
            row=db.execute('SELECT document FROM current_purchase_observer_health WHERE generation_id=?',
                           (self.store.generation_id,)).fetchone()
        if row is None:return None
        value=json.loads(row[0])
        if (value.get('generationId')!=self.store.generation_id
                or value.get('schema')!='solslot.current-purchase-observer-health.v1'
                or type(value.get('checkedAt'))is not int
                or type(value.get('cycles'))is not int or value['cycles']<1
                or value.get('cursor')is not None and re.fullmatch(r'0x[0-9a-f]{64}:(RESERVATION|DELIVERY|RELEASE)',value['cursor'])is None):
            raise ValueError('CURRENT_PURCHASE_OBSERVER_HEALTH_INVALID')
        if int(self.clock())-value['checkedAt']>self.batch_size*25+2*self.interval:
            value={**value,'status':'STALE'}
        return value

    def _targets(self,cursor):
        with self.store._connect() as db:
            rows=db.execute('''SELECT e.intent_id,e.phase,r.browser_hash
                FROM current_purchase_executions e JOIN current_customer_purchase_reviews r
                ON r.intent_id=e.intent_id WHERE r.generation_id=? AND e.stage!='CONFIRMED'
                ORDER BY e.intent_id,e.phase LIMIT 97''',(self.store.generation_id,)).fetchall()
            if len(rows)>96:raise ValueError('CURRENT_PURCHASE_OBSERVER_CAPACITY_EXCEEDED')
            ordered=sorted(rows,key=lambda r:r['intent_id']+':'+r['phase'])
            if cursor:
                ordered=[r for r in ordered if r['intent_id']+':'+r['phase']>cursor]+[
                    r for r in ordered if r['intent_id']+':'+r['phase']<=cursor]
            selected=ordered[:self.batch_size]
            # Verify retained claim hashes/generation/binding before any node read.
            for row in selected:self.store._row(db,row['intent_id'],row['browser_hash'])
        return selected

    async def tick(self):
        if self._running:raise ValueError('CURRENT_PURCHASE_OBSERVER_ALREADY_RUNNING')
        self._running=True
        try:
            previous=self.health();cursor=previous['cursor']if previous else None
            rows=self._targets(cursor);confirmed=0;errors=0
            for row in rows:
                cursor=row['intent_id']+':'+row['phase']
                try:
                    async with asyncio.timeout(25):
                        status=await self.service.reconcile(row['intent_id'],row['phase'],browser_hash=row['browser_hash'])
                    confirmed+=status['stage']=='CONFIRMED'
                except asyncio.CancelledError:raise
                except Exception:errors+=1
            now=int(self.clock())
            value={'schema':'solslot.current-purchase-observer-health.v1','generationId':self.store.generation_id,
                'checkedAt':now,'cycles':(previous['cycles']if previous else 0)+1,'cursor':cursor,
                'examined':len(rows),'confirmed':confirmed,'errors':errors,
                'status':'DEGRADED'if errors else 'HEALTHY','nextCheckAt':now+self.interval,
                'signaturesRequested':0,'feesAllocated':0,'transactionsSubmitted':0}
            with self.store._connect() as db:
                db.execute('INSERT INTO current_purchase_observer_health VALUES (?,?) ON CONFLICT(generation_id) DO UPDATE SET document=excluded.document',
                           (self.store.generation_id,canonical(value)))
            return value
        finally:self._running=False

    async def run(self,stop):
        while not stop.is_set():
            try:await self.tick()
            except asyncio.CancelledError:raise
            except Exception:
                # Fail closed on corrupt recovery state. Never repair/reset a
                # journal here or let one failed cycle trigger a transaction.
                pass
            try:await asyncio.wait_for(stop.wait(),timeout=self.interval)
            except TimeoutError:pass
