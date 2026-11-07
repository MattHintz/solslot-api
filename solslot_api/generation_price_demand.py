"""Coalesced demand for the existing signed price collector, disabled by default.

The caller authenticates a quote request and binds the existing collector at
deployment. This module exposes no route, credential, provider selection,
purchase authority or transaction submission. A status read never starts work.
"""
import asyncio
import inspect
import logging
import time
import uuid
from .generation_customer_purchase_store import CurrentCustomerPurchaseStore

logger=logging.getLogger(__name__)


class PriceDemandRuntime:
    def __init__(self, *, store, health, collect, enabled=False, clock=time.time, owner=None):
        if (not isinstance(store, CurrentCustomerPurchaseStore) or not callable(health)
                or not callable(collect) or type(enabled) is not bool):
            raise ValueError('CURRENT_PRICE_DEMAND_CONFIGURATION_INVALID')
        self.store,self.health,self.collect,self.enabled,self.clock=store,health,collect,enabled,clock
        self.owner=owner or 'price-worker-'+uuid.uuid4().hex
        if not isinstance(self.owner,str) or not 1<=len(self.owner)<=128:
            raise ValueError('CURRENT_PRICE_WORKER_OWNER_INVALID')

    async def _health(self,now):
        # Reserve the complete five-minute quote window before declaring a
        # round usable; a nearly expired round must not be silently reused.
        required=now+300
        value=self.health(now=now,required_until=required)
        if inspect.isawaitable(value):
            value=await asyncio.wait_for(value,timeout=8)
        if (not isinstance(value,dict) or value.get('schema')!='solslot.price-refresh-status.v1'
                or value.get('network')!='testnet11' or type(value.get('checkedAt'))is not int
                or not now<=value['checkedAt']<=now+5
                or value.get('requiredUntil')!=value['checkedAt']+300 or type(value.get('canQuote'))is not bool
                or type(value.get('canRefresh'))is not bool):
            raise ValueError('CURRENT_PRICE_HEALTH_BINDING_INVALID')
        if value['canQuote'] and (value.get('status')!='READY' or type(value.get('validUntil'))is not int
                or value['validUntil']<value['requiredUntil'] or type(value.get('sourceCount'))is not int
                or type(value.get('signerCount'))is not int or value['sourceCount']<2 or value['signerCount']<2):
            raise ValueError('CURRENT_PRICE_SIGNED_EVIDENCE_REQUIRED')
        if value['canRefresh'] and (value.get('status') not in ('READY','REFRESH_REQUIRED')
                or value.get('quota',{}).get('status')!='AVAILABLE'
                or type(value.get('quota',{}).get('remainingRequests'))is not int
                or value['quota']['remainingRequests']<1):
            raise ValueError('CURRENT_PRICE_REFRESH_QUOTA_REQUIRED')
        return value

    async def status(self):
        """Read current health and saved work only; never schedule or collect."""
        now=int(self.clock())
        return {'price':await self._health(now),'job':self.store.price_refresh_job_status()}

    async def request(self):
        """Called only by an authenticated explicit quote action."""
        if not self.enabled:raise ValueError('CURRENT_PRICE_DEMAND_NOT_ENABLED')
        now=int(self.clock());value=await self._health(now)
        if value['canQuote'] or not value['canRefresh']:
            return {'price':value,'job':self.store.price_refresh_job_status()}
        return {'price':value,'job':self.store.request_price_refresh(now=now)}

    async def run_once(self):
        """Claim one durable job, reconcile, then call the fixed collector once."""
        if not self.enabled:raise ValueError('CURRENT_PRICE_DEMAND_NOT_ENABLED')
        now=int(self.clock())
        job=self.store.claim_checkout_job('price-refresh',owner=self.owner,now=now,lease_seconds=90)
        if job is None:return {'state':'IDLE'}
        if job.get('busy'):return {'state':'BUSY'}
        status='UNAVAILABLE';done=job['attempts']>=2
        try:
            value=await self._health(now)
            if value['canQuote']:
                status='READY';done=True
            elif not value['canRefresh']:
                status='REVIEW_REQUIRED';done=True
            else:
                # No DB transaction crosses provider I/O. The fixed collector
                # enforces its own process lock, two-source/two-signer checks,
                # finite policy and quota. Recheck saved evidence after a lost
                # response or restart before requesting another collection.
                await asyncio.wait_for(self.collect(),timeout=65)
                value=await self._health(int(self.clock()))
                if value['canQuote']:
                    status='READY';done=True
        except asyncio.CancelledError:
            status='INTERRUPTED'
            raise
        except TimeoutError:
            status='TIMED_OUT'
        except Exception:
            status='UNAVAILABLE'
        finally:
            checked=int(self.clock())
            self.store.finish_checkout_job(job['purchase_id'],'price-refresh',owner=self.owner,
                now=checked,status=status,done=done)
            self.store.lifecycle_health('price-refresh',now=checked,
                binding={'generationId':self.store.generation_id,'network':'testnet11'},status=status)
        return {'state':status,'terminal':done}

    async def run(self, stop, *, interval=5):
        """Run the existing bounded job lane until application shutdown."""
        if not isinstance(stop,asyncio.Event) or type(interval)is not int or not 1<=interval<=60:
            raise ValueError('CURRENT_PRICE_WORKER_INTERVAL_INVALID')
        while not stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A transient journal failure must not silently kill the lane.
                # Do not log provider payloads or credentials.
                logger.warning('price_worker_unavailable exception_type=%s',type(exc).__name__)
                try:
                    self.store.lifecycle_health('price-refresh',now=int(self.clock()),
                        binding={'generationId':self.store.generation_id,'network':'testnet11'},status='UNAVAILABLE')
                except Exception:
                    # A broken health write must not permanently stop retry.
                    pass
            try:
                await asyncio.wait_for(stop.wait(),timeout=interval)
            except TimeoutError:
                pass
