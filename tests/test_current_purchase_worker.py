import asyncio
import json
from types import SimpleNamespace
import pytest
from solslot_api.generation_customer_purchase_worker import CurrentPurchaseWorker
from tests.test_current_purchase_execution_recovery import recover
from tests.test_current_purchase_store import BROWSER

async def no_issuer(_):raise AssertionError('No payer authorization permits an issuer call')

@pytest.fixture(autouse=True)
def fixture_artifact(monkeypatch):
 # Recovery fixtures deliberately contain an opaque claim. Native artifact,
 # signatures and exact delivery are exercised by the full consensus test.
 monkeypatch.setattr('solslot_api.generation_customer_purchase_worker.purchase_artifact_v3_from_json',
     lambda _:SimpleNamespace(quote_expires_at=200))

@pytest.mark.asyncio
async def test_expired_prepared_work_is_closed_without_funding_or_signing(recover):
 r=recover;w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['errors']==0 and h['examined']==1
 with r.store._connect()as db:assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='CLOSED'
 assert (await w.tick())['examined']==0
 assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==0

@pytest.mark.asyncio
async def test_interrupted_reservation_is_reconciled_before_any_dispatch(recover):
 r=recover;r.retain();w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['errors']==0
 assert r.store.execution_status(r.identity,'RESERVATION',browser_hash=BROWSER)['stage']=='CONFIRMED'
 assert r.node.observations==1

@pytest.mark.asyncio
async def test_durable_lease_excludes_another_worker_and_recovers_after_restart(recover):
 r=recover;a=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);b=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 rows=a._claim();assert len(rows)==1 and b._claim()==[]
 r.clock[0]+=a.LEASE_SECONDS_PER_ACTION*a.batch_size+6
 assert len(b._claim())==1

@pytest.mark.asyncio
async def test_errors_back_off_durably_without_exposing_node_details(recover):
 r=recover;r.retain();r.node.network='mainnet';w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['errors']==1 and h['status']=='DEGRADED'
 assert (await w.tick())['examined']==0
 r.clock[0]+=11;r.node.network='testnet11'
 h=await CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]).tick()
 assert h['errors']==0 and r.node.observations==1 and 'mainnet'not in json.dumps(h)

@pytest.mark.asyncio
async def test_corrupt_retained_claim_stops_before_node_or_issuer(recover):
 r=recover;w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer)
 with r.store._connect()as db:db.execute('UPDATE current_customer_purchase_reviews SET claim_hash=?',('0x'+'ff'*32,))
 with pytest.raises(ValueError,match='SAVED_REVIEW_CHANGED'):await w.tick()
 assert r.node.reads==0 and w.health()is None

@pytest.mark.asyncio
async def test_cancellation_holds_lease_and_restarts_without_duplicate_action(recover):
 r=recover;r.retain();entered=asyncio.Event()
 async def pending(*a,**kw):entered.set();await asyncio.Event().wait()
 r.node.observe_exact_protocol_bundle=pending
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);task=asyncio.create_task(w.tick());await asyncio.wait_for(entered.wait(),2);task.cancel()
 with pytest.raises(asyncio.CancelledError):await task
 assert w.health()is None and not w.running
 assert CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])._claim()==[]

@pytest.mark.asyncio
async def test_stale_health_is_not_an_enabled_worker_claim(recover):
 r=recover;w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 r.clock[0]+=w.batch_size*w.LEASE_SECONDS_PER_ACTION+2*w.interval
 assert w.health()['status']=='HEALTHY'
 r.clock[0]+=1;assert w.health()['status']=='STALE'

@pytest.mark.asyncio
async def test_confirmed_unpaid_reservation_is_selected_for_automatic_timeout(recover):
 r=recover;r.retain();await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
 r.clock[0]=210;r.service.policy=SimpleNamespace(expires_at=400,commitment=r.service.policy.commitment)
 calls=[]
 def funding():calls.append('funding')
 async def release(identity,*,browser_hash):calls.append(('release',identity,browser_hash))
 async def dispatch(identity,phase,*,browser_hash):calls.append(('dispatch',phase))
 r.service._funding_context=funding;r.service.prepare_timeout=release;r.service.dispatch=dispatch
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['examined']==1 and h['errors']==0
 assert calls==['funding',('release',r.identity,BROWSER),('dispatch','RELEASE')]

@pytest.mark.asyncio
async def test_saved_delivery_is_reconciled_before_timeout_even_after_quote_expiry(recover):
 r=recover;r.retain();await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
 r.clock[0]=210;r.service.policy=SimpleNamespace(expires_at=400,commitment=r.service.policy.commitment)
 original=r.service._existing
 r.service._existing=lambda identity,phase,binding:({'stage':'RECONCILING'}if phase=='DELIVERY'else original(identity,phase,binding))
 calls=[]
 async def reconcile(identity,phase,*,browser_hash):calls.append(phase);return {'stage':'CONFIRMED'}
 r.service.reconcile=reconcile
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 assert (await w.tick())['errors']==0
 assert calls==['RESERVATION','DELIVERY']
 with r.store._connect()as db:assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='COMPLETE'

@pytest.mark.parametrize('options',[{'issuer_sign':None},{'batch_size':0},{'batch_size':5},{'interval':4},{'interval':61}])
def test_worker_has_no_default_signer_or_unbounded_loop(recover,options):
 with pytest.raises(ValueError):CurrentPurchaseWorker(recover.service,**{'issuer_sign':no_issuer,**options})
