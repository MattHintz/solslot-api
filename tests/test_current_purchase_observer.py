import asyncio
import json
from dataclasses import replace
import pytest
from solslot_api.generation_customer_purchase_observer import CurrentPurchaseObserver
from tests.test_current_purchase_execution_recovery import recover
from tests.test_current_purchase_store import BROWSER
from tests.test_generation_customer_purchase_reservation_claim import body
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from tests.test_current_purchase_execution_store import bundle

@pytest.mark.asyncio
async def test_observer_confirms_retained_broadcast_after_expiry_without_browser_or_submission(recover):
 r=recover;r.retain();observer=CurrentPurchaseObserver(r.service,clock=lambda:r.clock[0])
 result=await observer.tick()
 assert result['confirmed']==1 and result['transactionsSubmitted']==result['signaturesRequested']==result['feesAllocated']==0
 assert r.store.execution_status(r.identity,'RESERVATION',browser_hash=BROWSER)['stage']=='CONFIRMED'
 assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==1
 assert (await observer.tick())['examined']==0

@pytest.mark.asyncio
async def test_no_prepared_input_is_funded_by_observation(recover):
 r=recover;observer=CurrentPurchaseObserver(r.service,clock=lambda:r.clock[0]);result=await observer.tick()
 assert result['examined']==1 and result['confirmed']==0 and result['errors']==0
 assert r.node.reads==r.node.observations==0
 assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER) is None
 assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==0

@pytest.mark.asyncio
async def test_failed_node_reads_have_health_and_retry_exact_saved_work(recover):
 r=recover;r.retain();r.node.network='mainnet'
 observer=CurrentPurchaseObserver(r.service,clock=lambda:r.clock[0]);failed=await observer.tick()
 assert failed['status']=='DEGRADED' and failed['errors']==1
 assert 'browser'not in json.dumps(failed).lower() and 'mainnet'not in json.dumps(failed)
 r.node.network='testnet11';result=await observer.tick()
 assert result['status']=='HEALTHY'and result['confirmed']==1
 assert result['cycles']==2 and r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==1

@pytest.mark.asyncio
async def test_restart_retains_health_cursor_and_advances_other_pending_purchases(recover):
 r=recover;r.retain()
 await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
 policy=replace(r.service.policy,maximum_purchases=2,deed_launchers=r.service.policy.deed_launchers|frozenset([type(r.service.policy.generation)(bytes([9])*32)]));r.service.policy=policy
 r.store.bind_execution_policy(policy.commitment,2,10)
 for n in (2,3):
  claim=CurrentReservationClaim.model_validate({**body(),'issuerPolicyHash':policy.commitment,'availableCoinId':'0x'+format(n,'02x')*32})
  identity=r.store.save_review(claim,browser_hash=BROWSER,request_key='other-'+str(n),now=110)
  r.store.prepare_execution(identity,'RESERVATION',bundle(n),browser_hash=BROWSER,
   claim_hash=claim.digest(),fee_cap=10,expires_at=200,now=115)
 one=CurrentPurchaseObserver(r.service,batch_size=1,clock=lambda:r.clock[0]);a=await one.tick()
 two=CurrentPurchaseObserver(r.service,batch_size=1,clock=lambda:r.clock[0]);b=await two.tick()
 assert a['cursor']!=b['cursor'] and a['examined']==b['examined']==1 and b['cycles']==2
 assert a['errors']==b['errors']==0 and r.node.observations==1

@pytest.mark.asyncio
async def test_cancellation_preserves_saved_bundle_and_does_not_report_a_completed_cycle(recover):
 r=recover;r.retain();entered=asyncio.Event()
 async def pending(*a,**kw):entered.set();await asyncio.Event().wait()
 r.node.observe_exact_protocol_bundle=pending
 observer=CurrentPurchaseObserver(r.service,clock=lambda:r.clock[0]);task=asyncio.create_task(observer.tick())
 await entered.wait();task.cancel()
 with pytest.raises(asyncio.CancelledError):await task
 assert observer.health() is None and not observer._running
 assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER)['spendBundleId']==r.prepared.spend_bundle_id

@pytest.mark.asyncio
async def test_concurrent_cycle_is_refused(recover):
 observer=CurrentPurchaseObserver(recover.service);observer._running=True
 with pytest.raises(ValueError,match='ALREADY_RUNNING'):await observer.tick()

@pytest.mark.parametrize('options',[{'batch_size':0},{'batch_size':True},{'batch_size':9},{'interval':0},{'interval':301}])
def test_observer_is_bounded(recover,options):
 with pytest.raises(ValueError,match='BOUNDED'):CurrentPurchaseObserver(recover.service,**options)

@pytest.mark.asyncio
async def test_stale_health_uses_receipt_age(recover):
 r=recover;observer=CurrentPurchaseObserver(r.service,clock=lambda:r.clock[0]);await observer.tick()
 r.clock[0]+=observer.batch_size*25+2*observer.interval+1
 assert observer.health()['status']=='STALE'

@pytest.mark.asyncio
async def test_corrupt_claim_fails_before_node_or_financial_mutation(recover):
 r=recover;r.retain();observer=CurrentPurchaseObserver(r.service,clock=lambda:r.clock[0])
 with r.store._connect() as db:
  db.execute('UPDATE current_customer_purchase_reviews SET claim_hash=? WHERE intent_id=?',('0x'+'ff'*32,r.identity))
 with pytest.raises(ValueError,match='SAVED_REVIEW_CHANGED'):await observer.tick()
 assert r.node.reads==r.node.observations==0 and observer.health() is None
 assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==1

@pytest.mark.asyncio
async def test_stopped_worker_does_not_touch_saved_work(recover):
 r=recover;observer=CurrentPurchaseObserver(r.service);stop=asyncio.Event();stop.set()
 await observer.run(stop)
 assert observer.health() is None and r.node.reads==r.node.observations==0
