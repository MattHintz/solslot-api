"""Demand-driven pricing uses existing durable jobs and never runs on GET."""
import asyncio
from datetime import datetime,timezone
import json
from pathlib import Path
import pytest
from solslot_api.generation_customer_purchase_store import CurrentCustomerPurchaseStore
from solslot_api.generation_price_demand import PriceDemandRuntime
from solslot_api.xch_price_feed import publish_snapshot
from solslot_api.xch_price_feed_status import price_refresh_status
from solslot_api import xch_price_feed_runner as runner
from tests.test_xch_price_feed import NOW, authorized, settings


@pytest.fixture
def setup(tmp_path):
    store=CurrentCustomerPurchaseStore(tmp_path/'payment_purchases_v2.db','0x'+'01'*32)
    clock=[NOW];state={'ready':False,'refresh':True};calls=[]
    def health(*,now,required_until):
        return {'schema':'solslot.price-refresh-status.v1','network':'testnet11',
            'checkedAt':now,'requiredUntil':required_until,'canQuote':state['ready'],
            'canRefresh':state['refresh'],'status':'READY'if state['ready']else 'REFRESH_REQUIRED'if state['refresh']else 'REFRESH_UNAVAILABLE',
            'validUntil':now+300 if state['ready']else None,'sourceCount':2 if state['ready']else 0,
            'signerCount':2 if state['ready']else 0,'quota':{'status':'AVAILABLE'if state['refresh']else 'EXHAUSTED',
                'remainingRequests':20 if state['refresh']else 0}}
    async def collect():calls.append('collect');state['ready']=True
    def worker(**kwargs):return PriceDemandRuntime(store=store,health=health,collect=collect,
        enabled=True,clock=lambda:clock[0],**kwargs)
    return store,clock,state,calls,health,worker


@pytest.mark.asyncio
async def test_status_is_read_only_and_never_schedules_work(setup):
    store,clock,state,calls,health,worker=setup
    w=worker()
    for _ in range(3):assert (await w.status())['job']is None
    assert calls==[] and store.price_refresh_job_status()is None


@pytest.mark.asyncio
async def test_disabled_by_default_and_invalid_health_fails_closed(setup):
    store,clock,state,calls,health,worker=setup
    w=PriceDemandRuntime(store=store,health=health,collect=lambda:None,clock=lambda:clock[0])
    with pytest.raises(ValueError,match='NOT_ENABLED'):await w.request()
    def bad(**kwargs):return {**health(**kwargs),'canQuote':True,'status':'READY','sourceCount':1,'signerCount':1}
    w=PriceDemandRuntime(store=store,health=bad,collect=lambda:None,enabled=True,clock=lambda:clock[0])
    with pytest.raises(ValueError,match='SIGNED_EVIDENCE_REQUIRED'):await w.request()
    assert store.price_refresh_job_status()is None


@pytest.mark.asyncio
async def test_quote_must_cover_full_window_at_health_check_time(setup):
    store,clock,state,calls,health,worker=setup
    state['ready']=True
    def delayed(**kwargs):
        value=health(**kwargs)
        return {**value,'checkedAt':kwargs['now']+1,'requiredUntil':kwargs['now']+301}
    w=PriceDemandRuntime(store=store,health=delayed,collect=lambda:None,enabled=True,clock=lambda:clock[0])
    with pytest.raises(ValueError,match='SIGNED_EVIDENCE_REQUIRED'):await w.request()
    assert store.price_refresh_job_status()is None


@pytest.mark.asyncio
async def test_concurrent_quote_requests_coalesce_into_one_collector_call(setup):
    store,clock,state,calls,health,worker=setup
    started=asyncio.Event();release=asyncio.Event()
    async def collect():calls.append('collect');started.set();await release.wait();state['ready']=True
    a=PriceDemandRuntime(store=store,health=health,collect=collect,enabled=True,clock=lambda:clock[0],owner='worker-a')
    b=PriceDemandRuntime(store=store,health=health,collect=collect,enabled=True,clock=lambda:clock[0],owner='worker-b')
    assert (await a.request())['job']['status']=='WAITING'
    assert (await b.request())['job']['status']=='WAITING'
    first=asyncio.create_task(a.run_once());await started.wait()
    assert await b.run_once()=={'state':'BUSY'}
    assert (await b.request())['job']['attempts']==1
    release.set();assert await first=={'state':'READY','terminal':True}
    assert calls==['collect'] and store.price_refresh_job_status()['done']
    assert (await b.request())['price']['canQuote'] and calls==['collect']


@pytest.mark.asyncio
async def test_failed_collection_has_three_durable_attempts_and_explicit_retry(setup):
    store,clock,state,calls,health,worker=setup
    async def fail():calls.append('attempt');raise OSError('synthetic provider failure')
    w=PriceDemandRuntime(store=store,health=health,collect=fail,enabled=True,clock=lambda:clock[0])
    await w.request()
    for expected in (1,2,3):
        result=await w.run_once();job=store.price_refresh_job_status()
        assert result['state']=='UNAVAILABLE' and job['attempts']==expected
        assert job['done']==(expected==3)
        if expected<3:clock[0]=job['nextAttemptAt']
    assert calls==['attempt']*3
    before=store.price_refresh_job_status()
    assert (await w.request())['job']['done'] and store.price_refresh_job_status()==before
    assert await w.run_once()=={'state':'IDLE'}
    clock[0]=before['nextAttemptAt']
    assert not (await w.request())['job']['done'] and store.price_refresh_job_status()['attempts']==0


@pytest.mark.asyncio
async def test_restart_reconciles_published_price_before_retrying_provider(setup):
    store,clock,state,calls,health,worker=setup
    w=worker(owner='original');await w.request()
    claimed=store.claim_checkout_job('price-refresh',owner='crashed',now=clock[0],lease_seconds=90)
    assert claimed is not None
    # A previous collector published a valid round but its response was lost.
    state['ready']=True;clock[0]+=91
    resumed=worker(owner='resumed')
    assert await resumed.run_once()=={'state':'READY','terminal':True}
    assert calls==[] and store.price_refresh_job_status()['done']


@pytest.mark.asyncio
async def test_cancelled_worker_preserves_attempt_and_recovers_published_price(setup):
    store,clock,state,calls,health,worker=setup
    started=asyncio.Event()
    async def interrupted():
        calls.append('collect');state['ready']=True;started.set()
        await asyncio.Event().wait()
    w=PriceDemandRuntime(store=store,health=health,collect=interrupted,enabled=True,clock=lambda:clock[0])
    await w.request();task=asyncio.create_task(w.run_once());await started.wait();task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    job=store.price_refresh_job_status()
    assert job['attempts']==1 and job['status']=='INTERRUPTED' and not job['done']
    clock[0]=job['nextAttemptAt']
    assert await worker(owner='resumed').run_once()=={'state':'READY','terminal':True}
    assert calls==['collect']


@pytest.mark.asyncio
async def test_repeated_crashes_do_not_reset_attempts_or_restart_automatically(setup):
    store,clock,state,calls,health,worker=setup
    await worker().request()
    for i in range(3):
        assert store.claim_checkout_job('price-refresh',owner=f'crashed-{i}',now=clock[0],lease_seconds=90)
        clock[0]+=91
    assert store.claim_checkout_job('price-refresh',owner='fourth',now=clock[0],lease_seconds=90)is None
    job=store.price_refresh_job_status()
    assert job['done'] and job['attempts']==3 and job['status']=='INTERRUPTED'
    assert (await worker().request())['job']['done'] and calls==[]


@pytest.mark.asyncio
async def test_exhausted_quota_never_starts_collector(setup):
    store,clock,state,calls,health,worker=setup
    state['refresh']=False;w=worker()
    assert (await w.request())['job']is None
    assert await w.run_once()=={'state':'IDLE'} and calls==[]


@pytest.mark.asyncio
async def test_real_signed_snapshot_is_verified_after_synthetic_collection(setup,tmp_path,monkeypatch):
    store,clock,state,calls,_,worker=setup
    pubkeys,signed=authorized();config=settings(tmp_path,pubkeys)
    usage=tmp_path/'usage.json';policy=tmp_path/'policy.json'
    usage.write_text(json.dumps({'month':datetime.fromtimestamp(NOW,timezone.utc).strftime('%Y-%m'),'calls':1}))
    policy.write_text(json.dumps({'schema':'solslot.xch-price-test-window.v1','network':'testnet11','notBefore':NOW-1,'expiresAt':NOW+3600}))
    monkeypatch.setattr(runner,'_check_config_owner',lambda p:None)
    def actual_health(*,now,required_until):return price_refresh_status(config,snapshot=Path(config.payment_oracle_rounds_path),
        usage=usage,policy=policy,now=now,required_until=required_until)
    async def collect():calls.append('synthetic signed round');publish_snapshot(config,signed,now=NOW)
    w=PriceDemandRuntime(store=store,health=actual_health,collect=collect,enabled=True,clock=lambda:NOW)
    assert (await w.request())['price']['refreshRequired']
    assert await w.run_once()=={'state':'READY','terminal':True}
    q=(await w.status())['price']
    assert q['sourceCount']==2 and q['signerCount']==2 and q['canQuote']
    assert calls==['synthetic signed round']
