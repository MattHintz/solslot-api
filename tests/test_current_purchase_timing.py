import asyncio
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import pytest
from solslot_api import generation_customer_purchase_timing as timing


@pytest.mark.asyncio
async def test_completed_stage_survives_later_failure_and_timeout():
    service=SimpleNamespace(_checkout_timings=timing.CheckoutTimings())
    async def ok():return 17
    async def fail():raise RuntimeError('private detail')
    async def slow():await asyncio.sleep(1)
    assert await timing.measured(service,'intent','validator_quorum',ok())==17
    with pytest.raises(RuntimeError,match='private detail'):
        await timing.measured(service,'intent','freshness_verification',fail())
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(.001):
            await timing.measured(service,'intent','freshness_verification',slow())
    value=service._checkout_timings.snapshot('intent')
    assert value['scope']=='process_lifetime'
    assert value['stages']['validator_quorum']['count']==1
    assert value['stages']['freshness_verification'] is None
    assert value['stages']['queue'] is None
    assert 'private detail' not in str(value)


def test_bounded_concurrent_aggregate_and_unknown_stages():
    c=timing.CheckoutTimings()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _:c.record('one','reservation_verification',timing.start()),range(100)))
    assert c.snapshot('one')['stages']['reservation_verification']['count']==100
    c.record('one','arbitrary private data',timing.start())
    assert 'arbitrary' not in str(c.snapshot('one'))
    for n in range(timing.MAX_INTENTS+1):c.record(str(n),'validator_quorum',timing.start())
    assert len(c._rows)==timing.MAX_INTENTS
    assert c.snapshot('one')['stages']['reservation_verification'] is None


@pytest.mark.asyncio
async def test_instrumentation_failure_never_changes_operation(monkeypatch):
    service=SimpleNamespace(_checkout_timings=SimpleNamespace(record=lambda *a: (_ for _ in ()).throw(RuntimeError())))
    async def work():return 'result'
    monkeypatch.setattr(timing,'monotonic_ns',lambda: (_ for _ in ()).throw(RuntimeError()))
    assert await timing.measured(service,'intent','validator_quorum',work())=='result'


@pytest.mark.asyncio
async def test_single_reservation_instruments_actual_order_and_preserves_failure(monkeypatch):
    from solslot_api import generation_customer_purchase_execution as execution
    service=object.__new__(execution.CurrentNativePurchaseExecution)
    service._checkout_timings=timing.CheckoutTimings()
    service._saved=lambda *a:{'reservationClaim':object(),'retainedSignatures':{'reservation':{}}}
    service._existing=lambda *a:None
    service._arguments=lambda:{}
    service.settings=object()
    calls=[]
    async def verify(*args,**kwargs):
        calls.append('verify')
        if len(calls)==3:raise ValueError('freshness failed')
        return object()
    async def quorum(*args,**kwargs):calls.append('quorum');return object()
    monkeypatch.setattr(execution,'verify_current_reservation',verify)
    monkeypatch.setattr(execution,'collect_current_purchase_quorum',quorum)
    with pytest.raises(ValueError,match='freshness failed'):
        await service.prepare_reservation('intent',browser_hash='binding')
    snapshot=service._checkout_timings.snapshot('intent')
    assert calls==['verify','quorum','verify']
    assert snapshot['lastCompleted']=='validator_quorum'
    assert snapshot['stages']['reservation_verification']['count']==1
    assert snapshot['stages']['validator_quorum']['count']==1
    assert snapshot['stages']['freshness_verification'] is None


@pytest.mark.asyncio
async def test_worker_attempts_isolate_concurrent_stages_and_record_timeout():
    service=SimpleNamespace(_checkout_timings=timing.CheckoutTimings())
    async def step():await asyncio.sleep(.003)
    async def cycle(identity,stage):
        await timing.measured(service,identity,stage,step())
        await asyncio.sleep(.05)
    async def run(identity,stage):
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(.01):
                await timing.worker_attempt(service,identity,cycle(identity,stage))
    await asyncio.gather(run('a','validator_quorum'),run('b','reservation_verification'))
    for identity,stage in [('a','validator_quorum'),('b','reservation_verification')]:
        attempt=service._checkout_timings.snapshot(identity)['latestAttempt']
        assert attempt['scope']=='worker_cycle' and list(attempt['stagesMs'])==[stage]
        assert attempt['outcome']=='cancelled'
        assert attempt['totalMs']>=attempt['stagesMs'][stage]
        assert attempt['unattributedMs']==attempt['totalMs']-attempt['stagesMs'][stage]
