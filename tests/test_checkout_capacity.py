"""Retained-history cost and slow-provider scheduling at real shared boundaries."""
import asyncio
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_api.purchase_admission import ADMISSION_POLICY
from solslot_api.stripe_delivery_worker import StripeDeliveryWorker, StripeDeliveryWorkerConfig
from tests.test_purchase_admission import receipt, OWNER


def test_active_admission_does_not_scan_expired_history(tmp_path,monkeypatch):
    store=PaymentPurchaseStore(str(tmp_path/'capacity.db'))
    with store._connect() as db:
        db.execute('BEGIN')
        db.executemany('INSERT INTO payment_purchase_admission VALUES (?,?,?,?,?,?,NULL,?,?,?)',
            [(f'history-{i}',f'subject-{i}',f'vault-{i}','{}',1,OWNER,'QUOTING' if i%2 else 'CLOSED',1,2) for i in range(50000)])
        db.execute('COMMIT')
    connect=store._connect;steps=[]
    @contextmanager
    def bounded():
        with connect() as db:
            # Deterministic VM work limit, not a timing assertion on the host.
            def progress():
                steps.append(1)
                return int(len(steps)>20)
            db.set_progress_handler(progress,1000)
            yield db
    monkeypatch.setattr(store,'_connect',bounded)
    store.admit_purchase(purchase_intent_id='live',receipt=receipt(),activation=ADMISSION_POLICY,
        now=1000,owner_auth_type=1,owner_key=OWNER)
    with connect() as db:assert db.execute('SELECT count(*) FROM payment_purchase_admission').fetchone()[0]==50001


@pytest.mark.asyncio
async def test_slow_delivery_has_deadline_and_no_waiter_queue():
    worker=object.__new__(StripeDeliveryWorker)
    worker.config=StripeDeliveryWorkerConfig(enabled=True,advance_timeout_seconds=.05)
    worker._advance_lock=asyncio.Lock();worker._owner='isolated'
    worker._writes_are_open=lambda:True;worker._rail_is_enabled=lambda _:True
    a=SimpleNamespace(purchase_id='slow',state='PAYMENT_VERIFIED')
    b=SimpleNamespace(purchase_id='next',state='PAYMENT_VERIFIED')
    queue=[a,b];errors=[];entered=asyncio.Event()
    worker.store=SimpleNamespace(claim_next=lambda **kw:queue.pop(0),
        record_error=lambda purchase_id,error:errors.append(purchase_id) or a)
    async def advance(op):
        if op is a:
            entered.set();await asyncio.Event().wait()
        return op
    worker._advance=advance
    task=asyncio.create_task(worker.reconcile_once());await entered.wait()
    # A busy caller does not wait behind the slow provider or claim another row.
    assert await asyncio.wait_for(worker.reconcile_once(),.02) is None
    assert await asyncio.wait_for(task,.2) is a and errors==['slow']
    assert await worker.reconcile_once() is b


@pytest.mark.asyncio
async def test_delivery_cancellation_preserves_recovery_and_unlocks():
    worker=object.__new__(StripeDeliveryWorker);worker.config=StripeDeliveryWorkerConfig(enabled=True)
    worker._advance_lock=asyncio.Lock();worker._owner='isolated';worker._writes_are_open=lambda:True
    worker._rail_is_enabled=lambda _:True;op=SimpleNamespace(purchase_id='retained',state='DELIVERY_PREPARED')
    errors=[];entered=asyncio.Event()
    worker.store=SimpleNamespace(claim_next=lambda **kw:op,record_error=lambda pid,error:errors.append(pid))
    async def advance(_):entered.set();await asyncio.Event().wait()
    worker._advance=advance;task=asyncio.create_task(worker.reconcile_once());await entered.wait();task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    assert errors==['retained'] and not worker._advance_lock.locked()
