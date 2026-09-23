import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from solslot_api import stamp_recovery_worker as worker
from solslot_api.config import Settings

@pytest.mark.asyncio
async def test_worker_ignores_unsigned_attempts_and_bounds_signed_recovery(monkeypatch):
    records={'unsigned':{'status':'stamp_pending'},'signed':{'status':'stamp_pending'},'done':{'status':'chia_confirmed'}}
    ledger=SimpleNamespace(all_enrollments=lambda:records,get_stamp_attempt=lambda key:{'bundle_hex':'aa' if key=='signed' else None})
    monkeypatch.setattr(worker,'get_credential_ledger',lambda _:ledger)
    monkeypatch.setattr(worker.enrollment,'_sync_chia_stamp',lambda *_:SimpleNamespace(status='stamp_pending'))
    recovery=AsyncMock();monkeypatch.setattr(worker,'recover_saved_stamp',recovery)
    store=SimpleNamespace(attempt_count=lambda key:0)
    w=worker.StampRecoveryWorker(Settings(network='testnet11',protocol_fee_funding_enabled=True),object(),store)
    await w.tick();assert recovery.await_count==1
    assert recovery.call_args.args[3]=='signed'
    await w.tick();assert recovery.await_count==1  # interval/backoff, no flooding
    w.next_check.clear();store.attempt_count=lambda key:3
    await w.tick();assert recovery.await_count==1  # persistent submission-window ceiling

@pytest.mark.asyncio
async def test_worker_indexes_confirmation_and_releases_funding(monkeypatch):
    ledger=SimpleNamespace(all_enrollments=lambda:{'v':{'status':'stamp_pending'}},get_stamp_attempt=lambda _:{'bundle_hex':'aa'})
    monkeypatch.setattr(worker,'get_credential_ledger',lambda _:ledger)
    monkeypatch.setattr(worker.enrollment,'_sync_chia_stamp',lambda *_:SimpleNamespace(status='chia_confirmed'))
    events=[]
    store=SimpleNamespace(latest=lambda _: {'bundle_id':'tx'},event=lambda *a:events.append(a))
    w=worker.StampRecoveryWorker(Settings(network='testnet11',protocol_fee_funding_enabled=True),object(),store)
    await w.tick();assert events==[('tx','confirmed')]

@pytest.mark.asyncio
async def test_worker_failures_back_off_without_changing_saved_authorization(monkeypatch):
    ledger=SimpleNamespace(all_enrollments=lambda:{'v':{'status':'stamp_pending'}},get_stamp_attempt=lambda _:{'bundle_hex':'aa'})
    monkeypatch.setattr(worker,'get_credential_ledger',lambda _:ledger)
    monkeypatch.setattr(worker.enrollment,'_sync_chia_stamp',lambda *_:SimpleNamespace(status='stamp_pending'))
    recovery=AsyncMock(side_effect=ValueError('canonical event changed'));monkeypatch.setattr(worker,'recover_saved_stamp',recovery)
    w=worker.StampRecoveryWorker(Settings(network='testnet11',protocol_fee_funding_enabled=True),object(),SimpleNamespace(attempt_count=lambda _:0))
    await w.tick();assert w.failures['v']==1
    await w.tick();assert recovery.await_count==1


def test_worker_rejects_mainnet():
    with pytest.raises(ValueError,match='Testnet11'):
        worker.StampRecoveryWorker(Settings(network='mainnet',protocol_fee_funding_enabled=True),object(),object())
