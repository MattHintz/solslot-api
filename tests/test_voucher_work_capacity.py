"""Local signed execution and real SQLite scheduling; no live provider outcomes."""
import asyncio
from dataclasses import replace
import time

import pytest
from chia.types.blockchain_format.coin import Coin
from chia_rs import SpendBundle
from chia_rs.sized_ints import uint64

from solslot_api.config import Settings
from solslot_api.faucet import Faucet
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_api.presale_endpoints import PresaleStore
from solslot_api.voucher_issuance_worker import VoucherIssuanceWorker, VoucherIssuanceWorkerConfig
from tests.test_presale_endpoints import terms, create_series, ingest, FakeCoinset, b32, coin_record
from tests.test_current_stripe_voucher_delivery import voucher_case, confirm_records


def pending(tmp_path, *, second=False):
    store = PresaleStore(str(tmp_path/'presales.db'))
    current = terms(int(time.time()))
    create_series(store, current)
    ingest(store, current)
    if second:
        ingest(store, current, deed_index=1, nonce=51, global_payment_id=61, height=101)
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11')
    node = FakeCoinset(Coin(b32(110), faucet.address_puzzle_hash, uint64(20)))
    worker = VoucherIssuanceWorker(settings=Settings(runtime_environment='test', network='testnet11'),
        faucet=faucet, coinset=node, presales=store, purchases=PaymentPurchaseStore(str(tmp_path/'payments.db')),
        config=VoucherIssuanceWorkerConfig(enabled=True, operation_timeout_seconds=.1))
    return worker, store, current, node


@pytest.mark.asyncio
async def test_failed_first_row_rotates_and_backoff_survives_restart(tmp_path, monkeypatch):
    worker, store, current, node = pending(tmp_path, second=True)
    visited = []
    async def advance(series, voucher):
        visited.append(voucher['serial'])
        if voucher['serial'] == 0:
            raise RuntimeError('isolated failing first payer')
        return dict(termsHash=series['termsHash'], serial=voucher['serial'], status='WAITING')
    monkeypatch.setattr(worker, '_advance', advance)
    assert (await worker._run_lane('issuance'))['status'] == 'ERROR'
    worker.presales = PresaleStore(str(tmp_path/'presales.db'))
    assert (await worker._run_lane('issuance'))['serial'] == 1
    assert (await worker._run_lane('issuance'))['serial'] == 1
    assert visited == [0, 1, 1]
    assert store.voucher(current['termsHash'], 0)['state'] == 'PENDING_ISSUANCE'


@pytest.mark.asyncio
async def test_stalled_issuance_does_not_stop_independent_terminal_lane(tmp_path, monkeypatch):
    worker, store, current, node = pending(tmp_path)
    series = dict(store._conn.execute('SELECT * FROM presale_series_v2').fetchone())
    series.update(terms_hash='0x'+'fe'*32, series_singleton_id='0x'+'fd'*32, collection_id='0x'+'fc'*32,
        state='PRESALE', phase_bundle_id='0x'+'fb'*32, phase_confirmed_height=None)
    store._conn.execute('INSERT INTO presale_series_v2('+','.join(series)+') VALUES ('+','.join('?' for _ in series)+')', tuple(series.values()))
    entered = asyncio.Event(); terminal = asyncio.Event()
    async def stalled(*args):
        entered.set(); await asyncio.Event().wait()
    async def observed(*args):
        terminal.set(); return True
    monkeypatch.setattr(worker, '_advance', stalled)
    monkeypatch.setattr(worker, '_confirm_phase_if_ready', observed)
    issuance = asyncio.create_task(worker._run_lane('issuance'))
    await asyncio.wait_for(entered.wait(), 1)
    result = await asyncio.wait_for(worker._run_lane('phase'), .08)
    assert terminal.is_set() and not issuance.done() and result['status'] == 'PHASE_CONFIRMED'
    assert (await issuance)['status'] == 'TIMED_OUT'
    assert store._conn.execute("SELECT status FROM voucher_worker_attempts WHERE lane='issuance'").fetchone()[0] == 'TIMED_OUT'


@pytest.mark.asyncio
async def test_large_history_uses_bounded_index_work_and_cross_worker_series_lease(tmp_path):
    worker, store, current, node = pending(tmp_path)
    row = dict(store._conn.execute('SELECT * FROM voucher_records_v2').fetchone())
    query = 'INSERT INTO voucher_records_v2('+','.join(row)+') VALUES ('+','.join('?' for _ in row)+')'
    with store.txn() as cur:
        for i in range(1, 50001):
            historic = dict(row, serial=i, state='REDEEMED')
            for key in ('deed_launcher_id','purchase_id','global_payment_id','commitment_hash'):
                historic[key] = f'0x{i:064x}'
            cur.execute(query, tuple(historic.values()))
    budget = [0]
    def progress():
        budget[0] += 100
        return int(budget[0] > 6000)
    store._conn.set_progress_handler(progress, 100)
    first = store.claim_voucher_work('issuance', 'first', 1000)
    store._conn.set_progress_handler(None, 0)
    assert first['serial'] == 0 and budget[0] <= 6000
    other = PresaleStore(str(tmp_path/'presales.db'))
    assert other.claim_voucher_work('issuance', 'other', 1001) is None
    later = other.claim_voucher_work('issuance', 'later', 1061)
    assert later['owner'] == 'later'
    store.finish_voucher_work(first, 1062, 'ERROR')
    assert other.claim_voucher_work('issuance', 'third', 1063) is None
    # Exercise hydration through the actual worker, not only queue selection.
    async def benign(series, voucher):
        assert 'vouchers' not in series
        return dict(termsHash=series['termsHash'], serial=voucher['serial'], status='WAITING')
    worker._advance=benign
    budget[0]=0
    store._conn.set_progress_handler(progress, 100)
    result=await worker._run_lane('issuance')
    store._conn.set_progress_handler(None, 0)
    assert result['status']=='WAITING' and budget[0]<=6000



@pytest.mark.asyncio
async def test_timeout_retains_one_signed_funding_bundle_and_reserves_coin(tmp_path, monkeypatch):
    worker, store, current, node = pending(tmp_path, second=True)
    sent = []
    async def lost(raw):
        sent.append(raw)
        assert store.pending_voucher_execution(current['termsHash'], 0)['spendBundle'] == raw
        await asyncio.Event().wait()
    monkeypatch.setattr(node, 'push_tx', lost)
    result = await worker._run_lane('issuance')
    assert result['status'] == 'TIMED_OUT'
    retained = store.pending_voucher_execution(current['termsHash'], 0)
    assert len(sent) == 1
    assert store.pending_voucher_funding_coin_ids() == {'0x'+node.faucet_coin.name().hex()}
    assert store.claim_voucher_work('issuance', 'second', time.time()+16) is None
    assert store.claim_voucher_work('issuance', 'second', time.time()+16)['serial'] == 0
    worker.presales = PresaleStore(str(tmp_path/'presales.db'))
    async def accepted(raw):
        sent.append(raw); return {'success': True, 'status': 'SUCCESS'}
    monkeypatch.setattr(node, 'push_tx', accepted)
    series = store.get(current['termsHash']); voucher = store.voucher(current['termsHash'], 0)
    await worker._resume_retained_execution(series, voucher, retained)
    assert len(sent) == 2 and sent[0] == sent[1]
    bundle = SpendBundle.from_json_dict(sent[0])
    launcher = next(coin for coin in bundle.additions() if coin.amount == 2)
    node.records['0x'+launcher.name().hex()] = coin_record(launcher)
    assert await worker._resume_retained_execution(series, voucher, retained) is None
    assert not store.pending_voucher_funding_coin_ids()
    with pytest.raises(ValueError, match='cannot be replaced'):
        store.retain_voucher_execution(current['termsHash'], 0, dict(retained, bindings={}))


@pytest.mark.asyncio
async def test_stripe_timeout_resumes_exact_signed_delivery_and_destination(tmp_path, monkeypatch):
    c = voucher_case(tmp_path, monkeypatch)
    c.voucher_worker.config = replace(c.voucher_worker.config, operation_timeout_seconds=.1)
    original = c.voucher_worker.exact_executor.dispatch
    async def lost(request, prepared):
        await original(request, prepared)
        await asyncio.Event().wait()
    c.voucher_worker.exact_executor.dispatch = lost
    result = await c.voucher_worker._run_lane('stripe_redemption')
    assert result['status'] == 'TIMED_OUT'
    assert len(c.prepared_bundles) == len(c.dispatched) == 1
    c.voucher_worker.presales = PresaleStore(c.presale_path)
    c.voucher_worker.exact_executor = None
    c.clock[0] += 200000
    confirm_records(c, c.dispatched[0])
    results = await c.voucher_worker.reconcile_once()
    assert results == [dict(termsHash=c.current['termsHash'], serial=0, status='STRIPE_DEED_DELIVERED')]
    assert len(c.prepared_bundles) == len(c.dispatched) == 1
    saved = c.voucher_worker.presales.voucher(c.current['termsHash'], 0)
    assert saved['state'] == 'REDEEMED' and saved['deliveryOutputCoinId'] == saved['redemptionDeedOutputCoinId']


@pytest.mark.asyncio
async def test_pause_before_push_retains_execution_and_observes_confirmed_funding(tmp_path, monkeypatch):
    worker, store, current, node = pending(tmp_path)
    async def paused_records(*args, **kwargs):
        worker.config=replace(worker.config, enabled=False)
        return [coin_record(node.faucet_coin)]
    monkeypatch.setattr(node, 'get_coin_records_by_puzzle_hash', paused_records)
    result=await worker._run_lane('issuance')
    assert result['status']=='ERROR' and not node.pushed
    saved=store.pending_voucher_execution(current['termsHash'], 0)
    assert saved is not None
    bundle=SpendBundle.from_json_dict(saved['spendBundle'])
    launcher=next(coin for coin in bundle.additions() if coin.amount==2)
    # Synthetic canonical observation is permitted while dispatch is paused.
    node.records['0x'+launcher.name().hex()]=coin_record(launcher)
    assert await worker._resume_retained_execution(store.get(current['termsHash']), store.voucher(current['termsHash'],0), saved) is None
    assert not node.pushed and not store.pending_voucher_funding_coin_ids()
