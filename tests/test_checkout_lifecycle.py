"""Restart/flood and actual private-signature lifecycle fixtures, never live funds."""
import asyncio
import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi import HTTPException

from solslot_api import checkout_lifecycle as lifecycle, payment_start, native_purchases
from solslot_api.checkout_lifecycle import CheckoutLifecycleWorker, enqueue_candidate, lifecycle_activation
from solslot_api.inventory_extension_store import canonical
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_api.payment_start import PaymentStartClaim, adopt_payment_start
from solslot_api.validator_app import create_validator_app
from solslot_api.validator_quorum import ValidatorQuorumError
from tests.test_checkout_terminals import setup, delivered_case, admission
from tests.test_inventory_checkout_coordinator import coordinator, arm
from tests.test_inventory_payment_holds import paid, refunded, returned, close
from tests.test_inventory_extensions import advance, confirm
from tests.test_single_external_delivery_context import hx


def activate(c):
    hold, ext = c.genesis['inventoryPaymentHolds'], c.genesis['inventoryExtension']
    value = dict(schema='solslot.checkout-lifecycle.v1', environment='staging-alpha', network='testnet11',
        deploymentId=hold['deploymentId'], sourceShas=hold['sourceShas'], adapterVersion=1,
        paymentHoldReleaseIdentity=hold['releaseIdentity'], extensionReleaseIdentity=ext['releaseIdentity'],
        stripeAccountId=hold['stripeAccountId'], stripeMode='test', workerLeaseSeconds=60,
        advanceDeadlineSeconds=45, recoveryLane='independent', achReviewSeconds=10*86400)
    value['releaseIdentity'] = hashlib.sha256(canonical(value).encode()).hexdigest()
    value['reviewEvidenceSha256'] = 'bc'*32
    c.genesis['checkoutLifecycle'] = value
    c.settings.checkout_lifecycle_worker_enabled = True
    c.settings.protocol_fee_funding_enabled = True
    assert lifecycle_activation(c.genesis, 'staging-alpha') == value


def worker(c, authorize=lambda: None):
    return CheckoutLifecycleWorker(store=c.purchases, presales=c.presales, settings=c.settings, node=c.node,
        submitter=c.submitter, load_artifact=lambda:copy.deepcopy(c.genesis), authorize=authorize)


def enqueue(c, **changes):
    enqueue_candidate(store=c.purchases, settings=c.settings, purchase_id=hx(c.purchase.purchase_id),
        payment=dict(c.payment, **changes), load_artifact=lambda:copy.deepcopy(c.genesis))


async def observation_http(c, monkeypatch):
    # Restore the real collector: extension_case installs an in-process signer
    # helper for older tests; here exercise the new private HTTP route and BLS.
    from solslot_api.validator_quorum import _collect_inventory_quorum
    apps = [create_validator_app(settings=s, ledger=l) for s,l in zip(c.signers,c.ledgers,strict=True)]
    transports = [httpx.ASGITransport(app=a) for a in apps]
    async def dispatch(request):
        index = int(request.url.host[-1])
        if index in c.offline:
            return httpx.Response(503, json={'detail':'isolated unavailable signer'})
        return await transports[index].handle_async_request(request)
    async def collect(settings, claim):
        async with httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as client:
            return await _collect_inventory_quorum(settings, claim, '/v1/payment-start/observe', client=client)
    monkeypatch.setattr(payment_start, 'collect_payment_start_quorum', collect)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem', ['event', 'account', 'amount', 'partial_quorum'])
async def test_bad_start_never_pins_extension_and_corrected_evidence_recovers(tmp_path, monkeypatch, problem):
    c = await coordinator(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c); await observation_http(c, monkeypatch)
        original = copy.deepcopy(c.event)
        if problem == 'event': c.event['data']['object']['id'] = 'pi_other'
        elif problem == 'account': c.account = 'acct_other'
        elif problem == 'amount': c.intent['amount'] += 1
        else: c.offline.add(1)
        with pytest.raises(ValidatorQuorumError): await advance(c)
        pid = hx(c.purchase.purchase_id)
        assert c.purchases.payment_start(pid) is None
        assert c.purchases.pending_inventory_extension(pid) is None
        assert not c.funded and not c.extension_dispatches and admission(c) == 'SIGNING'
        c.event = original; c.account = 'acct_test123'; c.intent['amount'] = c.purchase.rail_amount; c.offline = {2}
        assert (await advance(c))['extensionState'] == 'SUBMITTED'
        retained = c.purchases.payment_start(pid)
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        assert c.purchases.payment_start(pid) == retained
        claim = PaymentStartClaim.model_validate(retained['claim'])
        from chia_rs import AugSchemeMPL, G2Element
        signature = G2Element.from_bytes(bytes.fromhex(retained['receipt']['signature'][2:]))
        extension = c.purchases.pending_inventory_extension(pid)
        from solslot_api.inventory_extension_claims import InventoryExtensionClaim
        keys = [c.keys[i].get_g1() for i in retained['receipt']['signerIndices']]
        assert not AugSchemeMPL.aggregate_verify(keys, [InventoryExtensionClaim.model_validate(extension['claim']).signature_message()]*2, signature)
    finally: close(c)


@pytest.mark.asyncio
async def test_automatic_renewal_restart_confirm_then_paid_terminal_capacity(tmp_path, monkeypatch):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c); enqueue(c)
        w = worker(c)
        assert await w.reconcile_once('renewal')
        pid = hx(c.purchase.purchase_id)
        assert c.purchases.pending_inventory_extension(pid)['state'] == 'SUBMITTED'
        assert admission(c) == 'SIGNING' and len(c.funded) == 1
        confirm(c); c.clock[0] += 31
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        assert await worker(c).reconcile_once('renewal')
        assert len(c.purchases.get(pid).inventory_extension_receipts) == 1 and len(c.funded) == 1
        assert await worker(c).reconcile_once('terminal')
        assert admission(c) == 'SIGNING'
    finally: close(c)
    # A separately prepared actual current-voucher redemption is already absent
    # from pending-redemption lists. Startup backfill still observes and closes it.
    c, _ = await delivered_case(tmp_path/'paid', monkeypatch)
    try:
        activate(c); c.purchases = PaymentPurchaseStore(c.purchases.path)
        assert await worker(c).reconcile_once('terminal')
        assert admission(c) == 'CLOSED'
        assert c.purchases.checkout_terminal(hx(c.purchase.purchase_id))['kind'] == 'DELIVERED'
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('partial', [False, True])
async def test_terminal_lane_survives_busy_renewal_paused_writes_and_restart(tmp_path, monkeypatch, partial):
    c = await setup(tmp_path, monkeypatch)
    try:
        if partial:
            c.offline.add(1)
            with pytest.raises(ValidatorQuorumError): await arm(c)
            c.offline.remove(1)
        else: await arm(c)
        activate(c)
        c.purchases.claim_checkout_job('renewal', owner='crashed-worker', now=c.clock[0])
        c.intent['status'] = 'canceled'; returned(c)
        def paused(): raise HTTPException(status_code=503, detail='paused')
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        assert await worker(c, paused).reconcile_once('terminal')
        assert admission(c) == 'CLOSED' and not c.funded and not c.extension_dispatches
    finally: close(c)


@pytest.mark.asyncio
async def test_flood_is_one_job_pair_and_cross_process_leases_are_fair(tmp_path, monkeypatch):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c)
        for _ in range(200): enqueue(c)
        pid = hx(c.purchase.purchase_id)
        assert len(c.purchases.checkout_job_status(pid)) == 2
        stores = [PaymentPurchaseStore(c.purchases.path) for _ in range(16)]
        with ThreadPoolExecutor(max_workers=16) as pool:
            claimed = list(pool.map(lambda pair: pair[1].claim_checkout_job('renewal', owner=str(pair[0]), now=c.clock[0]), enumerate(stores)))
        assert sum(bool(x and not x.get('busy')) for x in claimed) == 1
        assert c.purchases.claim_checkout_job('terminal', owner='recovery', now=c.clock[0])['purchase_id'] == pid
        c.clock[0] += 61
        assert c.purchases.claim_checkout_job('renewal', owner='restart', now=c.clock[0])['purchase_id'] == pid
        c.purchases.finish_checkout_job(pid,'renewal',owner='restart',now=c.clock[0],status='TIMED_OUT')
        prior = c.purchases.checkout_job_status(pid)
        for _ in range(100): enqueue(c)
        assert c.purchases.checkout_job_status(pid) == prior
        assert c.purchases.claim_checkout_job('renewal',owner='spam',now=c.clock[0]) is None
    finally: close(c)


@pytest.mark.asyncio
async def test_interrupted_advance_retains_anchor_and_clears_only_owned_lease(tmp_path, monkeypatch):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c); enqueue(c)
        w = worker(c); entered = asyncio.Event()
        async def stalled(*args): entered.set(); await asyncio.Event().wait()
        monkeypatch.setattr(w,'advance',stalled)
        task = asyncio.create_task(w.reconcile_once('renewal')); await entered.wait(); task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert c.purchases.checkout_job_status(hx(c.purchase.purchase_id))[0]['status'] == 'INTERRUPTED'
        assert admission(c) == 'SIGNING' and c.purchases.payment_candidate(hx(c.purchase.purchase_id))
        assert await worker(c).reconcile_once('terminal')
        c.clock[0] += 31
        assert await worker(c).reconcile_once('renewal')
        assert len(c.funded) == 1
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem', ['environment','source','adapter','review','network','disabled'])
async def test_mismatched_lifecycle_does_not_queue_or_dispatch(tmp_path, monkeypatch, problem):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c)
        if problem == 'environment': c.settings.runtime_environment = 'production'
        elif problem == 'source': c.genesis['checkoutLifecycle']['sourceShas'] = dict(c.genesis['sourceShas'], api='ab'*20)
        elif problem == 'adapter': c.genesis['checkoutLifecycle']['adapterVersion'] = 2
        elif problem == 'review': c.genesis['checkoutLifecycle']['reviewEvidenceSha256'] = '0'*64
        elif problem == 'network': c.settings.network = 'mainnet'
        else: c.settings.checkout_lifecycle_worker_enabled = False
        with pytest.raises((HTTPException, ValueError)): enqueue(c)
        assert c.purchases.payment_candidate(hx(c.purchase.purchase_id)) is None
        assert not c.funded and admission(c) == 'SIGNING'
    finally: close(c)


@pytest.mark.asyncio
async def test_service_auth_and_ten_day_ach_is_review_not_release(tmp_path, monkeypatch):
    c = await coordinator(tmp_path, monkeypatch, 'us_bank_account')
    try:
        await arm(c); paid(c); activate(c)
        payload = native_purchases.PaymentStartCandidateRequest(purchaseId=hx(c.purchase.purchase_id),
            paymentIntentId=c.payment['payment_intent_id'], paymentEventId=c.payment['payment_event_id'],
            paymentStartedAt=c.payment['payment_started_at'], paymentMethod='us_bank_account')
        with pytest.raises(HTTPException) as exc: await native_purchases.observe_checkout_payment(payload,c.settings,None)
        assert exc.value.status_code == 401
        result = await native_purchases.observe_checkout_payment(payload,c.settings,'Bearer synthetic-extension-service-token')
        assert result['observationQueued'] and not result['independentlyVerified']
        await adopt_payment_start(store=c.purchases,settings=c.settings,purchase_id=hx(c.purchase.purchase_id),
            payment=c.payment,load_artifact=lambda:copy.deepcopy(c.genesis))
        c.clock[0] = c.payment['payment_started_at'] + 10*86400
        assert await worker(c).reconcile_once('renewal')
        assert c.purchases.checkout_job_status(hx(c.purchase.purchase_id))[0]['status'] == 'REVIEW_REQUIRED'
        assert admission(c) == 'SIGNING' and not c.funded
    finally: close(c)


@pytest.mark.asyncio
async def test_deadline_is_inside_lease_and_health_requires_fresh_bound_receipts(tmp_path, monkeypatch):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c); enqueue(c)
        w = worker(c)
        real_timeout = asyncio.timeout
        def fast_timeout(seconds):
            assert seconds == 45
            return real_timeout(0.01)
        async def stalled(*_): await asyncio.Event().wait()
        monkeypatch.setattr(w,'advance',stalled)
        with monkeypatch.context() as patch:
            patch.setattr(lifecycle.asyncio,'timeout',fast_timeout)
            assert await w.reconcile_once('renewal')
        pid = hx(c.purchase.purchase_id)
        assert c.purchases.checkout_job_status(pid)[0]['status'] == 'TIMED_OUT'
        assert admission(c) == 'SIGNING' and not c.funded
        with pytest.raises(HTTPException) as exc: await native_purchases.checkout_lifecycle_health(c.settings,None)
        assert exc.value.status_code == 401
        token = 'Bearer synthetic-extension-service-token'
        assert not (await native_purchases.checkout_lifecycle_health(c.settings,token))['healthy']
        c.clock[0] += 31
        assert await worker(c).reconcile_once('renewal')
        assert await worker(c).reconcile_once('terminal')
        assert (await native_purchases.checkout_lifecycle_health(c.settings,token))['healthy']
        c.clock[0] += 91
        assert not (await native_purchases.checkout_lifecycle_health(c.settings,token))['healthy']
    finally: close(c)


@pytest.mark.asyncio
async def test_old_hold_backfill_and_failed_job_do_not_starve_another_purchase(tmp_path, monkeypatch):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); activate(c)
        pid = hx(c.purchase.purchase_id)
        with c.purchases._connect() as db:
            db.execute('DELETE FROM payment_checkout_jobs')
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        c.purchases.seed_checkout_jobs()
        assert len(c.purchases.checkout_job_status(pid)) == 2
        first = c.purchases.claim_checkout_job('renewal',owner='failed',now=c.clock[0])
        assert first['purchase_id'] == pid
        other = '0x'+'ff'*32
        with c.purchases._connect() as db:
            db.execute("INSERT INTO payment_checkout_jobs(purchase_id,lane) VALUES (?,'renewal')",(other,))
        c.purchases.finish_checkout_job(pid,'renewal',owner='failed',now=c.clock[0],status='UNAVAILABLE')
        assert c.purchases.claim_checkout_job('renewal',owner='next',now=c.clock[0])['purchase_id'] == other
    finally: close(c)


@pytest.mark.asyncio
async def test_observation_only_keeps_payment_and_does_not_pin_a_spend(tmp_path, monkeypatch):
    c = await setup(tmp_path, monkeypatch)
    try:
        await arm(c); paid(c); activate(c); enqueue(c)
        c.settings.protocol_fee_funding_enabled = False
        w = worker(c); w.submitter = None
        assert await w.reconcile_once('renewal')
        pid = hx(c.purchase.purchase_id)
        assert c.purchases.payment_start(pid) is not None
        assert c.purchases.pending_inventory_extension(pid) is None
        assert c.purchases.checkout_job_status(pid)[0]['status'] == 'PAUSED'
        assert admission(c) == 'SIGNING' and not c.funded
    finally: close(c)
