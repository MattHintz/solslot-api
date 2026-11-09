"""Durable explicit scalar/batch intent, independent of wallets or live networks."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1,purchase_batch_from_json,purchase_batch_to_json,purchase_artifact_to_json
from solslot_api.generation_customer_purchase_batch import CurrentReservationBatch
from solslot_api.generation_customer_purchase_batch_execution import request_reservation
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.generation_customer_purchase_worker import CurrentPurchaseWorker
from tests.test_current_purchase_execution_store import bundle
from tests.test_current_purchase_store import BROWSER
from tests.test_generation_customer_purchase_reservation_claim import body
from tests.test_native_purchases import _context


def another_batch(claim):
    original=purchase_batch_from_json(claim.purchase_batch)
    batch=build_purchase_batch_v1(batch_nonce=bytes32(b'o'*32),artifacts=original.artifacts)
    return CurrentReservationBatch(purchaseBatch=purchase_batch_to_json(batch),children=claim.children)


@pytest.fixture
def batch_queue(tmp_path):
    payment=AugSchemeMPL.key_gen(b'p'*32)
    validators=tuple(AugSchemeMPL.key_gen(bytes([i])*32)for i in (51,52,53))
    contexts=[_context(payment,validators,deed_parent_seed=i,now=100)[0]for i in (61,62,63)]
    batch=build_purchase_batch_v1(batch_nonce=bytes32(b'n'*32),artifacts=[c.purchase for c in contexts[:2]])
    children=tuple(CurrentReservationClaim.model_validate({**body(),
        'purchaseArtifact':purchase_artifact_to_json(a),'availableCoinId':'0x'+f'{i+10:02x}'*32})
        for i,a in enumerate(batch.artifacts))
    claim=CurrentReservationBatch(purchaseBatch=purchase_batch_to_json(batch),children=children)
    store=CurrentPurchaseExecutionStore(tmp_path/'queue.db',claim.generation_id)
    store.bind_execution_policy(claim.issuer_policy_hash,3,10)
    identity=store.save_review(claim,browser_hash=BROWSER,request_key='customer-batch',now=101)
    service=object.__new__(CurrentNativePurchaseExecution)
    service.settings=SimpleNamespace(network='testnet11');service.store=store;service.clock=lambda:110
    service.policy=SimpleNamespace(issued_at=100,expires_at=400,buyer_vault=batch.artifacts[0].vault_launcher_id,
        commitment=claim.issuer_policy_hash)
    return SimpleNamespace(store=store,claim=claim,identity=identity,service=service)


@pytest.fixture
def scalar_queue(batch_queue):
    q=batch_queue
    claim=q.claim.children[0]
    identity=q.store.save_review(claim,browser_hash=BROWSER,request_key='customer-scalar',now=102)
    q.service.fee_cap=10
    return SimpleNamespace(store=q.store,claim=claim,identity=identity,service=q.service)


def test_scalar_request_receipt_and_review_survive_lost_response_and_restart(scalar_queue):
    q=scalar_queue
    assert q.service.review(q.identity,browser_hash=BROWSER)['reservationRequested']is False
    reply=q.service.request_reservation(q.identity,browser_hash=BROWSER)
    assert reply=={'schema':'solslot.current-reservation-request.v1','intentId':q.identity,
        'generationId':q.claim.generation_id,'receivingVaultLauncherId':'0x'+bytes(q.service.policy.buyer_vault).hex(),
        'reservationClaimHash':q.claim.digest(),'quantity':1,'requestedAt':110}
    q.service.store=CurrentPurchaseExecutionStore(q.store.path,q.store.generation_id)
    q.service.clock=lambda:999
    assert q.service.request_reservation(q.identity,browser_hash=BROWSER)==reply
    review=q.service.review(q.identity,browser_hash=BROWSER)
    assert review['reservationRequested']is True and review['quoteExpired']is True
    with q.service.store._connect()as db:
        assert db.execute('SELECT count(*) FROM current_customer_reservation_requests').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0]==0
    with pytest.raises(ValueError,match='REVIEW_UNAVAILABLE'):
        q.service.request_reservation(q.identity,browser_hash='ef'*32)


def test_scalar_request_cannot_queue_under_changed_execution_policy(scalar_queue):
    q=scalar_queue;q.service.policy.commitment='0x'+'ee'*32
    with pytest.raises(ValueError,match='SAVED_POLICY_CHANGED'):
        q.service.request_reservation(q.identity,browser_hash=BROWSER)
    assert q.store.reservation_request(q.identity,browser_hash=BROWSER)is None


@pytest.mark.parametrize('now',[99,400,999])
def test_new_scalar_request_respects_policy_and_quote_expiry(scalar_queue,now):
    q=scalar_queue;q.service.clock=lambda:now
    with pytest.raises(ValueError,match='PURCHASE_WINDOW_CLOSED'):
        q.service.request_reservation(q.identity,browser_hash=BROWSER)
    assert q.store.reservation_request(q.identity,browser_hash=BROWSER)is None


def test_new_scalar_request_cannot_outlive_quote_with_longer_policy(scalar_queue):
    from solslot_api.generation_customer_purchase_batch import artifacts
    q=scalar_queue;expires=artifacts(q.claim)[0].quote_expires_at
    q.service.policy.expires_at=expires+100
    q.service.clock=lambda:expires
    with pytest.raises(ValueError,match='PURCHASE_WINDOW_CLOSED'):
        q.service.request_reservation(q.identity,browser_hash=BROWSER)
    with pytest.raises(ValueError,match='PURCHASE_WINDOW_CLOSED'):
        q.store.request_reservation(q.identity,browser_hash=BROWSER,now=expires)


def test_concurrent_scalar_retries_create_one_request(scalar_queue):
    q=scalar_queue
    def request(_):
        return CurrentPurchaseExecutionStore(q.store.path,q.store.generation_id).request_reservation(
            q.identity,browser_hash=BROWSER,now=110)
    with ThreadPoolExecutor(max_workers=4)as pool:
        assert list(pool.map(request,range(8)))==[110]*8
    with q.store._connect()as db:
        assert db.execute('SELECT count(*) FROM current_customer_reservation_requests').fetchone()[0]==1


def test_scalar_queue_and_prepared_work_count_once_against_shared_batch_capacity(scalar_queue,batch_queue):
    q=scalar_queue;b=batch_queue
    q.service.request_reservation(q.identity,browser_hash=BROWSER)
    q.store.prepare_execution(q.identity,'RESERVATION',bundle(),browser_hash=BROWSER,
        claim_hash=q.claim.digest(),fee_cap=10,expires_at=200,now=111)
    request_reservation(b.service,b.identity,BROWSER)
    extra=q.claim.model_copy(update={'available_coin_id':'0x'+'ee'*32})
    identity=q.store.save_review(extra,browser_hash=BROWSER,request_key='over-scalar-budget',now=112)
    with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):
        q.store.request_reservation(identity,browser_hash=BROWSER,now=113)


def test_concurrent_scalar_and_batch_cannot_overrun_remaining_capacity(scalar_queue,batch_queue):
    q=scalar_queue;b=batch_queue
    q.service.request_reservation(q.identity,browser_hash=BROWSER)
    extra=q.claim.model_copy(update={'available_coin_id':'0x'+'ee'*32})
    identity=q.store.save_review(extra,browser_hash='ef'*32,request_key='competing-scalar',now=112)
    def request(pair):
        try:
            current=CurrentPurchaseExecutionStore(q.store.path,q.store.generation_id)
            current.request_reservation(pair[0],browser_hash=pair[1],now=113)
            return 'accepted'
        except ValueError as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=2)as pool:
        results=list(pool.map(request,[(b.identity,BROWSER),(identity,'ef'*32)]))
    assert sorted(results)==['CURRENT_EXECUTION_POLICY_CAPACITY_EXHAUSTED','accepted']


@pytest.mark.asyncio
async def test_existing_worker_advances_explicit_scalar_queue_without_payer_or_issuer(scalar_queue):
    q=scalar_queue;events=[]
    async def no_issuer(_):raise AssertionError('No saved payer offer')
    worker=CurrentPurchaseWorker(q.service,issuer_sign=no_issuer,clock=lambda:110)
    assert worker._claim()==[]
    q.service.request_reservation(q.identity,browser_hash=BROWSER)
    def funding():events.append('funding')
    async def prepare(identity,*,browser_hash):
        events.append('prepare')
        return q.store.prepare_execution(identity,'RESERVATION',bundle(),browser_hash=browser_hash,
            claim_hash=q.claim.digest(),fee_cap=10,expires_at=200,now=111)
    async def reconcile(identity,phase,*,browser_hash):
        events.append('reconcile');return q.store.execution_status(identity,phase,browser_hash=browser_hash)
    async def dispatch(identity,phase,*,browser_hash):events.append('dispatch')
    q.service._funding_context=funding;q.service.prepare_reservation=prepare
    q.service.reconcile=reconcile;q.service.dispatch=dispatch
    result=await worker.tick()
    assert result['examined']==1 and result['errors']==0
    assert events==['funding','prepare']
    # The durable PREPARED checkpoint returns before a later dispatch cycle.
    # Dispatch still independently reconciles and validates its saved inputs.


@pytest.mark.asyncio
async def test_worker_closes_expired_unprepared_scalar_queue_without_signing(scalar_queue):
    q=scalar_queue
    async def no_issuer(_):raise AssertionError('No saved payer offer')
    q.service.request_reservation(q.identity,browser_hash=BROWSER)
    worker=CurrentPurchaseWorker(q.service,issuer_sign=no_issuer,clock=lambda:999)
    result=await worker.tick()
    assert result['examined']==1 and result['errors']==0
    with q.store._connect()as db:
        assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='CLOSED'
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0]==0


@pytest.mark.parametrize('queue_name',['batch_queue','scalar_queue'])
def test_read_only_reconnect_never_requests_a_reservation(request,queue_name):
    q=request.getfixturevalue(queue_name)
    for _ in range(3):
        assert q.store.reservation_request(q.identity,browser_hash=BROWSER)is None
        assert q.store.saved(q.identity,browser_hash=BROWSER)['deliveryClaim']is None
    with q.store._connect()as db:
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM current_customer_reservation_requests').fetchone()[0]==0


def test_one_explicit_request_survives_lost_response_and_restart(batch_queue):
    q=batch_queue
    reply=request_reservation(q.service,q.identity,BROWSER)
    assert reply=={'schema':'solslot.current-reservation-request.v1','intentId':q.identity,
        'generationId':q.claim.generation_id,'receivingVaultLauncherId':'0x'+bytes(q.service.policy.buyer_vault).hex(),
        'reservationClaimHash':q.claim.digest(),'quantity':2,'requestedAt':110}
    reopened=CurrentPurchaseExecutionStore(q.store.path,q.store.generation_id)
    assert reopened.reservation_request(q.identity,browser_hash=BROWSER)==110
    assert reopened.request_reservation(q.identity,browser_hash=BROWSER,now=999)==110
    with reopened._connect()as db:
        assert db.execute('SELECT count(*) FROM current_customer_reservation_requests').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0]==0
    with pytest.raises(ValueError):reopened.request_reservation(q.identity,browser_hash='cd'*32,now=111)


def test_queue_and_prepared_batch_count_deeds_once_and_preserve_scalar_capacity(batch_queue):
    q=batch_queue;q.store.request_reservation(q.identity,browser_hash=BROWSER,now=110)
    q.store.prepare_execution(q.identity,'RESERVATION',bundle(),browser_hash=BROWSER,
        claim_hash=q.claim.digest(),fee_cap=10,expires_at=200,now=111)
    single=q.claim.children[0].model_copy(update={'available_coin_id':'0x'+'ee'*32})
    identity=q.store.save_review(single,browser_hash=BROWSER,request_key='remaining-deed',now=112)
    q.store.prepare_execution(identity,'RESERVATION',bundle(2),browser_hash=BROWSER,
        claim_hash=single.digest(),fee_cap=10,expires_at=200,now=113)
    other=q.store.save_review(another_batch(q.claim),browser_hash='ef'*32,request_key='over-budget',now=114)
    with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):
        q.store.request_reservation(other,browser_hash='ef'*32,now=115)


def test_concurrent_batches_cannot_each_claim_the_same_remaining_deed_budget(batch_queue):
    q=batch_queue
    other=q.store.save_review(another_batch(q.claim),browser_hash='ef'*32,request_key='second-customer',now=102)
    def request(pair):
        try:
            current=CurrentPurchaseExecutionStore(q.store.path,q.store.generation_id)
            current.request_reservation(pair[0],browser_hash=pair[1],now=110)
            return 'accepted'
        except ValueError as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=2)as pool:
        results=list(pool.map(request,[(q.identity,BROWSER),(other,'ef'*32)]))
    assert sorted(results)==['CURRENT_EXECUTION_POLICY_CAPACITY_EXHAUSTED','accepted']


@pytest.mark.asyncio
@pytest.mark.parametrize('queue_name',['batch_queue','scalar_queue'])
async def test_worker_claims_only_explicit_customer_request_and_recovers_it(request,queue_name):
    q=request.getfixturevalue(queue_name)
    async def no_issuer(_):raise AssertionError('No saved payer offer')
    worker=CurrentPurchaseWorker(q.service,issuer_sign=no_issuer,clock=lambda:110)
    assert worker._claim()==[]
    q.store.request_reservation(q.identity,browser_hash=BROWSER,now=110)
    rows=worker._claim()
    assert len(rows)==1 and rows[0][:2]==(q.identity,BROWSER)
    restarted=CurrentPurchaseWorker(q.service,issuer_sign=no_issuer,clock=lambda:110)
    assert restarted._claim()==[]
    restarted.clock=lambda:110+worker.LEASE_SECONDS_PER_ACTION*worker.batch_size+6
    assert len(restarted._claim())==1
