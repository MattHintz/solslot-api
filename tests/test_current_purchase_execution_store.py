"""Real SQLite execution recovery; all spends and confirmations are synthetic."""
from concurrent.futures import ThreadPoolExecutor

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
import pytest

from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.protocol_submission import PreparedProtocolBundle
from tests.test_current_purchase_store import BROWSER, delivery
from tests.test_generation_customer_purchase_reservation_claim import body


def bundle(n=1):
    puzzle=Program.to(1)
    coin=Coin(bytes32(bytes([n])*32),puzzle.get_tree_hash(),uint64(100))
    return SpendBundle([make_spend(coin,puzzle,Program.to([]))],G2Element())


@pytest.fixture
def execution(tmp_path):
    claim=CurrentReservationClaim.model_validate(body())
    store=CurrentPurchaseExecutionStore(tmp_path/'payment_purchases_v2.db',claim.generation_id)
    store.bind_execution_policy(claim.issuer_policy_hash,1,10)
    identity=store.save_review(claim,browser_hash=BROWSER,request_key='buy-one',now=100)
    protocol=bundle()
    def prepare(current=store):
        return current.prepare_execution(identity,'RESERVATION',protocol,browser_hash=BROWSER,
            claim_hash=claim.digest(),fee_cap=10,expires_at=200,now=110)
    return store,claim,identity,protocol,prepare


def test_concurrent_duplicate_preparation_survives_restart(execution):
    store,claim,identity,protocol,prepare=execution
    def retry(_):
        return prepare(CurrentPurchaseExecutionStore(store.path,store.generation_id))
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses=list(pool.map(retry,range(8)))
    assert len({s['originalBundleId'] for s in statuses})==1
    reopened=CurrentPurchaseExecutionStore(store.path,store.generation_id)
    assert bytes(reopened.execution_bundle(identity,'RESERVATION',browser_hash=BROWSER))==bytes(protocol)
    with reopened._connect() as db:
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0]==1


def test_lost_response_recovers_exact_funded_bytes_after_expiry(execution):
    store,_,identity,protocol,prepare=execution;prepare()
    funded=PreparedProtocolBundle(protocol,5,'0x'+'03'*32)
    store.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=120)
    reopened=CurrentPurchaseExecutionStore(store.path,store.generation_id)
    assert reopened.execution_status(identity,'RESERVATION',browser_hash=BROWSER)['stage']=='RECONCILING'
    assert reopened.execution_funding(identity,'RESERVATION',browser_hash=BROWSER)==funded.to_json()
    reopened.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=300)
    status=reopened.observe_execution(identity,'RESERVATION',browser_hash=BROWSER,
        transaction_id=funded.spend_bundle_id,status='CONFIRMED',confirmed_height=123,now=300)
    assert status['stage']=='CONFIRMED'
    assert reopened.observe_execution(identity,'RESERVATION',browser_hash=BROWSER,
        transaction_id=funded.spend_bundle_id,status='MEMPOOL',now=301)['stage']=='CONFIRMED'


def test_late_funding_checkpoint_preserves_bytes_without_authorizing_a_push(execution):
    store,_,identity,protocol,prepare=execution;prepare()
    funded=PreparedProtocolBundle(protocol,5,'fee')
    store.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=201)
    assert store.execution_funding(identity,'RESERVATION',browser_hash=BROWSER)==funded.to_json()
    assert store.execution_status(identity,'RESERVATION',browser_hash=BROWSER)['stage']=='RECONCILING'


@pytest.mark.parametrize('field,value', [('fee_cap',11),('expires_at',201),('claim_hash','0x'+'ff'*32)])
def test_review_retry_cannot_reprice_or_replace_claim(execution,field,value):
    store,claim,identity,protocol,prepare=execution;prepare()
    args=dict(browser_hash=BROWSER,claim_hash=claim.digest(),fee_cap=10,expires_at=200,now=111)
    args[field]=value
    with pytest.raises(ValueError):store.prepare_execution(identity,'RESERVATION',protocol,**args)


def test_fee_cap_protocol_bytes_and_saved_funding_are_immutable(execution):
    store,_,identity,protocol,prepare=execution;prepare()
    for candidate in (PreparedProtocolBundle(protocol,11,'fee'),PreparedProtocolBundle(bundle(2),5,'fee'),
                      PreparedProtocolBundle(protocol,5,'fee',backing_mojos=1)):
        with pytest.raises(ValueError,match='PROTOCOL_OR_CAP'):
            store.save_execution_funding(identity,'RESERVATION',candidate,browser_hash=BROWSER,now=120)
    original=PreparedProtocolBundle(protocol,5,'fee')
    store.save_execution_funding(identity,'RESERVATION',original,browser_hash=BROWSER,now=120)
    with pytest.raises(ValueError,match='FUNDED_BYTES_IMMUTABLE'):
        store.save_execution_funding(identity,'RESERVATION',PreparedProtocolBundle(protocol,6,'other'),browser_hash=BROWSER,now=121)


def test_delivery_requires_saved_wallet_work_and_confirmed_reservation(execution):
    store,claim,identity,protocol,prepare=execution
    signed=delivery(claim)
    args=dict(browser_hash=BROWSER,claim_hash=signed.digest(),fee_cap=10,expires_at=200,now=120)
    with pytest.raises(ValueError,match='SAVED_BUYER_REQUIRED'):
        store.prepare_execution(identity,'DELIVERY',bundle(2),**args)
    store.save_delivery(identity,signed,browser_hash=BROWSER,now=115)
    with pytest.raises(ValueError,match='CONFIRMED_RESERVATION_REQUIRED'):
        store.prepare_execution(identity,'DELIVERY',bundle(2),**args)
    prepare();funded=PreparedProtocolBundle(protocol,5,'fee')
    store.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=120)
    with pytest.raises(ValueError,match='EXACT_SAVED_TRANSACTION_REQUIRED'):
        store.observe_execution(identity,'RESERVATION',browser_hash=BROWSER,transaction_id='0x'+'ff'*32,status='CONFIRMED',confirmed_height=1,now=121)
    store.observe_execution(identity,'RESERVATION',browser_hash=BROWSER,transaction_id=funded.spend_bundle_id,status='CONFIRMED',confirmed_height=1,now=121)
    assert store.prepare_execution(identity,'DELIVERY',bundle(2),**args)['stage']=='PREPARED'


def test_status_reads_never_create_work_or_accept_another_browser(execution):
    store,_,identity,_,prepare=execution;prepare()
    with store._connect() as db:before=list(db.execute('SELECT * FROM current_purchase_executions'))
    for _ in range(5):store.execution_status(identity,'RESERVATION',browser_hash=BROWSER)
    with store._connect() as db:after=list(db.execute('SELECT * FROM current_purchase_executions'))
    assert [tuple(r) for r in before]==[tuple(r) for r in after]
    for read in (store.execution_status,store.execution_funding,store.execution_bundle):
        with pytest.raises(ValueError):read(identity,'RESERVATION',browser_hash='cd'*32)


def test_policy_capacity_and_fee_cap_cannot_be_reset_by_new_request(execution):
    store,claim,identity,_,prepare=execution;prepare()
    with pytest.raises(ValueError,match='POLICY_LIMIT_IMMUTABLE'):
        store.bind_execution_policy(claim.issuer_policy_hash,2,10)
    changed=claim.model_copy(update={'available_coin_id':'0x'+'08'*32})
    second=store.save_review(changed,browser_hash=BROWSER,request_key='another-click',now=111)
    with pytest.raises(ValueError,match='POLICY_CAPACITY_EXHAUSTED'):
        store.prepare_execution(second,'RESERVATION',bundle(2),browser_hash=BROWSER,
            claim_hash=changed.digest(),fee_cap=10,expires_at=200,now=112)

def test_timeout_requires_confirmed_reservation_without_a_payer_offer(execution):
    store,claim,identity,protocol,prepare=execution
    args=dict(browser_hash=BROWSER,claim_hash=claim.digest(),fee_cap=10,expires_at=400,now=210)
    with pytest.raises(ValueError,match='CONFIRMED_RESERVATION_REQUIRED'):
        store.prepare_execution(identity,'RELEASE',bundle(2),**args)
    prepare();funded=PreparedProtocolBundle(protocol,5,'fee')
    store.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=120)
    store.observe_execution(identity,'RESERVATION',browser_hash=BROWSER,transaction_id=funded.spend_bundle_id,
        status='CONFIRMED',confirmed_height=123,now=121)
    assert store.prepare_execution(identity,'RELEASE',bundle(2),**args)['stage']=='PREPARED'
    assert store.saved(identity,browser_hash=BROWSER)['deliveryClaim'] is None

def test_old_two_phase_schema_migration_preserves_exact_funded_work(execution):
    store,_,identity,protocol,prepare=execution;prepare()
    funded=PreparedProtocolBundle(protocol,5,'fee')
    store.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=120)
    with store._connect()as db:
        sql=db.execute("SELECT sql FROM sqlite_master WHERE name='current_purchase_executions'").fetchone()[0]
        db.execute('BEGIN IMMEDIATE')
        db.execute(sql.replace('current_purchase_executions','old_executions',1).replace(
            "'RESERVATION','DELIVERY','RELEASE'","'RESERVATION','DELIVERY'"))
        db.execute('INSERT INTO old_executions SELECT * FROM current_purchase_executions')
        before=[tuple(r)for r in db.execute('SELECT * FROM current_purchase_executions')]
        db.execute('DROP TABLE current_purchase_executions')
        db.execute('ALTER TABLE old_executions RENAME TO current_purchase_executions');db.commit()
    for _ in range(2):
        store=CurrentPurchaseExecutionStore(store.path,store.generation_id)
        with store._connect()as db:
            assert [tuple(r)for r in db.execute('SELECT * FROM current_purchase_executions')]==before
            assert not db.execute('PRAGMA foreign_key_check').fetchall()
        assert store.execution_funding(identity,'RESERVATION',browser_hash=BROWSER)==funded.to_json()
