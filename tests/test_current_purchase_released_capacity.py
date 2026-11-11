"""Unpaid release frees unit capacity, never fee authority or signed history."""
import pytest
from solslot_api.protocol_submission import PreparedProtocolBundle
from tests.test_current_purchase_execution_store import execution,bundle
from tests.test_current_purchase_store import BROWSER,delivery
from tests.test_current_purchase_batch_queue import batch_queue,another_batch


def released(execution,stage='CONFIRMED'):
 store,claim,identity,protocol,prepare=execution;prepare()
 funded=PreparedProtocolBundle(protocol,5,'reservation-fee')
 store.save_execution_funding(identity,'RESERVATION',funded,browser_hash=BROWSER,now=120)
 store.observe_execution(identity,'RESERVATION',browser_hash=BROWSER,transaction_id=funded.spend_bundle_id,
  status='CONFIRMED',confirmed_height=123,now=121)
 raw=bundle(2)
 store.prepare_execution(identity,'RELEASE',raw,browser_hash=BROWSER,claim_hash=claim.digest(),fee_cap=10,expires_at=400,now=210)
 if stage!='PREPARED':
  release=PreparedProtocolBundle(raw,5,'release-fee')
  store.save_execution_funding(identity,'RELEASE',release,browser_hash=BROWSER,now=211)
  store.observe_execution(identity,'RELEASE',browser_hash=BROWSER,transaction_id=release.spend_bundle_id,
   status=stage,confirmed_height=124 if stage=='CONFIRMED'else None,now=212)
 return store,claim,identity


def retry(store,claim,key='retry'):
 changed=claim.model_copy(update={'available_coin_id':'0x'+'08'*32})
 identity=store.save_review(changed,browser_hash=BROWSER,request_key=key,now=213)
 return identity,lambda:store.prepare_execution(identity,'RESERVATION',bundle(3),browser_hash=BROWSER,
  claim_hash=changed.digest(),fee_cap=10,expires_at=400,now=214)


def test_confirmed_unpaid_release_restores_unit_capacity_and_preserves_all_rows(execution):
 store,claim,old=released(execution)
 with store._connect()as db:
  before=[tuple(r)for r in db.execute('SELECT * FROM current_purchase_executions WHERE intent_id=? ORDER BY phase',(old,))]
 new,prepare=retry(store,claim);assert prepare()['stage']=='PREPARED'
 with store._connect()as db:
  assert [tuple(r)for r in db.execute('SELECT * FROM current_purchase_executions WHERE intent_id=? ORDER BY phase',(old,))]==before
  assert db.execute('SELECT count(*) FROM current_purchase_executions WHERE intent_id=?',(old,)).fetchone()[0]==2
 # A new request cannot reset the still-occupied one-unit allowance.
 changed=claim.model_copy(update={'available_coin_id':'0x'+'09'*32})
 third=store.save_review(changed,browser_hash=BROWSER,request_key='third',now=215)
 with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):
  store.prepare_execution(third,'RESERVATION',bundle(4),browser_hash=BROWSER,claim_hash=changed.digest(),fee_cap=10,expires_at=400,now=216)
 assert store.execution_status(new,'RESERVATION',browser_hash=BROWSER)['stage']=='PREPARED'


@pytest.mark.parametrize('stage',['PREPARED','MEMPOOL'])
def test_unconfirmed_release_does_not_restore_capacity(execution,stage):
 store,claim,_=released(execution,stage);_,prepare=retry(store,claim)
 with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):prepare()


def test_saved_payer_authorization_never_frees_capacity_automatically(execution):
 store,claim,old=released(execution)
 store.save_delivery(old,delivery(claim),browser_hash=BROWSER,now=213)
 _,prepare=retry(store,claim)
 with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):prepare()


@pytest.mark.parametrize('patch',["confirmed_height=NULL","confirmed_height=0","transaction_id=NULL"])
def test_incomplete_confirmation_is_not_a_capacity_release(execution,patch):
 store,claim,old=released(execution)
 with store._connect()as db:db.execute("UPDATE current_purchase_executions SET "+patch+" WHERE intent_id=? AND phase='RELEASE'",(old,))
 _,prepare=retry(store,claim)
 with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):prepare()


def test_two_unit_release_allows_same_two_unit_retry_but_preserves_three_unit_cap(batch_queue):
 q=batch_queue;raw=bundle()
 def prepare():
  return q.store.prepare_execution(q.identity,'RESERVATION',raw,browser_hash=BROWSER,
   claim_hash=q.claim.digest(),fee_cap=10,expires_at=400,now=110)
 released((q.store,q.claim,q.identity,raw,prepare))
 changed=another_batch(q.claim)
 new=q.store.save_review(changed,browser_hash=BROWSER,request_key='batch-retry',now=213)
 q.store.request_reservation(new,browser_hash=BROWSER,now=214)
 # The same pending request consumes exactly two units, once.
 q.store.prepare_execution(new,'RESERVATION',bundle(3),browser_hash=BROWSER,
  claim_hash=changed.digest(),fee_cap=10,expires_at=400,now=215)
 scalar=q.claim.children[0].model_copy(update={'available_coin_id':'0x'+'08'*32})
 last=q.store.save_review(scalar,browser_hash=BROWSER,request_key='last-unit',now=216)
 q.store.request_reservation(last,browser_hash=BROWSER,now=217)
 extra=scalar.model_copy(update={'available_coin_id':'0x'+'09'*32})
 over=q.store.save_review(extra,browser_hash=BROWSER,request_key='over-budget',now=218)
 with pytest.raises(ValueError,match='CAPACITY_EXHAUSTED'):
  q.store.request_reservation(over,browser_hash=BROWSER,now=219)
 with q.store._connect()as db:
  assert db.execute('SELECT maximum_purchases,fee_cap FROM current_purchase_execution_policies').fetchone()[:]==(3,10)
  assert db.execute("SELECT count(*) FROM current_purchase_executions WHERE intent_id=?",(q.identity,)).fetchone()[0]==2
