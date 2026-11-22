from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from solslot_api.generation_customer_purchase_holds import hold_cart, cancel_cart
from tests.test_current_purchase_batch_queue import batch_queue, another_batch
from tests.test_current_purchase_store import BROWSER


def test_explicit_cancel_and_expiry_never_queue_chain_work(batch_queue):
    q = batch_queue
    params = {'browser_hash': BROWSER, 'now': 102}
    active = hold_cart(q.store, q.identity, **params)
    assert active['state'] == 'HELD'
    assert hold_cart(q.store, q.identity, **params) == active
    with pytest.raises(ValueError, match='off-chain cart'):
        q.store.request_reservation(q.identity, **params)
    assert cancel_cart(q.store, q.identity, **params) == 'CANCELED'
    assert cancel_cart(q.store, q.identity, **params) == 'CANCELED'
    other = q.store.save_review(another_batch(q.claim), browser_hash=BROWSER, request_key='second-cart', now=102)
    assert hold_cart(q.store, other, **params)['state'] == 'HELD'
    assert hold_cart(q.store, other, browser_hash=BROWSER, now=active['expiresAt'])['state'] == 'EXPIRED'
    with q.store._connect() as db:
        assert db.execute('SELECT count(*) FROM current_customer_reservation_requests').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0] == 0
        assert db.execute('SELECT sum(active) FROM current_native_cart_items').fetchone()[0] == 0


def test_contending_carts_have_one_winner_and_no_partial_hold(batch_queue):
    q = batch_queue
    other = q.store.save_review(another_batch(q.claim), browser_hash=BROWSER, request_key='contender', now=102)
    ready = Barrier(2)
    def attempt(identity):
        ready.wait()
        try:
            return hold_cart(q.store, identity, browser_hash=BROWSER, now=103)['state']
        except ValueError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (q.identity,other)))
    assert outcomes.count('HELD') == 1
    with q.store._connect() as db:
        assert db.execute('SELECT count(DISTINCT intent_id),sum(active) FROM current_native_cart_items').fetchone()[:] == (1,2)


def test_old_reservation_never_converts_to_an_unpaid_cart(batch_queue):
    q = batch_queue
    q.store.request_reservation(q.identity, browser_hash=BROWSER, now=103)
    with pytest.raises(ValueError, match='on-chain recovery'):
        hold_cart(q.store, q.identity, browser_hash=BROWSER, now=104)
