"""Saved checkout work survives reconnect/restart without granting authority."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import pytest
from chia_rs import AugSchemeMPL, G2Element

from solslot_api.generation_customer_purchase_store import CurrentCustomerPurchaseStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.generation_customer_purchase_delivery import CurrentDeliveryClaim
from solslot_api.generation_storage import GenerationStorageError, GenerationRetentionFull
from tests.test_generation_customer_purchase_reservation_claim import body


BROWSER = 'ab' * 32


@pytest.fixture
def checkout(tmp_path):
    claim = CurrentReservationClaim.model_validate(body())
    store = CurrentCustomerPurchaseStore(tmp_path / 'payment_purchases_v2.db', claim.generation_id)
    identity = store.save_review(claim, browser_hash=BROWSER, request_key='user-click-1', now=100)
    return store, claim, identity


def reply(claim, index=0):
    # The real quorum suite verifies cryptography; these explicit synthetic
    # responses exercise durable binding and read-only recovery only.
    return dict(claimHash=claim.digest(), signerIndex=index,
        validatorPubkey='0x' + bytes(AugSchemeMPL.key_gen(b'x' * 32).get_g1()).hex(),
        signature='0x' + bytes(G2Element()).hex())


def delivery(claim, offer='offer1' + 'a' * 64):
    return CurrentDeliveryClaim(reservation=claim, reservedCoinId='0x'+'07'*32, buyerOffer=offer)


def test_reopen_recovers_same_review_partial_quorum_and_signed_offer(checkout):
    store, claim, identity = checkout
    store.save_signature(identity, 'reservation', 0, reply(claim), browser_hash=BROWSER)
    signed = delivery(claim)
    store.save_delivery(identity, signed, browser_hash=BROWSER, now=110)
    store.save_signature(identity, 'delivery', 1, reply(signed, 1), browser_hash=BROWSER)
    restarted = CurrentCustomerPurchaseStore(store.path, store.generation_id)
    assert restarted.save_review(claim, browser_hash=BROWSER, request_key='user-click-1', now=1000) == identity
    restarted.save_delivery(identity, signed, browser_hash=BROWSER, now=1000)
    result = restarted.saved(identity, browser_hash=BROWSER)
    assert result['createdAt'] == 100
    assert result['reservationClaim'] == claim
    assert result['deliveryClaim'] == signed
    assert result['retainedSignatures'] == {'reservation': {0: reply(claim)}, 'delivery': {1: reply(signed, 1)}}


def test_status_recovery_does_not_write_or_expire_saved_signatures(checkout):
    store, claim, identity = checkout
    store.save_signature(identity, 'reservation', 0, reply(claim), browser_hash=BROWSER)
    with store._connect() as db:
        before = db.execute('SELECT * FROM current_customer_purchase_reviews').fetchall()
    a = store.saved(identity, browser_hash=BROWSER)
    b = store.saved(identity, browser_hash=BROWSER)
    with store._connect() as db:
        after = db.execute('SELECT * FROM current_customer_purchase_reviews').fetchall()
    assert [tuple(r) for r in before] == [tuple(r) for r in after]
    assert a == b and a['retainedSignatures']['reservation']


def test_different_browser_cannot_read_bind_or_overwrite(checkout):
    store, claim, identity = checkout
    other = 'bc'*32
    with pytest.raises(ValueError, match='UNAVAILABLE'):
        store.saved(identity, browser_hash=other)
    with pytest.raises(ValueError, match='UNAVAILABLE'):
        store.save_delivery(identity, delivery(claim), browser_hash=other, now=110)
    with pytest.raises(ValueError, match='ALREADY_BOUND'):
        store.save_review(claim, browser_hash=other, request_key='user-click-1', now=110)


def test_duplicate_clicks_are_atomic_across_independent_store_instances(checkout):
    store, claim, identity = checkout
    def save(_):
        reopened = CurrentCustomerPurchaseStore(store.path, store.generation_id)
        return reopened.save_review(claim, browser_hash=BROWSER, request_key='user-click-1', now=120)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(save, range(8))) == [identity]*8
    with store._connect() as db:
        assert db.execute('SELECT count(*) FROM current_customer_purchase_reviews').fetchone()[0] == 1


@pytest.mark.parametrize('changes', [
    {'available_coin_id':'0x'+'08'*32}, {'current_vault_coin_id':'0x'+'09'*32},
    {'purchase_artifact':{'synthetic':'different quote'}}, {'signer_indices':(0,2)}])
def test_same_request_key_cannot_silently_reprice_or_change_receiver(checkout, changes):
    store, claim, identity = checkout
    with pytest.raises(ValueError, match='RETRY_CHANGES_REVIEW'):
        store.save_review(claim.model_copy(update=changes), browser_hash=BROWSER, request_key='user-click-1', now=101)
    assert store.saved(identity, browser_hash=BROWSER)['reservationClaim'] == claim


def test_first_signed_wallet_offer_is_immutable(checkout):
    store, claim, identity = checkout
    store.save_delivery(identity, delivery(claim), browser_hash=BROWSER, now=110)
    with pytest.raises(ValueError, match='SIGNED_PAYER_OFFER_ALREADY_BOUND'):
        store.save_delivery(identity, delivery(claim, 'offer1'+'b'*64), browser_hash=BROWSER, now=111)
    other = claim.model_copy(update={'current_vault_coin_id':'0x'+'08'*32})
    with pytest.raises(ValueError, match='DELIVERY_CHANGES_RESERVATION'):
        store.save_delivery(identity, delivery(other), browser_hash=BROWSER, now=111)


def test_signature_phase_hash_slot_and_first_reply_are_bound(checkout):
    store, claim, identity = checkout
    with pytest.raises(ValueError, match='DELIVERY_NOT_SAVED'):
        store.save_signature(identity, 'delivery', 0, reply(claim), browser_hash=BROWSER)
    for index, value in [(2, reply(claim, 2)), (1, reply(claim)), (0, {**reply(claim), 'claimHash':'0x'+'09'*32})]:
        with pytest.raises(ValueError, match='SIGNATURE_BINDING_CHANGED'):
            store.save_signature(identity, 'reservation', index, value, browser_hash=BROWSER)
    store.save_signature(identity, 'reservation', 0, reply(claim), browser_hash=BROWSER)
    store.save_signature(identity, 'reservation', 0, reply(claim), browser_hash=BROWSER)
    different = {**reply(claim), 'validatorPubkey':'0x'+bytes(AugSchemeMPL.key_gen(b'y'*32).get_g1()).hex()}
    with pytest.raises(ValueError, match='SAVED_SIGNATURE_CHANGED'):
        store.save_signature(identity, 'reservation', 0, different, browser_hash=BROWSER)


def test_wrong_generation_database_cannot_admit_saved_checkout(checkout):
    store, claim, identity = checkout
    with pytest.raises(GenerationStorageError):
        CurrentCustomerPurchaseStore(store.path, '0x'+'09'*32)
    assert store.saved(identity, browser_hash=BROWSER)['reservationClaim'] == claim


def test_storage_admission_failure_retains_old_review_and_signature(checkout):
    store, claim, identity = checkout
    store.save_signature(identity, 'reservation', 0, reply(claim), browser_hash=BROWSER)
    store.MAX_CURRENT_RETAINED_BYTES = 1
    with pytest.raises(GenerationRetentionFull):
        store.save_delivery(identity, delivery(claim), browser_hash=BROWSER, now=110)
    saved = store.saved(identity, browser_hash=BROWSER)
    assert saved['deliveryClaim'] is None
    assert saved['retainedSignatures']['reservation'] == {0:reply(claim)}


def test_corrupted_review_or_delivery_does_not_become_recovered_authority(checkout):
    store, claim, identity = checkout
    store.save_delivery(identity, delivery(claim), browser_hash=BROWSER, now=110)
    with store._connect() as db:
        db.execute("UPDATE current_customer_purchase_delivery SET claim_hash=?", ('0x'+'09'*32,))
    with pytest.raises(ValueError, match='SAVED_DELIVERY_CHANGED'):
        store.saved(identity, browser_hash=BROWSER)
    with store._connect() as db:
        db.execute("UPDATE current_customer_purchase_reviews SET claim_hash=?", ('0x'+'09'*32,))
    with pytest.raises(ValueError, match='SAVED_REVIEW_CHANGED'):
        store.saved(identity, browser_hash=BROWSER)


def test_actual_sqlite_restore_keeps_signed_work_in_existing_payment_database(checkout, tmp_path):
    store, claim, identity = checkout
    signed = delivery(claim)
    store.save_delivery(identity, signed, browser_hash=BROWSER, now=110)
    store.save_signature(identity, 'reservation', 0, reply(claim), browser_hash=BROWSER)
    expected = store.saved(identity, browser_hash=BROWSER)
    # Native SQLite backup includes the WAL and original generation binding;
    # no table-by-table export or separate untracked checkout database.
    restored_path = tmp_path / 'restored' / 'generations' / store.generation_id[2:] / 'payment_purchases_v2.db'
    restored_path.parent.mkdir(parents=True)
    with sqlite3.connect(store.path) as source, sqlite3.connect(restored_path) as target:
        source.backup(target)
        assert target.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    restored = CurrentCustomerPurchaseStore(restored_path, store.generation_id)
    assert restored.saved(identity, browser_hash=BROWSER) == expected
    assert store.saved(identity, browser_hash=BROWSER) == expected
