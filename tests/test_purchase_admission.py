"""Concurrent checkout floods cannot multiply one verified person's reservations."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_api.purchase_admission import ADMISSION_POLICY, admission_subject, close_inventory_admission


OWNER="0x"+"11"*48


def receipt(n=1,*,vault=None):
    return dict(vaultLauncherId='0x'+f'{vault or n:064x}',network='testnet11',scopedNullifier='0x'+f'{n:064x}',
                nullifierType=1,serviceScopeHash='0x'+'a'*64,serviceSubscopeHash='0x'+'b'*64)


def test_parallel_alias_wallets_share_one_verified_identity_slot(tmp_path):
    path=str(tmp_path/'admission.db');store=PaymentPurchaseStore(path)
    def admit(i):
        own=PaymentPurchaseStore(path)
        try:
            own.admit_purchase(purchase_intent_id=f'intent-{i}',receipt=receipt(1,vault=i+2),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
            return 'admitted'
        except PaymentPurchaseConflict:return 'limited'
    with ThreadPoolExecutor(max_workers=16) as pool:results=list(pool.map(admit,range(64)))
    assert results.count('admitted')==1 and results.count('limited')==63
    with store._connect() as db:assert db.execute('SELECT count(*) FROM payment_purchase_admission').fetchone()[0]==1


def test_new_nullifier_does_not_bypass_same_vault_quota(tmp_path):
    store=PaymentPurchaseStore(str(tmp_path/'admission.db'))
    store.admit_purchase(purchase_intent_id='one',receipt=receipt(1,vault=5),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
    with pytest.raises(PaymentPurchaseConflict):
        store.admit_purchase(purchase_intent_id='two',receipt=receipt(2,vault=5),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1001)


def test_unsigned_slot_expires_but_partial_signing_survives_time_and_restart(tmp_path):
    path=str(tmp_path/'admission.db');store=PaymentPurchaseStore(path)
    store.admit_purchase(purchase_intent_id='unsigned',receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
    store.admit_purchase(purchase_intent_id='signed',receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1900)
    with pytest.raises(PaymentPurchaseConflict):store.begin_admitted_reservation(
        stored=SimpleNamespace(purchase_intent_id='unsigned',purchase_id='old'),receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1900)
    stored=SimpleNamespace(purchase_intent_id='signed',purchase_id='retained')
    store.begin_admitted_reservation(stored=stored,receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1900)
    store=PaymentPurchaseStore(path)
    with pytest.raises(PaymentPurchaseConflict):
        store.admit_purchase(purchase_intent_id='replacement',receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000000)
    # Only the internal proven inventory-expiry/release commit closes this slot.
    with store._connect() as db:close_inventory_admission(db,'retained')
    store.admit_purchase(purchase_intent_id='after-recovery',receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000000)


def test_verified_identities_have_global_new_work_budget_without_blocking_recovery(tmp_path):
    store=PaymentPurchaseStore(str(tmp_path/'admission.db'))
    for n in range(1,61):store.admit_purchase(purchase_intent_id=str(n),receipt=receipt(n),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
    with pytest.raises(PaymentPurchaseConflict,match='capacity'):
        store.admit_purchase(purchase_intent_id='61',receipt=receipt(61),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
    store.begin_admitted_reservation(stored=SimpleNamespace(purchase_intent_id='1',purchase_id='existing'),
        receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
    store.admit_purchase(purchase_intent_id='61',receipt=receipt(61),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1060)


@pytest.mark.parametrize('field,value',[('scopedNullifier',None),('scopedNullifier','0x'+'0'*64),
    ('scopedNullifier','0x'+'A'*64),('nullifierType',True),('serviceScopeHash',None),('network','mainnet')])
def test_unverified_or_ambiguous_subject_has_no_admission(field,value):
    with pytest.raises(PaymentPurchaseConflict):admission_subject({**receipt(),field:value})


def test_private_quorum_singleflight_cooldown_and_separate_recovery_capacity(tmp_path):
    path=str(tmp_path/'admission.db');store=PaymentPurchaseStore(path)
    def claim(i):
        try:PaymentPurchaseStore(path).claim_checkout_quorum('same',kind='arm',owner=str(i),now=1000);return str(i)
        except PaymentPurchaseConflict:return None
    with ThreadPoolExecutor(max_workers=16) as pool:winners=[n for n in pool.map(claim,range(64)) if n is not None]
    assert len(winners)==1
    store.finish_checkout_quorum('same',owner=winners[0],now=1001)
    with pytest.raises(PaymentPurchaseConflict):store.claim_checkout_quorum('same',kind='arm',owner='retry',now=1002)
    for n in range(8):store.claim_checkout_quorum(str(n),kind='arm',owner=str(n),now=1010)
    with pytest.raises(PaymentPurchaseConflict):store.claim_checkout_quorum('overflow',kind='arm',owner='extra',now=1010)
    store.claim_checkout_quorum('recovery',kind='abort',owner='recovery',now=1010)
    # Crash recovery is a lease takeover, not a payment retry or new inventory.
    store.claim_checkout_quorum('0',kind='arm',owner='after-crash',now=1130)


def test_admission_policy_and_release_binding_cannot_change_during_signing(tmp_path):
    store=PaymentPurchaseStore(str(tmp_path/'admission.db'))
    store.admit_purchase(purchase_intent_id='one',receipt=receipt(),activation=ADMISSION_POLICY,owner_auth_type=1,owner_key=OWNER,now=1000)
    with pytest.raises(PaymentPurchaseConflict):store.begin_admitted_reservation(
        stored=SimpleNamespace(purchase_intent_id='one',purchase_id='payment'),receipt=receipt(),
        activation={**ADMISSION_POLICY,'releaseIdentity':'changed'},owner_auth_type=1,owner_key=OWNER,now=1001)
    with pytest.raises(PaymentPurchaseConflict):store.admit_purchase(
        purchase_intent_id='two',receipt=receipt(2),activation={**ADMISSION_POLICY,'maxPendingPurchasesPerIdentity':2},owner_auth_type=1,owner_key=OWNER,now=1001)


@pytest.mark.parametrize('problem',['missing','other_owner','wrong_type','boolean_type','case_alias'])
def test_authenticated_wallet_cannot_consume_another_vault_identity_quota(monkeypatch,problem):
    from solslot_api.purchase_admission import require_admission_owner
    from solslot_api import state
    from chia_rs import AugSchemeMPL
    key=bytes(AugSchemeMPL.key_gen(bytes(range(32))).get_g1())
    record=SimpleNamespace(auth_type=1,owner_pubkey=key)
    monkeypatch.setattr(state,'get_registry',lambda:SimpleNamespace(get=lambda _:record))
    require_admission_owner(receipt()['vaultLauncherId'],1,'0x'+key.hex())
    owner='0x'+key.hex();kind=1
    if problem=='missing':owner=None
    elif problem=='other_owner':owner='0x'+bytes(AugSchemeMPL.key_gen(bytes(reversed(range(32)))).get_g1()).hex()
    elif problem=='wrong_type':kind=3
    elif problem=='boolean_type':kind=True
    else:owner=owner.upper()
    with pytest.raises(PaymentPurchaseConflict,match='session does not control'):
        require_admission_owner(receipt()['vaultLauncherId'],kind,owner)
