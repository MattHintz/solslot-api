"""Durable coordinator ordering with actual private HTTP/BLS and timeout CLVM."""
import copy

import httpx
import pytest
from fastapi import HTTPException

from solslot_api import inventory_payment_holds as holds, native_purchases
from solslot_api.inventory_payment_hold_claims import InventoryPaymentHoldClaim
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_api.validator_app import create_validator_app
from solslot_api.validator_quorum import collect_inventory_payment_hold_quorum, ValidatorQuorumError
from tests.test_inventory_payment_holds import hold_case, close, returned
from tests.test_inventory_payment_hold_abort import activate_abort
from tests.test_single_external_delivery_context import hx


async def coordinator(tmp_path,monkeypatch,method='card'):
    c=await hold_case(tmp_path,monkeypatch,method);activate_abort(c)
    from types import SimpleNamespace
    from tests.test_inventory_status import complete_offer
    complete_offer(SimpleNamespace(store=c.purchases,stored=c.purchases.get(hx(c.purchase.purchase_id))))
    c.admission_receipt=dict(vaultLauncherId=hx(c.purchase.vault_launcher_id),network='testnet11',scopedNullifier='0x'+'a1'*32,
                            nullifierType=1,serviceScopeHash='0x'+'a2'*32,serviceSubscopeHash='0x'+'a3'*32)
    from solslot_api import state
    c.admission_owner=SimpleNamespace(auth_type=1,owner_pubkey=bytes(c.keys[0].get_g1()))
    monkeypatch.setattr(state,'get_registry',lambda:SimpleNamespace(get=lambda _:c.admission_owner))
    stored=c.purchases.get(hx(c.purchase.purchase_id))
    c.purchases.admit_purchase(purchase_intent_id=stored.purchase_intent_id,receipt=c.admission_receipt,
        activation=c.claim.activation,now=c.clock[0],owner_auth_type=1,owner_key=hx(c.keys[0].get_g1()))
    c.purchases.begin_admitted_reservation(stored=stored,receipt=c.admission_receipt,activation=c.claim.activation,now=c.clock[0],
        owner_auth_type=1,owner_key=hx(c.keys[0].get_g1()))
    c.settings.zkpassport_validator_pubkeys=c.genesis['validatorSet']['pubkeys']
    c.settings.zkpassport_validator_threshold=2
    c.settings.zkpassport_validator_urls=['http://validator-0','http://validator-1','http://validator-2']
    apps=[create_validator_app(settings=s,ledger=l) for s,l in zip(c.signers,c.ledgers,strict=True)]
    for app,ledger in zip(apps,c.ledgers,strict=True):app.state.validator_ledger=ledger
    transports=[httpx.ASGITransport(app=app) for app in apps]
    c.offline={2};c.after_quorum=lambda:None;c.before_quorum=lambda:None;c.request_count=0
    async def dispatch(request):
        index=int(request.url.host[-1]);c.request_count+=1
        assert c.purchases.checkout_hold(hx(c.purchase.purchase_id)) is not None
        if index in c.offline:return httpx.Response(503,json=dict(detail='isolated unavailable fixture'))
        return await transports[index].handle_async_request(request)
    async def collect(settings,claim):
        c.before_quorum()
        async with httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as client:
            quorum=await collect_inventory_payment_hold_quorum(settings,claim,client=client)
        c.after_quorum()
        return quorum
    monkeypatch.setattr(holds,'collect_inventory_payment_hold_quorum',collect)
    monkeypatch.setattr(native_purchases,'get_payment_purchase_store',lambda _:c.purchases)
    monkeypatch.setattr(native_purchases,'load_signed_public_artifact',lambda _:copy.deepcopy(c.genesis))
    return c


async def arm(c,**overrides):
    return await holds.arm_checkout(**dict(store=c.purchases,settings=c.settings,purchase_id=hx(c.purchase.purchase_id),
        payment_intent_id=c.claim.payment_intent_id,payment_method=c.claim.payment_method,
        load_artifact=lambda:copy.deepcopy(c.genesis),authorize=lambda:None,**overrides))


async def abort(c):
    return await holds.abort_checkout(store=c.purchases,settings=c.settings,purchase_id=hx(c.purchase.purchase_id),
                                     load_artifact=lambda:copy.deepcopy(c.genesis))


@pytest.mark.asyncio
@pytest.mark.parametrize('method',['card','us_bank_account'])
async def test_journal_precedes_quorum_and_exact_arm_recovers_after_restart(tmp_path,monkeypatch,method):
    c=await coordinator(tmp_path,monkeypatch,method)
    try:
        first=await arm(c)
        assert first['state']=='ARMED' and first['confirmationAllowed'] is True
        assert first['paymentRetryAllowed'] is False and first['inventoryReusable'] is False
        c.purchases=PaymentPurchaseStore(c.purchases.path)
        assert await arm(c)==first
        record=c.purchases.checkout_hold(hx(c.purchase.purchase_id))
        holds.verify_hold_receipt(InventoryPaymentHoldClaim.model_validate(record['claim']),record['armReceipt'],c.genesis)
        assert not c.funded and not c.extension_dispatches
    finally:close(c)


@pytest.mark.asyncio
async def test_lost_partial_quorum_stays_pinned_then_cancel_observation_closes_private_holds(tmp_path,monkeypatch):
    c=await coordinator(tmp_path,monkeypatch)
    try:
        c.offline.add(1)
        with pytest.raises(ValidatorQuorumError):await arm(c)
        purchase_id=hx(c.purchase.purchase_id)
        assert c.purchases.checkout_hold(purchase_id)['state']=='ARMING'
        original=c.purchases.get(purchase_id)
        for action in (
            lambda:c.purchases.claim_inventory_timeout(purchase_id,0,binding={},owner='fixture',now=c.clock[0]),
            lambda:c.purchases.record_inventory_released(purchase_id,evidence={}),
            lambda:c.purchases.record_inventory_authorization_expired(purchase_id,evidence={})):
            with pytest.raises(PaymentPurchaseConflict,match='checkout payment hold'):action()
        c.purchases=PaymentPurchaseStore(c.purchases.path)
        c.intent['status']='canceled';returned(c);c.offline.remove(1)
        result=await abort(c)
        assert result['state']=='ABORTED' and not result['confirmationAllowed'] and not result['inventoryReusable']
        assert c.purchases.get(purchase_id)==original
        assert c.purchases.latest_released_inventory(hx(c.purchase.deed_launcher_id)) is None
        assert await abort(c)==result
        with pytest.raises(PaymentPurchaseConflict):await arm(c)
        for ledger in c.ledgers:assert ledger.inventory_payment_hold(purchase_id)['state']=='RELEASED'
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['other_pi','other_method','expired','release','invalid_signature','duplicate_signer','tampered_claim'])
async def test_armed_journal_is_not_replacement_or_current_confirmation_authority(tmp_path,monkeypatch,problem):
    c=await coordinator(tmp_path,monkeypatch)
    try:
        original=await arm(c);purchase_id=hx(c.purchase.purchase_id)
        if problem=='other_pi':c.claim=c.claim.model_copy(update={'payment_intent_id':'pi_other'})
        elif problem=='other_method':c.claim=c.claim.model_copy(update={'payment_method':'us_bank_account'})
        elif problem=='expired':c.clock[0]=c.reservation.expires_at
        elif problem=='release':c.genesis['artifactHash']='0x'+'fe'*32
        else:
            record=c.purchases.checkout_hold(purchase_id)
            if problem=='invalid_signature':record['armReceipt']['signature']='0x'+'00'*96
            elif problem=='duplicate_signer':record['armReceipt']['signerIndices']=[0,0]
            else:record['claim']['payment_intent_id']='pi_other'
            with pytest.raises(PaymentPurchaseConflict):holds.checkout_status(record,c.genesis,now=c.clock[0])
            return
        with pytest.raises((PaymentPurchaseConflict,ValidatorQuorumError,ValueError)):await arm(c)
        assert c.purchases.checkout_hold(purchase_id)['claim']['payment_intent_id']==original['paymentIntentId']
        if problem=='expired':
            assert not holds.checkout_status(c.purchases.checkout_hold(purchase_id),c.genesis,now=c.clock[0])['confirmationAllowed']
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['expiry','release','abort','owner_rotated'])
async def test_validation_to_commit_race_never_returns_confirmation_permission(tmp_path,monkeypatch,problem):
    c=await coordinator(tmp_path,monkeypatch)
    try:
        def change():
            if problem=='expiry':c.clock[0]=c.reservation.expires_at
            elif problem=='release':c.genesis['artifactHash']='0x'+'fe'*32
            elif problem=='owner_rotated':c.admission_owner.owner_pubkey=bytes(c.keys[1].get_g1())
            else:
                with c.purchases._connect() as db:db.execute("UPDATE payment_checkout_holds SET state='ABORTING'")
        c.after_quorum=change
        with pytest.raises(PaymentPurchaseConflict):await arm(c)
        assert c.purchases.checkout_hold(hx(c.purchase.purchase_id))['armReceipt'] is None
        assert all(l.inventory_payment_hold(hx(c.purchase.purchase_id)) for l in c.ledgers)
    finally:close(c)


@pytest.mark.asyncio
async def test_repeated_armed_requests_do_not_repeat_private_provider_work(tmp_path,monkeypatch):
    c=await coordinator(tmp_path,monkeypatch)
    try:
        first=await arm(c);requests=c.request_count
        for _ in range(20):assert await arm(c)==first
        assert c.request_count==requests==3
        c.admission_owner.owner_pubkey=bytes(c.keys[1].get_g1())
        with pytest.raises(PaymentPurchaseConflict):await arm(c)
        assert c.request_count==requests
    finally:close(c)


@pytest.mark.asyncio
async def test_service_routes_require_auth_new_arm_gates_and_recovery_observes_while_paused(tmp_path,monkeypatch):
    c=await coordinator(tmp_path,monkeypatch)
    try:
        payload=native_purchases.InventoryPaymentHoldRequest(purchaseId=hx(c.purchase.purchase_id),
            paymentIntentId=c.claim.payment_intent_id,paymentMethod='card')
        with pytest.raises(HTTPException) as denied:await native_purchases.arm_inventory_payment_hold(payload,c.settings,None)
        assert denied.value.status_code==401 and c.request_count==0
        token='Bearer synthetic-extension-service-token'
        response=await native_purchases.arm_inventory_payment_hold(payload,c.settings,token)
        assert response['checkoutHold']['state']=='ARMED'
        c.settings.alpha_writes_enabled=False
        with pytest.raises(HTTPException):await native_purchases.arm_inventory_payment_hold(payload,c.settings,token)
        c.intent['status']='canceled';returned(c)
        result=await native_purchases.abort_inventory_payment_hold(
            native_purchases.InventoryReservationRequest(purchaseId=payload.purchase_id),c.settings,token)
        assert result['checkoutHold']['state']=='ABORTED'
        status=await native_purchases.inventory_purchase_status(payload.purchase_id,c.settings,token)
        assert status['checkoutHold']['state']=='ABORTED' and status['checkoutHold']['inventoryReusable'] is False
    finally:close(c)
