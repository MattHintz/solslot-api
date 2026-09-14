"""Actual private BLS/HTTP and canonical local coin proofs; no network outcomes."""
import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from solslot_api import checkout_terminals as terminal, inventory_payment_holds as holds, native_purchases
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_api.validator_quorum import ValidatorQuorumError
from tests.test_inventory_checkout_coordinator import coordinator, arm, abort
from tests.test_inventory_payment_holds import close, paid, refunded, returned
from tests.test_inventory_extensions import advance, confirm, current_position
from tests.test_single_external_delivery_context import hx


async def setup(tmp_path, monkeypatch):
    c = await coordinator(tmp_path, monkeypatch)
    monkeypatch.setattr(terminal, 'collect_inventory_payment_hold_quorum', holds.collect_inventory_payment_hold_quorum)
    return c


async def recover(c):
    return await terminal.reconcile_checkout_return(store=c.purchases,node=c.node,settings=c.settings,
        purchase_id=hx(c.purchase.purchase_id),load_artifact=lambda:copy.deepcopy(c.genesis))


def admission(c):
    with c.purchases._connect() as db:
        return db.execute('SELECT state FROM payment_purchase_admission WHERE purchase_id=?', (hx(c.purchase.purchase_id),)).fetchone()[0]


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['canceled','refunded','partial_abort','extended_refund'])
async def test_terminal_return_closes_capacity_and_preserves_all_originals(tmp_path,monkeypatch,kind):
    c=await setup(tmp_path,monkeypatch)
    try:
        if kind=='partial_abort':
            c.offline.add(1)
            with pytest.raises(ValidatorQuorumError):await arm(c)
            c.offline.remove(1)
        else:await arm(c)
        original=c.purchases.get(hx(c.purchase.purchase_id))
        position=None
        if kind=='extended_refund':
            paid(c);await advance(c);confirm(c);await advance(c,observe_only=True)
            position=current_position(c.purchases.get(original.purchase_id),c.purchases.inventory_items(original.purchase_id),c.genesis)
        if 'refund' in kind:refunded(c)
        else:c.intent['status']='canceled'
        returned_claim=returned(c,position)
        if kind=='partial_abort':await abort(c)
        result=await recover(c)
        assert result['state']=='RETURNED' and result['capacityReleased'] is True
        assert not result['confirmationAllowed'] and not result['paymentRetryAllowed']
        assert admission(c)=='CLOSED'
        stored=c.purchases.get(original.purchase_id)
        assert stored.inventory_state=='RELEASED' and stored.purchase_artifact==original.purchase_artifact
        assert stored.inventory_bundle==original.inventory_bundle
        assert c.purchases.latest_released_inventory(hx(c.purchase.deed_launcher_id))['availableCoinId']==returned_claim.available_coin_id
        assert all(l.inventory_payment_hold(original.purchase_id)['state']=='RELEASED' for l in c.ledgers[:2])
        c.purchases=PaymentPurchaseStore(c.purchases.path)
        c.records[returned_claim.available_coin_id].update(spent=True,spent_block_index=c.height+1)
        # Recorded terminal proof survives another legitimate use of its output.
        before=c.request_count
        assert await recover(c)==result and c.request_count==before
        status=await native_purchases.inventory_purchase_status(original.purchase_id,c.settings,'Bearer synthetic-extension-service-token')
        assert status['recoveryReceipt']['kind']=='payment-return'
        assert status['checkoutHold']['capacityReleased']
        c.purchases.admit_purchase(purchase_intent_id='next-legitimate-purchase',receipt=c.admission_receipt,
            activation=c.claim.activation,now=c.clock[0],owner_auth_type=1,owner_key=hx(c.keys[0].get_g1()))
        with pytest.raises(PaymentPurchaseConflict):await arm(c)
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['processing','partial_refund','missing_successor','spent_successor','wrong_spend','wrong_network','immature','source_changed'])
async def test_uncertain_return_never_closes_capacity(tmp_path,monkeypatch,problem):
    c=await setup(tmp_path,monkeypatch)
    try:
        await arm(c);refunded(c);claim=returned(c)
        if problem=='processing':c.intent['status']='processing'
        elif problem=='partial_refund':c.charge['amount_refunded']-=1
        elif problem=='missing_successor':c.records.pop(claim.available_coin_id)
        elif problem=='spent_successor':c.records[claim.available_coin_id].update(spent=True,spent_block_index=c.height)
        elif problem=='wrong_spend':c.spends[(claim.reserved_coin_id,c.height-3)]=c.initial.coin_spends[0].to_json_dict()
        elif problem=='wrong_network':c.settings.network='mainnet'
        elif problem=='immature':c.height-=3
        else:c.records[hx(c.initial.coin_spends[0].coin.name())]['spent_block_index']-=1
        with pytest.raises((PaymentPurchaseConflict,ValidatorQuorumError,ValueError)):await recover(c)
        assert admission(c)=='SIGNING' and c.purchases.checkout_terminal(hx(c.purchase.purchase_id)) is None
        assert c.purchases.get(hx(c.purchase.purchase_id)).inventory_state=='CONFIRMED'
    finally:close(c)


@pytest.mark.asyncio
async def test_lost_quorum_and_commit_race_recover_exact_return(tmp_path,monkeypatch):
    c=await setup(tmp_path,monkeypatch)
    try:
        await arm(c);refunded(c);returned(c)
        c.offline.add(1)
        with pytest.raises(ValidatorQuorumError):await recover(c)
        pinned=c.purchases.checkout_return(hx(c.purchase.purchase_id))
        assert pinned['quorum'] is None and admission(c)=='SIGNING'
        c.purchases=PaymentPurchaseStore(c.purchases.path);c.offline.remove(1);c.clock[0]+=6
        original=c.purchases.record_checkout_terminal
        def race(*args,**kwargs):
            with c.purchases._connect() as db:db.execute("UPDATE payment_purchases SET external_message_json=? WHERE purchase_id=?", ('{}',hx(c.purchase.purchase_id)))
            return original(*args,**kwargs)
        monkeypatch.setattr(c.purchases,'record_checkout_terminal',race)
        with pytest.raises(PaymentPurchaseConflict):await recover(c)
        assert admission(c)=='SIGNING'
        monkeypatch.setattr(c.purchases,'record_checkout_terminal',original)
        assert (await recover(c))['capacityReleased']
        assert c.purchases.checkout_return(hx(c.purchase.purchase_id))['claim']==pinned['claim']
    finally:close(c)


@pytest.mark.asyncio
async def test_return_observer_auth_and_paused_new_purchases(tmp_path,monkeypatch):
    c=await setup(tmp_path,monkeypatch)
    try:
        await arm(c);refunded(c);returned(c);c.settings.alpha_writes_enabled=False
        payload=native_purchases.InventoryReservationRequest(purchaseId=hx(c.purchase.purchase_id))
        request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node)))
        with pytest.raises(HTTPException) as e:await native_purchases.reconcile_payment_return(payload,request,c.settings,None)
        assert e.value.status_code==401 and admission(c)=='SIGNING'
        result=await native_purchases.reconcile_payment_return(payload,request,c.settings,'Bearer synthetic-extension-service-token')
        assert result['checkoutHold']['state']=='RETURNED' and admission(c)=='CLOSED'
    finally:close(c)


async def delivered_case(tmp_path, monkeypatch):
    from tests.test_current_stripe_voucher_delivery import submit, prove_bundle
    from tests.test_single_external_delivery_context import coin_record
    c = await setup(tmp_path, monkeypatch)
    await arm(c); paid(c)
    # Premature recovery cannot interrupt a live payment or its later delivery.
    with pytest.raises(PaymentPurchaseConflict): await recover(c)
    assert c.purchases.checkout_hold(hx(c.purchase.purchase_id))['state']=='ARMED'
    assert c.purchases.checkout_return(hx(c.purchase.purchase_id)) is None
    from solslot_api.inventory_extension_store import canonical
    saved=c.purchases.get(hx(c.purchase.purchase_id)).offer_artifact
    saved['protocol']['collectionWorkspaceId']='local-dossier'
    with c.purchases._connect() as db:
        db.execute('UPDATE payment_purchases SET offer_artifact_json=?',(canonical(saved),))
    assert await submit(c)
    bundle = prove_bundle(c)
    height = 240
    for coin in bundle.removals():
        old = c.records.get(hx(coin.name()))
        c.records[hx(coin.name())] = coin_record(coin, confirmed=old['confirmed_block_index'] if old else 200, spent=height)
    removed = {coin.name() for coin in bundle.removals()}
    for coin in bundle.additions():
        c.records[hx(coin.name())] = coin_record(coin, confirmed=height, spent=height if coin.name() in removed else 0)
    for spend in bundle.coin_spends:
        c.spends[(hx(spend.coin.name()), height)] = spend.to_json_dict()
    assert await c.voucher_worker._confirm_stripe_redemption_if_ready(
        c.presales.get(c.current['termsHash']), c.presales.voucher(c.current['termsHash'], 0))
    return c, bundle


async def recover_paid(c):
    return await terminal.reconcile_paid_checkout(store=c.purchases,presales=c.presales,node=c.node,settings=c.settings,
        purchase_id=hx(c.purchase.purchase_id),load_artifact=lambda:copy.deepcopy(c.genesis))


@pytest.mark.asyncio
async def test_current_voucher_smartdeed_terminal_closes_admission_and_survives_restart(tmp_path, monkeypatch):
    from solslot_api.presale_endpoints import PresaleStore
    c, bundle = await delivered_case(tmp_path, monkeypatch)
    try:
        original = c.purchases.get(hx(c.purchase.purchase_id))
        status = await recover_paid(c)
        assert status['state'] == 'DELIVERED' and status['capacityReleased'] is True
        assert admission(c) == 'CLOSED' and not status['confirmationAllowed']
        assert c.purchases.get(original.purchase_id) == original
        assert c.purchases.latest_released_inventory(hx(c.purchase.deed_launcher_id)) is None
        assert status['terminalReceipt']['transactionId'] == hx(bundle.name())
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        c.presales = PresaleStore(c.presale_path)
        c.records[status['terminalReceipt']['outputCoinId']].update(spent=True, spent_block_index=c.height)
        assert await recover_paid(c) == status
        with c.purchases._connect() as db:
            db.execute("UPDATE payment_purchase_admission SET state='SIGNING'")
        with pytest.raises(PaymentPurchaseConflict,match='checkout state'):
            await recover_paid(c)
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem', ['voucher_only','wrong_transaction','missing_output','different_input_spend','changed_payment','split_heights','immature','changed_artifact'])
async def test_uncertain_paid_delivery_retains_capacity(tmp_path,monkeypatch,problem):
    c,bundle = await delivered_case(tmp_path,monkeypatch)
    try:
        voucher=c.presales.voucher_for_purchase(hx(c.purchase.purchase_id))
        if problem=='voucher_only':
            c.presales._conn.execute("UPDATE voucher_records_v2 SET state='ESCROWED'")
        elif problem=='wrong_transaction':
            c.presales._conn.execute("UPDATE voucher_records_v2 SET redemption_bundle_id=?", ('0x'+'f1'*32,))
        elif problem=='missing_output': c.records.pop(voucher['deliveryOutputCoinId'])
        elif problem=='different_input_spend': c.spends[(hx(bundle.coin_spends[-1].coin.name()),240)]=c.initial.coin_spends[0].to_json_dict()
        elif problem=='changed_payment':
            value=copy.deepcopy(voucher['settlementReceipt']);value['evidence']['paymentIntentId']='pi_other'
            from solslot_api.inventory_extension_store import canonical
            c.presales._conn.execute('UPDATE voucher_records_v2 SET settlement_receipt_json=?',(canonical(value),))
        elif problem=='split_heights': c.records[voucher['deliveryOutputCoinId']]['confirmed_block_index']=241
        elif problem=='immature': c.height=241
        else: c.genesis['artifactHash']='0x'+'f2'*32
        with pytest.raises((PaymentPurchaseConflict,ValueError,TypeError,KeyError)):
            await recover_paid(c)
        assert admission(c)=='SIGNING' and c.purchases.checkout_terminal(hx(c.purchase.purchase_id)) is None
    finally:close(c)
