"""Cash and deed journal recovery against deterministic Stripe and Chia fixtures."""
import asyncio
from contextlib import closing
from dataclasses import replace
import hmac
import json
from secrets import token_hex
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from httpx import AsyncClient,ASGITransport
from solslot_puzzles.payment_artifacts_v3 import purchase_batch_to_json

from solslot_api import vault_card_events as events
from solslot_api.vault_card_provider import metadata
from solslot_api.vault_card_store import VaultCardRecord,VaultCardStore
from solslot_api.stripe_delivery_store import get_stripe_delivery_store,StripeDeliveryNotFound
from .test_current_stripe_order import arrange,h


@pytest.fixture()
def scenario(tmp_path,monkeypatch):
    r=arrange(tmp_path,monkeypatch)
    s=r.settings
    s.payment_purchase_db_path=r.store.path
    s.stripe_delivery_db_path=str(tmp_path/'deliver.db')
    key=b'whsec_'+token_hex(24).encode()
    file=tmp_path/'hook.key'
    file.write_bytes(key)
    file.chmod(0o600)
    s.vault_card_webhook_key_file=str(file)
    store=VaultCardStore(r.store.path)
    batch=r.batch
    o=VaultCardRecord(purchase_id=h(batch.purchase_id),batch_hash=h(batch.batch_hash),generation_id=h(r.generation),
        collection_id=h(r.scope.collection),vault_launcher_id=h(r.launcher),destination_puzzle_hash=h(batch.vault_p2_puzzle_hash),
        deed_launcher_ids=tuple(h(x.deed_launcher_id) for x in batch.artifacts),reserved_coin_ids=(h(r.nonce),h(r.batch_nonce)),
        network='testnet11',mode='test',account_id=s.stripe_account_id,amount_minor=batch.total_rail_amount,currency='usd',
        expires_at=batch.quote_expires_at,batch=purchase_batch_to_json(batch),release_id=h(r.scope.release_id),
        original_coin_ids=tuple(map(h,r.scope.originals)),vault_coin_id=h(r.vault.coin.name()),credential_root=h(r.root),owner_key=h(r.owner_pk),owner_auth_type=1,policy_version=2,
        generation_anchor_hash=h(r.scope.anchor_hash),bridge_policy_hash=h(r.scope.anchor_hash),
        technology_fee_puzzle_hash=h(r.items[0].terms.protocol_treasury_puzzle_hash),
        primary_proceeds_puzzle_hash=h(r.items[0].terms.protocol_puzhash))
    store.save(o)
    store.begin_dispatch(o,{'expires_at':str(o.expires_at-121)},now=o.expires_at-2200)
    o=store.bind_session(o.purchase_id,'cs_test_Session123')
    pi='pi_Card123'
    evt={'id':'evt_Success123','object':'event','type':events.PAID,'created':r.now,'livemode':False,
        'data':{'object':{'id':pi,'object':'payment_intent','metadata':metadata(o)}}}
    charge=dict(id='ch_Card123',livemode=False,currency='usd',payment_intent=pi,paid=True,captured=True,
        amount_captured=o.amount_minor,refunded=False,amount_refunded=0,disputed=False,
        payment_method_details=dict(type='card',card=dict(funding='debit')))
    intent=dict(id=pi,livemode=False,created=r.now-2,status='succeeded',currency='usd',amount=o.amount_minor,
                amount_received=o.amount_minor,metadata=metadata(o),latest_charge=charge)
    session=dict(id=o.session_id,client_reference_id=o.purchase_id,payment_intent=pi,livemode=False,mode='payment',
        status='complete',payment_status='paid',currency='usd',amount_total=o.amount_minor,metadata=metadata(o))
    provider=SimpleNamespace(_api=AsyncMock(return_value={"object":"list","data":[],"has_more":False}),account=AsyncMock(return_value={'id':s.stripe_account_id}),retrieve_event=AsyncMock(return_value=evt),
        retrieve_payment_intent=AsyncMock(return_value=intent),retrieve_session=AsyncMock(return_value=session),
        refund_payment=AsyncMock(),retrieve_refund=AsyncMock())
    r.app.state.vault_card_checkout=SimpleNamespace(provider=provider)
    r.app.include_router(events.router)
    inbox=events.CardInbox(s.payment_purchase_db_path)
    from solslot_api import vault_stripe_protection as prot
    bind=Mock()
    can_refund=AsyncMock(return_value=False)
    refunded=Mock()
    monkeypatch.setattr(prot,'bind_card_payment',bind)
    monkeypatch.setattr(prot,'prepare_card_refund',can_refund)
    monkeypatch.setattr(prot,'mark_card_refunded',refunded)
    monkeypatch.setattr(events,'configured_validator_pubkeys',lambda _:r.items[0].terms.validator_pubkeys)
    return SimpleNamespace(**locals())


async def notify(t, *, sign=True):
    raw=json.dumps(t.evt,separators=(',',':')).encode()
    now=int(events.time.time())
    sig=hmac.digest(t.key,str(now).encode()+b'.'+raw,'sha256').hex()
    async with AsyncClient(transport=ASGITransport(app=t.r.app),base_url='https://tests.invalid') as cli:
        return await cli.post('/stripe/vault-card/webhook',content=raw,headers={'Stripe-Signature':f't={now},v1={sig if sign else "0"*64}'})


@pytest.mark.asyncio
async def test_signed_payment_resumes_once_and_waits_for_both_outputs(scenario,monkeypatch):
    t=scenario
    assert (await notify(t,sign=False)).status_code==401
    assert t.inbox.claim(t.r.now) is None
    assert [r.status_code for r in await asyncio.gather(notify(t),notify(t))]==[200,200]
    row=t.inbox.claim(t.r.now)
    assert row and t.inbox.claim(t.r.now) is None
    assert await events.advance(t.r.app,t.s,t.inbox,row,t.r.now)=='PENDING'
    ledger=get_stripe_delivery_store(t.s.stripe_delivery_db_path)
    op=ledger.get(t.o.purchase_id)
    assert op.state=='PAYMENT_VERIFIED' and op.evidence['paymentIntentId']==t.pi
    assert t.store.get(t.o.purchase_id).payment_intent_id==t.pi
    assert events.card_status(t.r.app,t.s,t.o)=='PROCESSING'
    restarted=events.CardInbox(t.s.payment_purchase_db_path)
    assert await events.advance(t.r.app,t.s,restarted,row,t.r.now)=='PENDING'
    assert ledger.get(t.o.purchase_id).receipt_hash==op.receipt_hash
    t.provider.retrieve_payment_intent.assert_awaited_once()
    original_get=ledger.get
    incomplete=replace(op,state='FINALIZED',confirmation_height=121,expected_delivery_output_coin_ids=t.o.reserved_coin_ids[:1])
    monkeypatch.setattr(ledger,'get',lambda _:incomplete)
    assert events.card_status(t.r.app,t.s,t.o)=='REVIEW_REQUIRED'
    complete=replace(incomplete,expected_delivery_output_coin_ids=t.o.reserved_coin_ids)
    monkeypatch.setattr(ledger,'get',lambda _:complete)
    assert events.card_status(t.r.app,t.s,t.o)=='DELIVERED'
    assert await events.advance(t.r.app,t.s,restarted,row,t.o.expires_at+10)=='DONE'
    t.provider.refund_payment.assert_not_awaited()
    monkeypatch.setattr(ledger,'get',original_get)


@pytest.mark.parametrize('change', ['amount','account','mode','vault','intent','refund','dispute','unpaid'])
@pytest.mark.asyncio
async def test_mismatch_never_queues_or_refunds(scenario,change):
    t=scenario
    assert (await notify(t)).status_code==200
    row=t.inbox.claim(t.r.now)
    if change=='amount':t.intent['amount_received']-=1
    if change=='account':t.provider.account.return_value={'id':'acct_other'}
    if change=='mode':t.charge['livemode']=True
    if change=='vault':t.session['metadata']['vault_launcher_id']=t.o.collection_id
    if change=='intent':t.session['payment_intent']='pi_Other'
    if change=='refund':t.charge['amount_refunded']=1
    if change=='dispute':t.charge['disputed']=True
    if change=='unpaid':t.session['payment_status']='unpaid'
    with pytest.raises(events.EvidenceMismatch):
        await events.advance(t.r.app,t.s,t.inbox,row,t.r.now)
    assert t.inbox.settlement(t.o.purchase_id) is None
    with pytest.raises(StripeDeliveryNotFound):
        get_stripe_delivery_store(t.s.stripe_delivery_db_path).get(t.o.purchase_id)
    t.provider.refund_payment.assert_not_awaited()


@pytest.mark.asyncio
async def test_delayed_paid_webhook_waits_for_both_returns_before_refunding(scenario):
    t=scenario
    assert (await notify(t)).status_code==200
    row=t.inbox.claim(t.r.now)
    now=t.o.expires_at+1
    assert await events.advance(t.r.app,t.s,t.inbox,row,now)=='PENDING'
    t.provider.refund_payment.assert_not_awaited()
    t.can_refund.return_value=True
    refund=dict(id='re_TestCard',currency=t.o.currency,amount=t.o.amount_minor,payment_intent=t.pi,
                metadata={'purchase_id':t.o.purchase_id},status='pending')
    t.provider.refund_payment.return_value=refund
    assert await events.advance(t.r.app,t.s,t.inbox,row,now)=='PENDING'
    assert events.card_status(t.r.app,t.s,t.o)=='PROCESSING'
    t.provider.retrieve_refund.return_value=dict(refund,status='succeeded')
    assert await events.advance(t.r.app,t.s,t.inbox,row,now)=='DONE'
    assert await events.advance(t.r.app,t.s,t.inbox,row,now)=='DONE'
    t.provider.refund_payment.assert_awaited_once()
    assert events.card_status(t.r.app,t.s,t.o)=='REFUNDED'
    t.refunded.assert_called_once()
    with pytest.raises(StripeDeliveryNotFound):
        get_stripe_delivery_store(t.s.stripe_delivery_db_path).get(t.o.purchase_id)


def test_signature_window_and_repeat_event_identity(scenario):
    t=scenario
    raw=json.dumps(t.evt).encode()
    past=t.r.now-301
    sig=hmac.digest(t.key,str(past).encode()+b'.'+raw,'sha256').hex()
    with pytest.raises(events.HTTPException) as error:
        events.verified_payload(raw,f't={past},v1={sig}',t.key,t.r.now)
    assert error.value.status_code==401
    row=(t.evt['id'],events.PAID,t.pi,t.o.purchase_id,t.pi)
    t.inbox.receive(row)
    t.inbox.receive(row)
    with pytest.raises(events.EvidenceMismatch):t.inbox.receive((*row[:4],'pi_other'))


@pytest.mark.asyncio
async def test_expiry_sweep_recovers_missed_stripe_event(scenario):
    from solslot_api.vault_card_recovery import recover_expired,expired_job
    t=scenario
    assert expired_job(t.inbox,t.r.now-2400) is None
    assert expired_job(t.inbox,t.o.expires_at+2)==t.o.purchase_id
    t.provider._api.return_value={'object':'list','data':[t.evt],'has_more':False}
    result=await recover_expired(t.r.app,t.s,t.inbox,t.store,t.provider,t.o,now=t.o.expires_at+2)
    assert result=='PENDING'
    assert t.inbox.claim(t.o.expires_at+3)['event_id']==t.evt['id']
    t.provider.refund_payment.assert_not_awaited()


@pytest.mark.asyncio
async def test_long_outage_finds_original_paid_session_without_retrying_charge(scenario):
    from solslot_api.vault_card_recovery import recover_expired
    t = scenario
    with t.store.db() as db:
        db.execute('UPDATE vault_card_orders SET session_id=NULL WHERE purchase_id=?',(t.o.purchase_id,))
    order = t.store.get(t.o.purchase_id)
    session = dict(t.session, object='checkout.session', expires_at=t.o.session_expires_at,
                   payment_method_types=['card'])
    t.provider._api.side_effect = [
        {'object':'list','data':[session],'has_more':False},
        {'object':'list','data':[t.evt],'has_more':False}]
    t.provider.create_session = AsyncMock()
    state = await recover_expired(t.r.app,t.s,t.inbox,t.store,t.provider,order,now=t.r.now+172800)
    assert state == 'PENDING'
    assert t.store.get(order.purchase_id).session_id == t.session['id']
    assert t.inbox.claim(t.r.now+172800)['payment_id'] == t.pi
    assert all(call.args[0] == 'GET' for call in t.provider._api.await_args_list)
    t.provider.create_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_unpaid_returned_pair_has_a_terminal_buyer_receipt(scenario,monkeypatch):
    from solslot_api import vault_card_recovery as recovery, vault_stripe_protection as protection
    t=scenario
    later=t.o.expires_at+1
    assert recovery.expired_job(t.inbox,later)==t.o.purchase_id
    t.provider.retrieve_session.return_value=dict(t.session,status='expired',payment_status='unpaid',payment_intent=None)
    release=AsyncMock(return_value=True)
    monkeypatch.setattr(protection,'prepare_unpaid_release',release)
    state=await recovery.recover_expired(t.r.app,t.s,t.inbox,t.store,t.provider,t.o,now=later)
    assert state=='DONE'
    recovery.save_expiry(t.inbox,t.o.purchase_id,state)
    assert events.card_status(t.r.app,t.s,t.o)=='EXPIRED'
    assert t.inbox.settlement(t.o.purchase_id) is None
    t.provider.refund_payment.assert_not_awaited()


@pytest.mark.asyncio
async def test_external_refund_recovered_without_second_request(scenario):
    t=scenario
    assert (await notify(t)).status_code==200
    row=t.inbox.claim(t.r.now)
    t.can_refund.return_value=True
    refund=dict(id='re_TestCard',currency=t.o.currency,amount=t.o.amount_minor,payment_intent=t.pi,
        metadata={'rail':'solslot_vault_card','purchase_id':t.o.purchase_id},status='succeeded')
    t.provider._api.return_value={'object':'list','data':[refund],'has_more':False}
    assert await events.advance(t.r.app,t.s,t.inbox,row,t.o.expires_at+2)=='DONE'
    t.provider.refund_payment.assert_not_awaited()
    assert events.card_status(t.r.app,t.s,t.o)=='REFUNDED'


@pytest.mark.asyncio
async def test_unrelated_stripe_event_and_wrong_account(scenario):
    t=scenario
    t.evt['data']['object']['metadata']={}
    assert (await notify(t)).status_code==200
    assert t.inbox.claim(t.r.now) is None
    t.evt['account']='acct_Other'
    assert (await notify(t)).status_code==409
    t.evt['account']=t.s.stripe_account_id
    t.evt['livemode']=True
    assert (await notify(t)).status_code==409


@pytest.mark.asyncio
async def test_owner_checkout_signed_stripe_reply_reaches_funded_native_worker(tmp_path,monkeypatch):
    """Drive both mounted HTTP entry points, the funding journal, and native receipt preparation."""
    from .test_vault_stripe_protection import fixture,allocate
    from solslot_api import credential_auth
    f=await fixture(tmp_path,monkeypatch)
    x,o=f.x,f.o
    await allocate(f)
    x.app.include_router(events.router)
    async with AsyncClient(transport=ASGITransport(app=x.app),base_url=x.s.vault_card_return_origin) as client:
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,x.r.token)
        client.headers['Origin']=x.s.vault_card_return_origin
        checkout=await client.post(x.url+'/checkout',json={'purchaseId':o.purchase_id,'batchHash':o.batch_hash,'intent':'checkout'})
        assert checkout.status_code==200 and checkout.json()['checkoutUrl'].startswith('https://checkout.stripe.com/')
        order=x.store.get(o.purchase_id)
        pi=order.payment_intent_id or 'pi_BuyerCard123'
        now=int(events.time.time())
        event=dict(object='event',id='evt_BuyerCard123',type=events.PAID,livemode=False,created=now,
            data=dict(object=dict(id=pi,object='payment_intent',metadata=metadata(order))))
        session=dict(id=order.session_id,client_reference_id=o.purchase_id,payment_intent=pi,livemode=False,mode='payment',
            status='complete',payment_status='paid',currency=o.currency,amount_total=o.amount_minor,metadata=metadata(order))
        charge=dict(id='ch_BuyerCard123',livemode=False,currency=o.currency,payment_intent=pi,paid=True,captured=True,
            amount_captured=o.amount_minor,refunded=False,amount_refunded=0,disputed=False,
            payment_method_details=dict(type='card',card=dict(funding='credit')))
        intent=dict(id=pi,livemode=False,created=now-1,status='succeeded',currency=o.currency,amount=o.amount_minor,
            amount_received=o.amount_minor,metadata=metadata(order),latest_charge=charge)
        service=x.app.state.vault_card_checkout
        monkeypatch.setattr(service.provider,'retrieve_event',AsyncMock(return_value=event))
        monkeypatch.setattr(service.provider,'retrieve_payment_intent',AsyncMock(return_value=intent))
        monkeypatch.setattr(service.provider,'retrieve_session',AsyncMock(return_value=session))
        raw=json.dumps(event).encode()
        key=events.signing_key(x.s.vault_card_webhook_key_file)
        signature=hmac.digest(key,str(now).encode()+b'.'+raw,'sha256').hex()
        for _ in range(2):
            resp=await client.post('/stripe/vault-card/webhook',content=raw,headers={'Stripe-Signature':f't={now},v1={signature}'})
            assert resp.status_code==200
        inbox=events.CardInbox(x.s.payment_purchase_db_path)
        work=inbox.claim(now)
        assert await events.advance(x.app,x.s,inbox,work,now)=='PENDING'
        projection=(await client.get(x.url,params={'purchase':o.purchase_id})).json()
        assert projection['paymentReceived'] and projection['state']=='PROCESSING'
        op=f.worker.store.get(o.purchase_id)
        assert op.evidence['paymentIntentId']==pi
        prepared=await f.worker._advance(op)
        funded=f.fondos.cards.get(o.purchase_id)
        assert prepared.receipt_funding_input_coin_id==h(funded['coins']['receipt_parent'].name())
        assert funded['payment']==pi and len(set(o.reserved_coin_ids))==2
