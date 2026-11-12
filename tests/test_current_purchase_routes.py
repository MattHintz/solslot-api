"""HTTP admission and side-effect separation, using an explicit fake transport.

Native proof, SQLite durability and real CLVM purchase execution have separate
tests. These checks verify that HTTP cannot bypass those service boundaries.
"""
from types import SimpleNamespace

from chia_rs.sized_bytes import bytes32
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

from solslot_api import generation_customer_purchase_routes as routes
from solslot_api.config import get_settings
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution

GEN='0x'+'01'*32
VAULT='0x'+'02'*32
INTENT='0x'+'03'*32
DEED='0x'+'04'*32
ORIGIN={'Origin':'https://solslot.com','Sec-Fetch-Site':'same-origin'}


@pytest.fixture
def checkout(monkeypatch):
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GEN,
        generation_customer_purchase_enabled=True,generation_customer_public_origin='https://solslot.com',
        vault_session_jwt_secret='synthetic-jwt-only-for-local-tests-'+'x'*32)
    service=object.__new__(CurrentNativePurchaseExecution)
    service.settings=settings;service.store=SimpleNamespace(generation_id=GEN,review_for_request=lambda *a,**k:None)
    service.policy=SimpleNamespace(buyer_vault=bytes32.from_hexstr(VAULT))
    events=[];current=SimpleNamespace(owner_key='0x'+'05'*48,auth_type='chia_bls',session_id='first')
    def owner(*args):
        if current.session_id=='expired':raise HTTPException(401,detail='synthetic sensitive provider detail')
        return current
    monkeypatch.setattr(routes,'owner',owner)
    def review(identity,*,browser_hash):
        events.append(('read',identity,browser_hash))
        return {'intentId':identity,'generationId':GEN}
    async def quote(key,deed,*,browser_hash):
        events.append(('quote',key,deed,browser_hash));return {'intentId':INTENT}
    async def reserve(identity,*,browser_hash):events.append(('prepare',identity,browser_hash))
    def request_reservation(identity,*,browser_hash):
        events.append(('request',identity,browser_hash))
        return {'schema':'solslot.current-reservation-request.v1','intentId':identity,
            'generationId':GEN,'receivingVaultLauncherId':VAULT,
            'reservationClaimHash':'0x'+'07'*32,'quantity':1,'requestedAt':110}
    async def dispatch(identity,phase,*,browser_hash):
        events.append(('dispatch',identity,phase,browser_hash));return {'stage':'MEMPOOL'}
    async def reconcile(identity,phase,*,browser_hash):
        events.append(('observe',identity,phase,browser_hash));return {'stage':'CONFIRMED'}
    service.review=review;service.quote=quote;service.prepare_reservation=reserve
    service.request_reservation=request_reservation
    async def inventory():events.append(('inventory',));return {'generationId':GEN,'items':[]}
    async def payer_coins(identity,keys,*,browser_hash,public_key_kind='raw'):
        events.append(('payer-coins',identity,keys,public_key_kind));return {'generationId':GEN,'candidates':[]}
    service.inventory=inventory;service.payer_coins=payer_coins
    service._funding_context=lambda:None
    service.dispatch=dispatch;service.reconcile=reconcile;service._existing=lambda *a:None
    service._saved=lambda *a:{'reservationClaim':None}
    app=FastAPI();app.include_router(routes.router);app.state.generation_customer_purchase=service
    app.dependency_overrides[get_settings]=lambda:settings
    with TestClient(app) as client:
        yield SimpleNamespace(client=client,settings=settings,service=service,events=events,owner=current,app=app)


def url(suffix=''):
    return '/customer/purchases/'+VAULT+'/'+INTENT+suffix


@pytest.mark.parametrize('suffix,body',[
    ('/quotes',{'requestKey':'one','deedLauncherIds':[DEED,'0x'+'08'*32]}),
    ('/'+INTENT+'/reservation',{}),
    ('/'+INTENT+'/payment-review',{'paymentCoinId':DEED,'paymentPublicKey':'0x'+'01'*48}),
    ('/'+INTENT+'/payer-coins',{'publicKeys':['0x'+'01'*48],'paymentPublicKeyKind':'synthetic'}),
    ('/'+INTENT+'/payer-authorization',{'buyerOffer':'offer1synthetic'}),
    ('/'+INTENT+'/issuer-review',{'buyerOffer':'offer1synthetic'}),
    ('/'+INTENT+'/delivery',{'buyerOffer':'offer1synthetic','issuerSignature':'0x'+'00'*96}),
])
def test_evm_vault_cannot_begin_or_authorize_native_payment(checkout,suffix,body):
    c=checkout;c.owner.auth_type='evm';c.owner.owner_key='0x'+'05'*20
    response=c.client.post('/customer/purchases/'+VAULT+suffix,
        json={'generationId':GEN,**body},headers=ORIGIN)
    assert response.status_code==403 and c.events==[]
    assert response.json()['detail']['code']=='CURRENT_CHECKOUT_PAYMENT_WALLET_NOT_ALLOWED'
    assert 'Chia-wallet vault' in response.json()['detail']['message']
    assert 'Reconnect' not in response.text and response.headers['cache-control']=='no-store'


def test_evm_vault_retains_status_and_inventory_reads_without_mutation(checkout):
    c=checkout;c.owner.auth_type='evm'
    assert c.client.get(url()).status_code==200
    assert c.client.get('/customer/purchases/'+VAULT+'/inventory').status_code==200
    assert [event[0]for event in c.events]==['read','inventory']


@pytest.mark.parametrize('quantity',[1,2,3])
def test_evm_interrupted_quote_recovers_only_the_exact_saved_selection(checkout,quantity):
    c=checkout;c.owner.auth_type='evm'
    deeds=['0x'+f'{i:02x}'*32 for i in range(10,10+quantity)]
    c.service.store.review_for_request=lambda key,**k:{'intentId':INTENT}if key=='saved'else None
    c.service.review=lambda identity,**k:{'intentId':identity,'deedLauncherIds':deeds}
    target='/customer/purchases/'+VAULT+'/quotes'
    body={'generationId':GEN,'requestKey':'saved','deedLauncherIds':list(reversed(deeds))}
    assert c.client.post(target,json=body,headers=ORIGIN).json()['intentId']==INTENT
    assert c.client.post(target,json={**body,'requestKey':'new'},headers=ORIGIN).status_code==403
    assert c.client.post(target,json={**body,'deedLauncherIds':[DEED]},headers=ORIGIN).status_code==403
    assert c.events==[] # No new quote, signatures, reservation or dispatch.


@pytest.mark.parametrize('claim_type',[routes.CurrentDeliveryClaim,routes.CurrentDeliveryBatch])
def test_existing_evm_authorized_delivery_can_continue_only_its_exact_offer(checkout,monkeypatch,claim_type):
    c=checkout
    monkeypatch.setattr(routes,'context',lambda *a:(c.service,'original-owner-binding','evm'))
    claim=claim_type.model_construct(buyer_offer='offer1previouslysigned')
    c.service._saved=lambda identity,binding:{'deliveryClaim':claim}
    assert routes.delivery_context(None,None,VAULT,INTENT,claim.buyer_offer)==(c.service,'original-owner-binding')
    with pytest.raises(HTTPException)as denied:
        routes.delivery_context(None,None,VAULT,INTENT,'offer1replacement')
    assert denied.value.status_code==403 and c.events==[]


@pytest.mark.parametrize('quantity',[2,3])
def test_quantity_reaches_one_current_order_without_single_order_loop(checkout,quantity):
    c=checkout;ids=['0x'+f'{i:02x}'*32 for i in range(10,10+quantity)]
    reply=c.client.post('/customer/purchases/'+VAULT+'/quotes',json={
        'generationId':GEN,'requestKey':'one-batch','deedLauncherIds':ids},headers=ORIGIN)
    assert reply.status_code==200
    assert len(c.events)==1 and c.events[0][0:3]==('quote','one-batch',ids)


@pytest.mark.parametrize('selection',[
    {},{'deedLauncherId':DEED,'deedLauncherIds':[DEED]},
    {'deedLauncherIds':[]},{'deedLauncherIds':[DEED,DEED]},
    {'deedLauncherIds':['0x'+f'{i:02x}'*32 for i in range(26)]},
])
def test_invalid_batch_selection_cannot_create_partial_orders(checkout,selection):
    c=checkout
    reply=c.client.post('/customer/purchases/'+VAULT+'/quotes',json={
        'generationId':GEN,'requestKey':'one-batch',**selection},headers=ORIGIN)
    assert reply.status_code==422 and c.events==[]


def test_owner_session_failure_precedes_every_service_read(checkout):
    c=checkout;c.owner.session_id='expired'
    response=c.client.get(url())
    assert response.status_code==401 and c.events==[]
    assert 'sensitive' not in response.text and response.headers['cache-control']=='no-store'


@pytest.mark.parametrize('suffix,body',[
    ('/quotes',{'requestKey':'one','deedLauncherId':DEED}),
    ('/'+INTENT+'/reservation',{}),
    ('/'+INTENT+'/payment-review',{'paymentCoinId':DEED,'paymentPublicKey':'0x'+'01'*48}),
    ('/'+INTENT+'/payer-coins',{'publicKeys':['0x'+'01'*48]}),
    ('/'+INTENT+'/issuer-review',{'buyerOffer':'offer1synthetic'}),
    ('/'+INTENT+'/payer-authorization',{'buyerOffer':'offer1synthetic'}),
    ('/'+INTENT+'/delivery',{'buyerOffer':'offer1synthetic','issuerSignature':'0x'+'00'*96}),
])
def test_every_mutation_requires_same_origin_and_exact_generation(checkout,suffix,body):
    c=checkout;target='/customer/purchases/'+VAULT+suffix
    assert c.client.post(target,json={'generationId':GEN,**body}).status_code==403
    assert c.client.post(target,json={'generationId':'0x'+'09'*32,**body},headers=ORIGIN).status_code==409
    assert c.events==[]


def test_status_get_only_observes_existing_phases(checkout):
    c=checkout
    for _ in range(3):assert c.client.get(url()).status_code==200
    assert [e[0] for e in c.events]==['read']*3
    c.events.clear();c.service._existing=lambda *a:{'stage':'RECONCILING'}
    response=c.client.get(url())
    assert response.json()['delivery']['stage']=='CONFIRMED'
    assert [e[0] for e in c.events]==['read','observe','observe','observe']
    assert response.json()['release']['stage']=='CONFIRMED'


def test_status_exposes_expiry_only_after_reconciliation_and_bound_proof(checkout,monkeypatch):
    from solslot_api import generation_customer_purchase_worker as worker
    c=checkout
    c.service.review=lambda identity,*,browser_hash:{'intentId':identity,'quoteExpired':True,'payerAuthorizationSaved':False}
    c.service._existing=lambda identity,phase,binding: {'stage':'PREPARED'} if phase=='RESERVATION' else None
    monkeypatch.setattr(worker,'expired_unsubmitted_reservation',lambda service,identity,binding: c.events.append(('proof',identity)) or True)
    reply=c.client.get(url())
    assert reply.status_code==200 and reply.json()['reservationUnsubmittedExpired'] is True
    assert [e[0] for e in c.events]==['observe','proof']


@pytest.mark.parametrize('quote_expired,payer_saved',[(True,False),(False,False),(True,True)])
def test_status_without_expiry_proof_preserves_the_original_review_contract(checkout,monkeypatch,quote_expired,payer_saved):
    from solslot_api import generation_customer_purchase_worker as worker
    c=checkout
    original={'intentId':INTENT,'quoteExpired':quote_expired,'payerAuthorizationSaved':payer_saved}
    c.service.review=lambda identity,*,browser_hash:dict(original)
    c.service._existing=lambda identity,phase,binding:{'stage':'PREPARED'} if phase=='RESERVATION' else None
    monkeypatch.setattr(worker,'expired_unsubmitted_reservation',lambda service,identity,binding:c.events.append(('proof',identity)) or False)
    reply=c.client.get(url())
    assert reply.status_code==200 and reply.json()=={**original,'reservation':{'stage':'CONFIRMED'}}
    assert [e[0]for e in c.events]==(['observe','proof']if quote_expired and not payer_saved else ['observe'])
    assert reply.headers['cache-control']=='no-store'


def test_inventory_get_cannot_quote_reserve_or_dispatch(checkout):
    c=checkout;target='/customer/purchases/'+VAULT+'/inventory'
    for _ in range(3):assert c.client.get(target).status_code==200
    assert c.events==[('inventory',)]*3
    c.owner.session_id='expired';c.events.clear()
    assert c.client.get(target).status_code==401 and not c.events


def test_explicit_public_key_discovery_stays_separate_from_receiver_and_dispatch(checkout):
    c=checkout;keys=['0x'+'01'*48]
    response=c.client.post(url('/payer-coins'),json={'generationId':GEN,'publicKeys':keys},headers=ORIGIN)
    assert response.status_code==200 and c.events==[('payer-coins',INTENT,keys,'raw')]
    assert c.owner.auth_type=='chia_bls'
    c.events.clear()
    assert c.client.post(url('/payer-coins'),json={'generationId':GEN,'publicKeys':keys,'paymentPublicKeyKind':'synthetic'},headers=ORIGIN).status_code==200
    assert c.events==[('payer-coins',INTENT,keys,'synthetic')]
    assert c.client.post(url('/payer-coins'),json={'generationId':GEN,'publicKeys':keys,'paymentPublicKeyKind':'unknown'},headers=ORIGIN).status_code==422
    assert c.client.post(url('/payer-coins'),json={'generationId':GEN,'publicKeys':keys,'privateKey':'synthetic'},headers=ORIGIN).status_code==422


def test_reconnect_preserves_binding_and_owner_change_replaces_it(checkout):
    c=checkout;c.client.get(url());first=c.events[-1][-1]
    c.owner.session_id='new-session';c.client.get(url())
    assert c.events[-1][-1]==first
    c.owner.owner_key='0x'+'06'*48;c.client.get(url())
    assert c.events[-1][-1]!=first


def test_write_disabled_and_other_vault_cannot_reach_purchase_service(checkout):
    c=checkout;c.settings.generation_customer_purchase_enabled=False
    assert c.client.get(url()).status_code==503 and not c.events
    c.settings.generation_customer_purchase_enabled=True
    c.service.policy.buyer_vault=bytes32.from_hexstr(DEED)
    assert c.client.get(url()).status_code==503 and not c.events


def test_explicit_reservation_post_only_queues_without_waiting_for_signing_or_dispatch(checkout):
    c=checkout;response=c.client.post(url('/reservation'),json={'generationId':GEN},headers=ORIGIN)
    assert response.status_code==200 and response.json()=={
        'schema':'solslot.current-reservation-request.v1','intentId':INTENT,
        'generationId':GEN,'receivingVaultLauncherId':VAULT,
        'reservationClaimHash':'0x'+'07'*32,'quantity':1,'requestedAt':110}
    assert [e[0] for e in c.events]==['request']
    assert response.headers['cache-control']=='no-store'


def test_client_cannot_supply_claim_destinations_or_amounts(checkout):
    c=checkout
    for extra in ({'amountMojos':'1'},{'reservation':{}},{'receivingVaultLauncherId':DEED}):
        response=c.client.post('/customer/purchases/'+VAULT+'/quotes',headers=ORIGIN,
            json={'generationId':GEN,'requestKey':'one','deedLauncherId':DEED,**extra})
        assert response.status_code==422
    assert not c.events


def test_provider_objects_never_become_user_messages(checkout):
    c=checkout
    async def reject(*a,**kw):raise HTTPException(503,detail={'providerSecret':'synthetic-must-stay-private'})
    c.service.quote=reject
    response=c.client.post('/customer/purchases/'+VAULT+'/quotes',headers=ORIGIN,
        json={'generationId':GEN,'requestKey':'one','deedLauncherId':DEED})
    assert response.status_code==503 and 'synthetic-must-stay-private' not in response.text
    assert response.json()['detail']['code']=='CURRENT_CHECKOUT_STEP_UNAVAILABLE'


def test_closed_funding_rejects_reservation_before_private_signatures(checkout):
    c=checkout
    def closed():raise ValueError('CURRENT_EXECUTION_BOUNDED_NATIVE_FUNDING_REQUIRED')
    c.service._funding_context=closed
    response=c.client.post(url('/reservation'),json={'generationId':GEN},headers=ORIGIN)
    assert response.status_code==409 and c.events==[]


@pytest.mark.asyncio
async def test_actual_application_mounts_checkout_with_no_purchase_authority(monkeypatch):
    from httpx import ASGITransport,AsyncClient
    from solslot_api.app import app
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GEN,
        generation_customer_purchase_enabled=False,generation_customer_public_origin='https://solslot.com')
    app.dependency_overrides[get_settings]=lambda:settings
    monkeypatch.setattr(routes,'owner',lambda *args:None)
    try:
        async with AsyncClient(transport=ASGITransport(app=app),base_url='https://solslot.com') as client:
            response=await client.get(url())
        assert response.status_code==503 and response.json()['detail']['code']=='CURRENT_CHECKOUT_NOT_OPEN'
    finally:app.dependency_overrides.pop(get_settings,None)
