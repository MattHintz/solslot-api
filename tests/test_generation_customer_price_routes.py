"""Test authenticated price requests without wallets, providers or transactions."""
from types import SimpleNamespace
import pytest
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
from solslot_api.config import get_settings
from solslot_api.generation_customer_purchase_store import CurrentCustomerPurchaseStore
from solslot_api.generation_price_demand import PriceDemandRuntime
import solslot_api.generation_customer_price_routes as routes

GEN='0x'+'01'*32
VAULT='0x'+'ab'*32
ORIGIN='https://solslot.com'


@pytest.fixture
def harness(tmp_path,monkeypatch):
    store=CurrentCustomerPurchaseStore(tmp_path/'payments.db',GEN)
    calls=[]
    def health(*,now,required_until):
        return {'schema':'solslot.price-refresh-status.v1','network':'testnet11','checkedAt':now,
            'requiredUntil':required_until,'canQuote':False,'canRefresh':True,'status':'REFRESH_REQUIRED',
            'validUntil':None,'sourceCount':0,'signerCount':0,
            'quota':{'status':'AVAILABLE','remainingRequests':20}}
    async def collect():calls.append('provider')
    demand=PriceDemandRuntime(store=store,health=health,collect=collect,enabled=True,clock=lambda:1000)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GEN,generation_customer_public_origin=ORIGIN)
    app=FastAPI();app.include_router(routes.router);app.state.generation_price_demand=demand
    app.dependency_overrides[get_settings]=lambda:settings
    seen=[]
    monkeypatch.setattr(routes,'owner',lambda request,settings,launcher:seen.append(launcher))
    with TestClient(app) as client:yield client,store,calls,seen,settings,demand


def test_status_never_schedules_or_contacts_provider(harness):
    client,store,calls,seen,settings,demand=harness
    for _ in range(3):
        response=client.get('/customer/pricing/'+VAULT)
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        assert response.json()['job'] is None
    assert seen==[VAULT]*3 and store.price_refresh_job_status() is None and calls==[]


def test_refresh_is_authenticated_origin_and_generation_bound(harness,monkeypatch):
    client,store,calls,seen,settings,demand=harness
    url='/customer/pricing/'+VAULT+'/refresh'
    assert client.post(url,json={'generationId':GEN},headers={'origin':'https://other.example'}).status_code==403
    assert client.post(url,json={'generationId':'0x'+'02'*32},headers={'origin':ORIGIN}).status_code==409
    assert store.price_refresh_job_status() is None and calls==[] and seen==[]
    def reject(*args):raise HTTPException(401,detail={'code':'VAULT_SESSION_REQUIRED'})
    monkeypatch.setattr(routes,'owner',reject)
    assert client.post(url,json={'generationId':GEN},headers={'origin':ORIGIN}).status_code==401
    assert store.price_refresh_job_status() is None and calls==[]


def test_authorized_refresh_coalesces_and_does_not_collect(harness):
    client,store,calls,seen,settings,demand=harness
    url='/customer/pricing/'+VAULT+'/refresh'
    first=client.post(url,json={'generationId':GEN},headers={'origin':ORIGIN})
    second=client.post(url,json={'generationId':GEN},headers={'origin':ORIGIN})
    assert first.status_code==second.status_code==200
    assert first.json()['job']==second.json()['job']
    assert first.json()['job']['status']=='WAITING' and calls==[] and seen==[VAULT,VAULT]
    observed=client.get('/customer/pricing/'+VAULT).json()['job']
    assert observed['status']=='WAITING' and observed['attempts']==0
    assert calls==[]


def test_missing_or_mismatched_runtime_fails_closed(harness):
    client,store,calls,seen,settings,demand=harness
    settings.deployment_generation_id='0x'+'02'*32
    result=client.get('/customer/pricing/'+VAULT)
    assert result.status_code==503 and result.json()['detail']['code']=='CURRENT_PRICE_UNAVAILABLE'
    assert store.price_refresh_job_status() is None and calls==[]


def test_health_error_does_not_leak_private_provider_details(harness):
    client,store,calls,seen,settings,demand=harness
    def failure(**kwargs):raise RuntimeError('sensitive provider error detail')
    demand.health=failure
    result=client.get('/customer/pricing/'+VAULT)
    assert result.status_code==503 and 'sensitive provider' not in result.text
    assert store.price_refresh_job_status() is None and calls==[]


def test_real_owner_auth_rejects_missing_vault_session(harness,monkeypatch):
    from solslot_api import generation_customer_identity_routes as identity
    client,store,calls,seen,settings,demand=harness
    monkeypatch.setattr(routes,'owner',identity.owner)
    result=client.post('/customer/pricing/'+VAULT+'/refresh',json={'generationId':GEN},headers={'origin':ORIGIN})
    assert result.status_code==401 and store.price_refresh_job_status() is None and calls==[]


def test_owner_lookup_errors_are_sanitized_and_never_schedule(harness,monkeypatch):
    client,store,calls,seen,settings,demand=harness
    def failure(*args):raise RuntimeError('private owner store details')
    monkeypatch.setattr(routes,'owner',failure)
    result=client.post('/customer/pricing/'+VAULT+'/refresh',json={'generationId':GEN},headers={'origin':ORIGIN})
    assert result.status_code==503 and 'private owner store details' not in result.text
    assert store.price_refresh_job_status() is None and calls==[]


@pytest.mark.asyncio
async def test_application_mounts_pricing_without_enabling_it(monkeypatch):
    from httpx import ASGITransport,AsyncClient
    from solslot_api.app import app
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GEN,generation_customer_public_origin=ORIGIN)
    app.dependency_overrides[get_settings]=lambda:settings
    monkeypatch.setattr(routes,'owner',lambda *args:None)
    try:
        async with AsyncClient(transport=ASGITransport(app=app),base_url='https://solslot.com') as client:
            response=await client.get('/customer/pricing/'+VAULT)
        assert response.status_code==503 and response.json()['detail']['code']=='CURRENT_PRICE_UNAVAILABLE'
    finally:
        app.dependency_overrides.pop(get_settings,None)
