"""Default-closed price worker lifecycle for the current Testnet generation."""
import asyncio
import sqlite3
from types import SimpleNamespace
import pytest
from pydantic import ValidationError
from solslot_api.config import Settings
from solslot_api.generation_customer_purchase_store import CurrentCustomerPurchaseStore
from solslot_api.generation_price_demand import PriceDemandRuntime
import solslot_api.generation_price_demand_factory as factory

GEN='0x'+'01'*32


def test_disabled_price_factory_opens_no_journal_or_socket(monkeypatch):
    def forbidden(*args,**kwargs):raise AssertionError('disabled pricing touched resources')
    monkeypatch.setattr(factory,'CurrentCustomerPurchaseStore',forbidden)
    monkeypatch.setattr(factory,'PriceDemandSocketCollector',forbidden)
    assert factory.configured_price_demand(SimpleNamespace(generation_customer_pricing_enabled=False),customers=None,identity=None) is None


def test_enabled_settings_require_current_generation_identity_and_exact_socket():
    with pytest.raises(ValidationError,match='Testnet price demand'):
        Settings(runtime_environment='test',generation_customer_pricing_enabled=True)
    with pytest.raises(ValidationError,match='Testnet price demand'):
        Settings(runtime_environment='test',deployment_generation_id=GEN,generation_customer_pricing_enabled=True,
            generation_customer_identity_enabled=True,generation_customer_pricing_socket_gid=12,
            generation_customer_pricing_socket='/tmp/untrusted.sock')
    value=Settings(runtime_environment='test',deployment_generation_id=GEN,generation_customer_pricing_enabled=True,
        generation_customer_identity_enabled=True,generation_customer_pricing_socket_gid=12)
    assert value.generation_customer_pricing_socket=='/run/solslot-price-demand/input.sock'


def test_factory_binds_generation_identity_and_root_owned_socket(tmp_path,monkeypatch):
    class Customers:pass
    class Identity:pass
    customers=Customers();customers.store=SimpleNamespace(generation_id=GEN)
    identity=Identity();identity.customers=customers
    calls=[]
    class Collector:
        def __init__(self,path,**kwargs):calls.append((path,kwargs))
        async def status(self,**kwargs):return {}
        async def __call__(self):return {}
    monkeypatch.setattr(factory,'GenerationCustomerRuntime',Customers)
    monkeypatch.setattr(factory,'CurrentCustomerIdentityRuntime',Identity)
    monkeypatch.setattr(factory,'PriceDemandSocketCollector',Collector)
    settings=SimpleNamespace(generation_customer_pricing_enabled=True,network='testnet11',deployment_generation_id=GEN,
        generation_customer_pricing_socket='/run/solslot-price-demand/input.sock',
        generation_customer_pricing_socket_gid=12,payment_purchase_db_path=str(tmp_path/'payments.db'))
    worker=factory.configured_price_demand(settings,customers=customers,identity=identity)
    assert isinstance(worker,PriceDemandRuntime) and worker.enabled and worker.store.generation_id==GEN
    assert calls==[('/run/solslot-price-demand/input.sock',{'expected_uid':0,'expected_gid':12})]
    identity.customers=Customers()
    with pytest.raises(ValueError,match='CONFIGURATION_INVALID'):
        factory.configured_price_demand(settings,customers=customers,identity=identity)


@pytest.mark.asyncio
@pytest.mark.parametrize('health_failure',[False,True])
async def test_worker_records_failure_and_retries_without_automatic_provider_call(tmp_path,monkeypatch,health_failure):
    store=CurrentCustomerPurchaseStore(tmp_path/'payments.db',GEN)
    worker=PriceDemandRuntime(store=store,health=lambda **kw:{},collect=lambda:None,enabled=True,clock=lambda:1000)
    stop=asyncio.Event();calls=[];health=[]
    async def once():
        calls.append('attempt')
        if len(calls)==1:raise sqlite3.OperationalError('private db error')
        stop.set();return {'state':'IDLE'}
    monkeypatch.setattr(worker,'run_once',once)
    def record_health(lane,**kw):
        health.append((lane,kw['status']))
        if health_failure:raise TypeError('synthetic health write failure')
    monkeypatch.setattr(store,'lifecycle_health',record_health)
    await asyncio.wait_for(worker.run(stop,interval=1),timeout=4)
    assert calls==['attempt','attempt'] and health==[('price-refresh','UNAVAILABLE')]
