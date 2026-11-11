from chia_rs.sized_bytes import bytes32
from tests.test_current_purchase_routes import checkout,GEN,VAULT,DEED,INTENT,ORIGIN
from tests.test_current_collection_issuer_policy import make_policy


def test_collection_quote_binds_each_authenticated_launcher_without_mutating_service(checkout):
    c=checkout;c.service.policy=make_policy()[0];calls=[]
    async def quote(key,deed,*,browser_hash,receiving_launcher,receiving_owner):
        calls.append((key,deed,browser_hash,receiving_launcher,receiving_owner));return {'intentId':INTENT}
    c.service.quote=quote
    second='0x'+'06'*32
    for launcher in (VAULT,second):
        response=c.client.post('/customer/purchases/'+launcher+'/quotes',
            json={'generationId':GEN,'requestKey':'same','deedLauncherId':DEED},headers=ORIGIN)
        assert response.status_code==200
    assert calls[0][3]==bytes32.from_hexstr(VAULT) and calls[1][3]==bytes32.from_hexstr(second)
    assert calls[0][2]!=calls[1][2]
    assert calls[0][4]==calls[1][4]==c.owner.owner_key
    assert not hasattr(c.service,'receiving_launcher')
    c.owner.auth_type='evm'
    response=c.client.post('/customer/purchases/'+VAULT+'/quotes',
        json={'generationId':GEN,'requestKey':'new','deedLauncherId':DEED},headers=ORIGIN)
    assert response.status_code==403 and len(calls)==2


def test_retained_single_quote_rejects_other_launcher_even_with_same_binding(monkeypatch):
    import pytest
    from types import SimpleNamespace
    from tests.test_native_purchases import _b32
    from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution
    service=CurrentNativePurchaseExecution.__new__(CurrentNativePurchaseExecution);service.policy=make_policy()[0]
    artifact=SimpleNamespace(deed_launcher_id=_b32(10),vault_launcher_id=_b32(11))
    service._review_saved=lambda *_:{'reservationClaim':SimpleNamespace(purchase_artifact={})}
    service.review=lambda *_args,**_kwargs:{'ok':True}
    monkeypatch.setattr('solslot_api.generation_customer_purchase_execution.purchase_artifact_v3_from_json',lambda _:artifact)
    assert service._same_quote('id',_b32(10),'binding',receiving_launcher=_b32(11))=={'ok':True}
    with pytest.raises(ValueError,match='RECEIVING_VAULT_CHANGED'):
        service._same_quote('id',_b32(10),'binding',receiving_launcher=_b32(12))


def test_collection_runtime_cannot_start_before_transition_and_fee_activation(monkeypatch):
    import pytest
    from types import SimpleNamespace
    from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution
    from solslot_api import generation_customer_purchase_execution as execution
    policy,_=make_policy();generation='0x'+policy.generation.hex()
    class Store:
        generation_id=generation
        def bind_execution_policy(self,*_):raise AssertionError('must not bind a new fee policy')
    monkeypatch.setattr(execution,'CurrentPurchaseExecutionStore',Store)
    settings=SimpleNamespace(network='testnet11',generation_customer_purchase_enabled=True,deployment_generation_id=generation)
    anchor=SimpleNamespace(issuance=SimpleNamespace(generation=policy.generation))
    with pytest.raises(ValueError,match='COLLECTION_CUTOVER_REQUIRED'):
        CurrentNativePurchaseExecution(settings=settings,anchor=anchor,provider=object(),policy=policy,store=Store(),fee_cap=100)
