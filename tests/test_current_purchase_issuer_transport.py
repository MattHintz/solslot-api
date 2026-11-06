"""Current issuer shares the independently installed current signer mTLS lane."""
from types import SimpleNamespace
import httpx
import pytest
from chia_rs import G2Element
from solslot_api import generation_customer_purchase_issuer_client as module
from tests.test_current_purchase_private_boundary import policy

CURRENT_URLS=['https://10.77.0.10:9544','https://10.77.0.11:9544','https://10.77.0.12:9544']

def settings(**change):
    return SimpleNamespace(**dict(dict(network='testnet11',generation_customer_purchase_worker_enabled=True,
        zkpassport_validator_urls=CURRENT_URLS.copy()),**change))

@pytest.mark.parametrize('change',[
    {'network':'mainnet'}, {'generation_customer_purchase_worker_enabled':False},
    {'zkpassport_validator_urls':[u.replace(':9544',':9443')for u in CURRENT_URLS]},
    {'zkpassport_validator_urls':list(reversed(CURRENT_URLS))},
    {'zkpassport_validator_urls':CURRENT_URLS[:2]+['https://attacker.invalid:9544']},
    {'zkpassport_validator_urls':CURRENT_URLS+['https://10.77.0.13:9544']},
])
def test_issuer_cannot_drift_to_legacy_or_arbitrary_transport(change):
    with pytest.raises(ValueError,match='FIXED_PRIVATE_TOPOLOGY'):
        module.PrivateCurrentIssuerClient(settings(**change))

@pytest.mark.asyncio
async def test_health_and_signing_both_use_exact_current_index_two_lane(monkeypatch):
    p=policy();seen=[]
    request={'generationId':'0x'+p.generation.hex(),'policyHash':p.commitment,'claimHash':'0x'+'08'*32}
    signature=G2Element()
    def respond(r):
        seen.append((r.method,str(r.url)))
        if r.url.path.endswith('/status'):
            return httpx.Response(200,json={**request,'checkedAt':1100,'expiresAt':p.expires_at,
                'remainingPurchases':p.maximum_purchases,'canSign':True})
        return httpx.Response(200,json={**request,'signature':'0x'+bytes(signature).hex()})
    monkeypatch.setattr(module,'_private_validator_client',lambda _:httpx.AsyncClient(transport=httpx.MockTransport(respond)))
    client=module.PrivateCurrentIssuerClient(settings())
    assert (await client.status(p,now=1100))['canSign'] is True
    assert await client(request)==signature
    assert seen==[
        ('GET',CURRENT_URLS[2]+'/v1/generation/purchase/issuer/status'),
        ('POST',CURRENT_URLS[2]+'/v1/generation/purchase/issuer/sign')]

@pytest.mark.asyncio
async def test_correct_transport_never_accepts_mismatched_policy_health(monkeypatch):
    p=policy()
    def respond(r):
        return httpx.Response(200,json={'generationId':'0x'+p.generation.hex(),'policyHash':'0x'+'00'*32,
            'checkedAt':1100,'expiresAt':p.expires_at,'remainingPurchases':1,'canSign':True})
    monkeypatch.setattr(module,'_private_validator_client',lambda _:httpx.AsyncClient(transport=httpx.MockTransport(respond)))
    with pytest.raises(ValueError,match='HEALTH_CHANGED'):
        await module.PrivateCurrentIssuerClient(settings()).status(p,now=1100)


def current_configuration(urls):
    from solslot_api.config import Settings
    return Settings(_env_file=None,network='testnet11',deployment_generation_id='0x'+'01'*32,
        alpha_writes_enabled=False,generation_customer_enabled=True,generation_customer_identity_enabled=True,
        generation_customer_purchase_enabled=True,generation_customer_purchase_funding_enabled=True,
        generation_customer_purchase_worker_enabled=True,generation_customer_purchase_policy_path='/synthetic/issuer.json',
        generation_customer_purchase_policy_hash='0x'+'02'*32,
        generation_customer_purchase_fee_authority_path='/synthetic/fees.json',
        generation_customer_purchase_fee_authority_hash='0x'+'03'*32,
        generation_customer_purchase_fee_signer_key_path='/run/synthetic-fee',zkpassport_validator_urls=urls)


def test_actual_runtime_configuration_and_issuer_client_accept_same_current_topology():
    configured=current_configuration(CURRENT_URLS)
    assert module.PrivateCurrentIssuerClient(configured).settings is configured


def test_actual_runtime_configuration_rejects_legacy_signer_port_before_startup():
    from pydantic import ValidationError
    with pytest.raises(ValidationError,match='automatic delivery'):
        current_configuration([u.replace(':9544',':9443')for u in CURRENT_URLS])
