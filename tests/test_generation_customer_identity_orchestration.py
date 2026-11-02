"""Closed defaults, bounded budgets, pure status and scoped identity routing."""
from types import SimpleNamespace
from dataclasses import replace
from hashlib import sha256
import copy
import httpx
import pytest
from fastapi import FastAPI,HTTPException
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_api.config import get_settings
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.generation_customer_identity_fees import CurrentIdentityAuthority
from solslot_api.generation_customer_identity_runtime import CurrentIdentityReads,CurrentCustomerIdentityRuntime
from solslot_api.generation_customer_identity_scope import current_identity_request
from solslot_api.generation_customer_runtime import GenerationCustomerRuntime
from tests.test_generation_customer_identity_context import profile


def authority(pins,**changes):
    data=dict(schema='solslot.current-customer-identity-authority.v1',network='testnet11',
        generationId=pins.generation_id,identityProfileHash=pins.commitment,
        relayerAddress=pins.trusted_direct_relayer,issuedAt=1000,expiresAt=2000,
        baseMaximumFeeWei=10_000_000_000_000,baseDailyFeeWei=50_000_000_000_000,
        fundingPuzzleHash='0x'+'61'*32,feeCoinIds=['0x'+'62'*32],
        maximumFeeParentMojos=2_000_000,maximumStampFeeMojos=1000)
    data.update(changes)
    return CurrentIdentityAuthority.model_validate(data)


@pytest.mark.parametrize('mutation',[{'expiresAt':1000+48*3600+1},{'expiresAt':1000},
    {'feeCoinIds':['0x'+'62'*32]*2},{'maximumStampFeeMojos':1_000_000_001},
    {'baseMaximumFeeWei':100_000_000_000_001},{'baseDailyFeeWei':1},
    {'maximumFeeParentMojos':1},{'network':'mainnet'}, {'issuedAt':True},
    {'expiresAt':'2000'},{'maximumStampFeeMojos':1.5}])
def test_identity_budget_cannot_broaden_time_fees_or_network(mutation):
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0])
    with pytest.raises(ValueError):authority(pins,**mutation)


def test_expired_or_foreign_identity_authority_cannot_be_reused():
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0]);policy=authority(pins)
    assert policy.require_live(pins,1000) is policy
    for now in (999,2000):
        with pytest.raises(ValueError):policy.require_live(pins,now)
    with pytest.raises(ValueError):authority(pins,identityProfileHash='0x'+'91'*32).require_live(pins,1000)
    with pytest.raises(ValueError):authority(pins,relayerAddress='0x'+'92'*20).require_live(pins,1000)


def test_primary_read_set_has_no_fallback_and_cannot_mutate_retained_records():
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0]);coin=pins.bridge_coins[0]
    raw={'coin':Coin(bytes32.from_hexstr(coin.parent_id),bytes32.from_hexstr(pins.bridge_policy_hash),uint64(1)).to_json_dict(),
        'confirmed_block_index':1,'spent_block_index':0}
    source={coin.coin_id:copy.deepcopy(raw),'0x'+'82'*32:None}
    reads=CurrentIdentityReads('0x'+'81'*32,'0x'+'82'*32,pins,source,None,1000,lambda:1000)
    got=reads.coin_record(coin.coin_id);got['coin']['amount']=99
    assert reads.coin_record(coin.coin_id)==raw and reads.coin_record('0x'+'82'*32) is None
    with pytest.raises(ValueError):reads.coin_record('0x'+'91'*32)
    with pytest.raises(ValueError):reads.children(['0x'+'91'*32])
    with pytest.raises(ValueError):reads.bridge_records('0x'+'92'*32)
    with pytest.raises(ValueError):reads.verified_event('0x'+'93'*32,reads.launcher)
    with pytest.raises(ValueError):replace(reads,clock=lambda:1061).coin_record(coin.coin_id)


def test_relay_scope_never_opens_legacy_or_mint_write_gate(monkeypatch):
    from solslot_api.credential_auth import require_alpha_writes,require_minting_writes,_require_credential_action
    from solslot_api.zkpassport_relay import _require_relay_writes
    doc,bindings=profile();pins=CurrentCustomerIdentityProfile.model_validate(doc)
    import solslot_api.generation_customer_context as context
    monkeypatch.setattr(context,'current_customer_launch_bindings',lambda *args,**kwargs:bindings)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=pins.generation_id,
        alpha_writes_enabled=False,zkpassport_base_evm_rpc_url='https://example.invalid')
    settings.model_copy=lambda *,update:SimpleNamespace(**{**vars(settings),**update})
    launcher='0x'+'81'*32
    snapshot={'generationId':pins.generation_id,'registrationId':'0x'+'82'*32,'owner':'0x'+'83'*20,
        'authType':'evm','checkedAt':1000,'vault':{'identityVerified':False,'identityStatus':'FRESH_ID_REQUIRED'}}
    customers=SimpleNamespace(index=object(),current_vault_snapshot=lambda _:snapshot)
    reads=CurrentIdentityReads(launcher,'0x'+'84'*32,pins,{},None,1000,lambda:1000,authority=authority(pins))
    with current_identity_request(settings,pins,launcher,customers,runtime=reads,clock=lambda:1000) as scope:
        _require_relay_writes(scope.settings)
        _require_credential_action(scope.settings,'relay',launcher)
        for guard in (require_alpha_writes,require_minting_writes):
            with pytest.raises(HTTPException):guard(scope.settings)
    with pytest.raises(HTTPException):_require_relay_writes(settings)
    with current_identity_request(settings,pins,launcher,customers,runtime=replace(reads,authority=None),clock=lambda:1000) as scope:
        with pytest.raises(HTTPException):_require_relay_writes(scope.settings)


@pytest.mark.asyncio
async def test_current_identity_get_is_pure_and_mutations_require_exact_generation_and_origin(monkeypatch):
    from solslot_api.generation_customer_identity_routes import router
    import solslot_api.generation_customer_identity_routes as routes
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0]);launcher='0x'+'81'*32
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=pins.generation_id,
        generation_customer_identity_enabled=True,generation_customer_public_origin='https://test')
    customers=GenerationCustomerRuntime.__new__(GenerationCustomerRuntime)
    customers.store=SimpleNamespace(generation_id=pins.generation_id)
    service=CurrentCustomerIdentityRuntime.__new__(CurrentCustomerIdentityRuntime)
    service.customers=customers;service.authority=authority(pins);service.clock=lambda:1000
    service.fee_submitter=None;service.health={'status':'READY'};service.profile=lambda:pins
    service.cached=lambda _:dict(vaultLauncherId=launcher,status='reserved')
    def forbidden(*a,**kw):raise AssertionError('GET status must not reconcile, sign or submit')
    service.request_reads=forbidden;service.reserve=forbidden
    monkeypatch.setattr(routes,'owner',lambda *a,**kw:SimpleNamespace(owner_key='0x'+'83'*20))
    app=FastAPI();app.include_router(router);app.state.generation_customers=customers;app.state.generation_customer_identity=service
    app.dependency_overrides[get_settings]=lambda:settings
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test',headers={'Origin':'https://test'}) as client:
        for _ in range(3):
            got=await client.get('/customer/identity/enrollments/'+launcher)
            assert got.status_code==200 and got.json()['status']=='reserved'
            assert got.headers['cache-control']=='no-store'
        assert (await client.post('/customer/identity/enrollments/'+launcher,json={'generationId':'0x'+'91'*32})).status_code==409
        assert (await client.post('/customer/identity/enrollments/'+launcher,json={'generationId':pins.generation_id},headers={'Origin':'https://attacker'})).status_code==403
        assert (await client.post('/customer/identity/enrollments/'+launcher,json={})).status_code==422
        app.state.generation_customer_identity=None
        assert (await client.get('/customer/identity/enrollments/'+launcher)).status_code==503


def test_disabled_identity_factory_reads_no_profile_credential_or_store(monkeypatch):
    from solslot_api.generation_customer_identity_factory import configured_current_customer_identity
    import solslot_api.generation_customer_identity_factory as factory
    def forbidden(*a,**kw):raise AssertionError('disabled identity must read nothing')
    monkeypatch.setattr(factory,'read_current_identity_profile',forbidden)
    assert configured_current_customer_identity(SimpleNamespace(generation_customer_identity_enabled=False),None) is None
