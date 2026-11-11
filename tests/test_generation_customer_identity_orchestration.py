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


@pytest.mark.asyncio
async def test_old_confirmed_receipt_remains_readable_and_sync_keeps_evm_evidence(tmp_path,monkeypatch):
    from solslot_api.generation_customer_identity_context import select_record_identity_profile
    import solslot_api.generation_customer_context as context
    doc,bindings=profile();old=CurrentCustomerIdentityProfile.model_validate(doc)
    path=tmp_path/'old.json';path.write_text(old.model_dump_json(by_alias=True))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=old.generation_id,alpha_writes_enabled=False,
        zkpassport_base_evm_rpc_url='https://example.invalid',generation_customer_identity_previous_profile_path=str(path),
        generation_customer_identity_previous_profile_hash='0x'+sha256(path.read_bytes()).hexdigest())
    settings.model_copy=lambda *,update:SimpleNamespace(**{**vars(settings),**update})
    monkeypatch.setattr(context,'current_customer_launch_bindings',lambda *args,**kwargs:bindings)
    doc['acceptedProofVersions'].append('0.22.0');current=CurrentCustomerIdentityProfile.model_validate(doc)
    h=lambda c:'0x'+c*64
    launcher=h('1');registration=h('2');root=h('3');coin=h('4');newcoin=h('5');tx=h('6');bridge=old.bridge_coins[0]
    receipt=dict(generationId=old.generation_id,identityProfileHash=old.commitment,vaultLauncherId=launcher,
        network='testnet11',policyVersion=2,identityAttestRoot=root,attestationLeafHash=h('7'),
        attestationProof={'bitpath':0,'siblings':[]},bridgePolicyHash=old.bridge_policy_hash,
        bridgeParentId=bridge.parent_id,bridgeAmount=1,bridgeCoinId=bridge.coin_id,evmTxHash=tx,
        chiaVaultCoinId=coin,enrolledAt=1)
    record=dict(vaultLauncherId=launcher,network='testnet11',policyVersion=2,status='chia_confirmed',
        bridgePolicyHash=old.bridge_policy_hash,bridgeParentId=bridge.parent_id,bridgeAmount=1,bridgeCoinId=bridge.coin_id,
        createdAt=1,updatedAt=1,identityDeployment={'schema':'solslot.current-customer-enrollment-binding.v1',
        'generationId':old.generation_id,'identityProfileHash':old.commitment,'registrationId':registration},receipt=receipt)
    class Ledger:
        def get_enrollment(self,_):return copy.deepcopy(record)
        def update_enrollment(self,value,**_):self.saved=value
    ledger=Ledger();snapshot={'generationId':old.generation_id,'registrationId':registration,'owner':'0x'+'01'*20,
        'authType':'evm','checkedAt':1000,'vault':{'identityVerified':True,'identityAttestRoot':root,'currentCoinId':coin}}
    service=CurrentCustomerIdentityRuntime.__new__(CurrentCustomerIdentityRuntime)
    service.settings=settings;service.ledger=ledger;service.clock=lambda:1000;service.funding_store=None
    service.customers=SimpleNamespace(index=object(),current_vault_snapshot=lambda _:snapshot)
    service.profile=lambda:current
    assert service.cached(launcher)['receipt']['identityProfileHash']==old.commitment
    class NativeCoin:
        def name(self):return bytes.fromhex(newcoin[2:])
    native=SimpleNamespace(identity_verified=True,root=bytes.fromhex(root[2:]),bridge_coin_id=bytes.fromhex(bridge.coin_id[2:]),
        coin=NativeCoin(),stamp_coin_id=bytes.fromhex(coin[2:]),confirmed_height=5)
    async def reads(*args,**kwargs):
        selected=select_record_identity_profile(settings,current,record)
        return SimpleNamespace(profile=selected),native
    service.request_reads=reads
    await service.sync(launcher)
    assert ledger.saved['receipt']['identityProfileHash']==old.commitment
    assert ledger.saved['receipt']['evmTxHash']==tx and ledger.saved['receipt']['chiaVaultCoinId']==newcoin


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
    service.refresh_compatibility=forbidden
    monkeypatch.setattr(routes,'owner',lambda *a,**kw:SimpleNamespace(owner_key='0x'+'83'*20))
    app=FastAPI();app.include_router(router);app.state.generation_customers=customers;app.state.generation_customer_identity=service
    app.dependency_overrides[get_settings]=lambda:settings
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test',headers={'Origin':'https://test'}) as client:
        assert (await client.get('/customer/identity/profile')).json()['enrollmentEnabled'] is False
        service.compatibility={'status':'READY','checkedAt':1000,'profileHash':pins.commitment,
            'proofVersions':list(pins.accepted_proof_versions),'blockNumber':123}
        assert (await client.get('/customer/identity/profile')).json()['enrollmentEnabled'] is True
        service.compatibility['checkedAt']=939
        assert (await client.get('/customer/identity/profile')).json()['enrollmentEnabled'] is False
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
