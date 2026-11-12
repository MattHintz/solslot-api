"""The complete deployment boundary is checked before a document scan."""
import asyncio
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.generation_customer_identity_runtime import CurrentCustomerIdentityRuntime
import solslot_api.generation_customer_identity_runtime as runtime_module
import solslot_api.generation_customer_identity_routes as routes
from tests.test_generation_customer_identity_context import profile


def service():
    value=CurrentCustomerIdentityRuntime.__new__(CurrentCustomerIdentityRuntime)
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0])
    now=[1000]
    value.settings=SimpleNamespace();value.clock=lambda:now[0];value.profile=lambda:pins
    value.compatibility={'status':'NOT_CHECKED','checkedAt':None}
    return value,pins,now


@pytest.mark.asyncio
async def test_incompatible_adapter_blocks_before_reservation_or_native_reads(monkeypatch):
    value,pins,now=service();calls=[]
    def incompatible(*args):
        calls.append(1);raise ValueError('CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED')
    monkeypatch.setattr(runtime_module,'read_current_identity_compatibility',incompatible)
    async def forbidden(*args,**kwargs):raise AssertionError('No reservation or native read before compatibility')
    value.request_reads=forbidden
    for _ in range(2):
        with pytest.raises(ValueError,match='PROOF_VERSION_UNSUPPORTED'):
            await value.reserve('0x'+'81'*32,object())
    assert calls==[1] and not value.compatibility_ready(pins)
    now[0]+=30
    with pytest.raises(ValueError):await value.refresh_compatibility()
    assert len(calls)==2


@pytest.mark.asyncio
async def test_cached_compatible_check_is_coalesced_and_never_renews_its_time(monkeypatch):
    value,pins,now=service();calls=[]
    def compatible(settings,selected,checked):
        calls.append(1)
        return {'status':'READY','checkedAt':checked,'profileHash':selected.commitment,
            'proofVersions':list(selected.accepted_proof_versions),'blockNumber':123}
    monkeypatch.setattr(runtime_module,'read_current_identity_compatibility',compatible)
    await asyncio.gather(*(value.refresh_compatibility()for _ in range(4)))
    assert calls==[1] and value.compatibility_ready(pins)
    now[0]+=29;await value.refresh_compatibility()
    assert calls==[1] and value.compatibility['checkedAt']==1000
    now[0]+=32;assert not value.compatibility_ready(pins)
    await value.refresh_compatibility();assert len(calls)==2 and value.compatibility_ready(pins)
    now[0]=999;assert not value.compatibility_ready(pins)


@pytest.mark.asyncio
async def test_wrong_profile_and_unexpected_provider_details_fail_closed(monkeypatch):
    value,pins,now=service()
    def wrong(*args):return {'status':'READY','checkedAt':1000,'profileHash':'wrong','proofVersions':list(pins.accepted_proof_versions)}
    monkeypatch.setattr(runtime_module,'read_current_identity_compatibility',wrong)
    with pytest.raises(ValueError,match='COMPATIBILITY_UNAVAILABLE'):await value.refresh_compatibility()
    assert not value.compatibility_ready(pins)
    now[0]+=30
    def unavailable(*args):raise RuntimeError('private-provider-body-must-never-escape')
    monkeypatch.setattr(runtime_module,'read_current_identity_compatibility',unavailable)
    with pytest.raises(ValueError,match='COMPATIBILITY_UNAVAILABLE'):await value.refresh_compatibility()
    assert 'private-provider' not in str(value.compatibility)


def test_known_adapter_rejection_has_a_safe_actionable_message(caplog):
    result=routes.failure(HTTPException(400,detail='Simulation reverted: UnsupportedProofVersion(0xsecret-proof)'))
    assert result.detail['code']=='CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED'
    assert 'compatibility update' in result.detail['message']
    assert 'secret-proof' not in str(result.detail)+caplog.text


@pytest.mark.asyncio
async def test_relay_error_remains_readable_to_existing_clients(monkeypatch):
    import solslot_api.enrollment_permit_runtime as permit
    monkeypatch.setattr(routes,'mutation',lambda *args:None)
    monkeypatch.setattr(routes,'owner',lambda *args:None)
    monkeypatch.setattr(permit,'decode_enrollment',lambda _:SimpleNamespace(vault='0x'+'81'*32))
    async def rejected(*args,**kwargs):raise HTTPException(400,detail='Simulation reverted: UnsupportedProofVersion(0xprivate)')
    monkeypatch.setattr(routes,'runtime',lambda *args:SimpleNamespace(request_reads=rejected))
    with pytest.raises(HTTPException)as caught:
        await routes.submit_relay(SimpleNamespace(data='0x00'),object(),SimpleNamespace(headers={}),object(),bls=False)
    assert caught.value.status_code==400
    assert isinstance(caught.value.detail,str) and 'compatibility update' in caught.value.detail
    assert caught.value.headers['X-Solslot-Error-Code']=='CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED'
    assert 'private' not in caught.value.detail
