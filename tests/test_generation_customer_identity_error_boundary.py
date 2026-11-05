"""A code-only session/runtime rejection must remain a readable 4xx/5xx."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException,Response
from solslot_api import generation_customer_identity_routes as routes

@pytest.mark.parametrize('code,status',[('CURRENT_ID_OWNER_CHANGED',403),('CURRENT_ID_RUNTIME_CHANGED',503),
    ('CURRENT_ID_UNAVAILABLE',503),('CURRENT_ID_NOT_STARTED',404)])
def test_code_only_rejection_always_has_safe_readable_message(code,status):
    error=routes.failure(HTTPException(status,detail={'code':code}))
    assert error.status_code==status
    assert error.detail['code']==code and isinstance(error.detail['message'],str) and error.detail['message']


def test_approved_code_never_reflects_arbitrary_provider_fields():
    error=routes.failure(HTTPException(400,detail={'code':'CURRENT_ID_STEP_UNAVAILABLE',
        'message':'SYNTHETIC_PRIVATE_PROOF_DO_NOT_REFLECT','proof':'SYNTHETIC_PRIVATE_PROOF_DO_NOT_REFLECT'}))
    assert set(error.detail)=={'code','message'}
    assert 'SYNTHETIC_PRIVATE'not in str(error.detail)


def test_fee_cap_rejection_explains_that_authorization_is_saved_and_nothing_was_sent():
    error=routes.failure(HTTPException(503,detail={'code':'CURRENT_ID_FEE_CAP_EXCEEDED'}))
    assert error.status_code==503
    assert error.detail['code']=='CURRENT_ID_FEE_CAP_EXCEEDED'
    assert 'No transaction was sent' in error.detail['message']
    assert 'approval is saved' in error.detail['message']


@pytest.mark.asyncio
async def test_relay_keeps_original_error_status_and_text_instead_of_key_error(monkeypatch):
    import solslot_api.enrollment_permit_runtime as permits
    monkeypatch.setattr(routes,'mutation',lambda *args:None)
    monkeypatch.setattr(permits,'decode_enrollment',lambda data:SimpleNamespace(vault='0x'+'01'*32))
    def unavailable(*args):raise HTTPException(503,detail={'code':'CURRENT_ID_RUNTIME_CHANGED'})
    monkeypatch.setattr(routes,'runtime',unavailable)
    with pytest.raises(HTTPException)as caught:
        await routes.submit_relay(SimpleNamespace(data='0x80'),SimpleNamespace(),Response(),SimpleNamespace(),bls=False)
    assert caught.value.status_code==503 and isinstance(caught.value.detail,str)
    assert caught.value.headers['X-Solslot-Error-Code']=='CURRENT_ID_RUNTIME_CHANGED'
    assert 'saved check' in caught.value.detail
