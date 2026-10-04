"""Status outages cannot discard, replace or dispatch a retained transaction."""
import pytest
from fastapi import HTTPException
from requests.exceptions import HTTPError
from solslot_api import zkpassport_relay as relay
from tests.test_relay_durable_recovery import rig, VAULT


@pytest.mark.parametrize('dispatch', [False, True])
@pytest.mark.parametrize('failure', [HTTPError('429 provider rate limit'), TimeoutError('timeout')])
def test_deployment_provider_outage_preserves_transaction(rig, monkeypatch, dispatch, failure):
    rig.setup('bls')()
    before = rig.ledger.get_relay_transaction(VAULT).copy()
    counts = rig.counts.copy()
    sends = rig.w3.eth.send_count
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(relay, '_check_saved_deployment', fail)
    def no_receipt(*args, **kwargs):
        pytest.fail('Receipt or dispatch must not follow a failed deployment check')
    monkeypatch.setattr(relay, '_relay_receipt_state', no_receipt)
    with pytest.raises(HTTPException) as error:
        relay._resume_saved(rig.settings, rig.record, rig.session, before, dispatch=dispatch)
    assert error.value.status_code == 502
    assert error.value.headers == {'Retry-After': '5'}
    assert 'preserved' in error.value.detail
    assert '429 provider' not in error.value.detail
    assert rig.ledger.get_relay_transaction(VAULT) == before
    assert rig.counts == counts and rig.w3.eth.send_count == sends


@pytest.mark.parametrize('dispatch', [False, True])
@pytest.mark.parametrize('status', [403, 409, 503])
def test_authorization_refusal_is_not_reclassified_as_retry(rig, monkeypatch, dispatch, status):
    rig.setup('bls')()
    before = rig.ledger.get_relay_transaction(VAULT).copy()
    refusal = HTTPException(status_code=status, detail='Original authority refusal')
    def fail(*args, **kwargs):
        raise refusal
    monkeypatch.setattr(relay, '_check_saved_deployment', fail)
    with pytest.raises(HTTPException) as error:
        relay._resume_saved(rig.settings, rig.record, rig.session, before, dispatch=dispatch)
    assert error.value is refusal
    assert rig.ledger.get_relay_transaction(VAULT) == before
    assert rig.w3.eth.send_count == 1
