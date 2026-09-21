"""Provider diagnostics cannot return identity request data to clients."""
from types import SimpleNamespace

from fastapi import HTTPException
import pytest
from web3.exceptions import ContractLogicError

from solslot_api import enrollment_permit_runtime, zkpassport_relay as relay
from tests.test_relay_durable_recovery import rig, VAULT, EMITTER

SYNTHETIC_MARKER = 'SYNTHETIC-DOCUMENT-DATA-DO-NOT-ECHO'


@pytest.mark.parametrize('error', [
    RuntimeError(SYNTHETIC_MARKER),
    ContractLogicError(SYNTHETIC_MARKER),
    ContractLogicError('0x12345678 ' + SYNTHETIC_MARKER),
    ContractLogicError('0xa54999ed ' + SYNTHETIC_MARKER),
])
def test_bls_provider_echo_never_reaches_response_or_relay_storage(rig, monkeypatch, error):
    action = rig.setup('bls')

    def rejected(*args, **kwargs):
        raise error

    monkeypatch.setattr(rig.w3.eth, 'call', rejected)
    with pytest.raises(HTTPException) as captured:
        action()
    detail = str(captured.value.detail)
    assert captured.value.status_code in (400, 502)
    assert SYNTHETIC_MARKER not in detail
    assert '0x12345678' not in detail
    assert 'Raw error' not in detail
    if '0xa54999ed' in str(error):
        assert 'ScopeMismatch' in detail
    assert rig.ledger.get_relay_attempt(VAULT) is None
    assert rig.ledger.get_relay_transaction(VAULT) is None
    assert rig.counts['sign'] == 0
    assert rig.w3.eth.send_count == 0


@pytest.mark.parametrize('error', [RuntimeError(SYNTHETIC_MARKER), ValueError(SYNTHETIC_MARKER)])
def test_forwarded_deployment_rpc_echo_is_sanitized_before_storage(rig, monkeypatch, error):
    action = rig.setup('evm')

    def rejected(*args, **kwargs):
        raise error

    monkeypatch.setattr(rig.w3.eth, 'get_code', rejected)
    with pytest.raises(HTTPException) as captured:
        action()
    assert captured.value.status_code == 502
    assert SYNTHETIC_MARKER not in str(captured.value.detail)
    assert rig.ledger.get_relay_attempt(VAULT) is None
    assert rig.counts['sign'] == 0
    assert rig.w3.eth.send_count == 0


def test_selected_emitter_value_error_is_not_echoed(rig, monkeypatch):
    def rejected(*args, **kwargs):
        raise ValueError(SYNTHETIC_MARKER)

    monkeypatch.setattr(enrollment_permit_runtime, 'verify_selected_emitter', rejected)
    monkeypatch.setattr(relay, '_active_genesis_artifact', lambda _: rig.artifact)
    with pytest.raises(HTTPException) as captured:
        relay._verify_emitter_deployment(rig.w3, SimpleNamespace(enrollment_permit_release_identity='selected'), EMITTER)
    assert captured.value.status_code == 503
    assert SYNTHETIC_MARKER not in str(captured.value.detail)


@pytest.mark.parametrize('stage', ['verify', 'execute', 'nonces'])
def test_forwarded_rpc_stage_errors_never_echo_request_data(rig, monkeypatch, stage):
    action = rig.setup('evm')

    class RejectedCall:
        def call(self, *args, **kwargs):
            raise RuntimeError(SYNTHETIC_MARKER)

    monkeypatch.setattr(rig.Functions, stage, lambda *args, **kwargs: RejectedCall())
    with pytest.raises(HTTPException) as captured:
        action()
    assert captured.value.status_code == 502
    assert SYNTHETIC_MARKER not in str(captured.value.detail)
    assert rig.ledger.get_relay_attempt(VAULT) is None
    assert rig.counts['sign'] == 0
    assert rig.w3.eth.send_count == 0


def test_revert_diagnostics_only_contain_fixed_allowlisted_messages():
    description = relay._describe_revert(RuntimeError('0xd6bda275 '+SYNTHETIC_MARKER+' 0xd6bda275 0xa54999ed 0x12345678'))
    assert description.count('FailedCall()') == 1
    assert 'ScopeMismatch()' in description
    assert SYNTHETIC_MARKER not in description
    assert '0x12345678' not in description
    assert relay._describe_revert(RuntimeError(SYNTHETIC_MARKER)) == relay._describe_revert(RuntimeError('0x12345678'))
