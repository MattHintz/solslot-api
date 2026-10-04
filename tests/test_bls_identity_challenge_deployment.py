"""Synthetic proofs exercise the Sage-only authorization boundary; no RPC or signing."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from solslot_api import zkpassport_enrollments as enrollments, zkpassport_relay as relay
from solslot_api.config import Settings
from solslot_api.identity_deployment import enrollment_identity_binding
from tests.test_eligibility_query import artifact, calldata, VAULT
from tests.test_zkpassport_enrollments import _coin_id

V = '0x' + VAULT.hex()
PARENT = '0x' + '44' * 32
POLICY = '0x' + '77' * 32
V21 = bytes.fromhex('000000150000' + '00' * 26)


@pytest.fixture
def challenge(monkeypatch):
    base = artifact()
    base.update(artifactHash='0x' + 'aa' * 32,
        evmAddresses={'forwarder': '0x'+'11'*20, 'verifierAdapter': '0x'+'22'*20,
                      'attestationEmitter': '0x'+'33'*20},
        bridgePolicy={'policyVersion': 2, 'policyHash': POLICY,
                      'parentCoinIds': [PARENT], 'bridgeCoinIds': [_coin_id(PARENT, POLICY)]})
    current = {'source': 'confirmed-network-amendment', 'revision': 2,
        'amendmentHash': '0x'+'bb'*32, 'evmChainId': 8453,
        'acceptedProofVersions': ['0.20.0', '0.21.0'],
        'addresses': {'forwarder': '0x'+'55'*20, 'verifierAdapter': '0x'+'66'*20,
                      'attestationEmitter': '0x'+'88'*20}, 'credentialPolicyVersion': 2,
        'chiaBridgePolicyHash': POLICY}
    record = {'vaultLauncherId': V, 'bridgeParentId': PARENT, 'bridgeAmount': 1,
              'bridgePolicyHash': POLICY, 'bridgeCoinId': _coin_id(PARENT, POLICY),
              'identityDeployment': enrollment_identity_binding(current)}
    settings = Settings(_env_file=None, runtime_environment='test',
        zkpassport_eligibility_policy='age-sanctions-v1')
    session = SimpleNamespace(auth_type='chia_bls', owner_key='synthetic-owner')
    issued = []
    monkeypatch.setattr(enrollments, '_settings', lambda: settings)
    monkeypatch.setattr(enrollments, 'verify_vault_session', lambda *_: session)
    monkeypatch.setattr(enrollments, 'get_credential_ledger', lambda *_:
                        SimpleNamespace(get_enrollment=lambda *_: record))
    monkeypatch.setattr(enrollments, '_active_genesis_artifact', lambda *_: base)
    monkeypatch.setattr(relay, '_active_genesis_artifact', lambda *_: base)
    monkeypatch.setattr(relay, '_w3', lambda *_: pytest.fail('challenge must not reach RPC'))
    def issue(selected, **kwargs):
        issued.append((selected, kwargs))
        return kwargs['request']
    monkeypatch.setattr(enrollments, 'issue_owner_challenge', issue)
    request = Request({'type': 'http', 'method': 'POST', 'headers': [],
                       'app': SimpleNamespace(state=SimpleNamespace(identity_deployment=current))})
    def invoke(data=None):
        return enrollments.create_bls_relay_challenge(V,
            enrollments.RelayChallengeRequest(data='0x'+(data or calldata(version=V21)).hex()), request)
    return SimpleNamespace(invoke=invoke, record=record, current=current, issued=issued,
                           session=session, settings=settings)


def test_current_sage_proof_uses_authenticated_base_revision(challenge):
    before = deepcopy(challenge.record)
    result = challenge.invoke()
    assert result.action == 'relay'
    assert result.payload == {'data': '0x'+calldata(version=V21).hex()}
    selected, _ = challenge.issued[0]
    assert selected.zkpassport_evm_chain_id == 8453
    assert selected.zkpassport_emitter_address == challenge.current['addresses']['attestationEmitter']
    assert challenge.settings.zkpassport_evm_chain_id == 11155111
    assert challenge.record == before


def test_historical_enrollment_cannot_inherit_new_proof_versions(challenge):
    del challenge.record['identityDeployment']
    with pytest.raises(HTTPException) as error:
        challenge.invoke()
    assert error.value.status_code == 409
    assert 'verifier update required' in error.value.detail
    assert not challenge.issued


@pytest.mark.parametrize('field,value', [
    ('revision', 1), ('amendmentHash', '0x'+'cc'*32), ('evmChainId', 11155111),
    ('attestationEmitter', '0x'+'99'*20), ('acceptedProofVersions', ['0.20.0']),
])
def test_altered_enrollment_binding_cannot_reach_wallet(challenge, field, value):
    challenge.record['identityDeployment'][field] = value
    with pytest.raises(HTTPException) as error:
        challenge.invoke()
    assert error.value.status_code == 503
    assert not challenge.issued


@pytest.mark.parametrize('kwargs', [
    {'version': bytes.fromhex('000000160000'+'00'*26)},
    {'domain': 'other.example'}, {'scope': 'vault:0x'+'99'*32}, {'dev': True},
    {'inputs': bytes.fromhex('0100021200')},
])
def test_unsupported_or_unreviewed_proof_still_fails_closed(challenge, kwargs):
    with pytest.raises(HTTPException) as error:
        challenge.invoke(calldata(version=V21, **kwargs) if 'version' not in kwargs else calldata(**kwargs))
    assert error.value.status_code == 409
    assert not challenge.issued


def test_evm_session_does_not_enter_sage_challenge(challenge):
    challenge.session.auth_type = 'evm'
    with pytest.raises(HTTPException) as error:
        challenge.invoke()
    assert error.value.status_code == 409
    assert 'ForwardRequest' in error.value.detail
    assert not challenge.issued


def test_invalid_bridge_coin_never_reaches_deployment_or_wallet(challenge):
    challenge.record['bridgeAmount'] = 2
    with pytest.raises(HTTPException) as error:
        challenge.invoke()
    assert error.value.status_code == 409
    assert 'bridge coin' in error.value.detail
    assert not challenge.issued
