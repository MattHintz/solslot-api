"""Synthetic, offline permit authority and coordinator retry contract."""
import copy
import json
import ssl
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from chia_rs.sized_bytes import bytes32
from eth_keys.constants import SECPK1_N
from fastapi import HTTPException
from solslot_puzzles.enrollment_permit import EnrollmentPermit

from solslot_api import enrollment_permit_remote as remote
from solslot_api import enrollment_permit_issuance as issuance
from solslot_api import enrollment_signer_service as issuer
from solslot_api.enrollment_permit_signing import PermitIssuerUnavailable
from solslot_api.enrollment_signer_settings import EnrollmentSignerSettings
from tests.test_enrollment_permit_issuance import artifact, signature, setup
from tests.test_enrollment_permit_signing import inputs


@pytest.fixture
def authority(monkeypatch, tmp_path):
    value = artifact(8453)
    active = value['enrollmentActivation']
    _, _, wire = inputs(8453)
    release = tmp_path / 'release.json'
    release.write_text(json.dumps({'schemaVersion': 2, 'protocolVersion': 'solslot-v2',
        'api_commit': value['sourceShas']['api'], 'protocol_commit': value['sourceShas']['protocol']}))
    settings = EnrollmentSignerSettings(signing_enabled=True, runtime_environment='staging',
        expected_artifact_hash=value['artifactHash'], release_metadata_path=str(release),
        enrollment_permit_release_identity=active['releaseIdentity'],
        enrollment_permit_issuer_key_ref=active['issuerKeyRef'],
        enrollment_permit_identity_client_id=active['issuerIdentityClientId'],
        expected_context_hash=active['contextHash'], expected_emitter=active['emitter'], expected_issuer=active['issuer'])
    # The cryptographic artifact worker has its own tamper tests. These tests
    # exercise the independent role's checks on an already-verified artifact.
    monkeypatch.setattr(issuer, 'verify_signed_public_artifact_file', lambda _: value)
    clock = [wire['issuedAt']]
    monkeypatch.setattr(issuer.time, 'time', lambda: clock[0])
    calls = []
    def sign(settings, activation, permit):
        calls.append(copy.deepcopy(permit))
        return signature(activation, permit)
    monkeypatch.setattr(issuer, 'sign_permit_with_key_vault', sign)
    return SimpleNamespace(settings=settings, artifact=value, active=active, wire=wire,
        request=remote.canonical_request(value['artifactHash'], wire), calls=calls, clock=clock, release=release)


def test_stateless_identical_live_retry_and_expiry(authority):
    a = authority
    first = issuer.sign_enrollment_request(a.settings, a.request)
    assert first == {'capability': remote.CAPABILITY, 'requestHash': remote.request_hash(a.request),
        'permitHash': a.wire['permitHash'], 'issuer': a.active['issuer'], 'signature': signature(a.active, a.wire)}
    assert issuer.sign_enrollment_request(a.settings, a.request) == first
    assert a.calls == [a.wire, a.wire]
    a.clock[0] = a.wire['expiresAt']
    with pytest.raises(ValueError):
        issuer.sign_enrollment_request(a.settings, a.request)
    assert len(a.calls) == 2


@pytest.mark.parametrize('field,value', [
    ('expected_artifact_hash', '0x' + 'ab' * 32), ('runtime_environment', 'production'),
    ('enrollment_permit_release_identity', '0x' + 'ab' * 32),
    ('enrollment_permit_issuer_key_ref', 'https://another.vault.azure.net/keys/key/' + 'ab' * 16),
    ('enrollment_permit_identity_client_id', '00000000-0000-0000-0000-000000000000'),
    ('expected_context_hash', '0x' + 'ab' * 32), ('expected_emitter', '0x' + 'ab' * 20),
    ('expected_issuer', '0x' + 'ab' * 20), ('signing_enabled', False),
])
def test_wrong_local_authority_pins_never_sign(authority, field, value):
    a = authority
    setattr(a.settings, field, value)
    with pytest.raises(PermitIssuerUnavailable):
        issuer.sign_enrollment_request(a.settings, a.request)
    assert not a.calls


@pytest.mark.parametrize('failure', ['api_source', 'protocol_source', 'operational_chain', 'identity_chain', 'missing_release', 'bad_artifact'])
def test_bad_local_evidence_never_signs(authority, monkeypatch, failure):
    a = authority
    if failure.endswith('_source'):
        a.artifact['sourceShas'][failure.removesuffix('_source')] = 'ab' * 20
    elif failure == 'operational_chain':
        a.artifact['evmChainId'] = 8453
    elif failure == 'identity_chain':
        a.artifact['enrollmentActivation']['evmChainId'] = 84532
    elif failure == 'missing_release':
        a.release.unlink()
    else:
        monkeypatch.setattr(issuer, 'verify_signed_public_artifact_file', lambda _: (_ for _ in ()).throw(ValueError('tampered')))
    with pytest.raises(PermitIssuerUnavailable):
        issuer.sign_enrollment_request(a.settings, a.request)
    assert not a.calls


@pytest.mark.parametrize('failure', ['extra_digest', 'extra_key', 'capability', 'artifact', 'future', 'expired', 'duration', 'context', 'extra_permit_field', 'hash'])
def test_untrusted_request_cannot_select_authority_or_deadline(authority, failure):
    a = authority
    request = copy.deepcopy(a.request)
    permit = EnrollmentPermit.from_wire(a.wire)
    if failure in ('extra_digest', 'extra_key'):
        request[failure.removeprefix('extra_')] = 'caller-selected'
    elif failure == 'capability':
        request['capability'] = 'arbitrary-digest'
    elif failure == 'artifact':
        request['artifactHash'] = '0x' + 'ab' * 32
    elif failure == 'future':
        request['permit'] = replace(permit, issued_at=permit.issued_at + 1, expires_at=permit.expires_at + 1).to_wire()
    elif failure == 'expired':
        a.clock[0] = permit.expires_at
    elif failure == 'duration':
        request['permit'] = replace(permit, expires_at=permit.expires_at + 1).to_wire()
    elif failure == 'context':
        request['permit'] = replace(permit, context_hash=bytes32(b'x' * 32)).to_wire()
    elif failure == 'extra_permit_field':
        request['permit']['digest'] = '0x' + 'ab' * 32
    else:
        request['permit']['permitHash'] = '0x' + 'ab' * 32
    with pytest.raises(ValueError):
        issuer.sign_enrollment_request(a.settings, request)
    assert not a.calls


def test_result_after_deadline_never_leaves_authority(authority, monkeypatch):
    a = authority
    def late(settings, activation, wire):
        a.clock[0] = wire['expiresAt']
        return signature(activation, wire)
    monkeypatch.setattr(issuer, 'sign_permit_with_key_vault', late)
    with pytest.raises(ValueError):
        issuer.sign_enrollment_request(a.settings, a.request)


def client_config(monkeypatch, settings):
    settings.enrollment_permit_signer_mode = 'remote'
    settings.enrollment_permit_remote_url = 'https://10.77.0.12:8793' + remote.SIGN_PATH
    # Real TLS and file validation are covered in the transport test module.
    monkeypatch.setattr(remote, 'validate_remote_signer_config', lambda _: ssl.create_default_context())


def test_coordinator_validates_original_signed_request(authority, monkeypatch):
    a = authority
    settings, _, _ = inputs(8453)
    client_config(monkeypatch, settings)
    real_client = httpx.Client
    seen = []
    def handle(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=issuer.sign_enrollment_request(a.settings, seen[-1]))
    def transport(**kw):
        assert kw['follow_redirects'] is False and kw['trust_env'] is False
        assert isinstance(kw['verify'], ssl.SSLContext)
        return real_client(transport=httpx.MockTransport(handle), **kw)
    monkeypatch.setattr(remote.httpx, 'Client', transport)
    assert remote.sign_permit_with_remote(settings, a.active, a.wire, artifact_hash=a.artifact['artifactHash']) == signature(a.active, a.wire)
    assert seen == [a.request] and a.calls == [a.wire]


@pytest.mark.parametrize('failure', ['redirect', 'oversize', 'timeout', 'provider_error', 'request_hash', 'permit_hash', 'issuer', 'capability', 'extra', 'wrong_signer', 'high_s', 'malformed'])
def test_remote_responses_fail_closed_without_provider_echo(authority, monkeypatch, failure):
    a = authority
    settings, _, _ = inputs(8453)
    client_config(monkeypatch, settings)
    real_client = httpx.Client
    def handle(request):
        if failure == 'redirect':
            return httpx.Response(307, headers={'Location': 'https://evil.test/private'})
        if failure == 'oversize':
            return httpx.Response(200, content=b'x' * (remote.MAX_RESPONSE_BYTES + 1))
        if failure == 'timeout':
            raise httpx.ReadTimeout('synthetic-sensitive-provider-value')
        if failure == 'provider_error':
            return httpx.Response(503, text='synthetic-sensitive-provider-value')
        response = issuer.sign_enrollment_request(a.settings, a.request)
        if failure in ('request_hash', 'permit_hash'):
            response['requestHash' if failure == 'request_hash' else 'permitHash'] = '0x' + 'ab' * 32
        elif failure in ('issuer', 'capability'):
            response[failure] = 'wrong'
        elif failure == 'extra':
            response['permit'] = a.wire
        elif failure == 'wrong_signer':
            response['signature'] = signature(a.active, a.wire, b'\x02' * 32)
        elif failure == 'high_s':
            raw = bytes.fromhex(response['signature'][2:])
            response['signature'] = '0x' + (raw[:32] + (SECPK1_N - int.from_bytes(raw[32:64], 'big')).to_bytes(32, 'big') + raw[64:]).hex()
        else:
            response['signature'] = '0x00'
        return httpx.Response(200, json=response)
    monkeypatch.setattr(remote.httpx, 'Client', lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    with pytest.raises(PermitIssuerUnavailable) as error:
        remote.sign_permit_with_remote(settings, a.active, a.wire, artifact_hash=a.artifact['artifactHash'])
    assert 'synthetic-sensitive' not in str(error.value) and 'evil.test' not in str(error.value)


@pytest.mark.parametrize('field,value', [('alpha_writes_enabled', False), ('network', 'mainnet'),
    ('runtime_environment', 'production'), ('zkpassport_evm_chain_id', 84532),
    ('enrollment_permit_release_identity', 'other'), ('enrollment_permit_issuer_key_ref', 'other'),
    ('enrollment_permit_identity_client_id', 'other')])
def test_client_pin_mismatch_does_not_open_transport(authority, monkeypatch, field, value):
    a = authority
    settings, _, _ = inputs(8453)
    client_config(monkeypatch, settings)
    setattr(settings, field, value)
    monkeypatch.setattr(remote.httpx, 'Client', lambda **_: pytest.fail('unexpected transport'))
    with pytest.raises(PermitIssuerUnavailable):
        remote.sign_permit_with_remote(settings, a.active, a.wire, artifact_hash=a.artifact['artifactHash'])


def test_remote_lost_response_retries_saved_permit_and_preserves_first_result(setup, monkeypatch):
    s = setup
    client_config(monkeypatch, s.settings)
    real_client = httpx.Client
    requests = []
    monkeypatch.setattr(issuance, 'sign_permit_with_key_vault', lambda *_: pytest.fail('local fallback'))
    def handle(request):
        value = json.loads(request.content)
        requests.append(value)
        saved = s.ledger.get_enrollment(s.vault)
        assert saved['enrollmentPermit'] == value['permit']
        signed = signature(s.active, value['permit'])
        if len(requests) == 1:
            raise httpx.ReadTimeout('reply lost after signing')
        return httpx.Response(200, json={'capability': remote.CAPABILITY, 'requestHash': remote.request_hash(value),
            'permitHash': value['permit']['permitHash'], 'issuer': s.active['issuer'], 'signature': signed})
    monkeypatch.setattr(remote.httpx, 'Client', lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    with pytest.raises(HTTPException) as error:
        s.issue(signer=None)
    assert error.value.status_code == 503
    pending = s.ledger.get_enrollment(s.vault)
    assert pending['permitIssuanceStatus'] == 'pending'
    s.clock[0] += 5
    result = s.issue(signer=None)
    assert result['permitIssuanceStatus'] == 'issued'
    assert requests == [requests[0], requests[0]]
    assert result['enrollmentPermit'] == pending['enrollmentPermit']
    assert s.issue(signer=None) == result and len(requests) == 2
    events = [r[0] for r in s.ledger._conn.execute('SELECT event FROM permit_issuance_history ORDER BY id')]
    assert events == ['started', 'unavailable', 'started', 'issued']
