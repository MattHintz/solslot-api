"""Offline Key Vault transport contract; all identities and keys are synthetic."""
import base64
import json
import copy
from types import SimpleNamespace
import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys.constants import SECPK1_N
from web3 import Web3
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.enrollment_permit import EnrollmentPermit,permit_signing_typed_data
from solslot_puzzles.enrollment_activation import activation_context
from solslot_api import enrollment_permit_signing as signer
from tests.test_enrollment_permit_issuance import artifact,signature,SYNTHETIC_KEY

def inputs():
    active=artifact()['enrollmentActivation']
    wire=EnrollmentPermit(bytes32(b'p'*32),activation_context(active).context_hash,bytes32(b'v'*32),
        bytes32(b'c'*32),2,bytes32(b'o'*32),bytes32(b'b'*32),1900000000,1900000900).to_wire()
    settings=SimpleNamespace(enrollment_permit_issuer_key_ref=active['issuerKeyRef'],
        enrollment_permit_identity_client_id=active['issuerIdentityClientId'],enrollment_permit_release_identity=active['releaseIdentity'],
        runtime_environment='staging',network='testnet11',zkpassport_evm_chain_id=84532,alpha_writes_enabled=True)
    return settings,active,wire

@pytest.mark.parametrize('high_s',[False,True])
def test_exact_versioned_key_vault_digest_and_issuer_recovery(monkeypatch,high_s):
    settings,active,wire=inputs();requests=[];real_client=httpx.Client
    def handle(request):
        requests.append(request)
        if request.method=='GET':
            assert str(request.url).startswith('http://169.254.169.254/metadata/identity/oauth2/token?')
            assert request.url.params['client_id']==active['issuerIdentityClientId']
            assert request.url.params['resource']=='https://vault.azure.net' and request.headers['Metadata']=='true'
            return httpx.Response(200,json={'access_token':'synthetic-token','token_type':'Bearer','resource':'https://vault.azure.net'})
        assert str(request.url)==active['issuerKeyRef']+'/sign?api-version=2025-07-01'
        assert request.headers['Authorization']=='Bearer synthetic-token'
        payload=json.loads(request.content);message=encode_typed_data(full_message=permit_signing_typed_data(EnrollmentPermit.from_wire(wire),activation_context(active)))
        assert payload['alg']=='ES256K' and base64.urlsafe_b64decode(payload['value']+'=')==bytes(Web3.keccak(b'\x19'+message.version+message.header+message.body))
        raw=bytes.fromhex(signature(active,wire)[2:])[:64]
        if high_s:raw=raw[:32]+(SECPK1_N-int.from_bytes(raw[32:],'big')).to_bytes(32,'big')
        return httpx.Response(200,json={'kid':active['issuerKeyRef'],'value':base64.urlsafe_b64encode(raw).decode().rstrip('=')})
    def client(**kwargs):
        assert kwargs['follow_redirects'] is False and kwargs['trust_env'] is False
        return real_client(transport=httpx.MockTransport(handle),**kwargs)
    monkeypatch.setattr(signer.httpx,'Client',client)
    result=signer.sign_permit_with_key_vault(settings,active,wire)
    assert result==signature(active,wire) and len(requests)==2

@pytest.mark.parametrize('failure',['redirect','oversize','bad_token','wrong_kid','wrong_key','bad_scalars','timeout'])
def test_provider_failures_are_bounded_and_sanitized(monkeypatch,failure):
    settings,active,wire=inputs();real_client=httpx.Client;calls=[]
    def handle(request):
        calls.append(request)
        if failure=='timeout':raise httpx.ReadTimeout('synthetic-sensitive-provider-value')
        if failure=='redirect':return httpx.Response(302,headers={'Location':'https://evil.test'})
        if failure=='oversize':return httpx.Response(200,content=b'x'*16385)
        if request.method=='GET':return httpx.Response(200,json={'access_token':'bad\nsecret' if failure=='bad_token' else 'synthetic-token','token_type':'Bearer','resource':'https://vault.azure.net'})
        raw=bytes.fromhex(signature(active,wire,b'\x02'*32 if failure=='wrong_key' else SYNTHETIC_KEY)[2:])[:64]
        if failure=='bad_scalars':raw=bytes(64)
        return httpx.Response(200,json={'kid':active['issuerKeyRef']+'/wrong' if failure=='wrong_kid' else active['issuerKeyRef'],'value':base64.urlsafe_b64encode(raw).decode().rstrip('=')})
    monkeypatch.setattr(signer.httpx,'Client',lambda **kw:real_client(transport=httpx.MockTransport(handle),**kw))
    with pytest.raises(signer.PermitIssuerUnavailable) as error:signer.sign_permit_with_key_vault(settings,active,wire)
    assert 'synthetic-sensitive' not in str(error.value) and 'secret' not in str(error.value)
    assert len(calls)==(1 if failure in ('redirect','oversize','bad_token','timeout') else 2)

@pytest.mark.parametrize('url',['https://evil.test/key','https://a.vault.azure.net/keys/key/abc','https://solslot-test.vault.azure.net@evil.test/keys/key/'+'ab'*16,'http://solslot-test.vault.azure.net/keys/key/'+'ab'*16])
def test_unapproved_key_coordinates_never_open_transport(monkeypatch,url):
    settings,active,wire=inputs();active['issuerKeyRef']=url;settings.enrollment_permit_issuer_key_ref=url
    monkeypatch.setattr(signer.httpx,'Client',lambda **_:pytest.fail('unexpected network client'))
    with pytest.raises(signer.PermitIssuerUnavailable):signer.sign_permit_with_key_vault(settings,active,wire)

def test_signature_cannot_replay_another_permit_or_deployment():
    _,active,wire=inputs();sig=signature(active,wire)
    assert signer.verify_permit_signature(wire,active,sig)==sig
    other=copy.deepcopy(active);other['environment']='production-alpha'
    with pytest.raises(ValueError):signer.verify_permit_signature(wire,other,sig)
    other=EnrollmentPermit.from_wire(wire)
    from dataclasses import replace
    with pytest.raises(ValueError):signer.verify_permit_signature(replace(other,permit_id=bytes32(b'x'*32)).to_wire(),active,sig)
