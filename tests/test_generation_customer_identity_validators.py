"""Current identity schema and independent authorization boundary regressions."""
from hashlib import sha256
import json
from types import SimpleNamespace
import httpx
import pytest
from chia_rs import AugSchemeMPL
from pydantic import ValidationError
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.generation_customer_identity_validators import (
    selected_current_identity_profile, sign_current_identity, verify_current_identity_claim, _verify_event,
)
from solslot_api.validator_quorum import CurrentIdentityClaim, ValidatorClaim, collect_validator_quorum
from tests.test_generation_customer_identity_context import profile
from tests.test_validator_quorum import _claim, _settings


def current_claim(pins, **changes):
    keys = [AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33)]
    data = _claim(keys).model_dump()
    data.pop('artifact_hash')
    data.update(claim_version='solslot.current-customer-identity-claim.v1',
        generation_id=pins.generation_id, identity_profile_hash=pins.commitment,
        emitter_address=next(c.address for c in pins.contracts if c.role=='attestationEmitter'),
        bridge_policy_hash=pins.bridge_policy_hash, bridge_parent_id=pins.bridge_coins[0].parent_id,
        bridge_coin_id=pins.bridge_coins[0].coin_id)
    data.update(changes)
    return CurrentIdentityClaim.model_validate(data)


def signer(tmp_path):
    data, _ = profile(); pins = CurrentCustomerIdentityProfile.model_validate(data)
    path=tmp_path/'identity-profile.json'; path.write_text(pins.model_dump_json(by_alias=True))
    addresses={c.role:c.address for c in pins.contracts}
    settings=SimpleNamespace(generation_customer_identity_enabled=True, network='testnet11',
        deployment_generation_id=pins.generation_id, generation_customer_identity_profile_path=str(path),
        generation_customer_identity_profile_hash='0x'+sha256(path.read_bytes()).hexdigest(),
        roster_pubkeys=list(pins.validator_public_keys), bridge_policy_hash=pins.bridge_policy_hash,
        evm_chain_id=8453, evm_forwarder_address=addresses['forwarder'],
        evm_verifier_adapter_address=addresses['verifierAdapter'], evm_attestation_emitter_address=addresses['attestationEmitter'],
        claim_clock_skew_seconds=90, proof_max_age_seconds=604800)
    return settings,pins


def test_legacy_wire_hash_stays_unchanged_and_cannot_parse_current_claim():
    keys=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33)]
    legacy=_claim(keys); data=legacy.model_dump()
    expected='0x'+sha256(json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    assert legacy.canonical_hash()==expected and 'claim_version' not in data
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0]); current=current_claim(pins)
    assert 'artifact_hash' not in current.model_dump()
    with pytest.raises(ValidationError):ValidatorClaim.model_validate(current.model_dump())
    with pytest.raises(ValidationError):CurrentIdentityClaim.model_validate(data)
    with pytest.raises(ValidationError):CurrentIdentityClaim.model_validate({**current.model_dump(),'artifact_hash':legacy.artifact_hash})


@pytest.mark.parametrize('field,value', [
    ('deployment_generation_id','0x'+'91'*32),('bridge_policy_hash','0x'+'92'*32),
    ('evm_chain_id',11155111),('evm_attestation_emitter_address','0x'+'93'*20),
    ('generation_customer_identity_enabled',False)])
def test_independent_signer_configuration_never_falls_back_to_old_artifact(tmp_path,field,value):
    settings,_=signer(tmp_path);setattr(settings,field,value)
    with pytest.raises(ValueError):selected_current_identity_profile(settings)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation',['hash','generation','profile','clock','proof','legacy'])
async def test_invalid_claim_never_reads_a_signing_key_or_calls_a_node(tmp_path,monkeypatch,mutation):
    settings,pins=signer(tmp_path);claim=current_claim(pins); digest=claim.canonical_hash()
    if mutation=='hash':digest='0x'+'91'*32
    if mutation=='generation':claim=claim.model_copy(update={'generation_id':'0x'+'92'*32});digest=claim.canonical_hash()
    if mutation=='profile':claim=claim.model_copy(update={'identity_profile_hash':'0x'+'93'*32});digest=claim.canonical_hash()
    if mutation=='clock':claim=claim.model_copy(update={'current_timestamp':claim.current_timestamp-91});digest=claim.canonical_hash()
    if mutation=='proof':claim=claim.model_copy(update={'proof_timestamp':claim.current_timestamp+1});digest=claim.canonical_hash()
    if mutation=='legacy':claim=_claim([AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33)]);digest=claim.canonical_hash()
    import solslot_api.validator_service as service
    def forbidden(*a,**kw):raise AssertionError('signing credential must not be read')
    monkeypatch.setattr(service,'load_validator_private_key',forbidden)
    class NoNode:
        def __getattr__(self,name):raise AssertionError('invalid claims must not reach a node')
    with pytest.raises(ValueError):
        await sign_current_identity(settings,object(),claim,digest,provider=NoNode(),clock=lambda:1_800_000_000)


@pytest.mark.asyncio
async def test_current_quorum_uses_separate_route_and_rejects_foreign_response():
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0]);claim=current_claim(pins)
    keys=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33)];settings=_settings(keys)
    async def handle(request):
        assert request.url.path=='/v1/generation/identity/sign'
        assert request.extensions['timeout']['read']==55.0
        body=json.loads(request.content);assert 'artifact_hash' not in body['claim']
        index=int(request.url.host.split('-')[1].split('.')[0])
        return httpx.Response(200,json={'claimHash':claim.canonical_hash() if index!=2 else '0x'+'99'*32,
            'signerIndex':index,'validatorPubkey':pins.validator_public_keys[index],
            'signature':'0x'+bytes(AugSchemeMPL.sign(keys[index],claim.signature_message())).hex()})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result=await collect_validator_quorum(settings,claim,client=client)
    assert result.signer_indices==(0,1)


@pytest.mark.parametrize('auth',[1,3])
@pytest.mark.parametrize('mutation',[None,'sender','root','block'])
def test_independently_fetched_event_matches_the_correct_native_owner_kind(tmp_path,monkeypatch,auth,mutation):
    settings,pins=signer(tmp_path);settings.evm_rpc_url='https://example.invalid';settings.evm_min_confirmations=12
    claim=current_claim(pins,owner_auth_type=auth)
    data=claim.model_dump()
    data.update(transaction_hash=claim.evm_transaction_hash,block_number=claim.evm_block_number,
        sender=claim.owner_key if auth==3 else pins.trusted_direct_relayer)
    if mutation=='sender':data['sender']='0x'+'91'*20
    if mutation=='root':data['identity_attest_root']='0x'+'92'*32
    if mutation=='block':data['block_number']+=1
    import solslot_api.zkpassport_enrollments as identity
    def observed(selected,*,current_profile,transaction_hash,expected_vault_launcher_id):
        assert selected.deployment_generation_id==pins.generation_id and current_profile==pins
        assert selected.alpha_writes_enabled is False and transaction_hash==claim.evm_transaction_hash
        return SimpleNamespace(**data)
    monkeypatch.setattr(identity,'_fetch_verified_evm_attestation',observed)
    if mutation:
        with pytest.raises(ValueError):_verify_event(settings,pins,claim)
    else:_verify_event(settings,pins,claim)


def test_current_identity_endpoint_is_closed_by_default_and_rejects_legacy_shape(tmp_path):
    from fastapi.testclient import TestClient
    from solslot_api.validator_app import create_validator_app
    from solslot_api.validator_ledger import ValidatorLedger
    from tests.test_validator_app import _settings as app_settings
    settings=app_settings(tmp_path);pins=CurrentCustomerIdentityProfile.model_validate(profile()[0])
    ledger=ValidatorLedger(':memory:')
    try:
        with TestClient(create_validator_app(settings=settings,ledger=ledger)) as client:
            claim=current_claim(pins)
            response=client.post('/v1/generation/identity/sign',json={'claim':claim.model_dump(),'claimHash':claim.canonical_hash()})
            assert response.status_code==503 and response.json()['detail']=='CURRENT_ID_SIGNER_NOT_READY'
            old=_claim([AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33)])
            response=client.post('/v1/generation/identity/sign',json={'claim':old.model_dump(),'claimHash':old.canonical_hash()})
            assert response.status_code==422
    finally:ledger.close()
