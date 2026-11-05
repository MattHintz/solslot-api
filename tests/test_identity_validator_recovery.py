"""Recovered signer responses require old evidence and fresh independent checks."""
import json
import time
from types import SimpleNamespace
import pytest
from chia_rs import AugSchemeMPL
from solslot_api.generation_customer_identity_validators import recover_existing_current_identity_signature
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.validator_ledger import ValidatorLedger
from tests.test_generation_customer_identity_context import profile
from tests.test_generation_customer_identity_validators import current_claim


@pytest.fixture
def recovery():
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0])
    original=current_claim(pins);now=original.current_timestamp+300
    fresh=original.model_copy(update={'current_timestamp':now})
    keys=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33)]
    signature='0x'+bytes(AugSchemeMPL.sign(keys[1],original.signature_message())).hex()
    ledger=ValidatorLedger(':memory:')
    ledger.record_or_recover(claim_hash=original.canonical_hash(),
        canonical_claim=json.dumps(original.model_dump(mode='json'),sort_keys=True,separators=(',',':'),ensure_ascii=True),
        scoped_nullifier=original.scoped_nullifier,bridge_coin_id=original.bridge_coin_id,
        vault_action='synthetic-action',evm_transaction_hash=original.evm_transaction_hash,signature=signature)
    settings=SimpleNamespace(signer_index=1,roster_pubkeys=['0x'+bytes(key.get_g1()).hex() for key in keys])
    yield SimpleNamespace(original=original,fresh=fresh,now=now,ledger=ledger,settings=settings,signature=signature)
    ledger.close()


def test_recovery_route_is_closed_by_default(recovery,tmp_path):
    from fastapi.testclient import TestClient
    from solslot_api.validator_app import create_validator_app
    from tests.test_validator_app import _settings
    settings=_settings(tmp_path)
    with TestClient(create_validator_app(settings=settings,ledger=recovery.ledger)) as client:
        got=client.post('/v1/generation/identity/recover',json={'claim':recovery.fresh.model_dump(),
            'claimHash':recovery.fresh.canonical_hash(),'originalClaimHash':recovery.original.canonical_hash()})
        assert got.status_code==503 and got.json()['detail']=='CURRENT_ID_RECOVERY_NOT_READY'


def test_recovery_configuration_requires_an_explicit_deadline(tmp_path):
    from pydantic import ValidationError
    from tests.test_validator_app import _settings
    settings=_settings(tmp_path)
    data=settings.model_dump()
    data.update(generation_customer_identity_enabled=True,
                generation_customer_identity_recovery_enabled=True,
                generation_customer_identity_recovery_expires_at=0)
    with pytest.raises(ValidationError,match='finite expiry'):
        type(settings).model_validate(data)


def test_recovery_route_requires_explicit_enable_and_uses_only_retained_handler(recovery,tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from solslot_api.validator_app import create_validator_app
    from solslot_api.validator_quorum import ValidatorSignatureResponse
    from tests.test_validator_app import _settings
    import solslot_api.generation_customer_identity_validators as validators
    settings=_settings(tmp_path);app=create_validator_app(settings=settings,ledger=recovery.ledger)
    calls=[]
    async def retained(settings,ledger,**kwargs):
        calls.append(kwargs)
        return ValidatorSignatureResponse(claimHash=kwargs['original_claim_hash'],signerIndex=1,
            validatorPubkey=recovery.settings.roster_pubkeys[1],signature=recovery.signature)
    monkeypatch.setattr(validators,'recover_existing_current_identity_signature',retained)
    body={'claim':recovery.fresh.model_dump(),'claimHash':recovery.fresh.canonical_hash(),
        'originalClaimHash':recovery.original.canonical_hash()}
    with TestClient(app) as client:
        settings.generation_customer_identity_enabled=True
        app.state.generation_provider=object()
        assert client.post('/v1/generation/identity/recover',json=body).status_code==404
        settings.generation_customer_identity_recovery_enabled=True
        settings.generation_customer_identity_recovery_expires_at=int(time.time())+120
        got=client.post('/v1/generation/identity/recover',json=body)
        assert got.status_code==200 and got.json()['claimHash']==recovery.original.canonical_hash()
        assert len(calls)==1 and calls[0]['refreshed_claim']==recovery.fresh
        settings.generation_customer_identity_recovery_expires_at=int(time.time())-1
        assert client.post('/v1/generation/identity/recover',json=body).status_code==503
        assert len(calls)==1
        app.state.generation_provider=None


def test_recovery_does_not_return_a_signature_after_the_deadline(recovery,tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from solslot_api.validator_app import create_validator_app
    from solslot_api.validator_quorum import ValidatorSignatureResponse
    from tests.test_validator_app import _settings
    import solslot_api.generation_customer_identity_validators as validators
    settings=_settings(tmp_path);app=create_validator_app(settings=settings,ledger=recovery.ledger)
    async def expires_during_check(settings,ledger,**kwargs):
        settings.generation_customer_identity_recovery_expires_at=int(time.time())-1
        return ValidatorSignatureResponse(claimHash=kwargs['original_claim_hash'],signerIndex=1,
            validatorPubkey=recovery.settings.roster_pubkeys[1],signature=recovery.signature)
    monkeypatch.setattr(validators,'recover_existing_current_identity_signature',expires_during_check)
    body={'claim':recovery.fresh.model_dump(),'claimHash':recovery.fresh.canonical_hash(),
        'originalClaimHash':recovery.original.canonical_hash()}
    with TestClient(app) as client:
        settings.generation_customer_identity_enabled=True
        settings.generation_customer_identity_recovery_enabled=True
        settings.generation_customer_identity_recovery_expires_at=int(time.time())+120
        app.state.generation_provider=object()
        result=client.post('/v1/generation/identity/recover',json=body)
        assert result.status_code==503 and result.json()['detail']=='CURRENT_ID_RECOVERY_NOT_READY'
        app.state.generation_provider=None


@pytest.mark.asyncio
async def test_recovery_revalidates_and_reuses_only_recorded_signature(recovery,monkeypatch):
    import solslot_api.generation_customer_identity_validators as validators
    import solslot_api.validator_service as service
    def no_private_key(*a,**k):raise AssertionError('recovery must never access a private key')
    monkeypatch.setattr(service,'load_validator_private_key',no_private_key)
    calls=[]
    async def verify(settings,claim,claim_hash,*,provider,clock):calls.append((claim,claim_hash))
    monkeypatch.setattr(validators,'verify_current_identity_claim',verify)
    got=await recover_existing_current_identity_signature(recovery.settings,recovery.ledger,
        original_claim_hash=recovery.original.canonical_hash(),refreshed_claim=recovery.fresh,
        refreshed_claim_hash=recovery.fresh.canonical_hash(),provider=object(),clock=lambda:recovery.now)
    assert got.signature==recovery.signature and got.claimHash==recovery.original.canonical_hash()
    assert calls==[(recovery.fresh,recovery.fresh.canonical_hash())]
    assert recovery.ledger.read_existing_identity_signature(claim_hash=recovery.fresh.canonical_hash()) is None


@pytest.mark.asyncio
async def test_recovery_does_not_return_if_fresh_window_expires_during_independent_checks(recovery,monkeypatch):
    import solslot_api.generation_customer_identity_validators as validators
    now=[recovery.now]
    async def verify(*a,**k):now[0]+=61
    monkeypatch.setattr(validators,'verify_current_identity_claim',verify)
    with pytest.raises(ValueError,match='CLOCK_OR_SCOPE_INVALID'):
        await recover_existing_current_identity_signature(recovery.settings,recovery.ledger,
            original_claim_hash=recovery.original.canonical_hash(),refreshed_claim=recovery.fresh,
            refreshed_claim_hash=recovery.fresh.canonical_hash(),provider=object(),clock=lambda:now[0])


@pytest.mark.asyncio
@pytest.mark.parametrize('case',['unknown','changed_subject','bad_hash','expired','wrong_key'])
async def test_missing_or_changed_recovery_never_signs(recovery,monkeypatch,case):
    import solslot_api.generation_customer_identity_validators as validators
    async def verify(*a,**k):return None
    monkeypatch.setattr(validators,'verify_current_identity_claim',verify)
    original_hash=recovery.original.canonical_hash();fresh=recovery.fresh;now=recovery.now
    if case=='unknown':original_hash='0x'+'99'*32
    if case=='changed_subject':fresh=fresh.model_copy(update={'identity_attest_root':'0x'+'99'*32})
    fresh_hash=fresh.canonical_hash()
    if case=='bad_hash':fresh_hash='0x'+'99'*32
    if case=='expired':now+=61
    if case=='wrong_key':recovery.settings.signer_index=0
    with pytest.raises(ValueError):
        await recover_existing_current_identity_signature(recovery.settings,recovery.ledger,
            original_claim_hash=original_hash,refreshed_claim=fresh,refreshed_claim_hash=fresh_hash,
            provider=object(),clock=lambda:now)
