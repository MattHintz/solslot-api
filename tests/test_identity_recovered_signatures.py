"""Signature-only recovery checks. Synthetic keys; no chain or submission."""
from chia_rs import AugSchemeMPL,G1Element
import pytest
from solslot_api.generation_identity_signature_recovery import verify_recovered_signatures_only
from solslot_api.validator_quorum import CurrentIdentityClaim
from tests.test_validator_quorum import _claim


@pytest.fixture
def evidence():
    keys=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (1,2,3)]
    values=_claim(keys).model_dump();values.pop('artifact_hash')
    values.update(claim_version='solslot.current-customer-identity-claim.v1',
        generation_id='0x'+'91'*32,identity_profile_hash='0x'+'92'*32)
    original=CurrentIdentityClaim.model_validate(values)
    now=original.current_timestamp+300
    refreshed=CurrentIdentityClaim.model_validate({**values,'current_timestamp':now})
    responses=[{'claimHash':original.canonical_hash(),'signerIndex':i,
        'validatorPubkey':'0x'+bytes(keys[i].get_g1()).hex(),
        'signature':'0x'+bytes(AugSchemeMPL.sign(keys[i],original.signature_message())).hex()} for i in (1,2)]
    return dict(original=original,refreshed=refreshed,responses=responses,
        validator_pubkeys=[bytes(key.get_g1()) for key in keys],now=now)


def test_retained_quorum_can_be_verified_without_new_signature(evidence):
    result=verify_recovered_signatures_only(**evidence)
    assert result.signer_indices==(1,2)
    assert result.original_claim_hash==evidence['original'].canonical_hash()
    assert result.refreshed_claim_hash==evidence['refreshed'].canonical_hash()
    assert AugSchemeMPL.aggregate_verify([G1Element.from_bytes(evidence['validator_pubkeys'][i]) for i in (1,2)],
        [evidence['original'].signature_message()]*2,result.aggregated_signature)


@pytest.mark.parametrize('field,value',[
    ('identity_attest_root','0x'+'a1'*32),('owner_key','0x'+'a2'*20),
    ('bridge_coin_id','0x'+'a3'*32),('owner_authorization','0x'+'a4'*65),
    ('identity_profile_hash','0x'+'a5'*32),('evm_transaction_hash','0x'+'a6'*32)])
def test_any_changed_claim_subject_is_rejected(evidence,field,value):
    evidence['refreshed']=evidence['refreshed'].model_copy(update={field:value})
    with pytest.raises(ValueError,match='SUBJECT_CHANGED'):verify_recovered_signatures_only(**evidence)


@pytest.mark.parametrize('case',['duplicate','foreign','bad_signature','one','boolean_slot','wrong_roster','stale','bls'])
def test_no_quorum_or_wrong_authority_is_accepted(evidence,case):
    rows=evidence['responses']
    if case=='duplicate':rows[1]=dict(rows[0])
    if case=='foreign':rows[1]={**rows[1],'claimHash':'0x'+'77'*32}
    if case=='bad_signature':rows[1]={**rows[1],'signature':rows[0]['signature']}
    if case=='one':evidence['responses']=rows[:1]
    if case=='boolean_slot':rows[0]={**rows[0],'signerIndex':True}
    if case=='wrong_roster':evidence['validator_pubkeys']=list(reversed(evidence['validator_pubkeys']))
    if case=='stale':evidence['now']+=61
    if case=='bls':
        evidence['original']=evidence['original'].model_copy(update={'owner_auth_type':1})
        evidence['refreshed']=evidence['refreshed'].model_copy(update={'owner_auth_type':1})
    with pytest.raises(ValueError):verify_recovered_signatures_only(**evidence)
