"""Only independently revalidated retained signatures can form a quorum."""
import json
import httpx
import pytest
from chia_rs import AugSchemeMPL
from solslot_api.generation_identity_recovery_quorum import collect_retained_identity_quorum
from solslot_api.validator_quorum import CurrentIdentityClaim,ValidatorQuorumError
from tests.test_validator_quorum import _keys,_settings,_claim


@pytest.mark.asyncio
@pytest.mark.parametrize('bad_slot',[None,1,2])
async def test_recovery_requires_two_matching_saved_signatures(bad_slot):
    keys=_keys();settings=_settings(keys);values=_claim(keys).model_dump();values.pop('artifact_hash')
    values.update(claim_version='solslot.current-customer-identity-claim.v1',
        generation_id='0x'+'91'*32,identity_profile_hash='0x'+'92'*32)
    original=CurrentIdentityClaim.model_validate(values);now=original.current_timestamp+300
    refreshed=original.model_copy(update={'current_timestamp':now})
    async def endpoint(request):
        assert request.url.path=='/v1/generation/identity/recover'
        body=json.loads(request.content)
        assert body['originalClaimHash']==original.canonical_hash()
        assert body['claimHash']==refreshed.canonical_hash()
        slot=int(request.url.host.split('-')[1].split('.')[0])
        if slot==0:return httpx.Response(409,json={'detail':'not saved'})
        if slot==bad_slot:return httpx.Response(200,json={'claimHash':'0x'+'99'*32,'signerIndex':slot,
            'validatorPubkey':'0x'+bytes(keys[slot].get_g1()).hex(),'signature':'0x'+'00'*96})
        return httpx.Response(200,json={'claimHash':original.canonical_hash(),'signerIndex':slot,
            'validatorPubkey':'0x'+bytes(keys[slot].get_g1()).hex(),
            'signature':'0x'+bytes(AugSchemeMPL.sign(keys[slot],original.signature_message())).hex()})
    async with httpx.AsyncClient(transport=httpx.MockTransport(endpoint)) as client:
        if bad_slot is not None:
            with pytest.raises(ValidatorQuorumError):
                await collect_retained_identity_quorum(settings,original,refreshed,client=client,clock=lambda:now)
        else:
            result=await collect_retained_identity_quorum(settings,original,refreshed,client=client,clock=lambda:now)
            assert result.signer_indices==(1,2)
