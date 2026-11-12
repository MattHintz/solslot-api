"""Finite request scope and legacy-context exclusion; no live data or keys."""
from copy import deepcopy
import pytest
from pydantic import ValidationError
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim


def body():
    return dict(generationId='0x'+'01'*32,anchorHash='0x'+'02'*32,
        issuerPolicyHash='0x'+'03'*32,purchaseArtifact={'synthetic':'fixture'},signedPrice={'synthetic':'fixture'},
        availableCoinId='0x'+'04'*32,currentVaultCoinId='0x'+'05'*32,signerIndices=[0,1])


def test_exact_claim_hash_is_order_independent_and_field_bound():
    raw=body();claim=CurrentReservationClaim.model_validate(raw)
    assert claim.digest()==CurrentReservationClaim.model_validate(dict(reversed(list(raw.items())))).digest()
    for key in ('generationId','anchorHash','issuerPolicyHash','availableCoinId','currentVaultCoinId'):
        other=deepcopy(raw);other[key]='0x'+'06'*32
        assert CurrentReservationClaim.model_validate(other).digest()!=claim.digest()
    for key in ('purchaseArtifact','signedPrice'):
        other=deepcopy(raw);other[key]['synthetic']='changed'
        assert CurrentReservationClaim.model_validate(other).digest()!=claim.digest()
    assert CurrentReservationClaim.model_validate({**raw,'signerIndices':[0,2]}).digest()!=claim.digest()


@pytest.mark.parametrize('pair',[[0,0],[1,0],[0,3],[True,1],['0',1],[0,1,2]])
def test_distinct_typed_canonical_signer_pair_required(pair):
    with pytest.raises(ValidationError):CurrentReservationClaim.model_validate({**body(),'signerIndices':pair})


@pytest.mark.parametrize('changed',[{'network':'mainnet'},{'genesisArtifactHash':'0x'+'09'*32},
    {'schema_version':'solslot.legacy-reservation.v1'}, {'purchaseArtifact':{'data':'x'*65536}},
    {'availableCoinId':'../input'},{'currentVaultCoinId':'0x'+'AA'*32}])
def test_old_context_wrong_network_oversize_and_invalid_inputs_rejected(changed):
    with pytest.raises(ValidationError):CurrentReservationClaim.model_validate({**body(),**changed})
