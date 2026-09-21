"""Age-only proof admission: synthetic envelopes, no passport or live RPC."""
from eth_abi import decode, encode
from fastapi import HTTPException
import pytest

from solslot_api import zkpassport_enrollments as enroll, zkpassport_relay as relay
from solslot_api.enrollment_permit_runtime import (
    BINDING_ABI, PERMIT_ABI, PROOF_PARAMS_ABI, PERMIT_SELECTOR,
    require_private_age_query,
)
from tests.test_enrollment_permit_issuance import setup
from tests.test_permit_transaction_wiring import calldata


def change_proof(data, change):
    types=[BINDING_ABI,PERMIT_ABI,'bytes','bytes']
    outer=list(decode(types,data[4:]))
    params=list(decode([PROOF_PARAMS_ABI],outer[-1])[0])
    change(params)
    outer[-1]=encode([PROOF_PARAMS_ABI],[params])
    return PERMIT_SELECTOR+encode(types,outer)


def test_private_age_query_reaches_permit_validation_without_disclosing_document_fields(setup,monkeypatch):
    s=setup;record=s.issue();data=calldata(record)
    monkeypatch.setattr(enroll,'_active_genesis_artifact',lambda _:s.a)
    require_private_age_query(data,environment='staging-alpha')
    assert relay._validate_relay_permit(s.settings,record,s.session,data,live=True)
    assert s.ledger.get_relay_attempt(s.vault) is None


@pytest.mark.parametrize('query',[
    b'',bytes.fromhex('0100021100'),bytes.fromhex('0100021300'),
    bytes.fromhex('0100021263'),bytes.fromhex('01000212000100021200'),
    bytes.fromhex('010002120000000b')+b'SYNTHETIC-ID',
    bytes.fromhex('00000b')+b'SYNTHETIC-ID'+bytes.fromhex('0100021200'),
])
def test_extra_disclosures_and_other_queries_never_enter_relay_storage(setup,monkeypatch,query):
    s=setup;record=s.issue()
    monkeypatch.setattr(enroll,'_active_genesis_artifact',lambda _:s.a)
    data=change_proof(calldata(record),lambda p:p.__setitem__(2,query))
    with pytest.raises(HTTPException) as error:
        relay._validate_relay_permit(s.settings,record,s.session,data,live=True)
    assert error.value.status_code==409
    assert 'SYNTHETIC-ID' not in str(error.value.detail)
    assert s.ledger.get_relay_attempt(s.vault) is None


@pytest.mark.parametrize('field,value',[
    (0,bytes(32)),
    (3,(604800,'elsewhere.example','vault:',False)),
    (3,(604800,'staging.solslot.com','vault:another',False)),
    (3,(604800,'staging.solslot.com','vault:',True)),
    (3,(2**64,'staging.solslot.com','vault:',False)),
])
def test_wrong_version_and_request_policy_fail_without_echoing_proof_data(setup,field,value):
    record=setup.issue()
    data=change_proof(calldata(record),lambda p:p.__setitem__(field,value))
    with pytest.raises(ValueError,match='only the private age-18 query'):
        require_private_age_query(data,environment='staging-alpha')


def test_noncanonical_inner_proof_is_rejected_even_with_canonical_outer_calldata(setup):
    data=calldata(setup.issue());types=[BINDING_ABI,PERMIT_ABI,'bytes','bytes']
    outer=list(decode(types,data[4:]));outer[-1]+=bytes(32)
    with pytest.raises(ValueError,match='not canonical'):
        require_private_age_query(PERMIT_SELECTOR+encode(types,outer),environment='staging-alpha')
