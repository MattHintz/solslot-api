from copy import deepcopy
import pytest
from eth_abi import encode
from solslot_puzzles.eligibility_policy import ELIGIBILITY_POLICY
from solslot_api.enrollment_permit_runtime import (
    ACCEPTED_PROOF_VERSION, BINDING_ABI, LEGACY_SELECTOR, PROOF_PARAMS_ABI,
    require_private_eligibility_query,
)

AGE = bytes.fromhex('0100021200')
SANCTIONS = bytes.fromhex('090021') + b'\x55' * 32 + b'\x00'
VAULT = b'\x11' * 32

def artifact():
    return {'evmChainId':11155111, 'identityPolicy':deepcopy(ELIGIBILITY_POLICY),
            'genesisPlan':{'identityPolicy':deepcopy(ELIGIBILITY_POLICY)}}

def calldata(inputs=AGE+SANCTIONS, domain='solslot.com', dev=False, scope=None):
    params = (ACCEPTED_PROOF_VERSION, (b'\x22'*32, b'proof', [b'\x33'*32]), inputs,
              (604800, domain, scope or 'vault:0x'+VAULT.hex(), dev))
    return LEGACY_SELECTOR + encode([BINDING_ABI, 'bytes'],
        [(VAULT, b'\x44'*32, 1), encode([PROOF_PARAMS_ABI], [params])])

@pytest.mark.parametrize('inputs', [AGE+SANCTIONS, SANCTIONS+AGE])
def test_accepts_only_reviewed_private_checks(inputs):
    require_private_eligibility_query(calldata(inputs), artifact())

@pytest.mark.parametrize('kwargs', [
    {'inputs':AGE}, {'inputs':SANCTIONS}, {'inputs':AGE+AGE},
    {'inputs':AGE+SANCTIONS+b'\x01'}, {'domain':'staging.solslot.com'},
    {'dev':True}, {'scope':'vault:0x'+'77'*32},
    {'inputs':AGE+SANCTIONS[:-1]+b'\x01'},
])
def test_rejects_unreviewed_or_disclosure_bearing_proofs(kwargs):
    with pytest.raises(ValueError):
        require_private_eligibility_query(calldata(**kwargs), artifact())

def test_old_genesis_cannot_be_upgraded_by_runtime_flag():
    with pytest.raises(ValueError, match='not selected'):
        require_private_eligibility_query(calldata(), {'genesisPlan':{}})

@pytest.mark.parametrize('runtime,selected', [('age-only',True), ('age-sanctions-v1',False)])
def test_relayer_cannot_silently_change_signed_identity_policy(monkeypatch,runtime,selected):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from solslot_api import zkpassport_relay as relay
    settings=SimpleNamespace(enrollment_permit_release_identity=None,zkpassport_eligibility_policy=runtime)
    record={'vaultLauncherId':'0x'+VAULT.hex(),'bridgeParentId':'0x'+'44'*32,'bridgeAmount':1}
    monkeypatch.setattr(relay,'_active_genesis_artifact',lambda _:artifact() if selected else {'genesisPlan':{}})
    with pytest.raises(HTTPException) as error:
        relay._validate_relay_permit(settings,record,None,calldata())
    assert error.value.status_code == 409
    assert 'runtime policy differs' in error.value.detail
