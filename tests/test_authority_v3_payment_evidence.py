import copy
import pytest
from eth_keys import keys
from eth_utils import keccak

from solslot_api.authority_v3_payment_evidence import validate_payment_governance_v3
from solslot_api.omnichain_ownership_activation import (
    _safe_message_data, _validate_approval, _typed_data_digest,
    _encode_contract_signatures, OwnershipActivationError,
)


def address(n):
    return '0x' + f'{n:040x}'


def evidence():
    administrators = []
    identities = []
    recovery_ids = []
    for slot in range(3):
        pub = keys.PrivateKey(bytes([slot + 1]) * 32).public_key
        admin = {'slot': slot, 'address': pub.to_checksum_address(),
                 'compressedPubkey': '0x' + pub.to_compressed_bytes().hex()}
        administrators.append(admin)
        identities.append({'slot':slot,'address':address(10+slot),'owners':[admin['address']],
                           'threshold':1,'guard':address(20+slot),'recoveryModule':address(30)})
        bls = bytes([slot+11])*48
        recovery_ids.append({'slot':slot,'evmGuardian':address(40+slot),'blsPubkey':'0x'+bls.hex(),
                             'blsCommitment':'0x'+keccak(bls).hex(),'revision':1,'drillVerifiedAt':'2026-09-24T00:00:00Z'})
    hashes = {name:'0x'+'ab'*32 for name in (
        'identitySafe0','identitySafe1','identitySafe2','identityGuard0','identityGuard1','identityGuard2',
        'coadminSafe','coadminGuard','rootSafe','rootGuard','recovery','timelock',
        'identitySetup','compatibilityFallbackHandler','signMessageLibrary')}
    return {
        'schemaVersion':3,'kind':'solslot-alpha-authority-v3-governance-deployment',
        'authorityRule':'slot0_and_one_of_slot1_slot2','chainId':8453,'network':'baseMainnet',
        'sourceSha':'a'*40,'artifactHash':'0x'+'aa'*32,'rosterArtifactHash':'0x'+'bb'*32,
        'administrators':administrators,'safes':{'identities':identities,
            'coadmin':{'address':address(50),'owners':[address(11),address(12)],'threshold':1,'guard':address(51)},
            'root':{'address':address(60),'owners':[address(10),address(50)],'threshold':2,'guard':address(61)}},
        'payoutAddress':address(60),'timelock':{'address':address(70),'minimumDelaySeconds':'86400',
            'proposer':address(60),'executor':address(60),'canceller':address(60),'externalAdmin':address(0)},
        'recovery':{'address':address(30),'routineDelaySeconds':'86400','lostKeyDelaySeconds':'604800',
            'replacementAcceptanceRequired':True,'globalFreezeRequired':True,'crossChainConvergenceRequired':True,
            'recoveryKitRotationSupported':True,'rollbackRequiresChiaCancellationReceipt':True,'identities':recovery_ids},
        'safeInfrastructure':{'safeVersion':'1.4.1','identitySetup':address(80),
            'compatibilityFallbackHandler':address(81),'signMessageLibrary':address(82)},
        'runtimeCodeHashes':hashes,'chiaAuthority':{'network':'testnet11','sourceManifestHash':'0x'+'ab'*32,
            'authorityLauncherId':'0x'+'11'*32,'identityLauncherIds':['0x'+x*32 for x in ('22','33','44')]},
    }


def validate(value):
    validate_payment_governance_v3(value,chain_id=8453,source_sha='a'*40,artifact_hash='0x'+'aa'*32,
        root_safe=address(60),timelock=address(70),code_hashes={'governanceRootSafe':'0x'+'ab'*32,'governanceTimelock':'0x'+'ab'*32})


def test_complete_base_authority_topology():
    validate(evidence())


@pytest.mark.parametrize('change', [
    lambda e: e.update(chainId=84532),
    lambda e: e['safes']['coadmin'].update(owners=[a['address'] for a in e['administrators'][1:]]),
    lambda e: e['safes']['root'].update(threshold=1),
    lambda e: e['safes']['identities'][2].update(recoveryModule=address(31)),
    lambda e: e['recovery'].update(globalFreezeRequired=False),
    lambda e: e['recovery']['identities'][1].update(evmGuardian=e['administrators'][0]['address']),
    lambda e: e['recovery']['identities'][1].update(blsCommitment='0x'+'cc'*32),
    lambda e: e['administrators'][1].update(compressedPubkey=e['administrators'][0]['compressedPubkey']),
    lambda e: e['timelock'].update(externalAdmin=address(90)),
    lambda e: e['runtimeCodeHashes'].pop('identityGuard2'),
    lambda e: e['chiaAuthority'].update(network='mainnet'),
    lambda e: e['chiaAuthority'].update(identityLauncherIds=['0x'+'22'*32]*3),
])
def test_rejects_wrong_chain_legacy_or_weakened_topology(change):
    value=evidence();change(value)
    with pytest.raises(ValueError):validate(value)


def test_nested_approval_is_bound_to_parent_safe_and_version():
    root_data='0x1901'+'44'*64
    parent=address(50);leaf=address(11)
    typed={'domain':{'chainId':8453,'verifyingContract':leaf},
           'types':{'SafeMessage':[{'name':'message','type':'bytes'}]},'primaryType':'SafeMessage',
           'message':{'message':_safe_message_data(8453,parent,root_data)}}
    value={'role':'coadmin','safe':leaf,'parentSafe':parent,'allowedSigners':[address(41)],
           'typedData':typed,'messageHash':_typed_data_digest(typed)}
    assert _validate_approval(value,chain_id=8453,transaction_data=root_data,schema_version=2)['parentSafe'].lower()==parent
    with pytest.raises(OwnershipActivationError):
        _validate_approval(value,chain_id=8453,transaction_data=root_data,schema_version=1)
    wrong=copy.deepcopy(value);wrong['parentSafe']=address(51)
    with pytest.raises(OwnershipActivationError):
        _validate_approval(wrong,chain_id=8453,transaction_data=root_data,schema_version=2)
