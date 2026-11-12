"""Synthetic release binding. No real EVM address, proof, key or bridge coin."""
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
import pytest
from chia_rs import AugSchemeMPL,Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile,load_current_identity_profile,select_record_identity_profile
from tests.test_generation_customer_launch import fixture


def profile():
    _,_,bindings,_,_=fixture()
    keys=[AugSchemeMPL.key_gen(bytes([i])*32).get_g1() for i in (31,32,33)]
    bridge=make_bridge_policy_hash([bytes(k) for k in keys],2)
    bindings=replace(bindings,bridge_policy=bridge)
    coin=Coin(bytes32(b'o'*32),bridge,uint64(1))
    data={'schema':'solslot.current-customer-identity-profile.v1',
        'purpose':'REUSE_VERIFIER_INFRASTRUCTURE_FRESH_ENROLLMENTS_ONLY','network':'testnet11',
        'generationId':'0x'+bindings.generation.hex(),'preparationManifest':'0x'+bindings.preparation_manifest.hex(),
        'poolLauncherId':'0x'+bindings.pool_launcher.hex(),'vaultModuleHash':'0x'+bindings.vault_module.hex(),
        'bridgePolicyHash':'0x'+bridge.hex(),'validatorPublicKeys':['0x'+bytes(k).hex() for k in keys],
        'validatorThreshold':2,'bridgeCoins':[{'parentId':'0x'+coin.parent_coin_info.hex(),'coinId':'0x'+coin.name().hex()}],
        'evmChainId':8453,'trustedDirectRelayer':'0x'+'08'*20,'contracts':[{'role':role,'address':'0x'+f'{i:02x}'*20,'codeHash':'0x'+f'{i:02x}'*32}
            for i,role in enumerate(('forwarder','verifierAdapter','attestationEmitter','zkPassportRootVerifier'),1)],
        'sourceIdentityAmendment':'0x'+'76'*32,'acceptedProofVersions':['0.20.0','0.21.0'],
        'legacyVaultsAdmitted':False,'legacyReceiptsAdmitted':False,'requiresFreshPrivateCheck':True,
        'realDocumentOnly':True,'minimumAge':18}
    return data,bindings


def test_reused_contracts_are_explicitly_separate_from_legacy_receipt_authority():
    data,bindings=profile();p=CurrentCustomerIdentityProfile.model_validate(data).require_native(bindings)
    result=p.public()
    assert result['schema']=='solslot.current-customer-identity-deployment.v1'
    assert 'artifactHash' not in result and 'amendmentHash' not in result
    assert result['profileHash']==p.commitment and not result['legacyReceiptsAdmitted']
    assert result['requiresFreshPrivateCheck'] and result['identityPolicy']['devMode'] is False


@pytest.mark.parametrize('field', ['generation','preparation_manifest','pool_launcher','vault_module','bridge_policy'])
def test_changed_native_authority_never_reuses_a_profile(field):
    data,bindings=profile();p=CurrentCustomerIdentityProfile.model_validate(data)
    with pytest.raises(ValueError):p.require_native(replace(bindings,**{field:bytes32(b'X'*32)}))


@pytest.mark.parametrize('field,value', [('legacyVaultsAdmitted',True),('legacyReceiptsAdmitted',True),
    ('requiresFreshPrivateCheck',False),('realDocumentOnly',False),('minimumAge',17),
    ('network','mainnet'),('validatorThreshold',1),('acceptedProofVersions',['9.99.0'])])
def test_legacy_admission_or_weakened_identity_policy_is_rejected(field,value):
    data,_=profile();data[field]=value
    with pytest.raises(ValueError):CurrentCustomerIdentityProfile.model_validate(data)


@pytest.mark.parametrize('mutation', ['validator','bridge','code','role'])
def test_exact_native_bridge_and_external_contract_roles(mutation):
    data,_=profile()
    if mutation=='validator':data['validatorPublicKeys'][0]=data['validatorPublicKeys'][1]
    if mutation=='bridge':data['bridgeCoins'][0]['coinId']='0x'+'91'*32
    if mutation=='code':data['contracts'][0]['codeHash']='0x'+'00'*32
    if mutation=='role':data['contracts'][0]['role']='attestationEmitter'
    with pytest.raises(ValueError):CurrentCustomerIdentityProfile.model_validate(data)


def test_disabled_profile_reads_no_file_or_native_index():
    assert load_current_identity_profile(SimpleNamespace(generation_customer_identity_enabled=False),None,now=1000) is None


def test_existing_record_uses_only_exactly_pinned_same_custody_previous_profile(tmp_path):
    data,_=profile();old=CurrentCustomerIdentityProfile.model_validate(data)
    path=tmp_path/'old.json';path.write_text(old.model_dump_json(by_alias=True))
    settings=SimpleNamespace(generation_customer_identity_previous_profile_path=str(path),
        generation_customer_identity_previous_profile_hash='0x'+sha256(path.read_bytes()).hexdigest())
    data['acceptedProofVersions'].append('0.22.0')
    current=CurrentCustomerIdentityProfile.model_validate(data)
    record={'status':'chia_confirmed','identityDeployment':{'identityProfileHash':old.commitment}}
    assert select_record_identity_profile(settings,current,record)==old
    assert select_record_identity_profile(settings,current,None)==current
    with pytest.raises(ValueError,match='MISMATCH'):
        select_record_identity_profile(settings,current,{'status':'chia_confirmed','identityDeployment':{'identityProfileHash':'0x'+'99'*32}})
    with pytest.raises(ValueError,match='IN_FLIGHT'):
        select_record_identity_profile(settings,current,{**record,'status':'reserved'})
    changed=current.model_copy(update={'pool_launcher_id':'0x'+'88'*32})
    with pytest.raises(ValueError,match='MISMATCH'):select_record_identity_profile(settings,changed,record)
    path.write_text(path.read_text()+' ')
    with pytest.raises(ValueError,match='frozen release'):select_record_identity_profile(settings,current,record)


def test_frozen_source_and_native_binding_are_both_required(tmp_path,monkeypatch):
    data,bindings=profile();profile_doc=CurrentCustomerIdentityProfile.model_validate(data)
    path=tmp_path/'profile.json';path.write_text(profile_doc.model_dump_json(by_alias=True))
    settings=SimpleNamespace(generation_customer_identity_enabled=True,generation_customer_enabled=True,
        network='testnet11',alpha_writes_enabled=False,generation_customer_identity_profile_path=str(path),
        generation_customer_identity_profile_hash='0x'+sha256(path.read_bytes()).hexdigest())
    import solslot_api.generation_customer_context as context
    monkeypatch.setattr(context,'current_customer_launch_bindings',lambda *args,**kwargs:bindings)
    assert load_current_identity_profile(settings,None,now=1000)==profile_doc
    path.write_text(path.read_text()+' ')
    with pytest.raises(ValueError,match='frozen release'):load_current_identity_profile(settings,None,now=1000)
