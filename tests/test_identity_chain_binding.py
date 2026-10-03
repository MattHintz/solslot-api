import copy, importlib.util, json
from pathlib import Path
import pytest
bootstrap=Path(__file__).parent.parent/'deployment/solslot_identity_chain_binding.py'
if not bootstrap.is_file():bootstrap=Path(__file__).parent/'solslot_identity_chain_binding.py'
spec=importlib.util.spec_from_file_location('ae169_test_bootstrap',bootstrap)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
verify_runtime_bindings=module.verify_runtime_bindings
from solslot_api.public_artifact import _verify_runtime_bindings, PublicArtifactError
from solslot_api.identity_deployment import require_runtime_identity_bindings, IdentityDeploymentError
from tests.test_public_artifact import _signed_artifact, _settings
from tests import test_public_artifact as artifact_tests
from solslot_puzzles import identity_deployment_amendment as v1
from solslot_puzzles import identity_network_amendment as network

def seal(d):
    import hashlib
    d={k:v for k,v in d.items() if k!='artifactHash'}
    return {**d,'artifactHash':'0x'+hashlib.sha256(v1.canonical_json(d)).hexdigest()}

@pytest.fixture
def binding(tmp_path):
    base=_signed_artifact()
    old=json.loads((Path(artifact_tests.__file__).parent/'fixtures/identity-deployment-v2.json').read_text())
    coins=['0x'+f'{i:02x}'*32 for i in (1,2,3)]
    boundary={'authorityLauncherId':base['launcherIds']['adminAuthority'],'authorityCoinId':'0x'+'aa'*32,'authorityVersion':2,'rosterIdentityCoinIds':coins,'signerSlots':[0,1],'signerIdentityCoinIds':coins[:2]}
    previous=v1.build_statement(base_artifact=base,deployment_artifact=old,deployment_plan_hash='0x'+'cc'*32,activation_source_shas={'api':'3'*40,'protocol':'4'*40},activation_boundary=boundary,revision=1,previous_amendment_hash=v1.ZERO_HASH,approval_expires_at=2_000_000_000)
    predecessor=network.ConfirmedPredecessor(previous,old,'0x'+'cc'*32,v1.ConfirmedAmendmentAnchor(v1.amendment_hash(previous),boundary['authorityLauncherId'],boundary['authorityCoinId'],2,100,1_999_999_999,v1.announcement_message(v1.amendment_hash(previous))))
    new=copy.deepcopy(old);new.update(chainId=8453,network='base')
    for i,name in enumerate(('forwarder','verifierAdapter','attestationEmitter')):
        new[name+'Address']='0x'+str(i+4)*40
        new['deploymentTransactions'][name].update(hash='0x'+str(i+4)*64,blockNumber=52_000_000+i,blockHash='0x'+str(i+7)*64)
    new=seal(new);current_boundary=dict(boundary,authorityCoinId='0x'+'bb'*32,authorityVersion=4)
    candidate=network.build_statement(base_artifact=base,deployment_artifact=new,deployment_plan_hash='0x'+'dd'*32,activation_source_shas={'api':'3'*40,'protocol':'4'*40},activation_boundary=current_boundary,approval_expires_at=2_000_000_200,predecessor=predecessor)
    for name,value in [('previous',previous),('old',old),('candidate',candidate),('new',new)]:
        (tmp_path/(name+'.json')).write_bytes(v1.canonical_json(value))
    s=_settings(tmp_path,base,zkpassport_evm_chain_id=8453,identity_deployment_amendment_path=str(tmp_path/'previous.json'),identity_deployment_artifact_path=str(tmp_path/'old.json'),identity_deployment_plan_hash='0x'+'cc'*32,identity_network_amendment_path=str(tmp_path/'candidate.json'),identity_network_artifact_path=str(tmp_path/'new.json'),identity_network_plan_hash='0x'+'dd'*32)
    return s,base,candidate,tmp_path

def test_reproduces_failure_then_accepts_bound_base_without_mutation(binding):
    s,base,candidate,_=binding;before=copy.deepcopy(base)
    with pytest.raises(PublicArtifactError,match='identity chain'):_verify_runtime_bindings(s,base)
    verify_runtime_bindings(_verify_runtime_bindings,s,base)
    assert s.zkpassport_evm_chain_id==8453 and base==before

@pytest.mark.parametrize('field',['identity_network_amendment_path','identity_network_artifact_path','identity_network_plan_hash','identity_deployment_artifact_path'])
def test_incomplete_records_fail_closed(binding,field):
    s,base,_,_=binding;setattr(s,field,'')
    with pytest.raises(PublicArtifactError):verify_runtime_bindings(_verify_runtime_bindings,s,base)

@pytest.mark.parametrize('alter',['wrong-plan','changed-domain','noncanonical','wrong-artifact','wrong-bridge','wrong-roster'])
def test_invalid_evidence_and_other_runtime_guards_remain(binding,alter):
    s,base,candidate,p=binding
    if alter=='wrong-plan':s.identity_network_plan_hash='0x'+'ee'*32
    elif alter=='changed-domain':
        candidate['identityPolicy']['domain']='wrong.example';(p/'candidate.json').write_bytes(v1.canonical_json(candidate))
    elif alter=='noncanonical':(p/'candidate.json').write_bytes(v1.canonical_json(candidate)+b'\n')
    elif alter=='wrong-artifact':base['artifactHash']='0x'+'ee'*32
    elif alter=='wrong-bridge':s.zkpassport_bridge_policy_hash='0x'+'ee'*32
    else:s.zkpassport_validator_pubkeys=list(reversed(s.zkpassport_validator_pubkeys))
    with pytest.raises(PublicArtifactError):verify_runtime_bindings(_verify_runtime_bindings,s,base)

def test_admission_does_not_make_an_unconfirmed_candidate_effective(binding):
    s,base,_,_=binding
    verify_runtime_bindings(_verify_runtime_bindings,s,base)
    with pytest.raises(IdentityDeploymentError,match='chain'):
        require_runtime_identity_bindings(s,{'evmChainId':11155111,'addresses':base['evmAddresses'],'credentialPolicyVersion':2,'chiaBridgePolicyHash':base['bridgePolicy']['policyHash']})

def test_original_sepolia_guard_is_preserved(binding):
    s,base,_,_=binding;s.zkpassport_evm_chain_id=11155111
    verify_runtime_bindings(_verify_runtime_bindings,s,base)
    s.zkpassport_bridge_policy_hash='0x'+'ee'*32
    with pytest.raises(PublicArtifactError):verify_runtime_bindings(_verify_runtime_bindings,s,base)
