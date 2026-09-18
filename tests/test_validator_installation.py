"""Artifact preflight is read-only and uses the runtime signer's full validator."""
import json
from pathlib import Path
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys
from solslot_puzzles.artifact_schema_v4 import _rebuild_plan, build_public_artifact, artifact_signing_typed_data
from solslot_puzzles.enrollment_activation import activation_context
from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle
from solslot_api.validator_service import ValidatorEvidenceError
from tests.test_public_artifact import _signed_artifact
from solslot_api.validator_installation import validate_install_candidate


def candidate(tmp_path, identity_chain=84532):
    accounts=[Account.from_key(bytes(31)+bytes([i])) for i in (71,72,73)]
    original=_signed_artifact(accounts=accounts)
    plan=original['genesisPlan']
    active=json.loads((Path(__file__).parent/'fixtures/enrollment-activation.json').read_text())['enrollmentActivation']
    active['evmChainId']=identity_chain
    active['deploymentId']=original['ceremony']['ceremonyId']
    active['emitter']=original['evmAddresses']['attestationEmitter']
    context=activation_context(active).context_hash
    active['contextHash']='0x'+context.hex()
    active['bridgePolicyHash']='0x'+make_permit_bridge_puzzle([bytes.fromhex(k[2:]) for k in plan['validatorSet']['pubkeys']],context).get_tree_hash().hex()
    plan['enrollmentActivation']=active;plan['evmChainId']=84532
    a=build_public_artifact(plan=_rebuild_plan({'genesisPlan':plan}),spend_bundle_id=original['ceremony']['spendBundleId'],
        confirmed_block_index=1234,build_timestamp=original['buildTimestamp'],signatures=[],review_class=original['reviewClass'])
    typed=encode_typed_data(full_message=artifact_signing_typed_data(a))
    a['signatures']=[dict(adminIndex=i,compressedPubkey='0x'+keys.PrivateKey(bytes(accounts[i].key)).public_key.to_compressed_bytes().hex(),
        signature='0x'+bytes(accounts[i].sign_message(typed).signature).hex()) for i in (0,2)]
    artifact=tmp_path/'candidate.json';artifact.write_text(json.dumps(a))
    release=tmp_path/'release.json';release.write_text(json.dumps({'schemaVersion':2,'protocolVersion':'solslot-v2','api_commit':a['sourceShas']['api'],'protocol_commit':a['sourceShas']['protocol']}))
    config=dict(SIGNER_INDEX=0,DEPLOYMENT_ENVIRONMENT='staging-alpha',EVM_CHAIN_ID=identity_chain,EVM_RPC_URL='https://rpc.invalid',
        ENROLLMENT_ACTIVATION=json.dumps(a['enrollmentActivation'],separators=(',',':')),BRIDGE_POLICY_HASH=a['bridgePolicy']['policyHash'],
        ROSTER_PUBKEYS=json.dumps(a['validatorSet']['pubkeys']),
        EVM_FORWARDER_ADDRESS=a['evmAddresses']['forwarder'],EVM_VERIFIER_ADAPTER_ADDRESS=a['evmAddresses']['verifierAdapter'],
        EVM_ATTESTATION_EMITTER_ADDRESS=a['evmAddresses']['attestationEmitter'])
    env=tmp_path/'validator.env'
    def write():env.write_text('\n'.join('SOLSLOT_VALIDATOR_'+k+'='+str(v) for k,v in config.items()))
    write();return a,artifact,release,config,env,write


@pytest.mark.parametrize("identity_chain", [84532, 8453])
def test_signed_candidate_is_checked_without_reading_keys_or_installing(tmp_path, identity_chain):
    a,artifact,release,config,env,_=candidate(tmp_path, identity_chain)
    assert a["network"] == "testnet11" and a["evmChainId"] == 84532
    before={p:p.read_bytes() for p in (artifact,release,env)}
    assert validate_install_candidate(str(env),str(artifact),str(release))==a['artifactHash']
    assert {p:p.read_bytes() for p in before}==before


@pytest.mark.parametrize('failure',['activation_missing','wrong_chain','wrong_environment','wrong_address','wrong_revision','duplicate','unknown','corrupt_signature'])
def test_invalid_candidate_is_rejected_before_any_installation(tmp_path,failure):
    a,artifact,release,config,env,write=candidate(tmp_path)
    if failure=='activation_missing':config.pop('ENROLLMENT_ACTIVATION');write()
    elif failure=='wrong_chain':config['EVM_CHAIN_ID']=11155111;write()
    elif failure=='wrong_environment':config['DEPLOYMENT_ENVIRONMENT']='production-alpha';write()
    elif failure=='wrong_address':config['EVM_FORWARDER_ADDRESS']='0x'+'ab'*20;write()
    elif failure=='wrong_revision':release.write_text(json.dumps({'schemaVersion':2,'protocolVersion':'solslot-v2','api_commit':'f'*40,'protocol_commit':a['sourceShas']['protocol']}))
    elif failure=='duplicate':env.write_text(env.read_text()+'\nSOLSLOT_VALIDATOR_EVM_CHAIN_ID=84532')
    elif failure=='unknown':env.write_text(env.read_text()+'\nSOLSLOT_VALIDATOR_TYPO=84532')
    else:a['artifactHash']='0x'+'ab'*32;artifact.write_text(json.dumps(a))
    before={p:p.read_bytes() for p in (artifact,release,env)}
    with pytest.raises((ValueError,ValidatorEvidenceError)):validate_install_candidate(str(env),str(artifact),str(release))
    assert {p:p.read_bytes() for p in before}==before


def test_operator_environment_cannot_change_file_configuration(tmp_path,monkeypatch):
    a,artifact,release,config,env,_=candidate(tmp_path)
    monkeypatch.setenv('SOLSLOT_VALIDATOR_NETWORK','mainnet')
    monkeypatch.setenv('SOLSLOT_VALIDATOR_BRIDGE_POLICY_HASH','0x'+'ff'*32)
    assert validate_install_candidate(str(env),str(artifact),str(release))==a['artifactHash']


@pytest.mark.parametrize('legacy',[False,True])
def test_unit_supplied_index_and_stripe_credential_reference_are_compatible(tmp_path,legacy):
    a,artifact,release,config,env,write=candidate(tmp_path)
    if legacy:
        a=_signed_artifact();artifact.write_text(json.dumps(a))
        config.pop('ENROLLMENT_ACTIVATION');config.pop('DEPLOYMENT_ENVIRONMENT')
        config['EVM_CHAIN_ID']=11155111
        config['BRIDGE_POLICY_HASH']=a['bridgePolicy']['policyHash']
        config['ROSTER_PUBKEYS']=json.dumps(a['validatorSet']['pubkeys'])
        config['EVM_FORWARDER_ADDRESS']=a['evmAddresses']['forwarder']
        config['EVM_VERIFIER_ADAPTER_ADDRESS']=a['evmAddresses']['verifierAdapter']
        config['EVM_ATTESTATION_EMITTER_ADDRESS']=a['evmAddresses']['attestationEmitter']
    config.pop('SIGNER_INDEX')
    config.update(STRIPE_SETTLEMENT_ENABLED='true',STRIPE_ACCOUNT_ID='acct_synthetic')
    write()
    before={p:p.read_bytes() for p in (artifact,release,env)}
    unit=dict(signer_index='0',seed_file='%d/validator-seed',stripe_restricted_key_file='%d/stripe-read-key')
    assert validate_install_candidate(str(env),str(artifact),str(release),unit_environment=unit)==a['artifactHash']
    assert {p:p.read_bytes() for p in before}==before


def test_unit_metadata_reader_selects_only_fixed_public_references(monkeypatch):
    from solslot_api import validator_installation as module
    def read(command,*,text):
        assert command==['systemctl','show','--property','Environment','--value','solslot-validator.service'] and text
        return 'PYTHONUNBUFFERED=1 SOLSLOT_VALIDATOR_SIGNER_INDEX=2 SOLSLOT_VALIDATOR_SEED_FILE=%d/validator-seed "SOLSLOT_VALIDATOR_STRIPE_RESTRICTED_KEY_FILE=%d/stripe-read-key"'
    monkeypatch.setattr(module.subprocess,'check_output',read)
    assert module.validator_unit_environment()==dict(signer_index='2',seed_file='%d/validator-seed',stripe_restricted_key_file='%d/stripe-read-key')


def test_environment_file_precedence_is_preserved(tmp_path):
    a,artifact,release,config,env,write=candidate(tmp_path)
    # The file contains a valid index and overrides this unused unit value.
    assert validate_install_candidate(str(env),str(artifact),str(release),unit_environment={'signer_index':'9'})==a['artifactHash']


def test_unsupported_unit_field_is_not_an_operator_environment_escape(tmp_path):
    a,artifact,release,config,env,write=candidate(tmp_path)
    with pytest.raises(ValueError,match='unsupported'):
        validate_install_candidate(str(env),str(artifact),str(release),unit_environment={'enrollment_activation':'{}'})
