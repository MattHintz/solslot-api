"""Selected provenance verification against controlled RPCs; no live deployment."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import rlp
from web3 import Web3

from solslot_puzzles.enrollment_activation import activation_context
from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle
from solslot_api import genesis_permit_evm as selected, launch_control as launch
from solslot_api.genesis_evm import verify_genesis_evm_deployment, GenesisEvmEvidenceError, _canonical_hash
from solslot_api.config import Settings


def digest(value):
    return hashlib.sha256(value).hexdigest()


def reseal(s):
    s.deployment['artifactHash'] = _canonical_hash({k:v for k,v in s.deployment.items() if k!='artifactHash'})
    s.review['deploymentArtifactHash'] = s.deployment['artifactHash']
    s.review['activationHash'] = _canonical_hash({k:v for k,v in s.active.items() if k!='reviewEvidenceSha256'})
    raw = json.dumps(s.review).encode()
    Path(s.settings.enrollment_deployment_review_path).write_bytes(raw)
    s.active['reviewEvidenceSha256'] = digest(raw)
    s.settings.enrollment_deployment_review_sha256 = digest(raw)
    Path(s.settings.genesis_evm_deployment_path).write_text(json.dumps(s.deployment))


@pytest.fixture
def deployment_setup(tmp_path, monkeypatch):
    artifact=json.loads((Path(__file__).parent/'fixtures/enrollment-activation.json').read_text())
    plan=artifact['genesisPlan'];active=plan['enrollmentActivation']
    deployer='0x'+'dd'*20;start=7
    addresses={name:'0x'+Web3.keccak(rlp.encode([bytes.fromhex(deployer[2:]),start+i]))[-20:].hex()
        for i,name in enumerate(selected.EVM_CONTRACTS)}
    plan['evmAddresses']=addresses;active['emitter']=addresses['attestationEmitter']
    context=activation_context(active).context_hash
    active['contextHash']='0x'+context.hex()
    active['bridgePolicyHash']='0x'+make_permit_bridge_puzzle([bytes.fromhex(k[2:]) for k in plan['validatorSet']['pubkeys']],context).get_tree_hash().hex()
    plan['puzzleHashes']['bridgePolicy']=active['bridgePolicyHash']
    record=dict(ceremony_id=plan['ceremonyId'],draft=dict(evmChainId=84532,sourceShas=active['sourceShas']),
        plan=plan,plan_input=dict(enrollmentActivation=active))
    codes={name:('runtime-'+name).encode() for name in (*selected.EVM_CONTRACTS,'zkPassportRootVerifier')}
    txs={name:dict(hash='0x'+f'{i+1:02x}'*32,blockNumber=100+i,blockHash='0x'+f'{i+11:02x}'*32,
        nonce=start+i,initCodeHash='0x'+Web3.keccak(('init-'+name).encode()).hex()) for i,name in enumerate(selected.EVM_CONTRACTS)}
    deployment=dict(schemaVersion=3,protocolVersion='solslot-v2',credentialPolicyVersion=2,network='baseSepolia',chainId=84532,
        sourceShas=copy.deepcopy(active['sourceShas']),deployer=deployer,startNonce=start,
        **{field:addresses[name] for name,field in selected.ADDRESS_FIELDS.items()},
        trustedDirectRelayerAddress='0x'+'aa'*20,bridgePolicyHash=active['bridgePolicyHash'],
        zkPassportRootVerifierAddress=selected.ROOT_VERIFIER,zkPassportDomain='staging.solslot.com',zkPassportDevMode=False,
        permitIssuer=active['issuer'],permitContextHash=active['contextHash'],deploymentId=active['deploymentId'],
        releaseIdentity=active['releaseIdentity'],deploymentTransactions=txs,
        runtimeCodeHashes={name:'0x'+Web3.keccak(code).hex() for name,code in codes.items()})
    release_tag='solslot-v2-alpha-rc99.1-20260912'
    manifest=dict(schemaVersion=4,kind='solslot-release-source-manifest',releaseId=release_tag,network='testnet11',testOnly=True,
        sourceShas=active['sourceShas'],dependencies={'administratorRecovery':dict(repository=launch.PINNED_CNI_WALLET_SDK_REPOSITORY,
        commit=launch.PINNED_CNI_WALLET_SDK_COMMIT,license=launch.PINNED_CNI_WALLET_SDK_LICENSE,manifestHash=launch.RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX)},
        authoritySourceCommitment=launch._authority_source_commitment(active['sourceShas']),
        sources={name:dict(repository='https://github.com/'+selected.SOURCE_REPOSITORIES[name],branch='release/testnet-alpha-rc99.1-20260912',commit=sha) for name,sha in active['sourceShas'].items()})
    manifest['manifestHash']=launch._source_manifest_hash(manifest)
    release=dict(schemaVersion=5,kind='solslot-rc27-launch-source-evidence',network='testnet11',testOnly=True,
        completeReleaseManifest=True,releaseRefsVerified=True,releaseTag=release_tag,releaseId=release_tag,
        manifestHash=manifest['manifestHash'],sourceManifest=manifest)
    raw=json.dumps(release).encode();(tmp_path/'release.json').write_bytes(raw)
    review=dict(schema='solslot.enrollment-deployment-review.v1',outcome='approved',activationHash='',deploymentArtifactHash='',
        releaseEvidenceSha256=digest(raw),manifestHash=manifest['manifestHash'],sourceShas=copy.deepcopy(active['sourceShas']),
        reviews=[dict(scope=scope,approved=True,reviewer='synthetic-'+scope,evidenceHash='0x'+'ab'*32) for scope in sorted(selected.REVIEW_SCOPES)])
    settings=Settings(runtime_environment='staging',network='testnet11',eip712_chain_id=84532,zkpassport_evm_chain_id=84532,
        zkpassport_evm_rpc_url='https://rpc.invalid',genesis_evm_deployment_path=str(tmp_path/'deployment.json'),
        enrollment_deployment_review_path=str(tmp_path/'review.json'),enrollment_deployment_review_sha256='',
        enrollment_permit_release_identity=active['releaseIdentity'],enrollment_permit_issuer_key_ref=active['issuerKeyRef'],
        enrollment_permit_identity_client_id=active['issuerIdentityClientId'],launch_release_tag=release_tag,
        launch_source_evidence_path=str(tmp_path/'release.json'),launch_source_evidence_sha256=digest(raw))
    class Eth:
        chain_id=84532
        block_number=120
        def get_block(self,n): return {'hash':self.blocks[n]}
        def get_transaction_receipt(self,h): return copy.deepcopy(self.receipts[h])
        def get_transaction(self,h): return copy.deepcopy(self.transactions[h])
        def get_code(self,a,*,block_identifier):
            assert block_identifier==120
            return self.codes[a.lower()]
        def contract(self,*,address,abi):
            name=abi[0]['name']
            def fn(*args):
                if name=='isTrustedForwarder':assert args[0].lower()==addresses['forwarder']
                def call(*,block_identifier):
                    assert block_identifier==120
                    return self.getters[(address.lower(),name)]
                return SimpleNamespace(call=call)
            return SimpleNamespace(functions=SimpleNamespace(**{name:fn}))
    eth=Eth();eth.blocks={120:'0x'+'ef'*32};eth.receipts={};eth.transactions={}
    for name,item in txs.items():
        h=item['hash'];eth.blocks[item['blockNumber']]=item['blockHash']
        eth.receipts[h]=dict(status=1,transactionHash=h,blockNumber=item['blockNumber'],blockHash=item['blockHash'],contractAddress=addresses[name])
        eth.transactions[h]=dict(hash=h,blockNumber=item['blockNumber'],blockHash=item['blockHash'],nonce=item['nonce'],
            chainId=84532,value=0,to=None,input='0x'+('init-'+name).encode().hex(),**{'from':deployer})
    eth.codes={**{addresses[name]:codes[name] for name in addresses},selected.ROOT_VERIFIER:codes['zkPassportRootVerifier']}
    emitter=addresses['attestationEmitter'];adapter=addresses['verifierAdapter']
    eth.getters={(emitter,name):value for name,value in dict(bridgePolicyHash=active['bridgePolicyHash'],permitContextHash=active['contextHash'],
        permitIssuer=active['issuer'],verifier=adapter,trustedDirectRelayer=deployment['trustedDirectRelayerAddress'],POLICY_VERSION=2,isTrustedForwarder=True).items()}
    eth.getters.update({(adapter,name):value for name,value in dict(ZKPASSPORT_ROOT_VERIFIER=selected.ROOT_VERIFIER,
        domain='staging.solslot.com',devMode=False,DEFAULT_VALIDITY_SECONDS=604800,MINIMUM_AGE=18).items()})
    class FakeWeb3:
        HTTPProvider=staticmethod(lambda *a,**kw:None)
        keccak=staticmethod(Web3.keccak)
        to_checksum_address=staticmethod(Web3.to_checksum_address)
        def __init__(self,*args):self.eth=eth
        def is_connected(self):return True
    monkeypatch.setattr(selected,'Web3',FakeWeb3)
    s=SimpleNamespace(settings=settings,record=record,plan=plan,active=active,deployment=deployment,review=review,eth=eth,release=release)
    reseal(s);return s


def verify(s): return verify_genesis_evm_deployment(s.settings,s.record,s.plan)


def test_selected_deployment_requires_independent_pins_and_returns_bound_receipts(deployment_setup):
    s=deployment_setup;result=verify(s)
    assert result['chainId']==84532 and result['checkedAtBlock']==120
    assert result['enrollmentDeploymentReview']['receipt']==s.review
    for name,contract in result['contracts'].items():
        assert contract['transactionHash']==s.deployment['deploymentTransactions'][name]['hash']
        assert contract['bytecodeHash']==s.deployment['runtimeCodeHashes'][name]
    s.settings.enrollment_deployment_review_sha256=''
    with pytest.raises(GenesisEvmEvidenceError,match='operator pin'):verify(s)


@pytest.mark.parametrize('failure',['review_bytes','source_bytes','missing_review_pin','missing_source_pin','wrong_manifest','unapproved','duplicate_lane','missing_lane','activation','chain','null_activation','runtime_environment','coordinator_issuer','plan_input','plan_sources'])
def test_selected_review_and_configuration_fail_closed(deployment_setup,failure):
    s=deployment_setup
    if failure=='review_bytes':Path(s.settings.enrollment_deployment_review_path).write_text('{}')
    elif failure=='source_bytes':Path(s.settings.launch_source_evidence_path).write_text('{}')
    elif failure=='missing_review_pin':s.settings.enrollment_deployment_review_sha256=''
    elif failure=='missing_source_pin':s.settings.launch_source_evidence_sha256=None
    elif failure=='wrong_manifest':s.review['manifestHash']='0x'+'ab'*32;reseal(s)
    elif failure=='unapproved':s.review['reviews'][0]['approved']=False;reseal(s)
    elif failure=='duplicate_lane':s.review['reviews'][0]=copy.deepcopy(s.review['reviews'][1]);reseal(s)
    elif failure=='missing_lane':s.review['reviews'].pop();reseal(s)
    elif failure=='activation':s.active['contextHash']='0x'+'ab'*32
    elif failure=='chain':s.plan['evmChainId']=11155111
    elif failure=='null_activation':s.plan['enrollmentActivation']=None
    elif failure=='runtime_environment':s.settings.runtime_environment='production'
    elif failure=='coordinator_issuer':s.settings.enrollment_permit_issuer_key_ref='https://wrong.invalid'
    elif failure=='plan_input':s.record['plan_input']['enrollmentActivation']=None
    elif failure=='plan_sources':s.plan['sourceShas']={}
    with pytest.raises(GenesisEvmEvidenceError):verify(s)


@pytest.mark.parametrize('component', sorted(['protocol','evm','omnichain','api','legacyBackend','keyOfSolomon','samuel','customerWeb','adminPortal']))
def test_any_deployment_revision_drift_is_rejected_even_if_json_is_rehashed(deployment_setup,component):
    s=deployment_setup;s.deployment['sourceShas'][component]='f'*40;reseal(s)
    with pytest.raises(GenesisEvmEvidenceError,match='differs'):verify(s)


@pytest.mark.parametrize('field,value',[('chainId',11155111),('nonce',8),('value',1),('to','0x'+'ab'*20),('from','0x'+'bc'*20),
    ('hash','0x'+'cc'*32),('blockHash','0x'+'cc'*32),('blockNumber',90),('input','0xff')])
def test_changed_transaction_provenance_is_rejected(deployment_setup,field,value):
    s=deployment_setup;h=s.deployment['deploymentTransactions']['forwarder']['hash'];s.eth.transactions[h][field]=value
    with pytest.raises(GenesisEvmEvidenceError):verify(s)


@pytest.mark.parametrize('field,value',[('status',0),('transactionHash','0x'+'cc'*32),('blockHash','0x'+'cc'*32),('blockNumber',90),('contractAddress','0x'+'cc'*20)])
def test_changed_receipt_is_rejected(deployment_setup,field,value):
    s=deployment_setup;h=s.deployment['deploymentTransactions']['forwarder']['hash'];s.eth.receipts[h][field]=value
    with pytest.raises(GenesisEvmEvidenceError):verify(s)


@pytest.mark.parametrize('failure',['reorg','shallow','wrong_rpc','missing_runtime','changed_runtime','planned_nonce','planned_address','missing_transaction','bool_nonce','duplicate_json','symlink'])
def test_canonical_state_and_planned_identity_are_required(deployment_setup,failure):
    s=deployment_setup
    if failure=='reorg':s.eth.blocks[100]='0x'+'cc'*32
    elif failure=='shallow':s.eth.block_number=110
    elif failure=='wrong_rpc':s.eth.chain_id=1
    elif failure=='missing_runtime':s.eth.codes[selected.ROOT_VERIFIER]=b''
    elif failure=='changed_runtime':s.eth.codes[selected.ROOT_VERIFIER]=b'changed'
    elif failure=='planned_nonce':s.deployment['startNonce']+=1;reseal(s)
    elif failure=='planned_address':s.deployment['forwarderAddress']='0x'+'cc'*20;reseal(s)
    elif failure=='missing_transaction':s.deployment['deploymentTransactions'].pop('forwarder');reseal(s)
    elif failure=='bool_nonce':s.deployment['startNonce']=True;reseal(s)
    elif failure=='duplicate_json':
        p=Path(s.settings.genesis_evm_deployment_path);p.write_text(p.read_text()[:-1]+',"chainId":84532}')
    elif failure=='symlink':
        p=Path(s.settings.genesis_evm_deployment_path);p.rename(p.with_suffix('.held'));p.symlink_to(p.with_suffix('.held'))
    with pytest.raises(GenesisEvmEvidenceError):verify(s)


@pytest.mark.parametrize('getter',['bridgePolicyHash','permitContextHash','permitIssuer','verifier','trustedDirectRelayer','POLICY_VERSION','isTrustedForwarder',
    'ZKPASSPORT_ROOT_VERIFIER','domain','devMode','DEFAULT_VALIDITY_SECONDS','MINIMUM_AGE'])
def test_runtime_getters_must_match_review(deployment_setup,getter):
    s=deployment_setup;key=next(k for k in s.eth.getters if k[1]==getter);value=s.eth.getters[key]
    s.eth.getters[key]=(not value if type(value) is bool else value+1 if type(value) is int else 'wrong')
    with pytest.raises(GenesisEvmEvidenceError):verify(s)


def test_reorganization_during_snapshot_read_is_rejected(deployment_setup):
    s=deployment_setup;original=s.eth.get_block;reads=0
    def get_block(n):
        nonlocal reads
        if n==120:
            reads+=1
            if reads>1:return {'hash':'0x'+'cc'*32}
        return original(n)
    s.eth.get_block=get_block
    with pytest.raises(GenesisEvmEvidenceError,match='reorganized'):verify(s)


def test_self_rehashed_source_record_cannot_transfer_repository_ownership(deployment_setup):
    s=deployment_setup
    manifest=s.release['sourceManifest'];manifest['sources']['api']['repository']='https://github.com/other/solslot-api'
    manifest['manifestHash']=launch._source_manifest_hash(manifest);s.release['manifestHash']=manifest['manifestHash']
    raw=json.dumps(s.release).encode();Path(s.settings.launch_source_evidence_path).write_bytes(raw)
    s.settings.launch_source_evidence_sha256=digest(raw);s.review['releaseEvidenceSha256']=digest(raw);s.review['manifestHash']=manifest['manifestHash'];reseal(s)
    with pytest.raises(GenesisEvmEvidenceError,match='ownership'):verify(s)
