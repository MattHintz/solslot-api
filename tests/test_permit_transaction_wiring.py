"""Offline boundaries: real issuer signatures and canonical ABI, synthetic RPC."""
import copy
from dataclasses import replace
from types import SimpleNamespace
import pytest
from eth_abi import encode
from web3 import Web3
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException
from pydantic import ValidationError
from solslot_puzzles.enrollment_permit import EnrollmentPermit
from solslot_api import zkpassport_enrollments as enroll, zkpassport_relay as relay
from solslot_api.enrollment_permit_runtime import (
    BINDING_ABI, PERMIT_ABI, PERMIT_SELECTOR, LEGACY_SELECTOR, PERMIT_EVENT_TOPIC,
    PERMIT_EVENT_ABI, PROOF_PARAMS_ABI, decode_enrollment, validate_record_permit, require_calldata_record,
    verify_permit_event_pair, hx,
)
from solslot_api.validator_quorum import ValidatorClaim, PermitValidatorClaim, configured_bridge_policy_hash
from solslot_api.validator_app import ValidatorSignRequest
from solslot_api.validator_settings import ValidatorSettings
from tests.test_enrollment_permit_issuance import setup, signature
from tests.test_validator_quorum import _keys, _claim


def calldata(record, permit=None):
    p = permit or EnrollmentPermit.from_wire(record['enrollmentPermit'])
    values = (p.permit_id, p.context_hash, p.vault_launcher_id, p.current_vault_coin_id,
        p.owner_auth_type, p.owner_key_hash, p.bridge_coin_id, p.issued_at, p.expires_at)
    binding = (bytes.fromhex(record['vaultLauncherId'][2:]), bytes.fromhex(record['bridgeParentId'][2:]), 1)
    # Canonical private age-18 request; the cryptographic proof is synthetic.
    proof = encode([PROOF_PARAMS_ABI], [(bytes.fromhex('0000001400000000000000000000000000000000000000000000000000000000'),
        (b'k'*32, b'proof', [bytes(32)]*9), bytes.fromhex('0100021200'),
        (604800, 'staging.solslot.com', 'vault:'+record['vaultLauncherId'], False))])
    return PERMIT_SELECTOR + encode([BINDING_ABI, PERMIT_ABI, 'bytes', 'bytes'],
        [binding, values, bytes.fromhex(record['permitIssuerSignature'][2:]), proof])


def test_exact_calldata_owner_issuer_and_deadline(setup, monkeypatch):
    s=setup;record=s.issue();p=EnrollmentPermit.from_wire(record['enrollmentPermit'])
    monkeypatch.setattr(enroll,'_active_genesis_artifact',lambda _:s.a)
    data=calldata(record)
    assert relay._decode_enrollment_calldata(data)==(s.vault,record['bridgeParentId'],1)
    assert relay._validate_relay_permit(s.settings,record,s.session,data,live=True)==p
    for changed in (data+b'\x00'*32, LEGACY_SELECTOR+data[4:], data[:3]):
        with pytest.raises((ValueError, HTTPException)):relay._validate_relay_permit(s.settings,record,s.session,changed,live=True)
    legacy=LEGACY_SELECTOR+encode([BINDING_ABI,'bytes'],[(p.vault_launcher_id,bytes.fromhex(record['bridgeParentId'][2:]),1),b'proof'])
    with pytest.raises(ValueError):require_calldata_record(legacy,record,p)
    with pytest.raises(ValueError):require_calldata_record(data,{**record,'permitIssuerSignature':None},None)
    for field,value in [('owner_key','0x'+'11'*20)]:
        with pytest.raises(HTTPException):relay._validate_relay_permit(s.settings,record,replace(s.session,**{field:value}),data)
    s.clock[0]=p.expires_at
    assert relay._validate_relay_permit(s.settings,record,s.session,data)==p
    with pytest.raises(HTTPException):relay._validate_relay_permit(s.settings,record,s.session,data,live=True)


@pytest.mark.parametrize('field,value',[('permit_id',b'X'*32),('current_vault_coin_id',b'Y'*32),
    ('owner_key_hash',b'Z'*32),('context_hash',b'C'*32),('expires_at',1_900_000_899)])
def test_mutated_permit_cannot_reuse_issuer_or_calldata(setup,field,value):
    s=setup;r=s.issue();p=EnrollmentPermit.from_wire(r['enrollmentPermit']);changed=replace(p,**{field:value})
    with pytest.raises(ValueError):validate_record_permit({**r,'enrollmentPermit':changed.to_wire()},s.a)
    with pytest.raises(ValueError):require_calldata_record(calldata(r,changed),r,p)


def pair(s,r):
    p=EnrollmentPermit.from_wire(r['enrollmentPermit']);legacy=bytes32(b'm'*32)
    values=(p.permit_hash,p.current_vault_coin_id,p.owner_auth_type,p.owner_key_hash,p.issued_at,p.expires_at,p.validator_message(legacy))
    emitter=s.active['emitter']
    logs=[dict(address=emitter,logIndex=7,topics=[PERMIT_EVENT_TOPIC,p.permit_id,p.vault_launcher_id,p.bridge_coin_id],data=encode(PERMIT_EVENT_ABI,values)),
        dict(address=emitter,logIndex=8,topics=[enroll._ATTESTATION_EVENT_TOPIC],data=b'')]
    return dict(logs=logs,emitter=emitter,attestation_topic=enroll._ATTESTATION_EVENT_TOPIC,
        permit=p,legacy_message=legacy,block_timestamp=p.issued_at+1)


def test_pair_uses_inclusion_time_and_exact_commitments(setup):
    s=setup;r=s.issue();args=pair(s,r);p=args['permit']
    s.clock[0]=p.expires_at+86400
    assert verify_permit_event_pair(**args)==p.validator_message(args['legacy_message'])


@pytest.mark.parametrize('change',['missing','duplicate','wrong_emitter','reverse','missing_index','trailing','topic','commitment','at_expiry','before_issue'])
def test_pair_rejects_incomplete_reordered_or_expired_evidence(setup,change):
    s=setup;r=s.issue();args=pair(s,r);logs=args['logs']
    if change=='missing':logs.pop(0)
    elif change=='duplicate':logs.append(copy.deepcopy(logs[0]))
    elif change=='wrong_emitter':logs[0]['address']='0x'+'ee'*20
    elif change=='reverse':logs[0]['logIndex']=9
    elif change=='missing_index':logs[0].pop('logIndex')
    elif change=='trailing':logs[0]['data']+=b'\x00'*32
    elif change=='topic':logs[0]['topics'][2]=b'x'*32
    elif change=='commitment':logs[0]['data']=b'x'*32+logs[0]['data'][32:]
    elif change=='at_expiry':args['block_timestamp']=args['permit'].expires_at
    else:args['block_timestamp']=args['permit'].issued_at-1
    with pytest.raises(ValueError):verify_permit_event_pair(**args)


def test_legacy_claim_hash_and_selected_wire_version_are_distinct(setup):
    s=setup;r=s.issue();old=_claim(_keys());before=old.model_dump(mode='json');digest=old.canonical_hash()
    parsed=ValidatorSignRequest(claim=before,claimHash=digest).claim
    assert type(parsed) is ValidatorClaim and parsed.model_dump(mode='json')==before and parsed.canonical_hash()==digest
    new=PermitValidatorClaim(**before,claim_version='solslot.enrollment-permit-claim.v1',
        enrollment_permit=r['enrollmentPermit'],permit_issuer_signature=r['permitIssuerSignature'])
    roundtrip=ValidatorSignRequest(claim=new.model_dump(mode='json'),claimHash=new.canonical_hash()).claim
    assert type(roundtrip) is PermitValidatorClaim and roundtrip.canonical_hash()==new.canonical_hash()!=digest
    for field in ('claim_version','enrollment_permit','permit_issuer_signature'):
        altered=new.model_dump(mode='json');altered.pop(field)
        with pytest.raises(ValidationError):ValidatorSignRequest(claim=altered,claimHash=new.canonical_hash())


def signer_settings(s):
    a=s.a
    return dict(signer_index=0,seed_file='/unread-synthetic-only',evm_rpc_url='https://base.example.invalid',
        evm_chain_id=s.active['evmChainId'],deployment_environment='staging-alpha',enrollment_activation=s.active,
        bridge_policy_hash=s.active['bridgePolicyHash'],roster_pubkeys=a['validatorSet']['pubkeys'],
        evm_forwarder_address=a['evmAddresses']['forwarder'],evm_verifier_adapter_address=a['evmAddresses']['verifierAdapter'],
        evm_attestation_emitter_address=a['evmAddresses']['attestationEmitter'])


def test_signer_config_requires_complete_selected_context(setup):
    s=setup;values=signer_settings(s);checked=ValidatorSettings(**values)
    assert checked.enrollment_activation==s.active
    other_selected_chain=8453 if s.active['evmChainId']==84532 else 84532
    for field,value in [('evm_chain_id',11155111),('evm_chain_id',other_selected_chain),('deployment_environment','production-alpha'),
        ('enrollment_activation',None),('bridge_policy_hash','0x'+'ab'*32),('evm_attestation_emitter_address','0x'+'cd'*20)]:
        with pytest.raises(ValidationError):ValidatorSettings(**{**values,field:value})
    s.settings.zkpassport_validator_urls=['https://v0.test','https://v1.test','https://v2.test']
    s.settings.zkpassport_validator_pubkeys=s.a['validatorSet']['pubkeys']
    s.settings.zkpassport_emitter_address=s.active['emitter']
    assert configured_bridge_policy_hash(s.settings,activation=s.active)==s.active['bridgePolicyHash']
    from solslot_api.validator_quorum import ValidatorQuorumError
    s.settings.zkpassport_evm_chain_id=other_selected_chain
    with pytest.raises(ValidatorQuorumError):
        configured_bridge_policy_hash(s.settings,activation=s.active)


def canonical_case(s, monkeypatch, auth_type):
    """Real signed permits/owners; only artifact authority and RPC transport stubbed."""
    from chia_rs import Coin, AugSchemeMPL
    from chia.types.blockchain_format.program import Program
    from eth_keys import keys
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from solslot_api.faucet import AGG_SIG_ME_DATA
    from solslot_api import validator_service as vs
    from solslot_puzzles.vault_driver import puzzle_for_vault_full, one_leaf_merkle_root, DEFAULT_IDENTITY_ATTEST_ROOT, eip712_typed_data_for_vault_spend
    from solslot_puzzles.enrollment_permit import permit_owner_from_native
    from solslot_puzzles.zkpassport_attestation import ZkPassportAttestation, compute_attestation_root, compute_attestation_bridge_message, compute_validator_bridge_message
    bls=AugSchemeMPL.key_gen(b'o'*32)
    evm=keys.PrivateKey(bytes(31)+b'\x01')
    owner_key=bytes(bls.get_g1()) if auth_type==1 else evm.public_key.to_compressed_bytes()
    owner_address=owner_key if auth_type==1 else evm.public_key.to_canonical_address()
    policy=bytes32.from_hexstr(s.active['bridgePolicyHash']);launcher=bytes32.from_hexstr(s.vault)
    puzzle=puzzle_for_vault_full(launcher,owner_key,auth_type,one_leaf_merkle_root(owner_key),
        bytes32.from_hexstr(s.a['launcherIds']['pool']),identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,zkpassport_bridge_policy_hash=policy)
    vault=Coin(launcher,puzzle.get_tree_hash(),1)
    kind,digest=permit_owner_from_native(auth_type,owner_address)
    p=EnrollmentPermit(bytes32(b'P'*32),bytes32.from_hexstr(s.active['contextHash']),launcher,vault.name(),kind,digest,s.bridge.name(),s.clock[0],s.clock[0]+900)
    r=dict(enrollmentPermit=p.to_wire(),permitIssuerSignature=signature(s.active,p.to_wire()),permitIssuanceStatus='issued',
        vaultLauncherId=s.vault,bridgeCoinId=hx(s.bridge.name()),bridgeParentId=hx(s.bridge.parent_coin_info),bridgeAmount=1,
        bridgePolicyHash=hx(policy),network='testnet11',policyVersion=2)
    att=ZkPassportAttestation(launcher,bytes32(b'n'*32),1,bytes32(b's'*32),bytes32(b't'*32),s.clock[0]-10,2)
    leaf=att.leaf_hash;root=compute_attestation_root([leaf])
    bm=compute_attestation_bridge_message(vault_launcher_id=launcher,attestation_root=root,bridge_policy_hash=policy,policy_version=2)
    legacy=compute_validator_bridge_message(vault_launcher_id=launcher,attestation_root=root,bridge_policy_hash=policy,
        bridge_coin_id=s.bridge.name(),bridge_message=bm,attestation_leaf_hash=leaf,scoped_nullifier=att.scoped_nullifier,
        nullifier_type=1,service_scope_hash=att.service_scope_hash,service_subscope_hash=att.service_subscope_hash,
        proof_timestamp=att.proof_timestamp,policy_version=2)
    vm=p.validator_message(legacy);sender='0x'+'dd'*20 if auth_type==1 else hx(owner_address)
    tx=b'T'*32;blockhash=b'H'*32;emitter=s.active['emitter']
    coordinates=dict(address=emitter,blockNumber=20,blockHash=blockhash,transactionHash=tx,removed=False)
    logs=[dict(**coordinates,logIndex=2,topics=[PERMIT_EVENT_TOPIC,p.permit_id,launcher,p.bridge_coin_id],
        data=encode(PERMIT_EVENT_ABI,[p.permit_hash,p.current_vault_coin_id,kind,digest,p.issued_at,p.expires_at,vm])),
        dict(**coordinates,logIndex=3,topics=[enroll._ATTESTATION_EVENT_TOPIC,bytes(12)+bytes.fromhex(sender[2:]),launcher,att.scoped_nullifier],
        data=encode(['uint16','bytes32','bytes32','uint64','bytes32','bytes32','bytes32','uint64','bytes32','bytes32','bytes32','uint16'],
            [1,att.service_scope_hash,att.service_subscope_hash,att.proof_timestamp,leaf,root,s.bridge.parent_coin_info,1,s.bridge.name(),bm,policy,2]))]
    receipt=dict(status=1,transactionHash=tx,blockHash=blockhash,blockNumber=20,logs=logs)
    functions=SimpleNamespace(**{name:(lambda value=value:SimpleNamespace(call=lambda:value)) for name,value in dict(
        bridgePolicyHash=policy,permitContextHash=p.context_hash,permitIssuer=s.active['issuer'],
        verifier=s.a['evmAddresses']['verifierAdapter'],trustedDirectRelayer='0x'+'dd'*20).items()})
    functions.isTrustedForwarder=lambda _:SimpleNamespace(call=lambda:True)
    block=dict(hash=blockhash,number=20,timestamp=s.clock[0]+1)
    rpc=SimpleNamespace(eth=SimpleNamespace(chain_id=s.active['evmChainId'],block_number=40,get_transaction_receipt=lambda _:receipt,
        get_block=lambda _:block,get_code=lambda _:b'code',contract=lambda **_:SimpleNamespace(functions=functions)))
    class FakeWeb3(Web3):
        def __new__(cls,*args,**kwargs):return rpc
    monkeypatch.setattr(enroll,'Web3',FakeWeb3)
    monkeypatch.setattr(enroll,'_active_genesis_artifact',lambda _:s.a)
    if auth_type==1:
        message=bytes(Program.to([b'z',root,vault.name()]).get_tree_hash())+bytes(vault.name())+AGG_SIG_ME_DATA['testnet11']
        owner_signature=hx(bytes(AugSchemeMPL.sign(bls,message)))
    else:
        owner_signature=hx(Account.sign_message(encode_typed_data(full_message=eip712_typed_data_for_vault_spend(b'z',root,vault.name())),bytes(31)+b'\x01').signature)
    old=_claim(_keys()).model_dump()
    old.update(artifact_hash=s.a['artifactHash'],vault_launcher_id=s.vault,current_vault_coin_id=hx(vault.name()),
        owner_key=hx(owner_address),owner_auth_type=auth_type,owner_authorization=owner_signature,
        owner_authorization_hash=hx(__import__('hashlib').sha256(bytes.fromhex(owner_signature[2:])).digest()),
        current_timestamp=s.clock[0],evm_transaction_hash=hx(tx),evm_block_number=20,emitter_address=emitter,
        identity_attest_root=hx(root),attestation_leaf_hash=hx(leaf),scoped_nullifier=hx(att.scoped_nullifier),
        service_scope_hash=hx(att.service_scope_hash),service_subscope_hash=hx(att.service_subscope_hash),proof_timestamp=att.proof_timestamp,
        bridge_policy_hash=hx(policy),bridge_parent_id=hx(s.bridge.parent_coin_info),bridge_coin_id=hx(s.bridge.name()),validator_message=hx(vm))
    claim=PermitValidatorClaim(**old,claim_version='solslot.enrollment-permit-claim.v1',enrollment_permit=p.to_wire(),permit_issuer_signature=r['permitIssuerSignature'])
    settings=ValidatorSettings(**signer_settings(s))
    monkeypatch.setattr(vs,'load_validator_artifact',lambda _:(s.a,SimpleNamespace()))
    def coin_record(_,name,label):
        coin=vault if name==hx(vault.name()) else s.bridge
        return dict(coin=coin.to_json_dict(),confirmed_block_index=10,spent=False,spent_block_index=0)
    monkeypatch.setattr(vs,'_fetch_coin',coin_record)
    return SimpleNamespace(record=r,permit=p,claim=claim,settings=settings,receipt=receipt,block=block,rpc=rpc,vm=vm)


@pytest.mark.parametrize('auth_type',[1,3])
def test_full_event_reader_and_private_validator_reconstruct_owner_and_inputs(setup,monkeypatch,auth_type):
    from solslot_api import validator_service as vs
    s=setup;c=canonical_case(s,monkeypatch,auth_type)
    event=enroll._fetch_verified_evm_attestation(s.settings,transaction_hash=c.claim.evm_transaction_hash,
        expected_vault_launcher_id=s.vault,authenticated_artifact=s.a,permit_record=c.record)
    assert event.validator_message==hx(c.vm)
    vs.verify_validator_claim(c.settings,c.claim,c.claim.canonical_hash())
    # A historical canonical receipt remains readable; a new private signature does not.
    s.clock[0]=c.permit.expires_at
    assert enroll._fetch_verified_evm_attestation(s.settings,transaction_hash=c.claim.evm_transaction_hash,
        expected_vault_launcher_id=s.vault,authenticated_artifact=s.a,permit_record=c.record).validator_message==hx(c.vm)
    with pytest.raises(vs.ValidatorEvidenceError):vs.verify_validator_claim(c.settings,c.claim,c.claim.canonical_hash())


@pytest.mark.parametrize('change',['missing_pair','wrong_context','wrong_owner','changed_coin','legacy_claim','legacy_message','reorg','removed','expired_inclusion','padded_sender','trailing_attestation'])
def test_private_validator_rejects_alternate_evidence(setup,monkeypatch,change):
    from solslot_api import validator_service as vs
    s=setup;c=canonical_case(s,monkeypatch,3);claim=c.claim
    if change=='missing_pair':c.receipt['logs'].pop(0)
    elif change=='wrong_context':c.rpc.eth.contract().functions.permitContextHash=lambda:SimpleNamespace(call=lambda:b'W'*32)
    elif change=='wrong_owner':claim=claim.model_copy(update={'owner_key':'0x'+'cd'*20})
    elif change=='changed_coin':claim=claim.model_copy(update={'current_vault_coin_id':'0x'+'cd'*32})
    elif change=='legacy_claim':claim=ValidatorClaim(**{k:v for k,v in claim.model_dump().items() if k not in ('claim_version','enrollment_permit','permit_issuer_signature')})
    elif change=='legacy_message':claim=claim.model_copy(update={'validator_message':'0x'+'ab'*32})
    elif change=='reorg':c.block['hash']=b'R'*32
    elif change=='removed':c.receipt['logs'][0]['removed']=True
    elif change=='expired_inclusion':c.block['timestamp']=c.permit.expires_at
    elif change=='padded_sender':c.receipt['logs'][1]['topics'][1]=b'x'*12+c.receipt['logs'][1]['topics'][1][12:]
    else:c.receipt['logs'][1]['data']+=b'\x00'*32
    with pytest.raises((vs.ValidatorEvidenceError,HTTPException)):
        vs.verify_validator_claim(c.settings,claim,claim.canonical_hash())


@pytest.mark.parametrize('change',[None,'chain','other_selected_chain','context','missing_activation','environment'])
def test_preartifact_validator_health_binds_selected_release(setup,change):
    import asyncio, httpx
    from solslot_api.validator_quorum import probe_validator_health, ValidatorQuorumError
    s=setup;s.settings.zkpassport_validator_urls=['https://v0.test','https://v1.test','https://v2.test']
    s.settings.zkpassport_validator_pubkeys=s.a['validatorSet']['pubkeys'];s.settings.zkpassport_emitter_address=s.active['emitter']
    def response(request):
        index=int(request.url.host[1]);activation=copy.deepcopy(s.active)
        if change=='context':activation['contextHash']='0x'+'ab'*32
        if change=='environment':activation['environment']='production-alpha'
        observed_chain=s.active['evmChainId']
        if change=='chain':observed_chain=11155111
        if change=='other_selected_chain':observed_chain=8453 if observed_chain==84532 else 84532
        body=dict(status='healthy',signerIndex=index,validatorPubkey=s.a['validatorSet']['pubkeys'][index],
            apiCommit=s.a['sourceShas']['api'],protocolCommit=s.a['sourceShas']['protocol'],network='testnet11',
            bridgePolicyHash=s.active['bridgePolicyHash'],evmAddresses=s.a['evmAddresses'],
            artifactReady=False,artifactHash=None,ledgerReady=True,evmChainId=observed_chain,
            enrollmentActivation=None if change=='missing_activation' else activation)
        return httpx.Response(200,json=body)
    async def probe():
        async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
            return await probe_validator_health(s.settings,expected_api_commit=s.a['sourceShas']['api'],
                expected_protocol_commit=s.a['sourceShas']['protocol'],expected_network='testnet11',
                expected_bridge_policy_hash=s.active['bridgePolicyHash'],expected_evm_addresses=s.a['evmAddresses'],
                expected_artifact_ready=False,expected_enrollment_activation=s.active,client=client)
    if change is None:assert len(asyncio.run(probe()))==3
    else:
        with pytest.raises(ValidatorQuorumError):asyncio.run(probe())


@pytest.mark.parametrize('legacy',[False,True])
def test_validator_chain_environment_text_retains_legacy_compatibility(setup,monkeypatch,legacy):
    chain = 11155111 if legacy else setup.active["evmChainId"]
    s=setup;values=signer_settings(s);values.pop('evm_chain_id')
    if chain==11155111:values['enrollment_activation']=None
    monkeypatch.setenv('SOLSLOT_VALIDATOR_EVM_CHAIN_ID',str(chain))
    assert ValidatorSettings(**values).evm_chain_id==chain
    for bad in ('1','mainnet','true','84532.0','8453.0'):
        monkeypatch.setenv('SOLSLOT_VALIDATOR_EVM_CHAIN_ID',bad)
        with pytest.raises(ValidationError):ValidatorSettings(**values)


@pytest.mark.parametrize('auth_type',[1,3])
@pytest.mark.parametrize('indices',[(0,1),(0,2),(1,2)])
def test_selected_api_stamp_outcome_for_every_validator_pair(setup,monkeypatch,auth_type,indices):
    import asyncio
    from chia_rs import Coin, AugSchemeMPL, validate_clvm_and_signature, get_flags_for_height_and_constants, MEMPOOL_MODE
    from chia.consensus.default_constants import DEFAULT_CONSTANTS
    from chia_rs.sized_ints import uint32, uint64
    from chia.wallet.lineage_proof import LineageProof
    from eth_keys import keys
    from solslot_api import validator_service as vs, public_artifact
    from solslot_api.validator_quorum import ValidatorQuorumResult
    from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle
    from tests.test_zkpassport_enrollments import _request
    s=setup;validators=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (7,8,9)]
    pubkeys=[bytes(k.get_g1()) for k in validators]
    policy=make_permit_bridge_puzzle(pubkeys,bytes32.from_hexstr(s.active['contextHash'])).get_tree_hash()
    s.active['bridgePolicyHash']=hx(policy);s.a['validatorSet']['pubkeys']=[hx(k) for k in pubkeys]
    s.a['genesisPlan']['enrollmentActivation']=copy.deepcopy(s.active)
    s.a['bridgePolicy']['policyHash']=hx(policy);s.a['puzzleHashes']['bridgePolicy']=hx(policy)
    s.bridge=Coin(s.bridge.parent_coin_info,policy,1)
    s.a['bridgePolicy']['bridgeCoinIds']=[hx(s.bridge.name())]
    c=canonical_case(s,monkeypatch,auth_type)
    event=enroll._fetch_verified_evm_attestation(s.settings,transaction_hash=c.claim.evm_transaction_hash,
        expected_vault_launcher_id=s.vault,authenticated_artifact=s.a,permit_record=c.record)
    coin=Coin.from_json_dict(vs._fetch_coin(c.settings,c.claim.current_vault_coin_id,'vault')['coin'])
    owner_pubkey=(bytes(AugSchemeMPL.key_gen(b'o'*32).get_g1()) if auth_type==1 else
        keys.PrivateKey(bytes(31)+b'\x01').public_key.to_compressed_bytes())
    vault_record=SimpleNamespace(auth_type=auth_type,owner_pubkey=owner_pubkey,
        owner_evm_address=None if auth_type==1 else c.claim.owner_key)
    session=SimpleNamespace(owner_key=c.claim.owner_key,vault_record=vault_record,auth_type='chia_bls' if auth_type==1 else 'evm')
    receipt=enroll.VaultCredentialReceipt(vaultLauncherId=s.vault,network='testnet11',policyVersion=2,
        identityAttestRoot=event.identity_attest_root,attestationLeafHash=event.attestation_leaf_hash,
        attestationProof=enroll.AttestationProof(),bridgePolicyHash=event.bridge_policy_hash,
        bridgeParentId=event.bridge_parent_id,bridgeAmount=1,bridgeCoinId=event.bridge_coin_id,
        validatorMessage=event.validator_message,evmTxHash=event.transaction_hash,enrolledAt=s.clock[0])
    record={**c.record,'status':'evm_confirmed','createdAt':s.clock[0],'updatedAt':s.clock[0],'receipt':receipt.model_dump()}
    s.settings.zkpassport_validator_urls=['https://v0.test','https://v1.test','https://v2.test']
    s.settings.zkpassport_validator_pubkeys=s.a['validatorSet']['pubkeys'];s.settings.zkpassport_emitter_address=s.active['emitter']
    monkeypatch.setattr(public_artifact,'load_signed_public_artifact',lambda _:s.a)
    monkeypatch.setattr(enroll,'_settings',lambda:s.settings)
    monkeypatch.setattr(enroll,'verify_vault_session',lambda *_:session)
    monkeypatch.setattr(enroll,'get_registry',lambda:SimpleNamespace(get=lambda _:vault_record))
    monkeypatch.setattr(enroll,'get_credential_ledger',lambda _:SimpleNamespace(get_enrollment=lambda _:record,get_stamp_attempt=lambda _:None))
    monkeypatch.setattr(enroll,'_find_initial_vault_coin',lambda *_:coin)
    monkeypatch.setattr(enroll,'_verify_reserved_bridge_coin',lambda *_:s.bridge)
    launcher_record=s.records[s.vault]['coin']
    monkeypatch.setattr(enroll,'_initial_vault_lineage',lambda *_:LineageProof(parent_name=bytes32.from_hexstr(launcher_record['parent_coin_info']),amount=uint64(1)))
    frozen=[];monkeypatch.setattr(enroll,'_freeze_stamp_attempt',lambda _,claim,successor:frozen.append((claim,successor)))
    async def quorum(_,claim):
        assert isinstance(claim,PermitValidatorClaim) and claim.enrollment_permit==c.record['enrollmentPermit']
        return ValidatorQuorumResult(indices,AugSchemeMPL.aggregate([AugSchemeMPL.sign(validators[i],claim.signature_message()) for i in indices]),claim.canonical_hash())
    monkeypatch.setattr(enroll,'collect_validator_quorum',quorum)
    outcomes=[]
    async def inspect(_,**kwargs):
        bundle=kwargs['spend_bundle']
        assert bundle.coin_spends[0].coin==s.bridge
        assert bundle.coin_spends[1].coin==coin
        assert kwargs['expected_vault_coin'] in bundle.additions()
        flags=get_flags_for_height_and_constants(uint32(10_000_000),DEFAULT_CONSTANTS)|MEMPOOL_MODE
        # API uses the testnet aggregate-signature domain, so consensus must too.
        from solslot_api.faucet import AGG_SIG_ME_DATA
        constants=DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(AGG_SIG_ME_DATA['testnet11']))
        validate_clvm_and_signature(bundle,11_000_000_000,constants,flags)
        outcomes.append(bundle);return bundle
    monkeypatch.setattr(enroll,'_push_chia_stamp_and_mark_pending',inspect)
    asyncio.run(enroll.submit_evm_chia_stamp(s.vault,enroll.SubmitChiaStampRequest(signature=c.claim.owner_authorization,
        currentTimestamp=s.clock[0] if auth_type==1 else None),_request(SimpleNamespace())))
    assert len(outcomes)==1 and len(frozen)==1
