"""Synthetic issuer signatures and coin records; no external signing or broadcast."""
import asyncio
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
import pytest
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import HTTPException
from solslot_puzzles.enrollment_activation import activation_context
from solslot_puzzles.enrollment_permit import EnrollmentPermit,permit_signing_typed_data
from solslot_api import enrollment_permit_issuance as service,zkpassport_enrollments as enroll
from solslot_api.bridge_coin_policy import BridgeCoinPolicy
from solslot_api.config import Settings
from solslot_api.credential_auth import VerifiedVaultSession
from solslot_api.credential_ledger import CredentialLedger,LedgerConflict,LedgerRateLimited,get_credential_ledger

SYNTHETIC_KEY=bytes(31)+b'\x01'

def artifact(identity_chain=84532):
    value = json.loads((Path(__file__).parent/'fixtures/enrollment-activation.json').read_text())
    if identity_chain != 84532:
        from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle
        active = value['enrollmentActivation']
        active['evmChainId'] = identity_chain
        context = activation_context(active).context_hash
        active['contextHash'] = '0x' + context.hex()
        active['bridgePolicyHash'] = '0x' + make_permit_bridge_puzzle(
            [bytes.fromhex(k[2:]) for k in value['validatorSet']['pubkeys']], context).get_tree_hash().hex()
        value['genesisPlan']['enrollmentActivation'] = copy.deepcopy(active)
        value['genesisPlan']['puzzleHashes']['bridgePolicy'] = active['bridgePolicyHash']
        value['bridgePolicy']['policyHash'] = active['bridgePolicyHash']
        value['puzzleHashes']['bridgePolicy'] = active['bridgePolicyHash']
        value['bridgePolicy']['bridgeCoinIds'] = [
            '0x' + Coin(bytes32.from_hexstr(parent), bytes32.from_hexstr(active['bridgePolicyHash']), uint64(1)).name().hex()
            for parent in value['bridgePolicy']['parentCoinIds']]
    return value

def signature(activation,wire,key=SYNTHETIC_KEY):
    msg=encode_typed_data(full_message=permit_signing_typed_data(EnrollmentPermit.from_wire(wire),activation_context(activation)))
    return '0x'+Account.sign_message(msg,key).signature.hex()

@pytest.fixture(params=[84532, 8453], ids=["base-sepolia", "base-mainnet-identity"])
def setup(monkeypatch,tmp_path,request):
    a=artifact(request.param);active=a['enrollmentActivation'];policy=BridgeCoinPolicy.from_artifact(a)
    settings=Settings(runtime_environment='staging',network='testnet11',alpha_writes_enabled=True,
        zkpassport_evm_chain_id=request.param,eip712_chain_id=84532,zkpassport_ledger_db_path=str(tmp_path/'ledger.db'),
        enrollment_permit_release_identity=active['releaseIdentity'],enrollment_permit_issuer_key_ref=active['issuerKeyRef'],
        enrollment_permit_identity_client_id=active['issuerIdentityClientId'])
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    launcher=Coin(bytes32(b'l'*32),SINGLETON_LAUNCHER_HASH,uint64(1))
    vault='0x'+launcher.name().hex();coin=Coin(launcher.name(),bytes32(b'v'*32),uint64(1))
    session=VerifiedVaultSession(active['issuer'],'evm',vault,'testnet11',2_000_000_000,
        SimpleNamespace(auth_type=3,full_puzhash=coin.puzzle_hash))
    parent=a['bridgePolicy']['parentCoinIds'][0]
    bridge=Coin(bytes32.from_hexstr(parent),bytes32.from_hexstr(policy.policy_hash),uint64(1))
    candidate=enroll.BridgeCoinCandidate(parent,1,'0x'+bridge.name().hex())
    records={'0x'+c.name().hex():dict(coin=c.to_json_dict(),confirmed_block_index=123,spent_block_index=0,spent=False) for c in (coin,bridge)}
    records[vault]=dict(coin=launcher.to_json_dict(),confirmed_block_index=100,spent_block_index=123)
    monkeypatch.setattr(enroll,'_find_initial_vault_coin',lambda *_:coin)
    monkeypatch.setattr(enroll,'_expected_stamped_vault_puzzle_hash',lambda *args,**kwargs:'0x'+coin.puzzle_hash.hex())
    monkeypatch.setattr(enroll,'_fetch_coin_record_by_name',lambda _,name:records.get(name))
    monkeypatch.setattr(enroll,'_bridge_coin_candidates',lambda *args,**kwargs:[candidate])
    clock=[1_900_000_000];monkeypatch.setattr(service.time,'time',lambda:clock[0])
    calls=[]
    def signer(settings,activation,wire):
        # Durable evidence must exist before any external signing is attempted.
        reopened=CredentialLedger(settings.zkpassport_ledger_db_path)
        try:
            saved=reopened.get_enrollment_permit(vault)
            assert json.loads(saved['permit_json'])==wire and saved['issuer_signature'] is None
        finally:reopened.close()
        calls.append(copy.deepcopy(wire));return signature(activation,wire)
    def issue(**kw):
        return asyncio.run(service.reserve_and_issue_permit(settings,kw.pop('session',session),a,policy,signer=kw.pop('signer',signer),**kw))
    return SimpleNamespace(a=a,active=active,policy=policy,settings=settings,session=session,vault=vault,
        coin=coin,bridge=bridge,records=records,clock=clock,calls=calls,issue=issue,signer=signer,
        ledger=get_credential_ledger(settings))

def test_issuer_signed_reservation_survives_restart_and_model_roundtrip(setup,monkeypatch):
    s=setup;record=s.issue();wire=record['enrollmentPermit']
    assert record['permitIssuanceStatus']=='issued' and record['permitIssuerSignature']==signature(s.active,wire)
    assert wire['currentVaultCoinId']=='0x'+s.coin.name().hex()
    assert enroll.EnrollmentRecord.model_validate(record).model_dump()['enrollmentPermit']==wire
    reopened=CredentialLedger(s.settings.zkpassport_ledger_db_path)
    try:assert reopened.get_enrollment(s.vault)==record
    finally:reopened.close()
    s.clock[0]+=1000
    assert s.issue()==record and len(s.calls)==1 # receipt lookup never mints a renewal
    monkeypatch.setattr(enroll, '_active_genesis_artifact', lambda _: s.a)
    enroll._require_enrollment_bridge_policy(s.settings,record,policy=s.policy,execution=True)
    # Readiness validation is historical; only a new signing/submission asks for liveness.
    with pytest.raises(HTTPException) as error:
        enroll._record_permit(s.settings, record, now=s.clock[0])
    assert error.value.status_code==409
    enroll._require_enrollment_bridge_policy(s.settings,record,policy=s.policy)

@pytest.mark.parametrize('failure',['timeout','invalid','wrong_issuer'])
def test_interruption_preserves_original_permit_and_retry_deadline(setup,failure):
    s=setup
    def fail(settings,active,wire):
        if failure=='timeout':raise TimeoutError('synthetic-only-provider-error')
        return '0x00' if failure=='invalid' else signature(active,wire,b'\x02'*32)
    with pytest.raises(HTTPException) as error:s.issue(signer=fail)
    assert error.value.status_code==503
    pending=s.ledger.get_enrollment(s.vault);wire=pending['enrollmentPermit']
    assert pending['permitIssuanceStatus']=='pending'
    assert enroll._public_record(pending).enrollmentPermit is None
    with pytest.raises(HTTPException) as error:s.issue()
    assert error.value.status_code==429
    s.clock[0]+=5;record=s.issue()
    assert record['enrollmentPermit']==wire and len(s.calls)==1
    events=[r[0] for r in s.ledger._conn.execute('SELECT event FROM permit_issuance_history ORDER BY id')]
    assert events==['started','unavailable' if failure=='timeout' else 'invalid','started','issued']

def test_expired_pending_permit_is_never_renewed(setup):
    s=setup
    with pytest.raises(HTTPException):s.issue(signer=lambda *_:(_ for _ in ()).throw(TimeoutError()))
    before=s.ledger.get_enrollment_permit(s.vault);s.clock[0]+=901
    with pytest.raises(HTTPException) as error:s.issue()
    assert error.value.status_code==409 and not s.calls
    assert s.ledger.get_enrollment_permit(s.vault)==before

@pytest.mark.parametrize('field,value',[
    ('spent',True),('spent',0),('spent_block_index',1),('spent_block_index',False),
    ('confirmed_block_index',0),('confirmed_block_index',True),('coin',{})])
@pytest.mark.parametrize('which',['coin','bridge'])
def test_missing_spent_or_noncanonical_inputs_never_reach_issuer(setup,field,value,which):
    s=setup;s.records['0x'+getattr(s,which).name().hex()][field]=value
    with pytest.raises(HTTPException):s.issue()
    assert not s.calls

@pytest.mark.parametrize('field,value',[
    ('network','mainnet'),('runtime_environment','production'),('zkpassport_evm_chain_id',11155111),
    ('alpha_writes_enabled',False),('enrollment_permit_release_identity','0x'+'ab'*32),
    ('enrollment_permit_issuer_key_ref','https://wrong.test/key'),('enrollment_permit_identity_client_id','wrong')])
def test_other_release_network_and_write_freeze_do_not_reserve(setup,field,value):
    s=setup;setattr(s.settings,field,value)
    with pytest.raises((HTTPException,ValueError)):s.issue()
    assert not s.calls and s.ledger.get_enrollment(s.vault) is None

def test_recovery_only_session_and_unsupported_owner_cannot_issue(setup):
    s=setup
    with pytest.raises(HTTPException):s.issue(session=replace(s.session,scope='relay_recovery'))
    s.session.vault_record.auth_type=2
    with pytest.raises(HTTPException):s.issue()
    assert not s.calls and s.ledger.get_enrollment(s.vault) is None

@pytest.mark.parametrize('field,value',[
    ('enrollmentPermit',None),('permitIssuerSignature',None),('permitIssuanceStatus','pending'),
    ('bridgeParentId','0x'+'ef'*32),('bridgeCoinId','0x'+'de'*32),('network','mainnet'),('createdAt',1)])
def test_generic_updates_cannot_replace_issued_authorization(setup,field,value):
    s=setup;record=s.issue();changed=copy.deepcopy(record);changed[field]=value
    with pytest.raises(LedgerConflict):s.ledger.update_enrollment(changed)
    assert s.ledger.get_enrollment(s.vault)==record

def test_legacy_row_cannot_be_upgraded_and_first_reservation_remains(setup):
    s=setup;record=dict(vaultLauncherId=s.vault,bridgeCoinId='0x'+s.bridge.name().hex(),status='reserved',network='testnet11',policyVersion=2)
    s.ledger.reserve_enrollment(record=record,owner_key=s.session.owner_key)
    with pytest.raises(HTTPException) as error:s.issue()
    assert error.value.status_code==409 and s.ledger.get_enrollment(s.vault)==record and not s.calls

def test_late_valid_issuer_result_is_retained_without_extending_authorization(setup):
    s=setup
    def late(settings,active,wire):s.clock[0]=wire['expiresAt']+1;return signature(active,wire)
    with pytest.raises(HTTPException) as error:s.issue(signer=late)
    assert error.value.status_code==409
    row=s.ledger.get_enrollment(s.vault)
    assert row['permitIssuanceStatus']=='issued' and row['enrollmentPermit']['expiresAt']<s.clock[0]

def test_second_inflight_result_cannot_replace_first_signature(setup):
    s=setup
    with pytest.raises(HTTPException):s.issue(signer=lambda *_:(_ for _ in ()).throw(TimeoutError()))
    saved=s.ledger.get_enrollment_permit(s.vault);context=json.loads(saved['context_json']);wire=json.loads(saved['permit_json'])
    s.clock[0]+=5;a=s.ledger.begin_permit_issuance(s.vault,context)
    s.clock[0]+=5;b=s.ledger.begin_permit_issuance(s.vault,context)
    sig=signature(s.active,wire);first=s.ledger.finish_permit_issuance(s.vault,context,b,signature=sig)
    assert s.ledger.finish_permit_issuance(s.vault,context,a,signature=sig)==first
    with pytest.raises(LedgerConflict):s.ledger.finish_permit_issuance(s.vault,context,b,signature=sig)

def test_bls_owner_uses_native_to_permit_mapping(setup):
    from chia_rs import AugSchemeMPL
    import hashlib
    s=setup;owner=bytes(AugSchemeMPL.key_gen(b's'*32).get_g1())
    s.session.vault_record.auth_type=1
    record=s.issue(session=replace(s.session,owner_key='0x'+owner.hex(),auth_type='chia_bls'))
    assert record['enrollmentPermit']['ownerAuthType']==1
    assert record['enrollmentPermit']['ownerKeyHash']=='0x'+hashlib.sha256(owner).hexdigest()

def test_genesis_signatures_bind_explicit_chain_and_old_default():
    from solslot_puzzles.genesis_signing import genesis_plan_signing_typed_data,genesis_artifact_signing_typed_data
    from solslot_api.genesis import _plan_typed_data,DraftRequest
    from tests.test_genesis_api import _source_shas
    params=dict(ceremony_id='0x'+'aa'*32,roster_hash='0x'+'bb'*32,plan_hash='0x'+'cc'*32,expires_at=2000000000)
    legacy=genesis_plan_signing_typed_data(**params)
    assert legacy==genesis_plan_signing_typed_data(**params,chain_id=11155111)
    selected=genesis_plan_signing_typed_data(**params,chain_id=84532)
    signed=Account.sign_message(encode_typed_data(full_message=selected),SYNTHETIC_KEY).signature
    expected=Account.from_key(SYNTHETIC_KEY).address
    assert Account.recover_message(encode_typed_data(full_message=selected),signature=signed)==expected
    assert Account.recover_message(encode_typed_data(full_message=legacy),signature=signed)!=expected
    assert DraftRequest(sourceShas=_source_shas()).evm_chain_id==11155111
    assert DraftRequest(sourceShas=_source_shas(),evmChainId=84532).evm_chain_id==84532
    assert genesis_artifact_signing_typed_data(artifact())['domain']['chainId']==84532

@pytest.mark.parametrize('field,value',[('ownerAuthType',True),('issuedAt',1900000000.0),('expiresAt',1900000900.0)])
def test_boolean_and_float_aliases_cannot_change_protected_wire(setup,field,value):
    from chia_rs import AugSchemeMPL
    s=setup;owner=bytes(AugSchemeMPL.key_gen(b's'*32).get_g1());s.session.vault_record.auth_type=1
    row=s.issue(session=replace(s.session,owner_key='0x'+owner.hex(),auth_type='chia_bls'))
    changed=copy.deepcopy(row);changed['enrollmentPermit'][field]=value
    with pytest.raises(LedgerConflict):s.ledger.update_enrollment(changed)
    assert s.ledger.get_enrollment(s.vault)==row
    assert enroll.EnrollmentRecord.model_validate(row).enrollmentPermit==row['enrollmentPermit']

def test_nonlauncher_parent_never_reaches_issuer(setup):
    s=setup;s.records[s.vault]['coin']['puzzle_hash']='0x'+'12'*32
    with pytest.raises(HTTPException):s.issue()
    assert not s.calls and s.ledger.get_enrollment(s.vault) is None

@pytest.mark.parametrize("identity_chain", [84532, 8453])
def test_permit_network_posture_requires_explicit_complete_metadata_and_matching_wallet_chain(identity_chain):
    from tests.test_server_hardening import _staging
    from solslot_api.config import validate_server_hardening_at_startup
    active=artifact()['enrollmentActivation']
    values=dict(eip712_chain_id=84532,zkpassport_evm_chain_id=identity_chain,
        enrollment_permit_release_identity=active['releaseIdentity'],enrollment_permit_issuer_key_ref=active['issuerKeyRef'],
        enrollment_permit_identity_client_id=active['issuerIdentityClientId'])
    validate_server_hardening_at_startup(_staging(**values))
    validate_server_hardening_at_startup(_staging())
    for change in [dict(eip712_chain_id=8453),dict(zkpassport_evm_chain_id=1),dict(eip712_chain_id=11155111),dict(enrollment_permit_identity_client_id=''),dict(network='mainnet')]:
        with pytest.raises(RuntimeError):validate_server_hardening_at_startup(_staging(**{**values,**change}))
    with pytest.raises(RuntimeError):validate_server_hardening_at_startup(_staging(eip712_chain_id=84532,zkpassport_evm_chain_id=84532))

def test_selected_genesis_cannot_reuse_legacy_deployment_verification_or_sign_faucet(monkeypatch):
    from solslot_api import genesis,genesis_evm
    selected=artifact()['genesisPlan']
    monkeypatch.setattr(genesis_evm,'Path',lambda *_:pytest.fail('must reject before reading legacy evidence'))
    with pytest.raises(genesis_evm.GenesisEvmEvidenceError,match='invalid selected activation'):
        genesis_evm.verify_genesis_evm_deployment(Settings(),{},selected)
    record=dict(draft=dict(evmChainId=84532),plan_input=dict(enrollmentActivation=selected['enrollmentActivation']))
    monkeypatch.setattr(genesis, '_faucet', lambda: pytest.fail('unapproved selection must not sign faucet inputs'))
    with pytest.raises(genesis.GenesisConflict,match='Authority V3 launch approval failed'):
        asyncio.run(genesis._prepare_bundle(Settings(),record))

def test_unsigned_legacy_artifact_cannot_acquire_permit_runtime_configuration(setup):
    from solslot_api.public_artifact import _verify_runtime_bindings,PublicArtifactError
    old=json.loads((Path(__file__).parent/'fixtures/enrollment-activation-legacy.json').read_text())
    with pytest.raises(PublicArtifactError,match='requires signed enrollment activation'):_verify_runtime_bindings(setup.settings,old)
