"""Real local EVM signatures, SQLite restarts and provider-boundary failures."""
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import json
import time
import pytest
from eth_account import Account
from eth_abi import encode
from web3 import Web3
from web3.exceptions import TransactionNotFound
from starlette.requests import Request
from fastapi import HTTPException
from solslot_api import zkpassport_relay as relay, public_artifact
from solslot_api.config import Settings
from solslot_api.credential_ledger import CredentialLedger, LedgerConflict

VAULT='0x'+'11'*32
PARENT='0x'+'22'*32
POLICY='0x'+'33'*32
EMITTER='0x'+'44'*20
FORWARDER='0x'+'55'*20
OWNER=Account.from_key(bytes([1])*32)
RELAYER=Account.from_key(bytes([2])*32)
BLS='0x'+'66'*48
BRIDGE=relay.Web3.to_hex(Web3.keccak(text='synthetic bridge'))

@pytest.fixture
def rig(tmp_path, monkeypatch):
    from solslot_api.zkpassport_enrollments import _coin_id
    bridge=_coin_id(PARENT,POLICY,1)
    ledger=CredentialLedger(tmp_path/'relay.db')
    settings=Settings(runtime_environment='test',network='testnet11',alpha_writes_enabled=True,
        zkpassport_emitter_address=EMITTER,zkpassport_forwarder_address=FORWARDER,
        zkpassport_bridge_policy_hash=POLICY,zkpassport_evm_chain_id=11155111,
        zkpassport_ledger_db_path=str(tmp_path/'relay.db'))
    artifact={'artifactHash':'0x'+'77'*32,'network':'testnet11',
        'bridgePolicy':{'policyHash':POLICY,'parentCoinIds':[PARENT],'bridgeCoinIds':[bridge]},
        'evmAddresses':{'attestationEmitter':EMITTER,'forwarder':FORWARDER}}
    now=int(time.time())
    data=Web3.to_bytes(hexstr=relay._VERIFY_AND_EMIT_SELECTOR)+encode(
        ['(bytes32,bytes32,uint64)','bytes'],[(bytes.fromhex(VAULT[2:]),bytes.fromhex(PARENT[2:]),1),b'proof'])
    session=SimpleNamespace(auth_type='chia_bls',owner_key=BLS,network='testnet11',
        vault_record=SimpleNamespace(owner_evm_address=None))
    record=dict(vaultLauncherId=VAULT,network='testnet11',policyVersion=2,status='reserved',
        bridgePolicyHash=POLICY,bridgeParentId=PARENT,bridgeAmount=1,bridgeCoinId=bridge,
        createdAt=now,updatedAt=now,receipt=None)
    class Call:
        def __init__(self,value=None,request=None):self.value=value;self.request=request
        def call(self,*a):return self.value
        def estimate_gas(self,*a):return 1000000
        def build_transaction(self,fields):
            return {**fields,'to':FORWARDER,'data':'0x'+encode(['bytes'],[data]).hex(),'gasPrice':7}
    class Functions:
        def bridgePolicyHash(self):return Call(bytes.fromhex(POLICY[2:]))
        def trustedDirectRelayer(self):return Call(RELAYER.address)
        def isTrustedForwarder(self,*a):return Call(True)
        def verify(self,*a):return Call(True)
        def execute(self,*a):return Call(request=a)
        def nonces(self,*a):return Call(3)
    class Eth:
        chain_id=11155111;gas_price=7;block_number=112
        fail=False;send_count=0;raw=[];receipt=None
        def get_code(self,*a):return b'code'
        def contract(self,*a,**k):return SimpleNamespace(functions=Functions())
        def call(self,*a):return b''
        def estimate_gas(self,*a):return 1000000
        def get_transaction_count(self,*a):return 9
        def send_raw_transaction(self,raw):
            self.send_count+=1;self.raw.append(bytes(raw))
            if hasattr(ledger,'get_relay_transaction'):
                saved=ledger.get_relay_transaction(VAULT)
                assert saved and bytes.fromhex(saved['raw_transaction_hex'])==bytes(raw)
                assert saved['tx_hash']==Web3.to_hex(Web3.keccak(raw))
                assert saved['dispatch_status']=='unknown'
            if self.fail:raise TimeoutError('provider accepted bytes then response was lost')
            return Web3.keccak(raw)
        def get_transaction_receipt(self,*a):
            if self.receipt is None:raise TransactionNotFound('pending')
            return self.receipt
        def get_block(self,*a):return {'hash':bytes.fromhex('88'*32),'number':100,'timestamp':now}
    w3=SimpleNamespace(eth=Eth(),to_hex=Web3.to_hex)
    counts={'auth':0,'sign':0}
    class SigningAccount:
        address=RELAYER.address
        def sign_transaction(self,tx):counts['sign']+=1;return RELAYER.sign_transaction(tx)
    def auth(*a,**k):counts['auth']+=1;return session
    monkeypatch.setattr(relay,'_load_settings',lambda:settings)
    monkeypatch.setattr(relay,'_require_relayer_account',lambda s:SigningAccount())
    monkeypatch.setattr(relay,'_w3',lambda u:w3)
    monkeypatch.setattr(relay,'get_credential_ledger',lambda s:ledger)
    monkeypatch.setattr(relay,'verify_vault_session',lambda *a,**k:session)
    monkeypatch.setattr(relay,'verify_owner_auth',auth)
    monkeypatch.setattr(public_artifact,'load_signed_public_artifact',lambda s:artifact)
    request=Request({'type':'http','method':'POST','path':'/zkpassport/relay/bls','headers':[], 'client':('203.0.113.5',1234)})
    def setup(mode):
        if mode=='evm':session.auth_type='evm';session.owner_key=OWNER.address.lower();session.vault_record.owner_evm_address=OWNER.address
        ledger.reserve_enrollment(record=record,owner_key=session.owner_key,max_pending_per_owner=2)
        if mode=='bls':
            req=relay.BlsRelayRequest(data=Web3.to_hex(data),ownerAuth={'challengeId':'a'*32,'signature':'0x'+'bb'*96})
            return lambda:relay.relay_bls(req,request)
        req=relay.RelayRequest(**{'from':OWNER.address,'to':EMITTER,'gas':'1800000','deadline':now+900,'data':Web3.to_hex(data),'signature':'0x'+'aa'*65})
        return lambda:relay.relay(req,request)
    yield SimpleNamespace(**locals())
    ledger.close()

@pytest.mark.parametrize('mode',['bls','evm'])
def test_successful_relay_control(rig,mode):
    response=rig.setup(mode)()
    assert response.tx_hash==Web3.to_hex(Web3.keccak(rig.w3.eth.raw[0]))
    rig.ledger.require_submitted_relay(transaction_hash=response.tx_hash,vault_launcher_id=VAULT,
        owner_key=rig.session.owner_key,bridge_coin_id=rig.bridge)

@pytest.mark.parametrize('mode',['bls','evm'])
def test_provider_timeout_retains_signed_transaction_and_hash(rig,mode):
    action=rig.setup(mode);rig.w3.eth.fail=True
    try:action()
    except HTTPException:pass
    with rig.ledger._lock:
        row=rig.ledger._conn.execute('SELECT * FROM relay_attempts').fetchone()
    expected=Web3.to_hex(Web3.keccak(rig.w3.eth.raw[0]))
    assert row['tx_hash']==expected
    saved=rig.ledger.get_relay_transaction(VAULT)
    assert saved['raw_transaction_hex']==rig.w3.eth.raw[0].hex()
    assert saved['dispatch_status']=='unknown'

@pytest.mark.parametrize('mode',['bls','evm'])
def test_restart_exact_retry_does_not_sign_or_consume_owner_again(rig,mode,monkeypatch):
    action=rig.setup(mode);rig.w3.eth.fail=True
    first=action();before=rig.counts.copy()
    saved=rig.ledger.get_relay_transaction(VAULT)
    other=CredentialLedger(rig.tmp_path/'relay.db')
    monkeypatch.setattr(relay,'get_credential_ledger',lambda s:other)
    monkeypatch.setattr(relay.time,'time',lambda:rig.now+6)
    rig.w3.eth.fail=False
    resumed=action()
    assert resumed.tx_hash==first.tx_hash
    assert rig.w3.eth.raw[0]==rig.w3.eth.raw[1]
    assert rig.counts==before
    assert other.get_relay_transaction(VAULT)['dispatch_count']==2
    assert other._conn.execute('SELECT COUNT(*) FROM relay_attempts').fetchone()[0]==1
    other.close()

@pytest.mark.parametrize('mutation',['environment','network','emitter','forwarder','artifact','owner'])
def test_changed_authorization_context_cannot_resume(rig,monkeypatch,mutation):
    rig.setup('bls')()
    monkeypatch.setattr(relay.time,'time',lambda:rig.now+6)
    if mutation=='artifact':rig.artifact['artifactHash']='0x'+'99'*32
    elif mutation=='owner':rig.session.owner_key='0x'+'99'*48
    else:
        key={'environment':'runtime_environment','network':'network','emitter':'zkpassport_emitter_address','forwarder':'zkpassport_forwarder_address'}[mutation]
        value={'environment':'staging','network':'mainnet','emitter':'0x'+'99'*20,'forwarder':'0x'+'99'*20}[mutation]
        rig.settings.__dict__[key]=value
    with pytest.raises(HTTPException) as error:relay.resume_relay(VAULT,rig.request)
    assert error.value.status_code in (403,409)
    assert rig.w3.eth.send_count==1


def test_provider_hash_mismatch_preserves_local_hash(rig,monkeypatch):
    action=rig.setup('bls')
    monkeypatch.setattr(rig.w3.eth,'send_raw_transaction',lambda raw:bytes([9])*32)
    result=action()
    saved=rig.ledger.get_relay_transaction(VAULT)
    assert result.tx_hash==saved['tx_hash'] and result.tx_hash!='0x'+'09'*32
    assert result.submission_status=='unknown'

@pytest.mark.parametrize('mode',['bls','evm'])
def test_expiry_allows_receipt_lookup_but_never_renews_or_resends(rig,monkeypatch,mode):
    rig.setup(mode)()
    saved=rig.ledger.get_relay_transaction(VAULT)
    monkeypatch.setattr(relay.time,'time',lambda:saved['retry_until'])
    outcome=relay.resume_relay(VAULT,rig.request)
    assert outcome.status=='expired' and outcome.txHash==saved['tx_hash']
    assert rig.w3.eth.send_count==1 and rig.counts['sign']==1


def test_receipt_provider_error_does_not_become_absent_receipt(rig,monkeypatch):
    rig.setup('bls')()
    def outage(*a):raise TimeoutError('unavailable')
    monkeypatch.setattr(rig.w3.eth,'get_transaction_receipt',outage)
    with pytest.raises(HTTPException) as err:relay.resume_relay(VAULT,rig.request)
    assert err.value.status_code==502 and rig.w3.eth.send_count==1


def canonical_outcome(rig,*,status=1):
    saved=rig.ledger.get_relay_transaction(VAULT)
    rig.w3.eth.receipt={'transactionHash':bytes.fromhex(saved['tx_hash'][2:]),'status':status,
        'blockNumber':100,'blockHash':bytes.fromhex('88'*32),'logs':[]}
    return saved


def test_late_revert_is_terminal_without_rebroadcast(rig,monkeypatch):
    rig.setup('bls')();saved=canonical_outcome(rig,status=0)
    monkeypatch.setattr(relay.time,'time',lambda:saved['retry_until']+5)
    assert relay.resume_relay(VAULT,rig.request).status=='reverted'
    assert rig.w3.eth.send_count==1

@pytest.mark.parametrize('mode',['bls','evm'])
def test_late_confirmed_event_recovers_exact_proof_after_enrollment_progress(rig,monkeypatch,mode):
    rig.setup(mode)();saved=canonical_outcome(rig)
    monkeypatch.setattr(relay.time,'time',lambda:saved['retry_until']+5)
    event=SimpleNamespace(sender=rig.session.owner_key if mode=='evm' else RELAYER.address,
        vault_launcher_id=VAULT,bridge_coin_id=rig.bridge,bridge_parent_id=PARENT,bridge_amount=1,
        bridge_policy_hash=POLICY,policy_version=2,identity_attest_root='0x'+'a1'*32,
        attestation_leaf_hash='0x'+'a2'*32,bridge_message='0x'+'a3'*32,validator_message='0x'+'a4'*32)
    monkeypatch.setattr(relay,'_fetch_verified_evm_attestation',lambda *a,**k:event)
    record=rig.ledger.get_enrollment(VAULT);record['status']='evm_confirmed'
    rig.ledger._conn.execute('UPDATE enrollments SET status=?,record_json=? WHERE vault_launcher_id=?',('evm_confirmed',json.dumps(record),VAULT))
    outcome=relay.resume_relay(VAULT,rig.request)
    assert outcome.status=='confirmed' and outcome.proof['txHash']==saved['tx_hash']
    assert rig.w3.eth.send_count==1

@pytest.mark.parametrize('field',['transactionHash','blockHash','removed','logTransaction','logBlock','logHeight'])
def test_noncanonical_receipt_never_confirms_or_dispatches(rig,monkeypatch,field):
    rig.setup('bls')();canonical_outcome(rig)
    receipt=rig.w3.eth.receipt
    receipt['logs']=[dict(transactionHash=receipt['transactionHash'],blockHash=receipt['blockHash'],blockNumber=100,removed=False)]
    if field in ('transactionHash','blockHash'):receipt[field]=bytes([9])*32
    if field=='removed':receipt['logs'][0]['removed']=True
    if field=='logTransaction':receipt['logs'][0]['transactionHash']=bytes([9])*32
    if field=='logBlock':receipt['logs'][0]['blockHash']=bytes([9])*32
    if field=='logHeight':receipt['logs'][0]['blockNumber']=99
    with pytest.raises(HTTPException) as err:relay.resume_relay(VAULT,rig.request)
    assert err.value.status_code==409 and rig.w3.eth.send_count==1


def test_historical_incomplete_reservation_is_preserved(rig):
    rig.setup('bls')
    rig.ledger.reserve_relay(request_digest='0x'+'99'*32,vault_launcher_id=VAULT,owner_key=BLS,
        source_ip='203.0.113.5',bridge_coin_id=rig.bridge,forwarder_nonce=9,inner_gas=1000000,
        per_ip_per_minute=10,per_owner_per_minute=10,per_vault_per_hour=10,global_gas_per_day=9999999)
    result=relay.get_relay_recovery(VAULT,rig.request)
    assert result.status=='incomplete' and result.txHash is None
    with pytest.raises(HTTPException,match='no recoverable'):relay.resume_relay(VAULT,rig.request)
    assert rig.ledger._conn.execute('SELECT COUNT(*) FROM relay_attempts').fetchone()[0]==1
    assert rig.w3.eth.send_count==0


def test_noncanonical_calldata_rejected_before_owner_auth(rig):
    rig.setup('bls')
    request=relay.BlsRelayRequest(data=Web3.to_hex(rig.data+b'\x00'*32),ownerAuth={'challengeId':'a'*32,'signature':'0x'+'bb'*96})
    with pytest.raises(HTTPException) as err:relay.relay_bls(request,rig.request)
    assert err.value.status_code==422 and rig.counts['auth']==0 and rig.w3.eth.send_count==0


def test_parallel_workers_allocate_distinct_outer_nonces(tmp_path):
    path=tmp_path/'parallel.db'
    seed=CredentialLedger(path);now=int(time.time())
    for i in range(8):
        vault='0x'+bytes([10+i]*32).hex();bridge='0x'+bytes([30+i]*32).hex();owner='0x'+bytes([50+i]*20).hex()
        seed.reserve_enrollment(record=dict(vaultLauncherId=vault,network='testnet11',policyVersion=2,status='reserved',bridgeCoinId=bridge,createdAt=now,updatedAt=now),owner_key=owner,max_pending_per_owner=2)
        seed.reserve_relay(request_digest='0x'+bytes([70+i]*32).hex(),vault_launcher_id=vault,owner_key=owner,source_ip='local',bridge_coin_id=bridge,
            forwarder_nonce=9,inner_gas=1000,per_ip_per_minute=100,per_owner_per_minute=100,per_vault_per_hour=100,global_gas_per_day=99999999)
    def worker(i):
        ledger=CredentialLedger(path)
        vault='0x'+bytes([10+i]*32).hex();bridge='0x'+bytes([30+i]*32).hex();owner='0x'+bytes([50+i]*20).hex()
        saved=ledger.prepare_relay_transaction(request_digest='0x'+bytes([70+i]*32).hex(),context=dict(owner=owner,vaultLauncherId=vault,bridgeCoinId=bridge),request={'mode':'evm' if i%2 else 'chia_bls'},
            transaction={'from':RELAYER.address,'to':EMITTER,'nonce':9,'chainId':11155111,'gas':21000,'gasPrice':7,'value':0,'data':'0x'},sign_transaction=RELAYER.sign_transaction,retry_until=now+900)
        ledger.close();return saved['outer_nonce']
    with ThreadPoolExecutor(max_workers=8) as pool:nonces=list(pool.map(worker,range(8)))
    assert sorted(nonces)==list(range(9,17))
    seed.close()


def test_closed_write_gate_still_allows_read_only_receipt_recovery(rig,monkeypatch):
    rig.setup('bls')()
    rig.settings.__dict__['alpha_writes_enabled']=False
    monkeypatch.setattr(relay.time,'time',lambda:rig.now+6)
    assert relay.get_relay_recovery(VAULT,rig.request).status=='pending'
    with pytest.raises(HTTPException) as err:relay.resume_relay(VAULT,rig.request)
    assert err.value.status_code==503 and rig.w3.eth.send_count==1


@pytest.mark.parametrize('typed',[False,True])
def test_signed_transaction_identity_checks_complete_construction(typed):
    from solslot_api.evm_relay_transaction import signed_transaction_identity
    tx={'from':RELAYER.address,'to':EMITTER,'nonce':7,'chainId':11155111,'gas':21000,'value':0,'data':'0x'}
    tx.update({'maxFeePerGas':10,'maxPriorityFeePerGas':1,'type':2} if typed else {'gasPrice':7})
    raw=bytes(RELAYER.sign_transaction(tx).raw_transaction)
    assert signed_transaction_identity(raw,tx)['tx_hash']==Web3.to_hex(Web3.keccak(raw))
    for field,value in [('chainId',84532),('nonce',8),('to',FORWARDER),('value',1),('data','0x01'),('gas',21001),('from',OWNER.address)]:
        with pytest.raises(ValueError,match=field):signed_transaction_identity(raw,{**tx,field:value})


def test_unprotected_transaction_and_fake_signed_bytes_are_rejected():
    from solslot_api.evm_relay_transaction import signed_transaction_identity
    tx={'from':RELAYER.address,'to':EMITTER,'nonce':7,'gas':21000,'gasPrice':7,'value':0,'data':'0x'}
    raw=bytes(RELAYER.sign_transaction(tx).raw_transaction)
    with pytest.raises(ValueError,match='chain protected'):signed_transaction_identity(raw,{**tx,'chainId':11155111})
    with pytest.raises(ValueError):signed_transaction_identity(b'not a signed transaction',tx)


def test_failure_to_commit_signed_bytes_never_broadcasts(rig,monkeypatch):
    action=rig.setup('bls')
    def storage_failure(**kwargs):raise OSError('synthetic disk failure')
    monkeypatch.setattr(rig.ledger,'prepare_relay_transaction',storage_failure)
    with pytest.raises(HTTPException) as err:action()
    assert err.value.status_code==502 and rig.w3.eth.send_count==0
    assert relay.get_relay_recovery(VAULT,rig.request).status=='incomplete'

@pytest.mark.parametrize('legacy_owner',[BLS,OWNER.address.lower()])
def test_migrated_ambiguous_relay_blocks_new_signing_across_owners(tmp_path,legacy_owner):
    path=tmp_path/'historical.db';ledger=CredentialLedger(path);now=int(time.time())
    def reserve(i,owner):
        vault='0x'+bytes([i]*32).hex();bridge='0x'+bytes([i+10]*32).hex();digest='0x'+bytes([i+20]*32).hex()
        ledger.reserve_enrollment(record=dict(vaultLauncherId=vault,network='testnet11',policyVersion=2,status='reserved',bridgeCoinId=bridge),owner_key=owner)
        ledger.reserve_relay(request_digest=digest,vault_launcher_id=vault,owner_key=owner,bridge_coin_id=bridge,source_ip='local',forwarder_nonce=9,inner_gas=1,per_ip_per_minute=10,per_owner_per_minute=10,per_vault_per_hour=10,global_gas_per_day=100)
        return vault,bridge,digest
    reserve(1,legacy_owner)
    ledger._conn.execute('DROP TABLE relay_transactions')
    ledger._conn.execute('ALTER TABLE relay_attempts DROP COLUMN construction_version')
    ledger._conn.execute('PRAGMA user_version=2');ledger.close();ledger=CredentialLedger(path)
    vault,bridge,digest=reserve(2,'new-owner')
    with pytest.raises(LedgerConflict,match='unresolved historical'):
        ledger.prepare_relay_transaction(request_digest=digest,context=dict(owner='new-owner',vaultLauncherId=vault,bridgeCoinId=bridge),request={'mode':'evm'},
            transaction={'from':RELAYER.address,'nonce':9,'chainId':11155111},sign_transaction=lambda tx:pytest.fail('must not sign'),retry_until=now+300)
    assert ledger.get_relay_transaction(vault) is None
    assert ledger._conn.execute('SELECT COUNT(*) FROM relay_attempts WHERE construction_version=0').fetchone()[0]==1
    ledger.close()

@pytest.mark.parametrize('mode',['evm','bls'])
@pytest.mark.parametrize('reopen',[False,True])
def test_expired_owner_can_renew_only_receipt_scope_during_write_freeze(tmp_path,monkeypatch,mode,reopen):
    import jwt
    from http.cookies import SimpleCookie
    from chia_rs import AugSchemeMPL
    from eth_keys import keys
    from eth_account.messages import encode_typed_data
    from fastapi import Response
    from solslot_api import credential_auth as auth, zkpassport_enrollments as enroll
    from solslot_api.credential_ledger import get_credential_ledger,reset_credential_ledgers_for_tests
    from solslot_api.state import reset_registry_for_tests
    from tests.test_credential_ledger import _settings,_record,_enrollment
    settings=_settings(tmp_path);ledger=get_credential_ledger(settings)
    bls=AugSchemeMPL.key_gen(bytes([8])*32)
    owner=OWNER.address.lower() if mode=='evm' else '0x'+bytes(bls.get_g1()).hex()
    record=_record(owner_pubkey=keys.PrivateKey(bytes([1])*32).public_key.to_compressed_bytes() if mode=='evm' else bytes(bls.get_g1()),auth_type=3 if mode=='evm' else 1,evm_address=OWNER.address if mode=='evm' else None)
    reset_registry_for_tests(tmp_path/'vault.db').record(record)
    enrollment=_enrollment();ledger.reserve_enrollment(record=enrollment,owner_key=owner)
    ledger.reserve_relay(request_digest='0x'+'aa'*32,vault_launcher_id=VAULT,owner_key=owner,bridge_coin_id=enrollment['bridgeCoinId'],source_ip='local',forwarder_nonce=9,inner_gas=1,per_ip_per_minute=10,per_owner_per_minute=10,per_vault_per_hour=10,global_gas_per_day=100)
    token,_=auth.issue_vault_session(settings,auth.VerifiedOwner(owner_key=owner,auth_type='evm' if mode=='evm' else 'chia_bls',vault_record=record))
    claims=jwt.decode(token,auth._vault_session_secret(settings),algorithms=['HS256'],audience=auth.VAULT_SESSION_AUDIENCE)
    claims['exp']=int(time.time())-1;expired=jwt.encode(claims,auth._vault_session_secret(settings),algorithm='HS256')
    def request(t):return Request({'type':'http','headers':[(b'cookie',f'{auth.VAULT_SESSION_COOKIE}={t}'.encode())]})
    with pytest.raises(HTTPException) as err:auth.verify_vault_session(settings,request(expired),VAULT,allow_recovery=True)
    assert err.value.status_code==401
    settings.__dict__['alpha_writes_enabled']=False;monkeypatch.setattr(enroll,'_settings',lambda:settings)
    if reopen:reset_credential_ledgers_for_tests()
    challenge=enroll.create_vault_session_challenge(VAULT)
    ledger=get_credential_ledger(settings)
    if mode=='evm':signature=OWNER.sign_message(encode_typed_data(full_message=challenge.typedData)).signature.hex()
    else:signature=bytes(AugSchemeMPL.sign(bls,auth.credential_bls_signing_digest(settings,ledger.get_owner_challenge(challenge.challengeId)))).hex()
    response=Response()
    issued=enroll.create_vault_session(VAULT,enroll.VaultSessionLoginRequest(ownerAuth=auth.OwnerAuth(challengeId=challenge.challengeId,signature='0x'+signature.removeprefix('0x'))),response)
    assert issued.scope=='relay_recovery'
    cookie=SimpleCookie();cookie.load(response.headers['set-cookie']);new_token=cookie[auth.VAULT_SESSION_COOKIE].value
    session=auth.verify_vault_session(settings,request(new_token),VAULT,allow_recovery=True)
    assert session.scope=='relay_recovery'
    with pytest.raises(HTTPException) as denied:auth.verify_vault_session(settings,request(new_token),VAULT)
    assert denied.value.status_code==403
    settings.__dict__['alpha_writes_enabled']=True
    with pytest.raises(HTTPException) as denied:relay._dispatch_saved(None,settings,{},session)
    assert denied.value.status_code==403
    reset_credential_ledgers_for_tests()


@pytest.mark.parametrize('field',['value','gas'])
def test_malformed_evm_quantity_retains_422_error_contract(rig,field):
    rig.setup('evm')
    values={'from':OWNER.address,'to':EMITTER,'value':'0','gas':'1800000','deadline':rig.now+900,'data':Web3.to_hex(rig.data),'signature':'0x'+'aa'*65}
    values[field]='not-an-integer'
    with pytest.raises(HTTPException) as err:relay.relay(relay.RelayRequest(**values),rig.request)
    assert err.value.status_code==422 and rig.w3.eth.send_count==0
