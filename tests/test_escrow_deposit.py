"""Actual deposit verifier and ABI, with explicitly offline provider responses."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from eth_abi import encode
from web3 import Web3

from solslot_api import escrow_deposit as proof, protocol_artifacts as api, validator_service as validator


def h(n): return '0x' + bytes([n]).hex() * 32

def normalized():
    return dict(gatewayProfile='bse', globalPaymentId=h(3), purchaseId=h(1), artifactHash=h(2),
        amount=1_000_000, quantity=1, collectionId=h(4), deedLauncherId=h(5),
        vaultLauncherId=h(6), destinationPuzzle=h(7), quoteExpiresAt=1_900_000_100,
        depositor='0x'+'14'*20, settlementToken='0x'+'13'*20, localPaymentId=h(10),
        source=dict(chainId=84532, spoke='0x'+'12'*20, transactionHash=h(8), blockNumber=100,
                    blockHash=h(9), blockTimestamp=1_900_000_000, logIndex=2, confirmations=12))


class Chain:
    def __init__(self, evidence=None):
        self.evidence = deepcopy(evidence or normalized())
        e = self.evidence; s = e['source']
        self.calls = []; self.chain_id = s['chainId']; self.fail = None; self.reorg = None
        self.block_reads = 0
        self.deposit = [e['depositor'], e['settlementToken'], *[bytes.fromhex(e[k][2:]) for k in (
            'localPaymentId','purchaseId','artifactHash','collectionId','deedLauncherId',
            'vaultLauncherId','destinationPuzzle')], bytes.fromhex(h(11)[2:]), bytes(32), bytes(32),
            e['amount'], e['quantity'], 1, s['spoke'], s['blockTimestamp'], e['quoteExpiresAt'], 1, False]
        self.current = deepcopy(self.deposit); self.latest = deepcopy(self.deposit)
        self.block = dict(hash=s['blockHash'], timestamp=s['blockTimestamp'], number=s['blockNumber'])
        self.tip = dict(hash=h(22), timestamp=s['blockTimestamp']+30,
                        number=s['blockNumber']+s['confirmations']-1)
        self.receipt = dict(status=1, to=s['spoke'], transactionHash=s['transactionHash'],
            blockNumber=s['blockNumber'], blockHash=s['blockHash'], logs=[dict(address=s['spoke'],
                logIndex=s['logIndex'], removed=False, topics=[proof.DEPOSIT_TOPIC,
                    e['globalPaymentId'], e['localPaymentId'], '0x'+'00'*12+e['depositor'][2:]],
                data=encode(proof.EVENT_TYPES, [e['settlementToken'],e['amount'],1,s['spoke'],bytes.fromhex(h(11)[2:]),0]))])
        chain = self
        class FakeWeb3:
            def __init__(self, _): self.eth = chain
            @staticmethod
            def HTTPProvider(url, request_kwargs, exception_retry_configuration):
                assert request_kwargs == {'timeout': proof.RPC_TIMEOUT_SECONDS}
                assert exception_retry_configuration is None
                return None
        self.web3 = FakeWeb3

    def get_transaction_receipt(self, tx):
        self.calls.append(('receipt',tx))
        if self.fail == 'receipt': raise OSError('offline provider unavailable')
        assert tx == self.evidence['source']['transactionHash']
        return deepcopy(self.receipt)

    def get_block(self, height):
        self.calls.append(('block',height)); self.block_reads += 1
        if self.fail == 'block': raise OSError('offline provider unavailable')
        block = deepcopy(self.block if height == self.block['number'] else self.tip)
        if self.block_reads > 2 and self.reorg == height: block['hash'] = h(99)
        return block

    def contract(self, **kwargs):
        assert kwargs['address'].lower() == self.evidence['source']['spoke']
        assert kwargs['abi'] == proof.ESCROW_DEPOSIT_ABI
        return SimpleNamespace(functions=SimpleNamespace(getDeposit=self.get_deposit))

    def get_deposit(self, ident):
        assert ident == self.evidence['globalPaymentId']
        def call(**kwargs):
            self.calls.append(('deposit',ident,kwargs))
            if self.fail == 'storage': raise OSError('offline provider unavailable')
            height = kwargs.get('block_identifier')
            return deepcopy(self.deposit if height == self.block['number'] else self.current if height else self.latest)
        return SimpleNamespace(call=call)

    def verify(self, evidence=None):
        proof.verify_escrow_deposit(rpc_url='https://offline.invalid', evidence=evidence or self.evidence,
            chain_id=84532, spoke=self.evidence['source']['spoke'], token=self.evidence['settlementToken'],
            confirmations=12, web3_factory=self.web3)


@pytest.mark.parametrize('encoding',['bytes','hex'])
@pytest.mark.parametrize('status', [1,2,3])
def test_confirmed_deposit_accepts_authenticated_key_and_current_eligible_state(encoding,status):
    c = Chain()
    c.current[18:] = c.latest[18:] = [status,status != 1]
    if encoding == 'hex':
        c.receipt['logs'][0]['data'] = '0x'+c.receipt['logs'][0]['data'].hex()
        c.receipt['logs'][0]['topics'][0] = '0x'+bytes(proof.DEPOSIT_TOPIC).hex()
    c.verify()
    queries = [q for q in c.calls if q[0]=='deposit']
    assert [q[2] for q in queries] == [{'block_identifier':100},{'block_identifier':111},{}]
    assert all(q[1] == c.evidence['globalPaymentId'] for q in queries)


@pytest.mark.parametrize('problem',[
    'rpc_chain','source_chain','source_spoke','source_token','underconfirmed','inflated_confirmations',
    'receipt_tx','receipt_hash','block_hash','block_time','receipt_height','reverted','removed',
    'missing_log','duplicate_log','settlement_instead','global_id','local_id','payer_padding',
    'wrong_emitter','event_token','event_amount','event_request','event_trailer','malformed_data',
    'created_at','too_late','expired_quote','zero_deposit','refund','emergency','failed_result',
    'late_refund','deposit_reorg','tip_reorg','latest_regression','changed_current_amount',
])
def test_changed_receipt_event_storage_or_terminal_outcome_fails_closed(problem):
    c=Chain(); log=c.receipt['logs'][0]
    if problem=='rpc_chain': c.chain_id=1
    elif problem=='source_chain': c.evidence['source']['chainId']=1
    elif problem=='source_spoke': c.evidence['source']['spoke']='0x'+'ff'*20
    elif problem=='source_token': c.evidence['settlementToken']='0x'+'ff'*20
    elif problem=='underconfirmed': c.tip['number']=110
    elif problem=='inflated_confirmations': c.evidence['source']['confirmations']=13
    elif problem=='receipt_tx': c.receipt['transactionHash']=h(99)
    elif problem=='receipt_hash': c.receipt['blockHash']=h(99)
    elif problem=='block_hash': c.block['hash']=h(99)
    elif problem=='block_time': c.block['timestamp']+=1
    elif problem=='receipt_height': c.receipt['blockNumber']+=1
    elif problem=='reverted': c.receipt['status']=0
    elif problem=='removed': log['removed']=True
    elif problem=='missing_log': c.receipt['logs']=[]
    elif problem=='duplicate_log': c.receipt['logs']*=2
    elif problem=='settlement_instead': log['topics']=[Web3.keccak(text='PaymentSettled(bytes32,address,address,uint256,bool,bool)'),c.evidence['globalPaymentId']]
    elif problem=='global_id': log['topics'][1]=h(99)
    elif problem=='local_id': log['topics'][2]=h(99)
    elif problem=='payer_padding': log['topics'][3]='0x'+'ff'*12+c.evidence['depositor'][2:]
    elif problem=='wrong_emitter': log['address']='0x'+'ff'*20
    elif problem.startswith('event_') and problem!='event_trailer':
        values=[c.evidence['settlementToken'],c.evidence['amount'],1,c.evidence['source']['spoke'],bytes.fromhex(h(11)[2:]),0]
        if problem=='event_token': values[0]='0x'+'ff'*20
        elif problem=='event_amount': values[1]+=1
        else: values[4]=bytes.fromhex(h(99)[2:])
        log['data']=encode(proof.EVENT_TYPES,values)
    elif problem=='event_trailer': log['data']+=bytes(32)
    elif problem=='malformed_data': log['data']=b'bad'
    elif problem=='created_at': c.deposit[16]-=1
    elif problem=='too_late':
        c.evidence['quoteExpiresAt']+=1801
        c.deposit[17]=c.current[17]=c.latest[17]=c.evidence['quoteExpiresAt']
    elif problem=='expired_quote':
        c.evidence['quoteExpiresAt']=c.evidence['source']['blockTimestamp']
        c.deposit[17]=c.current[17]=c.latest[17]=c.evidence['quoteExpiresAt']
    elif problem=='zero_deposit': c.current[18]=0
    elif problem=='refund': c.current[18:]=[4,False]
    elif problem=='emergency': c.current[18:]=[5,False]
    elif problem=='failed_result': c.current[18:]=[2,False]
    elif problem=='late_refund': c.latest[18:]=[4,False]
    elif problem=='deposit_reorg': c.reorg=100
    elif problem=='tip_reorg': c.reorg=111
    elif problem=='latest_regression': c.current[18:]=[3,True]
    elif problem=='changed_current_amount': c.current[12]+=1
    with pytest.raises(proof.EscrowDepositError): c.verify()


@pytest.mark.parametrize('index',list(range(9))+[12,13,17])
def test_every_immutable_purchase_commitment_checked_in_storage(index):
    c=Chain()
    old=c.deposit[index]
    c.deposit[index] = old+1 if isinstance(old,int) else bytes(32) if isinstance(old,bytes) else '0x'+'ff'*20
    with pytest.raises(proof.EscrowDepositError,match='commitments'): c.verify()


@pytest.mark.parametrize('where',['receipt','block','storage'])
def test_rpc_outage_is_retryable_and_never_a_payment(where):
    c=Chain();c.fail=where
    with pytest.raises(proof.EscrowProviderUnavailable): c.verify()


def test_contract_wallet_deposit_is_bound_to_emitter_not_outer_transaction():
    c=Chain(); c.receipt['to']='0x'+'fa'*20
    c.verify()


def test_proof_deadline_stops_further_rpc(monkeypatch):
    c=Chain(); clock=iter([0,0,13])
    monkeypatch.setattr(proof.time,'monotonic',lambda:next(clock))
    with pytest.raises(proof.EscrowProviderUnavailable,match='deadline'): c.verify()
    assert c.calls==[]


def test_api_and_validator_use_actual_shared_provider_verification(monkeypatch):
    c=Chain();e=c.evidence
    monkeypatch.setattr(api,'Web3',c.web3); monkeypatch.setattr(validator,'Web3',c.web3)
    settings=SimpleNamespace(payment_omnichain_rpc_url='https://offline.invalid',
        base_sepolia_rpc_url='https://offline.invalid',base_sepolia_spoke_address=e['source']['spoke'],
        base_sepolia_usdc_address=e['settlementToken'],base_sepolia_min_confirmations=12)
    purchase=SimpleNamespace(purchase_id=bytes.fromhex(e['purchaseId'][2:]),artifact_hash=bytes.fromhex(e['artifactHash'][2:]),
        quote_expires_at=e['quoteExpiresAt'],assert_live=lambda at: None)
    voucher=SimpleNamespace(global_payment_id=bytes.fromhex(e['globalPaymentId'][2:]),
        original_payer=bytes(12)+bytes.fromhex(e['depositor'][2:]),payment_principal=e['amount'],quantity=e['quantity'],
        **{dest:bytes.fromhex(e[src][2:]) for dest,src in [('collection_id','collectionId'),('deed_launcher_id','deedLauncherId'),
        ('approved_vault_launcher_id','vaultLauncherId'),('approved_vault_p2_puzzle_hash','destinationPuzzle')]})
    api._verify_external_escrow_chain_evidence(settings,normalized=e,
        deployment=SimpleNamespace(spoke_address=e['source']['spoke'],confirmations=12))
    validator._verify_base_voucher_payment(settings,e,purchase=purchase,voucher=voucher)
    c.latest[18:]=[5,False]
    with pytest.raises(validator.ValidatorEvidenceError,match='eligible'):
        validator._verify_base_voucher_payment(settings,e,purchase=purchase,voucher=voucher)


def test_real_web3_rpc_formatting_and_contract_abi_decode(monkeypatch):
    from web3.providers.base import BaseProvider
    c=Chain();requests=[]
    def rpc(value):
        if isinstance(value,(bytes,bytearray)):return '0x'+bytes(value).hex()
        if isinstance(value,list):return [rpc(v) for v in value]
        if isinstance(value,dict):return {k:rpc(v) for k,v in value.items()}
        return value
    class Provider(BaseProvider):
        def make_request(self,method,params):
            requests.append((method,params))
            if method=='eth_chainId': result=hex(c.chain_id)
            elif method=='eth_getTransactionReceipt': result=rpc(c.receipt)
            elif method=='eth_getBlockByNumber':
                height=params[0] if params[0]=='latest' else int(params[0],16)
                result=rpc(c.get_block(height))
            elif method=='eth_call':
                assert params[0]['to'].lower()==c.evidence['source']['spoke']
                assert params[0]['data'].endswith(c.evidence['globalPaymentId'][2:])
                values=c.deposit if params[1]==hex(c.block['number']) else c.latest if params[1]=='latest' else c.current
                result='0x'+encode(['('+','.join(t for _,t in proof.DEPOSIT_FIELDS)+')'],[values]).hex()
            else: raise AssertionError((method,params))
            return {'id':1,'jsonrpc':'2.0','result':result}
    monkeypatch.setattr(Web3,'HTTPProvider',lambda *a,**kw:Provider())
    proof.verify_escrow_deposit(rpc_url='https://offline.invalid',evidence=c.evidence,
        chain_id=84532,spoke=c.evidence['source']['spoke'],token=c.evidence['settlementToken'],confirmations=12)
    assert len([r for r in requests if r[0]=='eth_call'])==3
