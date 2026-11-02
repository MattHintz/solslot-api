"""Synthetic canonical EVM calldata/receipt evidence, without network access."""
from dataclasses import replace
from types import SimpleNamespace
from eth_abi import encode
import pytest
from web3 import Web3
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.generation_customer_identity_evm import (
    require_current_identity_query, verify_current_identity_transaction, FORWARD_ABI,
    FORWARD_SELECTOR, PROOF_VERSIONS,
)
from solslot_api.enrollment_permit_runtime import BINDING_ABI, PROOF_PARAMS_ABI, LEGACY_SELECTOR
from tests.test_generation_customer_identity_context import profile

LAUNCHER='0x'+'81'*32
OWNER='0x'+'82'*20
INPUTS=bytes.fromhex('0100021200090021')+bytes(33)


def calldata(pins,*,version='0.21.0',query=INPUTS,domain='solslot.com',scope=None,dev=False,parent=None):
    params=(PROOF_VERSIONS[version],(bytes(32),b'synthetic-proof',[]),query,
        (604800,domain,scope or 'vault:'+LAUNCHER,dev))
    return LEGACY_SELECTOR+encode([BINDING_ABI,'bytes'],[(bytes.fromhex(LAUNCHER[2:]),
        bytes.fromhex((parent or pins.bridge_coins[0].parent_id)[2:]),1),encode([PROOF_PARAMS_ABI],[params])])


def evidence(*,forwarded=False):
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0]);addresses={c.role:c.address for c in pins.contracts}
    code={c.address:b'code-'+c.role.encode() for c in pins.contracts}
    doc=pins.model_dump(mode='json',by_alias=True)
    for c in doc['contracts']:c['codeHash']=Web3.to_hex(Web3.keccak(code[c['address']]))
    pins=CurrentCustomerIdentityProfile.model_validate(doc)
    receipt={'blockNumber':123,'blockHash':b'b'*32,'transactionHash':b't'*32}
    data=calldata(pins)
    if forwarded:data=FORWARD_SELECTOR+encode([FORWARD_ABI],[(OWNER,addresses['attestationEmitter'],0,2_000_000,1000,data,b'signature')])
    tx={**receipt,'hash':receipt['transactionHash'],'value':0,'input':data,'from':OWNER,
        'to':addresses['forwarder'] if forwarded else addresses['attestationEmitter']}
    values={name:payload for name,payload in (
        ('bridgePolicyHash()',bytes.fromhex(pins.bridge_policy_hash[2:])),
        ('verifier()',bytes(12)+bytes.fromhex(addresses['verifierAdapter'][2:])),
        ('trustedDirectRelayer()',bytes(12)+bytes.fromhex(pins.trusted_direct_relayer[2:])),
        ('isTrustedForwarder(address)',bytes(31)+b'\x01'))}
    calls={bytes(Web3.keccak(text=name))[:4]:value for name,value in values.items()}
    class Eth:
        chain_id=8453
        def get_block(self,height):assert height==123;return {'hash':receipt['blockHash']}
        def get_code(self,address,block_identifier):assert block_identifier==123;return code[address.lower()]
        def call(self,request,block_identifier):assert block_identifier==123;return calls[bytes.fromhex(request['data'][2:])[:4]]
        def get_transaction(self,digest):assert digest==receipt['transactionHash'];return tx
    w3=SimpleNamespace(eth=Eth())
    return pins,w3,receipt,tx,code,calls


@pytest.mark.parametrize('version',['0.20.0','0.21.0'])
def test_only_the_profiled_private_real_document_query_is_allowed(version):
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0])
    result=require_current_identity_query(calldata(pins,version=version),pins,launcher=LAUNCHER)
    assert result.vault==LAUNCHER and result.amount==1 and result.permit is None


@pytest.mark.parametrize('changes',[{'query':bytes.fromhex('0100021200')},{'query':INPUTS+b'extra'},
    {'domain':'other.invalid'},{'scope':'vault:'+'0x'+'91'*32},{'dev':True},{'parent':'0x'+'92'*32}])
def test_disclosure_weakened_query_wrong_scope_or_other_bridge_is_rejected(changes):
    pins=CurrentCustomerIdentityProfile.model_validate(profile()[0])
    with pytest.raises(ValueError):require_current_identity_query(calldata(pins,**changes),pins,launcher=LAUNCHER)


@pytest.mark.parametrize('forwarded',[False,True])
def test_receipt_code_and_forwarded_owner_are_verified_at_inclusion(forwarded):
    pins,w3,receipt,*_=evidence(forwarded=forwarded)
    owner,parsed=verify_current_identity_transaction(w3,pins,receipt,launcher=LAUNCHER)
    assert owner==OWNER and parsed.vault==LAUNCHER


@pytest.mark.parametrize('mutation',['network','code','trust','target','value','block','bytes','forward-target'])
def test_changed_contract_receipt_or_transaction_is_rejected(mutation):
    pins,w3,receipt,tx,code,calls=evidence(forwarded=mutation=='forward-target')
    if mutation=='network':w3.eth.chain_id=11155111
    if mutation=='code':code[pins.contracts[0].address]=b'changed'
    if mutation=='trust':calls[bytes(Web3.keccak(text='trustedDirectRelayer()'))[:4]]=bytes(32)
    if mutation=='target':tx['to']='0x'+'91'*20
    if mutation=='value':tx['value']=1
    if mutation=='block':tx['blockHash']=b'x'*32
    if mutation=='bytes':tx['input']=calldata(pins)+b'trailing'
    if mutation=='forward-target':tx['input']=FORWARD_SELECTOR+encode([FORWARD_ABI],[(OWNER,'0x'+'91'*20,0,2_000_000,1000,calldata(pins),b'sig')])
    with pytest.raises(ValueError):verify_current_identity_transaction(w3,pins,receipt,launcher=LAUNCHER)
