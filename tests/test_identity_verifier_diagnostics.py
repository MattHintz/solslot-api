"""Redaction and real ABI error handling, with no customer proof fixtures."""
import ast
from pathlib import Path
import re
from types import SimpleNamespace
import pytest
from eth_abi import encode, decode
from web3.exceptions import ContractLogicError

SOURCE = Path(__file__).parents[1] / 'solslot_api' / 'zkpassport_relay.py'
NAMES = {'_KNOWN_REVERT_SELECTORS','_REVERT_SELECTOR_RE','_KNOWN_STANDARD_REVERTS',
         '_standard_revert_diagnostic','_describe_revert','_simulate_forwarded_inner_call'}
tree = ast.parse(SOURCE.read_text())
nodes = [n for n in tree.body if (isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in NAMES)
         or (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in NAMES for t in n.targets))]
namespace = {'abi_encode':encode,'abi_decode':decode,'re':re,'Web3':SimpleNamespace(to_bytes=lambda **kw:bytes.fromhex(kw['hexstr'][2:]))}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),namespace)
describe = namespace['_describe_revert']
known = namespace['_KNOWN_STANDARD_REVERTS']
GENERIC = 'Identity verification was rejected by the EVM verifier.'

def failure(reason):
    return ContractLogicError('provider echoed PRIVATE_PROOF_AND_SIGNATURE',
                              data='0x08c379a0'+encode(['string'],[reason]).hex())

@pytest.mark.parametrize('reason',list(known))
def test_exact_known_abi_reasons_return_only_static_diagnostic(reason):
    assert describe(failure(reason)) == known[reason]
    assert 'PRIVATE_PROOF' not in describe(failure(reason))

@pytest.mark.parametrize('reason',['customer document number: PRIVATE_DOCUMENT','Invalid certificate registry root PRIVATE_PROOF','', 'A'*10000])
def test_unknown_or_oversized_reasons_never_expose_payload(reason):
    assert describe(failure(reason)) == GENERIC

@pytest.mark.parametrize('data',['0x08c379a0','0x08c379a0zz','0x08c379a0'+'00'*96,
                                None,{'data':'0x08c379a0'}, '0x08c379a0'+encode(['string'],['Invalid certificate registry root']).hex()+'00'])
def test_malformed_or_noncanonical_error_data_fails_closed(data):
    assert describe(ContractLogicError('PRIVATE_PROVIDER_MESSAGE',data=data)) == GENERIC

def test_provider_text_cannot_spoof_a_standard_reason():
    assert describe(ContractLogicError('Invalid certificate registry root PRIVATE_PROOF')) == GENERIC

def test_existing_forwarder_custom_error_remains_available():
    text = describe(ContractLogicError('0xd6bda275 PRIVATE_PROOF'))
    assert text.startswith('OpenZeppelin FailedCall()')
    assert 'PRIVATE_PROOF' not in text

def test_inner_simulation_preserves_binding_and_redacts_revert():
    calls = []
    class Eth:
        def call(self,request):
            calls.append(request)
            raise failure('Invalid certificate registry root')
    result=namespace['_simulate_forwarded_inner_call'](SimpleNamespace(eth=Eth()),
       forwarder_address='0x'+'12'*20,emitter_address='0x'+'34'*20,
       signer_address='0x'+'56'*20,data=b'synthetic-calldata')
    assert result == known['Invalid certificate registry root']
    assert calls == [{'from':'0x'+'12'*20,'to':'0x'+'34'*20,'value':0,
                      'data':b'synthetic-calldata'+bytes.fromhex('56'*20)}]

def test_inner_simulation_unknown_revert_does_not_leak():
    class Eth:
        def call(self,request): raise failure('PRIVATE_PROOF')
    assert namespace['_simulate_forwarded_inner_call'](SimpleNamespace(eth=Eth()),
       forwarder_address='0x'+'12'*20,emitter_address='0x'+'34'*20,
       signer_address='0x'+'56'*20,data=b'synthetic-calldata') == GENERIC
