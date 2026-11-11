"""Exercise real Web3 RPC address normalization, not permissive Eth doubles."""
from types import SimpleNamespace
import pytest
from web3 import Web3
from web3.providers.base import BaseProvider
from solslot_api.identity_relay_fees import check_base_dispatch,validate_quote

SENDER='0x062a700871ce6b20829af76b2dadd20247fb1f4a'

class ReadOnlyProvider(BaseProvider):
    def __init__(self):super().__init__();self.calls=[]
    def make_request(self,method,params):
        self.calls.append((method,params))
        if method=='eth_chainId':value='0x2105'
        elif method=='eth_getBlockByNumber':value={'number':'0x64','baseFeePerGas':hex(5_000_000)}
        elif method=='eth_call':value='0x'+format(100,'064x')
        elif method=='eth_getBalance':
            assert Web3.is_checksum_address(params[0]);value=hex(10**15)
        else:raise AssertionError('Only public reads are allowed: '+method)
        return {'jsonrpc':'2.0','id':1,'result':value}


def quote():
    return {'schema':'solslot.base-identity-relay-fee.v1','chainId':8453,'relayer':SENDER,
        'gas':1_000_000,'maxFeePerGas':11_000_000,'maxPriorityFeePerGas':1_000_000,
        'maximumSignedBytes':514,'maximumFeeWei':50_000_000_000_000,
        'auxiliaryFeeBudgetWei':39_000_000_000_000,'dailyFeeLimitWei':100_000_000_000_000,'quotedBlock':100}


def test_canonical_lowercase_review_uses_checksum_only_at_rpc_boundary():
    provider=ReadOnlyProvider();w3=Web3(provider);q=quote();original=dict(q)
    tx={'from':SENDER,'chainId':8453,'type':2,'gas':q['gas'],'maxFeePerGas':q['maxFeePerGas'],
        'maxPriorityFeePerGas':q['maxPriorityFeePerGas'],'data':'0x1234','value':0}
    validate_quote(q,tx)
    check_base_dispatch(SimpleNamespace(zkpassport_base_relay_max_fee_wei=q['maximumFeeWei'],
        zkpassport_base_relay_daily_fee_wei=q['dailyFeeLimitWei']),w3,q)
    assert q==original and tx['from']==SENDER
    balances=[args for method,args in provider.calls if method=='eth_getBalance']
    assert balances==[[Web3.to_checksum_address(SENDER),'pending']]
    assert all(not method.startswith('eth_send')for method,_ in provider.calls)


def test_real_web3_rejects_the_previous_lowercase_rpc_call_before_provider():
    from web3.exceptions import InvalidAddress
    provider=ReadOnlyProvider()
    with pytest.raises(InvalidAddress):Web3(provider).eth.get_balance(SENDER,'pending')
    assert not provider.calls
