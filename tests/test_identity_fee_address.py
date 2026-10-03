import ast
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest
from web3 import Web3
from web3.exceptions import InvalidAddress

root = Path(__file__).parent
if not (root / 'solslot_identity_fee_address.py').exists():
    root = root.parent / 'deployment'
spec = importlib.util.spec_from_file_location('ae170_bootstrap', root / 'solslot_identity_fee_address.py')
patch = importlib.util.module_from_spec(spec); spec.loader.exec_module(patch)
fee_path = Path(__file__).parent.parent / 'solslot_api/identity_relay_fees.py'
if not fee_path.exists():
    fee_path = Path('/home/hiram/solslot-work/identity-chain-binding-draft169/api/solslot_api/identity_relay_fees.py')
spec = importlib.util.spec_from_file_location('ae170_preserved_fees', fee_path)
fees = importlib.util.module_from_spec(spec); spec.loader.exec_module(fees)
RELAYER = '0x0E61D3Bb1148bDd802F747CaEa112333d156626a'


class StrictEth:
    chain_id = 8453
    def __init__(self, *, balance=10**15, base=5_000_000, auxiliary=80_000_000_000):
        self.balance, self.base, self.auxiliary = balance, base, auxiliary
        self.addresses = []
    def get_block(self, _): return {'baseFeePerGas': self.base}
    def get_balance(self, address, block):
        if not Web3.is_checksum_address(address):
            raise InvalidAddress('checksum required')
        self.addresses.append((address, block)); return self.balance
    def contract(self, **_):
        return SimpleNamespace(functions=SimpleNamespace(
            getL1FeeUpperBound=lambda _: SimpleNamespace(call=lambda: self.auxiliary),
            getOperatorFee=lambda _: SimpleNamespace(call=lambda: 0)))


def fixture():
    settings = SimpleNamespace(zkpassport_base_relay_max_fee_wei=10**14,
                              zkpassport_base_relay_daily_fee_wei=10**15)
    quote = {'chainId':8453,'relayer':RELAYER.lower(),'maximumFeeWei':10**14,
             'dailyFeeLimitWei':10**15,'maxPriorityFeePerGas':1_000_000,
             'maxFeePerGas':11_000_000,'maximumSignedBytes':12000,
             'gas':2_250_000,'auxiliaryFeeBudgetWei':75_250_000_000_000}
    return settings, quote


def test_reproduces_strict_web3_failure_and_corrects_only_rpc_address():
    settings, quote = fixture(); before = copy.deepcopy(quote)
    w3 = SimpleNamespace(eth=StrictEth())
    with pytest.raises(InvalidAddress): fees.check_base_dispatch(settings, w3, quote)
    patch.corrected_dispatch(fees)(settings, w3, quote)
    assert quote == before
    assert w3.eth.addresses == [(Web3.to_checksum_address(RELAYER), 'pending')]


@pytest.mark.parametrize('failure', ['wrong-chain','budget','daily','base','auxiliary','balance'])
def test_retains_all_fee_checks(failure):
    settings, quote = fixture(); eth = StrictEth()
    if failure == 'wrong-chain': eth.chain_id = 11155111
    elif failure == 'budget': settings.zkpassport_base_relay_max_fee_wei = 1
    elif failure == 'daily': settings.zkpassport_base_relay_daily_fee_wei = 1
    elif failure == 'base': eth.base = 20_000_000
    elif failure == 'auxiliary': eth.auxiliary = 10**14
    else: eth.balance = 1
    with pytest.raises(fees.RelayFeeUnavailable):
        patch.corrected_dispatch(fees)(settings, SimpleNamespace(eth=eth), quote)


def test_rejects_changed_preserved_source(tmp_path):
    path = tmp_path / 'changed.py'; path.write_text(fee_path.read_text() + '\n')
    changed = SimpleNamespace(__file__=str(path))
    with pytest.raises(RuntimeError, match='source pin'): patch.corrected_dispatch(changed)


def test_preserves_original_file_bytes():
    before = fee_path.read_bytes(); patch.corrected_dispatch(fees)
    assert fee_path.read_bytes() == before
