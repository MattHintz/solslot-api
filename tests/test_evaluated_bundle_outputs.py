"""Exact output/ancestry validation and bounded batch evaluation regressions."""
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_api.governed_output_index import (
    EvaluatedBundleOutputs, GovernedOutputConflict, find_exact_governed_descendant,
)


def fixture(quantity):
    spends, inputs, outputs = [], [], []
    for i in range(quantity):
        destination = bytes32((i + 1).to_bytes(32, 'big'))
        intermediate = Program.to((1, [[51, destination, 1]]))
        puzzle = Program.to((1, [[51, intermediate.get_tree_hash(), 1]]))
        original = Coin(bytes32((i + 1000).to_bytes(32, 'big')), puzzle.get_tree_hash(), uint64(1))
        child = Coin(original.name(), intermediate.get_tree_hash(), uint64(1))
        final = Coin(child.name(), destination, uint64(1))
        spends.extend([make_spend(original, puzzle, Program.to([])),
                       make_spend(child, intermediate, Program.to([]))])
        inputs.append(original); outputs.append(final)
    return WalletSpendBundle(spends, G2Element()), inputs, outputs


@pytest.mark.parametrize('quantity', [1, 2, 100])
def test_real_clvm_batch_evaluates_exact_bundle_once_and_preserves_all_descendants(quantity, monkeypatch):
    bundle, inputs, outputs = fixture(quantity)
    calls = []
    original = WalletSpendBundle.additions
    def counted(self):
        calls.append(self.name())
        return original(self)
    monkeypatch.setattr(WalletSpendBundle, 'additions', counted)
    evaluated = EvaluatedBundleOutputs(bundle)
    for ancestor, output in zip(inputs, outputs, strict=True):
        assert evaluated.find_exact_descendant(ancestor_coin_id=ancestor.name(),
            puzzle_hash=output.puzzle_hash, amount=1, label='deed') == output
    assert calls == [bundle.name()]
    with pytest.raises(FrozenInstanceError):
        evaluated.additions = ()
    with pytest.raises(TypeError):
        evaluated._additions_by_id[outputs[0].name()] = inputs[0]


@pytest.mark.parametrize('problem', ['missing_output', 'duplicate_output', 'wrong_amount',
    'unspent_intermediate', 'uncreated_intermediate', 'absent_ancestor', 'wrong_ancestor'])
@pytest.mark.parametrize('entry', ['single', 'index'])
def test_invalid_destination_or_ancestry_stays_rejected(problem, entry):
    bundle, inputs, outputs = fixture(1)
    adds, removes = bundle.additions(), bundle.removals()
    ancestor = inputs[0].name()
    if problem == 'missing_output': adds.remove(outputs[0])
    elif problem == 'duplicate_output': adds.append(Coin(bytes32(b'x'*32), outputs[0].puzzle_hash, uint64(1)))
    elif problem == 'wrong_amount':
        adds[adds.index(outputs[0])] = Coin(outputs[0].parent_coin_info, outputs[0].puzzle_hash, uint64(2))
    elif problem == 'unspent_intermediate': removes.pop()
    elif problem == 'uncreated_intermediate': adds = [coin for coin in adds if coin.name() != outputs[0].parent_coin_info]
    elif problem == 'absent_ancestor': removes.remove(inputs[0])
    else: ancestor = bytes32(b'z'*32)
    exact = SimpleNamespace(additions=lambda: adds, removals=lambda: removes)
    kwargs = dict(ancestor_coin_id=ancestor, puzzle_hash=outputs[0].puzzle_hash, amount=1, label='deed')
    with pytest.raises(GovernedOutputConflict):
        if entry == 'single': find_exact_governed_descendant(exact, **kwargs)
        else: EvaluatedBundleOutputs(exact).find_exact_descendant(**kwargs)


def test_new_bundle_has_new_evaluation_and_cannot_reuse_prior_outputs():
    bundle, inputs, outputs = fixture(1)
    old = EvaluatedBundleOutputs(bundle)
    changed = WalletSpendBundle(bundle.coin_spends[:1], G2Element())
    new = EvaluatedBundleOutputs(changed)
    kwargs = dict(ancestor_coin_id=inputs[0].name(), puzzle_hash=outputs[0].puzzle_hash, amount=1, label='deed')
    assert old.find_exact_descendant(**kwargs) == outputs[0]
    with pytest.raises(GovernedOutputConflict): new.find_exact_descendant(**kwargs)


@pytest.mark.asyncio
async def test_worker_logs_numeric_exit_without_wallet_bytes(caplog):
    from solslot_api.wallet_offer_worker import _exchange
    class Stdin:
        def write(self, payload): pass
        async def drain(self): pass
        def close(self): pass
        async def wait_closed(self): pass
    class Stdout:
        async def read(self, amount): return b''
    async def wait(): return -9
    process = SimpleNamespace(stdin=Stdin(), stdout=Stdout(), returncode=-9, wait=wait)
    with pytest.raises(ValueError, match='^wallet validation worker failed$'):
        await _exchange(process, b'private-wallet-fixture-payload')
    assert 'returncode=-9' in caplog.text
    assert 'private-wallet-fixture-payload' not in caplog.text
