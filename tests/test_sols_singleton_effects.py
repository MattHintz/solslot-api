"""Executed successor consistency under synthetic provider confirmation."""
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER, SINGLETON_LAUNCHER_HASH, SINGLETON_MOD,
    SINGLETON_MOD_HASH, solution_for_singleton,
)
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import sols_market as market
from solslot_puzzles import load_puzzle
from tests.test_sols_singleton_evidence import Chain, hx
from tests.test_sols_swaps import funding_runtime


@pytest.mark.asyncio
@pytest.mark.parametrize('hop', [0, 1, 2])
@pytest.mark.parametrize('effects', [[], [[51, bytes(32), 1]],
    [[51, Program.to(1).get_tree_hash(), 3]],
    [[51, Program.to(1).get_tree_hash(), 1]] * 2,
    [[51, Program.to(1).get_tree_hash(), 1], [51, bytes(32), 3]]])
async def test_each_parent_must_create_unique_recorded_successor(hop, effects):
    chain = Chain(3)
    chain.spends[chain.ids[hop]]['solution'] = bytes(Program.to(effects)).hex()
    with pytest.raises(ValueError, match='successor'):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
async def test_latest_solution_substitution_after_traversal_is_rejected():
    chain = Chain()
    tip = await market._singleton_tip(chain, chain.launcher)
    chain.spends[chain.ids[-2]]['solution'] = '80'
    with pytest.raises(ValueError, match='successor'):
        await market._latest_solution(chain, tip)


@pytest.mark.asyncio
async def test_executed_even_side_output_remains_compatible():
    chain = Chain(amount=3)
    for value in chain.spends.values():
        effects = Program.from_bytes(bytes.fromhex(value['solution'])).as_python()
        value['solution'] = bytes(Program.to([*effects, [51, bytes(32), 2, [b'memo']]])).hex()
    tip = await market._singleton_tip(chain, chain.launcher)
    assert tip.live.coin_id == chain.tip and tip.live.amount == 3


@pytest.mark.asyncio
async def test_execution_budget_is_shared_across_history(monkeypatch):
    chain = Chain(3)
    # Each identity evaluation plus CREATE_COIN costs 1,800,044: one fits, two do not.
    monkeypatch.setattr(market, 'MAX_SINGLETON_EVIDENCE_COST', 2_000_000)
    with pytest.raises(ValueError, match='cost budget'):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
async def test_last_condition_cost_cannot_exceed_budget(monkeypatch):
    chain = Chain(1)
    monkeypatch.setattr(market, 'MAX_SINGLETON_EVIDENCE_COST', 1_800_000)
    with pytest.raises(ValueError, match='cost budget'):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
async def test_clvm_execution_itself_is_bounded(monkeypatch):
    chain = Chain(1)
    monkeypatch.setattr(market, 'MAX_SINGLETON_EVIDENCE_COST', 1)
    with pytest.raises(ValueError, match='cost budget'):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
async def test_exact_execution_budget_is_accepted(monkeypatch):
    chain = Chain(1)
    monkeypatch.setattr(market, 'MAX_SINGLETON_EVIDENCE_COST', 1_800_044)
    assert (await market._singleton_tip(chain, chain.launcher)).live.coin_id == chain.tip


@pytest.mark.asyncio
@pytest.mark.parametrize('hop', [0, 1, 2])
async def test_every_parent_requires_available_spend(hop):
    chain = Chain(3)
    del chain.spends[chain.ids[hop]]
    with pytest.raises(ValueError, match='unavailable'):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
async def test_invalid_executed_conditions_fail_closed():
    chain = Chain(1)
    chain.spends[chain.launcher]['solution'] = bytes(Program.to([[51, bytes(31), 1]])).hex()
    with pytest.raises(ValueError):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
async def test_spent_parent_rechecked_during_every_hop():
    chain = Chain(3)
    def on_read(name, row):
        if name == chain.ids[1]: row['spent_block_index'] += 1
        return row
    chain.on_read = on_read
    with pytest.raises(ValueError, match='changed during'):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
@pytest.mark.parametrize('custom', [False, True], ids=['standard', 'did-launcher'])
@pytest.mark.parametrize('amount', [1, 3])
@pytest.mark.parametrize('same_block', [False, True])
async def test_real_launcher_eve_and_successor_puzzles(custom, amount, same_block):
    did_struct = Program.to((SINGLETON_MOD_HASH, (bytes32(bytes([7]) * 32), SINGLETON_LAUNCHER_HASH)))
    launcher_puzzle = (load_puzzle('singleton_launcher_with_did.clsp').curry(did_struct)
                       if custom else SINGLETON_LAUNCHER)
    launcher = Coin(bytes32(bytes([9]) * 32), launcher_puzzle.get_tree_hash(), uint64(amount))
    struct = Program.to((SINGLETON_MOD_HASH, (launcher.name(), launcher.puzzle_hash)))
    inner = Program.to(1)
    full = SINGLETON_MOD.curry(struct, inner)
    eve = Coin(launcher.name(), full.get_tree_hash(), uint64(amount))
    successor = Coin(eve.name(), full.get_tree_hash(), uint64(amount))
    final = Coin(successor.name(), full.get_tree_hash(), uint64(amount))
    launcher_args = [full.get_tree_hash(), amount, []]
    if custom: launcher_args.insert(0, bytes32(bytes([8]) * 32))
    spends = [make_spend(launcher, launcher_puzzle, Program.to(launcher_args)),
        make_spend(eve, full, solution_for_singleton(
            LineageProof(launcher.parent_coin_info, None, uint64(amount)), uint64(amount),
            Program.to([[51, inner.get_tree_hash(), amount]]))),
        make_spend(successor, full, solution_for_singleton(
            LineageProof(eve.parent_coin_info, inner.get_tree_hash(), uint64(amount)), uint64(amount),
            Program.to([[51, inner.get_tree_hash(), amount]])))]
    chain = Chain(0)
    chain.ids = [hx(c.name()) for c in [launcher, eve, successor, final]]
    chain.launcher, chain.tip = chain.ids[0], chain.ids[-1]
    chain.records, chain.children = {}, {}
    for i, coin in enumerate([launcher, eve, successor, final]):
        row = dict(coin=coin.to_json_dict(), confirmed_block_index=100 if same_block else 100+i,
                   spent_block_index=(100 if same_block else 101+i) if i < 3 else 0,
                   spent=i < 3)
        chain.records[hx(coin.name())] = row
        chain.children[hx(coin.parent_coin_info)] = [row]
    chain.spends = {hx(s.coin.name()): s.to_json_dict() for s in spends}
    tip = await market._singleton_tip(chain, chain.launcher)
    result = await market._latest_solution(chain, tip)
    assert tip.depth == 3 and tip.live.coin_id == hx(final.name())
    assert result['solution'] == bytes(spends[-1].solution).hex()


@pytest.mark.asyncio
@pytest.mark.parametrize('evm', [False, True], ids=['bls', 'evm'])
@pytest.mark.parametrize('reverse', [False, True], ids=['sols-to-deed', 'deed-to-sols'])
async def test_signed_swap_singletons_execute_without_template_substitution(monkeypatch, tmp_path, evm, reverse):
    # Full bundle consensus validation is a compatibility control. The fake node
    # below supplies no block-inclusion proof, and the context loader is a fixture.
    from tests.test_sols_swap_execution import signed_case, consensus
    from tests.test_sols_swaps import _hex32, VAULT_LAUNCHER, _settings
    from solslot_api.sols_swaps import complete_sols_swap
    request, body, _, _ = await signed_case(monkeypatch, tmp_path, evm=evm, reverse=reverse)
    bundles = []
    async def push(raw, **_kwargs):
        bundle = SpendBundle.from_json_dict(raw)
        consensus(bundle)
        bundles.append(bundle)
        return dict(provider='synthetic-primary', observed_at='2026-09-17T12:00:00Z', ambiguous_push=False)
    request.app.state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = push
    await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    assert len(bundles) == 1
    bundle = bundles[0]
    chain = Chain(0)
    chain.records, chain.spends = {}, {}
    for coin in bundle.additions():
        chain.records[hx(coin.name())] = dict(coin=coin.to_json_dict(), confirmed_block_index=101,
                                             spent_block_index=0, spent=False)
    for spend in bundle.coin_spends:
        chain.records.setdefault(hx(spend.coin.name()), dict(
            coin=spend.coin.to_json_dict(), confirmed_block_index=100))
        chain.records[hx(spend.coin.name())].update(spent_block_index=101, spent=True)
        chain.spends[hx(spend.coin.name())] = spend.to_json_dict()
    checked = 0
    for spend in bundle.coin_spends:
        puzzle = Program.from_bytes(bytes(spend.puzzle_reveal))
        if puzzle.uncurry()[0].get_tree_hash() != SINGLETON_MOD_HASH: continue
        children = [c for c in bundle.additions() if c.parent_coin_info == spend.coin.name() and c.amount % 2]
        assert len(children) == 1
        parent, child = [market._coin(chain.records[hx(c.name())]) for c in [spend.coin, children[0]]]
        result, cost = await market._singleton_spend(chain, parent, child,
            max_cost=market.MAX_SINGLETON_EVIDENCE_COST)
        assert result['solution'] == bytes(spend.solution).hex() and cost > 0
        checked += 1
    assert checked == (5 if reverse else 4)  # Includes the ephemeral deposit deed in reverse swaps.
