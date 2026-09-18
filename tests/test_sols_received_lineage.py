"""A real consensus-valid reverse swap must leave usable vault Sols.

Chain records are synthetic observations of the executed bundle. This does not
replace the outstanding fresh-genesis/browser/provider acceptance ceremony.
"""
import copy
import pytest
from chia.types.blockchain_format.program import Program
from chia_rs import SpendBundle
from solslot_api import sols_swaps as swaps
from solslot_puzzles.sols_swap_v4_driver import puzzle_for_vault_sols_cat
from tests.test_sols_swap_execution import signed_case, consensus
from tests.test_sols_swaps import funding_runtime, _settings, _hex32, VAULT_LAUNCHER


@pytest.mark.asyncio
@pytest.mark.parametrize('evm', [False, True], ids=['bls', 'evm'])
async def test_reverse_swap_receipt_is_selectable_with_actual_parent_lineage(monkeypatch, tmp_path, evm):
    request, body, _path, _loader = await signed_case(monkeypatch, tmp_path, reverse=True, evm=evm)
    context = await swaps._load_reverse_swap_context()
    chain = request.app.state.coinset
    async def push(raw, **_kwargs):
        bundle = SpendBundle.from_json_dict(raw)
        consensus(bundle)
        chain.include(bundle)
        return dict(provider='synthetic-primary', observed_at='2026-09-18T15:00:00Z', ambiguous_push=False)
    request.app.state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = push
    response = await swaps.complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    assert response.status == 'MEMPOOL'
    class Observations:
        async def get_coin_record_by_name(self, coin_id): return chain.records.get(coin_id)
        async def get_puzzle_and_solution(self, coin_id, height):
            assert height == 100
            return chain.spends.get(coin_id)
        async def get_mempool_items_by_coin_name(self, _coin_id): return []
        async def get_coin_records_by_puzzle_hash(self, puzzle_hash, **_kwargs):
            return [row for row in chain.records.values()
                    if row['coin']['puzzle_hash'] == puzzle_hash and not row['spent']]
    arguments = dict(provider=Observations(), config=context.config,
        vault_launcher_id=context.vault_record.launcher_id, required_amount=1)
    payment = await swaps._select_vault_sols_payment_coin(**arguments)
    assert payment is not None, 'Newly received Sols must be spendable by its recipient vault'
    expected = puzzle_for_vault_sols_cat(config=context.config, vault_launcher_id=context.vault_record.launcher_id)
    assert payment.coin.puzzle_hash == expected.get_tree_hash()
    parent_id = _hex32(payment.coin.parent_coin_info)
    parent = chain.records[parent_id]['coin']
    parent_spend = chain.spends[parent_id]
    reveal = Program.from_bytes(bytes.fromhex(parent_spend['puzzle_reveal'][2:]))
    _, args = reveal.uncurry()
    assert payment.lineage.inner_puzzle_hash == list(args.as_iter())[2].get_tree_hash()
    assert payment.lineage.parent_name.hex() == parent['parent_coin_info'].removeprefix('0x')
    original = copy.deepcopy(parent_spend)
    # A forged parent reveal, even with the right observed child, is rejected.
    parent_spend['puzzle_reveal'] = '0x'+bytes(Program.to(1)).hex()
    assert await swaps._select_vault_sols_payment_coin(**arguments) is None
    chain.spends[parent_id] = original
    chain.records[parent_id]['spent_block_index'] = 99
    assert await swaps._select_vault_sols_payment_coin(**arguments) is None
