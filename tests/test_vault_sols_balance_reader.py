"""A newly launched pool has no previous solution; both reader paths must work."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from chia_rs.sized_bytes import bytes32
from solslot_api import sols_market as market, sols_swaps as swaps

@pytest.mark.asyncio
@pytest.mark.parametrize('has_solution', [False, True])
async def test_balance_reads_canonical_custody_before_and_after_first_pool_spend(monkeypatch, has_solution):
    artifact = {'launcherIds': {'pool': '0x' + '11' * 32}}
    tip, config = object(), object()
    solution = object() if has_solution else None
    monkeypatch.setattr(market, 'load_signed_public_artifact', lambda _: artifact)
    monkeypatch.setattr(market, '_singleton_tip', AsyncMock(return_value=tip))
    monkeypatch.setattr(market, '_latest_solution', AsyncMock(return_value=solution))
    calls = []
    def initial(a, t):
        assert a is artifact and t is tip
        calls.append('initial')
        return config
    def advanced(s, a, t):
        assert s is solution and a is artifact and t is tip
        calls.append('advanced')
        return config
    monkeypatch.setattr(swaps, '_initial_pool_config', initial)
    monkeypatch.setattr(swaps, '_pool_config', advanced)
    ph = bytes32(b'\x33' * 32)
    def custody(**kwargs):
        assert kwargs == {'config': config, 'vault_launcher_id': bytes32(b'\x22' * 32)}
        return SimpleNamespace(get_tree_hash=lambda: ph)
    monkeypatch.setattr(market, 'puzzle_for_vault_sols_cat', custody)
    provider = SimpleNamespace(get_coin_records_by_puzzle_hash=AsyncMock(return_value=[
        {'coin': {'amount': 7}, 'confirmed_block_index': 12, 'spent_block_index': 0},
        {'coin': {'amount': 99}, 'confirmed_block_index': 12, 'spent_block_index': 13},
        {'coin': {'amount': 55}, 'confirmed_block_index': 0, 'spent_block_index': 0},
    ]))
    reader = market.SolsMarketReader(provider, None, None)
    assert await reader.vault_sols_balance('0x' + '22' * 32) == 7
    assert calls == ['advanced' if has_solution else 'initial']
    provider.get_coin_records_by_puzzle_hash.assert_awaited_once_with('0x' + ph.hex(), include_spent=False)
