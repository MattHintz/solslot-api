from copy import deepcopy
import time
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.cost_fees import CostFeeAdapter, FeeAdviceError, parse_tiers
from solslot_api.chia_provider import ChiaProvider, ChiaProviderConfig, ChiaProviderError
from solslot_api.faucet import Faucet
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy, ProtocolSubmissionError


def tiers(cost=100):
    return {'success': True, 'cost': cost, 'estimates': {
        name: {'fee': fee, 'fee_rate': fee/cost, 'target_time_secs': target,
            'pressure': False, 'resolution': '10s', 'window_secs': 60, 'mode': 'estimate'}
        for name, fee, target in [('economy', 0, 3600), ('standard', 25, 300), ('urgent', 50, 60)]}}


@pytest.mark.parametrize('change', [
    lambda p: p.update(cost=True), lambda p: p.update(cost=99),
    lambda p: p.update(success=False), lambda p: p.update(error='unavailable'),
    lambda p: p['estimates'].pop('urgent'),
    lambda p: p['estimates']['standard'].update(fee=0),
    lambda p: p['estimates']['standard'].update(fee=1.5),
    lambda p: p['estimates']['standard'].update(fee=True),
    lambda p: p['estimates']['standard'].update(fee=2**64),
    lambda p: p['estimates']['standard'].update(fee_rate=float('nan')),
    lambda p: p['estimates']['standard'].update(fee_rate=-1),
    lambda p: p['estimates']['standard'].update(target_time_secs=0),
])
def test_malformed_cost_advice_cannot_be_used(change):
    value = tiers(); change(value)
    with pytest.raises(FeeAdviceError):
        parse_tiers(value, cost=100, target_seconds=300, source='primary')


class Rpc:
    def __init__(self, supported=False):
        self.supported = supported
        self.route_calls = 0
        self.costs = []
        self.error = None

    async def get_routes(self):
        self.route_calls += 1
        return {'success': True, 'routes': ['/get_fee_tiers_by_cost'] if self.supported else ['/get_fee_estimate']}

    async def get_fee_tiers_by_cost(self, *, cost):
        self.costs.append(cost)
        if self.error:
            raise self.error
        return tiers(cost)


@pytest.mark.asyncio
async def test_capability_is_probed_and_cached_but_prices_are_not():
    now = [1000]
    primary, fallback = Rpc(), Rpc(True)
    adapter = CostFeeAdapter(primary, fallback, monotonic=lambda: now[0])
    for cost in [100, 200]:
        quote = await adapter.quote(cost=cost, target_seconds=300)
        assert quote.source == 'coinset-advisory' and quote.cost == cost
        assert quote.tier.fee_mojos == 25
    assert primary.route_calls == 1 and primary.costs == []
    assert fallback.costs == [100, 200]  # No bundle, addresses or signatures sent.
    primary.supported = True; now[0] += 301
    quote = await adapter.quote(cost=300, target_seconds=60)
    assert quote.source == 'primary' and quote.tier.fee_mojos == 50
    assert primary.route_calls == 2 and primary.costs == [300]
    assert fallback.costs == [100, 200]
    primary.error = FeeAdviceError('bad primary result')
    with pytest.raises(FeeAdviceError):
        await adapter.quote(cost=300, target_seconds=60)
    assert fallback.costs == [100, 200]


@pytest.mark.asyncio
async def test_optional_fallback_failure_does_not_claim_a_quote_or_primary_health():
    fallback = Rpc(True); fallback.error = RuntimeError('offline')
    assert await CostFeeAdapter(Rpc(), fallback).quote(cost=100, target_seconds=300) is None
    provider = ChiaProvider(None, fallback, ChiaProviderConfig('testnet11', None, 'https://testnet11.api.coinset.org'))
    with pytest.raises(ChiaProviderError, match='healthy local node'):
        await provider.get_cost_fee_advice(cost=100, target_seconds=300)


@pytest.mark.asyncio
async def test_native_cost_advice_preserves_admission_and_rejects_fee_cap_before_push():
    puzzle = Program.to((1, [[51, bytes32(b'2'*32), 1]]))
    coin = Coin(bytes32(b'1'*32), puzzle.get_tree_hash(), uint64(1))
    bundle = SpendBundle([make_spend(coin, puzzle, Program.to(0))], G2Element())
    seen = []
    response = {'target_times': [300], 'estimates': [1], 'full_node_synced': True,
        'peak_height': 5000000, 'mempool_size': 0, 'mempool_max_size': 55_000_000_000,
        'last_peak_timestamp': int(time.time()), 'node_time_utc': int(time.time())}
    async def estimate(**kwargs):
        assert kwargs['spend_bundle'] == bundle.to_json_dict() and kwargs['require_primary']
        return response
    async def advice(*, cost, target_seconds):
        seen.append(cost)
        return parse_tiers(tiers(cost), cost=cost, target_seconds=target_seconds, source='coinset-advisory')
    provider = SimpleNamespace(get_fee_estimate=estimate, get_cost_fee_advice=advice)
    submitter = ProtocolBundleSubmitter(provider=provider, faucet=Faucet.from_seed_hex('01'*32, 'testnet11'),
        policy=ProtocolFeePolicy(native_admission_enabled=True, cost_fee_tiers_enabled=True, maximum_mojos=20))
    with pytest.raises(ProtocolSubmissionError, match='exceeds the existing limit'):
        await submitter._estimate_fee(bundle)
    assert len(seen) == 1 and seen[0] > 100
    response['full_node_synced'] = False
    with pytest.raises(ProtocolSubmissionError, match='not synced'):
        await submitter._estimate_fee(bundle)
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_rpc_adapter_sends_only_cost_and_checks_it_before_network():
    from solslot_api.coinset_client import CoinsetClient
    client = CoinsetClient.__new__(CoinsetClient)
    calls = []
    async def post(path, body):
        calls.append((path, body)); return tiers(body['cost'])
    client._post = post
    assert await client.get_fee_tiers_by_cost(cost=100) == tiers()
    assert calls == [('/get_fee_tiers_by_cost', {'cost': 100})]
    for cost in [0, -1, True, 1.5, 11_000_000_001]:
        with pytest.raises(FeeAdviceError):
            await client.get_fee_tiers_by_cost(cost=cost)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_advisory_timeout_is_bounded_and_outage_has_a_retry_cooldown():
    import asyncio
    now, calls, cancelled = [1000.0], [], []
    async def stalled(*, cost):
        calls.append(cost)
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(cost)
    fallback = SimpleNamespace(get_fee_tiers_by_cost=stalled)
    adapter = CostFeeAdapter(Rpc(), fallback, monotonic=lambda: now[0], fallback_timeout_seconds=0.01)
    assert await adapter.quote(cost=100, target_seconds=300) is None
    assert cancelled == [100]
    assert await adapter.quote(cost=200, target_seconds=300) is None
    assert calls == [100]
    now[0] += 31
    async def recovered(*, cost): calls.append(cost); return tiers(cost)
    fallback.get_fee_tiers_by_cost = recovered
    advice = await adapter.quote(cost=300, target_seconds=300)
    assert calls == [100, 300] and advice.cost == 300
