"""Primary observation boundaries; no network, signing or consensus proof claims."""
import asyncio
from copy import deepcopy
from types import SimpleNamespace
from time import time

import pytest
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32

from solslot_api.chia_provider import ChiaProvider, ChiaProviderConfig, ChiaProviderError
from solslot_api.chia_snapshot import PrimaryReadSnapshot, active_snapshot, _hash
from solslot_api import chia_snapshot as snapshots
from solslot_api import sols_swaps as swaps

pytestmark = pytest.mark.asyncio
COIN = Coin(bytes32(b"a" * 32), bytes32(b"b" * 32), 128)
HX = "0x" + COIN.name().hex()


class Node:
    def __init__(self):
        self.info = dict(success=True, network_name="testnet11")
        self.state = dict(success=True, blockchain_state=dict(
            peak=dict(height=100, header_hash="11" * 32), sync=dict(synced=True, sync_mode=False)))
        self.clock = int(time())
        self.records = {HX: dict(coin=COIN.to_json_dict(), confirmed_block_index=10,
                                spent_block_index=0, spent=False)}
        self.pending = []
        self.calls = []
        self.error = None

    async def get_network_info(self): return self.info
    async def get_blockchain_state(self): return self.state
    async def get_block_record(self, digest):
        return dict(success=True, block_record=dict(height=100, header_hash=digest,
            timestamp=self.clock, prev_hash="22" * 32))
    async def get_coin_record_by_name(self, name):
        self.calls.append(name)
        if self.error: raise self.error
        return self.records.get(name)
    async def get_mempool_items_by_coin_name(self, name): return self.pending
    async def get_fee_estimate(self, **kwargs): return dict(estimates=[100], target_times=kwargs['target_times'])


def provider(node=None):
    node = node or Node()
    fallback = Node()
    return ChiaProvider(node, fallback, ChiaProviderConfig(
        network="testnet11", primary_url="https://primary.invalid", fallback_url="https://fallback.invalid"))


def binding(): return {"quoteExpiresAt": int(time()) + 120, "protocolCandidateHash": "0x" + "33" * 32}


async def test_detached_primary_observation_includes_exact_input_and_stable_peak():
    p = provider()
    async with PrimaryReadSnapshot(p, "testnet11") as s:
        response = await p.get_coin_record_by_name(HX)
        response['coin']['amount'] = 9  # caller cannot rewrite the captured response
        receipt = await s.finish([('vault', COIN)], binding())
    assert receipt['status'] == 'PRIMARY_NODE_OBSERVATION'
    assert receipt['consensusInclusionProven'] is False
    assert receipt['inputs'][0]['coin']['amount'] == '128'
    assert receipt['inputs'][0]['coinId'] == HX
    assert receipt['snapshotHash'] == _hash({k: v for k, v in receipt.items() if k != 'snapshotHash'})
    assert not p.fallback.calls and active_snapshot() is None


@pytest.mark.parametrize('change', ['branch', 'height', 'network', 'sync', 'sync_mode', 'primary', 'record', 'missing', 'pending'])
async def test_changed_or_unavailable_current_state_is_rejected(change):
    p = provider()
    with pytest.raises(ChiaProviderError):
        async with PrimaryReadSnapshot(p, 'testnet11') as s:
            await p.get_coin_record_by_name(HX)
            if change == 'branch': p.primary.state['blockchain_state']['peak']['header_hash'] = '44' * 32
            elif change == 'height': p.primary.state['blockchain_state']['peak']['height'] += 1
            elif change == 'network': p.primary.info['network_name'] = 'mainnet'
            elif change == 'sync': p.primary.state['blockchain_state']['sync']['synced'] = False
            elif change == 'sync_mode': p.primary.state['blockchain_state']['sync']['sync_mode'] = True
            elif change == 'primary': p.primary = Node()
            elif change == 'record': p.primary.records[HX]['spent_block_index'] = 100
            elif change == 'missing': p.primary.records.pop(HX)
            elif change == 'pending': p.primary.pending = [{'spend': 'other'}]
            await s.finish([('vault', COIN)], binding())
    assert active_snapshot() is None


@pytest.mark.parametrize('age', [-301, 61])
async def test_stale_and_future_chain_time_are_rejected(age):
    p = provider(); p.primary.clock = int(time()) + age
    with pytest.raises(ChiaProviderError, match='clock'):
        async with PrimaryReadSnapshot(p, 'testnet11'): pass
    assert active_snapshot() is None


async def test_read_error_never_uses_fallback_and_scope_cleanup_restores_regular_reads():
    p = provider()
    with pytest.raises(ChiaProviderError):
        async with PrimaryReadSnapshot(p, 'testnet11'):
            p.primary.error = OSError('lost primary')
            await p.get_coin_record_by_name(HX)
    assert not p.fallback.calls
    p.primary.error = None
    assert await p.get_coin_record_by_name(HX)


async def test_second_provider_cannot_supply_funding_even_on_the_same_network():
    p, second = provider(), provider()
    with pytest.raises(ChiaProviderError, match='provider'):
        async with PrimaryReadSnapshot(p, 'testnet11'):
            await second.get_fee_estimate(target_times=[60], cost=100, require_primary=True)


async def test_authority_rechecked_after_all_provider_awaits():
    p = provider(); authority = {'session': 'original'}
    with pytest.raises(ChiaProviderError, match='authority'):
        async with PrimaryReadSnapshot(p, 'testnet11') as s:
            s.recheck(lambda: authority, authority)
            authority['session'] = 'replacement'
            await s.finish([('vault', COIN)], binding())


async def test_no_primary_and_wrong_network_are_rejected():
    p = provider(); p.primary = None
    with pytest.raises(ChiaProviderError): PrimaryReadSnapshot(p, 'testnet11')
    with pytest.raises(ChiaProviderError): PrimaryReadSnapshot(provider(), 'mainnet')


async def test_snapshot_timeout_cleans_scope(monkeypatch):
    monkeypatch.setattr(snapshots, 'SNAPSHOT_TIMEOUT_SECONDS', 0.01)
    with pytest.raises(ChiaProviderError, match='timed out'):
        async with PrimaryReadSnapshot(provider(), 'testnet11'):
            await asyncio.sleep(0.1)
    assert active_snapshot() is None


async def test_entry_timeout_cleans_scope(monkeypatch):
    monkeypatch.setattr(snapshots, 'SNAPSHOT_TIMEOUT_SECONDS', 0.01)
    p = provider()
    async def delayed(): await asyncio.sleep(0.1)
    p.primary.get_network_info = delayed
    with pytest.raises(ChiaProviderError, match='timed out'):
        async with PrimaryReadSnapshot(p, 'testnet11'): pass
    assert active_snapshot() is None


@pytest.mark.parametrize('limit', ['MAX_READS', 'MAX_READ_BYTES'])
async def test_resource_bounds_fail_closed(monkeypatch, limit):
    p = provider()
    async with PrimaryReadSnapshot(p, 'testnet11'):
        monkeypatch.setattr(snapshots, limit, 0)
        with pytest.raises(ChiaProviderError): await p.get_coin_record_by_name(HX)


async def test_no_broadcast_in_read_session():
    p = provider()
    async with PrimaryReadSnapshot(p, 'testnet11'):
        with pytest.raises(ChiaProviderError, match='broadcast'): await p.push_tx({})


@pytest.mark.parametrize('reverse,consolidation', [(False,0),(True,0),(True,2),(True,32)])
async def test_prepare_scope_covers_funding_but_excludes_ephemeral_inputs(monkeypatch, reverse, consolidation):
    p = provider(); coins = {}
    roles = ['sols_settlement', 'statutes', 'vault', 'pool'] + (
        ['held_deed', 'smart_deed', 'sols_reserve'] if reverse else ['sols_payment', 'deed_custody'])
    roles = [f'reserve_consolidation_{i}' for i in range(consolidation)] + roles
    ephemeral = {'sols_settlement', 'smart_deed'} | ({'sols_reserve'} if consolidation else set())
    def spend(role, index):
        coin = Coin(bytes32(bytes([index]) * 32), bytes32(b'b' * 32), 1)
        coins[role] = coin
        if role not in ephemeral:
            p.primary.records['0x' + coin.name().hex()] = dict(coin=coin.to_json_dict(),
                confirmed_block_index=10, spent_block_index=0, spent=False)
        return {'role': role, 'coin': dict(parentCoinInfo='0x' + coin.parent_coin_info.hex(),
            puzzleHash='0x' + coin.puzzle_hash.hex(), amount='1')}
    evidence = {'coinSpends': [spend(r, i + 1) for i, r in enumerate(roles)], 'protocolCandidateHash': 'candidate'}
    funding = {'fundingCoinSpend': spend('fee', 99), 'reservationHash': 'funding', 'binding': {'sessionFingerprint': 'session'}}
    result = SimpleNamespace(unsigned_protocol_evidence=evidence, funding_evidence=funding,
        operation_hash='operation', quote_expires_at=int(time()) + 120, model_copy=lambda *, update: update)
    async def prepare(*args):
        assert active_snapshot() is not None
        await p.get_coin_record_by_name('0x' + coins['pool'].name().hex())
        await p.get_fee_estimate(target_times=[60], cost=100, require_primary=True)
        return result
    monkeypatch.setattr(swaps, '_prepare_sols_swap', prepare)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=p)))
    prepared = await swaps._snapshot_prepare('vault', None, request, SimpleNamespace(network='testnet11'))
    receipt = prepared['current_state_evidence']
    assert {r['role'] for r in receipt['inputs']} == set(roles + ['fee']) - ephemeral
    assert receipt['binding']['fundingReservationHash'] == 'funding'
    assert receipt['binding']['sessionFingerprint'] == 'session'
    assert not p.fallback.calls


@pytest.mark.parametrize('amount', ['128', True, 128.0])
async def test_persistent_record_requires_exact_integer_amount(amount):
    p = provider(); p.primary.records[HX]['coin']['amount'] = amount
    with pytest.raises(ChiaProviderError, match='persistent input'):
        async with PrimaryReadSnapshot(p, 'testnet11') as s:
            await s.finish([('vault', COIN)], binding())


@pytest.mark.parametrize('change', ['branch', 'authority'])
async def test_mutation_during_final_input_await_is_rejected(change):
    p = provider(); authority = {'session':'original'}
    async def pending(name):
        if change == 'branch': p.primary.state['blockchain_state']['peak']['header_hash'] = '44' * 32
        else: authority['session'] = 'replaced'
        return []
    p.primary.get_mempool_items_by_coin_name = pending
    with pytest.raises(ChiaProviderError):
        async with PrimaryReadSnapshot(p, 'testnet11') as s:
            s.recheck(lambda: authority, authority)
            await s.finish([('vault', COIN)], binding())


@pytest.mark.parametrize('changed_fee', [False, True])
async def test_fee_replay_ignores_clock_telemetry_but_not_quote(changed_fee):
    p = provider(); calls = 0
    async def estimate(**kwargs):
        nonlocal calls
        calls += 1
        return dict(estimates=[100 + (calls if changed_fee else 0)], target_times=kwargs['target_times'],
            node_time_utc=int(time()) + calls, mempool_size=calls, mempool_fees=calls,
            current_fee_rate=0.1, full_node_synced=True, peak_height=100)
    p.primary.get_fee_estimate = estimate
    async def prepare():
        async with PrimaryReadSnapshot(p, 'testnet11') as s:
            quote = await p.get_fee_estimate(target_times=[60], cost=100, require_primary=True)
            assert set(quote) == {'estimates', 'target_times'}
            return await s.finish([('vault', COIN)], binding())
    if changed_fee:
        with pytest.raises(ChiaProviderError, match='observation changed'): await prepare()
    else: assert (await prepare())['status'] == 'PRIMARY_NODE_OBSERVATION'


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('changed', [False, True])
async def test_completion_context_rechecks_primary_and_exits_before_broadcast(monkeypatch, reverse, changed):
    from tests.test_sols_swaps import _fixture, _reverse_fixture
    from solslot_api.faucet import Faucet
    context = _reverse_fixture(Faucet.from_seed_hex('77' * 32, 'testnet11')) if reverse else _fixture().context
    p = provider()
    coins = [context.pool_coin, context.statutes_coin, context.vault_coin]
    coins += [context.deed.coin, context.reserve_coin] if reverse else [context.custody_coin, context.payment_coin]
    for coin in coins:
        p.primary.records['0x'+coin.name().hex()] = dict(coin=coin.to_json_dict(),
            confirmed_block_index=10, spent_block_index=0, spent=False)
    monkeypatch.setattr(swaps, 'load_signed_public_artifact', lambda *_: context.artifact)
    monkeypatch.setattr(swaps, 'require_vault_record', lambda *_: context.vault_record)
    monkeypatch.setattr(swaps, 'require_current_approved_vault', lambda *_: context.approved_vault)
    async def derive(**kwargs):
        assert active_snapshot() is not None
        await p.get_coin_record_by_name('0x'+context.vault_coin.name().hex())
        if changed: p.primary.state['blockchain_state']['peak']['header_hash'] = '44' * 32
        return context
    kwargs = dict(provider=p, settings=SimpleNamespace(network='testnet11'))
    if changed:
        with pytest.raises(ChiaProviderError): await swaps._load_observed_context(derive, kwargs)
    else:
        assert await swaps._load_observed_context(derive, kwargs) is context
    assert active_snapshot() is None and not p.fallback.calls


async def test_persistent_input_limit_still_rejects_oversized_snapshot():
    p = provider()
    inputs = [('input', Coin(bytes32(bytes([i]) * 32), bytes32(b'b' * 32), 1)) for i in range(38)]
    async with PrimaryReadSnapshot(p, 'testnet11') as snapshot:
        with pytest.raises(ChiaProviderError, match='distinct persistent inputs'):
            await snapshot.finish(inputs, binding())
