"""Native admission cost, full-bundle convergence, and cap refusals offline."""
from dataclasses import replace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, SpendBundle, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_api.faucet import Faucet
from solslot_api.protocol_submission import ProtocolFeePolicy, ProtocolSubmissionError
from solslot_api.stamp_fee_admission import StampFeeSubmitter, StampNetworkBusy, native_stamp_cost, check_saved_stamp_admission
from tests.test_protocol_submission import FakeProvider


def bundle():
    puzzle=Program.to((1,[[51,bytes32(b'O'*32),10]]))
    coin=Coin(bytes32(b'P'*32),puzzle.get_tree_hash(),uint64(10))
    return SpendBundle([make_spend(coin,puzzle,Program.to(0))],G2Element())


def case(*, used=0, capacity=110_000_000_000, cap=1_000_000_000):
    faucet=Faucet.from_seed_hex('21'*32,'testnet11')
    coin=Coin(bytes32(b'F'*32),faucet.address_puzzle_hash,uint64(10_000_000_000))
    class Provider(FakeProvider):
        async def get_fee_estimate(self,**kwargs):
            result=await super().get_fee_estimate(**kwargs)
            result.update(mempool_size=used,mempool_max_size=capacity)
            return result
    provider=Provider(fee_coin=coin,base_fee=8_730_336,aggregate_fee=9_158_063)
    policy=ProtocolFeePolicy(enabled=True,target_seconds=60,minimum_mojos=100_000_000,
        maximum_mojos=cap,maximum_funding_coin_mojos=10_000_000_000,estimate_buffer_bps=12500)
    return StampFeeSubmitter(provider=provider,faucet=faucet,policy=policy)


@pytest.mark.asyncio
async def test_room_in_mempool_keeps_existing_fee_and_one_primary_quote():
    submitter=case()
    assert await submitter._estimate_fee(bundle())==100_000_000
    assert len(submitter.provider.estimates)==1


@pytest.mark.asyncio
async def test_reported_stamp_cost_uses_full_pool_admission_floor_within_cap(monkeypatch):
    from solslot_api import stamp_fee_admission as admission
    monkeypatch.setattr(admission,'native_stamp_cost',lambda *args:199_726_052)
    submitter=case(used=109_925_604_060)
    assert await submitter._estimate_fee(bundle())==998_630_261
    assert submitter.policy.maximum_mojos==1_000_000_000


@pytest.mark.asyncio
async def test_busy_stamp_above_cap_waits_without_selecting_or_sending(monkeypatch):
    from solslot_api import stamp_fee_admission as admission
    monkeypatch.setattr(admission,'native_stamp_cost',lambda *args:200_000_000)
    submitter=case(used=109_925_604_060)
    with pytest.raises(StampNetworkBusy,match='approval are saved'):
        await submitter._prepare_locked(bundle().to_json_dict())
    assert submitter.provider.submitted is None


@pytest.mark.asyncio
async def test_native_aggregate_cost_prices_sponsor_and_preserves_exact_effects():
    submitter=case(used=110_000_000_000)
    submitter.policy=replace(submitter.policy,minimum_mojos=1)
    original=bundle()
    prepared=await submitter._prepare_locked(original.to_json_dict())
    cost=native_stamp_cost(prepared.bundle,4_779_194)
    assert prepared.fee_mojos>=5*cost+1
    assert prepared.bundle.coin_spends[0]==original.coin_spends[0]
    assert prepared.fee_mojos==sum(c.amount for c in prepared.bundle.removals())-sum(c.amount for c in prepared.bundle.additions())
    assert len(submitter.provider.estimates)<=4
    assert submitter.provider.submitted is None


@pytest.mark.asyncio
@pytest.mark.parametrize('changes',[{'full_node_synced':False},{'peak_height':True},{'mempool_size':-1},
    {'mempool_max_size':0},{'mempool_size':'100'},{'estimates':[False]},{'target_times':[300]},
    {'mempool_size':110_000_000_001}])
async def test_bad_primary_quote_refuses_before_sponsor_selection(changes):
    submitter=case(); original=submitter.provider.get_fee_estimate
    async def broken(**kwargs):
        result=await original(**kwargs); result.update(changes); return result
    submitter.provider.get_fee_estimate=broken
    with pytest.raises(ProtocolSubmissionError):await submitter._prepare_locked(bundle().to_json_dict())
    assert submitter.provider.submitted is None


@pytest.mark.asyncio
async def test_mempool_growth_preflight_does_not_mutate_saved_bundle_or_broadcast(monkeypatch):
    from solslot_api import stamp_fee_admission as admission
    monkeypatch.setattr(admission,'native_stamp_cost',lambda *args:199_726_052)
    submitter=case(used=109_925_604_060)
    saved={'spendBundle':bundle().to_json_dict(),'feeMojos':'100000000'}
    import copy
    held=copy.deepcopy(saved)
    with pytest.raises(StampNetworkBusy):await check_saved_stamp_admission(submitter,saved)
    assert saved==held and submitter.provider.submitted is None


@pytest.mark.asyncio
async def test_non_testnet_authority_refuses_native_admission_policy():
    submitter=case(); submitter.faucet.network='mainnet'
    with pytest.raises(ProtocolSubmissionError,match='Testnet11'):
        await submitter._estimate_fee(bundle())
    assert not submitter.provider.estimates
