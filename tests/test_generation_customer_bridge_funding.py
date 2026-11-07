"""Synthetic native acceptance for separate fresh identity bridge funding."""
from dataclasses import replace
import pytest
from chia._tests.util.spend_sim import SpendSim,SimClient
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_api.generation_customer_bridge_funding import CurrentIdentityBridgePlan
from tests.test_generation_customer_launch import fixture
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict


def plan():
    faucet,_,bindings,_,_=fixture()
    return faucet,CurrentIdentityBridgePlan(bindings,Coin(bytes32(b'F'*32),faucet.address_puzzle_hash,uint64(10000)),
        bytes(faucet.key.wallet_pk),3,999,2000)


@pytest.mark.parametrize('count', [0,17,True])
def test_count_is_finite_and_exact(count):
    _,p=plan()
    with pytest.raises(ValueError):replace(p,count=count).operation(1000)


def test_expiry_and_funding_destination_cannot_change():
    faucet,p=plan()
    with pytest.raises(ValueError):p.operation(2000)
    with pytest.raises(ValueError):replace(p,funding_coin=Coin(p.funding_coin.parent_coin_info,bytes32(b'X'*32),uint64(10000))).operation(1000)
    with pytest.raises(ValueError):p.sign(now=1000,sign_message=lambda message:AugSchemeMPL.sign(AugSchemeMPL.key_gen(b'W'*32),message))
    assert p.review(1000)==p.review(1000)
    assert p.review(1000)['fundingChangeMojos']=='9997'


@pytest.mark.asyncio
async def test_three_unique_new_native_bridge_outputs_and_unchanged_owner_change():
    faucet,p=plan();constants=DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=faucet.agg_sig_me_data)
    async with SpendSim.managed(None,defaults=constants) as sim:
        client=SimClient(sim);anyone=Program.to(1)
        await sim.farm_block(anyone.get_tree_hash())
        origin=(await client.get_coin_records_by_puzzle_hash(anyone.get_tree_hash()))[0].coin
        funding=Coin(origin.name(),faucet.address_puzzle_hash,uint64(10000))
        setup=SpendBundle([make_spend(origin,anyone,Program.to([[51,funding.puzzle_hash,10000],
            [51,anyone.get_tree_hash(),int(origin.amount)-10000]]))],G2Element())
        assert await client.push_tx(setup)==(MempoolInclusionStatus.SUCCESS,None);await sim.farm_block()
        p=replace(p,funding_coin=funding)
        bundle=p.sign(now=1000,sign_message=lambda message:AugSchemeMPL.sign(faucet.key.wallet_sk,message))
        # Even valid signatures over a subset cannot create a partial batch.
        partial_spends=list(bundle.coin_spends[:-1]);signatures=[]
        for spend in partial_spends:
            pairs=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(
                spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,faucet.agg_sig_me_data)
            signatures.extend(AugSchemeMPL.sign(faucet.key.wallet_sk,message)for _,message in pairs)
        partial=SpendBundle(partial_spends,AugSchemeMPL.aggregate(signatures))
        assert (await client.push_tx(partial))[0]!=MempoolInclusionStatus.SUCCESS
        root_conditions=list(Program.from_bytes(bytes(bundle.coin_spends[0].solution)).rest().first().rest().as_iter())
        assert sum(c.first().as_int()==64 for c in root_conditions)==p.count
        assert any(c.first().as_int()==85 and c.rest().first().as_int()==p.expires_at for c in root_conditions)
        assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None);await sim.farm_block()
        operation,coins=p.operation(1000)
        assert len(coins)==len({c.name() for c in coins})==3
        for coin in coins:
            record=await client.get_coin_record_by_name(coin.name())
            assert record and not record.spent and record.coin.puzzle_hash==p.bindings.bridge_policy and record.coin.amount==1
        # Only three mojos leave funding custody. Network fees are attached
        # separately by the bounded whole-bundle admission/submission layer.
        outputs=[r.coin for r in await client.get_coin_records_by_puzzle_hash(faucet.address_puzzle_hash) if not r.spent]
        assert sum(int(c.amount) for c in outputs)==9997
        assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
