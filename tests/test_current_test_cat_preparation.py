"""Fixed Testnet issuance, wallet-only signature and native consensus checks."""
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk,calculate_synthetic_secret_key,DEFAULT_HIDDEN_PUZZLE_HASH
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
import pytest

from solslot_api.generation_customer_test_cat import prepare_test_cat,TEST_CAT_ATOMIC_UNITS
from solslot_api.faucet import AGG_SIG_ME_DATA
from tests.test_generation_genesis_core import core


def setup():
    key=AugSchemeMPL.key_gen(b'CAT-test-only-synthetic-key-000001')
    wallet=puzzle_for_pk(key.get_g1())
    coin=Coin(bytes32(b'x'*32),wallet.get_tree_hash(),uint64(TEST_CAT_ATOMIC_UNITS+123))
    return key,wallet,coin


def sign(prepared,key):
    synthetic=calculate_synthetic_secret_key(key,DEFAULT_HIDDEN_PUZZLE_HASH)
    spend=prepared.funding_spend
    pairs=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,
        spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])
    return AugSchemeMPL.aggregate([AugSchemeMPL.sign(synthetic,message) for _,message in pairs])


def test_only_funding_wallet_input_is_sent_for_signing_and_supply_is_fixed():
    key,wallet,coin=setup()
    prepared=prepare_test_cat(funding_coin=coin,funding_public_key=key.get_g1(),
        recipient_inner_hash=wallet.get_tree_hash(),network='testnet11')
    review=prepared.review()
    assert review['wholeUnits']=='100000' and review['atomicUnits']=='100000000'
    assert review['walletCoinSpends']==[prepared.funding_spend.to_json_dict()]
    assert prepared.eve_spend.coin.parent_coin_info==coin.name()
    assert len(prepared.signed_bundle(sign(prepared,key)).coin_spends)==2
    with pytest.raises(ValueError,match='EXACT_TESTNET_FUNDING_SIGNATURE'):
        prepared.signed_bundle(G2Element())
    assert not review['priceOrPegAsserted'] and not review['poolBackingAuthorized']


@pytest.mark.parametrize('network',['mainnet','testnet10',''])
def test_wrong_network_is_rejected_before_any_preparation(network):
    key,wallet,coin=setup()
    with pytest.raises(ValueError,match='EXACT_TESTNET_INPUTS'):
        prepare_test_cat(funding_coin=coin,funding_public_key=key.get_g1(),
            recipient_inner_hash=wallet.get_tree_hash(),network=network)


@pytest.mark.asyncio
async def test_native_issue_has_exact_fixed_supply_and_duplicate_broadcast_cannot_mint_again(core):
    c=core;key,wallet,_=setup();acs=Program.to(1)
    origins=[r.coin for r in await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent]
    origin=origins[0];amount=TEST_CAT_ATOMIC_UNITS+123
    coin=Coin(origin.name(),wallet.get_tree_hash(),uint64(amount))
    fund=make_spend(origin,acs,Program.to([[51,coin.puzzle_hash,amount],
        [51,acs.get_tree_hash(),int(origin.amount)-amount]]))
    assert await c.client.push_tx(SpendBundle([fund],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    prepared=prepare_test_cat(funding_coin=coin,funding_public_key=key.get_g1(),
        recipient_inner_hash=wallet.get_tree_hash(),network='testnet11')
    signed=prepared.signed_bundle(sign(prepared,key))
    assert await c.client.push_tx(signed)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD,construct_cat_puzzle
    cat=construct_cat_puzzle(CAT_MOD,prepared.asset_id,wallet)
    records=await c.client.get_coin_records_by_puzzle_hash(cat.get_tree_hash())
    assert len(records)==1 and records[0].coin.amount==TEST_CAT_ATOMIC_UNITS and not records[0].spent
    assert (await c.client.push_tx(signed))[0]!=MempoolInclusionStatus.SUCCESS
    assert len(await c.client.get_coin_records_by_puzzle_hash(cat.get_tree_hash()))==1
