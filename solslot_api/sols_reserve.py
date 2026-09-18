"""Prepare a bounded, atomic consolidation of the governed Sols reserve."""
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import solution_for_conditions

from .cat_lineage import confirmed_cat_receipt_lineage


@dataclass(frozen=True)
class ReserveConsolidation:
    spend: CoinSpend
    signing_conditions: Program


async def prepare_reserve_anchor(*,provider,artifact,config,pool_state,reserve_inner_puzzle):
    from .sols_swaps import SolsSwapOfferError,_coin_from_record,_record_is_unspent_coin,_hex32
    inner_hash=reserve_inner_puzzle.get_tree_hash()
    if inner_hash!=config.reserve_puzzle_hash:
        raise SolsSwapOfferError('Protocol fountain does not control the governed Sols reserve.')
    puzzle=construct_cat_puzzle(CAT_MOD,config.permanent_rules.sols_tail_hash,reserve_inner_puzzle)
    records=await provider.get_coin_records_by_puzzle_hash(_hex32(puzzle.get_tree_hash()),include_spent=False)
    coins=[]
    for record in records:
        coin=_coin_from_record(record)
        if coin is not None and _record_is_unspent_coin(record,coin):
            if coin.puzzle_hash!=puzzle.get_tree_hash() or coin.amount<=0:
                raise SolsSwapOfferError('Sols reserve record has inconsistent custody.')
            coins.append(coin)
    if (not coins or len(coins)>32 or len({coin.name() for coin in coins})!=len(coins)
        or sum(int(coin.amount) for coin in coins)!=pool_state.economics.reserve_sols_mojos):
        raise SolsSwapOfferError('Confirmed Sols reserve coins must equal the exact governed reserve balance (maximum 32 inputs).')
    coins.sort(key=lambda coin:coin.name())
    proofs=[]
    for coin in coins:
        if _hex32(coin.name())==str(artifact['solsReserveSeed']['coinId']).lower():
            if coin.amount!=1 or len(coins)!=1:
                raise SolsSwapOfferError('Sols reserve seed is inconsistent with current state.')
            proofs.append(LineageProof())
        else:
            proofs.append(await confirmed_cat_receipt_lineage(provider=provider,coin=coin,
                expected_inner_hash=inner_hash,expected_tail_hash=config.permanent_rules.sols_tail_hash,
                asset_label='Sols reserve'))
    if len(coins)==1:
        return coins[0],proofs[0],()
    total=sum(int(coin.amount) for coin in coins)
    conditions=[Program.to([[51,inner_hash,total]])]+[Program.to([]) for _ in coins[1:]]
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(
        coin=coin,limitations_program_hash=config.permanent_rules.sols_tail_hash,
        inner_puzzle=reserve_inner_puzzle,inner_solution=solution_for_conditions(condition.as_python()),
        lineage_proof=lineage) for coin,lineage,condition in zip(coins,proofs,conditions)])
    anchor=Coin(coins[0].name(),puzzle.get_tree_hash(),total)
    if bundle.additions()!=[anchor]:
        raise SolsSwapOfferError('Reserve consolidation did not create its exact anchor.')
    lineage=LineageProof(parent_name=coins[0].parent_coin_info,inner_puzzle_hash=inner_hash,amount=coins[0].amount)
    return anchor,lineage,tuple(ReserveConsolidation(spend,condition)
        for spend,condition in zip(bundle.coin_spends,conditions))
