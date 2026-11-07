"""Unsigned, fixed-supply CAT preparation for the Testnet acceptance package.

No key access, coin selection, issuer privileges, broadcast or price assertion.
The final approval must pin a confirmed funding coin and receiving wallet.
Only the confirmed funding spend belongs in the wallet signing request; the
ephemeral CAT eve spend is assembled locally after the wallet approves it.
"""
from dataclasses import dataclass

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk, solution_for_conditions
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from .faucet import AGG_SIG_ME_DATA

TEST_CAT_DECIMALS=3
TEST_CAT_UNITS=100_000
TEST_CAT_ATOMIC_UNITS=TEST_CAT_UNITS*10**TEST_CAT_DECIMALS


def h(value):return '0x'+bytes(value).hex()


@dataclass(frozen=True)
class TestCatPreparation:
    funding_spend:object
    eve_spend:object
    asset_id:bytes32
    recipient_inner_hash:bytes32

    def review(self):
        return {'schema':'solslot.fixed-test-cat-preparation.v1','network':'testnet11',
            'name':'Solslot Test CAT','symbol':'SLTC','decimals':TEST_CAT_DECIMALS,
            'wholeUnits':str(TEST_CAT_UNITS),'atomicUnits':str(TEST_CAT_ATOMIC_UNITS),
            'assetId':h(self.asset_id),'fundingCoinId':h(self.funding_spend.coin.name()),
            'nativeIssuanceMojos':str(TEST_CAT_ATOMIC_UNITS),'networkFeeMojos':'0',
            'recipientInnerPuzzleHash':h(self.recipient_inner_hash),
            'walletCoinSpends':[self.funding_spend.to_json_dict()],
            'singleIssuance':True,'priceOrPegAsserted':False,'poolBackingAuthorized':False,
            'primaryConfirmationStillRequired':True,'submitted':False}

    def signed_bundle(self,signature):
        if not isinstance(signature,G2Element):raise ValueError('TEST_CAT_TYPED_WALLET_SIGNATURE_REQUIRED')
        pairs=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(
            self.funding_spend.puzzle_reveal,self.funding_spend.solution,100_000_000),
            self.funding_spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if not pairs or not AugSchemeMPL.aggregate_verify([p for p,_ in pairs],[m for _,m in pairs],signature):
            raise ValueError('TEST_CAT_EXACT_TESTNET_FUNDING_SIGNATURE_REQUIRED')
        return SpendBundle([self.funding_spend,self.eve_spend],signature)


def prepare_test_cat(*,funding_coin,funding_public_key,recipient_inner_hash,network):
    if (network!='testnet11' or not isinstance(funding_coin,Coin)
            or not isinstance(funding_public_key,G1Element) or funding_public_key==G1Element()
            or not isinstance(recipient_inner_hash,bytes32) or recipient_inner_hash==bytes32.zeros):
        raise ValueError('TEST_CAT_EXACT_TESTNET_INPUTS_REQUIRED')
    wallet=puzzle_for_pk(funding_public_key)
    if funding_coin.puzzle_hash!=wallet.get_tree_hash() or funding_coin.amount<TEST_CAT_ATOMIC_UNITS:
        raise ValueError('TEST_CAT_WALLET_FUNDING_REQUIRED')
    tail=GENESIS_BY_ID_MOD.curry(funding_coin.name())
    asset=tail.get_tree_hash();eve_inner=Program.to(1)
    eve=Coin(funding_coin.name(),construct_cat_puzzle(CAT_MOD,asset,eve_inner).get_tree_hash(),
        uint64(TEST_CAT_ATOMIC_UNITS))
    conditions=[[51,eve.puzzle_hash,TEST_CAT_ATOMIC_UNITS]]
    change=int(funding_coin.amount)-TEST_CAT_ATOMIC_UNITS
    if change:conditions.append([51,wallet.get_tree_hash(),change])
    source=make_spend(funding_coin,wallet,solution_for_conditions(conditions))
    issued=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,asset,eve_inner,
        Program.to([[51,recipient_inner_hash,TEST_CAT_ATOMIC_UNITS],[51,[],-113,tail,[]]]),
        limitations_program_reveal=tail)])
    if len(issued.coin_spends)!=1 or issued.aggregated_signature!=G2Element():
        raise ValueError('TEST_CAT_EXACT_UNSIGNED_EVE_REQUIRED')
    return TestCatPreparation(source,issued.coin_spends[0],asset,recipient_inner_hash)
