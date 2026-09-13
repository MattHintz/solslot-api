"""Actual Chia CLVM/BLS fixtures, not deployed Tibet transaction evidence."""
from dataclasses import replace
from hashlib import sha256

import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode as Op
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH, calculate_synthetic_secret_key, puzzle_for_pk, solution_for_conditions,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.tibet_wallet_offer import (
    MAX_OFFER_BYTES, MAX_SPEND_COST, TibetFundingCoin, TibetOfferTerms, TibetOfferVerificationError,
    TibetPairCommitment, TibetReleaseBinding, prepare_tibet_offer, verify_tibet_wallet_response,
    tibet_coin_spends_for_signing, verify_tibet_wallet_signature,
)


KEY = AugSchemeMPL.key_gen(b"tibet offline test fixture key 01")
OTHER_KEY = AugSchemeMPL.key_gen(b"tibet offline test fixture key 02")
TOKEN = bytes32(b"t" * 32)
NOW = 1_800_000_000


def pair():
    # Synthetic non-deployed module used ONLY to prove pin/launcher derivation.
    module = Program.to(1)
    launcher = bytes32(b"p" * 32)
    lp = module.curry((SINGLETON_MOD_HASH, (launcher, SINGLETON_LAUNCHER_HASH))).get_tree_hash()
    return TibetPairCommitment(launcher, TOKEN, lp, bytes32(b"q" * 32), bytes(module), module.get_tree_hash())


def terms(action="ADD", fee=10):
    return TibetOfferTerms(
        TibetReleaseBinding("staging", "testnet11", "offline-fixture-only", "alpha-review-fixture",
                            "1" * 40, bytes32(b"e" * 32), "tibet-offline-maker-v1"),
        pair(), bytes32(b"o" * 32), action, 100, 200, 50, fee, KEY.get_g1(), NOW - 1, NOW + 299,
    )


def funding(asset, amount=1_000, key=KEY):
    inner = puzzle_for_pk(key.get_g1())
    if asset is None:
        return TibetFundingCoin(Coin(bytes32(b"x" * 32), inner.get_tree_hash(), uint64(amount)), key.get_g1(), None)
    puzzle = construct_cat_puzzle(CAT_MOD, asset, inner)
    parent = Coin(bytes32(b"c" * 32), puzzle.get_tree_hash(), uint64(amount))
    return TibetFundingCoin(Coin(parent.name(), puzzle.get_tree_hash(), uint64(amount)), key.get_g1(), asset,
                            LineageProof(parent.parent_coin_info, inner.get_tree_hash(), parent.amount))


def prepare(action="ADD", fee=10):
    review = terms(action, fee)
    coins = ((funding(None), funding(TOKEN)) if action == "ADD" else
             ((funding(review.pair.liquidity_asset_id), funding(None)) if fee else
              (funding(review.pair.liquidity_asset_id),)))
    return prepare_tibet_offer(review, coins, now=NOW)


def sign(prepared, *, network="testnet11", key=KEY, omit_last=False):
    bundle = WalletSpendBundle.from_bytes(prepared.unsigned_wallet_bundle)
    signatures = []
    synthetic = calculate_synthetic_secret_key(key, DEFAULT_HIDDEN_PUZZLE_HASH)
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, MAX_SPEND_COST)
        for _, message in pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA[network]):
            signatures.append(AugSchemeMPL.sign(synthetic, message))
    if omit_last:
        signatures.pop()
    return bytes(WalletSpendBundle(bundle.coin_spends, AugSchemeMPL.aggregate(signatures)))


def verify(prepared, signed=None, **kwargs):
    return verify_tibet_wallet_response(
        prepared, sign(prepared) if signed is None else signed,
        active_binding=kwargs.get("active_binding", prepared.terms.binding),
        observed_network=kwargs.get("observed_network", "testnet11"), now=kwargs.get("now", NOW),
    )


@pytest.mark.parametrize("action,fee", [("ADD", 10), ("ADD", 0), ("REMOVE", 10), ("REMOVE", 0)])
def test_real_clvm_offer_roundtrip_has_exact_assets_payments_change_and_fee(action, fee):
    prepared = prepare(action, fee)
    offer = Offer.from_bytes(verify(prepared))
    lp = prepared.terms.pair.liquidity_asset_id
    assert offer.get_offered_amounts() == ({None: 100, TOKEN: 200} if action == "ADD" else {lp: 50})
    assert offer.get_requested_amounts() == ({lp: 50} if action == "ADD" else {None: 100, TOKEN: 200})
    receiver = puzzle_for_pk(KEY.get_g1()).get_tree_hash()
    for payments in offer.requested_payments.values():
        assert len(payments) == 1
        assert payments[0].puzzle_hash == receiver
        assert payments[0].memos == [bytes(receiver)]
        assert payments[0].nonce == prepared.review_digest
    created_coin_announcements = set()
    asserted_coin_announcements = set()
    for spend, coin in zip(offer.coin_spends(), prepared.funding, strict=True):
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, MAX_SPEND_COST)
        assert int.from_bytes(conditions[Op.ASSERT_SECONDS_ABSOLUTE][0].vars[0]) == NOW - 1
        assert int.from_bytes(conditions[Op.ASSERT_BEFORE_SECONDS_ABSOLUTE][0].vars[0]) == NOW + 299
        outputs = [(bytes32(c.vars[0]), int.from_bytes(c.vars[1])) for c in conditions[Op.CREATE_COIN]]
        offered = offer.get_offered_amounts().get(coin.asset_id, 0)
        charged_fee = fee if coin.asset_id is None else 0
        change = int(coin.coin.amount) - offered - charged_fee
        assert (coin.coin.puzzle_hash, change) in outputs
        assert sum(amount for _, amount in outputs) == int(coin.coin.amount) - charged_fee
        if coin.asset_id is None and fee:
            assert int.from_bytes(conditions[Op.RESERVE_FEE][0].vars[0]) == fee
        else:
            assert Op.RESERVE_FEE not in conditions
        # Every funding input commits to all other inputs and to all requested payouts.
        assert len(conditions[Op.ASSERT_COIN_ANNOUNCEMENT]) >= len(prepared.funding)
        assert len(conditions[Op.ASSERT_PUZZLE_ANNOUNCEMENT]) == len(offer.requested_payments)
        created_coin_announcements.update(
            sha256(bytes(spend.coin.name()) + c.vars[0]).digest()
            for c in conditions[Op.CREATE_COIN_ANNOUNCEMENT]
        )
        asserted_coin_announcements.update(c.vars[0] for c in conditions[Op.ASSERT_COIN_ANNOUNCEMENT])
    assert asserted_coin_announcements <= created_coin_announcements


@pytest.mark.parametrize("field,value", [
    ("network", "mainnet"), ("environment", "test"), ("deployment_id", "different-test-deployment"),
    ("release_id", "another-release"), ("source_sha", "2" * 40),
    ("evidence_sha256", bytes32(b"f" * 32)), ("adapter_version", "another-version"),
])
def test_rejects_current_release_evidence_or_deployment_change(field, value):
    prepared = prepare()
    with pytest.raises(TibetOfferVerificationError, match="release or wallet network"):
        verify(prepared, active_binding=replace(prepared.terms.binding, **{field: value}))


@pytest.mark.parametrize("network", ["mainnet", "testnet10", "unknown"])
def test_rejects_observed_wrong_network(network):
    with pytest.raises(TibetOfferVerificationError, match="network"):
        verify(prepare(), observed_network=network)


@pytest.mark.parametrize("bad_signature", ["mainnet", "other-key", "partial", "empty"])
def test_rejects_invalid_or_incomplete_wallet_signature(bad_signature):
    prepared = prepare()
    if bad_signature == "mainnet":
        signed = sign(prepared, network="mainnet")
    elif bad_signature == "other-key":
        signed = sign(prepared, key=OTHER_KEY)
    elif bad_signature == "partial":
        signed = sign(prepared, omit_last=True)
    else:
        signed = prepared.unsigned_wallet_bundle
    with pytest.raises(TibetOfferVerificationError, match="aggregate signature"):
        verify(prepared, signed)


@pytest.mark.parametrize("mutation", ["extra-spend", "missing-spend", "changed-solution", "duplicate-spend", "reorder"])
def test_wallet_cannot_change_any_reviewed_spend(mutation):
    prepared = prepare()
    signed = WalletSpendBundle.from_bytes(sign(prepared))
    spends = list(signed.coin_spends)
    if mutation == "extra-spend":
        other = funding(None, 2_000)
        spends.append(make_spend(other.coin, puzzle_for_pk(KEY.get_g1()), solution_for_conditions([])))
    elif mutation == "missing-spend":
        spends.pop()
    elif mutation == "changed-solution":
        # An untrusted puzzle/solution is compared before any CLVM execution.
        spends[0] = make_spend(spends[0].coin, Program.to(8), Program.to([]))
    elif mutation == "duplicate-spend":
        spends.append(spends[0])
    else:
        spends.reverse()
    with pytest.raises(TibetOfferVerificationError, match="changed reviewed"):
        verify(prepared, bytes(WalletSpendBundle(spends, signed.aggregated_signature)))


def test_expired_offer_and_signature_replay_across_operations_fail():
    original = prepare()
    with pytest.raises(TibetOfferVerificationError, match="expired"):
        verify(original, now=original.terms.expires_at)
    different = prepare_tibet_offer(replace(original.terms, operation_hash=bytes32(b"d" * 32)),
                                   original.funding, now=NOW)
    assert original.review_digest != different.review_digest
    with pytest.raises(TibetOfferVerificationError, match="changed reviewed"):
        verify(different, sign(original))


@pytest.mark.parametrize("mutation", ["owner", "asset", "lineage", "amount", "duplicate", "extra-asset"])
def test_invalid_funding_cannot_reach_wallet_prompt(mutation):
    review = terms()
    coins = [funding(None), funding(TOKEN)]
    if mutation == "owner":
        coins[1] = replace(coins[1], public_key=OTHER_KEY.get_g1())
    elif mutation == "asset":
        coins[1] = replace(coins[1], asset_id=bytes32(b"z" * 32))
    elif mutation == "lineage":
        coins[1] = replace(coins[1], lineage_proof=LineageProof(bytes32(b"z" * 32), bytes32(b"z" * 32), uint64(100)))
    elif mutation == "amount":
        coins[0] = funding(None, 100)
    elif mutation == "duplicate":
        coins[1] = coins[0]
    else:
        coins.append(funding(review.pair.liquidity_asset_id))
    with pytest.raises(TibetOfferVerificationError):
        prepare_tibet_offer(review, tuple(coins), now=NOW)


@pytest.mark.parametrize("mutation", ["module", "launcher", "lp"])
def test_pair_or_lp_commitment_mismatch_rejected(mutation):
    review = terms()
    field, value = {"module": ("liquidity_tail_module", bytes(Program.to(2))),
                    "launcher": ("launcher_id", bytes32(b"z" * 32)),
                    "lp": ("liquidity_asset_id", bytes32(b"z" * 32))}[mutation]
    with pytest.raises(TibetOfferVerificationError, match="LP"):
        prepare_tibet_offer(replace(review, pair=replace(review.pair, **{field: value})),
                            (funding(None), funding(TOKEN)), now=NOW)


@pytest.mark.parametrize("value", [b"bad", b"z" * (MAX_OFFER_BYTES + 1), b"z" * 200])
def test_wallet_parser_is_bounded_and_rejects_malformed_bytes(value):
    with pytest.raises(TibetOfferVerificationError, match="bundle"):
        verify(prepare(), value)


def test_module_remains_uninstalled_without_external_trial_evidence():
    from solslot_api.sols_market import LIQUIDITY_INSTALLED_ADAPTERS
    assert "TIBETSWAP_V2" not in LIQUIDITY_INSTALLED_ADAPTERS


def test_existing_wallet_signing_contract_and_signature_only_response_are_exact():
    prepared = prepare()
    request = tibet_coin_spends_for_signing(prepared, active_binding=prepared.terms.binding,
                                           observed_network="testnet11", now=NOW)
    bundle = WalletSpendBundle.from_bytes(sign(prepared))
    for wire, spend in zip(request, bundle.coin_spends, strict=True):
        assert wire["coin"]["amount"] == str(spend.coin.amount)
        assert wire["puzzleReveal"] == "0x" + bytes(spend.puzzle_reveal).hex()
        assert wire["solution"] == "0x" + bytes(spend.solution).hex()
    signed = verify_tibet_wallet_signature(
        prepared, "0x" + bytes(bundle.aggregated_signature).hex(),
        active_binding=prepared.terms.binding, observed_network="testnet11", now=NOW,
    )
    assert signed == verify(prepared)


@pytest.mark.parametrize("signature", ["0x00", "0x" + "ff" * 96, "aa" * 96])
def test_signature_only_response_must_be_canonical_valid_bls(signature):
    prepared = prepare()
    with pytest.raises(TibetOfferVerificationError, match="signature"):
        verify_tibet_wallet_signature(prepared, signature, active_binding=prepared.terms.binding,
                                     observed_network="testnet11", now=NOW)


def test_wallet_request_rejects_javascript_integer_rounding():
    prepared = prepare_tibet_offer(terms(), (funding(None, 2**53), funding(TOKEN)), now=NOW)
    with pytest.raises(TibetOfferVerificationError, match="represent"):
        tibet_coin_spends_for_signing(prepared, active_binding=prepared.terms.binding,
                                     observed_network="testnet11", now=NOW)


def test_expiry_is_rechecked_before_preparing_wallet_prompt():
    prepared = prepare()
    with pytest.raises(TibetOfferVerificationError, match="expired"):
        tibet_coin_spends_for_signing(prepared, active_binding=prepared.terms.binding,
                                     observed_network="testnet11", now=prepared.terms.expires_at)


def test_persisted_review_cannot_mix_terms_and_previously_reviewed_spends():
    prepared = prepare()
    altered = replace(prepared, terms=replace(prepared.terms, fee_mojos=20))
    with pytest.raises(TibetOfferVerificationError, match="stored review"):
        verify(altered, sign(prepared))
