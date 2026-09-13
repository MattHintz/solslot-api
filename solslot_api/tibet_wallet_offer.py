"""Offline Tibet maker-offer construction and wallet-response verification.

This is deliberately not an installed adapter or submission endpoint. Inputs must
come from an authenticated, current deployment review and independent Chia coin
observations, never from a wallet/venue response. A verified maker offer is NOT a
verified Tibet completion bundle. No function here broadcasts or enables writes.

Only canonical standard-wallet XCH and plain CAT funding is supported, with one
coin per asset. Vault puzzles, rCATs, arbitrary wallet offers and arbitrary change
addresses fail closed. The final pair/reserve-spend verifier remains a separate
required integration boundary before any signed offer can leave the application.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode as Op
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH, calculate_synthetic_public_key, puzzle_for_pk, solution_for_conditions,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH
from chia.wallet.trading.offer import OFFER_MOD_HASH, NotarizedPayment, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from .faucet import AGG_SIG_ME_DATA


MAX_OFFER_BYTES = 100_000
MAX_SPEND_COST = 50_000_000
MAX_LIFETIME_SECONDS = 600
MAX_WALLET_SAFE_INTEGER = 2**53 - 1


class TibetOfferVerificationError(ValueError):
    pass


@dataclass(frozen=True)
class TibetReleaseBinding:
    environment: str
    network: str
    deployment_id: str
    release_id: str
    source_sha: str
    evidence_sha256: bytes32
    adapter_version: str

    def validate(self) -> None:
        # This implementation is alpha only; a mainnet wallet signature cannot
        # be accepted by selecting different caller-supplied additional data.
        if self.network != "testnet11" or self.environment not in {"test", "staging", "production"}:
            raise TibetOfferVerificationError("Tibet offline alpha review requires isolated testnet11")
        if (not all((self.deployment_id, self.release_id, self.adapter_version))
                or not re.fullmatch(r"[0-9a-f]{40}", self.source_sha)
                or self.evidence_sha256 == bytes32.zeros):
            raise TibetOfferVerificationError("incomplete release binding")


@dataclass(frozen=True)
class TibetPairCommitment:
    """Reviewed artifact references, not evidence of a current pair spend.

    The LP TAIL module bytes AND their expected hash must be loaded from the
    pinned, reviewed deployment artifact. A public descriptor supplying both is
    not a trust root. The current pair puzzle hash is committed in signatures,
    but pair execution still needs independent final-bundle verification.
    """
    launcher_id: bytes32
    token_asset_id: bytes32
    liquidity_asset_id: bytes32
    pair_puzzle_hash: bytes32
    liquidity_tail_module: bytes
    liquidity_tail_module_hash: bytes32

    def validate(self) -> None:
        if (bytes32.zeros in (self.launcher_id, self.token_asset_id, self.liquidity_asset_id,
                              self.pair_puzzle_hash, self.liquidity_tail_module_hash)
                or self.token_asset_id == self.liquidity_asset_id
                or not 0 < len(self.liquidity_tail_module) <= 16_384):
            raise TibetOfferVerificationError("invalid pair commitment")
        module = Program.from_bytes(self.liquidity_tail_module)
        if module.get_tree_hash() != self.liquidity_tail_module_hash:
            raise TibetOfferVerificationError("LP TAIL module does not match reviewed pin")
        # Tibet V2 pair_liquidity_tail_puzzle: TAIL.curry(singleton_struct).
        expected_asset = module.curry(
            (SINGLETON_MOD_HASH, (self.launcher_id, SINGLETON_LAUNCHER_HASH))
        ).get_tree_hash()
        if expected_asset != self.liquidity_asset_id:
            raise TibetOfferVerificationError("LP asset does not commit to the reviewed pair launcher")


@dataclass(frozen=True)
class TibetFundingCoin:
    """One independently observed, unspent coin for an authenticated wallet key."""
    coin: Coin
    public_key: G1Element
    asset_id: bytes32 | None
    lineage_proof: LineageProof | None = None

    def inner_puzzle(self) -> Program:
        if self.public_key == G1Element():
            raise TibetOfferVerificationError("identity funding public key is forbidden")
        return puzzle_for_pk(self.public_key)

    def validate(self) -> None:
        inner = self.inner_puzzle()
        if self.coin.parent_coin_info == bytes32.zeros or self.coin.amount == 0:
            raise TibetOfferVerificationError("funding coin must be a real positive removal")
        if self.asset_id is None:
            if self.lineage_proof is not None:
                raise TibetOfferVerificationError("XCH funding cannot carry CAT lineage")
            expected = inner.get_tree_hash()
        else:
            expected = construct_cat_puzzle(CAT_MOD, self.asset_id, inner).get_tree_hash()
            lineage = self.lineage_proof
            if (lineage is None or lineage.parent_name is None
                    or lineage.inner_puzzle_hash is None or lineage.amount is None):
                raise TibetOfferVerificationError("complete CAT parent lineage is required")
            parent_puzzle_hash = construct_cat_puzzle(
                CAT_MOD, self.asset_id, lineage.inner_puzzle_hash
            ).get_tree_hash_precalc(lineage.inner_puzzle_hash)
            if Coin(lineage.parent_name, parent_puzzle_hash, lineage.amount).name() != self.coin.parent_coin_info:
                raise TibetOfferVerificationError("CAT lineage does not match funding parent")
        if self.coin.puzzle_hash != expected:
            raise TibetOfferVerificationError("funding coin is not controlled by the reviewed wallet key and asset")


@dataclass(frozen=True)
class TibetOfferTerms:
    binding: TibetReleaseBinding
    pair: TibetPairCommitment
    operation_hash: bytes32
    action: str
    xch_mojos: int
    cat_mojos: int
    liquidity_mojos: int
    fee_mojos: int
    receive_public_key: G1Element
    not_before: int
    expires_at: int

    def validate(self, now: int) -> None:
        self.binding.validate()
        self.pair.validate()
        if self.action not in {"ADD", "REMOVE"}:
            raise TibetOfferVerificationError("only ADD and REMOVE liquidity are supported")
        if any(type(n) is not int or not 0 < n < 2**64 for n in (
            self.xch_mojos, self.cat_mojos, self.liquidity_mojos
        )) or type(self.fee_mojos) is not int or not 0 <= self.fee_mojos < 2**64:
            raise TibetOfferVerificationError("asset amounts and fee must be bounded integer mojos")
        if (self.operation_hash == bytes32.zeros or self.receive_public_key == G1Element()
                or type(self.not_before) is not int or type(self.expires_at) is not int
                or not 0 < self.not_before <= now < self.expires_at < 2**64
                or self.expires_at - self.not_before > MAX_LIFETIME_SECONDS):
            raise TibetOfferVerificationError("invalid operation, receiver or expired quote")


@dataclass(frozen=True)
class PreparedTibetOffer:
    """Immutable local review; keep server-side and never hydrate from a browser."""
    terms: TibetOfferTerms
    funding: tuple[TibetFundingCoin, ...]
    review_digest: bytes32
    unsigned_offer: bytes
    unsigned_wallet_bundle: bytes


def _asset_key(asset: bytes32 | None) -> str:
    return "xch" if asset is None else asset.hex()


def prepare_tibet_offer(
    terms: TibetOfferTerms, funding: tuple[TibetFundingCoin, ...], *, now: int,
) -> PreparedTibetOffer:
    """Build reviewable canonical spends, with no signing or external calls."""
    terms.validate(now)
    pair = terms.pair
    offered = ({None: terms.xch_mojos, pair.token_asset_id: terms.cat_mojos}
               if terms.action == "ADD" else {pair.liquidity_asset_id: terms.liquidity_mojos})
    requested = ({pair.liquidity_asset_id: terms.liquidity_mojos} if terms.action == "ADD"
                 else {None: terms.xch_mojos, pair.token_asset_id: terms.cat_mojos})
    required_assets = set(offered) | ({None} if terms.fee_mojos else set())
    if (not isinstance(funding, tuple) or len(funding) != len(required_assets)
            or {item.asset_id for item in funding} != required_assets
            or len({item.coin.name() for item in funding}) != len(funding)):
        raise TibetOfferVerificationError("exactly one funding coin per required asset is supported")
    for item in funding:
        item.validate()
        if item.public_key != terms.receive_public_key:
            raise TibetOfferVerificationError("funding and receipt keys must match the authenticated wallet")
        needed = offered.get(item.asset_id, 0) + (terms.fee_mojos if item.asset_id is None else 0)
        if needed > item.coin.amount:
            raise TibetOfferVerificationError("insufficient reviewed funding coin")
    funding = tuple(sorted(funding, key=lambda item: _asset_key(item.asset_id)))
    binding = terms.binding
    commitment = {
        "domain": "solslot.tibet.maker-offer.v1", "operation": terms.operation_hash.hex(),
        "environment": binding.environment, "network": binding.network,
        "deployment": binding.deployment_id, "release": binding.release_id,
        "source": binding.source_sha, "evidence": binding.evidence_sha256.hex(),
        "adapter": binding.adapter_version, "pair": pair.launcher_id.hex(),
        "pairPuzzle": pair.pair_puzzle_hash.hex(), "lpTailModule": pair.liquidity_tail_module_hash.hex(),
        "action": terms.action, "offered": {_asset_key(k): v for k, v in offered.items()},
        "requested": {_asset_key(k): v for k, v in requested.items()},
        "fee": terms.fee_mojos, "receiver": bytes(terms.receive_public_key).hex(),
        "notBefore": terms.not_before, "expires": terms.expires_at,
        "funding": [item.coin.name().hex() for item in funding],
    }
    digest = bytes32(sha256(json.dumps(commitment, sort_keys=True, separators=(",", ":")).encode()).digest())
    receiver = puzzle_for_pk(terms.receive_public_key).get_tree_hash()
    payments = {
        asset: [NotarizedPayment(receiver, uint64(amount), [bytes(receiver)], nonce=digest)]
        for asset, amount in requested.items()
    }
    drivers = {asset: PuzzleInfo({"type": "CAT", "tail": "0x" + asset.hex()})
               for asset in (pair.token_asset_id, pair.liquidity_asset_id)}
    payout_assertions = [item.to_program() for item in Offer.calculate_announcements(payments, drivers)]
    bundles = []
    for item in funding:
        inner = item.inner_puzzle()
        amount = offered.get(item.asset_id, 0)
        fee = terms.fee_mojos if item.asset_id is None else 0
        change = int(item.coin.amount) - amount - fee
        conditions = [
            *payout_assertions,
            [Op.ASSERT_SECONDS_ABSOLUTE, terms.not_before],
            [Op.ASSERT_BEFORE_SECONDS_ABSOLUTE, terms.expires_at],
            [Op.CREATE_COIN_ANNOUNCEMENT, digest],
            *[[Op.ASSERT_COIN_ANNOUNCEMENT, sha256(bytes(other.coin.name()) + digest).digest()]
              for other in funding],
        ]
        if amount:
            conditions.append([Op.CREATE_COIN, OFFER_MOD_HASH, amount])
        if change:
            conditions.append([Op.CREATE_COIN, inner.get_tree_hash(), change, [inner.get_tree_hash()]])
        if fee:
            conditions.append([Op.RESERVE_FEE, fee])
        solution = solution_for_conditions(conditions)
        if item.asset_id is None:
            bundles.append(WalletSpendBundle([make_spend(item.coin, inner, solution)], G2Element()))
        else:
            assert item.lineage_proof is not None
            bundles.append(unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(
                item.coin, item.asset_id, inner, solution, lineage_proof=item.lineage_proof,
            )]))
    bundle = WalletSpendBundle.aggregate(bundles)
    # Execute only locally constructed, bounded canonical spends. This also
    # catches a malformed lineage/condition before any wallet prompt.
    for spend in bundle.coin_spends:
        conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, MAX_SPEND_COST)
    offer = Offer(payments, bundle, drivers)
    if offer.get_offered_amounts() != offered:
        raise TibetOfferVerificationError("constructed offer asset balance mismatch")
    return PreparedTibetOffer(terms, funding, digest, bytes(offer), bytes(bundle))


def _validate_prepared(
    prepared: PreparedTibetOffer, active_binding: TibetReleaseBinding, observed_network: str, now: int,
) -> None:
    prepared.terms.validate(now)
    if active_binding != prepared.terms.binding or observed_network != active_binding.network:
        raise TibetOfferVerificationError("current release or wallet network changed since review")
    if prepare_tibet_offer(prepared.terms, prepared.funding, now=now) != prepared:
        raise TibetOfferVerificationError("stored review differs from its canonical terms and funding")


def verify_tibet_wallet_response(
    prepared: PreparedTibetOffer, wallet_bundle_bytes: bytes, *,
    active_binding: TibetReleaseBinding, observed_network: str, now: int,
) -> bytes:
    """Return a signed maker offer after exact-spend and BLS verification.

    Wallet response is an uncompressed serialized WalletSpendBundle containing
    the exact requested real removals plus its aggregate signature. It is not
    bech32/zip input, a venue JSON success flag, or an arbitrary accepted offer.
    The returned bytes must remain private until final aggregate review exists.
    """
    _validate_prepared(prepared, active_binding, observed_network, now)
    if type(wallet_bundle_bytes) is not bytes or not 96 <= len(wallet_bundle_bytes) <= MAX_OFFER_BYTES:
        raise TibetOfferVerificationError("invalid or oversized wallet spend bundle")
    try:
        returned = WalletSpendBundle.from_bytes(wallet_bundle_bytes)
    except Exception as exc:
        raise TibetOfferVerificationError("invalid wallet spend bundle encoding") from exc
    expected = WalletSpendBundle.from_bytes(prepared.unsigned_wallet_bundle)
    # Compare before running anything returned by the wallet. No alternate
    # puzzle, extra spend, fee, change, payout, nonce or expiry is accepted.
    if ([bytes(spend) for spend in returned.coin_spends]
            != [bytes(spend) for spend in expected.coin_spends]):
        raise TibetOfferVerificationError("wallet changed reviewed coin spends")
    pairs = []
    for spend, item in zip(expected.coin_spends, prepared.funding, strict=True):
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, MAX_SPEND_COST)
        spend_pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA[active_binding.network])
        key = calculate_synthetic_public_key(item.public_key, DEFAULT_HIDDEN_PUZZLE_HASH)
        if len(spend_pairs) != 1 or spend_pairs[0][0] != key:
            raise TibetOfferVerificationError("unexpected wallet signature conditions")
        pairs.extend(spend_pairs)
    if not AugSchemeMPL.aggregate_verify(
        [key for key, _ in pairs], [message for _, message in pairs], returned.aggregated_signature,
    ):
        raise TibetOfferVerificationError("wallet aggregate signature does not authorize every reviewed spend")
    reviewed_offer = Offer.from_bytes(prepared.unsigned_offer)
    signed = WalletSpendBundle(expected.coin_spends, returned.aggregated_signature)
    return bytes(Offer(reviewed_offer.requested_payments, signed, reviewed_offer.driver_dict))


def tibet_coin_spends_for_signing(
    prepared: PreparedTibetOffer, *,
    active_binding: TibetReleaseBinding, observed_network: str, now: int,
) -> list[dict]:
    """Match the existing ChiaCoinSpendForSigning wire contract, without calling it.

    Current Sage/Goby transports cast amounts to JavaScript Number. Reject coins
    beyond its exact integer range instead of signing silently rounded inputs.
    The frontend's independent local review/signing guard is still required.
    """
    _validate_prepared(prepared, active_binding, observed_network, now)
    bundle = WalletSpendBundle.from_bytes(prepared.unsigned_wallet_bundle)
    if any(spend.coin.amount > MAX_WALLET_SAFE_INTEGER for spend in bundle.coin_spends):
        raise TibetOfferVerificationError("current wallet transport cannot represent this coin amount exactly")
    return [{
        "coin": {
            "parentCoinInfo": "0x" + spend.coin.parent_coin_info.hex(),
            "puzzleHash": "0x" + spend.coin.puzzle_hash.hex(),
            "amount": str(spend.coin.amount),
        },
        "puzzleReveal": "0x" + bytes(spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(spend.solution).hex(),
    } for spend in bundle.coin_spends]


def verify_tibet_wallet_signature(
    prepared: PreparedTibetOffer, signature_hex: str, *,
    active_binding: TibetReleaseBinding, observed_network: str, now: int,
) -> bytes:
    """Verify existing Sage/Goby signature-only responses over canonical spends."""
    if type(signature_hex) is not str or not re.fullmatch(r"0x[0-9a-fA-F]{192}", signature_hex):
        raise TibetOfferVerificationError("wallet must return exactly one aggregate BLS signature")
    try:
        signature = G2Element.from_bytes(bytes.fromhex(signature_hex[2:]))
    except Exception as exc:
        raise TibetOfferVerificationError("invalid BLS signature encoding") from exc
    expected = WalletSpendBundle.from_bytes(prepared.unsigned_wallet_bundle)
    return verify_tibet_wallet_response(
        prepared, bytes(WalletSpendBundle(expected.coin_spends, signature)),
        active_binding=active_binding, observed_network=observed_network, now=now,
    )
