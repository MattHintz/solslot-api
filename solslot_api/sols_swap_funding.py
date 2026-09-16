"""Exact private fee holds for unsigned Sols swap review.

Only the fee coin is reserved before owner authorization. Its signature never
leaves the private hold until that hold is atomically promoted to a signed
execution. This permits expiry of an unsealed hold, never of an execution.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from time import time

from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode as Op
from chia_rs import Coin, G2Element, SpendBundle

from .chia_provider import ChiaProviderError
from .protocol_submission import PreparedProtocolBundle, ProtocolSubmissionError

COST_UPPER_BOUND = int(DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return "0x" + hashlib.sha256(canonical(value).encode()).hexdigest()


def hx(value):
    return "0x" + bytes(value).hex()


def funding_identity(submitter, evidence, binding, operation, expires):
    if (submitter.faucet.network != "testnet11" or binding["network"] != "testnet11"
            or not submitter.policy.enabled):
        raise ValueError("swap funding requires the enabled Testnet11 policy")
    for value in (submitter.policy.minimum_mojos, submitter.policy.maximum_mojos,
                  submitter.policy.maximum_funding_coin_mojos, submitter.policy.target_seconds):
        if type(value) is not int or not 0 < value < 2**64:
            raise ValueError("swap funding policy is invalid")
    if (submitter.policy.minimum_mojos > submitter.policy.maximum_mojos
            or type(submitter.policy.maximum_backing_mojos) is not int
            or not 0 <= submitter.policy.maximum_backing_mojos < 2**64
            or not 0 <= evidence.required_backing_mojos <= submitter.policy.maximum_backing_mojos):
        raise ValueError("swap backing or fee exceeds the funding policy")
    return dict(operationHash=operation, protocolCandidateHash=hx(evidence.candidate_hash),
                binding=binding, quoteExpiresAt=expires, policy=asdict(submitter.policy),
                feeTillPuzzleHash=hx(submitter.faucet.address_puzzle_hash),
                backingMojos=str(evidence.required_backing_mojos), costUpperBound=COST_UPPER_BOUND)


def funding_conditions(evidence, coin, fee, change_hash, expires):
    change = int(coin.amount) - fee - evidence.required_backing_mojos
    if change < 0 or coin.puzzle_hash != change_hash:
        raise ValueError("reserved funding coin cannot cover exact backing and fee")
    result = [[Op.RESERVE_FEE, fee], [Op.ASSERT_BEFORE_SECONDS_ABSOLUTE, expires]]
    if change:
        result.append([Op.CREATE_COIN, change_hash, change])
    for spend in evidence.coin_spends:
        result.append([Op.ASSERT_CONCURRENT_SPEND, spend.coin.name()])
        # The canonical unsigned EVM vault cannot execute yet. Bind all inputs
        # and the executable protocol commitments, without faking its signature.
        if spend.coin.name() == evidence.vault_coin_id:
            continue
        conditions = conditions_dict_for_solution(Program.from_bytes(bytes(spend.puzzle_reveal)),
            Program.from_bytes(bytes(spend.solution)), COST_UPPER_BOUND)
        for create, assertion, origin in (
            (Op.CREATE_COIN_ANNOUNCEMENT, Op.ASSERT_COIN_ANNOUNCEMENT, spend.coin.name()),
            (Op.CREATE_PUZZLE_ANNOUNCEMENT, Op.ASSERT_PUZZLE_ANNOUNCEMENT, spend.coin.puzzle_hash),
        ):
            for condition in conditions.get(create, []):
                result.append([assertion, hashlib.sha256(bytes(origin) + condition.vars[0]).digest()])
    return Program.to(result)


def funding_spend(submitter, evidence, coin, fee, expires):
    conditions = funding_conditions(evidence, coin, fee, submitter.faucet.address_puzzle_hash, expires)
    return make_spend(coin, submitter.faucet.key.puzzle,
                      Program.to([0, Program.to((1, conditions)), Program.to(0)])), conditions


def public_spend(spend):
    return dict(coinId=hx(spend.coin.name()), coin=dict(parentCoinInfo=hx(spend.coin.parent_coin_info),
        puzzleHash=hx(spend.coin.puzzle_hash), amount=str(spend.coin.amount)),
        puzzleReveal=hx(spend.puzzle_reveal), solution=hx(spend.solution))


def validate_private_hold(payload):
    review = payload["review"]
    if payload["reservationHash"] != digest(review):
        raise ValueError("swap funding reservation identity changed")
    bundle = SpendBundle.from_json_dict(payload["fundingBundle"])
    if len(bundle.coin_spends) != 1 or bundle.aggregated_signature == G2Element():
        raise ValueError("private swap funding signature is missing")
    spend = bundle.coin_spends[0]
    if (review["fundingCoinSpend"] != public_spend(spend)
            or review["feeCoinId"] != hx(spend.coin.name())
            or review["ownerAuthorization"] != "PENDING"
            or review["status"] != "FUNDING_RESERVED" or review["consensusValidated"] is not False):
        raise ValueError("swap funding spend or pending state changed")
    for field in ("feeMojos", "backingMojos"):
        value = review[field]
        if type(value) is not str or not value.isascii() or not value.isdecimal() or str(int(value)) != value:
            raise ValueError("swap funding amount is not canonical")
    return bundle


async def require_live_fee(submitter, coin):
    raw = await submitter.provider.get_coin_record_by_name_primary(hx(coin.name()))
    if (not isinstance(raw, dict) or type(raw.get("confirmed_block_index")) is not int
            or raw["confirmed_block_index"] <= 0 or type(raw.get("spent_block_index")) is not int
            or raw["spent_block_index"] != 0
            or raw.get("spent", False) is not False or Coin.from_json_dict(raw["coin"]) != coin):
        raise ValueError("reserved funding requires the exact confirmed unspent primary coin")
    if await submitter.provider.get_mempool_items_by_coin_name(hx(coin.name())):
        raise ValueError("reserved funding coin already has a pending spend")


def require_hold(store, identity, reservation_hash=None):
    payload = store.funding(identity["operationHash"])
    if payload is None:
        raise ValueError("Prepare exact swap funding before owner signing")
    review = payload["review"]
    if (any(review.get(k) != v for k, v in identity.items())
            or (reservation_hash is not None and reservation_hash != payload["reservationHash"])):
        raise ValueError("swap funding review no longer matches the operation, session, release or policy")
    validate_private_hold(payload)
    return payload


async def reserve_funding(submitter, store, evidence, binding, operation, expires, authorize):
    identity = funding_identity(submitter, evidence, binding, operation, expires)
    async with submitter.funding_guard:
        if authorize() != binding:
            raise ValueError("swap funding authorization changed")
        record = store.get(operation)
        if record is not None and record.transaction_id is not None:
            raise ValueError("swap already has an exact execution; recover the retained operation")
        existing = store.funding(operation)
        if existing is not None:
            payload = require_hold(store, identity)
            await require_live_fee(submitter, validate_private_hold(payload).coin_spends[0].coin)
        else:
            fee = await estimate_swap_fee(submitter)
            if (authorize() != binding or expires <= time()
                    or funding_identity(submitter, evidence, binding, operation, expires) != identity):
                raise ValueError("swap funding authorization or quote expired")
            store.supersede_unsealed_funding(operation, binding["vaultLauncherId"])
            coin = await submitter._select_fee_coin(fee + evidence.required_backing_mojos,
                excluded_coin_ids={bytes(s.coin.name()) for s in evidence.coin_spends}, selection_purpose=None)
            await require_live_fee(submitter, coin)
            if (authorize() != binding or expires <= time()
                    or funding_identity(submitter, evidence, binding, operation, expires) != identity):
                raise ValueError("swap funding authorization or quote expired")
            spend, conditions = funding_spend(submitter, evidence, coin, fee, expires)
            private_bundle = SpendBundle([spend], G2Element.from_bytes(
                submitter.faucet.sign_delegated_spend(coin, conditions)))
            review = dict(schemaVersion=1, status="FUNDING_RESERVED", **identity,
                feeCoinId=hx(coin.name()), feeMojos=str(fee), feeTargetSeconds=submitter.policy.target_seconds,
                fundingCoinSpend=public_spend(spend), ownerAuthorization="PENDING", consensusValidated=False)
            payload = dict(review=review, reservationHash=digest(review), fundingBundle=private_bundle.to_json_dict())
            store.reserve_funding(operation, payload)
        if (authorize() != binding
                or funding_identity(submitter, evidence, binding, operation, expires) != identity):
            raise ValueError("swap funding authorization changed")
        return {**payload["review"], "reservationHash": payload["reservationHash"]}


async def estimate_swap_fee(submitter):
    # Never disclose a signed bundle to an estimation RPC before promotion.
    response = await submitter.provider.get_fee_estimate(target_times=[submitter.policy.target_seconds],
        cost=COST_UPPER_BOUND, require_primary=True)
    estimates = response.get("estimates")
    if (response.get("target_times") != [submitter.policy.target_seconds]
            or not isinstance(estimates, list) or len(estimates) != 1
            or type(estimates[0]) is not int or estimates[0] < 0):
        raise ValueError("primary cost fee estimate is malformed")
    fee = max(estimates[0], submitter.policy.minimum_mojos)
    if fee > submitter.policy.maximum_mojos:
        raise ValueError("conservative swap fee exceeds configured cap")
    return fee


def normalize_vault(spend):
    outer = list(Program.from_bytes(bytes(spend.solution)).as_iter())
    inner = list(outer[2].as_iter())
    auth = list(inner[4].as_iter())
    if len(outer) != 3 or len(inner) != 5 or len(auth) != 5:
        raise ValueError("unexpected vault authorization shape")
    auth[2] = Program.to(b"")
    inner[4] = Program.to(auth)
    outer[2] = Program.to(inner)
    return make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(outer))


async def submit_reserved_funding(submitter, store, evidence, identity, reservation_hash,
                                  protocol_bundle, authorize, before_push):
    if not reservation_hash:
        raise ValueError("The exact funding reservation hash is required before completion")
    async with submitter.funding_guard:
        if funding_identity(submitter, evidence, identity["binding"], identity["operationHash"], identity["quoteExpiresAt"]) != identity:
            raise ValueError("swap funding policy changed before dispatch")
        payload = require_hold(store, identity, reservation_hash)
        private = validate_private_hold(payload)
        fee = int(payload["review"]["feeMojos"])
        expected, _ = funding_spend(submitter, evidence, private.coin_spends[0].coin, fee, identity["quoteExpiresAt"])
        if expected != private.coin_spends[0]:
            raise ValueError("reserved funding spend differs from the canonical candidate")
        normalized = [normalize_vault(s) if s.coin.name() == evidence.vault_coin_id else s
                      for s in protocol_bundle.coin_spends]
        if (len(normalized) != len(evidence.coin_spends)
                or {bytes(s) for s in normalized} != {bytes(s) for s in evidence.coin_spends}):
            raise ValueError("signed protocol differs from reserved unsigned candidate")
        aggregate = SpendBundle.aggregate([SpendBundle.from_bytes(bytes(protocol_bundle)), private])
        await require_live_fee(submitter, private.coin_spends[0].coin)
        if await estimate_swap_fee(submitter) > fee:
            raise ValueError("reserved fee is insufficient; prepare a new funding review")
        if (authorize() != identity["binding"]
                or funding_identity(submitter, evidence, identity["binding"], identity["operationHash"], identity["quoteExpiresAt"]) != identity):
            raise ValueError("swap funding authorization changed before dispatch")
        prepared = PreparedProtocolBundle(aggregate, fee, payload["review"]["feeCoinId"], evidence.required_backing_mojos)
        # This hook validates the full signed consensus and atomically promotes
        # the still-current hold before any byte can reach a provider.
        await before_push(prepared)
        try:
            result = await submitter.provider.push_tx_confirmed_in_primary_mempool(aggregate.to_json_dict(),
                required_coin_id=prepared.fee_coin_id, required_spend_bundle_id=prepared.spend_bundle_id,
                timeout_seconds=submitter.policy.mempool_timeout_seconds,
                poll_seconds=submitter.policy.mempool_poll_seconds)
        except ChiaProviderError as exc:
            raise ProtocolSubmissionError(str(exc), submission_attempted=True) from exc
    return {**prepared.to_json(), "feeTargetSeconds": payload["review"]["feeTargetSeconds"],
            "submissionProvider": result["provider"], "mempoolObservedAt": result["observed_at"]}
