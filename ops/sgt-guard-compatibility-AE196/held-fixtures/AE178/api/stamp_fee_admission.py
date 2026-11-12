"""Testnet11 identity-only admission pricing, within the existing fee policy.

Native fee estimates are historical predictions. A full mempool additionally
requires five mojos per cost unit. Price the entire validated bundle against
that floor, never raising the configured cap or changing a protocol spend.
"""
from __future__ import annotations

import logging
from dataclasses import replace

from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia_rs import MEMPOOL_MODE, get_flags_for_height_and_constants, validate_clvm_and_signature

from .chia_provider import ChiaProviderError
from .faucet import AGG_SIG_ME_DATA
from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError

logger = logging.getLogger(__name__)
BUSY_MESSAGE = (
    "Chia Testnet11 is busy. Your proof and wallet approval are saved. "
    "Check status or resume the saved approval shortly; no new scan or wallet signature is needed. "
    "Solslot will keep the existing network-fee limit."
)


class StampNetworkBusy(ProtocolSubmissionError):
    """Retained authorization can be reconciled/resumed; never bypass its cap."""


def _integer(response, key, *, minimum=0):
    value = response.get(key)
    if type(value) is not int or value < minimum:
        raise ProtocolSubmissionError('Primary stamp admission quote is incomplete or invalid')
    return value


def native_stamp_cost(bundle, height):
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=AGG_SIG_ME_DATA['testnet11'])
    flags = MEMPOOL_MODE | get_flags_for_height_and_constants(height, constants)
    try:
        conditions, _, _ = validate_clvm_and_signature(bundle, constants.MAX_BLOCK_COST_CLVM, constants, flags)
    except Exception as exc:
        raise ProtocolSubmissionError('Identity stamp failed native cost/signature validation; nothing was sent') from exc
    cost = int(conditions.cost)
    if not 0 < cost <= constants.MAX_BLOCK_COST_CLVM:
        raise ProtocolSubmissionError('Identity stamp has an invalid native cost')
    return cost


class StampFeeSubmitter(ProtocolBundleSubmitter):
    """Used only by submit_funded_stamp; other protocol fees are unchanged."""

    async def _estimate_fee(self, bundle):
        if self.faucet.network != 'testnet11' or not self.policy.enabled:
            raise ProtocolSubmissionError('Stamp admission pricing requires funded Testnet11')
        try:
            response = await self.provider.get_fee_estimate(
                target_times=[self.policy.target_seconds], spend_bundle=bundle.to_json_dict(), require_primary=True)
        except ChiaProviderError as exc:
            raise ProtocolSubmissionError('The Chia network check is temporarily unavailable; your approval is saved') from exc
        if not isinstance(response, dict):
            raise ProtocolSubmissionError('Primary stamp admission quote is invalid')
        estimates = response.get('estimates')
        if (not isinstance(estimates, list) or len(estimates) != 1
                or type(estimates[0]) is not int or estimates[0] < 0
                or response.get('target_times') != [self.policy.target_seconds]
                or response.get('full_node_synced') is not True):
            raise ProtocolSubmissionError('Primary stamp admission quote is incomplete or invalid')
        height = _integer(response, 'peak_height', minimum=1)
        used = _integer(response, 'mempool_size')
        capacity = _integer(response, 'mempool_max_size', minimum=1)
        if used > capacity:
            raise ProtocolSubmissionError('Primary stamp mempool capacity is invalid')
        if not 10_000 <= self.policy.estimate_buffer_bps <= 30_000:
            raise ProtocolSubmissionError('Fee estimate buffer is outside its approved bound')
        cost = native_stamp_cost(bundle, height)
        predictive = (estimates[0] * self.policy.estimate_buffer_bps + 9_999) // 10_000
        # The estimator buffer applies to its prediction, not an additional
        # multiplier on Chia's fixed admission floor. One mojo gives a strict
        # margin above that floor; the node still owns actual admission.
        admission = 5 * cost + 1 if used + cost > capacity else 0
        fee = max(predictive, self.policy.minimum_mojos, admission)
        logger.info('stamp_fee_quote bundle_id=%s cost=%d used=%d capacity=%d predictive_mojos=%d admission_mojos=%d fee_mojos=%d cap_mojos=%d',
            '0x' + bundle.name().hex(), cost, used, capacity, predictive, admission, fee, self.policy.maximum_mojos)
        if fee > self.policy.maximum_mojos:
            raise StampNetworkBusy(BUSY_MESSAGE)
        return fee


async def check_saved_stamp_admission(submitter, document):
    """A read-only preflight also catches pool growth after fee convergence."""
    from chia_rs import SpendBundle
    quote = StampFeeSubmitter(provider=submitter.provider, faucet=submitter.faucet,
        policy=replace(submitter.policy, target_seconds=60))
    required = await quote._estimate_fee(SpendBundle.from_json_dict(document['spendBundle']))
    if required > int(document['feeMojos']):
        # No replacement within a live window, no fee bump, no extra signature.
        raise StampNetworkBusy(BUSY_MESSAGE)
