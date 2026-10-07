"""Primary-node admission checks; no estimates from a fallback authorize writes."""
from __future__ import annotations

import time

from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia_rs import MEMPOOL_MODE, get_flags_for_height_and_constants, validate_clvm_and_signature

from .faucet import AGG_SIG_ME_DATA
from .protocol_submission import ProtocolSubmissionError


def primary_admission_state(response):
    def integer(key, minimum=0):
        value = response.get(key)
        if type(value) is not int or value < minimum:
            raise ProtocolSubmissionError('Primary network admission check is incomplete; nothing was sent')
        return value
    if not isinstance(response, dict) or response.get('full_node_synced') is not True:
        raise ProtocolSubmissionError('Primary node is not synced; nothing was sent')
    height = integer('peak_height', 1)
    used, capacity = integer('mempool_size'), integer('mempool_max_size', 1)
    peak_time = integer('last_peak_timestamp', 1)
    node_time = integer('node_time_utc', 1)
    now = int(time.time())
    if used > capacity or not 0 <= now - peak_time <= 600 or abs(now - node_time) > 60:
        raise ProtocolSubmissionError('Primary network check is stale or invalid; nothing was sent')
    return height, used, capacity, peak_time


def admission_conditions(bundle, height, network):
    if network != 'testnet11':
        raise ProtocolSubmissionError('Native admission repair is restricted to Testnet11')
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=AGG_SIG_ME_DATA[network])
    flags = MEMPOOL_MODE | get_flags_for_height_and_constants(height, constants)
    try:
        conditions, _, _ = validate_clvm_and_signature(bundle, constants.MAX_BLOCK_COST_CLVM, constants, flags)
    except Exception as exc:
        raise ProtocolSubmissionError('Protocol failed native cost/signature validation; nothing was sent') from exc
    if not 0 < int(conditions.cost) <= constants.MAX_BLOCK_COST_CLVM:
        raise ProtocolSubmissionError('Protocol native cost is outside the consensus bound')
    return conditions
