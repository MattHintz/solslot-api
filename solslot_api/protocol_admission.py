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


def require_absolute_admission(conditions, *, height, peak_time):
    """Check absolute timelocks against the primary's transaction-block clock.

    Native CLVM/signature validation extracts these conditions but does not
    evaluate them against the current chain. Do this before reserving a fee
    coin, and again immediately before push. Expiry reconciliation deliberately
    only extracts conditions and does not call this admission-only check.
    """
    if int(conditions.height_absolute) > height or int(conditions.seconds_absolute) > peak_time:
        raise ProtocolSubmissionError(
            'The network has not reached this transaction\'s start time yet. '
            'Approvals are retained; wait for the next block and check again. Nothing was sent.',
            code='CHAIN_WAIT_REQUIRED',
        )
    before_height = conditions.before_height_absolute
    before_time = conditions.before_seconds_absolute
    if ((before_height is not None and height >= int(before_height))
            or (before_time is not None and peak_time >= int(before_time))):
        raise ProtocolSubmissionError(
            'This saved transaction\'s chain window has expired. '
            'Check its saved status before preparing another submission. Nothing was sent.',
            code='CHAIN_WINDOW_EXPIRED',
        )


async def require_relative_admission(conditions, bundle, *, provider, height, peak_time):
    """Check relative delays against exact primary-node coin birth evidence.

    This runs before fee selection as well as before broadcast. Consensus still
    performs the authoritative check. Display clocks, cached receipts and a
    caller-supplied ratification date cannot satisfy a native activation delay.
    """
    import asyncio
    from chia_rs import Coin
    from chia_rs.sized_bytes import bytes32
    fields = ('height_relative', 'seconds_relative', 'before_height_relative',
              'before_seconds_relative', 'birth_height', 'birth_seconds')
    timed = [s for s in conditions.spends if any(getattr(s, name) is not None for name in fields)]
    if not timed: return
    inputs = {coin.name(): coin for coin in bundle.removals()}
    ephemeral = {coin.name() for coin in bundle.additions()}
    records = []
    try:
        async with asyncio.timeout(15):
            if (await provider.get_network_info_primary()).get('network_name') != 'testnet11':
                raise ValueError('relative admission requires the primary Testnet11 node')
            for spend in timed:
                identity = bytes32(spend.coin_id)
                if identity not in inputs or identity in ephemeral:
                    raise ValueError('relative timelocks require a confirmed input')
                raw = await provider.get_coin_record_by_name_primary('0x' + identity.hex())
                if (not isinstance(raw, dict) or Coin.from_json_dict(raw['coin']) != inputs[identity]
                        or type(raw.get('confirmed_block_index')) is not int
                        or not 0 < raw['confirmed_block_index'] <= height
                        or type(raw.get('timestamp')) is not int or not 0 < raw['timestamp'] <= peak_time
                        or type(raw.get('spent_block_index')) is not int or raw['spent_block_index'] != 0
                        or raw.get('spent', False) is not False):
                    raise ValueError('timelocked input is missing, spent or inconsistent')
                born_height, born_time = raw['confirmed_block_index'], raw['timestamp']
                if ((spend.birth_height is not None and int(spend.birth_height) != born_height)
                        or (spend.birth_seconds is not None and int(spend.birth_seconds) != born_time)):
                    raise ValueError('asserted birth differs from confirmed input')
                if ((spend.height_relative is not None and height < born_height + int(spend.height_relative))
                        or (spend.seconds_relative is not None and peak_time < born_time + int(spend.seconds_relative))):
                    raise ProtocolSubmissionError('The confirmed on-chain waiting period is still running. '
                        'The reviewed action is retained. Nothing was sent.', code='CHAIN_WAIT_REQUIRED')
                if ((spend.before_height_relative is not None and height >= born_height + int(spend.before_height_relative))
                        or (spend.before_seconds_relative is not None and peak_time >= born_time + int(spend.before_seconds_relative))):
                    raise ProtocolSubmissionError('This transaction\'s relative chain window has expired. '
                        'Reconcile the saved transaction before preparing another action.', code='CHAIN_WINDOW_EXPIRED')
                records.append((identity, raw))
            for identity, before in records:
                after = await provider.get_coin_record_by_name_primary('0x' + identity.hex())
                if after != before: raise ValueError('timelocked input changed during admission')
    except ProtocolSubmissionError:
        raise
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, TimeoutError) as exc:
        raise ProtocolSubmissionError('The primary node could not verify the saved input and its on-chain waiting period. '
            'Nothing was sent.', code='INPUT_STATE_CHANGED') from exc
