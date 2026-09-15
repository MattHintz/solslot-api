"""Prove a launch is unusable before releasing its retained singleton claim."""
from __future__ import annotations

import time
import httpx
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.program import INFINITE_COST
from chia.types.condition_opcodes import ConditionOpcode
from solslot_puzzles.voucher_presale_v2 import series_terms_from_json, VoucherSeriesState
from solslot_puzzles.voucher_presale_v2_driver import (
    SeriesTransition, VoucherSeriesStateV2, build_voucher_series_phase_spend,
)


def launch_deadline(claim, coin, lineage):
    """Read the actual consensus deadline, not the signer's freshness window."""
    if claim.transition != int(SeriesTransition.LAUNCH):
        return None
    phase = build_voucher_series_phase_spend(
        terms=series_terms_from_json(claim.series_terms),
        state=VoucherSeriesStateV2(claim.series_sold_count, claim.series_redeemed_count,
                                  claim.series_refunded_count, VoucherSeriesState(claim.series_phase), claim.series_launched_at),
        series_coin=coin, series_lineage_proof=lineage, transition=SeriesTransition.LAUNCH,
        launch_anchor=claim.launch_anchor, signer_indices=(0, 1),
    )
    if '0x' + phase.validator_message.hex() != claim.validator_message or '0x' + coin.name().hex() != claim.series_coin_id:
        raise ValueError('Original campaign claim cannot be re-derived')
    spend = phase.series_spend
    conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, INFINITE_COST)
    before = conditions.get(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE, [])
    if len(before) != 1 or len(before[0].vars) != 1:
        raise ValueError('Campaign has no unambiguous consensus expiry')
    value = int.from_bytes(before[0].vars[0], 'big', signed=True)
    if value <= claim.launch_anchor:
        raise ValueError('Campaign consensus expiry is invalid')
    return value


def _hex(value):
    return '0x' + bytes32.from_hexstr(value).hex()


def _peak(info, response, network):
    chain = response['blockchain_state']
    peak = chain['peak']
    if (info.get('success') is not True or info['network_name'] != network or response.get('success') is not True
            or chain['sync']['synced'] is not True or chain['sync']['sync_mode'] is not False
            or type(peak['height']) is not int or peak['height'] < 3):
        raise ValueError('Campaign expiry requires the synced canonical network')
    return peak['height'], _hex(peak['header_hash'])


def expiry_requests(network, coin, deadline):
    """One proof algorithm for async coordinator and synchronous private signer.

    Require a stable tip, the exact mature unspent input and a hash-linked
    transaction clock at least three blocks deep. Wall time never frees a claim.
    """
    info = yield 'get_network_info', {}
    chain = yield 'get_blockchain_state', {}
    peak = _peak(info, chain, network)
    height, digest = peak
    timestamp = None
    for _ in range(128):
        response = yield 'get_block_record', {'header_hash': digest}
        block = response['block_record']
        if (response.get('success') is not True or type(block['height']) is not int
                or block['height'] != height or _hex(block['header_hash']) != digest):
            raise ValueError('Campaign expiry ancestor changed')
        value = block['timestamp']
        if height <= peak[0] - 2 and value is not None:
            if type(value) is not int or value <= 0:
                raise ValueError('Campaign expiry clock is invalid')
            timestamp = value
            break
        height -= 1
        digest = _hex(block['prev_hash'])
    if timestamp is None:
        raise ValueError('Campaign expiry exceeds the bounded ancestry window')
    record = yield 'get_coin_record_by_name', {'name': '0x' + coin.name().hex()}
    if (not record or Coin.from_json_dict(record['coin']) != coin
            or type(record['confirmed_block_index']) is not int
            or not 0 < record['confirmed_block_index'] <= peak[0] - 2
            or record.get('spent') is not False or record['spent_block_index'] != 0):
        raise ValueError('Campaign expiry input is not mature and unspent')
    fresh = yield 'get_blockchain_state', {}
    if _peak(info, fresh, network) != peak:
        raise ValueError('Campaign expiry tip changed; retry observation')
    if timestamp < deadline:
        return None
    return dict(peakHeight=peak[0], peakHash=peak[1], clockHeight=height, clockHash=digest,
                timestamp=timestamp, consensusDeadline=deadline, coinId='0x' + coin.name().hex())


async def prove_expiry(node, network, coin, deadline):
    proof = expiry_requests(network, coin, deadline)
    try:
        method, args = next(proof)
        while True:
            result = await getattr(node, method)(*args.values())
            method, args = proof.send(result)
    except StopIteration as done:
        return done.value


def independently_prove_expiry(settings, coin, deadline):
    proof = expiry_requests(settings.network, coin, deadline)
    cutoff = time.monotonic() + 20
    with httpx.Client(base_url=settings.coinset_base_url.rstrip('/'), timeout=2.0) as client:
        try:
            method, args = next(proof)
            while True:
                remaining = cutoff - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Campaign expiry proof timed out')
                response = client.post('/' + method, json=args, timeout=min(2.0, remaining))
                response.raise_for_status()
                result = response.json()
                if method == 'get_coin_record_by_name':
                    if result.get('success') is not True:
                        raise ValueError('Campaign expiry coin observation failed')
                    result = result.get('coin_record')
                method, args = proof.send(result)
        except StopIteration as done:
            return done.value
