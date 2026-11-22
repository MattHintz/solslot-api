import time
from unittest.mock import AsyncMock

import pytest

from solslot_api.buyer_network_fees import buyer_fee_choices
from solslot_api.cost_fees import FeeAdviceError
from solslot_api.protocol_submission import ProtocolSubmissionError


def primary(**changes):
    now = int(time.time())
    reply = dict(full_node_synced=True, peak_height=123, mempool_size=200,
                 mempool_max_size=1200, last_peak_timestamp=now, node_time_utc=now,
                 estimates=[12, 24], target_times=[300, 60])
    return AsyncMock(get_fee_estimate=AsyncMock(return_value={**reply, **changes}))


@pytest.mark.asyncio
async def test_buyer_selects_exact_integer_fee_for_the_complete_bundle():
    node = primary()
    fees = await buyer_fee_choices(node, cost=100)
    node.get_fee_estimate.assert_awaited_once_with(cost=100, target_times=[300, 60], require_primary=True)
    assert fees.select('standard') == 12
    assert fees.select('priority') == 24
    assert fees.select('custom', 99) == 99
    for invalid in (True, -1, 1.5, '99', 2**64, None):
        with pytest.raises(FeeAdviceError):
            fees.select('custom', invalid)
    with pytest.raises(FeeAdviceError):
        fees.select('standard', 99)


@pytest.mark.asyncio
async def test_primary_node_may_sort_horizons_and_their_matching_estimates():
    fees = await buyer_fee_choices(primary(mempool_max_size=1000000000, target_times=[60, 300],
                                           estimates=[29081260, 751214]), cost=575262024)
    assert fees.select('standard') == 751214
    assert fees.select('priority') == 29081260


@pytest.mark.asyncio
async def test_equal_estimates_have_no_artificial_priority_surcharge():
    fees = await buyer_fee_choices(primary(estimates=[0, 0]), cost=100)
    assert fees.select('priority') == fees.select('standard') == 0


@pytest.mark.asyncio
async def test_full_mempool_applies_same_floor_to_preset_and_custom_fees():
    fees = await buyer_fee_choices(primary(mempool_size=1150), cost=100)
    assert fees.minimum_mojos == fees.select('standard') == fees.select('priority') == 501
    with pytest.raises(FeeAdviceError):
        fees.select('custom', 500)
    assert fees.select('custom', 502) == 502


@pytest.mark.asyncio
@pytest.mark.parametrize('changes', [
    {'full_node_synced': False}, {'last_peak_timestamp': 1}, {'target_times': [60, 60]},
    {'estimates': [1]}, {'estimates': [1, True]}, {'estimates': [-1, 1]},
])
async def test_unusable_node_quote_is_rejected(changes):
    with pytest.raises((FeeAdviceError, ProtocolSubmissionError)):
        await buyer_fee_choices(primary(**changes), cost=100)
