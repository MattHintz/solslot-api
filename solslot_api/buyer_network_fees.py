"""Buyer fee choices for a measured Chia spend, in integer mojos."""
from dataclasses import dataclass

from .cost_fees import FeeAdviceError, integer, validate_cost
from .protocol_admission import mempool_fee_floor, primary_admission_state


@dataclass(frozen=True)
class BuyerFeeChoices:
    cost: int
    peak_height: int
    minimum_mojos: int
    standard_mojos: int
    priority_mojos: int

    def select(self, choice: str, custom_mojos: int | None = None) -> int:
        if choice == 'custom':
            return integer(custom_mojos, 'custom fee', minimum=self.minimum_mojos)
        if custom_mojos is not None or choice not in ('standard', 'priority'):
            raise FeeAdviceError('Choose a valid network fee')
        return self.priority_mojos if choice == 'priority' else self.standard_mojos


async def buyer_fee_choices(provider, *, cost: int) -> BuyerFeeChoices:
    """Get both targets from the same synced node and mempool snapshot.

    The caller supplies the cost of the complete transaction, including buyer
    funding. A returned estimate cannot authorize a wallet spend.
    """
    validate_cost(cost)
    targets = [300, 60]
    reply = await provider.get_fee_estimate(cost=cost, target_times=targets, require_primary=True)
    height, used, capacity, _ = primary_admission_state(reply)
    estimates = reply.get('estimates')
    horizons = reply.get('target_times')
    if (not isinstance(horizons, list) or len(horizons) != len(targets)
            or not all(type(t) is int for t in horizons) or set(horizons) != set(targets)
            or not isinstance(estimates, list) or len(estimates) != len(targets)):
        raise FeeAdviceError('The Chia node returned incomplete network fee choices')
    minimum = mempool_fee_floor(cost, used, capacity)
    by_horizon = {t: integer(fee, 'network fee') for t, fee in zip(horizons, estimates, strict=True)}
    standard = max(minimum, by_horizon[300])
    return BuyerFeeChoices(cost, height, minimum, standard, max(standard, by_horizon[60]))
