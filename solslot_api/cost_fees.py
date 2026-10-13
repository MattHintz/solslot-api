"""Typed, cost-only fee advice. No remote quote authorizes a transaction.

Coinset contract: https://www.coinset.org/docs/api/full-node/tag/fees/POST/get_fee_tiers_by_cost
Capability results may be cached; prices are always obtained for the exact cost.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Literal

TierName = Literal['economy', 'standard', 'urgent']
MAX_COST = 11_000_000_000
MAX_FEE = 2**64 - 1


class FeeAdviceError(ValueError):
    pass


def integer(value, label: str, *, minimum=0, maximum=MAX_FEE) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise FeeAdviceError(f'Invalid {label} in cost fee response')
    return value


def validate_cost(cost: int) -> int:
    return integer(cost, 'cost', minimum=1, maximum=MAX_COST)


def tier_for_target(seconds: int) -> TierName:
    integer(seconds, 'target time', minimum=1, maximum=86400)
    return 'urgent' if seconds <= 60 else 'standard' if seconds <= 300 else 'economy'


@dataclass(frozen=True)
class CostFeeTier:
    name: TierName
    fee_mojos: int
    fee_rate: Decimal
    target_seconds: int


@dataclass(frozen=True)
class CostFeeAdvice:
    cost: int
    tier: CostFeeTier
    source: Literal['primary', 'coinset-advisory']
    received_at: float


def parse_tiers(response: dict, *, cost: int, target_seconds: int, source) -> CostFeeAdvice:
    validate_cost(cost)
    name = tier_for_target(target_seconds)
    if (not isinstance(response, dict) or response.get('success') is not True
            or response.get('error') not in (None, '')
            or integer(response.get('cost'), 'cost', minimum=1, maximum=MAX_COST) != cost):
        raise FeeAdviceError('Cost fee response does not match the requested cost')
    estimates = response.get('estimates')
    if not isinstance(estimates, dict) or not {'economy', 'standard', 'urgent'} <= estimates.keys():
        raise FeeAdviceError('Cost fee tiers are incomplete')
    parsed = {}
    for tier_name in ('economy', 'standard', 'urgent'):
        raw = estimates[tier_name]
        if not isinstance(raw, dict):
            raise FeeAdviceError('Cost fee tier is malformed')
        fee = integer(raw.get('fee'), 'fee', minimum=0 if tier_name == 'economy' else 1)
        target = integer(raw.get('target_time_secs'), 'target time', minimum=1, maximum=86400)
        rate = raw.get('fee_rate')
        if isinstance(rate, bool) or not isinstance(rate, (int, float)):
            raise FeeAdviceError('Invalid fee rate')
        try:
            rate = Decimal(str(rate))
        except InvalidOperation as exc:
            raise FeeAdviceError('Invalid fee rate') from exc
        if not rate.is_finite() or rate < 0:
            raise FeeAdviceError('Invalid fee rate')
        parsed[tier_name] = CostFeeTier(tier_name, fee, rate, target)
    return CostFeeAdvice(cost, parsed[name], source, time.time())


class CostFeeAdapter:
    """Probe the primary's routes explicitly, then use optional Coinset advice.

    Failure to read routes never means support. A malformed advertised primary
    result fails closed; it is not hidden by fallback. Coinset failure is optional
    because the caller must already have a valid primary admission/fee response.
    Only the integer cost is sent to the advisory provider.
    """
    def __init__(self, primary, fallback, *, monotonic=time.monotonic, fallback_timeout_seconds: float = 3.0):
        if not 0 < fallback_timeout_seconds <= 10:
            raise ValueError('advisory timeout must be positive and at most ten seconds')
        self.fallback_timeout_seconds = fallback_timeout_seconds
        self._fallback_retry_at = 0.0
        self.primary = primary
        self.fallback = fallback
        self.monotonic = monotonic
        self._capability: tuple[float, bool] | None = None
        self._probe_lock = asyncio.Lock()

    async def primary_supports_tiers(self) -> bool:
        async with self._probe_lock:
            if self._capability and self.monotonic() - self._capability[0] < 300:
                return self._capability[1]
            supported = False
            if self.primary is not None:
                try:
                    response = await self.primary.get_routes()
                    routes = response.get('routes')
                    supported = (response.get('success') is True and isinstance(routes, list)
                        and all(isinstance(route, str) for route in routes)
                        and '/get_fee_tiers_by_cost' in routes)
                except Exception:
                    # Older/filtered RPC services can lack get_routes itself.
                    supported = False
            self._capability = (self.monotonic(), supported)
            return supported

    async def quote(self, *, cost: int, target_seconds: int) -> CostFeeAdvice | None:
        validate_cost(cost)
        tier_for_target(target_seconds)
        if await self.primary_supports_tiers():
            response = await self.primary.get_fee_tiers_by_cost(cost=cost)
            return parse_tiers(response, cost=cost, target_seconds=target_seconds, source='primary')
        if self.fallback is None or self.monotonic() < self._fallback_retry_at:
            return None
        try:
            response = await asyncio.wait_for(
                self.fallback.get_fee_tiers_by_cost(cost=cost), self.fallback_timeout_seconds)
            return parse_tiers(response, cost=cost, target_seconds=target_seconds, source='coinset-advisory')
        except Exception:
            # Do not turn an optional provider outage into repeated long waits.
            # This caches availability only, never a price for a different cost.
            self._fallback_retry_at = self.monotonic() + 30
            return None
