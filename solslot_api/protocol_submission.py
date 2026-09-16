"""Mempool-aware Chia submission funded by the existing server fee till."""
from __future__ import annotations

import asyncio
import inspect
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from chia.types.blockchain_format.program import Program, INFINITE_COST
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.condition_opcodes import ConditionOpcode
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle

from .chia_provider import ChiaProvider, ChiaProviderError
from .faucet import Faucet

CREATE_COIN = 51
RESERVE_FEE = 52


class ProtocolSubmissionError(RuntimeError):
    """A server-funded protocol bundle cannot be safely submitted."""

    def __init__(
        self,
        message: str,
        *,
        submission_attempted: bool = False,
    ) -> None:
        super().__init__(message)
        self.submission_attempted = submission_attempted


@dataclass(frozen=True)
class ProtocolFeePolicy:
    enabled: bool = False
    target_seconds: int = 300
    minimum_mojos: int = 1
    maximum_mojos: int = 10_000_000
    maximum_funding_coin_mojos: int = 10_000_000
    maximum_backing_mojos: int = 0
    mempool_timeout_seconds: float = 20.0
    mempool_poll_seconds: float = 0.5


@dataclass(frozen=True)
class PreparedProtocolBundle:
    bundle: SpendBundle
    fee_mojos: int
    fee_coin_id: str
    backing_mojos: int = 0

    @property
    def spend_bundle_id(self) -> str:
        return "0x" + self.bundle.name().hex()

    def to_json(self) -> dict[str, Any]:
        return {
            "spendBundleId": self.spend_bundle_id,
            "feeMojos": str(self.fee_mojos),
            "feeCoinId": self.fee_coin_id,
            "backingMojos": str(self.backing_mojos),
            "spendBundle": self.bundle.to_json_dict(),
        }


class ProtocolBundleSubmitter:
    """Add one bounded fee-till spend and prove local mempool propagation."""

    def __init__(
        self,
        *,
        provider: ChiaProvider,
        faucet: Faucet,
        policy: ProtocolFeePolicy,
    ) -> None:
        self.provider = provider
        self.faucet = faucet
        self.policy = policy
        self._lock = asyncio.Lock()
        self._fee_coin_reservation_sources: list[
            Callable[[], Iterable[str | bytes]]
        ] = []

    @property
    def funding_guard(self) -> asyncio.Lock:
        """Shared coordinator guard for voucher launcher and fee-till selection."""
        return self._lock

    def reserved_funding_coin_ids(self) -> set[bytes]:
        return self._reserved_fee_coin_ids()

    def add_fee_coin_reservation_source(
        self,
        source: Callable[[], Iterable[str | bytes]],
    ) -> None:
        """Exclude fee coins sealed in durable exact executions."""

        if source not in self._fee_coin_reservation_sources:
            self._fee_coin_reservation_sources.append(source)

    async def submit(
        self,
        protocol_bundle_json: dict[str, Any],
        *,
        before_push: Callable[
            [PreparedProtocolBundle], Awaitable[None] | None
        ]
        | None = None,
        selection_purpose: str | None = None,
        expected_backing_mojos: int = 0,
    ) -> dict[str, Any]:
        # Production keeps one worker for faucet-backed writes. Holding this
        # lock until mempool observation prevents reuse of an unconfirmed coin.
        async with self._lock:
            prepared = await self._prepare_locked(
                protocol_bundle_json, selection_purpose=selection_purpose,
                expected_backing_mojos=expected_backing_mojos
            )
            if before_push is not None:
                callback_result = before_push(prepared)
                if inspect.isawaitable(callback_result):
                    await callback_result
            try:
                mempool = await self.provider.push_tx_confirmed_in_primary_mempool(
                    prepared.bundle.to_json_dict(),
                    required_coin_id=prepared.fee_coin_id,
                    required_spend_bundle_id=prepared.spend_bundle_id,
                    timeout_seconds=self.policy.mempool_timeout_seconds,
                    poll_seconds=self.policy.mempool_poll_seconds,
                )
            except ChiaProviderError as exc:
                raise ProtocolSubmissionError(
                    str(exc),
                    submission_attempted=True,
                ) from exc

        return {
            "schemaVersion": 1,
            "status": "MEMPOOL",
            "network": self.faucet.network,
            **prepared.to_json(),
            "feeTargetSeconds": self.policy.target_seconds,
            "feeTillPuzzleHash": self.faucet.address_hex,
            "submissionProvider": mempool["provider"],
            "mempoolObservedAt": mempool["observed_at"],
            "ambiguousPushRecovered": bool(mempool["ambiguous_push"]),
        }

    async def prepare_and_dispatch(
        self,
        protocol_bundle_json: dict[str, Any],
        dispatcher: Callable[
            [PreparedProtocolBundle],
            Awaitable[Mapping[str, Any] | None],
        ],
        *,
        selection_purpose: str | None = None,
    ) -> dict[str, Any]:
        """Fund, persist, and hand one exact bundle to its sole executor."""

        async with self._lock:
            prepared = await self._prepare_locked(
                protocol_bundle_json, selection_purpose=selection_purpose
            )
            try:
                dispatch_result = await dispatcher(prepared)
            except ProtocolSubmissionError:
                raise
            except Exception as exc:
                raise ProtocolSubmissionError(
                    "exact protocol executor did not accept the funded bundle",
                    submission_attempted=True,
                ) from exc
        return {
            "schemaVersion": 2,
            "status": "DISPATCHED",
            "network": self.faucet.network,
            **prepared.to_json(),
            "feeTargetSeconds": self.policy.target_seconds,
            "feeTillPuzzleHash": self.faucet.address_hex,
            "dispatchResult": dict(dispatch_result or {}),
        }

    async def reconcile_reserved(
        self,
        reservation: Mapping[str, Any],
        *,
        before_push: Callable[[], Awaitable[None] | None] | None = None,
    ) -> dict[str, Any]:
        """Idempotently replay one exact durable bundle after an unknown push."""

        try:
            bundle_json = reservation["spendBundle"]
            bundle = SpendBundle.from_json_dict(bundle_json)
            spend_bundle_id = "0x" + bytes(bundle.name()).hex()
            expected_bundle_id = str(reservation["spendBundleId"])
            fee_coin_id = str(reservation["feeCoinId"])
            fee_mojos = int(str(reservation["feeMojos"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolSubmissionError(
                "durable protocol reservation is malformed"
            ) from exc
        if spend_bundle_id != expected_bundle_id:
            raise ProtocolSubmissionError(
                "durable protocol reservation changed its bundle id"
            )
        removal_ids = {"0x" + coin.name().hex() for coin in bundle.removals()}
        if fee_coin_id not in removal_ids:
            raise ProtocolSubmissionError(
                "durable protocol reservation fee coin is not an input"
            )
        if fee_mojos < 0 or fee_mojos > self.policy.maximum_mojos:
            raise ProtocolSubmissionError(
                "durable protocol reservation fee is outside policy"
            )
        async with self._lock:
            if before_push is not None:
                callback_result = before_push()
                if inspect.isawaitable(callback_result):
                    await callback_result
            try:
                mempool = await self.provider.push_tx_confirmed_in_primary_mempool(
                    dict(bundle_json),
                    required_coin_id=fee_coin_id,
                    required_spend_bundle_id=spend_bundle_id,
                    timeout_seconds=self.policy.mempool_timeout_seconds,
                    poll_seconds=self.policy.mempool_poll_seconds,
                )
            except ChiaProviderError as exc:
                raise ProtocolSubmissionError(
                    str(exc), submission_attempted=True
                ) from exc
        return {
            "schemaVersion": 1,
            "status": "MEMPOOL_RECONCILED",
            "network": self.faucet.network,
            "spendBundleId": spend_bundle_id,
            "feeMojos": str(fee_mojos),
            "feeCoinId": fee_coin_id,
            "spendBundle": dict(bundle_json),
            "feeTargetSeconds": self.policy.target_seconds,
            "feeTillPuzzleHash": self.faucet.address_hex,
            "submissionProvider": mempool["provider"],
            "mempoolObservedAt": mempool["observed_at"],
            "ambiguousPushRecovered": True,
        }

    async def _prepare_locked(
        self,
        protocol_bundle_json: dict[str, Any],
        *,
        selection_purpose: str | None = None,
        expected_backing_mojos: int = 0,
    ) -> PreparedProtocolBundle:
        if not self.policy.enabled:
            raise ProtocolSubmissionError("protocol fee funding is disabled")
        try:
            protocol_bundle = SpendBundle.from_json_dict(protocol_bundle_json)
        except Exception as exc:
            raise ProtocolSubmissionError("protocol spend bundle is malformed") from exc
        if not protocol_bundle.coin_spends:
            raise ProtocolSubmissionError("protocol spend bundle has no coin spends")
        try:
            existing_fee = sum(
                int(coin.amount) for coin in protocol_bundle.removals()
            ) - sum(int(coin.amount) for coin in protocol_bundle.additions())
        except Exception as exc:
            raise ProtocolSubmissionError(
                "protocol spend bundle conditions cannot be evaluated"
            ) from exc
        if (type(expected_backing_mojos) is not int or expected_backing_mojos < 0
                or expected_backing_mojos > self.policy.maximum_backing_mojos):
            raise ProtocolSubmissionError("issuance backing exceeds configured cap or is invalid")
        if expected_backing_mojos and existing_fee != -expected_backing_mojos:
            raise ProtocolSubmissionError("bundle deficit does not match authorized issuance backing")
        if not expected_backing_mojos and existing_fee != 0:
            raise ProtocolSubmissionError(
                "protocol spend bundle must not carry a separate user-funded fee"
            )
        # The node prevalidates fee-estimate bundles and rejects unfunded
        # issuance as MintingCoin. Estimate only after attaching its backing.
        preliminary_fee = (self.policy.minimum_mojos if expected_backing_mojos
                           else await self._estimate_fee(protocol_bundle))
        protocol_input_ids = {
            bytes(coin.name()) for coin in protocol_bundle.removals()
        }
        fee_coin = await self._select_fee_coin(
            preliminary_fee + expected_backing_mojos,
            excluded_coin_ids=protocol_input_ids,
            selection_purpose=selection_purpose,
        )
        final_bundle, fee, fee_coin = await self._converge_fee(
            protocol_bundle,
            fee_coin,
            preliminary_fee,
            selection_purpose=selection_purpose,
            backing_mojos=expected_backing_mojos,
            backing_conditions=self._backing_conditions(protocol_bundle) if expected_backing_mojos else (),
        )
        return PreparedProtocolBundle(
            bundle=final_bundle,
            fee_mojos=fee,
            fee_coin_id="0x" + fee_coin.name().hex(),
            backing_mojos=expected_backing_mojos,
        )

    @staticmethod
    def _backing_conditions(bundle: SpendBundle) -> tuple[Program, ...]:
        """Tie the subsidy to every protocol input and its emitted commitments."""
        conditions = []
        announcements = 0
        for spend in bundle.coin_spends:
            conditions.append(Program.to([ConditionOpcode.ASSERT_CONCURRENT_SPEND, spend.coin.name()]))
            emitted = conditions_dict_for_solution(
                Program.from_bytes(bytes(spend.puzzle_reveal)),
                Program.from_bytes(bytes(spend.solution)), INFINITE_COST,
            )
            for create, assertion, origin in (
                (ConditionOpcode.CREATE_COIN_ANNOUNCEMENT, ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT, spend.coin.name()),
                (ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT, ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT, spend.coin.puzzle_hash),
            ):
                for condition in emitted.get(create, []):
                    announcements += 1
                    digest = hashlib.sha256(bytes(origin) + condition.vars[0]).digest()
                    conditions.append(Program.to([assertion, digest]))
        if not announcements:
            raise ProtocolSubmissionError("issuance backing requires protocol announcement commitments")
        return tuple(conditions)

    async def _estimate_fee(self, bundle: SpendBundle) -> int:
        try:
            response = await self.provider.get_fee_estimate(
                target_times=[self.policy.target_seconds],
                spend_bundle=bundle.to_json_dict(),
                require_primary=True,
            )
        except ChiaProviderError as exc:
            raise ProtocolSubmissionError(str(exc)) from exc
        estimates = response.get("estimates")
        target_times = response.get("target_times")
        if (
            not isinstance(estimates, list)
            or len(estimates) != 1
            or not isinstance(target_times, list)
            or target_times != [self.policy.target_seconds]
        ):
            raise ProtocolSubmissionError("local node returned a malformed fee estimate")
        raw_estimate = estimates[0]
        if isinstance(raw_estimate, bool) or not isinstance(raw_estimate, int):
            raise ProtocolSubmissionError(
                "local node returned a non-integer fee estimate"
            )
        estimate = raw_estimate
        if estimate < 0:
            raise ProtocolSubmissionError("local node returned a negative fee estimate")
        fee = max(estimate, self.policy.minimum_mojos)
        if fee > self.policy.maximum_mojos:
            raise ProtocolSubmissionError(
                f"medium fee {fee} exceeds configured cap "
                f"{self.policy.maximum_mojos}"
            )
        return fee

    async def _select_fee_coin(
        self,
        fee: int,
        *,
        excluded_coin_ids: set[bytes],
        selection_purpose: str | None,
    ):
        try:
            records = await self.provider.get_coin_records_by_puzzle_hash(
                self.faucet.address_hex,
                include_spent=False,
            )
        except ChiaProviderError as exc:
            raise ProtocolSubmissionError(str(exc)) from exc

        reserved_coin_ids = self._reserved_fee_coin_ids()
        available: list[dict[str, Any]] = []
        for record in records:
            try:
                coin = self.faucet.select_coin(
                    [record],
                    min_amount=fee,
                    max_amount=self.policy.maximum_funding_coin_mojos,
                    purpose=selection_purpose,
                )
            except RuntimeError as exc:
                raise ProtocolSubmissionError(str(exc)) from exc
            except (KeyError, TypeError, ValueError):
                continue
            if coin is None:
                continue
            if bytes(coin.name()) in excluded_coin_ids:
                continue
            if bytes(coin.name()) in reserved_coin_ids:
                continue
            try:
                pending = await self.provider.get_mempool_items_by_coin_name(
                    "0x" + coin.name().hex()
                )
            except ChiaProviderError as exc:
                raise ProtocolSubmissionError(str(exc)) from exc
            if not pending:
                available.append(record)

        try:
            selected = self.faucet.select_coin(
                available,
                min_amount=fee,
                max_amount=self.policy.maximum_funding_coin_mojos,
                purpose=selection_purpose,
            )
        except RuntimeError as exc:
            raise ProtocolSubmissionError(str(exc)) from exc
        if selected is None:
            raise ProtocolSubmissionError(
                "protocol fee till has no eligible confirmed, unreserved coin"
            )
        return selected

    def _reserved_fee_coin_ids(self) -> set[bytes]:
        reserved: set[bytes] = set()
        for source in self._fee_coin_reservation_sources:
            try:
                values = source()
                for value in values:
                    if isinstance(value, bytes):
                        raw = value
                    elif isinstance(value, str):
                        normalized = value.removeprefix("0x")
                        raw = bytes.fromhex(normalized)
                    else:
                        raise TypeError("fee coin reservation is not bytes or hex")
                    if len(raw) != 32:
                        raise ValueError("fee coin reservation is not bytes32")
                    reserved.add(raw)
            except (TypeError, ValueError) as exc:
                raise ProtocolSubmissionError(
                    "durable fee coin reservation is malformed"
                ) from exc
            except Exception as exc:
                raise ProtocolSubmissionError(
                    "durable fee coin reservations are unavailable"
                ) from exc
        return reserved

    async def _converge_fee(
        self,
        protocol_bundle: SpendBundle,
        fee_coin,
        preliminary_fee: int,
        *,
        selection_purpose: str | None,
        backing_mojos: int = 0,
        backing_conditions: tuple[Program, ...] = (),
    ) -> tuple[SpendBundle, int, Coin]:
        fee = preliminary_fee
        for _ in range(3):
            if fee + backing_mojos > int(fee_coin.amount):
                if not backing_mojos:
                    raise ProtocolSubmissionError(
                        "selected protocol funding coin is smaller than backing plus the medium fee"
                    )
                fee_coin = await self._select_fee_coin(
                    fee + backing_mojos,
                    excluded_coin_ids={bytes(c.name()) for c in protocol_bundle.removals()},
                    selection_purpose=selection_purpose,
                )
            aggregate = SpendBundle.aggregate(
                [
                    protocol_bundle,
                    self._fee_bundle(
                        fee_coin,
                        fee,
                        selection_purpose=selection_purpose,
                        backing_mojos=backing_mojos,
                        backing_conditions=backing_conditions,
                    ),
                ]
            )
            estimated = await self._estimate_fee(aggregate)
            next_fee = max(fee, estimated)
            if next_fee == fee:
                net_fee = sum(int(c.amount) for c in aggregate.removals()) - sum(
                    int(c.amount) for c in aggregate.additions())
                if net_fee != fee:
                    raise ProtocolSubmissionError("funded bundle does not preserve the reserved fee")
                return aggregate, fee, fee_coin
            fee = next_fee
        raise ProtocolSubmissionError("medium fee estimate did not converge")

    def _fee_bundle(
        self,
        coin,
        fee: int,
        *,
        selection_purpose: str | None,
        backing_mojos: int = 0,
        backing_conditions: tuple[Program, ...] = (),
    ) -> SpendBundle:
        conditions = [Program.to([RESERVE_FEE, fee]), *backing_conditions]
        change = int(coin.amount) - fee - backing_mojos
        if change:
            conditions.insert(
                0,
                Program.to(
                    [CREATE_COIN, self.faucet.address_puzzle_hash, change]
                ),
            )
        condition_program = Program.to(conditions)
        delegated = Program.to((1, condition_program))
        solution = Program.to([0, delegated, Program.to(0)])
        spend = make_spend(coin, self.faucet.key.puzzle, solution)
        signature = G2Element.from_bytes(
            self.faucet.sign_delegated_spend(
                coin,
                condition_program,
                purpose=selection_purpose,
            )
        )
        return SpendBundle([spend], signature)


__all__ = [
    "PreparedProtocolBundle",
    "ProtocolBundleSubmitter",
    "ProtocolFeePolicy",
    "ProtocolSubmissionError",
]
