"""Automatic, chain-confirmed RC20 voucher issuance coordinator."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional
from types import SimpleNamespace

import httpx

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.voucher_purchase import voucher_purchase_from_json, validate_base_voucher_purchase
from solslot_puzzles.base_voucher_v5 import (
    prepare_base_voucher_redemption_offer_v5, build_base_voucher_primary_offer_v5,
)
from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentRail,
    purchase_artifact_from_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseKind,
    purchase_artifact_v3_from_json,
    stripe_evidence_to_json,
    stripe_receipt_from_json,
)
from solslot_puzzles.mint_publish_driver import deed_singleton_struct
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.voucher_presale_v2 import (
    VoucherSeriesState,
    series_terms_from_json,
    voucher_commitment_from_json,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    VoucherAction,
    VoucherSeriesStateV2,
    build_base_voucher_terminal_spends,
    build_voucher_issuance_spends,
    build_xch_voucher_terminal_spends,
    curry_base_result_authorization,
    curry_external_receipt,
    curry_purchase_launcher,
    curry_series,
    external_receipt_evidence_message,
)
from solslot_puzzles.voucher_presale_v3 import voucher_commitment_v3_from_json
from solslot_puzzles.voucher_presale_v3_driver import (
    build_stripe_voucher_issuance_spends,
    build_stripe_voucher_primary_offer_v5,
    build_stripe_voucher_terminal_spends,
    curry_stripe_voucher_receipt,
    prepare_stripe_voucher_redemption_offer,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.primary_purchase_v2_driver import (
    PrimaryPurchaseMode,
    build_universal_primary_offer_v4,
    prepare_base_voucher_redemption_offer,
    prepare_xch_voucher_redemption_offer,
)

from .voucher_work_store import LANES
from .config import Settings
from .faucet import Faucet
from .governed_output_index import EvaluatedBundleOutputs
from .kos_exact_execution import KeyOfSolomonExactExecutor
from .payment_purchase_store import PaymentPurchaseStore
from .protocol_submission import ProtocolBundleSubmitter
from .presale_endpoints import (
    BaseVoucherRefundChainEvidence,
    PresaleStore,
    VoucherIssuanceChainEvidence,
    VoucherRedemptionChainEvidence,
    VoucherRefundChainEvidence,
    VoucherSeriesPhaseChainEvidence,
    StripeVoucherRefundChainEvidence,
)
from .presale_endpoints import _confirmed_coin_and_lineage
from .native_purchases import _load_context, _load_context_group
from .public_artifact import load_signed_public_artifact
from .stripe_voucher_execution import (
    parse_stripe_terminal_execution,
    prepare_and_dispatch_stripe_terminal,
    resume_stripe_terminal,
)
from .validator_quorum import (
    ValidatorQuorumError,
    VoucherIssuanceClaim,
    VoucherTransitionClaim,
    base_settlement_evidence_hash,
    collect_voucher_issuance_quorum,
    collect_voucher_transition_quorum,
)


logger = logging.getLogger(__name__)
_CREATE_COIN = 51


@dataclass(frozen=True)
class VoucherIssuanceWorkerConfig:
    enabled: bool = False
    interval_seconds: float = 15.0
    operation_timeout_seconds: float = 45.0

    def __post_init__(self) -> None:
        if not (0 < self.operation_timeout_seconds <= 45 and 0 < self.interval_seconds <= 300):
            raise ValueError("Voucher worker deadlines must fit the 60-second lease")


class VoucherIssuanceWorker:
    """Advance paid Base reservations through one serialized series spend."""

    def __init__(
        self,
        *,
        settings: Settings,
        faucet: Faucet,
        coinset: Any,
        presales: PresaleStore,
        purchases: PaymentPurchaseStore,
        config: VoucherIssuanceWorkerConfig,
        submitter: ProtocolBundleSubmitter | None = None,
        exact_executor: KeyOfSolomonExactExecutor | None = None,
        authorize_dispatch: Callable[[], None] | None = None,
    ) -> None:
        self.settings = settings
        self.faucet = faucet
        self.coinset = coinset
        self.presales = presales
        self.purchases = purchases
        self.config = config
        self.submitter = submitter
        self.exact_executor = exact_executor
        self.authorize_dispatch = authorize_dispatch
        self._task: Optional[asyncio.Task[None]] = None
        self._stop = asyncio.Event()
        from .campaign_runtime import funding_guard
        self._funding_lock = funding_guard(presales, submitter)
        if submitter is not None:
            submitter.add_fee_coin_reservation_source(presales.pending_voucher_funding_coin_ids)

    async def start(self) -> None:
        if not self.config.enabled or (self._task is not None and not self._task.done()):
            return
        self._stop.clear()
        self._task = asyncio.create_task(
            self._run_forever(), name="solslot-voucher-issuance"
        )
        logger.info(
            "voucher issuance worker started; interval=%ss",
            self.config.interval_seconds,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run_forever(self) -> None:
        async with asyncio.TaskGroup() as group:
            for lane in LANES:
                group.create_task(self._run_lane_forever(lane))

    async def _run_lane_forever(self, lane: str) -> None:
        while not self._stop.is_set():
            try:
                await self._run_lane(lane)
            except Exception:
                logger.exception("voucher lane %s unavailable", lane)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.config.interval_seconds)
            except TimeoutError:
                pass

    async def reconcile_once(self) -> list[dict[str, Any]]:
        """One bounded job per independent lane; never queue behind a busy series."""
        seen: set[str] = set()
        results = await asyncio.gather(*(self._run_lane(lane, seen) for lane in (*tuple(lane for lane in LANES if lane != "retained"), "retained")))
        return [result for result in results if result is not None]

    async def _run_lane(self, lane: str, seen: set[str] | None = None) -> dict[str, Any] | None:
        job = self.presales.claim_voucher_work(lane, uuid.uuid4().hex, time.time(), seen)
        if job is None:
            return None
        if seen is not None:
            seen.add(job["termsHash"])
        base = {"termsHash": job["termsHash"]}
        if lane not in {"phase", "campaign"}:
            base["serial"] = job["serial"]
        status = "INTERRUPTED"
        try:
            async with asyncio.timeout(self.config.operation_timeout_seconds):
                series = self.presales._get_series(job["termsHash"])
                voucher = None if lane in {"phase", "campaign"} else self.presales.voucher(job["termsHash"], job["serial"])
                retained = None if voucher is None else self.presales.pending_voucher_execution(job["termsHash"], job["serial"])
                if retained:
                    result = await self._resume_retained_execution(series, voucher, retained)
                    if result is not None:
                        status = result["status"]
                        return result
                    if lane == "retained":
                        status = "FUNDING_CONFIRMED"
                        return {**base, "status": status}
                    # Funding confirmation allows the next step, using fresh bindings.
                    series = self.presales._get_series(job["termsHash"])
                    voucher = self.presales.voucher(job["termsHash"], job["serial"])
                if lane == "retained":
                    status = "OBSERVED"
                    return None
                result = await getattr(self, "_lane_" + lane)(series, voucher)
                status = result["status"]
                return result
        except TimeoutError:
            status = "TIMED_OUT"
            return {**base, "status": status, "detail": "Voucher work timed out; the same purchase and any signed execution are retained."}
        except Exception as exc:
            status = "ERROR"
            logger.exception("voucher lane %s failed", lane)
            return {**base, "status": status, "detail": str(exc)}
        finally:
            self.presales.finish_voucher_work(job, time.time(), status)

    async def _lane_campaign(self, series, voucher):
        from .campaign_runtime import resume_campaign
        return await resume_campaign(settings=self.settings, store=self.presales, node=self.coinset,
                                     series=series, authorize_dispatch=self._require_dispatch)

    async def _lane_issuance(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            result = await self._advance(series, voucher)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "voucher issuance failed for %s/%s",
                terms_hash,
                voucher["serial"],
            )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": "ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_stripe_terminal(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            status = await self._resume_stripe_terminal_execution(
                series,
                voucher,
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": status,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Stripe voucher exact execution retry failed for %s/%s",
                series["termsHash"],
                voucher["serial"],
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": "STRIPE_TERMINAL_RETRY_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_native_refund(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            confirmed = await self._confirm_refund_if_ready(series, voucher)
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": "REFUNDED" if confirmed else "REFUND_CONFIRMING",
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "voucher refund confirmation failed for %s/%s",
                series["termsHash"],
                voucher["serial"],
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": "REFUND_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_base_refund(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            confirmed = await self._confirm_base_refund_if_ready(series, voucher)
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": (
                    "BASE_REFUND_AUTHORIZED"
                    if confirmed
                    else "BASE_REFUND_CONFIRMING"
                ),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Base voucher refund confirmation failed for %s/%s",
                series["termsHash"],
                voucher["serial"],
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": "BASE_REFUND_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_stripe_refund(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            confirmed = await self._confirm_stripe_refund_if_ready(
                series, voucher
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": (
                    "STRIPE_REFUND_AUTHORIZED"
                    if confirmed
                    else "STRIPE_REFUND_CONFIRMING"
                ),
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Stripe voucher refund confirmation failed for %s/%s",
                series["termsHash"],
                voucher["serial"],
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "serial": int(voucher["serial"]),
                "status": "STRIPE_REFUND_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_native_redemption(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            if voucher.get("redemptionBundleId"):
                confirmed = await self._confirm_redemption_if_ready(
                    series, voucher
                )
                if confirmed:
                    status = "REDEEMED"
                elif (
                    int(time.time()) >= int(series.get("deliveryDeadline") or 0)
                    and await self._redemption_inputs_are_unspent(voucher)
                ):
                    await self._submit_expired_refund(series, voucher)
                    status = "REFUND_SUBMITTED"
                else:
                    status = "REDEMPTION_CONFIRMING"
            elif int(time.time()) >= int(
                series.get("deliveryDeadline") or 0
            ):
                await self._submit_expired_refund(series, voucher)
                status = "REFUND_SUBMITTED"
            else:
                submitted = await self._submit_redemption(series, voucher)
                status = (
                    "REDEMPTION_SUBMITTED"
                    if submitted
                    else "REDEMPTION_WAITING"
                )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": status,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "voucher redemption failed for %s/%s",
                terms_hash,
                voucher["serial"],
            )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": "REDEMPTION_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_base_redemption(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            if voucher.get("redemptionBundleId"):
                confirmed = await self._confirm_base_redemption_if_ready(
                    series, voucher
                )
                if confirmed:
                    status = "BASE_DELIVERY_AUTHORIZED"
                elif (
                    int(time.time()) >= int(series.get("deliveryDeadline") or 0)
                    and await self._base_terminal_inputs_are_unspent(voucher)
                ):
                    await self._submit_base_expired_refund(series, voucher)
                    status = "BASE_REFUND_SUBMITTED"
                else:
                    status = "BASE_REDEMPTION_CONFIRMING"
            elif int(time.time()) >= int(
                series.get("deliveryDeadline") or 0
            ):
                await self._submit_base_expired_refund(series, voucher)
                status = "BASE_REFUND_SUBMITTED"
            else:
                submitted = await self._submit_base_redemption(series, voucher)
                status = (
                    "BASE_REDEMPTION_SUBMITTED"
                    if submitted
                    else "BASE_REDEMPTION_WAITING"
                )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": status,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Base voucher settlement failed for %s/%s",
                terms_hash,
                voucher["serial"],
            )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": "BASE_SETTLEMENT_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_stripe_redemption(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            if (
                voucher.get("terminalExactExecution")
                and not voucher.get("redemptionBundleId")
            ):
                result = {
                    "termsHash": terms_hash,
                    "serial": int(voucher["serial"]),
                    "status": "STRIPE_TERMINAL_RETRY_PENDING",
                }
                return result
            if voucher.get("redemptionBundleId"):
                confirmed = await self._confirm_stripe_redemption_if_ready(
                    series, voucher
                )
                if confirmed:
                    status = "STRIPE_DEED_DELIVERED"
                else:
                    status = "STRIPE_REDEMPTION_CONFIRMING"
            elif int(time.time()) >= int(
                series.get("deliveryDeadline") or 0
            ):
                await self._submit_stripe_expired_refund(series, voucher)
                status = "STRIPE_REFUND_SUBMITTED"
            else:
                submitted = await self._submit_stripe_redemption(
                    series, voucher
                )
                status = (
                    "STRIPE_REDEMPTION_SUBMITTED"
                    if submitted
                    else "STRIPE_REDEMPTION_WAITING"
                )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": status,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Stripe voucher settlement failed for %s/%s",
                terms_hash,
                voucher["serial"],
            )
            result = {
                "termsHash": terms_hash,
                "serial": int(voucher["serial"]),
                "status": "STRIPE_SETTLEMENT_ERROR",
                "detail": str(exc),
            }
        return result

    async def _lane_phase(self, series, voucher):
        terms_hash = str(series["termsHash"])
        try:
            confirmed = await self._confirm_phase_if_ready(series)
            result = {
                "termsHash": str(series["termsHash"]),
                "status": "PHASE_CONFIRMED" if confirmed else "PHASE_CONFIRMING",
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "voucher phase confirmation failed for %s",
                series["termsHash"],
            )
            result = {
                "termsHash": str(series["termsHash"]),
                "status": "PHASE_ERROR",
                "detail": str(exc),
            }
        return result


    _RETAINED_KINDS = {
        "funding": ("record_issuance_funding", "fundingBundleId", "funding_bundle_id", "FUNDING_SUBMITTED"),
        "issuance": ("record_issuance_submission", "issuanceBundleId", "issuance_bundle_id", "ISSUANCE_SUBMITTED"),
        "native_refund": ("record_native_refund_submission", "refundBundleId", "spend_bundle_id", "REFUND_SUBMITTED"),
        "native_redemption": ("record_redemption_submission", "redemptionBundleId", "spend_bundle_id", "REDEMPTION_SUBMITTED"),
        "base_redemption": ("record_redemption_submission", "redemptionBundleId", "spend_bundle_id", "BASE_REDEMPTION_SUBMITTED"),
        "base_refund": ("record_base_expired_refund_submission", "refundBundleId", "spend_bundle_id", "BASE_REFUND_SUBMITTED"),
    }

    def _require_dispatch(self):
        if not self.config.enabled or self._stop.is_set():
            raise RuntimeError("Voucher dispatch is paused; known outcomes remain observable")
        if self.authorize_dispatch is not None:
            self.authorize_dispatch()

    def _bind_retained_execution(self, series, voucher, execution):
        method, field, binding, _ = self._RETAINED_KINDS[execution["kind"]]
        bundle = SpendBundle.from_json_dict(execution["spendBundle"])
        bundle_id = _hex32(bundle.name())
        if execution["bindings"][binding] != bundle_id:
            raise ValueError("Retained voucher bundle differs from its binding")
        if voucher.get(field):
            if voucher[field] != bundle_id:
                raise ValueError("Retained voucher submission was replaced")
        else:
            getattr(self.presales, method)(series["termsHash"], voucher["serial"], **execution["bindings"])
        return bundle

    async def _dispatch_retained_execution(self, series, voucher, bundle, *, kind, bindings):
        # Persist the signed bytes BEFORE any network dispatch. A deadline or a
        # lost response cannot cause another funding coin or a replacement spend.
        execution = dict(kind=kind, spendBundle=bundle.to_json_dict(), bindings=bindings)
        self.presales.retain_voucher_execution(series["termsHash"], voucher["serial"], execution)
        self._bind_retained_execution(series, voucher, execution)
        self._require_dispatch()
        result = await self.coinset.push_tx(bundle.to_json_dict())
        _require_push_accepted(result, "retained voucher " + kind)
        return self.presales.voucher(series["termsHash"], voucher["serial"])

    async def _resume_retained_execution(self, series, voucher, execution):
        bundle = self._bind_retained_execution(series, voucher, execution)
        voucher = self.presales.voucher(series["termsHash"], voucher["serial"])
        kind = execution["kind"]
        base = dict(termsHash=series["termsHash"], serial=voucher["serial"])
        if kind == "funding":
            record = await self.coinset.get_coin_record_by_name(voucher["purchaseLauncherCoinId"])
            coin = _confirmed_unspent_coin(record)
            confirmed = coin is not None and _hex32(coin.name()) == voucher["purchaseLauncherCoinId"] and _hex32(coin.puzzle_hash) == voucher["purchaseLauncherPuzzleHash"] and int(coin.amount) == 2
            final = None
        else:
            confirm, terminal_state, status = {
                "issuance": (self._confirm_if_ready, "ESCROWED", "CONFIRMED"),
                "native_refund": (self._confirm_refund_if_ready, "REFUNDED", "REFUNDED"),
                "base_refund": (self._confirm_base_refund_if_ready, "REFUNDED", "BASE_REFUND_AUTHORIZED"),
                "native_redemption": (self._confirm_redemption_if_ready, "REDEEMED", "REDEEMED"),
                "base_redemption": (self._confirm_base_redemption_if_ready, "REDEEMED", "BASE_DELIVERY_AUTHORIZED"),
            }[kind]
            confirmed = voucher["state"] == terminal_state or await confirm(series, voucher)
            final = {**base, "status": status}
        if confirmed:
            self.presales.confirm_voucher_execution(series["termsHash"], voucher["serial"], kind)
            return final
        self._require_dispatch()
        result = await self.coinset.push_tx(bundle.to_json_dict())
        _require_push_accepted(result, "retained voucher " + kind)
        status = {"funding": "FUNDING_SUBMITTED", "issuance": "CONFIRMING", "native_refund": "REFUND_CONFIRMING",
                  "base_refund": "BASE_REFUND_CONFIRMING", "native_redemption": "REDEMPTION_CONFIRMING",
                  "base_redemption": "BASE_REDEMPTION_CONFIRMING"}[kind]
        return {**base, "status": status}

    async def _advance(
        self, series: dict[str, Any], voucher: dict[str, Any]
    ) -> dict[str, Any]:
        base = {
            "termsHash": str(series["termsHash"]),
            "serial": int(voucher["serial"]),
        }
        if voucher["paymentRail"] not in {
            "BASE_SEPOLIA_USDC",
            "STRIPE_USD",
        }:
            return {**base, "status": "WAITING_FOR_WALLET_OFFER"}
        if voucher["state"] == "ISSUANCE_SUBMITTED":
            confirmed = await self._confirm_if_ready(series, voucher)
            return {**base, "status": "CONFIRMED" if confirmed else "CONFIRMING"}
        if not voucher.get("purchaseLauncherCoinId"):
            funded = await self._fund_purchase_launcher(series, voucher)
            return {
                **base,
                "status": "FUNDING_SUBMITTED",
                "spendBundleId": funded["fundingBundleId"],
            }
        submitted = await self._submit_if_ready(series, voucher)
        return {
            **base,
            "status": "ISSUANCE_SUBMITTED" if submitted else "WAITING_FOR_FUNDING",
        }

    async def _fund_purchase_launcher(
        self, series: dict[str, Any], voucher_json: dict[str, Any]
    ) -> dict[str, Any]:
        async with self._funding_lock:
            return await self._fund_purchase_launcher_locked(series, voucher_json)

    async def _fund_purchase_launcher_locked(self, series, voucher_json):
        terms = series_terms_from_json(series["terms"])
        if voucher_json["paymentRail"] == "STRIPE_USD":
            voucher = voucher_commitment_v3_from_json(
                voucher_json["commitment"]
            )
            purchase = purchase_artifact_v3_from_json(
                voucher_json["purchaseArtifact"]
            )
            payment_puzzle = curry_stripe_voucher_receipt(
                terms=terms,
                voucher=voucher,
                artifact=purchase,
            )
        else:
            voucher = voucher_commitment_from_json(voucher_json["commitment"])
            payment_puzzle = curry_external_receipt(terms=terms, voucher=voucher)
        launcher_puzzle = curry_purchase_launcher(
            terms=terms,
            voucher=voucher,
            payment_puzzle_hash=bytes32(payment_puzzle.get_tree_hash()),
            payment_amount=1,
        )
        records = await self.coinset.get_coin_records_by_puzzle_hash(
            "0x" + self.faucet.address_puzzle_hash.hex(), include_spent=False
        )
        reserved = (self.submitter.reserved_funding_coin_ids() if self.submitter is not None
                    else {bytes.fromhex(value[2:]) for value in self.presales.pending_voucher_funding_coin_ids() | self.presales.pending_campaign_funding_coin_ids()})
        records = [record for record in records if (coin := _confirmed_unspent_coin(record)) is not None and bytes(coin.name()) not in reserved]
        parent = self.faucet.select_coin(
            records,
            min_amount=2,
            max_amount=self.settings.faucet_max_spend_mojos,
        )
        if parent is None:
            raise RuntimeError("faucet has no eligible two-mojo voucher funding coin")
        conditions_list = [
            Program.to(
                [
                    _CREATE_COIN,
                    bytes32(launcher_puzzle.get_tree_hash()),
                    2,
                    [terms.terms_hash, voucher.commitment_hash, voucher.global_payment_id],
                ]
            )
        ]
        change = int(parent.amount) - 2
        if change:
            conditions_list.append(
                Program.to([_CREATE_COIN, self.faucet.address_puzzle_hash, change])
            )
        conditions = Program.to(conditions_list)
        delegated = Program.to((1, conditions))
        parent_spend = make_spend(
            parent,
            self.faucet.key.puzzle,
            Program.to([0, delegated, Program.to(0)]),
        )
        signature = G2Element.from_bytes(
            self.faucet.sign_delegated_spend(parent, conditions)
        )
        bundle = SpendBundle([parent_spend], signature)
        purchase_launcher = Coin(
            bytes32(parent.name()),
            bytes32(launcher_puzzle.get_tree_hash()),
            uint64(2),
        )
        return await self._dispatch_retained_execution(series, voucher_json, bundle,
            kind="funding", bindings=dict(
                funding_bundle_id=_hex32(bundle.name()),
                purchase_launcher_coin_id=_hex32(purchase_launcher.name()),
                purchase_launcher_puzzle_hash=_hex32(purchase_launcher.puzzle_hash),
            ))

    async def _submit_if_ready(
        self, series: dict[str, Any], voucher_json: dict[str, Any]
    ) -> bool:
        purchase_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["purchaseLauncherCoinId"])
        )
        purchase_coin = _confirmed_unspent_coin(purchase_record)
        if purchase_coin is None:
            return False
        if (
            _hex32(purchase_coin.name())
            != str(voucher_json["purchaseLauncherCoinId"]).lower()
            or _hex32(purchase_coin.puzzle_hash)
            != str(voucher_json["purchaseLauncherPuzzleHash"]).lower()
            or int(purchase_coin.amount) != 2
        ):
            raise RuntimeError("confirmed voucher funding coin differs from its binding")

        chain = series["chainState"]
        current_id = chain.get("currentCoinId")
        if not isinstance(current_id, str):
            raise RuntimeError("presale series has no confirmed singleton state")
        series_record = await self.coinset.get_coin_record_by_name(current_id)
        series_coin = _confirmed_unspent_coin(series_record)
        if series_coin is None:
            return False
        if _hex32(series_coin.name()) != current_id.lower():
            raise RuntimeError("current series coin record is not canonical")

        terms = series_terms_from_json(series["terms"])
        state = _series_state(series)
        lineage = LineageProof(
            _b32(chain["lineageParentName"]),
            (
                _b32(chain["lineageInnerPuzzleHash"])
                if chain.get("lineageInnerPuzzleHash")
                else None
            ),
            uint64(1),
        )
        stored_purchase = self.purchases.get(str(voucher_json["purchaseId"]))
        is_stripe = voucher_json["paymentRail"] == "STRIPE_USD"
        if is_stripe:
            voucher = voucher_commitment_v3_from_json(
                voucher_json["commitment"]
            )
            purchase = purchase_artifact_v3_from_json(
                voucher_json["purchaseArtifact"]
            )
            receipt = stripe_receipt_from_json(
                voucher_json["settlementReceipt"]
            )
            provisional = build_stripe_voucher_issuance_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=lineage,
                voucher=voucher,
                artifact=purchase,
                receipt=receipt,
                expected_original_payer=voucher.original_payer,
                smart_deed_inner_hash=voucher.smart_deed_inner_hash,
                purchase_launcher_coin=purchase_coin,
                signer_indices=tuple(
                    range(self.settings.zkpassport_validator_threshold)
                ),
            )
            payment_evidence = voucher_json["settlementReceipt"]["evidence"]
        else:
            voucher = voucher_commitment_from_json(voucher_json["commitment"])
            payment_puzzle = curry_external_receipt(terms=terms, voucher=voucher)
            provisional = build_voucher_issuance_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=lineage,
                voucher=voucher,
                purchase_launcher_coin=purchase_coin,
                payment_puzzle=payment_puzzle,
                payment_amount=1,
                signer_indices=tuple(
                    range(self.settings.zkpassport_validator_threshold)
                ),
            )
            if not isinstance(stored_purchase.external_message, Mapping):
                raise RuntimeError(
                    "voucher payment has no authenticated external evidence"
                )
            payment_evidence = dict(stored_purchase.external_message)
        artifact = load_signed_public_artifact(self.settings)
        claim = VoucherIssuanceClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(artifact["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored_purchase.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            purchase_launcher_coin_id=_hex32(purchase_coin.name()),
            payment_evidence=payment_evidence,
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_issuance_quorum(self.settings, claim)
        if is_stripe:
            issuance = build_stripe_voucher_issuance_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=lineage,
                voucher=voucher,
                artifact=purchase,
                receipt=receipt,
                expected_original_payer=voucher.original_payer,
                smart_deed_inner_hash=voucher.smart_deed_inner_hash,
                purchase_launcher_coin=purchase_coin,
                signer_indices=quorum.signer_indices,
            )
        else:
            issuance = build_voucher_issuance_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=lineage,
                voucher=voucher,
                purchase_launcher_coin=purchase_coin,
                payment_puzzle=payment_puzzle,
                payment_amount=1,
                signer_indices=quorum.signer_indices,
            )
        if issuance.validator_message != provisional.validator_message:
            raise RuntimeError("voucher issuance changed after quorum selection")
        bundle = SpendBundle(
            list(issuance.coin_spends), quorum.aggregated_signature
        )
        await self._dispatch_retained_execution(series, voucher_json, bundle,
            kind="issuance", bindings=dict(
                issuance_bundle_id=_hex32(bundle.name()),
                voucher_launcher_id=_hex32(issuance.voucher_launcher_id),
                voucher_output_coin_id=_hex32(issuance.voucher_coin.name()),
                payment_commitment_coin_id=_hex32(
                (
                    issuance.receipt_coin
                    if is_stripe
                    else issuance.payment_coin
                ).name()
            ),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=_hex32(issuance.next_series_coin.name()),
                signer_indices=quorum.signer_indices,
            ))
        return True

    async def _confirm_if_ready(
        self, series: dict[str, Any], voucher: dict[str, Any]
    ) -> bool:
        ids = {
            "voucher": str(voucher["voucherOutputCoinId"]),
            "payment": str(voucher["paymentCommitmentCoinId"]),
            "series_output": str(voucher["seriesOutputCoinId"]),
            "series_input": str(voucher["seriesInputCoinId"]),
            "purchase": str(voucher["purchaseLauncherCoinId"]),
        }
        records = {
            name: await self.coinset.get_coin_record_by_name(coin_id)
            for name, coin_id in ids.items()
        }
        output_records = [records[name] for name in ("voucher", "payment", "series_output")]
        if any(not _is_confirmed(record) for record in output_records):
            return False
        input_record = records["series_input"]
        purchase_record = records["purchase"]
        if not _is_spent(input_record) or not _is_spent(purchase_record):
            return False
        heights = {
            int(record.get("confirmed_block_index") or 0)
            for record in output_records
            if isinstance(record, Mapping)
        }
        spent_heights = {
            int(record.get("spent_block_index") or 0)
            for record in (input_record, purchase_record)
            if isinstance(record, Mapping)
        }
        if len(heights) != 1 or spent_heights != heights:
            raise RuntimeError("voucher issuance outputs are not from one atomic block")
        coins = {name: _coin_from_record(record) for name, record in records.items()}
        if any(coins[name] is None for name in coins):
            raise RuntimeError("voucher issuance confirmation has malformed coin records")
        for name, coin_id in ids.items():
            coin = coins[name]
            assert coin is not None
            if _hex32(coin.name()) != coin_id.lower():
                raise RuntimeError(f"voucher issuance {name} coin ID changed")
        series_input = coins["series_input"]
        assert series_input is not None
        next_state = _series_state(series)
        next_state = VoucherSeriesStateV2(
            sold_count=next_state.sold_count + 1,
            redeemed_count=next_state.redeemed_count,
            refunded_count=next_state.refunded_count,
            phase=next_state.phase,
            launched_at=next_state.launched_at,
        )
        terms = series_terms_from_json(series["terms"])
        from solslot_puzzles.voucher_presale_v2_driver import curry_series

        next_inner = curry_series(terms, next_state)
        self.presales.confirm_issuance(
            str(series["termsHash"]),
            int(voucher["serial"]),
            VoucherIssuanceChainEvidence(
                evidenceId="chia:" + str(voucher["issuanceBundleId"]),
                spendBundleId=str(voucher["issuanceBundleId"]),
                purchaseLauncherCoinId=ids["purchase"],
                voucherLauncherId=str(voucher["voucherLauncherId"]),
                voucherOutputCoinId=ids["voucher"],
                paymentCommitmentCoinId=ids["payment"],
                seriesInputCoinId=ids["series_input"],
                seriesInputParentCoinId=_hex32(series_input.parent_coin_info),
                seriesOutputCoinId=ids["series_output"],
                seriesOutputInnerPuzzleHash=_hex32(next_inner.get_tree_hash()),
                confirmedHeight=next(iter(heights)),
            ),
        )
        return True

    async def _confirm_refund_if_ready(
        self,
        series: dict[str, Any],
        voucher: dict[str, Any],
    ) -> bool:
        try:
            action = VoucherAction(int(voucher["refundAction"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("native refund has no valid action binding") from exc
        automatic = action == VoucherAction.REFUND_EXPIRED
        if action not in {
            VoucherAction.REFUND_PRESALE,
            VoucherAction.REFUND_EXPIRED,
            VoucherAction.REFUND_CANCELED,
        }:
            raise RuntimeError("native refund action is invalid")
        ids = {
            "refund": str(voucher["refundOutputCoinId"]),
            "terminal_voucher": str(voucher["terminalVoucherCoinId"]),
            "series_output": str(voucher["refundSeriesOutputCoinId"]),
            "series_input": str(voucher["refundSeriesInputCoinId"]),
            "voucher_input": str(voucher["voucherOutputCoinId"]),
            "payment_input": str(voucher["paymentCommitmentCoinId"]),
        }
        if not automatic:
            ids.update(
                {
                    "vault_output": str(voucher["refundVaultOutputCoinId"]),
                    "vault_input": str(voucher["refundVaultInputCoinId"]),
                }
            )
        if any(value in {"", "None"} for value in ids.values()):
            raise RuntimeError("native refund submission is missing chain bindings")
        records = {
            name: await self.coinset.get_coin_record_by_name(coin_id)
            for name, coin_id in ids.items()
        }
        output_names = ["refund", "terminal_voucher", "series_output"]
        input_names = ["series_input", "voucher_input", "payment_input"]
        if not automatic:
            output_names.append("vault_output")
            input_names.append("vault_input")
        if any(not _is_confirmed(records[name]) for name in output_names):
            return False
        if any(not _is_spent(records[name]) for name in input_names):
            return False
        heights = {
            int(records[name].get("confirmed_block_index") or 0)
            for name in output_names
        }
        spent_heights = {
            int(records[name].get("spent_block_index") or 0)
            for name in input_names
        }
        if len(heights) != 1 or spent_heights != heights:
            raise RuntimeError("native refund inputs and outputs are not atomic")
        coins = {name: _coin_from_record(record) for name, record in records.items()}
        if any(coin is None for coin in coins.values()):
            raise RuntimeError("native refund confirmation has malformed coin records")
        for name, coin_id in ids.items():
            coin = coins[name]
            assert coin is not None
            if _hex32(coin.name()) != coin_id.lower():
                raise RuntimeError(f"native refund {name} coin ID changed")
        refund_coin = coins["refund"]
        terminal_voucher = coins["terminal_voucher"]
        voucher_input = coins["voucher_input"]
        payment_input = coins["payment_input"]
        assert refund_coin is not None
        assert terminal_voucher is not None
        assert voucher_input is not None
        assert payment_input is not None
        if (
            refund_coin.parent_coin_info != payment_input.name()
            or _hex32(refund_coin.puzzle_hash) != str(voucher["originalPayer"]).lower()
            or int(refund_coin.amount) != int(voucher["paymentPrincipal"])
        ):
            raise RuntimeError("native refund changed its payer or exact principal")
        if (
            terminal_voucher.parent_coin_info != voucher_input.name()
            or int(terminal_voucher.amount) != 1
        ):
            raise RuntimeError("native refund did not terminally advance the voucher")
        expected_terminal_puzzle_hash = puzzle_for_singleton(
            _b32(voucher["voucherLauncherId"]),
            load_puzzle("voucher_burn_v2.clsp"),
        ).get_tree_hash()
        if terminal_voucher.puzzle_hash != expected_terminal_puzzle_hash:
            raise RuntimeError("native refund did not burn the voucher")
        if not automatic:
            vault_input = coins["vault_input"]
            vault_output = coins["vault_output"]
            assert vault_input is not None
            assert vault_output is not None
            if (
                vault_output.parent_coin_info != vault_input.name()
                or vault_output.puzzle_hash != vault_input.puzzle_hash
                or int(vault_output.amount) != 1
            ):
                raise RuntimeError(
                    "native refund did not atomically advance the owner vault"
                )
        next_state = _series_state(series)
        next_state = VoucherSeriesStateV2(
            sold_count=next_state.sold_count,
            redeemed_count=next_state.redeemed_count,
            refunded_count=next_state.refunded_count + 1,
            phase=next_state.phase,
            launched_at=next_state.launched_at,
        )
        from solslot_puzzles.voucher_presale_v2_driver import curry_series

        next_inner = curry_series(series_terms_from_json(series["terms"]), next_state)
        series_input = coins["series_input"]
        series_output = coins["series_output"]
        assert series_input is not None
        assert series_output is not None
        expected_series_puzzle_hash = puzzle_for_singleton(
            series_terms_from_json(series["terms"]).series_singleton_id,
            next_inner,
        ).get_tree_hash()
        if (
            series_output.parent_coin_info != series_input.name()
            or series_output.puzzle_hash != expected_series_puzzle_hash
            or int(series_output.amount) != 1
        ):
            raise RuntimeError("native refund changed series successor state")
        self.presales.confirm_native_refund(
            str(series["termsHash"]),
            int(voucher["serial"]),
            VoucherRefundChainEvidence(
                action=int(action),
                evidenceId="chia:" + str(voucher["refundBundleId"]),
                spendBundleId=str(voucher["refundBundleId"]),
                refundOutputCoinId=ids["refund"],
                terminalVoucherCoinId=ids["terminal_voucher"],
                seriesInputCoinId=ids["series_input"],
                seriesInputParentCoinId=_hex32(series_input.parent_coin_info),
                seriesOutputCoinId=ids["series_output"],
                seriesOutputInnerPuzzleHash=_hex32(next_inner.get_tree_hash()),
                vaultInputCoinId=ids.get("vault_input"),
                vaultOutputCoinId=ids.get("vault_output"),
                confirmedHeight=next(iter(heights)),
            ),
        )
        return True

    async def _redemption_inputs_are_unspent(
        self,
        voucher: dict[str, Any],
    ) -> bool:
        input_ids = (
            voucher.get("redemptionSeriesInputCoinId"),
            voucher.get("voucherOutputCoinId"),
            voucher.get("paymentCommitmentCoinId"),
            voucher.get("redemptionDeedInputCoinId"),
        )
        if any(not isinstance(value, str) or not value for value in input_ids):
            raise RuntimeError("submitted redemption is missing exact input bindings")
        records = [
            await self.coinset.get_coin_record_by_name(str(coin_id))
            for coin_id in input_ids
        ]
        return all(_confirmed_unspent_coin(record) is not None for record in records)

    async def _base_terminal_inputs_are_unspent(
        self,
        voucher: dict[str, Any],
    ) -> bool:
        return await self._redemption_inputs_are_unspent(voucher)

    async def _submit_expired_refund(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> None:
        now = int(time.time())
        deadline = int(series.get("deliveryDeadline") or 0)
        if series.get("state") != "LIVE" or deadline <= 0 or now < deadline:
            raise RuntimeError("voucher delivery window has not expired")

        stored = self.purchases.get(str(voucher_json["purchaseId"]))
        purchase = purchase_artifact_from_json(stored.purchase_artifact)
        terms = series_terms_from_json(series["terms"])
        voucher = voucher_commitment_from_json(voucher_json["commitment"])
        if (
            purchase.artifact_hash != voucher.purchase_artifact_hash
            or purchase.purchase_id != _b32(voucher_json["purchaseId"])
            or purchase.deed_launcher_id != voucher.deed_launcher_id
            or purchase.vault_launcher_id != voucher.approved_vault_launcher_id
        ):
            raise RuntimeError("expired refund differs from paid commitments")

        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(series["chainState"]["currentCoinId"]),
            "voucher series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(voucher_json["voucherOutputCoinId"]),
            "voucher coin",
        )
        payment_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        payment_coin = _confirmed_unspent_coin(payment_record)
        if (
            payment_coin is None
            or _hex32(payment_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise RuntimeError("voucher escrow coin is not confirmed and unspent")

        state = _series_state(series)
        provisional = build_xch_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            payment_coin=payment_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_EXPIRED,
            signer_indices=tuple(
                range(self.settings.zkpassport_validator_threshold)
            ),
        )
        genesis = load_signed_public_artifact(self.settings)
        claim = VoucherTransitionClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(payment_coin.name()),
            vault_launcher_id=_hex32(voucher.approved_vault_launcher_id),
            owner_authorization="",
            current_timestamp=now,
            action=int(VoucherAction.REFUND_EXPIRED),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(self.settings, claim)
        terminal = build_xch_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            payment_coin=payment_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_EXPIRED,
            signer_indices=quorum.signer_indices,
        )
        if terminal.validator_message != provisional.validator_message:
            raise RuntimeError("expired refund changed after quorum selection")
        bundle = SpendBundle(
            list(terminal.coin_spends),
            quorum.aggregated_signature,
        )
        additions = [
            addition
            for spend in bundle.coin_spends
            for addition in compute_additions(spend)
        ]
        _one_output(
            additions,
            voucher.original_payer,
            voucher.payment_principal,
            "exact original-payer refund",
        )
        await self._dispatch_retained_execution(series, voucher_json, bundle,
            kind="native_refund", bindings=dict(
                action=VoucherAction.REFUND_EXPIRED,
                spend_bundle_id=_hex32(bundle.name()),
                refund_output_coin_id=_hex32(terminal.settlement_coin.name()),
                terminal_voucher_coin_id=_hex32(
                terminal.terminal_voucher_coin.name()
            ),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=_hex32(terminal.next_series_coin.name()),
                vault_input_coin_id=None,
                vault_output_coin_id=None,
            ))

    async def _submit_redemption(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> bool:
        deadline = int(series.get("deliveryDeadline") or 0)
        if series.get("state") != "LIVE" or int(time.time()) >= deadline:
            return False
        context = await _load_context(
            self.settings,
            self.coinset,
            str(voucher_json["purchaseId"]),
            require_live=False,
        )
        terms = series_terms_from_json(series["terms"])
        voucher = voucher_commitment_from_json(voucher_json["commitment"])
        if (
            context.purchase.artifact_hash != voucher.purchase_artifact_hash
            or context.purchase.deed_launcher_id != voucher.deed_launcher_id
            or context.purchase.vault_launcher_id
            != voucher.approved_vault_launcher_id
            or context.terms.smart_deed_inner_hash
            != voucher.smart_deed_inner_hash
        ):
            raise RuntimeError(
                "voucher redemption context differs from paid commitments"
            )

        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(series["chainState"]["currentCoinId"]),
            "voucher series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(voucher_json["voucherOutputCoinId"]),
            "voucher coin",
        )
        payment_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        payment_coin = _confirmed_unspent_coin(payment_record)
        if (
            payment_coin is None
            or _hex32(payment_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise RuntimeError("voucher escrow coin is not confirmed and unspent")

        state = _series_state(series)
        provisional = build_xch_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=context.purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            payment_coin=payment_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            signer_indices=tuple(
                range(self.settings.zkpassport_validator_threshold)
            ),
        )
        provisional_buyer = prepare_xch_voucher_redemption_offer(
            terminal_coin_spends=provisional.coin_spends,
            payment_coin=payment_coin,
            artifact=context.purchase,
            terms=context.terms,
        )
        genesis = load_signed_public_artifact(self.settings)
        receipt = context.credential_receipt
        claim = VoucherTransitionClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=context.stored.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(payment_coin.name()),
            vault_launcher_id=_hex32(context.purchase.vault_launcher_id),
            vault_coin_id=str(receipt["chiaVaultCoinId"]),
            vault_identity_attest_root=str(receipt["identityAttestRoot"]),
            vault_owner_auth_type=context.credential_owner_auth_type,
            vault_owner_key="0x" + context.credential_owner_key.hex(),
            owner_authorization="",
            current_timestamp=int(time.time()),
            action=int(VoucherAction.REDEEM),
            deed_coin_id=_hex32(context.deed_coin.name()),
            deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
            smart_deed_inner_hash=_hex32(context.terms.smart_deed_inner_hash),
            protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
            buyer_offer=provisional_buyer.to_bech32(),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(self.settings, claim)
        terminal = build_xch_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=context.purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            payment_coin=payment_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            signer_indices=quorum.signer_indices,
        )
        if terminal.validator_message != provisional.validator_message:
            raise RuntimeError("voucher redemption changed after quorum selection")
        buyer_offer = prepare_xch_voucher_redemption_offer(
            terminal_coin_spends=terminal.coin_spends,
            payment_coin=payment_coin,
            artifact=context.purchase,
            terms=context.terms,
        )
        primary = build_universal_primary_offer_v4(
            buyer_offer=buyer_offer,
            deed_coin=context.deed_coin,
            deed_singleton_struct=context.deed_struct,
            lineage_proof=context.deed_lineage,
            artifact=context.purchase,
            signer_indices=quorum.signer_indices,
            terms=context.terms,
            purchase_mode=PrimaryPurchaseMode.VOUCHER,
            voucher_coin_id=voucher_coin.name(),
            voucher_transition_message=terminal.validator_message,
        )
        valid = primary.aggregate_offer.to_valid_spend()
        bundle = SpendBundle(
            list(valid.coin_spends),
            AugSchemeMPL.aggregate(
                [valid.aggregated_signature, quorum.aggregated_signature]
            ),
        )
        additions = [
            addition
            for spend in bundle.coin_spends
            for addition in compute_additions(spend)
        ]
        treasury_output = _one_output(
            additions,
            context.terms.protocol_puzhash,
            context.purchase.rail_amount,
            "protocol treasury payment",
        )
        deed_output = _one_output(
            additions,
            _deed_vault_full_puzzle_hash(
                context.purchase.deed_launcher_id,
                context.purchase.vault_launcher_id,
            ),
            1,
            "vault SmartDeed delivery",
        )
        await self._dispatch_retained_execution(series, voucher_json, bundle,
            kind="native_redemption", bindings=dict(
                spend_bundle_id=_hex32(bundle.name()),
                treasury_output_coin_id=_hex32(treasury_output.name()),
                deed_output_coin_id=_hex32(deed_output.name()),
                terminal_voucher_coin_id=_hex32(
                terminal.terminal_voucher_coin.name()
            ),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=_hex32(terminal.next_series_coin.name()),
                deed_input_coin_id=_hex32(context.deed_coin.name()),
            ))
        return True

    def _stripe_execution_services(
        self,
    ) -> tuple[ProtocolBundleSubmitter, KeyOfSolomonExactExecutor]:
        if self.submitter is None or self.exact_executor is None:
            raise RuntimeError(
                "Stripe voucher settlement requires the exact KoS executor and "
                "protocol fee funding"
            )
        async def dispatch(request, prepared):
            self._require_dispatch()
            return await self.exact_executor.dispatch(request, prepared)
        return self.submitter, SimpleNamespace(dispatch=dispatch)

    async def _resume_stripe_terminal_execution(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> str:
        stored = self.purchases.get(str(voucher_json["purchaseId"]))
        purchase = purchase_artifact_v3_from_json(stored.purchase_artifact)
        execution_json = voucher_json.get("terminalExactExecution")
        if not isinstance(execution_json, Mapping):
            raise RuntimeError("Stripe voucher exact execution is missing")
        execution_json = parse_stripe_terminal_execution(
            execution_json,
            expected_purchase_id=purchase.purchase_id,
            expected_artifact_hash=purchase.artifact_hash,
        )
        if execution_json["mode"] == "REDEEM":
            try:
                confirmed = await self._confirm_redemption_if_ready(
                    series, voucher_json, external_rail="STRIPE_USD",
                    retained_execution=execution_json,
                )
            except httpx.HTTPError:
                # Preserve exact retry when the primary node is unavailable.
                # Integrity failures above/below are not transport failures.
                logger.warning("Stripe voucher confirmation unavailable; retrying retained execution")
                confirmed = False
            if confirmed:
                return "STRIPE_DEED_DELIVERED"
        _submitter, exact_executor = self._stripe_execution_services()
        execution, observed_at = await resume_stripe_terminal(
            exact_executor=exact_executor,
            execution=execution_json,
            expected_purchase_id=purchase.purchase_id,
            expected_artifact_hash=purchase.artifact_hash,
        )
        self._record_stripe_terminal_submission(
            series,
            voucher_json,
            execution,
            observed_at,
        )
        return (
            "STRIPE_REDEMPTION_SUBMITTED"
            if execution["mode"] == "REDEEM"
            else "STRIPE_REFUND_SUBMITTED"
        )

    def _record_stripe_terminal_submission(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
        execution: Mapping[str, Any],
        observed_at: int,
    ) -> None:
        prepared = execution.get("prepared")
        roles = execution.get("outputRoles")
        bindings = execution.get("bindings")
        if not all(isinstance(value, Mapping) for value in (prepared, roles, bindings)):
            raise RuntimeError("Stripe voucher exact execution binding is malformed")
        mode = str(execution.get("mode", ""))
        action = VoucherAction(int(execution["voucherAction"]))
        bundle_id = str(prepared["spendBundleId"])
        terms_hash = str(series["termsHash"])
        serial = int(voucher_json["serial"])
        if mode == "REDEEM":
            self.presales.record_redemption_submission(
                terms_hash,
                serial,
                spend_bundle_id=bundle_id,
                treasury_output_coin_id=str(roles["coordination"]),
                deed_output_coin_id=str(roles["deed"]),
                terminal_voucher_coin_id=str(roles["terminalVoucher"]),
                series_input_coin_id=str(bindings["seriesInputCoinId"]),
                series_output_coin_id=str(roles["series"]),
                deed_input_coin_id=str(bindings["deedInputCoinId"]),
                external_settlement_evidence_hash=str(
                    bindings["externalSettlementEvidenceHash"]
                ),
                execution_observed_at=observed_at,
            )
            return
        if mode not in {"REFUND_EXPIRED", "REFUND_OWNER"}:
            raise RuntimeError("Stripe voucher exact execution mode is invalid")
        self.presales.record_stripe_refund_submission(
            terms_hash,
            serial,
            action=action,
            spend_bundle_id=bundle_id,
            external_settlement_evidence_hash=str(
                bindings["externalSettlementEvidenceHash"]
            ),
            terminal_voucher_coin_id=str(roles["terminalVoucher"]),
            series_input_coin_id=str(bindings["seriesInputCoinId"]),
            series_output_coin_id=str(roles["series"]),
            vault_input_coin_id=(
                str(bindings["vaultInputCoinId"])
                if bindings.get("vaultInputCoinId")
                else None
            ),
            vault_output_coin_id=(
                str(roles["vault"]) if roles.get("vault") else None
            ),
            execution_observed_at=observed_at,
        )

    def _stripe_payment_evidence(
        self,
        voucher_json: dict[str, Any],
    ) -> tuple[Any, Any, bytes32]:
        stored = self.purchases.get(str(voucher_json["purchaseId"]))
        receipt_json = voucher_json.get("settlementReceipt")
        if not isinstance(receipt_json, Mapping):
            raise RuntimeError("Stripe voucher settlement receipt is missing")
        receipt = stripe_receipt_from_json(receipt_json)
        purchase = purchase_artifact_v3_from_json(stored.purchase_artifact)
        if (
            receipt.artifact != purchase
            or _hex32(purchase.purchase_id)
            != str(voucher_json["purchaseId"]).lower()
        ):
            raise RuntimeError("Stripe voucher receipt differs from its purchase")
        return stored, receipt, receipt.evidence.evidence_hash

    async def _submit_stripe_redemption(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> bool:
        deadline = int(series.get("deliveryDeadline") or 0)
        if series.get("state") != "LIVE" or int(time.time()) >= deadline:
            return False
        stored, receipt, evidence_hash = self._stripe_payment_evidence(
            voucher_json
        )
        group = await _load_context_group(
            self.settings,
            self.coinset,
            str(voucher_json["purchaseId"]),
            require_live=False,
            allowed_rails=(PaymentRail.STRIPE,),
        )
        if (
            group.batch is not None
            or len(group.contexts) != 1
            or group.contexts[0].purchase != receipt.artifact
            or group.contexts[0].purchase.purchase_kind != PurchaseKind.PRESALE
        ):
            raise RuntimeError(
                "Stripe voucher differs from its single canonical reservation"
            )
        context = group.contexts[0]
        if context.reservation is None:
            raise RuntimeError("Stripe voucher inventory reservation is missing")
        if int(time.time()) >= context.reservation.expires_at:
            raise RuntimeError("Stripe voucher inventory reservation has expired")
        terms = series_terms_from_json(series["terms"])
        voucher = voucher_commitment_v3_from_json(voucher_json["commitment"])
        if (
            context.purchase != receipt.artifact
            or context.purchase.artifact_hash != voucher.purchase_artifact_hash
            or context.purchase.deed_launcher_id != voucher.deed_launcher_id
            or context.purchase.vault_launcher_id
            != voucher.approved_vault_launcher_id
            or context.terms.smart_deed_inner_hash
            != voucher.smart_deed_inner_hash
        ):
            raise RuntimeError(
                "Stripe voucher redemption differs from paid commitments"
            )

        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(series["chainState"]["currentCoinId"]),
            "voucher series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(voucher_json["voucherOutputCoinId"]),
            "voucher coin",
        )
        receipt_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        receipt_coin = _confirmed_unspent_coin(receipt_record)
        if (
            receipt_coin is None
            or _hex32(receipt_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise RuntimeError(
                "Stripe voucher receipt is not confirmed and unspent"
            )

        state = _series_state(series)
        provisional = build_stripe_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            artifact=context.purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            terminal_evidence_hash=evidence_hash,
            signer_indices=tuple(
                range(self.settings.zkpassport_validator_threshold)
            ),
        )
        provisional_buyer = prepare_stripe_voucher_redemption_offer(
            terminal=provisional,
            receipt_coin=receipt_coin,
            artifact=context.purchase,
            terms=context.terms,
            deed_singleton_struct=context.deed_struct,
        )
        genesis = load_signed_public_artifact(self.settings)
        credential = context.credential_receipt
        claim = VoucherTransitionClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(receipt_coin.name()),
            vault_launcher_id=_hex32(context.purchase.vault_launcher_id),
            vault_coin_id=str(credential["chiaVaultCoinId"]),
            vault_identity_attest_root=str(credential["identityAttestRoot"]),
            vault_owner_auth_type=context.credential_owner_auth_type,
            vault_owner_key="0x" + context.credential_owner_key.hex(),
            owner_authorization="",
            current_timestamp=int(time.time()),
            action=int(VoucherAction.REDEEM),
            deed_coin_id=_hex32(context.deed_coin.name()),
            deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
            smart_deed_inner_hash=_hex32(
                context.terms.smart_deed_inner_hash
            ),
            protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
            buyer_offer=provisional_buyer.to_bech32(),
            reservation_expires_at=context.reservation.expires_at,
            payment_evidence=stripe_evidence_to_json(receipt.evidence),
            external_settlement_evidence_hash=_hex32(evidence_hash),
            external_validator_message=_hex32(
                provisional.receipt_validator_message
            ),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(self.settings, claim)
        terminal = build_stripe_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            artifact=context.purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            terminal_evidence_hash=evidence_hash,
            signer_indices=quorum.signer_indices,
        )
        if (
            terminal.validator_message != provisional.validator_message
            or terminal.receipt_validator_message
            != provisional.receipt_validator_message
        ):
            raise RuntimeError(
                "Stripe voucher redemption changed after quorum selection"
            )
        buyer_offer = prepare_stripe_voucher_redemption_offer(
            terminal=terminal,
            receipt_coin=receipt_coin,
            artifact=context.purchase,
            terms=context.terms,
            deed_singleton_struct=context.deed_struct,
        )
        primary = build_stripe_voucher_primary_offer_v5(
            voucher_offer=buyer_offer,
            terminal=terminal,
            receipt_coin=receipt_coin,
            receipt=receipt,
            deed_coin=context.deed_coin,
            deed_singleton_struct=context.deed_struct,
            lineage_proof=context.deed_lineage,
            signer_indices=quorum.signer_indices,
            terms=context.terms,
            reservation=context.reservation,
        )
        valid = primary.aggregate_offer.to_valid_spend()
        bundle = SpendBundle(
            list(valid.coin_spends),
            AugSchemeMPL.aggregate(
                [valid.aggregated_signature, quorum.aggregated_signature]
            ),
        )
        evaluated = EvaluatedBundleOutputs(bundle)
        treasury_output = _one_output(
            evaluated.additions,
            context.terms.protocol_puzhash,
            1,
            "Stripe voucher coordination output",
        )
        deed_output = evaluated.find_exact_descendant(
            ancestor_coin_id=context.deed_coin.name(),
            puzzle_hash=SINGLETON_MOD.curry(
                context.deed_struct,
                puzzle_for_p2_vault(context.purchase.vault_launcher_id),
            ).get_tree_hash(),
            amount=1,
            label="vault SmartDeed delivery",
        )
        submitter, exact_executor = self._stripe_execution_services()
        execution, observed_at = await prepare_and_dispatch_stripe_terminal(
            store=self.presales,
            submitter=submitter,
            exact_executor=exact_executor,
            terms_hash=str(series["termsHash"]),
            serial=int(voucher_json["serial"]),
            mode="REDEEM",
            voucher_action=int(VoucherAction.REDEEM),
            purchase_id=context.purchase.purchase_id,
            artifact_hash=context.purchase.artifact_hash,
            claim_hash=terminal.validator_message,
            signer_indices=quorum.signer_indices,
            protocol_bundle=bundle,
            expected_outputs={
                "coordination": treasury_output,
                "deed": deed_output,
                "series": terminal.next_series_coin,
                "terminalVoucher": terminal.terminal_voucher_coin,
            },
            bindings={
                "seriesInputCoinId": _hex32(series_coin.name()),
                "deedInputCoinId": _hex32(context.deed_coin.name()),
                "externalSettlementEvidenceHash": _hex32(evidence_hash),
            },
        )
        self._record_stripe_terminal_submission(
            series,
            voucher_json,
            execution,
            observed_at,
        )
        return True

    def _base_payment_evidence(
        self,
        voucher_json: dict[str, Any],
    ) -> tuple[Any, dict[str, Any], bytes32]:
        stored = self.purchases.get(str(voucher_json["purchaseId"]))
        if not isinstance(stored.external_message, Mapping):
            raise RuntimeError(
                "Base voucher has no authenticated escrow deposit evidence"
            )
        evidence = dict(stored.external_message)
        evidence_hash = bytes32.fromhex(
            base_settlement_evidence_hash(evidence).removeprefix("0x")
        )
        return stored, evidence, evidence_hash

    async def _submit_base_redemption(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> bool:
        deadline = int(series.get("deliveryDeadline") or 0)
        if series.get("state") != "LIVE" or int(time.time()) >= deadline:
            return False
        group = await _load_context_group(
            self.settings,
            self.coinset,
            str(voucher_json["purchaseId"]),
            require_live=False,
            allowed_rails=(PaymentRail.EVM_TEST_USD,),
        )
        if (group.batch is not None or len(group.contexts) != 1
            or group.contexts[0].purchase.purchase_kind != PurchaseKind.PRESALE):
            raise RuntimeError("Base voucher differs from its single canonical reservation")
        context = group.contexts[0]
        if context.reservation is None:
            raise RuntimeError("Base voucher inventory reservation is missing")
        if int(time.time()) >= context.reservation.expires_at:
            raise RuntimeError("Base voucher inventory reservation has expired")
        stored, payment_evidence, evidence_hash = self._base_payment_evidence(
            voucher_json
        )
        terms = series_terms_from_json(series["terms"])
        voucher = voucher_commitment_from_json(voucher_json["commitment"])
        if (
            context.purchase.artifact_hash != voucher.purchase_artifact_hash
            or context.purchase.deed_launcher_id != voucher.deed_launcher_id
            or context.purchase.vault_launcher_id
            != voucher.approved_vault_launcher_id
            or context.terms.smart_deed_inner_hash
            != voucher.smart_deed_inner_hash
        ):
            raise RuntimeError(
                "Base voucher redemption differs from paid commitments"
            )

        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(series["chainState"]["currentCoinId"]),
            "voucher series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(voucher_json["voucherOutputCoinId"]),
            "voucher coin",
        )
        receipt_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        receipt_coin = _confirmed_unspent_coin(receipt_record)
        if (
            receipt_coin is None
            or _hex32(receipt_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise RuntimeError(
                "Base voucher receipt is not confirmed and unspent"
            )

        state = _series_state(series)
        provisional = build_base_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=context.purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            external_settlement_evidence_hash=evidence_hash,
            signer_indices=tuple(
                range(self.settings.zkpassport_validator_threshold)
            ),
        )
        provisional_buyer = prepare_base_voucher_redemption_offer_v5(
            terminal=provisional,
            receipt_coin=receipt_coin,
            artifact=context.purchase,
            terms=context.terms,
            deed_singleton_struct=context.deed_struct,
        )
        genesis = load_signed_public_artifact(self.settings)
        receipt = context.credential_receipt
        claim = VoucherTransitionClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(receipt_coin.name()),
            vault_launcher_id=_hex32(context.purchase.vault_launcher_id),
            vault_coin_id=str(receipt["chiaVaultCoinId"]),
            vault_identity_attest_root=str(receipt["identityAttestRoot"]),
            vault_owner_auth_type=context.credential_owner_auth_type,
            vault_owner_key="0x" + context.credential_owner_key.hex(),
            owner_authorization="",
            current_timestamp=int(time.time()),
            action=int(VoucherAction.REDEEM),
            deed_coin_id=_hex32(context.deed_coin.name()),
            deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
            smart_deed_inner_hash=_hex32(context.terms.smart_deed_inner_hash),
            protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
            buyer_offer=provisional_buyer.to_bech32(),
            reservation_expires_at=context.reservation.expires_at,
            payment_evidence=payment_evidence,
            external_settlement_evidence_hash=_hex32(evidence_hash),
            external_validator_message=_hex32(
                external_receipt_evidence_message(
                    voucher=voucher,
                    action=VoucherAction.REDEEM,
                    external_settlement_evidence_hash=evidence_hash,
                )
            ),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(self.settings, claim)
        terminal = build_base_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=context.purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            external_settlement_evidence_hash=evidence_hash,
            signer_indices=quorum.signer_indices,
        )
        if (
            terminal.validator_message != provisional.validator_message
            or terminal.external_settlement_evidence_hash != evidence_hash
        ):
            raise RuntimeError(
                "Base voucher redemption changed after quorum selection"
            )
        buyer_offer = prepare_base_voucher_redemption_offer_v5(
            terminal=terminal,
            receipt_coin=receipt_coin,
            artifact=context.purchase,
            terms=context.terms,
            deed_singleton_struct=context.deed_struct,
        )
        primary = build_base_voucher_primary_offer_v5(
            voucher_offer=buyer_offer, terminal=terminal, receipt_coin=receipt_coin,
            artifact=context.purchase, deed_coin=context.deed_coin,
            deed_singleton_struct=context.deed_struct, lineage_proof=context.deed_lineage,
            signer_indices=quorum.signer_indices, terms=context.terms,
            reservation=context.reservation,
        )
        valid = primary.aggregate_offer.to_valid_spend()
        bundle = SpendBundle(
            list(valid.coin_spends),
            AugSchemeMPL.aggregate(
                [valid.aggregated_signature, quorum.aggregated_signature]
            ),
        )
        evaluated = EvaluatedBundleOutputs(bundle)
        treasury_output = _one_output(
            evaluated.additions, context.terms.protocol_puzhash, 1,
            "Base receipt coordination output",
        )
        deed_output = evaluated.find_exact_descendant(
            ancestor_coin_id=context.deed_coin.name(),
            puzzle_hash=SINGLETON_MOD.curry(
                context.deed_struct, puzzle_for_p2_vault(context.purchase.vault_launcher_id),
            ).get_tree_hash(),
            amount=1, label="vault SmartDeed delivery",
        )
        await self._dispatch_retained_execution(series, voucher_json, bundle,
            kind="base_redemption", bindings=dict(
                spend_bundle_id=_hex32(bundle.name()),
                treasury_output_coin_id=_hex32(treasury_output.name()),
                deed_output_coin_id=_hex32(deed_output.name()),
                terminal_voucher_coin_id=_hex32(
                terminal.terminal_voucher_coin.name()
            ),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=_hex32(terminal.next_series_coin.name()),
                deed_input_coin_id=_hex32(context.deed_coin.name()),
                external_settlement_evidence_hash=_hex32(evidence_hash),
            ))
        return True

    async def _submit_stripe_expired_refund(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> None:
        now = int(time.time())
        deadline = int(series.get("deliveryDeadline") or 0)
        if series.get("state") != "LIVE" or deadline <= 0 or now < deadline:
            raise RuntimeError("Stripe voucher delivery window has not expired")
        stored, receipt, evidence_hash = self._stripe_payment_evidence(
            voucher_json
        )
        purchase = purchase_artifact_v3_from_json(stored.purchase_artifact)
        terms = series_terms_from_json(series["terms"])
        voucher = voucher_commitment_v3_from_json(voucher_json["commitment"])
        if (
            receipt.artifact != purchase
            or purchase.artifact_hash != voucher.purchase_artifact_hash
            or purchase.deed_launcher_id != voucher.deed_launcher_id
            or purchase.vault_launcher_id
            != voucher.approved_vault_launcher_id
        ):
            raise RuntimeError("Stripe refund differs from paid commitments")
        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(series["chainState"]["currentCoinId"]),
            "voucher series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(voucher_json["voucherOutputCoinId"]),
            "voucher coin",
        )
        receipt_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        receipt_coin = _confirmed_unspent_coin(receipt_record)
        if (
            receipt_coin is None
            or _hex32(receipt_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise RuntimeError(
                "Stripe voucher receipt is not confirmed and unspent"
            )
        state = _series_state(series)
        provisional = build_stripe_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            artifact=purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_EXPIRED,
            terminal_evidence_hash=evidence_hash,
            signer_indices=tuple(
                range(self.settings.zkpassport_validator_threshold)
            ),
        )
        genesis = load_signed_public_artifact(self.settings)
        claim = VoucherTransitionClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(receipt_coin.name()),
            vault_launcher_id=_hex32(voucher.approved_vault_launcher_id),
            owner_authorization="",
            current_timestamp=now,
            action=int(VoucherAction.REFUND_EXPIRED),
            payment_evidence=stripe_evidence_to_json(receipt.evidence),
            external_settlement_evidence_hash=_hex32(evidence_hash),
            external_validator_message=_hex32(
                provisional.receipt_validator_message
            ),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(self.settings, claim)
        terminal = build_stripe_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            artifact=purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_EXPIRED,
            terminal_evidence_hash=evidence_hash,
            signer_indices=quorum.signer_indices,
        )
        if (
            terminal.validator_message != provisional.validator_message
            or terminal.receipt_validator_message
            != provisional.receipt_validator_message
            or terminal.offer_coin is not None
        ):
            raise RuntimeError(
                "Stripe expired refund changed after quorum selection"
            )
        bundle = SpendBundle(
            list(terminal.coin_spends),
            quorum.aggregated_signature,
        )
        submitter, exact_executor = self._stripe_execution_services()
        execution, observed_at = await prepare_and_dispatch_stripe_terminal(
            store=self.presales,
            submitter=submitter,
            exact_executor=exact_executor,
            terms_hash=str(series["termsHash"]),
            serial=int(voucher_json["serial"]),
            mode="REFUND_EXPIRED",
            voucher_action=int(VoucherAction.REFUND_EXPIRED),
            purchase_id=purchase.purchase_id,
            artifact_hash=purchase.artifact_hash,
            claim_hash=terminal.validator_message,
            signer_indices=quorum.signer_indices,
            protocol_bundle=bundle,
            expected_outputs={
                "series": terminal.next_series_coin,
                "terminalVoucher": terminal.terminal_voucher_coin,
            },
            bindings={
                "seriesInputCoinId": _hex32(series_coin.name()),
                "externalSettlementEvidenceHash": _hex32(evidence_hash),
            },
        )
        self._record_stripe_terminal_submission(
            series,
            voucher_json,
            execution,
            observed_at,
        )

    async def _submit_base_expired_refund(
        self,
        series: dict[str, Any],
        voucher_json: dict[str, Any],
    ) -> None:
        now = int(time.time())
        deadline = int(series.get("deliveryDeadline") or 0)
        if series.get("state") != "LIVE" or deadline <= 0 or now < deadline:
            raise RuntimeError("Base voucher delivery window has not expired")
        stored, payment_evidence, evidence_hash = self._base_payment_evidence(
            voucher_json
        )
        purchase = voucher_purchase_from_json(stored.purchase_artifact)
        terms = series_terms_from_json(series["terms"])
        voucher = voucher_commitment_from_json(voucher_json["commitment"])
        if (
            purchase.artifact_hash != voucher.purchase_artifact_hash
            or purchase.deed_launcher_id != voucher.deed_launcher_id
            or purchase.vault_launcher_id
            != voucher.approved_vault_launcher_id
        ):
            raise RuntimeError("Base refund differs from paid commitments")

        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(series["chainState"]["currentCoinId"]),
            "voucher series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            self.coinset,
            str(voucher_json["voucherOutputCoinId"]),
            "voucher coin",
        )
        receipt_record = await self.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        receipt_coin = _confirmed_unspent_coin(receipt_record)
        if (
            receipt_coin is None
            or _hex32(receipt_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise RuntimeError(
                "Base voucher receipt is not confirmed and unspent"
            )

        state = _series_state(series)
        provisional = build_base_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_EXPIRED,
            external_settlement_evidence_hash=evidence_hash,
            signer_indices=tuple(
                range(self.settings.zkpassport_validator_threshold)
            ),
        )
        genesis = load_signed_public_artifact(self.settings)
        claim = VoucherTransitionClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(receipt_coin.name()),
            vault_launcher_id=_hex32(voucher.approved_vault_launcher_id),
            owner_authorization="",
            current_timestamp=now,
            action=int(VoucherAction.REFUND_EXPIRED),
            payment_evidence=payment_evidence,
            external_settlement_evidence_hash=_hex32(evidence_hash),
            external_validator_message=_hex32(
                external_receipt_evidence_message(
                    voucher=voucher,
                    action=VoucherAction.REFUND_EXPIRED,
                    external_settlement_evidence_hash=evidence_hash,
                )
            ),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(self.settings, claim)
        terminal = build_base_voucher_terminal_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=series_lineage,
            voucher=voucher,
            purchase=purchase,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"]),
            voucher_coin=voucher_coin,
            voucher_lineage_proof=voucher_lineage,
            receipt_coin=receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_EXPIRED,
            external_settlement_evidence_hash=evidence_hash,
            signer_indices=quorum.signer_indices,
        )
        if (
            terminal.validator_message != provisional.validator_message
            or terminal.offer_coin is not None
        ):
            raise RuntimeError(
                "Base expired refund changed after quorum selection"
            )
        bundle = SpendBundle(
            list(terminal.coin_spends),
            quorum.aggregated_signature,
        )
        await self._dispatch_retained_execution(series, voucher_json, bundle,
            kind="base_refund", bindings=dict(
                spend_bundle_id=_hex32(bundle.name()),
                external_settlement_evidence_hash=_hex32(evidence_hash),
                terminal_voucher_coin_id=_hex32(
                terminal.terminal_voucher_coin.name()
            ),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=_hex32(terminal.next_series_coin.name()),
            ))

    async def _confirm_redemption_if_ready(
        self,
        series: dict[str, Any],
        voucher: dict[str, Any],
        *,
        external_rail: str | None = None,
        retained_execution: Mapping[str, Any] | None = None,
    ) -> bool:
        if retained_execution is not None:
            if (
                external_rail != "STRIPE_USD"
                or retained_execution.get("mode") != "REDEEM"
                or voucher.get("terminalExactExecution") != retained_execution
            ):
                raise RuntimeError("Stripe voucher retained redemption changed")
            # Project the sealed bindings for read-only chain validation. Do not
            # record submission until the complete outcome is independently seen.
            roles = retained_execution["outputRoles"]
            bindings = retained_execution["bindings"]
            voucher = dict(voucher,
                redemptionBundleId=retained_execution["prepared"]["spendBundleId"],
                redemptionTreasuryOutputCoinId=roles["coordination"],
                redemptionDeedOutputCoinId=roles["deed"],
                redemptionTerminalVoucherCoinId=roles["terminalVoucher"],
                redemptionSeriesOutputCoinId=roles["series"],
                redemptionSeriesInputCoinId=bindings["seriesInputCoinId"],
                redemptionDeedInputCoinId=bindings["deedInputCoinId"],
                externalSettlementEvidenceHash=bindings["externalSettlementEvidenceHash"],
            )
        expected_rail = external_rail or "CHIA_XCH"
        if voucher.get("paymentRail") != expected_rail:
            raise RuntimeError("voucher redemption payment rail changed")
        ids = {
            "treasury": str(voucher["redemptionTreasuryOutputCoinId"] or ""),
            "deed_output": str(voucher["redemptionDeedOutputCoinId"] or ""),
            "terminal_voucher": str(
                voucher["redemptionTerminalVoucherCoinId"] or ""
            ),
            "series_output": str(voucher["redemptionSeriesOutputCoinId"] or ""),
            "series_input": str(voucher["redemptionSeriesInputCoinId"] or ""),
            "voucher_input": str(voucher["voucherOutputCoinId"] or ""),
            "payment_input": str(voucher["paymentCommitmentCoinId"] or ""),
            "deed_input": str(voucher["redemptionDeedInputCoinId"] or ""),
        }
        if any(not value for value in ids.values()):
            raise RuntimeError("voucher redemption is missing chain bindings")
        records = {
            name: await self.coinset.get_coin_record_by_name(coin_id)
            for name, coin_id in ids.items()
        }
        output_names = (
            "treasury",
            "deed_output",
            "terminal_voucher",
            "series_output",
        )
        input_names = (
            "series_input",
            "voucher_input",
            "payment_input",
            "deed_input",
        )
        if any(not _is_confirmed(records[name]) for name in output_names):
            return False
        if any(not _is_spent(records[name]) for name in input_names):
            return False
        heights = {
            int(records[name].get("confirmed_block_index") or 0)
            for name in output_names
        }
        spent_heights = {
            int(records[name].get("spent_block_index") or 0)
            for name in input_names
        }
        if len(heights) != 1 or spent_heights != heights:
            raise RuntimeError("voucher redemption inputs and outputs are not atomic")
        coins = {name: _coin_from_record(record) for name, record in records.items()}
        if any(coin is None for coin in coins.values()):
            raise RuntimeError("voucher redemption has malformed coin records")
        for name, coin_id in ids.items():
            coin = coins[name]
            assert coin is not None
            if _hex32(coin.name()) != coin_id.lower():
                raise RuntimeError(f"voucher redemption {name} coin ID changed")
        terms = series_terms_from_json(series["terms"])
        stripe = external_rail == "STRIPE_USD"
        base = external_rail == "BASE_SEPOLIA_USDC"
        voucher_commitment = (
            voucher_commitment_v3_from_json(voucher["commitment"])
            if stripe
            else voucher_commitment_from_json(voucher["commitment"])
        )
        treasury = coins["treasury"]
        deed_output = coins["deed_output"]
        terminal_voucher = coins["terminal_voucher"]
        voucher_input = coins["voucher_input"]
        series_input = coins["series_input"]
        series_output = coins["series_output"]
        assert all(
            coin is not None
            for coin in (
                treasury,
                deed_output,
                terminal_voucher,
                voucher_input,
                series_input,
                series_output,
            )
        )
        if (
            treasury.puzzle_hash != terms.trusted_protocol_treasury  # type: ignore[union-attr]
            or int(treasury.amount)
            != (
                1
                if external_rail is not None
                else voucher_commitment.payment_principal
            )  # type: ignore[union-attr]
        ):
            raise RuntimeError("voucher redemption changed treasury payment")
        expected_deed_puzzle_hash = (
            self._stripe_redemption_destination(voucher, coins)
            if stripe
            else self._base_redemption_destination(series, voucher, coins)
            if base and self.purchases.get(str(voucher["purchaseId"])).purchase_artifact.get("schema") == "solslot.purchase-artifact.v3"
            else _deed_vault_full_puzzle_hash(
                voucher_commitment.deed_launcher_id,
                voucher_commitment.approved_vault_launcher_id,
            )
        )
        if (
            deed_output.puzzle_hash != expected_deed_puzzle_hash  # type: ignore[union-attr]
            or int(deed_output.amount) != 1  # type: ignore[union-attr]
        ):
            raise RuntimeError("voucher redemption changed SmartDeed destination")
        if (
            terminal_voucher.parent_coin_info != voucher_input.name()  # type: ignore[union-attr]
            or int(terminal_voucher.amount) != 1  # type: ignore[union-attr]
            or series_output.parent_coin_info != series_input.name()  # type: ignore[union-attr]
            or int(series_output.amount) != 1  # type: ignore[union-attr]
        ):
            raise RuntimeError("voucher redemption changed terminal successors")
        expected_terminal_inner = (
            curry_base_result_authorization(
                terms=terms,
                voucher=voucher_commitment,
                action=VoucherAction.REDEEM,
            )
            if base
            else load_puzzle("voucher_burn_v2.clsp")
        )
        expected_terminal_puzzle_hash = puzzle_for_singleton(
            _b32(voucher["voucherLauncherId"]),
            expected_terminal_inner,
        ).get_tree_hash()
        if terminal_voucher.puzzle_hash != expected_terminal_puzzle_hash:  # type: ignore[union-attr]
            raise RuntimeError(
                "voucher redemption terminal authorization changed"
                if base
                else "voucher redemption did not burn the voucher"
            )
        current = _series_state(series)
        next_state = VoucherSeriesStateV2(
            sold_count=current.sold_count,
            redeemed_count=current.redeemed_count + 1,
            refunded_count=current.refunded_count,
            phase=current.phase,
            launched_at=current.launched_at,
        )
        next_inner = curry_series(terms, next_state)
        expected_series_puzzle_hash = puzzle_for_singleton(
            terms.series_singleton_id,
            next_inner,
        ).get_tree_hash()
        if series_output.puzzle_hash != expected_series_puzzle_hash:  # type: ignore[union-attr]
            raise RuntimeError("voucher redemption changed series successor state")
        external_evidence_hash = (
            str(voucher.get("externalSettlementEvidenceHash") or "")
            if external_rail is not None
            else None
        )
        if external_rail is not None and not external_evidence_hash:
            raise RuntimeError(
                "external redemption is missing settlement evidence"
            )
        if retained_execution is not None:
            self._record_stripe_terminal_submission(
                series, voucher, retained_execution, int(time.time()),
            )
        self.presales.confirm_redemption(
            str(series["termsHash"]),
            int(voucher["serial"]),
            VoucherRedemptionChainEvidence(
                evidenceId="chia:" + str(voucher["redemptionBundleId"]),
                spendBundleId=str(voucher["redemptionBundleId"]),
                treasuryOutputCoinId=ids["treasury"],
                deedOutputCoinId=ids["deed_output"],
                terminalVoucherCoinId=ids["terminal_voucher"],
                seriesInputCoinId=ids["series_input"],
                seriesInputParentCoinId=_hex32(
                    series_input.parent_coin_info  # type: ignore[union-attr]
                ),
                seriesOutputCoinId=ids["series_output"],
                seriesOutputInnerPuzzleHash=_hex32(next_inner.get_tree_hash()),
                deedInputCoinId=ids["deed_input"],
                externalSettlementEvidenceHash=external_evidence_hash,
                confirmedHeight=next(iter(heights)),
            ),
        )
        return True

    def _stripe_redemption_destination(
        self, voucher: Mapping[str, Any], coins: Mapping[str, Coin | None],
    ) -> bytes32:
        """Confirm retained exact delivery without reauthorizing an expired quote.

        The input is already spent. Use its sealed bundle and the canonical DID,
        not the unspent-inventory loader or the historical generic launcher.
        Chain records are independently checked for exact IDs and atomic heights
        by the caller before this read model can mark the voucher redeemed.
        """
        _, receipt, evidence_hash = self._stripe_payment_evidence(voucher)
        purchase = receipt.artifact
        commitment = voucher_commitment_v3_from_json(voucher["commitment"])
        if (
            purchase.network != self.settings.network
            or purchase.rail != PaymentRail.STRIPE
            or purchase.purchase_kind != PurchaseKind.PRESALE
            or purchase.artifact_hash != commitment.purchase_artifact_hash
            or purchase.presale_terms_hash != commitment.series_terms_hash
            or purchase.deed_launcher_id != commitment.deed_launcher_id
            or purchase.vault_launcher_id != commitment.approved_vault_launcher_id
            or _hex32(evidence_hash) != voucher.get("externalSettlementEvidenceHash")
        ):
            raise RuntimeError("Stripe voucher confirmation changed paid commitments")
        raw = voucher.get("terminalExactExecution")
        if not isinstance(raw, Mapping):
            raise RuntimeError("Stripe voucher exact redemption evidence is missing")
        execution = parse_stripe_terminal_execution(
            raw, expected_purchase_id=purchase.purchase_id,
            expected_artifact_hash=purchase.artifact_hash,
        )
        roles = execution["outputRoles"]
        bindings = execution["bindings"]
        if (
            execution["mode"] != "REDEEM"
            or execution["prepared"]["spendBundleId"] != voucher["redemptionBundleId"]
            or bindings["deedInputCoinId"] != voucher["redemptionDeedInputCoinId"]
            or bindings["seriesInputCoinId"] != voucher["redemptionSeriesInputCoinId"]
            or bindings["externalSettlementEvidenceHash"] != _hex32(evidence_hash)
            or roles != {
                "coordination": voucher["redemptionTreasuryOutputCoinId"],
                "deed": voucher["redemptionDeedOutputCoinId"],
                "series": voucher["redemptionSeriesOutputCoinId"],
                "terminalVoucher": voucher["redemptionTerminalVoucherCoinId"],
            }
        ):
            raise RuntimeError("Stripe voucher confirmation differs from exact execution")
        bundle = SpendBundle.from_json_dict(execution["prepared"]["spendBundle"])
        removals = {coin.name(): coin for coin in bundle.removals()}
        for name in ("series_input", "voucher_input", "payment_input", "deed_input"):
            coin = coins[name]
            if coin is None or removals.get(coin.name()) != coin:
                raise RuntimeError("Stripe voucher confirmation changed an exact input")
        genesis = load_signed_public_artifact(self.settings)
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=singleton_struct(_b32(genesis["launcherIds"]["did"])),
        )
        destination = SINGLETON_MOD.curry(
            deed_struct, puzzle_for_p2_vault(purchase.vault_launcher_id),
        ).get_tree_hash()
        output = EvaluatedBundleOutputs(bundle).find_exact_descendant(
            ancestor_coin_id=_b32(voucher["redemptionDeedInputCoinId"]),
            puzzle_hash=destination, amount=1, label="vault SmartDeed delivery",
        )
        if output != coins["deed_output"]:
            raise RuntimeError("Stripe voucher confirmation changed SmartDeed destination")
        return bytes32(destination)

    def _base_redemption_destination(self, series, voucher, coins) -> bytes32:
        stored, _, evidence_hash = self._base_payment_evidence(voucher)
        purchase = voucher_purchase_from_json(stored.purchase_artifact)
        commitment = voucher_commitment_from_json(voucher["commitment"])
        validate_base_voucher_purchase(commitment, purchase, series_terms_from_json(series["terms"]))
        if purchase.network != self.settings.network or _hex32(evidence_hash) != voucher["externalSettlementEvidenceHash"]:
            raise RuntimeError("Base voucher confirmation changed paid commitments")
        execution = self.presales.pending_voucher_execution(series["termsHash"], voucher["serial"])
        if not isinstance(execution, Mapping) or execution.get("kind") != "base_redemption":
            raise RuntimeError("Base voucher exact redemption evidence is missing")
        bundle = SpendBundle.from_json_dict(execution["spendBundle"])
        expected = dict(
            spend_bundle_id=voucher["redemptionBundleId"],
            treasury_output_coin_id=voucher["redemptionTreasuryOutputCoinId"],
            deed_output_coin_id=voucher["redemptionDeedOutputCoinId"],
            terminal_voucher_coin_id=voucher["redemptionTerminalVoucherCoinId"],
            series_input_coin_id=voucher["redemptionSeriesInputCoinId"],
            series_output_coin_id=voucher["redemptionSeriesOutputCoinId"],
            deed_input_coin_id=voucher["redemptionDeedInputCoinId"],
            external_settlement_evidence_hash=_hex32(evidence_hash),
        )
        if execution["bindings"] != expected or _hex32(bundle.name()) != expected["spend_bundle_id"]:
            raise RuntimeError("Base voucher confirmation differs from exact execution")
        removals = {coin.name(): coin for coin in bundle.removals()}
        for name in ("series_input", "voucher_input", "payment_input", "deed_input"):
            coin = coins[name]
            if coin is None or removals.get(coin.name()) != coin:
                raise RuntimeError("Base voucher confirmation changed an exact input")
        genesis = load_signed_public_artifact(self.settings)
        struct = deed_singleton_struct(deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=singleton_struct(_b32(genesis["launcherIds"]["did"])))
        destination = SINGLETON_MOD.curry(struct, puzzle_for_p2_vault(purchase.vault_launcher_id)).get_tree_hash()
        output = EvaluatedBundleOutputs(bundle).find_exact_descendant(
            ancestor_coin_id=_b32(voucher["redemptionDeedInputCoinId"]), puzzle_hash=destination,
            amount=1, label="vault SmartDeed delivery")
        if output != coins["deed_output"]:
            raise RuntimeError("Base voucher confirmation changed SmartDeed destination")
        return bytes32(destination)

    async def _confirm_base_redemption_if_ready(
        self,
        series: dict[str, Any],
        voucher: dict[str, Any],
    ) -> bool:
        return await self._confirm_redemption_if_ready(
            series,
            voucher,
            external_rail="BASE_SEPOLIA_USDC",
        )

    async def _confirm_stripe_redemption_if_ready(
        self,
        series: dict[str, Any],
        voucher: dict[str, Any],
    ) -> bool:
        return await self._confirm_redemption_if_ready(
            series,
            voucher,
            external_rail="STRIPE_USD",
        )

    async def _confirm_stripe_refund_if_ready(
        self,
        series: dict[str, Any],
        voucher: dict[str, Any],
    ) -> bool:
        ids = {
            "terminal_voucher": str(voucher["terminalVoucherCoinId"] or ""),
            "series_output": str(voucher["refundSeriesOutputCoinId"] or ""),
            "series_input": str(voucher["refundSeriesInputCoinId"] or ""),
            "voucher_input": str(voucher["voucherOutputCoinId"] or ""),
            "receipt_input": str(voucher["paymentCommitmentCoinId"] or ""),
        }
        vault_input_id = str(voucher.get("refundVaultInputCoinId") or "")
        vault_output_id = str(voucher.get("refundVaultOutputCoinId") or "")
        if bool(vault_input_id) != bool(vault_output_id):
            raise RuntimeError("Stripe refund has incomplete vault bindings")
        if vault_input_id:
            ids["vault_input"] = vault_input_id
            ids["vault_output"] = vault_output_id
        evidence_hash = str(
            voucher.get("externalSettlementEvidenceHash") or ""
        )
        if any(not value for value in ids.values()) or not evidence_hash:
            raise RuntimeError("Stripe refund is missing chain bindings")
        records = {
            name: await self.coinset.get_coin_record_by_name(coin_id)
            for name, coin_id in ids.items()
        }
        output_names = ["terminal_voucher", "series_output"]
        input_names = ["series_input", "voucher_input", "receipt_input"]
        if vault_input_id:
            output_names.append("vault_output")
            input_names.append("vault_input")
        if any(not _is_confirmed(records[name]) for name in output_names):
            return False
        if any(not _is_spent(records[name]) for name in input_names):
            return False
        heights = {
            int(records[name].get("confirmed_block_index") or 0)
            for name in output_names
        }
        spent_heights = {
            int(records[name].get("spent_block_index") or 0)
            for name in input_names
        }
        if len(heights) != 1 or spent_heights != heights:
            raise RuntimeError("Stripe refund inputs and outputs are not atomic")
        coins = {
            name: _coin_from_record(record)
            for name, record in records.items()
        }
        if any(coin is None for coin in coins.values()):
            raise RuntimeError("Stripe refund has malformed coin records")
        for name, coin_id in ids.items():
            coin = coins[name]
            assert coin is not None
            if _hex32(coin.name()) != coin_id.lower():
                raise RuntimeError(f"Stripe refund {name} coin ID changed")

        terms = series_terms_from_json(series["terms"])
        voucher_commitment_v3_from_json(voucher["commitment"])
        try:
            action = VoucherAction(int(voucher["refundAction"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Stripe refund has no valid action binding") from exc
        terminal_voucher = coins["terminal_voucher"]
        voucher_input = coins["voucher_input"]
        series_input = coins["series_input"]
        series_output = coins["series_output"]
        assert all(
            coin is not None
            for coin in (
                terminal_voucher,
                voucher_input,
                series_input,
                series_output,
            )
        )
        expected_terminal_puzzle_hash = puzzle_for_singleton(
            _b32(voucher["voucherLauncherId"]),
            load_puzzle("voucher_burn_v2.clsp"),
        ).get_tree_hash()
        if (
            terminal_voucher.parent_coin_info != voucher_input.name()  # type: ignore[union-attr]
            or terminal_voucher.puzzle_hash != expected_terminal_puzzle_hash  # type: ignore[union-attr]
            or int(terminal_voucher.amount) != 1  # type: ignore[union-attr]
        ):
            raise RuntimeError("Stripe refund did not burn the exact voucher")
        current = _series_state(series)
        next_state = VoucherSeriesStateV2(
            sold_count=current.sold_count,
            redeemed_count=current.redeemed_count,
            refunded_count=current.refunded_count + 1,
            phase=current.phase,
            launched_at=current.launched_at,
        )
        next_inner = curry_series(terms, next_state)
        expected_series_puzzle_hash = puzzle_for_singleton(
            terms.series_singleton_id,
            next_inner,
        ).get_tree_hash()
        if (
            series_output.parent_coin_info != series_input.name()  # type: ignore[union-attr]
            or series_output.puzzle_hash != expected_series_puzzle_hash  # type: ignore[union-attr]
            or int(series_output.amount) != 1  # type: ignore[union-attr]
        ):
            raise RuntimeError("Stripe refund changed series successor state")
        if vault_input_id:
            vault_input = coins["vault_input"]
            vault_output = coins["vault_output"]
            assert vault_input is not None and vault_output is not None
            if (
                vault_output.parent_coin_info != vault_input.name()
                or vault_output.puzzle_hash != vault_input.puzzle_hash
                or int(vault_output.amount) != 1
            ):
                raise RuntimeError(
                    "Stripe refund did not atomically advance the owner vault"
                )
        self.presales.confirm_stripe_refund(
            str(series["termsHash"]),
            int(voucher["serial"]),
            StripeVoucherRefundChainEvidence(
                action=int(action),
                evidenceId="chia:" + str(voucher["refundBundleId"]),
                spendBundleId=str(voucher["refundBundleId"]),
                externalSettlementEvidenceHash=evidence_hash,
                terminalVoucherCoinId=ids["terminal_voucher"],
                seriesInputCoinId=ids["series_input"],
                seriesInputParentCoinId=_hex32(
                    series_input.parent_coin_info  # type: ignore[union-attr]
                ),
                seriesOutputCoinId=ids["series_output"],
                seriesOutputInnerPuzzleHash=_hex32(next_inner.get_tree_hash()),
                vaultInputCoinId=ids.get("vault_input"),
                vaultOutputCoinId=ids.get("vault_output"),
                confirmedHeight=next(iter(heights)),
            ),
        )
        return True

    async def _confirm_base_refund_if_ready(
        self,
        series: dict[str, Any],
        voucher: dict[str, Any],
    ) -> bool:
        ids = {
            "terminal_voucher": str(voucher["terminalVoucherCoinId"] or ""),
            "series_output": str(voucher["refundSeriesOutputCoinId"] or ""),
            "series_input": str(voucher["refundSeriesInputCoinId"] or ""),
            "voucher_input": str(voucher["voucherOutputCoinId"] or ""),
            "receipt_input": str(voucher["paymentCommitmentCoinId"] or ""),
        }
        evidence_hash = str(
            voucher.get("externalSettlementEvidenceHash") or ""
        )
        if any(not value for value in ids.values()) or not evidence_hash:
            raise RuntimeError("Base refund is missing chain bindings")
        records = {
            name: await self.coinset.get_coin_record_by_name(coin_id)
            for name, coin_id in ids.items()
        }
        output_names = ("terminal_voucher", "series_output")
        input_names = ("series_input", "voucher_input", "receipt_input")
        if any(not _is_confirmed(records[name]) for name in output_names):
            return False
        if any(not _is_spent(records[name]) for name in input_names):
            return False
        heights = {
            int(records[name].get("confirmed_block_index") or 0)
            for name in output_names
        }
        spent_heights = {
            int(records[name].get("spent_block_index") or 0)
            for name in input_names
        }
        if len(heights) != 1 or spent_heights != heights:
            raise RuntimeError(
                "Base refund inputs and outputs are not atomic"
            )
        coins = {
            name: _coin_from_record(record)
            for name, record in records.items()
        }
        if any(coin is None for coin in coins.values()):
            raise RuntimeError("Base refund has malformed coin records")
        for name, coin_id in ids.items():
            coin = coins[name]
            assert coin is not None
            if _hex32(coin.name()) != coin_id.lower():
                raise RuntimeError(f"Base refund {name} coin ID changed")

        terms = series_terms_from_json(series["terms"])
        commitment = voucher_commitment_from_json(voucher["commitment"])
        try:
            action = VoucherAction(int(voucher["refundAction"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Base refund has no valid action binding") from exc
        terminal_voucher = coins["terminal_voucher"]
        voucher_input = coins["voucher_input"]
        series_input = coins["series_input"]
        series_output = coins["series_output"]
        assert all(
            coin is not None
            for coin in (
                terminal_voucher,
                voucher_input,
                series_input,
                series_output,
            )
        )
        expected_terminal_puzzle_hash = puzzle_for_singleton(
            _b32(voucher["voucherLauncherId"]),
            curry_base_result_authorization(
                terms=terms,
                voucher=commitment,
                action=action,
            ),
        ).get_tree_hash()
        if (
            terminal_voucher.parent_coin_info != voucher_input.name()  # type: ignore[union-attr]
            or terminal_voucher.puzzle_hash != expected_terminal_puzzle_hash  # type: ignore[union-attr]
            or int(terminal_voucher.amount) != 1  # type: ignore[union-attr]
        ):
            raise RuntimeError(
                "Base refund terminal authorization changed"
            )
        current = _series_state(series)
        next_state = VoucherSeriesStateV2(
            sold_count=current.sold_count,
            redeemed_count=current.redeemed_count,
            refunded_count=current.refunded_count + 1,
            phase=current.phase,
            launched_at=current.launched_at,
        )
        next_inner = curry_series(terms, next_state)
        expected_series_puzzle_hash = puzzle_for_singleton(
            terms.series_singleton_id,
            next_inner,
        ).get_tree_hash()
        if (
            series_output.parent_coin_info != series_input.name()  # type: ignore[union-attr]
            or series_output.puzzle_hash != expected_series_puzzle_hash  # type: ignore[union-attr]
            or int(series_output.amount) != 1  # type: ignore[union-attr]
        ):
            raise RuntimeError("Base refund changed series successor state")
        self.presales.confirm_base_refund(
            str(series["termsHash"]),
            int(voucher["serial"]),
            BaseVoucherRefundChainEvidence(
                action=int(VoucherAction.REFUND_EXPIRED),
                evidenceId="chia:" + str(voucher["refundBundleId"]),
                spendBundleId=str(voucher["refundBundleId"]),
                externalSettlementEvidenceHash=evidence_hash,
                terminalVoucherCoinId=ids["terminal_voucher"],
                seriesInputCoinId=ids["series_input"],
                seriesInputParentCoinId=_hex32(
                    series_input.parent_coin_info  # type: ignore[union-attr]
                ),
                seriesOutputCoinId=ids["series_output"],
                seriesOutputInnerPuzzleHash=_hex32(next_inner.get_tree_hash()),
                confirmedHeight=next(iter(heights)),
            ),
        )
        return True

    async def _confirm_phase_if_ready(self, series: dict[str, Any]) -> bool:
        phase = series["phaseTransition"]
        input_id = str(phase["inputCoinId"] or "")
        output_id = str(phase["outputCoinId"] or "")
        if not input_id or not output_id:
            raise RuntimeError("series phase submission is missing chain bindings")
        input_record = await self.coinset.get_coin_record_by_name(input_id)
        output_record = await self.coinset.get_coin_record_by_name(output_id)
        if not _is_confirmed(output_record) or not _is_spent(input_record):
            return False
        confirmed_height = int(output_record.get("confirmed_block_index") or 0)
        if int(input_record.get("spent_block_index") or 0) != confirmed_height:
            raise RuntimeError("series phase input and output are not atomic")
        input_coin = _coin_from_record(input_record)
        output_coin = _coin_from_record(output_record)
        if input_coin is None or output_coin is None:
            raise RuntimeError("series phase confirmation has malformed coin records")
        if (
            _hex32(input_coin.name()) != input_id.lower()
            or _hex32(output_coin.name()) != output_id.lower()
            or output_coin.parent_coin_info != input_coin.name()
            or int(output_coin.amount) != 1
        ):
            raise RuntimeError("series phase successor coin changed")
        current = _series_state(series)
        target = str(phase["targetState"])
        launch_anchor = int(phase["launchAnchor"] or 0)
        next_state = VoucherSeriesStateV2(
            sold_count=current.sold_count,
            redeemed_count=current.redeemed_count,
            refunded_count=current.refunded_count,
            phase=(
                VoucherSeriesState.LIVE
                if target == "LIVE"
                else VoucherSeriesState.CANCELED
            ),
            launched_at=launch_anchor if target == "LIVE" else 0,
        )
        terms = series_terms_from_json(series["terms"])
        next_inner = curry_series(terms, next_state)
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton

        expected_full = puzzle_for_singleton(terms.series_singleton_id, next_inner)
        if (
            output_coin.puzzle_hash != expected_full.get_tree_hash()
            or _hex32(next_inner.get_tree_hash())
            != str(phase["outputInnerPuzzleHash"]).lower()
        ):
            raise RuntimeError("series phase successor puzzle changed")
        self.presales.confirm_phase_transition(
            str(series["termsHash"]),
            VoucherSeriesPhaseChainEvidence(
                evidenceId="chia:" + str(phase["spendBundleId"]),
                spendBundleId=str(phase["spendBundleId"]),
                targetState=target,
                seriesInputCoinId=input_id,
                seriesInputParentCoinId=_hex32(input_coin.parent_coin_info),
                seriesOutputCoinId=output_id,
                seriesOutputInnerPuzzleHash=_hex32(next_inner.get_tree_hash()),
                launchAnchor=launch_anchor,
                confirmedHeight=confirmed_height,
            ),
            include_vouchers=False,
        )
        return True


def _series_state(series: Mapping[str, Any]) -> VoucherSeriesStateV2:
    chain = series["chainState"]
    state_name = str(series["state"])
    phase = {
        "PRESALE": VoucherSeriesState.PRESALE,
        "LIVE": VoucherSeriesState.LIVE,
        "CANCELED": VoucherSeriesState.CANCELED,
    }[state_name]
    return VoucherSeriesStateV2(
        sold_count=int(chain["soldCount"]),
        redeemed_count=int(chain["redeemedCount"]),
        refunded_count=int(chain["refundedCount"]),
        phase=phase,
        launched_at=int(series.get("launchedAt") or 0),
    )


def _b32(value: Any) -> bytes32:
    return bytes32.fromhex(str(value).removeprefix("0x"))


def _hex32(value: Any) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be bytes32")
    return "0x" + raw.hex()


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping) or not isinstance(record.get("coin"), Mapping):
        return None
    coin = record["coin"]
    try:
        return Coin(
            _b32(coin["parent_coin_info"]),
            _b32(coin["puzzle_hash"]),
            uint64(int(coin["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _is_confirmed(record: Any) -> bool:
    return isinstance(record, Mapping) and int(record.get("confirmed_block_index") or 0) > 0


def _is_spent(record: Any) -> bool:
    return _is_confirmed(record) and int(record.get("spent_block_index") or 0) > 0


def _confirmed_unspent_coin(record: Any) -> Coin | None:
    coin = _coin_from_record(record)
    if (
        coin is None
        or not _is_confirmed(record)
        or bool(record.get("spent"))
        or int(record.get("spent_block_index") or 0) != 0
    ):
        return None
    return coin


def _one_output(
    additions: list[Coin],
    puzzle_hash: bytes32,
    amount: int,
    label: str,
) -> Coin:
    matches = [
        coin
        for coin in additions
        if coin.puzzle_hash == puzzle_hash and int(coin.amount) == int(amount)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"voucher redemption must create exactly one {label}; found {len(matches)}"
        )
    return matches[0]


def _deed_vault_full_puzzle_hash(
    deed_launcher_id: bytes32,
    vault_launcher_id: bytes32,
) -> bytes32:
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    return bytes32(
        SINGLETON_MOD.curry(
            singleton_struct,
            puzzle_for_p2_vault(vault_launcher_id),
        ).get_tree_hash()
    )


def _require_push_accepted(result: Mapping[str, Any], label: str) -> None:
    status = str(result.get("status") or "").upper()
    if not result.get("success") and status not in {"SUCCESS", "PENDING"}:
        reason = result.get("error") or status or "unknown node rejection"
        raise RuntimeError(f"{label} was rejected by the Chia node: {reason}")


__all__ = ["VoucherIssuanceWorker", "VoucherIssuanceWorkerConfig"]
