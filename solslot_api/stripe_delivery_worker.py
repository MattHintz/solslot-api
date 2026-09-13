"""Crash-safe Stripe receipt and exact protocol-asset delivery coordinator."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Mapping

from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseDeliveryKind,
    PurchaseBatchV1,
    STRIPE_PAYMENT_PROVIDER_ID,
    build_purchase_batch_settlement_receipt_v1,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_from_json,
    purchase_batch_from_json,
    stripe_settlement_evidence_from_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    PurchaseBatchSettlementTermsV1,
    build_stripe_primary_offer_v5,
    build_external_primary_batch_offer_v5,
    build_purchase_batch_receipt_spend,
    prepare_stripe_receipt_offer,
    prepare_purchase_batch_receipt_offer,
    StripeSettlementTermsV1,
    curry_purchase_batch_settlement_receipt,
    curry_stripe_settlement_receipt,
    stripe_settlement_receipt_solution,
)
from solslot_puzzles.sgt_driver import sgt_free_inner_puzzle, sgt_locked_inner_mod
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    build_sgt_external_sale_spend,
)
from solslot_puzzles.vault_driver import (
    puzzle_for_p2_vault,
    puzzle_hash_for_p2_vault,
)
from .config import Settings
from .base_direct_settlement import build_direct_settlement_authorization
from .credential_auth import require_minting_writes
from .external_settlement import (
    base_result_authorization_puzzle_hash,
    build_base_batch_settlement_receipt,
    build_base_settlement_receipt,
)
from .faucet import Faucet
from .launch_gates import require_operation_gate
from .native_purchases import _load_context_group
from .omnichain_evidence import load_omnichain_evidence
from .governance_queue import GovernanceQueueStore
from .governance_sale_offer import (
    reconstruct_governed_sale_coin,
    reconstruct_governed_sale_lineage,
)
from .governed_output_index import (
    CONFIRMED as GOVERNED_CONFIRMED,
    GovernedOutputConflict,
    GovernedOutputExpectation,
    EvaluatedBundleOutputs,
    get_governed_output_index,
    reconcile_governed_delivery,
)
from .kos_exact_execution import (
    ExactExecutionAction,
    ExactExecutionOutput,
    ExactExecutionRequest,
    KeyOfSolomonExactExecutor,
)
from .payment_purchase_store import get_payment_purchase_store
from .protocol_submission import PreparedProtocolBundle, ProtocolBundleSubmitter
from .public_artifact import load_signed_public_artifact
from .state import get_registry
from .stripe_delivery_store import (
    DELIVERY_PREPARED,
    DELIVERY_SUBMITTED,
    EXTERNAL_SETTLEMENT_PENDING,
    FINALIZED,
    PAYMENT_VERIFIED,
    RECEIPT_CONFIRMED,
    RECEIPT_FUNDING_PREPARED,
    RECEIPT_FUNDING_SUBMITTED,
    PAYMENT_RAIL_BASE_USDC,
    PAYMENT_RAIL_STRIPE,
    StripeDeliveryOperation,
    StripeDeliveryStore,
)
from .vault_eligibility import require_current_approved_vault
from .validator_quorum import (
    PrimaryPurchaseDeedItem,
    StripeSettlementClaim,
    collect_stripe_settlement_quorum,
    configured_validator_pubkeys,
)


logger = logging.getLogger(__name__)
_CREATE_COIN = 51


class StripeDeliveryError(RuntimeError):
    """The exact paid delivery cannot safely advance."""


class StripeDeliveryManualReview(StripeDeliveryError):
    """Chain state conflicts with the operation's immutable commitments."""


@dataclass(frozen=True)
class StripeDeliveryWorkerConfig:
    enabled: bool = False
    interval_seconds: float = 15.0
    lease_seconds: int = 60


class StripeDeliveryWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        faucet: Faucet,
        provider: Any,
        submitter: ProtocolBundleSubmitter,
        exact_executor: KeyOfSolomonExactExecutor,
        store: StripeDeliveryStore,
        config: StripeDeliveryWorkerConfig,
    ) -> None:
        self.settings = settings
        self.faucet = faucet
        self.provider = provider
        self.submitter = submitter
        self.exact_executor = exact_executor
        self.store = store
        self.output_index = get_governed_output_index(
            settings.payment_purchase_db_path
        )
        self.config = config
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._advance_lock = asyncio.Lock()
        self._owner = f"stripe-delivery-{id(self):x}"

    async def start(self) -> None:
        if not self.config.enabled or (self._task and not self._task.done()):
            return
        self._stop.clear()
        self._task = asyncio.create_task(
            self._run_forever(), name="solslot-stripe-delivery"
        )
        logger.info(
            "Stripe protocol-asset delivery worker started; interval=%ss",
            self.config.interval_seconds,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                await self.reconcile_once()
            except Exception:  # noqa: BLE001
                logger.exception("Stripe protocol-asset delivery reconciliation failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.config.interval_seconds
                )
            except asyncio.TimeoutError:
                pass

    async def reconcile_once(
        self,
        purchase_id: str | None = None,
    ) -> StripeDeliveryOperation | None:
        if not self._writes_are_open():
            return None
        async with self._advance_lock:
            operation = (
                self.store.claim(
                    purchase_id,
                    owner=self._owner,
                    lease_seconds=self.config.lease_seconds,
                )
                if purchase_id is not None
                else self.store.claim_next(
                    owner=self._owner,
                    lease_seconds=self.config.lease_seconds,
                )
            )
            if operation is None or operation.state == FINALIZED:
                return operation
            if not self._rail_is_enabled(operation):
                return self.store.release_lease(operation.purchase_id)
            try:
                return await self._advance(operation)
            except StripeDeliveryManualReview as exc:
                logger.error(
                    "Stripe purchase %s requires manual review: %s",
                    operation.purchase_id,
                    exc,
                )
                return self.store.record_manual_review(
                    operation.purchase_id,
                    error=str(exc),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Stripe purchase %s remains retryable: %s",
                    operation.purchase_id,
                    exc,
                )
                return self.store.record_error(operation.purchase_id, str(exc))

    def _writes_are_open(self) -> bool:
        if not (
            self.config.enabled
            and self.settings.protocol_fee_funding_enabled
            and (
                self.settings.stripe_settlement_enabled
                or self.settings.payment_omnichain_enabled
            )
        ):
            return False
        try:
            require_minting_writes(self.settings)
            require_operation_gate(self.settings, "purchases")
        except HTTPException:
            return False
        return True

    def _rail_is_enabled(self, operation: StripeDeliveryOperation) -> bool:
        if operation.payment_rail == PAYMENT_RAIL_STRIPE:
            return self.settings.stripe_settlement_enabled
        if operation.payment_rail == PAYMENT_RAIL_BASE_USDC:
            return self.settings.payment_omnichain_enabled
        return False

    async def _advance(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        if operation.state == PAYMENT_VERIFIED:
            return await self._prepare_receipt_funding(operation)
        if operation.state == RECEIPT_FUNDING_PREPARED:
            return await self._submit_or_recover_receipt_funding(operation)
        if operation.state == RECEIPT_FUNDING_SUBMITTED:
            return await self._confirm_receipt(operation)
        if operation.state == RECEIPT_CONFIRMED:
            return await self._prepare_delivery(operation)
        if operation.state == DELIVERY_PREPARED:
            return await self._submit_or_recover_delivery(operation)
        if operation.state == DELIVERY_SUBMITTED:
            return await self._confirm_delivery(operation)
        if operation.state == EXTERNAL_SETTLEMENT_PENDING:
            if operation.settlement_authorization is None:
                purchase = self._stored_purchase_document(operation.purchase_id)
                authorization_id, authorization = (
                    build_direct_settlement_authorization(
                        operation=operation,
                        purchase=purchase,
                    )
                )
                return self.store.record_external_settlement_authorization(
                    operation.purchase_id,
                    authorization_id=authorization_id,
                    authorization=authorization,
                )
            return self.store.release_lease(operation.purchase_id)
        return operation

    def _receipt_terms(self, operation: StripeDeliveryOperation):
        purchase_document = self._stored_purchase_document(
            operation.purchase_id
        )
        batch = (
            purchase_document
            if isinstance(purchase_document, PurchaseBatchV1)
            else None
        )
        purchase = (
            batch.artifacts[0] if batch is not None else purchase_document
        )
        validator_pubkeys = configured_validator_pubkeys(self.settings)
        result_puzzle_hash = bytes32.zeros
        if operation.payment_rail == PAYMENT_RAIL_STRIPE:
            evidence = stripe_settlement_evidence_from_json(operation.evidence)
            receipt = (
                build_purchase_batch_settlement_receipt_v1(
                    batch=batch,
                    provider_id=STRIPE_PAYMENT_PROVIDER_ID,
                    external_reference_hash=evidence.payment_reference_hash,
                    evidence_hash=evidence.evidence_hash,
                    observed_at=evidence.observed_at,
                    validator_pubkeys=validator_pubkeys,
                    collected_amount_minor=evidence.amount_minor,
                    processing_charge_minor=evidence.processing_charge_minor,
                )
                if batch is not None
                else build_stripe_settlement_receipt_v1(
                    artifact=purchase,
                    evidence=evidence,
                    validator_pubkeys=validator_pubkeys,
                )
            )
        elif operation.payment_rail == PAYMENT_RAIL_BASE_USDC:
            token = self.settings.payment_evm_usdc_tokens.get(
                str(purchase.rail_chain_id)
            )
            if not token:
                raise StripeDeliveryManualReview(
                    "Base settlement token is disabled"
                )
            deployment = load_omnichain_evidence(
                self.settings,
                chain_id=purchase.rail_chain_id,
                token_address=token,
                gateway_profile=str(
                    operation.evidence.get("gatewayProfile") or ""
                ),
            )
            try:
                result_puzzle_hash = base_result_authorization_puzzle_hash(
                    artifact=purchase_document,
                    evidence=operation.evidence,
                    return_puzzle_hash=bytes32.from_hexstr(
                        deployment.return_puzzle_hash
                    ),
                )
                receipt = (
                    build_base_batch_settlement_receipt(
                        batch=batch,
                        evidence=operation.evidence,
                        validator_pubkeys=validator_pubkeys,
                        result_authorization_puzzle_hash=result_puzzle_hash,
                    )
                    if batch is not None
                    else build_base_settlement_receipt(
                        artifact=purchase,
                        evidence=operation.evidence,
                        result_authorization_puzzle_hash=result_puzzle_hash,
                    )
                )
            except (ValueError, PaymentArtifactError) as exc:
                raise StripeDeliveryManualReview(
                    "Base result authorization cannot be reconstructed"
                ) from exc
        else:
            raise StripeDeliveryManualReview("unsupported external payment rail")
        if _hex32(receipt.receipt_hash) != operation.receipt_hash.lower():
            raise StripeDeliveryManualReview(
                "stored Stripe receipt hash differs from canonical evidence"
            )
        terms = (
            PurchaseBatchSettlementTermsV1(
                receipt=receipt,
                validator_pubkeys=validator_pubkeys,
            )
            if batch is not None
            else StripeSettlementTermsV1(
                receipt=receipt,
                validator_pubkeys=validator_pubkeys,
            )
        )
        if receipt.result_authorization_puzzle_hash != result_puzzle_hash:
            raise StripeDeliveryManualReview(
                "external receipt result authorization differs from deployment evidence"
            )
        return purchase_document, receipt, terms

    def _stored_purchase(self, purchase_id: str) -> dict[str, Any]:
        return self._stored_record(purchase_id).purchase_artifact

    def _stored_purchase_document(self, purchase_id: str):
        raw = self._stored_purchase(purchase_id)
        return (
            purchase_batch_from_json(raw)
            if raw.get("schema") == "solslot.purchase-batch.v1"
            else purchase_artifact_v3_from_json(raw)
        )

    def _stored_record(self, purchase_id: str):
        return get_payment_purchase_store(
            self.settings.payment_purchase_db_path
        ).get(purchase_id)

    async def _prepare_receipt_funding(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        purchase, _receipt, terms = self._receipt_terms(operation)
        receipt_amount = (
            purchase.quantity if isinstance(purchase, PurchaseBatchV1) else 1
        )
        receipt_puzzle = (
            curry_purchase_batch_settlement_receipt(terms)
            if isinstance(purchase, PurchaseBatchV1)
            else curry_stripe_settlement_receipt(terms)
        )
        parent = await self._select_faucet_coin(receipt_amount)
        conditions = [
            Program.to(
                [
                    _CREATE_COIN,
                    bytes32(receipt_puzzle.get_tree_hash()),
                    receipt_amount,
                    [terms.receipt.receipt_hash],
                ]
            )
        ]
        change = int(parent.amount) - receipt_amount
        if change:
            conditions.append(
                Program.to(
                    [_CREATE_COIN, self.faucet.address_puzzle_hash, change]
                )
            )
        condition_program = Program.to(conditions)
        delegated = Program.to((1, condition_program))
        parent_spend = make_spend(
            parent,
            self.faucet.key.puzzle,
            Program.to([0, delegated, Program.to(0)]),
        )
        signature = G2Element.from_bytes(
            self.faucet.sign_delegated_spend(parent, condition_program)
        )
        protocol_bundle = SpendBundle([parent_spend], signature)
        receipt_coin = Coin(
            bytes32(parent.name()),
            bytes32(receipt_puzzle.get_tree_hash()),
            uint64(receipt_amount),
        )
        return self.store.record_receipt_prepared(
            operation.purchase_id,
            input_coin_id=_hex32(parent.name()),
            protocol_bundle=protocol_bundle.to_json_dict(),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
        )

    async def _submit_or_recover_receipt_funding(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        if not operation.receipt_coin_id or not operation.receipt_funding_input_coin_id:
            raise StripeDeliveryManualReview("prepared receipt funding is incomplete")
        receipt_amount = self._receipt_amount(operation)
        if await self._is_exact_confirmed_output(
            operation.receipt_coin_id,
            operation.receipt_puzzle_hash,
            receipt_amount,
            require_unspent=True,
        ):
            return self.store.record_receipt_confirmed(operation.purchase_id)
        input_record = await self.provider.get_coin_record_by_name(
            operation.receipt_funding_input_coin_id
        )
        pending_id = await self._mempool_bundle_id(
            operation.receipt_funding_input_coin_id
        )
        if pending_id:
            if operation.receipt_funding_exact_bundle is None:
                raise StripeDeliveryManualReview(
                    "receipt input is pending without a persisted exact KoS bundle"
                )
            prepared = _prepared_from_binding(
                operation.receipt_funding_exact_bundle
            )
            if pending_id != _hex32(prepared.bundle.name()):
                raise StripeDeliveryManualReview(
                    "receipt input is reserved by a different mempool bundle"
                )
            return self.store.record_receipt_funding(
                operation.purchase_id,
                bundle_id=pending_id,
                receipt_coin_id=operation.receipt_coin_id,
                receipt_puzzle_hash=str(operation.receipt_puzzle_hash),
                fee_mojos=prepared.fee_mojos,
                mempool_observed_at=_utc_now(),
            )
        if _is_spent(input_record):
            raise StripeDeliveryManualReview(
                "receipt funding input was spent without its committed receipt output"
            )
        if operation.receipt_funding_bundle is None:
            raise StripeDeliveryManualReview("prepared receipt bundle is missing")
        request = self._exact_execution_request(
            operation,
            action=ExactExecutionAction.RECEIPT,
            outputs=_bound_outputs(
                operation.receipt_funding_bundle,
                (operation.receipt_coin_id,),
            ),
        )
        if operation.receipt_funding_exact_bundle is None:
            async def dispatch(prepared: PreparedProtocolBundle):
                self.store.bind_receipt_exact_bundle(
                    operation.purchase_id,
                    exact_bundle=prepared.to_json(),
                )
                return await self.exact_executor.dispatch(request, prepared)

            result = await self.submitter.prepare_and_dispatch(
                operation.receipt_funding_bundle,
                dispatch,
            )
        else:
            prepared = _prepared_from_binding(
                operation.receipt_funding_exact_bundle
            )
            await self.exact_executor.dispatch(request, prepared)
            result = prepared.to_json()
        return self.store.record_receipt_funding(
            operation.purchase_id,
            bundle_id=str(result["spendBundleId"]).lower(),
            receipt_coin_id=operation.receipt_coin_id,
            receipt_puzzle_hash=str(operation.receipt_puzzle_hash),
            fee_mojos=int(result["feeMojos"]),
            mempool_observed_at=_utc_now(),
        )

    async def _confirm_receipt(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        if not operation.receipt_coin_id:
            raise StripeDeliveryManualReview("receipt coin binding is missing")
        if await self._is_exact_confirmed_output(
            operation.receipt_coin_id,
            operation.receipt_puzzle_hash,
            self._receipt_amount(operation),
            require_unspent=True,
        ):
            return self.store.record_receipt_confirmed(operation.purchase_id)
        return self.store.release_lease(operation.purchase_id)

    def _receipt_amount(self, operation: StripeDeliveryOperation) -> int:
        if operation.receipt_funding_bundle and operation.receipt_coin_id:
            bundle = SpendBundle.from_json_dict(operation.receipt_funding_bundle)
            matches = [
                int(coin.amount)
                for coin in bundle.additions()
                if _hex32(coin.name()) == operation.receipt_coin_id.lower()
            ]
            if len(matches) != 1:
                raise StripeDeliveryManualReview(
                    "persisted receipt funding bundle has no exact receipt output"
                )
            return matches[0]
        purchase = self._stored_purchase_document(operation.purchase_id)
        return purchase.quantity if isinstance(purchase, PurchaseBatchV1) else 1

    async def _prepare_delivery(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        purchase_document, receipt, receipt_terms = self._receipt_terms(operation)
        batch = (
            purchase_document
            if isinstance(purchase_document, PurchaseBatchV1)
            else None
        )
        purchase = (
            batch.artifacts[0] if batch is not None else purchase_document
        )
        expected_rail = (
            PaymentRail.STRIPE
            if operation.payment_rail == PAYMENT_RAIL_STRIPE
            else PaymentRail.EVM_TEST_USD
        )
        if purchase.rail != expected_rail or not operation.receipt_coin_id:
            raise StripeDeliveryManualReview("delivery payment rail changed")
        receipt_record = await self.provider.get_coin_record_by_name(
            operation.receipt_coin_id
        )
        receipt_coin = _confirmed_unspent_coin(receipt_record)
        if receipt_coin is None:
            return self.store.release_lease(operation.purchase_id)
        if purchase.delivery_kind == PurchaseDeliveryKind.SGT:
            if batch is not None:
                raise StripeDeliveryManualReview(
                    "SGT delivery cannot use a SmartDeed purchase batch"
                )
            return await self._prepare_sgt_delivery(
                operation=operation,
                purchase=purchase,
                receipt=receipt,
                receipt_terms=receipt_terms,
                receipt_coin=receipt_coin,
            )
        if purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED:
            raise StripeDeliveryManualReview(
                "external purchase has an unsupported delivery kind"
            )
        if batch is not None:
            return await self._prepare_smartdeed_batch_delivery(
                operation=operation,
                batch=batch,
                receipt=receipt,
                receipt_terms=receipt_terms,
                receipt_coin=receipt_coin,
                expected_rail=expected_rail,
            )
        group = await _load_context_group(
            self.settings,
            self.provider,
            operation.purchase_id,
            require_live=False,
            allowed_rails=(expected_rail,),
        )
        if (
            group.batch is not None
            or len(group.contexts) != 1
            or group.contexts[0].purchase != purchase
        ):
            raise StripeDeliveryManualReview(
                "Single SmartDeed differs from its canonical inventory"
            )
        context = group.contexts[0]
        if context.reservation is None:
            raise StripeDeliveryManualReview(
                "SmartDeed reservation terms are unavailable"
            )
        claim = StripeSettlementClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(context.genesis_artifact["artifactHash"]).lower(),
            purchase_artifact=context.stored.purchase_artifact,
            stripe_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else None
            ),
            base_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            base_result_authorization_puzzle_hash=(
                _hex32(
                    receipt.result_authorization_puzzle_hash
                )
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
            deed_coin_id=_hex32(context.deed_coin.name()),
            deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
            smart_deed_inner_hash=_hex32(context.terms.smart_deed_inner_hash),
            reservation_expires_at=context.reservation.expires_at,
            protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
            credential_vault_coin_id=str(
                context.credential_receipt["chiaVaultCoinId"]
            ),
            credential_identity_root=str(
                context.credential_receipt["identityAttestRoot"]
            ),
            credential_policy_version=int(
                context.credential_receipt["policyVersion"]
            ),
            credential_bridge_policy_hash=str(
                context.credential_receipt["bridgePolicyHash"]
            ),
            credential_owner_auth_type=context.credential_owner_auth_type,
            credential_owner_key="0x" + context.credential_owner_key.hex(),
        )
        quorum = await collect_stripe_settlement_quorum(self.settings, claim)
        receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
        receipt_spend = make_spend(
            receipt_coin,
            receipt_puzzle,
            stripe_settlement_receipt_solution(
                receipt_coin=receipt_coin,
                signer_indices=quorum.signer_indices,
            ),
        )
        buyer_offer = prepare_stripe_receipt_offer(
            receipt_spend=receipt_spend,
            receipt=receipt,
            terms=context.terms,
            deed_singleton_struct=context.deed_struct,
        )
        primary = build_stripe_primary_offer_v5(
            receipt_offer=buyer_offer,
            receipt=receipt,
            receipt_coin=receipt_coin,
            deed_coin=context.deed_coin,
            deed_singleton_struct=context.deed_struct,
            lineage_proof=context.deed_lineage,
            terms=context.terms,
            reservation=context.reservation,
        )
        valid = primary.aggregate_offer.to_valid_spend()
        signed = WalletSpendBundle(
            valid.coin_spends,
            AugSchemeMPL.aggregate(
                [valid.aggregated_signature, quorum.aggregated_signature]
            ),
        )
        evaluated = EvaluatedBundleOutputs(signed)
        additions = evaluated.additions
        vault_full = SINGLETON_MOD.curry(
            context.deed_struct,
            puzzle_for_p2_vault(purchase.vault_launcher_id),
        )
        try:
            deed_output = evaluated.find_exact_descendant(
                ancestor_coin_id=context.deed_coin.name(),
                puzzle_hash=bytes32(vault_full.get_tree_hash()),
                amount=1,
                label="vault SmartDeed",
            )
        except GovernedOutputConflict as exc:
            raise StripeDeliveryManualReview(str(exc)) from exc
        treasury_output = _one_output(
            additions,
            puzzle_hash=(
                receipt.result_authorization_puzzle_hash
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else context.terms.protocol_puzhash
            ),
            amount=1,
            label=(
                "Base result authorization"
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else "receipt treasury"
            ),
        )
        self._prepare_governed_index(
            operation=operation,
            artifact_hash=_hex32(purchase.artifact_hash),
            delivery_kind="smartdeed",
            quantity=1,
            bundle=signed,
            outputs=(
                GovernedOutputExpectation(
                    ordinal=0,
                    deed_launcher_id=_hex32(purchase.deed_launcher_id),
                    coin_id=_hex32(deed_output.name()),
                    parent_coin_id=_hex32(deed_output.parent_coin_info),
                    puzzle_hash=_hex32(deed_output.puzzle_hash),
                    amount=1,
                ),
            ),
        )
        return self.store.record_delivery_prepared(
            operation.purchase_id,
            protocol_bundle=signed.to_json_dict(),
            delivery_output_coin_id=_hex32(deed_output.name()),
            treasury_output_coin_id=_hex32(treasury_output.name()),
            signer_indices=quorum.signer_indices,
        )

    async def _prepare_smartdeed_batch_delivery(
        self,
        *,
        operation: StripeDeliveryOperation,
        batch: PurchaseBatchV1,
        receipt: Any,
        receipt_terms: PurchaseBatchSettlementTermsV1,
        receipt_coin: Coin,
        expected_rail: PaymentRail,
    ) -> StripeDeliveryOperation:
        group = await _load_context_group(
            self.settings,
            self.provider,
            operation.purchase_id,
            require_live=False,
            allowed_rails=(expected_rail,),
        )
        if group.batch != batch or len(group.contexts) != batch.quantity:
            raise StripeDeliveryManualReview(
                "SmartDeed batch differs from its canonical inventory"
            )
        if any(context.reservation is None for context in group.contexts):
            raise StripeDeliveryManualReview(
                "SmartDeed batch reservation terms are incomplete"
            )
        first = group.contexts[0]
        if any(
            context.credential_receipt != first.credential_receipt
            or context.credential_owner_auth_type
            != first.credential_owner_auth_type
            or context.credential_owner_key != first.credential_owner_key
            for context in group.contexts[1:]
        ):
            raise StripeDeliveryManualReview(
                "SmartDeed batch does not share one approved vault credential"
            )
        deed_items = tuple(
            PrimaryPurchaseDeedItem(
                deed_launcher_id=_hex32(context.purchase.deed_launcher_id),
                deed_coin_id=_hex32(context.deed_coin.name()),
                deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
                smart_deed_inner_hash=_hex32(
                    context.terms.smart_deed_inner_hash
                ),
                reservation_expires_at=int(context.reservation.expires_at),
            )
            for context in group.contexts
            if context.reservation is not None
        )
        claim = StripeSettlementClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(
                first.genesis_artifact["artifactHash"]
            ).lower(),
            purchase_artifact=group.stored.purchase_artifact,
            stripe_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else None
            ),
            base_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            base_result_authorization_puzzle_hash=(
                _hex32(receipt.result_authorization_puzzle_hash)
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
            deed_items=deed_items,
            protocol_puzzle_hash=_hex32(first.terms.protocol_puzhash),
            credential_vault_coin_id=str(
                first.credential_receipt["chiaVaultCoinId"]
            ),
            credential_identity_root=str(
                first.credential_receipt["identityAttestRoot"]
            ),
            credential_policy_version=int(
                first.credential_receipt["policyVersion"]
            ),
            credential_bridge_policy_hash=str(
                first.credential_receipt["bridgePolicyHash"]
            ),
            credential_owner_auth_type=first.credential_owner_auth_type,
            credential_owner_key="0x" + first.credential_owner_key.hex(),
        )
        quorum = await collect_stripe_settlement_quorum(self.settings, claim)
        receipt_spend = build_purchase_batch_receipt_spend(
            receipt_coin=receipt_coin,
            terms=receipt_terms,
            signer_indices=quorum.signer_indices,
        )
        item_terms = tuple(context.terms for context in group.contexts)
        receipt_offer = prepare_purchase_batch_receipt_offer(
            receipt_spend=receipt_spend,
            receipt=receipt,
            terms=item_terms,
            deed_singleton_structs=tuple(
                context.deed_struct for context in group.contexts
            ),
        )
        primary = build_external_primary_batch_offer_v5(
            receipt_offer=receipt_offer,
            receipt_coin=receipt_coin,
            receipt=receipt,
            deed_coins=tuple(context.deed_coin for context in group.contexts),
            deed_singleton_structs=tuple(
                context.deed_struct for context in group.contexts
            ),
            lineage_proofs=tuple(
                context.deed_lineage for context in group.contexts
            ),
            terms=item_terms,
            reservations=tuple(
                context.reservation
                for context in group.contexts
                if context.reservation is not None
            ),
        )
        valid = primary.aggregate_offer.to_valid_spend()
        signed = WalletSpendBundle(
            valid.coin_spends,
            AugSchemeMPL.aggregate(
                [valid.aggregated_signature, quorum.aggregated_signature]
            ),
        )
        evaluated = EvaluatedBundleOutputs(signed)
        additions = evaluated.additions
        delivery_outputs: list[Coin] = []
        treasury_outputs: list[Coin] = []
        for context in group.contexts:
            vault_full = SINGLETON_MOD.curry(
                context.deed_struct,
                puzzle_for_p2_vault(batch.vault_launcher_id),
            )
            try:
                delivery_outputs.append(
                    evaluated.find_exact_descendant(
                        ancestor_coin_id=context.deed_coin.name(),
                        puzzle_hash=bytes32(vault_full.get_tree_hash()),
                        amount=1,
                        label="vault SmartDeed",
                    )
                )
            except GovernedOutputConflict as exc:
                raise StripeDeliveryManualReview(str(exc)) from exc
            treasury_outputs.append(
                _one_child_output(
                    additions,
                    parent_coin_id=context.deed_coin.name(),
                    puzzle_hash=(
                        receipt.result_authorization_puzzle_hash
                        if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                        else context.terms.protocol_puzhash
                    ),
                    amount=1,
                    label="external settlement result",
                )
            )
        delivery_ids = tuple(_hex32(coin.name()) for coin in delivery_outputs)
        treasury_ids = tuple(_hex32(coin.name()) for coin in treasury_outputs)
        self._prepare_governed_index(
            operation=operation,
            artifact_hash=_hex32(batch.batch_hash),
            delivery_kind="smartdeed",
            quantity=batch.quantity,
            bundle=signed,
            outputs=tuple(
                GovernedOutputExpectation(
                    ordinal=ordinal,
                    deed_launcher_id=_hex32(
                        context.purchase.deed_launcher_id
                    ),
                    coin_id=_hex32(coin.name()),
                    parent_coin_id=_hex32(coin.parent_coin_info),
                    puzzle_hash=_hex32(coin.puzzle_hash),
                    amount=1,
                )
                for ordinal, (context, coin) in enumerate(
                    zip(group.contexts, delivery_outputs, strict=True)
                )
            ),
        )
        return self.store.record_delivery_prepared(
            operation.purchase_id,
            protocol_bundle=signed.to_json_dict(),
            delivery_output_coin_id=delivery_ids[0],
            delivery_output_coin_ids=delivery_ids,
            treasury_output_coin_id=treasury_ids[0],
            treasury_output_coin_ids=treasury_ids,
            signer_indices=quorum.signer_indices,
        )

    async def _prepare_sgt_delivery(
        self,
        *,
        operation: StripeDeliveryOperation,
        purchase: Any,
        receipt: Any,
        receipt_terms: StripeSettlementTermsV1,
        receipt_coin: Coin,
    ) -> StripeDeliveryOperation:
        stored = self._stored_record(operation.purchase_id)
        protocol = stored.offer_artifact.get("protocol")
        if not isinstance(protocol, Mapping):
            raise StripeDeliveryManualReview(
                "SGT purchase protocol context is missing"
            )
        proposal_id = protocol.get("governanceProposalId")
        if not isinstance(proposal_id, str):
            raise StripeDeliveryManualReview(
                "SGT purchase has no governed proposal"
            )
        queue = GovernanceQueueStore(self.settings.admin_db_path)
        try:
            record = queue.get(proposal_id)
        finally:
            queue.close()
        if record.kind != "SGT_SALE" or record.state != "EXECUTED":
            raise StripeDeliveryManualReview(
                "SGT sale is not an executed governance proposal"
            )
        chain = await reconstruct_governed_sale_coin(
            record=record,
            provider=self.provider,
            settings=self.settings,
        )
        terms = chain.terms
        if (
            chain.spent_height is not None
            or terms.payment_rail
            != (
                SGTAllocationRail.STRIPE
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else SGTAllocationRail.BASE_USDC
            )
            or terms.purchase_artifact_hash != purchase.artifact_hash
            or terms.payment_amount != purchase.rail_amount
            or terms.sgt_amount != purchase.delivery_amount
            or terms.sale_id != purchase.delivery_context_hash
            or terms.recipient_vault_launcher_id
            != purchase.vault_launcher_id
            or purchase.delivery_asset_id != chain.sgt_tail_hash
            or protocol.get("saleCoinId")
            != _hex32(chain.sale_coin.name())
        ):
            raise StripeDeliveryManualReview(
                "SGT delivery differs from its governed sale allocation"
            )
        lineage = await reconstruct_governed_sale_lineage(
            context=chain,
            provider=self.provider,
        )
        approved = require_current_approved_vault(
            self.settings,
            _hex32(purchase.vault_launcher_id),
            expected_identity_attest_root=_hex32(purchase.zkpassport_root),
        )
        vault_record = get_registry().get(purchase.vault_launcher_id)
        credential_receipt = approved.enrollment.receipt
        if vault_record is None or credential_receipt is None:
            raise StripeDeliveryManualReview(
                "SGT recipient vault ownership evidence is unavailable"
            )
        genesis = load_signed_public_artifact(self.settings)
        claim = StripeSettlementClaim(
            network=self.settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            purchase_artifact=stored.purchase_artifact,
            stripe_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_STRIPE
                else None
            ),
            base_evidence=(
                operation.evidence
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            base_result_authorization_puzzle_hash=(
                _hex32(
                    receipt.result_authorization_puzzle_hash
                )
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else None
            ),
            receipt_coin_id=_hex32(receipt_coin.name()),
            receipt_puzzle_hash=_hex32(receipt_coin.puzzle_hash),
            sgt_sale_coin_id=_hex32(chain.sale_coin.name()),
            sgt_sale_puzzle_hash=_hex32(chain.sale_coin.puzzle_hash),
            governance_proposal_id=record.id,
            governance_bill_clvm_hex=record.bill_clvm_hex,
            protocol_puzzle_hash=_hex32(
                purchase.protocol_treasury_puzzle_hash
            ),
            credential_vault_coin_id=str(
                credential_receipt.chiaVaultCoinId
            ),
            credential_identity_root=str(
                credential_receipt.identityAttestRoot
            ),
            credential_policy_version=int(
                credential_receipt.policyVersion
            ),
            credential_bridge_policy_hash=str(
                credential_receipt.bridgePolicyHash
            ),
            credential_owner_auth_type=vault_record.auth_type,
            credential_owner_key="0x" + bytes(vault_record.owner_pubkey).hex(),
        )
        quorum = await collect_stripe_settlement_quorum(self.settings, claim)
        receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
        receipt_spend = make_spend(
            receipt_coin,
            receipt_puzzle,
            stripe_settlement_receipt_solution(
                receipt_coin=receipt_coin,
                signer_indices=quorum.signer_indices,
            ),
        )
        sale_spend = build_sgt_external_sale_spend(
            sale_coin=chain.sale_coin,
            sale_lineage_proof=lineage,
            proposal_tracker_struct=chain.tracker_struct,
            reserve_owner_inner_hash=chain.reserve_owner_inner_hash,
            sgt_tail_hash=chain.sgt_tail_hash,
            terms=terms,
            external_receipt_coin_id=receipt_coin.name(),
            external_receipt_hash=receipt.receipt_hash,
        )
        signed = WalletSpendBundle(
            [receipt_spend, sale_spend],
            quorum.aggregated_signature,
        )
        recipient_inner = sgt_free_inner_puzzle(
            bytes32(sgt_locked_inner_mod().get_tree_hash()),
            chain.tracker_struct,
            puzzle_hash_for_p2_vault(purchase.vault_launcher_id),
        )
        recipient_full = construct_cat_puzzle(
            CAT_MOD,
            chain.sgt_tail_hash,
            recipient_inner,
        )
        evaluated = EvaluatedBundleOutputs(signed)
        additions = evaluated.additions
        try:
            sgt_output = evaluated.find_exact_descendant(
                ancestor_coin_id=chain.sale_coin.name(),
                puzzle_hash=bytes32(recipient_full.get_tree_hash()),
                amount=terms.sgt_amount,
                label="vault SGT",
            )
        except GovernedOutputConflict as exc:
            raise StripeDeliveryManualReview(str(exc)) from exc
        treasury_output = _one_output(
            additions,
            puzzle_hash=(
                receipt.result_authorization_puzzle_hash
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else purchase.protocol_treasury_puzzle_hash
            ),
            amount=1,
            label=(
                "Base result authorization"
                if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
                else "receipt treasury"
            ),
        )
        if treasury_output.parent_coin_info != receipt_coin.name():
            raise StripeDeliveryManualReview(
                "receipt treasury output is not descended from the receipt"
            )
        self._prepare_governed_index(
            operation=operation,
            artifact_hash=_hex32(purchase.artifact_hash),
            delivery_kind="sgt",
            quantity=terms.sgt_amount,
            bundle=signed,
            outputs=(
                GovernedOutputExpectation(
                    ordinal=0,
                    coin_id=_hex32(sgt_output.name()),
                    parent_coin_id=_hex32(sgt_output.parent_coin_info),
                    puzzle_hash=_hex32(sgt_output.puzzle_hash),
                    amount=terms.sgt_amount,
                ),
            ),
        )
        return self.store.record_delivery_prepared(
            operation.purchase_id,
            protocol_bundle=signed.to_json_dict(),
            delivery_output_coin_id=_hex32(sgt_output.name()),
            treasury_output_coin_id=_hex32(treasury_output.name()),
            signer_indices=quorum.signer_indices,
        )

    def _prepare_governed_index(
        self,
        *,
        operation: StripeDeliveryOperation,
        artifact_hash: str,
        delivery_kind: str,
        quantity: int,
        bundle: WalletSpendBundle,
        outputs: tuple[GovernedOutputExpectation, ...],
    ) -> None:
        try:
            self.output_index.prepare(
                purchase_id=operation.purchase_id,
                artifact_hash=artifact_hash,
                rail=operation.payment_rail,
                delivery_kind=delivery_kind,
                quantity=quantity,
                input_coin_ids=tuple(
                    _hex32(coin.name()) for coin in bundle.removals()
                ),
                protocol_bundle_id=_hex32(bundle.name()),
                outputs=outputs,
            )
        except (GovernedOutputConflict, ValueError) as exc:
            raise StripeDeliveryManualReview(
                f"governed delivery index rejected the prepared bundle: {exc}"
            ) from exc

    def _bind_governed_submission(
        self,
        operation: StripeDeliveryOperation,
        prepared: PreparedProtocolBundle,
        *,
        mempool_observed_at: str,
    ) -> None:
        try:
            self.output_index.bind_submission(
                operation.purchase_id,
                spend_bundle_id=_hex32(prepared.bundle.name()),
                input_coin_ids=tuple(
                    _hex32(coin.name())
                    for coin in prepared.bundle.removals()
                ),
                mempool_observed_at=mempool_observed_at,
            )
        except (GovernedOutputConflict, ValueError) as exc:
            raise StripeDeliveryManualReview(
                f"exact submitted bundle conflicts with its governed index: {exc}"
            ) from exc

    async def _submit_or_recover_delivery(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        confirmation = await self._delivery_confirmation(operation)
        if confirmation is not None:
            return await self._record_delivery_confirmation(
                operation, confirmation
            )
        if operation.delivery_bundle is None:
            raise StripeDeliveryManualReview("prepared delivery bundle is missing")
        bundle = SpendBundle.from_json_dict(operation.delivery_bundle)
        input_ids = [_hex32(coin.name()) for coin in bundle.removals()]
        delivery_output_ids, treasury_output_ids = _operation_output_ids(operation)
        if not delivery_output_ids or not treasury_output_ids:
            raise StripeDeliveryManualReview(
                "prepared delivery output manifest is incomplete"
            )
        for coin_id in input_ids:
            pending_id = await self._mempool_bundle_id(coin_id)
            if pending_id:
                if operation.delivery_exact_bundle is None:
                    raise StripeDeliveryManualReview(
                        "delivery input is pending without a persisted exact KoS bundle"
                    )
                prepared = _prepared_from_binding(operation.delivery_exact_bundle)
                if pending_id != _hex32(prepared.bundle.name()):
                    raise StripeDeliveryManualReview(
                        "delivery input is reserved by a different mempool bundle"
                    )
                observed_at = _utc_now()
                self._bind_governed_submission(
                    operation,
                    prepared,
                    mempool_observed_at=observed_at,
                )
                return self.store.record_delivery_submission(
                    operation.purchase_id,
                    bundle_id=pending_id,
                    delivery_output_coin_id=delivery_output_ids[0],
                    delivery_output_coin_ids=delivery_output_ids,
                    treasury_output_coin_id=treasury_output_ids[0],
                    treasury_output_coin_ids=treasury_output_ids,
                    signer_indices=operation.signer_indices,
                    fee_mojos=prepared.fee_mojos,
                    mempool_observed_at=observed_at,
                )
        input_records = [
            await self.provider.get_coin_record_by_name(coin_id)
            for coin_id in input_ids
        ]
        if any(_is_spent(record) for record in input_records):
            raise StripeDeliveryManualReview(
                "delivery input was spent without both committed outputs"
            )
        expected_output_ids = (*delivery_output_ids, *treasury_output_ids)
        request = self._exact_execution_request(
            operation,
            action=ExactExecutionAction.DELIVER,
            outputs=_bound_outputs(
                operation.delivery_bundle,
                expected_output_ids,
            ),
        )
        exact_prepared: PreparedProtocolBundle
        if operation.delivery_exact_bundle is None:
            async def dispatch(prepared: PreparedProtocolBundle):
                self.store.bind_delivery_exact_bundle(
                    operation.purchase_id,
                    exact_bundle=prepared.to_json(),
                )
                return await self.exact_executor.dispatch(request, prepared)

            result = await self.submitter.prepare_and_dispatch(
                operation.delivery_bundle,
                dispatch,
            )
            refreshed = self.store.get(operation.purchase_id)
            if refreshed.delivery_exact_bundle is None:
                raise StripeDeliveryManualReview(
                    "exact KoS delivery bundle was not persisted"
                )
            exact_prepared = _prepared_from_binding(
                refreshed.delivery_exact_bundle
            )
        else:
            exact_prepared = _prepared_from_binding(
                operation.delivery_exact_bundle
            )
            await self.exact_executor.dispatch(request, exact_prepared)
            result = exact_prepared.to_json()
        result_bundle_id = _normalize_hex32(str(result["spendBundleId"]))
        if result_bundle_id != _hex32(exact_prepared.bundle.name()):
            raise StripeDeliveryManualReview(
                "KoS returned a different exact delivery bundle ID"
            )
        observed_at = _utc_now()
        self._bind_governed_submission(
            operation,
            exact_prepared,
            mempool_observed_at=observed_at,
        )
        return self.store.record_delivery_submission(
            operation.purchase_id,
            bundle_id=result_bundle_id,
            delivery_output_coin_id=delivery_output_ids[0],
            delivery_output_coin_ids=delivery_output_ids,
            treasury_output_coin_id=treasury_output_ids[0],
            treasury_output_coin_ids=treasury_output_ids,
            signer_indices=operation.signer_indices,
            fee_mojos=int(result["feeMojos"]),
            mempool_observed_at=observed_at,
        )

    def _exact_execution_request(
        self,
        operation: StripeDeliveryOperation,
        *,
        action: ExactExecutionAction,
        outputs: tuple[ExactExecutionOutput, ...],
    ) -> ExactExecutionRequest:
        purchase = self._stored_purchase_document(operation.purchase_id)
        purchase_hash = (
            purchase.batch_hash
            if isinstance(purchase, PurchaseBatchV1)
            else purchase.artifact_hash
        )
        if _hex32(purchase.purchase_id) != operation.purchase_id.lower():
            raise StripeDeliveryManualReview(
                "delivery operation differs from its purchase artifact"
            )
        return ExactExecutionRequest(
            action=action,
            purchase_id=purchase.purchase_id,
            artifact_hash=purchase_hash,
            claim_hash=bytes32.from_hexstr(operation.receipt_hash),
            expected_outputs=outputs,
        )

    async def _confirm_delivery(
        self,
        operation: StripeDeliveryOperation,
    ) -> StripeDeliveryOperation:
        confirmation = await self._delivery_confirmation(operation)
        if confirmation is None:
            return self.store.release_lease(operation.purchase_id)
        return await self._record_delivery_confirmation(
            operation, confirmation
        )

    async def _record_delivery_confirmation(
        self,
        operation: StripeDeliveryOperation,
        confirmation_height: int,
    ) -> StripeDeliveryOperation:
        indexed = await reconcile_governed_delivery(
            self.output_index,
            self.provider,
            operation.purchase_id,
        )
        if (
            indexed.state != GOVERNED_CONFIRMED
            or indexed.confirmation_height != confirmation_height
        ):
            raise StripeDeliveryManualReview(
                "governed outputs are not fully confirmed with the delivery"
            )
        confirmed = self.store.record_delivery_confirmed(
            operation.purchase_id,
            confirmation_height=confirmation_height,
        )
        if confirmed.payment_rail != PAYMENT_RAIL_BASE_USDC:
            return confirmed
        purchase = self._stored_purchase_document(operation.purchase_id)
        authorization_id, authorization = build_direct_settlement_authorization(
            operation=confirmed,
            purchase=purchase,
        )
        return self.store.record_external_settlement_authorization(
            operation.purchase_id,
            authorization_id=authorization_id,
            authorization=authorization,
        )

    async def _delivery_confirmation(
        self,
        operation: StripeDeliveryOperation,
    ) -> int | None:
        delivery_output_ids, treasury_output_ids = _operation_output_ids(operation)
        output_ids = (*delivery_output_ids, *treasury_output_ids)
        if not output_ids or not (
            operation.delivery_exact_bundle or operation.delivery_bundle
        ):
            return None
        bundle = (
            _prepared_from_binding(operation.delivery_exact_bundle).bundle
            if operation.delivery_exact_bundle is not None
            else SpendBundle.from_json_dict(operation.delivery_bundle)
        )
        bundle_outputs = {
            _hex32(coin.name()): coin for coin in bundle.additions()
        }
        if any(coin_id not in bundle_outputs for coin_id in output_ids):
            raise StripeDeliveryManualReview(
                "stored delivery output manifest differs from the exact bundle"
            )
        output_records = [
            await self.provider.get_coin_record_by_name(coin_id)
            for coin_id in output_ids
        ]
        if any(not _is_confirmed(record) for record in output_records):
            return None
        for coin_id, record in zip(output_ids, output_records, strict=True):
            expected = bundle_outputs[coin_id]
            actual = _coin_from_record(record)
            if actual is None or actual != expected or _hex32(actual.name()) != coin_id:
                raise StripeDeliveryManualReview(
                    "confirmed delivery coin differs from the exact bundle"
                )
        heights = {
            int(record.get("confirmed_block_index") or 0)
            for record in output_records
            if isinstance(record, Mapping)
        }
        if len(heights) != 1:
            raise StripeDeliveryManualReview(
                "delivery assets and settlement outputs did not confirm atomically"
            )
        input_records = [
            await self.provider.get_coin_record_by_name(_hex32(coin.name()))
            for coin in bundle.removals()
        ]
        if any(not _is_spent(record) for record in input_records):
            return None
        for expected, record in zip(
            bundle.removals(), input_records, strict=True
        ):
            actual = _coin_from_record(record)
            if actual is None or actual != expected:
                raise StripeDeliveryManualReview(
                    "spent delivery input differs from the exact bundle"
                )
        spent_heights = {
            int(record.get("spent_block_index") or 0)
            for record in input_records
            if isinstance(record, Mapping)
        }
        if spent_heights != heights:
            raise StripeDeliveryManualReview(
                "delivery inputs and outputs did not settle in one block"
            )
        return heights.pop()

    async def _select_faucet_coin(self, amount: int) -> Coin:
        records = await self.provider.get_coin_records_by_puzzle_hash(
            self.faucet.address_hex,
            include_spent=False,
        )
        eligible: list[dict[str, Any]] = []
        for record in records:
            coin = self.faucet.select_coin(
                [record],
                min_amount=amount,
                max_amount=self.settings.faucet_max_spend_mojos,
            )
            if coin is None:
                continue
            if await self.provider.get_mempool_items_by_coin_name(
                _hex32(coin.name())
            ):
                continue
            eligible.append(record)
        selected = self.faucet.select_coin(
            eligible,
            min_amount=amount,
            max_amount=self.settings.faucet_max_spend_mojos,
        )
        if selected is None:
            raise StripeDeliveryError(
                "fee till has no confirmed unreserved receipt-funding coin"
            )
        return selected

    async def _mempool_bundle_id(self, coin_id: str) -> str | None:
        items = await self.provider.get_mempool_items_by_coin_name(coin_id)
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, Mapping):
                continue
            value = item.get("spend_bundle_name") or item.get("name")
            if isinstance(value, str):
                try:
                    return _normalize_hex32(value)
                except ValueError:
                    continue
        return None

    async def _is_exact_confirmed_output(
        self,
        coin_id: str,
        puzzle_hash: str | None,
        amount: int,
        *,
        require_unspent: bool,
    ) -> bool:
        if puzzle_hash is None:
            return False
        record = await self.provider.get_coin_record_by_name(coin_id)
        coin = _coin_from_record(record)
        return bool(
            coin is not None
            and _is_confirmed(record)
            and (not require_unspent or not _is_spent(record))
            and _hex32(coin.name()) == coin_id.lower()
            and _hex32(coin.puzzle_hash) == puzzle_hash.lower()
            and int(coin.amount) == amount
        )


def _one_output(
    additions: list[Coin],
    *,
    puzzle_hash: bytes32,
    amount: int,
    label: str,
) -> Coin:
    matches = [
        coin
        for coin in additions
        if coin.puzzle_hash == puzzle_hash and int(coin.amount) == amount
    ]
    if len(matches) != 1:
        raise StripeDeliveryManualReview(
            f"delivery must create exactly one {label}; found {len(matches)}"
        )
    return matches[0]


def _one_child_output(
    additions: list[Coin],
    *,
    parent_coin_id: bytes32,
    puzzle_hash: bytes32,
    amount: int,
    label: str,
) -> Coin:
    matches = [
        coin
        for coin in additions
        if coin.parent_coin_info == parent_coin_id
        and coin.puzzle_hash == puzzle_hash
        and int(coin.amount) == amount
    ]
    if len(matches) != 1:
        raise StripeDeliveryManualReview(
            f"delivery bundle has {len(matches)} exact {label} outputs"
        )
    return matches[0]


def _operation_output_ids(
    operation: StripeDeliveryOperation,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    delivery_ids = operation.expected_delivery_output_coin_ids or (
        (str(operation.expected_delivery_output_coin_id),)
        if operation.expected_delivery_output_coin_id
        else ()
    )
    treasury_ids = operation.expected_treasury_output_coin_ids or (
        (str(operation.expected_treasury_output_coin_id),)
        if operation.expected_treasury_output_coin_id
        else ()
    )
    return delivery_ids, treasury_ids


def _bound_outputs(
    bundle_json: Mapping[str, Any],
    coin_ids: tuple[str, ...],
) -> tuple[ExactExecutionOutput, ...]:
    try:
        bundle = SpendBundle.from_json_dict(dict(bundle_json))
        additions = {_hex32(coin.name()): coin for coin in bundle.additions()}
    except Exception as exc:  # noqa: BLE001
        raise StripeDeliveryManualReview(
            "prepared bundle output manifest cannot be reconstructed"
        ) from exc
    if len(set(value.lower() for value in coin_ids)) != len(coin_ids):
        raise StripeDeliveryManualReview(
            "prepared bundle output manifest contains duplicate coin IDs"
        )
    outputs: list[ExactExecutionOutput] = []
    for value in coin_ids:
        coin = additions.get(value.lower())
        if coin is None:
            raise StripeDeliveryManualReview(
                "prepared bundle does not create a committed output"
            )
        outputs.append(
            ExactExecutionOutput(
                coin_id=bytes32(coin.name()),
                puzzle_hash=bytes32(coin.puzzle_hash),
                amount=int(coin.amount),
            )
        )
    return tuple(sorted(outputs, key=lambda output: bytes(output.coin_id)))


def _prepared_from_binding(value: Mapping[str, Any]) -> PreparedProtocolBundle:
    try:
        bundle = SpendBundle.from_json_dict(dict(value["spendBundle"]))
        bundle_id = _normalize_hex32(str(value["spendBundleId"]))
        fee_mojos = int(value["feeMojos"])
        fee_coin_id = _normalize_hex32(str(value["feeCoinId"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise StripeDeliveryManualReview(
            "persisted exact KoS bundle is malformed"
        ) from exc
    if _hex32(bundle.name()) != bundle_id:
        raise StripeDeliveryManualReview(
            "persisted exact KoS bundle ID differs from its bytes"
        )
    if fee_mojos < 0:
        raise StripeDeliveryManualReview(
            "persisted exact KoS fee cannot be negative"
        )
    if fee_coin_id not in {_hex32(coin.name()) for coin in bundle.removals()}:
        raise StripeDeliveryManualReview(
            "persisted exact KoS fee coin is not an input"
        )
    return PreparedProtocolBundle(
        bundle=bundle,
        fee_mojos=fee_mojos,
        fee_coin_id=fee_coin_id,
    )


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping) or not isinstance(record.get("coin"), Mapping):
        return None
    coin = record["coin"]
    try:
        return Coin(
            bytes32.fromhex(str(coin["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(coin["puzzle_hash"]).removeprefix("0x")),
            uint64(int(coin["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _confirmed_unspent_coin(record: Any) -> Coin | None:
    coin = _coin_from_record(record)
    if coin is None or not _is_confirmed(record) or _is_spent(record):
        return None
    return coin


def _is_confirmed(record: Any) -> bool:
    return (
        isinstance(record, Mapping)
        and int(record.get("confirmed_block_index") or 0) > 0
    )


def _is_spent(record: Any) -> bool:
    return bool(
        _is_confirmed(record)
        and (
            bool(record.get("spent"))
            or int(record.get("spent_block_index") or 0) > 0
        )
    )


def _hex32(value: Any) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be bytes32")
    return "0x" + raw.hex()


def _normalize_hex32(value: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    if len(normalized) != 66:
        raise ValueError("value is not bytes32")
    bytes.fromhex(normalized[2:])
    return normalized


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "StripeDeliveryError",
    "StripeDeliveryManualReview",
    "StripeDeliveryWorker",
    "StripeDeliveryWorkerConfig",
]
