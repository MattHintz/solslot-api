"""One-approval native XCH/CAT primary SmartDeed purchases."""
from __future__ import annotations

import time
import httpx
from dataclasses import dataclass
from typing import Annotated, Any, Mapping, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, match_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.trading.offer import Offer
from chia.wallet.uncurried_puzzle import uncurry_puzzle
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.mint_publish_driver import (
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseBatchV1,
    PurchaseArtifactV3,
    PurchaseKind,
    purchase_artifact_v3_to_json,
    purchase_artifact_v3_from_json,
    purchase_batch_from_json,
)
from solslot_puzzles.voucher_presale_v2 import DELIVERY_WINDOW_SECONDS
from solslot_puzzles.stripe_settlement_v1_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    InventoryReservationV1,
    PrimaryMintTermsV3,
    build_inventory_reservation_spend,
    build_native_primary_batch_offer_v5,
    build_native_primary_offer_v5,
    inventory_reservation_message,
    inventory_terms_for_puzzle_hash,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
    prepare_chia_buyer_batch_offer_v3,
    prepare_chia_buyer_offer_v3,
    validate_chia_buyer_batch_offer_v3,
    validate_chia_buyer_offer_v3,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.vault_driver import puzzle_for_p2_vault

from .collection_store import CollectionNotFound, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_minting_writes
from .faucet import AGG_SIG_ME_DATA
from .mint_endpoints import get_mint_proposal_store
from .launch_gates import require_operation_gate
from .governed_output_index import (
    GovernedOutputConflict,
    GovernedOutputExpectation,
    GovernedOutputNotFound,
    EvaluatedBundleOutputs,
    get_governed_output_index,
    reconcile_governed_delivery,
    serialize_governed_delivery,
)
from .payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseNotFound,
    StoredPaymentPurchase,
    StoredPaymentInventoryItem,
    get_payment_purchase_store,
)
from .inventory_recovery import (
    decode_spend, record_coin, reconcile_timeout_release, timeout_successor_lineage,
)
from .protocol_artifacts import (
    _artifact_rejection_reasons,
    _require_server_to_server_token,
)
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from .protocol_submission import (
    ProtocolBundleSubmitter,
    ProtocolSubmissionError,
)
from .state import get_registry
from .wallet_offer_validation import decode_offer, validate_standard_payment
from .wallet_offer_worker import run_offer_job
from .validator_quorum import (
    InventoryReservationClaim,
    PrimaryPurchaseClaim,
    PrimaryPurchaseDeedItem,
    ValidatorQuorumError,
    collect_primary_purchase_quorum,
    collect_inventory_reservation_quorum,
    configured_validator_pubkeys,
)


router = APIRouter(prefix="/protocol/native-purchases", tags=["native-purchases"])


class NativePurchaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class PrepareNativePurchaseRequest(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId", min_length=66, max_length=66)
    payment_public_keys: list[str] = Field(
        alias="paymentPublicKeys",
        min_length=1,
        max_length=100,
    )

    @field_validator("payment_public_keys")
    @classmethod
    def validate_public_keys(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            raw = _hex_bytes(value, 48, "paymentPublicKeys")
            G1Element.from_bytes(raw)
            item = "0x" + raw.hex()
            if item not in normalized:
                normalized.append(item)
        if not normalized:
            raise ValueError("at least one unique payment public key is required")
        return normalized


class PrepareNativePurchaseResponse(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId")
    buyer_offer: str = Field(alias="buyerOffer")
    coin_spends: list[dict[str, Any]] = Field(alias="coinSpends")
    rail: str
    amount: int
    asset_id: str = Field(alias="assetId")
    quote_expires_at: int = Field(alias="quoteExpiresAt")
    quantity: int = 1
    deed_launcher_ids: list[str] = Field(
        alias="deedLauncherIds",
        default_factory=list,
    )


class CompleteNativePurchaseRequest(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId", min_length=66, max_length=66)
    buyer_offer: str = Field(alias="buyerOffer", min_length=16, max_length=2_000_000)
    aggregated_signature: str = Field(
        alias="aggregatedSignature",
        min_length=194,
        max_length=194,
    )


class CompleteNativePurchaseResponse(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId")
    transaction_id: str = Field(alias="transactionId")
    status: str
    signer_indices: list[int] = Field(alias="signerIndices")
    fee_mojos: int = Field(alias="feeMojos")
    fee_target_seconds: int = Field(alias="feeTargetSeconds")
    submission_provider: str = Field(alias="submissionProvider")
    mempool_observed_at: str = Field(alias="mempoolObservedAt")
    quantity: int = 1
    deed_launcher_ids: list[str] = Field(
        alias="deedLauncherIds",
        default_factory=list,
    )
    expected_delivery_coin_ids: list[str] = Field(
        alias="expectedDeliveryCoinIds",
        default_factory=list,
    )


@router.get("/{purchase_id}")
async def native_purchase_status(
    purchase_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Reconstruct one native purchase from every committed deed output."""

    _require_server_to_server_token(settings, authorization)
    normalized = "0x" + _hex_bytes(purchase_id, 32, "purchaseId").hex()
    index = get_governed_output_index(settings.payment_purchase_db_path)
    try:
        operation = await reconcile_governed_delivery(
            index,
            request.app.state.coinset,
            normalized,
        )
    except GovernedOutputNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return serialize_governed_delivery(
        operation,
        index.outputs(normalized),
    )


class InventoryReservationRequest(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId", min_length=66, max_length=66)


class InventoryReservationItemResponse(NativePurchaseModel):
    deed_launcher_id: str = Field(alias="deedLauncherId")
    available_coin_id: str = Field(alias="availableCoinId")
    reserved_coin_id: str = Field(alias="reservedCoinId")
    reserved_puzzle_hash: str = Field(alias="reservedPuzzleHash")


class InventoryReservationResponse(NativePurchaseModel):
    purchase_id: str = Field(alias="purchaseId")
    state: str
    available_coin_id: str = Field(alias="availableCoinId")
    reserved_coin_id: str = Field(alias="reservedCoinId")
    reserved_puzzle_hash: str = Field(alias="reservedPuzzleHash")
    expires_at: int = Field(alias="expiresAt")
    transaction_id: str | None = Field(alias="transactionId", default=None)
    mempool_observed_at: str | None = Field(
        alias="mempoolObservedAt",
        default=None,
    )
    confirmation_height: int | None = Field(
        alias="confirmationHeight",
        default=None,
    )
    quantity: int = 1
    items: list[InventoryReservationItemResponse] = Field(default_factory=list)


@router.get("/inventory/{purchase_id}")
async def inventory_purchase_status(
    purchase_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Retained, service-only receipts; available while new sales are closed."""
    from .inventory_status import retained_inventory_status
    _require_server_to_server_token(settings, authorization)
    normalized = "0x" + _hex_bytes(purchase_id, 32, "purchaseId").hex()
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        result = retained_inventory_status(store.inventory_status_snapshot(normalized),
            environment=settings.runtime_environment + "-alpha", network=settings.network)
        from .inventory_payment_holds import checkout_status
        checkout=store.checkout_hold(normalized)
        if checkout is not None:
            result['checkoutHold']=checkout_status(checkout,load_signed_public_artifact(settings),now=int(time.time()))
        from .inventory_extensions import hold_status
        hold = hold_status(store.get(normalized), store.inventory_extension_operations(normalized), now=int(time.time()))
        if hold is not None:
            from .inventory_extension_chain import current_position, validate_execution
            from .inventory_extension_claims import InventoryExtensionClaim
            stored = store.get(normalized)
            position = current_position(stored, store.inventory_items(normalized), load_signed_public_artifact(settings))
            pending = store.pending_inventory_extension(normalized)
            if pending and pending["protocol"] is not None:
                validate_execution(position, InventoryExtensionClaim.model_validate(pending["claim"]), pending)
            result["paymentHold"] = hold
        return result
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PaymentPurchaseConflict, ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=409, detail="Inventory evidence is incomplete. The purchase remains held for review.") from exc


class InventoryExtensionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)
    purchase_id: str = Field(alias="purchaseId", pattern=r"^0x[0-9a-f]{64}$")
    payment_intent_id: str = Field(alias="paymentIntentId", pattern=r"^pi_[A-Za-z0-9]{1,200}$")
    payment_event_id: str = Field(alias="paymentEventId", pattern=r"^evt_[A-Za-z0-9]{1,200}$")
    payment_started_at: int = Field(alias="paymentStartedAt", gt=0)
    payment_method: Literal["card", "us_bank_account"] = Field(alias="paymentMethod")
    observe_only: bool = Field(default=False, alias="observeOnly")


class InventoryPaymentHoldRequest(BaseModel):
    model_config = ConfigDict(extra='forbid',populate_by_name=True,strict=True)
    purchase_id: str = Field(alias='purchaseId',pattern=r'^0x[0-9a-f]{64}$')
    payment_intent_id: str = Field(alias='paymentIntentId',pattern=r'^pi_[A-Za-z0-9]{1,200}$')
    payment_method: Literal['card','us_bank_account'] = Field(alias='paymentMethod')


@router.post('/inventory/payment-hold/arm')
async def arm_inventory_payment_hold(payload:InventoryPaymentHoldRequest,
        settings:Annotated[Settings,Depends(get_settings)],authorization:Annotated[str|None,Header()]=None):
    from .inventory_payment_holds import arm_checkout
    _require_server_to_server_token(settings,authorization)
    def authorize():
        _require_server_to_server_token(settings,authorization)
        require_minting_writes(settings);require_operation_gate(settings,'purchases')
    try:
        result=await arm_checkout(store=get_payment_purchase_store(settings.payment_purchase_db_path),settings=settings,
            purchase_id=payload.purchase_id,payment_intent_id=payload.payment_intent_id,payment_method=payload.payment_method,
            load_artifact=lambda:load_signed_public_artifact(settings),authorize=authorize)
        return dict(purchaseId=payload.purchase_id,checkoutHold=result)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404,detail=str(exc)) from exc
    except (PaymentPurchaseConflict,ValueError,TypeError,KeyError,ValidatorQuorumError) as exc:
        raise HTTPException(status_code=409,detail='Checkout hold incomplete. Retain this payment and recover the same purchase.') from exc
    except (httpx.HTTPError,OSError,TimeoutError) as exc:
        raise HTTPException(status_code=503,detail='Checkout hold unavailable. Payment must remain unconfirmed.') from exc


@router.post('/inventory/payment-hold/abort')
async def abort_inventory_payment_hold(payload:InventoryReservationRequest,
        settings:Annotated[Settings,Depends(get_settings)],authorization:Annotated[str|None,Header()]=None):
    from .inventory_payment_holds import abort_checkout
    # Recovery remains service-only and available when new purchases are paused.
    _require_server_to_server_token(settings,authorization)
    try:
        result=await abort_checkout(store=get_payment_purchase_store(settings.payment_purchase_db_path),settings=settings,
            purchase_id=payload.purchase_id,load_artifact=lambda:load_signed_public_artifact(settings))
        return dict(purchaseId=payload.purchase_id,checkoutHold=result)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404,detail=str(exc)) from exc
    except (PaymentPurchaseConflict,ValueError,TypeError,KeyError,ValidatorQuorumError) as exc:
        raise HTTPException(status_code=409,detail='Canceled-payment proof is incomplete. Inventory remains held for review.') from exc
    except (httpx.HTTPError,OSError,TimeoutError) as exc:
        raise HTTPException(status_code=503,detail='Cancellation observation unavailable. Retry this same purchase.') from exc


@router.post("/inventory/extend")
async def extend_inventory(payload: InventoryExtensionRequest, request: Request,
                           settings: Annotated[Settings, Depends(get_settings)],
                           authorization: Annotated[str | None, Header()] = None):
    from .inventory_extensions import advance_extension
    from .presale_endpoints import get_presale_store
    _require_server_to_server_token(settings, authorization)
    def authorize():
        _require_server_to_server_token(settings, authorization)
        require_minting_writes(settings)
        require_operation_gate(settings, "purchases")
    try:
        result = await advance_extension(store=get_payment_purchase_store(settings.payment_purchase_db_path),
            node=request.app.state.coinset, submitter=getattr(request.app.state, "protocol_submitter", None),
            settings=settings, presales=get_presale_store(settings), purchase_id=payload.purchase_id,
            payment={key: getattr(payload, key) for key in ("payment_intent_id", "payment_event_id", "payment_started_at", "payment_method")},
            load_artifact=lambda: load_signed_public_artifact(settings), authorize=authorize,
            observe_only=payload.observe_only)
        return dict(purchaseId=payload.purchase_id, paymentHold=result)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PaymentPurchaseConflict, ValueError, TypeError, KeyError, ValidatorQuorumError) as exc:
        raise HTTPException(status_code=409, detail="Extension needs review. Inventory remains held: " + str(exc)) from exc
    except (httpx.HTTPError, OSError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail="Extension service unavailable. Retain this purchase and retry recovery.") from exc


@router.post("/inventory/reconcile-timeout")
async def reconcile_inventory_timeout(
    payload: InventoryReservationRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Observe an already executed timeout release; this endpoint never broadcasts."""
    _require_server_to_server_token(settings, authorization)
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    purchase_id = "0x" + _hex_bytes(payload.purchase_id, 32, "purchaseId").hex()
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        def authorize():
            _require_server_to_server_token(settings, authorization)
            require_minting_writes(settings)
            require_operation_gate(settings, "purchases")
        result = await reconcile_timeout_release(store, request.app.state.coinset,
                                                 purchase_id, settings.network, authorize=authorize)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (httpx.HTTPError, OSError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail="Chain confirmation is unavailable. The reservation remains held; retry later.") from exc
    return {"purchaseId": result.purchase_id, "state": result.inventory_state,
            "releaseEvidence": store.inventory_release_evidence(result.purchase_id)}


@router.post("/inventory/reconcile-expiry")
async def reconcile_inventory_expiry(
    payload: InventoryReservationRequest, request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Retire a never-confirmed V2 authorization after independent chain proof."""
    from .inventory_authorization_expiry import reconcile_inventory_authorization_expiry
    from .chia_provider import ChiaProviderError
    _require_server_to_server_token(settings, authorization)
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    purchase_id = "0x" + _hex_bytes(payload.purchase_id, 32, "purchaseId").hex()
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    primary = getattr(request.app.state.coinset, "primary", None)
    if primary is None or settings.network != "testnet11":
        raise HTTPException(status_code=503, detail="Expiry recovery requires the configured Testnet primary node.")
    try:
        artifact = load_signed_public_artifact(settings)
        def authorize():
            _require_server_to_server_token(settings, authorization)
            require_minting_writes(settings)
            require_operation_gate(settings, "purchases")
            current = load_signed_public_artifact(settings)
            if current["artifactHash"] != artifact["artifactHash"] or current["sourceShas"] != artifact["sourceShas"]:
                raise PaymentPurchaseConflict("signed release changed during authorization expiry")
        result = await reconcile_inventory_authorization_expiry(store=store, node=primary,
            purchase_id=purchase_id, artifact=artifact, environment=settings.runtime_environment+"-alpha", authorize=authorize)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (PublicArtifactError, ChiaProviderError, httpx.HTTPError, OSError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail="Expiry proof is unavailable. Inventory remains held; retry later.") from exc
    return dict(purchaseId=purchase_id, state=result.inventory_state,
                expiryEvidence=store.inventory_expiry_evidence(purchase_id))


@router.post("/inventory/resume-timeout")
async def resume_inventory_timeout(
    payload: InventoryReservationRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Prepare once, submit, or resume exact fee-funded Testnet timeout releases."""
    from .inventory_timeout_submission import advance_inventory_timeout
    from .chia_provider import ChiaProviderError

    _require_server_to_server_token(settings, authorization)
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    purchase_id = "0x" + _hex_bytes(payload.purchase_id, 32, "purchaseId").hex()
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    provider = getattr(request.app.state, "coinset", None)
    primary = getattr(provider, "primary", None)
    if submitter is None or primary is None or submitter.provider is not provider:
        raise HTTPException(status_code=503, detail="Timeout recovery requires the configured primary node and fee submitter.")
    try:
        artifact = load_signed_public_artifact(settings)
        binding = dict(network=artifact["network"], artifactHash=artifact["artifactHash"],
                       sourceShas=artifact["sourceShas"], adapterVersion=1,
                       protocolTreasuryPuzzleHash=artifact["puzzleHashes"]["protocolTreasuryPuzzleHash"],
                       validatorPubkeys=artifact["validatorSet"]["pubkeys"],
                       environment=settings.runtime_environment + "-alpha")

        def authorize() -> None:
            _require_server_to_server_token(settings, authorization)
            require_minting_writes(settings)
            require_operation_gate(settings, "purchases")
            current = load_signed_public_artifact(settings)
            if current["artifactHash"] != binding["artifactHash"] or current["sourceShas"] != binding["sourceShas"]:
                raise PaymentPurchaseConflict("signed release changed during timeout recovery")

        return await advance_inventory_timeout(store=store, node=primary, submitter=submitter,
            purchase_id=purchase_id, network=settings.network, release_binding=binding, authorize=authorize)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PaymentPurchaseConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (PublicArtifactError, ProtocolSubmissionError, ChiaProviderError, httpx.HTTPError, OSError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail="Timeout recovery is pending. The exact transaction and inventory remain reserved; retry this same purchase.") from exc


@dataclass(frozen=True)
class NativePurchaseContext:
    stored: StoredPaymentPurchase
    purchase: PurchaseArtifactV3
    terms: PrimaryMintTermsV3
    deed_coin: Coin
    deed_struct: Program
    deed_lineage: LineageProof
    genesis_artifact: dict[str, Any]
    credential_receipt: dict[str, Any]
    credential_owner_auth_type: int
    credential_owner_key: bytes
    reservation: InventoryReservationV1 | None = None


@dataclass(frozen=True)
class NativePurchaseGroup:
    stored: StoredPaymentPurchase
    contexts: tuple[NativePurchaseContext, ...]
    batch: PurchaseBatchV1 | None

    @property
    def quantity(self) -> int:
        return self.batch.quantity if self.batch is not None else 1

    @property
    def total_rail_amount(self) -> int:
        if self.batch is not None:
            return self.batch.total_rail_amount
        return self.contexts[0].purchase.rail_amount

    @property
    def deed_launcher_ids(self) -> list[str]:
        return [_hex32(context.purchase.deed_launcher_id) for context in self.contexts]


@router.post(
    "/reserve",
    response_model=InventoryReservationResponse,
)
async def reserve_smartdeed_inventory(
    body: InventoryReservationRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> InventoryReservationResponse:
    """Reserve every exact SmartDeed before a rail may accept customer funds."""

    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    _require_server_to_server_token(settings, authorization)
    purchase_id = "0x" + _hex_bytes(body.purchase_id, 32, "purchaseId").hex()
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        stored = store.get(purchase_id)
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if stored.inventory_state in {"RELEASED", "AUTHORIZATION_EXPIRED"}:
        raise HTTPException(status_code=409, detail="This reservation has ended. Start a new purchase with a fresh quote.")
    if stored.inventory_state in {"SUBMITTED", "CONFIRMED"}:
        confirmed = await _confirm_inventory_reservation(
            request.app.state.coinset,
            store,
            stored,
        )
        return _inventory_response(
            confirmed,
            store.inventory_items(purchase_id),
        )
    if stored.inventory_state == "PREPARED":
        pending_id = await _mempool_bundle_id(
            request.app.state.coinset,
            stored.inventory_available_coin_id,
        )
        if pending_id is not None:
            recovered = store.record_inventory_submitted(
                purchase_id,
                bundle_id=pending_id,
                mempool_observed_at="recovered-from-primary-mempool",
            )
            return _inventory_response(
                recovered,
                store.inventory_items(purchase_id),
            )
        if stored.inventory_bundle is None:
            raise HTTPException(
                status_code=409,
                detail="Prepared SmartDeed reservation has no deterministic bundle.",
            )
        recovered = await _submit_inventory_reservation(
            request,
            settings,
            store,
            stored,
        )
        return _inventory_response(
            recovered,
            store.inventory_items(purchase_id),
        )

    group = await _load_context_group(
        settings,
        request.app.state.coinset,
        purchase_id,
        allowed_rails=(
            PaymentRail.CHIA_XCH,
            PaymentRail.CHIA_CAT,
            PaymentRail.STRIPE,
            PaymentRail.EVM_TEST_USD,
        ),
        require_inventory_reservation=False,
    )
    from .inventory_payment_hold_claims import payment_hold_activation
    try:
        first=group.contexts[0]
        hold_capability=payment_hold_activation(first.genesis_artifact,settings.runtime_environment+'-alpha',required=False)
        if hold_capability is not None and hold_capability['adapterVersion']==2:
            from .purchase_admission import require_admission_owner
            require_admission_owner(_hex32(first.purchase.vault_launcher_id),first.credential_owner_auth_type,
                                    '0x'+first.credential_owner_key.hex())
            if len(group.contexts)>hold_capability['maxReservedDeedsPerIdentity']:
                raise ValueError('reviewed alpha admission permits one exact deed per identity')
            store.begin_admitted_reservation(stored=stored,receipt=first.credential_receipt,
                activation=hold_capability,now=int(time.time()),owner_auth_type=first.credential_owner_auth_type,
                owner_key='0x'+first.credential_owner_key.hex())
    except ValueError as exc:
        raise HTTPException(status_code=429,detail='Inventory admission is unavailable. Recover the existing purchase first.',
                            headers={'Retry-After':'60'}) from exc
    try:
        transitions = []
        quorums = []
        reservation_items: list[dict[str, Any]] = []
        for context in group.contexts:
            if context.reservation is None:
                raise PaymentArtifactError(
                    "SmartDeed reservation terms are unavailable"
                )
            validator_message = inventory_reservation_message(
                available_coin=context.deed_coin,
                reservation=context.reservation,
            )
            claim = InventoryReservationClaim(
                network=settings.network,
                genesis_artifact_hash=str(
                    context.genesis_artifact["artifactHash"]
                ),
                purchase_artifact=purchase_artifact_v3_to_json(
                    context.purchase
                ),
                available_coin_id=_hex32(context.deed_coin.name()),
                available_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
                smart_deed_inner_hash=_hex32(
                    context.terms.smart_deed_inner_hash
                ),
                protocol_puzzle_hash=_hex32(context.terms.protocol_puzhash),
                reservation_expires_at=context.reservation.expires_at,
                validator_message=_hex32(validator_message),
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
            quorum = await collect_inventory_reservation_quorum(settings, claim)
            transition = build_inventory_reservation_spend(
                available_coin=context.deed_coin,
                deed_singleton_struct=context.deed_struct,
                lineage_proof=context.deed_lineage,
                reservation=context.reservation,
                signer_indices=quorum.signer_indices,
                terms=context.terms,
            )
            if transition.validator_message != validator_message:
                raise PaymentArtifactError(
                    "reservation spend changed after validator approval"
                )
            transitions.append(transition)
            quorums.append(quorum)
            reservation_items.append(
                {
                    "deed_launcher_id": _hex32(
                        context.purchase.deed_launcher_id
                    ),
                    "available_coin_id": _hex32(context.deed_coin.name()),
                    "reserved_coin_id": _hex32(
                        transition.reserved_coin.name()
                    ),
                    "reserved_puzzle_hash": _hex32(
                        transition.reserved_coin.puzzle_hash
                    ),
                    "expires_at": context.reservation.expires_at,
                    "signer_indices": quorum.signer_indices,
                    "signature": "0x"
                    + bytes(quorum.aggregated_signature).hex(),
                }
            )
        bundle = WalletSpendBundle(
            [transition.spend for transition in transitions],
            AugSchemeMPL.aggregate(
                [quorum.aggregated_signature for quorum in quorums]
            ),
        )
        prepared = store.record_inventory_batch_prepared(
            purchase_id,
            items=tuple(reservation_items),
            bundle=bundle.to_json_dict(),
        )
    except (
        PaymentArtifactError,
        PaymentPurchaseConflict,
        ValidatorQuorumError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    submitted = await _submit_inventory_reservation(
        request,
        settings,
        store,
        prepared,
    )
    return _inventory_response(
        submitted,
        store.inventory_items(purchase_id),
    )


@router.post("/prepare", response_model=PrepareNativePurchaseResponse)
async def prepare_native_purchase(
    body: PrepareNativePurchaseRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> PrepareNativePurchaseResponse:
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    _require_server_to_server_token(settings, authorization)
    group = await _load_context_group(
        settings,
        request.app.state.coinset,
        body.purchase_id,
    )
    if any(context.reservation is None for context in group.contexts):
        raise HTTPException(
            status_code=409,
            detail="SmartDeed reservation terms are unavailable.",
        )
    first = group.contexts[0]
    selected: tuple[Coin, bytes, LineageProof | None] | None = None
    for key_hex in body.payment_public_keys:
        key = _hex_bytes(key_hex, 48, "paymentPublicKeys")
        candidate = await _select_payment_coin(
            request.app.state.coinset,
            first.purchase,
            key,
            minimum_amount=group.total_rail_amount,
        )
        if candidate is not None and (
            selected is None
            or int(candidate[0].amount) < int(selected[0].amount)
        ):
            selected = candidate
    if selected is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "No single confirmed wallet coin can cover the current "
                "H-system quote. Consolidate the selected asset and retry."
            ),
        )
    try:
        if group.batch is None:
            prepared = prepare_chia_buyer_offer_v3(
                payment_coin=selected[0],
                payment_public_key=selected[1],
                artifact=first.purchase,
                terms=first.terms,
                deed_singleton_struct=first.deed_struct,
                cat_lineage_proof=selected[2],
            )
        else:
            prepared = prepare_chia_buyer_batch_offer_v3(
                payment_coin=selected[0],
                payment_public_key=selected[1],
                batch=group.batch,
                terms=tuple(context.terms for context in group.contexts),
                deed_singleton_structs=tuple(
                    context.deed_struct for context in group.contexts
                ),
                cat_lineage_proof=selected[2],
            )
    except PaymentArtifactError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return PrepareNativePurchaseResponse(
        purchaseId=group.stored.purchase_id,
        buyerOffer=prepared.offer.to_bech32(),
        coinSpends=[_coin_spend_json(spend) for spend in prepared.offer.coin_spends()],
        rail=(
            "chia_xch"
            if first.purchase.rail == PaymentRail.CHIA_XCH
            else "chia_cat"
        ),
        amount=group.total_rail_amount,
        assetId=_hex32(first.purchase.rail_asset_id),
        quoteExpiresAt=(
            group.batch.quote_expires_at
            if group.batch is not None
            else first.purchase.quote_expires_at
        ),
        quantity=group.quantity,
        deedLauncherIds=group.deed_launcher_ids,
    )


@router.post("/complete", response_model=CompleteNativePurchaseResponse)
async def complete_native_purchase(
    body: CompleteNativePurchaseRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> CompleteNativePurchaseResponse:
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    _require_server_to_server_token(settings, authorization)
    group = await _load_context_group(
        settings,
        request.app.state.coinset,
        body.purchase_id,
    )
    if any(context.reservation is None for context in group.contexts):
        raise HTTPException(
            status_code=409,
            detail="SmartDeed reservation terms are unavailable.",
        )
    first = group.contexts[0]
    try:
        buyer_offer = await run_offer_job(
            "native", group=group, encoded=body.buyer_offer,
            signature_hex=body.aggregated_signature, network=settings.network,
        )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    payment_coin = buyer_offer.coin_spends()[0].coin
    payment_record = await request.app.state.coinset.get_coin_record_by_name(
        _hex32(payment_coin.name())
    )
    if not _record_is_unspent_coin(payment_record, payment_coin):
        raise HTTPException(
            status_code=409,
            detail="The wallet payment coin is no longer confirmed and unspent.",
        )

    try:
        reservations = tuple(
            context.reservation for context in group.contexts
            if context.reservation is not None
        )
        if len(reservations) != len(group.contexts):
            raise PaymentArtifactError(
                "SmartDeed reservation evidence is incomplete"
            )
        claim = PrimaryPurchaseClaim(
            network=settings.network,
            genesis_artifact_hash=str(
                first.genesis_artifact["artifactHash"]
            ),
            purchase_artifact=(
                group.stored.purchase_artifact
                if group.batch is not None
                else purchase_artifact_v3_to_json(first.purchase)
            ),
            buyer_offer=buyer_offer.to_bech32(),
            deed_coin_id=_hex32(first.deed_coin.name()),
            deed_puzzle_hash=_hex32(first.deed_coin.puzzle_hash),
            smart_deed_inner_hash=_hex32(
                first.terms.smart_deed_inner_hash
            ),
            reservation_expires_at=reservations[0].expires_at,
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
            deed_items=(
                tuple(
                    PrimaryPurchaseDeedItem(
                        deed_launcher_id=_hex32(context.purchase.deed_launcher_id),
                        deed_coin_id=_hex32(context.deed_coin.name()),
                        deed_puzzle_hash=_hex32(context.deed_coin.puzzle_hash),
                        smart_deed_inner_hash=_hex32(
                            context.terms.smart_deed_inner_hash
                        ),
                        reservation_expires_at=reservation.expires_at,
                    )
                    for context, reservation in zip(
                        group.contexts,
                        reservations,
                        strict=True,
                    )
                )
                if group.batch is not None
                else ()
            ),
        )
        quorum = await collect_primary_purchase_quorum(settings, claim)
        signed_spend, delivery_outputs = await run_offer_job(
            "native_bundle", group=group, buyer_offer=buyer_offer,
            signer_indices=quorum.signer_indices,
            aggregated_signature=quorum.aggregated_signature,
        )
    except (PaymentArtifactError, ValidatorQuorumError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    output_index = get_governed_output_index(
        settings.payment_purchase_db_path
    )
    try:
        output_index.prepare(
            purchase_id=group.stored.purchase_id,
            artifact_hash=(
                _hex32(group.batch.batch_hash)
                if group.batch is not None
                else _hex32(first.purchase.artifact_hash)
            ),
            rail=(
                "chia_xch"
                if first.purchase.rail == PaymentRail.CHIA_XCH
                else "chia_cat"
            ),
            delivery_kind="smartdeed",
            quantity=group.quantity,
            input_coin_ids=tuple(
                _hex32(coin.name()) for coin in signed_spend.removals()
            ),
            protocol_bundle_id=_hex32(signed_spend.name()),
            outputs=delivery_outputs,
        )
    except (GovernedOutputConflict, PaymentArtifactError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Protocol fee funding is unavailable. The purchase was not "
                "submitted."
            ),
        )
    try:
        result = await submitter.submit(signed_spend.to_json_dict())
    except ProtocolSubmissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"The atomic purchase was not accepted into the local mempool: {exc}",
        ) from exc
    try:
        exact_bundle = SpendBundle.from_json_dict(result["spendBundle"])
        _require_exact_governed_outputs(exact_bundle, delivery_outputs)
        output_index.bind_submission(
            group.stored.purchase_id,
            spend_bundle_id=str(result["spendBundleId"]),
            input_coin_ids=tuple(
                _hex32(coin.name()) for coin in exact_bundle.removals()
            ),
            mempool_observed_at=str(result["mempoolObservedAt"]),
        )
    except (KeyError, GovernedOutputConflict, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail=(
                "The submitted native purchase differs from its governed "
                f"delivery index: {exc}"
            ),
        ) from exc
    return CompleteNativePurchaseResponse(
        purchaseId=group.stored.purchase_id,
        transactionId=str(result["spendBundleId"]),
        status=str(result["status"]),
        signerIndices=sorted(
            quorum.signer_indices
        ),
        feeMojos=int(result["feeMojos"]),
        feeTargetSeconds=int(result["feeTargetSeconds"]),
        submissionProvider=str(result["submissionProvider"]),
        mempoolObservedAt=str(result["mempoolObservedAt"]),
        quantity=group.quantity,
        deedLauncherIds=group.deed_launcher_ids,
        expectedDeliveryCoinIds=[
            output.coin_id for output in delivery_outputs
        ],
    )


def _build_native_purchase_spend(*, group, buyer_offer, signer_indices, aggregated_signature):
    first = group.contexts[0]
    reservations = tuple(context.reservation for context in group.contexts)
    if group.batch is None:
        primary = build_native_primary_offer_v5(
            buyer_offer=buyer_offer,
            deed_coin=first.deed_coin,
            deed_singleton_struct=first.deed_struct,
            lineage_proof=first.deed_lineage,
            artifact=first.purchase,
            signer_indices=signer_indices,
            terms=first.terms,
            reservation=first.reservation,
        )
    else:
        primary = build_native_primary_batch_offer_v5(
            buyer_offer=buyer_offer,
            batch=group.batch,
            deed_coins=tuple(
                context.deed_coin for context in group.contexts
            ),
            deed_singleton_structs=tuple(
                context.deed_struct for context in group.contexts
            ),
            lineage_proofs=tuple(
                context.deed_lineage for context in group.contexts
            ),
            signer_indices_by_artifact=tuple(
                signer_indices for _context in group.contexts
            ),
            terms=tuple(context.terms for context in group.contexts),
            reservations=reservations,
        )
    valid_spend = primary.aggregate_offer.to_valid_spend()
    signed_spend = WalletSpendBundle(
        valid_spend.coin_spends,
        AugSchemeMPL.aggregate(
            [
                valid_spend.aggregated_signature,
                aggregated_signature,
            ]
        ),
    )
    return signed_spend, _governed_smartdeed_outputs(group, signed_spend)


def _governed_smartdeed_outputs(
    group: NativePurchaseGroup,
    bundle: WalletSpendBundle,
) -> tuple[GovernedOutputExpectation, ...]:
    outputs: list[GovernedOutputExpectation] = []
    evaluated = EvaluatedBundleOutputs(bundle)
    for ordinal, context in enumerate(group.contexts):
        vault = SINGLETON_MOD.curry(
            context.deed_struct,
            puzzle_for_p2_vault(context.purchase.vault_launcher_id),
        )
        coin = evaluated.find_exact_descendant(
            ancestor_coin_id=context.deed_coin.name(),
            puzzle_hash=bytes32(vault.get_tree_hash()),
            amount=1,
            label="vault SmartDeed",
        )
        outputs.append(
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
        )
    return tuple(outputs)


def _require_exact_governed_outputs(
    bundle: SpendBundle,
    outputs: tuple[GovernedOutputExpectation, ...],
) -> None:
    additions = {
        _hex32(coin.name()): coin for coin in bundle.additions()
    }
    for output in outputs:
        coin = additions.get(output.coin_id)
        if coin is None or (
            _hex32(coin.parent_coin_info) != output.parent_coin_id
            or _hex32(coin.puzzle_hash) != output.puzzle_hash
            or int(coin.amount) != output.amount
        ):
            raise PaymentArtifactError(
                "fee-funded bundle changed a governed SmartDeed output"
            )


async def _submit_inventory_reservation(
    request: Request,
    settings: Settings,
    store: Any,
    stored: StoredPaymentPurchase,
) -> StoredPaymentPurchase:
    if (stored.inventory_state in {"AUTHORIZATION_EXPIRED", "RELEASED"}
            or (stored.inventory_expires_at is not None and stored.inventory_expires_at <= int(time.time()))):
        raise HTTPException(status_code=409, detail="The reservation deadline has passed. Reconcile its chain status before starting a fresh purchase.")
    if stored.inventory_bundle is None:
        raise HTTPException(
            status_code=409,
            detail="SmartDeed reservation bundle is unavailable.",
        )
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Protocol fee funding is unavailable; no reservation was submitted.",
        )
    try:
        result = await submitter.submit(stored.inventory_bundle)
        return store.record_inventory_submitted(
            stored.purchase_id,
            bundle_id=str(result["spendBundleId"]).lower(),
            mempool_observed_at=str(result["mempoolObservedAt"]),
        )
    except (PaymentPurchaseConflict, ProtocolSubmissionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SmartDeed reservation was not proven in the local mempool: {exc}",
        ) from exc


async def _confirm_inventory_reservation(
    coinset: Any,
    store: Any,
    stored: StoredPaymentPurchase,
) -> StoredPaymentPurchase:
    items = store.inventory_items(stored.purchase_id)
    if not items or any(
        item.reserved_coin_id is None or item.reserved_puzzle_hash is None
        for item in items
    ):
        raise HTTPException(
            status_code=409,
            detail="SmartDeed reservation record is incomplete.",
        )
    heights: set[int] = set()
    for item in items:
        record = await coinset.get_coin_record_by_name(item.reserved_coin_id)
        coin = _coin_from_record(record)
        if coin is None:
            return stored
        if (
            _hex32(coin.name()) != item.reserved_coin_id
            or _hex32(coin.puzzle_hash) != item.reserved_puzzle_hash
            or int(coin.amount) != 1
            or not _record_is_unspent_coin(record, coin)
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "An on-chain SmartDeed reservation differs from the "
                    "approved batch."
                ),
            )
        height = int((record or {}).get("confirmed_block_index") or 0)
        if height <= 0:
            return stored
        heights.add(height)
    if len(heights) != 1:
        raise HTTPException(
            status_code=409,
            detail="The atomic reservation batch has inconsistent confirmation heights.",
        )
    if stored.inventory_state == "CONFIRMED":
        return stored
    try:
        return store.record_inventory_confirmed(
            stored.purchase_id,
            confirmation_height=next(iter(heights)),
        )
    except PaymentPurchaseConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


async def _mempool_bundle_id(
    coinset: Any,
    coin_id: str | None,
) -> str | None:
    if coin_id is None:
        return None
    items = await coinset.get_mempool_items_by_coin_name(coin_id)
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, Mapping):
            continue
        value = item.get("spend_bundle_name") or item.get("name")
        if not isinstance(value, str):
            continue
        try:
            return "0x" + _hex_bytes(value, 32, "spend bundle ID").hex()
        except ValueError:
            continue
    return None


def _inventory_response(
    stored: StoredPaymentPurchase,
    items: tuple[StoredPaymentInventoryItem, ...],
) -> InventoryReservationResponse:
    if (
        stored.inventory_available_coin_id is None
        or stored.inventory_reserved_coin_id is None
        or stored.inventory_reserved_puzzle_hash is None
        or stored.inventory_expires_at is None
    ):
        raise HTTPException(
            status_code=409,
            detail="SmartDeed reservation record is incomplete.",
        )
    return InventoryReservationResponse(
        purchaseId=stored.purchase_id,
        state=stored.inventory_state,
        availableCoinId=stored.inventory_available_coin_id,
        reservedCoinId=stored.inventory_reserved_coin_id,
        reservedPuzzleHash=stored.inventory_reserved_puzzle_hash,
        expiresAt=stored.inventory_expires_at,
        transactionId=stored.inventory_bundle_id,
        mempoolObservedAt=stored.inventory_mempool_observed_at,
        confirmationHeight=stored.inventory_confirmation_height,
        quantity=len(items),
        items=[
            InventoryReservationItemResponse(
                deedLauncherId=item.deed_launcher_id,
                availableCoinId=item.available_coin_id or "",
                reservedCoinId=item.reserved_coin_id or "",
                reservedPuzzleHash=item.reserved_puzzle_hash or "",
            )
            for item in items
        ],
    )


async def _load_context_group(
    settings: Settings,
    coinset: Any,
    purchase_id: str,
    *,
    require_live: bool = True,
    allowed_rails: tuple[PaymentRail, ...] = (
        PaymentRail.CHIA_XCH,
        PaymentRail.CHIA_CAT,
    ),
    require_inventory_reservation: bool = True,
) -> NativePurchaseGroup:
    normalized = "0x" + _hex_bytes(purchase_id, 32, "purchaseId").hex()
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        stored = store.get(normalized)
        if stored.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            batch = purchase_batch_from_json(stored.purchase_artifact)
            purchases = batch.artifacts
        else:
            batch = None
            purchases = (
                purchase_artifact_v3_from_json(stored.purchase_artifact),
            )
        inventory_by_launcher = {
            item.deed_launcher_id.casefold(): item
            for item in store.inventory_items(normalized)
        }
        if len(inventory_by_launcher) != len(purchases):
            raise PaymentArtifactError(
                "purchase inventory rows do not match the canonical quantity"
            )
    except (PaymentPurchaseNotFound, PaymentArtifactError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="The native purchase quote is missing, invalid, or expired.",
        ) from exc
    contexts = []
    for purchase in purchases:
        launcher = _hex32(purchase.deed_launcher_id).casefold()
        contexts.append(
            await _load_context(
                settings,
                coinset,
                normalized,
                require_live=require_live,
                allowed_rails=allowed_rails,
                require_inventory_reservation=require_inventory_reservation,
                stored_override=stored,
                purchase_override=purchase,
                inventory_item=inventory_by_launcher.get(launcher),
            )
        )
    return NativePurchaseGroup(
        stored=stored,
        contexts=tuple(contexts),
        batch=batch,
    )


async def _load_context(
    settings: Settings,
    coinset: Any,
    purchase_id: str,
    *,
    require_live: bool = True,
    allowed_rails: tuple[PaymentRail, ...] = (
        PaymentRail.CHIA_XCH,
        PaymentRail.CHIA_CAT,
    ),
    require_inventory_reservation: bool = True,
    stored_override: StoredPaymentPurchase | None = None,
    purchase_override: PurchaseArtifactV3 | None = None,
    inventory_item: StoredPaymentInventoryItem | None = None,
) -> NativePurchaseContext:
    normalized_purchase_id = "0x" + _hex_bytes(
        purchase_id,
        32,
        "purchaseId",
    ).hex()
    try:
        stored = stored_override or get_payment_purchase_store(
            settings.payment_purchase_db_path
        ).get(normalized_purchase_id)
        purchase = purchase_override or purchase_artifact_v3_from_json(
            stored.purchase_artifact
        )
        if require_live:
            purchase.assert_live(int(time.time()))
    except (PaymentPurchaseNotFound, PaymentArtifactError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="The native purchase quote is missing, invalid, or expired.",
        ) from exc
    if require_inventory_reservation and get_payment_purchase_store(settings.payment_purchase_db_path).pending_inventory_extension(normalized_purchase_id):
        raise HTTPException(status_code=409, detail="Reservation extension is unresolved. Resume its exact operation before delivery.")
    extended_position = None
    if purchase.rail not in allowed_rails:
        raise HTTPException(
            status_code=409,
            detail="Purchase rail is not supported by this settlement path.",
        )
    if require_inventory_reservation and (
        stored.inventory_state != "CONFIRMED"
        or inventory_item is None
        or inventory_item.state != "CONFIRMED"
        or inventory_item.reserved_coin_id is None
        or inventory_item.reserved_puzzle_hash is None
        or stored.inventory_expires_at is None
        or stored.inventory_confirmation_height is None
    ):
        raise HTTPException(
            status_code=409,
            detail="The exact SmartDeed is not yet confirmed as reserved for this purchase.",
        )
    if require_live:
        reasons = _artifact_rejection_reasons(
            stored.offer_artifact,
            stored.offer_artifact_hash,
            now=int(time.time()),
            settings=settings,
        )
        if reasons:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Purchase authorization is no longer current: "
                    + ", ".join(reasons)
                ),
            )

    from .zkpassport_enrollments import _sync_chia_stamp

    try:
        enrollment = _sync_chia_stamp(
            settings,
            _hex32(purchase.vault_launcher_id),
        )
    except HTTPException as exc:
        raise HTTPException(
            status_code=409,
            detail="The zkPassport vault credential is no longer current.",
        ) from exc
    receipt = enrollment.receipt
    if (
        enrollment.status != "chia_confirmed"
        or receipt is None
        or receipt.vaultLauncherId != _hex32(purchase.vault_launcher_id)
        or receipt.policyVersion != settings.zkpassport_policy_version
        or receipt.network != settings.network
        or receipt.bridgePolicyHash != settings.zkpassport_bridge_policy_hash
        or receipt.confirmedBlockIndex is None
    ):
        raise HTTPException(
            status_code=409,
            detail="A current chain-confirmed zkPassport vault credential is required.",
        )
    if require_live:
        stored_receipt = stored.offer_artifact.get("vaultCredentialReceipt")
        if (
            not isinstance(stored_receipt, Mapping)
            or receipt.chiaVaultCoinId != stored_receipt.get("chiaVaultCoinId")
            or receipt.identityAttestRoot != stored_receipt.get("identityAttestRoot")
        ):
            raise HTTPException(
                status_code=409,
                detail="Purchase authorization is no longer current.",
            )
    vault_record = get_registry().get(purchase.vault_launcher_id)
    if vault_record is None:
        raise HTTPException(
            status_code=409,
            detail="The zkPassport vault owner record is unavailable.",
        )

    protocol = stored.offer_artifact.get("protocol")
    if not isinstance(protocol, Mapping):
        raise HTTPException(status_code=409, detail="Purchase protocol context is missing.")
    workspace_id = protocol.get("collectionWorkspaceId")
    if not isinstance(workspace_id, str):
        raise HTTPException(status_code=409, detail="Purchase collection is missing.")
    try:
        collection = get_collection_store(settings).get(workspace_id)
    except CollectionNotFound as exc:
        raise HTTPException(status_code=409, detail="Purchase collection was not found.") from exc
    deed = next(
        (
            item
            for item in collection.get("deeds", [])
            if str(item.get("deedLauncherId") or "").lower()
            == _hex32(purchase.deed_launcher_id)
        ),
        None,
    )
    if not isinstance(deed, Mapping) or not deed.get("proposalId"):
        raise HTTPException(status_code=409, detail="Purchase SmartDeed is not published.")
    proposal = get_mint_proposal_store(settings).get(str(deed["proposalId"]))
    if (
        proposal is None
        or proposal.state not in {"EXECUTED", "MINTED"}
        or proposal.executed_bundle_id is None
        or proposal.smart_deed_inner_puzhash is None
        or deed.get("confirmationHeight") is None
        or not deed.get("outputCoinId")
    ):
        raise HTTPException(
            status_code=409,
            detail="Purchase SmartDeed is not executed and chain-confirmed.",
        )
    proposal_mismatches = _proposal_rejection_reasons(
        proposal,
        deed,
        purchase,
    )
    if proposal_mismatches:
        raise HTTPException(
            status_code=409,
            detail=(
                "Purchase SmartDeed no longer matches its governed proposal: "
                + ", ".join(proposal_mismatches)
            ),
        )
    try:
        genesis = load_signed_public_artifact(settings)
        validator_pubkeys = configured_validator_pubkeys(settings)
        launchers = genesis["launcherIds"]
        puzzle_hashes = genesis["puzzleHashes"]
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        protocol_puzhash = bytes32.fromhex(
            str(puzzle_hashes["protocolTreasuryPuzzleHash"]).removeprefix("0x")
        )
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32(
                _hex_bytes(
                    str(proposal.smart_deed_inner_puzhash),
                    32,
                    "smartDeedInnerPuzzleHash",
                )
            ),
            deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(
                protocol_did_singleton_struct=did_struct
            ),
            protocol_puzhash=protocol_puzhash,
            validator_pubkeys=validator_pubkeys,
            provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        if purchase.purchase_kind == PurchaseKind.PRESALE:
            from .presale_endpoints import get_presale_store

            series = get_presale_store(settings).get(
                _hex32(purchase.presale_terms_hash)
            )
            series_terms = series.get("terms")
            if (
                series.get("state") not in {"PRESALE", "LIVE"}
                or not isinstance(series_terms, Mapping)
                or str(series.get("termsHash") or "").lower()
                != _hex32(purchase.presale_terms_hash)
            ):
                raise PaymentArtifactError(
                    "presale reservation differs from its governed series"
                )
            presale_delivery_deadline = int(
                series_terms.get("launchDeadline") or 0
            ) + DELIVERY_WINDOW_SECONDS
            if presale_delivery_deadline <= int(time.time()):
                raise PaymentArtifactError(
                    "presale reservation delivery window has expired"
                )
        # PRESALE uses the same initial authorization bound as every other
        # purchase. A longer hold needs a separate, timely V5 extension; the
        # series delivery deadline does not authorize the initial reservation.
        initial_reservation_expiry = min(
            purchase.quote_expires_at,
            purchase.authorization_expires_at,
        )
        if require_inventory_reservation and getattr(stored, "inventory_extension_receipts", ()):
            from .inventory_extension_chain import current_position
            current_store = get_payment_purchase_store(settings.payment_purchase_db_path)
            extended_position = current_position(stored, current_store.inventory_items(normalized_purchase_id), genesis)
            terms = extended_position.terms
        reservation = InventoryReservationV1(
            artifact=purchase,
            expires_at=(
                (extended_position.reservation.expires_at if extended_position else stored.inventory_expires_at)
                if require_inventory_reservation
                and stored.inventory_expires_at is not None
                else initial_reservation_expiry
            ),
        )
        expected_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            (
                make_mint_offer_v5_inner(terms, reservation)
                if require_inventory_reservation
                else make_inventory_available_inner(terms)
            ),
        )
    except (KeyError, PublicArtifactError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="The signed primary-purchase coordinates are unavailable.",
        ) from exc
    released_cursor = (get_payment_purchase_store(settings.payment_purchase_db_path)
                       .latest_released_inventory(_hex32(purchase.deed_launcher_id)))
    expected_coin_id = (
        (_hex32(extended_position.coin.name()) if extended_position else str(inventory_item.reserved_coin_id))
        if require_inventory_reservation
        and inventory_item is not None
        else (str(released_cursor["availableCoinId"]) if released_cursor
              else str(deed["outputCoinId"]).lower())
    )
    deed_record = await coinset.get_coin_record_by_name(expected_coin_id)
    deed_coin = _coin_from_record(deed_record)
    if deed_coin is not None:
        try:
            terms = inventory_terms_for_puzzle_hash(
                terms, deed_struct, deed_coin.puzzle_hash,
                reservation=reservation if require_inventory_reservation else None,
            )
            expected_puzzle = SINGLETON_MOD.curry(
                deed_struct, make_mint_offer_v5_inner(terms, reservation)
                if require_inventory_reservation else make_inventory_available_inner(terms),
            )
        except PaymentArtifactError as exc:
            raise HTTPException(status_code=409, detail="The governed SmartDeed inventory version is unavailable.") from exc
    if (
        deed_coin is None
        or not _record_is_unspent_coin(deed_record, deed_coin)
        or (
            not require_inventory_reservation
            and released_cursor is None
            and deed_coin.parent_coin_info != purchase.deed_launcher_id
        )
        or deed_coin.puzzle_hash != expected_puzzle.get_tree_hash()
        or int(deed_coin.amount) != 1
        or _hex32(deed_coin.name()) != expected_coin_id
        or (
            require_inventory_reservation
            and _hex32(deed_coin.puzzle_hash)
            != (_hex32(extended_position.coin.puzzle_hash) if extended_position else inventory_item.reserved_puzzle_hash)
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="The governed SmartDeed coin is not available for delivery.",
        )
    launcher_record = await coinset.get_coin_record_by_name(
        _hex32(purchase.deed_launcher_id)
    )
    launcher_coin = _coin_from_record(launcher_record)
    expected_launcher_puzzle_hash = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=did_struct,
    )
    if (
        launcher_coin is None
        or launcher_coin.name() != purchase.deed_launcher_id
        or launcher_coin.puzzle_hash != expected_launcher_puzzle_hash
        or int(launcher_coin.amount) != 1
    ):
        raise HTTPException(status_code=409, detail="SmartDeed launcher lineage is unavailable.")
    lineage = LineageProof(parent_name=launcher_coin.parent_coin_info, amount=launcher_coin.amount)
    if extended_position:
        from .inventory_extension_chain import inspect_position
        from .inventory_recovery import release_peak
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
        try:
            peak = await release_peak(coinset, settings.network)
            await inspect_position(coinset, extended_position, peak)
            if await release_peak(coinset, settings.network) != peak:
                raise PaymentPurchaseConflict("chain tip changed during extended inventory loading")
            lineage = lineage_proof_for_coinsol(extended_position.creation_spend)
        except PaymentPurchaseConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    elif require_inventory_reservation:
        # The reservation may spend a released successor instead of the eve coin.
        available_id = inventory_item.available_coin_id
        if available_id != str(deed["outputCoinId"]).lower():
            available_record = await coinset.get_coin_record_by_name(available_id)
            available_coin = _coin_from_record(available_record)
            try:
                if available_coin is None or _hex32(available_coin.name()) != available_id:
                    raise PaymentPurchaseConflict("reservation available parent is unavailable")
                _, available_spent = record_coin(available_record, available_coin)
                reserved_height, _ = record_coin(deed_record, deed_coin)
                parent = decode_spend(await coinset.get_puzzle_and_solution(available_id, available_spent), available_coin)
                expected_parent = SINGLETON_MOD.curry(deed_struct, make_inventory_available_inner(terms))
                if (available_spent != reserved_height or deed_coin.parent_coin_info != available_coin.name()
                        or available_coin.puzzle_hash != expected_parent.get_tree_hash()):
                    raise PaymentPurchaseConflict("reservation available lineage is not atomic")
                from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
                lineage = lineage_proof_for_coinsol(parent)
            except PaymentPurchaseConflict as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        else:
            lineage = LineageProof(parent_name=purchase.deed_launcher_id,
                inner_puzzle_hash=bytes32(make_inventory_available_inner(terms).get_tree_hash()), amount=uint64(1))
    elif released_cursor:
        try:
            parent_record = await coinset.get_coin_record_by_name(_hex32(deed_coin.parent_coin_info))
            parent_coin = _coin_from_record(parent_record)
            if parent_coin is None or parent_coin.name() != deed_coin.parent_coin_info:
                raise PaymentPurchaseConflict("released inventory parent is unavailable")
            _, spent_height = record_coin(parent_record, parent_coin)
            child_height, _ = record_coin(deed_record, deed_coin)
            if not spent_height or spent_height != child_height:
                raise PaymentPurchaseConflict("released inventory lineage is not atomic")
            parent = decode_spend(await coinset.get_puzzle_and_solution(_hex32(parent_coin.name()), spent_height), parent_coin)
            lineage = timeout_successor_lineage(parent_spend=parent, successor=deed_coin,
                                                deed_struct=deed_struct, terms=terms)
        except PaymentPurchaseConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return NativePurchaseContext(
        stored=stored,
        purchase=purchase,
        terms=terms,
        deed_coin=deed_coin,
        deed_struct=deed_struct,
        deed_lineage=lineage,
        genesis_artifact=genesis,
        credential_receipt=receipt.model_dump(),
        credential_owner_auth_type=vault_record.auth_type,
        credential_owner_key=bytes(vault_record.owner_pubkey),
        reservation=reservation,
    )


def _proposal_rejection_reasons(
    proposal: Any,
    deed: Mapping[str, Any],
    purchase: PurchaseArtifactV3,
) -> list[str]:
    reasons: list[str] = []
    if proposal.deed_launcher_id != bytes(purchase.deed_launcher_id):
        reasons.append("deed launcher")
    try:
        proposal_collection_id = bytes32(
            canonicalise_property_id(proposal.collection_id)
        )
    except (TypeError, ValueError):
        proposal_collection_id = bytes32.zeros
    if proposal_collection_id != purchase.collection_id:
        reasons.append("collection")
    if proposal.property_id.casefold() != str(deed.get("deedId") or "").casefold():
        reasons.append("deed identifier")
    if proposal.share_ppm != purchase.share_ppm:
        reasons.append("share allocation")
    return reasons


async def _select_payment_coin(
    coinset: Any,
    purchase: PurchaseArtifactV3,
    payment_public_key: bytes,
    *,
    minimum_amount: int | None = None,
) -> tuple[Coin, bytes, LineageProof | None] | None:
    from chia.wallet.cat_wallet.cat_utils import construct_cat_puzzle
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk

    inner = puzzle_for_pk(G1Element.from_bytes(payment_public_key))
    if purchase.rail == PaymentRail.CHIA_XCH:
        puzzle = inner
    else:
        puzzle = construct_cat_puzzle(
            CAT_MOD,
            purchase.rail_asset_id,
            inner,
        )
    records = await coinset.get_coin_records_by_puzzle_hash(
        _hex32(puzzle.get_tree_hash()),
        include_spent=False,
    )
    required_amount = (
        purchase.rail_amount if minimum_amount is None else minimum_amount
    )
    if required_amount < purchase.rail_amount:
        raise PaymentArtifactError(
            "payment coin minimum cannot be below the authorized rail amount"
        )
    candidates: list[tuple[Coin, Mapping[str, Any]]] = []
    for record in records:
        coin = _coin_from_record(record)
        if (
            coin is not None
            and _record_is_unspent_coin(record, coin)
            and int(coin.amount) >= required_amount
        ):
            candidates.append((coin, record))
    for coin, _record in sorted(candidates, key=lambda item: int(item[0].amount)):
        if purchase.rail == PaymentRail.CHIA_XCH:
            return coin, payment_public_key, None
        parent_record = await coinset.get_coin_record_by_name(
            _hex32(coin.parent_coin_info)
        )
        parent_coin = _coin_from_record(parent_record)
        if parent_coin is None:
            continue
        height = int((parent_record or {}).get("spent_block_index") or 0)
        if height <= 0:
            continue
        solution = await coinset.get_puzzle_and_solution(
            _hex32(parent_coin.name()),
            height,
        )
        reveal_hex = (solution or {}).get("puzzle_reveal")
        if not isinstance(reveal_hex, str):
            continue
        try:
            args = match_cat_puzzle(
                uncurry_puzzle(
                    Program.from_bytes(
                        bytes.fromhex(reveal_hex.removeprefix("0x"))
                    )
                )
            )
            if args is None:
                continue
            _mod_hash, tail_hash, parent_inner = args
            if bytes32(tail_hash.as_atom()) != purchase.rail_asset_id:
                continue
            lineage = LineageProof(
                parent_name=parent_coin.parent_coin_info,
                inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
                amount=parent_coin.amount,
            )
        except (TypeError, ValueError):
            continue
        return coin, payment_public_key, lineage
    return None


def _parse_prepared_payment_offer(
    *, encoded: str, signature_hex: str, network: str,
    dummy_spends: int, asset_id: bytes32 | None,
    expected_assets: frozenset[bytes32 | None] | None = None,
) -> Offer:
    from chia.wallet.util.compute_hints import compute_spend_hints_and_additions
    decoded = decode_offer(
        encoded, real_spends=1, dummy_spends=dummy_spends,
        expected_assets=expected_assets,
    )
    validate_standard_payment(decoded, asset_id=asset_id)
    # Count both CLVM work and condition charges; a failed spend never gets a
    # fresh allowance or reaches Offer's exception-swallowing constructor.
    remaining = 100_000_000
    for spend in decoded.real_spends:
        _, used = compute_spend_hints_and_additions(spend, max_cost=remaining)
        if not 0 <= used <= remaining:
            raise PaymentArtifactError("wallet offer evaluation budget exceeded")
        remaining -= used
    unsigned = Offer.from_spend_bundle(decoded.bundle)
    signature = G2Element.from_bytes(_hex_bytes(signature_hex, 96, "aggregatedSignature"))
    buyer = Offer(
        unsigned.requested_payments,
        WalletSpendBundle(unsigned.coin_spends(), signature),
        unsigned.driver_dict,
    )
    _verify_buyer_signature(buyer, network)
    return buyer


def _validate_native_payment_offer(
    *, group: NativePurchaseGroup, encoded: str, signature_hex: str, network: str,
) -> Offer:
    first = group.contexts[0]
    buyer = _parse_prepared_payment_offer(
        encoded=encoded, signature_hex=signature_hex, network=network,
        dummy_spends=group.quantity,
        expected_assets=frozenset(context.purchase.deed_launcher_id for context in group.contexts),
        asset_id=(None if first.purchase.rail == PaymentRail.CHIA_XCH
                  else first.purchase.rail_asset_id),
    )
    if group.batch is None:
        validate_chia_buyer_offer_v3(
            buyer_offer=buyer, artifact=first.purchase, terms=first.terms,
            deed_singleton_struct=first.deed_struct,
        )
    else:
        validate_chia_buyer_batch_offer_v3(
            buyer_offer=buyer, batch=group.batch,
            terms=tuple(context.terms for context in group.contexts),
            deed_singleton_structs=tuple(context.deed_struct for context in group.contexts),
        )
    if len(buyer.coin_spends()) != 1 or buyer.fees() != 0:
        raise PaymentArtifactError("buyer offer must use one zero-fee payment coin")
    return buyer


def _verify_buyer_signature(offer: Offer, network: str) -> None:
    additional_data = AGG_SIG_ME_DATA.get(network)
    if additional_data is None:
        raise PaymentArtifactError("unsupported Chia network")
    pairs: list[tuple[G1Element, bytes]] = []
    for spend in offer.coin_spends():
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            100_000_000,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                additional_data,
            )
        )
    if not pairs or not AugSchemeMPL.aggregate_verify(
        [pair[0] for pair in pairs],
        [pair[1] for pair in pairs],
        offer.aggregated_signature(),
    ):
        raise PaymentArtifactError("wallet signature does not authorize this offer")


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping):
        return None
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            bytes32.fromhex(str(value["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(value["puzzle_hash"]).removeprefix("0x")),
            uint64(int(value["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _record_is_unspent_coin(record: Any, coin: Coin) -> bool:
    return (
        isinstance(record, Mapping)
        and int(record.get("confirmed_block_index") or 0) > 0
        and not bool(record.get("spent"))
        and int(record.get("spent_block_index") or 0) == 0
        and _coin_from_record(record) == coin
    )


def _coin_spend_json(spend: Any) -> dict[str, Any]:
    return {
        "coin": {
            "parent_coin_info": _hex32(spend.coin.parent_coin_info),
            "puzzle_hash": _hex32(spend.coin.puzzle_hash),
            "amount": int(spend.coin.amount),
        },
        "puzzle_reveal": "0x" + bytes(spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(spend.solution).hex(),
    }


def _hex_bytes(value: str, size: int, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return raw


def _hex32(value: Any) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be bytes32")
    return "0x" + raw.hex()


__all__ = ["router"]
