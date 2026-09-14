"""Protocol purchase artifact endpoints for Sols Lot integrations.

The Sols marketplace backend owns purchase-intent state and payment rails.
Solslot API owns the public, deterministic protocol artifact boundary:
build the artifact, verify its hash, and verify that a rail-specific payment
completion is bound to the artifact the buyer saw.
"""
from __future__ import annotations

import hashlib
import secrets
import stat
import time
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping, Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from chia_rs.sized_bytes import bytes32
from web3 import Web3

from solslot_puzzles.payment_artifacts_v2 import (
    DeedPriceV1,
    PaymentArtifactError,
    PaymentRail,
    PurchaseArtifactV2,
    build_cat_purchase_artifact,
    build_evm_test_usd_purchase_artifact,
    build_stripe_purchase_artifact,
    build_xch_purchase_artifact,
    purchase_artifact_from_json,
    purchase_artifact_to_json,
    validate_deed_price_plan,
)
from solslot_puzzles.payment_artifacts_v3 import (
    MAX_TECHNOLOGY_FEE_BPS,
    PurchaseDeliveryKind,
    PurchaseArtifactV3,
    PurchaseBatchV1,
    PurchaseKind,
    STRIPE_PAYMENT_PROVIDER_ID,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_settlement_receipt_v1,
    build_cat_purchase_artifact_v3,
    build_evm_test_usd_purchase_artifact_v3,
    build_stripe_purchase_artifact_v3,
    build_xch_purchase_artifact_v3,
    build_purchase_batch_v1,
    build_purchase_batch_settlement_receipt_v1,
    purchase_artifact_v3_from_json,
    purchase_artifact_v3_to_json,
    purchase_batch_from_json,
    purchase_batch_to_json,
    stripe_settlement_evidence_from_json,
    stripe_settlement_evidence_to_json,
    technology_fee_minor,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault

from .bootstrap_manifest import _assert_public_artifact, content_hash
from .config import Settings, get_settings
from .credential_auth import require_minting_writes
from .external_settlement import (
    base_result_authorization_puzzle_hash,
    build_base_batch_settlement_receipt,
    build_base_settlement_receipt,
)
from .collection_store import (
    CollectionNotFound,
    get_collection_store,
)
from .payment_quotes import (
    PaymentQuoteError,
    load_authorized_oracle_round,
    parse_authorized_oracle_round,
)
from .payment_purchase_store import (
    PaymentPurchaseConflict,
    PaymentPurchaseNotFound,
    get_payment_purchase_store,
)
from .omnichain_evidence import OmnichainEvidenceError, load_omnichain_evidence
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)
from .validator_quorum import configured_validator_pubkeys


router = APIRouter(prefix="/protocol", tags=["protocol-artifacts"])

ProtocolRail = Literal[
    "chia_xch",
    "chia_cat",
    "base_usdc",
    "evm_usdc",
    "stripe",
]
PurchaseIntentState = Literal[
    "created",
    "zk_verified",
    "artifact_ready",
    "payment_pending",
    "paid",
    "protocol_verified",
    "finalized",
    "failed",
    "expired",
    "refund_pending",
    "manual_review",
]

ALPHA_TECHNOLOGY_FEE_BPS = 100
PAYMENT_SETTLED_TOPIC = Web3.keccak(
    text="PaymentSettled(bytes32,address,address,uint256,bool,bool)"
).hex()
ESCROW_DEPOSIT_ABI = [
    {
        "inputs": [{"name": "globalPaymentId", "type": "bytes32"}],
        "name": "getDeposit",
        "outputs": [
            {
                "components": [
                    {"name": "depositor", "type": "address"},
                    {"name": "settlementToken", "type": "address"},
                    {"name": "localPaymentId", "type": "bytes32"},
                    {"name": "purchaseId", "type": "bytes32"},
                    {"name": "artifactHash", "type": "bytes32"},
                    {"name": "collectionId", "type": "bytes32"},
                    {"name": "deedLauncherId", "type": "bytes32"},
                    {"name": "vaultLauncherId", "type": "bytes32"},
                    {"name": "destinationPuzzle", "type": "bytes32"},
                    {"name": "requestMessageId", "type": "bytes32"},
                    {"name": "resultMessageId", "type": "bytes32"},
                    {"name": "warpNonce", "type": "bytes32"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "quantity", "type": "uint256"},
                    {"name": "hubChainSelector", "type": "uint64"},
                    {"name": "hubGateway", "type": "address"},
                    {"name": "createdAt", "type": "uint64"},
                    {"name": "quoteExpiresAt", "type": "uint64"},
                    {"name": "status", "type": "uint8"},
                    {"name": "succeeded", "type": "bool"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    }
]


@router.get("/artifact", response_model=dict[str, Any])
async def get_signed_public_artifact(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return only the administrator-signed RC23 ceremony artifact."""
    try:
        return load_signed_public_artifact(settings)
    except PublicArtifactMissing as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except PublicArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed RC23 public artifact failed verification.",
        ) from exc


class ProtocolPaymentTerms(BaseModel):
    currency: str = Field(..., min_length=1, max_length=32)
    amount: Optional[int] = Field(None, gt=0)
    quantity: int = Field(1, ge=1)
    usd_amount_minor: Optional[int] = Field(None, gt=0)
    payment_puzzle_hash: Optional[str] = Field(None, max_length=132)
    protocol_treasury_puzhash: Optional[str] = Field(None, max_length=132)
    chain_id: Optional[int] = Field(None, gt=0)


class BuildProtocolOfferArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["solslot-v2"]
    network: Literal["testnet11"]
    genesis_artifact_hash: str = Field(..., min_length=66, max_length=66)
    instance_id: str = Field(..., min_length=1, max_length=128)
    purchase_intent_id: str = Field(..., min_length=1, max_length=128)
    rail: ProtocolRail
    deed_launcher_id: Optional[str] = Field(None, min_length=1, max_length=132)
    property_id: str = Field(..., min_length=1, max_length=256)
    collection_id: str = Field(..., min_length=1, max_length=256)
    share_ppm: Optional[int] = Field(None, ge=1, le=1_000_000)
    vault_launcher_id: str = Field(..., min_length=1, max_length=132)
    current_vault_coin_id: str = Field(..., min_length=66, max_length=66)
    identity_attest_root: str = Field(..., min_length=66, max_length=66)
    expires_at: int = Field(..., gt=0, description="Unix seconds")
    payment_terms: ProtocolPaymentTerms
    zk_passport_required: bool = True
    current_state: PurchaseIntentState = "created"
    metadata: dict[str, Any] = Field(default_factory=dict)
    metadata_root: Optional[str] = Field(None, min_length=66, max_length=66)
    metadata_anchor_id: Optional[str] = Field(
        None, min_length=66, max_length=66
    )
    authorization_nonce: Optional[str] = Field(
        None, min_length=66, max_length=66
    )
    authorization_expires_at: Optional[int] = Field(None, gt=0)
    checkout_owner_auth_type: Optional[int] = Field(None,strict=True,ge=1,le=3)
    checkout_owner_key: Optional[str] = Field(None,pattern=r'^0x[0-9a-f]{66,130}$')
    native_asset_id: Optional[str] = Field(
        None, min_length=66, max_length=66
    )
    native_asset_decimals: Optional[int] = Field(None, ge=0, le=18)

    @model_validator(mode="after")
    def require_zkpassport(self):
        if self.zk_passport_required is not True:
            raise ValueError("zk_passport_required must be true for Sols Lot protocol purchases")
        return self


class ProtocolOfferArtifactResponse(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    protocol: dict[str, Any]
    purchase_artifact: Optional[dict[str, Any]] = None
    purchase_batch: Optional[dict[str, Any]] = None
    purchase_artifact_hash: Optional[str] = None
    purchase_id: Optional[str] = None
    oracle_authorization: Optional[dict[str, Any]] = None


class VerifyProtocolOfferArtifactRequest(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    now: Optional[int] = Field(None, gt=0)


class VerifyProtocolOfferArtifactResponse(BaseModel):
    valid: bool
    artifact_hash: str
    expected_artifact_hash: str
    expired: bool
    reasons: list[str] = Field(default_factory=list)


class VerifyPurchaseFinalizationRequest(BaseModel):
    artifact: dict[str, Any]
    artifact_hash: str
    rail: ProtocolRail
    purchase_intent_id: str = Field(..., min_length=1, max_length=128)
    payment_evidence: dict[str, Any] = Field(default_factory=dict)
    now: Optional[int] = Field(None, gt=0)


class VerifyPurchaseFinalizationResponse(BaseModel):
    verified: bool
    artifact_hash: str
    finalized_state: PurchaseIntentState
    reasons: list[str] = Field(default_factory=list)
    delivery_state: Optional[str] = None


class CanonicalizeStripeEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    stripe_account_id: str = Field(
        ..., alias="stripeAccountId", pattern=r"^acct_[A-Za-z0-9_]+$"
    )
    mode: Literal["test", "live"]
    payment_intent_id: str = Field(
        ..., alias="paymentIntentId", pattern=r"^pi_[A-Za-z0-9_]+$"
    )
    event_id: str = Field(
        ..., alias="eventId", pattern=r"^evt_[A-Za-z0-9_]+$"
    )
    amount_minor: int = Field(..., alias="amountMinor", gt=0)
    currency: Literal["usd"]
    method_family: Literal["card", "us_bank_account"] = Field(
        ..., alias="methodFamily"
    )
    funding_type: Literal[
        "not_applicable",
        "credit",
        "debit",
        "prepaid",
        "unknown",
    ] = Field(..., alias="fundingType")
    processing_charge_minor: int = Field(
        0,
        alias="processingChargeMinor",
        ge=0,
    )
    payment_status: Literal[
        "processing",
        "succeeded",
        "canceled",
    ] = Field(..., alias="paymentStatus")
    refund_state: Literal["none", "partial", "full"] = Field(
        ..., alias="refundState"
    )
    refunded_minor: int = Field(0, alias="refundedMinor", ge=0)
    dispute_state: Literal["none", "open", "won", "lost"] = Field(
        ..., alias="disputeState"
    )
    observed_at: int = Field(..., alias="observedAt", gt=0)


class VerifyExternalEscrowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    gateway_profile: str = Field(
        ...,
        alias="gatewayProfile",
        min_length=1,
        max_length=32,
    )
    global_payment_id: str = Field(
        ...,
        alias="globalPaymentId",
        min_length=66,
        max_length=66,
    )
    purchase_id: str = Field(
        ...,
        alias="purchaseId",
        min_length=66,
        max_length=66,
    )
    artifact_hash: str = Field(
        ...,
        alias="artifactHash",
        min_length=66,
        max_length=66,
    )
    amount: int = Field(..., gt=0)
    quantity: int = Field(..., ge=1)
    collection_id: str = Field(
        ...,
        alias="collectionId",
        min_length=66,
        max_length=66,
    )
    deed_launcher_id: str = Field(
        ...,
        alias="deedLauncherId",
        min_length=66,
        max_length=66,
    )
    vault_launcher_id: str = Field(
        ...,
        alias="vaultLauncherId",
        min_length=66,
        max_length=66,
    )
    destination_puzzle: str = Field(
        ...,
        alias="destinationPuzzle",
        min_length=66,
        max_length=66,
    )
    quote_expires_at: int = Field(..., alias="quoteExpiresAt", gt=0)
    depositor: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    settlement_token: str = Field(
        ...,
        alias="settlementToken",
        pattern=r"^0x[0-9a-fA-F]{40}$",
    )
    local_payment_id: str = Field(
        ...,
        alias="localPaymentId",
        pattern=r"^0x[0-9a-fA-F]{64}$",
    )


class ExternalEscrowSource(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    chain_id: int = Field(..., alias="chainId", gt=0)
    spoke: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    transaction_hash: str = Field(
        ...,
        alias="transactionHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
    )
    block_number: int = Field(..., alias="blockNumber", gt=0)
    block_hash: str = Field(
        ...,
        alias="blockHash",
        pattern=r"^0x[0-9a-fA-F]{64}$",
    )
    block_timestamp: int = Field(..., alias="blockTimestamp", gt=0)
    log_index: int = Field(..., alias="logIndex", ge=0)
    confirmations: int = Field(..., ge=12)


class VerifyExternalEscrowWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    escrow_message: VerifyExternalEscrowRequest = Field(..., alias="escrowMessage")
    source: ExternalEscrowSource


class VerifyExternalEscrowResponse(BaseModel):
    verified: bool
    purchase_intent_id: str
    purchase_artifact: dict[str, Any]
    fulfillment: dict[str, Any]


@router.post("/offer-artifacts", response_model=ProtocolOfferArtifactResponse)
async def build_protocol_offer_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> ProtocolOfferArtifactResponse:
    require_minting_writes(settings)
    _require_server_to_server_token(settings, authorization)
    from .zkpassport_enrollments import _normalize_hex32, _sync_chia_stamp
    from .vault_eligibility import require_current_approved_vault

    vault_launcher_id = _normalize_hex32(body.vault_launcher_id, "vault_launcher_id")
    approved_vault = require_current_approved_vault(
        settings,
        vault_launcher_id,
        expected_current_coin_id=body.current_vault_coin_id,
        expected_identity_attest_root=body.identity_attest_root,
        sync_enrollment=_sync_chia_stamp,
    )
    receipt = approved_vault.enrollment.receipt
    try:
        genesis_artifact = load_signed_public_artifact(settings)
    except PublicArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed RC23 genesis artifact is unavailable or invalid.",
        ) from exc
    expected_genesis_hash = _normalize_hex32(
        body.genesis_artifact_hash,
        "genesis_artifact_hash",
    )
    if genesis_artifact.get("artifactHash") != expected_genesis_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The requested genesis artifact is not the active signed artifact.",
        )
    from .inventory_payment_hold_claims import payment_hold_activation
    try:
        hold_capability=payment_hold_activation(genesis_artifact,settings.runtime_environment+'-alpha',required=False)
        if hold_capability is not None and hold_capability['adapterVersion']==2:
            from .purchase_admission import require_admission_owner
            require_admission_owner(vault_launcher_id,body.checkout_owner_auth_type,body.checkout_owner_key)
            if body.payment_terms.quantity>hold_capability['maxReservedDeedsPerIdentity']:
                raise ValueError('reviewed alpha admission permits one reserved deed per identity')
            if not int(time.time())<body.expires_at<=int(time.time())+hold_capability['maxSoftQuoteSeconds']:
                raise ValueError('reviewed alpha checkout requires a live fifteen-minute soft quote')
            get_payment_purchase_store(settings.payment_purchase_db_path).admit_purchase(
                purchase_intent_id=body.purchase_intent_id,receipt=receipt.model_dump(),
                activation=hold_capability,now=int(time.time()),owner_auth_type=body.checkout_owner_auth_type,owner_key=body.checkout_owner_key)
    except ValueError as exc:
        raise HTTPException(status_code=429,detail='New checkout admission is unavailable. Recover the existing purchase or retry later.',
                            headers={'Retry-After':'60'}) from exc
    try:
        if body.rail in {"base_usdc", "evm_usdc"}:
            chain_id = body.payment_terms.chain_id
            if chain_id is None and body.rail == "base_usdc":
                chain_id = 84532
            token_address = (
                settings.payment_evm_usdc_tokens.get(str(chain_id))
                if chain_id is not None
                else None
            )
            if token_address is None:
                raise OmnichainEvidenceError("EVM chain is not enabled for protocol purchases")
            load_omnichain_evidence(
                settings,
                chain_id=chain_id,
                token_address=token_address,
                gateway_profile=str(settings.payment_omnichain_gateway_profile or ""),
            )
        canonical_payment = _build_canonical_payment_artifact(
            body,
            settings,
            vault_launcher_id=vault_launcher_id,
            identity_attest_root=receipt.identityAttestRoot,
            genesis_artifact=genesis_artifact,
        )
    except OmnichainEvidenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except (PaymentArtifactError, PaymentQuoteError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    artifact = _build_artifact(
        body,
        settings,
        receipt=receipt.model_dump(),
        genesis_artifact=genesis_artifact,
        canonical_payment=canonical_payment,
    )
    try:
        _assert_protocol_offer_public_artifact(artifact)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    artifact_hash = content_hash(artifact)
    purchase_artifact, oracle_authorization = canonical_payment
    try:
        stored = get_payment_purchase_store(
            settings.payment_purchase_db_path
        ).save(
            purchase_intent_id=body.purchase_intent_id,
            rail=body.rail,
            offer_artifact_hash=artifact_hash,
            offer_artifact=artifact,
            purchase_artifact=purchase_artifact,
            created_at=int(time.time()),
        )
    except PaymentPurchaseConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    artifact = stored.offer_artifact
    artifact_hash = stored.offer_artifact_hash
    purchase_artifact = stored.purchase_artifact
    oracle_authorization = artifact.get("oracleAuthorization")
    return ProtocolOfferArtifactResponse(
        artifact=artifact,
        artifact_hash=artifact_hash,
        protocol=_protocol_object_from_artifact(artifact, artifact_hash),
        purchase_artifact=purchase_artifact,
        purchase_batch=(
            purchase_artifact
            if purchase_artifact.get("schema") == "solslot.purchase-batch.v1"
            else None
        ),
        purchase_artifact_hash=(
            purchase_artifact["batchHash"]
            if purchase_artifact.get("schema") == "solslot.purchase-batch.v1"
            else purchase_artifact["artifactHash"]
        ),
        purchase_id=purchase_artifact["purchaseId"],
        oracle_authorization=oracle_authorization,
    )


@router.post("/offer-artifacts/verify", response_model=VerifyProtocolOfferArtifactResponse)
async def verify_protocol_offer_artifact(
    body: VerifyProtocolOfferArtifactRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> VerifyProtocolOfferArtifactResponse:
    reasons = _artifact_rejection_reasons(
        body.artifact,
        body.artifact_hash,
        now=body.now,
        settings=settings,
    )
    expected_hash = content_hash(body.artifact)
    return VerifyProtocolOfferArtifactResponse(
        valid=not reasons,
        artifact_hash=body.artifact_hash,
        expected_artifact_hash=expected_hash,
        expired="expired" in reasons,
        reasons=reasons,
    )


@router.post(
    "/stripe-evidence",
    response_model=dict[str, Any],
)
async def canonicalize_stripe_evidence(
    body: CanonicalizeStripeEvidenceRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Canonicalize provider observations; validators re-fetch before signing."""

    _require_server_to_server_token(settings, authorization)
    if (
        not settings.stripe_account_id
        or body.stripe_account_id != settings.stripe_account_id
        or body.mode != settings.stripe_mode
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stripe evidence does not match the configured account and mode.",
        )
    methods = {
        "card": StripeMethodFamily.CARD,
        "us_bank_account": StripeMethodFamily.US_BANK_ACCOUNT,
    }
    funding = {
        "not_applicable": StripeFundingType.BANK_ACCOUNT,
        "credit": StripeFundingType.CREDIT,
        "debit": StripeFundingType.DEBIT,
        "prepaid": StripeFundingType.PREPAID,
        "unknown": StripeFundingType.UNKNOWN,
    }
    payment_statuses = {
        "processing": StripePaymentStatus.PROCESSING,
        "succeeded": StripePaymentStatus.SUCCEEDED,
        "canceled": StripePaymentStatus.CANCELED,
    }
    refunds = {
        "none": StripeRefundState.NONE,
        "partial": StripeRefundState.PARTIAL,
        "full": StripeRefundState.FULL,
    }
    disputes = {
        "none": StripeDisputeState.NONE,
        "open": StripeDisputeState.OPEN,
        "won": StripeDisputeState.WON,
        "lost": StripeDisputeState.LOST,
    }
    try:
        evidence = StripeSettlementEvidenceV1(
            stripe_account_id=body.stripe_account_id,
            livemode=body.mode == "live",
            payment_intent_id=body.payment_intent_id,
            event_id=body.event_id,
            amount_minor=body.amount_minor,
            currency=body.currency,
            method_family=methods[body.method_family],
            funding_type=funding[body.funding_type],
            processing_charge_minor=body.processing_charge_minor,
            status=payment_statuses[body.payment_status],
            refunded_minor=body.refunded_minor,
            refund_state=refunds[body.refund_state],
            dispute_state=disputes[body.dispute_state],
            observed_at=body.observed_at,
        )
    except (KeyError, PaymentArtifactError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return stripe_settlement_evidence_to_json(evidence)


@router.post(
    "/purchase-finalizations/verify",
    response_model=VerifyPurchaseFinalizationResponse,
)
async def verify_purchase_finalization(
    body: VerifyPurchaseFinalizationRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> VerifyPurchaseFinalizationResponse:
    _require_server_to_server_token(settings, authorization)
    verification_now = body.now
    if body.rail == "stripe":
        protocol_expiry = _mapping(body.artifact.get("protocol")).get("expiresAt")
        if isinstance(protocol_expiry, int) and protocol_expiry > 1:
            verification_now = min(
                verification_now or int(time.time()),
                protocol_expiry - 1,
            )
    reasons = _artifact_rejection_reasons(
        body.artifact,
        body.artifact_hash,
        now=verification_now,
        settings=settings,
    )
    protocol = _mapping(body.artifact.get("protocol"))
    if protocol.get("purchaseIntentId") != body.purchase_intent_id:
        reasons.append("purchase_intent_mismatch")
    if protocol.get("rail") != body.rail:
        reasons.append("rail_mismatch")
    canonical: PurchaseArtifactV2 | PurchaseArtifactV3 | PurchaseBatchV1 | None = None
    canonical_json = (
        body.artifact.get("purchaseBatchV1")
        or body.artifact.get("purchaseArtifactV3")
        or body.artifact.get("purchaseArtifactV2")
    )
    if isinstance(canonical_json, Mapping):
        try:
            canonical = (
                purchase_batch_from_json(canonical_json)
                if canonical_json.get("schema") == "solslot.purchase-batch.v1"
                else _purchase_artifact_from_json(canonical_json)
            )
        except (PaymentArtifactError, TypeError, ValueError):
            reasons.append("purchase_artifact_invalid")
    evidence_reasons = _payment_evidence_rejection_reasons(
        body.rail,
        body.payment_evidence,
    )
    reasons.extend(evidence_reasons)
    if canonical is not None and body.rail == "stripe":
        if not isinstance(canonical, (PurchaseArtifactV3, PurchaseBatchV1)):
            reasons.append("stripe_requires_purchase_artifact_v3")
        else:
            try:
                stripe_evidence = stripe_settlement_evidence_from_json(
                    body.payment_evidence
                )
            except (PaymentArtifactError, TypeError, ValueError):
                reasons.append("stripe_settlement_evidence_invalid")
            else:
                expected_stripe_total = (
                    canonical.total_subtotal_minor
                    if isinstance(canonical, PurchaseBatchV1)
                    else canonical.subtotal_minor
                ) + stripe_evidence.processing_charge_minor
                if stripe_evidence.amount_minor != expected_stripe_total:
                    reasons.append("stripe_amount_mismatch")
                if (
                    stripe_evidence.status
                    != StripePaymentStatus.SUCCEEDED
                    or stripe_evidence.refund_state
                    != StripeRefundState.NONE
                    or stripe_evidence.dispute_state
                    != StripeDisputeState.NONE
                ):
                    reasons.append("stripe_payment_not_deliverable")
                if not reasons:
                    try:
                        _verify_stripe_provider_evidence(
                            settings,
                            canonical,
                            stripe_evidence,
                        )
                    except PaymentArtifactError:
                        reasons.append("stripe_provider_unverified")
    if canonical is not None and body.rail in {"base_usdc", "evm_usdc"}:
        canonical_item = (
            canonical.artifacts[0]
            if isinstance(canonical, PurchaseBatchV1)
            else canonical
        )
        try:
            stored = get_payment_purchase_store(
                settings.payment_purchase_db_path
            ).get(_hex32(canonical.purchase_id))
        except PaymentPurchaseNotFound:
            reasons.append("external_purchase_not_found")
        else:
            message = stored.external_message
            if message is None:
                reasons.append("external_message_not_verified")
            else:
                token_address = settings.payment_evm_usdc_tokens.get(
                    str(canonical_item.rail_chain_id)
                )
                gateway_profile = message.get("gatewayProfile")
                if token_address is None or not isinstance(gateway_profile, str):
                    reasons.append("external_escrow_evidence_unavailable")
                else:
                    try:
                        load_omnichain_evidence(
                            settings,
                            chain_id=canonical_item.rail_chain_id,
                            token_address=token_address,
                            gateway_profile=gateway_profile,
                        )
                    except OmnichainEvidenceError:
                        reasons.append("external_escrow_evidence_unavailable")
                if (
                    body.payment_evidence.get("global_payment_id")
                    != message.get("globalPaymentId")
                ):
                    reasons.append("external_global_payment_mismatch")
    delivery_state: str | None = None
    if (
        not reasons
        and body.rail in {"stripe", "base_usdc", "evm_usdc"}
        and isinstance(canonical, (PurchaseArtifactV3, PurchaseBatchV1))
    ):
        try:
            canonical_item = (
                canonical.artifacts[0]
                if isinstance(canonical, PurchaseBatchV1)
                else canonical
            )
            canonical_hash = (
                canonical.batch_hash
                if isinstance(canonical, PurchaseBatchV1)
                else canonical.artifact_hash
            )
            stored = get_payment_purchase_store(
                settings.payment_purchase_db_path
            ).get(_hex32(canonical.purchase_id))
            if (
                stored.purchase_intent_id != body.purchase_intent_id
                or stored.artifact_hash != _hex32(canonical_hash)
                or stored.offer_artifact_hash != body.artifact_hash
                or stored.purchase_artifact != dict(canonical_json)
            ):
                reasons.append("external_stored_purchase_mismatch")
            else:
                delivery_evidence: Mapping[str, Any]
                if body.rail == "stripe":
                    validators = configured_validator_pubkeys(settings)
                    receipt = (
                        build_purchase_batch_settlement_receipt_v1(
                            batch=canonical,
                            provider_id=STRIPE_PAYMENT_PROVIDER_ID,
                            external_reference_hash=(
                                stripe_evidence.payment_reference_hash
                            ),
                            evidence_hash=stripe_evidence.evidence_hash,
                            observed_at=stripe_evidence.observed_at,
                            validator_pubkeys=validators,
                            collected_amount_minor=stripe_evidence.amount_minor,
                            processing_charge_minor=(
                                stripe_evidence.processing_charge_minor
                            ),
                        )
                        if isinstance(canonical, PurchaseBatchV1)
                        else build_stripe_settlement_receipt_v1(
                            artifact=canonical,
                            evidence=stripe_evidence,
                            validator_pubkeys=validators,
                        )
                    )
                    delivery_evidence = body.payment_evidence
                    payment_rail = "stripe"
                else:
                    if stored.external_message is None:
                        raise PaymentArtifactError(
                            "verified Base escrow evidence is missing"
                        )
                    delivery_evidence = stored.external_message
                    token_address = settings.payment_evm_usdc_tokens.get(
                        str(canonical_item.rail_chain_id)
                    )
                    gateway_profile = delivery_evidence.get(
                        "gatewayProfile"
                    )
                    if token_address is None or not isinstance(
                        gateway_profile,
                        str,
                    ):
                        raise PaymentArtifactError(
                            "reviewed Base deployment evidence is unavailable"
                        )
                    deployment = load_omnichain_evidence(
                        settings,
                        chain_id=canonical_item.rail_chain_id,
                        token_address=token_address,
                        gateway_profile=gateway_profile,
                    )
                    result_puzzle_hash = (
                        base_result_authorization_puzzle_hash(
                            artifact=canonical,
                            evidence=delivery_evidence,
                            return_puzzle_hash=bytes32.from_hexstr(
                                deployment.return_puzzle_hash
                            ),
                        )
                    )
                    receipt = (
                        build_base_batch_settlement_receipt(
                            batch=canonical,
                            evidence=delivery_evidence,
                            validator_pubkeys=configured_validator_pubkeys(
                                settings
                            ),
                            result_authorization_puzzle_hash=result_puzzle_hash,
                        )
                        if isinstance(canonical, PurchaseBatchV1)
                        else build_base_settlement_receipt(
                            artifact=canonical,
                            evidence=delivery_evidence,
                            result_authorization_puzzle_hash=result_puzzle_hash,
                        )
                    )
                    payment_rail = "base_usdc"
                if (
                    body.rail == "stripe"
                    and isinstance(canonical, PurchaseArtifactV3)
                    and canonical.purchase_kind == PurchaseKind.PRESALE
                ):
                    if canonical.delivery_kind != PurchaseDeliveryKind.SMARTDEED:
                        raise PaymentArtifactError(
                            "Stripe presales can issue SmartDeed vouchers only"
                        )
                    from .presale_endpoints import get_presale_store

                    voucher_event = get_presale_store(
                        settings
                    ).ingest_stripe_payment(
                        _hex32(canonical.presale_terms_hash),
                        artifact=canonical,
                        receipt=receipt,
                        evidence_id=stripe_evidence.event_id,
                        issued_purchase=stored,
                    )
                    delivery_state = str(voucher_event["voucherState"])
                else:
                    from .stripe_delivery_store import get_stripe_delivery_store

                    delivery = get_stripe_delivery_store(
                        settings.stripe_delivery_db_path
                    ).queue(
                        purchase_id=_hex32(canonical.purchase_id),
                        evidence=delivery_evidence,
                        receipt_hash=_hex32(receipt.receipt_hash),
                        payment_rail=payment_rail,
                        delivery_kind=(
                            "sgt"
                            if canonical_item.delivery_kind
                            == PurchaseDeliveryKind.SGT
                            else "smartdeed"
                        ),
                    )
                    delivery_state = delivery.state
        except (PaymentPurchaseNotFound, PaymentArtifactError, ValueError):
            reasons.append("external_delivery_queue_rejected")
    return VerifyPurchaseFinalizationResponse(
        verified=not reasons,
        artifact_hash=content_hash(body.artifact),
        finalized_state=(
            "paid"
            if not reasons and body.rail == "stripe"
            else "protocol_verified"
            if not reasons
            else "manual_review"
        ),
        reasons=reasons,
        delivery_state=delivery_state,
    )


@router.post(
    "/external-payments/verify",
    response_model=VerifyExternalEscrowResponse,
)
async def verify_external_escrow(
    payload: VerifyExternalEscrowWebhookRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> VerifyExternalEscrowResponse:
    """Verify and bind one confirmed escrow event and its protocol message."""

    _require_omnichain_ingest_token(settings, authorization)
    body = payload.escrow_message
    source = payload.source
    normalized = {
        "gatewayProfile": body.gateway_profile,
        "globalPaymentId": _normalized_hex32(
            body.global_payment_id,
            "globalPaymentId",
        ),
        "purchaseId": _normalized_hex32(
            body.purchase_id,
            "purchaseId",
        ),
        "artifactHash": _normalized_hex32(
            body.artifact_hash,
            "artifactHash",
        ),
        "amount": body.amount,
        "quantity": body.quantity,
        "collectionId": _normalized_hex32(
            body.collection_id,
            "collectionId",
        ),
        "deedLauncherId": _normalized_hex32(
            body.deed_launcher_id,
            "deedLauncherId",
        ),
        "vaultLauncherId": _normalized_hex32(
            body.vault_launcher_id,
            "vaultLauncherId",
        ),
        "destinationPuzzle": _normalized_hex32(
            body.destination_puzzle,
            "destinationPuzzle",
        ),
        "quoteExpiresAt": body.quote_expires_at,
        "depositor": _normalized_evm_address(body.depositor, "depositor"),
        "settlementToken": _normalized_evm_address(
            body.settlement_token,
            "settlementToken",
        ),
        "localPaymentId": _normalized_hex32(
            body.local_payment_id,
            "localPaymentId",
        ),
        "source": {
            "chainId": source.chain_id,
            "spoke": _normalized_evm_address(source.spoke, "source.spoke"),
            "transactionHash": _normalized_hex32(
                source.transaction_hash,
                "source.transactionHash",
            ),
            "blockNumber": source.block_number,
            "blockHash": _normalized_hex32(source.block_hash, "source.blockHash"),
            "blockTimestamp": source.block_timestamp,
            "logIndex": source.log_index,
            "confirmations": source.confirmations,
        },
    }
    if normalized["globalPaymentId"] == _hex32(bytes32.zeros):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="globalPaymentId cannot be zero",
        )
    store = get_payment_purchase_store(settings.payment_purchase_db_path)
    try:
        record = store.get(normalized["purchaseId"])
    except PaymentPurchaseNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    if record.rail not in {"base_usdc", "evm_usdc"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="purchase artifact is not an EVM escrow purchase",
        )
    try:
        batch = (
            purchase_batch_from_json(record.purchase_artifact)
            if record.purchase_artifact.get("schema")
            == "solslot.purchase-batch.v1"
            else None
        )
        canonical_document = (
            batch
            if batch is not None
            else _purchase_artifact_from_json(record.purchase_artifact)
        )
        canonical_document.assert_live(int(time.time()))
        canonical = (
            batch.artifacts[0] if batch is not None else canonical_document
        )
    except PaymentArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    token_address = settings.payment_evm_usdc_tokens.get(str(canonical.rail_chain_id))
    if token_address is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="EVM chain is not enabled for protocol purchases",
        )
    try:
        deployment = load_omnichain_evidence(
            settings,
            chain_id=canonical.rail_chain_id,
            token_address=token_address,
            gateway_profile=normalized["gatewayProfile"],
        )
    except OmnichainEvidenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    source_evidence = normalized["source"]
    if (
        source_evidence["chainId"] != canonical.rail_chain_id
        or source_evidence["spoke"] != deployment.spoke_address
        or source_evidence["confirmations"] < deployment.confirmations
        or normalized["settlementToken"] != token_address.lower()
        or canonical.rail_asset_id != _evm_token_asset_id(token_address)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="external payment provenance does not match the reviewed escrow rail",
        )
    try:
        _verify_external_escrow_chain_evidence(
            settings,
            normalized=normalized,
            deployment=deployment,
        )
    except PaymentArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    delivery_amount = batch.quantity if batch is not None else 1
    delivery_context = canonical.collection_id
    delivery_asset = canonical.deed_launcher_id
    if isinstance(canonical, PurchaseArtifactV3) and batch is None:
        delivery_amount = canonical.delivery_amount
        delivery_context = canonical.delivery_context_hash
        delivery_asset = canonical.delivery_asset_id
    expected = {
        "purchaseId": _hex32(canonical_document.purchase_id),
        "artifactHash": _hex32(
            batch.batch_hash if batch is not None else canonical.artifact_hash
        ),
        "amount": (
            batch.total_rail_amount if batch is not None else canonical.rail_amount
        ),
        # Preserve the reviewed escrow ABI while allowing PurchaseArtifactV3
        # to commit either a SmartDeed or SGT delivery. For V3 these legacy
        # wire slots carry the generic delivery tuple.
        "quantity": delivery_amount,
        "collectionId": _hex32(delivery_context),
        "deedLauncherId": _hex32(delivery_asset),
        "vaultLauncherId": _hex32(canonical.vault_launcher_id),
        "destinationPuzzle": _hex32(canonical.vault_p2_puzzle_hash),
        "quoteExpiresAt": canonical.quote_expires_at,
    }
    mismatches = [
        field
        for field, expected_value in expected.items()
        if normalized[field] != expected_value
    ]
    if mismatches:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "external payment does not match the purchase artifact: "
                + ", ".join(mismatches)
            ),
        )
    try:
        record = store.bind_external_message(
            normalized["purchaseId"],
            normalized,
        )
    except (PaymentPurchaseConflict, PaymentPurchaseNotFound) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    return VerifyExternalEscrowResponse(
        verified=True,
        purchase_intent_id=record.purchase_intent_id,
        purchase_artifact=record.purchase_artifact,
        fulfillment={
            **expected,
            "globalPaymentId": normalized["globalPaymentId"],
            "gatewayProfile": normalized["gatewayProfile"],
            "usdAmountMinor": (
                batch.total_subtotal_minor
                if batch is not None
                else canonical.gross_usd_amount_minor
                if isinstance(canonical, PurchaseArtifactV3)
                else canonical.usd_amount_minor
            ),
            "railChainId": canonical.rail_chain_id,
            "railAssetId": _hex32(canonical.rail_asset_id),
            "railAssetDecimals": canonical.rail_asset_decimals,
            "depositor": normalized["depositor"],
            "source": normalized["source"],
        },
    )


@router.post("/purchase-intents/escrow-webhook")
async def receive_external_escrow_webhook(
    payload: VerifyExternalEscrowWebhookRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Canonical callback consumed by the read-only confirmed-event relayer."""

    verified = await verify_external_escrow(payload, settings, authorization)
    presale = _ingest_verified_presale_payment(payload, verified, settings)
    return {
        "escrow": verified.model_dump(mode="json"),
        "verification": verified.model_dump(mode="json"),
        "presale": presale,
    }


def _ingest_verified_presale_payment(
    payload: VerifyExternalEscrowWebhookRequest,
    verified: VerifyExternalEscrowResponse,
    settings: Settings,
) -> dict[str, Any] | None:
    """Route one confirmed Base payment into its active voucher campaign."""
    from .presale_endpoints import (
        VoucherIssuanceEvidenceRequest,
        _external_escrow_contract,
        get_presale_store,
    )
    from .vault_eligibility import require_current_approved_vault

    store = get_presale_store(settings)
    try:
        series = store.get(payload.escrow_message.collection_id)
    except KeyError:
        return None
    if series["state"] != "PRESALE":
        return None
    # A closed customer sales window prevents new purchase artifacts. It must
    # not strand a payment that was already confirmed by the configured escrow
    # while its artifact was valid. The callback remains authenticated and all
    # artifact, vault, price, deed, and chain evidence checks still apply.
    body = payload.escrow_message
    source = payload.source
    record = get_payment_purchase_store(settings.payment_purchase_db_path).get(
        body.purchase_id
    )
    if record.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
        return None
    artifact = purchase_artifact_from_json(record.purchase_artifact)
    payer = bytes32(
        b"\x00" * 12 + bytes.fromhex(body.depositor.removeprefix("0x"))
    )
    evidence = VoucherIssuanceEvidenceRequest(
        purchaseArtifact=verified.purchase_artifact,
        globalPaymentId=body.global_payment_id,
        originalPayer=_hex32(payer),
        evidenceId=(
            f"base:{source.transaction_hash.lower()}:{source.log_index}"
        ),
        confirmedHeight=source.block_number,
        transactionIndex=0,
        outputIndex=source.log_index,
        confirmedAt=source.block_timestamp,
    )
    approved = require_current_approved_vault(
        settings,
        _hex32(artifact.vault_launcher_id),
    )
    return store.ingest_payment(
        series["termsHash"],
        evidence,
        approved_vault=approved,
        issued_purchase=record,
        external_escrow_contract=_external_escrow_contract(
            settings,
            artifact,
            record,
        ),
    )


def _build_canonical_payment_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Settings,
    *,
    vault_launcher_id: str,
    identity_attest_root: str,
    genesis_artifact: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    now = int(time.time())
    canonical_rails = {
        "chia_xch",
        "chia_cat",
        "base_usdc",
        "evm_usdc",
        "stripe",
    }
    if body.rail not in canonical_rails:
        raise PaymentArtifactError("unsupported protocol payment rail")
    if not settings.collection_metadata_enabled:
        raise PaymentArtifactError(
            "protocol purchases require the collection metadata workspace"
        )
    if body.payment_terms.quantity > 100:
        raise PaymentArtifactError("purchase quantity cannot exceed 100")
    if (
        body.rail in {"base_usdc", "evm_usdc"}
        and body.expires_at > now + 30 * 60
    ):
        raise PaymentArtifactError(
            "EVM escrow quote validity cannot exceed 30 minutes"
        )
    try:
        collection = get_collection_store(settings).get(body.collection_id)
    except CollectionNotFound as exc:
        raise PaymentArtifactError(str(exc)) from exc
    if (
        collection["state"] != "PUBLISHED"
        or not collection["allocationLocked"]
        or not collection["metadataRoot"]
        or not collection["metadataAnchorId"]
    ):
        raise PaymentArtifactError(
            "protocol purchases require a published, allocation-locked collection"
        )
    if body.payment_terms.quantity > 1:
        selected_deeds = _select_purchase_deeds(
            collection,
            property_id=body.property_id,
            deed_launcher_id=body.deed_launcher_id,
            quantity=body.payment_terms.quantity,
        )
        child_payloads: list[dict[str, Any]] = []
        oracle_authorization: dict[str, Any] | None = None
        for selected in selected_deeds:
            child_body = body.model_copy(
                update={
                    "property_id": str(selected["deedId"]),
                    "deed_launcher_id": str(selected["deedLauncherId"]),
                    "share_ppm": int(selected["sharePpm"]),
                    "payment_terms": body.payment_terms.model_copy(
                        update={"quantity": 1, "usd_amount_minor": None}
                    ),
                }
            )
            child, child_oracle = _build_canonical_payment_artifact(
                child_body,
                settings,
                vault_launcher_id=vault_launcher_id,
                identity_attest_root=identity_attest_root,
                genesis_artifact=genesis_artifact,
            )
            if child.get("schema") != "solslot.purchase-artifact.v3":
                raise PaymentArtifactError(
                    "multi-deed checkout requires direct governed inventory"
                )
            if child_oracle is not None:
                if oracle_authorization is None:
                    oracle_authorization = child_oracle
                elif child_oracle != oracle_authorization:
                    raise PaymentArtifactError(
                        "multi-deed checkout resolved inconsistent oracle evidence"
                    )
            child_payloads.append(child)

        artifacts = tuple(
            purchase_artifact_v3_from_json(value) for value in child_payloads
        )
        if any(
            artifact.purchase_kind != PurchaseKind.DIRECT
            for artifact in artifacts
        ):
            raise PaymentArtifactError(
                "multi-deed checkout requires direct governed inventory"
            )
        batch_nonce = bytes32(
            hashlib.sha256(
                b"SOLSLOT_PURCHASE_BATCH_NONCE_V1\x00"
                + body.purchase_intent_id.encode("utf-8")
                + bytes(artifacts[0].authorization_nonce)
            ).digest()
        )
        batch = build_purchase_batch_v1(
            batch_nonce=batch_nonce,
            artifacts=artifacts,
        )
        batch.assert_live(now)
        if (
            body.payment_terms.usd_amount_minor is not None
            and body.payment_terms.usd_amount_minor
            != batch.total_subtotal_minor
        ):
            raise PaymentArtifactError(
                "USD amount does not match the batched sealed price plus fees"
            )
        return purchase_batch_to_json(batch), oracle_authorization
    deed = next(
        (
            item
            for item in collection["deeds"]
            if item["deedId"].casefold() == body.property_id.casefold()
            or str(item.get("deedLauncherId") or "").casefold()
            == body.property_id.casefold()
        ),
        None,
    )
    if deed is None:
        raise PaymentArtifactError(
            "purchase deed is not in the sealed collection allocation"
        )
    if (
        not deed["deedLauncherId"]
        or not deed["executeBundleId"]
        or deed["confirmationHeight"] is None
    ):
        raise PaymentArtifactError(
            "purchase deed is not confirmed and available for delivery"
        )
    expected_deed_launcher = _bytes32_field(
        deed["deedLauncherId"], "deed_launcher_id"
    )
    if (
        body.deed_launcher_id is not None
        and _bytes32_field(body.deed_launcher_id, "deed_launcher_id")
        != expected_deed_launcher
    ):
        raise PaymentArtifactError(
            "deed_launcher_id does not match the collection workspace"
        )
    if (
        body.share_ppm is not None
        and body.share_ppm != int(deed["sharePpm"])
    ):
        raise PaymentArtifactError(
            "share_ppm does not match the sealed deed allocation"
        )
    share_ppm, base_usd_amount_minor = _sealed_deed_price(collection, deed)
    offering = _mapping(_mapping(collection.get("dossier")).get("offering"))
    fee_bps = _nonnegative_decimal_integer(
        offering.get("royaltyBps"),
        "dossier.offering.royaltyBps",
    )
    if fee_bps > MAX_TECHNOLOGY_FEE_BPS:
        raise PaymentArtifactError("technology fee exceeds 1000 bps")
    if fee_bps != ALPHA_TECHNOLOGY_FEE_BPS:
        raise PaymentArtifactError(
            "RC24 alpha collections require a 100-bps technology fee"
        )
    technology_fee = technology_fee_minor(
        base_usd_amount_minor,
        fee_bps,
    )
    gross_usd_amount_minor = base_usd_amount_minor + technology_fee
    if (
        body.payment_terms.usd_amount_minor is not None
        and body.payment_terms.usd_amount_minor != gross_usd_amount_minor
    ):
        raise PaymentArtifactError(
            "USD amount does not match the sealed price plus technology fee"
        )
    puzzle_hashes = _mapping(genesis_artifact.get("puzzleHashes"))
    protocol_treasury = _bytes32_field(
        str(puzzle_hashes.get("protocolTreasuryPuzzleHash") or ""),
        "protocol_treasury_puzzle_hash",
    )
    royalty_puzhash = _bytes32_field(
        str(offering.get("royaltyPuzhash") or ""),
        "dossier.offering.royaltyPuzhash",
    )
    if royalty_puzhash != protocol_treasury:
        raise PaymentArtifactError(
            "technology fee destination is not the trusted protocol treasury"
        )
    expected_metadata_root = _bytes32_field(
        collection["metadataRoot"], "metadata_root"
    )
    expected_metadata_anchor = _bytes32_field(
        collection["metadataAnchorId"], "metadata_anchor_id"
    )
    for supplied, expected, label in (
        (body.metadata_root, expected_metadata_root, "metadata_root"),
        (
            body.metadata_anchor_id,
            expected_metadata_anchor,
            "metadata_anchor_id",
        ),
    ):
        if supplied is not None and _bytes32_field(supplied, label) != expected:
            raise PaymentArtifactError(
                f"{label} does not match the published collection"
            )

    required = {
        "authorization_nonce": body.authorization_nonce,
        "authorization_expires_at": body.authorization_expires_at,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise PaymentArtifactError(
            "protocol purchases require " + ", ".join(missing)
        )

    collection_id = bytes32(canonicalise_property_id(collection["id"]))
    deed_launcher_id = expected_deed_launcher
    expected_collection_canon = body.metadata.get("collectionIdCanon")
    if (
        expected_collection_canon is not None
        and _bytes32_field(
            expected_collection_canon, "metadata.collectionIdCanon"
        )
        != collection_id
    ):
        raise PaymentArtifactError(
            "collectionIdCanon does not match the collection workspace"
        )
    vault_id = _bytes32_field(vault_launcher_id, "vault_launcher_id")
    vault_p2 = puzzle_hash_for_p2_vault(vault_id)
    zkpassport_root = _bytes32_field(
        identity_attest_root,
        "identity_attest_root",
    )
    voucher_terms_hash = _active_presale_terms_for_deed(
        settings,
        expected_deed_launcher,
    )
    is_voucher = voucher_terms_hash is not None
    if is_voucher and body.rail == "chia_xch":
        from .voucher_rail_policy import require_xch_voucher_sales
        require_xch_voucher_sales(settings)
    quote_expires_at = body.expires_at
    if voucher_terms_hash is not None:
        from .presale_endpoints import get_presale_store

        active_series = get_presale_store(settings).get(voucher_terms_hash)
        quote_expires_at = min(
            quote_expires_at,
            int(_mapping(active_series.get("terms")).get("saleClose") or 0),
        )
        if quote_expires_at <= now:
            raise PaymentArtifactError("governed presale sales window is closed")
    if is_voucher and body.rail not in {
        "chia_xch",
        "base_usdc",
        "evm_usdc",
        "stripe",
    }:
        raise PaymentArtifactError(
            "active presale inventory is available only through governed "
            "approved stablecoin or Stripe vouchers"
        )
    common = {
        "network": settings.network,
        "collection_id": collection_id,
        "deed_launcher_id": deed_launcher_id,
        "metadata_root": expected_metadata_root,
        "metadata_anchor_id": expected_metadata_anchor,
        "share_ppm": share_ppm,
        "vault_launcher_id": vault_id,
        "vault_p2_puzzle_hash": vault_p2,
        "authorization_nonce": _bytes32_field(
            str(body.authorization_nonce), "authorization_nonce"
        ),
        "authorization_expires_at": int(
            body.authorization_expires_at or 0
        ),
        "quote_expires_at": quote_expires_at,
    }
    if is_voucher:
        common["usd_amount_minor"] = gross_usd_amount_minor
    else:
        common.update(
            {
                "base_usd_amount_minor": base_usd_amount_minor,
                "technology_fee_bps": fee_bps,
                "protocol_treasury_puzzle_hash": protocol_treasury,
                "zkpassport_root": zkpassport_root,
            }
        )

    if body.rail == "stripe":
        if body.payment_terms.chain_id is not None:
            raise PaymentArtifactError(
                "Stripe purchases cannot declare an EVM chain"
            )
        if body.payment_terms.currency.upper() != "USD":
            raise PaymentArtifactError(
                "Stripe purchases must use USD minor units"
            )
        stripe_common = common
        if is_voucher:
            stripe_common = {
                "network": settings.network,
                "collection_id": collection_id,
                "deed_launcher_id": deed_launcher_id,
                "metadata_root": expected_metadata_root,
                "metadata_anchor_id": expected_metadata_anchor,
                "share_ppm": share_ppm,
                "base_usd_amount_minor": base_usd_amount_minor,
                "technology_fee_bps": fee_bps,
                "protocol_treasury_puzzle_hash": protocol_treasury,
                "zkpassport_root": zkpassport_root,
                "vault_launcher_id": vault_id,
                "vault_p2_puzzle_hash": vault_p2,
                "authorization_nonce": _bytes32_field(
                    str(body.authorization_nonce), "authorization_nonce"
                ),
                "authorization_expires_at": int(
                    body.authorization_expires_at or 0
                ),
                "quote_expires_at": quote_expires_at,
                "presale_terms_hash": _bytes32_field(
                    str(voucher_terms_hash), "presale_terms_hash"
                ),
            }
        purchase = build_stripe_purchase_artifact_v3(**stripe_common)
        purchase.assert_live(now)
        return purchase_artifact_v3_to_json(purchase), None

    if body.rail in {"base_usdc", "evm_usdc"}:
        if body.native_asset_id is not None or body.native_asset_decimals is not None:
            raise PaymentArtifactError(
                "EVM purchases cannot declare Chia CAT fields"
            )
        if body.payment_terms.currency.upper() not in {"USDC", "WUSDC"}:
            raise PaymentArtifactError(
                "EVM escrow purchases must use the configured USD stablecoin"
            )
        chain_id = body.payment_terms.chain_id
        if chain_id is None and body.rail == "base_usdc":
            chain_id = 84532
        if chain_id is None:
            raise PaymentArtifactError(
                "EVM escrow purchases require payment_terms.chain_id"
            )
        token_address = settings.payment_evm_usdc_tokens.get(str(chain_id))
        if token_address is None:
            raise PaymentArtifactError(
                "EVM chain is not enabled for protocol purchases"
            )
        builder = (
            build_evm_test_usd_purchase_artifact
            if is_voucher
            else build_evm_test_usd_purchase_artifact_v3
        )
        purchase = builder(
            **common,
            chain_id=chain_id,
            token_asset_id=_evm_token_asset_id(token_address),
        )
        purchase.assert_live(now)
        return (
            purchase_artifact_to_json(purchase)
            if is_voucher
            else purchase_artifact_v3_to_json(purchase)
        ), None

    asset_id = bytes32.zeros
    if body.rail == "chia_cat":
        if body.native_asset_id is None:
            raise PaymentArtifactError(
                "Chia CAT offers require native_asset_id"
            )
        if body.native_asset_decimals is None:
            raise PaymentArtifactError(
                "Chia CAT offers require native_asset_decimals"
            )
        asset_id = _bytes32_field(
            body.native_asset_id, "native_asset_id"
        )
        if asset_id == bytes32.zeros:
            raise PaymentArtifactError("native_asset_id cannot be zero")
        allowed_cat_ids = {
            _bytes32_field(value, "payment_oracle_allowed_cat_asset_ids")
            for value in settings.payment_oracle_allowed_cat_asset_ids
        }
        if asset_id not in allowed_cat_ids:
            raise PaymentArtifactError(
                "native_asset_id is not enabled for protocol purchases"
            )
    elif body.native_asset_id is not None or body.native_asset_decimals is not None:
        raise PaymentArtifactError(
            "native XCH offers cannot declare CAT asset fields"
        )

    authorized_round = load_authorized_oracle_round(
        settings,
        asset_id=asset_id,
        now=now,
    )
    if authorized_round.round.network != settings.network:
        raise PaymentArtifactError(
            "oracle round network does not match the active protocol"
        )
    native_common = {
        **common,
        "oracle_round": authorized_round.round,
    }
    if body.rail == "chia_xch":
        builder = (
            build_xch_purchase_artifact
            if is_voucher
            else build_xch_purchase_artifact_v3
        )
        purchase = builder(**native_common)
    else:
        purchase = build_cat_purchase_artifact_v3(
            **native_common,
            cat_asset_id=asset_id,
            cat_decimals=int(body.native_asset_decimals or 0),
        )
    purchase.assert_live(now)
    return (
        (
            purchase_artifact_to_json(purchase)
            if is_voucher
            else purchase_artifact_v3_to_json(purchase)
        ),
        authorized_round.public_evidence(),
    )


def _build_artifact(
    body: BuildProtocolOfferArtifactRequest,
    settings: Settings,
    *,
    receipt: dict[str, Any],
    genesis_artifact: Mapping[str, Any],
    canonical_payment: tuple[dict[str, Any], dict[str, Any] | None],
) -> dict[str, Any]:
    launchers = _mapping(genesis_artifact.get("launcherIds"))
    protocol = {
        "instanceId": body.instance_id,
        "purchaseIntentId": body.purchase_intent_id,
        "rail": body.rail,
        "deedLauncherId": body.deed_launcher_id,
        "propertyId": body.property_id,
        "collectionId": body.collection_id,
        "sharePpm": body.share_ppm,
        "vaultLauncherId": receipt["vaultLauncherId"],
        "zkPassportRequired": True,
        "currentState": body.current_state,
        "expiresAt": body.expires_at,
    }
    purchase_artifact, _oracle_authorization = canonical_payment
    is_batch = purchase_artifact.get("schema") == "solslot.purchase-batch.v1"
    is_v3 = purchase_artifact.get("schema") == "solslot.purchase-artifact.v3"
    canonical_item = (
        purchase_artifact["artifacts"][0] if is_batch else purchase_artifact
    )
    protocol["deedLauncherId"] = canonical_item["deedLauncherId"]
    protocol["deedLauncherIds"] = (
        [item["deedLauncherId"] for item in purchase_artifact["artifacts"]]
        if is_batch
        else [canonical_item["deedLauncherId"]]
    )
    protocol["collectionWorkspaceId"] = body.collection_id
    protocol["collectionId"] = canonical_item["collectionId"]
    protocol["sharePpm"] = int(canonical_item["sharePpm"])
    protocol["quantity"] = (
        int(purchase_artifact["quantity"])
        if is_batch
        else (
            int(canonical_item["deliveryAmount"])
            if is_v3
            and int(canonical_item["deliveryKind"])
            == int(PurchaseDeliveryKind.SGT)
            else 1
        )
    )
    protocol["purchaseArtifactHash"] = (
        purchase_artifact["batchHash"]
        if is_batch
        else purchase_artifact["artifactHash"]
    )
    protocol["purchaseId"] = purchase_artifact["purchaseId"]
    payment_terms = {
        "currency": (
            "XCH" if body.rail == "chia_xch" else body.payment_terms.currency
        ),
        "amount": (
            purchase_artifact["totalRailAmount"]
            if is_batch
            else purchase_artifact["railAmount"]
        ),
        "quantity": protocol["quantity"],
        "usd_amount_minor": (
            purchase_artifact["totalSubtotalMinor"]
            if is_batch
            else (
                purchase_artifact["subtotalMinor"]
                if is_v3
                else purchase_artifact["usdAmountMinor"]
            )
        ),
        "asset_id": canonical_item["railAssetId"],
        "asset_decimals": canonical_item["railAssetDecimals"],
    }
    if is_v3 or is_batch:
        payment_terms.update(
            {
                "base_usd_amount_minor": (
                    purchase_artifact["totalBaseAmountMinor"]
                    if is_batch
                    else purchase_artifact["baseAmountMinor"]
                ),
                "technology_fee_bps": int(
                    canonical_item["technologyFeeBps"]
                ),
                "technology_fee_minor": (
                    purchase_artifact["totalTechnologyFeeMinor"]
                    if is_batch
                    else purchase_artifact["technologyFeeMinor"]
                ),
                "gross_usd_amount_minor": (
                    purchase_artifact["totalSubtotalMinor"]
                    if is_batch
                    else purchase_artifact["subtotalMinor"]
                ),
                "protocol_treasury_puzzle_hash": canonical_item[
                    "protocolTreasuryPuzzleHash"
                ],
            }
        )
    artifact: dict[str, Any] = {
        "schemaVersion": 4 if is_batch else (3 if is_v3 else 2),
        "protocolVersion": "solslot-v2",
        "version": 4 if is_batch else (3 if is_v3 else 2),
        "kind": "solslot_protocol_offer",
        "network": settings.network,
        "genesisArtifactHash": genesis_artifact["artifactHash"],
        "protocol": protocol,
        "vaultCredentialReceipt": receipt,
        "paymentTerms": payment_terms,
        "metadata": body.metadata,
        "issuedAt": int(time.time()),
    }
    purchase_artifact, oracle_authorization = canonical_payment
    artifact[
        "purchaseBatchV1"
        if is_batch
        else ("purchaseArtifactV3" if is_v3 else "purchaseArtifactV2")
    ] = purchase_artifact
    if oracle_authorization is not None:
        artifact["oracleAuthorization"] = oracle_authorization
    artifact["poolLauncherId"] = launchers["pool"]
    artifact["protocolConfigLauncherId"] = launchers["protocolConfig"]
    artifact["vaultVersionRegistryLauncherId"] = launchers["vaultVersionRegistry"]
    return artifact


def _protocol_object_from_artifact(
    artifact: Mapping[str, Any],
    artifact_hash: str,
) -> dict[str, Any]:
    protocol = dict(_mapping(artifact.get("protocol")))
    protocol["artifactHash"] = artifact_hash
    protocol["paymentStatus"] = "unpaid"
    protocol["protocolStatus"] = protocol.get("currentState", "artifact_ready")
    return protocol


def _artifact_rejection_reasons(
    artifact: dict[str, Any],
    artifact_hash: str,
    *,
    now: Optional[int],
    settings: Optional[Settings] = None,
) -> list[str]:
    reasons: list[str] = []
    try:
        _assert_protocol_offer_public_artifact(artifact)
    except ValueError as e:
        reasons.append(str(e))
    expected_hash = content_hash(artifact)
    if artifact_hash != expected_hash:
        reasons.append("artifact_hash_mismatch")
    protocol = _mapping(artifact.get("protocol"))
    if artifact.get("kind") != "solslot_protocol_offer":
        reasons.append("kind_mismatch")
    schema_version = artifact.get("schemaVersion")
    if schema_version not in {2, 3, 4}:
        reasons.append("schema_version_mismatch")
    if artifact.get("protocolVersion") != "solslot-v2":
        reasons.append("protocol_version_mismatch")
    if artifact.get("network") != "testnet11":
        reasons.append("network_mismatch")
    if protocol.get("zkPassportRequired") is not True:
        reasons.append("zkpassport_required_missing")
    canonical_v2_json = artifact.get("purchaseArtifactV2")
    canonical_v3_json = artifact.get("purchaseArtifactV3")
    canonical_batch_json = artifact.get("purchaseBatchV1")
    canonical_json = {
        2: canonical_v2_json,
        3: canonical_v3_json,
        4: canonical_batch_json,
    }.get(schema_version)
    if protocol.get("rail") in {
        "chia_xch",
        "chia_cat",
        "base_usdc",
        "evm_usdc",
        "stripe",
    }:
        if not isinstance(canonical_json, Mapping):
            reasons.append(
                "purchase_batch_v1_missing"
                if schema_version == 4
                else (
                    "purchase_artifact_v3_missing"
                    if schema_version == 3
                    else "purchase_artifact_v2_missing"
                )
            )
    if sum(
        value is not None
        for value in (
            canonical_v2_json,
            canonical_v3_json,
            canonical_batch_json,
        )
    ) > 1:
        reasons.append("multiple_purchase_artifacts")
    if schema_version == 2 and protocol.get("rail") not in {
        "chia_xch",
        "base_usdc",
        "evm_usdc",
    }:
        reasons.append("purchase_artifact_v2_not_voucher_rail")
    if isinstance(canonical_json, Mapping):
        try:
            batch: PurchaseBatchV1 | None = None
            if schema_version == 4:
                batch = purchase_batch_from_json(canonical_json)
                batch.assert_live(now or int(time.time()))
                canonical: PurchaseArtifactV2 | PurchaseArtifactV3 = (
                    batch.artifacts[0]
                )
                canonical_hash = batch.batch_hash
                canonical_purchase_id = batch.purchase_id
                canonical_quantity = batch.quantity
                canonical_expiry = min(
                    item.quote_expires_at for item in batch.artifacts
                )
                canonical_deed_ids = [
                    _hex32(item.deed_launcher_id) for item in batch.artifacts
                ]
            else:
                canonical = (
                    purchase_artifact_v3_from_json(canonical_json)
                    if schema_version == 3
                    else purchase_artifact_from_json(canonical_json)
                )
                canonical.assert_live(now or int(time.time()))
                canonical_hash = canonical.artifact_hash
                canonical_purchase_id = canonical.purchase_id
                canonical_quantity = (
                    canonical.delivery_amount
                    if isinstance(canonical, PurchaseArtifactV3)
                    and canonical.delivery_kind == PurchaseDeliveryKind.SGT
                    else 1
                )
                canonical_expiry = canonical.quote_expires_at
                canonical_deed_ids = [_hex32(canonical.deed_launcher_id)]
            expected_pairs = (
                (canonical.network, artifact.get("network"), "purchase_network"),
                (
                    _hex32(canonical.collection_id),
                    protocol.get("collectionId"),
                    "purchase_collection",
                ),
                (
                    _hex32(canonical.deed_launcher_id),
                    protocol.get("deedLauncherId"),
                    "purchase_deed",
                ),
                (
                    canonical.share_ppm,
                    protocol.get("sharePpm"),
                    "purchase_share",
                ),
                (
                    _hex32(canonical.vault_launcher_id),
                    protocol.get("vaultLauncherId"),
                    "purchase_vault",
                ),
                (
                    canonical_expiry,
                    protocol.get("expiresAt"),
                    "purchase_expiry",
                ),
                (
                    _hex32(canonical_hash),
                    protocol.get("purchaseArtifactHash"),
                    "purchase_artifact_hash",
                ),
                (
                    _hex32(canonical_purchase_id),
                    protocol.get("purchaseId"),
                    "purchase_id",
                ),
            )
            for observed, expected, label in expected_pairs:
                if observed != expected:
                    reasons.append(f"{label}_mismatch")
            if canonical_quantity != protocol.get("quantity", 1):
                reasons.append("purchase_quantity_mismatch")
            if canonical_deed_ids != protocol.get(
                "deedLauncherIds", canonical_deed_ids
            ):
                reasons.append("purchase_deed_set_mismatch")
            expected_rail = {
                PaymentRail.CHIA_XCH: "chia_xch",
                PaymentRail.CHIA_CAT: "chia_cat",
                PaymentRail.STRIPE: "stripe",
            }.get(canonical.rail)
            protocol_rail = protocol.get("rail")
            if canonical.rail == PaymentRail.EVM_TEST_USD:
                rail_matches = protocol_rail in {"base_usdc", "evm_usdc"}
            else:
                rail_matches = expected_rail == protocol_rail
            if not rail_matches:
                reasons.append("purchase_rail_mismatch")
            canonical_p2 = puzzle_hash_for_p2_vault(
                canonical.vault_launcher_id
            )
            if canonical.vault_p2_puzzle_hash != canonical_p2:
                reasons.append("purchase_vault_p2_mismatch")
            if isinstance(canonical, PurchaseArtifactV3):
                payment_terms = _mapping(artifact.get("paymentTerms"))
                receipt = _mapping(artifact.get("vaultCredentialReceipt"))
                if canonical.technology_fee_bps != ALPHA_TECHNOLOGY_FEE_BPS:
                    reasons.append("purchase_technology_fee_mismatch")
                if (
                    _hex32(canonical.zkpassport_root)
                    != receipt.get("identityAttestRoot")
                ):
                    reasons.append("purchase_zkpassport_root_mismatch")
                base_minor = (
                    batch.total_base_amount_minor
                    if batch is not None
                    else canonical.base_usd_amount_minor
                )
                fee_minor = (
                    batch.total_technology_fee_minor
                    if batch is not None
                    else canonical.technology_fee_minor
                )
                gross_minor = (
                    batch.total_subtotal_minor
                    if batch is not None
                    else canonical.gross_usd_amount_minor
                )
                rail_amount = (
                    batch.total_rail_amount
                    if batch is not None
                    else canonical.rail_amount
                )
                v3_payment_pairs = (
                    (
                        str(base_minor),
                        payment_terms.get("base_usd_amount_minor"),
                        "purchase_base_amount",
                    ),
                    (
                        canonical.technology_fee_bps,
                        payment_terms.get("technology_fee_bps"),
                        "purchase_fee_bps",
                    ),
                    (
                        str(fee_minor),
                        payment_terms.get("technology_fee_minor"),
                        "purchase_fee_amount",
                    ),
                    (
                        str(gross_minor),
                        payment_terms.get("gross_usd_amount_minor"),
                        "purchase_gross_amount",
                    ),
                    (
                        _hex32(canonical.protocol_treasury_puzzle_hash),
                        payment_terms.get("protocol_treasury_puzzle_hash"),
                        "purchase_treasury",
                    ),
                )
                for observed, expected, label in v3_payment_pairs:
                    if observed != expected:
                        reasons.append(f"{label}_mismatch")
                if str(rail_amount) != payment_terms.get("amount"):
                    reasons.append("purchase_rail_amount_mismatch")

            if (
                settings is not None
                and canonical.rail
                in {PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT}
            ):
                authorization = parse_authorized_oracle_round(
                    settings,
                    artifact.get("oracleAuthorization"),
                )
                if (
                    authorization.round.round_hash
                    != canonical.oracle_round_hash
                    or authorization.round.asset_id
                    != canonical.rail_asset_id
                    or authorization.round.asset_decimals
                    != canonical.rail_asset_decimals
                    or authorization.round.price_usd_minor_per_asset
                    != canonical.oracle_price_usd_minor_per_asset
                    or authorization.round.source_evidence_root
                    != canonical.source_evidence_root
                ):
                    reasons.append("purchase_oracle_mismatch")
        except (PaymentArtifactError, PaymentQuoteError, TypeError, ValueError):
            reasons.append(
                "purchase_batch_v1_invalid"
                if schema_version == 4
                else (
                    "purchase_artifact_v3_invalid"
                    if schema_version == 3
                    else "purchase_artifact_v2_invalid"
                )
            )
    expires_at = protocol.get("expiresAt")
    if not isinstance(expires_at, int) or expires_at <= 0:
        reasons.append("expires_at_invalid")
    elif (now or int(time.time())) > expires_at:
        reasons.append("expired")
    receipt = _mapping(artifact.get("vaultCredentialReceipt"))
    if receipt.get("vaultLauncherId") != protocol.get("vaultLauncherId"):
        reasons.append("credential_vault_mismatch")
    if receipt.get("network") != artifact.get("network"):
        reasons.append("credential_network_mismatch")
    if receipt.get("policyVersion") != 2:
        reasons.append("credential_policy_mismatch")
    identity_root = receipt.get("identityAttestRoot")
    if not isinstance(identity_root, str) or identity_root in {
        "",
        "0x" + "00" * 32,
        "0x4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
    }:
        reasons.append("credential_root_missing")
    proof = _mapping(receipt.get("attestationProof"))
    if proof.get("bitpath") != 0 or proof.get("siblings") != []:
        reasons.append("credential_proof_path_mismatch")
    if receipt.get("attestationLeafHash") != identity_root:
        reasons.append("credential_proof_root_mismatch")
    if not receipt.get("chiaVaultCoinId") or not isinstance(
        receipt.get("confirmedBlockIndex"),
        int,
    ):
        reasons.append("credential_chia_confirmation_missing")
    if settings is not None:
        try:
            genesis_artifact = load_signed_public_artifact(settings)
        except PublicArtifactError:
            reasons.append("active_genesis_artifact_unavailable")
            return reasons
        launchers = _mapping(genesis_artifact.get("launcherIds"))
        if artifact.get("genesisArtifactHash") != genesis_artifact.get("artifactHash"):
            reasons.append("genesis_artifact_hash_mismatch")
        if artifact.get("network") != settings.network:
            reasons.append("active_network_mismatch")
        coordinate_pairs = (
            ("poolLauncherId", launchers.get("pool")),
            ("protocolConfigLauncherId", launchers.get("protocolConfig")),
            ("vaultVersionRegistryLauncherId", launchers.get("vaultVersionRegistry")),
        )
        for field, expected in coordinate_pairs:
            if not expected or artifact.get(field) != expected:
                reasons.append(f"{field}_mismatch")
        if isinstance(canonical_json, Mapping) and schema_version in {3, 4}:
            try:
                canonical_v3_items = (
                    purchase_batch_from_json(canonical_json).artifacts
                    if schema_version == 4
                    else (purchase_artifact_v3_from_json(canonical_json),)
                )
                trusted_treasury = _bytes32_field(
                    str(
                        _mapping(genesis_artifact.get("puzzleHashes")).get(
                            "protocolTreasuryPuzzleHash"
                        )
                        or ""
                    ),
                    "protocol_treasury_puzzle_hash",
                )
                if any(
                    item.protocol_treasury_puzzle_hash != trusted_treasury
                    for item in canonical_v3_items
                ):
                    reasons.append("purchase_treasury_not_trusted")
            except (PaymentArtifactError, TypeError, ValueError):
                reasons.append("purchase_treasury_unverifiable")
        bridge_policy = _mapping(genesis_artifact.get("bridgePolicy"))
        if receipt.get("bridgePolicyHash") != bridge_policy.get("policyHash"):
            reasons.append("credential_bridge_policy_mismatch")
        try:
            from .zkpassport_enrollments import _normalize_hex32, _sync_chia_stamp

            vault_launcher_id = _normalize_hex32(
                str(protocol.get("vaultLauncherId") or ""),
                "vaultLauncherId",
            )
            current_enrollment = _sync_chia_stamp(settings, vault_launcher_id)
            current_receipt = current_enrollment.receipt
            if (
                current_enrollment.status != "chia_confirmed"
                or current_receipt is None
                or current_receipt.vaultLauncherId != receipt.get("vaultLauncherId")
                or current_receipt.identityAttestRoot != receipt.get("identityAttestRoot")
                or current_receipt.chiaVaultCoinId != receipt.get("chiaVaultCoinId")
                or current_receipt.confirmedBlockIndex
                != receipt.get("confirmedBlockIndex")
            ):
                reasons.append("credential_not_current_on_chia")
        except (HTTPException, ValueError, TypeError):
            reasons.append("credential_not_current_on_chia")
        retired = {
            str(value).lower()
            for value in genesis_artifact.get("retiredCoordinates", [])
            if isinstance(value, str)
        }
        coordinate_values = [artifact.get(field) for field, _expected in coordinate_pairs]
        coordinate_values.extend(
            (protocol.get("deedLauncherId"), protocol.get("vaultLauncherId"))
        )
        deed_launcher_ids = protocol.get("deedLauncherIds")
        if isinstance(deed_launcher_ids, list):
            coordinate_values.extend(deed_launcher_ids)
        if any(
            isinstance(value, str) and value.lower() in retired
            for value in coordinate_values
        ):
            reasons.append("retired_coordinate")
    return reasons


def _payment_evidence_rejection_reasons(
    rail: ProtocolRail,
    evidence: dict[str, Any],
) -> list[str]:
    try:
        _assert_public_artifact(evidence, "purchase_finalization_evidence")
    except ValueError as e:
        return [str(e)]
    if rail in {"chia_xch", "chia_cat"}:
        if not any(evidence.get(k) for k in ("spend_bundle_id", "accepted_offer_id", "coin_spend_id")):
            return ["chia_evidence_missing"]
    elif rail in {"base_usdc", "evm_usdc"}:
        if not evidence.get("tx_hash"):
            return ["base_usdc_tx_hash_missing"]
    elif rail == "stripe":
        try:
            stripe_settlement_evidence_from_json(evidence)
        except (PaymentArtifactError, TypeError, ValueError):
            return ["stripe_settlement_evidence_invalid"]
    return []


def _active_presale_terms_for_deed(
    settings: Settings,
    deed_launcher_id: bytes32,
) -> str | None:
    """Return the sole active voucher series containing this governed deed."""

    from .presale_endpoints import get_presale_store

    expected = _hex32(deed_launcher_id).lower()
    matches: set[str] = set()
    for series in get_presale_store(settings).list():
        if series.get("state") != "PRESALE":
            continue
        terms = _mapping(series.get("terms"))
        deeds = terms.get("deeds")
        if not isinstance(deeds, list):
            raise PaymentArtifactError(
                "active presale has invalid governed deed commitments"
            )
        if any(
            isinstance(item, Mapping)
            and str(item.get("deedLauncherId") or "").lower() == expected
            for item in deeds
        ):
            terms_hash = series.get("termsHash")
            if not isinstance(terms_hash, str):
                raise PaymentArtifactError(
                    "active presale is missing its terms hash"
                )
            matches.add(terms_hash.lower())
    if len(matches) > 1:
        raise PaymentArtifactError(
            "governed deed belongs to multiple active presales"
        )
    return next(iter(matches), None)


def _purchase_artifact_from_json(
    value: Mapping[str, Any],
) -> PurchaseArtifactV2 | PurchaseArtifactV3:
    schema = value.get("schema")
    if schema == "solslot.purchase-artifact.v3":
        return purchase_artifact_v3_from_json(value)
    if schema == "solslot.purchase-artifact.v2":
        return purchase_artifact_from_json(value)
    raise PaymentArtifactError("purchase artifact schema is unsupported")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _select_purchase_deeds(
    collection: Mapping[str, Any],
    *,
    property_id: str,
    deed_launcher_id: str | None,
    quantity: int,
) -> tuple[Mapping[str, Any], ...]:
    """Select one exact, deterministic set of equivalent governed deeds."""

    deeds = collection.get("deeds")
    if not isinstance(deeds, list):
        raise PaymentArtifactError("collection deed inventory is unavailable")
    anchor = next(
        (
            _mapping(item)
            for item in deeds
            if str(_mapping(item).get("deedId") or "").casefold()
            == property_id.casefold()
            or str(_mapping(item).get("deedLauncherId") or "").casefold()
            == property_id.casefold()
        ),
        None,
    )
    if anchor is None:
        raise PaymentArtifactError(
            "purchase deed is not in the sealed collection allocation"
        )
    if deed_launcher_id is not None and str(
        anchor.get("deedLauncherId") or ""
    ).casefold() != deed_launcher_id.casefold():
        raise PaymentArtifactError(
            "deed_launcher_id does not match the collection workspace"
        )
    unit_share = int(anchor.get("sharePpm") or 0)
    unit_par = str(anchor.get("parValueMojos") or "")
    eligible = [
        _mapping(item)
        for item in deeds
        if int(_mapping(item).get("sharePpm") or 0) == unit_share
        and str(_mapping(item).get("parValueMojos") or "") == unit_par
        and bool(_mapping(item).get("deedLauncherId"))
        and bool(_mapping(item).get("executeBundleId"))
        and _mapping(item).get("confirmationHeight") is not None
    ]
    eligible.sort(
        key=lambda item: (
            0 if item.get("deedId") == anchor.get("deedId") else 1,
            str(item.get("deedId") or "").casefold(),
            str(item.get("deedLauncherId") or "").casefold(),
        )
    )
    unique: list[Mapping[str, Any]] = []
    launcher_ids: set[str] = set()
    for item in eligible:
        launcher = str(item.get("deedLauncherId") or "").casefold()
        if launcher and launcher not in launcher_ids:
            launcher_ids.add(launcher)
            unique.append(item)
    if len(unique) < quantity:
        raise PaymentArtifactError(
            f"only {len(unique)} equivalent confirmed SmartDeeds are available"
        )
    return tuple(unique[:quantity])


def _sealed_deed_price(
    collection: Mapping[str, Any],
    selected_deed: Mapping[str, Any],
) -> tuple[int, int]:
    dossier = _mapping(collection.get("dossier"))
    offering = _mapping(dossier.get("offering"))
    currency = offering.get("currency")
    if not isinstance(currency, str) or currency.strip().upper() != "USD":
        raise PaymentArtifactError(
            "protocol purchases require a USD-denominated sealed target raise"
        )
    target_raise = _positive_decimal_integer(
        offering.get("targetRaiseMinor"),
        "dossier.offering.targetRaiseMinor",
    )
    allocation = dossier.get("deedAllocation")
    if not isinstance(allocation, list) or not allocation:
        raise PaymentArtifactError(
            "published collection is missing its sealed deed allocation"
        )

    prices: list[DeedPriceV1] = []
    selected_price: DeedPriceV1 | None = None
    selected_id = selected_deed.get("deedId")
    if not isinstance(selected_id, str) or not selected_id.strip():
        raise PaymentArtifactError("selected collection deed has no deedId")

    for index, value in enumerate(allocation):
        item = _mapping(value)
        deed_id = item.get("deedId")
        share_ppm = item.get("sharePpm")
        if not isinstance(deed_id, str) or not deed_id.strip():
            raise PaymentArtifactError(
                f"dossier.deedAllocation[{index}].deedId is invalid"
            )
        if (
            isinstance(share_ppm, bool)
            or not isinstance(share_ppm, int)
            or share_ppm < 1
            or share_ppm > 1_000_000
        ):
            raise PaymentArtifactError(
                f"dossier.deedAllocation[{index}].sharePpm is invalid"
            )
        numerator = target_raise * share_ppm
        usd_amount_minor, remainder = divmod(numerator, 1_000_000)
        if remainder:
            raise PaymentArtifactError(
                "sealed deed allocation produces fractional USD minor units"
            )
        price = DeedPriceV1(
            deed_id=bytes32(canonicalise_property_id(deed_id)),
            share_ppm=share_ppm,
            usd_amount_minor=usd_amount_minor,
        )
        prices.append(price)
        if deed_id.casefold() == selected_id.casefold():
            if selected_price is not None:
                raise PaymentArtifactError(
                    "sealed deed allocation contains duplicate deed IDs"
                )
            selected_price = price
            dossier_par_value = _positive_decimal_integer(
                item.get("parValueMojos"),
                f"dossier.deedAllocation[{index}].parValueMojos",
            )
            collection_par_value = _positive_decimal_integer(
                selected_deed.get("parValueMojos"),
                "collection deed parValueMojos",
            )
            if dossier_par_value != collection_par_value:
                raise PaymentArtifactError(
                    "collection deed par value does not match the sealed allocation"
                )

    validate_deed_price_plan(
        prices,
        target_raise_usd_minor=target_raise,
    )
    if selected_price is None:
        raise PaymentArtifactError(
            "purchase deed is not in the sealed dossier allocation"
        )
    if selected_price.share_ppm != int(selected_deed["sharePpm"]):
        raise PaymentArtifactError(
            "collection deed share does not match the sealed allocation"
        )
    return selected_price.share_ppm, selected_price.usd_amount_minor


def _positive_decimal_integer(value: Any, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise PaymentArtifactError(
            f"{label} must be a canonical positive decimal string"
        )
    parsed = int(value)
    if parsed < 1:
        raise PaymentArtifactError(f"{label} must be positive")
    return parsed


def _nonnegative_decimal_integer(value: Any, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise PaymentArtifactError(f"{label} must be a decimal integer string")
    parsed = int(value)
    if parsed < 0:
        raise PaymentArtifactError(f"{label} cannot be negative")
    return parsed


def _assert_protocol_offer_public_artifact(
    artifact: Mapping[str, Any],
) -> None:
    scan_target = dict(artifact)
    # These envelopes have strict parsers and contain intentionally public
    # fields named authorizationNonce and signature. They carry no credential.
    scan_target.pop("purchaseArtifactV2", None)
    scan_target.pop("purchaseArtifactV3", None)
    scan_target.pop("purchaseBatchV1", None)
    scan_target.pop("oracleAuthorization", None)
    _assert_public_artifact(scan_target, "protocol_offer_artifact")


def _bytes32_field(value: str, label: str) -> bytes32:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 66:
        raise PaymentArtifactError(f"{label} must be 0x-prefixed bytes32")
    try:
        return bytes32.from_hexstr(value)
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} must be valid bytes32") from exc


def _normalized_hex32(value: str, label: str) -> str:
    return _hex32(_bytes32_field(value, label))


def _normalized_evm_address(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise PaymentArtifactError(f"{label} must be 0x-prefixed bytes20")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(f"{label} must be valid bytes20") from exc
    if raw == b"\x00" * 20:
        raise PaymentArtifactError(f"{label} cannot be zero")
    return "0x" + raw.hex()


def _evm_token_asset_id(value: str) -> bytes32:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise PaymentArtifactError(
            "configured EVM stablecoin address must be 0x-prefixed bytes20"
        )
    try:
        token = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise PaymentArtifactError(
            "configured EVM stablecoin address must be valid hex"
        ) from exc
    return bytes32(b"\x00" * 12 + token)


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def _require_server_to_server_token(
    settings: Settings,
    authorization: str | None,
) -> None:
    expected = settings.protocol_artifact_api_token
    if not expected:
        if settings.runtime_environment == "test":
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Protocol artifact service authentication is not configured.",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing protocol artifact bearer token.",
        )
    supplied = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid protocol artifact bearer token.",
        )


def _stripe_restricted_key(settings: Settings) -> str:
    path = Path(str(settings.stripe_restricted_key_file or ""))
    if path.is_symlink() or not path.is_file():
        raise PaymentArtifactError("Stripe restricted key file is unavailable")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PaymentArtifactError(
            "Stripe restricted key file must not be accessible by group/other"
        )
    try:
        key = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise PaymentArtifactError("Stripe restricted key is unreadable") from exc
    prefix = "rk_live_" if settings.stripe_mode == "live" else "rk_test_"
    if not key.startswith(prefix) or len(key) < len(prefix) + 16:
        raise PaymentArtifactError(
            "Stripe restricted key does not match the configured mode"
        )
    return key


def _verify_stripe_provider_evidence(
    settings: Settings,
    purchase: PurchaseArtifactV3 | PurchaseBatchV1,
    evidence: StripeSettlementEvidenceV1,
) -> None:
    """Independently reconstruct provider facts before durable queueing."""

    if (
        not settings.stripe_settlement_enabled
        or evidence.stripe_account_id != settings.stripe_account_id
        or evidence.livemode != (settings.stripe_mode == "live")
        or not settings.stripe_api_url.startswith("https://")
    ):
        raise PaymentArtifactError(
            "Stripe settlement verification is not securely configured"
        )
    headers = {
        "authorization": f"Bearer {_stripe_restricted_key(settings)}",
        "stripe-version": "2024-06-20",
    }
    try:
        with httpx.Client(
            base_url=settings.stripe_api_url.rstrip("/"),
            headers=headers,
            timeout=20.0,
        ) as client:
            intent_response = client.get(
                f"/v1/payment_intents/{evidence.payment_intent_id}",
                params={"expand[]": "latest_charge"},
            )
            intent_response.raise_for_status()
            event_response = client.get(f"/v1/events/{evidence.event_id}")
            event_response.raise_for_status()
            intent = intent_response.json()
            event = event_response.json()
            charge = intent.get("latest_charge")
            if isinstance(charge, str):
                charge_response = client.get(f"/v1/charges/{charge}")
                charge_response.raise_for_status()
                charge = charge_response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise PaymentArtifactError(
            "Stripe could not independently verify the paid purchase"
        ) from exc
    if not isinstance(intent, Mapping) or not isinstance(event, Mapping):
        raise PaymentArtifactError("Stripe returned malformed payment evidence")
    event_data = event.get("data")
    event_object = (
        event_data.get("object") if isinstance(event_data, Mapping) else None
    )
    metadata = intent.get("metadata")
    purchase_id = purchase.purchase_id
    purchase_hash = (
        purchase.batch_hash
        if isinstance(purchase, PurchaseBatchV1)
        else purchase.artifact_hash
    )
    if (
        intent.get("id") != evidence.payment_intent_id
        or bool(intent.get("livemode")) != evidence.livemode
        or intent.get("status") != "succeeded"
        or int(intent.get("created") or 0) <= 0
        or int(intent.get("created") or 0) >= purchase.quote_expires_at
        or intent.get("currency") != "usd"
        or int(intent.get("amount_received") or 0) != evidence.amount_minor
        or event.get("id") != evidence.event_id
        or event.get("type") != "payment_intent.succeeded"
        or bool(event.get("livemode")) != evidence.livemode
        or not isinstance(event_object, Mapping)
        or event_object.get("id") != evidence.payment_intent_id
        or not isinstance(metadata, Mapping)
        or str(metadata.get("protocol_purchase_id") or "").lower()
        != _hex32(purchase_id)
        or str(metadata.get("purchase_artifact_hash") or "").lower()
        != _hex32(purchase_hash)
    ):
        raise PaymentArtifactError(
            "Stripe PaymentIntent or event differs from the purchase artifact"
        )
    if not isinstance(charge, Mapping):
        raise PaymentArtifactError("Stripe payment has no retrievable charge")
    method_details = charge.get("payment_method_details")
    if not isinstance(method_details, Mapping):
        raise PaymentArtifactError("Stripe payment method evidence is unavailable")
    method_type = str(method_details.get("type") or "")
    expected_method = (
        "card"
        if evidence.method_family == StripeMethodFamily.CARD
        else "us_bank_account"
    )
    card = method_details.get("card")
    observed_funding = (
        str(card.get("funding") or "unknown")
        if isinstance(card, Mapping)
        else "not_applicable"
    )
    expected_funding = {
        StripeFundingType.CREDIT: "credit",
        StripeFundingType.DEBIT: "debit",
        StripeFundingType.PREPAID: "prepaid",
        StripeFundingType.UNKNOWN: "unknown",
        StripeFundingType.BANK_ACCOUNT: "not_applicable",
    }[evidence.funding_type]
    if (
        method_type != expected_method
        or observed_funding != expected_funding
        or bool(charge.get("refunded"))
        or int(charge.get("amount_refunded") or 0) != 0
        or bool(charge.get("disputed"))
    ):
        raise PaymentArtifactError(
            "Stripe funding, refund, or dispute state differs from the receipt"
        )


def _rpc_hex(value: object) -> str:
    if hasattr(value, "hex"):
        rendered = value.hex()  # type: ignore[union-attr]
        return rendered if str(rendered).startswith("0x") else "0x" + str(rendered)
    return str(value)


def _verify_external_escrow_chain_evidence(
    settings: Settings,
    *,
    normalized: Mapping[str, Any],
    deployment: Any,
) -> None:
    """Re-read the canonical receipt, settlement log, and deposit storage."""

    if not settings.payment_omnichain_rpc_url:
        raise PaymentArtifactError("EVM escrow RPC is not configured")
    source = normalized["source"]
    w3 = Web3(
        Web3.HTTPProvider(
            settings.payment_omnichain_rpc_url,
            request_kwargs={"timeout": 20.0},
        )
    )
    try:
        receipt = w3.eth.get_transaction_receipt(source["transactionHash"])
        block = w3.eth.get_block(source["blockNumber"])
        latest = int(w3.eth.block_number)
    except Exception as exc:  # noqa: BLE001
        raise PaymentArtifactError(
            "EVM escrow transaction could not be independently verified"
        ) from exc
    block_number = int(receipt.get("blockNumber") or 0)
    confirmations = latest - block_number + 1
    if (
        int(receipt.get("status") or 0) != 1
        or str(receipt.get("to") or "").lower() != deployment.spoke_address
        or _rpc_hex(receipt.get("transactionHash")).lower()
        != source["transactionHash"]
        or block_number != source["blockNumber"]
        or _rpc_hex(receipt.get("blockHash")).lower() != source["blockHash"]
        or _rpc_hex(block.get("hash")).lower() != source["blockHash"]
        or int(block.get("timestamp") or 0) != source["blockTimestamp"]
        or confirmations < deployment.confirmations
        or confirmations < source["confirmations"]
    ):
        raise PaymentArtifactError("EVM escrow receipt provenance changed")
    matching_logs = [
        log
        for log in receipt.get("logs", [])
        if int(log.get("logIndex", -1)) == source["logIndex"]
        and str(log.get("address") or "").lower() == deployment.spoke_address
        and len(log.get("topics") or []) >= 2
        and _rpc_hex(log["topics"][0]).lower() == PAYMENT_SETTLED_TOPIC.lower()
        and _rpc_hex(log["topics"][1]).lower()
        == normalized["globalPaymentId"]
    ]
    if len(matching_logs) != 1:
        raise PaymentArtifactError("EVM settlement log is missing or ambiguous")
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(deployment.spoke_address),
        abi=ESCROW_DEPOSIT_ABI,
    )
    try:
        deposit = contract.functions.getDeposit(
            normalized["globalPaymentId"]
        ).call(block_identifier=source["blockNumber"])
    except Exception as exc:  # noqa: BLE001
        raise PaymentArtifactError("EVM escrow deposit storage is unavailable") from exc
    observed = {
        "depositor": str(deposit[0]).lower(),
        "settlementToken": str(deposit[1]).lower(),
        "localPaymentId": _rpc_hex(deposit[2]).lower(),
        "purchaseId": _rpc_hex(deposit[3]).lower(),
        "artifactHash": _rpc_hex(deposit[4]).lower(),
        "collectionId": _rpc_hex(deposit[5]).lower(),
        "deedLauncherId": _rpc_hex(deposit[6]).lower(),
        "vaultLauncherId": _rpc_hex(deposit[7]).lower(),
        "destinationPuzzle": _rpc_hex(deposit[8]).lower(),
        "amount": int(deposit[12]),
        "quantity": int(deposit[13]),
        "quoteExpiresAt": int(deposit[17]),
        "status": int(deposit[18]),
        "succeeded": bool(deposit[19]),
    }
    expected = {
        field: normalized[field]
        for field in (
            "depositor",
            "settlementToken",
            "localPaymentId",
            "purchaseId",
            "artifactHash",
            "collectionId",
            "deedLauncherId",
            "vaultLauncherId",
            "destinationPuzzle",
            "amount",
            "quantity",
            "quoteExpiresAt",
        )
    }
    expected["status"] = 3
    expected["succeeded"] = True
    if observed != expected:
        raise PaymentArtifactError("EVM escrow deposit differs from callback evidence")


def _require_omnichain_ingest_token(
    settings: Settings,
    authorization: str | None,
) -> None:
    expected = settings.payment_omnichain_ingest_token
    if not expected or len(expected) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Omnichain escrow callback authentication is not configured.",
        )
    supplied = ""
    if authorization and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid omnichain escrow callback credential.",
        )
