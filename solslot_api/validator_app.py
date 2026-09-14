"""Private mTLS-only FastAPI application for one validator signer."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict

from .inventory_extension_claims import InventoryExtensionClaim
from .inventory_payment_hold_claims import InventoryPaymentHoldClaim, InventoryPaymentHoldReleaseClaim
from .validator_inventory_payment_hold import sign_inventory_payment_hold, sign_inventory_payment_hold_release
from .validator_inventory_extension import sign_inventory_extension_claim
from .release_metadata import load_release_metadata
from .validator_ledger import ValidatorLedger
from .validator_quorum import (
    InventoryReservationClaim,
    PrimaryPurchaseClaim,
    StripeSettlementClaim,
    ValidatorClaim,
    PermitValidatorClaim,
    ValidatorSignatureResponse,
    VoucherIssuanceClaim,
    VoucherSeriesPhaseClaim,
    VoucherTransitionClaim,
)
from .validator_service import (
    ValidatorEvidenceError,
    load_stripe_restricted_key,
    load_validator_artifact,
    load_validator_private_key,
    sign_validator_claim,
    sign_inventory_reservation_claim,
    sign_primary_purchase_claim,
    sign_stripe_settlement_claim,
    sign_voucher_issuance_claim,
    sign_voucher_series_phase_claim,
    sign_voucher_transition_claim,
)
from .validator_settings import ValidatorSettings, get_validator_settings


class ValidatorSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: PermitValidatorClaim | ValidatorClaim
    claimHash: str


class PrimaryPurchaseSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: PrimaryPurchaseClaim
    claimHash: str


class InventoryReservationSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: InventoryReservationClaim
    claimHash: str


class InventoryExtensionSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryExtensionClaim
    claimHash: str


class InventoryPaymentHoldSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryPaymentHoldClaim
    claimHash: str


class InventoryPaymentHoldReleaseSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryPaymentHoldReleaseClaim
    claimHash: str


class StripeSettlementSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: StripeSettlementClaim
    claimHash: str


class VoucherIssuanceSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: VoucherIssuanceClaim
    claimHash: str


class VoucherTransitionSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: VoucherTransitionClaim
    claimHash: str


class VoucherSeriesPhaseSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: VoucherSeriesPhaseClaim
    claimHash: str


class ValidatorHealthResponse(BaseModel):
    status: str
    signerIndex: int
    validatorPubkey: str
    apiCommit: str
    protocolCommit: str
    network: str
    bridgePolicyHash: str
    evmAddresses: dict[str, str]
    artifactHash: str | None
    artifactReady: bool
    ledgerReady: bool
    evmChainId: int = 11155111
    enrollmentActivation: dict[str, Any] | None = None


def create_validator_app(
    *,
    settings: ValidatorSettings | None = None,
    ledger: ValidatorLedger | None = None,
) -> FastAPI:
    configured = settings
    configured_ledger = ledger

    def current_settings() -> ValidatorSettings:
        return configured or get_validator_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        signer_settings = current_settings()
        load_validator_private_key(signer_settings)
        if signer_settings.stripe_settlement_enabled:
            load_stripe_restricted_key(signer_settings)
        active_ledger = configured_ledger or ValidatorLedger(
            signer_settings.ledger_db_path
        )
        if not active_ledger.healthcheck():
            raise RuntimeError("validator signature ledger failed SQLite quick_check")
        application.state.validator_ledger = active_ledger
        try:
            yield
        finally:
            if configured_ledger is None:
                active_ledger.close()

    application = FastAPI(
        title="Solslot Validator Signer",
        version="2",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @application.get("/health", response_model=ValidatorHealthResponse)
    def health() -> ValidatorHealthResponse:
        signer_settings = current_settings()
        private_key = load_validator_private_key(signer_settings)
        release = load_release_metadata(signer_settings.release_metadata_path)
        if release is None:
            raise HTTPException(status_code=503, detail="release metadata is missing")
        if signer_settings.enrollment_activation is not None:
            sources = signer_settings.enrollment_activation["sourceShas"]
            if sources["api"] != release.apiCommit or sources["protocol"] != release.protocolCommit:
                raise HTTPException(status_code=503, detail="permit health release does not match the reviewed activation")
        artifact_hash: str | None = None
        artifact_ready = False
        if Path(signer_settings.public_artifact_path).is_file():
            try:
                artifact, _ = load_validator_artifact(signer_settings)
                artifact_hash = str(artifact["artifactHash"])
                artifact_ready = True
            except ValidatorEvidenceError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        active_ledger: ValidatorLedger = application.state.validator_ledger
        return ValidatorHealthResponse(
            status="healthy",
            signerIndex=signer_settings.signer_index,
            validatorPubkey="0x" + bytes(private_key.get_g1()).hex(),
            apiCommit=release.apiCommit,
            protocolCommit=release.protocolCommit,
            network=signer_settings.network,
            bridgePolicyHash=signer_settings.bridge_policy_hash,
            evmAddresses={
                "forwarder": signer_settings.evm_forwarder_address,
                "verifierAdapter": signer_settings.evm_verifier_adapter_address,
                "attestationEmitter": signer_settings.evm_attestation_emitter_address,
            },
            artifactHash=artifact_hash,
            artifactReady=artifact_ready,
            ledgerReady=active_ledger.healthcheck(),
            evmChainId=signer_settings.evm_chain_id,
            enrollmentActivation=signer_settings.enrollment_activation,
        )

    @application.post(
        "/v1/zkpassport/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign(request: ValidatorSignRequest) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_validator_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    @application.post(
        "/v1/inventory-reservation/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign_inventory_reservation(
        request: InventoryReservationSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_inventory_reservation_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    async def payment_hold_response(body, *, release=False):
        signer_settings = current_settings()
        try:
            signer = sign_inventory_payment_hold_release if release else sign_inventory_payment_hold
            signature = await signer(signer_settings, application.state.validator_ledger, body.claim, body.claimHash)
        except ValidatorEvidenceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ValidatorSignatureResponse(claimHash=body.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[signer_settings.signer_index], signature=signature)

    @application.post("/v1/inventory-payment-hold/sign", response_model=ValidatorSignatureResponse)
    async def arm_payment_hold(body: InventoryPaymentHoldSignRequest):
        return await payment_hold_response(body)

    @application.post("/v1/inventory-payment-hold/release", response_model=ValidatorSignatureResponse)
    async def release_payment_hold(body: InventoryPaymentHoldReleaseSignRequest):
        return await payment_hold_response(body, release=True)

    @application.post(
        "/v1/inventory-extension/sign",
        response_model=ValidatorSignatureResponse,
    )
    async def sign_inventory_extension(
        request: InventoryExtensionSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = await sign_inventory_extension_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    @application.post(
        "/v1/primary-purchase/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign_primary_purchase(
        request: PrimaryPurchaseSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_primary_purchase_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    @application.post(
        "/v1/voucher-issuance/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign_voucher_issuance(
        request: VoucherIssuanceSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_voucher_issuance_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    @application.post(
        "/v1/stripe-settlement/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign_stripe_settlement(
        request: StripeSettlementSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_stripe_settlement_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    @application.post(
        "/v1/voucher-series-phase/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign_voucher_series_phase(
        request: VoucherSeriesPhaseSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_voucher_series_phase_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    @application.post(
        "/v1/voucher-transition/sign",
        response_model=ValidatorSignatureResponse,
    )
    def sign_voucher_transition(
        request: VoucherTransitionSignRequest,
    ) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            signature = sign_voucher_transition_claim(
                signer_settings,
                active_ledger,
                request.claim,
                request.claimHash,
            )
        except ValidatorEvidenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return ValidatorSignatureResponse(
            claimHash=request.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[
                signer_settings.signer_index
            ],
            signature=signature,
        )

    return application


app = create_validator_app()


__all__ = [
    "ValidatorHealthResponse",
    "PrimaryPurchaseSignRequest",
    "VoucherIssuanceSignRequest",
    "VoucherSeriesPhaseSignRequest",
    "VoucherTransitionSignRequest",
    "ValidatorSignRequest",
    "app",
    "create_validator_app",
]
