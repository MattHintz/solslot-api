"""Private mTLS-only FastAPI application for one validator signer."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .base_inventory_hold import BaseHoldClaim
from .validator_base_inventory_hold import sign_base_inventory_hold
from .inventory_extension_claims import InventoryExtensionClaim
from .base_lifecycle_claims import BaseInventoryExtensionClaim, BasePaymentStartClaim, BaseTerminalClaim
from .validator_base_terminal import sign_base_terminal
from .validator_base_lifecycle import sign_base_extension, sign_base_payment_start
from .payment_start import PaymentStartClaim, sign_payment_start
from .inventory_payment_hold_claims import InventoryPaymentHoldClaim, InventoryPaymentHoldReleaseClaim, InventoryPaymentHoldAbortClaim
from .validator_inventory_payment_hold import sign_inventory_payment_hold, sign_inventory_payment_hold_release, sign_inventory_payment_hold_abort
from .validator_inventory_extension import sign_inventory_extension_claim
from .release_metadata import load_release_metadata
from .validator_ledger import ValidatorLedger
from .validator_quorum import (
    InventoryReservationClaim,
    PrimaryPurchaseClaim,
    StripeSettlementClaim,
    ValidatorClaim,
    CurrentIdentityClaim,
    PermitValidatorClaim,
    ValidatorSignatureResponse,
    ValidatorHealthResponse,
    VoucherIssuanceClaim,
    VoucherSeriesPhaseClaim,
    VoucherTransitionClaim,
)
from .validator_service import (
    ValidatorEvidenceError,
    load_stripe_restricted_key,
    load_validator_artifact,
    load_validator_private_key,
    _coordinator_settings,
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


class CurrentIdentitySignRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    claim: CurrentIdentityClaim
    claimHash: str = Field(pattern=r'^0x[0-9a-f]{64}$')


class CurrentIdentityRecoveryRequest(CurrentIdentitySignRequest):
    originalClaimHash:str=Field(pattern=r'^0x[0-9a-f]{64}$')


def _identity_recovery_window_open(settings):
    import time
    deadline=getattr(settings,'generation_customer_identity_recovery_expires_at',0)
    return type(deadline) is int and 0 < int(time.time()) < deadline


from .generation_sols_batch_execution import PrimaryBatchClaim

class PrimaryBatchSignRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    claim:PrimaryBatchClaim
    claimHash:str


class PrimaryPurchaseSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: PrimaryPurchaseClaim
    claimHash: str


class InventoryReservationSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: InventoryReservationClaim
    claimHash: str


class BaseInventoryHoldSignRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    claim: BaseHoldClaim
    claimHash: str


class PaymentStartSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: PaymentStartClaim
    claimHash: str


class InventoryExtensionSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryExtensionClaim | BaseInventoryExtensionClaim
    claimHash: str


class BasePaymentStartSignRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    claim: BasePaymentStartClaim
    claimHash: str


class BaseTerminalSignRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    claim: BaseTerminalClaim
    claimHash: str


class InventoryPaymentHoldSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryPaymentHoldClaim
    claimHash: str


class InventoryPaymentHoldReleaseSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryPaymentHoldReleaseClaim
    claimHash: str

class InventoryPaymentHoldAbortSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: InventoryPaymentHoldAbortClaim
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
        from .chia_provider import ChiaProviderConfig, create_chia_provider
        from .identity_deployment import (
            load_effective_identity_deployment,
            require_runtime_identity_bindings,
        )
        identity_provider = None
        application.state.identity_deployment = None
        application.state.identity_provider = None
        if Path(signer_settings.public_artifact_path).is_file() and not signer_settings.generation_customer_identity_enabled:
            artifact, _release = load_validator_artifact(signer_settings)
            identity_provider = create_chia_provider(
                ChiaProviderConfig(
                    network=signer_settings.network,
                    primary_url=None,
                    fallback_url=signer_settings.coinset_base_url,
                )
            )
            await identity_provider.start()
            application.state.identity_provider = identity_provider
            coordinator = _coordinator_settings(signer_settings, artifact)
            application.state.identity_deployment = (
                await load_effective_identity_deployment(
                    coordinator, provider=identity_provider
                )
            )
            require_runtime_identity_bindings(
                coordinator, application.state.identity_deployment
            )
        application.state.generation_provider=None
        generation_provider=None
        if signer_settings.generation_sols_batch_enabled or signer_settings.generation_customer_identity_enabled:
            from .generation_sols_batch_validators import generation_settings
            from .generation_index import load_generation_read_anchor
            load_generation_read_anchor(generation_settings(signer_settings))
            if not signer_settings.generation_primary_url:
                raise RuntimeError('generation delivery requires an independent primary node')
            if signer_settings.generation_primary_readonly_gateway:
                from .generation_primary_reader import private_primary_reader
                generation_provider = private_primary_reader(signer_settings)
            else:
                generation_provider=create_chia_provider(ChiaProviderConfig(network='testnet11',
                primary_url=signer_settings.generation_primary_url,fallback_url=signer_settings.coinset_base_url,primary_required=True,
                primary_ca_cert_path=signer_settings.generation_primary_ca_cert_path,
                primary_client_cert_path=signer_settings.generation_primary_client_cert_path,
                primary_client_key_path=signer_settings.generation_primary_client_key_path))
            await generation_provider.start();application.state.generation_provider=generation_provider
        if signer_settings.generation_customer_identity_enabled:
            from .generation_customer_identity_validators import selected_current_identity_profile
            selected_current_identity_profile(signer_settings)
        try:
            yield
        finally:
            if generation_provider is not None:await generation_provider.close()
            if identity_provider is not None:
                await identity_provider.close()
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

    @application.middleware('http')
    async def current_signer_scope(request, call_next):
        from fastapi.responses import JSONResponse
        if getattr(current_settings(), 'generation_customer_identity_enabled', False):
            permitted = {('GET', '/health'), ('POST', '/v1/generation/identity/sign')}
            if getattr(current_settings(),'generation_customer_identity_recovery_enabled',False):
                permitted.add(('POST','/v1/generation/identity/recover'))
            if (request.method, request.url.path) not in permitted:
                return JSONResponse({'detail': 'CURRENT_SIGNER_ACTION_DISABLED'}, status_code=404)
        return await call_next(request)

    @application.post('/v1/generation/identity/sign', response_model=ValidatorSignatureResponse)
    async def sign_generation_identity(body: CurrentIdentitySignRequest):
        import asyncio
        from .generation_customer_identity_validators import sign_current_identity
        settings = current_settings()
        provider = getattr(application.state, 'generation_provider', None)
        if not settings.generation_customer_identity_enabled or provider is None:
            raise HTTPException(503, detail='CURRENT_ID_SIGNER_NOT_READY')
        try:
            async with asyncio.timeout(45):
                return await sign_current_identity(settings, application.state.validator_ledger,
                    body.claim, body.claimHash, provider=provider)
        except Exception as exc:
            # Proofs, provider payloads and signatures must not appear in errors.
            raise HTTPException(409, detail='CURRENT_ID_INDEPENDENT_EVIDENCE_REJECTED') from exc

    @application.post('/v1/generation/identity/recover', response_model=ValidatorSignatureResponse)
    async def recover_generation_identity(body:CurrentIdentityRecoveryRequest):
        import asyncio
        from .generation_customer_identity_validators import recover_existing_current_identity_signature
        settings=current_settings();provider=getattr(application.state,'generation_provider',None)
        if (not getattr(settings,'generation_customer_identity_recovery_enabled',False)
                or not _identity_recovery_window_open(settings) or provider is None):
            raise HTTPException(503,detail='CURRENT_ID_RECOVERY_NOT_READY')
        try:
            async with asyncio.timeout(45):
                recovered = await recover_existing_current_identity_signature(settings,application.state.validator_ledger,
                    original_claim_hash=body.originalClaimHash,refreshed_claim=body.claim,
                    refreshed_claim_hash=body.claimHash,provider=provider)
        except Exception as exc:
            raise HTTPException(409,detail='CURRENT_ID_RECOVERY_EVIDENCE_REJECTED') from exc
        if not _identity_recovery_window_open(settings):
            raise HTTPException(503,detail='CURRENT_ID_RECOVERY_NOT_READY')
        return recovered

    @application.post('/v1/generation/primary-sols/sign',response_model=ValidatorSignatureResponse)
    async def sign_generation_primary(body:PrimaryBatchSignRequest):
        import time
        from .generation_sols_batch_validators import sign_primary_batch
        if body.claim.digest()!=body.claimHash:raise HTTPException(409,detail='BATCH_CLAIM_CHANGED')
        provider=getattr(application.state,'generation_provider',None)
        if provider is None:raise HTTPException(503,detail='BATCH_SIGNER_NOT_READY')
        try:return await sign_primary_batch(body.claim,settings=current_settings(),provider=provider,
            ledger=application.state.validator_ledger,clock=time.time)
        except (ValueError,RuntimeError) as exc:
            raise HTTPException(409,detail='BATCH_INDEPENDENT_EVIDENCE_REJECTED') from exc

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
        if Path(signer_settings.public_artifact_path).is_file() and not signer_settings.generation_customer_identity_enabled:
            try:
                artifact, _ = load_validator_artifact(signer_settings)
                artifact_hash = str(artifact["artifactHash"])
                artifact_ready = True
            except ValidatorEvidenceError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
        active_ledger: ValidatorLedger = application.state.validator_ledger
        current_profile = None
        if signer_settings.generation_customer_identity_enabled:
            from .generation_customer_identity_validators import selected_current_identity_profile
            try:
                current_profile = selected_current_identity_profile(signer_settings)
                if getattr(application.state, 'generation_provider', None) is None:
                    raise ValueError('current primary provider missing')
            except (ValueError, OSError) as exc:
                raise HTTPException(503, detail='CURRENT_ID_SIGNER_NOT_READY') from exc
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
            currentIdentityGeneration=current_profile.generation_id if current_profile else None,
            currentIdentityProfileHash=current_profile.commitment if current_profile else None,
            currentIdentityConfigured=current_profile is not None,
            evmChainId=signer_settings.evm_chain_id,
            enrollmentActivation=signer_settings.enrollment_activation,
            identityDeploymentRevision=(
                int(application.state.identity_deployment["revision"])
                if application.state.identity_deployment is not None
                else 0
            ),
            identityDeploymentHash=(
                str(application.state.identity_deployment["amendmentHash"])
                if application.state.identity_deployment is not None
                else None
            ),
        )

    @application.post(
        "/v1/zkpassport/sign",
        response_model=ValidatorSignatureResponse,
    )
    async def sign(request: ValidatorSignRequest) -> ValidatorSignatureResponse:
        signer_settings = current_settings()
        active_ledger: ValidatorLedger = application.state.validator_ledger
        try:
            if signer_settings.identity_deployment_amendment_path:
                from .identity_deployment import (IdentityDeploymentError,
                    load_effective_identity_deployment, require_runtime_identity_bindings)
                provider = getattr(application.state, "identity_provider", None)
                if provider is None:
                    raise ValidatorEvidenceError("confirmed identity history provider is unavailable")
                artifact, _release = load_validator_artifact(signer_settings)
                coordinator = _coordinator_settings(signer_settings, artifact)
                try:
                    selected = await load_effective_identity_deployment(coordinator, provider=provider)
                    require_runtime_identity_bindings(coordinator, selected)
                except IdentityDeploymentError as exc:
                    raise ValidatorEvidenceError(str(exc)) from exc
            # Synchronous RPC and ledger work must not block the ASGI loop.
            from starlette.concurrency import run_in_threadpool
            signature = await run_in_threadpool(sign_validator_claim,
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

    async def payment_hold_response(body, *, release=False, abort=False):
        signer_settings = current_settings()
        try:
            signer = sign_inventory_payment_hold_abort if abort else (sign_inventory_payment_hold_release if release else sign_inventory_payment_hold)
            signature = await signer(signer_settings, application.state.validator_ledger, body.claim, body.claimHash)
        except ValidatorEvidenceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ValidatorSignatureResponse(claimHash=body.claim.canonical_hash(),
            signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[signer_settings.signer_index], signature=signature)

    @application.post('/v1/base-inventory-hold/sign', response_model=ValidatorSignatureResponse)
    async def arm_base_hold(body: BaseInventoryHoldSignRequest):
        settings = current_settings()
        try:
            signature = await sign_base_inventory_hold(settings, application.state.validator_ledger, body.claim, body.claimHash)
        except ValidatorEvidenceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ValidatorSignatureResponse(claimHash=body.claim.canonical_hash(), signerIndex=settings.signer_index,
            validatorPubkey=settings.roster_pubkeys[settings.signer_index], signature=signature)

    @application.post("/v1/inventory-payment-hold/sign", response_model=ValidatorSignatureResponse)
    async def arm_payment_hold(body: InventoryPaymentHoldSignRequest):
        return await payment_hold_response(body)

    @application.post("/v1/inventory-payment-hold/abort", response_model=ValidatorSignatureResponse)
    async def abort_payment_hold(body: InventoryPaymentHoldAbortSignRequest):
        return await payment_hold_response(body, abort=True)

    @application.post("/v1/inventory-payment-hold/release", response_model=ValidatorSignatureResponse)
    async def release_payment_hold(body: InventoryPaymentHoldReleaseSignRequest):
        return await payment_hold_response(body, release=True)

    @application.post('/v1/payment-start/observe', response_model=ValidatorSignatureResponse)
    async def observe_payment_start(body: PaymentStartSignRequest):
        signer_settings = current_settings()
        try:
            signature = await sign_payment_start(signer_settings, body.claim, body.claimHash)
        except ValidatorEvidenceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ValidatorSignatureResponse(claimHash=body.claim.canonical_hash(), signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[signer_settings.signer_index], signature=signature)

    @application.post('/v1/base-payment-start/observe', response_model=ValidatorSignatureResponse)
    async def observe_base_payment_start(body: BasePaymentStartSignRequest):
        signer_settings = current_settings()
        try:
            signature = await sign_base_payment_start(signer_settings, application.state.validator_ledger, body.claim, body.claimHash)
        except ValidatorEvidenceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ValidatorSignatureResponse(claimHash=body.claim.canonical_hash(), signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[signer_settings.signer_index], signature=signature)

    @application.post('/v1/base-checkout/terminal', response_model=ValidatorSignatureResponse)
    async def observe_base_terminal(body: BaseTerminalSignRequest):
        signer_settings = current_settings()
        try:
            signature = await sign_base_terminal(signer_settings, application.state.validator_ledger, body.claim, body.claimHash)
        except ValidatorEvidenceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ValidatorSignatureResponse(claimHash=body.claim.canonical_hash(), signerIndex=signer_settings.signer_index,
            validatorPubkey=signer_settings.roster_pubkeys[signer_settings.signer_index], signature=signature)

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
            signer = sign_base_extension if isinstance(request.claim, BaseInventoryExtensionClaim) else sign_inventory_extension_claim
            signature = await signer(
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
