"""Solslot API — FastAPI application.

Endpoints:
  GET  /health
  GET  /chia/provider-status
  GET  /protocol
  POST /auth/challenge
  POST /vault/register/evm
  POST /vault/register/chia
  GET  /vault/{launcher_id}

Removed endpoints:
  GET  /vault/by-evm/{address}  --  POP-CANON-014: removed in this brick.
      The endpoint enumerated the EVM ↔ vault_launcher_id binding and
      its on-chain state for any caller knowing the EVM address, turning
      the registry into a global doxxing oracle for member identities
      and amplifying unauthenticated coinset.org queries.  The portal's
      ``findVaultByEvmAddress`` consumer was already removed in Phase
      9-Hermes-D (vault discovery moved client-side via
      ``VaultDiscoveryService`` / CHIP-22 hint scan), so removal is
      consumer-safe.  ``VaultRegistry.get_by_evm`` remains as an
      internal helper used by ``register_evm_vault`` to reject
      duplicate registrations — it is no longer exposed over HTTP.
"""
from __future__ import annotations

import base64
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32

from .admin import router as admin_router
from .genesis import get_genesis_store, router as genesis_router
from .launch_control import router as launch_control_router
from .admin_auth import (
    router as admin_auth_router,
    validate_admin_config_at_startup,
)
from .admin_operations import router as admin_operations_router
from .admin_key_changes import router as admin_key_changes_router
from .admin_security import router as admin_security_router
from .omnichain_ownership_activation import (
    router as omnichain_ownership_activation_router,
)
try:
    from .admin_roster_update import router as admin_roster_update_router
except ModuleNotFoundError as e:
    if e.name != "solslot_api.admin_roster_update":
        raise
    admin_roster_update_router = None
from .mint_endpoints import router as mint_endpoints_router
from .governance_endpoints import router as governance_endpoints_router
from .funded_redemptions import router as funded_redemptions_router
from .collection_endpoints import router as collection_endpoints_router
from .admin_sales import router as admin_sales_router
from .protocol_artifacts import router as protocol_artifacts_router
from .native_purchases import router as native_purchases_router
from .stripe_deliveries import router as stripe_deliveries_router
from .presale_endpoints import router as presale_router
from .presale_endpoints import get_presale_store
from .payment_purchase_store import get_payment_purchase_store
from .alpha_observability import router as alpha_observability_router
from .alpha_metrics import router as alpha_metrics_router
from .chia_proxy import router as chia_proxy_router
from .sols_market import router as sols_market_router
from .sols_journey import router as sols_journey_router
from .sols_swaps import router as sols_swaps_router
from .zkpassport_relay import router as zkpassport_relay_router
from .zkpassport_enrollments import router as zkpassport_enrollments_router
from .challenges import (
    ChallengeStore,
    ChallengeStoreFullError,
    RateLimitedError,
    get_store as get_challenge_store,
    preflight_challenge_storage,
)
from .chia_provider import (
    ChiaProvider,
    ChiaProviderConfig,
    create_chia_provider,
)
from .config import (
    Settings,
    get_settings,
    validate_runtime_environment_namespace,
    validate_secret_env_file_permissions,
    validate_server_hardening_at_startup,
)
from .credential_auth import require_alpha_writes
from .protocol_config import build_snapshot as build_protocol_config_snapshot
from .protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from .kos_exact_execution import KeyOfSolomonExactExecutor
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)
from .release_metadata import ReleaseMetadata, load_release_metadata
from .singletons import build_singletons_snapshot
from .cors import cors_middleware_options
from .evm_auth import (
    eip712_domain,
    normalize_evm_address,
    recover_evm_signer,
    registration_bls_message,
    registration_bls_signing_digest,
    registration_typed_data,
    VAULT_SPEND_TYPEHASH_STRING,
)
from .faucet import Faucet, FaucetSelectionRestricted
from .state import VaultRecord, VaultRegistry, get_registry
from .server_hardening import (
    ServerHardeningMiddleware,
    documentation_urls,
    trusted_client_ip,
)
from .vault_launcher import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, build_and_sign_launch
from .vault_version_registry import (
    VaultVersionRegistrySnapshot,
    build_vault_version_registry_snapshot,
)
from solslot_puzzles.vault_driver import (
    VAULT_INNER_MOD,
    puzzle_for_p2_vault,
)

logger = logging.getLogger(__name__)

# Precompute at import time to sidestep pyo3's "LazyNode is unsendable" panic
# when FastAPI dispatches sync endpoints via anyio's thread pool.
VAULT_INNER_MOD_HASH_HEX: str = "0x" + VAULT_INNER_MOD.get_tree_hash().hex()

# Warm up chia puzzle templates on the import thread so their internal
# `chia_protocol::lazy_node::LazyNode` is bound to the main thread.
# Without this, when Starlette's lifespan runs on the anyio worker thread
# and the faucet calls `puzzle_for_pk(wallet_pk).get_tree_hash()`, the
# LazyNode (created lazily during the *first* access on whatever thread)
# panics with "LazyNode is unsendable, but sent to another thread".
#
# The fix is to force-touch each puzzle template here, on the import
# thread, so the LazyNode is materialised once and the resulting bytes
# are cached on the Program — making subsequent cross-thread access
# safe.  This mirrors the precomputation above for VAULT_INNER_MOD and
# closes the four chia_rs LazyNode errors in tests/test_smoke.py.
def _warm_chia_puzzle_templates() -> None:
    # p2_delegated_puzzle_or_hidden_puzzle.MOD — used by Faucet to
    # derive the wallet puzzle hash via puzzle_for_pk.
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD as P2_MOD
    bytes(P2_MOD)               # force serialize → caches Program._bytes
    P2_MOD.get_tree_hash()      # force tree-hash compute too

    # Eagerly import chia.wallet.trading.offer (and therefore
    # chia.wallet.util.puzzle_compression) here, on the main thread.
    # That module's body contains a top-level
    # ``bytes(standard_puzzle.MOD) + bytes(LEGACY_CAT_MOD)``
    # which walks two more LazyNodes; without this warm-up those walks
    # would happen on the first request thread (the /protocol endpoint
    # lazy-imports protocol_deployment, which transitively pulls in
    # chia.wallet.trading.offer) and panic with the same
    # "LazyNode is unsendable" assertion failure.
    import chia.wallet.trading.offer  # noqa: F401 — import for side-effect
    import chia.wallet.util.puzzle_compression  # noqa: F401

    # solslot_puzzles A.1, A.2, A.3, A.4, A.5 inner mods — same threading
    # hazard.  Touching them here on the import thread caches each
    # mod's serialised bytes + tree hash so cross-thread access in
    # request handlers is safe.  Without this, /protocol's call to
    # build_singletons_snapshot or build_vault_version_registry_snapshot
    # panics on the second hit.
    from solslot_puzzles.admin_authority_v3_driver import admin_authority_v3_inner_mod
    from solslot_puzzles.mint_proposal_v2_driver import mint_proposal_inner_v2_mod
    from solslot_puzzles.property_registry_driver import (
        property_registry_inner_mod,
    )
    from solslot_puzzles.protocol_config_driver import protocol_config_inner_mod
    from solslot_puzzles.vault_version_registry_driver import (
        vault_version_registry_inner_mod,
    )
    from solslot_puzzles.funded_redemption_v1 import (
        p2_deed_redemption_v1_mod,
    )
    from solslot_puzzles.redemption_treasury_v1 import (
        redemption_treasury_v1_mod,
    )
    for mod in (
        admin_authority_v3_inner_mod(),
        mint_proposal_inner_v2_mod(),
        property_registry_inner_mod(),
        protocol_config_inner_mod(),
        vault_version_registry_inner_mod(),
        p2_deed_redemption_v1_mod(),
        redemption_treasury_v1_mod(),
    ):
        bytes(mod)
        mod.get_tree_hash()

    # Phase 2.5: Eip712Member puzzle is loaded by admin_records.py (when
    # leaf_hash is omitted from the JSON) and by the
    # /admin/auth/eip712/compute_leaf_hash endpoint.  Warm it on the
    # import thread for the same LazyNode-threading reason as above.
    # ``_eip712_member_mod_hash()`` populates the module-level bytes32
    # cache so per-request curry computations can use pure-bytes math
    # without ever touching a LazyNode again.
    from solslot_puzzles.eip712_helpers import (
        _eip712_member_mod_hash,
        _eip712_member_puzzle,
    )
    _eip712_mod = _eip712_member_puzzle()
    bytes(_eip712_mod)
    _eip712_mod.get_tree_hash()
    _eip712_member_mod_hash()  # populate the bytes32 cache


_warm_chia_puzzle_templates()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


def _load_genesis_store_for_runtime(settings: Settings) -> Any | None:
    """Open configured genesis state whenever it can affect faucet safety."""

    database_path = settings.genesis_db_path
    if (
        database_path == ":memory:"
        or settings.ceremony_mode_enabled
        or settings.protocol_fee_funding_enabled
        or Path(database_path).exists()
    ):
        return get_genesis_store(settings)
    return None


def _enforce_genesis_faucet_isolation(
    *,
    settings: Settings,
    faucet: Faucet | None,
    genesis_store: Any | None,
) -> set[str]:
    """Keep every non-genesis spender away from an unresolved exact bundle."""

    pending_fee_coin_ids = (
        genesis_store.pending_exact_fee_coin_ids()
        if genesis_store is not None
        else set()
    )
    if faucet is not None and (
        settings.ceremony_mode_enabled or pending_fee_coin_ids
    ):
        faucet.restrict_coin_selection_to("genesis")
    return pending_fee_coin_ids


# ─── App lifecycle ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_runtime_environment_namespace()
    validate_secret_env_file_permissions()
    settings = get_settings()
    if settings.checkout_lifecycle_worker_enabled:
        from .checkout_lifecycle import worker_activation
        worker_activation(load_signed_public_artifact(settings), settings.runtime_environment + '-alpha')
        if settings.network != 'testnet11':
            raise RuntimeError('automatic checkout lifecycle requires isolated testnet11')
    validate_server_hardening_at_startup(settings)
    preflight_challenge_storage(settings)
    genesis_store = _load_genesis_store_for_runtime(settings)

    # POP-CANON-016: fail fast at boot if the admin desk is enabled but
    # SOLSLOT_ADMIN_JWT_SECRET is unset.  This complements the runtime
    # guard inside ``get_jwt_secret``; with both, an operator gets the
    # clear error during deployment rather than at the first admin
    # request hours later.
    validate_admin_config_at_startup(settings)

    app.state.settings = settings
    app.state.coinset = create_chia_provider(
        ChiaProviderConfig(
            network=settings.network,
            primary_url=settings.chia_primary_url,
            fallback_url=settings.effective_chia_fallback_url(),
            timeout_seconds=settings.chia_rpc_timeout_seconds,
            primary_retry_count=settings.chia_primary_retry_count,
            recovery_probe_seconds=settings.chia_recovery_probe_seconds,
            primary_required=settings.chia_primary_required,
            primary_ca_cert_path=settings.chia_primary_ca_cert_path,
            primary_client_cert_path=settings.chia_primary_client_cert_path,
            primary_client_key_path=settings.chia_primary_client_key_path,
        )
    )
    await app.state.coinset.start()

    if settings.faucet_master_sk_hex:
        app.state.faucet = Faucet.from_master_private_key_hex(
            settings.faucet_master_sk_hex, settings.network
        )
    elif settings.faucet_seed_hex:
        app.state.faucet = Faucet.from_seed_hex(settings.faucet_seed_hex, settings.network)
    elif settings.faucet_mnemonic:
        app.state.faucet = Faucet.from_mnemonic(settings.faucet_mnemonic, settings.network)
    else:
        app.state.faucet = None
        logger.warning(
            "Faucet not configured — vault registration endpoints will return 503. "
            "Set SOLSLOT_FAUCET_MASTER_SK_HEX, SOLSLOT_FAUCET_SEED_HEX, or SOLSLOT_FAUCET_MNEMONIC."
        )

    pending_genesis_fee_coin_ids = _enforce_genesis_faucet_isolation(
        settings=settings,
        faucet=app.state.faucet,
        genesis_store=genesis_store,
    )
    genesis_faucet_exclusive = bool(
        settings.ceremony_mode_enabled or pending_genesis_fee_coin_ids
    )
    if pending_genesis_fee_coin_ids and not settings.ceremony_mode_enabled:
        logger.warning(
            "Faucet remains genesis-exclusive because %d exact fee coin "
            "reservation(s) require reconciliation.",
            len(pending_genesis_fee_coin_ids),
        )

    if app.state.faucet is not None:
        logger.info(
            "Faucet ready: %s  (puzhash %s)",
            app.state.faucet.bech32_address(),
            app.state.faucet.address_hex,
        )

    app.state.protocol_submitter = None
    if settings.protocol_fee_funding_enabled:
        if app.state.faucet is None:
            raise RuntimeError(
                "SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED requires the existing "
                "SOLSLOT_FAUCET_* fee-till credential."
            )
        if not settings.chia_primary_url:
            raise RuntimeError(
                "SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED requires "
                "SOLSLOT_CHIA_PRIMARY_URL."
            )
        if (
            settings.protocol_minimum_fee_mojos
            > settings.protocol_maximum_fee_mojos
        ):
            raise RuntimeError(
                "SOLSLOT_PROTOCOL_MINIMUM_FEE_MOJOS cannot exceed "
                "SOLSLOT_PROTOCOL_MAXIMUM_FEE_MOJOS."
            )
        app.state.protocol_submitter = ProtocolBundleSubmitter(
            provider=app.state.coinset,
            faucet=app.state.faucet,
            policy=ProtocolFeePolicy(
                enabled=True,
                target_seconds=settings.protocol_medium_fee_target_seconds,
                minimum_mojos=settings.protocol_minimum_fee_mojos,
                maximum_mojos=settings.protocol_maximum_fee_mojos,
                maximum_funding_coin_mojos=settings.faucet_max_spend_mojos,
                maximum_backing_mojos=settings.protocol_issuance_backing_max_mojos,
                mempool_timeout_seconds=settings.protocol_mempool_timeout_seconds,
                mempool_poll_seconds=settings.protocol_mempool_poll_seconds,
            ),
        )

    stripe_delivery_store = None
    presale_store = None
    if app.state.protocol_submitter is not None:
        from .stripe_delivery_store import get_stripe_delivery_store

        if genesis_store is None:
            raise RuntimeError(
                "protocol fee funding started without durable genesis state"
            )
        stripe_delivery_store = get_stripe_delivery_store(
            settings.stripe_delivery_db_path
        )
        presale_store = get_presale_store(settings)
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            presale_store.pending_campaign_funding_coin_ids
        )
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            genesis_store.pending_exact_fee_coin_ids
        )
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            stripe_delivery_store.pending_exact_fee_coin_ids
        )
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            presale_store.pending_stripe_terminal_fee_coin_ids
        )
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            presale_store.pending_voucher_funding_coin_ids
        )
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            get_payment_purchase_store(settings.payment_purchase_db_path).pending_timeout_fee_coin_ids
        )
        app.state.protocol_submitter.add_fee_coin_reservation_source(
            get_payment_purchase_store(settings.payment_purchase_db_path).pending_extension_fee_coin_ids
        )

    app.state.voucher_issuance_worker = None
    app.state.stripe_delivery_worker = None
    app.state.kos_exact_executor = None
    if (
        settings.stripe_delivery_worker_enabled
        or settings.voucher_issuance_worker_enabled
    ):
        app.state.kos_exact_executor = KeyOfSolomonExactExecutor(
            url=str(settings.payment_kos_executor_url),
            private_key_file=str(
                settings.payment_kos_executor_private_key_file
            ),
            expected_public_key=str(settings.payment_kos_executor_public_key),
            timeout_seconds=settings.payment_kos_executor_timeout_seconds,
            mtls_ca_path=settings.payment_kos_executor_mtls_ca_path,
            mtls_cert_path=settings.payment_kos_executor_mtls_cert_path,
            mtls_key_path=settings.payment_kos_executor_mtls_key_path,
        )
    if settings.stripe_delivery_worker_enabled:
        if app.state.faucet is None or app.state.protocol_submitter is None:
            raise RuntimeError(
                "SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED requires the faucet "
                "and protocol fee funding."
            )

    if settings.voucher_issuance_worker_enabled:
        if (
            app.state.faucet is None
            or app.state.protocol_submitter is None
            or app.state.kos_exact_executor is None
        ):
            raise RuntimeError(
                "SOLSLOT_VOUCHER_ISSUANCE_WORKER_ENABLED requires the faucet, "
                "protocol fee funding, and exact KoS executor."
            )
    if settings.stripe_delivery_worker_enabled:
        from .stripe_delivery_worker import (
            StripeDeliveryWorker,
            StripeDeliveryWorkerConfig,
        )

        stripe_worker = StripeDeliveryWorker(
            settings=settings,
            faucet=app.state.faucet,
            provider=app.state.coinset,
            submitter=app.state.protocol_submitter,
            exact_executor=app.state.kos_exact_executor,
            store=stripe_delivery_store,
            config=StripeDeliveryWorkerConfig(
                enabled=True,
                interval_seconds=settings.stripe_delivery_interval_seconds,
                lease_seconds=settings.stripe_delivery_lease_seconds,
            ),
        )
        await stripe_worker.start()
        app.state.stripe_delivery_worker = stripe_worker
    if settings.voucher_issuance_worker_enabled:
        from .voucher_issuance_worker import (
            VoucherIssuanceWorker,
            VoucherIssuanceWorkerConfig,
        )

        from .credential_auth import require_minting_writes
        def authorize_voucher_dispatch():
            if not settings.voucher_issuance_worker_enabled or not settings.protocol_fee_funding_enabled:
                raise RuntimeError("Voucher transaction dispatch is paused")
            require_minting_writes(settings)

        voucher_worker = VoucherIssuanceWorker(
            settings=settings,
            faucet=app.state.faucet,
            coinset=app.state.coinset,
            presales=presale_store,
            purchases=get_payment_purchase_store(settings.payment_purchase_db_path),
            submitter=app.state.protocol_submitter,
            exact_executor=app.state.kos_exact_executor,
            authorize_dispatch=authorize_voucher_dispatch,
            config=VoucherIssuanceWorkerConfig(
                enabled=True,
                interval_seconds=settings.voucher_issuance_interval_seconds,
            ),
        )
        await voucher_worker.start()
        app.state.voucher_issuance_worker = voucher_worker

    app.state.checkout_lifecycle_worker = None
    if settings.checkout_lifecycle_worker_enabled:
        from .checkout_lifecycle import CheckoutLifecycleWorker
        from .credential_auth import require_minting_writes
        from .launch_gates import require_operation_gate
        def authorize_checkout_renewal():
            require_minting_writes(settings)
            require_operation_gate(settings, 'purchases')
        lifecycle_worker = CheckoutLifecycleWorker(
            store=get_payment_purchase_store(settings.payment_purchase_db_path), presales=get_presale_store(settings),
            settings=settings, node=app.state.coinset, submitter=app.state.protocol_submitter,
            load_artifact=lambda: load_signed_public_artifact(settings), authorize=authorize_checkout_renewal)
        await lifecycle_worker.start()
        app.state.checkout_lifecycle_worker = lifecycle_worker

    # POP-CANON-008: faucet UTXO consolidation worker.  Opt-in via
    # SOLSLOT_FAUCET_CONSOLIDATION_ENABLED=true.  Started here so the
    # task is owned by the FastAPI event loop and properly cancelled on
    # shutdown.
    app.state.faucet_worker = None
    if (
        app.state.faucet is not None
        and settings.faucet_consolidation_enabled
        and not genesis_faucet_exclusive
    ):
        from .faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        worker_config = FaucetConsolidationConfig(
            enabled=True,
            threshold=settings.faucet_consolidation_threshold,
            interval_seconds=settings.faucet_consolidation_interval_seconds,
            fee=settings.faucet_consolidation_fee,
            max_inputs_per_run=settings.faucet_consolidation_max_inputs,
        )
        worker = FaucetConsolidationWorker(
            faucet=app.state.faucet,
            coinset=app.state.coinset,
            config=worker_config,
        )
        await worker.start()
        app.state.faucet_worker = worker
    elif settings.faucet_consolidation_enabled and genesis_faucet_exclusive:
        logger.warning(
            "Faucet consolidation is suppressed while genesis owns the faucet."
        )

    try:
        yield
    finally:
        if app.state.checkout_lifecycle_worker is not None:
            await app.state.checkout_lifecycle_worker.stop()
        if app.state.stripe_delivery_worker is not None:
            await app.state.stripe_delivery_worker.stop()
        if app.state.voucher_issuance_worker is not None:
            await app.state.voucher_issuance_worker.stop()
        if app.state.faucet_worker is not None:
            await app.state.faucet_worker.stop()
        await app.state.coinset.close()
        # Lifespan services may retain thread-affine chia_rs Program/LazyNode
        # values. Release every owned reference on this event-loop thread so a
        # later TestClient or server restart cannot finalize it on another one.
        app.state.checkout_lifecycle_worker = None
        app.state.stripe_delivery_worker = None
        app.state.voucher_issuance_worker = None
        app.state.faucet_worker = None
        app.state.kos_exact_executor = None
        app.state.protocol_submitter = None
        app.state.faucet = None
        app.state.coinset = None


_server_settings = get_settings()

app = FastAPI(
    title="Solslot API",
    version="0.1.0",
    description="Solslot Protocol members-portal API (testnet)",
    lifespan=lifespan,
    **documentation_urls(_server_settings),
)


@app.exception_handler(FaucetSelectionRestricted)
async def faucet_selection_restricted_handler(
    _request: Request,
    _exc: FaucetSelectionRestricted,
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "detail": (
                "Faucet coin selection is temporarily reserved while the "
                "genesis transaction is reconciled."
            )
        },
    )


# Localhost matching is available only in development/test. Staging and
# production accept exact HTTPS origins from SOLSLOT_CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    **cors_middleware_options(_server_settings),
)
app.add_middleware(
    ServerHardeningMiddleware,
    settings=_server_settings,
)

# Run-once V2 ceremony routes use the operator token plus threshold admin
# signatures. The retired single-session bootstrap router is intentionally
# not mounted.
app.include_router(admin_router)
app.include_router(genesis_router)
app.include_router(launch_control_router)

# Post-genesis admin desk: wallet-signed JWT auth backed only by verified
# records committed by the current admin-authority singleton.
app.include_router(admin_auth_router)
app.include_router(admin_operations_router)
app.include_router(admin_key_changes_router)
app.include_router(admin_security_router)
app.include_router(omnichain_ownership_activation_router)
if admin_roster_update_router is not None:
    app.include_router(admin_roster_update_router)
app.include_router(mint_endpoints_router)
app.include_router(governance_endpoints_router)
app.include_router(funded_redemptions_router)
app.include_router(collection_endpoints_router)
app.include_router(admin_sales_router)
app.include_router(protocol_artifacts_router)
app.include_router(native_purchases_router)
app.include_router(stripe_deliveries_router)
app.include_router(presale_router)
app.include_router(alpha_observability_router)
app.include_router(alpha_metrics_router)
app.include_router(chia_proxy_router)
app.include_router(sols_market_router)
app.include_router(sols_journey_router)
app.include_router(sols_swaps_router)

# zkPassport vault bridge enrollment index (public receipt material only).
app.include_router(zkpassport_enrollments_router)

# zkPassport gasless relayer (ERC-2771 meta-tx; 503 when relayer key is unset).
app.include_router(zkpassport_relay_router)


# ─── Dependency injectors ───────────────────────────────────────────────

async def get_coinset() -> ChiaProvider:
    # async to keep the dependency on the event loop thread (FastAPI dispatches
    # sync deps to a worker pool, which would touch chia_rs LazyNodes that were
    # bound to the lifespan thread → pyo3 panic).
    return app.state.coinset  # type: ignore[attr-defined]


async def get_faucet() -> Faucet:
    f: Optional[Faucet] = app.state.faucet  # type: ignore[attr-defined]
    if f is None:
        raise HTTPException(
            status_code=503,
            detail="Faucet is not configured on this server — vault registration is disabled. "
            "Set SOLSLOT_FAUCET_SEED_HEX or SOLSLOT_FAUCET_MNEMONIC.",
        )
    return f


# ─── Schemas ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    ok: bool
    service: str = "Solslot API"
    protocol_version: str = "solslot-v2"
    network: str
    peak_height: Optional[int]
    api_commit: Optional[str] = None
    protocol_commit: Optional[str] = None


class ReleaseResponse(BaseModel):
    available: bool
    release: Optional[ReleaseMetadata] = None


class ProtocolInfo(BaseModel):
    network: str
    pool_launcher_id: Optional[str]
    governance_launcher_id: Optional[str]
    vault_inner_mod_hash: str
    eip712_domain: dict[str, Any]
    eip712_typehash_string: str
    faucet_address: Optional[str]
    faucet_balance_mojos: Optional[int]
    deployed: bool = False
    deployment_manifest: Optional[dict[str, Any]] = None
    artifact_hash: Optional[str] = None
    source_shas: Optional[dict[str, str]] = None
    # ── A.3 protocol-config singleton fields ──────────────────────────
    # Deterministic hash of (pool_launcher_id, governance_launcher_id,
    # network, protocol_config_version).  When the operator has launched
    # the on-chain singleton, the CREATE_PUZZLE_ANNOUNCEMENT it emits on
    # every update spend carries this exact same hash — frontends can
    # therefore independently verify the operator's published config
    # against on-chain state by walking the singleton lineage on
    # coinset.org and comparing.  Returned as ``None`` until both pool +
    # governance launchers are configured (without them, the singleton
    # has nothing meaningful to publish).  See SECURITY.md §A.3.
    protocol_config_hash: Optional[str] = None
    # Launcher coin id of the on-chain protocol-config singleton, when
    # the operator has set ``SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID``.
    # Until Phase 1.5 lands the singleton-lineage indexer, this field
    # is informational: clients can use it to locate the singleton on
    # coinset.org and verify the published content_hash themselves.
    protocol_config_launcher_id: Optional[str] = None
    # Monotonically increasing version stamped into the singleton's
    # curried state.  Bumped by the operator on every config update.
    protocol_config_version: int = 1
    # ── A.4 property-registry singleton fields ────────────────────────
    # Launcher coin id of the on-chain property-registry singleton, when
    # the operator has set ``SOLSLOT_PROTOCOL_PROPERTY_REGISTRY_LAUNCHER_ID``.
    # Off-chain consumers walk this singleton's lineage on coinset.org
    # to discover registered property ids (each registration spend
    # emits a CREATE_PUZZLE_ANNOUNCEMENT carrying the canonical id).
    # Returned as ``None`` until the operator opts in.  See SECURITY.md §A.4.
    property_registry_launcher_id: Optional[str] = None
    # Tree hash of the uncurried ``property_registry_inner.clsp`` mod
    # — clients use this to verify they're reading the canonical
    # puzzle on-chain (rather than a malicious lookalike).
    property_registry_mod_hash: Optional[str] = None
    # ── A.1 mint-proposal singleton fields ────────────────────────────
    # Tree hash of the uncurried ``mint_proposal_inner.clsp`` mod;
    # exposed so clients can identify mint-proposal singletons on
    # coinset.org by uncurrying their inner reveal and comparing this
    # value.  Each individual proposal has its own launcher_id (not
    # exposed here — that's per-proposal, not protocol-level).
    # See SECURITY.md §A.1.
    mint_proposal_mod_hash: Optional[str] = None
    # ── A.5 vault-version registry singleton fields ───────────────────
    # Launcher coin id of the on-chain vault-version registry singleton,
    # when the operator has set ``SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID``.
    # Off-chain consumers walk this singleton's lineage on coinset.org to
    # discover the current canonical vault descriptor (vault inner mod hash,
    # canonical params hash, version).  Returned as ``None`` until the
    # registry is deployed.  See SECURITY.md §A.5.
    vault_version_registry_launcher_id: Optional[str] = None
    # Tree hash of the uncurried ``vault_version_registry_inner.clsp`` mod;
    # clients use this to verify they found the canonical registry puzzle.
    vault_version_registry_mod_hash: Optional[str] = None
    # Monotonic vault descriptor version.  Default 1 = initial deployment.
    vault_version: int = 1
    # ``sha256tree`` of the protocol-wide vault params (pool singleton mod,
    # pool launcher id, pool launcher puzzle hash, zkPassport bridge policy
    # hash).  ``None`` when pool launcher is not configured.
    vault_canonical_params_hash: Optional[str] = None
    # ``sha256tree`` of ``[vault_inner_mod_hash, canonical_params_hash, vault_version]``.
    # The on-chain registry publishes this exact value via its announcement.
    vault_version_registry_content_hash: Optional[str] = None


class ChallengeRequest(BaseModel):
    address: str = Field(
        ..., min_length=1, max_length=1024, description="EVM address or Chia BLS pubkey hex"
    )
    auth_type: str = Field(..., pattern="^(evm|chia_bls|passkey)$")

    @model_validator(mode="after")
    def validate_address_for_auth_type(self):
        if self.auth_type == "evm":
            self.address = normalize_evm_address(self.address, "address")
        elif self.auth_type == "chia_bls":
            raw = self.address[2:] if self.address.startswith("0x") else self.address
            try:
                pk_bytes = bytes.fromhex(raw)
            except ValueError as e:
                raise ValueError("BLS pubkey must be hex") from e
            if len(pk_bytes) != 48:
                raise ValueError("BLS pubkey must be 48 bytes")
        return self


class ChallengeResponse(BaseModel):
    nonce: str
    expires_at: float
    typed_data: Optional[dict[str, Any]] = None
    message_hex: Optional[str] = None


class RegisterEvmVaultRequest(BaseModel):
    address: str
    nonce: str
    signature: str


class RegisterChiaVaultRequest(BaseModel):
    bls_pubkey: str
    nonce: str
    signature: str


class VaultCreationResponse(BaseModel):
    vault_launcher_id: str
    vault_full_puzhash: str
    p2_vault_puzhash: str
    spend_bundle_id: str
    pushed_at: float
    auth_type: str
    # POP-CANON-004 fix: surface the actual coinset.org acceptance status
    # to the frontend.  When False, the spend was NOT accepted by the
    # mempool; the frontend should show a hard error and avoid persisting
    # the launcher id.  ``push_status`` carries the raw error/status string.
    accepted: bool = True
    push_status: Optional[str] = None


class VaultStateResponse(BaseModel):
    vault_launcher_id: str
    vault_full_puzhash: str
    p2_vault_puzhash: str
    auth_type: str
    owner_address: Optional[str]
    owner_pubkey: str
    confirmed: bool
    confirmed_block_index: Optional[int]
    current_coin_id: Optional[str]
    balance: dict[str, Any]


# ─── Endpoints ──────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health(
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[ChiaProvider, Depends(get_coinset)],
) -> HealthResponse:
    release = load_release_metadata(settings.release_metadata_path)
    try:
        state = await coinset.get_blockchain_state()
        peak = state.get("blockchain_state", {}).get("peak") or {}
        return HealthResponse(
            ok=True,
            network=settings.network,
            peak_height=peak.get("height"),
            api_commit=release.apiCommit if release else None,
            protocol_commit=release.protocolCommit if release else None,
        )
    except Exception as e:
        logger.warning("Chia providers unreachable: %s", e)
        return HealthResponse(
            ok=False,
            network=settings.network,
            peak_height=None,
            api_commit=release.apiCommit if release else None,
            protocol_commit=release.protocolCommit if release else None,
        )


@app.get("/chia/provider-status")
async def chia_provider_status(
    coinset: Annotated[ChiaProvider, Depends(get_coinset)],
) -> JSONResponse:
    status = await coinset.refresh_status()
    return JSONResponse(
        status_code=503 if status["fallbackActive"] else 200,
        content=status,
    )


@app.get("/release", response_model=ReleaseResponse)
async def release(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ReleaseResponse:
    metadata = load_release_metadata(settings.release_metadata_path)
    return ReleaseResponse(available=metadata is not None, release=metadata)


@app.get("/protocol", response_model=ProtocolInfo)
async def protocol(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ProtocolInfo:
    try:
        artifact = load_signed_public_artifact(settings)
    except PublicArtifactMissing:
        artifact = None
    except PublicArtifactError as exc:
        logger.error("Signed V2 public artifact failed verification: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="The signed V2 public artifact failed verification.",
        ) from exc

    launchers = artifact["launcherIds"] if artifact else {}
    pool_launcher = launchers.get("pool")
    governance_launcher = launchers.get("governance")
    protocol_config_launcher = launchers.get("protocolConfig")
    vault_registry_launcher = launchers.get("vaultVersionRegistry")
    property_registry_launcher = launchers.get("propertyRegistry")
    state_versions = artifact.get("stateVersions", {}) if artifact else {}

    artifact_settings = settings.model_copy(
        update={
            "protocol_config_launcher_id": protocol_config_launcher,
            "protocol_config_version": int(state_versions.get("protocolConfig", 1)),
            "vault_version_registry_launcher_id": vault_registry_launcher,
            "vault_version_registry_version": int(state_versions.get("vault", 1)),
            "protocol_property_registry_launcher_id": property_registry_launcher,
        }
    )

    # POP-CANON-A3: compute the protocol_config_hash from whichever
    # source (manifest > env) the API is currently trusting.  Frontends
    # use this hash when binding the EIP-712 envelope; auditors can
    # recompute it from on-chain singleton state and refuse to sign
    # when the two diverge.
    protocol_snapshot = build_protocol_config_snapshot(
        artifact_settings,
        pool_launcher_id_hex=pool_launcher,
        governance_launcher_id_hex=governance_launcher,
    )

    # POP-CANON-A1 + A.4: surface the on-chain mint-proposal +
    # property-registry singleton handles.  Mod-hashes are static
    # across the deployment; launcher_id is operator-configurable
    # (None until the property-registry is launched on-chain).
    singletons_snapshot = build_singletons_snapshot(artifact_settings)

    # POP-CANON-A.5: surface the on-chain vault-version registry singleton
    # descriptor.  Mod-hash and current vault code are static across the
    # deployment; launcher_id, canonical params hash and content hash are
    # computable only when the pool launcher is configured (the params hash
    # binds the pool launcher id).
    vault_registry_snapshot = build_vault_version_registry_snapshot(
        artifact_settings,
        pool_launcher_id_hex=pool_launcher,
    )

    return ProtocolInfo(
        network=settings.network,
        pool_launcher_id=pool_launcher,
        governance_launcher_id=governance_launcher,
        vault_inner_mod_hash=VAULT_INNER_MOD_HASH_HEX,
        eip712_domain=eip712_domain(),
        eip712_typehash_string=VAULT_SPEND_TYPEHASH_STRING,
        # Retained as nullable compatibility fields. Operational funding data
        # belongs on authenticated admin surfaces, not the public snapshot.
        faucet_address=None,
        faucet_balance_mojos=None,
        deployed=artifact is not None,
        # Canonical public coordinates are exposed as typed fields below. The
        # raw ceremony manifest can contain operational metadata and is never
        # returned from this unauthenticated route.
        deployment_manifest=None,
        artifact_hash=artifact.get("artifactHash") if artifact else None,
        source_shas=dict(artifact["sourceShas"]) if artifact else None,
        protocol_config_hash=protocol_snapshot.content_hash_hex,
        protocol_config_launcher_id=protocol_config_launcher,
        protocol_config_version=protocol_snapshot.config_version,
        property_registry_launcher_id=property_registry_launcher,
        property_registry_mod_hash=singletons_snapshot.property_registry_mod_hash_hex,
        mint_proposal_mod_hash=singletons_snapshot.mint_proposal_mod_hash_hex,
        vault_version_registry_launcher_id=vault_registry_launcher,
        vault_version_registry_mod_hash=vault_registry_snapshot.vault_version_registry_mod_hash_hex,
        vault_version=vault_registry_snapshot.vault_version,
        vault_canonical_params_hash=vault_registry_snapshot.canonical_params_hash_hex,
        vault_version_registry_content_hash=vault_registry_snapshot.content_hash_hex,
    )


@app.post("/auth/challenge", response_model=ChallengeResponse)
async def request_challenge(
    body: ChallengeRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[ChallengeStore, Depends(get_challenge_store)],
) -> ChallengeResponse:
    """Issue a fresh registration challenge.

    Snapshots the current pool/network into the Challenge so that subsequent
    /vault/register/evm calls verify against THESE values, not whatever
    settings happen to be live at registration time (POP-CANON-002).

    Per-IP rate limited and capped at ``challenge_store_max_pending`` to
    bound memory under DoS load (POP-CANON-003).
    """
    require_alpha_writes(settings)
    pool_id_hex = _require_vault_protocol_ready(settings)
    network = settings.network
    source_ip = _client_ip(request, settings)
    try:
        ch = store.issue(
            body.address,
            body.auth_type,
            pool_launcher_id_hex=pool_id_hex,
            chia_network=network,
            source_ip=source_ip,
        )
    except RateLimitedError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e
    except ChallengeStoreFullError as e:
        raise HTTPException(status_code=429, detail=str(e)) from e

    typed_data: Optional[dict[str, Any]] = None
    message_hex: Optional[str] = None
    if body.auth_type == "evm":
        typed_data = registration_typed_data(
            body.address,
            ch.nonce,
            pool_launcher_id_hex=pool_id_hex,
            auth_type="secp256k1",
            chia_network=network,
        )
    elif body.auth_type == "chia_bls":
        message_hex = "0x" + registration_bls_message(
            ch.nonce,
            ch.pool_launcher_id_hex,
            ch.auth_type,
            ch.chia_network,
        ).hex()
    return ChallengeResponse(
        nonce=ch.nonce,
        expires_at=ch.expires_at,
        typed_data=typed_data,
        message_hex=message_hex,
    )


@app.post("/vault/register/evm", response_model=VaultCreationResponse)
async def register_evm_vault(
    body: RegisterEvmVaultRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[ChiaProvider, Depends(get_coinset)],
    faucet: Annotated[Faucet, Depends(get_faucet)],
    store: Annotated[ChallengeStore, Depends(get_challenge_store)],
    registry: Annotated[VaultRegistry, Depends(get_registry)],
) -> VaultCreationResponse:
    require_alpha_writes(settings)
    current_pool_id_hex = _require_vault_protocol_ready(settings)
    ch = store.pop(body.nonce, body.address, "evm")
    if ch is None:
        raise HTTPException(
            status_code=400,
            detail="Challenge is missing, expired, or does not match this address/auth_type.",
        )
    if ch.pool_launcher_id_hex.lower() != current_pool_id_hex.lower():
        raise HTTPException(
            status_code=409,
            detail="Challenge no longer matches the active A.3 protocol config. Request a new challenge.",
        )

    # POP-CANON-002 fix: rebuild the typed_data using the SNAPSHOT recorded
    # at challenge issuance time, not current settings.  This means that
    # even if an operator changes ``pool_launcher_id`` or ``network``
    # between /auth/challenge and /vault/register/evm, the digest matches
    # only the pool/network the user actually saw and signed off on.
    typed_data = registration_typed_data(
        body.address,
        ch.nonce,
        pool_launcher_id_hex=ch.pool_launcher_id_hex,
        auth_type="secp256k1",
        chia_network=ch.chia_network,
    )
    try:
        recovery = recover_evm_signer(typed_data, body.signature)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if recovery.address.lower() != body.address.lower():
        raise HTTPException(
            status_code=400,
            detail=(
                f"Signature is valid but recovered address {recovery.address} "
                f"does not match claimed {body.address}."
            ),
        )

    if registry.get_by_evm(recovery.address) is not None:
        raise HTTPException(
            status_code=409, detail="EVM address is already registered."
        )

    # Look up an unspent faucet coin
    coins = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    fee = 0
    min_amount = 1 + fee
    # POP-CANON-009 fix: enforce the documented per-spend cap.  Mirrors
    # Chia's CoinSelectionConfig.max_coin_amount filter.
    selected = faucet.select_coin(
        coins,
        min_amount=min_amount,
        max_amount=settings.faucet_max_spend_mojos,
    )
    if selected is None:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Faucet has no coins ≥ {min_amount} mojo at {faucet.bech32_address()}. "
                f"Please fund the faucet from a testnet11 faucet before registering new vaults."
            ),
        )

    # POP-CANON-002 fix: build the vault using the SNAPSHOTTED pool launcher
    # id (from the challenge), not the current settings.  This guarantees
    # the on-chain singleton is bound to the same pool the user saw in
    # their wallet at sign time.
    pool_launcher_id = bytes32.fromhex(_strip0x(ch.pool_launcher_id_hex))

    launched = build_and_sign_launch(
        faucet=faucet,
        faucet_coin_json={
            "parent_coin_info": "0x" + selected.parent_coin_info.hex(),
            "puzzle_hash": "0x" + selected.puzzle_hash.hex(),
            "amount": str(selected.amount),
        },
        owner_pubkey=recovery.compressed_pubkey,
        auth_type=AUTH_TYPE_SECP256K1,
        pool_launcher_id=pool_launcher_id,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            _strip0x(settings.zkpassport_bridge_policy_hash)
        ),
        fee=fee,
    )

    # POP-CANON-004 fix: hard-fail on push_tx rejection so the frontend
    # cannot silently believe a vault was registered when the spend was
    # never accepted into the mempool.
    accepted, push_status = await _push_or_fail(coinset, launched.spend_bundle)
    if not accepted:
        raise HTTPException(
            status_code=502,
            detail=f"coinset.org rejected the spend: {push_status}",
        )

    now = time.time()
    p2 = puzzle_for_p2_vault(launched.vault_launcher_id)
    p2_hash = bytes32(p2.get_tree_hash())

    record = VaultRecord(
        launcher_id=launched.vault_launcher_id,
        full_puzhash=launched.vault_full_puzhash,
        p2_vault_puzhash=p2_hash,
        auth_type=AUTH_TYPE_SECP256K1,
        owner_pubkey=recovery.compressed_pubkey,
        owner_evm_address=recovery.address,
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
    )
    registry.record(record)

    return VaultCreationResponse(
        vault_launcher_id="0x" + launched.vault_launcher_id.hex(),
        vault_full_puzhash="0x" + launched.vault_full_puzhash.hex(),
        p2_vault_puzhash="0x" + p2_hash.hex(),
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
        auth_type="evm",
        accepted=accepted,
        push_status=push_status,
    )


@app.post("/vault/register/chia", response_model=VaultCreationResponse)
async def register_chia_vault(
    body: RegisterChiaVaultRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    coinset: Annotated[ChiaProvider, Depends(get_coinset)],
    faucet: Annotated[Faucet, Depends(get_faucet)],
    store: Annotated[ChallengeStore, Depends(get_challenge_store)],
    registry: Annotated[VaultRegistry, Depends(get_registry)],
) -> VaultCreationResponse:
    require_alpha_writes(settings)
    pk_hex = body.bls_pubkey
    current_pool_id_hex = _require_vault_protocol_ready(settings)
    ch = store.pop(body.nonce, pk_hex, "chia_bls")
    if ch is None:
        raise HTTPException(
            status_code=400,
            detail="Challenge is missing, expired, or does not match this pubkey.",
        )
    if ch.pool_launcher_id_hex.lower() != current_pool_id_hex.lower():
        raise HTTPException(
            status_code=409,
            detail="Challenge no longer matches the active A.3 protocol config. Request a new challenge.",
        )

    pk_bytes = bytes.fromhex(pk_hex[2:] if pk_hex.startswith("0x") else pk_hex)
    if len(pk_bytes) != 48:
        raise HTTPException(status_code=400, detail="BLS pubkey must be 48 bytes")
    sig_bytes = bytes.fromhex(
        body.signature[2:] if body.signature.startswith("0x") else body.signature
    )
    if len(sig_bytes) != 96:
        raise HTTPException(status_code=400, detail="BLS signature must be 96 bytes")

    try:
        pk = G1Element.from_bytes(pk_bytes)
        sig = G2Element.from_bytes(sig_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"BLS key/sig invalid: {e}") from e

    signing_digest = registration_bls_signing_digest(
        ch.nonce,
        ch.pool_launcher_id_hex,
        ch.auth_type,
        ch.chia_network,
    )
    if not AugSchemeMPL.verify(pk, signing_digest, sig):
        raise HTTPException(status_code=400, detail="BLS signature does not verify")

    if registry.get_by_bls(pk_bytes) is not None:
        raise HTTPException(status_code=409, detail="BLS pubkey is already registered.")

    coins = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    fee = 0
    # POP-CANON-009 fix: enforce the documented per-spend cap.
    selected = faucet.select_coin(
        coins,
        min_amount=1 + fee,
        max_amount=settings.faucet_max_spend_mojos,
    )
    if selected is None:
        raise HTTPException(status_code=503, detail="Faucet has no spendable coins")

    # POP-CANON-002 parity: use the snapshotted pool_launcher_id_hex from
    # the challenge, not live settings. The CHIP-0002 signature commits to
    # this pool, auth path, and network. Without this parity, an operator
    # who changes pool_launcher_id between /auth/challenge and
    # /vault/register/chia would silently launch a BLS vault bound to a
    # different pool than the one snapshotted at challenge issuance.
    pool_launcher_id = bytes32.fromhex(_strip0x(ch.pool_launcher_id_hex))
    launched = build_and_sign_launch(
        faucet=faucet,
        faucet_coin_json={
            "parent_coin_info": "0x" + selected.parent_coin_info.hex(),
            "puzzle_hash": "0x" + selected.puzzle_hash.hex(),
            "amount": str(selected.amount),
        },
        owner_pubkey=pk_bytes,
        auth_type=AUTH_TYPE_BLS,
        pool_launcher_id=pool_launcher_id,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            _strip0x(settings.zkpassport_bridge_policy_hash)
        ),
        fee=fee,
    )

    # POP-CANON-004 fix: hard-fail on push_tx rejection.
    accepted, push_status = await _push_or_fail(coinset, launched.spend_bundle)
    if not accepted:
        raise HTTPException(
            status_code=502,
            detail=f"coinset.org rejected the spend: {push_status}",
        )

    now = time.time()
    p2 = puzzle_for_p2_vault(launched.vault_launcher_id)
    p2_hash = bytes32(p2.get_tree_hash())

    record = VaultRecord(
        launcher_id=launched.vault_launcher_id,
        full_puzhash=launched.vault_full_puzhash,
        p2_vault_puzhash=p2_hash,
        auth_type=AUTH_TYPE_BLS,
        owner_pubkey=pk_bytes,
        owner_evm_address=None,
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
    )
    registry.record(record)

    return VaultCreationResponse(
        vault_launcher_id="0x" + launched.vault_launcher_id.hex(),
        vault_full_puzhash="0x" + launched.vault_full_puzhash.hex(),
        p2_vault_puzhash="0x" + p2_hash.hex(),
        spend_bundle_id=launched.spend_bundle_id,
        pushed_at=now,
        auth_type="chia_bls",
        accepted=accepted,
        push_status=push_status,
    )


@app.get("/vault/{launcher_id}", response_model=VaultStateResponse)
async def get_vault(
    launcher_id: str,
    coinset: Annotated[ChiaProvider, Depends(get_coinset)],
    registry: Annotated[VaultRegistry, Depends(get_registry)],
) -> VaultStateResponse:
    lid = _parse_bytes32(launcher_id, "launcher_id")
    record = registry.get(lid)
    if record is None:
        raise HTTPException(status_code=404, detail="Vault not registered on this server")

    confirmed_block_index: Optional[int] = None
    current_coin_id: Optional[str] = None
    confirmed = False

    coins = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + record.full_puzhash.hex(), include_spent=False
    )
    for rec in coins:
        if rec.get("spent_block_index") in (0, None):
            cjson = rec.get("coin") or rec
            from chia.types.blockchain_format.coin import Coin
            coin = Coin(
                parent_coin_info=bytes32.fromhex(cjson["parent_coin_info"].removeprefix("0x")),
                puzzle_hash=bytes32.fromhex(cjson["puzzle_hash"].removeprefix("0x")),
                amount=int(cjson["amount"]),
            )
            current_coin_id = "0x" + bytes(coin.name()).hex()
            confirmed_block_index = rec.get("confirmed_block_index")
            confirmed = True
            break

    auth_label = "evm" if record.auth_type == AUTH_TYPE_SECP256K1 else "chia_bls"
    return VaultStateResponse(
        vault_launcher_id="0x" + record.launcher_id.hex(),
        vault_full_puzhash="0x" + record.full_puzhash.hex(),
        p2_vault_puzhash="0x" + record.p2_vault_puzhash.hex(),
        auth_type=auth_label,
        owner_address=record.owner_evm_address,
        owner_pubkey="0x" + record.owner_pubkey.hex(),
        confirmed=confirmed,
        confirmed_block_index=confirmed_block_index,
        current_coin_id=current_coin_id,
        balance={"xch_mojos": 0, "deeds": []},  # TODO: aggregate p2_vault holdings
    )


# POP-CANON-014: /vault/by-evm/{address} removed.  See module docstring.
# ``VaultRegistry.get_by_evm`` remains an internal-only helper.


# ─── Helpers ─────────────────────────────────────────────────────────────────────

def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _pool_launcher_id_or_zero(settings: Settings) -> bytes32:
    """Return the pool launcher committed by the signed V2 artifact.

    The historical function name is retained for internal call compatibility;
    it no longer returns a zero placeholder or trusts mutable environment and
    deployment-manifest coordinates.
    """
    try:
        artifact = load_signed_public_artifact(settings)
        return bytes32.fromhex(_strip0x(artifact["launcherIds"]["pool"]))
    except (KeyError, PublicArtifactError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Vault registration is disabled until a signed V2 genesis artifact is active.",
        ) from exc


def _pool_launcher_id_hex(settings: Settings) -> str:
    """Hex form of the pool launcher id, snapshotted into challenges."""
    return "0x" + _pool_launcher_id_or_zero(settings).hex()


def _require_vault_protocol_ready(settings: Settings) -> str:
    try:
        artifact = load_signed_public_artifact(settings)
    except PublicArtifactError as exc:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until a signed V2 genesis artifact is active.",
        ) from exc
    launchers = artifact["launcherIds"]
    bridge_policy = artifact["bridgePolicy"]["policyHash"]
    if not settings.zkpassport_bridge_policy_hash:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until the fresh V2 bridge policy is pinned.",
        )
    _require_nonzero_bytes32_hex(
        settings.zkpassport_bridge_policy_hash,
        "SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH",
    )
    if settings.zkpassport_bridge_policy_hash.lower() != bridge_policy.lower():
        raise HTTPException(
            status_code=409,
            detail="Configured bridge policy does not match the signed V2 artifact.",
        )
    protocol_config_launcher_id = getattr(settings, "protocol_config_launcher_id", None)
    if not protocol_config_launcher_id:
        raise HTTPException(
            status_code=409,
            detail="Vault registration is disabled until the A.3 protocol-config singleton is launched.",
        )
    _require_nonzero_bytes32_hex(
        protocol_config_launcher_id,
        "SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID",
    )

    pool_id_hex = _require_nonzero_bytes32_hex(
        launchers.get("pool"),
        "public_artifact.launcherIds.pool",
    )
    governance_id_hex = _require_nonzero_bytes32_hex(
        launchers.get("governance"),
        "public_artifact.launcherIds.governance",
    )
    if protocol_config_launcher_id.lower() != str(launchers.get("protocolConfig", "")).lower():
        raise HTTPException(
            status_code=409,
            detail="Configured protocol-config launcher does not match the signed V2 artifact.",
        )
    _require_nonzero_bytes32_hex(governance_id_hex, "public_artifact.launcherIds.governance")
    return pool_id_hex


def _require_nonzero_bytes32_hex(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=409, detail=f"{field_name} is required.")
    clean = _strip0x(value.strip())
    if len(clean) != 64:
        raise HTTPException(status_code=409, detail=f"{field_name} must be 32 bytes.")
    try:
        parsed = bytes32.fromhex(clean)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=f"{field_name} is not valid hex.") from e
    if parsed == bytes32(b"\x00" * 32):
        raise HTTPException(status_code=409, detail=f"{field_name} cannot be zero.")
    return "0x" + parsed.hex()


def _client_ip(request: Request, settings: Settings) -> str:
    """Extract the client IP for per-IP rate limiting.

    Trusts Cloudflare's client header only when the immediate peer belongs to
    an explicitly configured Cloudflare source range.
    """
    return trusted_client_ip(request.scope, settings)


async def _push_or_fail(
    coinset: ChiaProvider, spend_bundle: Any
) -> tuple[bool, Optional[str]]:
    """Broadcast a spend bundle to coinset.org and surface the result.

    Returns:
        (accepted, status_string).  ``accepted`` is True iff coinset's
        ``push_tx`` returned ``success: true``.  When False, the caller
        should still return a response (so the client can render the
        error) but ``status_string`` carries the diagnostic.

    POP-CANON-004 fix: previously this only logged a warning and returned
    success regardless of the actual mempool acceptance status.
    """
    try:
        push_result = await coinset.push_tx(_spend_bundle_to_json(spend_bundle))
    except Exception as e:
        logger.exception("coinset push_tx failed: %s", e)
        raise HTTPException(
            status_code=502, detail=f"coinset.org rejected the spend: {e}"
        ) from e

    if push_result.get("success"):
        return True, None

    status = push_result.get("status") or push_result.get("error") or str(push_result)
    logger.warning("push_tx returned non-success: %s", status)
    return False, str(status)


def _parse_bytes32(h: str, field_name: str) -> bytes32:
    clean = h[2:] if h.startswith("0x") else h
    if len(clean) != 64:
        raise HTTPException(status_code=400, detail=f"{field_name} must be 32 bytes")
    try:
        return bytes32.fromhex(clean)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"{field_name} is not valid hex: {e}") from e


def _spend_bundle_to_json(bundle) -> dict[str, Any]:
    """Serialise a chia_rs.SpendBundle into coinset.org's expected JSON shape."""
    # chia_rs.SpendBundle has to_json_dict() that returns the exact shape
    # that Chia full-node `push_tx` accepts.
    if hasattr(bundle, "to_json_dict"):
        return bundle.to_json_dict()  # type: ignore[no-any-return]
    # Fallback: manually serialise
    return {
        "coin_spends": [
            {
                "coin": {
                    "parent_coin_info": "0x" + bytes(cs.coin.parent_coin_info).hex(),
                    "puzzle_hash": "0x" + bytes(cs.coin.puzzle_hash).hex(),
                    "amount": cs.coin.amount,
                },
                "puzzle_reveal": "0x" + bytes(cs.puzzle_reveal).hex(),
                "solution": "0x" + bytes(cs.solution).hex(),
            }
            for cs in bundle.coin_spends
        ],
        "aggregated_signature": "0x" + bytes(bundle.aggregated_signature).hex(),
    }


__all__ = ["app"]
