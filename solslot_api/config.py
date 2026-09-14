"""Runtime configuration for the Solslot API.

Values are loaded from environment variables (optionally via .env) by
pydantic-settings.  Secrets — the faucet key and the challenge secret —
are the two values that MUST be set in production.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .service_urls import (
    valid_internal_service_url,
    valid_launch_rehearsal_service_url,
)


SECRET_ENV_FILE_KEYS = frozenset(
    {
        "SOLSLOT_ADMIN_JWT_SECRET",
        "SOLSLOT_ADMIN_TOKEN",
        "SOLSLOT_FAUCET_MASTER_SK_HEX",
        "SOLSLOT_FAUCET_SEED_HEX",
        "SOLSLOT_FAUCET_MNEMONIC",
        "SOLSLOT_CHALLENGE_SECRET",
        "SOLSLOT_BOOTSTRAP_SESSION_SECRET",
        "SOLSLOT_LAUNCH_SESSION_SECRET",
        "SOLSLOT_LAUNCH_OWNER_CLAIM_TOKEN",
        "SOLSLOT_LAUNCH_REHEARSAL_SERVICE_TOKEN",
        "SOLSLOT_LAUNCH_REHEARSAL_EVIDENCE_HMAC_SECRET",
        "SOLSLOT_SMTP_PASSWORD",
        "SOLSLOT_VAULT_SESSION_JWT_SECRET",
        "SOLSLOT_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX",
        "SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN",
        "SOLSLOT_PURCHASE_OPERATIONS_TOKEN",
        "SOLSLOT_PAYMENT_KOS_EXECUTOR_PRIVATE_KEY_FILE",
        "SOLSLOT_PAYMENT_OMNICHAIN_INGEST_TOKEN",
        "SOLSLOT_COLLECTION_S3_SECRET_ACCESS_KEY",
        "SOLSLOT_COLLECTION_IPFS_PINNING_TOKEN",
        "SOLSLOT_COLLECTION_MALWARE_SCAN_TOKEN",
    }
)

_RETIRED_NAMESPACE_DIGEST = (
    "4b61ef4fda96729ef3703e602087708f3fa1ebfc2d809e0be3398086f8ec6706"
)
_RETIRED_NAMESPACE_LENGTH = 7


def validate_runtime_environment_namespace() -> None:
    """Reject environment keys from the abandoned runtime namespace."""
    offenders: list[str] = []
    for key in os.environ:
        lowered = key.lower().encode("utf-8")
        for index in range(len(lowered) - _RETIRED_NAMESPACE_LENGTH + 1):
            token = lowered[index : index + _RETIRED_NAMESPACE_LENGTH]
            if hashlib.sha256(token).hexdigest() == _RETIRED_NAMESPACE_DIGEST:
                offenders.append(key)
                break
    if offenders:
        raise RuntimeError(
            "Retired runtime namespace detected in environment keys: "
            + ", ".join(sorted(offenders))
            + ". Configure SOLSLOT_* variables only."
        )


def validate_secret_env_file_permissions(env_file: Path | None = None) -> None:
    path = env_file or Path(str(Settings.model_config.get("env_file", ".env")))
    if not path.exists() or not path.is_file():
        return
    secret_keys = _secret_keys_present_in_env_file(path)
    if not secret_keys:
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        keys = ", ".join(sorted(secret_keys))
        raise RuntimeError(
            f"{path} contains secret env vars ({keys}) but is readable or writable "
            f"by group/other (mode {mode:03o}). Run `chmod 600 {path}` or move "
            "secrets into a secret store before starting the API."
        )


def validate_server_hardening_at_startup(settings: "Settings") -> None:
    """Reject unsafe staging/production HTTP posture before serving traffic."""

    hosted = settings.runtime_environment in {"staging", "production"}
    if hosted and len(settings.protocol_artifact_api_token or "") < 32:
        raise RuntimeError(
            "SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN must contain at least 32 "
            "characters in staging/production."
        )
    if settings.stripe_settlement_enabled:
        if not (settings.stripe_account_id or "").startswith("acct_"):
            raise RuntimeError(
                "SOLSLOT_STRIPE_SETTLEMENT_ENABLED requires a configured "
                "SOLSLOT_STRIPE_ACCOUNT_ID."
            )
        if not settings.stripe_api_url.startswith("https://"):
            raise RuntimeError(
                "SOLSLOT_STRIPE_SETTLEMENT_ENABLED requires an HTTPS "
                "SOLSLOT_STRIPE_API_URL."
            )
        key_path = Path(str(settings.stripe_restricted_key_file or ""))
        try:
            if key_path.is_symlink() or not key_path.is_file():
                raise RuntimeError(
                    "SOLSLOT_STRIPE_SETTLEMENT_ENABLED requires a regular, "
                    "non-symlink SOLSLOT_STRIPE_RESTRICTED_KEY_FILE."
                )
            key_mode = stat.S_IMODE(key_path.stat().st_mode)
            if key_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise RuntimeError(
                    "SOLSLOT_STRIPE_RESTRICTED_KEY_FILE must not be accessible "
                    "by group/other."
                )
            restricted_key = key_path.read_text(encoding="ascii").strip()
        except RuntimeError:
            raise
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(
                "SOLSLOT_STRIPE_RESTRICTED_KEY_FILE is unavailable or unreadable."
            ) from exc
        key_prefix = "rk_live_" if settings.stripe_mode == "live" else "rk_test_"
        if not restricted_key.startswith(key_prefix) or len(restricted_key) < len(
            key_prefix
        ) + 16:
            raise RuntimeError(
                "SOLSLOT_STRIPE_RESTRICTED_KEY_FILE does not contain a "
                "restricted key for the configured Stripe mode."
            )

    if settings.chia_primary_required and not settings.chia_primary_url:
        raise RuntimeError(
            "SOLSLOT_CHIA_PRIMARY_REQUIRED requires SOLSLOT_CHIA_PRIMARY_URL."
        )
    if bool(settings.purchase_operations_service_url) != bool(
        settings.purchase_operations_token
    ):
        raise RuntimeError(
            "Purchase operations require both SOLSLOT_PURCHASE_OPERATIONS_SERVICE_URL "
            "and SOLSLOT_PURCHASE_OPERATIONS_TOKEN."
        )
    if settings.purchase_operations_service_url:
        if not valid_internal_service_url(settings.purchase_operations_service_url):
            raise RuntimeError(
                "SOLSLOT_PURCHASE_OPERATIONS_SERVICE_URL must use HTTPS or "
                "loopback-only HTTP."
            )
        if len(settings.purchase_operations_token or "") < 32:
            raise RuntimeError(
                "SOLSLOT_PURCHASE_OPERATIONS_TOKEN must contain at least 32 characters."
            )
    for label, url in (
        ("SOLSLOT_CHIA_PRIMARY_URL", settings.chia_primary_url),
        ("SOLSLOT_CHIA_FALLBACK_URL", settings.effective_chia_fallback_url()),
    ):
        if url and not url.startswith(("https://", "http://")):
            raise RuntimeError(f"{label} must be an HTTP(S) URL.")
    chia_mtls_paths = (
        settings.chia_primary_ca_cert_path,
        settings.chia_primary_client_cert_path,
        settings.chia_primary_client_key_path,
    )
    if any(chia_mtls_paths) and not all(chia_mtls_paths):
        raise RuntimeError(
            "Chia primary mTLS requires CA, client certificate, and client key paths."
        )
    if settings.protocol_fee_funding_enabled:
        if not settings.chia_primary_url:
            raise RuntimeError(
                "SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED requires "
                "SOLSLOT_CHIA_PRIMARY_URL."
            )
        if not any(
            (
                settings.faucet_master_sk_hex,
                settings.faucet_seed_hex,
                settings.faucet_mnemonic,
            )
        ):
            raise RuntimeError(
                "SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED requires one existing "
                "SOLSLOT_FAUCET_* credential."
            )
        if (
            settings.protocol_minimum_fee_mojos
            > settings.protocol_maximum_fee_mojos
        ):
            raise RuntimeError(
                "SOLSLOT_PROTOCOL_MINIMUM_FEE_MOJOS cannot exceed "
                "SOLSLOT_PROTOCOL_MAXIMUM_FEE_MOJOS."
            )
    if settings.stripe_delivery_worker_enabled:
        if not (
            settings.stripe_settlement_enabled
            or settings.payment_omnichain_enabled
        ):
            raise RuntimeError(
                "SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED requires "
                "Stripe settlement or the reviewed omnichain rail."
            )
    if (
        settings.stripe_delivery_worker_enabled
        or settings.voucher_issuance_worker_enabled
    ):
        worker_name = (
            "SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED"
            if settings.stripe_delivery_worker_enabled
            else "SOLSLOT_VOUCHER_ISSUANCE_WORKER_ENABLED"
        )
        if not settings.protocol_fee_funding_enabled:
            raise RuntimeError(
                f"{worker_name} requires "
                "SOLSLOT_PROTOCOL_FEE_FUNDING_ENABLED."
            )
        if not (
            settings.payment_kos_executor_url
            and settings.payment_kos_executor_private_key_file
            and settings.payment_kos_executor_public_key
        ):
            raise RuntimeError(
                f"{worker_name} requires the exact "
                "Key of Solomon executor URL, request key file, and public key."
            )
        if not valid_internal_service_url(settings.payment_kos_executor_url):
            raise RuntimeError(
                "SOLSLOT_PAYMENT_KOS_EXECUTOR_URL must use HTTPS or "
                "loopback-only HTTP."
            )
        try:
            kos_public_key = bytes.fromhex(
                settings.payment_kos_executor_public_key.removeprefix("0x")
            )
        except ValueError as exc:
            raise RuntimeError(
                "SOLSLOT_PAYMENT_KOS_EXECUTOR_PUBLIC_KEY is not valid hex."
            ) from exc
        if len(kos_public_key) != 48:
            raise RuntimeError(
                "SOLSLOT_PAYMENT_KOS_EXECUTOR_PUBLIC_KEY must be 48 bytes."
            )
        kos_mtls = (
            settings.payment_kos_executor_mtls_ca_path,
            settings.payment_kos_executor_mtls_cert_path,
            settings.payment_kos_executor_mtls_key_path,
        )
        if any(kos_mtls) and not all(kos_mtls):
            raise RuntimeError(
                "Key of Solomon mTLS requires CA, certificate, and key paths."
            )
        if (
            settings.runtime_environment in {"staging", "production"}
            and settings.payment_kos_executor_url.startswith("https://")
            and not all(kos_mtls)
        ):
            raise RuntimeError(
                "Remote Key of Solomon execution requires mTLS in hosted environments."
            )

    if settings.minting_enabled and not settings.alpha_writes_enabled:
        raise RuntimeError(
            "SOLSLOT_MINTING_ENABLED requires SOLSLOT_ALPHA_WRITES_ENABLED."
        )
    if settings.sgt_allocations_enabled:
        value = (settings.sgt_company_treasury_puzzle_hash or "").removeprefix("0x")
        if len(value) != 64:
            raise RuntimeError(
                "SOLSLOT_SGT_ALLOCATIONS_ENABLED requires the release-bound "
                "SOLSLOT_SGT_COMPANY_TREASURY_PUZZLE_HASH."
            )
        wusdc_b = (settings.sgt_wusdc_b_asset_id or "").removeprefix("0x")
        if len(wusdc_b) != 64:
            raise RuntimeError(
                "SOLSLOT_SGT_ALLOCATIONS_ENABLED requires the release-bound "
                "SOLSLOT_SGT_WUSDC_B_ASSET_ID."
            )
    if settings.funded_redemptions_enabled and not settings.alpha_writes_enabled:
        raise RuntimeError(
            "SOLSLOT_FUNDED_REDEMPTIONS_ENABLED requires SOLSLOT_ALPHA_WRITES_ENABLED."
        )
    if settings.funded_redemptions_enabled and not settings.sgt_allocations_enabled:
        raise RuntimeError(
            "SOLSLOT_FUNDED_REDEMPTIONS_ENABLED requires "
            "SOLSLOT_SGT_ALLOCATIONS_ENABLED."
        )
    if settings.presale_enabled and not settings.alpha_writes_enabled:
        raise RuntimeError(
            "SOLSLOT_PRESALE_ENABLED requires SOLSLOT_ALPHA_WRITES_ENABLED."
        )
    if settings.presale_enabled and not settings.collection_minting_enabled:
        raise RuntimeError(
            "SOLSLOT_PRESALE_ENABLED requires SOLSLOT_COLLECTION_MINTING_ENABLED."
        )
    if settings.voucher_issuance_worker_enabled and not settings.presale_enabled:
        raise RuntimeError(
            "SOLSLOT_VOUCHER_ISSUANCE_WORKER_ENABLED requires "
            "SOLSLOT_PRESALE_ENABLED."
        )
    if settings.voucher_issuance_worker_enabled and settings.network != "testnet11":
        raise RuntimeError("RC20 voucher issuance is restricted to testnet11.")
    for capability, capability_id, enabled, path_value, digest in (
        (
            "SOLS bridge",
            "warp-cat-bridge",
            settings.sols_bridge_enabled,
            settings.sols_bridge_release_evidence_path,
            settings.sols_bridge_release_evidence_sha256,
        ),
        (
            "SOLS liquidity",
            "governed-liquidity",
            settings.sols_liquidity_enabled,
            settings.sols_liquidity_release_evidence_path,
            settings.sols_liquidity_release_evidence_sha256,
        ),
    ):
        if not enabled:
            continue
        if not path_value or not digest or len(digest.removeprefix("0x")) != 64:
            raise RuntimeError(
                f"{capability} execution requires checksum-pinned release evidence."
            )
        from .sols_capability_evidence import (
            SolsCapabilityEvidenceError,
            load_sols_capability_evidence,
        )

        try:
            load_sols_capability_evidence(
                path_value=path_value,
                expected_sha256=digest,
                capability=capability_id,
                **settings.capability_evidence_binding(),
            )
        except SolsCapabilityEvidenceError as exc:
            raise RuntimeError(
                f"{capability} execution requires valid reviewed release evidence: {exc}"
            ) from exc
    if settings.ceremony_mode_enabled and not settings.alpha_writes_enabled:
        raise RuntimeError(
            "SOLSLOT_CEREMONY_MODE_ENABLED requires SOLSLOT_ALPHA_WRITES_ENABLED."
        )
    if settings.launch_control_enabled:
        if settings.network != "testnet11":
            raise RuntimeError("Guided alpha launch control is restricted to Testnet11.")
        if not settings.launch_source_evidence_path:
            raise RuntimeError(
                "SOLSLOT_LAUNCH_CONTROL_ENABLED requires checksum-pinned "
                "coordinated source evidence."
            )
        if settings.runtime_environment in {"staging", "production"}:
            if (
                not settings.launch_source_evidence_sha256
                or len(settings.launch_source_evidence_sha256.removeprefix("0x")) != 64
            ):
                raise RuntimeError(
                    "Guided launch control requires a pinned source-evidence SHA-256."
                )
            if len(settings.launch_session_secret) < 32:
                raise RuntimeError(
                    "Guided launch control requires a persistent 32-byte session secret."
                )
            if (
                not settings.launch_owner_claim_token
                or len(settings.launch_owner_claim_token) < 32
            ):
                raise RuntimeError(
                    "Guided launch control requires a separate one-time owner "
                    "claim token."
                )
        if (
            settings.launch_rehearsal_service_url
            and not valid_launch_rehearsal_service_url(
                settings.launch_rehearsal_service_url
            )
        ):
            raise RuntimeError(
                "SOLSLOT_LAUNCH_REHEARSAL_SERVICE_URL must use HTTPS or "
                "loopback-only HTTP and must not use the Key of Solomon "
                "port 8793."
            )
    if settings.collection_minting_enabled and not settings.collection_metadata_enabled:
        raise RuntimeError(
            "SOLSLOT_COLLECTION_MINTING_ENABLED requires "
            "SOLSLOT_COLLECTION_METADATA_ENABLED."
        )
    if settings.collection_minting_enabled and not settings.minting_enabled:
        raise RuntimeError(
            "SOLSLOT_COLLECTION_MINTING_ENABLED requires SOLSLOT_MINTING_ENABLED."
        )
    if settings.kos_mint_execute_signer_enabled:
        if not settings.alpha_writes_enabled or not settings.minting_enabled:
            raise RuntimeError(
                "SOLSLOT_KOS_MINT_EXECUTE_SIGNER_ENABLED requires alpha writes and minting."
            )
        if settings.network != "testnet11":
            raise RuntimeError("KoS MINT execute signing is restricted to testnet11.")
        if not settings.kos_mint_execute_signer_url:
            raise RuntimeError("KoS MINT execute signing requires a signer URL.")
        if not settings.kos_mint_execute_signer_url.startswith("https://"):
            raise RuntimeError("KoS MINT execute signer URL must use HTTPS.")
        if not all(
            (
                settings.kos_mint_execute_signer_mtls_ca_path,
                settings.kos_mint_execute_signer_mtls_cert_path,
                settings.kos_mint_execute_signer_mtls_key_path,
            )
        ):
            raise RuntimeError(
                "KoS MINT execute signing requires CA, client certificate, and client key paths."
            )

    if settings.payment_omnichain_ownership_activation_enabled:
        if settings.network != "testnet11":
            raise RuntimeError(
                "Base Sepolia ownership activation is restricted to the Testnet11 alpha."
            )
        if (
            not settings.payment_omnichain_rpc_url
            or not settings.payment_omnichain_rpc_url.startswith("https://")
        ):
            raise RuntimeError(
                "SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_ACTIVATION_ENABLED "
                "requires an HTTPS SOLSLOT_PAYMENT_OMNICHAIN_RPC_URL."
            )
        from .omnichain_ownership_activation import (
            OwnershipActivationError,
            load_authority_operation,
        )

        try:
            load_authority_operation(settings)
        except OwnershipActivationError as exc:
            raise RuntimeError(
                "Base Sepolia ownership activation requires the exact reviewed "
                f"Safe operation package: {exc}"
            ) from exc

    if settings.payment_omnichain_enabled:
        if (
            not settings.payment_omnichain_ingest_token
            or len(settings.payment_omnichain_ingest_token) < 32
        ):
            raise RuntimeError(
                "SOLSLOT_PAYMENT_OMNICHAIN_ENABLED requires a dedicated "
                "SOLSLOT_PAYMENT_OMNICHAIN_INGEST_TOKEN of at least 32 characters."
            )
        if len(settings.payment_evm_usdc_tokens) != 1:
            raise RuntimeError(
                "SOLSLOT_PAYMENT_OMNICHAIN_ENABLED requires exactly one "
                "SOLSLOT_PAYMENT_EVM_USDC_TOKENS chain binding."
            )
        if (
            not settings.payment_omnichain_rpc_url
            or not settings.payment_omnichain_rpc_url.startswith("https://")
        ):
            raise RuntimeError(
                "SOLSLOT_PAYMENT_OMNICHAIN_ENABLED requires an HTTPS "
                "SOLSLOT_PAYMENT_OMNICHAIN_RPC_URL."
            )
        chain_id_raw, token_address = next(
            iter(settings.payment_evm_usdc_tokens.items())
        )
        try:
            chain_id = int(chain_id_raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "SOLSLOT_PAYMENT_EVM_USDC_TOKENS must use a decimal chain ID."
            ) from exc
        from .omnichain_evidence import (
            OmnichainEvidenceError,
            load_omnichain_evidence,
        )

        try:
            load_omnichain_evidence(
                settings,
                chain_id=chain_id,
                token_address=token_address,
                gateway_profile=str(
                    settings.payment_omnichain_gateway_profile or ""
                ),
            )
        except OmnichainEvidenceError as exc:
            raise RuntimeError(
                "SOLSLOT_PAYMENT_OMNICHAIN_ENABLED requires valid reviewed "
                "preflight, deployment, Warp portal, Samuel, governance, "
                f"ownership, and activation evidence: {exc}"
            ) from exc

    if not hosted:
        return
    if settings.chia_primary_url:
        if not settings.chia_primary_url.startswith("https://"):
            raise RuntimeError(
                "SOLSLOT_CHIA_PRIMARY_URL must use HTTPS in staging/production."
            )
        if not all(chia_mtls_paths):
            raise RuntimeError(
                "The staging/production Chia primary requires reviewed mTLS files."
            )
    if not settings.admin_operation_approvals_enabled:
        raise RuntimeError(
            "SOLSLOT_ADMIN_OPERATION_APPROVALS_ENABLED must be true in staging/production."
        )
    if settings.collection_metadata_enabled:
        required_collection_settings = {
            "SOLSLOT_COLLECTION_S3_ENDPOINT_URL": settings.collection_s3_endpoint_url,
            "SOLSLOT_COLLECTION_S3_ACCESS_KEY_ID": settings.collection_s3_access_key_id,
            "SOLSLOT_COLLECTION_S3_SECRET_ACCESS_KEY": settings.collection_s3_secret_access_key,
            "SOLSLOT_COLLECTION_S3_PUBLIC_BASE_URL": settings.collection_s3_public_base_url,
            "SOLSLOT_COLLECTION_IPFS_API_URL": settings.collection_ipfs_api_url,
            "SOLSLOT_COLLECTION_IPFS_PINNING_SERVICE_URL": settings.collection_ipfs_pinning_service_url,
            "SOLSLOT_COLLECTION_IPFS_PINNING_TOKEN": settings.collection_ipfs_pinning_token,
            "SOLSLOT_COLLECTION_IPFS_GATEWAY_URL": settings.collection_ipfs_gateway_url,
            "SOLSLOT_COLLECTION_MALWARE_SCAN_URL": settings.collection_malware_scan_url,
        }
        missing = [name for name, value in required_collection_settings.items() if not value]
        if missing:
            raise RuntimeError(
                "Collection metadata is enabled without verified media services: "
                + ", ".join(missing)
            )
    proxy_cidrs = settings.trusted_proxy_cidr_list()
    if not proxy_cidrs:
        raise RuntimeError(
            "SOLSLOT_TRUSTED_PROXY_CIDRS must contain the Cloudflare source "
            "ranges in staging/production."
        )
    for value in proxy_cidrs:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise RuntimeError(
                f"SOLSLOT_TRUSTED_PROXY_CIDRS contains invalid CIDR {value!r}."
            ) from exc
        minimum_prefix = 8 if network.version == 4 else 16
        if network.prefixlen < minimum_prefix:
            raise RuntimeError(
                f"SOLSLOT_TRUSTED_PROXY_CIDRS range {value!r} is too broad."
            )
    if not settings.bootstrap_cookie_secure:
        raise RuntimeError(
            "SOLSLOT_BOOTSTRAP_COOKIE_SECURE must be true in staging/production."
        )
    if not settings.vault_session_cookie_secure:
        raise RuntimeError(
            "SOLSLOT_VAULT_SESSION_COOKIE_SECURE must be true in "
            "staging/production."
        )
    if settings.api_docs_enabled:
        raise RuntimeError(
            "SOLSLOT_API_DOCS_ENABLED must be false in staging/production."
        )
    if not settings.security_headers_enabled or not settings.hsts_enabled:
        raise RuntimeError(
            "Security headers and HSTS must be enabled in staging/production."
        )
    if settings.alpha_writes_enabled:
        if len(settings.vault_session_jwt_secret) < 32:
            raise RuntimeError(
                "SOLSLOT_VAULT_SESSION_JWT_SECRET must contain at least 32 "
                "characters before protocol writes are enabled."
            )
        if settings.zkpassport_validator_threshold != 2:
            raise RuntimeError(
                "Staging/production protocol writes require an exact 2-of-3 "
                "zkPassport validator quorum in SOLSLOT_ZKPASSPORT_VALIDATOR_THRESHOLD."
            )
        if len(settings.zkpassport_validator_urls) != 3:
            raise RuntimeError(
                "SOLSLOT_ZKPASSPORT_VALIDATOR_URLS must configure three signers."
            )
        if len(settings.zkpassport_validator_pubkeys) != 3:
            raise RuntimeError(
                "SOLSLOT_ZKPASSPORT_VALIDATOR_PUBKEYS must configure three public keys."
            )
        if len(set(settings.zkpassport_validator_pubkeys)) != 3:
            raise RuntimeError("zkPassport validator public keys must be distinct.")
        for index, pubkey in enumerate(settings.zkpassport_validator_pubkeys):
            try:
                raw_pubkey = bytes.fromhex(pubkey.removeprefix("0x"))
            except ValueError as exc:
                raise RuntimeError(
                    f"zkPassport validator public key {index} is not valid hex."
                ) from exc
            if len(raw_pubkey) != 48:
                raise RuntimeError(
                    f"zkPassport validator public key {index} must be 48 bytes."
                )
        expected_validator_urls = [
            "https://10.77.0.10:9443",
            "https://10.77.0.11:9443",
            "https://10.77.0.12:9443",
        ]
        if settings.zkpassport_validator_urls != expected_validator_urls:
            raise RuntimeError(
                "SOLSLOT_ZKPASSPORT_VALIDATOR_URLS must use the ordered private "
                "WireGuard signer topology."
            )
        if not all(
            (
                settings.zkpassport_validator_mtls_ca_path,
                settings.zkpassport_validator_mtls_cert_path,
                settings.zkpassport_validator_mtls_key_path,
            )
        ):
            raise RuntimeError(
                "Validator quorum calls require CA, client certificate, and client key paths."
            )
        if settings.zkpassport_evm_min_confirmations < 12:
            raise RuntimeError(
                "Protocol writes require at least 12 Sepolia confirmations for "
                "zkPassport attestation events."
            )

    if settings.ceremony_mode_enabled:
        if settings.network != "testnet11":
            raise RuntimeError("Ceremony mode is restricted to testnet11.")
        if settings.minting_enabled:
            raise RuntimeError("Ceremony mode cannot enable minting.")
        if not settings.admin_token:
            raise RuntimeError(
                "Ceremony mode requires a one-time SOLSLOT_ADMIN_TOKEN."
            )
        if settings.allowed_origins():
            raise RuntimeError(
                "Ceremony mode must be same-origin and cannot configure CORS origins."
            )
        incompatible_faucet_workers = [
            name
            for name, enabled in (
                (
                    "SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED",
                    settings.stripe_delivery_worker_enabled,
                ),
                (
                    "SOLSLOT_VOUCHER_ISSUANCE_WORKER_ENABLED",
                    settings.voucher_issuance_worker_enabled,
                ),
                (
                    "SOLSLOT_CHECKOUT_LIFECYCLE_WORKER_ENABLED",
                    settings.checkout_lifecycle_worker_enabled,
                ),
                (
                    "SOLSLOT_FAUCET_CONSOLIDATION_ENABLED",
                    settings.faucet_consolidation_enabled,
                ),
            )
            if enabled
        ]
        if incompatible_faucet_workers:
            raise RuntimeError(
                "Ceremony mode requires exclusive faucet selection; disable "
                + ", ".join(incompatible_faucet_workers)
            )
    # Post-ceremony authority is validated cryptographically from the signed
    # RC23 V4 artifact by ``validate_admin_config_at_startup``. Keeping that check
    # out of this HTTP-posture validator avoids a second mutable coordinate
    # source and a circular trust dependency.

    expected_evm_chain_id = 1 if settings.network == "mainnet" else 11155111
    permit_metadata = (settings.enrollment_permit_release_identity,
        settings.enrollment_permit_issuer_key_ref, settings.enrollment_permit_identity_client_id)
    if any(permit_metadata):
        if settings.network != "testnet11" or not all(permit_metadata):
            raise RuntimeError("Enrollment permit issuer metadata requires complete isolated Testnet configuration.")
        expected_evm_chain_id = 84532
    # This is a posture precheck, not activation authority. Every trust-critical
    # call still verifies the full signed artifact and exact issuer/release pins.
    if settings.eip712_chain_id != expected_evm_chain_id:
        raise RuntimeError(
            "SOLSLOT_EIP712_CHAIN_ID does not match SOLSLOT_NETWORK: "
            f"{settings.network} requires {expected_evm_chain_id}."
        )
    if settings.zkpassport_evm_chain_id != expected_evm_chain_id:
        raise RuntimeError(
            "SOLSLOT_ZKPASSPORT_EVM_CHAIN_ID does not match SOLSLOT_NETWORK: "
            f"{settings.network} requires {expected_evm_chain_id}."
        )

    insecure_origins: list[str] = []
    for origin in settings.allowed_origins():
        lowered = origin.lower()
        if (
            origin == "*"
            or lowered.startswith("http://")
            or "localhost" in lowered
            or "127.0.0.1" in lowered
            or "0.0.0.0" in lowered
        ):
            insecure_origins.append(origin)
    if insecure_origins:
        raise RuntimeError(
            "Staging/production CORS origins must be exact HTTPS origins; rejected: "
            + ", ".join(sorted(insecure_origins))
        )


def _secret_keys_present_in_env_file(path: Path) -> set[str]:
    keys: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return keys
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key in SECRET_ENV_FILE_KEYS and value.strip().strip("\"'"):
            keys.add(key)
    return keys


class Settings(BaseSettings):
    """Solslot API runtime settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="SOLSLOT_",
        extra="ignore",
    )

    # ── Empty-string → None coercion for optional-string fields ──────────
    # Setting an env var to "" (e.g. by the test conftest's ``.env``-mask
    # shim) must read back as ``None`` rather than ``""`` so callers'
    # ``is None`` checks behave the same as when the var is genuinely
    # unset.  Applied to every ``Optional[str]`` field where ``None`` is
    # the meaningful "absent" sentinel.
    @field_validator(
        "protocol_admin_authority_v2_launcher_id",
        "protocol_admin_authority_v2_mips_root_hash",
        "protocol_admin_authority_v2_admins_hash",
        "protocol_admin_authority_v2_pending_ops_hash",
        "pool_launcher_id",
        "governance_launcher_id",
        "protocol_config_launcher_id",
        "protocol_property_registry_launcher_id",
        "protocol_did_singleton_struct_hex",
        "protocol_did_puzhash",
        "p2_pool_mod_hash",
        "p2_vault_mod_hash",
        "vault_version_registry_launcher_id",
        "admin_records_path",
        "zkpassport_validator_mtls_ca_path",
        "zkpassport_validator_mtls_cert_path",
        "zkpassport_validator_mtls_key_path",
        "kos_mint_execute_signer_url",
        "kos_mint_execute_signer_mtls_ca_path",
        "kos_mint_execute_signer_mtls_cert_path",
        "kos_mint_execute_signer_mtls_key_path",
        "zkpassport_relayer_private_key_hex",
        "zkpassport_bridge_policy_hash",
        "zkpassport_forwarder_address",
        "zkpassport_verifier_adapter_address",
        "zkpassport_emitter_address",
        "protocol_artifact_api_token",
        "purchase_operations_service_url",
        "purchase_operations_token",
        "payment_kos_executor_url",
        "payment_kos_executor_private_key_file",
        "payment_kos_executor_public_key",
        "payment_kos_executor_mtls_ca_path",
        "payment_kos_executor_mtls_cert_path",
        "payment_kos_executor_mtls_key_path",
        "payment_omnichain_ingest_token",
        "payment_omnichain_rpc_url",
        "stripe_restricted_key_file",
        "payment_omnichain_ownership_safe_operation_path",
        "payment_omnichain_ownership_safe_operation_hash",
        "payment_omnichain_ownership_execute_operation_path",
        "payment_omnichain_ownership_execute_operation_hash",
        "launch_source_evidence_path",
        "launch_owner_claim_token",
        "launch_settlement_rehearsal_path",
        "launch_rehearsal_service_url",
        "launch_rehearsal_service_token",
        "launch_rehearsal_config_hash",
        "launch_rehearsal_evidence_hmac_secret",
        "launch_plan_template_path",
        "launch_source_evidence_sha256",
        "authority_v3_governance_evidence_path",
        "authority_v3_evm_rpc_url",
        "authority_v3_independent_review_path",
        "authority_v3_independent_review_sha256",
        "smtp_host",
        "smtp_username",
        "smtp_password",
        "smtp_from_address",
        "payment_oracle_rounds_path",
        "collection_s3_endpoint_url",
        "collection_s3_access_key_id",
        "collection_s3_secret_access_key",
        "collection_s3_public_base_url",
        "collection_ipfs_api_url",
        "collection_ipfs_pinning_service_url",
        "collection_ipfs_pinning_token",
        "collection_ipfs_gateway_url",
        "collection_malware_scan_url",
        "collection_malware_scan_token",
        "chia_primary_url",
        "chia_fallback_url",
        "chia_primary_ca_cert_path",
        "chia_primary_client_cert_path",
        "chia_primary_client_key_path",
        mode="before",
    )
    @classmethod
    def _empty_string_is_none(cls, v: object) -> object:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # ── Server posture ───────────────────────────────────────────────────
    # Secure-by-default: local development must opt in explicitly.  This
    # prevents a missing environment variable on a newly provisioned host
    # from silently enabling development CORS or API documentation.
    runtime_environment: Literal[
        "development", "test", "staging", "production"
    ] = "production"
    api_docs_enabled: bool = False
    security_headers_enabled: bool = True
    hsts_enabled: bool = True
    max_request_body_bytes: int = Field(4 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    request_timeout_seconds: float = Field(30.0, gt=0, le=120.0)
    # Only immediate peers in these Cloudflare source ranges may supply
    # CF-Connecting-IP. Keep this list synchronized from infrastructure code.
    trusted_proxy_cidrs: str = ""

    # ── Network ───────────────────────────────────────────────────────────
    network: Literal["testnet11", "mainnet"] = "testnet11"
    # ``coinset_base_url`` remains as a compatibility input while callers
    # migrate to the explicit fallback setting.
    coinset_base_url: str = "https://testnet11.api.coinset.org"
    chia_primary_url: Optional[str] = None
    chia_fallback_url: Optional[str] = None
    chia_primary_required: bool = False
    chia_primary_retry_count: int = Field(1, ge=0, le=3)
    chia_recovery_probe_seconds: float = Field(30.0, ge=5.0, le=300.0)
    chia_rpc_timeout_seconds: float = Field(20.0, gt=0, le=60.0)
    chia_push_per_ip_per_minute: int = Field(6, ge=1, le=60)
    chia_primary_ca_cert_path: Optional[str] = None
    chia_primary_client_cert_path: Optional[str] = None
    chia_primary_client_key_path: Optional[str] = None
    # Server-funded protocol submissions use the local node's native fee
    # estimator. The existing faucet wallet acts as a bounded fee till.
    protocol_fee_funding_enabled: bool = False
    protocol_medium_fee_target_seconds: int = Field(300, ge=60, le=1800)
    protocol_minimum_fee_mojos: int = Field(1, ge=0)
    protocol_maximum_fee_mojos: int = Field(10_000_000, ge=1)
    protocol_mempool_timeout_seconds: float = Field(20.0, ge=2.0, le=120.0)
    protocol_mempool_poll_seconds: float = Field(0.5, ge=0.1, le=5.0)

    def effective_chia_fallback_url(self) -> str:
        return self.chia_fallback_url or self.coinset_base_url

    # High-risk protocol writes remain locked until the frozen RC23 V4 artifact
    # bundle has passed ceremony preflight. Read-only health, protocol, vault,
    # and credential receipt recovery remain available while this is false.
    alpha_writes_enabled: bool = False
    minting_enabled: bool = False
    presale_enabled: bool = False
    # Additional server ceiling beneath the signed XCH voucher admin window.
    presale_xch_enabled: bool = False
    # Bridge and governed-liquidity adapters ship dark. A statutes record is
    # necessary but never sufficient to make either customer action live.
    sols_bridge_enabled: bool = False
    sols_liquidity_enabled: bool = False
    # Independent deployment pins; leaving any unset keeps execution closed.
    sols_capability_deployment_id: Optional[str] = None
    sols_capability_release_tag: Optional[str] = None
    sols_capability_source_sha: Optional[str] = None
    sols_capability_evm_rpc_url: Optional[str] = None
    sols_capability_operations_path: str = "./state/sols_capability_operations.db"

    def capability_evidence_binding(self) -> dict[str, object]:
        return {
            "expected_network": self.network,
            "expected_environment": self.runtime_environment,
            "expected_deployment_id": self.sols_capability_deployment_id,
            "expected_release_tag": self.sols_capability_release_tag,
            "expected_source_sha": self.sols_capability_source_sha,
            "require_runtime_binding": True,
        }

    # Capability evidence is a reviewed JSON package whose exact
    # checksum is pinned by deployment. The API also binds its governed root
    # and records to reconstructed statutes before advertising execution.
    sols_bridge_release_evidence_path: Optional[str] = None
    sols_bridge_release_evidence_sha256: Optional[str] = None
    sols_liquidity_release_evidence_path: Optional[str] = None
    sols_liquidity_release_evidence_sha256: Optional[str] = None
    # Automatic paid-reservation -> Chia voucher reconciliation. This is a
    # separate opt-in because it spends faucet coins and requests validator
    # quorum. Presale endpoints may be rehearsed while this remains disabled.
    voucher_issuance_worker_enabled: bool = False
    voucher_issuance_interval_seconds: float = Field(15.0, ge=5.0, le=300.0)
    # KoS is an isolated, optional co-signer for the one MINT EXECUTE
    # condition emitted by governance. The coordinator never receives a KoS
    # private key; it calls a separately deployed signer over mutual TLS.
    kos_mint_execute_signer_enabled: bool = False
    kos_mint_execute_signer_url: Optional[str] = None
    kos_mint_execute_signer_mtls_ca_path: Optional[str] = None
    kos_mint_execute_signer_mtls_cert_path: Optional[str] = None
    kos_mint_execute_signer_mtls_key_path: Optional[str] = None
    kos_mint_execute_signer_timeout_seconds: float = Field(8.0, gt=0, le=30)
    # One-shot testnet ceremony mode is the only state in which protocol
    # writes may run before a chain-bound admin authority exists. It requires
    # the bootstrap token, disables minting, and refuses all CORS origins.
    ceremony_mode_enabled: bool = False
    # The guided launch desk can be deployed while every chain-write ceiling
    # remains closed. It exposes preparation and signed review only; dynamic
    # operation windows never override the hard environment flags above.
    launch_control_enabled: bool = False
    release_metadata_path: str = "./release.json"

    # ── Auth / challenges ────────────────────────────────────────────────
    challenge_ttl_seconds: int = 300
    # 32-byte hex string.  If empty a random one is generated per-process.
    challenge_secret: str = ""
    # HttpOnly, same-site session issued after a normal wallet login. The
    # session authenticates silent credential workflow transitions; it never
    # substitutes for the two exact action signatures (proof relay and Chia
    # vault stamp).
    vault_session_jwt_secret: str = ""
    vault_session_ttl_seconds: int = Field(900, ge=300, le=3600)
    vault_session_cookie_secure: bool = True
    vault_session_cookie_path: str = "/protocol-api"

    # ── Faucet (launcher payer) ──────────────────────────────────────────
    # ONE of these three must be set; without any the backend refuses to
    # register new vaults.
    #   * faucet_mnemonic           — 12/24-word BIP-39 mnemonic
    #   * faucet_seed_hex           — 32-byte hex entropy for AugSchemeMPL.key_gen
    #   * faucet_master_sk_hex      — 32-byte hex of a serialised BLS master PrivateKey
    #                                 (e.g. pulled directly out of Chia's keychain)
    faucet_mnemonic: Optional[str] = None
    faucet_seed_hex: Optional[str] = None
    faucet_master_sk_hex: Optional[str] = None
    # Maximum amount (mojos) a single faucet-funded launcher may consume.
    # Launchers themselves cost 1 mojo; the rest is fee headroom.
    faucet_max_spend_mojos: int = 10_000_000  # 0.01 XCH per registration

    # ── Protocol deployment ───────────────────────────────────────────────
    # Once the pool singleton, governance singleton and DID are launched on
    # testnet they are pinned here.  Vaults must reference the same pool.
    pool_launcher_id: Optional[str] = None
    governance_launcher_id: Optional[str] = None
    # Dedicated company proceeds destination for governed SGT sales. Fresh
    # release evidence must bind this value; it is intentionally distinct from
    # the protocol's non-withdrawable treasury.
    sgt_company_treasury_puzzle_hash: Optional[str] = None
    sgt_allocations_enabled: bool = False
    # Governed collection redemptions funded by the protocol's immutable
    # wUSDC.b treasury. This remains independently gated from ordinary SGT
    # allocations so a release can prepare and review proposals while the
    # customer acceptance path stays closed.
    funded_redemptions_enabled: bool = False
    # Exact Warp wUSDC.b CAT used by governed SGT sale offers. Administrators
    # select the named rail; browsers never supply a CAT asset ID.
    sgt_wusdc_b_asset_id: Optional[str] = None
    # Retained only as an offline evidence/recovery input. Active runtime
    # coordinates come exclusively from the signed RC23 V4 public artifact.
    deployment_manifest_path: str = "./state/deployment_manifest_v2.json"
    public_artifact_path: str = "./state/public_artifact_v4.json"
    # Public, version-pinned issuer coordinates only; private keys remain in Key Vault.
    enrollment_permit_release_identity: str = ""
    enrollment_permit_issuer_key_ref: str = ""
    enrollment_permit_identity_client_id: str = ""
    bootstrap_manifest_path: str = "./state/bootstrap_manifest_v2.json"
    genesis_db_path: str = "./state/genesis_ceremony_v2.db"
    genesis_output_dir: str = "./state/genesis_ceremonies"
    genesis_audit_approval_path: str = "./state/genesis_audit_approval_v2.json"
    genesis_evm_deployment_path: str = "./state/genesis_evm_deployment_v2.json"
    enrollment_deployment_review_path: str = ""
    enrollment_deployment_review_sha256: str = ""
    genesis_invitation_ttl_seconds: int = Field(172800, ge=1800, le=172800)
    genesis_plan_ttl_seconds: int = Field(3600, ge=900, le=7200)
    genesis_sepolia_confirmations: int = Field(12, ge=12, le=12)
    genesis_chia_confirmations: int = Field(3, ge=3, le=3)
    bootstrap_session_secret: str = ""
    bootstrap_session_ttl_seconds: int = Field(900, ge=1)
    bootstrap_cookie_secure: bool = True
    launch_session_secret: str = ""
    launch_session_ttl_seconds: int = Field(900, ge=300, le=3600)
    launch_cookie_path: str = "/protocol-api/admin/launch"
    # The guided browser never chooses the ceremony review class. Official
    # Testnet11 releases use an independent review; an explicitly configured
    # internal engineering run remains available only as a disposable operator
    # workflow and must not be represented as the official genesis.
    launch_genesis_review_class: Literal[
        "independent-release-review", "internal-engineering-testnet"
    ] = "independent-release-review"
    launch_release_tag: str = "solslot-v2-alpha-rc27.36-20260824"
    launch_owner_claim_token: Optional[str] = None
    launch_source_evidence_path: Optional[str] = (
        "./state/source-freeze-evidence-rc27.36.json"
    )
    launch_source_evidence_sha256: Optional[str] = None
    launch_plan_template_path: Optional[str] = (
        "./state/plan-input-template-rc27.36.json"
    )
    launch_settlement_rehearsal_path: Optional[str] = (
        "./state/settlement-rehearsal-rc27.36.json"
    )
    launch_rehearsal_service_url: Optional[str] = None
    launch_rehearsal_service_token: Optional[str] = None
    launch_rehearsal_config_hash: Optional[str] = None
    launch_rehearsal_evidence_hmac_secret: Optional[str] = None
    launch_rehearsal_timeout_seconds: int = Field(20, ge=5, le=60)
    launch_gate_max_seconds: int = Field(3600, ge=300, le=86400)

    # Recovery-aware Authority V3. Coordinates are accepted only from the
    # checksummed deployment evidence produced by the pinned Omnichain
    # release. The independent-review receipt is a hard ceremony-readiness
    # requirement, not a runtime authority override.
    authority_v3_governance_evidence_path: Optional[str] = None
    authority_v3_evm_rpc_url: Optional[str] = None
    authority_v3_evm_min_confirmations: int = Field(12, ge=12)
    authority_v3_independent_review_path: Optional[str] = None
    authority_v3_independent_review_sha256: Optional[str] = None

    # Provider-neutral reminders. Email is advisory; the persisted task inbox
    # remains authoritative when SMTP is absent or delivery fails.
    smtp_host: Optional[str] = None
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_address: Optional[str] = None
    smtp_starttls: bool = True

    # Canonical publish context. These values are populated only from the
    # signed ceremony artifact and are required before a mint can be
    # published. Draft creation may remain available without them.
    protocol_did_singleton_struct_hex: Optional[str] = None
    protocol_did_puzhash: Optional[str] = None
    p2_pool_mod_hash: Optional[str] = None
    p2_vault_mod_hash: Optional[str] = None

    # ── Protocol-config singleton (A.3) ───────────────────────────────────
    # On-chain replacement for the three trust-root env vars
    # ``pool_launcher_id`` / ``governance_launcher_id`` / ``network``.
    # When the operator has launched a ``protocol_config_inner.clsp``
    # singleton, set this to its 32-byte launcher coin id (0x-prefixed
    # hex).  The API then surfaces a deterministic ``protocol_config_hash``
    # on ``/protocol`` so frontends can independently verify the
    # operator's published config matches the on-chain singleton state.
    #
    # The value must come from the signed RC23 V4 ceremony artifact.
    protocol_config_launcher_id: Optional[str] = None
    # Monotonically increasing version stamped into the singleton's
    # curried state.  Bumped by the operator on every config update;
    # the puzzle enforces ``new_version > old_version`` (replay
    # protection).  Default 1 = "initial deployment".
    protocol_config_version: int = 1

    # ── Solslot V2 admin-authority singleton ──────────────────────────────
    # CHIP-0043 MIPS composition replaces flat key allowlists.
    # composition. Each admin slot holds a OneOfN of personal auth methods
    # (BLS, EIP-712 / MetaMask, passkey, ...) under a protocol-level MofN
    # quorum. Lets admins mix signing methods and add backup keys over time
    # without going through SGT governance.
    #
    # The API exposes these values publicly and accepts admin JWTs only from
    # a records file whose launcher and admins hash match this authority.
    #
    protocol_admin_authority_v2_launcher_id: Optional[str] = None
    # 0x-prefixed 32-byte sha256-tree hash of the MIPS m_of_n quorum tree.
    # Computed off-chain via chia-wallet-sdk MIPS bindings; published here
    # so the snapshot endpoint can return the same value the on-chain
    # puzzle has curried.
    protocol_admin_authority_v2_mips_root_hash: Optional[str] = None
    # 0x-prefixed sha256-tree hash of the admins list (each entry is
    # ``(admin_idx, leaves_list, m_within)``). Computed via
    # ``solslot_puzzles.admin_authority_v2_driver.compute_admins_hash``.
    protocol_admin_authority_v2_admins_hash: Optional[str] = None
    # 0x-prefixed sha256-tree hash of the pending-ops list. Defaults to
    # the empty-list hash when omitted; bumped whenever a KEY_ADD_PROPOSE
    # / KEY_REMOVE_EMERGENCY adds an entry, or KEY_ADD_ACTIVATE / VETO
    # / KEY_ADD_REMOVE_ACTIVATE removes one.
    protocol_admin_authority_v2_pending_ops_hash: Optional[str] = None
    # Monotonic uint64 stamped into the v2 singleton's curried state.
    # Strictly increases across all 6 spend tags. Defaults to 1; operators
    # The clean V2 ceremony starts this counter at 1.
    protocol_admin_authority_v2_version: int = 1

    # ── Property-registry singleton (A.4) ─────────────────────────────────
    # On-chain replacement for the off-chain property-uniqueness role
    # of ``MintProposalStore`` (POP-CANON-014).  When the operator has
    # launched a ``property_registry_inner.clsp`` singleton, set this
    # to its launcher coin id; the API surfaces it on the ``/protocol``
    # endpoint so clients can walk the singleton's lineage on
    # coinset.org to enumerate registered properties.
    #
    # Minting remains locked until this singleton can be verified on-chain.
    protocol_property_registry_launcher_id: Optional[str] = None

    # ── Vault-version registry singleton (vault upgrade / Brick 4d) ────────
    # On-chain ``vault_version_registry_inner.clsp`` singleton that publishes
    # the canonical current vault descriptor (vault inner mod hash, canonical
    # params hash, vault version).  Backend-free clients walk its lineage on
    # coinset.org to detect outdated vaults and offer a decentralized upgrade.
    # When the operator has launched the registry, set this to its 32-byte
    # launcher coin id (0x-prefixed hex); the API then surfaces a deterministic
    # ``vault_version_registry_content_hash`` clients can independently verify
    # against the singleton's on-chain ``CREATE_PUZZLE_ANNOUNCEMENT``.  ``None``
    # until the registry is deployed (clients treat the protocol as
    # "registry-less" and skip the upgrade banner).
    vault_version_registry_launcher_id: Optional[str] = None
    # Monotonically increasing vault descriptor version stamped into the
    # registry's curried state.  Bumped by the authorizer on every publish
    # spend; default 1 = "initial deployment".
    vault_version_registry_version: int = 1

    # ── zkPassport validator quorum ───────────────────────────────────────
    # The coordinator owns no validator private key. These ordered arrays
    # commit to three independent signer services; the same order is curried
    # into the Chia bridge puzzle. Production calls use mutual TLS.
    zkpassport_validator_urls: list[str] = Field(default_factory=list)
    zkpassport_validator_pubkeys: list[str] = Field(default_factory=list)
    zkpassport_validator_threshold: int = Field(2, ge=1, le=3)
    zkpassport_validator_mtls_ca_path: Optional[str] = None
    zkpassport_validator_mtls_cert_path: Optional[str] = None
    zkpassport_validator_mtls_key_path: Optional[str] = None
    zkpassport_validator_timeout_seconds: float = Field(8.0, gt=0, le=30)

    # ── zkPassport vault bridge policy hash ───────────────────────────
    # Canonical validator-set commitment curried into every vault at mint so
    # the on-chain spend_update_identity ('z') can assert the validator bridge
    # coin announcement.  MUST equal the deployed emitter's bridgePolicyHash and
    # the portal's environment.zkPassport bridgePolicyHash.  Vaults minted before
    # this was wired (the old zero default) are NOT enrollable and must be
    # re-registered.
    zkpassport_bridge_policy_hash: Optional[str] = None
    zkpassport_bridge_amount: int = 1
    # Enrollment discovers confirmed unspent coins at the current bridge
    # policy hash. Public enrollment requests never spend the faucet. A
    # chain-verified admin replenishes the pool through the protected route.
    # Persistent public receipt/index and anti-replay ledger. Chia vault state
    # remains final authority. A fresh database is required for every V2
    # ceremony; retired JSON enrollment stores are never imported.
    zkpassport_ledger_db_path: str = "./state/zkpassport_v2.db"
    zkpassport_policy_version: int = Field(2, ge=2)
    zkpassport_owner_challenge_ttl_seconds: int = Field(300, ge=30, le=900)

    # ── zkPassport gasless relayer (ERC-2771 meta-transactions) ────────
    # The relayer submits forwarder.execute() on behalf of users so alpha
    # testers never need Sepolia ETH.  Users still sign an EIP-712
    # ForwardRequest in their wallet (gasless); this key only pays gas.
    #
    # SECRET — 0x-prefixed 32-byte key of a funded EOA.  When unset, POST
    # /zkpassport/relay returns 503.  Store in .env (mode 0600); on testnet you
    # may reuse the EVM deployer key.
    zkpassport_relayer_private_key_hex: Optional[str] = None

    # ── Sols Lot protocol artifact server-to-server guard ────────────────
    # Optional bearer token for endpoints that *build* or *finalize*
    # protocol purchase artifacts.  Public verification remains open so
    # wallets, portals, and auditors can recompute artifact hashes without
    # holding any service credential.
    protocol_artifact_api_token: Optional[str] = None
    # Read-only bridge from the coordinator's admin JWT boundary to the
    # durable customer purchase ledger. HTTP is permitted only on loopback.
    purchase_operations_service_url: Optional[str] = None
    purchase_operations_token: Optional[str] = None
    # H-system generated oracle snapshots for XCH/CAT purchase offers.
    # The browser never supplies prices. Each strict CLVM round in this file
    # must carry a 2-of-3 BLS authorization from this dedicated roster.
    payment_oracle_rounds_path: Optional[str] = None
    payment_oracle_operator_pubkeys: list[str] = Field(default_factory=list)
    payment_oracle_allowed_cat_asset_ids: list[str] = Field(
        default_factory=list
    )
    # Coordinator-owned purchase ledger and allowlisted six-decimal EVM
    # stablecoin contracts. The map uses decimal chain IDs as keys and
    # 0x-prefixed 20-byte token addresses as values.
    payment_purchase_db_path: str = "./state/payment_purchases_v2.db"
    payment_evm_usdc_tokens: dict[str, str] = Field(default_factory=dict)
    # Stripe fulfillment is a post-mint direct rail. The API and each isolated
    # validator use distinct restricted read-only keys so provider evidence is
    # verified before durable queueing and again before validator signing.
    stripe_settlement_enabled: bool = False
    stripe_account_id: Optional[str] = None
    stripe_mode: Literal["test", "live"] = "test"
    stripe_restricted_key_file: Optional[str] = None
    stripe_api_url: str = "https://api.stripe.com"
    stripe_delivery_db_path: str = "./state/stripe_deliveries_v1.db"
    stripe_delivery_worker_enabled: bool = False
    checkout_lifecycle_worker_enabled: bool = False
    stripe_delivery_interval_seconds: float = Field(15.0, ge=5.0, le=300.0)
    stripe_delivery_lease_seconds: int = Field(60, ge=30, le=600)
    # The coordinator signs only exact execution envelopes. Key of Solomon
    # receives no payment credential and is the sole submit/retry boundary.
    payment_kos_executor_url: Optional[str] = None
    payment_kos_executor_private_key_file: Optional[str] = None
    payment_kos_executor_public_key: Optional[str] = None
    payment_kos_executor_timeout_seconds: float = Field(30.0, gt=0, le=120.0)
    payment_kos_executor_mtls_ca_path: Optional[str] = None
    payment_kos_executor_mtls_cert_path: Optional[str] = None
    payment_kos_executor_mtls_key_path: Optional[str] = None
    # External CCIP/Warp escrow is separately deployed from the ceremony EVM
    # bridge. Token allowlisting alone must never activate this rail.
    payment_omnichain_enabled: bool = False
    payment_omnichain_ingest_token: Optional[str] = None
    payment_omnichain_rpc_url: Optional[str] = None
    payment_omnichain_preflight_evidence_path: Optional[str] = None
    payment_omnichain_evidence_path: Optional[str] = None
    payment_omnichain_activation_evidence_path: Optional[str] = None
    payment_omnichain_governance_evidence_path: Optional[str] = None
    payment_omnichain_samuel_evidence_path: Optional[str] = None
    payment_omnichain_warp_portal_evidence_path: Optional[str] = None
    payment_omnichain_ownership_intent_evidence_path: Optional[str] = None
    # A separate, one-shot gate for transferring the Base Sepolia rail to the
    # reviewed 2-of-3 Safe + timelock. Administrators sign the actual nested
    # SafeMessage payload; no API-specific approval envelope is introduced.
    payment_omnichain_ownership_activation_enabled: bool = False
    payment_omnichain_ownership_safe_operation_path: Optional[str] = None
    payment_omnichain_ownership_safe_operation_hash: Optional[str] = None
    payment_omnichain_ownership_execute_operation_path: Optional[str] = None
    payment_omnichain_ownership_execute_operation_hash: Optional[str] = None
    payment_omnichain_ownership_min_confirmations: int = Field(12, ge=12)
    payment_omnichain_source_sha: Optional[str] = None
    payment_omnichain_gateway_profile: Optional[str] = Field(
        None, min_length=1, max_length=32
    )
    # JSON-RPC endpoint the relayer uses (defaults to a public Sepolia node).
    zkpassport_evm_rpc_url: str = "https://ethereum-sepolia-rpc.publicnode.com"
    # EIP-155 chain id the relayer signs for (11155111 = Eth Sepolia).
    zkpassport_evm_chain_id: int = 11155111
    # Fresh V2 addresses are intentionally unset until the EVM ceremony.
    zkpassport_forwarder_address: Optional[str] = None
    zkpassport_verifier_adapter_address: Optional[str] = None
    zkpassport_emitter_address: Optional[str] = None
    zkpassport_evm_min_confirmations: int = Field(12, ge=1)
    # Admission bound only. Existing external authorizations have no lease;
    # pending coins are never freed solely because local time has elapsed.
    zkpassport_enrollment_max_pending_per_owner: int = Field(3, ge=1, le=20)

    # Persistent relay limits. Each axis is enforced independently so one
    # account, vault, source, or bridge coin cannot drain the sponsored key.
    zkpassport_relay_per_ip_per_minute: int = Field(12, ge=1)
    zkpassport_relay_per_owner_per_minute: int = Field(6, ge=1)
    zkpassport_relay_per_vault_per_hour: int = Field(2, ge=1)
    zkpassport_relay_global_gas_per_day: int = Field(20_000_000, ge=1)
    zkpassport_relay_circuit_failure_threshold: int = Field(5, ge=1)
    zkpassport_relay_circuit_cooldown_seconds: int = Field(900, ge=60)

    # ── Admin auth ────────────────────────────────────────────────────────
    # Bearer token required by `/admin/deploy/*` and other one-shot operator
    # commands.  When unset, those routes are disabled (return 503) — the
    # safest default for a public endpoint without an explicit operator
    # opt-in.  Generate with `openssl rand -hex 32`.
    admin_token: Optional[str] = None

    # ── Admin Desk (interactive operator UI) ──────────────────────────────
    # The Admin Desk uses chain-bound records + a short-lived JWT instead
    # of the ceremony token. See
    # `docs/ADMIN_DESK_DESIGN.md` §3 for the full rationale.

    # Path to a JSON file containing the OPERATOR-EXPANDED admin records
    # When set, the API:
    #   1. Loads the records at boot.
    #   2. Recomputes ``admins_hash`` from them via the protocol's
    #      canonical hash function and asserts it matches the on-chain
    #      singleton's ``admins_hash`` (sourced from
    #      ``protocol_admin_authority_v2_admins_hash`` ceremony coordinate).
    #   3. Builds the EVM-address set from the JSON's EIP-712 leaf metadata.
    #
    # The file is ENVIRONMENT-LOCAL — it contains only data that's already
    # public (pubkeys, EVM addresses, hashes); no secrets.  But it MUST
    # match the on-chain state or the API refuses to boot, so treat it
    # as part of the deployment artefact.
    #
    # See ``solslot_api.admin_records.AdminRecordsConfig`` for the JSON
    # schema; ``GENESIS_README.md`` shows how to generate this file from
    # a launch wizard run.
    admin_records_path: Optional[str] = None

    def effective_admin_records_path(self) -> Optional[str]:
        if self.admin_records_path:
            return self.admin_records_path
        path = Path(self.bootstrap_manifest_path).with_name("admin_records_v2.json")
        return str(path) if path.exists() else None

    def _finalized_admin_authority_v2(self) -> dict[str, object]:
        path = Path(self.bootstrap_manifest_path).with_name("portal_runtime_config_v2.json")
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict):
            return {}
        authority = raw.get("admin_authority_v2")
        return authority if isinstance(authority, dict) else {}

    def effective_protocol_admin_authority_v2_launcher_id(self) -> Optional[str]:
        if self.protocol_admin_authority_v2_launcher_id:
            return self.protocol_admin_authority_v2_launcher_id
        value = self._finalized_admin_authority_v2().get("launcher_id")
        return value if isinstance(value, str) and value.strip() else None

    def effective_protocol_admin_authority_v2_mips_root_hash(self) -> Optional[str]:
        if self.protocol_admin_authority_v2_mips_root_hash:
            return self.protocol_admin_authority_v2_mips_root_hash
        value = self._finalized_admin_authority_v2().get("mips_root")
        return value if isinstance(value, str) and value.strip() else None

    def effective_protocol_admin_authority_v2_admins_hash(self) -> Optional[str]:
        if self.protocol_admin_authority_v2_admins_hash:
            return self.protocol_admin_authority_v2_admins_hash
        value = self._finalized_admin_authority_v2().get("admins_hash")
        return value if isinstance(value, str) and value.strip() else None

    def effective_protocol_admin_authority_v2_version(self) -> int:
        authority = self._finalized_admin_authority_v2()
        value = authority.get("authority_version")
        if (
            self.protocol_admin_authority_v2_version != 1
            or not isinstance(value, int)
        ):
            return self.protocol_admin_authority_v2_version
        return value

    # HS256 secret used to sign admin-desk JWTs.  Generate with
    # `openssl rand -hex 32`.  When empty, a random per-process secret is
    # generated; that's fine for local dev but means tokens don't survive
    # restart.  In production, set this explicitly.
    admin_jwt_secret: str = ""

    # Consequential post-genesis mutations require a persistent operation
    # envelope signed by slot 0 and one of slots 1/2. This may be disabled
    # only in explicit development/test fixtures.
    admin_operation_approvals_enabled: bool = True

    # Lifetime (seconds) of an admin JWT.  Default 15 minutes.  Refresh via
    # /admin/auth/refresh while the session is active.
    admin_jwt_ttl_seconds: int = 900

    # Rate limit on /admin/auth/challenge per source IP per minute.
    admin_login_per_ip_per_minute: int = 6

    # Default voting window (seconds) for newly-published mint proposals.
    # The operator can override per-proposal within
    # [voting_window_min, voting_window_max].  Default 24h.
    voting_window_seconds_default: int = 86400
    voting_window_seconds_min: int = 3600       # 1h floor
    voting_window_seconds_max: int = 604800     # 7d ceiling

    # Filesystem path to the admin desk SQLite database (mint proposals,
    # property metadata).  Distinct from the vault registry path so the
    # operator can back them up independently.
    admin_db_path: str = "./state/admin_desk_v2.db"

    # ── Chain-verifiable collection minting ──────────────────────────────
    # Metadata authoring and proposal publication are independently gated.
    # Both default off so an API upgrade cannot expose an unfinished desk.
    collection_metadata_enabled: bool = False
    collection_minting_enabled: bool = False

    # Authenticated S3-compatible staging store. Objects are never considered
    # investor-ready until the API has fetched and verified their bytes.
    collection_s3_endpoint_url: Optional[str] = None
    collection_s3_region: str = "us-east-1"
    collection_s3_bucket: str = "solslot-collections"
    collection_s3_access_key_id: Optional[str] = None
    collection_s3_secret_access_key: Optional[str] = None
    collection_s3_public_base_url: Optional[str] = None
    collection_s3_presign_ttl_seconds: int = Field(900, ge=60, le=3600)
    collection_asset_max_bytes: int = Field(
        100 * 1024 * 1024, ge=1, le=250 * 1024 * 1024
    )
    collection_asset_verification_timeout_seconds: float = Field(
        30.0, gt=0, le=120.0
    )
    collection_private_download_ttl_seconds: int = Field(300, ge=60, le=900)

    # Bytes first enter an IPFS node/API, then the provider-neutral Pinning
    # Service API records the returned CID. Gateway re-fetch verifies that
    # the pinned object still hashes to the declared SHA-256.
    collection_ipfs_api_url: Optional[str] = None
    collection_ipfs_pinning_service_url: Optional[str] = None
    collection_ipfs_pinning_token: Optional[str] = None
    collection_ipfs_gateway_url: Optional[str] = None

    # Scanner must return {"status":"CLEAN"}. No scanner means no publish;
    # there is deliberately no production fail-open mode.
    collection_malware_scan_url: Optional[str] = None
    collection_malware_scan_token: Optional[str] = None

    # ── CORS ──────────────────────────────────────────────────────────────
    # Same-origin deployments need no CORS entries. Local development opts
    # in with SOLSLOT_RUNTIME_ENVIRONMENT=development; only then is the
    # localhost regex accepted by cors_middleware_options().
    cors_origins: str = ""

    # ── EIP-712 domain ────────────────────────────────────────────────────
    eip712_name: str = "Solslot Protocol"
    # V2 binds pool, auth type, and network. Other versions are rejected.
    eip712_version: str = "2"
    # MUST match EIP712_DOMAIN_CHAIN_ID in solslot_puzzles/vault_driver.py.
    # The current Solslot V2 alpha vault is bound to Ethereum Sepolia.
    eip712_chain_id: int = 11155111

    # ── DoS hardening (POP-CANON-003 / Strategy 7) ────────────────────────
    # Maximum number of pending challenges in memory at any time.  When the
    # cap is reached, /auth/challenge returns 429 to back off load.
    challenge_store_max_pending: int = 50_000
    # Maximum challenges issued per source IP per minute.
    challenge_per_ip_per_minute: int = 60
    # Shared SQLite-WAL store makes challenge quotas and nonce consumption
    # process-safe. Tests opt into the in-memory implementation explicitly.
    challenge_store_path: str = "./state/challenges_v2.db"

    # ── Faucet UTXO consolidation worker (POP-CANON-008) ──────────────────
    # Background task that periodically merges fragmented faucet change UTXOs
    # back into a single coin.  Disabled by default — operators must opt in
    # after verifying behaviour against their own faucet.
    faucet_consolidation_enabled: bool = False
    # When the unspent UTXO count exceeds this, the worker triggers a merge.
    faucet_consolidation_threshold: int = 50
    # Polling interval in seconds (default 10 min).
    faucet_consolidation_interval_seconds: float = 600.0
    # Fee paid by the consolidating spend bundle (mojos).  Default 0 — testnet
    # mempools accept zero-fee bundles when block space is available.
    faucet_consolidation_fee: int = 0
    # Cap on inputs per consolidation run (well below MAX_SPENDS_PER_BLOCK).
    faucet_consolidation_max_inputs: int = 500

    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def trusted_proxy_cidr_list(self) -> list[str]:
        return [
            value.strip()
            for value in self.trusted_proxy_cidrs.split(",")
            if value.strip()
        ]

    def effective_admin_allowlist_set(self) -> set[str]:
        """Return EVM admins derived only from hash-verified V2 records."""
        if self.effective_admin_records_path():
            from .admin_records import get_admin_records_for_settings
            records = get_admin_records_for_settings(self)
            if records is None:
                return set()  # path set but load failed validation already
            return records.eip712_evm_address_set()
        return set()

@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
