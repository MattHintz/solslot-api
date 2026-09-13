from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import httpx
from fastapi import FastAPI, Request
from pydantic import BaseModel

from solslot_api.config import Settings, validate_server_hardening_at_startup
from solslot_api.challenges import RequestRateLimiter, preflight_challenge_storage
from solslot_api.server_hardening import (
    ServerHardeningMiddleware,
    documentation_urls,
    trusted_client_ip,
)
from solslot_api.genesis_store import GenesisStore


class ChallengeBody(BaseModel):
    address: str


def _app(settings: Settings) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(ServerHardeningMiddleware, settings=settings)

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, bool]:
        await request.body()
        return {"ok": True}

    @app.get("/slow")
    async def slow() -> dict[str, bool]:
        await asyncio.sleep(0.05)
        return {"ok": True}

    @app.post("/auth/challenge")
    async def challenge(body: ChallengeBody) -> dict[str, str]:
        return {"address": body.address}

    @app.post("/chia/push_tx")
    async def chia_push() -> dict[str, bool]:
        return {"success": True}

    return app


def _staging(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "runtime_environment": "staging",
        "api_docs_enabled": False,
        "bootstrap_cookie_secure": True,
        "security_headers_enabled": True,
        "hsts_enabled": True,
        "trusted_proxy_cidrs": "203.0.113.0/24,2001:db8:1234::/48",
        "cors_origins": "https://staging.solslot.com",
        "alpha_writes_enabled": False,
        "admin_operation_approvals_enabled": True,
        "vault_session_jwt_secret": "v" * 32,
        "protocol_artifact_api_token": "a" * 32,
        "minting_enabled": False,
        "zkpassport_validator_urls": [
            "https://10.77.0.10:9443",
            "https://10.77.0.11:9443",
            "https://10.77.0.12:9443",
        ],
        "zkpassport_validator_pubkeys": [
            "0x" + "11" * 48,
            "0x" + "22" * 48,
            "0x" + "33" * 48,
        ],
        "zkpassport_validator_mtls_ca_path": "/run/secrets/validator-ca.pem",
        "zkpassport_validator_mtls_cert_path": "/run/secrets/coordinator-cert.pem",
        "zkpassport_validator_mtls_key_path": "/run/secrets/coordinator-key.pem",
    }
    values.update(overrides)
    return Settings(**values)


def test_staging_posture_passes_with_exact_https_origin() -> None:
    validate_server_hardening_at_startup(_staging())


@pytest.mark.parametrize("token", [None, "", "too-short"])
def test_staging_requires_protocol_artifact_service_token(
    token: str | None,
) -> None:
    with pytest.raises(RuntimeError, match="PROTOCOL_ARTIFACT_API_TOKEN"):
        validate_server_hardening_at_startup(
            _staging(protocol_artifact_api_token=token)
        )


def test_stripe_settlement_requires_restricted_provider_key(
    tmp_path,
) -> None:
    missing = tmp_path / "missing-key"
    with pytest.raises(RuntimeError, match="STRIPE_RESTRICTED_KEY_FILE"):
        validate_server_hardening_at_startup(
            _staging(
                stripe_settlement_enabled=True,
                stripe_account_id="acct_testnet",
                stripe_restricted_key_file=str(missing),
            )
        )

    key_path = tmp_path / "coordinator-stripe-read-key"
    key_path.write_text("rk_test_" + "a" * 24, encoding="ascii")
    key_path.chmod(0o600)
    validate_server_hardening_at_startup(
        _staging(
            stripe_settlement_enabled=True,
            stripe_account_id="acct_testnet",
            stripe_restricted_key_file=str(key_path),
        )
    )


def test_stripe_settlement_rejects_exposed_or_wrong_mode_key(
    tmp_path,
) -> None:
    key_path = tmp_path / "coordinator-stripe-read-key"
    key_path.write_text("rk_live_" + "a" * 24, encoding="ascii")
    key_path.chmod(0o644)
    with pytest.raises(RuntimeError, match="group/other"):
        validate_server_hardening_at_startup(
            _staging(
                stripe_settlement_enabled=True,
                stripe_account_id="acct_testnet",
                stripe_restricted_key_file=str(key_path),
            )
        )

    key_path.chmod(0o600)
    with pytest.raises(RuntimeError, match="configured Stripe mode"):
        validate_server_hardening_at_startup(
            _staging(
                stripe_settlement_enabled=True,
                stripe_account_id="acct_testnet",
                stripe_restricted_key_file=str(key_path),
            )
        )


def test_sgt_allocations_require_release_bound_company_treasury() -> None:
    with pytest.raises(RuntimeError, match="SGT_COMPANY_TREASURY"):
        validate_server_hardening_at_startup(
            _staging(sgt_allocations_enabled=True)
        )
    validate_server_hardening_at_startup(
        _staging(
            sgt_allocations_enabled=True,
            sgt_company_treasury_puzzle_hash="0x" + "19" * 32,
            sgt_wusdc_b_asset_id="0x" + "20" * 32,
        )
    )


def test_guided_launch_requires_a_separate_owner_claim_token() -> None:
    common = {
        "launch_control_enabled": True,
        "launch_source_evidence_sha256": "11" * 32,
        "launch_session_secret": "session-secret-that-is-long-enough",
        "admin_token": "legacy-admin-token-that-is-long-enough",
    }
    with pytest.raises(RuntimeError, match="separate one-time owner claim token"):
        validate_server_hardening_at_startup(_staging(**common))

    validate_server_hardening_at_startup(
        _staging(
            **common,
            launch_owner_claim_token="owner-claim-token-that-is-long-enough",
        )
    )


def test_customer_bridge_and_liquidity_cannot_execute_on_testnet() -> None:
    with pytest.raises(RuntimeError, match="bridge execution requires checksum-pinned release evidence"):
        validate_server_hardening_at_startup(
            _staging(sols_bridge_enabled=True)
        )
    with pytest.raises(RuntimeError, match="liquidity execution requires checksum-pinned release evidence"):
        validate_server_hardening_at_startup(
            _staging(sols_liquidity_enabled=True)
        )


def test_mainnet_capability_flag_requires_checksum_pinned_evidence() -> None:
    with pytest.raises(RuntimeError, match="checksum-pinned release evidence"):
        validate_server_hardening_at_startup(
            _staging(
                runtime_environment="production",
                network="mainnet",
                sols_bridge_enabled=True,
            )
        )


def test_required_chia_primary_requires_a_url() -> None:
    with pytest.raises(RuntimeError, match="CHIA_PRIMARY_REQUIRED"):
        validate_server_hardening_at_startup(
            _staging(chia_primary_required=True)
        )


def test_staging_chia_primary_requires_https_and_complete_mtls() -> None:
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        validate_server_hardening_at_startup(
            _staging(chia_primary_url="http://127.0.0.1:8555")
        )

    with pytest.raises(RuntimeError, match="requires reviewed mTLS"):
        validate_server_hardening_at_startup(
            _staging(chia_primary_url="https://127.0.0.1:8555")
        )

    validate_server_hardening_at_startup(
        _staging(
            chia_primary_url="https://127.0.0.1:8555",
            chia_primary_required=True,
            chia_primary_ca_cert_path="/run/secrets/chia-ca.crt",
            chia_primary_client_cert_path="/run/secrets/chia-client.crt",
            chia_primary_client_key_path="/run/secrets/chia-client.key",
        )
    )


def test_chia_primary_rejects_partial_mtls_configuration() -> None:
    with pytest.raises(RuntimeError, match="requires CA, client certificate"):
        validate_server_hardening_at_startup(
            _staging(
                chia_primary_url="https://127.0.0.1:8555",
                chia_primary_ca_cert_path="/run/secrets/chia-ca.crt",
            )
        )


def test_staging_rejects_disabled_owner_plus_one_approvals() -> None:
    with pytest.raises(RuntimeError, match="ADMIN_OPERATION_APPROVALS_ENABLED"):
        validate_server_hardening_at_startup(
            _staging(admin_operation_approvals_enabled=False)
        )


def test_omnichain_enablement_requires_reviewed_evidence_at_startup() -> None:
    with pytest.raises(RuntimeError, match="requires valid reviewed"):
        validate_server_hardening_at_startup(
            _staging(
                payment_omnichain_enabled=True,
                payment_omnichain_ingest_token="test-only-relayer-token-value-32",
                payment_evm_usdc_tokens={"84532": "0x" + "ab" * 20},
                payment_omnichain_source_sha="a" * 40,
                payment_omnichain_gateway_profile="bse",
                payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
            )
        )


@pytest.mark.parametrize("rpc_url", [None, "", "http://base-sepolia.example.invalid"])
def test_omnichain_enablement_requires_https_rpc(rpc_url: str | None) -> None:
    with pytest.raises(RuntimeError, match="requires an HTTPS.*RPC_URL"):
        validate_server_hardening_at_startup(
            _staging(
                payment_omnichain_enabled=True,
                payment_omnichain_ingest_token="test-only-relayer-token-value-32",
                payment_evm_usdc_tokens={"84532": "0x" + "ab" * 20},
                payment_omnichain_source_sha="a" * 40,
                payment_omnichain_gateway_profile="bse",
                payment_omnichain_rpc_url=rpc_url,
            )
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bootstrap_cookie_secure", False, "COOKIE_SECURE"),
        ("api_docs_enabled", True, "API_DOCS_ENABLED"),
        ("security_headers_enabled", False, "Security headers"),
        ("hsts_enabled", False, "Security headers"),
        ("vault_session_cookie_secure", False, "VAULT_SESSION_COOKIE_SECURE"),
        ("cors_origins", "http://localhost:4200", "CORS origins"),
        ("cors_origins", "*", "CORS origins"),
    ],
)
def test_staging_rejects_insecure_server_posture(
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        validate_server_hardening_at_startup(_staging(**{field: value}))


@pytest.mark.asyncio
async def test_security_headers_cover_success_and_error_responses() -> None:
    transport = httpx.ASGITransport(app=_app(_staging()))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        success = await client.get("/ok")
        missing = await client.get("/missing")

    for response in (success, missing):
        assert response.headers["strict-transport-security"].startswith("max-age=31536000")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_request_body_over_limit_is_rejected_before_routing() -> None:
    settings = _staging(max_request_body_bytes=16)
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.post("/echo", content=b"x" * 17)

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds the configured limit."}
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_chunked_request_body_cannot_bypass_limit() -> None:
    async def body_chunks():
        yield b"x" * 8
        yield b"y" * 9

    settings = _staging(max_request_body_bytes=16)
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.post("/echo", content=body_chunks())

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body exceeds the configured limit."}


@pytest.mark.asyncio
async def test_request_timeout_returns_bounded_gateway_timeout() -> None:
    settings = _staging(request_timeout_seconds=0.01)
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        response = await client.get("/slow")

    assert response.status_code == 504
    assert response.json() == {"detail": "Request processing timed out."}
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_pending_admin_recovery_freezes_privileged_mutations(
    tmp_path,
) -> None:
    database = tmp_path / "genesis.sqlite3"
    settings = _staging(genesis_db_path=str(database))
    store = GenesisStore(database)
    ceremony_id = "0x" + "11" * 32
    now = int(time.time())
    store.create_draft(
        ceremony_id,
        {"network": "testnet11"},
        now=now,
    )
    store.create_recovery_case(
        ceremony_id,
        case_id="case-freeze",
        authority_slot=0,
        kind="ROUTINE",
        intent_hash="0x" + "22" * 32,
        intent={"schemaVersion": 1, "slot": 0},
        execute_after=now + 86_400,
        expires_at=now + 172_800,
        prepared_by="0x" + "33" * 20,
        now=now,
    )

    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://test",
    ) as client:
        blocked = await client.post("/admin/change")
        recovery = await client.post(
            "/admin/security/key-changes/case-freeze/evm/observe"
        )
        login = await client.post("/admin/auth/login")

    assert blocked.status_code == 423
    assert "Security & Access" in blocked.json()["detail"]
    assert recovery.status_code == 404
    assert login.status_code == 404


def test_development_may_opt_into_http_cookie_and_docs() -> None:
    validate_server_hardening_at_startup(
        Settings(
            runtime_environment="development",
            bootstrap_cookie_secure=False,
            api_docs_enabled=True,
            cors_origins="http://localhost:4200",
        )
    )


def test_staging_write_mode_rejects_single_validator_policy() -> None:
    with pytest.raises(RuntimeError, match="VALIDATOR_THRESHOLD"):
        validate_server_hardening_at_startup(
            _staging(
                alpha_writes_enabled=True,
                zkpassport_validator_threshold=1,
            )
        )


def test_staging_write_mode_rejects_validator_outside_fixed_wireguard_topology() -> None:
    with pytest.raises(RuntimeError, match="WireGuard signer topology"):
        validate_server_hardening_at_startup(
            _staging(
                alpha_writes_enabled=True,
                zkpassport_validator_urls=[
                    "https://validator-0.example.com",
                    "https://10.77.0.11:9443",
                    "https://10.77.0.12:9443",
                ],
            )
        )


def test_read_only_staging_accepts_single_validator_default() -> None:
    validate_server_hardening_at_startup(
        _staging(alpha_writes_enabled=False, zkpassport_validator_threshold=1)
    )


def test_http_posture_does_not_accept_mutable_authority_coordinates() -> None:
    validate_server_hardening_at_startup(
        _staging(
            alpha_writes_enabled=True,
            zkpassport_validator_threshold=2,
        )
    )


def test_ceremony_mode_requires_locked_minting_token_and_same_origin() -> None:
    validate_server_hardening_at_startup(
        _staging(
            alpha_writes_enabled=True,
            ceremony_mode_enabled=True,
            zkpassport_validator_threshold=2,
            admin_token="one-time-token",
            cors_origins="",
        )
    )

    with pytest.raises(RuntimeError, match="cannot configure CORS"):
        validate_server_hardening_at_startup(
            _staging(
                alpha_writes_enabled=True,
                ceremony_mode_enabled=True,
                zkpassport_validator_threshold=2,
                admin_token="one-time-token",
            )
        )


def test_minting_cannot_be_enabled_while_alpha_writes_are_locked() -> None:
    with pytest.raises(RuntimeError, match="MINTING_ENABLED"):
        validate_server_hardening_at_startup(
            _staging(minting_enabled=True, alpha_writes_enabled=False)
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"alpha_writes_enabled": False, "minting_enabled": False},
            "requires alpha writes and minting",
        ),
        (
            {
                "alpha_writes_enabled": True,
                "minting_enabled": True,
                "network": "mainnet",
            },
            "restricted to testnet11",
        ),
        (
            {"alpha_writes_enabled": True, "minting_enabled": True},
            "requires a signer URL",
        ),
        (
            {
                "alpha_writes_enabled": True,
                "minting_enabled": True,
                "kos_mint_execute_signer_url": "http://kos.internal",
            },
            "must use HTTPS",
        ),
        (
            {
                "alpha_writes_enabled": True,
                "minting_enabled": True,
                "kos_mint_execute_signer_url": "https://kos.internal",
            },
            "requires CA, client certificate, and client key paths",
        ),
    ],
)
def test_kos_mint_execute_signer_fails_closed_without_testnet_mtls(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(RuntimeError, match=message):
        validate_server_hardening_at_startup(
            _staging(kos_mint_execute_signer_enabled=True, **overrides)
        )


def test_kos_mint_execute_signer_accepts_the_complete_testnet_posture() -> None:
    validate_server_hardening_at_startup(
        _staging(
            alpha_writes_enabled=True,
            minting_enabled=True,
            zkpassport_validator_threshold=2,
            kos_mint_execute_signer_enabled=True,
            kos_mint_execute_signer_url="https://kos.testnet.internal",
            kos_mint_execute_signer_mtls_ca_path="/run/secrets/kos-ca.pem",
            kos_mint_execute_signer_mtls_cert_path="/run/secrets/api-kos-cert.pem",
            kos_mint_execute_signer_mtls_key_path="/run/secrets/api-kos-key.pem",
        )
    )


@pytest.mark.asyncio
async def test_challenge_limiter_counts_valid_and_invalid_requests() -> None:
    settings = Settings(
        runtime_environment="test",
        challenge_per_ip_per_minute=3,
    )
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        invalid = await client.post("/auth/challenge", json={})
        valid_one = await client.post(
            "/auth/challenge",
            json={"address": "0x1111111111111111111111111111111111111111"},
        )
        valid_two = await client.post(
            "/auth/challenge",
            json={"address": "0x2222222222222222222222222222222222222222"},
        )
        limited = await client.post("/auth/challenge", json={})

    assert invalid.status_code == 422
    assert valid_one.status_code == 200
    assert valid_two.status_code == 200
    assert limited.status_code == 429
    assert limited.json() == {"detail": "Too many challenge requests. Try again later."}
    assert limited.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_challenge_limiter_ignores_spoofed_forwarding_headers() -> None:
    settings = Settings(
        runtime_environment="test",
        challenge_per_ip_per_minute=1,
    )
    transport = httpx.ASGITransport(app=_app(settings), client=("203.0.113.9", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        first = await client.post(
            "/auth/challenge",
            json={"address": "first"},
            headers={"X-Forwarded-For": "198.51.100.1"},
        )
        second = await client.post(
            "/auth/challenge",
            json={"address": "second"},
            headers={"X-Forwarded-For": "198.51.100.2"},
        )

    assert first.status_code == 200
    assert second.status_code == 429


@pytest.mark.asyncio
async def test_chia_push_limiter_bounds_public_transaction_relay() -> None:
    settings = Settings(
        runtime_environment="test",
        chia_push_per_ip_per_minute=2,
    )
    transport = httpx.ASGITransport(app=_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        first = await client.post("/chia/push_tx", json={})
        second = await client.post("/chia/push_tx", json={})
        limited = await client.post("/chia/push_tx", json={})

    assert first.status_code == second.status_code == 200
    assert limited.status_code == 429
    assert limited.json() == {
        "detail": "Too many Chia transaction submissions. Try again later."
    }


def test_persistent_challenge_limiter_is_atomic_across_workers(tmp_path) -> None:
    path = tmp_path / "shared" / "challenges.db"
    workers = [
        RequestRateLimiter(25, db_path=path),
        RequestRateLimiter(25, db_path=path),
    ]

    def attempt(index: int) -> bool:
        return workers[index % len(workers)].allow("198.51.100.44")

    with ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(attempt, range(200)))

    assert sum(results) == 25
    assert results.count(False) == 175


def test_deployed_challenge_store_requires_absolute_shared_path(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="absolute shared-state path"):
        preflight_challenge_storage(
            _staging(challenge_store_path="./state/challenges_v2.db")
        )

    absolute_path = tmp_path / "shared" / "challenges_v2.db"
    preflight_challenge_storage(
        _staging(challenge_store_path=str(absolute_path))
    )
    assert absolute_path.is_file()


def test_client_ip_accepts_cloudflare_header_only_from_trusted_peer() -> None:
    settings = Settings(trusted_proxy_cidrs="203.0.113.0/24")
    trusted_scope = {
        "client": ("203.0.113.9", 443),
        "headers": [(b"cf-connecting-ip", b"198.51.100.44")],
    }
    direct_scope = {
        "client": ("192.0.2.9", 443),
        "headers": [(b"cf-connecting-ip", b"198.51.100.44")],
    }
    assert trusted_client_ip(trusted_scope, settings) == "198.51.100.44"
    assert trusted_client_ip(direct_scope, settings) == "192.0.2.9"


@pytest.mark.parametrize(
    "headers",
    [
        [(b"cf-connecting-ip", b"not-an-ip")],
        [
            (b"cf-connecting-ip", b"198.51.100.1"),
            (b"cf-connecting-ip", b"198.51.100.2"),
        ],
    ],
)
def test_client_ip_falls_back_to_proxy_for_ambiguous_header(headers) -> None:
    settings = Settings(trusted_proxy_cidrs="203.0.113.0/24")
    assert (
        trusted_client_ip(
            {"client": ("203.0.113.9", 443), "headers": headers}, settings
        )
        == "203.0.113.9"
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("eip712_chain_id", 1, "SOLSLOT_EIP712_CHAIN_ID"),
        (
            "zkpassport_evm_chain_id",
            1,
            "SOLSLOT_ZKPASSPORT_EVM_CHAIN_ID",
        ),
    ],
)
def test_testnet11_rejects_mainnet_evm_chain_ids(
    field: str,
    value: int,
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        validate_server_hardening_at_startup(_staging(**{field: value}))


def test_mainnet_rejects_sepolia_eip712_domain() -> None:
    with pytest.raises(RuntimeError, match="SOLSLOT_EIP712_CHAIN_ID"):
        validate_server_hardening_at_startup(
            _staging(
                runtime_environment="production",
                network="mainnet",
                zkpassport_validator_threshold=2,
                zkpassport_evm_chain_id=1,
            )
        )


def test_documentation_urls_are_disabled_when_not_explicitly_enabled() -> None:
    assert documentation_urls(Settings(api_docs_enabled=False)) == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }
    assert documentation_urls(_staging()) == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_development_documentation_requires_explicit_opt_in() -> None:
    assert documentation_urls(
        Settings(runtime_environment="development", api_docs_enabled=True)
    ) == {
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json",
    }
