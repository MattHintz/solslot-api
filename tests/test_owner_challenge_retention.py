from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest
from chia_rs.sized_bytes import bytes32
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys
from fastapi import FastAPI

from solslot_api import credential_ledger, zkpassport_enrollments
from solslot_api.config import Settings
from solslot_api.credential_ledger import (
    CredentialLedger, LedgerConflict, LedgerError, LedgerRateLimited,
    reset_credential_ledgers_for_tests,
)
from solslot_api.server_hardening import ServerHardeningMiddleware
from solslot_api.state import VaultRecord, reset_registry_for_tests
from solslot_puzzles.vault_driver import AUTH_TYPE_SECP256K1


VAULT = "0x" + "11" * 32
KEY = bytes.fromhex("01" * 32)  # Deterministic test-only signing key.
ACCOUNT = Account.from_key(KEY)
ROUTE = f"/zkpassport/enrollments/{VAULT}/session/challenge"


@pytest.fixture(autouse=True)
def reset_ledgers():
    reset_credential_ledgers_for_tests()
    yield
    reset_credential_ledgers_for_tests()


def row_count(path):
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT COUNT(*) FROM owner_challenges").fetchone()[0]


def issue(ledger, **overrides):
    return ledger.issue_owner_challenge(**{
        "vault_launcher_id": VAULT, "action": "session_login", "payload_hash": "0x" + "22" * 32,
        "auth_type": "evm", "ttl_seconds": 300, **overrides,
    })


def app_fixture(tmp_path, monkeypatch, **overrides):
    settings = Settings(_env_file=None, **{
        "runtime_environment": "test", "alpha_writes_enabled": True, "network": "testnet11",
        "zkpassport_ledger_db_path": str(tmp_path / "credential.db"),
        "vault_session_jwt_secret": "test-owner-session-secret-" * 2,
        **overrides,
    })
    registry = reset_registry_for_tests(tmp_path / "vault.db")
    registry.record(VaultRecord(
        launcher_id=bytes32.fromhex(VAULT[2:]), full_puzhash=bytes32(b"\x33" * 32),
        p2_vault_puzhash=bytes32(b"\x44" * 32), auth_type=AUTH_TYPE_SECP256K1,
        owner_pubkey=keys.PrivateKey(KEY).public_key.to_compressed_bytes(),
        owner_evm_address=ACCOUNT.address, spend_bundle_id="0x" + "55" * 32, pushed_at=time.time(),
    ))
    monkeypatch.setattr(zkpassport_enrollments, "_settings", lambda: settings)
    app = FastAPI()
    app.include_router(zkpassport_enrollments.router)
    app.add_middleware(ServerHardeningMiddleware, settings=settings)
    return app, settings


@pytest.mark.asyncio
async def test_public_owner_challenge_requests_use_existing_ip_limit(tmp_path, monkeypatch):
    app, settings = app_fixture(tmp_path, monkeypatch, challenge_per_ip_per_minute=2)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
        responses = [await client.post(ROUTE) for _ in range(3)]
    assert [response.status_code for response in responses] == [200, 200, 429]
    assert row_count(settings.zkpassport_ledger_db_path) == 2


@pytest.mark.asyncio
async def test_owner_challenge_issuance_honors_configured_shared_store_capacity(tmp_path, monkeypatch):
    app, settings = app_fixture(tmp_path, monkeypatch, challenge_per_ip_per_minute=100,
                                challenge_store_max_pending=2)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
        responses = [await client.post(ROUTE) for _ in range(3)]
    assert [response.status_code for response in responses] == [200, 200, 429]
    assert row_count(settings.zkpassport_ledger_db_path) == 2


def test_expired_challenges_are_cleaned_after_restart(tmp_path, monkeypatch):
    now = [1_800_000_000]
    monkeypatch.setattr(credential_ledger.time, "time", lambda: now[0])
    path = tmp_path / "restart.db"
    ledger = CredentialLedger(path)
    challenge = issue(ledger)
    ledger.close()
    now[0] += 301
    reopened = CredentialLedger(path)
    try:
        assert row_count(path) == 0
        assert reopened.get_owner_challenge(challenge.challenge_id) is None
    finally:
        reopened.close()


def consume(ledger, challenge):
    return ledger.consume_owner_challenge(challenge_id=challenge.challenge_id, vault_launcher_id=VAULT,
                                          action=challenge.action, payload_hash=challenge.payload_hash)


def test_retention_preserves_live_and_consumed_rows_through_exact_signed_expiry(tmp_path, monkeypatch):
    now = [1_800_000_000]
    monkeypatch.setattr(credential_ledger.time, "time", lambda: now[0])
    path = tmp_path / "boundary.db"
    ledger = CredentialLedger(path)
    consumed = issue(ledger, max_pending=2)
    live = issue(ledger, max_pending=2)
    consume(ledger, consumed)
    now[0] = live.expires_at
    ledger.close()
    ledger = CredentialLedger(path)
    try:
        assert row_count(path) == 2
        with pytest.raises(LedgerRateLimited):
            issue(ledger, max_pending=2)
        with pytest.raises(LedgerConflict, match="consumed"):
            consume(ledger, consumed)
        assert consume(ledger, live) == live  # Preserve the existing inclusive second boundary.
        now[0] += 1
        fresh = issue(ledger, max_pending=2)
        assert row_count(path) == 1
        assert ledger.get_owner_challenge(fresh.challenge_id) == fresh
        for prior in (live, consumed):
            with pytest.raises(LedgerConflict, match="unknown"):
                consume(ledger, prior)
    finally:
        ledger.close()


def test_capacity_is_atomic_across_independent_worker_connections_and_restart(tmp_path):
    path = tmp_path / "workers.db"
    CredentialLedger(path).close()
    # Every attempt opens its own SQLite connection/lock, as separate workers
    # do. A Python lock on one CredentialLedger object cannot satisfy this test.
    def attempt(_):
        ledger = CredentialLedger(path)
        try:
            try:
                return issue(ledger, max_pending=5)
            except LedgerRateLimited:
                return None
        finally:
            ledger.close()
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt, range(24)))
    accepted = [result for result in results if result is not None]
    assert len(accepted) == 5
    assert len({challenge.challenge_id for challenge in accepted}) == 5
    assert row_count(path) == 5
    reopened = CredentialLedger(path)
    try:
        with pytest.raises(LedgerRateLimited):
            issue(reopened, max_pending=5)
        for challenge in accepted:
            assert reopened.get_owner_challenge(challenge.challenge_id) == challenge
        assert consume(reopened, accepted[0]) == accepted[0]
    finally:
        reopened.close()


def test_cleanup_commits_at_lowered_capacity_without_evicting_live_challenges(tmp_path, monkeypatch):
    now = [1_800_000_000]
    monkeypatch.setattr(credential_ledger.time, "time", lambda: now[0])
    path = tmp_path / "lowered-capacity.db"
    ledger = CredentialLedger(path)
    try:
        issue(ledger, ttl_seconds=1)
        live = [issue(ledger) for _ in range(3)]
        now[0] += 2
        with pytest.raises(LedgerRateLimited):
            issue(ledger, max_pending=2)
        assert row_count(path) == 3
        assert all(ledger.get_owner_challenge(challenge.challenge_id) for challenge in live)
        assert consume(ledger, live[0]) == live[0]
    finally:
        ledger.close()


@pytest.mark.parametrize("overrides", [{"ttl_seconds": 0}, {"ttl_seconds": 901},
                                      {"ttl_seconds": 1.5}, {"max_pending": 0}, {"max_pending": True}])
def test_direct_issuance_cannot_disable_retention_or_capacity(tmp_path, overrides):
    path = tmp_path / "invalid-bounds.db"
    ledger = CredentialLedger(path)
    try:
        with pytest.raises(LedgerError):
            issue(ledger, **overrides)
        assert row_count(path) == 0
    finally:
        ledger.close()


@pytest.mark.asyncio
async def test_limiter_counts_bad_vaults_aliases_relay_and_spoofed_forwarding_headers(tmp_path, monkeypatch):
    app, settings = app_fixture(tmp_path, monkeypatch, challenge_per_ip_per_minute=3)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
        invalid = await client.post("/zkpassport/enrollments/not-a-vault/session/challenge")
        redirect = await client.post(ROUTE + "/", follow_redirects=False)
        relay = await client.post(f"/zkpassport/enrollments/{VAULT}/relay/challenge", json={})
        limited = await client.post(ROUTE, headers={"X-Forwarded-For": "198.51.100.19"})
    assert invalid.status_code == 422
    assert redirect.status_code == 307
    assert relay.status_code == 422
    assert limited.status_code == 429
    assert not Path(settings.zkpassport_ledger_db_path).exists()


@pytest.mark.asyncio
async def test_closed_alpha_and_unknown_vault_still_cannot_issue_challenges(tmp_path, monkeypatch):
    app, settings = app_fixture(tmp_path, monkeypatch, alpha_writes_enabled=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
        closed = await client.post(ROUTE)
        settings.alpha_writes_enabled = True
        unknown = await client.post(f"/zkpassport/enrollments/{'99' * 32}/session/challenge")
    assert closed.status_code == 503
    assert unknown.status_code == 404
    assert not Path(settings.zkpassport_ledger_db_path).exists()


@pytest.mark.asyncio
async def test_real_owner_login_survives_retention_and_old_signature_never_replays(tmp_path, monkeypatch):
    now = [int(time.time())]
    monkeypatch.setattr(credential_ledger.time, "time", lambda: now[0])
    app, settings = app_fixture(tmp_path, monkeypatch, challenge_per_ip_per_minute=100)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
        challenge = (await client.post(ROUTE)).json()
        signed = Account.sign_message(encode_typed_data(full_message=challenge["typedData"]), KEY)
        auth = {"ownerAuth": {"challengeId": challenge["challengeId"], "signature": signed.signature.hex()}}
        assert (await client.post(ROUTE.removesuffix("/challenge"), json=auth)).status_code == 200
        reset_credential_ledgers_for_tests()
        assert (await client.post(ROUTE.removesuffix("/challenge"), json=auth)).status_code == 409
        now[0] = challenge["expiresAt"] + 1
        reset_credential_ledgers_for_tests()
        assert (await client.post(ROUTE.removesuffix("/challenge"), json=auth)).status_code == 409
        assert row_count(settings.zkpassport_ledger_db_path) == 0
        fresh = (await client.post(ROUTE)).json()
        stale_signature = {"ownerAuth": {"challengeId": fresh["challengeId"], "signature": signed.signature.hex()}}
        assert (await client.post(ROUTE.removesuffix("/challenge"), json=stale_signature)).status_code == 403
        fresh_signature = Account.sign_message(encode_typed_data(full_message=fresh["typedData"]), KEY)
        fresh_auth = {"ownerAuth": {"challengeId": fresh["challengeId"], "signature": fresh_signature.signature.hex()}}
        assert (await client.post(ROUTE.removesuffix("/challenge"), json=fresh_auth)).status_code == 200


def test_owner_retention_does_not_prune_enrollment_or_bridge_replay_records(tmp_path, monkeypatch):
    now = [1_800_000_000]
    monkeypatch.setattr(credential_ledger.time, "time", lambda: now[0])
    path = tmp_path / "permanent-records.db"
    ledger = CredentialLedger(path)
    bridge = "0x" + "66" * 32
    enrollment = {"vaultLauncherId": VAULT, "bridgeCoinId": bridge, "network": "testnet11",
                  "policyVersion": 2, "status": "reserved"}
    ledger.reserve_enrollment(record=enrollment, owner_key=ACCOUNT.address)
    issue(ledger)
    ledger.close()
    now[0] += 1000
    reopened = CredentialLedger(path)
    try:
        assert row_count(path) == 0
        assert reopened.get_enrollment(VAULT) == enrollment
        with pytest.raises(LedgerConflict):
            reopened.reserve_enrollment(record={**enrollment, "vaultLauncherId": "0x" + "88" * 32},
                                        owner_key="another-owner")
    finally:
        reopened.close()
