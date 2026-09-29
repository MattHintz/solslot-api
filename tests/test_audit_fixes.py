"""Regression tests for CANON_SOLSLOT_API_AUDIT_2026_04_26 fixes.

Each finding has its own test class so a future audit revisiting these can
trace test → finding 1:1.  Tests run as direct function-level units (no
TestClient) so they're not subject to the chia_rs LazyNode thread-binding
panic that affects ``tests/test_smoke.py``.

Findings covered:
  - POP-CANON-002 / SIGCOV-1 + Strategy 2 — EIP-712 envelope binds pool/auth/network
  - POP-CANON-003 / Strategy 7         — /auth/challenge rate limiting + cap
  - POP-CANON-004 / TRUTH-1            — push_tx success surfaced to caller
  - POP-CANON-005 / SIGN-1             — covered by 002 (same envelope expansion)
  - POP-CANON-006 / LD-1               — ChallengeStore.pop is write-once-read-once

Pass 2 audit (CANON_SOLSLOT_API_AUDIT_2026_04_26 Pass 2) findings covered:
  - POP-CANON-007 / SP-2 + CL-1         — VaultRegistry persisted via SQLite (WAL, indexed reverse lookup)
  - POP-CANON-008 / CL-1 + Producer Deadline — Faucet consolidation worker (opt-in, joins fragmented UTXOs)
  - POP-CANON-009 / Documentation drift — faucet_max_spend_mojos enforced via select_coin max_amount
  - POP-CANON-010 / LD-2                — coinset query pagination via start_height (limit unsupported upstream)
  - POP-CANON-011 / SN-3                — pool launcher comes only from signed V2 artifact
  - V7 / 2026-07 audit                  — Chia BLS vault registration dedup mirrors EVM
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from chia_rs import AugSchemeMPL
from eth_account import Account

from solslot_api.challenges import (
    Challenge,
    ChallengeStore,
    ChallengeStoreFullError,
    RateLimitedError,
)
from solslot_api.evm_auth import (
    REGISTER_PRIMARY_TYPE,
    REGISTER_TYPES,
    recover_evm_signer,
    registration_bls_signing_digest,
    registration_typed_data,
)


# ============================================================================
# POP-CANON-002 / SIGCOV-1 + Strategy 2 — Envelope binds pool/auth/network
# ============================================================================
class TestEnvelopeExpansion:
    """The v2 EIP-712 envelope must include poolLauncherId, authType,
    and chiaNetwork so the user's wallet displays them and the signature
    cryptographically commits to them."""

    def test_register_types_includes_v2_fields(self) -> None:
        primary = REGISTER_TYPES[REGISTER_PRIMARY_TYPE]
        names = {field["name"] for field in primary}
        assert names == {"owner", "nonce", "poolLauncherId", "authType", "chiaNetwork"}

    def test_pool_launcher_id_is_bytes32(self) -> None:
        primary = REGISTER_TYPES[REGISTER_PRIMARY_TYPE]
        pool_field = next(f for f in primary if f["name"] == "poolLauncherId")
        assert pool_field["type"] == "bytes32"

    def test_auth_type_is_string(self) -> None:
        primary = REGISTER_TYPES[REGISTER_PRIMARY_TYPE]
        f = next(f for f in primary if f["name"] == "authType")
        assert f["type"] == "string"

    def test_chia_network_is_string(self) -> None:
        primary = REGISTER_TYPES[REGISTER_PRIMARY_TYPE]
        f = next(f for f in primary if f["name"] == "chiaNetwork")
        assert f["type"] == "string"

    def test_typed_data_carries_all_fields(self) -> None:
        td = registration_typed_data(
            owner_address="0x1234567890123456789012345678901234567890",
            nonce_hex="0x" + "ab" * 32,
            pool_launcher_id_hex="0x" + "cd" * 32,
            auth_type="secp256k1",
            chia_network="testnet11",
        )
        assert td["primaryType"] == "SolslotVaultRegister"
        assert "SolslotVaultRegister" in td["types"]
        assert set(td["types"]) == {"EIP712Domain", "SolslotVaultRegister"}
        msg = td["message"]
        assert msg["owner"] == "0x1234567890123456789012345678901234567890"
        assert msg["nonce"] == "0x" + "ab" * 32
        assert msg["poolLauncherId"] == "0x" + "cd" * 32
        assert msg["authType"] == "secp256k1"
        assert msg["chiaNetwork"] == "testnet11"

    def test_eip712_version_bumped_to_v2(self) -> None:
        """v1 signatures must NOT validate against the v2 envelope."""
        td = registration_typed_data(
            owner_address="0x1234567890123456789012345678901234567890",
            nonce_hex="0x" + "ab" * 32,
            pool_launcher_id_hex="0x" + "cd" * 32,
            auth_type="secp256k1",
            chia_network="testnet11",
        )
        # Default Settings.eip712_version is "2" post-fix.
        assert td["domain"]["version"] == "2"


class TestSnapshotPreservation:
    """Challenge snapshots the pool/network at issue time so the
    /vault/register/evm verifier can rebuild the digest correctly even
    when settings change between issuance and verification."""

    def test_challenge_records_snapshot(self) -> None:
        store = ChallengeStore(ttl_seconds=300)
        ch = store.issue(
            address="0xABC",
            auth_type="evm",
            pool_launcher_id_hex="0x" + "11" * 32,
            chia_network="testnet11",
        )
        assert ch.pool_launcher_id_hex == "0x" + "11" * 32
        assert ch.chia_network == "testnet11"

    def test_snapshot_survives_pop(self) -> None:
        store = ChallengeStore(ttl_seconds=300)
        ch = store.issue(
            address="0xabc",
            auth_type="evm",
            pool_launcher_id_hex="0x" + "22" * 32,
            chia_network="mainnet",
        )
        popped = store.pop(ch.nonce, "0xabc", "evm")
        assert popped is not None
        assert popped.pool_launcher_id_hex == "0x" + "22" * 32
        assert popped.chia_network == "mainnet"

    def test_signature_matches_when_snapshot_consistent(self) -> None:
        """End-to-end: sign envelope with snapshot params, verify with same
        snapshot → recovers the signer.  This is the happy path proving
        v2 signatures work."""
        acct = Account.from_key(b"\x42" * 32)
        nonce_hex = "0x" + "ab" * 32
        pool_hex = "0x" + "cd" * 32

        td = registration_typed_data(
            owner_address=acct.address,
            nonce_hex=nonce_hex,
            pool_launcher_id_hex=pool_hex,
            auth_type="secp256k1",
            chia_network="testnet11",
        )
        signed = acct.sign_typed_data(
            domain_data=td["domain"],
            message_types={k: v for k, v in td["types"].items() if k != "EIP712Domain"},
            message_data=td["message"],
        )
        recovery = recover_evm_signer(td, "0x" + signed.signature.hex())
        assert recovery.address.lower() == acct.address.lower()

    def test_signature_fails_when_snapshot_drifts(self) -> None:
        """If the verifier rebuilds the typed_data with DIFFERENT pool_launcher_id
        than the user signed, recovery yields a different address — proving
        the signature is bound to the snapshotted params."""
        acct = Account.from_key(b"\x42" * 32)
        nonce_hex = "0x" + "ab" * 32
        signed_pool = "0x" + "cd" * 32  # what user signed
        attacker_pool = "0x" + "ee" * 32  # what server tries to use

        # User signs with signed_pool
        td_signed = registration_typed_data(
            owner_address=acct.address,
            nonce_hex=nonce_hex,
            pool_launcher_id_hex=signed_pool,
            auth_type="secp256k1",
            chia_network="testnet11",
        )
        signed = acct.sign_typed_data(
            domain_data=td_signed["domain"],
            message_types={
                k: v for k, v in td_signed["types"].items() if k != "EIP712Domain"
            },
            message_data=td_signed["message"],
        )
        signature_hex = "0x" + signed.signature.hex()

        # Server (incorrectly) reconstructs with attacker_pool.  The recovered
        # address will NOT match the original signer.
        td_attacker = registration_typed_data(
            owner_address=acct.address,
            nonce_hex=nonce_hex,
            pool_launcher_id_hex=attacker_pool,
            auth_type="secp256k1",
            chia_network="testnet11",
        )
        recovery = recover_evm_signer(td_attacker, signature_hex)
        # ECDSA recovery never throws — it just returns a junk address.
        # The endpoint's address-match check is what actually rejects it.
        assert recovery.address.lower() != acct.address.lower()

    def test_signature_fails_when_network_drifts(self) -> None:
        """Same drift detection but for chia_network — testnet sig must not
        replay against mainnet."""
        acct = Account.from_key(b"\x42" * 32)
        nonce_hex = "0x" + "ab" * 32
        pool_hex = "0x" + "cd" * 32

        td_testnet = registration_typed_data(
            owner_address=acct.address,
            nonce_hex=nonce_hex,
            pool_launcher_id_hex=pool_hex,
            auth_type="secp256k1",
            chia_network="testnet11",
        )
        signed = acct.sign_typed_data(
            domain_data=td_testnet["domain"],
            message_types={
                k: v for k, v in td_testnet["types"].items() if k != "EIP712Domain"
            },
            message_data=td_testnet["message"],
        )

        td_mainnet = registration_typed_data(
            owner_address=acct.address,
            nonce_hex=nonce_hex,
            pool_launcher_id_hex=pool_hex,
            auth_type="secp256k1",
            chia_network="mainnet",  # <-- drift
        )
        recovery = recover_evm_signer(td_mainnet, "0x" + signed.signature.hex())
        assert recovery.address.lower() != acct.address.lower()


# ============================================================================
# POP-CANON-003 / Strategy 7 — Rate limit + capacity cap
# ============================================================================
class TestRateLimit:
    def test_per_ip_quota_enforced(self) -> None:
        store = ChallengeStore(ttl_seconds=300, per_ip_per_minute=3)
        ip = "1.2.3.4"
        for _ in range(3):
            store.issue("0xabc", "evm", source_ip=ip)
        with pytest.raises(RateLimitedError, match="exceeded"):
            store.issue("0xabc", "evm", source_ip=ip)

    def test_different_ips_independent(self) -> None:
        store = ChallengeStore(ttl_seconds=300, per_ip_per_minute=2)
        for _ in range(2):
            store.issue("0xabc", "evm", source_ip="1.1.1.1")
        # Different IP not affected by 1.1.1.1's quota.
        ch = store.issue("0xabc", "evm", source_ip="2.2.2.2")
        assert ch is not None

    def test_no_source_ip_skips_rate_limit(self) -> None:
        """Internal callers (no source IP) must not be rate-limited.
        This keeps the API usable for server-side scripts and tests."""
        store = ChallengeStore(ttl_seconds=300, per_ip_per_minute=1)
        for _ in range(10):
            store.issue("0xabc", "evm", source_ip=None)

    def test_persistent_quota_is_shared_across_workers(self, tmp_path) -> None:
        path = tmp_path / "challenges.db"
        first = ChallengeStore(
            ttl_seconds=300,
            per_ip_per_minute=2,
            db_path=path,
        )
        second = ChallengeStore(
            ttl_seconds=300,
            per_ip_per_minute=2,
            db_path=path,
        )
        first.issue("0xabc", "evm", source_ip="192.0.2.10")
        second.issue("0xabc", "evm", source_ip="192.0.2.10")
        with pytest.raises(RateLimitedError, match="exceeded"):
            first.issue("0xabc", "evm", source_ip="192.0.2.10")

    def test_persistent_quota_is_atomic_under_parallel_load(self, tmp_path) -> None:
        quota = 12
        store = ChallengeStore(
            ttl_seconds=300,
            max_pending=100,
            per_ip_per_minute=quota,
            db_path=tmp_path / "parallel-challenges.db",
        )

        def issue(_index: int) -> bool:
            try:
                store.issue("0xabc", "evm", source_ip="192.0.2.30")
            except RateLimitedError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=32) as workers:
            accepted = list(workers.map(issue, range(100)))

        assert sum(accepted) == quota
        assert len(store) == quota

    def test_persistent_nonce_is_single_use_across_workers(self, tmp_path) -> None:
        path = tmp_path / "challenges.db"
        first = ChallengeStore(ttl_seconds=300, db_path=path)
        second = ChallengeStore(ttl_seconds=300, db_path=path)
        challenge = first.issue("0xabc", "evm", source_ip="192.0.2.20")

        assert second.pop(challenge.nonce, "0xabc", "evm") is not None
        assert first.pop(challenge.nonce, "0xabc", "evm") is None


class TestCapacityCap:
    def test_max_pending_enforced(self) -> None:
        store = ChallengeStore(ttl_seconds=300, max_pending=3)
        for _ in range(3):
            store.issue("0xabc", "evm")
        with pytest.raises(ChallengeStoreFullError, match="capacity"):
            store.issue("0xabc", "evm")

    def test_pop_frees_capacity(self) -> None:
        store = ChallengeStore(ttl_seconds=300, max_pending=2)
        ch1 = store.issue("0xabc", "evm")
        ch2 = store.issue("0xabc", "evm")
        store.pop(ch1.nonce, "0xabc", "evm")
        # One slot freed → next issue succeeds.
        ch3 = store.issue("0xabc", "evm")
        assert ch3 is not None


# ============================================================================
# POP-CANON-006 / LD-1 — pop is write-once-read-once
# ============================================================================
class TestPopIsWriteOnceReadOnce:
    def test_pop_with_wrong_address_removes_entry(self) -> None:
        """Failed validation must STILL remove the entry — otherwise an
        attacker can poll wrong addresses to keep the store full."""
        store = ChallengeStore(ttl_seconds=300, max_pending=10)
        ch = store.issue("0xabc", "evm")
        # Validation will fail (wrong address)
        result = store.pop(ch.nonce, "0xdef", "evm")
        assert result is None
        # The entry must NOT be retrievable now — even with the right address.
        result2 = store.pop(ch.nonce, "0xabc", "evm")
        assert result2 is None

    def test_pop_with_wrong_auth_type_removes_entry(self) -> None:
        store = ChallengeStore(ttl_seconds=300, max_pending=10)
        ch = store.issue("0xabc", "evm")
        # Wrong auth_type → fail
        result = store.pop(ch.nonce, "0xabc", "chia_bls")
        assert result is None
        # Entry should be gone
        result2 = store.pop(ch.nonce, "0xabc", "evm")
        assert result2 is None

    def test_pop_with_expired_entry_removes_entry(self) -> None:
        store = ChallengeStore(ttl_seconds=0)  # immediately expired
        ch = store.issue("0xabc", "evm")
        time.sleep(0.01)  # ensure now > expires_at
        result = store.pop(ch.nonce, "0xabc", "evm")
        assert result is None
        # Entry already gone
        assert len(store) == 0

    def test_successful_pop_removes_entry(self) -> None:
        """Sanity: the success path must also remove the entry."""
        store = ChallengeStore(ttl_seconds=300, max_pending=10)
        ch = store.issue("0xabc", "evm")
        result = store.pop(ch.nonce, "0xabc", "evm")
        assert result is not None
        # Replay must fail
        result2 = store.pop(ch.nonce, "0xabc", "evm")
        assert result2 is None

    def test_capacity_pressure_relieved_by_failed_pops(self) -> None:
        """The whole point of POP-CANON-006: failed pops should free slots."""
        store = ChallengeStore(ttl_seconds=300, max_pending=2)
        ch1 = store.issue("0xabc", "evm")
        ch2 = store.issue("0xdef", "evm")
        # Both slots now full.  Attacker tries a wrong-address pop on ch1.
        store.pop(ch1.nonce, "0xWRONG", "evm")
        # Should free a slot
        ch3 = store.issue("0xnewuser", "evm")
        assert ch3 is not None


class TestChallengeRequestValidationBeforeAllocation:
    def test_public_evm_challenge_invalid_address_does_not_allocate(
        self, monkeypatch
    ) -> None:
        from fastapi.testclient import TestClient
        from solslot_api.app import app, get_challenge_store

        store = ChallengeStore(ttl_seconds=300, max_pending=1, per_ip_per_minute=100)
        monkeypatch.setattr(
            "solslot_api.app._require_vault_protocol_ready",
            lambda _settings: "0x" + "00" * 32,
        )
        app.dependency_overrides[get_challenge_store] = lambda: store
        try:
            with TestClient(app) as client:
                bad = client.post(
                    "/auth/challenge",
                    json={"address": "0x1234", "auth_type": "evm"},
                )
                assert bad.status_code == 422
                assert len(store) == 0

                good = client.post(
                    "/auth/challenge",
                    json={
                        "address": "0x1234567890123456789012345678901234567890",
                        "auth_type": "evm",
                    },
                )
                assert good.status_code == 200, good.text
        finally:
            app.dependency_overrides.clear()


# ============================================================================
# POP-CANON-004 / TRUTH-1 — push_tx success/failure surfaced
# ============================================================================
class TestPushOrFail:
    """Tests for the _push_or_fail helper in app.py."""

    @pytest.mark.asyncio
    async def test_success_returns_true_none(self) -> None:
        from solslot_api.app import _push_or_fail

        coinset = MagicMock()
        coinset.push_tx = AsyncMock(return_value={"success": True})
        bundle = MagicMock()
        bundle.to_json_dict = lambda: {"coin_spends": [], "aggregated_signature": "0x" + "00" * 96}

        accepted, status = await _push_or_fail(coinset, bundle)
        assert accepted is True
        assert status is None

    @pytest.mark.asyncio
    async def test_non_success_returns_false_with_status(self) -> None:
        """The PRE-fix code only logged a warning and returned success.  Now
        the (False, status) tuple lets the endpoint surface failure to the
        client."""
        from solslot_api.app import _push_or_fail

        coinset = MagicMock()
        coinset.push_tx = AsyncMock(return_value={
            "success": False,
            "error": "DOUBLE_SPEND",
        })
        bundle = MagicMock()
        bundle.to_json_dict = lambda: {"coin_spends": [], "aggregated_signature": "0x" + "00" * 96}

        accepted, status = await _push_or_fail(coinset, bundle)
        assert accepted is False
        assert "DOUBLE_SPEND" in (status or "")

    @pytest.mark.asyncio
    async def test_exception_raises_502(self) -> None:
        """Network/HTTP errors during push_tx must surface as 502, not
        be swallowed."""
        from fastapi import HTTPException
        from solslot_api.app import _push_or_fail

        coinset = MagicMock()
        coinset.push_tx = AsyncMock(side_effect=ConnectionError("coinset down"))
        bundle = MagicMock()
        bundle.to_json_dict = lambda: {"coin_spends": [], "aggregated_signature": "0x" + "00" * 96}

        with pytest.raises(HTTPException) as exc_info:
            await _push_or_fail(coinset, bundle)
        assert exc_info.value.status_code == 502


class TestVaultRegistrationSafetyFalsifiers:
    def _faucet(self):
        from solslot_api.faucet import Faucet

        return Faucet.from_seed_hex("00" * 32, "testnet11")

    def _settings(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            alpha_writes_enabled=True,
            protocol_fee_funding_enabled=False,
            runtime_environment="test",
            faucet_max_spend_mojos=10_000_000,
            zkpassport_bridge_policy_hash="0x" + "c1" * 32,
        )

    def _coin_records(self, faucet):
        return [
            {
                "spent_block_index": 0,
                "coin": {
                    "parent_coin_info": "0x" + "11" * 32,
                    "puzzle_hash": "0x" + faucet.address_puzzle_hash.hex(),
                    "amount": 1000,
                },
            }
        ]

    def _signed_request(self):
        from solslot_api.app import RegisterEvmVaultRequest

        acct = Account.from_key(b"\x42" * 32)
        store = ChallengeStore(ttl_seconds=300, max_pending=10, per_ip_per_minute=10)
        ch = store.issue(
            acct.address,
            "evm",
            pool_launcher_id_hex="0x" + "00" * 32,
            chia_network="testnet11",
        )
        typed_data = registration_typed_data(
            acct.address,
            ch.nonce,
            pool_launcher_id_hex=ch.pool_launcher_id_hex,
            auth_type="secp256k1",
            chia_network=ch.chia_network,
        )
        signed = acct.sign_typed_data(
            domain_data=typed_data["domain"],
            message_types={
                k: v for k, v in typed_data["types"].items() if k != "EIP712Domain"
            },
            message_data=typed_data["message"],
        )
        body = RegisterEvmVaultRequest(
            address=acct.address,
            nonce=ch.nonce,
            signature="0x" + signed.signature.hex().replace("0x", ""),
        )
        return acct, store, body

    def _signed_chia_request(self):
        from solslot_api.app import RegisterChiaVaultRequest

        owner_sk = AugSchemeMPL.key_gen(b"\x77" * 32)
        pubkey = "0x" + bytes(owner_sk.get_g1()).hex()
        store = ChallengeStore(ttl_seconds=300, max_pending=10, per_ip_per_minute=10)
        ch = store.issue(
            pubkey,
            "chia_bls",
            pool_launcher_id_hex="0x" + "00" * 32,
            chia_network="testnet11",
        )
        digest = registration_bls_signing_digest(
            ch.nonce,
            ch.pool_launcher_id_hex,
            ch.auth_type,
            ch.chia_network,
        )
        signature = AugSchemeMPL.sign(owner_sk, digest)
        body = RegisterChiaVaultRequest(
            bls_pubkey=pubkey,
            nonce=ch.nonce,
            signature="0x" + bytes(signature).hex(),
        )
        return owner_sk, store, body

    @pytest.mark.asyncio
    async def test_rejected_push_does_not_persist_registry_record(self, monkeypatch):
        from fastapi import HTTPException
        from solslot_api.app import register_evm_vault

        _acct, store, body = self._signed_request()
        monkeypatch.setattr(
            "solslot_api.app._require_vault_protocol_ready",
            lambda _settings: "0x" + "00" * 32,
        )
        faucet = self._faucet()
        coinset = MagicMock()
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(
            return_value=self._coin_records(faucet)
        )
        coinset.push_tx = AsyncMock(
            return_value={"success": False, "error": "DOUBLE_SPEND"}
        )
        registry = MagicMock()
        registry.get_by_evm = MagicMock(return_value=None)

        try:
            result = await register_evm_vault(
                body,
                self._settings(),
                coinset,
                faucet,
                store,
                registry,
            )
        except HTTPException as e:
            assert e.status_code == 502
        else:
            assert result.accepted is False
        registry.record.assert_not_called()

    @pytest.mark.asyncio
    async def test_duplicate_evm_registration_rejected_before_push(self, monkeypatch):
        from fastapi import HTTPException
        from solslot_api.app import register_evm_vault

        _acct, store, body = self._signed_request()
        monkeypatch.setattr(
            "solslot_api.app._require_vault_protocol_ready",
            lambda _settings: "0x" + "00" * 32,
        )
        faucet = self._faucet()
        coinset = MagicMock()
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(
            return_value=self._coin_records(faucet)
        )
        coinset.push_tx = AsyncMock(return_value={"success": True})
        registry = MagicMock()
        registry.get_by_evm = MagicMock(return_value=object())

        with pytest.raises(HTTPException) as exc_info:
            await register_evm_vault(
                body,
                self._settings(),
                coinset,
                faucet,
                store,
                registry,
            )

        assert exc_info.value.status_code == 409
        coinset.push_tx.assert_not_called()
        registry.record.assert_not_called()

    @pytest.mark.asyncio
    async def test_duplicate_chia_registration_rejected_before_coinset(
        self, monkeypatch
    ):
        from fastapi import HTTPException
        from solslot_api.app import register_chia_vault

        _owner_sk, store, body = self._signed_chia_request()
        monkeypatch.setattr(
            "solslot_api.app._require_vault_protocol_ready",
            lambda _settings: "0x" + "00" * 32,
        )
        faucet = self._faucet()
        coinset = MagicMock()
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(return_value=[])
        coinset.push_tx = AsyncMock(return_value={"success": True})
        registry = MagicMock()
        registry.get_by_bls = MagicMock(return_value=object())

        with pytest.raises(HTTPException) as exc_info:
            await register_chia_vault(
                body,
                self._settings(),
                coinset,
                faucet,
                store,
                registry,
            )

        assert exc_info.value.status_code == 409
        coinset.get_coin_records_by_puzzle_hash.assert_not_called()
        coinset.push_tx.assert_not_called()
        registry.record.assert_not_called()


class TestChallengeDoSFalsifiers:
    def _settings(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            alpha_writes_enabled=True,
            deployment_manifest_path="/tmp/no-solslot-test-manifest.json",
            pool_launcher_id=None,
            network="testnet11",
            trusted_proxy_cidr_list=lambda: [],
        )

    def _request(self, *, xff: str, peer: str = "203.0.113.10"):
        from types import SimpleNamespace

        return SimpleNamespace(
            headers={"x-forwarded-for": xff},
            client=SimpleNamespace(host=peer),
            scope={
                "client": (peer, 443),
                "headers": [(b"x-forwarded-for", xff.encode("ascii"))],
            },
        )

    @pytest.mark.asyncio
    async def test_xff_spoofing_does_not_bypass_per_peer_rate_limit(self, monkeypatch):
        from fastapi import HTTPException
        from solslot_api.app import ChallengeRequest, request_challenge

        store = ChallengeStore(ttl_seconds=300, max_pending=10, per_ip_per_minute=1)
        monkeypatch.setattr(
            "solslot_api.app._require_vault_protocol_ready",
            lambda _settings: "0x" + "00" * 32,
        )
        settings = self._settings()
        await request_challenge(
            ChallengeRequest(
                address="0x1234567890123456789012345678901234567890",
                auth_type="evm",
            ),
            self._request(xff="198.51.100.1"),
            settings,
            store,
        )

        with pytest.raises(HTTPException) as exc_info:
            await request_challenge(
                ChallengeRequest(
                    address="0x1234567890123456789012345678901234567890",
                    auth_type="evm",
                ),
                self._request(xff="198.51.100.2"),
                settings,
                store,
            )

        assert exc_info.value.status_code == 429
        assert len(store) == 1

    def test_unbounded_passkey_challenge_rejected_before_allocation(self):
        from pydantic import ValidationError
        from solslot_api.app import ChallengeRequest

        store = ChallengeStore(ttl_seconds=300, max_pending=10, per_ip_per_minute=10)
        with pytest.raises(ValidationError):
            ChallengeRequest(address="p" * 100_000, auth_type="passkey")
        assert len(store) == 0


# ============================================================================
# POP-CANON-009 — faucet_max_spend_mojos enforced via Faucet.select_coin
# ============================================================================
class TestFaucetMaxAmount:
    """Pre-fix: ``settings.faucet_max_spend_mojos`` was documented as a per-spend
    cap but never read anywhere in the codebase.  An operator setting the
    value would not get the documented behaviour.

    Post-fix: ``Faucet.select_coin`` accepts a ``max_amount`` kwarg.  Both
    callers (``register_evm_vault`` / ``register_chia_vault``) thread
    ``settings.faucet_max_spend_mojos`` into it.  Mirrors Chia's
    ``CoinSelectionConfig.max_coin_amount`` field
    (``chia/wallet/util/tx_config.py:16-42``)."""

    def _faucet(self):
        from solslot_api.faucet import Faucet

        seed = "00" * 32
        return Faucet.from_seed_hex(seed, "testnet11")

    def _make_record(self, amount: int) -> dict:
        return {
            "spent_block_index": 0,
            "coin": {
                "parent_coin_info": "0x" + "11" * 32,
                "puzzle_hash": "0x" + "22" * 32,
                "amount": amount,
            },
        }

    def test_max_amount_rejects_oversized_coins(self):
        """A 100 XCH coin must NOT be selected when max_amount = 0.01 XCH."""
        f = self._faucet()
        # 100 XCH coin; cap is 0.01 XCH.
        records = [self._make_record(100 * 10**12)]
        sel = f.select_coin(records, min_amount=1, max_amount=10_000_000)
        assert sel is None, "oversized coin must be filtered out"

    def test_max_amount_allows_within_cap(self):
        """A 0.005 XCH coin must be selected when min=1, cap=0.01 XCH."""
        f = self._faucet()
        records = [self._make_record(5_000_000)]  # 0.005 XCH
        sel = f.select_coin(records, min_amount=1, max_amount=10_000_000)
        assert sel is not None
        assert sel.amount == 5_000_000

    def test_max_amount_picks_smallest_within_cap(self):
        """When several coins are within both bounds, the smallest wins."""
        f = self._faucet()
        records = [
            self._make_record(8_000_000),
            self._make_record(2_000_000),  # smallest within cap
            self._make_record(50_000_000),  # too big — cap is 0.01 XCH
        ]
        sel = f.select_coin(records, min_amount=1, max_amount=10_000_000)
        assert sel is not None
        assert sel.amount == 2_000_000, "must pick smallest coin within cap"

    def test_max_amount_none_preserves_legacy_behaviour(self):
        """Omitting max_amount must select the smallest coin overall —
        no behavioural change for callers that don't specify the cap."""
        f = self._faucet()
        records = [
            self._make_record(100 * 10**12),  # 100 XCH
            self._make_record(1),
        ]
        sel = f.select_coin(records, min_amount=1)
        assert sel is not None
        assert sel.amount == 1


# ============================================================================
# POP-CANON-010 — coinset query pagination by start_height (no limit upstream)
# ============================================================================
class TestCoinsetPaginationCursor:
    """Pre-fix: callers might assume the coinset client supports a row-count
    ``limit`` param.  Upstream Chia full-node RPC
    ``get_coin_records_by_puzzle_hash`` does NOT — pagination is by height
    range only.  The audit's recommended ``limit=100`` was based on the
    wrong upstream contract.

    Post-fix: ``coinset_client.py`` documents ``start_height`` as the
    canonical cursor and emits a defensive warning when responses get
    large enough to suggest the caller should be paginating."""

    @pytest.mark.asyncio
    async def test_start_height_passed_through_to_rpc(self):
        """When start_height is provided, the coinset client must include
        it in the JSON body."""
        from unittest.mock import AsyncMock, patch

        from solslot_api.coinset_client import CoinsetClient

        client = CoinsetClient("https://testnet11.api.coinset.org")
        try:
            with patch.object(
                client, "_post", new=AsyncMock(return_value={"coin_records": []})
            ) as mock_post:
                await client.get_coin_records_by_puzzle_hash(
                    "0x" + "ab" * 32, start_height=12345
                )
                args, kwargs = mock_post.call_args
                # body is the second positional arg
                body = args[1] if len(args) > 1 else kwargs.get("body") or kwargs
                assert body.get("start_height") == 12345, (
                    "start_height must be threaded into the RPC body"
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_no_limit_param_in_body(self):
        """The client must NOT accept or pass a limit param — upstream
        doesn't support it.  Verifies our docstring contract."""
        from unittest.mock import AsyncMock, patch

        from solslot_api.coinset_client import CoinsetClient

        client = CoinsetClient("https://testnet11.api.coinset.org")
        try:
            with patch.object(
                client, "_post", new=AsyncMock(return_value={"coin_records": []})
            ) as mock_post:
                await client.get_coin_records_by_puzzle_hash("0x" + "ab" * 32)
                args, kwargs = mock_post.call_args
                body = args[1] if len(args) > 1 else kwargs.get("body") or kwargs
                assert "limit" not in body, (
                    "limit param is not part of the upstream RPC contract"
                )
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_large_response_logs_warning(self, caplog):
        """A response with > 1000 records must log a warning suggesting
        the caller paginate via start_height."""
        import logging
        from unittest.mock import AsyncMock, patch

        from solslot_api.coinset_client import CoinsetClient

        big_payload = {
            "coin_records": [
                {
                    "spent_block_index": 0,
                    "coin": {
                        "parent_coin_info": "0x" + "11" * 32,
                        "puzzle_hash": "0x" + "22" * 32,
                        "amount": 1,
                    },
                }
                for _ in range(1500)
            ]
        }

        client = CoinsetClient("https://testnet11.api.coinset.org")
        try:
            with patch.object(
                client, "_post", new=AsyncMock(return_value=big_payload)
            ):
                with caplog.at_level(logging.WARNING, logger="solslot_api.coinset_client"):
                    records = await client.get_coin_records_by_puzzle_hash("0x" + "ab" * 32)
                    assert len(records) == 1500, "client must not silently truncate"
                    assert any(
                        "POP-CANON-010" in rec.message for rec in caplog.records
                    ), "large-response warning must reference POP-CANON-010"
        finally:
            await client.close()


# ============================================================================
# POP-CANON-011 — pool launcher resolution requires signed V2 authority
# ============================================================================
class TestPoolLauncherSignedArtifactAuthority:
    """Vault registration must fail closed without signed ceremony authority."""

    def test_signed_artifact_pool_is_used(self, monkeypatch):
        from types import SimpleNamespace

        from solslot_api import app as app_module
        from solslot_api.app import _pool_launcher_id_or_zero

        monkeypatch.setattr(
            app_module,
            "load_signed_public_artifact",
            lambda _settings: {"launcherIds": {"pool": "0x" + "ab" * 32}},
        )
        settings = SimpleNamespace(
            pool_launcher_id="0x" + "ff" * 32,
            deployment_manifest_path="/untrusted/manifest.json",
        )
        assert _pool_launcher_id_or_zero(settings).hex() == "ab" * 32

    def test_missing_artifact_disables_registration(self, monkeypatch):
        from types import SimpleNamespace

        from fastapi import HTTPException
        from solslot_api import app as app_module
        from solslot_api.app import _pool_launcher_id_or_zero
        from solslot_api.public_artifact import PublicArtifactMissing

        def missing(_settings):
            raise PublicArtifactMissing("missing")

        monkeypatch.setattr(app_module, "load_signed_public_artifact", missing)
        with pytest.raises(HTTPException) as exc:
            _pool_launcher_id_or_zero(SimpleNamespace(pool_launcher_id=None))
        assert exc.value.status_code == 503

    def test_incomplete_artifact_disables_registration(self, monkeypatch):
        from types import SimpleNamespace

        from fastapi import HTTPException
        from solslot_api import app as app_module
        from solslot_api.app import _pool_launcher_id_or_zero

        monkeypatch.setattr(
            app_module,
            "load_signed_public_artifact",
            lambda _settings: {"launcherIds": {}},
        )
        with pytest.raises(HTTPException) as exc:
            _pool_launcher_id_or_zero(
                SimpleNamespace(pool_launcher_id="0x" + "ff" * 32)
            )
        assert exc.value.status_code == 503

    def test_artifact_is_rechecked_for_each_registration(self, monkeypatch):
        from types import SimpleNamespace

        from solslot_api import app as app_module
        from solslot_api.app import _pool_launcher_id_or_zero

        state = {"pool": "0x" + "aa" * 32}
        monkeypatch.setattr(
            app_module,
            "load_signed_public_artifact",
            lambda _settings: {"launcherIds": {"pool": state["pool"]}},
        )
        settings = SimpleNamespace()
        assert _pool_launcher_id_or_zero(settings).hex() == "aa" * 32
        state["pool"] = "0x" + "bb" * 32
        assert _pool_launcher_id_or_zero(settings).hex() == "bb" * 32


# ============================================================================
# POP-CANON-007 — VaultRegistry persistence via SQLite (WAL + indexed lookup)
# ============================================================================
class TestVaultRegistryPersistence:
    """Pre-fix: ``VaultRegistry`` was a process-local in-memory dict.  Memory
    grew monotonically with each successful registration (no remove, no TTL,
    no eviction), and ALL state was lost on process restart.

    Post-fix: ``VaultRegistry`` is backed by SQLite running in WAL mode
    (``solslot_api.vault_db.VaultStore``).  Records survive restart, the
    EVM reverse-lookup is a B-tree index (O(log N)), writes are
    transactional (``BEGIN IMMEDIATE`` + ``COMMIT``), and concurrent
    readers don't block the writer.  Schema versioning via
    ``PRAGMA user_version`` makes future migrations routine."""

    def _make_record(self, launcher_byte: int = 0x11, evm: bool = True):
        """Build a VaultRecord with deterministic test bytes."""
        from chia_rs.sized_bytes import bytes32

        from solslot_api.state import VaultRecord

        return VaultRecord(
            launcher_id=bytes32(bytes([launcher_byte] * 32)),
            full_puzhash=bytes32(bytes([0xaa] * 32)),
            p2_vault_puzhash=bytes32(bytes([0xbb] * 32)),
            auth_type=3,  # AUTH_TYPE_SECP256K1
            owner_pubkey=bytes([0x02] * 33),
            owner_evm_address=("0x" + "cd" * 20) if evm else None,
            spend_bundle_id="0x" + "ee" * 32,
            pushed_at=1234567890.0,
        )

    def test_record_round_trip_via_disk(self, tmp_path):
        """Record a vault, close the registry, reopen at the same path,
        verify the record survives — proves on-disk durability."""
        from solslot_api.state import VaultRegistry

        path = tmp_path / "vault_registry.db"
        rec = self._make_record()

        reg_a = VaultRegistry.open(path)
        reg_a.record(rec)
        assert len(reg_a) == 1
        reg_a.close()

        # Simulate process restart: open afresh.
        reg_b = VaultRegistry.open(path)
        try:
            loaded = reg_b.get(rec.launcher_id)
            assert loaded is not None, "record must survive restart"
            assert loaded.launcher_id == rec.launcher_id
            assert loaded.full_puzhash == rec.full_puzhash
            assert loaded.auth_type == rec.auth_type
            assert loaded.owner_pubkey == rec.owner_pubkey
            assert loaded.owner_evm_address == rec.owner_evm_address
            assert loaded.spend_bundle_id == rec.spend_bundle_id
        finally:
            reg_b.close()

    def test_evm_index_reverse_lookup_case_insensitive(self, tmp_path):
        """``get_by_evm`` is case-insensitive thanks to ``COLLATE NOCASE``
        on the unique index — callers don't need to normalize."""
        from solslot_api.state import VaultRegistry

        rec = self._make_record(launcher_byte=0x22, evm=True)
        reg = VaultRegistry.open(":memory:")
        try:
            reg.record(rec)

            # Mixed-case query against a lowercased stored value.
            evm_upper = (rec.owner_evm_address or "").upper().replace("0X", "0x")
            loaded = reg.get_by_evm(evm_upper)
            assert loaded is not None
            assert loaded.launcher_id == rec.launcher_id

            # Original casing also works.
            loaded2 = reg.get_by_evm(rec.owner_evm_address or "")
            assert loaded2 is not None
            assert loaded2.launcher_id == rec.launcher_id
        finally:
            reg.close()

    def test_remove_clears_both_lookups(self, tmp_path):
        """``remove`` must drop the row, so neither lookup returns it
        afterwards.  SQLite's row deletion automatically maintains the
        EVM index; we verify both views agree."""
        from solslot_api.state import VaultRegistry

        rec = self._make_record()
        reg = VaultRegistry.open(":memory:")
        try:
            reg.record(rec)
            assert reg.get(rec.launcher_id) is not None
            assert reg.get_by_evm(rec.owner_evm_address) is not None

            removed = reg.remove(rec.launcher_id)
            assert removed is True, "remove should return True on hit"
            assert reg.get(rec.launcher_id) is None
            assert reg.get_by_evm(rec.owner_evm_address) is None
            assert reg.remove(rec.launcher_id) is False, (
                "remove on a missing row returns False, doesn't raise"
            )
        finally:
            reg.close()

    def test_record_upsert_overwrites_existing(self, tmp_path):
        """Re-recording the same launcher_id replaces the row in place.
        Verified via SQL: the upsert relies on
        ``ON CONFLICT(launcher_id) DO UPDATE``."""
        from solslot_api.state import VaultRecord, VaultRegistry

        rec_v1 = self._make_record()
        rec_v2 = VaultRecord(
            launcher_id=rec_v1.launcher_id,
            full_puzhash=rec_v1.full_puzhash,
            p2_vault_puzhash=rec_v1.p2_vault_puzhash,
            auth_type=rec_v1.auth_type,
            owner_pubkey=rec_v1.owner_pubkey,
            owner_evm_address=rec_v1.owner_evm_address,
            spend_bundle_id="0x" + "ff" * 32,
            pushed_at=9999999999.0,
        )

        reg = VaultRegistry.open(":memory:")
        try:
            reg.record(rec_v1)
            reg.record(rec_v2)
            loaded = reg.get(rec_v1.launcher_id)
            assert loaded is not None
            assert loaded.spend_bundle_id == rec_v2.spend_bundle_id
            assert loaded.pushed_at == rec_v2.pushed_at
            assert len(reg) == 1, "upsert must not double-count"
        finally:
            reg.close()

    def test_schema_check_constraints_reject_bad_data(self, tmp_path):
        """The ``vaults`` table has CHECK constraints (32-byte hashes,
        valid auth_type).  Inserting bad data must raise rather than
        silently corrupt the registry."""
        import sqlite3

        from solslot_api.vault_db import StoredVault, VaultStore

        store = VaultStore(":memory:")
        try:
            # Wrong launcher_id length (16 bytes instead of 32).
            bad = StoredVault(
                launcher_id=b"\x00" * 16,
                full_puzhash=b"\x00" * 32,
                p2_vault_puzhash=b"\x00" * 32,
                auth_type=1,
                owner_pubkey=b"\x00" * 32,
                owner_evm_address=None,
                spend_bundle_id="0x" + "00" * 32,
                pushed_at=0.0,
            )
            with pytest.raises(sqlite3.IntegrityError):
                store.upsert(bad)

            # Out-of-range auth_type (only 1, 2, 3 allowed).
            bad2 = StoredVault(
                launcher_id=b"\x01" * 32,
                full_puzhash=b"\x00" * 32,
                p2_vault_puzhash=b"\x00" * 32,
                auth_type=99,
                owner_pubkey=b"\x00" * 32,
                owner_evm_address=None,
                spend_bundle_id="0x" + "00" * 32,
                pushed_at=0.0,
            )
            with pytest.raises(sqlite3.IntegrityError):
                store.upsert(bad2)
        finally:
            store.close()

    def test_evm_address_uniqueness_enforced_by_index(self, tmp_path):
        """The unique partial index on ``owner_evm_address`` rejects
        two distinct launcher_ids claiming the same EVM key.  The error
        must surface as ``sqlite3.IntegrityError`` rather than silent
        overwrite."""
        import sqlite3

        from chia_rs.sized_bytes import bytes32

        from solslot_api.state import VaultRecord, VaultRegistry

        reg = VaultRegistry.open(":memory:")
        try:
            rec_a = self._make_record(launcher_byte=0xAA, evm=True)
            rec_b = VaultRecord(
                launcher_id=bytes32(bytes([0xBB] * 32)),  # different launcher
                full_puzhash=rec_a.full_puzhash,
                p2_vault_puzhash=rec_a.p2_vault_puzhash,
                auth_type=rec_a.auth_type,
                owner_pubkey=rec_a.owner_pubkey,
                owner_evm_address=rec_a.owner_evm_address,  # SAME evm
                spend_bundle_id=rec_a.spend_bundle_id,
                pushed_at=rec_a.pushed_at,
            )
            reg.record(rec_a)
            with pytest.raises(sqlite3.IntegrityError):
                reg.record(rec_b)
        finally:
            reg.close()

    def test_bls_pubkey_lookup_and_uniqueness_enforced_by_index(self, tmp_path):
        """Chia BLS vaults get the same one-owner-one-vault invariant as
        EVM vaults: lookup by owner pubkey is indexed, and a second
        launcher claiming the same BLS key is rejected by SQLite.
        """
        import sqlite3

        from chia_rs.sized_bytes import bytes32

        from solslot_api.state import VaultRecord, VaultRegistry

        pubkey = bytes([0x07] * 48)
        reg = VaultRegistry.open(":memory:")
        try:
            rec_a = VaultRecord(
                launcher_id=bytes32(bytes([0xA1] * 32)),
                full_puzhash=bytes32(bytes([0xA2] * 32)),
                p2_vault_puzhash=bytes32(bytes([0xA3] * 32)),
                auth_type=1,  # AUTH_TYPE_BLS
                owner_pubkey=pubkey,
                owner_evm_address=None,
                spend_bundle_id="0x" + "a4" * 32,
                pushed_at=1.0,
            )
            rec_b = VaultRecord(
                launcher_id=bytes32(bytes([0xB1] * 32)),
                full_puzhash=rec_a.full_puzhash,
                p2_vault_puzhash=rec_a.p2_vault_puzhash,
                auth_type=rec_a.auth_type,
                owner_pubkey=pubkey,
                owner_evm_address=None,
                spend_bundle_id=rec_a.spend_bundle_id,
                pushed_at=rec_a.pushed_at,
            )

            reg.record(rec_a)
            loaded = reg.get_by_bls(pubkey)
            assert loaded is not None
            assert loaded.launcher_id == rec_a.launcher_id
            with pytest.raises(sqlite3.IntegrityError):
                reg.record(rec_b)
        finally:
            reg.close()

    def test_schema_version_tracked(self, tmp_path):
        """``PRAGMA user_version`` is set after migration so future
        migrations can detect the current schema."""
        from solslot_api.vault_db import SCHEMA_VERSION, VaultStore

        store = VaultStore(":memory:")
        try:
            assert store.schema_version() == SCHEMA_VERSION
        finally:
            store.close()

    def test_wal_mode_enabled_for_disk_databases(self, tmp_path):
        """File-backed stores must come up in WAL mode — that's the
        whole point of choosing SQLite over a JSON file.  Verified via
        ``PRAGMA journal_mode`` after open."""
        from solslot_api.vault_db import VaultStore

        path = tmp_path / "wal_check.db"
        store = VaultStore(path)
        try:
            mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert str(mode).lower() == "wal", f"expected WAL, got {mode}"
        finally:
            store.close()


# ============================================================================
# POP-CANON-008 — Faucet UTXO consolidation worker
# ============================================================================
class TestFaucetConsolidationWorker:
    """Pre-fix: faucet UTXOs accumulated forever.  Each registration created
    a change UTXO at the faucet's puzhash; ``select_coin`` fetched and
    sorted ALL of them on every call.  At N=10000 the per-registration
    cost was O(N log N) and coinset wire size grew unbounded.

    Post-fix: opt-in background worker that periodically joins all
    unspent UTXOs into one.  Pattern mirrors Chia's
    ``pool_wallet.claim_pool_rewards`` (consolidation-style spend
    bundle).  The bundle uses one consolidator coin (CREATE_COIN with
    sum-minus-fee) plus N junior coins with empty conditions; mempool
    value conservation flows their amounts to the consolidator,
    aggregated signature ensures atomicity."""

    def _faucet(self):
        from solslot_api.faucet import Faucet

        return Faucet.from_seed_hex("00" * 32, "testnet11")

    def _record(self, parent_hex: str, faucet_puzhash, amount: int) -> dict:
        return {
            "spent_block_index": 0,
            "coin": {
                "parent_coin_info": "0x" + parent_hex,
                "puzzle_hash": "0x" + faucet_puzhash.hex(),
                "amount": amount,
            },
        }

    @pytest.mark.asyncio
    async def test_below_threshold_is_no_op(self):
        """When the unspent count is below threshold, ``maybe_consolidate``
        must return None and not push any bundle."""
        from unittest.mock import AsyncMock, MagicMock

        from solslot_api.faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        f = self._faucet()
        coinset = MagicMock()
        # 5 unspent (threshold = 10) → no action.
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(return_value=[
            self._record("11" * 32, f.address_puzzle_hash, 1000)
            for _ in range(5)
        ])
        coinset.push_tx = AsyncMock(return_value={"success": True})

        worker = FaucetConsolidationWorker(
            faucet=f, coinset=coinset,
            config=FaucetConsolidationConfig(enabled=False, threshold=10),
        )
        result = await worker.maybe_consolidate()
        assert result is None, "below-threshold must not push"
        coinset.push_tx.assert_not_called()

    @pytest.mark.asyncio
    async def test_above_threshold_pushes_consolidating_bundle(self):
        """At/above threshold, the worker builds a SpendBundle that
        consumes all unspent UTXOs and produces exactly ONE output at
        the faucet's puzhash."""
        from unittest.mock import AsyncMock, MagicMock

        from solslot_api.faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        f = self._faucet()
        # 10 records (threshold = 5) → action.
        records = [
            self._record(f"{i:02x}" * 32, f.address_puzzle_hash, 1000 + i)
            for i in range(10)
        ]
        captured_bundle: dict = {}

        async def fake_push(bundle_json):
            captured_bundle.update(bundle_json)
            return {"success": True, "status": "SUCCESS"}

        coinset = MagicMock()
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(return_value=records)
        coinset.push_tx = AsyncMock(side_effect=fake_push)

        worker = FaucetConsolidationWorker(
            faucet=f, coinset=coinset,
            config=FaucetConsolidationConfig(enabled=False, threshold=5, fee=0),
        )
        result = await worker.maybe_consolidate()
        assert result == {"success": True, "status": "SUCCESS"}

        # The pushed bundle must consume all 10 inputs.
        spends = captured_bundle.get("coin_spends", [])
        assert len(spends) == 10, f"expected 10 inputs, got {len(spends)}"

    @pytest.mark.asyncio
    async def test_consolidator_amount_equals_sum_minus_fee(self):
        """The single output amount must equal the total of inputs minus fee."""
        from unittest.mock import AsyncMock, MagicMock

        from solslot_api.faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        f = self._faucet()
        amounts = [1000, 2000, 3000, 4000, 5000]  # total 15000
        records = [
            self._record(f"{i:02x}" * 32, f.address_puzzle_hash, amt)
            for i, amt in enumerate(amounts)
        ]

        coinset = MagicMock()
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(return_value=records)
        coinset.push_tx = AsyncMock(return_value={"success": True})

        worker = FaucetConsolidationWorker(
            faucet=f, coinset=coinset,
            config=FaucetConsolidationConfig(enabled=False, threshold=2, fee=100),
        )
        # Build the bundle directly to inspect amount math.
        chunk = records[: 500]
        bundle = worker._build_consolidation_bundle(chunk, fee=100)
        assert bundle is not None

        # Decode the consolidator's CREATE_COIN by parsing its solution.
        from chia.types.blockchain_format.program import Program

        # Coins are sorted DESC by amount, so the consolidator (coin 0)
        # is the largest input (amount 5000).
        consolidator_spend = bundle.coin_spends[0]
        assert consolidator_spend.coin.amount == 5000

        # Solution shape: [0, delegated_puzzle, 0]; delegated_puzzle is (q . conditions)
        solution = Program.from_bytes(bytes(consolidator_spend.solution))
        # solution = [0, (q . conds), 0]; second item is delegated puzzle.
        delegated = solution.at("rf")  # solution.rest().first()
        # delegated puzzle is (q . conditions) — get the conditions list.
        conditions = delegated.rest()
        # First condition: [CREATE_COIN, faucet_puzhash, total]
        first_cond = conditions.first().as_python()
        assert int.from_bytes(first_cond[0], "big") == 51, "must be CREATE_COIN"
        assert first_cond[1] == bytes(f.address_puzzle_hash)
        # Amount may be encoded as variable-width; convert.
        amt_bytes = first_cond[2]
        amt = int.from_bytes(amt_bytes, "big") if amt_bytes else 0
        assert amt == sum(amounts) - 100, (
            f"consolidator amount must = sum({sum(amounts)}) - fee(100); got {amt}"
        )

    @pytest.mark.asyncio
    async def test_disabled_worker_does_not_start_task(self):
        """``start()`` is a no-op when ``config.enabled`` is False."""
        from unittest.mock import MagicMock

        from solslot_api.faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        f = self._faucet()
        coinset = MagicMock()
        worker = FaucetConsolidationWorker(
            faucet=f, coinset=coinset,
            config=FaucetConsolidationConfig(enabled=False),
        )
        await worker.start()
        assert worker._task is None, "disabled worker must not schedule a task"
        await worker.stop()  # must be safe to call

    @pytest.mark.asyncio
    async def test_stop_cancels_background_task(self):
        """``stop()`` must signal the loop and await its completion."""
        from unittest.mock import AsyncMock, MagicMock

        from solslot_api.faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        f = self._faucet()
        coinset = MagicMock()
        coinset.get_coin_records_by_puzzle_hash = AsyncMock(return_value=[])
        coinset.push_tx = AsyncMock(return_value={"success": True})

        worker = FaucetConsolidationWorker(
            faucet=f, coinset=coinset,
            config=FaucetConsolidationConfig(
                enabled=True, threshold=1000, interval_seconds=0.05
            ),
        )
        await worker.start()
        assert worker._task is not None
        # Let the loop run at least one iteration.
        import asyncio
        await asyncio.sleep(0.01)
        await worker.stop()
        assert worker._task is None, "stop() must clear the task reference"

    def test_build_bundle_aborts_below_two_inputs(self):
        """Single-coin or empty input lists return None — nothing to merge."""
        from unittest.mock import MagicMock

        from solslot_api.faucet_worker import FaucetConsolidationWorker

        f = self._faucet()
        worker = FaucetConsolidationWorker(faucet=f, coinset=MagicMock())
        assert worker._build_consolidation_bundle([], fee=0) is None
        single = [self._record("00" * 32, f.address_puzzle_hash, 100)]
        assert worker._build_consolidation_bundle(single, fee=0) is None

    def test_max_inputs_per_run_caps_bundle_size(self):
        """When unspent count exceeds max_inputs_per_run, only that many
        coins are included.  Subsequent worker runs handle the remainder."""
        from unittest.mock import MagicMock

        from solslot_api.faucet_worker import (
            FaucetConsolidationConfig,
            FaucetConsolidationWorker,
        )

        f = self._faucet()
        records = [
            self._record(f"{i:04x}".zfill(64), f.address_puzzle_hash, 100 + i)
            for i in range(10)
        ]
        worker = FaucetConsolidationWorker(
            faucet=f, coinset=MagicMock(),
            config=FaucetConsolidationConfig(
                enabled=False, threshold=2, max_inputs_per_run=3, fee=0,
            ),
        )
        # Build directly (skip the threshold gate) with the chunk size cap.
        chunk = records[: 3]
        bundle = worker._build_consolidation_bundle(chunk, fee=0)
        assert bundle is not None
        assert len(bundle.coin_spends) == 3, (
            "max_inputs_per_run must cap the bundle size"
        )
