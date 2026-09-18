from __future__ import annotations

import time

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import HTTPException, Request

from solslot_api.config import Settings
from solslot_api.credential_auth import (
    OwnerAuth,
    OwnerChallengeRequest,
    VAULT_SESSION_COOKIE,
    credential_bls_signing_digest,
    issue_vault_session,
    issue_owner_challenge,
    verify_owner_auth,
    verify_vault_session,
    vault_session_payload,
)
from solslot_api.credential_ledger import (
    LedgerCircuitOpen,
    LedgerConflict,
    LedgerRateLimited,
    get_credential_ledger,
    reset_credential_ledgers_for_tests,
)
from solslot_api.state import VaultRecord, reset_registry_for_tests
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1


VAULT = "0x" + "11" * 32
BRIDGE = "0x" + "22" * 32


@pytest.fixture(autouse=True)
def _reset_ledgers():
    reset_credential_ledgers_for_tests()
    yield
    reset_credential_ledgers_for_tests()


def _settings(tmp_path) -> Settings:
    return Settings(
        alpha_writes_enabled=True,
        network="testnet11",
        zkpassport_ledger_db_path=str(tmp_path / "credential.db"),
    )


def _record(*, owner_pubkey: bytes, auth_type: int, evm_address: str | None) -> VaultRecord:
    return VaultRecord(
        launcher_id=bytes32.fromhex(VAULT[2:]),
        full_puzhash=bytes32(b"\x33" * 32),
        p2_vault_puzhash=bytes32(b"\x44" * 32),
        auth_type=auth_type,
        owner_pubkey=owner_pubkey,
        owner_evm_address=evm_address,
        spend_bundle_id="0x" + "55" * 32,
        pushed_at=time.time(),
    )


def _enrollment() -> dict:
    now = int(time.time())
    return {
        "vaultLauncherId": VAULT,
        "network": "testnet11",
        "policyVersion": 2,
        "status": "reserved",
        "bridgePolicyHash": "0x" + "66" * 32,
        "bridgeParentId": "0x" + "77" * 32,
        "bridgeAmount": 1,
        "bridgeCoinId": BRIDGE,
        "createdAt": now,
        "updatedAt": now,
        "receipt": None,
    }


def test_evm_owner_challenge_is_payload_bound_and_single_use(tmp_path):
    settings = _settings(tmp_path)
    account = Account.from_key(bytes.fromhex("01" * 32))
    from eth_keys import keys

    pubkey = keys.PrivateKey(bytes.fromhex("01" * 32)).public_key.to_compressed_bytes()
    registry = reset_registry_for_tests(tmp_path / "vault.db")
    registry.record(
        _record(
            owner_pubkey=pubkey,
            auth_type=AUTH_TYPE_SECP256K1,
            evm_address=account.address,
        )
    )
    payload = vault_session_payload(settings)
    challenge = issue_owner_challenge(
        settings,
        vault_launcher_id=VAULT,
        request=OwnerChallengeRequest(action="session_login", payload=payload),
    )
    signed = Account.sign_message(
        encode_typed_data(full_message=challenge.typedData),
        account.key,
    )
    auth = OwnerAuth(challengeId=challenge.challengeId, signature=signed.signature.hex())

    verified = verify_owner_auth(
        settings,
        vault_launcher_id=VAULT,
        action="session_login",
        payload=payload,
        owner_auth=auth,
    )
    assert verified.owner_key == account.address.lower()
    with pytest.raises(Exception, match="unknown or consumed"):
        verify_owner_auth(
            settings,
            vault_launcher_id=VAULT,
            action="session_login",
            payload=payload,
            owner_auth=auth,
        )

    token, public_session = issue_vault_session(settings, verified)
    request = Request(
        {
            "type": "http",
            "headers": [
                (
                    b"cookie",
                    f"{VAULT_SESSION_COOKIE}={token}".encode("ascii"),
                )
            ],
        }
    )
    recovered = verify_vault_session(settings, request, VAULT)
    assert public_session.protocolVersion == "solslot-v2"
    assert recovered.owner_key == account.address.lower()
    assert recovered.vault_launcher_id == VAULT
    assert len(recovered.session_id) == 32
    assert 'session_id' not in public_session.model_dump()
    from solslot_api.sols_swap_funding import digest
    assert public_session.sessionFingerprint == digest(recovered.session_id)
    assert recovered.session_id not in public_session.model_dump_json()
    with pytest.raises(HTTPException, match="does not match") as mismatch:
        verify_vault_session(settings, request, "0x" + "99" * 32)
    assert mismatch.value.status_code == 403


def test_bls_owner_challenge_verifies_without_an_evm_identity(tmp_path):
    settings = _settings(tmp_path)
    owner_sk = AugSchemeMPL.key_gen(b"\x88" * 32)
    registry = reset_registry_for_tests(tmp_path / "vault.db")
    registry.record(
        _record(
            owner_pubkey=bytes(owner_sk.get_g1()),
            auth_type=AUTH_TYPE_BLS,
            evm_address=None,
        )
    )
    payload = {"evmTxHash": "0x" + "aa" * 32}
    challenge = issue_owner_challenge(
        settings,
        vault_launcher_id=VAULT,
        request=OwnerChallengeRequest(action="relay", payload=payload),
    )
    stored = get_credential_ledger(settings).get_owner_challenge(challenge.challengeId)
    assert stored is not None
    assert challenge.nonce == stored.nonce
    assert len(challenge.nonce) == 66
    signature = AugSchemeMPL.sign(owner_sk, credential_bls_signing_digest(settings, stored))
    verified = verify_owner_auth(
        settings,
        vault_launcher_id=VAULT,
        action="relay",
        payload=payload,
        owner_auth=OwnerAuth(
            challengeId=challenge.challengeId,
            signature="0x" + bytes(signature).hex(),
        ),
    )
    assert verified.auth_type == "chia_bls"


def test_bridge_coin_and_event_nullifier_are_consumed_once(tmp_path):
    settings = _settings(tmp_path)
    ledger = get_credential_ledger(settings)
    record, created = ledger.reserve_enrollment(record=_enrollment(), owner_key="owner")
    assert created is True
    assert record["bridgeCoinId"] == BRIDGE
    duplicate = dict(_enrollment(), vaultLauncherId="0x" + "99" * 32)
    with pytest.raises(LedgerConflict):
        ledger.reserve_enrollment(record=duplicate, owner_key="other")

    updated = dict(record, status="evm_confirmed")
    ledger.record_evm_event(
        record=updated,
        owner_key="owner",
        transaction_hash="0x" + "aa" * 32,
        scoped_nullifier="0x" + "bb" * 32,
        bridge_coin_id=BRIDGE,
        block_number=123,
    )
    with pytest.raises(LedgerConflict):
        ledger.record_evm_event(
            record=updated,
            owner_key="owner",
            transaction_hash="0x" + "aa" * 32,
            scoped_nullifier="0x" + "bb" * 32,
            bridge_coin_id=BRIDGE,
            block_number=123,
        )


def test_relay_nonce_budget_and_circuit_persist(tmp_path):
    settings = _settings(tmp_path)
    ledger = get_credential_ledger(settings)
    ledger.reserve_enrollment(record=_enrollment(), owner_key="owner")
    ledger.reserve_relay(
        request_digest="0x" + "10" * 32,
        vault_launcher_id=VAULT,
        owner_key="owner",
        source_ip="127.0.0.1",
        bridge_coin_id=BRIDGE,
        forwarder_nonce=1,
        inner_gas=100,
        per_ip_per_minute=1,
        per_owner_per_minute=1,
        per_vault_per_hour=1,
        global_gas_per_day=100,
    )
    with pytest.raises((LedgerConflict, LedgerRateLimited)):
        ledger.reserve_relay(
            request_digest="0x" + "20" * 32,
            vault_launcher_id=VAULT,
            owner_key="owner",
            source_ip="127.0.0.1",
            bridge_coin_id=BRIDGE,
            forwarder_nonce=1,
            inner_gas=1,
            per_ip_per_minute=1,
            per_owner_per_minute=1,
            per_vault_per_hour=1,
            global_gas_per_day=100,
        )
    ledger.finish_relay(
        request_digest="0x" + "10" * 32,
        tx_hash=None,
        error="rpc failed",
        failure_threshold=1,
        cooldown_seconds=60,
    )
    with pytest.raises(LedgerCircuitOpen):
        ledger.reserve_relay(
            request_digest="0x" + "30" * 32,
            vault_launcher_id=VAULT,
            owner_key="owner",
            source_ip="127.0.0.2",
            bridge_coin_id=BRIDGE,
            forwarder_nonce=2,
            inner_gas=1,
            per_ip_per_minute=10,
            per_owner_per_minute=10,
            per_vault_per_hour=10,
            global_gas_per_day=1000,
        )


def test_submitted_relay_is_bound_to_transaction_owner_vault_and_bridge(tmp_path):
    settings = _settings(tmp_path)
    ledger = get_credential_ledger(settings)
    ledger.reserve_enrollment(record=_enrollment(), owner_key="owner")
    request_digest = "0x" + "31" * 32
    transaction_hash = "0x" + "32" * 32
    ledger.reserve_relay(
        request_digest=request_digest,
        vault_launcher_id=VAULT,
        owner_key="owner",
        source_ip="127.0.0.1",
        bridge_coin_id=BRIDGE,
        forwarder_nonce=3,
        inner_gas=100,
        per_ip_per_minute=10,
        per_owner_per_minute=10,
        per_vault_per_hour=10,
        global_gas_per_day=1000,
    )

    with pytest.raises(LedgerConflict):
        ledger.require_submitted_relay(
            transaction_hash=transaction_hash,
            vault_launcher_id=VAULT,
            owner_key="owner",
            bridge_coin_id=BRIDGE,
        )

    ledger.finish_relay(
        request_digest=request_digest,
        tx_hash=transaction_hash,
        error=None,
        failure_threshold=5,
        cooldown_seconds=60,
    )
    ledger.require_submitted_relay(
        transaction_hash=transaction_hash,
        vault_launcher_id=VAULT,
        owner_key="owner",
        bridge_coin_id=BRIDGE,
    )

    with pytest.raises(LedgerConflict):
        ledger.require_submitted_relay(
            transaction_hash=transaction_hash,
            vault_launcher_id=VAULT,
            owner_key="other",
            bridge_coin_id=BRIDGE,
        )

    with pytest.raises(LedgerConflict):
        ledger.finish_relay(
            request_digest=request_digest,
            tx_hash=transaction_hash,
            error=None,
            failure_threshold=5,
            cooldown_seconds=60,
        )
