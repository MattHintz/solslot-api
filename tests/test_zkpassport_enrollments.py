from __future__ import annotations

import asyncio
from types import SimpleNamespace
import json

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys as eth_keys
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import Request
from fastapi.testclient import TestClient

from solslot_api.app import app
from solslot_api import public_artifact, zkpassport_enrollments
from solslot_api.config import Settings
from solslot_api.credential_auth import VerifiedVaultSession
from solslot_api.credential_ledger import get_credential_ledger
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_api.state import VaultRecord, get_registry, reset_registry_for_tests
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1


from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
LAUNCHER_COIN_A = Coin(bytes32(b"\x0a" * 32), SINGLETON_LAUNCHER_HASH, uint64(1))
VAULT_A = "0x" + LAUNCHER_COIN_A.name().hex()
VAULT_B = "0x" + "22" * 32
VAULT_C = "0x" + "33" * 32
PARENT_A = "0x" + "aa" * 32
PARENT_B = "0x" + "bb" * 32
POLICY_HASH = "0x" + "c1" * 32
ROOT = "0x" + "44" * 32
LEAF = "0x" + "55" * 32
TX = "0x" + "66" * 32
VALIDATOR_MESSAGE = "0x" + "88" * 32
VAULT_COIN_PARENT = "0x" + "99" * 32
VAULT_COIN_PUZZLE = "0x" + "d1" * 32
_DEFAULT_PRIVATE_KEY = bytes.fromhex("01" * 32)
_DEFAULT_ACCOUNT = Account.from_key(_DEFAULT_PRIVATE_KEY)
_DEFAULT_OWNER_PUBKEY = eth_keys.PrivateKey(
    _DEFAULT_PRIVATE_KEY
).public_key.to_compressed_bytes()
EVM_SENDER = _DEFAULT_ACCOUNT.address


def _install_signed_artifact(
    monkeypatch,
    *,
    bridge_policy_hash: str = POLICY_HASH,
    pool_launcher_id: str = "0x" + "70" * 32,
) -> dict:
    artifact = {
        "artifactHash": "0x" + "cd" * 32,
        "launcherIds": {"pool": pool_launcher_id},
        "bridgePolicy": {
            "policyHash": bridge_policy_hash,
            "policyVersion": 2,
            "parentCoinIds": [PARENT_A, PARENT_B],
            "bridgeCoinIds": [_coin_id(parent, bridge_policy_hash) for parent in (PARENT_A, PARENT_B)],
        },
        "evmAddresses": {
            "attestationEmitter": "0x" + "ab" * 20,
        },
    }
    monkeypatch.setattr(
        public_artifact,
        "load_signed_public_artifact",
        lambda _settings: artifact,
    )
    return artifact


def _install_validator_quorum(monkeypatch, tmp_path):
    validator_keys = tuple(
        zkpassport_enrollments.AugSchemeMPL.key_gen(bytes([index]) * 32)
        for index in (7, 8, 9)
    )
    validator_pubkeys = tuple(bytes(key.get_g1()) for key in validator_keys)
    from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash

    policy_hash = make_bridge_policy_hash(validator_pubkeys, 2)
    monkeypatch.setenv(
        "SOLSLOT_ZKPASSPORT_VALIDATOR_URLS",
        json.dumps(["https://v0.test", "https://v1.test", "https://v2.test"]),
    )
    monkeypatch.setenv(
        "SOLSLOT_ZKPASSPORT_VALIDATOR_PUBKEYS",
        json.dumps(["0x" + pubkey.hex() for pubkey in validator_pubkeys]),
    )
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_VALIDATOR_THRESHOLD", "2")
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_EMITTER_ADDRESS", "0x" + "ab" * 20)
    async def collect(_settings, claim):
        attempt = get_credential_ledger(_settings).get_stamp_attempt(claim.vault_launcher_id)
        assert attempt is not None and attempt["claim_hash"] == claim.canonical_hash()
        assert json.loads(attempt["claim_json"]) == claim.model_dump(mode="json")
        assert attempt["bundle_hex"] is None
        signatures = [
            zkpassport_enrollments.AugSchemeMPL.sign(key, claim.signature_message())
            for key in validator_keys[:2]
        ]
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=zkpassport_enrollments.AugSchemeMPL.aggregate(signatures),
            claim_hash=claim.canonical_hash(),
        )

    monkeypatch.setattr(zkpassport_enrollments, "collect_validator_quorum", collect)
    return validator_keys, policy_hash


def _install_owner_bypass(monkeypatch) -> None:
    def fake_verify_session(_settings, _request, vault_launcher_id):
        record = get_registry().get(bytes32.fromhex(vault_launcher_id[2:]))
        assert record is not None
        auth_type = "evm" if record.owner_evm_address else "chia_bls"
        return VerifiedVaultSession(
            owner_key=(record.owner_evm_address or ("0x" + record.owner_pubkey.hex())).lower(),
            auth_type=auth_type,
            vault_launcher_id=vault_launcher_id,
            network="testnet11",
            expires_at=2_000_000_000,
            vault_record=record,
        )

    monkeypatch.setattr(
        zkpassport_enrollments,
        "verify_vault_session",
        fake_verify_session,
    )


def _request(coinset=None) -> Request:
    app = SimpleNamespace(state=SimpleNamespace(coinset=coinset))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("testserver", 443),
            "app": app,
        }
    )


def _coin_id(parent: str, policy_hash: str, amount: int = 1) -> str:
    return "0x" + Coin(
        bytes32.fromhex(parent.removeprefix("0x")),
        bytes32.fromhex(policy_hash.removeprefix("0x")),
        uint64(amount),
    ).name().hex()


def _bridge_record(parent: str = PARENT_A, *, amount: int = 1, puzzle_hash: str = POLICY_HASH) -> dict:
    return {
        "coin": {
            "parent_coin_info": parent,
            "puzzle_hash": puzzle_hash,
            "amount": amount,
        },
        "confirmed_block_index": 123,
        "spent_block_index": 0,
    }


def _indexed_event(
    *,
    vault_launcher_id: str = VAULT_A,
    bridge_parent_id: str = PARENT_A,
    bridge_policy_hash: str = POLICY_HASH,
    bridge_amount: int = 1,
) -> zkpassport_enrollments.IndexedEvmAttestation:
    return zkpassport_enrollments.IndexedEvmAttestation(
        sender=EVM_SENDER,
        vault_launcher_id=vault_launcher_id,
        scoped_nullifier="0x" + "12" * 32,
        nullifier_type=1,
        service_scope_hash="0x" + "13" * 32,
        service_subscope_hash="0x" + "14" * 32,
        proof_timestamp=1_700_000_000,
        attestation_leaf_hash=LEAF,
        identity_attest_root=ROOT,
        bridge_parent_id=bridge_parent_id,
        bridge_amount=bridge_amount,
        bridge_coin_id=_coin_id(bridge_parent_id, bridge_policy_hash, bridge_amount),
        bridge_message="0x" + "99" * 32,
        bridge_policy_hash=bridge_policy_hash,
        policy_version=2,
        validator_message=VALIDATOR_MESSAGE,
        transaction_hash=TX,
        block_number=456,
    )


def _client(
    monkeypatch,
    tmp_path,
    bridge_records: list[dict] | None = None,
) -> TestClient:
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_LEDGER_DB_PATH", str(tmp_path / "credential.db"))
    monkeypatch.setenv("SOLSLOT_ALPHA_WRITES_ENABLED", "true")
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH", POLICY_HASH)
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_AMOUNT", "1")
    _install_signed_artifact(monkeypatch)
    if bridge_records is None:
        bridge_records = [
            _bridge_record(PARENT_A),
            _bridge_record(PARENT_B),
        ]
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_bridge_coin_records",
        lambda _settings, _bridge_policy_hash: list(bridge_records or []),
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_verified_evm_attestation",
        lambda _settings, **kwargs: _indexed_event(
            vault_launcher_id=kwargs["expected_vault_launcher_id"]
        ),
    )
    registry = reset_registry_for_tests(tmp_path / "vault_registry.db")
    for index, vault in enumerate((VAULT_A, VAULT_B, VAULT_C), start=1):
        private_key = bytes([index]) * 32
        account = Account.from_key(private_key)
        owner_pubkey = eth_keys.PrivateKey(private_key).public_key.to_compressed_bytes()
        registry.record(
            VaultRecord(
                launcher_id=bytes32.fromhex(vault[2:]),
                full_puzhash=bytes32(b"\x01" * 32),
                p2_vault_puzhash=bytes32(b"\x02" * 32),
                auth_type=AUTH_TYPE_SECP256K1,
                owner_pubkey=owner_pubkey,
                owner_evm_address=account.address,
                spend_bundle_id="test-fixture",
                pushed_at=0,
            )
        )

    _install_owner_bypass(monkeypatch)
    return TestClient(app)


def test_create_enrollment_fails_closed_without_bridge_pool(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, bridge_records=[]) as client:
        resp = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})

    assert resp.status_code == 503
    assert "bridge coins" in resp.json()["detail"]


def test_malformed_vault_launcher_path_is_rejected_before_handler():
    with TestClient(app) as client:
        response = client.get("/zkpassport/enrollments/not-a-launcher")

    assert response.status_code == 422


def test_create_enrollment_rejects_noncanonical_bridge_amount(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, bridge_records=[_bridge_record(amount=2)]) as client:
        created = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})

    assert created.status_code == 503
    assert "signed-policy" in created.json()["detail"]


def test_create_enrollment_reserves_bridge_coin_and_gets_same_record(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        created = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        again = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        fetched = client.get(f"/zkpassport/enrollments/{VAULT_A}")

    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "reserved"
    assert body["bridgeParentId"] == PARENT_A
    assert body["bridgePolicyHash"] == POLICY_HASH
    assert body["bridgeCoinId"] == _coin_id(PARENT_A, POLICY_HASH)
    assert again.json()["bridgeParentId"] == PARENT_A
    assert fetched.json()["vaultLauncherId"] == VAULT_A


def test_bridge_coin_pool_is_single_use(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        first = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        second = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_B})
        third = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_C})

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["bridgeParentId"] == PARENT_B
    assert third.status_code == 409


def test_chia_confirmation_cannot_skip_stamp_submission(monkeypatch, tmp_path):
    vault_coin_id = _coin_id(VAULT_COIN_PARENT, VAULT_COIN_PUZZLE)
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_expected_stamped_vault_puzzle_hash",
        lambda _settings, **_kwargs: VAULT_COIN_PUZZLE,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_coin_record_by_name",
        lambda _settings, coin_id: {
            "coin": {
                "parent_coin_info": VAULT_COIN_PARENT,
                "puzzle_hash": VAULT_COIN_PUZZLE,
                "amount": 1,
            },
            "confirmed_block_index": 123,
            "spent_block_index": 0,
        }
        if coin_id == vault_coin_id
        else None,
    )
    with _client(monkeypatch, tmp_path, bridge_records=[_bridge_record()]) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        proof = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 2,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": enrollment["bridgeParentId"],
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": enrollment["bridgeCoinId"],
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )
        confirmed = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/chia-confirmation",
            json={
                "chiaVaultCoinId": vault_coin_id,
                "confirmedBlockIndex": 123,
            },
        )

    assert proof.status_code == 200
    assert proof.json()["status"] == "evm_confirmed"
    assert proof.json()["receipt"]["identityAttestRoot"] == ROOT
    assert proof.json()["receipt"]["validatorMessage"] == VALIDATOR_MESSAGE
    assert confirmed.status_code == 410
    assert "server indexes" in confirmed.json()["detail"].lower()


def test_chia_confirmation_rejects_client_only_coin_claim(monkeypatch, tmp_path):
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_expected_stamped_vault_puzzle_hash",
        lambda _settings, **_kwargs: VAULT_COIN_PUZZLE,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_coin_record_by_name",
        lambda _settings, _coin_id: None,
    )
    with _client(monkeypatch, tmp_path, bridge_records=[_bridge_record()]) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 2,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": enrollment["bridgeParentId"],
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": enrollment["bridgeCoinId"],
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )
        confirmed = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/chia-confirmation",
            json={
                "chiaVaultCoinId": "0x" + "77" * 32,
                "confirmedBlockIndex": 123,
            },
        )

    assert confirmed.status_code == 410
    assert "client-supplied" in confirmed.json()["detail"].lower()


def test_record_proof_rejects_wrong_reserved_bridge_coin(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, bridge_records=[_bridge_record()]) as client:
        enrollment = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        resp = client.post(
            f"/zkpassport/enrollments/{VAULT_A}/proof",
            json={
                "vaultLauncherId": VAULT_A,
                "policyVersion": 2,
                "identityAttestRoot": ROOT,
                "attestationLeafHash": LEAF,
                "attestationProof": {"bitpath": 0, "siblings": []},
                "bridgePolicyHash": enrollment["bridgePolicyHash"],
                "bridgeParentId": PARENT_B,
                "bridgeAmount": enrollment["bridgeAmount"],
                "bridgeCoinId": _coin_id(PARENT_B, POLICY_HASH),
                "bridgeMessage": "0x" + "99" * 32,
                "validatorMessage": VALIDATOR_MESSAGE,
                "evmTxHash": TX,
            },
        )

    assert resp.status_code == 409


def test_evm_proof_builds_and_confirms_atomic_chia_vault_stamp(monkeypatch, tmp_path):
    _install_owner_bypass(monkeypatch)
    monkeypatch.setenv("SOLSLOT_ALPHA_WRITES_ENABLED", "true")
    from solslot_puzzles.vault_driver import (
        AUTH_TYPE_SECP256K1,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        one_leaf_merkle_root,
        puzzle_for_p2_vault,
        puzzle_for_vault_full,
    )
    from solslot_puzzles.zkpassport_attestation import (
        ZkPassportAttestation,
        compute_attestation_bridge_message,
        compute_attestation_root,
        compute_validator_bridge_message,
    )
    from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash

    private_key = bytes.fromhex("01" * 32)
    account = Account.from_key(private_key)
    owner_pubkey = eth_keys.PrivateKey(private_key).public_key.to_compressed_bytes()
    validator_keys, policy_hash = _install_validator_quorum(monkeypatch, tmp_path)
    monkeypatch.setattr(zkpassport_enrollments, "_fetch_coin_record_by_name",
        lambda _settings, coin_id: {"coin": LAUNCHER_COIN_A.to_json_dict(),
            "confirmed_block_index": 100, "spent_block_index": 101}
        if coin_id == VAULT_A else None)
    policy_hex = "0x" + policy_hash.hex()
    launcher = bytes32.fromhex(VAULT_A.removeprefix("0x"))
    pool_launcher = bytes32(b"\x70" * 32)
    _install_signed_artifact(
        monkeypatch,
        bridge_policy_hash=policy_hex,
        pool_launcher_id="0x" + pool_launcher.hex(),
    )
    current_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_SECP256K1,
        one_leaf_merkle_root(owner_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=policy_hash,
    )
    current_coin = Coin(launcher, bytes32(current_puzzle.get_tree_hash()), uint64(1))
    bridge_parent = bytes32.fromhex(PARENT_A.removeprefix("0x"))
    bridge_coin = Coin(bridge_parent, policy_hash, uint64(1))
    attestation = ZkPassportAttestation(
        vault_launcher_id=launcher,
        scoped_nullifier=bytes32(b"\x12" * 32),
        nullifier_type=1,
        service_scope_hash=bytes32(b"\x13" * 32),
        service_subscope_hash=bytes32(b"\x14" * 32),
        proof_timestamp=1_700_000_000,
        policy_version=2,
    )
    root = compute_attestation_root([attestation.leaf_hash])
    bridge_message = compute_attestation_bridge_message(
        vault_launcher_id=launcher,
        attestation_root=root,
        bridge_policy_hash=policy_hash,
        policy_version=2,
    )
    validator_message = compute_validator_bridge_message(
        vault_launcher_id=launcher,
        attestation_root=root,
        bridge_policy_hash=policy_hash,
        bridge_coin_id=bridge_coin.name(),
        bridge_message=bridge_message,
        attestation_leaf_hash=attestation.leaf_hash,
        scoped_nullifier=attestation.scoped_nullifier,
        nullifier_type=attestation.nullifier_type,
        service_scope_hash=attestation.service_scope_hash,
        service_subscope_hash=attestation.service_subscope_hash,
        proof_timestamp=attestation.proof_timestamp,
        policy_version=2,
    )
    event = zkpassport_enrollments.IndexedEvmAttestation(
        sender=account.address,
        vault_launcher_id=VAULT_A,
        scoped_nullifier="0x" + attestation.scoped_nullifier.hex(),
        nullifier_type=attestation.nullifier_type,
        service_scope_hash="0x" + attestation.service_scope_hash.hex(),
        service_subscope_hash="0x" + attestation.service_subscope_hash.hex(),
        proof_timestamp=attestation.proof_timestamp,
        attestation_leaf_hash="0x" + attestation.leaf_hash.hex(),
        identity_attest_root="0x" + root.hex(),
        bridge_parent_id=PARENT_A,
        bridge_amount=1,
        bridge_coin_id="0x" + bridge_coin.name().hex(),
        bridge_message="0x" + bridge_message.hex(),
        bridge_policy_hash=policy_hex,
        policy_version=2,
        validator_message="0x" + validator_message.hex(),
        transaction_hash=TX,
        block_number=456,
    )

    monkeypatch.setenv(
        "SOLSLOT_ZKPASSPORT_LEDGER_DB_PATH",
        str(tmp_path / "credential.db"),
    )
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH", policy_hex)
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_AMOUNT", "1")
    monkeypatch.setenv("SOLSLOT_POOL_LAUNCHER_ID", "0x" + pool_launcher.hex())
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_bridge_coin_records",
        lambda _settings, _policy: [_bridge_record(puzzle_hash=policy_hex)],
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_verified_evm_attestation",
        lambda _settings, **_kwargs: event,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_find_initial_vault_coin",
        lambda _settings, _launcher: current_coin,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_verify_reserved_bridge_coin",
        lambda _settings, _record: bridge_coin,
    )
    pushed: list[dict] = []

    class FakeChiaProvider:
        async def push_tx(self, spend_bundle_json):
            ledger = get_credential_ledger(Settings())
            attempt = ledger.get_stamp_attempt(VAULT_A)
            stored = SpendBundle.from_bytes(bytes.fromhex(attempt["bundle_hex"]))
            assert stored.to_json_dict() == spend_bundle_json
            assert ledger.get_enrollment(VAULT_A)["status"] == "stamp_pending"
            assert attempt["dispatch_status"] == "unknown"
            pushed.append(spend_bundle_json)
            return {"success": True, "status": "SUCCESS"}

    fake_chia_provider = FakeChiaProvider()
    reset_registry_for_tests(tmp_path / "vault_registry.db")
    get_registry().record(
        VaultRecord(
            launcher_id=launcher,
            full_puzhash=bytes32(current_puzzle.get_tree_hash()),
            p2_vault_puzhash=bytes32(puzzle_for_p2_vault(launcher).get_tree_hash()),
            auth_type=AUTH_TYPE_SECP256K1,
            owner_pubkey=owner_pubkey,
            owner_evm_address=account.address,
            spend_bundle_id="test-launch",
            pushed_at=1.0,
        )
    )

    enrollment = asyncio.run(
        zkpassport_enrollments.create_enrollment(
            zkpassport_enrollments.CreateEnrollmentRequest(
                vaultLauncherId=VAULT_A,
            ),
            _request(fake_chia_provider),
        )
    )
    proof = zkpassport_enrollments.record_evm_proof(
        VAULT_A,
        zkpassport_enrollments.RecordProofRequest(
            vaultLauncherId=VAULT_A,
            policyVersion=2,
            identityAttestRoot=event.identity_attest_root,
            attestationLeafHash=event.attestation_leaf_hash,
            attestationProof={"bitpath": 0, "siblings": []},
            bridgePolicyHash=enrollment.bridgePolicyHash,
            bridgeParentId=enrollment.bridgeParentId,
            bridgeAmount=enrollment.bridgeAmount,
            bridgeCoinId=enrollment.bridgeCoinId,
            bridgeMessage=event.bridge_message,
            validatorMessage=event.validator_message,
            evmTxHash=TX,
        ),
        _request(),
    )
    prepared = zkpassport_enrollments.prepare_chia_stamp(
        VAULT_A,
        _request(),
    )
    signature = Account.sign_message(
        encode_typed_data(full_message=prepared.typedData),
        private_key,
    ).signature.hex()
    submitted = asyncio.run(
        zkpassport_enrollments.submit_evm_chia_stamp(
            VAULT_A,
            zkpassport_enrollments.SubmitChiaStampRequest(
                signature="0x" + signature,
            ),
            _request(fake_chia_provider),
        )
    )

    assert proof.status == "evm_confirmed"
    assert prepared.authType == "evm"
    assert submitted.enrollment.status == "stamp_pending"
    assert len(pushed) == 1
    assert len(pushed[0]["coin_spends"]) == 2
    submitted_bundle = SpendBundle.from_json_dict(pushed[0])
    validator_full_message = (
        bytes(validator_message)
        + bytes(bridge_coin.name())
        + zkpassport_enrollments.AGG_SIG_ME_DATA["testnet11"]
    )
    assert zkpassport_enrollments.AugSchemeMPL.aggregate_verify(
        [validator_keys[0].get_g1(), validator_keys[1].get_g1()],
        [validator_full_message, validator_full_message],
        submitted_bundle.aggregated_signature,
    )

    expected_coin_id = submitted.expectedVaultCoinId
    expected_puzzle_hash = zkpassport_enrollments._expected_stamped_vault_puzzle_hash(
        Settings(),
        vault_launcher_id=VAULT_A,
        identity_attest_root=event.identity_attest_root,
    )
    expected_parent = "0x" + current_coin.name().hex()
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_coin_record_by_name",
        lambda _settings, coin_id: {
            "coin": {
                "parent_coin_info": expected_parent,
                "puzzle_hash": expected_puzzle_hash,
                "amount": 1,
            },
            "confirmed_block_index": 789,
            "spent_block_index": 0,
        }
        if coin_id == expected_coin_id
        else None,
    )
    synced = zkpassport_enrollments.sync_chia_stamp(
        VAULT_A,
        _request(),
    )

    assert synced.confirmed is True
    assert synced.enrollment.status == "chia_confirmed"
    assert synced.enrollment.receipt is not None
    assert synced.enrollment.receipt.confirmedBlockIndex == 789


def test_bls_proof_requires_wallet_signature_for_atomic_chia_vault_stamp(
    monkeypatch, tmp_path
):
    _install_owner_bypass(monkeypatch)
    monkeypatch.setenv("SOLSLOT_ALPHA_WRITES_ENABLED", "true")
    from chia.types.blockchain_format.program import Program
    from solslot_api.state import VaultRecord, get_registry
    from solslot_puzzles.vault_driver import (
        AUTH_TYPE_BLS,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        one_leaf_merkle_root,
        puzzle_for_p2_vault,
        puzzle_for_vault_full,
    )
    from solslot_puzzles.zkpassport_attestation import (
        ZkPassportAttestation,
        compute_attestation_bridge_message,
        compute_attestation_root,
        compute_validator_bridge_message,
    )
    from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash

    owner_sk = zkpassport_enrollments.AugSchemeMPL.key_gen(bytes.fromhex("02" * 32))
    owner_pubkey = bytes(owner_sk.get_g1())
    validator_keys, policy_hash = _install_validator_quorum(monkeypatch, tmp_path)
    monkeypatch.setattr(zkpassport_enrollments, "_fetch_coin_record_by_name",
        lambda _settings, coin_id: {"coin": LAUNCHER_COIN_A.to_json_dict(),
            "confirmed_block_index": 100, "spent_block_index": 101}
        if coin_id == VAULT_A else None)
    policy_hex = "0x" + policy_hash.hex()
    launcher = bytes32.fromhex(VAULT_A.removeprefix("0x"))
    pool_launcher = bytes32(b"\x70" * 32)
    _install_signed_artifact(
        monkeypatch,
        bridge_policy_hash=policy_hex,
        pool_launcher_id="0x" + pool_launcher.hex(),
    )
    current_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_BLS,
        one_leaf_merkle_root(owner_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=policy_hash,
    )
    current_coin = Coin(launcher, bytes32(current_puzzle.get_tree_hash()), uint64(1))
    bridge_parent = bytes32.fromhex(PARENT_A.removeprefix("0x"))
    bridge_coin = Coin(bridge_parent, policy_hash, uint64(1))
    attestation = ZkPassportAttestation(
        vault_launcher_id=launcher,
        scoped_nullifier=bytes32(b"\x12" * 32),
        nullifier_type=1,
        service_scope_hash=bytes32(b"\x13" * 32),
        service_subscope_hash=bytes32(b"\x14" * 32),
        proof_timestamp=1_700_000_000,
        policy_version=2,
    )
    root = compute_attestation_root([attestation.leaf_hash])
    bridge_message = compute_attestation_bridge_message(
        vault_launcher_id=launcher,
        attestation_root=root,
        bridge_policy_hash=policy_hash,
        policy_version=2,
    )
    validator_message = compute_validator_bridge_message(
        vault_launcher_id=launcher,
        attestation_root=root,
        bridge_policy_hash=policy_hash,
        bridge_coin_id=bridge_coin.name(),
        bridge_message=bridge_message,
        attestation_leaf_hash=attestation.leaf_hash,
        scoped_nullifier=attestation.scoped_nullifier,
        nullifier_type=attestation.nullifier_type,
        service_scope_hash=attestation.service_scope_hash,
        service_subscope_hash=attestation.service_subscope_hash,
        proof_timestamp=attestation.proof_timestamp,
        policy_version=2,
    )
    event = zkpassport_enrollments.IndexedEvmAttestation(
        sender=EVM_SENDER,
        vault_launcher_id=VAULT_A,
        scoped_nullifier="0x" + attestation.scoped_nullifier.hex(),
        nullifier_type=attestation.nullifier_type,
        service_scope_hash="0x" + attestation.service_scope_hash.hex(),
        service_subscope_hash="0x" + attestation.service_subscope_hash.hex(),
        proof_timestamp=attestation.proof_timestamp,
        attestation_leaf_hash="0x" + attestation.leaf_hash.hex(),
        identity_attest_root="0x" + root.hex(),
        bridge_parent_id=PARENT_A,
        bridge_amount=1,
        bridge_coin_id="0x" + bridge_coin.name().hex(),
        bridge_message="0x" + bridge_message.hex(),
        bridge_policy_hash=policy_hex,
        policy_version=2,
        validator_message="0x" + validator_message.hex(),
        transaction_hash=TX,
        block_number=456,
    )

    monkeypatch.setenv(
        "SOLSLOT_ZKPASSPORT_LEDGER_DB_PATH",
        str(tmp_path / "credential.db"),
    )
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH", policy_hex)
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_AMOUNT", "1")
    monkeypatch.setenv("SOLSLOT_POOL_LAUNCHER_ID", "0x" + pool_launcher.hex())
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_bridge_coin_records",
        lambda _settings, _policy: [_bridge_record(puzzle_hash=policy_hex)],
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_fetch_verified_evm_attestation",
        lambda _settings, **_kwargs: event,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_find_initial_vault_coin",
        lambda _settings, _launcher: current_coin,
    )
    monkeypatch.setattr(
        zkpassport_enrollments,
        "_verify_reserved_bridge_coin",
        lambda _settings, _record: bridge_coin,
    )
    pushed: list[dict] = []

    class FakeChiaProvider:
        async def push_tx(self, spend_bundle_json):
            ledger = get_credential_ledger(Settings())
            attempt = ledger.get_stamp_attempt(VAULT_A)
            stored = SpendBundle.from_bytes(bytes.fromhex(attempt["bundle_hex"]))
            assert stored.to_json_dict() == spend_bundle_json
            assert ledger.get_enrollment(VAULT_A)["status"] == "stamp_pending"
            assert attempt["dispatch_status"] == "unknown"
            pushed.append(spend_bundle_json)
            return {"success": True, "status": "SUCCESS"}

    fake_chia_provider = FakeChiaProvider()
    reset_registry_for_tests(tmp_path / "vault_registry.db")
    get_registry().record(
        VaultRecord(
            launcher_id=launcher,
            full_puzhash=bytes32(current_puzzle.get_tree_hash()),
            p2_vault_puzhash=bytes32(puzzle_for_p2_vault(launcher).get_tree_hash()),
            auth_type=AUTH_TYPE_BLS,
            owner_pubkey=owner_pubkey,
            owner_evm_address=None,
            spend_bundle_id="test-launch",
            pushed_at=1.0,
        )
    )

    enrollment = asyncio.run(
        zkpassport_enrollments.create_enrollment(
            zkpassport_enrollments.CreateEnrollmentRequest(
                vaultLauncherId=VAULT_A,
            ),
            _request(fake_chia_provider),
        )
    )
    credential_ledger = get_credential_ledger(Settings())
    credential_ledger.reserve_relay(
        request_digest="0x" + "31" * 32,
        vault_launcher_id=VAULT_A,
        owner_key="0x" + owner_pubkey.hex(),
        source_ip="127.0.0.1",
        bridge_coin_id=enrollment.bridgeCoinId,
        forwarder_nonce=1,
        inner_gas=100_000,
        per_ip_per_minute=10,
        per_owner_per_minute=10,
        per_vault_per_hour=10,
        global_gas_per_day=1_000_000,
    )
    credential_ledger.finish_relay(
        request_digest="0x" + "31" * 32,
        tx_hash=TX,
        error=None,
        failure_threshold=5,
        cooldown_seconds=60,
    )
    proof = zkpassport_enrollments.record_evm_proof(
        VAULT_A,
        zkpassport_enrollments.RecordProofRequest(
            vaultLauncherId=VAULT_A,
            policyVersion=2,
            identityAttestRoot=event.identity_attest_root,
            attestationLeafHash=event.attestation_leaf_hash,
            attestationProof={"bitpath": 0, "siblings": []},
            bridgePolicyHash=enrollment.bridgePolicyHash,
            bridgeParentId=enrollment.bridgeParentId,
            bridgeAmount=enrollment.bridgeAmount,
            bridgeCoinId=enrollment.bridgeCoinId,
            bridgeMessage=event.bridge_message,
            validatorMessage=event.validator_message,
            evmTxHash=TX,
        ),
        _request(),
    )
    prepared = zkpassport_enrollments.prepare_chia_stamp(
        VAULT_A,
        _request(),
    )
    assert prepared.authType == "chia_bls"
    assert prepared.typedData is None
    assert prepared.currentTimestamp is not None
    assert prepared.vaultCoinSpend is not None
    assert prepared.vaultCoinSpend["coin"]["amount"] == 1

    owner_inner_message = bytes(
        Program.to([b"z", root, current_coin.name()]).get_tree_hash()
    )
    owner_message = (
        owner_inner_message
        + bytes(current_coin.name())
        + zkpassport_enrollments.AGG_SIG_ME_DATA["testnet11"]
    )
    owner_signature = zkpassport_enrollments.AugSchemeMPL.sign(
        owner_sk, owner_message
    )
    wrong_owner_sk = zkpassport_enrollments.AugSchemeMPL.key_gen(
        bytes.fromhex("03" * 32)
    )
    wrong_owner_signature = zkpassport_enrollments.AugSchemeMPL.sign(
        wrong_owner_sk, owner_message
    )
    with pytest.raises(zkpassport_enrollments.HTTPException) as wrong_error:
        asyncio.run(
            zkpassport_enrollments.submit_evm_chia_stamp(
                VAULT_A,
                zkpassport_enrollments.SubmitChiaStampRequest(
                    signature="0x" + bytes(wrong_owner_signature).hex(),
                    currentTimestamp=prepared.currentTimestamp,
                ),
                _request(),
            )
        )
    assert wrong_error.value.status_code == 400
    assert pushed == []

    with pytest.raises(zkpassport_enrollments.HTTPException) as stale_error:
        asyncio.run(
            zkpassport_enrollments.submit_evm_chia_stamp(
                VAULT_A,
                zkpassport_enrollments.SubmitChiaStampRequest(
                    signature="0x" + bytes(owner_signature).hex(),
                    currentTimestamp=prepared.currentTimestamp - 1000,
                ),
                _request(),
            )
        )
    assert stale_error.value.status_code == 409
    assert pushed == []

    submitted = asyncio.run(
        zkpassport_enrollments.submit_evm_chia_stamp(
            VAULT_A,
            zkpassport_enrollments.SubmitChiaStampRequest(
                signature="0x" + bytes(owner_signature).hex(),
                currentTimestamp=prepared.currentTimestamp,
            ),
            _request(fake_chia_provider),
        )
    )

    assert proof.status == "evm_confirmed"
    assert submitted.enrollment.status == "stamp_pending"
    assert len(pushed) == 1
    submitted_bundle = SpendBundle.from_json_dict(pushed[0])
    validator_full_message = (
        bytes(validator_message)
        + bytes(bridge_coin.name())
        + zkpassport_enrollments.AGG_SIG_ME_DATA["testnet11"]
    )
    assert zkpassport_enrollments.AugSchemeMPL.aggregate_verify(
        [owner_sk.get_g1(), validator_keys[0].get_g1(), validator_keys[1].get_g1()],
        [owner_message, validator_full_message, validator_full_message],
        submitted_bundle.aggregated_signature,
    )
