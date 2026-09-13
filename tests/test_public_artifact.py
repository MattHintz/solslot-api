from __future__ import annotations

import json

import pytest
from chia_rs import AugSchemeMPL
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.config import Settings, get_settings
from solslot_api.admin_authority_v3 import build_admin_authority_v3_snapshot
from solslot_api.genesis_worker import execute
from solslot_api.protocol_artifacts import router
from solslot_api.public_artifact import (
    MAX_PUBLIC_ARTIFACT_BYTES,
    PublicArtifactError,
    load_signed_public_artifact,
    signed_admin_allowlist,
    verify_signed_public_artifact_file,
)
from solslot_puzzles.artifact_schema_v4 import artifact_signing_typed_data
from tests.test_genesis_api import _plan_body


SOURCE_SHAS = {
    name: f"{index:x}" * 40
    for index, name in enumerate(
        (
            "protocol",
            "evm",
            "omnichain",
            "api",
            "legacyBackend",
            "keyOfSolomon",
            "samuel",
            "customerWeb",
            "adminPortal",
        ),
        start=1,
    )
}


def _signed_artifact(*, signed_slots: tuple[int, ...] = (0, 2), accounts=None, ceremony_id=None) -> dict:
    accounts = accounts or [Account.create(f"public-artifact-admin-{slot}") for slot in range(3)]
    recovery_accounts = [
        Account.create(f"public-artifact-recovery-{slot}")
        for slot in range(3)
    ]
    recovery_bls_keys = [
        bytes(
            AugSchemeMPL.key_gen(
                bytes([0xD0 + slot]) * 32
            ).get_g1()
        )
        for slot in range(3)
    ]
    ceremony = {
        "ceremony_id": ceremony_id or "0x" + "91" * 32,
        "draft": {"sourceManifestVersion": 4, "sourceShas": SOURCE_SHAS},
        "invitations": [
            {
                "slot": slot + 1,
                "compressed_pubkey": "0x"
                + keys.PrivateKey(bytes(account.key))
                .public_key.to_compressed_bytes()
                .hex(),
            }
            for slot, account in enumerate(accounts)
        ],
    }
    plan_input = _plan_body()
    plan_input["adminRecoveryKits"] = [
        {
            "slot": slot,
            "revision": 1,
            "evmGuardian": recovery_accounts[slot].address,
            "recoveryBlsPubkey": "0x" + recovery_bls_keys[slot].hex(),
            "drillChallengeHash": "0x"
            + bytes([0xA0 + slot] * 32).hex(),
        }
        for slot in range(3)
    ]
    artifact = execute(
        {
            "operation": "artifact",
            "ceremony": ceremony,
            "planInput": plan_input,
            "expiresAt": 1_999_999_999,
            "spendBundleId": "0x" + "92" * 32,
            "confirmedBlockIndex": 1234,
            "buildTimestamp": "2026-07-14T00:00:00+00:00",
        }
    )["artifact"]
    assert artifact["schemaVersion"] == 4
    assert artifact["protocolVersion"] == "solslot-v2-rc23"
    assert artifact["genesisPlan"]["schema"] == "solslot-genesis-plan-v4"
    assert artifact["statutes"]["roots"]["liquidityVenues"] == (
        artifact["genesisPlan"]["state"]["statutesRoots"]["liquidityVenues"]
    )
    typed_data = artifact_signing_typed_data(artifact)
    artifact["signatures"] = [
        {
            "adminIndex": slot,
            "compressedPubkey": ceremony["invitations"][slot]["compressed_pubkey"],
            "signature": "0x"
            + bytes(
                accounts[slot]
                .sign_message(encode_typed_data(full_message=typed_data))
                .signature
            ).hex(),
        }
        for slot in signed_slots
    ]
    return artifact


def _settings(tmp_path, artifact: dict, **updates) -> Settings:
    path = tmp_path / "public_artifact_v4.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    values = {
        "runtime_environment": "test",
        "public_artifact_path": str(path),
        "release_metadata_path": str(tmp_path / "missing-release.json"),
        "cors_origins": "",
        "pool_launcher_id": artifact["launcherIds"]["pool"],
        "governance_launcher_id": artifact["launcherIds"]["governance"],
        "protocol_config_launcher_id": artifact["launcherIds"]["protocolConfig"],
        "vault_version_registry_launcher_id": artifact["launcherIds"][
            "vaultVersionRegistry"
        ],
        "zkpassport_bridge_policy_hash": artifact["bridgePolicy"]["policyHash"],
        "zkpassport_forwarder_address": artifact["evmAddresses"]["forwarder"],
        "zkpassport_verifier_adapter_address": artifact["evmAddresses"][
            "verifierAdapter"
        ],
        "zkpassport_emitter_address": artifact["evmAddresses"][
            "attestationEmitter"
        ],
        "zkpassport_validator_pubkeys": artifact["validatorSet"]["pubkeys"],
    }
    values.update(updates)
    return Settings(**values)


def test_loads_real_two_admin_signed_artifact(tmp_path) -> None:
    artifact = _signed_artifact()
    loaded = load_signed_public_artifact(_settings(tmp_path, artifact))
    assert loaded["artifactHash"] == artifact["artifactHash"]
    assert loaded["validatorSet"]["threshold"] == 2
    assert len(loaded["bridgePolicy"]["bridgeCoinIds"]) == 32


def test_signed_artifact_is_the_complete_admin_login_roster(tmp_path) -> None:
    artifact = _signed_artifact()
    allowlist = signed_admin_allowlist(_settings(tmp_path, artifact))
    expected_pubkeys = {
        str(value).lower()
        for value in artifact["adminAuthority"]["compressedPubkeys"]
    }
    expected_addresses = {
        keys.PublicKey.from_compressed_bytes(bytes.fromhex(value[2:]))
        .to_checksum_address()
        .lower()
        for value in expected_pubkeys
    }
    assert allowlist == expected_pubkeys | expected_addresses


@pytest.mark.asyncio
async def test_authority_snapshot_uses_the_same_signed_artifact(
    tmp_path,
) -> None:
    artifact = _signed_artifact()
    _settings(tmp_path, artifact, runtime_environment="development")
    snapshot = await build_admin_authority_v3_snapshot(artifact=artifact)

    assert snapshot.launcher_id == artifact["launcherIds"]["adminAuthority"]
    assert (
        snapshot.operational_mips_root_hash
        == artifact["adminAuthority"]["operationalMipsRootHash"]
    )
    assert snapshot.authority_rule == "slot0_and_one_of_slot1_slot2"
    assert snapshot.authority_version == artifact["stateVersions"]["adminAuthority"]
    assert snapshot.chain_verified is False


def test_rejects_tampering_and_insufficient_signature_quorum(tmp_path) -> None:
    tampered = _signed_artifact()
    tampered["launcherIds"]["pool"] = "0x" + "ff" * 32
    with pytest.raises(PublicArtifactError, match="invalid"):
        load_signed_public_artifact(_settings(tmp_path, tampered))

    one_signature = _signed_artifact(signed_slots=(1,))
    with pytest.raises(PublicArtifactError, match="two administrator signatures"):
        load_signed_public_artifact(_settings(tmp_path, one_signature))


def test_rejects_oversized_public_artifact_before_worker_execution(tmp_path) -> None:
    path = tmp_path / "oversized-artifact.json"
    path.write_bytes(b" " * (MAX_PUBLIC_ARTIFACT_BYTES + 1))

    with pytest.raises(PublicArtifactError, match="size limit"):
        verify_signed_public_artifact_file(path)


def test_rejects_runtime_coordinate_and_release_commit_drift(tmp_path) -> None:
    artifact = _signed_artifact()
    wrong_pool = _settings(tmp_path, artifact, pool_launcher_id="0x" + "fe" * 32)
    with pytest.raises(PublicArtifactError, match="pool launcher"):
        load_signed_public_artifact(wrong_pool)

    missing_forwarder = _settings(
        tmp_path,
        artifact,
        zkpassport_forwarder_address=None,
    )
    with pytest.raises(PublicArtifactError, match="forwarder address"):
        load_signed_public_artifact(missing_forwarder)

    wrong_verifier_adapter = _settings(
        tmp_path,
        artifact,
        zkpassport_verifier_adapter_address="0x" + "fd" * 20,
    )
    with pytest.raises(PublicArtifactError, match="verifier adapter address"):
        load_signed_public_artifact(wrong_verifier_adapter)

    release_path = tmp_path / "release.json"
    release_path.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "protocolVersion": "solslot-v2",
                "api_commit": "a" * 40,
                "protocol_commit": SOURCE_SHAS["protocol"],
                "built_at_utc": "2026-07-14T00:00:00Z",
                "package_name": "solslot_api",
                "app_module": "solslot_api.app:app",
            }
        ),
        encoding="utf-8",
    )
    release_drift = _settings(
        tmp_path,
        artifact,
        release_metadata_path=str(release_path),
    )
    with pytest.raises(PublicArtifactError, match="API release commit"):
        load_signed_public_artifact(release_drift)


def test_public_endpoint_returns_only_verified_artifact(tmp_path) -> None:
    artifact = _signed_artifact()
    settings = _settings(tmp_path, artifact)
    api = FastAPI()
    api.include_router(router)
    api.dependency_overrides[get_settings] = lambda: settings
    response = TestClient(api).get("/protocol/artifact")
    assert response.status_code == 200
    assert response.json()["artifactHash"] == artifact["artifactHash"]

    artifact["network"] = "mainnet"
    settings = _settings(tmp_path, artifact)
    api.dependency_overrides[get_settings] = lambda: settings
    response = TestClient(api).get("/protocol/artifact")
    assert response.status_code == 503
    assert response.json()["detail"] == "The signed RC23 public artifact failed verification."
