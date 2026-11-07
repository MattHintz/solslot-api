from __future__ import annotations

import asyncio
import json

import pytest
from chia_rs import AugSchemeMPL
from fastapi.testclient import TestClient

from solslot_api.validator_app import create_validator_app
from solslot_api.validator_ledger import ValidatorLedger
from solslot_api.validator_service import (
    ValidatorEvidenceError,
    load_stripe_restricted_key,
    load_validator_private_key,
)
from solslot_api.validator_settings import ValidatorSettings
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash


def _settings(tmp_path) -> ValidatorSettings:
    keys = [AugSchemeMPL.key_gen(bytes([index]) * 32) for index in (31, 32, 33)]
    pubkeys = ["0x" + bytes(key.get_g1()).hex() for key in keys]
    seed_file = tmp_path / "validator.seed"
    seed_file.write_text((bytes([31]) * 32).hex() + "\n", encoding="ascii")
    seed_file.chmod(0o600)
    release = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "api_commit": "a" * 40,
        "protocol_commit": "b" * 40,
        "built_at_utc": "2026-07-14T00:00:00Z",
        "package_name": "solslot-api-test.tgz",
        "app_module": "solslot_api.app:app",
    }
    release_path = tmp_path / "release.json"
    release_path.write_text(json.dumps(release), encoding="utf-8")
    policy = make_bridge_policy_hash(
        [bytes(key.get_g1()) for key in keys],
        2,
    )
    return ValidatorSettings(
        signer_index=0,
        seed_file=str(seed_file),
        ledger_db_path=str(tmp_path / "ledger.db"),
        public_artifact_path=str(tmp_path / "artifact.json"),
        release_metadata_path=str(release_path),
        evm_rpc_url="https://sepolia.example.invalid",
        bridge_policy_hash="0x" + bytes(policy).hex(),
        roster_pubkeys=pubkeys,
        evm_forwarder_address="0x" + "11" * 20,
        evm_verifier_adapter_address="0x" + "22" * 20,
        evm_attestation_emitter_address="0x" + "33" * 20,
    )


def _enable_stripe(
    settings: ValidatorSettings,
    key_file,
) -> ValidatorSettings:
    settings.stripe_settlement_enabled = True
    settings.stripe_account_id = "acct_test_solslot"
    settings.stripe_mode = "test"
    settings.stripe_restricted_key_file = str(key_file)
    return settings


def _run_lifespan(app) -> None:
    async def run() -> None:
        async with app.router.lifespan_context(app):
            pass

    asyncio.run(run())


def test_private_signer_health_exposes_public_fingerprints_only(tmp_path) -> None:
    settings = _settings(tmp_path)
    ledger = ValidatorLedger(":memory:")
    app = create_validator_app(settings=settings, ledger=ledger)
    try:
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["status"] == "healthy"
            assert body["signerIndex"] == 0
            assert body["validatorPubkey"] == settings.roster_pubkeys[0]
            assert body["artifactReady"] is False
            assert body["ledgerReady"] is True
            # A healthy signer response must be accepted by the coordinator,
            # including identity-revision fields. Separate schema copies had
            # drifted and caused healthy signers to be rejected by consumers.
            from solslot_api.validator_quorum import ValidatorHealthResponse as ConsumedHealth
            parsed=ConsumedHealth.model_validate(body)
            assert parsed.validatorPubkey==body['validatorPubkey']
            assert client.get("/openapi.json").status_code == 404
    finally:
        ledger.close()


def test_seed_file_permissions_fail_closed(tmp_path) -> None:
    settings = _settings(tmp_path)
    seed_file = tmp_path / "validator.seed"
    seed_file.chmod(0o644)
    try:
        load_validator_private_key(settings)
    except ValidatorEvidenceError as exc:
        assert "group/other" in str(exc)
    else:
        raise AssertionError("world-readable validator seed was accepted")


def test_group_readable_seed_outside_systemd_credentials_fails_closed(
    tmp_path,
) -> None:
    settings = _settings(tmp_path)
    seed_file = tmp_path / "validator.seed"
    seed_file.chmod(0o640)

    try:
        load_validator_private_key(settings)
    except ValidatorEvidenceError as exc:
        assert "group/other" in str(exc)
    else:
        raise AssertionError("ordinary group-readable validator seed was accepted")


def test_ubuntu_systemd_credential_mount_is_accepted(tmp_path, monkeypatch) -> None:
    credentials_directory = tmp_path / "credentials"
    credentials_directory.mkdir(mode=0o750)
    seed_file = credentials_directory / "validator-seed"
    seed_file.write_text((bytes([31]) * 32).hex() + "\n", encoding="ascii")
    seed_file.chmod(0o440)
    settings = _settings(tmp_path)
    settings.seed_file = str(seed_file)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    private_key = load_validator_private_key(settings)

    assert "0x" + bytes(private_key.get_g1()).hex() == settings.roster_pubkeys[0]


def test_writable_systemd_credential_directory_fails_closed(
    tmp_path, monkeypatch
) -> None:
    credentials_directory = tmp_path / "credentials"
    credentials_directory.mkdir(mode=0o770)
    credentials_directory.chmod(0o770)
    seed_file = credentials_directory / "validator-seed"
    seed_file.write_text((bytes([31]) * 32).hex() + "\n", encoding="ascii")
    seed_file.chmod(0o440)
    settings = _settings(tmp_path)
    settings.seed_file = str(seed_file)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    try:
        load_validator_private_key(settings)
    except ValidatorEvidenceError as exc:
        assert "group/other" in str(exc)
    else:
        raise AssertionError("credential from a group-writable directory was accepted")


def test_writable_systemd_credential_file_fails_closed(tmp_path, monkeypatch) -> None:
    credentials_directory = tmp_path / "credentials"
    credentials_directory.mkdir(mode=0o750)
    seed_file = credentials_directory / "validator-seed"
    seed_file.write_text((bytes([31]) * 32).hex() + "\n", encoding="ascii")
    seed_file.chmod(0o640)
    settings = _settings(tmp_path)
    settings.seed_file = str(seed_file)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    try:
        load_validator_private_key(settings)
    except ValidatorEvidenceError as exc:
        assert "group/other" in str(exc)
    else:
        raise AssertionError("writable systemd credential was accepted")


def test_ubuntu_systemd_stripe_credential_mount_is_accepted(
    tmp_path,
    monkeypatch,
) -> None:
    credentials_directory = tmp_path / "credentials"
    credentials_directory.mkdir(mode=0o750)
    key_file = credentials_directory / "stripe-read-key"
    key_value = "rk_test_" + "a" * 24
    key_file.write_text(key_value, encoding="ascii")
    key_file.chmod(0o440)
    settings = _enable_stripe(_settings(tmp_path), key_file)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    assert load_stripe_restricted_key(settings) == key_value


@pytest.mark.parametrize(
    ("name", "file_mode", "directory_mode"),
    (
        ("unexpected-read-key", 0o440, 0o750),
        ("stripe-read-key", 0o640, 0o750),
        ("stripe-read-key", 0o440, 0o770),
    ),
)
def test_unsafe_systemd_stripe_credentials_fail_closed(
    tmp_path,
    monkeypatch,
    name: str,
    file_mode: int,
    directory_mode: int,
) -> None:
    credentials_directory = tmp_path / "credentials"
    credentials_directory.mkdir(mode=directory_mode)
    credentials_directory.chmod(directory_mode)
    key_file = credentials_directory / name
    key_file.write_text("rk_test_" + "a" * 24, encoding="ascii")
    key_file.chmod(file_mode)
    settings = _enable_stripe(_settings(tmp_path), key_file)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    with pytest.raises(ValidatorEvidenceError, match="group/other"):
        load_stripe_restricted_key(settings)


def test_group_readable_stripe_key_outside_credentials_fails_closed(
    tmp_path,
    monkeypatch,
) -> None:
    credentials_directory = tmp_path / "credentials"
    credentials_directory.mkdir(mode=0o750)
    key_file = tmp_path / "stripe-read-key"
    key_file.write_text("rk_test_" + "a" * 24, encoding="ascii")
    key_file.chmod(0o440)
    settings = _enable_stripe(_settings(tmp_path), key_file)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    with pytest.raises(ValidatorEvidenceError, match="group/other"):
        load_stripe_restricted_key(settings)


def test_startup_does_not_require_stripe_key_when_settlement_is_disabled(
    tmp_path,
) -> None:
    settings = _settings(tmp_path)
    settings.stripe_restricted_key_file = str(tmp_path / "missing-stripe-key")
    ledger = ValidatorLedger(":memory:")
    app = create_validator_app(settings=settings, ledger=ledger)
    try:
        _run_lifespan(app)
    finally:
        ledger.close()


def test_startup_validates_enabled_stripe_key(tmp_path) -> None:
    key_file = tmp_path / "stripe.read.key"
    key_file.write_text("rk_live_" + "a" * 24, encoding="ascii")
    key_file.chmod(0o600)
    settings = _enable_stripe(_settings(tmp_path), key_file)
    ledger = ValidatorLedger(":memory:")
    app = create_validator_app(settings=settings, ledger=ledger)
    try:
        with pytest.raises(
            ValidatorEvidenceError,
            match="does not match the configured mode",
        ):
            _run_lifespan(app)
    finally:
        ledger.close()


def test_startup_accepts_valid_enabled_stripe_key(tmp_path) -> None:
    key_file = tmp_path / "stripe.read.key"
    key_file.write_text("rk_test_" + "a" * 24, encoding="ascii")
    key_file.chmod(0o600)
    settings = _enable_stripe(_settings(tmp_path), key_file)
    ledger = ValidatorLedger(":memory:")
    app = create_validator_app(settings=settings, ledger=ledger)
    try:
        _run_lifespan(app)
    finally:
        ledger.close()
