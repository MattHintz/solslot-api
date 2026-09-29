from __future__ import annotations

import json
from pathlib import Path

import pytest

from solslot_puzzles.identity_deployment_amendment import (
    ZERO_HASH,
    amendment_hash,
    announcement_message,
    build_statement,
    canonical_json,
)

from solslot_api.config import Settings
from solslot_api.identity_deployment import (
    ChainAmendment,
    IdentityDeploymentError,
    load_effective_identity_deployment,
)


BASE = json.loads(
    Path("/home/hiram/solslot-work/e2e-audit-draft144/evidence/public-artifact.json").read_text()
)
DEPLOYMENT = json.loads(
    Path(
        "/home/hiram/secure/solslot-deployments/"
        "AE-SOLSLOT-IDENTITY-COMPATIBILITY-20260928-148/deployment.json"
    ).read_text()
)
PLAN_HASH = "0xdb9912f4e47ec349d6fb67aa95f78058f8c64c757a22a2244af8f0d9a73a381b"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        public_artifact_path=str(tmp_path / "genesis.json"),
    )


def _statement():
    roster = ["0x" + f"{n:02x}" * 32 for n in (1, 2, 3)]
    return build_statement(
        base_artifact=BASE,
        deployment_artifact=DEPLOYMENT,
        deployment_plan_hash=PLAN_HASH,
        activation_source_shas={"protocol": "1" * 40, "api": "2" * 40},
        activation_boundary={
            "authorityLauncherId": BASE["launcherIds"]["adminAuthority"],
            "authorityCoinId": "0x" + "aa" * 32,
            "authorityVersion": 2,
            "rosterIdentityCoinIds": roster,
            "signerSlots": [0, 1],
            "signerIdentityCoinIds": roster[:2],
        },
        revision=1,
        previous_amendment_hash=ZERO_HASH,
        approval_expires_at=2_000_000_000,
    )


def _chain(statement):
    digest = amendment_hash(statement)
    return ChainAmendment(
        digest=digest,
        authority_coin_id=statement["activationBoundary"]["authorityCoinId"],
        authority_version=statement["activationBoundary"]["authorityVersion"],
        spent_height=4_800_000,
        announcement=announcement_message(digest),
    )


@pytest.mark.asyncio
async def test_genesis_is_used_only_with_no_confirmed_amendment(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "solslot_api.identity_deployment.load_signed_public_artifact", lambda _settings: BASE
    )

    async def none(**_kwargs):
        return ()

    monkeypatch.setattr("solslot_api.identity_deployment.discover_confirmed_identity_amendments", none)
    selected = await load_effective_identity_deployment(settings, provider=object())
    assert selected["source"] == "signed-genesis"
    assert selected["addresses"] == BASE["evmAddresses"]


@pytest.mark.asyncio
async def test_missing_body_fails_after_chain_activation(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    statement = _statement()
    monkeypatch.setattr(
        "solslot_api.identity_deployment.load_signed_public_artifact", lambda _settings: BASE
    )

    async def one(**_kwargs):
        return (_chain(statement),)

    monkeypatch.setattr("solslot_api.identity_deployment.discover_confirmed_identity_amendments", one)
    with pytest.raises(IdentityDeploymentError, match="body is missing"):
        await load_effective_identity_deployment(settings, provider=object())


@pytest.mark.asyncio
async def test_latest_confirmed_amendment_resolves(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    statement = _statement()
    amendment_path = tmp_path / "identity-amendment.json"
    deployment_path = tmp_path / "identity-deployment.json"
    amendment_path.write_bytes(canonical_json(statement))
    deployment_path.write_text(json.dumps(DEPLOYMENT))
    settings.identity_deployment_amendment_path = str(amendment_path)
    settings.identity_deployment_artifact_path = str(deployment_path)
    settings.identity_deployment_plan_hash = PLAN_HASH
    monkeypatch.setattr(
        "solslot_api.identity_deployment.load_signed_public_artifact", lambda _settings: BASE
    )

    async def one(**_kwargs):
        return (_chain(statement),)

    async def valid_boundary(**_kwargs):
        return None

    monkeypatch.setattr("solslot_api.identity_deployment.discover_confirmed_identity_amendments", one)
    monkeypatch.setattr("solslot_api.identity_deployment._verify_activation_boundary", valid_boundary)
    selected = await load_effective_identity_deployment(settings, provider=object())
    assert selected["source"] == "confirmed-authority-amendment"
    assert selected["revision"] == 1
    assert selected["addresses"]["attestationEmitter"] == DEPLOYMENT["attestationEmitterAddress"]


@pytest.mark.asyncio
async def test_prepared_unconfirmed_amendment_keeps_genesis_active(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    statement = _statement()
    amendment_path = tmp_path / "identity-amendment.json"
    deployment_path = tmp_path / "identity-deployment.json"
    amendment_path.write_bytes(canonical_json(statement))
    deployment_path.write_text(json.dumps(DEPLOYMENT))
    settings.identity_deployment_amendment_path = str(amendment_path)
    settings.identity_deployment_artifact_path = str(deployment_path)
    settings.identity_deployment_plan_hash = PLAN_HASH
    monkeypatch.setattr(
        "solslot_api.identity_deployment.load_signed_public_artifact", lambda _settings: BASE
    )

    async def none(**_kwargs):
        return ()

    monkeypatch.setattr("solslot_api.identity_deployment.discover_confirmed_identity_amendments", none)
    selected = await load_effective_identity_deployment(settings, provider=object())
    assert selected["source"] == "signed-genesis"
    assert selected["revision"] == 0
    assert selected["addresses"] == BASE["evmAddresses"]


@pytest.mark.asyncio
async def test_old_or_mixed_revision_fails_closed(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    statement = _statement()
    amendment_path = tmp_path / "identity-amendment.json"
    deployment_path = tmp_path / "identity-deployment.json"
    amendment_path.write_bytes(canonical_json(statement))
    deployment_path.write_text(json.dumps(DEPLOYMENT))
    settings.identity_deployment_amendment_path = str(amendment_path)
    settings.identity_deployment_artifact_path = str(deployment_path)
    settings.identity_deployment_plan_hash = PLAN_HASH
    monkeypatch.setattr(
        "solslot_api.identity_deployment.load_signed_public_artifact", lambda _settings: BASE
    )

    async def newer(**_kwargs):
        old = _chain(statement)
        return (old, ChainAmendment("0x" + "99" * 32, "0x" + "bb" * 32, 3, 4_800_010, b"x"))

    monkeypatch.setattr("solslot_api.identity_deployment.discover_confirmed_identity_amendments", newer)
    with pytest.raises(IdentityDeploymentError, match="latest confirmed revision"):
        await load_effective_identity_deployment(settings, provider=object())


@pytest.mark.asyncio
async def test_mutable_address_env_cannot_select_deployment(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    settings.zkpassport_emitter_address = DEPLOYMENT["attestationEmitterAddress"]
    settings.zkpassport_verifier_adapter_address = DEPLOYMENT["verifierAdapterAddress"]
    settings.zkpassport_forwarder_address = DEPLOYMENT["forwarderAddress"]
    monkeypatch.setattr(
        "solslot_api.identity_deployment.load_signed_public_artifact", lambda _settings: BASE
    )

    async def none(**_kwargs):
        return ()

    monkeypatch.setattr("solslot_api.identity_deployment.discover_confirmed_identity_amendments", none)
    selected = await load_effective_identity_deployment(settings, provider=object())
    assert selected["addresses"] == BASE["evmAddresses"]
    assert selected["addresses"]["attestationEmitter"] != settings.zkpassport_emitter_address
