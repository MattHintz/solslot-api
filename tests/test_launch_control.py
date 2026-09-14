from __future__ import annotations

import gc
import json
import time
from pathlib import Path

import pytest
from tests.launch_authority_fixtures import install_signed_authority
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI, HTTPException, Response
from fastapi.testclient import TestClient
from chia_rs import AugSchemeMPL

import solslot_api.launch_control as launch_control_module
from solslot_api.config import Settings, get_settings
from solslot_api.genesis import get_genesis_store
from solslot_api.genesis_store import GenesisConflict, GenesisExpired, GenesisStore
from solslot_api.launch_control import router


ADMIN_TOKEN = "deployment-owner-link-token-that-is-long-enough"
LEGACY_ADMIN_TOKEN = "legacy-operator-token-that-is-also-long-enough"
SOURCE_KEYS = (
    "protocol",
    "evm",
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
    "customerWeb",
    "adminPortal",
)


def _sign(account, typed_data: dict) -> str:
    signed = account.sign_message(encode_typed_data(full_message=typed_data))
    return "0x" + bytes(signed.signature).hex()


def _client(tmp_path) -> tuple[TestClient, GenesisStore, Settings]:
    # Callers can import this helper without importing TestClient, so the
    # module-detection fixture cannot protect this boundary. Finalize prior
    # CLVM exception cycles on their owning test thread before starting an
    # HTTP portal thread. Keep unraisable exceptions fatal in the test runner.
    gc.collect()
    release_tag = "solslot-v2-alpha-rc27-20260804"
    release_branch = "release/testnet-alpha-rc27-20260804"
    source_shas = {
        name: f"{index:x}" * 40
        for index, name in enumerate(SOURCE_KEYS, start=1)
    }
    source_manifest = {
        "schemaVersion": 4,
        "kind": "solslot-release-source-manifest",
        "releaseId": release_tag,
        "network": "testnet11",
        "testOnly": True,
        "sourceShas": source_shas,
        "dependencies": {
            "administratorRecovery": {
                "repository": (
                    launch_control_module.PINNED_CNI_WALLET_SDK_REPOSITORY
                ),
                "commit": (
                    launch_control_module.PINNED_CNI_WALLET_SDK_COMMIT
                ),
                "license": (
                    launch_control_module.PINNED_CNI_WALLET_SDK_LICENSE
                ),
                "manifestHash": (
                    launch_control_module
                    .RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
                ),
            }
        },
        "authoritySourceCommitment": (
            launch_control_module._authority_source_commitment(
                source_shas
            )
        ),
        "sources": {
            name: {
                "repository": f"https://github.com/solslot/{name}",
                "branch": release_branch,
                "commit": source_shas[name],
            }
            for name in SOURCE_KEYS
        },
    }
    source_manifest["manifestHash"] = (
        launch_control_module._source_manifest_hash(source_manifest)
    )
    evidence = {
        "schemaVersion": 5,
        "kind": "solslot-rc27-launch-source-evidence",
        "network": "testnet11",
        "testOnly": True,
        "completeReleaseManifest": True,
        "releaseRefsVerified": True,
        "releaseTag": release_tag,
        "releaseId": release_tag,
        "manifestHash": source_manifest["manifestHash"],
        "sourceManifest": source_manifest,
    }
    evidence_path = tmp_path / "source-freeze.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        launch_control_enabled=True,
        launch_release_tag=release_tag,
        launch_source_evidence_path=str(evidence_path),
        launch_source_evidence_sha256=None,
        launch_session_secret="launch-session-secret-for-tests!",
        launch_owner_claim_token=ADMIN_TOKEN,
        launch_cookie_path="/admin/launch",
        bootstrap_cookie_secure=False,
        admin_token=LEGACY_ADMIN_TOKEN,
        genesis_db_path=str(tmp_path / "genesis.db"),
        genesis_output_dir=str(tmp_path / "ceremonies"),
        public_artifact_path=str(tmp_path / "not-published.json"),
        bootstrap_manifest_path=str(tmp_path / "not-locked.json"),
    )
    store = GenesisStore(settings.genesis_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_genesis_store] = lambda: store
    return TestClient(app), store, settings


def test_client_helper_finalizes_prior_program_cycles_on_owner_thread(tmp_path):
    import threading
    from chia.types.blockchain_format.program import Program

    released_on = []

    class OwnerSentinel:
        def __del__(self):
            released_on.append(threading.get_ident())

    # Model a retained exception-frame cycle from an earlier protocol test.
    # Disable automatic GC to exercise the helper's explicit boundary.
    enabled = gc.isenabled()
    gc.disable()
    try:
        cycle = [Program.from_bytes(b"\xff\x01\x80"), OwnerSentinel()]
        cycle.append(cycle)
        del cycle
        client, _, _ = _client(tmp_path)
        try:
            assert released_on == [threading.get_ident()]
        finally:
            client.close()
    finally:
        gc.collect()
        if enabled:
            gc.enable()


def _plan_template(kos_pubkey: bytes) -> dict:
    validator_pubkeys = [
        bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
        for index in (21, 22, 23)
    ]
    governance_pubkey = bytes(AugSchemeMPL.key_gen(b"g" * 32).get_g1())
    return {
        "evmAddresses": {
            "forwarder": "0x" + "a1" * 20,
            "verifierAdapter": "0x" + "a2" * 20,
            "attestationEmitter": "0x" + "a3" * 20,
        },
        "faucetPuzzleHash": "0x" + "31" * 32,
        "governanceBlsPubkey": "0x" + governance_pubkey.hex(),
        "kosMintExecutePubkey": "0x" + kos_pubkey.hex(),
        "validatorPubkeys": ["0x" + value.hex() for value in validator_pubkeys],
        "trustedTreasuryReservePuzzleHash": "0x" + "41" * 32,
        "trustedProtocolTreasuryPuzzleHash": "0x" + "42" * 32,
        "companySgtSaleTreasuryPuzzleHash": "0x" + "45" * 32,
        "wusdcBAssetId": "0x" + "46" * 32,
        "trustedGovernanceRewardsPuzzleHash": "0x" + "43" * 32,
        "trustedGovernanceRewardsRoot": "0x" + "44" * 32,
        "retiredCoordinates": ["0x" + "51" * 32],
        "protocolParameters": {
            "votingWindowSeconds": 300,
            "quorumBps": 5000,
            "minProposalStake": 10_000,
            "navValiditySeconds": 86_400,
            "oracleMaxAgeSeconds": 600,
            "exchangeFeeBps": 100,
            "protocolFeeBps": 30,
            "sgtRewardsFeeBps": 70,
            "rewardEpochSeconds": 86_400,
        },
    }


def test_release_evidence_binds_recovery_sdk_and_authority_source(
    tmp_path,
) -> None:
    _, _, settings = _client(tmp_path)
    loaded = launch_control_module._load_release_evidence(settings)
    assert loaded["recoveryDependencyManifestHash"] == (
        launch_control_module.RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
    )

    path = settings.launch_source_evidence_path
    assert path is not None
    payload = json.loads(open(path, encoding="utf-8").read())
    manifest = payload["sourceManifest"]
    manifest["dependencies"]["administratorRecovery"]["commit"] = (
        "f" * 40
    )
    manifest["manifestHash"] = (
        launch_control_module._source_manifest_hash(manifest)
    )
    payload["manifestHash"] = manifest["manifestHash"]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)

    with pytest.raises(Exception, match="pinned recovery SDK"):
        launch_control_module._load_release_evidence(settings)


def test_release_evidence_rejects_authority_commitment_drift(
    tmp_path,
) -> None:
    _, _, settings = _client(tmp_path)
    path = settings.launch_source_evidence_path
    assert path is not None
    payload = json.loads(open(path, encoding="utf-8").read())
    manifest = payload["sourceManifest"]
    manifest["authoritySourceCommitment"] = "0x" + "ff" * 32
    manifest["manifestHash"] = (
        launch_control_module._source_manifest_hash(manifest)
    )
    payload["manifestHash"] = manifest["manifestHash"]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)

    with pytest.raises(Exception, match="source commitment"):
        launch_control_module._load_release_evidence(settings)


def _claim_and_enroll_owner(client: TestClient):
    owner = Account.create("launch-owner")
    claimed = client.post(
        "/admin/launch/claim",
        json={
            "token": ADMIN_TOKEN,
            "displayName": "Owner Admin",
            "email": "owner@example.com",
            "timezone": "America/Chicago",
        },
    )
    assert claimed.status_code == 200, claimed.text
    token = claimed.json()["ownerEnrollmentToken"]
    prepared = client.post(
        "/admin/launch/invitations/prepare",
        json={"token": token, "wallet": owner.address},
    )
    assert prepared.status_code == 200, prepared.text
    accepted = client.post(
        "/admin/launch/invitations/accept",
        json={
            "token": token,
            "wallet": owner.address,
            "signature": _sign(owner, prepared.json()["typedData"]),
        },
    )
    assert accepted.status_code == 200, accepted.text
    challenge = client.post(
        "/admin/launch/auth/challenge", json={"wallet": owner.address}
    )
    assert challenge.status_code == 200, challenge.text
    login = client.post(
        "/admin/launch/auth/login",
        json={
            "wallet": owner.address,
            "nonce": challenge.json()["nonce"],
            "signature": _sign(owner, challenge.json()["typedData"]),
        },
    )
    assert login.status_code == 200, login.text
    return owner, claimed.json()["ceremonyId"]


def _enroll_coadmin(client: TestClient, slot: int = 2):
    coadmin = Account.create(f"launch-coadmin-{slot}")
    invited = client.post(
        f"/admin/launch/invitations/{slot}",
        json={
            "displayName": f"Coadministrator {slot}",
            "timezone": "America/Chicago",
            "remindersEnabled": True,
        },
    )
    assert invited.status_code == 200, invited.text
    token = invited.json()["invitationFragment"].split("=", 1)[1]
    prepared = client.post(
        "/admin/launch/invitations/prepare",
        json={"token": token, "wallet": coadmin.address},
    )
    assert prepared.status_code == 200, prepared.text
    accepted = client.post(
        "/admin/launch/invitations/accept",
        json={
            "token": token,
            "wallet": coadmin.address,
            "signature": _sign(coadmin, prepared.json()["typedData"]),
        },
    )
    assert accepted.status_code == 200, accepted.text
    challenge = client.post(
        "/admin/launch/auth/challenge", json={"wallet": coadmin.address}
    )
    assert challenge.status_code == 200, challenge.text
    login = client.post(
        "/admin/launch/auth/login",
        json={
            "wallet": coadmin.address,
            "nonce": challenge.json()["nonce"],
            "signature": _sign(coadmin, challenge.json()["typedData"]),
        },
    )
    assert login.status_code == 200, login.text
    return coadmin


def _login(client: TestClient, account) -> None:
    challenge = client.post(
        "/admin/launch/auth/challenge", json={"wallet": account.address}
    )
    assert challenge.status_code == 200, challenge.text
    login = client.post(
        "/admin/launch/auth/login",
        json={
            "wallet": account.address,
            "nonce": challenge.json()["nonce"],
            "signature": _sign(account, challenge.json()["typedData"]),
        },
    )
    assert login.status_code == 200, login.text


def _mark_launch_locked(store: GenesisStore, ceremony_id: str, settings, accounts) -> None:
    install_signed_authority(settings, ceremony_id, accounts)
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='locked' WHERE ceremony_id=?",
            (ceremony_id,),
        )


def test_owner_link_is_single_use_and_scrubbed_into_http_only_session(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    legacy_credential = client.post(
        "/admin/launch/claim",
        json={"token": LEGACY_ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert legacy_credential.status_code == 403

    claimed = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert claimed.status_code == 200, claimed.text
    cookie = claimed.headers["set-cookie"]
    assert "solslot_launch_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/admin/launch" in cookie
    assert ADMIN_TOKEN not in cookie
    assert store.active()["invitations"][0]["slot"] == 1

    repeated = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert repeated.status_code == 409
    assert "already consumed" in repeated.json()["detail"]


def test_guided_owner_claim_rejects_browser_review_class(tmp_path) -> None:
    client, store, _ = _client(tmp_path)

    rejected = client.post(
        "/admin/launch/claim",
        json={
            "token": ADMIN_TOKEN,
            "displayName": "Owner Admin",
            "reviewClass": "internal-engineering-testnet",
        },
    )

    assert rejected.status_code == 422
    assert store.active() is None


@pytest.mark.asyncio
async def test_guided_owner_claim_uses_server_review_class(
    tmp_path,
) -> None:
    _, store, settings = _client(tmp_path)
    assert settings.launch_genesis_review_class == "independent-release-review"

    claimed = await launch_control_module.claim_owner_link(
        launch_control_module.OwnerClaimRequest(
            token=ADMIN_TOKEN, display_name="Owner Admin"
        ),
        Response(),
        settings,
        store,
    )

    assert claimed["claimed"] is True
    assert store.active()["draft"]["reviewClass"] == "independent-release-review"


@pytest.mark.asyncio
async def test_guided_internal_disposable_flow_requires_server_selection(
    tmp_path,
) -> None:
    _, store, settings = _client(tmp_path)
    settings.launch_genesis_review_class = "internal-engineering-testnet"

    claimed = await launch_control_module.claim_owner_link(
        launch_control_module.OwnerClaimRequest(
            token=ADMIN_TOKEN, display_name="Internal Test Owner"
        ),
        Response(),
        settings,
        store,
    )

    assert claimed["claimed"] is True
    assert store.active()["draft"]["reviewClass"] == "internal-engineering-testnet"


@pytest.mark.asyncio
async def test_official_claim_rejects_stale_internal_draft_without_consuming_link(
    tmp_path,
) -> None:
    _, store, settings = _client(tmp_path)
    release = launch_control_module._load_release_evidence(settings)
    stale_ceremony = "0x" + "ac" * 32
    store.create_draft(
        stale_ceremony,
        {
            "schemaVersion": 2,
            "sourceManifestVersion": launch_control_module.SOURCE_MANIFEST_VERSION,
            "network": "testnet11",
            "evmChainId": 11155111,
            "reviewClass": "internal-engineering-testnet",
            "releaseTag": release["releaseTag"],
            "releaseEvidenceHash": release["fileSha256"],
            "sourceShas": release["sourceShas"],
        },
        now=100,
    )
    body = launch_control_module.OwnerClaimRequest(
        token=ADMIN_TOKEN,
        display_name="Official Owner",
    )

    with pytest.raises(HTTPException) as exc_info:
        await launch_control_module.claim_owner_link(
            body,
            Response(),
            settings,
            store,
        )

    assert exc_info.value.status_code == 409
    assert "protected launch policy" in str(exc_info.value.detail)
    claim_hash = launch_control_module._token_hash(ADMIN_TOKEN)
    assert store.owner_claim_used(claim_hash) is False
    assert store.active()["ceremony_id"] == stale_ceremony

    store.abandon(
        stale_ceremony,
        "Superseded by the protected official release policy.",
        now=101,
    )
    claimed = await launch_control_module.claim_owner_link(
        body,
        Response(),
        settings,
        store,
    )

    assert claimed["claimed"] is True
    assert claimed["ceremonyId"] != stale_ceremony
    assert store.active()["draft"]["reviewClass"] == "independent-release-review"
    assert store.owner_claim_used(claim_hash) is True


def test_enrolled_wallet_resumes_without_token_or_ceremony_id(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    owner, ceremony_id = _claim_and_enroll_owner(client)
    workspace = client.get("/admin/launch/workspace")
    assert workspace.status_code == 200, workspace.text
    body = workspace.json()
    assert body["session"]["slot"] == 1
    assert body["session"]["role"] == "owner"
    assert body["launch"]["ceremonyId"] == ceremony_id
    assert body["launch"]["administrators"][0]["enrolled"] is True
    assert body["notice"] == "TESTNET, NO REAL INVESTMENT OR LEGAL RIGHT."
    plan_readiness = next(
        item for item in body["readiness"] if item["id"] == "planInputs"
    )
    assert plan_readiness["status"] == "Blocked"
    assert plan_readiness["action"] == "replacePlanEvidence"
    assert "browser" in plan_readiness["impact"]
    assert "plan-input-template" not in plan_readiness["impact"]

    evm_readiness = next(
        item for item in body["readiness"] if item["id"] == "evmEvidence"
    )
    assert evm_readiness["status"] == "Blocked"
    assert evm_readiness["action"] == "installEvmEvidence"
    assert evm_readiness["evidence"]["deploymentEvidenceInstalled"] is False
    assert "auditApprovalInstalled" not in evm_readiness["evidence"]

    audit_readiness = next(
        item for item in body["readiness"] if item["id"] == "planAudit"
    )
    assert audit_readiness["status"] == "Waiting"
    assert audit_readiness["blocksCeremony"] is False
    assert audit_readiness["evidence"]["auditApprovalRequired"] is False

    validator_readiness = next(
        item for item in body["readiness"] if item["id"] == "validators"
    )
    assert validator_readiness["status"] == "Blocked"
    assert validator_readiness["action"] == "configureValidators"
    assert validator_readiness["evidence"]["requiredValidators"] == 3
    assert validator_readiness["evidence"]["configuredValidators"] == 0
    assert body["nextTask"]["action"] == "enrollment"
    assert body["nextTask"]["title"] == "Finish administrator enrollment"

    attacker = Account.create("wrong-wallet")
    rejected = client.post(
        "/admin/launch/auth/challenge", json={"wallet": attacker.address}
    )
    assert rejected.status_code == 403
    assert owner.address.lower() not in rejected.text.lower()


def test_plan_template_rejects_fixture_kos_key_and_accepts_release_key(tmp_path) -> None:
    _, _, settings = _client(tmp_path)
    plan_path = tmp_path / "plan.json"
    settings.launch_plan_template_path = str(plan_path)

    plan_path.write_text(
        json.dumps(
            _plan_template(launch_control_module.TEST_KOS_MINT_EXECUTE_PUBKEY)
        ),
        encoding="utf-8",
    )
    try:
        launch_control_module._plan_template_evidence(settings)
    except Exception as exc:  # noqa: BLE001
        assert "public test fixture key" in str(exc)
    else:
        raise AssertionError("fixture KoS key must not pass release readiness")

    release_key = bytes(AugSchemeMPL.key_gen(b"release-kos-key" * 3).get_g1())
    plan_path.write_text(
        json.dumps(_plan_template(release_key)),
        encoding="utf-8",
    )
    evidence = launch_control_module._plan_template_evidence(settings)
    assert evidence["kosMintExecutePubkey"] == "0x" + release_key.hex()
    assert evidence["validatorCount"] == 3


def test_owner_creates_named_coadmin_link_without_exposing_stored_secret(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    _, ceremony_id = _claim_and_enroll_owner(client)
    invited = client.post(
        "/admin/launch/invitations/2",
        json={
            "displayName": "Technical Admin",
            "email": "technical@example.com",
            "timezone": "America/New_York",
            "remindersEnabled": True,
        },
    )
    assert invited.status_code == 200, invited.text
    body = invited.json()
    assert body["slot"] == 2
    assert body["invitationFragment"].startswith("#launch-invite=")
    assert body["profile"]["displayName"] == "Technical Admin"
    persisted = store.get(ceremony_id)
    serialized = json.dumps(persisted)
    assert body["invitationFragment"].split("=", 1)[1] not in serialized


def test_setup_cookie_cannot_issue_coadmin_invites_before_owner_wallet_enrollment(
    tmp_path,
) -> None:
    client, _, _ = _client(tmp_path)
    claimed = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert claimed.status_code == 200
    rejected = client.post(
        "/admin/launch/invitations/2",
        json={"displayName": "Admin 2"},
    )
    assert rejected.status_code == 401
    assert "Finish owner enrollment" in rejected.json()["detail"]


def test_owner_setup_cookie_can_replace_a_lost_enrollment_secret(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    claimed = client.post(
        "/admin/launch/claim",
        json={"token": ADMIN_TOKEN, "displayName": "Owner Admin"},
    )
    assert claimed.status_code == 200
    original = claimed.json()["ownerEnrollmentToken"]

    replacement = client.post("/admin/launch/owner/enrollment")

    assert replacement.status_code == 200, replacement.text
    new_token = replacement.json()["ownerEnrollmentToken"]
    assert new_token != original
    persisted = json.dumps(store.active())
    assert original not in persisted
    assert new_token not in persisted
    rejected = client.post(
        "/admin/launch/invitations/prepare",
        json={"token": original, "wallet": Account.create().address},
    )
    assert rejected.status_code == 404


def test_settlement_rehearsal_is_coadmin_only_and_observes_stripe_vouchers(
    tmp_path, monkeypatch
) -> None:
    client, store, settings = _client(tmp_path)
    owner, ceremony_id = _claim_and_enroll_owner(client)
    rejected = client.post("/admin/launch/settlement-rehearsal/start")
    assert rejected.status_code == 403
    assert "coadministrator" in rejected.json()["detail"]

    coadmin = _enroll_coadmin(client)
    before_genesis = client.post("/admin/launch/settlement-rehearsal/start")
    assert before_genesis.status_code == 409
    assert "Complete genesis first" in before_genesis.json()["detail"]
    _mark_launch_locked(store, ceremony_id, settings, [owner, coadmin])

    async def fake_start(
        _settings,
        *,
        ceremony_id,
        release_evidence_hash,
        wallet_address,
    ):
        assert ceremony_id
        assert release_evidence_hash.startswith("0x")
        assert wallet_address == coadmin.address.lower()
        return {
            "jobId": "rehearsal_job_0001",
            "state": "VALIDATING",
            "configHash": "0x" + "ab" * 32,
            "phase": "WAITING_DELIVERY_PURCHASE",
            "completedSteps": 0,
            "step": "Complete the delivery test purchase",
            "message": "Stripe test mode only.",
            "walletTransaction": None,
        }

    monkeypatch.setattr(launch_control_module, "start_rehearsal", fake_start)
    started = client.post("/admin/launch/settlement-rehearsal/start")
    assert started.status_code == 200, started.text
    result = started.json()
    assert result["status"]["state"] == "VALIDATING"
    assert result["status"]["phase"] == "WAITING_DELIVERY_PURCHASE"
    assert result["status"]["walletTransaction"] is None
    assert result["decisionReceipt"]["network"] == "Stripe test mode and Testnet11"
    assert result["decisionReceipt"]["requiredApprovers"].startswith("One enrolled")
    assert store.settlement_rehearsal(ceremony_id)["state"] == "VALIDATING"


def test_purchase_gate_stays_locked_until_delivery_and_refund_are_proven(
    tmp_path,
) -> None:
    client, store, settings = _client(tmp_path)
    owner, ceremony_id = _claim_and_enroll_owner(client)
    coadmin = _enroll_coadmin(client)
    _mark_launch_locked(store, ceremony_id, settings, [owner, coadmin])
    now = 2_000_000_000
    payload_hash = "0x" + "ab" * 32
    store.upsert_gate(
        ceremony_id,
        gate_name="purchases",
        opens_at=now - 60,
        closes_at=now + 600,
        payload_hash=payload_hash,
        state="pending",
        now=now - 120,
    )
    action_id, _ = launch_control_module._gate_payload(
        store, ceremony_id, "purchases"
    )
    for slot, account in ((1, owner), (2, coadmin)):
        store.add_action_approval(
            ceremony_id,
            settings=settings,
            action_id=action_id,
            action_type="gate:purchases",
            payload_hash=payload_hash,
            slot=slot,
            signer_address=account.address,
            signature="0x" + f"{slot:02x}" * 65,
            expires_at=now + 600,
            now=now - 100 + slot,
        )
    _login(client, owner)

    activated = client.post("/admin/launch/gates/purchases/activate")

    assert activated.status_code == 409
    assert "delivery and exact-refund test" in activated.json()["detail"]
    assert (
        store.gates(ceremony_id, now=now)["purchases"]["configuredState"]
        == "pending"
    )


@pytest.mark.asyncio
async def test_approved_future_gate_is_configured_open_but_not_yet_effective(
    tmp_path,
) -> None:
    ceremony_id = "0x" + "ac" * 32
    now = int(time.time())
    payload_hash = "0x" + "bc" * 32
    gate = {
        "name": "ceremonyBroadcast",
        "network": "testnet11",
        "opensAt": now + 300,
        "closesAt": now + 900,
        "payloadHash": payload_hash,
        "configuredState": "pending",
        "state": "pending",
        "updatedAt": now,
    }
    captured: dict[str, object] = {}

    class GateStore:
        def get(self, actual_ceremony_id):
            assert actual_ceremony_id == ceremony_id
            return {"state": "plan_approved"}

        def gates(self, actual_ceremony_id):
            assert actual_ceremony_id == ceremony_id
            return {"ceremonyBroadcast": gate}

        def action_approvals(self, actual_ceremony_id, action_id, *, settings):
            assert actual_ceremony_id == ceremony_id
            assert action_id.startswith("0x")
            return {"approved": True}

        def upsert_gate(self, actual_ceremony_id, **kwargs):
            assert actual_ceremony_id == ceremony_id
            captured.update(kwargs)
            return {
                **gate,
                "configuredState": kwargs["state"],
                "state": "pending",
            }

    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        genesis_db_path=str(tmp_path / "unused-genesis.db"),
        genesis_output_dir=str(tmp_path / "unused-ceremonies"),
    )
    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=1,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=now + 3600,
    )
    activated = await launch_control_module.activate_gate(
        "ceremonyBroadcast",
        settings,
        GateStore(),  # type: ignore[arg-type]
        session,
    )

    assert captured["state"] == "open"
    assert activated["configuredState"] == "open"
    assert activated["state"] == "pending"


def test_settlement_rehearsal_rejects_legacy_admin_wallet_transactions(tmp_path) -> None:
    client, store, settings = _client(tmp_path)
    owner, ceremony_id = _claim_and_enroll_owner(client)
    coadmin = _enroll_coadmin(client)
    _mark_launch_locked(store, ceremony_id, settings, [owner, coadmin])
    store.set_settlement_rehearsal(
        ceremony_id,
        job_id="rehearsal_job_0001",
        config_hash="0x" + "ab" * 32,
        state="AWAITING_WALLET",
        payload={"state": "AWAITING_WALLET"},
    )

    submitted = client.post(
        "/admin/launch/settlement-rehearsal/transaction",
        json={"transactionHash": "0x" + "cd" * 32},
    )
    assert submitted.status_code == 410, submitted.text
    assert "never asks an administrator" in submitted.json()["detail"]
    assert store.settlement_rehearsal(ceremony_id)["state"] == "AWAITING_WALLET"


def test_post_genesis_settlement_does_not_block_ceremony_task_selection() -> None:
    readiness = [
        {
            "id": "settlement",
            "title": "Customer payment test follows launch",
            "status": "Waiting",
            "impact": "Run after genesis.",
            "assignedRole": "technical-coadmin",
            "blocksCeremony": False,
        }
    ]
    before_genesis = launch_control_module._task_for(
        {"state": "roster_frozen", "invitations": [{"consumed_at": 1}] * 3},
        readiness,
    )
    assert before_genesis["action"] == "buildPlan"

    after_genesis = launch_control_module._task_for(
        {"state": "locked", "invitations": [{"consumed_at": 1}] * 3},
        readiness,
    )
    assert after_genesis["title"] == "Customer payment test follows launch"


def test_incomplete_payment_rail_does_not_block_genesis_task_selection() -> None:
    readiness = [
        {
            "id": "railOwnership",
            "title": "Base Sepolia rail ownership",
            "status": "Waiting",
            "impact": "The payment rail remains inactive.",
            "assignedRole": "administrator",
            "blocksCeremony": False,
        }
    ]

    task = launch_control_module._task_for(
        {
            "state": "plan_approved",
            "plan_expires_at": int(time.time()) + 600,
            "invitations": [{"consumed_at": 1}] * 3,
        },
        readiness,
    )

    assert task["action"] == "preflight"


def test_plan_audit_waits_for_independent_plan_and_internal_flow_skips_file(
    tmp_path,
) -> None:
    _, _, settings = _client(tmp_path)
    independent = {
        "state": "roster_frozen",
        "draft": {"reviewClass": "independent-release-review"},
    }

    before_plan = launch_control_module._audit_readiness(settings, independent)
    assert before_plan["status"] == "Waiting"
    assert before_plan["blocksCeremony"] is False
    assert before_plan["evidence"]["auditApprovalRequired"] is False

    independent["state"] = "plan_approved"
    strict_gate = launch_control_module._audit_readiness(settings, independent)
    assert strict_gate["status"] == "Blocked"
    assert strict_gate.get("blocksCeremony", True) is True
    assert strict_gate["evidence"]["auditApprovalRequired"] is True

    internal = {
        "state": "plan_approved",
        "draft": {"reviewClass": "internal-engineering-testnet"},
    }
    disposable = launch_control_module._audit_readiness(settings, internal)
    assert disposable["status"] == "Healthy"
    assert disposable["blocksCeremony"] is False
    assert disposable["evidence"]["auditApprovalRequired"] is False


def test_plan_build_requires_sepolia_deployment_but_not_plan_audit(tmp_path) -> None:
    _, _, settings = _client(tmp_path)

    with pytest.raises(GenesisConflict, match="Sepolia deployment evidence"):
        launch_control_module._require_preplan_evm_evidence(settings)

    deployment_path = tmp_path / "deployment.json"
    deployment_path.write_text("{}", encoding="utf-8")
    settings.genesis_evm_deployment_path = str(deployment_path)
    settings.genesis_audit_approval_path = str(tmp_path / "not-created.json")

    launch_control_module._require_preplan_evm_evidence(settings)
    assert not Path(settings.genesis_audit_approval_path).exists()


@pytest.mark.asyncio
async def test_guided_strict_preflight_stops_before_bundle_on_missing_audit(
    tmp_path,
    monkeypatch,
) -> None:
    _, _, settings = _client(tmp_path)
    ceremony_id = "0x" + "ab" * 32
    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=1,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=int(time.time()) + 600,
    )

    class Store:
        @staticmethod
        def get(actual_ceremony_id):
            assert actual_ceremony_id == ceremony_id
            return {
                "state": "plan_approved",
                "plan_hash": "0x" + "34" * 32,
                "plan_expires_at": int(time.time()) + 600,
                "draft": {"reviewClass": "independent-release-review"},
            }

    async def fake_readiness(*_args):
        return [
            {
                "id": "planAudit",
                "title": "Independent plan audit",
                "status": "Blocked",
                "impact": "Missing plan-bound approval.",
                "assignedRole": "technical-coadmin",
            }
        ]

    async def unexpected_prepare(*_args):
        raise AssertionError("bundle preparation must not run past the readiness gate")

    monkeypatch.setattr(launch_control_module, "_readiness", fake_readiness)
    monkeypatch.setattr(launch_control_module, "_prepare_bundle", unexpected_prepare)

    with pytest.raises(HTTPException) as exc_info:
        await launch_control_module.guided_preflight(
            object(), settings, Store(), session  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["findings"][0]["id"] == "planAudit"


@pytest.mark.asyncio
async def test_payment_activation_requires_completed_base_sepolia_ownership(
    tmp_path,
    monkeypatch,
) -> None:
    _, _, settings = _client(tmp_path)
    ceremony_id = "0x" + "cd" * 32
    gate = {
        "payloadHash": "0x" + "56" * 32,
        "opensAt": int(time.time()) - 60,
        "closesAt": int(time.time()) + 600,
        "configuredState": "pending",
        "state": "pending",
    }

    class Store:
        @staticmethod
        def get(actual_ceremony_id):
            assert actual_ceremony_id == ceremony_id
            return {"state": "locked"}

        @staticmethod
        def gates(actual_ceremony_id):
            assert actual_ceremony_id == ceremony_id
            return {"purchases": gate}

        @staticmethod
        def action_approvals(actual_ceremony_id, _action_id, *, settings):
            assert actual_ceremony_id == ceremony_id
            return {"approved": True}

        @staticmethod
        def upsert_gate(*_args, **_kwargs):
            raise AssertionError("payment gate must stay closed")

    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=1,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=int(time.time()) + 600,
    )
    monkeypatch.setattr(
        launch_control_module,
        "require_completed_rehearsal",
        lambda *_args: ({"state": "COMPLETE"}, "0x" + "78" * 32),
    )
    monkeypatch.setattr(
        launch_control_module,
        "get_ownership_activation_store",
        lambda _settings: object(),
    )
    monkeypatch.setattr(
        launch_control_module,
        "_rail_phase_status",
        lambda _settings, _store: {"state": "WAITING_FOR_DELAY"},
    )

    with pytest.raises(HTTPException) as exc_info:
        await launch_control_module.activate_gate(
            "purchases", settings, Store(), session  # type: ignore[arg-type]
        )

    assert exc_info.value.status_code == 409
    assert "rail ownership is active" in str(exc_info.value.detail)


def test_expired_approved_plan_routes_owner_to_exact_renewal() -> None:
    task = launch_control_module._task_for(
        {
            "state": "plan_approved",
            "plan_expires_at": 1,
            "invitations": [{"consumed_at": 1}] * 3,
        },
        [],
    )

    assert task["action"] == "renewPlan"
    assert task["assignedRole"] == "owner"


def test_gate_open_returns_exact_signed_broadcast_authorization(tmp_path) -> None:
    ceremony_id = "0x" + "ad" * 32
    gate = {
        "name": "ceremonyBroadcast",
        "network": "testnet11",
        "opensAt": 1_999_999_000,
        "closesAt": 2_000_001_000,
        "payloadHash": "0x" + "35" * 32,
        "configuredState": "open",
        "state": "open",
        "updatedAt": 1_999_999_000,
    }

    class GateStore:
        def authorized_gate(self, settings, actual_ceremony_id, gate_name):
            assert actual_ceremony_id == ceremony_id
            assert gate_name == "ceremonyBroadcast"
            return gate

    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        ceremony_mode_enabled=True,
        genesis_db_path=str(tmp_path / "unused-genesis.db"),
        genesis_output_dir=str(tmp_path / "unused-ceremonies"),
    )

    authorization = launch_control_module._gate_open(
        settings,
        GateStore(),  # type: ignore[arg-type]
        ceremony_id,
        "ceremonyBroadcast",
    )

    assert authorization == {
        "gate": "ceremonyBroadcast",
        "payloadHash": gate["payloadHash"],
        "opensAt": gate["opensAt"],
        "closesAt": gate["closesAt"],
        "configuredState": "open",
        "state": "open",
        "approved": True,
    }


@pytest.mark.asyncio
async def test_guided_broadcast_forwards_the_application_request(
    tmp_path, monkeypatch
) -> None:
    _, store, settings = _client(tmp_path)
    ceremony_id = "0x" + "ab" * 32
    request = object()
    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=1,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=2_000_000_000,
    )
    observed: dict[str, object] = {}
    gate_authorization = {
        "gate": "ceremonyBroadcast",
        "payloadHash": "0x" + "34" * 32,
        "opensAt": 1_999_999_000,
        "closesAt": 2_000_001_000,
        "configuredState": "open",
        "state": "open",
        "approved": True,
    }

    def fake_gate_open(actual_settings, actual_store, actual_ceremony_id, gate_name):
        assert actual_settings is settings
        assert actual_store is store
        assert actual_ceremony_id == ceremony_id
        assert gate_name == "ceremonyBroadcast"
        return gate_authorization

    monkeypatch.setattr(
        store,
        "get",
        lambda actual_ceremony_id: {
            "ceremony_id": actual_ceremony_id,
            "state": "plan_approved",
            "broadcast": None,
        },
    )

    async def fake_broadcast_ceremony(
        actual_ceremony_id,
        actual_request,
        actual_settings,
        actual_store,
        *,
        gate_authorization: dict[str, object] | None,
    ):
        observed.update(
            ceremony_id=actual_ceremony_id,
            request=actual_request,
            settings=actual_settings,
            store=actual_store,
            gate_authorization=gate_authorization,
        )
        return {"submitted": True}

    monkeypatch.setattr(launch_control_module, "_gate_open", fake_gate_open)
    monkeypatch.setattr(
        launch_control_module,
        "_broadcast_ceremony",
        fake_broadcast_ceremony,
    )

    result = await launch_control_module.guided_broadcast(
        request=request,
        settings=settings,
        store=store,
        session=session,
    )

    assert result == {"submitted": True}
    assert observed == {
        "ceremony_id": ceremony_id,
        "request": request,
        "settings": settings,
        "store": store,
        "gate_authorization": gate_authorization,
    }


@pytest.mark.asyncio
async def test_guided_broadcast_finalized_recovery_does_not_require_new_gate(
    tmp_path,
    monkeypatch,
) -> None:
    _, store, settings = _client(tmp_path)
    ceremony_id = "0x" + "ac" * 32
    request = object()
    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=1,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=2_000_000_000,
    )
    monkeypatch.setattr(
        store,
        "get",
        lambda actual_ceremony_id: {
            "ceremony_id": actual_ceremony_id,
            "state": "broadcast",
            "broadcast": {"reservationState": "FINALIZED"},
        },
    )
    monkeypatch.setattr(
        launch_control_module,
        "_gate_open",
        lambda *_args, **_kwargs: pytest.fail(
            "FINALIZED evidence recovery must not require a new write gate"
        ),
    )

    async def fake_broadcast_ceremony(
        actual_ceremony_id,
        actual_request,
        actual_settings,
        actual_store,
        *,
        gate_authorization,
    ):
        assert actual_ceremony_id == ceremony_id
        assert actual_request is request
        assert actual_settings is settings
        assert actual_store is store
        assert gate_authorization is None
        return {"recovered": True}

    monkeypatch.setattr(
        launch_control_module,
        "_broadcast_ceremony",
        fake_broadcast_ceremony,
    )

    assert await launch_control_module.guided_broadcast(
        request=request,
        settings=settings,
        store=store,
        session=session,
    ) == {"recovered": True}


@pytest.mark.asyncio
async def test_guided_broadcast_maps_expired_plan_to_gone(
    tmp_path,
    monkeypatch,
) -> None:
    _, store, settings = _client(tmp_path)
    ceremony_id = "0x" + "af" * 32

    def expired_get(_ceremony_id):
        raise GenesisExpired("ceremony plan expired")

    monkeypatch.setattr(
        store,
        "get",
        expired_get,
    )
    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=1,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=2_000_000_000,
    )

    with pytest.raises(launch_control_module.HTTPException) as error:
        await launch_control_module.guided_broadcast(
            request=object(),
            settings=settings,
            store=store,
            session=session,
        )

    assert error.value.status_code == 410
    assert "expired" in str(error.value.detail)


@pytest.mark.asyncio
async def test_progress_retry_reports_locked_ceremony_complete(
    tmp_path,
    monkeypatch,
) -> None:
    _, store, settings = _client(tmp_path)
    ceremony_id = "0x" + "ae" * 32
    record = {"ceremony_id": ceremony_id, "state": "locked"}
    monkeypatch.setattr(store, "get", lambda _ceremony_id: record)
    monkeypatch.setattr(
        launch_control_module,
        "_public_ceremony",
        lambda actual_record, actual_store: {
            "ceremonyId": actual_record["ceremony_id"],
            "state": actual_record["state"],
        },
    )
    session = launch_control_module.LaunchSession(
        ceremony_id=ceremony_id,
        slot=2,
        wallet="0x" + "12" * 20,
        setup=False,
        expires_at=2_000_000_000,
    )

    result = await launch_control_module.progress_after_broadcast(
        settings=settings,
        store=store,
        session=session,
    )

    assert result == {
        "ceremony": {"ceremonyId": ceremony_id, "state": "locked"},
        "waiting": False,
        "complete": True,
    }
