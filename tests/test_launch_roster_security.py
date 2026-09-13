"""Launch authority regressions with synthetic signed identities and local state."""

import time

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import HTTPException, Request, Response

import solslot_api.admin_roster as roster
import solslot_api.launch_control as launch
from solslot_api.config import Settings
from solslot_api.genesis_store import GenesisConflict, GenesisStore, launch_gate_action_id
from solslot_api.public_artifact import PublicArtifactMissing


CEREMONY = "0x" + "a1" * 32
ACCOUNTS = [Account.from_key(index.to_bytes(32, "big")) for index in (901, 902, 903, 904)]


def compressed(account):
    return "0x" + account._key_obj.public_key.to_compressed_bytes().hex()


@pytest.fixture
def authority(tmp_path, monkeypatch):
    settings = Settings(
        runtime_environment="test", network="testnet11", launch_control_enabled=True,
        launch_session_secret="synthetic-launch-session-secret-for-regressions",
        genesis_db_path=str(tmp_path / "genesis.db"),
        public_artifact_path=str(tmp_path / "public.json"),
        bootstrap_manifest_path=str(tmp_path / "bootstrap.json"),
    )
    store = GenesisStore(settings.genesis_db_path)
    store.create_draft(CEREMONY, {}, now=100)
    for slot, account in enumerate(ACCOUNTS[:3], start=1):
        store.issue_invitation(CEREMONY, slot=slot, token_hash=f"token-{slot}",
                               nonce=f"nonce-{slot}", expires_at=1000, now=101)
        store.consume_invitation(token_hash=f"token-{slot}", wallet_address=account.address,
                                 compressed_pubkey=compressed(account), signature="0x" + "01" * 65,
                                 now=102)
    with store._transaction() as connection:
        connection.execute("UPDATE ceremonies SET state='locked' WHERE ceremony_id=?", (CEREMONY,))
    artifact = {
        "ceremony": {"ceremonyId": CEREMONY},
        "adminAuthority": {"version": 3, "identityVaults": [
            {"slot": slot, "dailyCompressedPubkey": compressed(account)}
            for slot, account in enumerate(ACCOUNTS[:3])
        ]},
    }
    # Artifact signature/runtime verification has its own tests. This fixture
    # supplies that trusted boundary's result; no production auth bypass exists.
    monkeypatch.setattr(roster, "load_signed_public_artifact", lambda _: artifact)
    cases = []
    monkeypatch.setattr(store, "recovery_cases", lambda _: cases)
    return settings, store, cases, artifact


def rotate(cases, slot=0, account=ACCOUNTS[3]):
    cases.insert(0, {"state": "COMPLETED", "kind": "ROUTINE", "intent": {
        "slot": slot, "newDailyEvmKey": account.address, "newDailyChiaKey": compressed(account),
    }})


def session(settings, account, slot=1):
    token, _ = launch._issue_session(settings, ceremony_id=CEREMONY, slot=slot,
                                     wallet=account.address, setup=False)
    return Request({"type": "http", "headers": [
        (b"cookie", f"{launch.LAUNCH_COOKIE_NAME}={token}".encode())
    ]})


def test_original_launch_session_control(authority):
    settings, store, _, _ = authority
    result = launch.require_launch_session(session(settings, ACCOUNTS[0]), settings, store)
    assert result.slot == 1


def test_retired_cookie_loses_access_on_next_request(authority):
    settings, store, cases, _ = authority
    request = session(settings, ACCOUNTS[0])
    rotate(cases)
    with pytest.raises(HTTPException) as failure:
        launch.require_launch_session(request, settings, store)
    assert failure.value.status_code == 403


def test_current_replacement_uses_same_launch_slot(authority):
    settings, store, cases, _ = authority
    rotate(cases)
    result = launch.require_launch_session(session(settings, ACCOUNTS[3]), settings, store)
    assert result.slot == 1
    assert result.wallet == ACCOUNTS[3].address.lower()


@pytest.mark.asyncio
async def test_challenge_cannot_complete_after_signer_is_retired(authority):
    settings, store, cases, _ = authority
    account = ACCOUNTS[0]
    challenge = await launch.resume_challenge(launch.ResumeChallengeRequest(wallet=account.address), settings, store)
    signature = account.sign_message(encode_typed_data(full_message=challenge["typedData"]))
    rotate(cases)
    with pytest.raises(HTTPException) as failure:
        await launch.resume_login(launch.ResumeLoginRequest(wallet=account.address, nonce=challenge["nonce"],
            signature="0x" + bytes(signature.signature).hex()), Response(), settings, store)
    assert failure.value.status_code == 403


def test_retired_identity_rejoining_another_slot_does_not_restore_owner_cookie(authority):
    settings, store, cases, _ = authority
    request = session(settings, ACCOUNTS[0])
    rotate(cases)
    rotate(cases, 1, ACCOUNTS[0])
    with pytest.raises(HTTPException):
        launch.require_launch_session(request, settings, store)
    assert launch.require_launch_session(session(settings, ACCOUNTS[0], 2), settings, store).slot == 2


@pytest.mark.asyncio
async def test_current_replacement_can_sign_a_fresh_login(authority):
    settings, store, cases, _ = authority
    rotate(cases)
    account = ACCOUNTS[3]
    with pytest.raises(HTTPException):
        await launch.resume_challenge(launch.ResumeChallengeRequest(wallet=ACCOUNTS[0].address), settings, store)
    challenge = await launch.resume_challenge(launch.ResumeChallengeRequest(wallet=account.address), settings, store)
    signature = account.sign_message(encode_typed_data(full_message=challenge["typedData"]))
    result = await launch.resume_login(launch.ResumeLoginRequest(wallet=account.address, nonce=challenge["nonce"],
        signature="0x" + bytes(signature.signature).hex()), Response(), settings, store)
    assert result["authenticated"] and result["slot"] == 1


def test_signed_artifact_must_belong_to_the_requested_launch(authority):
    settings, store, _, artifact = authority
    artifact["ceremony"]["ceremonyId"] = "0x" + "ff" * 32
    with pytest.raises(HTTPException):
        launch.require_launch_session(session(settings, ACCOUNTS[0]), settings, store)


def test_missing_signed_evidence_never_falls_back_after_lock(authority, monkeypatch):
    settings, store, _, _ = authority
    def missing(_):
        raise PublicArtifactMissing("synthetic missing artifact")
    monkeypatch.setattr(roster, "load_signed_public_artifact", missing)
    with pytest.raises(HTTPException):
        launch.require_launch_session(session(settings, ACCOUNTS[0]), settings, store)
    with store._transaction() as connection:
        connection.execute("UPDATE ceremonies SET state='roster_open' WHERE ceremony_id=?", (CEREMONY,))
    assert launch.require_launch_session(session(settings, ACCOUNTS[0]), settings, store).slot == 1
    from pathlib import Path
    Path(settings.bootstrap_manifest_path).write_text("{}")
    with pytest.raises(HTTPException):
        launch.require_launch_session(session(settings, ACCOUNTS[0]), settings, store)


def approve(store, settings, action_id, payload, account, slot, *, now=1000, expires=1300):
    return store.add_action_approval(CEREMONY, settings=settings, action_id=action_id,
        action_type="gate:minting", payload_hash=payload, slot=slot, signer_address=account.address,
        signature="0x" + f"{slot:02x}" * 65, expires_at=expires, now=now)


def prepare_gate(store, settings):
    payload = "0x" + "b1" * 32
    action_id = launch_gate_action_id(CEREMONY, "minting", payload)
    store.upsert_gate(CEREMONY, gate_name="minting", opens_at=1000, closes_at=4600,
                      payload_hash=payload, state="pending", now=999)
    for slot, account in enumerate(ACCOUNTS[:2], 1):
        approve(store, settings, action_id, payload, account, slot)
    return action_id, payload


def activate(store, settings, payload, now=1001):
    return store.upsert_gate(CEREMONY, settings=settings, gate_name="minting", opens_at=1000,
                            closes_at=4600, payload_hash=payload, state="open", now=now)


def test_retired_approval_stops_counting_and_replacement_preserves_history(authority):
    settings, store, cases, _ = authority
    action_id, payload = prepare_gate(store, settings)
    assert store.action_approvals(CEREMONY, action_id, settings=settings, now=1001)["approved"]
    rotate(cases)
    assert not store.action_approvals(CEREMONY, action_id, settings=settings, now=1001)["approved"]
    with pytest.raises(GenesisConflict):
        approve(store, settings, action_id, payload, ACCOUNTS[0], 1)
    assert approve(store, settings, action_id, payload, ACCOUNTS[3], 1)["approved"]
    with store._connect() as connection:
        archived = connection.execute("SELECT event_json FROM audit_events WHERE event_type='launch_action_approval_superseded'").fetchall()
    assert len(archived) == 1
    assert ACCOUNTS[0].address.lower() in archived[0]["event_json"]
    assert 'signature' in archived[0]["event_json"]


def test_active_gate_keeps_approved_duration_but_loses_retired_signers(authority):
    settings, store, cases, _ = authority
    action_id, payload = prepare_gate(store, settings)
    activate(store, settings, payload)
    # Approval TTL is 1300, while the deliberately approved gate runs to 4600.
    assert store.authorized_gate(settings, CEREMONY, "minting", now=1400)["state"] == "open"
    rotate(cases)
    with pytest.raises(GenesisConflict):
        store.authorized_gate(settings, CEREMONY, "minting", now=1100)
    approve(store, settings, action_id, payload, ACCOUNTS[3], 1, now=1100)
    # A new approval does not silently replace a gate's historical activation.
    with pytest.raises(GenesisConflict):
        store.authorized_gate(settings, CEREMONY, "minting", now=1101)
    activate(store, settings, payload, now=1101)
    assert store.authorized_gate(settings, CEREMONY, "minting", now=1400)["state"] == "open"
    with pytest.raises(GenesisConflict):
        store.authorized_gate(settings, CEREMONY, "minting", now=4600)


def test_gate_without_activation_proof_is_not_authorized(authority):
    settings, store, _, _ = authority
    _, payload = prepare_gate(store, settings)
    store.upsert_gate(CEREMONY, gate_name="minting", opens_at=1000, closes_at=4600,
                      payload_hash=payload, state="open", now=1001)
    with pytest.raises(GenesisConflict):
        store.authorized_gate(settings, CEREMONY, "minting", now=1002)


@pytest.mark.asyncio
async def test_reserved_finalization_keeps_authenticated_guided_retry(tmp_path, monkeypatch):
    from pathlib import Path
    import solslot_api.genesis as genesis
    from tests.test_genesis_api import _finalization_fixture

    real_worker = genesis._run_worker
    store, settings, ceremony_id, _ = await _finalization_fixture(tmp_path, monkeypatch)
    from tests.test_public_artifact import _signed_artifact
    import json
    accounts = [Account.from_key(index.to_bytes(32, "big")) for index in (951, 952, 953)]
    artifact = _signed_artifact(accounts=accounts, ceremony_id=ceremony_id, signed_slots=(0, 1))
    # The older finalization fixture uses opaque signatures. For this authority
    # regression install a cryptographically valid artifact into its synthetic
    # confirmed ledger, while keeping chain/network behavior simulated.
    with store._transaction() as connection:
        connection.execute("UPDATE ceremonies SET artifact_hash=?, artifact_json=? WHERE ceremony_id=?",
                           (artifact["artifactHash"], json.dumps(artifact), ceremony_id))
        for slot, account in enumerate(accounts, 1):
            connection.execute("UPDATE invitations SET wallet_address=?, compressed_pubkey=? WHERE ceremony_id=? AND slot=?",
                               (account.address, compressed(account), ceremony_id, slot))
        for entry in artifact["signatures"]:
            connection.execute("UPDATE artifact_signatures SET artifact_hash=?, compressed_pubkey=?, signature=? WHERE ceremony_id=? AND slot=?",
                               (artifact["artifactHash"], entry["compressedPubkey"], entry["signature"], ceremony_id, entry["adminIndex"] + 1))
    monkeypatch.setattr(genesis, "_run_worker", real_worker)
    settings.launch_control_enabled = True
    owner = store.get(ceremony_id)["invitations"][0]["wallet_address"]
    token, _ = launch._issue_session(settings, ceremony_id=ceremony_id, slot=1, wallet=owner, setup=False)
    request = Request({"type": "http", "method": "POST", "path": "/admin/launch/progress", "headers": [
        (b"cookie", f"{launch.LAUNCH_COOKIE_NAME}={token}".encode())
    ]})
    assert launch.require_launch_session(request, settings, store).slot == 1
    materialize = genesis._materialize_broadcast_evidence
    def interrupted(**kwargs):
        raise OSError("synthetic interruption after reservation")
    monkeypatch.setattr(genesis, "_materialize_broadcast_evidence", interrupted)
    with pytest.raises(OSError):
        genesis._commit_finalization(ceremony_id=ceremony_id, settings=settings, store=store,
                                    record=store.get(ceremony_id), artifact=artifact)
    assert store.finalization_publication(ceremony_id) is not None
    assert store.get(ceremony_id)["state"] == "artifact_signed"
    assert not Path(settings.public_artifact_path).exists()
    reserved = store.finalization_publication(ceremony_id)
    with store._connect() as connection:
        original_publication = connection.execute(
            "SELECT publication_json FROM genesis_finalization_reservation WHERE singleton_slot=1"
        ).fetchone()[0]
    changed = json.loads(json.dumps(reserved))
    changed["artifact"]["signatures"] = []
    with store._transaction() as connection:
        connection.execute("UPDATE genesis_finalization_reservation SET publication_json=?", (json.dumps(changed),))
    with pytest.raises(HTTPException):
        launch.require_launch_session(request, settings, store)
    with store._transaction() as connection:
        connection.execute("UPDATE genesis_finalization_reservation SET publication_json=?", (original_publication,))
    expected_chain = settings.zkpassport_evm_chain_id
    settings.zkpassport_evm_chain_id = 1
    with pytest.raises(HTTPException):
        launch.require_launch_session(request, settings, store)
    settings.zkpassport_evm_chain_id = expected_chain
    retry_session = launch.require_launch_session(request, settings, store)
    assert retry_session.slot == 1
    fresh = await launch.resume_challenge(launch.ResumeChallengeRequest(wallet=owner), settings, store)
    assert fresh["nonce"]
    # Publication authority must not unlock unrelated administration.
    other = Request({**request.scope, "path": "/admin/launch/funding/execute"})
    with pytest.raises(HTTPException):
        launch.require_launch_session(other, settings, store)
    monkeypatch.setattr(genesis, "_materialize_broadcast_evidence", materialize)
    await launch.progress_after_broadcast(settings, store, retry_session)
    assert store.get(ceremony_id)["state"] == "locked"
    assert Path(settings.public_artifact_path).is_file()
