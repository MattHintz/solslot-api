from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest
from tests.launch_authority_fixtures import bootstrap_settings

from solslot_api.genesis_store import (
    GenesisConflict,
    GenesisExpired,
    GenesisStore,
    owner_plus_one_approved,
)


CEREMONY = "0x" + "11" * 32
ROSTER = "0x" + "22" * 32
PLAN = "0x" + "33" * 32
ARTIFACT = "0x" + "44" * 32
BUNDLE_ID = "0x" + "55" * 32
FEE_COIN_ID = "0x" + "66" * 32
FEE_MOJOS = 7
SPEND_BUNDLE = {
    "aggregated_signature": "0x" + "00" * 96,
    "coin_spends": [],
}
CEREMONY_EVIDENCE = {
    "auditApproval": {"approved": True},
    "authorityV3ReviewBase64": "e30K",
    "validatorHealth": {"checkedAt": 100, "signers": []},
}


def test_owner_claim_consumption_and_draft_creation_are_atomic(tmp_path) -> None:
    store = GenesisStore(tmp_path / "owner-claim.db")
    barrier = threading.Barrier(2)

    def claim(index: int) -> str:
        barrier.wait()
        try:
            record = store.claim_or_create_draft(
                token_hash="one-use-owner-link",
                ceremony_id="0x" + f"{index + 1:02x}" * 32,
                draft={"sourceShas": {}},
                now=100 + index,
            )
            return str(record["ceremony_id"])
        except GenesisConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, range(2)))

    assert results.count("conflict") == 1
    assert len(store.list_ceremonies()) == 1


def test_owner_claim_rejects_active_draft_from_another_launch_policy(
    tmp_path,
) -> None:
    store = GenesisStore(tmp_path / "stale-owner-claim.db")
    stale_ceremony = "0x" + "a1" * 32
    stale_draft = {
        "schemaVersion": 2,
        "sourceManifestVersion": 4,
        "network": "testnet11",
        "evmChainId": 11155111,
        "reviewClass": "internal-engineering-testnet",
        "releaseTag": "solslot-v2-alpha-rc27.32-20260823",
        "releaseEvidenceHash": "0x" + "11" * 32,
        "sourceShas": {"api": "1" * 40},
    }
    official_draft = {
        **stale_draft,
        "reviewClass": "independent-release-review",
        "releaseTag": "solslot-v2-alpha-rc27.36-20260824",
        "releaseEvidenceHash": "0x" + "22" * 32,
        "sourceShas": {"api": "2" * 40},
    }
    store.create_draft(stale_ceremony, stale_draft, now=100)

    with pytest.raises(GenesisConflict, match="protected launch policy"):
        store.claim_or_create_draft(
            token_hash="fresh-official-owner-link",
            ceremony_id="0x" + "a2" * 32,
            draft=official_draft,
            now=101,
        )

    assert store.owner_claim_used("fresh-official-owner-link") is False
    assert store.active()["ceremony_id"] == stale_ceremony


def test_owner_claim_may_resume_only_an_exact_matching_active_draft(tmp_path) -> None:
    store = GenesisStore(tmp_path / "matching-owner-claim.db")
    ceremony_id = "0x" + "b1" * 32
    draft = {
        "schemaVersion": 2,
        "sourceManifestVersion": 4,
        "network": "testnet11",
        "evmChainId": 11155111,
        "reviewClass": "independent-release-review",
        "releaseTag": "solslot-v2-alpha-rc27.36-20260824",
        "releaseEvidenceHash": "0x" + "33" * 32,
        "sourceShas": {"api": "3" * 40},
    }
    store.create_draft(ceremony_id, draft, now=100)

    selected = store.claim_or_create_draft(
        token_hash="matching-official-owner-link",
        ceremony_id="0x" + "b2" * 32,
        draft=draft,
        now=101,
    )

    assert selected["ceremony_id"] == ceremony_id
    assert selected["draft"] == draft
    assert store.owner_claim_used("matching-official-owner-link") is True


def test_only_one_ceremony_can_reserve_global_finalization(tmp_path) -> None:
    store = GenesisStore(tmp_path / "finalization.db")
    first = "0x" + "a1" * 32
    second = "0x" + "a2" * 32
    store.create_draft(first, {}, now=100)
    store.create_draft(second, {}, now=101)
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='artifact_signed' "
            "WHERE ceremony_id IN (?,?)",
            (first, second),
        )

    store.reserve_finalization(first, now=110)

    with pytest.raises(GenesisConflict, match="owns finalization"):
        store.reserve_finalization(second, now=111)


def _enroll(store: GenesisStore, slot: int, now: int = 100) -> None:
    token_hash = f"token-{slot}"
    store.issue_invitation(
        CEREMONY,
        slot=slot,
        token_hash=token_hash,
        nonce=f"nonce-{slot}",
        expires_at=now + 1800,
        now=now,
    )
    store.consume_invitation(
        token_hash=token_hash,
        wallet_address="0x" + f"{slot:02x}" * 20,
        compressed_pubkey="0x" + f"{slot:02x}" * 33,
        signature="0x" + f"{slot:02x}" * 65,
        now=now + 1,
    )


def _planned_store(tmp_path) -> GenesisStore:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    for slot in (1, 2, 3):
        _enroll(store, slot)
    store.freeze_roster(CEREMONY, ROSTER, now=110)
    store.set_plan(
        CEREMONY,
        plan_input={"funding": []},
        plan={"planHash": PLAN},
        plan_hash=PLAN,
        expires_at=1000,
        now=120,
    )
    return store


def _approve_plan(store: GenesisStore) -> None:
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )


def _reserve_bundle(
    store: GenesisStore,
    *,
    now: int = 140,
    expected_plan_hash: str = PLAN,
    gate_authorization: dict | None = None,
) -> dict:
    return store.reserve_broadcast(
        CEREMONY,
        expected_plan_hash=expected_plan_hash,
        spend_bundle_id=BUNDLE_ID,
        spend_bundle=SPEND_BUNDLE,
        fee_coin_id=FEE_COIN_ID,
        fee_mojos=FEE_MOJOS,
        ceremony_evidence=CEREMONY_EVIDENCE,
        gate_authorization=gate_authorization,
        now=now,
    )


def _broadcast_response() -> dict:
    return {
        "success": True,
        "status": "MEMPOOL",
        "spendBundleId": BUNDLE_ID,
        "spendBundle": SPEND_BUNDLE,
        "feeCoinId": FEE_COIN_ID,
        "feeMojos": str(FEE_MOJOS),
    }


def _confirmation_evidence(height: int) -> dict:
    return {
        "schemaVersion": 1,
        "spendBundleId": BUNDLE_ID,
        "exactReservedCoinSpends": True,
        "inputCoinIds": ["0x" + "77" * 32],
        "confirmedBlockIndex": height,
    }


def _reserve_and_finalize(store: GenesisStore, *, now: int = 140) -> dict:
    _reserve_bundle(store, now=now)
    return store.mark_broadcast(
        CEREMONY,
        spend_bundle_id=BUNDLE_ID,
        response=_broadcast_response(),
        now=now + 1,
    )


def test_chain_reconciliation_finalizes_and_confirms_in_one_transaction(
    tmp_path,
) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)
    _reserve_bundle(store, now=140)
    response = {
        **_broadcast_response(),
        "status": "CHAIN_RECONCILED",
        "submissionProvider": "exact-chain-reconciliation",
    }

    confirmed = store.mark_chain_reconciled_confirmed(
        CEREMONY,
        spend_bundle_id=BUNDLE_ID,
        response=response,
        confirmed_block_index=500,
        confirmation_evidence=_confirmation_evidence(500),
        now=150,
    )

    assert confirmed["state"] == "confirmed"
    assert confirmed["confirmed_block_index"] == 500
    assert confirmed["broadcast"]["reservationState"] == "FINALIZED"
    assert confirmed["broadcast"]["status"] == "CHAIN_RECONCILED"
    assert confirmed["broadcast"]["chainConfirmation"] == (
        _confirmation_evidence(500)
    )
    assert store.pending_exact_fee_coin_ids() == set()


def test_failed_chain_reconciliation_leaves_exact_reservation_unchanged(
    tmp_path,
) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)
    before = _reserve_bundle(store, now=140)

    with pytest.raises(GenesisConflict, match="changed the reserved fee coin"):
        store.mark_chain_reconciled_confirmed(
            CEREMONY,
            spend_bundle_id=BUNDLE_ID,
            response={**_broadcast_response(), "feeCoinId": "0x" + "99" * 32},
            confirmed_block_index=500,
            confirmation_evidence=_confirmation_evidence(500),
            now=150,
        )

    after = store.get(CEREMONY)
    assert after["state"] == "broadcast"
    assert after["broadcast"] == before["broadcast"]


def test_three_single_use_invitations_freeze_roster(tmp_path) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    for slot in (1, 2, 3):
        _enroll(store, slot)
    frozen = store.freeze_roster(CEREMONY, ROSTER, now=110)
    assert frozen["state"] == "roster_frozen"
    assert frozen["roster_hash"] == ROSTER
    with pytest.raises(GenesisConflict, match="already consumed"):
        store.consume_invitation(
            token_hash="token-1",
            wallet_address="0x" + "01" * 20,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=111,
        )


def test_roster_cannot_freeze_early_or_reuse_wallet(tmp_path) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {}, now=100)
    _enroll(store, 1)
    with pytest.raises(GenesisConflict, match="all three"):
        store.freeze_roster(CEREMONY, ROSTER, now=110)
    store.issue_invitation(
        CEREMONY,
        slot=2,
        token_hash="token-2",
        nonce="nonce-2",
        expires_at=1000,
        now=100,
    )
    with pytest.raises(GenesisConflict, match="already enrolled"):
        store.consume_invitation(
            token_hash="token-2",
            wallet_address="0x" + "01" * 20,
            compressed_pubkey="0x" + "02" * 33,
            signature="0x" + "02" * 65,
            now=101,
        )


def test_owner_plus_one_plan_signatures_unlock_broadcast(tmp_path) -> None:
    store = _planned_store(tmp_path)
    one = store.add_plan_signature(
        CEREMONY,
        slot=1,
        plan_hash=PLAN,
        compressed_pubkey="0x" + "01" * 33,
        signature="0x" + "01" * 65,
        now=130,
    )
    assert one["state"] == "planned"
    with pytest.raises(GenesisConflict, match="already signed"):
        store.add_plan_signature(
            CEREMONY,
            slot=1,
            plan_hash=PLAN,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=131,
        )
    two = store.add_plan_signature(
        CEREMONY,
        slot=2,
        plan_hash=PLAN,
        compressed_pubkey="0x" + "02" * 33,
        signature="0x" + "02" * 65,
        now=132,
    )
    assert two["state"] == "plan_approved"
    reserved = _reserve_bundle(store, now=133)
    assert reserved["broadcast"]["reservationState"] == "RESERVED"
    broadcast = store.mark_broadcast(
        CEREMONY,
        spend_bundle_id=BUNDLE_ID,
        response=_broadcast_response(),
        now=134,
    )
    assert broadcast["state"] == "broadcast"
    assert broadcast["broadcast"]["reservationState"] == "FINALIZED"


def test_two_coadmins_cannot_approve_plan_without_owner(tmp_path) -> None:
    store = _planned_store(tmp_path)
    for slot in (2, 3):
        result = store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    assert result["state"] == "planned"
    with pytest.raises(GenesisConflict, match="expected plan_approved"):
        _reserve_bundle(store, now=140)


def test_expired_plan_and_mutated_hash_fail_closed(tmp_path) -> None:
    store = _planned_store(tmp_path)
    with pytest.raises(GenesisConflict, match="current plan"):
        store.add_plan_signature(
            CEREMONY,
            slot=1,
            plan_hash="0x" + "99" * 32,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=130,
        )
    with pytest.raises(GenesisExpired, match="expired"):
        store.add_plan_signature(
            CEREMONY,
            slot=1,
            plan_hash=PLAN,
            compressed_pubkey="0x" + "01" * 33,
            signature="0x" + "01" * 65,
            now=1001,
        )


def test_broadcast_reservation_requires_exact_live_plan(tmp_path) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)

    with pytest.raises(GenesisConflict, match="plan changed"):
        _reserve_bundle(
            store,
            expected_plan_hash="0x" + "99" * 32,
            now=999,
        )
    with pytest.raises(GenesisExpired, match="expired"):
        _reserve_bundle(store, now=1000)

    reserved = _reserve_bundle(store, now=999)
    assert reserved["state"] == "broadcast"
    assert reserved["spend_bundle_id"] == BUNDLE_ID
    assert reserved["broadcast"] == {
        "reservationSchemaVersion": 1,
        "reservationState": "RESERVED",
        "planHash": PLAN,
        "spendBundleId": BUNDLE_ID,
        "spendBundle": SPEND_BUNDLE,
        "feeCoinId": FEE_COIN_ID,
        "feeMojos": str(FEE_MOJOS),
        "reservedAt": 999,
        "ceremonyEvidence": CEREMONY_EVIDENCE,
    }
    reservation_event = store.audit_events(CEREMONY)[-1]
    assert reservation_event["type"] == "bundle_broadcast_reserved"
    assert reservation_event["details"]["spendBundleId"] == BUNDLE_ID
    assert reservation_event["createdAt"] == 999


def test_broadcast_reservation_requires_exact_open_gate_binding(tmp_path) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)
    payload_hash = "0x" + "81" * 32
    store.upsert_gate(
        CEREMONY,
        gate_name="ceremonyBroadcast",
        opens_at=200,
        closes_at=300,
        payload_hash=payload_hash,
        state="open",
        now=150,
    )
    authorization = {
        "gate": "ceremonyBroadcast",
        "payloadHash": payload_hash,
        "opensAt": 200,
        "closesAt": 300,
        "configuredState": "open",
        "state": "open",
        "approved": True,
    }

    with pytest.raises(GenesisConflict, match="authorization changed"):
        _reserve_bundle(
            store,
            gate_authorization={
                **authorization,
                "payloadHash": "0x" + "82" * 32,
            },
            now=250,
        )
    with pytest.raises(GenesisConflict, match="gate is closed"):
        _reserve_bundle(store, gate_authorization=authorization, now=300)

    reserved = _reserve_bundle(
        store,
        gate_authorization=authorization,
        now=250,
    )
    assert reserved["broadcast"]["gateAuthorization"] == authorization


def test_plan_renewal_and_broadcast_reservation_are_atomic(tmp_path) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)
    barrier = threading.Barrier(2)
    renewed_hash = "0x" + "77" * 32
    renewed_plan = {
        "planHash": renewed_hash,
        "expiresAt": 2000,
    }

    def reserve() -> str:
        barrier.wait()
        try:
            _reserve_bundle(store, now=999)
            return "reserved"
        except GenesisConflict:
            return "conflict"

    def renew() -> str:
        barrier.wait()
        try:
            store.renew_expired_plan(
                CEREMONY,
                expected_plan_hash=PLAN,
                plan=renewed_plan,
                plan_hash=renewed_hash,
                expires_at=2000,
                now=1000,
            )
            return "renewed"
        except GenesisConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(reserve), pool.submit(renew)]
        outcomes = [result.result() for result in results]

    assert outcomes.count("conflict") == 1
    assert set(outcomes) in ({"conflict", "reserved"}, {"conflict", "renewed"})
    assert store.get(CEREMONY)["state"] in {"broadcast", "planned"}


def test_broadcast_finalize_requires_and_preserves_exact_reservation(tmp_path) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)
    _reserve_bundle(store, now=999)

    with pytest.raises(GenesisConflict, match="expected plan_approved"):
        _reserve_bundle(store, now=999)
    with pytest.raises(GenesisConflict, match="bundle id"):
        store.mark_broadcast(
            CEREMONY,
            spend_bundle_id="0x" + "88" * 32,
            response=_broadcast_response(),
            now=1000,
        )
    with pytest.raises(GenesisConflict, match="spend bundle"):
        store.mark_broadcast(
            CEREMONY,
            spend_bundle_id=BUNDLE_ID,
            response={
                **_broadcast_response(),
                "spendBundle": {"coin_spends": []},
            },
            now=1000,
        )

    finalized = store.mark_broadcast(
        CEREMONY,
        spend_bundle_id=BUNDLE_ID,
        response=_broadcast_response(),
        now=1001,
    )
    assert finalized["broadcast"]["reservationState"] == "FINALIZED"
    assert finalized["broadcast"]["reservedAt"] == 999
    assert finalized["broadcast"]["finalizedAt"] == 1001
    duplicate = store.mark_broadcast(
        CEREMONY,
        spend_bundle_id=BUNDLE_ID,
        response=_broadcast_response(),
        now=1100,
    )
    assert duplicate["broadcast"]["finalizedAt"] == 1001


def test_pending_broadcast_fee_coin_survives_restart_and_cannot_be_abandoned(
    tmp_path,
) -> None:
    store = _planned_store(tmp_path)
    _approve_plan(store)
    _reserve_bundle(store, now=140)

    reopened = GenesisStore(tmp_path / "genesis.db")
    assert reopened.pending_exact_fee_coin_ids() == {FEE_COIN_ID}
    with pytest.raises(GenesisConflict, match="cannot be abandoned"):
        reopened.abandon(CEREMONY, "ambiguous submission", now=141)
    assert reopened.pending_exact_fee_coin_ids() == {FEE_COIN_ID}

    with reopened._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET broadcast_json='{}' WHERE ceremony_id=?",
            (CEREMONY,),
        )
    with pytest.raises(GenesisConflict, match="reservation is invalid"):
        reopened.pending_exact_fee_coin_ids()


def test_schema_11_preserves_locked_legacy_evidence_but_rejects_active_legacy(
    tmp_path,
) -> None:
    locked_path = tmp_path / "locked-legacy.db"
    locked = GenesisStore(locked_path)
    locked.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    with locked._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='locked',spend_bundle_id=?,"
            "broadcast_json=? WHERE ceremony_id=?",
            (BUNDLE_ID, '{"status":"legacy-complete"}', CEREMONY),
        )
        connection.execute("PRAGMA user_version = 10")

    reopened = GenesisStore(locked_path)
    assert reopened.get(CEREMONY)["broadcast"] == {
        "status": "legacy-complete"
    }

    active_path = tmp_path / "active-legacy.db"
    active = GenesisStore(active_path)
    active.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    with active._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='broadcast',spend_bundle_id=?,"
            "broadcast_json=? WHERE ceremony_id=?",
            (BUNDLE_ID, '{"status":"legacy-unknown"}', CEREMONY),
        )
        connection.execute("PRAGMA user_version = 10")

    with pytest.raises(RuntimeError, match="unreconciled legacy"):
        GenesisStore(active_path)


def test_expired_plan_renewal_is_atomic_and_requires_fresh_signatures(
    tmp_path,
) -> None:
    store = _planned_store(tmp_path)
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    before = store.get(CEREMONY)
    renewed_hash = "0x" + "55" * 32
    renewed_plan = {
        **before["plan"],
        "expiresAt": 2000,
        "planHash": renewed_hash,
    }

    renewed = store.renew_expired_plan(
        CEREMONY,
        expected_plan_hash=PLAN,
        plan=renewed_plan,
        plan_hash=renewed_hash,
        expires_at=2000,
        now=1001,
    )

    assert renewed["state"] == "planned"
    assert renewed["plan_signatures"] == []
    assert renewed["plan_input"] == before["plan_input"]
    assert renewed["roster_hash"] == before["roster_hash"]
    one = store.add_plan_signature(
        CEREMONY,
        slot=1,
        plan_hash=renewed_hash,
        compressed_pubkey="0x" + "01" * 33,
        signature="0x" + "01" * 65,
        now=1100,
    )
    assert one["state"] == "planned"
    two = store.add_plan_signature(
        CEREMONY,
        slot=2,
        plan_hash=renewed_hash,
        compressed_pubkey="0x" + "02" * 33,
        signature="0x" + "02" * 65,
        now=1101,
    )
    assert two["state"] == "plan_approved"


def test_plan_renewal_rejects_live_plan_cas_drift_and_binding_changes(
    tmp_path,
) -> None:
    store = _planned_store(tmp_path)
    renewed_hash = "0x" + "55" * 32
    renewed_plan = {
        "planHash": renewed_hash,
        "expiresAt": 2000,
    }
    with pytest.raises(GenesisConflict, match="has not expired"):
        store.renew_expired_plan(
            CEREMONY,
            expected_plan_hash=PLAN,
            plan=renewed_plan,
            plan_hash=renewed_hash,
            expires_at=2000,
            now=999,
        )
    with pytest.raises(GenesisConflict, match="changed before renewal"):
        store.renew_expired_plan(
            CEREMONY,
            expected_plan_hash="0x" + "66" * 32,
            plan=renewed_plan,
            plan_hash=renewed_hash,
            expires_at=2000,
            now=1001,
        )
    changed_plan = {
        **renewed_plan,
        "fundingCoinIds": {"sgt": "0x" + "77" * 32},
    }
    with pytest.raises(GenesisConflict, match="immutable ceremony bindings"):
        store.renew_expired_plan(
            CEREMONY,
            expected_plan_hash=PLAN,
            plan=changed_plan,
            plan_hash=renewed_hash,
            expires_at=2000,
            now=1001,
        )


def test_artifact_requires_two_roster_signatures_before_lock(tmp_path) -> None:
    store = _planned_store(tmp_path)
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    _reserve_and_finalize(store, now=140)
    store.mark_confirmed(
        CEREMONY,
        confirmed_block_index=500,
        confirmation_evidence=_confirmation_evidence(500),
        now=150,
    )
    store.set_artifact(
        CEREMONY,
        artifact={"artifactHash": ARTIFACT},
        artifact_hash=ARTIFACT,
        now=160,
    )
    first = store.add_artifact_signature(
        CEREMONY,
        slot=1,
        artifact_hash=ARTIFACT,
        compressed_pubkey="0x" + "01" * 33,
        signature="0x" + "01" * 65,
        now=170,
    )
    assert first["state"] == "artifact_pending"
    with pytest.raises(GenesisConflict, match="expected artifact_signed"):
        store.mark_locked(CEREMONY, now=171)
    store.add_artifact_signature(
        CEREMONY,
        slot=3,
        artifact_hash=ARTIFACT,
        compressed_pubkey="0x" + "03" * 33,
        signature="0x" + "03" * 65,
        now=172,
    )
    record = store.get(CEREMONY)
    store.reserve_finalization(
        CEREMONY,
        publication={
            "schemaVersion": 1,
            "artifact": {
                **record["artifact"],
                "signatures": [
                    {
                        "adminIndex": int(entry["slot"]) - 1,
                        "compressedPubkey": entry["compressed_pubkey"],
                        "signature": entry["signature"],
                    }
                    for entry in record["artifact_signatures"]
                ],
            },
            "bootstrapLock": {"lockedAt": 173},
        },
        now=173,
    )
    assert store.mark_locked(CEREMONY, now=173)["state"] == "locked"


def test_settlement_rehearsal_state_is_forward_only_and_payload_is_readable(
    tmp_path,
) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    prepared = store.set_settlement_rehearsal(
        CEREMONY,
        job_id="rehearsal_job_0001",
        config_hash="0x" + "aa" * 32,
        state="AWAITING_WALLET",
        payload={"step": "Review the test purchase"},
        now=110,
    )
    assert prepared["payload"]["step"] == "Review the test purchase"

    validating = store.set_settlement_rehearsal(
        CEREMONY,
        job_id="rehearsal_job_0001",
        config_hash="0x" + "aa" * 32,
        state="VALIDATING",
        payload={"step": "Validators are checking delivery"},
        now=120,
    )
    assert validating["state"] == "VALIDATING"

    with pytest.raises(GenesisConflict, match="move backwards"):
        store.set_settlement_rehearsal(
            CEREMONY,
            job_id="rehearsal_job_0001",
            config_hash="0x" + "aa" * 32,
            state="PAYMENT_SUBMITTED",
            payload={"step": "Stale response"},
            now=121,
        )
def test_guided_launch_owner_claim_profiles_and_wallet_resume_are_persistent(
    tmp_path,
) -> None:
    path = tmp_path / "genesis.db"
    store = GenesisStore(path)
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    store.consume_owner_claim(CEREMONY, token_hash="owner-link", now=101)
    assert store.owner_claim_used("owner-link") is True
    with pytest.raises(GenesisConflict, match="already consumed"):
        store.consume_owner_claim(CEREMONY, token_hash="owner-link", now=102)

    store.set_profile(
        CEREMONY,
        slot=1,
        display_name="Owner",
        role_label="Owner",
        email="owner@example.com",
        timezone="America/Chicago",
        reminders_enabled=True,
        now=103,
    )
    _enroll(store, 1, now=110)
    nonce_hash = "resume-nonce"
    store.create_auth_challenge(
        CEREMONY,
        slot=1,
        wallet_address="0x" + "01" * 20,
        nonce_hash=nonce_hash,
        expires_at=1000,
        now=120,
     settings=bootstrap_settings(store))
    reopened = GenesisStore(path)
    challenge = reopened.consume_auth_challenge(
        nonce_hash=nonce_hash,
        wallet_address="0x" + "01" * 20,
        now=121,
     settings=bootstrap_settings(reopened))
    assert challenge["slot"] == 1
    assert reopened.profiles(CEREMONY)[1]["displayName"] == "Owner"
    with pytest.raises(GenesisConflict, match="already used"):
        reopened.consume_auth_challenge(
            nonce_hash=nonce_hash,
            wallet_address="0x" + "01" * 20,
            now=122,
         settings=bootstrap_settings(reopened))


def test_guided_action_requires_owner_plus_one_and_rejects_changed_payload(
    tmp_path,
) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {}, now=100)
    for slot in (1, 2, 3):
        _enroll(store, slot)
    action_id = "0x" + "91" * 32
    payload_hash = "0x" + "92" * 32
    one = store.add_action_approval(
        CEREMONY,
        action_id=action_id,
        action_type="funding",
        payload_hash=payload_hash,
        slot=1,
        signer_address="0x" + "01" * 20,
        signature="0x" + "01" * 65,
        expires_at=200,
        now=130,
     settings=bootstrap_settings(store))
    assert one["approved"] is False
    assert owner_plus_one_approved(set(one["slots"])) is False
    two = store.add_action_approval(
        CEREMONY,
        action_id=action_id,
        action_type="funding",
        payload_hash=payload_hash,
        slot=3,
        signer_address="0x" + "03" * 20,
        signature="0x" + "03" * 65,
        expires_at=200,
        now=131,
     settings=bootstrap_settings(store))
    assert two["approved"] is True
    with pytest.raises(GenesisConflict, match="already approved"):
        store.add_action_approval(
            CEREMONY,
            action_id=action_id,
            action_type="funding",
            payload_hash="0x" + "99" * 32,
            slot=1,
            signer_address="0x" + "01" * 20,
            signature="0x" + "04" * 65,
            expires_at=200,
            now=132,
         settings=bootstrap_settings(store))

    assert store.action_approvals(CEREMONY, action_id, now=200, settings=bootstrap_settings(store))["approved"] is True
    expired = store.action_approvals(CEREMONY, action_id, now=201, settings=bootstrap_settings(store))
    assert expired["approved"] is False
    assert expired["slots"] == []
    for slot in (1, 3):
        renewed = store.add_action_approval(
            CEREMONY,
            action_id=action_id,
            action_type="funding",
            payload_hash=payload_hash,
            slot=slot,
            signer_address="0x" + f"{slot:02x}" * 20,
            signature="0x" + f"{slot + 10:02x}" * 65,
            expires_at=300,
            now=210 + slot,
         settings=bootstrap_settings(store))
    assert renewed["approved"] is True


def test_guided_gate_expires_fail_closed_and_funding_plan_is_immutable(tmp_path) -> None:
    store = GenesisStore(tmp_path / "genesis.db")
    store.create_draft(CEREMONY, {}, now=100)
    payload_hash = "0x" + "82" * 32
    store.upsert_gate(
        CEREMONY,
        gate_name="ceremonyBroadcast",
        opens_at=200,
        closes_at=300,
        payload_hash=payload_hash,
        state="pending",
        now=150,
    )
    pending = store.gates(CEREMONY, now=250)["ceremonyBroadcast"]
    assert pending["configuredState"] == "pending"
    assert pending["state"] == "pending"
    assert store.gates(CEREMONY, now=301)["ceremonyBroadcast"]["state"] == "pending"

    store.upsert_gate(
        CEREMONY,
        gate_name="ceremonyBroadcast",
        opens_at=200,
        closes_at=300,
        payload_hash=payload_hash,
        state="open",
        now=151,
    )
    before_open = store.gates(CEREMONY, now=199)["ceremonyBroadcast"]
    assert before_open["configuredState"] == "open"
    assert before_open["state"] == "pending"
    assert store.gates(CEREMONY, now=250)["ceremonyBroadcast"]["state"] == "open"
    assert store.gates(CEREMONY, now=300)["ceremonyBroadcast"]["state"] == "closed"

    plan = {"sourceCoinId": "0x" + "a1" * 32, "outputs": []}
    store.set_funding_receipt(
        CEREMONY,
        plan=plan,
        plan_hash="0x" + "83" * 32,
        now=160,
    )
    with pytest.raises(GenesisConflict, match="already sealed"):
        store.set_funding_receipt(
            CEREMONY,
            plan={"sourceCoinId": "0x" + "a2" * 32, "outputs": []},
            plan_hash="0x" + "84" * 32,
            now=161,
        )


def test_two_coadmins_cannot_sign_artifact_without_owner(tmp_path) -> None:
    store = _planned_store(tmp_path)
    for slot in (1, 2):
        store.add_plan_signature(
            CEREMONY,
            slot=slot,
            plan_hash=PLAN,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=130 + slot,
        )
    _reserve_and_finalize(store, now=140)
    store.mark_confirmed(
        CEREMONY,
        confirmed_block_index=500,
        confirmation_evidence=_confirmation_evidence(500),
        now=150,
    )
    store.set_artifact(
        CEREMONY,
        artifact={"artifactHash": ARTIFACT},
        artifact_hash=ARTIFACT,
        now=160,
    )
    for slot in (2, 3):
        result = store.add_artifact_signature(
            CEREMONY,
            slot=slot,
            artifact_hash=ARTIFACT,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=170 + slot,
        )
    assert result["state"] == "artifact_pending"
    with pytest.raises(GenesisConflict, match="expected artifact_signed"):
        store.mark_locked(CEREMONY, now=180)
