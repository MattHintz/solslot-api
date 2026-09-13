from __future__ import annotations

import pytest

from solslot_api.genesis_store import (
    SCHEMA_VERSION,
    GenesisConflict,
    GenesisNotFound,
    GenesisStore,
)


CEREMONY_ID = "0x" + "11" * 32
CHALLENGE_HASH = "0x" + "22" * 32
INTENT_HASH = "0x" + "33" * 32


def _store() -> GenesisStore:
    store = GenesisStore(":memory:")
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    return store


def _public_kit(revision: int = 1, *, ceremony_slot: int = 1) -> dict:
    return {
        "schemaVersion": 1,
        # Storage uses ceremony slots 1..3; signed/public payloads use 0..2.
        "slot": ceremony_slot - 1,
        "revision": revision,
        "evmGuardian": "0x" + f"{0x43 + ceremony_slot:02x}" * 20,
        "recoveryBlsPubkey": "0x" + f"{0x54 + ceremony_slot:02x}" * 48,
        "recoveryBlsCommitment": "0x" + f"{0x65 + ceremony_slot:02x}" * 32,
    }


def _complete_kit(
    store: GenesisStore,
    *,
    challenge_id: str = "drill-1",
    challenge_hash: str = CHALLENGE_HASH,
    revision: int = 1,
    now: int = 101,
) -> dict:
    store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id=challenge_id,
        slot=1,
        challenge_hash=challenge_hash,
        public_payload=_public_kit(revision),
        expires_at=now + 900,
        now=now,
    )
    return store.complete_recovery_drill(
        challenge_id,
        expected_challenge_hash=challenge_hash,
        backup_status="VERIFIED",
        backup_revision=revision,
        backup_ciphertext_hash="0x" + "77" * 32,
        now=now + 1,
    )


def test_current_schema_keeps_only_public_recovery_evidence() -> None:
    store = _store()
    with store._connect() as connection:  # noqa: SLF001 - migration assertion
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == (
            SCHEMA_VERSION
        )

    kit = _complete_kit(store)
    assert kit["slot"] == 0
    assert kit["revision"] == 1
    assert kit["backupStatus"] == "VERIFIED"
    assert set(kit).isdisjoint(
        {"mnemonic", "password", "privateKey", "googleEmail", "oauthToken"}
    )


def test_drill_is_single_use_and_recovery_revision_cannot_roll_back() -> None:
    store = _store()
    _complete_kit(store)
    with pytest.raises(GenesisConflict, match="already used"):
        store.complete_recovery_drill(
            "drill-1",
            expected_challenge_hash=CHALLENGE_HASH,
            backup_status="NOT_CONFIGURED",
            backup_revision=None,
            backup_ciphertext_hash=None,
            now=104,
        )

    store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id="drill-2",
        slot=1,
        challenge_hash="0x" + "88" * 32,
        public_payload=_public_kit(1),
        expires_at=1_100,
        now=200,
    )
    with pytest.raises(GenesisConflict, match="next revision"):
        store.complete_recovery_drill(
            "drill-2",
            expected_challenge_hash="0x" + "88" * 32,
            backup_status="NOT_CONFIGURED",
            backup_revision=None,
            backup_ciphertext_hash=None,
            now=201,
        )


def test_recovery_kit_replacement_stays_pending_until_activation() -> None:
    store = _store()
    original = _complete_kit(store)
    replacement_hash = "0x" + "88" * 32
    store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id="drill-2",
        slot=1,
        challenge_hash=replacement_hash,
        public_payload={
            **_public_kit(2),
            "evmGuardian": "0x" + "45" * 20,
            "recoveryBlsPubkey": "0x" + "56" * 48,
            "recoveryBlsCommitment": "0x" + "67" * 32,
        },
        expires_at=1_100,
        now=200,
    )
    candidate = store.complete_recovery_drill(
        "drill-2",
        expected_challenge_hash=replacement_hash,
        backup_status="NOT_CONFIGURED",
        backup_revision=None,
        backup_ciphertext_hash=None,
        now=201,
    )

    assert candidate["state"] == "PENDING"
    assert candidate["revision"] == 2
    assert store.recovery_kit(CEREMONY_ID, 1) == original
    activated = store.activate_recovery_kit_candidate("drill-2", now=202)
    assert activated["revision"] == 2
    assert activated["evmGuardian"] == "0x" + "45" * 20
    assert store.recovery_kit_candidate("drill-2")["state"] == "ACTIVATED"


def test_cancelled_recovery_kit_candidate_never_changes_active_kit() -> None:
    store = _store()
    original = _complete_kit(store)
    replacement_hash = "0x" + "89" * 32
    store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id="drill-cancel",
        slot=1,
        challenge_hash=replacement_hash,
        public_payload={
            **_public_kit(2),
            "evmGuardian": "0x" + "46" * 20,
        },
        expires_at=1_100,
        now=200,
    )
    store.complete_recovery_drill(
        "drill-cancel",
        expected_challenge_hash=replacement_hash,
        backup_status="NOT_CONFIGURED",
        backup_revision=None,
        backup_ciphertext_hash=None,
        now=201,
    )
    cancelled = store.cancel_recovery_kit_candidate(
        "drill-cancel",
        now=202,
    )

    assert cancelled["state"] == "CANCELLED"
    assert store.recovery_kit(CEREMONY_ID, 1) == original
    with pytest.raises(GenesisConflict, match="not pending"):
        store.activate_recovery_kit_candidate("drill-cancel", now=203)


@pytest.mark.parametrize("candidate_state", ["PENDING", "ACTIVATED", "CANCELLED"])
def test_recovery_drill_cleanup_preserves_replacement_evidence(
    tmp_path,
    candidate_state: str,
) -> None:
    path = tmp_path / "recovery.db"
    store = GenesisStore(path)
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    _complete_kit(store)
    initial_drill = store.recovery_drill("drill-1")
    _complete_kit(
        store,
        challenge_id="replacement",
        challenge_hash="0x" + "81" * 32,
        revision=2,
        now=200,
    )
    if candidate_state == "ACTIVATED":
        store.activate_recovery_kit_candidate("replacement", now=202)
    elif candidate_state == "CANCELLED":
        store.cancel_recovery_kit_candidate("replacement", now=202)
    candidate = store.recovery_kit_candidate("replacement")
    replacement_drill = store.recovery_drill("replacement")
    active_kit = store.recovery_kit(CEREMONY_ID, 1)
    assert candidate["state"] == candidate_state

    # Reopening exercises the persistent foreign keys, after proof expiry.
    store = GenesisStore(path)
    other_public = _public_kit(ceremony_slot=2)
    other_drill = store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id="other-slot",
        slot=2,
        challenge_hash="0x" + "82" * 32,
        public_payload=other_public,
        expires_at=3_000,
        now=2_000,
    )
    other_kit = store.complete_recovery_drill(
        "other-slot",
        expected_challenge_hash="0x" + "82" * 32,
        backup_status="NOT_CONFIGURED",
        backup_revision=None,
        backup_ciphertext_hash=None,
        now=2_001,
    )
    assert other_drill["slot"] == 2
    assert other_drill["public"]["slot"] == other_kit["slot"] == 1
    assert other_kit["evmGuardian"] == other_public["evmGuardian"]
    assert other_kit["evmGuardian"] != active_kit["evmGuardian"]
    assert other_kit["recoveryBlsPubkey"] != active_kit["recoveryBlsPubkey"]
    other_ceremony = "0x" + "12" * 32
    store.create_draft(other_ceremony, {"network": "testnet11"}, now=2_002)
    store.create_recovery_drill(
        other_ceremony,
        challenge_id="other-ceremony",
        slot=1,
        challenge_hash="0x" + "83" * 32,
        public_payload=_public_kit(),
        expires_at=3_000,
        now=2_003,
    )
    if candidate_state != "PENDING":
        store.create_recovery_drill(
            CEREMONY_ID,
            challenge_id="next-replacement",
            slot=1,
            challenge_hash="0x" + "84" * 32,
            public_payload=_public_kit(int(active_kit["revision"]) + 1),
            expires_at=3_000,
            now=2_004,
        )

    assert store.recovery_drill("drill-1") == initial_drill
    assert store.recovery_drill("replacement") == replacement_drill
    assert store.recovery_kit_candidate("replacement") == candidate
    assert store.recovery_kit(CEREMONY_ID, 1) == active_kit
    for drill in (initial_drill, replacement_drill):
        with pytest.raises(GenesisConflict, match="already used"):
            store.complete_recovery_drill(
                drill["challengeId"],
                expected_challenge_hash=drill["challengeHash"],
                backup_status="NOT_CONFIGURED",
                backup_revision=None,
                backup_ciphertext_hash=None,
                now=2_005,
            )


def test_recovery_drill_cleanup_removes_only_expired_unused_challenges() -> None:
    store = _store()
    _complete_kit(store)
    completed = store.recovery_drill("drill-1")
    for challenge_id, expires_at in (("expired", 299), ("still-valid", 300)):
        store.create_recovery_drill(
            CEREMONY_ID,
            challenge_id=challenge_id,
            slot=2,
            challenge_hash="0x" + f"{expires_at:064x}",
            public_payload=_public_kit(ceremony_slot=2),
            expires_at=expires_at,
            now=200,
        )
    still_valid = store.recovery_drill("still-valid")
    created = store.create_recovery_drill(
        CEREMONY_ID,
        challenge_id="new-drill",
        slot=3,
        challenge_hash="0x" + "85" * 32,
        public_payload=_public_kit(ceremony_slot=3),
        expires_at=1_000,
        now=300,
    )

    with pytest.raises(GenesisNotFound, match="challenge not found"):
        store.recovery_drill("expired")
    assert store.recovery_drill("still-valid") == still_valid
    assert store.recovery_drill("drill-1") == completed
    assert created["challengeId"] == "new-drill"
    assert created["slot"] == 3
    assert created["public"]["slot"] == 2


def test_only_one_key_change_can_be_active_and_receipts_are_append_only() -> None:
    store = _store()
    case = store.create_recovery_case(
        CEREMONY_ID,
        case_id="case-1",
        authority_slot=0,
        kind="ROUTINE",
        intent_hash=INTENT_HASH,
        intent={"schemaVersion": 1, "slot": 0},
        execute_after=86_500,
        expires_at=173_000,
        prepared_by="0x" + "99" * 20,
        now=100,
    )
    assert case["state"] == "AWAITING_APPROVALS"

    with pytest.raises(GenesisConflict, match="another administrator"):
        store.create_recovery_case(
            CEREMONY_ID,
            case_id="case-2",
            authority_slot=1,
            kind="LOST",
            intent_hash="0x" + "aa" * 32,
            intent={"schemaVersion": 1, "slot": 1},
            execute_after=604_900,
            expires_at=700_000,
            prepared_by="0x" + "bb" * 20,
            now=101,
        )

    store.add_recovery_approval(
        "case-1",
        actor_role="AUTHORITY",
        actor_id="slot-0",
        signer_slot=0,
        signer_address="0x" + "99" * 20,
        signature="0x" + "cc" * 65,
        message_hash=INTENT_HASH,
        now=102,
    )
    store.add_recovery_receipt(
        "case-1",
        chain="CHIA",
        phase="PREPARE",
        transaction_id="0x" + "dd" * 32,
        receipt_hash="0x" + "ee" * 32,
        receipt={"confirmed": True},
        now=103,
    )
    with pytest.raises(GenesisConflict, match="already recorded"):
        store.add_recovery_receipt(
            "case-1",
            chain="CHIA",
            phase="PREPARE",
            transaction_id="0x" + "ff" * 32,
            receipt_hash="0x" + "00" * 32,
            receipt={"confirmed": True},
            now=104,
        )

    completed = store.add_recovery_receipt(
        "case-1",
        chain="CHIA",
        phase="COMPLETE",
        transaction_id="0x" + "12" * 32,
        receipt_hash="0x" + "13" * 32,
        receipt={"confirmed": True},
        now=105,
    )
    assert [
        (item["chain"], item["phase"])
        for item in completed["receipts"]
    ] == [("CHIA", "PREPARE"), ("CHIA", "COMPLETE")]


def test_chia_recovery_signatures_are_action_bound_and_public_view_is_redacted() -> None:
    store = _store()
    store.create_recovery_case(
        CEREMONY_ID,
        case_id="case-chia-signatures",
        authority_slot=1,
        kind="LOST",
        intent_hash=INTENT_HASH,
        intent={"schemaVersion": 1, "slot": 1},
        execute_after=604_900,
        expires_at=700_000,
        prepared_by="0x" + "99" * 20,
        now=100,
    )
    signature = "0x" + "aa" * 96
    action_id = "0x" + "bb" * 32
    message_hash = "0x" + "cc" * 32
    case = store.add_recovery_chia_signature(
        "case-chia-signatures",
        phase="PREPARE",
        action_id=action_id,
        signer_kind="BLS_RECOVERY",
        signer_slot=1,
        signer_public_key="0x" + "dd" * 48,
        signature=signature,
        message_hash=message_hash,
        now=101,
    )

    assert case["chiaSignatures"] == [
        {
            "phase": "PREPARE",
            "actionId": action_id,
            "signerKind": "BLS_RECOVERY",
            "signerSlot": 1,
            "signerPublicKey": "0x" + "dd" * 48,
            "messageHash": message_hash,
            "submittedAt": 101,
        }
    ]
    assert "signature" not in case["chiaSignatures"][0]
    internal = store.recovery_chia_signatures(
        "case-chia-signatures",
        phase="PREPARE",
        include_signatures=True,
    )
    assert internal[0]["signature"] == signature

    with pytest.raises(GenesisConflict, match="already signed"):
        store.add_recovery_chia_signature(
            "case-chia-signatures",
            phase="PREPARE",
            action_id=action_id,
            signer_kind="BLS_RECOVERY",
            signer_slot=1,
            signer_public_key="0x" + "dd" * 48,
            signature=signature,
            message_hash=message_hash,
            now=102,
        )


def test_evm_safe_signatures_resume_and_stale_nonce_invalidates_the_package() -> None:
    store = _store()
    store.create_recovery_case(
        CEREMONY_ID,
        case_id="case-safe-signatures",
        authority_slot=0,
        kind="ROUTINE",
        intent_hash=INTENT_HASH,
        intent={"schemaVersion": 1, "slot": 0},
        execute_after=86_500,
        expires_at=173_000,
        prepared_by="0x" + "99" * 20,
        now=100,
    )
    action_id = "authority-approval"
    package_one = "0x" + "ab" * 32
    owner_signature = "0x" + "cd" * 64 + "1b"
    coadmin_signature = "0x" + "ef" * 64 + "1c"

    stored = store.add_recovery_evm_safe_signature(
        "case-safe-signatures",
        action_id=action_id,
        package_hash=package_one,
        safe_nonce=4,
        coadmin_slot=2,
        signer_slot=0,
        signer_role="OWNER",
        signer_address="0x" + "11" * 20,
        signature=owner_signature,
        message_hash="0x" + "12" * 32,
        now=101,
    )
    assert stored[0]["signerSlot"] == 0
    assert stored[0]["signature"] == owner_signature

    stored = store.add_recovery_evm_safe_signature(
        "case-safe-signatures",
        action_id=action_id,
        package_hash=package_one,
        safe_nonce=4,
        coadmin_slot=2,
        signer_slot=2,
        signer_role="COADMIN",
        signer_address="0x" + "22" * 20,
        signature=coadmin_signature,
        message_hash="0x" + "23" * 32,
        now=102,
    )
    assert [item["signerSlot"] for item in stored] == [0, 2]

    package_two = "0x" + "bc" * 32
    replacement = store.add_recovery_evm_safe_signature(
        "case-safe-signatures",
        action_id=action_id,
        package_hash=package_two,
        safe_nonce=5,
        coadmin_slot=1,
        signer_slot=1,
        signer_role="COADMIN",
        signer_address="0x" + "33" * 20,
        signature=owner_signature,
        message_hash="0x" + "34" * 32,
        now=103,
    )
    assert len(replacement) == 1
    assert replacement[0]["packageHash"] == package_two
    assert replacement[0]["safeNonce"] == 5
    assert replacement[0]["coadminSlot"] == 1
    assert replacement[0]["signerSlot"] == 1


def test_evm_submission_survives_restart_and_conflicts_fail_closed(
    tmp_path,
) -> None:
    database = tmp_path / "authority-v3.sqlite3"
    store = GenesisStore(str(database))
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    store.create_recovery_case(
        CEREMONY_ID,
        case_id="case-evm-submission",
        authority_slot=0,
        kind="ROUTINE",
        intent_hash=INTENT_HASH,
        intent={"schemaVersion": 1, "slot": 0},
        execute_after=86_500,
        expires_at=173_000,
        prepared_by="0x" + "99" * 20,
        now=100,
    )
    transaction_hash = "0x" + "ab" * 32
    submitted_by = "0x" + "12" * 20

    pending = store.add_recovery_evm_submission(
        "case-evm-submission",
        action_id="authority-approval",
        transaction_hash=transaction_hash,
        submitted_by=submitted_by,
        now=101,
    )
    assert pending == {
        "actionId": "authority-approval",
        "transactionHash": transaction_hash,
        "state": "PENDING",
        "submittedBy": submitted_by,
        "submittedAt": 101,
        "updatedAt": 101,
    }
    assert store.add_recovery_evm_submission(
        "case-evm-submission",
        action_id="authority-approval",
        transaction_hash=transaction_hash,
        submitted_by=submitted_by,
        now=102,
    ) == pending

    restarted = GenesisStore(str(database))
    assert restarted.recovery_case("case-evm-submission")[
        "evmSubmissions"
    ] == [pending]

    with pytest.raises(GenesisConflict, match="different transaction"):
        restarted.add_recovery_evm_submission(
            "case-evm-submission",
            action_id="authority-approval",
            transaction_hash="0x" + "cd" * 32,
            submitted_by=submitted_by,
            now=103,
        )
    with pytest.raises(GenesisConflict, match="already assigned"):
        restarted.add_recovery_evm_submission(
            "case-evm-submission",
            action_id="replacement-acceptance",
            transaction_hash=transaction_hash,
            submitted_by=submitted_by,
            now=103,
        )

    confirmed = restarted.confirm_recovery_evm_submission(
        "case-evm-submission",
        transaction_hash=transaction_hash,
        now=104,
    )
    assert confirmed is not None
    assert confirmed["state"] == "CONFIRMED"
    assert confirmed["updatedAt"] == 104
    assert restarted.recovery_evm_submissions(
        "case-evm-submission",
        pending_only=True,
    ) == []


def test_schema_eight_adds_resumable_evm_submissions_on_restart(
    tmp_path,
) -> None:
    database = tmp_path / "authority-v3-migration.sqlite3"
    store = GenesisStore(str(database))
    with store._connect() as connection:  # noqa: SLF001 - migration fixture
        connection.execute("DROP TABLE admin_recovery_evm_submissions")
        connection.execute("PRAGMA user_version = 8")

    migrated = GenesisStore(str(database))
    with migrated._connect() as connection:  # noqa: SLF001 - migration assertion
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        table = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='admin_recovery_evm_submissions'"
        ).fetchone()

    assert version == SCHEMA_VERSION == 13
    assert table is not None
