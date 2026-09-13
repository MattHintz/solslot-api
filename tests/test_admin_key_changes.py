from __future__ import annotations

import json
from pathlib import Path

import pytest
from chia_rs import AugSchemeMPL
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

import solslot_api.admin_key_changes as admin_key_changes
from solslot_api.admin_key_changes import (
    AdminKeyChangeIntentV1,
    EVENT_TOPICS,
    _contract_owner_signature,
    _encode_safe_signature_entries,
    _normalize_safe_eoa_signature,
    _prepared_event_fields,
    _safe_message_typed_data,
    _safe_transaction_typed_data,
    _safe_typed_data_digest,
    _verify_recovery_guardian_transaction,
    hash_admin_key_change_intent,
    lost_key_authorization_typed_data,
    prepare_key_change_calldata,
    prepare_lost_key_with_signature_calldata,
    recovery_guardian_action_typed_data,
    recovery_guardian_action_with_signature_calldata,
    recovery_intent_bls_digest,
    verify_lost_guardian_authorization,
    verify_lost_recovery_bls_signature,
    verify_recovery_guardian_action_authorization,
)


FIXTURE = (
    Path(__file__).parent / "fixtures" / "admin_key_change_intent_v1.json"
)


def test_python_matches_authority_v3_solidity_intent_fixture() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    intent = AdminKeyChangeIntentV1.model_validate(fixture["intent"])
    expected = fixture["expected"]
    intent_hash = hash_admin_key_change_intent(intent)
    calldata = prepare_key_change_calldata(intent)

    assert intent_hash == expected["intentHash"]
    assert calldata[:10] == expected["prepareRoutineSelector"]
    assert (len(calldata) - 2) // 2 == expected["prepareRoutineCalldataBytes"]
    assert (
        "0x" + recovery_intent_bls_digest(intent_hash).hex()
        == expected["recoveryBlsDigest"]
    )


def test_nested_safe_signatures_preserve_owner_plus_one_topology() -> None:
    owner = Account.from_key("0x" + "31" * 32)
    coadmin = Account.from_key("0x" + "32" * 32)
    identity_zero = "0x" + "41" * 20
    identity_two = "0x" + "43" * 20
    coadmin_safe = "0x" + "44" * 20
    transaction_data = "0x" + "aa" * 96

    owner_typed = _safe_message_typed_data(identity_zero, transaction_data)
    coadmin_typed = _safe_message_typed_data(identity_two, transaction_data)
    owner_signature = _normalize_safe_eoa_signature(
        "0x"
        + owner.sign_message(
            encode_typed_data(full_message=owner_typed)
        ).signature.hex()
    )
    coadmin_signature = _normalize_safe_eoa_signature(
        "0x"
        + coadmin.sign_message(
            encode_typed_data(full_message=coadmin_typed)
        ).signature.hex()
    )
    nested_coadmin = _contract_owner_signature(
        identity_two,
        coadmin_signature,
    )
    root_signatures = _encode_safe_signature_entries(
        [
            (identity_zero, owner_signature, True),
            (coadmin_safe, nested_coadmin, True),
        ]
    )

    assert _safe_typed_data_digest(owner_typed) == (
        "0x"
        + owner.sign_message(
            encode_typed_data(full_message=owner_typed)
        ).message_hash.hex()
    )
    assert int.from_bytes(root_signatures[:32], "big") == int(
        identity_zero,
        16,
    )
    assert root_signatures[64] == 0
    assert int.from_bytes(root_signatures[65:97], "big") == int(
        coadmin_safe,
        16,
    )
    assert root_signatures[129] == 0
    assert len(root_signatures) > 2 * 65


def test_direct_identity_safe_transaction_uses_the_standard_safe_tx_digest() -> None:
    safe = "0x" + "51" * 20
    transaction = {
        "to": "0x" + "52" * 20,
        "value": 0,
        "data": "0x12345678",
        "operation": 0,
        "safeTxGas": 0,
        "baseGas": 0,
        "gasPrice": 0,
        "gasToken": "0x" + "00" * 20,
        "refundReceiver": "0x" + "00" * 20,
        "nonce": 7,
    }
    typed_data = _safe_transaction_typed_data(safe, transaction)
    signer = Account.from_key("0x" + "33" * 32)
    signed = signer.sign_message(
        encode_typed_data(full_message=typed_data)
    )

    assert typed_data["primaryType"] == "SafeTx"
    assert typed_data["message"]["nonce"] == 7
    assert _safe_typed_data_digest(typed_data) == "0x" + signed.message_hash.hex()


@pytest.mark.asyncio
async def test_safe_transaction_reconstructs_the_approved_nonce_after_mining(
    monkeypatch,
) -> None:
    from tests.test_safe_rpc_binding import safe_preimage, standard_transaction
    expected_data = safe_preimage("0x" + "51" * 20, standard_transaction(nonce=7))
    expected_hash = "0x" + keccak(expected_data).hex()
    calls: list[dict] = []

    async def reject_live_nonce(*_args, **_kwargs):
        raise AssertionError("approved package reconstruction read the live nonce")

    async def rpc(_settings, method: str, params: list):
        assert method == "eth_call"
        call = params[0]
        calls.append(call)
        if len(calls) == 1:
            return expected_hash
        return "0x" + abi_encode(
            ["bytes"],
            [expected_data],
        ).hex()

    monkeypatch.setattr(
        admin_key_changes,
        "_call_uint",
        reject_live_nonce,
    )
    monkeypatch.setattr(admin_key_changes, "_rpc", rpc)

    context = await admin_key_changes._safe_transaction_context(
        object(),
        safe="0x" + "51" * 20,
        to="0x" + "52" * 20,
        data="0x12345678",
        nonce_override=7,
    )

    assert context["nonce"] == 7
    assert context["transaction"]["nonce"] == 7
    assert context["transactionHash"] == expected_hash
    assert context["transactionData"] == "0x" + expected_data.hex()
    assert len(calls) == 2
    for call in calls:
        calldata = bytes.fromhex(call["data"][2:])
        assert int.from_bytes(calldata[4 + 9 * 32 : 4 + 10 * 32], "big") == 7


def test_lost_key_bls_proof_is_bound_to_the_exact_intent() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw = dict(fixture["intent"])
    raw["kind"] = "LOST"
    intent = AdminKeyChangeIntentV1.model_validate(raw)
    secret_key = AugSchemeMPL.key_gen(b"authority v3 recovery proof seed")
    digest = recovery_intent_bls_digest(
        hash_admin_key_change_intent(intent)
    )
    signature = AugSchemeMPL.sign(secret_key, digest)

    verify_lost_recovery_bls_signature(
        intent=intent,
        recovery_bls_pubkey="0x" + bytes(secret_key.get_g1()).hex(),
        signature="0x" + bytes(signature).hex(),
    )

    altered = intent.model_copy(update={"nonce": intent.nonce + 1})
    try:
        verify_lost_recovery_bls_signature(
            intent=altered,
            recovery_bls_pubkey="0x" + bytes(secret_key.get_g1()).hex(),
            signature="0x" + bytes(signature).hex(),
        )
    except ValueError as exc:
        assert "invalid" in str(exc)
    else:
        raise AssertionError("altered recovery intent accepted the old signature")


def test_lost_key_guardian_can_authorize_an_exact_gas_paying_relay() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    guardian = Account.from_key("0x" + "73" * 32)
    raw = {
        **fixture["intent"],
        "kind": "LOST",
        "oldRecoveryGuardian": guardian.address,
        "newRecoveryGuardian": guardian.address,
    }
    intent = AdminKeyChangeIntentV1.model_validate(raw)
    coordinator = "0x" + "84" * 20
    intent_hash = hash_admin_key_change_intent(intent)
    typed_data = lost_key_authorization_typed_data(
        intent_hash,
        coordinator,
    )
    signature = "0x" + guardian.sign_message(
        encode_typed_data(full_message=typed_data)
    ).signature.hex()

    assert typed_data == {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "SolslotLostKeyPrepare": [
                {"name": "intentHash", "type": "bytes32"},
            ],
        },
        "primaryType": "SolslotLostKeyPrepare",
        "domain": {
            "name": "Solslot Admin Recovery",
            "version": "1",
            "chainId": 84532,
            "verifyingContract": coordinator,
        },
        "message": {"intentHash": intent_hash},
    }
    assert (
        verify_lost_guardian_authorization(
            intent=intent,
            coordinator=coordinator,
            guardian_signature=signature,
        )
        == guardian.address
    )

    calldata = prepare_lost_key_with_signature_calldata(
        intent,
        signature,
    )
    expected_selector = keccak(
        text=(
            "prepareLostKeyWithSignature("
            "(uint8,uint8,address,address,bytes,bytes,address,address,"
            "bytes,bytes,bytes32[3],address[3],bytes32,address,address,"
            "string,uint256,bytes32,uint256,uint64,uint64),bytes)"
        )
    )[:4]
    assert calldata[:10] == "0x" + expected_selector.hex()


def test_lost_key_guardian_authorization_rejects_context_or_intent_drift() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    guardian = Account.from_key("0x" + "74" * 32)
    intent = AdminKeyChangeIntentV1.model_validate(
        {
            **fixture["intent"],
            "kind": "LOST",
            "oldRecoveryGuardian": guardian.address,
            "newRecoveryGuardian": guardian.address,
        }
    )
    coordinator = "0x" + "85" * 20
    signature = "0x" + guardian.sign_message(
        encode_typed_data(
            full_message=lost_key_authorization_typed_data(
                hash_admin_key_change_intent(intent),
                coordinator,
            )
        )
    ).signature.hex()

    for changed_intent, changed_coordinator in (
        (intent.model_copy(update={"nonce": intent.nonce + 1}), coordinator),
        (intent, "0x" + "86" * 20),
    ):
        try:
            verify_lost_guardian_authorization(
                intent=changed_intent,
                coordinator=changed_coordinator,
                guardian_signature=signature,
            )
        except ValueError as exc:
            assert "guardian" in str(exc)
        else:
            raise AssertionError(
                "guardian authorization survived context or intent drift"
            )


def test_recovery_guardian_actions_are_exact_and_relayer_safe() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    old_guardian = Account.from_key("0x" + "75" * 32)
    new_guardian = Account.from_key("0x" + "76" * 32)
    new_recovery_bls = "0x" + bytes(
        AugSchemeMPL.key_gen(
            b"replacement recovery kit one seed material"
        ).get_g1()
    ).hex()
    intent = AdminKeyChangeIntentV1.model_validate(
        {
            **fixture["intent"],
            "kind": "RECOVERY_KIT",
            "newDailyEvmKey": fixture["intent"]["oldDailyEvmKey"],
            "newDailyChiaKey": fixture["intent"]["oldDailyChiaKey"],
            "oldRecoveryGuardian": old_guardian.address,
            "newRecoveryGuardian": new_guardian.address,
            "newRecoveryBlsKey": new_recovery_bls,
        }
    )
    coordinator = "0x" + "87" * 20
    intent_hash = hash_admin_key_change_intent(intent)

    for action, guardian, primary_type, function_name in (
        (
            "ACCEPT",
            new_guardian,
            "SolslotRecoveryGuardianAccept",
            "acceptRecoveryGuardianWithSignature",
        ),
        (
            "VETO",
            old_guardian,
            "SolslotRecoveryGuardianVeto",
            "vetoByOldRecoveryGuardianWithSignature",
        ),
    ):
        typed_data = recovery_guardian_action_typed_data(
            intent_hash,
            coordinator,
            action,
        )
        assert typed_data["primaryType"] == primary_type
        assert typed_data["domain"] == {
            "name": "Solslot Admin Recovery",
            "version": "1",
            "chainId": 84532,
            "verifyingContract": coordinator,
        }
        assert typed_data["message"] == {"intentHash": intent_hash}
        signature = "0x" + guardian.sign_message(
            encode_typed_data(full_message=typed_data)
        ).signature.hex()
        assert (
            verify_recovery_guardian_action_authorization(
                intent=intent,
                coordinator=coordinator,
                action=action,
                guardian_signature=signature,
            )
            == guardian.address
        )
        calldata = recovery_guardian_action_with_signature_calldata(
            intent_hash,
            action,
            signature,
        )
        assert calldata[:10] == (
            "0x"
            + keccak(
                text=f"{function_name}(bytes32,bytes)"
            )[:4].hex()
        )


def test_recovery_guardian_action_rejects_wrong_guardian_or_context() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    old_guardian = Account.from_key("0x" + "77" * 32)
    new_guardian = Account.from_key("0x" + "78" * 32)
    new_recovery_bls = "0x" + bytes(
        AugSchemeMPL.key_gen(
            b"replacement recovery kit two seed material"
        ).get_g1()
    ).hex()
    intent = AdminKeyChangeIntentV1.model_validate(
        {
            **fixture["intent"],
            "kind": "RECOVERY_KIT",
            "newDailyEvmKey": fixture["intent"]["oldDailyEvmKey"],
            "newDailyChiaKey": fixture["intent"]["oldDailyChiaKey"],
            "oldRecoveryGuardian": old_guardian.address,
            "newRecoveryGuardian": new_guardian.address,
            "newRecoveryBlsKey": new_recovery_bls,
        }
    )
    coordinator = "0x" + "88" * 20
    signature = "0x" + new_guardian.sign_message(
        encode_typed_data(
            full_message=recovery_guardian_action_typed_data(
                hash_admin_key_change_intent(intent),
                coordinator,
                "ACCEPT",
            )
        )
    ).signature.hex()

    for action, changed_coordinator in (
        ("VETO", coordinator),
        ("ACCEPT", "0x" + "89" * 20),
    ):
        try:
            verify_recovery_guardian_action_authorization(
                intent=intent,
                coordinator=changed_coordinator,
                action=action,
                guardian_signature=signature,
            )
        except ValueError as exc:
            assert "guardian" in str(exc)
        else:
            raise AssertionError(
                "offline guardian signature survived action or context drift"
            )


def test_confirmed_recovery_guardian_relay_rederives_public_authority() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    old_guardian = Account.from_key("0x" + "79" * 32)
    new_guardian = Account.from_key("0x" + "7a" * 32)
    new_recovery_bls = "0x" + bytes(
        AugSchemeMPL.key_gen(
            b"replacement recovery relay fixture seed"
        ).get_g1()
    ).hex()
    intent = AdminKeyChangeIntentV1.model_validate(
        {
            **fixture["intent"],
            "kind": "RECOVERY_KIT",
            "newDailyEvmKey": fixture["intent"]["oldDailyEvmKey"],
            "newDailyChiaKey": fixture["intent"]["oldDailyChiaKey"],
            "oldRecoveryGuardian": old_guardian.address,
            "newRecoveryGuardian": new_guardian.address,
            "newRecoveryBlsKey": new_recovery_bls,
        }
    )
    coordinator = "0x" + "8a" * 20
    intent_hash = hash_admin_key_change_intent(intent)
    signature = "0x" + new_guardian.sign_message(
        encode_typed_data(
            full_message=recovery_guardian_action_typed_data(
                intent_hash,
                coordinator,
                "ACCEPT",
            )
        )
    ).signature.hex()
    relayer = Account.from_key("0x" + "7b" * 32)
    signer, gas_payer, mode = _verify_recovery_guardian_transaction(
        transaction={
            "from": relayer.address,
            "to": coordinator,
            "value": "0x0",
            "input": recovery_guardian_action_with_signature_calldata(
                intent_hash,
                "ACCEPT",
                signature,
            ),
        },
        intent=intent,
        coordinator=coordinator,
        action="ACCEPT",
    )
    assert signer == new_guardian.address
    assert gas_payer == relayer.address
    assert mode == "OFFLINE_GUARDIAN_RELAY"

    try:
        _verify_recovery_guardian_transaction(
            transaction={
                "from": relayer.address,
                "to": "0x" + "8b" * 20,
                "value": "0x0",
                "input": recovery_guardian_action_with_signature_calldata(
                    intent_hash,
                    "ACCEPT",
                    signature,
                ),
            },
            intent=intent,
            coordinator=coordinator,
            action="ACCEPT",
        )
    except ValueError as exc:
        assert "destination" in str(exc)
    else:
        raise AssertionError("guardian relay accepted an altered destination")


def test_prepared_event_fields_are_decoded_from_contract_evidence() -> None:
    old_key = "0x" + "11" * 20
    new_key = "0x" + "22" * 20
    event = {
        "topics": [
            EVENT_TOPICS["prepared"],
            "0x" + "33" * 32,
            "0x" + (1).to_bytes(32, "big").hex(),
        ],
        "data": "0x"
        + abi_encode(
            ["uint8", "address", "address", "uint64"],
            [2, old_key, new_key, 604_900],
        ).hex(),
    }

    assert _prepared_event_fields(event) == (
        1,
        2,
        old_key,
        new_key,
        604_900,
    )


def test_prepared_event_rejects_missing_indexed_slot() -> None:
    try:
        _prepared_event_fields(
            {
                "topics": [
                    EVENT_TOPICS["prepared"],
                    "0x" + "33" * 32,
                ],
                "data": "0x",
            }
        )
    except ValueError as exc:
        assert "topics" in str(exc)
    else:
        raise AssertionError("malformed prepared event was accepted")
