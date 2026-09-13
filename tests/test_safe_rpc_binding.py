"""Synthetic Safe encoding and approval regressions; no network or live keys."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_abi import decode as abi_decode, encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from fastapi import HTTPException

import solslot_api.admin_key_changes as changes
from solslot_api.genesis_store import GenesisStore

TX_TYPES = ["address", "uint256", "bytes", "uint8", "uint256", "uint256",
            "uint256", "address", "address", "uint256"]
TX_NAMES = ["to", "value", "data", "operation", "safeTxGas", "baseGas",
            "gasPrice", "gasToken", "refundReceiver", "nonce"]
ZERO = "0x" + "00" * 20


def safe_preimage(safe, transaction, *, chain_id=84532):
    # Independent ABI formulation from Safe v1.4.1 encodeTransactionData,
    # rather than the application's eth_account typed-data encoder.
    # https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol
    domain_type = bytes.fromhex("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218")
    tx_type = bytes.fromhex("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8")
    domain = keccak(abi_encode(["bytes32", "uint256", "address"], [domain_type, chain_id, safe]))
    values = [transaction[key] for key in TX_NAMES]
    data = values[2]
    values[2] = keccak(bytes.fromhex(data[2:]) if isinstance(data, str) else data)
    types = list(TX_TYPES)
    types[2] = "bytes32"
    struct = keccak(abi_encode(["bytes32", *types], [tx_type, *values]))
    return b"\x19\x01" + domain + struct


def standard_transaction(*, nonce=7):
    return dict(zip(TX_NAMES, ["0x" + "52" * 20, 0, "0x12345678", 0, 0, 0, 0, ZERO, ZERO, nonce], strict=True))


class SafeRpc:
    def __init__(self, *, tamper=None, tamper_hash=True, tamper_encoding=True):
        self.nonce = 7
        self.tamper = tamper
        self.tamper_hash = tamper_hash
        self.tamper_encoding = tamper_encoding
        self.nonce_reads = 0

    async def __call__(self, _settings, method, params):
        assert method == "eth_call"
        call = params[0]
        raw = bytes.fromhex(call["data"][2:])
        if raw == keccak(text="nonce()")[:4]:
            self.nonce_reads += 1
            return "0x" + abi_encode(["uint256"], [self.nonce]).hex()
        transaction = dict(zip(TX_NAMES, abi_decode(TX_TYPES, raw[4:]), strict=True))
        canonical = safe_preimage(call["to"], transaction)
        changed = dict(transaction)
        safe, chain = call["to"], 84532
        if self.tamper == "safe":
            safe = "0x" + "ab" * 20
        elif self.tamper == "chain":
            chain = 1
        elif self.tamper in {"to", "gasToken", "refundReceiver"}:
            changed[self.tamper] = "0x" + "ac" * 20
        elif self.tamper == "data":
            changed["data"] = b"\x12\x34\x56\x79"
        elif self.tamper:
            changed[self.tamper] += 1
        other = safe_preimage(safe, changed, chain_id=chain)
        if raw[:4] == keccak(text="getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)")[:4]:
            return "0x" + keccak(other if self.tamper_hash else canonical).hex()
        assert raw[:4] == keccak(text="encodeTransactionData(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)")[:4]
        return "0x" + abi_encode(["bytes"], [other if self.tamper_encoding else canonical]).hex()


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [None, 0, 7, 2**256 - 1])
async def test_honest_rpc_matches_local_action_and_approved_nonce(monkeypatch, override):
    rpc = SafeRpc()
    monkeypatch.setattr(changes, "_rpc", rpc)
    context = await changes._safe_transaction_context(
        object(), safe="0x" + "51" * 20, to="0x" + "52" * 20,
        data="0x12345678", nonce_override=override,
    )
    expected = safe_preimage(context["safe"], standard_transaction(nonce=7 if override is None else override))
    assert context["transactionData"] == "0x" + expected.hex()
    assert context["transactionHash"] == "0x" + keccak(expected).hex()
    assert rpc.nonce_reads == (1 if override is None else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["to", "data", "nonce", "safe", "chain", "value", "operation", "safeTxGas", "baseGas", "gasPrice", "gasToken", "refundReceiver"])
@pytest.mark.parametrize("changed_part", ["both", "hash", "encoding"])
async def test_rpc_substitution_is_rejected_before_context_return(monkeypatch, tamper, changed_part):
    monkeypatch.setattr(changes, "_rpc", SafeRpc(
        tamper=tamper, tamper_hash=changed_part != "encoding",
        tamper_encoding=changed_part != "hash",
    ))
    with pytest.raises(ValueError, match="Safe transaction"):
        await changes._safe_transaction_context(
            object(), safe="0x" + "51" * 20, to="0x" + "52" * 20,
            data="0x12345678", nonce_override=7,
        )


def package_fixture(monkeypatch, tmp_path, *, kind="ROUTINE"):
    keys = [Account.from_key("0x" + value * 32) for value in ("31", "32", "33")]
    intent = json.loads((Path(__file__).parent / "fixtures/admin_key_change_intent_v1.json").read_text())["intent"]
    intent.update(kind=kind, oldDailyEvmKey=keys[0].address)
    model = changes.AdminKeyChangeIntentV1.model_validate(intent)
    safes = intent["identitySafes"]
    evidence = {"recovery": {"address": "0x" + "71" * 20}, "safes": {
        "identities": [{"slot": i, "address": address} for i, address in enumerate(safes)],
        "coadmin": {"address": intent["coadminSafe"], "threshold": 1, "owners": safes[1:]},
        "root": {"address": intent["rootSafe"], "threshold": 2, "owners": [safes[0], intent["coadminSafe"]]},
    }}
    async def verified(_settings):
        return {}, evidence, evidence["recovery"]["address"]
    async def runtime(*_args):
        return None
    # Isolate this RPC-to-signature boundary; deployment/roster cryptographic
    # evidence is covered separately and is not established by these fixtures.
    monkeypatch.setattr(changes, "_verified_evidence_context", verified)
    monkeypatch.setattr(changes, "_validate_intent_bindings", lambda **_kwargs: None)
    monkeypatch.setattr(changes, "_verify_safe_runtime_code", runtime)
    monkeypatch.setattr(changes, "_current_administrators", lambda *_args: [(key.address, "unused") for key in keys])
    rpc = SafeRpc()
    monkeypatch.setattr(changes, "_rpc", rpc)
    store = GenesisStore(str(tmp_path / "safe-approvals.sqlite3"))
    ceremony = "0x" + "11" * 32
    store.create_draft(ceremony, {"network": "testnet11"}, now=100)
    store.create_recovery_case(
        ceremony, case_id="safe-binding", authority_slot=0, kind=kind,
        intent_hash=changes.hash_admin_key_change_intent(model), intent=intent,
        execute_after=86500, expires_at=2000000000, prepared_by=keys[0].address, now=100,
    )
    return SimpleNamespace(keys=keys, store=store, rpc=rpc, settings=object())


async def package(fixture, *, coadmin=1, action="authority-approval", approved_nonce=None):
    return await changes._build_evm_safe_action_package(
        case=fixture.store.recovery_case("safe-binding"),
        body=changes.EvmSafeActionPackageRequest(actionId=action, coadminSlot=coadmin),
        settings=fixture.settings, store=fixture.store, approved_safe_nonce=approved_nonce,
    )


@pytest.mark.asyncio
async def test_nested_package_rejects_consistent_provider_substitution(monkeypatch, tmp_path):
    fixture = package_fixture(monkeypatch, tmp_path)
    fixture.rpc.tamper = "data"
    with pytest.raises(ValueError, match="Safe transaction"):
        await package(fixture)
    assert fixture.store.recovery_evm_safe_signatures("safe-binding", action_id="authority-approval") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("coadmin,kind,action", [(1, "ROUTINE", "authority-approval"), (2, "RECOVERY_KIT", "authority-approval"), (None, "LOST", "peer-1-approval")])
async def test_valid_leaf_approvals_preserve_partial_ready_and_mined_packages(monkeypatch, tmp_path, coadmin, kind, action):
    fixture = package_fixture(monkeypatch, tmp_path, kind=kind)
    current = await package(fixture, coadmin=coadmin, action=action)
    original_hash = current["packageHash"]
    assert current["readyToBroadcast"] is False
    assert [x["slot"] for x in current["approvals"]] == ([1] if coadmin is None else [0, coadmin])
    for descriptor in list(current["approvals"]):
        signed = fixture.keys[descriptor["slot"]].sign_message(encode_typed_data(full_message=descriptor["typedData"]))
        current = await changes.submit_key_change_evm_safe_signature(
            "safe-binding", changes.EvmSafeActionSignatureSubmission(
                actionId=action, coadminSlot=coadmin, packageHash=original_hash,
                signature="0x" + signed.signature.hex(),
            ), fixture.settings, fixture.store,
        )
        assert current["packageHash"] == original_hash
    assert current["readyToBroadcast"] is True
    assert all(x["signed"] for x in current["approvals"])
    broadcast = current["broadcastTransaction"]
    assert broadcast["to"] == current["executionSafe"]
    raw = bytes.fromhex(broadcast["data"][2:])
    decoded = abi_decode([*TX_TYPES[:-1], "bytes"], raw[4:])
    tx = current["transaction"]
    assert list(decoded[:-1]) == [bytes.fromhex(tx[k][2:]) if k == "data" else tx[k].lower() if isinstance(tx[k], str) else tx[k] for k in TX_NAMES[:-1]]
    assert (len(decoded[-1]) == 65) if coadmin is None else (len(decoded[-1]) > 130)
    fixture.rpc.nonce = 8
    stale = await package(fixture, coadmin=coadmin, action=action)
    assert stale["packageHash"] != original_hash and stale["readyToBroadcast"] is False
    before_reads = fixture.rpc.nonce_reads
    mined = await package(fixture, coadmin=coadmin, action=action, approved_nonce=7)
    assert fixture.rpc.nonce_reads == before_reads
    assert mined["packageHash"] == original_hash
    assert mined["broadcastTransaction"] == broadcast


@pytest.mark.asyncio
async def test_signature_submission_rechecks_rpc_binding_before_storage(monkeypatch, tmp_path):
    fixture = package_fixture(monkeypatch, tmp_path)
    current = await package(fixture)
    descriptor = current["approvals"][0]
    signed = fixture.keys[0].sign_message(encode_typed_data(full_message=descriptor["typedData"]))
    body = changes.EvmSafeActionSignatureSubmission(
        actionId="authority-approval", coadminSlot=1, packageHash=current["packageHash"],
        signature="0x" + signed.signature.hex(),
    )
    fixture.rpc.tamper = "data"
    fixture.rpc.tamper_hash = False
    with pytest.raises(HTTPException) as error:
        await changes.submit_key_change_evm_safe_signature("safe-binding", body, fixture.settings, fixture.store)
    assert error.value.status_code == 409
    assert "Safe transaction data" in error.value.detail
    assert fixture.store.recovery_evm_safe_signatures("safe-binding", action_id="authority-approval") == []
    fixture.rpc.tamper = None
    retried = await changes.submit_key_change_evm_safe_signature("safe-binding", body, fixture.settings, fixture.store)
    assert retried["approvals"][0]["signed"] is True
    assert retried["readyToBroadcast"] is False
    assert retried["packageHash"] == current["packageHash"]


@pytest.mark.asyncio
@pytest.mark.parametrize("malformed", ["empty", "truncated", "trailing", "offset", "prefix"])
async def test_malformed_rpc_encoding_fails_closed(monkeypatch, malformed):
    original = SafeRpc()
    async def rpc(settings, method, params):
        result = await original(settings, method, params)
        if len(result) == 66:
            return result
        if malformed == "empty":
            return "0x"
        if malformed == "truncated":
            return result[:-2]
        if malformed == "trailing":
            return result + "00" * 32
        if malformed == "offset":
            return "0x" + "ff" * 32 + result[66:]
        return "zz" + result[2:]
    monkeypatch.setattr(changes, "_rpc", rpc)
    with pytest.raises(ValueError, match="Safe transaction data"):
        await changes._safe_transaction_context(
            object(), safe="0x" + "51" * 20, to="0x" + "52" * 20,
            data="0x12345678", nonce_override=7,
        )
