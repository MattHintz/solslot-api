from __future__ import annotations

from types import SimpleNamespace

import pytest
from eth_abi import encode as abi_encode
from fastapi import HTTPException
from starlette.requests import Request
from web3 import Web3

import solslot_api.zkpassport_relay as relay_module
from solslot_api.zkpassport_relay import (
    BlsRelayRequest,
    _decode_enrollment_calldata,
    _simulate_forwarded_inner_call,
    relay_bls,
)


FORWARDER = "0x" + "11" * 20
EMITTER = "0x" + "22" * 20
SIGNER = "0x" + "33" * 20


class _RevertingEth:
    def __init__(self) -> None:
        self.transaction = None

    def call(self, transaction):
        self.transaction = transaction
        raise RuntimeError("execution reverted: 0xa54999ed")


class _FakeWeb3:
    def __init__(self) -> None:
        self.eth = _RevertingEth()


def test_forwarded_inner_simulation_appends_original_signer_and_decodes_revert():
    w3 = _FakeWeb3()

    detail = _simulate_forwarded_inner_call(
        w3,
        forwarder_address=FORWARDER,
        emitter_address=EMITTER,
        signer_address=SIGNER,
        data=b"\x12\x34",
    )

    assert "ScopeMismatch" in detail
    assert w3.eth.transaction == {
        "from": FORWARDER,
        "to": EMITTER,
        "value": 0,
        "data": b"\x12\x34" + bytes.fromhex("33" * 20),
    }


def _calldata(binding_type: str, binding: tuple, proof: bytes = b"proof") -> bytes:
    signature = f"verifyAndEmit({binding_type},bytes)"
    return bytes(Web3.keccak(text=signature)[:4]) + abi_encode(
        [binding_type, "bytes"],
        [binding, proof],
    )


def test_decodes_only_canonical_v2_enrollment_binding():
    data = _calldata(
        "(bytes32,bytes32,uint64)",
        (bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), 1),
    )

    assert _decode_enrollment_calldata(data) == (
        "0x" + "11" * 32,
        "0x" + "22" * 32,
        1,
    )


def test_rejects_retired_caller_supplied_attestation_tuple():
    retired_type = (
        "(bytes32,bytes32,uint16,bytes32,bytes32,uint64,bytes32,bytes32,"
        "bytes32,uint64,bytes32,bytes32)"
    )
    data = _calldata(
        retired_type,
        (
            bytes.fromhex("11" * 32),
            bytes.fromhex("12" * 32),
            1,
            bytes.fromhex("13" * 32),
            bytes.fromhex("14" * 32),
            1_900_000_000,
            bytes.fromhex("15" * 32),
            bytes.fromhex("16" * 32),
            bytes.fromhex("22" * 32),
            1,
            bytes.fromhex("17" * 32),
            bytes.fromhex("18" * 32),
        ),
    )

    with pytest.raises(ValueError, match="selector"):
        _decode_enrollment_calldata(data)


@pytest.mark.parametrize(
    ("binding", "message"),
    [
        ((bytes(32), bytes.fromhex("22" * 32), 1), "vaultLauncherId"),
        ((bytes.fromhex("11" * 32), bytes(32), 1), "bridgeParentId"),
        ((bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), 0), "bridgeAmount"),
    ],
)
def test_rejects_empty_enrollment_binding_fields(binding, message):
    data = _calldata("(bytes32,bytes32,uint64)", binding)

    with pytest.raises(ValueError, match=message):
        _decode_enrollment_calldata(data)


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/zkpassport/relay/bls",
            "headers": [],
            "client": ("203.0.113.10", 443),
        }
    )


def _bls_request() -> BlsRelayRequest:
    data = _calldata(
        "(bytes32,bytes32,uint64)",
        (bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), 1),
    )
    return BlsRelayRequest(
        data="0x" + data.hex(),
        ownerAuth={
            "challengeId": "a" * 32,
            "signature": "0x" + "bb" * 96,
        },
    )


def _relay_settings() -> SimpleNamespace:
    return SimpleNamespace(
        zkpassport_emitter_address=EMITTER,
        zkpassport_bridge_policy_hash="0x" + "77" * 32,
        zkpassport_evm_rpc_url="https://rpc.invalid",
        zkpassport_evm_chain_id=11155111,
        zkpassport_relay_per_ip_per_minute=3,
        zkpassport_relay_per_owner_per_minute=2,
        zkpassport_relay_per_vault_per_hour=1,
        zkpassport_relay_global_gas_per_day=5_000_000,
        zkpassport_relay_circuit_failure_threshold=3,
        zkpassport_relay_circuit_cooldown_seconds=60,
    )


def test_bls_relay_rejects_an_evm_vault_session_before_owner_challenge(monkeypatch):
    monkeypatch.setattr(relay_module, "_load_settings", _relay_settings)
    monkeypatch.setattr(
        relay_module,
        "_require_relayer_account",
        lambda _settings: SimpleNamespace(address=SIGNER),
    )
    monkeypatch.setattr(
        relay_module,
        "verify_vault_session",
        lambda *_args: SimpleNamespace(auth_type="evm"),
    )
    monkeypatch.setattr(
        relay_module,
        "verify_owner_auth",
        lambda *_args, **_kwargs: pytest.fail("owner challenge must not be consumed"),
    )

    with pytest.raises(HTTPException) as exc_info:
        relay_bls(_bls_request(), _request())

    assert exc_info.value.status_code == 409
    assert "signed ForwardRequest" in str(exc_info.value.detail)


from tests.test_relay_durable_recovery import rig


def test_bls_relay_binds_exact_calldata_owner_and_bridge_coin(rig):
    response = rig.setup('bls')()
    attempt = rig.ledger.get_relay_attempt('0x'+'11'*32)
    assert rig.counts['auth'] == 1
    assert attempt['bridge_coin_id'] == rig.bridge
    assert attempt['owner_key'] == rig.session.owner_key
    assert attempt['inner_gas'] == 1_000_000
    assert attempt['tx_hash'] == response.tx_hash
    assert attempt['status'] == 'submitted'
    assert response.signer == rig.session.owner_key
