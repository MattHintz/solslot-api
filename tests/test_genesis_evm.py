from __future__ import annotations

import hashlib
import json

import pytest
from web3 import Web3 as RealWeb3

from solslot_api import genesis_evm
from solslot_api.config import Settings
from solslot_api.genesis_evm import (
    GenesisEvmEvidenceError,
    verify_genesis_evm_deployment,
)


def _canonical_hash(payload: dict) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _fixture(tmp_path):
    addresses = {
        "forwarder": "0x" + "11" * 20,
        "verifierAdapter": "0x" + "22" * 20,
        "attestationEmitter": "0x" + "33" * 20,
    }
    transactions = {
        name: {
            "hash": "0x" + bytes([index]).hex() * 32,
            "blockNumber": 100 + index,
        }
        for index, name in enumerate(addresses, start=1)
    }
    code = {
        addresses["forwarder"]: b"forwarder-runtime",
        addresses["verifierAdapter"]: b"adapter-runtime",
        addresses["attestationEmitter"]: b"emitter-runtime",
        "0x" + "44" * 20: b"root-runtime",
    }
    deployment = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "credentialPolicyVersion": 2,
        "network": "ethSepolia",
        "chainId": 11155111,
        "confirmations": 12,
        "createdAt": "2026-07-16T00:00:00.000Z",
        "sourceShas": {"evm": "2" * 40, "protocol": "1" * 40},
        "deployer": "0x" + "55" * 20,
        "forwarderAddress": addresses["forwarder"],
        "verifierAdapterAddress": addresses["verifierAdapter"],
        "attestationEmitterAddress": addresses["attestationEmitter"],
        "trustedDirectRelayerAddress": "0x" + "66" * 20,
        "bridgePolicyHash": "0x" + "77" * 32,
        "zkPassportRootVerifierAddress": "0x" + "44" * 20,
        "zkPassportDomain": "staging.solslot.com",
        "zkPassportDevMode": True,
        "deploymentTransactions": transactions,
        "runtimeCodeHashes": {
            "forwarder": RealWeb3.keccak(code[addresses["forwarder"]]).hex(),
            "verifierAdapter": RealWeb3.keccak(code[addresses["verifierAdapter"]]).hex(),
            "attestationEmitter": RealWeb3.keccak(
                code[addresses["attestationEmitter"]]
            ).hex(),
            "zkPassportRootVerifier": RealWeb3.keccak(code["0x" + "44" * 20]).hex(),
        },
    }
    deployment["artifactHash"] = _canonical_hash(deployment)
    path = tmp_path / "evm-deployment.json"
    path.write_text(json.dumps(deployment), encoding="ascii")
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        genesis_evm_deployment_path=str(path),
        zkpassport_evm_rpc_url="https://rpc.invalid",
        cors_origins="",
    )
    record = {
        "draft": {
            "sourceShas": {
                "protocol": "1" * 40,
                "evm": "2" * 40,
                "omnichain": "3" * 40,
                "api": "4" * 40,
                "legacyBackend": "5" * 40,
                "keyOfSolomon": "6" * 40,
                "samuel": "7" * 40,
                "customerWeb": "8" * 40,
                "adminPortal": "9" * 40,
            }
        }
    }
    plan = {
        "evmAddresses": addresses,
        "puzzleHashes": {"bridgePolicy": "0x" + "77" * 32},
    }
    return settings, record, plan, deployment, code


def _install_fake_web3(monkeypatch, deployment, code, *, peak=120, adapter_values=None):
    receipts = {
        item["hash"].lower(): {
            "status": 1,
            "blockNumber": item["blockNumber"],
            "contractAddress": deployment[
                {
                    "forwarder": "forwarderAddress",
                    "verifierAdapter": "verifierAdapterAddress",
                    "attestationEmitter": "attestationEmitterAddress",
                }[name]
            ],
        }
        for name, item in deployment["deploymentTransactions"].items()
    }

    class FakeEth:
        chain_id = 11155111
        block_number = peak

        @staticmethod
        def get_transaction_receipt(transaction_hash):
            return receipts[str(transaction_hash).lower()]

        @staticmethod
        def get_code(address):
            assert RealWeb3.is_checksum_address(address)
            return code[str(address).lower()]

        @staticmethod
        def contract(**_kwargs):
            from types import SimpleNamespace
            class Functions:
                def __getattr__(self, name):
                    return lambda: SimpleNamespace(call=lambda: adapter_values[name])
            return SimpleNamespace(functions=Functions())

    class FakeWeb3:
        HTTPProvider = staticmethod(lambda *_args, **_kwargs: object())
        keccak = staticmethod(RealWeb3.keccak)
        to_checksum_address = staticmethod(RealWeb3.to_checksum_address)

        def __init__(self, _provider):
            self.eth = FakeEth()

        @staticmethod
        def is_connected():
            return True

    monkeypatch.setattr(genesis_evm, "Web3", FakeWeb3)


def test_live_evm_deployment_verification_accepts_immutable_confirmed_evidence(
    tmp_path, monkeypatch
) -> None:
    settings, record, plan, deployment, code = _fixture(tmp_path)
    _install_fake_web3(monkeypatch, deployment, code)

    result = verify_genesis_evm_deployment(settings, record, plan)

    assert result["manifestArtifactHash"] == deployment["artifactHash"]
    assert result["checkedAtBlock"] == 120
    assert set(result["contracts"]) == {
        "forwarder",
        "verifierAdapter",
        "attestationEmitter",
    }
    assert min(item["confirmations"] for item in result["contracts"].values()) >= 12


def test_live_evm_deployment_verification_rejects_insufficient_confirmations(
    tmp_path, monkeypatch
) -> None:
    settings, record, plan, deployment, code = _fixture(tmp_path)
    _install_fake_web3(monkeypatch, deployment, code, peak=111)

    with pytest.raises(GenesisEvmEvidenceError, match="12 are required"):
        verify_genesis_evm_deployment(settings, record, plan)


def test_live_evm_deployment_verification_rejects_source_or_manifest_drift(
    tmp_path, monkeypatch
) -> None:
    settings, record, plan, deployment, code = _fixture(tmp_path)
    _install_fake_web3(monkeypatch, deployment, code)

    record["draft"]["sourceShas"]["evm"] = "f" * 40
    with pytest.raises(GenesisEvmEvidenceError, match="source SHA"):
        verify_genesis_evm_deployment(settings, record, plan)

    record["draft"]["sourceShas"]["evm"] = "2" * 40
    deployment["forwarderAddress"] = "0x" + "99" * 20
    path = settings.genesis_evm_deployment_path
    with open(path, "w", encoding="ascii") as stream:
        json.dump(deployment, stream)
    with pytest.raises(GenesisEvmEvidenceError, match="artifactHash"):
        verify_genesis_evm_deployment(settings, record, plan)


@pytest.mark.parametrize("drift", [None, "domain", "devMode", "ELIGIBILITY_POLICY_ID", "SANCTIONS_STRICT", "config", "manifest"])
def test_fresh_eligibility_genesis_checks_live_policy(tmp_path, monkeypatch, drift):
    from solslot_puzzles.eligibility_policy import ELIGIBILITY_POLICY
    settings, record, plan, deployment, code = _fixture(tmp_path)
    settings.zkpassport_eligibility_policy = "age-sanctions-v1"
    plan["identityPolicy"] = ELIGIBILITY_POLICY
    deployment.update(identityPolicy=ELIGIBILITY_POLICY, zkPassportDomain="solslot.com", zkPassportDevMode=False)
    values = {
        "domain": "solslot.com", "devMode": False, "SANCTIONS_STRICT": False,
        "ELIGIBILITY_POLICY_ID": bytes(RealWeb3.keccak(text="solslot:age18:sanctions:all:standard:real:solslot.com:v1")),
    }
    if drift == "config":
        settings.zkpassport_eligibility_policy = "age-only"
    elif drift == "manifest":
        deployment.pop("identityPolicy")
    elif drift is not None:
        values[drift] = {"domain": "staging.solslot.com", "devMode": True,
                         "SANCTIONS_STRICT": True, "ELIGIBILITY_POLICY_ID": bytes(32)}[drift]
    deployment["artifactHash"] = _canonical_hash({k:v for k,v in deployment.items() if k != "artifactHash"})
    with open(settings.genesis_evm_deployment_path, "w", encoding="ascii") as stream:
        json.dump(deployment, stream)
    _install_fake_web3(monkeypatch, deployment, code, adapter_values=values)
    if drift:
        with pytest.raises(GenesisEvmEvidenceError, match="policy"):
            verify_genesis_evm_deployment(settings, record, plan)
    else:
        assert verify_genesis_evm_deployment(settings, record, plan)["manifestArtifactHash"] == deployment["artifactHash"]
