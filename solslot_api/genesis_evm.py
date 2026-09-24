"""Live Sepolia verification for disposable testnet genesis deployments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from web3 import Web3

from .config import Settings


EVM_CONTRACTS = ("forwarder", "verifierAdapter", "attestationEmitter")
ADDRESS_FIELDS = {
    "forwarder": "forwarderAddress",
    "verifierAdapter": "verifierAdapterAddress",
    "attestationEmitter": "attestationEmitterAddress",
}


class GenesisEvmEvidenceError(ValueError):
    """The deployment manifest or its live Sepolia state is invalid."""


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _hex(value: object, size: int, field: str) -> str:
    normalized = str(value).lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise GenesisEvmEvidenceError(f"{field} is not valid hex") from exc
    if len(raw) != size or raw == b"\x00" * size:
        raise GenesisEvmEvidenceError(f"{field} must be a nonzero {size}-byte value")
    return normalized


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GenesisEvmEvidenceError(f"{field} must be an object")
    return value


def _receipt_value(receipt: object, key: str) -> object:
    if isinstance(receipt, Mapping):
        return receipt.get(key)
    return getattr(receipt, key, None)


def verify_genesis_evm_deployment(
    settings: Settings,
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the immutable deployment manifest against live Sepolia state."""

    if 'enrollmentActivation' in plan or plan.get('evmChainId', 11155111) != 11155111:
        from .genesis_permit_evm import verify_permit_deployment
        return verify_permit_deployment(settings, record, plan)
    path = Path(settings.genesis_evm_deployment_path)
    if not path.is_file():
        raise GenesisEvmEvidenceError("genesis EVM deployment evidence is missing")
    try:
        deployment = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenesisEvmEvidenceError("genesis EVM deployment evidence is invalid") from exc
    if not isinstance(deployment, dict):
        raise GenesisEvmEvidenceError("genesis EVM deployment evidence must be an object")

    supplied_hash = _hex(deployment.get("artifactHash"), 32, "deployment artifactHash")
    unsigned = {key: value for key, value in deployment.items() if key != "artifactHash"}
    if supplied_hash != _canonical_hash(unsigned):
        raise GenesisEvmEvidenceError("deployment artifactHash is not canonical")
    from solslot_puzzles.eligibility_policy import validate_identity_policy
    identity_policy = validate_identity_policy(plan.get("identityPolicy"), evm_chain_id=plan.get("evmChainId", 11155111))
    if (deployment.get("identityPolicy") != identity_policy
            or (identity_policy is not None and (
                settings.zkpassport_eligibility_policy != "age-sanctions-v1"
                or deployment.get("zkPassportDomain") != "solslot.com"
                or deployment.get("zkPassportDevMode") is not False))):
        raise GenesisEvmEvidenceError("identity deployment policy differs from the signed plan")
    if (
        deployment.get("schemaVersion") != 2
        or deployment.get("protocolVersion") != "solslot-v2"
        or deployment.get("network") != "ethSepolia"
        or deployment.get("chainId") != 11155111
    ):
        raise GenesisEvmEvidenceError("deployment is not Solslot V2 on Sepolia")

    draft = _mapping(record.get("draft"), "ceremony draft")
    source_shas = _mapping(deployment.get("sourceShas"), "deployment sourceShas")
    expected_sources = _mapping(draft.get("sourceShas"), "ceremony sourceShas")
    for name in ("evm", "protocol"):
        if source_shas.get(name) != expected_sources.get(name):
            raise GenesisEvmEvidenceError(
                f"deployment {name} source SHA does not match the ceremony"
            )

    plan_addresses = _mapping(plan.get("evmAddresses"), "plan evmAddresses")
    addresses: dict[str, str] = {}
    for name, field in ADDRESS_FIELDS.items():
        address = _hex(deployment.get(field), 20, f"deployment {name} address")
        if address != str(plan_addresses.get(name, "")).lower():
            raise GenesisEvmEvidenceError(
                f"deployment {name} address does not match the signed plan"
            )
        addresses[name] = address

    bridge_policy_hash = _hex(
        deployment.get("bridgePolicyHash"), 32, "deployment bridge policy"
    )
    puzzle_hashes = _mapping(plan.get("puzzleHashes"), "plan puzzleHashes")
    if bridge_policy_hash != str(puzzle_hashes.get("bridgePolicy", "")).lower():
        raise GenesisEvmEvidenceError(
            "deployment bridge policy does not match the signed plan"
        )

    transactions = _mapping(
        deployment.get("deploymentTransactions"), "deployment transactions"
    )
    code_hashes = _mapping(deployment.get("runtimeCodeHashes"), "runtime code hashes")
    if set(transactions) != set(EVM_CONTRACTS):
        raise GenesisEvmEvidenceError("deployment transactions are incomplete")
    for name in (*EVM_CONTRACTS, "zkPassportRootVerifier"):
        _hex(code_hashes.get(name), 32, f"{name} runtime bytecode hash")

    web3 = Web3(Web3.HTTPProvider(settings.zkpassport_evm_rpc_url, request_kwargs={"timeout": 15}))
    try:
        if not web3.is_connected():
            raise GenesisEvmEvidenceError("Sepolia RPC is unavailable")
        if int(web3.eth.chain_id) != 11155111:
            raise GenesisEvmEvidenceError("configured EVM RPC is not Sepolia")
        peak = int(web3.eth.block_number)
    except GenesisEvmEvidenceError:
        raise
    except Exception as exc:
        raise GenesisEvmEvidenceError("could not query live Sepolia state") from exc

    contracts: dict[str, dict[str, Any]] = {}
    for name in EVM_CONTRACTS:
        transaction = _mapping(transactions.get(name), f"{name} deployment transaction")
        transaction_hash = _hex(transaction.get("hash"), 32, f"{name} transaction hash")
        try:
            receipt = web3.eth.get_transaction_receipt(transaction_hash)
            status = int(_receipt_value(receipt, "status") or 0)
            block_number = int(_receipt_value(receipt, "blockNumber") or 0)
            contract_address = _hex(
                _receipt_value(receipt, "contractAddress"),
                20,
                f"{name} receipt contract address",
            )
            code = bytes(
                web3.eth.get_code(Web3.to_checksum_address(addresses[name]))
            )
        except GenesisEvmEvidenceError:
            raise
        except Exception as exc:
            raise GenesisEvmEvidenceError(
                f"could not verify {name} deployment on Sepolia"
            ) from exc
        if status != 1 or contract_address != addresses[name]:
            raise GenesisEvmEvidenceError(f"{name} deployment receipt is invalid")
        if block_number != int(transaction.get("blockNumber") or 0):
            raise GenesisEvmEvidenceError(
                f"{name} deployment block does not match immutable evidence"
            )
        confirmations = peak - block_number + 1
        if confirmations < settings.genesis_sepolia_confirmations:
            raise GenesisEvmEvidenceError(
                f"{name} has {confirmations} Sepolia confirmations; 12 are required"
            )
        if not code:
            raise GenesisEvmEvidenceError(f"{name} has no runtime bytecode")
        live_code_hash = "0x" + bytes(Web3.keccak(code)).hex()
        expected_code_hash = _hex(
            code_hashes[name], 32, f"{name} runtime bytecode hash"
        )
        if live_code_hash != expected_code_hash:
            raise GenesisEvmEvidenceError(f"{name} runtime bytecode hash changed")
        contracts[name] = {
            "address": addresses[name],
            "transactionHash": transaction_hash,
            "blockNumber": block_number,
            "confirmations": confirmations,
            "bytecodeHash": live_code_hash,
        }

    root_address = _hex(
        deployment.get("zkPassportRootVerifierAddress"),
        20,
        "zkPassport root verifier address",
    )
    try:
        root_code = bytes(
            web3.eth.get_code(Web3.to_checksum_address(root_address))
        )
    except Exception as exc:
        raise GenesisEvmEvidenceError(
            "could not verify zkPassport root verifier bytecode"
        ) from exc
    if not root_code:
        raise GenesisEvmEvidenceError("zkPassport root verifier has no bytecode")
    root_code_hash = "0x" + bytes(Web3.keccak(root_code)).hex()
    if root_code_hash != _hex(
        code_hashes["zkPassportRootVerifier"],
        32,
        "zkPassportRootVerifier runtime bytecode hash",
    ):
        raise GenesisEvmEvidenceError("zkPassport root verifier bytecode hash changed")

    if identity_policy is not None:
        try:
            adapter = web3.eth.contract(address=Web3.to_checksum_address(addresses["verifierAdapter"]), abi=[
                {"type":"function","name":name,"inputs":[],"outputs":[{"type":kind}],"stateMutability":"view"}
                for name,kind in (("ELIGIBILITY_POLICY_ID","bytes32"),("domain","string"),("devMode","bool"),("SANCTIONS_STRICT","bool"))
            ])
            expected_id = bytes(Web3.keccak(text="solslot:age18:sanctions:all:standard:real:solslot.com:v1"))
            if (bytes(adapter.functions.ELIGIBILITY_POLICY_ID().call()) != expected_id
                    or adapter.functions.domain().call() != "solslot.com"
                    or adapter.functions.devMode().call() is not False
                    or adapter.functions.SANCTIONS_STRICT().call() is not False):
                raise ValueError("policy mismatch")
        except Exception as exc:
            raise GenesisEvmEvidenceError("live verifier does not enforce the reviewed eligibility policy") from exc

    return {
        "manifestArtifactHash": supplied_hash,
        "checkedAtBlock": peak,
        "contracts": contracts,
        "zkPassportRootVerifier": {
            "address": root_address,
            "bytecodeHash": root_code_hash,
        },
    }


__all__ = [
    "EVM_CONTRACTS",
    "GenesisEvmEvidenceError",
    "verify_genesis_evm_deployment",
]
