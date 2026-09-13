"""Canonical permit transaction evidence shared by relays and private validators.

Activation must come from an authenticated artifact. These pure checks never
load signing keys, send transactions, renew permits, or trust browser flags.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping
from eth_abi import decode, encode
from eth_abi.exceptions import DecodingError
from web3 import Web3
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.enrollment_activation import activation_from_artifact
from solslot_puzzles.enrollment_permit import EnrollmentPermit, permit_owner_from_native
from .enrollment_permit_signing import verify_permit_signature

BINDING_ABI = "(bytes32,bytes32,uint64)"
PERMIT_ABI = "(bytes32,bytes32,bytes32,bytes32,uint8,bytes32,bytes32,uint64,uint64)"
LEGACY_SELECTOR = bytes.fromhex("d33b3d83")
PERMIT_SELECTOR = bytes(Web3.keccak(text=f"verifyAndEmitWithPermit({BINDING_ABI},{PERMIT_ABI},bytes,bytes)"))[:4]
PERMIT_EVENT_TOPIC = bytes(Web3.keccak(text="EnrollmentPermitConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,uint8,bytes32,uint64,uint64,bytes32)"))
PERMIT_EVENT_ABI = ["bytes32", "bytes32", "uint8", "bytes32", "uint64", "uint64", "bytes32"]


def hx(value: bytes) -> str:
    return "0x" + bytes(value).hex()


@dataclass(frozen=True)
class EnrollmentCalldata:
    vault: str
    parent: str
    amount: int
    permit: EnrollmentPermit | None
    issuer_signature: str | None


def decode_enrollment(data: bytes) -> EnrollmentCalldata:
    if not isinstance(data, bytes) or len(data) < 4:
        raise ValueError("invalid enrollment calldata")
    selected = data[:4] == PERMIT_SELECTOR
    if not selected and data[:4] != LEGACY_SELECTOR:
        raise ValueError("calldata selector is not a supported enrollment function")
    types = [BINDING_ABI, PERMIT_ABI, "bytes", "bytes"] if selected else [BINDING_ABI, "bytes"]
    try:
        values = decode(types, data[4:])
    except DecodingError as exc:
        raise ValueError("enrollment calldata ABI is malformed") from exc
    if encode(types, values) != data[4:]:
        raise ValueError("calldata has trailing bytes or noncanonical ABI offsets")
    binding = values[0]
    if binding[0] == bytes(32):
        raise ValueError("vaultLauncherId must be non-zero")
    if binding[1] == bytes(32):
        raise ValueError("bridgeParentId must be non-zero")
    if binding[2] != 1:
        raise ValueError("bridgeAmount must be exactly one mojo")
    permit = EnrollmentPermit(*values[1]) if selected else None
    if permit is not None and permit.vault_launcher_id != binding[0]:
        raise ValueError("permit vault differs from enrollment binding")
    return EnrollmentCalldata(hx(binding[0]), hx(binding[1]), binding[2], permit,
        hx(values[2]) if selected else None)


def validate_record_permit(record: Mapping[str, Any], artifact: Mapping[str, Any], *,
        owner_auth_type: int | None = None, owner_key: str | None = None,
        current_vault_coin_id: str | None = None, now: int | None = None) -> EnrollmentPermit | None:
    activation = activation_from_artifact(artifact)
    wire = record.get("enrollmentPermit")
    if activation is None:
        if wire is not None or record.get("permitIssuerSignature") is not None or record.get("permitIssuanceStatus") is not None:
            raise ValueError("legacy enrollment cannot contain permit evidence")
        return None
    if record.get("permitIssuanceStatus") != "issued":
        raise ValueError("the saved enrollment permit has not been issued")
    permit = EnrollmentPermit.from_wire(wire)
    verify_permit_signature(wire, activation, record.get("permitIssuerSignature"))
    if (hx(permit.context_hash) != activation["contextHash"]
            or hx(permit.vault_launcher_id) != record.get("vaultLauncherId")
            or hx(permit.bridge_coin_id) != record.get("bridgeCoinId")
            or record.get("bridgePolicyHash") != activation["bridgePolicyHash"]
            or record.get("network") != activation["network"]
            or record.get("policyVersion") != 2
            or permit.expires_at - permit.issued_at > activation["permitLifetimeSeconds"]):
        raise ValueError("permit does not match the signed release and enrollment")
    if owner_auth_type is not None or owner_key is not None:
        if owner_auth_type is None or not isinstance(owner_key, str):
            raise ValueError("permit owner evidence is incomplete")
        auth, digest = permit_owner_from_native(owner_auth_type, bytes.fromhex(owner_key.removeprefix("0x")))
        if permit.owner_auth_type != auth or permit.owner_key_hash != digest:
            raise ValueError("permit belongs to another vault owner")
    if current_vault_coin_id is not None and hx(permit.current_vault_coin_id) != current_vault_coin_id:
        raise ValueError("permit belongs to another vault input")
    if now is not None:
        permit.require_live(now)
    return permit


def require_calldata_record(data: bytes, record: Mapping[str, Any], permit: EnrollmentPermit | None) -> None:
    parsed = decode_enrollment(data)
    if (parsed.vault != record["vaultLauncherId"] or parsed.parent != record["bridgeParentId"]
            or parsed.amount != record["bridgeAmount"] or parsed.permit != permit
            or parsed.issuer_signature != record.get("permitIssuerSignature")):
        raise ValueError("calldata does not match the original enrollment and issuer authorization")


def verify_permit_event_pair(*, logs: list[Any], emitter: str, attestation_topic: bytes,
        permit: EnrollmentPermit, legacy_message: bytes32, block_timestamp: int) -> bytes32:
    """Pair the two events in one canonical receipt, using its inclusion time.

    The caller authenticates the receipt/block and checks all attestation
    commitments. Receipt lookup remains valid after the permit expires.
    """
    permit.require_live(block_timestamp)
    relevant = [log for log in logs if str(log.get("address", "")).lower() == emitter.lower()]
    attestations = [log for log in relevant if log.get("topics") and bytes(log["topics"][0]) == attestation_topic]
    consumed = [log for log in relevant if log.get("topics") and bytes(log["topics"][0]) == PERMIT_EVENT_TOPIC]
    if len(attestations) != 1 or len(consumed) != 1:
        raise ValueError("selected emitter requires exactly one permit and attestation event")
    att, event = attestations[0], consumed[0]
    ai, pi = att.get("logIndex"), event.get("logIndex")
    if type(ai) is not int or type(pi) is not int or pi < 0 or ai != pi + 1:
        raise ValueError("permit and attestation event order is invalid")
    topics = list(event.get("topics") or [])
    expected_topics = [PERMIT_EVENT_TOPIC, permit.permit_id, permit.vault_launcher_id, permit.bridge_coin_id]
    if len(topics) != 4 or [bytes(t) for t in topics] != expected_topics:
        raise ValueError("permit event identity differs from the saved authorization")
    data = bytes(event.get("data") or b"")
    try:
        observed = decode(PERMIT_EVENT_ABI, data)
    except DecodingError as exc:
        raise ValueError("permit event ABI is malformed") from exc
    wrapped = permit.validator_message(legacy_message)
    expected = (permit.permit_hash, permit.current_vault_coin_id, permit.owner_auth_type,
        permit.owner_key_hash, permit.issued_at, permit.expires_at, wrapped)
    if observed != expected or encode(PERMIT_EVENT_ABI, observed) != data:
        raise ValueError("permit event commitments or encoding do not match")
    return wrapped


def verify_selected_emitter(w3: Any, artifact: Mapping[str, Any], *, expected_direct_relayer: str | None = None) -> str:
    """Inspect immutable deployment bindings using the caller's own RPC."""
    activation = activation_from_artifact(artifact, required=True)
    addresses = artifact["evmAddresses"]
    abi = [{"type": "function", "name": name, "stateMutability": "view", "inputs": [],
            "outputs": [{"name": "", "type": kind}]} for name, kind in (
        ("bridgePolicyHash", "bytes32"), ("permitContextHash", "bytes32"),
        ("permitIssuer", "address"), ("verifier", "address"), ("trustedDirectRelayer", "address"))]
    abi.append({"type": "function", "name": "isTrustedForwarder", "stateMutability": "view",
        "inputs": [{"name": "forwarder", "type": "address"}], "outputs": [{"name": "", "type": "bool"}]})
    address = Web3.to_checksum_address(activation["emitter"])
    if int(w3.eth.chain_id) != activation["evmChainId"] or not w3.eth.get_code(address):
        raise ValueError("permit emitter is unavailable on the reviewed chain")
    emitter = w3.eth.contract(address=address, abi=abi)
    if (hx(emitter.functions.bridgePolicyHash().call()) != activation["bridgePolicyHash"]
            or hx(emitter.functions.permitContextHash().call()) != activation["contextHash"]
            or emitter.functions.permitIssuer().call().lower() != activation["issuer"]
            or emitter.functions.verifier().call().lower() != addresses["verifierAdapter"].lower()
            or emitter.functions.isTrustedForwarder(Web3.to_checksum_address(addresses["forwarder"])).call() is not True):
        raise ValueError("permit emitter immutables differ from authenticated deployment evidence")
    direct = emitter.functions.trustedDirectRelayer().call().lower()
    if direct == "0x" + "00" * 20 or (expected_direct_relayer is not None and direct != expected_direct_relayer.lower()):
        raise ValueError("permit emitter direct relayer does not match")
    return direct
