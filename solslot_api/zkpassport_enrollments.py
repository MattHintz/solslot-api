"""zkPassport vault enrollment receipt index.

This router tracks public, non-PII credential receipt material for the
testnet alpha vault stamp flow.  The Chia vault state is still the source of
truth; this index reserves bridge coins and gives the frontend a recoverable
receipt surface instead of trusting browser-local flags.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import httpx
from eth_abi import decode as abi_decode, encode as abi_encode
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, HTTPException, Path as ApiPath, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from web3 import Web3

from .config import Settings
from .bridge_coin_policy import BridgeCoinPolicy
from .chia_provider import ChiaProvider
from .credential_auth import (
    OwnerAuth,
    OwnerChallengeRequest,
    OwnerChallengeResponse,
    VAULT_SESSION_COOKIE,
    VaultSessionResponse,
    issue_owner_challenge,
    issue_vault_session,
    verify_owner_auth,
    verify_vault_session,
    vault_session_payload,
)
from .credential_ledger import LedgerConflict, LedgerRateLimited, get_credential_ledger
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA
from .state import VaultRecord, get_registry
from .validator_quorum import (
    ValidatorClaim,
    PermitValidatorClaim,
    ValidatorQuorumError,
    collect_validator_quorum,
    configured_bridge_policy_hash,
    configured_validator_pubkeys,
)
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS

router = APIRouter(prefix="/zkpassport/enrollments", tags=["zkpassport"])

_HEX32_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
_EMPTY_ATTEST_ROOT = "0x4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
_ATTESTATION_EVENT_SIGNATURE = (
    "VaultAttestationVerified(address,bytes32,bytes32,uint16,bytes32,bytes32,"
    "uint64,bytes32,bytes32,bytes32,uint64,bytes32,bytes32,bytes32,uint16)"
)
_ATTESTATION_EVENT_TOPIC = bytes(Web3.keccak(text=_ATTESTATION_EVENT_SIGNATURE))
VaultLauncherPath = Annotated[
    str,
    ApiPath(pattern=r"^(0x)?[0-9a-fA-F]{64}$"),
]


@dataclass(frozen=True)
class IndexedEvmAttestation:
    sender: str
    vault_launcher_id: str
    scoped_nullifier: str
    nullifier_type: int
    service_scope_hash: str
    service_subscope_hash: str
    proof_timestamp: int
    attestation_leaf_hash: str
    identity_attest_root: str
    bridge_parent_id: str
    bridge_amount: int
    bridge_coin_id: str
    bridge_message: str
    bridge_policy_hash: str
    policy_version: int
    validator_message: str
    transaction_hash: str
    block_number: int


@dataclass(frozen=True)
class BridgeCoinCandidate:
    parent_id: str
    amount: int
    coin_id: str


class AttestationProof(BaseModel):
    bitpath: int = Field(0, ge=0)
    siblings: list[str] = Field(default_factory=list)

    @field_validator("siblings")
    @classmethod
    def _siblings_are_hashes(cls, value: list[str]) -> list[str]:
        return [_normalize_hex32(v, "attestationProof.siblings[]") for v in value]


class VaultCredentialReceipt(BaseModel):
    vaultLauncherId: str
    network: str
    policyVersion: int = Field(..., ge=1)
    identityAttestRoot: str
    attestationLeafHash: str
    attestationProof: AttestationProof
    scopedNullifier: Optional[str] = None
    nullifierType: Optional[int] = None
    serviceScopeHash: Optional[str] = None
    serviceSubscopeHash: Optional[str] = None
    proofTimestamp: Optional[int] = None
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int = Field(..., gt=0)
    bridgeCoinId: str
    bridgeMessage: Optional[str] = None
    validatorMessage: Optional[str] = None
    evmTxHash: str
    evmConfirmedBlockIndex: Optional[int] = None
    chiaVaultCoinId: Optional[str] = None
    chiaStampCoinId: Optional[str] = None
    genesisArtifactHash: Optional[str] = None
    confirmedBlockIndex: Optional[int] = None
    chiaSpendBundleId: Optional[str] = None
    enrolledAt: int


class EnrollmentRecord(BaseModel):
    enrollmentPermit: dict[str, Any] | None = None
    permitIssuerSignature: str | None = None
    permitIssuanceStatus: Literal['pending','issued'] | None = None

    @field_validator('enrollmentPermit')
    @classmethod
    def _permit_is_canonical(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            from solslot_puzzles.enrollment_permit import EnrollmentPermit
            EnrollmentPermit.from_wire(value)
        return value

    vaultLauncherId: str
    network: str
    policyVersion: int
    status: Literal[
        "reserved",
        "evm_confirmed",
        "stamp_pending",
        "chia_confirmed",
        "receipt_syncing",
    ]
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int
    bridgeCoinId: str
    createdAt: int
    updatedAt: int
    receipt: Optional[VaultCredentialReceipt] = None


class CreateEnrollmentRequest(BaseModel):
    vaultLauncherId: str


class RecordProofRequest(BaseModel):
    vaultLauncherId: str
    policyVersion: int = Field(..., ge=1)
    identityAttestRoot: str
    attestationLeafHash: str
    attestationProof: AttestationProof = Field(default_factory=AttestationProof)
    bridgePolicyHash: str
    bridgeParentId: str
    bridgeAmount: int = Field(..., gt=0)
    bridgeCoinId: str
    bridgeMessage: Optional[str] = None
    validatorMessage: Optional[str] = None
    evmTxHash: str


class VaultSessionLoginRequest(BaseModel):
    ownerAuth: OwnerAuth


class RelayChallengeRequest(BaseModel):
    data: str = Field(..., min_length=10)


class PrepareChiaStampResponse(BaseModel):
    vaultLauncherId: str
    authType: Literal["evm", "chia_bls"]
    currentVaultCoinId: str
    identityAttestRoot: str
    typedData: Optional[dict[str, Any]] = None
    currentTimestamp: Optional[int] = None
    vaultCoinSpend: Optional[dict[str, Any]] = None


class SubmitChiaStampRequest(BaseModel):
    signature: str
    currentTimestamp: Optional[int] = Field(None, ge=0)


class SubmitChiaStampResponse(BaseModel):
    enrollment: EnrollmentRecord
    spendBundleId: str
    expectedVaultCoinId: str


class SyncChiaStampResponse(BaseModel):
    enrollment: EnrollmentRecord
    confirmed: bool


def _settings() -> Settings:
    return Settings()


def _normalize_hex32(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not _HEX32_RE.match(text):
        raise ValueError(f"{field} must be a 32-byte hex string")
    return "0x" + text.removeprefix("0x").lower()


def _normalize_tx(value: object, field: str) -> str:
    return _normalize_hex32(value, field)


def _coin_id(parent_id: str, puzzle_hash: str, amount: int) -> str:
    coin = Coin(
        parent_coin_info=bytes32.fromhex(parent_id.removeprefix("0x")),
        puzzle_hash=bytes32.fromhex(puzzle_hash.removeprefix("0x")),
        amount=uint64(amount),
    )
    return "0x" + coin.name().hex()


def _hex32(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _active_genesis_artifact(settings: Settings) -> dict[str, Any]:
    try:
        from .public_artifact import load_signed_public_artifact

        return load_signed_public_artifact(settings)
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed V2 genesis artifact is unavailable or invalid.",
        ) from exc


def _active_pool_launcher_id(settings: Settings) -> str:
    try:
        return _normalize_hex32(
            _active_genesis_artifact(settings)["launcherIds"]["pool"],
            "publicArtifact.launcherIds.pool",
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed V2 genesis artifact has no pool launcher.",
        ) from exc


def _active_bridge_policy_hash(settings: Settings) -> str:
    try:
        return _normalize_hex32(
            _active_genesis_artifact(settings)["bridgePolicy"]["policyHash"],
            "publicArtifact.bridgePolicy.policyHash",
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed V2 genesis artifact has no bridge policy.",
        ) from exc


def _active_bridge_coin_policy(settings: Settings) -> BridgeCoinPolicy:
    try:
        return BridgeCoinPolicy.from_artifact(_active_genesis_artifact(settings))
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="The signed bridge coin policy is invalid.") from exc


def _require_enrollment_bridge_policy(
    settings: Settings, record: dict[str, Any], *, policy: BridgeCoinPolicy | None = None,
    execution: bool = False,
) -> None:
    policy = policy or _active_bridge_coin_policy(settings)
    if execution and (policy.permit_version is not None or record.get('enrollmentPermit') is not None):
        _record_permit(settings, record)
    try:
        policy.require_coin(
            policy_hash=record.get("bridgePolicyHash"), parent_id=record.get("bridgeParentId"),
            amount=record.get("bridgeAmount"), coin_id=record.get("bridgeCoinId"),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=("This enrollment's bridge coin is outside the signed release policy. "
                    "Contact support to reconcile any existing proof before restarting verification."),
        ) from exc


def _record_permit(settings: Settings, record: dict[str, Any], *,
        owner_auth_type: int | None = None, owner_key: str | None = None,
        current_vault_coin_id: str | None = None, now: int | None = None):
    if not settings.enrollment_permit_release_identity and record.get("enrollmentPermit") is None:
        return None
    from .enrollment_permit_runtime import validate_record_permit
    try:
        return validate_record_permit(record, _active_genesis_artifact(settings),
            owner_auth_type=owner_auth_type, owner_key=owner_key,
            current_vault_coin_id=current_vault_coin_id, now=now)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=409, detail=f"The saved permit cannot authorize this action: {exc}") from exc


def _active_emitter_address(settings: Settings) -> str:
    try:
        value = _active_genesis_artifact(settings)["evmAddresses"][
            "attestationEmitter"
        ]
        return Web3.to_checksum_address(value)
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed V2 genesis artifact has no valid attestation emitter.",
        ) from exc


def _fetch_verified_evm_attestation(
    settings: Settings,
    *,
    transaction_hash: str,
    expected_vault_launcher_id: str,
    authenticated_artifact: dict[str, Any] | None = None,
    permit_record: dict[str, Any] | None = None,
) -> IndexedEvmAttestation:
    """Read and fully validate the canonical emitter event from Sepolia."""
    tx_hash = _normalize_tx(transaction_hash, "evmTxHash")
    artifact = authenticated_artifact
    if artifact is None and settings.enrollment_permit_release_identity:
        artifact = _active_genesis_artifact(settings)
    emitter_address = (Web3.to_checksum_address(artifact["evmAddresses"]["attestationEmitter"])
        if artifact is not None else _active_emitter_address(settings))
    w3 = Web3(
        Web3.HTTPProvider(
            settings.zkpassport_evm_rpc_url,
            request_kwargs={"timeout": 20.0},
        )
    )
    from .evm_relay_transaction import canonical_receipt
    try:
        if int(w3.eth.chain_id) != settings.zkpassport_evm_chain_id:
            raise ValueError("zkPassport RPC chain does not match the signed deployment")
        receipt = canonical_receipt(w3, tx_hash, settings.zkpassport_evm_min_confirmations)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=f"The zkPassport receipt is not canonical: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not verify the canonical zkPassport receipt.") from exc
    if receipt is None:
        raise HTTPException(status_code=409, detail="The zkPassport EVM event is not yet confirmed with the required confirmations.")
    if receipt['status'] != 1:
        raise HTTPException(status_code=409, detail="The zkPassport EVM transaction reverted.")
    block_number = receipt['blockNumber']

    permit = None
    if artifact is not None:
        from solslot_puzzles.enrollment_activation import activation_from_artifact
        from .enrollment_permit_runtime import validate_record_permit
        try:
            activation = activation_from_artifact(artifact)
            if activation is not None:
                record = permit_record
                if record is None:
                    record = get_credential_ledger(settings).get_enrollment(
                        _normalize_hex32(expected_vault_launcher_id, "vaultLauncherId"))
                if record is None:
                    raise ValueError("permit reservation is unavailable")
                permit = validate_record_permit(record, artifact)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=409, detail=f"Permit receipt evidence is invalid: {exc}") from exc

    matching: list[IndexedEvmAttestation] = []
    for log in receipt.get("logs", []):
        topics = list(log.get("topics") or [])
        if (
            str(log.get("address", "")).lower() != emitter_address.lower()
            or len(topics) != 4
            or bytes(topics[0]) != _ATTESTATION_EVENT_TOPIC
        ):
            continue
        sender = Web3.to_checksum_address("0x" + bytes(topics[1])[-20:].hex())
        vault_launcher_id = _hex32(bytes(topics[2]))
        scoped_nullifier = _hex32(bytes(topics[3]))
        try:
            (
                nullifier_type,
                service_scope_hash,
                service_subscope_hash,
                proof_timestamp,
                attestation_leaf_hash,
                attestation_root,
                bridge_parent_id,
                bridge_amount,
                bridge_coin_id,
                bridge_message,
                bridge_policy_hash,
                policy_version,
            ) = abi_decode(
                [
                    "uint16",
                    "bytes32",
                    "bytes32",
                    "uint64",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "uint64",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "uint16",
                ],
                bytes(log.get("data") or b""),
            )
        except Exception as exc:  # noqa: BLE001 - malformed event is a hard failure
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"The zkPassport emitter event is malformed: {exc}",
            ) from exc

        if permit is not None:
            types = ["uint16", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32",
                "uint64", "bytes32", "bytes32", "bytes32", "uint16"]
            values = (nullifier_type, service_scope_hash, service_subscope_hash, proof_timestamp,
                attestation_leaf_hash, attestation_root, bridge_parent_id, bridge_amount, bridge_coin_id,
                bridge_message, bridge_policy_hash, policy_version)
            if (any(len(bytes(t)) != 32 for t in topics) or bytes(topics[1])[:12] != bytes(12)
                    or abi_encode(types, values) != bytes(log.get("data") or b"")):
                raise HTTPException(status_code=409, detail="The selected attestation encoding is not canonical.")

        matching.append(
            IndexedEvmAttestation(
                sender=sender,
                vault_launcher_id=vault_launcher_id,
                scoped_nullifier=scoped_nullifier,
                nullifier_type=int(nullifier_type),
                service_scope_hash=_hex32(service_scope_hash),
                service_subscope_hash=_hex32(service_subscope_hash),
                proof_timestamp=int(proof_timestamp),
                attestation_leaf_hash=_hex32(attestation_leaf_hash),
                identity_attest_root=_hex32(attestation_root),
                bridge_parent_id=_hex32(bridge_parent_id),
                bridge_amount=int(bridge_amount),
                bridge_coin_id=_hex32(bridge_coin_id),
                bridge_message=_hex32(bridge_message),
                bridge_policy_hash=_hex32(bridge_policy_hash),
                policy_version=int(policy_version),
                validator_message="",
                transaction_hash=tx_hash,
                block_number=block_number,
            )
        )

    expected_vault = _normalize_hex32(expected_vault_launcher_id, "vaultLauncherId")
    matching = [event for event in matching if event.vault_launcher_id == expected_vault]
    if len(matching) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The transaction must contain exactly one canonical vault attestation event.",
        )
    event = matching[0]

    try:
        from solslot_puzzles.zkpassport_attestation import (
            ZkPassportAttestation,
            compute_attestation_bridge_message,
            compute_attestation_root,
            compute_validator_bridge_message,
        )

        attestation = ZkPassportAttestation(
            vault_launcher_id=bytes32.fromhex(event.vault_launcher_id.removeprefix("0x")),
            scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
            nullifier_type=event.nullifier_type,
            service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
            service_subscope_hash=bytes32.fromhex(event.service_subscope_hash.removeprefix("0x")),
            proof_timestamp=event.proof_timestamp,
            policy_version=event.policy_version,
        )
        leaf = attestation.leaf_hash
        root = compute_attestation_root([leaf])
        bridge_policy_hash = bytes32.fromhex(event.bridge_policy_hash.removeprefix("0x"))
        bridge_message = compute_attestation_bridge_message(
            vault_launcher_id=attestation.vault_launcher_id,
            attestation_root=root,
            bridge_policy_hash=bridge_policy_hash,
            policy_version=event.policy_version,
        )
        bridge_coin_id = Coin(
            bytes32.fromhex(event.bridge_parent_id.removeprefix("0x")),
            bridge_policy_hash,
            uint64(event.bridge_amount),
        ).name()
        validator_message = compute_validator_bridge_message(
            vault_launcher_id=attestation.vault_launcher_id,
            attestation_root=root,
            bridge_policy_hash=bridge_policy_hash,
            bridge_coin_id=bridge_coin_id,
            bridge_message=bridge_message,
            attestation_leaf_hash=leaf,
            scoped_nullifier=attestation.scoped_nullifier,
            nullifier_type=attestation.nullifier_type,
            service_scope_hash=attestation.service_scope_hash,
            service_subscope_hash=attestation.service_subscope_hash,
            proof_timestamp=attestation.proof_timestamp,
            policy_version=event.policy_version,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The zkPassport event commitments are invalid: {exc}",
        ) from exc

    expected = {
        "policyVersion": settings.zkpassport_policy_version,
        "attestationLeafHash": _hex32(leaf),
        "identityAttestRoot": _hex32(root),
        "bridgePolicyHash": artifact["bridgePolicy"]["policyHash"] if artifact is not None else _active_bridge_policy_hash(settings),
        "bridgeCoinId": _hex32(bridge_coin_id),
        "bridgeMessage": _hex32(bridge_message),
    }
    observed = {
        "policyVersion": event.policy_version,
        "attestationLeafHash": event.attestation_leaf_hash,
        "identityAttestRoot": event.identity_attest_root,
        "bridgePolicyHash": event.bridge_policy_hash,
        "bridgeCoinId": event.bridge_coin_id,
        "bridgeMessage": event.bridge_message,
    }
    if observed != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The zkPassport EVM event commitments do not match the Chia policy.",
        )
    if permit is not None:
        from .enrollment_permit_runtime import verify_permit_event_pair, verify_selected_emitter
        try:
            block = w3.eth.get_block(block_number)
            if bytes(block["hash"]) != bytes(receipt["blockHash"]):
                raise ValueError("permit inclusion block changed during verification")
            validator_message = verify_permit_event_pair(logs=list(receipt.get("logs", [])),
                emitter=emitter_address, attestation_topic=_ATTESTATION_EVENT_TOPIC,
                permit=permit, legacy_message=validator_message, block_timestamp=block["timestamp"])
            direct = verify_selected_emitter(w3, artifact)
            from solslot_puzzles.enrollment_permit import owner_key_hash
            if ((permit.owner_auth_type == 1 and event.sender.lower() != direct)
                    or (permit.owner_auth_type == 2 and owner_key_hash(2, bytes.fromhex(event.sender[2:])) != permit.owner_key_hash)):
                raise ValueError("permit event sender differs from its authorized owner or relayer")
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(status_code=409, detail=f"Permit receipt does not match: {exc}") from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Could not inspect the permit deployment and inclusion block.") from exc
    return IndexedEvmAttestation(
        **{
            **event.__dict__,
            "validator_message": _hex32(validator_message),
        }
    )


def _fetch_coin_record_by_name(settings: Settings, coin_id: str) -> Optional[dict[str, Any]]:
    base_url = settings.coinset_base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post("/get_coin_record_by_name", json={"name": coin_id})
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not verify the Chia vault stamp: {exc}",
        ) from exc
    if not isinstance(payload, dict):
        return None
    record = payload.get("coin_record")
    return record if isinstance(record, dict) else None


def _fetch_coin_records_by_parent_ids(
    settings: Settings,
    parent_ids: list[str],
    *,
    include_spent: bool = False,
) -> list[dict[str, Any]]:
    base_url = settings.coinset_base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_coin_records_by_parent_ids",
                json={
                    "parent_ids": parent_ids,
                    "include_spent_coins": include_spent,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not resolve the current vault coin: {exc}",
        ) from exc
    records = payload.get("coin_records") if isinstance(payload, dict) else None
    return records if isinstance(records, list) else []


def _coin_from_record(record: dict[str, Any], field: str) -> Coin:
    coin = record.get("coin")
    if not isinstance(coin, dict):
        raise ValueError(f"{field} is missing coin fields")
    parent_id = _normalize_hex32(coin.get("parent_coin_info"), f"{field}.parent_coin_info")
    puzzle_hash = _normalize_hex32(coin.get("puzzle_hash"), f"{field}.puzzle_hash")
    amount = int(coin.get("amount"))
    return Coin(
        bytes32.fromhex(parent_id.removeprefix("0x")),
        bytes32.fromhex(puzzle_hash.removeprefix("0x")),
        uint64(amount),
    )


def _find_initial_vault_coin(settings: Settings, vault_launcher_id: str) -> Coin:
    launcher = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    candidates: list[Coin] = []
    for record in _fetch_coin_records_by_parent_ids(
        settings,
        [launcher],
        include_spent=True,
    ):
        try:
            coin = _coin_from_record(record, "vaultCoin")
        except (TypeError, ValueError):
            continue
        if coin.parent_coin_info == bytes32.fromhex(launcher.removeprefix("0x")) and int(coin.amount) == 1:
            candidates.append(coin)
    if len(candidates) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The unspent initial Chia vault coin could not be resolved uniquely. "
                "The vault may already be stamped or its launcher is not confirmed."
            ),
        )
    return candidates[0]


def _initial_vault_lineage(settings: Settings, vault_coin: Coin, launcher_id: bytes32) -> LineageProof:
    """An eve singleton proves its launcher using the launcher's parent, not its ID."""
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    record = _fetch_coin_record_by_name(settings, _hex32(launcher_id))
    try:
        launcher = _coin_from_record(record, "vaultLauncher")
        if (launcher.name() != launcher_id or launcher.puzzle_hash != SINGLETON_LAUNCHER_HASH
                or launcher.amount != 1 or vault_coin.parent_coin_info != launcher_id
                or type(record.get("confirmed_block_index")) is not int
                or record["confirmed_block_index"] <= 0
                or type(record.get("spent_block_index")) is not int
                or record["spent_block_index"] < record["confirmed_block_index"]):
            raise ValueError("launcher record does not prove the initial vault lineage")
        return LineageProof(parent_name=launcher.parent_coin_info, amount=uint64(1))
    except (AttributeError, TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=409,
            detail="The confirmed launcher lineage is unavailable or does not match this vault.") from exc


def _verify_reserved_bridge_coin(settings: Settings, record: EnrollmentRecord) -> Coin:
    _require_enrollment_bridge_policy(settings, record.model_dump(), execution=True)
    coin_record = _fetch_coin_record_by_name(settings, record.bridgeCoinId)
    try:
        confirmed = coin_record is not None and int(coin_record.get("confirmed_block_index") or 0) > 0
    except (TypeError, ValueError):
        confirmed = False
    if not confirmed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved zkPassport bridge coin is not confirmed on Chia.",
        )
    try:
        coin = _coin_from_record(coin_record, "bridgeCoin")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Coinset returned an invalid bridge coin: {exc}",
        ) from exc
    expected = Coin(
        bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
        bytes32.fromhex(record.bridgePolicyHash.removeprefix("0x")),
        uint64(record.bridgeAmount),
    )
    if coin != expected or _hex32(coin.name()) != record.bridgeCoinId:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved bridge coin does not match its indexed enrollment.",
        )
    if coin_record.get("spent_block_index") not in (0, None) or coin_record.get("spent") is True:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved zkPassport bridge coin is already spent.",
        )
    return coin


def _active_artifact_hash(settings: Settings) -> str:
    try:
        from .public_artifact import load_signed_public_artifact

        payload = load_signed_public_artifact(settings)
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed V2 public artifact is unavailable or invalid.",
        ) from exc
    try:
        return _normalize_hex32(payload.get("artifactHash"), "artifactHash")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The signed V2 public artifact has no canonical hash.",
        ) from exc


def _validator_claim(
    settings: Settings,
    *,
    key: str,
    record: EnrollmentRecord,
    event: IndexedEvmAttestation,
    vault_coin: Coin,
    vault_record: VaultRecord,
    owner_key: str,
    owner_authorization: str,
    current_timestamp: int,
) -> ValidatorClaim:
    if record.receipt is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential validator evidence is incomplete.",
        )
    try:
        authorization_bytes = bytes.fromhex(owner_authorization.removeprefix("0x"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Owner authorization is not hex.") from exc
    permit = _record_permit(settings, record.model_dump(), owner_auth_type=vault_record.auth_type,
        owner_key=owner_key, current_vault_coin_id=_hex32(vault_coin.name()), now=int(time.time()))
    claim_type = PermitValidatorClaim if permit is not None else ValidatorClaim
    extra = dict(claim_version="solslot.enrollment-permit-claim.v1", enrollment_permit=permit.to_wire(),
        permit_issuer_signature=record.permitIssuerSignature) if permit is not None else {}
    return claim_type(
        **extra,
        network=settings.network,
        artifact_hash=_active_artifact_hash(settings),
        vault_launcher_id=key,
        current_vault_coin_id=_hex32(vault_coin.name()),
        owner_key=owner_key,
        owner_auth_type=vault_record.auth_type,
        owner_authorization=owner_authorization,
        owner_authorization_hash="0x" + hashlib.sha256(authorization_bytes).hexdigest(),
        current_timestamp=current_timestamp,
        evm_transaction_hash=event.transaction_hash,
        evm_block_number=event.block_number,
        emitter_address=_active_emitter_address(settings),
        policy_version=record.policyVersion,
        identity_attest_root=event.identity_attest_root,
        attestation_leaf_hash=event.attestation_leaf_hash,
        scoped_nullifier=event.scoped_nullifier,
        nullifier_type=event.nullifier_type,
        service_scope_hash=event.service_scope_hash,
        service_subscope_hash=event.service_subscope_hash,
        proof_timestamp=event.proof_timestamp,
        bridge_policy_hash=record.bridgePolicyHash,
        bridge_parent_id=record.bridgeParentId,
        bridge_amount=record.bridgeAmount,
        bridge_coin_id=record.bridgeCoinId,
        validator_message=event.validator_message,
    )


def _verify_current_chia_vault_coin(
    settings: Settings,
    *,
    coin_id: str,
    confirmed_block_index: int,
    expected_puzzle_hash: str,
    expected_parent_id: Optional[str] = None,
) -> dict[str, Any]:
    record = _fetch_coin_record_by_name(settings, coin_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coinset has no confirmed record for the claimed vault coin.",
        )
    coin = record.get("coin")
    if not isinstance(coin, dict):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coinset returned a malformed vault coin record.",
        )
    try:
        parent_id = _normalize_hex32(coin.get("parent_coin_info"), "coin.parent_coin_info")
        puzzle_hash = _normalize_hex32(coin.get("puzzle_hash"), "coin.puzzle_hash")
        amount = int(coin.get("amount"))
        observed_confirmed_height = int(record.get("confirmed_block_index"))
        spent_height = int(record.get("spent_block_index") or 0)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Coinset returned an invalid vault coin record.",
        ) from exc
    if amount != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The confirmed coin is not a one-mojo vault singleton coin.",
        )
    if expected_parent_id and parent_id != _normalize_hex32(
        expected_parent_id,
        "expected_parent_id",
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed vault coin is not the stamped successor of this vault.",
        )
    if puzzle_hash != expected_puzzle_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The current vault coin puzzle hash does not match the stamped identity root.",
        )
    if _coin_id(parent_id, puzzle_hash, amount) != coin_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed vault coin id does not match Coinset's coin fields.",
        )
    if observed_confirmed_height != confirmed_block_index:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed confirmation height does not match Coinset.",
        )
    if spent_height != 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The claimed vault coin is already spent, so it is not current.",
        )
    return record


def _expected_stamped_vault_puzzle_hash(
    settings: Settings,
    *,
    vault_launcher_id: str,
    identity_attest_root: str,
) -> str:
    pool_launcher_id = _active_pool_launcher_id(settings)
    bridge_policy_hash = _active_bridge_policy_hash(settings)
    registry = get_registry()
    record = registry.get(bytes32.fromhex(vault_launcher_id.removeprefix("0x")))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault is not registered on this server; cannot verify stamped vault puzzle.",
        )
    try:
        from solslot_puzzles.vault_driver import (
            one_leaf_merkle_root,
            puzzle_for_vault_full,
        )

        expected = puzzle_for_vault_full(
            bytes32.fromhex(vault_launcher_id.removeprefix("0x")),
            bytes(record.owner_pubkey),
            int(record.auth_type),
            one_leaf_merkle_root(bytes(record.owner_pubkey)),
            bytes32.fromhex(pool_launcher_id.removeprefix("0x")),
            identity_attest_root=bytes32.fromhex(identity_attest_root.removeprefix("0x")),
            zkpassport_bridge_policy_hash=bytes32.fromhex(
                bridge_policy_hash.removeprefix("0x")
            ),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Vault registry cannot reconstruct the stamped vault puzzle: {exc}",
        ) from exc
    return "0x" + expected.get_tree_hash().hex()


def _sync_chia_stamp(settings: Settings, key: str) -> EnrollmentRecord:
    ledger = get_credential_ledger(settings)
    existing = ledger.get_enrollment(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    record = EnrollmentRecord.model_validate(existing)
    if record.receipt is None or not record.receipt.chiaVaultCoinId:
        return record
    if record.status not in {"stamp_pending", "receipt_syncing", "chia_confirmed"}:
        return record

    from .vault_chain_evidence import resolve_enrolled_vault_tip, VaultHistoryError
    from solslot_puzzles.vault_driver import DEFAULT_IDENTITY_ATTEST_ROOT

    expected_puzzle_hash = _expected_stamped_vault_puzzle_hash(
        settings, vault_launcher_id=key,
        identity_attest_root=record.receipt.identityAttestRoot,
    )
    artifact_hash = _active_artifact_hash(settings)
    try:
        if (record.network != settings.network or record.receipt.network != record.network
                or record.receipt.vaultLauncherId != key
                or record.policyVersion != settings.zkpassport_policy_version
                or record.receipt.policyVersion != record.policyVersion
                or record.bridgePolicyHash != _active_bridge_policy_hash(settings)
                or record.receipt.bridgePolicyHash != record.bridgePolicyHash
                or record.receipt.identityAttestRoot == _hex32(DEFAULT_IDENTITY_ATTEST_ROOT)
                or (record.receipt.genesisArtifactHash is not None
                    and record.receipt.genesisArtifactHash != artifact_hash)):
            raise VaultHistoryError("Receipt differs from the active enrollment release")
        stamp_id = bytes32.fromhex(_normalize_hex32(
            record.receipt.chiaStampCoinId or record.receipt.chiaVaultCoinId,
            "receipt.chiaStampCoinId").removeprefix("0x"))
        if (record.status != "chia_confirmed"
                and _fetch_coin_record_by_name(settings, _hex32(stamp_id)) is None):
            return record
        tip, stamp_id = resolve_enrolled_vault_tip(
            stamp_id=stamp_id, launcher_id=bytes32.fromhex(key.removeprefix("0x")),
            unstamped_puzzle_hash=bytes32.fromhex(_expected_stamped_vault_puzzle_hash(
                settings, vault_launcher_id=key,
                identity_attest_root=_hex32(DEFAULT_IDENTITY_ATTEST_ROOT),
            ).removeprefix("0x")),
            stamped_puzzle_hash=bytes32.fromhex(expected_puzzle_hash.removeprefix("0x")),
            fetch_coin=lambda coin_id: _fetch_coin_record_by_name(settings, _hex32(coin_id)),
        )
        coin_id = _hex32(tip.coin.name())
        confirmed_block_index = tip.confirmed_height
    except (VaultHistoryError, HTTPException) as exc:
        if record.status != "chia_confirmed":
            raise HTTPException(status_code=409, detail=f"Vault receipt history is not current: {exc}") from exc
        latest = EnrollmentRecord.model_validate(ledger.get_enrollment(key) or existing)
        downgraded = latest.model_copy(
            update={"status": "receipt_syncing", "updatedAt": int(time.time())}
        )
        try:
            ledger.update_enrollment(downgraded.model_dump(), expected_statuses={"chia_confirmed"})
        except LedgerConflict as conflict:
            raise HTTPException(status_code=409, detail=str(conflict)) from conflict
        return downgraded

    registry = get_registry()
    vault_record = registry.get(bytes32.fromhex(key.removeprefix("0x")))
    if vault_record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault ownership metadata is missing; the Chia stamp cannot be indexed safely.",
        )
    registry.record(
        VaultRecord(
            launcher_id=vault_record.launcher_id,
            full_puzhash=bytes32.fromhex(expected_puzzle_hash.removeprefix("0x")),
            p2_vault_puzhash=vault_record.p2_vault_puzhash,
            auth_type=vault_record.auth_type,
            owner_pubkey=vault_record.owner_pubkey,
            owner_evm_address=vault_record.owner_evm_address,
            spend_bundle_id=record.receipt.chiaSpendBundleId or vault_record.spend_bundle_id,
            pushed_at=vault_record.pushed_at,
        )
    )

    latest_raw = ledger.get_enrollment(key)
    if not latest_raw:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    latest = EnrollmentRecord.model_validate(latest_raw)
    if latest.receipt is None:
        raise HTTPException(status_code=409, detail="No EVM proof receipt to confirm.")
    receipt = latest.receipt.model_copy(
        update={
            "chiaVaultCoinId": coin_id,
            "chiaStampCoinId": _hex32(stamp_id),
            "genesisArtifactHash": artifact_hash,
            "confirmedBlockIndex": confirmed_block_index,
        }
    )
    confirmed = latest.model_copy(
        update={
            "status": "chia_confirmed",
            "receipt": receipt,
            "updatedAt": int(time.time()),
        }
    )
    try:
        ledger.update_enrollment(
            confirmed.model_dump(),
            expected_statuses={"stamp_pending", "receipt_syncing", "chia_confirmed"},
        )
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return confirmed


def _fetch_bridge_coin_records(settings: Settings, bridge_policy_hash: str) -> list[dict[str, Any]]:
    base_url = settings.coinset_base_url.rstrip("/")
    try:
        with httpx.Client(
            base_url=base_url,
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_coin_records_by_puzzle_hash",
                json={
                    "puzzle_hash": bridge_policy_hash,
                    "include_spent_coins": False,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Coinset could not discover zkPassport bridge coins: {exc}",
        ) from exc
    if not isinstance(payload, dict):
        return []
    records = payload.get("coin_records") or []
    return records if isinstance(records, list) else []


def _bridge_coin_candidates(
    settings: Settings,
    *,
    bridge_policy_hash: str,
    policy: BridgeCoinPolicy | None = None,
) -> list[BridgeCoinCandidate]:
    policy = policy or _active_bridge_coin_policy(settings)
    if policy.policy_hash != bridge_policy_hash:
        raise HTTPException(status_code=503, detail="The bridge discovery policy does not match the signed release.")
    candidates_by_id: dict[str, BridgeCoinCandidate] = {}

    for record in _fetch_bridge_coin_records(settings, bridge_policy_hash):
        if not isinstance(record, dict):
            continue
        if record.get("spent_block_index") not in (0, None) or bool(record.get("spent")):
            continue
        coin = record.get("coin")
        if not isinstance(coin, dict):
            continue
        try:
            if int(record.get("confirmed_block_index") or 0) <= 0:
                continue
            parent = _normalize_hex32(coin.get("parent_coin_info"), "bridge.parent_coin_info")
            puzzle_hash = _normalize_hex32(coin.get("puzzle_hash"), "bridge.puzzle_hash")
            raw_amount = coin.get("amount")
            if isinstance(raw_amount, bool) or not isinstance(raw_amount, (str, int)):
                continue
            amount = int(raw_amount)
            if amount != 1:
                continue
            coin_id = _coin_id(parent, puzzle_hash, amount)
            policy.require_coin(policy_hash=puzzle_hash, parent_id=parent, amount=amount, coin_id=coin_id)
        except (TypeError, ValueError):
            continue
        candidates_by_id[coin_id] = BridgeCoinCandidate(
            parent_id=parent,
            amount=amount,
            coin_id=coin_id,
        )

    return sorted(
        candidates_by_id.values(),
        key=lambda item: (item.amount, item.parent_id),
    )

def _public_record(record: dict[str, Any]) -> EnrollmentRecord:
    parsed = EnrollmentRecord.model_validate(record)
    if parsed.permitIssuanceStatus == 'pending':
        return parsed.model_copy(update={'enrollmentPermit':None,'permitIssuerSignature':None})
    return parsed


@router.post(
    "/{vault_launcher_id}/session/challenge",
    response_model=OwnerChallengeResponse,
)
def create_vault_session_challenge(
    vault_launcher_id: VaultLauncherPath,
) -> OwnerChallengeResponse:
    settings = _settings()
    return issue_owner_challenge(
        settings,
        vault_launcher_id=vault_launcher_id,
        request=OwnerChallengeRequest(
            action="session_login",
            payload=vault_session_payload(settings),
        ),
    )


@router.post("/{vault_launcher_id}/session", response_model=VaultSessionResponse)
def create_vault_session(
    vault_launcher_id: VaultLauncherPath,
    req: VaultSessionLoginRequest,
    response: Response,
) -> VaultSessionResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    verified_owner = verify_owner_auth(
        settings,
        vault_launcher_id=key,
        action="session_login",
        payload=vault_session_payload(settings),
        owner_auth=req.ownerAuth,
    )
    token, session = issue_vault_session(settings, verified_owner,
        scope='vault' if settings.alpha_writes_enabled else 'relay_recovery')
    response.set_cookie(
        key=VAULT_SESSION_COOKIE,
        value=token,
        max_age=settings.vault_session_ttl_seconds,
        path=settings.vault_session_cookie_path,
        secure=settings.vault_session_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return session


@router.get("/{vault_launcher_id}/session", response_model=VaultSessionResponse)
def get_vault_session(
    vault_launcher_id: VaultLauncherPath,
    request: Request,
) -> VaultSessionResponse:
    from .credential_auth import vault_session_fingerprint
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    session = verify_vault_session(settings, request, key, allow_recovery=True)
    return VaultSessionResponse(
        vaultLauncherId=key,
        authType=session.auth_type,
        network=session.network,
        expiresAt=session.expires_at,
        scope=session.scope,
        sessionFingerprint=vault_session_fingerprint(session.session_id),
    )


@router.post(
    "/{vault_launcher_id}/relay/challenge",
    response_model=OwnerChallengeResponse,
)
def create_bls_relay_challenge(
    vault_launcher_id: VaultLauncherPath,
    req: RelayChallengeRequest,
    request: Request,
) -> OwnerChallengeResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    session = verify_vault_session(settings, request, key)
    if session.auth_type != "chia_bls":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="EVM vaults authorize the proof with a ForwardRequest.",
        )
    enrollment = get_credential_ledger(settings).get_enrollment(key)
    if not enrollment:
        raise HTTPException(status_code=404, detail="Create an enrollment before requesting relay authorization.")
    _require_enrollment_bridge_policy(settings, enrollment, execution=True)
    from .zkpassport_relay import _validate_relay_permit
    try:
        data = Web3.to_bytes(hexstr=req.data)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Relay calldata must be hex.") from exc
    _validate_relay_permit(settings, enrollment, session, data, live=True)
    return issue_owner_challenge(
        settings,
        vault_launcher_id=key,
        request=OwnerChallengeRequest(
            action="relay",
            payload={"data": req.data.lower()},
        ),
    )


def indexed_validator_message(vault_launcher_id: str) -> Optional[str]:
    """Return the indexed validator message for a vault, if a proof exists."""
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = get_credential_ledger(settings).get_enrollment(key)
    if not record:
        return None
    parsed = EnrollmentRecord.model_validate(record)
    return parsed.receipt.validatorMessage if parsed.receipt else None


def indexed_validator_signing_context(
    vault_launcher_id: str,
) -> Optional[tuple[str, str, str]]:
    """Return the AGG_SIG_ME inputs for one indexed vault proof."""
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = get_credential_ledger(settings).get_enrollment(key)
    if not record:
        return None
    parsed = EnrollmentRecord.model_validate(record)
    if parsed.receipt is None or not parsed.receipt.validatorMessage:
        return None
    return (
        parsed.receipt.validatorMessage,
        parsed.bridgeCoinId,
        parsed.network,
    )


@router.post("", response_model=EnrollmentRecord)
async def create_enrollment(
    req: CreateEnrollmentRequest,
    request: Request,
) -> EnrollmentRecord:
    settings = _settings()
    vault_launcher_id = _normalize_hex32(req.vaultLauncherId, "vaultLauncherId")
    verified_owner = verify_vault_session(settings, request, vault_launcher_id)
    policy = _active_bridge_coin_policy(settings)
    if policy.permit_version is not None:
        artifact = _active_genesis_artifact(settings)
        from .enrollment_permit_issuance import reserve_and_issue_permit
        return _public_record(await reserve_and_issue_permit(settings,verified_owner,artifact,policy))
    bridge_policy_hash = policy.policy_hash
    if int(settings.zkpassport_bridge_amount) != 1:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport bridge coins must be configured for exactly one mojo.",
        )
    while True:
        ledger = get_credential_ledger(settings)
        existing = ledger.get_enrollment(vault_launcher_id)
        if existing:
            _require_enrollment_bridge_policy(settings, existing, policy=policy)
            return _public_record(existing)

        bridge_candidates = _bridge_coin_candidates(
            settings, bridge_policy_hash=bridge_policy_hash, policy=policy,
        )
        used_coin_ids = ledger.enrollment_bridge_coin_ids()
        bridge_candidate = next(
            (
                candidate
                for candidate in bridge_candidates
                if candidate.coin_id not in used_coin_ids
            ),
            None,
        )
        if bridge_candidate is not None:
            now = int(time.time())
            record = EnrollmentRecord(
                vaultLauncherId=vault_launcher_id,
                network=settings.network,
                policyVersion=settings.zkpassport_policy_version,
                status="reserved",
                bridgePolicyHash=bridge_policy_hash,
                bridgeParentId=bridge_candidate.parent_id,
                bridgeAmount=bridge_candidate.amount,
                bridgeCoinId=bridge_candidate.coin_id,
                createdAt=now,
                updatedAt=now,
            )
            try:
                stored, _created = ledger.reserve_enrollment(
                    record=record.model_dump(),
                    owner_key=verified_owner.owner_key,
                    max_pending_per_owner=settings.zkpassport_enrollment_max_pending_per_owner,
                )
            except LedgerRateLimited as exc:
                raise HTTPException(status_code=429, detail=str(exc)) from exc
            except LedgerConflict:
                continue
            _require_enrollment_bridge_policy(settings, stored, policy=policy)
            return _public_record(stored)

        detail = (
            "No confirmed signed-policy zkPassport bridge coins are available; contact support."
            if not bridge_candidates
            else "No unreserved signed-policy zkPassport bridge coins remain; contact support."
        )
        raise HTTPException(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
                if not bridge_candidates
                else status.HTTP_409_CONFLICT
            ),
            detail=detail,
        )


@router.get("/{vault_launcher_id}", response_model=EnrollmentRecord)
def get_enrollment(vault_launcher_id: VaultLauncherPath) -> EnrollmentRecord:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = get_credential_ledger(settings).get_enrollment(key)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No zkPassport enrollment receipt is indexed for this vault.",
        )
    parsed = _public_record(record)
    if parsed.status in {"reserved", "evm_confirmed"}:
        _require_enrollment_bridge_policy(settings, record)
    if parsed.status in {"stamp_pending", "receipt_syncing", "chia_confirmed"}:
        return _sync_chia_stamp(settings, key)
    return parsed


@router.post("/{vault_launcher_id}/proof", response_model=EnrollmentRecord)
def record_evm_proof(
    vault_launcher_id: VaultLauncherPath,
    req: RecordProofRequest,
    request: Request,
) -> EnrollmentRecord:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    vault_from_body = _normalize_hex32(req.vaultLauncherId, "vaultLauncherId")
    if vault_from_body != key:
        raise HTTPException(status_code=422, detail="vaultLauncherId does not match URL.")
    verified_owner = verify_vault_session(settings, request, key)

    event = _fetch_verified_evm_attestation(
        settings,
        transaction_hash=req.evmTxHash,
        expected_vault_launcher_id=key,
    )
    if event.identity_attest_root == _EMPTY_ATTEST_ROOT:
        raise HTTPException(status_code=422, detail="identityAttestRoot must be non-empty.")
    if req.attestationProof.bitpath != 0 or req.attestationProof.siblings:
        raise HTTPException(
            status_code=422,
            detail="Alpha policy requires the one-leaf attestation proof.",
        )

    client_commitments = {
        "policyVersion": int(req.policyVersion),
        "identityAttestRoot": _normalize_hex32(
            req.identityAttestRoot,
            "identityAttestRoot",
        ),
        "attestationLeafHash": _normalize_hex32(
            req.attestationLeafHash,
            "attestationLeafHash",
        ),
        "bridgePolicyHash": _normalize_hex32(req.bridgePolicyHash, "bridgePolicyHash"),
        "bridgeParentId": _normalize_hex32(req.bridgeParentId, "bridgeParentId"),
        "bridgeAmount": int(req.bridgeAmount),
        "bridgeCoinId": _normalize_hex32(req.bridgeCoinId, "bridgeCoinId"),
        "bridgeMessage": _normalize_hex32(req.bridgeMessage, "bridgeMessage")
        if req.bridgeMessage
        else None,
        "validatorMessage": _normalize_hex32(req.validatorMessage, "validatorMessage")
        if req.validatorMessage
        else None,
    }
    event_commitments = {
        "policyVersion": event.policy_version,
        "identityAttestRoot": event.identity_attest_root,
        "attestationLeafHash": event.attestation_leaf_hash,
        "bridgePolicyHash": event.bridge_policy_hash,
        "bridgeParentId": event.bridge_parent_id,
        "bridgeAmount": event.bridge_amount,
        "bridgeCoinId": event.bridge_coin_id,
        "bridgeMessage": event.bridge_message,
        "validatorMessage": event.validator_message,
    }
    if client_commitments != event_commitments:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Browser proof fields do not match the indexed EVM attestation event.",
        )

    vault_record = verified_owner.vault_record
    ledger = get_credential_ledger(settings)
    if (
        vault_record.owner_evm_address
        and vault_record.owner_evm_address.lower() != event.sender.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The zkPassport event signer is not the registered EVM vault owner.",
        )
    if not vault_record.owner_evm_address:
        if verified_owner.auth_type != "chia_bls":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The zkPassport event is not bound to a BLS vault session.",
            )
        try:
            ledger.require_submitted_relay(
                transaction_hash=event.transaction_hash,
                vault_launcher_id=key,
                owner_key=verified_owner.owner_key,
                bridge_coin_id=event.bridge_coin_id,
            )
        except LedgerConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    existing = ledger.get_enrollment(key)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Create an enrollment before recording proof.",
        )
    record = EnrollmentRecord.model_validate(existing)
    if record.status != "reserved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This enrollment is not awaiting a new EVM proof.",
        )
    _require_enrollment_bridge_policy(settings, existing, execution=True)
    expected = {
        "bridgePolicyHash": record.bridgePolicyHash,
        "bridgeParentId": record.bridgeParentId,
        "bridgeAmount": record.bridgeAmount,
        "bridgeCoinId": record.bridgeCoinId,
    }
    observed = {
        "bridgePolicyHash": event.bridge_policy_hash,
        "bridgeParentId": event.bridge_parent_id,
        "bridgeAmount": event.bridge_amount,
        "bridgeCoinId": event.bridge_coin_id,
    }
    if observed != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="EVM event bridge fields do not match the reserved enrollment.",
        )

    now = int(time.time())
    receipt = VaultCredentialReceipt(
        vaultLauncherId=key,
        network=record.network,
        policyVersion=event.policy_version,
        identityAttestRoot=event.identity_attest_root,
        attestationLeafHash=event.attestation_leaf_hash,
        attestationProof=AttestationProof(bitpath=0, siblings=[]),
        scopedNullifier=event.scoped_nullifier,
        nullifierType=event.nullifier_type,
        serviceScopeHash=event.service_scope_hash,
        serviceSubscopeHash=event.service_subscope_hash,
        proofTimestamp=event.proof_timestamp,
        bridgePolicyHash=record.bridgePolicyHash,
        bridgeParentId=record.bridgeParentId,
        bridgeAmount=record.bridgeAmount,
        bridgeCoinId=record.bridgeCoinId,
        bridgeMessage=event.bridge_message,
        validatorMessage=event.validator_message,
        evmTxHash=event.transaction_hash,
        evmConfirmedBlockIndex=event.block_number,
        genesisArtifactHash=_active_artifact_hash(settings),
        enrolledAt=now,
    )
    updated = record.model_copy(
        update={"status": "evm_confirmed", "receipt": receipt, "updatedAt": now}
    )
    try:
        ledger.record_evm_event(
            record=updated.model_dump(),
            owner_key=verified_owner.owner_key,
            transaction_hash=event.transaction_hash,
            scoped_nullifier=event.scoped_nullifier,
            bridge_coin_id=event.bridge_coin_id,
            block_number=event.block_number,
        )
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return updated


def _wallet_coin_spend(coin_spend: Any) -> dict[str, Any]:
    """Return the CHIP-0002 shape consumed by Goby and Sage."""
    return {
        "coin": {
            "parentCoinInfo": _hex32(coin_spend.coin.parent_coin_info),
            "puzzleHash": _hex32(coin_spend.coin.puzzle_hash),
            "amount": int(coin_spend.coin.amount),
        },
        "puzzleReveal": "0x" + bytes(coin_spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(coin_spend.solution).hex(),
    }


def _build_bls_chia_stamp(
    settings: Settings,
    *,
    key: str,
    record: EnrollmentRecord,
    event: IndexedEvmAttestation,
    vault_coin: Coin,
    current_timestamp: int,
    signer_indices: tuple[int, ...] = (0, 1),
) -> tuple[Any, Coin, bytes]:
    """Build the exact BLS vault spend and both AGG_SIG_ME messages.

    The browser receives only the vault coin spend. The API rebuilds it from
    canonical state during submission and verifies the returned owner
    signature before aggregating the independently produced validator
    signature.
    """
    if record.receipt is None:
        raise HTTPException(status_code=409, detail="No EVM proof receipt to stamp.")
    active_pool_launcher_id = _active_pool_launcher_id(settings)

    from solslot_puzzles.vault_driver import (
        AUTH_TYPE_BLS,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        one_leaf_merkle_root,
        puzzle_for_vault_full,
    )
    from solslot_puzzles.zkpassport_bridge_driver import (
        build_bridge_and_vault_update_identity_bundle,
    )

    launcher = bytes32.fromhex(key.removeprefix("0x"))
    vault_record = get_registry().get(launcher)
    if vault_record is None or vault_record.auth_type != AUTH_TYPE_BLS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The registered vault is not a Chia BLS vault.",
        )
    owner_pubkey = bytes(vault_record.owner_pubkey)
    try:
        G1Element.from_bytes(owner_pubkey)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The registered BLS vault owner key is invalid.",
        ) from exc

    pool_launcher_id = bytes32.fromhex(active_pool_launcher_id.removeprefix("0x"))
    bridge_policy_hash = bytes32.fromhex(record.bridgePolicyHash.removeprefix("0x"))
    members_root = one_leaf_merkle_root(owner_pubkey)
    current_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_BLS,
        members_root,
        pool_launcher_id,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if bytes32(current_puzzle.get_tree_hash()) != vault_coin.puzzle_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The current Chia coin does not match the registered BLS vault.",
        )

    try:
        validator_pubkeys = configured_validator_pubkeys(settings)
        configured_policy_hash = configured_bridge_policy_hash(settings)
    except ValidatorQuorumError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if configured_policy_hash != record.bridgePolicyHash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The configured validator quorum does not match the vault bridge policy.",
        )

    try:
        built = build_bridge_and_vault_update_identity_bundle(
            enrollment_permit=_record_permit(settings, record.model_dump(), now=int(time.time())),
            bridge_parent_id=bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
            bridge_amount=record.bridgeAmount,
            validator_pubkeys=validator_pubkeys,
            threshold=settings.zkpassport_validator_threshold,
            signer_indices=signer_indices,
            vault_coin=vault_coin,
            vault_launcher_id=launcher,
            owner_pubkey_bytes=owner_pubkey,
            auth_type=AUTH_TYPE_BLS,
            members_merkle_root=members_root,
            pool_launcher_id=pool_launcher_id,
            new_identity_attest_root=bytes32.fromhex(
                record.receipt.identityAttestRoot.removeprefix("0x")
            ),
            attestation_leaf_hash=bytes32.fromhex(
                record.receipt.attestationLeafHash.removeprefix("0x")
            ),
            scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
            nullifier_type=event.nullifier_type,
            service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
            service_subscope_hash=bytes32.fromhex(
                event.service_subscope_hash.removeprefix("0x")
            ),
            proof_timestamp=event.proof_timestamp,
            current_timestamp=current_timestamp,
            lineage_proof=_initial_vault_lineage(settings, vault_coin, launcher),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The Chia BLS identity stamp could not be built: {exc}",
        ) from exc
    if _hex32(built.bridge.validator_message) != event.validator_message:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Chia bridge validator message does not match the EVM event.",
        )

    identity_root = bytes32.fromhex(record.receipt.identityAttestRoot.removeprefix("0x"))
    expected_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_BLS,
        members_root,
        pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    expected_vault_coin = Coin(
        vault_coin.name(),
        bytes32(expected_puzzle.get_tree_hash()),
        uint64(1),
    )
    owner_inner_message = bytes(
        Program.to([b"z", identity_root, vault_coin.name()]).get_tree_hash()
    )
    owner_message = (
        owner_inner_message
        + bytes(vault_coin.name())
        + AGG_SIG_ME_DATA[settings.network]
    )
    return built, expected_vault_coin, owner_message


def _freeze_stamp_attempt(settings: Settings, claim: ValidatorClaim, expected_vault_coin: Coin) -> None:
    try:
        get_credential_ledger(settings).reserve_stamp_attempt(
            claim=claim.model_dump(mode="json"), expected_coin=expected_vault_coin.to_json_dict(),
        )
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


async def _push_chia_stamp_and_mark_pending(
    settings: Settings,
    *,
    coinset: ChiaProvider,
    key: str,
    spend_bundle: SpendBundle,
    expected_vault_coin: Coin,
) -> SubmitChiaStampResponse:
    spend_bundle_id = _hex32(spend_bundle.name())
    expected_vault_coin_id = _hex32(expected_vault_coin.name())
    ledger = get_credential_ledger(settings)
    try:
        # FULL synchronous SQLite commit precedes any provider call. Ambiguous
        # sends retain exact bytes, claim, input locks and the expected output.
        pending = EnrollmentRecord.model_validate(ledger.persist_stamp_bundle(
            vault_launcher_id=key, bundle_hex=bytes(spend_bundle).hex(),
        ))
        if pending.receipt is None or pending.receipt.chiaVaultCoinId != expected_vault_coin_id:
            raise LedgerConflict("Stamp successor differs from retained authorization.")
        ledger.record_stamp_dispatch(key, spend_bundle_id, "unknown")
    except (ValueError, LedgerConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        push_result = await coinset.push_tx(spend_bundle.to_json_dict())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502,
            detail="Stamp submission is uncertain. Its signed bundle and receipt IDs are retained; check status before retrying.") from exc
    push_status = str(push_result.get("status") or "").upper()
    if not push_result.get("success") and push_status not in {"SUCCESS", "PENDING"}:
        ledger.record_stamp_dispatch(key, spend_bundle_id, "rejected")
        raise HTTPException(status_code=502,
            detail="The Chia provider rejected the retained stamp. Check status before retrying the same bundle.")
    ledger.record_stamp_dispatch(key, spend_bundle_id, "submitted")
    return SubmitChiaStampResponse(enrollment=pending, spendBundleId=spend_bundle_id,
        expectedVaultCoinId=expected_vault_coin_id)


@router.post("/{vault_launcher_id}/stamp/prepare", response_model=PrepareChiaStampResponse)
def prepare_chia_stamp(
    vault_launcher_id: VaultLauncherPath,
    request: Request,
) -> PrepareChiaStampResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    session = verify_vault_session(settings, request, key)
    existing = get_credential_ledger(settings).get_enrollment(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    record = EnrollmentRecord.model_validate(existing)
    _require_enrollment_bridge_policy(settings, existing, execution=True)
    if record.status == "chia_confirmed":
        raise HTTPException(status_code=409, detail="This vault is already stamped on Chia.")
    if record.status == "stamp_pending":
        raise HTTPException(status_code=409, detail="The Chia vault stamp is already pending.")
    if record.status != "evm_confirmed" or record.receipt is None:
        raise HTTPException(
            status_code=409,
            detail="A confirmed EVM zkPassport event is required before stamping the vault.",
        )

    vault_coin = _find_initial_vault_coin(settings, key)
    _record_permit(settings, existing, owner_auth_type=session.vault_record.auth_type,
        owner_key=session.owner_key, current_vault_coin_id=_hex32(vault_coin.name()), now=int(time.time()))
    vault_record = get_registry().get(bytes32.fromhex(key.removeprefix("0x")))
    auth_type = "chia_bls" if vault_record and vault_record.auth_type == 1 else "evm"
    typed_data: Optional[dict[str, Any]] = None
    current_timestamp: Optional[int] = None
    vault_coin_spend: Optional[dict[str, Any]] = None
    if auth_type == "evm":
        from solslot_puzzles.vault_driver import eip712_typed_data_for_vault_spend

        typed_data = eip712_typed_data_for_vault_spend(
            b"z",
            bytes32.fromhex(record.receipt.identityAttestRoot.removeprefix("0x")),
            vault_coin.name(),
        )
    else:
        event = _fetch_verified_evm_attestation(
            settings,
            transaction_hash=record.receipt.evmTxHash,
            expected_vault_launcher_id=key,
        )
        _verify_reserved_bridge_coin(settings, record)
        attempt = get_credential_ledger(settings).get_stamp_attempt(key)
        current_timestamp = json.loads(attempt["claim_json"])["current_timestamp"] if attempt else int(time.time())
        if abs(int(time.time()) - current_timestamp) > 90:
            raise HTTPException(status_code=409,
                detail="The retained stamp submission window expired. Check the existing attempt before recovery.")
        built, _, _ = _build_bls_chia_stamp(
            settings,
            key=key,
            record=record,
            event=event,
            vault_coin=vault_coin,
            current_timestamp=current_timestamp,
        )
        vault_coin_spend = _wallet_coin_spend(built.vault_spend)
    return PrepareChiaStampResponse(
        vaultLauncherId=key,
        authType=auth_type,
        currentVaultCoinId=_hex32(vault_coin.name()),
        identityAttestRoot=record.receipt.identityAttestRoot,
        typedData=typed_data,
        currentTimestamp=current_timestamp,
        vaultCoinSpend=vault_coin_spend,
    )


@router.post("/{vault_launcher_id}/stamp/submit", response_model=SubmitChiaStampResponse)
async def submit_evm_chia_stamp(
    vault_launcher_id: VaultLauncherPath,
    req: SubmitChiaStampRequest,
    request: Request,
) -> SubmitChiaStampResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    verified_owner = verify_vault_session(settings, request, key)
    existing = get_credential_ledger(settings).get_enrollment(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    record = EnrollmentRecord.model_validate(existing)
    _require_enrollment_bridge_policy(settings, existing, execution=True)
    attempt = get_credential_ledger(settings).get_stamp_attempt(key)
    retained_claim = json.loads(attempt["claim_json"]) if attempt else None
    if retained_claim:
        req = SubmitChiaStampRequest(signature=retained_claim["owner_authorization"],
            currentTimestamp=retained_claim["current_timestamp"])
    if record.status == "stamp_pending" and record.receipt:
        if record.receipt.chiaSpendBundleId and record.receipt.chiaVaultCoinId:
            if attempt and attempt["bundle_hex"]:
                if abs(int(time.time()) - retained_claim["current_timestamp"]) > 90:
                    raise HTTPException(status_code=409,
                        detail="The retained stamp submission window has passed. Check its existing receipt; authorization will not be renewed.")
                # Exact bytes protect against replacement, not against a reorg
                # or a changed release. Revalidate their original authorization
                # without collecting another quorum or refreshing the clock.
                event = _fetch_verified_evm_attestation(settings,
                    transaction_hash=record.receipt.evmTxHash, expected_vault_launcher_id=key)
                vault_coin = _find_initial_vault_coin(settings, key)
                _verify_reserved_bridge_coin(settings, record)
                fresh_claim = _validator_claim(settings, key=key, record=record, event=event,
                    vault_coin=vault_coin, vault_record=verified_owner.vault_record,
                    owner_key=verified_owner.owner_key, owner_authorization=retained_claim["owner_authorization"],
                    current_timestamp=retained_claim["current_timestamp"])
                if (fresh_claim.model_dump(mode="json") != retained_claim
                        or fresh_claim.canonical_hash() != attempt["claim_hash"]
                        or (verified_owner.vault_record.owner_evm_address
                            and event.sender.lower() != verified_owner.vault_record.owner_evm_address.lower())):
                    raise HTTPException(status_code=409,
                        detail="The retained stamp no longer matches its original owner, EVM event or release. Reconcile the existing receipt.")
                return await _push_chia_stamp_and_mark_pending(settings,
                    coinset=request.app.state.coinset, key=key,
                    spend_bundle=SpendBundle.from_bytes(bytes.fromhex(attempt["bundle_hex"])),
                    expected_vault_coin=Coin.from_json_dict(json.loads(attempt["expected_coin_json"])))
            return SubmitChiaStampResponse(
                enrollment=record,
                spendBundleId=record.receipt.chiaSpendBundleId,
                expectedVaultCoinId=record.receipt.chiaVaultCoinId,
            )
    if record.status != "evm_confirmed" or record.receipt is None:
        raise HTTPException(
            status_code=409,
            detail="A confirmed EVM zkPassport event is required before stamping the vault.",
        )
    active_pool_launcher_id = _active_pool_launcher_id(settings)

    event = _fetch_verified_evm_attestation(
        settings,
        transaction_hash=record.receipt.evmTxHash,
        expected_vault_launcher_id=key,
    )
    if (
        event.identity_attest_root != record.receipt.identityAttestRoot
        or event.validator_message != record.receipt.validatorMessage
        or event.bridge_coin_id != record.bridgeCoinId
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The indexed receipt no longer matches the canonical EVM event.",
        )

    vault_coin = _find_initial_vault_coin(settings, key)
    _verify_reserved_bridge_coin(settings, record)

    launcher = bytes32.fromhex(key.removeprefix("0x"))
    vault_record = verified_owner.vault_record
    if vault_record.auth_type == AUTH_TYPE_BLS:
        if req.currentTimestamp is None:
            raise HTTPException(
                status_code=422,
                detail="currentTimestamp is required for a Chia BLS vault stamp.",
            )
        if abs(int(time.time()) - req.currentTimestamp) > 90:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The BLS stamp submission window expired. Check the existing attempt; retained authorization cannot be renewed.",
            )
        built, expected_vault_coin, owner_message = (
            _build_bls_chia_stamp(
                settings,
                key=key,
                record=record,
                event=event,
                vault_coin=vault_coin,
                current_timestamp=req.currentTimestamp,
            )
        )
        try:
            owner_signature_bytes = bytes.fromhex(req.signature.removeprefix("0x"))
            if len(owner_signature_bytes) != 96:
                raise ValueError("BLS vault stamp signature must be 96 bytes.")
            owner_signature = G2Element.from_bytes(owner_signature_bytes)
            owner_public_key = G1Element.from_bytes(bytes(vault_record.owner_pubkey))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not AugSchemeMPL.verify(owner_public_key, owner_message, owner_signature):
            raise HTTPException(
                status_code=400,
                detail="The BLS owner signature does not authorize this exact vault stamp.",
            )
        claim = _validator_claim(
            settings,
            key=key,
            record=record,
            event=event,
            vault_coin=vault_coin,
            vault_record=vault_record,
            owner_key=verified_owner.owner_key,
            owner_authorization=req.signature,
            current_timestamp=req.currentTimestamp,
        )
        _freeze_stamp_attempt(settings, claim, expected_vault_coin)
        try:
            quorum = await collect_validator_quorum(settings, claim)
        except ValidatorQuorumError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if quorum.signer_indices != (0, 1):
            built, expected_vault_coin, owner_message = _build_bls_chia_stamp(
                settings,
                key=key,
                record=record,
                event=event,
                vault_coin=vault_coin,
                current_timestamp=req.currentTimestamp,
                signer_indices=quorum.signer_indices,
            )
        spend_bundle = SpendBundle(
            list(built.spend_bundle.coin_spends),
            AugSchemeMPL.aggregate([owner_signature, quorum.aggregated_signature]),
        )
        return await _push_chia_stamp_and_mark_pending(
            settings,
            coinset=request.app.state.coinset,
            key=key,
            spend_bundle=spend_bundle,
            expected_vault_coin=expected_vault_coin,
        )

    from solslot_puzzles.vault_driver import (
        AUTH_TYPE_SECP256K1,
        DEFAULT_IDENTITY_ATTEST_ROOT,
        compact_signature_from_evm,
        eip712_typed_data_for_vault_spend,
        one_leaf_merkle_root,
        puzzle_for_vault_full,
    )
    from solslot_puzzles.zkpassport_bridge_driver import (
        build_bridge_and_vault_update_identity_bundle,
    )

    identity_root = bytes32.fromhex(record.receipt.identityAttestRoot.removeprefix("0x"))
    typed_data = eip712_typed_data_for_vault_spend(
        b"z",
        identity_root,
        vault_coin.name(),
    )
    try:
        recovery = recover_evm_signer(typed_data, req.signature)
        compact_signature = compact_signature_from_evm(req.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not vault_record.owner_evm_address or (
        recovery.address.lower() != vault_record.owner_evm_address.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The vault stamp signature is not from the registered vault owner.",
        )

    pool_launcher_id = bytes32.fromhex(active_pool_launcher_id.removeprefix("0x"))
    bridge_policy_hash = bytes32.fromhex(record.bridgePolicyHash.removeprefix("0x"))
    members_root = one_leaf_merkle_root(recovery.compressed_pubkey)
    current_puzzle = puzzle_for_vault_full(
        launcher,
        recovery.compressed_pubkey,
        AUTH_TYPE_SECP256K1,
        members_root,
        pool_launcher_id,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if bytes32(current_puzzle.get_tree_hash()) != vault_coin.puzzle_hash:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The owner signature does not reconstruct the current unstamped Chia vault coin. "
                "Reconnect the wallet that created this vault."
            ),
        )

    if (
        vault_record.auth_type != AUTH_TYPE_SECP256K1
        or bytes(vault_record.owner_pubkey) != recovery.compressed_pubkey
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The vault stamp signature conflicts with registered vault ownership.",
        )

    try:
        validator_pubkeys = configured_validator_pubkeys(settings)
        configured_policy_hash = configured_bridge_policy_hash(settings)
    except ValidatorQuorumError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if configured_policy_hash != record.bridgePolicyHash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The configured validator quorum does not match the vault bridge policy.",
        )

    current_timestamp = retained_claim["current_timestamp"] if retained_claim else int(time.time())
    if abs(int(time.time()) - current_timestamp) > 90:
        raise HTTPException(status_code=409,
            detail="The retained stamp submission window expired. Check the existing attempt before recovery.")
    try:
        built = build_bridge_and_vault_update_identity_bundle(
            enrollment_permit=_record_permit(settings, record.model_dump(), now=int(time.time())),
            bridge_parent_id=bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
            bridge_amount=record.bridgeAmount,
            validator_pubkeys=validator_pubkeys,
            threshold=settings.zkpassport_validator_threshold,
            signer_indices=[0, 1],
            vault_coin=vault_coin,
            vault_launcher_id=launcher,
            owner_pubkey_bytes=recovery.compressed_pubkey,
            auth_type=AUTH_TYPE_SECP256K1,
            members_merkle_root=members_root,
            pool_launcher_id=pool_launcher_id,
            new_identity_attest_root=identity_root,
            attestation_leaf_hash=bytes32.fromhex(
                record.receipt.attestationLeafHash.removeprefix("0x")
            ),
            scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
            nullifier_type=event.nullifier_type,
            service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
            service_subscope_hash=bytes32.fromhex(
                event.service_subscope_hash.removeprefix("0x")
            ),
            proof_timestamp=event.proof_timestamp,
            current_timestamp=current_timestamp,
            lineage_proof=_initial_vault_lineage(settings, vault_coin, launcher),
            signature_data=compact_signature,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The Chia identity stamp could not be built: {exc}",
        ) from exc
    if _hex32(built.bridge.validator_message) != event.validator_message:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Chia bridge validator message does not match the EVM event.",
        )

    expected_puzzle = puzzle_for_vault_full(
        launcher,
        recovery.compressed_pubkey,
        AUTH_TYPE_SECP256K1,
        members_root,
        pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    expected_vault_coin = Coin(
        vault_coin.name(),
        bytes32(expected_puzzle.get_tree_hash()),
        uint64(1),
    )
    claim = _validator_claim(
        settings,
        key=key,
        record=record,
        event=event,
        vault_coin=vault_coin,
        vault_record=vault_record,
        owner_key=verified_owner.owner_key,
        owner_authorization=req.signature,
        current_timestamp=current_timestamp,
    )
    _freeze_stamp_attempt(settings, claim, expected_vault_coin)
    try:
        quorum = await collect_validator_quorum(settings, claim)
    except ValidatorQuorumError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if quorum.signer_indices != (0, 1):
        try:
            built = build_bridge_and_vault_update_identity_bundle(
                enrollment_permit=_record_permit(settings, record.model_dump(), now=int(time.time())),
                bridge_parent_id=bytes32.fromhex(record.bridgeParentId.removeprefix("0x")),
                bridge_amount=record.bridgeAmount,
                validator_pubkeys=validator_pubkeys,
                threshold=settings.zkpassport_validator_threshold,
                signer_indices=quorum.signer_indices,
                vault_coin=vault_coin,
                vault_launcher_id=launcher,
                owner_pubkey_bytes=recovery.compressed_pubkey,
                auth_type=AUTH_TYPE_SECP256K1,
                members_merkle_root=members_root,
                pool_launcher_id=pool_launcher_id,
                new_identity_attest_root=identity_root,
                attestation_leaf_hash=bytes32.fromhex(
                    record.receipt.attestationLeafHash.removeprefix("0x")
                ),
                scoped_nullifier=bytes32.fromhex(event.scoped_nullifier.removeprefix("0x")),
                nullifier_type=event.nullifier_type,
                service_scope_hash=bytes32.fromhex(event.service_scope_hash.removeprefix("0x")),
                service_subscope_hash=bytes32.fromhex(
                    event.service_subscope_hash.removeprefix("0x")
                ),
                proof_timestamp=event.proof_timestamp,
                current_timestamp=current_timestamp,
                lineage_proof=_initial_vault_lineage(settings, vault_coin, launcher),
                signature_data=compact_signature,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail=f"The Chia identity stamp could not be rebuilt: {exc}",
            ) from exc
    spend_bundle = SpendBundle(
        list(built.spend_bundle.coin_spends),
        quorum.aggregated_signature,
    )
    return await _push_chia_stamp_and_mark_pending(
        settings,
        coinset=request.app.state.coinset,
        key=key,
        spend_bundle=spend_bundle,
        expected_vault_coin=expected_vault_coin,
    )


@router.post("/{vault_launcher_id}/stamp/sync", response_model=SyncChiaStampResponse)
def sync_chia_stamp(
    vault_launcher_id: VaultLauncherPath,
    request: Request,
) -> SyncChiaStampResponse:
    settings = _settings()
    key = _normalize_hex32(vault_launcher_id, "vaultLauncherId")
    verify_vault_session(settings, request, key)
    enrollment = _sync_chia_stamp(settings, key)
    return SyncChiaStampResponse(
        enrollment=enrollment,
        confirmed=enrollment.status == "chia_confirmed",
    )


@router.post("/{vault_launcher_id}/chia-confirmation", include_in_schema=False)
def reject_client_chia_confirmation(
    vault_launcher_id: VaultLauncherPath,
) -> None:
    del vault_launcher_id
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail=(
            "Client-supplied Chia confirmations are retired. The server indexes "
            "the current stamped singleton coin directly from Chia."
        ),
    )
