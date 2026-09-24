"""Administrator recovery coordination for Admin Authority V3.

The API stores public recovery commitments and signed coordination evidence
only. Authority remains on the Chia singleton and the configured Safe
hierarchy; this module never receives or reconstructs recovery secrets.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Mapping, Optional

from clvm.casts import int_to_bytes
from chia_rs import AugSchemeMPL, G1Element, G2Element
from eth_utils import keccak
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .admin_auth import require_admin_jwt
from .authority_network import authority_chain_id, authority_network_name, ceremony_authority_document
from .admin_roster import (
    artifact_ceremony_id,
    current_artifact_admins,
)
from .admin_authority_v3 import build_admin_authority_v3_snapshot
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .genesis import get_genesis_store
from .genesis_store import (
    GenesisConflict,
    GenesisExpired,
    GenesisNotFound,
    GenesisStore,
    GenesisStoreError,
)
from .launch_control import LAUNCH_COOKIE_NAME, require_launch_session
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)


router = APIRouter(prefix="/admin/security", tags=["admin-security"])

AUTHORITY_EVM_CHAIN_ID = 84_532
DRILL_TTL_SECONDS = 15 * 60
RECOVERY_BLS_PATH = "m/12381/8444/2/0-unhardened"
RECOVERY_EVM_PATH = "m/44'/60'/0'/0/0"
HEX32_LENGTH = 64
BLS_PUBLIC_KEY_LENGTH = 96
BLS_SIGNATURE_LENGTH = 192


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class RecoveryDrillPrepareRequest(ApiModel):
    evm_guardian: str = Field(alias="evmGuardian")
    recovery_bls_pubkey: str = Field(alias="recoveryBlsPubkey")

    @field_validator("recovery_bls_pubkey")
    @classmethod
    def validate_bls_public_key(cls, value: str) -> str:
        return _hex_value(
            value,
            BLS_PUBLIC_KEY_LENGTH,
            "recoveryBlsPubkey",
        )


class RecoveryBackupEvidence(ApiModel):
    status: Literal["NOT_CONFIGURED", "VERIFIED"] = "NOT_CONFIGURED"
    revision: Optional[int] = Field(None, ge=1)
    ciphertext_hash: Optional[str] = Field(None, alias="ciphertextHash")

    @field_validator("ciphertext_hash")
    @classmethod
    def validate_ciphertext_hash(cls, value: str | None) -> str | None:
        return (
            _hex_value(value, HEX32_LENGTH, "backup.ciphertextHash")
            if value is not None
            else None
        )


class RecoveryDrillCompleteRequest(ApiModel):
    challenge_id: str = Field(alias="challengeId", min_length=66, max_length=66)
    evm_signature: str = Field(alias="evmSignature")
    bls_signature: str = Field(alias="blsSignature")
    offline_copy_confirmed: bool = Field(alias="offlineCopyConfirmed")
    second_device_confirmed: bool = Field(alias="secondDeviceConfirmed")
    backup: RecoveryBackupEvidence = Field(
        default_factory=RecoveryBackupEvidence
    )

    @field_validator("challenge_id")
    @classmethod
    def validate_challenge_id(cls, value: str) -> str:
        return _hex_value(value, HEX32_LENGTH, "challengeId")

    @field_validator("bls_signature")
    @classmethod
    def validate_bls_signature(cls, value: str) -> str:
        return _hex_value(value, BLS_SIGNATURE_LENGTH, "blsSignature")


class RecoveryDrillChallenge(ApiModel):
    challenge_id: str = Field(alias="challengeId")
    challenge_hash: str = Field(alias="challengeHash")
    expires_at: int = Field(alias="expiresAt")
    revision: int
    evm_typed_data: dict[str, Any] = Field(alias="evmTypedData")
    bls_signing_digest: str = Field(alias="blsSigningDigest")
    recovery_bls_path: str = Field(
        RECOVERY_BLS_PATH,
        alias="recoveryBlsPath",
    )
    recovery_evm_path: str = Field(
        RECOVERY_EVM_PATH,
        alias="recoveryEvmPath",
    )


@dataclass(frozen=True)
class SecurityActor:
    ceremony_id: str
    ceremony_slot: int
    authority_slot: int
    wallet: str
    source: Literal["launch_session", "admin_jwt"]


def _hex_value(value: str, length: int, label: str) -> str:
    normalized = str(value or "").lower()
    if not normalized.startswith("0x") or len(normalized) != length + 2:
        raise ValueError(f"{label} must be 0x-prefixed hex")
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ValueError(f"{label} must be valid hex") from exc
    if not any(raw):
        raise ValueError(f"{label} cannot be zero")
    return normalized


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def require_security_actor(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> SecurityActor:
    if request.cookies.get(LAUNCH_COOKIE_NAME):
        session = require_launch_session(request, settings, store)
        if session.setup or not session.wallet:
            raise HTTPException(
                status_code=401,
                detail="Finish administrator wallet enrollment first.",
            )
        return SecurityActor(
            ceremony_id=session.ceremony_id,
            ceremony_slot=session.slot,
            authority_slot=session.slot - 1,
            wallet=session.wallet.lower(),
            source="launch_session",
        )

    claims = require_admin_jwt(settings, authorization)
    try:
        artifact = load_signed_public_artifact(settings)
        administrators = current_artifact_admins(artifact, store)
        subject = claims.sub.lower()
        authority_slot = next(
            slot
            for slot, (address, compressed) in enumerate(administrators)
            if subject in {address, compressed}
        )
        ceremony_id = artifact_ceremony_id(artifact)
        store.get(ceremony_id)
    except StopIteration as exc:
        raise HTTPException(
            status_code=403,
            detail="Administrator session is not in the Authority V3 roster.",
        ) from exc
    except (GenesisStoreError, PublicArtifactError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Authority V3 evidence is unavailable.",
        ) from exc
    return SecurityActor(
        ceremony_id=ceremony_id,
        ceremony_slot=authority_slot + 1,
        authority_slot=authority_slot,
        wallet=administrators[authority_slot][0],
        source="admin_jwt",
    )


def _drill_payload(
    *,
    actor: SecurityActor,
    guardian: str,
    recovery_bls_pubkey: str,
    revision: int,
    nonce: str,
    expires_at: int,
    evm_chain_id: int = AUTHORITY_EVM_CHAIN_ID,
) -> dict[str, Any]:
    authority_network_name(evm_chain_id)
    commitment = "0x" + keccak(
        bytes.fromhex(recovery_bls_pubkey[2:])
    ).hex()
    return {
        "schemaVersion": 2 if evm_chain_id == 8453 else 1,
        **({"evmChainId": evm_chain_id} if evm_chain_id == 8453 else {}),
        "purpose": "Solslot administrator recovery drill",
        "ceremonyId": actor.ceremony_id,
        "slot": actor.authority_slot,
        "dailyWallet": actor.wallet,
        "evmGuardian": guardian,
        "recoveryBlsPubkey": recovery_bls_pubkey,
        "recoveryBlsCommitment": commitment,
        "revision": revision,
        "nonce": nonce,
        "expiresAt": expires_at,
        "recoveryBlsPath": RECOVERY_BLS_PATH,
        "recoveryEvmPath": RECOVERY_EVM_PATH,
    }


def _drill_chain(payload: Mapping[str, Any]) -> int:
    if payload.get("schemaVersion") == 1 and "evmChainId" not in payload:
        return AUTHORITY_EVM_CHAIN_ID
    if payload.get("schemaVersion") == 2 and type(payload.get("evmChainId")) is int and payload["evmChainId"] == 8453:
        return 8453
    raise ValueError("unsupported recovery drill network profile")


def _drill_typed_data(payload: Mapping[str, Any]) -> dict[str, Any]:
    chain = _drill_chain(payload)
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolslotAdminRecoveryDrill": [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "slot", "type": "uint8"},
                {"name": "dailyWallet", "type": "address"},
                {"name": "evmGuardian", "type": "address"},
                {"name": "recoveryBlsCommitment", "type": "bytes32"},
                {"name": "revision", "type": "uint64"},
                {"name": "nonce", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint64"},
            ],
        },
        "primaryType": "SolslotAdminRecoveryDrill",
        "domain": {
            "name": "Solslot Admin Recovery",
            "version": str(payload["schemaVersion"]),
            "chainId": chain,
        },
        "message": {
            key: payload[key]
            for key in (
                "ceremonyId",
                "slot",
                "dailyWallet",
                "evmGuardian",
                "recoveryBlsCommitment",
                "revision",
                "nonce",
                "expiresAt",
            )
        },
    }


def _drill_bls_digest(payload: Mapping[str, Any]) -> bytes:
    chain = _drill_chain(payload)
    def atom_hash(value: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + value).digest()

    def pair_hash(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x02" + left + right).digest()

    def proper_list_hash(values: list[bytes]) -> bytes:
        result = atom_hash(b"")
        for value in reversed(values):
            result = pair_hash(atom_hash(value), result)
        return result

    message = proper_list_hash(
        [
            b"SolslotAdminRecoveryDrill",
            int_to_bytes(payload["schemaVersion"]),
            *([int_to_bytes(chain)] if payload["schemaVersion"] == 2 else []),
            bytes.fromhex(str(payload["ceremonyId"])[2:]),
            int_to_bytes(int(payload["slot"])),
            bytes.fromhex(str(payload["recoveryBlsCommitment"])[2:]),
            int_to_bytes(int(payload["revision"])),
            bytes.fromhex(str(payload["nonce"])[2:]),
            int_to_bytes(int(payload["expiresAt"])),
        ]
    )
    return pair_hash(atom_hash(b"Chia Signed Message"), atom_hash(message))


def _assert_recovery_identity_is_unique(
    store: GenesisStore,
    actor: SecurityActor,
    guardian: str,
) -> None:
    ceremony = store.get(actor.ceremony_id)
    daily_wallets = {
        str(item["wallet_address"]).lower()
        for item in ceremony["invitations"]
        if item.get("wallet_address")
    }
    daily_wallets.add(actor.wallet.lower())
    for case in store.recovery_cases(actor.ceremony_id):
        if case["state"] != "COMPLETED" or case["kind"] == "RECOVERY_KIT":
            continue
        intent = case.get("intent")
        if isinstance(intent, Mapping) and intent.get("newDailyEvmKey"):
            daily_wallets.add(str(intent["newDailyEvmKey"]).lower())
    if guardian.lower() in daily_wallets:
        raise HTTPException(
            status_code=409,
            detail="Recovery wallet must be separate from every daily wallet.",
        )
    for kit in store.recovery_kits(actor.ceremony_id):
        if (
            int(kit["slot"]) != actor.authority_slot
            and str(kit["evmGuardian"]).lower() == guardian.lower()
        ):
            raise HTTPException(
                status_code=409,
                detail="Each administrator needs a distinct recovery wallet.",
            )
    for slot in (1, 2, 3):
        candidate = store.pending_recovery_kit_candidate(
            actor.ceremony_id,
            slot,
        )
        if (
            candidate is not None
            and int(candidate["slot"]) != actor.authority_slot
            and str(candidate["evmGuardian"]).lower() == guardian.lower()
        ):
            raise HTTPException(
                status_code=409,
                detail="Each administrator needs a distinct recovery wallet.",
            )


@router.get("/status")
async def security_status(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    kits = store.recovery_kits(actor.ceremony_id)
    cases = store.recovery_cases(actor.ceremony_id)
    authority: dict[str, Any] | None = None
    authority_error: str | None = None
    try:
        artifact = load_signed_public_artifact(settings)
        provider = getattr(request.app.state, "coinset", None)
        authority = (
            await build_admin_authority_v3_snapshot(
                artifact=artifact,
                provider=provider,
            )
        ).to_wire()
    except PublicArtifactMissing:
        authority_error = "Authority V3 will become chain-verifiable after genesis."
    except (PublicArtifactError, ValueError):
        authority_error = "Authority V3 evidence failed verification."
    active_case = next(
        (
            item
            for item in cases
            if item["state"] not in {"COMPLETED", "CANCELLED", "FAILED"}
        ),
        None,
    )
    return {
        "schemaVersion": 1,
        "actor": {
            "ceremonyId": actor.ceremony_id,
            "slot": actor.authority_slot,
            "role": "Owner" if actor.authority_slot == 0 else "Coadministrator",
            "wallet": actor.wallet,
        },
        "authorityRule": "owner_plus_one",
        "authority": authority,
        "authorityNotice": authority_error,
        "recoveryKits": kits,
        "recoveryReady": len(kits) == 3,
        "myRecoveryKit": next(
            (
                kit
                for kit in kits
                if int(kit["slot"]) == actor.authority_slot
            ),
            None,
        ),
        "pendingRecoveryKit": store.pending_recovery_kit_candidate(
            actor.ceremony_id,
            actor.ceremony_slot,
        ),
        "activeRecovery": active_case,
        "operationsFrozen": bool(
            active_case or (authority and authority.get("pending"))
        ),
        "recoveryPolicy": {
            "routineDelaySeconds": 86_400,
            "lostKeyDelaySeconds": 604_800,
            "oldKeyVeto": True,
            "replacementAcceptanceRequired": True,
            "totalLossBypass": False,
        },
    }


@router.post("/recovery-kit/drill", response_model=RecoveryDrillChallenge)
async def prepare_recovery_drill(
    body: RecoveryDrillPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> RecoveryDrillChallenge:
    try:
        guardian = normalize_evm_address(
            body.evm_guardian,
            "evmGuardian",
        )
        _assert_recovery_identity_is_unique(store, actor, guardian)
        record = store.get(actor.ceremony_id)
        existing = next(
            (
                item
                for item in store.recovery_kits(actor.ceremony_id)
                if int(item["slot"]) == actor.authority_slot
            ),
            None,
        )
        if (
            existing is not None
            and store.pending_recovery_kit_candidate(
                actor.ceremony_id,
                actor.ceremony_slot,
            )
            is not None
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "A tested replacement recovery kit is already waiting "
                    "for on-chain approval."
                ),
            )
        revision = int(existing["revision"]) + 1 if existing else 1
        expires_at = int(time.time()) + DRILL_TTL_SECONDS
        nonce = "0x" + secrets.token_hex(32)
        challenge_id = "0x" + secrets.token_hex(32)
        payload = _drill_payload(
            actor=actor,
            guardian=guardian,
            recovery_bls_pubkey=body.recovery_bls_pubkey,
            revision=revision,
            nonce=nonce,
            expires_at=expires_at,
            evm_chain_id=authority_chain_id(ceremony_authority_document(record)),
        )
        challenge_hash = _canonical_hash(payload)
        store.create_recovery_drill(
            actor.ceremony_id,
            challenge_id=challenge_id,
            slot=actor.ceremony_slot,
            challenge_hash=challenge_hash,
            public_payload=payload,
            expires_at=expires_at,
        )
        return RecoveryDrillChallenge(
            challengeId=challenge_id,
            challengeHash=challenge_hash,
            expiresAt=expires_at,
            revision=revision,
            evmTypedData=_drill_typed_data(payload),
            blsSigningDigest="0x" + _drill_bls_digest(payload).hex(),
        )
    except HTTPException:
        raise
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/recovery-kit/drill/complete")
async def complete_recovery_drill(
    body: RecoveryDrillCompleteRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    if not body.offline_copy_confirmed or not body.second_device_confirmed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Confirm the offline copy and complete the second-device "
                "restore drill before enrollment."
            ),
        )
    if body.backup.status == "VERIFIED" and (
        body.backup.revision is None
        or body.backup.ciphertext_hash is None
    ):
        raise HTTPException(
            status_code=422,
            detail="Verified Drive backup evidence is incomplete.",
        )
    if body.backup.status == "NOT_CONFIGURED" and (
        body.backup.revision is not None
        or body.backup.ciphertext_hash is not None
    ):
        raise HTTPException(
            status_code=422,
            detail="Backup evidence is present while Drive backup is disabled.",
        )
    try:
        drill = store.recovery_drill(body.challenge_id)
        if (
            drill["ceremonyId"] != actor.ceremony_id
            or int(drill["slot"]) != actor.ceremony_slot
        ):
            raise GenesisConflict(
                "recovery drill belongs to another administrator"
            )
        payload = drill["public"]
        typed_data = _drill_typed_data(payload)
        recovered = recover_evm_signer(typed_data, body.evm_signature)
        if recovered.address.lower() != str(payload["evmGuardian"]).lower():
            raise ValueError(
                "EVM recovery drill was not signed by the recovery wallet"
            )
        bls_public_key = G1Element.from_bytes(
            bytes.fromhex(str(payload["recoveryBlsPubkey"])[2:])
        )
        bls_signature = G2Element.from_bytes(
            bytes.fromhex(body.bls_signature[2:])
        )
        if not AugSchemeMPL.verify(
            bls_public_key,
            _drill_bls_digest(payload),
            bls_signature,
        ):
            raise ValueError("BLS recovery drill signature is invalid")
        kit = store.complete_recovery_drill(
            body.challenge_id,
            expected_challenge_hash=str(drill["challengeHash"]),
            backup_status=body.backup.status,
            backup_revision=body.backup.revision,
            backup_ciphertext_hash=body.backup.ciphertext_hash,
        )
        return {
            "verified": True,
            (
                "recoveryKitCandidate"
                if kit.get("state") == "PENDING"
                else "recoveryKit"
            ): kit,
            "notice": (
                "Recovery proof passed. Solslot did not receive your phrase, "
                "backup password, or private keys. "
                + (
                    "The current recovery kit remains active until both "
                    "chains confirm this replacement."
                    if kit.get("state") == "PENDING"
                    else ""
                )
            ),
        }
    except (
        GenesisConflict,
        GenesisExpired,
        GenesisNotFound,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


__all__ = [
    "AUTHORITY_EVM_CHAIN_ID",
    "RECOVERY_BLS_PATH",
    "RECOVERY_EVM_PATH",
    "SecurityActor",
    "_drill_bls_digest",
    "_drill_typed_data",
    "require_security_actor",
    "router",
]
