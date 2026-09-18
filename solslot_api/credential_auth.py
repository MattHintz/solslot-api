"""Vault-owner authorization for Solslot V2 credential mutations."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal

import jwt as pyjwt
from chia.types.blockchain_format.program import Program
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1

from .config import Settings
from .credential_ledger import LedgerConflict, LedgerRateLimited, OwnerChallenge, get_credential_ledger, get_existing_credential_ledger
from .evm_auth import recover_evm_signer
from .state import VaultRecord, get_registry


CredentialAction = Literal[
    "session_login",
    "relay",
]

CREDENTIAL_ACTION_PRIMARY_TYPE = "SolslotVaultCredentialAction"
CREDENTIAL_ACTION_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
    ],
    CREDENTIAL_ACTION_PRIMARY_TYPE: [
        {"name": "vaultLauncherId", "type": "bytes32"},
        {"name": "action", "type": "bytes32"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "nonce", "type": "bytes32"},
        {"name": "expiresAt", "type": "uint64"},
    ],
}


class OwnerAuth(BaseModel):
    challengeId: str = Field(..., min_length=32, max_length=128)
    signature: str = Field(..., min_length=2)


class OwnerChallengeRequest(BaseModel):
    action: CredentialAction
    payload: dict[str, Any] = Field(default_factory=dict)


class OwnerChallengeResponse(BaseModel):
    challengeId: str
    vaultLauncherId: str
    action: CredentialAction
    payloadHash: str
    nonce: str | None = None
    authType: Literal["evm", "chia_bls"]
    expiresAt: int
    typedData: dict[str, Any] | None = None
    messageHex: str | None = None


class VaultSessionResponse(BaseModel):
    scope: Literal['vault', 'relay_recovery'] = 'vault'
    vaultLauncherId: str
    authType: Literal["evm", "chia_bls"]
    network: str
    protocolVersion: Literal["solslot-v2"] = "solslot-v2"
    expiresAt: int
    sessionFingerprint: str | None = None


@dataclass(frozen=True)
class VerifiedOwner:
    owner_key: str
    auth_type: Literal["evm", "chia_bls"]
    vault_record: VaultRecord


@dataclass(frozen=True)
class VerifiedVaultSession:
    owner_key: str
    auth_type: Literal["evm", "chia_bls"]
    vault_launcher_id: str
    network: str
    expires_at: int
    vault_record: VaultRecord
    scope: Literal['vault', 'relay_recovery'] = 'vault'
    session_id: str = ''


VAULT_SESSION_COOKIE = "solslot_vault_session_v2"
VAULT_SESSION_AUDIENCE = "solslot-credential-v2"
VAULT_SESSION_ISSUER = "solslot-api"


def vault_session_payload(settings: Settings) -> dict[str, Any]:
    return {
        "network": settings.network,
        "protocolVersion": "solslot-v2",
    }


def issue_vault_session(
    settings: Settings,
    verified_owner: VerifiedOwner,
    *, scope: Literal['vault', 'relay_recovery'] = 'vault',
) -> tuple[str, VaultSessionResponse]:
    secret = _vault_session_secret(settings)
    now = int(time.time())
    expires_at = now + settings.vault_session_ttl_seconds
    vault = "0x" + verified_owner.vault_record.launcher_id.hex()
    claims = {
        "iss": VAULT_SESSION_ISSUER,
        "aud": VAULT_SESSION_AUDIENCE,
        "sub": verified_owner.owner_key,
        "jti": secrets.token_hex(16),
        "scope": scope,
        "iat": now,
        "exp": expires_at,
        "vaultLauncherId": vault,
        "authType": verified_owner.auth_type,
        "network": settings.network,
        "protocolVersion": "solslot-v2",
    }
    token = pyjwt.encode(claims, secret, algorithm="HS256")
    return token, VaultSessionResponse(
        scope=scope,
        vaultLauncherId=vault,
        authType=verified_owner.auth_type,
        network=settings.network,
        expiresAt=expires_at,
        sessionFingerprint=vault_session_fingerprint(claims["jti"]),
    )


def vault_session_fingerprint(session_id: str) -> str | None:
    """Non-authorizing identity for binding a browser review to its HTTP session."""
    if not session_id:
        return None
    return "0x" + hashlib.sha256(json.dumps(session_id, separators=(",", ":")).encode()).hexdigest()


def verify_vault_session(
    settings: Settings,
    request: Request,
    vault_launcher_id: str,
    *, allow_recovery: bool = False,
) -> VerifiedVaultSession:
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    token = request.cookies.get(VAULT_SESSION_COOKIE)
    authorization = request.headers.get("authorization", "")
    if not token and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A fresh vault-owner session is required.",
        )
    try:
        claims = pyjwt.decode(
            token,
            _vault_session_secret(settings),
            algorithms=["HS256"],
            audience=VAULT_SESSION_AUDIENCE,
            issuer=VAULT_SESSION_ISSUER,
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The vault-owner session expired. Reconnect the wallet.",
        ) from exc
    except pyjwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The vault-owner session is invalid.",
        ) from exc
    if (
        claims.get("vaultLauncherId") != vault
        or claims.get("network") != settings.network
        or claims.get("protocolVersion") != "solslot-v2"
        or claims.get("authType") not in {"evm", "chia_bls"}
        or not claims.get("sub")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The vault-owner session does not match this vault and network.",
        )
    scope = claims.get('scope', 'vault')
    if scope not in ('vault', 'relay_recovery') or (scope == 'relay_recovery' and not allow_recovery):
        raise HTTPException(status_code=403, detail='This session can only check retained relay receipts. Reconnect when writes are available.')
    record = require_vault_record(vault)
    expected_owner = (
        record.owner_evm_address.lower()
        if record.owner_evm_address
        else "0x" + bytes(record.owner_pubkey).hex()
    )
    expected_auth_type = "evm" if record.auth_type == AUTH_TYPE_SECP256K1 else "chia_bls"
    if (
        str(claims["sub"]).lower() != expected_owner.lower()
        or claims["authType"] != expected_auth_type
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The vault-owner session no longer matches canonical ownership.",
        )
    return VerifiedVaultSession(
        owner_key=expected_owner,
        auth_type=expected_auth_type,
        vault_launcher_id=vault,
        network=settings.network,
        expires_at=int(claims["exp"]),
        vault_record=record,
        scope=scope,
        session_id=claims.get("jti", ""),
    )


def _vault_session_secret(settings: Settings) -> str:
    if len(settings.vault_session_jwt_secret) >= 32:
        return settings.vault_session_jwt_secret
    if settings.runtime_environment == "test":
        return "solslot-test-vault-session-secret-v2"
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Vault-owner sessions are not configured.",
    )


def normalize_hex32(value: object, field: str) -> str:
    text = str(value or "").strip().lower().removeprefix("0x")
    if len(text) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return "0x" + text


def credential_payload_hash(
    action: CredentialAction,
    vault_launcher_id: str,
    payload: dict[str, Any],
) -> str:
    envelope = {
        "action": action,
        "payload": payload,
        "vaultLauncherId": normalize_hex32(vault_launcher_id, "vaultLauncherId"),
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def credential_action_hash(action: CredentialAction) -> str:
    return "0x" + hashlib.sha256(action.encode("ascii")).hexdigest()


def credential_typed_data(
    settings: Settings,
    challenge: OwnerChallenge,
) -> dict[str, Any]:
    return {
        "types": CREDENTIAL_ACTION_TYPES,
        "primaryType": CREDENTIAL_ACTION_PRIMARY_TYPE,
        "domain": {
            "name": settings.eip712_name,
            "version": settings.eip712_version,
            "chainId": settings.eip712_chain_id,
        },
        "message": {
            "vaultLauncherId": challenge.vault_launcher_id,
            "action": credential_action_hash(challenge.action),
            "payloadHash": challenge.payload_hash,
            "nonce": challenge.nonce,
            "expiresAt": challenge.expires_at,
        },
    }


def credential_bls_message(settings: Settings, challenge: OwnerChallenge) -> bytes:
    material = b"\x53SOLSLOT_V2_CREDENTIAL_ACTION\x00" + b"".join(
        (
            bytes.fromhex(challenge.vault_launcher_id.removeprefix("0x")),
            bytes.fromhex(credential_action_hash(challenge.action).removeprefix("0x")),
            bytes.fromhex(challenge.payload_hash.removeprefix("0x")),
            bytes.fromhex(challenge.nonce.removeprefix("0x")),
            int(challenge.expires_at).to_bytes(8, "big"),
            settings.network.encode("ascii"),
        )
    )
    return hashlib.sha256(material).digest()


def credential_bls_signing_digest(settings: Settings, challenge: OwnerChallenge) -> bytes:
    """Return the CHIP-0002 digest signed by Chia wallet message RPCs."""

    return bytes(
        Program.to(
            ("Chia Signed Message", credential_bls_message(settings, challenge))
        ).get_tree_hash()
    )


def require_alpha_writes(settings: Settings) -> None:
    if not settings.alpha_writes_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Solslot V2 protocol writes are locked until the security audit "
                "and fresh genesis ceremony are complete."
            ),
        )


def require_minting_writes(settings: Settings) -> None:
    require_alpha_writes(settings)
    if not settings.minting_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Solslot V2 minting and offer creation remain locked until the "
                "independent audit and live ceremony smoke gate pass."
            ),
        )
    if settings.network != "testnet11":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Solslot protocol writes are disabled outside Testnet Alpha.",
        )


def require_presale_writes(settings: Settings) -> None:
    require_minting_writes(settings)
    if not settings.presale_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Refundable voucher presales are disabled.",
        )


def require_vault_record(vault_launcher_id: str) -> VaultRecord:
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    record = get_registry().get(bytes32.fromhex(vault.removeprefix("0x")))
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The vault is not registered in the canonical V2 vault registry.",
        )
    return record


def _require_credential_action(settings: Settings, action: str, vault: str) -> None:
    if action == 'session_login' and not settings.alpha_writes_enabled:
        # A write freeze must not lock an owner out of an existing receipt.
        # The login route issues a restricted recovery session in this state.
        ledger = get_existing_credential_ledger(settings)
        if ledger is not None and ledger.get_relay_attempt(vault) is not None:
            return
    require_alpha_writes(settings)


def issue_owner_challenge(
    settings: Settings,
    *,
    vault_launcher_id: str,
    request: OwnerChallengeRequest,
) -> OwnerChallengeResponse:
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    _require_credential_action(settings, request.action, vault)
    record = require_vault_record(vault)
    if record.auth_type == AUTH_TYPE_SECP256K1 and record.owner_evm_address:
        auth_type: Literal["evm", "chia_bls"] = "evm"
    elif record.auth_type == AUTH_TYPE_BLS:
        auth_type = "chia_bls"
    else:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This vault authorization type cannot stamp V2 credentials.",
        )
    payload_hash = credential_payload_hash(request.action, vault, request.payload)
    try:
        challenge = get_credential_ledger(settings).issue_owner_challenge(
            vault_launcher_id=vault,
            action=request.action,
            payload_hash=payload_hash,
            auth_type=auth_type,
            ttl_seconds=settings.zkpassport_owner_challenge_ttl_seconds,
            max_pending=settings.challenge_store_max_pending,
        )
    except LedgerRateLimited as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    return OwnerChallengeResponse(
        challengeId=challenge.challenge_id,
        vaultLauncherId=vault,
        action=request.action,
        payloadHash=payload_hash,
        nonce=challenge.nonce,
        authType=auth_type,
        expiresAt=challenge.expires_at,
        typedData=credential_typed_data(settings, challenge) if auth_type == "evm" else None,
        messageHex=(
            "0x" + credential_bls_message(settings, challenge).hex()
            if auth_type == "chia_bls"
            else None
        ),
    )


def verify_owner_auth(
    settings: Settings,
    *,
    vault_launcher_id: str,
    action: CredentialAction,
    payload: dict[str, Any],
    owner_auth: OwnerAuth,
) -> VerifiedOwner:
    vault = normalize_hex32(vault_launcher_id, "vaultLauncherId")
    _require_credential_action(settings, action, vault)
    record = require_vault_record(vault)
    payload_hash = credential_payload_hash(action, vault, payload)
    ledger = get_credential_ledger(settings)
    challenge = ledger.get_owner_challenge(owner_auth.challengeId)
    if challenge is None:
        raise HTTPException(status_code=409, detail="Owner challenge is unknown or consumed.")
    if challenge.expires_at < int(time.time()):
        raise HTTPException(status_code=409, detail="Owner challenge expired.")
    if (
        challenge.vault_launcher_id != vault
        or challenge.action != action
        or challenge.payload_hash != payload_hash
    ):
        raise HTTPException(status_code=409, detail="Owner challenge does not match this mutation.")

    if challenge.auth_type == "evm":
        if record.auth_type != AUTH_TYPE_SECP256K1 or not record.owner_evm_address:
            raise HTTPException(status_code=409, detail="Vault owner metadata is not EVM-authenticated.")
        try:
            recovered = recover_evm_signer(
                credential_typed_data(settings, challenge),
                owner_auth.signature,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail=f"Invalid owner signature: {exc}") from exc
        if recovered.address.lower() != record.owner_evm_address.lower():
            raise HTTPException(status_code=403, detail="Signature does not belong to this vault owner.")
        owner_key = recovered.address.lower()
        auth_type: Literal["evm", "chia_bls"] = "evm"
    elif challenge.auth_type == "chia_bls":
        if record.auth_type != AUTH_TYPE_BLS:
            raise HTTPException(status_code=409, detail="Vault owner metadata is not BLS-authenticated.")
        try:
            signature = G2Element.from_bytes(bytes.fromhex(owner_auth.signature.removeprefix("0x")))
            pubkey = G1Element.from_bytes(bytes(record.owner_pubkey))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=401, detail=f"Invalid BLS owner signature: {exc}") from exc
        if not AugSchemeMPL.verify(
            pubkey,
            credential_bls_signing_digest(settings, challenge),
            signature,
        ):
            raise HTTPException(status_code=403, detail="BLS signature does not belong to this vault owner.")
        owner_key = "0x" + bytes(pubkey).hex()
        auth_type = "chia_bls"
    else:
        raise HTTPException(status_code=409, detail="Unsupported owner challenge type.")

    try:
        ledger.consume_owner_challenge(
            challenge_id=owner_auth.challengeId,
            vault_launcher_id=vault,
            action=action,
            payload_hash=payload_hash,
        )
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return VerifiedOwner(owner_key=owner_key, auth_type=auth_type, vault_record=record)


__all__ = [
    "CREDENTIAL_ACTION_PRIMARY_TYPE",
    "CREDENTIAL_ACTION_TYPES",
    "CredentialAction",
    "OwnerAuth",
    "OwnerChallengeRequest",
    "OwnerChallengeResponse",
    "VAULT_SESSION_COOKIE",
    "VaultSessionResponse",
    "VerifiedOwner",
    "VerifiedVaultSession",
    "credential_payload_hash",
    "credential_bls_message",
    "credential_bls_signing_digest",
    "credential_typed_data",
    "issue_owner_challenge",
    "issue_vault_session",
    "require_alpha_writes",
    "require_minting_writes",
    "require_presale_writes",
    "verify_owner_auth",
    "verify_vault_session",
    "vault_session_payload",
]
