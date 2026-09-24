"""Guided, role-aware control plane for the one-time Testnet11 launch.

This router intentionally wraps the existing genesis state machine. It does
not duplicate ceremony transitions or accept operator-supplied protocol
coordinates. The browser receives plain-language tasks and decision receipts;
the underlying signed evidence remains downloadable for technical review.
"""

from __future__ import annotations

from solslot_puzzles.enrollment_networks import enrollment_operational_chain_id

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping, Optional

import jwt as pyjwt
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import G2Element, SpendBundle
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)
from solslot_puzzles.sgt_driver import TEST_KOS_MINT_EXECUTE_PUBKEY

from .authority_v3_evidence import (
    load_governance_evidence,
    validate_governance_roster,
)
from .authority_v3_review import (
    AuthorityV3ReviewError,
    load_authority_v3_review,
)
from .config import Settings, get_settings
from .disposable_genesis import is_disposable, require_scope, require_allowed_gate
from .evm_auth import normalize_evm_address, recover_evm_signer
from .genesis import (
    INDEPENDENT_REVIEW_CLASS,
    INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    PlanRequest,
    SignaturePrepareRequest,
    SignatureRequest,
    _broadcast_ceremony,
    _invitation_typed_data,
    _prepare_bundle,
    _require_live_plan,
    _run_worker,
    _token_hash,
    accept_invitation,
    confirm,
    create_artifact,
    create_plan,
    finalize,
    freeze_roster,
    get_genesis_store,
    prepare_artifact_signature,
    prepare_plan_signature,
    renew_plan,
    sign_artifact,
    sign_plan,
)
from .genesis_funding import (
    FUNDING_NAMES,
    GENESIS_BRIDGE_BATCH_FUNDING_AMOUNT,
    GENESIS_DEFAULT_TOTAL_FUNDING_AMOUNT,
    plan_genesis_funding_fanout,
)
from .genesis_store import (
    COADMIN_SLOTS,
    OWNER_SLOT,
    GenesisConflict,
    GenesisExpired,
    GenesisNotFound,
    GenesisStore,
    GenesisStoreError,
)
from .launch_rehearsal import (
    HEX32_RE,
    LaunchRehearsalError,
    persist_evidence,
    require_completed_rehearsal,
    rehearsal_status,
    start_rehearsal,
)
from .omnichain_ownership_activation import (
    BroadcastRequest as OwnershipBroadcastRequest,
    OwnershipActivationError,
    OwnershipActivationStore,
    SignatureRequest as OwnershipSignatureRequest,
    _chain_state,
    _public_status,
    get_ownership_activation_store,
    load_authority_operation,
    load_execution_authority_operation,
    record_ownership_activation_broadcast,
    record_ownership_execution_broadcast,
    sign_ownership_activation,
    sign_ownership_execution,
)


router = APIRouter(prefix="/admin/launch", tags=["admin-launch"])

LAUNCH_COOKIE_NAME = "solslot_launch_session"
LAUNCH_SCOPE = "alpha-launch"
SOURCE_KEYS = (
    "protocol",
    "evm",
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
    "customerWeb",
    "adminPortal",
)
SOURCE_MANIFEST_VERSION = 4
RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX = (
    "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
)
GATE_NAMES = ("ceremonyBroadcast", "minting", "presale", "purchases", "xchVouchers")
CREATE_COIN = 51
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
PLACEHOLDER_FUNDING_IDS = {
    name: "0x" + f"{index:02x}" * 32
    for index, name in enumerate(FUNDING_NAMES, start=1)
}
PLAN_BOUND_AUDIT_STATES = frozenset(
    {
        "plan_approved",
        "broadcast",
        "confirmed",
        "artifact_pending",
        "artifact_signed",
        "locked",
    }
)


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class OwnerClaimRequest(ApiModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    token: str = Field(min_length=32, max_length=512)
    display_name: str = Field("Owner", alias="displayName", min_length=2, max_length=80)
    email: Optional[str] = Field(None, max_length=254)
    timezone: str = Field("America/Chicago", min_length=1, max_length=64)


class InviteProfileRequest(ApiModel):
    display_name: str = Field(alias="displayName", min_length=2, max_length=80)
    email: Optional[str] = Field(None, max_length=254)
    timezone: str = Field("America/Chicago", min_length=1, max_length=64)
    reminders_enabled: bool = Field(True, alias="remindersEnabled")


class InvitationPrepareRequest(ApiModel):
    token: str = Field(min_length=32, max_length=512)
    wallet: str


class InvitationAcceptRequest(InvitationPrepareRequest):
    signature: str


class ResumeChallengeRequest(ApiModel):
    wallet: str


class ResumeLoginRequest(ApiModel):
    wallet: str
    nonce: str
    signature: str


class ProfileUpdateRequest(InviteProfileRequest):
    pass


class ActionPrepareRequest(ApiModel):
    action_type: Literal[
        "funding",
        "abandon",
        "gate:ceremonyBroadcast",
        "gate:minting",
        "gate:presale",
        "gate:purchases",
        "gate:xchVouchers",
    ] = Field(alias="actionType")


class ActionApproveRequest(ActionPrepareRequest):
    action_id: str = Field(alias="actionId")
    payload_hash: str = Field(alias="payloadHash")
    expires_at: int = Field(alias="expiresAt")
    signature: str


class GateProposalRequest(ApiModel):
    gate: Literal["ceremonyBroadcast", "minting", "presale", "purchases", "xchVouchers"]
    starts_in_seconds: int = Field(0, alias="startsInSeconds", ge=0, le=86400)
    duration_seconds: int = Field(alias="durationSeconds", ge=300, le=86400)


class SignatureSubmission(ApiModel):
    signature: str


class AbandonPrepareRequest(ApiModel):
    reason: str = Field(min_length=8, max_length=1000)


class RailSignatureSubmission(SignatureSubmission):
    phase: Literal["schedule", "execute"]


class RailBroadcastSubmission(ApiModel):
    phase: Literal["schedule", "execute"]
    transaction_hash: str = Field(alias="transactionHash")


class RehearsalTransactionSubmission(ApiModel):
    transaction_hash: str = Field(alias="transactionHash")


@dataclass(frozen=True)
class LaunchSession:
    ceremony_id: str
    slot: int
    wallet: str | None
    setup: bool
    expires_at: int


_ephemeral_launch_secret: str | None = None


def _hash_json(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _source_manifest_hash(value: Mapping[str, Any]) -> str:
    return _hash_json(
        {
            key: item
            for key, item in value.items()
            if key != "manifestHash"
        }
    )


def _authority_source_commitment(source_shas: Mapping[str, str]) -> str:
    return _hash_json(
        {
            "version": SOURCE_MANIFEST_VERSION,
            "sources": dict(source_shas),
            "dependencies": {
                "administratorRecovery": (
                    RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
                )
            },
        }
    )


def _secret(settings: Settings) -> str:
    global _ephemeral_launch_secret
    if settings.launch_session_secret:
        return settings.launch_session_secret
    if settings.bootstrap_session_secret:
        return settings.bootstrap_session_secret
    if _ephemeral_launch_secret is None:
        _ephemeral_launch_secret = secrets.token_hex(32)
    return _ephemeral_launch_secret


def _issue_session(
    settings: Settings,
    *,
    ceremony_id: str,
    slot: int,
    wallet: str | None,
    setup: bool,
) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + settings.launch_session_ttl_seconds
    token = pyjwt.encode(
        {
            "scope": LAUNCH_SCOPE,
            "ceremonyId": ceremony_id,
            "slot": slot,
            "wallet": wallet,
            "setup": setup,
            "iat": now,
            "exp": expires_at,
        },
        _secret(settings),
        algorithm="HS256",
    )
    return token, expires_at


def _set_session_cookie(
    response: Response, settings: Settings, token: str, expires_at: int
) -> None:
    _clear_legacy_session_cookie(response, settings)
    response.set_cookie(
        LAUNCH_COOKIE_NAME,
        token,
        max_age=max(1, expires_at - int(time.time())),
        httponly=True,
        secure=settings.bootstrap_cookie_secure,
        samesite="strict",
        path=settings.launch_cookie_path,
    )


def _clear_legacy_session_cookie(response: Response, settings: Settings) -> None:
    legacy_path = "/protocol-api/admin/launch"
    if settings.launch_cookie_path != legacy_path:
        response.delete_cookie(
            LAUNCH_COOKIE_NAME,
            path=legacy_path,
            secure=settings.bootstrap_cookie_secure,
            httponly=True,
            samesite="strict",
        )


def _decode_session(token: str, settings: Settings) -> LaunchSession:
    try:
        payload = pyjwt.decode(
            token,
            _secret(settings),
            algorithms=["HS256"],
            options={
                "require": [
                    "scope",
                    "ceremonyId",
                    "slot",
                    "setup",
                    "iat",
                    "exp",
                ]
            },
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Administrator session expired.") from exc
    except pyjwt.InvalidTokenError as exc:
        raise HTTPException(status_code=403, detail="Administrator session is invalid.") from exc
    if payload.get("scope") != LAUNCH_SCOPE:
        raise HTTPException(status_code=403, detail="Administrator session has the wrong scope.")
    return LaunchSession(
        ceremony_id=str(payload["ceremonyId"]),
        slot=int(payload["slot"]),
        wallet=str(payload["wallet"]).lower() if payload.get("wallet") else None,
        setup=bool(payload["setup"]),
        expires_at=int(payload["exp"]),
    )


def require_launch_session(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> LaunchSession:
    if not settings.launch_control_enabled:
        raise HTTPException(status_code=503, detail="Alpha launch control is disabled.")
    token = request.cookies.get(LAUNCH_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Connect an enrolled administrator wallet.")
    session = _decode_session(token, settings)
    try:
        record = store.get(session.ceremony_id)
    except GenesisStoreError as exc:
        raise HTTPException(status_code=401, detail="Administrator launch no longer exists.") from exc
    from .admin_roster import current_launch_authority
    try:
        authority = current_launch_authority(settings, store, session.ceremony_id)
        if authority.finalizing and (request.scope.get("method"), request.scope.get("path")) not in {
            ("GET", "/admin/launch/workspace"), ("GET", "/admin/launch/audit"),
            ("POST", "/admin/launch/progress"),
        }:
            raise ValueError("Finish the reserved genesis publication before other administrator actions.")
        if session.setup:
            if not authority.bootstrap or session.wallet or session.slot != OWNER_SLOT:
                raise ValueError("Owner setup is no longer available.")
        elif not session.wallet or authority.wallets.get(session.slot) != session.wallet:
            raise ValueError("Wallet is not the current administrator for this launch slot.")
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return session


def _require_wallet_session(session: LaunchSession) -> None:
    if session.setup or not session.wallet:
        raise HTTPException(
            status_code=401,
            detail="Finish owner enrollment and reconnect the enrolled wallet.",
        )


def _require_owner(session: LaunchSession) -> None:
    _require_wallet_session(session)
    if session.slot != OWNER_SLOT:
        raise HTTPException(status_code=403, detail="This action is assigned to the owner.")


def _require_coadmin(session: LaunchSession) -> None:
    _require_wallet_session(session)
    if session.slot not in COADMIN_SLOTS:
        raise HTTPException(
            status_code=403,
            detail="This rehearsal is assigned to a coadministrator.",
        )


def _read_json_file(path_value: str | None, label: str) -> tuple[dict[str, Any], str]:
    if not path_value:
        raise GenesisConflict(f"{label} is not configured")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise GenesisConflict(f"{label} is unavailable")
    size = path.stat().st_size
    if size <= 0 or size > MAX_EVIDENCE_BYTES:
        raise GenesisConflict(f"{label} has an invalid size")
    raw_bytes = path.read_bytes()
    try:
        value = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenesisConflict(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise GenesisConflict(f"{label} must be a JSON object")
    return value, hashlib.sha256(raw_bytes).hexdigest()


def _load_release_evidence(settings: Settings) -> dict[str, Any]:
    evidence, digest = _read_json_file(
        settings.launch_source_evidence_path, "RC27 source evidence"
    )
    if settings.launch_source_evidence_sha256:
        expected = settings.launch_source_evidence_sha256.removeprefix("0x").lower()
        if not secrets.compare_digest(digest, expected):
            raise GenesisConflict("RC27 source evidence checksum changed")
    if (
        evidence.get("schemaVersion") != 5
        or evidence.get("kind") != "solslot-rc27-launch-source-evidence"
        or evidence.get("network") != "testnet11"
        or evidence.get("releaseTag") != settings.launch_release_tag
        or evidence.get("releaseId") != settings.launch_release_tag
        or evidence.get("completeReleaseManifest") is not True
        or evidence.get("releaseRefsVerified") is not True
        or evidence.get("testOnly") is not True
    ):
        raise GenesisConflict(
            "RC27 source evidence is incomplete or targets another release"
        )
    source_manifest = evidence.get("sourceManifest")
    if (
        not isinstance(source_manifest, Mapping)
        or source_manifest.get("schemaVersion")
        != SOURCE_MANIFEST_VERSION
        or source_manifest.get("kind")
        != "solslot-release-source-manifest"
        or source_manifest.get("releaseId")
        != settings.launch_release_tag
        or source_manifest.get("network") != "testnet11"
        or source_manifest.get("testOnly") is not True
        or source_manifest.get("manifestHash")
        != evidence.get("manifestHash")
        or source_manifest.get("manifestHash")
        != _source_manifest_hash(source_manifest)
    ):
        raise GenesisConflict(
            "RC27 source manifest checksum or release binding is invalid"
        )
    shas = source_manifest.get("sourceShas")
    if not isinstance(shas, Mapping) or set(shas) != set(SOURCE_KEYS):
        raise GenesisConflict(
            "RC27 evidence does not freeze all nine source commits"
        )
    normalized_shas: dict[str, str] = {}
    for key in SOURCE_KEYS:
        value = str(shas[key]).lower()
        if len(value) != 40:
            raise GenesisConflict(
                f"RC27 source commit {key} is not a full SHA"
            )
        try:
            int(value, 16)
        except ValueError as exc:
            raise GenesisConflict(
                f"RC27 source commit {key} is invalid"
            ) from exc
        normalized_shas[key] = value
    dependencies = source_manifest.get("dependencies")
    recovery = (
        dependencies.get("administratorRecovery")
        if isinstance(dependencies, Mapping)
        else None
    )
    if (
        not isinstance(recovery, Mapping)
        or recovery.get("repository")
        != PINNED_CNI_WALLET_SDK_REPOSITORY
        or recovery.get("commit") != PINNED_CNI_WALLET_SDK_COMMIT
        or recovery.get("license") != PINNED_CNI_WALLET_SDK_LICENSE
        or recovery.get("manifestHash")
        != RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
    ):
        raise GenesisConflict(
            "RC27 source manifest does not bind the pinned recovery SDK"
        )
    if source_manifest.get(
        "authoritySourceCommitment"
    ) != _authority_source_commitment(normalized_shas):
        raise GenesisConflict(
            "RC27 Authority V3 source commitment is invalid"
        )
    sources = source_manifest.get("sources")
    if not isinstance(sources, Mapping) or set(sources) != set(
        SOURCE_KEYS
    ):
        raise GenesisConflict(
            "RC27 source records are incomplete"
        )
    release_branch = (
        "release/testnet-alpha-"
        + settings.launch_release_tag.removeprefix(
            "solslot-v2-alpha-"
        )
    )
    for key in SOURCE_KEYS:
        source = sources.get(key)
        if (
            not isinstance(source, Mapping)
            or str(source.get("commit", "")).lower()
            != normalized_shas[key]
            or source.get("branch") != release_branch
            or not str(source.get("repository", "")).startswith(
                "https://github.com/"
            )
        ):
            raise GenesisConflict(
                f"RC27 source record {key} is not release-bound"
            )
    return {
        "releaseTag": evidence["releaseTag"],
        "manifestHash": evidence.get("manifestHash"),
        "fileSha256": "0x" + digest,
        "sourceShas": normalized_shas,
        "authoritySourceCommitment": source_manifest[
            "authoritySourceCommitment"
        ],
        "recoveryDependencyManifestHash": (
            RECOVERY_DEPENDENCY_MANIFEST_HASH_HEX
        ),
        "evidence": evidence,
    }


def _selected_template(settings: Settings, template: Mapping[str, Any], digest: str,
        *, record: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """Resolve selection from protected server evidence, never browser input."""
    from solslot_puzzles.enrollment_activation import validate_enrollment_activation, exact_hex
    from .genesis_permit_evm import _read, GenesisEvmEvidenceError
    selected = (any(k in template for k in ("enrollmentActivation", "enrollment_activation"))
        or settings.zkpassport_evm_chain_id != 11155111
        or (record is not None and record["draft"].get("evmChainId", 11155111) != 11155111))
    if not selected:
        return None
    try:
        # This path requires independently pinned release bytes, unlike legacy
        # setup where coordinates can still be installed after claiming a link.
        _read(settings.launch_source_evidence_path, "release evidence",
            (settings.launch_source_evidence_sha256 or "").removeprefix("0x"))
        release = _load_release_evidence(settings)
        body = PlanRequest.model_validate({**template, "fundingCoinIds": PLACEHOLDER_FUNDING_IDS})
        active = body.enrollment_activation
        if not isinstance(active, dict):
            raise ValueError("selected launch requires a complete activation")
        active = validate_enrollment_activation(active, source_shas=release["sourceShas"],
            ceremony_id=active["deploymentId"], emitter=body.evm_addresses["attestationEmitter"],
            validator_pubkeys=[exact_hex(k, 48, "validator") for k in body.validator_pubkeys],
            environment=settings.runtime_environment + "-alpha")
        if (settings.network != "testnet11" or settings.zkpassport_evm_chain_id != active["evmChainId"]
                or settings.eip712_chain_id != enrollment_operational_chain_id(active)
                or active["releaseIdentity"] != settings.enrollment_permit_release_identity
                or active["issuerKeyRef"] != settings.enrollment_permit_issuer_key_ref
                or active["issuerIdentityClientId"] != settings.enrollment_permit_identity_client_id
                or active["reviewEvidenceSha256"] != settings.enrollment_deployment_review_sha256):
            raise ValueError("selected launch differs from coordinator pins")
        binding = {"evmChainId": enrollment_operational_chain_id(active), "enrollmentActivation": active,
            "launchPlanTemplateSha256": digest}
        if record is not None and (record["ceremony_id"] != active["deploymentId"]
                or any(record["draft"].get(k) != v for k,v in binding.items())
                or record["draft"]["sourceShas"] != release["sourceShas"]
                or record["draft"].get("releaseEvidenceHash") != release["fileSha256"]):
            raise ValueError("protected launch selection changed after the original claim")
        return binding
    except (ValueError, KeyError, TypeError, GenesisEvmEvidenceError) as exc:
        raise GenesisConflict(f"selected launch evidence is invalid: {exc}") from exc


def _claim_selection(settings: Settings) -> dict[str, Any] | None:
    path = Path(settings.launch_plan_template_path)
    if not path.is_file() and settings.zkpassport_evm_chain_id == 11155111:
        return None
    from .genesis_permit_evm import _read, GenesisEvmEvidenceError
    try:
        template, digest = _read(str(path), "launch plan template")
        return _selected_template(settings, template, digest)
    except GenesisEvmEvidenceError as exc:
        raise GenesisConflict(str(exc)) from exc


def _ceremony_chain(record: Mapping[str, Any]) -> int:
    chain = record["draft"].get("evmChainId", 11155111)
    if type(chain) is not int or chain not in (11155111, 84532, 8453):
        raise GenesisConflict("unsupported ceremony signing chain")
    return chain


def _ceremony_binding(record: Mapping[str, Any]) -> dict[str, Any]:
    return {"ceremonyId": record["ceremony_id"], "evmChainId": _ceremony_chain(record)}


def _selected_commitments(record: Mapping[str, Any]) -> dict[str, Any] | None:
    plan = record.get("plan") or {}
    active = plan.get("enrollmentActivation") or record["draft"].get("enrollmentActivation")
    if not isinstance(active, Mapping):
        return None
    return {k: active[k] for k in ("environment", "evmChainId", "deploymentId", "releaseIdentity",
        "emitter", "issuer", "contextHash", "bridgePolicyHash", "reviewEvidenceSha256")}


def _plan_template_evidence(settings: Settings, record: Mapping[str, Any] | None = None) -> dict[str, Any]:
    template, digest = _read_json_file(
        settings.launch_plan_template_path, "RC27 launch plan template"
    )
    selection = _selected_template(settings, template, digest, record=record)
    template["fundingCoinIds"] = PLACEHOLDER_FUNDING_IDS
    plan = PlanRequest.model_validate(template)

    kos_pubkey = bytes.fromhex(plan.kos_mint_execute_pubkey.removeprefix("0x"))
    if len(kos_pubkey) != 48 or kos_pubkey == b"\x00" * 48:
        raise GenesisConflict("KoS MINT co-signer public key is missing")
    if secrets.compare_digest(kos_pubkey, TEST_KOS_MINT_EXECUTE_PUBKEY):
        raise GenesisConflict(
            "KoS MINT co-signer still uses the public test fixture key"
        )

    validator_pubkeys = [
        bytes.fromhex(value.removeprefix("0x")) for value in plan.validator_pubkeys
    ]
    if (
        any(len(value) != 48 or value == b"\x00" * 48 for value in validator_pubkeys)
        or len(set(validator_pubkeys)) != 3
    ):
        raise GenesisConflict(
            "RC23 plan must contain three unique nonzero validator public keys"
        )

    return {
        "fileSha256": "0x" + digest,
        "kosMintExecutePubkey": plan.kos_mint_execute_pubkey.lower(),
        "validatorCount": len(validator_pubkeys),
        **({"enrollmentActivation": selection["enrollmentActivation"]} if selection else {}),
    }


def _resume_typed_data(
    *,
    ceremony_id: str,
    slot: int,
    wallet: str,
    nonce: str,
    expires_at: int,
    chain_id: int = 11155111,
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolslotLaunchResume": [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "slot", "type": "uint8"},
                {"name": "wallet", "type": "address"},
                {"name": "nonce", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint64"},
            ],
        },
        "primaryType": "SolslotLaunchResume",
        "domain": {"name": "Solslot Alpha Launch", "version": "21", "chainId": chain_id},
        "message": {
            "ceremonyId": ceremony_id,
            "slot": slot,
            "wallet": normalize_evm_address(wallet, "wallet"),
            "nonce": nonce,
            "expiresAt": expires_at,
        },
    }


def _action_typed_data(
    *,
    ceremony_id: str,
    action_type: str,
    action_id: str,
    payload_hash: str,
    expires_at: int,
    chain_id: int = 11155111,
) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolslotLaunchAction": [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "actionType", "type": "string"},
                {"name": "actionId", "type": "bytes32"},
                {"name": "payloadHash", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint64"},
            ],
        },
        "primaryType": "SolslotLaunchAction",
        "domain": {"name": "Solslot Alpha Launch", "version": "21", "chainId": chain_id},
        "message": {
            "ceremonyId": ceremony_id,
            "actionType": action_type,
            "actionId": action_id,
            "payloadHash": payload_hash,
            "expiresAt": expires_at,
        },
    }


def _typed_digest(typed_data: Mapping[str, Any]) -> str:
    signable = encode_typed_data(full_message=dict(typed_data))
    return "0x" + keccak(
        b"\x19" + bytes(signable.version) + signable.header + signable.body
    ).hex()


def _funding_payload(store: GenesisStore, ceremony_id: str) -> tuple[str, str]:
    receipt = store.funding_receipt(ceremony_id)
    if not receipt:
        raise GenesisConflict("prepare the fixed ceremony funding first")
    payload_hash = str(receipt["planHash"])
    return "0x" + hashlib.sha256(
        f"{ceremony_id}:funding:{payload_hash}".encode("ascii")
    ).hexdigest(), payload_hash


def _gate_payload(
    store: GenesisStore, ceremony_id: str, gate_name: str
) -> tuple[str, str]:
    gate = store.gates(ceremony_id).get(gate_name)
    if not gate:
        raise GenesisConflict("prepare the timed gate first")
    payload_hash = str(gate["payloadHash"])
    return "0x" + hashlib.sha256(
        f"{ceremony_id}:gate:{gate_name}:{payload_hash}".encode("ascii")
    ).hexdigest(), payload_hash


def _action_payload(
    store: GenesisStore, ceremony_id: str, action_type: str
) -> tuple[str, str]:
    if action_type == "funding":
        return _funding_payload(store, ceremony_id)
    if action_type.startswith("gate:"):
        return _gate_payload(store, ceremony_id, action_type.split(":", 1)[1])
    if action_type == "abandon":
        intent = store.latest_action_intent(ceremony_id, "abandon")
        if not intent or intent["state"] != "prepared":
            raise GenesisConflict("prepare the abandonment reason first")
        return str(intent["actionId"]), str(intent["payloadHash"])
    raise GenesisConflict("the requested action is not prepared")


def _gate_open(
    settings: Settings, store: GenesisStore, ceremony_id: str, gate_name: str
) -> dict[str, Any]:
    if not settings.alpha_writes_enabled:
        raise GenesisConflict("the server chain-write ceiling is closed")
    if gate_name == "ceremonyBroadcast" and not settings.ceremony_mode_enabled:
        raise GenesisConflict("the server ceremony ceiling is closed")
    gate = store.authorized_gate(settings, ceremony_id, gate_name)
    if (
        not gate
        or gate["configuredState"] != "open"
        or gate["state"] != "open"
    ):
        raise GenesisConflict(f"the signed {gate_name} window is closed")
    return {
        "gate": gate_name,
        "payloadHash": gate["payloadHash"],
        "opensAt": gate["opensAt"],
        "closesAt": gate["closesAt"],
        "configuredState": gate["configuredState"],
        "state": gate["state"],
        "approved": True,
    }


def _funding_ceiling_open(settings: Settings) -> None:
    if not settings.alpha_writes_enabled or not settings.ceremony_mode_enabled:
        raise GenesisConflict("the server ceremony funding ceiling is closed")


def _decision_receipt(action_type: str, payload_hash: str) -> dict[str, Any]:
    labels = {
        "funding": (
            "Create the nine ceremony funding coins",
            "Moves 1,000,567 testnet mojos into nine fixed ceremony inputs. No fee.",
            "Creates fixed Testnet11 outputs; it cannot redirect funds.",
        ),
        "gate:ceremonyBroadcast": (
            "Open the launch window",
            "Allows only the exact approved Testnet11 ceremony bundle until expiry.",
            "The window closes automatically and cannot override the server ceiling.",
        ),
        "gate:minting": (
            "Open minting",
            "Temporarily permits approved collection mint operations on Testnet11.",
            "The window closes automatically.",
        ),
        "gate:presale": (
            "Open presale",
            "Temporarily permits governed refundable voucher reservations on Testnet11.",
            "The window closes automatically.",
        ),
        "gate:xchVouchers": (
            "Enable XCH voucher purchases",
            "Temporarily allows new XCH vouchers only after this release is approved for XCH.",
            "Off by default. Closing this control preserves existing refunds and recovery.",
        ),
        "gate:purchases": (
            "Open purchases",
            "Temporarily permits eligible test purchases on Testnet11.",
            "The window closes automatically.",
        ),
        "abandon": (
            "Abandon this alpha launch",
            "No payment is made. The active ceremony becomes permanently unusable.",
            "This cannot be undone. A future launch must start from a fresh ceremony.",
        ),
    }
    title, effect, reversibility = labels[action_type]
    return {
        "title": title,
        "network": "Testnet11",
        "financialEffect": effect,
        "customerImpact": "TESTNET only. No real investment or legal right.",
        "reversibility": reversibility,
        "requiredApprovers": "Owner plus either coadministrator",
        "payloadHash": payload_hash,
    }


def _rail_phase_status(
    settings: Settings, store: OwnershipActivationStore
) -> dict[str, Any]:
    schedule_package = load_authority_operation(settings, phase="schedule")
    schedule = _public_status(
        settings=settings, package=schedule_package, store=store
    )
    if schedule["state"] in {"SCHEDULED", "READY_TO_EXECUTE", "DONE"}:
        execute_package = load_execution_authority_operation(settings, store)
        execute = _public_status(
            settings=settings, package=execute_package, store=store
        )
        if execute["state"] != "WAITING_FOR_SCHEDULE" or schedule["state"] == "DONE":
            return execute
    return schedule


def _rail_decision_receipt(status_value: Mapping[str, Any]) -> dict[str, Any]:
    phase = str(status_value["phase"])
    return {
        "title": (
            "Schedule the Base Sepolia ownership handoff"
            if phase == "schedule"
            else "Accept Base Sepolia ownership after the safety delay"
        ),
        "network": "Base Sepolia",
        "financialEffect": "No protocol or customer funds move. The submitting wallet pays test gas.",
        "customerImpact": (
            "Schedules the reviewed Safe and timelock ownership transfer."
            if phase == "schedule"
            else "Activates the reviewed Safe and timelock as the payment-rail authority."
        ),
        "reversibility": (
            "A 24-hour timelock must finish before execution."
            if phase == "schedule"
            else "Execution is final for these reviewed contracts."
        ),
        "requiredApprovers": "Owner plus either coadministrator, using fresh Safe approvals",
        "expectedResult": (
            "The 24-hour waiting period begins."
            if phase == "schedule"
            else "Payment-rail ownership becomes active and independently verifiable."
        ),
    }


def _require_rail_session_signature(
    status_value: Mapping[str, Any],
    *,
    signature: str,
    session: LaunchSession,
) -> None:
    _require_wallet_session(session)
    matches: list[str] = []
    for descriptor in status_value.get("approvals", []):
        try:
            recovered = recover_evm_signer(descriptor["typedData"], signature)
        except ValueError:
            continue
        if any(
            str(allowed).lower() == recovered.address.lower()
            for allowed in descriptor.get("allowedSigners", [])
        ):
            matches.append(recovered.address.lower())
    if len(matches) != 1 or matches[0] != session.wallet:
        raise GenesisConflict(
            "Safe approval must come from this enrolled administrator wallet"
        )


def _store_rehearsal_status(
    settings: Settings,
    store: GenesisStore,
    ceremony_id: str,
    status_value: dict[str, Any],
) -> dict[str, Any]:
    payload = dict(status_value)
    if status_value["state"] == "SUCCEEDED":
        evidence = status_value.get("evidence")
        if not isinstance(evidence, Mapping):
            raise LaunchRehearsalError("Completed rehearsal evidence is missing.")
        payload["evidenceDigest"] = persist_evidence(settings, evidence)
    return store.set_settlement_rehearsal(
        ceremony_id,
        job_id=str(status_value["jobId"]),
        config_hash=str(status_value["configHash"]),
        state=str(status_value["state"]),
        payload=payload,
    )


def _rehearsal_result(record: Mapping[str, Any] | None) -> dict[str, Any]:
    if record is None:
        status_value: dict[str, Any] = {
            "state": "NOT_STARTED",
            "phase": "PREPARE",
            "completedSteps": 0,
            "step": "Ready after two governed test SmartDeeds are confirmed.",
            "message": (
                "A coadministrator will complete two Stripe test purchases: "
                "one delivered to its approved vault and one fully refunded."
            ),
            "assignedRole": "coadmin",
            "walletTransaction": None,
        }
    else:
        payload = record.get("payload")
        details = payload if isinstance(payload, Mapping) else {}
        status_value = {
            "jobId": record.get("jobId"),
            "state": record.get("state"),
            "phase": details.get("phase") or "PREPARE",
            "completedSteps": details.get("completedSteps") or 0,
            "step": details.get("step") or "",
            "message": details.get("message") or "",
            "walletTransaction": details.get("walletTransaction"),
            "review": details.get("review"),
            "evidenceDigest": details.get("evidenceDigest"),
            "updatedAt": record.get("updatedAt"),
        }
    review = status_value.get("review")
    amount_label = (
        str(review.get("amountLabel"))
        if isinstance(review, Mapping)
        else "two fixed Stripe test charges"
    )
    expected_outcome = (
        str(review.get("expectedOutcome"))
        if isinstance(review, Mapping)
        else "DELIVERED or REFUND"
    )
    return {
        "status": status_value,
        "decisionReceipt": {
            "title": "Verify the Stripe voucher payment path",
            "network": "Stripe test mode and Testnet11",
            "financialEffect": (
                f"Uses {amount_label} in Stripe test mode and Testnet11 mojos only. "
                "No real money or customer assets move."
            ),
            "customerImpact": (
                "Proves final Stripe payment, 2-of-3 validation, voucher issuance, "
                "KoS submission, SmartDeed delivery, and exact refund recovery."
            ),
            "reversibility": (
                "Both purchases use Stripe test mode. One voucher is consumed by "
                "delivery; the second must return its exact collected test amount."
            ),
            "requiredApprovers": (
                "One enrolled coadministrator runs the check; the normal validator "
                "quorum and protocol rules authorize settlement"
            ),
            "expectedResult": (
                f"This step expects {expected_outcome}. Readiness passes only after "
                "mempool observation and confirmed Testnet11 outputs are recorded."
            ),
        },
    }


def _task_for(record: Mapping[str, Any], readiness: list[dict[str, Any]]) -> dict[str, Any]:
    state = str(record["state"])
    ceremony_complete = state == "locked"
    enrolled = sum(bool(item.get("consumed_at")) for item in record["invitations"])
    if enrolled < 3:
        return {
            "title": "Finish administrator enrollment",
            "body": f"{enrolled} of 3 administrators are enrolled.",
            "assignedRole": "owner" if enrolled == 0 else "administrator",
            "action": "enrollment",
        }
    # These records bind deterministic plan coordinates. Requiring them before
    # the plan exists creates a circular deployment dependency. This changes
    # task ordering only: readiness and final preflight remain fail-closed.
    plan_pending = state in {"roster_open", "roster_frozen"}
    plan_dependencies = {"authorityV3Evm", "authorityV3Review"}

    def relevant(item: Mapping[str, Any]) -> bool:
        return (
            (item.get("blocksCeremony", True) or (ceremony_complete and not is_disposable(record)))
            and not (plan_pending and item.get("id") in plan_dependencies)
        )

    blocked = next(
        (
            item
            for item in readiness
            if item["status"] == "Blocked"
            and relevant(item)
        ),
        None,
    )
    if blocked:
        return {
            "title": blocked["title"],
            "body": blocked["impact"],
            "assignedRole": blocked["assignedRole"],
            "action": blocked.get("action"),
        }
    unfinished = next(
        (
            item
            for item in readiness
            if item["status"] in {"Needs action", "Waiting"}
            and relevant(item)
        ),
        None,
    )
    if unfinished:
        return {
            "title": unfinished["title"],
            "body": unfinished["impact"],
            "assignedRole": unfinished["assignedRole"],
            "action": unfinished.get("action"),
        }
    if (
        state in {"planned", "plan_approved"}
        and int(record.get("plan_expires_at") or 0) <= int(time.time())
    ):
        return {
            "title": "Renew the expired launch plan",
            "body": (
                "The exact reviewed inputs will be rebuilt with a new expiry. "
                "Every prior plan signature will be cleared."
            ),
            "assignedRole": "owner",
            "action": "renewPlan",
        }
    broadcast = record.get("broadcast")
    if (
        state == "broadcast"
        and isinstance(broadcast, Mapping)
        and broadcast.get("reservationState") == "RESERVED"
    ):
        return {
            "title": "Reconcile the exact reserved launch bundle",
            "body": (
                "Open a fresh owner-approved broadcast window, then replay only "
                "the already reserved bundle. A replacement genesis is forbidden."
            ),
            "assignedRole": "owner",
            "action": "broadcast",
        }
    mapping = {
        "roster_open": ("Confirm the administrator team", "technical-coadmin", "freezeRoster"),
        "roster_frozen": ("Create and review launch plan", "technical-coadmin", "buildPlan"),
        "planned": ("Approve the launch plan", "administrator", "signPlan"),
        "plan_approved": ("Run final launch check", "owner", "preflight"),
        "broadcast": ("Wait for Testnet11 confirmation", "system", "confirm"),
        "confirmed": ("Create the signed launch record", "system", "createArtifact"),
        "artifact_pending": ("Approve the launch archive", "administrator", "signArtifact"),
        "artifact_signed": ("Seal the launch archive", "owner", "finalize"),
        "locked": ("Launch complete", "owner", "openOperations"),
    }
    title, role, action = mapping.get(
        state, ("Review launch status", "administrator", "refresh")
    )
    return {"title": title, "body": "", "assignedRole": role, "action": action}


def _audit_readiness(
    settings: Settings,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """Describe the plan-bound audit gate without blocking plan creation.

    The guided review class is fixed when the server creates the draft.  An
    independent approval cannot be meaningfully checked until that draft has
    an owner-plus-one approved plan, because the approval binds the ceremony
    id, plan hash, and deterministic simulation bundle id.
    """

    review_class = str(record.get("draft", {}).get("reviewClass", ""))
    approval_installed = Path(settings.genesis_audit_approval_path).is_file()
    if review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS:
        return {
            "id": "planAudit",
            "title": "Disposable internal Testnet11 review",
            "status": "Healthy",
            "impact": (
                "This server-selected disposable flow produces an unaudited "
                "internal approval at strict preflight. It is not the official "
                "independently reviewed genesis."
            ),
            "assignedRole": "system",
            "blocksCeremony": False,
            "evidence": {
                "reviewClass": review_class,
                "auditApprovalInstalled": approval_installed,
                "auditApprovalRequired": False,
            },
        }
    if review_class != INDEPENDENT_REVIEW_CLASS:
        return {
            "id": "planAudit",
            "title": "Unsupported launch review policy",
            "status": "Blocked",
            "impact": "The protected server review class is not supported.",
            "assignedRole": "technical-coadmin",
            "action": "repairReviewPolicy",
            "evidence": {"reviewClass": review_class},
        }

    plan_is_approved = str(record.get("state")) in PLAN_BOUND_AUDIT_STATES
    if not plan_is_approved:
        return {
            "id": "planAudit",
            "title": "Independent plan audit follows plan approval",
            "status": "Waiting",
            "impact": (
                "After the owner and one coadministrator approve the exact plan, "
                "install its independent audit approval before final preflight."
            ),
            "assignedRole": "technical-coadmin",
            "blocksCeremony": False,
            "evidence": {
                "reviewClass": review_class,
                "auditApprovalInstalled": approval_installed,
                "auditApprovalRequired": False,
            },
        }
    return {
        "id": "planAudit",
        "title": "Independent plan audit",
        "status": "Healthy" if approval_installed else "Blocked",
        "impact": (
            "The plan-bound audit approval is installed and will be validated "
            "against the exact plan and live Sepolia deployment at strict preflight."
            if approval_installed
            else (
                "The approved plan requires a matching independent audit approval "
                "before strict preflight."
            )
        ),
        "assignedRole": "technical-coadmin",
        "action": None if approval_installed else "installPlanAudit",
        "evidence": {
            "reviewClass": review_class,
            "auditApprovalInstalled": approval_installed,
            "auditApprovalRequired": True,
        },
    }


def _require_preplan_evm_evidence(settings: Settings) -> None:
    if not Path(settings.genesis_evm_deployment_path).is_file():
        raise GenesisConflict(
            "install the protected Sepolia deployment evidence before building the plan"
        )


async def _readiness(
    request: Request,
    settings: Settings,
    store: GenesisStore,
    record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    release: dict[str, Any] | None = None
    try:
        release = _load_release_evidence(settings)
        items.append(
            {
                "id": "release",
                "title": "Reviewed release",
                "status": "Healthy",
                "impact": f"{release['releaseTag']} is pinned to all nine source commits.",
                "assignedRole": "system",
                "evidence": {
                    "manifestHash": release["manifestHash"],
                    "fileSha256": release["fileSha256"],
                },
            }
        )
    except GenesisStoreError as exc:
        items.append(
            {
                "id": "release",
                "title": "Release package needs attention",
                "status": "Blocked",
                "impact": (
                    "The reviewed release package is not installed correctly. "
                    "A technical coadministrator must repair it before launch."
                ),
                "assignedRole": "technical-coadmin",
                "action": "replaceReleaseEvidence",
                "evidence": {"technicalReason": str(exc)},
            }
        )

    try:
        plan_evidence = _plan_template_evidence(settings, record)
        items.append(
            {
                "id": "planInputs",
                "title": "Fixed launch coordinates",
                "status": "Healthy",
                "impact": (
                    "The reviewed EVM, validator, treasury, and KoS coordinates "
                    "are ready for the signed launch plan."
                ),
                "assignedRole": "system",
                "evidence": plan_evidence,
            }
        )
    except (GenesisStoreError, ValueError) as exc:
        items.append(
            {
                "id": "planInputs",
                "title": "Finish the fixed launch coordinates",
                "status": "Blocked",
                "impact": (
                    "The validator, treasury, EVM, and protected mint-signer "
                    "coordinates are not all installed yet. No administrator "
                    "should enter or paste them in the browser."
                ),
                "assignedRole": "technical-coadmin",
                "action": "replacePlanEvidence",
                "evidence": {"technicalReason": str(exc)},
            }
        )

    deployment_path = Path(settings.genesis_evm_deployment_path)
    evm_evidence_ready = deployment_path.is_file()
    items.append(
        {
            "id": "evmEvidence",
            "title": "Sepolia identity contracts",
            "status": "Waiting" if evm_evidence_ready else "Blocked",
            "blocksCeremony": not evm_evidence_ready,
            "impact": (
                "Deployment evidence is installed but not yet verified. Strict preflight "
                "must confirm the selected chain, review, receipts and contract code."
                if evm_evidence_ready
                else (
                    "The Sepolia deployment evidence is not installed. "
                    "A technical coadministrator must finish this protected server step."
                )
            ),
            "assignedRole": "technical-coadmin",
            "action": None if evm_evidence_ready else "installEvmEvidence",
            "evidence": {
                "deploymentEvidenceInstalled": deployment_path.is_file(),
                "deploymentVerified": False,
                "requiredConfirmations": settings.genesis_sepolia_confirmations,
            },
        }
    )
    items.append(_audit_readiness(settings, record))

    recovery_kits = store.recovery_kits(str(record["ceremony_id"]))
    recovery_ready = (
        [int(item["slot"]) for item in recovery_kits] == [0, 1, 2]
        and all(
            item["offlineCopyConfirmed"]
            and item["secondDeviceConfirmed"]
            for item in recovery_kits
        )
    )
    items.append(
        {
            "id": "adminRecoveryKits",
            "title": "Administrator recovery kits",
            "status": "Healthy" if recovery_ready else "Needs action",
            "impact": (
                "All three administrators proved an offline recovery copy "
                "on a second device. Optional Drive backups are recorded "
                "separately."
                if recovery_ready
                else (
                    "Each administrator must make an offline recovery copy "
                    "and prove it works on a second device before launch."
                )
            ),
            "assignedRole": "administrator",
            "action": None if recovery_ready else "securityAccess",
            "evidence": {
                "completed": len(recovery_kits),
                "required": 3,
                "driveBackups": sum(
                    item["backupStatus"] == "VERIFIED"
                    for item in recovery_kits
                ),
                "driveBackupRequired": False,
            },
        }
    )

    try:
        disposable = require_scope(settings, record)
    except ValueError as exc:
        disposable = False
        items.append({"id": "disposableScope", "title": "Disposable scope mismatch",
                      "status": "Blocked", "impact": str(exc), "assignedRole": "technical-coadmin"})
    if disposable:
        for name, title in (("authorityV3Evm", "EVM recovery setup deferred"),
                            ("authorityV3Review", "Independent recovery review deferred")):
            items.append({"id": name, "title": title, "status": "Waiting",
                          "impact": "Deferred for this disposable vault/identity test. Replace this genesis before bridge or sales testing.",
                          "assignedRole": "technical-coadmin", "blocksCeremony": False,
                          "deferredForDisposable": True, "action": None,
                          "evidence": {"auditStatus": "unaudited", "replaceBeforeBridgeTesting": True}})
    else:
        authority_evidence: dict[str, Any] | None = None
        try:
            authority_evidence = load_governance_evidence(settings)
            validate_governance_roster(
                record,
                recovery_kits,
                authority_evidence,
            )
            items.append(
                {
                    "id": "authorityV3Evm",
                    "title": "Protected administrator authority",
                    "status": "Healthy",
                    "impact": (
                        "The three identity Safes, owner-plus-one root, "
                        "recovery coordinator, guards, and delays match the "
                        "administrator recovery roster."
                    ),
                    "assignedRole": "system",
                    "evidence": {
                        "artifactHash": authority_evidence[
                            "artifactHash"
                        ],
                        "authorityRule": "Owner plus either coadministrator",
                        "identitySafes": 3,
                        "routineDelaySeconds": 86_400,
                        "lostKeyDelaySeconds": 604_800,
                    },
                }
            )
        except (GenesisStoreError, KeyError, TypeError, ValueError) as exc:
            items.append(
                {
                    "id": "authorityV3Evm",
                    "title": "Finish administrator protection",
                    "status": "Blocked",
                    "impact": (
                        "The protected Safe hierarchy and recovery roster are "
                        "not installed as one matching Authority V3 release."
                    ),
                    "assignedRole": "technical-coadmin",
                    "action": "installAuthorityV3",
                    "evidence": {"technicalReason": str(exc)},
                }
            )

        try:
            if release is None:
                raise AuthorityV3ReviewError(
                    "reviewed release evidence is unavailable"
                )
            if authority_evidence is None:
                raise AuthorityV3ReviewError(
                    "Authority V3 EVM evidence is unavailable"
                )
            inventory = await _run_worker(
                {"operation": "authorityV3Inventory"}
            )
            review = load_authority_v3_review(
                settings,
                source_shas=release["sourceShas"],
                authority_inner_mod_hash=str(
                    inventory["adminAuthorityInnerModHash"]
                ),
                governance_evidence_hash=str(
                    authority_evidence["artifactHash"]
                ),
            )
            items.append(
                {
                    "id": "authorityV3Review",
                    "title": "Independent recovery review",
                    "status": "Healthy",
                    "impact": (
                        "An independent reviewer approved the Chialisp "
                        "wrapper, MIPS composition, Safe recovery module, "
                        "and authority guards for this exact release."
                    ),
                    "assignedRole": "system",
                    "evidence": review,
                }
            )
        except (
            AuthorityV3ReviewError,
            GenesisStoreError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            items.append(
                {
                    "id": "authorityV3Review",
                    "title": "Independent recovery review required",
                    "status": "Blocked",
                    "impact": (
                        "A focused independent review of all four recovery "
                        "trust boundaries must approve this exact release "
                        "before launch."
                    ),
                    "assignedRole": "technical-coadmin",
                    "action": "installAuthorityReview",
                    "evidence": {"technicalReason": str(exc)},
                }
            )

    validator_pubkeys: list[bytes] = []
    for value in settings.zkpassport_validator_pubkeys:
        try:
            validator_pubkeys.append(bytes.fromhex(value.removeprefix("0x")))
        except ValueError:
            validator_pubkeys.append(b"")
    validator_credentials = (
        settings.zkpassport_validator_mtls_ca_path,
        settings.zkpassport_validator_mtls_cert_path,
        settings.zkpassport_validator_mtls_key_path,
    )
    validators_configured = (
        len(settings.zkpassport_validator_urls) == 3
        and len(validator_pubkeys) == 3
        and len(set(validator_pubkeys)) == 3
        and all(len(value) == 48 and value != b"\x00" * 48 for value in validator_pubkeys)
        and all(value and Path(value).is_file() for value in validator_credentials)
    )
    items.append(
        {
            "id": "validators",
            "title": "Independent validator team",
            "status": "Healthy" if validators_configured else "Blocked",
            "impact": (
                "Three distinct validator identities and their private connections "
                "are configured. Live health is checked again before launch."
                if validators_configured
                else (
                    "Three distinct validators are not fully connected to this "
                    "release. A technical coadministrator must finish their private setup."
                )
            ),
            "assignedRole": "technical-coadmin",
            "action": None if validators_configured else "configureValidators",
            "evidence": {
                "configuredValidators": min(
                    len(settings.zkpassport_validator_urls),
                    len(validator_pubkeys),
                ),
                "requiredValidators": 3,
                "threshold": settings.zkpassport_validator_threshold,
                "privateCredentialsInstalled": all(
                    value and Path(value).is_file() for value in validator_credentials
                ),
            },
        }
    )

    try:
        provider = getattr(request.app.state, "coinset", None)
        if provider is None:
            raise RuntimeError("Chia provider is unavailable")
        provider_status = provider.status() if hasattr(provider, "status") else {}
        fallback = provider_status.get("activeProvider") == "fallback"
        items.append(
            {
                "id": "chiaNode",
                "title": "Local Chia node",
                "status": "Needs action" if fallback else "Healthy",
                "impact": (
                    "The backup chain-data service is active. Launching should wait "
                    "for the primary Testnet11 node."
                    if fallback
                    else "The primary Testnet11 provider is available."
                ),
                "assignedRole": "technical-coadmin",
                "evidence": provider_status,
            }
        )
    except Exception as exc:  # noqa: BLE001
        items.append(
            {
                "id": "chiaNode",
                "title": "Local Chia node unavailable",
                "status": "Blocked",
                "impact": (
                    "The primary Testnet11 node cannot be reached. A technical "
                    "coadministrator must restore it before launch."
                ),
                "assignedRole": "technical-coadmin",
                "action": "restoreChiaNode",
                "evidence": {"technicalReason": str(exc)},
            }
        )

    fee_submitter = getattr(request.app.state, "protocol_submitter", None)
    fee_funding_healthy = (
        settings.protocol_fee_funding_enabled
        and fee_submitter is not None
    )
    items.append(
        {
            "id": "networkFee",
            "title": "Network fee funding",
            "status": "Healthy" if fee_funding_healthy else "Blocked",
            "impact": (
                "The fountain till will add the current medium Testnet11 fee "
                "and confirm the launch in the local mempool."
                if fee_funding_healthy
                else (
                    "The protected fee account is not ready. A technical "
                    "coadministrator must finish it before launch."
                )
            ),
            "assignedRole": "technical-coadmin",
            "action": None if fee_funding_healthy else "configureFeeTill",
            "evidence": {
                "targetSeconds": settings.protocol_medium_fee_target_seconds,
                "minimumMojos": settings.protocol_minimum_fee_mojos,
                "maximumMojos": settings.protocol_maximum_fee_mojos,
                "source": "local-full-node",
            },
        }
    )

    try:
        ownership_store = get_ownership_activation_store(settings)
        ownership = _rail_phase_status(settings, ownership_store)
        done = ownership["state"] == "DONE"
        rail_state_message = {
            "AWAITING_APPROVALS": "The fixed handoff is waiting for owner-plus-one approval.",
            "READY_TO_BROADCAST": "The reviewed handoff is ready to submit.",
            "BROADCAST_PENDING": "The handoff was submitted and is being tracked.",
            "CONFIRMING": "The handoff is confirming on Base Sepolia.",
            "SCHEDULED": "The 24-hour safety delay is active.",
            "WAITING_FOR_SCHEDULE": "The wizard is waiting for the safety delay to appear.",
            "WAITING_FOR_DELAY": "The 24-hour safety delay is active.",
            "READY_TO_EXECUTE": "Fresh owner-plus-one approval is ready.",
        }.get(str(ownership["state"]), "The fixed handoff still needs administrator action.")
        items.append(
            {
                "id": "railOwnership",
                "title": "Base Sepolia rail ownership",
                "status": "Healthy" if done else "Waiting",
                "impact": (
                    "Safe and timelock ownership is active."
                    if done
                    else rail_state_message
                ),
                "assignedRole": "administrator",
                "action": None if done else "railOwnership",
                "blocksCeremony": False,
                "evidence": ownership,
            }
        )
    except (OwnershipActivationError, HTTPException) as exc:
        items.append(
            {
                "id": "railOwnership",
                "title": "Base Sepolia rail ownership",
                "status": "Blocked",
                "impact": (
                    "The fixed Safe and timelock handoff is not ready for "
                    "administrator review. No payment rail is active."
                ),
                "assignedRole": "administrator",
                "action": "railOwnership",
                "blocksCeremony": False,
                "evidence": {
                    "technicalReason": str(getattr(exc, "detail", exc)),
                },
            }
        )

    try:
        _rehearsal, digest = require_completed_rehearsal(
            settings,
            store,
            str(record["ceremony_id"]),
        )
        items.append(
            {
                "id": "settlement",
                "title": "Customer payment activation",
                "status": "Healthy",
                "impact": (
                    "Test payment, SmartDeed delivery, and exact-refund evidence passed. "
                    "Presale and purchase windows may now be proposed."
                ),
                "assignedRole": "technical-coadmin",
                "evidence": {"fileSha256": digest},
                "blocksCeremony": False,
            }
        )
    except (GenesisStoreError, AttributeError) as exc:
        ceremony_complete = str(record["state"]) == "locked"
        items.append(
            {
                "id": "settlement",
                "title": (
                    "Activate customer payments"
                    if ceremony_complete
                    else "Customer payment test follows launch"
                ),
                "status": "Waiting",
                "impact": (
                    (
                        "The required test delivery and exact refund have not passed. "
                        "Customer presales and purchases remain closed."
                    )
                    if ceremony_complete
                    else (
                        "After genesis and the first governed test deed exist, a "
                        "coadministrator will prove delivery and an exact refund. "
                        "Presales and purchases stay locked until it passes."
                    )
                ),
                "assignedRole": "technical-coadmin",
                "action": "settlementRehearsal" if ceremony_complete else None,
                "blocksCeremony": False,
                "evidence": {"technicalReason": str(exc)} if ceremony_complete else None,
            }
        )

    funding = store.funding_receipt(str(record["ceremony_id"]))
    funding_healthy = funding is not None and funding["state"] == "confirmed"
    items.append(
        {
            "id": "funding",
            "title": "Ceremony funding",
            "status": "Healthy" if funding_healthy else "Waiting",
            "impact": (
                "All nine fixed ceremony inputs are confirmed, including the "
                "required bridge reserve."
                if funding_healthy
                else "Create and confirm the fixed ceremony funding transaction."
            ),
            "assignedRole": "owner",
            "action": None if funding_healthy else "funding",
            "evidence": funding,
        }
    )
    return items


def _public_ceremony(record: Mapping[str, Any], store: GenesisStore) -> dict[str, Any]:
    profiles = store.profiles(str(record["ceremony_id"]))
    administrators = []
    invitations = {int(item["slot"]): item for item in record["invitations"]}
    for slot in (1, 2, 3):
        invitation = invitations.get(slot, {})
        administrators.append(
            {
                "slot": slot,
                "role": "Owner" if slot == 1 else "Coadministrator",
                "profile": profiles.get(slot),
                "enrolled": bool(invitation.get("consumed_at")),
                "wallet": invitation.get("wallet_address"),
                "invitationExpiresAt": invitation.get("expires_at"),
            }
        )
    return {
        "ceremonyId": record["ceremony_id"],
        "state": record["state"],
        "network": record["network"],
        "evmChainId": _ceremony_chain(record),
        "launchProfile": record["draft"].get("launchProfile"),
        "reviewClass": record["draft"].get("reviewClass"),
        "enrollmentCommitments": _selected_commitments(record),
        "createdAt": record["created_at"],
        "updatedAt": record["updated_at"],
        "administrators": administrators,
        "planHash": record.get("plan_hash"),
        "planExpiresAt": record.get("plan_expires_at"),
        "planSignatureSlots": [
            int(item["slot"]) for item in record.get("plan_signatures", [])
        ],
        "spendBundleId": record.get("spend_bundle_id"),
        "artifactHash": record.get("artifact_hash"),
        "artifactSignatureSlots": [
            int(item["slot"]) for item in record.get("artifact_signatures", [])
        ],
    }


@router.get("/public")
async def public_launch_status(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    return {
        "enabled": settings.launch_control_enabled,
        "network": "testnet11",
        "title": "Alpha Protocol Launch",
        "notice": "TESTNET, NO REAL INVESTMENT OR LEGAL RIGHT.",
    }


@router.post("/claim")
async def claim_owner_link(
    body: OwnerClaimRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    if not settings.launch_control_enabled:
        raise HTTPException(status_code=503, detail="Alpha launch control is disabled.")
    if not settings.launch_owner_claim_token or not secrets.compare_digest(
        body.token, settings.launch_owner_claim_token
    ):
        raise HTTPException(status_code=403, detail="Owner launch link is invalid.")
    try:
        release = _load_release_evidence(settings)
        selection = _claim_selection(settings)
        active = store.claim_or_create_draft(
            token_hash=_token_hash(body.token),
            ceremony_id=selection["enrollmentActivation"]["deploymentId"] if selection else "0x" + secrets.token_hex(32),
            draft={
                "schemaVersion": 2,
                "sourceManifestVersion": SOURCE_MANIFEST_VERSION,
                "network": "testnet11",
                "evmChainId": 11155111,
                **(selection or {}),
                "reviewClass": settings.launch_genesis_review_class,
                "releaseTag": release["releaseTag"],
                "releaseEvidenceHash": release["fileSha256"],
                "sourceShas": release["sourceShas"],
            },
        )
        if selection and (active["ceremony_id"] != selection["enrollmentActivation"]["deploymentId"]
                or any(active["draft"].get(k) != v for k,v in selection.items())
                or active["draft"].get("releaseEvidenceHash") != release["fileSha256"]):
            raise GenesisConflict("existing ceremony differs from protected selected launch")
        if not selection and _ceremony_chain(active) != 11155111:
            raise GenesisConflict("selected ceremony cannot resume as a legacy claim")
        ceremony_id = str(active["ceremony_id"])
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
        store.issue_invitation(
            ceremony_id,
            slot=OWNER_SLOT,
            token_hash=_token_hash(token),
            nonce="0x" + secrets.token_hex(32),
            expires_at=expires_at,
        )
        store.set_profile(
            ceremony_id,
            slot=OWNER_SLOT,
            display_name=body.display_name,
            role_label="Owner",
            email=str(body.email) if body.email else None,
            timezone=body.timezone,
            reminders_enabled=True,
        )
        session_token, session_expiry = _issue_session(
            settings,
            ceremony_id=ceremony_id,
            slot=OWNER_SLOT,
            wallet=None,
            setup=True,
        )
        _set_session_cookie(response, settings, session_token, session_expiry)
        return {
            "claimed": True,
            "ceremonyId": ceremony_id,
            "ownerEnrollmentToken": token,
            "enrollmentExpiresAt": expires_at,
            "sessionExpiresAt": session_expiry,
        }
    except GenesisStoreError as exc:
        code = 410 if isinstance(exc, GenesisExpired) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post("/invitations/prepare")
async def prepare_launch_invitation(
    body: InvitationPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        invitation, typed = _invitation_typed_data(store, body.token, body.wallet)
        return {
            "ceremonyId": invitation["ceremony_id"],
            "slot": invitation["slot"],
            "expiresAt": invitation["expires_at"],
            "typedData": typed,
            "ceremonyBinding": _ceremony_binding(store.get(str(invitation["ceremony_id"]))),
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/owner/enrollment")
async def reissue_owner_enrollment(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    if not session.setup or session.slot != OWNER_SLOT or session.wallet:
        raise HTTPException(status_code=403, detail="Owner setup is already complete.")
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
    try:
        store.issue_invitation(
            session.ceremony_id,
            slot=OWNER_SLOT,
            token_hash=_token_hash(token),
            nonce="0x" + secrets.token_hex(32),
            expires_at=expires_at,
            replace_live=True,
        )
        return {
            "ownerEnrollmentToken": token,
            "enrollmentExpiresAt": expires_at,
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/invitations/accept")
async def accept_launch_invitation(
    body: InvitationAcceptRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    from .genesis import InvitationAcceptRequest as GenesisInvitationAcceptRequest

    return await accept_invitation(
        GenesisInvitationAcceptRequest(
            token=body.token, wallet=body.wallet, signature=body.signature
        ),
        store,
    )


@router.post("/auth/challenge")
async def resume_challenge(
    body: ResumeChallengeRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    if not settings.launch_control_enabled:
        raise HTTPException(status_code=503, detail="Alpha launch control is disabled.")
    try:
        wallet = normalize_evm_address(body.wallet, "wallet").lower()
        record = store.active()
        if record is None:
            history = store.list_ceremonies(limit=1)
            record = history[0] if history else None
        if record is None:
            raise GenesisNotFound("no active alpha launch")
        from .admin_roster import current_launch_authority
        authority = current_launch_authority(settings, store, str(record["ceremony_id"]))
        slot = next((slot for slot, identity in authority.wallets.items() if identity == wallet), None)
        if slot is None:
            raise GenesisNotFound("wallet is not enrolled for the active launch")
        nonce = "0x" + secrets.token_hex(32)
        expires_at = int(time.time()) + min(300, settings.challenge_ttl_seconds)
        store.create_auth_challenge(
            str(record["ceremony_id"]),
            settings=settings,
            slot=slot,
            wallet_address=wallet,
            nonce_hash=_token_hash(nonce),
            expires_at=expires_at,
        )
        return {
            "expiresAt": expires_at,
            "nonce": nonce,
            "ceremonyBinding": _ceremony_binding(record),
            "typedData": _resume_typed_data(
                ceremony_id=str(record["ceremony_id"]),
                chain_id=_ceremony_chain(record),
                slot=slot,
                wallet=wallet,
                nonce=nonce,
                expires_at=expires_at,
            ),
        }
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=403, detail="Wallet is not enrolled for this launch.") from exc


@router.post("/auth/login")
async def resume_login(
    body: ResumeLoginRequest,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        wallet = normalize_evm_address(body.wallet, "wallet").lower()
        challenge = store.auth_challenge(_token_hash(body.nonce))
        if challenge["consumed_at"] is not None or int(challenge["expires_at"]) < int(
            time.time()
        ):
            raise GenesisExpired("administrator challenge expired or was already used")
        typed = _resume_typed_data(
            ceremony_id=str(challenge["ceremony_id"]),
            chain_id=_ceremony_chain(store.get(str(challenge["ceremony_id"]))),
            slot=int(challenge["slot"]),
            wallet=wallet,
            nonce=body.nonce,
            expires_at=int(challenge["expires_at"]),
        )
        recovered = recover_evm_signer(typed, body.signature)
        if recovered.address.lower() != wallet:
            raise GenesisConflict("signature wallet changed")
        store.consume_auth_challenge(
            settings=settings,
            nonce_hash=_token_hash(body.nonce), wallet_address=wallet
        )
        token, expires_at = _issue_session(
            settings,
            ceremony_id=str(challenge["ceremony_id"]),
            slot=int(challenge["slot"]),
            wallet=wallet,
            setup=False,
        )
        _set_session_cookie(response, settings, token, expires_at)
        return {
            "authenticated": True,
            "slot": int(challenge["slot"]),
            "role": "owner" if int(challenge["slot"]) == 1 else "coadmin",
            "expiresAt": expires_at,
        }
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/auth/logout")
async def launch_logout(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, bool]:
    _clear_legacy_session_cookie(response, settings)
    response.delete_cookie(LAUNCH_COOKIE_NAME, path=settings.launch_cookie_path)
    return {"authenticated": False}


@router.get("/workspace")
async def launch_workspace(
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    # Upgrade a validated existing session without a new signature or enrollment.
    # Preserve its original expiry; visiting the workspace cannot extend access.
    _set_session_cookie(
        response, settings, request.cookies[LAUNCH_COOKIE_NAME], session.expires_at
    )
    record = store.get(session.ceremony_id)
    readiness = await _readiness(request, settings, store, record)
    action_approvals: dict[str, Any] = {}
    funding = store.funding_receipt(session.ceremony_id)
    if funding:
        funding_action_id, _ = _funding_payload(store, session.ceremony_id)
        action_approvals["funding"] = store.action_approvals(
            session.ceremony_id, funding_action_id, settings=settings
        )
    for gate_name in store.gates(session.ceremony_id):
        gate_action_id, _ = _gate_payload(store, session.ceremony_id, gate_name)
        action_approvals[f"gate:{gate_name}"] = store.action_approvals(
            session.ceremony_id, gate_action_id, settings=settings
        )
    abandon_intent = store.latest_action_intent(session.ceremony_id, "abandon")
    if abandon_intent and abandon_intent["state"] == "prepared":
        action_approvals["abandon"] = store.action_approvals(
            session.ceremony_id, str(abandon_intent["actionId"]), settings=settings
        )
    gate_states = store.gates(session.ceremony_id)
    from .voucher_rail_policy import xch_voucher_control
    xch_control = xch_voucher_control(settings)
    for gate_name, gate in gate_states.items():
        if gate["state"] == "open":
            try:
                store.authorized_gate(settings, session.ceremony_id, gate_name)
            except GenesisStoreError as exc:
                gate["state"] = "closed"
                gate["unavailableReason"] = str(exc)
    if not xch_control["canOpen"] and "xchVouchers" in gate_states:
        gate_states["xchVouchers"]["state"] = "closed"
        gate_states["xchVouchers"]["unavailableReason"] = xch_control["reason"]
    return {
        "session": {
            "slot": session.slot,
            "role": "owner" if session.slot == 1 else "coadmin",
            "wallet": session.wallet,
            "setup": session.setup,
            "expiresAt": session.expires_at,
        },
        "launch": _public_ceremony(record, store),
        "readiness": readiness,
        "nextTask": _task_for(record, readiness),
        "gates": gate_states,
        "voucherRailControls": {"xch": xch_control},
        "actionApprovals": action_approvals,
        "notice": "TESTNET, NO REAL INVESTMENT OR LEGAL RIGHT.",
    }


@router.get("/audit")
async def launch_audit(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
    after: int = 0,
) -> dict[str, Any]:
    _require_wallet_session(session)
    return {
        "events": store.audit_events(session.ceremony_id, after_event_id=after)
    }


@router.put("/profile")
async def update_launch_profile(
    body: ProfileUpdateRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return store.set_profile(
        session.ceremony_id,
        slot=session.slot,
        display_name=body.display_name,
        role_label="Owner" if session.slot == 1 else "Coadministrator",
        email=str(body.email) if body.email else None,
        timezone=body.timezone,
        reminders_enabled=body.reminders_enabled,
    )


@router.post("/invitations/{slot}")
async def issue_launch_invitation(
    slot: int,
    body: InviteProfileRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    if slot not in COADMIN_SLOTS:
        raise HTTPException(status_code=400, detail="Only Admin 2 or Admin 3 may be invited.")
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
    try:
        store.issue_invitation(
            session.ceremony_id,
            slot=slot,
            token_hash=_token_hash(token),
            nonce="0x" + secrets.token_hex(32),
            expires_at=expires_at,
            replace_live=True,
        )
        profile = store.set_profile(
            session.ceremony_id,
            slot=slot,
            display_name=body.display_name,
            role_label="Coadministrator",
            email=str(body.email) if body.email else None,
            timezone=body.timezone,
            reminders_enabled=body.reminders_enabled,
        )
        return {
            "slot": slot,
            "profile": profile,
            "expiresAt": expires_at,
            "invitationFragment": "#launch-invite=" + token,
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/roster/freeze")
async def guided_freeze_roster(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return await freeze_roster(session.ceremony_id, store)


@router.get("/rail-ownership")
def guided_rail_ownership(
    settings: Annotated[Settings, Depends(get_settings)],
    ownership_store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        status_value = _rail_phase_status(settings, ownership_store)
        return {
            "status": status_value,
            "decisionReceipt": _rail_decision_receipt(status_value),
        }
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/rail-ownership/sign")
def guided_sign_rail_ownership(
    body: RailSignatureSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    ownership_store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    try:
        current = _rail_phase_status(settings, ownership_store)
        if current["phase"] != body.phase:
            raise GenesisConflict("rail ownership phase changed before signing")
        _require_rail_session_signature(
            current, signature=body.signature, session=session
        )
        request = OwnershipSignatureRequest(signature=body.signature)
        status_value = (
            sign_ownership_activation(request, settings, ownership_store)
            if body.phase == "schedule"
            else sign_ownership_execution(request, settings, ownership_store)
        )
        return {
            "status": status_value,
            "decisionReceipt": _rail_decision_receipt(status_value),
        }
    except (GenesisStoreError, OwnershipActivationError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/rail-ownership/broadcast")
def guided_record_rail_broadcast(
    body: RailBroadcastSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    ownership_store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        current = _rail_phase_status(settings, ownership_store)
        if current["phase"] != body.phase:
            raise GenesisConflict("rail ownership phase changed before broadcast")
        request = OwnershipBroadcastRequest(transactionHash=body.transaction_hash)
        status_value = (
            record_ownership_activation_broadcast(request, settings, ownership_store)
            if body.phase == "schedule"
            else record_ownership_execution_broadcast(
                request, settings, ownership_store
            )
        )
        return {
            "status": status_value,
            "decisionReceipt": _rail_decision_receipt(status_value),
        }
    except (GenesisStoreError, OwnershipActivationError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/settlement-rehearsal")
async def guided_settlement_rehearsal_status(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    current = store.settlement_rehearsal(session.ceremony_id)
    if current is None:
        return _rehearsal_result(None)
    if current["state"] in {"SUCCEEDED", "FAILED"}:
        return _rehearsal_result(current)
    try:
        remote = await rehearsal_status(settings, job_id=str(current["jobId"]))
        return _rehearsal_result(
            _store_rehearsal_status(
                settings, store, session.ceremony_id, remote
            )
        )
    except (GenesisStoreError, LaunchRehearsalError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/settlement-rehearsal/start")
async def guided_start_settlement_rehearsal(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_coadmin(session)
    launch = store.get(session.ceremony_id)
    if launch["state"] != "locked":
        raise HTTPException(
            status_code=409,
            detail=(
                "Complete genesis first. The payment test requires the signed "
                "genesis artifact, an approved test vault, and a governed test deed."
            ),
        )
    current = store.settlement_rehearsal(session.ceremony_id)
    if current and current["state"] != "FAILED":
        return _rehearsal_result(current)
    try:
        record = store.get(session.ceremony_id)
        release_hash = str(record["draft"].get("releaseEvidenceHash") or "")
        if not HEX32_RE.fullmatch(release_hash):
            raise GenesisConflict("the release evidence hash is unavailable")
        remote = await start_rehearsal(
            settings,
            ceremony_id=session.ceremony_id,
            release_evidence_hash=release_hash,
            wallet_address=session.wallet,
        )
        return _rehearsal_result(
            _store_rehearsal_status(
                settings, store, session.ceremony_id, remote
            )
        )
    except (GenesisStoreError, LaunchRehearsalError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/settlement-rehearsal/transaction")
async def guided_submit_settlement_rehearsal_transaction(
    body: RehearsalTransactionSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    del body, settings, store
    _require_coadmin(session)
    raise HTTPException(
        status_code=410,
        detail=(
            "The RC27 Stripe voucher rehearsal observes normal customer test "
            "purchases and never asks an administrator to submit a wallet transaction."
        ),
    )


@router.post("/funding/prepare")
async def prepare_fixed_funding(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        faucet = getattr(request.app.state, "faucet", None)
        provider = getattr(request.app.state, "coinset", None)
        if faucet is None or provider is None:
            raise GenesisConflict("ceremony faucet or Chia provider is unavailable")
        records = await provider.get_coin_records_by_puzzle_hash(
            "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
        )
        source = faucet.select_coin(
            records,
            min_amount=GENESIS_DEFAULT_TOTAL_FUNDING_AMOUNT,
            max_amount=settings.faucet_max_spend_mojos,
            purpose="genesis",
        )
        if source is None:
            raise GenesisConflict(
                "The configured faucet needs one confirmed coin of at least "
                "1,000,567 mojos for the fixed ceremony funding."
            )
        fanout = plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=faucet.address_puzzle_hash,
            network="testnet11",
            fee=0,
        )
        receipt = store.set_funding_receipt(
            session.ceremony_id, plan=fanout.plan, plan_hash=fanout.digest
        )
        return {
            "receipt": receipt,
            "summary": {
                "sourceBalanceMojos": int(source.amount),
                "totalMojos": sum(item["amount"] for item in fanout.plan["outputs"]),
                "feeMojos": 0,
                "outputs": [
                    {
                        "purpose": item["name"],
                        "amountMojos": item["amount"],
                    }
                    for item in fanout.plan["outputs"]
                ],
                "bridgeBatchMojos": GENESIS_BRIDGE_BATCH_FUNDING_AMOUNT,
                "customizationAllowed": False,
            },
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/gates/propose")
async def propose_gate(
    body: GateProposalRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        require_allowed_gate(settings, store.get(session.ceremony_id), body.gate)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if body.gate == "xchVouchers":
        from .voucher_rail_policy import xch_voucher_control
        control = xch_voucher_control(settings)
        if not control["canOpen"]:
            raise HTTPException(status_code=409, detail=control["reason"])
    if body.duration_seconds > settings.launch_gate_max_seconds:
        raise HTTPException(status_code=400, detail="Requested window exceeds the release limit.")
    opens_at = int(time.time()) + body.starts_in_seconds
    closes_at = opens_at + body.duration_seconds
    payload = {
        "ceremonyId": session.ceremony_id,
        "gate": body.gate,
        "network": "testnet11",
        "opensAt": opens_at,
        "closesAt": closes_at,
    }
    if body.gate == "xchVouchers":
        payload["requestNonce"] = secrets.token_hex(16)
    payload_hash = _hash_json(payload)
    gate = store.upsert_gate(
        session.ceremony_id,
        gate_name=body.gate,
        opens_at=opens_at,
        closes_at=closes_at,
        payload_hash=payload_hash,
        state="pending",
    )
    return {"gate": gate, "decisionReceipt": _decision_receipt(f"gate:{body.gate}", payload_hash)}


@router.post("/actions/prepare")
async def prepare_launch_action(
    body: ActionPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        action_id, payload_hash = _action_payload(
            store, session.ceremony_id, body.action_type
        )
        expires_at = int(time.time()) + 600
        typed = _action_typed_data(
            ceremony_id=session.ceremony_id,
            chain_id=_ceremony_chain(store.get(session.ceremony_id)),
            action_type=body.action_type,
            action_id=action_id,
            payload_hash=payload_hash,
            expires_at=expires_at,
        )
        return {
            "actionId": action_id,
            "payloadHash": payload_hash,
            "expiresAt": expires_at,
            "typedData": typed,
            "typedDataHash": _typed_digest(typed),
            "decisionReceipt": _decision_receipt(body.action_type, payload_hash),
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/actions/approve")
async def approve_launch_action(
    body: ActionApproveRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        expected_id, expected_payload = _action_payload(
            store, session.ceremony_id, body.action_type
        )
        if body.action_id != expected_id or body.payload_hash.lower() != expected_payload:
            raise GenesisConflict("launch action changed after review")
        now = int(time.time())
        if body.expires_at < now or body.expires_at > now + 600:
            raise GenesisExpired("launch action signature expired")
        typed = _action_typed_data(
            ceremony_id=session.ceremony_id,
            chain_id=_ceremony_chain(store.get(session.ceremony_id)),
            action_type=body.action_type,
            action_id=body.action_id,
            payload_hash=body.payload_hash.lower(),
            expires_at=body.expires_at,
        )
        recovered = recover_evm_signer(typed, body.signature)
        if recovered.address.lower() != session.wallet:
            raise GenesisConflict("launch action signer changed")
        return store.add_action_approval(
            session.ceremony_id,
            action_id=body.action_id,
            action_type=body.action_type,
            payload_hash=body.payload_hash,
            slot=session.slot,
            signer_address=session.wallet or "",
            signature=body.signature,
            expires_at=body.expires_at,
            settings=settings,
        )
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/abandon/prepare")
async def prepare_launch_abandonment(
    body: AbandonPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    payload = {
        "ceremonyId": session.ceremony_id,
        "reason": body.reason.strip(),
        "network": "testnet11",
    }
    payload_hash = _hash_json(payload)
    action_id = "0x" + hashlib.sha256(
        f"{session.ceremony_id}:abandon:{payload_hash}".encode("ascii")
    ).hexdigest()
    try:
        store.set_action_intent(
            session.ceremony_id,
            action_id=action_id,
            action_type="abandon",
            payload_hash=payload_hash,
            payload=payload,
        )
        expires_at = int(time.time()) + 600
        typed = _action_typed_data(
            ceremony_id=session.ceremony_id,
            chain_id=_ceremony_chain(store.get(session.ceremony_id)),
            action_type="abandon",
            action_id=action_id,
            payload_hash=payload_hash,
            expires_at=expires_at,
        )
        return {
            "actionId": action_id,
            "payloadHash": payload_hash,
            "expiresAt": expires_at,
            "typedData": typed,
            "typedDataHash": _typed_digest(typed),
            "decisionReceipt": _decision_receipt("abandon", payload_hash),
        }
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/abandon/execute")
async def execute_launch_abandonment(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    try:
        intent = store.latest_action_intent(session.ceremony_id, "abandon")
        if not intent or intent["state"] != "prepared":
            raise GenesisConflict("approved abandonment is unavailable")
        approval = store.action_approvals(
            session.ceremony_id, str(intent["actionId"]), settings=settings
        )
        if not approval["approved"]:
            raise GenesisConflict("owner-plus-one abandonment approval is required")
        record = store.abandon(
            session.ceremony_id, str(intent["payload"]["reason"])
        )
        store.set_action_intent(
            session.ceremony_id,
            action_id=str(intent["actionId"]),
            action_type="abandon",
            payload_hash=str(intent["payloadHash"]),
            payload=dict(intent["payload"]),
            state="executed",
        )
        return {"launch": _public_ceremony(record, store), "abandoned": True}
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/gates/{gate_name}/activate")
async def activate_gate(
    gate_name: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    if gate_name not in GATE_NAMES:
        raise HTTPException(status_code=404, detail="Unknown launch gate.")
    if gate_name == "xchVouchers":
        from .voucher_rail_policy import xch_voucher_control
        control = xch_voucher_control(settings)
        if not control["canOpen"]:
            raise HTTPException(status_code=409, detail=control["reason"])
    launch = store.get(session.ceremony_id)
    if gate_name != "ceremonyBroadcast" and launch["state"] != "locked":
        raise HTTPException(
            status_code=409,
            detail="Complete and archive genesis before opening operational windows.",
        )
    action_id, _ = _gate_payload(store, session.ceremony_id, gate_name)
    approval = store.action_approvals(session.ceremony_id, action_id, settings=settings)
    if not approval["approved"]:
        raise HTTPException(status_code=409, detail="Owner-plus-one approval is required.")
    gate = store.gates(session.ceremony_id).get(gate_name)
    if not gate:
        raise HTTPException(status_code=409, detail="Gate proposal is missing.")
    if gate_name in {"presale", "purchases", "xchVouchers"}:
        try:
            require_completed_rehearsal(settings, store, session.ceremony_id)
        except GenesisStoreError as exc:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Customer payments remain locked until the guided delivery "
                    f"and exact-refund test passes: {exc}"
                ),
            ) from exc
        try:
            ownership_store = get_ownership_activation_store(settings)
            ownership = _rail_phase_status(settings, ownership_store)
        except (OwnershipActivationError, HTTPException) as exc:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Customer payments remain locked until Base Sepolia rail "
                    "ownership is active."
                ),
            ) from exc
        if ownership.get("state") != "DONE":
            raise HTTPException(
                status_code=409,
                detail=(
                    "Customer payments remain locked until Base Sepolia rail "
                    "ownership is active."
                ),
            )
    return store.upsert_gate(
        session.ceremony_id,
        gate_name=gate_name,
        opens_at=gate["opensAt"],
        closes_at=gate["closesAt"],
        payload_hash=gate["payloadHash"],
        state="open",
        settings=settings,
    )


@router.post("/funding/execute")
async def execute_fixed_funding(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    try:
        _funding_ceiling_open(settings)
        action_id, _ = _funding_payload(store, session.ceremony_id)
        if not store.action_approvals(session.ceremony_id, action_id, settings=settings)["approved"]:
            raise GenesisConflict("owner-plus-one funding approval is required")
        receipt = store.funding_receipt(session.ceremony_id)
        assert receipt is not None
        from chia.types.blockchain_format.coin import Coin
        from chia_rs.sized_bytes import bytes32
        from chia_rs.sized_ints import uint64

        faucet = getattr(request.app.state, "faucet", None)
        provider = getattr(request.app.state, "coinset", None)
        if faucet is None or provider is None:
            raise GenesisConflict("ceremony faucet or Chia provider is unavailable")
        source_record = await provider.get_coin_record_by_name(
            str(receipt["plan"]["sourceCoinId"])
        )
        if not source_record:
            raise GenesisConflict("the approved funding source coin is missing")
        payload = source_record.get("coin") or source_record
        source = Coin(
            bytes32.fromhex(str(payload["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(payload["puzzle_hash"]).removeprefix("0x")),
            uint64(int(payload["amount"])),
        )
        reproduced = plan_genesis_funding_fanout(
            source_coin=source,
            faucet_puzzle_hash=faucet.address_puzzle_hash,
            network="testnet11",
            fee=0,
        )
        if (
            reproduced.digest != receipt["planHash"]
            or reproduced.plan != receipt["plan"]
            or source_record.get("spent") is True
            or int(source_record.get("spent_block_index") or 0)
        ):
            raise GenesisConflict("the approved funding source changed or was spent")
        conditions = [
            Program.to([CREATE_COIN, faucet.address_puzzle_hash, int(item["amount"])])
            for item in receipt["plan"]["outputs"]
        ]
        if int(receipt["plan"]["changeAmount"]):
            conditions.append(
                Program.to(
                    [
                        CREATE_COIN,
                        faucet.address_puzzle_hash,
                        int(receipt["plan"]["changeAmount"]),
                    ]
                )
            )
        conditions_program = Program.to(conditions)
        delegated = Program.to((1, conditions_program))
        coin_spend = make_spend(
            source,
            faucet.key.puzzle,
            Program.to([0, delegated, Program.to(0)]),
        )
        signature = G2Element.from_bytes(
            faucet.sign_delegated_spend(
                source,
                conditions_program,
                purpose="genesis",
            )
        )
        bundle = SpendBundle([coin_spend], signature)
        bundle_id = "0x" + bytes(bundle.name()).hex()
        try:
            response = await provider.push_tx(bundle.to_json_dict())
        except Exception as exc:  # noqa: BLE001
            store.set_funding_receipt(
                session.ceremony_id,
                plan=receipt["plan"],
                plan_hash=receipt["planHash"],
                state="ambiguous",
                spend_bundle_id=bundle_id,
                response={"error": "provider response was ambiguous"},
            )
            raise GenesisConflict(
                "Funding submission is ambiguous. It is locked for reconciliation."
            ) from exc
        accepted = response.get("success") is True or str(
            response.get("status", "")
        ).upper() in {"SUCCESS", "PENDING"}
        if not accepted:
            raise GenesisConflict("Testnet11 rejected the fixed funding transaction")
        return store.set_funding_receipt(
            session.ceremony_id,
            plan=receipt["plan"],
            plan_hash=receipt["planHash"],
            state="broadcast",
            spend_bundle_id=bundle_id,
            response=response,
        )
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/funding/confirm")
async def confirm_fixed_funding(
    request: Request,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        provider = getattr(request.app.state, "coinset", None)
        receipt = store.funding_receipt(session.ceremony_id)
        if provider is None or receipt is None:
            raise GenesisConflict("funding transaction is not available")
        for item in receipt["plan"]["outputs"]:
            record = await provider.get_coin_record_by_name(str(item["coinId"]))
            if (
                record is None
                or int(record.get("confirmed_block_index") or 0) <= 0
                or record.get("spent") is True
                or int(record.get("spent_block_index") or 0)
            ):
                raise GenesisConflict(
                    f"{item['name']} funding coin is not confirmed and unspent"
                )
        return store.set_funding_receipt(
            session.ceremony_id,
            plan=receipt["plan"],
            plan_hash=receipt["planHash"],
            state="confirmed",
            spend_bundle_id=receipt["spendBundleId"],
            response=receipt["response"],
        )
    except GenesisStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/plan/build")
async def build_guided_plan(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        record = store.get(session.ceremony_id)
        if record["state"] != "roster_frozen":
            raise GenesisConflict("confirm the three-administrator roster first")
        _require_preplan_evm_evidence(settings)
        funding = store.funding_receipt(session.ceremony_id)
        if not funding or funding["state"] != "confirmed":
            raise GenesisConflict("confirm the fixed ceremony funding first")
        template, digest = _read_json_file(
            settings.launch_plan_template_path, "RC27 launch plan template"
        )
        selection = _selected_template(settings, template, digest, record=record)
        if selection:
            from .genesis_permit_evm import verify_permit_deployment
            active = selection["enrollmentActivation"]
            projection = {"network": "testnet11", "evmChainId": selection["evmChainId"], "sourceShas": record["draft"]["sourceShas"],
                "ceremonyId": record["ceremony_id"], "enrollmentActivation": active,
                "validatorSet": {"threshold": 2, "pubkeys": template["validatorPubkeys"]},
                "evmAddresses": template["evmAddresses"], "puzzleHashes": {"bridgePolicy": active["bridgePolicyHash"]}}
            await asyncio.to_thread(verify_permit_deployment, settings,
                {**record, "plan_input": {"enrollmentActivation": active}}, projection)
        template["fundingCoinIds"] = dict(funding["plan"]["fundingCoinIds"])
        body = PlanRequest.model_validate(template)
        return await create_plan(session.ceremony_id, body, settings, store)
    except (GenesisStoreError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/plan/signature/prepare")
async def guided_prepare_plan_signature(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    prepared = await prepare_plan_signature(
        session.ceremony_id, SignaturePrepareRequest(slot=session.slot), store
    )
    record = store.get(session.ceremony_id)
    prepared["ceremonyBinding"] = _ceremony_binding(record)
    payment_chain = (record.get("plan") or {}).get("paymentChainId")
    payment_label = {8453: "Base mainnet", 84532: "Base Sepolia"}.get(payment_chain)
    identity_label = {11155111: "Ethereum Sepolia", 8453: "Base mainnet", 84532: "Base Sepolia"}[_ceremony_chain(record)]
    prepared["decisionReceipt"] = {
        "enrollmentCommitments": _selected_commitments(record),
        "title": "Approve the disposable vault/identity test plan" if is_disposable(record) else "Approve the fixed Testnet11 launch plan",
        "network": (
            f"Chia Testnet11; identity {identity_label}; payment authority {payment_label}"
            if payment_label else "Testnet11"
        ),
        "financialEffect": "No payment is made by this signature.",
        "customerImpact": ("Disposable and unaudited: vault registration and identity tests only. Sales and bridge stay closed. Replace this genesis before bridge testing." if is_disposable(record) else "Approves the exact protocol coordinates and administrator roster. Payment and bridge activation are separate steps."),
        "reversibility": "Expires with the plan and cannot authorize another plan.",
        "expiresAt": record["plan_expires_at"],
        "requiredApprovers": "Owner plus either coadministrator",
        "expectedResult": "Only the owner may broadcast after final readiness passes.",
    }
    return prepared


@router.post("/plan/renew")
async def guided_renew_plan(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    return await renew_plan(session.ceremony_id, settings, store)


@router.post("/plan/signature")
async def guided_sign_plan(
    body: SignatureSubmission,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return await sign_plan(
        session.ceremony_id,
        SignatureRequest(slot=session.slot, signature=body.signature),
        store,
    )


@router.post("/preflight")
async def guided_preflight(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    try:
        record = store.get(session.ceremony_id)
        _require_live_plan(record)
        readiness = await _readiness(request, settings, store, record)
        failures = [
            item
            for item in readiness
            if item["status"] != "Healthy" and item.get("blocksCeremony", True)
        ]
        if failures:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "Final launch check has unfinished items.",
                    "findings": failures,
                },
            )
        plan, bundle, approval, validator_health = await _prepare_bundle(
            settings, record
        )
        return {
            "ready": True,
            "planHash": plan["planHash"],
            "spendBundleId": bundle["spendBundleId"],
            "reviewApproval": approval,
            "validatorHealth": [
                item.model_dump(mode="json") for item in validator_health
            ],
            "decisionReceipt": {
                "title": "Launch the Solslot Testnet Alpha",
                "network": "Testnet11",
                "financialEffect": "Consumes only the nine fixed testnet funding coins.",
                "customerImpact": "Creates the testnet protocol used by alpha vaults and SmartDeeds.",
                "reversibility": "The chain transaction cannot be reversed. An unknown result locks the exact bundle for reconciliation and forbids a replacement genesis.",
                "requiredApprovers": "Already approved by the owner and one coadministrator",
                "expectedResult": "The protocol confirms, creates a signed archive, and locks bootstrap.",
            },
        }
    except GenesisStoreError as exc:
        code = 410 if isinstance(exc, GenesisExpired) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post("/broadcast")
async def guided_broadcast(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    try:
        record = store.get(session.ceremony_id)
        broadcast_receipt = record.get("broadcast")
        finalized_recovery = (
            isinstance(broadcast_receipt, Mapping)
            and broadcast_receipt.get("reservationState") == "FINALIZED"
        )
        gate_authorization = (
            None
            if finalized_recovery
            else _gate_open(
                settings,
                store,
                session.ceremony_id,
                "ceremonyBroadcast",
            )
        )
        return await _broadcast_ceremony(
            session.ceremony_id,
            request,
            settings,
            store,
            gate_authorization=gate_authorization,
        )
    except GenesisStoreError as exc:
        code = 410 if isinstance(exc, GenesisExpired) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from exc


@router.post("/progress")
async def progress_after_broadcast(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    record = store.get(session.ceremony_id)
    if record["state"] == "broadcast":
        return await confirm(session.ceremony_id, settings, store)
    if record["state"] == "confirmed":
        return await create_artifact(session.ceremony_id, store)
    if record["state"] == "artifact_signed":
        _require_owner(session)
        return await finalize(session.ceremony_id, settings, store)
    if record["state"] == "locked":
        return {
            "ceremony": _public_ceremony(record, store),
            "waiting": False,
            "complete": True,
        }
    return {"ceremony": _public_ceremony(record, store), "waiting": True}


@router.post("/artifact/signature/prepare")
async def guided_prepare_artifact_signature(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    prepared = await prepare_artifact_signature(
        session.ceremony_id, SignaturePrepareRequest(slot=session.slot), store
    )
    record = store.get(session.ceremony_id)
    prepared["ceremonyBinding"] = _ceremony_binding(record)
    prepared["decisionReceipt"] = {
        "enrollmentCommitments": _selected_commitments(record),
        "title": "Sign the permanent launch archive",
        "network": "Testnet11",
        "financialEffect": "No payment is made.",
        "customerImpact": "Confirms the public protocol record matches the transaction.",
        "reversibility": "The signature is bound to this artifact hash only.",
        "requiredApprovers": "Owner plus either coadministrator",
    }
    return prepared


@router.post("/artifact/signature")
async def guided_sign_artifact(
    body: SignatureSubmission,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    return await sign_artifact(
        session.ceremony_id,
        SignatureRequest(slot=session.slot, signature=body.signature),
        store,
    )


@router.get("/archive")
async def launch_archive(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_wallet_session(session)
    ceremonies = [
        _public_ceremony(record, store)
        for record in store.list_ceremonies()
        if record["state"] in {"locked", "abandoned"}
    ]
    return {"launches": ceremonies}


__all__ = ["LAUNCH_COOKIE_NAME", "LaunchSession", "require_launch_session", "router"]


@router.post("/gates/xchVouchers/close")
async def close_xch_vouchers(
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    session: Annotated[LaunchSession, Depends(require_launch_session)],
) -> dict[str, Any]:
    _require_owner(session)
    now = int(time.time())
    payload = {"ceremonyId": session.ceremony_id, "gate": "xchVouchers",
               "enabled": False, "requestNonce": secrets.token_hex(16)}
    return store.upsert_gate(session.ceremony_id, gate_name="xchVouchers",
                             opens_at=now, closes_at=now + 1,
                             payload_hash=_hash_json(payload), state="closed")
