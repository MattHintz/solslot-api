"""Three-administrator, deterministic Solslot V2 genesis orchestration."""

from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Iterator, Literal, Mapping

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .admin import require_admin_token
from .chia_provider import ChiaProviderError
from .coinset_client import CoinsetClient
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .genesis_store import (
    GenesisConflict,
    GenesisExpired,
    GenesisNotFound,
    GenesisStore,
    GenesisStoreError,
)
from .genesis_evm import GenesisEvmEvidenceError, verify_genesis_evm_deployment
from .protocol_submission import PreparedProtocolBundle, ProtocolSubmissionError
from .validator_quorum import (
    ValidatorHealthResponse,
    ValidatorQuorumError,
    probe_validator_health,
)


router = APIRouter(prefix="/admin/genesis", tags=["admin-genesis"])

SOURCE_MANIFEST_VERSION = 4
REQUIRED_SOURCE_SHAS = (
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
REQUIRED_EVM_ADDRESSES = ("forwarder", "verifierAdapter", "attestationEmitter")
REQUIRED_AUDIT_LANES = (
    "protocol",
    "evm",
    "credentialBridge",
    "ceremonyOrchestrator",
)
INDEPENDENT_REVIEW_CLASS = "independent-release-review"
INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS = "internal-engineering-testnet"


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class DraftRequest(ApiModel):
    evm_chain_id: Literal[11155111,84532,8453] = Field(11155111,alias="evmChainId")
    source_shas: dict[str, str] = Field(alias="sourceShas")
    review_class: Literal[
        "independent-release-review", "internal-engineering-testnet"
    ] = Field(INDEPENDENT_REVIEW_CLASS, alias="reviewClass")

    @field_validator("source_shas")
    @classmethod
    def validate_source_shas(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) != set(REQUIRED_SOURCE_SHAS):
            raise ValueError("sourceShas must contain all nine frozen release commits")
        normalized: dict[str, str] = {}
        for key in REQUIRED_SOURCE_SHAS:
            sha = value[key].lower()
            if len(sha) != 40:
                raise ValueError(f"sourceShas.{key} must be a full commit SHA")
            int(sha, 16)
            normalized[key] = sha
        return normalized


class InvitationPrepareRequest(ApiModel):
    token: str = Field(min_length=32, max_length=256)
    wallet: str


class InvitationAcceptRequest(InvitationPrepareRequest):
    signature: str


class FundingCoinIds(ApiModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    sgt: str
    pool: str
    did: str
    governance: str
    statutes: str
    protocol_config: str = Field(alias="protocolConfig")
    admin_authority: str = Field(alias="adminAuthority")
    vault_version_registry: str = Field(alias="vaultVersionRegistry")
    bridge_batch: str = Field(alias="bridgeBatch")


class ProtocolParameters(ApiModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    voting_window_seconds: int = Field(300, alias="votingWindowSeconds", ge=1)
    quorum_bps: int = Field(5000, alias="quorumBps", ge=1, le=10000)
    min_proposal_stake: int = Field(10_000, alias="minProposalStake", ge=1)
    nav_validity_seconds: int = Field(
        86_400, alias="navValiditySeconds", ge=60
    )
    oracle_max_age_seconds: int = Field(
        600, alias="oracleMaxAgeSeconds", ge=30
    )
    exchange_fee_bps: int = Field(100, alias="exchangeFeeBps", ge=0, le=100)
    protocol_fee_bps: int = Field(30, alias="protocolFeeBps", ge=0, le=100)
    sgt_rewards_fee_bps: int = Field(
        70, alias="sgtRewardsFeeBps", ge=0, le=100
    )
    reward_epoch_seconds: int = Field(
        86_400, alias="rewardEpochSeconds", ge=60
    )


class PlanRequest(ApiModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    enrollment_activation: dict[str, Any] | None = Field(default=None, alias="enrollmentActivation")
    evm_addresses: dict[str, str] = Field(alias="evmAddresses")
    funding_coin_ids: FundingCoinIds = Field(alias="fundingCoinIds")
    faucet_puzzle_hash: str = Field(alias="faucetPuzzleHash")
    governance_bls_pubkey: str = Field(alias="governanceBlsPubkey")
    # A dedicated public key for the MINT-only KoS co-sign condition. It is
    # sealed into the governance puzzle and signed ceremony artifact; the
    # private key is never submitted to this API.
    kos_mint_execute_pubkey: str = Field(alias="kosMintExecutePubkey")
    validator_pubkeys: list[str] = Field(alias="validatorPubkeys", min_length=3, max_length=3)
    trusted_treasury_reserve_puzzle_hash: str = Field(
        alias="trustedTreasuryReservePuzzleHash"
    )
    trusted_protocol_treasury_puzzle_hash: str = Field(
        alias="trustedProtocolTreasuryPuzzleHash"
    )
    company_sgt_sale_treasury_puzzle_hash: str = Field(
        alias="companySgtSaleTreasuryPuzzleHash"
    )
    wusdc_b_asset_id: str = Field(alias="wusdcBAssetId")
    trusted_governance_rewards_puzzle_hash: str = Field(
        alias="trustedGovernanceRewardsPuzzleHash"
    )
    trusted_governance_rewards_root: str = Field(alias="trustedGovernanceRewardsRoot")
    retired_coordinates: list[str] = Field(
        alias="retiredCoordinates", min_length=1
    )
    protocol_parameters: ProtocolParameters = Field(
        default_factory=ProtocolParameters, alias="protocolParameters"
    )


class SignatureRequest(ApiModel):
    slot: int = Field(ge=1, le=3)
    signature: str


class SignaturePrepareRequest(ApiModel):
    slot: int = Field(ge=1, le=3)


class AbandonRequest(ApiModel):
    reason: str = Field(min_length=8, max_length=1000)


@lru_cache(maxsize=8)
def _store_for_path(path: str) -> GenesisStore:
    return GenesisStore(path)


def get_genesis_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> GenesisStore:
    return _store_for_path(settings.genesis_db_path)


def _coinset() -> CoinsetClient:
    from .app import app

    coinset = getattr(app.state, "coinset", None)
    if coinset is None:
        raise HTTPException(status_code=503, detail="Coinset client is unavailable.")
    return coinset


def _faucet() -> Any:
    from .app import app

    faucet = getattr(app.state, "faucet", None)
    if faucet is None:
        raise HTTPException(status_code=503, detail="Ceremony faucet is unavailable.")
    return faucet


def _hex(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _hex_bytes(value: str, length: int, field: str, *, nonzero: bool = True) -> bytes:
    normalized = value.removeprefix("0x")
    if len(normalized) != length * 2:
        raise ValueError(f"{field} must be {length} bytes")
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be valid hex") from exc
    if nonzero and raw == b"\x00" * length:
        raise ValueError(f"{field} must be nonzero")
    return raw


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _raise_store_error(exc: GenesisStoreError) -> None:
    if isinstance(exc, GenesisNotFound):
        code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, GenesisExpired):
        code = status.HTTP_410_GONE
    else:
        code = status.HTTP_409_CONFLICT
    raise HTTPException(status_code=code, detail=str(exc)) from exc


def _safe_state(record: dict[str, Any]) -> dict[str, Any]:
    """Return the operator view without invitation token hashes."""
    for invitation in record.get("invitations", []):
        invitation.pop("token_hash", None)
    broadcast_receipt = record.get("broadcast")
    if isinstance(broadcast_receipt, dict):
        broadcast_receipt.pop("spendBundle", None)
        broadcast_receipt.pop("ceremonyEvidence", None)
    return record


def _admin_pubkeys(record: Mapping[str, Any]) -> list[bytes]:
    invitations = record.get("invitations")
    if not isinstance(invitations, list) or len(invitations) != 3:
        raise GenesisConflict("three enrolled administrators are required")
    ordered = sorted(invitations, key=lambda item: int(item["slot"]))
    if [int(item["slot"]) for item in ordered] != [1, 2, 3]:
        raise GenesisConflict("administrator roster slots are incomplete")
    return [
        _hex_bytes(str(item["compressed_pubkey"]), 33, "administrator pubkey")
        for item in ordered
    ]


def _recovery_kits_for_plan(
    store: GenesisStore,
    ceremony_id: str,
) -> list[dict[str, Any]]:
    kits = store.recovery_kits(ceremony_id)
    if [int(item["slot"]) for item in kits] != [0, 1, 2]:
        raise GenesisConflict(
            "all three administrators must finish their recovery drill"
        )
    for kit in kits:
        if not (
            kit["offlineCopyConfirmed"]
            and kit["secondDeviceConfirmed"]
            and int(kit["revision"]) >= 1
        ):
            raise GenesisConflict(
                "administrator recovery readiness is incomplete"
            )
    return [
        {
            "slot": int(kit["slot"]),
            "revision": int(kit["revision"]),
            "evmGuardian": str(kit["evmGuardian"]).lower(),
            "recoveryBlsPubkey": str(
                kit["recoveryBlsPubkey"]
            ).lower(),
            "recoveryBlsCommitment": str(
                kit["recoveryBlsCommitment"]
            ).lower(),
            "drillChallengeHash": str(
                kit["drillChallengeHash"]
            ).lower(),
        }
        for kit in kits
    ]


async def _run_worker(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Execute CLVM work in a fresh interpreter and return canonical JSON."""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "solslot_api.genesis_worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(encoded), timeout=180
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise GenesisConflict("isolated ceremony worker timed out") from exc
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(detail)
            detail = str(parsed.get("error") or "ceremony worker failed")
        except json.JSONDecodeError:
            detail = detail[-2000:] or "ceremony worker failed"
        raise GenesisConflict(f"isolated ceremony worker rejected input: {detail}")
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise GenesisConflict("isolated ceremony worker returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise GenesisConflict("isolated ceremony worker returned an invalid result")
    return result


def _plan_typed_data(record: Mapping[str, Any]) -> dict[str, Any]:
    from solslot_puzzles.genesis_signing import genesis_plan_signing_typed_data

    return genesis_plan_signing_typed_data(
        ceremony_id=str(record["ceremony_id"]),
        roster_hash=str(record["roster_hash"]),
        plan_hash=str(record["plan_hash"]),
        expires_at=int(record["plan_expires_at"]),
        chain_id=record.get('draft',{}).get('evmChainId',11155111),
    )


def _recover_expected(
    typed_data: dict[str, Any], signature: str, expected_pubkey: str | None = None
) -> Any:
    try:
        recovered = recover_evm_signer(typed_data, signature)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid EIP-712 signature: {exc}") from exc
    if expected_pubkey and recovered.compressed_pubkey_hex.lower() != expected_pubkey.lower():
        raise HTTPException(status_code=403, detail="Signature does not match roster slot.")
    return recovered


def _atomic_json(path: Path, payload: Any, *, mode: int = 0o644) -> None:
    data = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    _atomic_bytes(path, data.encode("ascii"), mode=mode)


def _atomic_bytes(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _pretty_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def _write_exact_evidence(path: Path, payload: bytes, *, mode: int) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise GenesisConflict(f"ceremony evidence path is unsafe: {path.name}")
        if path.stat().st_uid != os.geteuid():
            raise GenesisConflict(
                f"ceremony evidence owner is unsafe: {path.name}"
            )
        if path.read_bytes() != payload:
            raise GenesisConflict(f"ceremony evidence changed: {path.name}")
        os.chmod(path, mode)
        return
    _atomic_bytes(path, payload, mode=mode)


def _broadcast_response(reservation: Mapping[str, Any]) -> dict[str, Any]:
    metadata_keys = {
        "reservationSchemaVersion",
        "reservationState",
        "planHash",
        "reservedAt",
        "finalizedAt",
        "gateAuthorization",
        "ceremonyEvidence",
        "chainConfirmation",
        "spendBundle",
    }
    return {
        key: value for key, value in reservation.items() if key not in metadata_keys
    }


@contextmanager
def _exclusive_evidence_lock(output: Path) -> Iterator[None]:
    """Serialize exact evidence publication across API workers."""

    output.parent.mkdir(parents=True, exist_ok=True)
    guard_path = output.parent / f".{output.name}.evidence.lock"
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(guard_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _is_known_evidence_temp(name: str, allowed: set[str]) -> bool:
    if name in {f"{base}.tmp" for base in allowed}:
        return True
    return any(
        name.startswith(f".{base}.") and name.endswith(".tmp")
        for base in allowed
    )


def _require_safe_evidence_directory(output: Path, *, create: bool) -> None:
    if output.is_symlink():
        raise GenesisConflict("ceremony evidence directory is unsafe")
    if create:
        try:
            output.mkdir(parents=True, mode=0o700, exist_ok=True)
        except FileExistsError as exc:
            raise GenesisConflict("ceremony evidence directory is unsafe") from exc
    if output.is_symlink():
        raise GenesisConflict("ceremony evidence directory is unsafe")
    if not output.exists():
        return
    if not output.is_dir():
        raise GenesisConflict("ceremony evidence directory is unsafe")
    metadata = output.stat()
    if metadata.st_uid != os.geteuid():
        raise GenesisConflict("ceremony evidence directory owner is unsafe")
    if (metadata.st_mode & 0o777) != 0o700:
        raise GenesisConflict("ceremony evidence directory must use mode 0700")


def _require_empty_evidence_output(output: Path) -> None:
    _require_safe_evidence_directory(output, create=False)
    if output.exists() and any(output.iterdir()):
        raise GenesisConflict("ceremony output directory is not empty")


def _require_fresh_finalization_targets(settings: Settings) -> None:
    """Prove global publication targets are absent and writable before push."""

    targets = (
        Path(settings.public_artifact_path),
        Path(settings.bootstrap_manifest_path),
    )
    if targets[0].absolute() == targets[1].absolute():
        raise GenesisConflict("genesis finalization paths must be distinct")
    for target in targets:
        if target.is_symlink() or target.exists():
            raise GenesisConflict(
                f"genesis finalization target must not exist: {target.name}"
            )
        parent = target.parent
        if parent.is_symlink() or not parent.is_dir():
            raise GenesisConflict(
                f"genesis finalization directory is unavailable: {target.name}"
            )
        probe = parent / f".{target.name}.{secrets.token_hex(8)}.preflight"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(probe, flags, 0o600)
        except OSError as exc:
            raise GenesisConflict(
                f"genesis finalization directory is not writable: {target.name}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                probe.unlink()
            except FileNotFoundError:
                pass


def _materialize_broadcast_evidence(
    *,
    settings: Settings,
    record: Mapping[str, Any],
    allow_finalization_files: bool = False,
) -> None:
    """Idempotently render DB-resident pre-push evidence to the private archive."""

    reservation = record.get("broadcast")
    if not isinstance(reservation, Mapping):
        raise GenesisConflict("durable broadcast reservation is missing")
    if reservation.get("reservationState") != "FINALIZED":
        raise GenesisConflict("broadcast reservation is not reconciled")
    evidence = reservation.get("ceremonyEvidence")
    if not isinstance(evidence, Mapping):
        raise GenesisConflict("durable ceremony evidence is missing")
    try:
        review_receipt = base64.b64decode(
            str(evidence["authorityV3ReviewBase64"]), validate=True
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise GenesisConflict("durable Authority V3 evidence is invalid") from exc

    output = (
        Path(settings.genesis_output_dir)
        / str(record["ceremony_id"]).removeprefix("0x")
    )
    allowed = {
        "plan.json",
        "spend_bundle.json",
        "fee_receipt.json",
        "audit_approval.json",
        "authority_v3_review.json",
        "validator_health.json",
    }
    chain_confirmation = reservation.get("chainConfirmation")
    if chain_confirmation is not None:
        allowed.add("chain_confirmation.json")
    if allow_finalization_files:
        allowed.update({"public_artifact.json", "sha256sums.txt"})
    files: dict[str, tuple[bytes, int]] = {
        "plan.json": (_pretty_json_bytes(record["plan"]), 0o644),
        "spend_bundle.json": (
            _pretty_json_bytes(reservation["spendBundle"]),
            0o644,
        ),
        "fee_receipt.json": (
            _pretty_json_bytes(_broadcast_response(reservation)),
            0o644,
        ),
        "audit_approval.json": (
            _pretty_json_bytes(evidence["auditApproval"]),
            0o644,
        ),
        "authority_v3_review.json": (review_receipt, 0o444),
        "validator_health.json": (
            _pretty_json_bytes(evidence["validatorHealth"]),
            0o644,
        ),
    }
    if chain_confirmation is not None:
        files["chain_confirmation.json"] = (
            _pretty_json_bytes(chain_confirmation),
            0o444,
        )
    with _exclusive_evidence_lock(output):
        _require_safe_evidence_directory(output, create=True)
        unexpected: list[str] = []
        for path in output.iterdir():
            if path.name in allowed:
                continue
            if _is_known_evidence_temp(path.name, allowed):
                if path.is_symlink() or not path.is_file():
                    raise GenesisConflict(
                        f"ceremony evidence temp path is unsafe: {path.name}"
                    )
                path.unlink()
                continue
            unexpected.append(path.name)
        if unexpected:
            raise GenesisConflict(
                "ceremony evidence directory contains unexpected entries: "
                + ", ".join(sorted(unexpected))
            )
        for name, (payload, mode) in files.items():
            _write_exact_evidence(output / name, payload, mode=mode)


def _ceremony_broadcast_gate_authorization(
    settings: Settings, store: GenesisStore, ceremony_id: str
) -> dict[str, Any]:
    if not settings.alpha_writes_enabled:
        raise GenesisConflict("the server chain-write ceiling is closed")
    if not settings.ceremony_mode_enabled:
        raise GenesisConflict("the server ceremony ceiling is closed")
    gate = store.authorized_gate(settings, ceremony_id, "ceremonyBroadcast")
    if (
        not gate
        or gate["configuredState"] != "open"
        or gate["state"] != "open"
    ):
        raise GenesisConflict("the signed ceremonyBroadcast window is closed")
    return {
        "gate": "ceremonyBroadcast",
        "payloadHash": gate["payloadHash"],
        "opensAt": gate["opensAt"],
        "closesAt": gate["closesAt"],
        "configuredState": gate["configuredState"],
        "state": gate["state"],
        "approved": True,
    }


@contextmanager
def _exclusive_finalization_lock(lock_path: Path) -> Iterator[None]:
    """Serialize the one global artifact/lock publication across API workers."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    guard_path = lock_path.with_name(lock_path.name + ".finalize.lock")
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(guard_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GenesisConflict(
                "another genesis finalization is already active"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _expected_bootstrap_lock(
    *,
    ceremony_id: str,
    record: Mapping[str, Any],
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schemaVersion": 4,
        "sourceManifestVersion": SOURCE_MANIFEST_VERSION,
        "protocolVersion": "solslot-v2-rc23",
        "reviewClass": artifact["reviewClass"],
        "testOnly": artifact["testOnly"],
        "auditStatus": artifact["auditStatus"],
        "ceremonyId": ceremony_id,
        "planHash": record["plan_hash"],
        "artifactHash": artifact["artifactHash"],
        "spendBundleId": record["spend_bundle_id"],
        "confirmedBlockIndex": record["confirmed_block_index"],
    }


def _validate_bootstrap_lock(
    bootstrap_lock: Mapping[str, Any],
    expected_lock: Mapping[str, Any],
) -> None:
    if (
        any(bootstrap_lock.get(key) != value for key, value in expected_lock.items())
        or type(bootstrap_lock.get("lockedAt")) is not int
        or int(bootstrap_lock["lockedAt"]) <= 0
    ):
        raise GenesisConflict("finalization bootstrap lock is invalid")


def _existing_bootstrap_lock(
    lock_path: Path,
    expected_lock: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Load a valid pre-v12 partial-finalization lock without rewriting it."""

    if lock_path.is_symlink():
        raise GenesisConflict("finalization bootstrap lock path is unsafe")
    if not lock_path.exists():
        return None
    if not lock_path.is_file() or lock_path.stat().st_uid != os.geteuid():
        raise GenesisConflict("finalization bootstrap lock path is unsafe")
    try:
        bootstrap_lock = json.loads(lock_path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GenesisConflict("finalization bootstrap lock is invalid") from exc
    if not isinstance(bootstrap_lock, dict):
        raise GenesisConflict("finalization bootstrap lock is invalid")
    _validate_bootstrap_lock(bootstrap_lock, expected_lock)
    return bootstrap_lock


def _commit_finalization(
    *,
    ceremony_id: str,
    settings: Settings,
    store: GenesisStore,
    record: Mapping[str, Any],
    artifact: dict[str, Any],
) -> dict[str, Any]:
    public_path = Path(settings.public_artifact_path)
    lock_path = Path(settings.bootstrap_manifest_path)
    with _exclusive_finalization_lock(lock_path):
        expected_lock = _expected_bootstrap_lock(
            ceremony_id=ceremony_id,
            record=record,
            artifact=artifact,
        )
        publication = store.finalization_publication(ceremony_id)
        if publication is None:
            bootstrap_lock = _existing_bootstrap_lock(lock_path, expected_lock)
            if bootstrap_lock is None:
                bootstrap_lock = {
                    **expected_lock,
                    "lockedAt": int(time.time()),
                }
            publication = {
                "schemaVersion": 1,
                "artifact": artifact,
                "bootstrapLock": bootstrap_lock,
            }
        bound = store.reserve_finalization(
            ceremony_id,
            publication=publication,
        )
        if not isinstance(bound, Mapping):
            raise GenesisConflict("finalization publication was not persisted")
        bound_artifact = bound.get("artifact")
        bootstrap_lock = bound.get("bootstrapLock")
        if (
            bound.get("schemaVersion") != 1
            or not isinstance(bound_artifact, Mapping)
            or not isinstance(bootstrap_lock, Mapping)
            or _pretty_json_bytes(bound_artifact) != _pretty_json_bytes(artifact)
        ):
            raise GenesisConflict("finalization publication is invalid")
        _validate_bootstrap_lock(bootstrap_lock, expected_lock)

        _materialize_broadcast_evidence(
            settings=settings,
            record=record,
            allow_finalization_files=True,
        )
        output = Path(settings.genesis_output_dir) / ceremony_id.removeprefix("0x")
        required_evidence = {
            "plan.json",
            "spend_bundle.json",
            "fee_receipt.json",
            "audit_approval.json",
            "authority_v3_review.json",
            "validator_health.json",
            "chain_confirmation.json",
        }
        missing_evidence = sorted(
            name for name in required_evidence if not (output / name).is_file()
        )
        if missing_evidence:
            raise GenesisConflict(
                "private ceremony evidence is incomplete: "
                + ", ".join(missing_evidence)
            )
        artifact_bytes = _pretty_json_bytes(bound_artifact)
        _write_exact_evidence(
            output / "public_artifact.json",
            artifact_bytes,
            mode=0o444,
        )
        _write_exact_evidence(public_path, artifact_bytes, mode=0o444)
        evidence_names = sorted(required_evidence | {"public_artifact.json"})
        evidence_files = [output / name for name in evidence_names]
        if any(not path.is_file() or path.is_symlink() for path in evidence_files):
            raise GenesisConflict("private ceremony evidence changed during finalization")
        sums = "".join(
            hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n"
            for path in evidence_files
        )
        sums_path = output / "sha256sums.txt"
        _write_exact_evidence(
            sums_path,
            sums.encode("ascii"),
            mode=0o444,
        )
        _write_exact_evidence(
            lock_path,
            _pretty_json_bytes(bootstrap_lock),
            mode=0o444,
        )
        locked = store.mark_locked(ceremony_id)
    return {
        "locked": True,
        "artifactHash": bound_artifact["artifactHash"],
        "publicArtifactPath": str(public_path),
        "bootstrapLockPath": str(lock_path),
        "ceremony": _safe_state(locked),
    }


@router.post("/drafts", dependencies=[Depends(require_admin_token)])
async def create_draft(
    body: DraftRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    ceremony_id = "0x" + secrets.token_hex(32)
    output = Path(settings.genesis_output_dir) / ceremony_id[2:]
    if output.exists() and any(output.iterdir()):
        raise HTTPException(status_code=409, detail="Ceremony output directory is not empty.")
    draft = {
        "schemaVersion": 2,
        "sourceManifestVersion": SOURCE_MANIFEST_VERSION,
        "network": "testnet11",
        "evmChainId": body.evm_chain_id,
        "reviewClass": body.review_class,
        "sourceShas": body.source_shas,
    }
    try:
        return _safe_state(store.create_draft(ceremony_id, draft))
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.get("/{ceremony_id}", dependencies=[Depends(require_admin_token)])
async def ceremony_status(
    ceremony_id: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        return _safe_state(store.get(ceremony_id.lower()))
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post(
    "/{ceremony_id}/invitations/{slot}", dependencies=[Depends(require_admin_token)]
)
async def issue_invitation(
    ceremony_id: str,
    slot: int,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    nonce = "0x" + secrets.token_hex(32)
    expires_at = int(time.time()) + settings.genesis_invitation_ttl_seconds
    try:
        invitation = store.issue_invitation(
            ceremony_id.lower(),
            slot=slot,
            token_hash=_token_hash(token),
            nonce=nonce,
            expires_at=expires_at,
        )
    except (GenesisStoreError, ValueError) as exc:
        if isinstance(exc, GenesisStoreError):
            _raise_store_error(exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ceremonyId": ceremony_id.lower(),
        "slot": slot,
        "expiresAt": invitation["expires_at"],
        "invitationFragment": "#genesis-admin=" + token,
    }


def _invitation_typed_data(
    store: GenesisStore, token: str, wallet: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    from solslot_puzzles.genesis_signing import genesis_admin_enrollment_typed_data

    try:
        normalized_wallet = normalize_evm_address(wallet, "wallet")
        invitation = store.invitation_for_token(_token_hash(token))
        if invitation["consumed_at"] is not None:
            raise GenesisConflict("invitation was already consumed")
        if int(invitation["expires_at"]) < int(time.time()):
            raise GenesisExpired("invitation expired")
        typed = genesis_admin_enrollment_typed_data(
            ceremony_id=str(invitation["ceremony_id"]),
            slot=int(invitation["slot"]),
            wallet=normalized_wallet,
            nonce=str(invitation["nonce"]),
            expires_at=int(invitation["expires_at"]),
            chain_id=store.get(str(invitation['ceremony_id']))['draft'].get('evmChainId',11155111),
        )
        return invitation, typed
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/invitations/prepare")
async def prepare_invitation(
    body: InvitationPrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    invitation, typed = _invitation_typed_data(store, body.token, body.wallet)
    return {
        "ceremonyId": invitation["ceremony_id"],
        "slot": invitation["slot"],
        "expiresAt": invitation["expires_at"],
        "typedData": typed,
    }


@router.post("/invitations/accept")
async def accept_invitation(
    body: InvitationAcceptRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    invitation, typed = _invitation_typed_data(store, body.token, body.wallet)
    recovered = _recover_expected(typed, body.signature)
    expected = normalize_evm_address(body.wallet, "wallet")
    if recovered.address.lower() != expected.lower():
        raise HTTPException(status_code=403, detail="Signature wallet does not match invitation.")
    try:
        record = store.consume_invitation(
            token_hash=_token_hash(body.token),
            wallet_address=recovered.address.lower(),
            compressed_pubkey=recovered.compressed_pubkey_hex.lower(),
            signature=body.signature.lower(),
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    return {
        "ceremonyId": invitation["ceremony_id"],
        "slot": invitation["slot"],
        "enrolled": True,
        "state": record["state"],
    }


@router.post("/{ceremony_id}/roster/freeze", dependencies=[Depends(require_admin_token)])
async def freeze_roster(
    ceremony_id: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        quorum = await _run_worker(
            {
                "operation": "roster",
                "compressedPubkeys": [_hex(value) for value in _admin_pubkeys(current)],
            }
        )
        return _safe_state(
            store.freeze_roster(ceremony_id.lower(), str(quorum["adminsHash"]))
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{ceremony_id}/plan", dependencies=[Depends(require_admin_token)])
async def create_plan(
    ceremony_id: str,
    body: PlanRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        expires_at = int(time.time()) + settings.genesis_plan_ttl_seconds
        input_payload = body.model_dump(by_alias=True)
        if input_payload.get("enrollmentActivation") is None:
            input_payload.pop("enrollmentActivation", None)
        elif input_payload["enrollmentActivation"].get("environment") != settings.runtime_environment + "-alpha":
            raise ValueError("enrollment activation must match the ceremony host environment")
        input_payload["adminRecoveryKits"] = _recovery_kits_for_plan(
            store,
            ceremony_id.lower(),
        )
        result = await _run_worker(
            {
                "operation": "plan",
                "ceremony": current,
                "planInput": input_payload,
                "expiresAt": expires_at,
            }
        )
        plan = result["plan"]
        if plan["adminAuthority"]["adminsHash"] != current["roster_hash"]:
            raise GenesisConflict("deterministic plan roster does not match frozen roster")
        created = store.set_plan(
            ceremony_id.lower(),
            plan_input=input_payload,
            plan=plan,
            plan_hash=str(result["planHash"]),
            expires_at=expires_at,
        )
        return {
            "ceremony": _safe_state(created),
            "typedData": _plan_typed_data(created),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/{ceremony_id}/plan/renew",
    dependencies=[Depends(require_admin_token)],
)
async def renew_plan(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    """Renew only the expiry/hash of an exact, already-reviewed plan binding."""

    try:
        current = store.get(ceremony_id.lower())
        previous_plan = current.get("plan")
        input_payload = current.get("plan_input")
        if not isinstance(previous_plan, Mapping) or not isinstance(
            input_payload, Mapping
        ):
            raise GenesisConflict("an existing deterministic plan is required")
        expires_at = int(time.time()) + settings.genesis_plan_ttl_seconds
        result = await _run_worker(
            {
                "operation": "plan",
                "ceremony": current,
                "planInput": dict(input_payload),
                "expiresAt": expires_at,
            }
        )
        plan = result["plan"]
        previous_binding = {
            key: value
            for key, value in previous_plan.items()
            if key not in {"expiresAt", "planHash"}
        }
        renewed_binding = {
            key: value
            for key, value in plan.items()
            if key not in {"expiresAt", "planHash"}
        }
        if previous_binding != renewed_binding:
            raise GenesisConflict(
                "renewed plan changed funding, launchers, sources, or authority bindings"
            )
        renewed = store.renew_expired_plan(
            ceremony_id.lower(),
            expected_plan_hash=str(current["plan_hash"]),
            plan=plan,
            plan_hash=str(result["planHash"]),
            expires_at=expires_at,
        )
        return {
            "ceremony": _safe_state(renewed),
            "typedData": _plan_typed_data(renewed),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{ceremony_id}/plan/signatures")
async def sign_plan(
    ceremony_id: str,
    body: SignatureRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        members = {int(item["slot"]): item for item in current["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        recovered = _recover_expected(
            _plan_typed_data(current), body.signature, str(member["compressed_pubkey"])
        )
        return _safe_state(
            store.add_plan_signature(
                ceremony_id.lower(),
                slot=body.slot,
                plan_hash=str(current["plan_hash"]),
                compressed_pubkey=recovered.compressed_pubkey_hex.lower(),
                signature=body.signature.lower(),
            )
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/plan/signatures/prepare")
async def prepare_plan_signature(
    ceremony_id: str,
    body: SignaturePrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        members = {int(item["slot"]): item for item in current["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        if not current.get("plan_hash") or not current.get("plan_expires_at"):
            raise GenesisConflict("deterministic ceremony plan has not been created")
        return {
            "ceremonyId": ceremony_id.lower(),
            "slot": body.slot,
            "typedData": _plan_typed_data(current),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


async def _live_funding(
    record: Mapping[str, Any], coinset: CoinsetClient
) -> dict[str, dict[str, Any]]:
    names = (
        "sgt",
        "pool",
        "did",
        "governance",
        "statutes",
        "protocolConfig",
        "adminAuthority",
        "vaultVersionRegistry",
        "bridgeBatch",
    )
    records: dict[str, dict[str, Any]] = {}
    for name in names:
        coin_id = str(record["plan_input"]["fundingCoinIds"][name]).lower()
        coin_record = await coinset.get_coin_record_by_name(coin_id)
        if coin_record is None:
            raise GenesisConflict(f"funding coin {name} is missing")
        if coin_record.get("spent") is True or int(coin_record.get("spent_block_index") or 0):
            raise GenesisConflict(f"funding coin {name} is already spent")
        if int(coin_record.get("confirmed_block_index") or 0) <= 0:
            raise GenesisConflict(f"funding coin {name} is not confirmed")
        coin = coin_record.get("coin") or coin_record
        try:
            records[name] = {
                "parentCoinInfo": str(coin["parent_coin_info"]),
                "puzzleHash": str(coin["puzzle_hash"]),
                "amount": int(coin["amount"]),
                "expectedCoinId": coin_id,
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise GenesisConflict(f"funding coin {name} record is malformed") from exc
    return records


def _validate_audit_approval(
    settings: Settings,
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    spend_bundle_id: str,
    evm_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    path = Path(settings.genesis_audit_approval_path)
    if not path.is_file():
        raise GenesisConflict("independent audit approval file is missing")
    try:
        approval = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenesisConflict("independent audit approval file is invalid") from exc
    expected = {
        "schemaVersion": 2,
        "sourceManifestVersion": SOURCE_MANIFEST_VERSION,
        "reviewClass": INDEPENDENT_REVIEW_CLASS,
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "sourceShas": record["draft"]["sourceShas"],
        "consensusSimulationBundleId": spend_bundle_id,
    }
    for key, value in expected.items():
        if approval.get(key) != value:
            raise GenesisConflict(f"audit approval {key} does not match ceremony")
    lanes = approval.get("approvals")
    if not isinstance(lanes, list) or {item.get("lane") for item in lanes} != set(
        REQUIRED_AUDIT_LANES
    ):
        raise GenesisConflict("all four independent audit lanes must approve")
    for lane in lanes:
        if lane.get("approved") is not True or not str(lane.get("reviewer", "")).strip():
            raise GenesisConflict(f"audit lane {lane.get('lane')} is not approved")
        _hex_bytes(str(lane.get("evidenceHash", "")), 32, "audit evidence hash")

    deployments = approval.get("evmContracts")
    live_deployments = evm_evidence.get("contracts")
    if not isinstance(deployments, Mapping) or set(deployments) != set(
        REQUIRED_EVM_ADDRESSES
    ):
        raise GenesisConflict("audit approval lacks fresh EVM deployment evidence")
    if not isinstance(live_deployments, Mapping) or set(live_deployments) != set(
        REQUIRED_EVM_ADDRESSES
    ):
        raise GenesisConflict("live EVM deployment evidence is incomplete")
    for name in REQUIRED_EVM_ADDRESSES:
        deployment = deployments[name]
        live_deployment = live_deployments[name]
        if not isinstance(deployment, Mapping) or not isinstance(
            live_deployment, Mapping
        ):
            raise GenesisConflict(
                f"EVM deployment evidence {name} is malformed"
            )
        if (
            str(deployment.get("address", "")).lower()
            != str(plan["evmAddresses"][name]).lower()
        ):
            raise GenesisConflict(f"audited EVM address {name} does not match plan")
        bytecode_hash = _hex_bytes(
            str(deployment.get("bytecodeHash", "")), 32, "bytecodeHash"
        )
        if (
            str(live_deployment.get("address", "")).lower()
            != str(deployment.get("address", "")).lower()
            or str(live_deployment.get("bytecodeHash", "")).lower()
            != "0x" + bytecode_hash.hex()
        ):
            raise GenesisConflict(
                f"audited EVM deployment {name} does not match live evidence"
            )
        if int(deployment.get("confirmations", 0)) < settings.genesis_sepolia_confirmations:
            raise GenesisConflict(f"EVM deployment {name} lacks 12 confirmations")

    validators = approval.get("validators")
    expected_keys = list(plan["validatorSet"]["pubkeys"])
    if not isinstance(validators, Mapping):
        raise GenesisConflict("validator health evidence is missing")
    if validators.get("threshold") != 2 or validators.get("pubkeys") != expected_keys:
        raise GenesisConflict("validator health evidence does not match plan")
    return approval


def _internal_review_approval(
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    spend_bundle_id: str,
    evm_evidence: Mapping[str, Any],
    validator_health: tuple[ValidatorHealthResponse, ...],
) -> dict[str, Any]:
    invitations = sorted(
        record.get("invitations") or [], key=lambda item: int(item.get("slot", 0))
    )
    if len(invitations) != 3 or any(
        not item.get("wallet_address") or not item.get("compressed_pubkey")
        for item in invitations
    ):
        raise GenesisConflict("internal testnet review requires three enrolled administrators")
    plan_signatures = sorted(
        record.get("plan_signatures") or [], key=lambda item: int(item.get("slot", 0))
    )
    signer_slots = [int(item.get("slot", 0)) for item in plan_signatures]
    if 1 not in signer_slots or not set(signer_slots).intersection({2, 3}):
        raise GenesisConflict(
            "internal testnet review requires slot 1 and one coadministrator signature"
        )
    if len(validator_health) != 3:
        raise GenesisConflict("internal testnet review requires three live validators")
    if any(item.artifactReady for item in validator_health):
        raise GenesisConflict(
            "a pre-genesis validator has a stale signed artifact installed"
        )

    contracts = evm_evidence.get("contracts")
    if not isinstance(contracts, Mapping) or set(contracts) != set(
        REQUIRED_EVM_ADDRESSES
    ):
        raise GenesisConflict("live EVM deployment evidence is incomplete")
    return {
        "schemaVersion": 2,
        "sourceManifestVersion": SOURCE_MANIFEST_VERSION,
        "reviewClass": INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
        "auditStatus": "unaudited",
        "testOnly": True,
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "sourceShas": record["draft"]["sourceShas"],
        "consensusSimulationBundleId": spend_bundle_id,
        "administratorReview": {
            "threshold": 2,
            "roster": [
                {
                    "slot": int(item["slot"]),
                    "wallet": str(item["wallet_address"]).lower(),
                    "compressedPubkey": str(item["compressed_pubkey"]).lower(),
                }
                for item in invitations
            ],
            "planSignerSlots": signer_slots,
        },
        "evmManifestArtifactHash": evm_evidence["manifestArtifactHash"],
        "evmCheckedAtBlock": evm_evidence["checkedAtBlock"],
        "evmContracts": {name: dict(contracts[name]) for name in REQUIRED_EVM_ADDRESSES},
        "validators": {
            "threshold": 2,
            "pubkeys": list(plan["validatorSet"]["pubkeys"]),
            "healthy": [True, True, True],
            "signerIndices": [item.signerIndex for item in validator_health],
            "artifactReady": [item.artifactReady for item in validator_health],
            "ledgerReady": [item.ledgerReady for item in validator_health],
        },
    }


def _selected_genesis(record: Mapping[str, Any]) -> bool:
    # Explicit null and mixed projections must reach strict validation, never legacy.
    return (any("enrollmentActivation" in record.get(key, {}) for key in ("plan", "plan_input"))
        or record.get("draft", {}).get("evmChainId", 11155111) != 11155111
        or record.get("plan", {}).get("evmChainId", 11155111) != 11155111)


async def _authority_preflight(settings: Settings, record: Mapping[str, Any]) -> dict[str, Any]:
    from .authority_v3_evidence import (
        load_governance_evidence,
        validate_governance_roster,
    )
    from .authority_v3_review import (
        AuthorityV3ReviewError,
        load_authority_v3_review,
    )

    try:
        recovery_kits = record["plan_input"]["adminRecoveryKits"]
        if not isinstance(recovery_kits, list):
            raise ValueError(
                "signed plan does not contain recovery-kit commitments"
            )
        authority_evidence = load_governance_evidence(settings)
        validate_governance_roster(
            record,
            recovery_kits,
            authority_evidence,
        )
        inventory = await _run_worker(
            {"operation": "authorityV3Inventory"}
        )
        authority_review = load_authority_v3_review(
            settings,
            source_shas=record["draft"]["sourceShas"],
            authority_inner_mod_hash=str(
                inventory["adminAuthorityInnerModHash"]
            ),
            governance_evidence_hash=str(
                authority_evidence["artifactHash"]
            ),
        )
    except (
        AuthorityV3ReviewError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise GenesisConflict(
            f"Authority V3 launch approval failed: {exc}"
        ) from exc
    return authority_review


async def _deployment_preflight(settings: Settings, record: Mapping[str, Any], plan: Mapping[str, Any]):
    try:
        validator_health = await probe_validator_health(
            settings,
            expected_api_commit=str(record["draft"]["sourceShas"]["api"]),
            expected_protocol_commit=str(record["draft"]["sourceShas"]["protocol"]),
            expected_network=str(plan["network"]),
            expected_bridge_policy_hash=str(plan["puzzleHashes"]["bridgePolicy"]),
            expected_evm_addresses={
                key: str(plan["evmAddresses"][key]) for key in REQUIRED_EVM_ADDRESSES
            },
            expected_artifact_ready=False,
            **({"expected_enrollment_activation": plan["enrollmentActivation"]}
               if _selected_genesis(record) else {}),
        )
    except (KeyError, TypeError, ValidatorQuorumError) as exc:
        raise GenesisConflict(f"live validator preflight failed: {exc}") from exc
    try:
        evm_evidence = await asyncio.to_thread(
            verify_genesis_evm_deployment, settings, record, plan
        )
    except GenesisEvmEvidenceError as exc:
        raise GenesisConflict(f"live EVM preflight failed: {exc}") from exc

    return evm_evidence, validator_health


async def _selected_push_preflight(settings: Settings, record: Mapping[str, Any], approval: Mapping[str, Any]) -> None:
    """Recheck a selected push without rebuilding or replacing reserved inputs."""
    authority = await _authority_preflight(settings, record)
    evidence, _health = await _deployment_preflight(settings, record, record["plan"])
    if (authority != approval.get("authorityV3Review")
            or evidence["enrollmentDeploymentReview"] != approval.get("enrollmentDeploymentReview")
            or evidence["manifestArtifactHash"] != approval.get("evmManifestArtifactHash")):
        raise GenesisConflict("selected genesis review changed before push; preserve the original reservation")


async def _prepare_bundle(
    settings: Settings, record: Mapping[str, Any]
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    tuple[ValidatorHealthResponse, ...],
]:
    authority_review = await _authority_preflight(settings, record)
    faucet = _faucet()
    if _hex(faucet.address_puzzle_hash).lower() != str(
        record["plan_input"]["faucetPuzzleHash"]
    ).lower():
        raise GenesisConflict("ceremony faucet no longer matches signed plan")
    funding = await _live_funding(record, _coinset())
    result = await _run_worker(
        {
            "operation": "bundle",
            "ceremony": record,
            "planInput": record["plan_input"],
            "expiresAt": int(record["plan_expires_at"]),
            "fundingCoins": funding,
            "faucetMasterPrivateKey": bytes(faucet.master_sk).hex(),
            "network": settings.network,
        }
    )
    plan = result["plan"]
    if plan != record["plan"] or result["planHash"] != record["plan_hash"]:
        raise GenesisConflict("stored ceremony plan does not reproduce exactly")
    evm_evidence, validator_health = await _deployment_preflight(settings, record, plan)

    review_class = str(
        record.get("draft", {}).get("reviewClass", INDEPENDENT_REVIEW_CLASS)
    )
    if review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS:
        if str(plan.get("network")) != "testnet11":
            raise GenesisConflict(
                "internal engineering review is permitted on testnet11 only"
            )
        approval = _internal_review_approval(
            record,
            plan,
            str(result["spendBundleId"]),
            evm_evidence,
            validator_health,
        )
    elif review_class == INDEPENDENT_REVIEW_CLASS:
        approval = _validate_audit_approval(
            settings,
            record,
            plan,
            str(result["spendBundleId"]),
            evm_evidence,
        )
    else:
        raise GenesisConflict("unsupported genesis review class")
    approval["authorityV3Review"] = authority_review
    if _selected_genesis(record):
        approval["enrollmentDeploymentReview"] = evm_evidence["enrollmentDeploymentReview"]
        approval["evmManifestArtifactHash"] = evm_evidence["manifestArtifactHash"]
    return plan, result, approval, validator_health


def _require_live_plan(
    record: Mapping[str, Any],
    *,
    expected_plan_hash: str | None = None,
    now: int | None = None,
) -> None:
    timestamp = int(time.time()) if now is None else now
    if record.get("state") != "plan_approved":
        raise GenesisConflict(
            "slot 1 and one coadministrator plan signature are required"
        )
    if expected_plan_hash is not None and record.get("plan_hash") != expected_plan_hash:
        raise GenesisConflict("ceremony plan changed before submission")
    if int(record.get("plan_expires_at") or 0) <= timestamp:
        raise GenesisExpired("ceremony plan expired")


@router.post("/{ceremony_id}/preflight", dependencies=[Depends(require_admin_token)])
async def preflight(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        _require_live_plan(record)
        plan, bundle, approval, validator_health = await _prepare_bundle(settings, record)
        output = Path(settings.genesis_output_dir) / ceremony_id.lower().removeprefix("0x")
        _require_empty_evidence_output(output)
        _require_fresh_finalization_targets(settings)
        return {
            "ready": True,
            "ceremonyId": ceremony_id.lower(),
            "planHash": plan["planHash"],
            "spendBundleId": bundle["spendBundleId"],
            "spendCount": bundle["spendCount"],
            "reviewClass": approval.get("reviewClass", INDEPENDENT_REVIEW_CLASS),
            "auditStatus": approval.get("auditStatus", "independently-reviewed"),
            "auditApprovalHash": "0x"
            + hashlib.sha256(
                json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "reviewApproval": approval,
            "validatorHealth": [
                item.model_dump(mode="json") for item in validator_health
            ],
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


async def _broadcast_ceremony(
    ceremony_id: str,
    request: Request,
    settings: Settings,
    store: GenesisStore,
    *,
    gate_authorization: dict[str, Any] | None,
) -> dict[str, Any]:
    record = store.get(ceremony_id.lower())
    if record.get("state") == "broadcast":
        reservation = record.get("broadcast")
        if not isinstance(reservation, Mapping):
            raise GenesisConflict("durable broadcast reservation is missing")
        if reservation.get("reservationState") == "FINALIZED":
            _materialize_broadcast_evidence(settings=settings, record=record)
            return _safe_state(record)
        if reservation.get("reservationState") != "RESERVED":
            raise GenesisConflict("durable broadcast reservation is invalid")
        _require_fresh_finalization_targets(settings)
        if gate_authorization is None:
            raise GenesisConflict(
                "a fresh signed ceremonyBroadcast window is required for exact replay"
            )
        submitter = getattr(request.app.state, "protocol_submitter", None)
        if submitter is None or not callable(
            getattr(submitter, "reconcile_reserved", None)
        ):
            raise GenesisConflict(
                "ceremony reconciliation requires the local-node fee submitter"
            )

        def authorize_exact_replay() -> None:
            _require_fresh_finalization_targets(settings)
            store.authorize_broadcast_reconciliation(
                ceremony_id.lower(),
                gate_authorization=dict(gate_authorization),
            )

        async def authorize_selected_replay() -> None:
            original = reservation.get("ceremonyEvidence", {}).get("auditApproval", {})
            await _selected_push_preflight(settings, record, original)
            authorize_exact_replay()

        try:
            receipt = await submitter.reconcile_reserved(
                reservation,
                before_push=(authorize_selected_replay if _selected_genesis(record) else authorize_exact_replay),
            )
        except ProtocolSubmissionError as exc:
            raise GenesisConflict(
                "Exact ceremony replay remains ambiguous; the durable bundle stays "
                "reserved and must not be replaced"
            ) from exc
        reconciled = store.mark_broadcast(
            ceremony_id.lower(),
            spend_bundle_id=str(reservation["spendBundleId"]),
            response=receipt,
        )
        _materialize_broadcast_evidence(settings=settings, record=reconciled)
        return _safe_state(reconciled)
    _require_live_plan(record)
    expected_plan_hash = str(record["plan_hash"])
    _require_fresh_finalization_targets(settings)
    plan, bundle, approval, validator_health = await _prepare_bundle(settings, record)
    output = Path(settings.genesis_output_dir) / ceremony_id.lower().removeprefix("0x")
    _require_empty_evidence_output(output)
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if submitter is None:
        raise GenesisConflict(
            "ceremony broadcast requires local-node medium-fee funding"
        )
    from .authority_v3_review import (
        AuthorityV3ReviewError,
        read_authority_v3_review_receipt,
    )

    try:
        review_receipt = read_authority_v3_review_receipt(
            settings,
            expected_file_sha256=str(
                approval["authorityV3Review"]["fileSha256"]
            ),
        )
    except (AuthorityV3ReviewError, KeyError, TypeError) as exc:
        raise GenesisConflict(
            f"Authority V3 review archive failed: {exc}"
        ) from exc
    current = store.get(ceremony_id.lower())
    _require_live_plan(current, expected_plan_hash=expected_plan_hash)
    reservation_gate = (
        dict(gate_authorization) if gate_authorization is not None else None
    )
    ceremony_evidence = {
        "auditApproval": approval,
        "authorityV3ReviewBase64": base64.b64encode(review_receipt).decode("ascii"),
        "validatorHealth": {
            "checkedAt": int(time.time()),
            "signers": [
                item.model_dump(mode="json") for item in validator_health
            ],
        },
    }
    reserved_spend_bundle_id: str | None = None

    def reserve_prepared(prepared: PreparedProtocolBundle) -> None:
        nonlocal reserved_spend_bundle_id
        _require_empty_evidence_output(output)
        _require_fresh_finalization_targets(settings)
        prepared_json = prepared.to_json()
        store.reserve_broadcast(
            ceremony_id.lower(),
            expected_plan_hash=expected_plan_hash,
            spend_bundle_id=prepared.spend_bundle_id,
            spend_bundle=dict(prepared_json["spendBundle"]),
            fee_coin_id=prepared.fee_coin_id,
            fee_mojos=prepared.fee_mojos,
            ceremony_evidence=ceremony_evidence,
            gate_authorization=reservation_gate,
        )
        reserved_spend_bundle_id = prepared.spend_bundle_id

    async def reserve_selected(prepared: PreparedProtocolBundle) -> None:
        current = store.get(ceremony_id.lower())
        _require_live_plan(current, expected_plan_hash=expected_plan_hash)
        await _selected_push_preflight(settings, current, approval)
        reserve_prepared(prepared)

    try:
        receipt = await submitter.submit(
            bundle["spendBundle"],
            before_push=(reserve_selected if _selected_genesis(record) else reserve_prepared),
            selection_purpose="genesis",
        )
    except ProtocolSubmissionError as exc:
        if reserved_spend_bundle_id is not None:
            detail = (
                "Ceremony broadcast did not reach a confirmed local-mempool "
                "result; its exact bundle remains reserved for reconciliation "
                "and may only be replayed exactly under a fresh signed gate"
            )
        elif exc.submission_attempted:
            detail = (
                "Ceremony broadcast was attempted without a durable reservation; "
                "operator reconciliation is required; only an independently "
                "verified exact bundle may be replayed, never a replacement"
            )
        else:
            detail = f"Ceremony fee preparation failed: {exc}"
        raise GenesisConflict(detail) from exc
    broadcast_state = store.mark_broadcast(
        ceremony_id.lower(),
        spend_bundle_id=str(receipt["spendBundleId"]),
        response=receipt,
    )
    _materialize_broadcast_evidence(settings=settings, record=broadcast_state)
    return _safe_state(broadcast_state)


@router.post("/{ceremony_id}/broadcast", dependencies=[Depends(require_admin_token)])
async def broadcast(
    ceremony_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        current = store.get(ceremony_id.lower())
        if current.get("state") != "broadcast":
            _require_live_plan(current)
        current_broadcast = current.get("broadcast")
        finalized_recovery = (
            isinstance(current_broadcast, Mapping)
            and current_broadcast.get("reservationState") == "FINALIZED"
        )
        gate_authorization = (
            None
            if finalized_recovery
            else _ceremony_broadcast_gate_authorization(
                settings, store, ceremony_id.lower()
            )
        )
        return await _broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=gate_authorization,
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/confirmation", dependencies=[Depends(require_admin_token)])
async def confirm(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] == "confirmed":
            _materialize_broadcast_evidence(settings=settings, record=record)
            return _safe_state(record)
        if record["state"] != "broadcast":
            raise GenesisConflict("ceremony bundle has not been broadcast")
        reservation = record.get("broadcast")
        if not isinstance(reservation, Mapping):
            raise GenesisConflict("durable broadcast reservation is missing")
        provider = _coinset()
        for method_name in (
            "get_coin_record_by_name_primary",
            "get_puzzle_and_solution_primary",
            "get_blockchain_state_primary",
        ):
            if not callable(getattr(provider, method_name, None)):
                raise GenesisConflict(
                    "synced local-primary genesis proof is unavailable"
                )
        result = await _run_worker(
            {
                "operation": "outputs",
                "ceremony": record,
                "planInput": record["plan_input"],
                "expiresAt": int(record["plan_expires_at"]),
            }
        )
        if result["plan"] != record["plan"] or result["planHash"] != record["plan_hash"]:
            raise GenesisConflict("stored ceremony plan does not reproduce exactly")

        from chia_rs import Coin, SpendBundle

        try:
            reserved_bundle = SpendBundle.from_json_dict(
                dict(reservation["spendBundle"])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GenesisConflict("reserved ceremony spend bundle is invalid") from exc
        computed_bundle_id = "0x" + bytes(reserved_bundle.name()).hex()
        if (
            computed_bundle_id != str(reservation.get("spendBundleId") or "")
            or computed_bundle_id != str(record.get("spend_bundle_id") or "")
        ):
            raise GenesisConflict(
                "reserved ceremony spend bundle id does not match its bytes"
            )
        expected_spends: dict[str, Any] = {}
        for coin_spend in reserved_bundle.coin_spends:
            coin_id = "0x" + bytes(coin_spend.coin.name()).hex()
            if coin_id in expected_spends:
                raise GenesisConflict("reserved ceremony repeats an input coin")
            expected_spends[coin_id] = coin_spend
        if not expected_spends:
            raise GenesisConflict("reserved ceremony has no input coin spends")
        if str(reservation.get("feeCoinId") or "") not in expected_spends:
            raise GenesisConflict(
                "reserved ceremony fee coin is not an input to the spend bundle"
            )

        spent_heights: list[int] = []
        for coin_id, expected_spend in expected_spends.items():
            coin_record = await provider.get_coin_record_by_name_primary(coin_id)
            if not isinstance(coin_record, Mapping):
                raise GenesisConflict("a reserved ceremony input is not confirmed")
            spent_height = int(coin_record.get("spent_block_index") or 0)
            if spent_height <= 0:
                raise GenesisConflict("a reserved ceremony input is not spent")
            coin_payload = coin_record.get("coin")
            if not isinstance(coin_payload, Mapping):
                raise GenesisConflict("a reserved ceremony input record is invalid")
            try:
                observed_coin = Coin.from_json_dict(dict(coin_payload))
            except (KeyError, TypeError, ValueError) as exc:
                raise GenesisConflict(
                    "a reserved ceremony input record is invalid"
                ) from exc
            if "0x" + bytes(observed_coin.name()).hex() != coin_id:
                raise GenesisConflict("a reserved ceremony input coin changed")
            observed_spend = await provider.get_puzzle_and_solution_primary(
                coin_id, spent_height
            )
            if not isinstance(observed_spend, Mapping):
                raise GenesisConflict("a reserved ceremony input spend is unavailable")
            try:
                observed_puzzle = bytes.fromhex(
                    str(observed_spend["puzzle_reveal"]).removeprefix("0x")
                )
                observed_solution = bytes.fromhex(
                    str(observed_spend["solution"]).removeprefix("0x")
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise GenesisConflict(
                    "a reserved ceremony input spend is invalid"
                ) from exc
            if (
                observed_puzzle != bytes(expected_spend.puzzle_reveal)
                or observed_solution != bytes(expected_spend.solution)
            ):
                raise GenesisConflict(
                    "a confirmed ceremony input differs from the reserved spend"
                )
            spent_heights.append(spent_height)
        if len(set(spent_heights)) != 1:
            raise GenesisConflict(
                "reserved ceremony inputs were not confirmed in one transaction block"
            )
        confirmed_height = spent_heights[0]

        for coin_id in result["coinIds"]:
            coin_record = await provider.get_coin_record_by_name_primary(coin_id)
            if coin_record is None:
                raise GenesisConflict("not all deterministic ceremony outputs are confirmed")
            if coin_record.get("spent") is True or int(coin_record.get("spent_block_index") or 0):
                raise GenesisConflict("a ceremony output was spent before artifact finalization")
            height = int(coin_record.get("confirmed_block_index") or 0)
            if height <= 0:
                raise GenesisConflict("a ceremony output is not confirmed")
            if height != confirmed_height:
                raise GenesisConflict(
                    "a deterministic ceremony output was not created with the reserved spends"
                )
        chain_state = await provider.get_blockchain_state_primary()
        peak = int(
            ((chain_state.get("blockchain_state") or {}).get("peak") or {}).get("height")
            or 0
        )
        confirmations = peak - confirmed_height + 1
        if confirmations < settings.genesis_chia_confirmations:
            raise GenesisConflict(
                f"ceremony has {confirmations} Chia confirmations; three are required"
            )
        chain_evidence = {
            "schemaVersion": 1,
            "spendBundleId": reservation["spendBundleId"],
            "exactReservedCoinSpends": True,
            "inputCoinIds": sorted(expected_spends),
            "outputCoinIds": list(result["coinIds"]),
            "confirmedBlockIndex": confirmed_height,
            "confirmations": confirmations,
            "source": (
                "exact-chain-reconciliation"
                if reservation.get("reservationState") == "RESERVED"
                or reservation.get("status") == "CHAIN_RECONCILED"
                or reservation.get("submissionProvider")
                == "exact-chain-reconciliation"
                else "exact-mempool-receipt-and-chain"
            ),
            "checkedAt": int(time.time()),
        }
        if reservation.get("reservationState") == "RESERVED":
            reconciled_response = {
                "schemaVersion": 1,
                "status": "CHAIN_RECONCILED",
                "network": settings.network,
                "spendBundleId": reservation["spendBundleId"],
                "feeMojos": reservation["feeMojos"],
                "feeCoinId": reservation["feeCoinId"],
                "spendBundle": reservation["spendBundle"],
                "submissionProvider": "exact-chain-reconciliation",
                "ambiguousPushRecovered": True,
                "chainReconciledAt": int(time.time()),
            }
            confirmed = store.mark_chain_reconciled_confirmed(
                ceremony_id.lower(),
                spend_bundle_id=str(reservation["spendBundleId"]),
                response=reconciled_response,
                confirmed_block_index=confirmed_height,
                confirmation_evidence=chain_evidence,
            )
        else:
            confirmed = store.mark_confirmed(
                ceremony_id.lower(),
                confirmed_block_index=confirmed_height,
                confirmation_evidence=chain_evidence,
            )
        _materialize_broadcast_evidence(settings=settings, record=confirmed)
        return _safe_state(confirmed)
    except GenesisStoreError as exc:
        _raise_store_error(exc)
    except ChiaProviderError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Synced local-primary genesis proof failed: {exc}",
        ) from exc


@router.post("/{ceremony_id}/artifact", dependencies=[Depends(require_admin_token)])
async def create_artifact(
    ceremony_id: str,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] != "confirmed":
            raise GenesisConflict("ceremony must have three Chia confirmations")
        result = await _run_worker(
            {
                "operation": "artifact",
                "ceremony": record,
                "planInput": record["plan_input"],
                "expiresAt": int(record["plan_expires_at"]),
                "spendBundleId": str(record["spend_bundle_id"]),
                "confirmedBlockIndex": int(record["confirmed_block_index"]),
            }
        )
        if result["plan"] != record["plan"]:
            raise GenesisConflict("stored ceremony plan does not reproduce exactly")
        artifact = result["artifact"]
        created = store.set_artifact(
            ceremony_id.lower(),
            artifact=artifact,
            artifact_hash=str(artifact["artifactHash"]),
        )
        from solslot_puzzles.genesis_signing import (
            genesis_artifact_signing_typed_data,
        )

        return {
            "ceremony": _safe_state(created),
            "typedData": genesis_artifact_signing_typed_data(artifact),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/artifact/signatures")
async def sign_artifact(
    ceremony_id: str,
    body: SignatureRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    from solslot_puzzles.genesis_signing import genesis_artifact_signing_typed_data

    try:
        record = store.get(ceremony_id.lower())
        if not record.get("artifact"):
            raise GenesisConflict("canonical artifact has not been created")
        members = {int(item["slot"]): item for item in record["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        recovered = _recover_expected(
            genesis_artifact_signing_typed_data(record["artifact"]),
            body.signature,
            str(member["compressed_pubkey"]),
        )
        return _safe_state(
            store.add_artifact_signature(
                ceremony_id.lower(),
                slot=body.slot,
                artifact_hash=str(record["artifact_hash"]),
                compressed_pubkey=recovered.compressed_pubkey_hex.lower(),
                signature=body.signature.lower(),
            )
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/artifact/signatures/prepare")
async def prepare_artifact_signature(
    ceremony_id: str,
    body: SignaturePrepareRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    from solslot_puzzles.genesis_signing import genesis_artifact_signing_typed_data

    try:
        current = store.get(ceremony_id.lower())
        members = {int(item["slot"]): item for item in current["invitations"]}
        member = members.get(body.slot)
        if member is None or not member.get("compressed_pubkey"):
            raise GenesisConflict("administrator slot is not enrolled")
        if not current.get("artifact") or not current.get("artifact_hash"):
            raise GenesisConflict("canonical artifact has not been created")
        return {
            "ceremonyId": ceremony_id.lower(),
            "slot": body.slot,
            "typedData": genesis_artifact_signing_typed_data(current["artifact"]),
        }
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/finalize", dependencies=[Depends(require_admin_token)])
async def finalize(
    ceremony_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        record = store.get(ceremony_id.lower())
        if record["state"] not in {"artifact_signed", "locked"}:
            raise GenesisConflict("slot 1 and one coadministrator artifact signature are required")
        artifact = dict(record["artifact"])
        artifact["signatures"] = [
            {
                "adminIndex": int(entry["slot"]) - 1,
                "compressedPubkey": entry["compressed_pubkey"],
                "signature": entry["signature"],
            }
            for entry in record["artifact_signatures"]
        ]

        await _run_worker({"operation": "verifyArtifact", "artifact": artifact})
        return _commit_finalization(
            ceremony_id=ceremony_id.lower(),
            settings=settings,
            store=store,
            record=record,
            artifact=artifact,
        )
    except GenesisStoreError as exc:
        _raise_store_error(exc)


@router.post("/{ceremony_id}/abandon", dependencies=[Depends(require_admin_token)])
async def abandon(
    ceremony_id: str,
    body: AbandonRequest,
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    try:
        return _safe_state(store.abandon(ceremony_id.lower(), body.reason))
    except GenesisStoreError as exc:
        _raise_store_error(exc)


__all__ = ["router", "get_genesis_store"]
