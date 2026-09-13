"""Load and verify the canonical signed Solslot RC23 public artifact."""

from __future__ import annotations

import json
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from eth_keys import keys as eth_keys

from .config import Settings
from .release_metadata import load_release_metadata


class PublicArtifactError(ValueError):
    """The configured public artifact cannot be trusted."""


class PublicArtifactMissing(PublicArtifactError):
    """No finalized RC23 ceremony artifact exists yet."""


MAX_PUBLIC_ARTIFACT_BYTES = 2 * 1024 * 1024
ARTIFACT_WORKER_TIMEOUT_SECONDS = 15


@lru_cache(maxsize=8)
def _verify_artifact_in_worker(
    path_text: str,
    modified_ns: int,
    size: int,
) -> str:
    del modified_ns, size
    try:
        raw = Path(path_text).read_text(encoding="utf-8")
        json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicArtifactError(
            "signed RC23 public artifact is unreadable"
        ) from exc
    return _verify_artifact_json(raw)


@lru_cache(maxsize=8)
def _verify_artifact_json(raw: str) -> str:
    payload = json.loads(raw)
    try:
        process = subprocess.run(
            [sys.executable, "-m", "solslot_api.genesis_worker"],
            input=json.dumps(
                {"operation": "verifyArtifact", "artifact": payload},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            capture_output=True,
            check=False,
            text=True,
            timeout=ARTIFACT_WORKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise PublicArtifactError(
            "signed RC23 public artifact verification timed out"
        ) from exc
    if process.returncode != 0:
        try:
            failure = json.loads(process.stderr)
            detail = str(failure.get("error", "worker rejected artifact"))
        except (json.JSONDecodeError, TypeError, ValueError):
            detail = "worker rejected artifact"
        raise PublicArtifactError(
            f"signed RC23 public artifact is invalid: {detail}"
        )
    return raw


def verify_signed_public_artifact_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Verify a bounded reserved artifact without publishing a file.

    As with verify_signed_public_artifact_file, callers must bind the returned
    artifact to their ceremony, network and permitted operation.
    """
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise PublicArtifactError("reserved signed artifact is invalid") from exc
    if len(raw.encode("utf-8")) > MAX_PUBLIC_ARTIFACT_BYTES:
        raise PublicArtifactError("reserved signed artifact exceeds the size limit")
    return json.loads(_verify_artifact_json(raw))


def _same_hex(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.lower() == right.lower()


def _require_configured_evm_binding(
    configured: str | None,
    signed: object,
    label: str,
) -> None:
    if configured is None:
        raise PublicArtifactError(
            f"configured {label} is required to verify signed artifact"
        )
    if not _same_hex(configured, signed):
        raise PublicArtifactError(f"configured {label} does not match signed artifact")


def _verify_runtime_bindings(settings: Settings, payload: Mapping[str, Any]) -> None:
    from solslot_puzzles.inventory_activation import validate_inventory_activation
    try:
        validate_inventory_activation(payload, environment=settings.runtime_environment + "-alpha")
    except ValueError as exc:
        raise PublicArtifactError(str(exc)) from exc
    from solslot_puzzles.enrollment_activation import activation_from_artifact
    try:
        selected = activation_from_artifact(payload, environment=settings.runtime_environment + "-alpha")
    except ValueError as exc:
        raise PublicArtifactError(str(exc)) from exc
    if selected is None and any((settings.enrollment_permit_release_identity,
            settings.enrollment_permit_issuer_key_ref,settings.enrollment_permit_identity_client_id)):
        raise PublicArtifactError('permit issuer configuration requires signed enrollment activation')
    if selected is not None and (settings.enrollment_permit_release_identity != selected['releaseIdentity']
            or settings.enrollment_permit_issuer_key_ref != selected['issuerKeyRef']
            or settings.enrollment_permit_identity_client_id != selected['issuerIdentityClientId']):
        raise PublicArtifactError('enrollment permit runtime does not match the reviewed release and issuer metadata')
    if payload.get("network") != settings.network:
        raise PublicArtifactError("public artifact network does not match this API")
    if payload.get("evmChainId") != settings.zkpassport_evm_chain_id:
        raise PublicArtifactError("public artifact EVM chain does not match this API")

    launchers = payload.get("launcherIds")
    bridge = payload.get("bridgePolicy")
    addresses = payload.get("evmAddresses")
    validators = payload.get("validatorSet")
    if not all(isinstance(value, Mapping) for value in (launchers, bridge, addresses, validators)):
        raise PublicArtifactError("public artifact runtime bindings are incomplete")

    configured_bindings = (
        (settings.pool_launcher_id, launchers.get("pool"), "pool launcher"),
        (
            settings.governance_launcher_id,
            launchers.get("governance"),
            "governance launcher",
        ),
        (
            settings.protocol_config_launcher_id,
            launchers.get("protocolConfig"),
            "protocol-config launcher",
        ),
        (
            settings.vault_version_registry_launcher_id,
            launchers.get("vaultVersionRegistry"),
            "vault-version registry launcher",
        ),
        (
            settings.zkpassport_bridge_policy_hash,
            bridge.get("policyHash"),
            "bridge policy",
        ),
    )
    for configured, signed, label in configured_bindings:
        if configured is not None and not _same_hex(configured, signed):
            raise PublicArtifactError(f"configured {label} does not match signed artifact")
    evm_bindings = (
        (
            settings.zkpassport_forwarder_address,
            addresses.get("forwarder"),
            "forwarder address",
        ),
        (
            settings.zkpassport_verifier_adapter_address,
            addresses.get("verifierAdapter"),
            "verifier adapter address",
        ),
        (
            settings.zkpassport_emitter_address,
            addresses.get("attestationEmitter"),
            "attestation emitter address",
        ),
    )
    for configured, signed, label in evm_bindings:
        _require_configured_evm_binding(configured, signed, label)

    if validators.get("threshold") != settings.zkpassport_validator_threshold:
        raise PublicArtifactError("validator threshold does not match signed artifact")
    configured_keys = [value.lower() for value in settings.zkpassport_validator_pubkeys]
    signed_keys = [str(value).lower() for value in validators.get("pubkeys", [])]
    if configured_keys and configured_keys != signed_keys:
        raise PublicArtifactError("validator roster does not match signed artifact")
    if bridge.get("policyVersion") != settings.zkpassport_policy_version:
        raise PublicArtifactError("credential policy version does not match signed artifact")

    release = load_release_metadata(settings.release_metadata_path)
    if release is None:
        if settings.runtime_environment in {"staging", "production"}:
            raise PublicArtifactError("release metadata is required beside a signed artifact")
        return
    source_shas = payload.get("sourceShas")
    if not isinstance(source_shas, Mapping):
        raise PublicArtifactError("public artifact source commits are missing")
    if source_shas.get("api") != release.apiCommit:
        raise PublicArtifactError("API release commit does not match signed artifact")
    if source_shas.get("protocol") != release.protocolCommit:
        raise PublicArtifactError("protocol release commit does not match signed artifact")


def verify_signed_public_artifact_file(path_value: str | Path) -> dict[str, Any]:
    """Read and cryptographically verify an RC23 public artifact.

    Runtime services which do not share the coordinator's mutable settings
    (notably the isolated validator signers) use this narrower entry point.
    It verifies the complete artifact schema and administrator signature
    quorum, but deliberately leaves host-specific runtime binding to the
    caller.
    """
    path = Path(path_value)
    if not path.is_file():
        raise PublicArtifactMissing("signed RC23 public artifact is unavailable")
    try:
        stat = path.stat()
        if stat.st_size > MAX_PUBLIC_ARTIFACT_BYTES:
            raise PublicArtifactError(
                "signed RC23 public artifact exceeds the size limit"
            )
        payload = json.loads(
            _verify_artifact_in_worker(
                str(path.resolve()),
                stat.st_mtime_ns,
                stat.st_size,
            )
        )
    except OSError as exc:
        raise PublicArtifactError(
            "signed RC23 public artifact is unreadable"
        ) from exc
    if not isinstance(payload, dict):
        raise PublicArtifactError("signed RC23 public artifact must be an object")
    return payload


def load_signed_public_artifact(settings: Settings) -> dict[str, Any]:
    """Read, cryptographically verify, and runtime-bind the RC23 artifact."""
    payload = verify_signed_public_artifact_file(settings.public_artifact_path)
    _verify_runtime_bindings(settings, payload)
    return payload


def signed_admin_allowlist(settings: Settings) -> set[str]:
    """Return the EVM identities committed by the signed 2-of-3 artifact.

    Both compressed keys and derived addresses are returned so signature
    recovery and JWT revocation checks can compare canonical values without a
    second, operator-maintained roster file.  ``load_signed_public_artifact``
    performs the signature quorum and runtime binding checks first.
    """
    artifact = load_signed_public_artifact(settings)
    admin = artifact["adminAuthority"]
    identities: set[str] = set()
    for value in admin["compressedPubkeys"]:
        normalized = str(value).lower()
        raw = bytes.fromhex(normalized.removeprefix("0x"))
        try:
            public_key = eth_keys.PublicKey.from_compressed_bytes(raw)
        except (TypeError, ValueError) as exc:
            raise PublicArtifactError(
                "signed RC23 artifact contains an invalid administrator key"
            ) from exc
        identities.add(normalized)
        identities.add(public_key.to_checksum_address().lower())
    return identities


__all__ = [
    "PublicArtifactError",
    "PublicArtifactMissing",
    "load_signed_public_artifact",
    "signed_admin_allowlist",
    "verify_signed_public_artifact_file",
    "verify_signed_public_artifact_payload",
]
