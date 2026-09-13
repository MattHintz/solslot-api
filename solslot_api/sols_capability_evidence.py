"""Release-evidence gates for customer bridge and liquidity execution.

Governed statutes authorize identities. They do not prove that an off-chain
adapter was shipped or that the referenced runtime code was re-derived during
the release. This module binds those separate facts without allowing a feature
flag or a browser-supplied address to substitute for either one.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from .sols_capability_adapters import (
    SolsCapabilityAdapterError,
    validate_adapter_descriptor,
    validate_adapter_governance_binding,
)


MAX_CAPABILITY_EVIDENCE_BYTES = 256 * 1024
CapabilityName = Literal["warp-cat-bridge", "governed-liquidity"]


class SolsCapabilityEvidenceError(ValueError):
    """Raised when release evidence is missing, altered, or incomplete."""


@dataclass(frozen=True)
class SolsCapabilityEvidence:
    capability: CapabilityName
    release_tag: str
    source_sha: str
    governed_root: str
    adapter_ids: tuple[str, ...]
    adapter_descriptors: tuple[dict[str, Any], ...]
    records: tuple[dict[str, Any], ...]
    runtime_evidence_root: str
    sha256: str
    environment: str | None = None
    network: str = "mainnet"
    deployment_id: str | None = None


def load_sols_capability_evidence(
    *,
    path_value: str | None,
    expected_sha256: str | None,
    capability: CapabilityName,
    governed_root: str | None = None,
    governed_records: Sequence[Mapping[str, Any]] | None = None,
    expected_network: str = "mainnet",
    expected_environment: str | None = None,
    expected_deployment_id: str | None = None,
    expected_release_tag: str | None = None,
    expected_source_sha: str | None = None,
    require_runtime_binding: bool = False,
) -> SolsCapabilityEvidence:
    """Load exact release evidence and bind it to statutes and deployment.

    Schema 2 is retained for offline historical review only. Runtime callers
    require schema 3 and explicit deployment coordinates; fixtures never enable
    a different environment or substitute purchase-rail evidence for a bridge.

    The expected SHA-256 is a deployment input recorded by the signed release
    manifest. The evidence then binds the reviewed adapter/runtime package to
    the chain-reconstructed statutes root and exact governed records.
    """

    if not path_value:
        raise SolsCapabilityEvidenceError("release evidence path is not configured")
    if not expected_sha256:
        raise SolsCapabilityEvidenceError(
            "release evidence SHA-256 is not configured"
        )
    expected_digest = _hex(expected_sha256, 32, "release evidence SHA-256")

    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise SolsCapabilityEvidenceError("release evidence file is unavailable")
    size = path.stat().st_size
    if size <= 0 or size > MAX_CAPABILITY_EVIDENCE_BYTES:
        raise SolsCapabilityEvidenceError("release evidence has an invalid size")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not secrets.compare_digest(digest, expected_digest):
        raise SolsCapabilityEvidenceError("release evidence checksum changed")

    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SolsCapabilityEvidenceError("release evidence is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise SolsCapabilityEvidenceError("release evidence must be an object")
    if (
        payload.get("schemaVersion") not in {2, 3}
        or payload.get("kind") != "solslot-sols-capability-release"
        or payload.get("capability") != capability
        or payload.get("network") != expected_network
        or payload.get("auditStatus") != "reviewed"
        or payload.get("testOnly") is not (expected_network == "testnet11")
    ):
        raise SolsCapabilityEvidenceError(
            "release evidence is not an approved network-bound capability package"
        )

    if expected_network not in {"mainnet", "testnet11"}:
        raise SolsCapabilityEvidenceError("unsupported capability network")
    if require_runtime_binding or payload.get("schemaVersion") == 3:
        if payload.get("schemaVersion") != 3:
            raise SolsCapabilityEvidenceError("runtime execution requires schema 3 deployment binding")
        for key, expected in (
            ("environment", expected_environment),
            ("deploymentId", expected_deployment_id),
            ("releaseTag", expected_release_tag),
            ("sourceSha", expected_source_sha),
        ):
            if not expected or payload.get(key) != expected:
                raise SolsCapabilityEvidenceError(f"release evidence {key} does not match runtime")
        if payload.get("environment") not in {"development", "test", "staging", "production"}:
            raise SolsCapabilityEvidenceError("unsupported capability environment")
        if payload.get("evidenceScope") != capability:
            raise SolsCapabilityEvidenceError("evidence scope is not the customer capability")

    release_tag = _nonempty(payload.get("releaseTag"), "releaseTag")
    source_sha = _hex(payload.get("sourceSha"), 20, "sourceSha")
    evidence_root = "0x" + _hex(
        payload.get("governedRoot"), 32, "governedRoot"
    )
    runtime = _mapping(payload.get("runtimeEvidence"), "runtimeEvidence")
    implementation = _mapping(payload.get("implementation"), "implementation")
    if runtime.get("verified") is not True:
        raise SolsCapabilityEvidenceError("runtime evidence is not verified")
    runtime_root = "0x" + _hex(
        runtime.get("evidenceRoot"), 32, "runtimeEvidence.evidenceRoot"
    )
    descriptor_values = runtime.get("adapters")
    if not isinstance(descriptor_values, list) or not descriptor_values:
        raise SolsCapabilityEvidenceError(
            "runtimeEvidence.adapters must be a non-empty list"
        )
    adapter_descriptors = tuple(
        dict(_mapping(value, f"runtimeEvidence.adapters[{index}]"))
        for index, value in enumerate(descriptor_values)
    )
    if (
        implementation.get("complete") is not True
        or implementation.get("fixturesPassed") is not True
    ):
        raise SolsCapabilityEvidenceError(
            "capability adapter implementation is incomplete"
        )

    if payload.get("schemaVersion") == 3:
        if implementation.get("chainTrialsPassed") is not True:
            raise SolsCapabilityEvidenceError("reviewed chain trials are not complete; fixtures are insufficient")
        _hex(implementation.get("chainTrialEvidenceRoot"), 32, "chainTrialEvidenceRoot")

    adapter_values = payload.get("adapterIds")
    if not isinstance(adapter_values, list) or not adapter_values:
        raise SolsCapabilityEvidenceError("adapterIds must be a non-empty list")
    adapter_ids = tuple(
        _nonempty(value, f"adapterIds[{index}]")
        for index, value in enumerate(adapter_values)
    )
    if len(set(adapter_ids)) != len(adapter_ids):
        raise SolsCapabilityEvidenceError("adapterIds contains duplicates")
    descriptor_ids = tuple(
        _nonempty(value.get("adapterId"), f"runtime adapterIds[{index}]")
        for index, value in enumerate(adapter_descriptors)
    )
    if len(set(descriptor_ids)) != len(descriptor_ids):
        raise SolsCapabilityEvidenceError(
            "runtimeEvidence.adapters contains duplicate adapter IDs"
        )
    if set(descriptor_ids) != set(adapter_ids):
        raise SolsCapabilityEvidenceError(
            "runtime adapter IDs do not match adapterIds"
        )

    record_values = payload.get("records")
    if not isinstance(record_values, list) or not record_values:
        raise SolsCapabilityEvidenceError("records must be a non-empty list")
    records = tuple(
        dict(_mapping(value, f"records[{index}]"))
        for index, value in enumerate(record_values)
    )
    record_ids = {
        str(value.get("routeId") or value.get("venueId", "")).lower()
        for value in records
    }
    records_by_id = {
        str(value.get("routeId") or value.get("venueId", "")).lower(): value
        for value in records
    }
    if "" in record_ids or len(record_ids) != len(records):
        raise SolsCapabilityEvidenceError(
            "records must have unique routeId or venueId values"
        )
    descriptor_record_ids = [str(item.get("recordId", "")).lower() for item in adapter_descriptors]
    if len(set(descriptor_record_ids)) != len(descriptor_record_ids):
        raise SolsCapabilityEvidenceError("multiple runtime adapters target the same governed record")
    for index, descriptor in enumerate(adapter_descriptors):
        if payload.get("schemaVersion") == 3:
            for key in ("environment", "network", "deploymentId", "releaseTag", "sourceSha"):
                if descriptor.get(key) != payload.get(key):
                    raise SolsCapabilityEvidenceError(f"runtime adapter {key} is not release-bound")
            if descriptor.get("kind") == "WARP_CAT":
                from .sols_bridge_observer import validate_observer_descriptor
                try:
                    validate_observer_descriptor(descriptor)
                except (KeyError, TypeError, ValueError) as exc:
                    raise SolsCapabilityEvidenceError(f"invalid Warp observer evidence: {exc}") from exc
            if descriptor.get("adapterVersion") != 1:
                raise SolsCapabilityEvidenceError("runtime adapter version is not installed")
            chain_id = descriptor.get("evmChainId")
            allowed_chains = {1, 8453} if expected_network == "mainnet" else {11155111, 84532}
            if descriptor.get("kind") != "TIBETSWAP_V2" and (type(chain_id) is not int or chain_id not in allowed_chains):
                raise SolsCapabilityEvidenceError("runtime adapter EVM chain crosses the network boundary")
        descriptor_record_id = _nonempty(
            descriptor.get("recordId"),
            f"runtimeEvidence.adapters[{index}].recordId",
        ).lower()
        if descriptor_record_id not in record_ids:
            raise SolsCapabilityEvidenceError(
                "runtime adapter targets an ungoverned record"
            )
        try:
            validate_adapter_descriptor(descriptor)
            validate_adapter_governance_binding(
                descriptor,
                records_by_id[descriptor_record_id],
            )
        except SolsCapabilityAdapterError as exc:
            raise SolsCapabilityEvidenceError(
                f"runtime adapter is invalid: {exc}"
            ) from exc

    if governed_root is not None and evidence_root.lower() != governed_root.lower():
        raise SolsCapabilityEvidenceError(
            "release evidence targets a different governed root"
        )
    if governed_records is not None:
        expected_records = _canonical_json(
            [_public_record(value) for value in governed_records]
        )
        evidence_records = _canonical_json(
            [_public_record(value) for value in records]
        )
        if not secrets.compare_digest(expected_records, evidence_records):
            raise SolsCapabilityEvidenceError(
                "release evidence records do not match reconstructed statutes"
            )

    return SolsCapabilityEvidence(
        capability=capability,
        release_tag=release_tag,
        source_sha=source_sha,
        governed_root=evidence_root,
        adapter_ids=adapter_ids,
        adapter_descriptors=adapter_descriptors,
        records=records,
        runtime_evidence_root=runtime_root,
        sha256=digest,
        environment=payload.get("environment"),
        network=expected_network,
        deployment_id=payload.get("deploymentId"),
    )


def _public_record(value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove response decoration before exact evidence comparison."""

    return {
        str(key): item
        for key, item in value.items()
        if key not in {"governedActive", "executable", "readiness"}
    }


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SolsCapabilityEvidenceError(f"{label} must be an object")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SolsCapabilityEvidenceError(f"{label} must be a non-empty string")
    return value.strip()


def _hex(value: object, size: int, label: str) -> str:
    if not isinstance(value, str):
        raise SolsCapabilityEvidenceError(f"{label} must be hex")
    normalized = value.removeprefix("0x").lower()
    if len(normalized) != size * 2:
        raise SolsCapabilityEvidenceError(f"{label} must be {size} bytes")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise SolsCapabilityEvidenceError(f"{label} must be hex") from exc
    return normalized


__all__ = [
    "SolsCapabilityEvidence",
    "SolsCapabilityEvidenceError",
    "load_sols_capability_evidence",
]
