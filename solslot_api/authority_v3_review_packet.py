"""Deterministic Authority V3 independent-review request and receipt helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)

from .authority_v3_review import REQUIRED_SCOPES, REVIEW_KIND


REQUEST_KIND = "solslot-authority-v3-review-request"
REQUEST_STATUS = "review-required"
PROTOCOL_VERSION = "solslot-v2"
REQUEST_SCHEMA_VERSION = 2
RECEIPT_SCHEMA_VERSION = 2
SOURCE_MANIFEST_VERSION = 4
MAX_SCOPE_EVIDENCE_BYTES = 2 * 1024 * 1024
SOURCE_REPOSITORIES = {
    "protocol": "https://github.com/MattHintz/solslot-protocol",
    "evm": "https://github.com/MattHintz/solslot-evm",
    "omnichain": "https://github.com/solslot/omnichain",
    "api": "https://github.com/MattHintz/solslot-api",
    "legacyBackend": "https://github.com/solslot/solslot-backend",
    "keyOfSolomon": "https://github.com/solslot/KeyofSolomon",
    "samuel": "https://github.com/solslot/Samuel",
    "customerWeb": "https://github.com/solslot/solslot",
    "adminPortal": "https://github.com/MattHintz/solslot-portal",
}
TRUST_BOUNDARIES = {
    "chialisp-wrapper": {
        "repositories": ["protocol", "api"],
        "sourcePaths": [
            "solslot_puzzles/admin_authority_v3_inner.clsp",
            "solslot_puzzles/admin_authority_action_v1.clsp",
            "solslot_puzzles/admin_identity_action_v1.clsp",
            "solslot_puzzles/admin_identity_prepare_announcement_v1.clsp",
            "solslot_puzzles/admin_identity_terminal_action_v1.clsp",
            "solslot_puzzles/eip712_member_v2.clsp",
            "solslot_puzzles/admin_authority_v3_driver.py",
            "solslot_api/admin_key_changes.py",
        ],
        "reviewObjectives": [
            "owner slot 0 plus exactly one coadministrator is required",
            "recovery keys cannot authorize operational spends",
            "replacement, network, manifest, nonce, and expiry are bound",
            "pending recovery freezes unrelated privileged operations",
            "cancel and completion can only reach the committed state",
        ],
        "verificationCommands": [
            {
                "repository": "protocol",
                "command": "pytest -q tests/test_admin_authority_v3.py",
            },
            {
                "repository": "api",
                "command": "pytest -q "
                "tests/test_admin_key_change_chia_packages.py "
                "tests/test_admin_key_changes.py",
            },
        ],
    },
    "mips-composition": {
        "repositories": ["protocol"],
        "sourcePaths": [
            "solslot_puzzles/recovery_dependencies.py",
            "solslot_puzzles/admin_authority_v3_inner.clsp",
            "solslot_puzzles/admin_authority_v3_driver.py",
            "tests/test_recovery_dependencies.py",
        ],
        "reviewObjectives": [
            "the pinned Apache-2.0 SDK commit is exact and reproducible",
            "singleton-member identities cannot change the authority tree",
            "restricted recovery modules expose no operational authority",
            "timelocks, vetoes, and side-effect prevention compose correctly",
        ],
        "verificationCommands": [
            {
                "repository": "protocol",
                "command": "pytest -q tests/test_recovery_dependencies.py "
                "tests/test_admin_authority_v3.py",
            },
        ],
    },
    "safe-recovery-module": {
        "repositories": ["omnichain", "api"],
        "sourcePaths": [
            "contracts/SolslotAdminRecoveryV3.sol",
            "test/AuthorityV3Recovery.test.js",
            "test/AuthorityV3IntentFixture.test.js",
            "solslot_api/admin_key_changes.py",
            "tests/test_admin_key_changes.py",
        ],
        "reviewObjectives": [
            "the two other identity Safes approve lost-key recovery",
            "the exact replacement and cross-chain intent are immutable",
            "routine and lost-key delays cannot be bypassed",
            "completion cannot create a partial authority transition",
        ],
        "verificationCommands": [
            {
                "repository": "omnichain",
                "command": "npm test -- --grep \"Authority V3\"",
            },
            {
                "repository": "api",
                "command": "pytest -q tests/test_admin_key_changes.py "
                "tests/test_admin_key_change_chia_packages.py",
            },
        ],
    },
    "safe-authority-guards": {
        "repositories": ["omnichain"],
        "sourcePaths": [
            "contracts/SolslotAuthorityGuardV3.sol",
            "contracts/SolslotAdminRecoveryV3.sol",
            "test/SafeAuthorityOperation.test.js",
            "test/AuthorityV3Recovery.test.js",
            "scripts/lib/authority-v3-deployment.js",
        ],
        "reviewObjectives": [
            "owner swaps, guard removal, and module removal are blocked",
            "owner slot 0 plus one coadministrator remains mandatory",
            "a pending recovery blocks arbitrary Safe transactions",
            "deployment evidence binds runtime code and the identity roster",
        ],
        "verificationCommands": [
            {
                "repository": "omnichain",
                "command": "npm test -- --grep "
                "\"Safe Authority|Authority V3\"",
            },
        ],
    },
}

_EVIDENCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RELEASE_ID = re.compile(
    r"^solslot-v2-alpha-(rc[0-9]+(?:\.[0-9]+)?)-([0-9]{8})$"
)
FINAL_APPROVAL_REQUIREMENTS = [
    "all nine source SHAs must match the exact release source manifest",
    "the live Base Sepolia governance deployment evidence must pass "
    "the API evidence loader",
    "all four trust boundaries need independent evidence",
    "the final receipt must be checksum-pinned before ceremony use",
]


class AuthorityV3ReviewPacketError(ValueError):
    """Review request or reviewer evidence is malformed or stale."""


def _exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise AuthorityV3ReviewPacketError(
            f"{label} contains unsupported or missing fields"
        )


def canonical_hash(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in payload.items() if key != "artifactHash"
    }
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path, *, maximum_bytes: int) -> str:
    try:
        stat = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.st_size <= 0
            or stat.st_size > maximum_bytes
        ):
            raise AuthorityV3ReviewPacketError(
                f"review evidence is invalid: {path}"
            )
        raw = path.read_bytes()
    except OSError as exc:
        raise AuthorityV3ReviewPacketError(
            f"review evidence is unreadable: {path}"
        ) from exc
    return "0x" + hashlib.sha256(raw).hexdigest()


def normalize_repository(value: object) -> str:
    candidate = str(value or "").strip()
    if candidate.startswith("git@github.com:"):
        candidate = (
            "https://github.com/"
            + candidate.removeprefix("git@github.com:")
        )
    parts = urlsplit(candidate)
    if (
        parts.scheme != "https"
        or parts.hostname != "github.com"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise AuthorityV3ReviewPacketError(
            "review repositories must use credential-free GitHub URLs"
        )
    path = parts.path.removesuffix(".git").rstrip("/")
    if len([item for item in path.split("/") if item]) != 2:
        raise AuthorityV3ReviewPacketError(
            "review repository URL must name one GitHub repository"
        )
    return urlunsplit(("https", "github.com", path, "", ""))


def _full_sha(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if len(normalized) != 40:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be a full commit SHA"
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be valid hex"
        ) from exc
    return normalized


def _bytes32(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if not normalized.startswith("0x") or len(normalized) != 66:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be 0x-prefixed 32-byte hex"
        )
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be valid hex"
        ) from exc
    if not any(raw):
        raise AuthorityV3ReviewPacketError(f"{label} cannot be zero")
    return normalized


def _timestamp(value: object, label: str) -> str:
    candidate = str(value or "")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityV3ReviewPacketError(
            f"{label} must be ISO-8601"
        ) from exc
    if parsed.tzinfo is None:
        raise AuthorityV3ReviewPacketError(
            f"{label} must include a timezone"
        )
    return candidate


def _release(value: object) -> tuple[str, str, str]:
    release_id = str(value or "").strip()
    match = _RELEASE_ID.fullmatch(release_id)
    if match is None:
        raise AuthorityV3ReviewPacketError(
            "releaseId must identify a coordinated testnet alpha release"
        )
    release_branch = "release/testnet-alpha-" + release_id.removeprefix(
        "solslot-v2-alpha-"
    )
    inventory_release = match.group(1).upper()
    return release_id, release_branch, inventory_release


def _source_manifest_hash(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key != "manifestHash"
    }
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _authority_source_commitment(
    source_shas: Mapping[str, str],
) -> str:
    return canonical_hash(
        {
            "version": SOURCE_MANIFEST_VERSION,
            "sources": dict(source_shas),
            "dependencies": {
                "administratorRecovery": (
                    "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
                )
            },
        }
    )


def validate_source_manifest(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    _exact_keys(
        payload,
        {
            "schemaVersion",
            "kind",
            "releaseId",
            "network",
            "testOnly",
            "sourceShas",
            "dependencies",
            "authoritySourceCommitment",
            "sources",
            "manifestHash",
        },
        "release source manifest",
    )
    release_id, release_branch, _ = _release(payload.get("releaseId"))
    if (
        payload.get("schemaVersion") != SOURCE_MANIFEST_VERSION
        or payload.get("kind") != "solslot-release-source-manifest"
        or payload.get("network") != "testnet11"
        or payload.get("testOnly") is not True
    ):
        raise AuthorityV3ReviewPacketError(
            "release source manifest is unsupported"
        )
    source_shas = payload.get("sourceShas")
    sources = payload.get("sources")
    dependencies = payload.get("dependencies")
    recovery = (
        dependencies.get("administratorRecovery")
        if isinstance(dependencies, Mapping)
        else None
    )
    if isinstance(dependencies, Mapping):
        _exact_keys(
            dependencies,
            {"administratorRecovery"},
            "release source dependencies",
        )
    if isinstance(recovery, Mapping):
        _exact_keys(
            recovery,
            {"repository", "commit", "license", "manifestHash"},
            "administrator recovery dependency",
        )
    if (
        not isinstance(source_shas, Mapping)
        or not isinstance(sources, Mapping)
        or set(source_shas) != set(SOURCE_REPOSITORIES)
        or set(sources) != set(SOURCE_REPOSITORIES)
    ):
        raise AuthorityV3ReviewPacketError(
            "release source manifest must bind all nine repositories"
        )
    normalized_shas: dict[str, str] = {}
    normalized_sources: dict[str, dict[str, str]] = {}
    for name, expected_repository in SOURCE_REPOSITORIES.items():
        source = sources.get(name)
        if not isinstance(source, Mapping):
            raise AuthorityV3ReviewPacketError(
                f"release source manifest {name} record is invalid"
            )
        _exact_keys(
            source,
            {"repository", "branch", "commit"},
            f"release source manifest {name} record",
        )
        commit = _full_sha(source_shas.get(name), f"sourceShas.{name}")
        if _full_sha(source.get("commit"), f"{name} commit") != commit:
            raise AuthorityV3ReviewPacketError(
                f"release source manifest {name} commit is inconsistent"
            )
        repository = normalize_repository(source.get("repository"))
        if repository != normalize_repository(expected_repository):
            raise AuthorityV3ReviewPacketError(
                f"release source manifest {name} repository is not canonical"
            )
        if source.get("branch") != release_branch:
            raise AuthorityV3ReviewPacketError(
                f"release source manifest {name} branch is not release-bound"
            )
        normalized_shas[name] = commit
        normalized_sources[name] = {
            "repository": repository,
            "branch": release_branch,
            "commit": commit,
        }
    if (
        not isinstance(recovery, Mapping)
        or recovery.get("repository") != PINNED_CNI_WALLET_SDK_REPOSITORY
        or recovery.get("commit") != PINNED_CNI_WALLET_SDK_COMMIT
        or recovery.get("license") != PINNED_CNI_WALLET_SDK_LICENSE
        or recovery.get("manifestHash")
        != "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
    ):
        raise AuthorityV3ReviewPacketError(
            "release source manifest does not bind the pinned Chia SDK"
        )
    authority_commitment = _authority_source_commitment(normalized_shas)
    if payload.get("authoritySourceCommitment") != authority_commitment:
        raise AuthorityV3ReviewPacketError(
            "release Authority V3 source commitment is invalid"
        )
    if payload.get("manifestHash") != _source_manifest_hash(payload):
        raise AuthorityV3ReviewPacketError(
            "release source manifest hash is invalid"
        )
    return {
        "releaseId": release_id,
        "releaseBranch": release_branch,
        "sourceShas": normalized_shas,
        "sources": normalized_sources,
        "manifestHash": payload["manifestHash"],
        "authoritySourceCommitment": authority_commitment,
    }


def build_review_request(
    *,
    source_states: Mapping[str, Mapping[str, object]],
    source_manifest: Mapping[str, Any],
    source_manifest_file_sha256: str,
    puzzle_inventory: Mapping[str, Any],
    puzzle_inventory_file_sha256: str,
    authority_inner_mod_hash: str,
    generated_at: str,
    release_refs_verified: bool,
) -> dict[str, Any]:
    manifest = validate_source_manifest(source_manifest)
    if set(source_states) != set(SOURCE_REPOSITORIES):
        raise AuthorityV3ReviewPacketError(
            "review request must bind all nine source repositories"
        )
    if release_refs_verified is not True:
        raise AuthorityV3ReviewPacketError(
            "review request requires exact branch, tag, and main verification"
        )
    sources: dict[str, dict[str, str]] = {}
    for name, expected_repository in SOURCE_REPOSITORIES.items():
        state = source_states[name]
        repository = normalize_repository(state.get("repository"))
        if repository != normalize_repository(expected_repository):
            raise AuthorityV3ReviewPacketError(
                f"{name} does not use the canonical repository"
            )
        branch = str(state.get("branch") or "").strip()
        commit = _full_sha(state.get("commit"), f"{name} commit")
        sources[name] = {
            "repository": repository,
            "branch": branch,
            "commit": commit,
        }
        if sources[name] != manifest["sources"][name]:
            raise AuthorityV3ReviewPacketError(
                f"{name} worktree differs from the release source manifest"
            )
    _, _, expected_inventory_release = _release(manifest["releaseId"])
    if (
        puzzle_inventory.get("schema") != "solslot.puzzle-hashes.v1"
        or puzzle_inventory.get("release") != expected_inventory_release
        or not isinstance(puzzle_inventory.get("newPuzzleHashes"), Mapping)
        or not isinstance(puzzle_inventory.get("changedPuzzleHashes"), Mapping)
    ):
        raise AuthorityV3ReviewPacketError(
            "current puzzle inventory is missing or unsupported"
        )
    inner_hash = _bytes32(
        authority_inner_mod_hash,
        "Authority V3 inner module hash",
    )
    inventory_hash = _bytes32(
        "0x" + puzzle_inventory_file_sha256.removeprefix("0x"),
        "puzzle inventory file SHA-256",
    )
    generated = _timestamp(generated_at, "generatedAt")
    manifest_file_hash = _bytes32(
        "0x" + source_manifest_file_sha256.removeprefix("0x"),
        "source manifest file SHA-256",
    )
    source_shas = manifest["sourceShas"]
    payload: dict[str, Any] = {
        "schemaVersion": REQUEST_SCHEMA_VERSION,
        "kind": REQUEST_KIND,
        "status": REQUEST_STATUS,
        "network": "testnet11",
        "protocolVersion": PROTOCOL_VERSION,
        "generatedAt": generated,
        "release": {
            "releaseId": manifest["releaseId"],
            "releaseBranch": manifest["releaseBranch"],
            "sourceManifestHash": manifest["manifestHash"],
            "sourceManifestFileSha256": manifest_file_hash,
            "authoritySourceCommitment": manifest[
                "authoritySourceCommitment"
            ],
            "releaseRefsVerified": True,
        },
        "sourceShas": source_shas,
        "sources": sources,
        "chiaAuthority": {
            "innerModHash": inner_hash,
            "puzzleInventoryRelease": expected_inventory_release,
            "puzzleInventoryFileSha256": inventory_hash,
            "canonicalPuzzleChecksum": _bytes32(
                "0x"
                + str(
                    puzzle_inventory.get("canonicalChecksum") or ""
                ).removeprefix("0x"),
                "canonical puzzle checksum",
            ),
        },
        "evmAuthority": {
            "sourceSha": source_shas["omnichain"],
            "governanceEvidenceRequired": True,
            "governanceEvidenceHash": None,
        },
        "upstream": {
            "repository": PINNED_CNI_WALLET_SDK_REPOSITORY,
            "commit": PINNED_CNI_WALLET_SDK_COMMIT,
            "license": PINNED_CNI_WALLET_SDK_LICENSE,
            "manifestHash": "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH,
        },
        "trustBoundaries": [
            {"scope": scope, **TRUST_BOUNDARIES[scope]}
            for scope in sorted(REQUIRED_SCOPES)
        ],
        "finalApprovalRequirements": FINAL_APPROVAL_REQUIREMENTS,
    }
    payload["artifactHash"] = canonical_hash(payload)
    return payload


def validate_review_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    if (
        payload.get("schemaVersion") != REQUEST_SCHEMA_VERSION
        or payload.get("kind") != REQUEST_KIND
        or payload.get("status") != REQUEST_STATUS
        or payload.get("network") != "testnet11"
        or payload.get("protocolVersion") != PROTOCOL_VERSION
        or payload.get("artifactHash") != canonical_hash(payload)
        or "outcome" in payload
        or "reviews" in payload
    ):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request is unsupported or approving"
        )
    _exact_keys(
        payload,
        {
            "schemaVersion",
            "kind",
            "status",
            "network",
            "protocolVersion",
            "generatedAt",
            "release",
            "sourceShas",
            "sources",
            "chiaAuthority",
            "evmAuthority",
            "upstream",
            "trustBoundaries",
            "finalApprovalRequirements",
            "artifactHash",
        },
        "Authority V3 review request",
    )
    source_shas = payload.get("sourceShas")
    sources = payload.get("sources")
    release = payload.get("release")
    chia = payload.get("chiaAuthority")
    evm = payload.get("evmAuthority")
    upstream = payload.get("upstream")
    boundaries = payload.get("trustBoundaries")
    if not all(
        isinstance(value, Mapping)
        for value in (
            source_shas,
            sources,
            release,
            chia,
            evm,
            upstream,
        )
    ) or not isinstance(boundaries, list):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request is incomplete"
        )
    if set(source_shas) != set(SOURCE_REPOSITORIES) or set(sources) != set(
        SOURCE_REPOSITORIES
    ):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request source set is incomplete"
        )
    release_id, release_branch, inventory_release = _release(
        release.get("releaseId")
    )
    _exact_keys(
        release,
        {
            "releaseId",
            "releaseBranch",
            "sourceManifestHash",
            "sourceManifestFileSha256",
            "authoritySourceCommitment",
            "releaseRefsVerified",
        },
        "Authority V3 review request release",
    )
    if (
        release.get("releaseBranch") != release_branch
        or release.get("releaseRefsVerified") is not True
    ):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request release refs are invalid"
        )
    _bytes32(
        release.get("sourceManifestFileSha256"),
        "source manifest file SHA-256",
    )
    normalized_shas: dict[str, str] = {}
    normalized_sources: dict[str, dict[str, str]] = {}
    for name, repository in SOURCE_REPOSITORIES.items():
        state = sources[name]
        commit = _full_sha(source_shas.get(name), f"sourceShas.{name}")
        if isinstance(state, Mapping):
            _exact_keys(
                state,
                {"repository", "branch", "commit"},
                f"Authority V3 review request {name} source",
            )
        if (
            not isinstance(state, Mapping)
            or normalize_repository(state.get("repository"))
            != normalize_repository(repository)
            or _full_sha(state.get("commit"), f"{name} commit")
            != commit
            or state.get("branch") != release_branch
        ):
            raise AuthorityV3ReviewPacketError(
                f"Authority V3 review request {name} source is invalid"
            )
        normalized_shas[name] = commit
        normalized_sources[name] = dict(state)
    authority_commitment = _authority_source_commitment(normalized_shas)
    if release.get("authoritySourceCommitment") != authority_commitment:
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request source commitment is invalid"
        )
    reconstructed_manifest: dict[str, Any] = {
        "schemaVersion": SOURCE_MANIFEST_VERSION,
        "kind": "solslot-release-source-manifest",
        "releaseId": release_id,
        "network": "testnet11",
        "testOnly": True,
        "sourceShas": normalized_shas,
        "dependencies": {
            "administratorRecovery": {
                "repository": PINNED_CNI_WALLET_SDK_REPOSITORY,
                "commit": PINNED_CNI_WALLET_SDK_COMMIT,
                "license": PINNED_CNI_WALLET_SDK_LICENSE,
                "manifestHash": "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH,
            }
        },
        "authoritySourceCommitment": authority_commitment,
        "sources": normalized_sources,
    }
    if release.get("sourceManifestHash") != _source_manifest_hash(
        reconstructed_manifest
    ):
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request source manifest hash is invalid"
        )
    _timestamp(payload.get("generatedAt"), "generatedAt")
    _exact_keys(
        chia,
        {
            "innerModHash",
            "puzzleInventoryRelease",
            "puzzleInventoryFileSha256",
            "canonicalPuzzleChecksum",
        },
        "Authority V3 Chia binding",
    )
    _bytes32(chia.get("innerModHash"), "Authority V3 inner module hash")
    if chia.get("puzzleInventoryRelease") != inventory_release:
        raise AuthorityV3ReviewPacketError(
            "Authority V3 review request puzzle inventory is stale"
        )
    _bytes32(
        chia.get("puzzleInventoryFileSha256"),
        "puzzle inventory file SHA-256",
    )
    _exact_keys(
        evm,
        {
            "sourceSha",
            "governanceEvidenceRequired",
            "governanceEvidenceHash",
        },
        "Authority V3 EVM binding",
    )
    _bytes32(
        chia.get("canonicalPuzzleChecksum"),
        "canonical puzzle checksum",
    )
    _exact_keys(
        upstream,
        {"repository", "commit", "license", "manifestHash"},
        "Authority V3 upstream binding",
    )
    if (
        _full_sha(evm.get("sourceSha"), "EVM source SHA")
        != source_shas["omnichain"]
        or evm.get("governanceEvidenceRequired") is not True
        or evm.get("governanceEvidenceHash") is not None
    ):
        raise AuthorityV3ReviewPacketError(
            "review request must leave live EVM evidence unresolved"
        )
    if (
        upstream.get("repository") != PINNED_CNI_WALLET_SDK_REPOSITORY
        or upstream.get("commit") != PINNED_CNI_WALLET_SDK_COMMIT
        or upstream.get("license") != PINNED_CNI_WALLET_SDK_LICENSE
        or upstream.get("manifestHash")
        != "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
    ):
        raise AuthorityV3ReviewPacketError(
            "review request does not bind the pinned Chia SDK"
        )
    expected_boundaries = [
        {"scope": scope, **TRUST_BOUNDARIES[scope]}
        for scope in sorted(REQUIRED_SCOPES)
    ]
    if boundaries != expected_boundaries:
        raise AuthorityV3ReviewPacketError(
            "review request must cover all four trust boundaries"
        )
    if payload.get("finalApprovalRequirements") != FINAL_APPROVAL_REQUIREMENTS:
        raise AuthorityV3ReviewPacketError(
            "review request final approval requirements are invalid"
        )
    return dict(payload)


def build_review_receipt(
    *,
    request: Mapping[str, Any],
    governance_evidence: Mapping[str, Any],
    scope_reviews: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    validated = validate_review_request(request)
    if set(scope_reviews) != REQUIRED_SCOPES:
        raise AuthorityV3ReviewPacketError(
            "review receipt requires all four trust boundaries"
        )
    if (
        governance_evidence.get("schemaVersion") != 3
        or governance_evidence.get("kind")
        != "solslot-alpha-authority-v3-governance-deployment"
        or (governance_evidence.get("network"), governance_evidence.get("chainId"))
        not in (("baseSepolia", 84_532), ("baseMainnet", 8453))
        or type(governance_evidence.get("chainId")) is not int
        or governance_evidence.get("artifactHash")
        != canonical_hash(governance_evidence)
    ):
        raise AuthorityV3ReviewPacketError(
            "live Authority V3 governance evidence is invalid"
        )
    reviews: list[dict[str, Any]] = []
    evidence_names: set[str] = set()
    for scope in sorted(REQUIRED_SCOPES):
        item = scope_reviews[scope]
        if not isinstance(item, Mapping):
            raise AuthorityV3ReviewPacketError(
                f"{scope} review must be an object"
            )
        reviewer = str(item.get("reviewer") or "").strip()
        evidence_path = Path(str(item.get("evidencePath") or ""))
        completed_at = _timestamp(
            item.get("completedAt"),
            f"{scope} completedAt",
        )
        if not reviewer:
            raise AuthorityV3ReviewPacketError(
                f"{scope} reviewer is required"
            )
        if (
            not evidence_path.name
            or not _EVIDENCE_NAME.fullmatch(evidence_path.name)
        ):
            raise AuthorityV3ReviewPacketError(
                f"{scope} evidencePath must end in one safe file name"
            )
        if evidence_path.name in evidence_names:
            raise AuthorityV3ReviewPacketError(
                "each trust boundary needs a distinct evidence file"
            )
        evidence_names.add(evidence_path.name)
        reviews.append(
            {
                "scope": scope,
                "approved": True,
                "reviewer": reviewer,
                "evidenceFile": evidence_path.name,
                "evidenceHash": file_sha256(
                    evidence_path,
                    maximum_bytes=MAX_SCOPE_EVIDENCE_BYTES,
                ),
                "completedAt": completed_at,
            }
        )
    payload: dict[str, Any] = {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "kind": REVIEW_KIND,
        "network": "testnet11",
        "protocolVersion": PROTOCOL_VERSION,
        "outcome": "approved",
        "reviewRequestHash": validated["artifactHash"],
        "release": validated["release"],
        "sourceShas": validated["sourceShas"],
        "chiaAuthority": {
            "innerModHash": validated["chiaAuthority"]["innerModHash"],
        },
        "evmAuthority": {
            "governanceEvidenceHash": governance_evidence["artifactHash"],
        },
        "upstream": validated["upstream"],
        "reviews": reviews,
    }
    payload["artifactHash"] = canonical_hash(payload)
    return payload


def review_request_file_sha256(payload: Mapping[str, Any]) -> str:
    raw = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(
        "ascii"
    )
    return hashlib.sha256(raw).hexdigest()


__all__ = [
    "AuthorityV3ReviewPacketError",
    "MAX_SCOPE_EVIDENCE_BYTES",
    "REQUEST_KIND",
    "REQUEST_STATUS",
    "SOURCE_REPOSITORIES",
    "TRUST_BOUNDARIES",
    "build_review_receipt",
    "build_review_request",
    "canonical_hash",
    "file_sha256",
    "normalize_repository",
    "review_request_file_sha256",
    "validate_review_request",
    "validate_source_manifest",
]
