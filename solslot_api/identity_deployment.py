"""Resolve the effective zkPassport deployment from confirmed Chia authority.

The signed genesis artifact is always verified and returned unchanged.  An EVM
deployment becomes effective only when a canonical amendment body matches the
latest amendment announcement in the chain-verified administrator authority
lineage.  Mutable environment variables cannot activate or roll back a revision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.condition_opcodes import ConditionOpcode

from solslot_puzzles.identity_deployment_amendment import (
    ANNOUNCEMENT_PREFIX,
    ConfirmedAmendmentAnchor,
    ZERO_HASH,
    amendment_hash,
    announcement_message,
    parse_canonical_statement,
    resolve_effective_identity_deployment,
    verify_statement_against_records,
)

from .admin_authority_v3 import (
    _inner_from_full_puzzle,
    _program,
    _singleton_tip,
    build_admin_authority_v3_snapshot,
)
from .chia_provider import ChiaProvider
from .config import Settings
from .public_artifact import load_signed_public_artifact


MAX_AMENDMENT_BYTES = 256 * 1024
MAX_DEPLOYMENT_ARTIFACT_BYTES = 512 * 1024


class IdentityDeploymentError(RuntimeError):
    """Identity deployment selection is absent, inconsistent, or unprovable."""


def genesis_identity_deployment(base: Mapping[str, Any]) -> dict[str, Any]:
    """Project the immutable genesis identity fields into the effective schema."""
    bridge = base.get("bridgePolicy")
    if not isinstance(bridge, Mapping):
        raise IdentityDeploymentError("genesis bridge policy is missing")
    return {
        "schema": "solslot.effective-identity-deployment.v1",
        "source": "signed-genesis",
        "baseArtifactHash": base["artifactHash"],
        "amendmentHash": ZERO_HASH,
        "revision": 0,
        "confirmedHeight": int(
            (base.get("ceremony") or {}).get("confirmedBlockIndex", 0)
        ),
        "evmChainId": int(base.get("evmChainId", 11155111)),
        "addresses": dict(base["evmAddresses"]),
        "acceptedProofVersions": ["0.20.0"],
        "credentialPolicyVersion": int(bridge.get("policyVersion", 2)),
        "identityPolicy": dict(base.get("identityPolicy") or {}),
        "chiaBridgePolicyHash": str(
            (base.get("permanentRules") or {}).get(
                "zkPassportPolicyHash", bridge["policyHash"]
            )
        ),
    }


def require_runtime_identity_bindings(
    settings: Settings, deployment: Mapping[str, Any]
) -> Settings:
    """Return settings pinned to a chain-selected deployment or fail closed.

    Environment values remain useful as operator redundancy, but can never
    select an identity deployment.  They must exactly match the deployment
    selected by confirmed Chia authority history.
    """
    addresses = deployment.get("addresses")
    if not isinstance(addresses, Mapping):
        raise IdentityDeploymentError("effective identity addresses are missing")
    expected = {
        "zkpassport_forwarder_address": addresses.get("forwarder"),
        "zkpassport_verifier_adapter_address": addresses.get("verifierAdapter"),
        "zkpassport_emitter_address": addresses.get("attestationEmitter"),
    }
    for field, selected in expected.items():
        configured = getattr(settings, field)
        if not isinstance(configured, str) or configured.lower() != str(selected).lower():
            raise IdentityDeploymentError(
                f"configured {field} does not match the chain-selected identity deployment"
            )
    if settings.zkpassport_evm_chain_id != deployment.get("evmChainId"):
        raise IdentityDeploymentError(
            "configured identity chain does not match the chain-selected deployment"
        )
    if str(settings.zkpassport_bridge_policy_hash).lower() != str(
        deployment.get("chiaBridgePolicyHash")
    ).lower():
        raise IdentityDeploymentError(
            "configured bridge policy does not match the chain-selected deployment"
        )
    if settings.zkpassport_policy_version != deployment.get("credentialPolicyVersion"):
        raise IdentityDeploymentError(
            "configured credential policy version does not match the chain-selected deployment"
        )
    return settings


def enrollment_identity_binding(deployment: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable deployment subset saved with a new enrollment."""
    addresses = deployment.get("addresses")
    if not isinstance(addresses, Mapping):
        raise IdentityDeploymentError("effective identity addresses are missing")
    return {
        "schema": "solslot.enrollment-identity-deployment.v1",
        "revision": deployment["revision"],
        "amendmentHash": deployment["amendmentHash"],
        "evmChainId": deployment["evmChainId"],
        "forwarder": addresses["forwarder"],
        "verifierAdapter": addresses["verifierAdapter"],
        "attestationEmitter": addresses["attestationEmitter"],
        "credentialPolicyVersion": deployment["credentialPolicyVersion"],
        "acceptedProofVersions": list(deployment["acceptedProofVersions"]),
    }


def deployment_for_enrollment(
    *,
    base_artifact: Mapping[str, Any],
    current: Mapping[str, Any],
    enrollment: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve the deployment permanently bound to an enrollment.

    Records created before amendment support have no binding and therefore
    remain attached to genesis.  New records must match the current confirmed
    deployment exactly; an uninstalled historical amendment fails closed.
    """
    saved = enrollment.get("identityDeployment")
    if saved is None:
        return genesis_identity_deployment(base_artifact)
    if not isinstance(saved, Mapping):
        raise IdentityDeploymentError("saved enrollment identity deployment is invalid")
    expected = enrollment_identity_binding(current)
    if dict(saved) != expected:
        raise IdentityDeploymentError(
            "saved enrollment belongs to a different identity deployment revision"
        )
    return dict(current)


def settings_for_identity_deployment(
    settings: Settings, deployment: Mapping[str, Any]
) -> Settings:
    """Create a request-local settings view pinned to one saved deployment."""
    addresses = deployment.get("addresses")
    if not isinstance(addresses, Mapping):
        raise IdentityDeploymentError("effective identity addresses are missing")
    return settings.model_copy(
        update={
            "zkpassport_evm_chain_id": deployment["evmChainId"],
            "zkpassport_forwarder_address": addresses["forwarder"],
            "zkpassport_verifier_adapter_address": addresses["verifierAdapter"],
            "zkpassport_emitter_address": addresses["attestationEmitter"],
            "zkpassport_policy_version": deployment["credentialPolicyVersion"],
            "zkpassport_bridge_policy_hash": deployment["chiaBridgePolicyHash"],
        }
    )


@dataclass(frozen=True)
class ChainAmendment:
    digest: str
    authority_coin_id: str
    authority_version: int
    spent_height: int
    announcement: bytes


def _read_bounded(path_text: str, maximum: int, label: str) -> bytes:
    path = Path(path_text)
    try:
        stat = path.stat()
        if not path.is_file() or path.is_symlink() or stat.st_size > maximum:
            raise IdentityDeploymentError(f"{label} is unavailable or exceeds its size limit")
        return path.read_bytes()
    except OSError as exc:
        raise IdentityDeploymentError(f"{label} is unreadable") from exc


def _deployment_artifact(path_text: str) -> dict[str, Any]:
    raw = _read_bounded(path_text, MAX_DEPLOYMENT_ARTIFACT_BYTES, "identity deployment artifact")
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IdentityDeploymentError("identity deployment artifact is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise IdentityDeploymentError("identity deployment artifact must be an object")
    return payload


def _condition_messages(puzzle: Program, solution: Program) -> list[bytes]:
    conditions = conditions_dict_for_solution(puzzle, solution, INFINITE_COST)
    messages: list[bytes] = []
    for opcode in (
        ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT,
        ConditionOpcode.CREATE_COIN_ANNOUNCEMENT,
    ):
        for condition in conditions.get(opcode, []):
            if condition.vars and condition.vars[0].startswith(ANNOUNCEMENT_PREFIX):
                messages.append(condition.vars[0])
    return messages


def _expiry_assertions(puzzle: Program, solution: Program) -> list[int]:
    conditions = conditions_dict_for_solution(puzzle, solution, INFINITE_COST)
    values: list[int] = []
    for condition in conditions.get(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE, []):
        if len(condition.vars) == 1:
            values.append(int.from_bytes(condition.vars[0], "big", signed=True))
    return values


async def discover_confirmed_identity_amendments(
    *, provider: ChiaProvider, artifact: Mapping[str, Any]
) -> tuple[ChainAmendment, ...]:
    launchers = artifact.get("launcherIds")
    if not isinstance(launchers, Mapping):
        raise IdentityDeploymentError("genesis artifact has no launcher coordinates")
    authority_launcher = str(launchers.get("adminAuthority") or "").lower()
    try:
        tip = await _singleton_tip(provider, authority_launcher)
    except ValueError as exc:
        raise IdentityDeploymentError(str(exc)) from exc
    if tip is None or tip.depth < 1:
        raise IdentityDeploymentError("administrator authority is not confirmed")
    found: list[ChainAmendment] = []
    for coin in tip.lineage[1:-1]:
        if coin.spent_height is None:
            raise IdentityDeploymentError("authority lineage spend height is missing")
        payload = await provider.get_puzzle_and_solution(coin.coin_id, coin.spent_height)
        if not isinstance(payload, Mapping):
            raise IdentityDeploymentError("authority lineage spend is unavailable")
        puzzle = _program(payload.get("puzzle_reveal"), "authority puzzle")
        solution = _program(payload.get("solution"), "authority solution")
        messages = _condition_messages(puzzle, solution)
        if len(messages) > 1:
            raise IdentityDeploymentError("authority spend emitted multiple identity amendments")
        if messages:
            message = messages[0]
            if len(message) != len(ANNOUNCEMENT_PREFIX) + 32:
                raise IdentityDeploymentError("identity amendment announcement is malformed")
            parsed = __import__(
                "solslot_puzzles.admin_authority_v3_driver",
                fromlist=["parse_inner_puzzle"],
            ).parse_inner_puzzle(_inner_from_full_puzzle(puzzle))
            found.append(
                ChainAmendment(
                    digest="0x" + message[len(ANNOUNCEMENT_PREFIX) :].hex(),
                    authority_coin_id=coin.coin_id,
                    authority_version=int(parsed.state.authority_version),
                    spent_height=coin.spent_height,
                    announcement=message,
                )
            )
    if len({item.digest for item in found}) != len(found):
        raise IdentityDeploymentError("identity amendment digest was replayed")
    return tuple(found)


async def _verify_activation_boundary(
    *,
    provider: ChiaProvider,
    artifact: Mapping[str, Any],
    statement: Mapping[str, Any],
    selected: ChainAmendment,
) -> None:
    boundary = statement["activationBoundary"]
    snapshot = await build_admin_authority_v3_snapshot(artifact=artifact, provider=provider)
    if not snapshot.chain_verified or snapshot.pending:
        raise IdentityDeploymentError("current administrator authority is not safely resolved")
    if snapshot.launcher_id != boundary["authorityLauncherId"]:
        raise IdentityDeploymentError("activation authority launcher is stale")
    if selected.authority_coin_id != boundary["authorityCoinId"]:
        raise IdentityDeploymentError("activation authority coin is stale")
    if selected.authority_version != boundary["authorityVersion"]:
        raise IdentityDeploymentError("activation authority version is stale")
    if snapshot.authority_version <= selected.authority_version:
        raise IdentityDeploymentError("activation authority continuation is unconfirmed")

    roster_coins = boundary["rosterIdentityCoinIds"]
    signer_slots = boundary["signerSlots"]
    signer_coins = boundary["signerIdentityCoinIds"]
    for slot, identity in enumerate(snapshot.identities):
        tip = await _singleton_tip(provider, identity.launcher_id)
        if tip is None or roster_coins[slot] not in {coin.coin_id for coin in tip.lineage}:
            raise IdentityDeploymentError("activation roster coin is not in the current identity lineage")
    for slot, coin_id in zip(signer_slots, signer_coins, strict=True):
        record = await provider.get_coin_record_by_name(coin_id)
        if not isinstance(record, Mapping) or int(record.get("spent_block_index") or 0) != selected.spent_height:
            raise IdentityDeploymentError(
                f"administrator identity slot {slot} did not authorize the activation spend"
            )

    spend = await provider.get_puzzle_and_solution(
        selected.authority_coin_id, selected.spent_height
    )
    if not isinstance(spend, Mapping):
        raise IdentityDeploymentError("activation authority spend is unavailable")
    puzzle = _program(spend.get("puzzle_reveal"), "activation authority puzzle")
    solution = _program(spend.get("solution"), "activation authority solution")
    if statement["approvalExpiresAt"] not in _expiry_assertions(puzzle, solution):
        raise IdentityDeploymentError("activation spend does not enforce the reviewed expiry")


async def load_effective_identity_deployment(
    settings: Settings,
    *,
    provider: ChiaProvider,
) -> dict[str, Any]:
    """Return genesis or the latest confirmed amendment; fail closed on drift."""
    base = load_signed_public_artifact(settings)
    amendments = await discover_confirmed_identity_amendments(provider=provider, artifact=base)
    configured = bool(settings.identity_deployment_amendment_path)
    required_config = (
        settings.identity_deployment_artifact_path,
        settings.identity_deployment_plan_hash,
    )
    if configured != all(bool(value) for value in required_config):
        raise IdentityDeploymentError("identity deployment activation configuration is incomplete")
    if not configured:
        if amendments:
            raise IdentityDeploymentError("confirmed identity amendment body is missing")
        return genesis_identity_deployment(base)
    raw = _read_bounded(
        settings.identity_deployment_amendment_path,
        MAX_AMENDMENT_BYTES,
        "identity deployment amendment",
    )
    try:
        statement = parse_canonical_statement(raw)
    except ValueError as exc:
        raise IdentityDeploymentError(str(exc)) from exc
    deployment = _deployment_artifact(settings.identity_deployment_artifact_path)
    if amendments:
        selected = amendments[-1]
        if amendment_hash(statement) != selected.digest:
            raise IdentityDeploymentError(
                "configured identity amendment is not the latest confirmed revision"
            )
        if statement["revision"] != len(amendments):
            raise IdentityDeploymentError(
                "identity amendment revision does not match authority history"
            )
    previous_hash = ZERO_HASH if len(amendments) <= 1 else amendments[-2].digest
    try:
        verify_statement_against_records(
            statement,
            base_artifact=base,
            deployment_artifact=deployment,
            deployment_plan_hash=settings.identity_deployment_plan_hash,
            previous_amendment_hash=previous_hash,
        )
    except ValueError as exc:
        raise IdentityDeploymentError(str(exc)) from exc

    # A reviewed amendment must be installable before its authority spend is
    # broadcast. Until that spend confirms, genesis remains authoritative.
    if not amendments:
        if statement["revision"] != 1:
            raise IdentityDeploymentError(
                "prepared identity amendment revision does not follow authority history"
            )
        return genesis_identity_deployment(base)

    await _verify_activation_boundary(
        provider=provider,
        artifact=base,
        statement=statement,
        selected=selected,
    )
    anchor = ConfirmedAmendmentAnchor(
        amendment_hash=selected.digest,
        authority_launcher_id=statement["activationBoundary"]["authorityLauncherId"],
        spent_authority_coin_id=selected.authority_coin_id,
        authority_version=selected.authority_version,
        confirmed_height=selected.spent_height,
        # The spend's exact ASSERT_BEFORE_SECONDS_ABSOLUTE was verified above;
        # using the bound value here avoids trusting an off-chain block clock.
        confirmed_timestamp=statement["approvalExpiresAt"],
        announcement=selected.announcement,
    )
    try:
        return resolve_effective_identity_deployment(
            base_artifact=base,
            deployment_artifact=deployment,
            deployment_plan_hash=settings.identity_deployment_plan_hash,
            statement=statement,
            anchor=anchor,
            previous_amendment_hash=(
                ZERO_HASH if len(amendments) == 1 else amendments[-2].digest
            ),
        )
    except ValueError as exc:
        raise IdentityDeploymentError(str(exc)) from exc


__all__ = [
    "ChainAmendment",
    "IdentityDeploymentError",
    "discover_confirmed_identity_amendments",
    "deployment_for_enrollment",
    "enrollment_identity_binding",
    "genesis_identity_deployment",
    "load_effective_identity_deployment",
    "require_runtime_identity_bindings",
    "settings_for_identity_deployment",
]
