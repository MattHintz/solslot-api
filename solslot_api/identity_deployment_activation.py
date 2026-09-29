"""Owner-plus-one activation of a reviewed identity deployment amendment."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from chia.types.blockchain_format.program import Program
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v3_driver import (
    AUTHORITY_LAUNCHER_AMOUNT,
    IDENTITY_LAUNCHER_AMOUNTS,
    build_authority_operational_mips_spend,
    build_identity_operational_action,
    build_identity_operational_solution,
    build_operational_solution,
)
from solslot_puzzles.eip712_helpers import build_eip712_member_solution
from solslot_puzzles.identity_deployment_amendment import (
    amendment_hash,
    announcement_message,
    parse_canonical_statement,
    verify_statement_against_records,
)

from .admin_authority_v3 import (
    build_admin_authority_v3_snapshot,
    load_live_singleton_context,
)
from .admin_key_changes import (
    _assert_full_puzzle_hash,
    _authority_inner_from_snapshot,
    _current_identity_vaults,
    _genesis_authority_from_artifact,
    _singleton_spend,
    _verified_evidence_context,
)
from .governance_publisher import _action


CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_BEFORE_SECONDS_ABSOLUTE = 85


@dataclass(frozen=True)
class IdentityActivationBuild:
    statement: Mapping[str, Any]
    statement_hash: str
    context: Any
    delegated: Program
    actions: tuple[Any, ...]

    @property
    def request_body(self) -> dict[str, Any]:
        return {
            "amendmentHash": self.statement_hash,
            "revision": int(self.statement["revision"]),
        }


def _read_canonical_statement(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 256 * 1024:
        raise ValueError("identity deployment amendment is unavailable")
    return parse_canonical_statement(path.read_bytes())


def _read_deployment_artifact(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 512 * 1024:
        raise ValueError("identity deployment artifact is unavailable")
    value = json.loads(path.read_text(encoding="ascii"))
    if not isinstance(value, dict):
        raise ValueError("identity deployment artifact must be an object")
    return value


def identity_activation_request(settings: Any) -> dict[str, Any]:
    """Return the only request body which can activate configured evidence."""
    if not settings.identity_deployment_amendment_path:
        raise ValueError("identity deployment activation evidence is not configured")
    statement = _read_canonical_statement(settings.identity_deployment_amendment_path)
    return {
        "amendmentHash": amendment_hash(statement),
        "revision": int(statement["revision"]),
    }


async def prepare_identity_activation(*, binding: Mapping[str, Any], request: Any, settings: Any,
                                      now: int | None = None) -> IdentityActivationBuild:
    """Rebuild the exact live action which two selected administrators review."""
    if binding.get("method") != "POST" or binding.get("path") != "/admin/identity-deployment/activate":
        raise ValueError("identity activation must bind the exact activation endpoint")
    if binding.get("query") or binding.get("ifMatch"):
        raise ValueError("identity activation does not accept query or conditional mutation fields")
    if not settings.identity_deployment_amendment_path or not settings.identity_deployment_artifact_path:
        raise ValueError("identity deployment activation evidence is not configured")
    statement = _read_canonical_statement(settings.identity_deployment_amendment_path)
    digest = amendment_hash(statement)
    if dict(binding.get("body") or {}) != {
        "amendmentHash": digest,
        "revision": statement["revision"],
    }:
        raise ValueError("identity activation request differs from the reviewed amendment")

    artifact, evidence, _ = await _verified_evidence_context(settings)
    deployment = _read_deployment_artifact(settings.identity_deployment_artifact_path)
    verify_statement_against_records(
        statement,
        base_artifact=artifact,
        deployment_artifact=deployment,
        deployment_plan_hash=settings.identity_deployment_plan_hash,
    )
    provider = getattr(request.app.state, "coinset", None)
    if provider is None:
        raise ValueError("Testnet11 Chia provider is unavailable")
    snapshot = await build_admin_authority_v3_snapshot(artifact=artifact, provider=provider)
    if not snapshot.chain_verified or snapshot.current_coin_id is None:
        raise ValueError("administrator authority is not confirmed on Testnet11")
    if snapshot.pending:
        raise ValueError("administrator key recovery is active; protocol writes are frozen")
    authority = _genesis_authority_from_artifact(artifact)
    from .genesis import get_genesis_store
    identities = _current_identity_vaults(
        artifact=artifact,
        evidence=evidence,
        store=get_genesis_store(settings),
        authority=authority,
    )
    authority_inner = _authority_inner_from_snapshot(snapshot)
    authority_context = await load_live_singleton_context(
        provider=provider, launcher_id=snapshot.launcher_id
    )
    identity_contexts = tuple(
        [
            await load_live_singleton_context(
                provider=provider, launcher_id=snapshot.identities[slot].launcher_id
            )
            for slot in range(3)
        ]
    )
    _assert_full_puzzle_hash(
        context=authority_context,
        launcher_id=authority.authority_launcher_id,
        inner_puzzle=authority_inner,
        label="administrator authority",
    )
    for slot, identity in enumerate(identities):
        _assert_full_puzzle_hash(
            context=identity_contexts[slot],
            launcher_id=identity.launcher_id,
            inner_puzzle=identity.custody_reveal,
            label=f"administrator identity {slot + 1}",
        )

    boundary = statement["activationBoundary"]
    live_boundary = {
        "authorityLauncherId": snapshot.launcher_id.lower(),
        "authorityCoinId": snapshot.current_coin_id.lower(),
        "authorityVersion": snapshot.authority_version,
        "rosterIdentityCoinIds": ["0x" + bytes(item.coin.name()).hex() for item in identity_contexts],
    }
    for field, value in live_boundary.items():
        if boundary[field] != value:
            raise ValueError(f"identity amendment {field} is stale")
    slots = tuple(int(value) for value in boundary["signerSlots"])
    if list(boundary["signerIdentityCoinIds"]) != [
        live_boundary["rosterIdentityCoinIds"][slot] for slot in slots
    ]:
        raise ValueError("identity amendment signer coins are stale")
    current_time = int(time.time()) if now is None else now
    if current_time >= int(statement["approvalExpiresAt"]):
        raise ValueError("identity amendment approval window is expired")

    delegated = Program.to(
        (
            1,
            [
                [ASSERT_BEFORE_SECONDS_ABSOLUTE, int(statement["approvalExpiresAt"])],
                [CREATE_PUZZLE_ANNOUNCEMENT, announcement_message(digest)],
            ],
        )
    )
    actions = tuple(
        _action(
            slot=slot,
            identity=identities[slot],
            coin_id=identity_contexts[slot].coin.name(),
            delegated_puzzle_hash=build_identity_operational_action(
                identity=identities[slot],
                current_authority_inner_puzzle=authority_inner,
                authority_delegated_puzzle=delegated,
            ).get_tree_hash(),
            proposal_hash=bytes32.from_hexstr(digest),
            voting_deadline=int(statement["approvalExpiresAt"]),
            purpose="IDENTITY_DEPLOYMENT_ACTIVATION",
        )
        for slot in slots
    )
    context = {
        "snapshot": snapshot,
        "authority": authority,
        "identities": identities,
        "authorityInner": authority_inner,
        "authorityContext": authority_context,
        "identityContexts": identity_contexts,
        "signerSlots": slots,
    }
    return IdentityActivationBuild(statement, digest, context, delegated, actions)


def build_identity_activation_bundle(build: IdentityActivationBuild,
                                     signatures: Mapping[int, Mapping[str, str]]) -> SpendBundle:
    context = build.context
    slots = context["signerSlots"]
    if len(slots) != 2 or slots[0] != 0 or slots[1] not in (1, 2):
        raise ValueError("identity activation requires the owner and one coadministrator")
    if set(signatures) != set(slots):
        raise ValueError("identity activation requires exactly the reviewed signer slots")
    mips = build_authority_operational_mips_spend(
        authority=context["authority"],
        current_authority_inner_puzzle=context["authorityInner"],
        current_identities=context["identities"],
        current_identity_coin_ids=tuple(item.coin.name() for item in context["identityContexts"]),
        authority_delegated_puzzle=build.delegated,
        coadmin_slot=slots[1],
    )
    snapshot = context["snapshot"]
    solution = build_operational_solution(
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=snapshot.authority_version + 1,
        mips_reveal=mips.reveal,
        mips_solution=mips.solution,
        authority_delegated_puzzle=build.delegated,
        identity_records=mips.identity_records,
    )
    spends = [
        _singleton_spend(
            context=context["authorityContext"],
            inner_puzzle=context["authorityInner"],
            inner_solution=solution,
            amount=AUTHORITY_LAUNCHER_AMOUNT,
        )
    ]
    actions = {action.signer_slot: action for action in build.actions}
    for slot in slots:
        action = actions[slot]
        signed = signatures.get(slot)
        if signed is None or signed["action_id"] != action.action_id:
            raise ValueError("identity activation chain approval is missing or stale")
        member = build_eip712_member_solution(
            network="testnet11",
            coin_id=context["identityContexts"][slot].coin.name(),
            delegated_puzzle_hash=bytes32.from_hexstr(action.delegated_puzzle_hash),
            compressed_pubkey=context["identities"][slot].daily_compressed_pubkey,
            signature=bytes.fromhex(signed["signature"].removeprefix("0x")),
        )
        spends.append(
            _singleton_spend(
                context=context["identityContexts"][slot],
                inner_puzzle=context["identities"][slot].custody_reveal,
                inner_solution=build_identity_operational_solution(
                    identity=context["identities"][slot],
                    current_authority_inner_puzzle=context["authorityInner"],
                    current_identity_coin_id=context["identityContexts"][slot].coin.name(),
                    daily_member_solution=member,
                    authority_delegated_puzzle=build.delegated,
                ),
                amount=IDENTITY_LAUNCHER_AMOUNTS[slot],
            )
        )
    return SpendBundle(spends, G2Element())


__all__ = [
    "IdentityActivationBuild",
    "build_identity_activation_bundle",
    "identity_activation_request",
    "prepare_identity_activation",
]
