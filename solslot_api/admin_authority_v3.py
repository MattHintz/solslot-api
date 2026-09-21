"""Chain-authoritative reader for recovery-aware Admin Authority V3."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.admin_authority_v2_driver import (
    singleton_full_puzzle_hash,
)
from solslot_puzzles.admin_authority_v3_driver import (
    AdminAuthorityV3State,
    PENDING_LOST,
    PENDING_NONE,
    PENDING_RECOVERY_KIT,
    PENDING_ROUTINE,
    SPEND_CANCEL,
    SPEND_COMPLETE,
    SPEND_OPERATIONAL,
    SPEND_PREPARE_LOST,
    SPEND_PREPARE_KIT,
    SPEND_PREPARE_ROUTINE,
    make_inner_puzzle,
    parse_inner_puzzle,
)

from .chia_provider import ChiaProvider


MAX_AUTHORITY_LINEAGE_DEPTH = 4_096


@dataclass(frozen=True)
class AdminIdentityVaultV1:
    slot: int
    launcher_id: str
    daily_compressed_pubkey: str
    recovery_bls_pubkey: str
    recovery_member_hash: str
    custody_hash: str
    live_coin_id: Optional[str]
    live_puzzle_hash: Optional[str]
    confirmed_height: Optional[int]


@dataclass(frozen=True)
class AdminAuthorityV3Snapshot:
    enabled: bool
    chain_verified: bool
    network: str
    launcher_id: str
    current_coin_id: Optional[str]
    current_puzzle_hash: Optional[str]
    confirmed_height: Optional[int]
    source_manifest_hash: str
    operational_mips_root_hash: str
    lost_recovery_mips_root_hashes: tuple[str, str, str]
    authority_version: int
    pending: bool
    pending_kind: str
    pending_slot: Optional[int]
    pending_intent_hash: Optional[str]
    pending_identity_coin_id: Optional[str]
    pending_original_custody_hash: Optional[str]
    pending_replacement_custody_hash: Optional[str]
    pending_replacement_member_hash: Optional[str]
    pending_delay_seconds: int
    routine_delay_seconds: int
    lost_key_delay_seconds: int
    authority_rule: str
    identities: tuple[
        AdminIdentityVaultV1,
        AdminIdentityVaultV1,
        AdminIdentityVaultV1,
    ]
    evidence: dict[str, Any]

    def to_wire(self) -> dict[str, Any]:
        value = asdict(self)
        value["identities"] = [asdict(item) for item in self.identities]
        return value


@dataclass(frozen=True)
class _LiveCoin:
    parent_coin_id: str
    coin_id: str
    puzzle_hash: str
    amount: int
    confirmed_height: int
    spent_height: Optional[int]
    launcher: bool = False

    def to_coin(self) -> Coin:
        return Coin(
            _b32(self.parent_coin_id, "parent coin id"),
            _b32(self.puzzle_hash, "puzzle hash"),
            uint64(self.amount),
        )


@dataclass(frozen=True)
class _SingletonTip:
    live: _LiveCoin
    latest_spent: Optional[_LiveCoin]
    depth: int
    lineage: tuple[_LiveCoin, ...]


@dataclass(frozen=True)
class LiveSingletonContext:
    """Exact live singleton input and parent spend used for lineage proofs."""

    launcher_id: bytes32
    coin: Coin
    parent_spend: CoinSpend
    confirmed_height: int
    depth: int


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _b32(value: object, field: str) -> bytes32:
    text = str(value or "").lower().removeprefix("0x")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be 32-byte hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must be 32-byte hex")
    return bytes32(raw)


def _program(value: object, field: str) -> Program:
    try:
        return Program.from_bytes(bytes.fromhex(str(value).removeprefix("0x")))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is malformed") from exc


def _coin(record: Mapping[str, Any], *, launcher: bool = False) -> _LiveCoin:
    payload = record.get("coin")
    if not isinstance(payload, Mapping):
        raise ValueError("Authority V3 coin record is malformed")
    parent = _b32(payload.get("parent_coin_info"), "parent coin id")
    puzzle_hash = _b32(payload.get("puzzle_hash"), "puzzle hash")
    amount = int(payload.get("amount"))
    coin_id = bytes32(Coin(parent, puzzle_hash, uint64(amount)).name())
    spent_height = int(record.get("spent_block_index") or 0)
    return _LiveCoin(
        parent_coin_id=_hex(parent),
        coin_id=_hex(coin_id),
        puzzle_hash=_hex(puzzle_hash),
        amount=amount,
        confirmed_height=int(record.get("confirmed_block_index") or 0),
        spent_height=spent_height or None,
        launcher=launcher,
    )


async def _singleton_tip(
    provider: ChiaProvider,
    launcher_id: str,
) -> Optional[_SingletonTip]:
    launcher_record = await provider.get_coin_record_by_name(launcher_id)
    if launcher_record is None:
        return None
    launcher = _coin(launcher_record, launcher=True)
    if launcher.spent_height is None:
        return _SingletonTip(launcher, None, 0, (launcher,))
    current = launcher
    latest_spent: Optional[_LiveCoin] = None
    lineage = [launcher]
    for depth in range(1, MAX_AUTHORITY_LINEAGE_DEPTH + 1):
        children = await provider.get_coin_records_by_parent_ids(
            [current.coin_id],
            include_spent=True,
        )
        candidates = [
            _coin(record)
            for record in children
            if isinstance(record.get("coin"), Mapping)
            and int(record["coin"].get("amount") or -1) == launcher.amount
        ]
        if len(candidates) != 1:
            raise ValueError("Authority V3 continuation is missing or ambiguous")
        latest_spent = current
        current = candidates[0]
        lineage.append(current)
        if current.spent_height is None:
            return _SingletonTip(current, latest_spent, depth, tuple(lineage))
    raise ValueError("Authority V3 lineage exceeds the safety limit")


async def load_live_singleton_context(
    *,
    provider: ChiaProvider,
    launcher_id: str,
) -> LiveSingletonContext:
    """Load one unspent singleton tip and its exact spent parent.

    The caller supplies the expected current puzzle reveal separately and
    checks it against ``coin.puzzle_hash`` before constructing a spend.
    """

    normalized_launcher = _b32(launcher_id, "singleton launcher id")
    tip = await _singleton_tip(provider, _hex(normalized_launcher))
    if tip is None or tip.depth < 1 or tip.latest_spent is None:
        raise ValueError("singleton is not launched")
    parent = tip.latest_spent
    if parent.spent_height is None:
        raise ValueError("singleton parent spend height is missing")
    payload = await provider.get_puzzle_and_solution(
        parent.coin_id,
        parent.spent_height,
    )
    if not isinstance(payload, Mapping):
        raise ValueError("singleton parent spend is unavailable")
    parent_spend = make_spend(
        parent.to_coin(),
        _program(payload.get("puzzle_reveal"), "singleton parent puzzle"),
        _program(payload.get("solution"), "singleton parent solution"),
    )
    return LiveSingletonContext(
        launcher_id=normalized_launcher,
        coin=tip.live.to_coin(),
        parent_spend=parent_spend,
        confirmed_height=tip.live.confirmed_height,
        depth=tip.depth,
    )


def _inner_from_full_puzzle(full_puzzle: Program) -> Program:
    uncurried = full_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("Authority V3 singleton puzzle is not curried")
    _mod, args_program = uncurried
    args = list(args_program.as_iter())
    if len(args) != 2:
        raise ValueError("Authority V3 singleton wrapper is malformed")
    return args[1]


def _state_after_solution(
    old_inner: Program,
    solution: Program,
) -> tuple[Any, AdminAuthorityV3State, int]:
    parsed = parse_inner_puzzle(old_inner)
    outer = list(solution.as_iter())
    if len(outer) != 3:
        raise ValueError("Authority V3 singleton solution must have three items")
    inner_solution = list(outer[2].as_iter())
    if len(inner_solution) != 4:
        raise ValueError("Authority V3 inner solution must have four items")
    spend_tag = int(inner_solution[0].as_int())
    new_version = int(inner_solution[2].as_int())
    if new_version != parsed.state.authority_version + 1:
        raise ValueError("Authority V3 version transition is not exact")
    if spend_tag == SPEND_OPERATIONAL:
        if parsed.state.pending_kind != PENDING_NONE:
            raise ValueError("Authority V3 operational spend bypasses recovery freeze")
        state = AdminAuthorityV3State(
            current_identity_custody_hashes=(
                parsed.state.current_identity_custody_hashes
            ),
            authority_version=new_version,
        )
    elif spend_tag in (
        SPEND_PREPARE_ROUTINE,
        SPEND_PREPARE_LOST,
        SPEND_PREPARE_KIT,
    ):
        if parsed.state.pending_kind != PENDING_NONE:
            raise ValueError("Authority V3 has simultaneous key changes")
        args = list(inner_solution[3].as_iter())
        if len(args) != 7:
            raise ValueError("Authority V3 prepare solution is malformed")
        pending = list(args[6].as_iter())
        if len(pending) != 6:
            raise ValueError(
                "Authority V3 prepare transition is malformed"
            )
        pending_kind = {
            SPEND_PREPARE_ROUTINE: PENDING_ROUTINE,
            SPEND_PREPARE_LOST: PENDING_LOST,
            SPEND_PREPARE_KIT: PENDING_RECOVERY_KIT,
        }[spend_tag]
        pending_slot = int(pending[0].as_int())
        if pending_slot not in range(3):
            raise ValueError("Authority V3 pending slot is invalid")
        current_custodies = list(
            parsed.state.current_identity_custody_hashes
        )
        current_custodies[pending_slot] = _b32(
            pending[4].as_atom().hex(),
            "intermediate custody hash",
        )
        state = AdminAuthorityV3State(
            current_identity_custody_hashes=tuple(current_custodies),  # type: ignore[arg-type]
            authority_version=new_version,
            pending_kind=pending_kind,
            pending_slot=pending_slot,
            pending_intent_hash=_b32(
                pending[1].as_atom().hex(),
                "intent hash",
            ),
            pending_identity_coin_id=_b32(
                pending[3].as_atom().hex(),
                "identity coin id",
            ),
            pending_original_custody_hash=(
                parsed.state.current_identity_custody_hashes[pending_slot]
            ),
            pending_replacement_custody_hash=_b32(
                pending[5].as_atom().hex(),
                "replacement custody hash",
            ),
            pending_replacement_member_hash=bytes32(
                args[2].get_tree_hash()
            ),
            pending_delay_seconds=(
                parsed.lost_key_delay_seconds
                if pending_kind == PENDING_LOST
                else parsed.routine_delay_seconds
            ),
        )
    elif spend_tag in (SPEND_CANCEL, SPEND_COMPLETE):
        if parsed.state.pending_kind == PENDING_NONE:
            raise ValueError("Authority V3 clears an empty recovery state")
        current_custodies = list(
            parsed.state.current_identity_custody_hashes
        )
        current_custodies[parsed.state.pending_slot] = (
            parsed.state.pending_replacement_custody_hash
            if spend_tag == SPEND_COMPLETE
            else parsed.state.pending_original_custody_hash
        )
        state = AdminAuthorityV3State(
            current_identity_custody_hashes=tuple(current_custodies),  # type: ignore[arg-type]
            authority_version=new_version,
        )
    else:
        raise ValueError("Authority V3 spend tag is unsupported")
    state.validate()
    return parsed, state, spend_tag


def _authority_from_artifact(artifact: Mapping[str, Any]) -> tuple[
    str,
    Mapping[str, Any],
    Mapping[str, Any],
]:
    launchers = artifact.get("launcherIds")
    authority = artifact.get("adminAuthority")
    hashes = artifact.get("puzzleHashes")
    if (
        artifact.get("network") != "testnet11"
        or not isinstance(launchers, Mapping)
        or not isinstance(authority, Mapping)
        or not isinstance(hashes, Mapping)
        or authority.get("version") != 3
    ):
        raise ValueError("Signed artifact does not contain Admin Authority V3")
    launcher_id = _hex(_b32(launchers.get("adminAuthority"), "authority launcher"))
    identities = authority.get("identityVaults")
    if not isinstance(identities, list) or len(identities) != 3:
        raise ValueError("Signed artifact must contain three identity vaults")
    return launcher_id, authority, hashes


async def build_admin_authority_v3_snapshot(
    *,
    artifact: Mapping[str, Any],
    provider: ChiaProvider | None = None,
) -> AdminAuthorityV3Snapshot:
    launcher_id, authority, hashes = _authority_from_artifact(artifact)
    identity_records = authority["identityVaults"]
    identity_tips: list[Optional[_SingletonTip]] = [None, None, None]
    authority_tip: Optional[_SingletonTip] = None
    parsed = None
    state = AdminAuthorityV3State()
    chain_verified = False
    latest_spend_tag: Optional[int] = None
    expected_identity_custody = [
        _b32(record["custodyHash"], f"identity {slot} custody hash")
        for slot, record in enumerate(identity_records)
    ]

    if provider is not None:
        authority_tip = await _singleton_tip(provider, launcher_id)
        for slot, record in enumerate(identity_records):
            identity_tips[slot] = await _singleton_tip(
                provider,
                str(record["launcherId"]),
            )
        if authority_tip is not None and authority_tip.depth >= 1:
            expected_genesis_full = str(
                hashes.get("adminAuthorityFull") or ""
            ).lower()
            if authority_tip.lineage[1].puzzle_hash.lower() != expected_genesis_full:
                raise ValueError("Authority V3 genesis puzzle hash mismatches")
            for index in range(1, len(authority_tip.lineage) - 1):
                spent_coin = authority_tip.lineage[index]
                if spent_coin.spent_height is None:
                    raise ValueError("Authority V3 lineage spend height is missing")
                spend = await provider.get_puzzle_and_solution(
                    spent_coin.coin_id,
                    spent_coin.spent_height,
                )
                if not isinstance(spend, Mapping):
                    raise ValueError("Authority V3 lineage spend is unavailable")
                old_inner = _inner_from_full_puzzle(
                    _program(spend.get("puzzle_reveal"), "authority puzzle")
                )
                parsed, state, spend_tag = _state_after_solution(
                    old_inner,
                    _program(spend.get("solution"), "authority solution"),
                )
                latest_spend_tag = spend_tag
                next_inner = make_inner_puzzle(
                    authority_puzzle_version=parsed.authority_puzzle_version,
                    authority_launcher_id=parsed.authority_launcher_id,
                    operational_root_hash=parsed.operational_root_hash,
                    lost_recovery_root_hashes=(
                        parsed.lost_recovery_root_hashes
                    ),
                    identity_launcher_ids=parsed.identity_launcher_ids,
                    source_manifest_hash=parsed.source_manifest_hash,
                    state=state,
                    routine_delay_seconds=parsed.routine_delay_seconds,
                    lost_key_delay_seconds=parsed.lost_key_delay_seconds,
                )
                expected_full = singleton_full_puzzle_hash(
                    _b32(launcher_id, "authority launcher"),
                    bytes32(next_inner.get_tree_hash()),
                )
                child = authority_tip.lineage[index + 1]
                if child.puzzle_hash != _hex(expected_full):
                    raise ValueError(
                        "Authority V3 continuation puzzle hash does not match its spend"
                    )
                if spend_tag == SPEND_COMPLETE:
                    completed_state = parsed.state
                    if completed_state.pending_kind == PENDING_NONE:
                        raise ValueError(
                            "Authority V3 completion has no committed identity change"
                        )
                    expected_identity_custody[completed_state.pending_slot] = (
                        completed_state.pending_replacement_custody_hash
                    )
            if state.pending_kind != PENDING_NONE:
                pending_tip = identity_tips[state.pending_slot]
                if (
                    pending_tip is None
                    or pending_tip.live.coin_id != _hex(state.pending_identity_coin_id)
                ):
                    raise ValueError(
                        "Authority V3 pending identity coin is not the live identity"
                    )
            for slot, tip in enumerate(identity_tips):
                if tip is None or tip.depth < 1:
                    raise ValueError(f"Identity vault {slot} is not launched")
                if (
                    state.pending_kind != PENDING_NONE
                    and slot == state.pending_slot
                ):
                    # The authority spend and identity spend are paired by
                    # announcements. During the veto window the authority
                    # commits the exact live intermediate coin id rather than
                    # its custody hash, so that id is the authoritative check.
                    continue
                expected = _hex(
                    singleton_full_puzzle_hash(
                        _b32(
                            identity_records[slot]["launcherId"],
                            f"identity {slot} launcher",
                        ),
                        expected_identity_custody[slot],
                    )
                )
                if tip.live.puzzle_hash.lower() != expected:
                    raise ValueError(
                        f"Identity vault {slot} puzzle hash mismatches"
                    )
            chain_verified = True

    operational_root = str(authority["operationalMipsRootHash"]).lower()
    recovery_roots = tuple(
        str(value).lower()
        for value in authority["lostRecoveryMipsRootHashes"]
    )
    if len(recovery_roots) != 3 or len(set(recovery_roots)) != 3:
        raise ValueError(
            "Authority V3 requires three distinct lost-key roots"
        )
    source_manifest = str(authority["sourceManifestHash"]).lower()
    if parsed is not None:
        if (
            _hex(parsed.operational_root_hash) != operational_root
            or tuple(
                _hex(value)
                for value in parsed.lost_recovery_root_hashes
            )
            != recovery_roots
            or _hex(parsed.source_manifest_hash) != source_manifest
            or [_hex(value) for value in parsed.identity_launcher_ids]
            != [str(item["launcherId"]).lower() for item in identity_records]
        ):
            raise ValueError("Authority V3 immutable chain state differs from artifact")

    pending_labels = {
        PENDING_NONE: "NONE",
        PENDING_ROUTINE: "ROUTINE",
        PENDING_LOST: "LOST",
        PENDING_RECOVERY_KIT: "RECOVERY_KIT",
    }
    reported_identity_custody = (
        state.current_identity_custody_hashes
        if parsed is not None
        else tuple(expected_identity_custody)
    )
    identities = tuple(
        AdminIdentityVaultV1(
            slot=slot,
            launcher_id=str(record["launcherId"]).lower(),
            daily_compressed_pubkey=str(record["dailyCompressedPubkey"]).lower(),
            recovery_bls_pubkey=str(record["recoveryBlsPubkey"]).lower(),
            recovery_member_hash=str(record["recoveryMemberHash"]).lower(),
            custody_hash=_hex(reported_identity_custody[slot]),
            live_coin_id=identity_tips[slot].live.coin_id
            if identity_tips[slot] is not None
            else None,
            live_puzzle_hash=identity_tips[slot].live.puzzle_hash
            if identity_tips[slot] is not None
            else None,
            confirmed_height=identity_tips[slot].live.confirmed_height
            if identity_tips[slot] is not None
            else None,
        )
        for slot, record in enumerate(identity_records)
    )
    return AdminAuthorityV3Snapshot(
        enabled=True,
        chain_verified=chain_verified,
        network="testnet11",
        launcher_id=launcher_id,
        current_coin_id=authority_tip.live.coin_id if authority_tip else None,
        current_puzzle_hash=authority_tip.live.puzzle_hash if authority_tip else None,
        confirmed_height=authority_tip.live.confirmed_height if authority_tip else None,
        source_manifest_hash=source_manifest,
        operational_mips_root_hash=operational_root,
        lost_recovery_mips_root_hashes=recovery_roots,  # type: ignore[arg-type]
        authority_version=state.authority_version,
        pending=state.pending_kind != PENDING_NONE,
        pending_kind=pending_labels[state.pending_kind],
        pending_slot=state.pending_slot if state.pending_kind != PENDING_NONE else None,
        pending_intent_hash=_hex(state.pending_intent_hash)
        if state.pending_kind != PENDING_NONE
        else None,
        pending_identity_coin_id=_hex(state.pending_identity_coin_id)
        if state.pending_kind != PENDING_NONE
        else None,
        pending_original_custody_hash=_hex(
            state.pending_original_custody_hash
        )
        if state.pending_kind != PENDING_NONE
        else None,
        pending_replacement_custody_hash=_hex(
            state.pending_replacement_custody_hash
        )
        if state.pending_kind != PENDING_NONE
        else None,
        pending_replacement_member_hash=_hex(
            state.pending_replacement_member_hash
        )
        if state.pending_kind != PENDING_NONE
        else None,
        pending_delay_seconds=state.pending_delay_seconds,
        routine_delay_seconds=int(authority["routineDelaySeconds"]),
        lost_key_delay_seconds=int(authority["lostKeyDelaySeconds"]),
        authority_rule="slot0_and_one_of_slot1_slot2",
        identities=identities,  # type: ignore[arg-type]
        evidence={
            "authorityInnerModHash": str(
                hashes.get("adminAuthorityInnerMod")
            ).lower(),
            "authorityFullPuzzleHash": str(
                hashes.get("adminAuthorityFull")
            ).lower(),
            "lineageDepth": authority_tip.depth if authority_tip else 0,
            "latestSpend": {
                SPEND_OPERATIONAL: "OPERATIONAL",
                SPEND_PREPARE_ROUTINE: "PREPARE_ROUTINE",
                SPEND_PREPARE_LOST: "PREPARE_LOST",
                SPEND_PREPARE_KIT: "PREPARE_RECOVERY_KIT",
                SPEND_CANCEL: "CANCEL",
                SPEND_COMPLETE: "COMPLETE",
            }.get(latest_spend_tag, "GENESIS"),
        },
    )


__all__ = [
    "AdminAuthorityV3Snapshot",
    "AdminIdentityVaultV1",
    "LiveSingletonContext",
    "build_admin_authority_v3_snapshot",
    "load_live_singleton_context",
]
