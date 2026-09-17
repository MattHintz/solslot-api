"""Chain-authoritative RC22 Sols secondary SmartDeed market.

Sols is the Pool V4 CAT. It is not a primary checkout rail. Database rows are
used only to decorate inventory that has already been reconstructed from the
Pool V4 and statutes singleton lineages on Testnet11.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from time import time
from typing import Annotated, Any, Literal, Mapping, Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from solslot_puzzles import load_puzzle
from solslot_puzzles.mint_publish_driver import canonical_p2_pool_mod_hash
from solslot_puzzles.pool_economics_v2 import deed_metadata_commitment
from solslot_puzzles.pool_v4_driver import pool_v4_inner_mod_hash
from solslot_puzzles.protocol_statutes_driver import (
    protocol_statutes_inner_mod_hash,
)
from solslot_puzzles.protocol_statutes_v1 import (
    BridgeRoute,
    CollectionStatute,
    LiquidityVenue,
    MutationKind,
    OracleRound,
    PermanentRules,
    ProtocolParameters,
    ScopedPause,
    StatutesState,
    initial_state,
    keyed_root,
)
from solslot_puzzles.real_estate_profiles import ASSET_CLASS_CODES
from solslot_puzzles.sols_economics_v3 import (
    SolsEconomicState,
    quote_sols_to_deed,
)
from solslot_puzzles.sols_pool_v4 import (
    INVENTORY_AVAILABLE,
    PoolInventoryRecord,
    SolsPoolStateV4,
    canonical_inventory,
    inventory_root,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.vault_sols_v1 import puzzle_for_vault_sols_cat

from .chia_provider import ChiaProvider, ChiaProviderError
from .collection_store import CollectionStore, get_collection_store
from .config import Settings, get_settings
from .credential_auth import verify_vault_session
from .public_artifact import (
    PublicArtifactError,
    PublicArtifactMissing,
    load_signed_public_artifact,
)
from .sols_capability_evidence import (
    SolsCapabilityEvidence,
    SolsCapabilityEvidenceError,
    load_sols_capability_evidence,
)
from .sols_capability_adapters import (
    SolsCapabilityAdapterError,
    build_aerodrome_liquidity_intent,
    build_tibetswap_liquidity_intent,
    build_uniswap_v3_liquidity_intent,
    build_warp_bridge_intent,
    descriptor_for_record,
    public_adapter_profile,
)
from .vault_eligibility import require_current_approved_vault
from .sols_capability_operations import CapabilityOperationStore, CapabilityOperationConflict


router = APIRouter(prefix="/sols", tags=["sols-secondary-market"])

POOL_SPEND_DEED_TO_SOLS = 1
POOL_SPEND_SOLS_TO_DEED = 2
STATUTES_SPEND_EVIDENCE = 1
STATUTES_SPEND_UPDATE = 2
STATUTES_SPEND_SOLS_EVIDENCE = 3
STATUTES_SPEND_GOVERNANCE_EVIDENCE = 4

# These constants are deliberately code-owned. A feature flag and an evidence
# file cannot advertise a transaction surface that this release does not
# actually implement.
WARP_CAT_EXECUTION_SURFACE_INSTALLED = True
WARP_CAT_CONFIRMATION_OBSERVER_INSTALLED = False
LIQUIDITY_EXECUTION_SURFACE_INSTALLED = True
WARP_CAT_INSTALLED_ADAPTERS = frozenset({"WARP_CAT"})
LIQUIDITY_INSTALLED_ADAPTERS = frozenset(
    {
        "AERODROME_V1",
        "UNISWAP_V3",
    }
)
DEED_SPEND_POOL_DEPOSIT = 0x64
MAX_SINGLETON_DEPTH = 10_000


class BridgeIntentRequest(BaseModel):
    vaultLauncherId: str = Field(..., pattern=r"^0x[0-9a-fA-F]{64}$")
    routeId: str = Field(..., pattern=r"^0x[0-9a-fA-F]{64}$")
    direction: Literal["CHIA_TO_EVM", "EVM_TO_CHIA"]
    amountMojos: str = Field(..., pattern=r"^[1-9][0-9]*$", max_length=78)
    destination: str = Field(..., min_length=2, max_length=66)


class LiquidityIntentRequest(BaseModel):
    vaultLauncherId: str = Field(..., pattern=r"^0x[0-9a-fA-F]{64}$")
    venueId: str = Field(..., pattern=r"^0x[0-9a-fA-F]{64}$")
    action: Literal["ADD", "REMOVE", "COLLECT"]
    account: str | None = Field(None, min_length=42, max_length=42)
    amountA: str = Field("0", pattern=r"^[0-9]+$", max_length=78)
    amountB: str = Field("0", pattern=r"^[0-9]+$", max_length=78)
    liquidity: str = Field("0", pattern=r"^[0-9]+$", max_length=78)
    minimumA: str = Field("0", pattern=r"^[0-9]+$", max_length=78)
    minimumB: str = Field("0", pattern=r"^[0-9]+$", max_length=78)
    tokenId: str | None = Field(None, pattern=r"^[1-9][0-9]*$", max_length=78)
    tickLower: int | None = None
    tickUpper: int | None = None
    deadlineSeconds: int = Field(600, ge=60, le=1800)


@dataclass(frozen=True)
class LiveCoin:
    coin_id: str
    parent_coin_id: str
    puzzle_hash: str
    amount: int
    confirmed_height: int
    spent_height: Optional[int]
    is_launcher: bool = False


@dataclass(frozen=True)
class SingletonTip:
    launcher_id: str
    live: LiveCoin
    latest_spent: Optional[LiveCoin]
    depth: int
    lineage: tuple[LiveCoin, ...]


@dataclass(frozen=True)
class PoolState:
    bootstrap_complete: bool
    inventory_nav_micro_usd: int
    treasury_assets_micro_usd: int
    proven_liabilities_micro_usd: int
    deed_count: int
    total_sols_mojos: int
    reserve_sols_mojos: int
    state_version: int
    inventory: tuple[PoolInventoryRecord, ...]
    live_coin_id: str
    live_puzzle_hash: str
    confirmed_height: int
    lineage_depth: int

    def economics(self) -> SolsEconomicState:
        return SolsEconomicState(
            bootstrap_complete=self.bootstrap_complete,
            inventory_nav_micro_usd=self.inventory_nav_micro_usd,
            treasury_assets_micro_usd=self.treasury_assets_micro_usd,
            proven_liabilities_micro_usd=self.proven_liabilities_micro_usd,
            deed_count=self.deed_count,
            total_sols_mojos=self.total_sols_mojos,
            reserve_sols_mojos=self.reserve_sols_mojos,
        )


@dataclass(frozen=True)
class StatutesSnapshot:
    live_coin_id: str
    live_puzzle_hash: str
    state: StatutesState
    parameters: ProtocolParameters
    collections: tuple[CollectionStatute, ...]
    oracle_rounds: tuple[OracleRound, ...]
    bridge_routes: tuple[BridgeRoute, ...]
    liquidity_venues: tuple[LiquidityVenue, ...]
    pauses: tuple[ScopedPause, ...]
    registry_version: int
    confirmed_height: int
    lineage_depth: int


@dataclass(frozen=True)
class PoolDeed:
    deed_coin_id: str
    deed_launcher_id: str
    par_value_mojos: int
    asset_class: int
    property_id_canon: str
    collection_id_canon: str
    share_ppm: int
    deed_commitment: str
    confirmed_height: int


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _hex32(value: str, label: str) -> str:
    normalized = value.removeprefix("0x").lower()
    if len(normalized) != 64:
        raise ValueError(f"{label} must be exactly 32 bytes")
    bytes.fromhex(normalized)
    return "0x" + normalized


def _program(value: str) -> Program:
    return Program.from_bytes(bytes.fromhex(value.removeprefix("0x")))


def _coin(record: Mapping[str, Any] | None, *, launcher: bool = False) -> LiveCoin:
    if not isinstance(record, Mapping):
        raise ValueError("coin record is unavailable")
    payload = record.get("coin")
    if not isinstance(payload, Mapping):
        raise ValueError("coin record has no coin")
    parent = _hex32(str(payload.get("parent_coin_info") or ""), "parent coin id")
    puzzle = _hex32(str(payload.get("puzzle_hash") or ""), "puzzle hash")
    amount = payload.get("amount")
    confirmed = record.get("confirmed_block_index")
    spent = record.get("spent_block_index")
    # Match the full-node JSON contract without coercing bools, floats or strings.
    if type(amount) is not int or not 0 <= amount < 2**64:
        raise ValueError("coin amount is not uint64")
    if (
        type(confirmed) is not int or not 0 < confirmed < 2**32
        or type(spent) is not int or not 0 <= spent < 2**32
    ):
        raise ValueError("invalid confirmed coin heights")
    if spent and spent < confirmed:
        raise ValueError("coin spend precedes confirmation")
    if "spent" in record and (
        type(record["spent"]) is not bool or record["spent"] != bool(spent)
    ):
        raise ValueError("inconsistent coin spent flag")
    coin_id = _hex(
        Coin(
            bytes32.fromhex(parent.removeprefix("0x")),
            bytes32.fromhex(puzzle.removeprefix("0x")),
            uint64(amount),
        ).name()
    )
    return LiveCoin(
        coin_id=coin_id,
        parent_coin_id=parent,
        puzzle_hash=puzzle,
        amount=amount,
        confirmed_height=confirmed,
        spent_height=spent or None,
        is_launcher=launcher,
    )


def _singleton_child(
    records: list[dict[str, Any]],
    *,
    expected_amount: int,
) -> LiveCoin:
    if not isinstance(records, list):
        raise ValueError("singleton children must be coin records")
    candidates = []
    for record in records:
        coin = _coin(record)
        if coin.amount == expected_amount:
            candidates.append(coin)
    if len(candidates) != 1:
        raise ValueError(
            "singleton continuation is missing or ambiguous"
        )
    return candidates[0]


async def _singleton_tip(provider: ChiaProvider, launcher_id: str) -> Optional[SingletonTip]:
    launcher_id = _hex32(launcher_id, "launcher id")
    launcher_record = await provider.get_coin_record_by_name(launcher_id)
    if launcher_record is None:
        return None
    launcher = _coin(launcher_record, launcher=True)
    if launcher.coin_id != launcher_id:
        raise ValueError("launcher coin does not match requested ID")
    if launcher.amount == 0 or launcher.amount % 2 != 1:
        raise ValueError("singleton launcher amount must be positive and odd")
    nodes = [launcher]
    if launcher.spent_height is None:
        await _require_same_coin(provider, launcher)
        return SingletonTip(
            launcher_id,
            launcher,
            None,
            0,
            tuple(nodes),
        )

    parent = launcher.coin_id
    for _ in range(MAX_SINGLETON_DEPTH):
        children = await provider.get_coin_records_by_parent_ids(
            [parent], include_spent=True
        )
        if not children:
            raise ValueError(
                "spent singleton coin has no confirmed continuation"
            )
        child = _singleton_child(
            children,
            expected_amount=launcher.amount,
        )
        if (
            child.parent_coin_id != parent
            or child.confirmed_height != nodes[-1].spent_height
        ):
            raise ValueError("singleton continuation is not an atomic child of its parent")
        nodes.append(child)
        if child.spent_height is None:
            await _require_same_coin(provider, launcher)
            await _require_same_coin(provider, child)
            return SingletonTip(
                launcher_id,
                child,
                next((item for item in reversed(nodes[:-1]) if item.spent_height), None),
                len(nodes) - 1,
                tuple(nodes),
            )
        parent = child.coin_id
    raise ValueError("singleton lineage exceeds the safety limit")


async def _require_same_coin(provider: ChiaProvider, expected: LiveCoin) -> None:
    current = _coin(
        await provider.get_coin_record_by_name(expected.coin_id),
        launcher=expected.is_launcher,
    )
    if current != expected:
        raise ValueError("singleton coin changed during evidence retrieval")


def _canonical_spend_program(value: Any) -> Program:
    # Product evidence bound, not a claim about the network consensus limit.
    if not isinstance(value, str) or len(value) > 2 * 2**21 + 2:
        raise ValueError("singleton spend program exceeds the evidence bound")
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
        if not raw or len(raw) > 2**21:
            raise ValueError("invalid program length")
        program = Program.from_bytes(raw)
        if bytes(program) != raw:
            raise ValueError("noncanonical program bytes")
        return program
    except (TypeError, ValueError) as exc:
        raise ValueError("singleton spend program is not canonical CLVM") from exc


async def _singleton_spend(provider: ChiaProvider, spent: LiveCoin) -> dict[str, Any]:
    """Bind one provider response to its recorded coin; this is not execution proof."""
    if spent.spent_height is None:
        raise ValueError("singleton coin has no confirmed spend")
    response = await provider.get_puzzle_and_solution(spent.coin_id, spent.spent_height)
    if not isinstance(response, Mapping):
        raise ValueError("singleton lineage solution is unavailable")
    returned = _coin(
        dict(
            coin=response.get("coin"),
            confirmed_block_index=spent.confirmed_height,
            spent_block_index=spent.spent_height,
        ),
        launcher=spent.is_launcher,
    )
    if returned != spent:
        raise ValueError("singleton spend coin does not match recorded input")
    puzzle = _canonical_spend_program(response.get("puzzle_reveal"))
    solution = _canonical_spend_program(response.get("solution"))
    if _hex(puzzle.get_tree_hash()) != spent.puzzle_hash:
        raise ValueError("singleton spend puzzle does not match recorded input")
    # Detach accepted bytes before the next await can mutate a provider object.
    result = dict(
        coin=dict(
            parent_coin_info=spent.parent_coin_id,
            puzzle_hash=spent.puzzle_hash,
            amount=spent.amount,
        ),
        puzzle_reveal=bytes(puzzle).hex(),
        solution=bytes(solution).hex(),
    )
    await _require_same_coin(provider, spent)
    return result


async def _latest_solution(
    provider: ChiaProvider, tip: SingletonTip
) -> Optional[dict[str, Any]]:
    spent = tip.latest_spent
    if spent is None or spent.is_launcher or spent.spent_height is None:
        return None
    result = await _singleton_spend(provider, spent)
    await _require_same_coin(provider, tip.live)
    return result


def _solution_parts(solution_hex: str, label: str) -> tuple[list[Program], list[Program]]:
    outer = list(_program(solution_hex).as_iter())
    if len(outer) != 3:
        raise ValueError(f"{label} singleton solution must have three items")
    inner = list(outer[2].as_iter())
    return outer, inner


def _bytes32_node(node: Program, label: str) -> bytes32:
    raw = node.as_atom()
    if len(raw) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes")
    return bytes32(raw)


def _protocol_parameters(node: Program) -> ProtocolParameters:
    values = [int(value.as_int()) for value in node.as_iter()]
    return ProtocolParameters.from_sequence(values).validate()


def _collection_statute(node: Program) -> CollectionStatute:
    values = list(node.as_iter())
    if len(values) != 7:
        raise ValueError("collection statute must have seven fields")
    return CollectionStatute(
        collection_id=_bytes32_node(values[0], "collection id"),
        nav_micro_usd=int(values[1].as_int()),
        allocation_ceiling_micro_usd=int(values[2].as_int()),
        nav_version=int(values[3].as_int()),
        valid_after=int(values[4].as_int()),
        valid_until=int(values[5].as_int()),
        status=int(values[6].as_int()),
    ).validate()


def _scoped_pause(node: Program) -> ScopedPause:
    values = list(node.as_iter())
    if len(values) != 4:
        raise ValueError("scoped pause must have four fields")
    return ScopedPause(
        scope_id=_bytes32_node(values[0], "pause scope id"),
        paused=int(values[1].as_int()),
        expires_at=int(values[2].as_int()),
        reason_hash=_bytes32_node(values[3], "pause reason hash"),
    ).validate()


def _liquidity_venue(node: Program) -> LiquidityVenue:
    values = list(node.as_iter())
    if len(values) != 9:
        raise ValueError("liquidity venue must have nine fields")
    return LiquidityVenue(
        venue_id=_bytes32_node(values[0], "liquidity venue id"),
        chain_id=_bytes32_node(values[1], "liquidity chain id"),
        protocol_id=_bytes32_node(values[2], "liquidity protocol id"),
        factory_id=_bytes32_node(values[3], "liquidity factory id"),
        pool_id=_bytes32_node(values[4], "liquidity pool id"),
        base_asset_id=_bytes32_node(values[5], "liquidity base asset id"),
        quote_asset_id=_bytes32_node(values[6], "liquidity quote asset id"),
        pool_code_hash=_bytes32_node(values[7], "liquidity pool code hash"),
        active=int(values[8].as_int()),
    ).validate()


def _oracle_round(node: Program) -> OracleRound:
    values = list(node.as_iter())
    if len(values) != 10:
        raise ValueError("oracle round must have ten fields")
    return OracleRound(
        asset_id=_bytes32_node(values[0], "oracle asset id"),
        price_micro_usd=int(values[1].as_int()),
        observed_at=int(values[2].as_int()),
        valid_until=int(values[3].as_int()),
        round_id=int(values[4].as_int()),
        source_root=_bytes32_node(values[5], "oracle source root"),
        source_count=int(values[6].as_int()),
        haircut_bps=int(values[7].as_int()),
        stable_min_bps=int(values[8].as_int()),
        stable_max_bps=int(values[9].as_int()),
    ).validate()


def _bridge_route(node: Program) -> BridgeRoute:
    values = list(node.as_iter())
    if len(values) != 7:
        raise ValueError("bridge route must have seven fields")
    return BridgeRoute(
        route_id=_bytes32_node(values[0], "bridge route id"),
        source_chain_id=_bytes32_node(values[1], "bridge source chain id"),
        destination_chain_id=_bytes32_node(
            values[2],
            "bridge destination chain id",
        ),
        asset_id=_bytes32_node(values[3], "bridge asset id"),
        remote_asset_id=_bytes32_node(values[4], "bridge remote asset id"),
        decimals=int(values[5].as_int()),
        active=int(values[6].as_int()),
    ).validate()


def _pool_inventory_record(node: Program) -> PoolInventoryRecord:
    values = list(node.as_iter())
    if len(values) != 9:
        raise ValueError("Pool V4 inventory record must have nine fields")
    return PoolInventoryRecord(
        deed_launcher_id=_bytes32_node(values[0], "deed launcher id"),
        custody_coin_id=_bytes32_node(values[1], "custody coin id"),
        deed_commitment=_bytes32_node(values[2], "deed commitment"),
        collection_id=_bytes32_node(values[3], "collection id"),
        share_ppm=int(values[4].as_int()),
        deed_value_micro_usd=int(values[5].as_int()),
        nav_version=int(values[6].as_int()),
        valid_until=int(values[7].as_int()),
        settlement_state=int(values[8].as_int()),
    ).validate()


def _pool_inventory(node: Program) -> tuple[PoolInventoryRecord, ...]:
    return canonical_inventory(
        tuple(_pool_inventory_record(item) for item in node.as_iter())
    )


def _pool_state_from_args(
    inner_args: list[Program],
    inventory: tuple[PoolInventoryRecord, ...],
) -> SolsPoolStateV4:
    bootstrap_flag = int(inner_args[5].as_int())
    if bootstrap_flag not in (0, 1):
        raise ValueError("Pool V4 bootstrap flag must be 0 or 1")
    state = SolsPoolStateV4(
        inventory_root=_bytes32_node(inner_args[4], "pool inventory root"),
        economics=SolsEconomicState(
            bootstrap_complete=bool(bootstrap_flag),
            inventory_nav_micro_usd=int(inner_args[6].as_int()),
            treasury_assets_micro_usd=int(inner_args[7].as_int()),
            proven_liabilities_micro_usd=int(inner_args[8].as_int()),
            deed_count=int(inner_args[9].as_int()),
            total_sols_mojos=int(inner_args[10].as_int()),
            reserve_sols_mojos=int(inner_args[11].as_int()),
        ),
        state_version=int(inner_args[12].as_int()),
    )
    return state.validate(inventory)


def _decode_pool_state(
    puzzle_solution: Mapping[str, Any],
    tip: SingletonTip,
) -> PoolState:
    full = _program(str(puzzle_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise ValueError("pool puzzle is not a curried singleton")
    full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2 or full_mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError("pool puzzle is not the canonical singleton")
    old_inner = full_args[1]
    old_uncurried = old_inner.uncurry()
    if old_uncurried is None:
        raise ValueError("pool inner puzzle is not curried")
    inner_mod, inner_args_program = old_uncurried
    inner_args = list(inner_args_program.as_iter())
    if len(inner_args) != 13:
        raise ValueError("Pool V4 inner puzzle must have 13 arguments")
    if inner_mod.get_tree_hash() != pool_v4_inner_mod_hash():
        raise ValueError("pool inner module hash is not Pool V4")

    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "pool"
    )
    if len(inner_solution) != 5:
        raise ValueError("Pool V4 inner solution must have five items")
    spend_case = int(inner_solution[3].as_int())
    params = list(inner_solution[4].as_iter())
    expected_params = (
        39
        if spend_case == POOL_SPEND_DEED_TO_SOLS
        else 33
        if spend_case == POOL_SPEND_SOLS_TO_DEED
        else -1
    )
    if len(params) != expected_params:
        raise ValueError("Pool V4 transition has the wrong parameter count")
    previous_inventory = _pool_inventory(params[0])
    previous = _pool_state_from_args(inner_args, previous_inventory)

    if spend_case == POOL_SPEND_DEED_TO_SOLS:
        record = _pool_inventory_record(params[30])
        current_inventory = canonical_inventory(
            (*previous_inventory, record)
        )
        current = SolsPoolStateV4(
            inventory_root=_bytes32_node(params[34], "next inventory root"),
            economics=SolsEconomicState(
                bootstrap_complete=True,
                inventory_nav_micro_usd=(
                    previous.economics.inventory_nav_micro_usd
                    + record.deed_value_micro_usd
                ),
                treasury_assets_micro_usd=(
                    previous.economics.treasury_assets_micro_usd
                ),
                proven_liabilities_micro_usd=(
                    previous.economics.proven_liabilities_micro_usd
                ),
                deed_count=previous.economics.deed_count + 1,
                total_sols_mojos=(
                    previous.economics.total_sols_mojos
                    + int(params[33].as_int())
                ),
                reserve_sols_mojos=(
                    previous.economics.reserve_sols_mojos
                    - int(params[32].as_int())
                ),
            ),
            state_version=previous.state_version + 1,
        ).validate(current_inventory)
        current_commitment = params[35]
        next_commitment = params[36]
    else:
        deed_launcher_id = _bytes32_node(params[11], "deed launcher id")
        matches = [
            item
            for item in previous_inventory
            if item.deed_launcher_id == deed_launcher_id
        ]
        if len(matches) != 1:
            raise ValueError("Pool V4 release deed is not in inventory")
        record = matches[0]
        if _pool_inventory_record(params[20]) != record:
            raise ValueError("Pool V4 release record does not match inventory")
        current_inventory = tuple(
            item
            for item in previous_inventory
            if item.deed_launcher_id != deed_launcher_id
        )
        current = SolsPoolStateV4(
            inventory_root=_bytes32_node(params[28], "next inventory root"),
            economics=SolsEconomicState(
                bootstrap_complete=True,
                inventory_nav_micro_usd=(
                    previous.economics.inventory_nav_micro_usd
                    - record.deed_value_micro_usd
                ),
                treasury_assets_micro_usd=(
                    previous.economics.treasury_assets_micro_usd
                ),
                proven_liabilities_micro_usd=(
                    previous.economics.proven_liabilities_micro_usd
                ),
                deed_count=previous.economics.deed_count - 1,
                total_sols_mojos=previous.economics.total_sols_mojos,
                reserve_sols_mojos=(
                    previous.economics.reserve_sols_mojos
                    + int(params[25].as_int())
                ),
            ),
            state_version=previous.state_version + 1,
        ).validate(current_inventory)
        current_commitment = params[29]
        next_commitment = params[30]
    if _bytes32_node(current_commitment, "current pool state commitment") != (
        previous.commitment_hash
    ):
        raise ValueError("Pool V4 previous state commitment is invalid")
    if _bytes32_node(next_commitment, "next pool state commitment") != (
        current.commitment_hash
    ):
        raise ValueError("Pool V4 next state commitment is invalid")
    current_inner = inner_mod.curry(
        *inner_args[:4],
        current.inventory_root,
        int(current.economics.bootstrap_complete),
        current.economics.inventory_nav_micro_usd,
        current.economics.treasury_assets_micro_usd,
        current.economics.proven_liabilities_micro_usd,
        current.economics.deed_count,
        current.economics.total_sols_mojos,
        current.economics.reserve_sols_mojos,
        current.state_version,
    )
    current_full = full_mod.curry(full_args[0], current_inner)
    if _hex(current_full.get_tree_hash()) != tip.live.puzzle_hash:
        raise ValueError(
            "reconstructed Pool V4 state does not match the live coin"
        )
    return PoolState(
        bootstrap_complete=current.economics.bootstrap_complete,
        inventory_nav_micro_usd=current.economics.inventory_nav_micro_usd,
        treasury_assets_micro_usd=current.economics.treasury_assets_micro_usd,
        proven_liabilities_micro_usd=(
            current.economics.proven_liabilities_micro_usd
        ),
        deed_count=current.economics.deed_count,
        total_sols_mojos=current.economics.total_sols_mojos,
        reserve_sols_mojos=current.economics.reserve_sols_mojos,
        state_version=current.state_version,
        inventory=current_inventory,
        live_coin_id=tip.live.coin_id,
        live_puzzle_hash=tip.live.puzzle_hash,
        confirmed_height=tip.live.confirmed_height,
        lineage_depth=tip.depth,
    )


def _singleton_struct(launcher_id: str) -> Program:
    return Program.to(
        (
            SINGLETON_MOD_HASH,
            (
                bytes32.fromhex(
                    _hex32(launcher_id, "launcher id").removeprefix("0x")
                ),
                SINGLETON_LAUNCHER_HASH,
            ),
        )
    )


def _statutes_state_from_args(
    inner_args: list[Program],
    permanent_rules: PermanentRules,
) -> StatutesState:
    return StatutesState(
        parameters_root=_bytes32_node(inner_args[9], "parameters root"),
        collections_root=_bytes32_node(inner_args[10], "collections root"),
        oracle_root=_bytes32_node(inner_args[11], "oracle root"),
        routes_root=_bytes32_node(inner_args[12], "routes root"),
        liquidity_root=_bytes32_node(inner_args[13], "liquidity root"),
        pauses_root=_bytes32_node(inner_args[14], "pauses root"),
        registry_version=int(inner_args[15].as_int()),
        permanent_rules_hash=permanent_rules.commitment_hash,
    ).validate()


def _raw_keyed_upsert_root(
    entries_node: Program,
    replacement_node: Program,
    expected_key: Program,
) -> bytes32:
    entries = list(entries_node.as_iter())
    replacement = list(replacement_node.as_iter())
    if not replacement:
        raise ValueError("statutes replacement record is empty")
    if bytes(replacement[0]) != bytes(expected_key):
        raise ValueError("statutes mutation key does not match its record")
    replacement_key = replacement[0].as_atom()
    seen: set[bytes] = set()
    updated: list[object] = []
    replaced = False
    for entry_node in entries:
        values = list(entry_node.as_iter())
        if not values:
            raise ValueError("statutes witness record is empty")
        key = values[0].as_atom()
        if key in seen:
            raise ValueError("statutes witness contains duplicate keys")
        seen.add(key)
        if key == replacement_key:
            updated.append(replacement_node.as_python())
            replaced = True
        else:
            updated.append(entry_node.as_python())
    if not replaced:
        updated.append(replacement_node.as_python())
    return bytes32(Program.to(updated).get_tree_hash())


def _apply_statutes_transition(
    state: StatutesState,
    inner_solution: list[Program],
) -> StatutesState:
    if len(inner_solution) != 5:
        raise ValueError("statutes inner solution must have five items")
    action = int(inner_solution[3].as_int())
    params = list(inner_solution[4].as_iter())
    if action != STATUTES_SPEND_UPDATE:
        if action not in (
            STATUTES_SPEND_EVIDENCE,
            STATUTES_SPEND_SOLS_EVIDENCE,
            STATUTES_SPEND_GOVERNANCE_EVIDENCE,
        ):
            raise ValueError("unsupported statutes spend action")
        return state
    if len(params) != 6:
        raise ValueError("statutes update has the wrong parameter count")
    kind = MutationKind(int(params[0].as_int()))
    old_root = {
        MutationKind.PARAMETER: state.parameters_root,
        MutationKind.COLLECTION: state.collections_root,
        MutationKind.ORACLE: state.oracle_root,
        MutationKind.ROUTE: state.routes_root,
        MutationKind.LIQUIDITY: state.liquidity_root,
        MutationKind.PAUSE: state.pauses_root,
    }[kind]
    if bytes32(params[3].get_tree_hash()) != old_root:
        raise ValueError("statutes update witness does not match its old root")
    if kind == MutationKind.PARAMETER:
        current = [int(item.as_int()) for item in params[3].as_iter()]
        if len(current) != 9:
            raise ValueError("statutes parameter witness is malformed")
        index = int(params[1].as_int())
        if not 0 <= index < len(current):
            raise ValueError("statutes parameter index is invalid")
        current[index] = int(params[2].as_int())
        new_root = bytes32(Program.to(current).get_tree_hash())
    else:
        new_root = _raw_keyed_upsert_root(
            params[3],
            params[2],
            params[1],
        )
    new_version = int(params[4].as_int())
    if new_version != state.registry_version + 1:
        raise ValueError("statutes version must advance exactly once")
    field = {
        MutationKind.PARAMETER: "parameters_root",
        MutationKind.COLLECTION: "collections_root",
        MutationKind.ORACLE: "oracle_root",
        MutationKind.ROUTE: "routes_root",
        MutationKind.LIQUIDITY: "liquidity_root",
        MutationKind.PAUSE: "pauses_root",
    }[kind]
    return replace(
        state,
        **{field: new_root},
        registry_version=new_version,
    ).validate()


def _decode_statutes_state(
    puzzle_solution: Mapping[str, Any],
    tip: SingletonTip,
    *,
    expected_permanent_rules: PermanentRules,
    expected_governance_launcher_id: str,
) -> StatutesState:
    full = _program(str(puzzle_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise ValueError("statutes puzzle is not a curried singleton")
    full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2 or full_mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError("statutes puzzle is not a canonical singleton")
    old_inner = full_args[1]
    inner_uncurried = old_inner.uncurry()
    if inner_uncurried is None:
        raise ValueError("statutes inner puzzle is not curried")
    inner_mod, inner_args_program = inner_uncurried
    inner_args = list(inner_args_program.as_iter())
    if (
        len(inner_args) != 16
        or inner_mod.get_tree_hash() != protocol_statutes_inner_mod_hash()
    ):
        raise ValueError("statutes inner puzzle is not RC22 V1")
    permanent_rules = PermanentRules(
        sgt_tail_hash=_bytes32_node(inner_args[3], "SGT tail"),
        sgt_total_supply=int(inner_args[4].as_int()),
        sols_tail_hash=_bytes32_node(inner_args[5], "Sols tail"),
        zkpassport_policy_hash=_bytes32_node(
            inner_args[6], "zkPassport policy"
        ),
        protocol_treasury_puzzle_hash=_bytes32_node(
            inner_args[7], "protocol treasury"
        ),
        network_id=_bytes32_node(inner_args[8], "network id"),
    ).validate()
    if permanent_rules != expected_permanent_rules:
        raise ValueError("statutes permanent rules do not match genesis")
    if bytes(inner_args[1]) != bytes(_singleton_struct(tip.launcher_id)):
        raise ValueError("statutes singleton struct does not match launcher")
    if bytes(inner_args[2]) != bytes(
        _singleton_struct(expected_governance_launcher_id)
    ):
        raise ValueError("statutes governance struct does not match genesis")
    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "statutes"
    )
    previous = _statutes_state_from_args(inner_args, permanent_rules)
    current = _apply_statutes_transition(previous, inner_solution)
    current_inner = inner_mod.curry(
        *inner_args[:9],
        current.parameters_root,
        current.collections_root,
        current.oracle_root,
        current.routes_root,
        current.liquidity_root,
        current.pauses_root,
        current.registry_version,
    )
    current_full = full_mod.curry(full_args[0], current_inner)
    if _hex(current_full.get_tree_hash()) != tip.live.puzzle_hash:
        raise ValueError(
            "reconstructed statutes state does not match the live coin"
        )
    return current


def _artifact_parameters(artifact: Mapping[str, Any]) -> ProtocolParameters:
    values = artifact["protocolParameters"]
    return ProtocolParameters(
        voting_window_seconds=int(values["votingWindowSeconds"]),
        quorum_bps=int(values["quorumBps"]),
        min_proposal_stake=int(values["minProposalStake"]),
        nav_validity_seconds=int(values["navValiditySeconds"]),
        oracle_max_age_seconds=int(values["oracleMaxAgeSeconds"]),
        exchange_fee_bps=int(values["exchangeFeeBps"]),
        protocol_fee_bps=int(values["protocolFeeBps"]),
        sgt_rewards_fee_bps=int(values["sgtRewardsFeeBps"]),
        reward_epoch_seconds=int(values["rewardEpochSeconds"]),
    ).validate()


def _artifact_permanent_rules(
    artifact: Mapping[str, Any],
) -> PermanentRules:
    values = artifact["permanentRules"]
    return PermanentRules(
        sgt_tail_hash=bytes32.fromhex(
            _hex32(str(values["sgtTailHash"]), "SGT tail").removeprefix("0x")
        ),
        sgt_total_supply=int(values["sgtTotalSupply"]),
        sols_tail_hash=bytes32.fromhex(
            _hex32(str(values["solsTailHash"]), "Sols tail").removeprefix("0x")
        ),
        zkpassport_policy_hash=bytes32.fromhex(
            _hex32(
                str(values["zkPassportPolicyHash"]),
                "zkPassport policy",
            ).removeprefix("0x")
        ),
        protocol_treasury_puzzle_hash=bytes32.fromhex(
            _hex32(
                str(values["protocolTreasuryPuzzleHash"]),
                "protocol treasury",
            ).removeprefix("0x")
        ),
        network_id=bytes32.fromhex(
            _hex32(str(values["networkId"]), "network id").removeprefix("0x")
        ),
    ).validate()


def _collections(node: Program) -> tuple[CollectionStatute, ...]:
    values = tuple(_collection_statute(item) for item in node.as_iter())
    keyed_root(values)
    return values


def _oracle_rounds(node: Program) -> tuple[OracleRound, ...]:
    values = tuple(_oracle_round(item) for item in node.as_iter())
    keyed_root(values)
    return values


def _bridge_routes(node: Program) -> tuple[BridgeRoute, ...]:
    values = tuple(_bridge_route(item) for item in node.as_iter())
    keyed_root(values)
    return values


def _pauses(node: Program) -> tuple[ScopedPause, ...]:
    values = tuple(_scoped_pause(item) for item in node.as_iter())
    keyed_root(values)
    return values


def _liquidity_venues(node: Program) -> tuple[LiquidityVenue, ...]:
    values = tuple(_liquidity_venue(item) for item in node.as_iter())
    keyed_root(values)
    return values


def _upsert_typed(
    current: (
        tuple[CollectionStatute, ...]
        | tuple[OracleRound, ...]
        | tuple[BridgeRoute, ...]
        | tuple[LiquidityVenue, ...]
        | tuple[ScopedPause, ...]
    ),
    replacement: (
        CollectionStatute
        | OracleRound
        | BridgeRoute
        | LiquidityVenue
        | ScopedPause
    ),
) -> (
    tuple[CollectionStatute, ...]
    | tuple[OracleRound, ...]
    | tuple[BridgeRoute, ...]
    | tuple[LiquidityVenue, ...]
    | tuple[ScopedPause, ...]
):
    replacement_key = _statute_record_key(replacement)
    updated: list[
        CollectionStatute
        | OracleRound
        | BridgeRoute
        | LiquidityVenue
        | ScopedPause
    ] = []
    found = False
    for item in current:
        key = _statute_record_key(item)
        if key == replacement_key:
            updated.append(replacement)
            found = True
        else:
            updated.append(item)
    if not found:
        updated.append(replacement)
    return tuple(updated)  # type: ignore[return-value]


def _statute_record_key(
    item: (
        CollectionStatute
        | OracleRound
        | BridgeRoute
        | LiquidityVenue
        | ScopedPause
    ),
) -> bytes32:
    if isinstance(item, CollectionStatute):
        return item.collection_id
    if isinstance(item, OracleRound):
        return item.asset_id
    if isinstance(item, BridgeRoute):
        return item.route_id
    if isinstance(item, LiquidityVenue):
        return item.venue_id
    return item.scope_id


def _statutes_witnesses(
    puzzle_solution: Mapping[str, Any],
) -> tuple[
    ProtocolParameters | None,
    tuple[CollectionStatute, ...] | None,
    tuple[OracleRound, ...] | None,
    tuple[BridgeRoute, ...] | None,
    tuple[LiquidityVenue, ...] | None,
    tuple[ScopedPause, ...] | None,
]:
    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "statutes"
    )
    if len(inner_solution) != 5:
        raise ValueError("statutes inner solution must have five items")
    action = int(inner_solution[3].as_int())
    params = list(inner_solution[4].as_iter())
    parameters: ProtocolParameters | None = None
    collections: tuple[CollectionStatute, ...] | None = None
    oracle_rounds: tuple[OracleRound, ...] | None = None
    bridge_routes: tuple[BridgeRoute, ...] | None = None
    liquidity_venues: tuple[LiquidityVenue, ...] | None = None
    pauses: tuple[ScopedPause, ...] | None = None
    if action == STATUTES_SPEND_EVIDENCE:
        if len(params) != 3:
            raise ValueError("statutes evidence has the wrong parameter count")
        kind = MutationKind(int(params[0].as_int()))
        if kind == MutationKind.PARAMETER:
            parameters = _protocol_parameters(params[2])
        elif kind == MutationKind.COLLECTION:
            collections = _collections(params[2])
        elif kind == MutationKind.ORACLE:
            oracle_rounds = _oracle_rounds(params[2])
        elif kind == MutationKind.ROUTE:
            bridge_routes = _bridge_routes(params[2])
        elif kind == MutationKind.LIQUIDITY:
            liquidity_venues = _liquidity_venues(params[2])
        elif kind == MutationKind.PAUSE:
            pauses = _pauses(params[2])
    elif action == STATUTES_SPEND_UPDATE:
        if len(params) != 6:
            raise ValueError("statutes update has the wrong parameter count")
        kind = MutationKind(int(params[0].as_int()))
        if kind == MutationKind.PARAMETER:
            current = _protocol_parameters(params[3])
            parameters = current.mutate(
                int(params[1].as_int()),
                int(params[2].as_int()),
            )
        elif kind == MutationKind.COLLECTION:
            collections = _upsert_typed(
                _collections(params[3]),
                _collection_statute(params[2]),
            )
        elif kind == MutationKind.ORACLE:
            oracle_rounds = _upsert_typed(
                _oracle_rounds(params[3]),
                _oracle_round(params[2]),
            )
        elif kind == MutationKind.ROUTE:
            bridge_routes = _upsert_typed(
                _bridge_routes(params[3]),
                _bridge_route(params[2]),
            )
        elif kind == MutationKind.LIQUIDITY:
            liquidity_venues = _upsert_typed(
                _liquidity_venues(params[3]),
                _liquidity_venue(params[2]),
            )
        elif kind == MutationKind.PAUSE:
            pauses = _upsert_typed(
                _pauses(params[3]),
                _scoped_pause(params[2]),
            )
    elif action == STATUTES_SPEND_SOLS_EVIDENCE:
        if len(params) != 5:
            raise ValueError(
                "statutes Sols evidence has the wrong parameter count"
            )
        parameters = _protocol_parameters(params[2])
        collections = _collections(params[3])
        pauses = _pauses(params[4])
    elif action == STATUTES_SPEND_GOVERNANCE_EVIDENCE:
        if len(params) != 1:
            raise ValueError(
                "statutes governance evidence has the wrong parameter count"
            )
        parameters = _protocol_parameters(params[0])
    else:
        raise ValueError("unsupported statutes spend action")
    return (
        parameters,
        collections,
        oracle_rounds,
        bridge_routes,
        liquidity_venues,
        pauses,
    )


async def _resolve_statutes_witnesses(
    provider: ChiaProvider,
    tip: SingletonTip,
    state: StatutesState,
    initial_parameters: ProtocolParameters,
) -> tuple[
    ProtocolParameters,
    tuple[CollectionStatute, ...],
    tuple[OracleRound, ...],
    tuple[BridgeRoute, ...],
    tuple[LiquidityVenue, ...],
    tuple[ScopedPause, ...],
]:
    empty_root = bytes32(Program.to([]).get_tree_hash())
    initial_parameters_root = bytes32(
        Program.to(list(initial_parameters.as_tuple())).get_tree_hash()
    )
    parameters: ProtocolParameters | None = (
        initial_parameters
        if state.parameters_root == initial_parameters_root
        else None
    )
    collections: tuple[CollectionStatute, ...] | None = (
        () if state.collections_root == empty_root else None
    )
    oracle_rounds: tuple[OracleRound, ...] | None = (
        () if state.oracle_root == empty_root else None
    )
    bridge_routes: tuple[BridgeRoute, ...] | None = (
        () if state.routes_root == empty_root else None
    )
    liquidity_venues: tuple[LiquidityVenue, ...] | None = (
        () if state.liquidity_root == empty_root else None
    )
    pauses: tuple[ScopedPause, ...] | None = (
        () if state.pauses_root == empty_root else None
    )
    spent = [
        coin
        for coin in reversed(tip.lineage)
        if not coin.is_launcher and coin.spent_height is not None
    ]
    for coin in spent:
        puzzle_solution = await _singleton_spend(provider, coin)
        (
            candidate_parameters,
            candidate_collections,
            candidate_oracle_rounds,
            candidate_bridge_routes,
            candidate_liquidity_venues,
            candidate_pauses,
        ) = _statutes_witnesses(puzzle_solution)
        if (
            parameters is None
            and candidate_parameters is not None
            and bytes32(
                Program.to(
                    list(candidate_parameters.as_tuple())
                ).get_tree_hash()
            )
            == state.parameters_root
        ):
            parameters = candidate_parameters
        if (
            collections is None
            and candidate_collections is not None
            and keyed_root(candidate_collections) == state.collections_root
        ):
            collections = candidate_collections
        if (
            oracle_rounds is None
            and candidate_oracle_rounds is not None
            and keyed_root(candidate_oracle_rounds) == state.oracle_root
        ):
            oracle_rounds = candidate_oracle_rounds
        if (
            bridge_routes is None
            and candidate_bridge_routes is not None
            and keyed_root(candidate_bridge_routes) == state.routes_root
        ):
            bridge_routes = candidate_bridge_routes
        if (
            liquidity_venues is None
            and candidate_liquidity_venues is not None
            and keyed_root(candidate_liquidity_venues)
            == state.liquidity_root
        ):
            liquidity_venues = candidate_liquidity_venues
        if (
            pauses is None
            and candidate_pauses is not None
            and keyed_root(candidate_pauses) == state.pauses_root
        ):
            pauses = candidate_pauses
        if (
            parameters is not None
            and collections is not None
            and oracle_rounds is not None
            and bridge_routes is not None
            and liquidity_venues is not None
            and pauses is not None
        ):
            break
    if (
        parameters is None
        or collections is None
        or oracle_rounds is None
        or bridge_routes is None
        or liquidity_venues is None
        or pauses is None
    ):
        raise ValueError(
            "current statutes parameters, collections, oracles, routes, "
            "liquidity, or pauses cannot be reconstructed"
        )
    await _require_same_coin(provider, tip.live)
    return (
        parameters,
        collections,
        oracle_rounds,
        bridge_routes,
        liquidity_venues,
        pauses,
    )


async def _statutes_snapshot(
    provider: ChiaProvider,
    tip: SingletonTip,
    artifact: Mapping[str, Any],
) -> StatutesSnapshot:
    parameters = _artifact_parameters(artifact)
    permanent_rules = _artifact_permanent_rules(artifact)
    if len(tip.lineage) < 2:
        raise ValueError("statutes launcher has no singleton continuation")
    expected_initial = str(
        artifact["puzzleHashes"]["statutesFullPuzzleHash"]
    ).lower()
    if tip.lineage[1].puzzle_hash.lower() != expected_initial:
        raise ValueError("statutes genesis puzzle hash does not match artifact")
    solution = await _latest_solution(provider, tip)
    if solution is None:
        state = initial_state(
            parameters=parameters,
            permanent_rules=permanent_rules,
        )
        collections: tuple[CollectionStatute, ...] = ()
        oracle_rounds: tuple[OracleRound, ...] = ()
        bridge_routes: tuple[BridgeRoute, ...] = ()
        liquidity_venues: tuple[LiquidityVenue, ...] = ()
        pauses: tuple[ScopedPause, ...] = ()
        if tip.live.puzzle_hash.lower() != expected_initial:
            raise ValueError("initial statutes coin does not match artifact")
    else:
        state = _decode_statutes_state(
            solution,
            tip,
            expected_permanent_rules=permanent_rules,
            expected_governance_launcher_id=str(
                artifact["launcherIds"]["governance"]
            ),
        )
        (
            parameters,
            collections,
            oracle_rounds,
            bridge_routes,
            liquidity_venues,
            pauses,
        ) = await _resolve_statutes_witnesses(
            provider,
            tip,
            state,
            parameters,
        )
    return StatutesSnapshot(
        live_coin_id=tip.live.coin_id,
        live_puzzle_hash=tip.live.puzzle_hash,
        state=state,
        parameters=parameters,
        collections=collections,
        oracle_rounds=oracle_rounds,
        bridge_routes=bridge_routes,
        liquidity_venues=liquidity_venues,
        pauses=pauses,
        registry_version=state.registry_version,
        confirmed_height=tip.live.confirmed_height,
        lineage_depth=tip.depth,
    )


def _initial_pool_state(
    tip: SingletonTip,
    artifact: Mapping[str, Any],
) -> PoolState:
    if len(tip.lineage) < 2:
        raise ValueError("pool launcher has no singleton continuation")
    expected = str(artifact["puzzleHashes"]["poolFullPuzzleHash"]).lower()
    if tip.lineage[1].puzzle_hash.lower() != expected:
        raise ValueError("pool genesis puzzle hash does not match artifact")
    if tip.live.puzzle_hash.lower() != expected:
        raise ValueError("initial pool coin does not match artifact")
    state = SolsPoolStateV4(
        inventory_root=inventory_root(()),
        economics=SolsEconomicState(
            bootstrap_complete=False,
            inventory_nav_micro_usd=0,
            treasury_assets_micro_usd=0,
            proven_liabilities_micro_usd=0,
            deed_count=0,
            total_sols_mojos=1,
            reserve_sols_mojos=1,
        ),
        state_version=1,
    ).validate(())
    expected_commitment = str(
        artifact["genesisPlan"]["state"]["poolCommitmentHash"]
    ).lower()
    if _hex(state.commitment_hash) != expected_commitment:
        raise ValueError("initial pool commitment does not match artifact")
    return PoolState(
        bootstrap_complete=False,
        inventory_nav_micro_usd=0,
        treasury_assets_micro_usd=0,
        proven_liabilities_micro_usd=0,
        deed_count=0,
        total_sols_mojos=1,
        reserve_sols_mojos=1,
        state_version=1,
        inventory=(),
        live_coin_id=tip.live.coin_id,
        live_puzzle_hash=tip.live.puzzle_hash,
        confirmed_height=tip.live.confirmed_height,
        lineage_depth=tip.depth,
    )


def _decode_pool_deed(
    puzzle_solution: Mapping[str, Any],
    tip: SingletonTip,
    *,
    expected_pool_launcher_id: str,
) -> PoolDeed:
    full = _program(str(puzzle_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise ValueError("SmartDeed puzzle is not a curried singleton")
    full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2 or full_mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError("SmartDeed is not a canonical singleton")
    old_inner = full_args[1]
    inner_uncurried = old_inner.uncurry()
    if inner_uncurried is None:
        raise ValueError("SmartDeed inner puzzle is not curried")
    inner_mod, inner_args_program = inner_uncurried
    inner_args = list(inner_args_program.as_iter())
    if (
        len(inner_args) != 15
        or inner_mod.get_tree_hash()
        != load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
    ):
        raise ValueError("SmartDeed V2 inner puzzle must have 15 arguments")
    _, inner_solution = _solution_parts(
        str(puzzle_solution["solution"]), "SmartDeed"
    )
    if len(inner_solution) != 5:
        raise ValueError("SmartDeed inner solution must have five items")
    if int(inner_solution[3].as_int()) != DEED_SPEND_POOL_DEPOSIT:
        raise ValueError("live SmartDeed is not in pool custody")

    deed_struct = inner_args[0]
    struct_values = list(deed_struct.as_iter())
    if len(struct_values) != 2:
        raise ValueError("SmartDeed singleton struct is malformed")
    launcher_pair = list(struct_values[1].as_iter())
    if len(launcher_pair) != 2:
        raise ValueError("SmartDeed launcher pair is malformed")
    deed_launcher_id = bytes32(launcher_pair[0].as_atom())
    pool_launcher_id = bytes32(inner_args[11].as_atom())
    if _hex(pool_launcher_id) != _hex32(
        expected_pool_launcher_id, "expected pool launcher id"
    ):
        raise ValueError("SmartDeed is committed to a different pool")
    p2_pool_mod_hash = bytes32(inner_args[13].as_atom())
    if p2_pool_mod_hash != canonical_p2_pool_mod_hash():
        raise ValueError("SmartDeed uses a retired pool custody module")

    par_value = int(inner_args[2].as_int())
    asset_class = int(inner_args[3].as_int())
    property_id = bytes32(inner_args[4].as_atom())
    collection_id = bytes32(inner_args[5].as_atom())
    share_ppm = int(inner_args[6].as_int())
    commitment = deed_metadata_commitment(
        deed_launcher_id,
        par_value,
        asset_class,
        property_id,
        collection_id,
        share_ppm,
    )
    p2_pool = load_puzzle("p2_pool_v2.clsp").curry(
        p2_pool_mod_hash,
        bytes32(inner_args[10].as_atom()),
        pool_launcher_id,
        bytes32(inner_args[12].as_atom()),
        commitment,
    )
    current_full = full_mod.curry(full_args[0], p2_pool)
    if _hex(current_full.get_tree_hash()) != tip.live.puzzle_hash:
        raise ValueError("pool-custodied SmartDeed does not match the live coin")
    return PoolDeed(
        deed_coin_id=tip.live.coin_id,
        deed_launcher_id=_hex(deed_launcher_id),
        par_value_mojos=par_value,
        asset_class=asset_class,
        property_id_canon=_hex(property_id),
        collection_id_canon=_hex(collection_id),
        share_ppm=share_ppm,
        deed_commitment=_hex(commitment),
        confirmed_height=tip.live.confirmed_height,
    )


def _inventory_payload(record: PoolInventoryRecord) -> dict[str, Any]:
    return {
        "deedLauncherId": _hex(record.deed_launcher_id),
        "custodyCoinId": _hex(record.custody_coin_id),
        "deedCommitment": _hex(record.deed_commitment),
        "collectionIdCanon": _hex(record.collection_id),
        "sharePpm": record.share_ppm,
        "deedValueMicroUsd": str(record.deed_value_micro_usd),
        "navVersion": record.nav_version,
        "validUntil": record.valid_until,
        "settlementState": record.settlement_state,
    }


def _pool_payload(pool: PoolState | None) -> dict[str, Any] | None:
    if pool is None:
        return None
    return {
        "bootstrapComplete": pool.bootstrap_complete,
        "inventoryNavMicroUsd": str(pool.inventory_nav_micro_usd),
        "treasuryAssetsMicroUsd": str(pool.treasury_assets_micro_usd),
        "provenLiabilitiesMicroUsd": str(pool.proven_liabilities_micro_usd),
        "deedCount": pool.deed_count,
        "totalSolsMojos": str(pool.total_sols_mojos),
        "reserveSolsMojos": str(pool.reserve_sols_mojos),
        "stateVersion": pool.state_version,
        "inventoryRoot": _hex(inventory_root(pool.inventory)),
        "inventory": [_inventory_payload(item) for item in pool.inventory],
        "liveCoinId": pool.live_coin_id,
        "livePuzzleHash": pool.live_puzzle_hash,
        "confirmedHeight": pool.confirmed_height,
        "lineageDepth": pool.lineage_depth,
    }


def _statutes_payload(
    statutes: StatutesSnapshot | None,
) -> dict[str, Any] | None:
    if statutes is None:
        return None
    state = statutes.state
    return {
        "registryVersion": statutes.registry_version,
        "contentHash": _hex(state.content_hash),
        "parametersRoot": _hex(state.parameters_root),
        "collectionsRoot": _hex(state.collections_root),
        "oracleRoot": _hex(state.oracle_root),
        "routesRoot": _hex(state.routes_root),
        "liquidityRoot": _hex(state.liquidity_root),
        "pausesRoot": _hex(state.pauses_root),
        "parameters": {
            "votingWindowSeconds": statutes.parameters.voting_window_seconds,
            "quorumBps": statutes.parameters.quorum_bps,
            "minimumProposalStake": str(
                statutes.parameters.min_proposal_stake
            ),
            "navValiditySeconds": statutes.parameters.nav_validity_seconds,
            "oracleMaxAgeSeconds": (
                statutes.parameters.oracle_max_age_seconds
            ),
            "exchangeFeeBps": statutes.parameters.exchange_fee_bps,
            "protocolFeeBps": statutes.parameters.protocol_fee_bps,
            "sgtRewardsFeeBps": statutes.parameters.sgt_rewards_fee_bps,
            "rewardEpochSeconds": statutes.parameters.reward_epoch_seconds,
        },
        "collections": [
            {
                "collectionIdCanon": _hex(item.collection_id),
                "navMicroUsd": str(item.nav_micro_usd),
                "allocationCeilingMicroUsd": str(
                    item.allocation_ceiling_micro_usd
                ),
                "navVersion": item.nav_version,
                "validAfter": item.valid_after,
                "validUntil": item.valid_until,
                "status": item.status,
            }
            for item in statutes.collections
        ],
        "oracleRounds": [
            {
                "assetId": _hex(item.asset_id),
                "priceMicroUsd": str(item.price_micro_usd),
                "observedAt": item.observed_at,
                "validUntil": item.valid_until,
                "roundId": item.round_id,
                "sourceRoot": _hex(item.source_root),
                "sourceCount": item.source_count,
                "haircutBps": item.haircut_bps,
                "stableMinBps": item.stable_min_bps,
                "stableMaxBps": item.stable_max_bps,
            }
            for item in statutes.oracle_rounds
        ],
        "bridgeRoutes": [
            {
                "routeId": _hex(item.route_id),
                "sourceChainId": _hex(item.source_chain_id),
                "destinationChainId": _hex(item.destination_chain_id),
                "assetId": _hex(item.asset_id),
                "remoteAssetId": _hex(item.remote_asset_id),
                "decimals": item.decimals,
                "active": bool(item.active),
            }
            for item in statutes.bridge_routes
        ],
        "liquidityVenues": [
            {
                "venueId": _hex(item.venue_id),
                "chainId": _hex(item.chain_id),
                "protocolId": _hex(item.protocol_id),
                "factoryId": _hex(item.factory_id),
                "poolId": _hex(item.pool_id),
                "baseAssetId": _hex(item.base_asset_id),
                "quoteAssetId": _hex(item.quote_asset_id),
                "poolCodeHash": _hex(item.pool_code_hash),
                "active": bool(item.active),
            }
            for item in statutes.liquidity_venues
        ],
        "pauses": [
            {
                "scopeId": _hex(item.scope_id),
                "paused": bool(item.paused),
                "expiresAt": item.expires_at,
                "reasonHash": _hex(item.reason_hash),
            }
            for item in statutes.pauses
        ],
        "liveCoinId": statutes.live_coin_id,
        "livePuzzleHash": statutes.live_puzzle_hash,
        "confirmedHeight": statutes.confirmed_height,
        "lineageDepth": statutes.lineage_depth,
    }


class SolsMarketReader:
    def __init__(
        self,
        provider: ChiaProvider,
        store: CollectionStore,
        settings: Settings,
    ) -> None:
        self.provider = provider
        self.store = store
        self.settings = settings

    async def snapshot(self) -> dict[str, Any]:
        artifact = load_signed_public_artifact(self.settings)
        launchers = artifact["launcherIds"]
        puzzle_hashes = artifact["puzzleHashes"]
        pool_tip = await _singleton_tip(self.provider, str(launchers["pool"]))
        statutes_tip = await _singleton_tip(
            self.provider,
            str(launchers["statutes"]),
        )
        pool_solution = (
            await _latest_solution(self.provider, pool_tip) if pool_tip else None
        )
        if pool_tip is None:
            pool = None
        elif pool_solution is None:
            pool = _initial_pool_state(pool_tip, artifact)
        else:
            if len(pool_tip.lineage) < 2 or (
                pool_tip.lineage[1].puzzle_hash.lower()
                != str(puzzle_hashes["poolFullPuzzleHash"]).lower()
            ):
                raise ValueError(
                    "pool genesis puzzle hash does not match artifact"
                )
            pool = _decode_pool_state(pool_solution, pool_tip)
        statutes = (
            await _statutes_snapshot(
                self.provider,
                statutes_tip,
                artifact,
            )
            if statutes_tip
            else None
        )

        opportunities: list[dict[str, Any]] = []
        rejected = 0
        candidates = {
            str(candidate["deedLauncherId"]).lower(): candidate
            for candidate in self.store.sols_market_candidates()
        }
        collections = {
            item.collection_id: item
            for item in statutes.collections
        } if statutes else {}
        pauses = {
            item.scope_id: item
            for item in statutes.pauses
        } if statutes else {}
        for inventory_record in pool.inventory if pool else ():
            try:
                candidate = candidates.get(
                    _hex(inventory_record.deed_launcher_id).lower()
                )
                if candidate is None:
                    raise ValueError(
                        "pool inventory has no published collection record"
                    )
                collection = self.store.public_collection(candidate["collectionId"])
                if not collection["verification"]["chainReconstructed"]:
                    raise ValueError("collection metadata is not reconstructed")
                tip = await _singleton_tip(
                    self.provider, str(candidate["deedLauncherId"])
                )
                solution = (
                    await _latest_solution(self.provider, tip) if tip else None
                )
                if not tip or not solution:
                    raise ValueError("SmartDeed has no current pool-custody spend")
                deed = _decode_pool_deed(
                    solution,
                    tip,
                    expected_pool_launcher_id=str(launchers["pool"]),
                )
                if deed.deed_launcher_id.lower() != str(
                    candidate["deedLauncherId"]
                ).lower():
                    raise ValueError("SmartDeed launcher does not match collection")
                if deed.share_ppm != int(candidate["sharePpm"]):
                    raise ValueError("SmartDeed share does not match collection")
                if deed.par_value_mojos != int(candidate["parValueMojos"]):
                    raise ValueError("SmartDeed par value does not match collection")
                if deed.deed_coin_id.lower() != (
                    _hex(inventory_record.custody_coin_id).lower()
                ):
                    raise ValueError(
                        "SmartDeed custody coin does not match Pool V4"
                    )
                if deed.deed_commitment.lower() != (
                    _hex(inventory_record.deed_commitment).lower()
                ):
                    raise ValueError(
                        "SmartDeed commitment does not match Pool V4"
                    )
                if deed.collection_id_canon.lower() != (
                    _hex(inventory_record.collection_id).lower()
                ):
                    raise ValueError(
                        "SmartDeed collection does not match Pool V4"
                    )
                if deed.share_ppm != inventory_record.share_ppm:
                    raise ValueError(
                        "SmartDeed share does not match Pool V4"
                    )
                statute = collections.get(inventory_record.collection_id)
                if statute is None:
                    raise ValueError(
                        "collection has no current governed statute"
                    )
                if statute.status not in (1, 3):
                    raise ValueError(
                        "collection is not available for Sols acquisition"
                    )
                pause = pauses.get(inventory_record.collection_id)
                if pause is not None and pause.paused:
                    raise ValueError("collection Sols swaps are paused")
                if (
                    inventory_record.nav_version != statute.nav_version
                    or inventory_record.valid_until != statute.valid_until
                ):
                    raise ValueError(
                        "Pool V4 inventory requires governed revaluation"
                    )
                governed_value = (
                    statute.nav_micro_usd * inventory_record.share_ppm
                    + 999_999
                ) // 1_000_000
                if inventory_record.deed_value_micro_usd != governed_value:
                    raise ValueError(
                        "Pool V4 deed value does not match the statute"
                    )
                if statute.valid_until <= int(time()):
                    raise ValueError("collection NAV is expired")
                quote = quote_sols_to_deed(
                    pool.economics(),
                    deed_value_micro_usd=(
                        inventory_record.deed_value_micro_usd
                    ),
                    exchange_fee_bps=statutes.parameters.exchange_fee_bps,
                    protocol_fee_bps=statutes.parameters.protocol_fee_bps,
                    sgt_rewards_fee_bps=(
                        statutes.parameters.sgt_rewards_fee_bps
                    ),
                )
                opportunities.append(
                    {
                        "deedId": candidate["deedId"],
                        "deedLauncherId": deed.deed_launcher_id,
                        "deedCoinId": deed.deed_coin_id,
                        "collectionId": candidate["collectionId"],
                        "collectionSlug": candidate["collectionSlug"],
                        "collectionTitle": candidate["collectionTitle"],
                        "collectionSummary": candidate["collectionSummary"],
                        "metadataRoot": candidate["metadataRoot"],
                        "propertyIdCanon": deed.property_id_canon,
                        "collectionIdCanon": deed.collection_id_canon,
                        "sharePpm": deed.share_ppm,
                        "parValueMojos": str(deed.par_value_mojos),
                        "assetClass": deed.asset_class,
                        "collectionNavMicroUsd": str(
                            statute.nav_micro_usd
                        ),
                        "deedValueMicroUsd": str(
                            inventory_record.deed_value_micro_usd
                        ),
                        "navVersion": statute.nav_version,
                        "navValidUntil": statute.valid_until,
                        "principalSolsMojos": str(
                            quote.principal_sols_mojos
                        ),
                        "protocolFeeSolsMojos": str(
                            quote.fee_split.protocol_fee_sols_mojos
                        ),
                        "sgtRewardsFeeSolsMojos": str(
                            quote.fee_split.sgt_rewards_fee_sols_mojos
                        ),
                        "totalSolsMojos": str(
                            quote.buyer_total_sols_mojos
                        ),
                        "chainVerified": True,
                        "confirmedHeight": deed.confirmed_height,
                    }
                )
            except (KeyError, TypeError, ValueError):
                rejected += 1

        if pool is None or statutes is None:
            outcome = "WAITING"
            title = "Sols market is waiting for confirmed protocol state"
            body = (
                "Inventory remains hidden until Pool V4 and statutes "
                "reconstruct from Testnet11."
            )
        elif not opportunities:
            outcome = "WAITING"
            title = "No SmartDeeds are available for SOLS yet"
            body = (
                "A deed appears after its Pool V4 custody record, collection "
                "statute, and public dossier all verify."
            )
        else:
            outcome = "READY"
            title = (
                f"{len(opportunities)} SmartDeed swap"
                f"{'s' if len(opportunities) != 1 else ''} available"
            )
            body = (
                "Prices come from the current governed statute and Pool V4 "
                "backing state."
            )
        visible_opportunities = (
            opportunities
            if pool is not None
            and statutes is not None
            else []
        )
        return {
            "schemaVersion": 2,
            "network": self.settings.network,
            "asset": {
                "symbol": "SOLS",
                "name": "Sols",
                "tailHash": puzzle_hashes["solsTailHash"],
                "purpose": "secondary-smartdeed-swaps-only",
            },
            "outcome": outcome,
            "title": title,
            "body": body,
            "pool": _pool_payload(pool),
            "statutes": _statutes_payload(statutes),
            "opportunities": visible_opportunities,
            "verifiedOpportunityCount": len(visible_opportunities),
            "rejectedCandidateCount": rejected,
            "provider": self.provider.status(),
        }

    async def vault_sols_balance(self, vault_launcher_id: str) -> int:
        """Return Sols held by the canonical Pool V4 vault custody puzzle."""
        artifact = load_signed_public_artifact(self.settings)
        pool_tip = await _singleton_tip(
            self.provider,
            str(artifact["launcherIds"]["pool"]),
        )
        if pool_tip is None:
            raise ValueError("Pool V4 launcher is not confirmed")
        pool_solution = await _latest_solution(self.provider, pool_tip)
        config = (
            _pool_config(pool_solution, artifact, pool_tip)
            if pool_solution is not None
            else _initial_pool_config(artifact, pool_tip)
        )
        vault_launcher = bytes32.fromhex(
            _hex32(vault_launcher_id, "vault launcher").removeprefix("0x")
        )
        cat = puzzle_for_vault_sols_cat(
            config=config,
            vault_launcher_id=vault_launcher,
        )
        records = await self.provider.get_coin_records_by_puzzle_hash(
            _hex(cat.get_tree_hash()),
            include_spent=False,
        )
        return sum(
            int(item["coin"]["amount"])
            for item in records
            if isinstance(item, Mapping)
            and isinstance(item.get("coin"), Mapping)
            and int(item.get("confirmed_block_index") or 0) > 0
            and int(item.get("spent_block_index") or 0) == 0
            and not bool(item.get("spent"))
        )

    async def vault_holdings(
        self,
        vault_launcher_id: str,
    ) -> dict[str, Any]:
        """Return only SmartDeeds whose live singleton is held by this vault."""
        artifact = load_signed_public_artifact(self.settings)
        launcher_id = bytes32.fromhex(
            _hex32(
                vault_launcher_id,
                "vault launcher",
            ).removeprefix("0x")
        )
        holdings: list[dict[str, Any]] = []
        rejected = 0
        for candidate in self.store.sols_market_candidates():
            try:
                deed_launcher = _hex32(
                    str(candidate["deedLauncherId"]),
                    "deed launcher",
                )
                tip = await _singleton_tip(self.provider, deed_launcher)
                if tip is None:
                    raise ValueError("SmartDeed launcher is not confirmed")
                # The singleton launcher is part of the full puzzle. Derive the
                # exact expected hash per deed rather than trusting an index.
                deed_id = bytes32.fromhex(
                    deed_launcher.removeprefix("0x")
                )
                deed_struct = Program.to(
                    (
                        SINGLETON_MOD_HASH,
                        (
                            deed_id,
                            bytes32.fromhex(
                                str(
                                    artifact["puzzleHashes"][
                                        "deedLauncherPuzzleHash"
                                    ]
                                ).removeprefix("0x")
                            ),
                        ),
                    )
                )
                expected = _hex(
                    SINGLETON_MOD.curry(
                        deed_struct,
                        puzzle_for_p2_vault(launcher_id),
                    ).get_tree_hash()
                )
                if tip.live.puzzle_hash.lower() != expected.lower():
                    continue
                lineage_ids = {item.coin_id.lower() for item in tip.lineage}
                if str(candidate["outputCoinId"]).lower() not in lineage_ids:
                    raise ValueError(
                        "executed mint output is not in the live deed lineage"
                    )
                collection = self.store.public_collection(
                    str(candidate["collectionId"])
                )
                verification = collection.get("verification")
                if (
                    not isinstance(verification, Mapping)
                    or not verification.get("chainReconstructed")
                ):
                    raise ValueError(
                        "SmartDeed collection metadata is not reconstructed"
                    )
                holdings.append(
                    {
                        "deedId": candidate["deedId"],
                        "deedLauncherId": deed_launcher,
                        "deedCoinId": tip.live.coin_id,
                        "collectionId": candidate["collectionId"],
                        "collectionSlug": candidate["collectionSlug"],
                        "collectionTitle": candidate["collectionTitle"],
                        "collectionSummary": candidate["collectionSummary"],
                        "metadataRoot": candidate["metadataRoot"],
                        "sharePpm": int(candidate["sharePpm"]),
                        "parValueMojos": str(candidate["parValueMojos"]),
                        "assetClass": int(
                            ASSET_CLASS_CODES[
                                str(
                                    collection["dossier"]["classification"][
                                        "assetClass"
                                    ]
                                ).upper()
                            ]
                        ),
                        "chainVerified": True,
                        "confirmedHeight": tip.live.confirmed_height,
                        "custody": "P2_VAULT",
                    }
                )
            except (KeyError, TypeError, ValueError):
                rejected += 1
        return {
            "holdings": holdings,
            "verifiedHoldingCount": len(holdings),
            "rejectedHoldingCandidateCount": rejected,
            "source": "chain-reconstructed-smartdeed-singletons",
            "protocolPoolLauncherId": str(
                artifact["launcherIds"]["pool"]
            ),
        }


def _reader(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> SolsMarketReader:
    provider = getattr(request.app.state, "coinset", None)
    if not isinstance(provider, ChiaProvider):
        raise HTTPException(status_code=503, detail="Chia provider is unavailable")
    return SolsMarketReader(provider, store, settings)


@router.get("/market")
async def sols_market(
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    try:
        return await reader.snapshot()
    except PublicArtifactMissing:
        return {
            "schemaVersion": 2,
            "network": "testnet11",
            "outcome": "LOCKED",
            "title": "SOLS secondary swaps begin after protocol launch",
            "body": "The signed genesis artifact is not installed. No swap inventory is exposed.",
            "pool": None,
            "statutes": None,
            "opportunities": [],
            "verifiedOpportunityCount": 0,
            "rejectedCandidateCount": 0,
        }
    except (ChiaProviderError, PublicArtifactError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SOLS market verification failed closed: {exc}",
        ) from exc


@router.get("/governance-summary")
async def governance_summary(
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    try:
        snapshot = await reader.snapshot()
        statutes = snapshot.get("statutes")
        if not isinstance(statutes, Mapping):
            raise ValueError("governed statutes are not confirmed")
        parameters = statutes.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ValueError("governed parameters are unavailable")
        return {
            "schemaVersion": 1,
            "network": settings.network,
            "statutesVersion": int(statutes["registryVersion"]),
            "statutesContentHash": str(statutes["contentHash"]),
            "votingWindowSeconds": int(
                parameters.get("votingWindowSeconds")
                or 0
            ),
            "quorumBps": int(parameters.get("quorumBps") or 0),
            "minimumProposalStake": str(
                parameters.get("minimumProposalStake") or "0"
            ),
            "activeProposals": [],
            "activeProposalCount": 0,
            "votingUrl": "/protocol/committee",
            "source": "chain-reconstructed-statutes",
            "confirmedHeight": int(statutes["confirmedHeight"]),
        }
    except PublicArtifactMissing:
        return {
            "schemaVersion": 1,
            "network": settings.network,
            "statutesVersion": 0,
            "statutesContentHash": None,
            "votingWindowSeconds": 0,
            "quorumBps": 0,
            "minimumProposalStake": "0",
            "activeProposals": [],
            "activeProposalCount": 0,
            "votingUrl": "/protocol/committee",
            "source": "awaiting-signed-genesis",
            "confirmedHeight": None,
        }
    except (
        ChiaProviderError,
        PublicArtifactError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Governance summary verification failed closed: {exc}",
        ) from exc


@router.get("/bridge-routes")
async def bridge_routes(
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    try:
        snapshot = await reader.snapshot()
        statutes = snapshot.get("statutes")
        if not isinstance(statutes, Mapping):
            raise ValueError("governed statutes are not confirmed")
        routes = statutes.get("bridgeRoutes")
        if not isinstance(routes, list):
            raise ValueError("governed bridge routes are unavailable")
        governed_routes = [item for item in routes if isinstance(item, Mapping)]
        checks, evidence_ready = _capability_checks(
            settings=settings,
            capability="warp-cat-bridge",
            governed_root=str(statutes["routesRoot"]),
            governed_records=governed_routes,
            governed_active=any(bool(item.get("active")) for item in governed_routes),
            feature_enabled=settings.sols_bridge_enabled,
            evidence_path=settings.sols_bridge_release_evidence_path,
            evidence_sha256=settings.sols_bridge_release_evidence_sha256,
            execution_surface_installed=WARP_CAT_EXECUTION_SURFACE_INSTALLED,
            installed_adapter_kinds=WARP_CAT_INSTALLED_ADAPTERS,
            confirmation_observer_installed=(
                WARP_CAT_CONFIRMATION_OBSERVER_INSTALLED
            ),
        )
        executable = all(item["status"] == "READY" for item in checks)
        profiles = _capability_profiles(
            settings=settings,
            evidence_ready=evidence_ready,
            capability="warp-cat-bridge",
            governed_root=str(statutes["routesRoot"]),
            governed_records=governed_routes,
            evidence_path=settings.sols_bridge_release_evidence_path,
            evidence_sha256=settings.sols_bridge_release_evidence_sha256,
            record_key="routeId",
        )
        return {
            "schemaVersion": 2,
            "network": settings.network,
            "environment": settings.runtime_environment,
            "deploymentId": settings.sols_capability_deployment_id,
            "releaseEvidenceSha256": (
                (settings.sols_bridge_release_evidence_sha256 or "").removeprefix("0x").lower() if evidence_ready else None
            ),
            "mode": "LIVE" if executable else "PREVIEW",
            "executable": executable,
            "activationState": _activation_state(
                settings.network,
                executable,
                checks,
            ),
            "reason": None if executable else _first_incomplete_detail(checks),
            "readiness": checks,
            "routesRoot": statutes["routesRoot"],
            "routes": [
                {
                    **item,
                    **profiles.get(str(item.get("routeId", "")).lower(), {}),
                    "governedActive": bool(item.get("active")),
                    "executable": executable and bool(item.get("active")),
                }
                for item in governed_routes
            ],
            "existingEvidenceScope": (
                "The pinned Samuel/Base Sepolia Warp portal supports the "
                "escrow purchase rail. A customer wSOLS CAT bridge additionally "
                "requires its own WrappedCAT deployment, registration, runtime "
                "evidence, and transfer adapter."
            ),
            "source": "chain-reconstructed-statutes",
            "confirmedHeight": statutes["confirmedHeight"],
        }
    except PublicArtifactMissing:
        return _locked_capability_view(
            settings.network,
            "routes",
            "Signed genesis is not installed.",
        )
    except (
        ChiaProviderError,
        PublicArtifactError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Bridge route verification failed closed: {exc}",
        ) from exc


@router.get("/liquidity-venues")
async def liquidity_venues(
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    try:
        snapshot = await reader.snapshot()
        statutes = snapshot.get("statutes")
        if not isinstance(statutes, Mapping):
            raise ValueError("governed statutes are not confirmed")
        venues = statutes.get("liquidityVenues")
        if not isinstance(venues, list):
            raise ValueError("governed liquidity venues are unavailable")
        governed_venues = [item for item in venues if isinstance(item, Mapping)]
        checks, evidence_ready = _capability_checks(
            settings=settings,
            capability="governed-liquidity",
            governed_root=str(statutes["liquidityRoot"]),
            governed_records=governed_venues,
            governed_active=any(bool(item.get("active")) for item in governed_venues),
            feature_enabled=settings.sols_liquidity_enabled,
            evidence_path=settings.sols_liquidity_release_evidence_path,
            evidence_sha256=settings.sols_liquidity_release_evidence_sha256,
            execution_surface_installed=LIQUIDITY_EXECUTION_SURFACE_INSTALLED,
            installed_adapter_kinds=LIQUIDITY_INSTALLED_ADAPTERS,
        )
        executable = all(item["status"] == "READY" for item in checks)
        profiles = _capability_profiles(
            settings=settings,
            evidence_ready=evidence_ready,
            capability="governed-liquidity",
            governed_root=str(statutes["liquidityRoot"]),
            governed_records=governed_venues,
            evidence_path=settings.sols_liquidity_release_evidence_path,
            evidence_sha256=settings.sols_liquidity_release_evidence_sha256,
            record_key="venueId",
        )
        return {
            "schemaVersion": 2,
            "network": settings.network,
            "environment": settings.runtime_environment,
            "deploymentId": settings.sols_capability_deployment_id,
            "releaseEvidenceSha256": (
                (settings.sols_liquidity_release_evidence_sha256 or "").removeprefix("0x").lower() if evidence_ready else None
            ),
            "mode": "LIVE" if executable else "PREVIEW",
            "executable": executable,
            "activationState": _activation_state(
                settings.network,
                executable,
                checks,
            ),
            "reason": None if executable else _first_incomplete_detail(checks),
            "readiness": checks,
            "liquidityRoot": statutes["liquidityRoot"],
            "venues": [
                {
                    **item,
                    **profiles.get(str(item.get("venueId", "")).lower(), {}),
                    "governedActive": bool(item.get("active")),
                    "executable": executable and bool(item.get("active")),
                }
                for item in governed_venues
            ],
            "source": "chain-reconstructed-statutes",
            "confirmedHeight": statutes["confirmedHeight"],
        }
    except PublicArtifactMissing:
        return _locked_capability_view(
            settings.network,
            "venues",
            "Signed genesis is not installed.",
        )
    except (
        ChiaProviderError,
        PublicArtifactError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Liquidity venue verification failed closed: {exc}",
        ) from exc


@router.post("/bridge-intents")
async def create_bridge_intent(
    body: BridgeIntentRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    session = verify_vault_session(settings, request, body.vaultLauncherId)
    require_current_approved_vault(settings, session.vault_launcher_id)
    try:
        statutes, records, evidence = await _execution_context(
            settings=settings,
            reader=reader,
            capability="warp-cat-bridge",
            records_key="bridgeRoutes",
            root_key="routesRoot",
            feature_enabled=settings.sols_bridge_enabled,
            evidence_path=settings.sols_bridge_release_evidence_path,
            evidence_sha256=settings.sols_bridge_release_evidence_sha256,
            execution_surface_installed=WARP_CAT_EXECUTION_SURFACE_INSTALLED,
            installed_adapter_kinds=WARP_CAT_INSTALLED_ADAPTERS,
            confirmation_observer_installed=(
                WARP_CAT_CONFIRMATION_OBSERVER_INSTALLED
            ),
        )
        record = _active_record(records, "routeId", body.routeId)
        descriptor = descriptor_for_record(
            evidence.adapter_descriptors,
            record_id=body.routeId,
        )
        if body.direction == "EVM_TO_CHIA" and session.auth_type != "evm":
            raise SolsCapabilityAdapterError("connect the EVM source wallet to prepare a return transfer")
        intent = build_warp_bridge_intent(
            descriptor=descriptor,
            direction=body.direction,
            amount_mojos=body.amountMojos,
            destination=body.destination,
        )
        response = _capability_intent_response(
            deployment_binding={"environment": evidence.environment, "deploymentId": evidence.deployment_id, "releaseTag": evidence.release_tag, "sourceSha": evidence.source_sha, "sourceAccount": session.owner_key},
            network=settings.network,
            vault_launcher_id=session.vault_launcher_id,
            capability="warp-cat-bridge",
            governed_root=str(statutes["routesRoot"]),
            confirmed_height=int(statutes["confirmedHeight"]),
            evidence_sha256=evidence.sha256,
            governed_record=record,
            intent=intent,
            decision_receipt={
                "title": (
                    "Bridge Sols to an EVM wallet"
                    if body.direction == "CHIA_TO_EVM"
                    else "Return wSOLS to a Chia wallet"
                ),
                "amountMojos": body.amountMojos,
                "destination": intent["destination"],
                "reversible": False,
                "customerImpact": (
                    "The selected amount leaves this chain and becomes the "
                    "corresponding asset after the disclosed bridge tip on the destination chain."
                ),
            },
        )
        store = CapabilityOperationStore(settings.sols_capability_operations_path)
        try:
            store.prepare(response)
        finally:
            store.close()
        return response
    except HTTPException:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        SolsCapabilityAdapterError,
        SolsCapabilityEvidenceError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Bridge intent is not ready: {exc}",
        ) from exc


@router.post("/liquidity-intents")
async def create_liquidity_intent(
    body: LiquidityIntentRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    session = verify_vault_session(settings, request, body.vaultLauncherId)
    require_current_approved_vault(settings, session.vault_launcher_id)
    try:
        statutes, records, evidence = await _execution_context(
            settings=settings,
            reader=reader,
            capability="governed-liquidity",
            records_key="liquidityVenues",
            root_key="liquidityRoot",
            feature_enabled=settings.sols_liquidity_enabled,
            evidence_path=settings.sols_liquidity_release_evidence_path,
            evidence_sha256=settings.sols_liquidity_release_evidence_sha256,
            execution_surface_installed=LIQUIDITY_EXECUTION_SURFACE_INSTALLED,
            installed_adapter_kinds=LIQUIDITY_INSTALLED_ADAPTERS,
        )
        record = _active_record(records, "venueId", body.venueId)
        descriptor = descriptor_for_record(
            evidence.adapter_descriptors,
            record_id=body.venueId,
        )
        kind = descriptor.get("kind")
        if kind == "AERODROME_V1":
            if body.account is None:
                raise SolsCapabilityAdapterError(
                    "an EVM receiving account is required"
                )
            intent = build_aerodrome_liquidity_intent(
                descriptor=descriptor,
                action=body.action,
                account=body.account,
                amount_a=body.amountA,
                amount_b=body.amountB,
                liquidity=body.liquidity,
                min_a=body.minimumA,
                min_b=body.minimumB,
                deadline_seconds=body.deadlineSeconds,
            )
        elif kind == "UNISWAP_V3":
            if body.account is None:
                raise SolsCapabilityAdapterError(
                    "an EVM receiving account is required"
                )
            intent = build_uniswap_v3_liquidity_intent(
                descriptor=descriptor,
                action=body.action,
                account=body.account,
                amount_a=body.amountA,
                amount_b=body.amountB,
                liquidity=body.liquidity,
                min_a=body.minimumA,
                min_b=body.minimumB,
                token_id=body.tokenId,
                tick_lower=body.tickLower,
                tick_upper=body.tickUpper,
                deadline_seconds=body.deadlineSeconds,
            )
        elif kind == "TIBETSWAP_V2":
            intent = build_tibetswap_liquidity_intent(
                descriptor=descriptor,
                action=body.action,
                amount_xch_mojos=body.amountA,
                amount_cat_mojos=body.amountB,
                liquidity_mojos=body.liquidity,
            )
        else:
            raise SolsCapabilityAdapterError(
                "the governed venue has no reviewed native adapter"
            )
        response = _capability_intent_response(
            deployment_binding={"environment": evidence.environment, "deploymentId": evidence.deployment_id, "releaseTag": evidence.release_tag, "sourceSha": evidence.source_sha, "sourceAccount": session.owner_key},
            network=settings.network,
            vault_launcher_id=session.vault_launcher_id,
            capability="governed-liquidity",
            governed_root=str(statutes["liquidityRoot"]),
            confirmed_height=int(statutes["confirmedHeight"]),
            evidence_sha256=evidence.sha256,
            governed_record=record,
            intent=intent,
            decision_receipt={
                "title": f"{body.action.title()} governed liquidity",
                "amountA": body.amountA,
                "amountB": body.amountB,
                "liquidity": body.liquidity,
                "minimumA": body.minimumA,
                "minimumB": body.minimumB,
                "reversible": False,
                "customerImpact": (
                    "This changes a liquidity position at the exact venue "
                    "approved in protocol statutes."
                ),
            },
        )
        store = CapabilityOperationStore(settings.sols_capability_operations_path)
        try:
            store.prepare(response)
        finally:
            store.close()
        return response
    except HTTPException:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        SolsCapabilityAdapterError,
        SolsCapabilityEvidenceError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Liquidity intent is not ready: {exc}",
        ) from exc


async def _execution_context(
    *,
    settings: Settings,
    reader: SolsMarketReader,
    capability: Literal["warp-cat-bridge", "governed-liquidity"],
    records_key: Literal["bridgeRoutes", "liquidityVenues"],
    root_key: Literal["routesRoot", "liquidityRoot"],
    feature_enabled: bool,
    evidence_path: str | None,
    evidence_sha256: str | None,
    execution_surface_installed: bool,
    installed_adapter_kinds: frozenset[str],
    confirmation_observer_installed: bool | None = None,
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]], Any]:
    snapshot = await reader.snapshot()
    statutes = snapshot.get("statutes")
    if not isinstance(statutes, Mapping):
        raise SolsCapabilityAdapterError("governed statutes are not confirmed")
    raw_records = statutes.get(records_key)
    if not isinstance(raw_records, list):
        raise SolsCapabilityAdapterError("governed records are unavailable")
    records = [value for value in raw_records if isinstance(value, Mapping)]
    checks, _ = _capability_checks(
        settings=settings,
        capability=capability,
        governed_root=str(statutes[root_key]),
        governed_records=records,
        governed_active=any(bool(value.get("active")) for value in records),
        feature_enabled=feature_enabled,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
        execution_surface_installed=execution_surface_installed,
        installed_adapter_kinds=installed_adapter_kinds,
        confirmation_observer_installed=confirmation_observer_installed,
    )
    if any(value["status"] != "READY" for value in checks):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": _first_incomplete_detail(checks),
                "readiness": checks,
            },
        )
    evidence = load_sols_capability_evidence(
        path_value=evidence_path,
        expected_sha256=evidence_sha256,
        capability=capability,
        **settings.capability_evidence_binding(),
        governed_root=str(statutes[root_key]),
        governed_records=records,
    )
    return statutes, records, evidence


def _active_record(
    records: list[Mapping[str, Any]],
    key: Literal["routeId", "venueId"],
    selected_id: str,
) -> Mapping[str, Any]:
    matches = [
        value
        for value in records
        if str(value.get(key, "")).lower() == selected_id.lower()
    ]
    if len(matches) != 1:
        raise SolsCapabilityAdapterError("governed record was not found")
    if not bool(matches[0].get("active")):
        raise SolsCapabilityAdapterError("governed record is not active")
    return matches[0]


def _capability_intent_response(
    *,
    network: str,
    vault_launcher_id: str,
    capability: str,
    governed_root: str,
    confirmed_height: int,
    evidence_sha256: str,
    governed_record: Mapping[str, Any],
    intent: Mapping[str, Any],
    decision_receipt: Mapping[str, Any],
    deployment_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    binding = {
        **dict(deployment_binding or {}),
        "network": network,
        "vaultLauncherId": vault_launcher_id,
        "capability": capability,
        "governedRoot": governed_root,
        "confirmedHeight": confirmed_height,
        "releaseEvidenceSha256": evidence_sha256,
        "governedRecord": dict(governed_record),
        "intent": dict(intent),
    }
    operation_hash = "0x" + hashlib.sha256(
        json.dumps(
            binding,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return {
        "schemaVersion": 1,
        "operationHash": operation_hash,
        **binding,
        "decisionReceipt": {
            **dict(decision_receipt),
            "network": network,
            "wallet": vault_launcher_id,
            "operationHash": operation_hash,
        },
    }


def _locked_capability_view(
    network: str,
    collection_key: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "network": network,
        "mode": "PREVIEW",
        "executable": False,
        "activationState": "AWAITING_SIGNED_GENESIS",
        "reason": reason,
        "readiness": [
            {
                "id": "governance",
                "label": "Governed records",
                "status": "WAITING",
                "detail": reason,
            }
        ],
        collection_key: [],
        "source": "awaiting-signed-genesis",
        "confirmedHeight": None,
    }


def _capability_checks(
    *,
    settings: Settings,
    capability: Literal["warp-cat-bridge", "governed-liquidity"],
    governed_root: str,
    governed_records: list[Mapping[str, Any]],
    governed_active: bool,
    feature_enabled: bool,
    evidence_path: str | None,
    evidence_sha256: str | None,
    execution_surface_installed: bool,
    installed_adapter_kinds: frozenset[str],
    confirmation_observer_installed: bool | None = None,
) -> tuple[list[dict[str, str]], bool]:
    checks: list[dict[str, str]] = [
        _readiness(
            "governance",
            "Governed route or venue",
            "READY" if governed_active else "WAITING",
            (
                "An active record was reconstructed from protocol statutes."
                if governed_active
                else "An administrator proposal and SGT approval must activate a record."
            ),
        ),
        _readiness(
            "network",
            "Deployment network boundary",
            "READY" if settings.sols_capability_deployment_id else "WAITING",
            (
                "The configured deployment requires matching network-specific evidence."
                if settings.sols_capability_deployment_id
                else "A separate network-specific capability deployment must be pinned."
            ),
        ),
    ]

    evidence_ready = False
    loaded_evidence: SolsCapabilityEvidence | None = None
    evidence_detail = "Checksum-pinned reviewed release evidence is not configured."
    if evidence_path or evidence_sha256:
        try:
            loaded_evidence = load_sols_capability_evidence(
                path_value=evidence_path,
                expected_sha256=evidence_sha256,
                capability=capability,
                **settings.capability_evidence_binding(),
                governed_root=governed_root,
                governed_records=governed_records,
            )
            evidence_ready = True
            evidence_detail = (
                "Release evidence matches the current statutes root and exact records."
            )
        except SolsCapabilityEvidenceError as exc:
            evidence_detail = str(exc)
    checks.append(
        _readiness(
            "releaseEvidence",
            "Reviewed release evidence",
            "READY" if evidence_ready else "WAITING",
            evidence_detail,
        )
    )
    adapter_ready = execution_surface_installed
    adapter_detail = (
        "The reviewed transaction surface is installed in this release."
        if execution_surface_installed
        else (
            "This release has no customer transaction builder for the "
            "approved route or venue yet."
        )
    )
    if adapter_ready and loaded_evidence is not None:
        adapter_ready, adapter_detail = _active_adapter_coverage(
            governed_records=governed_records,
            evidence=loaded_evidence,
            installed_adapter_kinds=installed_adapter_kinds,
        )
    checks.extend(
        [
            _readiness(
                "adapter",
                "Transaction adapter",
                "READY" if adapter_ready else "WAITING",
                adapter_detail,
            ),
        ]
    )
    if confirmation_observer_installed is not None:
        checks.append(
            _readiness(
                "confirmationObserver",
                "Transfer confirmation",
                "READY" if confirmation_observer_installed else "WAITING",
                (
                    "Destination completion is observed and resumable in Solslot."
                    if confirmation_observer_installed
                    else (
                        "Official Warp initiation is wired, but Solslot does not "
                        "yet have a reviewed watcher contract for pending, relayed, "
                        "and completed transfers."
                    )
                ),
            )
        )
    checks.append(
        _readiness(
            "operatorGate",
            "Runtime activation",
            "READY" if feature_enabled and settings.alpha_writes_enabled else "WAITING",
            (
                "The network-specific runtime gate is enabled."
                if feature_enabled and settings.alpha_writes_enabled
                else "The operator gate remains safely disabled."
            ),
        )
    )
    return checks, evidence_ready


def _active_adapter_coverage(
    *,
    governed_records: list[Mapping[str, Any]],
    evidence: SolsCapabilityEvidence,
    installed_adapter_kinds: frozenset[str],
) -> tuple[bool, str]:
    active_ids = {
        str(record.get("routeId") or record.get("venueId") or "").lower()
        for record in governed_records
        if bool(record.get("active"))
    }
    descriptors_by_record = {
        str(descriptor.get("recordId", "")).lower(): descriptor
        for descriptor in evidence.adapter_descriptors
    }
    missing = sorted(active_ids - descriptors_by_record.keys())
    unsupported = sorted(
        {
            str(descriptors_by_record[record_id].get("kind") or "UNKNOWN")
            for record_id in active_ids
            if record_id in descriptors_by_record
            and descriptors_by_record[record_id].get("kind")
            not in installed_adapter_kinds
        }
    )
    if missing:
        return (
            False,
            "An active governed record has no evidence-bound customer adapter.",
        )
    if unsupported:
        return (
            False,
            "Active governed adapter execution is not installed: "
            + ", ".join(unsupported)
            + ".",
        )
    return (
        True,
        "Every active governed record has an evidence-bound customer executor.",
    )


def _capability_profiles(
    *,
    settings: Settings,
    evidence_ready: bool,
    capability: Literal["warp-cat-bridge", "governed-liquidity"],
    governed_root: str,
    governed_records: list[Mapping[str, Any]],
    evidence_path: str | None,
    evidence_sha256: str | None,
    record_key: Literal["routeId", "venueId"],
) -> dict[str, dict[str, Any]]:
    if not evidence_ready:
        return {}
    evidence = load_sols_capability_evidence(
        path_value=evidence_path,
        expected_sha256=evidence_sha256,
        capability=capability,
        **settings.capability_evidence_binding(),
        governed_root=governed_root,
        governed_records=governed_records,
    )
    return {
        str(descriptor["recordId"]).lower(): public_adapter_profile(descriptor)
        for descriptor in evidence.adapter_descriptors
        if str(descriptor.get("recordId", "")).lower()
        in {
            str(record.get(record_key, "")).lower()
            for record in governed_records
        }
    }


def _readiness(
    check_id: str,
    label: str,
    status_value: str,
    detail: str,
) -> dict[str, str]:
    return {
        "id": check_id,
        "label": label,
        "status": status_value,
        "detail": detail,
    }


def _first_incomplete_detail(checks: list[dict[str, str]]) -> str:
    for item in checks:
        if item["status"] != "READY":
            return item["detail"]
    return "Capability activation is pending."


def _activation_state(
    network: str,
    executable: bool,
    checks: list[dict[str, str]],
) -> str:
    if executable:
        return "LIVE"
    readiness = {item["id"]: item["status"] for item in checks}
    if readiness.get("governance") != "READY":
        return "AWAITING_GOVERNANCE"
    if readiness.get("releaseEvidence") != "READY":
        return "AWAITING_RELEASE_EVIDENCE"
    if readiness.get("adapter") != "READY":
        return "AWAITING_EXECUTION_SURFACE"
    if readiness.get("confirmationObserver", "READY") != "READY":
        return "AWAITING_CONFIRMATION_OBSERVER"
    if readiness.get("operatorGate") != "READY":
        return "READY_DISABLED"
    return "BLOCKED"


@router.get("/vaults/{vault_launcher_id}/opportunities")
async def vault_sols_opportunities(
    vault_launcher_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    reader: Annotated[SolsMarketReader, Depends(_reader)],
) -> dict[str, Any]:
    session = verify_vault_session(settings, request, vault_launcher_id)
    approved = require_current_approved_vault(
        settings,
        session.vault_launcher_id,
    )
    try:
        snapshot = await reader.snapshot()
        balance = await reader.vault_sols_balance(
            approved.launcher_id,
        )
    except (
        ChiaProviderError,
        PublicArtifactError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SOLS vault verification failed closed: {exc}",
        ) from exc
    return {
        **snapshot,
        "vault": {
            "launcherId": approved.launcher_id,
            "eligible": True,
            "reason": None,
            "balanceSolsMojos": str(balance),
            "balanceCoverage": "VAULT_BOUND_CAT",
            "identityConfirmed": True,
        },
        "opportunities": [
            {
                **item,
                "affordable": balance >= int(item["totalSolsMojos"]),
            }
            for item in snapshot["opportunities"]
        ],
    }


__all__ = [
    "PoolDeed",
    "PoolState",
    "StatutesSnapshot",
    "SolsMarketReader",
    "router",
]


class CapabilityOperationHints(BaseModel):
    sourceTransactionId: str | None = Field(None, pattern=r"^0x[0-9a-fA-F]{64}$")
    destinationTransactionId: str | None = Field(None, pattern=r"^0x[0-9a-fA-F]{64}$")


@router.get("/vaults/{vault_launcher_id}/capability-operations")
async def list_capability_operations(vault_launcher_id: str, request: Request,
                                    settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    session = verify_vault_session(settings, request, vault_launcher_id)
    store = CapabilityOperationStore(settings.sols_capability_operations_path)
    try:
        operations = store.list_for_vault(session.vault_launcher_id)
        # Never mix deployment histories when a host is repointed.
        return {"operations": [op for op in operations if op["receipt"].get("network") == settings.network
                and op["receipt"].get("environment") == settings.runtime_environment
                and op["receipt"].get("deploymentId") == settings.sols_capability_deployment_id]}
    finally:
        store.close()


@router.post("/vaults/{vault_launcher_id}/capability-operations/{operation_hash}/observe")
async def observe_capability_operation(vault_launcher_id: str, operation_hash: str,
                                      body: CapabilityOperationHints, request: Request,
                                      settings: Annotated[Settings, Depends(get_settings)],
                                      reader: Annotated[SolsMarketReader, Depends(_reader)]) -> dict[str, Any]:
    """Persist discovery references; only re-fetched chain proof can complete.

    Recovery remains available with transaction flags disabled. This route has
    no signing/submission call and cannot spend customer or operator assets.
    """
    from web3 import AsyncWeb3, AsyncHTTPProvider
    from .sols_bridge_observer import WarpCatObserver
    session = verify_vault_session(settings, request, vault_launcher_id)
    store = CapabilityOperationStore(settings.sols_capability_operations_path)
    try:
        operation = store.get(operation_hash, session.vault_launcher_id)
        receipt = operation["receipt"]
        if receipt["capability"] != "warp-cat-bridge":
            raise ValueError("liquidity confirmation observer is not installed")
        evidence = load_sols_capability_evidence(
            path_value=settings.sols_bridge_release_evidence_path,
            expected_sha256=settings.sols_bridge_release_evidence_sha256,
            capability="warp-cat-bridge", **settings.capability_evidence_binding())
        if receipt["releaseEvidenceSha256"] != evidence.sha256 or receipt.get("deploymentId") != evidence.deployment_id or receipt.get("environment") != evidence.environment or receipt["network"] != evidence.network:
            raise ValueError("recovery requires the original deployment-bound release evidence")
        descriptor = descriptor_for_record(evidence.adapter_descriptors, record_id=receipt["governedRecord"]["routeId"])
        if not settings.sols_capability_evm_rpc_url or not settings.sols_capability_evm_rpc_url.startswith("https://"):
            raise ValueError("the dedicated customer bridge RPC is not configured")
        hints = body.model_dump(exclude_none=True)
        if hints:
            operation = store.record_hints(operation_hash, session.vault_launcher_id, hints)
        provider = AsyncHTTPProvider(settings.sols_capability_evm_rpc_url, request_kwargs={"timeout": 15})
        try:
            try:
                observation = await WarpCatObserver(AsyncWeb3(provider), reader.provider).observe(receipt, descriptor, operation["hints"])
            except Exception:
                # Provider outages and conflicting chain evidence invalidate
                # fresh completion. Never retry a spend to resolve uncertainty.
                observation = {"operationHash": operation_hash, "status": "RECOVERY_REQUIRED", "detail": "Both-chain confirmation is unavailable or inconsistent; inspect the saved transaction references before retrying observation."}
        finally:
            await provider.disconnect()
        return store.record_observation(operation_hash, session.vault_launcher_id, observation)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Capability operation or reviewed proof is unavailable.") from exc
    except (ValueError, CapabilityOperationConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        store.close()


@router.post("/vaults/{vault_launcher_id}/capability-operations/{operation_hash}/references")
async def record_capability_references(vault_launcher_id: str, operation_hash: str,
                                      body: CapabilityOperationHints, request: Request,
                                      settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    session = verify_vault_session(settings, request, vault_launcher_id)
    store = CapabilityOperationStore(settings.sols_capability_operations_path)
    try:
        operation = store.get(operation_hash, session.vault_launcher_id)
        receipt = operation["receipt"]
        if receipt.get("environment") != settings.runtime_environment or receipt["network"] != settings.network or receipt.get("deploymentId") != settings.sols_capability_deployment_id:
            raise ValueError("operation belongs to another deployment")
        return store.record_hints(operation_hash, session.vault_launcher_id, body.model_dump(exclude_none=True))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Capability operation not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        store.close()


@router.post("/vaults/{vault_launcher_id}/capability-operations/{operation_hash}/authorize")
async def authorize_capability_operation(vault_launcher_id: str, operation_hash: str,
                                         request: Request,
                                         settings: Annotated[Settings, Depends(get_settings)],
                                         reader: Annotated[SolsMarketReader, Depends(_reader)]) -> dict[str, Any]:
    """Revalidate a freshly prepared action; saved receipts grant no authority.

    Observation endpoints deliberately remain usable with writes disabled.
    Execution authorization must pass the current vault, deployment, evidence,
    governance and runtime gates each time it is requested.
    """
    session = verify_vault_session(settings, request, vault_launcher_id)
    require_current_approved_vault(settings, session.vault_launcher_id)
    store = CapabilityOperationStore(settings.sols_capability_operations_path)
    try:
        operation = store.get(operation_hash, session.vault_launcher_id)
        receipt = operation["receipt"]
        if operation["status"] != "PREPARED" or operation["hints"]:
            raise ValueError("saved or submitted operation is observation-only; prepare a new action")
        bridge = receipt["capability"] == "warp-cat-bridge"
        if not bridge and receipt["capability"] != "governed-liquidity":
            raise ValueError("unsupported capability")
        statutes, records, evidence = await _execution_context(
            settings=settings, reader=reader, capability=receipt["capability"],
            records_key="bridgeRoutes" if bridge else "liquidityVenues",
            root_key="routesRoot" if bridge else "liquidityRoot",
            feature_enabled=settings.sols_bridge_enabled if bridge else settings.sols_liquidity_enabled,
            evidence_path=settings.sols_bridge_release_evidence_path if bridge else settings.sols_liquidity_release_evidence_path,
            evidence_sha256=settings.sols_bridge_release_evidence_sha256 if bridge else settings.sols_liquidity_release_evidence_sha256,
            execution_surface_installed=WARP_CAT_EXECUTION_SURFACE_INSTALLED if bridge else LIQUIDITY_EXECUTION_SURFACE_INSTALLED,
            installed_adapter_kinds=WARP_CAT_INSTALLED_ADAPTERS if bridge else LIQUIDITY_INSTALLED_ADAPTERS,
            confirmation_observer_installed=WARP_CAT_CONFIRMATION_OBSERVER_INSTALLED if bridge else None,
        )
        record_key = "routeId" if bridge else "venueId"
        record = _active_record(records, record_key, receipt["governedRecord"][record_key])
        if dict(record) != receipt["governedRecord"] or str(statutes["routesRoot" if bridge else "liquidityRoot"]) != receipt["governedRoot"]:
            raise ValueError("governed record or root changed after preparation")
        if receipt.get("environment") != settings.runtime_environment or receipt["network"] != settings.network or receipt.get("deploymentId") != evidence.deployment_id or receipt["releaseEvidenceSha256"] != evidence.sha256 or receipt.get("sourceSha") != evidence.source_sha or receipt.get("releaseTag") != evidence.release_tag:
            raise ValueError("deployment or reviewed release changed after preparation")
        if receipt.get("sourceAccount", "").lower() != session.owner_key.lower():
            raise ValueError("prepared source account no longer matches the vault owner")
        return {"executable": True, "operationHash": operation_hash,
                "releaseEvidenceSha256": evidence.sha256, "governedRoot": receipt["governedRoot"],
                "recordId": record[record_key], "network": settings.network,
                "environment": settings.runtime_environment, "deploymentId": evidence.deployment_id}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Capability operation or current governed record is unavailable.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        store.close()
