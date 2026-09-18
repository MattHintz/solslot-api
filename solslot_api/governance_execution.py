"""Chain-authoritative execution for governed SGT sale and grant proposals."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    construct_cat_puzzle,
    get_innerpuzzle_from_puzzle,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.util.compute_additions import compute_additions
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    TRK_EXECUTE,
    TRK_EXPIRE,
    TRK_PROPOSE,
    TRK_VOTE,
    build_sgt_lock_coin_spend,
    build_tracker_execute_coin_spend,
    build_tracker_vote_coin_spend,
    proposal_tracker_v2_inner_puzzle,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
    sgt_locked_inner_puzzle,
    tracker_propose_policy_from_spend,
)
from solslot_puzzles.sgt_reserve_driver import (
    build_reserve_execute_spends,
    build_reserve_allocation_spend,
    build_reserve_release_spend,
    sgt_reserve_inner_puzzle,
)
from solslot_puzzles.funded_redemption_v1 import (
    FundedRedemptionAllocation,
    FundedRedemptionPlanV1,
)
from solslot_puzzles.redemption_treasury_v1 import (
    fund_redemption_leaves,
    redemption_treasury_inner_puzzle,
    redemption_treasury_puzzle,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    one_leaf_merkle_root,
    puzzle_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    build_vault_sgt_lock_spend,
    eip712_typed_data_for_sgt_lock,
    inner_solution_for_p2_vault_sgt_lock,
    puzzle_for_vault_v2_inner,
    sgt_lock_operation_hash,
)

from .admin_key_changes import _verified_evidence_context
from .credential_auth import require_vault_record
from .funded_redemption_store import get_funded_redemption_store
from .governance_queue import GovernanceQueueRecord
from .sols_swaps import _confirmed_cat_lineage, _confirmed_coin_and_lineage
from .vault_eligibility import ApprovedVault, require_current_approved_vault


_MAX_DEPTH = 4096


@dataclass(frozen=True)
class AllocationChainState:
    state: str
    current_coin: Coin | None = None
    current_coin_id: str | None = None
    confirmed_height: int | None = None
    vote_tally: int | None = None
    first_vote_amount: int | None = None
    voting_deadline: int | None = None
    proposal_parameters: tuple[int, ...] | None = None


@dataclass(frozen=True)
class AllocationExecutionBuild:
    chain: AllocationChainState
    bundle: SpendBundle | None
    locked_reserve_coin_id: str | None
    expected_output_coin_ids: tuple[str, ...]
    blocker: str | None = None


@dataclass(frozen=True)
class AllocationVoteBuild:
    chain: AllocationChainState
    bundle: SpendBundle
    operation_hash: bytes32
    proposal_hash: bytes32
    vault_launcher_id: bytes32
    vault_coin_id: bytes32
    vault_auth_type: str
    vault_typed_data: dict[str, Any] | None
    sgt_coin_id: bytes32
    sgt_amount: int
    available_sgt_amounts: tuple[int, ...]
    locked_inner_puzzle_hash: bytes32
    approved_vault: ApprovedVault


def _hex32(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _b32(value: object, label: str) -> bytes32:
    try:
        raw = bytes.fromhex(str(value).lower().removeprefix("0x"))
    except ValueError as exc:
        raise ValueError(f"{label} must be 32-byte hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32-byte hex")
    return bytes32(raw)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"signed artifact {label} is unavailable")
    return value


def _coin(record: Mapping[str, Any]) -> Coin | None:
    payload = record.get("coin")
    if not isinstance(payload, Mapping):
        return None
    try:
        return Coin(
            _b32(payload.get("parent_coin_info"), "coin parent"),
            _b32(payload.get("puzzle_hash"), "coin puzzle hash"),
            uint64(int(payload.get("amount"))),
        )
    except (TypeError, ValueError):
        return None


def _program(value: object, label: str) -> Program:
    try:
        return Program.from_bytes(bytes.fromhex(str(value).removeprefix("0x")))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is malformed") from exc


def _funded_redemption_plan(record: GovernanceQueueRecord) -> FundedRedemptionPlanV1:
    if record.kind != "FUNDED_REDEMPTION":
        raise ValueError("proposal is not a funded redemption")
    allocations_value = record.bill.get("allocations")
    if not isinstance(allocations_value, list):
        raise ValueError("funded redemption allocations are unavailable")
    allocations = tuple(
        FundedRedemptionAllocation(
            deed_launcher_id=_b32(item.get("deedLauncherId"), "deed launcher ID"),
            deed_commitment=_b32(item.get("deedCommitment"), "deed commitment"),
            share_ppm=int(item.get("sharePpm")),
            payment_amount=int(item.get("paymentAmount")),
        )
        for item in allocations_value
        if isinstance(item, Mapping)
    )
    if len(allocations) != len(allocations_value):
        raise ValueError("funded redemption allocation is malformed")
    return FundedRedemptionPlanV1(
        collection_id=_b32(record.bill.get("collectionId"), "collection ID"),
        settlement_id=_b32(record.bill.get("settlementId"), "settlement ID"),
        payment_asset_id=_b32(record.bill.get("paymentAssetId"), "payment asset ID"),
        total_payment_amount=int(record.bill.get("totalPaymentAmount")),
        allocations=allocations,
    ).validate()


def _tracker_solution(value: Mapping[str, Any]) -> tuple[int, list[Program]]:
    outer = list(_program(value.get("solution"), "tracker solution").as_iter())
    if len(outer) != 3:
        raise ValueError("governance tracker singleton solution is malformed")
    inner = list(outer[2].as_iter())
    if len(inner) != 5:
        raise ValueError("governance tracker inner solution is malformed")
    return inner[3].as_int(), list(inner[4].as_iter())


async def trace_allocation_proposal(
    *,
    provider: Any,
    proposal_coin_id: str,
    proposal_hash: bytes32,
    bill: Program,
    quorum_bps: int,
    total_supply: int,
    now: int | None = None,
) -> AllocationChainState:
    initial_record = await provider.get_coin_record_by_name(proposal_coin_id)
    if not isinstance(initial_record, Mapping):
        return AllocationChainState(state="MEMPOOL_OR_WAITING")
    initial_coin = _coin(initial_record)
    if initial_coin is None:
        raise ValueError("proposal tracker coin record is malformed")

    parent_record = await provider.get_coin_record_by_name(
        _hex32(initial_coin.parent_coin_info)
    )
    if not isinstance(parent_record, Mapping):
        raise ValueError("proposal tracker parent is unavailable")
    parent_height = int(parent_record.get("spent_block_index") or 0)
    if parent_height <= 0:
        raise ValueError("proposal tracker publication is not confirmed")
    parent_solution = await provider.get_puzzle_and_solution(
        _hex32(initial_coin.parent_coin_info), parent_height
    )
    if not isinstance(parent_solution, Mapping):
        raise ValueError("proposal tracker publication evidence is unavailable")
    dispatcher, params = _tracker_solution(parent_solution)
    if dispatcher != TRK_PROPOSE:
        raise ValueError("proposal tracker did not enter through PROPOSE")
    proposal_parameters = tracker_propose_policy_from_spend(
        _program(parent_solution.get("puzzle_reveal"), "tracker puzzle"), params,
    )
    if proposal_parameters is not None:
        quorum_bps = proposal_parameters[1]
    if bytes32(params[0].as_atom()) != proposal_hash:
        raise ValueError("proposal tracker hash does not match the queue")
    if bytes32(params[1].get_tree_hash()) != bytes32(bill.get_tree_hash()):
        raise ValueError("proposal tracker bill does not match the queue")
    vote_tally = int(params[3].as_int())
    first_vote_amount = vote_tally
    deadline = int(params[4].as_int())
    if vote_tally <= 0 or deadline <= 0:
        raise ValueError("proposal tracker publication terms are invalid")

    current_coin = initial_coin
    current_record = initial_record
    for _depth in range(_MAX_DEPTH):
        spent_height = int(current_record.get("spent_block_index") or 0)
        if spent_height == 0:
            timestamp = int(time.time()) if now is None else now
            if timestamp < deadline:
                state = "VOTING"
            elif vote_tally * 10_000 >= quorum_bps * total_supply:
                state = "AWAITING_EXECUTE"
            else:
                state = "AWAITING_EXPIRE"
            return AllocationChainState(
                state=state,
                current_coin=current_coin,
                current_coin_id=_hex32(current_coin.name()),
                confirmed_height=int(current_record.get("confirmed_block_index") or 0),
                vote_tally=vote_tally,
                first_vote_amount=first_vote_amount,
                voting_deadline=deadline,
                proposal_parameters=proposal_parameters,
            )
        solution = await provider.get_puzzle_and_solution(
            _hex32(current_coin.name()), spent_height
        )
        if not isinstance(solution, Mapping):
            raise ValueError("confirmed governance spend evidence is unavailable")
        dispatcher, params = _tracker_solution(solution)
        if dispatcher == TRK_EXECUTE:
            return AllocationChainState(
                state="EXECUTED",
                current_coin_id=_hex32(current_coin.name()),
                confirmed_height=spent_height,
                vote_tally=vote_tally,
                first_vote_amount=first_vote_amount,
                voting_deadline=deadline,
                proposal_parameters=proposal_parameters,
            )
        if dispatcher == TRK_EXPIRE:
            return AllocationChainState(
                state="FAILED",
                current_coin_id=_hex32(current_coin.name()),
                confirmed_height=spent_height,
                vote_tally=vote_tally,
                first_vote_amount=first_vote_amount,
                voting_deadline=deadline,
                proposal_parameters=proposal_parameters,
            )
        if dispatcher != TRK_VOTE or len(params) != 2:
            raise ValueError("governance proposal used an unexpected transition")
        additional = int(params[1].as_int())
        if additional <= 0:
            raise ValueError("governance vote amount is invalid")
        vote_tally += additional
        children = await provider.get_coin_records_by_parent_ids(
            [_hex32(current_coin.name())], include_spent=True
        )
        candidates = [
            child_coin
            for child in children
            if isinstance(child, Mapping)
            and (child_coin := _coin(child)) is not None
            and int(child_coin.amount) == int(current_coin.amount)
        ]
        if len(candidates) != 1:
            raise ValueError("governance tracker continuation is missing or ambiguous")
        current_coin = candidates[0]
        next_record = await provider.get_coin_record_by_name(_hex32(current_coin.name()))
        if not isinstance(next_record, Mapping):
            raise ValueError("governance tracker continuation is unavailable")
        current_record = next_record
    raise ValueError("governance tracker lineage exceeds the safety limit")


async def build_allocation_execution(
    *,
    record: GovernanceQueueRecord,
    request: Any,
    settings: Any,
    now: int | None = None,
) -> AllocationExecutionBuild:
    if record.state != "ACTIVE" or record.proposal_coin_id is None:
        raise ValueError("proposal must be active before execution")
    provider = getattr(request.app.state, "coinset", None)
    if provider is None:
        raise ValueError("Testnet11 Chia provider is unavailable")
    artifact, _evidence, _coordinator = await _verified_evidence_context(settings)
    plan = _mapping(artifact.get("genesisPlan", artifact), "genesisPlan")
    launchers = _mapping(plan.get("launcherIds"), "launcherIds")
    puzzles = _mapping(plan.get("puzzleHashes"), "puzzleHashes")
    parameters = _mapping(plan.get("protocolParameters"), "protocolParameters")
    governance = _mapping(artifact.get("governanceStruct"), "governanceStruct")
    tracker_launcher = _b32(launchers.get("governance"), "governance launcher")
    admin_launcher = _b32(launchers.get("adminAuthority"), "authority launcher")
    pool_launcher = _b32(launchers.get("pool"), "pool launcher")
    statutes_launcher = _b32(launchers.get("statutes"), "statutes launcher")
    sgt_tail = _b32(
        artifact.get("sgtTailHash")
        or _mapping(plan.get("permanentRules"), "permanentRules").get("sgtTailHash"),
        "SGT tail hash",
    )
    treasury = _b32(
        _mapping(plan.get("trustedDestinations"), "trustedDestinations").get(
            "companySgtSaleTreasuryPuzzleHash"
        ),
        "company SGT treasury",
    )
    bill = _program(record.bill_clvm_hex, "queued governance bill")
    proposal_hash = bytes32(bill.get_tree_hash())
    if _hex32(proposal_hash) != record.proposal_hash.lower():
        raise ValueError("queued proposal hash does not match its bill")
    quorum_bps = int(parameters.get("quorumBps"))
    total_supply = int(parameters.get("sgtTotalSupply"))
    chain = await trace_allocation_proposal(
        provider=provider,
        proposal_coin_id=record.proposal_coin_id,
        proposal_hash=proposal_hash,
        bill=bill,
        quorum_bps=quorum_bps,
        total_supply=total_supply,
        now=now,
    )
    if chain.state != "AWAITING_EXECUTE":
        return AllocationExecutionBuild(chain, None, None, ())
    if (
        chain.current_coin is None
        or chain.vote_tally is None
        or chain.first_vote_amount is None
        or chain.voting_deadline is None
    ):
        raise ValueError("executable governance tracker state is incomplete")

    tracker_struct = singleton_struct(tracker_launcher)
    tracker_inner = proposal_tracker_v2_inner_puzzle(
        tracker_struct,
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        bytes32(CAT_MOD.get_tree_hash()),
        sgt_tail,
        _b32(puzzles.get("didFull"), "DID full puzzle hash"),
        singleton_struct(pool_launcher),
        singleton_struct(admin_launcher),
        singleton_struct(statutes_launcher),
        chain.proposal_parameters[1] if chain.proposal_parameters else quorum_bps,
        chain.proposal_parameters[0] if chain.proposal_parameters else int(parameters.get("votingWindowSeconds")),
        total_supply,
        chain.proposal_parameters[2] if chain.proposal_parameters else int(parameters.get("minProposalStake")),
        bytes.fromhex(str(governance.get("mintExecuteCosignerPubkey")).removeprefix("0x")),
        proposal_hash,
        bill,
        chain.vote_tally,
        chain.voting_deadline,
    )
    expected_tracker_full = puzzle_for_singleton(tracker_launcher, tracker_inner)
    if bytes32(expected_tracker_full.get_tree_hash()) != chain.current_coin.puzzle_hash:
        raise ValueError("reconstructed governance tracker does not match chain")
    tracker_parent_record = await provider.get_coin_record_by_name(
        _hex32(chain.current_coin.parent_coin_info)
    )
    tracker_parent_height = int((tracker_parent_record or {}).get("spent_block_index") or 0)
    if tracker_parent_height <= 0:
        raise ValueError("governance tracker lineage is not confirmed")
    tracker_parent_payload = await provider.get_puzzle_and_solution(
        _hex32(chain.current_coin.parent_coin_info), tracker_parent_height
    )
    tracker_parent_coin = (
        _coin(tracker_parent_record)
        if isinstance(tracker_parent_record, Mapping)
        else None
    )
    if (
        tracker_parent_coin is None
        or not isinstance(tracker_parent_payload, Mapping)
    ):
        raise ValueError("governance tracker lineage evidence is unavailable")
    tracker_parent_spend = make_spend(
        tracker_parent_coin,
        _program(tracker_parent_payload.get("puzzle_reveal"), "tracker parent puzzle"),
        _program(tracker_parent_payload.get("solution"), "tracker parent solution"),
    )

    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=tracker_struct,
        admin_authority_struct=singleton_struct(admin_launcher),
        sgt_tail_hash=sgt_tail,
        wusdc_b_asset_id=_b32(
            _mapping(plan.get("trustedAssets"), "trustedAssets").get(
                "wusdcBAssetId"
            ),
            "trusted wUSDC.b asset ID",
        ),
        company_treasury_puzzle_hash=treasury,
    )
    reserve_inner_hash = bytes32(reserve_inner.get_tree_hash())
    if reserve_inner_hash != _b32(puzzles.get("sgtReserveInner"), "SGT reserve inner"):
        raise ValueError("SGT reserve does not match signed release evidence")
    bill_values = list(bill.as_iter())
    if len(bill_values) == 11 and bill_values[0].as_atom() == b"Y":
        reserve_commitment_index = 9
    elif len(bill_values) == 6 and bill_values[0].as_atom() == b"G":
        reserve_commitment_index = 5
    elif len(bill_values) == 7 and bill_values[0].as_atom() == b"D":
        reserve_commitment_index = None
    else:
        raise ValueError("queued bill is not an exact allocation or funded redemption")
    if (
        reserve_commitment_index is not None
        and bytes32(bill_values[reserve_commitment_index].as_atom())
        != reserve_inner_hash
    ):
        raise ValueError("SGT bill is not bound to the canonical reserve")
    locked_inner = sgt_locked_inner_puzzle(
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        tracker_struct,
        reserve_inner_hash,
        proposal_hash,
        chain.voting_deadline,
    )
    locked_full = construct_cat_puzzle(CAT_MOD, sgt_tail, locked_inner)
    locked_records = await provider.get_coin_records_by_puzzle_hash(
        _hex32(locked_full.get_tree_hash()), include_spent=True
    )
    locked_candidates = [
        candidate
        for item in locked_records
        if isinstance(item, Mapping)
        and (candidate := _coin(item)) is not None
        and int(candidate.amount) == chain.first_vote_amount
    ]
    if len(locked_candidates) != 1:
        raise ValueError("locked company SGT reserve is missing or ambiguous")
    locked_coin = locked_candidates[0]
    locked_record = next(item for item in locked_records if _coin(item) == locked_coin)
    released_coin = None
    released_lineage = None
    released_height = int(locked_record.get("spent_block_index") or 0)
    if released_height:
        released_payload = await provider.get_puzzle_and_solution(_hex32(locked_coin.name()), released_height)
        if not isinstance(released_payload, Mapping):
            raise ValueError("SGT deadline release evidence is unavailable")
        release_puzzle = _program(released_payload.get("puzzle_reveal"), "SGT release puzzle")
        if release_puzzle != locked_full:
            raise ValueError("SGT release puzzle does not match the locked reserve")
        release_spend = make_spend(locked_coin, release_puzzle,
            _program(released_payload.get("solution"), "SGT release solution"))
        free_inner = sgt_free_inner_puzzle(sgt_locked_inner_mod().get_tree_hash(), tracker_struct, reserve_inner_hash)
        expected = Coin(locked_coin.name(), construct_cat_puzzle(CAT_MOD, sgt_tail, free_inner).get_tree_hash(), locked_coin.amount)
        if expected not in compute_additions(release_spend):
            raise ValueError("SGT release did not return the exact reserve")
        returned = await provider.get_coin_record_by_name(_hex32(expected.name()))
        if (not isinstance(returned, Mapping) or _coin(returned) != expected
            or int(returned.get("spent_block_index") or 0)
            or int(returned.get("confirmed_block_index") or 0) != released_height):
            raise ValueError("returned SGT reserve is not confirmed and unspent")
        released_coin = expected
        released_lineage = LineageProof(locked_coin.parent_coin_info, locked_inner.get_tree_hash(), locked_coin.amount)
    reserve_parent_record = await provider.get_coin_record_by_name(
        _hex32(locked_coin.parent_coin_info)
    )
    reserve_parent_coin = (
        _coin(reserve_parent_record)
        if isinstance(reserve_parent_record, Mapping)
        else None
    )
    reserve_parent_height = int((reserve_parent_record or {}).get("spent_block_index") or 0)
    if reserve_parent_height <= 0:
        raise ValueError("locked reserve lineage is not confirmed")
    reserve_parent_payload = await provider.get_puzzle_and_solution(
        _hex32(locked_coin.parent_coin_info), reserve_parent_height
    )
    if (
        reserve_parent_coin is None
        or not isinstance(reserve_parent_payload, Mapping)
    ):
        raise ValueError("locked reserve lineage evidence is unavailable")
    reserve_parent_puzzle = _program(
        reserve_parent_payload.get("puzzle_reveal"), "reserve parent puzzle"
    )
    reserve_parent_inner = get_innerpuzzle_from_puzzle(reserve_parent_puzzle)
    expected_reserve_free = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        reserve_inner_hash,
    )
    if bytes32(reserve_parent_inner.get_tree_hash()) != bytes32(
        expected_reserve_free.get_tree_hash()
    ):
        raise ValueError("locked reserve lineage changed owner")
    locked_lineage = LineageProof(
        parent_name=reserve_parent_coin.parent_coin_info,
        inner_puzzle_hash=bytes32(reserve_parent_inner.get_tree_hash()),
        amount=reserve_parent_coin.amount,
    )

    tracker_spend = build_tracker_execute_coin_spend(
        tracker_coin=chain.current_coin,
        tracker_inner_puzzle=tracker_inner,
        tracker_launcher_id=tracker_launcher,
        lineage_proof=lineage_proof_for_coinsol(tracker_parent_spend),
    )
    if record.kind == "FUNDED_REDEMPTION":
        redemption_plan = _funded_redemption_plan(record)
        trusted_wusdc = _b32(
            _mapping(plan.get("trustedAssets"), "trustedAssets").get(
                "wusdcBAssetId"
            ),
            "trusted wUSDC.b asset ID",
        )
        if redemption_plan.payment_asset_id != trusted_wusdc:
            raise ValueError("funded redemption does not use trusted wUSDC.b")
        if bytes32(bill.get_tree_hash()) != bytes32(
            Program.to(
                [
                    b"D",
                    redemption_plan.collection_id,
                    redemption_plan.settlement_id,
                    redemption_plan.payment_asset_id,
                    redemption_plan.total_payment_amount,
                    redemption_plan.deed_count,
                    redemption_plan.allocations_root,
                ]
            ).get_tree_hash()
        ):
            raise ValueError("funded redemption plan does not reproduce its bill")
        deed_launcher_hash = _b32(
            puzzles.get("deedLauncherPuzzleHash"),
            "deed launcher puzzle hash",
        )
        treasury_inner = redemption_treasury_inner_puzzle(
            governance_singleton_struct=tracker_struct,
            payment_asset_id=trusted_wusdc,
            deed_launcher_puzzle_hash=deed_launcher_hash,
        )
        treasury_full = redemption_treasury_puzzle(
            governance_singleton_struct=tracker_struct,
            payment_asset_id=trusted_wusdc,
            deed_launcher_puzzle_hash=deed_launcher_hash,
        )
        funding_store = get_funded_redemption_store(str(settings.admin_db_path))
        funding = funding_store.get_funding(record.id)
        if funding is None:
            return AllocationExecutionBuild(
                chain,
                None,
                _hex32(locked_coin.name()),
                (),
                "The approved settlement still needs its exact wUSDC.b funding output.",
            )
        if (
            funding.payment_asset_id.lower() != _hex32(trusted_wusdc)
            or int(funding.payment_amount) != redemption_plan.total_payment_amount
        ):
            raise ValueError("stored redemption funding changes the governed terms")
        treasury_record = await provider.get_coin_record_by_name(
            funding.expected_funding_coin_id
        )
        treasury_coin = (
            _coin(treasury_record)
            if isinstance(treasury_record, Mapping)
            else None
        )
        confirmed_height = int(
            (treasury_record or {}).get("confirmed_block_index") or 0
        )
        spent_height = int((treasury_record or {}).get("spent_block_index") or 0)
        if (
            treasury_coin is None
            or confirmed_height <= 0
            or spent_height != 0
        ):
            return AllocationExecutionBuild(
                chain,
                None,
                _hex32(locked_coin.name()),
                (),
                "The exact wUSDC.b funding transaction is waiting for confirmation.",
            )
        if (
            treasury_coin.puzzle_hash != treasury_full.get_tree_hash()
            or int(treasury_coin.amount) != redemption_plan.total_payment_amount
        ):
            raise ValueError("confirmed redemption funding output changed")
        if funding.status != "CONFIRMED":
            funding_store.mark_funding_confirmed(record.id, confirmed_height)
        treasury_lineage = await _confirmed_cat_lineage(
            provider=provider,
            coin=treasury_coin,
            expected_inner_hash=bytes32(treasury_inner.get_tree_hash()),
            expected_tail_hash=trusted_wusdc,
        )
        funded = fund_redemption_leaves(
            treasury_coin=treasury_coin,
            treasury_lineage_proof=treasury_lineage,
            governance_singleton_struct=tracker_struct,
            governance_inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
            plan=redemption_plan,
            deed_launcher_puzzle_hash=deed_launcher_hash,
        )
        reserve_release = None if released_coin is not None else build_reserve_release_spend(
            locked_reserve_coin=locked_coin,
            locked_reserve_lineage_proof=locked_lineage,
            proposal_tracker_struct=tracker_struct,
            reserve_owner_inner_hash=reserve_inner_hash,
            sgt_tail_hash=sgt_tail,
            bill=bill,
            voting_deadline=chain.voting_deadline,
            tracker_inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
        )
        bundle = SpendBundle(
            [tracker_spend, *([reserve_release] if reserve_release else []), *funded.spend_bundle.coin_spends],
            G2Element(),
        )
        return AllocationExecutionBuild(
            chain=chain,
            bundle=bundle,
            locked_reserve_coin_id=_hex32(locked_coin.name()),
            expected_output_coin_ids=tuple(
                _hex32(coin.name()) for coin in funded.leaf_coins
            ),
        )
    if released_coin is not None:
        allocation_spend = build_reserve_allocation_spend(
            reserve_coin=released_coin, reserve_lineage_proof=released_lineage,
            proposal_tracker_struct=tracker_struct, admin_authority_struct=singleton_struct(admin_launcher),
            sgt_tail_hash=sgt_tail,
            wusdc_b_asset_id=_b32(_mapping(plan.get("trustedAssets"), "trustedAssets").get("wusdcBAssetId"), "trusted wUSDC.b asset ID"),
            company_treasury_puzzle_hash=treasury, bill=bill,
            tracker_inner_puzzle_hash=tracker_inner.get_tree_hash())
        allocation_spends = [allocation_spend]
    else:
        allocation_spends = list(build_reserve_execute_spends(
        locked_reserve_coin=locked_coin,
        locked_reserve_lineage_proof=locked_lineage,
        proposal_tracker_struct=tracker_struct,
        admin_authority_struct=singleton_struct(admin_launcher),
        sgt_tail_hash=sgt_tail,
        wusdc_b_asset_id=_b32(
            _mapping(plan.get("trustedAssets"), "trustedAssets").get(
                "wusdcBAssetId"
            ),
            "trusted wUSDC.b asset ID",
        ),
        company_treasury_puzzle_hash=treasury,
        bill=bill,
        voting_deadline=chain.voting_deadline,
        tracker_inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
        ))
        allocation_spend = allocation_spends[-1]
    bundle = SpendBundle([tracker_spend, *allocation_spends], G2Element())
    outputs = tuple(
        sorted(
            _hex32(coin.name())
            for coin in bundle.additions()
            if coin.parent_coin_info == allocation_spend.coin.name()
        )
    )
    if len(outputs) not in (1, 2):
        raise ValueError("SGT allocation outputs are missing or ambiguous")
    return AllocationExecutionBuild(
        chain=chain,
        bundle=bundle,
        locked_reserve_coin_id=_hex32(locked_coin.name()),
        expected_output_coin_ids=outputs,
    )


async def build_allocation_vote(
    *,
    record: GovernanceQueueRecord,
    request: Any,
    settings: Any,
    vault_launcher_id: str,
    vote_amount: int,
    signature_data: bytes | None = None,
    now: int | None = None,
) -> AllocationVoteBuild:
    """Build one exact SGT vote from an approved protocol vault.

    The existing ``p2_vault`` remains the SGT owner. The vault singleton only
    authorizes the exact proposal-bound LOCK transition, while the existing SGT
    and tracker puzzles enforce conservation, deadline, and vote weight.
    """

    if record.state != "ACTIVE" or record.proposal_coin_id is None:
        raise ValueError("proposal must be active before voting")
    if vote_amount <= 0:
        raise ValueError("vote amount must be positive")
    provider = getattr(request.app.state, "coinset", None)
    if provider is None:
        raise ValueError("Testnet11 Chia provider is unavailable")

    artifact, _evidence, _coordinator = await _verified_evidence_context(settings)
    plan = _mapping(artifact.get("genesisPlan", artifact), "genesisPlan")
    launchers = _mapping(plan.get("launcherIds"), "launcherIds")
    puzzles = _mapping(plan.get("puzzleHashes"), "puzzleHashes")
    parameters = _mapping(plan.get("protocolParameters"), "protocolParameters")
    governance = _mapping(artifact.get("governanceStruct"), "governanceStruct")
    tracker_launcher = _b32(launchers.get("governance"), "governance launcher")
    admin_launcher = _b32(launchers.get("adminAuthority"), "authority launcher")
    pool_launcher = _b32(launchers.get("pool"), "pool launcher")
    statutes_launcher = _b32(launchers.get("statutes"), "statutes launcher")
    sgt_tail = _b32(
        artifact.get("sgtTailHash")
        or _mapping(plan.get("permanentRules"), "permanentRules").get(
            "sgtTailHash"
        ),
        "SGT tail hash",
    )
    bill = _program(record.bill_clvm_hex, "queued governance bill")
    proposal_hash = bytes32(bill.get_tree_hash())
    if _hex32(proposal_hash) != record.proposal_hash.lower():
        raise ValueError("queued proposal hash does not match its bill")
    quorum_bps = int(parameters.get("quorumBps"))
    total_supply = int(parameters.get("sgtTotalSupply"))
    chain = await trace_allocation_proposal(
        provider=provider,
        proposal_coin_id=record.proposal_coin_id,
        proposal_hash=proposal_hash,
        bill=bill,
        quorum_bps=quorum_bps,
        total_supply=total_supply,
        now=now,
    )
    if chain.state != "VOTING":
        raise ValueError(
            f"proposal is {chain.state.lower().replace('_', ' ')}"
        )
    if (
        chain.current_coin is None
        or chain.vote_tally is None
        or chain.voting_deadline is None
    ):
        raise ValueError("governance tracker voting state is incomplete")

    tracker_struct = singleton_struct(tracker_launcher)
    tracker_inner = proposal_tracker_v2_inner_puzzle(
        tracker_struct,
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        bytes32(CAT_MOD.get_tree_hash()),
        sgt_tail,
        _b32(puzzles.get("didFull"), "DID full puzzle hash"),
        singleton_struct(pool_launcher),
        singleton_struct(admin_launcher),
        singleton_struct(statutes_launcher),
        chain.proposal_parameters[1] if chain.proposal_parameters else quorum_bps,
        chain.proposal_parameters[0] if chain.proposal_parameters else int(parameters.get("votingWindowSeconds")),
        total_supply,
        chain.proposal_parameters[2] if chain.proposal_parameters else int(parameters.get("minProposalStake")),
        bytes.fromhex(
            str(governance.get("mintExecuteCosignerPubkey")).removeprefix("0x")
        ),
        proposal_hash,
        bill,
        chain.vote_tally,
        chain.voting_deadline,
    )
    tracker_full = puzzle_for_singleton(tracker_launcher, tracker_inner)
    if bytes32(tracker_full.get_tree_hash()) != chain.current_coin.puzzle_hash:
        raise ValueError("reconstructed governance tracker does not match chain")
    _tracker_coin, tracker_lineage = await _confirmed_coin_and_lineage(
        provider,
        _hex32(chain.current_coin.name()),
        "governance tracker coin",
    )

    approved = require_current_approved_vault(settings, vault_launcher_id)
    vault_record = require_vault_record(approved.launcher_id)
    if vault_record.auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise ValueError("vault owner authorization is unsupported")
    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        provider,
        approved.current_coin_id,
        "approved vault coin",
    )
    vault_launcher = _b32(approved.launcher_id, "approved vault launcher")
    owner_inner = puzzle_for_p2_vault(vault_launcher)
    owner_inner_hash = bytes32(owner_inner.get_tree_hash())
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        owner_inner_hash,
    )
    sgt_full = construct_cat_puzzle(CAT_MOD, sgt_tail, free_inner)
    records = await provider.get_coin_records_by_puzzle_hash(
        _hex32(sgt_full.get_tree_hash()), include_spent=False
    )
    candidates = sorted(
        [
            coin
            for item in records
            if isinstance(item, Mapping)
            and int(item.get("confirmed_block_index") or 0) > 0
            and int(item.get("spent_block_index") or 0) == 0
            and not bool(item.get("spent"))
            and (coin := _coin(item)) is not None
        ],
        key=lambda coin: (int(coin.amount), bytes(coin.name())),
    )
    available = tuple(int(coin.amount) for coin in candidates)
    matches = [coin for coin in candidates if int(coin.amount) == vote_amount]
    if not matches:
        readable = ", ".join(str(value) for value in available) or "none"
        raise ValueError(
            "vote amount must equal one vault-held SGT coin; "
            f"available amounts: {readable}"
        )
    sgt_coin = matches[0]
    if await provider.get_mempool_items_by_coin_name(_hex32(sgt_coin.name())):
        raise ValueError("the selected SGT vote is already pending in the mempool")
    sgt_lineage = await _confirmed_cat_lineage(
        provider=provider,
        coin=sgt_coin,
        expected_inner_hash=bytes32(free_inner.get_tree_hash()),
        expected_tail_hash=sgt_tail,
    )
    locked_inner = sgt_locked_inner_puzzle(
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        tracker_struct,
        owner_inner_hash,
        proposal_hash,
        chain.voting_deadline,
    )
    locked_inner_hash = bytes32(locked_inner.get_tree_hash())
    members_root = one_leaf_merkle_root(bytes(vault_record.owner_pubkey))
    policy_hash = _b32(
        settings.zkpassport_bridge_policy_hash,
        "zkPassport bridge policy hash",
    )
    vault_inner = puzzle_for_vault_v2_inner(
        vault_launcher_id=vault_launcher,
        owner_pubkey=bytes(vault_record.owner_pubkey),
        auth_type=vault_record.auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=pool_launcher,
        identity_attest_root=_b32(
            approved.identity_attest_root,
            "approved vault identity root",
        ),
        zkpassport_bridge_policy_hash=policy_hash,
    )
    vault_spend = build_vault_sgt_lock_spend(
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher,
        owner_pubkey=bytes(vault_record.owner_pubkey),
        auth_type=vault_record.auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=pool_launcher,
        identity_attest_root=_b32(
            approved.identity_attest_root,
            "approved vault identity root",
        ),
        zkpassport_bridge_policy_hash=policy_hash,
        sgt_coin_id=sgt_coin.name(),
        proposal_hash=proposal_hash,
        lock_deadline=chain.voting_deadline,
        locked_inner_puzzle_hash=locked_inner_hash,
        lineage_proof=vault_lineage,
        signature_data=signature_data,
    )
    owner_solution = inner_solution_for_p2_vault_sgt_lock(
        vault_coin_id=vault_coin.name(),
        vault_inner_puzzle_hash=bytes32(vault_inner.get_tree_hash()),
        sgt_coin_id=sgt_coin.name(),
        sgt_free_inner_puzzle_hash=bytes32(free_inner.get_tree_hash()),
        sgt_amount=vote_amount,
        locked_inner_puzzle_hash=locked_inner_hash,
    )
    sgt_spend = build_sgt_lock_coin_spend(
        sgt_coin=sgt_coin,
        voter_inner_puzzle=owner_inner,
        voter_inner_solution=owner_solution,
        proposal_tracker_struct=tracker_struct,
        sgt_tail_hash=sgt_tail,
        lineage_proof=sgt_lineage,
        proposal_hash=proposal_hash,
        deadline=chain.voting_deadline,
    )
    tracker_spend = build_tracker_vote_coin_spend(
        tracker_coin=chain.current_coin,
        tracker_inner_puzzle=tracker_inner,
        tracker_launcher_id=tracker_launcher,
        lineage_proof=tracker_lineage,
        voter_inner_puzzle_hash=owner_inner_hash,
        additional_vote_amount=vote_amount,
    )
    operation_hash = sgt_lock_operation_hash(
        vault_coin_id=vault_coin.name(),
        sgt_coin_id=sgt_coin.name(),
        proposal_hash=proposal_hash,
        lock_deadline=chain.voting_deadline,
        locked_inner_puzzle_hash=locked_inner_hash,
    )
    return AllocationVoteBuild(
        chain=chain,
        bundle=SpendBundle([vault_spend, sgt_spend, tracker_spend], G2Element()),
        operation_hash=operation_hash,
        proposal_hash=proposal_hash,
        vault_launcher_id=vault_launcher,
        vault_coin_id=vault_coin.name(),
        vault_auth_type=(
            "chia_bls" if vault_record.auth_type == AUTH_TYPE_BLS else "evm"
        ),
        vault_typed_data=(
            eip712_typed_data_for_sgt_lock(operation_hash, vault_coin.name())
            if vault_record.auth_type == AUTH_TYPE_SECP256K1
            else None
        ),
        sgt_coin_id=sgt_coin.name(),
        sgt_amount=vote_amount,
        available_sgt_amounts=available,
        locked_inner_puzzle_hash=locked_inner_hash,
        approved_vault=approved,
    )


__all__ = [
    "AllocationChainState",
    "AllocationExecutionBuild",
    "AllocationVoteBuild",
    "build_allocation_execution",
    "build_allocation_vote",
    "trace_allocation_proposal",
]
