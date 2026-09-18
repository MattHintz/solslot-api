"""Governed wUSDC.b funding, permanent offers, and vault acceptance."""
from __future__ import annotations

import json
import secrets
import re
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from time import time
from typing import Annotated, Any, Mapping

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    construct_cat_puzzle,
    match_cat_puzzle,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia.wallet.trading.offer import Offer
from chia.wallet.uncurried_puzzle import uncurry_puzzle
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.util.bech32m import encode_puzzle_hash
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.funded_redemption_v1 import (
    DirectRedemptionAcceptance,
    FundedRedemptionAllocation,
    FundedRedemptionPlanV1,
    aggregate_direct_redemption,
    build_direct_redemption_acceptance,
    build_funded_redemption_plan,
    build_permanent_redemption_offer,
)
from solslot_puzzles.pool_economics_v2 import deed_metadata_commitment
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.real_estate_profiles import ASSET_CLASS_CODES
from solslot_puzzles.redemption_treasury_v1 import (
    redemption_treasury_inner_puzzle,
    redemption_treasury_puzzle,
)
from solslot_puzzles.sgt_driver import bill_funded_redemption
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    compact_signature_from_evm,
    one_leaf_merkle_root,
    puzzle_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    eip712_typed_data_for_redemption_accept,
)

from .admin_auth import AdminClaims, require_admin_jwt
from .chia_provider import ChiaProviderError, _mempool_item_matches_bundle
from .collection_store import CollectionStore, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_alpha_writes, verify_vault_session
from .evm_auth import recover_evm_signer
from .governance_endpoints import _public, get_governance_queue_store
from .governance_execution import (
    _funded_redemption_plan,
    build_allocation_execution,
)
from .governance_queue import (
    GovernanceQueueConflict,
    GovernanceQueueNotFound,
    GovernanceQueueRecord,
    GovernanceQueueStore,
)
from .funded_redemption_store import (
    StoredFundedRedemption,
    StoredRedemptionFunding,
    get_funded_redemption_store,
)
from .launch_gates import require_operation_gate
from .mint_endpoints import get_mint_proposal_store
from .mint_proposals import MintProposalStore
from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from .sols_swaps import (
    SolsSwapOfferError,
    _b32,
    _coin_from_record,
    _coin_spend_json,
    _confirmed_coin_and_lineage,
    _hex32,
    _hex_bytes,
    _load_vault_held_deed,
    _require_inputs_clear,
    _verify_aggregate_signature,
)
from .vault_eligibility import require_current_approved_vault


router = APIRouter(tags=["funded-redemptions"])


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CreateFundedRedemption(ApiModel):
    collection_id: str = Field(alias="collectionId", min_length=1, max_length=128)
    title: str = Field(min_length=3, max_length=120)
    total_payment_usd: str = Field(alias="totalPaymentUsd", min_length=1, max_length=32)

    @field_validator("total_payment_usd")
    @classmethod
    def validate_total(cls, value: str) -> str:
        _wusdc_amount(value)
        return value


class CompleteRedemption(ApiModel):
    operation_hash: str = Field(alias="operationHash", min_length=66, max_length=66)
    funding_reservation_hash: str | None = Field(default=None, alias="fundingReservationHash", pattern=r"^0x[0-9a-f]{64}$")
    aggregated_signature: str | None = Field(
        default=None, alias="aggregatedSignature", min_length=194, max_length=194
    )
    vault_owner_authorization: str | None = Field(
        default=None, alias="vaultOwnerAuthorization", pattern=r"^0x[0-9a-fA-F]{130}$"
    )


class SubmitRedemptionFunding(ApiModel):
    spend_bundle: dict[str, Any] | None = Field(default=None, alias="spendBundle")


@dataclass(frozen=True)
class RedemptionContext:
    record: GovernanceQueueRecord
    plan: FundedRedemptionPlanV1
    allocation: FundedRedemptionAllocation
    leaf_coin: Coin
    leaf_lineage: LineageProof
    maker_offer: Offer
    acceptance: DirectRedemptionAcceptance
    vault_record: Any
    artifact: Any
    approved_vault: Any


def _wusdc_amount(value: str) -> int:
    if re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,3})?", value) is None:
        raise ValueError("Settlement amount must be a plain decimal with at most three decimals.")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("Settlement amount must be a dollar amount.") from exc
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -3:
        raise ValueError("Settlement amount must be positive with at most three decimals.")
    minor = amount * 1000
    if minor != minor.to_integral_value() or minor >= 2**64:
        raise ValueError("Settlement amount is outside the supported range.")
    return int(minor)


def _require_funded_redemptions(settings: Settings) -> None:
    if not settings.funded_redemptions_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Funded SmartDeed redemptions are not open.",
        )


def _signed_coordinates(settings: Settings) -> tuple[dict[str, Any], bytes32, bytes32, bytes32]:
    artifact = load_signed_public_artifact(settings)
    plan = artifact.get("genesisPlan", artifact)
    if not isinstance(plan, Mapping):
        raise ValueError("signed genesis plan is unavailable")
    launchers = plan.get("launcherIds", artifact.get("launcherIds"))
    puzzles = plan.get("puzzleHashes", artifact.get("puzzleHashes"))
    assets = plan.get("trustedAssets")
    if not all(isinstance(value, Mapping) for value in (launchers, puzzles, assets)):
        raise ValueError("signed redemption coordinates are incomplete")
    return (
        artifact,
        _b32(str(launchers.get("governance")), "governance launcher"),
        _b32(str(puzzles.get("deedLauncherPuzzleHash")), "deed launcher puzzle hash"),
        _b32(str(assets.get("wusdcBAssetId")), "trusted wUSDC.b asset ID"),
    )


def _treasury_view(settings: Settings) -> dict[str, str]:
    _artifact, governance, deed_launcher_hash, asset_id = _signed_coordinates(settings)
    inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=singleton_struct(governance),
        payment_asset_id=asset_id,
        deed_launcher_puzzle_hash=deed_launcher_hash,
    )
    full = redemption_treasury_puzzle(
        governance_singleton_struct=singleton_struct(governance),
        payment_asset_id=asset_id,
        deed_launcher_puzzle_hash=deed_launcher_hash,
    )
    return {
        "asset": "wUSDC.b",
        "assetId": _hex32(asset_id),
        "recipientPuzzleHash": _hex32(inner.get_tree_hash()),
        "recipientAddress": encode_puzzle_hash(bytes32(inner.get_tree_hash()), "txch"),
        "catPuzzleHash": _hex32(full.get_tree_hash()),
    }


def _funding_bundle_output(
    bundle: SpendBundle,
    *,
    payment_asset_id: bytes32,
    treasury_puzzle_hash: bytes32,
    payment_amount: int,
) -> Coin:
    if not 1 <= len(bundle.coin_spends) <= 20:
        raise ValueError("Funding must contain between one and twenty CAT spends.")
    if bundle.aggregated_signature == G2Element():
        raise ValueError("The wUSDC.b funding bundle is not wallet-signed.")
    removal_ids: set[bytes32] = set()
    for spend in bundle.coin_spends:
        coin_id = bytes32(spend.coin.name())
        if coin_id in removal_ids:
            raise ValueError("The funding bundle spends the same coin more than once.")
        removal_ids.add(coin_id)
        if bytes32(spend.puzzle_reveal.get_tree_hash()) != spend.coin.puzzle_hash:
            raise ValueError("A funding input puzzle does not match its coin.")
        matched = match_cat_puzzle(uncurry_puzzle(spend.puzzle_reveal))
        args = [] if matched is None else list(matched)
        if len(args) != 3 or bytes32(args[1].as_atom()) != payment_asset_id:
            raise ValueError("Funding may spend only the trusted wUSDC.b CAT.")
    try:
        additions = tuple(bundle.additions())
    except Exception as exc:
        raise ValueError("Funding conditions cannot be evaluated.") from exc
    if not 1 <= len(additions) <= 2:
        raise ValueError(
            "Funding may create only the governed output and one wallet change output."
        )
    if sum(int(coin.amount) for coin in bundle.removals()) != sum(
        int(coin.amount) for coin in additions
    ):
        raise ValueError("The administrator funding bundle must carry zero fee.")
    matches = [
        coin
        for coin in additions
        if coin.puzzle_hash == treasury_puzzle_hash
        and int(coin.amount) == payment_amount
    ]
    if len(matches) != 1:
        raise ValueError("The exact governed wUSDC.b treasury output is missing.")
    return matches[0]


def _funding_operation_hash(
    record: GovernanceQueueRecord,
    expected_coin_id: bytes32,
) -> str:
    return _hex32(
        Program.to(
            [
                b"SOLSLOT_REDEMPTION_FUNDING_V1",
                _b32(record.proposal_hash, "proposal hash"),
                expected_coin_id,
            ]
        ).get_tree_hash()
    )


async def _refresh_funding(
    stored: StoredRedemptionFunding,
    request: Request,
) -> StoredRedemptionFunding:
    if stored.status == "CONFIRMED":
        return stored
    record = await request.app.state.coinset.get_coin_record_by_name(
        stored.expected_funding_coin_id
    )
    height = int((record or {}).get("confirmed_block_index") or 0)
    spent_height = int((record or {}).get("spent_block_index") or 0)
    if height > 0 and spent_height == 0:
        return get_funded_redemption_store(
            str(request.app.state.settings.admin_db_path)
        ).mark_funding_confirmed(stored.proposal_id, height)
    return stored


async def _recover_funding_submission(
    stored: StoredRedemptionFunding,
    request: Request,
    submitter: ProtocolBundleSubmitter,
) -> StoredRedemptionFunding:
    refreshed = await _refresh_funding(stored, request)
    if refreshed.status != "SUBMITTING":
        return refreshed
    if refreshed.signed_bundle_json is None or not refreshed.input_coin_ids:
        raise ValueError("Stored funding submission evidence is incomplete.")
    try:
        bundle = SpendBundle.from_json_dict(json.loads(refreshed.signed_bundle_json))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Stored funding spend bundle is malformed.") from exc
    transaction_id = _hex32(bundle.name())
    pending = False
    for coin_id in refreshed.input_coin_ids:
        items = await request.app.state.coinset.get_mempool_items_by_coin_name(
            coin_id
        )
        if any(
            _mempool_item_matches_bundle(item, transaction_id) for item in items
        ):
            pending = True
            break
    if not pending:
        for coin_id in refreshed.input_coin_ids:
            coin_record = await request.app.state.coinset.get_coin_record_by_name(
                coin_id
            )
            if int((coin_record or {}).get("spent_block_index") or 0) > 0:
                raise ValueError(
                    "Funding inputs were spent without the expected treasury output; "
                    "manual chain review is required."
                )
        mempool = await request.app.state.coinset.push_tx_confirmed_in_primary_mempool(
            bundle.to_json_dict(),
            required_coin_id=refreshed.input_coin_ids[0],
            required_spend_bundle_id=transaction_id,
            timeout_seconds=submitter.policy.mempool_timeout_seconds,
            poll_seconds=submitter.policy.mempool_poll_seconds,
        )
        provider = str(mempool["provider"])
        observed_at = str(mempool["observed_at"])
    else:
        provider = "primary-mempool-recovery"
        observed_at = str(int(time()))
    fee = sum(int(coin.amount) for coin in bundle.removals()) - sum(
        int(coin.amount) for coin in bundle.additions()
    )
    return get_funded_redemption_store(
        str(request.app.state.settings.admin_db_path)
    ).mark_funding_submitted(
        refreshed.proposal_id,
        transaction_id=transaction_id,
        fee_mojos=str(fee),
        fee_target_seconds=submitter.policy.target_seconds,
        submission_provider=provider,
        mempool_observed_at=observed_at,
    )


def _funding_view(stored: StoredRedemptionFunding | None) -> dict[str, Any] | None:
    if stored is None:
        return None
    return {
        "operationHash": stored.operation_hash,
        "status": stored.status,
        "paymentAmount": stored.payment_amount,
        "paymentAssetId": stored.payment_asset_id,
        "recipientPuzzleHash": stored.recipient_inner_puzzle_hash,
        "expectedFundingCoinId": stored.expected_funding_coin_id,
        "transactionId": stored.transaction_id,
        "feeMojos": stored.fee_mojos,
        "feeTargetSeconds": stored.fee_target_seconds,
        "submissionProvider": stored.submission_provider,
        "mempoolObservedAt": stored.mempool_observed_at,
        "confirmedHeight": stored.confirmed_height,
        "updatedAt": stored.updated_at,
    }


@router.get("/admin/redemptions/funding-destination")
def redemption_funding_destination(
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
) -> dict[str, Any]:
    try:
        return {"network": settings.network, **_treasury_view(settings)}
    except (KeyError, TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/admin/redemptions", status_code=201)
def create_funded_redemption(
    body: CreateFundedRedemption,
    settings: Annotated[Settings, Depends(get_settings)],
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    collections: Annotated[CollectionStore, Depends(get_collection_store)],
    mints: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    if not settings.funded_redemptions_enabled or not settings.sgt_allocations_enabled:
        raise HTTPException(status_code=503, detail="Funded redemptions are disabled.")
    try:
        collection = collections.get(body.collection_id)
        deeds = collection.get("deeds")
        if not isinstance(deeds, list) or not deeds:
            raise ValueError("Collection has no governed SmartDeed allocation.")
        shares: dict[bytes32, int] = {}
        commitments: dict[bytes32, bytes32] = {}
        for deed in deeds:
            if not isinstance(deed, Mapping) or not deed.get("deedLauncherId"):
                raise ValueError("Every SmartDeed must be minted before redemption.")
            if int(deed.get("confirmationHeight") or 0) <= 0:
                raise ValueError("Every SmartDeed must be chain-confirmed before redemption.")
            proposal = mints.get(str(deed.get("proposalId") or ""))
            if proposal is None or proposal.deed_launcher_id is None:
                raise ValueError("SmartDeed mint evidence is unavailable.")
            asset_class = ASSET_CLASS_CODES.get(proposal.asset_class.upper())
            if asset_class is None:
                raise ValueError("SmartDeed asset class is not recognized.")
            launcher = bytes32(proposal.deed_launcher_id)
            recorded_launcher = _b32(
                str(deed.get("deedLauncherId")), "confirmed deed launcher ID"
            )
            if launcher != recorded_launcher:
                raise ValueError(
                    "Confirmed SmartDeed launcher does not match its mint evidence."
                )
            share = int(deed.get("sharePpm"))
            shares[launcher] = share
            commitments[launcher] = deed_metadata_commitment(
                launcher,
                proposal.par_value,
                int(asset_class),
                canonicalise_property_id(proposal.property_id),
                canonicalise_property_id(proposal.collection_id),
                share,
            )
        _artifact, _governance, _deed_launcher, asset_id = _signed_coordinates(settings)
        plan = build_funded_redemption_plan(
            collection_id=canonicalise_property_id(str(collection["id"])),
            settlement_id=bytes32(secrets.token_bytes(32)),
            payment_asset_id=asset_id,
            total_payment_amount=_wusdc_amount(body.total_payment_usd),
            deed_shares_ppm=shares,
            deed_commitments=commitments,
        )
        bill = bill_funded_redemption(
            collection_id=plan.collection_id,
            settlement_id=plan.settlement_id,
            payment_asset_id=plan.payment_asset_id,
            total_payment_amount=plan.total_payment_amount,
            deed_count=plan.deed_count,
            allocations_root=plan.allocations_root,
        )
        record = queue.create(
            kind="FUNDED_REDEMPTION",
            title=body.title,
            bill={
                "collectionWorkspaceId": str(collection["id"]),
                "collectionId": _hex32(plan.collection_id),
                "settlementId": _hex32(plan.settlement_id),
                "paymentAssetId": _hex32(plan.payment_asset_id),
                "totalPaymentAmount": str(plan.total_payment_amount),
                "deedCount": plan.deed_count,
                "allocationsRoot": _hex32(plan.allocations_root),
                "allocations": [
                    {
                        "deedLauncherId": _hex32(item.deed_launcher_id),
                        "deedCommitment": _hex32(item.deed_commitment),
                        "sharePpm": item.share_ppm,
                        "paymentAmount": str(item.payment_amount),
                    }
                    for item in plan.allocations
                ],
            },
            bill_clvm_hex="0x" + bytes(bill).hex(),
            proposal_hash=_hex32(bill.get_tree_hash()),
            actor=claims.sub,
        )
        return {"redemption": _public(record), "funding": _treasury_view(settings)}
    except GovernanceQueueConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/admin/redemptions")
async def list_admin_redemptions(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    records = [item for item in queue.list() if item.kind == "FUNDED_REDEMPTION"]
    return {
        "redemptions": [
            await _redemption_summary(item, request, settings) for item in records
        ],
        "funding": _treasury_view(settings),
    }


@router.get("/admin/redemptions/{proposal_id}/funding")
async def get_redemption_funding(
    proposal_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    try:
        record = queue.get(proposal_id)
        if record.kind != "FUNDED_REDEMPTION":
            raise ValueError("Proposal is not a funded SmartDeed redemption.")
        stored = get_funded_redemption_store(settings.admin_db_path).get_funding(
            proposal_id
        )
        if stored is not None:
            stored = await _refresh_funding(stored, request)
        return {
            "proposalId": proposal_id,
            "chainState": record.state,
            "funding": _funding_view(stored),
        }
    except GovernanceQueueNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/redemptions/{proposal_id}/funding/submit")
async def submit_redemption_funding(
    proposal_id: str,
    body: SubmitRedemptionFunding,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    _require_funded_redemptions(settings)
    require_alpha_writes(settings)
    require_operation_gate(settings, "purchases")
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise HTTPException(status_code=503, detail="Protocol fee funding is unavailable.")
    store = get_funded_redemption_store(settings.admin_db_path)
    try:
        record = queue.get(proposal_id)
        if record.kind != "FUNDED_REDEMPTION":
            raise ValueError("Proposal is not a funded SmartDeed redemption.")
        build = await build_allocation_execution(
            record=record,
            request=request,
            settings=settings,
        )
        if build.chain.state != "AWAITING_EXECUTE":
            raise ValueError(
                "The committee vote must pass before wUSDC.b funding can move."
            )
        existing = store.get_funding(proposal_id)
        if existing is not None:
            existing = await _recover_funding_submission(existing, request, submitter)
            if existing.status != "PREPARED":
                return {
                    "proposalId": proposal_id,
                    "chainState": build.chain.state,
                    "funding": _funding_view(existing),
                }
        if body.spend_bundle is None:
            raise ValueError(
                "A fresh wallet-signed wUSDC.b funding bundle is required."
            )
        plan = _funded_redemption_plan(record)
        treasury = _treasury_view(settings)
        bundle = SpendBundle.from_json_dict(body.spend_bundle)
        expected_coin = _funding_bundle_output(
            bundle,
            payment_asset_id=plan.payment_asset_id,
            treasury_puzzle_hash=_b32(
                treasury["catPuzzleHash"], "redemption treasury CAT puzzle hash"
            ),
            payment_amount=plan.total_payment_amount,
        )
        _verify_aggregate_signature(bundle, settings.network)
        await _require_inputs_clear(
            request.app.state.coinset, tuple(bundle.removals())
        )
        operation_hash = _funding_operation_hash(record, expected_coin.name())
        unsigned = SpendBundle(list(bundle.coin_spends), G2Element())

        async def dispatch(prepared) -> dict[str, Any]:
            store.prepare_funding_submission(
                proposal_id=proposal_id,
                operation_hash=operation_hash,
                settlement_id=_hex32(plan.settlement_id),
                payment_asset_id=_hex32(plan.payment_asset_id),
                payment_amount=str(plan.total_payment_amount),
                recipient_inner_puzzle_hash=treasury["recipientPuzzleHash"],
                expected_funding_coin_id=_hex32(expected_coin.name()),
                unsigned_bundle=unsigned.to_json_dict(),
                signed_bundle=prepared.bundle.to_json_dict(),
                input_coin_ids=tuple(
                    _hex32(spend.coin.name())
                    for spend in prepared.bundle.coin_spends
                ),
                created_by=claims.sub,
            )
            return await request.app.state.coinset.push_tx_confirmed_in_primary_mempool(
                prepared.bundle.to_json_dict(),
                required_coin_id=prepared.fee_coin_id,
                required_spend_bundle_id=prepared.spend_bundle_id,
                timeout_seconds=submitter.policy.mempool_timeout_seconds,
                poll_seconds=submitter.policy.mempool_poll_seconds,
            )

        submission = await submitter.prepare_and_dispatch(
            bundle.to_json_dict(), dispatch
        )
        dispatch_result = submission.get("dispatchResult") or {}
        stored = store.mark_funding_submitted(
            proposal_id,
            transaction_id=str(submission["spendBundleId"]),
            fee_mojos=str(submission["feeMojos"]),
            fee_target_seconds=int(submission["feeTargetSeconds"]),
            submission_provider=str(dispatch_result.get("provider") or "primary"),
            mempool_observed_at=str(dispatch_result.get("observed_at") or ""),
        )
        return {
            "proposalId": proposal_id,
            "chainState": build.chain.state,
            "funding": _funding_view(stored),
        }
    except GovernanceQueueNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ProtocolSubmissionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ChiaProviderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/redemptions/vaults/{vault_launcher_id}")
async def list_vault_redemptions(
    vault_launcher_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    _require_funded_redemptions(settings)
    verify_vault_session(settings, request, vault_launcher_id)
    require_current_approved_vault(settings, vault_launcher_id)
    offers: list[dict[str, Any]] = []
    for record in queue.list(public=True):
        if record.kind != "FUNDED_REDEMPTION" or record.state != "EXECUTED":
            continue
        plan = _funded_redemption_plan(record)
        for index, allocation in enumerate(plan.allocations):
            try:
                context = await _redemption_context(
                    record=record,
                    allocation=allocation,
                    vault_launcher_id=vault_launcher_id,
                    request=request,
                    settings=settings,
                    build_acceptance=False,
                )
            except (ValueError, SolsSwapOfferError):
                continue
            offers.append(_offer_view(context, index))
    operations = [
        await _refresh_operation(item, request)
        for item in get_funded_redemption_store(settings.admin_db_path).list_for_vault(
            vault_launcher_id.lower()
        )
    ]
    from .funded_redemption_review import review_store, resume_execution
    for operation in review_store(request, settings).list_executions(vault_launcher_id.lower()):
        operations.append(await resume_execution(operation, request, settings))
    return {
        "offers": offers,
        "operations": operations,
        "count": len(offers),
    }


@router.post("/redemptions/vaults/{vault_launcher_id}/{settlement_id}/{deed_launcher_id}/prepare")
async def prepare_redemption(
    vault_launcher_id: str,
    settlement_id: str,
    deed_launcher_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    _require_funded_redemptions(settings)
    require_alpha_writes(settings)
    require_operation_gate(settings, "purchases")
    verify_vault_session(settings, request, vault_launcher_id)
    from .funded_redemption_review import prepare_review
    try:
        return await prepare_review(vault_launcher_id, settlement_id, deed_launcher_id, request, settings, queue)
    except HTTPException:
        raise
    except (ChiaProviderError, PublicArtifactError, ProtocolSubmissionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/redemptions/vaults/{vault_launcher_id}/{settlement_id}/{deed_launcher_id}/complete")
async def complete_redemption(
    vault_launcher_id: str,
    settlement_id: str,
    deed_launcher_id: str,
    body: CompleteRedemption,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict[str, Any]:
    _require_funded_redemptions(settings)
    require_alpha_writes(settings)
    require_operation_gate(settings, "purchases")
    verify_vault_session(settings, request, vault_launcher_id)
    from .funded_redemption_review import complete_review
    try:
        return await complete_review(vault_launcher_id, settlement_id, deed_launcher_id, body, request, settings, queue)
    except HTTPException:
        raise
    except (ChiaProviderError, PublicArtifactError, ProtocolSubmissionError) as exc:
        raise HTTPException(status_code=503, detail="Redemption submission is unresolved; resume this exact operation. " + str(exc)) from exc
    except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/redemptions/{operation_hash}")
async def get_redemption_operation(
    operation_hash: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        normalized = _hex32(_b32(operation_hash, "operation hash"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    from .funded_redemption_review import review_store, resume_execution
    reviewed = review_store(request, settings)
    if reviewed.execution(normalized) is not None or reviewed.expired_execution(normalized) is not None:
        try:
            return await resume_execution(normalized, request, settings)
        except (ChiaProviderError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    stored = get_funded_redemption_store(settings.admin_db_path).get(normalized)
    if stored is None:
        raise HTTPException(status_code=404, detail="Redemption operation was not found.")
    verify_vault_session(settings, request, stored.vault_launcher_id)
    return await _refresh_operation(stored, request)


async def _refresh_operation(
    stored: StoredFundedRedemption,
    request: Request,
) -> dict[str, Any]:
    # Historical rows lack a retained signed bundle. Preserve their recorded
    # status; one unbound output lookup cannot upgrade them to confirmed.
    return _operation_view(stored)


def _operation_view(stored: StoredFundedRedemption) -> dict[str, Any]:
    return {
        "operationHash": stored.operation_hash,
        "settlementId": stored.settlement_id,
        "deedLauncherId": stored.deed_launcher_id,
        "vaultLauncherId": stored.vault_launcher_id,
        "paymentAmount": stored.payment_amount,
        "paymentSymbol": "wUSDC.b",
        "fundingCoinId": stored.funding_coin_id,
        "expectedPaymentCoinId": stored.expected_payment_coin_id,
        "status": stored.status,
        "transactionId": stored.transaction_id,
        "feeMojos": stored.fee_mojos,
        "feeTargetSeconds": stored.fee_target_seconds,
        "submissionProvider": stored.submission_provider,
        "mempoolObservedAt": stored.mempool_observed_at,
        "confirmedHeight": stored.confirmed_height,
        "updatedAt": stored.updated_at,
    }


def _find_redemption(
    queue: GovernanceQueueStore, settlement_id: str, deed_launcher_id: str
) -> tuple[GovernanceQueueRecord, FundedRedemptionAllocation]:
    settlement = _hex32(_b32(settlement_id, "settlement ID"))
    deed = _b32(deed_launcher_id, "deed launcher ID")
    matches = queue.find_executed_redemptions(settlement)
    if len(matches) != 1:
        raise HTTPException(status_code=404, detail="Funded redemption is unavailable.")
    plan = _funded_redemption_plan(matches[0])
    allocations = [item for item in plan.allocations if item.deed_launcher_id == deed]
    if len(allocations) != 1:
        raise HTTPException(status_code=404, detail="SmartDeed has no funded redemption offer.")
    return matches[0], allocations[0]


async def _redemption_context(
    *,
    record: GovernanceQueueRecord,
    allocation: FundedRedemptionAllocation,
    vault_launcher_id: str,
    request: Request,
    settings: Settings,
    build_acceptance: bool,
    owner_authorization: str | None = None,
) -> RedemptionContext:
    approved = require_current_approved_vault(settings, vault_launcher_id)
    session = verify_vault_session(settings, request, vault_launcher_id)
    plan = _funded_redemption_plan(record)
    index = plan.allocations.index(allocation)
    if index >= len(record.expected_output_coin_ids):
        raise ValueError("redemption funding output is not indexed")
    leaf_id = record.expected_output_coin_ids[index]
    leaf_record = await request.app.state.coinset.get_coin_record_by_name(leaf_id)
    leaf_coin = _coin_from_record(leaf_record)
    if (
        leaf_coin is None
        or _hex32(leaf_coin.name()) != leaf_id.lower()
        or int((leaf_record or {}).get("confirmed_block_index") or 0) <= 0
        or int((leaf_record or {}).get("spent_block_index") or 0) != 0
    ):
        raise ValueError("permanent redemption funding is not available")
    artifact, governance, deed_launcher_hash, asset_id = _signed_coordinates(settings)
    if plan.payment_asset_id != asset_id:
        raise ValueError("redemption payment asset changed")
    treasury_inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=singleton_struct(governance),
        payment_asset_id=asset_id,
        deed_launcher_puzzle_hash=deed_launcher_hash,
    )
    treasury_record = await request.app.state.coinset.get_coin_record_by_name(
        _hex32(leaf_coin.parent_coin_info)
    )
    treasury_coin = _coin_from_record(treasury_record)
    expected_treasury = construct_cat_puzzle(CAT_MOD, asset_id, treasury_inner)
    if (treasury_coin is None or treasury_coin.name() != leaf_coin.parent_coin_info
            or treasury_coin.puzzle_hash != expected_treasury.get_tree_hash()
            or type((treasury_record or {}).get("spent_block_index")) is not int
            or treasury_record["spent_block_index"] != leaf_record["confirmed_block_index"]
            or treasury_record.get("spent") is not True):
        raise ValueError("redemption treasury lineage is unavailable")
    leaf_lineage = LineageProof(
        treasury_coin.parent_coin_info,
        bytes32(treasury_inner.get_tree_hash()),
        uint64(treasury_coin.amount),
    )
    deed = await _load_vault_held_deed(
        provider=request.app.state.coinset,
        config=type("RedemptionDeedConfig", (), {"deed_launcher_puzzle_hash": deed_launcher_hash})(),
        vault_launcher_id=_b32(vault_launcher_id, "vault launcher ID"),
        deed_launcher_id=_hex32(allocation.deed_launcher_id),
    )
    if deed.deed_commitment != allocation.deed_commitment or deed.share_ppm != allocation.share_ppm:
        raise ValueError("SmartDeed does not match the governed allocation")
    deed_struct = Program.to(
        (SINGLETON_MOD_HASH, (allocation.deed_launcher_id, deed_launcher_hash))
    )
    maker, _maker_spend = build_permanent_redemption_offer(
        funding_coin=leaf_coin,
        funding_lineage_proof=leaf_lineage,
        plan=plan,
        allocation=allocation,
        deed_singleton_struct=deed_struct,
    )
    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        request.app.state.coinset, approved.current_coin_id, "approved vault coin"
    )
    owner_key = bytes(session.vault_record.owner_pubkey)
    rules = artifact.get("genesisPlan", artifact).get("permanentRules", {})
    policy_hash = _b32(rules.get("zkpassportPolicyHash"), "zkPassport policy hash")
    signature_data = None
    placeholder = build_direct_redemption_acceptance(
        vault_coin=vault_coin,
        vault_launcher_id=session.vault_record.launcher_id,
        vault_lineage_proof=vault_lineage,
        vault_owner_pubkey=owner_key,
        vault_auth_type=session.vault_record.auth_type,
        vault_members_merkle_root=one_leaf_merkle_root(owner_key),
        pool_launcher_id=_b32(
            artifact.get("genesisPlan", artifact).get("launcherIds", artifact.get("launcherIds", {})).get("pool"),
            "pool launcher ID",
        ),
        identity_attest_root=_b32(approved.identity_attest_root, "identity root"),
        zkpassport_bridge_policy_hash=policy_hash,
        deed_coin=deed.coin,
        deed_lineage_proof=deed.lineage,
        deed_current_inner_puzzle_hash=bytes32(
            puzzle_for_p2_vault(session.vault_record.launcher_id).get_tree_hash()
        ),
        deed_singleton_struct=deed_struct,
        payment_recipient_inner_puzzle_hash=bytes32(
            puzzle_for_p2_vault(session.vault_record.launcher_id).get_tree_hash()
        ),
        plan=plan,
        allocation=allocation,
        signature_data=None,
    )
    if owner_authorization is not None:
        if session.vault_record.auth_type != AUTH_TYPE_SECP256K1 or not session.vault_record.owner_evm_address:
            raise ValueError("EVM authorization is not valid for this vault")
        typed = eip712_typed_data_for_redemption_accept(
            placeholder.operation_hash, vault_coin.name()
        )
        recovered = recover_evm_signer(typed, owner_authorization)
        if recovered.address.lower() != session.vault_record.owner_evm_address.lower():
            raise ValueError("EVM signature does not belong to this vault owner")
        signature_data = compact_signature_from_evm(owner_authorization)
    acceptance = (
        placeholder
        if signature_data is None
        else build_direct_redemption_acceptance(
            **{
                "vault_coin": vault_coin,
                "vault_launcher_id": session.vault_record.launcher_id,
                "vault_lineage_proof": vault_lineage,
                "vault_owner_pubkey": owner_key,
                "vault_auth_type": session.vault_record.auth_type,
                "vault_members_merkle_root": one_leaf_merkle_root(owner_key),
                "pool_launcher_id": _b32(
                    artifact.get("genesisPlan", artifact).get("launcherIds", artifact.get("launcherIds", {})).get("pool"),
                    "pool launcher ID",
                ),
                "identity_attest_root": _b32(approved.identity_attest_root, "identity root"),
                "zkpassport_bridge_policy_hash": policy_hash,
                "deed_coin": deed.coin,
                "deed_lineage_proof": deed.lineage,
                "deed_current_inner_puzzle_hash": bytes32(puzzle_for_p2_vault(session.vault_record.launcher_id).get_tree_hash()),
                "deed_singleton_struct": deed_struct,
                "payment_recipient_inner_puzzle_hash": bytes32(puzzle_for_p2_vault(session.vault_record.launcher_id).get_tree_hash()),
                "plan": plan,
                "allocation": allocation,
                "signature_data": signature_data,
            }
        )
    )
    return RedemptionContext(record, plan, allocation, leaf_coin, leaf_lineage, maker, acceptance, session.vault_record, artifact, approved)


async def _redemption_summary(
    record: GovernanceQueueRecord,
    request: Request,
    settings: Settings,
) -> dict[str, Any]:
    result = _public(record)
    outputs = []
    for coin_id in record.expected_output_coin_ids:
        record_value = await request.app.state.coinset.get_coin_record_by_name(coin_id)
        outputs.append(
            {
                "coinId": coin_id,
                "confirmedHeight": int((record_value or {}).get("confirmed_block_index") or 0),
                "spentHeight": int((record_value or {}).get("spent_block_index") or 0),
            }
        )
    result["offers"] = outputs
    result["availableOfferCount"] = sum(
        1 for item in outputs if item["confirmedHeight"] > 0 and item["spentHeight"] == 0
    )
    funding = get_funded_redemption_store(settings.admin_db_path).get_funding(
        record.id
    )
    if funding is not None:
        funding = await _refresh_funding(funding, request)
    result["funding"] = _funding_view(funding)
    result["chainState"] = record.state
    result["executionBlocker"] = None
    if record.state == "ACTIVE":
        try:
            build = await build_allocation_execution(
                record=record,
                request=request,
                settings=settings,
            )
            result["chainState"] = build.chain.state
            result["executionBlocker"] = build.blocker
        except ValueError as exc:
            result["chainState"] = "BLOCKED"
            result["executionBlocker"] = str(exc)
    return result


def _offer_view(context: RedemptionContext, index: int) -> dict[str, Any]:
    allocation = context.allocation
    return {
        "proposalId": context.record.id,
        "title": context.record.title,
        "collectionWorkspaceId": context.record.bill.get("collectionWorkspaceId"),
        "settlementId": _hex32(context.plan.settlement_id),
        "deedLauncherId": _hex32(allocation.deed_launcher_id),
        "sharePpm": allocation.share_ppm,
        "paymentAmount": str(allocation.payment_amount),
        "paymentSymbol": "wUSDC.b",
        "fundingCoinId": _hex32(context.leaf_coin.name()),
        "status": "AVAILABLE",
        "permanent": True,
        "allocationIndex": index,
    }


__all__ = ["router"]
