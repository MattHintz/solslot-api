"""Authenticated RC22 protocol swap execution.

The protocol package owns offer construction. This module only reconstructs
the live chain inputs, binds them to a zkPassport-approved vault, collects the
wallet authorization, and submits supported exact atomic bundles through the
existing fountain fee till. Directions that do not yet have a complete atomic
protocol assembler are never advertised as executable.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from functools import lru_cache
from time import time
from typing import Annotated, Any, Literal, Mapping, Optional

from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    construct_cat_puzzle,
    get_innerpuzzle_from_puzzle,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_economics_v2 import deed_metadata_commitment
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    make_pool_v4_full,
    make_pool_v4_inner,
)
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    PermanentRules,
    ScopedPause,
)
from solslot_puzzles.sols_economics_v3 import (
    SolsEconomicState,
    quote_sols_to_deed,
)
from solslot_puzzles.sols_pool_v4 import (
    DEED_TO_SOLS,
    PoolInventoryRecord,
    SolsPoolStateV4,
    inventory_root,
    prepare_deed_to_sols,
    prepare_sols_to_deed,
)
from solslot_puzzles.sols_swap_v4_driver import (
    SolsSwapOfferError,
    UnsignedSolsSwapEvidence,
    aggregate_sols_to_deed_swap,
    build_deed_to_sols_protocol_offer,
    build_sols_to_deed_protocol_offer,
    prepare_vault_sols_buyer_offer,
    prepare_unsigned_sols_to_deed_swap,
    prepare_unsigned_deed_to_sols_swap,
    validate_sols_buyer_offer,
)
from solslot_puzzles.vault_sols_v1 import (
    puzzle_for_vault_sols_cat,
    puzzle_for_vault_sols_inner,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    compact_signature_from_evm,
    one_leaf_merkle_root,
    puzzle_hash_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    eip712_typed_data_for_sols_swap,
    puzzle_for_vault_v2_full,
)

from .chia_provider import ChiaProvider, ChiaProviderError
from .config import Settings, get_settings
from .wallet_offer_worker import run_offer_job
from .credential_auth import (
    require_alpha_writes,
    require_vault_record,
    verify_vault_session,
)
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA, Faucet
from .launch_gates import require_operation_gate
from .protocol_submission import (
    ProtocolBundleSubmitter,
    ProtocolSubmissionError,
)
from .public_artifact import (
    PublicArtifactError,
    load_signed_public_artifact,
)
from .sols_market import (
    PoolState,
    SingletonTip,
    StatutesSnapshot,
    _artifact_permanent_rules,
    _decode_pool_state,
    _initial_pool_state,
    _latest_solution,
    _program,
    _singleton_struct,
    _singleton_tip,
    _statutes_snapshot,
)
from .sols_swap_store import SolsSwapStore, StoredSolsSwap
from .sols_swap_execution import execution_confirmed, validate_execution
from .sols_swap_funding import (
    digest as funding_digest, funding_identity, require_hold,
    reserve_funding, submit_reserved_funding,
)
from .release_metadata import read_release_metadata
from .state import VaultRecord
from .vault_eligibility import ApprovedVault, require_current_approved_vault


router = APIRouter(prefix="/sols", tags=["sols-secondary-swaps"])

SOLS_SWAP_QUOTE_TTL_SECONDS = 600


class SolsSwapModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class PrepareSolsSwapRequest(SolsSwapModel):
    direction: Literal["SOLS_TO_DEED", "DEED_TO_SOLS"] = "SOLS_TO_DEED"
    deed_launcher_id: str = Field(
        alias="deedLauncherId",
        min_length=66,
        max_length=66,
    )
    @field_validator("deed_launcher_id")
    @classmethod
    def validate_deed_launcher_id(cls, value: str) -> str:
        return _hex32_text(value, "deedLauncherId")


class PrepareSolsSwapResponse(SolsSwapModel):
    schema_version: int = Field(default=3, alias="schemaVersion")
    direction: Literal["SOLS_TO_DEED", "DEED_TO_SOLS"]
    operation_hash: str = Field(alias="operationHash")
    deed_launcher_id: str = Field(alias="deedLauncherId")
    vault_launcher_id: str = Field(alias="vaultLauncherId")
    buyer_offer: str | None = Field(default=None, alias="buyerOffer")
    signing_coin_spends: list[dict[str, Any]] = Field(alias="signingCoinSpends")
    unsigned_protocol_evidence: dict[str, Any] | None = Field(
        default=None, alias="unsignedProtocolEvidence",
    )
    funding_evidence: dict[str, Any] | None = Field(default=None, alias="fundingEvidence")
    current_state_evidence: dict[str, Any] | None = Field(default=None, alias="currentStateEvidence")
    selected_payment_public_key: str | None = Field(
        default=None,
        alias="selectedPaymentPublicKey",
    )
    selected_payment_coin_id: str | None = Field(
        default=None,
        alias="selectedPaymentCoinId",
    )
    quote_expires_at: int = Field(alias="quoteExpiresAt")
    principal_sols_mojos: str = Field(alias="principalSolsMojos")
    protocol_fee_sols_mojos: str = Field(alias="protocolFeeSolsMojos")
    sgt_rewards_fee_sols_mojos: str = Field(alias="sgtRewardsFeeSolsMojos")
    total_sols_mojos: str = Field(alias="totalSolsMojos")
    destination_p2_vault_hash: str | None = Field(
        default=None,
        alias="destinationP2VaultHash",
    )
    destination_puzzle_hash: str = Field(alias="destinationPuzzleHash")
    fresh_sols_mojos_minted: str = Field(
        default="0",
        alias="freshSolsMojosMinted",
    )
    vault_auth_type: str = Field(alias="vaultAuthType")
    vault_typed_data: Optional[dict[str, Any]] = Field(
        default=None,
        alias="vaultTypedData",
    )
    review: dict[str, Any]


class CompleteSolsSwapRequest(SolsSwapModel):
    funding_reservation_hash: str | None = Field(default=None, alias="fundingReservationHash", pattern=r"^0x[0-9a-f]{64}$")
    direction: Literal["SOLS_TO_DEED", "DEED_TO_SOLS"] = "SOLS_TO_DEED"
    deed_launcher_id: str = Field(
        alias="deedLauncherId",
        min_length=66,
        max_length=66,
    )
    operation_hash: str = Field(
        alias="operationHash",
        min_length=66,
        max_length=66,
    )
    quote_expires_at: int = Field(alias="quoteExpiresAt", gt=0)
    buyer_offer: str | None = Field(
        default=None,
        alias="buyerOffer",
        max_length=2_000_000,
    )
    aggregated_signature: str | None = Field(
        default=None,
        alias="aggregatedSignature",
        min_length=194,
        max_length=194,
    )
    vault_owner_authorization: Optional[str] = Field(
        default=None,
        alias="vaultOwnerAuthorization",
        min_length=132,
        max_length=132,
    )

    @field_validator("deed_launcher_id", "operation_hash")
    @classmethod
    def validate_bytes32_fields(cls, value: str, info: Any) -> str:
        return _hex32_text(value, info.field_name)


class CompleteSolsSwapResponse(SolsSwapModel):
    schema_version: int = Field(default=3, alias="schemaVersion")
    direction: Literal["SOLS_TO_DEED", "DEED_TO_SOLS"]
    operation_hash: str = Field(alias="operationHash")
    deed_launcher_id: str = Field(alias="deedLauncherId")
    destination_p2_vault_hash: str | None = Field(
        default=None,
        alias="destinationP2VaultHash",
    )
    destination_puzzle_hash: str = Field(alias="destinationPuzzleHash")
    transaction_id: str = Field(alias="transactionId")
    status: str
    fee_mojos: str = Field(alias="feeMojos")
    fee_target_seconds: int = Field(alias="feeTargetSeconds")
    submission_provider: str | None = Field(alias="submissionProvider")
    mempool_observed_at: str | None = Field(alias="mempoolObservedAt")


class SolsSwapOperationResponse(SolsSwapModel):
    operation_hash: str = Field(alias="operationHash")
    direction: str
    vault_launcher_id: str = Field(alias="vaultLauncherId")
    deed_launcher_id: str = Field(alias="deedLauncherId")
    status: str
    quote_expires_at: int = Field(alias="quoteExpiresAt")
    transaction_id: str | None = Field(alias="transactionId")
    fee_mojos: str | None = Field(alias="feeMojos")
    fee_target_seconds: int | None = Field(alias="feeTargetSeconds")
    submission_provider: str | None = Field(alias="submissionProvider")
    mempool_observed_at: str | None = Field(alias="mempoolObservedAt")
    updated_at: float = Field(alias="updatedAt")


@dataclass(frozen=True)
class VaultSolsPaymentCoin:
    coin: Coin
    lineage: LineageProof


@dataclass(frozen=True)
class SolsSwapContext:
    artifact: dict[str, Any]
    config: PoolV4Config
    pool_state: SolsPoolStateV4
    pool_inventory: tuple[PoolInventoryRecord, ...]
    pool_coin: Coin
    pool_lineage: LineageProof
    statutes: StatutesSnapshot
    statutes_coin: Coin
    statutes_lineage: LineageProof
    collection: CollectionStatute
    pause: ScopedPause | None
    approved_vault: ApprovedVault
    vault_record: VaultRecord
    vault_coin: Coin
    vault_lineage: LineageProof
    custody_coin: Coin
    custody_lineage: LineageProof
    payment_coin: Coin
    payment_lineage: LineageProof
    receipt: Any


@dataclass(frozen=True)
class VaultHeldDeed:
    coin: Coin
    lineage: LineageProof
    smart_deed_inner: Program
    par_value: int
    asset_class: int
    property_id: bytes32
    collection_id: bytes32
    share_ppm: int
    deed_commitment: bytes32


@dataclass(frozen=True)
class ReverseSolsSwapContext:
    artifact: dict[str, Any]
    config: PoolV4Config
    pool_state: SolsPoolStateV4
    pool_inventory: tuple[PoolInventoryRecord, ...]
    pool_coin: Coin
    pool_lineage: LineageProof
    statutes: StatutesSnapshot
    statutes_coin: Coin
    statutes_lineage: LineageProof
    collection: CollectionStatute
    pause: ScopedPause | None
    approved_vault: ApprovedVault
    vault_record: VaultRecord
    vault_coin: Coin
    vault_lineage: LineageProof
    deed: VaultHeldDeed
    reserve_coin: Coin
    reserve_lineage: LineageProof
    reserve_inner_puzzle: Program
    receipt: Any


@router.post(
    "/vaults/{vault_launcher_id}/swaps/prepare",
    response_model=PrepareSolsSwapResponse,
)
async def prepare_sols_swap(
    vault_launcher_id: str,
    body: PrepareSolsSwapRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> PrepareSolsSwapResponse:
    _authorize_swap(settings, request, vault_launcher_id)
    try:
        return await _snapshot_prepare(vault_launcher_id, body, request, settings)
    except (ChiaProviderError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail=f"Current swap state is unavailable: {exc}") from exc


async def _snapshot_prepare(vault_launcher_id, body, request, settings):
    from .chia_snapshot import PrimaryReadSnapshot
    async with PrimaryReadSnapshot(request.app.state.coinset, settings.network) as snapshot:
        result = await _prepare_sols_swap(vault_launcher_id, body, request, settings)
        evidence, funding = result.unsigned_protocol_evidence, result.funding_evidence
        ephemeral = {"sols_settlement", "smart_deed"}
        inputs = []
        for value in [*evidence["coinSpends"], {"role": "fee", **funding["fundingCoinSpend"]}]:
            if value["role"] in ephemeral:
                continue
            coin = value["coin"]
            inputs.append((value["role"], Coin(_b32(coin["parentCoinInfo"], "parent"),
                _b32(coin["puzzleHash"], "puzzle"), uint64(int(coin["amount"])))))
        receipt = await snapshot.finish(inputs, {
            "operationHash": result.operation_hash, "quoteExpiresAt": result.quote_expires_at,
            "protocolCandidateHash": evidence["protocolCandidateHash"],
            "fundingReservationHash": funding["reservationHash"], **funding["binding"],
        })
        return result.model_copy(update={"current_state_evidence": receipt})


async def _prepare_sols_swap(vault_launcher_id, body, request, settings):
    if body.direction == "DEED_TO_SOLS":
        return await _prepare_deed_to_sols_swap(
            vault_launcher_id=vault_launcher_id,
            body=body,
            request=request,
            settings=settings,
        )
    try:
        context = await _load_swap_context(
            settings=settings,
            provider=request.app.state.coinset,
            vault_launcher_id=vault_launcher_id,
            deed_launcher_id=body.deed_launcher_id,
            quote_expires_at=None,
        )
        quote = context.receipt.sols_to_deed_quote
        if quote is None:
            raise SolsSwapOfferError("Sols-to-deed quote is unavailable")
        buyer = prepare_vault_sols_buyer_offer(
            payment_coin=context.payment_coin,
            payment_lineage_proof=context.payment_lineage,
            receipt=context.receipt,
            config=context.config,
            vault_launcher_id=context.vault_record.launcher_id,
        )
        signing_spends: list[CoinSpend] = []
        unsigned_evidence = prepare_unsigned_sols_to_deed_swap(
            buyer_offer=buyer.offer, **_protocol_offer_arguments(context),
        )
        vault_typed_data: dict[str, Any] | None = None
        if context.vault_record.auth_type == AUTH_TYPE_BLS:
            protocol = _build_protocol_offer(context, signature_data=None)
            signing_spends.append(protocol.vault_spend)
            vault_auth_type = "chia_bls"
        else:
            vault_typed_data = _vault_swap_typed_data(context)
            vault_auth_type = "evm"
    except HTTPException:
        raise
    except (ChiaProviderError, PublicArtifactError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sols swap coordinates are unavailable: {exc}",
        ) from exc
    except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    destination = puzzle_hash_for_p2_vault(context.vault_record.launcher_id)
    expected_pool_output = Coin(
        context.pool_coin.name(),
        make_pool_v4_full(
            context.config,
            context.receipt.next_state,
        ).get_tree_hash(),
        context.pool_coin.amount,
    )
    try:
        _request_swap_store(request, settings).record_prepared(
            operation_hash=_hex32(context.receipt.operation_hash),
            direction="SOLS_TO_DEED",
            vault_launcher_id=_hex32(context.vault_record.launcher_id),
            deed_launcher_id=_hex32(context.receipt.record.deed_launcher_id),
            quote_expires_at=context.receipt.quote_expires_at,
            pool_input_coin_id=_hex32(context.pool_coin.name()),
            expected_pool_output_coin_id=_hex32(
                expected_pool_output.name()
            ),
            destination_puzzle_hash=_hex32(destination),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    funding_evidence = await _prepare_funding_review(request, settings, context, unsigned_evidence)
    return PrepareSolsSwapResponse(
        direction=body.direction,
        operationHash=_hex32(context.receipt.operation_hash),
        deedLauncherId=_hex32(context.receipt.record.deed_launcher_id),
        vaultLauncherId=_hex32(context.vault_record.launcher_id),
        buyerOffer=buyer.offer.to_bech32(),
        signingCoinSpends=[_coin_spend_json(item) for item in signing_spends],
        unsignedProtocolEvidence=_unsigned_protocol_evidence_json(unsigned_evidence, settings.network),
        fundingEvidence=funding_evidence,
        selectedPaymentPublicKey=None,
        selectedPaymentCoinId=_hex32(context.payment_coin.name()),
        quoteExpiresAt=context.receipt.quote_expires_at,
        principalSolsMojos=str(quote.principal_sols_mojos),
        protocolFeeSolsMojos=str(
            quote.fee_split.protocol_fee_sols_mojos
        ),
        sgtRewardsFeeSolsMojos=str(
            quote.fee_split.sgt_rewards_fee_sols_mojos
        ),
        totalSolsMojos=str(quote.buyer_total_sols_mojos),
        destinationP2VaultHash=_hex32(destination),
        destinationPuzzleHash=_hex32(destination),
        vaultAuthType=vault_auth_type,
        vaultTypedData=vault_typed_data,
        review={
            "network": settings.network,
            "asset": "SOLS",
            "deedLauncherId": _hex32(context.receipt.record.deed_launcher_id),
            "vaultLauncherId": _hex32(context.vault_record.launcher_id),
            "principalSolsMojos": str(quote.principal_sols_mojos),
            "protocolFeeSolsMojos": str(
                quote.fee_split.protocol_fee_sols_mojos
            ),
            "sgtRewardsFeeSolsMojos": str(
                quote.fee_split.sgt_rewards_fee_sols_mojos
            ),
            "totalSolsMojos": str(quote.buyer_total_sols_mojos),
            "quoteExpiresAt": context.receipt.quote_expires_at,
            "atomic": True,
            "reversibleAfterSubmission": False,
        },
    )


async def _prepare_deed_to_sols_swap(
    *,
    vault_launcher_id: str,
    body: PrepareSolsSwapRequest,
    request: Request,
    settings: Settings,
) -> PrepareSolsSwapResponse:
    faucet = getattr(request.app.state, "faucet", None)
    if not isinstance(faucet, Faucet):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The protocol fountain is unavailable. No deed was moved."
            ),
        )
    try:
        context = await _load_reverse_swap_context(
            settings=settings,
            provider=request.app.state.coinset,
            faucet=faucet,
            vault_launcher_id=vault_launcher_id,
            deed_launcher_id=body.deed_launcher_id,
            seller_sols_puzzle_hash=None,
            quote_expires_at=None,
        )
        protocol = (
            _build_reverse_protocol_offer(context, signature_data=None)
            if context.vault_record.auth_type == AUTH_TYPE_BLS
            else None
        )
        unsigned_evidence = prepare_unsigned_deed_to_sols_swap(
            **_reverse_protocol_offer_arguments(context),
        )
        quote = context.receipt.deed_to_sols_quote
        if quote is None:
            raise SolsSwapOfferError("SmartDeed-to-Sols quote is unavailable.")
    except HTTPException:
        raise
    except (ChiaProviderError, PublicArtifactError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sols swap coordinates are unavailable: {exc}",
        ) from exc
    except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    expected_pool_output = Coin(
        context.pool_coin.name(),
        make_pool_v4_full(
            context.config,
            context.receipt.next_state,
        ).get_tree_hash(),
        context.pool_coin.amount,
    )
    try:
        _request_swap_store(request, settings).record_prepared(
            operation_hash=_hex32(context.receipt.operation_hash),
            direction="DEED_TO_SOLS",
            vault_launcher_id=_hex32(context.vault_record.launcher_id),
            deed_launcher_id=_hex32(context.receipt.record.deed_launcher_id),
            quote_expires_at=context.receipt.quote_expires_at,
            pool_input_coin_id=_hex32(context.pool_coin.name()),
            expected_pool_output_coin_id=_hex32(
                expected_pool_output.name()
            ),
            destination_puzzle_hash=_hex32(
                context.receipt.counterparty_puzzle_hash
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    funding_evidence = await _prepare_funding_review(request, settings, context, unsigned_evidence)
    return PrepareSolsSwapResponse(
        direction="DEED_TO_SOLS",
        operationHash=_hex32(context.receipt.operation_hash),
        deedLauncherId=_hex32(context.receipt.record.deed_launcher_id),
        vaultLauncherId=_hex32(context.vault_record.launcher_id),
        buyerOffer=(protocol.offer.to_bech32() if protocol else None),
        unsignedProtocolEvidence=_unsigned_protocol_evidence_json(unsigned_evidence, settings.network),
        fundingEvidence=funding_evidence,
        signingCoinSpends=(
            [_coin_spend_json(protocol.vault_spend)]
            if protocol is not None
            else []
        ),
        selectedPaymentPublicKey=None,
        selectedPaymentCoinId=_hex32(context.reserve_coin.name()),
        quoteExpiresAt=context.receipt.quote_expires_at,
        principalSolsMojos=str(quote.seller_sols_mojos),
        protocolFeeSolsMojos="0",
        sgtRewardsFeeSolsMojos="0",
        totalSolsMojos=str(quote.seller_sols_mojos),
        destinationP2VaultHash=None,
        destinationPuzzleHash=_hex32(
            context.receipt.counterparty_puzzle_hash
        ),
        freshSolsMojosMinted=str(quote.fresh_sols_mojos_minted),
        vaultAuthType=(
            "chia_bls"
            if context.vault_record.auth_type == AUTH_TYPE_BLS
            else "evm"
        ),
        vaultTypedData=(
            None
            if context.vault_record.auth_type == AUTH_TYPE_BLS
            else _vault_swap_typed_data(context)
        ),
        review={
            "network": settings.network,
            "direction": "DEED_TO_SOLS",
            "assetIn": "SmartDeed",
            "assetOut": "SOLS",
            "deedLauncherId": _hex32(
                context.receipt.record.deed_launcher_id
            ),
            "vaultLauncherId": _hex32(context.vault_record.launcher_id),
            "governedDeedValueMicroUsd": str(
                context.receipt.record.deed_value_micro_usd
            ),
            "sellerSolsMojos": str(quote.seller_sols_mojos),
            "freshSolsMojosMinted": str(
                quote.fresh_sols_mojos_minted
            ),
            "destinationPuzzleHash": _hex32(
                context.receipt.counterparty_puzzle_hash
            ),
            "quoteExpiresAt": context.receipt.quote_expires_at,
            "atomic": True,
            "reversibleAfterSubmission": False,
        },
    )


@router.post(
    "/vaults/{vault_launcher_id}/swaps/complete",
    response_model=CompleteSolsSwapResponse,
)
async def complete_sols_swap(
    vault_launcher_id: str,
    body: CompleteSolsSwapRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> CompleteSolsSwapResponse:
    _authorize_swap(settings, request, vault_launcher_id)
    if body.direction == "DEED_TO_SOLS":
        return await _complete_deed_to_sols_swap(
            vault_launcher_id=vault_launcher_id,
            body=body,
            request=request,
            settings=settings,
        )
    store = _request_swap_store(request, settings)
    existing = store.get(body.operation_hash)
    if existing is None:
        raise HTTPException(
            status_code=409,
            detail="Prepare this exact Sols swap before signing it.",
        )
    _require_operation_identity(
        existing,
        vault_launcher_id,
        body.deed_launcher_id,
        body.direction,
    )
    if existing.quote_expires_at != body.quote_expires_at:
        raise HTTPException(
            status_code=409,
            detail="Swap quote expiry does not match the prepared operation.",
        )
    if existing.status in ("SUBMITTED", "CONFIRMED"):
        return _complete_response(existing)
    lock = _swap_lock(request)
    async with lock:
        try:
            resumed = await _resume_swap_execution(request, settings, store, body.operation_hash)
            if resumed is not None:
                return _complete_response(resumed)
            if body.buyer_offer is None:
                raise SolsSwapOfferError(
                    "Prepared Sols payment offer is required."
                )
            decoded = await run_offer_job(
                "decode", encoded=body.buyer_offer, real_spends=1, dummy_spends=0,
            )
            buyer_spends = decoded.real_spends
            if len(buyer_spends) != 1:
                raise SolsSwapOfferError(
                    "Prepared buyer offer must spend one Sols coin."
                )
            context = await _load_swap_context(
                settings=settings,
                provider=request.app.state.coinset,
                vault_launcher_id=vault_launcher_id,
                deed_launcher_id=body.deed_launcher_id,
                quote_expires_at=body.quote_expires_at,
                sols_payment_coin_id=buyer_spends[0].coin.name(),
            )
            if _hex32(context.receipt.operation_hash) != body.operation_hash:
                raise SolsSwapOfferError(
                    "Swap operation no longer matches current chain state."
                )
            expected_buyer = prepare_vault_sols_buyer_offer(
                payment_coin=context.payment_coin,
                payment_lineage_proof=context.payment_lineage,
                receipt=context.receipt,
                config=context.config,
                vault_launcher_id=context.vault_record.launcher_id,
            )
            if decoded.raw != bytes(expected_buyer.offer):
                raise SolsSwapOfferError(
                    "Prepared buyer offer does not match live chain state."
                )
            unsigned = expected_buyer.offer
            validate_sols_buyer_offer(
                buyer_offer=unsigned,
                receipt=context.receipt,
                config=context.config,
                vault_launcher_id=context.vault_record.launcher_id,
            )
            evidence = prepare_unsigned_sols_to_deed_swap(buyer_offer=unsigned, **_protocol_offer_arguments(context))
            funding = _completion_funding_identity(request, settings, context, evidence, body)
            signature_data = _vault_signature_data(context, body)
            protocol = _build_protocol_offer(
                context,
                signature_data=signature_data,
            )
            if (
                context.vault_record.auth_type == AUTH_TYPE_BLS
                and body.aggregated_signature is None
            ):
                raise SolsSwapOfferError(
                    "Chia vault aggregate signature is required."
                )
            if (
                context.vault_record.auth_type == AUTH_TYPE_SECP256K1
                and body.aggregated_signature is not None
            ):
                raise SolsSwapOfferError(
                    "EVM vault swaps cannot add a Chia wallet signature."
                )
            wallet_signature = (
                G2Element()
                if body.aggregated_signature is None
                else G2Element.from_bytes(
                    _hex_bytes(
                        body.aggregated_signature,
                        96,
                        "aggregatedSignature",
                    )
                )
            )
            signed_buyer = Offer(
                unsigned.requested_payments,
                WalletSpendBundle(unsigned.coin_spends(), wallet_signature),
                unsigned.driver_dict,
            )
            atomic = aggregate_sols_to_deed_swap(
                buyer_offer=signed_buyer,
                protocol_offer=protocol,
                receipt=context.receipt,
                config=context.config,
                vault_launcher_id=context.vault_record.launcher_id,
            )
            valid_spend = atomic.aggregate_offer.to_valid_spend()
            await run_offer_job(
                "swap_signature", bundle=valid_spend, network=settings.network,
            )
            inputs = (
                context.pool_coin,
                context.statutes_coin,
                context.vault_coin,
                context.custody_coin,
                *tuple(spend.coin for spend in unsigned.coin_spends()),
            )
            await _require_inputs_clear(request.app.state.coinset, inputs)
            submitter = getattr(
                request.app.state,
                "protocol_submitter",
                None,
            )
            if not isinstance(submitter, ProtocolBundleSubmitter):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Protocol fee funding is unavailable. The swap was "
                        "not submitted."
                    ),
                )
            result = await submit_reserved_funding(
                submitter, store, evidence, funding, body.funding_reservation_hash, valid_spend,
                lambda: _funding_binding(request, settings, context),
                _seal_swap_execution(request, settings, store, existing, valid_spend,
                    funding_reservation_hash=body.funding_reservation_hash, funding_identity=funding,
                    funding_authorize=lambda: _funding_binding(request, settings, context)),
            )
            stored = store.mark_submitted(
                body.operation_hash,
                transaction_id=str(result["spendBundleId"]),
                fee_mojos=str(result["feeMojos"]),
                fee_target_seconds=int(result["feeTargetSeconds"]),
                submission_provider=str(result["submissionProvider"]),
                mempool_observed_at=str(result["mempoolObservedAt"]),
            )
        except HTTPException:
            raise
        except (ChiaProviderError, PublicArtifactError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sols swap coordinates are unavailable: {exc}",
            ) from exc
        except ProtocolSubmissionError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=_swap_submission_error(store, body.operation_hash, exc),
            ) from exc
        except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return _complete_response(
        stored,
    )


async def _complete_deed_to_sols_swap(
    *,
    vault_launcher_id: str,
    body: CompleteSolsSwapRequest,
    request: Request,
    settings: Settings,
) -> CompleteSolsSwapResponse:
    store = _request_swap_store(request, settings)
    existing = store.get(body.operation_hash)
    if existing is None:
        raise HTTPException(
            status_code=409,
            detail="Prepare this exact SmartDeed swap before signing it.",
        )
    _require_operation_identity(
        existing,
        vault_launcher_id,
        body.deed_launcher_id,
        body.direction,
    )
    if existing.quote_expires_at != body.quote_expires_at:
        raise HTTPException(
            status_code=409,
            detail="Swap quote expiry does not match the prepared operation.",
        )
    if existing.status in ("SUBMITTED", "CONFIRMED"):
        return _complete_response(existing)
    faucet = getattr(request.app.state, "faucet", None)
    if not isinstance(faucet, Faucet):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The protocol fountain is unavailable. The swap was not "
                "submitted."
            ),
        )
    payout_hash = _b32(
        existing.destination_puzzle_hash,
        "destinationPuzzleHash",
    )
    lock = _swap_lock(request)
    async with lock:
        try:
            resumed = await _resume_swap_execution(request, settings, store, body.operation_hash)
            if resumed is not None:
                return _complete_response(resumed)
            context = await _load_reverse_swap_context(
                settings=settings,
                provider=request.app.state.coinset,
                faucet=faucet,
                vault_launcher_id=vault_launcher_id,
                deed_launcher_id=body.deed_launcher_id,
                seller_sols_puzzle_hash=payout_hash,
                quote_expires_at=body.quote_expires_at,
            )
            if _hex32(context.receipt.operation_hash) != body.operation_hash:
                raise SolsSwapOfferError(
                    "Swap operation no longer matches current chain state."
                )
            if context.vault_record.auth_type == AUTH_TYPE_BLS:
                if body.buyer_offer is None:
                    raise SolsSwapOfferError(
                        "Prepared protocol offer is required."
                    )
                expected_unsigned = _build_reverse_protocol_offer(
                    context,
                    signature_data=None,
                )
                expected_spends = expected_unsigned.offer.to_spend_bundle().coin_spends
                dummy_count = sum(
                    spend.coin.parent_coin_info == bytes32.zeros
                    for spend in expected_spends
                )
                decoded = await run_offer_job(
                    "decode", encoded=body.buyer_offer,
                    real_spends=len(expected_spends) - dummy_count,
                    dummy_spends=dummy_count,
                )
                if decoded.raw != bytes(expected_unsigned.offer):
                    raise SolsSwapOfferError(
                        "Prepared protocol offer does not match live chain state."
                    )
            elif body.buyer_offer is not None:
                raise SolsSwapOfferError(
                    "EVM vault settlement is rebuilt from its signed receipt."
                )
            evidence = prepare_unsigned_deed_to_sols_swap(**_reverse_protocol_offer_arguments(context))
            funding = _completion_funding_identity(request, settings, context, evidence, body)
            signature_data = _vault_signature_data(context, body)
            protocol = _build_reverse_protocol_offer(
                context,
                signature_data=signature_data,
            )
            if (
                context.vault_record.auth_type == AUTH_TYPE_BLS
                and body.aggregated_signature is None
            ):
                raise SolsSwapOfferError(
                    "Chia vault aggregate signature is required."
                )
            if (
                context.vault_record.auth_type == AUTH_TYPE_SECP256K1
                and body.aggregated_signature is not None
            ):
                raise SolsSwapOfferError(
                    "EVM vault swaps cannot add a Chia wallet signature."
                )
            wallet_signature = (
                G2Element()
                if body.aggregated_signature is None
                else G2Element.from_bytes(
                    _hex_bytes(
                        body.aggregated_signature,
                        96,
                        "aggregatedSignature",
                    )
                )
            )
            reserve_signature = G2Element.from_bytes(
                faucet.sign_delegated_spend(
                    context.reserve_coin,
                    protocol.reserve_signing_conditions,
                )
            )
            unsigned_spend = protocol.offer.to_valid_spend()
            valid_spend = WalletSpendBundle(
                unsigned_spend.coin_spends,
                AugSchemeMPL.aggregate(
                    [wallet_signature, reserve_signature]
                ),
            )
            await run_offer_job(
                "swap_signature", bundle=valid_spend, network=settings.network,
            )
            await _require_inputs_clear(
                request.app.state.coinset,
                tuple(
                    spend.coin
                    for spend in protocol.offer.coin_spends()
                ),
            )
            submitter = getattr(
                request.app.state,
                "protocol_submitter",
                None,
            )
            if not isinstance(submitter, ProtocolBundleSubmitter):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Protocol fee funding is unavailable. The swap was "
                        "not submitted."
                    ),
                )
            result = await submit_reserved_funding(
                submitter, store, evidence, funding, body.funding_reservation_hash, valid_spend,
                lambda: _funding_binding(request, settings, context),
                _seal_swap_execution(request, settings, store, existing, valid_spend,
                    funding_reservation_hash=body.funding_reservation_hash, funding_identity=funding,
                    funding_authorize=lambda: _funding_binding(request, settings, context)),
            )
            stored = store.mark_submitted(
                body.operation_hash,
                transaction_id=str(result["spendBundleId"]),
                fee_mojos=str(result["feeMojos"]),
                fee_target_seconds=int(result["feeTargetSeconds"]),
                submission_provider=str(result["submissionProvider"]),
                mempool_observed_at=str(result["mempoolObservedAt"]),
            )
        except HTTPException:
            raise
        except (ChiaProviderError, PublicArtifactError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sols swap coordinates are unavailable: {exc}",
            ) from exc
        except ProtocolSubmissionError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=_swap_submission_error(store, body.operation_hash, exc),
            ) from exc
        except (KeyError, TypeError, ValueError, SolsSwapOfferError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _complete_response(stored)


@router.get(
    "/swaps/{operation_hash}",
    response_model=SolsSwapOperationResponse,
)
async def sols_swap_status(
    operation_hash: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SolsSwapOperationResponse:
    normalized = _hex32_text(operation_hash, "operationHash")
    store = _request_swap_store(request, settings)
    record = store.get(normalized)
    if record is None:
        raise HTTPException(status_code=404, detail="Sols swap was not found.")
    verify_vault_session(settings, request, record.vault_launcher_id)
    try:
        execution = store.execution(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=f"Sols swap confirmation is unavailable: {exc}") from exc
    if execution is not None and record.status != "CONFIRMED":
        try:
            if execution["network"] != settings.network:
                raise ValueError("retained swap belongs to another network")
            bundle = validate_execution(execution, pool_input_id=record.pool_input_coin_id,
                                        pool_output_id=record.expected_pool_output_coin_id)
            if await execution_confirmed(request.app.state.coinset, bundle, record.expected_pool_output_coin_id):
                record = store.mark_confirmed(normalized)
        except (ChiaProviderError, ValueError) as exc:
            raise HTTPException(status_code=503, detail=f"Sols swap confirmation is unavailable: {exc}") from exc
    elif record.status == "SUBMITTED":
        try:
            coin_record = await request.app.state.coinset.get_coin_record_by_name(
                record.expected_pool_output_coin_id
            )
            coin = _coin_from_record(coin_record)
            if (
                coin is not None
                and _hex32(coin.name())
                == record.expected_pool_output_coin_id
                and int((coin_record or {}).get("confirmed_block_index") or 0)
                > 0
            ):
                record = store.mark_confirmed(record.operation_hash)
        except ChiaProviderError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Sols swap confirmation is unavailable: {exc}",
            ) from exc
    return _operation_response(record)


def _authorize_swap(
    settings: Settings,
    request: Request,
    vault_launcher_id: str,
) -> None:
    require_alpha_writes(settings)
    if settings.network != "testnet11":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sols secondary swaps are restricted to Testnet Alpha.",
        )
    require_operation_gate(settings, "purchases")
    session = verify_vault_session(settings, request, vault_launcher_id)
    if session.vault_launcher_id != _hex32_text(
        vault_launcher_id,
        "vaultLauncherId",
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault session does not own this swap.",
        )


async def _load_swap_context(
    **kwargs,
) -> SolsSwapContext:
    return await _load_observed_context(_derive_swap_context, kwargs)


async def _load_observed_context(derive, kwargs):
    """Completion reconstruction also uses the primary; broadcast is outside this scope."""
    from .chia_snapshot import PrimaryReadSnapshot, active_snapshot
    if active_snapshot() is not None:
        return await derive(**kwargs)
    settings = kwargs["settings"]
    async with PrimaryReadSnapshot(kwargs["provider"], settings.network) as snapshot:
        context = await derive(**kwargs)
        snapshot.recheck(lambda: funding_digest(load_signed_public_artifact(settings)), funding_digest(context.artifact))
        snapshot.recheck(lambda: require_vault_record(context.approved_vault.launcher_id) == context.vault_record, True)
        snapshot.recheck(lambda: require_current_approved_vault(settings, context.approved_vault.launcher_id) == context.approved_vault, True)
        inputs = [("pool", context.pool_coin), ("statutes", context.statutes_coin), ("vault", context.vault_coin)]
        if isinstance(context, SolsSwapContext):
            inputs.extend([("deed_custody", context.custody_coin), ("sols_payment", context.payment_coin)])
        else:
            inputs.extend([("held_deed", context.deed.coin), ("sols_reserve", context.reserve_coin)])
        await snapshot.finish(inputs, {"quoteExpiresAt": context.receipt.quote_expires_at})
        return context


async def _derive_swap_context(
    *,
    settings: Settings,
    provider: ChiaProvider,
    vault_launcher_id: str,
    deed_launcher_id: str,
    quote_expires_at: int | None,
    sols_payment_coin_id: bytes32 | None = None,
) -> SolsSwapContext:
    now = int(time())
    if quote_expires_at is not None and (
        quote_expires_at <= now
        or quote_expires_at > now + SOLS_SWAP_QUOTE_TTL_SECONDS
    ):
        raise SolsSwapOfferError("Sols swap quote is expired or too far ahead.")
    artifact = load_signed_public_artifact(settings)
    launchers = artifact["launcherIds"]
    pool_tip = await _required_singleton_tip(
        provider,
        str(launchers["pool"]),
        "Pool V4",
    )
    statutes_tip = await _required_singleton_tip(
        provider,
        str(launchers["statutes"]),
        "protocol statutes",
    )
    pool_solution = await _latest_solution(provider, pool_tip)
    if pool_solution is None:
        pool = _initial_pool_state(pool_tip, artifact)
        raise SolsSwapOfferError("Pool V4 has no SmartDeed inventory.")
    pool = _decode_pool_state(pool_solution, pool_tip)
    statutes = await _statutes_snapshot(provider, statutes_tip, artifact)
    pool_state = _pool_protocol_state(pool)
    config = _pool_config(
        pool_solution,
        artifact,
        pool_tip,
    )
    deed_id = _b32(deed_launcher_id, "deedLauncherId")
    records = [
        item for item in pool.inventory if item.deed_launcher_id == deed_id
    ]
    if len(records) != 1:
        raise SolsSwapOfferError(
            "SmartDeed is not available in current Pool V4 inventory."
        )
    record = records[0]
    collections = [
        item
        for item in statutes.collections
        if item.collection_id == record.collection_id
    ]
    if len(collections) != 1:
        raise SolsSwapOfferError(
            "SmartDeed collection has no current governed statute."
        )
    collection = collections[0]
    pauses = [
        item
        for item in statutes.pauses
        if item.scope_id == record.collection_id
    ]
    if len(pauses) > 1:
        raise SolsSwapOfferError("Collection has ambiguous pause state.")
    pause = pauses[0] if pauses else None
    if quote_expires_at is None:
        quote_expires_at = min(
            now + SOLS_SWAP_QUOTE_TTL_SECONDS,
            collection.valid_until,
        )
        if quote_expires_at <= now:
            raise SolsSwapOfferError("Governed NAV is expired.")
    if quote_expires_at > collection.valid_until:
        raise SolsSwapOfferError("Sols swap quote outlives governed NAV.")

    approved = require_current_approved_vault(
        settings,
        vault_launcher_id,
    )
    vault_record = require_vault_record(approved.launcher_id)
    if vault_record.auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise SolsSwapOfferError("Vault owner authorization is unsupported.")
    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        provider,
        approved.current_coin_id,
        "approved vault coin",
    )
    pool_coin, pool_lineage = await _confirmed_coin_and_lineage(
        provider,
        pool_tip.live.coin_id,
        "Pool V4 coin",
    )
    statutes_coin, statutes_lineage = await _confirmed_coin_and_lineage(
        provider,
        statutes_tip.live.coin_id,
        "statutes coin",
    )
    custody_coin, custody_lineage = await _confirmed_coin_and_lineage(
        provider,
        _hex32(record.custody_coin_id),
        "SmartDeed custody coin",
    )
    members_root = one_leaf_merkle_root(bytes(vault_record.owner_pubkey))
    identity_root = _b32(
        approved.identity_attest_root,
        "identityAttestRoot",
    )
    expected_vault = puzzle_for_vault_v2_full(
        vault_launcher_id=vault_record.launcher_id,
        owner_pubkey=bytes(vault_record.owner_pubkey),
        auth_type=vault_record.auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=config.pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=(
            config.permanent_rules.zkpassport_policy_hash
        ),
    )
    if (
        vault_coin.puzzle_hash != expected_vault.get_tree_hash()
        or int(vault_coin.amount) != 1
    ):
        raise SolsSwapOfferError(
            "Approved vault coin does not match registered RC22 ownership."
        )
    quote = quote_sols_to_deed(
        pool_state.economics,
        deed_value_micro_usd=record.deed_value_micro_usd,
        exchange_fee_bps=statutes.parameters.exchange_fee_bps,
        protocol_fee_bps=statutes.parameters.protocol_fee_bps,
        sgt_rewards_fee_bps=statutes.parameters.sgt_rewards_fee_bps,
    )
    payment = await _select_vault_sols_payment_coin(
        provider=provider,
        config=config,
        vault_launcher_id=vault_record.launcher_id,
        required_amount=quote.buyer_total_sols_mojos,
        required_coin_id=sols_payment_coin_id,
    )
    if payment is None:
        raise SolsSwapOfferError(
            "No confirmed Sols coin in this vault can cover the swap."
        )
    receipt = prepare_sols_to_deed(
        pool_coin_id=pool_coin.name(),
        state=pool_state,
        inventory=pool.inventory,
        deed_launcher_id=record.deed_launcher_id,
        collection=collection,
        parameters=statutes.parameters,
        statutes_state=statutes.state,
        pause=pause,
        vault_launcher_id=vault_record.launcher_id,
        vault_coin_id=vault_coin.name(),
        sols_payment_coin_id=payment.coin.name(),
        destination_p2_vault_hash=puzzle_hash_for_p2_vault(
            vault_record.launcher_id
        ),
        quote_expires_at=quote_expires_at,
    )
    return SolsSwapContext(
        artifact=artifact,
        config=config,
        pool_state=pool_state,
        pool_inventory=pool.inventory,
        pool_coin=pool_coin,
        pool_lineage=pool_lineage,
        statutes=statutes,
        statutes_coin=statutes_coin,
        statutes_lineage=statutes_lineage,
        collection=collection,
        pause=pause,
        approved_vault=approved,
        vault_record=vault_record,
        vault_coin=vault_coin,
        vault_lineage=vault_lineage,
        custody_coin=custody_coin,
        custody_lineage=custody_lineage,
        payment_coin=payment.coin,
        payment_lineage=payment.lineage,
        receipt=receipt,
    )


def _protocol_offer_arguments(context: SolsSwapContext) -> dict[str, Any]:
    return {
        "receipt": context.receipt,
        "config": context.config,
        "parameters": context.statutes.parameters,
        "collection": context.collection,
        "pause": context.pause,
        "statutes_state": context.statutes.state,
        "statutes_coin": context.statutes_coin,
        "statutes_launcher_id": _b32(
            context.artifact["launcherIds"]["statutes"],
            "statutesLauncherId",
        ),
        "statutes_lineage_proof": context.statutes_lineage,
        "collections": context.statutes.collections,
        "pauses": context.statutes.pauses,
        "vault_coin": context.vault_coin,
        "vault_launcher_id": context.vault_record.launcher_id,
        "vault_lineage_proof": context.vault_lineage,
        "vault_owner_pubkey": bytes(context.vault_record.owner_pubkey),
        "vault_auth_type": context.vault_record.auth_type,
        "vault_members_merkle_root": one_leaf_merkle_root(
            bytes(context.vault_record.owner_pubkey)
        ),
        "identity_attest_root": _b32(
            context.approved_vault.identity_attest_root,
            "identityAttestRoot",
        ),
        "zkpassport_bridge_policy_hash": context.config.permanent_rules.zkpassport_policy_hash,
        "pool_coin": context.pool_coin,
        "pool_lineage_proof": context.pool_lineage,
        "custody_coin": context.custody_coin,
        "custody_lineage_proof": context.custody_lineage,
        "quote_expires_at": context.receipt.quote_expires_at,
    }


def _build_protocol_offer(
    context: SolsSwapContext, *, signature_data: bytes | None,
) -> Any:
    return build_sols_to_deed_protocol_offer(
        **_protocol_offer_arguments(context), vault_signature_data=signature_data,
    )


async def _load_reverse_swap_context(
    **kwargs,
) -> ReverseSolsSwapContext:
    return await _load_observed_context(_derive_reverse_swap_context, kwargs)


async def _derive_reverse_swap_context(
    *,
    settings: Settings,
    provider: ChiaProvider,
    faucet: Faucet,
    vault_launcher_id: str,
    deed_launcher_id: str,
    seller_sols_puzzle_hash: bytes32 | None,
    quote_expires_at: int | None,
) -> ReverseSolsSwapContext:
    now = int(time())
    if quote_expires_at is not None and (
        quote_expires_at <= now
        or quote_expires_at > now + SOLS_SWAP_QUOTE_TTL_SECONDS
    ):
        raise SolsSwapOfferError("Sols swap quote is expired or too far ahead.")
    artifact = load_signed_public_artifact(settings)
    launchers = artifact["launcherIds"]
    pool_tip = await _required_singleton_tip(
        provider,
        str(launchers["pool"]),
        "Pool V4",
    )
    statutes_tip = await _required_singleton_tip(
        provider,
        str(launchers["statutes"]),
        "protocol statutes",
    )
    pool_solution = await _latest_solution(provider, pool_tip)
    if pool_solution is None:
        pool = _initial_pool_state(pool_tip, artifact)
    else:
        pool = _decode_pool_state(pool_solution, pool_tip)
    statutes = await _statutes_snapshot(provider, statutes_tip, artifact)
    pool_state = _pool_protocol_state(pool)
    config = _pool_config(pool_solution, artifact, pool_tip) if pool_solution else (
        _initial_pool_config(artifact, pool_tip)
    )

    approved = require_current_approved_vault(
        settings,
        vault_launcher_id,
    )
    vault_record = require_vault_record(approved.launcher_id)
    if vault_record.auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise SolsSwapOfferError("Vault owner authorization is unsupported.")
    owner_key = bytes(vault_record.owner_pubkey)
    expected_payout = bytes32(
        puzzle_for_vault_sols_inner(
            config=config,
            vault_launcher_id=vault_record.launcher_id,
        ).get_tree_hash()
    )
    if (
        seller_sols_puzzle_hash is not None
        and seller_sols_puzzle_hash != expected_payout
    ):
        raise SolsSwapOfferError(
            "Sols payout does not match the vault-bound custody puzzle."
        )
    seller_sols_puzzle_hash = expected_payout

    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        provider,
        approved.current_coin_id,
        "approved vault coin",
    )
    pool_coin, pool_lineage = await _confirmed_coin_and_lineage(
        provider,
        pool_tip.live.coin_id,
        "Pool V4 coin",
    )
    statutes_coin, statutes_lineage = await _confirmed_coin_and_lineage(
        provider,
        statutes_tip.live.coin_id,
        "statutes coin",
    )
    identity_root = _b32(
        approved.identity_attest_root,
        "identityAttestRoot",
    )
    expected_vault = puzzle_for_vault_v2_full(
        vault_launcher_id=vault_record.launcher_id,
        owner_pubkey=owner_key,
        auth_type=vault_record.auth_type,
        members_merkle_root=one_leaf_merkle_root(owner_key),
        pool_launcher_id=config.pool_launcher_id,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=(
            config.permanent_rules.zkpassport_policy_hash
        ),
    )
    if (
        vault_coin.puzzle_hash != expected_vault.get_tree_hash()
        or int(vault_coin.amount) != 1
    ):
        raise SolsSwapOfferError(
            "Approved vault coin does not match registered RC22 ownership."
        )

    deed = await _load_vault_held_deed(
        provider=provider,
        config=config,
        vault_launcher_id=vault_record.launcher_id,
        deed_launcher_id=deed_launcher_id,
        settings=settings,
        artifact=artifact,
    )
    collections = [
        item
        for item in statutes.collections
        if item.collection_id == deed.collection_id
    ]
    if len(collections) != 1:
        raise SolsSwapOfferError(
            "SmartDeed collection has no current governed statute."
        )
    collection = collections[0]
    pauses = [
        item
        for item in statutes.pauses
        if item.scope_id == collection.collection_id
    ]
    if len(pauses) > 1:
        raise SolsSwapOfferError("Collection has ambiguous pause state.")
    pause = pauses[0] if pauses else None
    if quote_expires_at is None:
        quote_expires_at = min(
            now + SOLS_SWAP_QUOTE_TTL_SECONDS,
            collection.valid_until,
        )
        if quote_expires_at <= now:
            raise SolsSwapOfferError("Governed NAV is expired.")
    if quote_expires_at > collection.valid_until:
        raise SolsSwapOfferError("Sols swap quote outlives governed NAV.")

    custody_inner = load_puzzle("p2_pool_v2.clsp").curry(
        config.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        config.pool_launcher_id,
        SINGLETON_LAUNCHER_HASH,
        deed.deed_commitment,
    )
    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (
                _b32(deed_launcher_id, "deedLauncherId"),
                config.deed_launcher_puzzle_hash,
            ),
        )
    )
    ephemeral = Coin(
        deed.coin.name(),
        bytes32(
            SINGLETON_MOD.curry(
                deed_struct,
                deed.smart_deed_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    custody_coin = Coin(
        ephemeral.name(),
        bytes32(
            SINGLETON_MOD.curry(
                deed_struct,
                custody_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    reserve_coin, reserve_lineage = await _load_reserve_cat(
        provider=provider,
        artifact=artifact,
        config=config,
        pool_state=pool_state,
        reserve_inner_puzzle=faucet.key.puzzle,
    )
    receipt = prepare_deed_to_sols(
        pool_coin_id=pool_coin.name(),
        state=pool_state,
        inventory=pool.inventory,
        deed_launcher_id=_b32(deed_launcher_id, "deedLauncherId"),
        custody_coin_id=custody_coin.name(),
        deed_commitment=deed.deed_commitment,
        collection=collection,
        share_ppm=deed.share_ppm,
        parameters=statutes.parameters,
        statutes_state=statutes.state,
        pause=pause,
        vault_launcher_id=vault_record.launcher_id,
        vault_coin_id=vault_coin.name(),
        seller_sols_puzzle_hash=seller_sols_puzzle_hash,
        quote_expires_at=quote_expires_at,
    )
    return ReverseSolsSwapContext(
        artifact=artifact,
        config=config,
        pool_state=pool_state,
        pool_inventory=pool.inventory,
        pool_coin=pool_coin,
        pool_lineage=pool_lineage,
        statutes=statutes,
        statutes_coin=statutes_coin,
        statutes_lineage=statutes_lineage,
        collection=collection,
        pause=pause,
        approved_vault=approved,
        vault_record=vault_record,
        vault_coin=vault_coin,
        vault_lineage=vault_lineage,
        deed=deed,
        reserve_coin=reserve_coin,
        reserve_lineage=reserve_lineage,
        reserve_inner_puzzle=faucet.key.puzzle,
        receipt=receipt,
    )


def _reverse_protocol_offer_arguments(context: ReverseSolsSwapContext) -> dict[str, Any]:
    return {
        "receipt": context.receipt,
        "config": context.config,
        "parameters": context.statutes.parameters,
        "collection": context.collection,
        "pause": context.pause,
        "statutes_state": context.statutes.state,
        "statutes_coin": context.statutes_coin,
        "statutes_launcher_id": _b32(
            context.artifact["launcherIds"]["statutes"],
            "statutesLauncherId",
        ),
        "statutes_lineage_proof": context.statutes_lineage,
        "collections": context.statutes.collections,
        "pauses": context.statutes.pauses,
        "vault_coin": context.vault_coin,
        "vault_launcher_id": context.vault_record.launcher_id,
        "vault_lineage_proof": context.vault_lineage,
        "vault_owner_pubkey": bytes(context.vault_record.owner_pubkey),
        "vault_auth_type": context.vault_record.auth_type,
        "vault_members_merkle_root": one_leaf_merkle_root(
            bytes(context.vault_record.owner_pubkey)
        ),
        "identity_attest_root": _b32(
            context.approved_vault.identity_attest_root,
            "identityAttestRoot",
        ),
        "zkpassport_bridge_policy_hash": context.config.permanent_rules.zkpassport_policy_hash,
        "pool_coin": context.pool_coin,
        "pool_lineage_proof": context.pool_lineage,
        'p2_vault_deed_coin': context.deed.coin,
        'p2_vault_deed_lineage_proof': context.deed.lineage,
        "smart_deed_inner": context.deed.smart_deed_inner,
        "par_value": context.deed.par_value,
        "asset_class": context.deed.asset_class,
        "property_id": context.deed.property_id,
        "reserve_cat_coin": context.reserve_coin,
        "reserve_cat_lineage_proof": context.reserve_lineage,
        "reserve_inner_puzzle": context.reserve_inner_puzzle,
        "quote_expires_at": context.receipt.quote_expires_at,
    }


def _build_reverse_protocol_offer(
    context: ReverseSolsSwapContext, *, signature_data: bytes | None,
) -> Any:
    return build_deed_to_sols_protocol_offer(
        **_reverse_protocol_offer_arguments(context), vault_signature_data=signature_data,
    )


def _initial_pool_config(
    artifact: Mapping[str, Any],
    tip: SingletonTip,
) -> PoolV4Config:
    hashes = artifact["puzzleHashes"]
    trusted = artifact["genesisPlan"]["trustedDestinations"]
    config = PoolV4Config(
        pool_launcher_id=_b32(tip.launcher_id, "poolLauncherId"),
        statutes_inner_mod_hash=_b32(
            hashes["statutesInnerModHash"],
            "statutesInnerModHash",
        ),
        statutes_singleton_struct=_singleton_struct(
            str(artifact["launcherIds"]["statutes"])
        ),
        governance_singleton_struct=_singleton_struct(
            str(artifact["launcherIds"]["governance"])
        ),
        permanent_rules=_artifact_permanent_rules(artifact),
        cat_mod_hash=bytes32(CAT_MOD.get_tree_hash()),
        offer_mod_hash=OFFER_MOD_HASH,
        p2_vault_mod_hash=bytes32(
            load_puzzle("p2_vault.clsp").get_tree_hash()
        ),
        vault_v2_mod_hash=_b32(
            hashes["vaultInnerModHash"],
            "vaultInnerModHash",
        ),
        p2_pool_v2_mod_hash=bytes32(
            load_puzzle("p2_pool_v2.clsp").get_tree_hash()
        ),
        deed_launcher_puzzle_hash=_b32(
            hashes["deedLauncherPuzzleHash"],
            "deedLauncherPuzzleHash",
        ),
        reserve_puzzle_hash=_b32(
            trusted["treasuryReservePuzzleHash"],
            "treasuryReservePuzzleHash",
        ),
        sgt_rewards_puzzle_hash=_b32(
            trusted["governanceRewardsPuzzleHash"],
            "governanceRewardsPuzzleHash",
        ),
    )
    initial_state = _pool_protocol_state(_initial_pool_state(tip, artifact))
    if _hex32(
        make_pool_v4_full(config, initial_state).get_tree_hash()
    ) != str(hashes["poolFullPuzzleHash"]).lower():
        raise SolsSwapOfferError(
            "Initial Pool V4 configuration does not match signed genesis."
        )
    return config


async def _load_vault_held_deed(
    *,
    provider: ChiaProvider,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
    deed_launcher_id: str,
    settings: Settings | None = None,
    artifact: Mapping[str, Any] | None = None,
) -> VaultHeldDeed:
    normalized = _hex32_text(deed_launcher_id, "deedLauncherId")
    tip = await _singleton_tip(provider, normalized)
    if tip is None:
        raise SolsSwapOfferError("SmartDeed launcher is not confirmed.")
    deed_id = _b32(normalized, "deedLauncherId")
    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (deed_id, config.deed_launcher_puzzle_hash),
        )
    )
    held_inner = load_puzzle("p2_vault.clsp").curry(
        SINGLETON_MOD_HASH,
        vault_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )
    expected_held = SINGLETON_MOD.curry(deed_struct, held_inner)
    if tip.live.puzzle_hash.lower() != _hex32(
        expected_held.get_tree_hash()
    ):
        raise SolsSwapOfferError(
            "SmartDeed is not held by this approved vault."
        )
    last_spend = await _latest_solution(provider, tip)
    if not isinstance(last_spend, Mapping):
        raise SolsSwapOfferError(
            "SmartDeed immutable terms are unavailable from chain."
        )
    prior_full = _program(str(last_spend["puzzle_reveal"]))
    from .sols_market import _singleton_spend, MAX_SINGLETON_EVIDENCE_COST
    cursor = len(tip.lineage) - 2
    custody_commitment = None
    remaining_cost = MAX_SINGLETON_EVIDENCE_COST
    for leg in range(3):
        full_mod, full_args_program = prior_full.uncurry()
        full_args = list(full_args_program.as_iter())
        if (full_mod.get_tree_hash() != SINGLETON_MOD_HASH or len(full_args) != 2
            or bytes(full_args[0]) != bytes(deed_struct)):
            raise SolsSwapOfferError("SmartDeed singleton identity does not match RC22.")
        smart_inner = full_args[1]
        inner_mod, inner_args = smart_inner.uncurry()
        pool_custody = inner_mod.get_tree_hash() == config.p2_pool_v2_mod_hash
        if leg == 0 and smart_inner.get_tree_hash() == OFFER_MOD_HASH:
            # Native primary offers settle through one ephemeral OFFER_MOD
            # singleton. Authenticate that exact preceding link before reading
            # the inventory commitment; never search arbitrary old metadata.
            if cursor < 1 or tip.lineage[cursor-1].spent_height != tip.lineage[cursor].spent_height:
                raise SolsSwapOfferError("SmartDeed offer settlement is not atomic.")
        elif pool_custody and custody_commitment is None and leg < 2:
            # A pool withdrawal's previous immutable reveal is the deposit
            # that created this exact custody coin, possibly in an older block.
            values = list(inner_args.as_iter())
            if (len(values) != 5 or values[0].as_atom() != bytes(config.p2_pool_v2_mod_hash)
                or values[1].as_atom() != bytes(SINGLETON_MOD_HASH)
                or values[2].as_atom() != bytes(config.pool_launcher_id)
                or values[3].as_atom() != bytes(SINGLETON_LAUNCHER_HASH)
                or len(values[4].as_atom()) != 32 or cursor < 1):
                raise SolsSwapOfferError("SmartDeed custody does not match the governed pool.")
            custody_commitment = bytes32(values[4].as_atom())
        else:
            break
        preceding, consumed_cost = await _singleton_spend(provider,tip.lineage[cursor-1],tip.lineage[cursor],
            max_cost=remaining_cost)
        remaining_cost -= consumed_cost
        cursor -= 1
        prior_full = _program(str(preceding["puzzle_reveal"]))
    smart_uncurried = smart_inner.uncurry()
    if smart_uncurried is None:
        raise SolsSwapOfferError("SmartDeed immutable puzzle is malformed.")
    smart_mod, smart_args_program = smart_uncurried
    smart_args = list(smart_args_program.as_iter())
    if custody_commitment is not None and smart_mod.get_tree_hash() != load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash():
        raise SolsSwapOfferError("Pool custody has no exact SmartDeed deposit predecessor.")
    if smart_mod.get_tree_hash() == load_puzzle("mint_offer_delegate_v5.clsp").get_tree_hash():
        # A primary purchase delivers directly from inventory into vault
        # custody. Its confirmed parent commits to the SmartDeed inner hash,
        # while the persisted mint record provides the immutable preimage.
        from .deed_witness import primary_deed_inner
        from .mint_endpoints import get_mint_proposal_store
        if settings is None or artifact is None:
            raise SolsSwapOfferError("Primary SmartDeed mint witness is unavailable.")
        try:
            record = get_mint_proposal_store(settings).get_by_deed_launcher_id(bytes(deed_id))
            smart_inner = primary_deed_inner(record=record,deed_id=deed_id,deed_struct=deed_struct,
                inventory_args=smart_args,config=config,artifact=artifact)
        except (KeyError, TypeError, ValueError) as exc:
            raise SolsSwapOfferError("Primary SmartDeed mint witness does not match chain.") from exc
        smart_mod, smart_args_program = smart_inner.uncurry()
        smart_args = list(smart_args_program.as_iter())
    if (
        smart_mod.get_tree_hash()
        != load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        or len(smart_args) != 15
    ):
        raise SolsSwapOfferError("SmartDeed is not the RC22 V2 asset.")
    if bytes(smart_args[0]) != bytes(deed_struct):
        raise SolsSwapOfferError(
            "SmartDeed inner singleton identity does not match launcher."
        )
    par_value = int(smart_args[2].as_int())
    asset_class = int(smart_args[3].as_int())
    property_id = bytes32(smart_args[4].as_atom())
    collection_id = bytes32(smart_args[5].as_atom())
    share_ppm = int(smart_args[6].as_int())
    commitment = deed_metadata_commitment(
        deed_id,
        par_value,
        asset_class,
        property_id,
        collection_id,
        share_ppm,
    )
    if custody_commitment is not None and custody_commitment != commitment:
        raise SolsSwapOfferError("SmartDeed deposit does not match the pool custody commitment.")
    coin, lineage = await _confirmed_coin_and_lineage(
        provider,
        tip.live.coin_id,
        "vault-held SmartDeed",
    )
    return VaultHeldDeed(
        coin=coin,
        lineage=lineage,
        smart_deed_inner=smart_inner,
        par_value=par_value,
        asset_class=asset_class,
        property_id=property_id,
        collection_id=collection_id,
        share_ppm=share_ppm,
        deed_commitment=commitment,
    )


async def _load_reserve_cat(
    *,
    provider: ChiaProvider,
    artifact: Mapping[str, Any],
    config: PoolV4Config,
    pool_state: SolsPoolStateV4,
    reserve_inner_puzzle: Program,
) -> tuple[Coin, LineageProof]:
    reserve_inner_hash = bytes32(reserve_inner_puzzle.get_tree_hash())
    if reserve_inner_hash != config.reserve_puzzle_hash:
        raise SolsSwapOfferError(
            "Protocol fountain does not control the governed Sols reserve."
        )
    reserve_puzzle = construct_cat_puzzle(
        CAT_MOD,
        config.permanent_rules.sols_tail_hash,
        reserve_inner_puzzle,
    )
    records = await provider.get_coin_records_by_puzzle_hash(
        _hex32(reserve_puzzle.get_tree_hash()),
        include_spent=False,
    )
    candidates = [
        coin
        for record in records
        if (
            (coin := _coin_from_record(record)) is not None
            and _record_is_unspent_coin(record, coin)
            and int(coin.amount)
            == pool_state.economics.reserve_sols_mojos
        )
    ]
    if len(candidates) != 1:
        raise SolsSwapOfferError(
            "Sols reserve must be one exact unspent CAT anchor."
        )
    coin = candidates[0]
    seed_id = _hex32_text(
        str(artifact["solsReserveSeed"]["coinId"]),
        "solsReserveSeed.coinId",
    )
    if _hex32(coin.name()) == seed_id:
        if int(coin.amount) != 1:
            raise SolsSwapOfferError("Sols reserve seed amount is invalid.")
        return coin, LineageProof()
    return coin, await _confirmed_cat_lineage(
        provider=provider,
        coin=coin,
        expected_inner_hash=reserve_inner_hash,
        expected_tail_hash=config.permanent_rules.sols_tail_hash,
    )


async def _confirmed_cat_lineage(
    *,
    provider: ChiaProvider,
    coin: Coin,
    expected_inner_hash: bytes32,
    expected_tail_hash: bytes32,
) -> LineageProof:
    parent_id = _hex32(coin.parent_coin_info)
    parent_record = await provider.get_coin_record_by_name(parent_id)
    parent_coin = _coin_from_record(parent_record)
    child_record = await provider.get_coin_record_by_name(_hex32(coin.name()))
    child_height = int((child_record or {}).get("confirmed_block_index") or 0)
    parent_height = int((parent_record or {}).get("spent_block_index") or 0)
    if (
        parent_coin is None
        or parent_coin.name() != coin.parent_coin_info
        or child_height <= 0
        or parent_height != child_height
    ):
        raise SolsSwapOfferError("Sols CAT lineage is not atomic.")
    parent_solution = await provider.get_puzzle_and_solution(
        parent_id,
        parent_height,
    )
    if not isinstance(parent_solution, Mapping):
        raise SolsSwapOfferError("Sols CAT parent spend is unavailable.")
    parent_puzzle = _program(str(parent_solution["puzzle_reveal"]))
    uncurried = parent_puzzle.uncurry()
    if uncurried is None:
        raise SolsSwapOfferError("Sols CAT parent puzzle is malformed.")
    parent_mod, parent_args = uncurried
    args = list(parent_args.as_iter())
    if (
        parent_mod.get_tree_hash() != CAT_MOD.get_tree_hash()
        or len(args) < 3
        or bytes32(args[1].as_atom()) != expected_tail_hash
    ):
        raise SolsSwapOfferError("Sols CAT parent uses an unexpected tail.")
    inner = get_innerpuzzle_from_puzzle(parent_puzzle)
    if bytes32(inner.get_tree_hash()) != expected_inner_hash:
        raise SolsSwapOfferError("Sols CAT parent uses an unexpected owner.")
    return LineageProof(
        parent_name=parent_coin.parent_coin_info,
        inner_puzzle_hash=expected_inner_hash,
        amount=parent_coin.amount,
    )


def _vault_swap_typed_data(context: SolsSwapContext | ReverseSolsSwapContext) -> dict:
    intent: dict[str, Any] = {
        "pool_coin_id": context.pool_coin.name(),
        "pool_inner_puzzle_hash": bytes32(
            make_pool_v4_inner(context.config, context.receipt.current_state).get_tree_hash()
        ),
        "quote_expires_at": context.receipt.quote_expires_at,
    }
    if context.receipt.direction == DEED_TO_SOLS:
        intent.update(
            deed_launcher_id=context.receipt.record.deed_launcher_id,
            p2_vault_coin_id=context.deed.coin.name(),
            smart_deed_inner_puzzle_hash=bytes32(context.deed.smart_deed_inner.get_tree_hash()),
        )
    return eip712_typed_data_for_sols_swap(
        context.receipt.operation_hash, context.vault_coin.name(), **intent,
    )


def _vault_signature_data(
    context: SolsSwapContext | ReverseSolsSwapContext,
    body: CompleteSolsSwapRequest,
) -> bytes | None:
    record = context.vault_record
    if record.auth_type == AUTH_TYPE_BLS:
        if body.vault_owner_authorization is not None:
            raise SolsSwapOfferError(
                "BLS vault authorization belongs in the aggregate signature."
            )
        return None
    if not body.vault_owner_authorization or not record.owner_evm_address:
        raise SolsSwapOfferError("EVM vault owner authorization is required.")
    typed_data = _vault_swap_typed_data(context)
    recovered = recover_evm_signer(
        typed_data,
        body.vault_owner_authorization,
    )
    if recovered.address.lower() != record.owner_evm_address.lower():
        raise SolsSwapOfferError(
            "EVM signature does not belong to this vault owner."
        )
    return compact_signature_from_evm(body.vault_owner_authorization)


async def _select_vault_sols_payment_coin(
    *,
    provider: ChiaProvider,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
    required_amount: int,
    required_coin_id: bytes32 | None = None,
) -> VaultSolsPaymentCoin | None:
    from .cat_lineage import confirmed_cat_receipt_lineage
    inner = puzzle_for_vault_sols_inner(
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    cat = puzzle_for_vault_sols_cat(
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    records = await provider.get_coin_records_by_puzzle_hash(
        _hex32(cat.get_tree_hash()),
        include_spent=False,
    )
    candidates: list[Coin] = []
    for record in records:
        coin = _coin_from_record(record)
        if (
            coin is None
            or not _record_is_unspent_coin(record, coin)
            or int(coin.amount) < required_amount
            or (
                required_coin_id is not None
                and coin.name() != required_coin_id
            )
        ):
            continue
        candidates.append(coin)
    for coin in sorted(
        candidates,
        key=lambda item: (int(item.amount), bytes(item.name())),
    ):
        if await provider.get_mempool_items_by_coin_name(_hex32(coin.name())):
            continue
        try:
            confirmed = await _confirmed_unspent_coin(
                provider,
                _hex32(coin.name()),
                "vault Sols payment coin",
            )
            lineage = await confirmed_cat_receipt_lineage(
                provider=provider,
                coin=confirmed,
                expected_inner_hash=bytes32(inner.get_tree_hash()),
                expected_tail_hash=config.permanent_rules.sols_tail_hash,
                asset_label='Sols',
            )
        except (ValueError, SolsSwapOfferError):
            continue
        return VaultSolsPaymentCoin(coin=confirmed, lineage=lineage)
    return None


async def _confirmed_unspent_coin(
    provider: ChiaProvider,
    coin_id: str,
    label: str,
) -> Coin:
    normalized = _hex32_text(coin_id, label)
    record = await provider.get_coin_record_by_name(normalized)
    coin = _coin_from_record(record)
    if (
        coin is None
        or not _record_is_unspent_coin(record, coin)
        or _hex32(coin.name()) != normalized
    ):
        raise ValueError(f"{label} is not confirmed and unspent")
    return coin


async def _confirmed_coin_and_lineage(
    provider: ChiaProvider,
    coin_id: str,
    label: str,
) -> tuple[Coin, LineageProof]:
    normalized = _hex32_text(coin_id, label)
    record = await provider.get_coin_record_by_name(normalized)
    coin = _coin_from_record(record)
    if (
        coin is None
        or not _record_is_unspent_coin(record, coin)
        or _hex32(coin.name()) != normalized
    ):
        raise ValueError(f"{label} is not confirmed and unspent")
    parent_id = _hex32(coin.parent_coin_info)
    parent_record = await provider.get_coin_record_by_name(parent_id)
    parent_coin = _coin_from_record(parent_record)
    child_height = int((record or {}).get("confirmed_block_index") or 0)
    parent_height = int((parent_record or {}).get("spent_block_index") or 0)
    if (
        parent_coin is None
        or parent_coin.name() != coin.parent_coin_info
        or child_height <= 0
        or parent_height != child_height
    ):
        raise ValueError(f"{label} lineage is not atomic")
    parent_solution = await provider.get_puzzle_and_solution(
        parent_id,
        parent_height,
    )
    if not isinstance(parent_solution, Mapping):
        raise ValueError(f"{label} parent spend is unavailable")
    try:
        parent_spend = make_spend(
            parent_coin,
            _program(str(parent_solution["puzzle_reveal"])),
            _program(str(parent_solution["solution"])),
        )
        lineage = lineage_proof_for_coinsol(parent_spend)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} parent spend is malformed") from exc
    return coin, lineage


def _pool_config(
    pool_solution: Mapping[str, Any],
    artifact: Mapping[str, Any],
    tip: SingletonTip,
) -> PoolV4Config:
    full = _program(str(pool_solution["puzzle_reveal"]))
    full_uncurried = full.uncurry()
    if full_uncurried is None:
        raise SolsSwapOfferError("Pool V4 puzzle is not curried.")
    _full_mod, full_args_program = full_uncurried
    full_args = list(full_args_program.as_iter())
    if len(full_args) != 2:
        raise SolsSwapOfferError("Pool V4 singleton arguments are malformed.")
    inner_uncurried = full_args[1].uncurry()
    if inner_uncurried is None:
        raise SolsSwapOfferError("Pool V4 inner puzzle is not curried.")
    _inner_mod, inner_args_program = inner_uncurried
    inner_args = list(inner_args_program.as_iter())
    if len(inner_args) != 13:
        raise SolsSwapOfferError("Pool V4 inner arguments are malformed.")
    statutes_values = list(inner_args[2].as_iter())
    market_values = list(inner_args[3].as_iter())
    if len(statutes_values) != 9 or len(market_values) != 8:
        raise SolsSwapOfferError("Pool V4 immutable configuration is malformed.")
    permanent = PermanentRules(
        sgt_tail_hash=_node_b32(statutes_values[3], "SGT tail"),
        sgt_total_supply=int(statutes_values[4].as_int()),
        sols_tail_hash=_node_b32(statutes_values[5], "Sols tail"),
        zkpassport_policy_hash=_node_b32(
            statutes_values[6],
            "zkPassport policy",
        ),
        protocol_treasury_puzzle_hash=_node_b32(
            statutes_values[7],
            "protocol treasury",
        ),
        network_id=_node_b32(statutes_values[8], "network ID"),
    ).validate()
    if permanent != _artifact_permanent_rules(artifact):
        raise SolsSwapOfferError(
            "Pool V4 permanent rules do not match signed genesis."
        )
    pool_launcher = _b32(tip.launcher_id, "poolLauncherId")
    if bytes(inner_args[1]) != bytes(_singleton_struct(tip.launcher_id)):
        raise SolsSwapOfferError("Pool V4 singleton binding is invalid.")
    statutes_launcher = str(artifact["launcherIds"]["statutes"])
    governance_launcher = str(artifact["launcherIds"]["governance"])
    if (
        bytes(statutes_values[1]) != bytes(_singleton_struct(statutes_launcher))
        or bytes(statutes_values[2])
        != bytes(_singleton_struct(governance_launcher))
    ):
        raise SolsSwapOfferError(
            "Pool V4 statutes or governance binding is invalid."
        )
    deed_launcher_hash = _node_b32(
        market_values[5],
        "deed launcher puzzle",
    )
    if _hex32(deed_launcher_hash) != str(
        artifact["puzzleHashes"]["deedLauncherPuzzleHash"]
    ).lower():
        raise SolsSwapOfferError(
            "Pool V4 deed launcher does not match signed genesis."
        )
    return PoolV4Config(
        pool_launcher_id=pool_launcher,
        statutes_inner_mod_hash=_node_b32(
            statutes_values[0],
            "statutes module",
        ),
        statutes_singleton_struct=statutes_values[1],
        governance_singleton_struct=statutes_values[2],
        permanent_rules=permanent,
        cat_mod_hash=_node_b32(market_values[0], "CAT module"),
        offer_mod_hash=_node_b32(market_values[1], "offer module"),
        p2_vault_mod_hash=_node_b32(market_values[2], "p2 vault module"),
        vault_v2_mod_hash=_node_b32(market_values[3], "vault module"),
        p2_pool_v2_mod_hash=_node_b32(market_values[4], "p2 pool module"),
        deed_launcher_puzzle_hash=deed_launcher_hash,
        reserve_puzzle_hash=_node_b32(market_values[6], "reserve puzzle"),
        sgt_rewards_puzzle_hash=_node_b32(
            market_values[7],
            "SGT rewards puzzle",
        ),
    )


def _pool_protocol_state(pool: PoolState) -> SolsPoolStateV4:
    return SolsPoolStateV4(
        inventory_root=inventory_root(pool.inventory),
        economics=SolsEconomicState(
            bootstrap_complete=pool.bootstrap_complete,
            inventory_nav_micro_usd=pool.inventory_nav_micro_usd,
            treasury_assets_micro_usd=pool.treasury_assets_micro_usd,
            proven_liabilities_micro_usd=pool.proven_liabilities_micro_usd,
            deed_count=pool.deed_count,
            total_sols_mojos=pool.total_sols_mojos,
            reserve_sols_mojos=pool.reserve_sols_mojos,
        ),
        state_version=pool.state_version,
    ).validate(pool.inventory)


def _verify_aggregate_signature(
    bundle: WalletSpendBundle,
    network: str,
) -> None:
    additional_data = AGG_SIG_ME_DATA.get(network)
    if additional_data is None:
        raise SolsSwapOfferError("Unsupported Chia network.")
    pairs: list[tuple[G1Element, bytes]] = []
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                additional_data,
            )
        )
    if not pairs:
        if bundle.aggregated_signature != G2Element():
            raise SolsSwapOfferError(
                "Unexpected Chia signature on a signature-free swap."
            )
        return
    if not AugSchemeMPL.aggregate_verify(
        [item[0] for item in pairs],
        [item[1] for item in pairs],
        bundle.aggregated_signature,
    ):
        raise SolsSwapOfferError(
            "Wallet signature does not authorize the complete atomic swap."
        )


async def _require_inputs_clear(
    provider: ChiaProvider,
    coins: tuple[Coin, ...],
) -> None:
    seen: set[bytes32] = set()
    for coin in coins:
        coin_id = bytes32(coin.name())
        if coin_id in seen:
            raise SolsSwapOfferError("Atomic swap contains duplicate inputs.")
        seen.add(coin_id)
        pending = await provider.get_mempool_items_by_coin_name(
            _hex32(coin_id)
        )
        if pending:
            raise SolsSwapOfferError(
                "A swap input is already pending in the mempool."
            )


def _swap_lock(request: Request) -> asyncio.Lock:
    lock = getattr(request.app.state, "sols_swap_lock", None)
    if not isinstance(lock, asyncio.Lock):
        lock = asyncio.Lock()
        request.app.state.sols_swap_lock = lock
    return lock


def _request_swap_store(
    request: Request,
    settings: Settings,
) -> SolsSwapStore:
    store = getattr(request.app.state, "sols_swap_store", None)
    if not isinstance(store, SolsSwapStore):
        store = _cached_swap_store(settings.admin_db_path)
        request.app.state.sols_swap_store = store
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if isinstance(submitter, ProtocolBundleSubmitter):
        submitter.add_fee_coin_reservation_source(store.reserved_input_coin_ids)
        submitter.faucet.add_coin_reservation_source(store.reserved_input_coin_ids)
    faucet = getattr(request.app.state, "faucet", None)
    if isinstance(faucet, Faucet):
        faucet.add_coin_reservation_source(store.reserved_input_coin_ids)
    return store


def _funding_binding(request, settings, context):
    vault = _hex32(context.vault_record.launcher_id)
    _authorize_swap(settings, request, vault)
    session = verify_vault_session(settings, request, vault)
    if not isinstance(session.session_id, str) or not session.session_id:
        raise ValueError("Reconnect the vault owner for a session-bound funding review")
    expected_owner = (context.vault_record.owner_evm_address.lower() if context.vault_record.owner_evm_address
                      else "0x" + bytes(context.vault_record.owner_pubkey).hex())
    expected_auth = "evm" if context.vault_record.auth_type == AUTH_TYPE_SECP256K1 else "chia_bls"
    if session.owner_key.lower() != expected_owner.lower() or session.auth_type != expected_auth:
        raise ValueError("canonical vault ownership changed during funding preparation")
    artifact = load_signed_public_artifact(settings)
    if funding_digest(artifact) != funding_digest(context.artifact):
        raise ValueError("signed artifact changed during swap preparation")
    release = read_release_metadata(settings.release_metadata_path)
    if release is None:
        raise ValueError("exact API and protocol release identity is required for funding review")
    sources = artifact.get("sourceShas")
    if (not isinstance(sources, Mapping) or sources.get("api") != release.apiCommit
            or sources.get("protocol") != release.protocolCommit):
        raise ValueError("current release identity no longer matches the signed artifact")
    return dict(vaultLauncherId=vault, ownerKey=session.owner_key, authType=session.auth_type,
        sessionFingerprint=funding_digest(session.session_id), sessionExpiresAt=session.expires_at,
        network=session.network, artifactHash=funding_digest(artifact),
        apiCommit=release.apiCommit, protocolCommit=release.protocolCommit)


async def _prepare_funding_review(request, settings, context, evidence):
    try:
        from .chia_snapshot import active_snapshot
        snapshot = active_snapshot()
        if snapshot is not None:
            def current_authority():
                if (require_vault_record(context.approved_vault.launcher_id) != context.vault_record
                        or require_current_approved_vault(settings, context.approved_vault.launcher_id)
                        != context.approved_vault):
                    raise ChiaProviderError("vault authority changed during swap review")
                return _funding_binding(request, settings, context)
            snapshot.recheck(current_authority, current_authority())
        submitter = getattr(request.app.state, "protocol_submitter", None)
        if not isinstance(submitter, ProtocolBundleSubmitter):
            raise ProtocolSubmissionError("Protocol funding is unavailable before owner review")
        return await reserve_funding(submitter, _request_swap_store(request, settings), evidence,
            _funding_binding(request, settings, context), _hex32(context.receipt.operation_hash),
            context.receipt.quote_expires_at, lambda: _funding_binding(request, settings, context))
    except (ChiaProviderError, PublicArtifactError, ProtocolSubmissionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _completion_funding_identity(request, settings, context, evidence, body):
    if not body.funding_reservation_hash:
        raise ValueError("Prepare and return the exact funding reservation hash before owner signing")
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise ProtocolSubmissionError("Protocol funding is unavailable")
    identity = funding_identity(submitter, evidence, _funding_binding(request, settings, context),
        body.operation_hash, body.quote_expires_at)
    require_hold(_request_swap_store(request, settings), identity, body.funding_reservation_hash)
    return identity


def _seal_swap_execution(request, settings, store, record, protocol_bundle, *,
                         funding_reservation_hash=None, funding_identity=None, funding_authorize=None):
    """The submitter holds its shared funding lock while this hook commits."""
    expected_spends = {bytes(spend) for spend in protocol_bundle.coin_spends}

    async def before_push(prepared):
        _authorize_swap(settings, request, record.vault_launcher_id)
        submitter = request.app.state.protocol_submitter
        execution = {
            **prepared.to_json(), "network": settings.network,
            "feeTargetSeconds": submitter.policy.target_seconds,
        }
        if funding_reservation_hash is not None:
            execution["fundingReservationHash"] = funding_reservation_hash
        bundle = validate_execution(execution, pool_input_id=record.pool_input_coin_id,
                                    pool_output_id=record.expected_pool_output_coin_id)
        actual_spends = {bytes(spend) for spend in bundle.coin_spends}
        if (len(actual_spends) != len(expected_spends) + 1 or not expected_spends < actual_spends
                or any(_hex32(spend.coin.name()) == prepared.fee_coin_id
                       for spend in protocol_bundle.coin_spends)
                or submitter.faucet.network != settings.network):
            raise ValueError("funded swap differs from the authorized protocol transaction")
        await run_offer_job("swap_signature", bundle=WalletSpendBundle.from_bytes(bytes(bundle)), network=settings.network)
        _authorize_swap(settings, request, record.vault_launcher_id)
        if funding_authorize is not None and funding_authorize() != funding_identity["binding"]:
            raise ValueError("swap funding authorization changed before execution promotion")
        if funding_identity is not None and (
                asdict(submitter.policy) != funding_identity["policy"]
                or _hex32(submitter.faucet.address_puzzle_hash) != funding_identity["feeTillPuzzleHash"]
                or submitter.faucet.network != funding_identity["binding"]["network"]):
            raise ValueError("swap funding policy changed before execution promotion")
        store.reserve_execution(record.operation_hash, execution, funding_reservation_hash=funding_reservation_hash)
        _authorize_swap(settings, request, record.vault_launcher_id)

    return before_push


def _swap_submission_error(store, operation_hash, error):
    record = store.get(operation_hash)
    if record is not None and record.transaction_id is not None:
        return ("Sols swap submission is unresolved. Retry this exact operation "
                f"to reconcile its retained transaction: {error}")
    return f"Sols swap was not submitted: {error}"


async def _resume_swap_execution(request, settings, store, operation_hash):
    """Read again after acquiring the swap lock; never rebuild sealed swaps."""
    record = store.get(operation_hash)
    if record is None:
        raise ValueError("prepared Sols swap operation does not exist")
    if record.status in ("SUBMITTED", "CONFIRMED"):
        return record
    execution = store.execution(operation_hash)
    if execution is None:
        if record.status != "PREPARED" or record.transaction_id is not None:
            raise ValueError("Sols swap has no recoverable exact execution")
        return None
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise HTTPException(status_code=503, detail="Protocol submission recovery is unavailable.")
    if execution["network"] != settings.network or submitter.faucet.network != settings.network:
        raise ValueError("retained swap belongs to another network")
    bundle = validate_execution(execution, pool_input_id=record.pool_input_coin_id,
                                pool_output_id=record.expected_pool_output_coin_id)
    if await execution_confirmed(request.app.state.coinset, bundle, record.expected_pool_output_coin_id):
        return store.mark_confirmed(operation_hash)
    fee_spend = next(spend for spend in bundle.coin_spends if _hex32(spend.coin.name()) == execution["feeCoinId"])
    if (not submitter.policy.enabled or int(execution["backingMojos"]) > submitter.policy.maximum_backing_mojos
            or fee_spend.coin.puzzle_hash != submitter.faucet.address_puzzle_hash):
        raise ValueError("retained swap funding no longer matches the active policy")
    _authorize_swap(settings, request, record.vault_launcher_id)
    result = await submitter.reconcile_reserved(
        execution,
        before_push=lambda: _authorize_swap(settings, request, record.vault_launcher_id),
    )
    return store.mark_submitted(
        operation_hash, transaction_id=str(result["spendBundleId"]), fee_mojos=str(result["feeMojos"]),
        fee_target_seconds=execution["feeTargetSeconds"], submission_provider=str(result["submissionProvider"]),
        mempool_observed_at=str(result["mempoolObservedAt"]),
    )


@lru_cache(maxsize=8)
def _cached_swap_store(path: str) -> SolsSwapStore:
    return SolsSwapStore(path)


def _require_operation_identity(
    record: StoredSolsSwap,
    vault_launcher_id: str,
    deed_launcher_id: str,
    direction: str,
) -> None:
    if (
        record.vault_launcher_id
        != _hex32_text(vault_launcher_id, "vaultLauncherId")
        or record.deed_launcher_id
        != _hex32_text(deed_launcher_id, "deedLauncherId")
        or record.direction != direction
    ):
        raise HTTPException(
            status_code=409,
            detail="Prepared operation does not match this vault and deed.",
        )


def _complete_response(
    record: StoredSolsSwap,
) -> CompleteSolsSwapResponse:
    if (
        record.transaction_id is None
        or record.fee_mojos is None
        or record.fee_target_seconds is None
        or (record.status != "CONFIRMED" and (record.submission_provider is None
                                             or record.mempool_observed_at is None))
    ):
        raise HTTPException(
            status_code=409,
            detail="Sols swap has not been submitted.",
        )
    destination = _hex32_text(
        record.destination_puzzle_hash,
        "destinationPuzzleHash",
    )
    return CompleteSolsSwapResponse(
        operationHash=record.operation_hash,
        direction=record.direction,
        deedLauncherId=record.deed_launcher_id,
        destinationP2VaultHash=(
            destination if record.direction == "SOLS_TO_DEED" else None
        ),
        destinationPuzzleHash=destination,
        transactionId=record.transaction_id,
        status=(
            "CONFIRMED" if record.status == "CONFIRMED" else "MEMPOOL"
        ),
        feeMojos=record.fee_mojos,
        feeTargetSeconds=record.fee_target_seconds,
        submissionProvider=record.submission_provider,
        mempoolObservedAt=record.mempool_observed_at,
    )


def _operation_response(
    record: StoredSolsSwap,
) -> SolsSwapOperationResponse:
    return SolsSwapOperationResponse(
        operationHash=record.operation_hash,
        direction=record.direction,
        vaultLauncherId=record.vault_launcher_id,
        deedLauncherId=record.deed_launcher_id,
        status=record.status,
        quoteExpiresAt=record.quote_expires_at,
        transactionId=record.transaction_id,
        feeMojos=record.fee_mojos,
        feeTargetSeconds=record.fee_target_seconds,
        submissionProvider=record.submission_provider,
        mempoolObservedAt=record.mempool_observed_at,
        updatedAt=record.updated_at,
    )


async def _required_singleton_tip(
    provider: ChiaProvider,
    launcher_id: str,
    label: str,
) -> SingletonTip:
    tip = await _singleton_tip(provider, launcher_id)
    if tip is None:
        raise SolsSwapOfferError(f"{label} is not confirmed.")
    return tip


def _node_b32(node: Program, label: str) -> bytes32:
    raw = node.as_atom()
    if len(raw) != 32:
        raise SolsSwapOfferError(f"{label} must be 32 bytes.")
    return bytes32(raw)


def _b32(value: object, label: str) -> bytes32:
    return bytes32.fromhex(
        _hex32_text(value, label).removeprefix("0x")
    )


def _hex32(value: bytes | bytes32) -> str:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError("value must be 32 bytes")
    return "0x" + raw.hex()


def _hex32_text(value: object, label: str) -> str:
    text = str(value or "").strip().lower().removeprefix("0x")
    if len(text) != 64:
        raise ValueError(f"{label} must be exactly 32 bytes")
    bytes.fromhex(text)
    return "0x" + text


def _hex_bytes(value: object, size: int, label: str) -> bytes:
    text = str(value or "").strip().lower().removeprefix("0x")
    if len(text) != size * 2:
        raise ValueError(f"{label} must be exactly {size} bytes")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{label} must be hexadecimal") from exc


def _coin_from_record(record: Any) -> Coin | None:
    if not isinstance(record, Mapping):
        return None
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            bytes32.fromhex(
                str(value["parent_coin_info"]).removeprefix("0x")
            ),
            bytes32.fromhex(str(value["puzzle_hash"]).removeprefix("0x")),
            uint64(int(value["amount"])),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _record_is_unspent_coin(record: Any, coin: Coin) -> bool:
    return (
        isinstance(record, Mapping)
        and int(record.get("confirmed_block_index") or 0) > 0
        and not bool(record.get("spent"))
        and int(record.get("spent_block_index") or 0) == 0
        and _coin_from_record(record) == coin
    )


def _coin_spend_json(spend: CoinSpend) -> dict[str, Any]:
    return {
        "coin": {
            "parentCoinInfo": _hex32(spend.coin.parent_coin_info),
            "puzzleHash": _hex32(spend.coin.puzzle_hash),
            "amount": int(spend.coin.amount),
        },
        "puzzleReveal": "0x" + bytes(spend.puzzle_reveal).hex(),
        "solution": "0x" + bytes(spend.solution).hex(),
    }


def _unsigned_protocol_evidence_json(
    evidence: UnsignedSolsSwapEvidence, network: str,
) -> dict[str, Any]:
    """Lossless unsigned protocol evidence; never a signable funding approval."""
    spends = []
    for role, spend in zip(evidence.spend_roles, evidence.coin_spends):
        value = _coin_spend_json(spend)
        value["coin"]["amount"] = str(spend.coin.amount)
        spends.append({"role": role, "coinId": _hex32(spend.coin.name()), **value})
    successor = evidence.expected_vault_successor
    return {
        "schemaVersion": 1,
        "status": "UNSIGNED_PROTOCOL_CANDIDATE",
        "network": network,
        "direction": evidence.direction,
        "protocolCandidateHash": _hex32(evidence.candidate_hash),
        "vaultCoinId": _hex32(evidence.vault_coin_id),
        "coinSpends": spends,
        "expectedVaultSuccessor": {
            "basis": "PINNED_TEMPLATE_PENDING_AUTHORIZATION",
            "coinId": _hex32(successor.name()),
            "parentCoinInfo": _hex32(successor.parent_coin_info),
            "puzzleHash": _hex32(successor.puzzle_hash),
            "amount": str(successor.amount),
        },
        "requiredBackingMojos": str(evidence.required_backing_mojos),
        "ownerAuthorization": "PENDING",
        "feeFunding": "PENDING",
        "consensusValidated": False,
    }


__all__ = [
    "CompleteSolsSwapRequest",
    "CompleteSolsSwapResponse",
    "PrepareSolsSwapRequest",
    "PrepareSolsSwapResponse",
    "SolsSwapOperationResponse",
    "SolsSwapContext",
    "complete_sols_swap",
    "prepare_sols_swap",
    "router",
    "sols_swap_status",
]
