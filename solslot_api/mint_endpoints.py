"""Admin Desk mint-proposal endpoints.

Backed by ``MintProposalStore`` for the lifecycle CRUD; gated by
``require_admin_jwt`` from ``admin_auth``.

Step A.2 / B scope:
  * /admin/mint/propose          DRAFT — full implementation
  * /admin/mint                  list  — full implementation
  * /admin/mint/{id}             read  — full implementation
  * /admin/mint/{id}/cancel      DRAFT → CANCELED — full implementation
  * /admin/mint/{id}/publish     canonical four-spend publish + persistence
  * /admin/mint/{id}/execute     canonical five-spend execution + persistence
  * /admin/committee/proposals   list filtered for committee — full impl
  * /admin/committee/vote        publish-only forwarder (Brick 3.5c-3)

Per POP-CANON-013 the committee-vote endpoint is **publish-only** and **not
gated by admin JWT** — the SGT signature embedded in the spend bundle is the
authority, and any SGT holder (not just allowlisted admins) must be able to
participate.  The voter's wallet builds the bundle client-side using the
governance/registry drivers in solslot-protocol (e.g.
``sgt_driver.build_tracker_execute_coin_spend`` + the registry routine
co-spend, sim-proven in ``test_governance_vault_version_execute_sim.py``);
this endpoint validates structure and forwards to coinset.org's mempool.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from chia.types.blockchain_format.coin import Coin
from chia_rs import AugSchemeMPL, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from .admin_auth import AdminClaims, require_admin_jwt
from .admin_operations import require_admin_operation
from .config import Settings, get_settings
from .coinset_client import CoinsetClient
from .collection_store import (
    CollectionConflict,
    CollectionForbidden,
    CollectionInvalidState,
    CollectionNotFound,
    get_collection_store,
)
from .credential_auth import require_minting_writes
from .kos_mint_execute_signer import (
    KosMintExecuteSignerError,
    request_kos_mint_execute_signature,
)
from .launch_gates import require_operation_gate
from .mint_chain_validation import (
    validate_kos_mint_execute_bundle,
    validate_publish_bundle,
)
from .mint_publish_validation import PublishProposalMetadata
from .mint_proposals import (
    DuplicateProperty,
    InvalidTransition,
    MintProposalStore,
    ProposalNotFound,
    StoredMintProposal,
)
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from solslot_puzzles.real_estate_profiles import ASSET_CLASS_CODES
from solslot_puzzles.property_registry_driver import canonicalise_property_id

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-mint"])


def require_mint_writes(
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    require_minting_writes(settings)
    require_operation_gate(settings, "minting")


# ── Module-level store singleton ────────────────────────────────────────────
_store: Optional[MintProposalStore] = None


def get_mint_proposal_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> MintProposalStore:
    """Lazy singleton for the SQLite-backed proposal store."""
    global _store
    if _store is None:
        _store = MintProposalStore(settings.admin_db_path)
        logger.info(
            "Opened mint-proposal store at %s (schema v%d)",
            settings.admin_db_path,
            _store.schema_version(),
        )
    return _store


def reset_mint_store_for_tests() -> None:
    """Test-only helper: close + clear the cached store."""
    global _store
    if _store is not None:
        try:
            _store.close()
        except Exception:
            pass
    _store = None


async def _get_coinset_dep(request: Request) -> Optional[CoinsetClient]:
    """Read the lifespan-owned Coinset client without crossing pyo3 threads."""
    return getattr(request.app.state, "coinset", None)


async def _submit_validated_mint(bundle, *, request, settings, coinset, completion):
    """Only called after complete owner/quorum/KoS semantic validation.

    The public committee-vote forwarder must never use this sponsor: its
    structural checks alone do not authorize spending the protocol fee till.
    """
    if not getattr(settings, "protocol_fee_funding_enabled", False):
        return await coinset.push_tx(bundle.to_json_dict()), "0x" + bundle.name().hex()
    from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError
    submitter = getattr(getattr(getattr(request, "app", None), "state", None), "protocol_submitter", None)
    if not isinstance(submitter, ProtocolBundleSubmitter) or submitter.funding_store is None:
        raise HTTPException(status_code=503, detail="Durable MINT fee funding is unavailable; nothing was submitted.")
    try:
        original_id = "0x" + bundle.name().hex()
        def before_push(prepared):
            submitter.funding_store.save_completion(submitter.faucet.network, original_id,
                {**completion, "bundleId": prepared.spend_bundle_id})
        result = await submitter.submit(bundle.to_json_dict(), selection_purpose="mint", before_push=before_push)
    except ProtocolSubmissionError as exc:
        raise HTTPException(status_code=503, detail="MINT submission needs reconciliation. Its saved transaction is retained.") from exc
    return {"success": True, "status": result["status"]}, result["spendBundleId"]



def _mark_mint_recorded(bundle, request, settings):
    if not getattr(settings, "protocol_fee_funding_enabled", False):
        return
    submitter = request.app.state.protocol_submitter
    submitter.funding_store.complete(submitter.faucet.network, "0x" + bundle.name().hex())


# ── Wire schemas ────────────────────────────────────────────────────────────
def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def _parse_bytes32(value: str, label: str) -> bytes:
    """Decode a 0x-prefixed 32-byte hex string into bytes."""
    raw = _strip0x(value)
    if len(raw) != 64:
        raise HTTPException(
            status_code=400,
            detail=f"{label} must be a 32-byte hex string (got {len(raw)} hex chars)",
        )
    try:
        return bytes.fromhex(raw)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=f"{label}: invalid hex ({e})",
        ) from e


class ProposeMintRequest(BaseModel):
    """Inputs the operator gives at DRAFT time.

    ``quorum_required`` is a snapshot of the protocol-level quorum
    expressed in *SGT mojos*; the desk reads it from the deployed
    governance manifest's ``quorum_bps × sgt_total_supply / 10_000``
    and the operator can override per-proposal if the manifest is
    looser than the desired threshold.
    """
    par_value: int = Field(..., gt=0, description="Par value in mojos (1 mojo = 1¢)")
    asset_class: str = Field(..., min_length=1, max_length=64,
                             description='e.g. "RWA-RE-RES" for residential real estate')
    property_id: str = Field(..., min_length=1, max_length=128,
                             description="Operator-assigned canonical id, e.g. \"US-TX-Travis-12345\"")
    collection_id: str = Field(..., min_length=1, max_length=128,
                               description="Canonical collection id used for NAV-registry pricing")
    share_ppm: int = Field(..., ge=1, le=1_000_000,
                           description="Share of collection NAV in ppm; 1000000 = 100%")
    jurisdiction: str = Field(..., min_length=1, max_length=64,
                              description="ISO-style jurisdiction code, e.g. \"US-TX-Travis\"")
    royalty_puzhash: str = Field(..., description="0x-prefixed 32-byte royalty payee puzzle hash")
    royalty_bps: int = Field(..., ge=0, le=10_000,
                             description="Basis points (0–10000) of par_value paid as royalty")
    quorum_required: int = Field(..., gt=0,
                                 description="Minimum SGT-mojos of YES votes for the proposal to pass")
    off_chain_metadata: Optional[dict[str, Any]] = Field(
        None, description="Free-form blob — title, address, photos, attestations etc.",
    )


PublishProposalMetadataRequest = PublishProposalMetadata


class PublishMintBundleRequest(BaseModel):
    spend_bundle: dict[str, Any]
    proposal_id: Optional[str] = Field(None, max_length=256)
    proposal_metadata: PublishProposalMetadata
    stake_vault_launcher_id: Optional[str] = Field(None, pattern=r"^0x[0-9a-fA-F]{64}$")
    publication_context_hash: Optional[str] = Field(None, pattern=r"^0x[0-9a-fA-F]{64}$")


class MintStakeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    context_hash: str = Field(alias="contextHash", pattern=r"^0x[0-9a-fA-F]{64}$")
    proposal_hash: str = Field(alias="proposalHash", pattern=r"^0x[0-9a-fA-F]{64}$")
    vault_launcher_id: str = Field(alias="vaultLauncherId", pattern=r"^0x[0-9a-fA-F]{64}$")
    stake_amount: str = Field(alias="stakeAmount", pattern=r"^[1-9][0-9]{0,19}$")
    voting_deadline: int = Field(alias="votingDeadline", gt=0, lt=2**64)
    operation_hash: str | None = Field(None, alias="operationHash", pattern=r"^0x[0-9a-fA-F]{64}$")
    vault_owner_authorization: str | None = Field(None, alias="vaultOwnerAuthorization", pattern=r"^0x[0-9a-fA-F]{130}$")


@router.post("/admin/mint/publication/context", dependencies=[Depends(require_mint_writes)])
async def mint_publication_context(
    request: Request,
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    from .genesis import get_genesis_store
    from .mint_publication import load_mint_publication_context
    import time
    try:
        context = await load_mint_publication_context(provider=request.app.state.coinset,
            settings=settings, genesis_store=get_genesis_store(settings))
        return context.to_wire(deadline=int(time.time()) + context.statutes.parameters.voting_window_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/mint/publication/stake", dependencies=[Depends(require_mint_writes)])
async def mint_publication_stake(
    body: MintStakeRequest,
    request: Request,
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    from .credential_auth import require_vault_record, verify_vault_session
    from .evm_auth import recover_evm_signer
    from .genesis import get_genesis_store
    from .governance_publisher import _b32, _hex32
    from .mint_publication import load_mint_publication_context
    from .mint_stake import build_mint_stake
    from .sols_swaps import _coin_spend_json
    from solslot_puzzles.vault_driver import compact_signature_from_evm
    import time
    try:
        verify_vault_session(settings, request, body.vault_launcher_id)
        context = await load_mint_publication_context(provider=request.app.state.coinset,
            settings=settings, genesis_store=get_genesis_store(settings))
        if context.commitment != _b32(body.context_hash, 'mint context'):
            raise ValueError('mint publication changed; prepare and review it again')
        now = int(time.time())
        if not now < body.voting_deadline <= now + context.statutes.parameters.voting_window_seconds:
            raise ValueError('mint publication deadline is expired or exceeds the current voting window')
        arguments = dict(context=context, provider=request.app.state.coinset, settings=settings,
            vault_launcher_id=body.vault_launcher_id, stake_amount=int(body.stake_amount),
            proposal_hash=_b32(body.proposal_hash, 'proposal hash'), deadline=body.voting_deadline)
        stake = await build_mint_stake(**arguments)
        if body.operation_hash is not None and _b32(body.operation_hash, 'stake operation') != stake.operation_hash:
            raise ValueError('mint stake changed while it was being authorized')
        if body.vault_owner_authorization is not None:
            if stake.vault_auth_type != 'evm' or body.operation_hash is None:
                raise ValueError('EVM mint stake requires its exact prepared operation')
            owner = require_vault_record(body.vault_launcher_id)
            recovered = recover_evm_signer(stake.vault_typed_data, body.vault_owner_authorization)
            if not owner.owner_evm_address or recovered.address.lower() != owner.owner_evm_address.lower():
                raise ValueError('mint stake signature does not belong to this vault owner')
            signed = await build_mint_stake(**arguments,
                signature_data=compact_signature_from_evm(body.vault_owner_authorization))
            if signed.operation_hash != stake.operation_hash:
                raise ValueError('mint stake changed while it was being authorized')
            stake = signed
        return {
            'contextHash': _hex32(context.commitment), 'proposalHash': body.proposal_hash.lower(),
            'operationHash': _hex32(stake.operation_hash), 'vaultLauncherId': _hex32(stake.vault_launcher_id),
            'vaultCoinId': _hex32(stake.vault_coin_id), 'vaultAuthType': stake.vault_auth_type,
            'vaultTypedData': stake.vault_typed_data, 'stakeAmount': str(stake.amount),
            'votingDeadline': body.voting_deadline, 'sgtCoinId': _hex32(stake.sgt_coin_id),
            'voterInnerPuzzleHash': _hex32(stake.owner_inner_hash),
            'sgtCoin': {'parentCoinInfo': _hex32(stake.sgt_coin.parent_coin_info),
                        'puzzleHash': _hex32(stake.sgt_coin.puzzle_hash), 'amount': str(stake.amount)},
            'lockedInnerPuzzleHash': _hex32(stake.locked_inner_hash),
            'availableSgtAmounts': [str(value) for value in stake.available_amounts],
            'signingCoinSpends': [_coin_spend_json(spend) for spend in stake.bundle.coin_spends],
            'evmOwnerAuthorized': stake.vault_auth_type == 'evm' and body.vault_owner_authorization is not None,
        }
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


class ExecuteMintBundleRequest(BaseModel):
    spend_bundle: dict[str, Any]
    proposal_id: Optional[str] = Field(None, max_length=256)


class CancelMintRequest(BaseModel):
    """Empty body — kept as a class so future cancel-reasons can attach."""
    pass


class MintProposalListResponse(BaseModel):
    proposals: list[dict[str, Any]]
    count: int


# ── /admin/mint/* endpoints ─────────────────────────────────────────────────
def _to_response(rec: StoredMintProposal) -> dict[str, Any]:
    return rec.to_public_dict()


@router.post(
    "/admin/mint/propose",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt), Depends(require_mint_writes)],
)
async def propose_mint(
    body: ProposeMintRequest,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
) -> dict[str, Any]:
    """Create a DRAFT mint proposal.

    All four computed puzzle hashes (smart_deed_inner / eve_inner /
    deed_full / proposal_hash) depend on the launcher coin id and so
    are NOT computed here — they're populated atomically by /publish
    in Step B.  DRAFT carries only operator metadata.
    """
    royalty_puzhash = _parse_bytes32(body.royalty_puzhash, "royalty_puzhash")
    try:
        rec = store.create(
            owner_pubkey=claims.sub,
            par_value=body.par_value,
            asset_class=body.asset_class,
            property_id=body.property_id,
            collection_id=body.collection_id,
            share_ppm=body.share_ppm,
            jurisdiction=body.jurisdiction,
            royalty_puzhash=royalty_puzhash,
            royalty_bps=body.royalty_bps,
            quorum_required=body.quorum_required,
            off_chain_metadata=body.off_chain_metadata,
        )
    except DuplicateProperty as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    logger.info(
        "Created DRAFT mint proposal %s by %s (property_id=%s par_value=%d)",
        rec.id, claims.sub, rec.property_id, rec.par_value,
    )
    return _to_response(rec)


@router.get(
    "/admin/mint",
    response_model=MintProposalListResponse,
    dependencies=[Depends(require_admin_jwt)],
)
async def list_mint_proposals(
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    state: Optional[str] = None,
    owner: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> MintProposalListResponse:
    """List proposals, filtered by state and/or owner.

    Returns the public dict shape (same as /admin/mint/{id}).
    """
    if limit < 1 or limit > 1_000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    states = [state] if state else None
    try:
        rows = store.list(
            states=states,
            owner_pubkey=owner.lower() if owner else None,
            limit=limit,
            offset=offset,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    total = store.count(state=state)
    return MintProposalListResponse(
        proposals=[_to_response(r) for r in rows],
        count=total,
    )


@router.get(
    "/admin/mint/{proposal_id}",
    response_model=dict[str, Any],
    dependencies=[Depends(require_admin_jwt)],
)
async def get_mint_proposal(
    proposal_id: str,
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
) -> dict[str, Any]:
    rec = store.get(proposal_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown proposal id {proposal_id!r}")
    return _to_response(rec)


@router.post(
    "/admin/mint/{proposal_id}/cancel",
    response_model=dict[str, Any],
    dependencies=[
        Depends(require_admin_operation("mint.cancel")),
        Depends(require_mint_writes),
    ],
)
async def cancel_mint_proposal(
    proposal_id: str,
    body: CancelMintRequest,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
) -> dict[str, Any]:
    """DRAFT → CANCELED.  Only the original proposer can cancel.

    Cancellation is the operator's escape hatch from a misconfigured
    DRAFT — it removes the active-property reservation so the same
    property_id can be re-proposed cleanly.  Once a proposal is
    PROPOSED on-chain it must run its on-chain lifecycle to
    completion (passes or fails by quorum); /cancel cannot pre-empt
    chain state.
    """
    rec = store.get(proposal_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Unknown proposal id {proposal_id!r}")
    if rec.owner_pubkey.lower() != claims.sub.lower():
        raise HTTPException(
            status_code=403,
            detail=(
                f"Only the original proposer ({rec.owner_pubkey}) may cancel "
                f"this proposal; you are {claims.sub}."
            ),
        )
    try:
        cancelled = store.cancel(proposal_id)
    except InvalidTransition as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except ProposalNotFound as e:
        # Race: the proposal was deleted between get() and cancel().
        raise HTTPException(status_code=404, detail=str(e)) from e
    logger.info("Cancelled mint proposal %s by %s", proposal_id, claims.sub)
    return _to_response(cancelled)


def _parse_spend_bundle(payload: dict[str, Any]):
    from chia_rs import SpendBundle

    try:
        bundle = SpendBundle.from_json_dict(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"spend_bundle is not a valid SpendBundle JSON: {exc}",
        ) from exc
    if not bundle.coin_spends:
        raise HTTPException(status_code=400, detail="spend_bundle must contain coin spends")
    return bundle


def _load_mint_artifact(settings: Settings) -> dict[str, Any]:
    try:
        artifact = load_signed_public_artifact(settings)
    except (PublicArtifactError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Signed Solslot V2 artifact is unavailable or invalid.",
        ) from exc
    if artifact.get("network") != "testnet11":
        raise HTTPException(
            status_code=403,
            detail="Disposable mint execution is enabled on testnet11 only.",
        )
    return artifact


def _coin_record_puzzle_hash(record: dict[str, Any]) -> Optional[str]:
    coin = record.get("coin")
    if not isinstance(coin, dict):
        return None
    value = coin.get("puzzle_hash")
    return str(value).lower() if isinstance(value, str) else None


async def _require_coin_ancestry(
    coinset: CoinsetClient,
    *,
    record: dict[str, Any],
    ancestor_coin_id: str,
    max_depth: int = 10_000,
) -> None:
    """Require ``record`` to descend from the artifact-selected coin id."""
    target = ancestor_coin_id.lower()
    current = record
    seen: set[str] = set()
    for _ in range(max_depth):
        coin = current.get("coin")
        if not isinstance(coin, dict):
            raise HTTPException(status_code=409, detail="Coinset returned malformed lineage data")
        parent = str(coin.get("parent_coin_info") or "").lower()
        if parent == target:
            return
        if not parent.startswith("0x") or len(parent) != 66 or parent in seen:
            raise HTTPException(
                status_code=409,
                detail="Property registry coin does not descend from the signed launcher",
            )
        seen.add(parent)
        try:
            parent_record = await coinset.get_coin_record_by_name(parent)
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Coinset failed while walking property registry lineage: {exc}",
            ) from exc
        if parent_record is None:
            raise HTTPException(
                status_code=409,
                detail="Property registry lineage is incomplete",
            )
        current = parent_record
    raise HTTPException(
        status_code=409,
        detail="Property registry lineage exceeded the safety depth",
    )


def _validate_collection_publish_context(
    *,
    settings: Settings,
    metadata: PublishProposalMetadata,
    claims: AdminClaims,
    canonical: Any,
    proposal_id: str,
    artifact: dict[str, Any],
) -> tuple[Any, str] | None:
    """Bind an extended MINT bill to the sealed API workspace.

    The spend bundle remains authoritative, but publication cannot substitute
    a different dossier root, anchor, allocation row, or collection owner.
    """
    has_commitment = bool(metadata.metadata_root and metadata.metadata_anchor_id)
    if settings.collection_minting_enabled and not has_commitment:
        raise HTTPException(
            status_code=400,
            detail="collection minting requires metadata_root and metadata_anchor_id",
        )
    if not has_commitment:
        return None
    if not settings.collection_metadata_enabled or not settings.collection_minting_enabled:
        raise HTTPException(
            status_code=503,
            detail="chain-verifiable collection minting is disabled",
        )
    collection_store = get_collection_store(settings)
    try:
        collection = collection_store.get(metadata.collection_id)
    except CollectionNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if collection["ownerSubject"] != claims.sub.lower():
        raise HTTPException(status_code=403, detail="only the collection owner may publish")
    if collection["state"] not in ("SEALED", "PUBLISHED"):
        raise HTTPException(status_code=409, detail="collection must be sealed before mint publication")
    if str(collection["metadataRoot"]).lower() != str(metadata.metadata_root).lower():
        raise HTTPException(status_code=409, detail="MINT metadata root does not match the sealed dossier")
    expected_anchor = collection["metadataAnchorId"] or (
        "0x" + canonical.deed_launcher_id.hex()
    )
    if expected_anchor.lower() != str(metadata.metadata_anchor_id).lower():
        raise HTTPException(status_code=409, detail="MINT metadata anchor does not match the collection")
    deed = next(
        (
            item
            for item in collection["deeds"]
            if item["deedId"].casefold() == metadata.property_id.casefold()
        ),
        None,
    )
    if deed is None:
        raise HTTPException(status_code=409, detail="property id is not in the sealed deed allocation")
    if metadata.primary_purchase_usd_amount_minor is None:
        raise HTTPException(
            status_code=400,
            detail="collection minting requires a purchase-aware V2 USD allocation",
        )
    dossier = collection.get("dossier")
    offering = dossier.get("offering") if isinstance(dossier, dict) else None
    target_raise = offering.get("targetRaiseMinor") if isinstance(offering, dict) else None
    if not isinstance(target_raise, str) or not target_raise.isdecimal() or int(target_raise) <= 0:
        raise HTTPException(status_code=409, detail="sealed collection has no valid USD target raise")
    numerator = int(target_raise) * int(deed["sharePpm"])
    base_usd_amount, remainder = divmod(numerator, 1_000_000)
    if remainder:
        raise HTTPException(
            status_code=409,
            detail="sealed deed allocation produces fractional USD minor units",
        )
    fee_bps = int(offering.get("royaltyBps") or 0)
    technology_fee = (base_usd_amount * fee_bps + 9_999) // 10_000
    expected_usd_amount = base_usd_amount + technology_fee
    if metadata.inventory_puzzle_version in (2, 3):
        # Explicit V2 carries the base price. Protocol CLVM adds the agreed fee
        # exactly once. Historical version-1 wire semantics remain unchanged.
        expected_usd_amount = base_usd_amount
        if fee_bps != 100:
            raise HTTPException(status_code=409, detail="inventory V2 alpha technology fee must be 100 basis points")
    if metadata.primary_purchase_usd_amount_minor != expected_usd_amount:
        raise HTTPException(
            status_code=409,
            detail="primary purchase USD amount does not match the sealed allocation and inventory version",
        )
    if deed["proposalId"] not in (None, proposal_id):
        raise HTTPException(status_code=409, detail="deed allocation row already has a proposal")
    if int(deed["sharePpm"]) != metadata.share_ppm:
        raise HTTPException(status_code=409, detail="MINT share_ppm differs from the sealed allocation")
    if int(deed["parValueMojos"]) != metadata.par_value_mojos:
        raise HTTPException(status_code=409, detail="MINT par value differs from the sealed allocation")
    offering = collection["dossier"]["offering"]
    if str(offering["assetClass"]).upper() != metadata.asset_class_name.upper():
        raise HTTPException(status_code=409, detail="MINT asset class differs from the sealed dossier")
    if int(offering["royaltyBps"]) != metadata.royalty_bps:
        raise HTTPException(status_code=409, detail="MINT royalty differs from the sealed dossier")
    if metadata.royalty_bps > 1_000:
        raise HTTPException(status_code=409, detail="primary technology fee exceeds 1000 bps")
    if str(offering["royaltyPuzhash"]).lower() != metadata.royalty_puzhash.lower():
        raise HTTPException(status_code=409, detail="MINT royalty payee differs from the sealed dossier")
    puzzle_hashes = artifact.get("puzzleHashes")
    trusted_treasury = (
        puzzle_hashes.get("protocolTreasuryPuzzleHash")
        if isinstance(puzzle_hashes, dict)
        else None
    )
    if not isinstance(trusted_treasury, str) or metadata.royalty_puzhash.lower() != trusted_treasury.lower():
        raise HTTPException(status_code=409, detail="technology fee destination is not the trusted protocol treasury")
    if int(offering["governanceQuorum"]) != metadata.quorum_threshold:
        raise HTTPException(status_code=409, detail="MINT quorum differs from the sealed dossier")
    try:
        jurisdiction = bytes.fromhex(metadata.jurisdiction.removeprefix("0x")).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="MINT jurisdiction is not valid UTF-8") from exc
    if str(offering["jurisdiction"]) != jurisdiction:
        raise HTTPException(status_code=409, detail="MINT jurisdiction differs from the sealed dossier")
    return collection_store, deed["deedId"]


async def _publish_mint_bundle(
    *,
    proposal_id: str,
    body: PublishMintBundleRequest,
    claims: AdminClaims,
    settings: Settings,
    store: MintProposalStore,
    coinset: Optional[CoinsetClient],
    request: Request | None = None,
) -> dict[str, Any]:
    if body.proposal_id is not None and body.proposal_id != proposal_id:
        raise HTTPException(status_code=400, detail="proposal_id does not match the route")
    if coinset is None:
        raise HTTPException(status_code=502, detail="Coinset client not initialised.")
    proposal = store.get(proposal_id)
    if proposal is None:
        metadata = body.proposal_metadata
        try:
            property_hash = bytes(canonicalise_property_id(metadata.property_id))
            collection_hash = bytes(canonicalise_property_id(metadata.collection_id))
            if property_hash != _parse_bytes32(
                metadata.property_id_canon, "property_id_canon"
            ):
                raise ValueError("property_id does not reproduce property_id_canon")
            if collection_hash != _parse_bytes32(
                metadata.collection_id_canon, "collection_id_canon"
            ):
                raise ValueError("collection_id does not reproduce collection_id_canon")
            expected_class = ASSET_CLASS_CODES.get(metadata.asset_class_name.upper())
            if expected_class is None or metadata.asset_class != int(expected_class):
                raise ValueError("asset_class_name does not match the alpha asset class code")
            if metadata.royalty_bps > 1_000:
                raise ValueError("primary technology fee cannot exceed 1000 bps")
            jurisdiction = bytes.fromhex(
                metadata.jurisdiction.removeprefix("0x")
            ).decode("utf-8")
            proposal = store.create(
                proposal_id=proposal_id,
                owner_pubkey=claims.sub,
                par_value=metadata.par_value_mojos,
                asset_class=metadata.asset_class_name,
                property_id=metadata.property_id,
                collection_id=metadata.collection_id,
                share_ppm=metadata.share_ppm,
                jurisdiction=jurisdiction,
                royalty_puzhash=_parse_bytes32(
                    metadata.royalty_puzhash, "royalty_puzhash"
                ),
                royalty_bps=metadata.royalty_bps,
                quorum_required=metadata.quorum_threshold,
                off_chain_metadata={"source": "authenticated-first-publish"},
            )
        except DuplicateProperty as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (UnicodeDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot import authenticated mint draft: {exc}",
            ) from exc
    if proposal.owner_pubkey.lower() != claims.sub.lower():
        raise HTTPException(status_code=403, detail="Only the original proposer may publish")

    bundle = _parse_spend_bundle(body.spend_bundle)
    owner_bundle_id = "0x" + bytes(bundle.name()).hex()
    prior_context = (proposal.off_chain_metadata or {}).get('publish_context', {})
    if proposal.state == "PROPOSED" and (proposal.published_bundle_id == owner_bundle_id
        or prior_context.get('owner_bundle_id') == owner_bundle_id):
        return {
            "pushed": True,
            "status": "ALREADY_RECORDED",
            "spend_bundle_id": proposal.published_bundle_id,
            "proposal_id": proposal_id,
            "proposal": _to_response(proposal),
        }
    if proposal.state != "DRAFT":
        raise HTTPException(
            status_code=409,
            detail=f"publish requires DRAFT; current={proposal.state}",
        )

    artifact = _load_mint_artifact(settings)
    try:
        from .admin_operations import _mint_build
        from .mint_publication import build_mint_authorization_spends
        operation = getattr(request.state, 'admin_operation', None) if request is not None else None
        if operation is None:
            raise HTTPException(status_code=428, detail='Current owner-plus-one mint approvals are required')
        reviewed = await _mint_build(operation, request, settings)
        if reviewed is None or reviewed.owner_bundle != bundle:
            raise ValueError('mint request differs from its exact approved wallet package')
        signatures = {int(item['admin_index']): item for item in operation['chain_signatures']}
        coadmin = next((slot for slot in (1, 2) if slot in signatures), None)
        if 0 not in signatures or coadmin is None:
            raise ValueError('mint needs the owner and one coadministrator chain approval')
        authorization_spends = build_mint_authorization_spends(reviewed.context,
            delegated=reviewed.delegated, actions=reviewed.actions, signatures=signatures,
            coadmin_slot=coadmin)
        bundle = SpendBundle([*bundle.coin_spends, *authorization_spends], bundle.aggregated_signature)
        bundle_id = '0x' + bytes(bundle.name()).hex()
        canonical = validate_publish_bundle(
            bundle=bundle,
            metadata=body.proposal_metadata,
            proposal=proposal,
            artifact=artifact,
            authenticated_owner=claims.sub,
            stake_vault_launcher_id=bytes32.from_hexstr(body.stake_vault_launcher_id),
            authorization_spends=authorization_spends,
            current_admin_pubkeys=tuple(bytes(identity.daily_compressed_pubkey) for identity in reviewed.context.identities),
        )
        from .sols_swaps import _require_inputs_clear, _verify_aggregate_signature
        from chia.wallet.wallet_spend_bundle import WalletSpendBundle
        _verify_aggregate_signature(WalletSpendBundle(bundle.coin_spends, bundle.aggregated_signature), settings.network)
        await _require_inputs_clear(coinset, tuple(spend.coin for spend in authorization_spends))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    collection_context = _validate_collection_publish_context(
        settings=settings,
        metadata=body.proposal_metadata,
        claims=claims,
        canonical=canonical,
        proposal_id=proposal_id,
        artifact=artifact,
    )

    registry_id = "0x" + canonical.property_registry_coin_id.hex()
    try:
        registry_record = await coinset.get_coin_record_by_name(registry_id)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Coinset failed to resolve the property registry coin: {exc}",
        ) from exc
    if registry_record is None:
        raise HTTPException(status_code=409, detail="Property registry coin is not confirmed")
    if int(registry_record.get("spent_block_index") or 0) != 0:
        raise HTTPException(status_code=409, detail="Property registry coin is already spent")
    expected_registry_ph = "0x" + canonical.property_registry_puzzle_hash.hex()
    if _coin_record_puzzle_hash(registry_record) != expected_registry_ph:
        raise HTTPException(
            status_code=409,
            detail="Property registry coin does not match the committed current puzzle hash",
        )
    launcher_ids = artifact.get("launcherIds")
    registry_launcher_id = (
        launcher_ids.get("propertyRegistry")
        if isinstance(launcher_ids, dict)
        else None
    )
    if not isinstance(registry_launcher_id, str):
        raise HTTPException(
            status_code=503,
            detail="Signed artifact lacks the property registry launcher",
        )
    await _require_coin_ancestry(
        coinset,
        record=registry_record,
        ancestor_coin_id=registry_launcher_id,
    )

    persisted_metadata = dict(proposal.off_chain_metadata or {})
    persisted_metadata["publish_context"] = {
        "owner_bundle_id": owner_bundle_id,
        "property_registry_puzzle_hash": "0x"
        + canonical.property_registry_puzzle_hash.hex(),
        "property_registry_coin_id": "0x" + canonical.property_registry_coin_id.hex(),
        "owner_member_hash": body.proposal_metadata.owner_member_hash.lower(),
        "gov_member_hash": body.proposal_metadata.gov_member_hash.lower(),
        "proposal_data_hash": "0x" + canonical.proposal_data_hash.hex(),
        "inventory_puzzle_version": body.proposal_metadata.inventory_puzzle_version,
        **(
            {
                "metadata_root": str(body.proposal_metadata.metadata_root).lower(),
                "metadata_anchor_id": str(
                    body.proposal_metadata.metadata_anchor_id
                ).lower(),
                "primary_purchase_usd_amount_minor": (
                    body.proposal_metadata.primary_purchase_usd_amount_minor
                ),
            }
            if body.proposal_metadata.metadata_root
            and body.proposal_metadata.metadata_anchor_id
            else {}
        ),
    }
    from .mint_recovery import PUBLISH_BYTES
    completion = {"schema": "solslot.mint-completion.v1", "phase": "publish",
        "proposalId": proposal_id, "owner": proposal.owner_pubkey,
        "artifactHash": str(artifact["artifactHash"]),
        "publication": {**{key: bytes(getattr(canonical, key)).hex() for key in PUBLISH_BYTES},
            "deadline": canonical.voting_deadline, "off_chain_metadata": persisted_metadata},
        "collection": None}
    if collection_context is not None:
        completion["collection"] = {"collection_id": body.proposal_metadata.collection_id,
            "deed_id": collection_context[1], "actor_subject": claims.sub, "proposal_id": proposal_id,
            "proposal_hash": bytes(canonical.proposal_hash).hex(),
            "proposal_launcher_id": bytes(canonical.proposal_singleton_launcher_id).hex(),
            "deed_launcher_id": bytes(canonical.deed_launcher_id).hex(),
            "output_coin_id": Coin(bytes32(canonical.deed_launcher_id),
                bytes32(canonical.deed_full_puzhash), uint64(1)).name().hex()}

    try:
        push_result, bundle_id = await _submit_validated_mint(bundle, request=request, settings=settings, coinset=coinset, completion=completion)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Coinset publish failed for mint %s", proposal_id)
        raise HTTPException(status_code=502, detail=f"Coinset publish failed: {exc}") from exc
    chain_status = str(
        push_result.get("status") or push_result.get("error") or push_result
    )
    accepted = bool(push_result.get("success")) or chain_status.upper() == "PENDING"
    if not accepted:
        return {
            "pushed": False,
            "status": chain_status,
            "spend_bundle_id": bundle_id,
            "proposal_id": proposal_id,
            "proposal": _to_response(proposal),
        }

    try:
        published = store.set_published(
            proposal_id,
            smart_deed_inner_puzhash=bytes(canonical.smart_deed_inner_puzhash),
            eve_inner_puzhash=bytes(canonical.eve_inner_puzhash),
            deed_full_puzhash=bytes(canonical.deed_full_puzhash),
            proposal_hash=bytes(canonical.proposal_hash),
            proposal_tracker_coin_id=bytes(canonical.proposal_tracker_coin_id),
            sgt_lock_coin_id=bytes(canonical.sgt_lock_coin_id),
            proposal_singleton_launcher_id=bytes(
                canonical.proposal_singleton_launcher_id
            ),
            property_registry_coin_id=bytes(canonical.property_registry_coin_id),
            property_registry_puzzle_hash=bytes(
                canonical.property_registry_puzzle_hash
            ),
            deed_launcher_id=bytes(canonical.deed_launcher_id),
            published_bundle_id=bundle_id,
            deadline=canonical.voting_deadline,
            off_chain_metadata=persisted_metadata,
        )
    except InvalidTransition as exc:
        # The observer may have recorded this exact accepted bundle while the
        # original RPC response was in flight. Preserve its later state.
        published = store.get(proposal_id)
        if (published.published_bundle_id != bundle_id
                or any(getattr(published, key) != bytes(getattr(canonical, key)) for key in PUBLISH_BYTES)):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    collection_record = None
    if collection_context is not None:
        collection_store, deed_id = collection_context
        try:
            output_coin_id = bytes(
                Coin(
                    bytes32(canonical.deed_launcher_id),
                    bytes32(canonical.deed_full_puzhash),
                    uint64(1),
                ).name()
            )
            collection_record = collection_store.record_proposal_publication(
                body.proposal_metadata.collection_id,
                deed_id,
                actor_subject=claims.sub,
                proposal_id=proposal_id,
                proposal_hash=bytes(canonical.proposal_hash),
                proposal_launcher_id=bytes(canonical.proposal_singleton_launcher_id),
                deed_launcher_id=bytes(canonical.deed_launcher_id),
                output_coin_id=output_coin_id,
                publish_bundle_id=bundle_id,
            )
        except (
            CollectionConflict,
            CollectionForbidden,
            CollectionInvalidState,
            CollectionNotFound,
            ValueError,
        ) as exc:
            logger.exception(
                "Mint %s reached the mempool but collection persistence failed",
                proposal_id,
            )
            raise HTTPException(
                status_code=500,
                detail=(
                    "Mint was accepted by the network but collection recording failed; "
                    f"reconcile proposal {proposal_id}: {exc}"
                ),
            ) from exc
    _mark_mint_recorded(bundle, request, settings)
    logger.info("Canonical mint proposal %s submitted as %s", proposal_id, bundle_id)
    return {
        "pushed": True,
        "status": chain_status,
        "spend_bundle_id": bundle_id,
        "proposal_id": proposal_id,
        "proposal": _to_response(published),
        "collection": collection_record,
    }


async def _execute_mint_bundle(
    *,
    proposal_id: str,
    body: ExecuteMintBundleRequest,
    claims: AdminClaims,
    settings: Settings,
    store: MintProposalStore,
    coinset: Optional[CoinsetClient],
    request: Request | None = None,
) -> dict[str, Any]:
    if body.proposal_id is not None and body.proposal_id != proposal_id:
        raise HTTPException(status_code=400, detail="proposal_id does not match the route")
    if coinset is None:
        raise HTTPException(status_code=502, detail="Coinset client not initialised.")
    proposal = store.get(proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail=f"Unknown proposal id {proposal_id!r}")
    if proposal.state == "EXECUTED":
        # The client bundle intentionally lacks the isolated co-signature, so
        # it cannot reproduce the final bundle id locally. Never ask KoS to
        # sign a proposal that has already been submitted; chain/index state
        # is the authoritative execution record.
        raise HTTPException(
            status_code=409,
            detail="MINT proposal is already executed; inspect its recorded chain bundle.",
        )

    bundle = _parse_spend_bundle(body.spend_bundle)
    if proposal.state not in {"PROPOSED", "VOTING", "PASSED"}:
        raise HTTPException(
            status_code=409,
            detail=f"execute requires an open or passed proposal; current={proposal.state}",
        )

    artifact = _load_mint_artifact(settings)
    try:
        execution = validate_kos_mint_execute_bundle(
            bundle=bundle,
            proposal=proposal,
            artifact=artifact,
            network=settings.network,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        kos_signature, kos_request_hash = await request_kos_mint_execute_signature(
            settings=settings,
            execution=execution,
            artifact_hash=str(artifact["artifactHash"]),
            proposal_id=proposal_id,
        )
    except KosMintExecuteSignerError as exc:
        logger.warning("KoS MINT co-sign unavailable for proposal %s", proposal_id)
        raise HTTPException(
            status_code=503,
            detail="MINT execution co-signer is unavailable; no bundle was submitted.",
        ) from exc
    bundle = SpendBundle(
        bundle.coin_spends,
        AugSchemeMPL.aggregate([bundle.aggregated_signature, kos_signature]),
    )
    bundle_id = "0x" + bytes(bundle.name()).hex()

    completion = {"schema": "solslot.mint-completion.v1", "phase": "execute",
        "proposalId": proposal_id, "owner": proposal.owner_pubkey, "actor": claims.sub,
        "artifactHash": str(artifact["artifactHash"]), "collectionEnabled": settings.collection_metadata_enabled}
    try:
        push_result, bundle_id = await _submit_validated_mint(bundle, request=request, settings=settings, coinset=coinset, completion=completion)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Coinset execute failed for mint %s", proposal_id)
        raise HTTPException(status_code=502, detail=f"Coinset execute failed: {exc}") from exc
    chain_status = str(
        push_result.get("status") or push_result.get("error") or push_result
    )
    accepted = bool(push_result.get("success")) or chain_status.upper() == "PENDING"
    if not accepted:
        return {
            "pushed": False,
            "status": chain_status,
            "spend_bundle_id": bundle_id,
            "proposal_id": proposal_id,
            "proposal": _to_response(proposal),
        }
    try:
        executed = store.set_chain_executed(
            proposal_id, executed_bundle_id=bundle_id
        )
    except InvalidTransition as exc:
        executed = store.get(proposal_id)
        if executed.executed_bundle_id != bundle_id:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    collection_record = None
    if settings.collection_metadata_enabled:
        try:
            collection_record = get_collection_store(settings).record_proposal_execution(
                proposal_id,
                execute_bundle_id=bundle_id,
                actor_subject=claims.sub,
            )
        except (CollectionConflict, ValueError) as exc:
            logger.exception(
                "Mint %s reached the mempool but collection execution persistence failed",
                proposal_id,
            )
            raise HTTPException(
                status_code=500,
                detail=(
                    "Mint execution was accepted by the network but collection recording "
                    f"failed; reconcile proposal {proposal_id}: {exc}"
                ),
            ) from exc
    _mark_mint_recorded(bundle, request, settings)
    logger.info(
        "Canonical mint execution %s submitted as %s with KoS request %s",
        proposal_id,
        bundle_id,
        kos_request_hash,
    )
    return {
        "pushed": True,
        "status": chain_status,
        "spend_bundle_id": bundle_id,
        "proposal_id": proposal_id,
        "proposal": _to_response(executed),
        "collection": collection_record,
    }


@router.post(
    "/admin/mint/{proposal_id}/publish",
    response_model=dict[str, Any],
    dependencies=[
        Depends(require_admin_operation("mint.publish")),
        Depends(require_mint_writes),
    ],
)
async def publish_mint_proposal(
    proposal_id: str,
    body: PublishMintBundleRequest,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    coinset: Annotated[Optional[CoinsetClient], Depends(_get_coinset_dep)],
) -> dict[str, Any]:
    """Validate, submit, and persist the canonical MINT publication bundle."""
    return await _publish_mint_bundle(
        proposal_id=proposal_id,
        body=body,
        claims=claims,
        settings=settings,
        store=store,
        coinset=coinset,
        request=request,
    )


@router.post(
    "/admin/mint/{proposal_id}/execute",
    response_model=dict[str, Any],
    dependencies=[
        Depends(require_admin_operation("mint.execute")),
        Depends(require_mint_writes),
    ],
)
async def execute_mint_proposal(
    proposal_id: str,
    body: ExecuteMintBundleRequest,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    coinset: Annotated[Optional[CoinsetClient], Depends(_get_coinset_dep)],
) -> dict[str, Any]:
    """Validate and submit the five-spend quorum-authorized MINT execution."""
    return await _execute_mint_bundle(
        proposal_id=proposal_id,
        body=body,
        claims=claims,
        settings=settings,
        store=store,
        coinset=coinset,
        request=request,
    )


# ── /admin/committee/* endpoints ────────────────────────────────────────────
#
# POP-CANON-013 keeps committee reads and SGT voting outside the administrator
# JWT boundary. Canonical MINT publication and execution remain operator
# actions and therefore require an artifact-bound administrator session.
#
# /committee/proposals is a public read.  /committee/vote (Step B) will
# carry its authority in the embedded SGT-VOTE signature inside the
# spend bundle — the API is publish-only and validates bundle
# structure, not signer identity.
@router.post(
    "/admin/committee/propose",
    response_model=dict[str, Any],
    dependencies=[
        Depends(require_admin_operation("mint.publish")),
        Depends(require_mint_writes),
    ],
)
async def committee_propose_mint(
    body: PublishMintBundleRequest,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    coinset: Annotated[Optional[CoinsetClient], Depends(_get_coinset_dep)],
) -> dict[str, Any]:
    """Compatibility route used by the portal's canonical publish runner."""
    if body.proposal_id is None:
        raise HTTPException(status_code=400, detail="proposal_id is required")
    return await _publish_mint_bundle(
        proposal_id=body.proposal_id,
        body=body,
        claims=claims,
        settings=settings,
        store=store,
        coinset=coinset,
        request=request,
    )


@router.post(
    "/admin/committee/execute",
    response_model=dict[str, Any],
    dependencies=[
        Depends(require_admin_operation("mint.execute")),
        Depends(require_mint_writes),
    ],
)
async def committee_execute_mint(
    body: ExecuteMintBundleRequest,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    coinset: Annotated[Optional[CoinsetClient], Depends(_get_coinset_dep)],
) -> dict[str, Any]:
    """Compatibility route used by the portal's five-spend execute runner."""
    if body.proposal_id is None:
        raise HTTPException(status_code=400, detail="proposal_id is required")
    return await _execute_mint_bundle(
        proposal_id=body.proposal_id,
        body=body,
        claims=claims,
        settings=settings,
        store=store,
        coinset=coinset,
        request=request,
    )


@router.get(
    "/admin/committee/proposals",
    response_model=MintProposalListResponse,
)
async def list_committee_proposals(
    store: Annotated[MintProposalStore, Depends(get_mint_proposal_store)],
    limit: int = 100,
    offset: int = 0,
) -> MintProposalListResponse:
    """List proposals open for committee voting.

    Filters to PROPOSED + VOTING — terminal and DRAFT proposals are
    excluded.  Used by the committee voting UI to populate the
    "open proposals" sidebar.

    Public: no authentication required.  Any SGT holder (or any
    interested observer) may read this list.  Rate-limiting can be
    layered at the reverse-proxy edge if needed.
    """
    if limit < 1 or limit > 1_000:
        raise HTTPException(status_code=400, detail="limit must be 1..1000")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    rows = store.list(
        states=["PROPOSED", "VOTING"],
        limit=limit,
        offset=offset,
    )
    # store.count doesn't accept multi-state, so sum manually for the
    # response total.
    total = store.count(state="PROPOSED") + store.count(state="VOTING")
    return MintProposalListResponse(
        proposals=[_to_response(r) for r in rows],
        count=total,
    )


class CommitteeVoteRequest(BaseModel):
    """Publish-only committee-vote payload.

    ``spend_bundle`` is a JSON object matching ``chia_rs.SpendBundle``'s
    ``to_json_dict()`` shape — i.e. ``{coin_spends: [...], aggregated_signature:
    "0x..."}`` — built and signed by the voter's wallet client-side using the
    SGT lock + governance tracker drivers (mirrors of
    ``sgt_driver.build_tracker_execute_coin_spend`` etc.).  The API neither
    constructs nor signs governance spends; it only forwards.

    ``proposal_id`` is purely informational (logged for correlation); the
    proposal binding is enforced on-chain by the bundle's own coin spends
    against the governance tracker singleton's proposal_hash.
    """

    spend_bundle: dict[str, Any] = Field(
        ...,
        description=(
            "SpendBundle JSON dict (chia_rs.SpendBundle.to_json_dict shape)."
        ),
    )
    proposal_id: Optional[str] = Field(
        None,
        max_length=256,
        description="Optional informational proposal id for logging/correlation.",
    )


class CommitteeVoteResponse(BaseModel):
    pushed: bool
    status: str
    spend_bundle_id: str = Field(..., description="0x-prefixed sha256 id of the bundle.")
    proposal_id: Optional[str] = None


@router.post(
    "/admin/committee/vote",
    response_model=CommitteeVoteResponse,
    dependencies=[Depends(require_mint_writes)],
)
async def cast_committee_vote(
    body: CommitteeVoteRequest,
    coinset: Annotated[Optional[CoinsetClient], Depends(_get_coinset_dep)],
) -> CommitteeVoteResponse:
    """Forward a committee-action spend bundle (PROPOSE / VOTE / EXECUTE) to chain.

    Publish-only forwarder.  The SGT signature embedded in the bundle's coin
    spends is the authority (POP-CANON-013): governance voting is open to any
    SGT holder, NOT gated by the admin allowlist — locking it behind admin JWT
    would conflate operator desk authority with token-holder governance.

    The API performs only **structural** validation (the bundle parses as a
    well-formed ``chia_rs.SpendBundle`` with at least one coin spend) before
    handing off to ``coinset.org``'s mempool, which enforces all semantic rules
    (signatures, announcements, quorum, deadlines, lineage).  Mempool rejection
    is surfaced as ``pushed=false`` with the chain's status string so the
    portal can render a precise error; coinset transport failures are 502.
    """
    # Lazy import — chia_rs is heavy and only this endpoint deserializes a
    # SpendBundle on the API side.
    from chia_rs import SpendBundle

    if coinset is None:
        raise HTTPException(
            status_code=502, detail="Coinset client not initialised.",
        )

    try:
        bundle = await run_in_threadpool(
            SpendBundle.from_json_dict,
            body.spend_bundle,
        )
    except (KeyError, TypeError, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"spend_bundle is not a valid SpendBundle JSON: {e}",
        ) from e
    if len(bundle.coin_spends) == 0:
        raise HTTPException(
            status_code=400,
            detail="spend_bundle must contain at least one coin_spend.",
        )
    bundle_id = "0x" + bytes(bundle.name()).hex()

    try:
        push_result = await coinset.push_tx(bundle.to_json_dict())
    except Exception as e:
        logger.exception(
            "coinset push_tx failed for committee vote %s (proposal_id=%r): %s",
            bundle_id, body.proposal_id, e,
        )
        raise HTTPException(
            status_code=502, detail=f"coinset.org error forwarding committee vote: {e}",
        ) from e

    accepted = bool(push_result.get("success"))
    if accepted:
        status_str = str(push_result.get("status") or "SUCCESS")
        logger.info(
            "committee vote %s accepted (proposal_id=%r, status=%s)",
            bundle_id, body.proposal_id, status_str,
        )
    else:
        status_str = str(
            push_result.get("status") or push_result.get("error") or push_result
        )
        logger.warning(
            "committee vote %s rejected (proposal_id=%r, status=%s)",
            bundle_id, body.proposal_id, status_str,
        )

    return CommitteeVoteResponse(
        pushed=accepted,
        status=status_str,
        spend_bundle_id=bundle_id,
        proposal_id=body.proposal_id,
    )


__all__ = [
    "router",
    "ProposeMintRequest",
    "CancelMintRequest",
    "MintProposalListResponse",
    "CommitteeVoteRequest",
    "CommitteeVoteResponse",
    "get_mint_proposal_store",
    "reset_mint_store_for_tests",
]
