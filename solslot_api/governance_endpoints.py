"""Typed administrator queue for SGT sale and grant proposals."""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Mapping
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.wallet_spend_bundle import WalletSpendBundle

from solslot_puzzles.sgt_driver import (
    TRK_EXECUTE,
    TRK_EXPIRE,
    TRK_VOTE,
    bill_sgt_grant,
    bill_sgt_sale,
    proposal_hash_from_bill,
)
from solslot_puzzles.sgt_reserve_driver import SGTAllocationRail
from solslot_puzzles.eip712_helpers import normalize_eip712_member_signature
from solslot_puzzles.vault_driver import compact_signature_from_evm
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseDeliveryKind,
    PurchaseArtifactV3,
    build_sgt_purchase_artifact_v3,
    purchase_artifact_v3_from_json,
    purchase_artifact_v3_to_json,
)

from .admin_auth import AdminClaims, require_admin_jwt
from .admin_security import SecurityActor, require_security_actor
from .admin_key_changes import _bytes32_hex
from .config import Settings, get_settings
from .genesis import get_genesis_store
from .genesis_store import GenesisStore
from .governance_publisher import build_governance_publication
from .governance_execution import build_allocation_execution, build_allocation_vote
from .governance_sale_offer import (
    reconstruct_governed_sale_coin,
    reconstruct_governed_sale_offer,
)
from .governance_queue import (
    GovernanceQueueConflict,
    GovernanceQueueNotFound,
    GovernanceQueueRecord,
    GovernanceQueueStore,
)
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from .bootstrap_manifest import content_hash
from .payment_purchase_store import (
    PaymentPurchaseConflict,
    get_payment_purchase_store,
)
from .protocol_artifacts import _require_server_to_server_token
from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError
from .credential_auth import (
    require_alpha_writes,
    require_vault_record,
    verify_vault_session,
)
from .evm_auth import recover_evm_signer
from .sols_swaps import (
    SolsSwapOfferError,
    _coin_spend_json,
    _require_inputs_clear,
    _verify_aggregate_signature,
)
from .vault_eligibility import ApprovedVault, require_current_approved_vault


router = APIRouter(tags=["governance-queue"])

STRIPE_SGT_SALE_MIN_SECONDS = 11 * 24 * 60 * 60
STRIPE_SGT_SALE_MAX_SECONDS = 14 * 24 * 60 * 60
BASE_USDC_SGT_SALE_MAX_SECONDS = 30 * 60
_store: GovernanceQueueStore | None = None
_store_path: str | None = None
_HEX32 = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_UINT = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MAX_TRACKER_RECONCILE_DEPTH = 4096


def get_governance_queue_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> GovernanceQueueStore:
    global _store, _store_path
    if _store is None or _store_path != settings.admin_db_path:
        if _store is not None:
            _store.close()
        _store = GovernanceQueueStore(settings.admin_db_path)
        _store_path = settings.admin_db_path
    return _store


def require_sgt_allocation_drafts(settings: Settings) -> None:
    if not settings.sgt_allocations_enabled:
        raise HTTPException(status_code=503, detail="SGT allocations are disabled.")
    _treasury(settings)


class CreateGovernanceProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["SGT_SALE", "SGT_GRANT"]
    title: str = Field(min_length=3, max_length=120)
    sgt_amount: str = Field(alias="sgtAmount")
    recipient_vault_launcher_id: str = Field(alias="recipientVaultLauncherId")
    sale_id: str | None = Field(None, alias="saleId")
    payment_rail: Literal["XCH", "WUSDC_B", "STRIPE", "BASE_USDC"] | None = Field(None, alias="paymentRail")
    payment_amount: str | None = Field(None, alias="paymentAmount")
    base_usd_amount_minor: str | None = Field(None, alias="baseUsdAmountMinor")
    expires_at: int | None = Field(None, alias="expiresAt", gt=0)
    grant_id: str | None = Field(None, alias="grantId")
    reason_hash: str | None = Field(None, alias="reasonHash")

    @model_validator(mode="after")
    def validate_shape(self) -> "CreateGovernanceProposal":
        if not _UINT.fullmatch(self.sgt_amount) or int(self.sgt_amount) == 0:
            raise ValueError("sgtAmount must be a positive integer string")
        _b32(
            self.recipient_vault_launcher_id,
            "recipientVaultLauncherId",
            nonzero=True,
        )
        if self.kind == "SGT_SALE":
            if None in (self.sale_id, self.payment_rail, self.expires_at):
                raise ValueError("saleId, paymentRail, and expiresAt are required")
            _b32(str(self.sale_id), "saleId", nonzero=True)
            if self.payment_rail in {"XCH", "WUSDC_B"}:
                if (
                    self.payment_amount is None
                    or not _UINT.fullmatch(self.payment_amount)
                    or int(self.payment_amount) == 0
                ):
                    raise ValueError("paymentAmount must be a positive integer string")
                if self.base_usd_amount_minor is not None:
                    raise ValueError("native sales do not accept baseUsdAmountMinor")
            else:
                if (
                    self.base_usd_amount_minor is None
                    or not _UINT.fullmatch(self.base_usd_amount_minor)
                    or int(self.base_usd_amount_minor) == 0
                ):
                    raise ValueError("baseUsdAmountMinor must be a positive integer string")
                if self.payment_amount is not None:
                    raise ValueError("external payment amounts are derived by the server")
            if self.grant_id is not None or self.reason_hash is not None:
                raise ValueError("grant fields are not accepted for SGT_SALE")
        else:
            if self.grant_id is None or self.reason_hash is None:
                raise ValueError("grantId and reasonHash are required")
            _b32(self.grant_id, "grantId", nonzero=True)
            _b32(self.reason_hash, "reasonHash", nonzero=True)
            if any(value is not None for value in (
                self.sale_id,
                self.payment_rail,
                self.payment_amount,
                self.base_usd_amount_minor,
                self.expires_at,
            )):
                raise ValueError("sale fields are not accepted for SGT_GRANT")
        return self


class ClaimExternalSGTPurchase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purchase_intent_id: str = Field(
        alias="purchaseIntentId",
        min_length=8,
        max_length=96,
        pattern=r"^pi_[A-Za-z0-9_-]+$",
    )
    rail: Literal["stripe", "base_usdc"]
    vault_launcher_id: str = Field(alias="vaultLauncherId")
    current_vault_coin_id: str = Field(alias="currentVaultCoinId")
    identity_attest_root: str = Field(alias="identityAttestRoot")

    @model_validator(mode="after")
    def validate_commitments(self) -> "ClaimExternalSGTPurchase":
        _b32(self.vault_launcher_id, "vaultLauncherId", nonzero=True)
        _b32(self.current_vault_coin_id, "currentVaultCoinId", nonzero=True)
        _b32(self.identity_attest_root, "identityAttestRoot", nonzero=True)
        return self


class TransitionRequest(BaseModel):
    target: Literal["READY", "CANCELED"]


class PublicationPackageRequest(BaseModel):
    coadmin_slot: int = Field(alias="coadminSlot", ge=1, le=2)


class PublicationSignatureRequest(PublicationPackageRequest):
    action_id: str = Field(alias="actionId")
    signature: str

    @field_validator("action_id")
    @classmethod
    def validate_action_id(cls, value: str) -> str:
        _b32(value, "actionId", nonzero=True)
        return "0x" + value.lower().removeprefix("0x")

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        normalized = "0x" + value.lower().removeprefix("0x")
        try:
            raw = bytes.fromhex(normalized[2:])
        except ValueError as exc:
            raise ValueError("signature must be hexadecimal") from exc
        if len(raw) not in (64, 65):
            raise ValueError("signature must be a 64/65-byte wallet signature")
        return normalized


class PrepareAllocationVoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vote_amount: str = Field(alias="voteAmount", min_length=1, max_length=20)

    @field_validator("vote_amount")
    @classmethod
    def validate_vote_amount(cls, value: str) -> str:
        if not _UINT.fullmatch(value) or int(value) <= 0:
            raise ValueError("voteAmount must be a positive integer string")
        if int(value) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("voteAmount exceeds uint64")
        return value


class CompleteAllocationVoteRequest(PrepareAllocationVoteRequest):
    operation_hash: str = Field(alias="operationHash", min_length=66, max_length=66)
    aggregated_signature: str | None = Field(
        default=None,
        alias="aggregatedSignature",
        min_length=194,
        max_length=194,
    )
    vault_owner_authorization: str | None = Field(
        default=None,
        alias="vaultOwnerAuthorization",
        min_length=132,
        max_length=132,
    )

    @field_validator("operation_hash")
    @classmethod
    def validate_operation_hash(cls, value: str) -> str:
        if not _HEX32.fullmatch(value):
            raise ValueError("operationHash must be 32-byte hex")
        return "0x" + value.lower().removeprefix("0x")

def _b32(value: str, label: str, *, nonzero: bool = False) -> bytes32:
    if not _HEX32.fullmatch(value):
        raise ValueError(f"{label} must be 32-byte hex")
    result = bytes32.from_hexstr(value)
    if nonzero and result == bytes32.zeros:
        raise ValueError(f"{label} must be non-zero")
    return result


def _treasury(settings: Settings) -> bytes32:
    value = settings.sgt_company_treasury_puzzle_hash
    if not value:
        raise HTTPException(
            status_code=503,
            detail="Company SGT sale treasury is not configured in release evidence.",
        )
    try:
        configured = _b32(
            value,
            "SOLSLOT_SGT_COMPANY_TREASURY_PUZZLE_HASH",
            nonzero=True,
        )
        artifact = load_signed_public_artifact(settings)
        signed_value = artifact["genesisPlan"]["trustedDestinations"][
            "companySgtSaleTreasuryPuzzleHash"
        ]
        signed = _b32(
            str(signed_value),
            "signed companySgtSaleTreasuryPuzzleHash",
            nonzero=True,
        )
        if configured != signed:
            raise ValueError(
                "configured company SGT treasury does not match the signed artifact"
            )
        return signed
    except (KeyError, TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _reserve_owner(settings: Settings) -> bytes32:
    try:
        artifact = load_signed_public_artifact(settings)
        value = artifact["genesisPlan"]["puzzleHashes"]["sgtReserveInner"]
        return _b32(str(value), "signed sgtReserveInner", nonzero=True)
    except (KeyError, TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _wusdc_b_asset_id(settings: Settings) -> bytes32:
    try:
        configured = _b32(
            str(settings.sgt_wusdc_b_asset_id or ""),
            "SOLSLOT_SGT_WUSDC_B_ASSET_ID",
            nonzero=True,
        )
        artifact = load_signed_public_artifact(settings)
        signed = _b32(
            str(artifact["genesisPlan"]["trustedAssets"]["wusdcBAssetId"]),
            "signed trustedAssets.wusdcBAssetId",
            nonzero=True,
        )
        if configured != signed:
            raise ValueError(
                "configured wUSDC.b asset does not match the signed artifact"
            )
        allowed = {
            _b32(value, "SOLSLOT_PAYMENT_ORACLE_ALLOWED_CAT_ASSET_IDS", nonzero=True)
            for value in settings.payment_oracle_allowed_cat_asset_ids
        }
        if signed not in allowed:
            raise ValueError(
                "configured wUSDC.b asset is not in the signed-oracle CAT allowlist"
            )
        return signed
    except (KeyError, TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _sgt_tail_hash(settings: Settings) -> bytes32:
    try:
        artifact = load_signed_public_artifact(settings)
        plan = artifact.get("genesisPlan")
        value = artifact.get("sgtTailHash")
        if value is None and isinstance(plan, Mapping):
            rules = plan.get("permanentRules")
            if isinstance(rules, Mapping):
                value = rules.get("sgtTailHash")
        return _b32(str(value or ""), "signed SGT tail hash", nonzero=True)
    except (TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _protocol_treasury(settings: Settings) -> bytes32:
    try:
        artifact = load_signed_public_artifact(settings)
        plan = artifact.get("genesisPlan")
        puzzle_hashes = plan.get("puzzleHashes") if isinstance(plan, Mapping) else None
        if not isinstance(puzzle_hashes, Mapping):
            puzzle_hashes = artifact.get("puzzleHashes")
        value = puzzle_hashes.get("protocolTreasuryPuzzleHash") if isinstance(puzzle_hashes, Mapping) else None
        return _b32(str(value or ""), "signed protocol treasury", nonzero=True)
    except (TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _external_sgt_purchase(
    body: CreateGovernanceProposal,
    approved_vault: ApprovedVault,
    settings: Settings,
) -> PurchaseArtifactV3:
    now = int(time.time())
    if body.expires_at is None or body.expires_at <= now:
        raise ValueError("external sale expiry must be in the future")
    lifetime = body.expires_at - now
    if body.payment_rail == "STRIPE":
        if lifetime < STRIPE_SGT_SALE_MIN_SECONDS:
            raise ValueError(
                "Stripe SGT sales must remain available for at least 11 days "
                "so a pending ACH payment can settle"
            )
        if lifetime > STRIPE_SGT_SALE_MAX_SECONDS:
            raise ValueError("Stripe SGT sales cannot remain available for more than 14 days")
    elif lifetime > BASE_USDC_SGT_SALE_MAX_SECONDS:
        raise ValueError("Base USDC sale quote cannot exceed 30 minutes")
    sale_id = _b32(str(body.sale_id), "saleId", nonzero=True)
    rail = PaymentRail.STRIPE
    chain_id = 0
    asset_id = bytes32.zeros
    decimals = 2
    if body.payment_rail == "BASE_USDC":
        rail = PaymentRail.EVM_TEST_USD
        chain_id = 84532
        token = settings.payment_evm_usdc_tokens.get(str(chain_id))
        if token is None:
            raise ValueError("Base Sepolia USDC is not configured")
        normalized = token.lower().removeprefix("0x")
        if len(normalized) != 40:
            raise ValueError("Base Sepolia USDC address is invalid")
        asset_id = bytes32(bytes.fromhex("00" * 12 + normalized))
        decimals = 6
    elif body.payment_rail != "STRIPE":
        raise ValueError("external SGT purchase rail is unsupported")
    artifact = build_sgt_purchase_artifact_v3(
        network=settings.network,
        sgt_asset_id=_sgt_tail_hash(settings),
        sale_id=sale_id,
        sgt_amount=int(body.sgt_amount),
        base_usd_amount_minor=int(str(body.base_usd_amount_minor)),
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=_protocol_treasury(settings),
        zkpassport_root=_b32(
            approved_vault.identity_attest_root,
            "approved vault identity root",
            nonzero=True,
        ),
        rail=rail,
        rail_chain_id=chain_id,
        rail_asset_id=asset_id,
        rail_asset_decimals=decimals,
        vault_launcher_id=_b32(
            approved_vault.launcher_id,
            "approved vault launcher ID",
            nonzero=True,
        ),
        vault_p2_puzzle_hash=_b32(
            approved_vault.p2_puzzle_hash,
            "approved vault p2 puzzle hash",
            nonzero=True,
        ),
        authorization_nonce=bytes32(secrets.token_bytes(32)),
        authorization_expires_at=body.expires_at,
        quote_expires_at=body.expires_at,
    )
    return artifact


def _recipient_vault(
    body: CreateGovernanceProposal,
    settings: Settings,
) -> tuple[ApprovedVault, bytes32]:
    approved = require_current_approved_vault(
        settings,
        body.recipient_vault_launcher_id,
    )
    return approved, _b32(
        approved.p2_puzzle_hash,
        "approved vault p2 puzzle hash",
        nonzero=True,
    )


def _public(
    value: GovernanceQueueRecord,
    *,
    include_private_actor: bool = True,
) -> dict:
    bill = dict(value.bill)
    if not include_private_actor:
        bill.pop("purchaseArtifact", None)
    result = {
        "id": value.id,
        "kind": value.kind,
        "state": value.state,
        "title": value.title,
        "bill": bill,
        "billClvmHex": value.bill_clvm_hex,
        "proposalHash": value.proposal_hash,
        "revision": value.revision,
        "queuePosition": value.queue_position,
        "createdAt": value.created_at,
        "updatedAt": value.updated_at,
        "activatedAt": value.activated_at,
        "completedAt": value.completed_at,
        "activationBundleId": value.activation_bundle_id,
        "proposalCoinId": value.proposal_coin_id,
        "completionBundleId": value.completion_bundle_id,
        "publicationCoadminSlot": value.publication_coadmin_slot,
        "publicationVotingDeadline": value.publication_voting_deadline,
        "executionBundleId": value.execution_bundle_id,
        "expectedOutputCoinIds": list(value.expected_output_coin_ids),
        "executionSubmittedAt": value.execution_submitted_at,
        "saleOffer": (
            {
                "offerId": value.sale_offer_id,
                "saleCoinId": value.sale_coin_id,
                "status": value.sale_offer_status,
                "publishedAt": value.sale_offer_published_at,
                "confirmedHeight": value.sale_offer_confirmed_height,
                "spentHeight": value.sale_offer_spent_height,
                **(
                    {"offerFile": value.sale_offer_bech32}
                    if include_private_actor and value.sale_offer_bech32 is not None
                    else {}
                ),
            }
            if value.kind == "SGT_SALE" and value.sale_offer_id is not None
            else None
        ),
    }
    if include_private_actor:
        result["createdBy"] = value.created_by
    return result


def _uses_native_sgt_offer(value: GovernanceQueueRecord) -> bool:
    return value.kind == "SGT_SALE" and value.bill.get("paymentRail") in {
        "XCH",
        "WUSDC_B",
    }


def _etag(response: Response, value: GovernanceQueueRecord) -> None:
    response.headers["ETag"] = f'"{value.revision}"'


def _if_match(value: str | None) -> int:
    if value is None:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="If-Match is required",
        )
    normalized = value.strip().strip('"')
    if not normalized.isdigit():
        raise HTTPException(status_code=400, detail="If-Match must be a revision")
    return int(normalized)


@router.post("/admin/governance/proposals", status_code=201)
def create_proposal(
    body: CreateGovernanceProposal,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    try:
        require_sgt_allocation_drafts(settings)
        approved_vault, recipient = _recipient_vault(body, settings)
        if body.kind == "SGT_SALE":
            treasury = _treasury(settings)
            reserve_owner = _reserve_owner(settings)
            if recipient == reserve_owner:
                raise ValueError("SGT sale recipient cannot be the governed reserve")
            purchase: PurchaseArtifactV3 | None = None
            purchase_artifact_hash = bytes32.zeros
            if body.payment_rail == "XCH":
                rail_code = 1
                asset = bytes32.zeros
                payment_amount = int(str(body.payment_amount))
            elif body.payment_rail == "WUSDC_B":
                rail_code = 2
                asset = _wusdc_b_asset_id(settings)
                payment_amount = int(str(body.payment_amount))
            else:
                purchase = _external_sgt_purchase(body, approved_vault, settings)
                rail_code = 3 if body.payment_rail == "STRIPE" else 4
                asset = purchase.rail_asset_id
                payment_amount = purchase.rail_amount
                purchase_artifact_hash = purchase.artifact_hash
            bill = bill_sgt_sale(
                sale_id=_b32(str(body.sale_id), "saleId", nonzero=True),
                sgt_amount=int(body.sgt_amount),
                recipient_vault_launcher_id=_b32(
                    approved_vault.launcher_id,
                    "approved vault launcher ID",
                    nonzero=True,
                ),
                payment_rail=rail_code,
                payment_asset_id=asset,
                payment_amount=payment_amount,
                company_treasury_puzzle_hash=treasury,
                expires_at=int(body.expires_at or 0),
                reserve_owner_inner_puzzle_hash=reserve_owner,
                purchase_artifact_hash=purchase_artifact_hash,
            )
            bill_view = {
                "saleId": "0x" + str(body.sale_id).lower().removeprefix("0x"),
                "sgtAmount": body.sgt_amount,
                "recipientVaultLauncherId": approved_vault.launcher_id,
                "recipientVaultIdentityRoot": approved_vault.identity_attest_root,
                "recipientInnerPuzzleHash": "0x" + recipient.hex(),
                "paymentRail": body.payment_rail,
                "paymentAssetId": None if asset == bytes32.zeros else "0x" + asset.hex(),
                "paymentAmount": str(payment_amount),
                "baseUsdAmountMinor": body.base_usd_amount_minor,
                "companyTreasuryPuzzleHash": "0x" + treasury.hex(),
                "expiresAt": body.expires_at,
                "reserveOwnerInnerPuzzleHash": "0x" + reserve_owner.hex(),
                "purchaseArtifact": (
                    purchase_artifact_v3_to_json(purchase)
                    if purchase is not None
                    else None
                ),
                "purchaseArtifactHash": (
                    "0x" + purchase_artifact_hash.hex()
                    if purchase is not None
                    else None
                ),
            }
        else:
            reserve_owner = _reserve_owner(settings)
            bill = bill_sgt_grant(
                grant_id=_b32(str(body.grant_id), "grantId", nonzero=True),
                sgt_amount=int(body.sgt_amount),
                recipient_vault_launcher_id=_b32(
                    approved_vault.launcher_id,
                    "approved vault launcher ID",
                    nonzero=True,
                ),
                reason_hash=_b32(str(body.reason_hash), "reasonHash", nonzero=True),
                reserve_owner_inner_puzzle_hash=reserve_owner,
            )
            bill_view = {
                "grantId": "0x" + str(body.grant_id).lower().removeprefix("0x"),
                "sgtAmount": body.sgt_amount,
                "recipientVaultLauncherId": approved_vault.launcher_id,
                "recipientVaultIdentityRoot": approved_vault.identity_attest_root,
                "recipientInnerPuzzleHash": "0x" + recipient.hex(),
                "reasonHash": "0x" + str(body.reason_hash).lower().removeprefix("0x"),
                "reserveOwnerInnerPuzzleHash": "0x" + reserve_owner.hex(),
            }
        value = store.create(
            kind=body.kind,
            title=body.title,
            bill=bill_view,
            bill_clvm_hex="0x" + bytes(bill).hex(),
            proposal_hash="0x" + proposal_hash_from_bill(bill).hex(),
            actor=claims.sub,
        )
    except (ValueError, GovernanceQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _etag(response, value)
    return _public(value)


class StarterGrantRecipients(BaseModel):
    model_config = ConfigDict(extra='forbid')
    vault_launcher_ids: list[str] = Field(alias='vaultLauncherIds', min_length=3, max_length=3)

    @field_validator('vault_launcher_ids')
    @classmethod
    def distinct_vaults(cls, values: list[str]) -> list[str]:
        normalized = ['0x' + _b32(value, 'administrator vault', nonzero=True).hex() for value in values]
        if len(set(normalized)) != 3:
            raise ValueError('select a different enrolled vault for each administrator')
        return normalized


@router.post('/admin/governance/sgt-starter-grants/preview')
async def preview_starter_grants(
    body: StarterGrantRecipients,
    request: Request,
    _: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Prepare three ordinary grants; publication retains owner-plus-one authority."""
    from .sols_market import _statutes_snapshot
    from .sols_swaps import _required_singleton_tip

    require_sgt_allocation_drafts(settings)
    try:
        artifact = load_signed_public_artifact(settings)
        launchers = artifact['genesisPlan']['launcherIds']
        provider = request.app.state.coinset
        tip = await _required_singleton_tip(provider, launchers['statutes'], 'protocol statutes')
        statutes = await _statutes_snapshot(provider, tip, artifact)
        amount = statutes.parameters.min_proposal_stake
        if amount <= 0:
            raise ValueError('current minimum proposal stake is invalid')
        proposals = []
        for slot, vault_id in enumerate(body.vault_launcher_ids):
            approved = require_current_approved_vault(settings, vault_id)
            # These are explicitly selected recipients. The owner and coadmin
            # review the slot-to-vault mapping before any on-chain allocation.
            grant_id = hashlib.sha256(bytes(Program.to([
                b'SOLSLOT_ADMIN_STARTER_V1', _b32(launchers['adminAuthority'], 'authority'),
                slot, _b32(approved.launcher_id, 'recipient'), amount,
            ]))).hexdigest()
            proposal = CreateGovernanceProposal.model_validate({
                'kind': 'SGT_GRANT', 'title': f'Administrator {slot + 1} starter SGT',
                'sgtAmount': str(amount), 'recipientVaultLauncherId': approved.launcher_id,
                'grantId': '0x' + grant_id,
                'reasonHash': '0x' + hashlib.sha256(b'One minimum proposal stake for administrator participation').hexdigest(),
            })
            proposals.append(proposal.model_dump(by_alias=True, exclude_none=True))
        return {'amountPerAdministrator': str(amount), 'totalAmount': str(amount * 3),
            'statutesCoinId': statutes.live_coin_id,
            'authorityRule': 'Owner administrator plus one of the other two administrators',
            'proposals': proposals}
    except (KeyError, TypeError, ValueError, PublicArtifactError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/admin/governance/sgt-allocation-options")
def get_sgt_allocation_options(
    _: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    require_sgt_allocation_drafts(settings)
    rails = [{"id": "XCH", "label": "XCH", "decimals": 12}]
    try:
        asset_id = _wusdc_b_asset_id(settings)
    except HTTPException:
        pass
    else:
        rails.append(
            {
                "id": "WUSDC_B",
                "label": "wUSDC.b",
                "decimals": 3,
                "assetId": "0x" + asset_id.hex(),
            }
        )
    if settings.stripe_settlement_enabled:
        rails.append(
            {
                "id": "STRIPE",
                "label": "Stripe USD",
                "decimals": 2,
                "serverPriced": True,
            }
        )
    token = settings.payment_evm_usdc_tokens.get("84532")
    if token:
        rails.append(
            {
                "id": "BASE_USDC",
                "label": "Base Sepolia USDC",
                "decimals": 6,
                "chainId": 84532,
                "assetId": token,
                "serverPriced": True,
            }
        )
    return {"paymentRails": rails}


@router.post("/protocol/sgt-sales/{proposal_id}/purchase-artifact")
async def claim_external_sgt_purchase_artifact(
    proposal_id: str,
    body: ClaimExternalSGTPurchase,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """Bind one existing purchase intent to one governed external SGT sale."""

    try:
        require_sgt_allocation_drafts(settings)
        _require_server_to_server_token(settings, authorization)
        record = store.get(proposal_id)
        if record.kind != "SGT_SALE" or record.state != "EXECUTED":
            raise ValueError("SGT sale is not executed and available for payment")
        bill = record.bill if isinstance(record.bill, Mapping) else {}
        expected_rail = "STRIPE" if body.rail == "stripe" else "BASE_USDC"
        if bill.get("paymentRail") != expected_rail:
            raise ValueError("purchase rail does not match the governed SGT sale")
        purchase_json = bill.get("purchaseArtifact")
        if not isinstance(purchase_json, Mapping):
            raise ValueError("governed SGT sale has no external purchase artifact")
        purchase = purchase_artifact_v3_from_json(purchase_json)
        purchase.assert_live(int(time.time()))
        expected_payment_rail = (
            PaymentRail.STRIPE
            if body.rail == "stripe"
            else PaymentRail.EVM_TEST_USD
        )
        if (
            purchase.delivery_kind != PurchaseDeliveryKind.SGT
            or purchase.rail != expected_payment_rail
            or "0x" + purchase.artifact_hash.hex()
            != str(bill.get("purchaseArtifactHash") or "").lower()
        ):
            raise ValueError("governed SGT purchase artifact is inconsistent")

        approved = require_current_approved_vault(
            settings,
            body.vault_launcher_id,
            expected_current_coin_id=body.current_vault_coin_id,
            expected_identity_attest_root=body.identity_attest_root,
        )
        if (
            approved.launcher_id != "0x" + purchase.vault_launcher_id.hex()
            or approved.p2_puzzle_hash != "0x" + purchase.vault_p2_puzzle_hash.hex()
            or approved.identity_attest_root != "0x" + purchase.zkpassport_root.hex()
        ):
            raise ValueError("current approved vault does not match the governed sale")

        provider = getattr(request.app.state, "coinset", None)
        if provider is None:
            raise ValueError("Testnet11 Chia provider is unavailable")
        chain = await reconstruct_governed_sale_coin(
            record=record,
            provider=provider,
            settings=settings,
        )
        terms = chain.terms
        expected_allocation_rail = 3 if body.rail == "stripe" else 4
        if (
            chain.spent_height is not None
            or int(time.time()) >= terms.expires_at
            or int(terms.payment_rail) != expected_allocation_rail
            or terms.purchase_artifact_hash != purchase.artifact_hash
            or terms.payment_amount != purchase.rail_amount
            or terms.sgt_amount != purchase.delivery_amount
            or terms.sale_id != purchase.delivery_context_hash
            or terms.recipient_vault_launcher_id != purchase.vault_launcher_id
        ):
            raise ValueError("governed SGT sale coin is spent, expired, or inconsistent")

        genesis_artifact = load_signed_public_artifact(settings)
        launchers = genesis_artifact.get("launcherIds")
        if not isinstance(launchers, Mapping):
            raise ValueError("signed genesis artifact has no launcher coordinates")
        receipt = approved.enrollment.receipt
        if receipt is None:
            raise ValueError("current approved vault has no credential receipt")
        purchase_artifact_json = purchase_artifact_v3_to_json(purchase)
        zero = "0x" + "00" * 32
        protocol = {
            "instanceId": f"sgt-sale:{record.id}",
            "purchaseIntentId": body.purchase_intent_id,
            "rail": body.rail,
            "deedLauncherId": zero,
            "propertyId": None,
            "collectionId": zero,
            "sharePpm": 0,
            "vaultLauncherId": approved.launcher_id,
            "zkPassportRequired": True,
            "currentState": "artifact_ready",
            "expiresAt": purchase.quote_expires_at,
            "purchaseId": "0x" + purchase.purchase_id.hex(),
            "purchaseArtifactHash": "0x" + purchase.artifact_hash.hex(),
            "governanceProposalId": record.id,
            "proposalHash": record.proposal_hash,
            "saleCoinId": "0x" + chain.sale_coin.name().hex(),
            "deliveryKind": "sgt",
            "deliveryAssetId": "0x" + purchase.delivery_asset_id.hex(),
            "deliveryAmount": str(purchase.delivery_amount),
            "quantity": purchase.delivery_amount,
            "deliveryContextHash": "0x" + purchase.delivery_context_hash.hex(),
        }
        envelope = {
            "schemaVersion": 3,
            "protocolVersion": "solslot-v2",
            "version": 3,
            "kind": "solslot_protocol_offer",
            "network": settings.network,
            "genesisArtifactHash": genesis_artifact.get("artifactHash"),
            "protocol": protocol,
            "vaultCredentialReceipt": receipt.model_dump(),
            "paymentTerms": {
                "currency": "USD" if body.rail == "stripe" else "USDC",
                "amount": str(purchase.rail_amount),
                "quantity": purchase.delivery_amount,
                "usd_amount_minor": str(purchase.gross_usd_amount_minor),
                "asset_id": "0x" + purchase.rail_asset_id.hex(),
                "asset_decimals": purchase.rail_asset_decimals,
                "base_usd_amount_minor": str(purchase.base_usd_amount_minor),
                "technology_fee_bps": purchase.technology_fee_bps,
                "technology_fee_minor": str(purchase.technology_fee_minor),
                "gross_usd_amount_minor": str(purchase.gross_usd_amount_minor),
                "protocol_treasury_puzzle_hash": (
                    "0x" + purchase.protocol_treasury_puzzle_hash.hex()
                ),
            },
            "metadata": {
                "assetType": "SGT",
                "governanceProposalId": record.id,
                "proposalHash": record.proposal_hash,
            },
            "issuedAt": int(time.time()),
            "purchaseArtifactV3": purchase_artifact_json,
            "poolLauncherId": launchers.get("pool"),
            "protocolConfigLauncherId": launchers.get("protocolConfig"),
            "vaultVersionRegistryLauncherId": launchers.get(
                "vaultVersionRegistry"
            ),
        }
        envelope_hash = content_hash(envelope)
        stored = get_payment_purchase_store(settings.payment_purchase_db_path).save(
            purchase_intent_id=body.purchase_intent_id,
            rail=body.rail,
            offer_artifact_hash=envelope_hash,
            offer_artifact=envelope,
            purchase_artifact=purchase_artifact_json,
            created_at=int(time.time()),
        )
        return {
            "artifact": stored.offer_artifact,
            "artifact_hash": stored.offer_artifact_hash,
            "purchase_artifact": stored.purchase_artifact,
            "purchase_artifact_hash": stored.artifact_hash,
            "purchase_id": stored.purchase_id,
            "protocol": protocol,
        }
    except GovernanceQueueNotFound as exc:
        raise HTTPException(status_code=404, detail="SGT sale not found") from exc
    except (PaymentPurchaseConflict, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/admin/governance/proposals")
def list_admin_proposals(
    _: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    require_sgt_allocation_drafts(settings)
    values = store.list()
    return {"proposals": [_public(value) for value in values], "count": len(values)}


@router.get("/committee/proposal-queue")
def list_public_queue(
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    values = store.list(public=True)
    return {
        "proposals": [
            _public(value, include_private_actor=False) for value in values
        ],
        "count": len(values),
    }


@router.get("/governance/sgt-sales")
def list_public_sgt_sales(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    require_sgt_allocation_drafts(settings)
    sales = [
        value
        for value in store.list(public=True)
        if value.kind == "SGT_SALE"
        and value.state == "EXECUTED"
    ]
    return {
        "sales": [
            {
                "proposalId": value.id,
                "title": value.title,
                "proposalHash": value.proposal_hash,
                "terms": value.bill,
                "offer": (
                    {
                        "offerId": value.sale_offer_id,
                        "saleCoinId": value.sale_coin_id,
                        "status": value.sale_offer_status,
                        "statusSource": "cached-index",
                        "publishedAt": value.sale_offer_published_at,
                        "confirmedHeight": value.sale_offer_confirmed_height,
                        "spentHeight": value.sale_offer_spent_height,
                    }
                    if value.bill.get("paymentRail") in {"XCH", "WUSDC_B"}
                    else None
                ),
                "externalPayment": (
                    {
                        "rail": (
                            "stripe"
                            if value.bill.get("paymentRail") == "STRIPE"
                            else "base_usdc"
                        ),
                        "saleCoinId": value.sale_coin_id,
                        "status": value.sale_offer_status,
                        "statusSource": "cached-index",
                        "confirmedHeight": value.sale_offer_confirmed_height,
                        "spentHeight": value.sale_offer_spent_height,
                    }
                    if value.bill.get("paymentRail") in {"STRIPE", "BASE_USDC"}
                    else None
                ),
            }
            for value in sales
        ],
        "count": len(sales),
    }


@router.get("/governance/sgt-sales/{proposal_id}")
async def get_public_sgt_sale(
    proposal_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    require_sgt_allocation_drafts(settings)
    try:
        value = store.get(proposal_id)
        if value.kind != "SGT_SALE" or value.state != "EXECUTED":
            raise GovernanceQueueNotFound(proposal_id)
        provider = getattr(request.app.state, "coinset", None)
        if provider is None:
            raise ValueError("Testnet11 Chia provider is unavailable")
        payment_rail = value.bill.get("paymentRail")
        if payment_rail in {"STRIPE", "BASE_USDC"}:
            chain = await reconstruct_governed_sale_coin(
                record=value,
                provider=provider,
                settings=settings,
            )
            now = int(time.time())
            live_status = (
                "TAKEN"
                if chain.spent_height is not None
                else "EXPIRED"
                if now >= chain.terms.expires_at
                else "AVAILABLE"
            )
            return {
                "proposalId": value.id,
                "title": value.title,
                "proposalHash": value.proposal_hash,
                "terms": value.bill,
                "offer": None,
                "externalPayment": {
                    "rail": "stripe" if payment_rail == "STRIPE" else "base_usdc",
                    "saleCoinId": "0x" + chain.sale_coin.name().hex(),
                    "status": live_status,
                    "statusSource": "live-chain",
                    "confirmedHeight": chain.confirmed_height,
                    "spentHeight": chain.spent_height,
                },
            }
        snapshot = await reconstruct_governed_sale_offer(
            record=value,
            provider=provider,
            settings=settings,
        )
        return {
            "proposalId": value.id,
            "title": value.title,
            "proposalHash": value.proposal_hash,
            "terms": value.bill,
            "offer": {
                "offerId": snapshot.offer_id,
                "offerFile": (
                    snapshot.offer_bech32
                    if snapshot.status == "AVAILABLE"
                    else None
                ),
                "saleCoinId": snapshot.sale_coin_id,
                "status": snapshot.status,
                "statusSource": "live-chain",
                "confirmedHeight": snapshot.confirmed_height,
                "spentHeight": snapshot.spent_height,
            },
            "externalPayment": None,
        }
    except GovernanceQueueNotFound as exc:
        raise HTTPException(status_code=404, detail="SGT sale not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/governance/proposals/{proposal_id}/transition")
def transition_proposal(
    proposal_id: str,
    body: TransitionRequest,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> dict:
    try:
        require_sgt_allocation_drafts(settings)
        value = store.transition(
            proposal_id=proposal_id,
            expected_revision=_if_match(if_match),
            target=body.target,
            actor=claims.sub,
        )
    except GovernanceQueueNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GovernanceQueueConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _etag(response, value)
    return _public(value)


def _publication_view(build, store: GovernanceQueueStore) -> dict:
    signed = {item.action_id for item in store.signatures(build.record.id)}
    return {
        "proposal": _public(build.record),
        "network": "Testnet11",
        "authorityRule": "Owner plus one coadministrator",
        "coadminSlot": build.coadmin_slot,
        "votingDeadline": build.deadline,
        "votingWindowSeconds": max(0, build.deadline - int(time.time())),
        "proposalHash": _hex32(build.proposal_hash),
        "reserveVoteAmount": str(build.reserve_coin.amount),
        "actions": [
            action.to_wire(signed=action.action_id in signed)
            for action in build.actions
        ],
        "readyToSubmit": build.bundle is not None,
        "expectedProposalCoinId": build.proposal_coin_id,
    }


def _hex32(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _tracker_dispatcher(solution: Mapping[str, object]) -> int:
    try:
        outer = list(
            Program.from_bytes(
                bytes.fromhex(str(solution["solution"]).removeprefix("0x"))
            ).as_iter()
        )
        if len(outer) != 3:
            raise ValueError
        inner = list(outer[2].as_iter())
        if len(inner) != 5:
            raise ValueError
        return inner[3].as_int()
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("governance tracker solution is malformed") from exc


def _record_coin(record: Mapping[str, object]) -> Coin | None:
    value = record.get("coin")
    if not isinstance(value, Mapping):
        return None
    try:
        return Coin(
            _b32(str(value.get("parent_coin_info")), "coin parent"),
            _b32(str(value.get("puzzle_hash")), "coin puzzle hash"),
            uint64(int(value.get("amount"))),
        )
    except (TypeError, ValueError):
        return None


async def _proposal_chain_state(provider, proposal_coin_id: str) -> dict:
    current_coin_id = proposal_coin_id
    for depth in range(_MAX_TRACKER_RECONCILE_DEPTH):
        record = await provider.get_coin_record_by_name(current_coin_id)
        if not isinstance(record, Mapping):
            if depth == 0:
                return {"state": "MEMPOOL_OR_WAITING"}
            raise ValueError("governance tracker continuation is unavailable")
        coin = _record_coin(record)
        if coin is None:
            raise ValueError("governance tracker coin record is malformed")
        spent_height = int(record.get("spent_block_index") or 0)
        if spent_height == 0:
            return {
                "state": "VOTING",
                "confirmedHeight": int(record.get("confirmed_block_index") or 0),
                "currentCoinId": _hex32(coin.name()),
            }
        solution = await provider.get_puzzle_and_solution(
            current_coin_id,
            spent_height,
        )
        if not isinstance(solution, Mapping):
            raise ValueError("confirmed governance spend evidence is unavailable")
        dispatcher = _tracker_dispatcher(solution)
        if dispatcher in (TRK_EXECUTE, TRK_EXPIRE):
            return {
                "state": "EXECUTED" if dispatcher == TRK_EXECUTE else "FAILED",
                "confirmedHeight": spent_height,
                "currentCoinId": current_coin_id,
            }
        if dispatcher != TRK_VOTE:
            raise ValueError("governance proposal used an unexpected transition")
        children = await provider.get_coin_records_by_parent_ids(
            [current_coin_id],
            include_spent=True,
        )
        candidates = [
            child_coin
            for child in children
            if isinstance(child, Mapping)
            and (child_coin := _record_coin(child)) is not None
            and int(child_coin.amount) == int(coin.amount)
        ]
        if len(candidates) != 1:
            raise ValueError("governance tracker continuation is missing or ambiguous")
        current_coin_id = _hex32(candidates[0].name())
    raise ValueError("governance tracker lineage exceeds the safety limit")


async def _publication_build(
    *,
    proposal_id: str,
    coadmin_slot: int,
    request: Request,
    settings: Settings,
    genesis_store: GenesisStore,
    queue_store: GovernanceQueueStore,
    actor: SecurityActor,
):
    record = queue_store.get(proposal_id)
    if record.publication_coadmin_slot is None and actor.authority_slot != 0:
        raise ValueError("the owner must assign the publication coadministrator")
    return await build_governance_publication(
        record=record,
        coadmin_slot=coadmin_slot,
        request=request,
        settings=settings,
        genesis_store=genesis_store,
        queue_store=queue_store,
        actor=actor.wallet,
    )


@router.post(
    "/governance/proposals/{proposal_id}/vaults/{vault_launcher_id}/votes/prepare"
)
async def prepare_allocation_vote(
    proposal_id: str,
    vault_launcher_id: str,
    body: PrepareAllocationVoteRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    """Prepare the exact vault, SGT, and tracker spends for one queue vote."""

    try:
        require_alpha_writes(settings)
        require_sgt_allocation_drafts(settings)
        verify_vault_session(settings, request, vault_launcher_id)
        record = queue_store.get(proposal_id)
        build = await build_allocation_vote(
            record=record,
            request=request,
            settings=settings,
            vault_launcher_id=vault_launcher_id,
            vote_amount=int(body.vote_amount),
        )
        return {
            "schemaVersion": 1,
            "proposalId": record.id,
            "proposalHash": _hex32(build.proposal_hash),
            "operationHash": _hex32(build.operation_hash),
            "vaultLauncherId": _hex32(build.vault_launcher_id),
            "vaultCoinId": _hex32(build.vault_coin_id),
            "vaultAuthType": build.vault_auth_type,
            "vaultTypedData": build.vault_typed_data,
            "sgtCoinId": _hex32(build.sgt_coin_id),
            "voteAmount": str(build.sgt_amount),
            "availableSgtAmounts": [
                str(value) for value in build.available_sgt_amounts
            ],
            "votingDeadline": build.chain.voting_deadline,
            "currentVoteTally": str(build.chain.vote_tally),
            "signingCoinSpends": [
                _coin_spend_json(spend) for spend in build.bundle.coin_spends
            ],
            "review": {
                "network": settings.network,
                "action": "Lock SGT for this governance vote",
                "proposalTitle": record.title,
                "proposalHash": _hex32(build.proposal_hash),
                "vaultLauncherId": _hex32(build.vault_launcher_id),
                "sgtAmount": str(build.sgt_amount),
                "financialEffect": (
                    "The selected SGT coin is locked until the proposal deadline. "
                    "It remains bound to this vault."
                ),
                "reversibleAfterSubmission": False,
            },
        }
    except HTTPException:
        raise
    except (GovernanceQueueNotFound, ValueError, SolsSwapOfferError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/governance/proposals/{proposal_id}/vaults/{vault_launcher_id}/votes/complete"
)
async def complete_allocation_vote(
    proposal_id: str,
    vault_launcher_id: str,
    body: CompleteAllocationVoteRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    """Rebuild, verify, fee, and submit one exact vault-custodied SGT vote."""

    try:
        require_alpha_writes(settings)
        require_sgt_allocation_drafts(settings)
        verify_vault_session(settings, request, vault_launcher_id)
        record = queue_store.get(proposal_id)
        prepared = await build_allocation_vote(
            record=record,
            request=request,
            settings=settings,
            vault_launcher_id=vault_launcher_id,
            vote_amount=int(body.vote_amount),
        )
        if _hex32(prepared.operation_hash) != body.operation_hash:
            raise ValueError("vote no longer matches the live vault or tracker state")

        if prepared.vault_auth_type == "chia_bls":
            if body.vault_owner_authorization is not None:
                raise ValueError(
                    "BLS vault authorization belongs in the aggregate signature"
                )
            if body.aggregated_signature is None:
                raise ValueError("wallet aggregate signature is required")
            signature = G2Element.from_bytes(
                bytes.fromhex(body.aggregated_signature.removeprefix("0x"))
            )
            bundle = WalletSpendBundle(prepared.bundle.coin_spends, signature)
            _verify_aggregate_signature(bundle, settings.network)
        else:
            if body.aggregated_signature is not None:
                raise ValueError("EVM vault votes do not accept a BLS signature")
            if (
                body.vault_owner_authorization is None
                or prepared.vault_typed_data is None
            ):
                raise ValueError("EVM vault owner authorization is required")
            owner = require_vault_record(prepared.approved_vault.launcher_id)
            if not owner.owner_evm_address:
                raise ValueError("EVM vault owner address is unavailable")
            recovered = recover_evm_signer(
                prepared.vault_typed_data,
                body.vault_owner_authorization,
            )
            if recovered.address.lower() != owner.owner_evm_address.lower():
                raise ValueError("EVM signature does not belong to this vault owner")
            signed = await build_allocation_vote(
                record=record,
                request=request,
                settings=settings,
                vault_launcher_id=vault_launcher_id,
                vote_amount=int(body.vote_amount),
                signature_data=compact_signature_from_evm(
                    body.vault_owner_authorization
                ),
            )
            if signed.operation_hash != prepared.operation_hash:
                raise ValueError("signed vote changed while it was being authorized")
            bundle = signed.bundle

        await _require_inputs_clear(
            request.app.state.coinset,
            tuple(spend.coin for spend in bundle.coin_spends),
        )
        submitter = getattr(request.app.state, "protocol_submitter", None)
        if not isinstance(submitter, ProtocolBundleSubmitter):
            raise ProtocolSubmissionError(
                "protocol fee-till submission is unavailable"
            )
        submission = await submitter.submit(bundle.to_json_dict())
        return {
            "schemaVersion": 1,
            "proposalId": record.id,
            "proposalHash": _hex32(prepared.proposal_hash),
            "operationHash": _hex32(prepared.operation_hash),
            "vaultLauncherId": _hex32(prepared.vault_launcher_id),
            "sgtCoinId": _hex32(prepared.sgt_coin_id),
            "voteAmount": str(prepared.sgt_amount),
            "status": submission["status"],
            "spendBundleId": submission["spendBundleId"],
            "feeMojos": str(submission["feeMojos"]),
            "feeTargetSeconds": submission["feeTargetSeconds"],
            "submissionProvider": submission["submissionProvider"],
            "mempoolObservedAt": submission["mempoolObservedAt"],
        }
    except HTTPException:
        raise
    except ProtocolSubmissionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (
        GovernanceQueueNotFound,
        TypeError,
        ValueError,
        SolsSwapOfferError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/governance/proposals/{proposal_id}/publication/package")
async def publication_package(
    proposal_id: str,
    body: PublicationPackageRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    genesis_store: Annotated[GenesisStore, Depends(get_genesis_store)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict:
    try:
        require_sgt_allocation_drafts(settings)
        build = await _publication_build(
            proposal_id=proposal_id,
            coadmin_slot=body.coadmin_slot,
            request=request,
            settings=settings,
            genesis_store=genesis_store,
            queue_store=queue_store,
            actor=actor,
        )
        return _publication_view(build, queue_store)
    except (ValueError, GovernanceQueueNotFound, GovernanceQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/governance/proposals/{proposal_id}/publication/signatures")
async def publication_signature(
    proposal_id: str,
    body: PublicationSignatureRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    genesis_store: Annotated[GenesisStore, Depends(get_genesis_store)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict:
    try:
        require_sgt_allocation_drafts(settings)
        build = await _publication_build(
            proposal_id=proposal_id,
            coadmin_slot=body.coadmin_slot,
            request=request,
            settings=settings,
            genesis_store=genesis_store,
            queue_store=queue_store,
            actor=actor,
        )
        action = next(
            (item for item in build.actions if item.action_id == body.action_id),
            None,
        )
        if action is None:
            raise ValueError("signature action is stale")
        if action.signer_slot != actor.authority_slot:
            raise ValueError("this approval belongs to a different administrator")
        normalize_eip712_member_signature(
            signature=bytes.fromhex(body.signature[2:]),
            digest=_bytes32_hex(action.message_hash, "action message hash"),
            compressed_pubkey=bytes.fromhex(action.signer_public_key[2:]),
        )
        queue_store.add_signature(
            proposal_id=proposal_id,
            action_id=action.action_id,
            signer_slot=action.signer_slot,
            signer_public_key=action.signer_public_key,
            message_hash=action.message_hash,
            signature=body.signature,
            actor=actor.wallet,
        )
        refreshed = await _publication_build(
            proposal_id=proposal_id,
            coadmin_slot=body.coadmin_slot,
            request=request,
            settings=settings,
            genesis_store=genesis_store,
            queue_store=queue_store,
            actor=actor,
        )
        return _publication_view(refreshed, queue_store)
    except (ValueError, GovernanceQueueNotFound, GovernanceQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/governance/proposals/{proposal_id}/publication/submit")
async def submit_publication(
    proposal_id: str,
    body: PublicationPackageRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    genesis_store: Annotated[GenesisStore, Depends(get_genesis_store)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict:
    try:
        require_sgt_allocation_drafts(settings)
        if actor.authority_slot != 0:
            raise ValueError("only the owner can submit an approved proposal")
        build = await _publication_build(
            proposal_id=proposal_id,
            coadmin_slot=body.coadmin_slot,
            request=request,
            settings=settings,
            genesis_store=genesis_store,
            queue_store=queue_store,
            actor=actor,
        )
        if build.bundle is None or build.proposal_coin_id is None:
            raise GovernanceQueueConflict("owner-plus-one approvals are incomplete")
        provider = getattr(request.app.state, "coinset", None)
        for spend in build.bundle.coin_spends:
            if await provider.get_mempool_items_by_coin_name(_hex32(spend.coin.name())):
                raise GovernanceQueueConflict("this proposal is already pending in the mempool")
        submitter = getattr(request.app.state, "protocol_submitter", None)
        if not isinstance(submitter, ProtocolBundleSubmitter):
            raise ProtocolSubmissionError("protocol fee-till submission is unavailable")
        submission = await submitter.submit(build.bundle.to_json_dict())
        active = queue_store.transition(
            proposal_id=proposal_id,
            expected_revision=build.record.revision,
            target="ACTIVE",
            actor=actor.wallet,
            activation_bundle_id=str(submission["spendBundleId"]),
            proposal_coin_id=build.proposal_coin_id,
        )
        return {
            "proposal": _public(active),
            "submission": {
                key: submission[key]
                for key in (
                    "status",
                    "network",
                    "spendBundleId",
                    "feeMojos",
                    "feeTargetSeconds",
                    "submissionProvider",
                    "mempoolObservedAt",
                    "ambiguousPushRecovered",
                )
            },
        }
    except ProtocolSubmissionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValueError, GovernanceQueueNotFound, GovernanceQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/governance/proposals/{proposal_id}/reconcile")
async def reconcile_publication(
    proposal_id: str,
    request: Request,
    _: Annotated[SecurityActor, Depends(require_security_actor)],
    settings: Annotated[Settings, Depends(get_settings)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
) -> dict:
    try:
        record = queue_store.get(proposal_id)
        if record.state == "EXECUTED" and _uses_native_sgt_offer(record):
            provider = getattr(request.app.state, "coinset", None)
            if provider is None:
                raise ValueError("Testnet11 Chia provider is unavailable")
            snapshot = await reconstruct_governed_sale_offer(
                record=record,
                provider=provider,
                settings=settings,
            )
            updated = queue_store.record_sale_offer_snapshot(
                proposal_id=record.id,
                offer_id=snapshot.offer_id,
                offer_bech32=snapshot.offer_bech32,
                sale_coin_id=snapshot.sale_coin_id,
                status=snapshot.status,
                confirmed_height=snapshot.confirmed_height,
                spent_height=snapshot.spent_height,
                actor="chain-reconciler",
            )
            return {
                "proposal": _public(updated),
                "chainState": "EXECUTED",
                "saleStatus": snapshot.status,
                "confirmedHeight": snapshot.confirmed_height,
            }
        if record.state != "ACTIVE" or record.proposal_coin_id is None:
            return {"proposal": _public(record), "chainState": record.state}
        provider = getattr(request.app.state, "coinset", None)
        if provider is None:
            raise ValueError("Testnet11 Chia provider is unavailable")
        execution = await build_allocation_execution(
            record=record,
            request=request,
            settings=settings,
        )
        chain = execution.chain
        if chain.state not in {"EXECUTED", "FAILED"}:
            return {
                "proposal": _public(record),
                "chainState": (
                    "EXECUTION_PENDING"
                    if record.execution_bundle_id is not None
                    else chain.state
                ),
                **({"confirmedHeight": chain.confirmed_height} if chain.confirmed_height is not None else {}),
                **({"voteTally": str(chain.vote_tally)} if chain.vote_tally is not None else {}),
                **({"votingDeadline": chain.voting_deadline} if chain.voting_deadline is not None else {}),
                **({"executionBlocker": execution.blocker} if execution.blocker else {}),
            }
        if chain.state == "EXECUTED":
            if record.execution_bundle_id is None or not record.expected_output_coin_ids:
                raise ValueError("tracker executed without recorded reserve allocation evidence")
            for coin_id in record.expected_output_coin_ids:
                output = await provider.get_coin_record_by_name(coin_id)
                if not isinstance(output, Mapping) or int(output.get("confirmed_block_index") or 0) <= 0:
                    raise ValueError("governed SGT allocation output is not confirmed")
            if _uses_native_sgt_offer(record):
                snapshot = await reconstruct_governed_sale_offer(
                    record=record,
                    provider=provider,
                    settings=settings,
                )
                record = queue_store.record_sale_offer_snapshot(
                    proposal_id=record.id,
                    offer_id=snapshot.offer_id,
                    offer_bech32=snapshot.offer_bech32,
                    sale_coin_id=snapshot.sale_coin_id,
                    status=snapshot.status,
                    confirmed_height=snapshot.confirmed_height,
                    spent_height=snapshot.spent_height,
                    actor="chain-reconciler",
                )
        terminal = queue_store.transition(
            proposal_id=proposal_id,
            expected_revision=record.revision,
            target=chain.state,
            actor="chain-reconciler",
            completion_bundle_id=(
                record.execution_bundle_id
                if chain.state == "EXECUTED"
                else f"chain:{chain.current_coin_id}:{chain.confirmed_height}"
            ),
        )
        return {
            "proposal": _public(terminal),
            "chainState": terminal.state,
            "confirmedHeight": chain.confirmed_height,
        }
    except (ValueError, GovernanceQueueNotFound, GovernanceQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/governance/proposals/{proposal_id}/execute")
async def execute_allocation(
    proposal_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue_store: Annotated[GovernanceQueueStore, Depends(get_governance_queue_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict:
    try:
        require_sgt_allocation_drafts(settings)
        record = queue_store.get(proposal_id)
        if record.execution_bundle_id is not None:
            return {
                "proposal": _public(record),
                "chainState": "EXECUTION_PENDING",
                "submission": {"spendBundleId": record.execution_bundle_id},
            }
        build = await build_allocation_execution(
            record=record,
            request=request,
            settings=settings,
        )
        if build.chain.state != "AWAITING_EXECUTE" or build.bundle is None:
            if build.blocker:
                raise GovernanceQueueConflict(build.blocker)
            raise GovernanceQueueConflict(
                f"proposal is {build.chain.state.lower().replace('_', ' ')}"
            )
        provider = getattr(request.app.state, "coinset", None)
        for spend in build.bundle.coin_spends:
            if await provider.get_mempool_items_by_coin_name(_hex32(spend.coin.name())):
                raise GovernanceQueueConflict("this allocation is already pending in the mempool")
        submitter = getattr(request.app.state, "protocol_submitter", None)
        if not isinstance(submitter, ProtocolBundleSubmitter):
            raise ProtocolSubmissionError("protocol fee-till submission is unavailable")
        submission = await submitter.submit(build.bundle.to_json_dict())
        updated = queue_store.record_execution_submission(
            proposal_id=proposal_id,
            expected_revision=record.revision,
            execution_bundle_id=str(submission["spendBundleId"]),
            expected_output_coin_ids=build.expected_output_coin_ids,
            actor=actor.wallet,
        )
        return {
            "proposal": _public(updated),
            "chainState": "EXECUTION_PENDING",
            "submission": {
                key: submission[key]
                for key in (
                    "status",
                    "network",
                    "spendBundleId",
                    "feeMojos",
                    "feeTargetSeconds",
                    "submissionProvider",
                    "mempoolObservedAt",
                    "ambiguousPushRecovered",
                )
            },
            "lockedReserveCoinId": build.locked_reserve_coin_id,
            "expectedOutputCoinIds": list(build.expected_output_coin_ids),
        }
    except ProtocolSubmissionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValueError, GovernanceQueueNotFound, GovernanceQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
