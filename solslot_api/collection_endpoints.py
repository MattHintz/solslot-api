"""Admin and public APIs for chain-verifiable property collections."""
from __future__ import annotations

import secrets
import time
from typing import Annotated, Any, Callable, Literal, Mapping, Optional, TypeVar

import httpx
from chia_rs.sized_bytes import bytes32
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from .admin_auth import AdminClaims, require_admin_jwt
from .admin_operations import require_admin_operation
from .collection_display_units import (
    DisplayUnitError,
    allocate_par_mojos,
    dollars_to_minor,
    ownership_to_ppm,
    percentage_to_bps,
    usd_minor_to_asset_units,
)
from .collection_media import (
    CollectionMediaPipeline,
    MediaPipelineUnavailable,
    MediaVerificationError,
)
from .collection_store import (
    CollectionConflict,
    CollectionForbidden,
    CollectionInvalidState,
    CollectionNotFound,
    CollectionNotReady,
    CollectionStore,
    get_collection_store,
)
from .coinset_client import CoinsetClient
from .config import Settings, get_settings
from .payment_quotes import PaymentQuoteError, load_authorized_oracle_round
from .property_amendment_auth import verify_amendment_signature
from .metadata_chain_indexer import MetadataChainIndexer, MetadataIndexError
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from .property_metadata import (
    ASSET_CLASS_DILIGENCE_KEYS,
    ASSET_CLASS_CODES,
    COMMON_DILIGENCE_KEYS,
    OVERLAY_DILIGENCE_KEYS,
    PROJECT_STAGES,
    PROPERTY_SUBTYPES,
    PROGRAM_OVERLAYS,
    STAGE_DILIGENCE_KEYS,
    PropertyAmendmentV1,
    PropertyDossierDraftV1,
    PropertyDossierV1,
)


router = APIRouter(tags=["property-collections"])
T = TypeVar("T")
HexSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]
DisplayDecimal = Annotated[
    str,
    StringConstraints(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$", max_length=40),
]
DisplayKey = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][A-Za-z0-9_.:-]{0,119}$"),
]


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class CreateCollectionRequest(ApiModel):
    collection_id: Optional[str] = Field(
        default=None, alias="collectionId", min_length=1, max_length=120
    )
    title: str = Field(min_length=1, max_length=180)
    slug: Optional[str] = Field(default=None, min_length=1, max_length=100)


class AssetUploadRequest(ApiModel):
    asset_id: str = Field(alias="assetId", min_length=1, max_length=120)
    kind: str
    filename: str = Field(min_length=1, max_length=240)
    sha256: HexSha256
    mime_type: str = Field(alias="mimeType", min_length=3, max_length=120)
    byte_size: int = Field(alias="byteSize", gt=0)
    role: Optional[str] = Field(default=None, max_length=80)
    title: Optional[str] = Field(default=None, max_length=180)
    alt: Optional[str] = Field(default=None, max_length=240)
    category: Optional[str] = Field(default=None, max_length=80)
    visibility: Literal["PUBLIC", "PRIVATE"] = "PUBLIC"


class CommentRequest(ApiModel):
    section: str = Field(min_length=1, max_length=80)
    body: str = Field(min_length=1, max_length=4000)
    blocking: bool = True


class ReviewRequest(ApiModel):
    decision: str = Field(pattern=r"^(APPROVED|CHANGES_REQUESTED)$")
    note: Optional[str] = Field(default=None, max_length=4000)


class AmendmentRequest(ApiModel):
    dossier: PropertyDossierV1
    amendment: PropertyAmendmentV1


class DisplayUnitConversionRequest(ApiModel):
    money: dict[DisplayKey, DisplayDecimal] = Field(default_factory=dict, max_length=100)
    percentages: dict[DisplayKey, DisplayDecimal] = Field(
        default_factory=dict, max_length=40
    )
    ownership_shares: dict[DisplayKey, DisplayDecimal] = Field(
        default_factory=dict, alias="ownershipShares", max_length=100
    )
    derive_xch_par: bool = Field(default=False, alias="deriveXchPar")

    @field_validator("percentages")
    @classmethod
    def validate_percentage_names(
        cls, value: dict[str, str]
    ) -> dict[str, str]:
        allowed = {"projectedReturn", "technologyFee", "debtRate"}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unsupported percentage field: {sorted(unknown)[0]}")
        return value


def _signed_governance_threshold(settings: Settings) -> int:
    artifact = load_signed_public_artifact(settings)
    parameters = artifact.get("protocolParameters")
    if not isinstance(parameters, Mapping):
        raise PublicArtifactError("signed protocol parameters are unavailable")
    quorum_bps = parameters.get("quorumBps")
    total_supply = parameters.get("sgtTotalSupply")
    if (
        isinstance(quorum_bps, bool)
        or not isinstance(quorum_bps, int)
        or quorum_bps <= 0
        or quorum_bps > 10_000
        or isinstance(total_supply, bool)
        or not isinstance(total_supply, int)
        or total_supply <= 0
    ):
        raise PublicArtifactError("signed governance parameters are invalid")
    threshold = (quorum_bps * total_supply) // 10_000
    if threshold <= 0:
        raise PublicArtifactError("signed governance threshold is invalid")
    return threshold


def require_collection_metadata(
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    if not settings.collection_metadata_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Chain-verifiable collection metadata is disabled.",
        )


def require_collection_minting(
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    require_collection_metadata(settings)
    if not settings.collection_minting_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Collection mint publication is disabled.",
        )


async def _coinset_from_app(request: Request) -> Optional[CoinsetClient]:
    return getattr(request.app.state, "coinset", None)


def _expected_revision(if_match: Optional[str]) -> int:
    if not if_match:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="If-Match with the current collection revision is required.",
        )
    value = if_match.strip()
    if value.startswith("W/"):
        value = value[2:]
    value = value.strip('"')
    try:
        revision = int(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="If-Match must contain a revision integer") from exc
    if revision <= 0:
        raise HTTPException(status_code=400, detail="If-Match revision must be positive")
    return revision


def _with_etag(response: Response, payload: dict[str, Any]) -> dict[str, Any]:
    revision = payload.get("revision")
    if isinstance(revision, int):
        response.headers["ETag"] = f'"{revision}"'
    return payload


def _store_call(call: Callable[[], T]) -> T:
    try:
        return call()
    except CollectionNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CollectionForbidden as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except CollectionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CollectionInvalidState as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CollectionNotReady as exc:
        raise HTTPException(
            status_code=422,
            detail={"message": str(exc), "issues": exc.issues},
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/admin/collections/feature-status",
    dependencies=[Depends(require_admin_jwt)],
)
async def collection_feature_status(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    return {
        "metadataEnabled": settings.collection_metadata_enabled,
        "mintingEnabled": settings.collection_minting_enabled,
        "maxCanonicalBytes": 24 * 1024,
        "maxAssetBytes": settings.collection_asset_max_bytes,
        "network": settings.network,
    }


@router.get(
    "/admin/collections/profiles",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def collection_profiles() -> dict[str, Any]:
    return {
        "assetClasses": [
            {
                "id": name,
                "code": int(code),
                "subtypes": sorted(PROPERTY_SUBTYPES[name]),
            }
            for name, code in ASSET_CLASS_CODES.items()
        ],
        "projectStages": sorted(PROJECT_STAGES),
        "programOverlays": sorted(PROGRAM_OVERLAYS),
        "diligence": {
            "common": sorted(COMMON_DILIGENCE_KEYS),
            "byAssetClass": {
                key: sorted(values) for key, values in ASSET_CLASS_DILIGENCE_KEYS.items()
            },
            "byProjectStage": {
                key: sorted(values) for key, values in STAGE_DILIGENCE_KEYS.items()
            },
            "byProgramOverlay": {
                key: sorted(values) for key, values in OVERLAY_DILIGENCE_KEYS.items()
            },
        },
        "legalRight": "future-sale-or-refinance-proceeds",
    }


@router.post(
    "/admin/collections/display-units/convert",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def convert_collection_display_units(
    body: DisplayUnitConversionRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Convert owner-facing values into canonical protocol integers.

    The browser cannot choose governance or oracle-derived values.  Both are
    taken from cryptographically verified runtime artifacts.
    """

    try:
        money_minor = {
            key: dollars_to_minor(value, label=key)
            for key, value in body.money.items()
        }
        percentage_bps = {
            key: percentage_to_bps(
                value,
                label=key,
                maximum_bps=1_000 if key == "technologyFee" else 10_000,
            )
            for key, value in body.percentages.items()
        }
        ownership_ppm = {
            key: ownership_to_ppm(value, label=key)
            for key, value in body.ownership_shares.items()
        }
        governance_quorum = _signed_governance_threshold(settings)
        result: dict[str, Any] = {
            "moneyMinor": money_minor,
            "percentageBps": percentage_bps,
            "ownershipPpm": ownership_ppm,
            "governanceQuorum": str(governance_quorum),
            "xchParMojos": None,
            "xchOracle": None,
        }
        if not body.derive_xch_par:
            return result

        target_raise = money_minor.get("targetRaise")
        if target_raise is None or int(target_raise) <= 0:
            raise DisplayUnitError(
                "target raise is required before protocol par can be calculated"
            )
        authorized = load_authorized_oracle_round(
            settings,
            asset_id=bytes32.zeros,
            now=int(time.time()),
        )
        round_ = authorized.round
        if round_.network != settings.network:
            raise DisplayUnitError("XCH oracle network does not match this workspace")
        collection_par = usd_minor_to_asset_units(
            int(target_raise),
            price_usd_minor_per_asset=round_.price_usd_minor_per_asset,
            asset_decimals=round_.asset_decimals,
        )
        deed_par = (
            allocate_par_mojos(collection_par, ownership_ppm)
            if sum(ownership_ppm.values()) == 1_000_000
            else {}
        )
        result["xchParMojos"] = {
            "collection": str(collection_par),
            "deeds": {key: str(value) for key, value in deed_par.items()},
        }
        result["xchOracle"] = {
            "priceUsdMinorPerXch": str(round_.price_usd_minor_per_asset),
            "validUntil": round_.valid_until,
            "roundHash": "0x" + round_.round_hash.hex(),
        }
        return result
    except (DisplayUnitError, PaymentQuoteError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PublicArtifactError as exc:
        raise HTTPException(
            status_code=503,
            detail="Signed genesis economics are not available yet.",
        ) from exc


@router.post(
    "/admin/collections",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
    status_code=201,
)
async def create_collection(
    body: CreateCollectionRequest,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    collection_id = body.collection_id or f"COL-{secrets.token_hex(8).upper()}"
    payload = _store_call(
        lambda: store.create(
            collection_id=collection_id,
            title=body.title,
            owner_subject=claims.sub,
            owner_auth_type=claims.auth_type,
            slug=body.slug,
        )
    )
    return _with_etag(response, payload)


@router.get(
    "/admin/collections",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def list_collections(
    store: Annotated[CollectionStore, Depends(get_collection_store)],
    state: Optional[str] = None,
    owner: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    collections = _store_call(
        lambda: store.list(state=state, owner_subject=owner, limit=limit, offset=offset)
    )
    return {"collections": collections, "count": len(collections)}


@router.get(
    "/admin/collections/{collection_id}",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def get_collection(
    collection_id: str,
    response: Response,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    return _with_etag(response, _store_call(lambda: store.get(collection_id)))


@router.put(
    "/admin/collections/{collection_id}",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def update_collection(
    collection_id: str,
    body: PropertyDossierDraftV1,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
    if_match: Annotated[Optional[str], Header(alias="If-Match")] = None,
    submit_for_review: bool = False,
) -> dict[str, Any]:
    payload = _store_call(
        lambda: store.update_draft(
            collection_id,
            draft=body,
            expected_revision=_expected_revision(if_match),
            actor_subject=claims.sub,
            submit_for_review=submit_for_review,
        )
    )
    return _with_etag(response, payload)


@router.post(
    "/admin/collections/{collection_id}/reviews",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def review_collection(
    collection_id: str,
    body: ReviewRequest,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    payload = _store_call(
        lambda: store.submit_review(
            collection_id,
            reviewer_subject=claims.sub,
            decision=body.decision,
            note=body.note,
        )
    )
    return _with_etag(response, payload)


@router.get(
    "/admin/collections/{collection_id}/readiness",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def collection_readiness(
    collection_id: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    return _store_call(lambda: store.readiness(collection_id))


@router.post(
    "/admin/collections/{collection_id}/seal",
    dependencies=[
        Depends(require_admin_operation("collection.seal")),
        Depends(require_collection_metadata),
    ],
)
async def seal_collection(
    collection_id: str,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
    if_match: Annotated[Optional[str], Header(alias="If-Match")] = None,
) -> dict[str, Any]:
    payload = _store_call(
        lambda: store.seal(
            collection_id,
            expected_revision=_expected_revision(if_match),
            actor_subject=claims.sub,
        )
    )
    return _with_etag(response, payload)


@router.post(
    "/admin/collections/{collection_id}/assets/presign",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def presign_collection_asset(
    collection_id: str,
    body: AssetUploadRequest,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    if body.byte_size > settings.collection_asset_max_bytes:
        raise HTTPException(status_code=413, detail="asset exceeds configured upload limit")
    declared = _store_call(
        lambda: store.declare_asset(
            collection_id,
            asset_id=body.asset_id,
            kind=body.kind,
            expected_sha256=body.sha256,
            expected_mime_type=body.mime_type,
            expected_byte_size=body.byte_size,
            actor_subject=claims.sub,
            role=body.role,
            title=body.title,
            alt_text=body.alt,
            category=body.category,
            visibility=body.visibility,
        )
    )
    pipeline = CollectionMediaPipeline(settings)
    try:
        upload = pipeline.presign_upload(
            collection_id=collection_id,
            asset_id=body.asset_id,
            filename=body.filename,
            private=body.visibility == "PRIVATE",
        )
    except (MediaPipelineUnavailable, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    asset = _store_call(
        lambda: store.assign_asset_object_key(
            collection_id,
            body.asset_id,
            object_key=upload["objectKey"],
            actor_subject=claims.sub,
            expected_revision=declared["revision"],
        )
    )
    return {**upload, "asset": asset}


@router.post(
    "/admin/collections/{collection_id}/assets/{asset_id}/complete",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def complete_collection_asset(
    collection_id: str,
    asset_id: str,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    asset = _store_call(lambda: store.get_asset(collection_id, asset_id))
    if not asset["objectKey"]:
        raise HTTPException(status_code=409, detail="asset has no authorized upload destination")
    if asset["state"] in ("PINNED", "VERIFIED"):
        return asset
    asset = _store_call(
        lambda: store.mark_asset_uploaded(
            collection_id, asset_id, object_key=asset["objectKey"], actor_subject=claims.sub,
            expected_revision=asset["revision"],
        )
    )
    try:
        pipeline = CollectionMediaPipeline(settings)
        if asset["visibility"] == "PRIVATE":
            verified = await pipeline.verify_private_document(
                object_key=asset["objectKey"],
                expected_sha256=asset["expectedSha256"],
                expected_mime_type=asset["expectedMimeType"],
                expected_byte_size=asset["expectedByteSize"],
            )
        else:
            verified = await pipeline.verify_and_pin(
                object_key=asset["objectKey"],
                expected_sha256=asset["expectedSha256"],
                expected_mime_type=asset["expectedMimeType"],
                expected_byte_size=asset["expectedByteSize"],
                asset_name=asset_id,
            )
    except (MediaPipelineUnavailable, MediaVerificationError, httpx.HTTPError) as exc:
        _store_call(
            lambda: store.mark_asset_failed(
                collection_id, asset_id, reason=str(exc), actor_subject=claims.sub,
                expected_revision=asset["revision"],
            )
        )
        code = 503 if isinstance(exc, MediaPipelineUnavailable) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    return _store_call(
        lambda: store.mark_asset_verified(
            collection_id,
            asset_id,
            actual_sha256=verified.sha256,
            actual_mime_type=verified.mime_type,
            actual_byte_size=verified.byte_size,
            malware_status=verified.malware_status,
            verified_https_url=getattr(verified, "https_url", None),
            ipfs_cid=getattr(verified, "cid", None),
            availability_status=verified.availability_status,
            actor_subject=claims.sub,
            expected_revision=asset["revision"],
        )
    )


@router.post(
    "/admin/collections/{collection_id}/assets/{asset_id}/private-download",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def authorize_private_collection_asset_download(
    collection_id: str,
    asset_id: str,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    asset = _store_call(
        lambda: store.authorize_private_asset_download(
            collection_id,
            asset_id,
            actor_subject=claims.sub,
        )
    )
    try:
        url = CollectionMediaPipeline(settings).presign_private_download(
            object_key=asset["objectKey"]
        )
    except (MediaPipelineUnavailable, MediaVerificationError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "assetId": asset_id,
        "downloadUrl": url,
        "expiresIn": settings.collection_private_download_ttl_seconds,
    }


@router.post(
    "/admin/collections/{collection_id}/comments",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
    status_code=201,
)
async def add_collection_comment(
    collection_id: str,
    body: CommentRequest,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    return _store_call(
        lambda: store.add_comment(
            collection_id,
            actor_subject=claims.sub,
            section=body.section,
            body=body.body,
            blocking=body.blocking,
        )
    )


@router.post(
    "/admin/collections/{collection_id}/comments/{comment_id}/resolve",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def resolve_collection_comment(
    collection_id: str,
    comment_id: str,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    return _store_call(
        lambda: store.resolve_comment(
            collection_id, comment_id, actor_subject=claims.sub
        )
    )


@router.post(
    "/admin/collections/{collection_id}/amendments",
    dependencies=[
        Depends(require_admin_operation("collection.amend")),
        Depends(require_collection_metadata),
    ],
)
async def append_collection_amendment(
    collection_id: str,
    body: AmendmentRequest,
    response: Response,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[CollectionStore, Depends(get_collection_store)],
    if_match: Annotated[Optional[str], Header(alias="If-Match")] = None,
) -> dict[str, Any]:
    try:
        verify_amendment_signature(body.amendment, claims=claims, settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    payload = _store_call(
        lambda: store.append_amendment(
            collection_id,
            dossier=body.dossier,
            amendment=body.amendment,
            expected_revision=_expected_revision(if_match),
            actor_subject=claims.sub,
        )
    )
    return _with_etag(response, payload)


@router.get(
    "/admin/collections/{collection_id}/audit",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def collection_audit(
    collection_id: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    events = _store_call(lambda: store.audit_events(collection_id))
    return {"events": events, "count": len(events)}


@router.post(
    "/admin/collections/{collection_id}/refresh-chain-evidence",
    dependencies=[Depends(require_admin_jwt), Depends(require_collection_metadata)],
)
async def refresh_collection_chain_evidence(
    collection_id: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
    coinset: Annotated[Optional[CoinsetClient], Depends(_coinset_from_app)],
) -> dict[str, Any]:
    if coinset is None:
        raise HTTPException(status_code=502, detail="Coinset client is not initialized")
    try:
        return await MetadataChainIndexer(coinset, store).refresh(collection_id)
    except CollectionNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except MetadataIndexError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"chain reconstruction failed: {exc}") from exc


@router.get(
    "/public/collections/{identifier}",
    dependencies=[Depends(require_collection_metadata)],
)
async def public_collection(
    identifier: str,
    response: Response,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=300"
    return _store_call(lambda: store.public_collection(identifier))


@router.get(
    "/public/collections/{identifier}/metadata",
    dependencies=[Depends(require_collection_metadata)],
)
async def public_collection_metadata(
    identifier: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    collection = _store_call(lambda: store.public_collection(identifier))
    return {
        "canonicalMetadata": collection["dossier"],
        "metadataRoot": collection["metadataRoot"],
        "metadataAnchorId": collection["metadataAnchorId"],
        "canonicalByteSize": collection["canonicalByteSize"],
        "verification": collection["verification"],
    }


@router.get(
    "/public/collections/{identifier}/versions",
    dependencies=[Depends(require_collection_metadata)],
)
async def public_collection_versions(
    identifier: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    collection = _store_call(lambda: store.public_collection(identifier))
    versions = collection["metadataVersions"]
    return {"versions": versions, "count": len(versions)}


@router.get(
    "/public/collections/{identifier}/evidence",
    dependencies=[Depends(require_collection_metadata)],
)
async def public_collection_evidence(
    identifier: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    collection = _store_call(lambda: store.public_collection(identifier))
    return {
        "metadataRoot": collection["metadataRoot"],
        "metadataAnchorId": collection["metadataAnchorId"],
        "deeds": collection["deeds"],
        "anchorEvidence": collection["anchorEvidence"],
        "verification": collection["verification"],
    }


@router.get(
    "/public/deeds/{deed_id}",
    dependencies=[Depends(require_collection_metadata)],
)
async def public_deed(
    deed_id: str,
    store: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    return _store_call(lambda: store.public_deed(deed_id))


__all__ = [
    "require_collection_metadata",
    "require_collection_minting",
    "router",
]
