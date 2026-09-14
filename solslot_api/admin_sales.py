"""Administrator purchase and fulfillment views.

The customer backend owns the durable payment-operation ledger. This module
projects its already-sanitized read model through the coordinator's normal
administrator JWT boundary; browsers never receive the internal service token.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .admin_auth import AdminClaims, require_admin_jwt
from .config import Settings, get_settings
from .governed_output_index import get_governed_output_index
from .stripe_deliveries import normalize_purchase_id, serialize_stripe_delivery
from .stripe_delivery_store import StripeDeliveryNotFound
from .stripe_delivery_worker import StripeDeliveryWorker


router = APIRouter(prefix="/admin/sales", tags=["admin-sales"])


PurchaseState = Literal[
    "created",
    "zk_verified",
    "artifact_ready",
    "payment_pending",
    "paid",
    "protocol_verified",
    "finalized",
    "failed",
    "expired",
    "refund_pending",
    "manual_review",
]


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class PurchaseOperationV1(ApiModel):
    id: str = Field(min_length=1, max_length=128)
    delivery_kind: Literal["smartdeed", "sgt"] = Field(alias="deliveryKind")
    governance_proposal_id: Optional[str] = Field(
        default=None, alias="governanceProposalId", max_length=96
    )
    rail: Literal["chia_xch", "chia_cat", "base_usdc", "stripe"]
    quantity: int = Field(ge=1)
    vault_launcher_id: str = Field(alias="vaultLauncherId", pattern=r"^0x[0-9a-f]{64}$")
    state: PurchaseState
    artifact_hash: Optional[str] = Field(default=None, alias="artifactHash")
    purchase_id: Optional[str] = Field(default=None, alias="purchaseId")
    artifact: Optional[dict[str, Any]] = None
    settlement_evidence: dict[str, Any] = Field(
        default_factory=dict, alias="settlementEvidence"
    )
    created_at: Any = Field(default=None, alias="createdAt")
    updated_at: Any = Field(default=None, alias="updatedAt")
    expires_at: Any = Field(default=None, alias="expiresAt")


class PurchaseOperationsResponse(ApiModel):
    purchase_operations: list[PurchaseOperationV1] = Field(
        alias="purchaseOperations"
    )


@router.get("/purchases", response_model=PurchaseOperationsResponse)
async def list_purchase_operations(
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    state_filter: Annotated[Optional[PurchaseState], Query(alias="state")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> PurchaseOperationsResponse:
    base_url = settings.purchase_operations_service_url
    token = settings.purchase_operations_token
    if not base_url or not token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The purchase operations feed is not configured.",
        )
    params: dict[str, str | int] = {"limit": limit}
    if state_filter:
        params["state"] = state_filter
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                base_url.rstrip("/") + "/internal/protocol/purchase-operations",
                params=params,
                headers={"Authorization": "Bearer " + token},
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The purchase operations feed is temporarily unavailable.",
        ) from exc
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The purchase operations feed rejected the request.",
        )
    try:
        return PurchaseOperationsResponse.model_validate(response.json())
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The purchase operations feed returned an invalid response.",
        ) from exc


@router.post("/purchases/{purchase_id}/reconcile")
async def reconcile_purchase_operation(
    purchase_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
) -> dict[str, Any]:
    """Advance only the immutable purchase already stored by the coordinator."""

    normalized_purchase_id = normalize_purchase_id(purchase_id)
    worker = getattr(request.app.state, "stripe_delivery_worker", None)
    if not isinstance(worker, StripeDeliveryWorker):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="External protocol-asset delivery is not enabled on this release.",
        )
    try:
        operation = await worker.reconcile_once(normalized_purchase_id)
    except StripeDeliveryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if operation is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=worker.unavailable_detail(),
            headers={"Retry-After": "2"},
        )
    outputs = get_governed_output_index(
        settings.payment_purchase_db_path
    ).outputs(operation.purchase_id)
    return serialize_stripe_delivery(operation, governed_outputs=outputs)
