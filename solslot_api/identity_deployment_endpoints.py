"""Reviewed, owner-plus-one activation of a new identity verifier set."""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .admin_auth import AdminClaims, require_admin_jwt
from .admin_operations import (
    OperationStore,
    get_operation_store,
    require_admin_operation,
)
from .config import Settings, get_settings
from .identity_deployment_activation import (
    build_identity_activation_bundle,
    identity_activation_request,
    prepare_identity_activation,
)
from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError


router = APIRouter(prefix="/admin/identity-deployment", tags=["admin-identity"])


class ActivateIdentityDeploymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    amendment_hash: str = Field(alias="amendmentHash", pattern=r"^0x[0-9a-fA-F]{64}$")
    revision: int = Field(ge=1)


def _binding(body: dict) -> dict:
    return {
        "schemaVersion": 1,
        "method": "POST",
        "path": "/admin/identity-deployment/activate",
        "query": [],
        "ifMatch": "",
        "body": body,
    }


def _identity_action_wire(action: object, *, signed: bool = False) -> dict:
    wire = action.to_wire(signed=signed)
    wire["title"] = (
        "Owner approves identity verifier activation"
        if action.signer_slot == 0
        else "Coadministrator approves identity verifier activation"
    )
    wire["summary"] = (
        "Approve the exact reviewed zkPassport verifier deployment for new vault checks. "
        "Existing identity receipts remain bound to their saved deployment."
    )
    wire["financialEffect"] = "No funds or assets move in this approval."
    return wire


@router.get("/review")
async def review_identity_deployment(
    request: Request,
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Reconstruct the live action before an approval record is created."""
    try:
        request_body = identity_activation_request(settings)
        build = await prepare_identity_activation(
            binding=_binding(request_body), request=request, settings=settings
        )
        current = build.statement["oldDeployment"]
        replacement = build.statement["newDeployment"]
        return {
            "schemaVersion": 1,
            "status": "ready",
            "operation": "identity.activate",
            "requestBinding": _binding(build.request_body),
            "amendmentHash": build.statement_hash,
            "revision": int(build.statement["revision"]),
            "approvalExpiresAt": int(build.statement["approvalExpiresAt"]),
            "signerSlots": list(build.context["signerSlots"]),
            "currentDeployment": current,
            "replacementDeployment": replacement,
            "acceptedProofVersions": list(replacement["acceptedProofVersions"]),
            "credentialPolicy": build.statement["identityPolicy"],
            "chainActions": [
                _identity_action_wire(action, signed=False) for action in build.actions
            ],
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/activate",
    dependencies=[Depends(require_admin_operation("identity.activate", defer_consume=True))],
)
async def activate_identity_deployment(
    body: ActivateIdentityDeploymentRequest,
    request: Request,
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[OperationStore, Depends(get_operation_store)],
) -> dict:
    """Submit the exact chain action, then consume its HTTP approval."""
    operation = getattr(request.state, "admin_operation", None)
    consume = getattr(request.state, "admin_operation_consume", None)
    if operation is None or consume is None:
        raise HTTPException(status_code=428, detail="Current owner-plus-one approval is required")
    submitted_at = int(time.time())
    try:
        build = await prepare_identity_activation(
            binding=operation["request_binding"], request=request, settings=settings
        )
        if body.model_dump(by_alias=True) != build.request_body:
            raise ValueError("identity activation request differs from its approval")
        signatures = {
            int(item["admin_index"]): item for item in operation["chain_signatures"]
        }
        bundle = build_identity_activation_bundle(build, signatures)

        submitter = getattr(request.app.state, "protocol_submitter", None)
        if settings.protocol_fee_funding_enabled:
            if not isinstance(submitter, ProtocolBundleSubmitter) or submitter.funding_store is None:
                raise HTTPException(
                    status_code=503,
                    detail="Durable identity-activation fee funding is unavailable; nothing was submitted.",
                )
            result = await submitter.submit(
                bundle.to_json_dict(), selection_purpose="identity-activation"
            )
            spend_bundle_id = result["spendBundleId"]
            submission = result
        else:
            if settings.runtime_environment not in {"development", "test"}:
                raise HTTPException(
                    status_code=503,
                    detail="Identity activation requires durable protocol fee funding.",
                )
            result = await request.app.state.coinset.push_tx(bundle.to_json_dict())
            spend_bundle_id = "0x" + bytes(bundle.name()).hex()
            submission = {"status": result.get("status", "SUBMITTED")}

        store.consume(now=submitted_at, **consume)
        # The authority spend may confirm before the service is restarted with
        # replacement EVM bindings. Fence only new enrollments during this
        # transition; existing records remain pinned to their saved deployment.
        request.app.state.identity_deployment_transition = {
            "amendmentHash": build.statement_hash,
            "revision": int(build.statement["revision"]),
            "spendBundleId": spend_bundle_id,
            "submittedAt": submitted_at,
        }
        return {
            "schemaVersion": 1,
            "status": submission["status"],
            "amendmentHash": build.statement_hash,
            "revision": int(build.statement["revision"]),
            "spendBundleId": spend_bundle_id,
            "restartRequired": True,
            "submission": submission,
        }
    except HTTPException:
        raise
    except ProtocolSubmissionError as exc:
        detail = (
            "Identity activation submission needs reconciliation. Its exact funded transaction is retained."
            if exc.submission_attempted
            else str(exc)
        )
        raise HTTPException(status_code=503, detail=detail) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


__all__ = ["router"]
