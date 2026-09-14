"""Server-authenticated status and deterministic retry for external delivery."""
from __future__ import annotations

from typing import Annotated, Any, Mapping

import asyncio
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from web3 import Web3
from web3.logs import DISCARD

from .config import Settings, get_settings
from .credential_auth import require_minting_writes
from .launch_gates import require_operation_gate
from .governed_output_index import (
    GovernedOutputRecord,
    get_governed_output_index,
)
from .protocol_artifacts import _require_server_to_server_token
from .omnichain_evidence import OmnichainEvidenceError, load_omnichain_evidence
from .presale_endpoints import (
    BASE_SETTLEMENT_ABI,
    BaseSettlementRelayEvidenceRequest,
    _require_ingest,
)
from .stripe_delivery_store import (
    PAYMENT_RAIL_BASE_USDC,
    StripeDeliveryNotFound,
    StripeDeliveryOperation,
    get_stripe_delivery_store,
)
from .stripe_delivery_worker import StripeDeliveryWorker


router = APIRouter(
    prefix="/protocol/stripe-deliveries",
    tags=["stripe-deliveries"],
)


@router.get("/{purchase_id}")
async def stripe_delivery_status(
    purchase_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_server_to_server_token(settings, authorization)
    try:
        operation = get_stripe_delivery_store(
            settings.stripe_delivery_db_path
        ).get(normalize_purchase_id(purchase_id))
    except StripeDeliveryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    outputs = get_governed_output_index(
        settings.payment_purchase_db_path
    ).outputs(operation.purchase_id)
    return serialize_stripe_delivery(operation, governed_outputs=outputs)


@router.post("/{purchase_id}/reconcile")
async def reconcile_stripe_delivery(
    purchase_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_server_to_server_token(settings, authorization)
    require_minting_writes(settings)
    require_operation_gate(settings, "purchases")
    worker = getattr(request.app.state, "stripe_delivery_worker", None)
    if not isinstance(worker, StripeDeliveryWorker):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="External protocol-asset delivery is not enabled on this release.",
        )
    try:
        operation = await worker.reconcile_once(
            normalize_purchase_id(purchase_id)
        )
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


@router.get("/base-settlements/by-payment/{global_payment_id}")
async def base_direct_settlement_by_payment(
    global_payment_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    payment_id = normalize_purchase_id(global_payment_id)
    try:
        operation = get_stripe_delivery_store(
            settings.stripe_delivery_db_path
        ).get_by_external_payment_id(payment_id)
    except StripeDeliveryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if operation.payment_rail != "base_usdc" or not operation.settlement_authorization:
        raise HTTPException(
            status_code=404,
            detail="Base direct settlement authorization is not ready",
        )
    return _settlement_envelope(operation)


@router.get("/base-settlements/pending")
async def pending_base_direct_settlements(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
    limit: int = 100,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    try:
        operations = get_stripe_delivery_store(
            settings.stripe_delivery_db_path
        ).list_pending_external_settlements(limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "schema": "solslot.base-direct-settlement-authorization.v1",
        "authorizations": [
            _settlement_envelope(operation) for operation in operations
        ],
    }


@router.post("/base-settlements/{authorization_id}/relay-evidence")
async def acknowledge_base_direct_settlement(
    authorization_id: str,
    body: BaseSettlementRelayEvidenceRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    normalized_id = normalize_purchase_id(authorization_id)
    store = get_stripe_delivery_store(settings.stripe_delivery_db_path)
    try:
        operation = store.get_by_settlement_authorization_id(normalized_id)
    except StripeDeliveryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if operation.settlement_authorization is None:
        raise HTTPException(status_code=409, detail="settlement authorization is missing")
    try:
        await asyncio.to_thread(
            _verify_direct_base_relay_evidence,
            settings,
            operation.settlement_authorization,
            body,
        )
        operation = store.record_external_settlement_finalized(
            operation.purchase_id,
            evidence=body.model_dump(by_alias=True),
        )
    except (ValueError, OmnichainEvidenceError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _settlement_envelope(operation)


def serialize_stripe_delivery(
    operation: StripeDeliveryOperation,
    *,
    governed_outputs: tuple[GovernedOutputRecord, ...] = (),
) -> dict[str, Any]:
    return {
        "schemaVersion": 3,
        "purchaseId": operation.purchase_id,
        "paymentRail": operation.payment_rail,
        "deliveryKind": operation.delivery_kind,
        "state": operation.state,
        "receiptFundingBundleId": operation.receipt_funding_bundle_id,
        "receiptCoinId": operation.receipt_coin_id,
        "deliveryBundleId": operation.delivery_bundle_id,
        "expectedSmartDeedCoinId": operation.expected_deed_output_coin_id,
        "expectedSmartDeedCoinIds": list(
            operation.expected_delivery_output_coin_ids
        ) if operation.delivery_kind == "smartdeed" else [],
        "expectedSgtCoinId": operation.expected_sgt_output_coin_id,
        "expectedDeliveryCoinId": operation.expected_delivery_output_coin_id,
        "expectedDeliveryCoinIds": list(
            operation.expected_delivery_output_coin_ids
        ),
        "expectedCoordinationCoinId": operation.expected_treasury_output_coin_id,
        "expectedCoordinationCoinIds": list(
            operation.expected_treasury_output_coin_ids
        ),
        "governedDeliveryOutputs": [
            {
                "ordinal": output.ordinal,
                "deedLauncherId": output.deed_launcher_id,
                "coinId": output.coin_id,
                "parentCoinId": output.parent_coin_id,
                "puzzleHash": output.puzzle_hash,
                "amount": str(output.amount),
                "confirmationHeight": output.confirmation_height,
                "chainConfirmed": output.confirmation_height is not None,
            }
            for output in governed_outputs
        ],
        "expectedTreasuryCoinId": (
            operation.expected_treasury_output_coin_id
            if operation.payment_rail != PAYMENT_RAIL_BASE_USDC
            else None
        ),
        "expectedResultAuthorizationCoinId": (
            operation.expected_treasury_output_coin_id
            if operation.payment_rail == PAYMENT_RAIL_BASE_USDC
            else None
        ),
        "receiptFundingFeeMojos": (
            str(operation.receipt_funding_fee_mojos)
            if operation.receipt_funding_fee_mojos is not None
            else None
        ),
        "deliveryFeeMojos": (
            str(operation.fee_mojos)
            if operation.fee_mojos is not None
            else None
        ),
        "signerIndices": list(operation.signer_indices),
        "mempoolObservedAt": operation.mempool_observed_at,
        "confirmationHeight": operation.confirmation_height,
        "externalSettlementEvidence": operation.external_settlement_evidence,
        "settlementAuthorizationId": operation.settlement_authorization_id,
        "attemptCount": operation.attempt_count,
        "lastError": operation.last_error,
        "createdAt": operation.created_at,
        "updatedAt": operation.updated_at,
    }


def normalize_purchase_id(value: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="purchase ID is invalid") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=422, detail="purchase ID must be 32 bytes")
    return normalized


def _settlement_envelope(operation: StripeDeliveryOperation) -> dict[str, Any]:
    return {
        "authorizationId": operation.settlement_authorization_id,
        "authorizationHash": operation.settlement_authorization_id,
        "state": (
            "RELAYED" if operation.external_settlement_evidence else "PENDING"
        ),
        "authorization": operation.settlement_authorization,
        "createdAt": operation.updated_at,
        "relayedAt": (
            operation.updated_at if operation.external_settlement_evidence else None
        ),
        "relayEvidence": operation.external_settlement_evidence,
    }


def _verify_direct_base_relay_evidence(
    settings: Settings,
    authorization: Mapping[str, Any],
    evidence: BaseSettlementRelayEvidenceRequest,
) -> None:
    payment = authorization.get("payment")
    if not isinstance(payment, Mapping):
        raise ValueError("Base direct payment authorization is malformed")
    token = settings.payment_evm_usdc_tokens.get(str(payment.get("chainId")))
    if not token:
        raise ValueError("Base settlement token is not configured")
    deployment = load_omnichain_evidence(
        settings,
        chain_id=int(payment["chainId"]),
        token_address=token,
        gateway_profile=str(settings.payment_omnichain_gateway_profile or ""),
    )
    if not settings.payment_omnichain_rpc_url:
        raise ValueError("Base settlement RPC is not configured")
    w3 = Web3(
        Web3.HTTPProvider(
            settings.payment_omnichain_rpc_url,
            request_kwargs={"timeout": 20.0},
        )
    )
    try:
        receipt = w3.eth.get_transaction_receipt(evidence.base_transaction_hash)
        block = w3.eth.get_block(evidence.confirmed_block_number)
        latest = int(w3.eth.block_number)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            "Base settlement transaction could not be independently verified"
        ) from exc
    block_number = int(receipt.get("blockNumber") or 0)
    if (
        int(receipt.get("status") or 0) != 1
        or str(receipt.get("to") or "").lower() != deployment.spoke_address
        or block_number != evidence.confirmed_block_number
        or int(block.get("timestamp") or 0) != evidence.confirmed_at
        or latest - block_number + 1 < deployment.confirmations
    ):
        raise ValueError("Base settlement receipt provenance changed")
    spoke = w3.eth.contract(
        address=Web3.to_checksum_address(deployment.spoke_address),
        abi=BASE_SETTLEMENT_ABI,
    )
    events = spoke.events.PaymentSettled().process_receipt(receipt, errors=DISCARD)
    if len(events) != 1:
        raise ValueError("Base settlement event is missing or ambiguous")
    event = events[0]["args"]
    if (
        "0x" + bytes(event["globalPaymentId"]).hex()
        != authorization["globalPaymentId"]
        or str(event["recipient"]).lower() != deployment.governance_root_safe
        or str(event["settlementToken"]).lower() != token.lower()
        or int(event["amount"]) != int(payment["principal"])
        or bool(event["succeeded"]) is not True
        or bool(event["emergency"]) is not False
    ):
        raise ValueError("Base settlement event differs from authorization")
    try:
        deposit = spoke.functions.getDeposit(
            authorization["globalPaymentId"]
        ).call()
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Base settlement deposit storage is unavailable") from exc
    expected = {
        "depositor": "0x" + authorization["originalPayer"][-40:],
        "settlementToken": token.lower(),
        "purchaseId": authorization["purchaseId"],
        "artifactHash": authorization["purchaseArtifactHash"],
        "collectionId": authorization["deliveryContextHash"],
        "deedLauncherId": authorization["deliveryAssetId"],
        "vaultLauncherId": authorization["vaultLauncherId"],
        "destinationPuzzle": authorization["vaultP2PuzzleHash"],
        "warpNonce": evidence.warp_message_id.lower(),
        "amount": int(payment["principal"]),
        "quantity": int(authorization["deliveryAmount"]),
        "status": 3,
        "succeeded": True,
    }
    stored = {
        "depositor": str(deposit[0]).lower(),
        "settlementToken": str(deposit[1]).lower(),
        "purchaseId": "0x" + bytes(deposit[3]).hex(),
        "artifactHash": "0x" + bytes(deposit[4]).hex(),
        "collectionId": "0x" + bytes(deposit[5]).hex(),
        "deedLauncherId": "0x" + bytes(deposit[6]).hex(),
        "vaultLauncherId": "0x" + bytes(deposit[7]).hex(),
        "destinationPuzzle": "0x" + bytes(deposit[8]).hex(),
        "resultMessageId": "0x" + bytes(deposit[10]).hex(),
        "warpNonce": "0x" + bytes(deposit[11]).hex(),
        "amount": int(deposit[12]),
        "quantity": int(deposit[13]),
        "status": int(deposit[18]),
        "succeeded": bool(deposit[19]),
    }
    if any(stored[field] != value for field, value in expected.items()):
        raise ValueError("Base settlement storage differs from authorization")
    if stored["resultMessageId"] == "0x" + "00" * 32:
        raise ValueError("Base settlement result message is missing")


__all__ = ["normalize_purchase_id", "router", "serialize_stripe_delivery"]
