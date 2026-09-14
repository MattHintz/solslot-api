from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from chia_rs.sized_bytes import bytes32

from solslot_api import protocol_artifacts
from solslot_api.config import Settings
from solslot_api.protocol_artifacts import (
    VerifyPurchaseFinalizationRequest,
    _require_server_to_server_token,
    _verify_external_escrow_chain_evidence,
    _verify_stripe_provider_evidence,
    verify_purchase_finalization,
)
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_purchase_artifact_v3,
    purchase_artifact_v3_to_json,
    stripe_settlement_evidence_to_json,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _stripe_purchase_and_evidence():
    vault = _b32(1)
    purchase = build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=_b32(2),
        deed_launcher_id=_b32(3),
        metadata_root=_b32(4),
        metadata_anchor_id=_b32(5),
        share_ppm=50_000,
        base_usd_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=_b32(6),
        zkpassport_root=_b32(7),
        vault_launcher_id=vault,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault),
        authorization_nonce=_b32(8),
        authorization_expires_at=1_900_000_600,
        quote_expires_at=1_900_000_300,
    )
    evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_test_solslot",
        livemode=False,
        payment_intent_id="pi_exact",
        event_id="evt_exact",
        amount_minor=purchase.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.CARD,
        funding_type=StripeFundingType.CREDIT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=1_800_000_100,
    )
    return purchase, evidence


def test_production_internal_service_authentication_fails_closed() -> None:
    settings = Settings(
        runtime_environment="production",
        protocol_artifact_api_token=None,
    )

    with pytest.raises(HTTPException) as exc_info:
        _require_server_to_server_token(settings, None)

    assert exc_info.value.status_code == 503


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


def test_stripe_provider_lookup_binds_payment_to_purchase(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    purchase, evidence = _stripe_purchase_and_evidence()
    key_path = tmp_path / "stripe.read.key"
    key_path.write_text("rk_test_" + "a" * 24, encoding="ascii")
    key_path.chmod(0o600)
    intent = {
        "id": evidence.payment_intent_id,
        "livemode": False,
        "status": "succeeded",
        "created": 1_800_000_000,
        "currency": "usd",
        "amount_received": evidence.amount_minor,
        "metadata": {
            "protocol_purchase_id": "0x" + purchase.purchase_id.hex(),
            "purchase_artifact_hash": "0x" + purchase.artifact_hash.hex(),
        },
        "latest_charge": {
            "payment_method_details": {
                "type": "card",
                "card": {"funding": "credit"},
            },
            "refunded": False,
            "amount_refunded": 0,
            "disputed": False,
        },
    }
    event = {
        "id": evidence.event_id,
        "type": "payment_intent.succeeded",
        "livemode": False,
        "data": {"object": {"id": evidence.payment_intent_id}},
    }

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, path, **_kwargs):
            return _Response(event if path.startswith("/v1/events/") else intent)

    monkeypatch.setattr(protocol_artifacts.httpx, "Client", Client)
    settings = Settings(
        runtime_environment="test",
        stripe_settlement_enabled=True,
        stripe_account_id="acct_test_solslot",
        stripe_mode="test",
        stripe_restricted_key_file=str(key_path),
    )

    _verify_stripe_provider_evidence(settings, purchase, evidence)

    intent["metadata"]["purchase_artifact_hash"] = "0x" + "ff" * 32
    with pytest.raises(
        protocol_artifacts.PaymentArtifactError,
        match="differs from the purchase artifact",
    ):
        _verify_stripe_provider_evidence(settings, purchase, evidence)


@pytest.mark.asyncio
async def test_unverified_stripe_evidence_never_reaches_delivery_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    purchase, evidence = _stripe_purchase_and_evidence()
    purchase_json = purchase_artifact_v3_to_json(purchase)
    monkeypatch.setattr(
        protocol_artifacts,
        "_artifact_rejection_reasons",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        protocol_artifacts,
        "_payment_evidence_rejection_reasons",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        protocol_artifacts,
        "_verify_stripe_provider_evidence",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            protocol_artifacts.PaymentArtifactError("unverified")
        ),
    )
    monkeypatch.setattr(
        protocol_artifacts,
        "get_payment_purchase_store",
        lambda *_args: pytest.fail("unverified evidence reached durable storage"),
    )
    result = await verify_purchase_finalization(
        VerifyPurchaseFinalizationRequest(
            artifact={
                "protocol": {
                    "purchaseIntentId": "internal-purchase",
                    "rail": "stripe",
                    "expiresAt": 1_900_000_300,
                },
                "purchaseArtifactV3": purchase_json,
            },
            artifact_hash="sha256:" + "11" * 32,
            rail="stripe",
            purchase_intent_id="internal-purchase",
            payment_evidence=stripe_settlement_evidence_to_json(evidence),
            now=1_800_000_100,
        ),
        Settings(runtime_environment="test"),
    )

    assert result.verified is False
    assert result.delivery_state is None
    assert result.reasons == ["stripe_provider_unverified"]


def _evm_normalized():
    return {
        "gatewayProfile": "bse",
        "globalPaymentId": "0x" + "11" * 32,
        "purchaseId": "0x" + "12" * 32,
        "artifactHash": "0x" + "13" * 32,
        "amount": 100,
        "quantity": 1,
        "collectionId": "0x" + "14" * 32,
        "deedLauncherId": "0x" + "15" * 32,
        "vaultLauncherId": "0x" + "16" * 32,
        "destinationPuzzle": "0x" + "17" * 32,
        "quoteExpiresAt": 1_900_000_000,
        "depositor": "0x" + "18" * 20,
        "settlementToken": "0x" + "19" * 20,
        "localPaymentId": "0x" + "1a" * 32,
        "source": {
            "chainId": 84532,
            "spoke": "0x" + "20" * 20,
            "transactionHash": "0x" + "21" * 32,
            "blockNumber": 100,
            "blockHash": "0x" + "22" * 32,
            "blockTimestamp": 1_800_000_000,
            "logIndex": 2,
            "confirmations": 12,
        },
    }


def test_evm_callback_is_reconstructed_from_rpc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_escrow_deposit import Chain
    normalized = _evm_normalized()
    # Relayer provenance is PaymentDeposited, not the later PaymentSettled.
    normalized["quoteExpiresAt"] = normalized["source"]["blockTimestamp"] + 300
    chain = Chain(normalized)
    monkeypatch.setattr(protocol_artifacts, "Web3", chain.web3)
    source = normalized["source"]
    settings = Settings(
        runtime_environment="test",
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
    )
    deployment = SimpleNamespace(spoke_address=source["spoke"], confirmations=12)

    _verify_external_escrow_chain_evidence(
        settings,
        normalized=normalized,
        deployment=deployment,
    )

    source["blockHash"] = "0x" + "ff" * 32
    with pytest.raises(
        protocol_artifacts.PaymentArtifactError,
        match="receipt provenance",
    ):
        _verify_external_escrow_chain_evidence(
            settings,
            normalized=normalized,
            deployment=deployment,
        )
