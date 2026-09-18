from __future__ import annotations

import hashlib
import asyncio
import json
import sqlite3
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import HTTPException
from pydantic import ValidationError

from solslot_puzzles import load_puzzle
from solslot_api.config import Settings
from solslot_api.faucet import Faucet
from solslot_api.native_purchases import NativePurchaseContext
from solslot_api.payment_purchase_store import PaymentPurchaseStore, StoredPaymentPurchase
from solslot_api.presale_endpoints import (
    BASE_SEPOLIA_CHAIN_ID,
    BASE_SEPOLIA_USDC,
    BASE_SETTLEMENT_AUTHORIZATION_SCHEMA,
    BaseSettlementRelayEvidenceRequest,
    DeliveryEvidenceRequest,
    PrepareNativeVoucherResponse,
    PresaleCreateRequest,
    PresaleStore,
    RefundEvidenceRequest,
    StripeRefundCompletionRequest,
    StripeVoucherRefundChainEvidence,
    VoucherIssuanceChainEvidence,
    VoucherIssuanceEvidenceRequest,
    VoucherSeriesPhaseChainEvidence,
    _authorize_native_voucher_request,
    _public_presale,
    _require_ingest,
    _verify_base_settlement_relay_evidence,
    _voucher_commitment,
)
from solslot_api.singleton_launcher import (
    build_and_sign_singleton_launch,
    launcher_coin_for_parent,
)
from solslot_api.vault_eligibility import ApprovedVault
from solslot_api.validator_quorum import (
    ValidatorQuorumResult,
    base_settlement_evidence_hash,
)
from solslot_api.voucher_issuance_worker import (
    VoucherIssuanceWorker,
    VoucherIssuanceWorkerConfig,
    _deed_vault_full_puzzle_hash,
)
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentRail,
    PurchaseArtifactV2,
    build_evm_test_usd_purchase_artifact,
    purchase_artifact_from_json,
    purchase_artifact_to_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_purchase_artifact_v3,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_to_json,
)
from solslot_puzzles.mint_publish_driver import (
    deed_launcher_coin_for_parent,
    deed_singleton_struct,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV2,
    make_mint_offer_v4_inner,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    DeedAllocationCommitmentV2,
    VoucherSeriesState,
    VoucherSeriesTermsV2,
    allocation_root,
    series_terms_from_json,
    voucher_commitment_from_json,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    SeriesTransition,
    VoucherAction,
    VoucherSeriesStateV2,
    build_xch_voucher_terminal_spends,
    build_voucher_issuance_spends,
    build_voucher_series_phase_spend,
    curry_purchase_launcher,
    curry_series,
    curry_external_receipt,
    curry_voucher_inner,
    curry_xch_escrow,
)
from solslot_puzzles.voucher_presale_v3 import voucher_commitment_v3_from_json
from solslot_puzzles.voucher_presale_v3_driver import (
    curry_stripe_voucher_receipt,
    curry_voucher_inner_v3,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def hex32(value: bytes32 | int) -> str:
    raw = b32(value) if isinstance(value, int) else value
    return "0x" + bytes(raw).hex()


def evm_address(value: int) -> str:
    return "0x" + bytes([value]).hex() * 20


def evm_payer(value: int) -> bytes32:
    return bytes32(b"\x00" * 12 + bytes([value]) * 20)


def test_terminal_settlement_ingest_remains_available_when_sales_are_closed() -> None:
    token = "settlement-service-token-that-is-long-enough"
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=False,
        minting_enabled=False,
        presale_enabled=False,
        launch_control_enabled=True,
        payment_omnichain_ingest_token=token,
    )

    _require_ingest(settings, f"Bearer {token}")
    with pytest.raises(HTTPException) as rejected:
        _require_ingest(settings, "Bearer wrong-token")
    assert rejected.value.status_code == 401


def test_base_settlement_relay_evidence_is_independently_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    global_payment_id = hex32(1)
    purchase_id = hex32(2)
    artifact_hash = hex32(3)
    collection_id = hex32(4)
    deed_launcher_id = hex32(5)
    vault_launcher_id = hex32(6)
    vault_puzzle_hash = hex32(7)
    result_message_id = hex32(8)
    warp_message_id = hex32(9)
    transaction_hash = hex32(10)
    payer = evm_address(11)
    safe = evm_address(12)
    spoke_address = evm_address(13)
    amount = 1_250_000
    event_args = {
        "globalPaymentId": bytes.fromhex(global_payment_id[2:]),
        "recipient": safe,
        "settlementToken": BASE_SEPOLIA_USDC,
        "amount": amount,
        "succeeded": True,
        "emergency": False,
    }
    deposit = [None] * 20
    deposit[0] = payer
    deposit[1] = BASE_SEPOLIA_USDC
    deposit[3] = bytes.fromhex(purchase_id[2:])
    deposit[4] = bytes.fromhex(artifact_hash[2:])
    deposit[5] = bytes.fromhex(collection_id[2:])
    deposit[6] = bytes.fromhex(deed_launcher_id[2:])
    deposit[7] = bytes.fromhex(vault_launcher_id[2:])
    deposit[8] = bytes.fromhex(vault_puzzle_hash[2:])
    deposit[10] = bytes.fromhex(result_message_id[2:])
    deposit[11] = bytes.fromhex(warp_message_id[2:])
    deposit[12] = amount
    deposit[13] = 1
    deposit[18] = 3
    deposit[19] = True
    receipt = {
        "status": 1,
        "to": spoke_address,
        "blockNumber": 500,
    }

    class FakeCall:
        def call(self):
            return deposit

    class FakeFunctions:
        def getDeposit(self, requested_payment_id):
            assert requested_payment_id == global_payment_id
            return FakeCall()

    class FakePaymentSettled:
        def process_receipt(self, requested_receipt, errors):
            assert requested_receipt is receipt
            assert errors is not None
            return [{"args": event_args}]

    class FakeEvents:
        @staticmethod
        def PaymentSettled():
            return FakePaymentSettled()

    class FakeContract:
        functions = FakeFunctions()
        events = FakeEvents()

    class FakeEth:
        block_number = 511

        @staticmethod
        def get_transaction_receipt(requested_transaction_hash):
            assert requested_transaction_hash == transaction_hash
            return receipt

        @staticmethod
        def get_block(block_number):
            assert block_number == 500
            return {"timestamp": 1_750_000_000}

        @staticmethod
        def contract(address, abi):
            assert address.lower() == spoke_address
            assert abi
            return FakeContract()

    class FakeWeb3:
        eth = FakeEth()

        def __init__(self, provider):
            assert provider == "provider"

        @staticmethod
        def HTTPProvider(url, request_kwargs):
            assert url == "https://base-sepolia.example.invalid"
            assert request_kwargs == {"timeout": 20.0}
            return "provider"

        @staticmethod
        def to_checksum_address(address):
            return address

    monkeypatch.setattr(
        "solslot_api.presale_endpoints.load_omnichain_evidence",
        lambda *_args, **_kwargs: SimpleNamespace(
            spoke_address=spoke_address,
            governance_root_safe=safe,
            confirmations=12,
        ),
    )
    monkeypatch.setattr("solslot_api.presale_endpoints.Web3", FakeWeb3)
    settings = Settings(
        payment_omnichain_rpc_url="https://base-sepolia.example.invalid",
        payment_omnichain_gateway_profile="bse",
        payment_evm_usdc_tokens={
            str(BASE_SEPOLIA_CHAIN_ID): BASE_SEPOLIA_USDC,
        },
    )
    record = {
        "authorization": {
            "outcome": "DELIVERED",
            "globalPaymentId": global_payment_id,
            "purchaseId": purchase_id,
            "purchaseArtifactHash": artifact_hash,
            "collectionId": collection_id,
            "deedLauncherId": deed_launcher_id,
            "vaultLauncherId": vault_launcher_id,
            "vaultP2PuzzleHash": vault_puzzle_hash,
            "originalPayer": "0x" + "00" * 12 + payer[2:],
            "payment": {
                "chainId": BASE_SEPOLIA_CHAIN_ID,
                "principal": str(amount),
            },
        }
    }
    evidence = BaseSettlementRelayEvidenceRequest(
        warpMessageId=warp_message_id,
        baseTransactionHash=transaction_hash,
        confirmedBlockNumber=500,
        confirmedAt=1_750_000_000,
    )

    _verify_base_settlement_relay_evidence(settings, record, evidence)

    event_args["amount"] = amount + 1
    with pytest.raises(ValueError, match="event differs"):
        _verify_base_settlement_relay_evidence(settings, record, evidence)


def test_native_voucher_wire_shape_matches_the_existing_customer_signer() -> None:
    response = PrepareNativeVoucherResponse(
        termsHash=hex32(1),
        purchaseId=hex32(2),
        buyerOffer="offer1signed-later",
        coinSpends=[],
        amount=103,
        assetId=hex32(bytes32.zeros),
        basePriceMinor=100,
        technologyFeeMinor=3,
        grossPriceMinor=103,
        quoteExpiresAt=200,
        refundDeadline=300,
    ).model_dump(by_alias=True)

    assert response["rail"] == "chia_xch"
    assert response["assetId"] == hex32(bytes32.zeros)
    assert response["amount"] == 103


def test_native_voucher_backend_auth_fails_closed_without_a_configured_token() -> None:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        protocol_artifact_api_token=None,
    )

    with pytest.raises(HTTPException) as exc_info:
        _authorize_native_voucher_request(
            settings=settings,
            request=None,  # type: ignore[arg-type]
            vault_launcher_id=hex32(1),
            authorization="Bearer presented-but-unconfigured",
        )

    assert exc_info.value.status_code == 503


def test_native_voucher_backend_auth_accepts_only_the_configured_token() -> None:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        protocol_artifact_api_token="backend-only-token",
    )

    with pytest.raises(HTTPException) as exc_info:
        _authorize_native_voucher_request(
            settings=settings,
            request=None,  # type: ignore[arg-type]
            vault_launcher_id=hex32(1),
            authorization="Bearer wrong-token",
        )
    assert exc_info.value.status_code == 403

    _authorize_native_voucher_request(
        settings=settings,
        request=None,  # type: ignore[arg-type]
        vault_launcher_id=hex32(1),
        authorization="Bearer backend-only-token",
    )


def terms(now: int) -> dict[str, object]:
    protocol_did_struct = singleton_struct(b32(117))
    deed_launchers = tuple(
        bytes32(
            deed_launcher_coin_for_parent(
                parent_coin_name=b32(parent_seed),
                protocol_did_singleton_struct=protocol_did_struct,
            ).name()
        )
        for parent_seed in (118, 119)
    )
    deeds = (
        DeedAllocationCommitmentV2(b32(20), 500_000, 1, deed_launchers[0]),
        DeedAllocationCommitmentV2(b32(21), 500_000, 1, deed_launchers[1]),
    )
    program = VoucherSeriesTermsV2(
        series_singleton_id=b32(1),
        collection_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        allocation_root=allocation_root(deeds),
        trusted_protocol_treasury=b32(5),
        base_return_puzzle_hash=b32(6),
        inventory_cap=2,
        sale_open=now - 10,
        sale_close=now + 100,
        refund_deadline=now + 200,
        launch_deadline=now + 300,
        validator_pubkeys=tuple(
            bytes(AugSchemeMPL.key_gen(bytes([seed]) * 32).get_g1())
            for seed in (1, 2, 3)
        ),
    )
    return {
        "schema": "solslot.refundable-voucher-series.v2",
        "termsHash": hex32(program.terms_hash),
        "seriesSingletonId": hex32(program.series_singleton_id),
        "collectionWorkspaceId": "test-collection",
        "collectionId": hex32(program.collection_id),
        "metadataRoot": hex32(program.metadata_root),
        "metadataAnchorId": hex32(program.metadata_anchor_id),
        "allocationRoot": hex32(program.allocation_root),
        "trustedProtocolTreasury": hex32(program.trusted_protocol_treasury),
        "baseReturnPuzzleHash": hex32(program.base_return_puzzle_hash),
        "inventoryCap": 2,
        "saleOpen": program.sale_open,
        "saleClose": program.sale_close,
        "refundDeadline": program.refund_deadline,
        "launchDeadline": program.launch_deadline,
        "deliveryWindowSeconds": DELIVERY_WINDOW_SECONDS,
        "technologyFeeBps": 250,
        "validatorPubkeys": ["0x" + value.hex() for value in program.validator_pubkeys],
        "deeds": [
            {
                "deedId": f"deed-{index}",
                "deedIdCanon": hex32(deed.deed_id),
                "deedLauncherId": hex32(deed.deed_launcher_id),
                "ordinal": index,
                "sharePpm": deed.share_ppm,
                "parValueMojos": deed.par_value_mojos,
                "basePriceMinor": 100,
                "technologyFeeMinor": 3,
                "grossPriceMinor": 103,
            }
            for index, deed in enumerate(deeds)
        ],
    }


def test_series_id_is_server_derived_from_signed_singleton_launch() -> None:
    with pytest.raises(ValidationError, match="seriesSingletonId"):
        PresaleCreateRequest.model_validate(
            {
                "collectionId": "test-collection",
                "seriesSingletonId": hex32(99),
                "saleOpen": 100,
                "saleClose": 200,
                "refundDeadline": 300,
                "launchDeadline": 400,
            }
        )

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    parent = Coin(b32(98), faucet.address_puzzle_hash, uint64(10))
    expected_launcher = launcher_coin_for_parent(parent)
    launched = build_and_sign_singleton_launch(
        faucet=faucet,
        parent_coin=parent,
        inner_puzzle_for_launcher=lambda launcher_id: Program.to(
            [b"series", launcher_id]
        ),
        launcher_memos=(b"SOLSLOT_PRESALE_SERIES_V2",),
    )

    assert launched.launcher_id == expected_launcher.name()
    assert len(launched.spend_bundle.coin_spends) == 2
    assert launched.full_puzzle_hash != bytes32.zeros
    assert launched.spend_bundle_id.startswith("0x")


def approved_vault() -> ApprovedVault:
    launcher = b32(40)
    return ApprovedVault(
        launcher_id=hex32(launcher),
        p2_puzzle_hash=hex32(puzzle_hash_for_p2_vault(launcher)),
        current_coin_id=hex32(41),
        identity_attest_root=hex32(42),
        confirmed_block_index=100,
        enrollment=SimpleNamespace(
            receipt=SimpleNamespace(network="testnet11")
        ),
    )


def artifact_json(
    current_terms: dict[str, object],
    *,
    deed_index: int = 0,
    nonce: int = 50,
    usd_amount_minor: int = 103,
) -> dict[str, object]:
    vault = approved_vault()
    deed = current_terms["deeds"][deed_index]  # type: ignore[index]
    token = bytes32(
        b"\x00" * 12 + bytes.fromhex(BASE_SEPOLIA_USDC.removeprefix("0x"))
    )
    artifact = build_evm_test_usd_purchase_artifact(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(str(current_terms["metadataAnchorId"])),
        share_ppm=int(deed["sharePpm"]),
        usd_amount_minor=usd_amount_minor,
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        token_asset_id=token,
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(nonce),
        authorization_expires_at=int(current_terms["launchDeadline"]) + 100,
        quote_expires_at=int(current_terms["saleClose"]),
    )
    return purchase_artifact_to_json(artifact)


def issued(
    artifact: dict[str, object],
    *,
    global_payment_id: int,
    bound: bool = True,
) -> StoredPaymentPurchase:
    return StoredPaymentPurchase(
        purchase_id=str(artifact["purchaseId"]),
        artifact_hash=str(artifact["artifactHash"]),
        purchase_intent_id=f"intent-{global_payment_id}",
        rail="base_usdc",
        quote_expires_at=int(artifact["quoteExpiresAt"]),
        offer_artifact_hash=hex32(70),
        offer_artifact={},
        purchase_artifact=artifact,
        external_message=(
            {
                "globalPaymentId": hex32(global_payment_id),
                "depositor": evm_address(80),
                "source": {
                    "chainId": BASE_SEPOLIA_CHAIN_ID,
                    "spoke": evm_address(99),
                    "transactionHash": hex32(global_payment_id + 20),
                    "confirmations": 12,
                },
            }
            if bound
            else None
        ),
    )


def coin_record(coin: Coin, *, confirmed: int = 100, spent: int = 0) -> dict[str, object]:
    return {
        "coin": {
            "parent_coin_info": hex32(coin.parent_coin_info),
            "puzzle_hash": hex32(coin.puzzle_hash),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
        "spent": spent > 0,
    }


class FakeCoinset:
    def __init__(self, faucet_coin: Coin) -> None:
        self.faucet_coin = faucet_coin
        self.records: dict[str, dict[str, object]] = {}
        self.pushed: list[dict[str, object]] = []

    async def get_coin_records_by_puzzle_hash(
        self, _puzzle_hash: str, *, include_spent: bool = False
    ) -> list[dict[str, object]]:
        del include_spent
        return [coin_record(self.faucet_coin)]

    async def get_coin_record_by_name(self, coin_id: str):
        return self.records.get(coin_id.lower())

    async def push_tx(self, bundle: dict[str, object]) -> dict[str, object]:
        self.pushed.append(bundle)
        return {"success": True, "status": "SUCCESS"}


def evidence(
    artifact: dict[str, object],
    current_terms: dict[str, object],
    *,
    global_payment_id: int,
    height: int = 100,
) -> VoucherIssuanceEvidenceRequest:
    return VoucherIssuanceEvidenceRequest(
        purchaseArtifact=artifact,
        globalPaymentId=hex32(global_payment_id),
        originalPayer=hex32(evm_payer(80)),
        evidenceId=f"confirmed-payment-{global_payment_id}",
        confirmedHeight=height,
        transactionIndex=0,
        outputIndex=0,
        confirmedAt=int(current_terms["saleOpen"]) + 1,
    )


def ingest(
    store: PresaleStore,
    current_terms: dict[str, object],
    *,
    deed_index: int = 0,
    nonce: int = 50,
    global_payment_id: int = 60,
    height: int = 100,
) -> dict[str, object]:
    artifact = artifact_json(current_terms, deed_index=deed_index, nonce=nonce)
    return store.ingest_payment(
        str(current_terms["termsHash"]),
        evidence(
            artifact,
            current_terms,
            global_payment_id=global_payment_id,
            height=height,
        ),
        approved_vault=approved_vault(),
        issued_purchase=issued(artifact, global_payment_id=global_payment_id),
        external_escrow_contract=b32(99),
        now_seconds=int(current_terms["saleOpen"]) + 2,
    )


def test_final_stripe_presale_payment_creates_v3_voucher_once() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    vault = approved_vault()
    deed = current_terms["deeds"][0]  # type: ignore[index]
    artifact = build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(
            str(current_terms["metadataAnchorId"])
        ),
        share_ppm=int(deed["sharePpm"]),
        base_usd_amount_minor=int(deed["basePriceMinor"]),
        technology_fee_bps=int(current_terms["technologyFeeBps"]),
        protocol_treasury_puzzle_hash=bytes32.from_hexstr(
            str(current_terms["trustedProtocolTreasury"])
        ),
        zkpassport_root=b32(42),
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(51),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 100,
        presale_terms_hash=bytes32.from_hexstr(
            str(current_terms["termsHash"])
        ),
    )
    evidence_value = StripeSettlementEvidenceV1(
        stripe_account_id="acct_testnet_alpha",
        livemode=False,
        payment_intent_id="pi_stripe_voucher_alpha",
        event_id="evt_stripe_voucher_alpha",
        amount_minor=artifact.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.US_BANK_ACCOUNT,
        funding_type=StripeFundingType.BANK_ACCOUNT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=now + 2,
    )
    receipt = build_stripe_settlement_receipt_v1(
        artifact=artifact,
        evidence=evidence_value,
        validator_pubkeys=tuple(
            bytes.fromhex(str(value).removeprefix("0x"))
            for value in current_terms["validatorPubkeys"]  # type: ignore[index]
        ),
    )
    artifact_value = purchase_artifact_v3_to_json(artifact)
    stored = StoredPaymentPurchase(
        purchase_id=str(artifact_value["purchaseId"]),
        artifact_hash=str(artifact_value["artifactHash"]),
        purchase_intent_id="pi_stripe_presale",
        rail="stripe",
        quote_expires_at=artifact.quote_expires_at,
        offer_artifact_hash=hex32(70),
        offer_artifact={},
        purchase_artifact=artifact_value,
        external_message=None,
    )

    first = store.ingest_stripe_payment(
        str(current_terms["termsHash"]),
        artifact=artifact,
        receipt=receipt,
        evidence_id=evidence_value.event_id,
        issued_purchase=stored,
    )
    second = store.ingest_stripe_payment(
        str(current_terms["termsHash"]),
        artifact=artifact,
        receipt=receipt,
        evidence_id=evidence_value.event_id,
        issued_purchase=stored,
    )
    voucher = store.voucher(str(current_terms["termsHash"]), 0)

    assert first["outcome"] == second["outcome"] == "PAYMENT_CONFIRMED"
    assert first["voucherState"] == second["voucherState"] == "PENDING_ISSUANCE"
    assert voucher["paymentRail"] == "STRIPE_USD"
    assert voucher["processingChargeMinor"] == 0
    assert voucher["purchaseArtifact"] == artifact_value
    assert voucher["settlementReceipt"]["receiptHash"] == hex32(
        receipt.receipt_hash
    )


def stripe_escrowed_voucher(
    *, now: int
) -> tuple[PresaleStore, dict[str, object], StripeSettlementEvidenceV1]:
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    vault = approved_vault()
    deed = current_terms["deeds"][0]  # type: ignore[index]
    artifact = build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(
            str(current_terms["metadataAnchorId"])
        ),
        share_ppm=int(deed["sharePpm"]),
        base_usd_amount_minor=int(deed["basePriceMinor"]),
        technology_fee_bps=int(current_terms["technologyFeeBps"]),
        protocol_treasury_puzzle_hash=bytes32.from_hexstr(
            str(current_terms["trustedProtocolTreasury"])
        ),
        zkpassport_root=b32(42),
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(53),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 100,
        presale_terms_hash=bytes32.from_hexstr(
            str(current_terms["termsHash"])
        ),
    )
    payment = StripeSettlementEvidenceV1(
        stripe_account_id="acct_testnet_alpha",
        livemode=False,
        payment_intent_id="pi_stripe_refund_alpha",
        event_id="evt_stripe_refund_alpha",
        amount_minor=artifact.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.US_BANK_ACCOUNT,
        funding_type=StripeFundingType.BANK_ACCOUNT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=now + 2,
    )
    receipt = build_stripe_settlement_receipt_v1(
        artifact=artifact,
        evidence=payment,
        validator_pubkeys=tuple(
            bytes.fromhex(str(value).removeprefix("0x"))
            for value in current_terms["validatorPubkeys"]  # type: ignore[index]
        ),
    )
    artifact_json_v3 = purchase_artifact_v3_to_json(artifact)
    stored = StoredPaymentPurchase(
        purchase_id=str(artifact_json_v3["purchaseId"]),
        artifact_hash=str(artifact_json_v3["artifactHash"]),
        purchase_intent_id="pi_stripe_refund_alpha",
        rail="stripe",
        quote_expires_at=artifact.quote_expires_at,
        offer_artifact_hash=hex32(71),
        offer_artifact={},
        purchase_artifact=artifact_json_v3,
        external_message=None,
    )
    store.ingest_stripe_payment(
        str(current_terms["termsHash"]),
        artifact=artifact,
        receipt=receipt,
        evidence_id=payment.event_id,
        issued_purchase=stored,
    )
    confirm_issuance(store, current_terms)
    return store, current_terms, payment


def test_stripe_refund_requires_terminal_chain_evidence_before_fiat() -> None:
    now = int(time.time())
    store, current_terms, payment = stripe_escrowed_voucher(now=now)
    terms_hash = str(current_terms["termsHash"])
    requested = store.request_refund(
        terms_hash,
        0,
        vault_launcher_id=approved_vault().launcher_id,
        now_seconds=now + 10,
    )
    assert requested["state"] == "ESCROWED"

    series = store.get(terms_hash)
    current_coin_id = str(series["chainState"]["currentCoinId"])
    next_state = VoucherSeriesStateV2(sold_count=1, refunded_count=1)
    next_inner = curry_series(series_terms_from_json(current_terms), next_state)
    evidence_hash = hex32(payment.evidence_hash)
    store.bind_stripe_terminal_execution(
        terms_hash,
        0,
        {
            "schema": "solslot.stripe-voucher-terminal-execution.v1",
            "mode": "REFUND_OWNER",
            "voucherAction": int(VoucherAction.REFUND_PRESALE),
            "prepared": {
                "spendBundleId": hex32(201),
                "feeMojos": "5",
                "feeCoinId": hex32(206),
                "spendBundle": {},
            },
            "request": {},
            "outputRoles": {},
            "bindings": {},
        },
    )
    submitted = store.record_stripe_refund_submission(
        terms_hash,
        0,
        action=VoucherAction.REFUND_PRESALE,
        spend_bundle_id=hex32(201),
        external_settlement_evidence_hash=evidence_hash,
        terminal_voucher_coin_id=hex32(202),
        series_input_coin_id=current_coin_id,
        series_output_coin_id=hex32(203),
        vault_input_coin_id=hex32(204),
        vault_output_coin_id=hex32(205),
        execution_observed_at=now + 11,
    )
    retried = store.record_stripe_refund_submission(
        terms_hash,
        0,
        action=VoucherAction.REFUND_PRESALE,
        spend_bundle_id=hex32(201),
        external_settlement_evidence_hash=evidence_hash,
        terminal_voucher_coin_id=hex32(202),
        series_input_coin_id=current_coin_id,
        series_output_coin_id=hex32(203),
        vault_input_coin_id=hex32(204),
        vault_output_coin_id=hex32(205),
        execution_observed_at=now + 99,
    )
    assert retried == submitted
    confirmed = store.confirm_stripe_refund(
        terms_hash,
        0,
        StripeVoucherRefundChainEvidence(
            action=int(VoucherAction.REFUND_PRESALE),
            evidenceId="chia:stripe-refund-confirmed",
            spendBundleId=hex32(201),
            externalSettlementEvidenceHash=evidence_hash,
            terminalVoucherCoinId=hex32(202),
            seriesInputCoinId=current_coin_id,
            seriesInputParentCoinId=hex32(206),
            seriesOutputCoinId=hex32(203),
            seriesOutputInnerPuzzleHash=hex32(next_inner.get_tree_hash()),
            vaultInputCoinId=hex32(204),
            vaultOutputCoinId=hex32(205),
            confirmedHeight=300,
        ),
    )
    assert confirmed["state"] == "REFUNDED"
    pending = store.pending_stripe_refund_authorizations()
    assert len(pending) == 1
    authorization = pending[0]
    assert authorization["paymentIntentId"] == payment.payment_intent_id
    assert authorization["amountMinor"] == str(payment.amount_minor)

    completed = store.complete_stripe_refund_authorization(
        authorization["authorizationId"],
        StripeRefundCompletionRequest(
            paymentIntentId=payment.payment_intent_id,
            refundId="re_stripe_refund_alpha",
            refundedMinor=payment.amount_minor,
            currency="usd",
            livemode=False,
            observedAt=now + 20,
        ),
    )
    assert completed["state"] == "COMPLETED"


def _rehearsal_terminal(mode: str, seed: int) -> dict[str, object]:
    roles = (
        {
            "coordination": hex32(seed + 10),
            "deed": hex32(seed + 11),
            "series": hex32(seed + 12),
            "terminalVoucher": hex32(seed + 13),
        }
        if mode == "REDEEM"
        else {
            "series": hex32(seed + 12),
            "terminalVoucher": hex32(seed + 13),
            "vault": hex32(seed + 14),
        }
    )
    return {
        "schema": "solslot.stripe-voucher-terminal-execution.v1",
        "mode": mode,
        "voucherAction": 3 if mode == "REDEEM" else 1,
        "signerIndices": [0, 2],
        "request": {
            "action": 7,
            "purchaseId": hex32(seed + 1),
            "artifactHash": hex32(seed + 2),
        },
        "prepared": {
            "spendBundleId": hex32(seed + 3),
            "feeMojos": "5",
            "feeCoinId": hex32(seed + 4),
        },
        "outputRoles": roles,
        "bindings": {},
    }


@pytest.mark.parametrize("outcome", ["delivery", "refund"])
def test_stripe_rehearsal_projection_requires_terminal_production_evidence(
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    now = int(time.time())
    store, current_terms, payment = stripe_escrowed_voucher(now=now)
    terms_hash = str(current_terms["termsHash"])
    voucher = store.voucher(terms_hash, 0)
    artifact = voucher["purchaseArtifact"]
    assert isinstance(artifact, dict)
    execution = _rehearsal_terminal(
        "REDEEM" if outcome == "delivery" else "REFUND_OWNER",
        220,
    )
    execution["request"]["purchaseId"] = artifact["purchaseId"]  # type: ignore[index]
    execution["request"]["artifactHash"] = artifact["artifactHash"]  # type: ignore[index]
    roles = execution["outputRoles"]
    assert isinstance(roles, dict)
    monkeypatch.setattr(
        "solslot_api.presale_endpoints.parse_stripe_terminal_execution",
        lambda *_args, **_kwargs: execution,
    )
    with store.txn() as cur:
        if outcome == "delivery":
            cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REDEEMED', terminal_exact_execution_json=?,
                    terminal_execution_observed_at=?, redemption_bundle_id=?,
                    redemption_treasury_output_coin_id=?,
                    redemption_deed_output_coin_id=?,
                    redemption_terminal_voucher_coin_id=?,
                    redemption_series_output_coin_id=?,
                    redemption_confirmed_height=?
                WHERE terms_hash=? AND serial=0
                """,
                (
                    json.dumps(execution),
                    now + 10,
                    execution["prepared"]["spendBundleId"],  # type: ignore[index]
                    roles["coordination"],
                    roles["deed"],
                    roles["terminalVoucher"],
                    roles["series"],
                    300,
                    terms_hash,
                ),
            )
        else:
            cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDED', terminal_exact_execution_json=?,
                    terminal_execution_observed_at=?, refund_bundle_id=?,
                    terminal_voucher_coin_id=?, refund_series_output_coin_id=?,
                    refund_vault_output_coin_id=?, refund_confirmed_height=?
                WHERE terms_hash=? AND serial=0
                """,
                (
                    json.dumps(execution),
                    now + 10,
                    execution["prepared"]["spendBundleId"],  # type: ignore[index]
                    roles["terminalVoucher"],
                    roles["series"],
                    roles["vault"],
                    301,
                    terms_hash,
                ),
            )
            completion = StripeRefundCompletionRequest(
                paymentIntentId=payment.payment_intent_id,
                refundId="re_rehearsal_projection_exact",
                refundedMinor=payment.amount_minor,
                currency="usd",
                livemode=False,
                observedAt=now + 20,
            ).model_dump(by_alias=True)
            cur.execute(
                """
                INSERT INTO stripe_refund_authorizations_v3(
                  authorization_id, terms_hash, serial, purchase_id,
                  authorization_json, state, created_at, completed_at,
                  completion_json
                ) VALUES (?, ?, 0, ?, '{}', 'COMPLETED', ?, ?, ?)
                """,
                (
                    hex32(250),
                    terms_hash,
                    voucher["purchaseId"],
                    now,
                    now + 20,
                    json.dumps(completion),
                ),
            )

    candidates = store.stripe_rehearsal_candidates(
        created_after=now - 1,
        vault_launcher_id=approved_vault().launcher_id,
        collection_id=str(current_terms["collectionId"]),
    )
    assert len(candidates[outcome]) == 1
    lane = candidates[outcome][0]
    assert lane["execution"]["action"] == 7
    assert lane["execution"]["feeMojos"] == "5"
    assert lane["voucher"]["signerIndices"] == [0, 1]
    if outcome == "refund":
        assert lane["exactRefund"] is True
        assert lane["stripeRefund"]["refundedMinor"] == str(
            payment.amount_minor
        )


def test_stripe_terminal_execution_serializes_each_singleton_series() -> None:
    now = int(time.time())
    store, current_terms, _payment = stripe_escrowed_voucher(now=now)
    terms_hash = str(current_terms["termsHash"])
    execution = {
        "schema": "solslot.stripe-voucher-terminal-execution.v1",
        "mode": "REDEEM",
        "voucherAction": int(VoucherAction.REDEEM),
        "prepared": {
            "spendBundleId": hex32(210),
            "feeMojos": "5",
            "feeCoinId": hex32(211),
            "spendBundle": {},
        },
        "request": {},
        "outputRoles": {},
        "bindings": {},
    }
    store.bind_stripe_terminal_execution(terms_hash, 0, execution)
    assert store.pending_stripe_terminal_fee_coin_ids() == {hex32(211)}
    second_deed = current_terms["deeds"][1]  # type: ignore[index]
    store._conn.execute(
        """
        INSERT INTO voucher_records_v2(
          terms_hash, serial, deed_launcher_id, payment_rail,
          payment_principal, base_price_minor, technology_fee_bps,
          technology_fee_minor, gross_price_minor, original_payer,
          vault_launcher_id, vault_p2_puzzle_hash, purchase_id,
          global_payment_id, commitment_hash, commitment_json, state,
          payment_evidence_id, created_at, updated_at
        ) VALUES (?, 1, ?, 'STRIPE_USD', 103, 100, 250, 3, 103, ?, ?, ?,
                  ?, ?, ?, '{}', 'ESCROWED', 'evt-second', ?, ?)
        """,
        (
            terms_hash.lower(),
            str(second_deed["deedLauncherId"]).lower(),
            hex32(212),
            approved_vault().launcher_id,
            approved_vault().p2_puzzle_hash,
            hex32(213),
            hex32(214),
            hex32(215),
            now,
            now,
        ),
    )

    competing = deepcopy(execution)
    competing["prepared"]["spendBundleId"] = hex32(216)
    with pytest.raises(ValueError, match="singleton series"):
        store.bind_stripe_terminal_execution(terms_hash, 1, competing)
    assert store.pending_stripe_refund_authorizations() == []


def test_generic_delivery_cannot_complete_a_stripe_voucher() -> None:
    now = int(time.time())
    store, current_terms, _payment = stripe_escrowed_voucher(now=now)
    with pytest.raises(ValueError, match="exact atomic Chia confirmation"):
        store.complete_delivery(
            str(current_terms["termsHash"]),
            0,
            DeliveryEvidenceRequest(
                evidenceId="generic-stripe-delivery",
                outputCoinId=hex32(210),
                deedLauncherId=str(
                    current_terms["deeds"][0]["deedLauncherId"]  # type: ignore[index]
                ),
                vaultP2PuzzleHash=approved_vault().p2_puzzle_hash,
            ),
        )


def create_series(
    store: PresaleStore, current_terms: dict[str, object]
) -> dict[str, object]:
    series_id = bytes32.from_hexstr(str(current_terms["seriesSingletonId"]))
    initial_inner = curry_series(
        series_terms_from_json(current_terms),
        VoucherSeriesStateV2(),
    )
    full_puzzle = puzzle_for_singleton(series_id, initial_inner)
    return store.create(
        current_terms,
        singleton_launch={
            "parentCoinId": hex32(129),
            "fullPuzzleHash": hex32(bytes32(full_puzzle.get_tree_hash())),
            "spendBundleId": hex32(128),
        },
    )


def test_presale_store_creates_parent_directory(tmp_path: Path) -> None:
    database_path = tmp_path / "fresh-state" / "presale.db"

    store = PresaleStore(str(database_path))

    assert database_path.is_file()


def test_pre_stripe_voucher_table_migrates_without_losing_records(
    tmp_path: Path,
) -> None:
    now = int(time.time())
    current_terms = terms(now)
    database_path = tmp_path / "presale.db"
    original = PresaleStore(str(database_path))
    create_series(original, current_terms)
    expected = ingest(original, current_terms)
    original._conn.close()

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=OFF")
    current_schema = str(
        connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            ("voucher_records_v2",),
        ).fetchone()["sql"]
    )
    legacy_schema = current_schema.replace(
        "CREATE TABLE voucher_records_v2",
        "CREATE TABLE voucher_records_v2_legacy",
        1,
    ).replace(", 'STRIPE_USD'", "")
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(legacy_schema)
    columns = [
        str(row[1])
        for row in connection.execute(
            "PRAGMA table_info(voucher_records_v2)"
        ).fetchall()
    ]
    columns_sql = ", ".join(f'"{name}"' for name in columns)
    connection.execute(
        f"INSERT INTO voucher_records_v2_legacy ({columns_sql}) "
        f"SELECT {columns_sql} FROM voucher_records_v2"
    )
    connection.execute("DROP TABLE voucher_records_v2")
    connection.execute(
        "ALTER TABLE voucher_records_v2_legacy RENAME TO voucher_records_v2"
    )
    connection.execute("COMMIT")
    connection.close()

    upgraded = PresaleStore(str(database_path))
    restored = upgraded.voucher(str(current_terms["termsHash"]), 0)
    schema = str(
        upgraded._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            ("voucher_records_v2",),
        ).fetchone()["sql"]
    )

    assert restored["globalPaymentId"] == expected["globalPaymentId"]
    assert restored["paymentRail"] == "BASE_SEPOLIA_USDC"
    assert "STRIPE_USD" in schema
    assert upgraded._conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_public_presale_redacts_vouchers_and_vault_view_is_scoped() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    ingest(store, current_terms)

    full = store.get(str(current_terms["termsHash"]))
    assert len(full["vouchers"]) == 1
    assert "vouchers" not in _public_presale(full)

    launcher_id = approved_vault().launcher_id
    scoped = store.vouchers_for_vault(launcher_id)
    assert len(scoped) == 1
    assert scoped[0]["vaultLauncherId"] == launcher_id
    assert scoped[0]["termsHash"] == current_terms["termsHash"]
    assert scoped[0]["seriesState"] == "PRESALE"
    assert scoped[0]["deedId"] == "deed-0"
    assert "commitment" not in scoped[0]
    assert store.vouchers_for_vault(hex32(255)) == []


def confirm_issuance(
    store: PresaleStore,
    current_terms: dict[str, object],
    serial: int = 0,
) -> dict[str, object]:
    offset = serial * 10
    purchase_launcher = hex32(131 + offset)
    series = store.get(str(current_terms["termsHash"]))
    chain_state = series["chainState"]
    series_input = str(chain_state["currentCoinId"])
    series_input_parent = (
        str(current_terms["seriesSingletonId"])
        if serial == 0
        else str(
            store.voucher(str(current_terms["termsHash"]), serial - 1)[
                "seriesInputCoinId"
            ]
        )
    )
    next_state = VoucherSeriesStateV2(
        sold_count=int(chain_state["soldCount"]) + 1,
        redeemed_count=int(chain_state["redeemedCount"]),
        refunded_count=int(chain_state["refundedCount"]),
    )
    next_inner = curry_series(series_terms_from_json(current_terms), next_state)
    next_full = puzzle_for_singleton(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        next_inner,
    )
    series_output = hex32(
        bytes32(
            Coin(
                bytes32.from_hexstr(series_input),
                bytes32(next_full.get_tree_hash()),
                uint64(1),
            ).name()
        )
    )
    store.record_issuance_funding(
        str(current_terms["termsHash"]),
        serial,
        funding_bundle_id=hex32(130 + offset),
        purchase_launcher_coin_id=purchase_launcher,
        purchase_launcher_puzzle_hash=hex32(137 + offset),
    )
    store.record_issuance_submission(
        str(current_terms["termsHash"]),
        serial,
        issuance_bundle_id=hex32(138 + offset),
        voucher_launcher_id=hex32(132 + offset),
        voucher_output_coin_id=hex32(133 + offset),
        payment_commitment_coin_id=hex32(134 + offset),
        series_input_coin_id=series_input,
        series_output_coin_id=series_output,
        signer_indices=(0, 1),
    )
    return store.confirm_issuance(
        str(current_terms["termsHash"]),
        serial,
        VoucherIssuanceChainEvidence(
            evidenceId=f"chain-confirmed-voucher-{serial}",
            spendBundleId=hex32(138 + offset),
            purchaseLauncherCoinId=purchase_launcher,
            voucherLauncherId=hex32(132 + offset),
            voucherOutputCoinId=hex32(133 + offset),
            paymentCommitmentCoinId=hex32(134 + offset),
            seriesInputCoinId=series_input,
            seriesInputParentCoinId=series_input_parent,
            seriesOutputCoinId=series_output,
            seriesOutputInnerPuzzleHash=hex32(bytes32(next_inner.get_tree_hash())),
            confirmedHeight=200 + serial,
        ),
    )


def native_escrowed_voucher(
    *, now: int
) -> tuple[
    PresaleStore,
    dict[str, object],
    VoucherSeriesTermsV2,
    object,
    object,
    PurchaseArtifactV2,
]:
    """Create one fully chain-confirmed native voucher through public store APIs."""
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    deed = current_terms["deeds"][0]  # type: ignore[index]
    vault = approved_vault()
    rail_amount = (103 * 10**12 + 2_500 - 1) // 2_500
    artifact = PurchaseArtifactV2(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(
            str(current_terms["metadataAnchorId"])
        ),
        share_ppm=int(deed["sharePpm"]),
        usd_amount_minor=103,
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=12,
        rail_amount=rail_amount,
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(180),
        authorization_expires_at=int(current_terms["saleClose"]),
        quote_expires_at=int(current_terms["saleClose"]),
        oracle_round_hash=b32(181),
        oracle_price_usd_minor_per_asset=2_500,
        source_evidence_root=b32(182),
    )
    artifact_payload = purchase_artifact_to_json(artifact)
    purchase = StoredPaymentPurchase(
        purchase_id=str(artifact_payload["purchaseId"]),
        artifact_hash=str(artifact_payload["artifactHash"]),
        purchase_intent_id="native-redemption-intent",
        rail="chia_xch",
        quote_expires_at=artifact.quote_expires_at,
        offer_artifact_hash=hex32(183),
        offer_artifact={},
        purchase_artifact=artifact_payload,
        external_message=None,
    )
    payment_source = Coin(b32(184), b32(185), uint64(rail_amount + 10))
    series = store.get(str(current_terms["termsHash"]))
    commitment = _voucher_commitment(
        series=series,
        deed=deed,
        artifact=artifact,
        original_payer=hex32(payment_source.puzzle_hash),
        global_payment_id=hex32(186),
        approved_vault=vault,
        external_escrow_contract=bytes32.zeros,
    )
    program_terms = series_terms_from_json(current_terms)
    payment_puzzle = curry_xch_escrow(
        terms=program_terms,
        voucher=commitment,
        purchase=artifact,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=program_terms,
        voucher=commitment,
        payment_puzzle_hash=bytes32(payment_puzzle.get_tree_hash()),
        payment_amount=rail_amount,
    )
    purchase_launcher = Coin(
        payment_source.name(),
        bytes32(launcher_puzzle.get_tree_hash()),
        uint64(rail_amount + 1),
    )
    series_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    issuance = build_voucher_issuance_spends(
        terms=program_terms,
        state=VoucherSeriesStateV2(),
        series_coin=series_coin,
        series_lineage_proof=LineageProof(bytes32.zeros, None, uint64(1)),
        voucher=commitment,
        purchase_launcher_coin=purchase_launcher,
        payment_puzzle=payment_puzzle,
        payment_amount=rail_amount,
        signer_indices=(0, 1),
    )
    submitted = store.record_native_issuance_submission(
        str(current_terms["termsHash"]),
        artifact=artifact,
        issued_purchase=purchase,
        approved_vault=vault,
        payment_coin=payment_source,
        global_payment_id=hex32(186),
        commitment=commitment,
        spend_bundle_id=hex32(187),
        purchase_launcher_coin=purchase_launcher,
        voucher_launcher_id=hex32(issuance.voucher_launcher_id),
        voucher_output_coin_id=hex32(issuance.voucher_coin.name()),
        payment_commitment_coin_id=hex32(issuance.payment_coin.name()),
        series_input_coin=series_coin,
        series_output_coin_id=hex32(issuance.next_series_coin.name()),
        submitted_at=now,
    )
    sold_state = VoucherSeriesStateV2(sold_count=1)
    sold_inner = curry_series(program_terms, sold_state)
    store.confirm_issuance(
        str(current_terms["termsHash"]),
        0,
        VoucherIssuanceChainEvidence(
            evidenceId="native-redemption-issuance-confirmed",
            spendBundleId=str(submitted["issuanceBundleId"]),
            purchaseLauncherCoinId=str(submitted["purchaseLauncherCoinId"]),
            voucherLauncherId=str(submitted["voucherLauncherId"]),
            voucherOutputCoinId=str(submitted["voucherOutputCoinId"]),
            paymentCommitmentCoinId=str(submitted["paymentCommitmentCoinId"]),
            seriesInputCoinId=str(submitted["seriesInputCoinId"]),
            seriesInputParentCoinId=hex32(series_coin.parent_coin_info),
            seriesOutputCoinId=str(submitted["seriesOutputCoinId"]),
            seriesOutputInnerPuzzleHash=hex32(sold_inner.get_tree_hash()),
            confirmedHeight=190,
        ),
    )
    return store, current_terms, program_terms, issuance, commitment, artifact


def native_redemption_confirmation_fixture(
    *, now: int, tmp_path: Path, altered_deed_destination: bool = False
) -> tuple[VoucherIssuanceWorker, PresaleStore, dict[str, object]]:
    store, current_terms, program_terms, issuance, commitment, _artifact = (
        native_escrowed_voucher(now=now)
    )
    launch_anchor = int(current_terms["saleClose"])
    live_state = VoucherSeriesStateV2(
        sold_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=launch_anchor,
    )
    phase = build_voucher_series_phase_spend(
        terms=program_terms,
        state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(
            issuance.series_spend
        ),
        transition=SeriesTransition.LAUNCH,
        launch_anchor=launch_anchor,
        signer_indices=(0, 1),
    )
    live_inner = curry_series(program_terms, live_state)
    live_series_coin = phase.next_series_coin
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="LIVE",
        spend_bundle_id=hex32(188),
        series_input_coin_id=hex32(issuance.next_series_coin.name()),
        series_output_coin_id=hex32(live_series_coin.name()),
        series_output_inner_puzzle_hash=hex32(live_inner.get_tree_hash()),
        launch_anchor=launch_anchor,
        governance_execution_ids=[hex32(189), hex32(190)],
    )
    store.confirm_phase_transition(
        str(current_terms["termsHash"]),
        VoucherSeriesPhaseChainEvidence(
            evidenceId="native-redemption-series-live",
            spendBundleId=hex32(188),
            targetState="LIVE",
            seriesInputCoinId=hex32(issuance.next_series_coin.name()),
            seriesInputParentCoinId=hex32(
                issuance.next_series_coin.parent_coin_info
            ),
            seriesOutputCoinId=hex32(live_series_coin.name()),
            seriesOutputInnerPuzzleHash=hex32(live_inner.get_tree_hash()),
            launchAnchor=launch_anchor,
            confirmedHeight=200,
        ),
    )

    redeemed_state = VoucherSeriesStateV2(
        sold_count=1,
        redeemed_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=launch_anchor,
    )
    redeemed_inner = curry_series(program_terms, redeemed_state)
    redeemed_series_coin = Coin(
        live_series_coin.name(),
        bytes32(
            puzzle_for_singleton(
                program_terms.series_singleton_id,
                redeemed_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    terminal_voucher = Coin(
        issuance.voucher_coin.name(),
        bytes32(
            puzzle_for_singleton(
                issuance.voucher_launcher_id,
                load_puzzle("voucher_burn_v2.clsp"),
            ).get_tree_hash()
        ),
        uint64(1),
    )
    deed_input = Coin(b32(191), b32(192), uint64(1))
    deed_destination = (
        b32(193)
        if altered_deed_destination
        else _deed_vault_full_puzzle_hash(
            commitment.deed_launcher_id,
            commitment.approved_vault_launcher_id,
        )
    )
    deed_output = Coin(b32(194), deed_destination, uint64(1))
    treasury_output = Coin(
        b32(195),
        program_terms.trusted_protocol_treasury,
        uint64(commitment.payment_principal),
    )
    store.record_redemption_submission(
        str(current_terms["termsHash"]),
        0,
        spend_bundle_id=hex32(196),
        treasury_output_coin_id=hex32(treasury_output.name()),
        deed_output_coin_id=hex32(deed_output.name()),
        terminal_voucher_coin_id=hex32(terminal_voucher.name()),
        series_input_coin_id=hex32(live_series_coin.name()),
        series_output_coin_id=hex32(redeemed_series_coin.name()),
        deed_input_coin_id=hex32(deed_input.name()),
    )

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    coinset = FakeCoinset(Coin(b32(197), faucet.address_puzzle_hash, uint64(20)))
    confirmed_height = 210
    for coin in (
        treasury_output,
        deed_output,
        terminal_voucher,
        redeemed_series_coin,
    ):
        coinset.records[hex32(coin.name())] = coin_record(
            coin, confirmed=confirmed_height
        )
    for coin in (
        live_series_coin,
        issuance.voucher_coin,
        issuance.payment_coin,
        deed_input,
    ):
        coinset.records[hex32(coin.name())] = coin_record(
            coin, confirmed=200, spent=confirmed_height
        )
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=PaymentPurchaseStore(str(tmp_path / "redemption-purchases.db")),
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )
    return worker, store, current_terms


def test_confirmed_payment_waits_for_chain_before_issuing_bound_voucher() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)

    event = ingest(store, current_terms)

    assert event["outcome"] == "PAYMENT_CONFIRMED"
    voucher = event["voucher"]
    assert voucher["vaultLauncherId"] == approved_vault().launcher_id
    assert voucher["vaultP2PuzzleHash"] == approved_vault().p2_puzzle_hash
    assert voucher["originalPayer"] == hex32(evm_payer(80))
    assert voucher["globalPaymentId"] == hex32(60)
    assert voucher["state"] == "PENDING_ISSUANCE"
    with pytest.raises(ValueError, match="not refundable"):
        store.request_refund(
            str(current_terms["termsHash"]),
            0,
            vault_launcher_id=approved_vault().launcher_id,
            now_seconds=now,
        )
    issued = confirm_issuance(store, current_terms)
    assert issued["state"] == "ESCROWED"
    assert issued["issuanceConfirmedHeight"] == 200


@pytest.mark.asyncio
async def test_native_redemption_requires_exact_atomic_deed_delivery(
    tmp_path: Path,
) -> None:
    bad_worker, bad_store, bad_terms = native_redemption_confirmation_fixture(
        now=int(time.time()),
        tmp_path=tmp_path,
        altered_deed_destination=True,
    )

    rejected = await bad_worker.reconcile_once()

    assert rejected[0]["status"] == "REDEMPTION_ERROR"
    assert "SmartDeed destination" in rejected[0]["detail"]
    assert bad_store.voucher(str(bad_terms["termsHash"]), 0)["state"] == "REDEEMING"
    assert bad_store.get(str(bad_terms["termsHash"]))["chainState"][
        "redeemedCount"
    ] == 0

    good_worker, good_store, good_terms = native_redemption_confirmation_fixture(
        now=int(time.time()),
        tmp_path=tmp_path,
    )

    confirmed = await good_worker.reconcile_once()

    assert confirmed == [
        {
            "termsHash": str(good_terms["termsHash"]),
            "serial": 0,
            "status": "REDEEMED",
        }
    ]
    voucher = good_store.voucher(str(good_terms["termsHash"]), 0)
    assert voucher["state"] == "REDEEMED"
    assert voucher["redemptionConfirmedHeight"] == 210
    assert voucher["deliveryOutputCoinId"] == voucher["redemptionDeedOutputCoinId"]
    assert good_store.get(str(good_terms["termsHash"]))["chainState"][
        "redeemedCount"
    ] == 1
    assert good_store.pending_base_settlement_authorizations() == []


@pytest.mark.asyncio
async def test_expired_native_delivery_refunds_without_a_second_owner_spend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wall_clock = int(time.time())
    fixture_now = wall_clock - DELIVERY_WINDOW_SECONDS - 500
    (
        store,
        current_terms,
        program_terms,
        issuance,
        commitment,
        artifact,
    ) = native_escrowed_voucher(now=fixture_now)
    launch_anchor = int(current_terms["saleClose"])
    live_state = VoucherSeriesStateV2(
        sold_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=launch_anchor,
    )
    phase = build_voucher_series_phase_spend(
        terms=program_terms,
        state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(
            issuance.series_spend
        ),
        transition=SeriesTransition.LAUNCH,
        launch_anchor=launch_anchor,
        signer_indices=(0, 1),
    )
    live_inner = curry_series(program_terms, live_state)
    live_series_coin = phase.next_series_coin
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="LIVE",
        spend_bundle_id=hex32(198),
        series_input_coin_id=hex32(issuance.next_series_coin.name()),
        series_output_coin_id=hex32(live_series_coin.name()),
        series_output_inner_puzzle_hash=hex32(live_inner.get_tree_hash()),
        launch_anchor=launch_anchor,
        governance_execution_ids=[hex32(199)],
    )
    store.confirm_phase_transition(
        str(current_terms["termsHash"]),
        VoucherSeriesPhaseChainEvidence(
            evidenceId="expired-refund-series-live",
            spendBundleId=hex32(198),
            targetState="LIVE",
            seriesInputCoinId=hex32(issuance.next_series_coin.name()),
            seriesInputParentCoinId=hex32(
                issuance.next_series_coin.parent_coin_info
            ),
            seriesOutputCoinId=hex32(live_series_coin.name()),
            seriesOutputInnerPuzzleHash=hex32(live_inner.get_tree_hash()),
            launchAnchor=launch_anchor,
            confirmedHeight=201,
        ),
    )

    purchases = PaymentPurchaseStore(str(tmp_path / "expired-refund.db"))
    artifact_payload = purchase_artifact_to_json(artifact)
    purchases.save(
        purchase_intent_id="expired-refund-intent",
        rail="chia_xch",
        offer_artifact_hash=hex32(200),
        offer_artifact={},
        purchase_artifact=artifact_payload,
        created_at=fixture_now,
    )
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    coinset = FakeCoinset(Coin(b32(201), faucet.address_puzzle_hash, uint64(20)))
    for coin in (live_series_coin, issuance.voucher_coin, issuance.payment_coin):
        coinset.records[hex32(coin.name())] = coin_record(coin, confirmed=201)

    async def fake_lineage(_coinset, _coin_id, label):
        if label == "voucher series coin":
            return live_series_coin, lineage_proof_for_coinsol(
                phase.series_spend
            )
        if label == "voucher coin":
            return issuance.voucher_coin, lineage_proof_for_coinsol(
                issuance.voucher_launcher_spend
            )
        raise AssertionError(label)

    async def fake_quorum(_settings, claim):
        assert claim.action == int(VoucherAction.REFUND_EXPIRED)
        assert claim.vault_coin_id is None
        assert claim.vault_owner_key is None
        assert claim.owner_authorization == ""
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=G2Element(),
            claim_hash=claim.canonical_hash(),
        )

    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker._confirmed_coin_and_lineage",
        fake_lineage,
    )
    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.collect_voucher_transition_quorum",
        fake_quorum,
    )
    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.load_signed_public_artifact",
        lambda _settings: {"artifactHash": hex32(203)},
    )
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=purchases,
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )

    submitted = await worker.reconcile_once()

    assert submitted == [
        {
            "termsHash": str(current_terms["termsHash"]),
            "serial": 0,
            "status": "REFUND_SUBMITTED",
        }
    ]
    refunding = store.voucher(str(current_terms["termsHash"]), 0)
    assert refunding["state"] == "REFUNDING"
    assert refunding["refundAction"] == int(VoucherAction.REFUND_EXPIRED)
    assert refunding["refundVaultInputCoinId"] is None
    assert refunding["refundVaultOutputCoinId"] is None
    pushed = SpendBundle.from_json_dict(coinset.pushed[-1])
    assert len(pushed.coin_spends) == 3
    additions = [
        addition
        for spend in pushed.coin_spends
        for addition in compute_additions(spend)
    ]
    additions_by_id = {hex32(coin.name()): coin for coin in additions}
    for field in (
        "refundOutputCoinId",
        "terminalVoucherCoinId",
        "refundSeriesOutputCoinId",
    ):
        coin_id = str(refunding[field])
        coinset.records[coin_id] = coin_record(
            additions_by_id[coin_id],
            confirmed=220,
        )
    for coin in (live_series_coin, issuance.voucher_coin, issuance.payment_coin):
        coinset.records[hex32(coin.name())] = coin_record(
            coin,
            confirmed=201,
            spent=220,
        )

    confirmed = await worker.reconcile_once()

    assert confirmed == [
        {
            "termsHash": str(current_terms["termsHash"]),
            "serial": 0,
            "status": "REFUNDED",
        }
    ]
    refunded = store.voucher(str(current_terms["termsHash"]), 0)
    assert refunded["state"] == "REFUNDED"
    assert refunded["refundConfirmedHeight"] == 220
    assert additions_by_id[str(refunded["refundOutputCoinId"])].puzzle_hash == (
        commitment.original_payer
    )
    assert int(
        additions_by_id[str(refunded["refundOutputCoinId"])].amount
    ) == commitment.payment_principal
    assert store.get(str(current_terms["termsHash"]))["chainState"][
        "refundedCount"
    ] == 1


def test_native_submission_rederives_every_persisted_chain_output() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    deed = current_terms["deeds"][0]  # type: ignore[index]
    vault = approved_vault()
    rail_amount = (103 * 10**12 + 2_500 - 1) // 2_500
    artifact = PurchaseArtifactV2(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(str(current_terms["metadataAnchorId"])),
        share_ppm=int(deed["sharePpm"]),
        usd_amount_minor=103,
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=12,
        rail_amount=rail_amount,
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(150),
        authorization_expires_at=int(current_terms["saleClose"]),
        quote_expires_at=int(current_terms["saleClose"]),
        oracle_round_hash=b32(151),
        oracle_price_usd_minor_per_asset=2_500,
        source_evidence_root=b32(152),
    )
    artifact_payload = purchase_artifact_to_json(artifact)
    purchase = StoredPaymentPurchase(
        purchase_id=str(artifact_payload["purchaseId"]),
        artifact_hash=str(artifact_payload["artifactHash"]),
        purchase_intent_id="native-voucher-intent",
        rail="chia_xch",
        quote_expires_at=artifact.quote_expires_at,
        offer_artifact_hash=hex32(153),
        offer_artifact={},
        purchase_artifact=artifact_payload,
        external_message=None,
    )
    payment_coin = Coin(b32(154), b32(155), uint64(rail_amount + 10))
    global_payment_id = hex32(156)
    series = store.get(str(current_terms["termsHash"]))
    commitment = _voucher_commitment(
        series=series,
        deed=deed,
        artifact=artifact,
        original_payer=hex32(payment_coin.puzzle_hash),
        global_payment_id=global_payment_id,
        approved_vault=vault,
        external_escrow_contract=bytes32.zeros,
    )
    program_terms = series_terms_from_json(current_terms)
    payment_puzzle = curry_xch_escrow(
        terms=program_terms,
        voucher=commitment,
        purchase=artifact,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=program_terms,
        voucher=commitment,
        payment_puzzle_hash=bytes32(payment_puzzle.get_tree_hash()),
        payment_amount=rail_amount,
    )
    purchase_launcher = Coin(
        bytes32(payment_coin.name()),
        bytes32(launcher_puzzle.get_tree_hash()),
        uint64(rail_amount + 1),
    )
    series_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    issuance = build_voucher_issuance_spends(
        terms=program_terms,
        state=VoucherSeriesStateV2(),
        series_coin=series_coin,
        series_lineage_proof=LineageProof(bytes32.zeros, None, uint64(1)),
        voucher=commitment,
        purchase_launcher_coin=purchase_launcher,
        payment_puzzle=payment_puzzle,
        payment_amount=rail_amount,
        signer_indices=(0, 1),
    )
    arguments = {
        "artifact": artifact,
        "issued_purchase": purchase,
        "approved_vault": vault,
        "payment_coin": payment_coin,
        "global_payment_id": global_payment_id,
        "commitment": commitment,
        "spend_bundle_id": hex32(157),
        "purchase_launcher_coin": purchase_launcher,
        "voucher_launcher_id": hex32(issuance.voucher_launcher_id),
        "voucher_output_coin_id": hex32(issuance.voucher_coin.name()),
        "payment_commitment_coin_id": hex32(issuance.payment_coin.name()),
        "series_input_coin": series_coin,
        "series_output_coin_id": hex32(issuance.next_series_coin.name()),
        "submitted_at": now,
    }
    with pytest.raises(ValueError, match="outputs changed"):
        store.record_native_issuance_submission(
            str(current_terms["termsHash"]),
            **{**arguments, "voucher_output_coin_id": hex32(199)},
        )
    assert store.get(str(current_terms["termsHash"]))["vouchers"] == []

    voucher = store.record_native_issuance_submission(
        str(current_terms["termsHash"]),
        **arguments,
    )
    assert voucher["state"] == "ISSUANCE_SUBMITTED"
    assert voucher["originalPayer"] == hex32(payment_coin.puzzle_hash)
    assert voucher["purchaseLauncherCoinId"] == hex32(purchase_launcher.name())
    assert voucher["voucherOutputCoinId"] == hex32(issuance.voucher_coin.name())
    assert voucher["paymentCommitmentCoinId"] == hex32(issuance.payment_coin.name())
    assert voucher["seriesOutputCoinId"] == hex32(issuance.next_series_coin.name())


@pytest.mark.asyncio
async def test_owner_refund_outputs_without_retained_signed_bytes_cannot_confirm(
    tmp_path: Path,
) -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    deed = current_terms["deeds"][0]  # type: ignore[index]
    vault = approved_vault()
    rail_amount = (103 * 10**12 + 2_500 - 1) // 2_500
    artifact = PurchaseArtifactV2(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(str(current_terms["metadataAnchorId"])),
        share_ppm=int(deed["sharePpm"]),
        usd_amount_minor=103,
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=12,
        rail_amount=rail_amount,
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(160),
        authorization_expires_at=int(current_terms["saleClose"]),
        quote_expires_at=int(current_terms["saleClose"]),
        oracle_round_hash=b32(161),
        oracle_price_usd_minor_per_asset=2_500,
        source_evidence_root=b32(162),
    )
    artifact_payload = purchase_artifact_to_json(artifact)
    purchase = StoredPaymentPurchase(
        purchase_id=str(artifact_payload["purchaseId"]),
        artifact_hash=str(artifact_payload["artifactHash"]),
        purchase_intent_id="native-refund-intent",
        rail="chia_xch",
        quote_expires_at=artifact.quote_expires_at,
        offer_artifact_hash=hex32(163),
        offer_artifact={},
        purchase_artifact=artifact_payload,
        external_message=None,
    )
    payment_source = Coin(b32(164), b32(165), uint64(rail_amount + 10))
    series = store.get(str(current_terms["termsHash"]))
    commitment = _voucher_commitment(
        series=series,
        deed=deed,
        artifact=artifact,
        original_payer=hex32(payment_source.puzzle_hash),
        global_payment_id=hex32(166),
        approved_vault=vault,
        external_escrow_contract=bytes32.zeros,
    )
    program_terms = series_terms_from_json(current_terms)
    payment_puzzle = curry_xch_escrow(
        terms=program_terms,
        voucher=commitment,
        purchase=artifact,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=program_terms,
        voucher=commitment,
        payment_puzzle_hash=bytes32(payment_puzzle.get_tree_hash()),
        payment_amount=rail_amount,
    )
    purchase_launcher = Coin(
        bytes32(payment_source.name()),
        bytes32(launcher_puzzle.get_tree_hash()),
        uint64(rail_amount + 1),
    )
    series_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    issuance = build_voucher_issuance_spends(
        terms=program_terms,
        state=VoucherSeriesStateV2(),
        series_coin=series_coin,
        series_lineage_proof=LineageProof(bytes32.zeros, None, uint64(1)),
        voucher=commitment,
        purchase_launcher_coin=purchase_launcher,
        payment_puzzle=payment_puzzle,
        payment_amount=rail_amount,
        signer_indices=(0, 1),
    )
    submitted = store.record_native_issuance_submission(
        str(current_terms["termsHash"]),
        artifact=artifact,
        issued_purchase=purchase,
        approved_vault=vault,
        payment_coin=payment_source,
        global_payment_id=hex32(166),
        commitment=commitment,
        spend_bundle_id=hex32(167),
        purchase_launcher_coin=purchase_launcher,
        voucher_launcher_id=hex32(issuance.voucher_launcher_id),
        voucher_output_coin_id=hex32(issuance.voucher_coin.name()),
        payment_commitment_coin_id=hex32(issuance.payment_coin.name()),
        series_input_coin=series_coin,
        series_output_coin_id=hex32(issuance.next_series_coin.name()),
        submitted_at=now,
    )
    sold_state = VoucherSeriesStateV2(sold_count=1)
    sold_inner = curry_series(program_terms, sold_state)
    escrowed = store.confirm_issuance(
        str(current_terms["termsHash"]),
        0,
        VoucherIssuanceChainEvidence(
            evidenceId="native-issuance-confirmed",
            spendBundleId=str(submitted["issuanceBundleId"]),
            purchaseLauncherCoinId=str(submitted["purchaseLauncherCoinId"]),
            voucherLauncherId=str(submitted["voucherLauncherId"]),
            voucherOutputCoinId=str(submitted["voucherOutputCoinId"]),
            paymentCommitmentCoinId=str(submitted["paymentCommitmentCoinId"]),
            seriesInputCoinId=str(submitted["seriesInputCoinId"]),
            seriesInputParentCoinId=hex32(series_coin.parent_coin_info),
            seriesOutputCoinId=str(submitted["seriesOutputCoinId"]),
            seriesOutputInnerPuzzleHash=hex32(bytes32(sold_inner.get_tree_hash())),
            confirmedHeight=170,
        ),
    )
    checked = store.request_refund(
        str(current_terms["termsHash"]),
        0,
        vault_launcher_id=vault.launcher_id,
        now_seconds=now,
    )
    assert checked["state"] == "ESCROWED"

    vault_coin = Coin(b32(168), b32(169), uint64(1))
    terminal = build_xch_voucher_terminal_spends(
        terms=program_terms,
        state=sold_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=LineageProof(
            series_coin.parent_coin_info,
            bytes32.fromhex(str(created["chainState"]["currentInnerPuzzleHash"])[2:]),
            uint64(1),
        ),
        voucher=commitment,
        purchase=artifact,
        voucher_launcher_id=issuance.voucher_launcher_id,
        voucher_coin=issuance.voucher_coin,
        voucher_lineage_proof=LineageProof(
            purchase_launcher.name(), None, uint64(1)
        ),
        payment_coin=issuance.payment_coin,
        vault_coin_id=vault_coin.name(),
        vault_inner_puzzle_hash=b32(170),
        action=VoucherAction.REFUND_PRESALE,
        signer_indices=(0, 1),
    )
    vault_output = Coin(vault_coin.name(), vault_coin.puzzle_hash, uint64(1))
    refunding = store.record_native_refund_submission(
        str(current_terms["termsHash"]),
        0,
        action=VoucherAction.REFUND_PRESALE,
        spend_bundle_id=hex32(171),
        refund_output_coin_id=hex32(terminal.settlement_coin.name()),
        terminal_voucher_coin_id=hex32(terminal.terminal_voucher_coin.name()),
        series_input_coin_id=hex32(issuance.next_series_coin.name()),
        series_output_coin_id=hex32(terminal.next_series_coin.name()),
        vault_input_coin_id=hex32(vault_coin.name()),
        vault_output_coin_id=hex32(vault_output.name()),
    )
    assert refunding["state"] == "REFUNDING"

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    coinset = FakeCoinset(Coin(b32(172), faucet.address_puzzle_hash, uint64(20)))
    confirmed_height = 180
    output_coins = (
        terminal.settlement_coin,
        terminal.terminal_voucher_coin,
        terminal.next_series_coin,
        vault_output,
    )
    input_coins = (
        issuance.next_series_coin,
        issuance.voucher_coin,
        issuance.payment_coin,
        vault_coin,
    )
    for coin in output_coins:
        coinset.records[hex32(coin.name())] = coin_record(
            coin, confirmed=confirmed_height
        )
    for coin in input_coins:
        coinset.records[hex32(coin.name())] = coin_record(
            coin, confirmed=170, spent=confirmed_height
        )
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=PaymentPurchaseStore(str(tmp_path / "refund-purchases.db")),
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )
    reconciled = await worker.reconcile_once()

    assert len(reconciled)==1
    assert reconciled[0]['status']=='REFUND_ERROR'
    assert 'retained signed bytes' in reconciled[0]['detail']
    refunded = store.voucher(str(current_terms["termsHash"]), 0)
    assert refunded["state"] == "REFUNDING"
    assert refunded["refundConfirmedHeight"] is None
    assert store.get(str(current_terms["termsHash"]))["chainState"][
        "refundedCount"
    ] == 0


def test_unbound_base_payment_and_changed_price_fail_closed() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    artifact = artifact_json(current_terms)
    request = evidence(artifact, current_terms, global_payment_id=60)
    with pytest.raises(ValueError, match="authenticated escrow"):
        store.ingest_payment(
            str(current_terms["termsHash"]),
            request,
            approved_vault=approved_vault(),
            issued_purchase=issued(artifact, global_payment_id=60, bound=False),
            external_escrow_contract=b32(99),
        )

    changed = artifact_json(current_terms, nonce=51, usd_amount_minor=104)
    with pytest.raises(ValueError, match="collection economics"):
        store.ingest_payment(
            str(current_terms["termsHash"]),
            evidence(changed, current_terms, global_payment_id=61),
            approved_vault=approved_vault(),
            issued_purchase=issued(changed, global_payment_id=61),
            external_escrow_contract=b32(99),
        )


def test_first_confirmed_deed_payment_wins_and_overflow_refunds() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    first = ingest(store, current_terms, global_payment_id=60, height=100)
    second = ingest(
        store,
        current_terms,
        nonce=51,
        global_payment_id=61,
        height=101,
    )
    assert first["outcome"] == "PAYMENT_CONFIRMED"
    assert second["outcome"] == "REFUND_REQUIRED"
    assert second["refundRequired"] is True
    assert len(store.get(str(current_terms["termsHash"]))["vouchers"]) == 1


def test_refund_returns_to_committed_payer_path() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    ingest(store, current_terms)
    confirm_issuance(store, current_terms)

    refunding = store.request_refund(
        str(current_terms["termsHash"]),
        0,
        vault_launcher_id=approved_vault().launcher_id,
        now_seconds=now,
    )
    assert refunding["state"] == "REFUNDING"
    assert refunding["originalPayer"] == hex32(evm_payer(80))
    with pytest.raises(ValueError, match="exact atomic Chia confirmation"):
        store.complete_refund(
            str(current_terms["termsHash"]),
            0,
            RefundEvidenceRequest(
                evidenceId="wrong-refund-evidence",
                outputCoinId=hex32(89),
                refundDestination=hex32(evm_payer(81)),
                refundAmount=1_030_000,
            ),
        )
    assert store.voucher(str(current_terms["termsHash"]), 0)["state"] == "REFUNDING"


def test_delivery_is_exact_and_deadlines_never_mutate_without_chain_evidence() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    ingest(store, current_terms, deed_index=0, global_payment_id=60)
    ingest(
        store,
        current_terms,
        deed_index=1,
        nonce=51,
        global_payment_id=61,
        height=101,
    )
    confirm_issuance(store, current_terms, 0)
    confirm_issuance(store, current_terms, 1)
    launched_at = int(current_terms["saleClose"])
    current = store.get(str(current_terms["termsHash"]))
    series_input = current["chainState"]["currentCoinId"]
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="LIVE",
        spend_bundle_id=hex32(200),
        series_input_coin_id=series_input,
        series_output_coin_id=hex32(201),
        series_output_inner_puzzle_hash=hex32(202),
        launch_anchor=launched_at,
        governance_execution_ids=[hex32(203), hex32(204)],
    )
    assert store.get(str(current_terms["termsHash"]))["state"] == "PRESALE"
    store.confirm_phase_transition(
        str(current_terms["termsHash"]),
        VoucherSeriesPhaseChainEvidence(
            evidenceId="series-live-chain-evidence",
            spendBundleId=hex32(200),
            targetState="LIVE",
            seriesInputCoinId=series_input,
            seriesInputParentCoinId=hex32(205),
            seriesOutputCoinId=hex32(201),
            seriesOutputInnerPuzzleHash=hex32(202),
            launchAnchor=launched_at,
            confirmedHeight=300,
        ),
    )
    with pytest.raises(ValueError, match="exact atomic Chia confirmation"):
        store.complete_delivery(
            str(current_terms["termsHash"]),
            0,
            DeliveryEvidenceRequest(
                evidenceId="wrong-delivery-evidence",
                outputCoinId=hex32(91),
                deedLauncherId=hex32(31),
                vaultP2PuzzleHash=approved_vault().p2_puzzle_hash,
            ),
        )
    assert store.voucher(str(current_terms["termsHash"]), 0)["state"] == "REDEEMING"

    changed = store.reconcile(launched_at + DELIVERY_WINDOW_SECONDS)
    assert changed == [
        {
            "termsHash": str(current_terms["termsHash"]),
            "reason": "EXPIRED_REFUND_SPENDS_REQUIRED",
            "voucherCount": 2,
        }
    ]
    assert store.voucher(str(current_terms["termsHash"]), 1)["state"] == "REDEEMING"


@pytest.mark.asyncio
async def test_phase_worker_confirms_exact_singleton_successor(tmp_path: Path) -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    terms_program = series_terms_from_json(current_terms)
    current_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    launch_anchor = int(current_terms["saleClose"])
    next_state = VoucherSeriesStateV2(
        phase=VoucherSeriesState.LIVE,
        launched_at=launch_anchor,
    )
    next_inner = curry_series(terms_program, next_state)
    next_coin = Coin(
        current_coin.name(),
        bytes32(
            puzzle_for_singleton(
                terms_program.series_singleton_id,
                next_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="LIVE",
        spend_bundle_id=hex32(220),
        series_input_coin_id=hex32(current_coin.name()),
        series_output_coin_id=hex32(next_coin.name()),
        series_output_inner_puzzle_hash=hex32(next_inner.get_tree_hash()),
        launch_anchor=launch_anchor,
        governance_execution_ids=[hex32(221), hex32(222)],
    )
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    coinset = FakeCoinset(Coin(b32(223), faucet.address_puzzle_hash, uint64(10)))
    confirmed_height = 400
    coinset.records[hex32(current_coin.name())] = coin_record(
        current_coin,
        confirmed=100,
        spent=confirmed_height,
    )
    coinset.records[hex32(next_coin.name())] = coin_record(
        next_coin,
        confirmed=confirmed_height,
    )
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=PaymentPurchaseStore(str(tmp_path / "phase-purchases.db")),
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )

    results = await worker.reconcile_once()

    assert results == [
        {
            "termsHash": str(current_terms["termsHash"]),
            "status": "PHASE_CONFIRMED",
        }
    ]
    confirmed = store.get(str(current_terms["termsHash"]))
    assert confirmed["state"] == "LIVE"
    assert confirmed["chainState"]["currentCoinId"] == hex32(next_coin.name())
    assert confirmed["phaseTransition"]["confirmedHeight"] == confirmed_height


def test_canceled_phase_requires_confirmation_and_keeps_refund_claimable() -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    create_series(store, current_terms)
    ingest(store, current_terms, deed_index=0, global_payment_id=230)
    confirm_issuance(store, current_terms, 0)
    current = store.get(str(current_terms["termsHash"]))
    series_input = current["chainState"]["currentCoinId"]
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="CANCELED",
        spend_bundle_id=hex32(231),
        series_input_coin_id=series_input,
        series_output_coin_id=hex32(232),
        series_output_inner_puzzle_hash=hex32(233),
        launch_anchor=0,
        governance_execution_ids=[],
        cancel_reason="Issuer canceled before launch.",
    )
    pending = store.get(str(current_terms["termsHash"]))
    assert pending["state"] == "PRESALE"
    assert pending["vouchers"][0]["state"] == "ESCROWED"

    store.confirm_phase_transition(
        str(current_terms["termsHash"]),
        VoucherSeriesPhaseChainEvidence(
            evidenceId="canceled-series-chain-evidence",
            spendBundleId=hex32(231),
            targetState="CANCELED",
            seriesInputCoinId=series_input,
            seriesInputParentCoinId=hex32(234),
            seriesOutputCoinId=hex32(232),
            seriesOutputInnerPuzzleHash=hex32(233),
            launchAnchor=0,
            confirmedHeight=500,
        ),
    )
    canceled = store.get(str(current_terms["termsHash"]))
    assert canceled["state"] == "CANCELED"
    assert canceled["vouchers"][0]["state"] == "ESCROWED"
    refundable = store.request_refund(
        str(current_terms["termsHash"]),
        0,
        vault_launcher_id=approved_vault().launcher_id,
        now_seconds=int(current_terms["refundDeadline"]) + 1,
    )
    assert refundable["state"] == "REFUNDING"


@pytest.mark.asyncio
async def test_base_voucher_worker_funds_then_submits_only_after_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    artifact = artifact_json(current_terms)
    ingest(store, current_terms)

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    faucet_coin = Coin(b32(110), faucet.address_puzzle_hash, uint64(20))
    coinset = FakeCoinset(faucet_coin)
    purchases = PaymentPurchaseStore(str(tmp_path / "purchases.db"))
    purchases.save(
        purchase_intent_id="voucher-intent",
        rail="base_usdc",
        offer_artifact_hash=hex32(111),
        offer_artifact={},
        purchase_artifact=artifact,
        created_at=now,
    )
    purchases.bind_external_message(
        str(artifact["purchaseId"]),
        {
            "globalPaymentId": hex32(60),
            "depositor": evm_address(80),
            "source": {
                "chainId": BASE_SEPOLIA_CHAIN_ID,
                "transactionHash": hex32(112),
                "blockTimestamp": now,
            },
        },
    )
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=purchases,
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )

    first = await worker.reconcile_once()
    assert first[0]["status"] == "FUNDING_SUBMITTED"
    pending = store.voucher(str(current_terms["termsHash"]), 0)
    assert pending["state"] == "PENDING_ISSUANCE"
    assert pending["purchaseLauncherCoinId"]
    assert len(coinset.pushed) == 1

    purchase_launcher = Coin(
        bytes32(faucet_coin.name()),
        bytes32.from_hexstr(str(pending["purchaseLauncherPuzzleHash"])),
        uint64(2),
    )
    series_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    coinset.records[str(pending["purchaseLauncherCoinId"])] = coin_record(
        purchase_launcher
    )
    coinset.records[str(created["chainState"]["currentCoinId"])] = coin_record(
        series_coin
    )

    async def fake_quorum(_settings, claim):
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=G2Element(),
            claim_hash=claim.canonical_hash(),
        )

    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.collect_voucher_issuance_quorum",
        fake_quorum,
    )
    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.load_signed_public_artifact",
        lambda _settings: {"artifactHash": hex32(113)},
    )
    second = await worker.reconcile_once()
    assert second[0]["status"] == "ISSUANCE_SUBMITTED"
    submitted = store.voucher(str(current_terms["termsHash"]), 0)
    assert submitted["state"] == "ISSUANCE_SUBMITTED"
    assert submitted["voucherOutputCoinId"]
    assert submitted["paymentCommitmentCoinId"]
    assert len(coinset.pushed) == 2

    program_terms = series_terms_from_json(current_terms)
    commitment = voucher_commitment_from_json(submitted["commitment"])
    voucher_launcher = bytes32.from_hexstr(str(submitted["voucherLauncherId"]))
    voucher_inner = curry_voucher_inner(
        terms=program_terms,
        voucher=commitment,
        voucher_launcher_id=voucher_launcher,
    )
    voucher_coin = Coin(
        voucher_launcher,
        bytes32(puzzle_for_singleton(voucher_launcher, voucher_inner).get_tree_hash()),
        uint64(1),
    )
    receipt = curry_external_receipt(terms=program_terms, voucher=commitment)
    receipt_coin = Coin(
        bytes32.from_hexstr(str(submitted["purchaseLauncherCoinId"])),
        bytes32(receipt.get_tree_hash()),
        uint64(1),
    )
    next_inner = curry_series(program_terms, VoucherSeriesStateV2(sold_count=1))
    next_series = Coin(
        bytes32.from_hexstr(str(submitted["seriesInputCoinId"])),
        bytes32(
            puzzle_for_singleton(
                bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
                next_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    confirmed_height = 120
    coinset.records[str(submitted["voucherOutputCoinId"])] = coin_record(
        voucher_coin, confirmed=confirmed_height
    )
    coinset.records[str(submitted["paymentCommitmentCoinId"])] = coin_record(
        receipt_coin, confirmed=confirmed_height
    )
    coinset.records[str(submitted["seriesOutputCoinId"])] = coin_record(
        next_series, confirmed=confirmed_height
    )
    coinset.records[str(submitted["seriesInputCoinId"])] = coin_record(
        series_coin, confirmed=100, spent=confirmed_height
    )
    coinset.records[str(submitted["purchaseLauncherCoinId"])] = coin_record(
        purchase_launcher, confirmed=100, spent=confirmed_height
    )

    third = await worker.reconcile_once()
    assert third[0]["status"] == "CONFIRMED"
    confirmed = store.voucher(str(current_terms["termsHash"]), 0)
    assert confirmed["state"] == "ESCROWED"
    assert confirmed["issuanceConfirmedHeight"] == confirmed_height
    assert store.get(str(current_terms["termsHash"]))["chainState"]["soldCount"] == 1


    launch_anchor = int(current_terms["saleClose"])
    issuance_bundle = SpendBundle.from_json_dict(coinset.pushed[1])
    issuance_series_spend = next(
        spend
        for spend in issuance_bundle.coin_spends
        if spend.coin.name() == series_coin.name()
    )
    phase = build_voucher_series_phase_spend(
        terms=program_terms,
        state=VoucherSeriesStateV2(sold_count=1),
        series_coin=next_series,
        series_lineage_proof=lineage_proof_for_coinsol(issuance_series_spend),
        transition=SeriesTransition.LAUNCH,
        launch_anchor=launch_anchor,
        signer_indices=(0, 1),
    )
    live_inner = curry_series(program_terms, phase.next_series_state)
    live_series = phase.next_series_coin
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="LIVE",
        spend_bundle_id=hex32(114),
        series_input_coin_id=hex32(next_series.name()),
        series_output_coin_id=hex32(live_series.name()),
        series_output_inner_puzzle_hash=hex32(live_inner.get_tree_hash()),
        launch_anchor=launch_anchor,
        governance_execution_ids=[hex32(115), hex32(116)],
    )
    store.confirm_phase_transition(
        str(current_terms["termsHash"]),
        VoucherSeriesPhaseChainEvidence(
            evidenceId="base-redemption-series-live",
            spendBundleId=hex32(114),
            targetState="LIVE",
            seriesInputCoinId=hex32(next_series.name()),
            seriesInputParentCoinId=hex32(next_series.parent_coin_info),
            seriesOutputCoinId=hex32(live_series.name()),
            seriesOutputInnerPuzzleHash=hex32(live_inner.get_tree_hash()),
            launchAnchor=launch_anchor,
            confirmedHeight=121,
        ),
    )

    # Historical V2 issuance remains observable. It must not be rebound to a
    # current V3 reservation. Current delivery and relay authorization are tested
    # through real stores/loaders in test_current_base_voucher_delivery.py.
    worker.settings.payment_purchase_db_path = str(purchases.path)
    before = purchases.get(str(artifact["purchaseId"])).purchase_artifact
    fourth = await worker.reconcile_once()
    assert fourth[0]["status"] == "BASE_SETTLEMENT_ERROR"
    assert store.voucher(str(current_terms["termsHash"]), 0)["state"] == "REDEEMING"
    assert store.pending_voucher_execution(str(current_terms["termsHash"]), 0) is None
    assert purchases.get(str(artifact["purchaseId"])).purchase_artifact == before
    assert len(coinset.pushed) == 2


@pytest.mark.asyncio
async def test_stripe_ach_voucher_worker_submits_exact_v3_issuance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = int(time.time())
    current_terms = terms(now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    vault = approved_vault()
    deed = current_terms["deeds"][0]  # type: ignore[index]
    artifact = build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=bytes32.from_hexstr(str(current_terms["collectionId"])),
        deed_launcher_id=bytes32.from_hexstr(str(deed["deedLauncherId"])),
        metadata_root=bytes32.from_hexstr(str(current_terms["metadataRoot"])),
        metadata_anchor_id=bytes32.from_hexstr(
            str(current_terms["metadataAnchorId"])
        ),
        share_ppm=int(deed["sharePpm"]),
        base_usd_amount_minor=int(deed["basePriceMinor"]),
        technology_fee_bps=int(current_terms["technologyFeeBps"]),
        protocol_treasury_puzzle_hash=bytes32.from_hexstr(
            str(current_terms["trustedProtocolTreasury"])
        ),
        zkpassport_root=b32(42),
        vault_launcher_id=bytes32.from_hexstr(vault.launcher_id),
        vault_p2_puzzle_hash=bytes32.from_hexstr(vault.p2_puzzle_hash),
        authorization_nonce=b32(151),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 100,
        presale_terms_hash=bytes32.from_hexstr(str(current_terms["termsHash"])),
    )
    stripe_evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_testnet_alpha",
        livemode=False,
        payment_intent_id="pi_stripe_ach_worker",
        event_id="evt_stripe_ach_worker",
        amount_minor=artifact.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.US_BANK_ACCOUNT,
        funding_type=StripeFundingType.BANK_ACCOUNT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=now + 2,
    )
    receipt = build_stripe_settlement_receipt_v1(
        artifact=artifact,
        evidence=stripe_evidence,
        validator_pubkeys=tuple(
            bytes.fromhex(str(value).removeprefix("0x"))
            for value in current_terms["validatorPubkeys"]  # type: ignore[index]
        ),
    )
    artifact_json_v3 = purchase_artifact_v3_to_json(artifact)
    purchases = PaymentPurchaseStore(str(tmp_path / "stripe-purchases.db"))
    stored = purchases.save(
        purchase_intent_id="pi_stripe_ach_worker",
        rail="stripe",
        offer_artifact_hash=hex32(170),
        offer_artifact={},
        purchase_artifact=artifact_json_v3,
        created_at=now,
    )
    store.ingest_stripe_payment(
        str(current_terms["termsHash"]),
        artifact=artifact,
        receipt=receipt,
        evidence_id=stripe_evidence.event_id,
        issued_purchase=stored,
    )

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    faucet_coin = Coin(b32(171), faucet.address_puzzle_hash, uint64(20))
    coinset = FakeCoinset(faucet_coin)
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=purchases,
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )

    first = await worker.reconcile_once()
    assert first[0]["status"] == "FUNDING_SUBMITTED"
    pending = store.voucher(str(current_terms["termsHash"]), 0)
    assert pending["state"] == "PENDING_ISSUANCE"
    assert pending["paymentRail"] == "STRIPE_USD"
    assert len(coinset.pushed) == 1

    purchase_launcher = Coin(
        bytes32(faucet_coin.name()),
        bytes32.from_hexstr(str(pending["purchaseLauncherPuzzleHash"])),
        uint64(2),
    )
    series_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    coinset.records[str(pending["purchaseLauncherCoinId"])] = coin_record(
        purchase_launcher
    )
    coinset.records[str(created["chainState"]["currentCoinId"])] = coin_record(
        series_coin
    )
    observed_claims = []

    async def fake_quorum(_settings, claim):
        observed_claims.append(claim)
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=G2Element(),
            claim_hash=claim.canonical_hash(),
        )

    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.collect_voucher_issuance_quorum",
        fake_quorum,
    )
    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.load_signed_public_artifact",
        lambda _settings: {"artifactHash": hex32(172)},
    )

    second = await worker.reconcile_once()
    assert second[0]["status"] == "ISSUANCE_SUBMITTED"
    submitted = store.voucher(str(current_terms["termsHash"]), 0)
    assert submitted["state"] == "ISSUANCE_SUBMITTED"
    assert submitted["voucherOutputCoinId"]
    assert submitted["paymentCommitmentCoinId"]
    assert len(coinset.pushed) == 2
    assert len(observed_claims) == 1
    assert observed_claims[0].purchase_artifact == artifact_json_v3
    assert (
        observed_claims[0].payment_evidence["paymentIntentId"]
        == stripe_evidence.payment_intent_id
    )

    program_terms = series_terms_from_json(current_terms)
    commitment = voucher_commitment_v3_from_json(submitted["commitment"])
    voucher_launcher = bytes32.from_hexstr(str(submitted["voucherLauncherId"]))
    voucher_inner = curry_voucher_inner_v3(
        terms=program_terms,
        voucher=commitment,
        voucher_launcher_id=voucher_launcher,
    )
    voucher_coin = Coin(
        voucher_launcher,
        bytes32(puzzle_for_singleton(voucher_launcher, voucher_inner).get_tree_hash()),
        uint64(1),
    )
    stripe_receipt = curry_stripe_voucher_receipt(
        terms=program_terms,
        voucher=commitment,
        artifact=artifact,
    )
    receipt_coin = Coin(
        bytes32.from_hexstr(str(submitted["purchaseLauncherCoinId"])),
        bytes32(stripe_receipt.get_tree_hash()),
        uint64(1),
    )
    assert submitted["voucherOutputCoinId"] == hex32(voucher_coin.name())
    assert submitted["paymentCommitmentCoinId"] == hex32(receipt_coin.name())


@pytest.mark.asyncio
async def test_worker_advances_stripe_redemption_from_the_shared_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    series = {
        "termsHash": hex32(220),
        "state": "LIVE",
        "deliveryDeadline": int(time.time()) + 300,
    }
    voucher = {
        "serial": 4,
        "paymentRail": "STRIPE_USD",
        "redemptionBundleId": None,
    }

    class QueueOnlyStore:
        campaign_funding_guard = asyncio.Lock()
        def claim_voucher_work(self, lane, owner, now, excluded_series=None):
            if lane == "stripe_redemption":
                return dict(lane=lane, owner=owner, termsHash=series['termsHash'], serial=voucher['serial'])

        def finish_voucher_work(self, job, now, status):
            pass

        def pending_voucher_execution(self, terms, serial):
            return None

        def _get_series(self, terms):
            return series

        def voucher(self, terms, serial):
            return voucher

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=FakeCoinset(Coin(b32(221), faucet.address_puzzle_hash, uint64(20))),
        presales=QueueOnlyStore(),  # type: ignore[arg-type]
        purchases=SimpleNamespace(),  # type: ignore[arg-type]
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )
    submitted: list[tuple[dict, dict]] = []

    async def submit(current_series, current_voucher):
        submitted.append((current_series, current_voucher))
        return True

    monkeypatch.setattr(worker, "_submit_stripe_redemption", submit)
    results = await worker.reconcile_once()

    assert submitted == [(series, voucher)]
    assert results == [
        {
            "termsHash": hex32(220),
            "serial": 4,
            "status": "STRIPE_REDEMPTION_SUBMITTED",
        }
    ]


@pytest.mark.asyncio
async def test_worker_never_replaces_an_exact_stripe_redemption_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    series = {
        "termsHash": hex32(222),
        "state": "LIVE",
        "deliveryDeadline": int(time.time()) - 1,
    }
    voucher = {
        "serial": 5,
        "paymentRail": "STRIPE_USD",
        "redemptionBundleId": hex32(223),
        "terminalExactExecution": {"mode": "REDEEM"},
    }

    class QueueOnlyStore:
        campaign_funding_guard = asyncio.Lock()
        def claim_voucher_work(self, lane, owner, now, excluded_series=None):
            if lane == "stripe_redemption":
                return dict(lane=lane, owner=owner, termsHash=series['termsHash'], serial=voucher['serial'])

        def finish_voucher_work(self, job, now, status):
            pass

        def pending_voucher_execution(self, terms, serial):
            return None

        def _get_series(self, terms):
            return series

        def voucher(self, terms, serial):
            return voucher

    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=Faucet.from_seed_hex("01" * 32, "testnet11"),
        coinset=SimpleNamespace(),  # type: ignore[arg-type]
        presales=QueueOnlyStore(),  # type: ignore[arg-type]
        purchases=SimpleNamespace(),  # type: ignore[arg-type]
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )
    refunds: list[int] = []

    async def confirm(_series, _voucher):
        return False

    async def refund(_series, current_voucher):
        refunds.append(int(current_voucher["serial"]))

    monkeypatch.setattr(worker, "_confirm_stripe_redemption_if_ready", confirm)
    monkeypatch.setattr(worker, "_submit_stripe_expired_refund", refund)

    results = await worker.reconcile_once()

    assert refunds == []
    assert results == [
        {
            "termsHash": hex32(222),
            "serial": 5,
            "status": "STRIPE_REDEMPTION_CONFIRMING",
        }
    ]


@pytest.mark.asyncio
async def test_expired_base_delivery_authorizes_exact_external_refund(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wall_clock = int(time.time())
    fixture_now = wall_clock - DELIVERY_WINDOW_SECONDS - 500
    current_terms = terms(fixture_now)
    store = PresaleStore(":memory:")
    created = create_series(store, current_terms)
    artifact_json_value = artifact_json(current_terms)
    ingest(store, current_terms)
    purchase = purchase_artifact_from_json(artifact_json_value)
    program_terms = series_terms_from_json(current_terms)

    purchases = PaymentPurchaseStore(str(tmp_path / "base-refund.db"))
    purchases.save(
        purchase_intent_id="base-refund-intent",
        rail="base_usdc",
        offer_artifact_hash=hex32(123),
        offer_artifact={},
        purchase_artifact=artifact_json_value,
        created_at=fixture_now,
    )
    payment_evidence = {
        "globalPaymentId": hex32(60),
        "depositor": evm_address(80),
        "source": {
            "chainId": BASE_SEPOLIA_CHAIN_ID,
            "transactionHash": hex32(124),
            "blockTimestamp": fixture_now,
        },
    }
    purchases.bind_external_message(
        str(artifact_json_value["purchaseId"]),
        payment_evidence,
    )

    pending = store.voucher(str(current_terms["termsHash"]), 0)
    commitment = voucher_commitment_from_json(pending["commitment"])
    purchase_launcher = Coin(b32(125), b32(126), uint64(2))
    voucher_launcher = Coin(
        purchase_launcher.name(),
        SINGLETON_LAUNCHER_HASH,
        uint64(1),
    )
    voucher_inner = curry_voucher_inner(
        terms=program_terms,
        voucher=commitment,
        voucher_launcher_id=bytes32(voucher_launcher.name()),
    )
    voucher_coin = Coin(
        voucher_launcher.name(),
        bytes32(
            puzzle_for_singleton(
                bytes32(voucher_launcher.name()),
                voucher_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    receipt_coin = Coin(
        purchase_launcher.name(),
        bytes32(
            curry_external_receipt(
                terms=program_terms,
                voucher=commitment,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    initial_series_coin = Coin(
        bytes32.from_hexstr(str(current_terms["seriesSingletonId"])),
        bytes32.from_hexstr(str(created["singletonLaunch"]["fullPuzzleHash"])),
        uint64(1),
    )
    sold_state = VoucherSeriesStateV2(sold_count=1)
    sold_inner = curry_series(program_terms, sold_state)
    sold_series_coin = Coin(
        initial_series_coin.name(),
        bytes32(
            puzzle_for_singleton(
                program_terms.series_singleton_id,
                sold_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    store.record_issuance_funding(
        str(current_terms["termsHash"]),
        0,
        funding_bundle_id=hex32(127),
        purchase_launcher_coin_id=hex32(purchase_launcher.name()),
        purchase_launcher_puzzle_hash=hex32(purchase_launcher.puzzle_hash),
    )
    store.record_issuance_submission(
        str(current_terms["termsHash"]),
        0,
        issuance_bundle_id=hex32(128),
        voucher_launcher_id=hex32(voucher_launcher.name()),
        voucher_output_coin_id=hex32(voucher_coin.name()),
        payment_commitment_coin_id=hex32(receipt_coin.name()),
        series_input_coin_id=hex32(initial_series_coin.name()),
        series_output_coin_id=hex32(sold_series_coin.name()),
        signer_indices=(0, 1),
    )
    store.confirm_issuance(
        str(current_terms["termsHash"]),
        0,
        VoucherIssuanceChainEvidence(
            evidenceId="base-refund-issuance-confirmed",
            spendBundleId=hex32(128),
            purchaseLauncherCoinId=hex32(purchase_launcher.name()),
            voucherLauncherId=hex32(voucher_launcher.name()),
            voucherOutputCoinId=hex32(voucher_coin.name()),
            paymentCommitmentCoinId=hex32(receipt_coin.name()),
            seriesInputCoinId=hex32(initial_series_coin.name()),
            seriesInputParentCoinId=hex32(initial_series_coin.parent_coin_info),
            seriesOutputCoinId=hex32(sold_series_coin.name()),
            seriesOutputInnerPuzzleHash=hex32(sold_inner.get_tree_hash()),
            confirmedHeight=140,
        ),
    )

    launch_anchor = int(current_terms["saleClose"])
    live_state = VoucherSeriesStateV2(
        sold_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=launch_anchor,
    )
    live_inner = curry_series(program_terms, live_state)
    live_series_coin = Coin(
        sold_series_coin.name(),
        bytes32(
            puzzle_for_singleton(
                program_terms.series_singleton_id,
                live_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    store.record_phase_submission(
        str(current_terms["termsHash"]),
        target_state="LIVE",
        spend_bundle_id=hex32(129),
        series_input_coin_id=hex32(sold_series_coin.name()),
        series_output_coin_id=hex32(live_series_coin.name()),
        series_output_inner_puzzle_hash=hex32(live_inner.get_tree_hash()),
        launch_anchor=launch_anchor,
        governance_execution_ids=[hex32(130)],
    )
    store.confirm_phase_transition(
        str(current_terms["termsHash"]),
        VoucherSeriesPhaseChainEvidence(
            evidenceId="base-refund-series-live",
            spendBundleId=hex32(129),
            targetState="LIVE",
            seriesInputCoinId=hex32(sold_series_coin.name()),
            seriesInputParentCoinId=hex32(sold_series_coin.parent_coin_info),
            seriesOutputCoinId=hex32(live_series_coin.name()),
            seriesOutputInnerPuzzleHash=hex32(live_inner.get_tree_hash()),
            launchAnchor=launch_anchor,
            confirmedHeight=141,
        ),
    )

    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    coinset = FakeCoinset(Coin(b32(131), faucet.address_puzzle_hash, uint64(20)))
    for coin in (live_series_coin, voucher_coin, receipt_coin):
        coinset.records[hex32(coin.name())] = coin_record(coin, confirmed=141)

    async def fake_lineage(_coinset, _coin_id, label):
        if label == "voucher series coin":
            return live_series_coin, LineageProof(
                parent_name=sold_series_coin.parent_coin_info,
                inner_puzzle_hash=bytes32(sold_inner.get_tree_hash()),
                amount=uint64(1),
            )
        if label == "voucher coin":
            return voucher_coin, LineageProof(
                parent_name=purchase_launcher.name(),
                amount=uint64(1),
            )
        raise AssertionError(label)

    expected_evidence_hash = base_settlement_evidence_hash(payment_evidence)

    async def fake_quorum(_settings, claim):
        assert claim.action == int(VoucherAction.REFUND_EXPIRED)
        assert claim.payment_evidence == payment_evidence
        assert claim.external_settlement_evidence_hash == expected_evidence_hash
        assert claim.deed_coin_id is None
        assert claim.vault_coin_id is None
        assert claim.owner_authorization == ""
        return ValidatorQuorumResult(
            signer_indices=(0, 1),
            aggregated_signature=G2Element(),
            claim_hash=claim.canonical_hash(),
        )

    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker._confirmed_coin_and_lineage",
        fake_lineage,
    )
    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.collect_voucher_transition_quorum",
        fake_quorum,
    )
    monkeypatch.setattr(
        "solslot_api.voucher_issuance_worker.load_signed_public_artifact",
        lambda _settings: {"artifactHash": hex32(132)},
    )
    worker = VoucherIssuanceWorker(
        settings=Settings(runtime_environment="test", network="testnet11"),
        faucet=faucet,
        coinset=coinset,
        presales=store,
        purchases=purchases,
        config=VoucherIssuanceWorkerConfig(enabled=True),
    )

    submitted = await worker.reconcile_once()
    assert submitted == [
        {
            "termsHash": str(current_terms["termsHash"]),
            "serial": 0,
            "status": "BASE_REFUND_SUBMITTED",
        }
    ]
    refunding = store.voucher(str(current_terms["termsHash"]), 0)
    assert refunding["state"] == "REFUNDING"
    assert refunding["externalSettlementEvidenceHash"] == expected_evidence_hash
    assert len(SpendBundle.from_json_dict(coinset.pushed[-1]).coin_spends) == 3

    refund_bundle = SpendBundle.from_json_dict(coinset.pushed[-1])
    refund_additions = [
        addition
        for spend in refund_bundle.coin_spends
        for addition in compute_additions(spend)
    ]
    additions_by_id = {
        hex32(addition.name()): addition for addition in refund_additions
    }
    for field in ("terminalVoucherCoinId", "refundSeriesOutputCoinId"):
        coin_id = str(refunding[field])
        coinset.records[coin_id] = coin_record(
            additions_by_id[coin_id], confirmed=150
        )
    for coin in (live_series_coin, voucher_coin, receipt_coin):
        coinset.records[hex32(coin.name())] = coin_record(
            coin, confirmed=141, spent=150
        )

    confirmed = await worker.reconcile_once()
    assert confirmed == [
        {
            "termsHash": str(current_terms["termsHash"]),
            "serial": 0,
            "status": "BASE_REFUND_AUTHORIZED",
        }
    ]
    refunded = store.voucher(str(current_terms["termsHash"]), 0)
    assert refunded["state"] == "REFUNDED"
    assert refunded["refundConfirmedHeight"] == 150
    assert refunded["externalSettlementEvidenceHash"] == expected_evidence_hash
    assert purchase.rail == PaymentRail.EVM_TEST_USD
    pending_settlements = store.pending_base_settlement_authorizations()
    assert len(pending_settlements) == 1
    authorization = pending_settlements[0]["authorization"]
    assert authorization["schema"] == BASE_SETTLEMENT_AUTHORIZATION_SCHEMA
    assert authorization["outcome"] == "REFUND"
    assert authorization["payment"]["principal"] == refunded["paymentPrincipal"]
    assert authorization["payment"]["evidenceHash"] == expected_evidence_hash
    assert authorization["chia"]["confirmedHeight"] == 150
    assert "deedInputCoinId" not in authorization["chia"]
    assert (
        authorization["chia"]["externalReceiptInputCoinId"]
        == refunding["paymentCommitmentCoinId"]
    )
