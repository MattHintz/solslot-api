"""RC20 refundable voucher presales derived from governed collection state."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Iterator, Literal, Optional

from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from web3 import Web3
from web3.logs import DISCARD

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
    purchase_artifact_from_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3,
    PurchaseKind,
    StripeSettlementReceiptV1,
    purchase_artifact_v3_from_json,
    purchase_artifact_v3_to_json,
    stripe_evidence_to_json,
    stripe_receipt_from_json,
    stripe_receipt_to_json,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    DeedAllocationCommitmentV2,
    VoucherCommitmentV2,
    VoucherPaymentRail,
    VoucherSeriesState,
    VoucherSeriesTermsV2,
    VoucherState,
    VoucherV2Error,
    allocation_root,
    technology_fee_minor,
    validate_purchase,
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
    curry_xch_escrow,
    curry_series,
    prepare_xch_voucher_offer,
    validate_xch_voucher_offer,
)
from solslot_puzzles.voucher_presale_v3 import (
    VoucherV3Error,
    build_stripe_voucher_commitment,
    stripe_original_payer,
    validate_stripe_voucher_purchase,
    voucher_commitment_v3_to_json,
    voucher_commitment_v3_from_json,
)
from solslot_puzzles.voucher_presale_v3_driver import (
    build_stripe_voucher_terminal_spends,
    stripe_voucher_evidence_message,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    build_vault_receive_spend,
    compact_signature_from_evm,
    eip712_typed_data_for_vault_spend,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
    puzzle_for_vault_inner,
)

from .admin_auth import require_admin_jwt
from .admin_operations import require_admin_operation
from .collection_store import CollectionStore, get_collection_store
from .config import Settings, get_settings
from .credential_auth import require_presale_writes, verify_vault_session
from .evm_auth import recover_evm_signer
from .faucet import AGG_SIG_ME_DATA
from .omnichain_evidence import OmnichainEvidenceError, load_omnichain_evidence
from .launch_gates import require_operation_gate
from .native_purchases import (
    _coin_from_record,
    _coin_spend_json,
    _record_is_unspent_coin,
    _select_payment_coin,
)
from .payment_purchase_store import (
    PaymentPurchaseNotFound,
    StoredPaymentPurchase,
    get_payment_purchase_store,
)
from .stripe_voucher_execution import (
    parse_stripe_terminal_execution,
    prepare_and_dispatch_stripe_terminal,
)
from .protocol_artifacts import (
    _artifact_rejection_reasons,
    _require_server_to_server_token,
)
from .public_artifact import PublicArtifactError, load_signed_public_artifact
from .singleton_launcher import (
    build_and_sign_singleton_launch,
    launcher_coin_for_parent,
)
from .vault_eligibility import ApprovedVault, require_current_approved_vault
from .state import get_registry
from .validator_quorum import (
    ValidatorQuorumError,
    VoucherIssuanceClaim,
    VoucherSeriesPhaseClaim,
    VoucherTransitionClaim,
    collect_voucher_issuance_quorum,
    collect_voucher_series_phase_quorum,
    collect_voucher_transition_quorum,
)


router = APIRouter(prefix="/presales", tags=["presales"])
HEX32_PATTERN = r"^0x[0-9a-fA-F]{64}$"
SERIES_SCHEMA = "solslot.refundable-voucher-series.v2"
BASE_SETTLEMENT_AUTHORIZATION_SCHEMA = (
    "solslot.base-voucher-settlement-authorization.v2"
)
STRIPE_REFUND_AUTHORIZATION_SCHEMA = (
    "solslot.stripe-voucher-refund-authorization.v1"
)
BASE_SEPOLIA_CHAIN_ID = 84532
BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
REFUND_AUTH_MAX_AGE_SECONDS = 90
BASE_SETTLEMENT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "name": "globalPaymentId",
                "type": "bytes32",
            },
            {"indexed": True, "name": "recipient", "type": "address"},
            {
                "indexed": False,
                "name": "settlementToken",
                "type": "address",
            },
            {"indexed": False, "name": "amount", "type": "uint256"},
            {"indexed": False, "name": "succeeded", "type": "bool"},
            {"indexed": False, "name": "emergency", "type": "bool"},
        ],
        "name": "PaymentSettled",
        "type": "event",
    },
    {
        "inputs": [{"name": "globalPaymentId", "type": "bytes32"}],
        "name": "getDeposit",
        "outputs": [
            {
                "components": [
                    {"name": "depositor", "type": "address"},
                    {"name": "settlementToken", "type": "address"},
                    {"name": "localPaymentId", "type": "bytes32"},
                    {"name": "purchaseId", "type": "bytes32"},
                    {"name": "artifactHash", "type": "bytes32"},
                    {"name": "collectionId", "type": "bytes32"},
                    {"name": "deedLauncherId", "type": "bytes32"},
                    {"name": "vaultLauncherId", "type": "bytes32"},
                    {"name": "destinationPuzzle", "type": "bytes32"},
                    {"name": "requestMessageId", "type": "bytes32"},
                    {"name": "resultMessageId", "type": "bytes32"},
                    {"name": "warpNonce", "type": "bytes32"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "quantity", "type": "uint256"},
                    {"name": "hubChainSelector", "type": "uint64"},
                    {"name": "hubGateway", "type": "address"},
                    {"name": "createdAt", "type": "uint64"},
                    {"name": "quoteExpiresAt", "type": "uint64"},
                    {"name": "status", "type": "uint8"},
                    {"name": "succeeded", "type": "bool"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


def _to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class ApiModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
        extra="forbid",
    )


class PresaleCreateRequest(ApiModel):
    collection_id: str = Field(min_length=1, max_length=120)
    sale_open: int = Field(gt=0)
    sale_close: int = Field(gt=0)
    refund_deadline: int = Field(gt=0)
    launch_deadline: int = Field(gt=0)


class VoucherIssuanceEvidenceRequest(ApiModel):
    purchase_artifact: dict[str, Any]
    global_payment_id: str = Field(pattern=HEX32_PATTERN)
    original_payer: str = Field(pattern=HEX32_PATTERN)
    evidence_id: str = Field(min_length=8, max_length=256)
    confirmed_height: int = Field(gt=0)
    transaction_index: int = Field(ge=0)
    output_index: int = Field(ge=0)
    confirmed_at: int = Field(gt=0)


class PrepareNativeVoucherRequest(ApiModel):
    purchase_id: str = Field(pattern=HEX32_PATTERN)
    payment_public_keys: list[str] = Field(min_length=1, max_length=100)

    @field_validator("payment_public_keys")
    @classmethod
    def validate_payment_public_keys(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            raw = _hex_bytes(value, 48, "paymentPublicKeys")
            G1Element.from_bytes(raw)
            normalized = "0x" + raw.hex()
            if normalized not in result:
                result.append(normalized)
        return result


class PrepareNativeVoucherResponse(ApiModel):
    terms_hash: str
    purchase_id: str
    buyer_offer: str
    coin_spends: list[dict[str, Any]]
    rail: Literal["chia_xch"] = "chia_xch"
    amount: int
    asset_id: str
    base_price_minor: int
    technology_fee_minor: int
    gross_price_minor: int
    quote_expires_at: int
    refund_deadline: int


class CompleteNativeVoucherRequest(ApiModel):
    purchase_id: str = Field(pattern=HEX32_PATTERN)
    buyer_offer: str = Field(min_length=16, max_length=2_000_000)
    aggregated_signature: str = Field(min_length=194, max_length=194)


class CompleteNativeVoucherResponse(ApiModel):
    terms_hash: str
    purchase_id: str
    transaction_id: str
    status: str
    signer_indices: list[int]
    voucher: dict[str, Any]


class PrepareVoucherRefundResponse(ApiModel):
    terms_hash: str
    serial: int
    auth_type: Literal["chia_bls", "evm"]
    action: Literal["REFUND_PRESALE"] = "REFUND_PRESALE"
    vault_coin_id: str
    voucher_coin_id: str
    series_coin_id: str
    current_timestamp: int
    expires_at: int
    coin_spends: list[dict[str, Any]] = Field(default_factory=list)
    typed_data: Optional[dict[str, Any]] = None


class CompleteVoucherRefundRequest(ApiModel):
    vault_coin_id: str = Field(pattern=HEX32_PATTERN)
    voucher_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_coin_id: str = Field(pattern=HEX32_PATTERN)
    current_timestamp: int = Field(gt=0)
    owner_authorization: str = Field(min_length=130, max_length=194)


class CompleteVoucherRefundResponse(ApiModel):
    terms_hash: str
    serial: int
    transaction_id: str
    status: str
    signer_indices: list[int]
    voucher: dict[str, Any]


class VoucherIssuanceChainEvidence(ApiModel):
    evidence_id: str = Field(min_length=8, max_length=256)
    spend_bundle_id: str = Field(pattern=HEX32_PATTERN)
    purchase_launcher_coin_id: str = Field(pattern=HEX32_PATTERN)
    voucher_launcher_id: str = Field(pattern=HEX32_PATTERN)
    voucher_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    payment_commitment_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_parent_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_inner_puzzle_hash: str = Field(pattern=HEX32_PATTERN)
    confirmed_height: int = Field(gt=0)


class VoucherRefundChainEvidence(ApiModel):
    action: int = Field(ge=1, le=4)
    evidence_id: str = Field(min_length=8, max_length=256)
    spend_bundle_id: str = Field(pattern=HEX32_PATTERN)
    refund_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    terminal_voucher_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_parent_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_inner_puzzle_hash: str = Field(pattern=HEX32_PATTERN)
    vault_input_coin_id: str | None = Field(default=None, pattern=HEX32_PATTERN)
    vault_output_coin_id: str | None = Field(default=None, pattern=HEX32_PATTERN)
    confirmed_height: int = Field(gt=0)


class VoucherRedemptionChainEvidence(ApiModel):
    evidence_id: str = Field(min_length=8, max_length=256)
    spend_bundle_id: str = Field(pattern=HEX32_PATTERN)
    treasury_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    deed_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    terminal_voucher_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_parent_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_inner_puzzle_hash: str = Field(pattern=HEX32_PATTERN)
    deed_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    external_settlement_evidence_hash: str | None = Field(
        default=None,
        pattern=HEX32_PATTERN,
    )
    confirmed_height: int = Field(gt=0)


class BaseVoucherRefundChainEvidence(ApiModel):
    action: Literal[2]
    evidence_id: str = Field(min_length=8, max_length=256)
    spend_bundle_id: str = Field(pattern=HEX32_PATTERN)
    external_settlement_evidence_hash: str = Field(pattern=HEX32_PATTERN)
    terminal_voucher_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_parent_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_inner_puzzle_hash: str = Field(pattern=HEX32_PATTERN)
    confirmed_height: int = Field(gt=0)


class StripeVoucherRefundChainEvidence(ApiModel):
    action: int = Field(ge=1, le=4)
    evidence_id: str = Field(min_length=8, max_length=256)
    spend_bundle_id: str = Field(pattern=HEX32_PATTERN)
    external_settlement_evidence_hash: str = Field(pattern=HEX32_PATTERN)
    terminal_voucher_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_parent_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_inner_puzzle_hash: str = Field(pattern=HEX32_PATTERN)
    vault_input_coin_id: str | None = Field(default=None, pattern=HEX32_PATTERN)
    vault_output_coin_id: str | None = Field(default=None, pattern=HEX32_PATTERN)
    confirmed_height: int = Field(gt=0)


class BaseSettlementRelayEvidenceRequest(ApiModel):
    warp_message_id: str = Field(pattern=HEX32_PATTERN)
    base_transaction_hash: str = Field(pattern=HEX32_PATTERN)
    confirmed_block_number: int = Field(gt=0)
    confirmed_at: int = Field(gt=0)


class StripeRefundCompletionRequest(ApiModel):
    payment_intent_id: str = Field(min_length=8, max_length=128)
    refund_id: str = Field(min_length=8, max_length=128)
    event_id: str | None = Field(default=None, min_length=8, max_length=128)
    refunded_minor: int = Field(gt=0)
    currency: Literal["usd"] = "usd"
    livemode: bool
    observed_at: int = Field(gt=0)


class VoucherSeriesPhaseChainEvidence(ApiModel):
    evidence_id: str = Field(min_length=8, max_length=256)
    spend_bundle_id: str = Field(pattern=HEX32_PATTERN)
    target_state: Literal["LIVE", "CANCELED"]
    series_input_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_input_parent_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_coin_id: str = Field(pattern=HEX32_PATTERN)
    series_output_inner_puzzle_hash: str = Field(pattern=HEX32_PATTERN)
    launch_anchor: int = Field(ge=0)
    confirmed_height: int = Field(gt=0)


class ChainEvidenceRequest(ApiModel):
    evidence_id: str = Field(min_length=8, max_length=256)
    output_coin_id: str = Field(pattern=HEX32_PATTERN)


class RefundEvidenceRequest(ChainEvidenceRequest):
    refund_destination: str = Field(pattern=HEX32_PATTERN)
    refund_amount: int = Field(gt=0)


class DeliveryEvidenceRequest(ChainEvidenceRequest):
    deed_launcher_id: str = Field(pattern=HEX32_PATTERN)
    vault_p2_puzzle_hash: str = Field(pattern=HEX32_PATTERN)


class LaunchRequest(ApiModel):
    pass


class CancelRequest(ApiModel):
    reason: str = Field(min_length=8, max_length=1000)


class PresaleStore:
    """Fresh V2 tables; unlaunched voucher V1 records are never migrated."""

    def __init__(self, path: str) -> None:
        self._lock = threading.RLock()
        db_path = Path(path)
        if path != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            ":memory:" if path == ":memory:" else str(db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS presale_series_v2 (
              terms_hash TEXT PRIMARY KEY NOT NULL,
              series_singleton_id TEXT NOT NULL UNIQUE,
              collection_id TEXT NOT NULL UNIQUE,
              chain_collection_id TEXT,
              terms_json TEXT NOT NULL,
              state TEXT NOT NULL CHECK (state IN ('PRESALE','LIVE','CANCELED')),
              launched_at INTEGER,
              launch_evidence_id TEXT,
              governance_execution_id TEXT,
              cancel_reason TEXT,
              phase_target_state TEXT,
              phase_bundle_id TEXT,
              phase_input_coin_id TEXT,
              phase_output_coin_id TEXT,
              phase_output_inner_puzzle_hash TEXT,
              phase_launch_anchor INTEGER,
              phase_governance_execution_ids_json TEXT,
              phase_submitted_at INTEGER,
              phase_confirmed_height INTEGER,
              singleton_parent_coin_id TEXT,
              singleton_full_puzzle_hash TEXT,
              singleton_launch_bundle_id TEXT,
              current_coin_id TEXT,
              current_inner_puzzle_hash TEXT,
              lineage_parent_name TEXT,
              lineage_inner_puzzle_hash TEXT,
              sold_count INTEGER NOT NULL DEFAULT 0,
              redeemed_count INTEGER NOT NULL DEFAULT 0,
              refunded_count INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS presale_payment_events_v2 (
              global_payment_id TEXT PRIMARY KEY NOT NULL,
              terms_hash TEXT NOT NULL REFERENCES presale_series_v2(terms_hash),
              order_key TEXT NOT NULL,
              evidence_id TEXT NOT NULL UNIQUE,
              outcome TEXT NOT NULL CHECK (outcome IN ('PAYMENT_CONFIRMED','REFUND_REQUIRED')),
              serial INTEGER,
              created_at INTEGER NOT NULL,
              UNIQUE (terms_hash, order_key)
            );
            CREATE TABLE IF NOT EXISTS voucher_records_v2 (
              terms_hash TEXT NOT NULL REFERENCES presale_series_v2(terms_hash),
              serial INTEGER NOT NULL,
              deed_launcher_id TEXT NOT NULL,
              payment_rail TEXT NOT NULL CHECK (payment_rail IN ('BASE_SEPOLIA_USDC','CHIA_XCH','STRIPE_USD')),
              payment_principal INTEGER NOT NULL,
              base_price_minor INTEGER NOT NULL,
              technology_fee_bps INTEGER NOT NULL,
              technology_fee_minor INTEGER NOT NULL,
              gross_price_minor INTEGER NOT NULL,
              original_payer TEXT NOT NULL,
              vault_launcher_id TEXT NOT NULL,
              vault_p2_puzzle_hash TEXT NOT NULL,
              purchase_id TEXT NOT NULL UNIQUE,
              global_payment_id TEXT NOT NULL UNIQUE,
              commitment_hash TEXT NOT NULL UNIQUE,
              commitment_json TEXT NOT NULL,
              purchase_artifact_json TEXT,
              settlement_receipt_json TEXT,
              processing_charge_minor INTEGER NOT NULL DEFAULT 0,
              state TEXT NOT NULL CHECK (state IN ('PENDING_ISSUANCE','ISSUANCE_SUBMITTED','ESCROWED','REFUNDING','REFUNDED','REDEEMING','REDEEMED')),
              payment_evidence_id TEXT NOT NULL,
              issuance_evidence_id TEXT,
              issuance_bundle_id TEXT,
              issuance_signer_indices_json TEXT,
              funding_bundle_id TEXT,
              purchase_launcher_coin_id TEXT,
              purchase_launcher_puzzle_hash TEXT,
              voucher_launcher_id TEXT,
              voucher_output_coin_id TEXT,
              payment_commitment_coin_id TEXT,
              series_input_coin_id TEXT,
              series_output_coin_id TEXT,
              issuance_confirmed_height INTEGER,
              refund_evidence_id TEXT,
              refund_action INTEGER,
              refund_bundle_id TEXT,
              refund_output_coin_id TEXT,
              terminal_voucher_coin_id TEXT,
              refund_series_input_coin_id TEXT,
              refund_series_output_coin_id TEXT,
              refund_vault_input_coin_id TEXT,
              refund_vault_output_coin_id TEXT,
              refund_submitted_at INTEGER,
              refund_confirmed_height INTEGER,
              redemption_bundle_id TEXT,
              redemption_treasury_output_coin_id TEXT,
              redemption_deed_output_coin_id TEXT,
              redemption_terminal_voucher_coin_id TEXT,
              redemption_series_input_coin_id TEXT,
              redemption_series_output_coin_id TEXT,
              redemption_deed_input_coin_id TEXT,
              external_settlement_evidence_hash TEXT,
              terminal_exact_execution_json TEXT,
              terminal_fee_coin_id TEXT,
              terminal_fee_mojos INTEGER,
              terminal_execution_observed_at INTEGER,
              redemption_submitted_at INTEGER,
              redemption_confirmed_height INTEGER,
              delivery_evidence_id TEXT,
              delivery_output_coin_id TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL,
              PRIMARY KEY (terms_hash, serial),
              UNIQUE (terms_hash, deed_launcher_id)
            );
            CREATE INDEX IF NOT EXISTS idx_presale_v2_state
              ON voucher_records_v2(terms_hash, state, serial);
            CREATE TABLE IF NOT EXISTS base_settlement_authorizations_v2 (
              authorization_id TEXT PRIMARY KEY NOT NULL,
              global_payment_id TEXT NOT NULL UNIQUE,
              terms_hash TEXT NOT NULL,
              serial INTEGER NOT NULL,
              outcome TEXT NOT NULL CHECK (outcome IN ('DELIVERED','REFUND')),
              authorization_hash TEXT NOT NULL UNIQUE,
              authorization_json TEXT NOT NULL,
              state TEXT NOT NULL CHECK (state IN ('PENDING','RELAYED')),
              created_at INTEGER NOT NULL,
              relayed_at INTEGER,
              relay_evidence_json TEXT,
              FOREIGN KEY (terms_hash, serial)
                REFERENCES voucher_records_v2(terms_hash, serial)
            );
            CREATE INDEX IF NOT EXISTS idx_base_settlement_v2_state
              ON base_settlement_authorizations_v2(state, created_at);
            CREATE TABLE IF NOT EXISTS stripe_refund_authorizations_v3 (
              authorization_id TEXT PRIMARY KEY NOT NULL,
              terms_hash TEXT NOT NULL,
              serial INTEGER NOT NULL,
              purchase_id TEXT NOT NULL UNIQUE,
              authorization_json TEXT NOT NULL,
              state TEXT NOT NULL CHECK (state IN ('PENDING','COMPLETED')),
              created_at INTEGER NOT NULL,
              completed_at INTEGER,
              completion_json TEXT,
              FOREIGN KEY (terms_hash, serial)
                REFERENCES voucher_records_v2(terms_hash, serial)
            );
            CREATE INDEX IF NOT EXISTS idx_stripe_refund_v3_state
              ON stripe_refund_authorizations_v3(state, created_at);
            """
        )
        columns = {
            row[1]
            for row in self._conn.execute(
                "PRAGMA table_info(presale_series_v2)"
            ).fetchall()
        }
        for name in (
            "singleton_parent_coin_id",
            "singleton_full_puzzle_hash",
            "singleton_launch_bundle_id",
            "chain_collection_id",
            "current_coin_id",
            "current_inner_puzzle_hash",
            "lineage_parent_name",
            "lineage_inner_puzzle_hash",
            "phase_target_state",
            "phase_bundle_id",
            "phase_input_coin_id",
            "phase_output_coin_id",
            "phase_output_inner_puzzle_hash",
            "phase_governance_execution_ids_json",
        ):
            if name not in columns:
                self._conn.execute(
                    f"ALTER TABLE presale_series_v2 ADD COLUMN {name} TEXT"
                )
        for name in (
            "phase_launch_anchor",
            "phase_submitted_at",
            "phase_confirmed_height",
        ):
            if name not in columns:
                self._conn.execute(
                    f"ALTER TABLE presale_series_v2 ADD COLUMN {name} INTEGER"
                )
        voucher_columns = {
            row[1]
            for row in self._conn.execute(
                "PRAGMA table_info(voucher_records_v2)"
            ).fetchall()
        }
        voucher_text_columns = (
            "purchase_artifact_json",
            "settlement_receipt_json",
            "issuance_signer_indices_json",
            "refund_bundle_id",
            "refund_output_coin_id",
            "terminal_voucher_coin_id",
            "refund_series_input_coin_id",
            "refund_series_output_coin_id",
            "refund_vault_input_coin_id",
            "refund_vault_output_coin_id",
            "redemption_bundle_id",
            "redemption_treasury_output_coin_id",
            "redemption_deed_output_coin_id",
            "redemption_terminal_voucher_coin_id",
            "redemption_series_input_coin_id",
            "redemption_series_output_coin_id",
            "redemption_deed_input_coin_id",
            "external_settlement_evidence_hash",
            "terminal_exact_execution_json",
            "terminal_fee_coin_id",
        )
        for name in voucher_text_columns:
            if name not in voucher_columns:
                self._conn.execute(
                    f"ALTER TABLE voucher_records_v2 ADD COLUMN {name} TEXT"
                )
        for name in (
            "processing_charge_minor",
            "refund_action",
            "refund_submitted_at",
            "refund_confirmed_height",
            "redemption_submitted_at",
            "redemption_confirmed_height",
            "terminal_fee_mojos",
            "terminal_execution_observed_at",
        ):
            if name not in voucher_columns:
                self._conn.execute(
                    f"ALTER TABLE voucher_records_v2 ADD COLUMN {name} INTEGER"
                )
        self._upgrade_voucher_payment_rail_constraint()

    def _upgrade_voucher_payment_rail_constraint(self) -> None:
        """Rebuild an initialized pre-Stripe table without changing its rows."""

        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            ("voucher_records_v2",),
        ).fetchone()
        if row is None or "STRIPE_USD" in str(row["sql"] or ""):
            return
        self._conn.execute(
            "UPDATE voucher_records_v2 SET processing_charge_minor=0 "
            "WHERE processing_charge_minor IS NULL"
        )
        self._conn.execute("PRAGMA foreign_keys=OFF")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                """
                CREATE TABLE voucher_records_v2_rc27 (
                  terms_hash TEXT NOT NULL REFERENCES presale_series_v2(terms_hash),
                  serial INTEGER NOT NULL,
                  deed_launcher_id TEXT NOT NULL,
                  payment_rail TEXT NOT NULL CHECK (payment_rail IN ('BASE_SEPOLIA_USDC','CHIA_XCH','STRIPE_USD')),
                  payment_principal INTEGER NOT NULL,
                  base_price_minor INTEGER NOT NULL,
                  technology_fee_bps INTEGER NOT NULL,
                  technology_fee_minor INTEGER NOT NULL,
                  gross_price_minor INTEGER NOT NULL,
                  original_payer TEXT NOT NULL,
                  vault_launcher_id TEXT NOT NULL,
                  vault_p2_puzzle_hash TEXT NOT NULL,
                  purchase_id TEXT NOT NULL UNIQUE,
                  global_payment_id TEXT NOT NULL UNIQUE,
                  commitment_hash TEXT NOT NULL UNIQUE,
                  commitment_json TEXT NOT NULL,
                  purchase_artifact_json TEXT,
                  settlement_receipt_json TEXT,
                  processing_charge_minor INTEGER NOT NULL DEFAULT 0,
                  state TEXT NOT NULL CHECK (state IN ('PENDING_ISSUANCE','ISSUANCE_SUBMITTED','ESCROWED','REFUNDING','REFUNDED','REDEEMING','REDEEMED')),
                  payment_evidence_id TEXT NOT NULL,
                  issuance_evidence_id TEXT,
                  issuance_bundle_id TEXT,
                  issuance_signer_indices_json TEXT,
                  funding_bundle_id TEXT,
                  purchase_launcher_coin_id TEXT,
                  purchase_launcher_puzzle_hash TEXT,
                  voucher_launcher_id TEXT,
                  voucher_output_coin_id TEXT,
                  payment_commitment_coin_id TEXT,
                  series_input_coin_id TEXT,
                  series_output_coin_id TEXT,
                  issuance_confirmed_height INTEGER,
                  refund_evidence_id TEXT,
                  refund_action INTEGER,
                  refund_bundle_id TEXT,
                  refund_output_coin_id TEXT,
                  terminal_voucher_coin_id TEXT,
                  refund_series_input_coin_id TEXT,
                  refund_series_output_coin_id TEXT,
                  refund_vault_input_coin_id TEXT,
                  refund_vault_output_coin_id TEXT,
                  refund_submitted_at INTEGER,
                  refund_confirmed_height INTEGER,
                  redemption_bundle_id TEXT,
                  redemption_treasury_output_coin_id TEXT,
                  redemption_deed_output_coin_id TEXT,
                  redemption_terminal_voucher_coin_id TEXT,
                  redemption_series_input_coin_id TEXT,
                  redemption_series_output_coin_id TEXT,
                  redemption_deed_input_coin_id TEXT,
                  external_settlement_evidence_hash TEXT,
                  terminal_exact_execution_json TEXT,
                  terminal_fee_coin_id TEXT,
                  terminal_fee_mojos INTEGER,
                  terminal_execution_observed_at INTEGER,
                  redemption_submitted_at INTEGER,
                  redemption_confirmed_height INTEGER,
                  delivery_evidence_id TEXT,
                  delivery_output_coin_id TEXT,
                  created_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL,
                  PRIMARY KEY (terms_hash, serial),
                  UNIQUE (terms_hash, deed_launcher_id)
                )
                """
            )
            old_columns = {
                str(info[1])
                for info in self._conn.execute(
                    "PRAGMA table_info(voucher_records_v2)"
                ).fetchall()
            }
            new_columns = [
                str(info[1])
                for info in self._conn.execute(
                    "PRAGMA table_info(voucher_records_v2_rc27)"
                ).fetchall()
            ]
            if old_columns != set(new_columns):
                raise RuntimeError(
                    "pre-Stripe voucher table cannot be migrated without data loss"
                )
            columns_sql = ", ".join(f'"{name}"' for name in new_columns)
            self._conn.execute(
                f"INSERT INTO voucher_records_v2_rc27 ({columns_sql}) "
                f"SELECT {columns_sql} FROM voucher_records_v2"
            )
            self._conn.execute("DROP TABLE voucher_records_v2")
            self._conn.execute(
                "ALTER TABLE voucher_records_v2_rc27 RENAME TO voucher_records_v2"
            )
            self._conn.execute(
                "CREATE INDEX idx_presale_v2_state "
                "ON voucher_records_v2(terms_hash, state, serial)"
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        finally:
            self._conn.execute("PRAGMA foreign_keys=ON")
        violations = self._conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError("voucher payment-rail migration broke foreign keys")

    def aggregate_counts(self) -> dict[str, Any]:
        """Aggregate the current schema; active vouchers are escrowed vouchers."""
        with self._lock:
            # One statement keeps both aggregates on the same SQLite snapshot.
            rows = self._conn.execute(
                "SELECT 'series' AS kind, state, COUNT(*) AS cnt "
                "FROM presale_series_v2 GROUP BY state UNION ALL "
                "SELECT 'voucher' AS kind, state, COUNT(*) AS cnt "
                "FROM voucher_records_v2 GROUP BY state"
            ).fetchall()
        series = {row["state"]: row["cnt"] for row in rows if row["kind"] == "series"}
        vouchers = {row["state"]: row["cnt"] for row in rows if row["kind"] == "voucher"}
        return {
            "series_by_phase": series,
            "vouchers_by_status": vouchers,
            "active_voucher_count": vouchers.get("ESCROWED", 0),
        }

    @contextmanager
    def txn(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
            finally:
                cur.close()

    def create(
        self,
        terms: dict[str, Any],
        *,
        singleton_launch: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        now = int(time.time())
        singleton_launch = singleton_launch or {}
        current_coin_id: Optional[str] = None
        current_inner_puzzle_hash: Optional[str] = None
        parent_coin_id = singleton_launch.get("parentCoinId")
        full_puzzle_hash = singleton_launch.get("fullPuzzleHash")
        if parent_coin_id and full_puzzle_hash:
            current_inner_puzzle_hash = _hex32(
                bytes32(curry_series(_series_program(terms), VoucherSeriesStateV2()).get_tree_hash())
            )
            current_coin_id = _hex32(
                bytes32(
                    Coin(
                        _b32(terms["seriesSingletonId"], nonzero=True),
                        _b32(full_puzzle_hash, nonzero=True),
                        uint64(1),
                    ).name()
                )
            )
        with self.txn() as cur:
            cur.execute(
                """
                INSERT INTO presale_series_v2(
                  terms_hash, series_singleton_id, collection_id,
                  chain_collection_id, terms_json,
                  state, singleton_parent_coin_id, singleton_full_puzzle_hash,
                  singleton_launch_bundle_id, current_coin_id,
                  current_inner_puzzle_hash, lineage_parent_name,
                  lineage_inner_puzzle_hash, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'PRESALE', ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    terms["termsHash"].lower(),
                    terms["seriesSingletonId"].lower(),
                    terms["collectionWorkspaceId"],
                    terms["collectionId"].lower(),
                    _json(terms),
                    singleton_launch.get("parentCoinId"),
                    singleton_launch.get("fullPuzzleHash"),
                    singleton_launch.get("spendBundleId"),
                    current_coin_id,
                    current_inner_puzzle_hash,
                    parent_coin_id,
                    now,
                    now,
                ),
            )
        return self.get(terms["termsHash"])

    def _get_series(self, identifier: str) -> dict[str, Any]:
        row = self._conn.execute(
            """
            SELECT * FROM presale_series_v2
            WHERE terms_hash=? OR collection_id=? OR chain_collection_id=?
              OR series_singleton_id=?
            """,
            (
                identifier.lower(),
                identifier,
                identifier.lower(),
                identifier.lower(),
            ),
        ).fetchone()
        if row is None:
            raise KeyError(identifier)
        return self._render_series(row)

    def get(self, identifier: str) -> dict[str, Any]:
        result = self._get_series(identifier)
        result["vouchers"] = [
            self._render_voucher(item, result)
            for item in self._conn.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? ORDER BY serial",
                (result["termsHash"].lower(),),
            ).fetchall()
        ]
        return result

    def list(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT terms_hash FROM presale_series_v2 ORDER BY created_at DESC"
        ).fetchall()
        return [self.get(row["terms_hash"]) for row in rows]

    def vouchers_for_vault(self, vault_launcher_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT * FROM voucher_records_v2
            WHERE vault_launcher_id=?
            ORDER BY created_at DESC, serial
            """,
            (vault_launcher_id.lower(),),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            series = self._get_series(row["terms_hash"])
            voucher = self._render_voucher(row, series)
            deed = next(
                (
                    item
                    for item in series["terms"]["deeds"]
                    if item["deedLauncherId"].lower()
                    == voucher["deedLauncherId"].lower()
                ),
                None,
            )
            result.append(
                {
                    key: voucher[key]
                    for key in (
                        "serial",
                        "deedLauncherId",
                        "paymentRail",
                        "paymentPrincipal",
                        "basePriceMinor",
                        "technologyFeeBps",
                        "technologyFeeMinor",
                        "grossPriceMinor",
                        "originalPayer",
                        "vaultLauncherId",
                        "vaultP2PuzzleHash",
                        "purchaseId",
                        "globalPaymentId",
                        "commitmentHash",
                        "state",
                        "paymentEvidenceId",
                        "issuanceEvidenceId",
                        "issuanceBundleId",
                        "voucherLauncherId",
                        "voucherOutputCoinId",
                        "paymentCommitmentCoinId",
                        "issuanceConfirmedHeight",
                        "deliveryDeadline",
                        "createdAt",
                        "updatedAt",
                    )
                }
                | {
                    "termsHash": series["termsHash"],
                    "seriesSingletonId": series["seriesSingletonId"],
                    "seriesState": series["state"],
                    "collectionId": series["collectionId"],
                    "deedId": (
                        deed["deedId"]
                        if deed is not None
                        else voucher["deedLauncherId"]
                    ),
                    "refundDeadline": series["terms"]["refundDeadline"],
                }
            )
        return result

    def ingest_payment(
        self,
        terms_hash: str,
        evidence: VoucherIssuanceEvidenceRequest,
        *,
        approved_vault: ApprovedVault,
        issued_purchase: StoredPaymentPurchase,
        external_escrow_contract: bytes32,
        now_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        series = self.get(terms_hash)
        if series["state"] != "PRESALE":
            raise ValueError("voucher series is not in PRESALE")
        if evidence.confirmed_at > int(now_seconds or time.time()) + 300:
            raise ValueError("payment confirmation time is in the future")
        try:
            artifact = purchase_artifact_from_json(evidence.purchase_artifact)
            artifact.assert_live(evidence.confirmed_at)
        except PaymentArtifactError as exc:
            raise ValueError(f"purchase artifact is invalid: {exc}") from exc
        terms = series["terms"]
        deed = next(
            (
                row
                for row in terms["deeds"]
                if row["deedLauncherId"].lower()
                == _hex32(artifact.deed_launcher_id)
            ),
            None,
        )
        if deed is None:
            raise ValueError("purchase artifact does not target this series")
        _validate_artifact_against_series(
            artifact=artifact,
            evidence=evidence,
            approved_vault=approved_vault,
            issued_purchase=issued_purchase,
            series=series,
            deed=deed,
        )
        original_payer = _verified_original_payer(
            artifact,
            evidence,
            issued_purchase,
        )
        purchase_id = _hex32(artifact.purchase_id)
        global_payment_id = evidence.global_payment_id.lower()
        order_key = (
            f"{evidence.confirmed_height:020d}:"
            f"{evidence.transaction_index:010d}:"
            f"{evidence.output_index:010d}:{global_payment_id}"
        )
        serial = int(deed["ordinal"])
        commitment = _voucher_commitment(
            series=series,
            deed=deed,
            artifact=artifact,
            original_payer=original_payer,
            global_payment_id=global_payment_id,
            approved_vault=approved_vault,
            external_escrow_contract=external_escrow_contract,
        )
        validate_purchase(
            series=_series_program(terms),
            voucher=commitment,
            now_seconds=evidence.confirmed_at,
        )
        commitment_json = _voucher_commitment_json(commitment)
        now = int(time.time())
        with self.txn() as cur:
            existing = cur.execute(
                "SELECT * FROM presale_payment_events_v2 WHERE global_payment_id=?",
                (global_payment_id,),
            ).fetchone()
            if existing is not None:
                if existing["evidence_id"] != evidence.evidence_id:
                    raise ValueError("global payment ID is bound to different evidence")
                return self._render_payment_event(existing)
            last = cur.execute(
                """
                SELECT order_key FROM presale_payment_events_v2
                WHERE terms_hash=? ORDER BY order_key DESC LIMIT 1
                """,
                (terms_hash.lower(),),
            ).fetchone()
            if last is not None and order_key < last["order_key"]:
                raise ValueError(
                    "payment evidence arrived out of canonical order; reconciliation is required"
                )
            occupied = cur.execute(
                "SELECT 1 FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (terms_hash.lower(), serial),
            ).fetchone()
            outcome = "REFUND_REQUIRED" if occupied else "PAYMENT_CONFIRMED"
            cur.execute(
                """
                INSERT INTO presale_payment_events_v2(
                  global_payment_id, terms_hash, order_key, evidence_id,
                  outcome, serial, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    global_payment_id,
                    terms_hash.lower(),
                    order_key,
                    evidence.evidence_id,
                    outcome,
                    serial,
                    now,
                ),
            )
            if not occupied:
                cur.execute(
                    """
                    INSERT INTO voucher_records_v2(
                      terms_hash, serial, deed_launcher_id, payment_rail,
                      payment_principal, base_price_minor, technology_fee_bps,
                      technology_fee_minor, gross_price_minor, original_payer,
                      vault_launcher_id, vault_p2_puzzle_hash, purchase_id,
                      global_payment_id,
                      commitment_hash, commitment_json, state,
                      payment_evidence_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'PENDING_ISSUANCE', ?, ?, ?)
                    """,
                    (
                        terms_hash.lower(),
                        serial,
                        deed["deedLauncherId"].lower(),
                        _voucher_rail_name(artifact.rail),
                        artifact.rail_amount,
                        deed["basePriceMinor"],
                        terms["technologyFeeBps"],
                        deed["technologyFeeMinor"],
                        deed["grossPriceMinor"],
                        original_payer,
                        approved_vault.launcher_id,
                        approved_vault.p2_puzzle_hash,
                        purchase_id,
                        global_payment_id,
                        _hex32(commitment.commitment_hash),
                        _json(commitment_json),
                        evidence.evidence_id,
                        now,
                        now,
                    ),
                )
            event = cur.execute(
                "SELECT * FROM presale_payment_events_v2 WHERE global_payment_id=?",
                (global_payment_id,),
            ).fetchone()
        return self._render_payment_event(event)

    def ingest_stripe_payment(
        self,
        terms_hash: str,
        *,
        artifact: PurchaseArtifactV3,
        receipt: StripeSettlementReceiptV1,
        evidence_id: str,
        issued_purchase: StoredPaymentPurchase,
    ) -> dict[str, Any]:
        """Persist one final Stripe payment as an exact Voucher V3 issuance."""

        series = self.get(terms_hash)
        if series["state"] != "PRESALE":
            raise ValueError("voucher series is not in PRESALE")
        terms = _series_program(series["terms"])
        if (
            artifact.purchase_kind != PurchaseKind.PRESALE
            or artifact.presale_terms_hash != terms.terms_hash
            or receipt.artifact != artifact
        ):
            raise ValueError("Stripe receipt does not target this presale")
        deed = next(
            (
                row
                for row in series["terms"]["deeds"]
                if str(row["deedLauncherId"]).lower()
                == _hex32(artifact.deed_launcher_id)
            ),
            None,
        )
        if deed is None:
            raise ValueError("Stripe purchase does not target this series")
        expected = (
            terms.collection_id,
            terms.metadata_root,
            terms.metadata_anchor_id,
            int(deed["sharePpm"]),
            int(deed["basePriceMinor"]),
            int(series["terms"]["technologyFeeBps"]),
            int(deed["technologyFeeMinor"]),
            int(deed["grossPriceMinor"]),
            terms.trusted_protocol_treasury,
        )
        observed = (
            artifact.collection_id,
            artifact.metadata_root,
            artifact.metadata_anchor_id,
            artifact.share_ppm,
            artifact.base_amount_minor,
            artifact.technology_fee_bps,
            artifact.technology_fee_minor,
            artifact.subtotal_minor,
            artifact.protocol_treasury_puzzle_hash,
        )
        if observed != expected:
            raise ValueError("Stripe purchase changes governed presale economics")
        artifact_json = purchase_artifact_v3_to_json(artifact)
        if (
            issued_purchase.rail != "stripe"
            or issued_purchase.purchase_id.lower()
            != _hex32(artifact.purchase_id)
            or issued_purchase.artifact_hash.lower()
            != _hex32(artifact.artifact_hash)
            or issued_purchase.purchase_artifact != artifact_json
        ):
            raise ValueError("stored Stripe purchase differs from the paid artifact")
        original_payer = stripe_original_payer(artifact)
        smart_deed_inner_hash = bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        )
        commitment = build_stripe_voucher_commitment(
            series=terms,
            allocation_root=terms.allocation_root,
            serial=int(deed["ordinal"]),
            original_payer=original_payer,
            smart_deed_inner_hash=smart_deed_inner_hash,
            artifact=artifact,
            receipt=receipt,
        )
        validate_stripe_voucher_purchase(
            series=terms,
            voucher=commitment,
            artifact=artifact,
            receipt=receipt,
            expected_original_payer=original_payer,
            expected_smart_deed_inner_hash=smart_deed_inner_hash,
            now_seconds=receipt.evidence.observed_at,
        )
        commitment_json = voucher_commitment_v3_to_json(commitment)
        receipt_json = stripe_receipt_to_json(receipt)
        global_payment_id = _hex32(commitment.global_payment_id)
        order_key = (
            f"stripe:{receipt.evidence.observed_at:020d}:"
            f"{receipt.evidence.event_id}:{global_payment_id}"
        )
        now = int(time.time())
        with self.txn() as cur:
            existing = cur.execute(
                "SELECT * FROM presale_payment_events_v2 WHERE global_payment_id=?",
                (global_payment_id,),
            ).fetchone()
            if existing is not None:
                if existing["evidence_id"] != evidence_id:
                    raise ValueError("Stripe payment is bound to different evidence")
                rendered = self._render_payment_event(existing)
                rendered["voucherState"] = self.voucher(
                    terms_hash, int(deed["ordinal"])
                )["state"]
                return rendered
            occupied = cur.execute(
                "SELECT 1 FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (terms_hash.lower(), int(deed["ordinal"])),
            ).fetchone()
            if occupied:
                raise ValueError("governed presale deed is already reserved")
            cur.execute(
                """
                INSERT INTO presale_payment_events_v2(
                  global_payment_id, terms_hash, order_key, evidence_id,
                  outcome, serial, created_at
                ) VALUES (?, ?, ?, ?, 'PAYMENT_CONFIRMED', ?, ?)
                """,
                (
                    global_payment_id,
                    terms_hash.lower(),
                    order_key,
                    evidence_id,
                    int(deed["ordinal"]),
                    now,
                ),
            )
            cur.execute(
                """
                INSERT INTO voucher_records_v2(
                  terms_hash, serial, deed_launcher_id, payment_rail,
                  payment_principal, base_price_minor, technology_fee_bps,
                  technology_fee_minor, gross_price_minor, processing_charge_minor,
                  original_payer, vault_launcher_id, vault_p2_puzzle_hash,
                  purchase_id, global_payment_id, commitment_hash,
                  commitment_json, purchase_artifact_json,
                  settlement_receipt_json, state, payment_evidence_id,
                  created_at, updated_at
                ) VALUES (?, ?, ?, 'STRIPE_USD', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, 'PENDING_ISSUANCE', ?, ?, ?)
                """,
                (
                    terms_hash.lower(),
                    int(deed["ordinal"]),
                    str(deed["deedLauncherId"]).lower(),
                    commitment.payment_principal,
                    commitment.base_price_minor,
                    commitment.technology_fee_bps,
                    commitment.technology_fee_minor,
                    commitment.gross_price_minor,
                    commitment.processing_charge_minor,
                    _hex32(commitment.original_payer),
                    _hex32(commitment.approved_vault_launcher_id),
                    _hex32(commitment.approved_vault_p2_puzzle_hash),
                    _hex32(artifact.purchase_id),
                    global_payment_id,
                    _hex32(commitment.commitment_hash),
                    _json(commitment_json),
                    _json(artifact_json),
                    _json(receipt_json),
                    evidence_id,
                    now,
                    now,
                ),
            )
            event = cur.execute(
                "SELECT * FROM presale_payment_events_v2 WHERE global_payment_id=?",
                (global_payment_id,),
            ).fetchone()
        rendered = self._render_payment_event(event)
        rendered["voucherState"] = "PENDING_ISSUANCE"
        return rendered

    def record_native_issuance_submission(
        self,
        terms_hash: str,
        *,
        artifact: Any,
        issued_purchase: StoredPaymentPurchase,
        approved_vault: ApprovedVault,
        payment_coin: Coin,
        global_payment_id: str,
        commitment: VoucherCommitmentV2,
        spend_bundle_id: str,
        purchase_launcher_coin: Coin,
        voucher_launcher_id: str,
        voucher_output_coin_id: str,
        payment_commitment_coin_id: str,
        series_input_coin: Coin,
        series_output_coin_id: str,
        submitted_at: Optional[int] = None,
    ) -> dict[str, Any]:
        """Persist one accepted atomic XCH payment and issuance submission."""
        series = self.get(terms_hash)
        now = int(submitted_at or time.time())
        if series["state"] != "PRESALE":
            raise ValueError("voucher series is not in PRESALE")
        deed = next(
            (
                row
                for row in series["terms"]["deeds"]
                if row["deedLauncherId"].lower() == _hex32(artifact.deed_launcher_id)
            ),
            None,
        )
        if deed is None:
            raise ValueError("purchase artifact does not target this series")
        _validate_artifact_binding(
            artifact=artifact,
            approved_vault=approved_vault,
            issued_purchase=issued_purchase,
            series=series,
            deed=deed,
        )
        if artifact.rail != PaymentRail.CHIA_XCH:
            raise ValueError("native voucher submission requires XCH")
        expected_commitment = _voucher_commitment(
            series=series,
            deed=deed,
            artifact=artifact,
            original_payer=_hex32(payment_coin.puzzle_hash),
            global_payment_id=global_payment_id,
            approved_vault=approved_vault,
            external_escrow_contract=bytes32.zeros,
        )
        if commitment != expected_commitment:
            raise ValueError("native voucher commitment changed before persistence")
        validate_purchase(
            series=_series_program(series["terms"]),
            voucher=commitment,
            now_seconds=now,
        )
        if (
            purchase_launcher_coin.parent_coin_info != payment_coin.name()
            or int(purchase_launcher_coin.amount) != int(artifact.rail_amount) + 1
        ):
            raise ValueError("native purchase launcher is not funded by the signed coin")
        expected_payment_puzzle = curry_xch_escrow(
            terms=_series_program(series["terms"]),
            voucher=commitment,
            purchase=artifact,
        )
        expected_launcher_puzzle = curry_purchase_launcher(
            terms=_series_program(series["terms"]),
            voucher=commitment,
            payment_puzzle_hash=bytes32(expected_payment_puzzle.get_tree_hash()),
            payment_amount=int(artifact.rail_amount),
        )
        if purchase_launcher_coin.puzzle_hash != expected_launcher_puzzle.get_tree_hash():
            raise ValueError("native purchase launcher puzzle changed before persistence")
        program_terms = _series_program(series["terms"])
        current_state = _chain_series_state(series)
        expected_series_puzzle = puzzle_for_singleton(
            program_terms.series_singleton_id,
            curry_series(program_terms, current_state),
        )
        if (
            _hex32(series_input_coin.name())
            != str(series["chainState"]["currentCoinId"]).lower()
            or series_input_coin.puzzle_hash != expected_series_puzzle.get_tree_hash()
            or int(series_input_coin.amount) != 1
        ):
            raise ValueError("native issuance does not spend the current series puzzle")
        expected_issuance = build_voucher_issuance_spends(
            terms=program_terms,
            state=current_state,
            series_coin=series_input_coin,
            series_lineage_proof=LineageProof(bytes32.zeros, None, uint64(1)),
            voucher=commitment,
            purchase_launcher_coin=purchase_launcher_coin,
            payment_puzzle=expected_payment_puzzle,
            payment_amount=int(artifact.rail_amount),
            signer_indices=(0, 1),
        )
        expected_outputs = {
            "voucher_launcher_id": _hex32(expected_issuance.voucher_launcher_id),
            "voucher_output_coin_id": _hex32(expected_issuance.voucher_coin.name()),
            "payment_commitment_coin_id": _hex32(expected_issuance.payment_coin.name()),
            "series_output_coin_id": _hex32(expected_issuance.next_series_coin.name()),
        }
        observed_outputs = {
            "voucher_launcher_id": voucher_launcher_id.lower(),
            "voucher_output_coin_id": voucher_output_coin_id.lower(),
            "payment_commitment_coin_id": payment_commitment_coin_id.lower(),
            "series_output_coin_id": series_output_coin_id.lower(),
        }
        if observed_outputs != expected_outputs:
            raise ValueError("native issuance outputs changed before persistence")

        normalized_global_id = global_payment_id.lower()
        serial = int(deed["ordinal"])
        evidence_id = "chia:" + spend_bundle_id.lower()
        order_key = f"mempool:{now:020d}:{normalized_global_id}"
        commitment_json = _voucher_commitment_json(commitment)
        with self.txn() as cur:
            existing = cur.execute(
                "SELECT * FROM presale_payment_events_v2 WHERE global_payment_id=?",
                (normalized_global_id,),
            ).fetchone()
            if existing is not None:
                if existing["evidence_id"] != evidence_id:
                    raise ValueError("native payment ID is bound to different evidence")
                return self.voucher(series["termsHash"], serial)
            chain = cur.execute(
                "SELECT current_coin_id FROM presale_series_v2 WHERE terms_hash=?",
                (series["termsHash"].lower(),),
            ).fetchone()
            if chain is None or chain["current_coin_id"] != _hex32(series_input_coin.name()):
                raise ValueError("series state changed before native submission")
            occupied = cur.execute(
                "SELECT 1 FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if occupied is not None:
                raise ValueError("the governed deed is already reserved")
            cur.execute(
                """
                INSERT INTO presale_payment_events_v2(
                  global_payment_id, terms_hash, order_key, evidence_id,
                  outcome, serial, created_at
                ) VALUES (?, ?, ?, ?, 'PAYMENT_CONFIRMED', ?, ?)
                """,
                (
                    normalized_global_id,
                    series["termsHash"].lower(),
                    order_key,
                    evidence_id,
                    serial,
                    now,
                ),
            )
            cur.execute(
                """
                INSERT INTO voucher_records_v2(
                  terms_hash, serial, deed_launcher_id, payment_rail,
                  payment_principal, base_price_minor, technology_fee_bps,
                  technology_fee_minor, gross_price_minor, original_payer,
                  vault_launcher_id, vault_p2_puzzle_hash, purchase_id,
                  global_payment_id, commitment_hash, commitment_json, state,
                  payment_evidence_id, issuance_bundle_id,
                  purchase_launcher_coin_id, purchase_launcher_puzzle_hash,
                  voucher_launcher_id, voucher_output_coin_id,
                  payment_commitment_coin_id, series_input_coin_id,
                  series_output_coin_id, created_at, updated_at
                ) VALUES (?, ?, ?, 'CHIA_XCH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'ISSUANCE_SUBMITTED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    series["termsHash"].lower(),
                    serial,
                    deed["deedLauncherId"].lower(),
                    int(artifact.rail_amount),
                    int(deed["basePriceMinor"]),
                    int(series["terms"]["technologyFeeBps"]),
                    int(deed["technologyFeeMinor"]),
                    int(deed["grossPriceMinor"]),
                    _hex32(payment_coin.puzzle_hash),
                    approved_vault.launcher_id,
                    approved_vault.p2_puzzle_hash,
                    _hex32(artifact.purchase_id),
                    normalized_global_id,
                    _hex32(commitment.commitment_hash),
                    _json(commitment_json),
                    evidence_id,
                    spend_bundle_id.lower(),
                    _hex32(purchase_launcher_coin.name()),
                    _hex32(purchase_launcher_coin.puzzle_hash),
                    voucher_launcher_id.lower(),
                    voucher_output_coin_id.lower(),
                    payment_commitment_coin_id.lower(),
                    _hex32(series_input_coin.name()),
                    series_output_coin_id.lower(),
                    now,
                    now,
                ),
            )
        return self.voucher(series["termsHash"], serial)

    def voucher_for_purchase(self, purchase_id: str) -> dict[str, Any]:
        """Use the unique current-protocol purchase binding, never a list scan."""
        row = self._conn.execute(
            "SELECT * FROM voucher_records_v2 WHERE purchase_id=?", (purchase_id,)
        ).fetchone()
        if row is None:
            raise KeyError(purchase_id)
        return self._render_voucher(row, self._get_series(row["terms_hash"]))

    def voucher(self, terms_hash: str, serial: int) -> dict[str, Any]:
        series = self._get_series(terms_hash)
        row = self._conn.execute(
            "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
            (series["termsHash"].lower(), serial),
        ).fetchone()
        if row is None:
            raise KeyError(serial)
        return self._render_voucher(row, series)

    def confirm_issuance(
        self,
        terms_hash: str,
        serial: int,
        evidence: VoucherIssuanceChainEvidence,
    ) -> dict[str, Any]:
        """Record chain-proven issuance after an independent node check.

        This store method deliberately cannot perform the node lookup itself;
        callers must re-derive and verify every listed coin before invoking it.
        """
        series = self._get_series(terms_hash)
        now = int(time.time())
        with self.txn() as cur:
            chain = cur.execute(
                """
                SELECT current_coin_id, current_inner_puzzle_hash, sold_count
                FROM presale_series_v2 WHERE terms_hash=?
                """,
                (series["termsHash"].lower(),),
            ).fetchone()
            if (
                chain is None
                or chain["current_coin_id"] != evidence.series_input_coin_id.lower()
            ):
                raise ValueError("issuance evidence does not spend the current series coin")
            submitted = cur.execute(
                """
                SELECT state, issuance_bundle_id, purchase_launcher_coin_id,
                       voucher_launcher_id, voucher_output_coin_id,
                       payment_commitment_coin_id, series_input_coin_id,
                       series_output_coin_id
                FROM voucher_records_v2 WHERE terms_hash=? AND serial=?
                """,
                (series["termsHash"].lower(), serial),
            ).fetchone()
            expected = {
                "issuance_bundle_id": evidence.spend_bundle_id.lower(),
                "purchase_launcher_coin_id": evidence.purchase_launcher_coin_id.lower(),
                "voucher_launcher_id": evidence.voucher_launcher_id.lower(),
                "voucher_output_coin_id": evidence.voucher_output_coin_id.lower(),
                "payment_commitment_coin_id": evidence.payment_commitment_coin_id.lower(),
                "series_input_coin_id": evidence.series_input_coin_id.lower(),
                "series_output_coin_id": evidence.series_output_coin_id.lower(),
            }
            if submitted is None or submitted["state"] != "ISSUANCE_SUBMITTED":
                raise ValueError(
                    "issuance confirmation requires ISSUANCE_SUBMITTED state"
                )
            if any(submitted[field] != value for field, value in expected.items()):
                raise ValueError("issuance evidence differs from submitted chain outputs")
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='ESCROWED', issuance_evidence_id=?,
                    issuance_bundle_id=?, purchase_launcher_coin_id=?,
                    voucher_launcher_id=?, voucher_output_coin_id=?,
                    payment_commitment_coin_id=?, series_input_coin_id=?,
                    series_output_coin_id=?, issuance_confirmed_height=?,
                    updated_at=?
                WHERE terms_hash=? AND serial=? AND state='ISSUANCE_SUBMITTED'
                """,
                (
                    evidence.evidence_id,
                    evidence.spend_bundle_id.lower(),
                    evidence.purchase_launcher_coin_id.lower(),
                    evidence.voucher_launcher_id.lower(),
                    evidence.voucher_output_coin_id.lower(),
                    evidence.payment_commitment_coin_id.lower(),
                    evidence.series_input_coin_id.lower(),
                    evidence.series_output_coin_id.lower(),
                    evidence.confirmed_height,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError(
                    "issuance confirmation requires ISSUANCE_SUBMITTED state"
                )
            series_updated = cur.execute(
                """
                UPDATE presale_series_v2
                SET current_coin_id=?, current_inner_puzzle_hash=?,
                    lineage_parent_name=?, lineage_inner_puzzle_hash=?,
                    sold_count=sold_count+1, updated_at=?
                WHERE terms_hash=? AND current_coin_id=?
                """,
                (
                    evidence.series_output_coin_id.lower(),
                    evidence.series_output_inner_puzzle_hash.lower(),
                    evidence.series_input_parent_coin_id.lower(),
                    chain["current_inner_puzzle_hash"],
                    now,
                    series["termsHash"].lower(),
                    evidence.series_input_coin_id.lower(),
                ),
            ).rowcount
            if series_updated != 1:
                raise ValueError("series state changed during issuance confirmation")
        return self.voucher(series["termsHash"], serial)

    def record_issuance_funding(
        self,
        terms_hash: str,
        serial: int,
        *,
        funding_bundle_id: str,
        purchase_launcher_coin_id: str,
        purchase_launcher_puzzle_hash: str,
    ) -> dict[str, Any]:
        series = self._get_series(terms_hash)
        now = int(time.time())
        with self.txn() as cur:
            existing = cur.execute(
                """
                SELECT funding_bundle_id, purchase_launcher_coin_id,
                       purchase_launcher_puzzle_hash, state
                FROM voucher_records_v2 WHERE terms_hash=? AND serial=?
                """,
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if existing is None:
                raise KeyError(serial)
            exact_retry = (
                existing["funding_bundle_id"] == funding_bundle_id.lower()
                and existing["purchase_launcher_coin_id"]
                == purchase_launcher_coin_id.lower()
                and existing["purchase_launcher_puzzle_hash"]
                == purchase_launcher_puzzle_hash.lower()
            )
            if exact_retry:
                return self.voucher(series["termsHash"], serial)
            if existing["state"] != "PENDING_ISSUANCE" or any(
                existing[field]
                for field in (
                    "funding_bundle_id",
                    "purchase_launcher_coin_id",
                    "purchase_launcher_puzzle_hash",
                )
            ):
                raise ValueError("voucher issuance funding is already bound")
            cur.execute(
                """
                UPDATE voucher_records_v2
                SET funding_bundle_id=?, purchase_launcher_coin_id=?,
                    purchase_launcher_puzzle_hash=?, updated_at=?
                WHERE terms_hash=? AND serial=?
                """,
                (
                    funding_bundle_id.lower(),
                    purchase_launcher_coin_id.lower(),
                    purchase_launcher_puzzle_hash.lower(),
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            )
        return self.voucher(series["termsHash"], serial)

    def record_issuance_submission(
        self,
        terms_hash: str,
        serial: int,
        *,
        issuance_bundle_id: str,
        voucher_launcher_id: str,
        voucher_output_coin_id: str,
        payment_commitment_coin_id: str,
        series_input_coin_id: str,
        series_output_coin_id: str,
        signer_indices: tuple[int, ...],
    ) -> dict[str, Any]:
        series = self._get_series(terms_hash)
        normalized_signers = _validator_signer_indices(signer_indices)
        now = int(time.time())
        with self.txn() as cur:
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='ISSUANCE_SUBMITTED', issuance_bundle_id=?,
                    issuance_signer_indices_json=?,
                    voucher_launcher_id=?, voucher_output_coin_id=?,
                    payment_commitment_coin_id=?, series_input_coin_id=?,
                    series_output_coin_id=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='PENDING_ISSUANCE'
                  AND purchase_launcher_coin_id IS NOT NULL
                """,
                (
                    issuance_bundle_id.lower(),
                    _json(normalized_signers),
                    voucher_launcher_id.lower(),
                    voucher_output_coin_id.lower(),
                    payment_commitment_coin_id.lower(),
                    series_input_coin_id.lower(),
                    series_output_coin_id.lower(),
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError(
                    "issuance submission requires funded PENDING_ISSUANCE state"
                )
        return self.voucher(series["termsHash"], serial)

    def pending_issuance(self) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT v.terms_hash, v.serial FROM voucher_records_v2 v
            JOIN presale_series_v2 s ON s.terms_hash=v.terms_hash
            WHERE v.state IN ('PENDING_ISSUANCE','ISSUANCE_SUBMITTED')
              AND s.state='PRESALE' AND s.phase_bundle_id IS NULL
            ORDER BY v.created_at, v.terms_hash, v.serial
            """
        ).fetchall()
        return [
            (self._get_series(row["terms_hash"]), self.voucher(row["terms_hash"], row["serial"]))
            for row in rows
        ]

    def request_refund(
        self,
        terms_hash: str,
        serial: int,
        *,
        vault_launcher_id: str,
        now_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        series = self.get(terms_hash)
        voucher = self.voucher(series["termsHash"], serial)
        now = int(now_seconds or time.time())
        expected_state = (
            "REDEEMING" if series["state"] == "LIVE" else "ESCROWED"
        )
        if voucher["state"] != expected_state or series["state"] not in {
            "PRESALE",
            "LIVE",
            "CANCELED",
        }:
            raise ValueError("voucher is not refundable in its current state")
        if (
            series["state"] == "PRESALE"
            and now >= int(series["terms"]["refundDeadline"])
        ):
            raise ValueError("voucher refund deadline has passed")
        if (
            series["state"] == "LIVE"
            and now < int(series["deliveryDeadline"] or 0)
        ):
            raise ValueError("voucher delivery window has not expired")
        if voucher["vaultLauncherId"] != vault_launcher_id.lower():
            raise ValueError("refund session does not own this voucher")
        # XCH and Stripe V3 remain in their current state until the exact
        # owner-authorized terminal bundle is accepted by the node. Base uses
        # its separate escrow coordinator and records REFUNDING immediately.
        if voucher["paymentRail"] == "BASE_SEPOLIA_USDC":
            self._set_voucher_state(
                series["termsHash"], serial, expected=expected_state, new="REFUNDING"
            )
        return self.voucher(series["termsHash"], serial)

    def bind_stripe_terminal_execution(
        self,
        terms_hash: str,
        serial: int,
        execution: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist one immutable fee-funded KoS terminal execution before dispatch."""

        if execution.get("schema") != "solslot.stripe-voucher-terminal-execution.v1":
            raise ValueError("Stripe terminal execution schema is invalid")
        if execution.get("mode") not in {
            "REDEEM",
            "REFUND_EXPIRED",
            "REFUND_OWNER",
        }:
            raise ValueError("Stripe terminal execution mode is invalid")
        prepared = execution.get("prepared")
        if not isinstance(prepared, dict):
            raise ValueError("Stripe terminal execution bundle is missing")
        try:
            fee_mojos = int(prepared["feeMojos"])
            fee_coin_id = _hex32(
                _b32(str(prepared["feeCoinId"]), nonzero=True)
            )
            _b32(str(prepared["spendBundleId"]), nonzero=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Stripe terminal execution fee binding is invalid") from exc
        if fee_mojos < 0:
            raise ValueError("Stripe terminal execution fee cannot be negative")
        canonical = json.dumps(
            execution,
            sort_keys=True,
            separators=(",", ":"),
        )
        series = self.get(terms_hash)
        now = int(time.time())
        with self.txn() as cur:
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            if row["payment_rail"] != "STRIPE_USD" or row["state"] not in {
                "ESCROWED",
                "REDEEMING",
            }:
                raise ValueError(
                    "Stripe terminal execution requires an unsettled Stripe voucher"
                )
            if row["refund_bundle_id"] or row["redemption_bundle_id"]:
                raise ValueError("Stripe voucher already has a submitted terminal spend")
            existing = row["terminal_exact_execution_json"]
            if existing is not None:
                if existing != canonical:
                    raise ValueError(
                        "Stripe voucher is already bound to another terminal execution"
                    )
                return self.voucher(series["termsHash"], serial)
            competing = cur.execute(
                """
                SELECT serial FROM voucher_records_v2
                WHERE terms_hash=? AND serial<>?
                  AND terminal_exact_execution_json IS NOT NULL
                  AND state IN ('ESCROWED', 'REDEEMING', 'REFUNDING')
                LIMIT 1
                """,
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if competing is not None:
                raise ValueError(
                    "another Stripe voucher terminal spend is already active "
                    "for this singleton series"
                )
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET terminal_exact_execution_json=?, terminal_fee_coin_id=?,
                    terminal_fee_mojos=?, updated_at=?
                WHERE terms_hash=? AND serial=?
                  AND terminal_exact_execution_json IS NULL
                  AND refund_bundle_id IS NULL AND redemption_bundle_id IS NULL
                """,
                (
                    canonical,
                    fee_coin_id,
                    fee_mojos,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("Stripe terminal execution changed concurrently")
        return self.voucher(series["termsHash"], serial)

    def pending_stripe_terminal_executions(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT terms_hash, serial FROM voucher_records_v2
            WHERE payment_rail='STRIPE_USD'
              AND terminal_exact_execution_json IS NOT NULL
              AND refund_bundle_id IS NULL AND redemption_bundle_id IS NULL
            ORDER BY updated_at, terms_hash, serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def pending_stripe_terminal_fee_coin_ids(self) -> set[str]:
        """Return fee coins sealed before Stripe terminal KoS handoff."""

        rows = self._conn.execute(
            """
            SELECT terminal_fee_coin_id FROM voucher_records_v2
            WHERE payment_rail='STRIPE_USD'
              AND terminal_exact_execution_json IS NOT NULL
              AND refund_confirmed_height IS NULL
              AND redemption_confirmed_height IS NULL
            """
        ).fetchall()
        reserved: set[str] = set()
        for row in rows:
            raw = row["terminal_fee_coin_id"]
            if not isinstance(raw, str):
                raise ValueError(
                    "persisted Stripe terminal execution has no fee coin binding"
                )
            reserved.add(_hex32(_b32(raw, nonzero=True)))
        return reserved

    def record_native_refund_submission(
        self,
        terms_hash: str,
        serial: int,
        *,
        action: VoucherAction,
        spend_bundle_id: str,
        refund_output_coin_id: str,
        terminal_voucher_coin_id: str,
        series_input_coin_id: str,
        series_output_coin_id: str,
        vault_input_coin_id: str | None,
        vault_output_coin_id: str | None,
    ) -> dict[str, Any]:
        """Bind REFUNDING only after the exact native bundle is accepted."""
        series = self.get(terms_hash)
        now = int(time.time())
        normalized = {
            "refund_action": int(action),
            "refund_bundle_id": spend_bundle_id.lower(),
            "refund_output_coin_id": refund_output_coin_id.lower(),
            "terminal_voucher_coin_id": terminal_voucher_coin_id.lower(),
            "refund_series_input_coin_id": series_input_coin_id.lower(),
            "refund_series_output_coin_id": series_output_coin_id.lower(),
            "refund_vault_input_coin_id": (
                vault_input_coin_id.lower() if vault_input_coin_id else None
            ),
            "refund_vault_output_coin_id": (
                vault_output_coin_id.lower() if vault_output_coin_id else None
            ),
        }
        owner_authorized = action in {
            VoucherAction.REFUND_PRESALE,
            VoucherAction.REFUND_CANCELED,
        }
        if action == VoucherAction.REFUND_EXPIRED:
            if series["state"] != "LIVE" or now < int(
                series["deliveryDeadline"] or 0
            ):
                raise ValueError("automatic refund requires an expired LIVE series")
            if vault_input_coin_id is not None or vault_output_coin_id is not None:
                raise ValueError("automatic refund cannot carry a vault co-spend")
        elif owner_authorized:
            if vault_input_coin_id is None or vault_output_coin_id is None:
                raise ValueError("owner refund requires exact vault chain bindings")
        else:
            raise ValueError("native refund action is invalid")
        with self.txn() as cur:
            existing = cur.execute(
                """
                SELECT payment_rail, state, refund_action, refund_bundle_id,
                       refund_output_coin_id, terminal_voucher_coin_id,
                       refund_series_input_coin_id, refund_series_output_coin_id,
                       refund_vault_input_coin_id, refund_vault_output_coin_id
                FROM voucher_records_v2 WHERE terms_hash=? AND serial=?
                """,
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if existing is None:
                raise KeyError(serial)
            if existing["payment_rail"] != "CHIA_XCH":
                raise ValueError("native refund submission requires an XCH voucher")
            exact_retry = existing["state"] == "REFUNDING" and all(
                existing[field] == value for field, value in normalized.items()
            )
            if exact_retry:
                return self.voucher(series["termsHash"], serial)
            expected_state = (
                "REDEEMING" if series["state"] == "LIVE" else "ESCROWED"
            )
            if existing["state"] != expected_state or any(
                existing[field] is not None for field in normalized
            ):
                raise ValueError("native voucher refund is already bound")
            if series["chainState"]["currentCoinId"] != normalized[
                "refund_series_input_coin_id"
            ]:
                raise ValueError("refund does not spend the current series coin")
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDING', refund_action=?, refund_bundle_id=?,
                    refund_output_coin_id=?, terminal_voucher_coin_id=?,
                    refund_series_input_coin_id=?, refund_series_output_coin_id=?,
                    refund_vault_input_coin_id=?, refund_vault_output_coin_id=?,
                    refund_submitted_at=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state=?
                """,
                (
                    normalized["refund_action"],
                    normalized["refund_bundle_id"],
                    normalized["refund_output_coin_id"],
                    normalized["terminal_voucher_coin_id"],
                    normalized["refund_series_input_coin_id"],
                    normalized["refund_series_output_coin_id"],
                    normalized["refund_vault_input_coin_id"],
                    normalized["refund_vault_output_coin_id"],
                    now,
                    now,
                    series["termsHash"].lower(),
                    serial,
                    expected_state,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("native refund submission requires ESCROWED state")
        return self.voucher(series["termsHash"], serial)

    def pending_native_refunds(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT terms_hash, serial FROM voucher_records_v2
            WHERE payment_rail='CHIA_XCH' AND state='REFUNDING'
              AND refund_bundle_id IS NOT NULL
            ORDER BY refund_submitted_at, terms_hash, serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def record_base_expired_refund_submission(
        self,
        terms_hash: str,
        serial: int,
        *,
        spend_bundle_id: str,
        external_settlement_evidence_hash: str,
        terminal_voucher_coin_id: str,
        series_input_coin_id: str,
        series_output_coin_id: str,
    ) -> dict[str, Any]:
        """Bind a Base refund only after its exact Chia terminal bundle is accepted."""
        series = self.get(terms_hash)
        now = int(time.time())
        if (
            series["state"] != "LIVE"
            or now < int(series["deliveryDeadline"] or 0)
        ):
            raise ValueError("Base automatic refund requires an expired LIVE series")
        normalized = {
            "refund_action": int(VoucherAction.REFUND_EXPIRED),
            "refund_bundle_id": spend_bundle_id.lower(),
            "terminal_voucher_coin_id": terminal_voucher_coin_id.lower(),
            "refund_series_input_coin_id": series_input_coin_id.lower(),
            "refund_series_output_coin_id": series_output_coin_id.lower(),
            "external_settlement_evidence_hash": (
                external_settlement_evidence_hash.lower()
            ),
        }
        with self.txn() as cur:
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            exact_retry = row["state"] == "REFUNDING" and all(
                row[field] == value for field, value in normalized.items()
            )
            if exact_retry:
                return self.voucher(series["termsHash"], serial)
            if (
                row["payment_rail"] != "BASE_SEPOLIA_USDC"
                or row["state"] != "REDEEMING"
            ):
                raise ValueError(
                    "Base automatic refund requires a REDEEMING USDC voucher"
                )
            for field in (
                "refund_action",
                "refund_bundle_id",
                "terminal_voucher_coin_id",
                "refund_series_input_coin_id",
                "refund_series_output_coin_id",
            ):
                if row[field] is not None:
                    raise ValueError("Base voucher refund is already bound")
            if (
                row["external_settlement_evidence_hash"] is not None
                and row["external_settlement_evidence_hash"]
                != normalized["external_settlement_evidence_hash"]
            ):
                raise ValueError("Base settlement evidence changed")
            if (
                series["chainState"]["currentCoinId"]
                != normalized["refund_series_input_coin_id"]
            ):
                raise ValueError("refund does not spend the current series coin")
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDING', refund_action=?, refund_bundle_id=?,
                    terminal_voucher_coin_id=?,
                    refund_series_input_coin_id=?, refund_series_output_coin_id=?,
                    external_settlement_evidence_hash=?,
                    refund_submitted_at=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REDEEMING'
                """,
                (
                    normalized["refund_action"],
                    normalized["refund_bundle_id"],
                    normalized["terminal_voucher_coin_id"],
                    normalized["refund_series_input_coin_id"],
                    normalized["refund_series_output_coin_id"],
                    normalized["external_settlement_evidence_hash"],
                    now,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("series changed during Base refund submission")
        return self.voucher(series["termsHash"], serial)

    def pending_base_refunds(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT terms_hash, serial FROM voucher_records_v2
            WHERE payment_rail='BASE_SEPOLIA_USDC' AND state='REFUNDING'
              AND refund_bundle_id IS NOT NULL
            ORDER BY refund_submitted_at, terms_hash, serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def record_stripe_refund_submission(
        self,
        terms_hash: str,
        serial: int,
        *,
        action: VoucherAction,
        spend_bundle_id: str,
        external_settlement_evidence_hash: str,
        terminal_voucher_coin_id: str,
        series_input_coin_id: str,
        series_output_coin_id: str,
        vault_input_coin_id: str | None = None,
        vault_output_coin_id: str | None = None,
        execution_observed_at: int,
    ) -> dict[str, Any]:
        """Bind a Stripe refund only after its exact V3 bundle is accepted."""
        series = self.get(terms_hash)
        now = int(time.time())
        owner_authorized = action in {
            VoucherAction.REFUND_PRESALE,
            VoucherAction.REFUND_CANCELED,
        }
        if action == VoucherAction.REFUND_EXPIRED:
            if (
                series["state"] != "LIVE"
                or now < int(series["deliveryDeadline"] or 0)
            ):
                raise ValueError(
                    "Stripe automatic refund requires an expired LIVE series"
                )
            if vault_input_coin_id is not None or vault_output_coin_id is not None:
                raise ValueError("automatic refund cannot carry a vault co-spend")
            expected_state = "REDEEMING"
        elif owner_authorized:
            if vault_input_coin_id is None or vault_output_coin_id is None:
                raise ValueError("owner refund requires exact vault chain bindings")
            expected_state = "REDEEMING" if series["state"] == "LIVE" else "ESCROWED"
        else:
            raise ValueError("Stripe refund action is invalid")
        normalized = {
            "refund_action": int(action),
            "refund_bundle_id": spend_bundle_id.lower(),
            "terminal_voucher_coin_id": terminal_voucher_coin_id.lower(),
            "refund_series_input_coin_id": series_input_coin_id.lower(),
            "refund_series_output_coin_id": series_output_coin_id.lower(),
            "refund_vault_input_coin_id": (
                vault_input_coin_id.lower() if vault_input_coin_id else None
            ),
            "refund_vault_output_coin_id": (
                vault_output_coin_id.lower() if vault_output_coin_id else None
            ),
            "external_settlement_evidence_hash": (
                external_settlement_evidence_hash.lower()
            ),
            "terminal_execution_observed_at": int(execution_observed_at),
        }
        with self.txn() as cur:
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            immutable_fields = {
                field: value
                for field, value in normalized.items()
                if field != "terminal_execution_observed_at"
            }
            exact_retry = row["state"] == "REFUNDING" and all(
                row[field] == value for field, value in immutable_fields.items()
            )
            if exact_retry:
                return self.voucher(series["termsHash"], serial)
            if row["payment_rail"] != "STRIPE_USD" or row["state"] != expected_state:
                raise ValueError(
                    "Stripe refund requires the exact unspent voucher state"
                )
            if not row["terminal_exact_execution_json"]:
                raise ValueError("Stripe refund has no persisted exact KoS execution")
            exact_execution = json.loads(row["terminal_exact_execution_json"])
            if (
                exact_execution.get("prepared", {}).get("spendBundleId", "").lower()
                != normalized["refund_bundle_id"]
            ):
                raise ValueError("Stripe refund bundle differs from its exact KoS binding")
            if any(row[field] is not None for field in normalized):
                raise ValueError("Stripe voucher refund is already bound")
            if (
                series["chainState"]["currentCoinId"]
                != normalized["refund_series_input_coin_id"]
            ):
                raise ValueError("refund does not spend the current series coin")
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDING', refund_action=?, refund_bundle_id=?,
                    terminal_voucher_coin_id=?,
                    refund_series_input_coin_id=?, refund_series_output_coin_id=?,
                    refund_vault_input_coin_id=?, refund_vault_output_coin_id=?,
                    external_settlement_evidence_hash=?,
                    terminal_execution_observed_at=?,
                    refund_submitted_at=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state=?
                """,
                (
                    normalized["refund_action"],
                    normalized["refund_bundle_id"],
                    normalized["terminal_voucher_coin_id"],
                    normalized["refund_series_input_coin_id"],
                    normalized["refund_series_output_coin_id"],
                    normalized["refund_vault_input_coin_id"],
                    normalized["refund_vault_output_coin_id"],
                    normalized["external_settlement_evidence_hash"],
                    normalized["terminal_execution_observed_at"],
                    now,
                    now,
                    series["termsHash"].lower(),
                    serial,
                    expected_state,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("series changed during Stripe refund submission")
        return self.voucher(series["termsHash"], serial)

    def pending_stripe_refunds(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT terms_hash, serial FROM voucher_records_v2
            WHERE payment_rail='STRIPE_USD' AND state='REFUNDING'
              AND refund_bundle_id IS NOT NULL
            ORDER BY refund_submitted_at, terms_hash, serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def confirm_base_refund(
        self,
        terms_hash: str,
        serial: int,
        evidence: BaseVoucherRefundChainEvidence,
    ) -> dict[str, Any]:
        """Record Base refund authorization only after exact Chia confirmation."""
        series = self.get(terms_hash)
        now = int(time.time())
        expected = {
            "refund_action": evidence.action,
            "refund_bundle_id": evidence.spend_bundle_id.lower(),
            "terminal_voucher_coin_id": evidence.terminal_voucher_coin_id.lower(),
            "refund_series_input_coin_id": evidence.series_input_coin_id.lower(),
            "refund_series_output_coin_id": evidence.series_output_coin_id.lower(),
            "external_settlement_evidence_hash": (
                evidence.external_settlement_evidence_hash.lower()
            ),
        }
        with self.txn() as cur:
            chain = cur.execute(
                """
                SELECT current_coin_id, current_inner_puzzle_hash
                FROM presale_series_v2 WHERE terms_hash=?
                """,
                (series["termsHash"].lower(),),
            ).fetchone()
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            if (
                row["payment_rail"] != "BASE_SEPOLIA_USDC"
                or row["state"] != "REFUNDING"
                or any(row[field] != value for field, value in expected.items())
            ):
                raise ValueError(
                    "Base refund evidence differs from submitted chain outputs"
                )
            if (
                chain is None
                or chain["current_coin_id"]
                != expected["refund_series_input_coin_id"]
            ):
                raise ValueError(
                    "Base refund evidence does not spend the current series coin"
                )
            voucher_updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDED', refund_evidence_id=?,
                    refund_confirmed_height=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REFUNDING'
                """,
                (
                    evidence.evidence_id,
                    evidence.confirmed_height,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            series_updated = cur.execute(
                """
                UPDATE presale_series_v2
                SET current_coin_id=?, current_inner_puzzle_hash=?,
                    lineage_parent_name=?, lineage_inner_puzzle_hash=?,
                    refunded_count=refunded_count+1, updated_at=?
                WHERE terms_hash=? AND current_coin_id=? AND state='LIVE'
                """,
                (
                    evidence.series_output_coin_id.lower(),
                    evidence.series_output_inner_puzzle_hash.lower(),
                    evidence.series_input_parent_coin_id.lower(),
                    chain["current_inner_puzzle_hash"],
                    now,
                    series["termsHash"].lower(),
                    evidence.series_input_coin_id.lower(),
                ),
            ).rowcount
            if voucher_updated != 1 or series_updated != 1:
                raise ValueError(
                    "series state changed during Base refund confirmation"
                )
            self._insert_base_settlement_authorization(
                cur,
                series=series,
                voucher=row,
                outcome="REFUND",
                chain_evidence={
                    "chainEvidenceId": evidence.evidence_id,
                    "spendBundleId": evidence.spend_bundle_id.lower(),
                    "confirmedHeight": evidence.confirmed_height,
                    "terminalVoucherCoinId": (
                        evidence.terminal_voucher_coin_id.lower()
                    ),
                    "seriesInputCoinId": evidence.series_input_coin_id.lower(),
                    "seriesInputParentCoinId": (
                        evidence.series_input_parent_coin_id.lower()
                    ),
                    "seriesOutputCoinId": evidence.series_output_coin_id.lower(),
                    "seriesOutputInnerPuzzleHash": (
                        evidence.series_output_inner_puzzle_hash.lower()
                    ),
                    "voucherInputCoinId": row["voucher_output_coin_id"],
                    "externalReceiptInputCoinId": (
                        row["payment_commitment_coin_id"]
                    ),
                },
                now=now,
            )
        return self.voucher(series["termsHash"], serial)

    def confirm_stripe_refund(
        self,
        terms_hash: str,
        serial: int,
        evidence: StripeVoucherRefundChainEvidence,
    ) -> dict[str, Any]:
        """Authorize the exact fiat refund only after V3 terminal confirmation."""
        series = self.get(terms_hash)
        now = int(time.time())
        expected = {
            "refund_action": evidence.action,
            "refund_bundle_id": evidence.spend_bundle_id.lower(),
            "terminal_voucher_coin_id": evidence.terminal_voucher_coin_id.lower(),
            "refund_series_input_coin_id": evidence.series_input_coin_id.lower(),
            "refund_series_output_coin_id": evidence.series_output_coin_id.lower(),
            "refund_vault_input_coin_id": (
                evidence.vault_input_coin_id.lower()
                if evidence.vault_input_coin_id
                else None
            ),
            "refund_vault_output_coin_id": (
                evidence.vault_output_coin_id.lower()
                if evidence.vault_output_coin_id
                else None
            ),
            "external_settlement_evidence_hash": (
                evidence.external_settlement_evidence_hash.lower()
            ),
        }
        owner_authorized = evidence.action in {
            int(VoucherAction.REFUND_PRESALE),
            int(VoucherAction.REFUND_CANCELED),
        }
        if evidence.action == int(VoucherAction.REFUND_EXPIRED):
            if evidence.vault_input_coin_id or evidence.vault_output_coin_id:
                raise ValueError("automatic Stripe refund cannot include a vault")
        elif owner_authorized:
            if not evidence.vault_input_coin_id or not evidence.vault_output_coin_id:
                raise ValueError("owner Stripe refund requires a vault successor")
        else:
            raise ValueError("Stripe refund evidence action is invalid")
        with self.txn() as cur:
            chain = cur.execute(
                """
                SELECT current_coin_id, current_inner_puzzle_hash
                FROM presale_series_v2 WHERE terms_hash=?
                """,
                (series["termsHash"].lower(),),
            ).fetchone()
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            if (
                row["payment_rail"] != "STRIPE_USD"
                or row["state"] != "REFUNDING"
                or any(row[field] != value for field, value in expected.items())
            ):
                raise ValueError(
                    "Stripe refund evidence differs from submitted chain outputs"
                )
            if chain is None or chain["current_coin_id"] != expected[
                "refund_series_input_coin_id"
            ]:
                raise ValueError("Stripe refund does not spend the current series coin")
            receipt_json = json.loads(row["settlement_receipt_json"] or "null")
            if not isinstance(receipt_json, dict):
                raise ValueError("Stripe voucher settlement receipt is missing")
            receipt = stripe_receipt_from_json(receipt_json)
            if (
                _hex32(receipt.artifact.purchase_id) != row["purchase_id"]
                or receipt.evidence.payment_intent_id == ""
                or receipt.evidence.amount_minor != row["payment_principal"]
                or _hex32(receipt.evidence.evidence_hash)
                != expected["external_settlement_evidence_hash"]
            ):
                raise ValueError("Stripe refund receipt commitments changed")
            authorization_body = {
                "schema": STRIPE_REFUND_AUTHORIZATION_SCHEMA,
                "termsHash": series["termsHash"].lower(),
                "serial": serial,
                "purchaseId": row["purchase_id"],
                "purchaseArtifactHash": _hex32(receipt.artifact.artifact_hash),
                "paymentIntentId": receipt.evidence.payment_intent_id,
                "amountMinor": str(receipt.evidence.amount_minor),
                "currency": "usd",
                "globalPaymentId": row["global_payment_id"],
                "terminalBundleId": evidence.spend_bundle_id.lower(),
                "terminalEvidenceHash": (
                    evidence.external_settlement_evidence_hash.lower()
                ),
                "confirmedHeight": evidence.confirmed_height,
            }
            authorization_id = "0x" + hashlib.sha256(
                _json(authorization_body).encode("ascii")
            ).hexdigest()
            authorization = {
                **authorization_body,
                "authorizationId": authorization_id,
            }
            voucher_updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDED', refund_evidence_id=?,
                    refund_confirmed_height=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REFUNDING'
                """,
                (
                    evidence.evidence_id,
                    evidence.confirmed_height,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            series_updated = cur.execute(
                """
                UPDATE presale_series_v2
                SET current_coin_id=?, current_inner_puzzle_hash=?,
                    lineage_parent_name=?, lineage_inner_puzzle_hash=?,
                    refunded_count=refunded_count+1, updated_at=?
                WHERE terms_hash=? AND current_coin_id=?
                """,
                (
                    evidence.series_output_coin_id.lower(),
                    evidence.series_output_inner_puzzle_hash.lower(),
                    evidence.series_input_parent_coin_id.lower(),
                    chain["current_inner_puzzle_hash"],
                    now,
                    series["termsHash"].lower(),
                    evidence.series_input_coin_id.lower(),
                ),
            ).rowcount
            if voucher_updated != 1 or series_updated != 1:
                raise ValueError("series state changed during Stripe refund confirmation")
            cur.execute(
                """
                INSERT INTO stripe_refund_authorizations_v3(
                  authorization_id, terms_hash, serial, purchase_id,
                  authorization_json, state, created_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
                """,
                (
                    authorization_id,
                    series["termsHash"].lower(),
                    serial,
                    row["purchase_id"],
                    _json(authorization),
                    now,
                ),
            )
        return self.voucher(series["termsHash"], serial)

    def pending_stripe_refund_authorizations(
        self,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        rows = self._conn.execute(
            """
            SELECT authorization_json FROM stripe_refund_authorizations_v3
            WHERE state='PENDING' ORDER BY created_at LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [json.loads(row["authorization_json"]) for row in rows]

    def stripe_rehearsal_candidates(
        self,
        *,
        created_after: int,
        vault_launcher_id: str,
        collection_id: str,
    ) -> dict[str, Any]:
        """Project completed production voucher paths into rehearsal evidence."""

        vault_id = _hex32(_b32(vault_launcher_id, nonzero=True))
        collection = _hex32(_b32(collection_id, nonzero=True))
        if created_after < 1:
            raise ValueError("rehearsal start time must be positive")
        rows = self._conn.execute(
            """
            SELECT v.*, r.state AS stripe_refund_state,
                   r.completion_json AS stripe_refund_completion_json
            FROM voucher_records_v2 v
            LEFT JOIN stripe_refund_authorizations_v3 r
              ON r.purchase_id=v.purchase_id
            WHERE v.payment_rail='STRIPE_USD'
              AND v.created_at>=? AND v.vault_launcher_id=?
              AND v.state IN ('REDEEMED','REFUNDED')
            ORDER BY v.updated_at, v.terms_hash, v.serial
            LIMIT 20
            """,
            (created_after, vault_id),
        ).fetchall()
        delivery: list[dict[str, Any]] = []
        refund: list[dict[str, Any]] = []
        for row in rows:
            artifact = json.loads(row["purchase_artifact_json"] or "null")
            if not isinstance(artifact, dict) or artifact.get("collectionId") != collection:
                continue
            lane = _stripe_rehearsal_lane(row, artifact)
            if row["state"] == "REDEEMED":
                if lane["execution"]["mode"] == "REDEEM":
                    delivery.append(lane)
            elif (
                lane["execution"]["mode"] == "REFUND_OWNER"
                and row["stripe_refund_state"] == "COMPLETED"
                and row["stripe_refund_completion_json"]
            ):
                completion = json.loads(row["stripe_refund_completion_json"])
                lane["exactRefund"] = True
                lane["stripeRefund"] = {
                    "refundId": completion["refundId"],
                    "refundedMinor": str(completion["refundedMinor"]),
                    "currency": completion["currency"],
                    "livemode": completion["livemode"],
                    "observedAt": completion["observedAt"],
                }
                refund.append(lane)
        return {
            "schema": "solslot.stripe-voucher-rehearsal-candidates.v1",
            "createdAfter": created_after,
            "vaultLauncherId": vault_id,
            "collectionId": collection,
            "delivery": delivery[:5],
            "refund": refund[:5],
        }

    def complete_stripe_refund_authorization(
        self,
        authorization_id: str,
        completion: StripeRefundCompletionRequest,
    ) -> dict[str, Any]:
        now = int(time.time())
        completion_json = completion.model_dump(by_alias=True)
        with self.txn() as cur:
            row = cur.execute(
                """
                SELECT * FROM stripe_refund_authorizations_v3
                WHERE authorization_id=?
                """,
                (authorization_id.lower(),),
            ).fetchone()
            if row is None:
                raise KeyError(authorization_id)
            authorization = json.loads(row["authorization_json"])
            expected_amount = int(authorization["amountMinor"])
            if (
                completion.payment_intent_id
                != authorization["paymentIntentId"]
                or completion.refunded_minor != expected_amount
                or completion.currency != authorization["currency"]
            ):
                raise ValueError("Stripe refund completion changes the authorization")
            if row["state"] == "COMPLETED":
                if json.loads(row["completion_json"]) != completion_json:
                    raise ValueError("Stripe refund completion evidence changed")
                return {
                    "authorization": authorization,
                    "state": "COMPLETED",
                    "completion": completion_json,
                }
            updated = cur.execute(
                """
                UPDATE stripe_refund_authorizations_v3
                SET state='COMPLETED', completed_at=?, completion_json=?
                WHERE authorization_id=? AND state='PENDING'
                """,
                (now, _json(completion_json), authorization_id.lower()),
            ).rowcount
            if updated != 1:
                raise ValueError("Stripe refund authorization changed")
        return {
            "authorization": authorization,
            "state": "COMPLETED",
            "completion": completion_json,
        }

    def confirm_native_refund(
        self,
        terms_hash: str,
        serial: int,
        evidence: VoucherRefundChainEvidence,
    ) -> dict[str, Any]:
        """Advance store state only after exact atomic chain confirmation."""
        series = self.get(terms_hash)
        now = int(time.time())
        expected = {
            "refund_action": evidence.action,
            "refund_bundle_id": evidence.spend_bundle_id.lower(),
            "refund_output_coin_id": evidence.refund_output_coin_id.lower(),
            "terminal_voucher_coin_id": evidence.terminal_voucher_coin_id.lower(),
            "refund_series_input_coin_id": evidence.series_input_coin_id.lower(),
            "refund_series_output_coin_id": evidence.series_output_coin_id.lower(),
            "refund_vault_input_coin_id": (
                evidence.vault_input_coin_id.lower()
                if evidence.vault_input_coin_id
                else None
            ),
            "refund_vault_output_coin_id": (
                evidence.vault_output_coin_id.lower()
                if evidence.vault_output_coin_id
                else None
            ),
        }
        if evidence.action == int(VoucherAction.REFUND_EXPIRED):
            if (
                evidence.vault_input_coin_id is not None
                or evidence.vault_output_coin_id is not None
            ):
                raise ValueError("automatic refund evidence cannot include a vault")
        elif evidence.action in {
            int(VoucherAction.REFUND_PRESALE),
            int(VoucherAction.REFUND_CANCELED),
        }:
            if (
                evidence.vault_input_coin_id is None
                or evidence.vault_output_coin_id is None
            ):
                raise ValueError("owner refund evidence requires a vault successor")
        else:
            raise ValueError("refund evidence action is invalid")
        with self.txn() as cur:
            chain = cur.execute(
                """
                SELECT current_coin_id, current_inner_puzzle_hash
                FROM presale_series_v2 WHERE terms_hash=?
                """,
                (series["termsHash"].lower(),),
            ).fetchone()
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            if row["state"] != "REFUNDING" or any(
                row[field] != value for field, value in expected.items()
            ):
                raise ValueError("refund evidence differs from submitted chain outputs")
            if chain is None or chain["current_coin_id"] != expected[
                "refund_series_input_coin_id"
            ]:
                raise ValueError("refund evidence does not spend the current series coin")
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDED', refund_evidence_id=?,
                    refund_confirmed_height=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REFUNDING'
                """,
                (
                    evidence.evidence_id,
                    evidence.confirmed_height,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            series_updated = cur.execute(
                """
                UPDATE presale_series_v2
                SET current_coin_id=?, current_inner_puzzle_hash=?,
                    lineage_parent_name=?, lineage_inner_puzzle_hash=?,
                    refunded_count=refunded_count+1, updated_at=?
                WHERE terms_hash=? AND current_coin_id=?
                """,
                (
                    evidence.series_output_coin_id.lower(),
                    evidence.series_output_inner_puzzle_hash.lower(),
                    evidence.series_input_parent_coin_id.lower(),
                    chain["current_inner_puzzle_hash"],
                    now,
                    series["termsHash"].lower(),
                    evidence.series_input_coin_id.lower(),
                ),
            ).rowcount
            if updated != 1 or series_updated != 1:
                raise ValueError("series state changed during refund confirmation")
        return self.voucher(series["termsHash"], serial)

    def pending_native_redemptions(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT v.terms_hash, v.serial FROM voucher_records_v2 v
            JOIN presale_series_v2 s ON s.terms_hash=v.terms_hash
            WHERE v.payment_rail='CHIA_XCH' AND v.state='REDEEMING'
              AND s.state='LIVE' AND s.phase_confirmed_height IS NOT NULL
            ORDER BY v.created_at, v.terms_hash, v.serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def pending_base_redemptions(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT v.terms_hash, v.serial FROM voucher_records_v2 v
            JOIN presale_series_v2 s ON s.terms_hash=v.terms_hash
            WHERE v.payment_rail='BASE_SEPOLIA_USDC' AND v.state='REDEEMING'
              AND s.state='LIVE' AND s.phase_confirmed_height IS NOT NULL
            ORDER BY v.created_at, v.terms_hash, v.serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def pending_stripe_redemptions(
        self,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        rows = self._conn.execute(
            """
            SELECT v.terms_hash, v.serial FROM voucher_records_v2 v
            JOIN presale_series_v2 s ON s.terms_hash=v.terms_hash
            WHERE v.payment_rail='STRIPE_USD' AND v.state='REDEEMING'
              AND s.state='LIVE' AND s.phase_confirmed_height IS NOT NULL
            ORDER BY v.created_at, v.terms_hash, v.serial
            """
        ).fetchall()
        return [
            (
                self._get_series(row["terms_hash"]),
                self.voucher(row["terms_hash"], row["serial"]),
            )
            for row in rows
        ]

    def record_redemption_submission(
        self,
        terms_hash: str,
        serial: int,
        *,
        spend_bundle_id: str,
        treasury_output_coin_id: str,
        deed_output_coin_id: str,
        terminal_voucher_coin_id: str,
        series_input_coin_id: str,
        series_output_coin_id: str,
        deed_input_coin_id: str,
        external_settlement_evidence_hash: str | None = None,
        execution_observed_at: int | None = None,
    ) -> dict[str, Any]:
        """Bind one accepted atomic voucher-to-SmartDeed settlement."""
        series = self.get(terms_hash)
        if series["state"] != "LIVE":
            raise ValueError("native redemption requires a LIVE series")
        now = int(time.time())
        normalized = {
            "redemption_bundle_id": spend_bundle_id.lower(),
            "redemption_treasury_output_coin_id": treasury_output_coin_id.lower(),
            "redemption_deed_output_coin_id": deed_output_coin_id.lower(),
            "redemption_terminal_voucher_coin_id": terminal_voucher_coin_id.lower(),
            "redemption_series_input_coin_id": series_input_coin_id.lower(),
            "redemption_series_output_coin_id": series_output_coin_id.lower(),
            "redemption_deed_input_coin_id": deed_input_coin_id.lower(),
            "external_settlement_evidence_hash": (
                external_settlement_evidence_hash.lower()
                if external_settlement_evidence_hash
                else None
            ),
            "terminal_execution_observed_at": (
                int(execution_observed_at)
                if execution_observed_at is not None
                else None
            ),
        }
        with self.txn() as cur:
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            immutable_fields = {
                field: value
                for field, value in normalized.items()
                if field != "terminal_execution_observed_at"
            }
            exact_retry = row["state"] == "REDEEMING" and all(
                row[field] == value for field, value in immutable_fields.items()
            )
            if exact_retry:
                return self.voucher(series["termsHash"], serial)
            if row["state"] != "REDEEMING":
                raise ValueError("redemption requires a REDEEMING voucher")
            if row["payment_rail"] == "CHIA_XCH":
                if external_settlement_evidence_hash is not None:
                    raise ValueError(
                        "native redemption cannot carry external settlement evidence"
                    )
            elif row["payment_rail"] in {
                "BASE_SEPOLIA_USDC",
                "STRIPE_USD",
            }:
                if external_settlement_evidence_hash is None:
                    raise ValueError(
                        "external redemption requires settlement evidence"
                    )
                if row["payment_rail"] == "STRIPE_USD":
                    if execution_observed_at is None:
                        raise ValueError(
                            "Stripe redemption requires KoS execution observation"
                        )
                    if not row["terminal_exact_execution_json"]:
                        raise ValueError(
                            "Stripe redemption has no persisted exact KoS execution"
                        )
                    exact_execution = json.loads(
                        row["terminal_exact_execution_json"]
                    )
                    if (
                        exact_execution.get("prepared", {}).get(
                            "spendBundleId", ""
                        ).lower()
                        != normalized["redemption_bundle_id"]
                    ):
                        raise ValueError(
                            "Stripe redemption bundle differs from its exact KoS binding"
                        )
            else:
                raise ValueError("voucher redemption rail is unsupported")
            if any(row[field] is not None for field in normalized):
                raise ValueError("voucher redemption is already bound")
            if (
                series["chainState"]["currentCoinId"]
                != normalized["redemption_series_input_coin_id"]
            ):
                raise ValueError("redemption does not spend the current series coin")
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET redemption_bundle_id=?,
                    redemption_treasury_output_coin_id=?,
                    redemption_deed_output_coin_id=?,
                    redemption_terminal_voucher_coin_id=?,
                    redemption_series_input_coin_id=?,
                    redemption_series_output_coin_id=?,
                    redemption_deed_input_coin_id=?,
                    external_settlement_evidence_hash=?,
                    terminal_execution_observed_at=?,
                    redemption_submitted_at=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REDEEMING'
                """,
                (
                    normalized["redemption_bundle_id"],
                    normalized["redemption_treasury_output_coin_id"],
                    normalized["redemption_deed_output_coin_id"],
                    normalized["redemption_terminal_voucher_coin_id"],
                    normalized["redemption_series_input_coin_id"],
                    normalized["redemption_series_output_coin_id"],
                    normalized["redemption_deed_input_coin_id"],
                    normalized["external_settlement_evidence_hash"],
                    normalized["terminal_execution_observed_at"],
                    now,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("series changed during redemption submission")
        return self.voucher(series["termsHash"], serial)

    def confirm_redemption(
        self,
        terms_hash: str,
        serial: int,
        evidence: VoucherRedemptionChainEvidence,
    ) -> dict[str, Any]:
        """Mark delivery only after every committed input/output confirms atomically."""
        series = self.get(terms_hash)
        now = int(time.time())
        expected = {
            "redemption_bundle_id": evidence.spend_bundle_id.lower(),
            "redemption_treasury_output_coin_id": (
                evidence.treasury_output_coin_id.lower()
            ),
            "redemption_deed_output_coin_id": evidence.deed_output_coin_id.lower(),
            "redemption_terminal_voucher_coin_id": (
                evidence.terminal_voucher_coin_id.lower()
            ),
            "redemption_series_input_coin_id": evidence.series_input_coin_id.lower(),
            "redemption_series_output_coin_id": evidence.series_output_coin_id.lower(),
            "redemption_deed_input_coin_id": evidence.deed_input_coin_id.lower(),
            "external_settlement_evidence_hash": (
                evidence.external_settlement_evidence_hash.lower()
                if evidence.external_settlement_evidence_hash
                else None
            ),
        }
        with self.txn() as cur:
            chain = cur.execute(
                """
                SELECT current_coin_id, current_inner_puzzle_hash
                FROM presale_series_v2 WHERE terms_hash=?
                """,
                (series["termsHash"].lower(),),
            ).fetchone()
            row = cur.execute(
                "SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?",
                (series["termsHash"].lower(), serial),
            ).fetchone()
            if row is None:
                raise KeyError(serial)
            if (
                row["payment_rail"] == "CHIA_XCH"
                and evidence.external_settlement_evidence_hash is not None
            ) or (
                row["payment_rail"]
                in {"BASE_SEPOLIA_USDC", "STRIPE_USD"}
                and evidence.external_settlement_evidence_hash is None
            ):
                raise ValueError(
                    "redemption evidence does not match its payment rail"
                )
            if row["state"] != "REDEEMING" or any(
                row[field] != value for field, value in expected.items()
            ):
                raise ValueError(
                    "redemption evidence differs from submitted chain outputs"
                )
            if chain is None or chain["current_coin_id"] != expected[
                "redemption_series_input_coin_id"
            ]:
                raise ValueError(
                    "redemption evidence does not spend the current series coin"
                )
            voucher_updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REDEEMED', delivery_evidence_id=?,
                    delivery_output_coin_id=?, redemption_confirmed_height=?,
                    updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REDEEMING'
                """,
                (
                    evidence.evidence_id,
                    evidence.deed_output_coin_id.lower(),
                    evidence.confirmed_height,
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            ).rowcount
            series_updated = cur.execute(
                """
                UPDATE presale_series_v2
                SET current_coin_id=?, current_inner_puzzle_hash=?,
                    lineage_parent_name=?, lineage_inner_puzzle_hash=?,
                    redeemed_count=redeemed_count+1, updated_at=?
                WHERE terms_hash=? AND current_coin_id=? AND state='LIVE'
                """,
                (
                    evidence.series_output_coin_id.lower(),
                    evidence.series_output_inner_puzzle_hash.lower(),
                    evidence.series_input_parent_coin_id.lower(),
                    chain["current_inner_puzzle_hash"],
                    now,
                    series["termsHash"].lower(),
                    evidence.series_input_coin_id.lower(),
                ),
            ).rowcount
            if voucher_updated != 1 or series_updated != 1:
                raise ValueError("series state changed during redemption confirmation")
            if row["payment_rail"] == "BASE_SEPOLIA_USDC":
                self._insert_base_settlement_authorization(
                    cur,
                    series=series,
                    voucher=row,
                    outcome="DELIVERED",
                    chain_evidence={
                        "chainEvidenceId": evidence.evidence_id,
                        "spendBundleId": evidence.spend_bundle_id.lower(),
                        "confirmedHeight": evidence.confirmed_height,
                        "terminalVoucherCoinId": (
                            evidence.terminal_voucher_coin_id.lower()
                        ),
                        "seriesInputCoinId": (
                            evidence.series_input_coin_id.lower()
                        ),
                        "seriesInputParentCoinId": (
                            evidence.series_input_parent_coin_id.lower()
                        ),
                        "seriesOutputCoinId": (
                            evidence.series_output_coin_id.lower()
                        ),
                        "seriesOutputInnerPuzzleHash": (
                            evidence.series_output_inner_puzzle_hash.lower()
                        ),
                        "voucherInputCoinId": row["voucher_output_coin_id"],
                        "externalReceiptInputCoinId": (
                            row["payment_commitment_coin_id"]
                        ),
                        "deedInputCoinId": evidence.deed_input_coin_id.lower(),
                        "deedOutputCoinId": evidence.deed_output_coin_id.lower(),
                        "treasuryOutputCoinId": (
                            evidence.treasury_output_coin_id.lower()
                        ),
                    },
                    now=now,
                )
        return self.voucher(series["termsHash"], serial)

    def _insert_base_settlement_authorization(
        self,
        cur: sqlite3.Cursor,
        *,
        series: dict[str, Any],
        voucher: sqlite3.Row,
        outcome: Literal["DELIVERED", "REFUND"],
        chain_evidence: dict[str, Any],
        now: int,
    ) -> None:
        if voucher["payment_rail"] != "BASE_SEPOLIA_USDC":
            raise ValueError(
                "only Base Sepolia USDC vouchers have external settlement authorization"
            )
        commitment = json.loads(voucher["commitment_json"])
        voucher_commitment_hash = _hex32(
            voucher_commitment_from_json(commitment).commitment_hash
        )
        payload = {
            "schema": BASE_SETTLEMENT_AUTHORIZATION_SCHEMA,
            "outcome": outcome,
            "globalPaymentId": voucher["global_payment_id"],
            "purchaseId": voucher["purchase_id"],
            "purchaseArtifactHash": commitment["purchaseArtifactHash"],
            "voucherCommitmentHash": voucher_commitment_hash,
            "termsHash": series["termsHash"],
            "seriesSingletonId": series["seriesSingletonId"],
            "collectionId": commitment["collectionId"],
            "metadataRoot": commitment["metadataRoot"],
            "allocationRoot": commitment["allocationRoot"],
            "serial": voucher["serial"],
            "voucherLauncherId": voucher["voucher_launcher_id"],
            "deedLauncherId": voucher["deed_launcher_id"],
            "vaultLauncherId": voucher["vault_launcher_id"],
            "vaultP2PuzzleHash": voucher["vault_p2_puzzle_hash"],
            "originalPayer": voucher["original_payer"],
            "payment": {
                "rail": "BASE_SEPOLIA_USDC",
                "chainId": commitment["paymentChainId"],
                "assetId": commitment["paymentAssetId"],
                "assetDecimals": commitment["paymentAssetDecimals"],
                "escrowContract": commitment["externalEscrowContract"],
                "principal": voucher["payment_principal"],
                "evidenceHash": voucher[
                    "external_settlement_evidence_hash"
                ],
            },
            "chia": chain_evidence,
        }
        authorization_hash = "0x" + hashlib.sha256(
            _json(payload).encode("utf-8")
        ).hexdigest()
        existing = cur.execute(
            """
            SELECT authorization_hash, authorization_json
            FROM base_settlement_authorizations_v2
            WHERE global_payment_id=?
            """,
            (voucher["global_payment_id"],),
        ).fetchone()
        if existing is not None:
            if (
                existing["authorization_hash"] != authorization_hash
                or existing["authorization_json"] != _json(payload)
            ):
                raise ValueError(
                    "Base payment is already bound to different settlement evidence"
                )
            return
        cur.execute(
            """
            INSERT INTO base_settlement_authorizations_v2(
              authorization_id, global_payment_id, terms_hash, serial,
              outcome, authorization_hash, authorization_json, state, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
            """,
            (
                authorization_hash,
                voucher["global_payment_id"],
                series["termsHash"].lower(),
                voucher["serial"],
                outcome,
                authorization_hash,
                _json(payload),
                now,
            ),
        )

    def pending_base_settlement_authorizations(
        self,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise ValueError("settlement authorization limit must be 1 through 500")
        rows = self._conn.execute(
            """
            SELECT * FROM base_settlement_authorizations_v2
            WHERE state='PENDING'
            ORDER BY created_at, authorization_id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [self._render_base_settlement_authorization(row) for row in rows]

    def base_settlement_authorization(
        self,
        authorization_id: str,
    ) -> dict[str, Any]:
        row = self._conn.execute(
            """
            SELECT * FROM base_settlement_authorizations_v2
            WHERE authorization_id=?
            """,
            (authorization_id.lower(),),
        ).fetchone()
        if row is None:
            raise KeyError(authorization_id)
        return self._render_base_settlement_authorization(row)

    def base_settlement_authorization_by_payment(
        self,
        global_payment_id: str,
    ) -> dict[str, Any]:
        row = self._conn.execute(
            """
            SELECT * FROM base_settlement_authorizations_v2
            WHERE global_payment_id=?
            """,
            (global_payment_id.lower(),),
        ).fetchone()
        if row is None:
            raise KeyError(global_payment_id)
        return self._render_base_settlement_authorization(row)

    def record_base_settlement_relay_evidence(
        self,
        authorization_id: str,
        evidence: BaseSettlementRelayEvidenceRequest,
    ) -> dict[str, Any]:
        normalized_id = authorization_id.lower()
        evidence_json = _json(evidence.model_dump(by_alias=True))
        now = int(time.time())
        with self.txn() as cur:
            row = cur.execute(
                """
                SELECT state, relay_evidence_json
                FROM base_settlement_authorizations_v2
                WHERE authorization_id=?
                """,
                (normalized_id,),
            ).fetchone()
            if row is None:
                raise KeyError(authorization_id)
            if row["state"] == "RELAYED":
                if row["relay_evidence_json"] != evidence_json:
                    raise ValueError(
                        "settlement authorization has different relay evidence"
                    )
                return self.base_settlement_authorization(normalized_id)
            updated = cur.execute(
                """
                UPDATE base_settlement_authorizations_v2
                SET state='RELAYED', relayed_at=?, relay_evidence_json=?
                WHERE authorization_id=? AND state='PENDING'
                """,
                (now, evidence_json, normalized_id),
            ).rowcount
            if updated != 1:
                raise ValueError(
                    "settlement authorization changed during relay acknowledgement"
                )
        return self.base_settlement_authorization(normalized_id)

    def _render_base_settlement_authorization(
        self,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        authorization = json.loads(row["authorization_json"])
        expected_hash = "0x" + hashlib.sha256(
            _json(authorization).encode("utf-8")
        ).hexdigest()
        if (
            row["authorization_id"] != expected_hash
            or row["authorization_hash"] != expected_hash
        ):
            raise ValueError("stored Base settlement authorization is corrupt")
        return {
            "authorizationId": row["authorization_id"],
            "authorizationHash": row["authorization_hash"],
            "state": row["state"],
            "authorization": authorization,
            "createdAt": row["created_at"],
            "relayedAt": row["relayed_at"],
            "relayEvidence": (
                json.loads(row["relay_evidence_json"])
                if row["relay_evidence_json"]
                else None
            ),
        }

    def complete_refund(
        self, terms_hash: str, serial: int, evidence: RefundEvidenceRequest
    ) -> dict[str, Any]:
        series = self.get(terms_hash)
        voucher = self.voucher(series["termsHash"], serial)
        if voucher["paymentRail"] in {
            "CHIA_XCH",
            "BASE_SEPOLIA_USDC",
            "STRIPE_USD",
        }:
            raise ValueError(
                "voucher refund requires exact atomic Chia confirmation"
            )
        if (
            voucher["originalPayer"] != evidence.refund_destination.lower()
            or voucher["paymentPrincipal"] != evidence.refund_amount
        ):
            raise ValueError("refund evidence changes the committed payer or principal")
        now = int(time.time())
        with self.txn() as cur:
            updated = cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REFUNDED', refund_evidence_id=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REFUNDING'
                """,
                (evidence.evidence_id, now, series["termsHash"].lower(), serial),
            ).rowcount
            if updated != 1:
                raise ValueError("refund evidence requires REFUNDING state")
        return self.voucher(series["termsHash"], serial)

    def record_phase_submission(
        self,
        terms_hash: str,
        *,
        target_state: Literal["LIVE", "CANCELED"],
        spend_bundle_id: str,
        series_input_coin_id: str,
        series_output_coin_id: str,
        series_output_inner_puzzle_hash: str,
        launch_anchor: int,
        governance_execution_ids: list[str],
        cancel_reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """Bind an accepted phase spend without claiming chain confirmation."""
        series = self.get(terms_hash)
        if series["state"] != "PRESALE":
            raise ValueError("only a PRESALE series can change phase")
        normalized = {
            "phase_target_state": target_state,
            "phase_bundle_id": spend_bundle_id.lower(),
            "phase_input_coin_id": series_input_coin_id.lower(),
            "phase_output_coin_id": series_output_coin_id.lower(),
            "phase_output_inner_puzzle_hash": series_output_inner_puzzle_hash.lower(),
            "phase_launch_anchor": launch_anchor,
            "phase_governance_execution_ids_json": _json(
                [item.lower() for item in governance_execution_ids]
            ),
        }
        if target_state == "LIVE" and launch_anchor <= 0:
            raise ValueError("LIVE phase submission requires a launch anchor")
        if target_state == "CANCELED" and (
            launch_anchor != 0 or governance_execution_ids
        ):
            raise ValueError("CANCELED phase submission cannot carry launch evidence")
        if series["chainState"]["currentCoinId"] != normalized[
            "phase_input_coin_id"
        ]:
            raise ValueError("phase submission does not spend the current series coin")
        now = int(time.time())
        with self.txn() as cur:
            row = cur.execute(
                "SELECT * FROM presale_series_v2 WHERE terms_hash=?",
                (series["termsHash"].lower(),),
            ).fetchone()
            if row is None:
                raise KeyError(terms_hash)
            exact_retry = row["phase_bundle_id"] is not None and all(
                row[field] == value for field, value in normalized.items()
            )
            if exact_retry:
                return self.get(series["termsHash"])
            if row["phase_bundle_id"] is not None:
                raise ValueError("series phase transition is already bound")
            cur.execute(
                """
                UPDATE presale_series_v2 SET
                    phase_target_state=?, phase_bundle_id=?,
                    phase_input_coin_id=?, phase_output_coin_id=?,
                    phase_output_inner_puzzle_hash=?, phase_launch_anchor=?,
                    phase_governance_execution_ids_json=?, cancel_reason=?,
                    phase_submitted_at=?, updated_at=?
                WHERE terms_hash=? AND state='PRESALE' AND phase_bundle_id IS NULL
                """,
                (
                    normalized["phase_target_state"],
                    normalized["phase_bundle_id"],
                    normalized["phase_input_coin_id"],
                    normalized["phase_output_coin_id"],
                    normalized["phase_output_inner_puzzle_hash"],
                    normalized["phase_launch_anchor"],
                    normalized["phase_governance_execution_ids_json"],
                    cancel_reason,
                    now,
                    now,
                    series["termsHash"].lower(),
                ),
            )
        return self.get(series["termsHash"])

    def pending_phase_transitions(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT terms_hash FROM presale_series_v2
            WHERE state='PRESALE' AND phase_bundle_id IS NOT NULL
              AND phase_confirmed_height IS NULL
            ORDER BY phase_submitted_at, terms_hash
            """
        ).fetchall()
        return [self.get(row["terms_hash"]) for row in rows]

    def confirm_phase_transition(
        self,
        terms_hash: str,
        evidence: VoucherSeriesPhaseChainEvidence,
    ) -> dict[str, Any]:
        """Advance local phase only after exact singleton chain confirmation."""
        series = self.get(terms_hash)
        now = int(time.time())
        with self.txn() as cur:
            row = cur.execute(
                "SELECT * FROM presale_series_v2 WHERE terms_hash=?",
                (series["termsHash"].lower(),),
            ).fetchone()
            if row is None:
                raise KeyError(terms_hash)
            expected = {
                "phase_target_state": evidence.target_state,
                "phase_bundle_id": evidence.spend_bundle_id.lower(),
                "phase_input_coin_id": evidence.series_input_coin_id.lower(),
                "phase_output_coin_id": evidence.series_output_coin_id.lower(),
                "phase_output_inner_puzzle_hash": (
                    evidence.series_output_inner_puzzle_hash.lower()
                ),
                "phase_launch_anchor": evidence.launch_anchor,
            }
            if row["state"] != "PRESALE" or any(
                row[field] != value for field, value in expected.items()
            ):
                raise ValueError("phase confirmation differs from submitted transition")
            if row["current_coin_id"] != evidence.series_input_coin_id.lower():
                raise ValueError("phase confirmation does not spend current series coin")
            governance_ids = json.loads(
                row["phase_governance_execution_ids_json"] or "[]"
            )
            governance_id = (
                "0x"
                + hashlib.sha256(
                    _json(governance_ids).encode("ascii")
                ).hexdigest()
                if governance_ids
                else None
            )
            updated = cur.execute(
                """
                UPDATE presale_series_v2 SET state=?, launched_at=?,
                    launch_evidence_id=?, governance_execution_id=?,
                    current_coin_id=?, current_inner_puzzle_hash=?,
                    lineage_parent_name=?, lineage_inner_puzzle_hash=?,
                    phase_confirmed_height=?, updated_at=?
                WHERE terms_hash=? AND state='PRESALE'
                  AND current_coin_id=? AND phase_bundle_id=?
                """,
                (
                    evidence.target_state,
                    evidence.launch_anchor if evidence.target_state == "LIVE" else None,
                    evidence.evidence_id,
                    governance_id,
                    evidence.series_output_coin_id.lower(),
                    evidence.series_output_inner_puzzle_hash.lower(),
                    evidence.series_input_parent_coin_id.lower(),
                    row["current_inner_puzzle_hash"],
                    evidence.confirmed_height,
                    now,
                    series["termsHash"].lower(),
                    evidence.series_input_coin_id.lower(),
                    evidence.spend_bundle_id.lower(),
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("series state changed during phase confirmation")
            if evidence.target_state == "LIVE":
                cur.execute(
                    """
                    UPDATE voucher_records_v2 SET state='REDEEMING', updated_at=?
                    WHERE terms_hash=? AND state='ESCROWED'
                    """,
                    (now, series["termsHash"].lower()),
                )
        return self.get(series["termsHash"])

    def complete_delivery(
        self, terms_hash: str, serial: int, evidence: DeliveryEvidenceRequest
    ) -> dict[str, Any]:
        series = self.get(terms_hash)
        voucher = self.voucher(series["termsHash"], serial)
        if voucher["paymentRail"] in {
            "CHIA_XCH",
            "BASE_SEPOLIA_USDC",
            "STRIPE_USD",
        }:
            raise ValueError(
                "voucher delivery requires exact atomic Chia confirmation"
            )
        if voucher["state"] != "REDEEMING":
            raise ValueError("delivery evidence requires REDEEMING state")
        if (
            voucher["deedLauncherId"] != evidence.deed_launcher_id.lower()
            or voucher["vaultP2PuzzleHash"] != evidence.vault_p2_puzzle_hash.lower()
        ):
            raise ValueError("delivery evidence changes the committed deed or vault")
        now = int(time.time())
        with self.txn() as cur:
            cur.execute(
                """
                UPDATE voucher_records_v2
                SET state='REDEEMED', delivery_evidence_id=?,
                    delivery_output_coin_id=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state='REDEEMING'
                """,
                (
                    evidence.evidence_id,
                    evidence.output_coin_id.lower(),
                    now,
                    series["termsHash"].lower(),
                    serial,
                ),
            )
        return self.voucher(series["termsHash"], serial)

    def reconcile(self, now_seconds: Optional[int] = None) -> list[dict[str, Any]]:
        """Report deterministic deadlines; never mirror a phase without chain proof."""
        now = int(now_seconds or time.time())
        changed: list[dict[str, Any]] = []
        rows = self._conn.execute(
            "SELECT * FROM presale_series_v2 WHERE state IN ('PRESALE','LIVE')"
        ).fetchall()
        for row in rows:
            terms = json.loads(row["terms_json"])
            if row["state"] == "PRESALE" and now >= int(terms["launchDeadline"]):
                changed.append(
                    {"termsHash": row["terms_hash"], "reason": "CANCEL_SPEND_REQUIRED"}
                )
            elif (
                row["state"] == "LIVE"
                and row["launched_at"] is not None
                and now >= int(row["launched_at"]) + DELIVERY_WINDOW_SECONDS
            ):
                count = self._conn.execute(
                    """
                    SELECT COUNT(*) FROM voucher_records_v2
                    WHERE terms_hash=? AND state='REDEEMING'
                    """,
                    (row["terms_hash"],),
                ).fetchone()[0]
                if count:
                    changed.append(
                        {
                            "termsHash": row["terms_hash"],
                            "reason": "EXPIRED_REFUND_SPENDS_REQUIRED",
                            "voucherCount": count,
                        }
                    )
        return changed

    def _set_voucher_state(
        self, terms_hash: str, serial: int, *, expected: str, new: str
    ) -> None:
        now = int(time.time())
        with self.txn() as cur:
            count = cur.execute(
                """
                UPDATE voucher_records_v2 SET state=?, updated_at=?
                WHERE terms_hash=? AND serial=? AND state=?
                """,
                (new, now, terms_hash.lower(), serial, expected),
            ).rowcount
            if count != 1:
                raise ValueError(f"voucher transition requires {expected} state")

    def _render_series(self, row: sqlite3.Row) -> dict[str, Any]:
        terms = json.loads(row["terms_json"])
        deadline = (
            int(row["launched_at"]) + DELIVERY_WINDOW_SECONDS
            if row["launched_at"] is not None
            else None
        )
        return {
            "schema": SERIES_SCHEMA,
            "termsHash": row["terms_hash"],
            "seriesSingletonId": row["series_singleton_id"],
            "collectionId": row["collection_id"],
            "state": row["state"],
            "terms": terms,
            "launchedAt": row["launched_at"],
            "deliveryDeadline": deadline,
            "launchEvidenceId": row["launch_evidence_id"],
            "governanceExecutionId": row["governance_execution_id"],
            "cancelReason": row["cancel_reason"],
            "phaseTransition": {
                "targetState": row["phase_target_state"],
                "spendBundleId": row["phase_bundle_id"],
                "inputCoinId": row["phase_input_coin_id"],
                "outputCoinId": row["phase_output_coin_id"],
                "outputInnerPuzzleHash": row[
                    "phase_output_inner_puzzle_hash"
                ],
                "launchAnchor": row["phase_launch_anchor"],
                "governanceExecutionIds": json.loads(
                    row["phase_governance_execution_ids_json"] or "[]"
                ),
                "submittedAt": row["phase_submitted_at"],
                "confirmedHeight": row["phase_confirmed_height"],
                "status": (
                    "CONFIRMED"
                    if row["phase_confirmed_height"] is not None
                    else "MEMPOOL_ACCEPTED"
                    if row["phase_bundle_id"]
                    else "NOT_SUBMITTED"
                ),
            },
            "singletonLaunch": {
                "parentCoinId": row["singleton_parent_coin_id"],
                "fullPuzzleHash": row["singleton_full_puzzle_hash"],
                "spendBundleId": row["singleton_launch_bundle_id"],
                "status": (
                    "MEMPOOL_ACCEPTED"
                    if row["singleton_launch_bundle_id"]
                    else "LEGACY_TEST_FIXTURE"
                ),
            },
            "chainState": {
                "currentCoinId": row["current_coin_id"],
                "currentInnerPuzzleHash": row["current_inner_puzzle_hash"],
                "lineageParentName": row["lineage_parent_name"],
                "lineageInnerPuzzleHash": row["lineage_inner_puzzle_hash"],
                "soldCount": row["sold_count"],
                "redeemedCount": row["redeemed_count"],
                "refundedCount": row["refunded_count"],
            },
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _render_voucher(
        self, row: sqlite3.Row, series: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "serial": row["serial"],
            "deedLauncherId": row["deed_launcher_id"],
            "paymentRail": row["payment_rail"],
            "paymentPrincipal": row["payment_principal"],
            "basePriceMinor": row["base_price_minor"],
            "technologyFeeBps": row["technology_fee_bps"],
            "technologyFeeMinor": row["technology_fee_minor"],
            "grossPriceMinor": row["gross_price_minor"],
            "processingChargeMinor": row["processing_charge_minor"] or 0,
            "originalPayer": row["original_payer"],
            "vaultLauncherId": row["vault_launcher_id"],
            "vaultP2PuzzleHash": row["vault_p2_puzzle_hash"],
            "purchaseId": row["purchase_id"],
            "globalPaymentId": row["global_payment_id"],
            "commitmentHash": row["commitment_hash"],
            "commitment": json.loads(row["commitment_json"]),
            "purchaseArtifact": (
                json.loads(row["purchase_artifact_json"])
                if row["purchase_artifact_json"]
                else None
            ),
            "settlementReceipt": (
                json.loads(row["settlement_receipt_json"])
                if row["settlement_receipt_json"]
                else None
            ),
            "state": row["state"],
            "paymentEvidenceId": row["payment_evidence_id"],
            "issuanceEvidenceId": row["issuance_evidence_id"],
            "issuanceBundleId": row["issuance_bundle_id"],
            "issuanceSignerIndices": (
                json.loads(row["issuance_signer_indices_json"])
                if row["issuance_signer_indices_json"]
                else []
            ),
            "fundingBundleId": row["funding_bundle_id"],
            "purchaseLauncherCoinId": row["purchase_launcher_coin_id"],
            "purchaseLauncherPuzzleHash": row["purchase_launcher_puzzle_hash"],
            "voucherLauncherId": row["voucher_launcher_id"],
            "voucherOutputCoinId": row["voucher_output_coin_id"],
            "paymentCommitmentCoinId": row["payment_commitment_coin_id"],
            "seriesInputCoinId": row["series_input_coin_id"],
            "seriesOutputCoinId": row["series_output_coin_id"],
            "issuanceConfirmedHeight": row["issuance_confirmed_height"],
            "refundEvidenceId": row["refund_evidence_id"],
            "refundAction": row["refund_action"],
            "refundBundleId": row["refund_bundle_id"],
            "refundOutputCoinId": row["refund_output_coin_id"],
            "terminalVoucherCoinId": row["terminal_voucher_coin_id"],
            "refundSeriesInputCoinId": row["refund_series_input_coin_id"],
            "refundSeriesOutputCoinId": row["refund_series_output_coin_id"],
            "refundVaultInputCoinId": row["refund_vault_input_coin_id"],
            "refundVaultOutputCoinId": row["refund_vault_output_coin_id"],
            "refundSubmittedAt": row["refund_submitted_at"],
            "refundConfirmedHeight": row["refund_confirmed_height"],
            "redemptionBundleId": row["redemption_bundle_id"],
            "redemptionTreasuryOutputCoinId": row[
                "redemption_treasury_output_coin_id"
            ],
            "redemptionDeedOutputCoinId": row[
                "redemption_deed_output_coin_id"
            ],
            "redemptionTerminalVoucherCoinId": row[
                "redemption_terminal_voucher_coin_id"
            ],
            "redemptionSeriesInputCoinId": row[
                "redemption_series_input_coin_id"
            ],
            "redemptionSeriesOutputCoinId": row[
                "redemption_series_output_coin_id"
            ],
            "redemptionDeedInputCoinId": row[
                "redemption_deed_input_coin_id"
            ],
            "externalSettlementEvidenceHash": row[
                "external_settlement_evidence_hash"
            ],
            "terminalExactExecution": (
                json.loads(row["terminal_exact_execution_json"])
                if row["terminal_exact_execution_json"]
                else None
            ),
            "terminalFeeCoinId": row["terminal_fee_coin_id"],
            "terminalFeeMojos": row["terminal_fee_mojos"],
            "terminalExecutionObservedAt": row[
                "terminal_execution_observed_at"
            ],
            "redemptionSubmittedAt": row["redemption_submitted_at"],
            "redemptionConfirmedHeight": row["redemption_confirmed_height"],
            "deliveryEvidenceId": row["delivery_evidence_id"],
            "deliveryOutputCoinId": row["delivery_output_coin_id"],
            "deliveryDeadline": series.get("deliveryDeadline"),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _render_payment_event(self, row: sqlite3.Row) -> dict[str, Any]:
        result = {
            "globalPaymentId": row["global_payment_id"],
            "termsHash": row["terms_hash"],
            "orderKey": row["order_key"],
            "evidenceId": row["evidence_id"],
            "outcome": row["outcome"],
            "serial": row["serial"],
            "refundRequired": row["outcome"] == "REFUND_REQUIRED",
        }
        if row["outcome"] == "PAYMENT_CONFIRMED":
            result["voucher"] = self.voucher(row["terms_hash"], int(row["serial"]))
        return result


def build_series_terms(
    request: PresaleCreateRequest,
    *,
    series_singleton_id: bytes32,
    collection: dict[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    if collection["id"] != request.collection_id:
        raise ValueError("collection identity mismatch")
    if collection["state"] != "PUBLISHED":
        raise ValueError("collection must have governed proposals before presale")
    if not collection.get("metadataRoot") or not collection.get("metadataAnchorId"):
        raise ValueError("collection metadata anchor is incomplete")
    if not (
        request.sale_open
        < request.sale_close
        <= request.refund_deadline
        <= request.launch_deadline
    ):
        raise ValueError(
            "must satisfy saleOpen < saleClose <= refundDeadline <= launchDeadline"
        )
    try:
        artifact = load_signed_public_artifact(settings)
    except PublicArtifactError as exc:
        raise ValueError("signed ceremony artifact is unavailable") from exc
    puzzle_hashes = artifact.get("puzzleHashes")
    validators = artifact.get("validatorSet")
    if not isinstance(puzzle_hashes, dict) or not isinstance(validators, dict):
        raise ValueError("signed ceremony artifact lacks presale coordinates")
    treasury = str(puzzle_hashes.get("protocolTreasuryPuzzleHash") or "")
    pubkeys = validators.get("pubkeys")
    if validators.get("threshold") != 2 or not isinstance(pubkeys, list) or len(pubkeys) != 3:
        raise ValueError("signed ceremony artifact lacks the required 2-of-3 validator set")
    offering = collection["dossier"].get("offering")
    if not isinstance(offering, dict):
        raise ValueError("collection offering is missing")
    if str(offering.get("currency")) != "USD":
        raise ValueError("voucher pricing requires USD collection economics")
    if str(offering.get("royaltyPuzhash") or "").lower() != treasury.lower():
        raise ValueError("technology fee destination is not the trusted protocol treasury")
    target_raise = _positive_int(offering.get("targetRaiseMinor"), "target raise")
    fee_bps = _nonnegative_int(offering.get("royaltyBps"), "technology fee")
    if fee_bps > 1_000:
        raise ValueError("technology fee exceeds 1000 bps")
    deed_rows: list[DeedAllocationCommitmentV2] = []
    deeds: list[dict[str, Any]] = []
    for deed in sorted(collection["deeds"], key=lambda item: int(item["ordinal"])):
        launcher = deed.get("deedLauncherId")
        if not launcher or not deed.get("proposalId"):
            raise ValueError("every presale deed requires a governed proposal and launcher")
        numerator = target_raise * int(deed["sharePpm"])
        base, remainder = divmod(numerator, 1_000_000)
        if remainder:
            raise ValueError("deed allocation produces fractional USD minor units")
        fee = technology_fee_minor(base, fee_bps)
        row = DeedAllocationCommitmentV2(
            deed_id=canonicalise_property_id(deed["deedId"]),
            share_ppm=int(deed["sharePpm"]),
            par_value_mojos=int(deed["parValueMojos"]),
            deed_launcher_id=_b32(launcher),
        )
        deed_rows.append(row)
        deeds.append(
            {
                "deedId": deed["deedId"],
                "deedIdCanon": _hex32(row.deed_id),
                "deedLauncherId": launcher.lower(),
                "ordinal": int(deed["ordinal"]),
                "sharePpm": int(deed["sharePpm"]),
                "parValueMojos": int(deed["parValueMojos"]),
                "basePriceMinor": base,
                "technologyFeeMinor": fee,
                "grossPriceMinor": base + fee,
            }
        )
    if [item["ordinal"] for item in deeds] != list(range(len(deeds))):
        raise ValueError("deed ordinals must be contiguous from zero")
    allocation = allocation_root(deed_rows)
    token = settings.payment_evm_usdc_tokens.get(str(BASE_SEPOLIA_CHAIN_ID))
    if token is None:
        raise ValueError("Base Sepolia USDC is not configured")
    try:
        omnichain = load_omnichain_evidence(
            settings,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            token_address=token,
            gateway_profile=str(settings.payment_omnichain_gateway_profile or ""),
        )
    except OmnichainEvidenceError as exc:
        raise ValueError("reviewed Samuel return coordinates are unavailable") from exc
    terms = VoucherSeriesTermsV2(
        series_singleton_id=series_singleton_id,
        collection_id=canonicalise_property_id(collection["id"]),
        metadata_root=_b32(collection["metadataRoot"], nonzero=True),
        metadata_anchor_id=_b32(collection["metadataAnchorId"], nonzero=True),
        allocation_root=allocation,
        trusted_protocol_treasury=_b32(treasury, nonzero=True),
        base_return_puzzle_hash=_b32(
            omnichain.return_puzzle_hash,
            nonzero=True,
        ),
        inventory_cap=len(deeds),
        sale_open=request.sale_open,
        sale_close=request.sale_close,
        refund_deadline=request.refund_deadline,
        launch_deadline=request.launch_deadline,
        validator_pubkeys=tuple(_pubkey(value) for value in pubkeys),  # type: ignore[arg-type]
    )
    return {
        "schema": SERIES_SCHEMA,
        "termsHash": _hex32(terms.terms_hash),
        "seriesSingletonId": _hex32(series_singleton_id),
        "collectionWorkspaceId": collection["id"],
        "collectionId": _hex32(terms.collection_id),
        "metadataRoot": collection["metadataRoot"].lower(),
        "metadataAnchorId": collection["metadataAnchorId"].lower(),
        "allocationRoot": _hex32(allocation),
        "trustedProtocolTreasury": treasury.lower(),
        "baseReturnPuzzleHash": omnichain.return_puzzle_hash.lower(),
        "inventoryCap": len(deeds),
        "saleOpen": request.sale_open,
        "saleClose": request.sale_close,
        "refundDeadline": request.refund_deadline,
        "launchDeadline": request.launch_deadline,
        "deliveryWindowSeconds": DELIVERY_WINDOW_SECONDS,
        "technologyFeeBps": fee_bps,
        "validatorPubkeys": [str(value).lower() for value in pubkeys],
        "deeds": deeds,
    }


def _series_program(terms: dict[str, Any]) -> VoucherSeriesTermsV2:
    return VoucherSeriesTermsV2(
        series_singleton_id=_b32(terms["seriesSingletonId"], nonzero=True),
        collection_id=_b32(terms["collectionId"], nonzero=True),
        metadata_root=_b32(terms["metadataRoot"], nonzero=True),
        metadata_anchor_id=_b32(terms["metadataAnchorId"], nonzero=True),
        allocation_root=_b32(terms["allocationRoot"], nonzero=True),
        trusted_protocol_treasury=_b32(
            terms["trustedProtocolTreasury"], nonzero=True
        ),
        base_return_puzzle_hash=_b32(
            terms["baseReturnPuzzleHash"],
            nonzero=True,
        ),
        inventory_cap=int(terms["inventoryCap"]),
        sale_open=int(terms["saleOpen"]),
        sale_close=int(terms["saleClose"]),
        refund_deadline=int(terms["refundDeadline"]),
        launch_deadline=int(terms["launchDeadline"]),
        validator_pubkeys=tuple(_pubkey(value) for value in terms["validatorPubkeys"]),  # type: ignore[arg-type]
    )


def _initial_series_inner(
    launcher_id: bytes32,
    *,
    expected_launcher_id: bytes32,
    terms: VoucherSeriesTermsV2,
):
    if launcher_id != expected_launcher_id:
        raise VoucherV2Error("derived presale launcher ID changed during construction")
    if terms.series_singleton_id != launcher_id:
        raise VoucherV2Error("presale terms are not bound to the derived launcher ID")
    return curry_series(terms, VoucherSeriesStateV2())


def _voucher_commitment(
    *,
    series: dict[str, Any],
    deed: dict[str, Any],
    artifact: Any,
    original_payer: str,
    global_payment_id: str,
    approved_vault: ApprovedVault,
    external_escrow_contract: bytes32,
) -> VoucherCommitmentV2:
    terms = series["terms"]
    fee_bps = int(terms["technologyFeeBps"])
    return VoucherCommitmentV2(
        series_terms_hash=_b32(series["termsHash"]),
        series_singleton_id=_b32(terms["seriesSingletonId"]),
        collection_id=_b32(terms["collectionId"]),
        metadata_root=_b32(terms["metadataRoot"]),
        allocation_root=_b32(terms["allocationRoot"]),
        serial=int(deed["ordinal"]),
        payment_rail=_voucher_rail(artifact.rail),
        payment_chain_id=int(artifact.rail_chain_id),
        payment_asset_id=artifact.rail_asset_id,
        payment_asset_decimals=int(artifact.rail_asset_decimals),
        external_escrow_contract=external_escrow_contract,
        base_price_minor=int(deed["basePriceMinor"]),
        technology_fee_bps=fee_bps,
        technology_fee_minor=int(deed["technologyFeeMinor"]),
        gross_price_minor=int(deed["grossPriceMinor"]),
        payment_principal=int(artifact.rail_amount),
        original_payer=_b32(original_payer, nonzero=True),
        approved_vault_launcher_id=_b32(approved_vault.launcher_id),
        approved_vault_p2_puzzle_hash=_b32(approved_vault.p2_puzzle_hash),
        refund_deadline=int(terms["refundDeadline"]),
        delivery_window_seconds=DELIVERY_WINDOW_SECONDS,
        trusted_protocol_treasury=_b32(terms["trustedProtocolTreasury"]),
        deed_launcher_id=_b32(deed["deedLauncherId"]),
        smart_deed_inner_hash=bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        ),
        purchase_artifact_hash=artifact.artifact_hash,
        global_payment_id=_b32(global_payment_id, nonzero=True),
        state=VoucherState.ESCROWED,
    )


def _validate_artifact_against_series(
    *,
    artifact: Any,
    evidence: VoucherIssuanceEvidenceRequest,
    approved_vault: ApprovedVault,
    issued_purchase: StoredPaymentPurchase,
    series: dict[str, Any],
    deed: dict[str, Any],
) -> None:
    _validate_artifact_binding(
        artifact=artifact,
        approved_vault=approved_vault,
        issued_purchase=issued_purchase,
        series=series,
        deed=deed,
    )
    if _json(issued_purchase.purchase_artifact) != _json(evidence.purchase_artifact):
        raise ValueError("payment evidence does not match the coordinator-issued purchase")
    if artifact.rail == PaymentRail.EVM_TEST_USD:
        message = issued_purchase.external_message
        if not isinstance(message, dict):
            raise ValueError("Base payment has not passed authenticated escrow verification")
        if (
            str(message.get("globalPaymentId") or "").lower()
            != evidence.global_payment_id.lower()
        ):
            raise ValueError("Base payment ID does not match verified escrow evidence")
        if not isinstance(message.get("source"), dict):
            raise ValueError("Base payment is missing confirmed chain provenance")
        depositor = message.get("depositor")
        if not isinstance(depositor, str):
            raise ValueError("Base payment is missing the original depositor")
        if _hex32(_evm_address_b32(depositor)) != evidence.original_payer.lower():
            raise ValueError("Base voucher payer does not match the verified depositor")
    if evidence.original_payer.lower() == "0x" + "00" * 32:
        raise ValueError("original payer commitment cannot be zero")


def _validate_artifact_binding(
    *,
    artifact: Any,
    approved_vault: ApprovedVault,
    issued_purchase: StoredPaymentPurchase,
    series: dict[str, Any],
    deed: dict[str, Any],
) -> None:
    terms = series["terms"]
    try:
        stored_artifact = purchase_artifact_from_json(issued_purchase.purchase_artifact)
    except PaymentArtifactError as exc:
        raise ValueError("coordinator-issued purchase artifact is invalid") from exc
    if stored_artifact != artifact:
        raise ValueError("purchase artifact differs from the coordinator-issued quote")
    expected = (
        _b32(terms["collectionId"]),
        _b32(terms["metadataRoot"]),
        _b32(terms["metadataAnchorId"]),
        _b32(deed["deedLauncherId"]),
        _b32(approved_vault.launcher_id),
        _b32(approved_vault.p2_puzzle_hash),
    )
    observed = (
        artifact.collection_id,
        artifact.metadata_root,
        artifact.metadata_anchor_id,
        artifact.deed_launcher_id,
        artifact.vault_launcher_id,
        artifact.vault_p2_puzzle_hash,
    )
    if observed != expected:
        raise ValueError("purchase artifact changes series, deed, or approved vault commitments")
    if artifact.network != approved_vault.enrollment.receipt.network:
        raise ValueError("purchase artifact network does not match approved vault")
    if artifact.share_ppm != int(deed["sharePpm"]):
        raise ValueError("purchase artifact share differs from governed allocation")
    if artifact.usd_amount_minor != int(deed["grossPriceMinor"]):
        raise ValueError("purchase artifact price differs from collection economics")
    if artifact.rail not in {PaymentRail.EVM_TEST_USD, PaymentRail.CHIA_XCH}:
        raise ValueError("voucher presale supports only Base Sepolia USDC or XCH")
    expected_rails = (
        {"base_usdc", "evm_usdc"}
        if artifact.rail == PaymentRail.EVM_TEST_USD
        else {"chia_xch"}
    )
    if issued_purchase.rail not in expected_rails:
        raise ValueError("coordinator purchase rail does not match voucher payment rail")


def _verified_original_payer(
    artifact: Any,
    evidence: VoucherIssuanceEvidenceRequest,
    issued_purchase: StoredPaymentPurchase,
) -> str:
    if artifact.rail != PaymentRail.EVM_TEST_USD:
        return evidence.original_payer.lower()
    message = issued_purchase.external_message
    if not isinstance(message, dict) or not isinstance(message.get("depositor"), str):
        raise ValueError("Base payment is missing the original depositor")
    return _hex32(_evm_address_b32(str(message["depositor"])))


def _voucher_commitment_json(value: VoucherCommitmentV2) -> dict[str, Any]:
    return {
        "seriesTermsHash": _hex32(value.series_terms_hash),
        "seriesSingletonId": _hex32(value.series_singleton_id),
        "collectionId": _hex32(value.collection_id),
        "metadataRoot": _hex32(value.metadata_root),
        "allocationRoot": _hex32(value.allocation_root),
        "serial": value.serial,
        "paymentRail": int(value.payment_rail),
        "paymentChainId": value.payment_chain_id,
        "paymentAssetId": _hex32(value.payment_asset_id),
        "paymentAssetDecimals": value.payment_asset_decimals,
        "externalEscrowContract": _hex32(value.external_escrow_contract),
        "basePriceMinor": value.base_price_minor,
        "technologyFeeBps": value.technology_fee_bps,
        "technologyFeeMinor": value.technology_fee_minor,
        "grossPriceMinor": value.gross_price_minor,
        "paymentPrincipal": value.payment_principal,
        "originalPayer": _hex32(value.original_payer),
        "approvedVaultLauncherId": _hex32(value.approved_vault_launcher_id),
        "approvedVaultP2PuzzleHash": _hex32(value.approved_vault_p2_puzzle_hash),
        "refundDeadline": value.refund_deadline,
        "deliveryWindowSeconds": value.delivery_window_seconds,
        "trustedProtocolTreasury": _hex32(value.trusted_protocol_treasury),
        "deedLauncherId": _hex32(value.deed_launcher_id),
        "smartDeedInnerHash": _hex32(value.smart_deed_inner_hash),
        "purchaseArtifactHash": _hex32(value.purchase_artifact_hash),
        "globalPaymentId": _hex32(value.global_payment_id),
        "programHex": bytes(value.to_program()).hex(),
    }


def _require_collection_executed(collection: dict[str, Any]) -> None:
    if not collection["deeds"] or any(
        deed.get("proposalState") != "EXECUTED"
        or not deed.get("deedLauncherId")
        or not deed.get("executeBundleId")
        for deed in collection["deeds"]
    ):
        raise ValueError("every governed SmartDeed must be executed before series launch")


async def _submit_series_phase_transition(
    *,
    request: Request,
    settings: Settings,
    store: PresaleStore,
    series: dict[str, Any],
    transition: SeriesTransition,
    collection: Optional[dict[str, Any]] = None,
    cancel_reason: Optional[str] = None,
) -> dict[str, Any]:
    if series["state"] != "PRESALE":
        raise ValueError("only a PRESALE series can change phase")
    if series["phaseTransition"]["status"] != "NOT_SUBMITTED":
        raise ValueError("series phase transition is already submitted")
    terms = _series_program(series["terms"])
    state = _chain_series_state(series)
    series_coin, lineage = await _confirmed_coin_and_lineage(
        request.app.state.coinset,
        str(series["chainState"]["currentCoinId"] or ""),
        "presale series coin",
    )
    launch_anchor = int(time.time()) if transition == SeriesTransition.LAUNCH else 0
    deed_launcher_ids: list[str] = []
    governance_execution_ids: list[str] = []
    governed_deed_puzzle_hashes: list[str] = []
    if transition == SeriesTransition.LAUNCH:
        if collection is None:
            raise ValueError("series launch requires collection execution evidence")
        _require_collection_executed(collection)
        collection_deeds = {
            str(item["deedId"]).casefold(): item for item in collection["deeds"]
        }
        for deed in sorted(series["terms"]["deeds"], key=lambda item: int(item["ordinal"])):
            stored = collection_deeds.get(str(deed["deedId"]).casefold())
            if (
                stored is None
                or str(stored.get("deedLauncherId") or "").lower()
                != str(deed["deedLauncherId"]).lower()
            ):
                raise ValueError("collection execution changed a committed deed launcher")
            deed_launcher_ids.append(str(deed["deedLauncherId"]).lower())
            governance_execution_ids.append(
                _hex32(_b32(stored["executeBundleId"], nonzero=True))
            )
            from .mint_endpoints import get_mint_proposal_store

            proposal = get_mint_proposal_store(settings).get(
                str(stored.get("proposalId") or "")
            )
            if (
                proposal is None
                or proposal.state != "EXECUTED"
                or proposal.deed_launcher_id is None
                or proposal.deed_full_puzhash is None
                or proposal.executed_bundle_id is None
                or _hex32(bytes32(proposal.deed_launcher_id))
                != str(deed["deedLauncherId"]).lower()
                or proposal.executed_bundle_id.lower()
                != str(stored["executeBundleId"]).lower()
            ):
                raise ValueError(
                    "collection execution differs from its canonical mint proposal"
                )
            governed_deed_puzzle_hashes.append(
                _hex32(bytes32(proposal.deed_full_puzhash))
            )
    provisional = build_voucher_series_phase_spend(
        terms=terms,
        state=state,
        series_coin=series_coin,
        series_lineage_proof=lineage,
        transition=transition,
        launch_anchor=launch_anchor,
        signer_indices=tuple(range(settings.zkpassport_validator_threshold)),
    )
    artifact = load_signed_public_artifact(settings)
    claim = VoucherSeriesPhaseClaim(
        network=settings.network,
        genesis_artifact_hash=str(artifact["artifactHash"]).lower(),
        series_terms=series["terms"],
        series_coin_id=_hex32(series_coin.name()),
        series_sold_count=state.sold_count,
        series_redeemed_count=state.redeemed_count,
        series_refunded_count=state.refunded_count,
        series_phase=int(state.phase),
        series_launched_at=state.launched_at,
        transition=int(transition),
        launch_anchor=launch_anchor,
        deed_launcher_ids=deed_launcher_ids,
        governed_deed_puzzle_hashes=governed_deed_puzzle_hashes,
        validator_message=_hex32(provisional.validator_message),
    )
    quorum = await collect_voucher_series_phase_quorum(settings, claim)
    phase = build_voucher_series_phase_spend(
        terms=terms,
        state=state,
        series_coin=series_coin,
        series_lineage_proof=lineage,
        transition=transition,
        launch_anchor=launch_anchor,
        signer_indices=quorum.signer_indices,
    )
    if phase.validator_message != provisional.validator_message:
        raise ValueError("series phase transition changed after quorum selection")
    bundle = WalletSpendBundle(
        [phase.series_spend],
        quorum.aggregated_signature,
    )
    result = await request.app.state.coinset.push_tx(bundle.to_json_dict())
    network_status = str(result.get("status") or "").upper()
    if not result.get("success") and network_status not in {"SUCCESS", "PENDING"}:
        raise ValueError("series phase transition was rejected by the Chia node")
    next_inner = curry_series(terms, phase.next_series_state)
    return store.record_phase_submission(
        series["termsHash"],
        target_state=(
            "LIVE" if transition == SeriesTransition.LAUNCH else "CANCELED"
        ),
        spend_bundle_id=_hex32(bundle.name()),
        series_input_coin_id=_hex32(series_coin.name()),
        series_output_coin_id=_hex32(phase.next_series_coin.name()),
        series_output_inner_puzzle_hash=_hex32(next_inner.get_tree_hash()),
        launch_anchor=launch_anchor,
        governance_execution_ids=governance_execution_ids,
        cancel_reason=cancel_reason,
    )


def _require_ingest(settings: Settings, authorization: Optional[str]) -> None:
    # Customer gates stop new reservations. They must never strand a payment
    # that already needs voucher issuance, delivery, reconciliation, or refund.
    # These endpoints remain restricted to the settlement-service credential.
    token = settings.payment_omnichain_ingest_token
    if not token or authorization != f"Bearer {token}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid settlement evidence credential",
        )


def _verify_base_settlement_relay_evidence(
    settings: Settings,
    record: dict[str, Any],
    evidence: BaseSettlementRelayEvidenceRequest,
) -> None:
    authorization = record["authorization"]
    payment = authorization["payment"]
    token = settings.payment_evm_usdc_tokens.get(str(payment["chainId"]))
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
        receipt = w3.eth.get_transaction_receipt(
            evidence.base_transaction_hash
        )
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
    events = spoke.events.PaymentSettled().process_receipt(
        receipt,
        errors=DISCARD,
    )
    if len(events) != 1:
        raise ValueError("Base settlement event is missing or ambiguous")
    event = events[0]["args"]
    succeeded = authorization["outcome"] == "DELIVERED"
    original_payer = "0x" + authorization["originalPayer"][-40:]
    expected_recipient = (
        deployment.governance_root_safe if succeeded else original_payer
    )
    if (
        "0x" + bytes(event["globalPaymentId"]).hex()
        != authorization["globalPaymentId"]
        or str(event["recipient"]).lower() != expected_recipient
        or str(event["settlementToken"]).lower() != token.lower()
        or int(event["amount"]) != int(payment["principal"])
        or bool(event["succeeded"]) is not succeeded
        or bool(event["emergency"]) is not False
    ):
        raise ValueError("Base settlement event differs from authorization")

    try:
        deposit = spoke.functions.getDeposit(
            authorization["globalPaymentId"]
        ).call()
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Base settlement deposit storage is unavailable") from exc
    expected_status = 3 if succeeded else 4
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
    expected = {
        "depositor": original_payer,
        "settlementToken": token.lower(),
        "purchaseId": authorization["purchaseId"],
        "artifactHash": authorization["purchaseArtifactHash"],
        "collectionId": authorization["collectionId"],
        "deedLauncherId": authorization["deedLauncherId"],
        "vaultLauncherId": authorization["vaultLauncherId"],
        "destinationPuzzle": authorization["vaultP2PuzzleHash"],
        "warpNonce": evidence.warp_message_id.lower(),
        "amount": int(payment["principal"]),
        "quantity": 1,
        "status": expected_status,
        "succeeded": succeeded,
    }
    if any(stored[field] != value for field, value in expected.items()):
        raise ValueError("Base settlement storage differs from authorization")
    if stored["resultMessageId"] == "0x" + "00" * 32:
        raise ValueError("Base settlement result message is missing")


def _load_issued_purchase(
    settings: Settings,
    evidence: VoucherIssuanceEvidenceRequest,
) -> tuple[Any, StoredPaymentPurchase]:
    try:
        artifact = purchase_artifact_from_json(evidence.purchase_artifact)
        stored = get_payment_purchase_store(settings.payment_purchase_db_path).get(
            _hex32(artifact.purchase_id)
        )
    except (PaymentArtifactError, PaymentPurchaseNotFound) as exc:
        raise ValueError("payment does not reference an issued purchase artifact") from exc
    if _json(stored.purchase_artifact) != _json(evidence.purchase_artifact):
        raise ValueError("payment artifact differs from the coordinator-issued artifact")
    reasons = _artifact_rejection_reasons(
        stored.offer_artifact,
        stored.offer_artifact_hash,
        now=evidence.confirmed_at,
        settings=settings,
    )
    if reasons:
        raise ValueError(
            "issued purchase artifact failed verification: " + ", ".join(reasons)
        )
    if artifact.rail == PaymentRail.EVM_TEST_USD:
        configured = settings.payment_evm_usdc_tokens.get(
            str(BASE_SEPOLIA_CHAIN_ID), ""
        ).lower()
        if configured != BASE_SEPOLIA_USDC:
            raise ValueError("Base Sepolia presale requires Circle's official USDC")
        expected_asset = bytes32(
            b"\x00" * 12 + bytes.fromhex(BASE_SEPOLIA_USDC.removeprefix("0x"))
        )
        if (
            artifact.rail_chain_id != BASE_SEPOLIA_CHAIN_ID
            or artifact.rail_asset_id != expected_asset
            or artifact.rail_asset_decimals != 6
        ):
            raise ValueError("purchase artifact is not the approved Base Sepolia USDC rail")
    elif artifact.rail != PaymentRail.CHIA_XCH:
        raise ValueError("presale supports only Base Sepolia USDC or native XCH")
    return artifact, stored


def _load_native_voucher_context(
    *,
    terms_hash: str,
    purchase_id: str,
    request: Request,
    settings: Settings,
    store: PresaleStore,
    authorization: Optional[str] = None,
) -> tuple[dict[str, Any], StoredPaymentPurchase, Any, ApprovedVault, dict[str, Any]]:
    now = int(time.time())
    try:
        series = store.get(terms_hash)
        issued = get_payment_purchase_store(settings.payment_purchase_db_path).get(
            purchase_id.lower()
        )
        artifact = purchase_artifact_from_json(issued.purchase_artifact)
        artifact.assert_live(now)
    except (KeyError, PaymentArtifactError, PaymentPurchaseNotFound, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="The XCH voucher quote is missing, invalid, or expired.",
        ) from exc
    if series["state"] != "PRESALE":
        raise HTTPException(status_code=409, detail="The voucher series is not in presale.")
    if not (
        int(series["terms"]["saleOpen"])
        <= now
        < int(series["terms"]["saleClose"])
    ):
        raise HTTPException(status_code=409, detail="The voucher sale window is closed.")
    if artifact.rail != PaymentRail.CHIA_XCH:
        raise HTTPException(status_code=409, detail="This voucher quote is not native XCH.")
    reasons = _artifact_rejection_reasons(
        issued.offer_artifact,
        issued.offer_artifact_hash,
        now=now,
        settings=settings,
    )
    if reasons:
        raise HTTPException(
            status_code=409,
            detail="Purchase authorization is no longer current: " + ", ".join(reasons),
        )
    try:
        approved = require_current_approved_vault(
            settings,
            _hex32(artifact.vault_launcher_id),
        )
    except (PaymentArtifactError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _authorize_native_voucher_request(
        settings=settings,
        request=request,
        vault_launcher_id=approved.launcher_id,
        authorization=authorization,
    )
    deed = next(
        (
            row
            for row in series["terms"]["deeds"]
            if row["deedLauncherId"].lower() == _hex32(artifact.deed_launcher_id)
        ),
        None,
    )
    if deed is None:
        raise HTTPException(status_code=409, detail="Quote does not target this series.")
    try:
        _validate_artifact_binding(
            artifact=artifact,
            approved_vault=approved,
            issued_purchase=issued,
            series=series,
            deed=deed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return series, issued, artifact, approved, deed


def _authorize_native_voucher_request(
    *,
    settings: Settings,
    request: Request,
    vault_launcher_id: str,
    authorization: Optional[str],
) -> None:
    if authorization:
        if not settings.protocol_artifact_api_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Protocol artifact bearer authentication is not configured.",
            )
        _require_server_to_server_token(settings, authorization)
        return
    session = verify_vault_session(
        settings,
        request,
        vault_launcher_id,
    )
    if session.vault_launcher_id.lower() != vault_launcher_id.lower():
        raise HTTPException(status_code=403, detail="Vault session does not own this quote.")


async def _confirmed_series_coin(coinset: Any, coin_id: str) -> Coin:
    if not coin_id:
        raise HTTPException(status_code=409, detail="Presale series is not confirmed yet.")
    record = await coinset.get_coin_record_by_name(coin_id)
    coin = _coin_from_record(record)
    if (
        coin is None
        or not _record_is_unspent_coin(record, coin)
        or _hex32(coin.name()) != coin_id.lower()
        or int(coin.amount) != 1
    ):
        raise HTTPException(
            status_code=409,
            detail="The current presale series coin is not confirmed and unspent.",
        )
    return coin


async def _confirmed_coin_and_lineage(
    coinset: Any,
    coin_id: str,
    label: str,
) -> tuple[Coin, LineageProof]:
    record = await coinset.get_coin_record_by_name(coin_id)
    coin = _coin_from_record(record)
    if (
        coin is None
        or not _record_is_unspent_coin(record, coin)
        or _hex32(coin.name()) != coin_id.lower()
    ):
        raise ValueError(f"{label} is not confirmed and unspent")
    parent_id = _hex32(coin.parent_coin_info)
    parent_record = await coinset.get_coin_record_by_name(parent_id)
    parent_coin = _coin_from_record(parent_record)
    child_height = int((record or {}).get("confirmed_block_index") or 0)
    parent_height = int((parent_record or {}).get("spent_block_index") or 0)
    if (
        parent_coin is None
        or _hex32(parent_coin.name()) != parent_id
        or child_height <= 0
        or parent_height != child_height
    ):
        raise ValueError(f"{label} lineage is not atomic")
    coin_solution = await coinset.get_puzzle_and_solution(parent_id, parent_height)
    if not isinstance(coin_solution, dict):
        raise ValueError(f"{label} parent spend is unavailable")
    try:
        puzzle_reveal = Program.from_bytes(
            bytes.fromhex(str(coin_solution["puzzle_reveal"]).removeprefix("0x"))
        )
        solution = Program.from_bytes(
            bytes.fromhex(str(coin_solution["solution"]).removeprefix("0x"))
        )
        parent_spend = make_spend(parent_coin, puzzle_reveal, solution)
        lineage = lineage_proof_for_coinsol(parent_spend)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} parent spend is malformed") from exc
    return coin, lineage


async def _vault_refund_context(
    *,
    request: Request,
    settings: Settings,
    approved: ApprovedVault,
    voucher_launcher_id: bytes32,
    voucher_coin_id: bytes32,
    current_timestamp: int,
    owner_authorization: Optional[str] = None,
) -> tuple[Coin, LineageProof, Any, bytes32, Any, Optional[dict[str, Any]]]:
    record = get_registry().get(_b32(approved.launcher_id, nonzero=True))
    if record is None:
        raise ValueError("approved vault owner record is unavailable")
    if record.auth_type not in {AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1}:
        raise ValueError("voucher refunds require a BLS or EVM vault owner")
    vault_coin, vault_lineage = await _confirmed_coin_and_lineage(
        request.app.state.coinset,
        approved.current_coin_id,
        "approved vault coin",
    )
    genesis = load_signed_public_artifact(settings)
    try:
        pool_launcher_id = _b32(genesis["launcherIds"]["pool"], nonzero=True)
        bridge_policy_hash = _b32(
            genesis["bridgePolicy"]["policyHash"], nonzero=True
        )
        identity_root = _b32(approved.identity_attest_root, nonzero=True)
        owner_key = bytes(record.owner_pubkey)
        member_root = one_leaf_merkle_root(owner_key)
        expected_full = puzzle_for_vault_full(
            record.launcher_id,
            owner_key,
            record.auth_type,
            member_root,
            pool_launcher_id,
            identity_attest_root=identity_root,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        inner = puzzle_for_vault_inner(
            record.launcher_id,
            owner_key,
            record.auth_type,
            member_root,
            pool_launcher_id,
            identity_attest_root=identity_root,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("active genesis vault coordinates are malformed") from exc
    if vault_coin.puzzle_hash != expected_full.get_tree_hash() or int(vault_coin.amount) != 1:
        raise ValueError("approved vault coin does not match its registered owner")

    typed_data: Optional[dict[str, Any]] = None
    signature_data: Optional[bytes] = None
    if record.auth_type == AUTH_TYPE_SECP256K1:
        typed_data = eip712_typed_data_for_vault_spend(
            b"i",
            voucher_launcher_id,
            vault_coin.name(),
        )
        if owner_authorization is not None:
            recovered = recover_evm_signer(typed_data, owner_authorization)
            if recovered.compressed_pubkey != owner_key:
                raise ValueError("EVM refund signature does not belong to the vault owner")
            signature_data = compact_signature_from_evm(owner_authorization)
    vault_spend = build_vault_receive_spend(
        vault_coin=vault_coin,
        vault_launcher_id=record.launcher_id,
        owner_pubkey_bytes=owner_key,
        auth_type=record.auth_type,
        members_merkle_root=member_root,
        pool_launcher_id=pool_launcher_id,
        deed_launcher_id=voucher_launcher_id,
        p2_vault_coin_id=voucher_coin_id,
        current_timestamp=current_timestamp,
        lineage_proof=vault_lineage,
        signature_data=signature_data,
        identity_attest_root=identity_root,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if record.auth_type == AUTH_TYPE_BLS and owner_authorization is not None:
        signature = G2Element.from_bytes(
            _hex_bytes(owner_authorization, 96, "ownerAuthorization")
        )
        conditions = conditions_dict_for_solution(
            vault_spend.puzzle_reveal,
            vault_spend.solution,
            INFINITE_COST,
        )
        pairs = pkm_pairs_for_conditions_dict(
            conditions,
            vault_spend.coin,
            AGG_SIG_ME_DATA[settings.network],
        )
        if not pairs or not AugSchemeMPL.aggregate_verify(
            [pair[0] for pair in pairs],
            [pair[1] for pair in pairs],
            signature,
        ):
            raise ValueError("BLS refund signature does not authorize the vault spend")
    return (
        vault_coin,
        vault_lineage,
        record,
        bytes32(inner.get_tree_hash()),
        vault_spend,
        typed_data,
    )


def _chain_series_state(series: dict[str, Any]) -> VoucherSeriesStateV2:
    chain = series["chainState"]
    phase = {
        "PRESALE": VoucherSeriesState.PRESALE,
        "LIVE": VoucherSeriesState.LIVE,
        "CANCELED": VoucherSeriesState.CANCELED,
    }.get(str(series["state"]))
    if phase is None:
        raise ValueError("presale series state is invalid")
    return VoucherSeriesStateV2(
        sold_count=int(chain["soldCount"]),
        redeemed_count=int(chain["redeemedCount"]),
        refunded_count=int(chain["refundedCount"]),
        phase=phase,
        launched_at=int(series.get("launchedAt") or 0),
    )


def _voucher_refund_action(
    series: dict[str, Any],
    *,
    now_seconds: int,
) -> VoucherAction:
    if series["state"] == "PRESALE":
        if now_seconds >= int(series["terms"]["refundDeadline"]):
            raise ValueError("voucher refund deadline has passed")
        return VoucherAction.REFUND_PRESALE
    if series["state"] == "CANCELED":
        return VoucherAction.REFUND_CANCELED
    if series["state"] == "LIVE":
        if now_seconds < int(series["deliveryDeadline"] or 0):
            raise ValueError("voucher delivery window has not expired")
        return VoucherAction.REFUND_EXPIRED
    raise ValueError("voucher series is not refundable")


def _native_global_payment_id(
    *,
    payment_coin: Coin,
    artifact: Any,
    terms_hash: bytes32,
) -> bytes32:
    return bytes32(
        hashlib.sha256(
            b"SOLSLOT_XCH_VOUCHER_PAYMENT_V2"
            + bytes(payment_coin.name())
            + bytes(artifact.artifact_hash)
            + bytes(terms_hash)
        ).digest()
    )


_store: Optional[PresaleStore] = None
_store_path: Optional[str] = None


def get_presale_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PresaleStore:
    global _store, _store_path
    if _store is None or _store_path != settings.admin_db_path:
        _store = PresaleStore(settings.admin_db_path)
        _store_path = settings.admin_db_path
    return _store


def response_or_404(call):
    try:
        return call()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="presale or voucher not found") from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="duplicate presale or payment evidence") from exc
    except (ValueError, VoucherV2Error, VoucherV3Error) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _public_presale(series: dict[str, Any]) -> dict[str, Any]:
    public = dict(series)
    public.pop("vouchers", None)
    return public


@router.get("/stripe-refunds/pending")
def pending_stripe_refunds(
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
    limit: int = 100,
) -> dict[str, Any]:
    if not settings.protocol_artifact_api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="protocol artifact bearer authentication is not configured",
        )
    _require_server_to_server_token(settings, authorization)
    return {
        "schema": STRIPE_REFUND_AUTHORIZATION_SCHEMA,
        "authorizations": response_or_404(
            lambda: store.pending_stripe_refund_authorizations(limit=limit)
        ),
    }


@router.post("/stripe-refunds/{authorization_id}/completion")
def complete_stripe_refund(
    authorization_id: str,
    body: StripeRefundCompletionRequest,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    if not settings.protocol_artifact_api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="protocol artifact bearer authentication is not configured",
        )
    _require_server_to_server_token(settings, authorization)
    if (
        len(authorization_id) != 66
        or not authorization_id.startswith("0x")
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in authorization_id[2:]
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="authorization ID must be a 32-byte hex value",
        )
    if body.livemode != (settings.stripe_mode == "live"):
        raise HTTPException(
            status_code=409,
            detail="Stripe refund completion uses the wrong account mode",
        )
    return response_or_404(
        lambda: store.complete_stripe_refund_authorization(
            authorization_id,
            body,
        )
    )


@router.get("/base-settlements/pending")
def pending_base_settlements(
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
    limit: int = 100,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    return {
        "schema": BASE_SETTLEMENT_AUTHORIZATION_SCHEMA,
        "authorizations": response_or_404(
            lambda: store.pending_base_settlement_authorizations(limit=limit)
        ),
    }


@router.get("/base-settlements/by-payment/{global_payment_id}")
def base_settlement_by_payment(
    global_payment_id: str,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    if (
        len(global_payment_id) != 66
        or not global_payment_id.startswith("0x")
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in global_payment_id[2:]
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="global payment ID must be a 32-byte hex value",
        )
    return response_or_404(
        lambda: store.base_settlement_authorization_by_payment(
            global_payment_id
        )
    )


@router.post("/base-settlements/{authorization_id}/relay-evidence")
async def acknowledge_base_settlement(
    authorization_id: str,
    body: BaseSettlementRelayEvidenceRequest,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    if (
        len(authorization_id) != 66
        or not authorization_id.startswith("0x")
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in authorization_id[2:]
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="authorization ID must be a 32-byte hex value",
        )
    record = response_or_404(
        lambda: store.base_settlement_authorization(authorization_id)
    )
    try:
        await asyncio.to_thread(
            _verify_base_settlement_relay_evidence,
            settings,
            record,
            body,
        )
    except (ValueError, OmnichainEvidenceError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return response_or_404(
        lambda: store.record_base_settlement_relay_evidence(
            authorization_id,
            body,
        )
    )


@router.get("/stripe-rehearsal/candidates")
def stripe_rehearsal_candidates(
    created_after: int,
    vault_launcher_id: str,
    collection_id: str,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    if not settings.protocol_artifact_api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="protocol artifact bearer authentication is not configured",
        )
    _require_server_to_server_token(settings, authorization)
    return response_or_404(
        lambda: store.stripe_rehearsal_candidates(
            created_after=created_after,
            vault_launcher_id=vault_launcher_id,
            collection_id=collection_id,
        )
    )


@router.post(
    "",
    status_code=201,
    dependencies=[
        Depends(require_admin_operation("presale.create")),
        Depends(require_presale_writes),
    ],
)
async def create_presale(
    body: PresaleCreateRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    collections: Annotated[CollectionStore, Depends(get_collection_store)],
) -> dict[str, Any]:
    try:
        store.get(body.collection_id)
    except KeyError:
        pass
    else:
        raise HTTPException(
            status_code=409,
            detail="collection already has a presale series",
        )

    faucet = getattr(request.app.state, "faucet", None)
    coinset = getattr(request.app.state, "coinset", None)
    if faucet is None or coinset is None:
        raise HTTPException(
            status_code=503,
            detail="signed singleton launch service is unavailable",
        )
    records = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    parent_coin = faucet.select_coin(
        records,
        min_amount=1,
        max_amount=settings.faucet_max_spend_mojos,
    )
    if parent_coin is None:
        raise HTTPException(
            status_code=503,
            detail="faucet has no eligible one-mojo singleton funding coin",
        )

    series_singleton_id = bytes32(launcher_coin_for_parent(parent_coin).name())
    try:
        terms = build_series_terms(
            body,
            series_singleton_id=series_singleton_id,
            collection=collections.get(body.collection_id),
            settings=settings,
        )
        series_program = _series_program(terms)
        launched = build_and_sign_singleton_launch(
            faucet=faucet,
            parent_coin=parent_coin,
            inner_puzzle_for_launcher=lambda launcher_id: _initial_series_inner(
                launcher_id,
                expected_launcher_id=series_singleton_id,
                terms=series_program,
            ),
            launcher_memos=(
                b"SOLSLOT_PRESALE_SERIES_V2",
                series_program.collection_id,
                series_program.terms_hash,
            ),
            eve_memos=(series_program.collection_id, series_program.terms_hash),
        )
        result = await coinset.push_tx(launched.spend_bundle.to_json_dict())
    except (ValueError, VoucherV2Error) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"presale series launch failed: {exc}",
        ) from exc
    if not result.get("success"):
        reason = result.get("error") or result.get("status") or "unknown rejection"
        raise HTTPException(
            status_code=502,
            detail=f"presale series launch was rejected: {reason}",
        )

    return response_or_404(
        lambda: store.create(
            terms,
            singleton_launch={
                "parentCoinId": _hex32(bytes32(parent_coin.name())),
                "fullPuzzleHash": _hex32(launched.full_puzzle_hash),
                "spendBundleId": launched.spend_bundle_id,
            },
        )
    )


@router.get("")
def list_presales(
    store: Annotated[PresaleStore, Depends(get_presale_store)],
) -> list[dict[str, Any]]:
    return [_public_presale(series) for series in store.list()]


@router.get("/admin", dependencies=[Depends(require_admin_jwt)])
def list_presales_for_admin(
    store: Annotated[PresaleStore, Depends(get_presale_store)],
) -> list[dict[str, Any]]:
    return store.list()


@router.get("/admin/{identifier}", dependencies=[Depends(require_admin_jwt)])
def get_presale_for_admin(
    identifier: str,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
) -> dict[str, Any]:
    return response_or_404(lambda: store.get(identifier))


@router.get("/vaults/{vault_launcher_id}/vouchers")
def list_vault_presale_vouchers(
    vault_launcher_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[PresaleStore, Depends(get_presale_store)],
) -> list[dict[str, Any]]:
    session = verify_vault_session(settings, request, vault_launcher_id)
    approved = require_current_approved_vault(
        settings,
        session.vault_launcher_id,
    )
    return store.vouchers_for_vault(approved.launcher_id)


@router.get("/{identifier}")
def get_presale(
    identifier: str,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
) -> dict[str, Any]:
    return response_or_404(lambda: _public_presale(store.get(identifier)))


@router.post(
    "/{terms_hash}/native/prepare",
    response_model=PrepareNativeVoucherResponse,
)
async def prepare_native_voucher(
    terms_hash: str,
    body: PrepareNativeVoucherRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> PrepareNativeVoucherResponse:
    require_presale_writes(settings)
    require_operation_gate(settings, "presale")
    series, issued, artifact, approved, deed = _load_native_voucher_context(
        terms_hash=terms_hash,
        purchase_id=body.purchase_id,
        request=request,
        settings=settings,
        store=store,
        authorization=authorization,
    )
    if any(int(item["serial"]) == int(deed["ordinal"]) for item in series["vouchers"]):
        raise HTTPException(status_code=409, detail="This governed deed is already reserved.")
    selected = None
    for public_key in body.payment_public_keys:
        candidate = await _select_payment_coin(
            request.app.state.coinset,
            artifact,
            _hex_bytes(public_key, 48, "paymentPublicKeys"),
            minimum_amount=int(artifact.rail_amount) + 1,
        )
        if candidate is not None and (
            selected is None or int(candidate[0].amount) < int(selected[0].amount)
        ):
            selected = candidate
    if selected is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "No single confirmed XCH coin can cover the system quote and "
                "one-mojo voucher output. Consolidate XCH and retry."
            ),
        )
    payment_coin, payment_public_key, _lineage = selected
    global_payment_id = _native_global_payment_id(
        payment_coin=payment_coin,
        artifact=artifact,
        terms_hash=_b32(series["termsHash"]),
    )
    commitment = _voucher_commitment(
        series=series,
        deed=deed,
        artifact=artifact,
        original_payer=_hex32(payment_coin.puzzle_hash),
        global_payment_id=_hex32(global_payment_id),
        approved_vault=approved,
        external_escrow_contract=bytes32.zeros,
    )
    chain = series["chainState"]
    series_coin = await _confirmed_series_coin(
        request.app.state.coinset,
        str(chain.get("currentCoinId") or ""),
    )
    try:
        prepared = prepare_xch_voucher_offer(
            terms=_series_program(series["terms"]),
            state=_chain_series_state(series),
            series_coin=series_coin,
            voucher=commitment,
            purchase=artifact,
            payment_coin=payment_coin,
            payment_public_key=payment_public_key,
        )
    except (PaymentArtifactError, VoucherV2Error, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return PrepareNativeVoucherResponse(
        termsHash=series["termsHash"],
        purchaseId=_hex32(artifact.purchase_id),
        buyerOffer=prepared.offer.to_bech32(),
        coinSpends=[_coin_spend_json(spend) for spend in prepared.offer.coin_spends()],
        amount=int(artifact.rail_amount),
        assetId=_hex32(artifact.rail_asset_id),
        basePriceMinor=int(deed["basePriceMinor"]),
        technologyFeeMinor=int(deed["technologyFeeMinor"]),
        grossPriceMinor=int(deed["grossPriceMinor"]),
        quoteExpiresAt=int(artifact.quote_expires_at),
        refundDeadline=int(series["terms"]["refundDeadline"]),
    )


@router.post(
    "/{terms_hash}/native/complete",
    response_model=CompleteNativeVoucherResponse,
)
async def complete_native_voucher(
    terms_hash: str,
    body: CompleteNativeVoucherRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> CompleteNativeVoucherResponse:
    require_presale_writes(settings)
    require_operation_gate(settings, "presale")
    series, issued, artifact, approved, deed = _load_native_voucher_context(
        terms_hash=terms_hash,
        purchase_id=body.purchase_id,
        request=request,
        settings=settings,
        store=store,
        authorization=authorization,
    )
    try:
        from .wallet_offer_worker import run_offer_job
        buyer_offer = await run_offer_job(
            "payment", encoded=body.buyer_offer,
            signature_hex=body.aggregated_signature, network=settings.network,
            dummy_spends=0, asset_id=None,
        )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    payment_coin = buyer_offer.coin_spends()[0].coin
    payment_record = await request.app.state.coinset.get_coin_record_by_name(
        _hex32(payment_coin.name())
    )
    if not _record_is_unspent_coin(payment_record, payment_coin):
        raise HTTPException(
            status_code=409,
            detail="The XCH payment coin is no longer confirmed and unspent.",
        )
    global_payment_id = _native_global_payment_id(
        payment_coin=payment_coin,
        artifact=artifact,
        terms_hash=_b32(series["termsHash"]),
    )
    commitment = _voucher_commitment(
        series=series,
        deed=deed,
        artifact=artifact,
        original_payer=_hex32(payment_coin.puzzle_hash),
        global_payment_id=_hex32(global_payment_id),
        approved_vault=approved,
        external_escrow_contract=bytes32.zeros,
    )
    terms = _series_program(series["terms"])
    state = _chain_series_state(series)
    chain = series["chainState"]
    series_coin = await _confirmed_series_coin(
        request.app.state.coinset,
        str(chain.get("currentCoinId") or ""),
    )
    try:
        purchase_launcher = await run_offer_job(
            "voucher",
            buyer_offer=buyer_offer,
            terms=terms,
            state=state,
            series_coin=series_coin,
            voucher=commitment,
            purchase=artifact,
        )
        lineage = LineageProof(
            _b32(chain["lineageParentName"], nonzero=True),
            (
                _b32(chain["lineageInnerPuzzleHash"], nonzero=True)
                if chain.get("lineageInnerPuzzleHash")
                else None
            ),
            uint64(1),
        )
        payment_puzzle = curry_xch_escrow(
            terms=terms,
            voucher=commitment,
            purchase=artifact,
        )
        provisional = build_voucher_issuance_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=lineage,
            voucher=commitment,
            purchase_launcher_coin=purchase_launcher,
            payment_puzzle=payment_puzzle,
            payment_amount=int(artifact.rail_amount),
            signer_indices=tuple(range(settings.zkpassport_validator_threshold)),
        )
        genesis = load_signed_public_artifact(settings)
        claim = VoucherIssuanceClaim(
            network=settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=_voucher_commitment_json(commitment),
            purchase_artifact=issued.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            purchase_launcher_coin_id=_hex32(purchase_launcher.name()),
            payment_evidence={
                "source": {
                    "chain": "chia",
                    "paymentCoinId": _hex32(payment_coin.name()),
                }
            },
            buyer_offer=buyer_offer.to_bech32(),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_issuance_quorum(settings, claim)
        issuance = build_voucher_issuance_spends(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=lineage,
            voucher=commitment,
            purchase_launcher_coin=purchase_launcher,
            payment_puzzle=payment_puzzle,
            payment_amount=int(artifact.rail_amount),
            signer_indices=quorum.signer_indices,
        )
        if issuance.validator_message != provisional.validator_message:
            raise VoucherV2Error("voucher issuance changed after quorum selection")
    except (
        PaymentArtifactError,
        PublicArtifactError,
        ValidatorQuorumError,
        VoucherV2Error,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    bundle = WalletSpendBundle(
        [*buyer_offer.coin_spends(), *issuance.coin_spends],
        AugSchemeMPL.aggregate(
            [buyer_offer.aggregated_signature(), quorum.aggregated_signature]
        ),
    )
    result = await request.app.state.coinset.push_tx(bundle.to_json_dict())
    network_status = str(result.get("status") or "").upper()
    if not result.get("success") and network_status not in {"SUCCESS", "PENDING"}:
        raise HTTPException(
            status_code=502,
            detail="The atomic XCH voucher purchase was rejected by the Chia node.",
        )
    voucher_json = response_or_404(
        lambda: store.record_native_issuance_submission(
            series["termsHash"],
            artifact=artifact,
            issued_purchase=issued,
            approved_vault=approved,
            payment_coin=payment_coin,
            global_payment_id=_hex32(global_payment_id),
            commitment=commitment,
            spend_bundle_id=_hex32(bundle.name()),
            purchase_launcher_coin=purchase_launcher,
            voucher_launcher_id=_hex32(issuance.voucher_launcher_id),
            voucher_output_coin_id=_hex32(issuance.voucher_coin.name()),
            payment_commitment_coin_id=_hex32(issuance.payment_coin.name()),
            series_input_coin=series_coin,
            series_output_coin_id=_hex32(issuance.next_series_coin.name()),
        )
    )
    return CompleteNativeVoucherResponse(
        termsHash=series["termsHash"],
        purchaseId=_hex32(artifact.purchase_id),
        transactionId=_hex32(bundle.name()),
        status=network_status or "SUCCESS",
        signerIndices=list(quorum.signer_indices),
        voucher=voucher_json,
    )


@router.post("/{terms_hash}/vouchers", status_code=status.HTTP_410_GONE)
def purchase_voucher() -> None:
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="vouchers are issued only from confirmed payment evidence",
    )


@router.post("/{terms_hash}/vouchers/evidence", status_code=status.HTTP_201_CREATED)
def ingest_voucher_issuance_evidence(
    terms_hash: str,
    evidence: VoucherIssuanceEvidenceRequest,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    try:
        artifact, issued_purchase = _load_issued_purchase(settings, evidence)
        external_escrow_contract = _external_escrow_contract(
            settings, artifact, issued_purchase
        )
        approved = require_current_approved_vault(
            settings, _hex32(artifact.vault_launcher_id)
        )
    except (PaymentArtifactError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return response_or_404(
        lambda: store.ingest_payment(
            terms_hash,
            evidence,
            approved_vault=approved,
            issued_purchase=issued_purchase,
            external_escrow_contract=external_escrow_contract,
        )
    )


@router.get(
    "/{terms_hash}/vouchers/{serial}",
    dependencies=[Depends(require_admin_jwt)],
)
def get_voucher(
    terms_hash: str,
    serial: int,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
) -> dict[str, Any]:
    return response_or_404(lambda: store.voucher(terms_hash, serial))


@router.post(
    "/{terms_hash}/vouchers/{serial}/refund-request",
    response_model=PrepareVoucherRefundResponse,
)
async def request_voucher_refund(
    terms_hash: str,
    serial: int,
    request: Request,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PrepareVoucherRefundResponse:
    require_presale_writes(settings)
    require_operation_gate(settings, "presale")
    voucher = response_or_404(lambda: store.voucher(terms_hash, serial))
    session = verify_vault_session(settings, request, voucher["vaultLauncherId"])
    approved = require_current_approved_vault(settings, session.vault_launcher_id)
    if voucher["paymentRail"] == "BASE_SEPOLIA_USDC":
        raise HTTPException(
            status_code=409,
            detail="Base USDC refunds use the escrow refund coordinator.",
        )
    if voucher["paymentRail"] not in {"CHIA_XCH", "STRIPE_USD"}:
        raise HTTPException(
            status_code=409,
            detail="This voucher payment rail cannot use the refund flow.",
        )
    eligible = response_or_404(
        lambda: store.request_refund(
            terms_hash,
            serial,
            vault_launcher_id=session.vault_launcher_id,
        )
    )
    voucher_coin_id = _b32(eligible["voucherOutputCoinId"], nonzero=True)
    voucher_launcher_id = _b32(eligible["voucherLauncherId"], nonzero=True)
    series = response_or_404(lambda: store.get(terms_hash))
    series_coin_id = _b32(series["chainState"]["currentCoinId"], nonzero=True)
    current_timestamp = int(time.time())
    try:
        vault_coin, _lineage, record, _inner_hash, vault_spend, typed_data = (
            await _vault_refund_context(
                request=request,
                settings=settings,
                approved=approved,
                voucher_launcher_id=voucher_launcher_id,
                voucher_coin_id=voucher_coin_id,
                current_timestamp=current_timestamp,
            )
        )
    except (PublicArtifactError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return PrepareVoucherRefundResponse(
        termsHash=series["termsHash"],
        serial=serial,
        authType="chia_bls" if record.auth_type == AUTH_TYPE_BLS else "evm",
        vaultCoinId=_hex32(vault_coin.name()),
        voucherCoinId=_hex32(voucher_coin_id),
        seriesCoinId=_hex32(series_coin_id),
        currentTimestamp=current_timestamp,
        expiresAt=current_timestamp + REFUND_AUTH_MAX_AGE_SECONDS,
        coinSpends=(
            [_coin_spend_json(vault_spend)]
            if record.auth_type == AUTH_TYPE_BLS
            else []
        ),
        typedData=typed_data,
    )


@router.post(
    "/{terms_hash}/vouchers/{serial}/refund-complete",
    response_model=CompleteVoucherRefundResponse,
)
async def complete_voucher_refund(
    terms_hash: str,
    serial: int,
    body: CompleteVoucherRefundRequest,
    request: Request,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CompleteVoucherRefundResponse:
    require_presale_writes(settings)
    require_operation_gate(settings, "presale")
    voucher_json = response_or_404(lambda: store.voucher(terms_hash, serial))
    session = verify_vault_session(settings, request, voucher_json["vaultLauncherId"])
    approved = require_current_approved_vault(
        settings,
        session.vault_launcher_id,
        expected_current_coin_id=body.vault_coin_id,
    )
    series = response_or_404(lambda: store.get(terms_hash))
    response_or_404(
        lambda: store.request_refund(
            terms_hash,
            serial,
            vault_launcher_id=session.vault_launcher_id,
            now_seconds=body.current_timestamp,
        )
    )
    now = int(time.time())
    if abs(now - body.current_timestamp) > REFUND_AUTH_MAX_AGE_SECONDS:
        raise HTTPException(status_code=409, detail="Refund authorization expired.")
    expected_ids = {
        "voucher": str(voucher_json["voucherOutputCoinId"] or "").lower(),
        "series": str(series["chainState"]["currentCoinId"] or "").lower(),
    }
    if (
        voucher_json["paymentRail"] not in {"CHIA_XCH", "STRIPE_USD"}
        or body.voucher_coin_id.lower() != expected_ids["voucher"]
        or body.series_coin_id.lower() != expected_ids["series"]
    ):
        raise HTTPException(
            status_code=409,
            detail="Refund chain inputs changed after wallet review.",
        )
    try:
        is_stripe = voucher_json["paymentRail"] == "STRIPE_USD"
        terms = _series_program(series["terms"])
        stored_purchase = get_payment_purchase_store(
            settings.payment_purchase_db_path
        ).get(str(voucher_json["purchaseId"]))
        if is_stripe:
            voucher = voucher_commitment_v3_from_json(
                voucher_json["commitment"]
            )
            purchase = purchase_artifact_v3_from_json(
                stored_purchase.purchase_artifact
            )
            receipt_json = voucher_json.get("settlementReceipt")
            if not isinstance(receipt_json, dict):
                raise ValueError("Stripe voucher settlement receipt is missing")
            stripe_receipt = stripe_receipt_from_json(receipt_json)
            if stripe_receipt.artifact != purchase:
                raise ValueError("Stripe voucher receipt changed")
            terminal_evidence_hash = stripe_receipt.evidence.evidence_hash
        else:
            voucher = voucher_commitment_from_json(
                voucher_json["commitment"]
            )
            purchase = purchase_artifact_from_json(
                stored_purchase.purchase_artifact
            )
            stripe_receipt = None
            terminal_evidence_hash = None
        state = _chain_series_state(series)
        refund_action = _voucher_refund_action(
            series,
            now_seconds=body.current_timestamp,
        )
        if is_stripe and refund_action == VoucherAction.REFUND_EXPIRED:
            raise ValueError(
                "Expired Stripe vouchers are refunded automatically; no wallet "
                "signature is required"
            )
        series_coin, series_lineage = await _confirmed_coin_and_lineage(
            request.app.state.coinset,
            body.series_coin_id.lower(),
            "presale series coin",
        )
        voucher_coin, voucher_lineage = await _confirmed_coin_and_lineage(
            request.app.state.coinset,
            body.voucher_coin_id.lower(),
            "voucher coin",
        )
        payment_record = await request.app.state.coinset.get_coin_record_by_name(
            str(voucher_json["paymentCommitmentCoinId"])
        )
        payment_coin = _coin_from_record(payment_record)
        if (
            payment_coin is None
            or not _record_is_unspent_coin(payment_record, payment_coin)
            or _hex32(payment_coin.name())
            != str(voucher_json["paymentCommitmentCoinId"]).lower()
        ):
            raise ValueError("voucher receipt coin is not confirmed and unspent")
        (
            vault_coin,
            _vault_lineage,
            vault_record,
            vault_inner_hash,
            vault_spend,
            _typed_data,
        ) = await _vault_refund_context(
            request=request,
            settings=settings,
            approved=approved,
            voucher_launcher_id=_b32(voucher_json["voucherLauncherId"], nonzero=True),
            voucher_coin_id=voucher_coin.name(),
            current_timestamp=body.current_timestamp,
            owner_authorization=body.owner_authorization,
        )
        provisional = (
            build_stripe_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                artifact=purchase,
                voucher_launcher_id=_b32(
                    voucher_json["voucherLauncherId"], nonzero=True
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                receipt_coin=payment_coin,
                vault_coin_id=vault_coin.name(),
                vault_inner_puzzle_hash=vault_inner_hash,
                action=refund_action,
                terminal_evidence_hash=terminal_evidence_hash,
                signer_indices=tuple(
                    range(settings.zkpassport_validator_threshold)
                ),
            )
            if is_stripe and terminal_evidence_hash is not None
            else build_xch_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase=purchase,
                voucher_launcher_id=_b32(
                    voucher_json["voucherLauncherId"], nonzero=True
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                payment_coin=payment_coin,
                vault_coin_id=vault_coin.name(),
                vault_inner_puzzle_hash=vault_inner_hash,
                action=refund_action,
                signer_indices=tuple(
                    range(settings.zkpassport_validator_threshold)
                ),
            )
        )
        genesis = load_signed_public_artifact(settings)
        claim = VoucherTransitionClaim(
            network=settings.network,
            genesis_artifact_hash=str(genesis["artifactHash"]).lower(),
            series_terms=series["terms"],
            voucher_commitment=voucher_json["commitment"],
            purchase_artifact=stored_purchase.purchase_artifact,
            series_coin_id=_hex32(series_coin.name()),
            series_sold_count=state.sold_count,
            series_redeemed_count=state.redeemed_count,
            series_refunded_count=state.refunded_count,
            series_phase=int(state.phase),
            series_launched_at=state.launched_at,
            voucher_launcher_id=str(voucher_json["voucherLauncherId"]),
            voucher_coin_id=_hex32(voucher_coin.name()),
            payment_coin_id=_hex32(payment_coin.name()),
            vault_launcher_id=approved.launcher_id,
            vault_coin_id=_hex32(vault_coin.name()),
            vault_identity_attest_root=approved.identity_attest_root,
            vault_owner_auth_type=vault_record.auth_type,
            vault_owner_key="0x" + bytes(vault_record.owner_pubkey).hex(),
            owner_authorization=(
                "0x" + body.owner_authorization.removeprefix("0x").lower()
            ),
            current_timestamp=body.current_timestamp,
            action=int(refund_action),
            payment_evidence=(
                stripe_evidence_to_json(stripe_receipt.evidence)
                if stripe_receipt is not None
                else None
            ),
            external_settlement_evidence_hash=(
                _hex32(terminal_evidence_hash)
                if terminal_evidence_hash is not None
                else None
            ),
            external_validator_message=(
                _hex32(provisional.receipt_validator_message)
                if is_stripe
                else None
            ),
            validator_message=_hex32(provisional.validator_message),
        )
        quorum = await collect_voucher_transition_quorum(settings, claim)
        terminal = (
            build_stripe_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                artifact=purchase,
                voucher_launcher_id=_b32(
                    voucher_json["voucherLauncherId"], nonzero=True
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                receipt_coin=payment_coin,
                vault_coin_id=vault_coin.name(),
                vault_inner_puzzle_hash=vault_inner_hash,
                action=refund_action,
                terminal_evidence_hash=terminal_evidence_hash,
                signer_indices=quorum.signer_indices,
            )
            if is_stripe and terminal_evidence_hash is not None
            else build_xch_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase=purchase,
                voucher_launcher_id=_b32(
                    voucher_json["voucherLauncherId"], nonzero=True
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                payment_coin=payment_coin,
                vault_coin_id=vault_coin.name(),
                vault_inner_puzzle_hash=vault_inner_hash,
                action=refund_action,
                signer_indices=quorum.signer_indices,
            )
        )
        if terminal.validator_message != provisional.validator_message:
            raise VoucherV2Error("refund transition changed after quorum selection")
        owner_signature = (
            G2Element.from_bytes(
                _hex_bytes(body.owner_authorization, 96, "ownerAuthorization")
            )
            if vault_record.auth_type == AUTH_TYPE_BLS
            else G2Element()
        )
    except (
        KeyError,
        PaymentArtifactError,
        PaymentPurchaseNotFound,
        PublicArtifactError,
        ValidatorQuorumError,
        VoucherV2Error,
        VoucherV3Error,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    bundle = WalletSpendBundle(
        [vault_spend, *terminal.coin_spends],
        AugSchemeMPL.aggregate([owner_signature, quorum.aggregated_signature]),
    )
    next_vault_coin = Coin(
        vault_coin.name(),
        vault_coin.puzzle_hash,
        uint64(1),
    )
    if is_stripe:
        assert terminal_evidence_hash is not None
        if (
            request.app.state.protocol_submitter is None
            or request.app.state.kos_exact_executor is None
        ):
            raise HTTPException(
                status_code=503,
                detail="Stripe voucher settlement is not configured.",
            )
        try:
            execution, observed_at = await prepare_and_dispatch_stripe_terminal(
                store=store,
                submitter=request.app.state.protocol_submitter,
                exact_executor=request.app.state.kos_exact_executor,
                terms_hash=series["termsHash"],
                serial=serial,
                mode="REFUND_OWNER",
                voucher_action=int(refund_action),
                purchase_id=purchase.purchase_id,
                artifact_hash=purchase.artifact_hash,
                claim_hash=terminal.validator_message,
                signer_indices=quorum.signer_indices,
                protocol_bundle=bundle,
                expected_outputs={
                    "series": terminal.next_series_coin,
                    "terminalVoucher": terminal.terminal_voucher_coin,
                    "vault": next_vault_coin,
                },
                bindings={
                    "seriesInputCoinId": _hex32(series_coin.name()),
                    "vaultInputCoinId": _hex32(vault_coin.name()),
                    "externalSettlementEvidenceHash": _hex32(
                        terminal_evidence_hash
                    ),
                },
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=502,
                detail="The exact Stripe voucher refund was not accepted.",
            ) from exc
        prepared = execution["prepared"]
        roles = execution["outputRoles"]
        submitted = response_or_404(
            lambda: store.record_stripe_refund_submission(
                series["termsHash"],
                serial,
                action=refund_action,
                spend_bundle_id=str(prepared["spendBundleId"]),
                external_settlement_evidence_hash=_hex32(
                    terminal_evidence_hash
                ),
                terminal_voucher_coin_id=str(roles["terminalVoucher"]),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=str(roles["series"]),
                vault_input_coin_id=_hex32(vault_coin.name()),
                vault_output_coin_id=str(roles["vault"]),
                execution_observed_at=observed_at,
            )
        )
        transaction_id = str(prepared["spendBundleId"])
        network_status = "MEMPOOL"
    else:
        result = await request.app.state.coinset.push_tx(bundle.to_json_dict())
        network_status = str(result.get("status") or "").upper()
        if not result.get("success") and network_status not in {"SUCCESS", "PENDING"}:
            raise HTTPException(
                status_code=502,
                detail="The atomic voucher refund was rejected by the Chia node.",
            )
        submitted = response_or_404(
            lambda: store.record_native_refund_submission(
                series["termsHash"],
                serial,
                action=refund_action,
                spend_bundle_id=_hex32(bundle.name()),
                refund_output_coin_id=_hex32(
                    terminal.settlement_coin.name()
                ),
                terminal_voucher_coin_id=_hex32(
                    terminal.terminal_voucher_coin.name()
                ),
                series_input_coin_id=_hex32(series_coin.name()),
                series_output_coin_id=_hex32(
                    terminal.next_series_coin.name()
                ),
                vault_input_coin_id=_hex32(vault_coin.name()),
                vault_output_coin_id=_hex32(next_vault_coin.name()),
            )
        )
        transaction_id = _hex32(bundle.name())
    return CompleteVoucherRefundResponse(
        termsHash=series["termsHash"],
        serial=serial,
        transactionId=transaction_id,
        status=network_status or "SUCCESS",
        signerIndices=list(quorum.signer_indices),
        voucher=submitted,
    )


@router.post("/{terms_hash}/vouchers/{serial}/refund-evidence")
def ingest_voucher_refund_evidence(
    terms_hash: str,
    serial: int,
    evidence: RefundEvidenceRequest,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    return response_or_404(
        lambda: store.complete_refund(terms_hash, serial, evidence)
    )


@router.post("/{terms_hash}/vouchers/{serial}/delivery-evidence")
def ingest_voucher_delivery_evidence(
    terms_hash: str,
    serial: int,
    evidence: DeliveryEvidenceRequest,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    return response_or_404(
        lambda: store.complete_delivery(terms_hash, serial, evidence)
    )


@router.post(
    "/{terms_hash}/launch",
    dependencies=[
        Depends(require_admin_operation("presale.launch")),
        Depends(require_presale_writes),
    ],
)
async def launch_presale(
    terms_hash: str,
    body: LaunchRequest,
    request: Request,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    collections: Annotated[CollectionStore, Depends(get_collection_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    del body
    series = response_or_404(lambda: store.get(terms_hash))
    collection = response_or_404(lambda: collections.get(series["collectionId"]))
    try:
        return await _submit_series_phase_transition(
            request=request,
            settings=settings,
            store=store,
            series=series,
            transition=SeriesTransition.LAUNCH,
            collection=collection,
        )
    except (
        PublicArtifactError,
        ValidatorQuorumError,
        VoucherV2Error,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/{terms_hash}/cancel",
    dependencies=[
        Depends(require_admin_operation("presale.cancel")),
        Depends(require_presale_writes),
    ],
)
async def cancel_presale(
    terms_hash: str,
    body: CancelRequest,
    request: Request,
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    series = response_or_404(lambda: store.get(terms_hash))
    try:
        return await _submit_series_phase_transition(
            request=request,
            settings=settings,
            store=store,
            series=series,
            transition=SeriesTransition.CANCEL,
            cancel_reason=body.reason,
        )
    except (
        PublicArtifactError,
        ValidatorQuorumError,
        VoucherV2Error,
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/reconcile/expired")
def reconcile_expired_presales(
    store: Annotated[PresaleStore, Depends(get_presale_store)],
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> dict[str, Any]:
    _require_ingest(settings, authorization)
    changed = store.reconcile()
    return {"changed": changed, "count": len(changed)}


def _voucher_rail(rail: PaymentRail) -> VoucherPaymentRail:
    if rail == PaymentRail.EVM_TEST_USD:
        return VoucherPaymentRail.BASE_SEPOLIA_USDC
    if rail == PaymentRail.CHIA_XCH:
        return VoucherPaymentRail.CHIA_XCH
    raise ValueError("unsupported voucher payment rail")


def _voucher_rail_name(rail: PaymentRail) -> Literal["BASE_SEPOLIA_USDC", "CHIA_XCH"]:
    return (
        "BASE_SEPOLIA_USDC"
        if _voucher_rail(rail) == VoucherPaymentRail.BASE_SEPOLIA_USDC
        else "CHIA_XCH"
    )


def _external_escrow_contract(
    settings: Settings, artifact: Any, issued_purchase: StoredPaymentPurchase
) -> bytes32:
    if artifact.rail == PaymentRail.CHIA_XCH:
        return bytes32.zeros
    message = issued_purchase.external_message
    if not isinstance(message, dict):
        raise ValueError("Base payment has not passed authenticated escrow verification")
    profile = message.get("gatewayProfile")
    token = settings.payment_evm_usdc_tokens.get(str(artifact.rail_chain_id))
    if not isinstance(profile, str) or token is None:
        raise ValueError("Base escrow deployment evidence is unavailable")
    evidence = load_omnichain_evidence(
        settings,
        chain_id=artifact.rail_chain_id,
        token_address=token,
        gateway_profile=profile,
    )
    source = message.get("source")
    if (
        not isinstance(source, dict)
        or str(source.get("spoke") or "").lower() != evidence.spoke_address
        or int(source.get("chainId") or 0) != artifact.rail_chain_id
        or int(source.get("confirmations") or 0) < evidence.confirmations
    ):
        raise ValueError("Base payment provenance does not match reviewed escrow evidence")
    return _evm_address_b32(evidence.spoke_address)


def _evm_address_b32(value: str) -> bytes32:
    normalized = value.lower().removeprefix("0x")
    if len(normalized) != 40:
        raise ValueError("EVM address must contain 20 bytes")
    try:
        return bytes32.fromhex("00" * 12 + normalized)
    except ValueError as exc:
        raise ValueError("EVM address is not hexadecimal") from exc


def _b32(value: object, *, nonzero: bool = False) -> bytes32:
    text = str(value or "").lower().removeprefix("0x")
    if len(text) != 64:
        raise ValueError("value must be a 32-byte hexadecimal string")
    try:
        result = bytes32.fromhex(text)
    except ValueError as exc:
        raise ValueError("value must be a 32-byte hexadecimal string") from exc
    if nonzero and result == bytes32.zeros:
        raise ValueError("bytes32 commitment cannot be zero")
    return result


def _pubkey(value: object) -> bytes:
    try:
        result = bytes.fromhex(str(value).removeprefix("0x"))
    except ValueError as exc:
        raise ValueError("validator public key is invalid hex") from exc
    if len(result) != 48:
        raise ValueError("validator public key must be 48 bytes")
    return result


def _hex32(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _hex_bytes(value: str, size: int, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return raw


def _positive_int(value: object, label: str) -> int:
    parsed = _nonnegative_int(value, label)
    if parsed == 0:
        raise ValueError(f"{label} must be positive")
    return parsed


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not str(value).isdecimal():
        raise ValueError(f"{label} must be an unsigned integer")
    parsed = int(str(value))
    if parsed > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{label} exceeds uint64")
    return parsed


def _stripe_rehearsal_lane(
    row: sqlite3.Row,
    artifact_json: dict[str, Any],
) -> dict[str, Any]:
    receipt_json = json.loads(row["settlement_receipt_json"] or "null")
    execution_json = json.loads(row["terminal_exact_execution_json"] or "null")
    if not isinstance(receipt_json, dict) or not isinstance(execution_json, dict):
        raise ValueError("completed Stripe voucher lacks canonical settlement evidence")
    artifact = purchase_artifact_v3_from_json(artifact_json)
    receipt = stripe_receipt_from_json(receipt_json)
    execution = parse_stripe_terminal_execution(
        execution_json,
        expected_purchase_id=artifact.purchase_id,
        expected_artifact_hash=artifact.artifact_hash,
    )
    issuance_signers = _validator_signer_indices(
        json.loads(row["issuance_signer_indices_json"] or "null")
    )
    terminal_signers = _validator_signer_indices(execution["signerIndices"])
    evidence = receipt.evidence
    if (
        receipt.artifact != artifact
        or row["purchase_id"] != _hex32(artifact.purchase_id)
        or row["payment_evidence_id"] != evidence.event_id
        or row["deed_launcher_id"] != _hex32(artifact.deed_launcher_id)
        or row["vault_launcher_id"] != _hex32(artifact.vault_launcher_id)
        or row["base_price_minor"] != artifact.base_amount_minor
        or row["technology_fee_minor"] != artifact.technology_fee_minor
        or row["processing_charge_minor"] != evidence.processing_charge_minor
        or evidence.amount_minor
        != artifact.subtotal_minor + evidence.processing_charge_minor
        or row["issuance_confirmed_height"] is None
        or row["terminal_execution_observed_at"] is None
    ):
        raise ValueError("completed Stripe voucher evidence changed after settlement")
    prepared = execution["prepared"]
    roles = execution["outputRoles"]
    fee_mojos = int(prepared["feeMojos"])
    if fee_mojos < 1:
        raise ValueError("Stripe voucher rehearsal did not use the bounded fee till")
    common = {
        "stripeAccountId": evidence.stripe_account_id,
        "livemode": evidence.livemode,
        "success": True,
        "purchaseId": _hex32(artifact.purchase_id),
        "artifactHash": _hex32(artifact.artifact_hash),
        "paymentIntentId": evidence.payment_intent_id,
        "eventId": evidence.event_id,
        "baseAmountMinor": str(artifact.base_amount_minor),
        "technologyFeeMinor": str(artifact.technology_fee_minor),
        "processingChargeMinor": str(evidence.processing_charge_minor),
        "amountMinor": str(evidence.amount_minor),
        "approvedVaultLauncherId": _hex32(artifact.vault_launcher_id),
        "deedLauncherId": _hex32(artifact.deed_launcher_id),
        "zkPassportRoot": _hex32(artifact.zkpassport_root),
        "settlementReceiptHash": _hex32(receipt.receipt_hash),
        "signerIndices": terminal_signers,
        "voucher": {
            "serial": int(row["serial"]),
            "signerIndices": issuance_signers,
            "issuanceBundleId": row["issuance_bundle_id"],
            "voucherCoinId": row["voucher_output_coin_id"],
            "paymentCommitmentCoinId": row["payment_commitment_coin_id"],
            "issuanceConfirmedHeight": int(row["issuance_confirmed_height"]),
        },
        "execution": {
            "schema": execution["schema"],
            "mode": execution["mode"],
            "action": int(execution["request"]["action"]),
            "spendBundleId": prepared["spendBundleId"],
            "feeCoinId": prepared["feeCoinId"],
            "feeMojos": str(fee_mojos),
            "mempoolObservedAt": int(row["terminal_execution_observed_at"]),
            "outputRoles": dict(roles),
        },
    }
    if row["state"] == "REDEEMED":
        chain = {
            "confirmationHeight": int(row["redemption_confirmed_height"] or 0),
            "deedOutputCoinId": row["redemption_deed_output_coin_id"],
            "seriesOutputCoinId": row["redemption_series_output_coin_id"],
            "terminalVoucherCoinId": row["redemption_terminal_voucher_coin_id"],
            "coordinationCoinId": row["redemption_treasury_output_coin_id"],
        }
    elif row["state"] == "REFUNDED":
        chain = {
            "confirmationHeight": int(row["refund_confirmed_height"] or 0),
            "seriesOutputCoinId": row["refund_series_output_coin_id"],
            "terminalVoucherCoinId": row["terminal_voucher_coin_id"],
            "vaultOutputCoinId": row["refund_vault_output_coin_id"],
        }
    else:
        raise ValueError("Stripe rehearsal voucher is not terminal")
    role_map = {
        "deedOutputCoinId": "deed",
        "seriesOutputCoinId": "series",
        "terminalVoucherCoinId": "terminalVoucher",
        "coordinationCoinId": "coordination",
        "vaultOutputCoinId": "vault",
    }
    if chain["confirmationHeight"] < 1 or any(
        not value
        or (field != "confirmationHeight" and value != roles[role_map[field]])
        for field, value in chain.items()
    ):
        raise ValueError("confirmed Stripe voucher outputs differ from KoS execution")
    return {**common, "chain": chain}


def _validator_signer_indices(value: object) -> list[int]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("validator signer indices must be a sequence")
    normalized = list(value)
    if (
        len(normalized) < 2
        or len(normalized) > 3
        or any(isinstance(item, bool) or not isinstance(item, int) for item in normalized)
        or normalized != sorted(normalized)
        or len(set(normalized)) != len(normalized)
        or any(item < 0 or item > 2 for item in normalized)
    ):
        raise ValueError("validator signer indices must be a unique ordered 2-of-3 quorum")
    return normalized


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


__all__ = [
    "BASE_SETTLEMENT_AUTHORIZATION_SCHEMA",
    "BaseSettlementRelayEvidenceRequest",
    "BaseVoucherRefundChainEvidence",
    "CancelRequest",
    "ChainEvidenceRequest",
    "DeliveryEvidenceRequest",
    "LaunchRequest",
    "PresaleCreateRequest",
    "PresaleStore",
    "VoucherIssuanceEvidenceRequest",
    "VoucherRedemptionChainEvidence",
    "VoucherRefundChainEvidence",
    "VoucherSeriesPhaseChainEvidence",
    "build_series_terms",
]
