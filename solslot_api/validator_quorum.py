"""Private 2-of-3 validator coordinator for Chia credential stamps."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from solslot_puzzles.zkpassport_bridge_driver import require_genesis_validator_set
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseDeliveryKind,
    STRIPE_PAYMENT_PROVIDER_ID,
    build_purchase_batch_settlement_receipt_v1,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_from_json,
    purchase_batch_from_json,
    stripe_settlement_evidence_from_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    PurchaseBatchSettlementTermsV1,
    StripeSettlementTermsV1,
    purchase_batch_settlement_authorization_message,
    stripe_settlement_authorization_message,
)

from .config import Settings
from .external_settlement import (
    build_base_batch_settlement_receipt,
    build_base_settlement_receipt,
)
from .faucet import AGG_SIG_ME_DATA


logger = logging.getLogger(__name__)


class ValidatorQuorumError(RuntimeError):
    """Raised when independent validator signatures cannot reach quorum."""


def _hex(value: str, size: int, field: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    try:
        raw = bytes.fromhex(normalized[2:])
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise ValueError(f"{field} must be {size} bytes")
    return normalized


def base_settlement_evidence_hash(evidence: dict[str, Any]) -> str:
    """Hash the authenticated Base deposit evidence used for terminal settlement."""
    encoded = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(encoded).hexdigest()


class ValidatorClaim(BaseModel):
    """All public evidence a signer must independently revalidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    artifact_hash: str
    vault_launcher_id: str
    current_vault_coin_id: str
    owner_key: str
    owner_auth_type: int = Field(..., ge=1, le=3)
    owner_authorization: str
    owner_authorization_hash: str
    current_timestamp: int = Field(..., ge=1)
    evm_transaction_hash: str
    evm_block_number: int = Field(..., ge=0)
    emitter_address: str
    policy_version: int = Field(..., ge=2)
    identity_attest_root: str
    attestation_leaf_hash: str
    scoped_nullifier: str
    nullifier_type: int = Field(..., ge=0)
    service_scope_hash: str
    service_subscope_hash: str
    proof_timestamp: int = Field(..., ge=1)
    bridge_policy_hash: str
    bridge_parent_id: str
    bridge_amount: int = Field(..., gt=0)
    bridge_coin_id: str
    validator_message: str

    @field_validator(
        "artifact_hash",
        "vault_launcher_id",
        "current_vault_coin_id",
        "owner_authorization_hash",
        "identity_attest_root",
        "attestation_leaf_hash",
        "scoped_nullifier",
        "service_scope_hash",
        "service_subscope_hash",
        "bridge_policy_hash",
        "bridge_parent_id",
        "bridge_coin_id",
        "validator_message",
    )
    @classmethod
    def _hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator("evm_transaction_hash")
    @classmethod
    def _tx_hash(cls, value: str) -> str:
        return _hex(value, 32, "evm_transaction_hash")

    @field_validator("emitter_address")
    @classmethod
    def _address(cls, value: str) -> str:
        return _hex(value, 20, "emitter_address")

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(f"unsupported Chia network: {self.network}")
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.bridge_coin_id[2:])
            + additional_data
        )


class PermitValidatorClaim(ValidatorClaim):
    """Explicit selected-deployment claim; legacy claim hashes stay unchanged."""

    claim_version: Literal["solslot.enrollment-permit-claim.v1"]
    enrollment_permit: dict[str, Any]
    permit_issuer_signature: str

    @field_validator("enrollment_permit")
    @classmethod
    def _canonical_permit(cls, value: dict[str, Any]) -> dict[str, Any]:
        from solslot_puzzles.enrollment_permit import EnrollmentPermit
        return EnrollmentPermit.from_wire(value).to_wire()

    @field_validator("permit_issuer_signature")
    @classmethod
    def _canonical_issuer_signature(cls, value: str) -> str:
        import re
        if re.fullmatch(r"0x[0-9a-f]{130}", value) is None:
            raise ValueError("issuer signature must be canonical 65-byte hex")
        return value


class PrimaryPurchaseDeedItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deed_launcher_id: str
    deed_coin_id: str
    deed_puzzle_hash: str
    smart_deed_inner_hash: str
    reservation_expires_at: int = Field(..., ge=1)

    @field_validator(
        "deed_launcher_id",
        "deed_coin_id",
        "deed_puzzle_hash",
        "smart_deed_inner_hash",
    )
    @classmethod
    def _hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)


class PrimaryPurchaseClaim(BaseModel):
    """Public evidence for one governed native SmartDeed delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    buyer_offer: str = Field(..., min_length=16, max_length=2_000_000)
    deed_coin_id: str
    deed_puzzle_hash: str
    smart_deed_inner_hash: str
    reservation_expires_at: int = Field(..., ge=1)
    protocol_puzzle_hash: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str
    deed_items: tuple[PrimaryPurchaseDeedItem, ...] = ()

    @field_validator(
        "genesis_artifact_hash",
        "deed_coin_id",
        "deed_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
    )
    @classmethod
    def _purchase_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_credential_owner(self) -> "PrimaryPurchaseClaim":
        expected_size = {1: 48, 3: 33}.get(self.credential_owner_auth_type)
        if expected_size is None:
            raise ValueError("credential owner auth type must be BLS or secp256k1")
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        value = self.purchase_artifact.get("purchaseId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("purchase artifact has no purchase ID")
        return _hex(value, 32, "purchaseId")

    def purchase_artifact_hash(self) -> str:
        value = self.purchase_artifact.get("artifactHash")
        if value is None:
            value = self.purchase_artifact.get("batchHash")
        if not isinstance(value, str):
            raise ValidatorQuorumError("purchase artifact has no artifact hash")
        return _hex(value, 32, "artifactHash or batchHash")

    def delivery_items(self) -> tuple[PrimaryPurchaseDeedItem, ...]:
        if self.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            if not self.deed_items:
                raise ValidatorQuorumError("purchase batch has no deed evidence")
            return self.deed_items
        if self.deed_items:
            raise ValidatorQuorumError(
                "single purchase cannot carry batch deed evidence"
            )
        return (
            PrimaryPurchaseDeedItem(
                deed_launcher_id=str(
                    self.purchase_artifact.get("deedLauncherId") or ""
                ),
                deed_coin_id=self.deed_coin_id,
                deed_puzzle_hash=self.deed_puzzle_hash,
                smart_deed_inner_hash=self.smart_deed_inner_hash,
                reservation_expires_at=self.reservation_expires_at,
            ),
        )

    def delivery_coin_id(self) -> str:
        return self.delivery_items()[0].deed_coin_id

    def signature_messages(self) -> tuple[bytes, ...]:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        if self.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            batch = purchase_batch_from_json(self.purchase_artifact)
            items = self.delivery_items()
            if len(items) != len(batch.artifacts):
                raise ValidatorQuorumError(
                    "purchase batch deed evidence is incomplete"
                )
            return tuple(
                bytes(artifact.artifact_hash)
                + bytes.fromhex(item.deed_coin_id[2:])
                + additional_data
                for artifact, item in zip(batch.artifacts, items, strict=True)
            )
        return (
            bytes.fromhex(self.purchase_artifact_hash()[2:])
            + bytes.fromhex(self.deed_coin_id[2:])
            + additional_data,
        )

    def signature_message(self) -> bytes:
        messages = self.signature_messages()
        if len(messages) != 1:
            raise ValidatorQuorumError(
                "batch purchase uses aggregate validator signature messages"
            )
        return messages[0]


class InventoryReservationClaim(BaseModel):
    """Evidence for the one chain-authoritative reservation of a SmartDeed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    available_coin_id: str
    available_puzzle_hash: str
    smart_deed_inner_hash: str
    protocol_puzzle_hash: str
    reservation_expires_at: int = Field(..., ge=1)
    validator_message: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str

    @field_validator(
        "genesis_artifact_hash",
        "available_coin_id",
        "available_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "validator_message",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
    )
    @classmethod
    def _reservation_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_credential_owner(self) -> "InventoryReservationClaim":
        expected_size = {1: 48, 3: 33}.get(self.credential_owner_auth_type)
        if expected_size is None:
            raise ValueError("credential owner auth type must be BLS or secp256k1")
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        value = self.purchase_artifact.get("purchaseId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("purchase artifact has no purchase ID")
        return _hex(value, 32, "purchaseId")

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.available_coin_id[2:])
            + additional_data
        )


class StripeSettlementClaim(BaseModel):
    """Evidence for one exact paid external protocol-asset delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    purchase_artifact: dict[str, Any]
    stripe_evidence: dict[str, Any] | None = None
    base_evidence: dict[str, Any] | None = None
    base_result_authorization_puzzle_hash: str | None = None
    receipt_coin_id: str
    receipt_puzzle_hash: str
    deed_coin_id: str | None = None
    deed_puzzle_hash: str | None = None
    smart_deed_inner_hash: str | None = None
    reservation_expires_at: int | None = Field(None, ge=1)
    sgt_sale_coin_id: str | None = None
    sgt_sale_puzzle_hash: str | None = None
    governance_proposal_id: str | None = Field(None, min_length=8, max_length=96)
    governance_bill_clvm_hex: str | None = Field(
        None,
        pattern=r"^(?:0x)?[0-9a-fA-F]+$",
        max_length=8194,
    )
    protocol_puzzle_hash: str
    credential_vault_coin_id: str
    credential_identity_root: str
    credential_policy_version: int = Field(..., ge=2)
    credential_bridge_policy_hash: str
    credential_owner_auth_type: int
    credential_owner_key: str
    deed_items: tuple[PrimaryPurchaseDeedItem, ...] = ()

    @field_validator(
        "genesis_artifact_hash",
        "receipt_coin_id",
        "receipt_puzzle_hash",
        "protocol_puzzle_hash",
        "credential_vault_coin_id",
        "credential_identity_root",
        "credential_bridge_policy_hash",
    )
    @classmethod
    def _stripe_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator(
        "deed_coin_id",
        "deed_puzzle_hash",
        "smart_deed_inner_hash",
        "sgt_sale_coin_id",
        "sgt_sale_puzzle_hash",
        "base_result_authorization_puzzle_hash",
    )
    @classmethod
    def _optional_stripe_hex32(cls, value: str | None, info) -> str | None:
        return None if value is None else _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_credential_owner(self) -> "StripeSettlementClaim":
        expected_size = {1: 48, 3: 33}.get(self.credential_owner_auth_type)
        if expected_size is None:
            raise ValueError("credential owner auth type must be BLS or secp256k1")
        normalized = _hex(
            self.credential_owner_key,
            expected_size,
            "credential_owner_key",
        )
        object.__setattr__(self, "credential_owner_key", normalized)
        if self.credential_owner_auth_type == 1:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        is_batch = (
            self.purchase_artifact.get("schema")
            == "solslot.purchase-batch.v1"
        )
        batch = (
            purchase_batch_from_json(self.purchase_artifact)
            if is_batch
            else None
        )
        purchase = (
            batch.artifacts[0]
            if batch is not None
            else purchase_artifact_v3_from_json(self.purchase_artifact)
        )
        if purchase.rail == PaymentRail.STRIPE:
            if (
                self.stripe_evidence is None
                or self.base_evidence is not None
                or self.base_result_authorization_puzzle_hash is not None
            ):
                raise ValueError("Stripe claim requires only Stripe evidence")
        elif purchase.rail == PaymentRail.EVM_TEST_USD:
            if (
                self.base_evidence is None
                or self.stripe_evidence is not None
                or self.base_result_authorization_puzzle_hash is None
            ):
                raise ValueError("Base claim requires only Base evidence")
        else:
            raise ValueError("external claim has an unsupported payment rail")
        if purchase.delivery_kind == PurchaseDeliveryKind.SMARTDEED:
            if any(
                value is not None
                for value in (
                    self.sgt_sale_coin_id,
                    self.sgt_sale_puzzle_hash,
                    self.governance_proposal_id,
                    self.governance_bill_clvm_hex,
                )
            ):
                raise ValueError("SmartDeed claim has inconsistent delivery evidence")
            if batch is not None:
                if any(
                    value is not None
                    for value in (
                        self.deed_coin_id,
                        self.deed_puzzle_hash,
                        self.smart_deed_inner_hash,
                        self.reservation_expires_at,
                    )
                ):
                    raise ValueError(
                        "SmartDeed batch cannot carry singular deed evidence"
                    )
                if len(self.deed_items) != len(batch.artifacts):
                    raise ValueError(
                        "SmartDeed batch claim has incomplete deed evidence"
                    )
                if any(
                    item.deed_launcher_id
                    != "0x" + bytes(artifact.deed_launcher_id).hex()
                    for artifact, item in zip(
                        batch.artifacts,
                        self.deed_items,
                        strict=True,
                    )
                ):
                    raise ValueError(
                        "SmartDeed batch claim changes canonical deed order"
                    )
            elif self.deed_items or None in {
                self.deed_coin_id,
                self.deed_puzzle_hash,
                self.smart_deed_inner_hash,
                self.reservation_expires_at,
            }:
                raise ValueError("single SmartDeed claim requires one deed")
        elif purchase.delivery_kind == PurchaseDeliveryKind.SGT:
            if None in {
                self.sgt_sale_coin_id,
                self.sgt_sale_puzzle_hash,
                self.governance_proposal_id,
                self.governance_bill_clvm_hex,
            } or any(
                value is not None
                for value in (
                    self.deed_coin_id,
                    self.deed_puzzle_hash,
                    self.smart_deed_inner_hash,
                    self.reservation_expires_at,
                )
            ):
                raise ValueError("SGT claim has inconsistent delivery evidence")
        else:
            raise ValueError("external claim has an unsupported delivery kind")
        return self

    def delivery_coin_id(self) -> str:
        value = self.deed_coin_id or self.sgt_sale_coin_id
        if value is None:
            raise ValidatorQuorumError("external claim has no delivery coin")
        return value

    def delivery_items(self) -> tuple[PrimaryPurchaseDeedItem, ...]:
        if self.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            if not self.deed_items:
                raise ValidatorQuorumError(
                    "external purchase batch has no deed evidence"
                )
            return self.deed_items
        if self.deed_items:
            raise ValidatorQuorumError(
                "single external purchase cannot carry batch deed evidence"
            )
        if None in {
            self.deed_coin_id,
            self.deed_puzzle_hash,
            self.smart_deed_inner_hash,
            self.reservation_expires_at,
        }:
            return ()
        return (
            PrimaryPurchaseDeedItem(
                deed_launcher_id=str(
                    self.purchase_artifact.get("deedLauncherId") or ""
                ),
                deed_coin_id=str(self.deed_coin_id),
                deed_puzzle_hash=str(self.deed_puzzle_hash),
                smart_deed_inner_hash=str(self.smart_deed_inner_hash),
                reservation_expires_at=int(self.reservation_expires_at),
            ),
        )

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def purchase_id(self) -> str:
        value = self.purchase_artifact.get("purchaseId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("purchase artifact has no purchase ID")
        return _hex(value, 32, "purchaseId")

    def signature_messages(
        self,
        validator_pubkeys: tuple[bytes, bytes, bytes],
    ) -> tuple[bytes, ...]:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        batch = (
            purchase_batch_from_json(self.purchase_artifact)
            if self.purchase_artifact.get("schema")
            == "solslot.purchase-batch.v1"
            else None
        )
        purchase = (
            batch.artifacts[0]
            if batch is not None
            else purchase_artifact_v3_from_json(self.purchase_artifact)
        )
        if batch is not None:
            if purchase.rail == PaymentRail.STRIPE:
                assert self.stripe_evidence is not None
                evidence = stripe_settlement_evidence_from_json(
                    self.stripe_evidence
                )
                receipt = build_purchase_batch_settlement_receipt_v1(
                    batch=batch,
                    provider_id=STRIPE_PAYMENT_PROVIDER_ID,
                    external_reference_hash=evidence.payment_reference_hash,
                    evidence_hash=evidence.evidence_hash,
                    observed_at=evidence.observed_at,
                    validator_pubkeys=validator_pubkeys,
                    collected_amount_minor=evidence.amount_minor,
                    processing_charge_minor=evidence.processing_charge_minor,
                )
            else:
                assert self.base_evidence is not None
                receipt = build_base_batch_settlement_receipt(
                    batch=batch,
                    evidence=self.base_evidence,
                    validator_pubkeys=validator_pubkeys,
                    result_authorization_puzzle_hash=bytes32.from_hexstr(
                        str(self.base_result_authorization_puzzle_hash)
                    ),
                )
            terms = PurchaseBatchSettlementTermsV1(
                receipt=receipt,
                validator_pubkeys=validator_pubkeys,
            )
            return (
                bytes(purchase_batch_settlement_authorization_message(terms))
                + bytes.fromhex(self.receipt_coin_id[2:])
                + additional_data,
            )
        if purchase.rail == PaymentRail.STRIPE:
            assert self.stripe_evidence is not None
            evidence = stripe_settlement_evidence_from_json(self.stripe_evidence)
            receipt = build_stripe_settlement_receipt_v1(
                artifact=purchase,
                evidence=evidence,
                validator_pubkeys=validator_pubkeys,
            )
        else:
            assert self.base_evidence is not None
            receipt = build_base_settlement_receipt(
                artifact=purchase,
                evidence=self.base_evidence,
                result_authorization_puzzle_hash=bytes32.from_hexstr(
                    str(self.base_result_authorization_puzzle_hash)
                ),
            )
        terms = StripeSettlementTermsV1(
            receipt=receipt,
            validator_pubkeys=validator_pubkeys,
        )
        return (
            bytes(stripe_settlement_authorization_message(terms))
            + bytes.fromhex(self.receipt_coin_id[2:])
            + additional_data,
        )


class VoucherIssuanceClaim(BaseModel):
    """Public evidence for one paid, chain-bound RC20 voucher issuance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    series_terms: dict[str, Any]
    voucher_commitment: dict[str, Any]
    purchase_artifact: dict[str, Any]
    series_coin_id: str
    series_sold_count: int = Field(..., ge=0)
    series_redeemed_count: int = Field(..., ge=0)
    series_refunded_count: int = Field(..., ge=0)
    series_phase: int = Field(..., ge=1, le=3)
    series_launched_at: int = Field(..., ge=0)
    purchase_launcher_coin_id: str
    payment_evidence: dict[str, Any]
    buyer_offer: str | None = Field(default=None, min_length=16, max_length=2_000_000)
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "series_coin_id",
        "purchase_launcher_coin_id",
        "validator_message",
    )
    @classmethod
    def _issuance_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def global_payment_id(self) -> str:
        value = self.voucher_commitment.get("globalPaymentId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("voucher has no global payment ID")
        return _hex(value, 32, "globalPaymentId")

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.series_coin_id[2:])
            + additional_data
        )


class VoucherSeriesPhaseClaim(BaseModel):
    """Chain evidence for one validator-governed series phase advance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    series_terms: dict[str, Any]
    series_coin_id: str
    series_sold_count: int = Field(..., ge=0)
    series_redeemed_count: int = Field(..., ge=0)
    series_refunded_count: int = Field(..., ge=0)
    series_phase: int = Field(..., ge=1, le=3)
    series_launched_at: int = Field(..., ge=0)
    transition: int = Field(..., ge=2, le=3)
    launch_anchor: int = Field(..., ge=0)
    deed_launcher_ids: list[str] = Field(default_factory=list, max_length=100_000)
    governed_deed_puzzle_hashes: list[str] = Field(
        default_factory=list,
        max_length=100_000,
    )
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "series_coin_id",
        "validator_message",
    )
    @classmethod
    def _phase_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator("deed_launcher_ids", "governed_deed_puzzle_hashes")
    @classmethod
    def _phase_hex32_list(cls, value: list[str], info) -> list[str]:
        return [_hex(item, 32, info.field_name) for item in value]

    @model_validator(mode="after")
    def _validate_phase_transition(self) -> "VoucherSeriesPhaseClaim":
        if self.transition not in {2, 3}:
            raise ValueError("series phase transition must launch or cancel")
        if self.transition == 2:
            if self.launch_anchor <= 0:
                raise ValueError("series launch requires a positive launch anchor")
            if not self.deed_launcher_ids:
                raise ValueError("series launch requires governed deed evidence")
            if len(self.deed_launcher_ids) != len(
                self.governed_deed_puzzle_hashes
            ):
                raise ValueError("series launch governed deed evidence is incomplete")
        elif (
            self.launch_anchor != 0
            or self.deed_launcher_ids
            or self.governed_deed_puzzle_hashes
        ):
            raise ValueError("series cancellation cannot carry launch evidence")
        if len(set(self.deed_launcher_ids)) != len(self.deed_launcher_ids):
            raise ValueError("series launch deed evidence contains duplicates")
        if len(set(self.governed_deed_puzzle_hashes)) != len(
            self.governed_deed_puzzle_hashes
        ):
            raise ValueError("series launch governed deed evidence contains duplicates")
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def signature_message(self) -> bytes:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        return (
            bytes.fromhex(self.validator_message[2:])
            + bytes.fromhex(self.series_coin_id[2:])
            + additional_data
        )


class VoucherTransitionClaim(BaseModel):
    """Evidence for one terminal RC20 voucher refund or redemption."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: str
    genesis_artifact_hash: str
    series_terms: dict[str, Any]
    voucher_commitment: dict[str, Any]
    purchase_artifact: dict[str, Any]
    series_coin_id: str
    series_sold_count: int = Field(..., ge=0)
    series_redeemed_count: int = Field(..., ge=0)
    series_refunded_count: int = Field(..., ge=0)
    series_phase: int = Field(..., ge=1, le=3)
    series_launched_at: int = Field(..., ge=0)
    voucher_launcher_id: str
    voucher_coin_id: str
    payment_coin_id: str
    vault_launcher_id: str
    vault_coin_id: str | None = None
    vault_identity_attest_root: str | None = None
    vault_owner_auth_type: int | None = None
    vault_owner_key: str | None = None
    owner_authorization: str = ""
    current_timestamp: int = Field(..., ge=1)
    action: int = Field(..., ge=1, le=4)
    deed_coin_id: str | None = None
    deed_puzzle_hash: str | None = None
    smart_deed_inner_hash: str | None = None
    protocol_puzzle_hash: str | None = None
    buyer_offer: str | None = Field(default=None, min_length=16, max_length=2_000_000)
    reservation_expires_at: int | None = Field(default=None, ge=1)
    payment_evidence: dict[str, Any] | None = None
    external_settlement_evidence_hash: str | None = None
    external_validator_message: str | None = None
    validator_message: str

    @field_validator(
        "genesis_artifact_hash",
        "series_coin_id",
        "voucher_launcher_id",
        "voucher_coin_id",
        "payment_coin_id",
        "vault_launcher_id",
        "validator_message",
    )
    @classmethod
    def _transition_hex32(cls, value: str, info) -> str:
        return _hex(value, 32, info.field_name)

    @field_validator(
        "deed_coin_id",
        "deed_puzzle_hash",
        "smart_deed_inner_hash",
        "protocol_puzzle_hash",
        "vault_coin_id",
        "vault_identity_attest_root",
        "external_settlement_evidence_hash",
        "external_validator_message",
    )
    @classmethod
    def _optional_transition_hex32(cls, value: str | None, info) -> str | None:
        return None if value is None else _hex(value, 32, info.field_name)

    @model_validator(mode="after")
    def _validate_owner_and_action(self) -> "VoucherTransitionClaim":
        if self.action not in {1, 2, 3, 4}:
            raise ValueError("voucher transition action is invalid")
        owner_fields = (
            self.vault_coin_id,
            self.vault_identity_attest_root,
            self.vault_owner_auth_type,
            self.vault_owner_key,
        )
        if self.action == 2:
            if any(value is not None for value in owner_fields):
                raise ValueError(
                    "expired refund cannot carry current vault ownership evidence"
                )
            if self.owner_authorization:
                raise ValueError("expired refund cannot request an owner signature")
        else:
            if any(value is None for value in owner_fields):
                raise ValueError("voucher transition requires current vault evidence")
            expected_size = {1: 48, 3: 33}.get(self.vault_owner_auth_type)
            if expected_size is None:
                raise ValueError("voucher vault owner must use BLS or secp256k1")
            normalized = _hex(
                self.vault_owner_key,  # type: ignore[arg-type]
                expected_size,
                "vault_owner_key",
            )
            object.__setattr__(self, "vault_owner_key", normalized)
            if self.vault_owner_auth_type == 1:
                G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        redemption_fields = (
            self.deed_coin_id,
            self.deed_puzzle_hash,
            self.smart_deed_inner_hash,
            self.protocol_puzzle_hash,
            self.buyer_offer,
        )
        is_stripe = (
            self.voucher_commitment.get("schema")
            == "solslot.voucher-commitment.v3"
        )
        if self.action == 3:
            if any(value is None for value in redemption_fields):
                raise ValueError("voucher redemption requires exact deed evidence")
            if is_stripe and self.reservation_expires_at is None:
                raise ValueError(
                    "Stripe voucher redemption requires its inventory reservation expiry"
                )
            if self.owner_authorization:
                raise ValueError("voucher redemption cannot request a second owner signature")
        elif self.action in {1, 4}:
            if any(value is not None for value in redemption_fields):
                raise ValueError("voucher refund cannot carry deed evidence")
            assert self.vault_owner_auth_type is not None
            auth_size = 96 if self.vault_owner_auth_type == 1 else 65
            object.__setattr__(
                self,
                "owner_authorization",
                _hex(self.owner_authorization, auth_size, "owner_authorization"),
            )
        else:
            if any(value is not None for value in redemption_fields):
                raise ValueError("voucher refund cannot carry deed evidence")
        if self.action != 3 and self.reservation_expires_at is not None:
            raise ValueError("voucher refund cannot carry inventory reservation data")
        if not is_stripe and self.reservation_expires_at is not None:
            raise ValueError(
                "legacy voucher transition cannot carry V3 reservation data"
            )
        is_base = self.voucher_commitment.get("paymentRail") == 1
        external_fields = (
            self.payment_evidence,
            self.external_settlement_evidence_hash,
            self.external_validator_message,
        )
        if is_base or is_stripe:
            if any(value is None for value in external_fields):
                raise ValueError(
                    "external voucher transition requires authenticated settlement evidence"
                )
        elif any(value is not None for value in external_fields):
            raise ValueError(
                "native voucher transition cannot carry external settlement evidence"
            )
        return self

    def canonical_hash(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return "0x" + hashlib.sha256(encoded).hexdigest()

    def global_payment_id(self) -> str:
        value = self.voucher_commitment.get("globalPaymentId")
        if not isinstance(value, str):
            raise ValidatorQuorumError("voucher has no global payment ID")
        return _hex(value, 32, "globalPaymentId")

    def signature_messages(self) -> tuple[bytes, ...]:
        additional_data = AGG_SIG_ME_DATA.get(self.network)
        if additional_data is None:
            raise ValidatorQuorumError(
                f"unsupported Chia network: {self.network}"
            )
        inner = bytes.fromhex(self.validator_message[2:])
        messages = tuple(
            inner + bytes.fromhex(coin_id[2:]) + additional_data
            for coin_id in (self.series_coin_id, self.voucher_coin_id)
        )
        payment_message = (
            bytes.fromhex(self.external_validator_message[2:])
            if self.external_validator_message is not None
            else inner
        )
        messages += (
            payment_message
            + bytes.fromhex(self.payment_coin_id[2:])
            + additional_data,
        )
        if self.action == 3:
            artifact_hash = self.purchase_artifact.get("artifactHash")
            if not isinstance(artifact_hash, str) or self.deed_coin_id is None:
                raise ValidatorQuorumError("voucher redemption has no deed binding")
            messages += (
                bytes.fromhex(_hex(artifact_hash, 32, "artifactHash")[2:])
                + bytes.fromhex(self.deed_coin_id[2:])
                + additional_data,
            )
        return messages


class ValidatorSignatureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claimHash: str
    signerIndex: int = Field(..., ge=0)
    validatorPubkey: str
    signature: str


class ValidatorHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    signerIndex: int = Field(..., ge=0, le=2)
    validatorPubkey: str
    apiCommit: str
    protocolCommit: str
    network: str
    bridgePolicyHash: str
    evmAddresses: dict[str, str]
    artifactHash: str | None = None
    artifactReady: bool
    ledgerReady: bool
    evmChainId: int = 11155111
    enrollmentActivation: dict[str, Any] | None = None


@dataclass(frozen=True)
class ValidatorQuorumResult:
    signer_indices: tuple[int, ...]
    aggregated_signature: G2Element
    claim_hash: str


def configured_validator_pubkeys(settings: Settings) -> tuple[bytes, ...]:
    try:
        pubkeys = tuple(
            bytes.fromhex(value.removeprefix("0x"))
            for value in settings.zkpassport_validator_pubkeys
        )
    except ValueError as exc:
        raise ValidatorQuorumError("validator public key configuration is invalid") from exc
    try:
        validator_set = require_genesis_validator_set(
            pubkeys,
            settings.zkpassport_validator_threshold,
        )
    except ValueError as exc:
        raise ValidatorQuorumError(str(exc)) from exc
    if len(settings.zkpassport_validator_urls) != len(validator_set.pubkeys):
        raise ValidatorQuorumError("validator URL and public key counts do not match")
    return validator_set.pubkeys


def configured_bridge_policy_hash(settings: Settings, *, activation: dict[str, Any] | None = None) -> str:
    pubkeys = configured_validator_pubkeys(settings)
    if activation is None and settings.enrollment_permit_release_identity:
        from .public_artifact import load_signed_public_artifact
        from solslot_puzzles.enrollment_activation import activation_from_artifact
        try:
            activation = activation_from_artifact(load_signed_public_artifact(settings), required=True,
                environment=settings.runtime_environment + "-alpha")
        except (OSError, ValueError) as exc:
            raise ValidatorQuorumError("signed permit policy is unavailable") from exc
    if activation is not None:
        from solslot_puzzles.enrollment_activation import validate_enrollment_activation
        try:
            checked = validate_enrollment_activation(activation, source_shas=activation["sourceShas"],
                ceremony_id=activation["deploymentId"], emitter=settings.zkpassport_emitter_address.lower(),
                validator_pubkeys=pubkeys, environment=settings.runtime_environment + "-alpha")
            if (settings.zkpassport_evm_chain_id != 84532
                    or settings.enrollment_permit_release_identity != checked["releaseIdentity"]
                    or settings.enrollment_permit_issuer_key_ref != checked["issuerKeyRef"]
                    or settings.enrollment_permit_identity_client_id != checked["issuerIdentityClientId"]):
                raise ValueError("permit policy differs from this API deployment")
            return checked["bridgePolicyHash"]
        except (AttributeError, KeyError, ValueError) as exc:
            raise ValidatorQuorumError("permit policy evidence does not match the configured deployment") from exc
    validator_set = require_genesis_validator_set(
        pubkeys,
        settings.zkpassport_validator_threshold,
    )
    return "0x" + bytes(validator_set.policy_hash).hex()


def _private_validator_client(settings: Settings) -> httpx.AsyncClient:
    ca_path = Path(str(settings.zkpassport_validator_mtls_ca_path or ""))
    cert_path = Path(str(settings.zkpassport_validator_mtls_cert_path or ""))
    key_path = Path(str(settings.zkpassport_validator_mtls_key_path or ""))
    for path, label in (
        (ca_path, "validator CA"),
        (cert_path, "validator client certificate"),
        (key_path, "validator client key"),
    ):
        if not path.is_file():
            raise ValidatorQuorumError(f"{label} file is unavailable")

    try:
        ssl_context = ssl.create_default_context(cafile=str(ca_path))
        ssl_context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
        )
    except (OSError, ssl.SSLError) as exc:
        raise ValidatorQuorumError(
            "validator mTLS client credentials are invalid"
        ) from exc

    return httpx.AsyncClient(
        verify=ssl_context,
        timeout=settings.zkpassport_validator_timeout_seconds,
        trust_env=False,
    )


async def probe_validator_health(
    settings: Settings,
    *,
    expected_api_commit: str,
    expected_protocol_commit: str,
    expected_network: str,
    expected_bridge_policy_hash: str,
    expected_evm_addresses: dict[str, str],
    expected_artifact_ready: bool | None = None,
    expected_artifact_hash: str | None = None,
    expected_enrollment_activation: dict[str, Any] | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[ValidatorHealthResponse, ...]:
    """Contact every private signer and bind health to the ceremony plan."""
    pubkeys = configured_validator_pubkeys(settings)
    if configured_bridge_policy_hash(settings, activation=expected_enrollment_activation) != expected_bridge_policy_hash.lower():
        raise ValidatorQuorumError(
            "ceremony bridge policy does not match configured validator roster"
        )
    normalized_addresses = {
        key: value.lower() for key, value in expected_evm_addresses.items()
    }
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_health(index: int, url: str) -> ValidatorHealthResponse:
        response = await client.get(url.rstrip("/") + "/health")
        response.raise_for_status()
        parsed = ValidatorHealthResponse.model_validate(response.json())
        expected_pubkey = "0x" + pubkeys[index].hex()
        if (parsed.enrollmentActivation != expected_enrollment_activation
                or parsed.evmChainId != (84532 if expected_enrollment_activation is not None else 11155111)):
            raise ValidatorQuorumError(f"validator signer {index} enrollment deployment does not match ceremony")
        checks = (
            (parsed.status, "healthy", "status"),
            (parsed.signerIndex, index, "signer index"),
            (parsed.validatorPubkey.lower(), expected_pubkey, "validator public key"),
            (parsed.apiCommit, expected_api_commit, "API commit"),
            (parsed.protocolCommit, expected_protocol_commit, "protocol commit"),
            (parsed.network, expected_network, "network"),
            (
                parsed.bridgePolicyHash.lower(),
                expected_bridge_policy_hash.lower(),
                "bridge policy",
            ),
            (
                {key: value.lower() for key, value in parsed.evmAddresses.items()},
                normalized_addresses,
                "EVM addresses",
            ),
            (parsed.ledgerReady, True, "signature ledger"),
        )
        for observed, expected, label in checks:
            if observed != expected:
                raise ValidatorQuorumError(
                    f"validator signer {index} {label} does not match ceremony"
                )
        if (
            expected_artifact_ready is not None
            and parsed.artifactReady is not expected_artifact_ready
        ):
            raise ValidatorQuorumError(
                f"validator signer {index} artifact readiness does not match ceremony phase"
            )
        if expected_artifact_hash is not None and (
            not parsed.artifactReady
            or str(parsed.artifactHash or "").lower()
            != expected_artifact_hash.lower()
        ):
            raise ValidatorQuorumError(
                f"validator signer {index} artifact hash does not match finalized genesis"
            )
        return parsed

    try:
        results = await asyncio.gather(
            *(
                request_health(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            ),
            return_exceptions=True,
        )
    finally:
        if owns_client:
            await client.aclose()
    failures = [
        f"signer {index}: {result}"
        for index, result in enumerate(results)
        if isinstance(result, BaseException)
    ]
    if failures:
        raise ValidatorQuorumError(
            "live validator preflight failed: " + "; ".join(failures)
        )
    return tuple(result for result in results if isinstance(result, ValidatorHealthResponse))


async def collect_validator_quorum(
    settings: Settings,
    claim: ValidatorClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect and verify an exact 2-of-3 signature set over ``claim``."""

    pubkeys = configured_validator_pubkeys(settings)
    expected_policy_hash = configured_bridge_policy_hash(settings)
    if claim.bridge_policy_hash != expected_policy_hash:
        raise ValidatorQuorumError("claim bridge policy does not match configured validators")
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()

    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(index: int, url: str) -> tuple[int, G2Element] | None:
        endpoint = url.rstrip("/") + "/v1/zkpassport/sign"
        try:
            response = await client.post(
                endpoint,
                json={"claim": claim.model_dump(mode="json"), "claimHash": claim_hash},
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash:
                raise ValueError("claim hash mismatch")
            if parsed.signerIndex != index:
                raise ValueError("signer index mismatch")
            configured_pubkey = pubkeys[index]
            response_pubkey = bytes.fromhex(parsed.validatorPubkey.removeprefix("0x"))
            if response_pubkey != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            public_key = G1Element.from_bytes(configured_pubkey)
            if not AugSchemeMPL.verify(public_key, message, signature):
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001 - one signer may be unavailable
            logger.warning("validator signer %s rejected or unavailable: %s", index, exc)
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()

    valid = sorted((item for item in responses if item is not None), key=lambda item: item[0])
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            f"validator quorum unavailable: received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_primary_purchase_quorum(
    settings: Settings,
    claim: PrimaryPurchaseClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect the configured quorum for one already wallet-signed offer."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    messages = claim.signature_messages()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/primary-purchase/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(
                response.json()
            )
            if parsed.claimHash.lower() != claim_hash:
                raise ValueError("claim hash mismatch")
            if parsed.signerIndex != index:
                raise ValueError("signer index mismatch")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            signer_key = G1Element.from_bytes(configured_pubkey)
            valid_signature = (
                AugSchemeMPL.verify(signer_key, messages[0], signature)
                if len(messages) == 1
                else AugSchemeMPL.aggregate_verify(
                    [signer_key] * len(messages),
                    list(messages),
                    signature,
                )
            )
            if not valid_signature:
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "primary purchase signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(
                    settings.zkpassport_validator_urls
                )
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "primary purchase validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_inventory_reservation_quorum(
    settings: Settings,
    claim: InventoryReservationClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect 2-of-3 signatures for one exact available-to-reserved spend."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/inventory-reservation/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("inventory signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey),
                message,
                signature,
            ):
                raise ValueError("invalid inventory reservation signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "inventory reservation signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "inventory reservation validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _signature in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _index, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_stripe_settlement_quorum(
    settings: Settings,
    claim: StripeSettlementClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect signatures for both receipt authorization and deed delivery."""

    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    messages = claim.signature_messages(pubkeys)
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int,
        url: str,
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/stripe-settlement/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("Stripe signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(
                parsed.validatorPubkey.removeprefix("0x")
            ) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.aggregate_verify(
                [G1Element.from_bytes(configured_pubkey)] * len(messages),
                list(messages),
                signature,
            ):
                raise ValueError("invalid Stripe settlement signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Stripe settlement signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "Stripe settlement validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_voucher_issuance_quorum(
    settings: Settings,
    claim: VoucherIssuanceClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect two independent signatures for an exact voucher issuance."""
    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int, url: str
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/voucher-issuance/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("voucher signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey), message, signature
            ):
                raise ValueError("invalid validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "voucher issuance signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "voucher issuance validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_voucher_transition_quorum(
    settings: Settings,
    claim: VoucherTransitionClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect quorum signatures for all three terminal protocol spends."""
    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    messages = claim.signature_messages()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int, url: str
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/voucher-transition/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("voucher transition signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            public_key = G1Element.from_bytes(configured_pubkey)
            if not AugSchemeMPL.aggregate_verify(
                [public_key] * len(messages),
                list(messages),
                signature,
            ):
                raise ValueError("invalid voucher transition validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "voucher transition signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "voucher transition validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


async def collect_voucher_series_phase_quorum(
    settings: Settings,
    claim: VoucherSeriesPhaseClaim,
    *,
    client: httpx.AsyncClient | None = None,
) -> ValidatorQuorumResult:
    """Collect two independent signatures for an exact series phase spend."""
    pubkeys = configured_validator_pubkeys(settings)
    claim_hash = claim.canonical_hash()
    message = claim.signature_message()
    owns_client = client is None
    if client is None:
        client = _private_validator_client(settings)

    async def request_signature(
        index: int, url: str
    ) -> tuple[int, G2Element] | None:
        try:
            response = await client.post(
                url.rstrip("/") + "/v1/voucher-series-phase/sign",
                json={
                    "claim": claim.model_dump(mode="json"),
                    "claimHash": claim_hash,
                },
            )
            response.raise_for_status()
            parsed = ValidatorSignatureResponse.model_validate(response.json())
            if parsed.claimHash.lower() != claim_hash or parsed.signerIndex != index:
                raise ValueError("series phase signer response does not match claim")
            configured_pubkey = pubkeys[index]
            if bytes.fromhex(parsed.validatorPubkey.removeprefix("0x")) != configured_pubkey:
                raise ValueError("validator public key mismatch")
            signature = G2Element.from_bytes(
                bytes.fromhex(parsed.signature.removeprefix("0x"))
            )
            if not AugSchemeMPL.verify(
                G1Element.from_bytes(configured_pubkey), message, signature
            ):
                raise ValueError("invalid series phase validator signature")
            return index, signature
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "series phase signer %s rejected or unavailable: %s",
                index,
                exc,
            )
            return None

    try:
        responses = await asyncio.gather(
            *(
                request_signature(index, url)
                for index, url in enumerate(settings.zkpassport_validator_urls)
            )
        )
    finally:
        if owns_client:
            await client.aclose()
    valid = sorted(
        (item for item in responses if item is not None),
        key=lambda item: item[0],
    )
    threshold = settings.zkpassport_validator_threshold
    if len(valid) < threshold:
        raise ValidatorQuorumError(
            "series phase validator quorum unavailable: "
            f"received {len(valid)} of {threshold} required signatures"
        )
    selected = valid[:threshold]
    return ValidatorQuorumResult(
        signer_indices=tuple(index for index, _ in selected),
        aggregated_signature=AugSchemeMPL.aggregate(
            [signature for _, signature in selected]
        ),
        claim_hash=claim_hash,
    )


__all__ = [
    "ValidatorClaim",
    "PrimaryPurchaseClaim",
    "PrimaryPurchaseDeedItem",
    "StripeSettlementClaim",
    "VoucherIssuanceClaim",
    "VoucherSeriesPhaseClaim",
    "VoucherTransitionClaim",
    "ValidatorHealthResponse",
    "ValidatorQuorumError",
    "ValidatorQuorumResult",
    "base_settlement_evidence_hash",
    "collect_validator_quorum",
    "collect_primary_purchase_quorum",
    "collect_stripe_settlement_quorum",
    "collect_voucher_issuance_quorum",
    "collect_voucher_series_phase_quorum",
    "collect_voucher_transition_quorum",
    "configured_bridge_policy_hash",
    "configured_validator_pubkeys",
    "probe_validator_health",
]
