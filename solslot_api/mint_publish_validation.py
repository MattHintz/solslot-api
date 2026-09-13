"""Canonical validation for admin mint-publish metadata and coordinates."""

from __future__ import annotations

from chia.types.blockchain_format.program import Program
from pydantic import BaseModel, Field, model_validator

from .config import Settings


class PublishProposalMetadata(BaseModel):
    property_id: str = Field(..., min_length=1, max_length=128)
    collection_id: str = Field(..., min_length=1, max_length=128)
    asset_class_name: str = Field(..., min_length=1, max_length=64)
    property_id_canon: str = Field(..., description="0x-prefixed bytes32")
    collection_id_canon: str = Field(..., description="0x-prefixed bytes32")
    share_ppm: int = Field(..., ge=1, le=1_000_000)
    property_registry_coin_id: str = Field(..., description="0x-prefixed bytes32")
    property_registry_puzzle_hash: str = Field(..., description="0x-prefixed bytes32")
    par_value_mojos: int = Field(..., gt=0)
    asset_class: int = Field(..., ge=0)
    jurisdiction: str = Field(..., description="0x-prefixed UTF-8 bytes")
    royalty_puzhash: str = Field(..., description="0x-prefixed bytes32")
    royalty_bps: int = Field(..., ge=0, le=10_000)
    quorum_threshold: int = Field(..., gt=0)
    owner_member_hash: str = Field(..., description="0x-prefixed bytes32")
    gov_member_hash: str = Field(..., description="0x-prefixed bytes32")
    voting_deadline: int = Field(..., gt=0)
    metadata_root: str | None = Field(None, description="0x-prefixed dossier SHA-256")
    metadata_anchor_id: str | None = Field(None, description="0x-prefixed first deed launcher id")
    primary_purchase_usd_amount_minor: int | None = Field(
        None,
        gt=0,
        description="Explicit inventory V2: sealed base USD minor units; fee added once. Historical V1 wire meaning is retained for reads.",
    )

    inventory_puzzle_version: int = Field(
        1, ge=1, le=2, strict=True,
        description="Governed inventory module version; omitted historical metadata remains V1",
    )

    @model_validator(mode="after")
    def validate_metadata_commitment_pair(self) -> "PublishProposalMetadata":
        if bool(self.metadata_root) != bool(self.metadata_anchor_id):
            raise ValueError("metadata_root and metadata_anchor_id must be supplied together")
        return self


def build_protocol_publish_context(settings: Settings) -> dict[str, str]:
    field_to_env = [
        ("protocol_did_singleton_struct_hex", "SOLSLOT_PROTOCOL_DID_SINGLETON_STRUCT_HEX"),
        ("protocol_did_puzhash", "SOLSLOT_PROTOCOL_DID_PUZHASH"),
        ("pool_launcher_id", "SOLSLOT_POOL_LAUNCHER_ID"),
        ("p2_pool_mod_hash", "SOLSLOT_P2_POOL_MOD_HASH"),
        ("p2_vault_mod_hash", "SOLSLOT_P2_VAULT_MOD_HASH"),
    ]
    context: dict[str, str] = {}
    for field_name, env_name in field_to_env:
        value = getattr(settings, field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{env_name} is required for mint publish validation")
        context[field_name] = _normalize_hex(value, field_name)
    _require_serialized_program(
        context["protocol_did_singleton_struct_hex"],
        "protocol_did_singleton_struct_hex",
    )
    _require_bytes32(context["protocol_did_puzhash"], "protocol_did_puzhash")
    _require_bytes32(context["pool_launcher_id"], "pool_launcher_id")
    _require_bytes32(context["p2_pool_mod_hash"], "p2_pool_mod_hash")
    _require_bytes32(context["p2_vault_mod_hash"], "p2_vault_mod_hash")
    return context


def metadata_bytes(metadata: PublishProposalMetadata) -> dict[str, bytes | int]:
    data = metadata.model_dump(
        exclude={"property_id", "collection_id", "asset_class_name"}
    )
    bytes32_fields = {
        "property_id_canon",
        "collection_id_canon",
        "property_registry_coin_id",
        "property_registry_puzzle_hash",
        "royalty_puzhash",
        "owner_member_hash",
        "gov_member_hash",
        "metadata_root",
        "metadata_anchor_id",
    }
    converted: dict[str, bytes | int] = {}
    for key, value in data.items():
        if value is None:
            continue
        if key in bytes32_fields:
            converted[key] = _require_bytes32(str(value), key)
        elif key == "jurisdiction":
            converted[key] = bytes.fromhex(_normalize_hex(str(value), key)[2:])
        else:
            converted[key] = int(value)
    return converted


def _normalize_hex(value: str, field_name: str) -> str:
    raw = value.strip().removeprefix("0x")
    if not raw or len(raw) % 2:
        raise ValueError(f"{field_name} must be even-length hexadecimal")
    try:
        bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be hexadecimal") from exc
    return "0x" + raw.lower()


def _require_bytes32(value: str, field_name: str) -> bytes:
    raw = bytes.fromhex(_normalize_hex(value, field_name)[2:])
    if len(raw) != 32:
        raise ValueError(f"{field_name} must be 32 bytes")
    return raw


def _require_serialized_program(value: str, field_name: str) -> bytes:
    raw = bytes.fromhex(_normalize_hex(value, field_name)[2:])
    try:
        Program.from_bytes(raw)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be serialized CLVM") from exc
    return raw


__all__ = [
    "PublishProposalMetadata",
    "build_protocol_publish_context",
    "metadata_bytes",
]
