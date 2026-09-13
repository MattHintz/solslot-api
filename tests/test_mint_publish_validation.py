from __future__ import annotations

import pytest

from solslot_api.config import Settings
from solslot_api.mint_publish_validation import (
    PublishProposalMetadata,
    build_protocol_publish_context,
    metadata_bytes,
)


def _settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "runtime_environment": "test",
        "protocol_did_singleton_struct_hex": "0x01",
        "protocol_did_puzhash": "0x" + "11" * 32,
        "pool_launcher_id": "0x" + "44" * 32,
        "p2_pool_mod_hash": "0x" + "22" * 32,
        "p2_vault_mod_hash": "0x" + "33" * 32,
    }
    values.update(updates)
    return Settings(_env_file=None, **values)


def _metadata(**updates: object) -> PublishProposalMetadata:
    values: dict[str, object] = {
        "property_id": "PROPERTY-1",
        "collection_id": "COLLECTION-1",
        "asset_class_name": "RWA-RE-RES",
        "property_id_canon": "0x" + "01" * 32,
        "collection_id_canon": "0x" + "02" * 32,
        "share_ppm": 250_000,
        "property_registry_coin_id": "0x" + "07" * 32,
        "property_registry_puzzle_hash": "0x" + "03" * 32,
        "par_value_mojos": 50_000,
        "asset_class": 1,
        "jurisdiction": "0x55532d544e",
        "royalty_puzhash": "0x" + "04" * 32,
        "royalty_bps": 100,
        "quorum_threshold": 10_000,
        "owner_member_hash": "0x" + "05" * 32,
        "gov_member_hash": "0x" + "06" * 32,
        "voting_deadline": 2_000_000_000,
    }
    values.update(updates)
    return PublishProposalMetadata(**values)


def test_publish_context_normalizes_canonical_coordinates() -> None:
    settings = _settings(
        protocol_did_puzhash="0x" + "AA" * 32,
    )
    context = build_protocol_publish_context(settings)
    assert context["protocol_did_singleton_struct_hex"] == "0x01"
    assert context["protocol_did_puzhash"] == "0x" + "aa" * 32
    assert context["pool_launcher_id"] == "0x" + "44" * 32


@pytest.mark.parametrize(
    "field",
    [
        "protocol_did_singleton_struct_hex",
        "protocol_did_puzhash",
        "pool_launcher_id",
        "p2_pool_mod_hash",
        "p2_vault_mod_hash",
    ],
)
def test_publish_context_rejects_missing_coordinate(field: str) -> None:
    with pytest.raises(ValueError, match="is required"):
        build_protocol_publish_context(_settings(**{field: None}))


def test_publish_context_rejects_non_bytes32_hash() -> None:
    with pytest.raises(ValueError, match="p2_pool_mod_hash must be 32 bytes"):
        build_protocol_publish_context(_settings(p2_pool_mod_hash="0x01"))


def test_publish_context_rejects_truncated_clvm_program() -> None:
    with pytest.raises(ValueError, match="serialized CLVM"):
        build_protocol_publish_context(
            _settings(protocol_did_singleton_struct_hex="0xff")
        )


def test_metadata_bytes_converts_wire_values() -> None:
    converted = metadata_bytes(_metadata())
    assert converted["property_id_canon"] == b"\x01" * 32
    assert converted["collection_id_canon"] == b"\x02" * 32
    assert converted["jurisdiction"] == b"US-TN"
    assert converted["share_ppm"] == 250_000


def test_metadata_bytes_rejects_non_bytes32_field() -> None:
    metadata = _metadata(property_id_canon="0x01")
    with pytest.raises(ValueError, match="property_id_canon must be 32 bytes"):
        metadata_bytes(metadata)


def test_inventory_version_metadata_is_explicit_and_historical_default_is_preserved():
    assert metadata_bytes(_metadata())["inventory_puzzle_version"] == 1
    assert metadata_bytes(_metadata(inventory_puzzle_version=2))["inventory_puzzle_version"] == 2


@pytest.mark.parametrize("value", [0, 3, True, "2", 2.0, None])
def test_inventory_version_metadata_rejects_unknown_or_coerced_values(value):
    with pytest.raises(ValueError):
        _metadata(inventory_puzzle_version=value)
