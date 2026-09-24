"""Sealed collection base/fee controls, independent of portal price claims."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from solslot_api import mint_endpoints
from tests.test_mint_publish_validation import _metadata


@pytest.mark.parametrize('version', [2, 3])
def test_api_mint_terms_match_reservation_provider_fee_and_signed_activation(version):
    from solslot_api.mint_chain_validation import primary_purchase_mint_config
    from solslot_api.mint_publish_validation import metadata_bytes
    from solslot_puzzles import load_puzzle
    from solslot_puzzles.stripe_settlement_v1_driver import PRIMARY_PURCHASE_PROVIDER_ID
    from chia_rs import AugSchemeMPL
    artifact = dict(network="testnet11", ceremony=dict(ceremonyId="0x"+"99"*32), sourceShas={"api": "ab"*20},
        puzzleHashes=dict(protocolTreasuryPuzzleHash="0x"+"66"*32),
        validatorSet=dict(threshold=2, pubkeys=["0x"+bytes(AugSchemeMPL.key_gen(bytes([i])*32).get_g1()).hex() for i in (1,2,3)]))
    values = metadata_bytes(_metadata(primary_purchase_usd_amount_minor=101, inventory_puzzle_version=2))
    with pytest.raises(ValueError, match="activation"): primary_purchase_mint_config(values, artifact)
    artifact["inventoryActivation"] = dict(schema="solslot.inventory-activation.v1", network="testnet11",
        environment="staging-alpha", deploymentId=artifact["ceremony"]["ceremonyId"], sourceShas=artifact["sourceShas"],
        inventoryVersion=2, adapterVersion=1, reviewEvidenceSha256="ab"*32,
        availableModuleHash="0x"+load_puzzle("mint_offer_inventory_available_v2.clsp").get_tree_hash().hex(),
        reservedModuleHash="0x"+load_puzzle("mint_offer_delegate_v5.clsp").get_tree_hash().hex())
    if version == 3:
        from solslot_puzzles.alpha_payment_profile import alpha_payment_profile
        artifact.update(evmChainId=11155111, paymentChainId=8453, genesisPlan={'paymentChainId':8453})
        artifact['inventoryActivation'].update(schema='solslot.inventory-activation.v2', inventoryVersion=3,
            adapterVersion=2, paymentProfile=alpha_payment_profile(),
            availableModuleHash='0x'+load_puzzle('mint_offer_inventory_available_v3.clsp').get_tree_hash().hex(),
            reservedModuleHash='0x'+load_puzzle('mint_offer_delegate_v6.clsp').get_tree_hash().hex())
    values['inventory_puzzle_version'] = version
    config = primary_purchase_mint_config(values, artifact)
    assert config.usd_amount_minor == 101 and config.technology_fee_bps == 100
    assert config.provider_id == PRIMARY_PURCHASE_PROVIDER_ID and config.inventory_version == version
    with pytest.raises(ValueError, match='differs from the signed activation'):
        primary_purchase_mint_config({**values, 'inventory_puzzle_version':5-version}, artifact)
    with pytest.raises(ValueError, match="governed inventory V2"):
        primary_purchase_mint_config({**values, "inventory_puzzle_version": 1}, artifact)
    with pytest.raises(ValueError, match="100 basis points"):
        primary_purchase_mint_config({**values, "royalty_bps": 200}, artifact)


@pytest.mark.parametrize("version,wire,accepted", [(1, 103, True), (2, 101, True), (2, 103, False), (1, 101, False), (3, 101, True), (3, 103, False)])
def test_sealed_allocation_preserves_old_wire_and_charges_v2_fee_once(monkeypatch, version, wire, accepted):
    metadata = _metadata(primary_purchase_usd_amount_minor=wire, inventory_puzzle_version=version,
        metadata_root="0x"+"77"*32, metadata_anchor_id="0x"+"88"*32)
    deed = dict(deedId=metadata.property_id, sharePpm=250_000, parValueMojos=50_000, proposalId=None)
    collection = dict(ownerSubject="test-owner", state="SEALED", metadataRoot=metadata.metadata_root,
        metadataAnchorId=metadata.metadata_anchor_id, deeds=[deed], dossier=dict(offering=dict(
            targetRaiseMinor="404", royaltyBps="100", assetClass="RWA-RE-RES", jurisdiction="US-TN",
            royaltyPuzhash=metadata.royalty_puzhash, governanceQuorum="10000")))
    store = SimpleNamespace(get=lambda _: collection)
    monkeypatch.setattr(mint_endpoints, "get_collection_store", lambda _: store)
    args = dict(settings=SimpleNamespace(collection_metadata_enabled=True, collection_minting_enabled=True),
        metadata=metadata, claims=SimpleNamespace(sub="test-owner"), canonical=None, proposal_id="proposal",
        artifact=dict(puzzleHashes=dict(protocolTreasuryPuzzleHash=metadata.royalty_puzhash)))
    if accepted:
        assert mint_endpoints._validate_collection_publish_context(**args) == (store, deed["deedId"])
    else:
        with pytest.raises(HTTPException) as exc: mint_endpoints._validate_collection_publish_context(**args)
        assert exc.value.status_code == 409
