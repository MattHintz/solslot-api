"""Bridge the stored, sealed public edition to one deterministic governed batch.

This is pure preparation. No provider calls, input selection, reservations,
signatures, or submission happen here. Funding identities must come from the
explicit operation preparation step and remain fixed on retries.
"""
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.generation_mint import GenerationMint, MintRow, TestMintEdition
from solslot_puzzles.property_metadata import commit_metadata
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.real_estate_profiles import ASSET_CLASS_CODES

from .collection_store import CollectionStore
from .config import Settings
from .payment_quotes import parse_authorized_oracle_round
from .test_collection_metadata import TestPropertyDossierV1


def build_sealed_test_mint(store: CollectionStore, settings: Settings, mint: GenerationMint,
                          collection_id: str, funding_parents: tuple[bytes32, ...]) -> TestMintEdition:
    generation = '0x'+mint.generation.hex()
    if (settings.network != 'testnet11' or store.network != 'testnet11'
            or settings.deployment_generation_id != generation or store.generation_id != generation):
        raise ValueError('mint, collection and deployment generations must match on Testnet11')
    snapshot = store.sealed_test_mint_snapshot(collection_id)
    dossier = TestPropertyDossierV1.model_validate(snapshot['canonicalMetadata'])
    # Verification uses the frozen configured keys, not keys supplied in the
    # browser or in the receipt. A later live price cannot rewrite sealed par.
    authorized = parse_authorized_oracle_round(settings, snapshot['pricing']['evidence'])
    authorized.round.assert_live(snapshot['pricing']['appliedAt'])
    if '0x'+authorized.round.round_hash.hex() != dossier.pricing_round_hash:
        raise ValueError('sealed price commitment does not match its verified receipt')
    if bytes32.from_hexstr(dossier.offering.royalty_puzhash) != mint.treasury_puzzle_hash:
        raise ValueError('sealed technology fee destination must be the generation treasury')
    if len(funding_parents) != len(dossier.deed_allocation):
        raise ValueError('one fixed launcher funding parent is required for every deed')
    rows = []
    for parent, deed in zip(funding_parents, dossier.deed_allocation, strict=True):
        amount, remainder = divmod(int(dossier.offering.target_raise_minor)*deed.share_ppm, 1_000_000)
        if remainder:
            raise ValueError('each deed allocation must resolve to whole USD cents; revise and review it')
        rows.append(MintRow(parent, deed.share_ppm, amount, int(deed.par_value_mojos)))
    # Address is already canonical public metadata. Domain separation prevents
    # a property address commitment from being confused with a collection ID.
    property_id = commit_metadata({'schema': 'solslot.test-property-address.v1',
        'address': dossier.property.address.model_dump(mode='json', by_alias=True, exclude_none=True)}).metadata_root
    edition = TestMintEdition(mint.generation, canonicalise_property_id(dossier.collection_id),
        bytes32.from_hexstr(snapshot['metadataRoot']), bytes32.from_hexstr(snapshot['previewHash']),
        property_id, authorized.round.round_hash, int(dossier.offering.royalty_bps),
        int(ASSET_CLASS_CODES[dossier.offering.asset_class.upper()]), dossier.offering.jurisdiction.encode(), tuple(rows))
    # Validate the canonical program and duplicate collection guard now, before
    # anyone is asked to review or sign it.
    mint.minted(edition)
    return edition
