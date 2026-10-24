"""Explicit revision correction; never rewrites a retained sealed snapshot."""
import asyncio
from .collection_mint_authority import collection_mint_authority
from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.property_registry_driver import canonicalise_property_id


async def correct_treasury(*, collection_id, generation_id, revision, metadata_root,
        treasury, actor, settings, collections, index, provider, submitter, reviews):
    if generation_id!=settings.deployment_generation_id or settings.network!='testnet11':
        raise ValueError('This correction belongs to another generation.')
    if any(v is None for v in (index,provider,submitter,reviews)):
        raise RuntimeError('Current chain and saved mint evidence are required before correction.')
    async with asyncio.timeout(60), submitter.funding_guard:
        if reviews.generation_id!=generation_id or reviews.for_collection(collection_id):
            raise ValueError('A saved mint review exists. Its source and funding must remain unchanged.')
        chain=await resolve_generation_chain(index.anchor,provider=provider)
        mint=next((v.state for v in chain.economic_components.values() if isinstance(v.state,GenerationMint)
            and v.state.launcher_id==chain.governance.state.mint_id),None)
        trusted=collection_mint_authority(settings)
        if (mint is None or chain.registry.state.pending or chain.registry.state.pause_mask & 3
                or mint.component() not in chain.registry.state.components
                or canonicalise_property_id(collection_id) in mint.issued.keys
                or treasury!='0x'+mint.treasury_puzzle_hash.hex()
                or not trusted or treasury!=trusted['treasuryPuzzleHash']):
            raise ValueError('This collection or its current mint authority cannot be corrected.')
        if not await current_evidence_unchanged(chain,provider=provider):
            raise ValueError('Chain authority changed. Refresh before correcting.')
        if reviews.for_collection(collection_id):
            raise ValueError('A saved mint review now exists.')
        return collections.correct_unissued_test_treasury(collection_id,expected_revision=revision,
            expected_metadata_root=metadata_root,treasury=treasury,actor_subject=actor)
