"""Primary checkout custody from confirmed generation history, never legacy rows.

This resolver has no wallet, signer, fee allocator or submission interface. Its
caller supplies coordinates from the preserved reviewed edition; customer input
cannot substitute module hashes, payment destinations or economic terms.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_mint import GenerationMint, MintedInventory
from solslot_puzzles.generation_pool import GenerationPool
from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged
from .generation_sols_batch_execution import current_inventory


def h(value):
    return '0x' + value.hex()


@dataclass(frozen=True)
class CurrentPrimaryItem:
    original: MintedInventory
    current: MintedInventory | None
    lineage: Any | None
    confirmed_height: int | None

    @property
    def available(self):
        return self.current is not None

    def public(self):
        terms = self.original.terms
        return {
            'deedLauncherId': h(terms.deed_launcher_id),
            'initialInventoryCoinId': h(self.original.coin.name()),
            'currentInventoryCoinId': h(self.current.coin.name()) if self.current else None,
            'status': 'AVAILABLE' if self.available else 'NOT_AVAILABLE',
            'confirmedHeight': self.confirmed_height,
            'baseAmountMinor': terms.base_amount_minor,
            'technologyFeeBps': terms.technology_fee_bps,
            'technologyFeeMinor': terms.technology_fee_minor,
            'subtotalMinor': terms.subtotal_minor,
            'sharePpm': terms.share_ppm,
        }


@dataclass(frozen=True)
class CurrentPrimaryInventory:
    generation: bytes32
    collection: bytes32
    edition: bytes32
    metadata_root: bytes32
    mint_coin_id: bytes32
    pool_launcher_id: bytes32
    items: tuple[CurrentPrimaryItem, ...]
    evidence: Any

    def require_available(self, launcher: bytes32):
        matched = [item for item in self.items if item.original.terms.deed_launcher_id == launcher]
        if len(matched) != 1 or not matched[0].available:
            raise ValueError('CURRENT_PRIMARY_DEED_NOT_AVAILABLE')
        return matched[0]

    def public(self):
        # Chain availability is separate from the release's purchase gate.
        # Never claim a sale is open merely because an unspent deed exists.
        return {
            'schema': 'solslot.current-primary-inventory.v1',
            'generationId': h(self.generation), 'network': 'testnet11',
            'collectionHash': h(self.collection), 'editionHash': h(self.edition),
            'metadataRoot': h(self.metadata_root), 'mintAuthorityCoinId': h(self.mint_coin_id),
            'deedCount': len(self.items),
            'availableDeeds': sum(item.available for item in self.items),
            'items': [item.public() for item in self.items],
        }


async def resolve_current_primary_inventory(*, settings, anchor, provider,
        collection: bytes32, edition_hash: bytes32, metadata_root: bytes32):
    """Reconstruct exact minted terms and currently spendable inventory.

    Network errors and inconsistent evidence abort the read; they never become
    a zero balance. Known singleton transitions out of AVAILABLE make only that
    deed unavailable. Reservation release history is handled by the existing
    consensus history reader shared with the Sols batch route.
    """
    generation = getattr(settings, 'deployment_generation_id', None)
    if (settings.network != 'testnet11' or not generation
            or bytes32.from_hexstr(generation) != anchor.issuance.generation
            or any(not isinstance(value, bytes32) or value == bytes32.zeros
                   for value in (collection, edition_hash, metadata_root))):
        raise ValueError('CURRENT_PRIMARY_GENERATION_CHANGED')
    if (await provider.get_network_info_primary()).get('network_name') != 'testnet11':
        raise ValueError('CURRENT_PRIMARY_NETWORK_CHANGED')
    chain = await resolve_generation_chain(anchor, provider=provider)
    mints = [history for history in chain.economic_components.values()
             if isinstance(history.state, GenerationMint)]
    pools = [history for history in chain.economic_components.values()
             if isinstance(history.state, GenerationPool)]
    if len(mints) != 1 or len(pools) != 1:
        raise ValueError('CURRENT_PRIMARY_AUTHORITIES_INCOMPLETE')
    mint, pool = mints[0], pools[0]
    if (mint.state.generation != anchor.issuance.generation
            or mint.state.registry_id != chain.registry.state.launcher_id
            or mint.state.governance_id != chain.governance.state.sgt.governance_launcher_id
            or mint.state.pool_id != pool.state.launcher_id
            or pool.state.generation != mint.state.generation):
        raise ValueError('CURRENT_PRIMARY_AUTHORITY_BINDING_CHANGED')
    transitions = [transition for transition in mint.transitions
                   if transition.edition is not None and transition.edition.collection == collection]
    if len(transitions) != 1:
        raise ValueError('CURRENT_PRIMARY_CONFIRMED_EDITION_MISSING')
    transition, = transitions
    edition = transition.edition
    if edition.commitment != edition_hash or edition.metadata_root != metadata_root:
        raise ValueError('CURRENT_PRIMARY_REVIEWED_EDITION_CHANGED')
    originals = transition.before.inventories(edition)
    if (not originals or len(originals) > 100
            or len({item.terms.deed_launcher_id for item in originals}) != len(originals)):
        raise ValueError('CURRENT_PRIMARY_ISSUANCE_INCONSISTENT')
    limit = asyncio.Semaphore(4)

    async def inspect(item):
        async with limit:
            try:
                current, lineage, record = await current_inventory(item, provider)
            except ValueError as error:
                if str(error) not in ('PRIMARY_INVENTORY_NOT_AVAILABLE', 'PRIMARY_INVENTORY_NO_CONTINUATION'):
                    raise
                return CurrentPrimaryItem(item, None, None, None)
            return CurrentPrimaryItem(item, current, lineage, record.confirmed_height)

    items = tuple(await asyncio.gather(*(inspect(item) for item in originals)))
    if not await current_evidence_unchanged(chain, provider=provider):
        raise ValueError('CURRENT_PRIMARY_AUTHORITY_CHANGED_DURING_READ')
    return CurrentPrimaryInventory(anchor.issuance.generation, collection, edition_hash,
        metadata_root, mint.current.coin.name(), pool.state.launcher_id, items, chain)
