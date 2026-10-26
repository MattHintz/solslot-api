"""Reuse verified in-process chain proofs, never browser or persisted claims."""
import asyncio
import re
import time

from .generation_chain_evidence import current_evidence_unchanged


async def checked_mint_chain_cache(anchor, *, provider, index=None):
    from .generation_index import GenerationIndexReconciler
    if (isinstance(index, GenerationIndexReconciler) and index.anchor is anchor
            and index.provider is provider and index.verified and index.evidence is not None):
        cached = index.evidence
        status = index.store.status(int(time.time()), verified_in_process=True)
        if (status['status'] == 'READY' and status['network'] == 'testnet11'
                and status['generationId'] == '0x' + anchor.issuance.generation.hex()
                and cached.registry.state.generation == anchor.issuance.generation
                and await current_evidence_unchanged(cached, provider=provider)
                and index.verified and index.evidence is cached):
            return cached
    # A stale, unverified, foreign, or restarted index never supplies authority.
    return None


async def primary_mint_coin_records(identities, *, provider):
    ids = tuple(identities)
    if (not 1 <= len(ids) <= 100 or len(set(ids)) != len(ids)
            or any(not isinstance(v, str) or not re.fullmatch(r'0x[0-9a-f]{64}', v) for v in ids)):
        raise ValueError('mint checks require distinct bounded primary coin identities')
    limit = asyncio.Semaphore(5)
    async def read(identity):
        async with limit:
            return await provider.get_coin_record_by_name_primary(identity)
    # Inspect every result; no missing/malformed read is treated as success.
    values = await asyncio.gather(*(read(identity) for identity in ids), return_exceptions=True)
    for value in values:
        if isinstance(value, BaseException):
            raise value
    return values
