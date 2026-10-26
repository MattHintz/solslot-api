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


async def checked_mint_administrators(anchor, *, settings, provider, admission=None):
    """Reuse only the actual admission observer's fresh native proof."""
    from .generation_admission import GenerationAdmission, RosterSnapshot, MAX_ROSTER_AGE, binding
    from .generation_administrator_evidence import GenerationAdministratorEvidence
    from .generation_coin_evidence import read_confirmed_coin
    if not isinstance(admission, GenerationAdmission) or settings is None:
        return None
    snapshot, evidence = admission.snapshot, admission.evidence
    if (admission.provider is not provider or admission.anchor != anchor
            or admission.deployment != binding(settings)
            or binding(admission.settings) != admission.deployment
            or not isinstance(snapshot, RosterSnapshot)
            or snapshot.deployment != admission.deployment
            or not isinstance(evidence, GenerationAdministratorEvidence)
            or not 0 <= admission.clock() - snapshot.checked < MAX_ROSTER_AGE):
        return None
    if (await provider.get_network_info_primary()).get('network_name') != 'testnet11':
        raise ValueError('mint consent requires the primary Testnet11 node')
    records=evidence.current_records
    observed=await primary_mint_coin_records(('0x'+r.coin.name().hex() for r in records),provider=provider)
    if any(read_confirmed_coin(raw,prior.coin.name())!=prior for prior,raw in zip(records,observed,strict=True)):
        return None
    current=admission.snapshot
    if (admission.evidence is not evidence or not isinstance(current,RosterSnapshot)
            or current.deployment!=admission.deployment or current.slots!=snapshot.slots
            or binding(settings) != admission.deployment
            or binding(admission.settings) != admission.deployment
            or not 0 <= admission.clock() - current.checked < MAX_ROSTER_AGE):
        return None
    return evidence


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
