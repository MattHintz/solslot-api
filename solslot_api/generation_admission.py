"""Confirmed-generation admission, separate from genesis and legacy artifacts.

Only the background observer contacts the primary node. Request contexts carry
an expiring, process-verified projection of public identities, never arbitrary
coordinator records or persisted allowlists. No transaction builder is used.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import logging
from pathlib import Path
import time

from chia_rs import G1Element
from eth_keys import keys
from pydantic import Field, model_validator

from .generation_preparation import PreparationModel, read_generation_preparation
from .public_artifact import PublicArtifactMissing

logger = logging.getLogger(__name__)
MAX_ROSTER_AGE = 30
REFRESH_SECONDS = 5
_request_roster = ContextVar('solslot_confirmed_generation_administrators', default=None)


def handoff_selected(settings):
    return bool(settings.generation_chain_anchor_path or settings.generation_chain_anchor_hash)


def binding(settings):
    return (settings.network, settings.deployment_generation_id,
        settings.generation_preparation_path, settings.generation_preparation_hash,
        settings.generation_chain_anchor_path, settings.generation_chain_anchor_hash,
        getattr(settings, 'generation_admin_identity_witnesses_path', None),
        getattr(settings, 'generation_admin_identity_witnesses_hash', None))


def require_handoff_configuration(settings):
    """Admit generation operations; retain every legacy/customer write gate."""
    from .disposable_genesis import CLOSED_FLAGS
    from .generation_index import load_generation_read_anchor
    preparation = read_generation_preparation(settings)
    if (settings.alpha_writes_enabled or settings.ceremony_mode_enabled or settings.generation_launch_enabled
            or any(getattr(settings, field) for field in CLOSED_FLAGS)
            or any(Path(path).exists() or Path(path).is_symlink()
                for path in (settings.public_artifact_path, settings.bootstrap_manifest_path))):
        raise ValueError('generation handoff requires closed legacy writes and no legacy authority')
    if not settings.admin_jwt_secret:
        raise ValueError('confirmed generation requires a stable administrator JWT secret')
    anchor = load_generation_read_anchor(settings)
    from solslot_puzzles.generation_statutes import GenerationStatutes
    from solslot_puzzles.generation_mint import GenerationMint
    from solslot_puzzles.generation_pool import GenerationPool
    if (anchor.administrator is None or len(anchor.economic_components) != 3
            or {type(s) for s in anchor.economic_components} != {GenerationStatutes, GenerationMint, GenerationPool}):
        raise ValueError('generation handoff requires the complete genesis and recovery authority')
    return preparation, anchor


class PublicIdentity(PreparationModel):
    slot: int = Field(strict=True, ge=0, le=2)
    daily_public_key: str = Field(alias='dailyPublicKey', pattern=r'^0x[0-9a-f]{66}$')
    recovery_public_key: str = Field(alias='recoveryPublicKey', pattern=r'^0x[0-9a-f]{96}$')


class IdentityWitnesses(PreparationModel):
    schema_version: int = Field(alias='schemaVersion', strict=True, ge=1, le=1)
    generation_id: str = Field(alias='generationId', pattern=r'^0x[0-9a-f]{64}$')
    preparation_manifest: str = Field(alias='preparationManifest', pattern=r'^0x[0-9a-f]{64}$')
    identities: tuple[PublicIdentity, ...] = Field(min_length=1, max_length=3)

    @model_validator(mode='after')
    def unique_slots(self):
        if len({row.slot for row in self.identities}) != len(self.identities):
            raise ValueError('identity witnesses contain duplicate slots')
        return self


def identity_policies(settings, initial):
    """Public preimages authorize nothing until matched to confirmed custody."""
    policies = list(initial.identity_vaults)
    path = getattr(settings, 'generation_admin_identity_witnesses_path', None)
    digest = getattr(settings, 'generation_admin_identity_witnesses_hash', None)
    if bool(path) != bool(digest):
        raise ValueError('identity witness path and digest must be installed together')
    if path:
        from .generation_index import _bounded_file
        from solslot_puzzles.admin_authority_v3_driver import build_admin_identity_vault
        raw = _bounded_file(path, 16384)
        if '0x' + sha256(raw).hexdigest() != digest:
            raise ValueError('public identity witnesses differ from their reviewed hash')
        document = IdentityWitnesses.model_validate_json(raw)
        if (document.generation_id != settings.deployment_generation_id
                or document.preparation_manifest != settings.generation_preparation_hash):
            raise ValueError('public identity witnesses belong to another preparation')
        for row in document.identities:
            daily, recovery = bytes.fromhex(row.daily_public_key[2:]), bytes.fromhex(row.recovery_public_key[2:])
            keys.PublicKey.from_compressed_bytes(daily)
            if G1Element.from_bytes(recovery) == G1Element():
                raise ValueError('recovery public key cannot be infinity')
            policies[row.slot] = build_admin_identity_vault(slot=row.slot,
                launcher_id=initial.identity_vaults[row.slot].launcher_id,
                authority_launcher_id=initial.authority_launcher_id, network='testnet11',
                daily_compressed_pubkey=daily, recovery_bls_pubkey=recovery)
    return tuple(policies)


@dataclass(frozen=True)
class RosterSnapshot:
    deployment: tuple
    slots: tuple[tuple[int, str, str], ...]
    checked: float


def current_admin_slots(settings):
    snapshot = _request_roster.get()
    if (snapshot is None or snapshot.deployment != binding(settings)
            or not 0 <= time.monotonic() - snapshot.checked < MAX_ROSTER_AGE):
        raise PublicArtifactMissing('fresh confirmed generation administrator evidence is unavailable')
    return {slot: (address, public_key) for slot, address, public_key in snapshot.slots}


class GenerationAdmission:
    def __init__(self, settings, anchor, provider, *, clock=time.monotonic):
        self.settings, self.anchor, self.provider, self.clock = settings, anchor, provider, clock
        self.deployment = binding(settings)
        self.snapshot = None
        self.evidence = None

    async def refresh(self):
        from .generation_administrator_evidence import resolve_generation_administrators
        from solslot_puzzles.admin_authority_v3_driver import parse_inner_puzzle
        from .admin_roster import address_from_compressed_pubkey
        try:
            if binding(self.settings) != self.deployment:
                raise ValueError('generation admission configuration changed')
            evidence = self.evidence
            if evidence is not None:
                from .generation_coin_evidence import read_confirmed_coin
                async with asyncio.timeout(10):
                    if (await self.provider.get_network_info_primary()).get('network_name') != 'testnet11':
                        raise ValueError('administrator observation requires the primary Testnet11 node')
                    async def unchanged(record):
                        raw = await self.provider.get_coin_record_by_name_primary('0x' + record.coin.name().hex())
                        return read_confirmed_coin(raw, record.coin.name()) == record
                    if not all(await asyncio.gather(*(unchanged(r) for r in evidence.current_records))):
                        evidence = None
            if evidence is None:
                evidence = await resolve_generation_administrators(self.anchor.administrator, provider=self.provider)
            policies = identity_policies(self.settings, self.anchor.administrator)
            state = parse_inner_puzzle(evidence.authority.state).state
            slots = []
            for slot, (policy, confirmed) in enumerate(zip(policies, evidence.identities, strict=True)):
                # A recovered or pending identity cannot authenticate using its
                # former key. Unknown preimages deny that slot, not other admins
                # or public holder voting/claims.
                if (policy.custody_hash != confirmed.custody_hash
                        or (state.pending_kind and state.pending_slot == slot)):
                    continue
                confirmed.verified_tip(policy, self.anchor.administrator.authority_launcher_id)
                key = '0x' + policy.daily_compressed_pubkey.hex()
                slots.append((slot, address_from_compressed_pubkey(key).lower(), key))
            if len({row[1] for row in slots}) != len(slots):
                raise ValueError('current administrator identities are not distinct')
            self.evidence = evidence
            self.snapshot = RosterSnapshot(self.deployment, tuple(slots), self.clock())
        except BaseException:
            self.snapshot = None
            self.evidence = None
            raise

    @contextmanager
    def request_context(self):
        snapshot = self.snapshot
        if (snapshot is None or binding(self.settings) != self.deployment
                or not 0 <= self.clock() - snapshot.checked < MAX_ROSTER_AGE):
            raise PublicArtifactMissing('confirmed generation authority needs reconciliation')
        token = _request_roster.set(snapshot)
        try:
            yield
        finally:
            _request_roster.reset(token)

    async def run(self):
        while True:
            await asyncio.sleep(REFRESH_SECONDS)
            try:
                await self.refresh()
            except Exception:
                logger.warning('Confirmed generation administrator observation unavailable; access closed.')


async def initialize_handoff(settings, provider):
    _, anchor = require_handoff_configuration(settings)
    from .generation_chain_evidence import resolve_generation_chain
    # An anchor file is an expectation, never a claim of chain confirmation.
    await resolve_generation_chain(anchor, provider=provider)
    admission = GenerationAdmission(settings, anchor, provider)
    await admission.refresh()
    return admission


class GenerationAdmissionMiddleware:
    """Apply the same native authority to launch cookies and desk JWTs."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        state = scope['app'].state
        settings = getattr(state, 'settings', None)
        path = scope.get('path', '')
        if settings is None or not handoff_selected(settings) or not path.startswith('/admin/'):
            return await self.app(scope, receive, send)
        from starlette.responses import JSONResponse
        if not path.startswith(('/admin/generation/', '/admin/auth/', '/admin/launch/')):
            return await JSONResponse({'detail': {'code': 'GENERATION_WORKFLOW_REQUIRED',
                'message': 'Use the reviewed generation workflow; legacy administration is unavailable.'}}, status_code=403)(scope, receive, send)
        if path == '/admin/launch/auth/logout':
            return await self.app(scope, receive, send)
        admission = getattr(state, 'generation_admission', None)
        with ExitStack() as context:
            try:
                if admission is None:
                    raise PublicArtifactMissing('confirmed generation admission is not initialized')
                context.enter_context(admission.request_context())
            except PublicArtifactMissing:
                return await JSONResponse({'detail': {'code': 'GENERATION_AUTHORITY_UNAVAILABLE',
                    'message': 'Administrator authority is being checked. Retry when the connection recovers; saved progress is retained.'}}, status_code=503)(scope, receive, send)
            return await self.app(scope, receive, send)
