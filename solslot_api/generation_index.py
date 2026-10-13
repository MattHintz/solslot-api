"""Durable read projection with background primary-node reconciliation.

No transaction construction, input reservation, signature or submission APIs
are imported here. A cached response is never authority to execute an action.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
from hashlib import sha256
import json
import logging
from pathlib import Path
import time

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_economic_reader import decode_initial_economic_inner
from solslot_puzzles.generation_registry_reader import decode_registry_inner
from solslot_puzzles.generation_sgt import GenesisIssuancePlan
from .generation_chain_evidence import GenerationChainAnchor, resolve_generation_chain, current_evidence_unchanged
from .generation_preparation import GenerationPreparation
from .generation_registry_evidence import _program
from .generation_storage import connect_generation_sqlite, generation_path

logger=logging.getLogger(__name__)


class AdministratorReadAnchor(BaseModel):
    model_config=ConfigDict(extra='forbid',populate_by_name=True,frozen=True)
    source_manifest_hash:str=Field(alias='sourceManifestHash',pattern=r'^0x[0-9a-f]{64}$')
    daily_public_keys:tuple[str,str,str]=Field(alias='dailyPublicKeys')
    recovery_public_keys:tuple[str,str,str]=Field(alias='recoveryPublicKeys')


class ReadAnchor(BaseModel):
    model_config=ConfigDict(extra='forbid',populate_by_name=True,frozen=True)
    schema_version: Literal[1]=Field(alias='schemaVersion')
    purpose: Literal['GENERATION_CHAIN_READ_ANCHOR']
    preparation_manifest: str=Field(alias='preparationManifest',pattern=r'^0x[0-9a-f]{64}$')
    registry_inner: str=Field(alias='registryInner',max_length=2_097_154)
    economic_inners: dict[str,str]=Field(default_factory=dict,alias='economicInners',max_length=3)
    governance_component_id: str=Field(alias='governanceComponentId',pattern=r'^0x[0-9a-f]{64}$')
    administrator:AdministratorReadAnchor|None=None


def _bounded_file(path, limit):
    with Path(path).open('rb') as stream:raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('generation anchor file exceeds its bound')
    return raw


def load_generation_read_anchor(settings) -> GenerationChainAnchor:
    if (settings.network!='testnet11' or not settings.deployment_generation_id
            or not settings.generation_preparation_path or not settings.generation_preparation_hash
            or not settings.generation_chain_anchor_path or not settings.generation_chain_anchor_hash):
        raise ValueError('reviewed generation read anchor is not configured')
    preparation=GenerationPreparation.model_validate_json(_bounded_file(settings.generation_preparation_path,131072))
    raw=_bounded_file(settings.generation_chain_anchor_path,2_200_000)
    if '0x'+sha256(raw).hexdigest()!=settings.generation_chain_anchor_hash:
        raise ValueError('generation read anchor differs from its reviewed file hash')
    document=ReadAnchor.model_validate_json(raw)
    if (preparation.generation_id!=settings.deployment_generation_id
            or preparation.manifest_hash!=settings.generation_preparation_hash
            or document.preparation_manifest!=preparation.manifest_hash):
        raise ValueError('generation read anchor differs from its preparation')
    b=bytes32.from_hexstr
    coordinate=lambda name:b(preparation.coordinates[name].launcher_id)
    # Reconstruct expected issuance for reading only. Actual issuance admission
    # separately requires three fresh recipient confirmations and signatures.
    issuance=GenesisIssuancePlan(b(preparation.sgt_funding_coin_id),b(preparation.generation_id),
        coordinate('holdings'),coordinate('governance'),b(preparation.reserve_owner_puzzle_hash),
        tuple(b(a.sgt_owner_puzzle_hash) for a in preparation.administrators),b(preparation.manifest_hash))
    registry=decode_registry_inner(_program(document.registry_inner),generation=issuance.generation,
        launcher_id=coordinate('registry'),governance_id=coordinate('governance'),administrator_id=coordinate('authority'))
    governance=Governance(issuance.bindings(),coordinate('registry'),coordinate('authority'),coordinate('mint'),
        b(document.governance_component_id),load_puzzle('generation_extension_v1.clsp').get_tree_hash())
    states=[]
    for name,raw_inner in document.economic_inners.items():
        if name not in ('parameters','mint','pool'):raise ValueError('unsupported economic authority in frozen anchor')
        state=decode_initial_economic_inner(_program(raw_inner),generation=issuance.generation,
            registry_id=coordinate('registry'),governance_id=coordinate('governance'),launcher_id=coordinate(name))
        from solslot_puzzles.generation_parameters import GenerationParameters
        from solslot_puzzles.generation_mint import GenerationMint
        from solslot_puzzles.generation_pool import GenerationPool
        from solslot_puzzles.generation_statutes import GenerationStatutes
        if not isinstance(state,{'parameters':GenerationParameters,'mint':GenerationMint,'pool':GenerationPool}[name]):
            raise ValueError('economic authority label changed')
        if name=='mint' and state.pool_id!=coordinate('pool'):raise ValueError('mint authority binds another pool')
        if isinstance(state,GenerationStatutes):
            from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
            rules=state.permanent_rules
            if (state.pool_id!=coordinate('pool') or rules.sgt_tail_hash!=issuance.bindings().tail_hash
                    or rules.sgt_total_supply!=1_000_000 or rules.sols_tail_hash!=pool_token_tail_hash(coordinate('pool'))
                    or rules.zkpassport_policy_hash!=b(preparation.bridge_policy_hash) or rules.network_id!=issuance.generation):
                raise ValueError('canonical statutes differ from the frozen generation token and identity bindings')
        if name=='pool':
            from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
            rules=state.permanent.permanent_rules
            if (rules.sgt_tail_hash!=issuance.bindings().tail_hash or rules.sgt_total_supply!=1_000_000
                    or rules.sols_tail_hash!=pool_token_tail_hash(coordinate('pool'))
                    or rules.zkpassport_policy_hash!=b(preparation.bridge_policy_hash) or rules.network_id!=issuance.generation):
                raise ValueError('pool token or identity policy differs from the frozen generation')
        states.append(state)
    # Every supported registered economic authority needs its original state;
    # omitting it must not make upgrades rely on a cached/coordinator state.
    kernels={load_puzzle(n).get_tree_hash() for n in ('generation_parameters_v1.clsp','generation_statutes_v1.clsp','generation_mint_v1.clsp','generation_pool_v1.clsp')}
    if {c.component_id for c in registry.components if c.kernel_hash in kernels}!={s.component_id for s in states}:
        raise ValueError('frozen economic component evidence is incomplete')
    administrator=None
    if document.administrator is not None:
        from solslot_puzzles.admin_authority_v3_driver import build_genesis_admin_authority_v3
        a=document.administrator
        if a.daily_public_keys!=tuple(row.custody_owner_public_key for row in preparation.administrators):
            raise ValueError('administrator signing keys differ from the acknowledged initial roster')
        import re
        if (any(not re.fullmatch(r'0x[0-9a-f]{66}',v) for v in a.daily_public_keys)
                or any(not re.fullmatch(r'0x[0-9a-f]{96}',v) for v in a.recovery_public_keys)):
            raise ValueError('administrator anchor requires exact canonical public keys')
        administrator=build_genesis_admin_authority_v3(
            parent_coin_id=b(preparation.coordinates['authority'].funding_coin_id),network='testnet11',
            daily_compressed_pubkeys=tuple(bytes.fromhex(v[2:]) for v in a.daily_public_keys),
            recovery_bls_pubkeys=tuple(bytes.fromhex(v[2:]) for v in a.recovery_public_keys),
            source_manifest_hash=b(a.source_manifest_hash),authority_puzzle_version=4)
        if administrator.authority_launcher_id!=coordinate('authority'):
            raise ValueError('administrator authority differs from its reserved protocol coordinate')
    return GenerationChainAnchor(issuance,registry,governance,tuple(states),administrator)


class GenerationIndexStore:
    def __init__(self,path,generation_id,anchor_hash):
        from .generation_context import generation_bytes
        generation_bytes(generation_id);generation_bytes(anchor_hash)
        self.generation_id,self.anchor_hash=generation_id,anchor_hash
        self.path=generation_path(path,generation_id)
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with closing(self._connect()) as con,con:
            con.execute('CREATE TABLE IF NOT EXISTS generation_index_cache ('
                'anchor_hash TEXT PRIMARY KEY,payload TEXT,checked_at INTEGER,last_attempt_at INTEGER NOT NULL,'
                'error_code TEXT)')

    def _connect(self):
        return connect_generation_sqlite(self.path,timeout=5,generation_id=self.generation_id)

    def save(self,payload,now):
        if payload.get('generationId')!=self.generation_id or payload.get('network')!='testnet11' or payload.get('checkedAt')!=now:
            raise ValueError('index payload has different deployment bindings')
        raw=json.dumps(payload,sort_keys=True,separators=(',',':'))
        if len(raw)>131072:raise ValueError('public index projection exceeds its bound')
        with closing(self._connect()) as con,con:
            con.execute('INSERT INTO generation_index_cache VALUES (?,?,?,?,NULL) '
                'ON CONFLICT(anchor_hash) DO UPDATE SET payload=excluded.payload,checked_at=excluded.checked_at,'
                'last_attempt_at=excluded.last_attempt_at,error_code=NULL '
                'WHERE excluded.last_attempt_at>=generation_index_cache.last_attempt_at',
                (self.anchor_hash,raw,now,now))

    def fail(self,code,now):
        if code not in ('NODE_UNAVAILABLE','CHAIN_EVIDENCE_CHANGED'):
            raise ValueError('unknown generation index error')
        with closing(self._connect()) as con,con:
            con.execute('INSERT INTO generation_index_cache VALUES (?,NULL,NULL,?,?) '
                'ON CONFLICT(anchor_hash) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,error_code=excluded.error_code '
                'WHERE excluded.last_attempt_at>=generation_index_cache.last_attempt_at',
                (self.anchor_hash,now,code))

    def status(self,now,*,verified_in_process=False):
        with closing(self._connect()) as con:
            row=con.execute('SELECT payload,checked_at,last_attempt_at,error_code FROM generation_index_cache WHERE anchor_hash=?',
                (self.anchor_hash,)).fetchone()
        payload=json.loads(row[0]) if row and row[0] else None
        if row and row[3]:state='STALE' if payload else 'ERROR'
        elif not verified_in_process:state='RECONCILING'
        elif not row or row[1] is None or not 0<=now-row[1]<=90:state='STALE'
        else:state='READY'
        return {'generationId':self.generation_id,'network':'testnet11','status':state,
            'lastCheckedAt':row[1] if row else None,'lastAttemptAt':row[2] if row else None,
            'errorCode':row[3] if row else None,'snapshot':payload,
            'pollAfterSeconds':5 if state!='READY' or (payload and payload['active']) else 30}


class GenerationIndexReconciler:
    def __init__(self,anchor,store,provider):
        self.anchor,self.store,self.provider=anchor,store,provider
        self.evidence=None
        self.verified=False
        self._lock=asyncio.Lock()

    async def run_once(self):
        # A timer and explicit operator reconciliation cannot race or replace
        # a newer confirmed view with an older one.
        async with self._lock:
            try:
                async with asyncio.timeout(30):
                    if self.evidence is None or not await current_evidence_unchanged(self.evidence,provider=self.provider):
                        self.evidence=await resolve_generation_chain(self.anchor,provider=self.provider)
                    now=int(time.time())
                    self.store.save(self.evidence.public_status(now),now)
                    self.verified=True
            except (ValueError,KeyError,TypeError,StopIteration):
                self.evidence=None;self.verified=False
                self.store.fail('CHAIN_EVIDENCE_CHANGED',int(time.time()))
            except (OSError,TimeoutError,RuntimeError):
                self.evidence=None;self.verified=False
                self.store.fail('NODE_UNAVAILABLE',int(time.time()))
            except Exception as exc:
                # An unexpected provider/decoder response must not kill the
                # background task and leave the last success looking healthy.
                self.evidence=None;self.verified=False
                logger.error('generation index verification failed (%s)',type(exc).__name__)
                self.store.fail('CHAIN_EVIDENCE_CHANGED',int(time.time()))

    async def run(self):
        while True:
            interval=5
            try:
                await self.run_once()
                snapshot=self.store.status(int(time.time()),verified_in_process=self.verified)
                interval=snapshot['pollAfterSeconds']
            except Exception as exc:
                self.evidence=None;self.verified=False
                logger.error('generation index storage unavailable (%s)',type(exc).__name__)
            await asyncio.sleep(interval) # Cancellation propagates normally.


def configured_generation_index(settings,provider):
    if not settings.deployment_generation_id or not settings.generation_chain_anchor_path:return None
    anchor=load_generation_read_anchor(settings)
    store=GenerationIndexStore(settings.generation_index_db_path,settings.deployment_generation_id,
        settings.generation_chain_anchor_hash)
    return GenerationIndexReconciler(anchor,store,provider)
