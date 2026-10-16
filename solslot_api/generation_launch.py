"""Source-bound final ceremony. Cached reads never build, sign or submit.

An installed, independently reviewed release certificate is a prerequisite,
not evidence this R1 implementation has obtained that certificate. The API
cannot supply or change it. Exact native outputs complete the ceremony.
"""
from __future__ import annotations
import asyncio
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3
import time
from typing import Literal
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element
from eth_account import Account
from eth_account.messages import encode_typed_data
from pydantic import Field, model_validator
from .generation_preparation import PreparationModel, GenerationPreparation, SOURCE_KEYS, commitment
from .generation_genesis_core import GenerationLaunchArtifact, CORE_FUNDING_NAMES, genesis_launch_funding_requests, assemble_genesis_launch
from .generation_recipient_evidence import verify_recipient_custody
from .generation_recipient_execution import _funding_coin
from .generation_storage import connect_generation_sqlite, generation_path, admit_retained_bytes
from .generation_operations import canonical

NAMES=(*CORE_FUNDING_NAMES,'pool')
H=r'^0x[0-9a-f]{64}$'


def runtime_source_hash():
    """Pin actual builder/API and puzzle bytes; file mtimes are not authority."""
    import solslot_puzzles
    roots={'api':Path(__file__).parent,'protocol':Path(solslot_puzzles.__file__).parent}
    entries=[]
    for label,root in roots.items():
        for path in sorted(root.rglob('*')):
            if path.is_file() and path.suffix in ('.py','.clsp','.clib','.hex'):
                entries.append([label+'/'+path.relative_to(root).as_posix(),sha256(path.read_bytes()).hexdigest()])
    return commitment({'files':entries})


class LaunchCertificate(PreparationModel):
    purpose:Literal['REVIEWED_TESTNET_GENERATION_RELEASE']='REVIEWED_TESTNET_GENERATION_RELEASE'
    generation_id:str=Field(alias='generationId',pattern=H)
    preparation_manifest:str=Field(alias='preparationManifest',pattern=H)
    artifact_hash:str=Field(alias='artifactHash',pattern=H)
    source_commits:dict[str,str]=Field(alias='sourceCommits')
    runtime_source_hash:str=Field(alias='runtimeSourceHash',pattern=H)
    release_manifest_hash:str=Field(alias='releaseManifestHash',pattern=H)
    action_envelope:str=Field(alias='actionEnvelope',pattern=r'^AE-SOLSLOT-[A-Z0-9-]{1,120}$')
    security_review_hash:str=Field(alias='securityReviewHash',pattern=H)
    backup_receipt_hash:str=Field(alias='backupReceiptHash',pattern=H)
    restore_receipt_hash:str=Field(alias='restoreReceiptHash',pattern=H)
    verified_at:int=Field(alias='verifiedAt',strict=True,gt=0)
    expires_at:int=Field(alias='expiresAt',strict=True,gt=0)
    maximum_fee_mojos:int=Field(alias='maximumFeeMojos',strict=True,ge=0,le=1_000_000_000)
    minimum_free_bytes:int=Field(alias='minimumFreeBytes',strict=True,ge=5*1024**3)
    @model_validator(mode='after')
    def bounded(self):
        if not 0<self.expires_at-self.verified_at<=86400:
            raise ValueError('release/recovery evidence must expire within 24 hours')
        GenerationPreparation.frozen_sources(self.source_commits)
        for value in (self.generation_id,self.preparation_manifest,self.artifact_hash,self.runtime_source_hash,
                self.release_manifest_hash,self.security_review_hash,self.backup_receipt_hash,self.restore_receipt_hash):
            if value=='0x'+'00'*32:raise ValueError('release evidence references must be nonzero')
        return self
    @property
    def digest(self):return commitment(self.model_dump(mode='json',by_alias=True))


class GenerationLaunchStore:
    MAX_REVIEWS=32
    def __init__(self,path,preparation_store,artifact,certificate,*,trusted_certificate_hash):
        self.preparation_store=preparation_store
        self.preparation=GenerationPreparation.model_validate_json(preparation_store.preparation.model_dump_json(by_alias=True))
        self.artifact=GenerationLaunchArtifact.model_validate_json(artifact.model_dump_json(by_alias=True))
        self.certificate=LaunchCertificate.model_validate_json(certificate.model_dump_json(by_alias=True))
        p,a,c=self.preparation,self.artifact,self.certificate
        if (c.digest!=trusted_certificate_hash or c.generation_id!=p.generation_id or c.preparation_manifest!=p.manifest_hash
                or a.generation_id!=p.generation_id or a.preparation_manifest!=p.manifest_hash or c.artifact_hash!=a.artifact_hash
                or c.source_commits!=p.source_commits):raise ValueError('release certificate differs from frozen launch')
        self._trusted_certificate_hash=trusted_certificate_hash
        self._trusted_preparation_hash=p.manifest_hash
        self._trusted_artifact_hash=a.artifact_hash
        self.path=self.initialize_storage(path,p.generation_id)

    @staticmethod
    def initialize_storage(path,generation_id):
        # Schema setup carries no release authority and writes no reviews.
        # This permits real recovery before a launch certificate is issued.
        from .generation_context import generation_bytes
        generation_bytes(generation_id)
        path=generation_path(path,generation_id);Path(path).parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with closing(connect_generation_sqlite(path,timeout=5,generation_id=generation_id)) as db,db:
            db.executescript('''CREATE TABLE IF NOT EXISTS generation_launch_reviews (
                id TEXT PRIMARY KEY, certificate TEXT NOT NULL, payload TEXT NOT NULL, created INTEGER NOT NULL,
                confirmed_height INTEGER, checked_at INTEGER, error_code TEXT);
                CREATE TABLE IF NOT EXISTS generation_launch_signatures (
                review_id TEXT NOT NULL, slot INTEGER NOT NULL, signature TEXT NOT NULL, signed_at INTEGER NOT NULL,
                PRIMARY KEY(review_id,slot));
                CREATE TABLE IF NOT EXISTS generation_launch_read_anchors (
                review_id TEXT PRIMARY KEY, document TEXT NOT NULL);''')
        return path

    def db(self):
        db=connect_generation_sqlite(self.path,timeout=5,generation_id=self.preparation.generation_id)
        db.row_factory=sqlite3.Row
        return db
    def require_ready(self,now):
        self.verify_bindings()
        c=self.certificate
        if not c.verified_at<=now<c.expires_at:raise ValueError('release/recovery certificate needs a fresh reviewed receipt')
        if runtime_source_hash()!=c.runtime_source_hash:raise ValueError('installed source differs from reviewed release')
        usage=shutil.disk_usage(Path(self.path).parent)
        if usage.free<c.minimum_free_bytes or usage.free*10<usage.total:
            raise ValueError('insufficient recovery and execution disk headroom')
    def verify_bindings(self):
        if (self.certificate.digest!=self._trusted_certificate_hash
                or self.preparation.manifest_hash!=self._trusted_preparation_hash
                or self.artifact.artifact_hash!=self._trusted_artifact_hash):
            raise ValueError('installed frozen launch commitments changed in memory')
    def latest(self):
        with closing(self.db()) as db:
            row=db.execute('SELECT id FROM generation_launch_reviews ORDER BY created DESC,id DESC LIMIT 1').fetchone()
        return self.status(row[0]) if row else None
    def status(self,identity):
        self.verify_bindings()
        with closing(self.db()) as db:
            row=db.execute('SELECT * FROM generation_launch_reviews WHERE id=?',(identity,)).fetchone()
            if row is None:raise ValueError('launch review is not saved')
            payload=json.loads(row['payload'])
            if row['certificate']!=self.certificate.digest or identity!=commitment(payload):
                raise ValueError('saved launch review commitment changed')
            approved=[r[0] for r in db.execute('SELECT slot FROM generation_launch_signatures WHERE review_id=? ORDER BY slot',(identity,))]
        return {**payload,'reviewId':identity,'approvedSlots':approved,'launchComplete':row['confirmed_height'] is not None and row['error_code'] is None,
            'confirmedHeight':row['confirmed_height'],'lastCheckedAt':row['checked_at'],'errorCode':row['error_code']}
    def save(self,payload,now,read_anchor):
        identity=commitment(payload);raw=canonical(payload)
        anchor=canonical(read_anchor)
        if len(anchor)>2_200_000 or commitment(read_anchor)!=payload['readAnchorHash']:
            raise ValueError('read anchor differs from the exact assembled launch')
        if len(raw)>131072:raise ValueError('launch review exceeds its storage bound')
        with closing(self.db()) as db,db:
            db.execute('BEGIN IMMEDIATE')
            previous=db.execute('SELECT id,payload FROM generation_launch_reviews ORDER BY created DESC,id DESC LIMIT 1').fetchone()
            if previous and json.loads(previous['payload'])['expiresAt']>now:
                if previous['id']!=identity:raise ValueError('an exact launch review is already pending')
                return self.status(identity)
            count=db.execute('SELECT count(*) FROM generation_launch_reviews').fetchone()[0]
            if count>=self.MAX_REVIEWS:raise ValueError('retained launch evidence needs archive review')
            retained=db.execute('SELECT coalesce(sum(length(payload)+2048),0) FROM generation_launch_reviews').fetchone()[0]
            retained+=db.execute('SELECT coalesce(sum(length(document)),0) FROM generation_launch_read_anchors').fetchone()[0]
            admit_retained_bytes(db,retained,len(raw)+len(anchor)+2048,64*1024**2)
            db.execute('INSERT OR IGNORE INTO generation_launch_reviews VALUES (?,?,?,?,NULL,NULL,NULL)',
                (identity,self.certificate.digest,raw,now))
            db.execute('INSERT OR IGNORE INTO generation_launch_read_anchors VALUES (?,?)',(identity,anchor))
        return self.status(identity)
    def read_anchor(self,identity):
        r=self.status(identity)
        with closing(self.db()) as db:
            row=db.execute('SELECT document FROM generation_launch_read_anchors WHERE review_id=?',(identity,)).fetchone()
        if row is None:raise ValueError('saved read anchor is missing')
        document=json.loads(row[0])
        if commitment(document)!=r['readAnchorHash']:raise ValueError('saved read anchor changed')
        return document
    def typed_data(self,identity,slot):
        if type(slot) is not int or slot not in (1,2,3):raise ValueError('invalid launch signer')
        r=self.status(identity)
        fields=[('reviewId','bytes32'),('preparationManifest','bytes32'),('artifactHash','bytes32'),
            ('certificateHash','bytes32'),('assemblyHash','bytes32'),('administratorSlot','uint8'),
            ('issuedAt','uint64'),('expiresAt','uint64'),('feeCapMojos','uint64')]
        return {'types':{'EIP712Domain':[{'name':'name','type':'string'},{'name':'version','type':'string'},
                    {'name':'salt','type':'bytes32'}],'SolslotGenerationLaunch':[{'name':n,'type':t} for n,t in fields]},
            'primaryType':'SolslotGenerationLaunch','domain':{'name':'Solslot generation launch','version':'1','salt':r['generationId']},
            'message':{n:slot if n=='administratorSlot' else r[n] for n,_ in fields}}
    def approve(self,identity,slot,signature,now):
        r=self.status(identity)
        if not r['issuedAt']<=now<r['expiresAt']:raise ValueError('launch consent expired; saved evidence is retained')
        typed=self.typed_data(identity,slot)
        if Account.recover_message(encode_typed_data(full_message=typed),signature=signature).lower()!=self.preparation.administrators[slot-1].wallet:
            raise ValueError('launch signature differs from assigned administrator')
        with closing(self.db()) as db,db:
            db.execute('INSERT OR IGNORE INTO generation_launch_signatures VALUES (?,?,?,?)',(identity,slot,signature,now))
    def require_consent(self,identity,now):
        r=self.status(identity)
        if not r['issuedAt']<=now<r['expiresAt']:raise ValueError('24-hour launch consent is no longer current')
        with closing(self.db()) as db:
            rows=list(db.execute('SELECT slot,signature FROM generation_launch_signatures WHERE review_id=?',(identity,)))
        if 1 not in {row[0] for row in rows} or not {2,3}&{row[0] for row in rows}:
            raise ValueError('owner and one coadministrator must approve this exact launch')
        for slot,signature in rows:
            if Account.recover_message(encode_typed_data(full_message=self.typed_data(identity,slot)),signature=signature).lower()!=self.preparation.administrators[slot-1].wallet:
                raise ValueError('saved launch consent changed')
        return r
    def observed(self,identity,now,height=None,error=None):
        if error not in (None,'NODE_UNAVAILABLE','LAUNCH_OUTPUTS_UNCONFIRMED'):raise ValueError('unknown launch status')
        with closing(self.db()) as db,db:
            db.execute('UPDATE generation_launch_reviews SET confirmed_height=coalesce(confirmed_height,?), checked_at=?,error_code=? WHERE id=?',
                (height,now,error,identity))


def unsigned_launch_hash(bundle,generation):
    from chia_rs import SpendBundle
    from chia_rs.sized_bytes import bytes32
    return '0x'+Program.to([b'GENERATION_NATIVE_OPERATION_V1',bytes32.from_hexstr(generation),
        b'INITIALIZE_GENERATION',bytes(SpendBundle(bundle.coin_spends,G2Element()))]).get_tree_hash().hex()


def launch_key(preparation):return 'launch:'+preparation.manifest_hash


def saved_launch(store,journal):
    saved=journal.request_status(launch_key(store.preparation))
    if saved:
        body=saved['review'];r=store.status(body['reviewId'])
        expected=request_document(store,r)
        if (body!=expected or saved['kind']!='INITIALIZE_GENERATION' or int(saved['feeCapMojos'])!=r['feeCapMojos']
                or unsigned_launch_hash(journal.protocol_bundle(saved['operationId']),store.preparation.generation_id)!=r['assemblyHash']):
            raise ValueError('saved operation differs from final launch review')
    return saved


def request_document(store,review):
    return {'generationId':store.preparation.generation_id,'kind':'INITIALIZE_GENERATION',
        'requestKey':launch_key(store.preparation),'reviewId':review['reviewId'],
        'certificateHash':store.certificate.digest,'preparationManifest':store.preparation.manifest_hash,
        'artifactHash':store.artifact.artifact_hash,'feeCapMojos':review['feeCapMojos']}


async def assemble_current(store,provider,faucet,issued_at):
    """Unsigned, exact assembly from primary inputs and acknowledged vaults."""
    p=store.preparation
    async with asyncio.timeout(30):
        evidence=await verify_recipient_custody(p,store.preparation_store.signatures(),
            trusted_preparation_hash=p.manifest_hash,provider=provider)
        ids={name:p.sgt_funding_coin_id if name=='sgt' else p.coordinates[name].funding_coin_id for name in NAMES}
        before=await asyncio.gather(*(provider.get_coin_record_by_name_primary(ids[n]) for n in NAMES))
        coins={n:_funding_coin(row,ids[n]) for n,row in zip(NAMES,before,strict=True)}
        if any(c.puzzle_hash!=faucet.address_puzzle_hash for c in coins.values()):raise ValueError('reserved launch input is not owned by the approved funder')
        arguments=dict(preparation=p,artifact=store.artifact,evidence=evidence,trusted_preparation_hash=p.manifest_hash,
            trusted_artifact_hash=store.artifact.artifact_hash,consent_issued_at=issued_at)
        requests=genesis_launch_funding_requests(**arguments,funding_coins=coins)
        spends={r.name:make_spend(r.coin,faucet.key.puzzle,Program.to([0,Program.to((1,r.conditions)),0])) for r in requests}
        built=assemble_genesis_launch(**arguments,funding_spends=spends)
        after=await asyncio.gather(*(provider.get_coin_record_by_name_primary(ids[n]) for n in NAMES))
        if before!=after:raise ValueError('launch inputs changed during source review')
        return built,evidence,coins


async def prepare_launch_review(store,journal,provider,faucet,*,clock=time.time):
    if saved_launch(store,journal):return store.latest()
    now=int(clock());store.require_ready(now)
    previous=store.latest()
    if previous and now<previous['expiresAt']:return previous
    built,_,_=await assemble_current(store,provider,faucet,now)
    store.require_ready(int(clock()))
    assembly=built.review()
    payload={'generationId':store.preparation.generation_id,'network':'testnet11','preparationManifest':store.preparation.manifest_hash,
        'artifactHash':store.artifact.artifact_hash,'certificateHash':store.certificate.digest,
        'assemblyHash':'0x'+built.operation.commitment.hex(),'issuedAt':now,'expiresAt':now+86400,
        'releaseExpiresAt':store.certificate.expires_at,
        'feeCapMojos':store.certificate.maximum_fee_mojos,'sourceCommits':dict(store.preparation.source_commits),
        'actionEnvelope':store.certificate.action_envelope,'releaseManifestHash':store.certificate.release_manifest_hash,
        'securityReviewHash':store.certificate.security_review_hash,'backupReceiptHash':store.certificate.backup_receipt_hash,
        'restoreReceiptHash':store.certificate.restore_receipt_hash,'recipients':store.preparation.review()['recipients'],
        'supply':assembly['supply'],'sgtTailHash':assembly['sgtTailHash'],'sgtOutputs':assembly['sgtOutputs'],
        'exchangeFees':assembly['exchangeFees'],'custody':assembly['custody'],'readAnchorHash':commitment(assembly['readAnchor']),
        'expectedOutputs':[c.to_json_dict() for c in (*[s.coin for s in built.operation.successors],*built.operation.auxiliary_outputs)]}
    return store.save(payload,now,assembly['readAnchor'])


async def prepare_launch_operation(identity,store,journal,provider,faucet,*,clock=time.time):
    saved=saved_launch(store,journal)
    if saved:
        if saved['review']['reviewId']!=identity:raise ValueError('a different exact launch is retained')
        return saved
    now=int(clock());store.require_ready(now);review=store.require_consent(identity,now)
    built,evidence,coins=await assemble_current(store,provider,faucet,review['issuedAt'])
    if '0x'+built.operation.commitment.hex()!=review['assemblyHash']:raise ValueError('native assembly differs from signed launch')
    store.require_ready(int(clock()));store.require_consent(identity,int(clock()))
    # A duplicate click may finish its primary reads after the first request
    # has saved the operation. Resume it before asking the scoped signer.
    saved=saved_launch(store,journal)
    if saved:
        if saved['review']['reviewId']!=identity:raise ValueError('a different exact launch is retained')
        return saved
    operation=faucet.sign_generation_launch(identity,evidence=evidence,funding_coins=coins,now=int(clock()))
    if unsigned_launch_hash(operation.bundle(),store.preparation.generation_id)!=review['assemblyHash']:raise ValueError('scoped signer changed launch intent')
    document=request_document(store,review)
    journal.prepare(operation,document['requestKey'],review['feeCapMojos'],int(clock()),
        request_document=document,request_digest='0x'+sha256(canonical(document).encode()).hexdigest())
    return saved_launch(store,journal)


async def recheck_launch_before_dispatch(identity,store,journal,provider,faucet,*,clock=time.time):
    review=store.require_consent(identity,int(clock()));store.require_ready(int(clock()))
    store.read_anchor(identity)
    saved=saved_launch(store,journal)
    if saved is None or saved['review']['reviewId']!=identity:raise ValueError('exact launch is not saved')
    built,_,_=await assemble_current(store,provider,faucet,review['issuedAt'])
    if '0x'+built.operation.commitment.hex()!=review['assemblyHash']:raise ValueError('confirmed launch inputs changed before dispatch')
    store.require_ready(int(clock()));store.require_consent(identity,int(clock()))


class GenerationLaunchObserver:
    """Check native confirmation after dispatch. Holds no builder or signer."""
    def __init__(self,store,journal,provider,*,clock=time.time):self.store,self.journal,self.provider,self.clock=store,journal,provider,clock
    async def run_once(self):
        saved=saved_launch(self.store,self.journal)
        if saved is None or saved['stage']!='CONFIRMED':return bool(saved and saved['transactionId'])
        r=self.store.status(saved['review']['reviewId'])
        try:
            async with asyncio.timeout(20):
                if (await self.provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('wrong primary network')
                coins=[Coin.from_json_dict(c) for c in r['expectedOutputs']]
                semaphore=asyncio.Semaphore(8)
                async def read(coin):
                    async with semaphore:return await self.provider.get_coin_record_by_name_primary('0x'+coin.name().hex())
                before=await asyncio.gather(*(read(c) for c in coins))
                for coin,row in zip(coins,before,strict=True):
                    if not isinstance(row,dict) or Coin.from_json_dict(row['coin'])!=coin or row['confirmed_block_index']!=saved['confirmedHeight']:
                        raise ValueError('exact initial outputs are not confirmed together')
                if before!=await asyncio.gather(*(read(c) for c in coins)):raise ValueError('launch output evidence changed')
            self.store.observed(r['reviewId'],int(self.clock()),height=saved['confirmedHeight'])
        except (ValueError,KeyError,TypeError):self.store.observed(r['reviewId'],int(self.clock()),error='LAUNCH_OUTPUTS_UNCONFIRMED')
        except (OSError,RuntimeError,TimeoutError):self.store.observed(r['reviewId'],int(self.clock()),error='NODE_UNAVAILABLE')
        return not self.store.status(r['reviewId'])['launchComplete']


def configured_launch_store(settings,preparation_store):
    """Load only locally installed artifacts whose certificate hash is pinned."""
    fields=(settings.generation_launch_artifact_path,settings.generation_launch_certificate_path,settings.generation_launch_certificate_hash)
    if not any(fields):
        if settings.generation_launch_enabled:raise ValueError('final launch cannot enable without its reviewed release certificate')
        return None
    if not all(fields) or preparation_store is None:raise ValueError('final launch configuration is incomplete')
    def read(path):
        with Path(path).open('rb') as stream:raw=stream.read(131073)
        if len(raw)>131072:raise ValueError('installed launch artifact exceeds bound')
        return raw
    artifact=GenerationLaunchArtifact.model_validate_json(read(fields[0]))
    certificate=LaunchCertificate.model_validate_json(read(fields[1]))
    return GenerationLaunchStore(settings.generation_launch_db_path,preparation_store,artifact,certificate,
        trusted_certificate_hash=fields[2])
