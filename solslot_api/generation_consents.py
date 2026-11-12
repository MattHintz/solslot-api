"""Durable, exact owner-plus-one reviews for the replacement generation.

Only explicit preparation contacts the node. GETs read saved public reviews;
they cannot change the consent clock, reserve a coin, construct a transaction
or request a signature. Completing consent does not publish a proposal: the
opening still requires independently reviewed holder sponsorship.
"""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import asyncio
import json
import logging
import os
import sqlite3
import time
from typing import Literal

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia_rs.sized_bytes import bytes32
from pydantic import Field, model_validator

from solslot_puzzles.admin_authority_v3_driver import parse_inner_puzzle
from solslot_puzzles.eip712_helpers import normalize_eip712_member_signature
from solslot_puzzles.generation_admin_transactions import (AdministratorIdentityTip,
    PreparedAdministratorAction, scoped_pause)
from solslot_puzzles.generation_governance import ADMIN_APPROVAL_SECONDS
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.holdings import quorum
from .generation_administrator_evidence import resolve_generation_administrators
from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged, public_bill
from .generation_coin_evidence import read_confirmed_coin
from .generation_context import generation_bytes
from .generation_execution import Hash, Model, ExpectedInputs, UpgradeIntent, ParameterIntent, StatuteIntent,RedemptionIntent
from .generation_operations import canonical
from .generation_registry_evidence import _program
from .generation_storage import connect_generation_sqlite, generation_path, admit_retained_bytes
from .generation_mint_reviews import revalidate_mint_review
from .generation_mint_checks import checked_mint_chain_cache, checked_mint_administrators, primary_mint_coin_records


logger=logging.getLogger(__name__)

class MintConsentTimeout(TimeoutError):
    def __init__(self,stage):
        super().__init__('mint publication preparation timed out')
        self.stage=stage

def h(value): return '0x'+value.hex()


class ConsentRequest(Model):
    generation_id:Hash=Field(alias='generationId')
    request_key:str=Field(alias='requestKey',pattern=r'^[a-zA-Z0-9_:-]{1,128}$')
    kind:Literal['PUBLICATION_APPROVAL','PAUSE_NEW_OPERATIONS']
    coadministrator_slot:int=Field(alias='coadministratorSlot',strict=True,ge=1,le=2)
    expected_inputs:ExpectedInputs=Field(alias='expectedInputs')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)
    proposal_kind:Literal['UPGRADE','PARAMETERS','STATUTES','REOPEN','MINT_TEST_ONLY','FUND_REDEMPTION']|None=Field(default=None,alias='proposalKind')
    mint_review_id:Hash|None=Field(default=None,alias='mintReviewId')
    upgrade:UpgradeIntent|None=None
    parameters:ParameterIntent|None=None
    statutes:StatuteIntent|None=None
    redemption:RedemptionIntent|None=None
    scope:int|None=Field(default=None,strict=True,ge=1,le=31)

    @model_validator(mode='after')
    def exact_fields(self):
        if (self.proposal_kind is not None)!=(self.kind=='PUBLICATION_APPROVAL'):
            raise ValueError('publication requires an explicit typed proposal')
        if bool(self.upgrade)!=(self.proposal_kind=='UPGRADE'):
            raise ValueError('upgrade intent is only valid for code publication')
        if bool(self.parameters)!=(self.proposal_kind=='PARAMETERS'):
            raise ValueError('parameter intent is only valid for parameter publication')
        if bool(self.statutes)!=(self.proposal_kind=='STATUTES'):
            raise ValueError('statutes intent is only valid for a canonical economic record')
        if bool(self.redemption)!=(self.proposal_kind=='FUND_REDEMPTION'):
            raise ValueError('redemption intent is required only for exact funding publication')
        if (self.scope is not None)!=(self.kind=='PAUSE_NEW_OPERATIONS' or self.proposal_kind=='REOPEN'):
            raise ValueError('scope is required only for pause or reopening')
        if (self.mint_review_id is not None)!=(self.proposal_kind=='MINT_TEST_ONLY'):
            raise ValueError('test mint publication requires its exact saved sealed source')
        if self.upgrade:self.upgrade.plan()
        return self

    def document(self):
        # Do not change existing request commitments by adding a null field.
        raw=self.model_dump(mode='json',by_alias=True)
        if self.mint_review_id is None:raw.pop('mintReviewId')
        if self.statutes is None:raw.pop('statutes')
        if self.redemption is None:raw.pop('redemption')
        return raw

    @property
    def digest(self):return h(sha256(canonical(self.document()).encode()).digest())


class GenerationConsentStore:
    MAX_RETAINED_BYTES = 128 * 1024 * 1024
    """Immutable public context and write-once signatures; no private keys."""
    def __init__(self,path,generation_id):
        generation_bytes(generation_id)
        self.generation_id=generation_id
        self.path=generation_path(path,generation_id)
        Path(self.path).parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        os.fchmod(fd,0o600);os.close(fd)
        with self._db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS generation_consents (
                    package_id TEXT PRIMARY KEY, request_key TEXT UNIQUE NOT NULL,
                    request_digest TEXT NOT NULL, document TEXT NOT NULL,
                    created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS generation_consent_signatures (
                    package_id TEXT NOT NULL, slot INTEGER NOT NULL, signature TEXT NOT NULL,
                    signed_at INTEGER NOT NULL, PRIMARY KEY(package_id,slot));
            ''')

    @contextmanager
    def _db(self,write=False):
        db=connect_generation_sqlite(self.path,timeout=5,isolation_level=None,generation_id=self.generation_id)
        db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            if write:db.execute('BEGIN IMMEDIATE')
            yield db
            if write:db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:db.execute('ROLLBACK')
            raise
        finally:db.close()

    def reviewed_request(self,request,now):
        with self._db() as db:
            row=db.execute('SELECT package_id,request_digest FROM generation_consents WHERE request_key=?',
                (request.request_key,)).fetchone()
        if row and row['request_digest']!=request.digest:raise ValueError('retry changes the original consent review')
        return self.status(row['package_id'],now) if row else None

    def save(self,request,document,now):
        if (request.generation_id!=self.generation_id or type(now) is not int or now<=0
                or document.get('generationId')!=self.generation_id
                or document.get('request')!=request.document()):
            raise ValueError('consent review belongs to another generation or request')
        raw=canonical(document)
        if len(raw)>2_000_000:raise ValueError('consent proof exceeds its bound')
        identity=h(sha256(raw.encode()).digest())
        with self._db(write=True) as db:
            row=db.execute('SELECT * FROM generation_consents WHERE request_key=?',(request.request_key,)).fetchone()
            if row:
                if row['document']!=raw or row['request_digest']!=request.digest:
                    raise ValueError('saved signing package cannot be replaced')
                return row['package_id']
            if db.execute('SELECT count(*) FROM generation_consents').fetchone()[0]>=10000:
                raise ValueError('consent journal reached its retention bound; archive review is required')
            retained=db.execute('SELECT coalesce(sum(length(CAST(document AS BLOB))+2048),0) FROM generation_consents').fetchone()[0]
            admit_retained_bytes(db,retained,len(raw.encode())+2048,self.MAX_RETAINED_BYTES)
            db.execute('INSERT INTO generation_consents VALUES (?,?,?,?,?)',
                (identity,request.request_key,request.digest,raw,now))
        return identity

    def document(self,identity):
        generation_bytes(identity)
        with self._db() as db:
            row=db.execute('SELECT * FROM generation_consents WHERE package_id=?',(identity,)).fetchone()
        if row is None:raise ValueError('consent review is unavailable in this generation')
        if h(sha256(row['document'].encode()).digest())!=identity:
            raise ValueError('saved consent review differs from its commitment')
        document=json.loads(row['document']);request=ConsentRequest.model_validate(document['request'])
        if document['generationId']!=self.generation_id or request.generation_id!=self.generation_id or request.digest!=row['request_digest']:
            raise ValueError('saved consent bindings changed')
        return document

    def signatures(self,identity):
        with self._db() as db:
            rows=db.execute('SELECT slot,signature,signed_at FROM generation_consent_signatures WHERE package_id=? ORDER BY slot',
                (identity,)).fetchall()
        return [dict(row) for row in rows]

    def record_signature(self,identity,slot,signature,now):
        document=self.document(identity)
        challenge=next((c for c in document['challenges'] if c['slot']==slot),None)
        if type(slot) is not int or challenge is None:raise ValueError('this slot is not assigned to the review')
        if type(now) is not int or not document['createdAt']<=now<document['expiresAt']:
            raise ValueError('consent window ended; prepare a fresh review explicitly')
        # Normalize and cryptographically verify the signature before storing it.
        normalized=normalize_eip712_member_signature(signature=signature,
            digest=bytes32.from_hexstr(challenge['digest']),compressed_pubkey=bytes.fromhex(challenge['publicKey'][2:]))
        encoded=h(normalized)
        with self._db(write=True) as db:
            old=db.execute('SELECT signature FROM generation_consent_signatures WHERE package_id=? AND slot=?',
                (identity,slot)).fetchone()
            if old and old[0]!=encoded:raise ValueError('an administrator approval cannot be replaced')
            db.execute('INSERT OR IGNORE INTO generation_consent_signatures VALUES (?,?,?,?)',(identity,slot,encoded,now))
        return self.status(identity,now)

    def status(self,identity,now):
        document=self.document(identity);signatures=self.signatures(identity)
        expected={c['slot'] for c in document['challenges']}
        seen=set()
        for row in signatures:
            if row['slot'] not in expected or row['slot'] in seen or not document['createdAt']<=row['signed_at']<document['expiresAt']:
                raise ValueError('saved signature role or timestamp changed')
            challenge=next(c for c in document['challenges'] if c['slot']==row['slot'])
            normalized=normalize_eip712_member_signature(signature=bytes.fromhex(row['signature'][2:]),
                digest=bytes32.from_hexstr(challenge['digest']),compressed_pubkey=bytes.fromhex(challenge['publicKey'][2:]))
            if h(normalized)!=row['signature']:raise ValueError('saved signature is not canonical')
            seen.add(row['slot'])
        stage='EXPIRED' if now>=document['expiresAt'] else 'READY' if seen==expected else 'AWAITING_APPROVALS'
        return {**document['review'],'packageId':identity,'stage':stage,
            'signatures':[{'slot':r['slot'],'signedAt':r['signed_at']} for r in signatures],
            'challenges':document['challenges'],'pollAfterSeconds':5 if stage=='AWAITING_APPROVALS' else 30}

    def recent(self,now,limit=20):
        if type(limit) is not int or not 1<=limit<=50:raise ValueError('review batch is out of bounds')
        with self._db() as db:
            ids=[r[0] for r in db.execute('SELECT package_id FROM generation_consents ORDER BY created_at DESC,package_id LIMIT ?', (limit,))]
        return [self.status(identity,now) for identity in ids]


def _tip_document(tip):
    return {'launcherId':h(tip.launcher_id),'inner':h(bytes(tip.inner)),
        'coin':tip.coin.to_json_dict(),'parentSpend':tip.parent.to_json_dict()}


def restore_consent(document,initial):
    """Reconstruct only the stored exact action against the frozen authority."""
    raw=document['authorityTip']
    admin=SingletonTip(bytes32.from_hexstr(raw['launcherId']),_program(raw['inner']),
        Coin.from_json_dict(raw['coin']),CoinSpend.from_json_dict(raw['parentSpend']))
    policies = initial.identity_vaults
    if 'identityPublicKeys' in document:
        from .generation_admission import PublicIdentity
        from solslot_puzzles.admin_authority_v3_driver import build_admin_identity_vault
        raw_policies = document['identityPublicKeys']
        if not isinstance(raw_policies, list) or len(raw_policies) != 3:
            raise ValueError('saved consent needs all three exact identity policies')
        parsed = [PublicIdentity.model_validate(row) for row in raw_policies]
        if [row.slot for row in parsed] != [0, 1, 2]:
            raise ValueError('saved identity policy slots changed')
        policies = tuple(build_admin_identity_vault(slot=row.slot,
            launcher_id=initial.identity_vaults[row.slot].launcher_id,
            authority_launcher_id=initial.authority_launcher_id, network='testnet11',
            daily_compressed_pubkey=bytes.fromhex(row.daily_public_key[2:]),
            recovery_bls_pubkey=bytes.fromhex(row.recovery_public_key[2:])) for row in parsed)
    if len(document['identityTips']) != 3:
        raise ValueError('saved consent identity inputs are incomplete')
    identities=tuple(AdministratorIdentityTip(policy,Coin.from_json_dict(v['coin']),
        CoinSpend.from_json_dict(v['parentSpend'])) for policy,v in zip(policies,document['identityTips'],strict=True))
    request=ConsentRequest.model_validate(document['request'])
    subject=bytes32.from_hexstr(document['review']['proposalId']) if request.kind=='PUBLICATION_APPROVAL' else (
        document['review']['pauseEpoch'],request.scope)
    prepared=PreparedAdministratorAction(bytes32.from_hexstr(request.generation_id),initial,admin,identities,
        bytes32.from_hexstr(document['review']['targetPuzzleHash']),request.kind,subject,
        document['review']['issuedAt'],request.coadministrator_slot).validate()
    if [_challenge(c) for c in prepared.challenges()]!=document['challenges']:
        raise ValueError('stored action differs from its exact public signing challenges')
    return prepared


def _challenge(challenge):
    return {'slot':challenge.slot,'coinId':h(challenge.coin_id),'delegatedPuzzleHash':h(challenge.delegated_hash),
        'digest':h(challenge.digest),'publicKey':h(challenge.public_key),'typedData':challenge.typed_data()}


async def consent_inputs_unchanged(document,provider):
    if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
        raise ValueError('consent requires the primary Testnet11 node')
    if document['request'].get('proposalKind')=='MINT_TEST_ONLY':
        expected=[read_confirmed_coin(raw,Coin.from_json_dict(raw['coin']).name()) for raw in document['confirmedInputs']]
        identities=list(dict.fromkeys(h(r.coin.name()) for r in expected));observed={}
        for offset in range(0,len(identities),100):
            batch=identities[offset:offset+100]
            values=await primary_mint_coin_records(batch,provider=provider)
            observed.update(zip(batch,values,strict=True))
        for record in expected:
            current=read_confirmed_coin(observed[h(record.coin.name())],record.coin.name())
            if current!=record or current.spent_height:raise ValueError('a reviewed input changed; refresh and prepare a new review')
    else:
        for raw in document['confirmedInputs']:
            expected=read_confirmed_coin(raw, Coin.from_json_dict(raw['coin']).name())
            observed=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(expected.coin.name())),expected.coin.name())
            if observed!=expected or observed.spent_height:raise ValueError('a reviewed input changed; refresh and prepare a new review')
    intent=document['request'].get('redemption')
    if intent:
        raw=document.get('redemptionParent')
        if not isinstance(raw,dict):raise ValueError('reviewed redemption funding parent is unavailable')
        expected=read_confirmed_coin(raw,bytes32.from_hexstr(intent['treasuryParentId']))
        observed=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(expected.coin.name())),expected.coin.name())
        source_id=bytes32.from_hexstr(intent['treasuryCoinId'])
        sources=[read_confirmed_coin(raw,Coin.from_json_dict(raw['coin']).name())
            for raw in document['confirmedInputs'] if Coin.from_json_dict(raw['coin']).name()==source_id]
        if (observed!=expected or len(sources)!=1 or not expected.spent_height
                or sources[0].coin.parent_coin_info!=expected.coin.name()
                or sources[0].confirmed_height!=expected.spent_height):
            raise ValueError('reviewed redemption funding lineage changed')
    elif document.get('redemptionParent') is not None:
        raise ValueError('an unrelated consent cannot contain redemption funding evidence')


async def prepare_consent(request,*,anchor,provider,store,clock=time.time,settings=None,collections=None,mint_reviews=None,index=None,admission=None):
    request=ConsentRequest.model_validate_json(request.model_dump_json(by_alias=True))
    if request.generation_id!=store.generation_id or bytes32.from_hexstr(request.generation_id)!=anchor.issuance.generation:
        raise ValueError('consent belongs to another generation')
    saved=store.reviewed_request(request,int(clock()))
    if saved:return saved # Explicit retry recovers the original clock even offline.
    if anchor.administrator is None:raise ValueError('frozen administrator anchor is unavailable')
    stage='VERIFYING_CHAIN'
    def phase(value):
        nonlocal stage
        stage=value
        if request.proposal_kind=='MINT_TEST_ONLY':logger.info('mint_consent stage=%s request=%s',stage,request.digest)
    phase(stage)
    try:
        async with asyncio.timeout(40 if request.proposal_kind=='MINT_TEST_ONLY' else 60):
            chain=await checked_mint_chain_cache(anchor,provider=provider,index=index) if request.proposal_kind=='MINT_TEST_ONLY' else None
            if chain is None:chain=await resolve_generation_chain(anchor,provider=provider)
            phase('VERIFYING_ADMINISTRATORS')
            admins=await checked_mint_administrators(anchor,settings=settings,provider=provider,admission=admission) if request.proposal_kind=='MINT_TEST_ONLY' else None
            if admins is None:admins=await resolve_generation_administrators(anchor.administrator,provider=provider)
            gov,registry=chain.governance.state,chain.registry.state
            for name in ('registry','governance','holdings'):
                if h(getattr(chain,name).current.coin.name())!=getattr(request.expected_inputs,name):
                    raise ValueError('confirmed chain inputs changed before review')
            mint_source=None;mint_records=();redemption_records=()
            if request.proposal_kind=='MINT_TEST_ONLY':
                phase('RECHECKING_SEALED_BATCH')
                mint_source,edition,mint_records=await revalidate_mint_review(request.mint_review_id,
                    settings=settings,collections=collections,store=mint_reviews,chain=chain,provider=provider)
                for transition in chain.governance.transitions:
                    previous=transition.after.active if transition.action=='OPEN' else None
                    if (previous is not None and previous.bill==edition.bill()
                            and gov.action_key(previous.proposal_id,previous.bill) in gov.approved.keys):
                        raise ValueError('the approved test edition awaits execution; do not open another vote')
            required=({bytes32.from_hexstr(request.parameters.component_id)} if request.proposal_kind=='PARAMETERS'
                else {bytes32.from_hexstr(request.statutes.component_id)} if request.proposal_kind=='STATUTES'
                else {bytes32.from_hexstr(mint_source['mintAuthority']['componentId'])} if mint_source else set())
            if {bytes32.from_hexstr(k) for k in request.expected_inputs.components}!=required:
                raise ValueError('affected economic inputs must be explicitly reviewed')
            if mint_source and request.expected_inputs.components[mint_source['mintAuthority']['componentId']]!=mint_source['mintAuthority']['coinId']:
                raise ValueError('reviewed mint authority input changed')
            bill=None
            if request.kind=='PUBLICATION_APPROVAL':
                if gov.active or not chain.holdings.state[0].root.eligible or (registry.pause_mask&1 and request.proposal_kind!='REOPEN'):
                    raise ValueError('finish the existing vote or unblock proposal opening first')
                if request.proposal_kind=='UPGRADE':
                    if registry.pending or gov.upgrade_reserved:raise ValueError('finish the pending upgrade first')
                    plan=request.upgrade.plan();registry.updated_components(plan)
                    bill=Program.to([b'UPGRADE',registry.nonce,plan.program()])
                elif request.proposal_kind=='PARAMETERS':
                    p=request.parameters;history=chain.economic_components.get(bytes32.from_hexstr(p.component_id))
                    if (history is None or not isinstance(history.state,GenerationParameters)
                            or h(history.current.coin.name())!=request.expected_inputs.components[p.component_id]
                            or h(history.state.launcher_id)!=p.launcher_id or history.state.revision!=p.revision
                            or h(Program.to(list(history.state.values)).get_tree_hash())!=p.previous_values_hash):
                        raise ValueError('parameter intent differs from the current authority')
                    bill=history.state.bill(p.values)
                elif request.proposal_kind=='STATUTES':
                    intent=request.statutes;history=chain.economic_components.get(bytes32.from_hexstr(intent.component_id))
                    if history is None or h(history.current.coin.name())!=request.expected_inputs.components[intent.component_id]:
                        raise ValueError('statutes input changed before review')
                    bill=intent.bill(history.state)
                elif request.proposal_kind=='MINT_TEST_ONLY':
                    bill=edition.bill()
                elif request.proposal_kind=='FUND_REDEMPTION':
                    from solslot_puzzles.generation_redemptions import redemption_bill
                    from .generation_redemption_evidence import verified_redemption_source
                    if registry.pause_mask&8:raise ValueError('new redemption funding is paused')
                    source,redemption_records=await verified_redemption_source(request.redemption,governance=gov,provider=provider)
                    bill=redemption_bill(gov,source,request.redemption.plan(),bytes32.from_hexstr(request.redemption.deed_launcher_puzzle_hash))
                else:
                    if registry.reopening or request.scope&registry.pause_mask!=request.scope:
                        raise ValueError('reopening scope differs from the current pause')
                    bill=Program.to([b'REOPEN',registry.pause_epoch,request.scope])
            phase('BUILDING_REVIEW')
            current=admins.authority.verified_tip(registry.administrator_id,admins.authority.state)
            from .generation_admission import identity_policies
            policies = identity_policies(settings, anchor.administrator)
            # Public key preimages are not authority. Every policy must reconstruct
            # the exact current custody output independently verified on chain.
            identities=tuple(e.verified_tip(policy,current.launcher_id)
                for e,policy in zip(admins.identities,policies,strict=True))
            now=int(clock());issued=now if bill is not None else 0
            subject=gov.proposal_id(bill,chain.holdings.state[0]) if bill is not None else (registry.pause_epoch,request.scope)
            target=chain.governance.current.coin.puzzle_hash if bill is not None else chain.registry.current.coin.puzzle_hash
            prepared=PreparedAdministratorAction(anchor.issuance.generation,anchor.administrator,current,identities,
                target,request.kind,subject,issued,request.coadministrator_slot).validate()
            review={'generationId':request.generation_id,'network':'testnet11','kind':request.kind,
                'request':request.document(),
                'requestKey':request.request_key,'requestDigest':request.digest,'createdAt':now,
                'issuedAt':issued,'expiresAt':now+ADMIN_APPROVAL_SECONDS,'feeCapMojos':str(request.fee_cap_mojos),
                'coadministratorSlot':request.coadministrator_slot,'targetPuzzleHash':h(target),
                'authorityLauncherId':h(current.launcher_id),'authorityCoinId':h(current.coin.name()),
                'authorityCoin':current.coin.to_json_dict(),
                'authorityPuzzleHash':h(current.coin.puzzle_hash),'authorityInnerHash':h(current.inner.get_tree_hash()),
                'sourceManifestHash':h(anchor.administrator.source_manifest_hash),
                'authorityVersion':parse_inner_puzzle(current.inner).state.authority_version,
                'authorityDelegatedHash':h(prepared.delegated().get_tree_hash()),
                'identityCustodies':[h(t.identity.custody_hash) for t in identities],
                'identityPuzzles':[h(t.identity.full_puzzle_hash) for t in identities],
                'identityLauncherIds':[h(t.identity.launcher_id) for t in identities],
                'identityCoins':[t.coin.to_json_dict() for t in identities],
                'proposalId':h(subject) if bill is not None else None,'proposal':public_bill(bill) if bill is not None else None,
                'billHash':h(bill.get_tree_hash()) if bill is not None else None,
                'eligibleSupply':chain.holdings.state[0].root.eligible,
                'governanceNonce':gov.nonce,'eligibleTotal':chain.holdings.state[0].root.total,
                'requiredVotes':quorum(chain.holdings.state[0].root.eligible) if bill is not None else None,
                'holdingsRoot':h(chain.holdings.state[0].root.hash),'pauseEpoch':registry.pause_epoch,
                'scope':request.scope,'expectedInputs':request.expected_inputs.model_dump(mode='json',by_alias=True)}
            if mint_source:review['mintSource']=mint_source
            records=(*chain.current_records,*admins.current_records,*mint_records,*redemption_records[:1])
            def raw_record(record):
                return {'coin':record.coin.to_json_dict(),'confirmed_block_index':record.confirmed_height,
                    'spent_block_index':record.spent_height,'spent':bool(record.spent_height)}
            document={'generationId':request.generation_id,'request':request.document(),
                'createdAt':now,'expiresAt':review['expiresAt'],'review':review,
                'authorityTip':_tip_document(current),'identityTips':[{'coin':t.coin.to_json_dict(),
                    'parentSpend':t.parent.to_json_dict()} for t in identities],
                'confirmedInputs':[raw_record(r) for r in records],
                'challenges':[_challenge(c) for c in prepared.challenges()]}
            if policies != anchor.administrator.identity_vaults:
                document['identityPublicKeys'] = [{'slot':p.slot,
                    'dailyPublicKey':h(p.daily_compressed_pubkey),
                    'recoveryPublicKey':h(p.recovery_bls_pubkey)} for p in policies]
            if redemption_records:document['redemptionParent']=raw_record(redemption_records[1])
            restore_consent(document,anchor.administrator)
            phase('RECHECKING_INPUTS')
            if not await current_evidence_unchanged(chain,provider=provider):raise ValueError('chain changed during preparation')
            await consent_inputs_unchanged(document,provider)
            phase('SAVING_REVIEW')
            identity=store.save(request,document,now)
            return store.status(identity,now)
    except TimeoutError as exc:
        if request.proposal_kind!='MINT_TEST_ONLY':raise
        logger.warning('mint_consent timeout stage=%s request=%s',stage,request.digest)
        raise MintConsentTimeout(stage) from exc


async def sign_consent(identity,slot,signature,*,anchor,provider,store,clock=time.time):
    document=store.document(identity)
    if anchor.administrator is None:raise ValueError('frozen administrator anchor is unavailable')
    restore_consent(document,anchor.administrator)
    async with asyncio.timeout(20):await consent_inputs_unchanged(document,provider)
    return store.record_signature(identity,slot,signature,int(clock()))


async def prepare_scoped_pause(identity,*,anchor,provider,store,journal,clock=time.time):
    document=store.document(identity);request=ConsentRequest.model_validate(document['request'])
    if request.kind!='PAUSE_NEW_OPERATIONS':raise ValueError('publication still requires exact holder sponsorship')
    key='pause:'+identity
    review={'generationId':store.generation_id,'requestKey':key,'kind':'PAUSE_NEW_OPERATIONS',
        'packageId':identity,'scope':request.scope,'pauseEpoch':document['review']['pauseEpoch'],
        'feeCapMojos':request.fee_cap_mojos}
    review_digest=h(sha256(canonical(review).encode()).digest())
    saved=journal.reviewed_request(key,review_digest)
    if saved:return saved
    if store.status(identity,int(clock()))['stage']!='READY':raise ValueError('both unexpired administrator approvals are required')
    async with asyncio.timeout(40):
        await consent_inputs_unchanged(document,provider)
        chain=await resolve_generation_chain(anchor,provider=provider)
        consent=restore_consent(document,anchor.administrator)
        signatures={r['slot']:bytes.fromhex(r['signature'][2:]) for r in store.signatures(identity)}
        registry=chain.registry.state;tip=chain.registry.verified_tip(registry.launcher_id,registry.inner())
        operation,_,_=scoped_pause(registry,tip,consent,signatures)
        if not await current_evidence_unchanged(chain,provider=provider):raise ValueError('chain changed during preparation')
        # The durable operation retains the public scope/consent package for
        # human review. No fee selection, key request or dispatch occurs here.
        operation_id=journal.prepare(operation,key,request.fee_cap_mojos,int(clock()),
            request_digest=review_digest,request_document=review)
        return journal.status(operation_id)
