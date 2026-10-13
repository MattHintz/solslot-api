"""Exact, durable co-sponsorship and holder-vote preparation.

This R1 candidate does not grant launch or dispatch permission. Wallet
signatures authorize a whole holding to one exact proposal. Combining reviews
never pools custody, adds reserve weight or extends an opening clock. Polling
reads saved context only; final assembly rechecks the native inputs and keeps
the result in the existing write-once operation journal before any broadcast.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import os
import sqlite3
from pathlib import Path
import time
from typing import Literal

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from eth_keys import keys
from pydantic import Field, model_validator

from solslot_puzzles.eip712_helpers import normalize_eip712_member_signature
from solslot_puzzles.generation_admin_transactions import complete_administrator_action
from solslot_puzzles.generation_ballots import CurrentHoldings, CustodyAuthorization, SGTInput, open_proposal, cast_vote
from solslot_puzzles.generation_governance import ADMIN_APPROVAL_SECONDS, MINIMUM_SPONSORSHIP
from solslot_puzzles.generation_sgt import SGTOutput, ledger_inner, transition_digest
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.generation_vault import authorization_hash, authorization_solution, signing_data, signing_digest
from solslot_puzzles.holdings import HoldingKind, quorum
from .faucet import AGG_SIG_ME_DATA
from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged, public_bill
from .generation_coin_evidence import read_confirmed_coin
from .generation_consents import ConsentRequest, restore_consent, consent_inputs_unchanged, _tip_document
from .generation_context import generation_bytes
from .generation_execution import Hash, Model, ExpectedInputs
from .generation_holder_evidence import resolve_holder_custody
from .generation_holding_evidence import verified_sgt_inputs
from .generation_operations import canonical
from .generation_registry_evidence import _program
from .generation_storage import connect_generation_sqlite, generation_path, admit_retained_bytes
from .generation_mint_reviews import reviewed_mint_edition


def h(value):return '0x'+bytes(value).hex()


class SelectedHolderCoin(Model):
    coin_id:Hash=Field(alias='coinId')
    vault_launcher_id:Hash=Field(alias='vaultLauncherId')


class HolderBallotRequest(Model):
    generation_id:Hash=Field(alias='generationId')
    request_key:str=Field(alias='requestKey',pattern=r'^[a-zA-Z0-9_:-]{1,128}$')
    kind:Literal['OPEN_PROPOSAL','CAST_VOTE']
    proposal_id:Hash=Field(alias='proposalId')
    consent_package_id:Hash|None=Field(default=None,alias='consentPackageId')
    expected_inputs:ExpectedInputs=Field(alias='expectedInputs')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)
    selected:tuple[SelectedHolderCoin,...]=Field(min_length=1,max_length=32)

    @model_validator(mode='after')
    def selection(self):
        if bool(self.consent_package_id)!=(self.kind=='OPEN_PROPOSAL'):
            raise ValueError('opening requires the exact saved administrator consent')
        if (len({v.coin_id for v in self.selected})!=len(self.selected)
                or len({v.vault_launcher_id for v in self.selected})!=len(self.selected)):
            raise ValueError('select distinct complete inputs, at most one per custody continuation')
        if self.expected_inputs.components:
            raise ValueError('holder ballots do not change economic components')
        return self

    @property
    def digest(self):return h(sha256(canonical(self.model_dump(mode='json',by_alias=True)).encode()).digest())


def _signature(row,signature):
    fields=row['context'];request=row['request'];owner=fields['owner']
    if not isinstance(signature,bytes):raise ValueError('signature must use exact bytes')
    if owner['authType']==3:
        digest=signing_digest(bytes32.from_hexstr(request['generationId']),bytes32.from_hexstr(request['vaultCoinId']),
            bytes32.from_hexstr(request['sgtCoinId']),bytes32.from_hexstr(row['transitionDigest']),request['expiresAt'])
        return normalize_eip712_member_signature(signature=signature,digest=bytes32(digest),
            compressed_pubkey=bytes.fromhex(owner['publicKey'][2:]))
    if owner['authType']!=1 or len(signature)!=96:raise ValueError('unsupported holder authorization')
    pk=G1Element.from_bytes(bytes.fromhex(owner['publicKey'][2:]));sig=G2Element.from_bytes(signature)
    message=bytes32.from_hexstr(row['authorizationHash'])+bytes32.from_hexstr(request['vaultCoinId'])+AGG_SIG_ME_DATA['testnet11']
    if pk==G1Element() or not AugSchemeMPL.verify(pk,message,sig):
        raise ValueError('BLS holder signature does not authorize this exact Testnet11 holding')
    return bytes(sig)


class GenerationBallotStore:
    MAX_RETAINED_BYTES = 256 * 1024 * 1024
    def __init__(self,path,generation_id):
        generation_bytes(generation_id);self.generation_id=generation_id;self.path=generation_path(path,generation_id)
        Path(self.path).parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600);os.close(fd)
        with self._db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''CREATE TABLE IF NOT EXISTS generation_ballot_reviews (
                package_id TEXT PRIMARY KEY,request_key TEXT UNIQUE NOT NULL,request_digest TEXT NOT NULL,
                document TEXT NOT NULL,created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS generation_ballot_signatures (
                package_id TEXT NOT NULL,coin_id TEXT NOT NULL,signature TEXT NOT NULL,signed_at INTEGER NOT NULL,
                PRIMARY KEY(package_id,coin_id));''')

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
            row=db.execute('SELECT package_id,request_digest FROM generation_ballot_reviews WHERE request_key=?',
                (request.request_key,)).fetchone()
        if row and row['request_digest']!=request.digest:raise ValueError('retry changes the reviewed holder selection')
        return self.status(row['package_id'],now) if row else None

    def save(self,request,document,now):
        if (request.generation_id!=self.generation_id or document.get('generationId')!=self.generation_id
                or document.get('request')!=request.model_dump(mode='json',by_alias=True)
                or type(now) is not int or now<=0 or document.get('createdAt')!=now):
            raise ValueError('ballot review differs from its generation or original request')
        raw=canonical(document)
        if len(raw)>2_000_000:raise ValueError('ballot review exceeds its retention bound')
        identity=h(sha256(raw.encode()).digest())
        with self._db(write=True) as db:
            old=db.execute('SELECT * FROM generation_ballot_reviews WHERE request_key=?',(request.request_key,)).fetchone()
            if old:
                if old['document']!=raw or old['request_digest']!=request.digest:raise ValueError('saved holder review cannot be replaced')
                return old['package_id']
            if db.execute('SELECT count(*) FROM generation_ballot_reviews').fetchone()[0]>=10000:
                raise ValueError('ballot journal needs an explicit archive review')
            retained=db.execute('SELECT coalesce(sum(length(CAST(document AS BLOB))+17408),0) FROM generation_ballot_reviews').fetchone()[0]
            # Reserve space for all 32 write-once signature rows up front.
            admit_retained_bytes(db,retained,len(raw.encode())+1024+32*512,self.MAX_RETAINED_BYTES)
            db.execute('INSERT INTO generation_ballot_reviews VALUES (?,?,?,?,?)',(identity,request.request_key,request.digest,raw,now))
        return identity

    def document(self,identity):
        generation_bytes(identity)
        with self._db() as db:row=db.execute('SELECT * FROM generation_ballot_reviews WHERE package_id=?',(identity,)).fetchone()
        if row is None:raise ValueError('holder review is unavailable in this generation')
        if h(sha256(row['document'].encode()).digest())!=identity:raise ValueError('saved holder review changed')
        doc=json.loads(row['document']);request=HolderBallotRequest.model_validate(doc['request'])
        if request.generation_id!=self.generation_id or doc['generationId']!=self.generation_id or request.digest!=row['request_digest']:
            raise ValueError('holder generation or request bindings changed')
        return doc

    def signatures(self,identity):
        return self._signature_rows(identity)

    def _signature_rows(self,identity):
        with self._db() as db:
            return [dict(r) for r in db.execute('SELECT coin_id,signature,signed_at FROM generation_ballot_signatures WHERE package_id=? ORDER BY coin_id',(identity,))]

    def record_signature(self,identity,coin_id,signature,now):
        doc=self.document(identity);row=next((r for r in doc['holders'] if r['request']['sgtCoinId']==coin_id),None)
        if row is None or type(now) is not int or not doc['createdAt']<=now<doc['expiresAt']:
            raise ValueError('holder is not selected or its signing window ended')
        encoded=h(_signature(row,signature))
        with self._db(write=True) as db:
            old=db.execute('SELECT signature FROM generation_ballot_signatures WHERE package_id=? AND coin_id=?',(identity,coin_id)).fetchone()
            if old and old[0]!=encoded:raise ValueError('saved holder signature cannot be replaced')
            db.execute('INSERT OR IGNORE INTO generation_ballot_signatures VALUES (?,?,?,?)',(identity,coin_id,encoded,now))
        return self.status(identity,now)

    def status(self,identity,now):
        doc=self.document(identity);rows=self._signature_rows(identity);holders={r['request']['sgtCoinId']:r for r in doc['holders']}
        for row in rows:
            if (row['coin_id'] not in holders or not doc['createdAt']<=row['signed_at']<doc['expiresAt']
                    or h(_signature(holders[row['coin_id']],bytes.fromhex(row['signature'][2:])))!=row['signature']):
                raise ValueError('saved holder signature or timestamp changed')
        return {**doc['review'],'packageId':identity,'holders':doc['holders'],
            'stage':'EXPIRED' if now>=doc['expiresAt'] else 'READY' if len(rows)==len(holders) else 'AWAITING_HOLDER_SIGNATURES',
            'signatures':[{'coinId':r['coin_id'],'signedAt':r['signed_at']} for r in rows],
            'pollAfterSeconds':5 if len(rows)<len(holders) and now<doc['expiresAt'] else 30}

    def recent(self,now,limit=20):
        if type(limit) is not int or not 1<=limit<=50:raise ValueError('ballot review batch is out of bounds')
        with self._db() as db:ids=[r[0] for r in db.execute('SELECT package_id FROM generation_ballot_reviews ORDER BY created_at DESC,package_id LIMIT ?',(limit,))]
        return [self.status(v,now) for v in ids]


def _coin(coin):return {'parentCoinInfo':h(coin.parent_coin_info),'puzzleHash':h(coin.puzzle_hash),'amount':int(coin.amount)}
def _spend(spend):return {'coin':_coin(spend.coin),'puzzleReveal':h(spend.puzzle_reveal),'solution':h(spend.solution)}
def _record(record):return {'coin':record.coin.to_json_dict(),'confirmed_block_index':record.confirmed_height,
    'spent_block_index':record.spent_height,'spent':bool(record.spent_height)}
def _context_record(record):return {'coin':_coin(record.coin),'confirmedHeight':record.confirmed_height,'spentHeight':record.spent_height}


def _publication_bill(document):
    request=ConsentRequest.model_validate(document['request']);proposal=document['review']['proposal']
    if request.proposal_kind=='UPGRADE':return Program.to([b'UPGRADE',proposal['registryNonce'],request.upgrade.plan().program()])
    if request.proposal_kind=='PARAMETERS':
        p=request.parameters;return Program.to([b'PARAMETERS',bytes32.from_hexstr(p.component_id),bytes32.from_hexstr(p.launcher_id),
            p.revision,bytes32.from_hexstr(p.previous_values_hash),list(p.values)])
    if request.proposal_kind=='REOPEN':return Program.to([b'REOPEN',proposal['pauseEpoch'],request.scope])
    if request.proposal_kind=='MINT_TEST_ONLY':
        source=document['review'].get('mintSource')
        if (source is None or source['packageId']!=request.mint_review_id or source['generationId']!=request.generation_id):
            raise ValueError('publication requires the exact sealed test mint source')
        bill=reviewed_mint_edition(source).bill()
        if public_bill(bill)!=proposal:raise ValueError('test mint publication differs from its saved edition')
        return bill
    raise ValueError('holder publication requires a supported typed bill')


async def ballot_inputs_unchanged(document,provider):
    if (await provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('primary node network changed')
    for raw in document['confirmedInputs']:
        expected=read_confirmed_coin(raw,Coin.from_json_dict(raw['coin']).name())
        actual=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(expected.coin.name())),expected.coin.name())
        if expected!=actual or actual.spent_height:raise ValueError('reviewed ballot input changed')


async def prepare_holder_ballot(request,*,anchor,custodies,provider,store,consents,clock=time.time):
    request=HolderBallotRequest.model_validate_json(request.model_dump_json(by_alias=True))
    if request.generation_id!=store.generation_id or bytes32.from_hexstr(request.generation_id)!=anchor.issuance.generation:
        raise ValueError('holder review belongs to another deployment generation')
    saved=store.reviewed_request(request,int(clock()))
    if saved:return saved
    custodies=tuple(custodies)
    frozen={h(c.launcher_id):c for c in custodies}
    if len(frozen)!=len(custodies) or any(c.generation!=anchor.issuance.generation for c in frozen.values()):
        raise ValueError('custody catalog has ambiguous or wrong-generation bindings')
    async with asyncio.timeout(60):
        chain=await resolve_generation_chain(anchor,provider=provider)
        gov,reg=chain.governance.state,chain.registry.state;tree,seq=chain.holdings.state
        for name in ('registry','governance','holdings'):
            if h(getattr(chain,name).current.coin.name())!=getattr(request.expected_inputs,name):raise ValueError('ballot chain inputs changed')
        now=int(clock());consent=None
        if request.kind=='OPEN_PROPOSAL':
            if consents is None or consents.generation_id!=store.generation_id or consents.status(request.consent_package_id,now)['stage']!='READY':
                raise ValueError('both unexpired exact publication approvals are required')
            consent=consents.document(request.consent_package_id)
            if consent['request']['kind']!='PUBLICATION_APPROVAL' or request.fee_cap_mojos>consent['request']['feeCapMojos']:
                raise ValueError('opening changes the approved action or fee ceiling')
            await consent_inputs_unchanged(consent,provider);bill=_publication_bill(consent)
            snapshot=tree;proposal=gov.proposal_id(bill,snapshot);closes=None;expires=consent['expiresAt']
            if gov.active or (reg.pause_mask&1 and bill.first().as_atom()!=b'REOPEN') or h(proposal)!=consent['review']['proposalId']:
                raise ValueError('publication differs from the current proposal, pause or snapshot')
        else:
            if not gov.active or not gov.active.opened_at:raise ValueError('vote opening is not yet confirmed and anchored')
            bill=gov.active.bill;proposal=gov.active.proposal_id;closes=gov.active.voting_closes_at
            snapshot,snapshot_seq=chain.snapshots[proposal]
            if snapshot.root!=gov.active.snapshot or snapshot_seq!=gov.active.ledger_sequence:
                raise ValueError('confirmed opening snapshot differs from the proposal')
            expires=closes
        if request.proposal_id!=h(proposal) or not now<expires<=now+ADMIN_APPROVAL_SECONDS:
            raise ValueError('exact proposal or its original signing deadline changed')
        inputs=await verified_sgt_inputs(tuple(bytes32.from_hexstr(v.coin_id) for v in request.selected),
            bindings=gov.sgt,tree=tree,provider=provider)
        from solslot_puzzles.generation_governance import ballot_witnesses
        ballot_witnesses(snapshot,[i.coin.name() for i in inputs],gov.closed)
        if request.kind=='OPEN_PROPOSAL' and sum(i.coin.amount for i in inputs)<MINIMUM_SPONSORSHIP:
            raise ValueError('co-sponsorship needs at least 10,000 eligible SGT without pooling custody')
        rows,tips,records=[],[],list(chain.current_records)
        for selected,item in zip(request.selected,inputs,strict=True):
            custody=frozen.get(selected.vault_launcher_id)
            if custody is None or custody.owner!=item.descriptor.owner:
                raise ValueError('selected holding does not belong to an enrolled frozen custody vault')
            history=await resolve_holder_custody(custody,provider=provider);tip=history.verified_tip(custody.launcher_id,history.state)
            fields=custody.fields(history.state);key=fields[1].as_atom();auth_type=fields[2].as_int()
            output=replace(item.descriptor,kind=HoldingKind.LOCKED_HOLDER,lock_id=proposal)
            digest=transition_digest(gov.sgt,item.coin,'LOCK',(output,))
            authhash=authorization_hash(gov.sgt.generation,tip.coin.name(),item.coin.name(),digest,expires)
            context={'generationId':store.generation_id,'network':'testnet11','bindings':{
                'ledgerLauncherId':h(gov.sgt.ledger_launcher_id),'governanceLauncherId':h(gov.sgt.governance_launcher_id),
                'reserveOwner':h(gov.sgt.reserve_owner),'tailHash':h(gov.sgt.tail_hash),'poolLauncherId':h(custody.pool_id),
                'bridgePolicyHash':h(custody.bridge_policy_hash)},
                'owner':{'authType':auth_type,'publicKey':h(key),'address':h(key) if auth_type==1 else keys.PublicKey.from_compressed_bytes(key).to_address()},
                'vault':{'launcherId':h(tip.launcher_id),'identityRoot':h(fields[4].as_atom()),
                    'current':_context_record(history.current),'parentSpend':_spend(tip.parent)},
                'holding':{'current':_context_record(read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(item.coin.name())),item.coin.name()))},
                'selection':{'action':'LOCK','proposalId':h(proposal),'snapshotRoot':h(snapshot.root.hash),
                    'eligibleSupply':snapshot.root.eligible,'snapshotProof':[[h(v[0]),v[1],v[2]] for v in snapshot.proof(item.coin.name())],
                    'votingClosesAt':closes}}
            if item.descriptor.kind==HoldingKind.LOCKED_HOLDER:
                context['holding']['priorLock']={'proposalId':h(item.descriptor.lock_id),'closedRoot':h(gov.closed.root),
                    'closedProof':[h(v) for v in gov.closed.proof(item.descriptor.lock_id)]}
            wallet={'generationId':store.generation_id,'action':'LOCK','expiresAt':expires,'vaultCoinId':h(tip.coin.name()),
                'sgtCoinId':h(item.coin.name()),'outputs':[{'kind':2,'owner':h(output.owner),'amount':output.amount,'lockId':h(proposal)}]}
            if auth_type==1:wallet['vaultCoinSpend']=_spend(tip.spend(authorization_solution(
                gov.sgt.generation,tip.coin,tip.inner,item.coin.name(),digest,expires)))
            else:wallet['typedData']=signing_data(gov.sgt.generation,tip.coin.name(),item.coin.name(),digest,expires)
            rows.append({'context':context,'request':wallet,'transitionDigest':h(digest),'authorizationHash':h(authhash)})
            tips.append({'vault':_tip_document(tip),'holding':{'coin':item.coin.to_json_dict(),
                'descriptor':[int(item.descriptor.kind),h(item.descriptor.owner),item.descriptor.amount,h(item.descriptor.lock_id) if item.descriptor.lock_id else None],
                'parentSpend':item.parent.to_json_dict()}})
            records.extend([history.current,read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(item.coin.name())),item.coin.name())])
        review={'generationId':store.generation_id,'network':'testnet11','kind':request.kind,'request':request.model_dump(mode='json',by_alias=True),
            'requestDigest':request.digest,'createdAt':now,'expiresAt':expires,'proposalId':h(proposal),'proposal':public_bill(bill),
            'proposalNonce':gov.nonce if request.kind=='OPEN_PROPOSAL' else gov.nonce-1,
            'eligibleSupply':snapshot.root.eligible,'requiredVotes':quorum(snapshot.root.eligible),'selectedWeight':sum(i.coin.amount for i in inputs),
            'snapshotRoot':h(snapshot.root.hash),'votingClosesAt':closes,'feeCapMojos':str(request.fee_cap_mojos),
            'selectionRule':'Lock each complete selected input; retain each owner. Transferred or new outputs are eligible next proposal.'}
        doc={'generationId':store.generation_id,'request':request.model_dump(mode='json',by_alias=True),'createdAt':now,'expiresAt':expires,
            'review':review,'holders':rows,'tips':tips,'confirmedInputs':[_record(r) for r in records]}
        if not await current_evidence_unchanged(chain,provider=provider):raise ValueError('chain changed during holder review')
        await ballot_inputs_unchanged(doc,provider)
        identity=store.save(request,doc,now);return store.status(identity,now)


async def sign_holder_ballot(identity,coin_id,signature,*,provider,store,clock=time.time):
    doc=store.document(identity)
    async with asyncio.timeout(20):await ballot_inputs_unchanged(doc,provider)
    return store.record_signature(identity,coin_id,signature,int(clock()))


def _saved_authorizations(document,store,identity):
    signatures={r['coin_id']:bytes.fromhex(r['signature'][2:]) for r in store.signatures(identity)}
    result,bls=[],[]
    for row,raw in zip(document['holders'],document['tips'],strict=True):
        v=raw['vault'];tip=SingletonTip(bytes32.from_hexstr(v['launcherId']),_program(v['inner']),
            Coin.from_json_dict(v['coin']),CoinSpend.from_json_dict(v['parentSpend']))
        item=raw['holding'];kind,owner,amount,lock=item['descriptor']
        holding=SGTInput(Coin.from_json_dict(item['coin']),SGTOutput(HoldingKind(kind),bytes32.from_hexstr(owner),amount,
            bytes32.from_hexstr(lock) if lock else None),CoinSpend.from_json_dict(item['parentSpend']))
        signature=_signature(row,signatures[h(holding.coin.name())])
        is_bls=row['context']['owner']['authType']==1
        if is_bls:bls.append(G2Element.from_bytes(signature))
        result.append(CustodyAuthorization(holding,tip,document['expiresAt'],b'' if is_bls else signature))
    return tuple(result),AugSchemeMPL.aggregate(bls)


async def assemble_holder_ballot(identity,*,anchor,provider,store,consents,journal,clock=time.time):
    doc=store.document(identity);request=HolderBallotRequest.model_validate(doc['request'])
    if journal.generation_id!=store.generation_id or anchor.issuance.generation!=bytes32.from_hexstr(store.generation_id):
        raise ValueError('ballot assembly has another deployment generation')
    review={'generationId':store.generation_id,'requestKey':'ballot:'+identity,'kind':request.kind,
        'packageId':identity,'proposalId':request.proposal_id,'selected':request.model_dump(mode='json',by_alias=True)['selected'],
        'selectedWeight':doc['review']['selectedWeight'],'snapshotRoot':doc['review']['snapshotRoot'],
        'eligibleSupply':doc['review']['eligibleSupply'],'requiredVotes':doc['review']['requiredVotes'],
        'votingClosesAt':doc['review']['votingClosesAt'],'feeCapMojos':request.fee_cap_mojos}
    digest=h(sha256(canonical(review).encode()).digest())
    saved=journal.reviewed_request(review['requestKey'],digest)
    if saved:return saved
    if store.status(identity,int(clock()))['stage']!='READY':raise ValueError('all selected holder signatures must be recorded before expiry')
    async with asyncio.timeout(60):
        await ballot_inputs_unchanged(doc,provider);chain=await resolve_generation_chain(anchor,provider=provider)
        gov,reg=chain.governance.state,chain.registry.state;tree,seq=chain.holdings.state
        govtip=chain.governance.verified_tip(reg.governance_id,gov.inner());regtip=chain.registry.verified_tip(reg.launcher_id,reg.inner())
        holdings=CurrentHoldings(gov.sgt,tree,seq,chain.holdings.verified_tip(gov.sgt.ledger_launcher_id,ledger_inner(gov.sgt,tree,seq)))
        auths,aggregate=_saved_authorizations(doc,store,identity)
        if request.kind=='OPEN_PROPOSAL':
            if consents is None or consents.generation_id!=store.generation_id or consents.status(request.consent_package_id,int(clock()))['stage']!='READY':
                raise ValueError('publication consent expired or changed')
            consentdoc=consents.document(request.consent_package_id);await consent_inputs_unchanged(consentdoc,provider)
            consent=restore_consent(consentdoc,anchor.administrator)
            publication=complete_administrator_action(consent,{r['slot']:bytes.fromhex(r['signature'][2:]) for r in consents.signatures(request.consent_package_id)})
            built=open_proposal(gov,govtip,reg,regtip,holdings,_publication_bill(consentdoc),consent.administrator,
                publication.spends,consentdoc['review']['issuedAt'],auths)
        else:
            if not gov.active or h(gov.active.proposal_id)!=request.proposal_id:raise ValueError('the original vote is no longer open')
            snapshot,_=chain.snapshots[gov.active.proposal_id]
            built=cast_vote(gov,govtip,holdings,snapshot,auths)
        operation=built.operation.with_aggregated_signature(aggregate)
        if not await current_evidence_unchanged(chain,provider=provider):raise ValueError('chain changed during ballot assembly')
        await ballot_inputs_unchanged(doc,provider)
        operation_id=journal.prepare(operation,review['requestKey'],request.fee_cap_mojos,int(clock()),
            request_digest=digest,request_document=review)
        return journal.status(operation_id)
