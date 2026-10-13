"""Native holder ballots for the frozen rehearsal roster.

Preparation, assigned wallet signatures and assembly are explicit actions.
GET only reads saved packages or the already verified holdings projection.
This route does not enroll arbitrary vaults or grant dispatch permission.
"""
import sqlite3
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import Field
from solslot_puzzles.holdings import HoldingKind
from .admin_auth import AdminClaims, require_admin_jwt
from .config import Settings, get_settings
from .generation_execution import Hash, Model
from .generation_holder_ballots import HolderBallotRequest, prepare_holder_ballot, sign_holder_ballot, assemble_holder_ballot, h
from .generation_holder_evidence import preparation_custody_anchors
from .generation_storage import GenerationRetentionFull

router=APIRouter(prefix='/admin/generation/ballots',tags=['generation-ballots'],dependencies=[Depends(require_admin_jwt)])


def _services(request,settings,*,write=False):
    store=getattr(request.app.state,'generation_ballots',None)
    index=getattr(request.app.state,'generation_index',None)
    provider=getattr(request.app.state,'coinset',None)
    preparation=getattr(request.app.state,'generation_preparation',None)
    if (store is None or settings.network!='testnet11' or store.generation_id!=settings.deployment_generation_id
            or (write and (index is None or preparation is None or provider is None))):
        raise HTTPException(503,detail={'code':'GENERATION_BALLOT_NOT_READY',
            'message':'The frozen recipient roster and holder ballot review are not configured yet.'})
    return store,index,provider,preparation


def _failure(exc):
    if isinstance(exc,GenerationRetentionFull):
        return HTTPException(503,detail={'code':'GENERATION_RETAINED_STATE_FULL',
            'message':'Saved evidence is retained. An operator must review archive capacity before preparing another action.'})
    if isinstance(exc,ValueError):
        return HTTPException(409,detail={'code':'GENERATION_BALLOT_REVIEW_CHANGED',
            'message':'The selected holdings, assigned wallet, proposal or signing window changed. Refresh and review again.'})
    return HTTPException(503,detail={'code':'GENERATION_BALLOT_UNAVAILABLE',
        'message':'The holder check could not finish. Keep the saved review and retry this same action.'})


def cached_holder_selection(index,preparation,now):
    status=index.store.status(now,verified_in_process=index.verified)
    chain=index.evidence
    if status['status']!='READY' or chain is None:
        raise ValueError('holdings projection needs fresh confirmed evidence')
    p=preparation.preparation
    from chia_rs.sized_bytes import bytes32
    if (p.generation_id!=status['generationId']
            or bytes32.from_hexstr(p.manifest_hash)!=index.anchor.issuance.preparation_manifest_hash):
        raise ValueError('recipient catalog differs from the frozen issuance')
    tree,_=chain.holdings.state;gov=chain.governance.state
    snapshot=chain.snapshots[gov.active.proposal_id][0] if gov.active else tree
    names={row.custody.launcher_id:row.name for row in p.administrators}
    anchors={c.owner:c for c in preparation_custody_anchors(p)}
    rows=[]
    for identity,holding in sorted(tree.holdings.items()):
        custody=anchors.get(holding.owner_hash)
        if custody is None or snapshot.holdings.get(identity)!=holding or holding.kind not in (HoldingKind.HOLDER,HoldingKind.LOCKED_HOLDER):continue
        if holding.kind==HoldingKind.LOCKED_HOLDER and holding.lock_id not in gov.closed.keys:continue
        rows.append({'coinId':h(identity),'vaultLauncherId':h(custody.launcher_id),'name':names[h(custody.launcher_id)],
            'ownerPuzzleHash':h(holding.owner_hash),'amount':holding.amount})
    return {'generationId':status['generationId'],'network':'testnet11','checkedAt':status['lastCheckedAt'],
        'expectedInputs':{k:status['snapshot']['chainEvidence'][k]['coinId'] for k in ('registry','governance','holdings')},
        'proposalId':h(gov.active.proposal_id) if gov.active else None,
        'snapshotRoot':h(snapshot.root.hash),'eligibleSupply':snapshot.root.eligible,
        'votingClosesAt':gov.active.voting_closes_at if gov.active else None,
        'holdings':rows[:96],'truncated':len(rows)>96,'scope':'FROZEN_GENESIS_ROSTER'}


@router.get('/holdings')
def holdings(request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    _,index,_,preparation=_services(request,settings)
    if index is None or preparation is None:raise HTTPException(503,detail={'code':'GENERATION_HOLDINGS_NOT_READY'})
    try:return cached_holder_selection(index,preparation,int(time.time()))
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.get('')
def list_ballots(request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    store,_,_,_=_services(request,settings)
    try:return {'generationId':store.generation_id,'network':'testnet11',
        'reviews':[{k:v for k,v in r.items() if k!='holders'} for r in store.recent(int(time.time()))]}
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.post('/prepare')
async def prepare(body:HolderBallotRequest,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    store,index,provider,preparation=_services(request,settings,write=True)
    try:return await prepare_holder_ballot(body,anchor=index.anchor,custodies=preparation_custody_anchors(preparation.preparation),
        provider=provider,store=store,consents=getattr(request.app.state,'generation_consents',None))
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


class HolderSignature(Model):
    coin_id:Hash=Field(alias='coinId')
    signature:str=Field(pattern=r'^0x([0-9a-fA-F]{128}|[0-9a-fA-F]{130}|[0-9a-fA-F]{192})$')


@router.post('/{identity}/sign')
async def sign(body:HolderSignature,request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        claims:Annotated[AdminClaims,Depends(require_admin_jwt)],settings:Annotated[Settings,Depends(get_settings)]):
    store,_,provider,_=_services(request,settings,write=True)
    try:
        row=next((r for r in store.document(identity)['holders'] if r['request']['sgtCoinId']==body.coin_id),None)
        if (row is None or claims.generation_id!=store.generation_id or claims.compressed_pubkey!=row['context']['owner']['publicKey']
                or claims.auth_type!=('evm' if row['context']['owner']['authType']==3 else 'chia_bls')):
            raise ValueError('session is not the selected holder wallet')
        return await sign_holder_ballot(identity,body.coin_id,bytes.fromhex(body.signature[2:]),provider=provider,store=store)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.post('/{identity}/check-inputs')
async def check_inputs(request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        settings:Annotated[Settings,Depends(get_settings)]):
    # Called only around an explicit wallet action. Never part of a status poll.
    from .generation_holder_ballots import ballot_inputs_unchanged
    import asyncio
    store,_,provider,_=_services(request,settings,write=True)
    try:
        if store.status(identity,int(time.time()))['stage']=='EXPIRED':raise ValueError('signing deadline ended')
        async with asyncio.timeout(20):await ballot_inputs_unchanged(store.document(identity),provider)
        return {'generationId':store.generation_id,'packageId':identity,'unchanged':True}
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.post('/{identity}/assemble')
async def assemble(request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        settings:Annotated[Settings,Depends(get_settings)]):
    store,index,provider,_=_services(request,settings,write=True)
    journal=getattr(request.app.state,'generation_operations',None)
    if journal is None or journal.generation_id!=store.generation_id:raise HTTPException(503,detail={'code':'GENERATION_OPERATIONS_NOT_READY'})
    try:return await assemble_holder_ballot(identity,anchor=index.anchor,provider=provider,store=store,
        consents=getattr(request.app.state,'generation_consents',None),journal=journal)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.get('/{identity}')
def ballot_status(request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        settings:Annotated[Settings,Depends(get_settings)]):
    store,_,_,_=_services(request,settings)
    try:return store.status(identity,int(time.time()))
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc
