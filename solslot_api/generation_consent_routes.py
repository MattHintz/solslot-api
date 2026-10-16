"""Assigned generation consent actions; cached reads never invoke a builder."""
import sqlite3
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import Field
from .admin_auth import AdminClaims, require_admin_jwt
from .config import Settings, get_settings
from .generation_consents import ConsentRequest, prepare_consent, sign_consent, prepare_scoped_pause
from .generation_execution import Model
from .generation_storage import GenerationRetentionFull
from .collection_store import get_collection_store, CollectionStoreError

router=APIRouter(prefix='/admin/generation/consents',tags=['generation-consents'],dependencies=[Depends(require_admin_jwt)])


def _services(request,settings,*,write=False):
    store=getattr(request.app.state,'generation_consents',None)
    index=getattr(request.app.state,'generation_index',None)
    provider=getattr(request.app.state,'coinset',None)
    if (store is None or settings.network!='testnet11' or store.generation_id!=settings.deployment_generation_id
            or (write and (index is None or index.anchor.administrator is None or provider is None))):
        raise HTTPException(503,detail={'code':'GENERATION_CONSENT_NOT_READY',
            'message':'The exact generation approval review is not configured yet.'})
    return store,index,provider


def _failure(exc):
    if isinstance(exc,GenerationRetentionFull):
        return HTTPException(503,detail={'code':'GENERATION_RETAINED_STATE_FULL',
            'message':'Saved evidence is retained. An operator must review archive capacity before preparing another action.'})
    if isinstance(exc,(ValueError,CollectionStoreError)):
        return HTTPException(409,detail={'code':'GENERATION_CONSENT_REVIEW_CHANGED',
            'message':'The review, assigned wallet or confirmed inputs changed, or this review expired. Refresh and review again.'})
    return HTTPException(503,detail={'code':'GENERATION_CONSENT_UNAVAILABLE',
        'message':'We could not complete the approval check. Your saved review is retained; retry the same action.'})


@router.get('')
def list_consents(request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    store,_,_=_services(request,settings)
    try:return {'generationId':store.generation_id,'network':'testnet11','reviews':store.recent(int(time.time()))}
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.post('/prepare')
async def prepare_review(body:ConsentRequest,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    store,index,provider=_services(request,settings,write=True)
    source={'settings':settings}
    try:
        if body.proposal_kind=='MINT_TEST_ONLY':
            source={'settings':settings,'collections':get_collection_store(settings),
                'mint_reviews':getattr(request.app.state,'generation_mint_reviews',None)}
        return await prepare_consent(body,anchor=index.anchor,provider=provider,store=store,**source)
    except (ValueError,CollectionStoreError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


class ConsentSignature(Model):
    signature:str=Field(pattern=r'^0x[0-9a-fA-F]{128}([0-9a-fA-F]{2})?$')


@router.post('/{identity}/sign')
async def sign_review(body:ConsentSignature,request:Request,
        identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        claims:Annotated[AdminClaims,Depends(require_admin_jwt)],settings:Annotated[Settings,Depends(get_settings)]):
    store,index,provider=_services(request,settings,write=True)
    try:
        document=store.document(identity)
        challenge=next((c for c in document['challenges'] if c['slot']==claims.authority_slot),None)
        if (claims.generation_id!=store.generation_id or claims.auth_type!='evm' or challenge is None
                or claims.compressed_pubkey!=challenge['publicKey']):
            raise ValueError('session is not the exact assigned current administrator wallet')
        return await sign_consent(identity,claims.authority_slot,bytes.fromhex(body.signature[2:]),
            anchor=index.anchor,provider=provider,store=store)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.post('/{identity}/prepare-pause')
async def prepare_pause(request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        settings:Annotated[Settings,Depends(get_settings)]):
    store,index,provider=_services(request,settings,write=True)
    journal=getattr(request.app.state,'generation_operations',None)
    if journal is None or journal.generation_id!=store.generation_id:
        raise HTTPException(503,detail={'code':'GENERATION_OPERATIONS_NOT_READY'})
    try:return await prepare_scoped_pause(identity,anchor=index.anchor,provider=provider,store=store,journal=journal)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc


@router.get('/{identity}')
def review_status(request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
        settings:Annotated[Settings,Depends(get_settings)]):
    store,_,_=_services(request,settings)
    try:return store.status(identity,int(time.time()))
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc
