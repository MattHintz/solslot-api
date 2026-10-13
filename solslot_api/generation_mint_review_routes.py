"""Authenticated sealed-edition review; cached GETs have no node/builder calls."""
import sqlite3
import time
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import Field
from .admin_auth import require_admin_jwt
from .config import Settings, get_settings
from .collection_store import get_collection_store, CollectionNotFound, CollectionStoreError
from .generation_mint_reviews import MintReviewRequest, prepare_mint_review
from .generation_storage import GenerationRetentionFull
from .generation_execution import Model, Hash
from .generation_mint_execution import MintExecutionRequest, prepare_mint_execution, mint_request_key
from .generation_operations import submit_saved_operation
from .protocol_submission import ProtocolSubmissionError

router = APIRouter(prefix='/admin/generation/mint-reviews', tags=['generation-mint-reviews'], dependencies=[Depends(require_admin_jwt)])


def _store(request, settings):
    store = getattr(request.app.state, 'generation_mint_reviews', None)
    if store is None or settings.network!='testnet11' or store.generation_id!=settings.deployment_generation_id:
        raise HTTPException(503, detail={'code':'GENERATION_MINT_REVIEW_NOT_READY'})
    return store


def _error(exc):
    if isinstance(exc, GenerationRetentionFull):
        return HTTPException(503, detail={'code':'GENERATION_RETAINED_STATE_FULL',
            'message':'Your saved evidence is retained. Review archive capacity before preparing another batch.'})
    if isinstance(exc, (ValueError, CollectionStoreError)):
        return HTTPException(409, detail={'code':'GENERATION_MINT_SOURCE_CHANGED',
            'message':'The sealed source, mint authority or launcher funding cannot satisfy this review. Keep any saved package; operator reconciliation may be needed.'})
    return HTTPException(503, detail={'code':'GENERATION_MINT_REVIEW_UNAVAILABLE',
        'message':'Review preparation could not finish. Retry this same edition to recover saved progress.'})


@router.post('/prepare')
async def prepare(body:MintReviewRequest, request:Request, settings:Annotated[Settings,Depends(get_settings)]):
    store = _store(request, settings)
    index = getattr(request.app.state,'generation_index',None)
    provider = getattr(request.app.state,'coinset',None)
    faucet = getattr(request.app.state,'faucet',None)
    submitter = getattr(request.app.state,'protocol_submitter',None)
    try:
        if index is None or provider is None or faucet is None or submitter is None:
            # Cached recovery still works while the node/submitter is offline.
            saved = store.reviewed_request(body)
            if saved: return saved
            raise HTTPException(503, detail={'code':'GENERATION_MINT_FUNDING_NOT_READY'})
        return await prepare_mint_review(body, settings=settings, collections=get_collection_store(settings),
            anchor=index.anchor, provider=provider, faucet=faucet, store=store, funding_guard=submitter.funding_guard)
    except CollectionNotFound as exc: raise HTTPException(404, detail={'code':'COLLECTION_NOT_FOUND'}) from exc
    except (ValueError, CollectionStoreError, OSError, TimeoutError, RuntimeError, sqlite3.Error) as exc: raise _error(exc) from exc


@router.get('/collection/{collection_id}')
def collection_review(collection_id:Annotated[str,Path(pattern=r'^[A-Za-z0-9_-]{1,128}$')], request:Request, settings:Annotated[Settings,Depends(get_settings)]):
    try: return {'review':_store(request,settings).for_collection(collection_id)}
    except (ValueError,OSError,sqlite3.Error) as exc: raise _error(exc) from exc


def execution_status(identity,request,settings):
    store=_store(request,settings);source=store.status(identity)
    journal=getattr(request.app.state,'generation_operations',None)
    if journal is None or journal.generation_id!=store.generation_id:raise HTTPException(503,detail={'code':'GENERATION_OPERATIONS_NOT_READY'})
    operation=journal.request_status(mint_request_key(identity))
    if operation is not None:
        raw={k:v for k,v in operation['review'].items() if k not in ('kind','requestKey','collectionId','mintBill','metadataRoot','previewHash','funding')}
        body=MintExecutionRequest.model_validate(raw)
        if (body.source_review_id!=identity or body.generation_id!=store.generation_id or operation['kind']!='MINT_COLLECTION'
                or body.fee_cap_mojos!=int(operation['feeCapMojos']) or body.document(source)!=operation['review']):
            raise ValueError('saved execution differs from the exact mint source')
    inventory=store.inventory_status(identity)
    if inventory['receipt'] and (operation is None or inventory['receipt']['operationId']!=operation['operationId']
            or inventory['receipt']['transactionId']!=operation['transactionId'] or operation['stage']!='CONFIRMED'):
        raise ValueError('inventory confirmation differs from the saved transaction')
    return {'generationId':store.generation_id,'network':'testnet11','sourceReviewId':identity,
        'operation':operation,'inventory':inventory,'pollAfterSeconds':5 if operation and not inventory['receipt'] else 30}


@router.get('/{identity}/execution')
def saved_execution(identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],request:Request,
        settings:Annotated[Settings,Depends(get_settings)]):
    try:return execution_status(identity,request,settings)
    except (ValueError,OSError,sqlite3.Error) as exc:raise _error(exc) from exc


@router.post('/{identity}/execution/prepare')
async def prepare_execution(body:MintExecutionRequest,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],request:Request,
        settings:Annotated[Settings,Depends(get_settings)]):
    store=_store(request,settings);journal=getattr(request.app.state,'generation_operations',None)
    index=getattr(request.app.state,'generation_index',None);provider=getattr(request.app.state,'coinset',None)
    faucet=getattr(request.app.state,'faucet',None);submitter=getattr(request.app.state,'protocol_submitter',None)
    if (not getattr(settings,'generation_execution_enabled',False) or journal is None or index is None
            or provider is None or faucet is None or submitter is None):
        raise HTTPException(503,detail={'code':'GENERATION_MINT_EXECUTION_NOT_READY',
            'message':'Mint execution is not enabled for this generation. Your source and approvals remain saved.'})
    try:
        if body.source_review_id!=identity or submitter.policy.maximum_mojos>body.fee_cap_mojos:
            raise ValueError('mint source or fee ceiling differs from this review')
        await prepare_mint_execution(body,settings=settings,collections=get_collection_store(settings),reviews=store,
            journal=journal,anchor=index.anchor,provider=provider,faucet=faucet,funding_guard=submitter.funding_guard)
        return execution_status(identity,request,settings)
    except (ValueError,CollectionStoreError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _error(exc) from exc


class SubmitMintExecution(Model):
    generation_id:Hash=Field(alias='generationId')
    operation_id:Hash=Field(alias='operationId')
    intent_hash:Hash=Field(alias='intentHash')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)


@router.post('/{identity}/execution/submit')
async def submit_execution(body:SubmitMintExecution,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],request:Request,
        settings:Annotated[Settings,Depends(get_settings)]):
    if not getattr(settings,'generation_execution_enabled',False):raise HTTPException(503,detail={'code':'GENERATION_EXECUTION_NOT_ENABLED'})
    submitter=getattr(request.app.state,'protocol_submitter',None)
    if submitter is None:raise HTTPException(503,detail={'code':'GENERATION_SUBMITTER_UNAVAILABLE'})
    try:
        status=execution_status(identity,request,settings);operation=status['operation']
        if (operation is None or body.generation_id!=status['generationId'] or body.operation_id!=operation['operationId']
                or body.intent_hash!=operation['intentHash'] or body.fee_cap_mojos!=int(operation['feeCapMojos'])):
            raise ValueError('submission differs from the exact saved mint')
        await submit_saved_operation(request.app.state.generation_operations,operation['operationId'],submitter,clock=time.time)
        return execution_status(identity,request,settings)
    except ProtocolSubmissionError as exc:
        saved=execution_status(identity,request,settings)
        raise HTTPException(503,detail={'code':saved['operation']['errorCode'],
            'message':'Check the original saved transaction before retrying. No replacement was authorized.','execution':saved}) from exc
    except (ValueError,CollectionStoreError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _error(exc) from exc
