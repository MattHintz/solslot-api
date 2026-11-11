"""Assigned final-genesis actions; no generic bundle or signer endpoint."""
import sqlite3
import time
from typing import Annotated
from fastapi import APIRouter,Depends,HTTPException,Request,Path,Response
from pydantic import Field
from .config import Settings,get_settings
from .launch_control import LaunchSession,require_launch_session
from .generation_preparation_routes import require_recipient_session
from .generation_launch import saved_launch,prepare_launch_review,prepare_launch_operation,recheck_launch_before_dispatch
from .generation_preparation import PreparationModel
from .generation_operations import submit_saved_operation,canonical
from .protocol_submission import ProtocolSubmissionError

router=APIRouter(prefix='/admin/launch/generation/final',tags=['generation-final-launch'])
H=r'^0x[0-9a-f]{64}$'
class LaunchIdentity(PreparationModel):
    generation_id:str=Field(alias='generationId',pattern=H)
    review_id:str=Field(alias='reviewId',pattern=H)
class LaunchSignature(LaunchIdentity):
    signature:str=Field(pattern=r'^0x[0-9a-fA-F]{130}$')
class LaunchSubmission(LaunchIdentity):
    operation_id:str=Field(alias='operationId',pattern=H)
    intent_hash:str=Field(alias='intentHash',pattern=H)
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)


def runtime(request,settings,session,*,write=False):
    store=getattr(request.app.state,'generation_launch',None)
    journal=getattr(request.app.state,'generation_operations',None)
    if store is None or journal is None:
        raise HTTPException(503,detail={'code':'GENERATION_FINAL_RELEASE_NOT_READY',
            'message':'Final launch requires its reviewed release, security and recovery certificate.'})
    if settings.network!='testnet11' or journal.generation_id!=store.preparation.generation_id or settings.deployment_generation_id!=journal.generation_id:
        raise HTTPException(503,detail={'code':'GENERATION_LAUNCH_BINDING_CHANGED'})
    slot=require_recipient_session(session,store.preparation_store)
    submitter=getattr(request.app.state,'protocol_submitter',None)
    if write and (not getattr(settings,'generation_launch_enabled',False) or not settings.generation_execution_enabled
            or submitter is None or not submitter.policy.enabled or not submitter.policy.native_admission_enabled
            or submitter.policy.maximum_mojos!=store.certificate.maximum_fee_mojos):
        raise HTTPException(503,detail={'code':'GENERATION_LAUNCH_NOT_ENABLED',
            'message':'The final launch ActionEnvelope and native fee admission must be enabled by the reviewed deployment.'})
    return store,journal,submitter,slot


def status(store,journal,slot,enabled):
    operation=saved_launch(store,journal)
    review=store.status(operation['review']['reviewId']) if operation else store.latest()
    return {'generationId':store.preparation.generation_id,'network':'testnet11','assignedSlot':slot,
        'enabled':enabled,'review':review,'operation':operation,
        'nextAction':'LAUNCH_CONFIRMED' if review and review['launchComplete'] else
            'WAIT_FOR_CONFIRMATION' if operation and operation['transactionId'] else
            'SUBMIT_SAVED_LAUNCH' if operation else
            'PREPARE_EXACT_LAUNCH' if review and 1 in review['approvedSlots'] and {2,3}&set(review['approvedSlots']) else
            'APPROVE_EXACT_LAUNCH' if review else 'REVIEW_FINAL_LAUNCH',
        'pollAfterSeconds':5 if review and not review['launchComplete'] else 30}


def verify_identity(body,store):
    if body.generation_id!=store.preparation.generation_id:raise ValueError('generation changed')
    store.status(body.review_id)


@router.get('')
def read_status(request:Request,session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,journal,_,slot=runtime(request,settings,session)
    try:return status(store,journal,slot,bool(getattr(settings,'generation_launch_enabled',False)))
    except (ValueError,OSError,sqlite3.Error) as exc:raise HTTPException(503,detail={'code':'GENERATION_LAUNCH_STATUS_UNAVAILABLE',
        'message':'Saved launch progress needs reconciliation. Do not create another generation.'}) from exc


@router.post('/review')
async def review_launch(request:Request,session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,journal,sender,slot=runtime(request,settings,session,write=True)
    if slot!=1:raise HTTPException(403,detail={'code':'OWNER_LAUNCH_REVIEW_REQUIRED'})
    try:
        await prepare_launch_review(store,journal,sender.provider,sender.faucet,clock=time.time)
        return status(store,journal,slot,True)
    except ValueError as exc:raise HTTPException(409,detail={'code':'GENERATION_LAUNCH_GATES_CHANGED',
        'message':'Source, recovery, disk headroom or confirmed destinations need review. No launch was signed.'}) from exc
    except (OSError,RuntimeError,TimeoutError,sqlite3.Error) as exc:raise HTTPException(503,detail={'code':'GENERATION_LAUNCH_REVIEW_UNAVAILABLE',
        'message':'Review could not finish. Check saved progress before retrying.'}) from exc


@router.post('/consent/prepare')
def prepare_consent(body:LaunchIdentity,request:Request,session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,journal,_,slot=runtime(request,settings,session,write=True)
    try:
        verify_identity(body,store);store.require_ready(int(time.time()))
        r=store.status(body.review_id)
        if not r['issuedAt']<=int(time.time())<r['expiresAt']:raise ValueError('review expired')
        return {**status(store,journal,slot,True),'typedData':store.typed_data(body.review_id,slot)}
    except ValueError as exc:raise HTTPException(409,detail={'code':'GENERATION_LAUNCH_CONSENT_CHANGED',
        'message':'The final release or consent window changed. Refresh this exact review.'}) from exc


@router.post('/consent')
def approve_consent(body:LaunchSignature,request:Request,session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,journal,_,slot=runtime(request,settings,session,write=True)
    try:
        verify_identity(body,store);store.require_ready(int(time.time()));store.approve(body.review_id,slot,body.signature,int(time.time()))
        return status(store,journal,slot,True)
    except ValueError as exc:raise HTTPException(409,detail={'code':'GENERATION_LAUNCH_CONSENT_REJECTED',
        'message':'Consent must come from your assigned wallet for this exact release and destinations.'}) from exc


@router.post('/prepare')
async def prepare_launch(body:LaunchIdentity,request:Request,session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,journal,sender,slot=runtime(request,settings,session,write=True)
    if slot!=1:raise HTTPException(403,detail={'code':'OWNER_LAUNCH_PREPARATION_REQUIRED'})
    try:
        verify_identity(body,store)
        await prepare_launch_operation(body.review_id,store,journal,sender.provider,sender.faucet,clock=time.time)
        return status(store,journal,slot,True)
    except ValueError as exc:raise HTTPException(409,detail={'code':'GENERATION_LAUNCH_PREPARATION_CHANGED',
        'message':'The exact consent, inputs or release changed. No replacement launch is authorized.'}) from exc
    except (OSError,RuntimeError,TimeoutError,sqlite3.Error) as exc:raise HTTPException(503,detail={'code':'GENERATION_LAUNCH_PREPARATION_UNCERTAIN',
        'message':'Check saved launch progress. Retained inputs and signatures will be reused.'}) from exc


@router.post('/submit')
async def submit_launch(body:LaunchSubmission,request:Request,session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,journal,sender,slot=runtime(request,settings,session,write=True)
    if slot!=1:raise HTTPException(403,detail={'code':'OWNER_LAUNCH_SUBMISSION_REQUIRED'})
    try:
        verify_identity(body,store);saved=saved_launch(store,journal)
        if (saved is None or saved['review']['reviewId']!=body.review_id or saved['operationId']!=body.operation_id
                or saved['intentHash']!=body.intent_hash or int(saved['feeCapMojos'])!=body.fee_cap_mojos):raise ValueError('saved submission changed')
        # A sent transaction is reconciled exactly even after consent expires;
        # its consensus expiry cannot be extended and no new signature occurs.
        if not saved['transactionId']:
            store.require_ready(int(time.time()));store.require_consent(body.review_id,int(time.time()))
            await recheck_launch_before_dispatch(body.review_id,store,journal,sender.provider,sender.faucet,clock=time.time)
        await submit_saved_operation(journal,saved['operationId'],sender,clock=time.time,selection_purpose='genesis')
        return status(store,journal,slot,True)
    except ValueError as exc:raise HTTPException(409,detail={'code':'GENERATION_LAUNCH_SUBMISSION_CHANGED',
        'message':'This is not the reviewed saved launch. No replacement was sent.'}) from exc
    except ProtocolSubmissionError as exc:
        saved=saved_launch(store,journal)
        code=saved['errorCode'] or 'RECONCILIATION_REQUIRED'
        messages={'FEE_CAP_EXCEEDED':'Network fees exceed this approved ceiling. Wait or review a new fee policy.',
            'CHAIN_WINDOW_EXPIRED':'This signed launch has expired. Its inputs and evidence remain retained for explicit review.',
            'NATIVE_VALIDATION_FAILED':'The saved transaction failed native admission. No replacement is authorized.',
            'INPUT_STATE_CHANGED':'A reserved input changed. Reconcile the exact saved launch before proceeding.'}
        raise HTTPException(503,detail={'code':code,'message':messages.get(code,
            'The exact transaction is retained. Follow automatic confirmation before retrying.'),'operation':saved}) from exc
    except (OSError,RuntimeError,TimeoutError,sqlite3.Error) as exc:raise HTTPException(503,detail={'code':'GENERATION_LAUNCH_SUBMISSION_UNCERTAIN',
        'message':'The exact transaction is retained. Follow automatic confirmation before retrying.'}) from exc


@router.get('/{identity}/read-anchor')
def read_anchor(request:Request,identity:Annotated[str,Path(pattern=H)],
        session:Annotated[LaunchSession,Depends(require_launch_session)],settings:Annotated[Settings,Depends(get_settings)]):
    store,_,_,slot=runtime(request,settings,session)
    if slot!=1:raise HTTPException(403,detail={'code':'OWNER_READ_ANCHOR_REQUIRED'})
    try:
        if not store.status(identity)['launchComplete']:raise ValueError('launch output confirmation is incomplete')
        raw=canonical(store.read_anchor(identity))
        from hashlib import sha256
        return Response(raw,media_type='application/json',headers={'Cache-Control':'private, no-store',
            'Content-Disposition':'attachment; filename="generation-'+store.preparation.generation_id[2:14]+'-read-anchor.json"',
            'X-Content-SHA256':'0x'+sha256(raw.encode()).hexdigest()})
    except (ValueError,OSError,sqlite3.Error) as exc:raise HTTPException(409,detail={'code':'GENERATION_LAUNCH_ANCHOR_UNCONFIRMED',
        'message':'The exact saved launch and read anchor require confirmed output evidence.'}) from exc
