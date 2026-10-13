"""Explicit prepare/submit actions, with strictly cached and side-effect-free GETs."""
import sqlite3
import time
from typing import Annotated
from fastapi import APIRouter,Depends,HTTPException,Path,Request
from .admin_auth import require_admin_jwt
from .config import Settings,get_settings
from .generation_execution import Hash,Model,MaintenanceRequest,prepare_maintenance
from .generation_operations import submit_saved_operation
from .protocol_submission import ProtocolSubmissionError
from .generation_storage import GenerationRetentionFull
from pydantic import Field

router=APIRouter(prefix='/admin/generation/operations',tags=['generation-operations'],dependencies=[Depends(require_admin_jwt)])


def _journal(request,settings):
    journal=getattr(request.app.state,'generation_operations',None)
    if journal is not None and (settings.network!='testnet11' or journal.generation_id!=settings.deployment_generation_id):
        raise HTTPException(503,detail={'code':'GENERATION_OPERATION_BINDING_CHANGED',
            'message':'The saved operation history does not match this deployment.'})
    return journal


@router.get('')
def list_operations(request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    journal=_journal(request,settings)
    try:operations=journal.recent() if journal is not None else []
    except (OSError,ValueError,sqlite3.Error) as exc:
        raise HTTPException(503,detail={'code':'GENERATION_OPERATION_STORE_UNAVAILABLE',
            'message':'Saved progress is temporarily unavailable. Wait for the next check; do not repeat the transaction.'}) from exc
    return {'generationId':settings.deployment_generation_id,'network':settings.network,
        'available':journal is not None,'operations':operations,
        'executionEnabled':bool(getattr(settings,'generation_execution_enabled',False)),
        'maximumFeeMojos':str(getattr(getattr(getattr(request.app.state,'protocol_submitter',None),'policy',None),'maximum_mojos',0)),
        'pollAfterSeconds':5 if any(o['transactionId'] and o['stage']!='CONFIRMED' for o in operations) else 30}


@router.post('/prepare')
async def prepare_operation(body:MaintenanceRequest,request:Request,
                            settings:Annotated[Settings,Depends(get_settings)]):
    journal=_journal(request,settings)
    index=getattr(request.app.state,'generation_index',None)
    provider=getattr(request.app.state,'coinset',None)
    if journal is None or index is None or provider is None:
        raise HTTPException(503,detail={'code':'GENERATION_OPERATIONS_NOT_READY'})
    try:
        return await prepare_maintenance(body,anchor=index.anchor,provider=provider,journal=journal)
    except GenerationRetentionFull as exc:
        raise HTTPException(503,detail={'code':'GENERATION_RETAINED_STATE_FULL',
            'message':'Saved evidence is retained. Review archive capacity before preparing another action.'}) from exc
    except ValueError as exc:
        raise HTTPException(409,detail={'code':'GENERATION_REVIEW_CHANGED',
            'message':'The action is not available for these confirmed inputs. Refresh the chain state and review again.'}) from exc
    except (OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:
        raise HTTPException(503,detail={'code':'GENERATION_PREPARATION_UNAVAILABLE',
            'message':'We could not finish preparing this action. Retry this review to recover any saved progress.'}) from exc


class SubmitOperation(Model):
    generation_id:Hash=Field(alias='generationId')
    intent_hash:Hash=Field(alias='intentHash')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)


@router.post('/{identity}/submit')
async def submit_operation(body:SubmitOperation,request:Request,
                           identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
                           settings:Annotated[Settings,Depends(get_settings)]):
    journal=_journal(request,settings)
    if (journal is None or settings.network!='testnet11'
            or not getattr(settings,'generation_execution_enabled',False)):
        raise HTTPException(503,detail={'code':'GENERATION_EXECUTION_NOT_ENABLED',
            'message':'This generation is not enabled for chain submission.'})
    submitter=getattr(request.app.state,'protocol_submitter',None)
    if submitter is None:raise HTTPException(503,detail={'code':'GENERATION_SUBMITTER_UNAVAILABLE'})
    try:
        saved=journal.status(identity)
        if saved['kind'] in ('CREATE_RECIPIENT_VAULT','MINT_COLLECTION','INITIALIZE_GENERATION','PRIMARY_SOLS_BATCH'):
            raise ValueError('recipient/mint execution requires its exact source-scoped action')
        if (body.generation_id!=journal.generation_id or body.intent_hash!=saved['intentHash']
                or body.fee_cap_mojos!=int(saved['feeCapMojos'])):
            raise ValueError('submission differs from the reviewed saved action')
        return await submit_saved_operation(journal,identity,submitter,clock=time.time)
    except ValueError as exc:
        raise HTTPException(409,detail={'code':'GENERATION_SUBMISSION_REVIEW_CHANGED',
            'message':'The saved action or fee policy differs from this review. No replacement was authorized.'}) from exc
    except ProtocolSubmissionError as exc:
        saved=journal.status(identity)
        raise HTTPException(503,detail={'code':saved['errorCode'],
            'message':'The saved action needs reconciliation. Check its status before retrying.',
            'operation':saved}) from exc
    except (OSError,TimeoutError,sqlite3.Error) as exc:
        raise HTTPException(503,detail={'code':'GENERATION_SUBMISSION_UNAVAILABLE',
            'message':'Submission status is uncertain. Keep the saved operation and check confirmation; do not start another action.'}) from exc


@router.get('/{identity}')
def operation_status(request:Request,identity:Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')],
                     settings:Annotated[Settings,Depends(get_settings)]):
    journal=_journal(request,settings)
    if journal is None:raise HTTPException(503,detail={'code':'GENERATION_OPERATIONS_NOT_READY'})
    try:return journal.status(identity)
    except ValueError as exc:raise HTTPException(404,detail={'code':'GENERATION_OPERATION_NOT_FOUND'}) from exc
    except (OSError,sqlite3.Error) as exc:
        raise HTTPException(503,detail={'code':'GENERATION_OPERATION_STORE_UNAVAILABLE'}) from exc
