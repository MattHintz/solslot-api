"""Authenticated native setup for frozen SGT recipient evidence and consent.

Creation preparation and submission are separate explicit scoped actions.
Polling returns durable cached evidence only; it never constructs or signs.
"""
from __future__ import annotations

import time
import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings, get_settings
from .generation_preparation import GenerationPreparation
from .generation_preparation_store import GenerationPreparationStore
from .generation_recipient_evidence import verify_single_recipient
from .generation_recipient_execution import RecipientLaunchRequest, Hash, prepare_recipient_launch, recipient_operation
from .generation_operations import submit_saved_operation
from .protocol_submission import ProtocolSubmissionError
from .launch_control import LaunchSession, require_launch_session

router=APIRouter(prefix='/admin/launch/generation',tags=['generation-preparation'])


class RecipientAcknowledgement(BaseModel):
    model_config=ConfigDict(extra='forbid')
    preparation_manifest: str=Field(alias='preparationManifest',pattern=r'^0x[0-9a-f]{64}$')
    signature: str=Field(pattern=r'^0x[0-9a-fA-F]{130}$')


def preparation_store(settings: Annotated[Settings,Depends(get_settings)]) -> GenerationPreparationStore:
    if (settings.network!='testnet11' or not settings.deployment_generation_id
            or not settings.generation_preparation_path or not settings.generation_preparation_hash):
        raise HTTPException(503,detail={'code':'GENERATION_PREPARATION_NOT_READY',
            'message':'The reviewed preparation manifest is not installed.'})
    try:
        path=Path(settings.generation_preparation_path)
        # Bound the read itself, including a concurrently replaced file.
        with path.open('rb') as stream: raw=stream.read(131073)
        if len(raw)>131072:raise ValueError('manifest size limit')
        preparation=GenerationPreparation.model_validate_json(raw)
        if (preparation.generation_id!=settings.deployment_generation_id
                or preparation.manifest_hash!=settings.generation_preparation_hash):
            raise ValueError('reviewed preparation commitment differs')
        return GenerationPreparationStore(settings.generation_preparation_db_path,preparation)
    except (OSError,ValueError) as exc:
        raise HTTPException(503,detail={'code':'GENERATION_PREPARATION_NOT_READY',
            'message':'The installed preparation needs operator review.'}) from exc


def require_recipient_session(session: LaunchSession, store: GenerationPreparationStore) -> int:
    p=store.preparation
    if (session.setup or session.slot not in (1,2,3) or not session.wallet
            or session.generation_id!=p.generation_id
            or session.wallet.lower()!=p.administrators[session.slot-1].wallet):
        raise HTTPException(403,detail={'code':'RECIPIENT_SESSION_MISMATCH',
            'message':'Sign in with your enrolled administrator wallet for this generation.'})
    return session.slot


def recipient_review(request, store, slot, settings):
    journal = getattr(request.app.state, 'generation_operations', None)
    if journal is not None and (settings.network != 'testnet11'
            or journal.generation_id != store.preparation.generation_id
            or journal.generation_id != settings.deployment_generation_id):
        raise HTTPException(503, detail={'code':'GENERATION_OPERATION_BINDING_CHANGED',
            'message':'Saved launch progress does not match the reviewed generation.'})
    submitter = getattr(request.app.state, 'protocol_submitter', None)
    ready = bool(journal and submitter and settings.generation_execution_enabled
        and submitter.policy.enabled and submitter.policy.native_admission_enabled)
    try:
        review = store.review(int(time.time()))
        for recipient in review['recipients']:
            recipient['creation'] = recipient_operation(store.preparation, recipient['administratorSlot'], journal)
    except (OSError, ValueError, sqlite3.Error) as exc:
        raise HTTPException(503, detail={'code':'RECIPIENT_PROGRESS_UNAVAILABLE',
            'message':'Saved progress is temporarily unavailable. Do not create another vault.'}) from exc
    return {**review, 'assignedSlot':slot, 'creationAvailable':ready,
        'maximumFeeMojos':str(submitter.policy.maximum_mojos) if ready else '0'}


def recipient_runtime(request, store, settings):
    journal = getattr(request.app.state, 'generation_operations', None)
    submitter = getattr(request.app.state, 'protocol_submitter', None)
    if (settings.network != 'testnet11' or not settings.generation_execution_enabled
            or journal is None or submitter is None or not submitter.policy.enabled
            or not submitter.policy.native_admission_enabled
            or settings.deployment_generation_id != store.preparation.generation_id
            or journal.generation_id != store.preparation.generation_id):
        raise HTTPException(503, detail={'code':'RECIPIENT_CREATION_NOT_ENABLED',
            'message':'Recipient creation needs the reviewed deployment and native admission gates.'})
    return journal, submitter


@router.get('/recipients')
def recipient_status(request: Request, session: Annotated[LaunchSession,Depends(require_launch_session)],
                     store: Annotated[GenerationPreparationStore,Depends(preparation_store)],
                     settings: Annotated[Settings,Depends(get_settings)]):
    slot=require_recipient_session(session,store)
    return recipient_review(request, store, slot, settings)


@router.post('/recipients/creation/prepare')
async def prepare_creation(body: RecipientLaunchRequest, request: Request,
        session: Annotated[LaunchSession,Depends(require_launch_session)],
        store: Annotated[GenerationPreparationStore,Depends(preparation_store)],
        settings: Annotated[Settings,Depends(get_settings)]):
    slot = require_recipient_session(session, store)
    if body.administrator_slot != slot:
        raise HTTPException(403, detail={'code':'RECIPIENT_SESSION_MISMATCH'})
    journal, submitter = recipient_runtime(request, store, settings)
    if body.fee_cap_mojos != submitter.policy.maximum_mojos:
        raise HTTPException(409, detail={'code':'RECIPIENT_FEE_REVIEW_CHANGED',
            'message':'The fee ceiling changed. Review the current limit; no replacement is authorized.'})
    try:
        await prepare_recipient_launch(body, preparation=store.preparation, provider=submitter.provider,
            faucet=submitter.faucet, journal=journal)
        return recipient_review(request, store, slot, settings)
    except ValueError as exc:
        raise HTTPException(409, detail={'code':'RECIPIENT_REVIEW_CHANGED',
            'message':'The reserved parent or destination differs from this review. Refresh and review again.'}) from exc
    except (OSError, TimeoutError, RuntimeError, sqlite3.Error) as exc:
        raise HTTPException(503, detail={'code':'RECIPIENT_PREPARATION_UNAVAILABLE',
            'message':'Preparation could not finish. Refresh saved progress before retrying this same review.'}) from exc


class SubmitRecipientCreation(BaseModel):
    model_config = ConfigDict(extra='forbid', populate_by_name=True)
    generation_id: Hash = Field(alias='generationId')
    preparation_manifest: Hash = Field(alias='preparationManifest')
    operation_id: Hash = Field(alias='operationId')
    intent_hash: Hash = Field(alias='intentHash')
    fee_cap_mojos: int = Field(alias='feeCapMojos', strict=True, ge=0, le=1_000_000_000)


@router.post('/recipients/creation/submit')
async def submit_creation(body: SubmitRecipientCreation, request: Request,
        session: Annotated[LaunchSession,Depends(require_launch_session)],
        store: Annotated[GenerationPreparationStore,Depends(preparation_store)],
        settings: Annotated[Settings,Depends(get_settings)]):
    slot = require_recipient_session(session, store)
    journal, submitter = recipient_runtime(request, store, settings)
    try:
        saved = recipient_operation(store.preparation, slot, journal)
        if (saved is None or body.generation_id != store.preparation.generation_id
                or body.preparation_manifest != store.preparation.manifest_hash
                or body.operation_id != saved['operationId'] or body.intent_hash != saved['intentHash']
                or body.fee_cap_mojos != int(saved['feeCapMojos'])):
            raise ValueError('submission differs from the assigned saved recipient review')
        await submit_saved_operation(journal, saved['operationId'], submitter, clock=time.time, selection_purpose='genesis')
        return recipient_review(request, store, slot, settings)
    except ValueError as exc:
        raise HTTPException(409, detail={'code':'RECIPIENT_SUBMISSION_REVIEW_CHANGED',
            'message':'This is not your exact saved launch. No replacement was sent.'}) from exc
    except (ProtocolSubmissionError, OSError, TimeoutError, sqlite3.Error) as exc:
        raise HTTPException(503, detail={'code':'RECIPIENT_SUBMISSION_UNCERTAIN',
            'message':'Check the saved launch status before retrying. Its exact transaction and destination are retained.'}) from exc


@router.post('/recipients/check')
async def check_recipient(request: Request,
                          session: Annotated[LaunchSession,Depends(require_launch_session)],
                          store: Annotated[GenerationPreparationStore,Depends(preparation_store)],
                          settings: Annotated[Settings,Depends(get_settings)]):
    slot=require_recipient_session(session,store)
    provider=getattr(request.app.state,'coinset',None)
    if provider is None:
        raise HTTPException(503,detail={'code':'NODE_UNAVAILABLE','message':'The confirmation service is unavailable. Try checking again.'})
    now=int(time.time())
    try:
        receipt=await verify_single_recipient(store.preparation,slot,
            trusted_preparation_hash=store.preparation.manifest_hash,provider=provider)
        store.record_confirmation(receipt,int(time.time()))
    except (ValueError,KeyError,TypeError):
        store.record_error(slot,'RECIPIENT_NOT_CONFIRMED',now)
    except (OSError,TimeoutError,RuntimeError):
        store.record_error(slot,'NODE_UNAVAILABLE',now)
    return recipient_review(request, store, slot, settings)


@router.post('/recipients/acknowledgement/prepare')
def prepare_acknowledgement(session: Annotated[LaunchSession,Depends(require_launch_session)],
                             store: Annotated[GenerationPreparationStore,Depends(preparation_store)]):
    slot=require_recipient_session(session,store)
    review=store.review(int(time.time()))
    recipient=review['recipients'][slot-1]
    if not recipient['confirmationFresh']:
        raise HTTPException(409,detail={'code':'RECIPIENT_CHECK_REQUIRED',
            'message':'Check your recipient vault confirmation before signing.'})
    return {'generationId':store.preparation.generation_id,'preparationManifest':store.preparation.manifest_hash,
        'recipient':recipient,'typedData':store.preparation.acknowledgement(slot)}


@router.post('/recipients/acknowledgement')
def acknowledge_recipient(body: RecipientAcknowledgement, request: Request,
                           session: Annotated[LaunchSession,Depends(require_launch_session)],
                           store: Annotated[GenerationPreparationStore,Depends(preparation_store)],
                           settings: Annotated[Settings,Depends(get_settings)]):
    slot=require_recipient_session(session,store)
    if body.preparation_manifest!=store.preparation.manifest_hash:
        raise HTTPException(409,detail={'code':'PREPARATION_CHANGED','message':'The preparation changed. Review your destination again.'})
    try:store.acknowledge(slot,body.signature,int(time.time()))
    except ValueError as exc:
        raise HTTPException(409,detail={'code':'RECIPIENT_ACKNOWLEDGEMENT_REJECTED',
            'message':'Confirmation or wallet consent is no longer valid. Check your vault and review again.'}) from exc
    return recipient_review(request, store, slot, settings)
