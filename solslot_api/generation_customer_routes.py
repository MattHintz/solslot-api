"""Native current-generation registration, without administrator enrollment."""
from __future__ import annotations
import hashlib,re,secrets,sqlite3
from typing import Annotated,Literal
from fastapi import APIRouter,Depends,HTTPException,Path,Request,Response
from pydantic import BaseModel,ConfigDict,Field
from .config import Settings,get_settings
from .credential_auth import VAULT_SESSION_COOKIE,issue_vault_session,OwnerAuth
from .generation_customer_runtime import GenerationCustomerRuntime,normalized_owner
from .generation_customer_store import CustomerRegistrationConflict
from .generation_storage import GenerationRetentionFull
from .protocol_submission import ProtocolSubmissionError

router=APIRouter(prefix='/customer/registration',tags=['current-customer-registration'])
Hash=Annotated[str,Field(pattern=r'^0x[0-9a-f]{64}$')]
Identity=Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')]
class CurrentGeneration(BaseModel):
    model_config=ConfigDict(extra='forbid',populate_by_name=True)
    generation_id:Hash=Field(alias='generationId')
class ReviewRequest(CurrentGeneration):
    owner:str=Field(min_length=2,max_length=98)
    auth_type:Literal['evm','chia_bls']=Field(alias='authType')
class SignatureRequest(CurrentGeneration):
    signature:str=Field(pattern=r'^0x(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{130}|[0-9a-fA-F]{192})$')

def _runtime(request,settings):
    runtime=getattr(request.app.state,'generation_customers',None)
    if (not isinstance(runtime,GenerationCustomerRuntime) or settings.network!='testnet11'
            or runtime.store.generation_id!=settings.deployment_generation_id):
        raise HTTPException(503,detail={'code':'CURRENT_CUSTOMER_REGISTRATION_UNAVAILABLE',
            'message':'Current Testnet vault registration is not available yet. You can keep browsing.'})
    return runtime
def _origin(request,settings):
    # Browser mutations need an exact origin even when a proxy changes the
    # transport scheme. Neither Host nor an untrusted forwarded header chooses it.
    expected=getattr(settings,'generation_customer_public_origin','https://solslot.com')
    if request.headers.get('origin')!=expected or request.headers.get('sec-fetch-site')=='cross-site':
        raise HTTPException(403,detail={'code':'CURRENT_CUSTOMER_ORIGIN_REJECTED'})
def _cookie_name(settings):
    return 'solslot_customer_browser_'+str(settings.deployment_generation_id)[2:18]
def _browser_hash(request,settings,*,new=False):
    token=request.cookies.get(_cookie_name(settings))
    if not isinstance(token,str) or re.fullmatch(r'[0-9a-f]{64}',token) is None:
        if not new:raise HTTPException(401,detail={'code':'CUSTOMER_CONTINUATION_REQUIRED',
            'message':'Use the browser where this vault request started, or reconnect your wallet.'})
        token=secrets.token_hex(32)
    digest=hashlib.sha256((str(settings.deployment_generation_id)+':'+token).encode()).hexdigest()
    return token,digest
def _failure(exc):
    if isinstance(exc,GenerationRetentionFull):
        return HTTPException(503,detail={'code':'CUSTOMER_SAVED_STATE_CAPACITY',
            'message':'Saved progress is preserved. New registrations are paused while capacity is reviewed.'})
    if isinstance(exc,CustomerRegistrationConflict):
        return HTTPException(409,detail={'code':'CUSTOMER_REGISTRATION_CONTINUATION_REQUIRED',
            'message':'Resume the saved request in its original browser, or sign in to your current vault.'})
    if isinstance(exc,ValueError):
        return HTTPException(409,detail={'code':'CUSTOMER_REGISTRATION_REVIEW_CHANGED',
            'message':'The request or current network state changed. Keep your saved progress and reconnect.'})
    return HTTPException(503,detail={'code':'CUSTOMER_REGISTRATION_TEMPORARILY_UNAVAILABLE',
        'message':'We could not complete this step. Your saved authorization is preserved; check progress before retrying.'})

@router.get('/profile')
async def profile(request:Request,response:Response,settings:Annotated[Settings,Depends(get_settings)]):
    response.headers['Cache-Control']='no-store'
    runtime=getattr(request.app.state,'generation_customers',None)
    if runtime is None:
        return {'schema':'solslot.current-customer-profile.v1','generationId':settings.deployment_generation_id,
            'network':settings.network,'status':'DISABLED','registrationEnabled':False,'earlierVaultsAdmitted':False,
            'requiresFreshIdCheck':True,'pollAfterSeconds':30,'nextAction':'REGISTRATION_NOT_ENABLED'}
    return _runtime(request,settings).profile()

@router.get('/lookup')
async def lookup(request:Request,response:Response,owner:str,authType:Literal['evm','chia_bls'],
        settings:Annotated[Settings,Depends(get_settings)]):
    response.headers['Cache-Control']='no-store'
    try:
        runtime=_runtime(request,settings);canonical=normalized_owner(owner,authType)
        result=runtime.store.confirmed_owner(canonical,authType)
        return {'generationId':runtime.store.generation_id,'network':'testnet11','vault':result}
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc

@router.post('/reviews')
async def review(body:ReviewRequest,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _origin(request,settings);token,browser=_browser_hash(request,settings,new=True)
    try:
        result=await _runtime(request,settings).prepare_review(body.owner,body.auth_type,body.generation_id,browser)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc
    response.set_cookie(_cookie_name(settings),token,max_age=86400,path='/protocol-api/next/customer',
        secure=True,httponly=True,samesite='strict')
    response.headers['Cache-Control']='no-store'
    return result

@router.get('/reviews/{identity}')
async def progress(identity:Identity,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _,browser=_browser_hash(request,settings)
    response.headers['Cache-Control']='no-store'
    try:return _runtime(request,settings).status(identity,browser)
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc

@router.post('/reviews/{identity}/authorize')
async def authorize(identity:Identity,body:SignatureRequest,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _origin(request,settings);_,browser=_browser_hash(request,settings)
    response.headers['Cache-Control']='no-store'
    try:return await _runtime(request,settings).authorize(identity,body.signature,browser,body.generation_id)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc

@router.post('/reviews/{identity}/submit')
async def submit(identity:Identity,body:CurrentGeneration,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _origin(request,settings);_,browser=_browser_hash(request,settings)
    response.headers['Cache-Control']='no-store'
    try:return await _runtime(request,settings).submit(identity,browser,body.generation_id)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc

@router.post('/reviews/{identity}/prepare')
async def resume_preparation(identity:Identity,body:CurrentGeneration,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _origin(request,settings);_,browser=_browser_hash(request,settings)
    response.headers['Cache-Control']='no-store'
    try:return await _runtime(request,settings).prepare_authorized(identity,browser,body.generation_id)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc

@router.post('/reviews/{identity}/connect')
async def connect(identity:Identity,body:CurrentGeneration,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _origin(request,settings);_,browser=_browser_hash(request,settings)
    if body.generation_id!=settings.deployment_generation_id:raise HTTPException(409,detail={'code':'CUSTOMER_GENERATION_CHANGED'})
    try:
        runtime=_runtime(request,settings)
        owner=await runtime.verified_registration_owner(identity,browser)
        await runtime.observe_current_vault(identity)
        token,session=issue_vault_session(settings,owner)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc
    response.set_cookie(VAULT_SESSION_COOKIE,token,max_age=settings.vault_session_ttl_seconds,
        path=settings.vault_session_cookie_path,secure=True,httponly=True,samesite='strict')
    response.headers['Cache-Control']='no-store'
    return session


session_router=APIRouter(prefix='/customer/session',tags=['current-customer-session'])

class SessionSignature(CurrentGeneration):
    ownerAuth:OwnerAuth


@session_router.get('/{launcher}')
async def current_session(launcher:Identity,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    from .credential_auth import verify_vault_session
    response.headers['Cache-Control']='no-store'
    runtime=_runtime(request,settings)
    owner=verify_vault_session(settings,request,launcher)
    try:
        snapshot=runtime.current_vault_snapshot(launcher)
        if (snapshot['authType']!=owner.auth_type or
                snapshot['owner'].lower()!=owner.owner_key.lower()):
            raise ValueError('CURRENT_CUSTOMER_SESSION_OWNER_CHANGED')
        return {**snapshot,'sessionExpiresAt':owner.expires_at}
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc


@session_router.post('/{launcher}/challenge')
async def current_session_challenge(launcher:Identity,body:CurrentGeneration,request:Request,
        response:Response,settings:Annotated[Settings,Depends(get_settings)]):
    from .credential_auth import issue_owner_challenge,OwnerChallengeRequest,vault_session_payload
    _origin(request,settings);response.headers['Cache-Control']='no-store'
    runtime=_runtime(request,settings)
    if body.generation_id!=runtime.store.generation_id:
        raise HTTPException(409,detail={'code':'CUSTOMER_GENERATION_CHANGED'})
    try:
        runtime.current_vault_snapshot(launcher)
        return issue_owner_challenge(settings,vault_launcher_id=launcher,
            request=OwnerChallengeRequest(action='session_login',payload=vault_session_payload(settings)),
            current_customer_session=True)
    except (ValueError,OSError,sqlite3.Error) as exc:raise _failure(exc) from exc


@session_router.post('/{launcher}/connect')
async def current_session_connect(launcher:Identity,body:SessionSignature,request:Request,
        response:Response,settings:Annotated[Settings,Depends(get_settings)]):
    from .credential_auth import verify_owner_auth,vault_session_payload
    _origin(request,settings);response.headers['Cache-Control']='no-store'
    runtime=_runtime(request,settings)
    if body.generation_id!=runtime.store.generation_id:
        raise HTTPException(409,detail={'code':'CUSTOMER_GENERATION_CHANGED'})
    try:
        snapshot=runtime.current_vault_snapshot(launcher)
        owner=verify_owner_auth(settings,vault_launcher_id=launcher,action='session_login',
            payload=vault_session_payload(settings),owner_auth=body.ownerAuth,current_customer_session=True)
        if snapshot['owner'].lower()!=owner.owner_key.lower() or snapshot['authType']!=owner.auth_type:
            raise ValueError('CURRENT_CUSTOMER_SESSION_OWNER_CHANGED')
        # An explicit reconnect verifies current chain state before issuing a
        # session. Polling does not execute this path or renew authorization.
        await runtime.observe_current_vault(snapshot['registrationId'])
        token,session=issue_vault_session(settings,owner)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise _failure(exc) from exc
    response.set_cookie(VAULT_SESSION_COOKIE,token,max_age=settings.vault_session_ttl_seconds,
        path=settings.vault_session_cookie_path,secure=True,httponly=True,samesite='strict')
    return session


@session_router.post('/disconnect')
async def disconnect_current_session(body:CurrentGeneration,request:Request,response:Response,
        settings:Annotated[Settings,Depends(get_settings)]):
    _origin(request,settings)
    if body.generation_id!=settings.deployment_generation_id:
        raise HTTPException(409,detail={'code':'CUSTOMER_GENERATION_CHANGED'})
    response.delete_cookie(VAULT_SESSION_COOKIE,path=settings.vault_session_cookie_path,
        secure=True,httponly=True,samesite='strict')
    response.headers['Cache-Control']='no-store'
    return {'generationId':settings.deployment_generation_id,'disconnected':True}
