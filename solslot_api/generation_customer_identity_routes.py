"""Native customer ID lifecycle. No administrator login or legacy admission."""
from typing import Annotated
import logging
import re
from fastapi import APIRouter,Depends,HTTPException,Request,Response
from pydantic import Field
from starlette.concurrency import run_in_threadpool
from .config import Settings,get_settings
from .credential_auth import verify_vault_session,VaultSessionResponse,vault_session_fingerprint
from .generation_customer_routes import CurrentGeneration,Identity,_origin,_runtime as customers_runtime
from .generation_customer_identity_runtime import CurrentCustomerIdentityRuntime
from .generation_customer_identity_scope import current_identity_request
from .zkpassport_enrollments import RecordProofRequest,SubmitChiaStampRequest,RelayChallengeRequest
from .zkpassport_relay import RelayRequest,BlsRelayRequest

router=APIRouter(prefix='/customer/identity',tags=['current-customer-identity'])
Configured=Annotated[Settings,Depends(get_settings)]
logger=logging.getLogger(__name__)


class ProofBody(CurrentGeneration,RecordProofRequest):pass
class StampBody(CurrentGeneration,SubmitChiaStampRequest):pass
class ChallengeBody(CurrentGeneration,RelayChallengeRequest):pass
class EvmRelayBody(CurrentGeneration,RelayRequest):pass
class BlsRelayBody(CurrentGeneration,BlsRelayRequest):pass


def runtime(request,settings):
    value=getattr(request.app.state,'generation_customer_identity',None)
    if not settings.generation_customer_identity_enabled or not isinstance(value,CurrentCustomerIdentityRuntime):
        raise HTTPException(503,detail={'code':'CURRENT_ID_UNAVAILABLE','message':'Current Testnet ID setup is not ready yet.'})
    if value.customers is not customers_runtime(request,settings):
        raise HTTPException(503,detail={'code':'CURRENT_ID_RUNTIME_CHANGED'})
    return value


def owner(request,settings,launcher):
    verified=verify_vault_session(settings,request,launcher)
    snapshot=customers_runtime(request,settings).current_vault_snapshot(launcher)
    if (verified.scope!='vault' or verified.owner_key.lower()!=snapshot['owner'].lower()
            or verified.auth_type!=snapshot['authType']):
        raise HTTPException(403,detail={'code':'CURRENT_ID_OWNER_CHANGED'})
    return verified


def mutation(request,settings,body):
    _origin(request,settings)
    if body.generation_id!=settings.deployment_generation_id:
        raise HTTPException(409,detail={'code':'CURRENT_ID_GENERATION_CHANGED'})


def failure(exc):
    # Never return proof/provider/credential-bearing exception text.
    detail=exc.detail if isinstance(exc,HTTPException) else None
    code=detail.get('code') if isinstance(detail,dict) else str(exc)
    safe=code if isinstance(code,str) and re.fullmatch(r'CURRENT_ID_[A-Z_]{1,80}',code) else 'CURRENT_ID_STEP_UNAVAILABLE'
    message='Your saved check is preserved. Check progress before trying this step again.'
    if (safe=='CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED' or
            isinstance(exc,HTTPException) and 'UnsupportedProofVersion' in str(detail)):
        safe='CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED'
        message='The identity verifier needs a compatibility update. Your vault is saved; please wait before starting another scan.'
    elif isinstance(exc,HTTPException) and isinstance(detail,str):
        if detail=='ForwardRequest signature/nonce/deadline is invalid.':
            safe='CURRENT_ID_OWNER_AUTHORIZATION_REJECTED'
            message='The wallet approval is no longer valid. Reconnect your vault and use the newest wallet request.'
        elif detail.startswith('Simulation reverted:'):
            safe='CURRENT_ID_RELAY_SIMULATION_REJECTED'
            message='The identity contract could not accept this proof. Your vault is saved; please wait before starting another scan.'
    logger.warning('current_identity_step_failed code=%s exception_type=%s',safe,type(exc).__name__)
    if isinstance(exc,HTTPException) and isinstance(detail,dict) and safe==code:return exc
    return HTTPException(exc.status_code if isinstance(exc,HTTPException) else 409,detail={'code':safe,
        'message':message})


@router.get('/profile')
async def profile(request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);pins=service.profile();enabled=False
        if service.authority is not None:
            try:service.authority.require_live(pins,int(service.clock()));enabled=service.compatibility_ready(pins)
            except ValueError:pass
        return {'schema':'solslot.current-customer-identity-runtime.v1','profileHash':pins.commitment,
            'profile':pins.model_dump(mode='json',by_alias=True),'enrollmentEnabled':enabled,
            'stampEnabled':enabled and service.fee_submitter is not None,
            'authorityExpiresAt':service.authority.expires_at if service.authority else None,
            'compatibility':getattr(service,'compatibility',{}),
            'observer':service.health}
    except Exception as exc:raise failure(exc) from exc


@router.get('/enrollments/{launcher}/session',response_model=VaultSessionResponse)
async def session(launcher:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store';runtime(request,settings)
    verified=owner(request,settings,launcher)
    return VaultSessionResponse(vaultLauncherId=launcher,authType=verified.auth_type,network='testnet11',
        expiresAt=verified.expires_at,scope='vault',generationId=settings.deployment_generation_id,
        sessionFingerprint=vault_session_fingerprint(verified.session_id))


@router.get('/enrollments/{launcher}')
async def enrollment(launcher:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher);record=service.cached(launcher)
        if record is None:raise HTTPException(404,detail={'code':'CURRENT_ID_NOT_STARTED'})
        return record
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}')
async def reserve(launcher:Identity,body:CurrentGeneration,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);verified=owner(request,settings,launcher)
        if service.authority is None:raise ValueError('CURRENT_ID_NOT_AUTHORIZED')
        service.authority.require_live(service.profile(),int(service.clock()))
        return await service.reserve(launcher,verified)
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}/proof')
async def proof(launcher:Identity,body:ProofBody,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        existing=service.cached(launcher)
        if existing is not None and existing.get('receipt') is not None:
            receipt=existing['receipt']
            fields=('vaultLauncherId','policyVersion','identityAttestRoot','attestationLeafHash','attestationProof',
                'bridgePolicyHash','bridgeParentId','bridgeAmount','bridgeCoinId','bridgeMessage','validatorMessage','evmTxHash')
            values=body.model_dump()
            if any(values[key]!=receipt.get(key) for key in fields):raise ValueError('CURRENT_ID_PROOF_CHANGED')
            return existing
        reads,_=await service.request_reads(launcher,transaction_hash=body.evmTxHash)
        from .zkpassport_enrollments import record_evm_proof
        with current_identity_request(settings,reads.profile,launcher,service.customers,runtime=reads,
                clock=service.clock,require_fresh=False):
            return await run_in_threadpool(record_evm_proof,launcher,
                RecordProofRequest.model_validate(body.model_dump(exclude={'generation_id'})),request)
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}/relay/challenge')
async def relay_challenge(launcher:Identity,body:ChallengeBody,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        reads,_=await service.request_reads(launcher,include_event=False)
        from .zkpassport_enrollments import create_bls_relay_challenge
        with current_identity_request(settings,reads.profile,launcher,service.customers,runtime=reads,clock=service.clock):
            return await run_in_threadpool(create_bls_relay_challenge,launcher,RelayChallengeRequest(data=body.data),request)
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}/stamp/prepare')
async def stamp_prepare(launcher:Identity,body:CurrentGeneration,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        reads,_=await service.request_reads(launcher)
        from .zkpassport_enrollments import prepare_chia_stamp
        with current_identity_request(settings,reads.profile,launcher,service.customers,runtime=reads,clock=service.clock) as scope:
            reads.require_stamp(scope)
            return await run_in_threadpool(prepare_chia_stamp,launcher,request)
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}/stamp/submit')
async def stamp_submit(launcher:Identity,body:StampBody,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        reads,native=await service.request_reads(launcher)
        if native.identity_verified:
            record=await service.sync(launcher)
            return {'enrollment':record,'spendBundleId':record.receipt.chiaSpendBundleId,
                'expectedVaultCoinId':record.receipt.chiaStampCoinId}
        from .zkpassport_enrollments import submit_evm_chia_stamp
        with current_identity_request(settings,reads.profile,launcher,service.customers,runtime=reads,clock=service.clock) as scope:
            reads.require_stamp(scope)
            # z authorization signs the root and input, not the unsigned
            # transaction clock. Refresh that clock before first dispatch;
            # existing durable attempts retain their exact original claim.
            inner=SubmitChiaStampRequest(signature=body.signature,currentTimestamp=int(service.clock()))
            return await submit_evm_chia_stamp(launcher,inner,request)
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}/stamp/sync')
async def stamp_sync(launcher:Identity,body:CurrentGeneration,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        return {'enrollment':await service.sync(launcher)}
    except Exception as exc:raise failure(exc) from exc


async def submit_relay(body,request,response,settings,*,bls):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        from .enrollment_permit_runtime import decode_enrollment
        if len(body.data)>2_000_000:raise ValueError('CURRENT_ID_PROOF_TOO_LARGE')
        launcher=decode_enrollment(bytes.fromhex(body.data.removeprefix('0x'))).vault
        service=runtime(request,settings);owner(request,settings,launcher)
        reads,_=await service.request_reads(launcher,include_event=False)
        from .zkpassport_relay import relay,relay_bls
        with current_identity_request(settings,reads.profile,launcher,service.customers,runtime=reads,clock=service.clock) as scope:
            reads.require_relay(scope)
            inner=(BlsRelayRequest if bls else RelayRequest).model_validate(body.model_dump(exclude={'generation_id'},by_alias=True))
            return await run_in_threadpool(relay_bls if bls else relay,inner,request)
    except Exception as exc:
        safe=failure(exc)
        # Existing relay clients render detail as text. Keep this boundary
        # readable without returning raw provider errors or proof bytes.
        if isinstance(safe.detail,dict):
            raise HTTPException(safe.status_code,detail=safe.detail['message'],
                headers={'X-Solslot-Error-Code':safe.detail['code']}) from exc
        raise safe from exc


@router.post('/relay')
async def relay(body:EvmRelayBody,request:Request,response:Response,settings:Configured):
    return await submit_relay(body,request,response,settings,bls=False)


@router.post('/relay/bls')
async def relay_bls(body:BlsRelayBody,request:Request,response:Response,settings:Configured):
    return await submit_relay(body,request,response,settings,bls=True)


@router.get('/enrollments/{launcher}/relay/recovery')
async def recovery(launcher:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        return service.relay_status(launcher)
    except Exception as exc:raise failure(exc) from exc


@router.post('/enrollments/{launcher}/relay/resume')
async def resume(launcher:Identity,body:CurrentGeneration,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service=runtime(request,settings);owner(request,settings,launcher)
        reads,_=await service.request_reads(launcher,include_event=False)
        from .zkpassport_relay import resume_relay
        with current_identity_request(settings,reads.profile,launcher,service.customers,runtime=reads,clock=service.clock):
            return await run_in_threadpool(resume_relay,launcher,request)
    except Exception as exc:raise failure(exc) from exc
