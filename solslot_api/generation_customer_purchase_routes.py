"""Current native checkout HTTP adapter; installation remains separately gated.

Receiving-vault authentication is separate from the payer's Chia wallet.
GET observes saved work only. Every financial action requires an explicit
same-origin POST and the installed finite execution policy. Its runtime is
absent by default and its source remains unpublished until release review.
"""
import hashlib
import hmac
import re
from typing import Annotated

from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field

from .config import Settings, get_settings
from .generation_operations import canonical
from .generation_customer_identity_routes import owner
from .generation_customer_routes import CurrentGeneration, Identity, _origin
from .generation_customer_purchase_execution import CurrentNativePurchaseExecution, h
from .generation_customer_purchase_wallet import CurrentNativePaymentRequest
from .generation_customer_purchase_delivery import CurrentDeliveryClaim

router=APIRouter(prefix='/customer/purchases',tags=['current-customer-purchases'])
Configured=Annotated[Settings,Depends(get_settings)]


class QuoteBody(CurrentGeneration):
    request_key:str=Field(alias='requestKey',pattern=r'^[A-Za-z0-9_:-]{1,128}$')
    deed_launcher_id:Identity=Field(alias='deedLauncherId')


class PaymentBody(CurrentGeneration):
    payment_coin_id:Identity=Field(alias='paymentCoinId')
    payment_public_key:str=Field(alias='paymentPublicKey',pattern=r'^0x[0-9a-f]{96}$')


class PayerBody(CurrentGeneration):
    buyer_offer:str=Field(alias='buyerOffer',min_length=8,max_length=1024*1024)


class PayerKeysBody(CurrentGeneration):
    public_keys:list[str]=Field(alias='publicKeys',min_length=1,max_length=32)


class DeliveryBody(PayerBody):
    issuer_signature:str=Field(alias='issuerSignature',pattern=r'^0x[0-9a-f]{192}$')


def context(request,settings,launcher):
    verified=owner(request,settings,launcher)
    service=getattr(request.app.state,'generation_customer_purchase',None)
    if (getattr(settings,'generation_customer_purchase_enabled',False) is not True
            or not isinstance(service,CurrentNativePurchaseExecution)
            or settings.network!='testnet11'
            or service.settings is not settings
            or service.store.generation_id!=settings.deployment_generation_id
            or service.policy.buyer_vault!=bytes32.from_hexstr(launcher)):
        raise HTTPException(503,detail={'code':'CURRENT_CHECKOUT_NOT_OPEN',
            'message':'Test purchases are not open for this vault yet.'})
    secret=settings.vault_session_jwt_secret
    if len(secret)<32:
        raise HTTPException(503,detail={'code':'CURRENT_CHECKOUT_CONTEXT_UNAVAILABLE'})
    # Re-authentication must recover the same work. Short-lived session IDs
    # and browser storage are deliberately excluded from this owner binding.
    document=canonical(['current-purchase-owner-v1',settings.deployment_generation_id,
        launcher,verified.auth_type,verified.owner_key.lower()])
    binding=hmac.new(secret.encode(),document.encode(),hashlib.sha256).hexdigest()
    return service,binding


def mutation(request,settings,body):
    _origin(request,settings)
    if body.generation_id!=settings.deployment_generation_id:
        raise HTTPException(409,detail={'code':'CURRENT_CHECKOUT_GENERATION_CHANGED',
            'message':'The Testnet deployment changed. Reconnect your vault before continuing.'})


def failure(exc):
    status=exc.status_code if isinstance(exc,HTTPException) else 409
    detail=exc.detail if isinstance(exc,HTTPException) else None
    code=detail.get('code') if isinstance(detail,dict) else str(exc)
    if status in (401,403):
        return HTTPException(status,detail={'code':'CURRENT_CHECKOUT_OWNER_SESSION_REQUIRED',
            'message':'Reconnect the owner wallet for this vault to resume your saved checkout.'},
            headers={'Cache-Control':'no-store'})
    if not isinstance(code,str):code=''
    if not re.fullmatch(r'CURRENT_(?:EXECUTION|CHECKOUT|PURCHASE|PAYMENT|PRIMARY|ISSUER)_[A-Z_]{1,90}',code):
        code='CURRENT_CHECKOUT_STEP_UNAVAILABLE'
    message={
        'CURRENT_EXECUTION_REQUEST_KEY_DEED_CHANGED':'This saved checkout belongs to a different deed. Resume it or start a new checkout.',
        'CURRENT_EXECUTION_DISPATCH_WINDOW_CLOSED':'This payment window ended. Your saved work is preserved; check its status before starting another checkout.',
        'CURRENT_EXECUTION_RESERVATION_NOT_CONFIRMED':'Your deed reservation is waiting for confirmation. No payment approval is needed yet.',
        'CURRENT_PRIMARY_DEED_NOT_AVAILABLE':'This deed is no longer available. Check its saved purchase status before choosing another.',
    }.get(code,'Your saved checkout is preserved. Check its progress before trying again.')
    return HTTPException(status,detail={'code':code,'message':message},headers={'Cache-Control':'no-store'})


def unchanged(request,settings,launcher,service,binding):
    fresh,current=context(request,settings,launcher)
    if fresh is not service or not hmac.compare_digest(current,binding):
        raise HTTPException(409,detail={'code':'CURRENT_CHECKOUT_OWNER_CHANGED',
            'message':'Your wallet changed. Reconnect the receiving vault before continuing.'})


@router.post('/{launcher}/quotes')
async def quote(launcher:Identity,body:QuoteBody,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        result=await service.quote(body.request_key,body.deed_launcher_id,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.get('/{launcher}/inventory')
async def inventory(launcher:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        result=await service.inventory()
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/payer-coins')
async def payer_coins(launcher:Identity,identity:Identity,body:PayerKeysBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        result=await service.payer_coins(identity,body.public_keys,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.get('/{launcher}/{identity}')
async def status(launcher:Identity,identity:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        result=service.review(identity,browser_hash=binding)
        for phase in ('RESERVATION','DELIVERY','RELEASE'):
            current=service._existing(identity,phase,binding)
            if current is not None:
                result[phase.lower()]=await service.reconcile(identity,phase,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/reservation')
async def reserve(launcher:Identity,identity:Identity,body:CurrentGeneration,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        service._funding_context()
        await service.prepare_reservation(identity,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return await service.dispatch(identity,'RESERVATION',browser_hash=binding)
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/payment-review')
async def payment(launcher:Identity,identity:Identity,body:PaymentBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        saved=service._saved(identity,binding)
        operation=CurrentNativePaymentRequest(reservation=saved['reservationClaim'],
            reservedCoinId=service.reserved_coin_id(identity,browser_hash=binding),
            paymentCoinId=body.payment_coin_id,paymentPublicKey=body.payment_public_key)
        result=(await service.prepare_wallet(identity,operation,browser_hash=binding)).review()
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


def payer_claim(service,binding,identity,body):
    saved=service._saved(identity,binding)
    return CurrentDeliveryClaim(reservation=saved['reservationClaim'],
        reservedCoinId=service.reserved_coin_id(identity,browser_hash=binding),buyerOffer=body.buyer_offer)


@router.post('/{launcher}/{identity}/payer-authorization')
async def accept_payer(launcher:Identity,identity:Identity,body:PayerBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        claim=payer_claim(service,binding,identity,body)
        result=await service.accept_payer(identity,claim,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/issuer-review')
async def issuer_review(launcher:Identity,identity:Identity,body:PayerBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        claim=payer_claim(service,binding,identity,body)
        _,signed,companion,pair=await service.delivery_issuer_review(identity,claim,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return {'schema':'solslot.current-testnet-issuer-review.v1','generationId':settings.deployment_generation_id,
            'intentId':identity,'policyHash':service.policy.commitment,'deliveryClaimHash':claim.digest(),
            'issuerPublicKey':h(pair[0]),'message':h(pair[1]),'purchaseBundle':signed.to_json_dict(),
            'issuerCoinSpend':companion.issuer_signature_spend.to_json_dict(),
            'scope':'NEW_EPHEMERAL_PRIMARY_PROCEEDS_ONLY','transactionSubmitted':False}
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/delivery')
async def deliver(launcher:Identity,identity:Identity,body:DeliveryBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=context(request,settings,launcher)
        service._funding_context()
        claim=payer_claim(service,binding,identity,body)
        signature=G2Element.from_bytes(bytes.fromhex(body.issuer_signature[2:]))
        await service.prepare_delivery(identity,claim,signature,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return await service.dispatch(identity,'DELIVERY',browser_hash=binding)
    except Exception as exc:raise failure(exc) from exc
