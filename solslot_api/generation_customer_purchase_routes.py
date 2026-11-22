"""Current native checkout HTTP adapter; installation remains separately gated.

Only Chia-owned vaults may begin Chia payment. Base and card eligibility is
separate from those rails' installed capabilities. Existing work remains readable.
GET observes saved work only. Every financial action requires an explicit
same-origin POST and the installed execution authority. Its runtime is
absent by default and its source remains unpublished until release review.
"""
import hashlib
import hmac
import re
from typing import Annotated, Literal

from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field,model_validator

from .config import Settings, get_settings
from .generation_operations import canonical
from .generation_customer_identity_routes import owner
from .generation_customer_routes import CurrentGeneration, Identity, _origin
from .generation_customer_purchase_execution import CurrentNativePurchaseExecution, h
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_customer_purchase_wallet import CurrentNativePaymentRequest
from .generation_customer_purchase_delivery import CurrentDeliveryClaim
from .generation_customer_purchase_batch import CurrentReservationBatch,CurrentDeliveryBatch,CurrentBatchPaymentRequest
from .current_payment_wallet_policy import permits_payment_rail,CHIA_PAYMENT_VAULT_MESSAGE

router=APIRouter(prefix='/customer/purchases',tags=['current-customer-purchases'])
Configured=Annotated[Settings,Depends(get_settings)]


class QuoteBody(CurrentGeneration):
    checkout_mode: Literal['BUYER_PAID'] | None = Field(default=None, alias='checkoutMode')
    request_key:str=Field(alias='requestKey',pattern=r'^[A-Za-z0-9_:-]{1,128}$')
    deed_launcher_id:Identity|None=Field(default=None,alias='deedLauncherId')
    deed_launcher_ids:list[Identity]|None=Field(default=None,alias='deedLauncherIds',min_length=1,max_length=25)

    @model_validator(mode='after')
    def exact_selection(self):
        if (self.deed_launcher_id is None)==(self.deed_launcher_ids is None):
            raise ValueError('CURRENT_PURCHASE_EXACT_SELECTION_REQUIRED')
        if self.deed_launcher_ids is not None and len(set(self.deed_launcher_ids))!=len(self.deed_launcher_ids):
            raise ValueError('CURRENT_PURCHASE_DUPLICATE_DEED_REJECTED')
        return self


class PaymentBody(CurrentGeneration):
    payment_public_key_kind:Literal["raw","synthetic"]=Field(default="raw",alias="paymentPublicKeyKind")
    payment_coin_id:Identity=Field(alias='paymentCoinId')
    payment_public_key:str=Field(alias='paymentPublicKey',pattern=r'^0x[0-9a-f]{96}$')


class PayerBody(CurrentGeneration):
    buyer_offer:str=Field(alias='buyerOffer',min_length=8,max_length=1024*1024)


class PayerKeysBody(CurrentGeneration):
    payment_public_key_kind:Literal["raw","synthetic"]=Field(default="raw",alias="paymentPublicKeyKind")
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
            or (not isinstance(service.policy,TestnetCollectionIssuerPolicy)
                and service.policy.buyer_vault!=bytes32.from_hexstr(launcher))):
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
    return service,binding,verified.auth_type


def wallet_denied():
    return HTTPException(403,detail={'code':'CURRENT_CHECKOUT_PAYMENT_WALLET_NOT_ALLOWED',
        'message':CHIA_PAYMENT_VAULT_MESSAGE},headers={'Cache-Control':'no-store'})


def native_context(request,settings,launcher):
    service,binding,auth_type=context(request,settings,launcher)
    if not permits_payment_rail(auth_type,'CHIA_XCH'):
        raise wallet_denied()
    return service,binding


def delivery_context(request,settings,launcher,identity,buyer_offer):
    service,binding,auth_type=context(request,settings,launcher)
    if not permits_payment_rail(auth_type,'CHIA_XCH'):
        # Do not strand payment authorized before the rule changed. Only the
        # exact durably accepted claim may continue; a new offer is rejected.
        claim=service._saved(identity,binding).get('deliveryClaim')
        if not isinstance(claim,(CurrentDeliveryClaim,CurrentDeliveryBatch)) or claim.buyer_offer!=buyer_offer:
            raise wallet_denied()
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
    if code=='CURRENT_CHECKOUT_PAYMENT_WALLET_NOT_ALLOWED':
        return wallet_denied()
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
        'CURRENT_CHECKOUT_REFRESH_REQUIRED':'Refresh checkout to review the current payment options.',
        'CURRENT_CHECKOUT_HOLD_EXPIRED':'Your hold expired. Check availability to get a new total.',
        'CURRENT_PAYMENT_NETWORK_FEE_INCREASED':'The minimum network fee changed. Review the updated fee before paying.',
        'CURRENT_PAYMENT_INSUFFICIENT_FUNDS':'Your selected coin has insufficient funds for the purchase and network fee.',
        'CURRENT_PRIMARY_DEED_NOT_AVAILABLE':'This deed is no longer available. Check its saved purchase status before choosing another.',
        'CURRENT_EXECUTION_OPERATIONAL_PAUSED':'Checkout is temporarily paused. Check the status of any saved purchase.',
    }.get(code,'Your saved checkout is preserved. Check its progress before trying again.')
    return HTTPException(status,detail={'code':code,'message':message},headers={'Cache-Control':'no-store'})


def unchanged(request,settings,launcher,service,binding):
    fresh,current,_=context(request,settings,launcher)
    if fresh is not service or not hmac.compare_digest(current,binding):
        raise HTTPException(409,detail={'code':'CURRENT_CHECKOUT_OWNER_CHANGED',
            'message':'Your wallet changed. Reconnect the receiving vault before continuing.'})


@router.post('/{launcher}/quotes')
async def quote(launcher:Identity,body:QuoteBody,request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding,auth_type=context(request,settings,launcher)
        if not permits_payment_rail(auth_type,'CHIA_XCH'):
            prior=service.store.review_for_request(body.request_key,browser_hash=binding)
            if prior is None:raise wallet_denied()
            result=service.review(prior['intentId'],browser_hash=binding)
            selected=body.deed_launcher_ids if body.deed_launcher_ids is not None else [body.deed_launcher_id]
            retained=result.get('deedLauncherIds') or [result.get('deedLauncherId')]
            if sorted(selected)!=sorted(retained):raise wallet_denied()
            unchanged(request,settings,launcher,service,binding)
            return result
        buyer_paid = body.checkout_mode == 'BUYER_PAID'
        enabled = getattr(settings, 'generation_customer_purchase_atomic_enabled', False)
        prior = service.store.review_for_request(body.request_key, browser_hash=binding)
        if buyer_paid and (not enabled or (prior is None and not settings.generation_customer_purchase_atomic_accepting)):
            raise ValueError('CURRENT_CHECKOUT_BUYER_PAID_UNAVAILABLE')
        if enabled and not buyer_paid and prior is None:
            raise ValueError('CURRENT_CHECKOUT_REFRESH_REQUIRED')
        selected=body.deed_launcher_ids if body.deed_launcher_ids is not None else body.deed_launcher_id
        if isinstance(service.policy,TestnetCollectionIssuerPolicy):
            verified = owner(request, settings, launcher)
            result = await service.quote(body.request_key, selected, browser_hash=binding,
                receiving_launcher=bytes32.from_hexstr(launcher), receiving_owner=verified.owner_key, **({'buyer_paid': True} if buyer_paid else {}))
        else:
            result=await service.quote(body.request_key,selected,browser_hash=binding, **({'buyer_paid': True} if buyer_paid else {}))
        if buyer_paid:
            from .generation_customer_native_cart_checkout import recover_cart_quote
            result = await recover_cart_quote(service, result['intentId'], binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.get('/{launcher}/inventory')
async def inventory(launcher:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service,binding,_=context(request,settings,launcher)
        if isinstance(service.policy,TestnetCollectionIssuerPolicy):
            result=await service.inventory(receiving_launcher=bytes32.from_hexstr(launcher))
        else:
            result=await service.inventory()
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/payer-coins')
async def payer_coins(launcher:Identity,identity:Identity,body:PayerKeysBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=native_context(request,settings,launcher)
        result=await service.payer_coins(identity,body.public_keys,public_key_kind=body.payment_public_key_kind,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


def customer_stage_receipt(service, identity, phase, binding, stage):
    """Report the buyer's sponsored limit while preserving the bound journal ceiling."""
    faucet = getattr(getattr(service, 'submitter', None), 'faucet', None)
    if not getattr(faucet, 'paired_grant', False):
        return stage
    quoted_cap = str(service.review_fee_cap(identity, binding))
    if stage['feeCapMojos'] == quoted_cap:
        return stage
    if (stage['feeCapMojos'] != str(service.fee_cap)
            or quoted_cap != str(faucet.authority.maximum_stage_fee_mojos)
            or int(quoted_cap) >= service.fee_cap):
        raise ValueError('CURRENT_EXECUTION_STAGE_FEE_CAP_CHANGED')
    funded = service.store.execution_funding(identity, phase, browser_hash=binding)
    if funded is not None and not 0 <= int(funded['feeMojos']) <= int(quoted_cap):
        raise ValueError('CURRENT_EXECUTION_FUNDED_FEE_EXCEEDS_QUOTE')
    return {**stage, 'feeCapMojos': quoted_cap}


@router.get('/{launcher}/{identity}')
async def status(launcher:Identity,identity:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    try:
        service,binding,_=context(request,settings,launcher)
        from .generation_customer_native_cart_checkout import cart_review
        result = cart_review(service, identity, binding) if hasattr(service.store, '_connect') else service.review(identity,browser_hash=binding)
        if 'cart' in result:
            unchanged(request,settings,launcher,service,binding)
            return result
        for phase in ('RESERVATION','DELIVERY','RELEASE'):
            current=service._existing(identity,phase,binding)
            if current is not None:
                stage = await service.reconcile(identity, phase, browser_hash=binding)
                result[phase.lower()] = customer_stage_receipt(
                    service, identity, phase, binding, stage)
        unchanged(request,settings,launcher,service,binding)
        # Only a durable, exact-bundle expiry proof may end an unpaid PREPARED
        # checkout. The original reservation and journals remain intact.
        if result.get('quoteExpired') and not result.get('payerAuthorizationSaved'):
            from .generation_customer_purchase_worker import expired_unsubmitted_reservation
            collection = isinstance(service.policy, TestnetCollectionIssuerPolicy)
            retired = (service.retired_outcome(identity, service._review_saved(identity, binding)['reservationClaim'])
                       if collection else None)
            closed_before_preparation = (collection and retired is None and result.get('reservationRequested')
                and 'reservation' not in result and service.store.closed_without_preparation(identity, browser_hash=binding))
            if retired == 'UNSUBMITTED_EXPIRED' or (
                    retired is None and expired_unsubmitted_reservation(service,identity,binding)) or closed_before_preparation:
                result['reservationUnsubmittedExpired']=True
            unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/reservation')
async def reserve(launcher:Identity,identity:Identity,body:CurrentGeneration,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=native_context(request,settings,launcher)
        if (getattr(settings, 'generation_customer_purchase_atomic_enabled', False)
                and service.store.reservation_request(identity, browser_hash=binding) is None):
            raise ValueError('CURRENT_CHECKOUT_REFRESH_REQUIRED')
        service._funding_context()
        result=service.request_reservation(identity,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/payment-review')
async def payment(launcher:Identity,identity:Identity,body:PaymentBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=native_context(request,settings,launcher)
        saved=service._saved(identity,binding)
        if isinstance(saved['reservationClaim'],CurrentReservationBatch):
            operation=CurrentBatchPaymentRequest(reservation=saved['reservationClaim'],
                reservedCoinIds=service.reserved_coin_id(identity,browser_hash=binding),
                paymentCoinId=body.payment_coin_id,paymentPublicKey=body.payment_public_key,paymentPublicKeyKind=body.payment_public_key_kind)
        else:operation=CurrentNativePaymentRequest(reservation=saved['reservationClaim'],
            reservedCoinId=service.reserved_coin_id(identity,browser_hash=binding),
            paymentCoinId=body.payment_coin_id,paymentPublicKey=body.payment_public_key,paymentPublicKeyKind=body.payment_public_key_kind)
        result=(await service.prepare_wallet(identity,operation,browser_hash=binding)).review()
        unchanged(request,settings,launcher,service,binding)
        return result
    except Exception as exc:raise failure(exc) from exc


def payer_claim(service,binding,identity,body):
    saved=service._saved(identity,binding)
    if isinstance(saved['reservationClaim'],CurrentReservationBatch):
        return CurrentDeliveryBatch(reservation=saved['reservationClaim'],
            reservedCoinIds=service.reserved_coin_id(identity,browser_hash=binding),buyerOffer=body.buyer_offer)
    return CurrentDeliveryClaim(reservation=saved['reservationClaim'],
        reservedCoinId=service.reserved_coin_id(identity,browser_hash=binding),buyerOffer=body.buyer_offer)


@router.post('/{launcher}/{identity}/payer-authorization')
async def accept_payer(launcher:Identity,identity:Identity,body:PayerBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=native_context(request,settings,launcher)
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
        service,binding=delivery_context(request,settings,launcher,identity,body.buyer_offer)
        claim=payer_claim(service,binding,identity,body)
        _,signed,companion,pair=await service.delivery_issuer_review(identity,claim,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        from .generation_customer_purchase_worker import issuer_message
        public,message=issuer_message(pair)
        return {'schema':'solslot.current-testnet-issuer-review.v2'if isinstance(claim,CurrentDeliveryBatch)else'solslot.current-testnet-issuer-review.v1','generationId':settings.deployment_generation_id,
            'intentId':identity,'policyHash':service.policy.commitment,'deliveryClaimHash':claim.digest(),
            'issuerPublicKey':public,'message':message,'purchaseBundle':signed.to_json_dict(),
            'issuerCoinSpend':([spend.to_json_dict()for spend in companion.issuer_signature_spends]
                if hasattr(companion,'issuer_signature_spends')else companion.issuer_signature_spend.to_json_dict()),
            'scope':'NEW_EPHEMERAL_PRIMARY_PROCEEDS_ONLY','transactionSubmitted':False}
    except Exception as exc:raise failure(exc) from exc


@router.post('/{launcher}/{identity}/delivery')
async def deliver(launcher:Identity,identity:Identity,body:DeliveryBody,
        request:Request,response:Response,settings:Configured):
    mutation(request,settings,body);response.headers['Cache-Control']='no-store'
    try:
        service,binding=delivery_context(request,settings,launcher,identity,body.buyer_offer)
        service._funding_context()
        claim=payer_claim(service,binding,identity,body)
        signature=G2Element.from_bytes(bytes.fromhex(body.issuer_signature[2:]))
        await service.prepare_delivery(identity,claim,signature,browser_hash=binding)
        unchanged(request,settings,launcher,service,binding)
        stage = await service.dispatch(identity, 'DELIVERY', browser_hash=binding)
        return customer_stage_receipt(service, identity, 'DELIVERY', binding, stage)
    except Exception as exc:raise failure(exc) from exc


class CartPaymentBody(PaymentBody):
    network_fee_mojos: str = Field(alias='networkFeeMojos', pattern=r'^(0|[1-9][0-9]{0,19})$')


def cart_context(request, settings, launcher):
    if not getattr(settings, 'generation_customer_purchase_atomic_enabled', False):
        raise HTTPException(503, detail={'code': 'CURRENT_CHECKOUT_BUYER_PAID_UNAVAILABLE'})
    return native_context(request, settings, launcher)


@router.post('/{launcher}/{identity}/cart/fees')
async def cart_fees(launcher: Identity, identity: Identity, body: PaymentBody, request: Request,
                    response: Response, settings: Configured):
    from .generation_customer_native_cart_checkout import fee_options
    mutation(request, settings, body)
    response.headers['Cache-Control'] = 'no-store'
    try:
        service, binding = cart_context(request, settings, launcher)
        result = await fee_options(service, identity, binding, body)
        unchanged(request, settings, launcher, service, binding)
        return result
    except Exception as exc:
        raise failure(exc) from exc


@router.post('/{launcher}/{identity}/cart/payment-review')
async def cart_wallet_review(launcher: Identity, identity: Identity, body: CartPaymentBody, request: Request,
                             response: Response, settings: Configured):
    from .generation_customer_native_cart_checkout import payment_review
    mutation(request, settings, body)
    response.headers['Cache-Control'] = 'no-store'
    try:
        service, binding = cart_context(request, settings, launcher)
        result = await payment_review(service, identity, binding, body)
        unchanged(request, settings, launcher, service, binding)
        return result
    except Exception as exc:
        raise failure(exc) from exc


@router.post('/{launcher}/{identity}/cart/approval')
async def cart_approval(launcher: Identity, identity: Identity, body: PayerBody, request: Request,
                        response: Response, settings: Configured):
    from .generation_customer_native_cart_checkout import approve_payment
    mutation(request, settings, body)
    response.headers['Cache-Control'] = 'no-store'
    try:
        service, binding = cart_context(request, settings, launcher)
        result = await approve_payment(service, identity, binding, body.buyer_offer)
        unchanged(request, settings, launcher, service, binding)
        return result
    except Exception as exc:
        raise failure(exc) from exc
