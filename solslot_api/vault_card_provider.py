"""Sols Lot's fixed Stripe API origin and server-built Checkout Session."""
import hashlib
import re
from urllib.parse import urlencode,urlsplit

import httpx
from .protocol_artifacts import _stripe_restricted_key

VERSION="2026-02-25.clover"
def metadata(order):
    return dict(rail="solslot_vault_card",purchase_id=order.purchase_id,protocol_purchase_id=order.purchase_id,
        batch_hash=order.batch_hash,purchase_artifact_hash=order.batch_hash,generation_id=order.generation_id,
        collection_id=order.collection_id,vault_launcher_id=order.vault_launcher_id,destination_puzzle_hash=order.destination_puzzle_hash,
        deed_launcher_ids=",".join(order.deed_launcher_ids),network=order.network)


def session_params(order,origin,now):
    u=urlsplit(origin)
    if (u.scheme!="https" or not u.hostname or u.username or u.password or origin!="https://"+u.netloc or len(",".join(order.deed_launcher_ids))>500):
        raise ValueError("Invalid card checkout origin or order")
    ref=origin+"/checkout/card-return?"+urlencode(dict(vault=order.vault_launcher_id,collection=order.collection_id,purchase=order.purchase_id))
    expiry=min(now+86400,order.expires_at-120)
    if expiry<now+1830:raise ValueError("Insufficient time for this original Checkout Session")
    body=dict(mode="payment",ui_mode="hosted",success_url=ref,cancel_url=ref,client_reference_id=order.purchase_id,expires_at=str(expiry))
    body["payment_method_types[0]"]="card"
    for i,deed in enumerate(order.batch["artifacts"]):
        base=f"line_items[{i}]"
        body[base+"[price_data][currency]"]=order.currency
        body[base+"[price_data][product_data][name]"]="SmartDeed "+deed["deedLauncherId"][2:10]
        body[base+"[price_data][unit_amount]"]=str(int(deed["railAmount"]))
        body[base+"[quantity]"]="1"
    for key,value in metadata(order).items():
        body["metadata["+key+"]"]=value
        body["payment_intent_data[metadata]["+key+"]"]=value
    return body


def checked_session(order,session,*,expected_expiry):
    sid=session.get("id")
    if (not isinstance(sid,str) or not re.fullmatch("cs_"+order.mode+"_[A-Za-z0-9]+",sid)
        or session.get("object")!="checkout.session" or session.get("mode")!="payment"
        or session.get("livemode") is not (order.mode=="live") or session.get("currency")!=order.currency
        or type(session.get("amount_total")) is not int or session["amount_total"]!=order.amount_minor
        or session.get("client_reference_id")!=order.purchase_id or session.get("metadata")!=metadata(order)
        or session.get("expires_at")!=expected_expiry or session.get("status") not in ("open","complete","expired")
        or order.session_id not in (None,sid) or session.get("payment_method_types")!=["card"]):
        raise ValueError("Stripe returned a different card order")
    pi=session.get("payment_intent")
    if pi is not None and (not isinstance(pi,str) or not re.fullmatch("pi_[A-Za-z0-9]+",pi) or order.payment_intent_id not in (None,pi)):
        raise ValueError("Stripe returned a different PaymentIntent")
    if session["status"]=="open":
        link=urlsplit(session.get("url") or "")
        if (link.scheme!="https" or link.netloc!="checkout.stripe.com" or link.path!="/c/pay/"+sid
            or session.get("payment_status")!="unpaid"):
            raise ValueError("Stripe Checkout URL is unavailable")
    return session


class VaultCardProvider:
    def __init__(self,settings,*,transport=None):
        if settings.stripe_api_url!="https://api.stripe.com":raise ValueError("Unrecognized Stripe API origin")
        self.settings,self.transport=settings,transport

    async def _api(self,method,path,*,params=None,data=None,key=None):
        headers={"Authorization":"Bearer "+_stripe_restricted_key(self.settings),"Stripe-Version":VERSION}
        if key:headers["Idempotency-Key"]=key
        async with httpx.AsyncClient(base_url="https://api.stripe.com",timeout=12,follow_redirects=False,trust_env=False,transport=self.transport) as client:
            reply=await client.request(method,path,params=params,data=data,headers=headers)
        if reply.status_code not in (200,201):raise ValueError("Stripe could not confirm the original request")
        doc=reply.json()
        if not isinstance(doc,dict):raise ValueError("Stripe returned an invalid observation")
        return doc

    async def account(self):
        account=await self._api("GET","/v1/account")
        if account.get("object")!="account" or account.get("id")!=self.settings.stripe_account_id:raise ValueError("Stripe business differs")
        return account

    async def _resource(self,kind,identifier,pattern,params=None):
        if not isinstance(identifier,str) or not re.fullmatch(pattern,identifier):raise ValueError("Invalid Stripe reference")
        doc=await self._api("GET","/v1/"+kind+"/"+identifier,params=params)
        if doc.get("id")!=identifier or doc.get("livemode") is not (self.settings.stripe_mode=="live"):raise ValueError("Stripe resource differs")
        return doc

    async def retrieve_session(self,session_id):
        return await self._resource("checkout/sessions",session_id,"cs_(?:test|live)_[A-Za-z0-9]+")
    async def retrieve_payment_intent(self,payment_intent_id):
        return await self._resource("payment_intents",payment_intent_id,"pi_[A-Za-z0-9]+",{"expand[]":"latest_charge"})
    async def retrieve_event(self,event_id):
        return await self._resource("events",event_id,"evt_[A-Za-z0-9]+")
    async def retrieve_refund(self,refund_id):
        if not isinstance(refund_id,str) or not re.fullmatch("re_[A-Za-z0-9]+",refund_id):raise ValueError("Invalid Stripe refund")
        # Refund objects do not universally expose livemode. Verify their owned PaymentIntent separately.
        doc=await self._api("GET","/v1/refunds/"+refund_id)
        if doc.get("id")!=refund_id or doc.get("object")!="refund":raise ValueError("Stripe refund differs")
        return doc

    def _key(self,order,purpose):
        return "solslot-vault-card-"+purpose+"-"+hashlib.sha256("|".join([order.account_id,order.mode,order.network,order.purchase_id]).encode()).hexdigest()
    async def create_session(self,order,params):
        if self.settings.stripe_account_id!=order.account_id or self.settings.stripe_mode!=order.mode:raise ValueError("Stripe account or mode changed")
        account=await self.account()
        if account.get("charges_enabled") is not True:raise ValueError("This Stripe account cannot receive card payments")
        return await self._api("POST","/v1/checkout/sessions",data=params,key=self._key(order,"checkout"))
    async def refund_payment(self,order,payment_intent_id):
        if order.payment_intent_id!=payment_intent_id or self.settings.stripe_account_id!=order.account_id or self.settings.stripe_mode!=order.mode:
            raise ValueError("Refund does not match its original payment")
        await self.account()
        pi=await self.retrieve_payment_intent(payment_intent_id)
        if (pi.get("status")!="succeeded" or pi.get("amount")!=order.amount_minor or pi.get("amount_received")!=order.amount_minor
            or pi.get("currency")!=order.currency or pi.get("metadata")!=metadata(order)):raise ValueError("Original payment does not match the refund")
        data={"payment_intent":payment_intent_id,"amount":str(order.amount_minor),
              "metadata[rail]":"solslot_vault_card","metadata[purchase_id]":order.purchase_id}
        return await self._api("POST","/v1/refunds",data=data,key=self._key(order,"refund"))

    async def recover_session(self,order,store,*,now):
        dispatch=store.dispatch(order.purchase_id)
        if not dispatch or not dispatch['first_dispatch']<=now<dispatch['first_dispatch']+23*3600:
            raise ValueError("Previous dispatch requires manual reconciliation")
        if order.session_id:
            await self.account()
            session=await self.retrieve_session(order.session_id)
        else:
            # A replay after the original parameter expiry cannot create a fresh valid Session.
            session=await self.create_session(order,dispatch['params'])
        checked_session(order,session,expected_expiry=dispatch['session_expires_at'])
        return store.bind_session(order.purchase_id,session['id'],session.get('payment_intent'))
