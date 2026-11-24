"""Current vault customer checkout. The only hosted-session mutation requires an owner click."""
import asyncio
import logging
import sqlite3
import time
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

from .config import Settings, get_settings
from .credential_auth import verify_vault_session
from .generation_customer_routes import Identity, _origin
from .payment_purchase_store import get_payment_purchase_store
from .vault_card_events import CardInbox, card_status, signing_key
from .vault_card_native import Hash,VaultCardNative
from .vault_card_provider import VaultCardProvider,checked_session,session_params
from .vault_card_reservations import reserve
from .vault_card_store import VaultCardStore
from .vault_stripe_protection import allocate_current_card_coverage,current_card_coverage

router=APIRouter(prefix='/customer/purchases',tags=['vault-card-checkout'])
PRIVATE={'Cache-Control':'private, no-store'}
KNOWN_ERRORS=(ValueError,KeyError,LookupError,RuntimeError,OSError,TimeoutError,sqlite3.Error,httpx.HTTPError)
LOG=logging.getLogger(__name__)


class CardClick(BaseModel):
    model_config=ConfigDict(extra='forbid')
    purchaseId: Hash
    batchHash: Hash
    intent: Literal['prepare','checkout']


def dto(settings,vault,collection,state='UNAVAILABLE',order=None,requested=False,paid=False):
    return dict(schema='solslot.vault-card-order.v1',state=state,network=settings.network,mode=settings.stripe_mode,
        generationId=settings.deployment_generation_id,collectionId=collection,vaultLauncherId=vault,
        purchaseId=order.purchase_id if order else None,batchHash=order.batch_hash if order else None,
        destinationPuzzleHash=order.destination_puzzle_hash if order else None,
        deedLauncherIds=list(order.deed_launcher_ids) if order else [],quantity=len(order.deed_launcher_ids) if order else 0,
        amountMinor=order.amount_minor if order else 0,currency='usd',expiresAt=order.expires_at if order else None,
        reservationRequested=requested,paymentReceived=paid)


def owner_context(request,settings,vault):
    owner=verify_vault_session(settings,request,vault)
    customers=getattr(request.app.state,'generation_customers',None)
    if customers is None:
        raise HTTPException(503,'Current vault service unavailable')
    snapshot=customers.current_vault_snapshot(vault)
    if (snapshot['owner'].lower()!=owner.owner_key.lower() or snapshot['authType']!=owner.auth_type
            or snapshot['generationId']!=settings.deployment_generation_id or snapshot['network']!=settings.network
            or snapshot['vault']['vaultLauncherId']!=vault):
        raise HTTPException(403,'Current owner or generation changed')
    return customers,snapshot


def same_original(first,second):
    return replace(first,session_id=None,payment_intent_id=None,session_expires_at=None)==replace(
        second,session_id=None,payment_intent_id=None,session_expires_at=None)


class VaultCardCheckout:
    def __init__(self,settings,native,store,purchases,provider,*,clock=time.time):
        self.settings,self.native,self.store,self.purchases,self.provider=settings,native,store,purchases,provider
        self.clock=clock
        self.lock=asyncio.Lock()

    @classmethod
    def configured(cls,settings):
        if not settings.vault_card_checkout_enabled:
            return None
        native=VaultCardNative.configured(settings)
        if settings.vault_card_return_origin and settings.vault_card_return_origin!=settings.generation_customer_public_origin:
            raise ValueError('Card return origin differs from current vault checkout')
        purchases=get_payment_purchase_store(settings.payment_purchase_db_path)
        return cls(settings,native,VaultCardStore(settings.payment_purchase_db_path),purchases,VaultCardProvider(settings))

    def active_time(self):
        now=int(self.clock())
        return self.native.scope.validFrom<=now<self.native.scope.expiresAt-1950

    def integrations(self):
        s=self.settings
        if not (s.vault_card_checkout_enabled and s.generation_customer_enabled and not s.alpha_writes_enabled and not s.minting_enabled
                and s.vault_card_delivery_enabled and not s.stripe_settlement_enabled and not s.stripe_delivery_worker_enabled
                and not s.protocol_fee_funding_enabled and s.vault_card_webhook_key_file):
            return False
        try:
            signing_key(s.vault_card_webhook_key_file)
        except (OSError,ValueError):
            return False
        return True

    async def advance(self,app,customers,snapshot,previous):
        if not self.active_time() or not self.integrations() or previous.session_id:
            return
        evidence=await self.native.reconstruct(customers,snapshot)
        if not same_original(evidence.order,previous):
            raise ValueError('Retained card purchase changed')
        if card_status(app,self.settings,previous):
            return
        stage=await self.native.stage(evidence,customers.provider)
        if self.store.dispatch(previous.purchase_id):
            if stage[0]=='CONFIRMED' and await current_card_coverage(app,self.settings,previous,now=int(self.clock())):
                await self.provider.recover_session(previous,self.store,now=int(self.clock()))
            return
        self.native.retain(self.purchases,evidence,int(self.clock()))
        saved=await reserve(SimpleNamespace(app=app),self.settings,self.native,evidence,self.purchases,stage)
        if not self.active_time():
            return
        if saved.inventory_state=='CONFIRMED' and stage==('CONFIRMED',saved.inventory_confirmation_height):
            await allocate_current_card_coverage(app,self.settings,previous,now=int(self.clock()))

    async def run(self,app):
        while True:
            try:
                async with self.lock:
                    customers=getattr(app.state,'generation_customers',None)
                    old=self.store.by_release(self.native.release_id)
                    if old and customers is not None and self.active_time():
                        await self.advance(app,customers,customers.current_vault_snapshot(old.vault_launcher_id),old)
            except (*KNOWN_ERRORS,HTTPException) as exc:
                LOG.warning('Card reservation pending (%s)',type(exc).__name__)
            await asyncio.sleep(10)

    async def handle(self,request,vault,collection,click,customers,snapshot):
        s=self.settings
        def reauthenticate():
            current,observed=owner_context(request,s,vault)
            if (current is not customers or observed!=snapshot or getattr(request.app.state,'vault_card_checkout',None) is not self):
                raise HTTPException(409,'Vault or card release changed')
        if (vault,collection)!=(self.native.scope.vaultLauncherId,self.native.scope.collectionId):
            return dto(s,vault,collection),None
        self.native.check_profile()
        old=self.store.by_release(self.native.release_id)
        def result(state,order=old,link=None):
            reauthenticate()
            paid=bool(order and CardInbox(s.payment_purchase_db_path).settlement(order.purchase_id))
            return dto(s,vault,collection,state,order,old is not None,paid),link
        if old:
            if click and (click.purchaseId,click.batchHash)!=(old.purchase_id,old.batch_hash):
                raise HTTPException(409,'Order differs from the current vault')
            terminal=card_status(request.app,s,old)
            if terminal:
                return result(terminal)
            if self.store.dispatch(old.purchase_id) and not old.session_id and not self.active_time():
                return result('REVIEW_REQUIRED')
            if int(self.clock())>=min(old.expires_at,old.session_expires_at or old.expires_at):
                if old.session_id:
                    return result('PROCESSING')
                return result('EXPIRED')
        if not self.native.scope.validFrom<=int(self.clock())<self.native.scope.expiresAt:
            return result('EXPIRED' if old else 'UNAVAILABLE')
        if not self.integrations():
            return result('UNAVAILABLE')
        evidence=await self.native.reconstruct(customers,snapshot)
        order=evidence.order
        if evidence.inventory.evidence.registry.state.pause_mask & 8:
            return result('PROCESSING' if old and self.store.dispatch(old.purchase_id) else 'UNAVAILABLE',old)
        if old and not same_original(old,order):
            return result('REVIEW_REQUIRED')
        if click and (click.purchaseId,click.batchHash)!=(order.purchase_id,order.batch_hash):
            raise HTTPException(409,'Approved order and displayed total differ')
        stage=await self.native.stage(evidence,customers.provider)
        if not self.active_time() and not (old and old.session_id):
            return result('UNAVAILABLE',order)
        if click and click.intent=='prepare':
            reauthenticate()
            if not old and stage!=('AVAILABLE',None):
                return result('UNAVAILABLE',order)
            if not old:
                old=self.store.save(order)
            await self.advance(request.app,customers,snapshot,old)
            return result('AWAITING_RESERVATION',old)
        if not old or stage[0]!='CONFIRMED':
            return result('AWAITING_RESERVATION',order)
        if not await current_card_coverage(request.app,s,old,now=int(self.clock())):
            if old.session_id or self.store.dispatch(old.purchase_id):
                return result('PROCESSING')
            return result('AWAITING_RESERVATION',old)
        if not click:
            if old.session_id or self.store.dispatch(old.purchase_id):
                if not old.session_id:
                    return result('PROCESSING')
                await self.provider.account()
                seen=checked_session(old,await self.provider.retrieve_session(old.session_id),expected_expiry=old.session_expires_at)
                return result({'open':'CHECKOUT_OPEN','expired':'EXPIRED','complete':'PROCESSING'}[seen['status']])
            account=await self.provider.account()
            return result('READY' if account.get('charges_enabled') is True else 'UNAVAILABLE')
        reauthenticate()
        if old.session_id:
            await self.provider.account()
            session=await self.provider.retrieve_session(old.session_id)
        else:
            if not self.active_time():
                return result('UNAVAILABLE')
            now=int(self.clock())
            params=self.store.begin_dispatch(old,session_params(old,s.generation_customer_public_origin,now),now=now)
            if params is None:
                old=self.store.get(old.purchase_id)
                await self.provider.account()
                session=await self.provider.retrieve_session(old.session_id)
            else:
                session=await self.provider.create_session(old,params)
            old=self.store.get(old.purchase_id)
        checked_session(old,session,expected_expiry=old.session_expires_at)
        old=self.store.bind_session(old.purchase_id,session['id'],session.get('payment_intent'))
        terminal=card_status(request.app,s,old)
        if terminal:
            return result(terminal,old)
        if session['status']=='open' and int(self.clock())<old.session_expires_at:
            return result('CHECKOUT_OPEN',old,session['url'])
        return result('EXPIRED' if session['status']=='expired' else 'PROCESSING',old)


def receipt(app,settings,order,state,requested=True):
    paid=bool(CardInbox(settings.payment_purchase_db_path).settlement(order.purchase_id))
    doc=dto(settings,order.vault_launcher_id,order.collection_id,state,order,requested,paid)
    if state=='DELIVERED':
        from .stripe_delivery_store import get_stripe_delivery_store
        op=get_stripe_delivery_store(settings.stripe_delivery_db_path).get(order.purchase_id)
        outputs=op.expected_deed_output_coin_ids
        if (not paid or not op.confirmation_height or len(set(outputs))!=len(outputs)
                or len(outputs)!=len(order.deed_launcher_ids)):
            raise ValueError('Incomplete confirmed delivery')
        doc['delivery']=dict(confirmationHeight=op.confirmation_height,deedOutputCoinIds=list(outputs))
    return doc


def historical(request,settings,vault,collection,purchase,owner):
    if not Path(settings.payment_purchase_db_path).is_file():
        raise HTTPException(404,'Vault card order unavailable')
    store=VaultCardStore(settings.payment_purchase_db_path)
    order=store.get(purchase)
    if (not order or (vault,collection,settings.network,settings.stripe_mode,settings.stripe_account_id,
                      settings.deployment_generation_id,owner.vault_record.auth_type,'0x'+bytes(owner.vault_record.owner_pubkey).hex())
            !=(order.vault_launcher_id,order.collection_id,order.network,order.mode,order.account_id,
               order.generation_id,order.owner_auth_type,order.owner_key)):
        raise HTTPException(404,'Vault card order unavailable')
    state=card_status(request.app,settings,order)
    if not state:
        if store.dispatch(purchase):
            state='PROCESSING'
        else:
            state='EXPIRED' if int(time.time())>=order.expires_at else 'UNAVAILABLE'
    return receipt(request.app,settings,order,state)


async def call(request,response,settings,vault,collection,click=None,purchase=None):
    response.headers.update(PRIVATE)
    try:
        owner=verify_vault_session(settings,request,vault)
        if click:
            if len(request.headers.getlist('origin'))!=1:
                raise HTTPException(403,'Card request origin differs')
            _origin(request,settings)
        service=getattr(request.app.state,'vault_card_checkout',None)
        if purchase is not None:
            document=historical(request,settings,vault,collection,purchase,owner)
            if document['paymentReceived'] or document['state'] in ('DELIVERED','REFUNDED','REVIEW_REQUIRED','EXPIRED'):
                return document
            if (not service or not settings.vault_card_checkout_enabled
                    or not (stored:=service.store.by_release(service.native.release_id)) or stored.purchase_id!=purchase):
                return document
        if service is None or not settings.vault_card_checkout_enabled:
            document,link=dto(settings,vault,collection),None
        else:
            customers,snapshot=owner_context(request,settings,vault)
            async with asyncio.timeout(150):
                async with service.lock:
                    document,link=await service.handle(request,vault,collection,click,customers,snapshot)
        if document['state']=='DELIVERED' and service:
            document=receipt(request.app,settings,service.store.get(document['purchaseId']),'DELIVERED')
        return dict(document,checkoutUrl=link) if click else document
    except HTTPException as exc:
        exc.headers={**(exc.headers or {}),**PRIVATE}
        raise
    except KNOWN_ERRORS as exc:
        LOG.warning('Vault card checkout unavailable (%s)',type(exc).__name__)
        raise HTTPException(503,'Current card order could not be verified',headers=PRIVATE) from None


@router.get('/{vault}/card/{collection}')
async def current_card(vault:Identity,collection:Identity,request:Request,response:Response,settings:Settings=Depends(get_settings),purchase:Hash|None=None):
    return await call(request,response,settings,vault,collection,purchase=purchase)


@router.post('/{vault}/card/{collection}/checkout')
async def open_card(vault:Identity,collection:Identity,body:CardClick,request:Request,response:Response,settings:Settings=Depends(get_settings)):
    return await call(request,response,settings,vault,collection,body)
