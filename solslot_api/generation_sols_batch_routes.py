"""Native offer receipts and explicit source-scoped testnet batch execution."""
import asyncio
import sqlite3
import time
from typing import Annotated
from fastapi import APIRouter,Depends,HTTPException,Path,Request,Header
from pydantic import Field
from chia.wallet.trading.offer import Offer
from chia_rs.sized_bytes import bytes32
from .admin_auth import require_admin_jwt
from .config import get_settings,Settings
from .generation_execution import Model,Hash
from .generation_sols_batch_execution import PrimaryBatchClaim,PrimaryBatchSelection,BatchBuyer,resolve_batch,unspent
from .generation_sols_batch_validators import collect_primary_batch
from .generation_sols_batches import external_inputs,parse_signed_order,verify_order_signature
from .generation_operations import submit_saved_operation
from .protocol_submission import ProtocolSubmissionError
from .generation_sols_policy import require_order_policy,REVIEWED_FEES

router=APIRouter(tags=['generation-sols-batches'])
Identity=Annotated[str,Path(pattern=r'^0x[0-9a-f]{64}$')]


def runtime(request,settings):
    book=getattr(request.app.state,'generation_sols_orders',None)
    if (settings.network!='testnet11' or not settings.generation_sols_batch_enabled or book is None
            or book.generation_id!=settings.deployment_generation_id):
        raise HTTPException(503,detail={'code':'SOLS_BATCH_NOT_READY','message':'Batch ordering is waiting for the verified testnet generation.'})
    return book


def public_error(exc):
    if isinstance(exc,ValueError):
        code=str(exc) if str(exc).isupper() and len(str(exc))<80 else 'SOLS_OFFER_REVIEW_CHANGED'
        if code in ('SOLS_FEE_POLICY_UNAVAILABLE','SOLS_FEE_POLICY_REVIEW_REQUIRED'):
            return HTTPException(503,detail={'code':code,'message':'New orders are waiting for a fresh review of the offering fee. Keep your saved offer and receipt; its signed terms will not change.'})
        return HTTPException(409,detail={'code':code,'message':'The offer or current settlement inputs need another review. Your original offer is retained.'})
    return HTTPException(503,detail={'code':'SOLS_BATCH_STATUS_UNAVAILABLE','message':'Status is temporarily unavailable. Keep your original offer and receipt; retry to recover saved progress.'})


@router.get('/sols/batches/status')
def batch_capability(request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=getattr(request.app.state,'generation_sols_orders',None)
    catalog=book.catalog() if book else None
    try:
        require_order_policy(book)
        fresh=bool(catalog.get('ready'))
    except (ValueError,AttributeError):fresh=False
    return {'generationId':settings.deployment_generation_id,'network':'testnet11','purpose':'TEST_ONLY',
        'enabled':bool(settings.network=='testnet11' and settings.generation_sols_batch_enabled and fresh
            and book.generation_id==settings.deployment_generation_id),
        'solsAssetId':'0x'+book.sols_asset.hex() if book else None,'catalog':catalog,
        'solsDecimals':3,'pollAfterSeconds':30,'identityRequiredForSols':False,'identityRequiredForSmartDeed':True,
        **REVIEWED_FEES}


class ReviewOffer(Model):
    generation_id:Hash=Field(alias='generationId')
    offer:str=Field(min_length=10,max_length=2_000_000)


@router.post('/sols/batches/review')
async def review_offer(body:ReviewOffer,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings);provider=getattr(request.app.state,'coinset',None)
    if body.generation_id!=book.generation_id:raise HTTPException(409,detail={'code':'SOLS_ORDER_GENERATION_CHANGED'})
    if provider is None:raise HTTPException(503,detail={'code':'SOLS_PRIMARY_NODE_UNAVAILABLE'})
    try:
        fees=require_order_policy(book)
        from chia.util.bech32m import encode_puzzle_hash
        from solslot_puzzles.generation_batch_orders import inspect_buyer_offer
        from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
        async with asyncio.timeout(20):
            offer=parse_signed_order(body.offer)
            requested=offer.requested_payments.get(book.sols_asset)
            if not requested or len(requested)!=1:raise ValueError('SOLS_OFFER_ASSET_CHANGED')
            offered=offer.get_offered_amounts()
            if len(offered)!=1:raise ValueError('SOLS_OFFER_PAYMENT_CHANGED')
            asset=next(iter(offered));destination=requested[0].puzzle_hash
            order=inspect_buyer_offer(offer,generation=book.generation,sols_asset=book.sols_asset,
                sols_driver=chia_cat_driver(book.sols_asset),payment_asset=asset,
                destination_inner_hash=destination,approved_payment_assets=book.approved_assets)
            verify_order_signature(offer)
            if (await provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('SOLS_NETWORK_CHANGED')
            for coin in external_inputs(offer):await unspent(provider,coin)
            return {'generationId':book.generation_id,'orderId':'0x'+order.order_id.hex(),
                'paymentAsset':'0x'+asset.hex() if asset else None,'paymentAmount':str(order.payment_amount),
                'solsAmount':str(order.sols_amount),'destination':'0x'+destination.hex(),
                'destinationAddress':encode_puzzle_hash(destination,'txch'),**fees,'identityRequired':False}
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise public_error(exc) from exc


class PlaceOffer(Model):
    generation_id:Hash=Field(alias='generationId')
    offer:str=Field(min_length=10,max_length=2_000_000)
    destination:Hash
    payment_asset:Hash|None=Field(default=None,alias='paymentAsset')
    receipt_key:Hash=Field(alias='receiptKey')


@router.post('/sols/batches/orders')
async def place_offer(body:PlaceOffer,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings);provider=getattr(request.app.state,'coinset',None)
    if body.generation_id!=book.generation_id:raise HTTPException(409,detail={'code':'SOLS_ORDER_GENERATION_CHANGED'})
    if provider is None:raise HTTPException(503,detail={'code':'SOLS_PRIMARY_NODE_UNAVAILABLE'})
    try:
        async with asyncio.timeout(20):
            offer=parse_signed_order(body.offer)
            existing=book.existing_receipt(offer,body.receipt_key)
            if existing:return existing
            require_order_policy(book)
            if (await provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('SOLS_NETWORK_CHANGED')
            from solslot_puzzles.generation_batch_orders import inspect_buyer_offer
            from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
            inspect_buyer_offer(offer,generation=book.generation,sols_asset=book.sols_asset,sols_driver=chia_cat_driver(book.sols_asset),
                payment_asset=bytes32.from_hexstr(body.payment_asset) if body.payment_asset else None,
                destination_inner_hash=bytes32.from_hexstr(body.destination),approved_payment_assets=book.approved_assets)
            verify_order_signature(offer)
            for coin in external_inputs(offer):await unspent(provider,coin)
            return book.place(offer,payment_asset=bytes32.from_hexstr(body.payment_asset) if body.payment_asset else None,
                destination=bytes32.from_hexstr(body.destination),now=int(time.time()),receipt_key=body.receipt_key)
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise public_error(exc) from exc


@router.get('/sols/batches/orders/{identity}')
def order_status(identity:Identity,request:Request,settings:Annotated[Settings,Depends(get_settings)],
    receipt_key:Annotated[str,Header(alias='X-Solslot-Order-Receipt',pattern=r'^0x[0-9a-f]{64}$')]):
    book=runtime(request,settings)
    try:
        book.authorize_receipt(identity,receipt_key)
        return book.status(identity)
    except ValueError as exc:raise HTTPException(404,detail={'code':'SOLS_ORDER_NOT_FOUND'}) from exc


class RemoveOffer(Model):
    generation_id:Hash=Field(alias='generationId')
    receipt_key:Hash=Field(alias='receiptKey')


@router.post('/sols/batches/orders/{identity}/remove')
def remove_offer(body:RemoveOffer,identity:Identity,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings)
    if body.generation_id!=book.generation_id:raise HTTPException(409,detail={'code':'SOLS_ORDER_GENERATION_CHANGED'})
    try:return book.remove_from_matching(identity,receipt_key=body.receipt_key)
    except ValueError as exc:raise public_error(exc) from exc


@router.get('/admin/generation/sols-batches/orders',dependencies=[Depends(require_admin_jwt)])
def waiting_orders(request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings)
    journal=getattr(request.app.state,'generation_operations',None)
    return {'generationId':book.generation_id,'orders':book.waiting(512),'catalog':book.catalog(),
        'operations':[row for row in journal.recent(50) if row['kind']=='PRIMARY_SOLS_BATCH'] if journal else []}


class PrepareBatch(Model):
    generation_id:Hash=Field(alias='generationId')
    order_ids:tuple[Hash,...]=Field(alias='orderIds',min_length=1,max_length=32)
    claim:PrimaryBatchSelection
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)


@router.post('/admin/generation/sols-batches/prepare',dependencies=[Depends(require_admin_jwt)])
async def prepare_batch(body:PrepareBatch,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings);journal=getattr(request.app.state,'generation_operations',None)
    index=getattr(request.app.state,'generation_index',None)
    if journal is None or index is None:raise HTTPException(503,detail={'code':'SOLS_BATCH_AUTHORITIES_NOT_READY'})
    if body.generation_id!=book.generation_id or body.claim.generation_id!=book.generation_id:
        raise HTTPException(409,detail={'code':'SOLS_ORDER_GENERATION_CHANGED'})
    try:
        async with request.app.state.generation_sols_guard,asyncio.timeout(90):
            saved=book.linked_operation(body.order_ids,journal)
            if saved:
                if int(saved['feeCapMojos'])!=body.fee_cap_mojos:raise ValueError('SAVED_SETTLEMENT_FEE_CHANGED')
                return saved
            buyers=[]
            for identity in body.order_ids:
                row=book.status(identity)
                if row['stage']!='WAITING_FOR_MATCH':raise ValueError('ORDER_NOT_AVAILABLE_FOR_MATCHING')
                buyers.append(BatchBuyer(offer=book.original(identity).to_bech32(),destination=row['destinationInnerHash'],paymentAsset=row['paymentAsset']))
            claim=body.claim.with_buyers(buyers)
            prepared,evidence=await resolve_batch(claim,settings=settings,anchor=index.anchor,provider=request.app.state.coinset)
            prepared=await collect_primary_batch(settings,claim,prepared)
            from .generation_chain_evidence import current_evidence_unchanged
            if not await current_evidence_unchanged(evidence,provider=request.app.state.coinset):raise ValueError('BATCH_AUTHORITIES_CHANGED')
            children={coin.name() for coin in prepared.bundle.additions()}
            for coin in prepared.bundle.removals():
                if coin.name() not in children:await unspent(request.app.state.coinset,coin)
            if int(time.time())>=claim.expires_at:raise ValueError('BATCH_PRICE_REVIEW_EXPIRED')
            pool=next(h for h in evidence.economic_components.values() if h.state.__class__.__name__=='GenerationPool')
            statutes=next(h for h in evidence.economic_components.values() if h.state.__class__.__name__=='GenerationStatutes')
            return book.retain_settlement(prepared,journal=journal,pool_tip=pool,statutes_tip=statutes,
                registry_tip=evidence.registry,fee_cap=body.fee_cap_mojos,now=int(time.time()))
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise public_error(exc) from exc


class ExecuteBatch(Model):
    generation_id:Hash=Field(alias='generationId')
    operation_id:Hash=Field(alias='operationId')
    intent_hash:Hash=Field(alias='intentHash')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)


@router.post('/admin/generation/sols-batches/submit',dependencies=[Depends(require_admin_jwt)])
async def submit_batch(body:ExecuteBatch,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings);journal=getattr(request.app.state,'generation_operations',None)
    submitter=getattr(request.app.state,'protocol_submitter',None)
    if journal is None or submitter is None or not settings.generation_execution_enabled:
        raise HTTPException(503,detail={'code':'SOLS_BATCH_EXECUTION_NOT_ENABLED'})
    try:
        async with request.app.state.generation_sols_guard:
            saved=journal.status(body.operation_id)
            if (body.generation_id!=book.generation_id or saved['kind']!='PRIMARY_SOLS_BATCH'
                    or saved['intentHash']!=body.intent_hash or int(saved['feeCapMojos'])!=body.fee_cap_mojos):
                raise ValueError('SAVED_SETTLEMENT_REVIEW_CHANGED')
            book.repair_saved_links(journal)
            if any(book.status(identity)['operationId']!=body.operation_id for identity in saved['review']['orderIds']):
                raise ValueError('SAVED_ORDER_LINK_CHANGED')
            return await submit_saved_operation(journal,body.operation_id,submitter,clock=time.time)
    except ProtocolSubmissionError as exc:
        raise HTTPException(503,detail={'code':exc.code,'operation':journal.status(body.operation_id),
            'message':'The exact saved settlement needs reconciliation. Do not replace the offers or transaction.'}) from exc
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise public_error(exc) from exc


@router.post('/admin/generation/sols-batches/release-expired',dependencies=[Depends(require_admin_jwt)])
async def release_expired_batch(body:ExecuteBatch,request:Request,settings:Annotated[Settings,Depends(get_settings)]):
    book=runtime(request,settings);journal=getattr(request.app.state,'generation_operations',None)
    submitter=getattr(request.app.state,'protocol_submitter',None)
    if journal is None or submitter is None:raise HTTPException(503,detail={'code':'SOLS_BATCH_AUTHORITIES_NOT_READY'})
    try:
        async with request.app.state.generation_sols_guard,asyncio.timeout(60):
            saved=journal.status(body.operation_id)
            if (body.generation_id!=book.generation_id or saved['kind']!='PRIMARY_SOLS_BATCH'
                    or saved['intentHash']!=body.intent_hash or int(saved['feeCapMojos'])!=body.fee_cap_mojos):
                raise ValueError('SAVED_SETTLEMENT_REVIEW_CHANGED')
            from .generation_sols_batch_recovery import release_batch_quote
            return await release_batch_quote(book,journal,body.operation_id,submitter,clock=time.time)
    except ProtocolSubmissionError as exc:
        raise HTTPException(409,detail={'code':'SOLS_EXPIRY_NOT_RECONCILED',
            'message':'The primary node has not proven this saved settlement can be released. Its original transaction and offers are retained.'}) from exc
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise public_error(exc) from exc
