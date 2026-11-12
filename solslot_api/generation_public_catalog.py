"""Read-only projection of independently reviewed, confirmed public test editions.

No preview constants, private draft serialization, transaction preparation or
automatic sale opening. A confirmed mint and an executable sale are separate.
"""
import time
import sqlite3
import asyncio
from solslot_puzzles.property_metadata import commit_metadata

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from .config import Settings, get_settings
from .collection_store import CollectionStoreError
from .collection_endpoints import get_collection_store
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy

router = APIRouter(prefix='/public/generation', tags=['public-generation-catalog'])


def confirmed_catalog_entry(identifier, *, collections, reviews, journal, generation):
    source = reviews.for_collection(identifier)
    if not source or source['generationId'] != generation:
        raise ValueError('source generation differs')
    result = reviews.inventory_status(source['packageId'])
    receipt = result['receipt']
    if not receipt:
        return None
    operation = journal.status(receipt['operationId'])
    if (operation['stage'] != 'CONFIRMED' or operation['kind'] != 'MINT_COLLECTION'
            or operation['generationId'] != generation
            or operation['review']['sourceReviewId'] != source['packageId']
            or operation['transactionId'] != receipt['transactionId']
            or operation['confirmedHeight'] != receipt['confirmedHeight']):
        raise ValueError('mint confirmation differs')
    sealed = collections.sealed_test_mint_snapshot(identifier)
    metadata = sealed['canonicalMetadata']
    root = '0x' + commit_metadata(metadata).metadata_root.hex()
    if (metadata.get('collectionId') != identifier or metadata.get('purpose') != 'TEST_ONLY' or metadata.get('network') != 'testnet11'
            or metadata.get('generationId') != generation
            or root != sealed['metadataRoot'] or root != receipt['metadataRoot']
            or source['request']['metadataRoot'] != root
            or metadata['revision'] != source['request']['revision']
            or receipt['deedCount'] != len(metadata['deedAllocation'])):
        raise ValueError('public sealed edition differs')
    # Only the canonical investor-visible edition and verified issuance evidence.
    # Do not return the admin workspace, uploaded originals, notes, wallet slots,
    # signing challenges, retained funding parents or private asset descriptors.
    return {'collectionId': identifier, 'revision': metadata['revision'],
        'metadataRoot': root, 'canonicalMetadata': metadata,
        'mint': {key: receipt[key] for key in ('transactionId', 'confirmedHeight',
            'deedCount', 'editionHash', 'inventory')},
        'sale': {'status': 'UNAVAILABLE', 'availableDeeds': None,
            'code': 'PRIMARY_OFFERING_STATUS_UNAVAILABLE', 'reason': 'Mint confirmation is verified. Purchase availability could not be checked for this edition.'}}


def _bound_context(request: Request, settings: Settings):
    reviews = getattr(request.app.state, 'generation_mint_reviews', None)
    journal = getattr(request.app.state, 'generation_operations', None)
    index = getattr(request.app.state, 'generation_index', None)
    generation = settings.deployment_generation_id
    if (settings.network != 'testnet11' or not generation or reviews is None
            or journal is None or index is None
            or reviews.generation_id != generation or journal.generation_id != generation):
        raise HTTPException(503, detail={'code': 'PUBLIC_GENERATION_NOT_READY'})
    return reviews, journal, index, generation


async def _collection_sale(service, pricing, fixed):
    inventory = await service.inventory_snapshot()
    execution = await service.collection_readiness(inventory)
    count = sum(item.available for item in inventory.items)
    status = 'UNAVAILABLE'
    code = 'PRIMARY_OFFERING_STATUS_UNAVAILABLE'
    reason = 'Purchase availability could not be checked for this edition.'
    if execution['status'] == 'PAUSED' or count == 0:
        status = 'NOT_OPEN'
        code = 'CURRENT_PRIMARY_SALE_NOT_OPEN'
        reason = 'Purchases are currently unavailable for this edition.'
    elif execution['status'] == 'READY':
        if fixed:
            from .generation_customer_test_conversion import status as conversion_status
            price = conversion_status(service.policy, now=int(service.clock()))
        else:
            price = await pricing.status()
        if price['price']['canQuote'] or price['price']['canRefresh']:
            status = 'OPEN'
            code = 'CURRENT_PRIMARY_SALE_OPEN'
            reason = 'Available on Chia Testnet11 with a verified Chia vault.'
    checked = int(time.time())
    return {
        'checkedAt': checked,
        'generationId': service.store.generation_id,
        'editionHash': '0x' + inventory.edition.hex(),
        'metadataRoot': '0x' + inventory.metadata_root.hex(),
        'sale': {
            'schema': 'solslot.current-primary-sale.v2',
            'status': status,
            'availableDeeds': count,
            'code': code,
            'reason': reason,
            'paymentRails': ['CHIA_XCH'] if status == 'OPEN' else [],
            'checkedAt': checked,
        },
    }


async def _catalog_settings(request: Request, settings: Settings = Depends(get_settings)):
    # Reject an unbound feed before opening a store or resolving native state.
    _bound_context(request, settings)
    request.state.current_sale=None
    service=getattr(request.app.state,'generation_customer_purchase',None)
    worker=getattr(request.app.state,'generation_customer_purchase_worker',None)
    pricing=getattr(request.app.state,'generation_price_demand',None)
    fixed=getattr(getattr(service,'policy',None),'test_usd_minor_per_txch',None)is not None
    if service is not None and worker is not None and worker.service is service and (pricing is not None or fixed):
        # This read-only projection never requests prices or invokes a signer.
        # Cache only recent independently reconstructed inventory and private
        # readiness, with one in-flight refresh per application process.
        lock=getattr(request.app.state,'current_sale_lock',None)
        if lock is None:
            lock=asyncio.Lock();request.app.state.current_sale_lock=lock
        try:
            async with asyncio.timeout(25):
                async with lock:
                    now=int(time.time());cached=getattr(request.app.state,'current_sale_projection',None)
                    if isinstance(getattr(service, 'policy', None), TestnetCollectionIssuerPolicy):
                        if cached is None or not 0 <= now - cached['checkedAt'] < 5:
                            cached = await _collection_sale(service, pricing, fixed)
                            request.app.state.current_sale_projection = cached
                        request.state.current_sale = cached
                        return settings
                    if cached is None or cached['checkedAt']+30<=now:
                        service._funding_context()
                        inventory=await service.inventory()
                        issuer=await worker.issuer_sign.status(service.policy,now=int(time.time()))
                        if fixed:
                            from .generation_customer_test_conversion import status
                            price=status(service.policy,now=int(time.time()))
                        else:price=await pricing.status()
                        count=sum(i['status']=='AVAILABLE'and i['withinTestPolicy']for i in inventory['items'])
                        health=worker.health()
                        opened=(health is not None and health['status']=='HEALTHY'
                            and inventory['purchaseWindowOpen']and issuer['canSign']and count>0
                            and (price['price']['canQuote']or price['price']['canRefresh']))
                        cached={'checkedAt':int(time.time()),'generationId':service.store.generation_id,
                            'editionHash':inventory['editionHash'],'metadataRoot':inventory['metadataRoot'],
                            'sale':{'status':'OPEN'if opened else'NOT_OPEN','availableDeeds':count,
                            'code':'LIMITED_TEST_PURCHASES_OPEN'if opened else'LIMITED_TEST_WINDOW_NOT_OPEN',
                            'reason':'Limited Testnet purchase window. A verified receiving vault and fresh quote are required.'if opened else'The finite test purchase window is not currently ready.',
                            'limitedTest':True,'paymentRails':['CHIA_XCH']if opened else[],
                            'checkedAt':int(time.time()),'expiresAt':service.policy.expires_at}}
                        request.app.state.current_sale_projection=cached
                    request.state.current_sale=cached
        except Exception:
            # An outage is unknown availability, never an empty inventory or
            # permission to buy. Keep the confirmed mint visible.
            request.state.current_sale=None
    return settings


@router.get('/collections')
def public_catalog(request: Request, response: Response,
                   settings: Settings = Depends(_catalog_settings),
                   collections = Depends(get_collection_store)):
    reviews, journal, index, generation = _bound_context(request, settings)
    try:
        status = index.store.status(int(time.time()), verified_in_process=index.verified)
        if status['status'] != 'READY' or status['generationId'] != generation:
            raise ValueError('current generation evidence unavailable')
        # The existing store dependency resolves native authority on the event
        # loop and passes only plain values into this synchronous read worker.
        entries = [confirmed_catalog_entry(identity, collections=collections, reviews=reviews,
            journal=journal, generation=generation) for identity in reviews.confirmed_collection_ids()]
        sale=getattr(request.state,'current_sale',None)
        if sale is not None and sale['generationId']==generation and int(time.time())-sale['checkedAt']<=30:
            for entry in entries:
                if entry is not None and entry['mint']['editionHash']==sale['editionHash']and entry['metadataRoot']==sale['metadataRoot']:
                    entry['sale']=sale['sale']
        response.headers['Cache-Control'] = 'public, max-age=5, must-revalidate'
        return {'schemaVersion': 1, 'generationId': generation, 'network': 'testnet11',
            'status': 'READY', 'lastCheckedAt': status['lastCheckedAt'], 'pollAfterSeconds': 30,
            'collections': [entry for entry in entries if entry is not None]}
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error, CollectionStoreError) as exc:
        # An unavailable or inconsistent feed is never an authoritative empty
        # catalog, a mock preview, a zero balance or permission to buy.
        raise HTTPException(503, detail={'code': 'PUBLIC_GENERATION_EVIDENCE_UNAVAILABLE'}) from exc
