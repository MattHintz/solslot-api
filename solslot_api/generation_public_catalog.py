"""Read-only projection of independently reviewed, confirmed public test editions.

No preview constants, private draft serialization, transaction preparation or
automatic sale opening. A confirmed mint and an executable sale are separate.
"""
import time
import sqlite3
from solslot_puzzles.property_metadata import commit_metadata

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from .config import Settings, get_settings
from .collection_store import CollectionStoreError
from .collection_endpoints import get_collection_store

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


async def _catalog_settings(request: Request, settings: Settings = Depends(get_settings)):
    # Reject an unbound feed before opening a store or resolving native state.
    _bound_context(request, settings)
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
        response.headers['Cache-Control'] = 'public, max-age=5, must-revalidate'
        return {'schemaVersion': 1, 'generationId': generation, 'network': 'testnet11',
            'status': 'READY', 'lastCheckedAt': status['lastCheckedAt'], 'pollAfterSeconds': 30,
            'collections': [entry for entry in entries if entry is not None]}
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error, CollectionStoreError) as exc:
        # An unavailable or inconsistent feed is never an authoritative empty
        # catalog, a mock preview, a zero balance or permission to buy.
        raise HTTPException(503, detail={'code': 'PUBLIC_GENERATION_EVIDENCE_UNAVAILABLE'}) from exc
