"""Current-generation private dashboard route, under the owner cookie path."""
import asyncio
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from .config import Settings, get_settings
from .credential_auth import verify_vault_session
from .generation_customer_routes import Identity, _runtime
from .generation_customer_portfolio import read_current_portfolio, h
from .generation_public_catalog import confirmed_catalog_entry
from .collection_endpoints import get_collection_store
from .collection_store import CollectionStoreError

router = APIRouter(prefix='/customer/vaults', tags=['current-customer-portfolio'])


async def _owner_context(launcher: Identity, request: Request, settings: Settings = Depends(get_settings)):
    # Authenticate before opening metadata stores or making network calls.
    owner = verify_vault_session(settings, request, launcher)
    runtime = _runtime(request, settings)
    try:
        snapshot = runtime.current_vault_snapshot(launcher)
        if (snapshot['owner'].lower() != owner.owner_key.lower()
                or snapshot['authType'] != owner.auth_type):
            raise HTTPException(403, detail={'code': 'CURRENT_PORTFOLIO_OWNER_CHANGED'})
        return runtime, snapshot
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        raise HTTPException(503, detail={'code': 'CURRENT_PORTFOLIO_UNAVAILABLE',
            'message': 'Your vault is saved. Current holdings could not be checked.'}) from exc


async def _portfolio_settings(context=Depends(_owner_context), settings: Settings = Depends(get_settings)):
    return settings


@router.get('/{launcher}/journey')
async def current_portfolio(launcher: Identity, request: Request, response: Response,
        context=Depends(_owner_context), settings: Settings = Depends(_portfolio_settings),
        collections=Depends(get_collection_store)):
    response.headers['Cache-Control'] = 'no-store'
    runtime, snapshot = context
    index, evidence = runtime.index, runtime.index.evidence
    reviews = getattr(request.app.state, 'generation_mint_reviews', None)
    journal = getattr(request.app.state, 'generation_operations', None)

    def metadata(edition):
        if (reviews is None or journal is None or reviews.generation_id != snapshot['generationId']
                or journal.generation_id != snapshot['generationId']):
            raise ValueError('portfolio public metadata authority is unavailable')
        found = []
        for identifier in reviews.confirmed_collection_ids():
            entry = confirmed_catalog_entry(identifier, collections=collections, reviews=reviews,
                journal=journal, generation=snapshot['generationId'])
            if (entry and entry['mint']['editionHash'] == h(edition.commitment)
                    and entry['metadataRoot'] == h(edition.metadata_root)):
                found.append(entry['canonicalMetadata'])
        if len(found) != 1:
            raise ValueError('portfolio requires one sealed public edition')
        return found[0]

    try:
        async with asyncio.timeout(15):
            result = await read_current_portfolio(snapshot=snapshot, evidence=evidence,
                sgt_bindings=index.anchor.issuance.bindings(), provider=runtime.provider,
                metadata_for_edition=metadata)
        # Long reads cannot outlive native authority freshness or a wallet's
        # observed custody. This getter never refreshes a session or signs.
        latest = runtime.current_vault_snapshot(launcher)
        if (latest['vault'] != snapshot['vault'] or latest['owner'] != snapshot['owner']
                or latest['generationId'] != snapshot['generationId']):
            raise ValueError('portfolio owner or native custody changed during read')
        return result
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, TimeoutError,
            sqlite3.Error, CollectionStoreError) as exc:
        raise HTTPException(503, detail={'code': 'CURRENT_PORTFOLIO_UNAVAILABLE',
            'message': 'Your vault and saved verification are preserved. Holdings could not be checked.'},
            headers={'Cache-Control': 'no-store', 'Retry-After': '30'}) from exc
