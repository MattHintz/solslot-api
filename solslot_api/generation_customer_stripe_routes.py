"""Authenticated discovery for the single privately provisioned Stripe test order."""
import asyncio
import re
import sqlite3
from typing import Annotated

from solslot_puzzles.payment_artifacts_v3 import purchase_batch_to_json
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from .config import Settings, get_settings
from .generation_customer_portfolio_routes import _owner_context
from .generation_customer_routes import Identity
from .generation_customer_stripe_order import CurrentStripeOrder, StripeOrderReview, h
from .payment_purchase_store import PaymentPurchaseNotFound


router = APIRouter(prefix='/customer/purchases', tags=['current-private-stripe-order'])
PRIVATE = {'Cache-Control':'private, no-store'}


def _enabled_test_payment(settings):
    return (settings.network == 'testnet11' and settings.stripe_mode == 'test'
            and settings.stripe_settlement_enabled is True and settings.stripe_delivery_worker_enabled is True
            and settings.protocol_fee_funding_enabled is True and bool(settings.stripe_account_id))


def _available_handoff(handoff, native, settings, now):
    allowed = {'releaseId','readinessId','checkedAt','validUntil','providerAccount','publishableKey',
               'mode','purchaseIntent','authorization'}
    if not isinstance(handoff, dict) or set(handoff) != allowed:
        return False
    auth, intent = handoff['authorization'], handoff['purchaseIntent']
    if not isinstance(auth,dict) or not isinstance(intent,dict):
        return False
    expected = {'protocolVersion':'solslot-v2', 'network':'testnet11', 'purchaseId':native.purchase_id,
        'purchaseArtifactHash':native.batch_hash, 'offerArtifactHash':native.offer_artifact_hash,
        'genesisArtifactHash':native.genesis_artifact_hash, 'purchaseIntentId':native.purchase_intent_id,
        'vaultLauncherId':native.vault_launcher_id,
        'vaultP2PuzzleHash':native.destination_puzzle_hash, 'currentVaultCoinId':native.vault_coin_id,
        'identityAttestRoot':native.credential_root,'purchaseArtifact':purchase_batch_to_json(native.batch)}
    if any(auth.get(key) != value for key,value in expected.items()):
        return False
    return (intent.get('id') == native.purchase_intent_id and intent.get('rail') == 'stripe'
            and intent.get('vaultLauncherId') == native.vault_launcher_id and intent.get('quantity') == 2
            and intent.get('zkPassportRequired') is True and intent.get('artifactHash') == native.offer_artifact_hash
            and handoff['releaseId'] == native.release_id and isinstance(handoff['readinessId'], str)
            and re.fullmatch(r'0x[0-9a-f]{64}', handoff['readinessId']) and int(handoff['readinessId'],16) > 0
            and type(handoff['checkedAt']) is int and type(handoff['validUntil']) is int
            and handoff['checkedAt'] <= now < handoff['validUntil'] <= min(handoff['checkedAt']+30,native.expires_at)
            and handoff['mode'] == 'test' and handoff['providerAccount'] == settings.stripe_account_id
            and isinstance(handoff['publishableKey'], str) and re.fullmatch(r'pk_test_[A-Za-z0-9]+',handoff['publishableKey'])
            )


async def current_stripe_order(request, settings, vault: str, collection: str, *, require_ready: bool = False):
    try:
        # Existing vault JWT, registered owner and fresh in-process custody observation.
        customers, snapshot = await _owner_context(vault, request, settings)
        service = getattr(request.app.state,'generation_customer_stripe_order',None)
        if not isinstance(service,CurrentStripeOrder) or service.settings is not settings:
            raise HTTPException(503, 'Private Stripe checkout unavailable.')
        if vault != h(service.scope.vault) or collection != h(service.scope.collection):
            raise HTTPException(404, 'Private Stripe order unavailable.')
        async with asyncio.timeout(40):
            review = await service.review(customers,snapshot)
            native = review.native
            handoff = None
            adapter = getattr(request.app.state,'generation_customer_stripe_handoff',None)
            if native is not None and adapter is not None and _enabled_test_payment(settings):
                handoff = await adapter.review(native,now=int(service.clock()))
            # Reauthenticate after node and provider I/O. Expired or switched sessions cannot act.
            latest_customers, latest = await _owner_context(vault,request,settings)
            if (getattr(request.app.state,'generation_customer_stripe_order',None) is not service
                    or getattr(request.app.state,'generation_customer_stripe_handoff',None) is not adapter):
                raise HTTPException(503,'Private Stripe service changed during review.')
            if latest_customers is not customers or any(latest[key] != snapshot[key] for key in
                    ('vault','owner','ownerPublicKey','authType','registrationId','generationId','p2VaultPuzzleHash')):
                raise HTTPException(403,'Current vault ownership changed.')
            if (native is not None and _enabled_test_payment(settings)
                    and _available_handoff(handoff,native,settings,int(service.clock()))):
                doc = dict(review.document,state='READY_FOR_STRIPE',validUntil=handoff['validUntil'],handoff=handoff)
                return StripeOrderReview(doc,native)
            if require_ready:
                raise HTTPException(409,'The original Stripe order is not ready for payment.')
            return review
    except HTTPException as exc:
        exc.headers = {**(exc.headers or {}), **PRIVATE}
        raise
    except PaymentPurchaseNotFound:
        raise HTTPException(404, 'Private Stripe order unavailable.', headers=PRIVATE) from None
    except (ValueError, KeyError, TypeError, RuntimeError, OSError, TimeoutError, sqlite3.Error):
        raise HTTPException(503,'The original order and current custody could not be verified.',headers=PRIVATE) from None


async def current_stripe_native_again(app, settings, expectedPurchaseId, *, now):
    """Internal proof refresh for service-authenticated consumption of an existing owner claim."""
    service = getattr(app.state,'generation_customer_stripe_order',None)
    customers = getattr(app.state,'generation_customers',None)
    if (not isinstance(service,CurrentStripeOrder) or service.settings is not settings or customers is None
            or not _enabled_test_payment(settings) or h(service.scope.purchase_id) != expectedPurchaseId or type(now) is not int
            or not 0 <= int(service.clock()) - now < 30):
        raise ValueError('Exact private Stripe order required')
    launcher = h(service.scope.vault)
    snapshot = customers.current_vault_snapshot(launcher)
    async with asyncio.timeout(40):
        review = await service.review(customers,snapshot)
    latest = customers.current_vault_snapshot(launcher)
    if (review.native is None or not _enabled_test_payment(settings)
            or getattr(app.state,'generation_customer_stripe_order',None) is not service
            or getattr(app.state,'generation_customers',None) is not customers
            or any(latest[key] != snapshot[key] for key in
            ('vault','owner','ownerPublicKey','authType','registrationId','generationId','p2VaultPuzzleHash'))
            or not now <= int(service.clock()) < min(now + 30,review.native.expires_at)):
        raise ValueError('Current native Stripe confirmation required')
    return review.native


@router.get('/{vault}/stripe/{collection}')
async def stripe_order(vault: Identity, collection: Identity, request: Request, response: Response,
                       settings: Annotated[Settings, Depends(get_settings)]):
    response.headers.update(PRIVATE)
    return (await current_stripe_order(request,settings,vault,collection)).document
