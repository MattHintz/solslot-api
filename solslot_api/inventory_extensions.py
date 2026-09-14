"""Durable current-protocol payment holds; no payment retry or fulfillment authority."""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict

from chia_rs import SpendBundle
from solslot_puzzles.stripe_settlement_v1_driver import (
    build_inventory_extension_spend, MAX_RESERVATION_EXTENSION_SECONDS,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from .inventory_extension_claims import (
    InventoryExtensionClaim, extension_activation, RENEWAL_WINDOW_SECONDS, ACH_REVIEW_SECONDS,
)
from .inventory_extension_chain import (
    current_position, inspect_position, observe_extension, validate_execution,
)
from .inventory_recovery import hx, release_peak
from .inventory_timeout_submission import canonical_time
from .payment_purchase_store import PaymentPurchaseConflict
from .validator_inventory_extension import require_timely_extension
from .validator_quorum import collect_inventory_extension_quorum


def hold_status(stored, operations, *, now):
    if not operations:
        return None
    first, latest = operations[0], operations[-1]
    claim = InventoryExtensionClaim.model_validate(latest['claim'])
    original = InventoryExtensionClaim.model_validate(first['claim'])
    expiry = claim.next_expires_at if latest['state'] == 'CONFIRMED' else claim.reservation_expires_at
    review = (latest.get('lastError') is not None or now >= expiry or (original.payment_method == 'us_bank_account'
        and now - original.payment_started_at >= ACH_REVIEW_SECONDS))
    return dict(state='REVIEW_REQUIRED' if review else 'PAYMENT_HELD',
        extensionState=latest['state'], currentExpiresAt=expiry,
        currentReservedCoinId=(latest['confirmation']['reservedCoinId']
            if latest['state'] == 'CONFIRMED' else claim.reserved_coin_id),
        transactionId=latest['prepared']['spendBundleId'] if latest['prepared'] else None,
        lastError=latest.get('lastError'),
        extensionCount=len(getattr(stored, 'inventory_extension_receipts', ())),
        inventoryReusable=False, paymentRetryAllowed=False)


async def advance_extension(*, store, node, submitter, settings, presales, purchase_id,
                            payment, load_artifact, authorize, observe_only=False):
    """Exact claim before quorum, signed bytes before funding, funded bytes before push."""
    artifact = load_artifact()
    active = extension_activation(artifact, settings.runtime_environment + '-alpha')
    if settings.network != 'testnet11':
        raise PaymentPurchaseConflict('extension requires the isolated testnet11 deployment')
    stored = store.get(purchase_id)
    position = current_position(stored, store.inventory_items(purchase_id), artifact)
    operations = store.inventory_extension_operations(purchase_id)
    pending = store.pending_inventory_extension(purchase_id)
    # The first independently verified processing/success event is immutable across renewals.
    if operations:
        anchor = InventoryExtensionClaim.model_validate(operations[0]['claim'])
        if payment['payment_intent_id'] != anchor.payment_intent_id or payment['payment_method'] != anchor.payment_method:
            raise PaymentPurchaseConflict('payment hold cannot be reassigned to another intent or method')
        payment = {key: getattr(anchor, key) for key in ('payment_intent_id', 'payment_event_id', 'payment_started_at', 'payment_method')}
    if pending:
        claim = InventoryExtensionClaim.model_validate(pending['claim'])
        if claim.activation != active or claim.genesis_artifact_hash != artifact['artifactHash']:
            raise PaymentPurchaseConflict('pending extension requires its original reviewed release')
        if pending['protocol'] is not None:
            evidence = await observe_extension(node, position, claim, pending)
            if evidence:
                store.confirm_inventory_extension(pending['sequence'], retained=pending,
                    evidence=evidence, expected_snapshot=stored)
                return hold_status(store.get(purchase_id), store.inventory_extension_operations(purchase_id), now=int(time.time()))
    elif observe_only or position.reservation.expires_at - int(time.time()) > RENEWAL_WINDOW_SECONDS:
        return hold_status(stored, operations, now=int(time.time()))
    else:
        authorize()
        from .voucher_issuance_worker import _series_state
        series = presales.get(hx(position.reservation.artifact.presale_terms_hash))
        state = asdict(_series_state(series)); state['phase'] = int(state['phase'])
        next_expiry = position.reservation.expires_at + MAX_RESERVATION_EXTENSION_SECONDS
        transition = build_inventory_extension_spend(reserved_coin=position.coin,
            deed_singleton_struct=position.struct, lineage_proof=lineage_proof_for_coinsol(position.creation_spend),
            reservation=position.reservation, next_expires_at=next_expiry, signer_indices=(0, 1), terms=position.terms)
        claim = InventoryExtensionClaim(network='testnet11', genesis_artifact_hash=artifact['artifactHash'], activation=active,
            purchase_artifact=stored.purchase_artifact, smart_deed_inner_hash=hx(position.terms.smart_deed_inner_hash),
            reserved_coin_id=hx(position.coin.name()), reserved_puzzle_hash=hx(position.coin.puzzle_hash),
            reservation_expires_at=position.reservation.expires_at, next_expires_at=next_expiry,
            validator_message=hx(transition.validator_message), series_terms=series['terms'], series_state=state,
            series_coin_id=series['chainState']['currentCoinId'], **payment)
    if observe_only:
        return hold_status(stored, operations, now=int(time.time()))

    async def preflight():
        authorize()
        fresh = load_artifact()
        if extension_activation(fresh, settings.runtime_environment + '-alpha') != active or fresh['artifactHash'] != artifact['artifactHash']:
            raise PaymentPurchaseConflict('extension release changed before dispatch')
        require_timely_extension(claim, int(time.time()))
        if store.get(purchase_id) != stored:
            raise PaymentPurchaseConflict('purchase changed before extension dispatch')
        peak = await release_peak(node, settings.network)
        await inspect_position(node, position, peak)
        if await canonical_time(node, peak) >= claim.reservation_expires_at:
            raise PaymentPurchaseConflict('current reservation already expired on the canonical chain')
        if await release_peak(node, settings.network) != peak:
            raise PaymentPurchaseConflict('chain tip changed before extension dispatch')

    if not operations:
        await preflight()
        from .payment_start import adopt_payment_start
        await adopt_payment_start(store=store, settings=settings, purchase_id=purchase_id,
            payment=payment, load_artifact=load_artifact)
    owner = uuid.uuid4().hex
    retained = store.claim_inventory_extension(purchase_id, claim=claim.model_dump(mode='json'),
        binding=dict(artifactHash=artifact['artifactHash'], activation=active), owner=owner,
        now=int(time.time()), expected_snapshot=stored)
    receipt = None
    try:
        await preflight()
        if retained['protocol'] is None:
            quorum = await collect_inventory_extension_quorum(settings, claim)
            from .inventory_extension_chain import transition_for
            transition = transition_for(position, claim, quorum.signer_indices)
            bundle = SpendBundle([transition.spend], quorum.aggregated_signature)
            retained.update(protocol=bundle.to_json_dict(), signerIndices=list(quorum.signer_indices))
            validate_execution(position, claim, retained)
            store.preserve_inventory_extension(retained['sequence'], owner=owner, now=int(time.time()),
                protocol=retained['protocol'], signer_indices=retained['signerIndices'])
        validate_execution(position, claim, retained)

        async def before_push(value=None):
            # Previously signed bytes are not current provider evidence. The same
            # private claim must still pass an independent quorum before replay.
            await collect_inventory_extension_quorum(settings, claim)
            await preflight()
            exact = value.to_json() if value is not None else retained['prepared']
            validate_execution(position, claim, {**retained, 'prepared': exact})
            store.preserve_inventory_extension(retained['sequence'], owner=owner, now=int(time.time()), prepared=exact)

        if submitter is None:
            raise PaymentPurchaseConflict('extension submission is unavailable; inventory remains held')
        if retained['prepared']:
            receipt = await submitter.reconcile_reserved(retained['prepared'], before_push=before_push)
        else:
            receipt = await submitter.submit(retained['protocol'], before_push=before_push)
    finally:
        store.finish_inventory_extension_attempt(retained['sequence'], owner=owner, receipt=receipt)
    return hold_status(store.get(purchase_id), store.inventory_extension_operations(purchase_id), now=int(time.time()))
