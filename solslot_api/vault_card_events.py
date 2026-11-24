"""Receive Stripe notifications durably. The chain worker establishes deed delivery."""
from __future__ import annotations

import asyncio
from contextlib import closing
import hmac
import json
import logging
import os
import re
import sqlite3
import stat
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from solslot_puzzles.payment_artifacts_v3 import (
    STRIPE_PAYMENT_PROVIDER_ID, StripeDisputeState, StripeFundingType, StripeMethodFamily,
    StripePaymentStatus, StripeRefundState, StripeSettlementEvidenceV1,
    build_purchase_batch_settlement_receipt_v1, purchase_batch_from_json, stripe_settlement_evidence_to_json,
)

from .config import Settings, get_settings
from .generation_storage import connect_generation_sqlite
from .payment_purchase_store import get_payment_purchase_store
from .stripe_delivery_store import FINALIZED, MANUAL_REVIEW, StripeDeliveryNotFound, get_stripe_delivery_store
from .validator_quorum import configured_validator_pubkeys
from .vault_card_provider import metadata as order_metadata
from .vault_card_store import VaultCardStore

router = APIRouter()
log = logging.getLogger(__name__)
PAID = 'payment_intent.succeeded'
ALERTS = {'charge.refunded', 'refund.created', 'refund.updated', 'refund.failed',
          'charge.dispute.created', 'charge.dispute.updated', 'charge.dispute.closed'}


class EvidenceMismatch(ValueError):
    """Verified provider objects conflict with the retained order."""


def require(condition, message):
    if not condition:
        raise EvidenceMismatch(message)


def verified_payload(raw, signature, key, now):
    parts = [value.strip().partition('=') for value in signature.split(',')]
    times = [v for k, _, v in parts if k == 't']
    if len(times) != 1 or not re.fullmatch(r'[0-9]{1,12}', times[0]) or abs(int(times[0])-now) > 300:
        raise HTTPException(401, 'Invalid Stripe signature.')
    expected = hmac.digest(key, times[0].encode('ascii') + b'.' + raw, 'sha256').hex()
    if not any(re.fullmatch(r'[0-9a-f]{64}', v) and hmac.compare_digest(v, expected)
               for k, _, v in parts if k == 'v1'):
        raise HTTPException(401, 'Invalid Stripe signature.')
    try:
        event = json.loads(raw)
        if (not isinstance(event, dict) or event.get('object') != 'event'
                or not re.fullmatch(r'evt_[A-Za-z0-9]+', event.get('id', ''))
                or not isinstance(event['data']['object'], dict) or not isinstance(event['type'], str)):
            raise ValueError
    except (UnicodeError, ValueError, TypeError, KeyError):
        raise HTTPException(400, 'Invalid Stripe event.') from None
    return event


def signing_key(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        meta = os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 1024:
            raise ValueError('Private webhook credential file required')
        key = f.read().strip()
    if not key.startswith(b'whsec_') or len(key) < 22:
        raise ValueError('Webhook credential unavailable')
    return key


class CardInbox:
    def __init__(self, path):
        self.path = path
        with closing(self.connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS vault_card_events (
                    event_id TEXT PRIMARY KEY, kind TEXT NOT NULL, object_id TEXT NOT NULL,
                    purchase_id TEXT NOT NULL, payment_id TEXT NOT NULL,
                    next_at INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'PENDING', reason TEXT);
                CREATE INDEX IF NOT EXISTS card_event_due ON vault_card_events(state,next_at);
                CREATE TABLE IF NOT EXISTS vault_card_expiry (
                    purchase_id TEXT PRIMARY KEY,next_at INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'PENDING');
                CREATE TABLE IF NOT EXISTS vault_card_settlement (
                    purchase_id TEXT PRIMARY KEY, payment_id TEXT NOT NULL UNIQUE,
                    event_id TEXT NOT NULL UNIQUE, evidence TEXT NOT NULL,
                    refund_id TEXT UNIQUE, refunded INTEGER NOT NULL DEFAULT 0);
            """)

    def connect(self):
        db = connect_generation_sqlite(self.path, timeout=8)
        db.row_factory = sqlite3.Row
        return db

    def receive(self, row):
        with closing(self.connect()) as db, db:
            db.execute("INSERT OR IGNORE INTO vault_card_events(event_id,kind,object_id,purchase_id,payment_id) VALUES(?,?,?,?,?)", row)
            stored = db.execute("SELECT event_id,kind,object_id,purchase_id,payment_id FROM vault_card_events WHERE event_id=?", (row[0],)).fetchone()
            require(tuple(stored) == row, 'Conflicting event identity')

    def claim(self, now):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT * FROM vault_card_events WHERE state='PENDING' AND next_at<=?
                               ORDER BY next_at,event_id LIMIT 1""", (now,)).fetchone()
            if row:
                db.execute("UPDATE vault_card_events SET next_at=?,attempts=attempts+1 WHERE event_id=?", (now+180,row['event_id']))
                return dict(row)

    def finish(self, row, state, reason=None):
        with closing(self.connect()) as db, db:
            db.execute("""UPDATE vault_card_events SET state=?,reason=?,next_at=?
                        WHERE event_id=? AND attempts=? AND state='PENDING'""",
                       (state,reason,int(time.time())+(min(300, 3 * (2**min(7,row['attempts']))) if reason else 5),
                        row['event_id'], row['attempts']+1))

    def paid(self, order, event_id, evidence, payment_id):
        document = json.dumps(evidence, sort_keys=True, separators=(',', ':'))
        with closing(self.connect()) as db, db:
            db.execute("INSERT OR IGNORE INTO vault_card_settlement(purchase_id,payment_id,event_id,evidence) VALUES(?,?,?,?)",
                       (order.purchase_id,payment_id,event_id,document))
            row = db.execute("SELECT * FROM vault_card_settlement WHERE purchase_id=?", (order.purchase_id,)).fetchone()
            require(row and row['payment_id'] == payment_id, 'Payment already associated with another order')
            return dict(row)

    def settlement(self, purchase_id):
        with closing(self.connect()) as db:
            row = db.execute("SELECT * FROM vault_card_settlement WHERE purchase_id=?", (purchase_id,)).fetchone()
            return dict(row) if row else None

    def review(self, purchase_id):
        with closing(self.connect()) as db:
            return bool(db.execute("SELECT 1 FROM vault_card_events WHERE purchase_id=? AND state='REVIEW' UNION ALL SELECT 1 FROM vault_card_expiry WHERE purchase_id=? AND state='REVIEW' LIMIT 1", (purchase_id,purchase_id)).fetchone())

    def expired(self, purchase_id):
        with closing(self.connect()) as db:
            return bool(db.execute("SELECT 1 FROM vault_card_expiry WHERE purchase_id=? AND state='DONE'",
                                   (purchase_id,)).fetchone())

    def refund(self, purchase_id, refund_id, succeeded):
        with closing(self.connect()) as db, db:
            cur = db.execute("""UPDATE vault_card_settlement SET refund_id=?,refunded=max(refunded,?)
                              WHERE purchase_id=? AND (refund_id IS NULL OR refund_id=?)""",
                             (refund_id,int(succeeded),purchase_id,refund_id))
            require(cur.rowcount == 1, 'Conflicting refund reference')


def card_status(app, settings, order):
    inbox = CardInbox(settings.payment_purchase_db_path)
    row = inbox.settlement(order.purchase_id)
    if inbox.review(order.purchase_id):
        return 'REVIEW_REQUIRED'
    if not row:
        return 'EXPIRED' if inbox.expired(order.purchase_id) else None
    if row['refunded']:
        return 'REFUNDED'
    try:
        operation = get_stripe_delivery_store(settings.stripe_delivery_db_path).get(order.purchase_id)
    except StripeDeliveryNotFound:
        return 'PROCESSING'
    if operation.state == FINALIZED:
        outputs = operation.expected_deed_output_coin_ids
        if (operation.evidence.get('paymentIntentId') == row['payment_id'] and operation.confirmation_height
                and len(set(outputs)) == len(outputs) == len(order.deed_launcher_ids)):
            return 'DELIVERED'
        return 'REVIEW_REQUIRED'
    return 'REVIEW_REQUIRED' if operation.state == MANUAL_REVIEW else 'PROCESSING'


@router.post('/stripe/vault-card/webhook')
async def receive(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.vault_card_webhook_key_file:
        raise HTTPException(503, 'Card event receiver unavailable.')
    signatures = request.headers.getlist('stripe-signature')
    if len(signatures) != 1 or len(signatures[0]) > 4096:
        raise HTTPException(401, 'Invalid Stripe signature.')
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 262144:
            raise HTTPException(413, 'Event too large.')
        body.extend(chunk)
    event = verified_payload(body, signatures[0], signing_key(settings.vault_card_webhook_key_file), int(time.time()))
    if (event.get('livemode') is not (settings.stripe_mode == 'live')
            or event.get('account', settings.stripe_account_id) != settings.stripe_account_id):
        raise HTTPException(409, 'Stripe account or mode mismatch.')
    kind, obj = event['type'],event['data']['object']
    if kind != PAID and kind not in ALERTS:
        return {'received':True}
    orders = VaultCardStore(settings.payment_purchase_db_path)
    payment_id = obj.get('id') if kind == PAID else obj.get('payment_intent')
    meta = obj.get('metadata') or {}
    order = orders.get(meta.get('purchase_id')) if meta.get('rail') == 'solslot_vault_card' else None
    if order is None and isinstance(payment_id,str):
        order = orders.by_payment_intent(payment_id)
    if order is None:
        return {'received':True}
    if not re.fullmatch(r'pi_[A-Za-z0-9]+', payment_id or '') or not isinstance(obj.get('id'),str):
        raise HTTPException(400, 'Invalid payment reference.')
    try:
        CardInbox(settings.payment_purchase_db_path).receive((event['id'],kind,obj['id'],order.purchase_id,payment_id))
    except EvidenceMismatch:
        raise HTTPException(409, 'Conflicting event identity.') from None
    return {'received':True}


def check_metadata(obj, order):
    metadata = obj.get('metadata') or {}
    expected = order_metadata(order)
    require(all(metadata.get(k) == v for k,v in expected.items()), 'Stripe purchase terms differ')


def payment_evidence(order, intent, session, event, now):
    live = order.mode == 'live'
    pid = intent['id']
    charge = intent.get('latest_charge') or {}
    require(all(obj.get('livemode') is live for obj in (intent,session,event,charge))
            and event.get('account',order.account_id) == order.account_id, 'Stripe payment environment differs')
    require(event['type'] == PAID and event['data']['object']['id'] == pid
            and session.get('id') == order.session_id and session.get('payment_intent') == pid
            and session.get('client_reference_id') == order.purchase_id
            and (order.payment_intent_id is None or order.payment_intent_id == pid), 'Stripe payment identity differs')
    for obj in (intent,session):
        check_metadata(obj,order)
    require(session.get('mode') == 'payment' and session.get('status') == 'complete' and session.get('payment_status') == 'paid'
            and session.get('currency') == intent.get('currency') == charge.get('currency') == order.currency
            and intent.get('status') == 'succeeded' and charge.get('payment_intent') == pid
            and charge.get('paid') is True and charge.get('captured') is True
            and all(type(v) is int and v == order.amount_minor for v in (
                session.get('amount_total'),intent.get('amount_received'),intent.get('amount'),charge.get('amount_captured')))
            and type(event.get('created')) is int and 0 < intent.get('created',0) <= event['created'] <= now+300,
            'Paid amount or status differs')
    details = charge.get('payment_method_details') or {}
    require(details.get('type') == 'card', 'Unexpected card payment method')
    require(charge.get('disputed') is False and charge.get('refunded') is False
            and type(charge.get('amount_refunded')) is int and charge.get('amount_refunded') == 0, 'Charge has refund or dispute activity')
    funding = {'credit':StripeFundingType.CREDIT,'debit':StripeFundingType.DEBIT,
               'prepaid':StripeFundingType.PREPAID,'unknown':StripeFundingType.UNKNOWN}
    card_funding = (details.get('card') or {}).get('funding','unknown')
    require(card_funding in funding, 'Unknown funding type')
    return StripeSettlementEvidenceV1(stripe_account_id=order.account_id,livemode=live,payment_intent_id=pid,
        event_id=event['id'],amount_minor=order.amount_minor,currency=order.currency,method_family=StripeMethodFamily.CARD,
        funding_type=funding[card_funding],processing_charge_minor=0,status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,refund_state=StripeRefundState.NONE,dispute_state=StripeDisputeState.NONE,observed_at=event['created'])


def queue_delivery(settings, order, evidence):
    from solslot_puzzles.payment_artifacts_v3 import stripe_settlement_evidence_from_json
    record = get_payment_purchase_store(settings.payment_purchase_db_path).get(order.purchase_id)
    require(record.rail == 'stripe' and record.purchase_artifact == order.batch and record.artifact_hash == order.batch_hash,
            'Saved Chia purchase differs')
    batch = purchase_batch_from_json(record.purchase_artifact)
    proof = stripe_settlement_evidence_from_json(evidence)
    receipt = build_purchase_batch_settlement_receipt_v1(batch=batch,provider_id=STRIPE_PAYMENT_PROVIDER_ID,
        external_reference_hash=proof.payment_reference_hash,evidence_hash=proof.evidence_hash,
        observed_at=proof.observed_at,validator_pubkeys=configured_validator_pubkeys(settings),
        collected_amount_minor=proof.amount_minor,processing_charge_minor=proof.processing_charge_minor)
    return get_stripe_delivery_store(settings.stripe_delivery_db_path).queue(
        purchase_id=order.purchase_id,evidence=evidence,receipt_hash='0x'+receipt.receipt_hash.hex())


async def advance(app, settings, inbox, row, now):
    from .vault_stripe_protection import bind_card_payment, prepare_card_refund, mark_card_refunded
    orders = VaultCardStore(settings.payment_purchase_db_path)
    order = orders.get(row['purchase_id'])
    require(order and (order.network,order.mode,order.account_id) ==
            (settings.network,settings.stripe_mode,settings.stripe_account_id), 'Order environment differs')
    if not order.session_id:
        raise RuntimeError('Waiting for original checkout session')
    service = getattr(app.state,'vault_card_checkout',None)
    if service is None:
        from .vault_card_provider import VaultCardProvider
        provider = VaultCardProvider(settings)
    else:
        provider = service.provider
    require((await provider.account()).get('id') == order.account_id, 'Stripe account differs')
    event = await provider.retrieve_event(row['event_id'])
    require(event.get('id') == row['event_id'] and event.get('type') == row['kind']
            and event.get('livemode') is (order.mode == 'live') and event.get('account',order.account_id) == order.account_id
            and event['data']['object']['id'] == row['object_id'], 'Stripe event differs')
    settled = inbox.settlement(order.purchase_id)
    if row['kind'] != PAID:
        if not settled:
            raise RuntimeError('Waiting for payment evidence')
        if not settled['refund_id'] and row['kind'] in ('refund.created','refund.updated','charge.refunded'):
            if (event['data']['object'].get('metadata') or {}).get('purchase_id') == order.purchase_id or now >= order.expires_at:
                # Stripe may notify us before our worker records the refund response.
                # A bounded retry lets the stable refund request recover after interruption.
                if row['attempts'] < 6:
                    raise RuntimeError('Waiting for refund recording')
        if row['kind'].startswith('refund.') and settled['refund_id'] == row['object_id']:
            return 'DONE'  # The payment job tracks this exact refund until it succeeds.
        if row['kind'] == 'charge.refunded' and settled['refund_id']:
            refund = await provider.retrieve_refund(settled['refund_id'])
            if refund.get('charge') == row['object_id'] and refund.get('payment_intent') == row['payment_id']:
                return 'DONE'
        raise EvidenceMismatch('Unexpected refund or dispute requires review')
    if not settled:
        intent, session = await asyncio.gather(provider.retrieve_payment_intent(row['payment_id']),
                                              provider.retrieve_session(order.session_id))
        require(intent.get('id') == row['payment_id'], 'Payment intent differs')
        if session.get('status') == 'open' and session.get('payment_status') == 'unpaid':
            raise RuntimeError('Waiting for Checkout confirmation')
        evidence = payment_evidence(order,intent,session,event,now)
        order = orders.bind_payment_intent(order.purchase_id,order.session_id,row['payment_id'])
        settled = inbox.paid(order,event['id'],stripe_settlement_evidence_to_json(evidence),row['payment_id'])
    payment_id = settled['payment_id']
    require(payment_id == row['payment_id'], 'Original payment changed')
    if settled['refunded']:
        return 'DONE'
    bind_card_payment(app,order,payment_id)
    if inbox.review(order.purchase_id):
        return 'REVIEW'
    if card_status(app,settings,order) == 'DELIVERED':
        return 'DONE'
    if now < order.expires_at:
        queue_delivery(settings,order,json.loads(settled['evidence']))
        return 'PENDING'
    # A transaction already in flight can still confirm. Independent chain evidence
    # of BOTH returned reservations must precede a full refund.
    if not await prepare_card_refund(app,settings,order,payment_id,now=now):
        return 'PENDING'
    from .vault_card_recovery import recover_refund
    if settled['refund_id']:
        refund = await provider.retrieve_refund(settled['refund_id'])
    else:
        refund = await recover_refund(provider,order,payment_id)
        if refund is None:
            refund = await provider.refund_payment(order,payment_id)
    require(isinstance(refund.get('id'),str) and re.fullmatch(r're_[A-Za-z0-9]+',refund['id'])
            and refund.get('payment_intent') == payment_id and refund.get('amount') == order.amount_minor
            and refund.get('currency') == order.currency and refund.get('metadata',{}).get('purchase_id') == order.purchase_id,
            'Refund differs from original purchase')
    state = refund.get('status')
    require(state in ('pending','requires_action','succeeded'), 'Refund needs provider review')
    inbox.refund(order.purchase_id,refund['id'],False)
    if state != 'succeeded':
        return 'PENDING'
    mark_card_refunded(app,order,payment_id,refund['id'])
    inbox.refund(order.purchase_id,refund['id'],True)
    return 'DONE'


async def run_card_events(app, settings):
    inbox = CardInbox(settings.payment_purchase_db_path)
    from .vault_card_recovery import expired_job, recover_expired, save_expiry
    from .vault_card_provider import VaultCardProvider
    orders = VaultCardStore(settings.payment_purchase_db_path)
    next_scan = 0.
    while True:
        try:
            if time.monotonic() >= next_scan:
                now = int(time.time())
                purchase = expired_job(inbox,now)
                next_scan = time.monotonic()+5
                if purchase:
                    try:
                        async with asyncio.timeout(90):
                            status = await recover_expired(app,settings,inbox,orders,VaultCardProvider(settings),
                                orders.get(purchase),now=now)
                    except Exception as exc:
                        log.warning('Expired card order will retry (%s)',type(exc).__name__)
                        status = 'PENDING'
                    save_expiry(inbox,purchase,status)
            row = inbox.claim(int(time.time()))
            if row:
                try:
                    async with asyncio.timeout(90):
                        state = await advance(app,settings,inbox,row,int(time.time()))
                except EvidenceMismatch as exc:
                    inbox.finish(row,'REVIEW',str(exc))
                except Exception as exc:
                    # Never log provider bodies, customer details, or credential values.
                    log.warning('Card reconciliation will retry %s (%s)',row['event_id'],type(exc).__name__)
                    inbox.finish(row,'PENDING',type(exc).__name__)
                else:
                    inbox.finish(row,state)
                continue
        except sqlite3.Error as exc:
            log.warning('Card journal unavailable (%s)',type(exc).__name__)
        await asyncio.sleep(2)
