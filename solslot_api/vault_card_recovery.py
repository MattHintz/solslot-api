"""Recover missed payment notifications and release abandoned vault-card orders."""
import time
from contextlib import closing
import re

from .vault_card_provider import checked_session, metadata


async def matching_object(provider, resource, params, predicate):
    """A bounded search may be inconclusive. Absence never authorizes a refund or new charge."""
    params = dict(params,limit=100)
    for _ in range(10):
        page = await provider._api('GET','/v1/'+resource,params=params)
        if page.get('object') != 'list' or not isinstance(page.get('data'),list):
            raise ValueError('Invalid Stripe recovery response')
        found = [doc for doc in page['data'] if predicate(doc)]
        if found:
            return found[0]
        if page.get('has_more') is False:
            return None
        if not page['data'] or not isinstance(page['data'][-1].get('id'),str):
            break
        params['starting_after'] = page['data'][-1]['id']
    raise ValueError('Original Stripe object still requires reconciliation')


async def recover_refund(provider, order, payment_id):
    require_metadata = {'purchase_id':order.purchase_id,'rail':'solslot_vault_card'}
    return await matching_object(provider,'refunds',{'payment_intent':payment_id},lambda d:
        d.get('payment_intent') == payment_id and d.get('amount') == order.amount_minor
        and d.get('currency') == order.currency and all((d.get('metadata') or {}).get(k)==v for k,v in require_metadata.items()))


async def recover_expired(app, settings, inbox, orders, provider, order, *, now):
    from .vault_stripe_protection import prepare_unpaid_release
    if (order.network,order.mode,order.account_id) != (settings.network,settings.stripe_mode,settings.stripe_account_id):
        return 'REVIEW'
    if inbox.settlement(order.purchase_id):
        return 'DONE'  # The durable payment job owns the terminal outcome.
    if (await provider.account()).get('id') != order.account_id:
        raise ValueError('Original Stripe account unavailable')
    dispatch = orders.dispatch(order.purchase_id)
    if not dispatch:
        if not orders.fence_undispatched_order(order.purchase_id,now=now):
            return 'PENDING'
        evidence = None
    else:
        if not order.session_id:
            if now >= dispatch['first_dispatch']+23*3600:
                # Stripe can forget an idempotency key before our worker recovers.
                # Search the original dispatch window without issuing another POST.
                original = await matching_object(
                    provider, 'checkout/sessions',
                    {'created[gte]': max(0, dispatch['first_dispatch']-300),
                     'created[lte]': dispatch['session_expires_at']},
                    lambda session: session.get('client_reference_id') == order.purchase_id
                    and session.get('metadata') == metadata(order))
                if original is None:
                    return 'REVIEW'
                checked_session(order, original, expected_expiry=dispatch['session_expires_at'])
                order = orders.bind_session(order.purchase_id, original['id'], original.get('payment_intent'))
            else:
                order = await provider.recover_session(order,orders,now=now)
        session = await provider.retrieve_session(order.session_id)
        if (not isinstance(session,dict) or session.get('id') != order.session_id
                or session.get('livemode') is not (order.mode=='live') or session.get('metadata') != metadata(order)
                or session.get('client_reference_id') != order.purchase_id
                or session.get('amount_total') != order.amount_minor or session.get('currency') != order.currency):
            return 'REVIEW'
        pid = session.get('payment_intent')
        intent = None
        if pid:
            if not isinstance(pid,str) or not re.fullmatch(r'pi_[A-Za-z0-9]+',pid):
                return 'REVIEW'
            intent = await provider.retrieve_payment_intent(pid)
            if (intent.get('id') != pid or intent.get('livemode') is not (order.mode=='live')
                    or intent.get('metadata') != metadata(order) or intent.get('amount') != order.amount_minor
                    or intent.get('currency') != order.currency):
                return 'REVIEW'
            orders.bind_payment_intent(order.purchase_id,order.session_id,pid)
        if session.get('payment_status') == 'paid' or (intent and intent.get('status')=='succeeded'):
            if intent is None:
                return 'PENDING'
            event = await matching_object(provider,'events',{'type':'payment_intent.succeeded',
                'created[gte]':int(intent['created']),'created[lte]':now}, lambda e:
                    e.get('type')=='payment_intent.succeeded' and e.get('livemode') is (order.mode=='live')
                    and e.get('account',order.account_id)==order.account_id
                    and (e.get('data',{}).get('object') or {}).get('id')==pid)
            if event:
                inbox.receive((event['id'],'payment_intent.succeeded',pid,order.purchase_id,pid))
            return 'PENDING'
        if (session.get('status') != 'expired' or session.get('payment_status') != 'unpaid'
                or intent and (intent.get('status')!='canceled' or intent.get('amount_received')!=0)):
            return 'PENDING'
        evidence = {'session':session,'payment_intent':intent}
    closed = await prepare_unpaid_release(app,settings,order,now=now,session_evidence=evidence)
    return 'DONE' if closed else 'PENDING'


def expired_job(inbox, now):
    with closing(inbox.connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        # The order and event tables share the same generation database.
        db.execute('''INSERT OR IGNORE INTO vault_card_expiry(purchase_id)
                      SELECT purchase_id FROM vault_card_orders
                      WHERE session_expires_at<=? OR CAST(json_extract(document,'$.expires_at') AS INTEGER)<=?''',(now,now))
        row = db.execute("""SELECT purchase_id FROM vault_card_expiry WHERE state='PENDING' AND next_at<=?
                           ORDER BY next_at,purchase_id LIMIT 1""",(now,)).fetchone()
        if row:
            db.execute('UPDATE vault_card_expiry SET next_at=? WHERE purchase_id=?',(now+180,row[0]))
            return row[0]


def save_expiry(inbox,purchase_id,state):
    with closing(inbox.connect()) as db, db:
        db.execute("""UPDATE vault_card_expiry SET state=?,next_at=? WHERE purchase_id=? AND state='PENDING'""",
                   (state,int(time.time())+30,purchase_id))
