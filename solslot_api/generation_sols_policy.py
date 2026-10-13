"""Read-only fee capability for this reviewed one-percent primary route.

An ordinary parameter upgrade cannot silently change the signed offer review
or the offering's sealed fee. A differently priced route requires a new review.
"""
import time

REVIEWED_FEES = {'feeBps':100,'sgtFeeBps':30,'protocolFeeBps':70}


def current_fee_policy(values):
    if len(values)!=6 or any(type(v) is not int for v in values):
        raise ValueError('SOLS_FEE_POLICY_UNAVAILABLE')
    return {'feeBps':values[2],'sgtFeeBps':values[4],'protocolFeeBps':values[3]}


def require_order_policy(book,*,now=None):
    now=int(time.time()) if now is None else now
    catalog=book.catalog()
    if (not catalog or catalog.get('generationId')!=book.generation_id
            or type(catalog.get('lastCheckedAt')) is not int
            or not 0<=now-catalog['lastCheckedAt']<=45):
        raise ValueError('SOLS_FEE_POLICY_UNAVAILABLE')
    if catalog.get('feePolicy')!=REVIEWED_FEES:
        raise ValueError('SOLS_FEE_POLICY_REVIEW_REQUIRED')
    return dict(REVIEWED_FEES)
