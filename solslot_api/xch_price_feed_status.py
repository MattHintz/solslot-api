"""Read-only price freshness and quota decision for demand-based checkout.

An available timer is not a successful price observation. This reads the same
verified snapshot and finite usage/policy records as the existing collector.
It performs no provider calls, quota reservations, signatures or file writes.
"""
from pathlib import Path
from chia_rs.sized_bytes import bytes32
from .payment_quotes import load_authorized_oracle_round, PaymentQuoteError
from .xch_price_feed import read_prior_snapshot, PriceFeedError
from .xch_price_feed_runner import read_provider_usage, validate_test_window, MONTHLY_CALLS_PER_ROLE


def price_refresh_status(settings, *, snapshot, usage, policy, now, required_until):
    if (type(now) is not int or now <= 0 or type(required_until) is not int
            or not now < required_until <= now+300 or settings.network != 'testnet11'
            or str(snapshot) != str(settings.payment_oracle_rounds_path)):
        raise ValueError('CURRENT_PRICE_STATUS_BINDING_INVALID')
    base = {'schema':'solslot.price-refresh-status.v1', 'network':'testnet11',
        'checkedAt':now, 'requiredUntil':required_until, 'canQuote':False,
        'refreshRequired':True, 'canRefresh':False, 'lastSuccessfulAt':None,
        'validUntil':None, 'sequence':None, 'sourceCount':0, 'signerCount':0,
        'quota':{'status':'UNAVAILABLE','remainingRequests':None,'period':None}}
    try:
        until = validate_test_window(Path(policy),now=now)
    except (OSError,ValueError,PriceFeedError):
        return {**base,'status':'POLICY_CLOSED','code':'PRICE_REFRESH_WINDOW_UNAVAILABLE'}
    if required_until > until:
        return {**base,'status':'POLICY_CLOSED','code':'PRICE_QUOTE_EXCEEDS_REFRESH_WINDOW'}
    usage = Path(usage)
    if not usage.exists() and not usage.is_symlink():
        quota = base['quota']
    else:
        try:
            value = read_provider_usage(usage,now=now)
            remaining = max(0,MONTHLY_CALLS_PER_ROLE-value['calls'])
            quota = {'status':'AVAILABLE' if remaining else 'EXHAUSTED',
                'remainingRequests':remaining,'period':value['month']}
        except (OSError,ValueError,PriceFeedError):
            quota = {**base['quota'],'status':'INVALID'}
    base = {**base,'quota':quota,'canRefresh':quota['status']=='AVAILABLE'}
    try:
        prior = read_prior_snapshot(settings,Path(snapshot))
    except (OSError,ValueError,PriceFeedError):
        # Corrupt signed sequence evidence must never be overwritten by a
        # demand refresh that quietly treats it as an initial deployment.
        return {**base,'status':'SOURCE_UNAVAILABLE','code':'PRICE_SNAPSHOT_INVALID','canRefresh':False}
    if prior is not None:
        document, authorized = prior
        if document['generatedAt'] > now:
            return {**base,'status':'SOURCE_UNAVAILABLE','code':'PRICE_SNAPSHOT_CLOCK_INVALID','canRefresh':False}
        base = {**base,'lastSuccessfulAt':document['generatedAt'],
            'validUntil':authorized.round.valid_until,'sequence':authorized.round.sequence,
            'sourceCount':len(authorized.round.observations),'signerCount':len(authorized.signatures)}
        try:
            live = load_authorized_oracle_round(settings,asset_id=bytes32.zeros,now=now)
            if live.round.valid_until >= required_until:
                return {**base,'status':'READY','code':None,'canQuote':True,'refreshRequired':False}
        except (OSError,ValueError,PaymentQuoteError):
            pass
    return {**base,'status':'REFRESH_REQUIRED' if base['canRefresh'] else 'REFRESH_UNAVAILABLE',
        'code':'FRESH_SIGNED_PRICE_REQUIRED' if base['canRefresh'] else 'PRICE_REFRESH_QUOTA_UNAVAILABLE'}
