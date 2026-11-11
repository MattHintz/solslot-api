"""Compatibility helpers for exact legacy and collection policy scope."""
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy


def quote_deadline(policy,quote_expires_at):
    if type(quote_expires_at)is not int or quote_expires_at<=0:
        raise ValueError('CURRENT_PURCHASE_QUOTE_DEADLINE_INVALID')
    if isinstance(policy, TestnetCollectionIssuerPolicy):
        return quote_expires_at
    return min(quote_expires_at, policy.expires_at)


def policy_live_at(policy,now):
    return type(now) is int and now > 0 and (
        isinstance(policy, TestnetCollectionIssuerPolicy) or policy.issued_at <= now < policy.expires_at)
