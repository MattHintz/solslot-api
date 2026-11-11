"""Finite Testnet conversion, committed by every independently installed policy.

This is not an oracle attestation. No market observation or price signature is
fabricated. Existing artifact commitment slots carry domain-separated policy
commitments, and the original dollar terms remain byte-for-byte unchanged.
Only the private validators' existing Testnet reservation quorum can authorize
the native transition. Mainnet and arbitrary customer-selected rates are refused.
"""
from dataclasses import dataclass
from hashlib import sha256
from types import SimpleNamespace
from chia_rs.sized_bytes import bytes32
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy


@dataclass(frozen=True)
class FixedTestnetConversion:
    policy:TestnetIssuerPolicy
    expires_at:int

    def evidence(self):
        return {'schema':'solslot.fixed-testnet-conversion.v1',
            'issuerPolicyHash':self.policy.commitment,'expiresAt':self.expires_at}

    @property
    def round(self):
        self.verify_policy(self.policy,now=self.expires_at-300,expires_at=self.expires_at)
        def digest(domain):
            return bytes32(sha256(domain+self.policy.commitment.encode()+str(self.expires_at).encode()).digest())
        return SimpleNamespace(network='testnet11',asset_id=bytes32.zeros,asset_decimals=12,
            valid_from=self.expires_at-300,valid_until=self.expires_at,
            price_usd_minor_per_asset=self.policy.test_usd_minor_per_txch,
            round_hash=digest(b'SOLSLOT_FIXED_TESTNET_CONVERSION_V1'),
            source_evidence_root=digest(b'SOLSLOT_APPROVED_TEST_POLICY_V1'))

    def verify_policy(self,policy,*,now,expires_at):
        if (not isinstance(policy,(TestnetIssuerPolicy,TestnetCollectionIssuerPolicy))or policy.test_usd_minor_per_txch is None
                or policy.commitment!=self.policy.commitment or type(now)is not int
                or type(expires_at)is not int or expires_at!=self.expires_at
                or not expires_at-300<=now<expires_at
                or (isinstance(policy,TestnetIssuerPolicy) and not (policy.issued_at<=expires_at-300 and expires_at<=policy.expires_at))):
            raise ValueError('CURRENT_PURCHASE_FIXED_TEST_CONVERSION_CHANGED')
        policy.validate()
        return self


def claim_price(evidence,policy):
    if getattr(policy,'test_usd_minor_per_txch',None) is None:
        from .generation_sols_batch_execution import signed_price
        return signed_price(evidence)
    if (not isinstance(evidence,dict)or set(evidence)!={'schema','issuerPolicyHash','expiresAt'}
            or evidence['schema']!='solslot.fixed-testnet-conversion.v1'
            or evidence['issuerPolicyHash']!=policy.commitment or type(evidence['expiresAt'])is not int):
        raise ValueError('CURRENT_PURCHASE_FIXED_TEST_CONVERSION_CHANGED')
    return FixedTestnetConversion(policy,evidence['expiresAt'])


def configured_price(settings,policy,*,now,expires_at):
    if settings.network!='testnet11' or settings.deployment_generation_id!='0x'+policy.generation.hex():
        raise ValueError('CURRENT_PURCHASE_FIXED_TEST_NETWORK_CHANGED')
    if getattr(policy,'test_usd_minor_per_txch',None) is not None:
        price=FixedTestnetConversion(policy,expires_at).verify_policy(policy,now=now,expires_at=expires_at)
        return price,price.evidence()
    from .payment_quotes import load_authorized_oracle_round
    from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
    authorized=load_authorized_oracle_round(settings,asset_id=bytes32.zeros,now=now)
    price=SignedPrimaryPrice(authorized.round,tuple((s['signerIndex'],bytes.fromhex(s['signature'].removeprefix('0x')))
        for s in authorized.signatures))
    return price,authorized.public_evidence()


def status(policy,*,now):
    policy.validate()
    if getattr(policy,'test_usd_minor_per_txch',None) is None:raise ValueError('CURRENT_PURCHASE_FIXED_TEST_DISABLED')
    ready=(policy.issued_at<=now and now+300<=policy.expires_at) if isinstance(policy,TestnetIssuerPolicy) else type(now)is int and now>0
    valid_until=policy.expires_at if isinstance(policy,TestnetIssuerPolicy) else now+300
    return {'price':{'schema':'solslot.price-refresh-status.v1','network':'testnet11',
        'mode':'FIXED_TESTNET_CONVERSION','policyHash':policy.commitment,'checkedAt':now,
        'requiredUntil':now+300,'validUntil':valid_until,'status':'READY'if ready else'CLOSED',
        'canQuote':ready,'canRefresh':False,'sourceCount':0,'signerCount':0},'job':None}
