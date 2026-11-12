"""Explicit, separately funded current-customer runtime installation.

There is no generic faucet fallback. A frozen policy, exact public funding
puzzle, isolated fee journal and protected runtime key are all required.
Disabled startup reads no key, creates no customer DB and grants no authority.
"""
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from .faucet import Faucet
from .generation_customer_runtime import CustomerCreationPolicy, GenerationCustomerRuntime
from .generation_customer_signer import CustomerFeeFaucet
from .generation_customer_store import GenerationCustomerStore
from .protocol_funding_store import ProtocolFundingStore
from .protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy


def load_customer_policy(path, expected_hash, generation, *, now, allow_expired_read_context=False):
    if not isinstance(expected_hash,str) or re.fullmatch(r'0x[0-9a-f]{64}',expected_hash) is None:
        raise ValueError('customer funding needs a frozen policy hash')
    raw=Path(path).read_bytes()
    if len(raw)>16384 or '0x'+hashlib.sha256(raw).hexdigest()!=expected_hash:
        raise ValueError('customer funding policy differs from its frozen source')
    data=json.loads(raw)
    names={'schema','generationId','fundingPuzzleHash','creationParentIds','feeParentIds',
        'maximumCreationParentMojos','maximumFeeParentMojos','maximumFeeMojos','issuedAt','expiresAt'}
    if (not isinstance(data,dict) or set(data)!=names or data['schema']!='solslot.customer-funding-policy.v1'
            or not isinstance(data['creationParentIds'],list) or not isinstance(data['feeParentIds'],list)
            or len(data['creationParentIds'])!=len(set(data['creationParentIds']))
            or len(data['feeParentIds'])!=len(set(data['feeParentIds']))
            or not isinstance(data['fundingPuzzleHash'],str)
            or re.fullmatch(r'0x[0-9a-f]{64}',data['fundingPuzzleHash']) is None):
        raise ValueError('one exact bounded customer policy is required')
    policy=CustomerCreationPolicy(data['generationId'],frozenset(data['creationParentIds']),
        data['maximumCreationParentMojos'],data['maximumFeeMojos'],data['issuedAt'],data['expiresAt'],
        frozenset(data['feeParentIds']),data['maximumFeeParentMojos'])
    validation_time=now
    if allow_expired_read_context and type(policy.issued_at)is int and type(policy.expires_at)is int:
        # Structural validation remains exact. An expired policy may reopen
        # observation/session state, but never load a key or enable a submitter.
        validation_time=max(policy.issued_at,min(now,policy.expires_at-1))
    return policy.validate(generation,validation_time),data['fundingPuzzleHash']


def protected_customer_faucet(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        metadata=os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in (0,os.geteuid())
                or stat.S_IMODE(metadata.st_mode)&0o027 or metadata.st_size not in (64,65,66,67)):
            raise ValueError('customer signer needs a protected runtime key file')
        with os.fdopen(descriptor,'r',closefd=False) as source:
            secret=source.read(68).strip()
        if re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}',secret) is None:
            raise ValueError('customer signer runtime material is invalid')
        # The retained funding account stores a serialized master BLS key,
        # not entropy to feed through key_gen again. The reviewed public
        # puzzle below independently checks the exact derived account.
        return Faucet.from_master_private_key_hex(secret,'testnet11')
    finally:
        os.close(descriptor)


def configured_generation_customers(settings,*,index,provider,journal,registry,clock=time.time):
    if not getattr(settings,'generation_customer_enabled',False):
        return None
    if settings.network!='testnet11' or not settings.deployment_generation_id or index is None or journal is None:
        raise ValueError('customer runtime needs its current native generation and journal')
    policy,puzzle=load_customer_policy(settings.generation_customer_policy_path,
        settings.generation_customer_policy_hash,settings.deployment_generation_id,now=int(clock()),
        allow_expired_read_context=True)
    if not policy.issued_at<=int(clock())<policy.expires_at:
        from .generation_storage import generation_path
        if not Path(generation_path(settings.generation_customer_db_path,settings.deployment_generation_id)).is_file():
            return None
        store=GenerationCustomerStore(settings.generation_customer_db_path,settings.deployment_generation_id)
        return GenerationCustomerRuntime(settings=settings,index=index,provider=provider,store=store,
            journal=journal,registry=registry,clock=clock)
    faucet=protected_customer_faucet(settings.generation_customer_signer_key_path)
    if faucet.address_hex!=puzzle:
        raise ValueError('customer signer differs from the reviewed funding puzzle')
    store=GenerationCustomerStore(settings.generation_customer_db_path,settings.deployment_generation_id)
    funding=ProtocolFundingStore(settings.generation_customer_fee_db_path)
    try:
        faucet.add_coin_reservation_source(store.held_funding_ids)
        faucet.add_coin_reservation_source(journal.reserved_input_coin_ids)
        sender=ProtocolBundleSubmitter(provider=provider,
            faucet=CustomerFeeFaucet(faucet,policy,clock,store,journal),funding_store=funding,
            policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,
                maximum_mojos=policy.fee_cap_mojos,
                maximum_funding_coin_mojos=policy.maximum_fee_parent_mojos,native_admission_enabled=True,
                cost_fee_tiers_enabled=bool(getattr(settings,'protocol_fee_cost_tiers_enabled',False))))
        return GenerationCustomerRuntime(settings=settings,index=index,provider=provider,store=store,
            journal=journal,registry=registry,faucet=faucet,policy=policy,submitter=sender,clock=clock)
    except BaseException:
        funding.close()
        raise
