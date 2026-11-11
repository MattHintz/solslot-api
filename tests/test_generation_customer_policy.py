"""Finite funding authority and disabled startup boundaries."""
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
import json

import pytest
from chia.types.blockchain_format.program import Program

from solslot_api.generation_customer_factory import configured_generation_customers,load_customer_policy,protected_customer_faucet
from solslot_api.generation_customer_runtime import CustomerCreationPolicy
from solslot_api.generation_customer_signer import ReviewedCustomerSigner,CustomerFeeFaucet
from solslot_api.generation_customer_store import GenerationCustomerStore
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_api.server_hardening import ServerHardeningMiddleware
from tests.test_generation_customer_launch import fixture,sign

GEN='0x'+'67'*32
PARENT='0x'+'11'*32
FEE='0x'+'22'*32


def policy():
    return CustomerCreationPolicy(GEN,frozenset([PARENT]),10000,100,1000,2000,frozenset([FEE]),10000)


@pytest.mark.parametrize('field,value',[
    ('generation_id','0x'+'ab'*32),('expires_at',1000),('expires_at',1000+172801),
    ('issued_at',True),('maximum_parent_mojos',True),('fee_cap_mojos',1000000001),
    ('allowed_parent_ids',frozenset()),('allowed_fee_ids',frozenset()),
    ('allowed_fee_ids',frozenset([PARENT])),('allowed_parent_ids',frozenset(['bad'])),
])
def test_policy_rejects_changed_generation_expiry_and_unbounded_authority(field,value):
    with pytest.raises(ValueError):replace(policy(),**{field:value}).validate(GEN,1100)


def test_frozen_policy_hash_and_no_key_read_for_disabled_feature(tmp_path):
    assert configured_generation_customers(SimpleNamespace(generation_customer_enabled=False),
        index=None,provider=None,journal=None,registry=None) is None
    assert not list(tmp_path.iterdir())
    value=dict(schema='solslot.customer-funding-policy.v1',generationId=GEN,
        fundingPuzzleHash='0x'+'33'*32,creationParentIds=[PARENT],feeParentIds=[FEE],
        maximumCreationParentMojos=10000,maximumFeeParentMojos=10000,maximumFeeMojos=100,
        issuedAt=1000,expiresAt=2000)
    path=tmp_path/'policy.json';path.write_text(json.dumps(value))
    digest='0x'+sha256(path.read_bytes()).hexdigest()
    assert load_customer_policy(path,digest,GEN,now=1100)[0]==policy()
    path.write_text(json.dumps({**value,'maximumFeeMojos':1000}))
    with pytest.raises(ValueError,match='frozen source'):load_customer_policy(path,digest,GEN,now=1100)


def test_runtime_secret_is_not_read_through_symlink_or_world_readable_file(tmp_path):
    source=tmp_path/'synthetic-key';source.write_text('04'*32);source.chmod(0o644)
    with pytest.raises(ValueError,match='protected'):protected_customer_faucet(source)
    source.chmod(0o400)
    assert protected_customer_faucet(source).network=='testnet11'
    link=tmp_path/'key-link';link.symlink_to(source)
    with pytest.raises(OSError):protected_customer_faucet(link)


def test_scoped_signer_rejects_another_execution_hold_and_fee_only_extraction(tmp_path):
    faucet,funding,bindings,consent,secret=fixture()
    store=GenerationCustomerStore(str(tmp_path/'customers.db'),'0x'+bindings.generation.hex())
    identity=store.reserve(consent,now=1000)['registrationId']
    store.accept_signature(identity,sign(consent,secret),now=1000)
    faucet.add_coin_reservation_source(store.held_funding_ids)
    signer=ReviewedCustomerSigner(faucet,store,identity,funding,bindings=bindings,maximum_parent_amount=10000)
    with pytest.raises(ValueError,match='changed output'):
        signer.sign_delegated_spend(funding,Program.to([[51,funding.puzzle_hash,9999]]))
    faucet.add_coin_reservation_source(lambda:[consent.message()['fundingCoinId']])
    with pytest.raises(ValueError,match='another retained execution'):
        signer.sign_delegated_spend(funding,Program.to([]))
    # No saved reviewed native operation authorizes a standalone fee donation.
    scoped=replace(policy(),generation_id=store.generation_id,
        allowed_parent_ids=frozenset([PARENT]),allowed_fee_ids=frozenset([consent.message()['fundingCoinId']]))
    journal=GenerationOperationJournal(str(tmp_path/'ops.db'),store.generation_id)
    fees=CustomerFeeFaucet(faucet,scoped,lambda:1100,store,journal)
    with pytest.raises(ValueError,match='exact retained registration'):
        fees.sign_delegated_spend(funding,Program.to([[51,funding.puzzle_hash,9999],[52,1]]))


@pytest.mark.parametrize('path',[
    '/customer/registration/reviews','/customer/registration/reviews/malformed/authorize',
    '/customer/registration/reviews/malformed/prepare','/customer/registration/reviews/malformed/submit',
    '/customer/registration/reviews/malformed/connect',
])
def test_customer_mutations_share_challenge_budget_before_body_validation(path):
    assert ServerHardeningMiddleware._is_public_challenge_request({'method':'POST','path':path})
    assert not ServerHardeningMiddleware._is_public_challenge_request({'method':'GET','path':path})
    assert ServerHardeningMiddleware._is_public_challenge_request({'method':'POST',
        'root_path':'/protocol-api/next','path':'/protocol-api/next'+path})
