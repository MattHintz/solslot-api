"""Verify renewal against retained policy and journal evidence."""
from contextlib import closing
from dataclasses import replace
from hashlib import sha256
import json
import sqlite3
from types import SimpleNamespace

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD
from chia_rs import G1Element
import pytest

from solslot_api import generation_customer_purchase_factory as factory
from solslot_api.generation_customer_collection_policy import TestnetCollectionIssuerPolicy as CollectionPolicy
from solslot_api.generation_customer_purchase_cutover import CheckoutCutover, activate_checkout_journal
from solslot_api.generation_customer_purchase_cutover_evidence import checkout_journal_snapshots
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_fees import CurrentPurchaseFeeAuthority, read_purchase_fee_renewal
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.generation_customer_purchase_worker import CurrentPurchaseWorker
from solslot_api.generation_customer_runtime import GenerationCustomerRuntime
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from tests.test_current_purchase_fee_guard import guarded
from tests.test_current_purchase_store import BROWSER
from tests.test_generation_customer_purchase_reservation_claim import body


def pin(path, data):
    raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    path.write_bytes(raw)
    return str(path), '0x' + sha256(raw).hexdigest()


@pytest.fixture
def renewal(tmp_path, guarded):
    original, prior = guarded.authority, guarded.policy
    proceeds = Program.from_bytes(bytes(MOD)).curry(G1Element.from_bytes(prior.issuer_public_key)).get_tree_hash()
    prior = replace(prior, proceeds_puzzle=proceeds)
    policy = CollectionPolicy(
        prior.generation, prior.collection, prior.edition, prior.metadata_root,
        prior.proceeds_puzzle, prior.fee_puzzle, prior.issuer_public_key,
        prior.deed_launchers, prior.maximum_gross_mojos,
    )
    authority_data = {
        **original.model_dump(mode='json', by_alias=True),
        'issuerPolicyHash': policy.commitment,
        'feeCoinIds': [*original.fee_coin_ids, '0x' + 'ab' * 32],
        'maximumTotalFeeMojos': 20,
    }
    original = CurrentPurchaseFeeAuthority.model_validate(authority_data)
    renewal_data = {
        **authority_data, 'issuedAt': 250, 'expiresAt': 400,
        'feeCoinIds': list(original.fee_coin_ids[:1]), 'maximumTotalFeeMojos': 10,
    }
    return SimpleNamespace(
        original=original, data=renewal_data, path=tmp_path/'renewal.json',
        policy=policy, prior=prior, guarded=guarded,
    )


@pytest.mark.parametrize('changes', [
    {'issuedAt': 199},
    {'fundingPuzzleHash': '0x' + 'cd' * 32},
    {'issuerPolicyHash': '0x' + 'cd' * 32},
    {'generationId': '0x' + 'cd' * 32},
    {'feeCoinIds': ['0x' + 'cd' * 32]},
    {'maximumStageFeeMojos': 11, 'maximumTotalFeeMojos': 11},
    {'maximumFeeParentMojos': 101},
    {'maximumTotalFeeMojos': 21},
    {'expiresAt': 250 + 48 * 3600 + 1},
])
def test_renewal_requires_same_authority_scope(renewal, changes):
    path, digest = pin(renewal.path, {**renewal.data, **changes})
    with pytest.raises(ValueError, match='(RENEWAL_SCOPE|FEE_POLICY|permitted input)'):
        read_purchase_fee_renewal(path, digest, renewal.policy, renewal.original)


def test_renewal_rejects_unpinned_file_and_prior_policy(renewal):
    path, digest = pin(renewal.path, renewal.data)
    with pytest.raises(ValueError, match='FEE_AUTHORITY_CHANGED'):
        read_purchase_fee_renewal(path, '0x' + 'cd' * 32, renewal.policy, renewal.original)
    with pytest.raises(ValueError, match='COLLECTION_RENEWAL_REQUIRED'):
        read_purchase_fee_renewal(path, digest, renewal.prior, renewal.original)


@pytest.fixture
def renewal_runtime(tmp_path, renewal, monkeypatch):
    original, policy, prior = renewal.original, renewal.policy, renewal.prior
    store = CurrentPurchaseExecutionStore(tmp_path/'renewed-payments.db', original.generation_id)
    claim = CurrentReservationClaim.model_validate({**body(), 'issuerPolicyHash': prior.commitment})
    saved_intent = store.save_review(claim, browser_hash=BROWSER, request_key='saved', now=110)
    fee_path, fee_hash = pin(tmp_path/'fees.json', original.model_dump(mode='json', by_alias=True))
    prior_path, prior_hash = pin(tmp_path/'prior.json', prior.public())
    policy_path, policy_hash = pin(tmp_path/'collection.json', policy.public())
    renewal_path, renewal_hash = pin(renewal.path, renewal.data)
    generation = original.generation_id
    funding = ProtocolFundingStore(generation_path(str(tmp_path/'funding.db'), generation))
    anchor = SimpleNamespace(issuance=SimpleNamespace(generation=policy.generation))
    prior_context = SimpleNamespace(
        network='testnet11', generation_customer_purchase_enabled=True, deployment_generation_id=generation,
    )
    old_checkout = CurrentNativePurchaseExecution(
        settings=prior_context, anchor=anchor, provider=None, policy=prior, store=store, fee_cap=10,
    )
    CurrentPurchaseWorker(old_checkout, issuer_sign=lambda _: pytest.fail('Unexpected signer request'))
    with store._connect() as purchase_db, purchase_db, funding.db:
        purchase_db.execute('BEGIN')
        funding.db.execute('BEGIN')
        snapshots = checkout_journal_snapshots(purchase_db, funding.db)
    evidence = CheckoutCutover.model_validate({
        'schema': 'solslot.testnet-checkout-cutover.v1',
        'generationId': generation, 'anchorHash': '0x' + 'ef' * 32,
        'priorPolicy': prior.commitment, 'collectionPolicy': policy.commitment,
        'feeAuthority': fee_hash, 'feeLimitMojos': 25, 'inheritedFeeMojos': 5,
        'priorIssuerRows': '0x' + '11' * 32, 'purchaseJournalSnapshot': snapshots[0],
        'fundingJournalSnapshot': snapshots[1], 'peakHash': '0x' + '22' * 32,
        'peakHeight': 1, 'transactionTime': 110, 'retiredOrders': [],
    })
    cutover_path, cutover_hash = pin(tmp_path/'cutover.json', evidence.model_dump(mode='json', by_alias=True))
    settings = SimpleNamespace(
        network='testnet11', deployment_generation_id=generation, alpha_writes_enabled=False,
        generation_chain_anchor_hash=evidence.anchor_hash, generation_customer_purchase_enabled=True,
        generation_customer_purchase_funding_enabled=True, payment_purchase_db_path=store.path,
        generation_customer_purchase_policy_path=policy_path, generation_customer_purchase_policy_hash=policy_hash,
        generation_customer_purchase_prior_policy_path=prior_path, generation_customer_purchase_prior_policy_hash=prior_hash,
        generation_customer_purchase_fee_authority_path=fee_path, generation_customer_purchase_fee_authority_hash=fee_hash,
        generation_customer_purchase_cutover_path=cutover_path, generation_customer_purchase_cutover_hash=cutover_hash,
        generation_customer_purchase_fee_renewal_path=renewal_path, generation_customer_purchase_fee_renewal_hash=renewal_hash,
        generation_customer_purchase_fee_signer_key_path='/synthetic/test-only-key',
    )
    customers = object.__new__(GenerationCustomerRuntime)
    customers.settings = settings
    customers.store = SimpleNamespace(generation_id=generation, held_funding_ids=set)
    customers.journal = SimpleNamespace(reserved_input_coin_ids=set)
    customers.index = SimpleNamespace(anchor=anchor)
    customers.provider = SimpleNamespace()
    reads = []
    faucet = renewal.guarded.guard._faucet
    faucet.add_coin_reservation_source = lambda source: None

    def synthetic_key(path):
        reads.append(path)
        return faucet

    monkeypatch.setattr(factory, 'protected_customer_faucet', synthetic_key)

    def start(now):
        return factory.configured_current_customer_purchase(
            settings, customers=customers, funding_store=funding, clock=lambda: now,
        )

    try:
        yield SimpleNamespace(settings=settings, start=start, reads=reads, store=store, funding=funding,
                              cutover=evidence, saved_intent=saved_intent)
    finally:
        funding.close()


def test_renewal_reopens_existing_journal_and_closes_at_expiry(renewal, renewal_runtime):
    settings, start, reads = renewal_runtime.settings, renewal_runtime.start, renewal_runtime.reads
    store, funding = renewal_runtime.store, renewal_runtime.funding
    policy, prior, original = renewal.policy, renewal.prior, renewal.original
    cutover_hash, saved_intent = settings.generation_customer_purchase_cutover_hash, renewal_runtime.saved_intent
    # A renewal must never create the original journal binding.
    with pytest.raises(ValueError, match='RECOVERY_(JOURNAL|POLICY)_REQUIRED'):
        start(250)
    assert reads == []
    activate_checkout_journal(store.path, funding.path, settings=settings, prior=prior, policy=policy)
    assert start(249).submitter.policy.enabled is False
    live = start(250)
    assert live.submitter.policy.enabled is True
    assert live.submitter.faucet.available_fee_ids() == set(original.fee_coin_ids[:1])
    with funding.db:
        funding.db.execute(
            'INSERT INTO funded_protocol_input_history VALUES (?,?,?)',
            ('testnet11', original.fee_coin_ids[0], '0x' + '56' * 32),
        )
    assert live.submitter.faucet.available_fee_ids() == set()
    assert start(400).submitter.policy.enabled is False
    assert reads == ['/synthetic/test-only-key']
    with closing(sqlite3.connect(store.path)) as db:
        assert db.execute('SELECT policy_hash,cutover_hash,fee_cap FROM current_purchase_collection_execution').fetchall() == [
            (policy.commitment, cutover_hash, 10),
        ]
        assert db.execute('SELECT intent_id FROM current_customer_purchase_reviews').fetchall() == [(saved_intent,)]
