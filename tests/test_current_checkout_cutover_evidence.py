"""Use real local journals and signed bundles against a controlled primary."""
import json
import time
from types import SimpleNamespace

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
import pytest
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import PurchaseArtifactV3, purchase_artifact_v3_to_json

from solslot_api import generation_customer_purchase_cutover_evidence as evidence
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import PreparedProtocolBundle
from tests.test_current_purchase_store import BROWSER, delivery
from tests.test_generation_customer_purchase_reservation_claim import body


def hex_id(value):
    return '0x' + bytes(value).hex()


def hash_id(value):
    return hex_id(bytes([value]) * 32)


class Primary:
    def __init__(self, height, timestamp):
        self.primary = object()
        self.height, self.timestamp = height, timestamp
        self.header_hash = hash_id(20)
        self.settled = {}
        self.on_observe = None

    async def get_network_info_primary(self):
        return {'success': True, 'network_name': 'testnet11'}

    async def get_blockchain_state_primary(self):
        return {'success': True, 'blockchain_state': {
            'sync': {'synced': True, 'sync_mode': False},
            'peak': {'height': self.height, 'header_hash': self.header_hash},
        }}

    async def get_fee_estimate(self, *, target_times, cost, require_primary):
        assert require_primary
        return {'full_node_synced': True, 'peak_height': self.height, 'mempool_size': 0,
                'mempool_max_size': 1, 'last_peak_timestamp': self.timestamp,
                'node_time_utc': int(time.time())}

    async def observe_exact_protocol_bundle(self, document):
        if self.on_observe:
            self.on_observe()
        identity = hex_id(SpendBundle.from_json_dict(document).name())
        return self.settled.get(identity)


@pytest.fixture
def scenario(tmp_path):
    generation = body()['generationId']
    policy, predecessor, collection = hash_id(3), hash_id(10), hash_id(11)
    store = CurrentPurchaseExecutionStore(tmp_path / 'payment.db', generation)
    funding = ProtocolFundingStore(generation_path(str(tmp_path / 'funding.db'), generation))
    store.bind_execution_policy(policy, 5, 100)
    store.bind_execution_policy(predecessor, 5, 50)
    with store._connect() as db:
        db.execute('''CREATE TABLE current_purchase_worker_jobs (
            intent_id TEXT PRIMARY KEY, lease_token TEXT, lease_until INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'WAITING', issuer_document TEXT, error_code TEXT, expiry_document TEXT)''')

    timestamp = int(time.time())
    expiry = timestamp - 60
    primary = Primary(5_000_000, timestamp)
    puzzle = Program.to(1)
    puzzle_hash = puzzle.get_tree_hash()
    def make_review(label, parent, policy_hash):
        coin = Coin(bytes32.from_hexstr(hash_id(parent)), puzzle_hash, uint64(1))
        def tag(value):
            return bytes32.from_hexstr(hash_id(value))
        artifact = PurchaseArtifactV3(
            network='testnet11', collection_id=tag(20), deed_launcher_id=tag(21),
            metadata_root=tag(22), metadata_anchor_id=tag(23), share_ppm=40000,
            base_amount_minor=100, technology_fee_bps=100, technology_fee_minor=1, subtotal_minor=101,
            protocol_treasury_puzzle_hash=tag(26), zkpassport_root=tag(25),
            rail=PaymentRail.CHIA_XCH, rail_chain_id=0, rail_asset_id=bytes32.zeros,
            rail_asset_decimals=12, rail_amount=101_000_000_000, vault_launcher_id=tag(27),
            vault_p2_puzzle_hash=tag(24), authorization_nonce=tag(parent),
            authorization_expires_at=expiry, quote_expires_at=expiry,
            oracle_round_hash=tag(28), oracle_price_usd_minor_per_asset=1000, source_evidence_root=tag(29),
        )
        claim = CurrentReservationClaim.model_validate({
            **body(), 'issuerPolicyHash': policy_hash, 'availableCoinId': hex_id(coin.name()),
            'purchaseArtifact': purchase_artifact_v3_to_json(artifact),
        })
        identity = store.save_review(claim, browser_hash=BROWSER, request_key=label, now=expiry - 200)
        message = evidence.inventory_reservation_message(available_coin=coin,
            reservation=evidence.InventoryReservationV1(artifact, expiry))
        keys = [AugSchemeMPL.key_gen(bytes([i]) * 32) for i in (41, 42)]
        conditions = [[51, puzzle_hash, 1], [85, expiry], *[[50, key.get_g1(), message] for key in keys]]
        spend = make_spend(coin, puzzle, Program.to(conditions))
        signature = AugSchemeMPL.aggregate([AugSchemeMPL.sign(key, message + coin.name() + AGG_SIG_ME_DATA['testnet11'])
                                            for key in keys])
        return identity, claim, SpendBundle([spend], signature)

    def prepare(identity, claim, bundle, phase, *, cap=100):
        if phase == 'RESERVATION':
            store.request_reservation(identity, browser_hash=BROWSER, now=expiry - 180)
        store.prepare_execution(identity, phase, bundle, browser_hash=BROWSER,
            claim_hash=claim.digest(), fee_cap=cap, expires_at=expiry, now=expiry - 150)

    def settle(identity, bundle, phase, *, fee, fee_parent, height):
        coin = Coin(bytes32.from_hexstr(hash_id(fee_parent)), puzzle_hash, uint64(1000))
        fee_spend = make_spend(coin, puzzle, Program.to([[51, puzzle_hash, 1000 - fee], [52, fee]]))
        funded = SpendBundle([*bundle.coin_spends, fee_spend], bundle.aggregated_signature)
        prepared = PreparedProtocolBundle(funded, fee, hex_id(coin.name()))
        funding.reserve('testnet11', hex_id(bundle.name()),
            {'feeTill': hex_id(puzzle_hash), 'purpose': None, 'backingMojos': 0},
            {**prepared.to_json(), 'protocolSpendBundle': bundle.to_json_dict()})
        store.save_execution_funding(identity, phase, prepared, browser_hash=BROWSER, now=expiry - 120)
        store.observe_execution(identity, phase, browser_hash=BROWSER, transaction_id=prepared.spend_bundle_id,
                                status='CONFIRMED', confirmed_height=height, now=expiry - 100)
        primary.settled[prepared.spend_bundle_id] = {
            'status': 'CONFIRMED', 'provider': 'local-full-node', 'confirmed_height': height,
        }
        return prepared.spend_bundle_id

    released, released_claim, reservation = make_review('released', 31, predecessor)
    prepare(released, released_claim, reservation, 'RESERVATION', cap=50)
    funded_reservation = settle(released, reservation, 'RESERVATION', fee=7, fee_parent=35, height=4_999_000)
    reserved = reservation.additions()[0]
    release = SpendBundle([make_spend(reserved, puzzle, Program.to([[51, puzzle_hash, 1], [81, expiry]]))],
                          G2Element())
    prepare(released, released_claim, release, 'RELEASE', cap=50)
    funded_release = settle(released, release, 'RELEASE', fee=11, fee_parent=36, height=4_999_010)

    expired, expired_claim, original = make_review('expired', 32, policy)
    prepare(expired, expired_claim, original, 'RESERVATION')
    bundle_id = hex_id(original.name())
    inputs = [hex_id(original.removals()[0].name())]
    proof = {
        'schema': 'solslot.current-unsubmitted-reservation-expiry.v1', 'generationId': generation,
        'intentId': expired, 'reservationClaimHash': expired_claim.digest(), 'bundleId': bundle_id,
        'absoluteExpiry': expiry, 'inputIds': inputs, 'peakHeight': primary.height - 100,
        'peakTimestamp': timestamp - 30, 'allInputsUnspentAndClear': True,
    }
    with store._connect() as db:
        db.execute("INSERT INTO current_purchase_worker_jobs(intent_id,state) VALUES(?, 'RELEASED')", (released,))
        db.execute("INSERT INTO current_purchase_worker_jobs(intent_id,state,expiry_document) VALUES(?, 'CLOSED', ?)",
                   (expired, json.dumps(proof)))

    unstarted, _, _ = make_review('unstarted', 33, predecessor)
    fresh = {
        **proof, 'peakHeight': primary.height, 'peakTimestamp': timestamp, 'allInputsUnspentAndClear': False,
        'allInputsKnownAndNoPendingSpends': True, 'externalInputEvidence': [
            {'coinId': inputs[0], 'confirmedHeight': 4_999_000, 'spentHeight': 4_999_001,
             'matchesSavedSpend': False},
        ],
    }

    async def prove(bundle, *, allow_confirmed_conflicts):
        assert allow_confirmed_conflicts and bytes(bundle) == bytes(original)
        return fresh

    submitter = SimpleNamespace(provider=primary, faucet=SimpleNamespace(network='testnet11'),
                                policy=SimpleNamespace(target_seconds=60), prove_expired_bundle=prove)

    async def collect(fee_limit=1000):
        return await evidence.collect_checkout_cutover_evidence(store.path, funding.path, submitter=submitter,
            generation_id=generation, anchor_hash=body()['anchorHash'], prior_policy=policy,
            collection_policy=collection, fee_authority=hash_id(51), prior_issuer_rows=hash_id(52),
            fee_limit_mojos=fee_limit)

    yield SimpleNamespace(collect=collect, store=store, funding=funding, released=released, expired=expired,
                          unstarted=unstarted, primary=primary, proof=fresh, funded_reservation=funded_reservation,
                          funded_release=funded_release, expired_bundle_id=bundle_id, released_claim=released_claim)
    funding.close()


@pytest.mark.asyncio
async def test_exact_whole_journal_closure_includes_older_policy_and_exposure(scenario):
    r = scenario
    result = await r.collect()
    assert result.confirmed_fee_mojos == 18
    assert result.unfunded_fee_mojos == 100
    assert result.cutover.inherited_fee_mojos == 118
    assert {order.intent_id: order.outcome for order in result.cutover.retired_orders} == {
        r.expired: 'UNSUBMITTED_EXPIRED', r.released: 'RELEASED', r.unstarted: 'UNSTARTED',
    }
    assert result == await r.collect()
    with pytest.raises(ValueError, match='LINEAGE_LIMIT_EXCEEDED'):
        await r.collect(117)


@pytest.mark.asyncio
@pytest.mark.parametrize('proof_change', ['confirmed_exact', 'pending', 'changed_peak'])
async def test_expired_prepared_keeps_any_unresolved_spend(scenario, proof_change):
    r = scenario
    if proof_change == 'confirmed_exact':
        r.proof['externalInputEvidence'][0]['matchesSavedSpend'] = True
    elif proof_change == 'pending':
        r.proof['allInputsKnownAndNoPendingSpends'] = False
    else:
        r.proof['peakHeight'] -= 1
    with pytest.raises(ValueError, match='PRIMARY_EXPIRY_CHANGED'):
        await r.collect()


@pytest.mark.asyncio
async def test_unresolved_funding_history_blocks_retirement(scenario):
    r = scenario
    r.funding.event('testnet11', r.expired_bundle_id, 'dispatching')
    with pytest.raises(ValueError, match='PREPARED_FUNDING_HISTORY_PRESENT'):
        await r.collect()


@pytest.mark.asyncio
async def test_old_release_requires_exact_primary_confirmation(scenario):
    r = scenario
    r.primary.settled[r.funded_release]['confirmed_height'] -= 1
    with pytest.raises(ValueError, match='CONFIRMATION_CHANGED'):
        await r.collect()


@pytest.mark.asyncio
async def test_orphaned_funding_cannot_disappear_with_restored_purchase_journal(scenario):
    r = scenario
    coin_id = r.released_claim.available_coin_id
    with r.funding.lock:
        r.funding.db.execute("INSERT INTO funded_protocol_input_history VALUES('testnet11',?,?)",
                             (coin_id, hash_id(91)))
    with pytest.raises(ValueError, match='ORPHAN_CHECKOUT_FUNDING'):
        await r.collect()


@pytest.mark.asyncio
async def test_fee_metadata_must_match_the_actual_confirmed_sponsor_spend(scenario):
    r = scenario
    with r.store._connect() as db:
        row = db.execute('SELECT original_id,funded_document FROM current_purchase_executions WHERE transaction_id=?',
                         (r.funded_reservation,)).fetchone()
        document = json.loads(row['funded_document'])
        document['feeMojos'] = '1'
        db.execute('UPDATE current_purchase_executions SET funded_document=? WHERE original_id=?',
                   (evidence.canonical(document), row['original_id']))
    with r.funding.lock:
        original = json.loads(r.funding.db.execute('SELECT document FROM funded_protocol_bundles WHERE original_id=?',
                                                 (row['original_id'],)).fetchone()[0])
        original['feeMojos'] = '1'
        r.funding.db.execute('UPDATE funded_protocol_bundles SET document=? WHERE original_id=?',
                             (evidence.canonical(original), row['original_id']))
    with pytest.raises(ValueError, match='FUNDING_AMOUNT_CHANGED'):
        await r.collect()


@pytest.mark.asyncio
async def test_retirement_refuses_active_lease_or_saved_payment(scenario):
    r = scenario
    with r.store._connect() as db:
        db.execute("UPDATE current_purchase_worker_jobs SET lease_token='running' WHERE intent_id=?", (r.expired,))
    with pytest.raises(ValueError, match='WORKER_LEASE_PRESENT'):
        await r.collect()
    with r.store._connect() as db:
        db.execute("UPDATE current_purchase_worker_jobs SET lease_token=NULL WHERE intent_id=?", (r.expired,))
    r.store.save_delivery(r.released, delivery(r.released_claim), browser_hash=BROWSER, now=int(time.time()))
    with pytest.raises(ValueError, match='RELEASE_OPEN_OR_SAVED_PAYMENT'):
        await r.collect()


@pytest.mark.asyncio
async def test_primary_tip_and_both_journals_must_remain_stable(scenario):
    r = scenario
    r.primary.on_observe = lambda: setattr(r.primary, 'header_hash', hash_id(90))
    with pytest.raises(ValueError, match='PRIMARY_CHANGED'):
        await r.collect()
    r.primary.on_observe = lambda: r.funding.event('testnet11', r.expired_bundle_id, 'changed')
    with pytest.raises(ValueError, match='JOURNAL_CHANGED'):
        await r.collect()
