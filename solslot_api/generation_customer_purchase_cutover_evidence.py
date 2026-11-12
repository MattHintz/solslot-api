"""Read-only reconciliation for retiring a generation's finite Testnet checkout.

The operator must fence all writers before collecting evidence. The caller
must check the two journal snapshots again under its final transaction and
verify issuer evidence separately before activating collection authority.
"""
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3

from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, inventory_reservation_message

from .generation_customer_purchase_batch import (
    CurrentReservationBatch, artifacts, delivery_from_json, reservation_from_json,
)
from .generation_customer_purchase_cutover import CheckoutCutover, RetiredCheckout
from .generation_customer_purchase_expiry_proof import valid_expiry_proof
from .generation_customer_purchase_fee_lineage import FeeExposure, calculate_fee_lineage
from .generation_operations import bundle_id, canonical
from .protocol_admission import admission_conditions, primary_admission_state
from .protocol_funding_store import valid_expired_input_evidence
from .protocol_submission import PreparedProtocolBundle
from .validator_quorum import ValidatorSignatureResponse
from .wallet_offer_validation import decode_offer


_NETWORK = 'testnet11'
_PURCHASE = {
    'deployment_generation_binding': 'singleton',
    'current_purchase_execution_policies': 'policy_hash',
    'current_customer_purchase_reviews': 'intent_id',
    'current_customer_reservation_requests': 'intent_id',
    'current_customer_purchase_signatures': 'intent_id,phase,signer_index',
    'current_customer_purchase_delivery': 'intent_id',
    'current_purchase_executions': 'intent_id,phase',
    'current_purchase_worker_jobs': 'intent_id',
}
_FUNDING = {
    'deployment_generation_binding': 'singleton',
    'funded_protocol_bundles': 'network,original_id',
    'funded_protocol_inputs': 'network,coin_id',
    'funded_protocol_input_history': 'network,coin_id,original_id',
    'funded_protocol_releases': 'network,original_id',
    'funded_protocol_events': 'id',
    'funded_protocol_completions': 'network,original_id',
}


@dataclass(frozen=True)
class CheckoutCutoverEvidence:
    cutover: CheckoutCutover
    confirmed_fee_mojos: int
    unfunded_fee_mojos: int


def _require(condition, code):
    if not condition:
        raise ValueError('CURRENT_CHECKOUT_CUTOVER_' + code)


def _hash(data):
    return '0x' + sha256(data).hexdigest()


def _hex(value):
    return '0x' + bytes(value).hex()


def _snapshot(db, tables):
    _require(db.in_transaction, 'SNAPSHOT_TRANSACTION_REQUIRED')
    digest = sha256()
    for name, order in tables.items():
        cursor = db.execute(f'SELECT * FROM {name} ORDER BY {order}')
        digest.update(canonical([name, [column[0] for column in cursor.description]]).encode() + b'\n')
        for row in cursor:
            values = [{'blobSha256': _hash(value)} if isinstance(value, bytes) else value for value in row]
            digest.update(canonical(values).encode() + b'\n')
    return '0x' + digest.hexdigest()


def checkout_journal_snapshots(purchase_db, funding_db):
    """Commit to all retained checkout rows and all funding history.

    The caller supplies open transactions. The hash includes row/column order
    explicitly and omits worker heartbeat telemetry.
    """
    return _snapshot(purchase_db, _PURCHASE), _snapshot(funding_db, _FUNDING)


def _open_read_only(path):
    db = sqlite3.connect(Path(path).absolute().as_uri() + '?mode=ro', uri=True)
    try:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        return db
    except BaseException:
        db.close()
        raise


async def _primary_peak(submitter, node):
    provider = submitter.provider
    _require(node is not None and provider.primary is node, 'PRIMARY_CHANGED')
    info = await provider.get_network_info_primary()
    state = await provider.get_blockchain_state_primary()
    quote = await provider.get_fee_estimate(
        target_times=[submitter.policy.target_seconds], cost=1, require_primary=True)
    height, _, _, timestamp = primary_admission_state(quote)
    chain = state['blockchain_state']
    peak = chain['peak']
    _require(info.get('success') is True and info.get('network_name') == _NETWORK
             and state.get('success') is True and chain['sync']['synced'] is True
             and chain['sync']['sync_mode'] is False
             and type(peak['height']) is int and peak['height'] == height
             and provider.primary is node, 'PRIMARY_CHANGED')
    return _hex(bytes32.from_hexstr(peak['header_hash'])), height, timestamp


def _stored_bundle(row):
    bundle = SpendBundle.from_bytes(row['protocol_bundle'])
    inputs = bundle.removals()
    _require(bytes(bundle) == row['protocol_bundle'] and bundle_id(bundle) == row['original_id']
             and 1 <= len(inputs) <= 256 and len({coin.name() for coin in inputs}) == len(inputs),
             'ORIGINAL_BUNDLE_CHANGED')
    return bundle


def _reservation_outputs(original, children, selected):
    inputs = {_hex(spend.coin.name()): spend for spend in original.coin_spends}
    _require(set(inputs) == {child.available_coin_id for child in children}, 'RESERVATION_INPUTS_CHANGED')
    outputs = []
    for child, artifact in zip(children, selected, strict=True):
        spend = inputs[child.available_coin_id]
        expected = inventory_reservation_message(available_coin=spend.coin,
            reservation=InventoryReservationV1(artifact, artifact.quote_expires_at))
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 100_000_000)
        signatures = conditions.get(ConditionOpcode.AGG_SIG_ME, ())
        _require(len(signatures) == len(child.signer_indices)
                 and all(len(signature.vars) == 2 and signature.vars[1] == expected for signature in signatures),
                 'RESERVATION_ARTIFACT_CHANGED')
        coins, _ = compute_additions_with_cost(spend, max_cost=100_000_000)
        successors = [coin for coin in coins if coin.amount % 2]
        _require(len(successors) == 1 and successors[0].amount == 1, 'RESERVATION_OUTPUT_CHANGED')
        outputs.append(_hex(successors[0].name()))
    return tuple(outputs)


def _require_timeout(original, reserved, reservation, children):
    spends = {_hex(spend.coin.name()): spend for spend in original.coin_spends}
    _require(set(spends) == set(reserved) and original.aggregated_signature == G2Element(),
             'RELEASE_INPUTS_CHANGED')
    sources = {_hex(spend.coin.name()): spend for spend in reservation.coin_spends}
    for identity, child in zip(reserved, children, strict=True):
        source = sources[child.available_coin_id]
        coins, _ = compute_additions_with_cost(spends[identity], max_cost=100_000_000)
        successors = [coin for coin in coins if coin.amount % 2]
        _require(len(successors) == 1 and successors[0].amount == 1
                 and successors[0].puzzle_hash == source.coin.puzzle_hash, 'RELEASE_OUTPUT_CHANGED')


def _funding_record(db, original_id):
    return db.execute('SELECT * FROM funded_protocol_bundles WHERE network=? AND original_id=?',
                      (_NETWORK, original_id)).fetchone()


def _require_no_orphan_funding(db, input_ids, original_ids):
    # An independently restored purchase journal could lose its execution row
    # while the funding journal still retains the signed transaction.
    for table in ('funded_protocol_inputs', 'funded_protocol_input_history'):
        for coin_id, original_id in db.execute(f'SELECT coin_id,original_id FROM {table} WHERE network=?', (_NETWORK,)):
            _require(coin_id not in input_ids or original_id in original_ids, 'ORPHAN_CHECKOUT_FUNDING')


async def _confirmed_execution(db, submitter, row, original, peak_height):
    height = row['confirmed_height']
    _require(row['stage'] == 'CONFIRMED' and type(height) is int and 0 < height <= peak_height
             and row['funded_document'] is not None and row['error_code'] is None, 'EXECUTION_OPEN')
    record = _funding_record(db, row['original_id'])
    _require(record is not None, 'FUNDING_RECORD_MISSING')
    saved = json.loads(row['funded_document'])
    durable = json.loads(record['document'])
    stored_original = durable.pop('protocolSpendBundle', None)
    _require(durable == saved and canonical(saved) == row['funded_document']
             and stored_original == original.to_json_dict(), 'FUNDING_RECORD_CHANGED')
    funded = SpendBundle.from_json_dict(saved['spendBundle'])
    fee = int(saved['feeMojos'])
    prepared = PreparedProtocolBundle(funded, fee, saved['feeCoinId'], 0)
    _require(prepared.to_json() == saved and row['transaction_id'] == bundle_id(funded)
             and 0 <= fee <= row['fee_cap'], 'FUNDING_DOCUMENT_CHANGED')

    by_input = {_hex(spend.coin.name()): spend for spend in funded.coin_spends}
    original_inputs = {_hex(spend.coin.name()): spend for spend in original.coin_spends}
    fee_id = prepared.fee_coin_id
    _require(len(by_input) == len(funded.coin_spends) and fee_id not in original_inputs
             and set(by_input) == set(original_inputs) | {fee_id}
             and all(by_input[identity] == spend for identity, spend in original_inputs.items()),
             'FUNDED_PROTOCOL_CHANGED')
    fee_spend = by_input[fee_id]
    fee_outputs, _ = compute_additions_with_cost(fee_spend, max_cost=100_000_000)
    fee_puzzle = fee_spend.coin.puzzle_hash
    _require(record['context'] == canonical({'feeTill': _hex(fee_puzzle), 'purpose': None, 'backingMojos': 0})
             and all(coin.puzzle_hash == fee_puzzle for coin in fee_outputs)
             and int(fee_spend.coin.amount) - sum(int(coin.amount) for coin in fee_outputs) == fee,
             'FUNDING_AMOUNT_CHANGED')
    held = db.execute('SELECT coin_id FROM funded_protocol_input_history WHERE network=? AND original_id=?',
                      (_NETWORK, row['original_id'])).fetchall()
    _require({item[0] for item in held} == set(by_input)
             and db.execute('SELECT 1 FROM funded_protocol_releases WHERE network=? AND original_id=?',
                            (_NETWORK, row['original_id'])).fetchone() is None,
             'FUNDING_HISTORY_CHANGED')
    admission_conditions(funded, height, _NETWORK)
    observed = await submitter.provider.observe_exact_protocol_bundle(funded.to_json_dict())
    _require(observed and observed.get('provider') == 'local-full-node'
             and observed.get('status') == 'CONFIRMED' and observed.get('confirmed_height') == height,
             'CONFIRMATION_CHANGED')
    return FeeExposure(row['transaction_id'], fee, 'CONFIRMED')


async def _expired_execution(db, submitter, row, original, job, expiry, peak, generation_id):
    _, height, timestamp = peak
    _require(row['stage'] == 'PREPARED' and row['funded_document'] is None
             and row['transaction_id'] is None and row['confirmed_height'] is None
             and row['expires_at'] == expiry and job['state'] == 'CLOSED'
             and job['issuer_document'] is None and job['expiry_document'] is not None
             and len(job['expiry_document'].encode()) <= 4096
             and _funding_record(db, row['original_id']) is None, 'PREPARED_EXECUTION_OPEN')
    for table in _FUNDING:
        if table in ('deployment_generation_binding', 'funded_protocol_bundles'):
            continue
        _require(db.execute(f'SELECT 1 FROM {table} WHERE network=? AND original_id=?',
                            (_NETWORK, row['original_id'])).fetchone() is None,
                 'PREPARED_FUNDING_HISTORY_PRESENT')
    retained = json.loads(job['expiry_document'])
    inputs = sorted(_hex(coin.name()) for coin in original.removals())
    binding = {'schema': 'solslot.current-unsubmitted-reservation-expiry.v1',
               'generationId': generation_id, 'intentId': row['intent_id'],
               'reservationClaimHash': row['claim_hash'], 'bundleId': row['original_id'],
               'absoluteExpiry': expiry, 'inputIds': inputs}
    _require(valid_expiry_proof(retained, binding)
             and retained['peakHeight'] <= height and retained['peakTimestamp'] <= timestamp,
             'RETAINED_EXPIRY_CHANGED')
    proof = await submitter.prove_expired_bundle(original, allow_confirmed_conflicts=True)
    _require(proof.get('bundleId') == row['original_id'] and proof.get('absoluteExpiry') == expiry
             and proof.get('peakHeight') == height and proof.get('peakTimestamp') == timestamp
             and proof.get('inputIds') == inputs and valid_expired_input_evidence(original, proof)
             and bool(proof['externalInputEvidence'])
             and all(item.get('matchesSavedSpend') is False for item in proof['externalInputEvidence']),
             'PRIMARY_EXPIRY_CHANGED')
    return FeeExposure(row['original_id'], row['fee_cap'], 'PREPARED')


def _group_rows(db, table, identities):
    rows = {identity: [] for identity in identities}
    for row in db.execute(f'SELECT * FROM {table}'):
        _require(row['intent_id'] in rows, 'ORPHAN_CHECKOUT_ROW')
        rows[row['intent_id']].append(dict(row))
    return rows


async def _retire_review(
    review, policies, rows, funding, submitter, peak, generation_id, anchor_hash, collection_policy, checkout_inputs,
):
    identity = review['intent_id']
    reservation = reservation_from_json(review['canonical_claim'])
    children = reservation.children if isinstance(reservation, CurrentReservationBatch) else (reservation,)
    selected = artifacts(reservation)
    policy_hash = reservation.issuer_policy_hash
    expected_intent = _hash(canonical([generation_id, review['browser_hash'], review['request_key']]).encode())
    _require(review['generation_id'] == reservation.generation_id == generation_id
             and identity == expected_intent
             and reservation.digest() == review['claim_hash']
             and reservation.canonical() == review['canonical_claim']
             and policy_hash != collection_policy
             and policy_hash in policies
             and all(child.anchor_hash == anchor_hash for child in children)
             and bool(selected) and all(artifact.network == _NETWORK and artifact.rail == PaymentRail.CHIA_XCH
                                        and 0 < artifact.quote_expires_at <= peak[2] for artifact in selected),
             'REVIEW_OPEN_OR_CHANGED')
    checkout_inputs.update(child.available_coin_id for child in children)
    delivery_rows, signature_rows, request_rows, execution_rows, job_rows = (table[identity] for table in rows)
    _require(all(len(group) <= 1 for group in (delivery_rows, request_rows, job_rows)), 'DUPLICATE_CHECKOUT_ROW')
    job = job_rows[0] if job_rows else None
    _require(job is None or (job['lease_token'] is None and job['lease_until'] == 0), 'WORKER_LEASE_PRESENT')
    delivery = delivery_from_json(delivery_rows[0]['canonical_claim']) if delivery_rows else None
    if delivery is not None:
        _require(delivery.reservation.canonical() == reservation.canonical()
                 and delivery.canonical() == delivery_rows[0]['canonical_claim']
                 and delivery.digest() == delivery_rows[0]['claim_hash'], 'SAVED_DELIVERY_CHANGED')

    signatures = set()
    for row in signature_rows:
        phase, index = row['phase'], row['signer_index']
        reply = ValidatorSignatureResponse.model_validate_json(row['canonical_reply'])
        expected = review['claim_hash'] if phase == 'reservation' else delivery.digest() if delivery else None
        _require(phase in ('reservation', 'delivery') and index in reservation.signer_indices
                 and reply.signerIndex == index and reply.claimHash == expected
                 and (phase, index) not in signatures, 'SAVED_SIGNATURE_CHANGED')
        signatures.add((phase, index))

    executions = {row['phase']: row for row in execution_rows}
    _require(len(executions) == len(execution_rows) and set(executions) <= {'RESERVATION', 'DELIVERY', 'RELEASE'},
             'EXECUTION_PHASE_CHANGED')
    if not executions:
        _require(not request_rows and job is None and delivery is None
                 and len(signatures) < len(reservation.signer_indices), 'UNSTARTED_REVIEW_OPEN')
        return RetiredCheckout(intentId=identity, claimHash=review['claim_hash'], outcome='UNSTARTED'), []

    _require('RESERVATION' in executions and request_rows and job is not None, 'EXECUTION_OR_JOB_MISSING')
    fee_cap = policies[policy_hash]
    expiry = min(artifact.quote_expires_at for artifact in selected)
    bundles = {}
    for phase, row in executions.items():
        _require(row['fee_cap'] == fee_cap and type(row['expires_at']) is int
                 and 0 < row['updated_at']
                 and row['claim_hash'] == (delivery.digest() if phase == 'DELIVERY' and delivery else review['claim_hash'])
                 and (phase == 'RELEASE' or row['expires_at'] == expiry), 'EXECUTION_BINDING_CHANGED')
        bundles[phase] = _stored_bundle(row)
    reserved = _reservation_outputs(bundles['RESERVATION'], children, selected)
    checkout_inputs.update(reserved)
    if set(executions) == {'RESERVATION'}:
        _require(delivery is None, 'SAVED_PAYMENT_OPEN')
        exposure = await _expired_execution(funding, submitter, executions['RESERVATION'],
            bundles['RESERVATION'], job, expiry, peak, generation_id)
        outcome, exposures = 'UNSUBMITTED_EXPIRED', [exposure]
    elif set(executions) == {'RESERVATION', 'RELEASE'}:
        _require(delivery is None and job['state'] == 'RELEASED' and job['issuer_document'] is None
                 and job['expiry_document'] is None, 'RELEASE_OPEN_OR_SAVED_PAYMENT')
        _require_timeout(bundles['RELEASE'], reserved, bundles['RESERVATION'], children)
        outcome, exposures = 'RELEASED', []
    else:
        _require(set(executions) == {'RESERVATION', 'DELIVERY'} and delivery is not None
                 and job['state'] == 'COMPLETE' and job['expiry_document'] is None, 'SAVED_PAYMENT_OPEN')
        delivery_reserved = getattr(delivery, 'reserved_coin_ids', None) or (delivery.reserved_coin_id,)
        offer = decode_offer(delivery.buyer_offer, real_spends=1, dummy_spends=len(selected),
                             expected_assets=frozenset(artifact.deed_launcher_id for artifact in selected),
                             allow_signed=True)
        _require(tuple(delivery_reserved) == reserved
                 and set(reserved) <= {_hex(coin.name()) for coin in bundles['DELIVERY'].removals()}
                 and all(spend in bundles['DELIVERY'].coin_spends for spend in offer.real_spends),
                 'DELIVERY_INPUTS_CHANGED')
        outcome, exposures = 'COMPLETE', []

    if not exposures:
        for phase, row in executions.items():
            exposures.append(await _confirmed_execution(funding, submitter, row, bundles[phase], peak[1]))
        terminal = 'RELEASE' if outcome == 'RELEASED' else 'DELIVERY'
        _require(executions['RESERVATION']['confirmed_height'] <= executions[terminal]['confirmed_height'],
                 'TERMINAL_CONFIRMATION_PRECEDES_RESERVATION')
    return RetiredCheckout(intentId=identity, claimHash=review['claim_hash'], outcome=outcome), exposures


async def collect_checkout_cutover_evidence(
    purchase_path, funding_path, *, submitter, generation_id, anchor_hash, prior_policy,
    collection_policy, fee_authority, prior_issuer_rows, fee_limit_mojos,
):
    """Verify every retained review and its exact funding before forming evidence."""
    node = submitter.provider.primary
    _require(submitter.faucet.network == _NETWORK, 'WRONG_NETWORK')
    with closing(_open_read_only(purchase_path)) as purchase, closing(_open_read_only(funding_path)) as funding:
        for db in (purchase, funding):
            bindings = db.execute('SELECT generation_id,network FROM deployment_generation_binding').fetchall()
            _require([tuple(row) for row in bindings] == [(generation_id, _NETWORK)], 'JOURNAL_SCOPE_CHANGED')
        _require(purchase.execute("SELECT 1 FROM sqlite_master WHERE name='current_purchase_collection_execution'").fetchone()
                 is None, 'ALREADY_ACTIVATED')
        initial = checkout_journal_snapshots(purchase, funding)
        reviews = purchase.execute('SELECT * FROM current_customer_purchase_reviews ORDER BY intent_id').fetchall()
        identities = {review['intent_id'] for review in reviews}
        policies = {}
        for row in purchase.execute('SELECT * FROM current_purchase_execution_policies'):
            _require(type(row['maximum_purchases']) is int and 1 <= row['maximum_purchases'] <= 25
                     and type(row['fee_cap']) is int and 0 <= row['fee_cap'] <= 1_000_000_000,
                     'LEGACY_POLICY_INVALID')
            policies[row['policy_hash']] = row['fee_cap']
        _require(prior_policy in policies and collection_policy not in policies, 'LEGACY_POLICY_MISSING')
        rows = [_group_rows(purchase, table, identities) for table in (
            'current_customer_purchase_delivery', 'current_customer_purchase_signatures',
            'current_customer_reservation_requests', 'current_purchase_executions', 'current_purchase_worker_jobs',
        )]
        peak = await _primary_peak(submitter, node)
        orders, exposures, checkout_inputs = [], [], set()
        for review in reviews:
            order, fees = await _retire_review(review, policies, rows, funding, submitter, peak, generation_id,
                                               anchor_hash, collection_policy, checkout_inputs)
            orders.append(order)
            exposures.extend(fees)
        original_ids = {row['original_id'] for row in purchase.execute('SELECT original_id FROM current_purchase_executions')}
        _require_no_orphan_funding(funding, checkout_inputs, original_ids)
        _require(await _primary_peak(submitter, node) == peak, 'PRIMARY_CHANGED')

    # A second independent SQLite snapshot catches writes made during RPC.
    # A caller must still take the final snapshots under its activation fence.
    with closing(_open_read_only(purchase_path)) as purchase, closing(_open_read_only(funding_path)) as funding:
        _require(purchase.execute("SELECT 1 FROM sqlite_master WHERE name='current_purchase_collection_execution'").fetchone()
                 is None, 'ALREADY_ACTIVATED')
        _require(checkout_journal_snapshots(purchase, funding) == initial, 'JOURNAL_CHANGED')

    balance = calculate_fee_lineage(fee_limit_mojos, exposures)
    confirmed = sum(item.maximum_mojos for item in exposures if item.state == 'CONFIRMED')
    unfunded = sum(item.maximum_mojos for item in exposures if item.state == 'PREPARED')
    _require(confirmed + unfunded == balance.committed_mojos, 'DUPLICATE_FEE_EXPOSURE')
    cutover = CheckoutCutover(schema='solslot.testnet-checkout-cutover.v1', generationId=generation_id,
        anchorHash=anchor_hash, priorPolicy=prior_policy, collectionPolicy=collection_policy,
        feeAuthority=fee_authority, priorIssuerRows=prior_issuer_rows, purchaseJournalSnapshot=initial[0],
        fundingJournalSnapshot=initial[1], feeLimitMojos=fee_limit_mojos,
        inheritedFeeMojos=balance.committed_mojos, peakHash=peak[0], peakHeight=peak[1],
        transactionTime=peak[2], retiredOrders=tuple(orders))
    return CheckoutCutoverEvidence(cutover, confirmed, unfunded)
