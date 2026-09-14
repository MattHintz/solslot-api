"""Observe exact terminal outcomes before reclaiming checkout capacity.

These services never cancel/refund a provider payment or broadcast a transaction.
Source publication does not activate presale checkout.
"""
import asyncio
import copy
import time
import uuid

from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, lineage_proof_for_coinsol
from chia_rs import Coin, SpendBundle
from solslot_puzzles.stripe_settlement_v1_driver import build_inventory_release_spend
from solslot_puzzles.vault_driver import puzzle_for_p2_vault

from .inventory_extension_chain import current_position, inspect_position, verify_signature
from .inventory_payment_hold_claims import InventoryPaymentHoldClaim, InventoryPaymentHoldReleaseClaim, InventoryPaymentHoldAbortClaim, payment_hold_activation
from .inventory_payment_holds import verify_hold_receipt, receipt_for, checkout_status
from .inventory_recovery import hx, record_coin, decode_spend, equivalent_timeout_spend, release_peak
from .payment_purchase_store import PaymentPurchaseConflict
from .validator_quorum import collect_inventory_payment_hold_quorum, configured_validator_pubkeys
from .governed_output_index import EvaluatedBundleOutputs
from .stripe_voucher_execution import parse_stripe_terminal_execution
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json, stripe_receipt_from_json

SCHEMA = 'solslot.checkout-terminal.v1'


def require(condition, message):
    if not condition:
        raise PaymentPurchaseConflict(message)


def return_claim(value):
    cls = InventoryPaymentHoldAbortClaim if value.get('schema_version') == 'solslot.inventory-payment-hold-abort.v1' else InventoryPaymentHoldReleaseClaim
    return cls.model_validate(value)


def context(snapshot, hold, artifact):
    stored, rows, _, _ = snapshot
    require(hold.purchase_artifact == stored.purchase_artifact and stored.rail == 'stripe'
        and hold.genesis_artifact_hash == artifact['artifactHash']
        and hold.activation == payment_hold_activation(artifact, hold.activation['environment'])
        and hold.activation['adapterVersion'] == 2,
        'terminal checkout differs from its original reviewed purchase')
    position = current_position(stored, rows, artifact)
    require(hx(position.reservation.artifact.purchase_id) == stored.purchase_id,
        'terminal purchase identity changed')
    return position


def timeout(position):
    return build_inventory_release_spend(reserved_coin=position.coin, deed_singleton_struct=position.struct,
        lineage_proof=lineage_proof_for_coinsol(position.creation_spend), reservation=position.reservation,
        terms=position.terms, timed_out=True)


def paid_output(position, bundle):
    puzzle = SINGLETON_MOD.curry(position.struct, puzzle_for_p2_vault(position.reservation.artifact.vault_launcher_id))
    return EvaluatedBundleOutputs(bundle).find_exact_descendant(ancestor_coin_id=position.coin.name(),
        puzzle_hash=puzzle.get_tree_hash(), amount=1, label='paid checkout SmartDeed')


def validate_terminal_evidence(snapshot, evidence, artifact):
    """Validate retained proof without claiming its output is still unspent today."""
    try:
        require(artifact is not None, 'terminal checkout needs its original trusted release')
        stored, rows, _, _ = snapshot
        hold = InventoryPaymentHoldClaim.model_validate(evidence['hold'])
        position = context(snapshot, hold, artifact)
        require(evidence['schema'] == SCHEMA and evidence['network'] == 'testnet11'
            and evidence['purchaseId'] == stored.purchase_id
            and type(evidence['peakHeight']) is int and evidence['peakHeight'] > 0
            and isinstance(evidence['peakHash'], str) and len(bytes.fromhex(evidence['peakHash'].removeprefix('0x'))) == 32,
            'terminal checkout evidence is incomplete')
        if evidence['kind'] == 'RETURNED':
            claim = return_claim(evidence['returnClaim'])
            returned = timeout(position)
            require(claim.hold == hold and claim.reserved_coin_id == hx(position.coin.name())
                and claim.reservation_expires_at == position.reservation.expires_at
                and claim.available_coin_id == hx(returned.next_coin.name()), 'terminal claim changes the current reserved coin')
            if isinstance(claim, InventoryPaymentHoldAbortClaim):
                require(claim.reserved_coin_id == hold.reserved_coin_id
                    and claim.reservation_expires_at == hold.reservation_expires_at,
                    'partial abort cannot release an extended reservation')
            verify_hold_receipt(claim, evidence['returnQuorum'], artifact)
            require(len(evidence['items']) == len(rows) == 1, 'terminal return requires one exact deed')
            item = evidence['items'][0]
            height = item['confirmationHeight']
            require(type(height) is int and height > position.height and evidence['peakHeight'] - height + 1 >= 3
                and type(item['ordinal']) is int and item['ordinal'] == rows[0].ordinal
                and item['deedLauncherId'] == rows[0].deed_launcher_id
                and item['reservedCoinId'] == hx(position.coin.name())
                and item['availableCoinId'] == hx(returned.next_coin.name())
                and item['availablePuzzleHash'] == hx(returned.next_coin.puzzle_hash)
                and equivalent_timeout_spend(decode_spend(item['releaseSpend'], position.coin), returned.spend),
                'terminal inventory receipt changes its canonical return')
        elif evidence['kind'] == 'DELIVERED':
            verify_hold_receipt(hold, evidence['armQuorum'], artifact)
            bundle = SpendBundle.from_json_dict(evidence['spendBundle'])
            require(0 < len(bundle.coin_spends) <= 128, 'terminal bundle size is unsupported')
            verify_signature(bundle, 'testnet11')
            validate_paid_voucher(evidence['voucher'], snapshot, hold, position, bundle)
            output = paid_output(position, bundle)
            height = evidence['confirmationHeight']
            require(evidence['paymentIntentId'] == hold.payment_intent_id
                and evidence['transactionId'] == hx(bundle.name())
                and evidence['outputCoinId'] == hx(output.name())
                and type(height) is int and height == evidence['voucher']['redemptionConfirmedHeight'] and height > position.height
                and evidence['peakHeight'] - height + 1 >= 3,
                'paid checkout receipt changes payment, transaction or destination')
        else:
            raise PaymentPurchaseConflict('unknown terminal checkout disposition')
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, RuntimeError) as exc:
        if isinstance(exc, PaymentPurchaseConflict):
            raise
        raise PaymentPurchaseConflict('terminal checkout proof is incomplete or inconsistent') from exc


def terminal_status(store, purchase_id, artifact):
    evidence = store.checkout_terminal(purchase_id)
    require(evidence is not None, 'terminal checkout receipt is missing')
    validate_terminal_evidence(store.inventory_status_snapshot(purchase_id), evidence, artifact)
    held = store.checkout_hold(purchase_id)
    require(held is not None and held['state'] == evidence['kind'] and held['claim'] == evidence['hold']
        and store.checkout_admission_closed(purchase_id, evidence['hold']['activation']),
        'terminal receipt conflicts with checkout state')
    status = checkout_status(held, artifact, now=int(time.time()))
    status.update(capacityReleased=True, terminalReceipt=evidence)
    return status


def active_context(store, settings, purchase_id, artifact):
    held = store.checkout_hold(purchase_id)
    require(held is not None, 'checkout has no retained payment hold')
    hold = InventoryPaymentHoldClaim.model_validate(held['claim'])
    require(settings.network == 'testnet11'
        and hold.activation == payment_hold_activation(artifact, settings.runtime_environment + '-alpha')
        and [hx(k) for k in configured_validator_pubkeys(settings)] == artifact['validatorSet']['pubkeys'],
        'terminal recovery requires the original reviewed coordinator deployment')
    snapshot = store.inventory_status_snapshot(purchase_id)
    return held, hold, snapshot, context(snapshot, hold, artifact)


async def reconcile_checkout_return(*, store, node, settings, purchase_id, load_artifact):
    artifact = copy.deepcopy(load_artifact())
    held, hold, snapshot, position = active_context(store, settings, purchase_id, artifact)
    if store.checkout_terminal(purchase_id) is not None:
        return terminal_status(store, purchase_id, artifact)
    retained = store.checkout_return(purchase_id)
    if retained:
        claim = return_claim(retained['claim'])
    elif held['state'] == 'ABORTED':
        claim = InventoryPaymentHoldAbortClaim.model_validate(held['abortClaim'])
    else:
        require(held['state'] == 'ARMED' and held['armReceipt'] is not None,
            'partial checkout must first recover its canceled/unfunded abort quorum')
        verify_hold_receipt(hold, held['armReceipt'], artifact)
        returned = timeout(position)
        claim = InventoryPaymentHoldReleaseClaim(hold=hold, reserved_coin_id=hx(position.coin.name()),
            reservation_expires_at=position.reservation.expires_at, available_coin_id=hx(returned.next_coin.name()))
    # An early status/recovery request must not pin a live checkout in RETURNING.
    # First prove the reserved coin has actually taken its mature canonical timeout.
    # Repeat the observation after quorum before changing the inventory cursor.
    await observe_return(node, position)
    require(load_artifact() == artifact, 'release changed before terminal claim')
    store.claim_checkout_return(purchase_id, claim=claim, snapshot=snapshot, expected_hold=held)
    retained = store.checkout_return(purchase_id)
    if retained['quorum'] is None:
        if isinstance(claim, InventoryPaymentHoldAbortClaim):
            receipt = held['abortReceipt']
        else:
            owner = uuid.uuid4().hex
            store.claim_checkout_quorum(purchase_id, kind='return', owner=owner, now=int(time.time()))
            try:
                quorum = await asyncio.wait_for(collect_inventory_payment_hold_quorum(settings, claim), timeout=90)
                receipt = receipt_for(claim, quorum, artifact)
            finally:
                store.finish_checkout_quorum(purchase_id, owner=owner, now=int(time.time()))
        require(load_artifact() == artifact, 'release changed during terminal quorum')
        store.preserve_checkout_return_quorum(purchase_id, claim=claim, receipt=receipt, artifact=artifact)
    # Private signatures alone never advance the local inventory cursor.
    held = store.checkout_hold(purchase_id)
    snapshot = store.inventory_status_snapshot(purchase_id)
    position = context(snapshot, hold, artifact)
    peak, height, returned, spend = await observe_return(node, position)
    require(load_artifact() == artifact, 'release changed during terminal reconciliation')
    evidence = dict(schema=SCHEMA, kind='RETURNED', network='testnet11', purchaseId=purchase_id,
        hold=hold.model_dump(mode='json'), returnClaim=claim.model_dump(mode='json'),
        returnQuorum=store.checkout_return(purchase_id)['quorum'], peakHeight=peak[0], peakHash=peak[1],
        items=[dict(ordinal=snapshot[1][0].ordinal, deedLauncherId=snapshot[1][0].deed_launcher_id,
            reservedCoinId=hx(position.coin.name()), availableCoinId=hx(returned.next_coin.name()),
            availablePuzzleHash=hx(returned.next_coin.puzzle_hash), confirmationHeight=height,
            releaseSpend=spend.to_json_dict())])
    store.record_checkout_terminal(purchase_id, evidence=evidence, snapshot=snapshot, artifact=artifact, expected_hold=held)
    return terminal_status(store, purchase_id, artifact)


async def observe_return(node, position):
    peak = await release_peak(node, 'testnet11')
    await inspect_position(node, position, peak, require_unspent=False)
    _, height = record_coin(await node.get_coin_record_by_name(hx(position.coin.name())), position.coin)
    require(height > 0 and peak[0] - height + 1 >= 3, 'current timeout is not mature')
    returned = timeout(position)
    spend = decode_spend(await node.get_puzzle_and_solution(hx(position.coin.name()), height), position.coin)
    require(equivalent_timeout_spend(spend, returned.spend), 'current coin was not spent by its exact timeout')
    created, spent = record_coin(await node.get_coin_record_by_name(hx(returned.next_coin.name())), returned.next_coin)
    require(created == height and not spent, 'returned inventory is not atomically confirmed and available')
    require(await release_peak(node, 'testnet11') == peak,
        'chain tip changed during terminal reconciliation')
    return peak, height, returned, spend


def general_coin_record(raw, expected):
    try:
        actual = Coin.from_json_dict(raw['coin'])
        created, spent = raw['confirmed_block_index'], raw['spent_block_index']
        require(actual == expected and type(created) is int and created > 0
            and type(spent) is int and (spent == 0 or spent >= created)
            and type(raw['spent']) is bool and raw['spent'] == bool(spent), 'delivery coin record is inconsistent')
        return created, spent
    except (KeyError, TypeError, ValueError) as exc:
        raise PaymentPurchaseConflict('delivery coin record is incomplete') from exc


def validate_paid_voucher(voucher, snapshot, hold, position, bundle):
    purchase = purchase_artifact_v3_from_json(snapshot[0].purchase_artifact)
    receipt = stripe_receipt_from_json(voucher['settlementReceipt'])
    execution = parse_stripe_terminal_execution(voucher['terminalExactExecution'],
        expected_purchase_id=purchase.purchase_id, expected_artifact_hash=purchase.artifact_hash)
    output = paid_output(position, bundle)
    require(voucher['state'] == 'REDEEMED' and voucher['paymentRail'] == 'STRIPE_USD'
        and voucher['purchaseId'] == hx(purchase.purchase_id)
        and receipt.artifact == purchase and receipt.evidence.payment_intent_id == hold.payment_intent_id
        and execution['mode'] == 'REDEEM'
        and execution['prepared']['spendBundle'] == bundle.to_json_dict()
        and execution['prepared']['spendBundleId'] == voucher['redemptionBundleId'] == hx(bundle.name())
        and execution['bindings']['deedInputCoinId'] == voucher['redemptionDeedInputCoinId'] == hx(position.coin.name())
        and execution['bindings']['seriesInputCoinId'] == voucher['redemptionSeriesInputCoinId']
        and execution['bindings']['externalSettlementEvidenceHash'] == voucher['externalSettlementEvidenceHash'] == hx(receipt.evidence.evidence_hash)
        and execution['outputRoles'] == dict(coordination=voucher['redemptionTreasuryOutputCoinId'],
            deed=voucher['redemptionDeedOutputCoinId'], series=voucher['redemptionSeriesOutputCoinId'],
            terminalVoucher=voucher['redemptionTerminalVoucherCoinId'])
        and voucher['deliveryOutputCoinId'] == voucher['redemptionDeedOutputCoinId'] == hx(output.name()),
        'paid capacity requires the current voucher protocol exact SmartDeed outcome')


async def reconcile_paid_checkout(*, store, presales, node, settings, purchase_id, load_artifact):
    artifact = copy.deepcopy(load_artifact())
    held, hold, snapshot, position = active_context(store, settings, purchase_id, artifact)
    if store.checkout_terminal(purchase_id) is not None:
        return terminal_status(store, purchase_id, artifact)
    voucher = presales.voucher_for_purchase(purchase_id)
    require(held['state'] == 'ARMED' and voucher['state'] == 'REDEEMED',
        'paid capacity requires delivered SmartDeed, not payment success or voucher issuance')
    bundle = SpendBundle.from_json_dict(voucher['terminalExactExecution']['prepared']['spendBundle'])
    evidence = dict(schema=SCHEMA, kind='DELIVERED', network='testnet11', purchaseId=purchase_id,
        hold=hold.model_dump(mode='json'), armQuorum=held['armReceipt'], paymentIntentId=hold.payment_intent_id,
        transactionId=hx(bundle.name()), spendBundle=bundle.to_json_dict(), voucher=copy.deepcopy(voucher),
        outputCoinId=hx(paid_output(position, bundle).name()), confirmationHeight=voucher['redemptionConfirmedHeight'])
    peak = await release_peak(node, 'testnet11')
    evidence.update(peakHeight=peak[0], peakHash=peak[1])
    validate_terminal_evidence(snapshot, evidence, artifact)
    await inspect_position(node, position, peak, require_unspent=False)
    heights = set()
    for spend in bundle.coin_spends:
        _, height = general_coin_record(await node.get_coin_record_by_name(hx(spend.coin.name())), spend.coin)
        require(height > 0 and decode_spend(await node.get_puzzle_and_solution(hx(spend.coin.name()), height), spend.coin) == spend,
            'paid delivery input is not its retained canonical spend')
        heights.add(height)
    removal_ids = {coin.name() for coin in bundle.removals()}
    for coin in bundle.additions():
        if coin.name() not in removal_ids:
            height, _ = general_coin_record(await node.get_coin_record_by_name(hx(coin.name())), coin)
            heights.add(height)
    require(heights == {voucher['redemptionConfirmedHeight']}
        and await release_peak(node, 'testnet11') == peak
        and presales.voucher_for_purchase(purchase_id) == voucher and load_artifact() == artifact,
        'paid delivery changed or did not confirm atomically')
    store.record_checkout_terminal(purchase_id, evidence=evidence, snapshot=snapshot, artifact=artifact, expected_hold=held)
    return terminal_status(store, purchase_id, artifact)
