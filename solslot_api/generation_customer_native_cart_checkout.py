"""Checkout review for an off-chain inventory hold and one buyer-paid settlement."""
import json
from hashlib import sha256
from types import SimpleNamespace
from chia_rs.sized_bytes import bytes32

from .buyer_network_fees import buyer_fee_choices
from .generation_coin_evidence import read_confirmed_coin
from .generation_customer_purchase_atomic import prepare_buyer_payment, purchase_inputs, unsigned_settlement_cost
from .generation_customer_purchase_atomic_signing import AtomicBuyerApproval, cat_wallet_inputs, verify_approval
from .generation_customer_purchase_batch import (CurrentBatchPaymentPreparation, CurrentBatchPaymentRequest,
    CurrentReservationBatch, artifacts, h, verify_current_batch_reservation)
from .generation_customer_purchase_cart_worker import forwarding_spends
from .generation_customer_purchase_holds import cart_status, retain_approved_cart, saved_approval
from .generation_customer_purchase_reservation import verify_current_reservation
from .generation_customer_purchase_wallet import CurrentNativePaymentPreparation, CurrentNativePaymentRequest
from .generation_operations import canonical


def cart_review(service, identity, binding):
    with service.store._connect() as db:
        cart = db.execute('SELECT c.intent_id, o.output_ids FROM current_native_carts c LEFT JOIN current_native_cart_outputs o USING(intent_id) WHERE c.intent_id=?', (identity,)).fetchone()
    review = service.review(identity, browser_hash=binding)
    if cart is None:
        return review
    status = cart_status(service.store, identity, browser_hash=binding, now=int(service.clock()))
    approval = saved_approval(service.store, identity, browser_hash=binding)
    if cart['output_ids'] is None:
        raise ValueError('CURRENT_CHECKOUT_CART_TERMS_UNAVAILABLE')
    return {**review, 'reservedCoinIds': json.loads(cart['output_ids']), 'cart': status, 'payerAuthorizationSaved': approval is not None,
            'buyerNetworkFeeMojos': str(approval.network_fee_mojos) if approval is not None else None,
            'feeCapMojosPerStage': '0', 'maximumNetworkFeeMojos': '0'}


async def recover_cart_quote(service, identity, binding):
    with service.store._connect() as db:
        if not db.execute('SELECT 1 FROM current_native_quote_modes WHERE intent_id=?', (identity,)).fetchone():
            raise ValueError('CURRENT_CHECKOUT_SAVED_MODE_CHANGED')
        row = db.execute('SELECT 1 FROM current_native_cart_outputs WHERE intent_id=?', (identity,)).fetchone()
    if row is None:
        from .generation_customer_purchase_holds import hold_verified_cart
        claim = service._saved(identity, binding)['reservationClaim']
        verify = verify_current_batch_reservation if isinstance(claim, CurrentReservationBatch) else verify_current_reservation
        evidence = await verify(claim, **service._arguments())
        hold_verified_cart(service.store, identity, evidence, browser_hash=binding, now=int(service.clock()))
    return cart_review(service, identity, binding)


async def payment_inputs(service, identity, binding, body):
    status = cart_status(service.store, identity, browser_hash=binding, now=int(service.clock()))
    if status['state'] != 'HELD':
        raise ValueError('CURRENT_CHECKOUT_HOLD_EXPIRED')
    claim = service._saved(identity, binding)['reservationClaim']
    verify = verify_current_batch_reservation if isinstance(claim, CurrentReservationBatch) else verify_current_reservation
    evidence = await verify(claim, **service._arguments())
    raw = await service.provider.get_coin_record_by_name_primary(body.payment_coin_id)
    payer = read_confirmed_coin(raw, bytes32.from_hexstr(body.payment_coin_id))
    if payer.spent_height:
        raise ValueError('CURRENT_PAYMENT_CONFIRMED_UNSPENT_COIN_REQUIRED')
    wallet = dict(payment_coin=payer.coin, payment_public_key=bytes.fromhex(body.payment_public_key[2:]),
                  payment_public_key_kind=body.payment_public_key_kind)
    asset = artifacts(claim)[0].rail_asset_id
    wallet.update(await cat_wallet_inputs(service.provider, payer.coin, wallet['payment_public_key'],
        body.payment_public_key_kind, asset, getattr(body,'fee_coin_id',None),getattr(body,'fee_public_key',None)))
    return claim, evidence, payer, wallet


def cost_for(service, evidence, wallet, fee, height):
    return unsigned_settlement_cost(evidence, wallet=wallet, network_fee_mojos=fee, height=height,
        forwarding_builder=lambda delivery: forwarding_spends(service, evidence, delivery))


async def primary_height(provider):
    response = await provider.get_blockchain_state_primary()
    chain = response['blockchain_state']
    if chain['sync']['synced'] is not True or chain['sync']['sync_mode'] is not False:
        raise ValueError('CURRENT_CHECKOUT_PRIMARY_UNAVAILABLE')
    height = chain['peak']['height']
    if type(height) is not int or not 0 < height < 2**32:
        raise ValueError('CURRENT_CHECKOUT_PRIMARY_UNAVAILABLE')
    return height


async def fee_options(service, identity, binding, body):
    claim, evidence, payer, wallet = await payment_inputs(service, identity, binding, body)
    surplus = int(payer.coin.amount) - sum(int(a.rail_amount) for a in artifacts(claim))
    if surplus < 0:
        raise ValueError('CURRENT_PAYMENT_INSUFFICIENT_FUNDS')
    if wallet.get('cat_lineage_proof') is not None:
        fee_coin = wallet.get('fee_input')
        if fee_coin is None:
            raise ValueError('CURRENT_PAYMENT_NATIVE_FEE_INPUT_REQUIRED')
        surplus = int(fee_coin.coin.amount)
    height = await primary_height(service.provider)
    # Keep both the fee condition and the change output in the priced template whenever possible.
    exemplar = max(1 if wallet.get('fee_input') else 0, surplus - 1)
    cost = cost_for(service, evidence, wallet, exemplar, height)
    options = await buyer_fee_choices(service.provider, cost=cost)
    return {'intentId': identity, 'paymentCoinId': body.payment_coin_id, 'expiresAt': artifacts(claim)[0].quote_expires_at,
            'minimumMojos': str(options.minimum_mojos), 'standardMojos': str(options.standard_mojos),
            'priorityMojos': str(options.priority_mojos), 'availableForFeeMojos': str(surplus),
            **({'feeCoinId':body.fee_coin_id} if wallet.get('fee_input') else {})}


async def payment_review(service, identity, binding, body):
    claim, evidence, payer, wallet = await payment_inputs(service, identity, binding, body)
    fee = int(body.network_fee_mojos)
    if not fee:
        wallet.pop('fee_input', None)
    if fee >= 2**64:
        raise ValueError('CURRENT_PAYMENT_NETWORK_FEE_INVALID')
    height = await primary_height(service.provider)
    cost = cost_for(service, evidence, wallet, fee, height)
    options = await buyer_fee_choices(service.provider, cost=cost)
    if fee < options.minimum_mojos:
        raise ValueError('CURRENT_PAYMENT_NETWORK_FEE_INCREASED')
    prepared = prepare_buyer_payment(evidence, **wallet, network_fee_mojos=fee)
    now = int(service.clock())
    inputs = {'reservation': claim, 'paymentCoinId': body.payment_coin_id, 'paymentPublicKey': body.payment_public_key,
              'paymentPublicKeyKind': body.payment_public_key_kind}
    children, _, _ = purchase_inputs(evidence)
    targets = [h(child.transition.reserved_coin.name()) for child in children]
    if isinstance(claim, CurrentReservationBatch):
        request = CurrentBatchPaymentRequest(**inputs, reservedCoinIds=targets)
        result = CurrentBatchPaymentPreparation(request, children, evidence.batch, prepared, payer, now).review()
    else:
        request = CurrentNativePaymentRequest(**inputs, reservedCoinId=targets[0])
        result = CurrentNativePaymentPreparation(request, SimpleNamespace(artifact=artifacts(claim)[0]), prepared, payer, now).review()
    if wallet.get('cat_lineage_proof') is not None:
        result.pop('reviewHash')
        amount = int(result.pop('amountMojos'))
        result.pop('changeMojos')
        result.update(rail='CHIA_CAT',assetId=h(artifacts(claim)[0].rail_asset_id),
                      amountAtomicUnits=str(amount),changeAtomicUnits=str(payer.coin.amount-amount),
                      coinSpends=[spend.to_json_dict() for spend in prepared.offer.coin_spends()])
        if wallet.get('fee_input'):
            coin = wallet['fee_input'].coin
            result.update(feeCoinId=h(coin.name()),feePublicKey=body.fee_public_key,
                          feeInputMojos=str(coin.amount),feeChangeMojos=str(coin.amount-fee))
        result['reviewHash'] = '0x'+sha256(canonical(result).encode()).hexdigest()
    spend_hash = review_spend_hash(prepared.offer.coin_spends())
    selected_fee = {'feeCoinId':body.fee_coin_id,'feePublicKey':body.fee_public_key} if wallet.get('fee_input') else {}
    selection = canonical({**{k:v for k,v in inputs.items() if k != 'reservation'}, **selected_fee, 'networkFeeMojos': fee})
    with service.store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        service.store._row(db, identity, binding)
        cart = db.execute("SELECT expires_at FROM current_native_carts WHERE intent_id=? AND state='HELD'", (identity,)).fetchone()
        if cart is None or int(service.clock()) >= cart['expires_at']:
            raise ValueError('CURRENT_CHECKOUT_HOLD_EXPIRED')
        prior = db.execute('SELECT wallet_selection FROM current_native_payment_reviews WHERE intent_id=? AND spend_hash=?',
                           (identity, spend_hash)).fetchone()
        if prior is None:
            service.store._execution_capacity(db, len(selection) + 128)
            db.execute('INSERT INTO current_native_payment_reviews VALUES(?,?,?)', (identity, spend_hash, selection))
        elif prior['wallet_selection'] != selection:
            raise ValueError('CURRENT_PAYMENT_SAVED_REVIEW_CHANGED')
        db.commit()
    return result


def review_spend_hash(spends):
    if len(spends) == 1:
        return sha256(bytes(spends[0])).hexdigest()
    if len(spends) != 2:
        raise ValueError('Unexpected number of wallet inputs')
    return sha256(b'SOLSLOT_CAT_WALLET_SPENDS_V1' +
                  b''.join(sha256(bytes(spend)).digest() for spend in spends)).hexdigest()


async def approve_payment(service, identity, binding, offer):
    retained = saved_approval(service.store, identity, browser_hash=binding)
    if retained is not None:
        if retained.buyer_offer != offer:
            raise ValueError('CURRENT_CHECKOUT_SAVED_APPROVAL_CHANGED')
    else:
        from .wallet_offer_validation import decode_offer
        claim = service._saved(identity, binding)['reservationClaim']
        items = artifacts(claim)
        decode_args = dict(dummy_spends=len(items), expected_assets=frozenset(a.deed_launcher_id for a in items), allow_signed=True)
        try:
            decoded = decode_offer(offer, real_spends=1, **decode_args)
        except ValueError:
            if items[0].rail_asset_id == bytes32.zeros:
                raise
            decoded = decode_offer(offer, real_spends=2, **decode_args)
        spend_hash = review_spend_hash(decoded.real_spends)
        with service.store._connect() as db:
            row = db.execute('SELECT wallet_selection FROM current_native_payment_reviews WHERE intent_id=? AND spend_hash=?',
                             (identity, spend_hash)).fetchone()
        if row is None:
            raise ValueError('CURRENT_PAYMENT_REVIEW_REQUIRED')
        approval = AtomicBuyerApproval(reservation=claim, buyerOffer=offer, **json.loads(row['wallet_selection']))
        verified = await verify_approval(approval, **service._arguments())
        retain_approved_cart(service.store, identity, verified, browser_hash=binding, now=int(service.clock()))
    service.cart_worker.notify_work()
    return cart_review(service, identity, binding)
