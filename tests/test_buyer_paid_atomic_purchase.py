"""The buyer pays the reviewed fee once with the actual minted inventory."""
import pytest
from pathlib import Path
from types import SimpleNamespace
from contextlib import nullcontext
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element, SpendBundle

from solslot_api.generation_customer_purchase_atomic import assemble_purchase, prepare_buyer_payment
from solslot_api.generation_customer_purchase_batch import verify_current_batch_reservation
from solslot_api.generation_customer_purchase_batch_execution import forwardings
from tests.test_generation_customer_purchase_native import (core, real_synthetic_identity_policy, signed,
    test_native_current_checkout_delivery_and_fee_boundaries as scenario)


@pytest.mark.asyncio
@pytest.mark.parametrize('real_synthetic_identity_policy', ['forwarding'], indirect=True)
@pytest.mark.parametrize('quantity', [1, 2])
async def test_one_buyer_paid_transaction(core, tmp_path, real_synthetic_identity_policy, monkeypatch, quantity):
    core.checkout_batch_quantity = quantity
    core.checkout_nominal_candidate = True
    core.buyer_paid_settlement = True
    await scenario(core, tmp_path, real_synthetic_identity_policy, monkeypatch)


@pytest.mark.asyncio
@pytest.mark.parametrize('real_synthetic_identity_policy', ['forwarding'], indirect=True)
@pytest.mark.parametrize('scoped', [False, True], ids=['collection', 'single-order'])
async def test_two_deeds_with_funded_standard_cat(core, tmp_path, real_synthetic_identity_policy, monkeypatch, scoped):
    core.single_cat_window = scoped
    core.checkout_batch_quantity = 2
    core.checkout_nominal_candidate = True
    core.buyer_paid_settlement = True
    core.buyer_paid_cat = True
    await scenario(core, tmp_path, real_synthetic_identity_policy, monkeypatch)


async def fund_checkout_cat(c, source, synthetic):
    from solslot_api.generation_customer_collection_policy import CheckoutCat
    from solslot_api.generation_customer_test_cat import prepare_test_cat
    issuance = prepare_test_cat(funding_coin=source, funding_public_key=synthetic.get_g1(),
        funding_public_key_kind='synthetic', recipient_inner_hash=source.puzzle_hash, network='testnet11')
    bundle = signed(SpendBundle([issuance.funding_spend, issuance.eve_spend], G2Element()), [synthetic], c.faucet.agg_sig_me_data)
    assert await c.client.push_tx(bundle) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    [c.buyer_fee_coin] = [coin for coin in compute_additions(issuance.funding_spend) if coin.puzzle_hash == source.puzzle_hash]
    c.checkout_cats = (CheckoutCat(issuance.asset_id, 'SLTC', 3, 100, 3_030_000),)
    [recipient] = compute_additions(issuance.eve_spend)
    return recipient


async def settle_in_simulator(c, service, store, identity, binding, pay_coin, synthetic, validators, arguments, monkeypatch, collection_issuer=None):
    from solslot_api.generation_customer_purchase_atomic import unsigned_settlement_cost
    from solslot_api.generation_customer_purchase_holds import hold_cart, retain_approved_cart
    hold = hold_cart(store, identity, browser_hash=binding, now=int(c.sim.timestamp))
    assert hold['state'] == 'HELD'
    claim = store.saved(identity, browser_hash=binding)['reservationClaim']
    from solslot_api.generation_customer_purchase_reservation import verify_current_reservation
    from solslot_api.generation_customer_purchase_batch import artifacts, CurrentReservationBatch
    from solslot_api.generation_customer_purchase_atomic import purchase_inputs
    from solslot_api.generation_customer_purchase_cart_worker import forwarding_spends
    verifier = verify_current_batch_reservation if isinstance(claim, CurrentReservationBatch) else verify_current_reservation
    evidence = await verifier(claim, settings=service.settings, **arguments)
    children,_,_ = purchase_inputs(evidence)
    fee = 7100
    args = dict(payment_coin=pay_coin, payment_public_key=bytes(synthetic.get_g1()), payment_public_key_kind='synthetic', network_fee_mojos=fee)
    fee_selection = {}
    if getattr(c, 'buyer_paid_cat', False):
        from solslot_api.generation_customer_purchase_atomic_signing import cat_wallet_inputs
        from solslot_api.generation_customer_purchase_batch import h
        fee_selection = {'feeCoinId': h(c.buyer_fee_coin.name()), 'feePublicKey': h(synthetic.get_g1())}
        args.update(await cat_wallet_inputs(c.provider, pay_coin, bytes(synthetic.get_g1()), 'synthetic',
            c.checkout_cats[0].asset_id, fee_selection['feeCoinId'], fee_selection['feePublicKey']))
    measured = unsigned_settlement_cost(evidence, wallet={k:v for k,v in args.items() if k!='network_fee_mojos'},
        network_fee_mojos=fee, height=c.sim.block_height,
        forwarding_builder=lambda delivery: forwarding_spends(service,evidence,delivery))
    assert 0 < measured < 11_000_000_000
    reviewed = prepare_buyer_payment(evidence, **args)
    assert reviewed.offer.fees() == fee
    assert len(reviewed.offer.coin_spends()) == (2 if fee_selection else 1)
    buyer_signature = signed(SpendBundle(reviewed.offer.coin_spends(), G2Element()), [synthetic], c.faucet.agg_sig_me_data).aggregated_signature
    with pytest.raises(ValueError, match='ORDER_SIGNATURE_INVALID'):
        assemble_purchase(evidence, buyer_signature=buyer_signature, **{**args, 'network_fee_mojos':fee+1})
    settlement = assemble_purchase(evidence, buyer_signature=buyer_signature, **args)
    bundle = settlement.bundle(forwarding_spends(service, evidence, settlement.delivery_bundle))
    from solslot_api.generation_customer_purchase_atomic_signing import AtomicBuyerApproval, sign_atomic_purchase, sign_atomic_issuer
    from solslot_api.generation_customer_issuer import TestnetIssuerJournal
    from solslot_api.validator_ledger import ValidatorLedger
    from solslot_api.generation_customer_purchase_batch import h
    authorization = AtomicBuyerApproval(reservation=claim,paymentCoinId=h(pay_coin.name()),paymentPublicKey=h(synthetic.get_g1()),
        paymentPublicKeyKind='synthetic',networkFeeMojos=fee,buyerOffer=settlement.buyer_offer.to_bech32(), **fee_selection)
    from solslot_api.generation_customer_purchase_atomic_signing import verify_approval
    from solslot_api.generation_customer_purchase_holds import saved_approval
    from solslot_api import protocol_admission
    from solslot_api.generation_customer_native_cart_checkout import fee_options, payment_review, approve_payment, cart_review
    from solslot_api.generation_customer_purchase_cart_worker import NativeCartWorker
    from solslot_api.generation_customer_purchase_settlement_receipt import confirm_settlement
    from solslot_api.generation_customer_purchase_holds import saved_approval
    from solslot_api.generation_operations import bundle_id

    common = dict(anchor=service.anchor,provider=c.provider,clock=service.clock)
    base = {**vars(service.settings),'generation_customer_purchase_atomic_enabled':True,'generation_customer_purchase_issuer_enabled':True}
    async def blockchain_state():
        return {'blockchain_state': {'peak': {'height': int(c.sim.block_height), 'header_hash':h(bytes([int(c.sim.block_height)%256])*32)}, 'sync': {'synced': True, 'sync_mode': False}}}
    async def estimate(*, target_times, require_primary, cost=None, spend_bundle=None):
        assert require_primary and ((cost is None) != (spend_bundle is None))
        now = int(c.sim.timestamp)
        return {'estimates':[fee if t==60 else 100 for t in target_times], 'target_times':target_times,
                'full_node_synced':True,'peak_height':int(c.sim.block_height),'mempool_size':0,
                'mempool_max_size':11_000_000_000,'last_peak_timestamp':now,'node_time_utc':now}
    monkeypatch.setattr(protocol_admission, 'time', SimpleNamespace(time=lambda:int(c.sim.timestamp)))
    monkeypatch.setattr(c.provider, 'get_blockchain_state_primary', blockchain_state, raising=False)
    monkeypatch.setattr(c.provider, 'get_fee_estimate', estimate, raising=False)
    body = SimpleNamespace(payment_coin_id=h(pay_coin.name()), payment_public_key=h(synthetic.get_g1()),
                payment_public_key_kind='synthetic', network_fee_mojos=str(fee))
    if fee_selection:
        body.fee_coin_id = fee_selection['feeCoinId']
        body.fee_public_key = fee_selection['feePublicKey']
    prices = await fee_options(service, identity, binding, body)
    assert prices['standardMojos']=='100' and prices['priorityMojos']==str(fee)
    review = await payment_review(service, identity, binding, body)
    assert review['walletFeeMojos']==str(fee) and review['buyerOffer']==reviewed.offer.to_bech32()
    other = SimpleNamespace(**{**vars(body), 'network_fee_mojos':str(fee+1)})
    assert (await payment_review(service, identity, binding, other))['buyerOffer'] != review['buyerOffer']
    assert cart_review(service, identity, binding)['reservedCoinIds']==(review['reservedCoinIds'] if len(children)>1 else [review['reservedCoinId']])
    submitted=[]
    async def send(raw, *, required_coin_id, required_spend_bundle_id, timeout_seconds, poll_seconds):
        final=SpendBundle.from_json_dict(raw)
        assert required_coin_id==h(pay_coin.name()) and required_spend_bundle_id==bundle_id(final)
        assert final.coin_spends==bundle.coin_spends
        assert await c.client.push_tx(final)==(MempoolInclusionStatus.SUCCESS,None)
        submitted.append(final)
        raise TimeoutError('Lost submission response')

    async def observe(raw):
        tx = SpendBundle.from_json_dict(raw)
        assert raw == submitted[0].to_json_dict()
        record = await c.client.get_coin_record_by_name(pay_coin.name())
        if record.spent:
            return {'status':'CONFIRMED','confirmed_height':int(record.spent_block_index)}
        if c.sim.mempool_manager.get_mempool_item(tx.name()) is not None:
            return {'status':'MEMPOOL'}
        return None
    monkeypatch.setattr(c.provider, 'observe_exact_protocol_bundle', observe, raising=False)
    monkeypatch.setattr(c.provider, 'push_tx_confirmed_in_primary_mempool', send, raising=False)
    async def quorum(_settings, verified):
        receipts=[]
        for i in claim.signer_indices:
            signer=SimpleNamespace(**{**base,'signer_index':i})
            ledger=ValidatorLedger(Path(store.path).parent/f'atomic-validator-{i}.db')
            try:
                reply=await sign_atomic_purchase(verified.claim,verified.claim.digest(),settings=signer,
                    ledger=ledger,issuer_policy=service.policy,expected_issuer_policy_hash=service.policy.commitment,
                    load_key=lambda i=i:validators[i],**common)
                receipts.append(G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
            finally:
                ledger.close()
        return AugSchemeMPL.aggregate(receipts)

    class Issuer:
        async def atomic_signature(self, approval, quorum_signature):
            if fee_selection:
                journal = collection_issuer
            else:
                journal=TestnetIssuerJournal(Path(store.path).parent/'atomic-issuer.db',service.policy)
            try:
                final=await sign_atomic_issuer(approval, approval.digest(),quorum_signature,
                    settings=SimpleNamespace(**{**base,'signer_index':2}),journal=journal,journal_lock=nullcontext(),
                    load_key=lambda:c.faucet.key.wallet_sk,**common)
                return bundle_id(final),final.aggregated_signature
            finally:
                if journal is not collection_issuer:
                    journal.close()

    worker=NativeCartWorker(service,Issuer(),collect_quorum=quorum)
    service.cart_worker=worker
    order=await approve_payment(service,identity,binding,authorization.buyer_offer)
    assert order['cart']['state']=='APPROVED' and worker.wake.is_set()
    assert saved_approval(store,identity,browser_hash=binding)==authorization
    assert store.reservation_request(identity,browser_hash=binding) is None
    for child in children:
        assert await c.client.get_coin_record_by_name(child.transition.reserved_coin.name()) is None
    with pytest.raises(TimeoutError, match='Lost submission'):
        await worker.advance(identity,binding)
    final=submitted[0]
    saved=bundle_id(final)
    assert cart_review(service,identity,binding)['cart']['transactionId']==saved
    assert await confirm_settlement(store,identity,browser_hash=binding,provider=c.provider) is None
    await worker.advance(identity,binding)
    assert len(submitted)==1
    await c.sim.farm_block()
    restored_worker=NativeCartWorker(service,Issuer(),collect_quorum=quorum)
    await restored_worker.advance(identity,binding)
    assert len(submitted)==1 and cart_review(service,identity,binding)['cart']['state']=='CONFIRMED'
    from chia_rs.sized_bytes import bytes32
    payer = await c.client.get_coin_record_by_name(pay_coin.name())
    delivered = [await c.client.get_coin_record_by_name(bytes32.from_hexstr(o.coin_id)) for o in settlement.delivery_outputs]
    assert len(delivered)==len(children) and all(not coin.spent and coin.confirmed_block_index==payer.spent_block_index for coin in delivered)
    receipt = await confirm_settlement(store, identity, browser_hash=binding, provider=c.provider)
    assert receipt['transactionId'] == saved and receipt['confirmedHeight'] == payer.spent_block_index
    assert len(receipt['deedCoinIds']) == len(set(receipt['deedCoinIds'])) == len(children)
    assert await confirm_settlement(store, identity, browser_hash=binding, provider=c.provider) == receipt
    assert payer.spent
    for child in children:
        intermediate = await c.client.get_coin_record_by_name(child.transition.reserved_coin.name())
        assert intermediate.confirmed_block_index == intermediate.spent_block_index == payer.spent_block_index
    change = [coin for coin in compute_additions(reviewed.coin_spend) if coin.puzzle_hash == pay_coin.puzzle_hash]
    assert sum(coin.amount for coin in change) == pay_coin.amount - sum(a.rail_amount for a in artifacts(claim)) - (0 if fee_selection else fee)
    if fee_selection:
        fee_record = await c.client.get_coin_record_by_name(c.buyer_fee_coin.name())
        assert fee_record.spent_block_index == payer.spent_block_index
        fee_spend = next(spend for spend in final.coin_spends if spend.coin == c.buyer_fee_coin)
        [fee_change] = compute_additions(fee_spend)
        assert fee_change.amount == c.buyer_fee_coin.amount - fee and fee_change.puzzle_hash == c.buyer_fee_coin.puzzle_hash
    assert (await c.client.push_tx(final))[0] != MempoolInclusionStatus.SUCCESS
