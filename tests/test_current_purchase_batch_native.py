"""Real simulator batch: current governance, mint, vault, ID and native spends.

Reuses the existing full-flow setup; only private HTTP transport is replaced
with the same independent signer functions running against simulator evidence.
"""
from dataclasses import replace
from types import SimpleNamespace
import pytest
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL,G2Element,SpendBundle
from solslot_api.generation_customer_purchase_batch import (CurrentReservationBatch,CurrentDeliveryBatch,
    CurrentBatchPaymentRequest,h)
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_validators import sign_current_reservation
from solslot_api.generation_customer_purchase_delivery import sign_current_delivery
from solslot_api.generation_customer_purchase_issuer import CurrentIssuerRequest,sign_current_issuer
from solslot_api.generation_customer_issuer import TestnetIssuerJournal as IssuerJournal
from solslot_api.generation_customer_purchase_worker import issuer_message
from solslot_api.validator_ledger import ValidatorLedger
from tests.test_generation_customer_purchase_native import (core,real_synthetic_identity_policy,
    test_native_current_checkout_delivery_and_fee_boundaries as native_scenario,signed)


@pytest.mark.asyncio
@pytest.mark.parametrize('quantity',[2,3])
@pytest.mark.parametrize('real_synthetic_identity_policy',['forwarding'],indirect=True)
async def test_current_two_and_three_deeds_one_native_payment(core,tmp_path,monkeypatch,real_synthetic_identity_policy,quantity):
    core.checkout_batch_quantity=quantity;core.checkout_nominal_candidate=True
    await native_scenario(core,tmp_path,real_synthetic_identity_policy,monkeypatch)


async def exercise_batch(c,ctx,built,inventory,vault,pay_coin,payment_key,synthetic,validators,policy,tmp_path,monkeypatch):
    import time
    started=time.monotonic()
    def progress(label):print('native batch: '+label+' '+str(round(time.monotonic()-started,2))+'s',flush=True)
    from solslot_api import generation_customer_purchase_batch_execution as adapter
    from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
    from solslot_api.generation_customer_purchase_batch import verify_current_batch_delivery
    quantity=c.checkout_batch_quantity;now=lambda:int(c.sim.timestamp)
    selected=sorted(inventory.items,key=lambda item:bytes(item.original.terms.deed_launcher_id))[:3]
    policy=replace(policy,deed_launchers=frozenset(i.original.terms.deed_launcher_id for i in selected),maximum_purchases=3)
    prep=tmp_path/'batch-preparation.json';prep.write_text(c.prep.model_dump_json(by_alias=True))
    settings=SimpleNamespace(**{**ctx.settings.model_dump(),'generation_preparation_path':str(prep),
        'generation_preparation_hash':c.prep.manifest_hash,'generation_chain_anchor_hash':'0x'+'d8'*32,
        'generation_customer_purchase_enabled':True,'roster_pubkeys':[h(k.get_g1())for k in validators]})
    store=CurrentPurchaseExecutionStore(tmp_path/'batch-payments.db',c.prep.generation_id)
    service=CurrentNativePurchaseExecution(settings=settings,anchor=built.anchor,provider=c.provider,
        policy=policy,store=store,fee_cap=10,clock=now)
    arguments=dict(anchor=built.anchor,provider=c.provider,issuer_policy=policy,
        expected_issuer_policy_hash=policy.commitment,clock=now)
    ledgers=[ValidatorLedger(tmp_path/f'batch-validator-{i}.db')for i in (0,1)]
    async def transport(_,evidence,*,retained=None,on_signature=None):
        signatures=[]
        signer=sign_current_reservation if isinstance(evidence.claim,CurrentReservationBatch)else sign_current_delivery
        for index in (0,1):
            configured=SimpleNamespace(**{**vars(settings),'signer_index':index})
            reply=await signer(evidence.claim,evidence.claim.digest(),settings=configured,ledger=ledgers[index],
                load_key=lambda:validators[index],**arguments)
            if on_signature:on_signature(index,reply.model_dump(mode='json'))
            signatures.append(G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
        return AugSchemeMPL.aggregate(signatures)
    monkeypatch.setattr(adapter,'collect_current_purchase_quorum',transport)
    ids=[h(i.original.terms.deed_launcher_id)for i in selected[:quantity]];binding='ab'*32
    review=await service.quote('one-customer-order',ids,browser_hash=binding);identity=review['intentId']
    progress('quote')
    assert review['quantity']==quantity and review['deedLauncherIds']==ids
    assert int(review['amountMojos'])==quantity*101_000_000_000
    assert int(review['baseAmountUsdMinor'])==quantity*300_000
    assert (await service.quote('one-customer-order',list(reversed(ids)),browser_hash=binding))==review
    with pytest.raises(ValueError):await service.quote('one-customer-order',ids[:1],browser_hash=binding)
    assert store.reservation_request(identity,browser_hash=binding)is None
    acknowledgement=adapter.request_reservation(service,identity,binding)
    assert acknowledgement['quantity']==quantity
    assert adapter.request_reservation(service,identity,binding)==acknowledgement
    await service.prepare_reservation(identity,browser_hash=binding)
    progress('reservation prepared')
    reservation=store.execution_bundle(identity,'RESERVATION',browser_hash=binding)
    await service._revalidate_prepared(store.saved(identity,browser_hash=binding),'RESERVATION',reservation)
    assert len(reservation.coin_spends)==quantity
    assert await c.client.push_tx(reservation)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    coins=service.reserved_coin_id(identity,browser_hash=binding)
    record=await c.provider.get_coin_record_by_name_primary(coins[0])
    from solslot_api.protocol_submission import PreparedProtocolBundle
    store.save_execution_funding(identity,'RESERVATION',PreparedProtocolBundle(reservation,0,'0x'+'e1'*32),browser_hash=binding,now=now())
    store.observe_execution(identity,'RESERVATION',browser_hash=binding,transaction_id=h(reservation.name()),status='CONFIRMED',
        confirmed_height=record['confirmed_block_index'],now=now())
    assert service.review(identity,browser_hash=binding)['reservedCoinIds']==list(coins)
    request=CurrentBatchPaymentRequest(reservation=store.saved(identity,browser_hash=binding)['reservationClaim'],
        reservedCoinIds=coins,paymentCoinId=h(pay_coin.name()),paymentPublicKey=h(payment_key.get_g1()))
    prepared=await service.prepare_wallet(identity,request,browser_hash=binding);wallet=prepared.review()
    progress('wallet review')
    assert wallet['quantity']==quantity and len(wallet['coinSpends'])==1
    assert wallet['changeMojos']==str(int(pay_coin.amount)-quantity*101_000_000_000)
    payment=signed(SpendBundle([prepared.prepared.coin_spend],G2Element()),[synthetic],c.faucet.agg_sig_me_data)
    claim=prepared.signed_delivery(payment.aggregated_signature)
    assert isinstance(claim,CurrentDeliveryBatch)
    with pytest.raises(ValueError):await service.accept_payer(identity,claim.model_copy(update={'reserved_coin_ids':tuple(reversed(coins))}),browser_hash=binding)
    assert (await service.accept_payer(identity,claim,browser_hash=binding))['payerAuthorizationSaved']
    # Closing/reopening the existing journal recovers the one batch and offer.
    restored=CurrentPurchaseExecutionStore(store.path,c.prep.generation_id)
    assert restored.saved(identity,browser_hash=binding)['deliveryClaim']==claim
    evidence,bundle,companions,pairs=await service.delivery_issuer_review(identity,claim,browser_hash=binding)
    progress('delivery verified')
    # Exercise the journal budget independently of malformed requests: this
    # complete native candidate has coherent child memos, but exceeds a
    # separate narrower synthetic journal's finite number of deed slots.
    narrow=IssuerJournal(tmp_path/'narrow-issuer-budget.db',replace(policy,maximum_purchases=quantity-1))
    def no_budget_key(_):raise AssertionError('budget rejection must precede the key callback')
    with pytest.raises(ValueError,match='BUDGET_EXHAUSTED'):
        narrow.authorize_batch(bundle=bundle,artifacts=evidence.batch.artifacts,
            terms=[child.item.original.terms for child in evidence.children],fees=service._fees(evidence),
            now=now(),sign_message=no_budget_key)
    assert narrow.db.execute('SELECT count(*) FROM issuer_forwarding').fetchone()[0]==0
    narrow.close()
    public,messages=issuer_message(pairs)
    issuer=IssuerJournal(tmp_path/'issuer.db',policy)
    packet=CurrentIssuerRequest(generationId=c.prep.generation_id,policyHash=policy.commitment,
        claim=claim,claimHash=claim.digest(),purchaseBundle=bundle.to_json_dict(),
        issuerCoinSpend=[s.to_json_dict()for s in companions.issuer_signature_spends],issuerPublicKey=public,message=messages)
    issuer_signature=await sign_current_issuer(packet,settings=settings,anchor=built.anchor,provider=c.provider,
        journal=issuer,load_key=lambda:c.faucet.key.wallet_sk,clock=now)
    progress('issuer verified')
    assert issuer.db.execute('SELECT count(*) FROM issuer_forwarding').fetchone()[0]==quantity
    def no_key():raise AssertionError('retry must recover issuer signatures')
    assert await sign_current_issuer(packet,settings=settings,anchor=built.anchor,provider=c.provider,journal=issuer,load_key=no_key,clock=now)==issuer_signature
    # The worker checkpoints this independently verified issuer review before
    # its next funding cycle; no second quorum or signature request is needed.
    await adapter.save_reviewed_delivery(service,identity,claim,issuer_signature,binding,evidence,bundle,companions,pairs)
    progress('delivery prepared')
    final=store.execution_bundle(identity,'DELIVERY',browser_hash=binding)
    await service._revalidate_prepared(store.saved(identity,browser_hash=binding),'DELIVERY',final)
    assert await c.client.push_tx(final)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    assert (await c.client.push_tx(final))[0]!=MempoolInclusionStatus.SUCCESS
    # Every exact NFT settlement output is present, with unique current coins.
    from chia.wallet.util.compute_additions import compute_additions
    outputs=[coin for spend in final.coin_spends for coin in compute_additions(spend)]
    assert len(outputs)==len({coin.name()for coin in outputs})
    delivered=[]
    for output in evidence.delivery_outputs:
        from chia_rs.sized_bytes import bytes32
        result=await c.client.get_coin_record_by_name(bytes32.from_hexstr(output.coin_id))
        assert result is not None and not result.spent
        delivered.append(result.coin.name())
    assert len(set(delivered))==quantity
    assert (await c.client.get_coin_record_by_name(pay_coin.name())).spent
    spent={spend.coin.name()for spend in final.coin_spends}
    terminal=[coin for coin in outputs if coin.name()not in spent]
    fee=service._fees(evidence)
    issuer_puzzle=evidence.children[0].item.original.terms.protocol_puzhash
    issuer_outputs=[coin for coin in terminal if coin.puzzle_hash==issuer_puzzle]
    company_outputs=[coin for coin in terminal if coin.puzzle_hash==fee.revenue.inner().get_tree_hash()]
    assert len(issuer_outputs)==len(company_outputs)==quantity
    assert all(int(coin.amount)==100_000_000_000 for coin in issuer_outputs)
    assert all(int(coin.amount)==700_000_000 for coin in company_outputs)
    # Distinct SGT reward custody coins receive the remaining 0.3% per deed.
    rewards=[coin for coin in terminal if int(coin.amount)==300_000_000]
    assert len(rewards)==quantity
    change=[coin for coin in terminal if coin.puzzle_hash==pay_coin.puzzle_hash]
    assert len(change)==1 and int(change[0].amount)==int(pay_coin.amount)-quantity*101_000_000_000
    for ledger in ledgers:ledger.close()
    issuer.close()
