"""Real simulator batch: current governance, mint, vault, ID and native spends.

Reuses the existing full-flow setup; only private HTTP transport is replaced
with the same independent signer functions running against simulator evidence.
"""
from dataclasses import replace
from hashlib import sha256
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
from solslot_api.generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from solslot_api.generation_customer_issuer import TestnetIssuerJournal as IssuerJournal
from solslot_api.generation_customer_issuer_lineage import activate_collection_issuer_lineage,issuer_rows_snapshot
from solslot_api.generation_customer_purchase_cutover import CheckoutCutover,activate_checkout_journal
from solslot_api.generation_customer_purchase_cutover_evidence import checkout_journal_snapshots
from solslot_api.generation_customer_purchase_fee_lineage import calculate_fee_lineage
from solslot_api.generation_customer_purchase_fees import (
    CurrentPurchaseFeeAuthority,CurrentPurchaseFeeFaucet,CurrentPurchaseBundleSubmitter,
)
from solslot_api.generation_operations import bundle_id
from solslot_api.generation_customer_purchase_worker import CurrentPurchaseWorker,issuer_message
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import PreparedProtocolBundle,ProtocolFeePolicy
from solslot_api.validator_ledger import ValidatorLedger
from tests.test_generation_customer_purchase_native import (core,real_synthetic_identity_policy,
    test_native_current_checkout_delivery_and_fee_boundaries as native_scenario,signed)


@pytest.mark.asyncio
@pytest.mark.parametrize('quantity',[2,3,4])
@pytest.mark.parametrize('real_synthetic_identity_policy',['forwarding'],indirect=True)
async def test_current_two_and_three_deeds_one_native_payment(core,tmp_path,monkeypatch,real_synthetic_identity_policy,quantity):
    core.checkout_batch_quantity=quantity;core.checkout_nominal_candidate=True
    await native_scenario(core,tmp_path,real_synthetic_identity_policy,monkeypatch)


async def collection_checkout(c, settings, prior, inventory, store, service, tmp_path, now):
    policy = TestnetCollectionIssuerPolicy(prior.generation, prior.collection, prior.edition, prior.metadata_root,
        prior.proceeds_puzzle, prior.fee_puzzle, prior.issuer_public_key,
        frozenset(item.original.terms.deed_launcher_id for item in inventory.items),
        prior.maximum_gross_mojos, prior.test_usd_minor_per_txch)
    # Reuse the existing runtime's empty ledger schema before the offline transition.
    async def unused_issuer(_):
        raise AssertionError('Staging must never call an issuer')
    CurrentPurchaseWorker(service, issuer_sign=unused_issuer, clock=now)
    funding = ProtocolFundingStore(generation_path(str(tmp_path/'native-funding.db'), store.generation_id))
    issuer = IssuerJournal(tmp_path/'issuer.db', prior)
    issuer_rows = issuer_rows_snapshot(issuer.db)[0]
    coins = [row.coin for row in await c.client.get_coin_records_by_puzzle_hash(c.faucet.address_puzzle_hash)
             if not row.spent and 100 <= row.coin.amount <= 20_000_000_000]
    assert len(coins) >= 2
    authority = CurrentPurchaseFeeAuthority.model_validate({'schema':'solslot.current-purchase-fee-authority.v1',
        'network':'testnet11','generationId':store.generation_id,'issuerPolicyHash':policy.commitment,
        'fundingPuzzleHash':c.faucet.address_hex,'feeCoinIds':[h(coin.name()) for coin in coins[:2]],
        'maximumFeeParentMojos':max(int(coin.amount) for coin in coins[:2]),
        'maximumStageFeeMojos':10,'maximumTotalFeeMojos':20,'issuedAt':now(),'expiresAt':now()+3600})
    fee_path = tmp_path/'collection-fees.json'
    fee_document = authority.model_dump_json(by_alias=True).encode()
    fee_path.write_bytes(fee_document)
    settings.generation_customer_purchase_fee_authority_path = str(fee_path)
    settings.generation_customer_purchase_fee_authority_hash = h(sha256(fee_document).digest())
    with store._connect() as purchase_db, funding.db:
        purchase_db.execute('BEGIN')
        funding.db.execute('BEGIN')
        purchase_snapshot, funding_snapshot = checkout_journal_snapshots(purchase_db, funding.db)
    receipt = CheckoutCutover.model_validate({'schema':'solslot.testnet-checkout-cutover.v1',
        'generationId':store.generation_id,'anchorHash':settings.generation_chain_anchor_hash,
        'priorPolicy':prior.commitment,'collectionPolicy':policy.commitment,
        'feeAuthority':settings.generation_customer_purchase_fee_authority_hash,
        'priorIssuerRows':issuer_rows,'purchaseJournalSnapshot':purchase_snapshot,
        'fundingJournalSnapshot':funding_snapshot,'feeLimitMojos':20,'inheritedFeeMojos':0,
        'peakHash':h(bytes([4])*32),'peakHeight':1,'transactionTime':now(),'retiredOrders':[]})
    cutover_path = tmp_path/'collection-cutover.json'
    cutover_document = receipt.model_dump_json(by_alias=True).encode()
    cutover_path.write_bytes(cutover_document)
    settings.generation_customer_purchase_cutover_path = str(cutover_path)
    settings.generation_customer_purchase_cutover_hash = h(sha256(cutover_document).digest())
    with pytest.raises(ValueError, match='COLLECTION_CUTOVER_REQUIRED'):
        CurrentNativePurchaseExecution(settings=settings, anchor=service.anchor, provider=c.provider,
            policy=policy, store=store, fee_cap=10, clock=now, cutover=receipt)
    assert activate_checkout_journal(store.path, funding.path, settings=settings, prior=prior, policy=policy) == receipt
    assert activate_checkout_journal(store.path, funding.path, settings=settings, prior=prior, policy=policy) == receipt
    with pytest.raises(ValueError, match='LEGACY_POLICY_RETIRED'):
        store.bind_execution_policy(prior.commitment, prior.maximum_purchases, 10)
    activate_collection_issuer_lineage(issuer.db, prior_policy=prior, next_policy=policy,
        expected_rows_hash=issuer_rows, fee_balance=calculate_fee_lineage(20,[]),
        closure_hash=settings.generation_customer_purchase_cutover_hash)
    issuer.close()
    issuer = IssuerJournal(tmp_path/'issuer.db', policy, cutover_hash=settings.generation_customer_purchase_cutover_hash)
    faucet = CurrentPurchaseFeeFaucet(c.faucet,authority,policy,store,clock=now,funding_store=funding,cutover=receipt)
    sender = CurrentPurchaseBundleSubmitter(execution_store=store,clock=now,provider=c.provider,
        faucet=faucet,funding_store=funding,policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,
        maximum_mojos=10,native_admission_enabled=True))
    # Use a deterministic small fee for simulator admission.
    async def estimate(_):
        return 5
    async def select(*_args, **_kwargs):
        return next(coin for coin in coins if h(coin.name()) in faucet.available_fee_ids())
    sender._estimate_fee=estimate
    sender._select_fee_coin=select
    service = CurrentNativePurchaseExecution(settings=settings,anchor=service.anchor,provider=c.provider,
        policy=policy,store=store,fee_cap=10,clock=now,submitter=sender,cutover=receipt)
    return service, issuer, funding


async def exercise_batch(c,ctx,built,inventory,vault,pay_coin,payment_key,synthetic,validators,policy,tmp_path,monkeypatch):
    import time
    started=time.monotonic()
    def progress(label):print('native batch: '+label+' '+str(round(time.monotonic()-started,2))+'s',flush=True)
    from solslot_api import generation_customer_purchase_batch_execution as adapter
    from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
    from solslot_api.generation_customer_purchase_batch import verify_current_batch_delivery
    quantity=c.checkout_batch_quantity;now=lambda:int(c.sim.timestamp)
    selected=sorted(inventory.items,key=lambda item:bytes(item.original.terms.deed_launcher_id))
    policy=replace(policy,deed_launchers=frozenset(i.original.terms.deed_launcher_id for i in selected[:3]),maximum_purchases=3)
    prep=tmp_path/'batch-preparation.json';prep.write_text(c.prep.model_dump_json(by_alias=True))
    settings=SimpleNamespace(**{**ctx.settings.model_dump(),'generation_preparation_path':str(prep),
        'generation_preparation_hash':c.prep.manifest_hash,'generation_chain_anchor_hash':'0x'+'d8'*32,
        'generation_customer_purchase_enabled':True,'roster_pubkeys':[h(k.get_g1())for k in validators]})
    store=CurrentPurchaseExecutionStore(tmp_path/'batch-payments.db',c.prep.generation_id)
    service=CurrentNativePurchaseExecution(settings=settings,anchor=built.anchor,provider=c.provider,
        policy=policy,store=store,fee_cap=10,clock=now)
    collection_test = quantity > 3
    funding = None
    issuer = None
    receiver = {}
    if collection_test:
        service, issuer, funding = await collection_checkout(c, settings, policy, inventory, store, service, tmp_path, now)
        policy = service.policy
        receiver = {'receiving_launcher':vault.launcher,
            'receiving_owner':h(list(vault.inner.uncurry()[1].as_iter())[1].as_atom())}
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
    async def submit(phase, original):
        if collection_test:
            prepared = await service.submitter._prepare_locked(original.to_json_dict(), bind_protocol=phase=='DELIVERY')
            assert prepared.fee_mojos == 5
            funding.reserve('testnet11',bundle_id(original),service._funding_context(),
                {**prepared.to_json(),'protocolSpendBundle':original.to_json_dict()})
            assert prepared.fee_coin_id not in service.submitter.faucet.available_fee_ids()
        else:
            prepared = PreparedProtocolBundle(original,0,'0x'+'e1'*32)
        assert await c.client.push_tx(prepared.bundle)==(MempoolInclusionStatus.SUCCESS,None)
        await c.sim.farm_block()
        return prepared
    monkeypatch.setattr(adapter,'collect_current_purchase_quorum',transport)
    ids=[h(i.original.terms.deed_launcher_id)for i in selected[:quantity]];binding='ab'*32
    review=await service.quote('one-customer-order',ids,browser_hash=binding,**receiver);identity=review['intentId']
    progress('quote')
    assert review['quantity']==quantity and review['deedLauncherIds']==ids
    assert int(review['amountMojos'])==quantity*101_000_000_000
    assert int(review['baseAmountUsdMinor'])==quantity*300_000
    assert (await service.quote('one-customer-order',list(reversed(ids)),browser_hash=binding,**receiver))==review
    with pytest.raises(ValueError):await service.quote('one-customer-order',ids[:1],browser_hash=binding,**receiver)
    assert store.reservation_request(identity,browser_hash=binding)is None
    acknowledgement=adapter.request_reservation(service,identity,binding)
    assert acknowledgement['quantity']==quantity
    assert adapter.request_reservation(service,identity,binding)==acknowledgement
    await service.prepare_reservation(identity,browser_hash=binding)
    progress('reservation prepared')
    reservation=store.execution_bundle(identity,'RESERVATION',browser_hash=binding)
    await service._revalidate_prepared(store.saved(identity,browser_hash=binding),'RESERVATION',reservation)
    assert len(reservation.coin_spends)==quantity
    reservation_funded = await submit('RESERVATION', reservation)
    coins=service.reserved_coin_id(identity,browser_hash=binding)
    record=await c.provider.get_coin_record_by_name_primary(coins[0])
    store.save_execution_funding(identity,'RESERVATION',reservation_funded,browser_hash=binding,now=now())
    store.observe_execution(identity,'RESERVATION',browser_hash=binding,transaction_id=h(reservation_funded.bundle.name()),status='CONFIRMED',
        confirmed_height=record['confirmed_block_index'],now=now())
    assert service.review(identity,browser_hash=binding)['reservedCoinIds']==list(coins)
    request=CurrentBatchPaymentRequest(reservation=store.saved(identity,browser_hash=binding)['reservationClaim'],
        reservedCoinIds=coins,paymentCoinId=h(pay_coin.name()),paymentPublicKey=h(payment_key.get_g1()))
    prepared=await service.prepare_wallet(identity,request,browser_hash=binding);wallet=prepared.review()
    progress('wallet review')
    assert wallet['paymentPublicKeyKind']=='raw'
    sage_request=request.model_copy(update={'payment_public_key':h(synthetic.get_g1()),'payment_public_key_kind':'synthetic'})
    sage_prepared=await service.prepare_wallet(identity,sage_request,browser_hash=binding)
    sage_review=sage_prepared.review()
    assert sage_review['paymentPublicKeyKind']=='synthetic'
    assert bytes(sage_prepared.prepared.coin_spend)==bytes(prepared.prepared.coin_spend)
    assert sage_review['reviewHash']!=wallet['reviewHash']
    with pytest.raises(ValueError):
        await service.prepare_wallet(identity,sage_request.model_copy(update={'payment_public_key_kind':'raw'}),browser_hash=binding)
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
    def no_budget_key(_):raise AssertionError('budget rejection must precede the key callback')
    if not collection_test:
        # A coherent older candidate still obeys its historical journal cap.
        narrow=IssuerJournal(tmp_path/'narrow-issuer-budget.db',replace(policy,maximum_purchases=quantity-1))
        with pytest.raises(ValueError,match='BUDGET_EXHAUSTED'):
            narrow.authorize_batch(bundle=bundle,artifacts=evidence.batch.artifacts,
                terms=[child.item.original.terms for child in evidence.children],fees=service._fees(evidence),
                now=now(),sign_message=no_budget_key)
        assert narrow.db.execute('SELECT count(*) FROM issuer_forwarding').fetchone()[0]==0
        narrow.close()
    public,messages=issuer_message(pairs)
    if issuer is None:
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
    if quantity == 2:
        # Exercise the collection issuer against the same real native batch. The
        # scope and closure receipt are synthetic; no production cutover occurs.
        collection=TestnetCollectionIssuerPolicy(policy.generation,policy.collection,policy.edition,policy.metadata_root,
            policy.proceeds_puzzle,policy.fee_puzzle,policy.issuer_public_key,policy.deed_launchers,
            policy.maximum_gross_mojos,policy.test_usd_minor_per_txch)
        cutover_journal=IssuerJournal(tmp_path/'collection-issuer.db',policy)
        rows_hash=issuer_rows_snapshot(cutover_journal.db)[0]
        receipt=CheckoutCutover.model_validate({'schema':'solslot.testnet-checkout-cutover.v1',
            'generationId':h(policy.generation),'anchorHash':settings.generation_chain_anchor_hash,
            'priorPolicy':policy.commitment,'collectionPolicy':collection.commitment,'feeAuthority':h(bytes([1])*32),
            'priorIssuerRows':rows_hash,'purchaseJournalSnapshot':h(bytes([2])*32),
            'fundingJournalSnapshot':h(bytes([3])*32),'feeLimitMojos':1000,'inheritedFeeMojos':0,
            'peakHash':h(bytes([4])*32),'peakHeight':1,'transactionTime':now(),'retiredOrders':[]})
        closure_hash='0x'+sha256(receipt.model_dump_json(by_alias=True).encode()).hexdigest()
        activate_collection_issuer_lineage(cutover_journal.db,prior_policy=policy,next_policy=collection,
            expected_rows_hash=rows_hash,fee_balance=calculate_fee_lineage(1000,[]),closure_hash=closure_hash)
        with pytest.raises(ValueError,match='POLICY_CHANGED'):cutover_journal._require_binding()
        cutover_journal.close()
        with pytest.raises(ValueError,match='ACTIVE_LINEAGE_REQUIRED'):
            IssuerJournal(tmp_path/'collection-issuer.db',collection,cutover_hash=h(bytes([5])*32))
        collection_journal=IssuerJournal(tmp_path/'collection-issuer.db',collection,cutover_hash=closure_hash)
        calls=[]
        def collection_sign(message):
            calls.append(message);return AugSchemeMPL.sign(c.faucet.key.wallet_sk,message)
        collection_bundle=collection_journal.authorize_batch(bundle=bundle,artifacts=evidence.batch.artifacts,
            terms=[child.item.original.terms for child in evidence.children],fees=service._fees(evidence),now=now(),sign_message=collection_sign)
        assert len(calls)==quantity
        assert bytes(collection_journal.authorize_batch(bundle=bundle,artifacts=evidence.batch.artifacts,
            terms=[child.item.original.terms for child in evidence.children],fees=service._fees(evidence),now=now(),sign_message=no_budget_key))==bytes(collection_bundle)
        collection_journal.close()
        single=IssuerJournal(tmp_path/'collection-single-issuer.db',policy)
        activate_collection_issuer_lineage(single.db,prior_policy=policy,next_policy=collection,
            expected_rows_hash=issuer_rows_snapshot(single.db)[0],fee_balance=calculate_fee_lineage(1000,[]),closure_hash=closure_hash)
        single.close();single=IssuerJournal(tmp_path/'collection-single-issuer.db',collection,cutover_hash=closure_hash)
        calls.clear()
        signed_single=single.authorize(bundle=bundle,artifact=evidence.batch.artifacts[0],
            terms=evidence.children[0].item.original.terms,fees=service._fees(evidence),now=now(),sign_message=collection_sign)
        assert len(calls)==1
        assert bytes(single.authorize(bundle=bundle,artifact=evidence.batch.artifacts[0],
            terms=evidence.children[0].item.original.terms,fees=service._fees(evidence),now=now(),sign_message=no_budget_key))==bytes(signed_single)
        single.close()
    # The worker checkpoints this independently verified issuer review before
    # its next funding cycle; no second quorum or signature request is needed.
    await adapter.save_reviewed_delivery(service,identity,claim,issuer_signature,binding,evidence,bundle,companions,pairs)
    progress('delivery prepared')
    final=store.execution_bundle(identity,'DELIVERY',browser_hash=binding)
    await service._revalidate_prepared(store.saved(identity,browser_hash=binding),'DELIVERY',final)
    delivery_funded = await submit('DELIVERY', final)
    assert (await c.client.push_tx(delivery_funded.bundle))[0]!=MempoolInclusionStatus.SUCCESS
    if collection_test:
        assert not service.submitter.faucet.available_fee_ids()
        assert delivery_funded.fee_coin_id != reservation_funded.fee_coin_id
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
    if funding is not None:
        funding.close()
