"""Complete current generation -> fresh customer ID -> real native purchase.

All administrators, ID validators, wallets, prices and property facts here are
explicit synthetic fixtures. No public server or chain transaction is used.
"""
from dataclasses import replace
import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD,LineageProof,puzzle_for_singleton
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk,calculate_synthetic_secret_key,DEFAULT_HIDDEN_PUZZLE_HASH
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
from solslot_puzzles.generation_revenue import CompanyRevenue,PrimaryFeeSplitter
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.generation_vault_identity import build_generation_identity_bundle
from solslot_puzzles.payment_artifacts_v2 import build_oracle_round,OracleObservationV1,oracle_operator_set_root,oracle_round_signature_message
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1,build_inventory_reservation_spend,prepare_chia_buyer_offer_v3,build_native_primary_offer_v5
from solslot_puzzles.vault_driver import one_leaf_merkle_root
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from solslot_api.generation_preparation import GenerationPreparation
from solslot_api.generation_customer_launch import CustomerLaunchBindings,CustomerLaunchConsent,assemble_customer_launch
from solslot_api.generation_customer_vault import trace_current_customer_vault
from solslot_api.generation_customer_inventory import resolve_current_primary_inventory
from solslot_api.generation_customer_quote import current_customer_xch_quote
from solslot_api.singleton_launcher import launcher_coin_for_parent
from solslot_api.generation_mint_execution import MintExecutionRequest,prepare_mint_execution
from solslot_api.generation_mint_reviews import h,reviewed_mint_edition
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import initialize_and_upgrade
from tests.test_generation_mint_reviews import context
from tests.test_generation_mint_execution import approved


def b32(n):return bytes32(bytes([n])*32)

@pytest.fixture(autouse=True)
def real_synthetic_identity_policy(monkeypatch, request):
    import tests.test_generation_genesis_core as fixture
    from tests.test_generation_preparation import bind_custody
    original=fixture.manifest
    def manifest():
        prep,accounts=original();raw=prep.model_dump(mode='json',by_alias=True)
        keys=[bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (31,32,33)]
        raw['bridgePolicyHash']=h(make_bridge_policy_hash(keys,2));bind_custody(raw)
        return GenerationPreparation.model_validate(raw),accounts
    monkeypatch.setattr(fixture,'manifest',manifest)
    route = getattr(request, 'param', 'legacy')
    if route == 'forwarding':
        import tests.test_generation_genesis_launch as launch
        original_artifact=launch.launch_artifact
        def wallet_artifact(c):
            # Existing-style wallet destination, still no fee router in the
            # immutable inventory. Only this simulator wallet owns its key.
            c.testnet_forwarding_candidate=True
            return original_artifact(c).model_copy(update={'protocol_puzzle_hash':c.faucet.address_hex})
        monkeypatch.setattr(launch,'launch_artifact',wallet_artifact)
    if route == 'prebound':
        # A separate local genesis fixture binds the candidate *before* issue.
        # This never retags or substitutes the live generation's old destination.
        import tests.test_generation_genesis_launch as launch
        from solslot_puzzles.generation_primary_proceeds import PrimaryProceedsSplitter
        original_artifact=launch.launch_artifact
        def routed_artifact(c):
            core_built=fixture.assembly(c)
            fees=PrimaryFeeSplitter(core_built.anchor.issuance.bindings(),
                bytes32.from_hexstr(c.prep.coordinates['parameters'].launcher_id),
                CompanyRevenue(bytes32.from_hexstr(c.prep.generation_id),core_built.authority.authority_launcher_id))
            base=original_artifact(c)
            c.primary_proceeds_splitter=PrimaryProceedsSplitter(bytes32.from_hexstr(base.protocol_puzzle_hash),fees)
            return base.model_copy(update={'protocol_puzzle_hash':h(c.primary_proceeds_splitter.inner().get_tree_hash())})
        monkeypatch.setattr(launch,'launch_artifact',routed_artifact)


def signed(bundle,keys,additional):
    bykey={bytes(key.get_g1()):key for key in keys};signatures=[]
    for spend in bundle.coin_spends:
        for public,message in pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,11_000_000_000),spend.coin,additional):
            signatures.append(AugSchemeMPL.sign(bykey[bytes(public)],message))
    return SpendBundle(list(bundle.coin_spends),AugSchemeMPL.aggregate(signatures))

@pytest.mark.asyncio
@pytest.mark.parametrize('real_synthetic_identity_policy', ['legacy', 'prebound', 'forwarding'], indirect=True)
async def test_native_current_checkout_delivery_and_fee_boundaries(core,tmp_path,real_synthetic_identity_policy,monkeypatch):
    c=core;print("native: governance upgrade",flush=True);initialized=await initialize_and_upgrade(c,tmp_path)
    built,_=initialized;ctx=await context(c,tmp_path,initialized_generation=initialized)
    print("native: approved mint",flush=True);source,proposal,journal,chain=await approved(c,ctx,tmp_path)
    c.faucet.bind_generation_mint_reviews(ctx.store,generation_id=c.prep.generation_id,maximum_parent_mojos=1000)
    import asyncio
    body=MintExecutionRequest.model_validate({'generationId':c.prep.generation_id,'sourceReviewId':source['packageId'],
        'proposalId':proposal,'feeCapMojos':1000,'expectedInputs':{**{name:h(getattr(chain,name).current.coin.name()) for name in ('registry','governance','holdings')},
        'components':{source['mintAuthority']['componentId']:source['mintAuthority']['coinId']}}})
    prepared=await prepare_mint_execution(body,settings=ctx.settings,collections=ctx.collections,reviews=ctx.store,
        journal=journal,anchor=built.anchor,provider=c.provider,faucet=c.faucet,funding_guard=asyncio.Lock(),clock=lambda:int(c.sim.timestamp))
    assert await c.client.push_tx(journal.protocol_bundle(prepared['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    print("native: mint confirmed",flush=True);edition=reviewed_mint_edition(source)
    inventory_args=dict(settings=ctx.settings,anchor=built.anchor,provider=c.provider,
        collection=edition.collection,edition_hash=edition.commitment,metadata_root=edition.metadata_root)
    inventory=await resolve_current_primary_inventory(**inventory_args)
    assert len(inventory.items)==25 and sum(item.available for item in inventory.items)==25
    print("native: inventory resolved",flush=True);item=inventory.items[0];terms=item.original.terms;validators=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (31,32,33)]
    # Real fresh customer consent and launch using the same installed custody module.
    owner=AugSchemeMPL.key_gen(b'Q'*32);owner_pk=bytes(owner.get_g1())
    payment_pk=AugSchemeMPL.key_gen(b'R'*32);payment_puzzle=puzzle_for_pk(payment_pk.get_g1())
    synthetic=calculate_synthetic_secret_key(payment_pk,DEFAULT_HIDDEN_PUZZLE_HASH)
    acs=Program.to(1);origins=[r.coin for r in await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent]
    funding=Coin(origins[0].name(),c.faucet.address_puzzle_hash,uint64(10000))
    policy=bytes32.from_hexstr(c.prep.bridge_policy_hash);bridge=Coin(origins[1].name(),policy,uint64(1))
    pay_coin=Coin(origins[2].name(),payment_puzzle.get_tree_hash(),uint64(500_000_000_000 if getattr(c,'checkout_nominal_candidate',False)else 1_000_000_000))
    setup=[make_spend(origin,acs,Program.to([[51,coin.puzzle_hash,int(coin.amount)],[51,acs.get_tree_hash(),int(origin.amount)-int(coin.amount)]])) for origin,coin in zip(origins,(funding,bridge,pay_coin))]
    assert await c.client.push_tx(SpendBundle(setup,G2Element()))==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    bindings=CustomerLaunchBindings(bytes32.from_hexstr(c.prep.generation_id),bytes32.from_hexstr(c.prep.manifest_hash),inventory.pool_launcher_id,policy,load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash())
    now=int(c.sim.timestamp)
    consent=CustomerLaunchConsent(bindings,b32(161),h(owner_pk),'chia_bls',funding.name(),launcher_coin_for_parent(funding).name(),now+300)
    signature=h(bytes(AugSchemeMPL.sign(owner,bytes(Program.to(('Chia Signed Message',consent.bls_message())).get_tree_hash()))))
    print("native: fresh vault creation",flush=True);creation=assemble_customer_launch(bindings=bindings,consent=consent,signature=signature,funding_coin=funding,faucet=c.faucet,now=now)
    assert await c.client.push_tx(creation.bundle())==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    tip,=creation.successors
    vault_args=dict(bindings=bindings,launcher=tip.launcher_id,owner_pubkey=owner_pk,auth_type=1,initial_coin=tip.coin,provider=c.provider)
    print("native: fresh vault confirmed",flush=True);empty=await trace_current_customer_vault(**vault_args)
    # Synthetic but independently signed two-source price for simulator sizing.
    price_keys=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (41,42,43)];now=int(c.sim.timestamp)
    round=build_oracle_round(network='testnet11',sequence=1,asset_id=bytes32.zeros,asset_decimals=12,
        operator_set_root=oracle_operator_set_root([bytes(key.get_g1()) for key in price_keys]),
        observations=tuple(OracleObservationV1(b32(n),bytes32.zeros,12,1_000_000_000,now,now+600,b32(n+2)) for n in (151,152)))
    price=SignedPrimaryPrice(round,tuple((i,bytes(AugSchemeMPL.sign(price_keys[i],oracle_round_signature_message(round.round_hash)))) for i in (0,1)))
    quote_args=dict(inventory=inventory,deed_launcher=terms.deed_launcher_id,price=price,nonce=b32(162),now=now,expires_at=now+300)
    with pytest.raises(ValueError,match='FRESH_ID_REQUIRED'):current_customer_xch_quote(vault=empty,**quote_args)
    print("native: fresh ID stamp",flush=True);root=b32(163)
    identity=build_generation_identity_bundle(bridge_parent_id=bridge.parent_coin_info,bridge_amount=1,
        validator_pubkeys=[bytes(k.get_g1()) for k in validators],threshold=2,signer_indices=[0,1],
        vault_coin=tip.coin,vault_launcher_id=tip.launcher_id,owner_pubkey_bytes=owner_pk,auth_type=1,
        members_merkle_root=one_leaf_merkle_root(owner_pk),pool_launcher_id=bindings.pool_launcher,
        new_identity_attest_root=root,attestation_leaf_hash=b32(164),scoped_nullifier=b32(165),nullifier_type=1,
        service_scope_hash=b32(166),service_subscope_hash=b32(167),proof_timestamp=now,current_timestamp=now,
        lineage_proof=LineageProof(parent_name=funding.name(),amount=uint64(1)))
    assert await c.client.push_tx(signed(identity.spend_bundle,[owner,*validators],c.faucet.agg_sig_me_data))==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    vault=await trace_current_customer_vault(**vault_args);assert vault.identity_verified
    proceeds=getattr(c,'primary_proceeds_splitter',None)
    issuer_policy=None
    print("native: quote",flush=True)
    if proceeds is not None:
        quote=current_customer_xch_quote(vault=vault,proceeds=proceeds,**quote_args)
        for bad in (replace(proceeds,issuer=b32(201)),
                replace(proceeds,fees=replace(proceeds.fees,statutes_id=b32(202)))):
            with pytest.raises(ValueError,match='FEE_ROUTE_CHANGED'):
                current_customer_xch_quote(vault=vault,proceeds=bad,**quote_args)
    elif getattr(c,'testnet_forwarding_candidate',False):
        from solslot_api.generation_customer_issuer import TestnetIssuerPolicy
        fees=PrimaryFeeSplitter(built.anchor.issuance.bindings(),
            bytes32.from_hexstr(c.prep.coordinates['parameters'].launcher_id),
            CompanyRevenue(bindings.generation,built.authority.authority_launcher_id))
        issuer_policy=TestnetIssuerPolicy(bindings.generation,inventory.collection,inventory.edition,inventory.metadata_root,
            terms.protocol_puzhash,terms.protocol_treasury_puzzle_hash,bytes(c.faucet.key.wallet_pk),
            frozenset([terms.deed_launcher_id]),vault.launcher,10_000_000_000,1,now-1,now+3600)
        if getattr(c,'checkout_nominal_candidate',False):
            from solslot_api.generation_customer_test_conversion import FixedTestnetConversion
            issuer_policy=replace(issuer_policy,maximum_gross_mojos=200_000_000_000,test_usd_minor_per_txch=3_000_000)
            price=FixedTestnetConversion(issuer_policy,now+300)
            quote_args['price']=price
        quote=current_customer_xch_quote(vault=vault,forwarding_policy=issuer_policy,**quote_args)
        for bad in (replace(issuer_policy,buyer_vault=b32(203)),
                replace(issuer_policy,issuer_public_key=owner_pk)):
            with pytest.raises(ValueError):
                current_customer_xch_quote(vault=vault,forwarding_policy=bad,**quote_args)
        with pytest.raises(ValueError):
            current_customer_xch_quote(vault=vault,forwarding_policy=replace(issuer_policy,maximum_gross_mojos=2),**quote_args)
    else:
        with pytest.raises(ValueError,match='FEE_ROUTE_UNSUPPORTED'):
            current_customer_xch_quote(vault=vault,**quote_args)
        # Native repro deliberately invokes the old public SDK, bypassing the
        # new fail-closed quote service to demonstrate the on-chain defect.
        from solslot_puzzles.payment_artifacts_v3 import build_xch_purchase_artifact
        quote=build_xch_purchase_artifact(network='testnet11',collection_id=terms.collection_id,
            deed_launcher_id=terms.deed_launcher_id,metadata_root=terms.metadata_root,
            metadata_anchor_id=terms.metadata_anchor_id,share_ppm=terms.share_ppm,
            base_amount_minor=terms.base_amount_minor,technology_fee_bps=terms.technology_fee_bps,
            protocol_treasury_puzzle_hash=terms.protocol_treasury_puzzle_hash,zkpassport_root=vault.root,
            vault_launcher_id=vault.launcher,vault_p2_puzzle_hash=puzzle_for_p2_vault(vault.launcher).get_tree_hash(),
            authorization_nonce=quote_args['nonce'],authorization_expires_at=now+300,
            quote_expires_at=now+300,oracle_round=price.round)
    current_verified=None
    execution=None
    reservation_replies={}
    delivery_replies={}
    if issuer_policy is not None:
        from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim,verify_current_reservation
        from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
        from solslot_puzzles.payment_artifacts_v2 import oracle_round_to_json
        import json
        prep_path=tmp_path/'reservation-preparation.json'
        prep_path.write_text(c.prep.model_dump_json(by_alias=True))
        bound=ctx.settings.model_copy(update={'generation_preparation_path':str(prep_path),
            'generation_preparation_hash':c.prep.manifest_hash,'generation_chain_anchor_hash':h(b32(216))})
        claim=CurrentReservationClaim(generationId=c.prep.generation_id,anchorHash=bound.generation_chain_anchor_hash,
            issuerPolicyHash=issuer_policy.commitment,purchaseArtifact=purchase_artifact_v3_to_json(quote),
            signedPrice=(price.evidence()if issuer_policy.test_usd_minor_per_txch is not None else
                {'round':oracle_round_to_json(price.round),'signatures':[
                {'signerIndex':i,'signature':h(sig)}for i,sig in price.signatures]}),
            availableCoinId=h(item.current.coin.name()),currentVaultCoinId=h(vault.coin.name()),signerIndices=(0,1))
        args=dict(settings=bound,anchor=built.anchor,provider=c.provider,issuer_policy=issuer_policy,
            expected_issuer_policy_hash=issuer_policy.commitment,clock=lambda:now)
        current_verified=await verify_current_reservation(claim,**args)
        assert current_verified.vault.identity_verified
        assert current_verified.inventory.edition==inventory.edition
        assert current_verified.item.current.coin==item.current.coin
        for changes in ({'generation_id':h(b32(217))},{'available_coin_id':h(b32(218))},
                        {'current_vault_coin_id':h(b32(219))},{'issuer_policy_hash':h(b32(220))}):
            with pytest.raises(ValueError):await verify_current_reservation(claim.model_copy(update=changes),**args)
        with pytest.raises(ValueError,match='POLICY_EXPIRED'):
            await verify_current_reservation(claim,**{**args,'clock':lambda:issuer_policy.expires_at})
        altered=json.loads(json.dumps(claim.signed_price))
        if issuer_policy.test_usd_minor_per_txch is not None:altered['issuerPolicyHash']=h(b32(223))
        else:altered['signatures'][0]['signature']=h(bytes(96))
        with pytest.raises(ValueError):await verify_current_reservation(claim.model_copy(update={'signed_price':altered}),**args)
    reservation=InventoryReservationV1(quote,quote.quote_expires_at)
    # Use the exact singleton wrapper constant from the native driver.
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
    structure=Program.to((SINGLETON_MOD_HASH,(terms.deed_launcher_id,terms.deed_launcher_puzzle_hash)))
    print("native: reservation",flush=True);reserved=build_inventory_reservation_spend(available_coin=item.current.coin,deed_singleton_struct=structure,
        lineage_proof=item.lineage,reservation=reservation,signer_indices=(0,1),terms=terms)
    if current_verified is not None:assert bytes(current_verified.transition.spend)==bytes(reserved.spend)
    if current_verified is not None:
        from types import SimpleNamespace
        from solslot_api.generation_customer_purchase_validators import sign_current_reservation
        from solslot_api.validator_ledger import ValidatorLedger
        signatures=[]
        for slot in (0,1):
            signer_settings=SimpleNamespace(**bound.model_dump())
            signer_settings.generation_customer_purchase_enabled=True
            signer_settings.signer_index=slot
            signer_settings.roster_pubkeys=[h(bytes(k.get_g1()))for k in validators]
            ledger=ValidatorLedger(tmp_path/('current-purchase-validator-'+str(slot)+'.sqlite3'))
            loads=[]
            def load_synthetic():loads.append(slot);return validators[slot]
            call=dict(settings=signer_settings,anchor=built.anchor,provider=c.provider,ledger=ledger,
                issuer_policy=issuer_policy,expected_issuer_policy_hash=issuer_policy.commitment,clock=lambda:now)
            reply=await sign_current_reservation(claim,claim.digest(),load_key=load_synthetic,**call)
            reservation_replies[slot]=reply.model_dump(mode='json')
            assert loads==[slot]
            def no_second_key_read():raise AssertionError('saved reservation must recover without loading a key')
            recovered=await sign_current_reservation(claim,claim.digest(),load_key=no_second_key_read,**call)
            assert recovered==reply
            with pytest.raises(ValueError,match='NOT_ENABLED'):
                await sign_current_reservation(claim,h(b32(222)),load_key=no_second_key_read,**call)
            ledger.close();signatures.append(G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
        reservation_bundle=SpendBundle([reserved.spend],AugSchemeMPL.aggregate(signatures))
        from solslot_api import generation_customer_purchase_execution as execute
        from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
        execution_store=CurrentPurchaseExecutionStore(tmp_path/'payment_purchases_v2.db',c.prep.generation_id)
        intent=execution_store.save_review(claim,browser_hash='ab'*32,request_key='native-1',now=now)
        execution=execute.CurrentNativePurchaseExecution(settings=SimpleNamespace(**{
            **bound.model_dump(),'generation_customer_purchase_enabled':True}),anchor=built.anchor,
            provider=c.provider,policy=issuer_policy,store=execution_store,fee_cap=10,clock=lambda:now)
        from solslot_api.payment_quotes import AuthorizedOracleRound
        if issuer_policy.test_usd_minor_per_txch is None:
            authorized=AuthorizedOracleRound(price.round,tuple(
                {'signerIndex':i,'signature':h(sig)} for i,sig in price.signatures))
            from solslot_api import payment_quotes
            monkeypatch.setattr(payment_quotes,'load_authorized_oracle_round',lambda *a,**kw:authorized)
        visible_inventory=await execution.inventory()
        assert visible_inventory['deedCount']==25 and visible_inventory['availableDeeds']==25
        assert visible_inventory['receivingVaultLauncherId']==h(vault.launcher)
        selected_row=next(row for row in visible_inventory['items']if row['deedLauncherId']==h(terms.deed_launcher_id))
        assert selected_row['smartDeedInnerHash']==h(terms.smart_deed_inner_hash)
        assert len({row['smartDeedInnerHash']for row in visible_inventory['items']})==25
        async def primary_payer_coins(puzzle_hash,*,include_spent=False):
            return [record.to_json_dict()for record in await c.client.get_coin_records_by_puzzle_hash(bytes32.from_hexstr(puzzle_hash))
                if include_spent or not record.spent]
        monkeypatch.setattr(c.provider,'get_coin_records_by_puzzle_hash_primary',primary_payer_coins,raising=False)
        candidates=await execution.payer_coins(intent,[h(bytes(payment_pk.get_g1()))],browser_hash='ab'*32)
        assert candidates['candidates'][0]['paymentCoinId']==h(pay_coin.name())
        assert candidates['receivingVaultLauncherId']==h(vault.launcher)
        # Exercise the server-side quote against real native custody and ID,
        # then recover that exact review after expiry without repricing.
        review=await execution.quote('native-quote',h(terms.deed_launcher_id),browser_hash='ab'*32)
        assert review['receivingVaultLauncherId']==h(vault.launcher)
        assert review['baseAmountUsdMinor']==str(terms.base_amount_minor)
        assert review['totalAmountUsdMinor']==str(terms.subtotal_minor)
        assert review['quoteExpiresAt']==now+300
        execution.clock=lambda:issuer_policy.expires_at+1
        recovered=await execution.quote('native-quote',h(terms.deed_launcher_id),browser_hash='ab'*32)
        assert recovered['intentId']==review['intentId'] and recovered['quoteExpired']
        assert recovered['amountMojos']==review['amountMojos']
        with pytest.raises(ValueError,match='REQUEST_KEY_DEED_CHANGED'):
            await execution.quote('native-quote',h(b32(240)),browser_hash='ab'*32)
        execution.clock=lambda:now
        async def native_transport(settings,evidence,*,retained=None,on_signature=None):
            # Only transport is replaced. These replies came from actual
            # independent native signer reconstruction above/below.
            from solslot_api.generation_customer_purchase_reservation import CurrentReservationEvidence
            replies=reservation_replies if isinstance(evidence,CurrentReservationEvidence) else delivery_replies
            values=[]
            for slot in (0,1):
                response=replies[slot]
                if on_signature is not None:on_signature(slot,response)
                values.append(G2Element.from_bytes(bytes.fromhex(response['signature'][2:])))
            return AugSchemeMPL.aggregate(values)
        monkeypatch.setattr(execute,'collect_current_purchase_quorum',native_transport)
        await execution.prepare_reservation(intent,browser_hash='ab'*32)
        assert bytes(execution_store.execution_bundle(intent,'RESERVATION',browser_hash='ab'*32))==bytes(reservation_bundle)
        await execution._revalidate_prepared(execution_store.saved(intent,browser_hash='ab'*32),'RESERVATION',reservation_bundle)
        from solslot_api.protocol_submission import PreparedProtocolBundle
        execution_store.save_execution_funding(intent,'RESERVATION',PreparedProtocolBundle(reservation_bundle,0,h(b32(225))),browser_hash='ab'*32,now=now)
    else:
        reservation_bundle=signed(SpendBundle([reserved.spend],G2Element()),validators,c.faucet.agg_sig_me_data)
    assert await c.client.push_tx(reservation_bundle)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    print("native: reservation confirmed",flush=True);reserved_coin=reserved.reserved_coin
    if execution is not None:
        record=await c.provider.get_coin_record_by_name_primary(h(reserved_coin.name()))
        execution_store.observe_execution(intent,'RESERVATION',browser_hash='ab'*32,
            transaction_id=h(reservation_bundle.name()),status='CONFIRMED',
            confirmed_height=record['confirmed_block_index'],now=now)
    if getattr(c,'checkout_timeout_candidate',False):
        from solslot_api.generation_customer_purchase_timeout import verify_current_timeout
        with pytest.raises(ValueError,match='FINITE_SCOPE_CHANGED'):
            await execution.prepare_timeout(intent,browser_hash='ab'*32)
        c.sim.pass_time(uint64(301));await c.sim.farm_block();now=int(c.sim.timestamp)
        execution.clock=lambda:now
        # Feed actual simulator coin/block evidence through the real primary
        # provider and snapshot implementation, with no fallback authority.
        from solslot_api.chia_provider import ChiaProvider,ChiaProviderConfig
        from solslot_api import chia_snapshot
        class Node:
            async def get_network_info(self):return {'success':True,'network_name':'testnet11'}
            async def get_blockchain_state(self):return {'success':True,'blockchain_state':{
                'peak':{'height':int(c.sim.block_records[-1].height),'header_hash':h(c.sim.block_records[-1].header_hash)},
                'sync':{'synced':True,'sync_mode':False}}}
            async def get_block_record(self,digest):
                block=await c.client.get_block_record(bytes32.from_hexstr(digest))
                return {'success':True,'block_record':{'height':int(block.height),'header_hash':h(block.header_hash),
                    'timestamp':int(block.timestamp),'prev_hash':h(block.prev_transaction_block_hash)}}
            async def get_coin_record_by_name(self,name):return await c.provider.get_coin_record_by_name_primary(name)
            async def get_puzzle_and_solution(self,name,height):return await c.provider.get_puzzle_and_solution_primary(name,height)
        primary=ChiaProvider(Node(),None,ChiaProviderConfig(network='testnet11',primary_url='https://sim.invalid',fallback_url=''))
        monkeypatch.setattr(chia_snapshot.time,'time',lambda:now)
        args={**args,'provider':primary};execution.provider=primary
        # Wall time alone cannot release; the unchanged primary transaction
        # block and unspent native reservation provide the actual deadline.
        release=await verify_current_timeout(claim,h(reserved_coin.name()),**{**args,'clock':lambda:now})
        assert bytes(release.aggregated_signature)==bytes(G2Element())
        with pytest.raises(ValueError,match='CONFIRMED_RESERVATION_CHANGED'):
            await verify_current_timeout(claim,h(b32(241)),**{**args,'clock':lambda:now})
        await execution.prepare_timeout(intent,browser_hash='ab'*32)
        await execution._revalidate_prepared(execution_store.saved(intent,browser_hash='ab'*32),'RELEASE',release)
        from solslot_api.generation_customer_purchase_fees import CurrentPurchaseFeeAuthority,CurrentPurchaseFeeFaucet,CurrentPurchaseBundleSubmitter
        from solslot_api.protocol_submission import ProtocolFeePolicy
        candidates=[r.coin for r in await c.client.get_coin_records_by_puzzle_hash(c.faucet.address_puzzle_hash)
            if not r.spent and 100<=r.coin.amount<=20_000_000_000]
        fee_coin=candidates[0]
        authority=CurrentPurchaseFeeAuthority.model_validate({'schema':'solslot.current-purchase-fee-authority.v1',
            'network':'testnet11','generationId':c.prep.generation_id,'issuerPolicyHash':issuer_policy.commitment,
            'fundingPuzzleHash':c.faucet.address_hex,'feeCoinIds':[h(fee_coin.name())],
            'maximumFeeParentMojos':int(fee_coin.amount),'maximumStageFeeMojos':10,'maximumTotalFeeMojos':10,
            'issuedAt':now,'expiresAt':issuer_policy.expires_at})
        guard=CurrentPurchaseFeeFaucet(c.faucet,authority,issuer_policy,execution_store,clock=lambda:now)
        sender=CurrentPurchaseBundleSubmitter(execution_store=execution_store,clock=lambda:now,provider=c.provider,
            faucet=guard,policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,maximum_mojos=10))
        async def estimate(_):return 5
        async def select(*a,**kw):return fee_coin
        sender._estimate_fee=estimate;sender._select_fee_coin=select
        prepared=await sender._prepare_locked(release.to_json_dict())
        assert prepared.fee_mojos==5
        fee_only=SpendBundle([s for s in prepared.bundle.coin_spends if s.coin==fee_coin],prepared.bundle.aggregated_signature)
        assert (await c.client.push_tx(fee_only))[0]!=MempoolInclusionStatus.SUCCESS
        assert await c.client.push_tx(prepared.bundle)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
        assert (await c.client.push_tx(prepared.bundle))[0]!=MempoolInclusionStatus.SUCCESS
        restored=await resolve_current_primary_inventory(**inventory_args)
        assert sum(x.available for x in restored.items)==25
        assert (await c.client.get_coin_record_by_name(pay_coin.name())).spent is False
        assert (await trace_current_customer_vault(**vault_args)).identity_verified
        print('native: unpaid timeout released; 25 deeds available; payer untouched; replay rejected',flush=True)
        ctx.collections.close()
        return
    offered=prepare_chia_buyer_offer_v3(payment_coin=pay_coin,payment_public_key=bytes(payment_pk.get_g1()),artifact=quote,terms=terms,deed_singleton_struct=structure)
    current_payment=None
    if current_verified is not None:
        from solslot_api.generation_customer_purchase_wallet import CurrentNativePaymentRequest,prepare_current_native_payment
        from solslot_api.generation_customer_purchase_store import CurrentCustomerPurchaseStore
        from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError
        payment_request=CurrentNativePaymentRequest(reservation=claim,reservedCoinId=h(reserved_coin.name()),
            paymentCoinId=h(pay_coin.name()),paymentPublicKey=h(bytes(payment_pk.get_g1())))
        payment_args=dict(settings=bound,anchor=built.anchor,provider=c.provider,issuer_policy=issuer_policy,
            expected_issuer_policy_hash=issuer_policy.commitment,clock=lambda:now)
        current_payment=(await execution.prepare_wallet(intent,payment_request,browser_hash='ab'*32)
            if execution is not None else await prepare_current_native_payment(payment_request,**payment_args))
        wallet_review=current_payment.review()
        assert len(wallet_review['coinSpends'])==1
        assert wallet_review['paymentCoinId']==h(pay_coin.name())
        assert wallet_review['recipientVaultLauncherId']==h(vault.launcher)
        assert wallet_review['paymentPublicKey']!=h(owner_pk)
        assert bytes(current_payment.prepared.coin_spend)==bytes(offered.coin_spend)
        assert current_payment.prepared.offer.to_bech32()==offered.offer.to_bech32()
        assert wallet_review['walletFeeMojos']=='0'
        assert wallet_review['payerConfirmedHeight']>0 and wallet_review['observedAt']==now
        assert wallet_review['payerCoin']['puzzleHash']==h(payment_puzzle.get_tree_hash())
        with pytest.raises(ValueError,match='ORDER_SIGNATURE_INVALID'):
            current_payment.signed_delivery(G2Element())
        with pytest.raises(PaymentArtifactError,match='does not belong'):
            await prepare_current_native_payment(payment_request.model_copy(update={'payment_public_key':h(owner_pk)}),**payment_args)
    raw=SpendBundle([offered.coin_spend],G2Element());payment_signed=signed(raw,[synthetic],c.faucet.agg_sig_me_data)
    buyer=Offer(offered.offer.requested_payments,WalletSpendBundle(payment_signed.coin_spends,payment_signed.aggregated_signature),offered.offer.driver_dict)
    print("native: offer combine",flush=True);purchase=build_native_primary_offer_v5(buyer_offer=buyer,deed_coin=reserved_coin,deed_singleton_struct=structure,
        lineage_proof=LineageProof(parent_name=item.current.coin.parent_coin_info,inner_puzzle_hash=item.current.inner.get_tree_hash(),amount=uint64(1)),
        artifact=quote,signer_indices=(0,1),terms=terms,reservation=reservation)
    print("native: offer finalize",flush=True);full=purchase.aggregate_offer.to_valid_spend()
    if current_verified is not None:
        from solslot_api.generation_customer_purchase_delivery import CurrentDeliveryClaim,verify_current_delivery,sign_current_delivery
        delivery_claim=CurrentDeliveryClaim(reservation=claim,reservedCoinId=h(reserved_coin.name()),buyerOffer=buyer.to_bech32())
        assert current_payment.signed_delivery(payment_signed.aggregated_signature)==delivery_claim
        # Existing payment DB, current generation and browser binding, no new
        # recovery store. Real signed buyer work survives process reopening.
        current_store=CurrentCustomerPurchaseStore(str(tmp_path/'payment_purchases_v2.db'),c.prep.generation_id)
        browser='ab'*32
        intent=current_store.save_review(claim,browser_hash=browser,request_key='native-1',now=now)
        if execution is not None:
            bad=delivery_claim.model_copy(update={'buyer_offer':offered.offer.to_bech32()})
            with pytest.raises(ValueError):await execution.accept_payer(intent,bad,browser_hash=browser)
            assert execution_store.saved(intent,browser_hash=browser)['deliveryClaim'] is None
            assert (await execution.accept_payer(intent,delivery_claim,browser_hash=browser))['payerAuthorizationSaved']
            assert (await execution.accept_payer(intent,delivery_claim,browser_hash=browser))['payerAuthorizationSaved']
        else:current_store.save_delivery(intent,delivery_claim,browser_hash=browser,now=now)
        reopened_store=CurrentCustomerPurchaseStore(current_store.path,c.prep.generation_id)
        assert reopened_store.saved(intent,browser_hash=browser)['deliveryClaim']==delivery_claim
        checked=await verify_current_delivery(delivery_claim,settings=bound,anchor=built.anchor,provider=c.provider,
            issuer_policy=issuer_policy,expected_issuer_policy_hash=issuer_policy.commitment,clock=lambda:now)
        assert bytes(checked.bundle)==bytes(full)
        delivery_signatures=[]
        for slot in (0,1):
            signer_settings=SimpleNamespace(**bound.model_dump());signer_settings.generation_customer_purchase_enabled=True
            signer_settings.signer_index=slot;signer_settings.roster_pubkeys=[h(bytes(k.get_g1()))for k in validators]
            ledger=ValidatorLedger(tmp_path/('current-purchase-validator-'+str(slot)+'.sqlite3'))
            loads=[]
            def load_delivery_key():loads.append(slot);return validators[slot]
            call=dict(settings=signer_settings,anchor=built.anchor,provider=c.provider,ledger=ledger,
                issuer_policy=issuer_policy,expected_issuer_policy_hash=issuer_policy.commitment,clock=lambda:now)
            response=await sign_current_delivery(delivery_claim,delivery_claim.digest(),load_key=load_delivery_key,**call)
            delivery_replies[slot]=response.model_dump(mode='json')
            assert loads==[slot]
            recovered=await sign_current_delivery(delivery_claim,delivery_claim.digest(),load_key=no_second_key_read,**call)
            assert response==recovered
            delivery_signatures.append(G2Element.from_bytes(bytes.fromhex(response.signature[2:])))
            ledger.close()
        full=SpendBundle(full.coin_spends,AugSchemeMPL.aggregate([full.aggregated_signature,*delivery_signatures]))
    unforwarded=full
    route_operation=None
    forwarding=None
    if proceeds is not None:
        roots=[coin for spend in full.coin_spends for coin in compute_additions(spend)
            if coin.puzzle_hash==proceeds.inner().get_tree_hash()]
        assert len(roots)==1
        route_operation=proceeds.operation(roots[0])
        full=SpendBundle([*full.coin_spends,*route_operation.spends],full.aggregated_signature)
    elif getattr(c,'testnet_forwarding_candidate',False):
        from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
        fees=PrimaryFeeSplitter(built.anchor.issuance.bindings(),
            bytes32.from_hexstr(c.prep.coordinates['parameters'].launcher_id),
            CompanyRevenue(bindings.generation,built.authority.authority_launcher_id))
        args=dict(bundle=full,artifact=quote,terms=terms,
            issuer_public_key=bytes(c.faucet.key.wallet_pk),fees=fees)
        forwarding=build_testnet_primary_forwarding(**args)
        with pytest.raises(ValueError,match='cannot authorize'):
            build_testnet_primary_forwarding(**{**args,'issuer_public_key':bytes(owner.get_g1())})
        assert forwarding.review()['issuerSignatureRequired']
        assert not forwarding.review()['serverSigningAuthorityGranted']
        proceeds=forwarding.proceeds;route_operation=forwarding.operation
        full=SpendBundle([*full.coin_spends,*route_operation.spends],full.aggregated_signature)
    # Sign the remaining delivery conditions as well as the exact buyer spend.
    keys=[synthetic,*validators]
    if forwarding is not None:
        incomplete=signed(SpendBundle(full.coin_spends,G2Element()),keys+[c.faucet.key.wallet_sk],c.faucet.agg_sig_me_data)
        # Removing the issuer's authorization must not spend the proceeds.
        missing=SpendBundle(incomplete.coin_spends,AugSchemeMPL.aggregate([
            AugSchemeMPL.sign(key,message) for spend in incomplete.coin_spends
            for public,message in pkm_pairs_for_conditions_dict(
                conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,11_000_000_000),spend.coin,c.faucet.agg_sig_me_data)
            for key in keys if bytes(key.get_g1())==bytes(public)]))
        assert (await c.client.push_tx(missing))[0]!=MempoolInclusionStatus.SUCCESS
        keys.append(c.faucet.key.wallet_sk)
    full=signed(SpendBundle(full.coin_spends,G2Element()),keys,c.faucet.agg_sig_me_data)
    if forwarding is not None:
        # The compatibility signer has a finite policy and durable replay
        # record. It receives only the exact payout message, never arbitrary
        # wallet spends or a general-purpose key RPC.
        from solslot_api.generation_customer_issuer import TestnetIssuerPolicy,TestnetIssuerJournal
        policy=issuer_policy
        base=unforwarded if current_verified is not None else signed(SpendBundle(unforwarded.coin_spends,G2Element()),keys[:-1],c.faucet.agg_sig_me_data)
        calls=[]
        def issuer_sign(message):calls.append(message);return AugSchemeMPL.sign(c.faucet.key.wallet_sk,message)
        location=tmp_path/'issuer-guard.db';guard=TestnetIssuerJournal(location,policy)
        guarded=guard.authorize(bundle=base,artifact=quote,terms=terms,fees=fees,now=now,sign_message=issuer_sign)
        retained_signature=G2Element.from_bytes(bytes.fromhex(guard.db.execute('SELECT signature FROM issuer_forwarding').fetchone()[0][2:]))
        assert len(calls)==1 and bytes(guarded)==bytes(full)
        with pytest.raises(ValueError,match='EXPIRED'):
            guard.authorize(bundle=base,artifact=quote,terms=terms,fees=fees,now=policy.expires_at,sign_message=issuer_sign)
        with pytest.raises(ValueError,match='SCOPE_CHANGED'):
            guard.authorize(bundle=base,artifact=replace(quote,vault_launcher_id=b32(211)),terms=terms,fees=fees,now=now,sign_message=issuer_sign)
        with pytest.raises(ValueError,match='BUDGET_EXHAUSTED'):
            guard.authorize(bundle=base,artifact=replace(quote,authorization_nonce=b32(212)),terms=terms,fees=fees,now=now,sign_message=issuer_sign)
        assert len(calls)==1
        guard.close();guard=TestnetIssuerJournal(location,policy)
        def no_second_signature(_):raise AssertionError('a saved authorization must not prompt or sign again')
        assert bytes(guard.authorize(bundle=base,artifact=quote,terms=terms,fees=fees,now=now,
            sign_message=no_second_signature))==bytes(guarded)
        if execution is not None:
            # Independently reconstruct the entire coordinator handoff before
            # using the scoped issuer key. Replays recover the durable result.
            from solslot_api.generation_customer_purchase_issuer import CurrentIssuerRequest,sign_current_issuer
            _,issuer_base,companion,pair=await execution.delivery_issuer_review(intent,delivery_claim,browser_hash='ab'*32)
            request=CurrentIssuerRequest(generationId=bound.deployment_generation_id,policyHash=policy.commitment,
                claim=delivery_claim,claimHash=delivery_claim.digest(),purchaseBundle=issuer_base.to_json_dict(),
                issuerCoinSpend=companion.issuer_signature_spend.to_json_dict(),issuerPublicKey=h(bytes(pair[0])),message=h(bytes(pair[1])))
            def no_issuer_key_load():raise AssertionError('retained issuer work must not reopen a key')
            args=dict(settings=execution.settings,anchor=built.anchor,provider=c.provider,journal=guard,
                load_key=no_issuer_key_load,clock=lambda:now)
            assert await sign_current_issuer(request,**args)==retained_signature
            with pytest.raises(ValueError,match='REVIEW_CHANGED'):
                await sign_current_issuer(request.model_copy(update={'message':h(bytes(96))}),**args)
            unsigned=issuer_base.to_json_dict();unsigned['aggregated_signature']=h(bytes(G2Element()))
            with pytest.raises(ValueError,match='QUORUM_SIGNATURES_REQUIRED'):
                await sign_current_issuer(request.model_copy(update={'purchase_bundle':unsigned}),**args)
        guard.close()
        with pytest.raises(ValueError,match='POLICY_CHANGED'):
            TestnetIssuerJournal(location,replace(policy,expires_at=policy.expires_at+1))
        full=guarded
        if execution is not None:
            await execution.prepare_delivery(intent,delivery_claim,retained_signature,browser_hash='ab'*32)
            assert bytes(execution_store.execution_bundle(intent,'DELIVERY',browser_hash='ab'*32))==bytes(full)
            await execution._revalidate_prepared(execution_store.saved(intent,browser_hash='ab'*32),'DELIVERY',full)
            execution_store.save_execution_funding(intent,'DELIVERY',PreparedProtocolBundle(full,0,h(b32(226))),browser_hash='ab'*32,now=now)
    print("native: purchase admission",flush=True);assert await c.client.push_tx(full)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    assert (await c.client.push_tx(full))[0]!=MempoolInclusionStatus.SUCCESS
    print("native: purchase confirmed",flush=True);after=await resolve_current_primary_inventory(**inventory_args)
    assert sum(item.available for item in after.items)==24
    with pytest.raises(ValueError,match='NOT_AVAILABLE'):after.require_available(terms.deed_launcher_id)
    # Exactly one governed NFT is delivered to this vault's p2 custody.
    # An offer uses an ephemeral singleton settlement output before the final
    # vault-custody output. Follow that chain rather than mistaking it for the tip.
    spends_by_id={spend.coin.name():spend for spend in full.coin_spends}
    delivered=reserved_coin
    for _ in range(len(full.coin_spends)+1):
        spend=spends_by_id.get(delivered.name())
        if spend is None:break
        children=[coin for coin in compute_additions(spend) if coin.amount%2]
        assert len(children)==1
        delivered=children[0]
    else:pytest.fail('the delivered deed did not leave the atomic offer bundle')
    assert delivered.amount==1
    assert delivered.puzzle_hash==SINGLETON_MOD.curry(structure,puzzle_for_p2_vault(vault.launcher)).get_tree_hash()
    assert (await c.client.get_coin_record_by_name(delivered.name())).spent is False
    # The customer dashboard follows the actual confirmed current-generation
    # mint/delivery lineage, including its custom DID launcher and ephemeral
    # offer outputs. A wallet match or an old collection row is not ownership.
    from solslot_api.generation_customer_portfolio import read_current_portfolio
    from solslot_api.generation_chain_evidence import resolve_generation_chain
    async def primary_parents(ids, *, include_spent=False):
        return [r.to_json_dict() for r in await c.client.get_coin_records_by_parent_ids(
            [bytes32.from_hexstr(value) for value in ids], include_spent_coins=include_spent)]
    c.provider.get_coin_records_by_parent_ids_primary = primary_parents
    portfolio = await read_current_portfolio(
        snapshot={'generationId':h(bindings.generation),'network':'testnet11','authType':'chia_bls',
            'vault':vault.public()},
        evidence=await resolve_generation_chain(built.anchor,provider=c.provider),
        sgt_bindings=built.anchor.issuance.bindings(),provider=c.provider,
        metadata_for_edition=lambda found: source['canonicalMetadata'] if found.commitment==edition.commitment else None)
    assert len(portfolio['holdings'])==1
    assert portfolio['holdings'][0]['deedCoinId']==h(delivered.name())
    assert portfolio['holdings'][0]['sharePpm']==terms.share_ppm
    assert portfolio['verification']['mintedDeedsChecked']==25
    assert portfolio['vault']['identityConfirmed']
    assert not portfolio['capabilities']['primaryPurchase']['available']
    print("native: verify fee outputs",flush=True);fee_candidates=[coin for spend in full.coin_spends for coin in compute_additions(spend) if coin.puzzle_hash==terms.protocol_treasury_puzzle_hash]
    import json,os
    from pathlib import Path
    if target:=os.environ.get('CURRENT_PURCHASE_EVIDENCE'):
        issuer_destination=proceeds.issuer if proceeds is not None else terms.protocol_puzhash
        spent_ids={spend.coin.name() for spend in full.coin_spends}
        issuer=[coin for spend in full.coin_spends for coin in compute_additions(spend)
            if coin.puzzle_hash==issuer_destination and coin.name() not in spent_ids]
        location=Path(target)
        route='forwarding' if forwarding is not None else 'prebound' if proceeds is not None else 'legacy-defect'
        location=location.with_name(location.stem+'-'+route+location.suffix)
        location.write_text(json.dumps({'schema':'solslot.synthetic-current-purchase.v1',
            'liveTransaction':False,'syntheticKeysAndPrice':True,'network':'testnet11',
            'localFutureRouteCandidate':proceeds is not None and forwarding is None,
            'issuerAuthorizedForwardingCandidate':forwarding is not None,
            'freshRegistrationConfirmed':True,'freshBridgeCoupledIdConfirmed':True,
            'paymentConfirmed':True,'duplicateSubmissionRejected':True,'remainingAvailable':24,
            'deliveredDeedCoinId':h(delivered.name()),'deliveredPuzzleHash':h(delivered.puzzle_hash),
            'quoteMojos':quote.rail_amount,'feeBps':terms.technology_fee_bps,
            'issuerProceedsMojos':sum(int(coin.amount) for coin in issuer),
            'feeSplitterMojos':sum(int(coin.amount) for coin in fee_candidates),
            'feeSplitterOutputCount':len(fee_candidates),
            'feeSplitterPuzzleHash':h(terms.protocol_treasury_puzzle_hash),
            'issuerProceedsPuzzleHash':h(issuer_destination)},indent=2)+'\n')
    if proceeds is None and forwarding is None:
        # The retained inventory really permits the old SDK's unsplit gross
        # payout. Keep that defect executable and explicit: the current quote
        # service rejected this route above. A passing negative test is not a
        # claim that the old immutable contract now enforces the new split.
        assert fee_candidates == []
        spent_ids={spend.coin.name() for spend in full.coin_spends}
        gross=[coin for spend in full.coin_spends for coin in compute_additions(spend)
            if coin.puzzle_hash==terms.protocol_puzhash and coin.name() not in spent_ids]
        assert sum(int(coin.amount) for coin in gross)==quote.rail_amount
        ctx.collections.close()
        return
    assert len(fee_candidates)==1
    revenue=CompanyRevenue(bindings.generation,built.authority.authority_launcher_id)
    splitter=PrimaryFeeSplitter(built.anchor.issuance.bindings(),bytes32.from_hexstr(c.prep.coordinates['parameters'].launcher_id),revenue)
    fee=fee_candidates[0];split=splitter.operation(fee)
    assert split.spends[0].coin.puzzle_hash==terms.protocol_treasury_puzzle_hash
    if route_operation is None:
        assert await c.client.push_tx(split.bundle())==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    else:
        assert (await c.client.get_coin_record_by_name(fee.name())).spent
    outputs=compute_additions(split.spends[0]);company=next(coin for coin in outputs if coin.puzzle_hash==revenue.inner().get_tree_hash())
    assert company.amount==(int(fee.amount)*70+99)//100
    assert sum(coin.amount for coin in outputs)==fee.amount
    assert next(coin for coin in outputs if coin!=company).amount==int(fee.amount)-int(company.amount)
    ctx.collections.close()

@pytest.mark.asyncio
@pytest.mark.parametrize('real_synthetic_identity_policy',['forwarding'],indirect=True)
async def test_native_current_checkout_timeout_releases_unpaid_inventory(core,tmp_path,real_synthetic_identity_policy,monkeypatch):
    core.checkout_timeout_candidate=True
    await test_native_current_checkout_delivery_and_fee_boundaries(core,tmp_path,real_synthetic_identity_policy,monkeypatch)


@pytest.mark.asyncio
@pytest.mark.parametrize('real_synthetic_identity_policy',['forwarding'],indirect=True)
async def test_native_current_nominal_txch_checkout_delivery(core,tmp_path,real_synthetic_identity_policy,monkeypatch):
    core.checkout_nominal_candidate=True
    await test_native_current_checkout_delivery_and_fee_boundaries(core,tmp_path,real_synthetic_identity_policy,monkeypatch)
