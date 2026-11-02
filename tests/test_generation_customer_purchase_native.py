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
async def test_native_current_checkout_delivery_and_fee_boundaries(core,tmp_path,real_synthetic_identity_policy):
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
    pay_coin=Coin(origins[2].name(),payment_puzzle.get_tree_hash(),uint64(1_000_000_000))
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
        quote=current_customer_xch_quote(vault=vault,forwarding_policy=issuer_policy,**quote_args)
        for bad in (replace(issuer_policy,buyer_vault=b32(203)),
                replace(issuer_policy,issuer_public_key=owner_pk)):
            with pytest.raises(ValueError,match='FEE_ROUTE_CHANGED'):
                current_customer_xch_quote(vault=vault,forwarding_policy=bad,**quote_args)
        with pytest.raises(ValueError,match='AMOUNT_CAP'):
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
    reservation=InventoryReservationV1(quote,quote.quote_expires_at)
    # Use the exact singleton wrapper constant from the native driver.
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
    structure=Program.to((SINGLETON_MOD_HASH,(terms.deed_launcher_id,terms.deed_launcher_puzzle_hash)))
    print("native: reservation",flush=True);reserved=build_inventory_reservation_spend(available_coin=item.current.coin,deed_singleton_struct=structure,
        lineage_proof=item.lineage,reservation=reservation,signer_indices=(0,1),terms=terms)
    reservation_bundle=signed(SpendBundle([reserved.spend],G2Element()),validators,c.faucet.agg_sig_me_data)
    assert await c.client.push_tx(reservation_bundle)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
    print("native: reservation confirmed",flush=True);reserved_coin=reserved.reserved_coin
    offered=prepare_chia_buyer_offer_v3(payment_coin=pay_coin,payment_public_key=bytes(payment_pk.get_g1()),artifact=quote,terms=terms,deed_singleton_struct=structure)
    raw=SpendBundle([offered.coin_spend],G2Element());payment_signed=signed(raw,[synthetic],c.faucet.agg_sig_me_data)
    buyer=Offer(offered.offer.requested_payments,WalletSpendBundle(payment_signed.coin_spends,payment_signed.aggregated_signature),offered.offer.driver_dict)
    print("native: offer combine",flush=True);purchase=build_native_primary_offer_v5(buyer_offer=buyer,deed_coin=reserved_coin,deed_singleton_struct=structure,
        lineage_proof=LineageProof(parent_name=item.current.coin.parent_coin_info,inner_puzzle_hash=item.current.inner.get_tree_hash(),amount=uint64(1)),
        artifact=quote,signer_indices=(0,1),terms=terms,reservation=reservation)
    print("native: offer finalize",flush=True);full=purchase.aggregate_offer.to_valid_spend()
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
        base=signed(SpendBundle(unforwarded.coin_spends,G2Element()),keys[:-1],c.faucet.agg_sig_me_data)
        calls=[]
        def issuer_sign(message):calls.append(message);return AugSchemeMPL.sign(c.faucet.key.wallet_sk,message)
        location=tmp_path/'issuer-guard.db';guard=TestnetIssuerJournal(location,policy)
        guarded=guard.authorize(bundle=base,artifact=quote,terms=terms,fees=fees,now=now,sign_message=issuer_sign)
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
        guard.close()
        with pytest.raises(ValueError,match='POLICY_CHANGED'):
            TestnetIssuerJournal(location,replace(policy,expires_at=policy.expires_at+1))
        full=guarded
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
