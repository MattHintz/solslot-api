"""Offline native mainnet card settlement, with synthetic keys, custody and provider observations."""
from dataclasses import replace
from hashlib import sha256
from secrets import token_bytes
from types import SimpleNamespace

import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD, lineage_proof_for_coinsol
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, Coin, G2Element, MEMPOOL_MODE, get_flags_for_height_and_constants, validate_clvm_and_signature
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32
from solslot_puzzles import load_puzzle
from solslot_puzzles.mint_publish_driver import (
    canonical_p2_pool_mod_hash, deed_launcher_puzzle_hash, deed_singleton_struct, make_smart_deed_inner,
)
from solslot_puzzles.payment_artifacts_v3 import (
    STRIPE_PAYMENT_PROVIDER_ID, build_purchase_batch_settlement_receipt_v1, build_purchase_batch_v1,
    build_stripe_purchase_artifact_v3, purchase_batch_from_json, purchase_batch_to_json,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1, PrimaryMintTermsV3, PurchaseBatchSettlementTermsV1,
    build_external_primary_batch_offer_v5, build_inventory_reservation_spend, build_inventory_release_spend,
    build_purchase_batch_receipt_spend, curry_purchase_batch_settlement_receipt,
    make_inventory_available_inner, prepare_purchase_batch_receipt_offer,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault, puzzle_hash_for_p2_vault

from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.governed_output_index import EvaluatedBundleOutputs
from solslot_api.stripe_delivery_worker import _batch_settlement_outputs
from solslot_api.vault_card_events import EvidenceMismatch, PAID, payment_evidence
from solslot_api.vault_card_provider import metadata


COST_LIMIT = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM
FLAGS = get_flags_for_height_and_constants(uint32(10_000_000), DEFAULT_CONSTANTS) | MEMPOOL_MODE
WHEN = 1_700_000_000


def digest(label):
    return bytes32(sha256(('offline vault card Chia mainnet ' + label).encode()).digest())


def hex_id(value):
    return '0x' + value.hex()


def signed_spends(spends, keys, network):
    by_public = {key.get_g1(): key for key in keys}
    signatures = []
    for spend in spends:
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, COST_LIMIT)
        pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA[network])
        signatures.extend(AugSchemeMPL.sign(by_public[pk], message) for pk, message in pairs)
    return WalletSpendBundle(list(spends), AugSchemeMPL.aggregate(signatures)), len(signatures)


def originals(keys, version):
    did = singleton_struct(digest('protocol did'))
    launcher_ph = deed_launcher_puzzle_hash(protocol_did_singleton_struct=did)
    candidates = [Coin(digest('launcher parent ' + str(i)), launcher_ph, 1) for i in range(12)]
    # Use a canonical pair in the same signed-CLVM sort range for the batch receipt.
    chosen = sorted((c for c in candidates if c.name()[0] < 128), key=lambda c: c.name())[:2]
    assert len(chosen) == 2
    outputs = []
    for launcher in chosen:
        struct = deed_singleton_struct(deed_launcher_id=launcher.name(), protocol_did_singleton_struct=did)
        smart_deed = make_smart_deed_inner(deed_singleton_struct_program=struct,
            protocol_did_puzhash=digest('protocol did puzzle'),par_value_mojos=1,
            asset_class=1,property_id_canon=digest('property'),collection_id_canon=digest('collection'),
            share_ppm=125000,jurisdiction=b'US-TN',royalty_puzhash=digest('royalty'),royalty_bps=0,
            pool_singleton_launcher_id=digest('pool'),pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
            p2_pool_mod_hash=canonical_p2_pool_mod_hash(),p2_vault_mod_hash=load_puzzle('p2_vault.clsp').get_tree_hash())
        purchase=build_stripe_purchase_artifact_v3(network='mainnet',collection_id=digest('collection'),
            deed_launcher_id=launcher.name(),metadata_root=digest('metadata'),metadata_anchor_id=digest('edition'),
            share_ppm=125000,base_usd_amount_minor=300000,technology_fee_bps=100,
            protocol_treasury_puzzle_hash=digest('technology'),zkpassport_root=digest('credential'),
            vault_launcher_id=digest('vault'),vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(digest('vault')),
            authorization_nonce=digest('authorization'),authorization_expires_at=WHEN+7200,quote_expires_at=WHEN+7200)
        terms=PrimaryMintTermsV3.for_artifact(artifact=purchase,smart_deed_inner_hash=smart_deed.get_tree_hash(),
            deed_launcher_puzzle_hash=launcher_ph,protocol_puzhash=digest('primary proceeds'),
            validator_pubkeys=tuple(bytes(key.get_g1()) for key in keys),inventory_version=version)
        inner=make_inventory_available_inner(terms)
        original=Coin(launcher.name(),SINGLETON_MOD.curry(struct,inner).get_tree_hash(),1)
        args=dict(available_coin=original,deed_singleton_struct=struct,terms=terms,
            lineage_proof=LineageProof(launcher.parent_coin_info,amount=launcher.amount),signer_indices=(0,1))
        reservation=InventoryReservationV1(purchase,purchase.quote_expires_at)
        with pytest.raises(ValueError,match='network'):
            build_inventory_reservation_spend(**args,reservation=InventoryReservationV1(
                replace(purchase,network='testnet11'),purchase.quote_expires_at))
        transition=build_inventory_reservation_spend(**args,reservation=reservation)
        outputs.append(SimpleNamespace(purchase=purchase,terms=terms,struct=struct,transition=transition,
                                       deed_coin=transition.reserved_coin))
    return outputs


def card_observation(batch):
    order=SimpleNamespace(mode='live',network='mainnet',account_id='acct_synthetic',purchase_id=hex_id(batch.purchase_id),
        batch_hash=hex_id(batch.batch_hash),generation_id=hex_id(digest('generation')),
        collection_id=hex_id(batch.artifacts[0].collection_id),vault_launcher_id=hex_id(batch.vault_launcher_id),
        destination_puzzle_hash=hex_id(batch.vault_p2_puzzle_hash),deed_launcher_ids=tuple(hex_id(a.deed_launcher_id) for a in batch.artifacts),
        payment_intent_id='pi_synthetic',session_id='cs_live_synthetic',amount_minor=batch.total_rail_amount,currency='usd')
    charge=dict(id='ch_synthetic',livemode=True,currency='usd',payment_intent=order.payment_intent_id,
        paid=True,captured=True,amount_captured=order.amount_minor,refunded=False,amount_refunded=0,disputed=False,
        payment_method_details={'type':'card','card':{'funding':'debit'}})
    intent=dict(id=order.payment_intent_id,livemode=True,status='succeeded',currency='usd',amount=order.amount_minor,
                amount_received=order.amount_minor,created=WHEN,metadata=metadata(order),latest_charge=charge)
    session=dict(id=order.session_id,livemode=True,payment_intent=order.payment_intent_id,client_reference_id=order.purchase_id,
        metadata=metadata(order),currency='usd',mode='payment',status='complete',payment_status='paid',amount_total=order.amount_minor)
    event=dict(id='evt_synthetic',type=PAID,livemode=True,account=order.account_id,created=WHEN+1,
               data={'object':{'id':order.payment_intent_id}})
    for changed in (dict(intent,livemode=False),dict(intent,latest_charge=dict(charge,livemode=False))):
        with pytest.raises(EvidenceMismatch,match='environment'):
            payment_evidence(order,changed,session,event,WHEN+2)
    with pytest.raises(EvidenceMismatch,match='environment'):
        payment_evidence(order,intent,dict(session,livemode=False),event,WHEN+2)
    with pytest.raises(EvidenceMismatch,match='environment'):
        payment_evidence(order,intent,session,dict(event,livemode=False),WHEN+2)
    return payment_evidence(order,intent,session,event,WHEN+2)


@pytest.mark.parametrize('version',[1,2])
def test_offline_mainnet_inventory_and_two_deed_card_receipt(version):
    assert DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA == AGG_SIG_ME_DATA['mainnet']
    keys=[AugSchemeMPL.key_gen(token_bytes(32)) for _ in range(3)]
    items=originals(keys,version)
    batch=build_purchase_batch_v1(batch_nonce=digest('batch nonce'),artifacts=tuple(i.purchase for i in items))
    assert purchase_batch_from_json(purchase_batch_to_json(batch))==batch
    assert (batch.network,batch.quantity,batch.total_base_amount_minor,batch.total_technology_fee_minor,batch.total_rail_amount)==(
        'mainnet',2,600000,6000,606000)
    reserves=[i.transition.spend for i in items]
    if version==1:
        # V2 introduced an explicit subtotal argument to rail-is-valid and
        # inlined reserve-conditions. Exercise the immutable V1 bytecode as issued.
        for spend in reserves:
            with pytest.raises(ValueError,match='clvm raise'):
                conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,COST_LIMIT)
        print('mainnet historical inventory V1: both original Stripe reservation spends rejected by compiled CLVM')
        return
    signed,count=signed_spends(reserves,keys,'mainnet')
    assert count==4
    conditions,*_=validate_clvm_and_signature(signed,COST_LIMIT,DEFAULT_CONSTANTS,FLAGS)
    assert set(signed.additions())=={i.deed_coin for i in items}
    wrong,_=signed_spends(reserves,keys,'testnet11')
    with pytest.raises(ValueError):
        validate_clvm_and_signature(wrong,COST_LIMIT,DEFAULT_CONSTANTS,FLAGS)
    # Independently validate the mutually exclusive timeout branch from each reservation.
    returns=[]
    for item in items:
        recovery=build_inventory_release_spend(reserved_coin=item.deed_coin,deed_singleton_struct=item.struct,
            lineage_proof=lineage_proof_for_coinsol(item.transition.spend),reservation=item.transition.reservation,
            terms=item.terms,timed_out=True)
        assert recovery.next_coin.puzzle_hash==item.transition.spend.coin.puzzle_hash
        conditions_by_opcode=conditions_dict_for_solution(recovery.spend.puzzle_reveal,recovery.spend.solution,COST_LIMIT)
        after=conditions_by_opcode[ConditionOpcode.ASSERT_SECONDS_ABSOLUTE]
        assert [int.from_bytes(row.vars[0],'big') for row in after]==[item.purchase.quote_expires_at]
        returns.append(recovery.spend)
    return_bundle=WalletSpendBundle(returns,G2Element())
    return_conditions,*_=validate_clvm_and_signature(return_bundle,COST_LIMIT,DEFAULT_CONSTANTS,FLAGS)
    assert len(return_bundle.additions())==2
    evidence=card_observation(batch)
    roster=items[0].terms.validator_pubkeys
    receipt=build_purchase_batch_settlement_receipt_v1(batch=batch,provider_id=STRIPE_PAYMENT_PROVIDER_ID,
        external_reference_hash=evidence.payment_reference_hash,evidence_hash=evidence.evidence_hash,
        observed_at=evidence.observed_at,validator_pubkeys=roster,collected_amount_minor=evidence.amount_minor,
        processing_charge_minor=evidence.processing_charge_minor)
    receipt_terms=PurchaseBatchSettlementTermsV1(receipt,roster)
    coin=Coin(digest('unfunded receipt parent'),curry_purchase_batch_settlement_receipt(receipt_terms).get_tree_hash(),2)
    receipt_spend=build_purchase_batch_receipt_spend(receipt_coin=coin,terms=receipt_terms,signer_indices=(0,1))
    terms=tuple(i.terms for i in items)
    structs=tuple(i.struct for i in items)
    offer=prepare_purchase_batch_receipt_offer(receipt_spend=receipt_spend,receipt=receipt,terms=terms,deed_singleton_structs=structs)
    primary=build_external_primary_batch_offer_v5(receipt_offer=offer,receipt_coin=coin,receipt=receipt,
        deed_coins=tuple(i.deed_coin for i in items),deed_singleton_structs=structs,
        lineage_proofs=tuple(lineage_proof_for_coinsol(i.transition.spend) for i in items),
        terms=terms,reservations=tuple(i.transition.reservation for i in items))
    final,count=signed_spends(primary.to_valid_spend().coin_spends,keys,'mainnet')
    assert count==2
    checked,*_=validate_clvm_and_signature(final,COST_LIMIT,DEFAULT_CONSTANTS,FLAGS)
    graph=EvaluatedBundleOutputs(final)
    received=[graph.find_exact_descendant(ancestor_coin_id=i.deed_coin.name(),
        puzzle_hash=SINGLETON_MOD.curry(i.struct,puzzle_for_p2_vault(batch.vault_launcher_id)).get_tree_hash(),
        amount=1,label='vault deed') for i in items]
    payouts=_batch_settlement_outputs(coin,tuple(items),final,graph,
        result_puzzle_hash=receipt.result_authorization_puzzle_hash)
    assert all(p.puzzle_hash==digest('primary proceeds') and p.amount==1 for p in payouts)
    assert len({c.name() for c in (*received,*payouts)})==4
    assert not set(c.name() for c in (*received,*payouts)).intersection(c.name() for c in final.removals())
    print('mainnet inventory V%d: reservation cost %d, delivery cost %d, timed return cost %d, two vault outputs, two proceeds outputs'
          % (version,conditions.cost,checked.cost,return_conditions.cost))
