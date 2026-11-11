"""R1 current-generation TXCH delivery reconstruction, no endpoint or broadcast.

The private signer follows confirmed mint/reservation ancestry, verifies fresh
ID, frozen price/terms and the original wallet offer, then signs only its own
native delivery condition. Coordinator-provided coin spends are never authority.
"""
from dataclasses import dataclass,replace
from hashlib import sha256
import json,time
from typing import Literal
from pydantic import Field,model_validator
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia.wallet.util.compute_hints import compute_spend_hints_and_additions
from chia.wallet.trading.offer import Offer
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL,G1Element,G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json,purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1,build_inventory_reservation_spend,build_native_primary_offer_v5
from .generation_execution import Model,Hash
from .generation_operations import canonical
from .generation_customer_purchase_reservation import CurrentReservationClaim
from .generation_customer_inventory import resolve_current_primary_inventory,CurrentPrimaryItem
from .generation_customer_context import customer_bindings_from_evidence
from .generation_customer_vault import resolve_native_identity_vault
from .generation_customer_quote import current_customer_xch_quote
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_preparation import read_generation_preparation
from .generation_sols_batch_execution import signed_price,unspent
from .generation_coin_evidence import read_confirmed_coin
from .generation_registry_evidence import _spend
from .generation_chain_evidence import current_evidence_unchanged
from .generation_sols_batches import external_inputs,verify_order_signature
from .wallet_offer_validation import decode_offer,validate_standard_payment
from .validator_quorum import ValidatorSignatureResponse
from .faucet import AGG_SIG_ME_DATA
from .generation_customer_test_conversion import claim_price


def h(v):return '0x'+bytes(v).hex()

class CurrentDeliveryClaim(Model):
    schema_version:Literal['solslot.current-customer-delivery.v1']='solslot.current-customer-delivery.v1'
    reservation:CurrentReservationClaim
    reserved_coin_id:Hash=Field(alias='reservedCoinId')
    buyer_offer:str=Field(alias='buyerOffer',min_length=16,max_length=2_000_000)
    def canonical(self):return canonical(self.model_dump(mode='json',by_alias=True))
    def digest(self):return '0x'+sha256(self.canonical().encode()).hexdigest()


@dataclass(frozen=True)
class CurrentDeliveryEvidence:
    claim:CurrentDeliveryClaim
    inventory:object
    item:object
    vault:object
    reservation_transition:object
    purchase:object
    bundle:object
    payment_coin:object


@dataclass(frozen=True)
class CurrentReservedPurchaseEvidence:
    claim:CurrentReservationClaim
    inventory:object
    item:object
    vault:object
    transition:object
    artifact:object
    deed_structure:object


async def _confirmed_reservation_source(original,identity,provider):
    coin,parent=original.coin,original.launcher_spend
    for _ in range(64):
        record=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(coin.name())),coin.name())
        if record.coin!=coin:raise ValueError('CURRENT_DELIVERY_ANCESTRY_COIN_CHANGED')
        if h(coin.name())==identity:
            if coin.puzzle_hash!=original.coin.puzzle_hash or not record.spent_height:
                raise ValueError('CURRENT_DELIVERY_RESERVATION_UNCONFIRMED')
            if parent.coin.name()==original.launcher_spend.coin.name():
                lineage=LineageProof(parent.coin.parent_coin_info,amount=parent.coin.amount)
            else:
                mod,args=Program.from_bytes(bytes(parent.puzzle_reveal)).uncurry();values=list(args.as_iter())
                if mod.get_tree_hash()!=SINGLETON_MOD_HASH or len(values)!=2:raise ValueError('CURRENT_DELIVERY_ANCESTRY_WRAPPER_CHANGED')
                lineage=LineageProof(parent.coin.parent_coin_info,values[1].get_tree_hash(),parent.coin.amount)
            spend=_spend(await provider.get_puzzle_and_solution_primary(identity,record.spent_height),coin)
            return replace(original,coin=coin),lineage,record,spend
        if not record.spent_height:raise ValueError('CURRENT_DELIVERY_RESERVATION_SOURCE_MISSING')
        parent=_spend(await provider.get_puzzle_and_solution_primary(h(coin.name()),record.spent_height),coin)
        outputs,_=compute_additions_with_cost(parent,max_cost=100_000_000)
        odd=[c for c in outputs if c.amount%2]
        if len(odd)!=1 or odd[0].amount!=1:raise ValueError('CURRENT_DELIVERY_ANCESTRY_NOT_SINGLETON')
        coin=odd[0]
    raise ValueError('CURRENT_DELIVERY_ANCESTRY_LIMIT')


async def verify_current_delivery(claim,*,settings,anchor,provider,issuer_policy,
        expected_issuer_policy_hash,clock=time.time):
    from .generation_customer_purchase_batch import CurrentDeliveryBatch, verify_current_batch_delivery
    if isinstance(claim,CurrentDeliveryBatch):
        return await verify_current_batch_delivery(claim,settings=settings,anchor=anchor,provider=provider,
            issuer_policy=issuer_policy,expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock)
    if not isinstance(claim,CurrentDeliveryClaim):raise ValueError('CURRENT_DELIVERY_TYPED_CLAIM_REQUIRED')
    claim=CurrentDeliveryClaim.model_validate_json(claim.model_dump_json(by_alias=True))
    checked=await resolve_current_reserved_purchase(claim.reservation,claim.reserved_coin_id,
        settings=settings,anchor=anchor,provider=provider,issuer_policy=issuer_policy,
        expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock)
    r=checked.claim;transition=checked.transition;purchase=checked.artifact
    inventory=checked.inventory;historical=checked.item;vault=checked.vault
    terms=historical.original.terms;struct=checked.deed_structure;now=int(clock())
    decoded=decode_offer(claim.buyer_offer,real_spends=1,dummy_spends=1,
        expected_assets=frozenset([purchase.deed_launcher_id]),allow_signed=True)
    validate_standard_payment(decoded,asset_id=None)
    # Only the bounded standard-wallet template is evaluated. Submitted offer
    # carriers remain data; they never receive a fresh CLVM execution budget.
    _,used=compute_spend_hints_and_additions(decoded.real_spends[0],max_cost=100_000_000)
    if not 0<=used<=100_000_000:raise ValueError('CURRENT_DELIVERY_WALLET_COST_EXCEEDED')
    buyer=Offer.from_spend_bundle(decoded.bundle);inputs=external_inputs(buyer)
    if len(inputs)!=1 or len(buyer._bundle.coin_spends)!=1:raise ValueError('CURRENT_DELIVERY_ONE_PAYMENT_COIN_REQUIRED')
    verify_order_signature(buyer)
    await unspent(provider,inputs[0])
    delivery=build_native_primary_offer_v5(buyer_offer=buyer,deed_coin=transition.reserved_coin,
        deed_singleton_struct=struct,lineage_proof=LineageProof(historical.current.coin.parent_coin_info,historical.current.inner.get_tree_hash(),historical.current.coin.amount),
        artifact=purchase,signer_indices=r.signer_indices,terms=terms,reservation=transition.reservation)
    bundle=delivery.aggregate_offer.to_valid_spend()
    if not await current_evidence_unchanged(inventory.evidence,provider=provider):raise ValueError('CURRENT_DELIVERY_AUTHORITY_CHANGED')
    await unspent(provider,transition.reserved_coin);await unspent(provider,vault.coin);await unspent(provider,inputs[0])
    if not now<=int(clock())<(min(purchase.quote_expires_at,issuer_policy.expires_at) if isinstance(issuer_policy,TestnetIssuerPolicy) else purchase.quote_expires_at):raise ValueError('CURRENT_DELIVERY_REVIEW_EXPIRED_DURING_READ')
    return CurrentDeliveryEvidence(claim,inventory,historical,vault,transition,delivery,bundle,inputs[0])


async def resolve_current_reserved_purchase(r,reserved_coin_id,*,settings,anchor,provider,issuer_policy,
        expected_issuer_policy_hash,clock=time.time,_current=None):
    """Prove the receiving vault and reservation before asking a payer to sign.

    Shared by wallet preparation and independent private delivery verification;
    a browser's stored confirmation or a supplied coin spend is insufficient.
    """
    if not isinstance(r,CurrentReservationClaim):raise ValueError('CURRENT_RESERVATION_TYPED_CLAIM_REQUIRED')
    r=CurrentReservationClaim.model_validate_json(r.model_dump_json(by_alias=True))
    if h(bytes32.from_hexstr(reserved_coin_id))!=reserved_coin_id:
        raise ValueError('CURRENT_RESERVATION_CANONICAL_COIN_REQUIRED')
    if (not isinstance(issuer_policy,(TestnetIssuerPolicy,TestnetCollectionIssuerPolicy))or issuer_policy.commitment!=expected_issuer_policy_hash
            or r.issuer_policy_hash!=expected_issuer_policy_hash or settings.network!='testnet11'
            or r.generation_id!=settings.deployment_generation_id or r.anchor_hash!=settings.generation_chain_anchor_hash
            or bytes32.from_hexstr(r.generation_id)!=anchor.issuance.generation
            or issuer_policy.generation!=anchor.issuance.generation):raise ValueError('CURRENT_DELIVERY_POLICY_BINDING_CHANGED')
    now=int(clock());purchase=purchase_artifact_v3_from_json(r.purchase_artifact)
    if (purchase_artifact_v3_to_json(purchase)!=r.purchase_artifact or purchase.rail!=PaymentRail.CHIA_XCH
            or purchase.collection_id!=issuer_policy.collection or purchase.metadata_anchor_id!=issuer_policy.edition
            or purchase.metadata_root!=issuer_policy.metadata_root
            or (isinstance(issuer_policy,TestnetIssuerPolicy) and purchase.vault_launcher_id!=issuer_policy.buyer_vault)
            or purchase.deed_launcher_id not in issuer_policy.deed_launchers
            or (isinstance(issuer_policy,TestnetIssuerPolicy) and not issuer_policy.issued_at<=now<issuer_policy.expires_at)):raise ValueError('CURRENT_DELIVERY_FINITE_SCOPE_CHANGED')
    inventory=(_current[0]if _current is not None else await resolve_current_primary_inventory(settings=settings,anchor=anchor,provider=provider,
        collection=issuer_policy.collection,edition_hash=issuer_policy.edition,metadata_root=issuer_policy.metadata_root))
    matches=[x for x in inventory.items if x.original.terms.deed_launcher_id==purchase.deed_launcher_id]
    if len(matches)!=1:raise ValueError('CURRENT_DELIVERY_MINT_MISSING')
    original=matches[0].original;terms=original.terms
    current,lineage,record,actual=await _confirmed_reservation_source(original,r.available_coin_id,provider)
    reservation=InventoryReservationV1(purchase,purchase.quote_expires_at)
    struct=Program.to((SINGLETON_MOD_HASH,(terms.deed_launcher_id,terms.deed_launcher_puzzle_hash)))
    transition=build_inventory_reservation_spend(available_coin=current.coin,deed_singleton_struct=struct,
        lineage_proof=lineage,reservation=reservation,signer_indices=r.signer_indices,terms=terms)
    if bytes(actual)!=bytes(transition.spend)or h(transition.reserved_coin.name())!=reserved_coin_id:
        raise ValueError('CURRENT_DELIVERY_CONFIRMED_RESERVATION_CHANGED')
    reserved=await unspent(provider,transition.reserved_coin)
    if reserved.confirmed_height!=record.spent_height:raise ValueError('CURRENT_DELIVERY_RESERVATION_HEIGHT_CHANGED')
    if _current is None:
        bindings=customer_bindings_from_evidence(read_generation_preparation(settings),anchor,inventory.evidence)
        vault=await resolve_native_identity_vault(bindings=bindings,launcher=purchase.vault_launcher_id,provider=provider)
    else:vault=_current[1]
    if h(vault.coin.name())!=r.current_vault_coin_id:raise ValueError('CURRENT_DELIVERY_RECIPIENT_CHANGED')
    # Reconstruct the exact still-live sealed quote from the proved historical
    # AVAILABLE source; it is not represented as currently for sale.
    historical=CurrentPrimaryItem(original,current,lineage,record.confirmed_height)
    quote_inventory=replace(inventory,items=tuple(historical if x.original.terms.deed_launcher_id==purchase.deed_launcher_id else x for x in inventory.items))
    rebuilt=current_customer_xch_quote(inventory=quote_inventory,vault=vault,deed_launcher=purchase.deed_launcher_id,
        price=claim_price(r.signed_price,issuer_policy),nonce=purchase.authorization_nonce,now=now,
        expires_at=purchase.quote_expires_at,forwarding_policy=issuer_policy)
    if rebuilt!=purchase:raise ValueError('CURRENT_DELIVERY_REVIEW_CHANGED')
    if not await current_evidence_unchanged(inventory.evidence,provider=provider):raise ValueError('CURRENT_DELIVERY_AUTHORITY_CHANGED')
    await unspent(provider,transition.reserved_coin);await unspent(provider,vault.coin)
    if not now<=int(clock())<(min(purchase.quote_expires_at,issuer_policy.expires_at) if isinstance(issuer_policy,TestnetIssuerPolicy) else purchase.quote_expires_at):raise ValueError('CURRENT_DELIVERY_REVIEW_EXPIRED_DURING_READ')
    return CurrentReservedPurchaseEvidence(r,inventory,historical,vault,transition,purchase,struct)


async def sign_current_delivery(claim,claim_hash,*,settings,anchor,provider,ledger,
        issuer_policy,expected_issuer_policy_hash,clock=time.time,load_key=None):
    from .generation_customer_purchase_batch_signing import sign_batch_delivery
    from .generation_customer_purchase_batch import CurrentDeliveryBatch
    if isinstance(claim,CurrentDeliveryBatch):
        return await sign_batch_delivery(claim,claim_hash,settings=settings,anchor=anchor,provider=provider,ledger=ledger,
            issuer_policy=issuer_policy,expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock,load_key=load_key)
    if (getattr(settings,'generation_customer_purchase_enabled',False)is not True
            or not isinstance(claim,CurrentDeliveryClaim)or claim.digest()!=claim_hash
            or settings.signer_index not in claim.reservation.signer_indices
            or (isinstance(issuer_policy,TestnetIssuerPolicy) and issuer_policy.maximum_purchases!=len(issuer_policy.deed_launchers))):
        raise ValueError('CURRENT_DELIVERY_SIGNER_NOT_ENABLED')
    evidence=await verify_current_delivery(claim,settings=settings,anchor=anchor,provider=provider,
        issuer_policy=issuer_policy,expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock)
    roster=tuple(bytes.fromhex(k.removeprefix('0x'))for k in settings.roster_pubkeys)
    if roster!=evidence.item.original.terms.validator_pubkeys:raise ValueError('CURRENT_DELIVERY_MINTED_ROSTER_CHANGED')
    spend=evidence.purchase.deed_spend
    conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
    pairs=pkm_pairs_for_conditions_dict(conditions,spend.coin,AGG_SIG_ME_DATA['testnet11'])
    if len(pairs)!=2 or {bytes(pk)for pk,_ in pairs}!={roster[i]for i in claim.reservation.signer_indices}:
        raise ValueError('CURRENT_DELIVERY_NATIVE_QUORUM_CHANGED')
    index=settings.signer_index;message=next(bytes(m)for pk,m in pairs if bytes(pk)==roster[index])
    prior=ledger.primary_purchase_authorization(claim_hash)
    if prior is not None:
        if prior['canonical_claim']!=claim.canonical():raise ValueError('CURRENT_DELIVERY_SAVED_CLAIM_CHANGED')
        signature=G2Element.from_bytes(bytes.fromhex(prior['signature'].removeprefix('0x')))
        if not AugSchemeMPL.verify(G1Element.from_bytes(roster[index]),message,signature):raise ValueError('CURRENT_DELIVERY_SAVED_SIGNATURE_CHANGED')
        encoded=prior['signature']
    else:
        if load_key is None:
            from .validator_service import load_validator_private_key
            private=load_validator_private_key(settings)
        else:private=load_key()
        if bytes(private.get_g1())!=roster[index]:raise ValueError('CURRENT_DELIVERY_PRIVATE_ROSTER_CHANGED')
        encoded='0x'+bytes(AugSchemeMPL.sign(private,message)).hex()
    encoded=ledger.record_primary_purchase_or_recover(claim_hash=claim_hash,canonical_claim=claim.canonical(),
        purchase_id=h(evidence.reservation_transition.reservation.artifact.purchase_id),
        deed_coin_id=claim.reserved_coin_id,signature=encoded)
    return ValidatorSignatureResponse(claimHash=claim_hash,signerIndex=index,validatorPubkey=h(roster[index]),signature=encoded)
