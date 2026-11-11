"""Current-generation adapter for the existing canonical native batch driver.

One review binds every child. Evidence is reconstructed for every deed before
wallet or private signing; completion remains one atomic native transaction.
There is no new key, price authority, token, or deployed puzzle in this adapter.
"""
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal
import time

from pydantic import Field, model_validator
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.wallet.util.compute_hints import compute_spend_hints_and_additions
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import (purchase_artifact_v3_from_json,
    purchase_batch_from_json, purchase_batch_to_json)
from solslot_puzzles.stripe_settlement_v1_driver import (
    prepare_chia_buyer_batch_offer_v3, build_native_primary_batch_offer_v5)
from .generation_execution import Model, Hash
from .generation_operations import canonical
from .generation_customer_purchase_scope import quote_deadline
from .generation_customer_purchase_reservation import CurrentReservationClaim, verify_current_reservation
from .generation_customer_purchase_delivery import resolve_current_reserved_purchase
from .generation_chain_evidence import current_evidence_unchanged
from .generation_sols_batch_execution import unspent
from .generation_sols_batches import external_inputs, verify_order_signature
from .generation_coin_evidence import read_confirmed_coin
from .wallet_offer_validation import decode_offer, validate_standard_payment


def h(value): return '0x'+bytes(value).hex()


class CurrentReservationBatch(Model):
    schema_version:Literal['solslot.current-customer-reservation-batch.v1']='solslot.current-customer-reservation-batch.v1'
    purchase_batch:dict=Field(alias='purchaseBatch')
    children:tuple[CurrentReservationClaim,...]=Field(min_length=2,max_length=25)

    @model_validator(mode='after')
    def bound(self):
        batch=purchase_batch_from_json(self.purchase_batch)
        if (purchase_batch_to_json(batch)!=self.purchase_batch or batch.quantity!=len(self.children)
                or len(self.canonical().encode())>2_000_000):
            raise ValueError('CURRENT_PURCHASE_BATCH_CANONICAL_BINDING_REQUIRED')
        first=self.children[0]
        for child,artifact in zip(self.children,batch.artifacts,strict=True):
            if (purchase_artifact_v3_from_json(child.purchase_artifact)!=artifact
                    or any(getattr(child,k)!=getattr(first,k)for k in
                        ('generation_id','anchor_hash','issuer_policy_hash','current_vault_coin_id','signer_indices','signed_price'))):
                raise ValueError('CURRENT_PURCHASE_BATCH_CHILD_CHANGED')
        if len({c.available_coin_id for c in self.children})!=len(self.children):
            raise ValueError('CURRENT_PURCHASE_BATCH_DUPLICATE_INVENTORY')
        return self

    @property
    def generation_id(self):return self.children[0].generation_id
    @property
    def issuer_policy_hash(self):return self.children[0].issuer_policy_hash
    @property
    def signer_indices(self):return self.children[0].signer_indices
    def canonical(self):return canonical(self.model_dump(mode='json',by_alias=True))
    def digest(self):return '0x'+sha256(self.canonical().encode()).hexdigest()


class CurrentDeliveryBatch(Model):
    schema_version:Literal['solslot.current-customer-delivery-batch.v1']='solslot.current-customer-delivery-batch.v1'
    reservation:CurrentReservationBatch
    reserved_coin_ids:tuple[Hash,...]=Field(alias='reservedCoinIds',min_length=2,max_length=25)
    buyer_offer:str=Field(alias='buyerOffer',min_length=16,max_length=2_000_000)

    @model_validator(mode='after')
    def bound(self):
        if len(self.reserved_coin_ids)!=len(self.reservation.children) or len(set(self.reserved_coin_ids))!=len(self.reserved_coin_ids):
            raise ValueError('CURRENT_DELIVERY_BATCH_EXACT_COINS_REQUIRED')
        return self
    def canonical(self):return canonical(self.model_dump(mode='json',by_alias=True))
    def digest(self):return '0x'+sha256(self.canonical().encode()).hexdigest()


def reservation_from_json(raw):
    value=__import__('json').loads(raw)if isinstance(raw,str)else raw
    cls=CurrentReservationBatch if value.get('schema_version')=='solslot.current-customer-reservation-batch.v1' else CurrentReservationClaim
    return cls.model_validate(value)


def delivery_from_json(raw):
    from .generation_customer_purchase_delivery import CurrentDeliveryClaim
    value=__import__('json').loads(raw)if isinstance(raw,str)else raw
    cls=CurrentDeliveryBatch if value.get('schema_version')=='solslot.current-customer-delivery-batch.v1' else CurrentDeliveryClaim
    return cls.model_validate(value)


def artifacts(claim):
    return purchase_batch_from_json(claim.purchase_batch).artifacts if isinstance(claim,CurrentReservationBatch) else (purchase_artifact_v3_from_json(claim.purchase_artifact),)


@dataclass(frozen=True)
class CurrentBatchEvidence:
    claim:object
    batch:object
    children:tuple
    purchase:object=None
    bundle:object=None
    payment_coin:object=None
    delivery_outputs:tuple=()

    @property
    def inventory(self):return self.children[0].inventory
    @property
    def vault(self):return self.children[0].vault


async def fresh_children(children,provider):
    """Recheck the shared authority and every input after the full bounded read."""
    first=children[0]
    tips=lambda c:tuple(sorted((bytes(r.coin.name()),r.confirmed_height,r.spent_height)for r in c.inventory.evidence.current_records))
    for child in children:
        # Native state objects contain parsed tree instances; compare the
        # independently proved coin commitments, not Python object identity.
        if child.vault.coin!=first.vault.coin or tips(child)!=tips(first):
            raise ValueError('CURRENT_PURCHASE_BATCH_CONTEXT_CHANGED_DURING_READ')
    if not await current_evidence_unchanged(first.inventory.evidence,provider=provider):
        raise ValueError('CURRENT_PURCHASE_BATCH_AUTHORITY_CHANGED')
    await unspent(provider,first.vault.coin)
    for child in children:
        await unspent(provider,child.transition.reserved_coin if hasattr(child,'artifact')else child.item.current.coin)


async def verify_current_batch_reservation(claim,**arguments):
    claim=CurrentReservationBatch.model_validate_json(claim.model_dump_json(by_alias=True))
    first=await verify_current_reservation(claim.children[0],**arguments)
    current=(first.inventory,first.vault)
    children=(first,*[await verify_current_reservation(child,**arguments,_current=current)for child in claim.children[1:]])
    await fresh_children(children,arguments['provider'])
    if int(arguments.get('clock',time.time)())>=quote_deadline(arguments['issuer_policy'],artifacts(claim)[0].quote_expires_at):
        raise ValueError('CURRENT_PURCHASE_BATCH_EXPIRED_DURING_READ')
    return CurrentBatchEvidence(claim,purchase_batch_from_json(claim.purchase_batch),children)


async def reserved_children(claim,coins,**arguments):
    if len(coins)!=len(claim.children)or len(set(coins))!=len(coins):
        raise ValueError('CURRENT_DELIVERY_BATCH_EXACT_COINS_REQUIRED')
    first=await resolve_current_reserved_purchase(claim.children[0],coins[0],**arguments)
    current=(first.inventory,first.vault)
    children=(first,*[await resolve_current_reserved_purchase(child,coin,**arguments,_current=current)
        for child,coin in zip(claim.children[1:],coins[1:],strict=True)])
    await fresh_children(children,arguments['provider'])
    return children


async def verify_current_batch_delivery(claim,**arguments):
    claim=CurrentDeliveryBatch.model_validate_json(claim.model_dump_json(by_alias=True))
    batch=purchase_batch_from_json(claim.reservation.purchase_batch)
    children=await reserved_children(claim.reservation,claim.reserved_coin_ids,**arguments)
    decoded=decode_offer(claim.buyer_offer,real_spends=1,dummy_spends=len(children),
        expected_assets=frozenset(a.deed_launcher_id for a in batch.artifacts),allow_signed=True)
    validate_standard_payment(decoded,asset_id=None)
    _,cost=compute_spend_hints_and_additions(decoded.real_spends[0],max_cost=100_000_000)
    if not 0<=cost<=100_000_000:raise ValueError('CURRENT_DELIVERY_BATCH_WALLET_COST_EXCEEDED')
    buyer=Offer.from_spend_bundle(decoded.bundle);inputs=external_inputs(buyer)
    if len(inputs)!=1 or len(buyer._bundle.coin_spends)!=1:
        raise ValueError('CURRENT_DELIVERY_BATCH_ONE_PAYMENT_COIN_REQUIRED')
    verify_order_signature(buyer);await unspent(arguments['provider'],inputs[0])
    purchase=build_native_primary_batch_offer_v5(buyer_offer=buyer,batch=batch,
        deed_coins=[c.transition.reserved_coin for c in children],
        deed_singleton_structs=[c.deed_structure for c in children],
        lineage_proofs=[LineageProof(c.item.current.coin.parent_coin_info,c.item.current.inner.get_tree_hash(),c.item.current.coin.amount)for c in children],
        signer_indices_by_artifact=[c.claim.signer_indices for c in children],
        terms=[c.item.original.terms for c in children],reservations=[c.transition.reservation for c in children])
    bundle=purchase.to_valid_spend()
    # Reuse the original checkout's exact descendant/receipt checks, including
    # the ephemeral NFT offer settlement before final vault custody.
    from types import SimpleNamespace
    from .native_purchases import _governed_smartdeed_outputs
    group=SimpleNamespace(contexts=tuple(SimpleNamespace(deed_struct=c.deed_structure,
        purchase=a,deed_coin=c.transition.reserved_coin)for c,a in zip(children,batch.artifacts,strict=True)))
    outputs=_governed_smartdeed_outputs(group,bundle)
    if len(outputs)!=len(children)or len({o.coin_id for o in outputs})!=len(children):
        raise ValueError('CURRENT_DELIVERY_BATCH_EXACT_OUTPUTS_REQUIRED')
    await fresh_children(children,arguments['provider']);await unspent(arguments['provider'],inputs[0])
    if int(arguments.get('clock',time.time)())>=quote_deadline(arguments['issuer_policy'],batch.artifacts[0].quote_expires_at):
        raise ValueError('CURRENT_DELIVERY_BATCH_EXPIRED_DURING_READ')
    return CurrentBatchEvidence(claim,batch,children,purchase,bundle,inputs[0],outputs)


class CurrentBatchPaymentRequest(Model):
    reservation:CurrentReservationBatch
    reserved_coin_ids:tuple[Hash,...]=Field(alias='reservedCoinIds',min_length=2,max_length=25)
    payment_coin_id:Hash=Field(alias='paymentCoinId')
    payment_public_key:str=Field(alias='paymentPublicKey',pattern=r'^0x[0-9a-f]{96}$')
    payment_public_key_kind:Literal['raw','synthetic']=Field(default='raw',alias='paymentPublicKeyKind')


@dataclass(frozen=True)
class CurrentBatchPaymentPreparation:
    request:CurrentBatchPaymentRequest
    children:tuple
    batch:object
    prepared:object
    payment_record:object
    observed_at:int

    def review(self):
        r,p,b=self.request,self.prepared,self.batch
        terms=[c.item.original.terms for c in self.children]
        first=b.artifacts[0]
        value={'schema':'solslot.current-native-payment-review.v2','network':'testnet11',
            'generationId':r.reservation.generation_id,'reservationClaimHash':r.reservation.digest(),
            'purchaseBatch':purchase_batch_to_json(b),'quantity':len(b.artifacts),
            'purchaseId':h(b.purchase_id),'artifactHash':h(b.batch_hash),
            'collectionId':h(first.collection_id),'metadataRoot':h(first.metadata_root),'editionHash':h(first.metadata_anchor_id),
            'deedLauncherIds':[h(a.deed_launcher_id)for a in b.artifacts],
            'deedLauncherPuzzleHashes':[h(t.deed_launcher_puzzle_hash)for t in terms],
            'smartDeedInnerHashes':[h(t.smart_deed_inner_hash)for t in terms],
            'recipientVaultLauncherId':h(first.vault_launcher_id),'recipientVaultP2PuzzleHash':h(first.vault_p2_puzzle_hash),
            'currentVaultCoinId':r.reservation.children[0].current_vault_coin_id,
            'reservedCoinIds':list(r.reserved_coin_ids),'paymentCoinId':r.payment_coin_id,'paymentPublicKey':r.payment_public_key,'paymentPublicKeyKind':r.payment_public_key_kind,
            'amountMojos':str(b.total_rail_amount),'baseAmountUsdMinor':str(b.total_base_amount_minor),
            'technologyFeeUsdMinor':str(b.total_technology_fee_minor),'totalAmountUsdMinor':str(b.total_subtotal_minor),
            'changeMojos':str(int(p.coin_spend.coin.amount)-b.total_rail_amount),'changePuzzleHash':h(p.payment_puzzle.get_tree_hash()),
            'payerCoin':{'parentCoinInfo':h(p.coin_spend.coin.parent_coin_info),'puzzleHash':h(p.coin_spend.coin.puzzle_hash),'amount':str(p.coin_spend.coin.amount)},
            'payerConfirmedHeight':self.payment_record.confirmed_height,'observedAt':self.observed_at,'walletFeeMojos':'0',
            'quoteExpiresAt':first.quote_expires_at,'buyerOffer':p.offer.to_bech32(),'coinSpends':[p.coin_spend.to_json_dict()]}
        return {**value,'reviewHash':'0x'+sha256(canonical(value).encode()).hexdigest()}

    def signed_delivery(self,signature):
        if not isinstance(signature,G2Element):raise ValueError('CURRENT_PAYMENT_TYPED_SIGNATURE_REQUIRED')
        original=self.prepared.offer
        buyer=Offer(original.requested_payments,WalletSpendBundle(original.coin_spends(),signature),original.driver_dict)
        verify_order_signature(buyer)
        return CurrentDeliveryBatch(reservation=self.request.reservation,reservedCoinIds=self.request.reserved_coin_ids,buyerOffer=buyer.to_bech32())


async def prepare_current_batch_payment(request,**arguments):
    request=CurrentBatchPaymentRequest.model_validate_json(request.model_dump_json(by_alias=True))
    public=G1Element.from_bytes(bytes.fromhex(request.payment_public_key[2:]))
    if public==G1Element():raise ValueError('CURRENT_PAYMENT_NONIDENTITY_KEY_REQUIRED')
    children=await reserved_children(request.reservation,request.reserved_coin_ids,**arguments)
    record=read_confirmed_coin(await arguments['provider'].get_coin_record_by_name_primary(request.payment_coin_id),bytes32.from_hexstr(request.payment_coin_id))
    if record.spent_height:raise ValueError('CURRENT_PAYMENT_CONFIRMED_UNSPENT_COIN_REQUIRED')
    batch=purchase_batch_from_json(request.reservation.purchase_batch)
    prepared=prepare_chia_buyer_batch_offer_v3(payment_coin=record.coin,payment_public_key=bytes(public), payment_public_key_kind=request.payment_public_key_kind,batch=batch,
        terms=[c.item.original.terms for c in children],deed_singleton_structs=[c.deed_structure for c in children])
    if len(prepared.offer.coin_spends())!=1 or prepared.offer.fees()!=0:
        raise ValueError('CURRENT_PAYMENT_ONE_ZERO_FEE_WALLET_INPUT_REQUIRED')
    await unspent(arguments['provider'],record.coin);await fresh_children(children,arguments['provider'])
    now=int(arguments.get('clock',time.time)())
    if now>=quote_deadline(arguments['issuer_policy'],batch.artifacts[0].quote_expires_at):
        raise ValueError('CURRENT_PAYMENT_REVIEW_EXPIRED_DURING_READ')
    return CurrentBatchPaymentPreparation(request,children,batch,prepared,record,now)
