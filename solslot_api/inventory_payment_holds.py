"""Service-only prepayment journal; no charging, timeout dispatch or inventory reuse."""
import time
import uuid
import asyncio

from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from solslot_puzzles.stripe_settlement_v1_driver import build_inventory_release_spend
from .inventory_extension_chain import current_position
from .inventory_payment_hold_claims import (
    InventoryPaymentHoldClaim, InventoryPaymentHoldAbortClaim, payment_hold_activation,
)
from .inventory_recovery import hx
from .payment_purchase_store import PaymentPurchaseConflict
from .validator_quorum import collect_inventory_payment_hold_quorum, configured_validator_pubkeys


def verify_hold_receipt(claim,receipt,artifact):
    hold=claim.hold if isinstance(claim,InventoryPaymentHoldAbortClaim) else claim
    try:
        if (hold.genesis_artifact_hash!=artifact['artifactHash']
                or hold.activation!=payment_hold_activation(artifact,hold.activation['environment'])
                or artifact['validatorSet']['threshold']!=2):raise ValueError('release mismatch')
        indices=receipt['signerIndices']
        if (set(receipt)!={'schema','claimHash','signerIndices','signature'}
                or receipt['schema']!='solslot.inventory-payment-hold-quorum.v1'
                or receipt['claimHash']!=claim.canonical_hash() or type(indices) is not list or len(indices)!=2
                or any(type(i) is not int or i not in (0,1,2) for i in indices) or sorted(set(indices))!=indices):
            raise ValueError('quorum identity mismatch')
        roster=artifact['validatorSet']['pubkeys']
        if len(roster)!=3:raise ValueError('roster mismatch')
        keys=[G1Element.from_bytes(bytes.fromhex(roster[i].removeprefix('0x'))) for i in indices]
        signature=G2Element.from_bytes(bytes.fromhex(receipt['signature'].removeprefix('0x')))
        if not AugSchemeMPL.aggregate_verify(keys,[claim.signature_message()]*2,signature):raise ValueError('invalid signature')
    except (KeyError,TypeError,ValueError,IndexError,AttributeError) as exc:
        raise PaymentPurchaseConflict('retained payment hold quorum is not authentic for this exact release') from exc


def receipt_for(claim,quorum,artifact):
    receipt=dict(schema='solslot.inventory-payment-hold-quorum.v1',claimHash=quorum.claim_hash,
                 signerIndices=list(quorum.signer_indices),signature=hx(quorum.aggregated_signature))
    verify_hold_receipt(claim,receipt,artifact)
    return receipt


def checkout_status(operation,artifact,*,now):
    if operation is None:return None
    claim=InventoryPaymentHoldClaim.model_validate(operation['claim'])
    # Even an ARMING record must retain its exact current reviewed deployment.
    if (claim.genesis_artifact_hash!=artifact['artifactHash']
            or claim.activation!=payment_hold_activation(artifact,claim.activation['environment'])):
        raise PaymentPurchaseConflict('checkout recovery requires its original reviewed release')
    if operation['armReceipt'] is not None:verify_hold_receipt(claim,operation['armReceipt'],artifact)
    if operation['state']=='ARMED' and operation['armReceipt'] is None:
        raise PaymentPurchaseConflict('armed checkout lacks its verified quorum')
    if operation['abortReceipt'] is not None:
        aborted=InventoryPaymentHoldAbortClaim.model_validate(operation['abortClaim'])
        if aborted.hold!=claim:raise PaymentPurchaseConflict('abort changes its retained payment hold')
        verify_hold_receipt(aborted,operation['abortReceipt'],artifact)
    if operation['state']=='ABORTED' and operation['abortReceipt'] is None:
        raise PaymentPurchaseConflict('aborted checkout lacks its verified quorum')
    return dict(state=operation['state'],purchaseId=operation['purchaseId'],paymentIntentId=claim.payment_intent_id,
        paymentMethod=claim.payment_method,claimHash=claim.canonical_hash(),artifactHash=claim.genesis_artifact_hash,
        activation=claim.activation,reservedCoinId=claim.reserved_coin_id,expiresAt=claim.reservation_expires_at,
        confirmationAllowed=operation['state']=='ARMED' and now<claim.reservation_expires_at,
        inventoryReusable=False,paymentRetryAllowed=False,armReceipt=operation['armReceipt'],abortReceipt=operation['abortReceipt'])


async def arm_checkout(*,store,settings,purchase_id,payment_intent_id,payment_method,load_artifact,authorize):
    authorize();artifact=load_artifact()
    active=payment_hold_activation(artifact,settings.runtime_environment+'-alpha')
    if (settings.network!='testnet11' or active['adapterVersion']!=2
            or [hx(k) for k in configured_validator_pubkeys(settings)]!=artifact['validatorSet']['pubkeys']):
        raise PaymentPurchaseConflict('checkout requires the reviewed isolated hold coordinator and validator roster')
    stored=store.get(purchase_id)
    from .purchase_admission import recheck_admitted_owner
    recheck_admitted_owner(store,purchase_id)
    position=current_position(stored,store.inventory_items(purchase_id),artifact)
    if stored.inventory_extension_receipts:raise PaymentPurchaseConflict('checkout cannot replace an extended payment')
    claim=InventoryPaymentHoldClaim(network=settings.network,genesis_artifact_hash=artifact['artifactHash'],activation=active,
        purchase_artifact=stored.purchase_artifact,smart_deed_inner_hash=hx(position.terms.smart_deed_inner_hash),
        reserved_coin_id=hx(position.coin.name()),reserved_puzzle_hash=hx(position.coin.puzzle_hash),
        reservation_expires_at=position.reservation.expires_at,payment_intent_id=payment_intent_id,payment_method=payment_method)
    # This commit precedes all private requests, including a lost/partial reply.
    retained=store.claim_checkout_hold(purchase_id,claim=claim.model_dump(mode='json'),expected_snapshot=stored,now=int(time.time()))
    if retained['state']=='ARMED':return checkout_status(retained,artifact,now=int(time.time()))
    owner=uuid.uuid4().hex
    store.claim_checkout_quorum(purchase_id,kind='arm',owner=owner,now=int(time.time()))
    try:
        quorum=await asyncio.wait_for(collect_inventory_payment_hold_quorum(settings,claim),timeout=90)
        authorize();fresh=load_artifact()
        recheck_admitted_owner(store,purchase_id)
        if fresh!=artifact:raise PaymentPurchaseConflict('checkout release changed while arming')
        store.preserve_checkout_arm(purchase_id,claim=claim,receipt=receipt_for(claim,quorum,fresh),artifact=fresh,
                                   expected_snapshot=stored,now=int(time.time()))
        return checkout_status(store.checkout_hold(purchase_id),fresh,now=int(time.time()))
    finally:store.finish_checkout_quorum(purchase_id,owner=owner,now=int(time.time()))


async def abort_checkout(*,store,settings,purchase_id,load_artifact):
    """Observe canceled/unfunded original return; never cancel or broadcast here."""
    artifact=load_artifact();operation=store.checkout_hold(purchase_id)
    if operation is None:raise PaymentPurchaseConflict('checkout has no retained prepayment hold')
    checkout_status(operation,artifact,now=int(time.time()))
    hold=InventoryPaymentHoldClaim.model_validate(operation['claim'])
    if (hold.activation!=payment_hold_activation(artifact,settings.runtime_environment+'-alpha')
            or settings.network!='testnet11' or hold.activation['adapterVersion']!=2
            or [hx(k) for k in configured_validator_pubkeys(settings)]!=artifact['validatorSet']['pubkeys']):
        raise PaymentPurchaseConflict('abort requires the original reviewed coordinator deployment')
    stored=store.get(purchase_id);position=current_position(stored,store.inventory_items(purchase_id),artifact)
    if stored.inventory_extension_receipts:raise PaymentPurchaseConflict('extended payment needs terminal release reconciliation')
    returned=build_inventory_release_spend(reserved_coin=position.coin,deed_singleton_struct=position.struct,
        lineage_proof=lineage_proof_for_coinsol(position.creation_spend),reservation=position.reservation,terms=position.terms,timed_out=True)
    claim=InventoryPaymentHoldAbortClaim(hold=hold,reserved_coin_id=hx(position.coin.name()),
        reservation_expires_at=position.reservation.expires_at,available_coin_id=hx(returned.next_coin.name()))
    store.claim_checkout_abort(purchase_id,claim=claim)
    if operation['state']=='ABORTED':return checkout_status(operation,artifact,now=int(time.time()))
    owner=uuid.uuid4().hex
    store.claim_checkout_quorum(purchase_id,kind='abort',owner=owner,now=int(time.time()))
    try:
        quorum=await asyncio.wait_for(collect_inventory_payment_hold_quorum(settings,claim),timeout=90)
        fresh=load_artifact()
        if fresh!=artifact:raise PaymentPurchaseConflict('checkout release changed during partial cancellation')
        store.preserve_checkout_abort(purchase_id,claim=claim,receipt=receipt_for(claim,quorum,fresh),artifact=fresh)
        return checkout_status(store.checkout_hold(purchase_id),fresh,now=int(time.time()))
    finally:store.finish_checkout_quorum(purchase_id,owner=owner,now=int(time.time()))
