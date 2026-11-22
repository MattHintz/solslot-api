"""Construct a native TXCH purchase from verified, still-available inventory.

No step in this module issues a signature, allocates a sponsor coin or submits
a transaction. The intermediate inventory outputs live inside the final spend.
"""
from dataclasses import dataclass
from types import SimpleNamespace

from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element, SpendBundle

from solslot_puzzles.stripe_settlement_v1_driver import (
    build_native_primary_batch_offer_v5, build_native_primary_offer_v5,
    prepare_chia_buyer_batch_offer_v3, prepare_chia_buyer_offer_v3,
)
from .generation_customer_purchase_batch import CurrentBatchEvidence, artifacts
from .generation_customer_purchase_reservation import CurrentReservationEvidence
from .generation_sols_batches import verify_order_signature


@dataclass(frozen=True)
class AtomicPurchase:
    claim_digest: str
    inventory_spends: tuple
    delivery_bundle: WalletSpendBundle
    buyer_offer: Offer
    network_fee_mojos: int
    delivery_outputs: tuple

    def bundle(self, forwarding_spends=()):
        delivery = self.delivery_bundle
        spends = [*self.inventory_spends, *delivery.coin_spends, *forwarding_spends]
        if len({s.coin.name() for s in spends}) != len(spends):
            raise ValueError('Duplicate settlement input')
        bundle = SpendBundle(spends, delivery.aggregated_signature)
        if sum(int(c.amount) for c in bundle.removals()) - sum(int(c.amount) for c in bundle.additions()) != self.network_fee_mojos:
            raise ValueError('Settlement fee differs from buyer approval')
        return bundle


def purchase_inputs(evidence):
    if isinstance(evidence, CurrentBatchEvidence):
        children = evidence.children
    elif isinstance(evidence, CurrentReservationEvidence):
        children = (evidence,)
    else:
        raise ValueError('Verified inventory evidence required')
    terms = tuple(child.item.original.terms for child in children)
    structures = tuple(Program.to((SINGLETON_MOD_HASH, (term.deed_launcher_id, term.deed_launcher_puzzle_hash))) for term in terms)
    return children, terms, structures


def prepare_buyer_payment(evidence, *, payment_coin, payment_public_key, payment_public_key_kind, network_fee_mojos):
    children, terms, structures = purchase_inputs(evidence)
    wallet = dict(payment_coin=payment_coin, payment_public_key=payment_public_key,
                  payment_public_key_kind=payment_public_key_kind, network_fee_mojos=network_fee_mojos)
    if len(children) == 1:
        return prepare_chia_buyer_offer_v3(artifact=artifacts(evidence.claim)[0], terms=terms[0],
                                           deed_singleton_struct=structures[0], **wallet)
    return prepare_chia_buyer_batch_offer_v3(batch=evidence.batch, terms=terms, deed_singleton_structs=structures, **wallet)


def assemble_purchase(evidence, *, buyer_signature, payment_coin, payment_public_key, payment_public_key_kind, network_fee_mojos):
    if not isinstance(buyer_signature, G2Element):
        raise ValueError('Buyer signature required')
    prepared = prepare_buyer_payment(evidence, payment_coin=payment_coin, payment_public_key=payment_public_key,
                                     payment_public_key_kind=payment_public_key_kind, network_fee_mojos=network_fee_mojos)
    original = prepared.offer
    buyer = Offer(original.requested_payments, WalletSpendBundle([prepared.coin_spend], buyer_signature), original.driver_dict)
    verify_order_signature(buyer)
    return _build_purchase(evidence, buyer, network_fee_mojos)


def _build_purchase(evidence, buyer, network_fee_mojos):
    from .native_purchases import _governed_smartdeed_outputs
    children, terms, structures = purchase_inputs(evidence)
    lineage = tuple(LineageProof(c.item.current.coin.parent_coin_info, c.item.current.inner.get_tree_hash(),
                                 c.item.current.coin.amount) for c in children)
    if len(children) == 1:
        child = children[0]
        delivery = build_native_primary_offer_v5(buyer_offer=buyer, artifact=artifacts(evidence.claim)[0],
            deed_coin=child.transition.reserved_coin, deed_singleton_struct=structures[0],
            lineage_proof=lineage[0], signer_indices=child.claim.signer_indices, terms=terms[0], reservation=child.reservation)
        delivery_bundle = delivery.aggregate_offer.to_valid_spend()
    else:
        delivery = build_native_primary_batch_offer_v5(buyer_offer=buyer, batch=evidence.batch,
            deed_coins=[child.transition.reserved_coin for child in children], deed_singleton_structs=structures,
            lineage_proofs=lineage, signer_indices_by_artifact=[child.claim.signer_indices for child in children],
            terms=terms, reservations=[child.reservation for child in children])
        delivery_bundle = delivery.to_valid_spend()
    contexts = tuple(SimpleNamespace(deed_struct=structure, purchase=artifact, deed_coin=child.transition.reserved_coin)
                     for structure, artifact, child in zip(structures, artifacts(evidence.claim), children, strict=True))
    outputs = _governed_smartdeed_outputs(SimpleNamespace(contexts=contexts), delivery_bundle)
    if len(outputs) != len(children) or len({output.coin_id for output in outputs}) != len(children):
        raise ValueError('Each selected deed requires one distinct verified vault output')
    return AtomicPurchase(evidence.claim.digest(), tuple(child.transition.spend for child in children),
                          delivery_bundle, buyer, network_fee_mojos, outputs)


def unsigned_settlement_cost(evidence, *, wallet, network_fee_mojos, forwarding_builder, height):
    """Measure all coin spends before asking the buyer to sign."""
    from chia.consensus.default_constants import DEFAULT_CONSTANTS
    from chia_rs import get_conditions_from_spendbundle
    from .faucet import AGG_SIG_ME_DATA
    prepared = prepare_buyer_payment(evidence, **wallet, network_fee_mojos=network_fee_mojos)
    purchase = _build_purchase(evidence, prepared.offer, network_fee_mojos)
    bundle = purchase.bundle(forwarding_builder(purchase.delivery_bundle))
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=AGG_SIG_ME_DATA['testnet11'])
    conditions = get_conditions_from_spendbundle(bundle, constants.MAX_BLOCK_COST_CLVM, constants, height)
    if conditions.reserve_fee != network_fee_mojos:
        raise ValueError('Network fee condition differs from selection')
    return int(conditions.cost)
