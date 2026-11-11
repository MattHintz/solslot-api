"""Recover one expired native TXCH reservation from confirmed ancestry.

This path never renews a quote or relies on a customer's current ID. The old
native before-deadline condition must be impossible on the primary node before
the signatureless timeout transition can be prepared. Fee authority is separate.
"""
import time
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json,purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1,build_inventory_reservation_spend,build_inventory_release_spend
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_customer_purchase_reservation import CurrentReservationClaim
from .generation_customer_purchase_delivery import _confirmed_reservation_source
from .generation_customer_purchase_validators import prove_primary_expired_source
from .generation_customer_inventory import resolve_current_primary_inventory
from .generation_chain_evidence import current_evidence_unchanged

def h(v):return '0x'+bytes(v).hex()

async def verify_current_timeout(claim,reserved_coin_id,*,settings,anchor,provider,
        issuer_policy,expected_issuer_policy_hash,clock=time.time):
    if not isinstance(claim,CurrentReservationClaim):raise ValueError('CURRENT_TIMEOUT_TYPED_CLAIM_REQUIRED')
    claim=CurrentReservationClaim.model_validate_json(claim.model_dump_json(by_alias=True))
    if (not isinstance(issuer_policy,(TestnetIssuerPolicy,TestnetCollectionIssuerPolicy))or issuer_policy.commitment!=expected_issuer_policy_hash
            or claim.issuer_policy_hash!=expected_issuer_policy_hash or settings.network!='testnet11'
            or claim.generation_id!=settings.deployment_generation_id or claim.anchor_hash!=settings.generation_chain_anchor_hash
            or bytes32.from_hexstr(claim.generation_id)!=anchor.issuance.generation
            or issuer_policy.generation!=anchor.issuance.generation):
        raise ValueError('CURRENT_TIMEOUT_POLICY_BINDING_CHANGED')
    now=int(clock());purchase=purchase_artifact_v3_from_json(claim.purchase_artifact)
    if (purchase_artifact_v3_to_json(purchase)!=claim.purchase_artifact or purchase.rail!=PaymentRail.CHIA_XCH
            or purchase.collection_id!=issuer_policy.collection or purchase.metadata_anchor_id!=issuer_policy.edition
            or purchase.metadata_root!=issuer_policy.metadata_root
            or (isinstance(issuer_policy,TestnetIssuerPolicy) and purchase.vault_launcher_id!=issuer_policy.buyer_vault)
            or purchase.deed_launcher_id not in issuer_policy.deed_launchers
            or (isinstance(issuer_policy,TestnetIssuerPolicy) and not issuer_policy.issued_at<=now<issuer_policy.expires_at)
            or now<purchase.quote_expires_at):raise ValueError('CURRENT_TIMEOUT_FINITE_SCOPE_CHANGED')
    inventory=await resolve_current_primary_inventory(settings=settings,anchor=anchor,provider=provider,
        collection=issuer_policy.collection,edition_hash=issuer_policy.edition,metadata_root=issuer_policy.metadata_root)
    matches=[x for x in inventory.items if x.original.terms.deed_launcher_id==purchase.deed_launcher_id]
    if len(matches)!=1:raise ValueError('CURRENT_TIMEOUT_MINT_MISSING')
    original=matches[0].original;terms=original.terms
    issuer_policy.require_terms(terms,now=now)
    current,lineage,record,actual=await _confirmed_reservation_source(original,claim.available_coin_id,provider)
    reservation=InventoryReservationV1(purchase,purchase.quote_expires_at)
    structure=Program.to((SINGLETON_MOD_HASH,(terms.deed_launcher_id,terms.deed_launcher_puzzle_hash)))
    transition=build_inventory_reservation_spend(available_coin=current.coin,deed_singleton_struct=structure,
        lineage_proof=lineage,reservation=reservation,signer_indices=claim.signer_indices,terms=terms)
    if bytes(actual)!=bytes(transition.spend)or reserved_coin_id is not None and h(transition.reserved_coin.name())!=reserved_coin_id:
        raise ValueError('CURRENT_TIMEOUT_CONFIRMED_RESERVATION_CHANGED')
    proof=await prove_primary_expired_source(provider,transition.reserved_coin,reservation.expires_at)
    if proof['confirmedHeight']!=record.spent_height:raise ValueError('CURRENT_TIMEOUT_RESERVATION_HEIGHT_CHANGED')
    released=build_inventory_release_spend(reserved_coin=transition.reserved_coin,deed_singleton_struct=structure,
        lineage_proof=LineageProof(current.coin.parent_coin_info,current.inner.get_tree_hash(),current.coin.amount),
        reservation=reservation,terms=terms,timed_out=True)
    if not await current_evidence_unchanged(inventory.evidence,provider=provider):
        raise ValueError('CURRENT_TIMEOUT_AUTHORITY_CHANGED')
    # A changing primary peak is retried; no consensus clock is inferred from
    # wall time, another explorer, or the previous browser's saved result.
    await prove_primary_expired_source(provider,transition.reserved_coin,reservation.expires_at)
    return SpendBundle([released.spend],G2Element())
