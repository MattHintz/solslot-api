"""R1 candidate: current-generation native reservation evidence.

No legacy genesis, registry import, signing credential, fee allocation, HTTP
endpoint or broadcaster. The caller supplies its independently frozen finite
issuer policy; customer input cannot select that policy or payout destination.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import time
from typing import Literal
from pydantic import Field,model_validator,StrictInt
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json,purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1,build_inventory_reservation_spend
from .generation_execution import Model,Hash
from .generation_operations import canonical
from .generation_customer_inventory import resolve_current_primary_inventory,h
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_quote import current_customer_xch_quote
from .generation_customer_vault import resolve_native_identity_vault
from .generation_customer_context import customer_bindings_from_evidence
from .generation_preparation import read_generation_preparation
from .generation_sols_batch_execution import signed_price,unspent
from .generation_chain_evidence import current_evidence_unchanged
from .generation_customer_test_conversion import claim_price


class CurrentReservationClaim(Model):
    schema_version:Literal['solslot.current-customer-reservation.v1']='solslot.current-customer-reservation.v1'
    network:Literal['testnet11']='testnet11'
    generation_id:Hash=Field(alias='generationId')
    anchor_hash:Hash=Field(alias='anchorHash')
    issuer_policy_hash:Hash=Field(alias='issuerPolicyHash')
    purchase_artifact:dict=Field(alias='purchaseArtifact',max_length=64)
    signed_price:dict=Field(alias='signedPrice',max_length=3)
    available_coin_id:Hash=Field(alias='availableCoinId')
    current_vault_coin_id:Hash=Field(alias='currentVaultCoinId')
    signer_indices:tuple[StrictInt,StrictInt]=Field(alias='signerIndices')

    @model_validator(mode='after')
    def bounded(self):
        if (any(type(i)is not int for i in self.signer_indices)or
                self.signer_indices not in ((0,1),(0,2),(1,2))or len(self.canonical().encode())>65536):
            raise ValueError('CURRENT_PURCHASE_CLAIM_BOUNDS_CHANGED')
        return self
    def canonical(self):return canonical(self.model_dump(mode='json',by_alias=True))
    def digest(self):return '0x'+sha256(self.canonical().encode()).hexdigest()


@dataclass(frozen=True)
class CurrentReservationEvidence:
    claim:CurrentReservationClaim
    inventory:object
    vault:object
    item:object
    reservation:InventoryReservationV1
    transition:object
    input_record:object


async def verify_current_reservation(claim,*,settings,anchor,provider,issuer_policy,
        expected_issuer_policy_hash,clock=time.time,_current=None):
    """Reconstruct custody, ID, price and reservation without legacy records.

    This checks the same confirmed mint and two-source/two-signer price as the
    native purchase builder. It returns evidence only; no signature or durable
    mutation occurs. No API-supplied bundle or module can be authorized.
    """
    if not isinstance(claim,CurrentReservationClaim):raise ValueError('CURRENT_PURCHASE_TYPED_CLAIM_REQUIRED')
    claim=CurrentReservationClaim.model_validate_json(claim.model_dump_json(by_alias=True))
    if (not isinstance(issuer_policy,TestnetIssuerPolicy)or issuer_policy.commitment!=expected_issuer_policy_hash
            or claim.issuer_policy_hash!=expected_issuer_policy_hash
            or settings.network!='testnet11' or claim.generation_id!=settings.deployment_generation_id
            or claim.anchor_hash!=settings.generation_chain_anchor_hash
            or bytes32.from_hexstr(claim.generation_id)!=anchor.issuance.generation
            or issuer_policy.generation!=anchor.issuance.generation):
        raise ValueError('CURRENT_PURCHASE_POLICY_BINDING_CHANGED')
    now=int(clock())
    if not issuer_policy.issued_at<=now<issuer_policy.expires_at:raise ValueError('CURRENT_PURCHASE_POLICY_EXPIRED')
    purchase=purchase_artifact_v3_from_json(claim.purchase_artifact)
    # Reject noncanonical extra/omitted terms before any primary-node reads.
    if purchase_artifact_v3_to_json(purchase)!=claim.purchase_artifact:
        raise ValueError('CURRENT_PURCHASE_CANONICAL_ARTIFACT_REQUIRED')
    if (purchase.collection_id!=issuer_policy.collection or purchase.metadata_anchor_id!=issuer_policy.edition
            or purchase.metadata_root!=issuer_policy.metadata_root or purchase.vault_launcher_id!=issuer_policy.buyer_vault
            or purchase.deed_launcher_id not in issuer_policy.deed_launchers):
        raise ValueError('CURRENT_PURCHASE_FINITE_SCOPE_CHANGED')
    inventory=(_current[0]if _current is not None else await resolve_current_primary_inventory(settings=settings,anchor=anchor,provider=provider,
        collection=issuer_policy.collection,edition_hash=issuer_policy.edition,metadata_root=issuer_policy.metadata_root))
    item=inventory.require_available(purchase.deed_launcher_id)
    if h(item.current.coin.name())!=claim.available_coin_id:raise ValueError('CURRENT_PURCHASE_INVENTORY_INPUT_CHANGED')
    if _current is None:
        preparation=read_generation_preparation(settings)
        bindings=customer_bindings_from_evidence(preparation,anchor,inventory.evidence)
        vault=await resolve_native_identity_vault(bindings=bindings,launcher=purchase.vault_launcher_id,provider=provider)
    else:vault=_current[1]
    if h(vault.coin.name())!=claim.current_vault_coin_id:raise ValueError('CURRENT_PURCHASE_VAULT_INPUT_CHANGED')
    rebuilt=current_customer_xch_quote(inventory=inventory,vault=vault,deed_launcher=purchase.deed_launcher_id,
        price=claim_price(claim.signed_price,issuer_policy),nonce=purchase.authorization_nonce,now=now,
        expires_at=purchase.quote_expires_at,forwarding_policy=issuer_policy)
    if rebuilt!=purchase:raise ValueError('CURRENT_PURCHASE_QUOTE_CHANGED')
    terms=item.original.terms
    structure=Program.to((SINGLETON_MOD_HASH,(terms.deed_launcher_id,terms.deed_launcher_puzzle_hash)))
    reservation=InventoryReservationV1(purchase,purchase.quote_expires_at)
    transition=build_inventory_reservation_spend(available_coin=item.current.coin,deed_singleton_struct=structure,
        lineage_proof=item.lineage,reservation=reservation,signer_indices=claim.signer_indices,terms=terms)
    record=await unspent(provider,item.current.coin)
    await unspent(provider,vault.coin)
    if not await current_evidence_unchanged(inventory.evidence,provider=provider):
        raise ValueError('CURRENT_PURCHASE_AUTHORITY_CHANGED_DURING_READ')
    fresh=int(clock())
    if not now<=fresh<purchase.quote_expires_at or fresh>=issuer_policy.expires_at:
        raise ValueError('CURRENT_PURCHASE_REVIEW_EXPIRED_DURING_READ')
    return CurrentReservationEvidence(claim,inventory,vault,item,reservation,transition,record)
