"""Prepare the existing native payer offer without changing recipient custody.

Only a confirmed standard-wallet payment coin reaches wallet signing. Protocol,
reservation, issuer-forwarding and fee spends are not wallet signing inputs.
No endpoint, key access, funding selection or transaction submission lives here.
"""
from typing import Literal
from dataclasses import dataclass
from hashlib import sha256
import time
from pydantic import Field
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.stripe_settlement_v1_driver import prepare_chia_buyer_offer_v3
from .generation_execution import Model, Hash
from .generation_operations import canonical
from .generation_customer_purchase_reservation import CurrentReservationClaim
from .generation_customer_purchase_scope import quote_deadline
from .generation_customer_purchase_delivery import CurrentDeliveryClaim, resolve_current_reserved_purchase
from .generation_coin_evidence import read_confirmed_coin
from .generation_sols_batch_execution import unspent
from .generation_chain_evidence import current_evidence_unchanged
from .generation_sols_batches import verify_order_signature


def h(value):
    return '0x' + bytes(value).hex()


class CurrentNativePaymentRequest(Model):
    reservation: CurrentReservationClaim
    reserved_coin_id: Hash = Field(alias='reservedCoinId')
    payment_coin_id: Hash = Field(alias='paymentCoinId')
    payment_public_key: str = Field(alias='paymentPublicKey', pattern=r'^0x[0-9a-f]{96}$')
    payment_public_key_kind: Literal['raw','synthetic'] = Field(default='raw', alias='paymentPublicKeyKind')


@dataclass(frozen=True)
class CurrentNativePaymentPreparation:
    request: CurrentNativePaymentRequest
    evidence: object
    prepared: object
    payment_record: object
    observed_at: int

    def review(self):
        r, e, p = self.request, self.evidence, self.prepared
        artifact = e.artifact
        document = {'schema': 'solslot.current-native-payment-review.v1',
            'network': 'testnet11', 'generationId': r.reservation.generation_id,
            'reservationClaimHash': r.reservation.digest(),
            'purchaseId': h(artifact.purchase_id), 'artifactHash': h(artifact.artifact_hash),
            'collectionId': h(artifact.collection_id), 'deedLauncherId': h(artifact.deed_launcher_id),
            'metadataRoot': h(artifact.metadata_root), 'editionHash': h(artifact.metadata_anchor_id),
            'recipientVaultLauncherId': h(artifact.vault_launcher_id),
            'recipientVaultP2PuzzleHash': h(artifact.vault_p2_puzzle_hash),
            'currentVaultCoinId': r.reservation.current_vault_coin_id,
            'reservedCoinId': r.reserved_coin_id, 'paymentCoinId': r.payment_coin_id,
            'paymentPublicKey': r.payment_public_key, 'paymentPublicKeyKind':r.payment_public_key_kind, 'amountMojos': str(artifact.rail_amount),
            'baseAmountUsdMinor': str(artifact.base_amount_minor),
            'technologyFeeUsdMinor': str(artifact.technology_fee_minor),
            'totalAmountUsdMinor': str(artifact.subtotal_minor),
            'changeMojos': str(int(p.coin_spend.coin.amount) - int(artifact.rail_amount)),
            'changePuzzleHash': h(p.payment_puzzle.get_tree_hash()),
            'payerCoin': {'parentCoinInfo':h(p.coin_spend.coin.parent_coin_info),
                'puzzleHash':h(p.coin_spend.coin.puzzle_hash),'amount':str(p.coin_spend.coin.amount)},
            'payerConfirmedHeight':self.payment_record.confirmed_height,'observedAt':self.observed_at,
            'walletFeeMojos': '0', 'quoteExpiresAt': artifact.quote_expires_at,
            'buyerOffer': p.offer.to_bech32(),
            'coinSpends': [p.coin_spend.to_json_dict()]}
        return {**document, 'reviewHash': '0x'+sha256(canonical(document).encode()).hexdigest()}

    def signed_delivery(self, signature):
        """Attach only the signature to the exact native-built original offer.

        Subsequent delivery independently rechecks primary-node state, ID,
        signed pricing and the original offer before any validator signature.
        """
        if not isinstance(signature, G2Element):
            raise ValueError('CURRENT_PAYMENT_TYPED_SIGNATURE_REQUIRED')
        original = self.prepared.offer
        buyer = Offer(original.requested_payments,
            WalletSpendBundle(original.coin_spends(), signature), original.driver_dict)
        verify_order_signature(buyer)
        return CurrentDeliveryClaim(reservation=self.request.reservation,
            reservedCoinId=self.request.reserved_coin_id, buyerOffer=buyer.to_bech32())


async def prepare_current_native_payment(request, *, settings, anchor, provider,
        issuer_policy, expected_issuer_policy_hash, clock=time.time):
    if not isinstance(request, CurrentNativePaymentRequest):
        raise ValueError('CURRENT_PAYMENT_TYPED_REQUEST_REQUIRED')
    request = CurrentNativePaymentRequest.model_validate_json(request.model_dump_json(by_alias=True))
    public = G1Element.from_bytes(bytes.fromhex(request.payment_public_key[2:]))
    if public == G1Element():
        raise ValueError('CURRENT_PAYMENT_NONIDENTITY_KEY_REQUIRED')
    now = int(clock())
    checked = await resolve_current_reserved_purchase(request.reservation, request.reserved_coin_id,
        settings=settings, anchor=anchor, provider=provider, issuer_policy=issuer_policy,
        expected_issuer_policy_hash=expected_issuer_policy_hash, clock=clock)
    record = read_confirmed_coin(await provider.get_coin_record_by_name_primary(request.payment_coin_id),
        bytes32.from_hexstr(request.payment_coin_id))
    if record.spent_height:
        raise ValueError('CURRENT_PAYMENT_CONFIRMED_UNSPENT_COIN_REQUIRED')
    prepared = prepare_chia_buyer_offer_v3(payment_coin=record.coin, payment_public_key=bytes(public), payment_public_key_kind=request.payment_public_key_kind,
        artifact=checked.artifact, terms=checked.item.original.terms,
        deed_singleton_struct=checked.deed_structure)
    if (len(prepared.offer.coin_spends()) != 1
            or bytes(prepared.offer.coin_spends()[0]) != bytes(prepared.coin_spend)
            or prepared.offer.fees() != 0):
        raise ValueError('CURRENT_PAYMENT_ONE_ZERO_FEE_WALLET_INPUT_REQUIRED')
    await unspent(provider, record.coin)
    await unspent(provider, checked.vault.coin)
    await unspent(provider, checked.transition.reserved_coin)
    if not await current_evidence_unchanged(checked.inventory.evidence, provider=provider):
        raise ValueError('CURRENT_PAYMENT_AUTHORITY_CHANGED')
    if not now <= int(clock()) < quote_deadline(issuer_policy,checked.artifact.quote_expires_at):
        raise ValueError('CURRENT_PAYMENT_REVIEW_EXPIRED_DURING_READ')
    return CurrentNativePaymentPreparation(request, checked, prepared, record, int(clock()))
