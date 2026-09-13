"""Private signer retirement: reconstruct old evidence and query its own node."""
from __future__ import annotations
import json
import httpx
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.inventory_activation import validate_inventory_recovery
from solslot_puzzles.mint_publish_driver import deed_launcher_puzzle_hash, deed_singleton_struct
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json, PurchaseDeliveryKind
from solslot_puzzles.stripe_settlement_v1_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID, PrimaryMintTermsV3, InventoryReservationV1,
    build_inventory_reservation_spend, inventory_reservation_message,
)
from .inventory_authorization_expiry import expiry_conditions
from .inventory_expiry_clock import prove_expired_unspent_sync
from .inventory_recovery import hx, record_coin
from .payment_purchase_store import PaymentPurchaseConflict
from .validator_quorum import InventoryReservationClaim


def prove_inventory_retirement(settings, previous: dict, replacement: InventoryReservationClaim) -> dict:
    from . import validator_service as service
    try:
        artifact, _ = service.load_validator_artifact(settings)
        if settings.deployment_environment is None:
            raise ValueError('validator deployment environment is required for retirement')
        activation = validate_inventory_recovery(artifact, required=True, environment=settings.deployment_environment)
        old = InventoryReservationClaim.model_validate(json.loads(previous['canonical_claim']))
        if (service.canonical_inventory_reservation_claim_json(old) != previous['canonical_claim']
                or old.canonical_hash() != previous['claim_hash'] or old.purchase_id() != previous['purchase_id']
                or old.available_coin_id != previous['available_coin_id']
                or old.available_coin_id != replacement.available_coin_id
                or old.network != settings.network or old.network != 'testnet11'
                or replacement.genesis_artifact_hash != artifact['artifactHash']
                or old.genesis_artifact_hash not in [artifact['artifactHash'], *activation['historicalArtifactHashes']]
                or artifact['validatorSet']['pubkeys'] != settings.roster_pubkeys):
            raise ValueError('old authorization differs from reviewed history or new source')
        purchase = purchase_artifact_v3_from_json(old.purchase_artifact)
        if (purchase.network != settings.network or purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED
                or old.reservation_expires_at > min(purchase.quote_expires_at, purchase.authorization_expires_at)
                or old.protocol_puzzle_hash != artifact['puzzleHashes']['protocolTreasuryPuzzleHash']
                or hx(purchase.protocol_treasury_puzzle_hash) != old.protocol_puzzle_hash):
            raise ValueError('old authorization terms are inconsistent')
        did = singleton_struct(bytes32.fromhex(artifact['launcherIds']['did'].removeprefix('0x')))
        struct = deed_singleton_struct(deed_launcher_id=purchase.deed_launcher_id, protocol_did_singleton_struct=did)
        terms = PrimaryMintTermsV3.for_artifact(artifact=purchase,
            smart_deed_inner_hash=bytes32.fromhex(old.smart_deed_inner_hash.removeprefix('0x')),
            deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(protocol_did_singleton_struct=did),
            protocol_puzhash=purchase.protocol_treasury_puzzle_hash,
            validator_pubkeys=tuple(bytes.fromhex(k.removeprefix('0x')) for k in settings.roster_pubkeys),
            provider_id=PRIMARY_PURCHASE_PROVIDER_ID, inventory_version=2)
        record = service._fetch_coin(settings, old.available_coin_id, 'expired reservation source')
        coin = service._coin_from_record(record, 'expired reservation source')
        created, spent = record_coin(record, coin)
        if hx(coin.name()) != old.available_coin_id or hx(coin.puzzle_hash) != old.available_puzzle_hash or spent:
            raise ValueError('source is not the retained available coin')
        if coin.parent_coin_info == purchase.deed_launcher_id:
            parent_record = service._fetch_coin(settings, hx(coin.parent_coin_info), 'deed launcher', require_unspent=False)
            parent = service._coin_from_record(parent_record, 'deed launcher')
            _, parent_spent = record_coin(parent_record, parent)
            if (parent.name() != coin.parent_coin_info or parent.puzzle_hash != terms.deed_launcher_puzzle_hash
                    or parent_spent != created):
                raise ValueError('initial inventory lineage is not canonical')
            lineage = LineageProof(parent_name=parent.parent_coin_info, amount=uint64(1))
        else:
            lineage = service._verify_released_inventory_parent(settings, record, coin, struct, terms)
        reservation = InventoryReservationV1(artifact=purchase, expires_at=old.reservation_expires_at)
        if hx(inventory_reservation_message(available_coin=coin, reservation=reservation)) != old.validator_message:
            raise ValueError('old validator message changed')
        indices = tuple(sorted((settings.signer_index, (settings.signer_index + 1) % 3)))
        transition = build_inventory_reservation_spend(available_coin=coin, deed_singleton_struct=struct,
            lineage_proof=lineage, reservation=reservation, signer_indices=indices, terms=terms)
        pks, messages = expiry_conditions(transition.spend, artifact=artifact,
            launcher=hx(purchase.deed_launcher_id), expires_at=old.reservation_expires_at)
        key = G1Element.from_bytes(bytes.fromhex(settings.roster_pubkeys[settings.signer_index].removeprefix('0x')))
        if (not any(pk == key and msg == old.signature_message() for pk, msg in zip(pks, messages, strict=True))
                or not AugSchemeMPL.verify(key, old.signature_message(), G2Element.from_bytes(bytes.fromhex(previous['signature'].removeprefix('0x'))))):
            raise ValueError('old signature is not this validator authorization')
        proof = prove_expired_unspent_sync(settings.coinset_base_url, coin, old.reservation_expires_at, settings.network)
        # Do not commit proof under an artifact replaced while RPC reads were pending.
        current, _ = service.load_validator_artifact(settings)
        if current['artifactHash'] != artifact['artifactHash'] or current['sourceShas'] != artifact['sourceShas']:
            raise ValueError('signed release changed during validator expiry proof')
        return dict(schema='solslot.validator-inventory-retirement.v1', claimHash=old.canonical_hash(),
            replacementClaimHash=replacement.canonical_hash(), sourceCoinId=hx(coin.name()),
            artifactHash=artifact['artifactHash'], activation=dict(activation), chainProof=proof)
    except (KeyError, TypeError, ValueError, RuntimeError, httpx.HTTPError, OSError, TimeoutError) as exc:
        raise service.ValidatorEvidenceError('inventory authorization retirement is not independently proven: ' + str(exc)) from exc
