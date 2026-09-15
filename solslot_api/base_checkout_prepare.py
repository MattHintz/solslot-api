"""Durable server-derived payment identity before any customer token approval."""
from copy import deepcopy
import secrets
import time

from eth_abi import encode
from web3 import Web3

from .base_inventory_hold import BaseInventoryHoldClaimV2, parse_base_hold, base_hold_coordinates
from .base_inventory_hold_coordinator import arm_base_checkout, base_checkout_status
from .base_lifecycle_claims import base_lifecycle_activation
from .inventory_extension_chain import current_position
from .inventory_extension_store import conflict
from .inventory_recovery import hx
from .purchase_admission import recheck_admitted_owner


def public_base_checkout(operation, artifact, stored):
    claim = parse_base_hold(operation['claim'])
    base_checkout_status(operation, artifact)
    cap = base_lifecycle_activation(artifact, claim.activation['environment'])
    return dict(schema='solslot.base-checkout.v1', purchaseId=claim.purchase_artifact['purchaseId'],
        purchaseArtifactHash=claim.purchase_artifact['artifactHash'], depositor=claim.depositor,
        genesisArtifactHash=stored.offer_artifact['genesisArtifactHash'],
        localPaymentId=claim.local_payment_id, globalPaymentId=claim.global_payment_id,
        network='testnet11', environment=cap['environment'], deploymentId=cap['deploymentId'],
        releaseIdentity=cap['releaseIdentity'], chainId=cap['chainId'], spoke=cap['spoke'], token=cap['token'],
        state=operation['state'], confirmationAllowed=False, paymentRetryAllowed=False,
        reason='Base payment is not enabled for this release. Your original checkout is saved for recovery.')


async def prepare_base_checkout(*, store, settings, purchase_id, depositor, load_artifact, authorize):
    artifact = deepcopy(load_artifact())
    cap = base_lifecycle_activation(artifact, settings.runtime_environment+'-alpha')
    retained = store.base_checkout_hold(purchase_id)
    recheck_admitted_owner(store, purchase_id)
    if retained is None:
        authorize()
        stored = store.get(purchase_id)
        position = current_position(stored, store.inventory_items(purchase_id), artifact)
        local = '0x'+secrets.token_hex(32)
        global_id = hx(Web3.keccak(encode(['uint8','uint64','address','address','bytes32','bytes32','bytes32'],
            [3,cap['sourceChainSelector'],cap['spoke'],cap['token'],bytes.fromhex(local[2:]),
             bytes.fromhex(purchase_id[2:]),bytes.fromhex(stored.purchase_artifact['artifactHash'][2:])])) )
        claim = BaseInventoryHoldClaimV2(network=settings.network, genesis_artifact_hash=artifact['artifactHash'], activation=cap,
            purchase_artifact=stored.purchase_artifact, smart_deed_inner_hash=hx(position.terms.smart_deed_inner_hash),
            reserved_coin_id=hx(position.coin.name()), reserved_puzzle_hash=hx(position.coin.puzzle_hash),
            reservation_expires_at=position.reservation.expires_at, depositor=depositor,
            local_payment_id=local, global_payment_id=global_id)
        base_hold_coordinates(claim, artifact, settings.runtime_environment+'-alpha')
        if load_artifact() != artifact:
            raise conflict('Base checkout release changed before identity retention')
        # Race winners retain the first identity. A losing duplicate may recover
        # only that exact same payer/purchase; it never substitutes a fresh ID.
        try:
            store.claim_base_checkout(claim, snapshot=stored, now=int(time.time()))
        except (ValueError, RuntimeError):
            retained = store.base_checkout_hold(purchase_id)
            if retained is None:
                raise
        retained = store.base_checkout_hold(purchase_id)
    claim = parse_base_hold(retained['claim'])
    if claim.depositor != depositor or claim.purchase_artifact['purchaseId'] != purchase_id:
        raise conflict('Use the original paying wallet to recover this Base checkout')
    if retained['state'] in ('TERMINATING','RETURNED','DELIVERED'):
        return public_base_checkout(retained, artifact, store.get(purchase_id))
    await arm_base_checkout(store=store, settings=settings, claim=claim, load_artifact=load_artifact, authorize=authorize)
    return public_base_checkout(store.base_checkout_hold(purchase_id), load_artifact(), store.get(purchase_id))
