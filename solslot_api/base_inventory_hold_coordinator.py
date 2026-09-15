"""Service-only hold preparation; v1 never permits a customer payment."""
import asyncio
import time
import uuid

from chia_rs import AugSchemeMPL, G1Element, G2Element
from .base_inventory_hold import parse_base_hold, base_hold_coordinates
from .inventory_extension_store import conflict
from .inventory_recovery import hx
from .purchase_admission import recheck_admitted_owner
from .validator_quorum import _collect_inventory_quorum, configured_validator_pubkeys


def verify_base_hold_receipt(claim, receipt, artifact):
    if artifact.get('baseReservationLifecycle') is not None:
        from .base_lifecycle_claims import hold_origin
        artifact = hold_origin(claim, artifact, claim.activation['environment'])
    base_hold_coordinates(claim, artifact, claim.activation['environment'])
    try:
        indices = receipt['signerIndices']
        if (set(receipt) != {'claimHash', 'signerIndices', 'signature'}
                or receipt['claimHash'] != claim.canonical_hash() or type(indices) is not list or len(indices) != 2
                or any(type(i) is not int or i not in (0, 1, 2) for i in indices) or sorted(set(indices)) != indices
                or artifact['validatorSet']['threshold'] != 2 or len(artifact['validatorSet']['pubkeys']) != 3):
            raise ValueError('Base quorum identity differs')
        keys = [G1Element.from_bytes(bytes.fromhex(artifact['validatorSet']['pubkeys'][i].removeprefix('0x'))) for i in indices]
        signature = G2Element.from_bytes(bytes.fromhex(receipt['signature'].removeprefix('0x')))
        if not AugSchemeMPL.aggregate_verify(keys, [claim.signature_message()]*2, signature):
            raise ValueError('Base hold signature is invalid')
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise conflict('Base hold lacks its authentic independent quorum') from exc


def base_checkout_status(operation, artifact):
    claim = parse_base_hold(operation['claim'])
    origin = artifact
    if artifact.get('baseReservationLifecycle') is not None:
        from .base_lifecycle_claims import hold_origin
        origin = hold_origin(claim, artifact, claim.activation['environment'])
    base_hold_coordinates(claim, origin, claim.activation['environment'])
    if operation['state'] not in ('ARMING', 'ARMED', 'TERMINATING', 'RETURNED', 'DELIVERED'):
        raise conflict('Unknown Base hold state requires review')
    if operation['receipt'] is not None:
        verify_base_hold_receipt(claim, operation['receipt'], artifact)
    if operation['state'] == 'ARMED' and operation['receipt'] is None:
        raise conflict('Base hold is missing its quorum')
    return dict(**operation, confirmationAllowed=False, inventoryReusable=False,
        paymentRetryAllowed=False, lifecycleReady=False,
        reason='Base customer payment is not enabled for this release. Keep this checkout for recovery.')


async def arm_base_checkout(*, store, settings, claim, load_artifact, authorize):
    creating = store.base_checkout_hold(claim.purchase_artifact['purchaseId']) is None
    if creating:
        authorize()
    artifact = load_artifact()
    origin = artifact
    if not creating and artifact.get('baseReservationLifecycle') is not None:
        from .base_lifecycle_claims import hold_origin
        origin = hold_origin(claim, artifact, settings.runtime_environment+'-alpha')
    base_hold_coordinates(claim, origin, settings.runtime_environment+'-alpha')
    if (settings.network != 'testnet11' or settings.zkpassport_validator_threshold != 2
            or [hx(k) for k in configured_validator_pubkeys(settings)] != artifact['validatorSet']['pubkeys']):
        raise conflict('Base hold coordinator requires the reviewed isolated validator roster')
    purchase_id = claim.purchase_artifact['purchaseId']
    recheck_admitted_owner(store, purchase_id)
    retained = store.claim_base_checkout(claim, snapshot=store.get(purchase_id), now=int(time.time()))
    if retained['state'] == 'ARMED':
        return base_checkout_status(retained, artifact)
    owner = uuid.uuid4().hex
    # Base and Stripe new holds share the admission lane. Neither can consume
    # the independently reserved abort/return budget.
    store.claim_checkout_quorum(purchase_id, kind='arm', owner=owner, now=int(time.time()))
    try:
        quorum = await asyncio.wait_for(_collect_inventory_quorum(settings, claim, '/v1/base-inventory-hold/sign'), timeout=35)
        if creating:
            authorize()
        recheck_admitted_owner(store, purchase_id)
        if load_artifact() != artifact:
            raise conflict('Base hold deployment changed during quorum collection')
        receipt = dict(claimHash=claim.canonical_hash(), signerIndices=list(quorum.signer_indices), signature=hx(quorum.aggregated_signature))
        store.preserve_base_checkout(claim, receipt, artifact)
        return base_checkout_status(store.base_checkout_hold(purchase_id), artifact)
    finally:
        store.finish_checkout_quorum(purchase_id, owner=owner, now=int(time.time()))
