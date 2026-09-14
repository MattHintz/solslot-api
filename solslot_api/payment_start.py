"""Independent payment observation. These signatures cannot authorize a spend."""
import hashlib
import time
from typing import Any, Literal

from chia_rs import AugSchemeMPL, G1Element, G2Element
from pydantic import BaseModel, ConfigDict, Field

from .inventory_extension_claims import extension_activation
from .inventory_extension_store import canonical, conflict
from .inventory_recovery import hx


class PaymentStartClaim(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    schema_version: Literal['solslot.payment-start-observation.v1'] = 'solslot.payment-start-observation.v1'
    network: Literal['testnet11']
    genesis_artifact_hash: str = Field(pattern=r'^0x[0-9a-f]{64}$')
    activation: dict[str, Any]
    purchase_artifact: dict[str, Any]
    payment_intent_id: str = Field(pattern=r'^pi_[A-Za-z0-9]{1,200}$')
    payment_event_id: str = Field(pattern=r'^evt_[A-Za-z0-9]{1,200}$')
    payment_started_at: int = Field(gt=0)
    payment_method: Literal['card', 'us_bank_account']

    def canonical_hash(self):
        return '0x' + hashlib.sha256(canonical(self.model_dump(mode='json')).encode()).hexdigest()

    def signature_message(self):
        return b'SOLSLOT_PAYMENT_START_OBSERVATION_V1\x00' + bytes.fromhex(self.canonical_hash()[2:])

    def payment(self):
        return {key: getattr(self, key) for key in ('payment_intent_id', 'payment_event_id', 'payment_started_at', 'payment_method')}


def validate_start(claim, artifact, environment):
    from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json
    from solslot_puzzles.payment_artifacts_v2 import PaymentRail
    from solslot_puzzles.payment_artifacts_v3 import PurchaseDeliveryKind, PurchaseKind
    purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
    if (claim.activation != extension_activation(artifact, environment)
            or claim.genesis_artifact_hash != artifact['artifactHash']
            or purchase.network != 'testnet11' or purchase.rail != PaymentRail.STRIPE
            or hx(purchase.protocol_treasury_puzzle_hash) != artifact['puzzleHashes']['protocolTreasuryPuzzleHash']
            or purchase.purchase_kind != PurchaseKind.PRESALE or purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED
            or not 0 < claim.payment_started_at < purchase.quote_expires_at
            or claim.payment_started_at > int(time.time())):
        raise conflict('payment start does not bind the original reviewed test purchase')
    return purchase


def verify_start_receipt(claim, receipt, artifact):
    validate_start(claim, artifact, claim.activation['environment'])
    try:
        indices = receipt['signerIndices']
        if (set(receipt) != {'claimHash', 'signerIndices', 'signature'} or receipt['claimHash'] != claim.canonical_hash()
                or type(indices) is not list or len(indices) != 2 or sorted(set(indices)) != indices
                or any(type(i) is not int or i not in (0, 1, 2) for i in indices)
                or artifact['validatorSet']['threshold'] != 2 or len(artifact['validatorSet']['pubkeys']) != 3):
            raise ValueError('observation quorum identity changed')
        keys = [G1Element.from_bytes(bytes.fromhex(artifact['validatorSet']['pubkeys'][i].removeprefix('0x'))) for i in indices]
        signature = G2Element.from_bytes(bytes.fromhex(receipt['signature'].removeprefix('0x')))
        if not AugSchemeMPL.aggregate_verify(keys, [claim.signature_message()] * 2, signature):
            raise ValueError('invalid observation signature')
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise conflict('payment start lacks an authentic independent observation quorum') from exc


async def sign_payment_start(settings, claim, claim_hash):
    from .validator_service import load_validator_artifact, load_validator_private_key, ValidatorEvidenceError
    from .validator_inventory_extension import provider_hold
    try:
        artifact, _ = load_validator_artifact(settings)
        validate_start(claim, artifact, settings.deployment_environment)
        if (claim.canonical_hash() != claim_hash or settings.network != claim.network
                or settings.roster_pubkeys != artifact['validatorSet']['pubkeys'] or artifact['validatorSet']['threshold'] != 2):
            raise ValueError('observation release or validator identity changed')
        await provider_hold(settings, claim)
        if load_validator_artifact(settings)[0] != artifact or claim.canonical_hash() != claim_hash:
            raise ValueError('release changed during payment observation')
        validate_start(claim, artifact, settings.deployment_environment)
        return hx(AugSchemeMPL.sign(load_validator_private_key(settings), claim.signature_message()))
    except Exception as exc:
        raise ValidatorEvidenceError('payment start is not independently proven: ' + str(exc)) from exc


async def collect_payment_start_quorum(settings, claim, *, client=None):
    from .validator_quorum import _collect_inventory_quorum, configured_validator_pubkeys, ValidatorQuorumError
    if settings.zkpassport_validator_threshold != 2 or len(configured_validator_pubkeys(settings)) != 3:
        raise ValidatorQuorumError('payment observation requires the reviewed two-of-three quorum')
    return await _collect_inventory_quorum(settings, claim, '/v1/payment-start/observe', client=client)


async def adopt_payment_start(*, store, settings, purchase_id, payment, load_artifact):
    """Reject bad candidates before they can pin the immutable extension journal."""
    artifact = load_artifact()
    stored = store.get(purchase_id)
    claim = PaymentStartClaim(network=settings.network, genesis_artifact_hash=artifact['artifactHash'],
        activation=extension_activation(artifact, settings.runtime_environment + '-alpha'),
        purchase_artifact=stored.purchase_artifact, **payment)
    validate_start(claim, artifact, settings.runtime_environment + '-alpha')
    old = store.payment_start(purchase_id)
    if old:
        retained = PaymentStartClaim.model_validate(old['claim'])
        verify_start_receipt(retained, old['receipt'], artifact)
        if retained != claim:
            raise conflict('the independently verified payment start cannot be replaced')
        return retained.payment()
    quorum = await collect_payment_start_quorum(settings, claim)
    receipt = dict(claimHash=claim.canonical_hash(), signerIndices=list(quorum.signer_indices), signature=hx(quorum.aggregated_signature))
    if load_artifact() != artifact:
        raise conflict('release changed before payment observation retention')
    store.retain_payment_start(purchase_id, claim=claim, receipt=receipt, artifact=artifact, snapshot=stored)
    return claim.payment()
