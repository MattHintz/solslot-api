"""Reviewed Base recovery authority, separate from the original prepayment hold.

Origins are projections inside the *authenticated current* public artifact.
They are never accepted from a customer as evidence of a release upgrade.
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from solslot_puzzles.inventory_activation import validate_inventory_activation
from solslot_puzzles.stripe_settlement_v1_driver import MAX_RESERVATION_EXTENSION_SECONDS

from .base_inventory_hold import BaseHoldClaim, BaseInventoryHoldClaimV2, base_hold_activation, base_hold_coordinates, bind_held_deposit
from .purchase_admission import ADMISSION_POLICY
from .inventory_extension_claims import COMPONENTS, RENEWAL_WINDOW_SECONDS
from .inventory_extension_store import canonical
from .faucet import AGG_SIG_ME_DATA

ORIGIN_FIELDS = ('artifactHash', 'network', 'sourceShas', 'inventoryActivation',
                 'baseInventoryHold', 'ceremony', 'validatorSet', 'launcherIds', 'puzzleHashes')


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def nonzero(value, size, prefix=''):
    return isinstance(value, str) and re.fullmatch(prefix + '[0-9a-f]{' + str(size) + '}', value) is not None and value != prefix + '0'*size


def base_lifecycle_activation(artifact, environment, *, required=True):
    value = artifact.get('baseReservationLifecycle')
    if value is None and not required:
        return None
    inventory = validate_inventory_activation(artifact, required=True, environment=environment)
    sources = artifact.get('sourceShas')
    origins = value.get('holdOrigins') if isinstance(value, dict) else None
    history = value.get('priorLifecycles') if isinstance(value, dict) else None
    direct = value.get('historicalDirectPaymentSha256') if isinstance(value, dict) else None
    if (environment not in ('staging-alpha', 'production-alpha') or not isinstance(sources, dict)
            or set(sources) != COMPONENTS or any(not nonzero(v, 40) for v in sources.values())
            or not nonzero(inventory['deploymentId'], 64, '0x')
            or not isinstance(origins, list) or not 0 <= len(origins) <= 32
            or not isinstance(history, list) or len(history) > 32
            or not isinstance(direct, list) or len(direct) > 128
            or any(not nonzero(v,64) for v in direct) or len(set(direct)) != len(direct)):
        raise ValueError('Base lifecycle requires an exact reviewed release and bounded hold origins')
    for item in history:
        if (not isinstance(item, dict) or set(item) != {'artifactHash','capabilitySha256','releaseIdentity'}
                or not nonzero(item['artifactHash'], 64, '0x')
                or not nonzero(item['capabilitySha256'], 64) or not nonzero(item['releaseIdentity'], 64)):
            raise ValueError('Base lifecycle history references are incomplete')
    if len({item['artifactHash'] for item in history}) != len(history):
        raise ValueError('Base lifecycle history is ambiguous')
    seen = set()
    for origin in origins:
        if not isinstance(origin, dict) or set(origin) != set(ORIGIN_FIELDS) or not nonzero(origin.get('artifactHash'), 64, '0x'):
            raise ValueError('Base lifecycle hold origin is incomplete')
        old = base_hold_activation(origin, environment)
        if (origin['artifactHash'] in seen or old['deploymentId'] != inventory['deploymentId']
                or any(origin[k] != artifact[k] for k in ('network', 'sourceShas', 'ceremony', 'validatorSet', 'launcherIds', 'puzzleHashes'))
                or any(old[k] != inventory[k] for k in ('availableModuleHash', 'reservedModuleHash'))):
            raise ValueError('Base lifecycle cannot silently migrate deployment, keys or protocol coordinates')
        seen.add(origin['artifactHash'])
    route = {k: value.get(k) for k in ('chainId', 'spoke', 'token', 'sourceChainSelector')}
    if (type(route['chainId']) is not int or route['chainId'] != 84532
            or any(not nonzero(route[k], 40, '0x') for k in ('spoke', 'token'))
            or type(route['sourceChainSelector']) is not int or not 0 < route['sourceChainSelector'] < 2**64):
        raise ValueError('Base lifecycle requires canonical isolated escrow coordinates')
    payout = value.get('payoutAddress')
    if not nonzero(payout, 40, '0x'):
        raise ValueError('Base lifecycle requires its reviewed settlement recipient')
    if any(any(origin['baseInventoryHold'][k] != v for k, v in route.items()) for origin in origins):
        raise ValueError('Base lifecycle cannot merge different escrow routes')
    expected = dict(schema='solslot.base-reservation-lifecycle.v1', environment=environment, network='testnet11',
        deploymentId=inventory['deploymentId'], sourceShas=sources, inventoryVersion=2, adapterVersion=1,
        validatorLedgerVersion=15, minConfirmations=3, **route, payoutAddress=payout,
        availableModuleHash=inventory['availableModuleHash'], reservedModuleHash=inventory['reservedModuleHash'],
        maximumExtensionSeconds=MAX_RESERVATION_EXTENSION_SECONDS, renewalWindowSeconds=RENEWAL_WINDOW_SECONDS,
        privateProofDeadlineSeconds=30, advanceDeadlineSeconds=45, workerLeaseSeconds=60,
        recoveryLane='independent', holdOrigins=origins, priorLifecycles=history, historicalDirectPaymentSha256=direct,
        customerPaymentEnabled=False, policy='base-original-deposit-through-canonical-terminal-v1', **ADMISSION_POLICY)
    expected['releaseIdentity'] = digest(expected)
    if (set(value) != set(expected) | {'reviewEvidenceSha256'}
            or any(value[k] != v or type(value[k]) is not type(v) for k, v in expected.items())
            or not nonzero(value.get('reviewEvidenceSha256'), 64)):
        raise ValueError('Base lifecycle evidence differs from the exact reviewed capability')
    return dict(value)


def historical_direct_payment_digest(purchase, evidence):
    """Reviewed recovery references bind only immutable original source facts."""
    source = evidence['source']
    if (any(not nonzero(v,64,'0x') for v in (evidence['globalPaymentId'],source['transactionHash'],source['blockHash']))
            or type(source['logIndex']) is not int or source['logIndex'] < 0):
        raise ValueError('Historical Base payment source is incomplete')
    return digest(dict(purchaseArtifact=purchase, globalPaymentId=evidence['globalPaymentId'],
        source={k:source[k] for k in ('transactionHash','blockHash','logIndex')}))


def lifecycle_artifact(activation, artifact_hash, artifact, environment):
    """A flat reviewed digest permits replay without recursively embedded releases."""
    active = base_lifecycle_activation(artifact, environment)
    if activation == active and artifact_hash == artifact['artifactHash']:
        return artifact
    reference = dict(artifactHash=artifact_hash, capabilitySha256=digest(activation), releaseIdentity=activation.get('releaseIdentity'))
    if reference not in active['priorLifecycles']:
        raise ValueError('Original Base lifecycle is not reviewed for this release')
    stable = ('environment','network','sourceShas','deploymentId','chainId','spoke','token','sourceChainSelector','payoutAddress',
              'availableModuleHash','reservedModuleHash','inventoryVersion','adapterVersion','policy')
    if any(activation.get(k) != active[k] for k in stable):
        raise ValueError('Base lifecycle migration changes immutable execution coordinates')
    origin = deepcopy(artifact)
    origin.update(artifactHash=artifact_hash, sourceShas=activation['sourceShas'], baseReservationLifecycle=activation)
    origin['inventoryActivation']['sourceShas'] = activation['sourceShas']
    base_lifecycle_activation(origin, environment)
    return origin


def hold_origin(hold, artifact, environment):
    active = base_lifecycle_activation(artifact, environment)
    if isinstance(hold, BaseInventoryHoldClaimV2):
        origin = lifecycle_artifact(hold.activation, hold.genesis_artifact_hash, artifact, environment)
        base_hold_coordinates(hold, origin, environment)
        return origin
    origin = next((o for o in active['holdOrigins'] if o['artifactHash'] == hold.genesis_artifact_hash), None)
    if origin is None:
        raise ValueError('Original Base hold is not explicitly reviewed for this release')
    base_hold_coordinates(hold, origin, environment)
    return origin


class BasePaymentStartClaim(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    schema_version: Literal['solslot.base-payment-start.v1'] = 'solslot.base-payment-start.v1'
    network: Literal['testnet11']
    genesis_artifact_hash: str
    activation: dict[str, Any]
    purchase_artifact: dict[str, Any]
    hold: BaseHoldClaim
    payment_evidence: dict[str, Any]

    @field_validator('genesis_artifact_hash')
    @classmethod
    def hex32(cls, value):
        if not nonzero(value, 64, '0x'):
            raise ValueError('canonical nonzero 32-byte commitment required')
        return value

    @property
    def payment_started_at(self):
        value = self.payment_evidence.get('source', {}).get('blockTimestamp')
        if type(value) is not int or value <= 0:
            raise ValueError('Base start requires its canonical source timestamp')
        return value

    @property
    def payment_method(self):
        return 'base_usdc'

    def canonical_hash(self):
        return '0x' + digest(self.model_dump(mode='json'))

    def signature_message(self):
        return b'SOLSLOT_BASE_PAYMENT_START_V1\x00' + bytes.fromhex(self.canonical_hash()[2:])

    def payment(self):
        return dict(hold=self.hold.model_dump(mode='json'), payment_evidence=self.payment_evidence)


class BaseInventoryExtensionClaim(BasePaymentStartClaim):
    schema_version: Literal['solslot.base-inventory-extension.v1'] = 'solslot.base-inventory-extension.v1'
    smart_deed_inner_hash: str
    reserved_coin_id: str
    reserved_puzzle_hash: str
    reservation_expires_at: int = Field(gt=0)
    next_expires_at: int = Field(gt=0)
    validator_message: str
    series_terms: dict[str, Any]
    series_state: dict[str, int]
    series_coin_id: str

    @field_validator('smart_deed_inner_hash', 'reserved_coin_id', 'reserved_puzzle_hash', 'validator_message', 'series_coin_id')
    @classmethod
    def commitment(cls, value):
        return cls.hex32(value)

    def signature_message(self):
        return bytes.fromhex(self.validator_message[2:]) + bytes.fromhex(self.reserved_coin_id[2:]) + AGG_SIG_ME_DATA[self.network]


def validate_base_start(claim, artifact, environment):
    authorized = lifecycle_artifact(claim.activation, claim.genesis_artifact_hash, artifact, environment)
    if claim.purchase_artifact != claim.hold.purchase_artifact:
        raise ValueError('Base lifecycle claim changes its release or original purchase')
    origin = hold_origin(claim.hold, authorized, environment)
    purchase, struct, terms = base_hold_coordinates(claim.hold, origin, environment)
    bind_held_deposit(claim.hold, claim.payment_evidence)
    expected = dict(amount=purchase.rail_amount, quantity=purchase.delivery_amount,
        collectionId='0x'+purchase.collection_id.hex(), deedLauncherId='0x'+purchase.deed_launcher_id.hex(),
        vaultLauncherId='0x'+purchase.vault_launcher_id.hex(), destinationPuzzle='0x'+purchase.vault_p2_puzzle_hash.hex(),
        quoteExpiresAt=purchase.quote_expires_at)
    if any(claim.payment_evidence.get(k) != v or type(claim.payment_evidence.get(k)) is not type(v) for k,v in expected.items()):
        raise ValueError('Base deposit differs from the original amount, inventory or destination')
    purchase.assert_live(claim.payment_started_at)
    if not 0 < claim.payment_started_at < purchase.quote_expires_at:
        raise ValueError('Base deposit did not start within its original quote')
    return purchase, struct, terms


def parse_extension(value):
    from .inventory_extension_claims import InventoryExtensionClaim
    cls = BaseInventoryExtensionClaim if value.get('schema_version') == 'solslot.base-inventory-extension.v1' else InventoryExtensionClaim
    return cls.model_validate(value)


class BaseTerminalClaim(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    schema_version: Literal['solslot.base-checkout-terminal.v1'] = 'solslot.base-checkout-terminal.v1'
    network: Literal['testnet11']
    genesis_artifact_hash: str
    activation: dict[str, Any]
    hold: BaseHoldClaim
    kind: Literal['RETURNED', 'DELIVERED']
    reserved_coin_id: str
    reservation_expires_at: int = Field(gt=0)
    output_coin_id: str
    confirmation_height: int = Field(gt=0)
    payment_evidence: dict[str, Any] | None
    settlement: dict[str, Any] | None
    spend_bundle: dict[str, Any] | None

    @field_validator('genesis_artifact_hash', 'reserved_coin_id', 'output_coin_id')
    @classmethod
    def hex32(cls, value):
        return BasePaymentStartClaim.hex32(value)

    def canonical_hash(self):
        return '0x'+digest(self.model_dump(mode='json'))

    def signature_message(self):
        return b'SOLSLOT_BASE_CHECKOUT_TERMINAL_V1\x00'+bytes.fromhex(self.canonical_hash()[2:])
