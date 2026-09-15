"""Base prepayment exclusion, separately versioned from Stripe holds.

Version one proves and retains protection only. It cannot enable customer
payment: renewal and terminal recovery need a coordinated later capability.
No coordinator acknowledgment, including this one, is an escrow authorization.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from solslot_puzzles.inventory_activation import validate_inventory_activation

from .inventory_extension_claims import COMPONENTS
from .inventory_extension_store import canonical
from .purchase_admission import ADMISSION_POLICY


def base_hold_activation(artifact, environment, *, required=True):
    value = artifact.get('baseInventoryHold')
    if value is None and not required:
        return None
    inventory = validate_inventory_activation(artifact, required=True, environment=environment)
    sources = artifact.get('sourceShas')
    if (environment not in ('staging-alpha', 'production-alpha')
            or not isinstance(sources, dict) or set(sources) != COMPONENTS
            or any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{40}', v) or v == '0'*40 for v in sources.values())
            or not re.fullmatch(r'0x[0-9a-f]{64}', str(inventory['deploymentId']))
            or inventory['deploymentId'] == '0x'+'0'*64
            or not isinstance(value, dict)):
        raise ValueError('Base hold requires the exact isolated nine-component release')
    route = {key: value.get(key) for key in ('spoke', 'token', 'sourceChainSelector')}
    if (any(not isinstance(route[k], str) or not re.fullmatch(r'0x[0-9a-f]{40}', route[k])
            or route[k] == '0x'+'0'*40 for k in ('spoke', 'token'))
            or type(route['sourceChainSelector']) is not int or not 0 < route['sourceChainSelector'] < 2**64):
        raise ValueError('Base hold requires canonical nonzero escrow coordinates')
    expected = dict(schema='solslot.base-inventory-hold.v1', environment=environment,
        network='testnet11', deploymentId=inventory['deploymentId'], sourceShas=sources,
        inventoryVersion=2, adapterVersion=1, validatorLedgerVersion=14,
        chainId=84532, minConfirmations=3, **route,
        availableModuleHash=inventory['availableModuleHash'], reservedModuleHash=inventory['reservedModuleHash'],
        paymentConfirmationEnabled=False, holdPolicy='base-prepayment-exclusion-v1', **ADMISSION_POLICY)
    expected['releaseIdentity'] = hashlib.sha256(canonical(expected).encode()).hexdigest()
    if (set(value) != set(expected) | {'reviewEvidenceSha256'}
            or any(value[k] != v or type(value[k]) is not type(v) for k, v in expected.items())
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('reviewEvidenceSha256')))
            or value['reviewEvidenceSha256'] == '0'*64):
        raise ValueError('Base hold evidence differs from its exact reviewed capability')
    return dict(value)


class BaseInventoryHoldClaim(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    schema_version: Literal['solslot.base-inventory-hold-claim.v1'] = 'solslot.base-inventory-hold-claim.v1'
    network: Literal['testnet11']
    genesis_artifact_hash: str
    activation: dict[str, Any]
    purchase_artifact: dict[str, Any]
    smart_deed_inner_hash: str
    reserved_coin_id: str
    reserved_puzzle_hash: str
    reservation_expires_at: int = Field(gt=0)
    local_payment_id: str
    global_payment_id: str
    depositor: str = Field(pattern=r'^0x[0-9a-f]{40}$')

    @field_validator('genesis_artifact_hash', 'smart_deed_inner_hash', 'reserved_coin_id',
                     'reserved_puzzle_hash', 'local_payment_id', 'global_payment_id')
    @classmethod
    def hex32(cls, value):
        if not re.fullmatch(r'0x[0-9a-f]{64}', value) or value == '0x'+'0'*64:
            raise ValueError('canonical nonzero 32-byte commitment required')
        return value

    def canonical_hash(self):
        return '0x' + hashlib.sha256(canonical(self.model_dump(mode='json')).encode()).hexdigest()

    def signature_message(self):
        return b'SOLSLOT_BASE_INVENTORY_HOLD_V1\x00' + bytes.fromhex(self.canonical_hash()[2:])


def base_hold_coordinates(claim, artifact, environment):
    from chia_rs.sized_bytes import bytes32
    from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json, purchase_artifact_v3_to_json
    from solslot_puzzles.voucher_purchase import require_current_base_presale
    from solslot_puzzles.protocol_deployment import singleton_struct
    from solslot_puzzles.mint_publish_driver import deed_singleton_struct, deed_launcher_puzzle_hash
    from solslot_puzzles.stripe_settlement_v1_driver import PrimaryMintTermsV3, PRIMARY_PURCHASE_PROVIDER_ID
    purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
    require_current_base_presale(purchase)
    if claim.purchase_artifact != purchase_artifact_v3_to_json(purchase):
        raise ValueError('Base hold purchase must use its exact canonical serialized identity')
    active = base_hold_activation(artifact, environment)
    if (claim.activation != active or claim.genesis_artifact_hash != artifact['artifactHash']
            or claim.network != purchase.network or claim.depositor == '0x'+'0'*40
            or '0x'+purchase.protocol_treasury_puzzle_hash.hex() != artifact['puzzleHashes']['protocolTreasuryPuzzleHash']
            or purchase.rail_chain_id != active['chainId']
            or bytes(purchase.rail_asset_id) != bytes(12)+bytes.fromhex(active['token'][2:])
            or claim.reservation_expires_at != min(purchase.quote_expires_at, purchase.authorization_expires_at)):
        raise ValueError('Base hold differs from its original current presale reservation')
    did = singleton_struct(bytes32.from_hexstr(artifact['launcherIds']['did']))
    struct = deed_singleton_struct(deed_launcher_id=purchase.deed_launcher_id, protocol_did_singleton_struct=did)
    terms = PrimaryMintTermsV3.for_artifact(artifact=purchase, inventory_version=2,
        smart_deed_inner_hash=bytes32.from_hexstr(claim.smart_deed_inner_hash),
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(protocol_did_singleton_struct=did),
        protocol_puzhash=purchase.protocol_treasury_puzzle_hash,
        validator_pubkeys=tuple(bytes.fromhex(k.removeprefix('0x')) for k in artifact['validatorSet']['pubkeys']),
        provider_id=PRIMARY_PURCHASE_PROVIDER_ID)
    return purchase, struct, terms


def bind_held_deposit(claim, evidence):
    """Identity only; callers must independently authenticate current RPC proof."""
    source = evidence.get('source', {})
    expected = dict(globalPaymentId=claim.global_payment_id, localPaymentId=claim.local_payment_id,
        depositor=claim.depositor, purchaseId=claim.purchase_artifact['purchaseId'],
        artifactHash=claim.purchase_artifact['artifactHash'], settlementToken=claim.activation['token'])
    if (any(evidence.get(k) != v for k, v in expected.items())
            or source.get('chainId') != claim.activation['chainId']
            or source.get('spoke') != claim.activation['spoke']):
        raise ValueError('deposit differs from the immutable Base prepayment hold')
