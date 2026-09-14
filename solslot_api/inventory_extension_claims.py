"""Distinct hold authority; processing payments never become paid receipts."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator
from solslot_puzzles.inventory_activation import validate_inventory_activation
from solslot_puzzles.stripe_settlement_v1_driver import MAX_RESERVATION_EXTENSION_SECONDS
from .faucet import AGG_SIG_ME_DATA
from .inventory_extension_store import canonical

RENEWAL_WINDOW_SECONDS = 24 * 60 * 60
ACH_REVIEW_SECONDS = 10 * 24 * 60 * 60
COMPONENTS = {'protocol', 'evm', 'omnichain', 'api', 'legacyBackend', 'keyOfSolomon',
              'samuel', 'customerWeb', 'adminPortal'}


def extension_activation(artifact: Mapping[str, Any], environment: str, *, required=True):
    value = artifact.get('inventoryExtension')
    if value is None and not required:
        return None
    activation = validate_inventory_activation(artifact, required=True, environment=environment)
    sources = artifact.get('sourceShas')
    if (environment not in ('staging-alpha', 'production-alpha') or not isinstance(sources, dict)
            or set(sources) != COMPONENTS or any(not isinstance(v, str) or re.fullmatch(r'[0-9a-f]{40}', v) is None for v in sources.values())
            or not re.fullmatch(r'0x[0-9a-f]{64}', str(activation['deploymentId']))
            or activation['deploymentId']=='0x'+'0'*64):
        raise ValueError('extension requires exact environment, deployment and nine-component release')
    expected = dict(schema='solslot.inventory-extension.v1', environment=environment, network='testnet11',
        deploymentId=activation['deploymentId'], sourceShas=sources, inventoryVersion=2,
        adapterVersion=1, validatorLedgerVersion=11, minConfirmations=3,
        availableModuleHash=activation['availableModuleHash'], reservedModuleHash=activation['reservedModuleHash'],
        maximumExtensionSeconds=MAX_RESERVATION_EXTENSION_SECONDS, renewalWindowSeconds=RENEWAL_WINDOW_SECONDS,
        paymentHoldPolicy='rc24-processing-through-terminal-v1')
    account = value.get('stripeAccountId') if isinstance(value, Mapping) else None
    if not isinstance(account, str) or re.fullmatch(r'acct_[A-Za-z0-9]{1,200}', account) is None:
        raise ValueError('reviewed extension Stripe account is required')
    expected.update(stripeAccountId=account, stripeMode='test')
    expected['releaseIdentity'] = hashlib.sha256(canonical(expected).encode()).hexdigest()
    if (not isinstance(value, Mapping) or set(value) != set(expected) | {'reviewEvidenceSha256'}
            or any(value.get(k) != v or type(value.get(k)) is not type(v) for k,v in expected.items())
            or re.fullmatch(r'[0-9a-f]{64}', str(value.get('reviewEvidenceSha256'))) is None
            or value['reviewEvidenceSha256']=='0'*64):
        raise ValueError('reviewed extension capability does not match deployment, adapter or release')
    return dict(value)


class InventoryExtensionClaim(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    schema_version: Literal['solslot.inventory-extension-claim.v1'] = 'solslot.inventory-extension-claim.v1'
    network: Literal['testnet11']
    genesis_artifact_hash: str
    activation: dict[str, Any]
    purchase_artifact: dict[str, Any]
    smart_deed_inner_hash: str
    reserved_coin_id: str
    reserved_puzzle_hash: str
    reservation_expires_at: int = Field(gt=0)
    next_expires_at: int = Field(gt=0)
    validator_message: str
    payment_intent_id: str = Field(pattern=r'^pi_[A-Za-z0-9]{1,200}$')
    payment_event_id: str = Field(pattern=r'^evt_[A-Za-z0-9]{1,200}$')
    payment_started_at: int = Field(gt=0)
    payment_method: Literal['card', 'us_bank_account']
    series_terms: dict[str, Any]
    series_state: dict[str, int]
    series_coin_id: str

    @field_validator('genesis_artifact_hash', 'smart_deed_inner_hash', 'reserved_coin_id',
                     'reserved_puzzle_hash', 'validator_message', 'series_coin_id')
    @classmethod
    def hex32(cls, value):
        if re.fullmatch(r'0x[0-9a-f]{64}', value) is None or value=='0x'+'0'*64:
            raise ValueError('canonical nonzero 32-byte commitment required')
        return value

    def canonical_hash(self):
        return '0x'+hashlib.sha256(canonical(self.model_dump(mode='json')).encode()).hexdigest()

    def signature_message(self):
        return bytes.fromhex(self.validator_message[2:])+bytes.fromhex(self.reserved_coin_id[2:])+AGG_SIG_ME_DATA[self.network]
