"""Private pre-payment holds are not settlement or on-chain authorizations."""
from __future__ import annotations
import hashlib
import re
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .inventory_extension_claims import extension_activation
from .inventory_extension_store import canonical


def payment_hold_activation(artifact, environment, *, required=True):
    value=artifact.get('inventoryPaymentHolds')
    if value is None and not required:
        return None
    extension=extension_activation(artifact,environment)
    expected=dict(schema='solslot.inventory-payment-holds.v1',environment=environment,network='testnet11',
        deploymentId=extension['deploymentId'],sourceShas=extension['sourceShas'],adapterVersion=1,
        validatorLedgerVersion=12,extensionReleaseIdentity=extension['releaseIdentity'],
        stripeAccountId=extension['stripeAccountId'],stripeMode='test',minConfirmations=3,
        paymentHoldPolicy=extension['paymentHoldPolicy'])
    expected['releaseIdentity']=hashlib.sha256(canonical(expected).encode()).hexdigest()
    if (not isinstance(value,dict) or set(value)!=set(expected)|{'reviewEvidenceSha256'}
            or any(value.get(k)!=v or type(value.get(k)) is not type(v) for k,v in expected.items())
            or not re.fullmatch(r'[0-9a-f]{64}',str(value.get('reviewEvidenceSha256')))
            or value['reviewEvidenceSha256']=='0'*64):
        raise ValueError('reviewed payment hold capability does not match its exact release')
    return dict(value)


class InventoryPaymentHoldClaim(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True,strict=True)
    schema_version: Literal['solslot.inventory-payment-hold-claim.v1']='solslot.inventory-payment-hold-claim.v1'
    network: Literal['testnet11']
    genesis_artifact_hash: str
    activation: dict[str,Any]
    purchase_artifact: dict[str,Any]
    smart_deed_inner_hash: str
    reserved_coin_id: str
    reserved_puzzle_hash: str
    reservation_expires_at: int=Field(gt=0)
    payment_intent_id: str=Field(pattern=r'^pi_[A-Za-z0-9]{1,200}$')
    payment_method: Literal['card','us_bank_account']

    @field_validator('genesis_artifact_hash','smart_deed_inner_hash','reserved_coin_id','reserved_puzzle_hash')
    @classmethod
    def hex32(cls,value):
        if not re.fullmatch(r'0x[0-9a-f]{64}',value) or value=='0x'+'0'*64:
            raise ValueError('canonical nonzero 32-byte commitment required')
        return value

    def canonical_hash(self):
        return '0x'+hashlib.sha256(canonical(self.model_dump(mode='json')).encode()).hexdigest()

    def signature_message(self):
        return b'solslot.inventory-payment-hold.arm.v1:'+bytes.fromhex(self.canonical_hash()[2:])


class InventoryPaymentHoldReleaseClaim(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True,strict=True)
    schema_version: Literal['solslot.inventory-payment-hold-release.v1']='solslot.inventory-payment-hold-release.v1'
    hold: InventoryPaymentHoldClaim
    reserved_coin_id: str
    reservation_expires_at: int=Field(gt=0)
    available_coin_id: str

    @field_validator('reserved_coin_id','available_coin_id')
    @classmethod
    def hex32(cls,value):
        return InventoryPaymentHoldClaim.hex32(value)

    def canonical_hash(self):
        return '0x'+hashlib.sha256(canonical(self.model_dump(mode='json')).encode()).hexdigest()

    def signature_message(self):
        return b'solslot.inventory-payment-hold.release.v1:'+bytes.fromhex(self.canonical_hash()[2:])
