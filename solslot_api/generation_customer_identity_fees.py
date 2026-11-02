"""Finite Testnet identity sponsorship, independent of legacy write authority."""
from hashlib import sha256
import json
from types import SimpleNamespace
from typing import Literal
from pydantic import Field, model_validator,field_validator
from chia.types.blockchain_format.program import Program
from chia_rs import Coin, SpendBundle
from .generation_preparation import PreparationModel
from .generation_customer_identity_context import Hash, Address


class CurrentIdentityAuthority(PreparationModel):
    schema_version:Literal['solslot.current-customer-identity-authority.v1']=Field(alias='schema')
    network:Literal['testnet11']
    generation_id:Hash=Field(alias='generationId')
    identity_profile_hash:Hash=Field(alias='identityProfileHash')
    relayer_address:Address=Field(alias='relayerAddress')
    issued_at:int=Field(alias='issuedAt',gt=0)
    expires_at:int=Field(alias='expiresAt',gt=0)
    base_max_fee_wei:int=Field(alias='baseMaximumFeeWei',gt=0,le=100_000_000_000_000)
    base_daily_fee_wei:int=Field(alias='baseDailyFeeWei',gt=0,le=1_000_000_000_000_000)
    funding_puzzle_hash:Hash=Field(alias='fundingPuzzleHash')
    fee_coin_ids:tuple[Hash,...]=Field(alias='feeCoinIds',min_length=1,max_length=16)
    maximum_fee_parent_mojos:int=Field(alias='maximumFeeParentMojos',gt=0,le=20_000_000_000)
    maximum_stamp_fee_mojos:int=Field(alias='maximumStampFeeMojos',gt=0,le=1_000_000_000)

    @field_validator('issued_at','expires_at','base_max_fee_wei','base_daily_fee_wei',
        'maximum_fee_parent_mojos','maximum_stamp_fee_mojos',mode='before')
    @classmethod
    def exact_integer(cls,value):
        if type(value)is not int:raise ValueError('identity authority requires exact integers')
        return value

    @model_validator(mode='after')
    def bounded(self):
        if (not 0<self.expires_at-self.issued_at<=48*3600 or len(set(self.fee_coin_ids))!=len(self.fee_coin_ids)
                or self.base_daily_fee_wei<self.base_max_fee_wei
                or self.maximum_stamp_fee_mojos>self.maximum_fee_parent_mojos):
            raise ValueError('identity authority must be finite and internally consistent')
        return self

    def require_live(self,profile,now):
        if (type(now)is not int or not self.issued_at<=now<self.expires_at
                or self.generation_id!=profile.generation_id or self.identity_profile_hash!=profile.commitment
                or self.relayer_address!=profile.trusted_direct_relayer):
            raise ValueError('CURRENT_ID_AUTHORITY_EXPIRED_OR_CHANGED')
        return self


def load_current_identity_authority(settings,profile,*,now,allow_expired_read_context=False):
    from .generation_index import _bounded_file
    raw=_bounded_file(settings.generation_customer_identity_authority_path,16384)
    if '0x'+sha256(raw).hexdigest()!=settings.generation_customer_identity_authority_hash:
        raise ValueError('CURRENT_ID_AUTHORITY_SOURCE_CHANGED')
    policy=CurrentIdentityAuthority.model_validate_json(raw)
    if allow_expired_read_context:now=max(policy.issued_at,min(now,policy.expires_at-1))
    return policy.require_live(profile,now)


class CurrentIdentityFeeFaucet:
    """Sign only a saved stamp subsidy, from explicitly fingerprinted inputs."""
    def __init__(self,faucet,authority,profile,ledger,*,clock):
        self._faucet,self.authority,self.profile,self.ledger,self.clock=faucet,authority,profile,ledger,clock
        self.network=faucet.network;self.address_puzzle_hash=faucet.address_puzzle_hash
        self.address_hex=faucet.address_hex;self.key=SimpleNamespace(puzzle=faucet.key.puzzle)

    def add_coin_reservation_source(self,source):self._faucet.add_coin_reservation_source(source)

    def select_coin(self,records,**kwargs):
        self.authority.require_live(self.profile,int(self.clock()))
        return self._faucet.select_coin([r for r in records
            if '0x'+Coin.from_json_dict(r.get('coin') or r).name().hex() in self.authority.fee_coin_ids],**kwargs)

    def sign_delegated_spend(self,coin,conditions,*,purpose=None):
        self.authority.require_live(self.profile,int(self.clock()))
        if (purpose is not None or self.network!='testnet11'
                or self.address_hex!=self.authority.funding_puzzle_hash
                or '0x'+coin.name().hex() not in self.authority.fee_coin_ids
                or coin.puzzle_hash!=self.address_puzzle_hash or coin.amount>self.authority.maximum_fee_parent_mojos):
            raise ValueError('CURRENT_ID_FEE_PARENT_REJECTED')
        values=list(conditions.as_iter());fees=[v for v in values if v.first().as_int()==52]
        if len(fees)!=1:raise ValueError('CURRENT_ID_FEE_CONDITIONS_REJECTED')
        fee=fees[0].rest().first().as_int()
        if not 0<=fee<=min(int(coin.amount),self.authority.maximum_stamp_fee_mojos-1):
            raise ValueError('CURRENT_ID_FEE_CAP_EXCEEDED')
        deadlines=[v for v in values if v.first().as_int()==85]
        if len(deadlines)!=1:raise ValueError('CURRENT_ID_FEE_DEADLINE_REQUIRED')
        deadline=deadlines[0].rest().first().as_int()
        if not int(self.clock())<deadline<=min(int(self.clock())+120,self.authority.expires_at):
            raise ValueError('CURRENT_ID_FEE_DEADLINE_REJECTED')
        exact=[]
        if coin.amount>fee:exact.append(Program.to([51,self.address_puzzle_hash,int(coin.amount)-fee]))
        exact.append(Program.to([52,fee]))
        from .protocol_submission import ProtocolBundleSubmitter
        matched=False
        for key,record in self.ledger.all_enrollments().items():
            binding=record.get('identityDeployment') or {}
            if (binding.get('generationId')!=self.profile.generation_id
                    or binding.get('identityProfileHash')!=self.profile.commitment):continue
            attempt=self.ledger.get_stamp_attempt(key)
            if not attempt or not attempt['bundle_hex']:continue
            claim=json.loads(attempt['claim_json'])
            if (claim.get('claim_version')!='solslot.current-customer-identity-claim.v1'
                    or claim.get('generation_id')!=self.profile.generation_id
                    or claim.get('identity_profile_hash')!=self.profile.commitment):continue
            bundle=SpendBundle.from_bytes(bytes.fromhex(attempt['bundle_hex']))
            backing=ProtocolBundleSubmitter._backing_conditions(bundle,require_announcements=True)
            if bytes(conditions)==bytes(Program.to([*exact,*backing,Program.to([85,deadline])])):
                matched=True;break
        if not matched:raise ValueError('CURRENT_ID_FEE_REQUIRES_SAVED_STAMP')
        return self._faucet.sign_delegated_spend(coin,conditions)
