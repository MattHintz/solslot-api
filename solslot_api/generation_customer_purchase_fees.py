"""Finite sponsorship of saved native Testnet purchases, default closed.

Only the listed existing fee coins may be used. Their change is not a renewed
budget. The fee spend must assert the exact saved purchase announcements;
this adapter cannot fund a different action or pay a different destination.
"""
from hashlib import sha256
from types import SimpleNamespace
from typing import Literal

from chia.types.blockchain_format.program import Program
from chia_rs import Coin, SpendBundle
from pydantic import Field, field_validator, model_validator

from .generation_preparation import PreparationModel
from .generation_execution import Hash
from .protocol_submission import ProtocolBundleSubmitter


class CurrentPurchaseFeeAuthority(PreparationModel):
    schema_version:Literal['solslot.current-purchase-fee-authority.v1']=Field(alias='schema')
    network:Literal['testnet11']
    generation_id:Hash=Field(alias='generationId')
    issuer_policy_hash:Hash=Field(alias='issuerPolicyHash')
    funding_puzzle_hash:Hash=Field(alias='fundingPuzzleHash')
    fee_coin_ids:tuple[Hash,...]=Field(alias='feeCoinIds',min_length=1,max_length=50)
    maximum_fee_parent_mojos:int=Field(alias='maximumFeeParentMojos',gt=0,le=20_000_000_000)
    maximum_stage_fee_mojos:int=Field(alias='maximumStageFeeMojos',gt=0,le=1_000_000_000)
    maximum_total_fee_mojos:int=Field(alias='maximumTotalFeeMojos',gt=0,le=50_000_000_000)
    issued_at:int=Field(alias='issuedAt',gt=0)
    expires_at:int=Field(alias='expiresAt',gt=0)

    @field_validator('maximum_fee_parent_mojos','maximum_stage_fee_mojos',
        'maximum_total_fee_mojos','issued_at','expires_at',mode='before')
    @classmethod
    def integers(cls,value):
        if type(value)is not int:raise ValueError('purchase fee authority requires exact integers')
        return value

    @model_validator(mode='after')
    def bounded(self):
        if (len(self.fee_coin_ids)!=len(set(self.fee_coin_ids))
                or not 0<self.expires_at-self.issued_at<=48*3600
                or self.maximum_stage_fee_mojos>self.maximum_fee_parent_mojos
                or len(self.fee_coin_ids)*self.maximum_stage_fee_mojos>self.maximum_total_fee_mojos):
            raise ValueError('purchase fee authority must bound every permitted input')
        return self

    def require_policy(self,policy):
        if (self.generation_id!='0x'+policy.generation.hex()
                or self.issuer_policy_hash!=policy.commitment
                or not policy.issued_at<=self.issued_at<self.expires_at<=policy.expires_at):
            raise ValueError('CURRENT_PURCHASE_FEE_POLICY_CHANGED')
        return self

    def require_live(self,policy,now):
        self.require_policy(policy)
        if type(now)is not int or not self.issued_at<=now<self.expires_at:
            raise ValueError('CURRENT_PURCHASE_FEE_WINDOW_CLOSED')
        return self


def read_purchase_fee_authority(path,expected_hash,policy):
    from .generation_index import _bounded_file
    raw=_bounded_file(path,16384)
    if '0x'+sha256(raw).hexdigest()!=expected_hash:
        raise ValueError('CURRENT_PURCHASE_FEE_AUTHORITY_CHANGED')
    return CurrentPurchaseFeeAuthority.model_validate_json(raw).require_policy(policy)


class CurrentPurchaseFeeFaucet:
    def __init__(self,faucet,authority,policy,store,*,clock):
        from .generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
        authority.require_policy(policy)
        if (not isinstance(store,CurrentPurchaseExecutionStore) or store.generation_id!=authority.generation_id
                or faucet.network!='testnet11' or faucet.address_hex!=authority.funding_puzzle_hash):
            raise ValueError('CURRENT_PURCHASE_FEE_ACCOUNT_CHANGED')
        self._faucet,self.authority,self.policy,self.store,self.clock=faucet,authority,policy,store,clock
        self.network=faucet.network;self.address_hex=faucet.address_hex
        self.address_puzzle_hash=faucet.address_puzzle_hash
        self.key=SimpleNamespace(puzzle=faucet.key.puzzle)

    def add_coin_reservation_source(self,source):self._faucet.add_coin_reservation_source(source)

    def select_coin(self,records,**kwargs):
        self.authority.require_live(self.policy,int(self.clock()))
        selected=[r for r in records if '0x'+Coin.from_json_dict(r.get('coin')or r).name().hex()
            in self.authority.fee_coin_ids]
        return self._faucet.select_coin(selected,**kwargs)

    def sign_delegated_spend(self,coin,conditions,*,purpose=None):
        self.authority.require_live(self.policy,int(self.clock()))
        if (purpose is not None or self.network!='testnet11'
                or '0x'+coin.name().hex() not in self.authority.fee_coin_ids
                or coin.puzzle_hash!=self.address_puzzle_hash
                or coin.amount>self.authority.maximum_fee_parent_mojos):
            raise ValueError('CURRENT_PURCHASE_FEE_INPUT_REJECTED')
        values=list(conditions.as_iter());fees=[v for v in values if v.first().as_int()==52]
        deadlines=[v for v in values if v.first().as_int()==85]
        if len(fees)!=1 or len(deadlines)!=1:
            raise ValueError('CURRENT_PURCHASE_FEE_CONDITIONS_REJECTED')
        fee=fees[0].rest().first().as_int();deadline=deadlines[0].rest().first().as_int()
        if not 0<=fee<=min(int(coin.amount),self.authority.maximum_stage_fee_mojos):
            raise ValueError('CURRENT_PURCHASE_FEE_CAP_EXCEEDED')
        if not int(self.clock())<deadline<=min(int(self.clock())+120,self.authority.expires_at):
            raise ValueError('CURRENT_PURCHASE_FEE_DEADLINE_REJECTED')
        prefix=[]
        if coin.amount>fee:prefix.append(Program.to([51,self.address_puzzle_hash,int(coin.amount)-fee]))
        prefix.append(Program.to([52,fee]))
        with self.store._connect() as db:
            rows=db.execute('''SELECT e.*,r.canonical_claim FROM current_purchase_executions e
                JOIN current_customer_purchase_reviews r ON r.intent_id=e.intent_id
                WHERE r.generation_id=?''',(self.store.generation_id,)).fetchall()
        from .generation_customer_purchase_batch import reservation_from_json
        matched=False
        for row in rows:
            claim=reservation_from_json(row['canonical_claim'])
            if claim.issuer_policy_hash!=self.policy.commitment or int(self.clock())>=row['expires_at']:continue
            original=SpendBundle.from_bytes(row['protocol_bundle'])
            # Native reservation and timeout control paths emit no
            # announcement. Their exact reviewed singleton must be consumed
            # concurrently; delivery additionally commits its announcements.
            backing=ProtocolBundleSubmitter._backing_conditions(original,require_announcements=row['phase']=='DELIVERY')
            exact=Program.to([*prefix,*backing,Program.to([85,deadline])])
            if bytes(conditions)==bytes(exact):matched=True;break
        if not matched:raise ValueError('CURRENT_PURCHASE_FEE_SAVED_EXECUTION_REQUIRED')
        return self._faucet.sign_delegated_spend(coin,conditions)


class CurrentPurchaseBundleSubmitter(ProtocolBundleSubmitter):
    """Attach the finite deadline to the existing durable native submitter.

    The executor has already reconstructed the native operation. This adapter
    accepts only its exact saved bytes and does not create a separate fee book.
    """
    def __init__(self,*,execution_store,clock,**kwargs):
        super().__init__(**kwargs)
        if not isinstance(self.faucet,CurrentPurchaseFeeFaucet)or self.faucet.store is not execution_store:
            raise ValueError('CURRENT_PURCHASE_GUARDED_SUBMITTER_REQUIRED')
        self.execution_store,self.clock=execution_store,clock
        self._purchase_deadline=None

    async def _prepare_locked(self,protocol_bundle_json,**kwargs):
        if kwargs.get('selection_purpose') is not None or kwargs.get('expected_backing_mojos',0):
            raise ValueError('CURRENT_PURCHASE_FEE_PURPOSE_REJECTED')
        self.faucet.authority.require_live(self.faucet.policy,int(self.clock()))
        original=SpendBundle.from_json_dict(protocol_bundle_json)
        with self.execution_store._connect()as db:
            rows=db.execute('SELECT protocol_bundle,expires_at FROM current_purchase_executions WHERE original_id=?',
                ('0x'+original.name().hex(),)).fetchall()
        if len(rows)!=1 or rows[0]['protocol_bundle']!=bytes(original):
            raise ValueError('CURRENT_PURCHASE_FEE_SAVED_EXECUTION_REQUIRED')
        self._purchase_deadline=min(rows[0]['expires_at'],self.faucet.authority.expires_at,int(self.clock())+120)
        if self._purchase_deadline<=int(self.clock()):raise ValueError('CURRENT_PURCHASE_FEE_WINDOW_CLOSED')
        try:return await super()._prepare_locked(protocol_bundle_json,**kwargs)
        finally:self._purchase_deadline=None

    def _fee_bundle(self,coin,fee,*,selection_purpose,backing_mojos=0,backing_conditions=()):
        if self._purchase_deadline is None:raise ValueError('CURRENT_PURCHASE_FEE_PREPARATION_REQUIRED')
        return super()._fee_bundle(coin,fee,selection_purpose=selection_purpose,backing_mojos=backing_mojos,
            backing_conditions=(*backing_conditions,Program.to([85,self._purchase_deadline])))
