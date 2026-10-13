"""Explicit maintenance preparation from fresh native chain evidence.

This module is never invoked by polling. It builds only supported exact
maintenance actions; no arbitrary bundle, module reveal or wallet signature
can be supplied by a client. Preparation saves intent but does not broadcast.
"""
from __future__ import annotations

import asyncio
from hashlib import sha256
import time
from typing import Annotated, Literal

from pydantic import BaseModel,ConfigDict,Field,model_validator
from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_registry import CodeChange,UpgradePlan
from solslot_puzzles.generation_transactions import (
    anchor_vote,finalize_vote,ratify_upgrade,activate_upgrade,ratify_reopening,reopen_operations,apply_parameters,apply_statutes,prove_state)
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_ballots import CurrentHoldings,unlock_stakes
from solslot_puzzles.generation_sgt import ledger_inner
from chia.types.blockchain_format.program import Program
from .generation_chain_evidence import resolve_generation_chain,current_evidence_unchanged
from .generation_operations import canonical
from .generation_holding_evidence import verified_sgt_inputs

Hash=Annotated[str,Field(pattern=r'^0x[0-9a-f]{64}$')]
UInt=Annotated[int,Field(strict=True,ge=0,lt=2**64)]


class Model(BaseModel):
    model_config=ConfigDict(extra='forbid',populate_by_name=True,frozen=True)


class UpgradeChange(Model):
    component_id:Hash=Field(alias='componentId')
    old_module_hash:Hash=Field(alias='oldModuleHash')
    new_module_hash:Hash=Field(alias='newModuleHash')
    next_version:UInt=Field(alias='nextVersion')
    compatibility:UInt
    transition:Literal['PRESERVE_STATE']='PRESERVE_STATE'


class UpgradeIntent(Model):
    source_manifest_hash:Hash=Field(alias='sourceManifestHash')
    changes:tuple[UpgradeChange,...]=Field(min_length=1,max_length=32)

    def plan(self):
        from .generation_context import generation_bytes
        for v in (self.source_manifest_hash,*(v for c in self.changes for v in
                   (c.component_id,c.old_module_hash,c.new_module_hash))):generation_bytes(v)
        plan=UpgradePlan(bytes32.from_hexstr(self.source_manifest_hash),tuple(CodeChange(
            bytes32.from_hexstr(c.component_id),bytes32.from_hexstr(c.old_module_hash),
            bytes32.from_hexstr(c.new_module_hash),c.next_version,c.compatibility) for c in self.changes))
        plan.program()
        return plan


class ExpectedInputs(Model):
    registry:Hash
    governance:Hash
    holdings:Hash
    components:dict[Hash,Hash]=Field(default_factory=dict,max_length=31)


class ParameterIntent(Model):
    component_id:Hash=Field(alias='componentId')
    launcher_id:Hash=Field(alias='launcherId')
    revision:UInt
    previous_values_hash:Hash=Field(alias='previousValuesHash')
    values:tuple[UInt,UInt,UInt,UInt,UInt,UInt]

    @model_validator(mode='after')
    def bounded(self):
        GenerationParameters.validate(self.values)
        return self


class StateProofIntent(Model):
    component_id:Hash=Field(alias='componentId')
    module_hash:Hash=Field(alias='moduleHash')
    version:UInt
    state_hash:Hash=Field(alias='stateHash')


class StatuteIntent(Model):
    component_id:Hash=Field(alias='componentId')
    launcher_id:Hash=Field(alias='launcherId')
    revision:UInt
    record_kind:Literal['COLLECTION','ORACLE','ROUTE','LIQUIDITY']=Field(alias='recordKind')
    key:Hash
    record:tuple[UInt|Hash,...]=Field(min_length=7,max_length=10)
    previous_root:Hash=Field(alias='previousRoot')
    next_root:Hash=Field(alias='nextRoot')
    current_records:tuple[tuple[UInt|Hash,...],...]=Field(alias='currentRecords',max_length=32)

    def replacement(self):
        from solslot_puzzles.generation_economic_reader import parse_statute_record
        return parse_statute_record(self.record_kind,Program.to([
            bytes32.from_hexstr(v) if isinstance(v,str) else v for v in self.record]))

    def entries(self):
        from solslot_puzzles.generation_economic_reader import parse_statute_record
        return tuple(parse_statute_record(self.record_kind,Program.to([
            bytes32.from_hexstr(v) if isinstance(v,str) else v for v in row])) for row in self.current_records)

    @model_validator(mode='after')
    def bounded(self):
        from solslot_puzzles.generation_statutes import canonical_records
        from solslot_puzzles.protocol_statutes_v1 import keyed_root
        record=self.replacement();entries=canonical_records(self.record_kind,self.entries())
        if ('0x'+record.as_program_value()[0].hex()!=self.key
                or '0x'+keyed_root(entries).hex()!=self.previous_root or self.previous_root==self.next_root):
            raise ValueError('statute intent differs from its canonical key or previous root')
        return self

    def bill(self,state):
        from solslot_puzzles.generation_statutes import GenerationStatutes
        if (not isinstance(state,GenerationStatutes) or '0x'+state.component_id.hex()!=self.component_id
                or '0x'+state.launcher_id.hex()!=self.launcher_id or state.revision!=self.revision):
            raise ValueError('statutes intent differs from the confirmed current authority')
        bill,_,_=state.record_change(self.record_kind,self.entries(),self.replacement())
        if '0x'+bill.as_python()[8].hex()!=self.next_root:
            raise ValueError('statutes intent changes the reviewed successor root')
        return bill


class StakeUnlockIntent(Model):
    coin_ids:tuple[Hash,...]=Field(alias='coinIds',min_length=1,max_length=32)

    @model_validator(mode='after')
    def unique(self):
        if len(set(self.coin_ids))!=len(self.coin_ids):raise ValueError('a holding may be selected only once')
        return self


class RedemptionAllocation(Model):
    deed_launcher_id:Hash=Field(alias='deedLauncherId')
    deed_commitment:Hash=Field(alias='deedCommitment')
    share_ppm:int=Field(alias='sharePpm',strict=True,gt=0,le=1_000_000)
    payment_amount:int=Field(alias='paymentAmount',strict=True,gt=0,le=2**53-1)


class RedemptionIntent(Model):
    treasury_coin_id:Hash=Field(alias='treasuryCoinId')
    treasury_parent_id:Hash=Field(alias='treasuryParentId')
    collection_id:Hash=Field(alias='collectionId')
    settlement_id:Hash=Field(alias='settlementId')
    payment_asset_id:Hash=Field(alias='paymentAssetId')
    total_payment_amount:int=Field(alias='totalPaymentAmount',strict=True,gt=0,le=2**53-1)
    allocations:tuple[RedemptionAllocation,...]=Field(min_length=1,max_length=100)
    deed_launcher_puzzle_hash:Hash=Field(alias='deedLauncherPuzzleHash')

    def plan(self):
        from solslot_puzzles.funded_redemption_v1 import FundedRedemptionPlanV1,FundedRedemptionAllocation,canonical_redemption_allocations
        from .generation_context import generation_bytes
        for value in (self.treasury_coin_id,self.treasury_parent_id,self.collection_id,self.settlement_id,
                self.payment_asset_id,self.deed_launcher_puzzle_hash,
                *(value for row in self.allocations for value in (row.deed_launcher_id,row.deed_commitment))):
            generation_bytes(value)
        entries=tuple(FundedRedemptionAllocation(bytes32.from_hexstr(row.deed_launcher_id),
            bytes32.from_hexstr(row.deed_commitment),row.share_ppm,row.payment_amount) for row in self.allocations)
        if entries!=canonical_redemption_allocations(entries):raise ValueError('redemption allocations must use canonical deed-ID order')
        return FundedRedemptionPlanV1(bytes32.from_hexstr(self.collection_id),bytes32.from_hexstr(self.settlement_id),
            bytes32.from_hexstr(self.payment_asset_id),self.total_payment_amount,entries).validate()

    @model_validator(mode='after')
    def exact_plan(self):
        self.plan()
        return self


class RewardEpochIntent(Model):
    asset_id:Hash=Field(alias='assetId')
    statutes_component_id:Hash=Field(alias='statutesComponentId')
    statutes_launcher_id:Hash=Field(alias='statutesLauncherId')
    revision:UInt
    values_hash:Hash=Field(alias='valuesHash')
    holdings_root:Hash=Field(alias='holdingsRoot')
    eligible_supply:int=Field(alias='eligibleSupply',strict=True,gt=0,le=1_000_000)
    ledger_sequence:UInt=Field(alias='ledgerSequence')
    fee_coin_ids:tuple[Hash,...]=Field(alias='feeCoinIds',min_length=1,max_length=64)

    @model_validator(mode='after')
    def bounded(self):
        from .generation_context import generation_bytes
        # Native TXCH is represented by the canonical zero asset identity;
        # every authority/input commitment still must be nonzero.
        for value in (self.statutes_component_id,self.statutes_launcher_id,self.values_hash,self.holdings_root,*self.fee_coin_ids):
            generation_bytes(value)
        if len(set(self.fee_coin_ids))!=len(self.fee_coin_ids):raise ValueError('duplicate reward fee input')
        return self


class RewardClaimIntent(Model):
    asset_id:Hash=Field(alias='assetId')
    statutes_launcher_id:Hash=Field(alias='statutesLauncherId')
    epoch_id:Hash=Field(alias='epochId')
    owner_puzzle_hash:Hash=Field(alias='ownerPuzzleHash')
    amount:int=Field(strict=True,gt=0,le=2**53-1)
    claim_coin_id:Hash=Field(alias='claimCoinId')
    vault_launcher_id:Hash=Field(alias='vaultLauncherId')

    @model_validator(mode='after')
    def bounded(self):
        from .generation_context import generation_bytes
        for value in (self.statutes_launcher_id,self.epoch_id,self.owner_puzzle_hash,self.claim_coin_id,self.vault_launcher_id):
            generation_bytes(value)
        return self


class RewardProgressIntent(Model):
    asset_id:Hash=Field(alias='assetId')
    statutes_launcher_id:Hash=Field(alias='statutesLauncherId')
    continuation_coin_id:Hash=Field(alias='continuationCoinId')


class MaintenanceRequest(Model):
    generation_id:Hash=Field(alias='generationId')
    request_key:str=Field(alias='requestKey',pattern=r'^[a-zA-Z0-9_:-]{1,128}$')
    kind:Literal['ANCHOR_VOTE','FINALIZE_VOTE','RATIFY_UPGRADE','ACTIVATE_UPGRADE','RATIFY_REOPENING','REOPEN_OPERATIONS','APPLY_PARAMETERS','APPLY_STATUTES','FUND_REDEMPTION','CLOSE_REWARD_EPOCH','ADVANCE_SGT_REWARDS','CLAIM_SGT_REWARD','PROVE_STATE','UNLOCK_STAKES']
    expected_inputs:ExpectedInputs=Field(alias='expectedInputs')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)
    proposal_id:Hash|None=Field(default=None,alias='proposalId')
    upgrade:UpgradeIntent|None=None
    scope:int|None=Field(default=None,strict=True,ge=1,le=31)
    parameters:ParameterIntent|None=None
    statutes:StatuteIntent|None=None
    proof:StateProofIntent|None=None
    stakes:StakeUnlockIntent|None=None
    redemption:RedemptionIntent|None=None
    reward_epoch:RewardEpochIntent|None=Field(default=None,alias='rewardEpoch')
    reward_claim:RewardClaimIntent|None=Field(default=None,alias='rewardClaim')
    reward_progress:RewardProgressIntent|None=Field(default=None,alias='rewardProgress')

    @model_validator(mode='after')
    def exact_fields(self):
        if bool(self.upgrade)!=(self.kind in ('RATIFY_UPGRADE','ACTIVATE_UPGRADE')):
            raise ValueError('upgrade plan is required only for a code upgrade')
        if bool(self.proposal_id)!=(self.kind in ('RATIFY_UPGRADE','RATIFY_REOPENING','APPLY_PARAMETERS','APPLY_STATUTES','FUND_REDEMPTION')):
            raise ValueError('ratification requires the exact approved proposal')
        if (self.scope is not None)!=(self.kind=='RATIFY_REOPENING'):
            raise ValueError('a scope is required only for reopening ratification')
        if bool(self.parameters)!=(self.kind=='APPLY_PARAMETERS'):
            raise ValueError('parameter intent is required only for a ratified parameter change')
        if bool(self.statutes)!=(self.kind=='APPLY_STATUTES'):
            raise ValueError('statutes intent is required only for its exact ratified record')
        if bool(self.proof)!=(self.kind=='PROVE_STATE'):
            raise ValueError('state proof requires the exact reviewed active code and state')
        if bool(self.stakes)!=(self.kind=='UNLOCK_STAKES'):
            raise ValueError('stake unlock requires explicitly selected complete input coins')
        if bool(self.redemption)!=(self.kind=='FUND_REDEMPTION'):
            raise ValueError('redemption funding requires its exact approved allocation')
        if bool(self.reward_epoch)!=(self.kind=='CLOSE_REWARD_EPOCH'):
            raise ValueError('reward closure requires exact funding and an authenticated holder snapshot')
        if bool(self.reward_claim)!=(self.kind=='CLAIM_SGT_REWARD'):
            raise ValueError('reward claim requires its exact unchanged recipient vault')
        if bool(self.reward_progress)!=(self.kind=='ADVANCE_SGT_REWARDS'):
            raise ValueError('reward progress requires its exact funded continuation input')
        if self.upgrade:self.upgrade.plan()
        return self

    @property
    def digest(self):
        return '0x'+sha256(canonical(self.document()).encode()).hexdigest()

    def document(self):
        value=self.model_dump(mode='json',by_alias=True)
        if self.statutes is None:value.pop('statutes')
        if self.redemption is None:value.pop('redemption')
        if self.reward_epoch is None:value.pop('rewardEpoch')
        if self.reward_claim is None:value.pop('rewardClaim')
        return value


async def prepare_maintenance(body:MaintenanceRequest,*,anchor,provider,journal,clock=time.time):
    # Copy maps and nested values before the first external await.
    body=MaintenanceRequest.model_validate_json(body.model_dump_json(by_alias=True))
    if (body.generation_id!=journal.generation_id
            or bytes32.from_hexstr(body.generation_id)!=anchor.issuance.generation):
        raise ValueError('operation belongs to another deployment generation')
    saved=journal.reviewed_request(body.request_key,body.digest)
    if saved:return saved  # Lost prepare response: resume the original action.
    async with asyncio.timeout(40):
        evidence=await resolve_generation_chain(anchor,provider=provider)
        for name in ('registry','governance','holdings'):
            if '0x'+getattr(evidence,name).current.coin.name().hex()!=getattr(body.expected_inputs,name):
                raise ValueError('confirmed inputs changed; refresh and review the new state')
        gov,reg=evidence.governance.state,evidence.registry.state
        required={c.component_id for c in body.upgrade.plan().changes if c.component_id!=gov.component_id} if body.kind=='ACTIVATE_UPGRADE' else set()
        if body.kind=='APPLY_PARAMETERS':required={bytes32.from_hexstr(body.parameters.component_id)}
        if body.kind=='APPLY_STATUTES':required={bytes32.from_hexstr(body.statutes.component_id)}
        if body.kind=='CLOSE_REWARD_EPOCH':required={bytes32.from_hexstr(body.reward_epoch.statutes_component_id)}
        if {bytes32.from_hexstr(k) for k in body.expected_inputs.components}!=required:
            raise ValueError('every affected economic input must be explicitly reviewed')
        for identity,coin_id in body.expected_inputs.components.items():
            history=evidence.economic_components.get(bytes32.from_hexstr(identity))
            if history is None or '0x'+history.current.coin.name().hex()!=coin_id:
                raise ValueError('confirmed economic inputs changed; refresh and review the new state')
        gov_tip=evidence.governance.verified_tip(reg.governance_id,gov.inner())
        reg_tip=evidence.registry.verified_tip(reg.launcher_id,reg.inner())
        redemption_records=();reward_records=()
        if body.kind=='ANCHOR_VOTE':
            if not gov.active or gov.active.opened_at:raise ValueError('no opening timestamp is waiting')
            record=await _confirmed_coin(provider,gov.active.clock_id)
            operation,_=anchor_vote(gov,gov_tip,record[0],record[1])
        elif body.kind=='FINALIZE_VOTE':
            operation,_=finalize_vote(gov,gov_tip)
        elif body.kind=='RATIFY_UPGRADE':
            operation,_,_=ratify_upgrade(gov,gov_tip,reg,reg_tip,bytes32.from_hexstr(body.proposal_id),body.upgrade.plan())
        elif body.kind=='ACTIVATE_UPGRADE':
            plan=body.upgrade.plan()
            components=[]
            for change in plan.changes:
                if change.component_id==gov.component_id:components.append((gov,gov_tip));continue
                history=evidence.economic_components.get(change.component_id)
                if history is None:
                    raise ValueError('the affected economic component has no supported frozen chain reader')
                state=history.state
                components.append((state,history.verified_tip(state.launcher_id,state.inner())))
            if not reg.pending:raise ValueError('no ratified upgrade ticket exists')
            ticket,_=await _confirmed_coin(provider,reg.pending[1])
            operation,_,_=activate_upgrade(gov,gov_tip,reg,reg_tip,plan,ticket,tuple(components))
        elif body.kind=='RATIFY_REOPENING':
            operation,_,_=ratify_reopening(gov,gov_tip,reg,reg_tip,bytes32.from_hexstr(body.proposal_id),body.scope)
        elif body.kind=='APPLY_PARAMETERS':
            intent=body.parameters
            history=evidence.economic_components[bytes32.from_hexstr(intent.component_id)]
            state=history.state
            if (not isinstance(state,GenerationParameters) or state.launcher_id!=bytes32.from_hexstr(intent.launcher_id)
                    or state.revision!=intent.revision
                    or Program.to(list(state.values)).get_tree_hash()!=bytes32.from_hexstr(intent.previous_values_hash)):
                raise ValueError('parameter review differs from the confirmed current authority')
            operation,_,_=apply_parameters(gov,gov_tip,reg,reg_tip,state,
                history.verified_tip(state.launcher_id,state.inner()),bytes32.from_hexstr(body.proposal_id),intent.values)
        elif body.kind=='APPLY_STATUTES':
            intent=body.statutes
            history=evidence.economic_components[bytes32.from_hexstr(intent.component_id)]
            state=history.state;intent.bill(state)
            operation,_,_,_=apply_statutes(gov,gov_tip,reg,reg_tip,state,
                history.verified_tip(state.launcher_id,state.inner()),bytes32.from_hexstr(body.proposal_id),
                intent.record_kind,intent.entries(),intent.replacement())
        elif body.kind=='FUND_REDEMPTION':
            from solslot_puzzles.generation_redemptions import fund_redemption
            from .generation_redemption_evidence import verified_redemption_source
            intent=body.redemption
            source,redemption_records=await verified_redemption_source(intent,governance=gov,provider=provider)
            operation=fund_redemption(gov,gov_tip,reg,reg_tip,bytes32.from_hexstr(body.proposal_id),
                source,intent.plan(),bytes32.from_hexstr(intent.deed_launcher_puzzle_hash)).operation
        elif body.kind=='CLOSE_REWARD_EPOCH':
            from solslot_puzzles.generation_rewards import RewardCustody,close_reward_epoch
            from solslot_puzzles.generation_statutes import GenerationStatutes
            from .generation_reward_evidence import verified_reward_inputs
            intent=body.reward_epoch;history=evidence.economic_components[bytes32.from_hexstr(intent.statutes_component_id)]
            state=history.state;tree,sequence=evidence.holdings.state
            if (not isinstance(state,GenerationStatutes) or state.launcher_id!=bytes32.from_hexstr(intent.statutes_launcher_id)
                    or state.revision!=intent.revision or Program.to(list(state.values)).get_tree_hash()!=bytes32.from_hexstr(intent.values_hash)
                    or tree.root.hash!=bytes32.from_hexstr(intent.holdings_root) or tree.root.eligible!=intent.eligible_supply
                    or sequence!=intent.ledger_sequence):
                raise ValueError('reward epoch differs from the confirmed holder and parameter snapshot')
            custody=RewardCustody(gov.sgt,state.launcher_id,bytes32.from_hexstr(intent.asset_id))
            fees,reward_records=await verified_reward_inputs(tuple(bytes32.from_hexstr(value) for value in intent.fee_coin_ids),provider=provider)
            current=CurrentHoldings(gov.sgt,tree,sequence,evidence.holdings.verified_tip(gov.sgt.ledger_launcher_id,ledger_inner(gov.sgt,tree,sequence)))
            operation=close_reward_epoch(custody,gov,reg,current,state,history.verified_tip(state.launcher_id,state.inner()),fees).operation
        elif body.kind=='ADVANCE_SGT_REWARDS':
            from solslot_puzzles.generation_rewards import RewardCustody
            from solslot_puzzles.generation_statutes import GenerationStatutes
            from .generation_reward_evidence import verified_reward_progress
            intent=body.reward_progress
            if not any(isinstance(history.state,GenerationStatutes) and history.state.launcher_id==bytes32.from_hexstr(intent.statutes_launcher_id)
                    for history in evidence.economic_components.values()):
                raise ValueError('reward progress belongs to an unknown generation authority')
            custody=RewardCustody(gov.sgt,bytes32.from_hexstr(intent.statutes_launcher_id),bytes32.from_hexstr(intent.asset_id))
            progress,reward_records=await verified_reward_progress(bytes32.from_hexstr(intent.continuation_coin_id),
                custody=custody,snapshots=evidence.snapshots,provider=provider)
            operation,_,_=progress.advance(limit=16)
        elif body.kind=='CLAIM_SGT_REWARD':
            from solslot_puzzles.generation_rewards import RewardCustody,EarnedReward,claim_vault_reward
            from solslot_puzzles.generation_statutes import GenerationStatutes
            from .generation_reward_evidence import verified_reward_inputs,verify_reward_claim_source
            intent=body.reward_claim
            if not any(isinstance(history.state,GenerationStatutes) and history.state.launcher_id==bytes32.from_hexstr(intent.statutes_launcher_id)
                    for history in evidence.economic_components.values()):
                raise ValueError('reward claim belongs to an unknown generation authority')
            custody=RewardCustody(gov.sgt,bytes32.from_hexstr(intent.statutes_launcher_id),bytes32.from_hexstr(intent.asset_id))
            sources,reward_records=await verified_reward_inputs((bytes32.from_hexstr(intent.claim_coin_id),),provider=provider)
            claim=EarnedReward(gov.sgt.generation,custody.asset_id,bytes32.from_hexstr(intent.epoch_id),
                bytes32.from_hexstr(intent.owner_puzzle_hash),intent.amount)
            verify_reward_claim_source(claim,sources[0],custody)
            operation=claim_vault_reward(claim,sources[0],bytes32.from_hexstr(intent.vault_launcher_id))
        elif body.kind=='PROVE_STATE':
            proof=body.proof
            if (bytes32.from_hexstr(proof.component_id)!=gov.component_id
                    or bytes32.from_hexstr(proof.module_hash)!=gov.module_hash or proof.version!=gov.version
                    or bytes32.from_hexstr(proof.state_hash)!=gov.state().get_tree_hash()):
                raise ValueError('state proof differs from the confirmed active code or state')
            operation=prove_state(gov,gov_tip)
        elif body.kind=='UNLOCK_STAKES':
            tree,sequence=evidence.holdings.state
            holdings=CurrentHoldings(gov.sgt,tree,sequence,evidence.holdings.verified_tip(
                gov.sgt.ledger_launcher_id,ledger_inner(gov.sgt,tree,sequence)))
            inputs=await verified_sgt_inputs(tuple(bytes32.from_hexstr(v) for v in body.stakes.coin_ids),
                bindings=gov.sgt,tree=tree,provider=provider)
            operation=unlock_stakes(gov,gov_tip,holdings,inputs).operation
        else:
            if not reg.reopening:raise ValueError('no ratified reopening ticket exists')
            ticket,_=await _confirmed_coin(provider,reg.reopening[1])
            operation,_=reopen_operations(reg,reg_tip,ticket)
        if not await current_evidence_unchanged(evidence,provider=provider):
            raise ValueError('confirmed inputs changed during preparation')
        if redemption_records:
            from .generation_redemption_evidence import redemption_inputs_unchanged
            await redemption_inputs_unchanged(redemption_records,provider)
        if reward_records:
            from .generation_reward_evidence import reward_records_unchanged
            await reward_records_unchanged(reward_records,provider)
        identity=journal.prepare(operation,body.request_key,body.fee_cap_mojos,int(clock()),request_digest=body.digest,
            request_document=body.document())
        return journal.status(identity)


async def _confirmed_coin(provider,identity):
    raw=await provider.get_coin_record_by_name_primary('0x'+identity.hex())
    if not isinstance(raw,dict):raise ValueError('confirmed auxiliary input is unavailable')
    coin=Coin.from_json_dict(raw['coin'])
    if (coin.name()!=identity or raw.get('spent') or raw.get('spent_block_index')!=0
            or type(raw.get('timestamp')) is not int or raw['timestamp']<=0
            or type(raw.get('confirmed_block_index')) is not int or raw['confirmed_block_index']<=0):
        raise ValueError('auxiliary input lacks exact unspent chain evidence')
    return coin,raw['timestamp']
