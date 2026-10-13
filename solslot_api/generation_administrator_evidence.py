"""Read the exact current authority and all three conserved identity outputs.

This is bounded primary-node observation. It executes confirmed continuations,
including the existing recovery transitions, and rechecks the complete proof.
It never reserves inputs, builds an action or changes the identity roster.
Current signing policies must separately reconstruct the authority's custody
commitments; missing recovery-key metadata cannot obstruct holder governance.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (SINGLETON_LAUNCHER_HASH,SINGLETON_MOD_HASH,puzzle_for_singleton)
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.admin_authority_v2_driver import singleton_full_puzzle_hash
from solslot_puzzles.admin_authority_v3_driver import (GenesisAdminAuthorityV3,make_inner_puzzle,parse_inner_puzzle)
from solslot_puzzles.generation_admin_transactions import AdministratorIdentityTip,validate_frozen_administrator
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_registry_reader import exact_list,uint
from solslot_puzzles.generation_transactions import MAX_NATIVE_COST
from .admin_authority_v3 import _state_after_solution
from .generation_chain_evidence import _history,SingletonHistory,MAX_HISTORY
from .generation_registry_evidence import _spend
from .vault_chain_evidence import ConfirmedVaultCoin
from .generation_coin_evidence import read_confirmed_coin


def administrator_successor(spend:CoinSpend,inner:Program,authority_id):
    full=Program.from_bytes(bytes(spend.puzzle_reveal))
    mod,args=full.uncurry();structure,old=exact_list(args,2)
    if (full.get_tree_hash()!=spend.coin.puzzle_hash or mod.get_tree_hash()!=SINGLETON_MOD_HASH
            or structure!=singleton_struct(authority_id) or old!=inner or spend.coin.amount!=1):
        raise ValueError('administrator spend differs from its last verified state and singleton')
    solution=Program.from_bytes(bytes(spend.solution));_,amount,_=exact_list(solution,3)
    if uint(amount)!=1:raise ValueError('administrator conserved amount changed')
    parsed,state,tag=_state_after_solution(inner,solution)
    if parsed.authority_puzzle_version!=4:
        raise ValueError('generation administration requires its frozen V4 recovery authority')
    after=make_inner_puzzle(authority_launcher_id=parsed.authority_launcher_id,
        operational_root_hash=parsed.operational_root_hash,lost_recovery_root_hashes=parsed.lost_recovery_root_hashes,
        identity_launcher_ids=parsed.identity_launcher_ids,source_manifest_hash=parsed.source_manifest_hash,
        state=state,routine_delay_seconds=parsed.routine_delay_seconds,lost_key_delay_seconds=parsed.lost_key_delay_seconds,
        authority_puzzle_version=4)
    additions,_=compute_additions_with_cost(spend,max_cost=MAX_NATIVE_COST)
    expected=Coin(spend.coin.name(),puzzle_for_singleton(authority_id,after).get_tree_hash(),spend.coin.amount)
    if [c for c in additions if c.amount%2]!=[expected]:
        raise ValueError('administrator transition differs from its exact native output')
    return after,expected,tag


@dataclass(frozen=True)
class AdministratorIdentityEvidence:
    launcher_id:bytes32
    custody_hash:bytes32
    current:ConfirmedVaultCoin
    parent_spend:CoinSpend
    records:tuple[ConfirmedVaultCoin,...]

    def verified_tip(self,policy,authority_id):
        if policy.launcher_id!=self.launcher_id or policy.custody_hash!=self.custody_hash:
            raise ValueError('signing keys do not reconstruct the current on-chain identity')
        return AdministratorIdentityTip(policy,self.current.coin,self.parent_spend).validate(authority_id)


@dataclass(frozen=True)
class GenerationAdministratorEvidence:
    authority:SingletonHistory
    identities:tuple[AdministratorIdentityEvidence,...]

    @property
    def current_records(self):
        return (self.authority.current,*(i.current for i in self.identities))


async def resolve_generation_administrators(initial:GenesisAdminAuthorityV3,*,provider):
    validate_frozen_administrator(initial)
    async with asyncio.timeout(40):
        if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
            raise ValueError('administrator observation requires the primary Testnet11 node')
        authority=await _history(provider,initial.authority_launcher_id,initial.inner_puzzle,lambda s:s,
            lambda inner,spend:administrator_successor(spend,inner,initial.authority_launcher_id))
        current=parse_inner_puzzle(authority.state)
        async def read(identity):
            return read_confirmed_coin(await provider.get_coin_record_by_name_primary('0x'+identity.hex()),identity)
        identities=[]
        for slot,frozen in enumerate(initial.identity_vaults):
            launcher=await read(frozen.launcher_id)
            if (launcher.coin.puzzle_hash!=SINGLETON_LAUNCHER_HASH or not launcher.spent_height
                    or launcher.coin.amount!=frozen.launcher_amount):
                raise ValueError('administrator identity launcher is not confirmed or its amount changed')
            launch=_spend(await provider.get_puzzle_and_solution_primary('0x'+launcher.coin.name().hex(),launcher.spent_height),launcher.coin)
            additions,_=compute_additions_with_cost(launch,max_cost=5_000_000)
            expected=Coin(launcher.coin.name(),frozen.full_puzzle_hash,launcher.coin.amount)
            if [c for c in additions if c.amount%2]!=[expected]:
                raise ValueError('administrator identity launch differs from its frozen custody policy')
            parent,height,records=launch,launcher.spent_height,[launcher]
            for step in range(MAX_HISTORY+1):
                record=await read(expected.name())
                if record.coin!=expected or record.confirmed_height!=height:
                    raise ValueError('administrator identity lacks its exact confirmed continuation')
                records.append(record)
                if not record.spent_height:break
                if step==MAX_HISTORY:raise ValueError('administrator identity exceeds its observation bound')
                spend=_spend(await provider.get_puzzle_and_solution_primary('0x'+record.coin.name().hex(),record.spent_height),record.coin)
                mod,args=Program.from_bytes(bytes(spend.puzzle_reveal)).uncurry();structure,_=exact_list(args,2)
                if mod.get_tree_hash()!=SINGLETON_MOD_HASH or structure!=singleton_struct(frozen.launcher_id):
                    raise ValueError('administrator identity parent belongs to another singleton')
                _,amount,_=exact_list(Program.from_bytes(bytes(spend.solution)),3)
                if uint(amount)!=frozen.launcher_amount:raise ValueError('identity solution changes its conserved amount')
                additions,_=compute_additions_with_cost(spend,max_cost=MAX_NATIVE_COST)
                odd=[c for c in additions if c.amount%2]
                if len(odd)!=1 or odd[0].amount!=frozen.launcher_amount:
                    raise ValueError('identity continuation changes its conserved output')
                parent,height,expected=spend,record.spent_height,odd[0]
            custody=current.state.current_identity_custody_hashes[slot]
            # Only the custody hash is available for an unspent output. Do not
            # invent a reveal or select keys from coordinator state.
            if record.coin.puzzle_hash!=singleton_full_puzzle_hash(frozen.launcher_id,custody):
                raise ValueError('identity output differs from current authority custody')
            if current.state.pending_kind and current.state.pending_slot==slot:
                if record.coin.name()!=current.state.pending_identity_coin_id:
                    raise ValueError('pending recovery does not bind the exact current identity coin')
            identities.append(AdministratorIdentityEvidence(frozen.launcher_id,custody,record,parent,tuple(records)))
        result=GenerationAdministratorEvidence(authority,tuple(identities))
        # Retain and recheck all historical inputs, not just the newest output,
        # so a reorg or concurrent authority/recovery spend cannot be mixed in.
        for history in (authority,*identities):
            for record in history.records:
                if await read(record.coin.name())!=record:
                    raise ValueError('administrator history changed during observation')
        return result
