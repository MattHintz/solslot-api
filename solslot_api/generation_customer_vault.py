"""Current custody and ID from this registration's actual native ancestry.

No legacy vault lookup, receipt import or client-selected identity root. An ID
status requires a confirmed bridge-coupled stamp of this exact fresh vault.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import DEFAULT_IDENTITY_ATTEST_ROOT,one_leaf_merkle_root
from .vault_chain_evidence import read_vault_coin
from .generation_registry_evidence import _spend

MAX_CURRENT_VAULT_HISTORY=512


def h(value):return '0x'+value.hex()


@dataclass(frozen=True)
class CurrentCustomerVault:
    generation:bytes32
    launcher:bytes32
    coin:Coin
    inner:Program
    root:bytes32
    confirmed_height:int
    stamp_coin_id:bytes32|None
    bridge_coin_id:bytes32|None
    stamp_height:int|None
    parent_spend:object|None

    @property
    def identity_verified(self):
        return (self.root not in (bytes32.zeros,DEFAULT_IDENTITY_ATTEST_ROOT)
            and self.stamp_coin_id is not None and self.bridge_coin_id is not None
            and type(self.stamp_height)is int and self.stamp_height>0)

    def public(self):
        return {'generationId':h(self.generation),'network':'testnet11',
            'vaultLauncherId':h(self.launcher),'currentCoinId':h(self.coin.name()),
            'currentPuzzleHash':h(self.coin.puzzle_hash),'confirmedHeight':self.confirmed_height,
            'identityVerified':self.identity_verified,
            'identityStatus':'VERIFIED' if self.identity_verified else 'FRESH_ID_REQUIRED',
            'identityAttestRoot':h(self.root),'stampCoinId':h(self.stamp_coin_id) if self.stamp_coin_id else None,
            'bridgeCoinId':h(self.bridge_coin_id) if self.bridge_coin_id else None,'stampHeight':self.stamp_height}


async def trace_current_customer_vault(*,bindings,launcher,owner_pubkey,auth_type,initial_coin,provider):
    """Internal primitive: caller first proves this registration's creation."""
    bindings.validate()
    if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
        raise ValueError('CURRENT_CUSTOMER_VAULT_NETWORK_CHANGED')
    if not isinstance(launcher,bytes32) or initial_coin.parent_coin_info!=launcher:
        raise ValueError('CURRENT_CUSTOMER_VAULT_ORIGIN_CHANGED')
    def inner(root):
        return vault_inner(vault_launcher_id=launcher,owner_pubkey=owner_pubkey,
            auth_type=auth_type,members_merkle_root=one_leaf_merkle_root(owner_pubkey),
            pool_launcher_id=bindings.pool_launcher,identity_attest_root=root,
            zkpassport_bridge_policy_hash=bindings.bridge_policy)
    async def read(coin_id):
        return read_vault_coin(await provider.get_coin_record_by_name_primary(h(coin_id)),coin_id)
    expected=initial_coin;root=DEFAULT_IDENTITY_ATTEST_ROOT;verified=[];bridges=[]
    stamp_id=bridge_id=stamp_height=parent=None
    async with asyncio.timeout(20):
        for step in range(MAX_CURRENT_VAULT_HISTORY+1):
            current_inner=inner(root)
            if (expected.amount!=1 or expected.puzzle_hash!=puzzle_for_singleton(launcher,current_inner).get_tree_hash()):
                raise ValueError('CURRENT_CUSTOMER_VAULT_CUSTODY_CHANGED')
            record=await read(expected.name())
            if record.coin!=expected:raise ValueError('CURRENT_CUSTOMER_VAULT_COIN_CHANGED')
            if parent is not None:
                previous=verified[-1]
                if previous.spent_height!=record.confirmed_height:
                    raise ValueError('CURRENT_CUSTOMER_VAULT_HISTORY_NOT_ATOMIC')
            verified.append(record)
            if not record.spent_height:
                for prior in (*verified,*bridges):
                    if await read(prior.coin.name())!=prior:
                        raise ValueError('CURRENT_CUSTOMER_VAULT_CHANGED_DURING_READ')
                return CurrentCustomerVault(bindings.generation,launcher,expected,current_inner,root,
                    record.confirmed_height,stamp_id,bridge_id,stamp_height,parent)
            if step==MAX_CURRENT_VAULT_HISTORY:
                raise ValueError('CURRENT_CUSTOMER_VAULT_HISTORY_LIMIT')
            spend=_spend(await provider.get_puzzle_and_solution_primary(h(expected.name()),record.spent_height),expected)
            if bytes(spend.puzzle_reveal)!=bytes(puzzle_for_singleton(launcher,current_inner)):
                raise ValueError('CURRENT_CUSTOMER_VAULT_REVEAL_CHANGED')
            outer=list(Program.from_bytes(bytes(spend.solution)).as_iter())
            if len(outer)!=3:raise ValueError('CURRENT_CUSTOMER_VAULT_SOLUTION_CHANGED')
            solution=list(outer[2].as_iter())
            if len(solution)!=5:raise ValueError('CURRENT_CUSTOMER_VAULT_ACTION_CHANGED')
            if solution[3].as_atom()==b'z':
                args=list(solution[4].as_iter())
                if (len(args)!=6 or root!=DEFAULT_IDENTITY_ATTEST_ROOT or stamp_id is not None
                        or args[0].as_atom()!=bytes(bindings.vault_module) or args[3].as_int()!=1):
                    raise ValueError('CURRENT_CUSTOMER_ID_STAMP_CHANGED')
                new_root=bytes32(args[1].as_atom())
                if new_root in (bytes32.zeros,DEFAULT_IDENTITY_ATTEST_ROOT):
                    raise ValueError('CURRENT_CUSTOMER_ID_ROOT_EMPTY')
                bridge=Coin(bytes32(args[2].as_atom()),bindings.bridge_policy,uint64(1))
                bridge_record=await read(bridge.name())
                if bridge_record.coin!=bridge or bridge_record.spent_height!=record.spent_height:
                    raise ValueError('CURRENT_CUSTOMER_ID_BRIDGE_NOT_ATOMIC')
                bridges.append(bridge_record)
                bridge_spend=_spend(await provider.get_puzzle_and_solution_primary(h(bridge.name()),bridge_record.spent_height),bridge)
                if bridge_spend.puzzle_reveal.get_tree_hash()!=bindings.bridge_policy:
                    raise ValueError('CURRENT_CUSTOMER_ID_BRIDGE_POLICY_CHANGED')
                # The confirmed custody spend's announcement pins this bridge
                # coin and root; a saved web receipt cannot substitute either.
                root=new_root;bridge_id=bridge.name();stamp_height=record.spent_height
            additions,_=compute_additions_with_cost(spend,max_cost=100_000_000)
            children=[coin for coin in additions if coin.amount%2]
            next_coin=Coin(expected.name(),puzzle_for_singleton(launcher,inner(root)).get_tree_hash(),uint64(1))
            if children!=[next_coin]:raise ValueError('CURRENT_CUSTOMER_VAULT_CONTINUATION_CHANGED')
            if bridge_id is not None and stamp_id is None:stamp_id=next_coin.name()
            expected=next_coin;parent=spend
    raise ValueError('CURRENT_CUSTOMER_VAULT_HISTORY_UNAVAILABLE')


async def resolve_registered_customer_vault(identity,*,store,journal,settings,index,provider,clock):
    from .generation_customer_execution import verify_customer_creation,validate_customer_bundle,saved_customer_operation
    await verify_customer_creation(identity,store=store,journal=journal,settings=settings,index=index,
        provider=provider,clock=clock,require_unused=False)
    consent,signature,accepted_at=store.authorized_material(identity)
    owner,auth=consent.verified_owner(signature,accepted_at)
    saved=saved_customer_operation(store,journal,identity)
    _,_,initial=validate_customer_bundle(journal.protocol_bundle(saved['operationId']),saved['review'])
    return await trace_current_customer_vault(bindings=consent.bindings,launcher=consent.vault_launcher_id,
        owner_pubkey=owner,auth_type=auth,initial_coin=initial,provider=provider)


async def resolve_native_identity_vault(*,bindings,launcher,provider):
    """Independent validator proof; imports no API registry or saved receipt.

    A stamped vault reveals its original native custody preimage on chain.
    Reconstruct that exact initial coin, then prove the bridge-coupled stamp
    and every successor. Customer UI discovery still requires its separate
    signed current registration; this is not a historical-vault import path.
    """
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    bindings.validate()
    if not isinstance(launcher,bytes32) or launcher==bytes32.zeros:
        raise ValueError('CURRENT_ID_NATIVE_VAULT_LAUNCHER_INVALID')
    async def read(value):
        return read_vault_coin(await provider.get_coin_record_by_name_primary(h(value)),value)
    async with asyncio.timeout(30):
        if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
            raise ValueError('CURRENT_ID_NATIVE_VAULT_NETWORK_CHANGED')
        origin=await read(launcher)
        if origin.coin.puzzle_hash!=SINGLETON_LAUNCHER_HASH or origin.coin.amount!=1 or not origin.spent_height:
            raise ValueError('CURRENT_ID_NATIVE_VAULT_ORIGIN_UNCONFIRMED')
        spend=_spend(await provider.get_puzzle_and_solution_primary(h(launcher),origin.spent_height),origin.coin)
        additions,_=compute_additions_with_cost(spend,max_cost=5_000_000)
        odd=[coin for coin in additions if coin.amount%2]
        if len(odd)!=1 or odd[0].amount!=1:
            raise ValueError('CURRENT_ID_NATIVE_VAULT_LAUNCH_CHANGED')
        initial=await read(odd[0].name())
        if initial.coin!=odd[0] or initial.confirmed_height!=origin.spent_height or not initial.spent_height:
            raise ValueError('CURRENT_ID_NATIVE_FRESH_CHECK_REQUIRED')
        revealed=_spend(await provider.get_puzzle_and_solution_primary(h(initial.coin.name()),initial.spent_height),initial.coin)
        outer,arguments=Program.from_bytes(bytes(revealed.puzzle_reveal)).uncurry()
        values=list(arguments.as_iter())
        if len(values)!=2:
            raise ValueError('CURRENT_ID_NATIVE_VAULT_WRAPPER_CHANGED')
        module,inner_arguments=values[1].uncurry();fields=list(inner_arguments.as_iter())
        if module.get_tree_hash()!=bindings.vault_module or len(fields)!=9:
            raise ValueError('CURRENT_ID_NATIVE_VAULT_MODULE_CHANGED')
        owner,auth=fields[1].as_atom(),fields[2].as_int()
        expected=vault_inner(vault_launcher_id=launcher,owner_pubkey=owner,auth_type=auth,
            members_merkle_root=one_leaf_merkle_root(owner),pool_launcher_id=bindings.pool_launcher,
            zkpassport_bridge_policy_hash=bindings.bridge_policy)
        if bytes(revealed.puzzle_reveal)!=bytes(puzzle_for_singleton(launcher,expected)):
            raise ValueError('CURRENT_ID_NATIVE_VAULT_BINDINGS_CHANGED')
        result=await trace_current_customer_vault(bindings=bindings,launcher=launcher,owner_pubkey=owner,
            auth_type=auth,initial_coin=initial.coin,provider=provider)
        if not result.identity_verified or await read(launcher)!=origin:
            raise ValueError('CURRENT_ID_NATIVE_VAULT_PROOF_UNAVAILABLE')
        return result
