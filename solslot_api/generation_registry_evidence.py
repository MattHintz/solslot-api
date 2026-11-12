"""Bounded primary-node registry reconciliation for the generation indexer.

Invoke from an explicit refresh/background reconciler, not the cached status
GET. The frozen initial state supplies authority coordinates; the node supplies
confirmed parent spends. No latest module is selected by an API setting.
"""
import asyncio
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_registry import Registry
from solslot_puzzles.generation_registry_reader import reconstruct_registry_successor
from .vault_chain_evidence import ConfirmedVaultCoin, read_vault_coin

MAX_REGISTRY_HISTORY = 512
MAX_REVEAL_BYTES = 1_048_576


def _program(value):
    if not isinstance(value,str) or len(value)>MAX_REVEAL_BYTES*2+2:
        raise ValueError('registry evidence exceeds the reveal bound')
    raw=bytes.fromhex(value.removeprefix('0x'))
    program=Program.from_bytes(raw)
    if bytes(program)!=raw:
        raise ValueError('registry evidence is not canonical')
    return program


def _spend(raw,expected):
    if not isinstance(raw,dict) or Coin.from_json_dict(raw['coin'])!=expected:
        raise ValueError('registry spend does not match its confirmed input')
    puzzle,solution=_program(raw['puzzle_reveal']),_program(raw['solution'])
    if puzzle.get_tree_hash()!=expected.puzzle_hash:
        raise ValueError('registry reveal differs from its confirmed puzzle hash')
    return make_spend(expected,puzzle,solution)


@dataclass(frozen=True)
class RegistryEvidence:
    state: Registry
    current: ConfirmedVaultCoin
    transition_count: int


async def resolve_registry_tip(initial: Registry, *, provider) -> RegistryEvidence:
    """Reconstruct every current output from a locally frozen genesis anchor."""
    async with asyncio.timeout(20):
        if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
            raise ValueError('registry reconciliation requires the primary Testnet11 node')
        async def read(coin_id):
            return read_vault_coin(await provider.get_coin_record_by_name_primary('0x'+coin_id.hex()),coin_id)
        launcher=await read(initial.launcher_id)
        if launcher.coin.puzzle_hash!=SINGLETON_LAUNCHER_HASH or not launcher.spent_height:
            raise ValueError('registry launcher is not confirmed')
        spend=_spend(await provider.get_puzzle_and_solution_primary('0x'+initial.launcher_id.hex(),launcher.spent_height),launcher.coin)
        additions,_=compute_additions_with_cost(spend,max_cost=5_000_000)
        expected=Coin(initial.launcher_id,puzzle_for_singleton(initial.launcher_id,initial.inner()).get_tree_hash(),uint64(1))
        if [coin for coin in additions if coin.amount%2]!=[expected]:
            raise ValueError('registry launch differs from the frozen initial state')
        verified=[launcher]
        state=initial
        parent_height=launcher.spent_height
        for steps in range(MAX_REGISTRY_HISTORY+1):
            record=await read(expected.name())
            if record.coin!=expected or record.confirmed_height!=parent_height:
                raise ValueError('registry history lacks its exact confirmed continuation')
            verified.append(record)
            if not record.spent_height:
                # Detect concurrent spends and reorgs across the complete proof.
                for prior in verified:
                    if await read(prior.coin.name())!=prior:
                        raise ValueError('registry history changed during reconciliation')
                return RegistryEvidence(state,record,steps)
            if steps==MAX_REGISTRY_HISTORY:
                raise ValueError('registry history exceeds the reconciliation bound')
            spend=_spend(await provider.get_puzzle_and_solution_primary('0x'+record.coin.name().hex(),record.spent_height),record.coin)
            transition=reconstruct_registry_successor(spend,state)
            state,expected=transition.after,transition.successor
            parent_height=record.spent_height
    raise AssertionError('registry reconciliation did not return or fail')
