"""Current custody proofs for explicit holder reviews, never status polling.

An anchor is the frozen initial custody policy, never a coordinator-selected
current puzzle. Follow confirmed supported key/identity transitions from that
anchor; preserve the module, launcher, pool and bridge bindings throughout.
New enrollment still needs its own frozen initial evidence.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_transactions import MAX_NATIVE_COST
from solslot_puzzles.generation_vault import sgt_owner
from .generation_chain_evidence import _history


@dataclass(frozen=True)
class HolderCustodyAnchor:
    generation:bytes32
    launcher_id:bytes32
    inner:Program
    pool_id:bytes32
    bridge_policy_hash:bytes32

    def fields(self,inner=None):
        inner=self.inner if inner is None else inner
        mod,args=inner.uncurry();v=list(args.as_iter())
        if (self.generation==bytes32.zeros or self.launcher_id==bytes32.zeros
                or self.pool_id==bytes32.zeros
                or mod.get_tree_hash()!=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash()
                or len(v)!=9 or Program.to(v)!=args or v[0]!=singleton_struct(self.launcher_id)
                or v[2].as_int() not in (1,3) or v[3].as_atom()!=Program.to(v[1].as_atom()).get_tree_hash()
                or v[5].as_atom()!=self.bridge_policy_hash or v[7].as_atom()!=self.pool_id):
            raise ValueError('holder custody requires a frozen supported single-owner generation policy')
        from solslot_puzzles.generation_vault import vault_inner
        expected=vault_inner(vault_launcher_id=self.launcher_id,owner_pubkey=v[1].as_atom(),auth_type=v[2].as_int(),
            members_merkle_root=bytes32(v[3].as_atom()),identity_attest_root=bytes32(v[4].as_atom()),
            pool_launcher_id=self.pool_id,zkpassport_bridge_policy_hash=self.bridge_policy_hash)
        if expected!=inner:raise ValueError('holder custody bindings differ from canonical vault construction')
        return v

    @property
    def owner(self):return sgt_owner(self.generation,self.launcher_id).get_tree_hash()


def preparation_custody_anchors(preparation):
    return tuple(HolderCustodyAnchor(bytes32.from_hexstr(preparation.generation_id),
        bytes32.from_hexstr(a.custody.launcher_id),preparation.custody_inner(a),
        bytes32.from_hexstr(preparation.coordinates['pool'].launcher_id),
        bytes32.from_hexstr(preparation.bridge_policy_hash)) for a in preparation.administrators)


async def resolve_holder_custody(anchor,*,provider):
    anchor.fields()
    def successor(inner,spend):
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
        from chia.types.blockchain_format.coin import Coin
        from chia_rs.sized_ints import uint64
        from solslot_puzzles.generation_registry_reader import exact_list,uint
        fields=anchor.fields(inner)
        if Program.from_bytes(bytes(spend.puzzle_reveal))!=puzzle_for_singleton(anchor.launcher_id,inner):
            raise ValueError('custody continuation changed its verified policy')
        _,amount,raw=exact_list(Program.from_bytes(bytes(spend.solution)),3)
        identity,inner_hash,vault_amount,action,args=exact_list(raw,5)
        if (uint(amount)!=1 or uint(vault_amount)!=1 or identity.as_atom()!=spend.coin.name()
                or inner_hash.as_atom()!=inner.get_tree_hash()):
            raise ValueError('custody continuation identifies another input')
        next_fields=list(fields);tag=action.as_atom()
        if tag==b'k':
            module,key,auth,members,_,_,_=exact_list(args,7)
            if module.as_atom()!=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash():
                raise ValueError('key rotation cannot replace the frozen vault module')
            next_fields[1:4]=[key,Program.to(uint(auth)),members]
        elif tag==b'z':
            module,identity_root,_,_,_,_=exact_list(args,6)
            if module.as_atom()!=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash():
                raise ValueError('identity stamp cannot replace the frozen vault module')
            next_fields[4]=identity_root
        elif tag not in (b'o',b'i',b'a',b's',b'd',b'v',b'g',b'm',b't'):
            raise ValueError('unsupported custody transition')
        next_inner=load_puzzle('vault_singleton_inner_generation_v1.clsp').curry(*next_fields)
        anchor.fields(next_inner)
        # Execute the confirmed puzzle, rather than trusting a projected child
        # or taking a caller's proposed key/credential as current authority.
        additions,_=compute_additions_with_cost(spend,max_cost=MAX_NATIVE_COST)
        child=Coin(spend.coin.name(),puzzle_for_singleton(anchor.launcher_id,next_inner).get_tree_hash(),uint64(1))
        if additions!=[child]:raise ValueError('custody output differs from its supported transition')
        return next_inner,child,tag.decode('ascii')
    history=await _history(provider,anchor.launcher_id,anchor.inner,lambda v:v,successor)
    return history
