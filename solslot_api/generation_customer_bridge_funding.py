"""Fresh finite bridge coins for current-generation private ID checks.

This deterministic native builder never selects a key, reserves inputs or
broadcasts. Ephemeral owned parents make each one-mojo bridge coin unique.
Earlier-generation bridge reservations are neither read nor reused.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD,solution_for_conditions
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL,Coin,G1Element,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_transactions import NativeOperation
from .faucet import AGG_SIG_ME_DATA


@dataclass(frozen=True)
class CurrentIdentityBridgePlan:
    bindings:object
    funding_coin:Coin
    funding_public_key:bytes
    count:int
    issued_at:int
    expires_at:int

    def validate(self,now):
        self.bindings.validate()
        if (not isinstance(self.funding_coin,Coin) or not 1<int(self.funding_coin.amount)<=20_000_000_000
                or not isinstance(self.funding_public_key,bytes) or len(self.funding_public_key)!=48
                or type(self.count)is not int or not 1<=self.count<=16
                or type(now)is not int or type(self.issued_at)is not int or type(self.expires_at)is not int
                or not 0<self.issued_at<=now<self.expires_at<=self.issued_at+172800):
            raise ValueError('CURRENT_ID_BRIDGE_PLAN_UNAVAILABLE')
        public=G1Element.from_bytes(self.funding_public_key)
        if public==G1Element():raise ValueError('CURRENT_ID_BRIDGE_FUNDING_KEY_INVALID')
        puzzle=Program.from_bytes(bytes(MOD)).curry(public)
        required=sum(range(2,self.count+2))
        if self.funding_coin.puzzle_hash!=puzzle.get_tree_hash() or self.funding_coin.amount<=required:
            raise ValueError('CURRENT_ID_BRIDGE_EXACT_FUNDING_CHANGED')
        return puzzle

    def operation(self,now):
        puzzle=self.validate(now)
        # Different ephemeral amounts produce different parent coin IDs. The
        # final bridge coins all have the immutable policy and amount one.
        children=[Coin(self.funding_coin.name(),puzzle.get_tree_hash(),uint64(i+2)) for i in range(self.count)]
        change=int(self.funding_coin.amount)-sum(int(c.amount) for c in children)
        message=Program.to([b'CURRENT_CUSTOMER_ID_BRIDGES_V1',self.bindings.generation,
            self.bindings.preparation_manifest,self.bindings.pool_launcher,self.bindings.vault_module,
            self.bindings.bridge_policy,self.funding_coin.name(),self.count,
            self.issued_at,self.expires_at]).get_tree_hash()
        first=make_spend(self.funding_coin,puzzle,solution_for_conditions(
            [[51,c.puzzle_hash,int(c.amount)] for c in children]+[[51,puzzle.get_tree_hash(),change],
                [60,message],[85,self.expires_at]]+[[64,c.name()]for c in children]))
        others=[make_spend(c,puzzle,solution_for_conditions([[51,self.bindings.bridge_policy,1],
            [51,puzzle.get_tree_hash(),int(c.amount)-1]])) for c in children]
        operation=NativeOperation(self.bindings.generation,'FUND_CURRENT_CUSTOMER_ID_BRIDGES',(first,*others),())
        coins=tuple(Coin(c.name(),self.bindings.bridge_policy,uint64(1)) for c in children)
        created=[c for spend in operation.spends for c in compute_additions(spend)]
        external=[c for c in created if c.name() not in {s.coin.name() for s in operation.spends}]
        if (len({c.name() for c in coins})!=self.count or any(c not in external for c in coins)
                or sum(int(c.amount) for c in external)!=self.funding_coin.amount
                or any(c.puzzle_hash not in (puzzle.get_tree_hash(),self.bindings.bridge_policy) for c in external)):
            raise ValueError('CURRENT_ID_BRIDGE_OUTPUTS_CHANGED')
        return operation,coins

    def review(self,now):
        operation,coins=self.operation(now)
        value={'schema':'solslot.current-customer-id-bridge-funding.v1','network':'testnet11',
            'generationId':'0x'+self.bindings.generation.hex(),
            'preparationManifest':'0x'+self.bindings.preparation_manifest.hex(),
            'fundingCoinId':'0x'+self.funding_coin.name().hex(),'fundingPuzzleHash':'0x'+self.funding_coin.puzzle_hash.hex(),
            'bridgePolicyHash':'0x'+self.bindings.bridge_policy.hex(),
            'newBridgeCoins':[{'parentId':'0x'+c.parent_coin_info.hex(),'coinId':'0x'+c.name().hex(),'amount':1} for c in coins],
            'bridgeCount':self.count,'fundingChangeMojos':str(int(self.funding_coin.amount)-self.count),
            'issuedAt':self.issued_at,'expiresAt':self.expires_at,'protocolBundleId':'0x'+operation.bundle().name().hex(),
            'earlierBridgeReservationsReused':False,'networkFeesIncluded':False}
        return {**value,'reviewHash':'0x'+sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

    def sign(self,*,now,sign_message):
        """Scoped callback signs only the exact reconstructed native messages."""
        operation,_=self.operation(now);signatures=[]
        for spend in operation.spends:
            conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
            pairs=pkm_pairs_for_conditions_dict(conditions,spend.coin,AGG_SIG_ME_DATA['testnet11'])
            if len(pairs)!=1 or bytes(pairs[0][0])!=self.funding_public_key:
                raise ValueError('CURRENT_ID_BRIDGE_SIGNATURE_SCOPE_CHANGED')
            public,message=pairs[0];signature=G2Element.from_bytes(bytes(sign_message(bytes(message))))
            if not AugSchemeMPL.verify(public,bytes(message),signature):
                raise ValueError('CURRENT_ID_BRIDGE_SIGNATURE_INVALID')
            signatures.append(signature)
        return SpendBundle(list(operation.spends),AugSchemeMPL.aggregate(signatures))
