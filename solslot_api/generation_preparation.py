"""Constrained pre-genesis coordinates and exact recipient acknowledgements.

This is preparation, never authority to broadcast. The final issuance builder
must consume confirmed custody evidence and all three acknowledgements. Names
are for administrator review; signer identities and destinations are committed.
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from chia.types.blockchain_format.coin import Coin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .generation_context import generation_bytes
from solslot_puzzles.generation_vault import vault_inner, sgt_owner
from solslot_puzzles.vault_driver import one_leaf_merkle_root, validate_owner_pubkey_for_auth_type
from solslot_puzzles.admin_authority_v3_driver import authority_v3_launcher_ids

SOURCE_KEYS = frozenset({'protocol','evm','omnichain','api','legacyBackend','keyOfSolomon','samuel','customerWeb','adminPortal'})
COORDINATE_KEYS = frozenset({'authority','registry','governance','holdings','pool','parameters','mint'})


def commitment(value: dict) -> str:
    return '0x'+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


class PreparationModel(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True,populate_by_name=True)


class ReservedCoordinate(PreparationModel):
    funding_coin_id: str = Field(alias='fundingCoinId',pattern=r'^0x[0-9a-f]{64}$')
    launcher_id: str = Field(alias='launcherId',pattern=r'^0x[0-9a-f]{64}$')

    @model_validator(mode='after')
    def derived_launcher(self):
        generation_bytes(self.funding_coin_id)
        expected = Coin(bytes32.from_hexstr(self.funding_coin_id),SINGLETON_LAUNCHER_HASH,uint64(1)).name()
        if self.launcher_id != '0x'+expected.hex():
            raise ValueError('reserved launcher does not match its committed funding coin')
        return self


class PreparationAdministrator(PreparationModel):
    slot: int = Field(ge=1,le=3,strict=True)
    name: str = Field(min_length=1,max_length=100)
    wallet: str = Field(pattern=r'^0x[0-9a-f]{40}$')
    identity_authority_launcher: str = Field(alias='identityAuthorityLauncher',pattern=r'^0x[0-9a-f]{64}$')
    recovery_drill_hash: str = Field(alias='recoveryDrillHash',pattern=r'^0x[0-9a-f]{64}$')
    custody_owner_public_key: str = Field(alias='custodyOwnerPublicKey',pattern=r'^0x[0-9a-f]{66,130}$')
    custody_auth_type: Literal[1,2,3] = Field(alias='custodyAuthType')
    custody: ReservedCoordinate
    custody_inner_hash: str = Field(alias='custodyInnerHash',pattern=r'^0x[0-9a-f]{64}$')
    sgt_owner_puzzle_hash: str = Field(alias='sgtOwnerPuzzleHash',pattern=r'^0x[0-9a-f]{64}$')
    initial_sgt: Literal[10000] = Field(default=10000,alias='initialSgt')

    @field_validator('custody_auth_type', mode='before')
    @classmethod
    def strict_auth_type(cls, value):
        if type(value) is not int:
            raise ValueError('custody auth type must be an integer')
        return value

    @model_validator(mode='after')
    def distinct_custody(self):
        if type(self.custody_auth_type) is not int:
            raise ValueError('custody auth type must be an integer')
        validate_owner_pubkey_for_auth_type(bytes.fromhex(self.custody_owner_public_key[2:]),self.custody_auth_type)
        for value in (self.identity_authority_launcher,self.recovery_drill_hash,self.custody_inner_hash,self.sgt_owner_puzzle_hash):
            generation_bytes(value)
        if self.wallet == '0x'+'00'*20:
            raise ValueError('administrator wallet must be nonzero')
        if self.custody.launcher_id == self.identity_authority_launcher:
            raise ValueError('SGT custody vault is distinct from administrator identity authority')
        return self


class GenerationPreparation(PreparationModel):
    schema_version: Literal[1] = Field(default=1,alias='schemaVersion')
    purpose: Literal['SGT_VAULT_PREPARATION'] = 'SGT_VAULT_PREPARATION'
    generation_id: str = Field(alias='generationId',pattern=r'^0x[0-9a-f]{64}$')
    network: Literal['testnet11'] = 'testnet11'
    source_commits: dict[str,str] = Field(alias='sourceCommits')
    coordinates: dict[str,ReservedCoordinate]
    sgt_funding_coin_id: str = Field(alias='sgtFundingCoinId',pattern=r'^0x[0-9a-f]{64}$')
    reserve_owner_puzzle_hash: str = Field(alias='reserveOwnerPuzzleHash',pattern=r'^0x[0-9a-f]{64}$')
    bridge_policy_hash: str = Field(alias='bridgePolicyHash',pattern=r'^0x[0-9a-f]{64}$')
    administrators: tuple[PreparationAdministrator,PreparationAdministrator,PreparationAdministrator]

    @field_validator('source_commits')
    @classmethod
    def frozen_sources(cls, value):
        import re
        if set(value) != SOURCE_KEYS or any(not re.fullmatch(r'[0-9a-f]{40}',sha) or sha == '0'*40 for sha in value.values()):
            raise ValueError('all nine exact source commits are required')
        return value

    @model_validator(mode='after')
    def reserved_plan(self):
        generation_bytes(self.generation_id)
        for v in (self.sgt_funding_coin_id,self.reserve_owner_puzzle_hash,self.bridge_policy_hash):
            generation_bytes(v)
        if set(self.coordinates) != COORDINATE_KEYS:
            raise ValueError('exact protocol coordinate set is required')
        if tuple(a.slot for a in self.administrators) != (1,2,3):
            raise ValueError('three ordered administrators are required')
        authority, *identities = authority_v3_launcher_ids(
            bytes32.from_hexstr(self.coordinates['authority'].funding_coin_id))
        if (self.coordinates['authority'].launcher_id != '0x'+authority.hex()
                or tuple(a.identity_authority_launcher for a in self.administrators)
                != tuple('0x'+identity.hex() for identity in identities)):
            raise ValueError('administrator identity authorities must derive from the reserved authority funding coin')
        for field in ('wallet','identity_authority_launcher','sgt_owner_puzzle_hash'):
            if len({getattr(a,field) for a in self.administrators}) != 3:
                raise ValueError('administrator identities and recipients must be distinct')
        reservations = [*self.coordinates.values(),*(a.custody for a in self.administrators)]
        if len({c.funding_coin_id for c in reservations}) != len(reservations):
            raise ValueError('reserved funding coins cannot be reused')
        if self.sgt_funding_coin_id in {c.funding_coin_id for c in reservations}:
            raise ValueError('SGT issuance funding cannot reuse a reserved launcher parent')
        identities = {a.identity_authority_launcher for a in self.administrators}
        if any(c.launcher_id in identities for c in reservations):
            raise ValueError('identity authority cannot substitute for protocol or custody coordinates')
        for admin in self.administrators:
            inner=self.custody_inner(admin)
            owner=sgt_owner(bytes32.from_hexstr(self.generation_id),bytes32.from_hexstr(admin.custody.launcher_id))
            if ('0x'+inner.get_tree_hash().hex()!=admin.custody_inner_hash
                    or '0x'+owner.get_tree_hash().hex()!=admin.sgt_owner_puzzle_hash):
                raise ValueError('recipient commitments do not match the canonical custody vault and generation')
            if admin.sgt_owner_puzzle_hash==self.reserve_owner_puzzle_hash:
                raise ValueError('administrator custody cannot be the nonvoting reserve')
        return self

    def custody_inner(self, admin: PreparationAdministrator):
        owner=bytes.fromhex(admin.custody_owner_public_key[2:])
        return vault_inner(vault_launcher_id=bytes32.from_hexstr(admin.custody.launcher_id),
            owner_pubkey=owner,auth_type=admin.custody_auth_type,members_merkle_root=one_leaf_merkle_root(owner),
            pool_launcher_id=bytes32.from_hexstr(self.coordinates['pool'].launcher_id),
            zkpassport_bridge_policy_hash=bytes32.from_hexstr(self.bridge_policy_hash))

    @property
    def manifest_hash(self) -> str:
        return commitment(self.model_dump(mode='json',by_alias=True))

    def acknowledgement(self, slot: int) -> dict:
        if type(slot) is not int or slot not in (1,2,3):
            raise ValueError('administrator slot must be 1, 2 or 3')
        admin=self.administrators[slot-1]
        return {
            'types': {
                'EIP712Domain':[{'name':'name','type':'string'},{'name':'version','type':'string'},
                    {'name':'salt','type':'bytes32'}],
                'SolslotSGTRecipient':[{'name':'preparationManifest','type':'bytes32'},
                    {'name':'network','type':'string'},{'name':'administratorSlot','type':'uint8'},
                    {'name':'identityAuthority','type':'bytes32'},{'name':'recipientVault','type':'bytes32'},
                    {'name':'recipientPuzzle','type':'bytes32'},{'name':'amount','type':'uint64'}]},
            'primaryType':'SolslotSGTRecipient',
            'domain':{'name':'Solslot SGT recipient','version':'1','salt':self.generation_id},
            'message':{'preparationManifest':self.manifest_hash,'network':self.network,
                'administratorSlot':slot,'identityAuthority':admin.identity_authority_launcher,
                'recipientVault':admin.custody.launcher_id,'recipientPuzzle':admin.sgt_owner_puzzle_hash,
                'amount':10000}}

    def verify_acknowledgements(self, signatures: dict[int,str]) -> None:
        if set(signatures) != {1,2,3} or any(type(k) is not int for k in signatures):
            raise ValueError('all three destination acknowledgements are required')
        for admin in self.administrators:
            self.verify_acknowledgement(admin.slot, signatures[admin.slot])

    def verify_acknowledgement(self, slot: int, signature: str) -> None:
        typed_data=self.acknowledgement(slot)
        signer=Account.recover_message(encode_typed_data(full_message=typed_data),signature=signature)
        if signer.lower()!=self.administrators[slot-1].wallet:
            raise ValueError('destination acknowledgement does not match administrator and frozen preparation')

    def review(self) -> dict:
        # Derive display amounts from the same committed entries as signing.
        return {'generationId':self.generation_id,'network':self.network,'preparationManifest':self.manifest_hash,
            'holderSupply':30000,'reserveSupply':970000,'totalSupply':1000000,'initialQuorum':15000,
            'recipients':[{'administratorSlot':a.slot,'name':a.name,'wallet':a.wallet,
                'identityAuthority':a.identity_authority_launcher,'recipientVault':a.custody.launcher_id,
                'recipientPuzzle':a.sgt_owner_puzzle_hash,'fundingCoinId':a.custody.funding_coin_id,
                'amount':a.initial_sgt} for a in self.administrators]}
