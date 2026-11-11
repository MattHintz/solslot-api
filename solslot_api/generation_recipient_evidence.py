"""Read-only primary-node proof of the three frozen pre-genesis recipients.

This proves custody and destination consent, not overall launch readiness.
Release/source/recovery admission and the explicit broadcast envelope remain
separate requirements. Never call a transaction builder from a status read.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_sgt import GenesisIssuancePlan
from .generation_preparation import GenerationPreparation
from .vault_chain_evidence import read_vault_coin


@dataclass(frozen=True)
class ConfirmedRecipient:
    slot: int
    launcher_id: bytes32
    coin_id: bytes32
    owner_puzzle_hash: bytes32
    confirmed_height: int


@dataclass(frozen=True)
class RecipientEvidence:
    generation_id: bytes32
    preparation_manifest_hash: bytes32
    recipients: tuple[ConfirmedRecipient, ...]


def _program(value) -> Program:
    if not isinstance(value,str) or len(value)>8194:
        raise ValueError('recipient launcher reveal exceeds the evidence bound')
    raw=bytes.fromhex(value.removeprefix('0x'))
    program=Program.from_bytes(raw)
    if not raw or bytes(program)!=raw:
        raise ValueError('recipient launcher reveal is noncanonical')
    return program


async def verify_recipient_custody(preparation: GenerationPreparation, signatures: dict[int,str],
                                   *, trusted_preparation_hash: str, provider) -> RecipientEvidence:
    preparation.verify_acknowledgements(dict(signatures))
    return await _verify_custody(preparation,(1,2,3),trusted_preparation_hash=trusted_preparation_hash,provider=provider)


async def verify_single_recipient(preparation: GenerationPreparation, slot: int,
                                   *, trusted_preparation_hash: str, provider) -> ConfirmedRecipient:
    if type(slot) is not int or slot not in (1,2,3):
        raise ValueError('recipient slot must be 1, 2 or 3')
    evidence=await _verify_custody(preparation,(slot,),trusted_preparation_hash=trusted_preparation_hash,provider=provider)
    return evidence.recipients[0]


async def _verify_custody(preparation: GenerationPreparation, slots: tuple[int,...],
                          *, trusted_preparation_hash: str, provider) -> RecipientEvidence:
    # Detach mutable maps before the first await; a provider/caller cannot
    # change the reviewed destination or source map during evidence reads.
    frozen=GenerationPreparation.model_validate_json(preparation.model_dump_json(by_alias=True))
    if frozen.manifest_hash!=trusted_preparation_hash:
        raise ValueError('preparation differs from the locally frozen reviewed manifest')
    async with asyncio.timeout(20):
        network=await provider.get_network_info_primary()
        if network.get('network_name')!='testnet11':
            raise ValueError('recipient evidence requires the primary Testnet11 node')
        receipts, initial_records=[] , []
        for admin in frozen.administrators:
            if admin.slot not in slots:
                continue
            launcher_id=bytes32.from_hexstr(admin.custody.launcher_id)
            launcher=read_vault_coin(await provider.get_coin_record_by_name_primary(admin.custody.launcher_id),launcher_id)
            if (launcher.coin.puzzle_hash!=SINGLETON_LAUNCHER_HASH
                    or launcher.coin.parent_coin_info!=bytes32.from_hexstr(admin.custody.funding_coin_id)
                    or not launcher.spent_height):
                raise ValueError('recipient launcher is not the confirmed reserved launch')
            full=puzzle_for_singleton(launcher_id,frozen.custody_inner(admin))
            expected=Coin(launcher_id,full.get_tree_hash(),uint64(1))
            child=read_vault_coin(await provider.get_coin_record_by_name_primary('0x'+expected.name().hex()),expected.name())
            if child.coin!=expected or child.spent_height or child.confirmed_height!=launcher.spent_height:
                raise ValueError('recipient must be the confirmed, unused reserved custody vault')
            raw=await provider.get_puzzle_and_solution_primary(admin.custody.launcher_id,launcher.spent_height)
            if not isinstance(raw,dict) or Coin.from_json_dict(raw['coin'])!=launcher.coin:
                raise ValueError('recipient launcher spend does not match the confirmed input')
            puzzle,solution=_program(raw['puzzle_reveal']),_program(raw['solution'])
            if puzzle.get_tree_hash()!=SINGLETON_LAUNCHER_HASH:
                raise ValueError('recipient uses an unrecognized launcher')
            additions,cost=compute_additions_with_cost(make_spend(launcher.coin,puzzle,solution),max_cost=5_000_000)
            if cost>5_000_000 or [c for c in additions if c.amount%2]!=[expected]:
                raise ValueError('launcher execution does not create the frozen recipient vault')
            receipts.append(ConfirmedRecipient(admin.slot,launcher_id,expected.name(),
                bytes32.from_hexstr(admin.sgt_owner_puzzle_hash),child.confirmed_height))
            initial_records.extend([launcher,child])
        # A reorg or concurrent spend invalidates the complete admission.
        for before in initial_records:
            after=read_vault_coin(await provider.get_coin_record_by_name_primary('0x'+before.coin.name().hex()),before.coin.name())
            if before!=after:
                raise ValueError('recipient confirmation changed during verification')
        return RecipientEvidence(bytes32.from_hexstr(frozen.generation_id),
            bytes32.from_hexstr(frozen.manifest_hash),tuple(receipts))


def issuance_plan_from_recipients(preparation: GenerationPreparation, evidence: RecipientEvidence) -> GenesisIssuancePlan:
    """Explicit builder, never part of verify/status. Reverify before dispatch."""
    if (evidence.generation_id!=bytes32.from_hexstr(preparation.generation_id)
            or evidence.preparation_manifest_hash!=bytes32.from_hexstr(preparation.manifest_hash)
            or tuple(r.slot for r in evidence.recipients)!=(1,2,3)):
        raise ValueError('recipient evidence is for another frozen preparation')
    for admin,receipt in zip(preparation.administrators,evidence.recipients):
        if (receipt.launcher_id!=bytes32.from_hexstr(admin.custody.launcher_id)
                or receipt.owner_puzzle_hash!=bytes32.from_hexstr(admin.sgt_owner_puzzle_hash)):
            raise ValueError('recipient evidence changed destination')
    return GenesisIssuancePlan(bytes32.from_hexstr(preparation.sgt_funding_coin_id),evidence.generation_id,
        bytes32.from_hexstr(preparation.coordinates['holdings'].launcher_id),
        bytes32.from_hexstr(preparation.coordinates['governance'].launcher_id),
        bytes32.from_hexstr(preparation.reserve_owner_puzzle_hash),
        tuple(r.owner_puzzle_hash for r in evidence.recipients),evidence.preparation_manifest_hash)
