"""Scoped pre-genesis launch and cached progress, bound to one frozen manifest.

Only explicit preparation constructs/signs an exact reserved faucet spend.
Submission remains a separate approved action using the durable native fee path.
The observer proves custody after confirmation; it cannot build or submit.
"""
from __future__ import annotations

import asyncio
from hashlib import sha256
import time
from typing import Annotated

from chia_rs import Coin
from pydantic import BaseModel, ConfigDict, Field

from .generation_operations import canonical
from .generation_preparation import GenerationPreparation
from .generation_recipient_evidence import verify_single_recipient

Hash = Annotated[str, Field(pattern=r'^0x[0-9a-f]{64}$')]


class RecipientLaunchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', populate_by_name=True, frozen=True)
    generation_id: Hash = Field(alias='generationId')
    preparation_manifest: Hash = Field(alias='preparationManifest')
    administrator_slot: int = Field(alias='administratorSlot', strict=True, ge=1, le=3)
    funding_coin_id: Hash = Field(alias='fundingCoinId')
    recipient_vault: Hash = Field(alias='recipientVault')
    recipient_puzzle: Hash = Field(alias='recipientPuzzle')
    fee_cap_mojos: int = Field(alias='feeCapMojos', strict=True, ge=0, le=1_000_000_000)

    def document(self):
        return {**self.model_dump(mode='json', by_alias=True), 'kind':'CREATE_RECIPIENT_VAULT',
                'requestKey':recipient_request_key(self.preparation_manifest, self.administrator_slot)}

    @property
    def digest(self):
        return '0x'+sha256(canonical(self.document()).encode()).hexdigest()


def recipient_request_key(manifest: str, slot: int) -> str:
    return f'recipient:{manifest}:{slot}'


def validate_recipient_request(body: RecipientLaunchRequest, preparation, journal):
    admin = preparation.administrators[body.administrator_slot-1]
    if (body.generation_id != preparation.generation_id or body.generation_id != journal.generation_id
            or body.preparation_manifest != preparation.manifest_hash
            or body.funding_coin_id != admin.custody.funding_coin_id
            or body.recipient_vault != admin.custody.launcher_id
            or body.recipient_puzzle != admin.sgt_owner_puzzle_hash):
        raise ValueError('recipient review differs from the frozen assigned destination')


def recipient_operation(preparation, slot, journal):
    if journal is None:
        return None
    saved = journal.request_status(recipient_request_key(preparation.manifest_hash, slot))
    if saved is None:
        return None
    document = dict(saved.get('review') or {})
    kind, key = document.pop('kind', None), document.pop('requestKey', None)
    body = RecipientLaunchRequest.model_validate(document)
    validate_recipient_request(body, preparation, journal)
    if (kind != 'CREATE_RECIPIENT_VAULT' or saved['kind'] != kind
            or body.administrator_slot != slot or key != recipient_request_key(preparation.manifest_hash, slot)
            or int(saved['feeCapMojos']) != body.fee_cap_mojos):
        raise ValueError('saved recipient launch differs from its frozen review')
    return saved


def _funding_coin(raw, expected):
    if not isinstance(raw, dict) or not isinstance(raw.get('coin'), dict):
        raise ValueError('reserved recipient funding coin is unavailable')
    fields = raw['coin']
    if (type(fields.get('amount')) is not int or not 1 <= fields['amount'] < 2**64
            or type(raw.get('confirmed_block_index')) is not int or raw['confirmed_block_index'] <= 0
            or type(raw.get('spent_block_index')) is not int or raw['spent_block_index'] != 0
            or ('spent' in raw and raw['spent'] is not False)):
        raise ValueError('reserved recipient parent must be confirmed and unspent')
    coin = Coin.from_json_dict(fields)
    if '0x'+coin.name().hex() != expected:
        raise ValueError('primary record does not identify the reserved recipient parent')
    return coin


async def prepare_recipient_launch(body, *, preparation, provider, faucet, journal, clock=time.time):
    body = RecipientLaunchRequest.model_validate_json(body.model_dump_json(by_alias=True))
    frozen = GenerationPreparation.model_validate_json(preparation.model_dump_json(by_alias=True))
    validate_recipient_request(body, frozen, journal)
    saved = journal.reviewed_request(recipient_request_key(frozen.manifest_hash, body.administrator_slot), body.digest)
    if saved:
        return recipient_operation(frozen, body.administrator_slot, journal)
    async with asyncio.timeout(20):
        if (await provider.get_network_info_primary()).get('network_name') != 'testnet11':
            raise ValueError('recipient launch requires the primary Testnet11 node')
        before = await provider.get_coin_record_by_name_primary(body.funding_coin_id)
        coin = _funding_coin(before, body.funding_coin_id)
        after = await provider.get_coin_record_by_name_primary(body.funding_coin_id)
        if before != after:
            raise ValueError('reserved recipient parent changed during review')
        # No external await between the scoped signature and durable save.
        operation = faucet.sign_generation_recipient(coin, body.administrator_slot,
            preparation_manifest=frozen.manifest_hash)
        journal.prepare(operation, recipient_request_key(frozen.manifest_hash, body.administrator_slot),
            body.fee_cap_mojos, int(clock()), request_digest=body.digest, request_document=body.document())
    return recipient_operation(frozen, body.administrator_slot, journal)


class GenerationRecipientObserver:
    def __init__(self, store, journal, provider, *, clock=time.time):
        self.store, self.journal, self.provider, self.clock = store, journal, provider, clock

    async def run_once(self):
        active = False
        for recipient in self.store.review(int(self.clock()))['recipients']:
            slot = recipient['administratorSlot']
            saved = recipient_operation(self.store.preparation, slot, self.journal)
            if saved is None or not saved['transactionId'] or recipient['confirmed']:
                continue
            active = True
            if saved['stage'] != 'CONFIRMED':
                continue
            try:
                receipt = await verify_single_recipient(self.store.preparation, slot,
                    trusted_preparation_hash=self.store.preparation.manifest_hash, provider=self.provider)
                self.store.record_confirmation(receipt, int(self.clock()))
            except (ValueError, KeyError, TypeError):
                self.store.record_error(slot, 'RECIPIENT_NOT_CONFIRMED', int(self.clock()))
            except (OSError, TimeoutError, RuntimeError):
                self.store.record_error(slot, 'NODE_UNAVAILABLE', int(self.clock()))
        return active
