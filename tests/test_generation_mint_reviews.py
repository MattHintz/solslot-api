"""Confirmed synthetic funding, sealed source, offline retries and held parents."""
import asyncio
from copy import deepcopy
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_api.collection_store import CollectionStore, CollectionStoreError
from solslot_api.config import Settings
from solslot_api.faucet import FaucetSelectionRestricted
from solslot_api.generation_mint_reviews import MintReviewRequest, GenerationMintReviewStore, prepare_mint_review, h
from solslot_api.generation_storage import GenerationRetentionFull
from solslot_api.payment_quotes import parse_authorized_oracle_round
from solslot_api.test_collection_metadata import TestPropertyDraftV1
from tests.test_generation_genesis_core import core
from tests.test_generation_consents import initialized
from tests.test_collection_generation_mint import review_and_seal
from tests.test_payment_quotes import _snapshot
from tests.test_testnet_collection_edition import edition


async def context(c, tmp_path, *, initialized_generation=None):
    built, chain = initialized_generation if initialized_generation is not None else await initialized(c)
    acs = Program.to(1)
    origin = next(r.coin for r in await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent)
    conditions = [[51,c.faucet.address_puzzle_hash,i] for i in range(2,27)]
    conditions.append([51,acs.get_tree_hash(),int(origin.amount)-sum(range(2,27))])
    assert await c.client.push_tx(SpendBundle([make_spend(origin,acs,Program.to(conditions))],G2Element())) == (MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    async def catalog(ph,include_spent=False):
        return [r.to_json_dict() for r in await c.client.get_coin_records_by_puzzle_hash(bytes32.from_hexstr(ph)) if include_spent or not r.spent]
    c.provider.get_coin_records_by_puzzle_hash_primary = catalog
    payload = edition();payload['generationId'] = c.prep.generation_id
    from solslot_puzzles.generation_mint import GenerationMint
    mint = next(s for s in built.anchor.economic_components if isinstance(s, GenerationMint))
    payload['offering']['royaltyPuzhash'] = h(mint.treasury_puzzle_hash)
    collections = CollectionStore(tmp_path/'collections.db', generation_id=c.prep.generation_id)
    cid = payload['collectionId']
    collections.create(collection_id=cid,title=payload['title'],owner_subject='owner',owner_auth_type='evm',initial_draft=TestPropertyDraftV1.model_validate(payload))
    keys,_,raw = _snapshot(int(time.time()))
    settings = Settings(_env_file=None,runtime_environment='test',deployment_generation_id=c.prep.generation_id,
        faucet_max_spend_mojos=1000,payment_oracle_operator_pubkeys=[h(bytes(k.get_g1())) for k in keys])
    collections.apply_test_pricing(cid,expected_revision=1,actor_subject='owner',authorized=parse_authorized_oracle_round(settings,raw['rounds'][0]))
    sealed = review_and_seal(collections,cid)
    request = MintReviewRequest.model_validate(dict(generationId=c.prep.generation_id,collectionId=cid,
        revision=sealed['revision'],metadataRoot=sealed['metadataRoot'],previewHash=sealed['draftHash']))
    store = GenerationMintReviewStore(tmp_path/'mint-reviews.db',c.prep.generation_id)
    c.faucet.add_coin_reservation_source(store.reserved_input_coin_ids)
    return SimpleNamespace(request=request,store=store,collections=collections,chain=chain,settings=settings,
        kwargs=dict(settings=settings,collections=collections,anchor=built.anchor,provider=c.provider,faucet=c.faucet,
            store=store,funding_guard=asyncio.Lock(),clock=lambda:int(c.sim.timestamp)))


@pytest.mark.asyncio
async def test_sealed_batch_fixed_parents_restart_and_no_signatures_or_dispatch(core,tmp_path,monkeypatch):
    c=core;ctx=await context(c,tmp_path)
    monkeypatch.setattr(c.faucet,'sign_delegated_spend',lambda *a,**k:pytest.fail('source review cannot sign'))
    audit = ctx.collections.audit_events(ctx.request.collection_id)
    review = await prepare_mint_review(ctx.request,**ctx.kwargs)
    assert review['purpose']=='TEST_ONLY' and review['stage']=='SOURCE_REVIEWED' and review['publicationReady'] is False
    assert len(review['funding'])==25 and len({r['launcherId'] for r in review['funding']})==25
    assert len({r['inventoryCoinId'] for r in review['funding']})==25
    assert review['canonicalMetadata']['offering']['targetRaiseMinor']=='7500000'
    assert 'privateDocuments' not in review['canonicalMetadata']
    assert c.faucet.reserved_coin_ids()=={bytes32.from_hexstr(r['coinId']) for r in review['funding']}
    for row in review['funding']:
        assert (await c.client.get_coin_record_by_name(bytes32.from_hexstr(row['coinId']))).spent is False
        with pytest.raises(FaucetSelectionRestricted):c.faucet.require_unreserved_coin((await c.client.get_coin_record_by_name(bytes32.from_hexstr(row['coinId']))).coin)
    before=Path(ctx.store.path).read_bytes()
    restored=GenerationMintReviewStore(ctx.store.path,c.prep.generation_id)
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('retry must be cached')))
    for _ in range(5):
        assert await prepare_mint_review(ctx.request,**{**ctx.kwargs,'store':restored,'provider':offline})==review
        assert restored.for_collection(ctx.request.collection_id)==review
    assert Path(ctx.store.path).read_bytes()==before
    assert ctx.collections.audit_events(ctx.request.collection_id)==audit
    assert restored.reserved_input_coin_ids()==ctx.store.reserved_input_coin_ids()
    for field,value in [('revision',99),('metadata_root','0x'+'99'*32),('preview_hash','0x'+'99'*32)]:
        with pytest.raises(ValueError,match='saved sealed'):
            await prepare_mint_review(ctx.request.model_copy(update={field:value}),**{**ctx.kwargs,'provider':offline})
    # Case aliases hash to the same native collection. Even with different
    # funding rows they cannot reserve a competing edition in another writer.
    alias=ctx.request.model_copy(update={'collection_id':ctx.request.collection_id.lower()})
    if alias.collection_id!=ctx.request.collection_id:
        duplicate={k:deepcopy(v) for k,v in review.items() if k!='packageId'}
        duplicate['request']=alias.model_dump(mode='json',by_alias=True);duplicate['requestDigest']=alias.digest
        for i,row in enumerate(duplicate['funding']):row['coinId']='0x'+format(i+100,'064x')
        with pytest.raises(ValueError,match='canonical collection'):restored.save(alias,duplicate)
        assert len(restored.reserved_input_coin_ids())==25 and restored.for_collection(alias.collection_id) is None
    if target:=os.environ.get('GENERATION_MINT_REVIEW_VECTOR'):
        Path(target).write_text(json.dumps(review,indent=2)+'\n')
    with restored._db(write=True) as db:db.execute('DELETE FROM generation_mint_parent_holds WHERE coin_id=?',(review['funding'][0]['coinId'],))
    with pytest.raises(ValueError,match='holds changed'):restored.reserved_input_coin_ids()
    ctx.collections.close()


@pytest.mark.asyncio
async def test_invalid_source_primary_funding_and_retention_never_save(core,tmp_path,monkeypatch):
    c=core;ctx=await context(c,tmp_path)
    # Resolve actual initial native chain once; the mutations below exercise
    # only preparation rejection, not fabricated positive consensus evidence.
    monkeypatch.setattr('solslot_api.generation_mint_reviews.resolve_generation_chain',AsyncMock(return_value=ctx.chain))
    for field,value in [('revision',99),('metadata_root','0x'+'99'*32),('preview_hash','0x'+'99'*32)]:
        with pytest.raises(ValueError,match='sealed revision'):
            await prepare_mint_review(ctx.request.model_copy(update={field:value}),**ctx.kwargs)
    original=c.provider.get_coin_records_by_puzzle_hash_primary
    records=await original(c.faucet.address_hex)
    for bad in ([],[{}],[None],records*5000,[r for r in records if r['coin']['amount']>1000],
                [r for r in records if r['coin']['amount']<=1000]*2):
        c.provider.get_coin_records_by_puzzle_hash_primary=AsyncMock(return_value=bad)
        with pytest.raises(ValueError):await prepare_mint_review(ctx.request,**ctx.kwargs)
    c.provider.get_coin_records_by_puzzle_hash_primary=original
    read=c.provider.get_coin_record_by_name_primary
    async def spent(name):
        raw=deepcopy(await read(name))
        if raw and raw['coin']['amount']<1000:raw.update(spent_block_index=999999,spent=True)
        return raw
    c.provider.get_coin_record_by_name_primary=spent
    with pytest.raises(ValueError,match='funding changed'):await prepare_mint_review(ctx.request,**ctx.kwargs)
    c.provider.get_coin_record_by_name_primary=read
    ctx.store.MAX_RETAINED_BYTES=0
    with pytest.raises(GenerationRetentionFull):await prepare_mint_review(ctx.request,**ctx.kwargs)
    assert ctx.store.for_collection(ctx.request.collection_id) is None and ctx.store.reserved_input_coin_ids()==set()
    ctx.collections.close()


@pytest.mark.asyncio
async def test_duplicate_explicit_clicks_share_one_package_under_funding_guard(core,tmp_path):
    ctx=await context(core,tmp_path)
    one,two=await asyncio.gather(prepare_mint_review(ctx.request,**ctx.kwargs),prepare_mint_review(ctx.request,**ctx.kwargs))
    assert one==two and len(ctx.store.reserved_input_coin_ids())==25
    ctx.collections.close()
