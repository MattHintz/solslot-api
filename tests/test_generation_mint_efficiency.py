"""Real native source checks stay intact when duplicate work is removed."""
import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from solslot_api import generation_mint_reviews as reviews
from solslot_api.generation_mint_checks import checked_mint_chain_cache, primary_mint_coin_records
from solslot_api.generation_index import GenerationIndexReconciler, GenerationIndexStore
from solslot_api.generation_mint_review_routes import _error
from tests.test_generation_genesis_core import core
from tests.test_generation_mint_reviews import context


async def verified_index(c,ctx,tmp_path):
    store=GenerationIndexStore(tmp_path/'index.db',c.prep.generation_id,'0x'+'11'*32)
    index=GenerationIndexReconciler(ctx.kwargs['anchor'],store,c.provider)
    await index.run_once()
    assert index.verified and index.evidence is not None
    return index


@pytest.mark.asyncio
async def test_native_25_deed_preparation_reuses_only_current_verified_proof(core,tmp_path,monkeypatch):
    c=core;ctx=await context(c,tmp_path);index=await verified_index(c,ctx,tmp_path)
    async def forbidden(*args,**kwargs):raise AssertionError('current proof must not replay history')
    monkeypatch.setattr(reviews,'resolve_generation_chain',forbidden)
    original=c.provider.get_coin_record_by_name_primary;active=0;peak=0
    # Authority freshness reads already run concurrently. Track only the helper's
    # funding window through its explicit invocation to measure its own bound.
    observed={}
    async def delayed(identity):
        nonlocal active,peak
        active+=1;peak=max(peak,active)
        try:
            await asyncio.sleep(0)
            value=await original(identity);observed[identity]=value
            return value
        finally:active-=1
    original_helper=reviews.primary_mint_coin_records
    async def measure(identities,*,provider):
        with monkeypatch.context() as patch:
            patch.setattr(provider,'get_coin_record_by_name_primary',delayed)
            return await original_helper(identities,provider=provider)
    monkeypatch.setattr(reviews,'primary_mint_coin_records',measure)
    result=await reviews.prepare_mint_review(ctx.request,**ctx.kwargs,index=index)
    assert len(result['funding'])==25 and len({v['coinId'] for v in result['funding']})==25
    assert 1<peak<=5 and active==0 and len(observed)==25
    assert result['request']==ctx.request.model_dump(mode='json',by_alias=True)
    assert result['request']['metadataRoot']==ctx.collections.get(ctx.request.collection_id)['metadataRoot']
    assert len(ctx.store.reserved_input_coin_ids())==25
    before=ctx.store.status(result['packageId'])
    checked=await reviews.revalidate_mint_review(result['packageId'],settings=ctx.settings,
        collections=ctx.collections,store=ctx.store,chain=index.evidence,provider=c.provider)
    assert checked[0]==before and len(checked[2])==25
    assert ctx.store.status(result['packageId'])==before
    ctx.collections.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('condition',['unverified','stale','foreign_provider','foreign_anchor','not_native_index'])
async def test_invalid_cache_cannot_supply_authority(core,tmp_path,condition,monkeypatch):
    c=core;ctx=await context(c,tmp_path);index=await verified_index(c,ctx,tmp_path)
    provider=c.provider;anchor=ctx.kwargs['anchor']
    if condition=='unverified':index.verified=False
    if condition=='stale':
        now=int(time.time());monkeypatch.setattr('solslot_api.generation_mint_checks.time.time',lambda:now+91)
    if condition=='foreign_provider':provider=SimpleNamespace()
    if condition=='foreign_anchor':anchor=SimpleNamespace()
    if condition=='not_native_index':index=SimpleNamespace(verified=True,evidence=index.evidence)
    assert await checked_mint_chain_cache(anchor,provider=provider,index=index) is None
    assert ctx.store.for_collection(ctx.request.collection_id) is None
    assert not ctx.store.reserved_input_coin_ids()
    ctx.collections.close()


@pytest.mark.asyncio
async def test_primary_unavailability_never_reuses_cached_authority(core,tmp_path,monkeypatch):
    c=core;ctx=await context(c,tmp_path);index=await verified_index(c,ctx,tmp_path)
    monkeypatch.setattr(c.provider,'get_network_info_primary',AsyncMock(side_effect=OSError('synthetic primary unavailable')))
    with pytest.raises(OSError):await reviews.prepare_mint_review(ctx.request,**ctx.kwargs,index=index)
    assert ctx.store.for_collection(ctx.request.collection_id) is None and not ctx.store.reserved_input_coin_ids()
    ctx.collections.close()


@pytest.mark.asyncio
async def test_timeout_is_typed_before_any_holds_and_preserves_guard_ownership(core,tmp_path,monkeypatch):
    c=core;ctx=await context(c,tmp_path);guard=ctx.kwargs['funding_guard'];await guard.acquire()
    timeout=asyncio.timeout
    monkeypatch.setattr(reviews.asyncio,'timeout',lambda seconds:timeout(.001 if seconds==50 else seconds))
    with pytest.raises(reviews.MintReviewTimeout) as error:
        await reviews.prepare_mint_review(ctx.request,**ctx.kwargs)
    assert error.value.stage=='WAITING_FOR_FUNDING_GUARD' and guard.locked()
    guard.release();assert not ctx.store.reserved_input_coin_ids()
    http=_error(error.value)
    assert http.status_code==503 and http.detail['code']=='GENERATION_MINT_REVIEW_TIMEOUT'
    assert http.headers=={'Retry-After':'5'}
    ctx.collections.close()


@pytest.mark.asyncio
async def test_primary_reads_keep_order_inspect_all_errors_and_never_use_fallback():
    ids=['0x'+f'{i:064x}' for i in range(25)];active=0;peak=0;seen=[]
    async def read(identity):
        nonlocal active,peak
        active+=1;peak=max(peak,active)
        try:
            await asyncio.sleep(0);seen.append(identity)
            return {'identity':identity}
        finally:active-=1
    provider=SimpleNamespace(get_coin_record_by_name_primary=read,get_coin_record_by_name=AsyncMock(side_effect=AssertionError('advisory fallback')))
    assert await primary_mint_coin_records(ids,provider=provider)==[{'identity':v} for v in ids]
    assert 1<peak<=5 and active==0
    async def fail(identity):
        seen.append(identity);await asyncio.sleep(0)
        if identity==ids[2]:raise OSError('synthetic read failure')
        return None
    seen.clear();provider.get_coin_record_by_name_primary=fail
    with pytest.raises(OSError):await primary_mint_coin_records(ids,provider=provider)
    assert set(seen)==set(ids)
    provider.get_coin_record_by_name.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancellation_drains_bounded_primary_reads():
    ids=['0x'+f'{i:064x}' for i in range(25)];active=0;started=asyncio.Event()
    async def read(identity):
        nonlocal active
        active+=1
        if active==5:started.set()
        try:await asyncio.Future()
        finally:active-=1
    task=asyncio.create_task(primary_mint_coin_records(ids,provider=SimpleNamespace(get_coin_record_by_name_primary=read)))
    await started.wait();task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    await asyncio.sleep(0)
    assert active==0


@pytest.mark.asyncio
@pytest.mark.parametrize('ids',[[],['bad'],['0x'+'11'*32]*2,['0x'+f'{i:064x}' for i in range(101)]])
async def test_unbounded_duplicate_or_malformed_inputs_never_query_primary(ids):
    provider=SimpleNamespace(get_coin_record_by_name_primary=AsyncMock())
    with pytest.raises(ValueError):await primary_mint_coin_records(ids,provider=provider)
    provider.get_coin_record_by_name_primary.assert_not_awaited()
