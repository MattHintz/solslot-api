"""Generation destination authority, authenticated correction and native source reuse."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from chia_rs.sized_bytes import bytes32
from solslot_api.admin_auth import require_admin_jwt
from solslot_api.collection_endpoints import router
from solslot_api.collection_store import CollectionStore, CollectionForbidden, get_collection_store
from solslot_api.collection_mint_authority import collection_mint_authority
from solslot_api.collection_treasury_correction import correct_treasury
from solslot_api.config import Settings, get_settings
from solslot_api.generation_mint_reviews import prepare_mint_review, MintReviewRequest
from solslot_api.payment_quotes import parse_authorized_oracle_round
from solslot_api.test_collection_metadata import TestPropertyDraftV1
from solslot_puzzles.generation_mint import GenerationMint
from tests.test_generation_genesis_core import core
from tests.test_generation_mint_reviews import context
from tests.test_collection_generation_mint import review_and_seal, prepared


def test_destination_requires_exact_native_component_and_generation(tmp_path, monkeypatch):
    store, _, settings, _, mint, _ = prepared(tmp_path)
    anchor = SimpleNamespace(economic_components=(mint,), governance=SimpleNamespace(mint_id=mint.launcher_id),
        registry=SimpleNamespace(components=(mint.component(),)))
    monkeypatch.setattr('solslot_api.collection_mint_authority.load_generation_read_anchor', lambda _: anchor)
    authority = collection_mint_authority(settings)
    assert authority['treasuryPuzzleHash'] == '0x'+mint.treasury_puzzle_hash.hex()
    assert authority['componentId'] == '0x'+mint.component_id.hex()
    for bad in [replace(mint, generation=bytes32(b'X'*32)), replace(mint, launcher_id=bytes32(b'X'*32))]:
        anchor.economic_components = (bad,)
        with pytest.raises(ValueError): collection_mint_authority(settings)
    anchor.economic_components = (mint, mint)
    with pytest.raises(ValueError): collection_mint_authority(settings)
    anchor.economic_components = (mint,); anchor.registry.components = ()
    with pytest.raises(ValueError): collection_mint_authority(settings)
    settings.network = 'mainnet'
    with pytest.raises(ValueError): collection_mint_authority(settings)
    settings.deployment_generation_id = None
    assert collection_mint_authority(settings) is None
    store.close()


@pytest.mark.asyncio
async def test_confirmed_native_chain_correction_and_exact_new_mint_source(core, tmp_path, monkeypatch):
    c = core; ctx = await context(c, tmp_path)
    anchor = ctx.kwargs['anchor']
    monkeypatch.setattr('solslot_api.collection_mint_authority.load_generation_read_anchor', lambda _: anchor)
    treasury = collection_mint_authority(ctx.settings)['treasuryPuzzleHash']
    # Simulate the defect in a separate synthetic collection ledger, keeping
    # the confirmed native mint and all chain evidence untouched.
    payload = ctx.collections.get(ctx.request.collection_id)['dossier']
    payload['revision'] = 1; payload['offering']['royaltyPuzhash'] = '0x'+'ab'*32
    old = CollectionStore(tmp_path/'legacy-destination.db', generation_id=c.prep.generation_id)
    cid = ctx.request.collection_id
    old.create(collection_id=cid, title=payload['title'], owner_subject='owner', owner_auth_type='evm',
        initial_draft=TestPropertyDraftV1.model_validate(payload))
    receipt = ctx.collections.sealed_test_mint_snapshot(cid)['pricing']['evidence']
    old.apply_test_pricing(cid, expected_revision=1, actor_subject='owner',
        authorized=parse_authorized_oracle_round(ctx.settings, receipt))
    source = review_and_seal(old, cid)
    old.mint_treasury = treasury; old.mint_authority_required = True
    kwargs = dict(collection_id=cid, generation_id=c.prep.generation_id, revision=source['revision'],
        metadata_root=source['metadataRoot'], treasury=treasury, actor='owner', settings=ctx.settings,
        collections=old, index=SimpleNamespace(anchor=anchor), provider=c.provider,
        submitter=SimpleNamespace(funding_guard=ctx.kwargs['funding_guard']), reviews=ctx.store)
    calls = []
    original = old.correct_unissued_test_treasury
    def guarded(*args, **values):
        assert ctx.kwargs['funding_guard'].locked()
        calls.append(1)
        return original(*args, **values)
    monkeypatch.setattr(old, 'correct_unissued_test_treasury', guarded)
    first, retry = await asyncio.gather(correct_treasury(**kwargs), correct_treasury(**kwargs))
    assert first == retry and first['revision'] == source['revision']+1
    assert old._conn.execute('SELECT count(*) FROM property_collection_seal_archives').fetchone()[0] == 1
    assert ctx.store.for_collection(cid) is None and not ctx.store.reserved_input_coin_ids()

    # Reject changed/unknown authority, saved preparation and stale chain reads
    # before the local writer. Negative variants derive from real chain state.
    baseline_calls = len(calls)
    resolver = AsyncMock(return_value=ctx.chain)
    monkeypatch.setattr('solslot_api.collection_treasury_correction.resolve_generation_chain', resolver)
    with pytest.raises(ValueError): await correct_treasury(**{**kwargs, 'treasury':'0x'+'dd'*32})
    with pytest.raises(ValueError): await correct_treasury(**{**kwargs, 'generation_id':'0x'+'dd'*32})
    with pytest.raises(RuntimeError): await correct_treasury(**{**kwargs, 'index':None})
    reviews = SimpleNamespace(generation_id=c.prep.generation_id, for_collection=Mock(return_value={'saved':True}))
    resolver.reset_mock()
    with pytest.raises(ValueError): await correct_treasury(**{**kwargs, 'reviews':reviews})
    resolver.assert_not_awaited()
    for key, value in [('pause_mask',1),('pending',object())]:
        registry = SimpleNamespace(**{**vars(ctx.chain.registry), 'state':replace(ctx.chain.registry.state, **{key:value})})
        resolver.return_value = SimpleNamespace(**{**vars(ctx.chain), 'registry':registry})
        with pytest.raises(ValueError): await correct_treasury(**kwargs)
    resolver.return_value = ctx.chain
    monkeypatch.setattr('solslot_api.collection_treasury_correction.current_evidence_unchanged', AsyncMock(return_value=False))
    with pytest.raises(ValueError): await correct_treasury(**kwargs)
    assert len(calls) == baseline_calls

    # The corrected sealed revision produces the native 25-output source review
    # using the original signed price and synthetic confirmed funding.
    sealed = review_and_seal(old, cid)
    req = MintReviewRequest.model_validate(dict(generationId=c.prep.generation_id, collectionId=cid,
        revision=sealed['revision'], metadataRoot=sealed['metadataRoot'], previewHash=sealed['draftHash']))
    review = await prepare_mint_review(req, **{**ctx.kwargs, 'collections':old})
    assert len(review['funding']) == 25 and len({r['inventoryCoinId'] for r in review['funding']}) == 25
    assert review['canonicalMetadata']['offering']['targetRaiseMinor'] == '7500000'
    assert review['canonicalMetadata']['offering']['royaltyPuzhash'] == treasury
    assert review['request']['metadataRoot'] != source['metadataRoot']
    assert review['canonicalMetadata']['pricingRoundHash'] == source['dossier']['pricingRoundHash']
    with pytest.raises(ValueError): await correct_treasury(**kwargs)
    old.close(); ctx.collections.close()


def test_http_correction_preserves_auth_recovery_flags_and_explicit_revision(monkeypatch):
    gen='0x'+'41'*32
    settings=Settings(_env_file=None,runtime_environment='test',deployment_generation_id=gen,
        collection_metadata_enabled=True,test_collection_editions_enabled=True)
    app=FastAPI();app.include_router(router)
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[get_collection_store]=lambda:object()
    auth=Mock(return_value=SimpleNamespace(sub='owner'))
    app.dependency_overrides[require_admin_jwt]=lambda:auth()
    monkeypatch.setattr('solslot_api.collection_generation_recovery.read_record_receipt',lambda _:{'checkedAt':1,'restoredAt':1})
    apply=AsyncMock(return_value={'revision':14})
    monkeypatch.setattr('solslot_api.collection_treasury_correction.correct_treasury',apply)
    path='/admin/collections/TEST-ONE/corrections/treasury'
    body={'generationId':gen,'metadataRoot':'0x'+'42'*32,'treasury':'0x'+'43'*32}
    with TestClient(app) as client:
        response=client.post(path,json=body,headers={'If-Match':'"13"'})
        assert response.status_code==200 and response.headers['etag']=='"14"'
        assert apply.call_args.kwargs['revision']==13 and apply.call_args.kwargs['actor']=='owner'
        assert client.post(path,json=body).status_code==428
        for mutation in [{'treasury':'arbitrary'}, {'generationId':gen.upper()}, {'signature':'any'}, {'revision':13}]:
            assert client.post(path,json={**body,**mutation},headers={'If-Match':'"13"'}).status_code==422
        assert apply.await_count==1
        for field,value in [('network','mainnet'),('test_collection_editions_enabled',False),('collection_metadata_enabled',False)]:
            previous=getattr(settings,field);setattr(settings,field,value)
            assert client.post(path,json=body,headers={'If-Match':'"13"'}).status_code==503
            setattr(settings,field,previous)
        assert apply.await_count==1
        apply.side_effect=CollectionForbidden('wrong owner')
        assert client.post(path,json=body,headers={'If-Match':'"13"'}).status_code==403
        auth.side_effect=HTTPException(401,'sign in')
        assert client.post(path,json=body,headers={'If-Match':'"13"'}).status_code==401
        assert apply.await_count==2
