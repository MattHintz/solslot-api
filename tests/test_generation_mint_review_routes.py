"""Mint review HTTP boundaries: explicit preparation, strictly cached reads."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import get_settings
from solslot_api.collection_store import CollectionInvalidState
from solslot_api.generation_mint_review_routes import router
from solslot_api.generation_storage import GenerationRetentionFull

GEN='0x'+'41'*32


def context(monkeypatch):
    app=FastAPI();app.include_router(router)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GEN)
    app.dependency_overrides[get_settings]=lambda:settings
    auth=Mock(return_value=object());app.dependency_overrides[require_admin_jwt]=lambda:auth()
    saved={'packageId':'0x'+'42'*32,'generationId':GEN,'purpose':'TEST_ONLY','publicationReady':False}
    store=SimpleNamespace(generation_id=GEN,for_collection=Mock(return_value=saved),reviewed_request=Mock(return_value=None))
    app.state.generation_mint_reviews=store
    app.state.generation_index=SimpleNamespace(anchor=object())
    app.state.coinset=object();app.state.faucet=object();app.state.protocol_submitter=SimpleNamespace(funding_guard=object())
    prepare=AsyncMock(return_value=saved);collections=object()
    monkeypatch.setattr('solslot_api.generation_mint_review_routes.prepare_mint_review',prepare)
    monkeypatch.setattr('solslot_api.generation_mint_review_routes.get_collection_store',lambda _:collections)
    return SimpleNamespace(app=app,store=store,settings=settings,prepare=prepare,saved=saved,auth=auth,collections=collections)


def body():return dict(generationId=GEN,collectionId='TEST-ONE',revision=2,metadataRoot='0x'+'44'*32,previewHash='0x'+'45'*32)


def test_authenticated_cached_read_does_not_access_node_or_builder(monkeypatch):
    c=context(monkeypatch)
    c.app.state.generation_index=None;c.app.state.coinset=None;c.app.state.faucet=None;c.app.state.protocol_submitter=None
    with TestClient(c.app) as client:
        for _ in range(5):assert client.get('/admin/generation/mint-reviews/collection/TEST-ONE').json()=={'review':c.saved}
        c.prepare.assert_not_called();assert c.auth.call_count==5
        c.store.reviewed_request.return_value=c.saved
        assert client.post('/admin/generation/mint-reviews/prepare',json=body()).json()==c.saved
        c.store.reviewed_request.side_effect=ValueError('changed original')
        response=client.post('/admin/generation/mint-reviews/prepare',json={**body(),'revision':3})
        assert response.status_code==409 and response.json()['detail']['code']=='GENERATION_MINT_SOURCE_CHANGED'
        c.prepare.assert_not_called()
        c.settings.deployment_generation_id='0x'+'49'*32
        assert client.get('/admin/generation/mint-reviews/collection/TEST-ONE').status_code==503
        c.settings.deployment_generation_id=GEN;c.settings.network='mainnet'
        assert client.post('/admin/generation/mint-reviews/prepare',json=body()).status_code==503


def test_prepare_requires_exact_source_fields_and_cannot_sign_select_arbitrary_inputs_or_submit(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        assert client.post('/admin/generation/mint-reviews/prepare',json=body()).status_code==200
        request=c.prepare.call_args.args[0]
        assert request.collection_id=='TEST-ONE' and request.revision==2
        assert c.prepare.call_args.kwargs['funding_guard'] is c.app.state.protocol_submitter.funding_guard
        for mutation in ({'revision':True},{'revision':0},{'collectionId':'../private'},{'metadataRoot':'bad'},
                         {'fundingCoinIds':[]},{'spendBundle':{}},{'signature':'0x01'},{'purpose':'PRODUCTION'}):
            assert client.post('/admin/generation/mint-reviews/prepare',json={**body(),**mutation}).status_code==422
        assert c.prepare.await_count==1
        assert client.post('/admin/generation/mint-reviews/submit',json=body()).status_code==404
        assert client.get('/admin/generation/mint-reviews/collection/not:a:collection').status_code==422
        c.app.state.protocol_submitter=None
        assert client.post('/admin/generation/mint-reviews/prepare',json=body()).status_code==503
        assert c.prepare.await_count==1


@pytest.mark.parametrize('failure,status,code',[(CollectionInvalidState('unsealed'),409,'GENERATION_MINT_SOURCE_CHANGED'),
    (TimeoutError(),503,'GENERATION_MINT_REVIEW_UNAVAILABLE'),(GenerationRetentionFull(),503,'GENERATION_RETAINED_STATE_FULL')])
def test_preparation_errors_are_actionable_and_never_claim_mint_success(monkeypatch,failure,status,code):
    c=context(monkeypatch);c.prepare.side_effect=failure
    with TestClient(c.app) as client:
        response=client.post('/admin/generation/mint-reviews/prepare',json=body())
        assert response.status_code==status and response.json()['detail']['code']==code


def test_authentication_failure_stops_reads_and_preparation(monkeypatch):
    c=context(monkeypatch);c.auth.side_effect=HTTPException(401,'sign in')
    with TestClient(c.app) as client:
        assert client.get('/admin/generation/mint-reviews/collection/TEST-ONE').status_code==401
        assert client.post('/admin/generation/mint-reviews/prepare',json=body()).status_code==401
    c.store.for_collection.assert_not_called();c.prepare.assert_not_called()
