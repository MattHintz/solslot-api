"""HTTP boundaries for cached reviews and assigned administrator signatures."""
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import Settings, get_settings
from solslot_api.generation_consent_routes import router


GENERATION='0x'+'41'*32
PACKAGE='0x'+'42'*32
KEY='0x02'+'43'*32
SIGNATURE='0x'+'44'*65


def context(monkeypatch):
    app=FastAPI();app.include_router(router)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GENERATION)
    claims=SimpleNamespace(generation_id=GENERATION,auth_type='evm',authority_slot=1,compressed_pubkey=KEY)
    auth=Mock(side_effect=lambda:claims)
    app.dependency_overrides[get_settings]=lambda:settings
    def authenticated():return auth()
    app.dependency_overrides[require_admin_jwt]=authenticated
    saved={'packageId':PACKAGE,'generationId':GENERATION,'expiresAt':90000,'stage':'AWAITING_APPROVALS'}
    store=SimpleNamespace(generation_id=GENERATION,recent=Mock(return_value=[saved]),status=Mock(return_value=saved),
        document=Mock(return_value={'challenges':[{'slot':1,'publicKey':KEY}]}))
    index=SimpleNamespace(anchor=SimpleNamespace(administrator=object()))
    provider=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('GET cannot query node')))
    app.state.generation_consents=store;app.state.generation_index=index;app.state.coinset=provider
    app.state.generation_operations=SimpleNamespace(generation_id=GENERATION)
    prepare=AsyncMock(return_value=saved);sign=AsyncMock(return_value=saved);pause=AsyncMock(return_value={'stage':'PREPARED'})
    monkeypatch.setattr('solslot_api.generation_consent_routes.prepare_consent',prepare)
    monkeypatch.setattr('solslot_api.generation_consent_routes.sign_consent',sign)
    monkeypatch.setattr('solslot_api.generation_consent_routes.prepare_scoped_pause',pause)
    return SimpleNamespace(app=app,settings=settings,claims=claims,auth=auth,store=store,index=index,provider=provider,
        prepare=prepare,sign=sign,pause=pause,saved=saved)


def request():
    return {'generationId':GENERATION,'requestKey':'exact-review','kind':'PAUSE_NEW_OPERATIONS',
        'coadministratorSlot':1,'scope':16,'feeCapMojos':1000,
        'expectedInputs':{name:'0x'+'45'*32 for name in ('registry','governance','holdings')}}


def test_cached_reads_are_authenticated_and_work_with_node_and_builder_absent(monkeypatch):
    c=context(monkeypatch)
    c.app.state.generation_index=None;c.app.state.coinset=None
    with TestClient(c.app) as client:
        for _ in range(10):
            response=client.get('/admin/generation/consents')
            assert response.status_code==200 and response.json()['reviews']==[c.saved]
            assert client.get('/admin/generation/consents/'+PACKAGE).json()==c.saved
        assert c.auth.call_count==20
        c.prepare.assert_not_called();c.sign.assert_not_called();c.pause.assert_not_called()
        c.provider.get_network_info_primary.assert_not_called()
        assert client.get('/admin/generation/consents/not-a-package').status_code==422
        c.settings.deployment_generation_id='0x'+'46'*32
        assert client.get('/admin/generation/consents').status_code==503
        c.settings.deployment_generation_id=GENERATION;c.settings.network='mainnet'
        assert client.get('/admin/generation/consents/'+PACKAGE).status_code==503


def test_explicit_prepare_has_strict_request_fields_and_never_signs_or_dispatches(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        response=client.post('/admin/generation/consents/prepare',json=request())
        assert response.status_code==200 and response.json()==c.saved
        body=c.prepare.call_args.args[0]
        assert body.request_key=='exact-review' and body.scope==16
        assert c.prepare.call_args.kwargs=={'anchor':c.index.anchor,'provider':c.provider,
            'store':c.store,'settings':c.settings}
        assert c.prepare.call_args.kwargs['settings'] is c.settings
        for bad in ({'scope':32},{'coadministratorSlot':True},{'feeCapMojos':True},{'signature':SIGNATURE},
                    {'spendBundle':{}},{'kind':'GRANT'}):
            assert client.post('/admin/generation/consents/prepare',json={**request(),**bad}).status_code==422
        assert c.prepare.await_count==1;c.sign.assert_not_called();c.pause.assert_not_called()
        c.app.state.generation_index=None
        assert client.post('/admin/generation/consents/prepare',json=request()).status_code==503
        assert c.prepare.await_count==1


def test_test_mint_publication_loads_only_the_saved_generation_source(monkeypatch):
    c=context(monkeypatch);collections=object();mint_reviews=object()
    getter=Mock(return_value=collections)
    monkeypatch.setattr('solslot_api.generation_consent_routes.get_collection_store',getter)
    c.app.state.generation_mint_reviews=mint_reviews
    body={k:v for k,v in request().items() if k!='scope'}
    body.update(kind='PUBLICATION_APPROVAL',proposalKind='MINT_TEST_ONLY',mintReviewId=PACKAGE)
    body['expectedInputs']['components']={'0x'+'48'*32:'0x'+'49'*32}
    with TestClient(c.app) as client:
        response=client.post('/admin/generation/consents/prepare',json=body)
        assert response.status_code==200
        assert c.prepare.call_args.kwargs=={'anchor':c.index.anchor,'provider':c.provider,'store':c.store,
            'settings':c.settings,'collections':collections,'mint_reviews':mint_reviews}
        getter.assert_called_once_with(c.settings)
        for mutation in ({'mintReviewId':None},{'mintReviewId':True},{'editionProgram':'0x80'},
                         {'funding':[PACKAGE]}, {'canonicalMetadata':{}}, {'scope':2}):
            assert client.post('/admin/generation/consents/prepare',json={**body,**mutation}).status_code==422
        assert c.prepare.await_count==1;c.sign.assert_not_called();c.pause.assert_not_called()


@pytest.mark.parametrize('field,value',[
    ('generation_id','0x'+'46'*32),('auth_type','chia_bls'),('authority_slot',0),('authority_slot',None),
    ('compressed_pubkey','0x03'+'47'*32),
])
def test_signature_requires_exact_session_generation_role_and_key(monkeypatch,field,value):
    c=context(monkeypatch);setattr(c.claims,field,value)
    with TestClient(c.app) as client:
        response=client.post('/admin/generation/consents/'+PACKAGE+'/sign',json={'signature':SIGNATURE})
        assert response.status_code==409 and response.json()['detail']['code']=='GENERATION_CONSENT_REVIEW_CHANGED'
    c.sign.assert_not_called();c.prepare.assert_not_called();c.pause.assert_not_called()


def test_assigned_signature_uses_session_slot_and_only_exact_stored_package(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        url='/admin/generation/consents/'+PACKAGE+'/sign'
        assert client.post(url,json={'signature':SIGNATURE}).status_code==200
        assert c.sign.call_args.args==(PACKAGE,1,bytes.fromhex(SIGNATURE[2:]))
        assert c.sign.call_args.kwargs=={'anchor':c.index.anchor,'provider':c.provider,'store':c.store}
        for body in ({'signature':SIGNATURE,'slot':0},{'signature':SIGNATURE,'generationId':GENERATION},
                     {'signature':'0x00'},{'signature':SIGNATURE,'spendBundle':{}}):
            assert client.post(url,json=body).status_code==422
        assert c.sign.await_count==1


def test_pause_preparation_is_separate_and_keeps_generation_journal_boundary(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        url='/admin/generation/consents/'+PACKAGE+'/prepare-pause'
        assert client.post(url).json()=={'stage':'PREPARED'}
        assert c.pause.call_args.args==(PACKAGE,)
        assert c.pause.call_args.kwargs['journal'] is c.app.state.generation_operations
        c.sign.assert_not_called();c.prepare.assert_not_called()
        c.app.state.generation_operations.generation_id='0x'+'46'*32
        assert client.post(url).status_code==503 and c.pause.await_count==1


@pytest.mark.parametrize('error,expected',[(ValueError('stale'),409),(OSError('disk'),503),
    (sqlite3.OperationalError('busy'),503),(TimeoutError('network'),503),(RuntimeError('node'),503)])
def test_action_failures_are_actionable_and_do_not_leak_internal_errors(monkeypatch,error,expected):
    c=context(monkeypatch);c.prepare.side_effect=error
    with TestClient(c.app) as client:
        response=client.post('/admin/generation/consents/prepare',json=request())
        assert response.status_code==expected
        assert response.json()['detail']['code'].startswith('GENERATION_CONSENT_')
        assert str(error) not in response.json()['detail']['message']


def test_authentication_is_required_and_storage_uses_separate_generation_namespace(monkeypatch):
    c=context(monkeypatch)
    def denied():raise HTTPException(401,detail='not signed in')
    c.app.dependency_overrides[require_admin_jwt]=denied
    with TestClient(c.app) as client:
        assert client.get('/admin/generation/consents').status_code==401
        assert client.post('/admin/generation/consents/prepare',json=request()).status_code==401
        assert client.post('/admin/generation/consents/'+PACKAGE+'/sign',json={'signature':SIGNATURE}).status_code==401
        assert client.post('/admin/generation/consents/'+PACKAGE+'/prepare-pause').status_code==401
    c.prepare.assert_not_called();c.sign.assert_not_called();c.pause.assert_not_called()
    settings=Settings(_env_file=None,network='testnet11',deployment_generation_id=GENERATION)
    assert '/generations/'+GENERATION[2:]+'/' in settings.generation_consents_db_path
    assert settings.generation_consents_db_path!=settings.generation_operations_db_path
