"""Assigned holder route boundaries; reads cannot construct or dispatch."""
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock

import pytest
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import Settings,get_settings
from solslot_api.generation_ballot_routes import router
from solslot_api.generation_storage import GenerationRetentionFull

GENERATION='0x'+'41'*32
PACKAGE='0x'+'42'*32
COIN='0x'+'43'*32
KEY='0x02'+'44'*32
SIGNATURE='0x'+'45'*65


def context(monkeypatch):
    app=FastAPI();app.include_router(router)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GENERATION)
    claims=SimpleNamespace(generation_id=GENERATION,auth_type='evm',compressed_pubkey=KEY)
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[require_admin_jwt]=lambda:claims
    row={'context':{'owner':{'authType':3,'publicKey':KEY}},'request':{'sgtCoinId':COIN}}
    review={'packageId':PACKAGE,'generationId':GENERATION,'stage':'AWAITING_HOLDER_SIGNATURES','holders':[row]}
    store=SimpleNamespace(generation_id=GENERATION,recent=Mock(return_value=[review]),status=Mock(return_value=review),
        document=Mock(return_value={'holders':[row]}))
    index=SimpleNamespace(anchor=object());provider=object();preparation=SimpleNamespace(preparation=object())
    app.state.generation_ballots=store;app.state.generation_index=index;app.state.coinset=provider
    app.state.generation_preparation=preparation;app.state.generation_consents=object()
    app.state.generation_operations=SimpleNamespace(generation_id=GENERATION)
    prepare=AsyncMock(return_value=review);sign=AsyncMock(return_value=review);assemble=AsyncMock(return_value={'stage':'PREPARED'})
    check=AsyncMock();catalog=Mock(return_value={'scope':'FROZEN_GENESIS_ROSTER'})
    for name,mock in [('prepare_holder_ballot',prepare),('sign_holder_ballot',sign),('assemble_holder_ballot',assemble),('cached_holder_selection',catalog)]:
        monkeypatch.setattr('solslot_api.generation_ballot_routes.'+name,mock)
    monkeypatch.setattr('solslot_api.generation_ballot_routes.preparation_custody_anchors',lambda p:('frozen',))
    monkeypatch.setattr('solslot_api.generation_holder_ballots.ballot_inputs_unchanged',check)
    return SimpleNamespace(app=app,settings=settings,claims=claims,store=store,index=index,provider=provider,preparation=preparation,
        review=review,prepare=prepare,sign=sign,assemble=assemble,check=check,catalog=catalog)


def body():
    return {'generationId':GENERATION,'requestKey':'holder-test','kind':'CAST_VOTE','proposalId':'0x'+'46'*32,
        'expectedInputs':{k:'0x'+'47'*32 for k in ('registry','governance','holdings')},'feeCapMojos':1000,
        'selected':[{'coinId':COIN,'vaultLauncherId':'0x'+'48'*32}]}


def test_status_uses_thin_metadata_and_reads_work_offline(monkeypatch):
    c=context(monkeypatch);c.app.state.generation_index=None;c.app.state.coinset=None;c.app.state.generation_preparation=None
    with TestClient(c.app) as client:
        for _ in range(5):
            response=client.get('/admin/generation/ballots').json()
            assert 'holders' not in response['reviews'][0]
            assert client.get('/admin/generation/ballots/'+PACKAGE).json()==c.review
        c.prepare.assert_not_called();c.sign.assert_not_called();c.assemble.assert_not_called();c.check.assert_not_called()
        assert client.get('/admin/generation/ballots/holdings').status_code==503
        assert client.get('/admin/generation/ballots/invalid').status_code==422
        c.settings.deployment_generation_id='0x'+'49'*32
        assert client.get('/admin/generation/ballots').status_code==503


def test_holdings_only_read_cached_projection_and_preparation_is_explicit(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        assert client.get('/admin/generation/ballots/holdings').json()=={'scope':'FROZEN_GENESIS_ROSTER'}
        c.catalog.assert_called_once();c.check.assert_not_called();c.prepare.assert_not_called()
        assert client.post('/admin/generation/ballots/prepare',json=body()).status_code==200
        assert c.prepare.call_args.args[0].request_key=='holder-test'
        assert c.prepare.call_args.kwargs['custodies']==('frozen',)
        assert c.prepare.call_args.kwargs['store'] is c.store
        for changes in ({'feeCapMojos':True},{'kind':'GRANT'},{'spendBundle':{}},{'signature':SIGNATURE},
                {'selected':body()['selected']*2},{'expectedInputs':{**body()['expectedInputs'],'components':{'0x'+'49'*32:'0x'+'50'*32}}}):
            assert client.post('/admin/generation/ballots/prepare',json={**body(),**changes}).status_code==422
        assert c.prepare.await_count==1;c.sign.assert_not_called();c.assemble.assert_not_called()


@pytest.mark.parametrize('field,value',[('generation_id','0x'+'49'*32),('auth_type','chia_bls'),('compressed_pubkey','0x03'+'44'*32)])
def test_signing_requires_the_exact_selected_owner_session(monkeypatch,field,value):
    c=context(monkeypatch);setattr(c.claims,field,value)
    with TestClient(c.app) as client:
        r=client.post('/admin/generation/ballots/'+PACKAGE+'/sign',json={'coinId':COIN,'signature':SIGNATURE})
        assert r.status_code==409 and r.json()['detail']['code']=='GENERATION_BALLOT_REVIEW_CHANGED'
    c.sign.assert_not_called()


def test_exact_evm_or_bls_owner_signatures_do_not_assemble_or_dispatch(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        url='/admin/generation/ballots/'+PACKAGE+'/sign'
        assert client.post(url,json={'coinId':COIN,'signature':SIGNATURE}).status_code==200
        assert c.sign.call_args.args==(PACKAGE,COIN,bytes.fromhex(SIGNATURE[2:]))
        c.claims.auth_type='chia_bls';c.claims.compressed_pubkey='0x'+'51'*48
        c.store.document.return_value['holders'][0]['context']['owner']={'authType':1,'publicKey':c.claims.compressed_pubkey}
        assert client.post(url,json={'coinId':COIN,'signature':'0x'+'52'*96}).status_code==200
        assert len(c.sign.call_args.args[2])==96
        for changes in ({'signature':'0x00'},{'coinId':True},{'spendBundle':{}},{'slot':0}):
            assert client.post(url,json={'coinId':COIN,'signature':SIGNATURE,**changes}).status_code==422
        assert client.post(url,json={'coinId':'0x'+'55'*32,'signature':SIGNATURE}).status_code==409
        c.prepare.assert_not_called();c.assemble.assert_not_called()


def test_input_check_is_separate_from_status_and_expiry_cannot_reopen(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        url='/admin/generation/ballots/'+PACKAGE+'/check-inputs'
        assert client.post(url).json()=={'generationId':GENERATION,'packageId':PACKAGE,'unchanged':True}
        c.check.assert_awaited_once();c.sign.assert_not_called();c.assemble.assert_not_called()
        c.store.status.return_value={**c.review,'stage':'EXPIRED'}
        assert client.post(url).status_code==409 and c.check.await_count==1


def test_assembly_keeps_generation_journal_and_does_not_sign(monkeypatch):
    c=context(monkeypatch)
    with TestClient(c.app) as client:
        url='/admin/generation/ballots/'+PACKAGE+'/assemble'
        assert client.post(url).json()=={'stage':'PREPARED'}
        assert c.assemble.call_args.kwargs['journal'] is c.app.state.generation_operations
        assert c.assemble.call_args.kwargs['index'] is c.index
        c.app.state.generation_operations.generation_id='0x'+'49'*32
        assert client.post(url).status_code==503 and c.assemble.await_count==1
        c.sign.assert_not_called();c.prepare.assert_not_called()


@pytest.mark.parametrize('error,code',[(ValueError('untrusted detail'),409),(OSError('internal path'),503),
    (sqlite3.OperationalError('disk busy'),503),(TimeoutError('internal URL'),503),(GenerationRetentionFull('synthetic internal capacity detail'),503)])
def test_errors_are_actionable_and_private_details_are_not_exposed(monkeypatch,error,code):
    c=context(monkeypatch);c.prepare.side_effect=error
    with TestClient(c.app) as client:
        response=client.post('/admin/generation/ballots/prepare',json=body())
        assert response.status_code==code and str(error) not in response.json()['detail']['message']
        if isinstance(error,GenerationRetentionFull):assert response.json()['detail']['code']=='GENERATION_RETAINED_STATE_FULL'


def test_routes_require_admin_access_and_store_is_generation_scoped(monkeypatch):
    c=context(monkeypatch)
    def denied():raise HTTPException(401,detail='not signed in')
    c.app.dependency_overrides[require_admin_jwt]=denied
    with TestClient(c.app) as client:
        for path in ('','/holdings','/'+PACKAGE):assert client.get('/admin/generation/ballots'+path).status_code==401
        assert client.post('/admin/generation/ballots/prepare',json=body()).status_code==401
    c.prepare.assert_not_called();c.catalog.assert_not_called()
    settings=Settings(_env_file=None,network='testnet11',deployment_generation_id=GENERATION)
    assert '/generations/'+GENERATION[2:]+'/' in settings.generation_ballots_db_path
    assert settings.generation_ballots_db_path not in (settings.generation_consents_db_path,settings.generation_operations_db_path)
