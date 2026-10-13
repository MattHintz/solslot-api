"""Cache polling cannot spend, reserve inputs or obtain a wallet signature."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.admin_auth import require_admin_jwt
from solslot_api.config import Settings,get_settings
from solslot_api.generation_operation_routes import router
from solslot_api.generation_operations import GenerationOperationJournal,GenerationOperationReconciler,submit_saved_operation
from solslot_api.generation_index import GenerationIndexReconciler
from tests.test_generation_operations import GENERATION,Node,operation,service
from solslot_api.faucet import Faucet


def test_authenticated_reads_preserve_original_transaction_and_generation(tmp_path):
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    identity=journal.prepare(operation(),'original-review',100,1000)
    app=FastAPI();app.include_router(router);app.state.generation_operations=journal
    settings=SimpleNamespace(deployment_generation_id=GENERATION,network='testnet11')
    app.dependency_overrides[get_settings]=lambda:settings
    authenticated=[]
    def session():authenticated.append(True)
    app.dependency_overrides[require_admin_jwt]=session
    before=Path(journal.path).read_bytes()
    with TestClient(app) as client:
        for _ in range(10):
            listing=client.get('/admin/generation/operations').json()
            assert listing['available'] and listing['operations']==[journal.status(identity)]
            assert client.get('/admin/generation/operations/'+identity).json()['transactionId'] is None
        assert len(authenticated)==20
        assert Path(journal.path).read_bytes()==before
        settings.deployment_generation_id='0x'+'ac'*32
        assert client.get('/admin/generation/operations').status_code==503
        settings.deployment_generation_id=GENERATION
        assert client.get('/admin/generation/operations/'+'0x'+'bc'*32).status_code==404
        assert client.get('/admin/generation/operations/bad-id').status_code==422


@pytest.mark.asyncio
async def test_background_resume_observes_original_bytes_never_dispatches(tmp_path):
    faucet=Faucet.from_seed_hex('01'*32,'testnet11');node=Node(faucet)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    identity=journal.prepare(operation(),'original-review',100,1000)
    node.observation={'status':'MEMPOOL'}
    await submit_saved_operation(journal,identity,service(tmp_path,node,faucet),clock=lambda:1001)
    assert node.pushes==1
    restored=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    worker=GenerationOperationReconciler(restored,node,clock=lambda:1002)
    for _ in range(3):await worker.run_once()
    assert node.pushes==1 and node.selection_count==1
    node.observation={'status':'CONFIRMED','confirmed_height':33}
    await worker.run_once()
    assert restored.status(identity)['stage']=='CONFIRMED'
    assert restored.pending_ids()==[]
    assert not await worker.run_once()


@pytest.mark.asyncio
async def test_index_recovers_from_unexpected_provider_response_and_storage_failure(monkeypatch):
    # A malformed response or a full disk cannot leave a silently dead timer.
    calls=[]
    store=SimpleNamespace(fail=lambda code,now:calls.append(code),save=lambda *args:None,
        status=lambda *args,**kw:{'pollAfterSeconds':30})
    index=GenerationIndexReconciler(None,store,None)
    resolve=AsyncMock(side_effect=AttributeError('synthetic malformed provider response'))
    monkeypatch.setattr('solslot_api.generation_index.resolve_generation_chain',resolve)
    await index.run_once()
    assert not index.verified and calls==['CHAIN_EVIDENCE_CHANGED']
    # Cancellation is not an error/retry and must propagate for clean shutdown.
    resolve.side_effect=asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):await index.run_once()
    attempts=0
    async def run_once():
        nonlocal attempts
        attempts+=1
        if attempts==1:raise OSError('synthetic full disk')
    index.run_once=run_once
    async def sleep(seconds):
        if attempts==1:assert seconds==5
        else:raise asyncio.CancelledError
    monkeypatch.setattr('solslot_api.generation_index.asyncio.sleep',sleep)
    with pytest.raises(asyncio.CancelledError):await index.run()
    assert attempts==2


def test_operation_journal_is_part_of_frozen_generation_storage_namespace():
    settings=Settings(_env_file=None,network='testnet11',deployment_generation_id=GENERATION)
    assert '/generations/'+GENERATION[2:]+'/' in settings.generation_operations_db_path


def test_submit_requires_enabled_generation_and_exact_saved_intent_and_cap(tmp_path,monkeypatch):
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    identity=journal.prepare(operation(),'original-review',100,1000)
    app=FastAPI();app.include_router(router);app.state.generation_operations=journal
    app.state.protocol_submitter=object()
    settings=SimpleNamespace(deployment_generation_id=GENERATION,network='testnet11',generation_execution_enabled=False)
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[require_admin_jwt]=lambda:None
    submit=AsyncMock(return_value=journal.status(identity))
    monkeypatch.setattr('solslot_api.generation_operation_routes.submit_saved_operation',submit)
    body={'generationId':GENERATION,'intentHash':journal.status(identity)['intentHash'],'feeCapMojos':100}
    url='/admin/generation/operations/'+identity+'/submit'
    with TestClient(app) as client:
        assert client.post(url,json=body).status_code==503;submit.assert_not_called()
        settings.generation_execution_enabled=True
        for bad in ({**body,'generationId':'0x'+'bb'*32},{**body,'feeCapMojos':101},{**body,'intentHash':'0x'+'cc'*32}):
            assert client.post(url,json=bad).status_code==409
        assert client.post(url,json={**body,'spendBundle':{}}).status_code==422
        submit.assert_not_called()
        assert client.post(url,json=body).status_code==200
        submit.assert_awaited_once()
        assert submit.call_args.args[:2]==(journal,identity)
        # Status reads never reach the submitter even when execution is enabled.
        for _ in range(5):assert client.get('/admin/generation/operations').status_code==200
        submit.assert_awaited_once()


def test_http_prepare_recovers_idempotent_action_and_never_submits(tmp_path,monkeypatch):
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    app=FastAPI();app.include_router(router);app.state.generation_operations=journal
    app.state.generation_index=SimpleNamespace(anchor=object());app.state.coinset=object()
    app.state.protocol_submitter=SimpleNamespace(submit=AsyncMock(side_effect=AssertionError('preparation cannot submit')))
    settings=SimpleNamespace(deployment_generation_id=GENERATION,network='testnet11')
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[require_admin_jwt]=lambda:None
    async def prepare(body,**kwargs):
        identity=journal.prepare(operation(),body.request_key,body.fee_cap_mojos,1000,request_digest=body.digest)
        return journal.status(identity)
    monkeypatch.setattr('solslot_api.generation_operation_routes.prepare_maintenance',prepare)
    body={'generationId':GENERATION,'requestKey':'UI-review','kind':'FINALIZE_VOTE','feeCapMojos':100,
          'expectedInputs':{key:'0x'+'aa'*32 for key in ('registry','governance','holdings')}}
    with TestClient(app) as client:
        first=client.post('/admin/generation/operations/prepare',json=body)
        assert first.status_code==200
        for _ in range(5):assert client.post('/admin/generation/operations/prepare',json=body).json()==first.json()
        assert client.post('/admin/generation/operations/prepare',json={**body,'feeCapMojos':101}).status_code==409
        assert len(journal.recent())==1
        assert app.state.protocol_submitter.submit.await_count==0


def test_execution_cannot_be_enabled_without_replacement_generation():
    with pytest.raises(ValueError,match='explicit Testnet11 generation'):
        Settings(_env_file=None,generation_execution_enabled=True,deployment_generation_id=None)
