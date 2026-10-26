"""Signed sealing uses a durable metadata outcome, never an early consumed flag."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest
from chia_rs.sized_bytes import bytes32
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from solslot_api import admin_operations as ops
from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.collection_endpoints import router
from solslot_api.collection_store import CollectionStore, get_collection_store
from solslot_api.config import Settings, get_settings
from tests.test_collection_store import verified_store


@pytest.fixture
def sealing(tmp_path, monkeypatch):
    accounts = [Account.from_key(bytes([i]) * 32) for i in (31, 32, 33)]
    roster = ops.AdminRoster(bytes32(b'\x11'*32), tuple(
        keys.PrivateKey(bytes(a.key)).public_key.to_compressed_bytes() for a in accounts))
    monkeypatch.setattr(ops, 'resolve_admin_roster', lambda _: roster)
    clock = [1_790_000_000]
    monkeypatch.setattr(ops.time, 'time', lambda: clock[0])
    path = tmp_path/'admin.sqlite'
    original, _ = verified_store()
    with sqlite3.connect(path) as con:
        original._conn.backup(con)
    original.close()
    collection = CollectionStore(path)
    collection._conn.execute('UPDATE property_collections SET owner_subject=?', (accounts[0].address.lower(),))
    operations = ops.OperationStore(path)
    settings = Settings(_env_file=None, runtime_environment='test', admin_db_path=str(path),
        collection_metadata_enabled=True, admin_operation_approvals_enabled=True, eip712_chain_id=11155111)
    subject = [accounts[0].address.lower()]
    app = FastAPI(); app.include_router(ops.router); app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_collection_store] = lambda: collection
    app.dependency_overrides[ops.get_operation_store] = lambda: operations
    app.dependency_overrides[require_admin_jwt] = lambda: AdminClaims(
        sub=subject[0], auth_type='evm', iat=clock[0]-1, exp=clock[0]+600)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post('/admin/auth/operations/prepare', json={
            'operation':'collection.seal', 'revision':2, 'expiresInSeconds':86400,
            'requestBinding':{'method':'POST','path':'/admin/collections/HARBOR-17/seal',
                'body':{},'query':[],'ifMatch':'"2"'}})
        assert response.status_code == 201, response.text
        item = response.json()
        for slot in (0, 1):
            subject[0] = accounts[slot].address.lower()
            signature = '0x'+accounts[slot].sign_message(encode_typed_data(full_message=item['typedData'])).signature.hex()
            assert client.post('/admin/auth/operations/'+item['operationId']+'/sign', json={'signature':signature}).status_code == 200
        subject[0] = accounts[0].address.lower()
        headers = {'If-Match':'"2"','X-Solslot-Admin-Operation-Id':item['operationId']}
        yield client, collection, operations, item, headers, clock, subject
    collection.close()


def post(client, headers):
    return client.post('/admin/collections/HARBOR-17/seal', headers=headers, json={})


def seals(collection):
    return [event for event in collection.audit_events('HARBOR-17') if event['action']=='COLLECTION_SEALED']


def test_failed_admission_does_not_consume_saved_signatures(sealing, monkeypatch):
    client, collection, operations, item, headers, *_ = sealing
    def pending(*args):
        raise HTTPException(503, detail={'code':'COLLECTION_MEDIA_RECOVERY_PENDING'})
    monkeypatch.setattr('solslot_api.collection_generation_recovery.require_preparation_step', pending)
    assert post(client, headers).status_code == 503
    assert operations.get(item['operationId'])['consumed_at'] is None
    assert collection.get('HARBOR-17')['state'] == 'REVIEW'
    assert len(operations.get(item['operationId'])['signatures']) == 2
    assert not seals(collection)


def test_legacy_consumed_failure_resumes_exact_request_without_erasing_evidence(sealing):
    client, collection, operations, item, headers, clock, subject = sealing
    operations.consume(operation_id=item['operationId'], expected_operation='collection.seal',
        expected_payload_hash=bytes32.from_hexstr(item['payloadHash']), caller=subject[0], now=clock[0])
    consumed = operations.get(item['operationId'])['consumed_at']
    active = client.get('/admin/auth/operations').json()['operations']
    assert active[0]['sealExecution']['state'] == 'retry_required'
    assert active[0]['status'] == 'consumed'
    first = post(client, headers)
    assert first.status_code == 200, first.text
    assert first.json()['state'] == 'SEALED'
    assert operations.get(item['operationId'])['consumed_at'] == consumed
    assert post(client, headers).json() == first.json()
    assert len(seals(collection)) == 1
    assert client.get('/admin/auth/operations').json()['count'] == 0
    saved = client.get('/admin/auth/operations/'+item['operationId']).json()
    assert saved['sealExecution'] == {'state':'confirmed','metadataRoot':first.json()['metadataRoot']}


def test_restart_after_metadata_commit_reconciles_without_duplicate_seal(sealing, monkeypatch):
    client, collection, operations, item, headers, *_ = sealing
    with monkeypatch.context() as m:
        m.setattr(operations, 'consume', lambda **kwargs: (_ for _ in ()).throw(RuntimeError('synthetic interruption after metadata commit')))
        assert post(client, headers).status_code == 500
    assert collection.get('HARBOR-17')['state'] == 'SEALED'
    assert operations.get(item['operationId'])['consumed_at'] is None
    # Reopen both durable stores, as after a process restart.
    path = collection.path
    collection.close()
    restored = CollectionStore(path)
    operations = ops.OperationStore(path)
    client.app.dependency_overrides[get_collection_store] = lambda: restored
    client.app.dependency_overrides[ops.get_operation_store] = lambda: operations
    try:
        assert post(client, headers).status_code == 200
        assert len(seals(restored)) == 1
        assert operations.get(item['operationId'])['consumed_at'] is not None
        assert post(client, headers).status_code == 200
        assert len(seals(restored)) == 1
    finally:
        restored.close()


def test_rolled_back_write_preserves_approval_and_duplicate_clicks_seal_once(sealing, monkeypatch):
    client, collection, operations, item, headers, *_ = sealing
    with monkeypatch.context() as m:
        m.setattr(collection, '_audit', lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('synthetic write failure')))
        assert post(client, headers).status_code == 500
    assert collection.get('HARBOR-17')['state'] == 'REVIEW'
    assert operations.get(item['operationId'])['consumed_at'] is None
    with ThreadPoolExecutor(2) as workers:
        responses = list(workers.map(lambda _: post(client, headers), range(2)))
    assert [r.status_code for r in responses] == [200, 200]
    assert len(seals(collection)) == 1


@pytest.mark.parametrize('change', ['expiry','revision','payload','caller','roster'])
def test_reconciliation_never_bypasses_current_authorization(sealing, monkeypatch, change):
    client, collection, operations, item, headers, clock, subject = sealing
    operations.consume(operation_id=item['operationId'], expected_operation='collection.seal',
        expected_payload_hash=bytes32.from_hexstr(item['payloadHash']), caller=subject[0], now=clock[0])
    if change == 'expiry': clock[0] = item['expiresAt']
    if change == 'revision': headers['If-Match'] = '"3"'
    if change == 'payload': headers['If-Match'] = '2'
    if change == 'caller': subject[0] = '0x'+'99'*20
    if change == 'roster':
        monkeypatch.setattr(ops, 'resolve_admin_roster', lambda _: ops.AdminRoster(bytes32(b'X'*32), (b'x'*33,)*3))
    assert post(client, headers).status_code == 409
    assert collection.get('HARBOR-17')['state'] == 'REVIEW'
    assert not seals(collection)


def test_reconciliation_cannot_be_enabled_for_other_operations():
    with pytest.raises(ValueError): ops.require_admin_operation('mint.execute', defer_consume=True, reconcile_seal=True)
    with pytest.raises(ValueError): ops.require_admin_operation('collection.seal', reconcile_seal=True)
