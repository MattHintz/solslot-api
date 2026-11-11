from __future__ import annotations

import copy
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.collection_endpoints import router
from solslot_api.collection_store import CollectionStore, get_collection_store
from solslot_api.config import Settings, get_settings
from solslot_api import collection_generation_recovery as recovery

GEN = '0x' + 'ab' * 32
SOURCE = '0x' + 'cd' * 32


def receipt(now=10000):
    return {'schema': 'solslot.generation-recovery-health.v1', 'entity': 'SOLSLOT',
        'network': 'testnet11', 'actionEnvelopeId': 'AE-SOLSLOT-GENERATION-RECOVERY-20261013-222',
        'purpose': 'LIVE_GENERATION_RECOVERY', 'generationId': GEN, 'sourceHash': SOURCE,
        'principalId': '6b6d66ae-e403-406e-8e2c-0f0b2709f1f4',
        'checkedAt': now, 'restoredAt': now, 'containerPrivate': True,
        'immutabilityVerified': True, 'createOnly': True, 'restoreMatches': True,
        'inventoryInitialized': True, 'databaseCount': 21, 'restoredBytes': 1024,
        'restoreEvidenceSha256': 'ef' * 32,
        'manifest': {'blobName': f'generation-journals/{GEN[2:]}/' + 'aa'*32 + '.aesgcm.json',
                     'sha256': 'aa'*32, 'bytes': 128, 'etag': '"original"'}}


@pytest.mark.parametrize('change', [
    {'generationId': '0x'+'11'*32}, {'sourceHash': '0x'+'22'*32},
    {'purpose': 'SYNTHETIC_RESTORE_DRILL'}, {'network': 'mainnet'},
    {'checkedAt': 9399}, {'restoredAt': 9399}, {'checkedAt': True},
    {'restoredAt': float('nan')}, {'databaseCount': 20}, {'databaseCount': True},
    {'restoreMatches': False}, {'inventoryInitialized': False},
    {'principalId': 'other'}, {'extra': 'unreviewed'},
    {'restoredBytes': 0}, {'restoreEvidenceSha256': 'bad'},
])
def test_wrong_stale_or_incomplete_receipt_cannot_admit_saves(change):
    with pytest.raises(ValueError):
        recovery.validate_record_receipt(dict(receipt(), **change), GEN, SOURCE, now=10000)


def test_generation_manifest_cannot_point_to_legacy_recovery():
    good = receipt()
    assert recovery.validate_record_receipt(good, GEN, SOURCE, now=10000) is good
    wrong = copy.deepcopy(good)
    wrong['manifest']['blobName'] = 'collections/AE181/' + 'aa'*32 + '.aesgcm.json'
    with pytest.raises(ValueError):
        recovery.validate_record_receipt(wrong, GEN, SOURCE, now=10000)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, runtime_environment='test', deployment_generation_id=GEN,
        admin_jwt_secret='synthetic-property-tests-only-'*3,
        collection_metadata_enabled=True, test_collection_editions_enabled=True,
        collection_generation_recovery_source_hash=SOURCE)
    store = CollectionStore(tmp_path/'collections.sqlite', generation_id=GEN)
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_collection_store] = lambda: store
    now = int(time.time())
    app.dependency_overrides[require_admin_jwt] = lambda: AdminClaims(sub='0xowner', auth_type='evm', iat=now, exp=now+300)
    monkeypatch.setattr(recovery, 'read_record_receipt', lambda settings: receipt(int(time.time())))
    with TestClient(app) as client:
        yield client, store, app
    store.close()


def test_record_recovery_status_does_not_read_legacy_receipt(workspace, monkeypatch):
    def legacy():
        raise AssertionError('Legacy recovery must not admit new generation writes')
    monkeypatch.setattr('solslot_api.collection_recovery_health.read_receipt', legacy)
    client, _, _ = workspace
    status = client.get('/admin/collections/feature-status').json()
    assert status['generationId'] == GEN
    assert status['metadataEnabled'] and not status['mintingEnabled']


def test_expired_backup_blocks_writes_but_preserves_read_access(workspace, monkeypatch):
    client, store, _ = workspace
    def stale(settings):
        raise ValueError('stale')
    monkeypatch.setattr(recovery, 'read_record_receipt', stale)
    response = client.post('/admin/collections', json={'title': 'Test property'})
    assert response.status_code == 503
    assert response.json()['detail']['code'] == 'COLLECTION_RECOVERY_PENDING'
    assert store.list() == []
    assert client.get('/admin/collections').status_code == 200
    assert not client.get('/admin/collections/feature-status').json()['metadataEnabled']


@pytest.mark.parametrize('path', ['C/assets/presign', 'C/assets/A/complete', 'C/seal', 'C/amendments'])
def test_fresh_record_backup_does_not_authorize_uncovered_media_or_sealing(workspace, path):
    from starlette.requests import Request
    from fastapi import HTTPException
    settings = Settings(_env_file=None, runtime_environment='test', deployment_generation_id=GEN)
    request = Request({'type': 'http', 'method': 'POST', 'path': '/admin/collections/'+path,
                       'headers': [], 'query_string': b''})
    with pytest.raises(HTTPException) as error:
        recovery.require_preparation_step(request, settings)
    assert error.value.detail['code'] == 'COLLECTION_MEDIA_RECOVERY_PENDING'


def test_authentication_still_required_even_with_fresh_recovery(workspace, monkeypatch):
    client, _, app = workspace
    app.dependency_overrides.pop(require_admin_jwt)
    monkeypatch.setattr('solslot_api.admin_auth._effective_admin_allowlist', lambda settings: {'0xowner'})
    assert client.get('/admin/collections').status_code == 401
    assert client.post('/admin/collections', json={'title': 'Test property'}).status_code == 401


def test_writable_receipt_directory_cannot_authorize_property_writes(monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace
    settings = SimpleNamespace(collection_generation_recovery_path='/receipt/latest.json', network='testnet11')
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o40777))
    monkeypatch.setattr(Path, 'is_symlink', lambda path: False)
    monkeypatch.setattr(recovery.os, 'open', lambda *args, **kwargs: pytest.fail('Untrusted receipt directory must not be opened'))
    with pytest.raises(ValueError, match='NOT_PROTECTED'):
        recovery.read_record_receipt(settings)
