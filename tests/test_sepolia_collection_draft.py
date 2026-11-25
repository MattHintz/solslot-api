from concurrent.futures import ThreadPoolExecutor

import pytest

from solslot_api import sepolia_collection_draft as pair
from solslot_api.collection_store import CollectionConflict, CollectionForbidden, CollectionStore


@pytest.fixture
def reviewed(tmp_path, monkeypatch):
    store = CollectionStore(tmp_path/'collections.sqlite', generation_id=pair.GENERATION, network='testnet11')
    original_get = store.get
    source = dict(id=pair.SOURCE_ID, state='SEALED', revision=14, generationId=pair.GENERATION,
                  metadataRoot=pair.SOURCE_ROOT, draftHash='0x'+'ac'*32, ownerSubject='source-admin')

    def read(identifier, **kwargs):
        return source.copy() if identifier == pair.SOURCE_ID else original_get(identifier, **kwargs)

    monkeypatch.setattr(store, 'get', read)
    yield store, source
    store.close()


def prepare(store, **overrides):
    args = dict(source_id=pair.SOURCE_ID, revision=14, root=pair.SOURCE_ROOT,
                auth_type='evm', subject='source-admin')
    return pair.prepare(store, **(args | overrides))


def test_retry_and_concurrent_preparation_save_one_private_draft(reviewed):
    store, source = reviewed
    prior = source.copy()
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(prepare, store) for _ in range(2)]
        a, b = [f.result() for f in pending]
    assert a['draftHash'] == b['draftHash'] == prepare(store)['draftHash']
    assert a['id'] == pair.EDITION_ID and a['revision'] == 1 and a['state'] == 'DRAFT'
    draft = a['dossier']
    assert draft['purpose'] == 'TEST_ONLY' and draft['network'] == 'testnet11'
    assert draft['offering']['targetRaiseMinor'] == '98' and draft['offering']['royaltyBps'] == '100'
    assert [x['sharePpm'] for x in draft['deedAllocation']] == [500_000, 500_000]
    assert [x['deedId'] for x in draft['deedAllocation']] == [pair.EDITION_ID+'-01',pair.EDITION_ID+'-02']
    assert draft['provenance']['sourceDraftHash'] == source['draftHash']
    assert not a['metadataRoot'] and not a['metadataAnchorId'] and not a['firstProposalId']
    assert 'chain 84532' in draft['summary'] and pair.REVIEW in draft['summary']
    assert source == prior


@pytest.mark.parametrize('change',[{'state':'DRAFT'},{'generationId':'0x'+'10'*32},
                                   {'revision':13},{'metadataRoot':'0x'+'fa'*32}])
def test_rejects_different_source(reviewed, change):
    store, source = reviewed
    source.update(change)
    with pytest.raises(CollectionConflict):
        prepare(store)


@pytest.mark.parametrize('args',[{'root':'0x'+'10'*32},{'source_id':'some-other-property'},{'revision':15}])
def test_rejects_different_client_selection(reviewed,args):
    with pytest.raises(CollectionConflict):
        prepare(reviewed[0],**args)


def test_requires_owner_and_test_network(reviewed):
    store, _ = reviewed
    with pytest.raises(CollectionForbidden):
        prepare(store,subject='another-admin')
    store.network = 'mainnet'
    with pytest.raises(CollectionConflict):
        prepare(store)


def test_respects_existing_draft_with_same_identifier(reviewed):
    store, _ = reviewed
    other=store.create(collection_id=pair.EDITION_ID,title='Unrelated draft',owner_subject='other-admin',owner_auth_type='evm')
    with pytest.raises(CollectionConflict):
        prepare(store)
    assert store.get(other['id'])['draftHash']==other['draftHash']


def test_http_parses_only_the_three_source_fields_and_applies_existing_guards(reviewed, monkeypatch):
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
    from solslot_api.admin_auth import AdminClaims, require_admin_jwt
    from solslot_api.collection_endpoints import router, require_collection_metadata, require_test_editions
    from solslot_api.collection_store import get_collection_store
    from solslot_api.config import get_settings, Settings

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: Settings(network='testnet11')
    app.dependency_overrides[get_collection_store] = lambda: reviewed[0]
    client = TestClient(app)
    path = '/admin/collections/test-editions/base-sepolia-pair'
    body = dict(sourceCollectionId=pair.SOURCE_ID, sourceRevision=14, sourceMetadataRoot=pair.SOURCE_ROOT)
    assert client.post(path,json=body).status_code == 503
    monkeypatch.setattr("solslot_api.admin_auth._effective_admin_allowlist", lambda settings: {"source-admin"})
    assert client.post(path,json=body).status_code == 401

    app.dependency_overrides[require_admin_jwt] = lambda: AdminClaims('source-admin','evm',1,2)
    def unavailable():
        raise HTTPException(503,'Recovery pending')
    app.dependency_overrides[require_collection_metadata] = unavailable
    app.dependency_overrides[require_test_editions] = lambda: None
    assert client.post(path,json=body).status_code == 503
    app.dependency_overrides[require_collection_metadata] = lambda: None
    assert client.post(path,json=body|{'quantity':3}).status_code == 422
    assert client.post(path,json=body|{'sourceRevision':15}).status_code == 409
    assert client.post(path,json=body).json()['id'] == pair.EDITION_ID
    app.dependency_overrides[require_admin_jwt] = lambda: AdminClaims('other-admin','evm',1,2)
    assert client.post(path,json=body).status_code == 403
