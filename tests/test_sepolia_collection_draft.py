from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json

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


@pytest.fixture
def issuer_review(reviewed, monkeypatch):
    from solslot_api.admin_auth import AdminClaims
    from solslot_api.collection_endpoints import SepoliaIssuerNoteRequest

    store, _ = reviewed
    workspace = prepare(store)
    text = 'Unsigned test issuance. Two test deeds for one test USDC.'
    note = SepoliaIssuerNoteRequest(section='review', blocking=False, body=text)
    canonical = json.dumps(workspace['dossier'], sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    monkeypatch.setattr(pair, 'DRAFT_DIGEST', sha256(canonical.encode()).hexdigest())
    monkeypatch.setattr(pair, 'ISSUER_NOTE_DIGEST', sha256(text.encode()).hexdigest())
    claims = AdminClaims('source-admin', 'evm', 1, 2, authority_slot=0, generation_id=pair.GENERATION)
    return store, claims, note


def test_private_note_has_one_receipt_across_independent_connections(issuer_review):
    from solslot_api.collection_store import CollectionNotFound

    store, claims, note = issuer_review
    before = store.get(pair.EDITION_ID)
    replica = CollectionStore(store.path, generation_id=pair.GENERATION, network='testnet11')
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(pair.save_issuer_note, connection, claims, note) for connection in (store, replica)]
            first, retry = [job.result() for job in jobs]
        assert first == retry
        assert first['id'] == 'comment_' + pair.ISSUER_NOTE_DIGEST[:32]
        assert not first['blocking'] and not first['resolved']
        after = replica.get(pair.EDITION_ID)
        assert after['comments'] == [first]
        assert [e['action'] for e in after['auditEvents']].count('COMMENT_ADDED') == 1
        assert after['revision'] == before['revision'] and after['dossier'] == before['dossier']
        assert not after['reviews'] and not after['firstProposalId']
        with pytest.raises(CollectionNotFound):
            replica.public_collection(pair.EDITION_ID)

        withdrawn = pair.withdraw_issuer_note(replica, claims)
        assert withdrawn['resolved'] and withdrawn['id'] == first['id']
        assert pair.withdraw_issuer_note(store, claims) == withdrawn
        assert pair.save_issuer_note(store, claims, note) == withdrawn
        assert len(store.get(pair.EDITION_ID)['comments']) == 1
    finally:
        replica.close()


@pytest.mark.parametrize('changes', [
    {'body': 'An unrelated issuance.'}, {'section': 'sales'}, {'blocking': True},
])
def test_only_reviewed_text_and_desk_section_can_be_saved(issuer_review, changes):
    store, claims, note = issuer_review
    with pytest.raises(CollectionConflict):
        pair.save_issuer_note(store, claims, note.model_copy(update=changes))
    assert store.get(pair.EDITION_ID)['comments'] == []


@pytest.mark.parametrize('field,value', [
    ('sub', 'another-admin'), ('authority_slot', 1), ('auth_type', 'chia_bls'), ('generation_id', 'another-generation'),
])
def test_both_note_actions_require_the_enrolled_collection_owner(issuer_review, field, value):
    from dataclasses import replace

    store, claims, note = issuer_review
    unauthorized = replace(claims, **{field: value})
    with pytest.raises(CollectionForbidden):
        pair.save_issuer_note(store, unauthorized, note)
    pair.save_issuer_note(store, claims, note)
    with pytest.raises(CollectionForbidden):
        pair.withdraw_issuer_note(store, unauthorized)
    assert not store.get(pair.EDITION_ID)['comments'][0]['resolved']


def test_issuer_note_requires_reviewed_private_draft_and_testnet(issuer_review, monkeypatch):
    store, claims, note = issuer_review
    monkeypatch.setattr(pair, 'DRAFT_DIGEST', '0' * 64)
    with pytest.raises(CollectionConflict):
        pair.save_issuer_note(store, claims, note)
    store.network = 'mainnet'
    with pytest.raises(CollectionConflict):
        pair.save_issuer_note(store, claims, note)
    with pytest.raises(CollectionConflict):
        pair.withdraw_issuer_note(store, claims)
    assert [e['action'] for e in store.audit_events(pair.EDITION_ID)] == ['COLLECTION_CREATED']


def test_issuer_note_http_round_trip_and_recovery_guard(issuer_review):
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
    from solslot_api.admin_auth import require_admin_jwt
    from solslot_api.collection_endpoints import router, require_collection_metadata, require_test_editions
    from solslot_api.collection_store import get_collection_store

    store, claims, note = issuer_review
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_admin_jwt] = lambda: claims
    app.dependency_overrides[get_collection_store] = lambda: store
    app.dependency_overrides[require_test_editions] = lambda: None
    client = TestClient(app)
    url = '/admin/collections/test-editions/base-sepolia-pair/issuer-note'
    body = note.model_dump()

    def unavailable():
        raise HTTPException(503, 'Recovery verification pending')
    app.dependency_overrides[require_collection_metadata] = unavailable
    assert client.post(url, json=body).status_code == 503
    assert store.get(pair.EDITION_ID)['comments'] == []
    app.dependency_overrides[require_collection_metadata] = lambda: None
    assert client.post(url, json={**body, 'blocking': 0}).status_code == 422
    assert client.post(url, json={**body, 'quantity': 3}).status_code == 422
    assert client.post(url + '/withdraw', json={}).status_code == 404
    saved = client.post(url, json=body)
    assert saved.status_code == 200
    readback = client.get('/admin/collections/' + pair.EDITION_ID)
    assert readback.json()['comments'] == [saved.json()]
    assert client.post(url + '/withdraw', json={'order': 1}).status_code == 422
    assert client.post(url + '/withdraw', json={}).json()['resolved']
