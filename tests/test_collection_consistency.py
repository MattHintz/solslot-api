from copy import deepcopy

import pytest
from pydantic import ValidationError

from solslot_api.collection_store import CollectionConflict, CollectionNotReady
from solslot_api.property_metadata import PropertyDossierDraftV1, PropertyDossierV1
from tests.test_collection_endpoints import _client
from tests.test_collection_store import dossier_payload, verified_store


def test_clean_save_preserves_review_revision_timestamp_deeds_and_audit(monkeypatch):
    store, _ = verified_store()
    try:
        before = store.get('HARBOR-17')
        monkeypatch.setattr('solslot_api.collection_store.time.time', lambda: before['updatedAt'] + 60)
        # The revision inside the request is server-managed; If-Match remains authoritative.
        payload = deepcopy(before['dossier'])
        payload['revision'] = 1
        payload['title'] = '  ' + payload['title'] + '  '
        for _ in range(3):
            saved = store.update_draft('HARBOR-17', draft=PropertyDossierDraftV1.model_validate(payload),
                                       expected_revision=2, actor_subject='0xowner')
            assert saved == before
        assert saved['readiness']['ready']
        assert store.seal('HARBOR-17', expected_revision=2, actor_subject='0xowner')['state'] == 'SEALED'
    finally:
        store.close()


def test_clean_save_still_rejects_stale_if_match():
    store, _ = verified_store()
    try:
        with pytest.raises(CollectionConflict):
            store.update_draft('HARBOR-17', draft=PropertyDossierDraftV1.model_validate(store.get('HARBOR-17')['dossier']),
                               expected_revision=1, actor_subject='0xowner')
    finally:
        store.close()


def test_review_transition_keeps_content_revision_and_repeated_submission_is_noop():
    store, _ = verified_store()
    try:
        store._conn.execute("UPDATE property_collections SET state='DRAFT' WHERE id='HARBOR-17'")
        before = store.get('HARBOR-17')
        draft = PropertyDossierDraftV1.model_validate(before['dossier'])
        submitted = store.update_draft('HARBOR-17', draft=draft, expected_revision=2,
                                       actor_subject='0xowner', submit_for_review=True)
        assert submitted['state'] == 'REVIEW'
        assert submitted['revision'] == 2
        assert submitted['readiness']['ready']
        assert len(submitted['auditEvents']) == len(before['auditEvents']) + 1
        assert submitted['auditEvents'][-1]['action'] == 'REVIEW_SUBMITTED'
        assert store.update_draft('HARBOR-17', draft=draft, expected_revision=2,
                                  actor_subject='0xowner', submit_for_review=True) == submitted
    finally:
        store.close()


def test_changed_content_increments_once_and_requires_a_fresh_review():
    store, _ = verified_store()
    try:
        payload = store.get('HARBOR-17')['dossier']
        payload['summary'] = 'Updated project scope.'
        draft = PropertyDossierDraftV1.model_validate(payload)
        changed = store.update_draft('HARBOR-17', draft=draft, expected_revision=2, actor_subject='0xowner')
        assert changed['revision'] == 3
        assert 'INDEPENDENT_REVIEW_REQUIRED' in {issue['code'] for issue in changed['readiness']['issues']}
        repeated = store.update_draft('HARBOR-17', draft=draft, expected_revision=3, actor_subject='0xowner')
        assert repeated == changed
        with pytest.raises(CollectionNotReady):
            store.seal('HARBOR-17', expected_revision=3, actor_subject='0xowner')
    finally:
        store.close()


@pytest.mark.parametrize('field,value,code,path', [
    (('property', 'propertyType'), 'single-family', 'PROPERTY_SUBTYPE_MISMATCH', '/property/propertyType'),
    (('offering', 'assetClass'), 'RWA-RE-MFR', 'ASSET_CLASS_MISMATCH', '/offering/assetClass'),
    (('valuation', 'currency'), 'EUR', 'CURRENCY_MISMATCH', '/valuation/currency'),
    (('operations', 'currency'), 'EUR', 'CURRENCY_MISMATCH', '/operations/currency'),
    (('capital', 'currency'), 'EUR', 'CURRENCY_MISMATCH', '/capital/currency'),
    (('offering', 'parValueMojos'), '1', 'ALLOCATION_PAR_MISMATCH', '/deedAllocation'),
    (('diligence', 0, 'evidenceAssetIds'), ['missing'], 'EVIDENCE_REFERENCE_MISSING', '/diligence/0/evidenceAssetIds'),
    (('diligence', 0, 'evidenceAssetIds'), ['hero-exterior', 'hero-exterior'], 'DUPLICATE_EVIDENCE_REFERENCE', '/diligence/0/evidenceAssetIds'),
])
def test_inconsistent_metadata_is_draftable_but_cannot_be_sealed(field, value, code, path):
    store, _ = verified_store()
    try:
        payload = store.get('HARBOR-17')['dossier']
        parent = payload
        for key in field[:-1]:
            parent = parent[key]
        parent[field[-1]] = value
        # Strict public contract and operational amendments share the same checks.
        with pytest.raises(ValidationError):
            PropertyDossierV1.model_validate(payload)
        changed = store.update_draft('HARBOR-17', draft=PropertyDossierDraftV1.model_validate(payload),
                                     expected_revision=2, actor_subject='0xowner')
        store.submit_review('HARBOR-17', reviewer_subject='0xreviewer', decision='APPROVED')
        issues = store.readiness('HARBOR-17')['issues']
        assert [item['path'] for item in issues if item['code'] == code] == [path]
        before = store.get('HARBOR-17')
        with pytest.raises(CollectionNotReady) as failure:
            store.seal('HARBOR-17', expected_revision=changed['revision'], actor_subject='0xowner')
        assert any(item['code'] == code for item in failure.value.issues)
        assert store.get('HARBOR-17') == before
        assert before['metadataRoot'] is None
    finally:
        store.close()


def test_private_reference_is_not_exported_as_dangling_public_evidence():
    payload = dossier_payload()
    payload['privateDocuments'] = [{'assetId': 'private-title', 'title': 'Original title', 'category': 'title'}]
    payload['diligence'][0]['evidenceAssetIds'] = ['private-title']
    draft = PropertyDossierDraftV1.model_validate(payload)
    with pytest.raises(ValidationError, match='Private originals'):
        draft.to_sealed_dossier()


def test_valid_shared_facts_and_public_references_remain_supported():
    payload = dossier_payload()
    payload['property']['propertyType'] = 'DUPLEX'
    payload['operations']['currency'] = 'usd'
    payload['diligence'][0]['evidenceAssetIds'] = ['hero-exterior', 'appraisal-2026']
    assert PropertyDossierV1.model_validate(payload).commitment().byte_size > 100


def test_equal_par_total_does_not_allow_conflicting_deed_shares():
    payload = dossier_payload()
    payload['deedAllocation'][0]['parValueMojos'] = '100000000000'
    payload['deedAllocation'][1]['parValueMojos'] = '150000000000'
    with pytest.raises(ValidationError, match='ownership share'):
        PropertyDossierV1.model_validate(payload)


def test_allocation_consistency_uses_the_same_largest_remainder_rounding_as_the_form():
    payload = dossier_payload()
    payload['offering']['parValueMojos'] = '3'
    payload['deedAllocation'][0]['parValueMojos'] = '2'
    payload['deedAllocation'][1]['parValueMojos'] = '1'
    assert PropertyDossierV1.model_validate(payload)


@pytest.mark.parametrize('column,value,code', [
    ('kind', 'DOCUMENT', 'ASSET_KIND_MISMATCH'),
    ('visibility', 'PRIVATE', 'PUBLIC_ASSET_REQUIRED'),
])
def test_seal_checks_public_asset_section_and_visibility(column, value, code):
    store, _ = verified_store()
    try:
        store._conn.execute(f"UPDATE property_collection_assets SET {column}=? WHERE asset_id='hero-exterior'", (value,))
        with pytest.raises(CollectionNotReady) as failure:
            store.seal('HARBOR-17', expected_revision=2, actor_subject='0xowner')
        assert any(item['code'] == code for item in failure.value.issues)
    finally:
        store.close()


def test_seal_readiness_runs_inside_the_committing_transaction(monkeypatch):
    store, _ = verified_store()
    original = store.readiness
    checks = []
    def readiness(identifier):
        checks.append(store._conn.in_transaction)
        return original(identifier)
    monkeypatch.setattr(store, 'readiness', readiness)
    try:
        assert store.seal('HARBOR-17', expected_revision=2, actor_subject='0xowner')['state'] == 'SEALED'
        assert checks[0] is True
    finally:
        store.close()


def test_http_clean_put_returns_the_same_etag_and_workspace(tmp_path):
    client, store, _ = _client(tmp_path)
    try:
        created = client.post('/admin/collections', json={'collectionId': 'COL-CLEAN', 'title': 'Clean draft'})
        for _ in range(2):
            saved = client.put('/admin/collections/COL-CLEAN', headers={'If-Match': '"1"'}, json=created.json()['dossier'])
            assert saved.status_code == 200
            assert saved.headers['etag'] == '"1"'
            assert saved.json() == created.json()
    finally:
        client.close()
        store.close()
