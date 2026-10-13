from copy import deepcopy
import json

import pytest
from pydantic import ValidationError
from solslot_puzzles.property_metadata import commit_metadata
from solslot_api.collection_store import CollectionStore, CollectionInvalidState, CollectionConflict
from solslot_api.property_metadata import PropertyDossierV1, PropertyDossierDraftV1
from solslot_api.test_collection_metadata import (
    TestPropertyDraftV1, TestPropertyDossierV1, TEST_EDITION_SCHEMA, TEST_DISCLOSURE,
    require_edition_binding,
    CANONICAL_DILIGENCE,
)
from tests.test_collection_store import dossier_payload

GEN = '0x' + 'a1' * 32


def edition():
    value = dossier_payload()
    value.update(schemaVersion=TEST_EDITION_SCHEMA, purpose='TEST_ONLY', network='testnet11', generationId=GEN,
        pricingRoundHash='0x'+'c1'*32,
        title='127 Eastmoreland St — Testnet Edition',
        provenance={'sourceCollectionId': 'PRIVATE-SOURCE', 'sourceRevision': 38,
            'sourceDraftHash': '0x' + 'b1' * 32, 'sourceGenerationId': 'archived-test-generation'},
        fsreTerms={'participationBps': 1500, 'outsideTermMonths': 14,
            'projectedMonthsMin': 10, 'projectedMonthsMax': 12},
        valuationBasis='TO_BE_BUILT', valuationEvidence='USER_CONFIRMED')
    value['offering'].update(targetRaiseMinor='7500000', parValueMojos='250000000000', royaltyBps='100')
    value['offering'].pop('governanceQuorum')
    value['deedAllocation'] = [{'deedId': f'TEST-{i+1}', 'sharePpm': 40000, 'parValueMojos': '10000000000'} for i in range(25)]
    value['valuation'].update(marketValueMinor='155000000', method='to-be-built appraisal')
    value['valuation'].pop('asOfDate'); value['valuation'].pop('source')
    value['capital'].pop('debtBalanceMinor'); value['capital'].pop('debtRateBps')
    value['legal'] = {}
    value['unknownFields'] = [{'path': path, 'reason': 'Controlling evidence remains unresolved.'} for path in (
        '/valuation/asOfDate', '/valuation/source', '/capital/debtBalanceMinor', '/capital/debtRateBps',
        '/legal/issuerLegalName', '/legal/securityStructure', '/legal/collateralSummary', '/legal/filingStatus', '/legal/transferPolicy')]
    value['disclosures'].append(TEST_DISCLOSURE)
    for item in value['diligence']:
        if item['key'] in CANONICAL_DILIGENCE:
            for field in ('value', 'unit', 'asOfDate'): item.pop(field, None)
            item['references'] = CANONICAL_DILIGENCE[item['key']]
    return value


def test_incomplete_test_edition_has_one_economic_source_and_cannot_be_production():
    payload = edition()
    dossier = TestPropertyDraftV1.model_validate(payload).to_sealed_dossier()
    canonical = dossier.canonical_payload()
    assert canonical['purpose'] == 'TEST_ONLY' and canonical['generationId'] == GEN
    assert canonical['capital'].get('debtBalanceMinor') is None
    assert canonical['legal'] == {}
    assert len(canonical['deedAllocation']) == 25
    assert int(canonical['offering']['targetRaiseMinor']) * 40000 // 1_000_000 == 300000
    assert canonical['fsreTerms']['returnBasis'] == 'MARKET_VALUE'
    assert next(item for item in canonical['diligence'] if item['key'] == 'debt')['references'] == ['/capital']
    with pytest.raises(ValidationError):
        PropertyDossierV1.model_validate(canonical)
    for network, generation in [('mainnet', GEN), ('testnet11', '0x' + 'a2'*32), ('testnet11', None)]:
        with pytest.raises(ValueError, match='generation'):
            require_edition_binding(dossier, network=network, generation_id=generation)
    changed = deepcopy(canonical); changed['generationId'] = '0x' + 'a2'*32
    assert commit_metadata(changed).metadata_root != dossier.commitment().metadata_root


@pytest.mark.parametrize('mutation', [
    lambda p: p['unknownFields'].pop(),
    lambda p: p['capital'].update(debtBalanceMinor='0'),
    lambda p: p['offering'].update(projectedReturnBps='1500'),
    lambda p: p['offering'].update(governanceQuorum='500000'),
    lambda p: p['offering'].update(royaltyBps='1001'),
    lambda p: p['deedAllocation'][0].update(sharePpm=50000),
    lambda p: p['deedAllocation'][0].update(parValueMojos='2'),
    lambda p: p.update(valuationEvidence='REPORT_REVIEWED'),
    lambda p: p['fsreTerms'].update(projectedMonthsMax=15),
    lambda p: p.update(network='mainnet'),
    lambda p: p.update(privateDocuments=[p['documents'][0]]),
    lambda p: p['unknownFields'].append({'path': '/legal/not-a-real-field', 'reason': 'Unresolved detail.'}),
    lambda p: p['unknownFields'].append({'path': '/diligence/not-a-real-field', 'reason': 'Unresolved detail.'}),
    lambda p: next(item for item in p['diligence'] if item['key'] == 'debt').update(value='$1 of debt'),
    lambda p: next(item for item in p['diligence'] if item['key'] == 'valuation').update(references=['/capital']),
])
def test_seal_rejects_ambiguous_inconsistent_or_private_values(mutation):
    payload = edition(); mutation(payload)
    with pytest.raises(ValidationError):
        TestPropertyDossierV1.model_validate(payload)


def test_edition_derivation_preserves_original_and_clean_saves_preserve_reviews():
    source = dossier_payload(); original = deepcopy(source)
    store = CollectionStore(':memory:', generation_id=GEN)
    created = store.create_test_edition(source=source, source_generation_id='prior',
        collection_id='TEST-EDITION', actor_subject='owner', actor_auth_type='evm')
    assert source == original
    assert created['dossier']['media'] == [] and created['dossier']['documents'] == []
    assert created['dossier']['provenance']['sourceDraftHash'] == '0x' + commit_metadata(
        PropertyDossierDraftV1.model_validate(source).model_dump(mode='json', by_alias=True, exclude_none=True)).metadata_root.hex()
    draft = TestPropertyDraftV1.model_validate(created['dossier'])
    saved = store.update_draft('TEST-EDITION', draft=draft, expected_revision=1, actor_subject='owner')
    assert saved['revision'] == 1 and saved['auditEvents'] == created['auditEvents']
    digest = '0x' + commit_metadata(saved['dossier']).metadata_root.hex()
    store.acknowledge_preview('TEST-EDITION', expected_revision=1, expected_draft_hash=digest, actor_subject='owner')
    assert 'PREVIEW_REVIEW_REQUIRED' not in {issue['code'] for issue in store.readiness('TEST-EDITION')['issues']}
    changed = draft.model_copy(update={'summary': 'A material preview change.'})
    store.update_draft('TEST-EDITION', draft=changed, expected_revision=1, actor_subject='owner')
    assert 'PREVIEW_REVIEW_REQUIRED' in {issue['code'] for issue in store.readiness('TEST-EDITION')['issues']}
    with pytest.raises(CollectionConflict):
        store.acknowledge_preview('TEST-EDITION', expected_revision=2, expected_draft_hash=digest, actor_subject='owner')
    with pytest.raises(CollectionInvalidState, match='purpose'):
        store.update_draft('TEST-EDITION', draft=PropertyDossierDraftV1(collectionId='TEST-EDITION', revision=2, title='Production'),
            expected_revision=2, actor_subject='owner')


def test_generation_database_cannot_be_rebound_or_reuse_legacy_records(tmp_path):
    path = tmp_path / 'new.sqlite'
    store = CollectionStore(path, generation_id=GEN); store.close()
    with pytest.raises(ValueError, match='another deployment'):
        CollectionStore(path, generation_id='0x' + 'a2'*32)
    with pytest.raises(ValueError, match='another deployment'):
        CollectionStore(path)
    legacy = tmp_path / 'old.sqlite'
    store = CollectionStore(legacy)
    store.create(collection_id='OLD', title='Original', owner_subject='owner', owner_auth_type='evm')
    store.close()
    original = legacy.read_bytes()
    with pytest.raises(ValueError, match='cannot be rebound'):
        CollectionStore(legacy, generation_id=GEN)
    assert legacy.read_bytes() == original


def test_generation_binds_real_login_signature_and_jwt():
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    from solslot_api.admin_auth import admin_login_typed_data, issue_jwt, verify_jwt, JWTVerifyError, reset_admin_state_for_tests
    from solslot_api.config import Settings
    reset_admin_state_for_tests()
    settings = Settings(runtime_environment='test', admin_jwt_secret='synthetic-test-secret-'*4, deployment_generation_id=GEN)
    other = settings.model_copy(update={'deployment_generation_id': '0x'+'a2'*32})
    old = settings.model_copy(update={'deployment_generation_id': None})
    account = Account.create()
    def envelope(config):
        return admin_login_typed_data(account.address, '0x'+'c1'*32, 1000, config)
    message = encode_typed_data(full_message=envelope(settings))
    signed = account.sign_message(message)
    assert Account.recover_message(message, signature=signed.signature) == account.address
    for config in [other, old]:
        assert Account.recover_message(encode_typed_data(full_message=envelope(config)), signature=signed.signature) != account.address
    token, _ = issue_jwt(sub=account.address, auth_type='evm', settings=settings)
    assert verify_jwt(token, settings).generation_id == GEN
    for config in [other, old]:
        with pytest.raises(JWTVerifyError, match='another deployment'):
            verify_jwt(token, config)
    old_token, _ = issue_jwt(sub=account.address, auth_type='evm', settings=old)
    with pytest.raises(JWTVerifyError, match='another deployment'):
        verify_jwt(old_token, settings)
    reset_admin_state_for_tests()


def test_native_api_can_derive_and_resume_test_edition_without_touching_source(tmp_path):
    import time
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from solslot_api.collection_endpoints import router
    from solslot_api.collection_store import get_collection_store
    from solslot_api.config import Settings, get_settings
    from solslot_api.admin_auth import require_admin_jwt, AdminClaims
    path = tmp_path / 'source.db'
    source = CollectionStore(path)
    source.create(collection_id='SOURCE', title='Original', owner_subject='owner', owner_auth_type='evm')
    source.close()
    original = path.read_bytes()
    target = CollectionStore(':memory:', generation_id=GEN)
    config = Settings(runtime_environment='test', deployment_generation_id=GEN, test_collection_editions_enabled=True,
        collection_metadata_enabled=True, collection_source_archive_db_path=str(path), collection_source_archive_generation_id='prior')
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: config
    app.dependency_overrides[get_collection_store] = lambda: target
    app.dependency_overrides[require_admin_jwt] = lambda: AdminClaims('owner', 'evm', int(time.time()), int(time.time())+300, generation_id=GEN)
    with TestClient(app) as client:
        source_info = client.get('/admin/collection-source/SOURCE').json()
        request = {'sourceCollectionId': 'SOURCE', 'sourceRevision': source_info['revision'], 'sourceDraftHash': source_info['draftHash']}
        created = client.post('/admin/collections/test-editions', json=request)
        assert created.status_code == 200, created.text
        saved = created.json()
        again = client.post('/admin/collections/test-editions', json=request)
        assert again.json() == saved
        assert len(target.list()) == 1
        bad = {**request, 'sourceRevision': request['sourceRevision']+1}
        assert client.post('/admin/collections/test-editions', json=bad).status_code == 409
        draft = saved['dossier']; draft['summary'] = 'Edited in the native API'
        updated = client.put('/admin/collections/'+saved['id'], headers={'If-Match': '"1"'}, json=draft)
        assert updated.status_code == 200, updated.text
        assert updated.json()['dossier']['purpose'] == 'TEST_ONLY'
        config.test_collection_editions_enabled = False
        assert client.post('/admin/collections/test-editions', json=request).status_code == 503
    assert path.read_bytes() == original
    target.close()
