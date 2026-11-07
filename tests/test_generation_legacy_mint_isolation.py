"""New-generation writes must never fall back to legacy proposal contracts."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from solslot_api import mint_endpoints, presale_endpoints


def forbidden(*args, **kwargs):
    raise AssertionError('legacy artifact, feature gate or storage was accessed')


def test_legacy_mint_dependency_rejects_generation_before_other_work(monkeypatch):
    monkeypatch.setattr(mint_endpoints, 'require_minting_writes', forbidden)
    monkeypatch.setattr(mint_endpoints, 'require_operation_gate', forbidden)
    with pytest.raises(HTTPException) as error:
        mint_endpoints.require_mint_writes(SimpleNamespace(deployment_generation_id='0x'+'ab'*32))
    assert error.value.status_code == 409
    assert error.value.detail['code'] == 'GENERATION_MINT_ROUTE_REQUIRED'


def test_internal_publication_validation_also_rejects_generation():
    with pytest.raises(HTTPException) as error:
        mint_endpoints._validate_collection_publish_context(
            settings=SimpleNamespace(deployment_generation_id='0x'+'ab'*32),
            metadata=None, claims=None, canonical=None, proposal_id='unused', artifact={})
    assert error.value.detail['code'] == 'GENERATION_MINT_ROUTE_REQUIRED'


@pytest.mark.parametrize('collection', [{'purpose':'TEST_ONLY'}, {'dossier':{'purpose':'TEST_ONLY'}}])
def test_legacy_publication_rejects_test_metadata_before_owner_or_chain_checks(monkeypatch, collection):
    monkeypatch.setattr(mint_endpoints, 'get_collection_store', lambda settings: SimpleNamespace(get=lambda _:collection))
    with pytest.raises(HTTPException) as error:
        mint_endpoints._validate_collection_publish_context(
            settings=SimpleNamespace(deployment_generation_id=None,collection_minting_enabled=True,collection_metadata_enabled=True),
            metadata=SimpleNamespace(metadata_root='root',metadata_anchor_id='anchor',collection_id='collection'),
            claims=None,canonical=None,proposal_id='unused',artifact={})
    assert error.value.detail['code'] == 'TEST_EDITION_MINT_ROUTE_REQUIRED'


@pytest.mark.parametrize(('generation','collection'), [
    ('0x'+'ab'*32, {}), (None, {'purpose':'TEST_ONLY'}), (None, {'dossier':{'purpose':'TEST_ONLY'}})])
def test_presale_rejects_test_edition_before_artifacts_or_terms(monkeypatch, generation, collection):
    monkeypatch.setattr(presale_endpoints,'load_signed_public_artifact',forbidden)
    with pytest.raises(ValueError, match='generation-bound|test editions'):
        presale_endpoints.build_series_terms(None,series_singleton_id=None,collection=collection,
            settings=SimpleNamespace(deployment_generation_id=generation))
