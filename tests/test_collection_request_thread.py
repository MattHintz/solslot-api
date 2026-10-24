"""Exercise native authority through FastAPI's real dependency scheduler."""
import asyncio
from hashlib import sha256
import json
from types import SimpleNamespace

from fastapi import FastAPI
import httpx
import pytest

from solslot_api.admin_auth import require_admin_jwt
from solslot_api.collection_endpoints import router
from solslot_api.collection_store import get_collection_store, reset_collection_store_for_tests
from solslot_api.config import Settings, get_settings
from solslot_api.test_collection_metadata import TestPropertyDraftV1
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared
from tests.test_testnet_collection_edition import edition


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain', ['economic'], indirect=True)
async def test_real_native_anchor_survives_http_reads_restart_and_invalidation(
    generation_chain, prepared, tmp_path,
):
    # Native fixtures and ASGI run on the same event-loop thread, as in uvicorn.
    # Neither the anchor resolver nor the store dependency is replaced.
    anchor, manifest = generation_chain[3], prepared[3]
    preparation = tmp_path / 'preparation.json'
    preparation.write_text(manifest.model_dump_json(by_alias=True))
    anchor_path = tmp_path / 'anchor.json'
    raw = json.dumps({
        'schemaVersion': 1, 'purpose': 'GENERATION_CHAIN_READ_ANCHOR',
        'preparationManifest': manifest.manifest_hash,
        'registryInner': '0x' + bytes(anchor.registry.inner()).hex(),
        'governanceComponentId': '0x' + anchor.governance.component_id.hex(),
        'economicInners': {name: '0x' + bytes(component.inner()).hex()
                           for name, component in zip(('mint', 'parameters'), anchor.economic_components)},
    }).encode()
    anchor_path.write_bytes(raw)
    settings = Settings(
        _env_file=None, runtime_environment='test', collection_metadata_enabled=True,
        test_collection_editions_enabled=True, admin_db_path=str(tmp_path / 'admin.db'),
        deployment_generation_id=manifest.generation_id,
        generation_preparation_path=str(preparation), generation_preparation_hash=manifest.manifest_hash,
        generation_chain_anchor_path=str(anchor_path), generation_chain_anchor_hash='0x' + sha256(raw).hexdigest(),
    )
    store = get_collection_store(settings)  # Existing synchronous callers still work.
    treasury = '0x' + anchor.economic_components[0].treasury_puzzle_hash.hex()
    assert store.mint_treasury == treasury
    payload = edition()
    payload['generationId'] = manifest.generation_id
    cid = payload['collectionId']
    store.create(collection_id=cid, title=payload['title'], owner_subject='owner', owner_auth_type='evm',
                 initial_draft=TestPropertyDraftV1.model_validate(payload))
    before, audit = store.get(cid), store.audit_events(cid)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[require_admin_jwt] = lambda: SimpleNamespace(sub='owner')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        async def check_read():
            response = await client.get('/admin/collections/' + cid)
            assert response.status_code == 200
            assert response.json() == before
        await check_read()
        await asyncio.gather(*(check_read() for _ in range(5)))
        assert store.mint_treasury == treasury
        assert store.audit_events(cid) == audit
        reset_collection_store_for_tests()
        await asyncio.gather(*(check_read() for _ in range(5)))
        # A changed/missing anchor must clear the cached authority, not inherit it.
        for invalid in (raw + b' ', None):
            if invalid is None:
                anchor_path.unlink()
            else:
                anchor_path.write_bytes(invalid)
            response = await client.get('/admin/collections/' + cid)
            assert response.status_code == 200
            assert 'MINT_AUTHORITY_REQUIRED' in {
                issue['code'] for issue in response.json()['readiness']['issues']}
        anchor_path.write_bytes(raw)
        await check_read()
    reopened = get_collection_store(settings)
    assert reopened.mint_treasury == treasury
    assert reopened.audit_events(cid) == audit


@pytest.mark.asyncio
async def test_legacy_request_needs_no_generation_authority(tmp_path):
    settings = Settings(_env_file=None, runtime_environment='test', collection_metadata_enabled=True,
                        admin_db_path=str(tmp_path / 'legacy.db'))
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[require_admin_jwt] = lambda: SimpleNamespace(sub='owner')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        response = await client.get('/admin/collections')
        assert response.status_code == 200 and response.json()['collections'] == []
    assert not get_collection_store(settings).mint_authority_required
