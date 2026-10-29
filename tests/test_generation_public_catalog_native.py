"""Exercise the catalog with real native authority and ASGI thread scheduling."""
import asyncio
from hashlib import sha256
import json
import time
from types import SimpleNamespace

from fastapi import FastAPI
import httpx
import pytest

from solslot_api.collection_store import get_collection_store, reset_collection_store_for_tests
from solslot_api.config import Settings, get_settings
from solslot_api.generation_public_catalog import router
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain', ['economic'], indirect=True)
async def test_catalog_resolves_real_native_authority_on_its_owning_thread(
    generation_chain, prepared, tmp_path,
):
    # Construct and warm the real native anchor on the ASGI event-loop thread,
    # exactly as application startup does. Do not replace its authority reader
    # or CollectionStore dependency with mocks.
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
    store = get_collection_store(settings)
    treasury = '0x' + anchor.economic_components[0].treasury_puzzle_hash.hex()
    assert store.mint_treasury == treasury
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.state.generation_mint_reviews = SimpleNamespace(
        generation_id=manifest.generation_id, confirmed_collection_ids=lambda: [])
    app.state.generation_operations = SimpleNamespace(generation_id=manifest.generation_id)
    app.state.generation_index = SimpleNamespace(verified=True, store=SimpleNamespace(
        status=lambda *args, **kwargs: {'status': 'READY', 'generationId': manifest.generation_id,
                                     'lastCheckedAt': int(time.time())}))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        async def read():
            response = await client.get('/public/generation/collections')
            assert response.status_code == 200, response.text
            assert response.json()['collections'] == []
            assert response.json()['generationId'] == manifest.generation_id
        await read()
        await asyncio.gather(*(read() for _ in range(6)))
        assert store.mint_treasury == treasury
        reset_collection_store_for_tests()
        await asyncio.gather(*(read() for _ in range(6)))
        assert get_collection_store(settings).mint_treasury == treasury
    reset_collection_store_for_tests()
