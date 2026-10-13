import json
from hashlib import sha256
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api.config import get_settings
from solslot_api.generation_index import GenerationIndexStore, GenerationIndexReconciler, load_generation_read_anchor
from solslot_api.generation_status_routes import router
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared, Primary


def test_cached_status_is_read_only_preserves_evidence_and_expires(tmp_path):
    generation='0x'+'ab'*32;anchor='0x'+'cd'*32
    store=GenerationIndexStore(str(tmp_path/'index.db'),generation,anchor)
    assert store.status(100)['status']=='RECONCILING'
    payload={'generationId':generation,'network':'testnet11','checkedAt':100,'active':False,'supply':{'distributed':30000}}
    store.save(payload,100)
    from pathlib import Path
    original=Path(store.path).read_bytes()
    assert store.status(101,verified_in_process=True)['status']=='READY'
    assert store.status(191,verified_in_process=True)['status']=='STALE'
    assert store.status(99,verified_in_process=True)['status']=='STALE'
    assert Path(store.path).read_bytes()==original
    store.fail('NODE_UNAVAILABLE',110)
    status=store.status(111,verified_in_process=True)
    assert status['status']=='STALE' and status['snapshot']==payload and status['lastCheckedAt']==100
    store.save({**payload,'checkedAt':105},105) # Stale concurrent completion cannot erase the failure.
    assert store.status(111)['errorCode']=='NODE_UNAVAILABLE'
    store.save({**payload,'checkedAt':112},112)
    reopened=GenerationIndexStore(str(tmp_path/'index.db'),generation,anchor)
    assert reopened.status(113)['status']=='RECONCILING' # Restart is not proof of freshness.
    assert reopened.status(113)['snapshot']['supply']['distributed']==30000
    different=GenerationIndexStore(str(tmp_path/'index.db'),generation,'0x'+'ef'*32)
    assert different.status(113)['snapshot'] is None # Changing anchor cannot inherit prior authority.
    with pytest.raises(ValueError):store.save({**payload,'generationId':'0x'+'01'*32},100)


@pytest.mark.asyncio
async def test_index_reuses_unchanged_tips_but_replays_after_restart_or_failure(generation_chain,tmp_path):
    _,client,_,anchor,_=generation_chain
    class Counting(Primary):
        spend_reads=0
        fail=False
        async def get_puzzle_and_solution_primary(self,*args):
            self.spend_reads+=1
            return await super().get_puzzle_and_solution_primary(*args)
        async def get_network_info_primary(self):
            if self.fail:raise TimeoutError('synthetic unavailable node')
            return await super().get_network_info_primary()
    provider=Counting(client)
    store=GenerationIndexStore(str(tmp_path/'cache.db'),'0x'+anchor.issuance.generation.hex(),'0x'+'12'*32)
    index=GenerationIndexReconciler(anchor,store,provider)
    await index.run_once()
    assert index.verified and provider.spend_reads>0
    first=provider.spend_reads
    await index.run_once()
    assert provider.spend_reads==first # Active/idle refresh does no replay when tips are unchanged.
    provider.fail=True
    await index.run_once()
    assert not index.verified and index.evidence is None
    import time
    failed=store.status(int(time.time()))
    assert failed['status']=='STALE' and failed['snapshot']['supply']['nextProposalQuorum']==15000
    provider.fail=False
    restarted=GenerationIndexReconciler(anchor,store,provider)
    await restarted.run_once()
    assert restarted.verified and provider.spend_reads>first


def test_public_status_route_never_reconciles_or_creates_transactions(tmp_path):
    generation='0x'+'ab'*32
    store=GenerationIndexStore(str(tmp_path/'cache.db'),generation,'0x'+'cd'*32)
    class ReadOnlyIndex:
        verified=False
        def __init__(self):self.store=store
        def run_once(self):raise AssertionError('GET must not reconcile')
    app=FastAPI();app.include_router(router)
    app.state.generation_index=ReadOnlyIndex()
    app.dependency_overrides[get_settings]=lambda:SimpleNamespace(deployment_generation_id=generation,network='testnet11')
    with TestClient(app) as client:
        for _ in range(3):
            response=client.get('/committee/generation/status')
            assert response.status_code==200 and response.json()['status']=='RECONCILING'
        app.state.generation_index=None
        assert client.get('/committee/generation/status').json()['status']=='NOT_READY'


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',[None,'economic','pool'],indirect=True)
async def test_frozen_anchor_requires_exact_preparation_and_registry(generation_chain,prepared,tmp_path):
    _,_,_,anchor,_=generation_chain
    manifest=prepared[3]
    prep=tmp_path/'preparation.json';prep.write_text(manifest.model_dump_json(by_alias=True))
    document={'schemaVersion':1,'purpose':'GENERATION_CHAIN_READ_ANCHOR','preparationManifest':manifest.manifest_hash,
        'registryInner':'0x'+bytes(anchor.registry.inner()).hex(),'governanceComponentId':'0x'+anchor.governance.component_id.hex()}
    if anchor.economic_components:
        document['economicInners']={('mint' if i==0 else 'parameters' if i==1 else 'pool'):'0x'+bytes(s.inner()).hex()
            for i,s in enumerate(anchor.economic_components)}
    path=tmp_path/'anchor.json';raw=json.dumps(document).encode();path.write_bytes(raw)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=manifest.generation_id,
        generation_preparation_path=str(prep),generation_preparation_hash=manifest.manifest_hash,
        generation_chain_anchor_path=str(path),generation_chain_anchor_hash='0x'+sha256(raw).hexdigest())
    loaded=load_generation_read_anchor(settings)
    assert loaded.registry.inner()==anchor.registry.inner() and loaded.governance.inner()==anchor.governance.inner()
    assert len(loaded.economic_components)==len(anchor.economic_components)
    if anchor.economic_components:
        bad=dict(document,economicInners={})
        bad_raw=json.dumps(bad).encode();path.write_bytes(bad_raw);settings.generation_chain_anchor_hash='0x'+sha256(bad_raw).hexdigest()
        with pytest.raises(ValueError,match='incomplete'):load_generation_read_anchor(settings)
        settings.generation_chain_anchor_hash='0x'+sha256(raw).hexdigest()
    path.write_bytes(raw+b' ')
    with pytest.raises(ValueError,match='reviewed file hash'):load_generation_read_anchor(settings)
    path.write_bytes(raw);settings.generation_preparation_hash='0x'+'aa'*32
    with pytest.raises(ValueError,match='preparation'):load_generation_read_anchor(settings)
