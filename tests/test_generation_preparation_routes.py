from dataclasses import replace

import httpx
import pytest
from fastapi import FastAPI

from solslot_api.generation_preparation import GenerationPreparation
from solslot_api.generation_preparation_routes import router, preparation_store
from solslot_api.generation_preparation_store import GenerationPreparationStore
from solslot_api.launch_control import LaunchSession,require_launch_session
from tests.test_generation_preparation import b32
from tests.test_generation_recipient_evidence import prepared


def harness(tmp_path,prepared):
    _,_,primary,m,_,_=prepared
    path=str(tmp_path/'recipients.sqlite3')
    store=GenerationPreparationStore(path,m)
    session=LaunchSession('test-ceremony',1,m.administrators[0].wallet,False,9999999999,m.generation_id)
    app=FastAPI();app.include_router(router);app.state.coinset=primary
    app.dependency_overrides[preparation_store]=lambda:store
    app.dependency_overrides[require_launch_session]=lambda:session
    return app,store,session,path


@pytest.mark.asyncio
async def test_native_confirmation_consent_status_refresh_and_restart_are_idempotent(tmp_path,prepared):
    app,store,session,path=harness(tmp_path,prepared)
    _,_,_,m,sigs,_=prepared
    transport=httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport,base_url='http://test') as client:
        prefix='/admin/launch/generation/recipients'
        assert (await client.post(prefix+'/acknowledgement/prepare')).status_code==409
        assert (await client.post(prefix+'/check')).json()['recipients'][0]['confirmed']
        prepared_signature=(await client.post(prefix+'/acknowledgement/prepare')).json()
        assert prepared_signature['typedData']==m.acknowledgement(1)
        body={'preparationManifest':m.manifest_hash,'signature':sigs[1]}
        first=(await client.post(prefix+'/acknowledgement',json=body)).json()
        assert first['recipients'][0]['acknowledgedAt']
        app.dependency_overrides[preparation_store]=lambda:GenerationPreparationStore(path,m)
        # Drop a submission response, restart the store, and retry exactly:
        # consent stays saved and never produces a transaction or new time.
        assert (await client.post(prefix+'/acknowledgement',json=body)).json()==first
        class NoNode:
            def __getattr__(self,name):raise AssertionError('status must read only the cache')
        app.state.coinset=NoNode()
        assert (await client.get(prefix)).json()==first
        assert first['genesisAuthorized'] is False
        assert first['recipientPreparationComplete'] is False
        assert store.signatures()=={1:sigs[1]}


@pytest.mark.asyncio
@pytest.mark.parametrize('attack',['setup','generation','wallet','slot'])
async def test_wrong_recipient_session_cannot_read_prepare_or_save(tmp_path,prepared,attack):
    app,store,session,_=harness(tmp_path,prepared)
    if attack=='setup':session=replace(session,setup=True)
    if attack=='generation':session=replace(session,generation_id=b32(89))
    if attack=='wallet':session=replace(session,wallet='0x'+'00'*20)
    if attack=='slot':session=replace(session,slot=2)
    app.dependency_overrides[require_launch_session]=lambda:session
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        base='/admin/launch/generation/recipients'
        for method,path,body in [('GET',base,None),('POST',base+'/check',{}),
            ('POST',base+'/acknowledgement/prepare',{}),('POST',base+'/acknowledgement',
                {'preparationManifest':store.preparation.manifest_hash,'signature':prepared[4][1]})]:
            assert (await client.request(method,path,json=body)).status_code==403


@pytest.mark.asyncio
async def test_other_wallet_manifest_and_extra_mutation_fields_are_rejected(tmp_path,prepared):
    app,store,_,_=harness(tmp_path,prepared)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        base='/admin/launch/generation/recipients'
        await client.post(base+'/check')
        valid={'preparationManifest':store.preparation.manifest_hash,'signature':prepared[4][1]}
        for mutation in ({'signature':prepared[4][2]},{'preparationManifest':b32(90)}):
            assert (await client.post(base+'/acknowledgement',json={**valid,**mutation})).status_code==409
        assert (await client.post(base+'/acknowledgement',json={**valid,'amount':20000})).status_code==422
        assert store.signatures()=={}


@pytest.mark.asyncio
async def test_recovery_from_transient_node_error_keeps_saved_acknowledgement(tmp_path,prepared):
    app,store,_,_=harness(tmp_path,prepared)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        base='/admin/launch/generation/recipients'
        await client.post(base+'/check')
        valid={'preparationManifest':store.preparation.manifest_hash,'signature':prepared[4][1]}
        await client.post(base+'/acknowledgement',json=valid)
        acknowledged=store.review(0)['recipients'][0]['acknowledgedAt']
        class Unavailable:
            async def get_network_info_primary(self):raise TimeoutError('unavailable')
        app.state.coinset=Unavailable()
        failed=(await client.post(base+'/check')).json()['recipients'][0]
        assert failed['errorCode']=='NODE_UNAVAILABLE' and not failed['confirmed']
        assert failed['acknowledgedAt']==acknowledged
        app.state.coinset=prepared[2]
        fixed=(await client.post(base+'/check')).json()['recipients'][0]
        assert fixed['confirmed'] and fixed['acknowledgedAt']==acknowledged


@pytest.mark.asyncio
async def test_wallet_review_delay_does_not_expire_consent_but_manifest_changes_invalidate_it(tmp_path,prepared):
    app,store,_,path=harness(tmp_path,prepared)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
        await client.post('/admin/launch/generation/recipients/check')
    m=store.preparation
    # An administrator spends ten minutes reviewing a destination in a wallet.
    checked=store.review(0)['recipients'][0]['lastCheckedAt']
    store.acknowledge(1,prepared[4][1],checked+600)
    assert store.review(checked+600)['recipients'][0]['acknowledgedAt']==checked+600
    raw=m.model_dump(mode='json',by_alias=True);raw['sourceCommits']['api']='56'*20
    next_manifest=GenerationPreparation.model_validate(raw)
    changed=GenerationPreparationStore(path,next_manifest)
    assert changed.signatures()=={}
    assert store.signatures()=={1:prepared[4][1]} # Original evidence remains.
    with pytest.raises(ValueError):changed.acknowledge(1,prepared[4][1],checked+600)
