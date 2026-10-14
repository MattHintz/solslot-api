"""Fresh wallet authentication against a pinned roster, with no old consent."""
import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI

from solslot_api.config import Settings,get_settings
from solslot_api.genesis import get_genesis_store
from solslot_api.genesis_store import GenesisStore
from solslot_api.generation_preparation import GenerationPreparation
from solslot_api.generation_preparation_routes import router as recipients
from solslot_api.launch_control import router,_issue_session,LAUNCH_COOKIE_NAME
from tests.test_generation_preparation import manifest

BASE='/admin/launch'


def setup(tmp_path):
    from solslot_api.disposable_genesis import CLOSED_FLAGS
    preparation,accounts=manifest()
    path=tmp_path/'preparation.json';path.write_text(preparation.model_dump_json(by_alias=True))
    settings=Settings(_env_file=None,runtime_environment='test',network='testnet11',
        deployment_generation_id=preparation.generation_id,generation_preparation_path=str(path),
        generation_preparation_hash=preparation.manifest_hash,launch_control_enabled=True,
        launch_cookie_path='/admin',launch_session_secret='synthetic-test-only-session-key-227',
        genesis_db_path=str(tmp_path/'genesis_ceremony_v2.db'),
        generation_preparation_db_path=str(tmp_path/'generation-preparation.sqlite3'),
        alpha_writes_enabled=False,**{field:False for field in CLOSED_FLAGS})
    store=GenesisStore.for_settings(settings)
    store.claim_or_create_draft(token_hash='synthetic-context-only-not-a-wallet-approval',
        ceremony_id=preparation.generation_id,draft={'generationId':preparation.generation_id,
        'preparationManifest':preparation.manifest_hash,'evmChainId':8453})
    app=FastAPI();app.include_router(router);app.include_router(recipients)
    app.dependency_overrides[get_settings]=lambda:settings
    app.dependency_overrides[get_genesis_store]=lambda:store
    return app,settings,store,preparation,accounts


async def sign_in(client,account):
    challenge=await client.post(BASE+'/auth/challenge',json={'wallet':account.address})
    assert challenge.status_code==200,challenge.text
    body=challenge.json()
    signature='0x'+account.sign_message(encode_typed_data(full_message=body['typedData'])).signature.hex()
    response=await client.post(BASE+'/auth/login',json={'wallet':account.address,'nonce':body['nonce'],'signature':signature})
    assert response.status_code==200,response.text
    return body


@pytest.mark.asyncio
@pytest.mark.parametrize('slot',[1,2,3])
async def test_each_real_signature_opens_only_its_generation_recipient_without_old_enrollment(tmp_path,slot,monkeypatch):
    app,settings,store,preparation,accounts=setup(tmp_path)
    import solslot_api.launch_control as control
    async def no_legacy_readiness(*args):pytest.fail('generation workspace must not build legacy readiness')
    monkeypatch.setattr(control,'_readiness',no_legacy_readiness)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test') as client:
        before=store.get(preparation.generation_id)
        assert before['invitations']==[] and before['plan_signatures']==[]
        challenge=await sign_in(client,accounts[slot-1])
        assert challenge['ceremonyBinding']['generationId']==preparation.generation_id
        first=await client.get(BASE+'/workspace');assert first.status_code==200,first.text
        assert first.json()['session']['slot']==slot and not first.json()['session']['setup']
        for _ in range(3):
            progress=await client.get(BASE+'/generation/recipients')
            assert progress.status_code==200,progress.text
            assert progress.json()['assignedSlot']==slot
            assert progress.json()['genesisAuthorized'] is False
            assert not progress.json()['creationAvailable']
        assert (await client.post(BASE+'/funding/execute',json={})).status_code==403
        assert (await client.post(BASE+'/plan/build',json={})).status_code==403
        after=store.get(preparation.generation_id)
        assert after['invitations']==[] and after['plan_signatures']==[] and after['artifact_signatures']==[]
        assert after['spend_bundle_id'] is None


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['outsider','legacy-cookie','changed-source','changed-context','active-anchor'])
async def test_unrelated_authority_or_stale_context_cannot_sign_in_to_replacement(tmp_path,fault):
    app,settings,store,preparation,accounts=setup(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test') as client:
        if fault=='outsider':
            outsider=Account.from_key(bytes([99])*32)
            assert (await client.post(BASE+'/auth/challenge',json={'wallet':outsider.address})).status_code==403
            return
        await sign_in(client,accounts[0])
        if fault=='legacy-cookie':
            old=settings.model_copy(update={'deployment_generation_id':None})
            cookie,_=_issue_session(old,ceremony_id=preparation.generation_id,slot=1,wallet=accounts[0].address.lower(),setup=False)
            client.cookies.clear();client.cookies.set(LAUNCH_COOKIE_NAME,cookie,path='/admin')
        elif fault=='changed-source':
            raw=preparation.model_dump(mode='json',by_alias=True);raw['sourceCommits']['api']='ab'*20
            changed=GenerationPreparation.model_validate(raw)
            settings.generation_preparation_hash=changed.manifest_hash
            __import__('pathlib').Path(settings.generation_preparation_path).write_text(changed.model_dump_json(by_alias=True))
        elif fault=='changed-context':settings.deployment_generation_id='0x'+'67'*32
        else:settings.generation_chain_anchor_path=str(tmp_path/'confirmed-generation-anchor.json')
        response=await client.get(BASE+'/workspace')
        assert response.status_code in (401,403),response.text


@pytest.mark.parametrize('fault',['alpha','legacy-mint','batch','anchor','published','wrong-preparation'])
def test_missing_identity_artifact_exception_cannot_open_customer_writes(tmp_path,fault):
    from solslot_api.generation_preparation import require_prelaunch_configuration
    app,settings,store,preparation,accounts=setup(tmp_path)
    settings.public_artifact_path=str(tmp_path/'public.json')
    settings.bootstrap_manifest_path=str(tmp_path/'bootstrap.json')
    assert require_prelaunch_configuration(settings)==preparation
    if fault=='alpha':settings.alpha_writes_enabled=True
    elif fault=='legacy-mint':settings.minting_enabled=True
    elif fault=='batch':settings.generation_sols_batch_enabled=True
    elif fault=='anchor':settings.generation_chain_anchor_path=str(tmp_path/'anchor.json')
    elif fault=='published':__import__('pathlib').Path(settings.public_artifact_path).write_text('{}')
    else:settings.generation_preparation_hash='0x'+'46'*32
    with pytest.raises(ValueError):require_prelaunch_configuration(settings)


@pytest.mark.asyncio
async def test_hosted_prelaunch_startup_uses_real_hardening_without_old_artifact(tmp_path,monkeypatch):
    from pathlib import Path
    import os
    from solslot_api import app as app_module
    from solslot_api.generation_recovery_storage import FIELDS
    from solslot_api.disposable_genesis import CLOSED_FLAGS
    app,old,store,preparation,accounts=setup(tmp_path)
    settings=Settings(_env_file=None,runtime_environment='production',network='testnet11',
        deployment_generation_id=preparation.generation_id,
        generation_preparation_path=old.generation_preparation_path,
        generation_preparation_hash=preparation.manifest_hash,generation_recovery_storage_enabled=True,
        **{field:str(tmp_path/'journals'/name) for field,name in FIELDS.items()},
        public_artifact_path=str(tmp_path/'artifacts/public.json'),
        bootstrap_manifest_path=str(tmp_path/'artifacts/bootstrap.json'),
        launch_control_enabled=True,launch_source_evidence_path=str(tmp_path/'sources.json'),
        launch_source_evidence_sha256='12'*32,launch_session_secret='synthetic-test-only-key-'+'a'*32,
        launch_owner_claim_token='synthetic-disabled-owner-token-'+'b'*32,
        protocol_artifact_api_token='synthetic-disabled-api-token-'+'c'*32,
        admin_operation_approvals_enabled=True,
        api_docs_enabled=False,security_headers_enabled=True,hsts_enabled=True,
        bootstrap_cookie_secure=True,vault_session_cookie_secure=True,
        trusted_proxy_cidrs='127.0.0.1/32',cors_origins='https://solslot.com',
        faucet_seed_hex=None,faucet_master_sk_hex=None,faucet_mnemonic=None,
        protocol_fee_funding_enabled=False,alpha_writes_enabled=False,
        **{field:False for field in CLOSED_FLAGS})
    class Node:
        async def start(self):pass
        async def close(self):pass
    monkeypatch.setattr(app_module,'get_settings',lambda:settings)
    monkeypatch.setattr(app_module,'create_chia_provider',lambda config:Node())
    # The provider is the only simulated runtime boundary. Hosted validation,
    # missing-artifact handling and all real journal schemas run unchanged.
    previous=os.umask(0o077)
    try:
        async with app_module.lifespan(app):
            assert app.state.identity_deployment is None
            assert app.state.generation_preparation.preparation==preparation
            assert app.state.generation_launch is None
            assert app.state.generation_index is None
            assert app.state.protocol_submitter is None
            assert len(list(Path(settings.generation_preparation_db_path).parent.glob('*.db')))>0
    finally:os.umask(previous)
