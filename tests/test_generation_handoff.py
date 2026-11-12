"""Actual native genesis -> production lifespan -> both administrator sessions.

Keys/coins are synthetic; hosted hardening and authority verification are not
stubbed. Only the primary-node transport is the native consensus simulator.
"""
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time

from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
import httpx
import pytest

from solslot_api.config import Settings, get_settings
from solslot_api.disposable_genesis import CLOSED_FLAGS
from solslot_api.genesis import get_genesis_store
from solslot_api.genesis_store import GenesisStore
from solslot_api.generation_admission import (GenerationAdmissionMiddleware, GenerationAdmission,
    current_admin_slots, initialize_handoff, require_handoff_configuration, identity_policies, MAX_ROSTER_AGE)
from solslot_api.generation_recovery_storage import FIELDS
from solslot_api.generation_preparation_store import GenerationPreparationStore
from solslot_api.generation_storage import generation_path
from solslot_api.public_artifact import PublicArtifactMissing
from solslot_api import admin_auth, launch_control
from solslot_api.generation_operation_routes import router as operations
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete
from tests.test_generation_preparation import manifest, signatures
from tests.test_generation_prelaunch_auth import sign_in
from chia.types.mempool_inclusion_status import MempoolInclusionStatus


def configuration(c, built, path):
    prep = path / 'preparation.json'
    prep.write_text(c.prep.model_dump_json(by_alias=True))
    anchor = path / 'anchor.json'
    anchor.write_text(json.dumps(built.review()['readAnchor']))
    return Settings(_env_file=None, runtime_environment='production', network='testnet11',
        deployment_generation_id=c.prep.generation_id,
        generation_preparation_path=str(prep), generation_preparation_hash=c.prep.manifest_hash,
        generation_chain_anchor_path=str(anchor), generation_chain_anchor_hash='0x'+sha256(anchor.read_bytes()).hexdigest(),
        **{field:str(path/'journals'/name) for field,name in FIELDS.items()},
        public_artifact_path=str(path/'artifacts/public.json'), bootstrap_manifest_path=str(path/'artifacts/bootstrap.json'),
        launch_control_enabled=True, launch_source_evidence_path=str(path/'sources.json'),
        launch_source_evidence_sha256='12'*32, launch_session_secret='synthetic-test-only-session-'+'a'*32,
        admin_jwt_secret='synthetic-test-only-jwt-'+'b'*32, launch_cookie_path='/admin',
        protocol_artifact_api_token='synthetic-disabled-api-token-'+'c'*32,
        launch_owner_claim_token='synthetic-disabled-owner-token-'+'d'*32,
        admin_operation_approvals_enabled=True, api_docs_enabled=False,
        security_headers_enabled=True, hsts_enabled=True, bootstrap_cookie_secure=True,
        vault_session_cookie_secure=True, trusted_proxy_cidrs='127.0.0.1/32', cors_origins='https://solslot.com',
        faucet_seed_hex=None, faucet_master_sk_hex=None, faucet_mnemonic=None,
        protocol_fee_funding_enabled=False, alpha_writes_enabled=False,
        **{field:False for field in CLOSED_FLAGS})


def runtime(settings, monkeypatch):
    from solslot_api import app as main
    from solslot_api.genesis_store import GenesisStore
    app = FastAPI(lifespan=main.lifespan)
    app.add_middleware(GenerationAdmissionMiddleware)
    app.include_router(admin_auth.router)
    app.include_router(launch_control.router)
    app.include_router(operations)
    app.dependency_overrides[get_settings] = lambda: settings
    store = GenesisStore.for_settings(settings)
    if store.active() is None:
        store.claim_or_create_draft(ceremony_id=settings.deployment_generation_id,
            token_hash='synthetic-auth-context-not-consent', draft={'generationId':settings.deployment_generation_id,
            'preparationManifest':settings.generation_preparation_hash, 'evmChainId':8453})
    app.dependency_overrides[get_genesis_store] = lambda: store
    monkeypatch.setattr(main, 'get_settings', lambda:settings)
    monkeypatch.setattr(admin_auth, 'get_settings', lambda:settings)
    return app, store


async def desk_sign_in(client, account):
    challenge = await client.post('/admin/auth/challenge', json={'owner':account.address, 'auth_type':'evm'})
    assert challenge.status_code == 200, challenge.text
    raw = challenge.json()
    signature = '0x'+account.sign_message(encode_typed_data(full_message=raw['typed_data'])).signature.hex()
    login = await client.post('/admin/auth/login', json={'owner':account.address, 'auth_type':'evm',
        'nonce':raw['nonce'], 'signature':signature})
    assert login.status_code == 200, login.text
    return login.json()


@contextmanager
def protected_files():
    before = os.umask(0o077)
    try: yield
    finally: os.umask(before)


@pytest.mark.asyncio
async def test_native_launch_production_restart_launch_cookie_and_desk_jwt_preserve_acknowledgements(core, tmp_path, monkeypatch):
    c=core; built=complete(c)[2]; settings=configuration(c,built,tmp_path)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    _,accounts=manifest()
    with protected_files():
        prep=GenerationPreparationStore(settings.generation_preparation_db_path,c.prep)
        for row in c.evidence.recipients:prep.record_confirmation(row,int(time.time()))
        for slot,sig in signatures(c.prep,accounts).items():prep.acknowledge(slot,sig,int(time.time()))
        before=prep.signatures()
        from solslot_api import app as main
        async def start():pass
        async def close():pass
        c.provider.start=start;c.provider.close=close
        monkeypatch.setattr(main,'create_chia_provider',lambda config:c.provider)
        admin_auth.reset_admin_state_for_tests()
        old_jwt=None
        for restart in range(2):
            app,store=runtime(settings,monkeypatch)
            async with app.router.lifespan_context(app):
                assert app.state.identity_deployment is None
                assert app.state.generation_admission.snapshot is not None
                assert app.state.generation_index is not None
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test') as client:
                    if old_jwt:
                        response=await client.get('/admin/auth/session',headers={'Authorization':'Bearer '+old_jwt})
                        assert response.status_code==200,response.text
                    for slot,account in enumerate(accounts):
                        await sign_in(client,account)
                        assert (await client.get('/admin/launch/workspace')).json()['session']['slot']==slot+1
                        login=await desk_sign_in(client,account)
                        assert login['authority_slot']==slot
                        old_jwt=login['jwt']
                        headers={'Authorization':'Bearer '+old_jwt}
                        response=await client.get('/admin/generation/operations',headers=headers)
                        assert response.status_code==200,response.text
                        assert response.json()['generationId']==c.prep.generation_id
                        assert (await client.post('/admin/launch/plan/build',json={})).status_code==403
                        assert (await client.get('/admin/operations')).status_code==403
                    original_snapshot=app.state.generation_admission.snapshot
                    app.state.generation_admission.snapshot=None
                    unavailable=await client.get('/admin/generation/operations',headers=headers)
                    assert unavailable.status_code==503
                    assert unavailable.json()['detail']['code']=='GENERATION_AUTHORITY_UNAVAILABLE'
                    app.state.generation_admission.snapshot=original_snapshot
                    # Old-generation tokens cannot be promoted by possessing
                    # the same secret or using the same wallet.
                    legacy=settings.model_copy(update={'deployment_generation_id':None})
                    token,_=admin_auth.issue_jwt(sub=accounts[0].address,auth_type='evm',settings=legacy,
                        authority_slot=0,compressed_pubkey='0x'+accounts[0]._key_obj.public_key.to_compressed_bytes().hex())
                    assert (await client.get('/admin/auth/session',headers={'Authorization':'Bearer '+token})).status_code==403
                    # Cached authenticated status cannot select inputs, request
                    # a wallet signature or use the primary node.
                    class Never:
                        def __getattr__(self,name):raise AssertionError('cached status contacted primary: '+name)
                    original=app.state.generation_admission.provider
                    app.state.generation_admission.provider=Never()
                    try:
                        for _ in range(3):
                            assert (await client.get('/admin/generation/operations',headers=headers)).status_code==200
                    finally:app.state.generation_admission.provider=original
                assert prep.signatures()==before
                assert store.get(c.prep.generation_id)['plan_signatures']==[]
            assert app.state.generation_admission is None
        admin_auth.reset_admin_state_for_tests()


@pytest.mark.asyncio
async def test_anchor_is_not_confirmation_and_foreign_or_incomplete_anchor_cannot_boot(core,tmp_path):
    c=core;built=complete(c)[2];settings=configuration(c,built,tmp_path)
    with pytest.raises((ValueError,KeyError,TypeError)):
        await initialize_handoff(settings,c.provider)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    for field,value in [('deployment_generation_id','0x'+'99'*32),
            ('generation_chain_anchor_hash','0x'+'98'*32),('network','mainnet'),
            ('admin_jwt_secret',None),('generation_launch_enabled',True),('minting_enabled',True)]:
        broken=settings.model_copy(update={field:value})
        with pytest.raises((ValueError,KeyError)):
            await initialize_handoff(broken,c.provider)
    anchor=Path(settings.generation_chain_anchor_path)
    doc=json.loads(anchor.read_text());doc['economicInners'].pop('pool')
    anchor.write_text(json.dumps(doc));settings.generation_chain_anchor_hash='0x'+sha256(anchor.read_bytes()).hexdigest()
    with pytest.raises(ValueError):require_handoff_configuration(settings)


@pytest.mark.asyncio
async def test_failed_or_stale_observation_never_inherits_disk_or_legacy_roster(core,tmp_path,monkeypatch):
    c=core;built=complete(c)[2];settings=configuration(c,built,tmp_path)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    service=await initialize_handoff(settings,c.provider)
    with pytest.raises(PublicArtifactMissing):current_admin_slots(settings)
    with service.request_context():assert len(current_admin_slots(settings))==3
    class Unchanged:
        def __init__(self):self.reads=0
        async def get_network_info_primary(self):return await c.provider.get_network_info_primary()
        async def get_coin_record_by_name_primary(self,identity):
            self.reads+=1
            return await c.provider.get_coin_record_by_name_primary(identity)
        async def get_puzzle_and_solution_primary(self,*args):
            pytest.fail('unchanged authority unnecessarily replayed its full history')
    unchanged=Unchanged();service.provider=unchanged
    await service.refresh()
    assert unchanged.reads==4
    service.snapshot=replace(service.snapshot,checked=time.monotonic()-MAX_ROSTER_AGE-1)
    with pytest.raises(PublicArtifactMissing):
        with service.request_context():pass
    service.provider=c.provider
    await service.refresh()
    class Offline:
        async def get_network_info_primary(self):raise TimeoutError('synthetic outage')
    service.provider=Offline()
    with pytest.raises(TimeoutError):await service.refresh()
    assert service.snapshot is None
    with pytest.raises(PublicArtifactMissing):
        with service.request_context():pass
    restarted=GenerationAdmission(settings,built.anchor,c.provider)
    assert restarted.snapshot is None
    with pytest.raises(PublicArtifactMissing):
        with restarted.request_context():pass


def test_public_policy_witnesses_are_exact_public_preimages_not_an_allowlist(tmp_path):
    from chia_rs import AugSchemeMPL
    from solslot_puzzles.admin_authority_v3_driver import build_genesis_admin_authority_v3
    from chia_rs.sized_bytes import bytes32
    _,accounts=manifest()
    initial=build_genesis_admin_authority_v3(parent_coin_id=bytes32(b'a'*32),network='testnet11',
        daily_compressed_pubkeys=tuple(a._key_obj.public_key.to_compressed_bytes() for a in accounts),
        recovery_bls_pubkeys=tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (21,22,23)),
        source_manifest_hash=bytes32(b'b'*32),authority_puzzle_version=4)
    replacement=Account.from_key(bytes([99])*32)
    path=tmp_path/'public-policies.json'
    doc={'schemaVersion':1,'generationId':'0x'+'11'*32,'preparationManifest':'0x'+'22'*32,
        'identities':[{'slot':1,'dailyPublicKey':'0x'+replacement._key_obj.public_key.to_compressed_bytes().hex(),
            'recoveryPublicKey':'0x'+initial.identity_vaults[1].recovery_bls_pubkey.hex()}]}
    path.write_text(json.dumps(doc))
    settings=Settings(_env_file=None,deployment_generation_id=doc['generationId'],generation_preparation_hash=doc['preparationManifest'],
        generation_admin_identity_witnesses_path=str(path),generation_admin_identity_witnesses_hash='0x'+sha256(path.read_bytes()).hexdigest())
    policies=identity_policies(settings,initial)
    assert policies[0]==initial.identity_vaults[0] and policies[2]==initial.identity_vaults[2]
    assert policies[1].launcher_id==initial.identity_vaults[1].launcher_id
    assert policies[1].custody_hash!=initial.identity_vaults[1].custody_hash
    for field,value in [('deployment_generation_id','0x'+'33'*32),('generation_admin_identity_witnesses_hash','0x'+'44'*32),
            ('generation_admin_identity_witnesses_hash',None)]:
        with pytest.raises(ValueError):identity_policies(settings.model_copy(update={field:value}),initial)


@pytest.mark.asyncio
async def test_real_delayed_recovery_revokes_old_login_key_and_restores_exact_scoped_signing(core,tmp_path):
    from eth_keys import keys
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton,solution_for_singleton,lineage_proof_for_coinsol
    from chia.wallet.util.compute_additions import compute_additions
    from chia_rs import G2Element, SpendBundle
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64
    from solslot_puzzles import admin_authority_v3_driver as driver
    from solslot_puzzles.eip712_helpers import (eip712_hash_to_sign,eip712_prefix_and_domain_separator,TESTNET11_GENESIS_CHALLENGE)
    from solslot_puzzles.generation_transactions import SingletonTip
    from solslot_api.generation_administrator_evidence import resolve_generation_administrators
    from solslot_api.generation_chain_evidence import resolve_generation_chain
    from solslot_api.generation_consents import GenerationConsentStore,prepare_consent,sign_consent,prepare_scoped_pause
    from solslot_api.generation_operations import GenerationOperationJournal
    from tests.test_generation_consents import request
    c=core;built=complete(c)[2];settings=configuration(c,built,tmp_path)
    assert await c.client.push_tx(built.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    service=await initialize_handoff(settings,c.provider)
    native=built.authority
    evidence=await resolve_generation_administrators(native,provider=c.provider)
    authority=evidence.authority.verified_tip(native.authority_launcher_id,evidence.authority.state)
    identities=[row.verified_tip(policy,native.authority_launcher_id)
        for row,policy in zip(evidence.identities,native.identity_vaults)]
    private=[keys.PrivateKey(bytes([n])*32) for n in (1,2,3)]
    replacement=keys.PrivateKey(bytes([99])*32)
    def member(key,coin,action):
        digest=eip712_hash_to_sign(eip712_prefix_and_domain_separator(TESTNET11_GENESIS_CHALLENGE),coin,action)
        return Program.to([coin,digest,key.sign_msg_hash(digest).to_bytes()[:64]])
    transition=driver.build_identity_vault_transition(identity=native.identity_vaults[1],
        authority_current_inner_puzzle=authority.inner,network='testnet11',kind=driver.PENDING_ROUTINE,
        intent_hash=bytes32(b'r'*32),current_identity_coin_id=identities[1].coin.name(),
        replacement_daily_compressed_pubkey=replacement.public_key.to_compressed_bytes())
    mips=driver.build_authority_prepare_mips_spend(authority=native,transition=transition,
        current_identities=native.identity_vaults,current_identity_coin_ids=tuple(t.coin.name() for t in identities))
    auth_spend=authority.spend(driver.build_prepare_solution(transition=transition,my_amount=1,new_authority_version=2,
        mips_reveal=mips.reveal,mips_solution=mips.solution,
        replacement_member_solution=member(replacement,authority.coin.name(),transition.prepare_binding_hash),identity_records=mips.identity_records))
    owner_action=driver.build_identity_approval_action(identity=identities[0].identity,transition=transition)
    def identity_spend(t,solution,inner=None):
        return make_spend(t.coin,puzzle_for_singleton(t.identity.launcher_id,inner or t.identity.custody_reveal),
            solution_for_singleton(lineage_proof_for_coinsol(t.parent),t.coin.amount,solution))
    owner_spend=identity_spend(identities[0],driver.build_identity_approval_solution(identity=identities[0].identity,
        transition=transition,current_identity_coin_id=identities[0].coin.name(),
        daily_member_solution=member(private[0],identities[0].coin.name(),owner_action.get_tree_hash())))
    target_spend=identity_spend(identities[1],driver.build_routine_identity_prepare_solution(identity=identities[1].identity,
        transition=transition,daily_member_solution=member(private[1],identities[1].coin.name(),transition.prepare_delegated_puzzle.get_tree_hash())))
    assert await c.client.push_tx(SpendBundle([auth_spend,owner_spend,target_spend],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    await service.refresh()
    with service.request_context():assert set(current_admin_slots(settings))=={0,2}
    authority_pending=authority.advanced(auth_spend,transition.authority_pending_inner_puzzle)
    identity_pending=SimpleNamespace(identity=identities[1].identity,coin=compute_additions(target_spend)[0],parent=target_spend)
    finish=SpendBundle([authority_pending.spend(driver.build_complete_solution(my_amount=1,new_authority_version=3)),
        identity_spend(identity_pending,driver.build_identity_finish_solution(transition),transition.intermediate_custody_reveal)],G2Element())
    assert (await c.client.push_tx(finish))[0]!=MempoolInclusionStatus.SUCCESS
    c.sim.pass_time(uint64(86401));await c.sim.farm_block()
    assert await c.client.push_tx(finish)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();await service.refresh()
    with service.request_context():assert set(current_admin_slots(settings))=={0,2}
    # No re-acknowledgement of SGT destination or rewrite of the initial anchor.
    path=tmp_path/'recovered-public-policy.json'
    path.write_text(json.dumps({'schemaVersion':1,'generationId':c.prep.generation_id,'preparationManifest':c.prep.manifest_hash,
        'identities':[{'slot':1,'dailyPublicKey':'0x'+replacement.public_key.to_compressed_bytes().hex(),
            'recoveryPublicKey':'0x'+native.identity_vaults[1].recovery_bls_pubkey.hex()}]}))
    settings.generation_admin_identity_witnesses_path=str(path)
    settings.generation_admin_identity_witnesses_hash='0x'+sha256(path.read_bytes()).hexdigest()
    recovered=await initialize_handoff(settings,c.provider)
    with recovered.request_context():
        slots=current_admin_slots(settings)
        assert set(slots)=={0,1,2}
        assert slots[1][1]=='0x'+replacement.public_key.to_compressed_bytes().hex()
        assert slots[1][1]!='0x'+private[1].public_key.to_compressed_bytes().hex()
    chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    req=request(built.anchor,chain,kind='PAUSE_NEW_OPERATIONS')
    consents=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    review=await prepare_consent(req,anchor=built.anchor,provider=c.provider,store=consents,settings=settings,clock=lambda:int(c.sim.timestamp)-1)
    for challenge in review['challenges']:
        key=private[0] if challenge['slot']==0 else replacement
        signature=key.sign_msg_hash(bytes32.from_hexstr(challenge['digest'])).to_bytes()
        await sign_consent(review['packageId'],challenge['slot'],signature,anchor=built.anchor,provider=c.provider,store=consents,
            clock=lambda:int(c.sim.timestamp)-1)
    operations=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    saved=await prepare_scoped_pause(review['packageId'],anchor=built.anchor,provider=c.provider,store=consents,journal=operations,
        clock=lambda:int(c.sim.timestamp)-1)
    assert await c.client.push_tx(operations.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
