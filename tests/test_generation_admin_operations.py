"""Generation approval preparation, real wallet signatures, and guarded execution.

The native test confirms a synthetic genesis in Chia before starting production
admission. No hosted authority/JWT verifier or roster resolver is stubbed.
"""
from dataclasses import replace
import time
from types import SimpleNamespace

from eth_account.messages import encode_typed_data
from fastapi import Depends
import httpx
import pytest
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs.sized_bytes import bytes32

from solslot_api import admin_auth, admin_operations as operations
from solslot_api.config import Settings
from solslot_api.generation_admission import MAX_ROSTER_AGE
from solslot_api.public_artifact import PublicArtifactMissing
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete
from tests.test_generation_preparation import manifest
from tests.test_generation_handoff import configuration, runtime, desk_sign_in, protected_files


def forbid_legacy(*args, **kwargs):
    pytest.fail('Confirmed generation must never load legacy authority')


def test_generation_uses_current_chain_keys_not_initial_anchor_keys(monkeypatch):
    settings = Settings(_env_file=None, runtime_environment='production',
        generation_chain_anchor_path='/synthetic/anchor.json')
    current = [('0x'+f'{i+1:02x}'*20, '0x02'+f'{i+8:02x}'*32) for i in range(3)]
    monkeypatch.setattr(operations, 'current_signed_admins', lambda _: current)
    monkeypatch.setattr(operations, 'load_generation_read_anchor', lambda _:
        SimpleNamespace(administrator=SimpleNamespace(authority_launcher_id=bytes32(b'\x34'*32))))
    monkeypatch.setattr(operations, 'load_signed_public_artifact', forbid_legacy)
    roster = operations.resolve_admin_roster(settings)
    assert roster.launcher_id == bytes32(b'\x34'*32)
    assert roster.compressed_pubkeys == tuple(bytes.fromhex(row[1][2:]) for row in current)


@pytest.mark.parametrize('missing', ['context', 'anchor', 'administrator'])
def test_generation_failure_never_falls_back_to_legacy(monkeypatch, missing):
    settings = Settings(_env_file=None, runtime_environment='production',
        generation_chain_anchor_hash='0x'+'ab'*32)
    monkeypatch.setattr(operations, 'load_signed_public_artifact', forbid_legacy)
    def current(_):
        if missing == 'context': raise PublicArtifactMissing('fresh confirmed evidence unavailable')
        return [('0x'+f'{i+1:02x}'*20, '0x02'+f'{i+8:02x}'*32) for i in range(3)]
    def anchor(_):
        if missing == 'anchor': raise ValueError('anchor differs from reviewed hash')
        return SimpleNamespace(administrator=None)
    monkeypatch.setattr(operations, 'current_signed_admins', current)
    monkeypatch.setattr(operations, 'load_generation_read_anchor', anchor)
    with pytest.raises(ValueError): operations.resolve_admin_roster(settings)


@pytest.mark.asyncio
async def test_native_generation_prepare_sign_restart_execute_and_replay(core, tmp_path, monkeypatch):
    c = core; built = complete(c)[2]; settings = configuration(c, built, tmp_path)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    _, accounts = manifest()
    monkeypatch.setattr(operations, 'load_signed_public_artifact', forbid_legacy)
    async def start(): pass
    async def close(): pass
    c.provider.start = start; c.provider.close = close
    from solslot_api import app as main
    monkeypatch.setattr(main, 'create_chia_provider', lambda _: c.provider)
    admin_auth.reset_admin_state_for_tests()
    operation = None
    path = '/admin/collections/SYNTHETIC/seal'
    executed = []
    body = {'operation':'collection.seal', 'revision':13, 'expiresInSeconds':600,
        'requestBinding':{'method':'POST', 'path':path, 'query':[], 'body':{}, 'ifMatch':'"13"'}}
    try:
        with protected_files():
            for restart in range(2):
                app, _ = runtime(settings, monkeypatch)
                app.include_router(operations.router)
                # This probe is the approval guard, not a substitute for the
                # separately covered collection/media/pricing seal validators.
                @app.post(path, dependencies=[Depends(operations.require_admin_operation('collection.seal'))])
                async def protected():
                    executed.append(True)
                    return {'executed':True}
                async with app.router.lifespan_context(app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://test') as client:
                        auth=[]
                        for account in accounts:
                            login=await desk_sign_in(client, account)
                            auth.append({'Authorization':'Bearer '+login['jwt']})
                        if restart == 0:
                            assert (await client.post('/admin/auth/operations/prepare',json=body)).status_code == 401
                            prepared=await client.post('/admin/auth/operations/prepare',headers=auth[0],json=body)
                            assert prepared.status_code == 201, prepared.text
                            operation=prepared.json(); operation_id=operation['operationId']
                            assert operation['authorityLauncherId'] == '0x'+built.authority.authority_launcher_id.hex()
                            assert operation['requestBinding']['ifMatch'] == '"13"'
                            assert operation['expiresAt']-operation['createdAt'] == 600
                            assert operation['revision'] == 13
                            # Two coadmins cannot replace the owner.
                            for slot in (1,2):
                                signature='0x'+accounts[slot].sign_message(encode_typed_data(full_message=operation['typedData'])).signature.hex()
                                signed=await client.post(f'/admin/auth/operations/{operation_id}/sign',headers=auth[slot],json={'signature':signature})
                                assert signed.status_code == 200, signed.text
                                assert signed.json()['status'] == 'pending'
                            denied=await client.post(path,headers={**auth[1], 'If-Match':'"13"', 'X-Solslot-Admin-Operation-Id':operation_id},json={})
                            assert denied.status_code == 409 and not executed
                            signature='0x'+accounts[0].sign_message(encode_typed_data(full_message=operation['typedData'])).signature.hex()
                            wrong=await client.post(f'/admin/auth/operations/{operation_id}/sign',headers=auth[1],json={'signature':signature})
                            assert wrong.status_code == 409
                            signed=await client.post(f'/admin/auth/operations/{operation_id}/sign',headers=auth[0],json={'signature':signature})
                            assert signed.status_code == 200 and signed.json()['status'] == 'approved'
                        else:
                            operation_id=operation['operationId']
                            restored=await client.get(f'/admin/auth/operations/{operation_id}',headers=auth[0])
                            assert restored.status_code == 200 and restored.json()['status'] == 'approved'
                            assert len(restored.json()['signatures']) == 3
                            headers={**auth[0], 'If-Match':'"13"', 'X-Solslot-Admin-Operation-Id':operation_id}
                            snapshot=app.state.generation_admission.snapshot
                            app.state.generation_admission.snapshot=replace(snapshot,checked=time.monotonic()-MAX_ROSTER_AGE-1)
                            stale=await client.post(path,headers=headers,json={})
                            assert stale.status_code == 503 and not executed
                            app.state.generation_admission.snapshot=snapshot
                            wrong=await client.post(path,headers={**headers,'If-Match':'"14"'},json={})
                            assert wrong.status_code == 409 and not executed
                            good=await client.post(path,headers=headers,json={})
                            assert good.status_code == 200 and executed == [True], good.text
                            replay=await client.post(path,headers=headers,json={})
                            assert replay.status_code == 409 and executed == [True]
                            assert (await client.get('/admin/auth/operations',headers=auth[0])).json()['count'] == 0
                            assert (await client.get(f'/admin/auth/operations/{operation_id}',headers=auth[0])).json()['status'] == 'consumed'
    finally:
        admin_auth.reset_admin_state_for_tests()
