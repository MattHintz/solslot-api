"""Real confirmed-generation authority must admit its native property editor."""
import json
from pathlib import Path
import time

import httpx
import pytest
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from solslot_api import admin_auth
from solslot_api.collection_endpoints import router as collections
from solslot_api.collection_store import CollectionStore, reset_collection_store_for_tests
from solslot_api.generation_preparation_store import GenerationPreparationStore
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete
from tests.test_generation_preparation import manifest, signatures
from tests.test_generation_handoff import configuration, runtime, desk_sign_in, protected_files
from tests.test_generation_prelaunch_auth import sign_in


@pytest.mark.asyncio
async def test_confirmed_generation_can_author_test_edition_without_opening_legacy_operations(core, tmp_path, monkeypatch):
    monkeypatch.setattr('solslot_api.collection_generation_recovery.read_record_receipt',
        lambda settings: {'checkedAt': int(time.time()), 'restoredAt': int(time.time())})
    c = core
    built = complete(c)[2]
    settings = configuration(c, built, tmp_path)
    archive = tmp_path/'source-archive.sqlite'
    source = CollectionStore(archive)
    source.create(collection_id='SOURCE', title='Existing private property', owner_subject='owner', owner_auth_type='evm')
    source.close()
    original = archive.read_bytes()
    settings.collection_metadata_enabled = True
    settings.test_collection_editions_enabled = True
    settings.collection_source_archive_db_path = str(archive)
    settings.collection_source_archive_generation_id = 'prior-test-generation'
    settings.collection_storage_backend = 'filesystem'
    settings.collection_local_root = str(tmp_path/'private-test-media')
    settings.collection_local_base_url = 'https://test/media'
    settings.collection_ipfs_api_url = 'http://127.0.0.1:5001'
    settings.collection_ipfs_gateway_url = 'https://test/ipfs'
    settings.collection_ipfs_pinning_mode = 'kubo'
    settings.collection_malware_scan_backend = 'clamav'
    settings.collection_clamav_socket = str(tmp_path/'test-clamav.sock')
    settings.collection_clamav_policy_path = str(tmp_path/'test-scan-policy.json')
    settings.collection_asset_max_bytes = 20*1024*1024
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    _, accounts = manifest()
    with protected_files():
        prep = GenerationPreparationStore(settings.generation_preparation_db_path, c.prep)
        for row in c.evidence.recipients:
            prep.record_confirmation(row, int(time.time()))
        for slot, signature in signatures(c.prep, accounts).items():
            prep.acknowledge(slot, signature, int(time.time()))
        from solslot_api import app as main
        async def start(): pass
        async def close(): pass
        c.provider.start = start
        c.provider.close = close
        monkeypatch.setattr(main, 'create_chia_provider', lambda config:c.provider)
        admin_auth.reset_admin_state_for_tests()
        reset_collection_store_for_tests()
        try:
            app, _ = runtime(settings, monkeypatch)
            app.include_router(collections)
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://test') as client:
                    login = await desk_sign_in(client, accounts[0])
                    headers = {'Authorization':'Bearer '+login['jwt']}
                    feature = await client.get('/admin/collections/feature-status', headers=headers)
                    assert feature.status_code == 200, feature.text
                    assert feature.json()['generationId'] == c.prep.generation_id
                    source_info = await client.get('/admin/collection-source/SOURCE', headers=headers)
                    assert source_info.status_code == 200, source_info.text
                    info = source_info.json()
                    request = {'sourceCollectionId':'SOURCE','sourceRevision':info['revision'],'sourceDraftHash':info['draftHash']}
                    created = await client.post('/admin/collections/test-editions', headers=headers, json=request)
                    assert created.status_code == 200, created.text
                    workspace = created.json()
                    assert workspace['dossier']['purpose'] == 'TEST_ONLY'
                    assert workspace['dossier']['generationId'] == c.prep.generation_id
                    again = await client.post('/admin/collections/test-editions', headers=headers, json=request)
                    assert again.json() == workspace
                    identifier = workspace['id']
                    clean = await client.put('/admin/collections/'+identifier, headers={**headers,'If-Match':'"1"'}, json=workspace['dossier'])
                    assert clean.status_code == 200, clean.text
                    assert clean.json()['revision'] == 1
                    # Exercise the editor's actual convert-then-save pipeline.
                    # No legacy artifact or oracle is present in this generation.
                    conversion = await client.post('/admin/collections/display-units/convert', headers=headers, json={
                        'money': {'marketValue':'1550000','targetRaise':'75000','minimumInvestment':'3000'},
                        'percentages': {'technologyFee':'1'},
                        'ownershipShares': {f'deed.{i}':'4' for i in range(25)}, 'deriveXchPar':False})
                    assert conversion.status_code == 200, conversion.text
                    units = conversion.json()
                    assert units['governanceQuorum'] is None
                    assert units['xchParMojos'] is None and units['xchOracle'] is None
                    draft = clean.json()['dossier']
                    draft.update(title='127 Eastmoreland St — Testnet Edition',
                        fsreTerms={'participationBps':1500,'outsideTermMonths':14,'projectedMonthsMin':10,'projectedMonthsMax':12},
                        valuationBasis='TO_BE_BUILT', valuationEvidence='USER_CONFIRMED')
                    draft['valuation'] = {'currency':'USD','marketValueMinor':units['moneyMinor']['marketValue']}
                    draft['offering'] = {'currency':'USD','targetRaiseMinor':units['moneyMinor']['targetRaise'],
                        'minimumInvestmentMinor':units['moneyMinor']['minimumInvestment'],
                        'royaltyBps':units['percentageBps']['technologyFee']}
                    draft['deedAllocation'] = [{'deedId':f'EAST-T11-{i+1:03d}', 'sharePpm':units['ownershipPpm'][f'deed.{i}']} for i in range(25)]
                    saved = await client.put('/admin/collections/'+identifier, headers={**headers,'If-Match':'"1"'}, json=draft)
                    assert saved.status_code == 200, saved.text
                    saved = saved.json()
                    assert saved['revision'] == 2
                    assert saved['dossier']['offering']['targetRaiseMinor'] == '7500000'
                    assert saved['dossier']['valuation']['marketValueMinor'] == '155000000'
                    assert saved['dossier']['fsreTerms']['returnBasis'] == 'MARKET_VALUE'
                    assert 'governanceQuorum' not in saved['dossier']['offering']
                    assert 'debtBalanceMinor' not in saved['dossier'].get('capital', {})
                    repeated = await client.put('/admin/collections/'+identifier,
                        headers={**headers,'If-Match':'"2"'}, json=saved['dossier'])
                    assert repeated.status_code == 200 and repeated.json()['revision'] == 2
                    assert repeated.json()['auditEvents'] == saved['auditEvents']
                    # Pricing and chain authority remain separate, closed checks.
                    rejected_price = await client.post('/admin/collections/'+identifier+'/pricing/apply',
                        headers={**headers,'If-Match':'"2"'})
                    assert rejected_price.status_code == 422
                    assert (await client.post('/admin/collections/'+identifier+'/seal',
                        headers={**headers,'If-Match':'"2"'}, json={})).status_code == 428
                    # The metadata editor still requires a current generation JWT.
                    assert (await client.get('/admin/collections/feature-status')).status_code == 401
                    assert (await client.get('/admin/operations', headers=headers)).status_code == 403
                    assert (await client.get('/admin/collections-unrelated', headers=headers)).status_code == 403
                    await sign_in(client, accounts[0])
                    assert (await client.post('/admin/launch/plan/build', headers=headers, json={})).status_code == 403
                    # A valid token from the archived generation remains invalid.
                    legacy = settings.model_copy(update={'deployment_generation_id':None})
                    token, _ = admin_auth.issue_jwt(sub=accounts[0].address, auth_type='evm', settings=legacy,
                        authority_slot=0, compressed_pubkey='0x'+accounts[0]._key_obj.public_key.to_compressed_bytes().hex())
                    assert (await client.get('/admin/collections/feature-status', headers={'Authorization':'Bearer '+token})).status_code == 403
                    # No frozen or stale administrator roster can keep authoring open.
                    snapshot = app.state.generation_admission.snapshot
                    app.state.generation_admission.snapshot = None
                    stale = await client.get('/admin/collections/feature-status', headers=headers)
                    assert stale.status_code == 503
                    app.state.generation_admission.snapshot = snapshot
                    settings.collection_metadata_enabled = False
                    disabled = await client.post('/admin/collections/test-editions', headers=headers, json=request)
                    assert disabled.status_code == 503
            assert archive.read_bytes() == original
        finally:
            reset_collection_store_for_tests()
            admin_auth.reset_admin_state_for_tests()
