"""Real lifespan and lazy collection/telemetry stores, not an invented file list."""
from types import SimpleNamespace
from pathlib import Path
import os
import pytest
from fastapi import FastAPI
from solslot_api import app as app_module
from solslot_api.config import Settings
from solslot_api.collection_store import get_collection_store,reset_collection_store_for_tests
from solslot_api.alpha_observability import get_alpha_observability_store
from solslot_api.submission_errors import record_submission
from generation_snapshot import snapshot,verify_isolated_restore,DATABASES

GEN='0x'+'71'*32


@pytest.fixture
def private_umask():
    # The reviewed service installs its private state with UMask=0077.
    previous=os.umask(0o077)
    try:yield
    finally:os.umask(previous)


@pytest.mark.asyncio
@pytest.mark.parametrize('complete',[False,True])
async def test_actual_startup_and_lazy_journals_have_recoverable_paths(tmp_path,monkeypatch,complete,private_umask):
    base=tmp_path/'journals'
    defaults=Settings(_env_file=None,runtime_environment='test')
    fields=['genesis_db_path','zkpassport_ledger_db_path','payment_purchase_db_path','stripe_delivery_db_path',
        'admin_db_path','generation_preparation_db_path','generation_launch_db_path','generation_index_db_path',
        'generation_operations_db_path','generation_consents_db_path','generation_ballots_db_path',
        'generation_mint_reviews_db_path','generation_sols_orders_db_path','vault_registry_path',
        'sols_capability_operations_path','challenge_store_path']
    paths={name:str(base/Path(getattr(defaults,name)).name) for name in fields}
    preparation={};identity=GEN
    if complete:
        from tests.test_generation_preparation import manifest
        model,_=manifest();identity=model.generation_id
        source=tmp_path/'preparation.json';source.write_text(model.model_dump_json(by_alias=True))
        preparation={'generation_recovery_storage_enabled':True,'generation_preparation_path':str(source),
            'generation_preparation_hash':model.manifest_hash}
    settings=Settings(_env_file=None,runtime_environment='test',network='testnet11',deployment_generation_id=identity,
        **paths,public_artifact_path=str(tmp_path/'artifacts/public_artifact_v4.json'),
        faucet_seed_hex=None,faucet_master_sk_hex=None,faucet_mnemonic=None,
        protocol_fee_funding_enabled=False,ceremony_mode_enabled=False,admin_enabled=False,**preparation)
    created=[]
    class Node:
        def __init__(self,config):self.config=config
        async def start(self):pass
        async def close(self):pass
    def provider(config):
        node=Node(config);created.append(node);return node
    monkeypatch.setattr(app_module,'get_settings',lambda:settings)
    monkeypatch.setattr(app_module,'create_chia_provider',provider)
    # This test exercises actual constructors and paths; production security
    # configuration validation has separate acceptance suites. No network/key.
    monkeypatch.setattr(app_module,'validate_runtime_environment_namespace',lambda:None)
    monkeypatch.setattr(app_module,'validate_secret_env_file_permissions',lambda:None)
    monkeypatch.setattr(app_module,'validate_server_hardening_at_startup',lambda _:None)
    monkeypatch.setattr(app_module,'validate_admin_config_at_startup',lambda _:None)
    app=FastAPI();root=Path(settings.zkpassport_ledger_db_path).parent
    try:
        async with app_module.lifespan(app):
            # These two files are created by the actual lifespan, regardless of
            # whether a signing feature is currently enabled.
            assert Path(app.state.protocol_funding_store.path).parent==root
            assert Path(app.state.stamp_funding_store.path).parent==root
            # Normal submission and UI telemetry/collection dependencies create
            # the other derived journals. No arbitrary-path fixtures are used.
            record_submission(created[0].config.submission_journal_path,network='testnet11',
                bundle_id='0x'+'72'*32,provider='local-full-node',event='synthetic')
            telemetry=get_alpha_observability_store(settings)
            collection=get_collection_store(settings)
            assert Path(collection.path)==root/'collections.sqlite'
            assert Path(telemetry.path).parent==root
            assert not (root/'generations').exists()
            package=snapshot(root,identity)
            names=set(package['manifest']['files'])
            assert {'zkpassport_v2.db.stamp-funding.sqlite3','protocol-submissions.sqlite3',
                'admin_desk_v2.db.alpha-observability.db','collections.sqlite'}.issubset(names)
            assert names.issubset(DATABASES)
            if complete:
                from solslot_api.generation_recovery_storage import DATABASES as REQUIRED
                assert names==DATABASES==REQUIRED
                assert app.state.generation_launch is None
                assert app.state.generation_index is None
                assert app.state.generation_sols_orders is None
                # Provisioning schemas cannot invent reviews, votes, offers,
                # confirmations, or release/recovery certification.
                for name in ('generation-launch.sqlite3','generation-index.sqlite3','generation-sols-orders.sqlite3'):
                    assert all(n==0 for table,n in package['manifest']['files'][name]['rowCounts'].items()
                        if table not in ('deployment_generation_binding','generation_recovery_inventory'))
            evidence=verify_isolated_restore(package,identity,parent=tmp_path)
            assert evidence['restoreMatches'] and evidence['databaseCount']==len(names)
            assert package['manifest']['files']['protocol-submissions.sqlite3']['rowCounts']['protocol_submission_events']==1
            if complete:
                from solslot_api.generation_recovery_storage import prepare_recovery_journals
                prepare_recovery_journals(settings,app.state.generation_preparation)
                assert snapshot(root,identity)==package
    finally:
        reset_collection_store_for_tests()
        import solslot_api.alpha_observability as alpha
        if alpha._store is not None:
            alpha._store._conn.close();alpha._store=None


@pytest.mark.parametrize('fault',['missing-preparation','different-generation','different-manifest',
    'custom-path','memory','group-writable','symlink','hardlink','old-ledger','foreign-ledger','unexpected-file',
    'sidecar-symlink','sidecar-hardlink','sidecar-writable'])
def test_schema_preflight_rejects_unsafe_or_unreviewed_state_without_rewriting_it(tmp_path,private_umask,fault):
    import sqlite3
    from hashlib import sha256
    from solslot_api.generation_preparation_store import GenerationPreparationStore
    from solslot_api.generation_recovery_storage import FIELDS,prepare_recovery_journals
    from tests.test_generation_preparation import manifest
    model,_=manifest()
    paths={field:str(tmp_path/'journals'/name) for field,name in FIELDS.items()}
    settings=Settings(_env_file=None,runtime_environment='test',network='testnet11',
        deployment_generation_id=model.generation_id,generation_preparation_hash=model.manifest_hash,**paths)
    store=GenerationPreparationStore(settings.generation_preparation_db_path,model)
    root=Path(store.path).parent
    if fault=='missing-preparation':store=None
    elif fault=='different-generation':settings.deployment_generation_id=GEN
    elif fault=='different-manifest':settings.generation_preparation_hash=GEN
    elif fault=='custom-path':settings.admin_db_path=str(tmp_path/'other.db')
    elif fault=='memory':settings.admin_db_path=':memory:'
    elif fault=='group-writable':root.chmod(0o770)
    elif fault in ('symlink','hardlink','sidecar-symlink','sidecar-hardlink'):
        target=tmp_path/'held-original';target.write_bytes(b'synthetic held evidence')
        name='zkpassport_v2.db-wal' if fault.startswith('sidecar') else 'zkpassport_v2.db'
        if fault.endswith('symlink'):(root/name).symlink_to(target)
        else:os.link(target,root/name)
    elif fault=='sidecar-writable':
        sidecar=root/'zkpassport_v2.db-wal';sidecar.write_bytes(b'synthetic unsafe sidecar');sidecar.chmod(0o660)
    elif fault in ('old-ledger','foreign-ledger'):
        with sqlite3.connect(root/'zkpassport_v2.db') as db:
            if fault=='old-ledger':db.execute('CREATE TABLE held_business_evidence(original BLOB)')
            else:
                db.execute('CREATE TABLE deployment_generation_binding(singleton INTEGER PRIMARY KEY,generation_id TEXT,network TEXT)')
                db.execute('INSERT INTO deployment_generation_binding VALUES(1,?,?)',(GEN,'testnet11'))
    else:(root/'not-a-journal.db').write_bytes(b'synthetic retained original')
    before={p.name:sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
    with pytest.raises(ValueError):prepare_recovery_journals(settings,store)
    after={p.name:sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
    assert after==before


def schema_setup(tmp_path):
    from solslot_api.generation_preparation_store import GenerationPreparationStore
    from solslot_api.generation_recovery_storage import FIELDS
    from tests.test_generation_preparation import manifest
    model,_=manifest()
    settings=Settings(_env_file=None,runtime_environment='test',network='testnet11',
        deployment_generation_id=model.generation_id,generation_preparation_hash=model.manifest_hash,
        **{field:str(tmp_path/'journals'/name) for field,name in FIELDS.items()})
    store=GenerationPreparationStore(settings.generation_preparation_db_path,model)
    return settings,store,Path(store.path).parent


@pytest.mark.parametrize('lost',['generation-preparation.sqlite3','generation-sols-orders.sqlite3',
    'generation-operations.sqlite3','zkpassport_v2.db.protocol-funding.sqlite3','all'])
def test_completed_initialization_never_recreates_lost_journals(tmp_path,private_umask,lost):
    from solslot_api.generation_recovery_storage import prepare_recovery_journals,DATABASES
    settings,store,root=schema_setup(tmp_path)
    prepare_recovery_journals(settings,store)
    targets=DATABASES if lost=='all' else {lost}
    for name in targets:
        (root/name).unlink()  # Synthetic lost-state fault; never real evidence.
        for suffix in ('-wal','-shm','-journal'):
            (root/(name+suffix)).unlink(missing_ok=True)
    with pytest.raises(ValueError,match='restore retained state'):
        prepare_recovery_journals(settings,store)
    assert all(not (root/name).exists() for name in targets)
    if lost=='generation-preparation.sqlite3':
        # The ordinary startup constructor runs before the inventory guard.
        # Its empty replacement must not turn a failed boot into healthy backup.
        from solslot_api.generation_preparation_store import GenerationPreparationStore
        from generation_replication import replicate
        from test_generation_replication import Azure,KEY,SOURCE
        recreated=GenerationPreparationStore(settings.generation_preparation_db_path,store.preparation)
        with pytest.raises(ValueError,match='restore retained state'):
            prepare_recovery_journals(settings,recreated)
        package=snapshot(root,settings.deployment_generation_id);azure=Azure()
        assert set(package['manifest']['files'])==DATABASES
        with pytest.raises(ValueError,match='INITIALIZATION_INCOMPLETE'):
            replicate(package,azure,KEY,settings.deployment_generation_id,SOURCE,parent=tmp_path)
        assert azure.puts==0


@pytest.mark.parametrize('flag',['alpha_writes_enabled','generation_execution_enabled',
    'generation_launch_enabled','generation_sols_batch_enabled'])
def test_first_initialization_requires_paused_write_gates(tmp_path,private_umask,flag):
    from solslot_api.generation_recovery_storage import prepare_recovery_journals
    settings,store,root=schema_setup(tmp_path)
    setattr(settings,flag,True)
    with pytest.raises(ValueError,match='paused prelaunch write gates'):
        prepare_recovery_journals(settings,store)
    assert set(p.name for p in root.iterdir())=={'generation-preparation.sqlite3'}


@pytest.mark.parametrize('phase',['schemas','ready','ready-then-loss'])
def test_interrupted_initialization_can_resume_but_cannot_reset_completed_journals(tmp_path,private_umask,monkeypatch,phase):
    import solslot_api.generation_recovery_storage as recovery
    from solslot_api.generation_sols_batches import GenerationSolsOrderBook
    settings,store,root=schema_setup(tmp_path)
    with monkeypatch.context() as patch:
        if phase=='schemas':
            def stop(*args):raise RuntimeError('synthetic schema interruption')
            patch.setattr(GenerationSolsOrderBook,'initialize_storage',stop)
        else:
            mark=recovery._mark
            def stop(path,generation,stage):
                mark(path,generation,stage)
                if stage=='READY':raise RuntimeError('synthetic ready interruption')
            patch.setattr(recovery,'_mark',stop)
        with pytest.raises(RuntimeError,match='synthetic'):
            recovery.prepare_recovery_journals(settings,store)
    if phase=='ready-then-loss':
        (root/'generation-sols-orders.sqlite3').unlink()
        with pytest.raises(ValueError,match='restore retained state'):
            recovery.prepare_recovery_journals(settings,store)
        assert not (root/'generation-sols-orders.sqlite3').exists()
    else:
        recovery.prepare_recovery_journals(settings,store)
        package=snapshot(root,settings.deployment_generation_id)
        assert set(package['manifest']['files'])==DATABASES
        assert verify_isolated_restore(package,settings.deployment_generation_id,parent=tmp_path)['restoreMatches']


def test_complete_isolated_restore_reconstructs_only_metadata_guard(tmp_path,private_umask):
    import base64
    from solslot_api.generation_recovery_storage import FIELDS,prepare_recovery_journals
    from solslot_api.generation_preparation_store import GenerationPreparationStore
    settings,store,root=schema_setup(tmp_path/'source')
    prepare_recovery_journals(settings,store)
    package=snapshot(root,settings.deployment_generation_id)
    restored_settings=Settings(_env_file=None,runtime_environment='test',network='testnet11',
        deployment_generation_id=settings.deployment_generation_id,generation_preparation_hash=store.preparation.manifest_hash,
        **{field:str(tmp_path/'restored'/'journals'/name) for field,name in FIELDS.items()})
    destination=Path(restored_settings.generation_preparation_db_path).parent
    destination.mkdir(parents=True,mode=0o700)
    for name,record in package['manifest']['files'].items():
        (destination/name).write_bytes(base64.b64decode(package['payloads'][record['sha256']]))
    restored=GenerationPreparationStore(restored_settings.generation_preparation_db_path,store.preparation)
    guard=destination.parent.parent/'generation-recovery-initialization'
    assert not guard.exists()
    prepare_recovery_journals(restored_settings,restored)
    assert guard.is_dir() and len(list(guard.iterdir()))==1
    assert snapshot(destination,settings.deployment_generation_id)==package


@pytest.mark.parametrize('fault',['missing-marker','foreign-marker','guard-corrupt','guard-symlink'])
def test_initialized_binding_or_guard_corruption_cannot_restart_empty(tmp_path,private_umask,fault):
    import sqlite3
    from solslot_api.generation_recovery_storage import prepare_recovery_journals
    settings,store,root=schema_setup(tmp_path)
    prepare_recovery_journals(settings,store)
    guard=root.parent.parent/'generation-recovery-initialization'/(settings.deployment_generation_id[2:]+'.json')
    if fault=='guard-corrupt':guard.write_text('{}')
    elif fault=='guard-symlink':
        target=tmp_path/'held-synthetic-guard';target.write_bytes(guard.read_bytes());guard.unlink();guard.symlink_to(target)
    else:
        with sqlite3.connect(root/'generation-sols-orders.sqlite3') as db:
            if fault=='missing-marker':db.execute('DROP TABLE generation_recovery_inventory')
            else:db.execute('UPDATE generation_recovery_inventory SET inventory_hash=?',('f'*64,))
    with pytest.raises(ValueError):prepare_recovery_journals(settings,store)
