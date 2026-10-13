"""Real lifespan and lazy collection/telemetry stores, not an invented file list."""
from types import SimpleNamespace
from pathlib import Path
import pytest
from fastapi import FastAPI
from solslot_api import app as app_module
from solslot_api.config import Settings
from solslot_api.collection_store import get_collection_store,reset_collection_store_for_tests
from solslot_api.alpha_observability import get_alpha_observability_store
from solslot_api.submission_errors import record_submission
from generation_snapshot import snapshot,verify_isolated_restore,DATABASES

GEN='0x'+'71'*32


@pytest.mark.asyncio
async def test_actual_startup_and_lazy_journals_have_recoverable_paths(tmp_path,monkeypatch):
    base=tmp_path/'journals'
    defaults=Settings(_env_file=None,runtime_environment='test')
    fields=['genesis_db_path','zkpassport_ledger_db_path','payment_purchase_db_path','stripe_delivery_db_path',
        'admin_db_path','generation_preparation_db_path','generation_launch_db_path','generation_index_db_path',
        'generation_operations_db_path','generation_consents_db_path','generation_ballots_db_path',
        'generation_mint_reviews_db_path','generation_sols_orders_db_path','vault_registry_path',
        'sols_capability_operations_path','challenge_store_path']
    paths={name:str(base/Path(getattr(defaults,name)).name) for name in fields}
    settings=Settings(_env_file=None,runtime_environment='test',network='testnet11',deployment_generation_id=GEN,
        **paths,public_artifact_path=str(tmp_path/'artifacts/public_artifact_v4.json'),
        faucet_seed_hex=None,faucet_master_sk_hex=None,faucet_mnemonic=None,
        protocol_fee_funding_enabled=False,ceremony_mode_enabled=False,admin_enabled=False)
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
            package=snapshot(root,GEN)
            names=set(package['manifest']['files'])
            assert {'zkpassport_v2.db.stamp-funding.sqlite3','protocol-submissions.sqlite3',
                'admin_desk_v2.db.alpha-observability.db','collections.sqlite'}.issubset(names)
            assert names.issubset(DATABASES)
            evidence=verify_isolated_restore(package,GEN,parent=tmp_path)
            assert evidence['restoreMatches'] and evidence['databaseCount']==len(names)
            assert package['manifest']['files']['protocol-submissions.sqlite3']['rowCounts']['protocol_submission_events']==1
    finally:
        reset_collection_store_for_tests()
        import solslot_api.alpha_observability as alpha
        if alpha._store is not None:
            alpha._store._conn.close();alpha._store=None
