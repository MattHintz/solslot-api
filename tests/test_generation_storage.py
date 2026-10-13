import sqlite3
from pathlib import Path
from importlib import import_module
from types import SimpleNamespace

import pytest

from solslot_api.config import Settings
from solslot_api.credential_ledger import CredentialLedger, get_credential_ledger, get_existing_credential_ledger, reset_credential_ledgers_for_tests
from solslot_api.genesis_store import GenesisStore
from solslot_api.generation_storage import bind_generation, generation_path, GenerationStorageError
from solslot_api.public_artifact import _verify_runtime_bindings, PublicArtifactError

GEN='0x'+'ab'*32
OTHER='0x'+'cd'*32


@pytest.mark.parametrize('store', [CredentialLedger, GenesisStore])
def test_database_generation_checked_before_migrations_or_retention(tmp_path, store):
    path=tmp_path/'state.db'
    first=store(path, generation_id=GEN)
    if hasattr(first,'close'): first.close()
    before=path.read_bytes()
    for generation in [OTHER,None]:
        with pytest.raises(GenerationStorageError, match='another deployment'):
            store(path, generation_id=generation)
        assert path.read_bytes()==before
    same=store(path, generation_id=GEN)
    if hasattr(same,'close'): same.close()


@pytest.mark.parametrize('store', [CredentialLedger, GenesisStore])
def test_existing_legacy_state_is_never_rebound(tmp_path, store):
    path=tmp_path/'archive.db'
    legacy=store(path)
    if hasattr(legacy,'close'): legacy.close()
    before=path.read_bytes()
    with pytest.raises(GenerationStorageError, match='existing database'):
        store(path, generation_id=GEN)
    assert path.read_bytes()==before


def test_credential_factories_cache_and_recover_only_their_generation(tmp_path):
    path=str(tmp_path/'credential.db')
    def settings(gen):return SimpleNamespace(zkpassport_ledger_db_path=path,deployment_generation_id=gen,network='testnet11')
    try:
        old=get_credential_ledger(settings(None))
        new=get_credential_ledger(settings(GEN))
        assert old is not new
        assert get_existing_credential_ledger(settings(OTHER)) is None
        assert get_existing_credential_ledger(settings(GEN)) is new
        assert new.path==generation_path(path,GEN)
    finally: reset_credential_ledgers_for_tests()


def test_ceremony_factory_preserves_old_file_and_uses_new_namespace(tmp_path):
    path=tmp_path/'ceremony.db'
    GenesisStore(path)
    before=path.read_bytes()
    new=GenesisStore.for_settings(Settings(runtime_environment='test',genesis_db_path=str(path),deployment_generation_id=GEN))
    assert new.path==generation_path(str(path),GEN)
    assert new.active() is None
    assert path.read_bytes()==before


def test_namespace_is_idempotent_and_rejects_misdirection():
    path=generation_path('/state/credentials.db',GEN)
    assert generation_path(path,GEN)==path
    with pytest.raises(GenerationStorageError):generation_path(path,OTHER)
    with pytest.raises(ValueError):generation_path('/state/credentials.db','0x'+'00'*32)
    db=sqlite3.connect(':memory:',isolation_level=None)
    with pytest.raises(GenerationStorageError):bind_generation(db,GEN,'mainnet')
    assert not db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    db.close()


def test_old_public_artifact_cannot_enable_new_generation_operations():
    for payload in [{}, {'deploymentGeneration':{'generationId':OTHER}}]:
        with pytest.raises(PublicArtifactError,match='deployment generation'):
            _verify_runtime_bindings(Settings(runtime_environment='test',deployment_generation_id=GEN),payload)


def test_all_runtime_state_is_namespaced_without_relocating_source_evidence(tmp_path):
    archive=str(tmp_path/'original-collection.db')
    common=dict(runtime_environment='test',collection_source_archive_db_path=archive,
        generation_preparation_path='/review/preparation.json',launch_source_evidence_path='/review/source.json')
    old=Settings(**common)
    new=Settings(**common,deployment_generation_id=GEN)
    for field in ('genesis_db_path','zkpassport_ledger_db_path','payment_purchase_db_path','stripe_delivery_db_path',
        'admin_db_path','generation_preparation_db_path','vault_registry_path','sols_capability_operations_path',
        'challenge_store_path','genesis_output_dir','deployment_manifest_path','public_artifact_path','bootstrap_manifest_path'):
        assert getattr(new,field)==generation_path(getattr(old,field),GEN)
    assert new.collection_source_archive_db_path==archive
    assert new.generation_preparation_path==old.generation_preparation_path
    assert new.launch_source_evidence_path==old.launch_source_evidence_path
    assert Settings.model_validate(new.model_dump()).model_dump()==new.model_dump()
    with pytest.raises(ValueError):Settings(**common,deployment_generation_id=GEN,network='mainnet')


@pytest.mark.parametrize('module,name',[
    ('payment_purchase_store','PaymentPurchaseStore'),('stripe_delivery_store','StripeDeliveryStore'),
    ('admin_operations','OperationStore'),('governance_queue','GovernanceQueueStore'),
    ('mint_proposals','MintProposalStore'),('protocol_funding_store','ProtocolFundingStore'),
    ('stamp_funding','StampFundingStore'),('sols_swap_store','SolsSwapStore'),
    ('validator_ledger','ValidatorLedger'),('funded_redemption_store','FundedRedemptionStore'),
    ('governed_output_index','GovernedOutputIndex'),('vault_db','VaultStore'),
])
def test_owned_stores_reject_copied_legacy_or_other_generation_before_migration(tmp_path,module,name):
    factory=getattr(import_module('solslot_api.'+module),name)
    target=Path(generation_path(str(tmp_path/'runtime.db'),GEN));target.parent.mkdir(parents=True)
    for marker in (None,OTHER):
        source=tmp_path/('original-'+str(marker is None)+'.db')
        with sqlite3.connect(source,isolation_level=None) as con:
            if marker:bind_generation(con,marker)
            con.execute('CREATE TABLE retained_evidence(receipt TEXT)')
            con.execute("INSERT INTO retained_evidence VALUES('already-submitted')")
        target.write_bytes(source.read_bytes());before=target.read_bytes()
        with pytest.raises(GenerationStorageError):factory(str(target))
        assert target.read_bytes()==before
        assert source.read_bytes()==before


def test_shared_store_connection_rejects_marker_even_if_copied_outside_namespace(tmp_path):
    from solslot_api.generation_storage import connect_generation_sqlite
    path=tmp_path/'misplaced.db'
    with sqlite3.connect(path,isolation_level=None) as con:bind_generation(con,GEN)
    before=path.read_bytes()
    with pytest.raises(GenerationStorageError):connect_generation_sqlite(path)
    assert path.read_bytes()==before


@pytest.mark.asyncio
async def test_new_generation_cannot_fall_through_historical_chain_builders():
    from fastapi import HTTPException
    from solslot_api.genesis import create_plan,_prepare_bundle,_broadcast_ceremony,GenesisConflict
    settings=Settings(runtime_environment='test',deployment_generation_id=GEN)
    class Unused:
        def __getattr__(self,name):raise AssertionError('legacy state or funding must not be accessed')
    with pytest.raises(HTTPException) as denied:await create_plan('ignored',Unused(),settings,Unused())
    assert denied.value.status_code==409
    with pytest.raises(GenesisConflict):await _prepare_bundle(settings,Unused())
    with pytest.raises(GenesisConflict):await _broadcast_ceremony('ignored',Unused(),settings,Unused(),gate_authorization={})


def test_collection_store_uses_one_normalized_generation_namespace(tmp_path):
    from solslot_api.collection_store import get_collection_store,reset_collection_store_for_tests
    root=tmp_path/'journals';settings=Settings(runtime_environment='test',deployment_generation_id=GEN,
        admin_db_path=str(root/'admin_desk_v2.db'))
    expected=Path(settings.admin_db_path).parent/'collections.sqlite'
    try:
        first=get_collection_store(settings)
        assert Path(first.path)==expected
        assert get_collection_store(Settings.model_validate(settings.model_dump())) is first
        assert not (expected.parent/'generations').exists()
        with sqlite3.connect(expected) as db:
            assert db.execute('SELECT generation_id,network FROM deployment_generation_binding').fetchall()==[(GEN,'testnet11')]
    finally:reset_collection_store_for_tests()


def test_generation_collection_memory_store_never_creates_a_file(tmp_path,monkeypatch):
    from solslot_api.collection_store import get_collection_store,reset_collection_store_for_tests
    monkeypatch.chdir(tmp_path)
    try:
        store=get_collection_store(Settings(runtime_environment='test',deployment_generation_id=GEN,admin_db_path=':memory:'))
        assert store.path==':memory:'
        assert not list(tmp_path.iterdir())
    finally:reset_collection_store_for_tests()
