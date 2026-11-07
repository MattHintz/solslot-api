"""Synthetic inventory extension and actual SQLite restore; no live records."""
from contextlib import closing
from hashlib import sha256
from types import SimpleNamespace
import json,os,sqlite3
import pytest
from solslot_api.generation_storage import connect_generation_sqlite
from solslot_api.generation_recovery_storage import DATABASES,INVENTORY_HASH
from solslot_api.generation_customer_recovery import CUSTOMER_FIELDS,migrate_customer_recovery_inventory,canonical,digest

@pytest.fixture
def old_inventory(tmp_path):
    generation='0x'+'51'*32;root=tmp_path/'generations'/generation[2:];root.mkdir(parents=True,mode=0o700)
    previous=DATABASES-set(CUSTOMER_FIELDS.values());old_hash=digest(sorted(previous))
    for name in previous:
        with closing(connect_generation_sqlite(root/name,generation_id=generation)) as db,db:
            db.execute('CREATE TABLE retained_evidence(id INTEGER PRIMARY KEY, value BLOB)')
            db.execute('INSERT INTO retained_evidence VALUES(1,?)',(b'unchanged synthetic signed operation',))
            db.execute('CREATE TABLE generation_recovery_inventory(singleton INTEGER PRIMARY KEY,inventory_hash TEXT,stage TEXT)')
            db.execute("INSERT INTO generation_recovery_inventory VALUES(1,?,'READY')",(old_hash,))
    guard=tmp_path/'generation-recovery-initialization'/(generation[2:]+'.json');guard.parent.mkdir(mode=0o700)
    guard.write_bytes(canonical({'schema':'solslot.generation-recovery-initialization.v1','generationId':generation,'inventoryHash':old_hash}));guard.chmod(0o600)
    settings=SimpleNamespace(deployment_generation_id=generation,network='testnet11',generation_preparation_db_path=str(root/'generation-preparation.sqlite3'),
        **{field:str(root/name) for field,name in CUSTOMER_FIELDS.items()})
    return settings,root,guard,sha256(guard.read_bytes()).hexdigest(),previous

def test_explicit_transition_preserves_all_original_rows_and_can_resume(old_inventory):
    settings,root,guard,expected,previous=old_inventory
    result=migrate_customer_recovery_inventory(settings,expected_guard_sha256=expected)
    assert result['recordsPreserved'] and result['databaseCount']==24 and result['requiresFreshEncryptedRestore']
    assert json.loads(guard.read_bytes())['inventoryHash']==INVENTORY_HASH
    for name in previous:
        with closing(sqlite3.connect(root/name)) as db:
            assert db.execute('SELECT value FROM retained_evidence').fetchall()==[(b'unchanged synthetic signed operation',)]
            assert db.execute('SELECT inventory_hash,stage FROM generation_recovery_inventory').fetchall()==[(INVENTORY_HASH,'READY')]
    assert migrate_customer_recovery_inventory(settings,expected_guard_sha256=expected)==result

@pytest.mark.parametrize('fault',['wrong_guard','missing_old','wrong_generation','unexpected_file','redirected_new','changed_marker'])
def test_transition_rejects_changed_or_unreviewed_state(old_inventory,fault,tmp_path):
    settings,root,guard,expected,previous=old_inventory
    if fault=='wrong_guard':expected='0'*64
    if fault=='missing_old':(root/next(iter(previous))).unlink()
    if fault=='wrong_generation':settings.deployment_generation_id='0x'+'52'*32
    if fault=='unexpected_file':(root/'not-a-reviewed-journal').write_bytes(b'synthetic')
    if fault=='redirected_new':
        external=tmp_path/'outside';external.write_text('retained original');(root/'customer-fees.sqlite3').symlink_to(external)
    if fault=='changed_marker':
        with sqlite3.connect(root/next(iter(previous))) as db:db.execute("UPDATE generation_recovery_inventory SET stage='INITIALIZING'")
    with pytest.raises(ValueError):migrate_customer_recovery_inventory(settings,expected_guard_sha256=expected)
    assert not (root/'generation-customers.sqlite3').exists()

def test_crash_after_some_marker_commits_resumes_without_changing_user_records(old_inventory,monkeypatch):
    import solslot_api.generation_customer_recovery as recovery
    settings,root,guard,expected,previous=old_inventory;real=recovery.atomic
    def interrupted(path,value):
        if path==guard:raise OSError('synthetic interruption after SQLite commits')
        return real(path,value)
    monkeypatch.setattr(recovery,'atomic',interrupted)
    with pytest.raises(OSError):migrate_customer_recovery_inventory(settings,expected_guard_sha256=expected)
    monkeypatch.setattr(recovery,'atomic',real)
    assert migrate_customer_recovery_inventory(settings,expected_guard_sha256=expected)['recordsPreserved']

def test_transitioned_inventory_restores_all_24_real_journals(old_inventory,tmp_path):
    import importlib.util
    from pathlib import Path
    spec=importlib.util.spec_from_file_location('current_generation_snapshot',Path(__file__).parents[1]/'ops/generation-recovery-AE222/generation_snapshot.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    settings,root,guard,expected,previous=old_inventory
    migrate_customer_recovery_inventory(settings,expected_guard_sha256=expected)
    package=module.snapshot(root,settings.deployment_generation_id)
    result=module.verify_isolated_restore(package,settings.deployment_generation_id,parent=tmp_path)
    assert result['restoreMatches'] and result['databaseCount']==24
