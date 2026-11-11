from contextlib import closing
from copy import deepcopy
from hashlib import sha256
import base64
import json
from pathlib import Path
import sqlite3
import threading

import pytest
from generation_snapshot import snapshot, verify_isolated_restore, canonical, inspect_database
from solslot_api.generation_storage import connect_generation_sqlite

GEN = '0x'+'11'*32
OTHER = '0x'+'22'*32


def namespace(tmp_path):
    root = tmp_path/'generations'/GEN[2:]
    root.mkdir(parents=True,mode=0o700)
    return root


def database(root, name='generation-operations.sqlite3', generation=GEN):
    path = root/name
    con = connect_generation_sqlite(str(path),generation_id=generation,isolation_level=None)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY, value BLOB)')
    con.execute('INSERT INTO evidence VALUES (1,?)',(b'exact signed bundle',))
    return con


def test_committed_wal_and_exact_bytes_survive_independent_restore(tmp_path):
    root = namespace(tmp_path)
    with closing(database(root)) as con:
        # Keep the writer open, leaving committed evidence in the WAL.
        con.execute('INSERT INTO evidence VALUES (2,?)',(b'committed after DB creation',))
        first = snapshot(root,GEN)
        assert (root/'generation-operations.sqlite3-wal').stat().st_size>0
        assert first['manifest']['files']['generation-operations.sqlite3']['rowCounts']['evidence']==2
        assert snapshot(root,GEN)==first
        assert con.execute('SELECT count(*) FROM evidence').fetchone()==(2,)
    restore = verify_isolated_restore(first,GEN,parent=tmp_path)
    assert restore['restoreMatches'] and restore['databaseCount']==1
    assert restore['manifestSha256']==sha256(canonical(first['manifest'])).hexdigest()
    assert not list(tmp_path.glob('generation-restore-*'))


def test_multiple_database_snapshot_pins_one_cut_and_readers_remain_usable(tmp_path):
    root = namespace(tmp_path)
    with closing(database(root)) as a, closing(database(root,'generation-sols-orders.sqlite3')) as b:
        result = snapshot(root,GEN)
        a.execute('INSERT INTO evidence VALUES (2,?)',(b'later transaction',))
        assert all(row['rowCounts']['evidence']==1 for row in result['manifest']['files'].values())
        assert snapshot(root,GEN)['manifest']['files']['generation-operations.sqlite3']['rowCounts']['evidence']==2
    assert verify_isolated_restore(result,GEN,parent=tmp_path)['databaseCount']==2


@pytest.mark.parametrize('fault',['old_namespace','wrong_generation','unbound','unknown_file','symlink','hardlink','writable_directory','corrupt'])
def test_export_fails_closed_without_exporting_legacy_or_arbitrary_state(tmp_path,fault):
    root=namespace(tmp_path)
    if fault=='wrong_generation':
        # An old file placed in a new namespace must not receive a marker.
        old=tmp_path/'legacy.sqlite3'
        with sqlite3.connect(old) as con:
            con.execute('CREATE TABLE deployment_generation_binding(singleton,generation_id,network)')
            con.execute('INSERT INTO deployment_generation_binding VALUES (1,?,?)',(OTHER,'testnet11'))
        (root/'generation-operations.sqlite3').write_bytes(old.read_bytes())
    elif fault=='unbound':
        with sqlite3.connect(root/'generation-operations.sqlite3') as con:con.execute('CREATE TABLE legacy_evidence(x)')
    else:
        with closing(database(root)):pass
    if fault=='old_namespace':root=tmp_path
    elif fault=='unknown_file':(root/'credentials.json').write_text('{}')
    elif fault=='symlink':
        p=root/'generation-operations.sqlite3';p.rename(tmp_path/'private.sqlite3');p.symlink_to(tmp_path/'private.sqlite3')
    elif fault=='hardlink':(tmp_path/'alias').hardlink_to(root/'generation-operations.sqlite3')
    elif fault=='writable_directory':root.chmod(0o777)
    elif fault=='corrupt':(root/'generation-operations.sqlite3').write_bytes(b'not SQLite')
    with pytest.raises((ValueError,sqlite3.Error)):
        snapshot(root,GEN)


@pytest.mark.parametrize('fault',['binding','digest','schema','count','filename','missing_payload','extra_payload','content'])
def test_restore_rejects_tampering_and_cross_generation_replay(tmp_path,fault):
    root=namespace(tmp_path)
    with closing(database(root)):pass
    package=snapshot(root,GEN);changed=deepcopy(package)
    name='generation-operations.sqlite3';record=changed['manifest']['files'][name]
    if fault=='binding':changed['manifest']['generationId']=OTHER
    elif fault=='digest':record['sha256']='ff'*32
    elif fault=='schema':record['schemaSha256']='ff'*32
    elif fault=='count':record['rowCounts']['evidence']=0
    elif fault=='filename':changed['manifest']['files']['../private.db']=changed['manifest']['files'].pop(name)
    elif fault=='missing_payload':changed['payloads'].clear()
    elif fault=='extra_payload':changed['payloads']['ff'*32]='AA=='
    elif fault=='content':changed['payloads'][record['sha256']]=base64.b64encode(b'changed').decode()
    with pytest.raises((ValueError,sqlite3.Error)):
        verify_isolated_restore(changed,GEN,parent=tmp_path)


def test_busy_writer_never_claims_healthy_partial_backup(tmp_path):
    root=namespace(tmp_path)
    with closing(database(root)) as con:
        con.execute('BEGIN IMMEDIATE')
        with pytest.raises(sqlite3.OperationalError,match='locked'):
            snapshot(root,GEN)
        con.execute('ROLLBACK')
    assert verify_isolated_restore(snapshot(root,GEN),GEN,parent=tmp_path)['restoreMatches']
