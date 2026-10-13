"""Bounded generation-only SQLite snapshots; no arbitrary file export.

SQLite write reservations briefly establish one cut across the named databases.
Readers then pin that cut and the reservations are released before copying.
Recovery contains no signing keys. It never opens an old-generation namespace.
"""
from __future__ import annotations
from contextlib import ExitStack, closing
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time

HEX = re.compile(r'[0-9a-f]{64}\Z')
DATABASES = frozenset({
    'genesis_ceremony_v2.db', 'zkpassport_v2.db', 'payment_purchases_v2.db',
    'stripe_deliveries_v1.db', 'admin_desk_v2.db', 'vault_registry_v2.db',
    'sols_capability_operations.db', 'challenges_v2.db',
    'zkpassport_v2.db.protocol-funding.sqlite3', 'zkpassport_v2.db.stamp-funding.sqlite3',
    'protocol-submissions.sqlite3', 'admin_desk_v2.db.alpha-observability.db', 'collections.sqlite',
    'generation-preparation.sqlite3', 'generation-launch.sqlite3',
    'generation-index.sqlite3', 'generation-operations.sqlite3',
    'generation-consents.sqlite3', 'generation-ballots.sqlite3',
    'generation-mint-reviews.sqlite3', 'generation-sols-orders.sqlite3',
})
MAX_DATABASE = 256 * 1024**2
MAX_TOTAL = 512 * 1024**2
MAX_MANIFEST = 1024 * 1024
INVENTORY_HASH=sha256(json.dumps(sorted(DATABASES),separators=(',',':')).encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def generation(value):
    if not isinstance(value, str) or not value.startswith('0x') or not HEX.fullmatch(value[2:]) or value == '0x'+'00'*32:
        raise ValueError('GENERATION_BINDING_INVALID')
    return value[2:]


def protected_path(path, *, directory=False):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('RECOVERY_PATH_MUST_BE_ABSOLUTE')
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError('RECOVERY_SYMLINK_REJECTED')
    info = path.stat()
    if directory:
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('RECOVERY_DIRECTORY_NOT_PROTECTED')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > MAX_DATABASE:
        raise ValueError('RECOVERY_DATABASE_NOT_BOUNDED')
    return info


def namespace(root, generation_id):
    root = Path(root)
    if root.name != generation(generation_id) or root.parent.name != 'generations':
        raise ValueError('RECOVERY_NAMESPACE_DIFFERS')
    protected_path(root, directory=True)
    return root


def inventory(root):
    names = set()
    for entry in root.iterdir():
        if entry.name in DATABASES:
            protected_path(entry)
            names.add(entry.name)
        elif any(entry.name == name+suffix for name in DATABASES for suffix in ('-wal', '-shm', '-journal')):
            protected_path(entry)
        else:
            # Artifacts and non-database output are backed by a distinct pinned
            # artifact lane; never silently omit an unexpected database/file.
            raise ValueError('RECOVERY_UNEXPECTED_NAMESPACE_ENTRY')
    if not names:
        raise ValueError('RECOVERY_NO_GENERATION_DATABASES')
    return sorted(names)


def connect(path, *, writable=False):
    con = sqlite3.connect(path.as_uri() + ('?mode=rw' if writable else '?mode=ro'), uri=True,
                          timeout=2, isolation_level=None)
    con.execute('PRAGMA trusted_schema=OFF')
    if not writable:
        con.execute('PRAGMA query_only=ON')
    return con


def inspect_database(con, generation_id):
    con.execute('PRAGMA trusted_schema=OFF')
    if con.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise ValueError('RECOVERY_SQLITE_INTEGRITY_FAILED')
    try:
        rows = con.execute('SELECT singleton,generation_id,network FROM deployment_generation_binding').fetchall()
    except sqlite3.Error as exc:
        raise ValueError('RECOVERY_DATABASE_HAS_NO_GENERATION') from exc
    if rows != [(1, generation_id, 'testnet11')]:
        raise ValueError('RECOVERY_DATABASE_GENERATION_DIFFERS')
    schemas = con.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    # sqlite_master text is retained as data only, never executed during restore.
    counts = {}
    for kind, name, _, _ in schemas:
        if kind == 'table':
            counts[name] = con.execute('SELECT count(*) FROM "'+name.replace('"', '""')+'"').fetchone()[0]
    state=None
    if 'generation_recovery_inventory' in counts:
        rows=con.execute('SELECT singleton,inventory_hash,stage FROM generation_recovery_inventory').fetchall()
        if len(rows)!=1 or rows[0][0]!=1 or rows[0][1]!=INVENTORY_HASH or rows[0][2] not in ('INITIALIZING','READY'):
            raise ValueError('RECOVERY_INITIALIZATION_MARKER_DIFFERS')
        state=rows[0][2]
    return {'schemaSha256': sha256(canonical(schemas)).hexdigest(), 'rowCounts': counts,'inventoryState':state}


def snapshot(root, generation_id, *, clock=time.monotonic, timeout=45):
    root = namespace(root, generation_id)
    names = inventory(root)
    deadline = clock()+timeout
    payloads = {}
    files = {}
    with ExitStack() as reservations, ExitStack() as readers:
        locks = []
        for name in names:
            if clock() >= deadline:
                raise TimeoutError('RECOVERY_SNAPSHOT_BUSY')
            con = reservations.enter_context(closing(connect(root/name, writable=True)))
            con.execute('BEGIN IMMEDIATE')
            locks.append(con)
        sources = {}
        for name in names:
            con = readers.enter_context(closing(connect(root/name)))
            con.execute('BEGIN')
            # Force a read while all writers are held, even for a lazy SQLite BEGIN.
            binding = con.execute('SELECT generation_id,network FROM deployment_generation_binding').fetchall()
            if binding != [(generation_id, 'testnet11')]:
                raise ValueError('RECOVERY_DATABASE_GENERATION_DIFFERS')
            con.set_progress_handler(lambda: int(clock() >= deadline), 10000)
            sources[name] = con
        if inventory(root) != names:
            raise ValueError('RECOVERY_NAMESPACE_CHANGED')
        for con in locks:
            con.execute('ROLLBACK')
        for name, con in sources.items():
            # A reader transaction pins each WAL snapshot. This copies committed
            # WAL pages; copying the .db file alone would lose recent writes.
            dest = sqlite3.connect(':memory:', isolation_level=None)
            try:
                def progress(status, remaining, total):
                    if clock() >= deadline:
                        raise TimeoutError('RECOVERY_SNAPSHOT_BUSY')
                    if total*page_size > MAX_DATABASE:
                        raise ValueError('RECOVERY_DATABASE_TOO_LARGE')
                page_size = con.execute('PRAGMA page_size').fetchone()[0]
                if con.execute('PRAGMA page_count').fetchone()[0]*page_size > MAX_DATABASE:
                    raise ValueError('RECOVERY_DATABASE_TOO_LARGE')
                con.backup(dest, pages=256, progress=progress, sleep=0.01)
                dest.set_progress_handler(lambda: int(clock() >= deadline), 10000)
                info = inspect_database(dest, generation_id)
                raw = dest.serialize()
            finally:
                dest.close()
            if len(raw) > MAX_DATABASE or sum(v['bytes'] for v in files.values())+len(raw)>MAX_TOTAL:
                raise ValueError('RECOVERY_CAPACITY_REVIEW_REQUIRED')
            digest = sha256(raw).hexdigest()
            files[name] = {'sha256': digest, 'bytes': len(raw), **info}
            payloads[digest] = base64.b64encode(raw).decode()
    manifest = {'schema': 'solslot.generation-snapshot.v1', 'entity': 'SOLSLOT',
                'network': 'testnet11', 'generationId': generation_id, 'files': files}
    if len(canonical(manifest)) > MAX_MANIFEST:
        raise ValueError('RECOVERY_MANIFEST_TOO_LARGE')
    return {'manifest': manifest, 'payloads': payloads}


def validate_export(package, generation_id):
    if not isinstance(package, dict) or set(package) != {'manifest', 'payloads'}:
        raise ValueError('RECOVERY_EXPORT_DIFFERS')
    m = package['manifest']
    if not isinstance(m, dict) or set(m) != {'schema','entity','network','generationId','files'} or (
        m['schema'] != 'solslot.generation-snapshot.v1' or m['entity'] != 'SOLSLOT'
        or m['network'] != 'testnet11' or m['generationId'] != generation_id):
        raise ValueError('RECOVERY_EXPORT_BINDING_DIFFERS')
    generation(generation_id)
    files = m['files']
    if not isinstance(files, dict) or not files or not set(files).issubset(DATABASES):
        raise ValueError('RECOVERY_FILE_INVENTORY_DIFFERS')
    used = 0
    for name, entry in files.items():
        if not isinstance(entry, dict) or set(entry) != {'sha256','bytes','schemaSha256','rowCounts','inventoryState'} or (
            type(entry['bytes']) is not int or not 0 < entry['bytes'] <= MAX_DATABASE
            or not isinstance(entry['sha256'], str) or not HEX.fullmatch(entry['sha256'])
            or not isinstance(entry['schemaSha256'], str) or not HEX.fullmatch(entry['schemaSha256'])):
            raise ValueError('RECOVERY_FILE_COMMITMENT_DIFFERS')
        if entry['inventoryState'] not in (None,'INITIALIZING','READY'):
            raise ValueError('RECOVERY_INITIALIZATION_STATE_DIFFERS')
        if not isinstance(entry['rowCounts'], dict) or len(entry['rowCounts'])>1000 or any(
            not isinstance(k,str) or type(v) is not int or v<0 for k,v in entry['rowCounts'].items()):
            raise ValueError('RECOVERY_ROW_COMMITMENT_DIFFERS')
        used += entry['bytes']
    if used>MAX_TOTAL or len(canonical(m))>MAX_MANIFEST or not isinstance(package['payloads'], dict) or (
        set(package['payloads']) != {entry['sha256'] for entry in files.values()}):
        raise ValueError('RECOVERY_EXPORT_BOUNDS_DIFFER')
    result = {}
    for digest, encoded in package['payloads'].items():
        if not isinstance(encoded,str) or len(encoded) > ((MAX_DATABASE+2)//3)*4:
            raise ValueError('RECOVERY_PAYLOAD_TOO_LARGE')
        raw = base64.b64decode(encoded, validate=True)
        if sha256(raw).hexdigest()!=digest or any(entry['bytes']!=len(raw) for entry in files.values() if entry['sha256']==digest):
            raise ValueError('RECOVERY_PAYLOAD_DIFFERS')
        result[digest] = raw
    return m, result


def verify_isolated_restore(package, generation_id, *, parent):
    """Restore only to a fresh isolated directory; no automatic live replacement."""
    m, payloads = validate_export(package, generation_id)
    protected_path(parent, directory=True)
    # On hosts parent is a private RuntimeDirectory in tmpfs, not a business archive.
    with tempfile.TemporaryDirectory(prefix='generation-restore-', dir=parent) as folder:
        root = Path(folder)/'generations'/generation(generation_id)
        root.mkdir(parents=True, mode=0o700)
        restored = {}
        for name, record in m['files'].items():
            path = root/name
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(payloads[record['sha256']]);stream.flush();os.fsync(stream.fileno())
            with closing(connect(path)) as con:
                if inspect_database(con,generation_id) != {k:record[k] for k in ('schemaSha256','rowCounts','inventoryState')}:
                    raise ValueError('RECOVERY_RESTORE_STATE_DIFFERS')
            restored[name] = record['sha256']
        return {'schema':'solslot.generation-restore-evidence.v1','entity':'SOLSLOT','network':'testnet11',
                'generationId':generation_id,'manifestSha256':sha256(canonical(m)).hexdigest(),
                'restoreMatches':True,'restoredFiles':restored,
                'databaseCount':len(restored),'restoredBytes':sum(e['bytes'] for e in m['files'].values())}
