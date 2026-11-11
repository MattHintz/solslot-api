"""Explicit, resumable 21 -> 24 journal inventory transition for Testnet.

Called only by a separately approved, quiesced deployment operation. Normal
startup never extends an initialized recovery inventory. Existing user tables
are hashed before and after; only recovery inventory markers may change.
"""
from contextlib import ExitStack,closing
from hashlib import sha256
from pathlib import Path
import base64,json,os,sqlite3
from .generation_storage import connect_generation_sqlite

CUSTOMER_FIELDS={'generation_customer_db_path':'generation-customers.sqlite3',
    'generation_customer_fee_db_path':'customer-fees.sqlite3',
    'generation_customer_identity_funding_db_path':'customer-identity-funding.sqlite3'}

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return sha256(canonical(value)).hexdigest()

def records_commitment(db):
    rows=[]
    for name,sql in db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        if name=='generation_recovery_inventory':continue
        table='"'+name.replace('"','""')+'"'
        def safe(v):return {'blob':base64.b64encode(v).decode()} if isinstance(v,bytes) else v
        values=sorted(digest([safe(v) for v in row]) for row in db.execute('SELECT * FROM '+table))
        rows.append({'table':name,'schema':sql,'rows':len(values),'commitment':digest(values)})
    return digest(rows)

def atomic(path,value):
    raw=canonical(value);temporary=path.with_suffix(path.suffix+'.new')
    if temporary.exists() or temporary.is_symlink():raise ValueError('RECOVERY_TRANSITION_TEMP_REQUIRES_REVIEW')
    fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def migrate_customer_recovery_inventory(settings,*,expected_guard_sha256):
    from .generation_recovery_storage import DATABASES,INVENTORY_HASH
    from .generation_context import generation_bytes
    from .generation_customer_store import GenerationCustomerStore
    from .protocol_funding_store import ProtocolFundingStore
    from .stamp_funding import StampFundingStore
    generation=settings.deployment_generation_id;identity=generation_bytes(generation).hex()
    root=Path(settings.generation_preparation_db_path).parent
    if settings.network!='testnet11' or root.name!=identity or root.parent.name!='generations' or not root.is_absolute():
        raise ValueError('RECOVERY_TRANSITION_EXACT_CURRENT_NAMESPACE_REQUIRED')
    for parent in (root,*root.parents):
        if parent.is_symlink():raise ValueError('RECOVERY_TRANSITION_SYMLINK_REJECTED')
    if root.stat().st_mode&0o022:raise ValueError('RECOVERY_TRANSITION_NAMESPACE_UNPROTECTED')
    if any(Path(getattr(settings,field))!=root/name for field,name in CUSTOMER_FIELDS.items()):
        raise ValueError('RECOVERY_TRANSITION_CUSTOMER_PATH_CHANGED')
    previous=DATABASES-set(CUSTOMER_FIELDS.values())
    if len(previous)!=21 or len(DATABASES)!=24:raise ValueError('RECOVERY_TRANSITION_INVENTORY_CHANGED')
    previous_hash=digest(sorted(previous))
    guard=root.parent.parent/'generation-recovery-initialization'/(identity+'.json')
    for path in (guard,*guard.parents):
        if path.is_symlink():raise ValueError('RECOVERY_TRANSITION_GUARD_UNPROTECTED')
    if guard.stat().st_mode&0o022 or guard.stat().st_nlink!=1 or guard.stat().st_size>4096:
        raise ValueError('RECOVERY_TRANSITION_GUARD_UNPROTECTED')
    guard_raw=guard.read_bytes()
    old_guard={'schema':'solslot.generation-recovery-initialization.v1','generationId':generation,'inventoryHash':previous_hash}
    new_guard={**old_guard,'inventoryHash':INVENTORY_HASH}
    if json.loads(guard_raw) not in (old_guard,new_guard):raise ValueError('RECOVERY_TRANSITION_GUARD_DIFFERS')
    if json.loads(guard_raw)==old_guard and sha256(guard_raw).hexdigest()!=expected_guard_sha256:
        raise ValueError('RECOVERY_TRANSITION_ORIGINAL_GUARD_REQUIRED')
    journal_root=root.parent.parent/'generation-recovery-inventory-transitions'
    journal_root.mkdir(exist_ok=True,mode=0o700)
    if journal_root.is_symlink() or journal_root.stat().st_mode&0o077:raise ValueError('RECOVERY_TRANSITION_JOURNAL_UNPROTECTED')
    journal=journal_root/(identity+'.json');prior=None
    if journal.exists():
        if journal.is_symlink() or journal.stat().st_mode&0o077:raise ValueError('RECOVERY_TRANSITION_JOURNAL_UNPROTECTED')
        prior=json.loads(journal.read_bytes())
        if (prior.get('schema')!='solslot.current-customer-recovery-transition.v1' or prior.get('generationId')!=generation
            or prior.get('previousGuardSha256')!=expected_guard_sha256 or prior.get('previousInventoryHash')!=previous_hash
            or prior.get('inventoryHash')!=INVENTORY_HASH):raise ValueError('RECOVERY_TRANSITION_REVIEW_CHANGED')
    elif json.loads(guard_raw)!=old_guard or sha256(guard_raw).hexdigest()!=expected_guard_sha256:
        raise ValueError('RECOVERY_TRANSITION_ORIGINAL_GUARD_REQUIRED')
    allowed=DATABASES|{name+suffix for name in DATABASES for suffix in ('-wal','-shm','-journal')}
    for path in root.iterdir():
        if path.name not in allowed:raise ValueError('RECOVERY_TRANSITION_UNEXPECTED_FILE')
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1 or path.stat().st_mode&0o022:
            raise ValueError('RECOVERY_TRANSITION_JOURNAL_UNPROTECTED')
    with ExitStack() as stack:
        connections={};before={}
        for name in sorted(previous):
            path=root/name
            if not path.is_file() or path.is_symlink() or path.stat().st_nlink!=1 or path.stat().st_mode&0o022:
                raise ValueError('RECOVERY_TRANSITION_ORIGINAL_JOURNAL_REQUIRED')
            db=stack.enter_context(closing(connect_generation_sqlite(path,generation_id=generation,isolation_level=None,timeout=2)))
            db.execute('BEGIN IMMEDIATE');connections[name]=db
            marker=db.execute('SELECT singleton,inventory_hash,stage FROM generation_recovery_inventory').fetchall()
            if len(marker)!=1 or tuple(marker[0]) not in ((1,previous_hash,'READY'),(1,INVENTORY_HASH,'READY')):
                raise ValueError('RECOVERY_TRANSITION_ORIGINAL_READY_MARKERS_REQUIRED')
            if prior is None and marker[0][1]!=previous_hash:raise ValueError('RECOVERY_TRANSITION_UNREVIEWED_PARTIAL_CHANGE')
            before[name]=records_commitment(db)
        if prior is not None and before!=prior.get('originalRecords'):
            raise ValueError('RECOVERY_TRANSITION_ORIGINAL_RECORDS_CHANGED')
        if prior is None:
            prior={'schema':'solslot.current-customer-recovery-transition.v1','generationId':generation,
                'previousGuardSha256':expected_guard_sha256,'previousInventoryHash':previous_hash,
                'inventoryHash':INVENTORY_HASH,'originalRecords':before,'stage':'STARTED'}
            atomic(journal,prior)
        GenerationCustomerStore(settings.generation_customer_db_path,generation)
        stores=[ProtocolFundingStore(settings.generation_customer_fee_db_path),
            StampFundingStore(settings.generation_customer_identity_funding_db_path,generation_id=generation)]
        for store in stores:store.close()
        for name in sorted(CUSTOMER_FIELDS.values()):
            db=stack.enter_context(closing(connect_generation_sqlite(root/name,generation_id=generation,isolation_level=None,timeout=2)))
            db.execute('BEGIN IMMEDIATE');connections[name]=db
            # Before activation the additional journals must contain no user
            # operations, reservations, signed material or dispatch events.
            for table, in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
                if table not in ('deployment_generation_binding','generation_recovery_inventory') and db.execute('SELECT COUNT(*) FROM "'+table.replace('"','""')+'"').fetchone()[0]:
                    raise ValueError('RECOVERY_TRANSITION_NEW_JOURNAL_ALREADY_ACTIVE')
        for name,db in connections.items():
            db.execute('CREATE TABLE IF NOT EXISTS generation_recovery_inventory(singleton INTEGER PRIMARY KEY CHECK(singleton=1),inventory_hash TEXT NOT NULL,stage TEXT NOT NULL)')
            db.execute("INSERT INTO generation_recovery_inventory VALUES(1,?,'READY') ON CONFLICT(singleton) DO UPDATE SET inventory_hash=excluded.inventory_hash,stage=excluded.stage",(INVENTORY_HASH,))
            if name in before and records_commitment(db)!=before[name]:raise ValueError('RECOVERY_TRANSITION_RECORD_PRESERVATION_FAILED')
        for db in connections.values():db.execute('COMMIT')
    atomic(guard,new_guard);atomic(journal,{**prior,'stage':'COMPLETED'})
    return {'schema':'solslot.current-customer-recovery-transition-result.v1','generationId':generation,
        'previousInventoryHash':previous_hash,'inventoryHash':INVENTORY_HASH,'originalJournalsPreserved':21,
        'databaseCount':24,'newJournalsEmpty':True,'recordsPreserved':True,'requiresFreshEncryptedRestore':True}
