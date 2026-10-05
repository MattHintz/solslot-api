"""Read-only, collection-scoped export behind a restricted SSH forced command.

This module never exports the complete administrator DB, credentials, customer
vault tables, rejected uploads or arbitrary filesystem paths.
"""
import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path

AE = 'AE-SOLSLOT-COLLECTION-AUTHORING-20261005-181'
DB = Path('/opt/solslot/genesis-rc28/state/admin_desk_v2.db')
MEDIA = Path('/opt/solslot/genesis-rc28/state/collection-media-AE165')
RECEIPT = Path('/opt/solslot/collection-recovery-AE181/health/latest.json')
TABLES = ('property_collections', 'property_collection_deeds',
          'property_collection_assets', 'property_collection_comments',
          'property_collection_reviews', 'property_metadata_versions',
          'property_collection_audit_events', 'property_anchor_evidence')
HEX = re.compile(r'[0-9a-f]{64}\Z')
KEY = re.compile(r'(?:private/)?collections/v2/[0-9a-f]{64}/[0-9a-f]{32}/asset(?:\.[a-z0-9]{1,12})?\Z')
MAX_OBJECT = 20 * 1024 * 1024
MAX_SOURCE = 64 * 1024 * 1024
MAX_WIRE = 96 * 1024 * 1024
MAX_OBJECTS = 1000
CID = re.compile(r'(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def protected_read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
            raise ValueError('Source is not a bounded regular file')
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('Source changed during read')
        return data


def ipfs_read(operation, arg=None, limit=MAX_OBJECT):
    if operation not in ('id','dag/export') or (arg is not None and not CID.fullmatch(arg)):
        raise ValueError('Invalid IPFS read')
    url='http://127.0.0.1:5012/api/v0/'+operation
    if arg is not None:url+='?arg='+urllib.parse.quote(arg,safe='')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url,method='POST',data=b''),timeout=30) as r:
        data=r.read(limit+1)
    if len(data)>limit:raise ValueError('IPFS export cap exceeded')
    return data


def snapshot(db=DB, media=MEDIA, known=(), ipfs=ipfs_read):
    if len(known) > MAX_OBJECTS or any(not isinstance(x, str) or not HEX.fullmatch(x) for x in known):
        raise ValueError('Invalid previously verified object inventory')
    for p in (db, media, media/'quarantine', media/'public'):
        if p.is_symlink():
            raise ValueError('Source path is a symlink')
    for p in (media, media/'quarantine', media/'public'):
        info=p.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('Source directory is not protected')
    con = sqlite3.connect('file:'+str(db)+'?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA query_only=ON')
    con.execute('BEGIN')
    try:
        existing={x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not set(TABLES).issubset(existing):
            raise ValueError('Collection recovery schema is incomplete')
        tables={};table_schemas={}
        for name in TABLES:
            table_schemas[name]=[
                {'name':column[1],'type':column[2],'notNull':bool(column[3]),'primaryKey':column[5]}
                for column in con.execute('PRAGMA table_info('+name+')')
            ]
            rows=[]
            for row in con.execute('SELECT * FROM '+name+' ORDER BY rowid'):
                if len(rows)>=10000:
                    raise ValueError('Collection record cap exceeded')
                value=dict(row)
                value={k:({'binaryB64':base64.b64encode(v).decode()} if isinstance(v,bytes) else v)
                       for k,v in value.items()}
                rows.append(value)
            tables[name]=rows
        metadata_size=len(canonical(tables))
        if metadata_size>8*1024*1024:
            raise ValueError('Collection metadata cap exceeded')
        files=[]; payloads={}; used=metadata_size
        for row in tables['property_collection_assets']:
            if row['state'] not in ('VERIFIED', 'PINNED') or row['malware_status']!='CLEAN':
                continue
            key=row['object_key']; digest=row['actual_sha256']; size=row['expected_byte_size']
            if not isinstance(key,str) or not KEY.fullmatch(key) or not isinstance(digest,str) or not HEX.fullmatch(digest):
                raise ValueError('Accepted asset commitment is invalid')
            if not isinstance(size,int) or not 0<size<=MAX_OBJECT:
                raise ValueError('Accepted asset size is invalid')
            object_id=hashlib.sha256(key.encode()).hexdigest()
            data=protected_read(media/'quarantine'/(object_id+'.blob'),MAX_OBJECT)
            if len(data)!=size or hashlib.sha256(data).hexdigest()!=digest:
                raise ValueError('Accepted asset differs from its commitment')
            published=not key.startswith('private/') and row['state']=='PINNED'
            if published:
                if protected_read(media/'public'/(object_id+'.blob'),MAX_OBJECT)!=data:
                    raise ValueError('Published asset differs from accepted bytes')
            files.append({'kind':'media','objectId':object_id,'sha256':digest,'bytes':size,'public':published})
            used+=size
            if len(files)>MAX_OBJECTS or used>MAX_SOURCE:
                raise ValueError('Bounded property trial recovery capacity exceeded')
            if digest not in known:
                payloads[digest]=base64.b64encode(data).decode()
        cids=set()
        def find_cids(value):
            if isinstance(value,dict):
                for v in value.values():find_cids(v)
            elif isinstance(value,list):
                for v in value:find_cids(v)
            elif isinstance(value,str):
                if CID.fullmatch(value):cids.add(value)
                elif value.startswith('ipfs://') and CID.fullmatch(value[7:]):cids.add(value[7:])
                elif value[:1] in ('{','['):
                    try:find_cids(json.loads(value))
                    except (ValueError,RecursionError):pass
        find_cids(tables)
        if len(cids)>MAX_OBJECTS:raise ValueError('IPFS root cap exceeded')
        for cid in sorted(cids):
            data=ipfs('dag/export',cid,MAX_OBJECT)
            digest=hashlib.sha256(data).hexdigest();size=len(data);used+=size
            if size==0 or used>MAX_SOURCE or len(files)>=MAX_OBJECTS:
                raise ValueError('IPFS recovery capacity exceeded')
            files.append({'kind':'ipfs-car','objectId':hashlib.sha256(cid.encode()).hexdigest(),
                          'sha256':digest,'bytes':size,'cid':cid})
            if digest not in known:payloads[digest]=base64.b64encode(data).decode()
        peer_id=json.loads(ipfs('id',None,65536))['ID']
        if not isinstance(peer_id,str) or not 10<=len(peer_id)<=128:
            raise ValueError('IPFS node identity is unavailable')
        manifest={'schema':'solslot.collection-recovery.v1','entity':'SOLSLOT',
                  'network':'testnet11','ipfsPeerId':peer_id,
                  'tables':tables,'tableSchemas':table_schemas,
                  'files':sorted(files,key=lambda f:f['objectId'])}
        package={'manifest':manifest,'payloads':payloads}
        if len(canonical(package))>MAX_WIRE:
            raise ValueError('Export wire cap exceeded')
        return package
    finally:
        con.close()


def save_receipt(receipt, target=RECEIPT):
    from recovery_health import validate_receipt
    validate_receipt(receipt, now=time.time())
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise ValueError('Health directory is unavailable')
    data=canonical(receipt)+b'\n'
    temp=target.with_name('incoming-'+os.urandom(12).hex()+'.json')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    os.fchmod(fd,0o640)
    os.fchown(fd,-1,target.parent.stat().st_gid)
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(temp,target)
    fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def main():
    try:
        request=sys.stdin.buffer.readline(131073)
        if len(request)>131072 or not request.endswith(b'\n'):
            raise ValueError('Invalid recovery command')
        q=json.loads(request)
        if q.get('op')=='snapshot' and set(q)<= {'op','known'}:
            sys.stdout.buffer.write(canonical(snapshot(known=q.get('known',[]))))
        elif q.get('op')=='receipt' and set(q)=={'op','receipt'}:
            save_receipt(q['receipt']);print('{"status":"receipt_saved"}')
        else:raise ValueError('Unsupported recovery command')
        return 0
    except Exception:
        # Never log the package, command, property content or capability URLs.
        print('Collection recovery command failed closed',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
