"""Generation-bound accepted media recovery, alongside the unchanged journal lane.

The frozen collections SQLite snapshot determines every exported object. Paths,
credentials and arbitrary URLs are never supplied by the remote caller.
"""
from contextlib import closing
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import urllib.parse
import urllib.request

from collection_media_recovery_contract import accepted_assets, object_name, validate_receipt
from generation_snapshot import canonical, generation, snapshot, validate_export as validate_journals, protected_path
from generation_replication import encrypt, decrypt, STORAGE, PRINCIPAL, ensure_object as ensure_journal, replicate as replicate_journals

SCHEMA='solslot.generation-media-snapshot.v1'
HEALTH='solslot.generation-media-recovery-health.v1'
AE='AE-SOLSLOT-GENERATION-MEDIA-20261023-271'
HEX=re.compile(r'[0-9a-f]{64}\Z')
KEY=re.compile(r'(?:private/)?collections/v2/[0-9a-f]{64}/[0-9a-f]{32}/asset(?:\.[a-z0-9]{1,12})?\Z')
CID=re.compile(r'(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})\Z')
# Accepted original files stay limited to 20 MiB by the shared contract.
# A CAR includes block metadata, so its bounded record allowance is larger.
MAX_OBJECT=21*1024**2
MAX_TOTAL=64*1024**2
MAX_OBJECTS=1000
MAX_METADATA=1024**2
FIELDS={'schema','entity','network','generationId','journalManifest','assets','cars','ipfsPeerId'}
ASSET_FIELDS={'objectId','sha256','bytes','public','cid'}
CAR_FIELDS={'cid','sha256','bytes'}
HEALTH_FIELDS={'schema','entity','network','generationId','sourceHash','actionEnvelopeId','principalId','checkedAt','restoredAt','containerPrivate','immutabilityVerified','createOnly','restoreMatches','manifest','assetCount','assetBytes','carCount','inventorySha256','restoreEvidenceSha256'}


def source_root(root,gen):
    root=Path(root)
    if root.name!=generation(gen) or root.parent.name!='collection-media':
        raise ValueError('MEDIA_NAMESPACE_DIFFERS')
    for path in (root,root/'quarantine',root/'public'):
        protected_path(path,directory=True)
    return root


def read_file(path,size):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode&0o022 or before.st_size!=size or not 0<size<=MAX_OBJECT:
            raise ValueError('MEDIA_FILE_BOUNDS_DIFFER')
        data=f.read(size+1);after=os.fstat(f.fileno())
        if len(data)!=size or (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            raise ValueError('MEDIA_FILE_CHANGED')
    return data




def ipfs_read(operation,arg=None):
    if operation not in ('id','dag/export') or (arg is not None and not CID.fullmatch(arg)):
        raise ValueError('MEDIA_IPFS_READ_INVALID')
    url='http://127.0.0.1:5012/api/v0/'+operation
    if arg is not None:url+='?arg='+urllib.parse.quote(arg,safe='')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url,data=b'',method='POST'),timeout=30) as response:
        data=response.read(MAX_OBJECT+1)
    if len(data)>MAX_OBJECT:raise ValueError('MEDIA_CAR_TOO_LARGE')
    return data


def capture(journal_root,media_root,gen,*,ipfs=ipfs_read):
    root=source_root(media_root,gen);journals=snapshot(journal_root,gen)
    m,payloads=validate_journals(journals,gen)
    if 'collections.sqlite' not in m['files']:raise ValueError('MEDIA_COLLECTION_JOURNAL_MISSING')
    assets=accepted_assets(payloads[m['files']['collections.sqlite']['sha256']],gen)
    objects={};cars=[];used=0
    for item in assets:
        data=read_file(root/'quarantine'/(item['objectId']+'.blob'),item['bytes'])
        if sha256(data).hexdigest()!=item['sha256']:raise ValueError('MEDIA_BYTES_DIFFER')
        if item['public'] and read_file(root/'public'/(item['objectId']+'.blob'),item['bytes'])!=data:
            raise ValueError('MEDIA_PUBLISHED_BYTES_DIFFER')
        used+=len(data)
        if used>MAX_TOTAL:raise ValueError('MEDIA_CAPACITY_REVIEW_REQUIRED')
        objects[item['sha256']]=base64.b64encode(data).decode()
    for cid in sorted({a['cid'] for a in assets if a['cid']}):
        data=ipfs('dag/export',cid)
        if not 0<len(data)<=MAX_OBJECT:raise ValueError('MEDIA_CAR_BOUNDS_DIFFER')
        used+=len(data);digest=sha256(data).hexdigest()
        cars.append({'cid':cid,'sha256':digest,'bytes':len(data)});objects[digest]=base64.b64encode(data).decode()
        if used>MAX_TOTAL:raise ValueError('MEDIA_CAPACITY_REVIEW_REQUIRED')
    peer=json.loads(ipfs('id'))['ID']
    if not isinstance(peer,str) or not 10<=len(peer)<=128:raise ValueError('MEDIA_IPFS_ID_INVALID')
    package={'manifest':{'schema':SCHEMA,'entity':'SOLSLOT','network':'testnet11','generationId':gen,
        'journalManifest':m,'assets':assets,'cars':cars,'ipfsPeerId':peer},'journalPayloads':journals['payloads'],'payloads':objects}
    validate(package,gen)
    return package


def validate(package,gen):
    generation(gen)
    if not isinstance(package,dict) or set(package)!={'manifest','journalPayloads','payloads'}:raise ValueError('MEDIA_PACKAGE_DIFFERS')
    m=package['manifest']
    if not isinstance(m,dict) or set(m)!=FIELDS or m['schema']!=SCHEMA or m['entity']!='SOLSLOT' or m['network']!='testnet11' or m['generationId']!=gen:
        raise ValueError('MEDIA_PACKAGE_BINDING_DIFFERS')
    if len(canonical(m))>MAX_METADATA or not isinstance(m['ipfsPeerId'],str) or not 10<=len(m['ipfsPeerId'])<=128:raise ValueError('MEDIA_MANIFEST_BOUNDS_DIFFER')
    jm,jp=validate_journals({'manifest':m['journalManifest'],'payloads':package['journalPayloads']},gen)
    if 'collections.sqlite' not in jm['files']:raise ValueError('MEDIA_COLLECTION_JOURNAL_MISSING')
    expected=accepted_assets(jp[jm['files']['collections.sqlite']['sha256']],gen)
    if m['assets']!=expected:raise ValueError('MEDIA_JOURNAL_INVENTORY_DIFFERS')
    if not isinstance(m['cars'],list) or len(m['cars'])>MAX_OBJECTS:raise ValueError('MEDIA_CAR_INVENTORY_DIFFERS')
    cids=set()
    for item in m['cars']:
        if not isinstance(item,dict) or set(item)!=CAR_FIELDS or not isinstance(item['cid'],str) or not CID.fullmatch(item['cid']) or item['cid'] in cids:
            raise ValueError('MEDIA_CAR_COMMITMENT_DIFFERS')
        cids.add(item['cid'])
    if cids!={a['cid'] for a in expected if a['cid']}:raise ValueError('MEDIA_CAR_INVENTORY_DIFFERS')
    records=m['assets']+m['cars'];total=0;digests=set()
    for item in records:
        if not isinstance(item['sha256'],str) or not HEX.fullmatch(item['sha256']) or type(item['bytes']) is not int or not 0<item['bytes']<=MAX_OBJECT:
            raise ValueError('MEDIA_OBJECT_COMMITMENT_DIFFERS')
        total+=item['bytes'];digests.add(item['sha256'])
    if total>MAX_TOTAL or not isinstance(package['payloads'],dict) or set(package['payloads'])!=digests:raise ValueError('MEDIA_PAYLOAD_INVENTORY_DIFFERS')
    result={}
    for digest,value in package['payloads'].items():
        if not isinstance(value,str) or len(value)>((MAX_OBJECT+2)//3)*4:raise ValueError('MEDIA_PAYLOAD_TOO_LARGE')
        raw=base64.b64decode(value,validate=True)
        if sha256(raw).hexdigest()!=digest or any(r['bytes']!=len(raw) for r in records if r['sha256']==digest):raise ValueError('MEDIA_PAYLOAD_DIFFERS')
        result[digest]=raw
    return m,result




def store(azure,raw,key,gen,kind):
    from urllib.error import HTTPError
    digest=sha256(raw).hexdigest();name=object_name(gen,digest)
    try:azure.call(STORAGE+'/'+name,method='PUT',data=encrypt(raw,key,gen,kind),headers={'x-ms-blob-type':'BlockBlob','Content-Type':'application/octet-stream','If-None-Match':'*'},limit=0)
    except HTTPError as exc:
        if exc.code!=412 and not (exc.code==409 and exc.headers.get('x-ms-error-code') in {'BlobAlreadyExists','BlobImmutableDueToPolicy'}):raise
    encoded,headers=azure.call(STORAGE+'/'+name,limit=((len(raw)+2)//3)*4+8192)
    if decrypt(encoded,key,gen,digest,kind)!=raw:raise ValueError('MEDIA_STORED_BYTES_DIFFER')
    return {'blobName':name,'sha256':digest,'bytes':len(raw),'etag':headers.get('ETag') or headers.get('Etag')}


def replicate(package,azure,key,gen,source,*,parent,clock):
    m,objects=validate(package,gen)
    record_receipt=replicate_journals({'manifest':m['journalManifest'],'payloads':package['journalPayloads']},azure,key,gen,source,parent=parent,clock=clock)
    for raw in objects.values():store(azure,raw,key,gen,'media')
    record=store(azure,canonical(m),key,gen,'media-manifest')
    # Independently fetch the manifest, journals and each object. Never use the
    # original source payloads as restore evidence or write into live storage.
    encoded,_=azure.call(STORAGE+'/'+record['blobName'],limit=MAX_METADATA*2)
    restored_m=json.loads(decrypt(encoded,key,gen,record['sha256'],'media-manifest'))
    if restored_m!=m:raise ValueError('MEDIA_RESTORED_MANIFEST_DIFFERS')
    journals={}
    from generation_replication import object_name as journal_name
    for r in restored_m['journalManifest']['files'].values():
        if r['sha256'] in journals:continue
        encoded,_=azure.call(STORAGE+'/'+journal_name(gen,r['sha256']),limit=((r['bytes']+2)//3)*4+8192)
        journals[r['sha256']]=base64.b64encode(decrypt(encoded,key,gen,r['sha256'],'database')).decode()
    restored_objects={}
    for r in restored_m['assets']+restored_m['cars']:
        if r['sha256'] in restored_objects:continue
        encoded,_=azure.call(STORAGE+'/'+object_name(gen,r['sha256']),limit=((r['bytes']+2)//3)*4+8192)
        restored_objects[r['sha256']]=base64.b64encode(decrypt(encoded,key,gen,r['sha256'],'media')).decode()
    _,decoded=validate({'manifest':restored_m,'journalPayloads':journals,'payloads':restored_objects},gen)
    protected_path(parent,directory=True)
    with tempfile.TemporaryDirectory(prefix='media-restore-',dir=parent) as folder:
        root=Path(folder)
        for item in restored_m['assets']+restored_m['cars']:
            path=root/item['sha256']
            if not path.exists():
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:f.write(decoded[item['sha256']]);f.flush();os.fsync(f.fileno())
            if read_file(path,item['bytes'])!=decoded[item['sha256']]:raise ValueError('MEDIA_ISOLATED_RESTORE_DIFFERS')
    now=int(clock());inventory=sha256(canonical(restored_m['assets'])).hexdigest()
    receipt={'schema':HEALTH,'entity':'SOLSLOT','network':'testnet11','generationId':gen,'sourceHash':source,'actionEnvelopeId':AE,
        'principalId':PRINCIPAL,'checkedAt':now,'restoredAt':now,'containerPrivate':True,'immutabilityVerified':True,'createOnly':True,'restoreMatches':True,
        'manifest':record,'assetCount':len(m['assets']),'assetBytes':sum(a['bytes'] for a in m['assets']),'carCount':len(m['cars']),
        'inventorySha256':inventory,'restoreEvidenceSha256':sha256(canonical({'manifest':record['sha256'],'assets':inventory,'objects':sorted(decoded)})).hexdigest()}
    validate_receipt(receipt,gen,source,now=now)
    return record_receipt,receipt
