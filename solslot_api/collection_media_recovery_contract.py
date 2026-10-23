"""Shared, dependency-free contract for generation media recovery admission.

Installed byte-for-byte into the restricted recovery worker, and imported by
this API. No credentials or configurable destinations are accepted here.
"""
from hashlib import sha256
import json
import re
import sqlite3
SCHEMA='solslot.generation-media-snapshot.v1'
HEALTH='solslot.generation-media-recovery-health.v1'
AE='AE-SOLSLOT-GENERATION-MEDIA-20261023-271'
PRINCIPAL='6b6d66ae-e403-406e-8e2c-0f0b2709f1f4'
HEX=re.compile(r'[0-9a-f]{64}\Z')
KEY=re.compile(r'(?:private/)?collections/v2/[0-9a-f]{64}/[0-9a-f]{32}/asset(?:\.[a-z0-9]{1,12})?\Z')
CID=re.compile(r'(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})\Z')
MAX_OBJECT=20*1024**2
MAX_TOTAL=64*1024**2
MAX_OBJECTS=1000
MAX_METADATA=1024**2
HEALTH_FIELDS={'schema','entity','network','generationId','sourceHash','actionEnvelopeId','principalId','checkedAt','restoredAt','containerPrivate','immutabilityVerified','createOnly','restoreMatches','manifest','assetCount','assetBytes','carCount','inventorySha256','restoreEvidenceSha256'}
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def generation(value):
    if not isinstance(value,str) or not value.startswith('0x') or not HEX.fullmatch(value[2:]) or value=='0x'+'00'*32:raise ValueError('MEDIA_GENERATION_INVALID')
    return value[2:]


def accepted_assets(raw,gen):
    if not isinstance(raw,bytes) or len(raw)>256*1024**2:raise ValueError('MEDIA_DATABASE_TOO_LARGE')
    con=sqlite3.connect(':memory:')
    try:
        # The archive retains the exact WAL-mode SQLite bytes. SQLite's in-memory
        # deserialize cannot open WAL sidecars, so only this read-only RAM view
        # uses rollback journal header flags. No archive or source is rewritten.
        view=bytearray(raw)
        if view[:16]!=b'SQLite format 3\0':raise ValueError('MEDIA_SQLITE_HEADER_INVALID')
        view[18:20]=b'\x01\x01'
        con.deserialize(bytes(view));con.row_factory=sqlite3.Row
        con.execute('PRAGMA trusted_schema=OFF');con.execute('PRAGMA query_only=ON')
        if [tuple(r) for r in con.execute('SELECT singleton,generation_id,network FROM deployment_generation_binding')]!=[(1,gen,'testnet11')]:
            raise ValueError('MEDIA_DATABASE_GENERATION_DIFFERS')
        rows=con.execute("SELECT object_key,actual_sha256,expected_sha256,expected_byte_size,actual_byte_size,state,malware_status,visibility,ipfs_cid FROM property_collection_assets WHERE state IN ('VERIFIED','PINNED') ORDER BY object_key LIMIT 1001").fetchall()
        if len(rows)>MAX_OBJECTS:raise ValueError('MEDIA_INVENTORY_LIMIT')
        result=[];seen=set()
        for row in rows:
            key=row['object_key'];digest=row['actual_sha256'];size=row['expected_byte_size'];cid=row['ipfs_cid']
            if (not isinstance(key,str) or not KEY.fullmatch(key) or not isinstance(digest,str) or not HEX.fullmatch(digest)
                or digest!=row['expected_sha256'] or type(size) is not int or not 0<size<=MAX_OBJECT or row['actual_byte_size']!=size
                or row['malware_status']!='CLEAN' or row['visibility'] not in ('PUBLIC','PRIVATE')
                or key.startswith('private/')!=(row['visibility']=='PRIVATE')):
                raise ValueError('MEDIA_ASSET_COMMITMENT_DIFFERS')
            if cid is not None and (not isinstance(cid,str) or not CID.fullmatch(cid)):
                raise ValueError('MEDIA_CID_INVALID')
            if row['visibility']=='PRIVATE' and cid is not None:raise ValueError('MEDIA_PRIVATE_CID_REJECTED')
            public=row['visibility']=='PUBLIC' and row['state']=='PINNED'
            if public and cid is None:raise ValueError('MEDIA_PUBLIC_CID_MISSING')
            oid=sha256(key.encode()).hexdigest()
            if oid in seen:raise ValueError('MEDIA_DUPLICATE_OBJECT')
            seen.add(oid);result.append({'objectId':oid,'sha256':digest,'bytes':size,'public':public,'cid':cid})
        return sorted(result,key=lambda x:x['objectId'])
    finally:con.close()

def object_name(gen,digest):
    if not isinstance(digest,str) or not HEX.fullmatch(digest):raise ValueError('MEDIA_DIGEST_INVALID')
    return 'generation-media/'+generation(gen)+'/'+digest+'.aesgcm.json'

def validate_receipt(q,gen,source,*,now):
    generation(gen);generation(source)
    if not isinstance(q,dict) or set(q)!=HEALTH_FIELDS:raise ValueError('MEDIA_RECEIPT_CONTRACT_DIFFERS')
    expected={'schema':HEALTH,'entity':'SOLSLOT','network':'testnet11','generationId':gen,'sourceHash':source,'actionEnvelopeId':AE,'principalId':PRINCIPAL}
    if any(q[k]!=v for k,v in expected.items()):raise ValueError('MEDIA_RECEIPT_BINDING_DIFFERS')
    if any(q[k] is not True for k in ('containerPrivate','immutabilityVerified','createOnly','restoreMatches')):raise ValueError('MEDIA_RECEIPT_NOT_HEALTHY')
    if any(type(q[k]) is not int or not now-600<=q[k]<=now+30 for k in ('checkedAt','restoredAt')) or q['restoredAt']>q['checkedAt']+30:raise ValueError('MEDIA_RECEIPT_STALE')
    if any(type(q[k]) is not int or not 0<=q[k]<=bound for k,bound in [('assetCount',MAX_OBJECTS),('carCount',MAX_OBJECTS),('assetBytes',MAX_TOTAL)]):raise ValueError('MEDIA_RECEIPT_BOUNDS_DIFFER')
    if any(not isinstance(q[k],str) or not HEX.fullmatch(q[k]) for k in ('inventorySha256','restoreEvidenceSha256')):raise ValueError('MEDIA_RECEIPT_DIGEST_DIFFERS')
    r=q['manifest']
    if not isinstance(r,dict) or set(r)!={'blobName','sha256','bytes','etag'} or r['blobName']!=object_name(gen,r['sha256']) or type(r['bytes']) is not int or not 0<r['bytes']<=MAX_METADATA or not isinstance(r['etag'],str) or not 1<=len(r['etag'])<=256:raise ValueError('MEDIA_RECEIPT_OBJECT_DIFFERS')
    return q
