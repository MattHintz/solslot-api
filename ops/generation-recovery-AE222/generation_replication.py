"""Create-only encrypted recovery in the existing private Azure container.

Azure credentials and backup keys stay in the worker process. Receipts contain
only generation/source commitments, counts and immutable object references.
"""
from __future__ import annotations
import base64
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import time
import urllib.error
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from generation_snapshot import (canonical, generation, validate_export,
                                 verify_isolated_restore, MAX_DATABASE, MAX_MANIFEST, DATABASES)

STORAGE = 'https://stsolslotrec5db856e6.blob.core.windows.net/solslot-collection-recovery-ae165'
KEY_REFERENCE = 'https://kv-sfcog-sols2-856e6.vault.azure.net/secrets/solslot-collection-backup-key-ae165/90df81b132264ccfb85df1fcff5acf52'
PRINCIPAL = '6b6d66ae-e403-406e-8e2c-0f0b2709f1f4'
AE = 'AE-SOLSLOT-GENERATION-RECOVERY-20261013-222'


def object_name(generation_id, digest):
    return 'generation-journals/'+generation(generation_id)+'/'+digest+'.aesgcm.json'


def context(generation_id, digest, kind):
    return {'schema':'solslot.generation-encrypted-object.v1','entity':'SOLSLOT',
            'network':'testnet11','generationId':generation_id,'actionEnvelopeId':AE,
            'plaintextSha256':digest,'kind':kind,'keyReference':KEY_REFERENCE}


def encrypt(raw, key, generation_id, kind):
    digest=sha256(raw).hexdigest();aad=canonical(context(generation_id,digest,kind));nonce=os.urandom(12)
    return canonical({'algorithm':'AES-256-GCM','nonceB64':base64.b64encode(nonce).decode(),
        'aadB64':base64.b64encode(aad).decode(),
        'ciphertextB64':base64.b64encode(AESGCM(key).encrypt(nonce,raw,aad)).decode()})


def decrypt(encoded, key, generation_id, digest, kind):
    limit=MAX_MANIFEST if kind=='manifest' else MAX_DATABASE
    if len(encoded)>((limit+2)//3)*4+8192:
        raise ValueError('RECOVERY_ENCRYPTED_OBJECT_TOO_LARGE')
    q=json.loads(encoded)
    if not isinstance(q,dict) or set(q)!={'algorithm','nonceB64','aadB64','ciphertextB64'} or q['algorithm']!='AES-256-GCM':
        raise ValueError('RECOVERY_ENCRYPTED_FORMAT_DIFFERS')
    aad=base64.b64decode(q['aadB64'],validate=True)
    if aad!=canonical(context(generation_id,digest,kind)):
        raise ValueError('RECOVERY_ENCRYPTED_CONTEXT_DIFFERS')
    nonce=base64.b64decode(q['nonceB64'],validate=True)
    if len(nonce)!=12:raise ValueError('RECOVERY_NONCE_DIFFERS')
    raw=AESGCM(key).decrypt(nonce,base64.b64decode(q['ciphertextB64'],validate=True),aad)
    if len(raw)>limit or not hmac.compare_digest(sha256(raw).hexdigest(),digest):
        raise ValueError('RECOVERY_DECRYPTED_BYTES_DIFFER')
    return raw


def ensure_object(azure,raw,key,generation_id,kind):
    digest=sha256(raw).hexdigest();name=object_name(generation_id,digest);url=STORAGE+'/'+name
    try:
        azure.call(url,method='PUT',data=encrypt(raw,key,generation_id,kind),headers={
            'x-ms-blob-type':'BlockBlob','Content-Type':'application/octet-stream','If-None-Match':'*'},limit=0)
    except urllib.error.HTTPError as exc:
        if exc.code!=412 and not (exc.code==409 and exc.headers.get('x-ms-error-code') in
            {'BlobAlreadyExists','BlobImmutableDueToPolicy'}):raise
    encoded,headers=azure.call(url,limit=((len(raw)+2)//3)*4+8192)
    if decrypt(encoded,key,generation_id,digest,kind)!=raw:
        raise ValueError('RECOVERY_STORED_OBJECT_DIFFERS')
    return {'blobName':name,'sha256':digest,'bytes':len(raw),'etag':headers.get('ETag') or headers.get('Etag')}


def restore_from_azure(azure,key,generation_id,manifest_record,*,parent):
    name=object_name(generation_id,manifest_record['sha256'])
    if manifest_record['blobName']!=name:raise ValueError('RECOVERY_MANIFEST_REFERENCE_DIFFERS')
    encoded,_=azure.call(STORAGE+'/'+name,limit=MAX_MANIFEST*2)
    m=json.loads(decrypt(encoded,key,generation_id,manifest_record['sha256'],'manifest'))
    # Validate structure and cap lengths before object requests or allocations.
    if not isinstance(m,dict) or not isinstance(m.get('files'),dict):
        raise ValueError('RECOVERY_STORED_MANIFEST_DIFFERS')
    # The empty payload check necessarily fails only on payload inventory once
    # the complete manifest contract has been admitted. Avoid accepting arbitrary
    # blob URLs or caller-selected file names below.
    from generation_snapshot import DATABASES, HEX, MAX_TOTAL
    if (set(m)!= {'schema','entity','network','generationId','files'} or m['schema']!='solslot.generation-snapshot.v1'
        or m['entity']!='SOLSLOT' or m['network']!='testnet11' or m['generationId']!=generation_id
        or not m['files'] or not set(m['files']).issubset(DATABASES)):
        raise ValueError('RECOVERY_STORED_MANIFEST_DIFFERS')
    total=0
    for record in m['files'].values():
        if not isinstance(record,dict) or set(record)!= {'sha256','bytes','schemaSha256','rowCounts','inventoryState'} or (
            not isinstance(record['sha256'],str) or not HEX.fullmatch(record['sha256'])
            or type(record['bytes']) is not int or not 0<record['bytes']<=MAX_DATABASE):
            raise ValueError('RECOVERY_STORED_COMMITMENT_DIFFERS')
        total+=record['bytes']
    if total>MAX_TOTAL:raise ValueError('RECOVERY_STORED_BOUNDS_DIFFER')
    payloads={}
    for record in m['files'].values():
        digest=record['sha256']
        if digest in payloads:continue
        encoded,_=azure.call(STORAGE+'/'+object_name(generation_id,digest),limit=((record['bytes']+2)//3)*4+8192)
        raw=decrypt(encoded,key,generation_id,digest,'database')
        if len(raw)!=record['bytes']:raise ValueError('RECOVERY_STORED_LENGTH_DIFFERS')
        payloads[digest]=base64.b64encode(raw).decode()
    return verify_isolated_restore({'manifest':m,'payloads':payloads},generation_id,parent=parent)


def replicate(package,azure,key,generation_id,source_hash,*,parent,clock=time.time,purpose='LIVE_GENERATION_RECOVERY'):
    generation(source_hash)
    if purpose not in {'LIVE_GENERATION_RECOVERY','SYNTHETIC_RESTORE_DRILL'}:
        raise ValueError('RECOVERY_PURPOSE_DIFFERS')
    azure.policy()  # Existing private container and locked 30-day retention.
    m,payloads=validate_export(package,generation_id)
    if purpose=='LIVE_GENERATION_RECOVERY' and set(m['files'])!=DATABASES:
        raise ValueError('GENERATION_RECOVERY_REQUIRED_DATABASE_MISSING')
    if purpose=='LIVE_GENERATION_RECOVERY' and any(record['inventoryState']!='READY' for record in m['files'].values()):
        raise ValueError('GENERATION_RECOVERY_INITIALIZATION_INCOMPLETE')
    for digest,raw in payloads.items():ensure_object(azure,raw,key,generation_id,'database')
    manifest_record=ensure_object(azure,canonical(m),key,generation_id,'manifest')
    # No reuse of source bytes as restore evidence: every byte comes from GET.
    restored=restore_from_azure(azure,key,generation_id,manifest_record,parent=parent)
    return {'schema':'solslot.generation-recovery-health.v1','entity':'SOLSLOT','network':'testnet11',
            'actionEnvelopeId':AE,'purpose':purpose,'generationId':generation_id,
            'sourceHash':source_hash,'principalId':PRINCIPAL,'checkedAt':int(clock()),
            'restoredAt':int(clock()),'containerPrivate':True,'immutabilityVerified':True,
            'createOnly':True,'restoreMatches':restored['restoreMatches'],
            'inventoryInitialized':set(m['files'])==DATABASES and all(r['inventoryState']=='READY' for r in m['files'].values()),
            'databaseCount':restored['databaseCount'],'restoredBytes':restored['restoredBytes'],
            'manifest':manifest_record,'restoreEvidenceSha256':sha256(canonical(restored)).hexdigest()}
