"""Fail closed on stale, synthetic or wrong-generation restore receipts."""
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import stat
import time
from generation_snapshot import HEX, canonical, generation, MAX_TOTAL, DATABASES
from generation_replication import AE, PRINCIPAL, object_name

FIELDS={'schema','entity','network','actionEnvelopeId','purpose','generationId','sourceHash','principalId',
        'checkedAt','restoredAt','containerPrivate','immutabilityVerified','createOnly','restoreMatches',
        'databaseCount','restoredBytes','manifest','restoreEvidenceSha256'}


def validate_receipt(q,generation_id,source_hash,*,now=None):
    now=time.time() if now is None else now
    generation(generation_id);generation(source_hash)
    if not isinstance(q,dict) or set(q)!=FIELDS or (
        q['schema']!='solslot.generation-recovery-health.v1' or q['entity']!='SOLSLOT'
        or q['network']!='testnet11' or q['actionEnvelopeId']!=AE or q['purpose']!='LIVE_GENERATION_RECOVERY'
        or q['generationId']!=generation_id or q['sourceHash']!=source_hash or q['principalId']!=PRINCIPAL):
        raise ValueError('GENERATION_RECOVERY_BINDING_DIFFERS')
    if any(q[k] is not True for k in ('containerPrivate','immutabilityVerified','createOnly','restoreMatches')):
        raise ValueError('GENERATION_RECOVERY_NOT_HEALTHY')
    for name in ('checkedAt','restoredAt'):
        if type(q[name]) is not int or not now-600<=q[name]<=now+30:
            raise ValueError('GENERATION_RECOVERY_STALE')
    if q['restoredAt']>q['checkedAt']+30:raise ValueError('GENERATION_RECOVERY_TIMELINE_DIFFERS')
    if type(q['databaseCount']) is not int or q['databaseCount']!=len(DATABASES) or (
        type(q['restoredBytes']) is not int or not 0<q['restoredBytes']<=MAX_TOTAL):
        raise ValueError('GENERATION_RECOVERY_BOUNDS_DIFFER')
    record=q['manifest']
    if not isinstance(record,dict) or set(record)!= {'blobName','sha256','bytes','etag'} or (
        not isinstance(record['sha256'],str) or not HEX.fullmatch(record['sha256'])
        or record['blobName']!=object_name(generation_id,record['sha256'])
        or type(record['bytes']) is not int or not 0<record['bytes']<=1024**2
        or not isinstance(record['etag'],str) or not 1<=len(record['etag'])<=256):
        raise ValueError('GENERATION_RECOVERY_OBJECT_DIFFERS')
    if not isinstance(q['restoreEvidenceSha256'],str) or not HEX.fullmatch(q['restoreEvidenceSha256']):
        raise ValueError('GENERATION_RECOVERY_RESTORE_COMMITMENT_DIFFERS')
    return q


def read_receipt(path,generation_id,source_hash,*,now=None):
    path=Path(path)
    for parent in path.parents:
        if parent.is_symlink():raise ValueError('GENERATION_RECOVERY_RECEIPT_SYMLINK')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>16384:
            raise ValueError('GENERATION_RECOVERY_RECEIPT_NOT_PROTECTED')
        raw=stream.read(16385)
    return validate_receipt(json.loads(raw),generation_id,source_hash,now=now)
