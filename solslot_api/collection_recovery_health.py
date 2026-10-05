"""Small, metadata-only contract shared by the export service and API guard."""
import json
import os
import re
import stat
import time
from pathlib import Path

AE='AE-SOLSLOT-COLLECTION-AUTHORING-20261005-181'
PRINCIPAL='6b6d66ae-e403-406e-8e2c-0f0b2709f1f4'
RECEIPT=Path('/opt/solslot/collection-recovery-AE181/health/latest.json')
FIELDS={'schema','actionEnvelopeId','entity','network','principalId','checkedAt',
        'restoredAt','healthy','containerPrivate','immutabilityVerified','createOnly',
        'restoreMatches','manifestSha256','blobName','assetCount','acceptedBytes'}


def validate_receipt(r, now=None):
    now=time.time() if now is None else now
    if not isinstance(r,dict) or set(r)!=FIELDS:
        raise ValueError('Recovery receipt contract differs')
    if (r['schema']!='solslot.collection-recovery-health.v1' or r['actionEnvelopeId']!=AE
            or r['entity']!='SOLSLOT' or r['network']!='testnet11' or r['principalId']!=PRINCIPAL):
        raise ValueError('Recovery authority differs')
    for key in ('healthy','containerPrivate','immutabilityVerified','createOnly','restoreMatches'):
        if r[key] is not True:raise ValueError('Recovery is not healthy')
    for key,max_age in [('checkedAt',600),('restoredAt',3600)]:
        value=r[key]
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not now-max_age<=value<=now+30:
            raise ValueError('Recovery receipt is stale')
    if r['restoredAt']>r['checkedAt']+30:raise ValueError('Recovery timeline differs')
    if not isinstance(r['manifestSha256'],str) or not re.fullmatch('[0-9a-f]{64}',r['manifestSha256']):
        raise ValueError('Recovery commitment differs')
    if r['blobName']!='collections/AE181/'+r['manifestSha256']+'.aesgcm.json':
        raise ValueError('Recovery destination differs')
    for name,cap in [('assetCount',1000),('acceptedBytes',64*1024*1024)]:
        if isinstance(r[name],bool) or not isinstance(r[name],int) or not 0<=r[name]<=cap:
            raise ValueError('Recovery bounds differ')
    return r


def read_receipt(path=RECEIPT,now=None):
    if path.parent.is_symlink():raise ValueError('Recovery directory differs')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_size>8192:
            raise ValueError('Recovery receipt is not protected')
        data=f.read(8193)
    return validate_receipt(json.loads(data),now)
