from contextlib import closing
from copy import deepcopy
from hashlib import sha256
from email.message import Message
from urllib.error import HTTPError
import json
import os

import pytest
from cryptography.exceptions import InvalidTag
from generation_snapshot import snapshot, canonical, DATABASES
from generation_replication import (replicate,restore_from_azure,decrypt,encrypt,STORAGE,KEY_REFERENCE)
from test_generation_snapshot import namespace, database, GEN, OTHER

KEY=bytes(range(32))  # Synthetic test key only.
SOURCE='0x'+'33'*32


class Azure:
    def __init__(self):self.objects={};self.puts=0;self.reads=0;self.policy_checks=0;self.tamper=False
    def policy(self):self.policy_checks+=1
    def call(self,url,method='GET',data=None,headers=None,limit=None):
        assert url.startswith(STORAGE+'/generation-journals/'+GEN[2:]+'/')
        if method=='PUT':
            assert headers['If-None-Match']=='*' and headers['x-ms-blob-type']=='BlockBlob'
            if url in self.objects:
                hs=Message();hs['x-ms-error-code']='BlobImmutableDueToPolicy'
                raise HTTPError(url,409,'retained',hs,None)
            self.puts+=1;self.objects[url]=bytes(data)
            return b'',{}
        assert method=='GET';self.reads+=1
        result=self.objects[url]
        if self.tamper:
            q=json.loads(result);q['ciphertextB64']='AAAA';result=canonical(q)
        assert len(result)<=limit
        return result,{'ETag':'"immutable"'}


def package(tmp_path):
    root=namespace(tmp_path)
    for name in DATABASES:
        with closing(database(root,name)):pass
    return snapshot(root,GEN)


def test_create_only_encrypted_objects_deduplicate_and_restore_from_cloud_gets(tmp_path):
    p=package(tmp_path);a=Azure()
    receipt=replicate(p,a,KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:1234)
    assert receipt['restoreMatches'] and receipt['restoredAt']==1234 and receipt['databaseCount']==len(DATABASES)
    assert a.puts==2 and a.reads==4 and a.policy_checks==1
    assert receipt==replicate(p,a,KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:1234)
    assert a.puts==2 and a.reads==8
    assert b'exact signed bundle' not in b''.join(a.objects.values())
    assert restore_from_azure(a,KEY,GEN,receipt['manifest'],parent=tmp_path)['restoreMatches']


@pytest.mark.parametrize('fault',['key','generation','digest','kind','ciphertext'])
def test_encrypted_envelope_binds_key_generation_digest_kind_and_bytes(fault):
    raw=b'private synthetic journal';digest=sha256(raw).hexdigest();encrypted=encrypt(raw,KEY,GEN,'database')
    key=KEY;gen=GEN;kind='database'
    if fault=='key':key=bytes(reversed(KEY))
    elif fault=='generation':gen=OTHER
    elif fault=='digest':digest='ff'*32
    elif fault=='kind':kind='manifest'
    else:
        q=json.loads(encrypted);q['ciphertextB64']='AAAA';encrypted=canonical(q)
    with pytest.raises((ValueError,InvalidTag)):
        decrypt(encrypted,key,gen,digest,kind)


def test_corrupt_cloud_bytes_cannot_produce_healthy_receipt(tmp_path):
    p=package(tmp_path);a=Azure();a.tamper=True
    with pytest.raises((ValueError,InvalidTag)):
        replicate(p,a,KEY,GEN,SOURCE,parent=tmp_path)


def test_synthetic_drill_evidence_is_explicitly_distinct_from_live_generation(tmp_path):
    receipt=replicate(package(tmp_path),Azure(),KEY,GEN,SOURCE,parent=tmp_path,purpose='SYNTHETIC_RESTORE_DRILL')
    assert receipt['purpose']=='SYNTHETIC_RESTORE_DRILL'


def test_missing_live_database_cannot_be_relabelled_as_complete_recovery(tmp_path):
    p=package(tmp_path);name=next(iter(p['manifest']['files']))
    p['manifest']['files'].pop(name)
    # Remaining identical DB bytes still satisfy export integrity. The complete
    # live inventory gate must independently reject this omission.
    with pytest.raises(ValueError,match='REQUIRED_DATABASE_MISSING'):
        replicate(p,Azure(),KEY,GEN,SOURCE,parent=tmp_path)
    receipt=replicate(p,Azure(),KEY,GEN,SOURCE,parent=tmp_path,purpose='SYNTHETIC_RESTORE_DRILL')
    assert receipt['purpose']=='SYNTHETIC_RESTORE_DRILL' and receipt['databaseCount']==len(DATABASES)-1
