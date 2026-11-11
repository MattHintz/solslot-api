from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import base64
import json
import sqlite3
import pytest

from generation_snapshot import snapshot, canonical
from generation_media import capture, validate, replicate, validate_receipt, source_root, accepted_assets
from generation_replication import STORAGE
from test_generation_replication import package as journal_package, Azure as JournalAzure, KEY, SOURCE
from test_generation_snapshot import GEN, OTHER

CONTENT=b"synthetic verified media bytes"
DIGEST=sha256(CONTENT).hexdigest()
KEY_NAME="collections/v2/"+"aa"*32+"/"+"bb"*16+"/asset.png"
CID="b"+"a"*50

def setup(tmp_path, private=False, pinned=True):
    journal_package(tmp_path)
    journal=tmp_path/'generations'/GEN[2:]
    with sqlite3.connect(journal/'collections.sqlite') as con:
        con.execute("CREATE TABLE property_collection_assets(object_key,actual_sha256,expected_sha256,expected_byte_size,actual_byte_size,state,malware_status,visibility,ipfs_cid)")
        key=('private/' if private else '')+KEY_NAME
        con.execute('INSERT INTO property_collection_assets VALUES(?,?,?,?,?,?,?,?,?)',(key,DIGEST,DIGEST,len(CONTENT),len(CONTENT),'PINNED' if pinned else 'VERIFIED','CLEAN','PRIVATE' if private else 'PUBLIC',None if private or not pinned else CID))
    root=tmp_path/'collection-media'/GEN[2:]
    root.mkdir(parents=True,mode=0o700)
    (root/'quarantine').mkdir(mode=0o700);(root/'public').mkdir(mode=0o700)
    oid=sha256(key.encode()).hexdigest()
    (root/'quarantine'/(oid+'.blob')).write_bytes(CONTENT)
    (root/'quarantine'/(oid+'.blob')).chmod(0o600)
    if not private and pinned:
        (root/'public'/(oid+'.blob')).write_bytes(CONTENT)
        (root/'public'/(oid+'.blob')).chmod(0o600)
    return journal,root,oid

def ipfs(op,arg=None):
    return b'{"ID":"retained-ipfs-node"}' if op=='id' else b'synthetic-car-for-'+arg.encode()

class Azure(JournalAzure):
    def call(self,url,**kwargs):
        if '/generation-media/' not in url:return super().call(url,**kwargs)
        from email.message import Message
        from urllib.error import HTTPError
        assert url.startswith(STORAGE+'/generation-media/'+GEN[2:]+'/')
        method=kwargs.get('method','GET')
        if method=='PUT':
            assert kwargs['headers']['If-None-Match']=='*'
            if url in self.objects:
                hs=Message();hs['x-ms-error-code']='BlobImmutableDueToPolicy'
                raise HTTPError(url,409,'retained',hs,None)
            self.puts+=1;self.objects[url]=kwargs['data'];return b'',{}
        assert method=='GET';self.reads+=1
        result=self.objects[url]
        assert len(result)<=kwargs['limit']
        if self.tamper:result=b'corrupted'
        return result,{'ETag':'"immutable"'}

@pytest.mark.parametrize('private,pinned',[(False,True),(False,False),(True,False)])
def test_real_snapshot_media_and_journals_roundtrip_through_cloud_get(tmp_path,private,pinned):
    j,r,oid=setup(tmp_path,private,pinned);p=capture(j,r,GEN,ipfs=ipfs);m,_=validate(p,GEN)
    a=Azure();record,media=replicate(p,a,KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:10000)
    assert record['databaseCount']==21 and record['restoreMatches']
    assert media['assetCount']==1 and media['assetBytes']==len(CONTENT) and media['carCount']==int(not private and pinned)
    assert media['restoreMatches'] and validate_receipt(media,GEN,SOURCE,now=10000)==media
    assert m['assets'][0]['public']==(not private and pinned)
    before=a.puts
    assert replicate(p,a,KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:10000)==(record,media)
    assert a.puts==before and a.reads>8
    assert not list(tmp_path.glob('media-restore-*'))
    assert CONTENT not in b''.join(a.objects.values())

@pytest.mark.parametrize('fault',['wrong_generation','asset_omission','public_escalation','extra_payload','wrong_bytes','missing_car','foreign_cid','journal_tamper'])
def test_package_cannot_omit_assets_leak_private_or_change_generation(tmp_path,fault):
    j,r,_=setup(tmp_path);p=capture(j,r,GEN,ipfs=ipfs)
    if fault=='wrong_generation':p['manifest']['generationId']=OTHER
    elif fault=='asset_omission':p['manifest']['assets']=[]
    elif fault=='public_escalation':p['manifest']['assets'][0]['public']=False
    elif fault=='extra_payload':p['payloads']['ff'*32]='AA=='
    elif fault=='wrong_bytes':p['payloads'][DIGEST]=base64.b64encode(b'bad').decode()
    elif fault=='missing_car':p['manifest']['cars']=[]
    elif fault=='foreign_cid':p['manifest']['cars'][0]['cid']='b'+'b'*50
    else:p['journalPayloads'].clear()
    with pytest.raises(ValueError):validate(p,GEN)

@pytest.mark.parametrize('fault',['symlink','writable','missing','changed','public_changed','wrong_root','unclean','private_cid'])
def test_export_rejects_unprotected_or_inconsistent_accepted_assets(tmp_path,fault):
    j,r,oid=setup(tmp_path)
    path=r/'quarantine'/(oid+'.blob')
    if fault=='symlink':path.unlink();path.symlink_to('/etc/passwd')
    elif fault=='writable':(r/'quarantine').chmod(0o777)
    elif fault=='missing':path.unlink()
    elif fault=='changed':path.write_bytes(b'bad')
    elif fault=='public_changed':(r/'public'/(oid+'.blob')).write_bytes(b'bad')
    elif fault=='wrong_root':r=r.parent
    else:
        with sqlite3.connect(j/'collections.sqlite') as con:
            if fault=='unclean':con.execute("UPDATE property_collection_assets SET malware_status='REJECTED'")
            else:con.execute("UPDATE property_collection_assets SET visibility='PRIVATE',object_key='private/'||object_key")
    with pytest.raises((ValueError,OSError)):capture(j,r,GEN,ipfs=ipfs)

@pytest.mark.parametrize('change',[{'checkedAt':9399},{'restoredAt':9399},{'sourceHash':OTHER},{'generationId':OTHER},{'restoreMatches':False},{'assetCount':True},{'extra':'value'},{'network':'mainnet'}])
def test_unhealthy_media_receipts_cannot_authorize_uploads(tmp_path,change):
    j,r,_=setup(tmp_path);_,q=replicate(capture(j,r,GEN,ipfs=ipfs),Azure(),KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:10000)
    q.update(change)
    with pytest.raises(ValueError):validate_receipt(q,GEN,SOURCE,now=10000)

def test_later_upload_is_not_claimed_by_earlier_frozen_journal(tmp_path):
    j,r,_=setup(tmp_path);p=capture(j,r,GEN,ipfs=ipfs)
    with sqlite3.connect(j/'collections.sqlite') as con:con.execute('DELETE FROM property_collection_assets')
    # The retained cut remains independently restorable; a later cut records the change.
    assert len(validate(p,GEN)[0]['assets'])==1
    assert capture(j,r,GEN,ipfs=ipfs)['manifest']['assets']==[]


def test_car_overhead_is_restorable_and_still_bounded(tmp_path):
    j,r,_=setup(tmp_path)
    car=b'c'*(20*1024**2+32)
    def export(op,arg=None):return ipfs(op,arg) if op=='id' else car
    package=capture(j,r,GEN,ipfs=export)
    _,receipt=replicate(package,Azure(),KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:10000)
    assert receipt['carCount']==1 and receipt['restoreMatches']
    car=b'c'*(21*1024**2+1)
    with pytest.raises(ValueError,match='CAR_BOUNDS'):capture(j,r,GEN,ipfs=export)
