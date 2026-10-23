from hashlib import sha256
from types import SimpleNamespace
from copy import deepcopy
import threading
import sqlite3
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from generation_media import capture,replicate,validate_receipt
from generation_snapshot import canonical
from solslot_api.collection_media_recovery_contract import validate_receipt as api_contract
from solslot_api import collection_generation_media_recovery as admission
from solslot_api import collection_generation_recovery as records
from solslot_api.config import Settings
from test_generation_media import setup,ipfs,Azure,KEY,SOURCE,GEN


def test_same_receipt_contract_and_actual_inventory_admit_seal(tmp_path,monkeypatch):
    j,r,_=setup(tmp_path);record,receipt=replicate(capture(j,r,GEN,ipfs=ipfs),Azure(),KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:10000)
    assert validate_receipt(receipt,GEN,SOURCE,now=10000)==api_contract(receipt,GEN,SOURCE,now=10000)
    monkeypatch.setattr(admission,'read_media_receipt',lambda settings:receipt)
    con=sqlite3.connect(j/'collections.sqlite')
    store=SimpleNamespace(_lock=threading.RLock(),_conn=con)
    monkeypatch.setattr('solslot_api.collection_store.get_collection_store',lambda settings:store)
    settings=Settings(_env_file=None,runtime_environment='test',deployment_generation_id=GEN)
    assert admission.require_media_recovery(settings,require_current_inventory=True)==receipt
    con.execute('DELETE FROM property_collection_assets');con.commit()
    with pytest.raises(HTTPException) as error:admission.require_media_recovery(settings,require_current_inventory=True)
    assert error.value.status_code==503 and error.value.detail['code']=='COLLECTION_MEDIA_RECOVERY_PENDING'
    con.close()


def test_upload_requires_both_record_and_media_restore_but_status_is_read_only(monkeypatch):
    settings=Settings(_env_file=None,runtime_environment='test',deployment_generation_id=GEN)
    calls=[]
    monkeypatch.setattr(records,'require_record_recovery',lambda s:calls.append('record'))
    monkeypatch.setattr(admission,'require_media_recovery',lambda s,**kw:calls.append(('media',kw['require_current_inventory'])))
    def request(method,path):return Request({'type':'http','method':method,'path':path,'headers':[],'query_string':b''})
    records.require_preparation_step(request('GET','/admin/collections/X'),settings)
    assert calls==[]
    records.require_preparation_step(request('POST','/admin/collections/X/assets/presign'),settings)
    assert calls==['record',('media',False)]
    calls.clear()
    records.require_preparation_step(request('POST','/admin/collections/X/seal'),settings)
    assert calls==['record',('media',True)]


def test_recovery_transport_admits_only_configured_fixed_media_snapshot(monkeypatch):
    from generation_export import dispatch
    from test_generation_export import config
    q=config();seen=[]
    with pytest.raises(ValueError):dispatch({'op':'media-snapshot','generationId':GEN},q,capture_media=lambda *a:None)
    q['mediaRoot']='/opt/solslot/generation-AE220/state/collection-media/'+GEN[2:]
    assert dispatch({'op':'media-snapshot','generationId':GEN},q,capture_media=lambda *a:seen.append(a)) is None
    assert len(seen)==1 and str(seen[0][1])==q['mediaRoot']
    for field in ('path','url','mediaRoot','keyReference'):
        with pytest.raises(ValueError):dispatch({'op':'media-snapshot','generationId':GEN,field:'/etc/shadow'},q,capture_media=lambda *a:pytest.fail('caller controls rejected'))
