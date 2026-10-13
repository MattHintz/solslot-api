"""Synthetic token claims only; no live bearer tokens or credentials."""
import base64,json
from copy import deepcopy
import pytest
from generation_worker import validate_tokens,AE,RESOURCES
from test_generation_replication import GEN,SOURCE


def token(resource,**changes):
    claims={'oid':'6b6d66ae-e403-406e-8e2c-0f0b2709f1f4','tid':'0c1708db-7f87-4fe9-9a96-eac4795c39bd',
            'aud':resource,'exp':5000}|changes
    return 'SYNTHETIC.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.NOT_A_SIGNATURE'


def record():return {'schema':'solslot.generation-identity-tokens.v1','actionEnvelopeId':AE,
 'generationId':GEN,'sourceHash':SOURCE,'tokens':{r:token(r) for r in RESOURCES}}


def test_root_staged_tokens_bind_exact_generation_principal_resources_and_expiry():
    q=record();out=validate_tokens(q,{'generationId':GEN,'sourceHash':SOURCE},now=1000)
    assert set(out)==RESOURCES
    q['tokens']['https://vault.azure.net/']=token('cfa8b339-82a2-471a-a3c9-0fc0be7a4093')
    validate_tokens(q,{'generationId':GEN,'sourceHash':SOURCE},now=1000)


@pytest.mark.parametrize('fault',['generation','source','envelope','missing_resource','extra_resource','principal','tenant','expired','wrong_audience'])
def test_staged_authority_cannot_rebind_or_cross_resource(fault):
    q=record();r='https://storage.azure.com/'
    if fault=='generation':q['generationId']='0x'+'44'*32
    elif fault=='source':q['sourceHash']='0x'+'44'*32
    elif fault=='envelope':q['actionEnvelopeId']='AE181'
    elif fault=='missing_resource':q['tokens'].pop(r)
    elif fault=='extra_resource':q['tokens']['https://other/']=token('https://other/')
    elif fault=='principal':q['tokens'][r]=token(r,oid='other')
    elif fault=='tenant':q['tokens'][r]=token(r,tid='other')
    elif fault=='expired':q['tokens'][r]=token(r,exp=1300)
    elif fault=='wrong_audience':q['tokens'][r]=token('https://vault.azure.net/')
    with pytest.raises(ValueError):validate_tokens(q,{'generationId':GEN,'sourceHash':SOURCE},now=1000)


def test_root_staging_preserves_group_read_under_private_umask(tmp_path,monkeypatch):
    import os
    from types import SimpleNamespace
    import generation_worker as worker
    monkeypatch.setattr(worker.os,'geteuid',lambda:0)
    monkeypatch.setattr(worker.os,'fchown',lambda *args:None)
    monkeypatch.setattr(worker.pwd,'getpwnam',lambda _:SimpleNamespace(pw_gid=os.getgid()))
    monkeypatch.setattr(worker,'existing_azure',lambda **kwargs:SimpleNamespace(token=lambda resource:token(resource,exp=4_000_000_000)))
    mask=os.umask(0o077)
    try:
        path=tmp_path/'identity.json'
        worker.stage_tokens({'generationId':GEN,'sourceHash':SOURCE},path=path)
        assert path.stat().st_mode&0o777==0o640
        assert not list(tmp_path.glob('*.incoming*'))
    finally:os.umask(mask)
