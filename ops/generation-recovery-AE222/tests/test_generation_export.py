from copy import deepcopy
import pytest
from generation_export import dispatch
from generation_replication import replicate
from test_generation_replication import package, Azure, KEY, GEN, SOURCE


def config():return {'schema':'solslot.generation-recovery-config.v1','generationId':GEN,'sourceHash':SOURCE,
 'journalRoot':'/opt/solslot/generation-AE220/state/journals/generations/'+GEN[2:]}


def test_only_fixed_generation_snapshot_and_fresh_receipt_are_supported(tmp_path):
    calls=[]
    def capture(root,gen):calls.append((str(root),gen));return {'fixed':'snapshot'}
    assert dispatch({'op':'snapshot','generationId':GEN},config(),capture=capture)=={'fixed':'snapshot'}
    assert calls==[(config()['journalRoot'],GEN)]
    receipt=replicate(package(tmp_path),Azure(),KEY,GEN,SOURCE,parent=tmp_path)
    output=[]
    assert dispatch({'op':'receipt','generationId':GEN,'receipt':receipt},config(),publish=output.append)=={'accepted':True,'generationId':GEN}
    assert output==[receipt]


@pytest.mark.parametrize('body',[{'op':'snapshot','generationId':GEN,'path':'/etc/shadow'},
 {'op':'shell','generationId':GEN},{'op':'snapshot','generationId':'0x'+'44'*32},
 {'op':'delete','generationId':GEN},{'op':'snapshot'},None])
def test_arbitrary_paths_commands_and_other_generations_are_rejected(body):
    with pytest.raises(ValueError):dispatch(body,config(),capture=lambda *a:pytest.fail('not authorized'))


def test_receipt_publication_keeps_api_group_read_and_protected_mode(tmp_path,monkeypatch):
    import os
    from types import SimpleNamespace
    import generation_export as exporter
    health=tmp_path/'health';health.mkdir(mode=0o750)
    monkeypatch.setattr(exporter,'RECEIPT',health/'latest.json')
    monkeypatch.setattr(exporter.os,'fchown',lambda *args:None)
    monkeypatch.setattr(exporter.grp,'getgrnam',lambda _:SimpleNamespace(gr_gid=os.getgid()))
    mask=os.umask(0o077)
    try:
        exporter.publish_receipt({'synthetic':'metadata only'})
        assert exporter.RECEIPT.stat().st_mode&0o777==0o640
        assert not list(health.glob('*.incoming*'))
    finally:os.umask(mask)
