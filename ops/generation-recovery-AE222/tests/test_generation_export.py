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


def test_root_export_routes_sqlite_capture_through_fixed_unprivileged_child(tmp_path,monkeypatch):
    import subprocess
    import generation_export as exporter
    from generation_snapshot import canonical,snapshot
    from test_generation_snapshot import namespace,database
    from contextlib import closing
    root=namespace(tmp_path)
    with closing(database(root)):pass
    package=snapshot(root,GEN);calls=[]
    def child(args,**kwargs):
        calls.append(args)
        assert kwargs['stderr']==subprocess.DEVNULL and kwargs['timeout']==90
        kwargs['stdout'].write(canonical(package))
        return type('Result',(),{'returncode':0})()
    monkeypatch.setattr(exporter.subprocess,'run',child)
    original_tempfile=exporter.tempfile.TemporaryFile
    monkeypatch.setattr(exporter.tempfile,'TemporaryFile',lambda **kwargs:original_tempfile(dir=tmp_path))
    assert exporter.capture_unprivileged(root,GEN)==package
    assert calls==[['/usr/sbin/runuser','-u','solslot-api','--','/usr/bin/python3','-I',
        '/opt/solslot/generation-recovery-AE222/worker_entry.py','--snapshot']]


def test_snapshot_child_cannot_retain_root_identity(monkeypatch):
    import generation_export as exporter
    from types import SimpleNamespace
    monkeypatch.setattr(exporter.os,'geteuid',lambda:0)
    monkeypatch.setattr(exporter.pwd,'getpwnam',lambda _:SimpleNamespace(pw_uid=101))
    monkeypatch.setattr(exporter,'bound_snapshot_output',lambda:pytest.fail('root cannot snapshot'))
    with pytest.raises(ValueError,match='REQUIRES_API_IDENTITY'):exporter.child_snapshot()


def test_snapshot_child_bounds_output_after_uid_check_before_loading_journals(monkeypatch):
    import generation_export as exporter
    from types import SimpleNamespace
    calls=[]
    monkeypatch.setattr(exporter.os,'geteuid',lambda:101)
    monkeypatch.setattr(exporter.pwd,'getpwnam',lambda _:SimpleNamespace(pw_uid=101))
    monkeypatch.setattr(exporter,'bound_snapshot_output',lambda:calls.append('limit'))
    def load():
        calls.append('config')
        raise ValueError('test stops before reading journals')
    monkeypatch.setattr(exporter,'load_config',load)
    with pytest.raises(ValueError,match='test stops'):exporter.child_snapshot()
    assert calls==['limit','config']


def test_snapshot_output_hard_limit_is_enforced_by_os_in_child(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path
    import generation_export as exporter
    target=tmp_path/'bounded-synthetic-output'
    code='''
import errno,json,os,resource,signal,sys
sys.path.insert(0,sys.argv[1])
from generation_export import bound_snapshot_output
signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
bound_snapshot_output(4096)
assert resource.getrlimit(resource.RLIMIT_FSIZE)==(4096,4096)
fd=os.open(sys.argv[2],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
try:
    assert os.write(fd,b'x'*8192)==4096
    try:os.write(fd,b'x')
    except OSError as exc:assert exc.errno==errno.EFBIG
    else:raise AssertionError('file-size limit not enforced')
finally:os.close(fd)
print(json.dumps({'bytes':os.stat(sys.argv[2]).st_size}))
'''
    result=subprocess.run([sys.executable,'-I','-c',code,str(Path(exporter.__file__).parent),str(target)],
        capture_output=True,text=True,check=True,timeout=10)
    assert json.loads(result.stdout)=={'bytes':4096}
    assert target.stat().st_size==4096
