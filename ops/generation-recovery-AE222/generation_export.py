"""Fixed SSH forced command for the new generation journals, separate from AE181."""
import json
import grp
import pwd
import resource
import subprocess
import tempfile
import os
from pathlib import Path
import re
import stat
import sys
from generation_snapshot import snapshot, canonical, generation, protected_path, MAX_TOTAL
from generation_health import validate_receipt

CONFIG=Path('/etc/solslot-generation-recovery-AE222.json')
RECEIPT=Path('/opt/solslot/generation-recovery-AE222/health/latest.json')
MAX_OUTPUT=MAX_TOTAL*2+1024**2


def load_config(path=CONFIG):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>8192:
            raise ValueError('GENERATION_RECOVERY_CONFIG_NOT_PROTECTED')
        q=json.loads(stream.read(8193))
    if not isinstance(q,dict) or set(q)!= {'schema','generationId','sourceHash','journalRoot'} or (
        q['schema']!='solslot.generation-recovery-config.v1'):
        raise ValueError('GENERATION_RECOVERY_CONFIG_DIFFERS')
    identity=generation(q['generationId']);generation(q['sourceHash'])
    if q['journalRoot']!='/opt/solslot/generation-AE220/state/journals/generations/'+identity:
        raise ValueError('GENERATION_RECOVERY_SOURCE_DIFFERS')
    return q


def dispatch(request,config,*,capture=snapshot,publish=None):
    if not isinstance(request,dict) or request.get('generationId')!=config['generationId']:
        raise ValueError('GENERATION_RECOVERY_REQUEST_DIFFERS')
    if request.get('op')=='snapshot' and set(request)=={'op','generationId'}:
        return capture(Path(config['journalRoot']),config['generationId'])
    if request.get('op')=='receipt' and set(request)=={'op','generationId','receipt'}:
        value=validate_receipt(request['receipt'],config['generationId'],config['sourceHash'])
        if publish is None:raise ValueError('GENERATION_RECOVERY_RECEIPT_WRITER_MISSING')
        publish(value)
        return {'accepted':True,'generationId':config['generationId']}
    raise ValueError('GENERATION_RECOVERY_OPERATION_REJECTED')


def publish_receipt(value):
    protected_path(RECEIPT.parent,directory=True)
    target=RECEIPT.with_name('latest.incoming-ae222')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    try:
        os.fchown(fd,0,grp.getgrnam('solslot-api').gr_gid)
        os.fchmod(fd,0o640)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.replace(target,RECEIPT)
        fd=os.open(RECEIPT.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        # Remove only this program's temporary receipt on failure, never a retained ledger.
        if target.exists():target.unlink()



def capture_unprivileged(root,generation_id):
    # The root forced command publishes protected receipts, but it must never
    # reopen API-owned paths as root. A separate child gets only the API uid's
    # existing filesystem access, closing the check/open replacement boundary.
    limit=MAX_OUTPUT
    with tempfile.TemporaryFile(dir='/run') as output:
        result=subprocess.run(['/usr/sbin/runuser','-u','solslot-api','--','/usr/bin/python3','-I',
            '/opt/solslot/generation-recovery-AE222/worker_entry.py','--snapshot'],
            stdout=output,stderr=subprocess.DEVNULL,check=False,timeout=90)
        if result.returncode or output.tell()>limit:raise ValueError('GENERATION_SNAPSHOT_CHILD_FAILED')
        output.seek(0);raw=output.read(limit+1)
        if len(raw)>limit:raise ValueError('GENERATION_SNAPSHOT_CHILD_TOO_LARGE')
    result=json.loads(raw)
    from generation_snapshot import validate_export
    validate_export(result,generation_id)
    return result


def bound_snapshot_output(limit=MAX_OUTPUT):
    # runuser resets RLIMIT_FSIZE on supported hosts. Set the hard and soft
    # limits inside the unprivileged process, before reading any journal.
    resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))


def child_snapshot():
    if os.geteuid()!=pwd.getpwnam('solslot-api').pw_uid:
        raise ValueError('GENERATION_SNAPSHOT_REQUIRES_API_IDENTITY')
    bound_snapshot_output()
    config=load_config()
    sys.stdout.buffer.write(canonical(snapshot(Path(config['journalRoot']),config['generationId']))+b'\n')


def main():
    if os.geteuid()!=0:raise ValueError('FIXED_PRIVILEGED_EXPORT_REQUIRED')
    raw=sys.stdin.buffer.read(16385)
    if len(raw)>16384:raise ValueError('GENERATION_RECOVERY_REQUEST_TOO_LARGE')
    result=dispatch(json.loads(raw),load_config(),capture=capture_unprivileged,publish=publish_receipt)
    sys.stdout.buffer.write(canonical(result)+b'\n')


if __name__=='__main__':
    try:main()
    except Exception:
        print('Generation recovery export failed; inspect metadata-only health.',file=sys.stderr)
        raise SystemExit(1)
