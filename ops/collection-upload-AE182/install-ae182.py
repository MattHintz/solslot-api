"""Pinned upload-only coordinator/static deployment; no Azure or ledger writes."""
import argparse, hashlib, json, os, shutil, subprocess, sys, time, urllib.request
from pathlib import Path
AE='AE-SOLSLOT-PROPERTY-UPLOAD-20261005-182'
OP=Path('/opt/solslot/genesis-rc28/operations/AE182')
ADMIN=Path('/var/www/solslot-admin-ceremony')
MOUNT=Path('/var/www/solslot-admin-mount/genesis-admin')
UNIT='solslot-genesis-rc28.service'
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args): return subprocess.check_output(args,stderr=subprocess.PIPE,text=True).strip()
def install(source,target):
    if source.is_symlink() or target.is_symlink(): raise ValueError('Unexpected installation symlink')
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() and target.read_bytes()!=source.read_bytes(): raise ValueError('Held target differs')
    if not target.exists(): shutil.copyfile(source,target)
    os.chown(target,0,0); target.chmod(0o644)
def switch(path,target):
    temporary=path.with_name(path.name+'.incoming-AE182')
    if temporary.exists() or temporary.is_symlink(): raise ValueError('Pending switch exists')
    temporary.symlink_to(target); os.replace(temporary,path)
def health():
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8792/health',timeout=3) as response: data=json.loads(response.read(65536))
            if data.get('ok') is True and data.get('network')=='testnet11': return
        except (OSError,ValueError): pass
        time.sleep(1)
    raise ValueError('Fresh coordinator health did not pass')
def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--approval',required=True); parser.add_argument('--rollback',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0 or args.approval!=AE: raise ValueError('Exact approved root operation required')
    root=args.package
    manifest=json.loads((root/'package-manifest.json').read_text())
    if manifest['actionEnvelopeId']!=AE: raise ValueError('Package authority differs')
    for name,digest in manifest['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or (root/name).is_symlink() or sha(root/name)!=digest:
            raise ValueError('Package source differs')
    plan=json.loads((root/'plan.json').read_text())
    drop=Path('/etc/systemd/system')/(UNIT+'.d')/plan['dropInName']
    prior=Path(plan['priorAdminRelease']); new=ADMIN/'releases/admin-property-upload-AE182'
    if args.rollback:
        for path in (ADMIN/'current',MOUNT):
            if not path.is_symlink() or path.resolve() not in (prior,new): raise ValueError('Admin rollback lineage differs')
        if drop.exists() and sha(drop)!=sha(root/'runtime.conf'): raise ValueError('Rollback runtime differs')
        if drop.exists():
            held=OP/'hold'/drop.name
            held.parent.mkdir(parents=True,exist_ok=True)
            if held.exists(): raise ValueError('Rollback source is already held')
            shutil.move(drop,held)
        for path in (ADMIN/'current',MOUNT):
            switch(path,prior)
        run(['systemctl','daemon-reload']);run(['systemctl','restart',UNIT]);health()
        print(json.dumps({'actionEnvelopeId':AE,'status':'rolled_back','evidenceRetained':True})); return
    for path in (ADMIN/'current',MOUNT):
        if not path.is_symlink() or path.resolve() not in (prior,new): raise ValueError('Admin delivery lineage differs')
    old=Path(plan['priorDropIn'])
    if not old.is_file() or sha(old)!=plan['priorDropInSha256']: raise ValueError('Prior runtime differs')
    # The old factory and eight-table recovery authority remain intact.
    sys.path.insert(0,str(root/'recovery'))
    from recovery_health import read_receipt
    read_receipt()
    for relative in manifest['files']:
        if relative.startswith(('release/','recovery/')) or relative=='runtime-source-pins.json': install(root/relative,OP/relative)
    install(old,OP/'hold/prior-runtime.conf')
    for relative in manifest['files']:
        if relative.startswith('admin/'): install(root/relative,new/Path(relative).relative_to('admin'))
    for file in prior.rglob('*'):
        if file.is_file() and not file.is_symlink() and file.suffix in ('.js','.css','.wasm'):
            install(file,new/file.relative_to(prior))
    install(root/'runtime.conf',drop)
    run(['systemctl','daemon-reload']);run(['systemctl','restart',UNIT]);health();read_receipt()
    for path in (ADMIN/'current',MOUNT): switch(path,new)
    print(json.dumps({'actionEnvelopeId':AE,'status':'deployed','network':'testnet11','mintingEnabled':False,'transactions':0}))
if __name__=='__main__':
    try:main()
    except Exception as error:
        print('AE182 stopped: '+str(error) if isinstance(error,ValueError) else 'AE182 deployment command failed; inspect service metadata without secret values',file=sys.stderr)
        raise SystemExit(1)
