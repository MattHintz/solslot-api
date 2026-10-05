"""Concrete approved deployment phases. No property upload or transaction calls."""
import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

AE='AE-SOLSLOT-COLLECTION-AUTHORING-20261005-181'
OP=Path('/opt/solslot/genesis-rc28/operations/AE181')
REC=Path('/opt/solslot/collection-recovery-AE181')
UNIT='solslot-genesis-rc28.service'
ADMIN=Path('/var/www/solslot-admin-ceremony')
USER='solslot-recovery-ae181'

def command(args):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout.strip()

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def install_file(source,target,mode=0o644):
    if source.is_symlink() or target.is_symlink():raise ValueError('Unexpected installation symlink')
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() and target.read_bytes()!=source.read_bytes():raise ValueError('Existing held deployment differs: '+str(target))
    if not target.exists():shutil.copyfile(source,target)
    target.chmod(mode);os.chown(target,0,0)

def atomic(target,data,mode=0o644):
    temp=target.with_name(target.name+'.incoming-ae181')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(temp,target)

def verified_package(root):
    manifest=json.loads((root/'package-manifest.json').read_text())
    if manifest['actionEnvelopeId']!=AE:raise ValueError('Package authority differs')
    for name,expected in manifest['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('Invalid package path')
        p=root/name
        if p.is_symlink() or digest(p)!=expected:raise ValueError('Package differs: '+name)
    return json.loads((root/'plan.json').read_text())

def service_health():
    if command(['systemctl','is-active',UNIT])!='active':raise ValueError('Coordinator not active')
    with urllib.request.urlopen('http://127.0.0.1:8792/health',timeout=30) as r:q=json.loads(r.read(65536))
    if q.get('network')!='testnet11' or q.get('ok') is not True:raise ValueError('Fresh coordinator health failed')
    return q

def api_dropin(plan,enabled):
    py=plan['coordinatorPython']
    data='[Service]\nEnvironment="PYTHONPATH='+str(OP/'release/api')+':/opt/solslot/genesis-rc28/operations/AE161/release/protocol"\n'
    data+='Environment="SOLSLOT_COLLECTION_METADATA_ENABLED='+('true' if enabled else 'false')+'"\n'
    data+='Environment="SOLSLOT_COLLECTION_MINTING_ENABLED=false"\nEnvironment="SOLSLOT_MINTING_ENABLED=false"\n'
    data+='Environment="SOLSLOT_COLLECTION_LOCAL_QUOTA_BYTES=25165824"\nEnvironment="SOLSLOT_COLLECTION_ASSET_MAX_BYTES=8388608"\n'
    data+='ExecStart=\nExecStart='+py+' -m uvicorn --app-dir '+str(OP/'recovery')+' --factory solslot_collection_recovery_AE181:create_app --host 127.0.0.1 --port 8792 --proxy-headers --forwarded-allow-ips 127.0.0.1 --timeout-keep-alive 5 --timeout-graceful-shutdown 30 --limit-concurrency 100 --backlog 256 --no-server-header --no-access-log\n'
    return data.encode()

def new_user(home,shell):
    try:account=pwd.getpwnam(USER)
    except KeyError:
        command(['useradd','--system','--no-create-home','--home-dir',str(home),'--shell',shell,USER]);account=pwd.getpwnam(USER)
    if Path(account.pw_dir)!=home or account.pw_shell!=shell:raise ValueError('Existing recovery user differs')
    return account

def coordinator(root,plan,phase,credential):
    drop=Path('/etc/systemd/system/'+UNIT+'.d')/plan['dropInName']
    if phase=='prepare':
        for name in json.loads((root/'package-manifest.json').read_text())['files']:
            if name.startswith(('release/','recovery/')) or name in ('runtime-source-pins.json','plan.json'):
                install_file(root/name,OP/name)
        for relative,expected in plan['preservedFactories'].items():
            p=OP.parent/relative
            if p.is_symlink() or digest(p)!=expected:raise ValueError('Prior runtime changed')
        home=Path('/var/lib/solslot-recovery-ae181');account=new_user(home,'/bin/sh')
        home.mkdir(mode=0o750,exist_ok=True);os.chown(home,0,account.pw_gid);home.chmod(0o750)
        keys=home/'.ssh';keys.mkdir(mode=0o750,exist_ok=True);os.chown(keys,0,account.pw_gid);keys.chmod(0o750)
        value=json.loads(credential.read_text());key=value['publicKey']
        if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{60,100}={0,2}',key):raise ValueError('Public recovery key differs')
        data=('restrict,from="10.77.0.12",command="/usr/bin/sudo -n /usr/bin/python3 -E -s '+str(REC/'collection_snapshot.py')+'" '+key+'\n').encode()
        target=keys/'authorized_keys'
        if target.exists() and target.read_bytes()!=data:raise ValueError('Existing recovery public key differs')
        if not target.exists():atomic(target,data,0o640)
        os.chown(target,0,account.pw_gid)
        REC.mkdir(mode=0o755,exist_ok=True)
        for name in ('collection_snapshot.py','recovery_health.py'):install_file(root/'recovery'/name,REC/name)
        health=REC/'health';health.mkdir(mode=0o750,exist_ok=True);os.chown(health,0,pwd.getpwnam('solslot-api').pw_gid);health.chmod(0o750)
        sudo=Path('/etc/sudoers.d/solslot-collection-recovery-ae181')
        data=(USER+' ALL=(root) NOPASSWD: /usr/bin/python3 -E -s '+str(REC/'collection_snapshot.py')+'\n').encode()
        if sudo.exists() and sudo.read_bytes()!=data:raise ValueError('Existing sudo rule differs')
        if not sudo.exists():atomic(sudo,data,0o440)
        command(['visudo','-cf',str(sudo)])
        rule=Path('/etc/ssh/sshd_config.d/solslot-collection-recovery-ae181.conf')
        data=('Match User '+USER+'\n  PasswordAuthentication no\n  AuthenticationMethods publickey\n  PermitTTY no\n  AllowTcpForwarding no\n  AllowAgentForwarding no\n  X11Forwarding no\n  PermitTunnel no\n  ForceCommand /usr/bin/sudo -n /usr/bin/python3 -E -s '+str(REC/'collection_snapshot.py')+'\nMatch all\n').encode()
        if rule.exists() and rule.read_bytes()!=data:raise ValueError('Existing SSH rule differs')
        if not rule.exists():atomic(rule,data)
        command(['/usr/sbin/sshd','-t'])
        effective=command(['/usr/sbin/sshd','-T','-C','user='+USER+',host=10.77.0.1,addr=10.77.0.12'])
        if 'forcecommand /usr/bin/sudo -n /usr/bin/python3 -E -s '+str(REC/'collection_snapshot.py') not in effective or 'permittty no' not in effective or 'authenticationmethods publickey' not in effective:raise ValueError('Restricted SSH settings were not applied')
        command(['systemctl','reload','ssh.service'])
    elif phase=='api-stage':
        if not (OP/'runtime-source-pins.json').is_file():raise ValueError('Prepare first')
        if (ADMIN/'current').resolve()!=Path(plan['priorAdminRelease']):raise ValueError('Admin release changed since review')
        if drop.exists():raise ValueError('AE181 drop-in already exists; reconcile before changing it')
        atomic(drop,api_dropin(plan,False));command(['systemctl','daemon-reload']);command(['systemctl','restart',UNIT]);service_health()
    elif phase=='activate':
        sys.path.insert(0,str(REC));from recovery_health import read_receipt
        read_receipt()
        if not drop.is_file() or drop.read_bytes()!=api_dropin(plan,False):raise ValueError('Exact paused AE181 runtime required')
        atomic(drop,api_dropin(plan,True));command(['systemctl','daemon-reload']);command(['systemctl','restart',UNIT]);service_health();read_receipt()
    elif phase=='admin':
        current=ADMIN/'current';prior=Path(plan['priorAdminRelease'])
        if current.resolve()!=prior:raise ValueError('Current admin release changed')
        dest=ADMIN/'releases/admin-property-form-AE181'
        dest.mkdir(exist_ok=True)
        for file in (root/'admin').rglob('*'):
            if file.is_file():install_file(file,dest/file.relative_to(root/'admin'))
        # Preserve prior lazy chunks so an already open tab can finish its reads.
        for file in prior.rglob('*'):
            if not file.is_file() or file.is_symlink() or file.name in ('index.html','release.json','_headers'):continue
            target=dest/file.relative_to(prior)
            if not target.exists():install_file(file,target)
            elif file.suffix in ('.js','.css','.wasm') and digest(file)!=digest(target):raise ValueError('Retained shared code path differs')
        link=ADMIN/'current-ae181';link.symlink_to(dest);os.replace(link,current)
    elif phase=='rollback':
        if drop.exists():drop.rename(OP/'disabled-drop-in-AE181.conf')
        current=ADMIN/'current'
        if current.resolve()==ADMIN/'releases/admin-property-form-AE181':
            link=ADMIN/'rollback-ae181';link.symlink_to(plan['priorAdminRelease']);os.replace(link,current)
        denied=Path('/etc/ssh/sshd_config.d/solslot-collection-recovery-ae181-disabled.conf')
        if not denied.exists():atomic(denied,('DenyUsers '+USER+'\n').encode())
        command(['/usr/sbin/sshd','-t']);command(['systemctl','reload','ssh.service'])
        command(['systemctl','daemon-reload']);command(['systemctl','restart',UNIT]);service_health()

def azure(root,phase):
    if phase=='prepare':
        account=new_user(REC,'/usr/sbin/nologin');REC.mkdir(mode=0o755,exist_ok=True)
        for name in ('replicate_collection.py','collection_snapshot.py','recovery_health.py','restore_collection.py'):
            install_file(root/'recovery'/name,REC/name)
        install_file(root/'deployment/tools/bootstrap-azure-credential.py',REC/'bootstrap-azure-credential.py')
        install_file(root/'coordinator-known-host',REC/'coordinator-known-host')
        state=REC/'state';state.mkdir(mode=0o700,exist_ok=True);state.chmod(0o700);os.chown(state,account.pw_uid,account.pw_gid)
        for name in ('solslot-collection-recovery-ae181.service','solslot-collection-recovery-ae181.timer'):
            install_file(root/'deployment/systemd'/name,Path('/etc/systemd/system')/name)
        command(['systemd-analyze','verify','/etc/systemd/system/solslot-collection-recovery-ae181.service','/etc/systemd/system/solslot-collection-recovery-ae181.timer'])
        command(['systemctl','daemon-reload'])
    elif phase=='activate':
        command(['systemctl','start','solslot-collection-recovery-ae181.service'])
        command(['systemctl','enable','--now','solslot-collection-recovery-ae181.timer'])
    elif phase=='rollback':
        command(['systemctl','disable','--now','solslot-collection-recovery-ae181.timer'])
        command(['systemctl','stop','solslot-collection-recovery-ae181.service'])
    else:raise ValueError('Unsupported Azure phase')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--approved',required=True);parser.add_argument('--host',choices=['coordinator','azure'],required=True)
    parser.add_argument('--phase',choices=['prepare','api-stage','admin','activate','rollback'],required=True);parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--public-credential',type=Path);args=parser.parse_args()
    if args.approved!=AE or os.geteuid()!=0:raise ValueError('Exact approved root execution required')
    plan=verified_package(args.package)
    if args.host=='coordinator':
        if command(['systemctl','show','-p','User','--value',UNIT])!='solslot-api':raise ValueError('Coordinator service identity differs')
        for relative,expected in plan['preservedFactories'].items():
            if digest(OP.parent/relative)!=expected:raise ValueError('Exact coordinator source required')
    else:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request=urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',headers={'Metadata':'true'})
        with opener.open(request,timeout=10) as r:compute=json.loads(r.read(65536))
        if compute.get('name')!='vm-sfcog-solslot-signer2-prod-01' or compute.get('subscriptionId')!='5db856e6-9fdd-474d-96a4-241e8cb89320':raise ValueError('Exact Azure VM required')
    if args.host=='coordinator':coordinator(args.package,plan,args.phase,args.public_credential)
    else:azure(args.package,args.phase)
    print(json.dumps({'actionEnvelopeId':AE,'host':args.host,'phase':args.phase,'status':'completed','transactions':0}))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('AE181 deployment stopped: '+str(exc) if isinstance(exc,ValueError) else 'AE181 deployment command failed; inspect service metadata without secret values',file=sys.stderr)
        raise SystemExit(1)
