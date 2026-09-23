"""Pin uvicorn imports and refuse startup on a mismatched runtime patch."""
import os,pathlib,subprocess,json,hashlib,shlex,datetime,pwd
assert os.geteuid()==0
root=pathlib.Path('/opt/solslot/validator/runtime-overlays/identity-thread-356f08dc6935')
manifest=json.loads((root/'runtime-patch.json').read_text())
assert manifest['fixApiCommit']=='356f08dc6935c05dd1c1e1ce73e30bf8fa72fbe6'
username=subprocess.check_output(['systemctl','show','solslot-validator','-p','User','--value'],text=True).strip()
account=pwd.getpwnam(username)
# Source archives are root:root 0640. Grant only the existing service group
# access to the new source copy; never chmod credentials or the frozen release.
for path in [root/'solslot_api',*(root/'solslot_api').rglob('*')]:
 assert not path.is_symlink()
 os.chown(path,0,account.pw_gid)
 path.chmod(0o750 if path.is_dir() else 0o640)
probe="import sys;sys.path.insert(0,"+repr(str(root))+");import solslot_api.validator_service as v;assert v.__file__.startswith("+repr(str(root)+'/')+");print('SERVICE_ACCOUNT_SOURCE_IMPORT_OK')"
subprocess.run(['runuser','-u',username,'--','/opt/solslot/validator/current/.venv/bin/python','-c',probe],check=True)
entry=root/'solslot_runtime_entrypoint.py'
code='''"""Refuse a validator startup that resolves an installed, unpatched package."""
import pathlib, json, hashlib, logging
ROOT=pathlib.Path(__file__).resolve().parent
manifest=json.loads((ROOT/'runtime-patch.json').read_text())
import solslot_api.validator_service as service
import solslot_api.vault_puzzle_hash as vault_hash
for module in (service,vault_hash):
 path=pathlib.Path(module.__file__).resolve()
 assert path.parent==ROOT/'solslot_api', 'Validator loaded outside the pinned source overlay'
 assert hashlib.sha256(path.read_bytes()).hexdigest()==manifest['fileHashes'][path.name], 'Validator source hash mismatch'
from solslot_api.validator_app import app
logging.getLogger('uvicorn.error').warning('Pinned validator runtime patch loaded: %s',manifest['fixApiCommit'])
'''
assert not entry.exists() or entry.read_text()==code
if not entry.exists():entry.write_text(code)
value=subprocess.check_output(['systemctl','show','solslot-validator','-p','ExecStart','--value'],text=True)
args=shlex.split(value.split('argv[]=',1)[1].split(' ; ignore_errors=',1)[0])
assert args[0]=='/opt/solslot/validator/current/.venv/bin/uvicorn'
assert args[1] in ('solslot_api.validator_app:app','solslot_runtime_entrypoint:app')
assert args[args.index('--ssl-cert-reqs')+1]=='2'
args[1]='solslot_runtime_entrypoint:app'
if '--app-dir' in args:
 assert args[args.index('--app-dir')+1]==str(root)
else:args.extend(['--app-dir',str(root)])
target=pathlib.Path('/etc/systemd/system/solslot-validator.service.d/51-identity-import.conf')
content='[Service]\n# AE-SOLSLOT-VALIDATOR-THREAD-20260923-90 import-path correction\nExecStart=\nExecStart='+' '.join(shlex.quote(x) for x in args)+'\n'
assert not target.is_symlink()
assert not target.exists() or target.read_text()==content
if not target.exists():
 with target.open('x') as f:f.write(content)
 target.chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','restart','solslot-validator'],check=True)
assert subprocess.check_output(['systemctl','is-active','solslot-validator'],text=True).strip()=='active'
print(json.dumps({'actionEnvelopeId':'AE-SOLSLOT-VALIDATOR-THREAD-20260923-90','importPathPinned':True,'startupModuleHashGuard':True,'entrypointSha256':hashlib.sha256(code.encode()).hexdigest(),'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'liveEndpointCheckStillRequired':True}))
