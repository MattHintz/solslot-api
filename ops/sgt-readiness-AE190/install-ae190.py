"""Apply or roll back the exact approved AE190 package; preserve runtime data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

AE = 'AE-SOLSLOT-SGT-RECIPIENT-READINESS-20261006-190'
OP = Path('/opt/solslot/genesis-rc28/operations/AE190')
PRIOR = Path('/opt/solslot/genesis-rc28/operations/AE187')
PROTOCOL = Path('/opt/solslot/genesis-rc28/operations/AE161/release')
ADMIN = Path('/var/www/solslot-admin-ceremony')
LINKS = (ADMIN / 'current', Path('/var/www/solslot-admin-mount/genesis-admin'))
NEW_ADMIN = ADMIN / 'releases/admin-sgt-readiness-AE190'
UNIT = 'solslot-genesis-rc28.service'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, text=True).strip()


def install(source, target):
    if source.is_symlink() or target.is_symlink():
        raise ValueError('Unexpected installation symlink')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() != source.read_bytes():
        raise ValueError('Held target differs')
    if not target.exists():
        shutil.copyfile(source, target)
    os.chown(target, 0, 0)
    target.chmod(0o644)


def switch(path, target):
    temporary = path.with_name(path.name + '.incoming-AE190')
    if temporary.exists() or temporary.is_symlink():
        raise ValueError('Pending delivery switch exists')
    temporary.symlink_to(target)
    os.replace(temporary, path)


def health():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8792/health', timeout=3) as response:
                data = json.loads(response.read(65536))
            if data.get('ok') is True and data.get('network') == 'testnet11':
                return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise ValueError('Fresh Testnet11 API health did not pass')


def verify_files(base, files):
    for name, digest in files.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unexpected source path')
        path = base / relative
        if path.is_symlink() or sha(path) != digest:
            raise ValueError('Pinned source differs: ' + name)


def verify_runtime_configuration():
    pid = run(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value'])
    env = dict(item.split('=', 1) for item in Path('/proc', pid, 'environ').read_bytes().decode().split('\0') if '=' in item)
    expected = {
        'SOLSLOT_NETWORK': 'testnet11',
        'SOLSLOT_ADMIN_DB_PATH': '/opt/solslot/genesis-rc28/state/admin_desk_v2.db',
        'SOLSLOT_COLLECTION_METADATA_ENABLED': 'true',
        'SOLSLOT_COLLECTION_MINTING_ENABLED': 'false',
        'SOLSLOT_MINTING_ENABLED': 'false',
        'SOLSLOT_COLLECTION_LOCAL_QUOTA_BYTES': '25165824',
        'SOLSLOT_COLLECTION_ASSET_MAX_BYTES': '8388608',
    }
    # Values are inspected locally only; never emit process environment/secrets.
    for key, value in expected.items():
        if env.get(key) != value:
            raise ValueError('Runtime boundary differs: ' + key)


def rollback(root, plan):
    drop = Path('/etc/systemd/system') / (UNIT + '.d') / plan['dropInName']
    prior_admin = Path(plan['priorAdminRelease'])
    for link in LINKS:
        if not link.is_symlink() or link.resolve() not in (prior_admin, NEW_ADMIN):
            raise ValueError('Admin rollback lineage differs')
    if drop.exists():
        if sha(drop) != sha(root / 'runtime.conf'):
            raise ValueError('Rollback runtime differs')
        held = OP / 'hold' / drop.name
        held.parent.mkdir(parents=True, exist_ok=True)
        if held.exists():
            raise ValueError('Rollback source already held')
        shutil.move(drop, held)
    for link in LINKS:
        if link.resolve() != prior_admin:
            switch(link, prior_admin)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', UNIT])
    health()
    verify_runtime_configuration()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--approval', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or args.approval != AE:
        raise ValueError('Exact approved root operation required')
    root = args.package
    if root.is_symlink() or sha(root / 'package-manifest.json') != args.manifest_sha256:
        raise ValueError('Approved package commitment differs')
    manifest = json.loads((root / 'package-manifest.json').read_text())
    if manifest['actionEnvelopeId'] != AE:
        raise ValueError('Package authority differs')
    verify_files(root, manifest['files'])
    plan = json.loads((root / 'plan.json').read_text())
    if (plan['actionEnvelopeId'] != AE or plan['coordinator'] != 'solslot-coordinator'
            or plan['collectionMintingEnabled'] is not False or plan['mintingEnabled'] is not False
            or not plan['dropInName'].endswith('-sgt-readiness-AE190.conf')):
        raise ValueError('Deployment scope differs')
    if args.rollback:
        rollback(root, plan)
        print(json.dumps({'actionEnvelopeId': AE, 'status': 'rolled_back', 'evidenceRetained': True}))
        return
    prior_admin = Path(plan['priorAdminRelease'])
    if prior_admin != ADMIN / 'releases/admin-sgt-review-visibility-AE189':
        raise ValueError('Prior admin authority differs')
    if sha(prior_admin / 'release.json') != plan['priorReleaseJsonSha256']:
        raise ValueError('Prior admin release metadata differs')
    for link in LINKS:
        if not link.is_symlink() or link.resolve() != prior_admin:
            raise ValueError('Admin delivery lineage differs')
    old = Path(plan['priorDropIn'])
    if not old.is_file() or old.is_symlink() or sha(old) != plan['priorDropInSha256']:
        raise ValueError('Prior runtime differs')
    if (sha(PRIOR / 'runtime-source-pins.json') != plan['priorSourcePinsSha256']
            or sha(PRIOR / 'recovery/solslot_collection_consistency_AE187.py') != plan['priorFactorySha256']):
        raise ValueError('Prior factory or source contract differs')
    old_pins = json.loads((PRIOR / 'runtime-source-pins.json').read_text())
    verify_files(PRIOR / 'release', old_pins['releaseFiles'])
    verify_files(PROTOCOL, old_pins['preservedProtocolFiles'])
    verify_files(PRIOR.parent, plan['preservedFactories'])
    verify_runtime_configuration()
    health()
    sys.path.insert(0, str(root / 'recovery'))
    from recovery_health import read_receipt
    read_receipt()
    for name in manifest['files']:
        if name.startswith(('release/', 'recovery/')) or name == 'runtime-source-pins.json':
            install(root / name, OP / name)
        if name.startswith('admin/'):
            install(root / name, NEW_ADMIN / Path(name).relative_to('admin'))
    # Retain hashed assets referenced by already-open tabs; no previous release is removed.
    for file in prior_admin.rglob('*'):
        if file.is_file() and not file.is_symlink() and file.suffix in ('.js', '.css', '.wasm'):
            install(file, NEW_ADMIN / file.relative_to(prior_admin))
    drop = Path('/etc/systemd/system') / (UNIT + '.d') / plan['dropInName']
    if drop.exists():
        raise ValueError('Candidate runtime already exists; reconcile before retrying')
    install(old, OP / 'hold/prior-runtime.conf')
    install(root / 'runtime.conf', drop)
    try:
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'restart', UNIT])
        health()
        verify_runtime_configuration()
        read_receipt()
        for link in LINKS:
            switch(link, NEW_ADMIN)
    except Exception:
        rollback(root, plan)
        raise
    print(json.dumps({'actionEnvelopeId': AE, 'status': 'deployed', 'network': 'testnet11',
                      'mintingEnabled': False, 'transactions': 0, 'dataMigration': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('AE190 stopped: ' + str(error) if isinstance(error, ValueError)
              else 'AE190 deployment command failed; inspect service metadata without secret values', file=sys.stderr)
        raise SystemExit(1)
