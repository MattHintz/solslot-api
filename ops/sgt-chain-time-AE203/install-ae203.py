"""Install the exact approved API-only chain-clock amendment, preserving evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request

AE = 'AE-SOLSLOT-SGT-CHAIN-TIME-20261008-203'
OP = Path('/opt/solslot/genesis-rc28/operations/AE203')
PRIOR = OP.parent / 'AE197'
PROTOCOL = OP.parent / 'AE161/release'
UNIT = 'solslot-genesis-rc28.service'
DROP_ROOT = Path('/etc/systemd/system') / (UNIT + '.d')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, text=True).strip()


def verify_files(root, files):
    for name, digest in files.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unreviewed source path')
        path = root / relative
        if path.is_symlink() or not path.is_file() or sha(path) != digest:
            raise ValueError('Pinned source differs: ' + name)
        if root.resolve() not in path.resolve().parents:
            raise ValueError('Source leaves its approved root')


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


def health():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8792/health', timeout=3) as response:
                result = json.loads(response.read(65536))
            if result.get('ok') is True and result.get('network') == 'testnet11':
                return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise ValueError('Fresh Testnet11 health did not pass')


def verify_runtime(operation, factory):
    pid = run(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value'])
    env = dict(item.split('=', 1) for item in Path('/proc', pid, 'environ').read_bytes().decode().split('\0') if '=' in item)
    expected = {
        'SOLSLOT_NETWORK': 'testnet11',
        'SOLSLOT_ADMIN_DB_PATH': '/opt/solslot/genesis-rc28/state/admin_desk_v2.db',
        'SOLSLOT_MINTING_ENABLED': 'false',
        'SOLSLOT_COLLECTION_MINTING_ENABLED': 'false',
        'SOLSLOT_GOVERNANCE_PUBLICATION_APPROVAL_WINDOW_SECONDS': '86400',
        'SOLSLOT_PROTOCOL_FEE_NATIVE_ADMISSION_ENABLED': 'true',
        'SOLSLOT_PROTOCOL_MAXIMUM_FEE_MOJOS': '1000000000',
    }
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError('Runtime authorization boundary differs')
    args = Path('/proc', pid, 'cmdline').read_bytes().decode().split('\0')
    if factory + ':create_app' not in args or str(operation / 'recovery') not in args:
        raise ValueError('Effective API factory lineage differs')


def verify_statics(plan):
    for name, target in plan['staticLinks'].items():
        path = Path(name)
        if not path.is_symlink() or str(path.resolve()) != target:
            raise ValueError('Static delivery lineage differs')


def rollback(root, plan):
    drop = DROP_ROOT / plan['dropInName']
    if drop.exists():
        if drop.is_symlink() or sha(drop) != sha(root / 'runtime.conf'):
            raise ValueError('Rollback candidate runtime differs')
        held = OP / 'hold' / drop.name
        held.parent.mkdir(parents=True, exist_ok=True)
        if held.exists():
            raise ValueError('Rollback evidence already held')
        shutil.move(drop, held)
    if sha(Path(plan['priorDropIn'])) != plan['priorDropInSha256']:
        raise ValueError('Previous runtime changed')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', UNIT])
    health()
    verify_runtime(PRIOR, 'solslot_user_journey_repair_AE197')
    verify_statics(plan)


def validate_scope(plan):
    if (plan.get('schema') != 'solslot.sgt-chain-time-deployment.v1'
            or plan.get('actionEnvelopeId') != AE
            or plan.get('coordinator') != 'solslot-coordinator'
            or plan.get('network') != 'testnet11'
            or plan.get('priorOperation') != 'AE197'
            or plan.get('restartUnits') != [UNIT]
            or plan.get('mintingEnabled') is not False
            or plan.get('collectionMintingEnabled') is not False
            or plan.get('feeCapMojos') != 1000000000
            or plan.get('feeCapChanged') is not False
            or plan.get('approvalWindowSeconds') != 86400
            or plan.get('committeeWindowChanged') is not False
            or plan.get('dataMigration') != 'none'
            or plan.get('transactions') != 0
            or plan.get('newFunding') is not False
            or plan.get('subscriptionsAdded') != 0
            or not re.fullmatch(r'z+-sgt-chain-time-AE203\.conf', plan.get('dropInName', ''))):
        raise ValueError('Deployment scope differs')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--approval', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--publication-receipt', type=Path)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or args.approval != AE:
        raise ValueError('Exact approved operation required')
    root = args.package
    if root.is_symlink() or sha(root / 'package-manifest.json') != args.manifest_sha256:
        raise ValueError('Approved package commitment differs')
    manifest = json.loads((root / 'package-manifest.json').read_text())
    if manifest['actionEnvelopeId'] != AE:
        raise ValueError('Package authority differs')
    verify_files(root, manifest['files'])
    plan = json.loads((root / 'plan.json').read_text())
    validate_scope(plan)
    if args.rollback:
        rollback(root, plan)
        print(json.dumps({'actionEnvelopeId': AE, 'status': 'rolled_back', 'evidenceRetained': True}))
        return
    if args.publication_receipt is None or args.publication_receipt.is_symlink():
        raise ValueError('Verified publication receipt required')
    publication = json.loads(args.publication_receipt.read_text())
    if (publication.get('actionEnvelopeId') != AE
            or publication.get('sourceCandidateSha256') != plan['sourceCandidateSha256']
            or set(publication.get('commits', {})) != {'api'}
            or not re.fullmatch('[0-9a-f]{40}', publication['commits']['api'])):
        raise ValueError('Publication commitment differs')
    if (sha(PRIOR / 'runtime-source-pins.json') != plan['priorSourcePinsSha256']
            or sha(PRIOR / 'recovery/solslot_user_journey_repair_AE197.py') != plan['priorFactorySha256']
            or sha(Path(plan['priorDropIn'])) != plan['priorDropInSha256']):
        raise ValueError('Previous runtime lineage differs')
    pins = json.loads((PRIOR / 'runtime-source-pins.json').read_text())
    verify_files(PRIOR / 'release', pins['releaseFiles'])
    verify_files(PROTOCOL, pins['preservedProtocolFiles'])
    verify_files(PRIOR.parent, plan['preservedFactories'])
    verify_runtime(PRIOR, 'solslot_user_journey_repair_AE197')
    verify_statics(plan)
    health()
    sys.path.insert(0, str(root / 'recovery'))
    from recovery_health import read_receipt
    read_receipt()
    drop = DROP_ROOT / plan['dropInName']
    if drop.exists() or drop.is_symlink():
        raise ValueError('Candidate runtime already exists; reconcile before retrying')
    if OP.exists() or OP.is_symlink():
        raise ValueError('Held candidate operation already exists; preserve it for review')
    for name in manifest['files']:
        if name.startswith(('release/', 'recovery/')) or name == 'runtime-source-pins.json':
            install(root / name, OP / name)
    install(args.publication_receipt, OP / 'publication-receipt.json')
    install(Path(plan['priorDropIn']), OP / 'hold/prior-runtime.conf')
    install(root / 'runtime.conf', drop)
    try:
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'restart', UNIT])
        health()
        verify_runtime(OP, 'solslot_chain_time_AE203')
        read_receipt()
        verify_statics(plan)
    except Exception:
        rollback(root, plan)
        raise
    print(json.dumps({'actionEnvelopeId': AE, 'status': 'deployed', 'network': 'testnet11',
                      'transactions': 0, 'dataMigration': 'none', 'staticsUnchanged': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('AE203 stopped: ' + str(error) if isinstance(error, ValueError)
              else 'AE203 deployment command failed; inspect metadata without secret values', file=sys.stderr)
        raise SystemExit(1)
