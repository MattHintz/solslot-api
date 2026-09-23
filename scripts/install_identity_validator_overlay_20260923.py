"""Create a reversible validator-only source overlay. Never sign or write ledgers."""
import os, sys, pathlib, subprocess, json, hashlib, shutil, datetime, time

PATCH = {'actionEnvelopeId': 'AE-SOLSLOT-VALIDATOR-THREAD-20260923-90', 'baseApiCommit': '2bc0f1413edf20261af8961095f26fff62317105', 'fixApiCommit': '356f08dc6935c05dd1c1e1ce73e30bf8fa72fbe6', 'baseServiceSha256': '813ecf52604eb0dbb9a63513ab79748c80f16b8e6ed8de5521fbe0bb67543f1e', 'fileHashes': {'validator_service.py': 'a959a27a94b4a0ec0a00c11399c199107e0660669f193ff632645de52bf111f3', 'vault_puzzle_hash.py': 'd7a414a11a55cc8914d661ff2e9deece7682b0315c92945ed1fdcc906718c8d8'}, 'helper': '"""Hash the protocol vault without moving lazy CLVM nodes across threads.\n\nOnly immutable module hashes cross the ASGI worker boundary. Currying is the\nsame as vault_driver.puzzle_for_vault_full; parity tests cover every argument.\n"""\n\nfrom chia.types.blockchain_format.program import Program\nfrom chia.wallet.puzzles.singleton_top_layer_v1_1 import (\n    SINGLETON_LAUNCHER_HASH,\n    SINGLETON_MOD_HASH,\n)\nfrom chia.wallet.util.curry_and_treehash import (\n    calculate_hash_of_quoted_mod_hash,\n    curry_and_treehash,\n)\nfrom chia_rs.sized_bytes import bytes32\nfrom solslot_puzzles.vault_driver import (\n    DEFAULT_IDENTITY_ATTEST_ROOT,\n    DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,\n    VAULT_INNER_MOD,\n    validate_owner_pubkey_for_auth_type,\n)\n\n# Read the module on its importing thread; never retain it in a returned puzzle.\n_VAULT_INNER_HASH = bytes32(VAULT_INNER_MOD.get_tree_hash())\n\n\ndef puzzle_hash_for_vault_full(\n    vault_launcher_id: bytes32,\n    owner_pubkey_bytes: bytes,\n    auth_type: int,\n    members_merkle_root: bytes32,\n    pool_launcher_id: bytes32,\n    *,\n    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,\n    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,\n) -> bytes32:\n    owner = validate_owner_pubkey_for_auth_type(owner_pubkey_bytes, auth_type)\n    singleton_struct = (SINGLETON_MOD_HASH, (vault_launcher_id, SINGLETON_LAUNCHER_HASH))\n    # Program.to receives only fresh Python values and immutable bytes here.\n    tree_hash = lambda value: bytes32(Program.to(value).get_tree_hash())\n    struct_hash = tree_hash(singleton_struct)\n    inner_hash = curry_and_treehash(\n        calculate_hash_of_quoted_mod_hash(_VAULT_INNER_HASH),\n        struct_hash,\n        tree_hash(owner),\n        tree_hash(auth_type),\n        tree_hash(members_merkle_root),\n        tree_hash(identity_attest_root),\n        tree_hash(zkpassport_bridge_policy_hash),\n        tree_hash(SINGLETON_MOD_HASH),\n        tree_hash(pool_launcher_id),\n        tree_hash(SINGLETON_LAUNCHER_HASH),\n    )\n    return bytes32(curry_and_treehash(\n        calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH),\n        struct_hash,\n        inner_hash,\n    ))\n', 'changes': [('from .validator_settings import ValidatorSettings\n', 'from .validator_settings import ValidatorSettings\nfrom .vault_puzzle_hash import puzzle_hash_for_vault_full\n'), ('    expected_puzzle = puzzle_for_vault_full(\n', '    expected_puzzle_hash = puzzle_hash_for_vault_full(\n'), ('    if coin.puzzle_hash != bytes32(expected_puzzle.get_tree_hash()):\n', '    if coin.puzzle_hash != expected_puzzle_hash:\n'), ('        zkpassport_forwarder_address=settings.evm_forwarder_address,\n', '        zkpassport_forwarder_address=settings.evm_forwarder_address,\n        zkpassport_verifier_adapter_address=settings.evm_verifier_adapter_address,\n')]}
assert os.geteuid() == 0
mode = sys.argv[1]
assert mode in ('prepare', 'activate', 'verify')
base = pathlib.Path('/opt/solslot/validator/current')
assert base.resolve().name == 'rc27.44-2bc0f1413edf-73fa04266bdf'
overlay = pathlib.Path('/opt/solslot/validator/runtime-overlays/identity-thread-' + PATCH['fixApiCommit'][:12])
dropin = pathlib.Path('/etc/systemd/system/solslot-validator.service.d/50-identity-thread.conf')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def unit_env():
    pid = subprocess.check_output(['systemctl','show','solslot-validator','-p','MainPID','--value'], text=True).strip()
    assert int(pid) > 1
    return dict(x.split('=',1) for x in pathlib.Path('/proc/'+pid+'/environ').read_text().split(chr(0)) if '=' in x)

env = unit_env()
index = int(env['SOLSLOT_VALIDATOR_SIGNER_INDEX'])
original = (base/'solslot_api/validator_service.py').read_bytes()
assert digest(original) == PATCH['baseServiceSha256']
patched = original.decode()
for old, new in PATCH['changes']:
    assert patched.count(old) == 1
    patched = patched.replace(old, new)
files = {'validator_service.py':patched, 'vault_puzzle_hash.py':PATCH['helper']}
assert {k:digest(v.encode()) for k,v in files.items()} == PATCH['fileHashes']
if mode != 'verify' and not overlay.exists():
    overlay.mkdir(parents=True, mode=0o755)
    shutil.copytree(base/'solslot_api', overlay/'solslot_api', ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for name, value in files.items():
        (overlay/'solslot_api'/name).write_text(value)
    (overlay/'protocol').symlink_to(base/'protocol', target_is_directory=True)
    (overlay/'release.json').symlink_to(base/'release.json')
    receipt = {k:v for k,v in PATCH.items() if k not in ('changes','helper')}
    receipt.update(createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat(), signerIndex=index,
        signedArtifactUnchanged=True, baseReleaseUnchanged=True, signed=False, broadcast=False)
    (overlay/'runtime-patch.json').write_text(json.dumps(receipt,indent=2))
for name, value in files.items():
    assert (overlay/'solslot_api'/name).read_text() == value

patch_env = 'SOLSLOT_VALIDATOR_RUNTIME_PATCH_COMMIT=' + PATCH['fixApiCommit'] + '\n'
if index == 2:
    assert env['SOLSLOT_VALIDATOR_EVM_RPC_URL'] in ('https://locked.invalid', 'https://ethereum-sepolia-rpc.publicnode.com')
    patch_env += 'SOLSLOT_VALIDATOR_EVM_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com\n'
if mode != 'verify':
    target = overlay/'runtime.env'
    assert not target.exists() or target.read_text() == patch_env
    if not target.exists():
        target.write_text(patch_env)
        target.chmod(0o644)
assert (overlay/'runtime.env').read_text() == patch_env
content = '[Service]\n# '+PATCH['actionEnvelopeId']+'\nWorkingDirectory='+str(overlay)+'\nEnvironmentFile='+str(overlay/'runtime.env')+'\n'
assert not dropin.is_symlink()
assert not dropin.exists() or dropin.read_text() == content
os.environ.update(env)
os.environ.update(dict(line.split('=',1) for line in patch_env.splitlines()))
os.chdir(overlay)
sys.path.insert(0,str(overlay))
sys.path.insert(1,str(overlay/'protocol'))
from solslot_api.validator_settings import get_validator_settings
from solslot_api.validator_service import load_validator_artifact, _coordinator_settings
from solslot_api.public_artifact import load_signed_public_artifact
s = get_validator_settings()
assert all(pathlib.Path(p).is_absolute() for p in (s.ledger_db_path,s.public_artifact_path,s.release_metadata_path,s.seed_file))
a, r = load_validator_artifact(s)
assert a['artifactHash'] == '0xb094088fc4a599daca70712dfdb20d5b814eaa12904a9f6b7e21c298336bf6c0'
assert r.apiCommit == PATCH['baseApiCommit']
assert load_signed_public_artifact(_coordinator_settings(s,a)) == a
from solslot_api.vault_puzzle_hash import puzzle_hash_for_vault_full
from solslot_puzzles.vault_driver import puzzle_for_vault_full
from chia_rs.sized_bytes import bytes32
from concurrent.futures import ThreadPoolExecutor
args = (bytes32(b'l'*32),b'\x02'+bytes(32),3,bytes32(b'm'*32),bytes32(b'p'*32))
expected = puzzle_for_vault_full(*args).get_tree_hash()
with ThreadPoolExecutor(max_workers=1) as pool:
    assert pool.submit(puzzle_hash_for_vault_full,*args).result() == expected
out = dict(actionEnvelopeId=PATCH['actionEnvelopeId'], signerIndex=index, state='prepared',
    baseApiCommit=r.apiCommit, fixApiCommit=PATCH['fixApiCommit'], overlay=str(overlay),
    artifactHash=a['artifactHash'], fileHashes=PATCH['fileHashes'], workerPuzzleCheckPassed=True,
    signed=False, broadcast=False)
if mode == 'activate':
    if not dropin.exists():
        backup = pathlib.Path('/var/backups/solslot/identity-thread-20260923')
        backup.mkdir(parents=True,exist_ok=True,mode=0o700)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        with (backup/(stamp+'-activation-intent.json')).open('x') as f:
            json.dump(dict(out, dropinPreviouslyAbsent=True, previousWorkingDirectory=str(base)),f)
        dropin.parent.mkdir(parents=True,exist_ok=True)
        with dropin.open('x') as f:
            f.write(content)
        dropin.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','solslot-validator'],check=True)
    for _ in range(40):
        if unit_env().get('SOLSLOT_VALIDATOR_RUNTIME_PATCH_COMMIT') == PATCH['fixApiCommit']:
            break
        time.sleep(0.25)
if mode in ('activate','verify'):
    assert unit_env().get('SOLSLOT_VALIDATOR_RUNTIME_PATCH_COMMIT') == PATCH['fixApiCommit']
    assert subprocess.check_output(['systemctl','show','solslot-validator','-p','WorkingDirectory','--value'],text=True).strip() == str(overlay)
    assert subprocess.check_output(['systemctl','is-active','solslot-validator'],text=True).strip() == 'active'
    out['state'] = 'active'
    out['fullClaimRehearsalStillRequired'] = True
out['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
print(json.dumps(out))
