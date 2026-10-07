"""Exercise the real retained guards in an isolated process without app workers."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
import hashlib, importlib.util, json, sys
from pathlib import Path
from types import SimpleNamespace
from starlette.applications import Starlette
sys.dont_write_bytecode = True
root = Path.cwd()
ops = root / 'ops/sgt-guard-compatibility-AE196'
sys.path.insert(0, str(ops))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
fixtures = ops / 'held-fixtures'
pins = json.loads((fixtures / 'pins.json').read_text())
for name, digest in pins.items():
    assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == digest
factory = load('factory196', ops / 'solslot_sgt_approval_repair_AE196.py')
factory.RELEASE = root.parent
admission = load('held_admission', fixtures / 'AE178/api/solslot_stamp_fee_admission_AE178.py')
'''


def isolated(code):
    result = subprocess.run(
        [sys.executable, '-c', PRELUDE + code], cwd=ROOT,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
        capture_output=True, text=True, timeout=40,
    )
    assert result.returncode == 0, result.stderr


def test_held_guard_rejects_old_pin_then_full_guard_composition_succeeds():
    isolated(r'''
from solslot_api import stamp_funding, zkpassport_enrollments, zkpassport_relay
original = (stamp_funding.submit_funded_stamp, zkpassport_enrollments.prepare_chia_stamp,
            zkpassport_enrollments.create_bls_relay_challenge, zkpassport_relay._resume_saved)
try:
    admission.install_guard()
except RuntimeError as error:
    assert str(error) == 'AE178 held protocol fee source pin differs'
else:
    raise AssertionError('Original startup regression was not reproduced')
factory.bind_reviewed_protocol_source(admission)
helper = load('solslot_api.stamp_fee_admission', fixtures / 'AE178/api/stamp_fee_admission.py')
sys.modules['solslot_api.stamp_fee_admission'] = helper
modules = {'admission': admission}
for name, (relative, digest) in factory.FACTORIES.items():
    if name != 'admission':
        assert pins[relative] == digest
        modules[name] = load('held_' + name, fixtures / relative)
base_called = []
def base():
    assert getattr(stamp_funding.submit_funded_stamp, '__ae178__', False)
    assert getattr(zkpassport_enrollments.prepare_chia_stamp, '__ae176__', False)
    from solslot_api import public_artifact
    assert getattr(public_artifact._verify_runtime_bindings, '__ae169__', False)
    assert 'solslot_api.app' not in sys.modules
    base_called.append(True)
    return Starlette()
wrapped = factory.compose_preserved_guards(modules, base)
assert isinstance(wrapped, factory.CollectionRecoveryGuard) and base_called == [True]
assert getattr(zkpassport_enrollments.create_bls_relay_challenge, '__ae175__', False)
from solslot_api import identity_relay_fees
assert getattr(identity_relay_fees.check_base_dispatch, '__ae170__', False)
assert original == (stamp_funding.submit_funded_stamp, zkpassport_enrollments.prepare_chia_stamp,
                    zkpassport_enrollments.create_bls_relay_challenge, zkpassport_relay._resume_saved)
admission.install_guard()  # Existing installation is still idempotent.
assert 'solslot_api.app' not in sys.modules
''')


@pytest.mark.parametrize('kind', ['legacy_pin', 'source_bytes', 'source_location', 'symlink'])
def test_unreviewed_pin_source_or_location_remain_rejected(kind):
    isolated(r'''
from solslot_api import protocol_submission
import tempfile
temporary = tempfile.TemporaryDirectory()
target = Path(temporary.name) / 'api/solslot_api/protocol_submission.py'
target.parent.mkdir(parents=True)
''' + {
        'legacy_pin': "admission.PROTOCOL_SUBMISSION_SHA = '0' * 64\n",
        'source_bytes': "target.write_text('unreviewed source')\nfactory.RELEASE = Path(temporary.name)\nprotocol_submission.__file__ = str(target)\n",
        'source_location': "factory.RELEASE = ops\n",
        'symlink': "target.symlink_to(protocol_submission.__file__)\nfactory.RELEASE = Path(temporary.name)\nprotocol_submission.__file__ = str(target)\n",
    }[kind] + r'''
try:
    factory.bind_reviewed_protocol_source(admission)
except RuntimeError:
    pass
else:
    raise AssertionError('Unreviewed pin/source accepted')
''')
