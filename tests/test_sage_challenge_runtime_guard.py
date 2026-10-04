import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.routing import APIRoute
from solslot_api import zkpassport_enrollments as enrollments
from tests.test_bls_identity_challenge_deployment import challenge

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ae175_guard', ROOT/'deployment/solslot_sage_identity_challenge_AE175.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
PRESERVED = ROOT.parent/'preserved/zkpassport_enrollments.py'


def original(module):
    node = next(n for n in ast.parse(PRESERVED.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'create_bls_relay_challenge')
    node.decorator_list = []
    namespace = dict(module.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 str(PRESERVED), 'exec'), namespace)
    return namespace[node.name]


def test_runtime_patch_matches_canonical_fix_without_rewriting_source():
    before = PRESERVED.read_bytes()
    module = SimpleNamespace(**enrollments.__dict__)
    module.__file__ = str(PRESERVED)
    replacement = guard.corrected_challenge(module)
    canonical = enrollments.create_bls_relay_challenge
    # Formatting affects Python 3.12 jump/NOP positions. Compare semantic AST
    # plus executable global/local names, then exercise the actual admission.
    node = next(n for n in ast.parse(Path(enrollments.__file__).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == canonical.__name__)
    node.decorator_list = []
    assert replacement.__ae175_ast__ == ast.dump(node, include_attributes=False)
    for field in ['co_consts', 'co_names', 'co_varnames']:
        assert getattr(replacement.__code__, field) == getattr(canonical.__code__, field)
    assert PRESERVED.read_bytes() == before


def test_registered_fastapi_dispatch_keeps_the_same_endpoint(monkeypatch):
    endpoint = original(enrollments)
    monkeypatch.setattr(enrollments, '__file__', str(PRESERVED))
    monkeypatch.setattr(enrollments, 'create_bls_relay_challenge', endpoint)
    route = APIRoute('/test-challenge/{vault_launcher_id}', endpoint=endpoint, methods=['POST'])
    prior = endpoint.__code__
    guard.install_guard()
    assert endpoint.__code__ is not prior
    assert route.endpoint is endpoint and route.dependant.call is endpoint
    installed = endpoint.__code__
    guard.install_guard()
    assert endpoint.__code__ is installed


def test_runtime_patch_refuses_changed_source(tmp_path):
    path = tmp_path/'changed.py'; path.write_bytes(PRESERVED.read_bytes()+b'\n')
    with pytest.raises(RuntimeError, match='source pin'):
        guard.corrected_challenge(SimpleNamespace(__file__=str(path)))


def test_runtime_replacement_accepts_same_bound_proof(challenge, monkeypatch):
    module=SimpleNamespace(**enrollments.__dict__);module.__file__=str(PRESERVED)
    monkeypatch.setattr(enrollments,'create_bls_relay_challenge',guard.corrected_challenge(module))
    assert challenge.invoke().action == 'relay'
    assert challenge.issued[0][0].zkpassport_evm_chain_id == 8453
