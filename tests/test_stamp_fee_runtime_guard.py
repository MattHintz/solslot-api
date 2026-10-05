"""Exact runtime overlay and held sources are verified before deployment."""
import ast, importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest
from solslot_api import stamp_funding, zkpassport_enrollments

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ae178',ROOT/'deployment/solslot_stamp_fee_admission_AE178.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

@pytest.mark.parametrize('module,name,builder',[
    (stamp_funding,'submit_funded_stamp',guard.corrected_funding),
    (zkpassport_enrollments,'_push_chia_stamp_and_mark_pending',guard.corrected_push)])
def test_overlay_equals_reviewed_canonical_function_and_preserves_original(module,name,builder):
    held=ROOT.parent/'preserved'/Path(module.__file__).name
    before=held.read_bytes()
    shadow=SimpleNamespace(**module.__dict__);shadow.__file__=str(held)
    replacement=builder(shadow)
    canonical=next(n for n in ast.parse(Path(module.__file__).read_text()).body
        if isinstance(n,ast.AsyncFunctionDef) and n.name==name)
    canonical.decorator_list=[]
    assert replacement.__ae178_ast__==ast.dump(canonical,include_attributes=False)
    assert held.read_bytes()==before

@pytest.mark.parametrize('name,builder',[
    ('stamp_funding.py',guard.corrected_funding),
    ('zkpassport_enrollments.py',guard.corrected_push)])
def test_changed_held_source_refuses(tmp_path,name,builder):
    changed=tmp_path/name;changed.write_bytes((ROOT.parent/'preserved'/name).read_bytes()+b'\n')
    with pytest.raises(RuntimeError,match='source pin'):
        builder(SimpleNamespace(__file__=str(changed)))
