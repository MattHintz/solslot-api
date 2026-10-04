"""The preserved runtime must refresh FastAPI's cached coroutine dispatch."""
import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from solslot_api import zkpassport_enrollments as enrollments, zkpassport_relay as relay

ROOT = Path(__file__).resolve().parents[1]
PRESERVED = ROOT.parent/'preserved'
spec = importlib.util.spec_from_file_location('ae176_guard', ROOT/'deployment/solslot_sage_stamp_dispatch_AE176.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


@pytest.mark.parametrize('module,name,builder', [
    (enrollments, 'prepare_chia_stamp', guard.corrected_prepare),
    (relay, '_resume_saved', guard.corrected_resume),
])
def test_runtime_patch_matches_canonical_source_and_holds_original(module, name, builder):
    path = PRESERVED/Path(module.__file__).name
    before = path.read_bytes()
    preserved_module = SimpleNamespace(**module.__dict__)
    preserved_module.__file__ = str(path)
    replacement = builder(preserved_module)
    canonical = next(n for n in ast.parse(Path(module.__file__).read_text()).body
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    canonical.decorator_list = []
    assert replacement.__ae176_ast__ == ast.dump(canonical, include_attributes=False)
    assert path.read_bytes() == before


@pytest.mark.parametrize('name,builder', [
    ('zkpassport_enrollments.py', guard.corrected_prepare),
    ('zkpassport_relay.py', guard.corrected_resume),
])
def test_guard_refuses_changed_original(tmp_path, name, builder):
    changed = tmp_path/name
    changed.write_bytes((PRESERVED/name).read_bytes()+b'\n')
    with pytest.raises(RuntimeError, match='source pin'):
        builder(SimpleNamespace(__file__=str(changed)))


def test_guard_refreshes_real_http_dispatch_before_app_composition():
    code = r'''
import asyncio, importlib.util, sys, threading
from pathlib import Path
import httpx
from fastapi import FastAPI, HTTPException
from solslot_api import zkpassport_enrollments as module, zkpassport_relay as relay
root=Path(sys.argv[1]); preserved=root.parent/'preserved'
assert 'solslot_api.app' not in sys.modules
module.__file__=str(preserved/'zkpassport_enrollments.py')
relay.__file__=str(preserved/'zkpassport_relay.py')
# Reconstruct the held synchronous endpoint, not the already-corrected source.
import ast
for target, name in [(module,'prepare_chia_stamp'),(relay,'_resume_saved')]:
 node=next(n for n in ast.parse(Path(target.__file__).read_text()).body
           if isinstance(n,ast.FunctionDef) and n.name==name)
 node.decorator_list=[]; namespace=dict(target.__dict__)
 exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'held','exec'),namespace)
 getattr(target,name).__code__=namespace[name].__code__
endpoint=module.prepare_chia_stamp
route=next(r for r in module.router.routes if getattr(r,'endpoint',None) is endpoint)
route.dependant.__dict__.pop('is_coroutine_callable',None)
assert route.dependant.is_coroutine_callable is False
spec=importlib.util.spec_from_file_location('guard',root/'deployment/solslot_sage_stamp_dispatch_AE176.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
guard.install_guard()
assert route.endpoint is endpoint and route.dependant.call is endpoint
assert route.dependant.is_coroutine_callable is True
installed=endpoint.__code__;guard.install_guard();assert endpoint.__code__ is installed
owner_thread=threading.get_ident()
def settings():
 assert threading.get_ident()==owner_thread, 'FastAPI used a foreign worker thread'
 raise HTTPException(status_code=409,detail='Owning thread verified')
module._settings=settings
app=FastAPI();app.include_router(module.router)
async def check():
 async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test') as client:
  response=await client.post('/zkpassport/enrollments/0x'+'11'*32+'/stamp/prepare')
  assert response.status_code==409 and response.json()['detail']=='Owning thread verified', response.text
asyncio.run(check())
'''
    result = subprocess.run([sys.executable, '-c', code, str(ROOT)],
                            env={**os.environ, 'PYTHONPATH': str(ROOT)+os.pathsep+os.environ.get('PYTHONPATH', '')},
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr[-3000:]
