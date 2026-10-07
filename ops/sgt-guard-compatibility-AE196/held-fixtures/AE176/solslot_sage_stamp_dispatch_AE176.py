"""AE176: preserve Sage's CLVM owning thread and retain status on RPC outages.

Install before the preserved app includes its routers. Function identities,
original files, middleware and authorization checks are retained.
"""
from pathlib import Path
import ast
import hashlib
import importlib.util
import sys

ENROLLMENTS_SHA = '2df96427691e6a35dea6f02b1578d65d20ffa98135e18dcf0f62fd8aa852c26c'
RELAY_SHA = '1c39cb653238b7937215c05a9ea844fa5d0e57216ce52c98b96b6b51851ee637'
PREVIOUS_FACTORY_SHA = '61e6d4b9c3352205eaffef96f17d1cf598d7903e9954c0178974da389c29cad7'


def _pinned_function(module, name, digest):
    path = Path(module.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError('AE176 preserved source pin differs')
    nodes = [n for n in ast.parse(path.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise RuntimeError('AE176 exact endpoint required')
    return nodes[0]


def _compile(module, function):
    function.decorator_list = []
    namespace = dict(module.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
                 'solslot_sage_stamp_dispatch_AE176', 'exec'), namespace)
    result = namespace[function.name]
    result.__ae176_ast__ = ast.dump(function, include_attributes=False)
    return result


def corrected_prepare(module):
    function = _pinned_function(module, 'prepare_chia_stamp', ENROLLMENTS_SHA)
    # The body and every authorization/puzzle check are exactly preserved.
    function = ast.AsyncFunctionDef(**function.__dict__)
    return _compile(module, function)


def corrected_resume(module):
    function = _pinned_function(module, '_resume_saved', RELAY_SHA)
    if [ast.unparse(n) for n in function.body[:3]] != [
        'w3 = _w3(settings.zkpassport_evm_rpc_url)',
        '_check_saved_deployment(w3, settings, saved)',
        'outcome = _relay_receipt_state(w3, settings, saved, enrollment, session)',
    ]:
        raise RuntimeError('AE176 exact status validation boundary required')
    wrapped = ast.parse('''
try:
    pass
except HTTPException:
    raise
except Exception as exc:
    raise HTTPException(status_code=502, headers={'Retry-After': '5'},
        detail='The identity network status check is temporarily unavailable. '
               'Your saved proof and original transaction are preserved; '
               'check status again without starting another proof.') from exc
''').body[0]
    wrapped.body = function.body[:3]
    function.body = [wrapped] + function.body[3:]
    return _compile(module, function)


def install_guard():
    from solslot_api import zkpassport_enrollments as enrollments, zkpassport_relay as relay
    endpoint = enrollments.prepare_chia_stamp
    if getattr(endpoint, '__ae176__', False):
        if not getattr(relay._resume_saved, '__ae176__', False):
            raise RuntimeError('AE176 partial guard installation')
        return
    if 'solslot_api.app' in sys.modules:
        raise RuntimeError('AE176 must install before app route composition')
    if endpoint.__module__ != enrollments.__name__ or relay._resume_saved.__module__ != relay.__name__:
        raise RuntimeError('AE176 preserved function identity differs')
    routes = [r for r in enrollments.router.routes if getattr(r, 'endpoint', None) is endpoint]
    if len(routes) != 1 or routes[0].dependant.call is not endpoint:
        raise RuntimeError('AE176 exact prepare route dispatch required')
    prepare = corrected_prepare(enrollments)
    resume = corrected_resume(relay)
    endpoint.__code__ = prepare.__code__
    relay._resume_saved.__code__ = resume.__code__
    # FastAPI caches coroutine dispatch while constructing the original router.
    # Clear that one cache and rebuild its handler before include_router copies
    # the effective context. Preserve dependency and response-model metadata.
    route = routes[0]
    route.dependant.__dict__.pop('is_coroutine_callable', None)
    from starlette.routing import request_response
    route.app = request_response(route.get_route_handler())
    endpoint.__ae176__ = relay._resume_saved.__ae176__ = True


def create_app():
    path = Path('/opt/solslot/genesis-rc28/operations/AE175/solslot_sage_identity_challenge_AE175.py')
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != PREVIOUS_FACTORY_SHA:
        raise RuntimeError('AE176 previous factory pin differs')
    install_guard()
    spec = importlib.util.spec_from_file_location('solslot_preserved_factory_ae176', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_app()
