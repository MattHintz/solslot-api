"""AE175: pin the Sage challenge to the same authenticated enrollment as relay.

Retain every previously held source file, route object, middleware, and factory.
Replace only the code of the already registered, exactly pinned endpoint.
"""
from pathlib import Path
import ast
import hashlib
import importlib.util

ENROLLMENTS_SHA = '2df96427691e6a35dea6f02b1578d65d20ffa98135e18dcf0f62fd8aa852c26c'
PREVIOUS_FACTORY_SHA = '8cd594fadced5316c79caa2cbfca69ad00bc0f6d9c583592034f12eebe06a860'


def corrected_challenge(module):
    path = Path(module.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != ENROLLMENTS_SHA:
        raise RuntimeError('AE175 preserved enrollment source pin differs')
    tree = ast.parse(path.read_text())
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == 'create_bls_relay_challenge']
    if len(functions) != 1:
        raise RuntimeError('AE175 exact Sage endpoint required')
    function = functions[0]
    anchors = [n for n in function.body if isinstance(n, ast.Expr) and
        ast.unparse(n) == '_require_enrollment_bridge_policy(settings, enrollment, execution=True)']
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call) and
        ast.unparse(n) == '_validate_relay_permit(settings, enrollment, session, data, live=True)']
    if len(anchors) != 1 or len(calls) != 1:
        raise RuntimeError('AE175 exact challenge validation boundary required')
    function.body.insert(function.body.index(anchors[0]) + 1, ast.parse(
        'settings, identity_deployment = _settings_for_enrollment(settings, request, enrollment)').body[0])
    calls[0].keywords.append(ast.keyword(arg='identity_deployment',
        value=ast.Name(id='identity_deployment', ctx=ast.Load())))
    function.decorator_list = []
    namespace = dict(module.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
                 'solslot_sage_identity_challenge_AE175', 'exec'), namespace)
    result = namespace[function.name]
    result.__ae175_ast__ = ast.dump(function, include_attributes=False)
    return result


def install_guard():
    from solslot_api import zkpassport_enrollments as module
    endpoint = module.create_bls_relay_challenge
    if getattr(endpoint, '__ae175__', False):
        return
    if endpoint.__module__ != module.__name__:
        raise RuntimeError('AE175 preserved challenge endpoint differs')
    replacement = corrected_challenge(module)
    # FastAPI already holds this function in route.endpoint and dependant.call.
    # Preserve its identity and metadata; both dispatch references see this code.
    endpoint.__code__ = replacement.__code__
    endpoint.__ae175__ = True


def create_app():
    path = Path('/opt/solslot/genesis-rc28/operations/AE170/solslot_identity_fee_address.py')
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != PREVIOUS_FACTORY_SHA:
        raise RuntimeError('AE175 previous factory pin differs')
    spec = importlib.util.spec_from_file_location('solslot_preserved_factory_ae175', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = module.create_app()
    install_guard()
    return app
