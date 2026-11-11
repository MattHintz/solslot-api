"""AE178: identity-only Chia admission fee and recoverable congestion signal.

Preserve held files and function identities; compose the exact AE176 factory.
"""
from pathlib import Path
import ast
import hashlib
import importlib.util
import sys

FUNDING_SHA = '0edd286bca57014c5cee93d6b5503963d65dc2213252ff0a494e7c97988425c2'
ENROLLMENTS_SHA = '2df96427691e6a35dea6f02b1578d65d20ffa98135e18dcf0f62fd8aa852c26c'
PREVIOUS_FACTORY_SHA = 'ecfe892f945c63cbdc411ffeb7a23eedd4b5957805cad11149f67253c69e528b'
PROTOCOL_SUBMISSION_SHA = '70d560e43e26f825d3a86d7cd83c06a663aa5588984c3faf8895f40edbbd949e'
ADMISSION_SHA = '94390ae8717c7f79321dc73b5d1f27f6f6968d5bd1ecc6ca68b9dfd0760499cb'


def _function(module, name, digest):
    path = Path(module.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError('AE178 held source pin differs')
    nodes = [n for n in ast.parse(path.read_text()).body if isinstance(n, ast.AsyncFunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise RuntimeError('AE178 exact async boundary required')
    return nodes[0]


def _compile(module, function):
    function.decorator_list = []
    namespace = dict(module.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), 'solslot_stamp_fee_admission_AE178', 'exec'), namespace)
    result = namespace[function.name]
    result.__ae178_ast__ = ast.dump(function, include_attributes=False)
    return result


def corrected_funding(module):
    function = _function(module, 'submit_funded_stamp', FUNDING_SHA)
    fast = [n for n in ast.walk(function) if isinstance(n, ast.Assign) and ast.unparse(n).startswith('fast = ProtocolBundleSubmitter(')]
    pushes = []
    for parent in ast.walk(function):
        body = getattr(parent, 'body', None)
        if isinstance(body, list):
            for index, node in enumerate(body):
                if ast.unparse(node) == "store.event(document['spendBundleId'], 'dispatching')":
                    pushes.append((body,index))
    handlers = [n for n in ast.walk(function) if isinstance(n, ast.ExceptHandler) and ast.unparse(n.type) == 'ChiaProviderError']
    if len(fast) != 1 or len(pushes) != 1 or len(handlers) != 1:
        raise RuntimeError('AE178 exact sponsorship boundary differs')
    fast[0].value.func.id = 'StampFeeSubmitter'
    body,index = pushes[0]
    body[index:index] = ast.parse('''
await check_saved_stamp_admission(submitter, document)
if time.time() >= document['expiresAt']-15:
    raise ProtocolSubmissionError('Saved stamp window ended during the network check; check status before resuming')
''').body
    handler = handlers[0]
    anchor = [n for n in handler.body if isinstance(n, ast.Expr) and ast.unparse(n).startswith("store.event(document['spendBundleId'],")]
    if len(anchor) != 1:
        raise RuntimeError('AE178 exact rejection journal boundary differs')
    handler.body[handler.body.index(anchor[0])+1:handler.body.index(anchor[0])+1] = ast.parse('''
if code in {'INVALID_FEE_TOO_CLOSE_TO_ZERO', 'INVALID_FEE_LOW_FEE'}:
    raise StampNetworkBusy(BUSY_MESSAGE, submission_attempted=True) from exc
''').body
    return _compile(module, function)


def corrected_push(module):
    function = _function(module, '_push_chia_stamp_and_mark_pending', ENROLLMENTS_SHA)
    handlers = [n for n in ast.walk(function) if isinstance(n, ast.ExceptHandler)
                and ast.unparse(n.type) == '(ProtocolSubmissionError, ChiaProviderError, ValueError)']
    if len(handlers) != 1 or ast.unparse(handlers[0].body[0]) != 'raise HTTPException(status_code=503, detail=str(exc)) from exc':
        raise RuntimeError('AE178 exact HTTP congestion boundary differs')
    handlers[0].body = ast.parse('''
from .stamp_fee_admission import StampNetworkBusy
headers = {'Retry-After': '10'} if isinstance(exc, StampNetworkBusy) else None
raise HTTPException(status_code=503, headers=headers, detail=str(exc)) from exc
''').body
    return _compile(module, function)


def install_guard():
    from solslot_api import protocol_submission
    protocol_path = Path(protocol_submission.__file__)
    if protocol_path.is_symlink() or hashlib.sha256(protocol_path.read_bytes()).hexdigest() != PROTOCOL_SUBMISSION_SHA:
        raise RuntimeError('AE178 held protocol fee source pin differs')
    from solslot_api import stamp_funding as funding, zkpassport_enrollments as enrollments
    names = ('StampFeeSubmitter','StampNetworkBusy','BUSY_MESSAGE','check_saved_stamp_admission')
    if getattr(funding.submit_funded_stamp, '__ae178__', False):
        if not getattr(enrollments._push_chia_stamp_and_mark_pending, '__ae178__', False):
            raise RuntimeError('AE178 partial guard installation')
        return
    if 'solslot_api.app' in sys.modules:
        raise RuntimeError('AE178 must install before app composition')
    from solslot_api import stamp_fee_admission as admission
    if hashlib.sha256(Path(admission.__file__).read_bytes()).hexdigest() != ADMISSION_SHA:
        raise RuntimeError('AE178 admission helper pin differs')
    if any(name in funding.__dict__ for name in names):
        raise RuntimeError('AE178 unexpected funding globals')
    replacements = corrected_funding(funding), corrected_push(enrollments)
    for name in names:
        funding.__dict__[name] = getattr(admission,name)
    for target,replacement in zip((funding.submit_funded_stamp,enrollments._push_chia_stamp_and_mark_pending),replacements):
        target.__code__ = replacement.__code__
        target.__ae178__ = True


def create_app():
    previous = Path('/opt/solslot/genesis-rc28/operations/AE176/solslot_sage_stamp_dispatch_AE176.py')
    helper = Path(__file__).with_name('stamp_fee_admission.py')
    if previous.is_symlink() or hashlib.sha256(previous.read_bytes()).hexdigest() != PREVIOUS_FACTORY_SHA:
        raise RuntimeError('AE178 previous factory pin differs')
    if helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest() != ADMISSION_SHA:
        raise RuntimeError('AE178 admission helper pin differs')
    name = 'solslot_api.stamp_fee_admission'
    if name in sys.modules:
        raise RuntimeError('AE178 unexpected preloaded admission helper')
    spec = importlib.util.spec_from_file_location(name,helper)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    install_guard()
    spec = importlib.util.spec_from_file_location('solslot_preserved_factory_ae178', previous)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.create_app()
