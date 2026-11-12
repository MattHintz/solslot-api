"""AE170: checksum the RPC balance address; retain canonical ledger addresses."""
from pathlib import Path
import ast
import hashlib
import importlib.util

FEE_SOURCE_SHA = 'cddf1ebfb4a9f21f9837b25df9a72e9132c264af02cb9c96447b51cd3fd9968a'
PREVIOUS_FACTORY_SHA = '0e122908faf206bca04067f2bfb766b7ad47dca9a794509b24b55249fccd0d72'


def corrected_dispatch(module):
    path = Path(module.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != FEE_SOURCE_SHA:
        raise RuntimeError('AE170 preserved fee source pin differs')
    tree = ast.parse(path.read_text())
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == 'check_base_dispatch']
    if len(functions) != 1:
        raise RuntimeError('AE170 exact fee function required')
    function = functions[0]
    matches = [n for n in ast.walk(function) if isinstance(n, ast.Call)
               and ast.unparse(n) == "w3.eth.get_balance(quote['relayer'], 'pending')"]
    if len(matches) != 1:
        raise RuntimeError('AE170 exact balance call required')
    target = matches[0]
    target.args[0] = ast.Call(func=ast.Attribute(value=ast.Name(id='Web3', ctx=ast.Load()),
        attr='to_checksum_address', ctx=ast.Load()), args=[target.args[0]], keywords=[])
    patched = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = dict(module.__dict__)
    exec(compile(patched, 'solslot_identity_fee_address_AE170', 'exec'), namespace)
    result = namespace['check_base_dispatch']
    result.__ae170__ = True
    return result


def install_guard():
    from solslot_api import identity_relay_fees as fees
    from solslot_api import zkpassport_relay as relay
    if getattr(fees.check_base_dispatch, '__ae170__', False):
        if relay.check_base_dispatch is not fees.check_base_dispatch:
            raise RuntimeError('AE170 relay binding differs')
        return
    if relay.check_base_dispatch is not fees.check_base_dispatch:
        raise RuntimeError('AE170 preserved relay binding differs')
    replacement = corrected_dispatch(fees)
    fees.check_base_dispatch = replacement
    relay.check_base_dispatch = replacement


def create_app():
    path = Path('/opt/solslot/genesis-rc28/operations/AE169/solslot_identity_chain_binding.py')
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != PREVIOUS_FACTORY_SHA:
        raise RuntimeError('AE170 previous factory pin differs')
    spec = importlib.util.spec_from_file_location('solslot_preserved_factory_ae170', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = module.create_app()
    install_guard()
    return app
