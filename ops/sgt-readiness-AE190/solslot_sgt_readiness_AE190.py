"""Preserve AE178 API behavior; gate collection mutations on fresh recovery."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from recovery_health import read_receipt
from pathlib import Path
import hashlib
import importlib.util
import sys

PREVIOUS=Path('/opt/solslot/genesis-rc28/operations/AE178/api')
PINS={'solslot_stamp_fee_admission_AE178.py':'69db32e9efbcfe04972ce50cac5434814234d148a85ce924be4aa47a65ddf268',
      'stamp_fee_admission.py':'94390ae8717c7f79321dc73b5d1f27f6f6968d5bd1ecc6ca68b9dfd0760499cb'}


class CollectionRecoveryGuard(BaseHTTPMiddleware):
    async def dispatch(self,request,call_next):
        path=request.url.path
        if request.method in ('POST','PUT','PATCH','DELETE') and (
                path=='/admin/collections' or path.startswith('/admin/collections/')):
            try:read_receipt()
            except (OSError,ValueError,TypeError,KeyError):
                return JSONResponse({'detail':'Property drafting is paused while its recovery check is renewed. Your saved draft is retained.'},status_code=503,
                                    headers={'Retry-After':'120','Cache-Control':'no-store'})
        return await call_next(request)


OPERATION=Path('/opt/solslot/genesis-rc28/operations/AE190')
RELEASE=OPERATION/'release'
PROTOCOL=Path('/opt/solslot/genesis-rc28/operations/AE161/release')
BOUNDARY=Path('/opt/solslot/genesis-rc28/operations/AE156/solslot_identity_http.py')
FACTORIES={
 'chain':('AE169/solslot_identity_chain_binding.py','0e122908faf206bca04067f2bfb766b7ad47dca9a794509b24b55249fccd0d72'),
 'fee':('AE170/solslot_identity_fee_address.py','8cd594fadced5316c79caa2cbfca69ad00bc0f6d9c583592034f12eebe06a860'),
 'challenge':('AE175/solslot_sage_identity_challenge_AE175.py','61e6d4b9c3352205eaffef96f17d1cf598d7903e9954c0178974da389c29cad7'),
 'dispatch':('AE176/solslot_sage_stamp_dispatch_AE176.py','ecfe892f945c63cbdc411ffeb7a23eedd4b5957805cad11149f67253c69e528b'),
 'admission':('AE178/api/solslot_stamp_fee_admission_AE178.py','69db32e9efbcfe04972ce50cac5434814234d148a85ce924be4aa47a65ddf268'),
}


def pinned_module(name,path,digest):
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
        raise RuntimeError('AE190 preserved factory differs: '+name)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def compose_preserved_guards(modules,base_factory):
    # Match the existing AE178 -> AE176 -> AE175 -> AE170 -> AE169 order.
    # Pre-app guards run before routers are copied. Post-app guards retain the
    # existing function identities and effective authentication dependencies.
    modules['admission'].install_guard()
    modules['dispatch'].install_guard()
    modules['chain'].install_guard()
    app=base_factory()
    modules['fee'].install_guard()
    modules['challenge'].install_guard()
    return CollectionRecoveryGuard(app)


def create_app():
    import json,os
    import solslot_api,solslot_puzzles
    if os.environ.get('SOLSLOT_CHAIN_BINDING_ROLE')!='coordinator':
        raise RuntimeError('AE190 coordinator role required')
    if (Path(solslot_api.__file__).resolve().parent!=RELEASE/'api/solslot_api'
            or Path(solslot_puzzles.__file__).resolve().parent!=PROTOCOL/'protocol/solslot_puzzles'):
        raise RuntimeError('AE190 source locations differ')
    pins=json.loads((OPERATION/'runtime-source-pins.json').read_text())
    if pins['schema']!='solslot.collection-authoring-runtime-pins.v1':
        raise RuntimeError('AE190 source contract differs')
    for base,files in ((RELEASE,pins['releaseFiles']),(PROTOCOL,pins['preservedProtocolFiles'])):
        for relative,digest in files.items():
            if Path(relative).is_absolute() or '..' in Path(relative).parts:
                raise RuntimeError('AE190 source path differs')
            path=base/relative
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise RuntimeError('AE190 release source differs: '+relative)
    modules={name:pinned_module('solslot_preserved_'+name+'_ae190',OPERATION.parent/relative,digest)
             for name,(relative,digest) in FACTORIES.items()}
    helper=PREVIOUS/'stamp_fee_admission.py'
    helper_module=pinned_module('solslot_api.stamp_fee_admission',helper,PINS['stamp_fee_admission.py'])
    if 'solslot_api.stamp_fee_admission' in sys.modules:
        raise RuntimeError('AE190 unexpected preloaded admission helper')
    sys.modules['solslot_api.stamp_fee_admission']=helper_module
    boundary=pinned_module('solslot_preserved_boundary_ae190',BOUNDARY,pins['preservedBoundaryFactorySha256'])
    def base_factory():
        app=boundary.create_app()
        from solslot_api.collection_media_runtime import with_local_collection_media
        from solslot_api.config import get_settings
        return with_local_collection_media(app,get_settings())
    return compose_preserved_guards(modules,base_factory)
