"""Additive AE169 guard: genesis authentication and current identity selection are separate."""
from pathlib import Path
import hashlib, importlib.util, json, os

ORIGINAL_SHA='f170db1f1aa086a80dc801ced0d3c73055b11fcd71a1cd8d97effbb7f14600b2'

def verify_runtime_bindings(original, settings, payload):
    from solslot_api.public_artifact import PublicArtifactError, _release_source_shas
    from solslot_puzzles import identity_network_amendment as network
    if settings.zkpassport_evm_chain_id == 8453:
        # Validate complete predecessor/candidate/deployment/plan/source binding
        # before authenticating genesis in its original identity-chain context.
        # This admits startup only. The existing async resolver must still prove
        # both exact Chia authority spends and require current Base bindings.
        fields=(settings.identity_network_amendment_path,
                settings.identity_network_artifact_path, settings.identity_network_plan_hash)
        if not all(fields):
            raise PublicArtifactError('Base identity chain requires complete network amendment evidence')
        _release_source_shas(settings, payload)
        candidate=network.parse_canonical_statement(Path(fields[0]).read_bytes())
        if (candidate['evmChainId'] != 8453 or candidate['previousEvmChainId'] != 11155111
                or candidate['revision'] != 2 or payload.get('evmChainId') != 11155111):
            raise PublicArtifactError('identity network candidate chain context differs from genesis')
        genesis_settings=settings.model_copy(update={'zkpassport_evm_chain_id':11155111})
        return original(genesis_settings, payload)
    return original(settings,payload)

def install_guard():
    import solslot_api.public_artifact as artifact
    path=Path(artifact.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=ORIGINAL_SHA:
        raise RuntimeError('AE169 original genesis verifier pin differs')
    if getattr(artifact._verify_runtime_bindings,'__ae169__',False):
        return
    original=artifact._verify_runtime_bindings
    def guarded(settings,payload):
        return verify_runtime_bindings(original,settings,payload)
    guarded.__ae169__=True
    artifact._verify_runtime_bindings=guarded

def _check_pins(root):
    pins=json.loads((root/'runtime-source-pins.json').read_text())
    for relative,digest in pins['releaseFiles'].items():
        relative=Path(relative)
        if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('invalid frozen source path')
        path=root/'release'/relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('AE169 preserved source pin differs: '+str(relative))

def create_app():
    role=os.environ.get('SOLSLOT_CHAIN_BINDING_ROLE')
    if role not in ('coordinator','validator'):raise RuntimeError('AE169 exact runtime role required')
    if role=='validator':
        _check_pins(Path('/opt/solslot/validator/identity-network-AE161'))
    install_guard()
    if role=='validator':
        from solslot_api.validator_app import app
        return app
    # Preserve the AE165 composition, XSRF boundary and media interfaces.
    path=Path('/opt/solslot/genesis-rc28/operations/AE165/solslot_media_http_AE165.py')
    expected=os.environ.get('SOLSLOT_AE169_PREVIOUS_FACTORY_SHA256','')
    if path.is_symlink() or len(expected)!=64 or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
        raise RuntimeError('AE169 previous API factory pin differs')
    spec=importlib.util.spec_from_file_location('solslot_preserved_media_ae169',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.create_app()
