"""Reviewed Base Sepolia deployment verification; never deployment authorization.

The operator pins a separate review receipt and the existing nine-component
release evidence. A deployment JSON's self hash cannot supply either pin.
Activation omits only its own review digest from the review commitment to avoid
circular hashing. Ceremony signatures/windows and Authority V3 reviews remain
separate gates. No live keys are needed by this reader.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from pathlib import Path
from typing import Any, Mapping

import rlp
from web3 import Web3

from solslot_puzzles.enrollment_activation import exact_hex, validate_enrollment_activation
from .config import Settings
from .genesis_evm import ADDRESS_FIELDS, EVM_CONTRACTS, GenesisEvmEvidenceError, _canonical_hash

MAX_BYTES = 256 * 1024
REVIEW_SCOPES = {'protocol', 'evm', 'credentialBridge', 'ceremonyOrchestrator'}
ROOT_VERIFIER = '0x1d000001000efd9a6371f4d90bb8920d5431c0d8'
SOURCE_REPOSITORIES = {'protocol': 'MattHintz/solslot-protocol', 'evm': 'MattHintz/solslot-evm', 'omnichain': 'solslot/omnichain', 'api': 'MattHintz/solslot-api', 'legacyBackend': 'solslot/solslot-backend', 'keyOfSolomon': 'solslot/KeyofSolomon', 'samuel': 'solslot/Samuel', 'customerWeb': 'solslot/solslot', 'adminPortal': 'MattHintz/solslot-portal'}


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GenesisEvmEvidenceError(f'{label} must be an object')
    return value


def _keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GenesisEvmEvidenceError(f'{label} fields are incomplete or unsupported')


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise GenesisEvmEvidenceError(f'{label} must be a safe integer')
    return value


def _hash(value: Any, label: str, size: int = 32) -> str:
    try:
        exact_hex(value, size, label)
    except ValueError as exc:
        raise GenesisEvmEvidenceError(str(exc)) from exc
    return value


def _rpc_hash(value: Any, label: str, size: int = 32) -> str:
    if isinstance(value, bytes):
        value = '0x' + value.hex()
    return _hash(value, label, size)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GenesisEvmEvidenceError('evidence contains duplicate JSON fields')
        result[key] = value
    return result


def _read(path_value: str, label: str, pin: str | None = None) -> tuple[dict[str, Any], str]:
    if not path_value:
        raise GenesisEvmEvidenceError(f'{label} path is missing')
    path = Path(path_value)
    try:
        stat = path.lstat()
        if path.is_symlink() or not path.is_file() or not 0 < stat.st_size <= MAX_BYTES:
            raise GenesisEvmEvidenceError(f'{label} must be a bounded regular file')
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if pin is not None and (re.fullmatch(r'[0-9a-f]{64}', pin) is None
                or pin == '0'*64 or not secrets.compare_digest(digest, pin)):
            raise GenesisEvmEvidenceError(f'{label} checksum is not pinned or changed')
        payload = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GenesisEvmEvidenceError(f'{label} is unreadable') from exc
    return dict(_object(payload, label)), digest


def _activation(settings: Settings, record: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if (settings.network != 'testnet11' or settings.zkpassport_evm_chain_id != 84532
                or settings.eip712_chain_id != 84532 or plan['evmChainId'] != 84532
                or type(plan['evmChainId']) is not int or plan['network'] != 'testnet11'
                or record['draft']['evmChainId'] != 84532
                or type(record['draft']['evmChainId']) is not int
                or plan['sourceShas'] != record['draft']['sourceShas']
                or plan['ceremonyId'] != record['ceremony_id']
                or plan['validatorSet']['threshold'] != 2):
            raise ValueError('selected deployment chain, source or ceremony differs')
        active = validate_enrollment_activation(plan['enrollmentActivation'],
            source_shas=record['draft']['sourceShas'], ceremony_id=record['ceremony_id'],
            emitter=plan['evmAddresses']['attestationEmitter'],
            validator_pubkeys=[exact_hex(key, 48, 'validator') for key in plan['validatorSet']['pubkeys']],
            environment=settings.runtime_environment+'-alpha')
        if (active != record['plan_input']['enrollmentActivation']
                or active['bridgePolicyHash'] != plan['puzzleHashes']['bridgePolicy']
                or active['releaseIdentity'] != settings.enrollment_permit_release_identity
                or active['issuerKeyRef'] != settings.enrollment_permit_issuer_key_ref
                or active['issuerIdentityClientId'] != settings.enrollment_permit_identity_client_id):
            raise ValueError('selected activation differs from coordinator or signed plan')
        return active
    except (ValueError, KeyError, TypeError) as exc:
        raise GenesisEvmEvidenceError(f'invalid selected activation: {exc}') from exc


def _review(settings: Settings, active: dict[str, Any], deployment: dict[str, Any]) -> dict[str, Any]:
    # Reuse the protected launch-release validator, including recovery SDK,
    # canonical manifest, release branch and all nine source records.
    from .launch_control import _load_release_evidence
    from .genesis_store import GenesisStoreError
    pin = settings.enrollment_deployment_review_sha256
    if pin != active['reviewEvidenceSha256']:
        raise GenesisEvmEvidenceError('activation review differs from the operator pin')
    review, digest = _read(settings.enrollment_deployment_review_path, 'permit deployment review', pin)
    _keys(review, {'schema', 'outcome', 'activationHash', 'deploymentArtifactHash',
        'releaseEvidenceSha256', 'manifestHash', 'sourceShas', 'reviews'}, 'permit deployment review')
    source_pin = (settings.launch_source_evidence_sha256 or '').removeprefix('0x')
    _read(settings.launch_source_evidence_path, 'release evidence', source_pin)
    try:
        release = _load_release_evidence(settings)
    except (GenesisStoreError, ValueError, KeyError, TypeError) as exc:
        raise GenesisEvmEvidenceError(f'permit release evidence is invalid: {exc}') from exc
    sources = release['evidence']['sourceManifest']['sources']
    for name, repository in SOURCE_REPOSITORIES.items():
        url = 'https://github.com/' + repository
        if sources[name]['repository'] not in (url, url+'.git'):
            raise GenesisEvmEvidenceError('selected source manifest changes canonical repository ownership')
    expected = {'schema': 'solslot.enrollment-deployment-review.v1', 'outcome': 'approved',
        'activationHash': _canonical_hash({k:v for k,v in active.items() if k!='reviewEvidenceSha256'}),
        'deploymentArtifactHash': deployment['artifactHash'],
        'releaseEvidenceSha256': source_pin, 'manifestHash': release['manifestHash'],
        'sourceShas': active['sourceShas']}
    if (any(review.get(k) != v for k,v in expected.items())
            or release['sourceShas'] != active['sourceShas']):
        raise GenesisEvmEvidenceError('permit review targets another activation, deployment or release')
    reviews = review['reviews']
    if not isinstance(reviews, list) or len(reviews) != len(REVIEW_SCOPES):
        raise GenesisEvmEvidenceError('permit review requires all four independent lanes')
    scopes = set()
    for item in reviews:
        item = _object(item, 'review lane')
        _keys(item, {'scope', 'approved', 'reviewer', 'evidenceHash'}, 'review lane')
        if (item['scope'] not in REVIEW_SCOPES or item['scope'] in scopes
                or item['approved'] is not True or not isinstance(item['reviewer'], str)
                or not item['reviewer'].strip()):
            raise GenesisEvmEvidenceError('permit review lane is not approved')
        _hash(item['evidenceHash'], 'review evidence hash')
        scopes.add(item['scope'])
    return {'fileSha256': digest, 'receipt': review, 'releaseEvidenceSha256': source_pin,
        'manifestHash': release['manifestHash']}


def _call(web3: Any, address: str, name: str, output: str, peak: int, args=(), inputs=()) -> Any:
    abi = [{'type':'function','name':name,'stateMutability':'view',
        'inputs':[{'name':f'p{i}','type':v} for i,v in enumerate(inputs)],
        'outputs':[{'name':'','type':output}]}]
    contract = web3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)
    return getattr(contract.functions, name)(*args).call(block_identifier=peak)


def verify_permit_deployment(settings: Settings, record: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
    active = _activation(settings, record, plan)
    deployment, _ = _read(settings.genesis_evm_deployment_path, 'permit deployment')
    fields = {'schemaVersion','protocolVersion','credentialPolicyVersion','network','chainId',
        'sourceShas','deployer','startNonce','forwarderAddress','verifierAdapterAddress',
        'attestationEmitterAddress','trustedDirectRelayerAddress','bridgePolicyHash',
        'zkPassportRootVerifierAddress','zkPassportDomain','zkPassportDevMode',
        'permitIssuer','permitContextHash','deploymentId','releaseIdentity',
        'deploymentTransactions','runtimeCodeHashes','artifactHash'}
    _keys(deployment, fields, 'permit deployment')
    _hash(deployment['artifactHash'], 'deployment artifact hash')
    if deployment['artifactHash'] != _canonical_hash({k:v for k,v in deployment.items() if k!='artifactHash'}):
        raise GenesisEvmEvidenceError('permit deployment hash is not canonical')
    expected = {'schemaVersion':3,'protocolVersion':'solslot-v2','credentialPolicyVersion':2,
        'network':'baseSepolia','chainId':84532,'sourceShas':active['sourceShas'],
        'bridgePolicyHash':active['bridgePolicyHash'],'permitIssuer':active['issuer'],
        'permitContextHash':active['contextHash'],'deploymentId':active['deploymentId'],
        'releaseIdentity':active['releaseIdentity'],'zkPassportRootVerifierAddress':ROOT_VERIFIER,
        'zkPassportDomain':{'staging-alpha':'staging.solslot.com','production-alpha':'solslot.com'}[active['environment']]}
    if (any(deployment[k]!=v for k,v in expected.items()) or deployment['zkPassportDevMode'] is not False
            or any(type(deployment[k]) is not int for k in ('schemaVersion','credentialPolicyVersion','chainId'))):
        raise GenesisEvmEvidenceError('permit deployment differs from selected Testnet activation')
    review = _review(settings, active, deployment)
    addresses = {name:_hash(deployment[field], name, 20) for name,field in ADDRESS_FIELDS.items()}
    if addresses != plan['evmAddresses'] or len(set(addresses.values())) != 3:
        raise GenesisEvmEvidenceError('permit deployment addresses differ from the signed plan')
    deployer = _hash(deployment['deployer'], 'deployer', 20)
    direct = _hash(deployment['trustedDirectRelayerAddress'], 'direct relayer', 20)
    nonce = _integer(deployment['startNonce'], 'startNonce')
    txs = _object(deployment['deploymentTransactions'], 'deployment transactions')
    codes = _object(deployment['runtimeCodeHashes'], 'runtime code hashes')
    _keys(txs, set(EVM_CONTRACTS), 'deployment transactions')
    _keys(codes, {*EVM_CONTRACTS,'zkPassportRootVerifier'}, 'runtime code hashes')
    web3 = Web3(Web3.HTTPProvider(settings.zkpassport_evm_rpc_url, request_kwargs={'timeout':15}))
    contracts = {}
    try:
        if not web3.is_connected() or web3.eth.chain_id != 84532:
            raise GenesisEvmEvidenceError('selected RPC must be Base Sepolia')
        peak = _integer(web3.eth.block_number, 'RPC peak', 1)
        peak_hash = _rpc_hash(web3.eth.get_block(peak)['hash'], 'peak hash')
        for offset, name in enumerate(EVM_CONTRACTS):
            item = _object(txs[name], f'{name} transaction')
            _keys(item, {'hash','blockNumber','blockHash','nonce','initCodeHash'}, f'{name} transaction')
            tx_hash = _hash(item['hash'], 'transaction hash')
            height = _integer(item['blockNumber'], 'deployment block', 1)
            block_hash = _hash(item['blockHash'], 'deployment block hash')
            tx_nonce = _integer(item['nonce'], 'deployment nonce')
            if tx_nonce != nonce+offset:
                raise GenesisEvmEvidenceError('deployment nonce differs from ordered plan')
            predicted = '0x'+bytes(Web3.keccak(rlp.encode([bytes.fromhex(deployer[2:]),tx_nonce])))[-20:].hex()
            if predicted != addresses[name]:
                raise GenesisEvmEvidenceError('deployment address does not derive from deployer and nonce')
            receipt = web3.eth.get_transaction_receipt(tx_hash)
            tx = web3.eth.get_transaction(tx_hash)
            if (receipt['status']!=1 or _rpc_hash(receipt['transactionHash'],'receipt transaction')!=tx_hash
                    or receipt['blockNumber']!=height or _rpc_hash(receipt['blockHash'],'receipt block')!=block_hash
                    or _rpc_hash(web3.eth.get_block(height)['hash'],'canonical block')!=block_hash
                    or str(receipt['contractAddress']).lower()!=addresses[name]
                    or _rpc_hash(tx['hash'],'transaction identity')!=tx_hash
                    or tx['blockNumber']!=height or _rpc_hash(tx['blockHash'],'transaction block')!=block_hash
                    or str(tx['from']).lower()!=deployer or tx['to'] is not None
                    or tx['nonce']!=tx_nonce or tx['chainId']!=84532 or tx['value']!=0):
                raise GenesisEvmEvidenceError(f'{name} canonical deployment transaction differs')
            init = tx['input']
            init_bytes = bytes.fromhex(init[2:]) if isinstance(init,str) and init.startswith('0x') else bytes(init)
            if '0x'+bytes(Web3.keccak(init_bytes)).hex()!=_hash(item['initCodeHash'],'init code hash'):
                raise GenesisEvmEvidenceError(f'{name} constructor input differs')
            confirmations = peak-height+1
            if confirmations < max(12, settings.genesis_sepolia_confirmations):
                raise GenesisEvmEvidenceError(f'{name} lacks 12 confirmations')
            contracts[name] = dict(address=addresses[name],transactionHash=tx_hash,blockNumber=height,
                blockHash=block_hash,nonce=tx_nonce,confirmations=confirmations,initCodeHash=item['initCodeHash'])
        for name, address in {**addresses,'zkPassportRootVerifier':ROOT_VERIFIER}.items():
            code = bytes(web3.eth.get_code(Web3.to_checksum_address(address), block_identifier=peak))
            digest = '0x'+bytes(Web3.keccak(code)).hex()
            if not code or digest!=_hash(codes[name], 'runtime bytecode hash'):
                raise GenesisEvmEvidenceError(f'{name} runtime bytecode differs from review')
            if name in contracts: contracts[name]['bytecodeHash'] = digest
        emitter, adapter = addresses['attestationEmitter'], addresses['verifierAdapter']
        for address,name,typ,expected_value in (
            (emitter,'bridgePolicyHash','bytes32',active['bridgePolicyHash']),
            (emitter,'permitContextHash','bytes32',active['contextHash']),
            (emitter,'permitIssuer','address',active['issuer']),
            (emitter,'verifier','address',adapter),
            (emitter,'trustedDirectRelayer','address',direct),
            (emitter,'POLICY_VERSION','uint16',2),
            (adapter,'ZKPASSPORT_ROOT_VERIFIER','address',ROOT_VERIFIER),
            (adapter,'domain','string',deployment['zkPassportDomain']),
            (adapter,'devMode','bool',False),
            (adapter,'DEFAULT_VALIDITY_SECONDS','uint256',604800),
            (adapter,'MINIMUM_AGE','uint8',18),
        ):
            value = _call(web3,address,name,typ,peak)
            if typ=='bytes32': value=_rpc_hash(value,name)
            if typ=='address': value=str(value).lower()
            if value!=expected_value or (typ=='bool' and value is not expected_value):
                raise GenesisEvmEvidenceError(f'{name} runtime binding differs from review')
        if _call(web3,emitter,'isTrustedForwarder','bool',peak,
                (Web3.to_checksum_address(addresses['forwarder']),),('address',)) is not True:
            raise GenesisEvmEvidenceError('emitter does not trust the reviewed forwarder')
        # A second canonical peak lookup detects an RPC reorganization during the read.
        if _rpc_hash(web3.eth.get_block(peak)['hash'],'final peak hash')!=peak_hash:
            raise GenesisEvmEvidenceError('Base Sepolia reorganized during deployment verification')
    except GenesisEvmEvidenceError:
        raise
    except Exception as exc:
        raise GenesisEvmEvidenceError('could not verify selected canonical deployment state') from exc
    return dict(manifestArtifactHash=deployment['artifactHash'],checkedAtBlock=peak,checkedAtBlockHash=peak_hash,
        chainId=84532,contracts=contracts,zkPassportRootVerifier=dict(address=ROOT_VERIFIER,
        bytecodeHash=codes['zkPassportRootVerifier']),enrollmentDeploymentReview=review)
