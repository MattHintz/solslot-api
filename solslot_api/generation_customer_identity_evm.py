"""Independent receipt/calldata checks for the fresh-generation ID profile.

No proof body is persisted or returned. Verification uses the caller's EVM
RPC and its confirmed inclusion block; there is no relayer or signing key.
"""
from eth_abi import decode, encode
from eth_abi.exceptions import DecodingError
from web3 import Web3
from solslot_puzzles.eligibility_policy import require_eligibility_inputs
from .enrollment_permit_runtime import decode_enrollment, PROOF_PARAMS_ABI

FORWARD_ABI = '(address,address,uint256,uint256,uint48,bytes,bytes)'
FORWARD_SELECTOR = bytes(Web3.keccak(text='execute(' + FORWARD_ABI + ')'))[:4]
PROOF_VERSIONS = {
    '0.20.0': bytes.fromhex('000000140000' + '00' * 26),
    '0.21.0': bytes.fromhex('000000150000' + '00' * 26),
    '0.21.1': bytes.fromhex('000000150001' + '00' * 26),
    '0.22.0': bytes.fromhex('000000160000' + '00' * 26),
}


def require_current_identity_query(data, profile, *, launcher):
    parsed = decode_enrollment(data)
    if parsed.permit is not None or parsed.vault != launcher:
        raise ValueError('CURRENT_ID_CALLDATA_BINDING_CHANGED')
    if not any(c.parent_id == parsed.parent for c in profile.bridge_coins):
        raise ValueError('CURRENT_ID_BRIDGE_OUTSIDE_PROFILE')
    try:
        params, = decode([PROOF_PARAMS_ABI], parsed.proof)
        if encode([PROOF_PARAMS_ABI], [params]) != parsed.proof:
            raise ValueError('noncanonical proof envelope')
        if (params[0] not in {PROOF_VERSIONS[v] for v in profile.accepted_proof_versions}
                or params[3] != (604800, 'solslot.com', 'vault:' + launcher, False)):
            raise ValueError('proof policy differs')
        require_eligibility_inputs(params[2])
    except (ValueError, TypeError, DecodingError) as exc:
        raise ValueError('CURRENT_ID_PRIVATE_QUERY_REJECTED') from exc
    return parsed


def verify_current_identity_transaction(w3, profile, receipt, *, launcher):
    if int(w3.eth.chain_id) != profile.evm_chain_id:
        raise ValueError('CURRENT_ID_EVM_NETWORK_CHANGED')
    height = receipt['blockNumber']
    block_hash = bytes(receipt['blockHash'])
    if bytes(w3.eth.get_block(height)['hash']) != block_hash:
        raise ValueError('CURRENT_ID_EVM_INCLUSION_CHANGED')
    addresses = verify_current_identity_contracts(w3, profile, height)
    tx = w3.eth.get_transaction(receipt['transactionHash'])
    if (bytes(tx['blockHash']) != block_hash or int(tx['blockNumber']) != height
            or bytes(tx['hash']) != bytes(receipt['transactionHash'])
            or int(tx['value']) != 0):
        raise ValueError('CURRENT_ID_EVM_TRANSACTION_CHANGED')
    destination = str(tx['to']).lower()
    data = bytes(tx['input'])
    sender = str(tx['from']).lower()
    if destination == addresses['forwarder']:
        if data[:4] != FORWARD_SELECTOR:
            raise ValueError('CURRENT_ID_EVM_FORWARDER_ACTION_CHANGED')
        try:
            request, = decode([FORWARD_ABI], data[4:])
        except (ValueError, DecodingError) as exc:
            raise ValueError('CURRENT_ID_EVM_FORWARDER_ENCODING_CHANGED') from exc
        if (encode([FORWARD_ABI], [request]) != data[4:]
                or request[1].lower() != addresses['attestationEmitter'] or request[2] != 0):
            raise ValueError('CURRENT_ID_EVM_FORWARDER_TARGET_CHANGED')
        sender, data = request[0].lower(), request[5]
    elif destination != addresses['attestationEmitter']:
        raise ValueError('CURRENT_ID_EVM_TRANSACTION_TARGET_CHANGED')
    parsed = require_current_identity_query(data, profile, launcher=launcher)
    if bytes(w3.eth.get_block(height)['hash']) != block_hash:
        raise ValueError('CURRENT_ID_EVM_INCLUSION_CHANGED')
    return sender, parsed


def verify_current_identity_contracts(w3, profile, height):
    if int(w3.eth.chain_id) != profile.evm_chain_id:
        raise ValueError('CURRENT_ID_EVM_NETWORK_CHANGED')
    addresses = {c.role: c.address for c in profile.contracts}
    for contract in profile.contracts:
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(contract.address), block_identifier=height))
        if not code or Web3.to_hex(Web3.keccak(code)) != contract.code_hash:
            raise ValueError('CURRENT_ID_EVM_CONTRACT_CHANGED')

    def call(signature, params=b''):
        return bytes(w3.eth.call({'to': Web3.to_checksum_address(addresses['attestationEmitter']),
            'data': Web3.to_hex(bytes(Web3.keccak(text=signature))[:4] + params)}, block_identifier=height))

    if (call('bridgePolicyHash()') != bytes.fromhex(profile.bridge_policy_hash[2:])
            or call('verifier()') != bytes(12) + bytes.fromhex(addresses['verifierAdapter'][2:])
            or call('trustedDirectRelayer()') != bytes(12) + bytes.fromhex(profile.trusted_direct_relayer[2:])
            or call('isTrustedForwarder(address)', bytes(12) + bytes.fromhex(addresses['forwarder'][2:])) != bytes(31) + b'\x01'):
        raise ValueError('CURRENT_ID_EVM_TRUST_BINDING_CHANGED')
    selector = bytes(Web3.keccak(text='supportsProofVersion(bytes32)'))[:4]
    for version in profile.accepted_proof_versions:
        # A matching upstream verifier bytecode does not establish that our
        # own immutable adapter admits the same circuit version.
        accepted = bytes(w3.eth.call({
            'to': Web3.to_checksum_address(addresses['verifierAdapter']),
            'data': Web3.to_hex(selector + PROOF_VERSIONS[version]),
        }, block_identifier=height))
        if accepted != bytes(31) + b'\x01':
            raise ValueError('CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED')
    return addresses


def read_current_identity_compatibility(settings, profile, now):
    """Public chain reads only; never opens a wallet or loads signing keys."""
    from .zkpassport_relay import _w3
    from .generation_customer_identity_scope import current_identity_settings
    selected = current_identity_settings(settings, profile)
    w3 = _w3(selected.zkpassport_evm_rpc_url)
    height = int(w3.eth.block_number)
    verify_current_identity_contracts(w3, profile, height)
    return {'status': 'READY', 'profileHash': profile.commitment,
            'checkedAt': now, 'blockNumber': height,
            'proofVersions': list(profile.accepted_proof_versions)}
