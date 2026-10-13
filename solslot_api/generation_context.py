"""Deployment domains for off-chain authorization. Never rewrites chain history."""
from copy import deepcopy
import re


def generation_bytes(generation_id: str) -> bytes:
    if not isinstance(generation_id, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', generation_id):
        raise ValueError('deployment generation must be a 32-byte identifier')
    value = bytes.fromhex(generation_id[2:])
    if value == bytes(32):
        raise ValueError('deployment generation cannot be zero')
    return value


def bind_typed_generation(typed: dict, generation_id: str | None) -> dict:
    """Salt OFF-CHAIN typed messages; existing contract signature domains stay fixed."""
    if generation_id is None:
        return typed
    salt = '0x' + generation_bytes(generation_id).hex()
    result = deepcopy(typed)
    domain_types = result['types']['EIP712Domain']
    if 'salt' in result['domain'] or any(field['name'] == 'salt' for field in domain_types):
        raise ValueError('typed message already has a domain salt')
    domain_types.append({'name': 'salt', 'type': 'bytes32'})
    result['domain']['salt'] = salt
    return result
