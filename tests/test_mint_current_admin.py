import pytest
from eth_keys import keys
from solslot_api.mint_chain_validation import _admin_member_hash
from solslot_puzzles.eip712_helpers import (
    compute_eip712_member_leaf_hash, eip712_prefix_and_domain_separator,
    eip712_type_hash, genesis_challenge_for_network,
)


def test_mint_member_binding_uses_confirmed_current_keys_after_rotation():
    genesis = tuple(keys.PrivateKey(bytes([i])*32).public_key for i in (61, 62, 63))
    replacement = keys.PrivateKey(bytes([64])*32).public_key
    current = (replacement, *genesis[1:])
    artifact = {'adminAuthority': {'compressedPubkeys': ['0x'+key.to_compressed_bytes().hex() for key in genesis]}}
    arguments = dict(artifact=artifact, compute_leaf=compute_eip712_member_leaf_hash,
        prefix=eip712_prefix_and_domain_separator(genesis_challenge_for_network('testnet11')),
        type_hash=eip712_type_hash())
    with pytest.raises(ValueError, match='absent'):
        _admin_member_hash(authenticated_owner=replacement.to_checksum_address(), **arguments)
    current_keys = tuple(key.to_compressed_bytes() for key in current)
    actual = _admin_member_hash(authenticated_owner=replacement.to_checksum_address(),
        current_admin_pubkeys=current_keys, **arguments)
    assert actual == compute_eip712_member_leaf_hash(secp256k1_pubkey=replacement.to_compressed_bytes(),
        prefix_and_domain_separator=arguments['prefix'], type_hash=arguments['type_hash'])
    with pytest.raises(ValueError, match='absent'):
        _admin_member_hash(authenticated_owner=genesis[0].to_checksum_address(),
            current_admin_pubkeys=current_keys, **arguments)
