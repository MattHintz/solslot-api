from concurrent.futures import ThreadPoolExecutor
import hashlib

import pytest
from chia_rs.sized_bytes import bytes32
from solslot_api.vault_puzzle_hash import puzzle_hash_for_vault_full
from solslot_puzzles.vault_driver import puzzle_for_vault_full


@pytest.mark.parametrize('auth_type,owner', [
    (1, bytes(range(48))),
    (2, b'\x04' + bytes(range(64))),
    (3, b'\x02' + bytes(range(32))),
    (3, b'\x03' + bytes(range(32))),
])
def test_worker_hash_matches_full_protocol_puzzle_for_all_state_fields(auth_type, owner):
    def h(label):
        return bytes32(hashlib.sha256(label.encode()).digest())
    baseline = dict(vault_launcher_id=h('launcher'), owner_pubkey_bytes=owner,
        auth_type=auth_type, members_merkle_root=h('members'), pool_launcher_id=h('pool'),
        identity_attest_root=h('identity'), zkpassport_bridge_policy_hash=h('bridge'))
    cases = [baseline]
    for field in ('vault_launcher_id', 'members_merkle_root', 'pool_launcher_id',
                  'identity_attest_root', 'zkpassport_bridge_policy_hash'):
        cases.append({**baseline, field: h('changed-' + field)})
    # Canonical protocol Programs are created/hashed on their importing thread.
    expected = [puzzle_for_vault_full(**case).get_tree_hash() for case in cases]
    assert len(set(expected)) == len(cases)
    # Reproduce the production boundary: module import here, validation on workers.
    with ThreadPoolExecutor(max_workers=4) as pool:
        actual = list(pool.map(lambda case: puzzle_hash_for_vault_full(**case), cases * 4))
    assert actual == expected * 4


@pytest.mark.parametrize('auth_type,owner', [(1,b'x'), (2,b'\x03'+bytes(64)), (3,b'\x04'+bytes(32)), (9,bytes(48))])
def test_invalid_owner_encoding_still_rejected(auth_type, owner):
    with pytest.raises(ValueError):
        puzzle_hash_for_vault_full(bytes32.zeros, owner, auth_type, bytes32.zeros, bytes32.zeros)
