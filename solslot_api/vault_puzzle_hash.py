"""Hash the protocol vault without moving lazy CLVM nodes across threads.

Only immutable module hashes cross the ASGI worker boundary. Currying is the
same as vault_driver.puzzle_for_vault_full; parity tests cover every argument.
"""

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.util.curry_and_treehash import (
    calculate_hash_of_quoted_mod_hash,
    curry_and_treehash,
)
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.vault_driver import (
    DEFAULT_IDENTITY_ATTEST_ROOT,
    DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
    VAULT_INNER_MOD,
    validate_owner_pubkey_for_auth_type,
)

# Read the module on its importing thread; never retain it in a returned puzzle.
_VAULT_INNER_HASH = bytes32(VAULT_INNER_MOD.get_tree_hash())


def puzzle_hash_for_vault_full(
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> bytes32:
    owner = validate_owner_pubkey_for_auth_type(owner_pubkey_bytes, auth_type)
    singleton_struct = (SINGLETON_MOD_HASH, (vault_launcher_id, SINGLETON_LAUNCHER_HASH))
    # Program.to receives only fresh Python values and immutable bytes here.
    tree_hash = lambda value: bytes32(Program.to(value).get_tree_hash())
    struct_hash = tree_hash(singleton_struct)
    inner_hash = curry_and_treehash(
        calculate_hash_of_quoted_mod_hash(_VAULT_INNER_HASH),
        struct_hash,
        tree_hash(owner),
        tree_hash(auth_type),
        tree_hash(members_merkle_root),
        tree_hash(identity_attest_root),
        tree_hash(zkpassport_bridge_policy_hash),
        tree_hash(SINGLETON_MOD_HASH),
        tree_hash(pool_launcher_id),
        tree_hash(SINGLETON_LAUNCHER_HASH),
    )
    return bytes32(curry_and_treehash(
        calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH),
        struct_hash,
        inner_hash,
    ))
