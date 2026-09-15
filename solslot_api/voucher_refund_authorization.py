"""Historical voucher burn authorization using the existing V1 vault contract.

The receive branch authorizes delivery to the vault inner, which cannot satisfy
an immutable voucher burn. V1's destination-bound transfer branch supports the
burn for BLS owners. Its EVM transfer branch is not implemented on chain; reject
that case before requesting an unusable signature. Never substitute a V2 puzzle
for an existing V1 coin or alter the voucher's immutable settlement conditions.
"""
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton, solution_for_singleton
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, puzzle_for_vault_inner
from solslot_puzzles.voucher_presale_v2_driver import burn_inner_hash


UNSUPPORTED_OWNER = (
    'This vault version cannot authorize a voucher refund with an EVM wallet. '
    'No transaction has been submitted. This recovery path requires a reviewed '
    'vault protocol upgrade; automatic delivery-timeout refunds remain available '
    'for launched vouchers.'
)


def build_vault_refund_spend(*, vault_coin, vault_launcher_id, owner_pubkey,
                           auth_type, members_merkle_root, pool_launcher_id,
                           identity_attest_root, zkpassport_bridge_policy_hash,
                           voucher_launcher_id, current_timestamp, lineage_proof):
    if auth_type != AUTH_TYPE_BLS:
        raise ValueError(UNSUPPORTED_OWNER)
    inner = puzzle_for_vault_inner(
        vault_launcher_id, owner_pubkey, auth_type, members_merkle_root,
        pool_launcher_id, identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full = puzzle_for_singleton(vault_launcher_id, inner)
    if vault_coin.puzzle_hash != full.get_tree_hash() or int(vault_coin.amount) != 1:
        raise ValueError('Refund vault does not match its registered V1 owner')
    # The existing m branch signs (case, voucher launcher, immutable burn, coin).
    # The voucher cannot transfer elsewhere and independently requires both the
    # vault announcement and validator-authorized series/payment settlement.
    solution = Program.to([
        vault_coin.name(), inner.get_tree_hash(), vault_coin.amount, b'm',
        [voucher_launcher_id, burn_inner_hash(), current_timestamp, b''],
    ])
    return make_spend(vault_coin, full, solution_for_singleton(lineage_proof, vault_coin.amount, solution))
