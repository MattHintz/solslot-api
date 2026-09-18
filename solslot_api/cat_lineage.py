"""Authenticated CAT receipt lineage across a change of ownership."""
from collections.abc import Mapping

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32


async def confirmed_cat_receipt_lineage(*, provider, coin: Coin, expected_inner_hash: bytes32,
    expected_tail_hash: bytes32, asset_label: str = 'CAT') -> LineageProof:
    """Authenticate both sides of a confirmed CAT transfer, allowing owner changes.

The child's owner is pinned by its full puzzle hash. The lineage proof carries
the actual parent's inner hash, which differs after a grant, sale or unlock.
"""
    from .sols_swaps import _coin_from_record
    expected_full_hash = construct_cat_puzzle(CAT_MOD, expected_tail_hash,
        expected_inner_hash).get_tree_hash_precalc(expected_inner_hash)
    if coin.puzzle_hash != expected_full_hash:
        raise ValueError(f'{asset_label} receipt does not belong to the expected vault')
    parent_id = '0x' + coin.parent_coin_info.hex()
    parent_record = await provider.get_coin_record_by_name(parent_id)
    child_record = await provider.get_coin_record_by_name('0x' + coin.name().hex())
    parent = _coin_from_record(parent_record)
    child = _coin_from_record(child_record)
    height = int((child_record or {}).get('confirmed_block_index') or 0)
    if (parent is None or child != coin or parent.name() != coin.parent_coin_info or height <= 0
        or int((parent_record or {}).get('spent_block_index') or 0) != height
        or int((child_record or {}).get('spent_block_index') or 0) != 0
        or bool((child_record or {}).get('spent'))):
        raise ValueError(f'{asset_label} receipt lineage is not a confirmed unspent atomic transfer')
    raw = await provider.get_puzzle_and_solution(parent_id, height)
    if not isinstance(raw, Mapping):
        raise ValueError(f'{asset_label} parent spend is unavailable')
    reveal = Program.from_bytes(bytes.fromhex(str(raw['puzzle_reveal']).removeprefix('0x')))
    solution = Program.from_bytes(bytes.fromhex(str(raw['solution']).removeprefix('0x')))
    mod, args_program = reveal.uncurry()
    args = list(args_program.as_iter())
    if (reveal.get_tree_hash() != parent.puzzle_hash or mod != CAT_MOD or len(args) != 3
        or args[0].as_atom() != CAT_MOD.get_tree_hash() or args[1].as_atom() != expected_tail_hash):
        raise ValueError(f'{asset_label} parent reveal or asset identity is inconsistent')
    if coin not in compute_additions(make_spend(parent, reveal, solution)):
        raise ValueError(f'{asset_label} parent spend did not create the selected receipt')
    return LineageProof(parent_name=parent.parent_coin_info,
        inner_puzzle_hash=args[2].get_tree_hash(), amount=parent.amount)
