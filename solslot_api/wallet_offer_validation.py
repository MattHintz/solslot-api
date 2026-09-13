"""Non-evaluating admission checks for supported customer wallet offers.

Only the standard-wallet templates produced by prepare are admitted here.
Protocol semantics and current-chain authority remain the callers' responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass
import zlib

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.util.bech32m import bech32_decode, convertbits
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    MOD, puzzle_for_synthetic_public_key,
)
from chia.wallet.util.puzzle_compression import LATEST_VERSION, zdict_for_version
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

MAX_ENCODED_OFFER = 2_000_000
MAX_RAW_OFFER = 2_000_000
MAX_DEEDS = 100
MAX_CONDITIONS = 512
MAX_CONDITION_NODES = 8192


@dataclass(frozen=True)
class DecodedOffer:
    raw: bytes
    bundle: WalletSpendBundle

    @property
    def real_spends(self):
        return tuple(spend for spend in self.bundle.coin_spends
                     if spend.coin.parent_coin_info != bytes32.zeros)


def proper_list(program: Program, maximum: int) -> list[Program]:
    values = []
    while program.pair is not None:
        if len(values) >= maximum:
            raise ValueError("wallet offer list exceeds the supported limit")
        values.append(program.first())
        program = program.rest()
    if program.as_atom() != b"":
        raise ValueError("wallet offer contains an improper list")
    return values


def decode_offer(
    encoded: str, *, real_spends: int, dummy_spends: int,
    expected_assets: frozenset[bytes32 | None] | None = None,
) -> DecodedOffer:
    """Decode bytes and spend records without invoking submitted puzzles."""
    if not 0 < real_spends <= MAX_DEEDS + 16 or not 0 <= dummy_spends <= MAX_DEEDS:
        raise ValueError("unsupported wallet offer shape")
    if not isinstance(encoded, str) or not 16 <= len(encoded) <= MAX_ENCODED_OFFER:
        raise ValueError("wallet offer size is unsupported")
    prefix, data = bech32_decode(encoded, max_length=MAX_ENCODED_OFFER)
    if prefix != "offer" or data is None:
        raise ValueError("invalid wallet offer encoding")
    converted = convertbits(data, 5, 8, False)
    if converted is None:
        raise ValueError("invalid wallet offer padding")
    wire = bytes(converted)
    if len(wire) < 4:
        raise ValueError("incomplete wallet offer")
    version = int.from_bytes(wire[:2], "big")
    # Uncompressed SpendBundle starts with a bounded four-byte spend count.
    # Version-zero compressed offers are distinguished by their zlib header.
    raw_count = int.from_bytes(wire[:4], "big")
    if version == 0 and 0 < raw_count <= real_spends + dummy_spends:
        raw = wire
    else:
        if version > LATEST_VERSION:
            raise ValueError("unsupported wallet offer compression version")
        try:
            decoder = zlib.decompressobj(zdict=zdict_for_version(version))
            raw = decoder.decompress(wire[2:], MAX_RAW_OFFER + 1)
        except zlib.error as exc:
            raise ValueError("invalid compressed wallet offer") from exc
        if (len(raw) > MAX_RAW_OFFER or not decoder.eof
                or decoder.unused_data or decoder.unconsumed_tail):
            raise ValueError("incomplete, oversized or trailing compressed wallet offer")
    if not 4 <= len(raw) <= MAX_RAW_OFFER:
        raise ValueError("wallet offer byte limit exceeded")
    count = int.from_bytes(raw[:4], "big")
    if count != real_spends + dummy_spends:
        raise ValueError("wallet offer has an unexpected input count")
    bundle = WalletSpendBundle.from_bytes(raw)
    if bytes(bundle) != raw:
        raise ValueError("wallet offer serialization is not exact")
    if bundle.aggregated_signature != G2Element():
        raise ValueError("prepared wallet offer must be unsigned")
    real = []
    dummy = []
    names = set()
    for spend in bundle.coin_spends:
        if spend.coin.name() in names:
            raise ValueError("wallet offer repeats an input")
        names.add(spend.coin.name())
        if spend.coin.puzzle_hash != Program.from_serialized(spend.puzzle_reveal).get_tree_hash():
            raise ValueError("wallet offer puzzle does not match its input")
        if spend.coin.parent_coin_info == bytes32.zeros:
            if spend.coin.amount != 0:
                raise ValueError("requested-payment carrier must have zero amount")
            dummy.append(spend)
        else:
            if spend.coin.amount == 0:
                raise ValueError("wallet payment input must have positive amount")
            real.append(spend)
    if len(real) != real_spends or len(dummy) != dummy_spends:
        raise ValueError("wallet offer has an unexpected real/carrier input shape")
    # Carriers are data; never execute them as spends. Require proper lists,
    # bounded fields and unique asset drivers before Offer can overwrite a key.
    assets = set()
    if dummy:
        from chia.wallet.outer_puzzles import create_asset_id, match_puzzle
        from chia.wallet.uncurried_puzzle import uncurry_puzzle
        for spend in dummy:
            driver = match_puzzle(uncurry_puzzle(spend.puzzle_reveal))
            asset = None if driver is None else create_asset_id(driver)
            if asset in assets:
                raise ValueError("wallet offer repeats a requested asset")
            assets.add(asset)
            groups = proper_list(Program.from_serialized(spend.solution), MAX_CONDITIONS)
            if not groups:
                raise ValueError("requested-payment carrier is empty")
            for group in groups:
                fields = proper_list(group, MAX_CONDITIONS + 1)
                if len(fields) < 2 or len(fields[0].as_atom()) != 32:
                    raise ValueError("invalid requested-payment nonce")
                for payment in fields[1:]:
                    args = proper_list(payment, 3)
                    if len(args) != 3 or len(args[0].as_atom()) != 32:
                        raise ValueError("invalid requested payment")
                    amount = args[1].as_int()
                    if not 0 < amount < 2**64 or args[1] != Program.to(amount):
                        raise ValueError("invalid requested-payment amount")
                    for memo in proper_list(args[2], 16):
                        if len(memo.as_atom()) > 1024:
                            raise ValueError("requested-payment memo is too large")
    if expected_assets is not None and assets != expected_assets:
        raise ValueError("requested assets do not match the prepared purchase")
    return DecodedOffer(raw, bundle)


def _standard_inner(puzzle: Program, solution: Program) -> tuple[Program, Program]:
    module, arguments = puzzle.uncurry()
    args = proper_list(arguments, 1)
    if module != MOD or len(args) != 1:
        raise ValueError("payment requires the prepared standard-wallet puzzle")
    key = G1Element.from_bytes(args[0].as_atom())
    if key == G1Element():
        raise ValueError("identity payment key is unsupported")
    expected = puzzle_for_synthetic_public_key(key)
    if bytes(puzzle) != bytes(expected):
        raise ValueError("payment puzzle is not canonical")
    fields = proper_list(solution, 3)
    if len(fields) != 3 or fields[0] != Program.NIL or fields[2] != Program.NIL:
        raise ValueError("payment requires the prepared delegated-condition solution")
    quoted = fields[1]
    if quoted.pair is None or quoted.first() != Program.to(1):
        raise ValueError("payment cannot execute an arbitrary delegated puzzle")
    conditions = proper_list(quoted.rest(), MAX_CONDITIONS)
    remaining = MAX_CONDITION_NODES
    for condition in conditions:
        fields_ = proper_list(condition, 8)
        if not fields_:
            raise ValueError("empty wallet condition")
        stack = [condition]
        while stack:
            remaining -= 1
            if remaining < 0:
                raise ValueError("wallet condition data exceeds the supported limit")
            node = stack.pop()
            if node.pair is None:
                if len(node.as_atom()) > 1024:
                    raise ValueError("wallet condition atom is too large")
            else:
                # Nested data must also be proper lists (memos, for example).
                stack.extend(proper_list(node, MAX_CONDITIONS))
    canonical = Program.to([[], Program.to((1, conditions)), []])
    if bytes(solution) != bytes(canonical):
        raise ValueError("wallet solution is not canonical")
    return expected, canonical


def validate_standard_payment(decoded: DecodedOffer, *, asset_id: bytes32 | None) -> None:
    if len(decoded.real_spends) != 1:
        raise ValueError("payment requires exactly one wallet input")
    spend = decoded.real_spends[0]
    puzzle = Program.from_serialized(spend.puzzle_reveal)
    solution = Program.from_serialized(spend.solution)
    if asset_id is None:
        _standard_inner(puzzle, solution)
        return
    module, arguments = puzzle.uncurry()
    args = proper_list(arguments, 3)
    if (module != CAT_MOD or len(args) != 3
            or args[0] != Program.to(CAT_MOD.get_tree_hash())
            or args[1] != Program.to(asset_id)):
        raise ValueError("payment CAT must match the authorized asset")
    fields = proper_list(solution, 7)
    if len(fields) != 7:
        raise ValueError("payment CAT solution must contain seven fields")
    inner, inner_solution = _standard_inner(args[2], fields[0])
    if bytes(puzzle) != bytes(construct_cat_puzzle(CAT_MOD, asset_id, inner)):
        raise ValueError("payment CAT puzzle is not canonical")
    lineage = proper_list(fields[1], 3)
    if len(lineage) != 3:
        raise ValueError("payment CAT requires complete parent lineage")
    parent = bytes32(lineage[0].as_atom())
    parent_inner_hash = bytes32(lineage[1].as_atom())
    amount = lineage[2].as_int()
    if not 0 < amount < 2**64:
        raise ValueError("invalid payment CAT parent amount")
    parent_hash = construct_cat_puzzle(
        CAT_MOD, asset_id, parent_inner_hash,
    ).get_tree_hash_precalc(parent_inner_hash)
    if Coin(parent, parent_hash, uint64(amount)).name() != spend.coin.parent_coin_info:
        raise ValueError("payment CAT lineage does not match its parent")
    expected_solution = Program.to([
        inner_solution, [parent, parent_inner_hash, amount], spend.coin.name(),
        [spend.coin.parent_coin_info, spend.coin.puzzle_hash, int(spend.coin.amount)],
        [spend.coin.parent_coin_info, inner.get_tree_hash(), int(spend.coin.amount)],
        0, 0,
    ])
    if bytes(solution) != bytes(expected_solution):
        raise ValueError("payment CAT must use the prepared single-input ring")
