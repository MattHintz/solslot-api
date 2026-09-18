"""Validation and chain proof for immutable, funded Sols swap executions."""
from __future__ import annotations

from typing import Any, Mapping

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32


def hx(value: bytes) -> str:
    return "0x" + value.hex()


def validate_execution(
    execution: Mapping[str, Any], *, pool_input_id: str, pool_output_id: str,
) -> SpendBundle:
    """Validate the persisted identity and amounts, never a caller's summary."""
    try:
        if execution["network"] != "testnet11":
            raise ValueError("wrong network")
        if type(execution["feeTargetSeconds"]) is not int or execution["feeTargetSeconds"] <= 0:
            raise ValueError("invalid target")
        for field in ("feeMojos", "backingMojos"):
            value = execution[field]
            if type(value) is not str or not value.isascii() or not value.isdecimal() or str(int(value)) != value:
                raise ValueError("noncanonical amount")
        bundle = SpendBundle.from_json_dict(execution["spendBundle"])
        inputs = [hx(spend.coin.name()) for spend in bundle.coin_spends]
        fee_id = execution["feeCoinId"]
        if (len(inputs) < 2 or len(set(inputs)) != len(inputs)
                or execution["spendBundleId"] != hx(bundle.name())
                or pool_input_id not in inputs or fee_id not in inputs or fee_id == pool_input_id):
            raise ValueError("changed inputs or transaction identity")
        for spend in bundle.coin_spends:
            if Program.from_bytes(bytes(spend.puzzle_reveal)).get_tree_hash() != spend.coin.puzzle_hash:
                raise ValueError("changed puzzle reveal")
        additions = bundle.additions()
        fee = int(execution["feeMojos"])
        if (fee <= 0 or sum(hx(coin.name()) == pool_output_id for coin in additions) != 1
                or sum(int(c.amount) for c in bundle.removals()) - sum(int(c.amount) for c in additions) != fee):
            raise ValueError("changed output or fee")
        funding = next(spend for spend in bundle.coin_spends if hx(spend.coin.name()) == fee_id)
        funding_additions = [coin for coin in additions if coin.parent_coin_info == funding.coin.name()]
        if (sum(int(c.amount) for c in funding_additions) + fee + int(execution["backingMojos"])
                != int(funding.coin.amount)):
            raise ValueError("changed backing")
        return bundle
    except (KeyError, TypeError, ValueError, RuntimeError, StopIteration) as exc:
        raise ValueError("durable Sols swap execution is inconsistent") from exc


def _record_height(raw: Mapping[str, Any], coin: Coin) -> tuple[int, int]:
    created, spent = raw["confirmed_block_index"], raw["spent_block_index"]
    if (type(created) is not int or created <= 0 or type(spent) is not int or spent < 0
            or (spent > 0 and spent < created) or Coin.from_json_dict(raw["coin"]) != coin
            or type(raw["spent"]) is not bool or raw["spent"] != (spent > 0)):
        raise ValueError("inconsistent coin record")
    return created, spent


async def _primary_peak(node: Any) -> tuple[int, bytes32]:
    state = await node.get_blockchain_state_primary()
    try:
        chain = state["blockchain_state"]
        height = chain["peak"]["height"]
        if (state.get("success") is not True or type(height) is not int or height <= 0
                or chain["sync"]["synced"] is not True or chain["sync"]["sync_mode"] is not False):
            raise ValueError("primary node is not synchronized")
        return height, bytes32.fromhex(chain["peak"]["header_hash"].removeprefix("0x"))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Sols swap proof requires a synchronized primary chain anchor") from exc


async def execution_confirmed(node: Any, bundle: SpendBundle, pool_output_id: str) -> bool:
    return await execution_confirmation_height(node, bundle, pool_output_id) is not None


async def execution_confirmation_height(node: Any, bundle: SpendBundle, pool_output_id: str) -> int | None:
    """Prove every retained spend at the pool successor's height on the primary.

    An output alone does not prove that the retained funding was consumed.
    Missing evidence leaves reservations intact. A contradictory spend is an
    explicit reconciliation error, never authority to release another input.
    """
    output = next(coin for coin in bundle.additions() if hx(coin.name()) == pool_output_id)
    peak = await _primary_peak(node)
    raw = await node.get_coin_record_by_name_primary(pool_output_id)
    if raw is None:
        return None
    try:
        height, _ = _record_height(raw, output)
        if height > peak[0]:
            raise ValueError("output is ahead of the primary chain anchor")
        for expected in bundle.coin_spends:
            coin_id = hx(expected.coin.name())
            record = await node.get_coin_record_by_name_primary(coin_id)
            if record is None:
                return None
            _, spent = _record_height(record, expected.coin)
            if not spent:
                return None
            actual = await node.get_puzzle_and_solution_primary(coin_id, spent)
            if actual is None:
                return None
            if spent != height or CoinSpend.from_json_dict(actual) != expected:
                raise ValueError("reserved input was spent by a different transaction")
        # Both a changed output and a different branch retaining the same
        # output/height invalidate the multi-read proof.
        anchor = await node.get_coin_record_by_name_primary(pool_output_id)
        if anchor is None or _record_height(anchor, output)[0] != height:
            return None
        return height if await _primary_peak(node) == peak else None
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise ValueError("Sols swap chain proof is inconsistent; retain funding for reconciliation") from exc
