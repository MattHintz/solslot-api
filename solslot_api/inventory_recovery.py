"""Exact timeout recovery; absence or elapsed local time never frees inventory.

The original signed reservation remains immutable. A release consumes its exact
reserved coin and recreates the governed available singleton. Only confirmed
timeout spends may advance the available-coin cursor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD, lineage_proof_for_coinsol,
)
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v3 import (
    purchase_artifact_v3_from_json, purchase_batch_from_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1, PrimaryMintTermsV3,
    RESERVATION_RELEASE_TIMEOUT_MODE,
    build_inventory_release_spend, build_inventory_reservation_spend,
    deed_launcher_puzzle_hash_from_struct, make_inventory_available_inner,
    inventory_terms_for_puzzle_hash,
    make_mint_offer_v5_inner,
)
from .payment_purchase_store import PaymentPurchaseConflict, PaymentPurchaseStore


MIN_RELEASE_CONFIRMATIONS = 3
MAX_SPEND_BYTES = 256_000


def hx(value: Any) -> str:
    return "0x" + bytes(value).hex()


def record_coin(record: Mapping[str, Any] | None, expected: Coin) -> tuple[int, int]:
    """Bind the RPC record's computed identity and both lifecycle heights."""
    try:
        if not isinstance(record, Mapping):
            raise ValueError("missing record")
        raw = record["coin"]
        if type(raw["amount"]) not in (str, int) or int(raw["amount"]) != 1:
            raise ValueError("invalid amount")
        actual = Coin(bytes32.fromhex(raw["parent_coin_info"].removeprefix("0x")),
                      bytes32.fromhex(raw["puzzle_hash"].removeprefix("0x")), uint64(1))
        confirmed, spent = record["confirmed_block_index"], record["spent_block_index"]
        if type(confirmed) is not int or type(spent) is not int:
            raise ValueError("invalid heights")
        if actual != expected or confirmed <= 0 or spent < 0:
            raise ValueError("inconsistent coin")
        if type(record.get("spent")) is not bool or record["spent"] != (spent > 0):
            raise ValueError("inconsistent spent flag")
        if spent and spent < confirmed:
            raise ValueError("invalid spending height")
        return confirmed, spent
    except (KeyError, TypeError, ValueError) as exc:
        raise PaymentPurchaseConflict("inventory chain record is missing or inconsistent") from exc


def decode_spend(raw: Mapping[str, Any] | None, expected_coin: Coin) -> CoinSpend:
    try:
        if not isinstance(raw, Mapping):
            raise ValueError("missing spend")
        for field in ("puzzle_reveal", "solution"):
            if not isinstance(raw[field], str) or len(raw[field]) > MAX_SPEND_BYTES * 2 + 2:
                raise ValueError("oversized spend")
        spend = CoinSpend.from_json_dict(dict(raw))
        if spend.coin != expected_coin or Program.from_bytes(bytes(spend.puzzle_reveal)).get_tree_hash() != expected_coin.puzzle_hash:
            raise ValueError("spend identity changed")
        return spend
    except (KeyError, TypeError, ValueError) as exc:
        raise PaymentPurchaseConflict("inventory parent spend is missing or inconsistent") from exc


def equivalent_timeout_spend(actual: CoinSpend, expected: CoinSpend) -> bool:
    """Accept the one uncommitted timeout field without loosening any binding.

    V5 size-checks buyer_offer_nonce (inner solution 20) but omits it from
    timeout commitments and conditions. A permissionless releaser may choose
    any 32-byte nonce. Every other field, the puzzle and input stay exact.
    """
    if actual.coin != expected.coin or actual.puzzle_reveal != expected.puzzle_reveal:
        return False
    try:
        solution = Program.from_bytes(bytes(actual.solution)).as_python()
        canonical = Program.from_bytes(bytes(expected.solution)).as_python()
        if (not isinstance(solution, list) or len(solution) != 3
                or not isinstance(solution[2], list) or len(solution[2]) != 32
                or not isinstance(solution[2][20], bytes) or len(solution[2][20]) != 32):
            return False
        solution[2][20] = canonical[2][20]
        return Program.to(solution) == Program.from_bytes(bytes(expected.solution))
    except (IndexError, TypeError, ValueError):
        return False


def timeout_successor_lineage(*, parent_spend: CoinSpend, successor: Coin,
                              deed_struct: Program, terms: PrimaryMintTermsV3):
    """Verify a canonical parent timeout under the same governed immutable terms.

The node must separately prove this parent spend canonical and atomic with the
child. A spent singleton with this exact struct is subject to consensus lineage
checks; matching a puzzle hash on an unspent, unsolicited coin is insufficient.
"""
    try:
        reveal = Program.from_bytes(bytes(parent_spend.puzzle_reveal))
        mod, arguments = reveal.uncurry()
        struct, inner = list(arguments.as_iter())
        inner_mod, inner_args = inner.uncurry()
        args = list(inner_args.as_iter())
        # Compare the immutable prefix by constructing the canonical available
        # puzzle. Available has [self hash, reserved mod hash, immutable args].
        _, available_args = make_inventory_available_inner(terms).uncurry()
        available = list(available_args.as_iter())
        outer_solution = list(Program.from_bytes(bytes(parent_spend.solution)).as_iter())
        control = list(outer_solution[2].as_iter())
        expected = Coin(parent_spend.coin.name(),
                        SINGLETON_MOD.curry(deed_struct, make_inventory_available_inner(terms)).get_tree_hash(),
                        uint64(1))
        if (mod != SINGLETON_MOD or struct != deed_struct
                or inner_mod.get_tree_hash() != bytes32(available[1].as_atom())
                or len(args) != 30 or args[0] != available[1]
                or args[1:22] != available[2:]
                or args[22].as_atom() != bytes(make_inventory_available_inner(terms).get_tree_hash())
                or len(outer_solution) != 3 or len(control) != 32
                or control[21].as_int() != RESERVATION_RELEASE_TIMEOUT_MODE
                or parent_spend.coin.amount != 1 or reveal.get_tree_hash() != parent_spend.coin.puzzle_hash
                or successor != expected):
            raise ValueError("not the governed timeout successor")
        return lineage_proof_for_coinsol(parent_spend)
    except (IndexError, TypeError, ValueError) as exc:
        raise PaymentPurchaseConflict("available inventory lacks canonical timeout lineage") from exc


@dataclass(frozen=True)
class TimeoutItem:
    ordinal: int
    launcher: str
    reservation_spend: CoinSpend
    release_spend: CoinSpend
    successor: Coin


def timeout_items(store: PaymentPurchaseStore, purchase_id: str) -> tuple[TimeoutItem, ...]:
    """Rebuild releases from retained signed reservation evidence, never a quote refresh."""
    stored = store.get(purchase_id)
    rows = store.inventory_items(purchase_id)
    try:
        bundle = WalletSpendBundle.from_json_dict(stored.inventory_bundle or {})
        raw = stored.purchase_artifact
        purchases = (purchase_batch_from_json(raw).artifacts if raw.get("schema") == "solslot.purchase-batch.v1"
                     else (purchase_artifact_v3_from_json(raw),))
        if not rows or len(rows) != len(purchases) or len(rows) != len(bundle.coin_spends):
            raise ValueError("incomplete reservation")
        result = []
        for row, purchase, spend in zip(rows, purchases, bundle.coin_spends, strict=True):
            reveal = Program.from_bytes(bytes(spend.puzzle_reveal))
            mod, arguments = reveal.uncurry()
            struct, inner = list(arguments.as_iter())
            _, arguments = inner.uncurry()
            args = list(arguments.as_iter())
            if len(args) != 23:
                raise ValueError("unsupported inventory puzzle")
            terms = PrimaryMintTermsV3.for_artifact(
                artifact=purchase, smart_deed_inner_hash=bytes32(args[2].as_atom()),
                deed_launcher_puzzle_hash=bytes32(args[6].as_atom()),
                protocol_puzhash=bytes32(args[20].as_atom()),
                validator_pubkeys=tuple(value.as_atom() for value in args[21].as_iter()),
                provider_id=bytes32(args[22].as_atom()),
            )
            terms = inventory_terms_for_puzzle_hash(terms, struct, spend.coin.puzzle_hash)
            if (mod != SINGLETON_MOD or inner != make_inventory_available_inner(terms)
                    or deed_launcher_puzzle_hash_from_struct(struct, purchase.deed_launcher_id) != terms.deed_launcher_puzzle_hash
                    or row.deed_launcher_id != hx(purchase.deed_launcher_id)
                    or row.child_purchase_id != hx(purchase.purchase_id)
                    or row.child_artifact_hash != hx(purchase.artifact_hash)
                    or row.available_coin_id != hx(spend.coin.name())):
                raise ValueError("reservation binding changed")
            reservation = InventoryReservationV1(artifact=purchase, expires_at=stored.inventory_expires_at)
            from chia.wallet.lineage_proof import LineageProof
            solution = list(Program.from_bytes(bytes(spend.solution)).as_iter())
            lineage_raw = list(solution[0].as_iter())
            lineage = (LineageProof(parent_name=bytes32(lineage_raw[0].as_atom()), amount=uint64(lineage_raw[1].as_int()))
                       if len(lineage_raw) == 2 else
                       LineageProof(parent_name=bytes32(lineage_raw[0].as_atom()), inner_puzzle_hash=bytes32(lineage_raw[1].as_atom()), amount=uint64(lineage_raw[2].as_int())))
            original = build_inventory_reservation_spend(available_coin=spend.coin,
                deed_singleton_struct=struct, lineage_proof=lineage, reservation=reservation,
                signer_indices=row.signer_indices, terms=terms)
            if (original.spend != spend or hx(original.reserved_coin.name()) != row.reserved_coin_id
                    or hx(original.reserved_coin.puzzle_hash) != row.reserved_puzzle_hash):
                raise ValueError("original signed reservation differs")
            release = build_inventory_release_spend(reserved_coin=original.reserved_coin,
                deed_singleton_struct=struct, lineage_proof=lineage_proof_for_coinsol(spend),
                reservation=reservation, terms=terms, timed_out=True)
            result.append(TimeoutItem(row.ordinal, row.deed_launcher_id, spend, release.spend, release.next_coin))
        return tuple(result)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise PaymentPurchaseConflict("retained reservation cannot prove exact timeout recovery") from exc


async def release_peak(node: Any, network: str) -> tuple[int, str]:
    info = await node.get_network_info()
    state = await node.get_blockchain_state()
    try:
        chain = state["blockchain_state"]
        peak = chain["peak"]
        if info.get("network_name") != network or info.get("success") is not True or state.get("success") is not True:
            raise ValueError("wrong network")
        if chain["sync"]["synced"] is not True or chain["sync"].get("sync_mode") is not False:
            raise ValueError("node not synced")
        height = peak["height"]
        digest = bytes32.fromhex(peak["header_hash"].removeprefix("0x"))
        if type(height) is not int or height <= 0:
            raise ValueError("invalid peak")
        return height, hx(digest)
    except (KeyError, TypeError, ValueError) as exc:
        raise PaymentPurchaseConflict("inventory recovery requires a synced node on the exact network") from exc


async def reconcile_timeout_release(store: PaymentPurchaseStore, node: Any,
                                    purchase_id: str, network: str):
    stored = store.get(purchase_id)
    if stored.inventory_state == "RELEASED":
        return stored
    items = timeout_items(store, purchase_id)
    if any(p.network != network for p in (purchase_batch_from_json(stored.purchase_artifact).artifacts
           if stored.purchase_artifact.get("schema") == "solslot.purchase-batch.v1"
           else (purchase_artifact_v3_from_json(stored.purchase_artifact),))):
        raise PaymentPurchaseConflict("reservation network differs from recovery network")
    peak = await release_peak(node, network)
    evidence = []
    for item in items:
        reserved = item.release_spend.coin
        reserved_height, spent_height = record_coin(await node.get_coin_record_by_name(hx(reserved.name())), reserved)
        if (stored.inventory_confirmation_height is not None
                and stored.inventory_confirmation_height != reserved_height):
            raise PaymentPurchaseConflict("reservation confirmation changed from its durable receipt")
        if not spent_height or peak[0] - spent_height + 1 < MIN_RELEASE_CONFIRMATIONS:
            raise PaymentPurchaseConflict("timeout release has not reached three confirmations")
        canonical = decode_spend(await node.get_puzzle_and_solution(hx(reserved.name()), spent_height), reserved)
        if not equivalent_timeout_spend(canonical, item.release_spend):
            raise PaymentPurchaseConflict("reserved inventory was not spent by its exact timeout release")
        child_height, child_spent = record_coin(await node.get_coin_record_by_name(hx(item.successor.name())), item.successor)
        if child_height != spent_height or child_spent:
            raise PaymentPurchaseConflict("timeout successor is not atomically confirmed and available")
        # Bind the creation of the reserved input too, including ambiguous
        # PREPARED dispatches which may actually have reached the chain.
        _, source_spent = record_coin(await node.get_coin_record_by_name(hx(item.reservation_spend.coin.name())), item.reservation_spend.coin)
        source = decode_spend(await node.get_puzzle_and_solution(hx(item.reservation_spend.coin.name()), source_spent), item.reservation_spend.coin)
        if source_spent != reserved_height or source != item.reservation_spend:
            raise PaymentPurchaseConflict("reservation confirmation does not match retained signed evidence")
        evidence.append(dict(ordinal=item.ordinal, deedLauncherId=item.launcher,
            reservedCoinId=hx(reserved.name()), availableCoinId=hx(item.successor.name()),
            availablePuzzleHash=hx(item.successor.puzzle_hash), confirmationHeight=spent_height,
            releaseSpend=canonical.to_json_dict()))
    if await release_peak(node, network) != peak:
        raise PaymentPurchaseConflict("chain tip changed during inventory recovery; retry reconciliation")
    return store.record_inventory_released(purchase_id, evidence={
        "schema": "solslot.inventory-timeout-release.v1", "network": network,
        "peakHeight": peak[0], "peakHash": peak[1], "items": evidence,
    })
