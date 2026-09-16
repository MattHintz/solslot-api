"""Faucet UTXO consolidation worker.

POP-CANON-008 fix (2026-04-26): the API faucet creates a change UTXO at
its own puzzle hash on every successful registration.  Without
consolidation the unspent UTXO count grows monotonically; ``select_coin``
fetches and sorts ALL of them on every registration, giving O(N log N)
per-registration cost and O(N²·log N) cumulative.  Coinset.org's response
size also grows with N.

This worker periodically merges all unspent faucet UTXOs into a single
output, restoring the faucet to a single-UTXO state.  The pattern follows
Chia's ``pool_wallet.claim_pool_rewards`` (``chia/pools/pool_wallet.py``):
a parametric "combine N small UTXOs into one larger one" routine that
runs as a background task and gracefully handles concurrency.

Concurrency model
-----------------
The worker spends ALL currently-unspent faucet coins; an in-flight
registration that selected one of those same coins will produce a
mempool conflict.  Two mitigations apply:

1. **Threshold gating**: by default the worker only acts when the
   unspent count exceeds ``FaucetConsolidationConfig.threshold``.  Below
   threshold the registration cost is acceptable and the conflict
   surface is small.

2. **Optimistic semantics**: a conflict from coinset.org surfaces to
   the user as the existing ``push_tx`` 503 path, prompting a retry.
   The worker never blocks registrations behind a lock — that would
   negate the throughput goal.

A future iteration can add an in-process "in-flight coin id" set
(mirroring Chia's ``unconfirmed_removals``) to eliminate the conflict
window entirely.  The audit only requires bounding the cumulative cost,
which threshold-gated consolidation does.

Default configuration
---------------------
``enabled=False``: opt-in.  Operators must set
``SOLSLOT_FAUCET_CONSOLIDATION_ENABLED=true`` to start the background
task.  This keeps the testnet smoke-test surface unchanged until the
operator has had a chance to verify behaviour against their own faucet.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

if TYPE_CHECKING:
    from .coinset_client import CoinsetClient
    from .faucet import Faucet

logger = logging.getLogger(__name__)


# Chialisp condition opcodes (subset).
_CREATE_COIN = 51
_RESERVE_FEE = 52


@dataclass(frozen=True)
class FaucetConsolidationConfig:
    """Tunable parameters for the consolidation worker.

    Defaults are conservative — the worker is disabled, runs every 10
    minutes when enabled, and only acts when the faucet has more than 50
    unspent UTXOs (well above the threshold at which O(N log N) per-
    registration cost is meaningful)."""
    enabled: bool = False
    threshold: int = 50
    interval_seconds: float = 600.0
    fee: int = 0
    # Maximum coins to consolidate in a single bundle.  Chia's mempool
    # caps spends per block at MAX_SPENDS_PER_BLOCK = 6000; we stay well
    # below to leave headroom and keep CLVM cost reasonable.
    max_inputs_per_run: int = 500


class FaucetConsolidationWorker:
    """Background task that periodically consolidates faucet UTXOs.

    Lifecycle owned by the FastAPI ``lifespan``: ``start()`` schedules a
    background ``asyncio.Task``, ``stop()`` signals it to exit and awaits
    completion.  ``consolidate_now()`` is the unit-testable core — it
    builds the spend bundle, pushes it, and returns the result; it does
    NOT loop or sleep.

    The bundle structure mirrors Chia's standard "join coins" pattern:

      - Coin 0 (the consolidator) emits ``CREATE_COIN(faucet_puzhash, sum)``.
      - Coins 1..N have empty conditions; their amount flows to coin 0
        via mempool value conservation (sum of inputs == sum of outputs +
        fee).
      - Each input is signed individually with the synthetic-sig path of
        ``p2_delegated_puzzle_or_hidden_puzzle``; signatures are
        aggregated into a single G2 point.

    Atomicity is guaranteed by the aggregated signature: any attempt to
    split the bundle invalidates the signature.
    """

    def __init__(
        self,
        faucet: "Faucet",
        coinset: "CoinsetClient",
        config: FaucetConsolidationConfig = FaucetConsolidationConfig(),
    ) -> None:
        self.faucet = faucet
        self.coinset = coinset
        self.config = config
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    # ── Lifecycle ───────────────────────────────────────────────────

    async def start(self) -> None:
        """Schedule the background loop.  No-op if disabled or already running."""
        if not self.config.enabled:
            logger.info("FaucetConsolidationWorker disabled; not starting")
            return
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(
            self._run_forever(), name="solslot-faucet-consolidator"
        )
        logger.info(
            "FaucetConsolidationWorker started; interval=%ss threshold=%d",
            self.config.interval_seconds, self.config.threshold,
        )

    async def stop(self) -> None:
        """Signal the loop to exit and await it."""
        self._stop.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run_forever(self) -> None:
        """Main loop: ``maybe_consolidate`` then sleep ``interval_seconds``."""
        while not self._stop.is_set():
            try:
                await self.maybe_consolidate()
            except Exception as e:
                logger.exception("consolidation iteration failed: %s", e)
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self.config.interval_seconds
                )
            except asyncio.TimeoutError:
                pass

    # ── Core ────────────────────────────────────────────────────────

    async def maybe_consolidate(self) -> Optional[dict[str, Any]]:
        """If the faucet's unspent count exceeds threshold, consolidate.

        Returns the ``push_tx`` response on success, or None when the
        threshold gate prevents action.

        Raises only when network / signing errors occur — the caller
        (``_run_forever``) catches and logs.
        """
        self.faucet.require_spend_purpose("faucet-consolidation")
        records = await self.coinset.get_coin_records_by_puzzle_hash(
            "0x" + self.faucet.address_puzzle_hash.hex(), include_spent=False
        )
        reserved = self.faucet.reserved_coin_ids()
        unspent = [r for r in records if r.get("spent_block_index") in (0, None)
                   and _record_coin(r).name() not in reserved]

        if len(unspent) < self.config.threshold:
            logger.debug(
                "consolidation skipped: %d unspent < threshold %d",
                len(unspent), self.config.threshold,
            )
            return None

        # Cap the bundle size; if the faucet has more than max_inputs_per_run
        # coins, this run reduces the count by max_inputs_per_run - 1
        # (consumes max, produces 1 change → net (max - 1) reduction).
        # Subsequent runs handle the remainder.
        chunk = unspent[: self.config.max_inputs_per_run]

        bundle = self._build_consolidation_bundle(chunk, fee=self.config.fee)
        if bundle is None:
            return None

        push_response = await self.coinset.push_tx(_bundle_to_json(bundle))
        if push_response.get("success"):
            logger.info(
                "consolidation pushed: merged %d UTXOs into 1, total=%d",
                len(chunk),
                sum(int((r.get("coin") or r)["amount"]) for r in chunk) - self.config.fee,
            )
        else:
            logger.warning(
                "consolidation push_tx not successful: %s",
                push_response.get("status") or push_response.get("error") or push_response,
            )
        return push_response

    # ── Spend bundle construction ──────────────────────────────────

    def _build_consolidation_bundle(
        self, records: list[dict[str, Any]], *, fee: int
    ) -> Optional[SpendBundle]:
        """Build a signed SpendBundle that joins all ``records`` into one
        output at the faucet's own puzhash.

        Returns None if ``records`` is empty, has only one coin (nothing
        to consolidate), or the total minus fee is non-positive.
        """
        self.faucet.require_spend_purpose("faucet-consolidation")
        if len(records) < 2:
            return None

        coins = [_record_coin(rec) for rec in records]

        total = sum(int(c.amount) for c in coins) - fee
        if total <= 0:
            logger.warning("consolidation aborted: total amount %d after fee", total)
            return None

        # Sort by amount descending so the consolidator (coin 0) is the
        # largest — minimises the chance of the consolidator being
        # selected by an in-flight registration (which picks SMALLEST).
        coins.sort(key=lambda c: int(c.amount), reverse=True)

        coin_spends = []
        sigs: list[G2Element] = []

        for i, coin in enumerate(coins):
            if i == 0:
                # The consolidator: CREATE_COIN(faucet_puzhash, total).
                conditions_list: list[Program] = [
                    Program.to([_CREATE_COIN, self.faucet.address_puzzle_hash, total])
                ]
                if fee > 0:
                    conditions_list.append(Program.to([_RESERVE_FEE, fee]))
                conditions = Program.to(conditions_list)
            else:
                # Junior coins: empty conditions; amount flows to the
                # consolidator via mempool value conservation.
                conditions = Program.to([])

            # Standard p2_delegated solution:
            #   (original_public_key_or_zero  delegated_puzzle  delegated_solution)
            # Passing 0 selects the synthetic-sig path which the puzzle
            # auto-signs over sha256tree(delegated_puzzle).
            delegated_puzzle = Program.to((1, conditions))
            delegated_solution = Program.to(0)
            solution = Program.to([0, delegated_puzzle, delegated_solution])
            coin_spends.append(make_spend(coin, self.faucet.key.puzzle, solution))

            # AGG_SIG_ME message:
            #   sha256tree(delegated_puzzle) || coin.name() || network_data
            sigs.append(G2Element.from_bytes(self.faucet.sign_delegated_spend(
                coin, conditions, purpose="faucet-consolidation",
            )))

        aggregated = AugSchemeMPL.aggregate(sigs)
        return SpendBundle(coin_spends, aggregated)


# ── helpers ─────────────────────────────────────────────────────────

def _record_coin(record: dict[str, Any]) -> Coin:
    payload = record.get("coin") or record
    return Coin(_b32(payload["parent_coin_info"]), _b32(payload["puzzle_hash"]), uint64(int(payload["amount"])))


def _b32(h: str) -> bytes32:
    clean = h[2:] if h.startswith("0x") else h
    return bytes32.fromhex(clean)


def _bundle_to_json(bundle: SpendBundle) -> dict[str, Any]:
    if hasattr(bundle, "to_json_dict"):
        return bundle.to_json_dict()  # type: ignore[no-any-return]
    raise TypeError(f"Cannot serialize bundle of type {type(bundle)}")


__all__ = [
    "FaucetConsolidationConfig",
    "FaucetConsolidationWorker",
]
