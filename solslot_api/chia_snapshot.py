"""Bounded, primary-only observations for a single unsigned transaction review.

This is a trusted full-node observation, not an SPV or consensus-inclusion proof.
The node and API remain observation authorities. General reads retain fallback;
reads inside this scope must use one configured primary and one unchanged peak.
"""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import time
from typing import Any

from chia_rs import Coin
from chia_rs.sized_bytes import bytes32

from .chia_provider import ChiaProvider, ChiaProviderError

MAX_READS = 2048
MAX_READ_BYTES = 16 * 1024 * 1024
SNAPSHOT_TIMEOUT_SECONDS = 60
MAX_PEAK_AGE_SECONDS = 300
MAX_FUTURE_SECONDS = 60
REVIEW_TTL_SECONDS = 60
_active: ContextVar[PrimaryReadSnapshot | None] = ContextVar("chia_read_snapshot", default=None)


def active_snapshot():
    return _active.get()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return "0x" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _hex(value):
    if not isinstance(value, str):
        raise ValueError("missing hash")
    return "0x" + bytes32.from_hexstr(value).hex()


def _review_value(operation, value):
    if operation == 'get_fee_estimate':
        # Only these fields determine the reviewed funding amount. Full-node
        # clock/mempool telemetry changes without changing the quoted fee.
        if not isinstance(value, dict):
            raise ChiaProviderError('primary fee estimate is malformed')
        return {key: value.get(key) for key in ('estimates', 'target_times')}
    return value


class PrimaryReadSnapshot:
    def __init__(self, provider: ChiaProvider, network: str):
        if not isinstance(provider, ChiaProvider) or provider.primary is None:
            raise ChiaProviderError("swap review requires the configured primary full node")
        if network != "testnet11" or provider.config.network != network:
            raise ChiaProviderError("swap snapshot requires the exact Testnet11 network")
        self.provider, self.node, self.network = provider, provider.primary, network
        self.reads: list[tuple[str, Any, str]] = []
        self.rechecks: list[tuple[Any, str]] = []
        self.read_bytes = 0
        self.closed = False
        self.finished = False

    async def __aenter__(self):
        if active_snapshot() is not None:
            raise ChiaProviderError("nested swap snapshots are not permitted")
        self.timeout = asyncio.timeout(SNAPSHOT_TIMEOUT_SECONDS)
        await self.timeout.__aenter__()
        try:
            self.peak = await self._peak()
            self.started_at = int(time.time())
            self.transaction_time = await self._transaction_time()
            self.token = _active.set(self)
            return self
        except BaseException as exc:
            await self._leave_timeout(type(exc), exc, exc.__traceback__)
            raise

    async def __aexit__(self, exc_type, exc, tb):
        self.closed = True
        _active.reset(self.token)
        return await self._leave_timeout(exc_type, exc, tb)

    async def _leave_timeout(self, exc_type, exc, tb):
        try:
            return await self.timeout.__aexit__(exc_type, exc, tb)
        except TimeoutError as exc:
            raise ChiaProviderError("primary swap snapshot timed out") from exc

    def _check(self, provider=None):
        if (self.closed or self.finished or self.provider.primary is not self.node
                or self.provider.config.network != self.network
                or (provider is not None and provider is not self.provider)):
            raise ChiaProviderError("swap snapshot provider or lifecycle changed")

    async def _peak(self):
        self._check()
        info = await self._node_read(lambda: self.node.get_network_info())
        state = await self._node_read(lambda: self.node.get_blockchain_state())
        try:
            chain = state["blockchain_state"]
            peak = chain["peak"]
            height = peak["height"]
            if (info["success"] is not True or info["network_name"] != self.network
                    or state["success"] is not True or chain["sync"]["synced"] is not True
                    or chain["sync"]["sync_mode"] is not False
                    or type(height) is not int or not 0 < height < 2**32):
                raise ValueError("unavailable peak")
            return {"height": height, "headerHash": _hex(peak["header_hash"])}
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ChiaProviderError("swap snapshot requires a synced primary on the exact network") from exc

    async def _transaction_time(self):
        height, digest = self.peak["height"], self.peak["headerHash"]
        for _ in range(128):
            response = await self._node_read(lambda: self.node.get_block_record(digest))
            try:
                block = response["block_record"]
                if (response["success"] is not True or type(block["height"]) is not int
                        or block["height"] != height or _hex(block["header_hash"]) != digest):
                    raise ValueError("wrong ancestor")
                timestamp = block["timestamp"]
                if timestamp is not None:
                    now = int(time.time())
                    if (type(timestamp) is not int or timestamp <= 0
                            or not now - MAX_PEAK_AGE_SECONDS <= timestamp <= now + MAX_FUTURE_SECONDS):
                        raise ValueError("stale or future chain clock")
                    return timestamp
                height -= 1
                digest = _hex(block["prev_hash"])
                if height < 0:
                    raise ValueError("invalid ancestry")
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise ChiaProviderError("swap snapshot lacks a fresh hash-linked transaction clock") from exc
        raise ChiaProviderError("swap snapshot transaction clock exceeds the ancestry bound")

    async def _node_read(self, invoke):
        self._check()
        try:
            result = deepcopy(await invoke())
            if len(_canonical(result).encode()) > MAX_READ_BYTES:
                raise ValueError("oversized primary response")
        except Exception as exc:
            raise ChiaProviderError("swap primary observation is unavailable") from exc
        self._check()
        return result

    async def read(self, provider, operation, invoke):
        self._check(provider)
        if len(self.reads) >= MAX_READS:
            raise ChiaProviderError("swap snapshot exceeds the read bound")
        try:
            result = _review_value(operation, await self._node_read(lambda: invoke(self.node)))
            encoded = _canonical(result)
        except Exception as exc:
            raise ChiaProviderError(f"primary swap snapshot read failed: {operation}") from exc
        self._check(provider)
        self.read_bytes += len(encoded.encode())
        if self.read_bytes > MAX_READ_BYTES:
            raise ChiaProviderError("swap snapshot exceeds the response bound")
        self.reads.append((operation, invoke, encoded))
        return result

    def recheck(self, callback, expected):
        self._check()
        self.rechecks.append((callback, _canonical(expected)))

    async def finish(self, inputs, binding):
        """Recheck the complete read set and every persistent input, including fees."""
        self._check()
        if await self._peak() != self.peak:
            raise ChiaProviderError("chain tip changed during swap review; prepare again")
        # Replay the actual invocations used to derive state, not a separate
        # selection of records which could miss a history or selection query.
        for operation, invoke, expected in tuple(self.reads):
            self._check()
            if _canonical(_review_value(operation, await self._node_read(lambda: invoke(self.node)))) != expected:
                raise ChiaProviderError(f"primary observation changed during swap review: {operation}")
        records = []
        if not 1 <= len(inputs) <= 16 or len({coin.name() for _, coin in inputs}) != len(inputs):
            raise ChiaProviderError("swap snapshot requires distinct persistent inputs")
        for role, coin in inputs:
            raw = await self._node_read(lambda: self.node.get_coin_record_by_name("0x" + coin.name().hex()))
            try:
                created, spent = raw["confirmed_block_index"], raw["spent_block_index"]
                if (type(raw["coin"]["amount"]) is not int or Coin.from_json_dict(raw["coin"]) != coin or type(created) is not int
                        or not 0 < created <= self.peak["height"] or type(spent) is not int or spent != 0
                        or raw.get("spent") is not False):
                    raise ValueError("missing or spent input")
                if await self._node_read(lambda: self.node.get_mempool_items_by_coin_name("0x" + coin.name().hex())):
                    raise ValueError("input has a pending spend")
                records.append({"role": role, "coinId": "0x" + coin.name().hex(),
                    "coin": {"parentCoinInfo": "0x" + coin.parent_coin_info.hex(),
                             "puzzleHash": "0x" + coin.puzzle_hash.hex(), "amount": str(coin.amount)},
                    "confirmedHeight": created, "spentHeight": 0})
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise ChiaProviderError("swap snapshot persistent input is missing, changed or spent") from exc
        if await self._peak() != self.peak:
            raise ChiaProviderError("chain tip changed while sealing swap review; prepare again")
        for callback, expected in self.rechecks:
            if _canonical(callback()) != expected:
                raise ChiaProviderError("swap authority changed while sealing review")
        now = int(time.time())
        if now - self.transaction_time > MAX_PEAK_AGE_SECONDS:
            raise ChiaProviderError("swap snapshot chain clock became stale")
        evidence = {"schemaVersion": 1, "status": "PRIMARY_NODE_OBSERVATION",
            "network": self.network, "authority": "CONFIGURED_PRIMARY_FULL_NODE",
            "consensusInclusionProven": False, "peak": self.peak,
            "transactionTimestamp": self.transaction_time, "observedAt": now,
            "expiresAt": min(now + REVIEW_TTL_SECONDS, binding["quoteExpiresAt"]),
            "inputs": records, "binding": deepcopy(binding),
            "readSetHash": _hash([[op, value] for op, _, value in self.reads])}
        if evidence["expiresAt"] <= now:
            raise ChiaProviderError("swap review expired during observation")
        self.finished = True
        return {**evidence, "snapshotHash": _hash(evidence)}
