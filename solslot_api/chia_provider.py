"""Primary Chia full-node provider with a fail-closed Coinset fallback."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Optional, TypeVar
from urllib.parse import urlsplit
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from .coinset_client import CoinsetClient

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ChiaProviderError(RuntimeError):
    """Raised when neither configured Chia provider can serve an operation."""


@dataclass(frozen=True)
class ChiaProviderConfig:
    network: str
    primary_url: str | None
    fallback_url: str
    timeout_seconds: float = 20.0
    primary_retry_count: int = 1
    recovery_probe_seconds: float = 30.0
    primary_required: bool = False
    primary_ca_cert_path: str | None = None
    primary_client_cert_path: str | None = None
    primary_client_key_path: str | None = None
    submission_journal_path: str | None = None
    submission_retry_count: int = 0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_origin(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{host}{port}"


def _primary_ssl_context(config: ChiaProviderConfig) -> ssl.SSLContext | None:
    paths = (
        config.primary_ca_cert_path,
        config.primary_client_cert_path,
        config.primary_client_key_path,
    )
    if not any(paths):
        return None
    if not all(paths):
        raise ChiaProviderError(
            "Chia primary mTLS requires CA, client certificate, and client key paths"
        )
    ca_path, cert_path, key_path = (Path(str(value)) for value in paths)
    for label, path in (
        ("CA certificate", ca_path),
        ("client certificate", cert_path),
        ("client key", key_path),
    ):
        if not path.is_file():
            raise ChiaProviderError(f"Chia primary {label} is unavailable: {path}")
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    hostname = urlsplit(config.primary_url or "").hostname or ""
    try:
        is_loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = hostname == "localhost"
    if is_loopback:
        # Chia's private full-node certificate is CA-authenticated but is not
        # normally issued for 127.0.0.1. Keep certificate-chain validation and
        # mTLS while allowing the same-host loopback RPC endpoint.
        context.check_hostname = False
    return context


class ChiaProvider:
    """Serve Chia RPC calls from a local full node before using Coinset.

    Read failures open a circuit and move traffic to the fallback. Recovery
    requires a successful network and sync probe. An ambiguous primary
    ``push_tx`` is checked for mempool propagation before the exact bundle is
    submitted once to the fallback.
    """

    def __init__(
        self,
        primary: CoinsetClient | None,
        fallback: CoinsetClient,
        config: ChiaProviderConfig,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self.config = config
        self._monotonic = monotonic
        self._fallback_active = primary is None
        self._last_probe_monotonic: float | None = None
        self._last_primary_failure_at: str | None = None
        self._last_primary_success_at: str | None = None
        self._last_primary_error: str | None = (
            "primary provider is not configured" if primary is None else None
        )
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self.primary is None:
            if self.config.primary_required:
                raise ChiaProviderError("SOLSLOT_CHIA_PRIMARY_REQUIRED needs a primary URL")
            return
        healthy = await self._probe_primary()
        if not healthy and self.config.primary_required:
            raise ChiaProviderError(
                "required Chia primary failed startup validation: "
                f"{self._last_primary_error or 'unknown error'}"
            )

    async def close(self) -> None:
        clients = [self.fallback]
        if self.primary is not None:
            clients.insert(0, self.primary)
        await asyncio.gather(*(client.close() for client in clients))

    async def _probe_primary(self) -> bool:
        if self.primary is None:
            return False
        self._last_probe_monotonic = self._monotonic()
        try:
            network_info = await self.primary.get_network_info()
            network_name = str(network_info.get("network_name") or "")
            if network_name != self.config.network:
                raise ChiaProviderError(
                    f"network mismatch: expected {self.config.network}, got {network_name or 'unknown'}"
                )
            state = await self.primary.get_blockchain_state()
            blockchain_state = state.get("blockchain_state") or {}
            sync = blockchain_state.get("sync") or {}
            if not sync.get("synced"):
                raise ChiaProviderError("primary full node is not synced")
            if not blockchain_state.get("peak"):
                raise ChiaProviderError("primary full node has no peak")
        except Exception as exc:
            await self._mark_primary_failure("health probe", exc)
            return False
        async with self._lock:
            self._fallback_active = False
            self._last_primary_success_at = _utc_now()
            self._last_primary_error = None
        return True

    async def _primary_available(self) -> bool:
        if self.primary is None:
            return False
        now = self._monotonic()
        probe_due = (
            self._last_probe_monotonic is None
            or now - self._last_probe_monotonic >= self.config.recovery_probe_seconds
        )
        if self._fallback_active or probe_due:
            if not probe_due:
                return False
            return await self._probe_primary()
        return True

    async def _mark_primary_failure(self, operation: str, exc: Exception) -> None:
        async with self._lock:
            self._fallback_active = True
            self._last_probe_monotonic = self._monotonic()
            self._last_primary_failure_at = _utc_now()
            self._last_primary_error = f"{operation}: {exc}"
        logger.warning("Chia primary failed during %s: %s", operation, exc)

    async def _read(
        self,
        operation: str,
        invoke: Callable[[CoinsetClient], Awaitable[T]],
    ) -> T:
        from .chia_snapshot import active_snapshot
        snapshot = active_snapshot()
        if snapshot is not None:
            return await snapshot.read(self, operation, invoke)
        primary_error: Exception | None = None
        if await self._primary_available():
            assert self.primary is not None
            for attempt in range(self.config.primary_retry_count + 1):
                try:
                    result = await invoke(self.primary)
                    self._last_primary_success_at = _utc_now()
                    return result
                except Exception as exc:
                    primary_error = exc
                    if attempt < self.config.primary_retry_count:
                        await asyncio.sleep(min(0.25 * (attempt + 1), 1.0))
            assert primary_error is not None
            await self._mark_primary_failure(operation, primary_error)
        try:
            return await invoke(self.fallback)
        except Exception as fallback_error:
            raise ChiaProviderError(
                f"Chia {operation} failed through primary and fallback: "
                f"primary={primary_error or self._last_primary_error}; "
                f"fallback={fallback_error}"
            ) from fallback_error

    async def _primary_read(
        self,
        operation: str,
        invoke: Callable[[CoinsetClient], Awaitable[T]],
    ) -> T:
        """Read only from the synced local primary; never fall back."""

        from .chia_snapshot import active_snapshot
        snapshot = active_snapshot()
        if snapshot is not None:
            return await snapshot.read(self, operation, invoke)

        if self.primary is None or not await self._primary_available():
            raise ChiaProviderError(
                f"local Chia full node is required for {operation}"
            )
        try:
            result = await invoke(self.primary)
            self._last_primary_success_at = _utc_now()
            return result
        except Exception as exc:
            await self._mark_primary_failure(operation, exc)
            raise ChiaProviderError(
                f"local Chia {operation} failed: {exc}"
            ) from exc

    async def get_blockchain_state(self) -> dict[str, Any]:
        return await self._read(
            "get_blockchain_state", lambda client: client.get_blockchain_state()
        )

    async def get_network_info(self) -> dict[str, Any]:
        return await self._read(
            "get_network_info", lambda client: client.get_network_info()
        )

    async def get_coin_record_by_name(
        self, coin_id: str
    ) -> Optional[dict[str, Any]]:
        return await self._read(
            "get_coin_record_by_name",
            lambda client: client.get_coin_record_by_name(coin_id),
        )

    async def get_coin_record_by_name_primary(
        self, coin_id: str
    ) -> Optional[dict[str, Any]]:
        return await self._primary_read(
            "genesis coin-record proof",
            lambda client: client.get_coin_record_by_name(coin_id),
        )

    async def get_coin_records_by_puzzle_hash(
        self,
        puzzle_hash: str,
        *,
        include_spent: bool = False,
        start_height: int | None = None,
        end_height: int | None = None,
    ) -> list[dict[str, Any]]:
        return await self._read(
            "get_coin_records_by_puzzle_hash",
            lambda client: client.get_coin_records_by_puzzle_hash(
                puzzle_hash,
                include_spent=include_spent,
                start_height=start_height,
                end_height=end_height,
            ),
        )

    async def get_coin_records_by_parent_ids(
        self, parent_ids: list[str], *, include_spent: bool = False
    ) -> list[dict[str, Any]]:
        return await self._read(
            "get_coin_records_by_parent_ids",
            lambda client: client.get_coin_records_by_parent_ids(
                parent_ids, include_spent=include_spent
            ),
        )

    async def get_coin_records_by_puzzle_hashes(
        self,
        puzzle_hashes: list[str],
        *,
        include_spent: bool = False,
        start_height: int | None = None,
        end_height: int | None = None,
    ) -> list[dict[str, Any]]:
        return await self._read(
            "get_coin_records_by_puzzle_hashes",
            lambda client: client.get_coin_records_by_puzzle_hashes(
                puzzle_hashes,
                include_spent=include_spent,
                start_height=start_height,
                end_height=end_height,
            ),
        )

    async def get_coin_records_by_hint(
        self,
        hint: str,
        *,
        include_spent: bool = False,
        start_height: int | None = None,
        end_height: int | None = None,
    ) -> list[dict[str, Any]]:
        return await self._read(
            "get_coin_records_by_hint",
            lambda client: client.get_coin_records_by_hint(
                hint,
                include_spent=include_spent,
                start_height=start_height,
                end_height=end_height,
            ),
        )

    async def get_puzzle_and_solution(
        self, coin_id: str, height: int
    ) -> Optional[dict[str, Any]]:
        return await self._read(
            "get_puzzle_and_solution",
            lambda client: client.get_puzzle_and_solution(coin_id, height),
        )

    async def get_puzzle_and_solution_primary(
        self, coin_id: str, height: int
    ) -> Optional[dict[str, Any]]:
        return await self._primary_read(
            "genesis coin-spend proof",
            lambda client: client.get_puzzle_and_solution(coin_id, height),
        )

    async def get_blockchain_state_primary(self) -> dict[str, Any]:
        return await self._primary_read(
            "genesis peak proof",
            lambda client: client.get_blockchain_state(),
        )

    async def get_mempool_items_by_coin_name(
        self, coin_id: str
    ) -> list[dict[str, Any]]:
        return await self._read(
            "get_mempool_items_by_coin_name",
            lambda client: client.get_mempool_items_by_coin_name(coin_id),
        )

    async def get_fee_estimate(
        self,
        *,
        target_times: list[int],
        spend_bundle: dict[str, Any] | None = None,
        cost: int | None = None,
        require_primary: bool = False,
    ) -> dict[str, Any]:
        """Estimate a complete bundle or a conservative unsigned cost bound."""
        if (spend_bundle is None) == (cost is None):
            raise ValueError("provide exactly one of spend_bundle or cost")
        if cost is not None and (type(cost) is not int or not 0 < cost <= 11_000_000_000):
            raise ValueError("fee estimation cost is outside the consensus bound")
        estimate_args = {"spend_bundle": spend_bundle} if spend_bundle is not None else {"cost": cost}
        from .chia_snapshot import active_snapshot
        snapshot = active_snapshot()
        if snapshot is not None:
            return await snapshot.read(self, "get_fee_estimate", lambda client: client.get_fee_estimate(
                target_times=target_times, **estimate_args,
            ))
        if require_primary:
            if self.primary is None or not await self._primary_available():
                raise ChiaProviderError(
                    "local Chia full node is required for protocol fee estimation"
                )
            try:
                result = await self.primary.get_fee_estimate(
                    target_times=target_times,
                    **estimate_args,
                )
                self._last_primary_success_at = _utc_now()
                return result
            except Exception as exc:
                await self._mark_primary_failure("get_fee_estimate", exc)
                raise ChiaProviderError(
                    f"local Chia fee estimation failed: {exc}"
                ) from exc
        return await self._read(
            "get_fee_estimate",
            lambda client: client.get_fee_estimate(
                target_times=target_times,
                **estimate_args,
            ),
        )

    async def _logged_push(self, client, bundle, provider):
        from .submission_errors import record_submission, error_code
        from chia_rs import SpendBundle
        try:
            bundle_id = "0x" + SpendBundle.from_json_dict(bundle).name().hex()
        except Exception:
            bundle_id = "invalid-bundle"
        def log(event, code=None):
            record_submission(self.config.submission_journal_path, network=self.config.network,
                bundle_id=bundle_id, provider=provider, event=event, code=code, bundle=bundle)
        log("dispatching")
        try:
            result = await client.push_tx(bundle)
        except Exception as exc:
            log("uncertain", error_code(exc))
            raise
        accepted = bool(result.get("success")) or str(result.get("status", "")).upper() in {"SUCCESS","PENDING"}
        log("accepted" if accepted else "rejected", None if accepted else error_code("rejected protocol bundle: " + str(result)))
        return result

    async def push_tx(self, spend_bundle_json: dict[str, Any]) -> dict[str, Any]:
        from .chia_snapshot import active_snapshot
        if active_snapshot() is not None:
            raise ChiaProviderError("swap read snapshots cannot broadcast transactions")
        if await self._primary_available():
            assert self.primary is not None
            try:
                result = await self._logged_push(self.primary, spend_bundle_json, "primary")
                self._last_primary_success_at = _utc_now()
                return result
            except Exception as primary_error:
                await self._mark_primary_failure("push_tx", primary_error)
                if await self._spend_observed(spend_bundle_json):
                    return {
                        "success": True,
                        "status": "PENDING",
                        "already_submitted": True,
                    }
        try:
            return await self._logged_push(self.fallback, spend_bundle_json, "fallback")
        except Exception as fallback_error:
            raise ChiaProviderError(
                "Chia push_tx failed through primary and fallback: "
                f"primary={self._last_primary_error}; fallback={fallback_error}"
            ) from fallback_error

    async def push_tx_confirmed_in_primary_mempool(
        self,
        spend_bundle_json: dict[str, Any],
        *,
        required_coin_id: str,
        required_spend_bundle_id: str | None = None,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> dict[str, Any]:
        """Push locally and require this full node to observe the fee input."""
        from .chia_snapshot import active_snapshot
        if active_snapshot() is not None:
            raise ChiaProviderError("swap read snapshots cannot broadcast transactions")
        normalized_coin_id = _normalize_coin_id(required_coin_id)
        try:
            from chia_rs import SpendBundle

            computed_bundle_id = "0x" + bytes(
                SpendBundle.from_json_dict(spend_bundle_json).name()
            ).hex()
        except Exception as exc:
            raise ChiaProviderError("protocol spend bundle is malformed") from exc
        normalized_bundle_id = _normalize_coin_id(computed_bundle_id)
        if (
            required_spend_bundle_id is not None
            and _normalize_coin_id(required_spend_bundle_id)
            != normalized_bundle_id
        ):
            raise ChiaProviderError(
                "required spend bundle id does not match the submitted bundle"
            )
        if normalized_coin_id not in set(_input_coin_ids(spend_bundle_json)):
            raise ChiaProviderError(
                "mempool confirmation coin is not an input to the spend bundle"
            )
        if self.primary is None or not await self._primary_available():
            raise ChiaProviderError(
                "local Chia full node is required for protocol submission"
            )

        push_result: dict[str, Any] | None = None
        push_error: Exception | None = None
        try:
            push_result = await self._logged_push(self.primary, spend_bundle_json, "primary")
            self._last_primary_success_at = _utc_now()
        except Exception as exc:
            push_error = exc
        else:
            push_status = str(push_result.get("status") or "").upper()
            if not push_result.get("success") and push_status not in {
                "SUCCESS",
                "PENDING",
            }:
                raise ChiaProviderError(
                    f"local Chia node rejected protocol bundle: {push_result}"
                )

        deadline = self._monotonic() + timeout_seconds
        retry_limit = min(2, max(0, self.config.submission_retry_count))
        retries_left = retry_limit
        while True:
            try:
                items = await self.primary.get_mempool_items_by_coin_name(
                    normalized_coin_id
                )
                exact_items = [
                    item
                    for item in items
                    if _mempool_item_matches_bundle(item, normalized_bundle_id)
                ]
                if exact_items:
                    self._last_primary_success_at = _utc_now()
                    return {
                        "success": True,
                        "status": "MEMPOOL",
                        "provider": "local-full-node",
                        "required_coin_id": normalized_coin_id,
                        "push_response": push_result,
                        "ambiguous_push": push_error is not None,
                        "spend_bundle_id": normalized_bundle_id,
                        "observed_at": _utc_now(),
                    }
            except Exception as exc:
                push_error = push_error or exc
            if self._monotonic() >= deadline:
                if retries_left and await self._primary_inputs_clear(spend_bundle_json):
                    retries_left -= 1
                    await asyncio.sleep(2 ** (retry_limit - retries_left - 1))
                    try:
                        push_result = await self._logged_push(self.primary, spend_bundle_json, "primary-retry")
                    except Exception as exc:
                        push_error = exc
                    else:
                        if not push_result.get("success") and str(push_result.get("status", "")).upper() not in {"SUCCESS", "PENDING"}:
                            raise ChiaProviderError(f"local Chia node rejected protocol bundle: {push_result}")
                    deadline = self._monotonic() + timeout_seconds
                    continue
                detail = (
                    f" after ambiguous push ({push_error})" if push_error else ""
                )
                raise ChiaProviderError(
                    "protocol bundle was not observed in the local mempool"
                    f"{detail}"
                )
            await asyncio.sleep(poll_seconds)

    async def observe_exact_protocol_bundle(self, bundle_json):
        """Reconcile saved spends on one synced primary before a resend.

        This is a full-node observation, not an SPV proof. Require every spend,
        including ephemeral inputs, to have its original puzzle and solution in
        the same block. A conflicting spend or changing tip fails closed.
        """
        from chia_rs import SpendBundle, CoinSpend
        bundle = SpendBundle.from_json_dict(bundle_json)
        if not bundle.coin_spends or self.primary is None or not await self._primary_available():
            raise ChiaProviderError("saved protocol submission requires the local Chia full node")
        node = self.primary
        async def peak():
            info = await node.get_network_info()
            state = await node.get_blockchain_state()
            chain = state["blockchain_state"]
            value = chain["peak"]
            if (info.get("network_name") != self.config.network or info.get("success") is not True
                    or state.get("success") is not True or chain["sync"].get("synced") is not True
                    or chain["sync"].get("sync_mode", False) is not False
                    or type(value.get("height")) is not int or value["height"] <= 0):
                raise ChiaProviderError("saved protocol observation requires a synced primary on the exact network")
            return value["height"], _normalize_coin_id(value["header_hash"])
        try:
            initial_peak = await peak()
            bundle_id = "0x" + bundle.name().hex()
            ephemeral = {coin.name() for coin in bundle.additions()}
            persistent = [s for s in bundle.coin_spends if s.coin.name() not in ephemeral]
            if not persistent:
                raise ChiaProviderError("saved protocol bundle has no persistent inputs")
            records = {}
            pending = False
            for spend in persistent:
                coin_id = "0x" + spend.coin.name().hex()
                items = await node.get_mempool_items_by_coin_name(coin_id)
                if any(not _mempool_item_matches_bundle(item, bundle_id) for item in items):
                    raise ChiaProviderError("saved protocol input has a conflicting pending transaction")
                pending = pending or bool(items)
                record = await node.get_coin_record_by_name(coin_id)
                if (not record or Coin.from_json_dict(record["coin"]) != spend.coin
                        or type(record.get("confirmed_block_index")) is not int
                        or not 0 < record["confirmed_block_index"] <= initial_peak[0]
                        or type(record.get("spent_block_index")) is not int
                        or not 0 <= record["spent_block_index"] <= initial_peak[0]):
                    raise ChiaProviderError("saved protocol input is missing or inconsistent")
                records[coin_id] = record
            heights = {r["spent_block_index"] for r in records.values()}
            confirmed_height = None
            if heights != {0}:
                if 0 in heights or len(heights) != 1 or pending:
                    raise ChiaProviderError("saved protocol inputs have inconsistent settlement")
                confirmed_height = next(iter(heights))
                for spend in bundle.coin_spends:
                    coin_id = "0x" + spend.coin.name().hex()
                    record = records.get(coin_id) or await node.get_coin_record_by_name(coin_id)
                    actual = await node.get_puzzle_and_solution(coin_id, confirmed_height)
                    if (not record or Coin.from_json_dict(record["coin"]) != spend.coin
                            or record.get("spent_block_index") != confirmed_height
                            or not actual or CoinSpend.from_json_dict(actual) != spend):
                        raise ChiaProviderError("confirmed spend differs from saved protocol authorization")
            if self.primary is not node or await peak() != initial_peak:
                raise ChiaProviderError("chain changed during saved protocol observation; retry status")
            if not pending and confirmed_height is None:
                return None
            return {"status": "CONFIRMED" if confirmed_height else "MEMPOOL",
                    "provider": "local-full-node", "observed_at": _utc_now(), "ambiguous_push": True,
                    **({"confirmed_height": confirmed_height} if confirmed_height else {})}
        except ChiaProviderError:
            raise
        except Exception as exc:
            raise ChiaProviderError("saved protocol observation is unavailable; original transaction retained") from exc

    async def _primary_inputs_clear(self, bundle):
        if self.primary is None:
            return False
        try:
            from chia_rs import SpendBundle
            parsed = SpendBundle.from_json_dict(bundle)
            ephemeral = {coin.name() for coin in parsed.additions()}
            for coin in parsed.removals():
                if coin.name() in ephemeral:
                    continue
                coin_id = "0x" + coin.name().hex()
                record = await self.primary.get_coin_record_by_name(coin_id)
                if (not record or Coin.from_json_dict(record["coin"]) != coin
                        or not record.get("confirmed_block_index") or record.get("spent_block_index")
                        or await self.primary.get_mempool_items_by_coin_name(coin_id)):
                    return False
            return True
        except Exception:
            return False

    async def _spend_observed(self, spend_bundle_json: dict[str, Any]) -> bool:
        try:
            from chia_rs import SpendBundle

            expected_bundle_id = "0x" + bytes(
                SpendBundle.from_json_dict(spend_bundle_json).name()
            ).hex()
        except Exception:
            return False
        coin_ids = _input_coin_ids(spend_bundle_json)
        if not coin_ids:
            return False
        clients = [client for client in (self.primary, self.fallback) if client]
        for coin_id in coin_ids:
            for client in clients:
                try:
                    items = await client.get_mempool_items_by_coin_name(coin_id)
                    if any(
                        _mempool_item_matches_bundle(item, expected_bundle_id)
                        for item in items
                    ):
                        return True
                except Exception:
                    continue
        return False

    async def refresh_status(self) -> dict[str, Any]:
        await self._primary_available()
        return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "network": self.config.network,
            "activeProvider": (
                "coinset-fallback" if self._fallback_active else "local-full-node"
            ),
            "primaryConfigured": self.primary is not None,
            "primaryRequired": self.config.primary_required,
            "fallbackActive": self._fallback_active,
            "primaryOrigin": _safe_origin(self.config.primary_url),
            "fallbackOrigin": _safe_origin(self.config.fallback_url),
            "lastPrimaryFailureAt": self._last_primary_failure_at,
            "lastPrimarySuccessAt": self._last_primary_success_at,
            "lastPrimaryError": self._last_primary_error,
        }


def _input_coin_ids(spend_bundle_json: dict[str, Any]) -> list[str]:
    coin_spends = spend_bundle_json.get("coin_spends")
    if coin_spends is None:
        coin_spends = spend_bundle_json.get("coinSpends")
    if not isinstance(coin_spends, list):
        return []
    result: list[str] = []
    for coin_spend in coin_spends:
        if not isinstance(coin_spend, dict):
            continue
        coin = coin_spend.get("coin")
        if not isinstance(coin, dict):
            continue
        parent_value = coin.get("parent_coin_info", coin.get("parentCoinInfo"))
        puzzle_value = coin.get("puzzle_hash", coin.get("puzzleHash"))
        try:
            parent = bytes.fromhex(str(parent_value).removeprefix("0x"))
            puzzle_hash = bytes.fromhex(str(puzzle_value).removeprefix("0x"))
            raw_amount = coin["amount"]
            if type(raw_amount) not in (str, int):
                continue
            amount = uint64(int(raw_amount))
        except (KeyError, OverflowError, TypeError, ValueError):
            continue
        if len(parent) != 32 or len(puzzle_hash) != 32:
            continue
        result.append("0x" + Coin(bytes32(parent), bytes32(puzzle_hash), amount).name().hex())
    return result


def _normalize_coin_id(value: str) -> str:
    clean = value.removeprefix("0x").lower()
    if len(clean) != 64:
        raise ChiaProviderError("coin id must be exactly 32 bytes")
    try:
        bytes.fromhex(clean)
    except ValueError as exc:
        raise ChiaProviderError("coin id must be hexadecimal") from exc
    return "0x" + clean


def _mempool_item_matches_bundle(item: Any, expected_bundle_id: str) -> bool:
    if not isinstance(item, Mapping):
        return False
    try:
        normalized_expected = _normalize_coin_id(expected_bundle_id)
    except ChiaProviderError:
        return False
    for key in (
        "spend_bundle_name",
        "spendBundleName",
        "spend_bundle_id",
        "spendBundleId",
        "name",
    ):
        value = item.get(key)
        if not isinstance(value, str):
            continue
        try:
            if _normalize_coin_id(value) == normalized_expected:
                return True
        except ChiaProviderError:
            continue
    return False


def create_chia_provider(config: ChiaProviderConfig) -> ChiaProvider:
    primary: CoinsetClient | None = None
    if config.primary_url:
        primary = CoinsetClient(
            config.primary_url,
            config.timeout_seconds,
            ssl_context=_primary_ssl_context(config),
            provider_label="local-full-node",
        )
    fallback = CoinsetClient(
        config.fallback_url,
        config.timeout_seconds,
        provider_label="coinset-fallback",
    )
    return ChiaProvider(primary, fallback, config)


__all__ = [
    "ChiaProvider",
    "ChiaProviderConfig",
    "ChiaProviderError",
    "create_chia_provider",
]
