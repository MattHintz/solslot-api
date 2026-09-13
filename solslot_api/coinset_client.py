"""Async client for coinset.org's public Chia full-node RPC.

This client performs both read queries (coin records, blockchain state) and
`push_tx` broadcasts for the Solslot portal.  All endpoints return vanilla
JSON — we parse into plain dicts and let the caller shape them further.

API reference: https://docs.coinset.org
"""
from __future__ import annotations

import logging
import ssl
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class CoinsetClient:
    """Thin async wrapper around coinset.org's RPC surface."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 20.0,
        *,
        ssl_context: ssl.SSLContext | None = None,
        provider_label: str = "coinset",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.provider_label = provider_label
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers={"content-type": "application/json"},
            verify=ssl_context if ssl_context is not None else True,
        )

    async def close(self) -> None:
        await self._client.aclose()

    # ── Read queries ─────────────────────────────────────────────────────

    async def get_blockchain_state(self) -> dict[str, Any]:
        """Return `{ blockchain_state: {...}, success: true }`."""
        r = await self._post("/get_blockchain_state", {})
        return r

    async def get_network_info(self) -> dict[str, Any]:
        """Return the full node's configured network name and address prefix."""
        return await self._post("/get_network_info", {})

    async def get_block_record(self, header_hash: str) -> dict[str, Any]:
        """Fetch a specific ancestor for canonical transaction-time proofs."""
        return await self._post("/get_block_record", {"header_hash": _hex0x(header_hash)})

    async def get_coin_record_by_name(self, coin_id: str) -> Optional[dict[str, Any]]:
        """Return a single CoinRecord or None when unconfirmed."""
        r = await self._post(
            "/get_coin_record_by_name",
            {"name": _hex0x(coin_id)},
        )
        return r.get("coin_record")

    async def get_coin_records_by_puzzle_hash(
        self,
        puzzle_hash: str,
        *,
        include_spent: bool = False,
        start_height: Optional[int] = None,
        end_height: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Fetch coin records for a puzzle hash from coinset.org.

        POP-CANON-010 note: the upstream Chia full-node RPC
        ``get_coin_records_by_puzzle_hash`` does NOT accept a row-count
        ``limit`` parameter (verified against
        ``chia/full_node/full_node_rpc_api.py::get_coin_records_by_puzzle_hash``).
        Pagination is by **height range**: callers pass ``start_height`` /
        ``end_height`` to bound the historical scan.  For a busy puzzle
        hash (e.g. the API faucet at scale), callers should track the last
        known activity height locally and pass ``start_height`` to skip
        the historical tail — this is the same pattern Chia's wallet uses
        in ``request_puzzle_state`` (full_node_api.py:1893-1947, with its
        ``min_height`` cursor).

        For now the faucet path (``register_evm_vault`` /
        ``register_chia_vault``) does not pass ``start_height`` and will
        rescan the full faucet history on every call.  POP-CANON-008
        addresses this with a consolidation worker + local UTXO tracking;
        until then the audit-noted O(N log N) per-registration cost stands.
        """
        body: dict[str, Any] = {
            "puzzle_hash": _hex0x(puzzle_hash),
            "include_spent_coins": include_spent,
        }
        if start_height is not None:
            body["start_height"] = start_height
        if end_height is not None:
            body["end_height"] = end_height
        r = await self._post("/get_coin_records_by_puzzle_hash", body)
        records = r.get("coin_records") or []
        # POP-CANON-010 defensive log: warn (don't fail) when the response is
        # large enough to suggest the caller should be using a height cursor.
        # 1000 records is well below coinset's likely server-side cap but high
        # enough that legitimate small-scale use never trips it.
        if len(records) > 1000:
            logger.warning(
                "coinset returned %d records for %s; consider passing start_height "
                "(POP-CANON-010 / POP-CANON-008)",
                len(records),
                puzzle_hash,
            )
        return records

    async def get_coin_records_by_puzzle_hashes(
        self,
        puzzle_hashes: list[str],
        *,
        include_spent: bool = False,
        start_height: Optional[int] = None,
        end_height: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "puzzle_hashes": [_hex0x(value) for value in puzzle_hashes],
            "include_spent_coins": include_spent,
        }
        if start_height is not None:
            body["start_height"] = start_height
        if end_height is not None:
            body["end_height"] = end_height
        r = await self._post("/get_coin_records_by_puzzle_hashes", body)
        return r.get("coin_records") or []

    async def get_coin_records_by_hint(
        self,
        hint: str,
        *,
        include_spent: bool = False,
        start_height: Optional[int] = None,
        end_height: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "hint": _hex0x(hint),
            "include_spent_coins": include_spent,
        }
        if start_height is not None:
            body["start_height"] = start_height
        if end_height is not None:
            body["end_height"] = end_height
        r = await self._post("/get_coin_records_by_hint", body)
        return r.get("coin_records") or []

    async def get_coin_records_by_parent_ids(
        self, parent_ids: list[str], *, include_spent: bool = False
    ) -> list[dict[str, Any]]:
        body = {
            "parent_ids": [_hex0x(p) for p in parent_ids],
            "include_spent_coins": include_spent,
        }
        r = await self._post("/get_coin_records_by_parent_ids", body)
        return r.get("coin_records") or []

    async def get_puzzle_and_solution(
        self, coin_id: str, height: int
    ) -> Optional[dict[str, Any]]:
        body = {"coin_id": _hex0x(coin_id), "height": height}
        r = await self._post("/get_puzzle_and_solution", body)
        return r.get("coin_solution")

    async def get_mempool_items_by_coin_name(
        self, coin_id: str
    ) -> list[dict[str, Any]]:
        """Return mempool items spending one coin.

        Chia's RPC accepts one ``coin_name`` per request. Callers checking a
        multi-input bundle must issue one request for each removal.
        """
        r = await self._post(
            "/get_mempool_items_by_coin_name",
            {"coin_name": _hex0x(coin_id)},
        )
        return r.get("mempool_items") or []

    async def get_fee_estimate(
        self,
        *,
        target_times: list[int],
        spend_bundle: dict[str, Any] | None = None,
        cost: int | None = None,
    ) -> dict[str, Any]:
        """Estimate absolute fees for a spend at the requested target times."""
        if (spend_bundle is None) == (cost is None):
            raise ValueError("provide exactly one of spend_bundle or cost")
        body: dict[str, Any] = {"target_times": list(target_times)}
        if spend_bundle is not None:
            body["spend_bundle"] = spend_bundle
        else:
            body["cost"] = cost
        return await self._post("/get_fee_estimate", body)

    # ── Writes ───────────────────────────────────────────────────────────

    async def push_tx(self, spend_bundle_json: dict[str, Any]) -> dict[str, Any]:
        """Submit a spend bundle.  Returns coinset.org's raw response.

        On success coinset returns `{ status: "SUCCESS", success: true }`.
        On duplicate it returns `{ status: "PENDING" }` which is still fine.
        """
        body = {"spend_bundle": spend_bundle_json}
        r = await self._post("/push_tx", body)
        if not r.get("success"):
            error = r.get("error") or r
            logger.warning("push_tx not successful: %s", error)
        return r

    # ── Internal ─────────────────────────────────────────────────────────

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._client.post(path, json=body)
        except httpx.HTTPError as e:
            logger.exception("%s HTTP error for %s: %s", self.provider_label, path, e)
            raise
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.warning(
                "%s %s returned %d: %s",
                self.provider_label,
                path,
                resp.status_code,
                resp.text[:400],
            )
            raise
        return resp.json()


def _hex0x(s: str) -> str:
    return s if s.startswith("0x") else "0x" + s
