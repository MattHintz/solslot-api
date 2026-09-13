"""Shared eligibility policy for signed genesis credential bridge coins."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-fA-F]{64}", value) is None:
        raise ValueError(f"{field} must be a canonical 32-byte hex string")
    return value.lower()


@dataclass(frozen=True)
class BridgeCoinPolicy:
    policy_hash: str
    parent_ids: frozenset[str]
    coin_ids: frozenset[str]
    permit_version: int | None = None

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> BridgeCoinPolicy:
        # Callers must verify the artifact's signature and runtime binding first.
        bridge = artifact.get("bridgePolicy")
        if not isinstance(bridge, Mapping):
            raise ValueError("artifact bridge policy is missing")
        policy_hash = _hash(bridge.get("policyHash"), "artifact bridge policy hash")
        parents, coins = bridge.get("parentCoinIds"), bridge.get("bridgeCoinIds")
        if not isinstance(parents, list) or not isinstance(coins, list):
            raise ValueError("artifact bridge coin allowlists are missing or malformed")
        from solslot_puzzles.enrollment_activation import activation_from_artifact
        activation = activation_from_artifact(artifact)
        return cls(
            policy_hash,
            frozenset(_hash(value, "artifact bridge parent") for value in parents),
            frozenset(_hash(value, "artifact bridge coin") for value in coins),
            1 if activation is not None else None,
        )

    def require_coin(self, *, policy_hash: str, parent_id: str, amount: int, coin_id: str) -> None:
        if isinstance(amount, bool) or not isinstance(amount, int) or amount != 1:
            raise ValueError("V2 genesis bridge coins must contain exactly one mojo")
        policy_hash = _hash(policy_hash, "bridge policy hash")
        parent_id = _hash(parent_id, "bridge parent")
        coin_id = _hash(coin_id, "bridge coin")
        if policy_hash != self.policy_hash:
            raise ValueError("bridge policy differs from the signed artifact")
        if parent_id not in self.parent_ids or coin_id not in self.coin_ids:
            raise ValueError("bridge lineage is not committed by the signed artifact")
        coin = Coin(bytes32.fromhex(parent_id[2:]), bytes32.fromhex(policy_hash[2:]), uint64(1))
        if "0x" + coin.name().hex() != coin_id:
            raise ValueError("bridge coin fields do not match the signed coin ID")
