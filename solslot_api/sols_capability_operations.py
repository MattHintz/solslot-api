"""Durable capability receipts. Wallet hints never establish chain finality."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from time import time
from typing import Any, Mapping


class CapabilityOperationConflict(ValueError):
    pass


class CapabilityOperationStore:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=10)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS capability_operations (
            operation_hash TEXT PRIMARY KEY, vault TEXT NOT NULL,
            binding TEXT NOT NULL, status TEXT NOT NULL, hints TEXT NOT NULL,
            observation TEXT, updated_at INTEGER NOT NULL)""")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS capability_messages (
            replay_key TEXT PRIMARY KEY, operation_hash TEXT NOT NULL)""")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS capability_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, operation_hash TEXT NOT NULL,
            observation TEXT NOT NULL, recorded_at INTEGER NOT NULL)""")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def prepare(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        operation_hash = str(receipt["operationHash"])
        binding = json.dumps(dict(receipt), sort_keys=True, separators=(",", ":"))
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO capability_operations VALUES (?, ?, ?, 'PREPARED', '{}', NULL, ?)",
                (operation_hash, receipt["vaultLauncherId"], binding, int(time())),
            )
            row = self.connection.execute("SELECT binding FROM capability_operations WHERE operation_hash=?", (operation_hash,)).fetchone()
            if row["binding"] != binding:
                raise CapabilityOperationConflict("operation is already bound to different intent evidence")
        return self.get(operation_hash, str(receipt["vaultLauncherId"]))

    def get(self, operation_hash: str, vault: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM capability_operations WHERE operation_hash=? AND lower(vault)=lower(?)",
            (operation_hash, vault),
        ).fetchone()
        if row is None:
            raise KeyError("capability operation not found")
        return {
            "operationHash": row["operation_hash"], "status": row["status"],
            "receipt": json.loads(row["binding"]), "hints": json.loads(row["hints"]),
            "observation": json.loads(row["observation"]) if row["observation"] else None,
            "updatedAt": row["updated_at"],
        }

    def list_for_vault(self, vault: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT operation_hash FROM capability_operations WHERE lower(vault)=lower(?) ORDER BY updated_at DESC LIMIT 100", (vault,)
        ).fetchall()
        return [self.get(row[0], vault) for row in rows]

    def record_hints(self, operation_hash: str, vault: str, hints: Mapping[str, str]) -> dict[str, Any]:
        # References can be amended after a wallet replacement transaction; they
        # are discovery hints only and cannot overwrite an observed receipt.
        allowed = {"sourceTransactionId", "destinationTransactionId"}
        if not hints or not set(hints).issubset(allowed):
            raise ValueError("only source and destination transaction references are accepted")
        for value in hints.values():
            if not isinstance(value, str) or len(value) != 66 or not value.startswith("0x"):
                raise ValueError("transaction reference must be 32-byte hex")
            try:
                bytes.fromhex(value[2:])
            except ValueError as exc:
                raise ValueError("transaction reference must be 32-byte hex") from exc
        with self.connection:
            current = self.get(operation_hash, vault)
            combined = {**current["hints"], **hints}
            submitted = list(current["hints"].get("submittedTransactionIds", []))
            source = hints.get("sourceTransactionId")
            if source and source not in submitted:
                submitted.append(source)
            combined["submittedTransactionIds"] = submitted
            state = "AWAITING_SOURCE" if current["status"] == "PREPARED" else current["status"]
            self.connection.execute(
                "UPDATE capability_operations SET hints=?, status=?, updated_at=? WHERE operation_hash=?",
                (json.dumps(combined, sort_keys=True), state, int(time()), operation_hash),
            )
        return self.get(operation_hash, vault)

    def record_observation(self, operation_hash: str, vault: str, observation: Mapping[str, Any]) -> dict[str, Any]:
        """Trusted observer only; deliberately not exposed as a write endpoint.

        Re-check both chains on every observation, including previously complete
        operations. A reorg or provider outage must not retain a fresh-looking
        completion. Keep the previous proof inside the immutable release ledger.
        """
        if observation.get("status") not in {"AWAITING_SOURCE", "SOURCE_CONFIRMED", "DESTINATION_CONFIRMED", "RECOVERY_REQUIRED", "SOURCE_FAILED", "SOURCE_ASSOCIATION_UNVERIFIED"}:
            raise ValueError("invalid observer status")
        with self.connection:
            current = self.get(operation_hash, vault)
            if observation.get("operationHash") != operation_hash:
                raise CapabilityOperationConflict("observer targets another operation")
            replay_key = observation.get("replayKey")
            if current["receipt"].get("intent", {}).get("direction") == "CHIA_TO_EVM":
                # Defense in depth: no caller, including an observer regression,
                # can claim another vault's public Chia transfer nonce.
                if replay_key or observation["status"] in {"SOURCE_CONFIRMED", "DESTINATION_CONFIRMED"}:
                    raise CapabilityOperationConflict("Chia funding association is unverified; owner confirmation and nonce reservation are disabled")
            if replay_key:
                self.connection.execute("INSERT OR IGNORE INTO capability_messages VALUES (?, ?)", (replay_key, operation_hash))
                owner = self.connection.execute("SELECT operation_hash FROM capability_messages WHERE replay_key=?", (replay_key,)).fetchone()[0]
                if owner != operation_hash:
                    raise CapabilityOperationConflict("source message is already bound to another operation")
            self.connection.execute(
                "INSERT INTO capability_observations(operation_hash, observation, recorded_at) VALUES (?, ?, ?)",
                (operation_hash, json.dumps(dict(observation), sort_keys=True), int(time())),
            )
            self.connection.execute(
                "UPDATE capability_operations SET status=?, observation=?, updated_at=? WHERE operation_hash=?",
                (observation["status"], json.dumps(dict(observation), sort_keys=True), int(time()), operation_hash),
            )
        return self.get(operation_hash, vault)
