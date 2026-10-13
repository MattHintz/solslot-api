"""Persistent vault registry.

Backed by ``solslot_api.vault_db.VaultStore`` (SQLite + WAL mode).  The
persistence layer survives process restarts, scales to millions of
records via B-tree indexes, and serializes concurrent writers via
SQLite's own file-locking — no application-level lock files, no full-
file rewrites, no JSON parsing on the hot path.

POP-CANON-007 fix (2026-04-26).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from chia_rs.sized_bytes import bytes32

from .vault_db import StoredVault, VaultStore

logger = logging.getLogger(__name__)


@dataclass
class VaultRecord:
    """One registered vault, exposed in the typed shape the API uses.

    This is a thin convenience over ``StoredVault``: ``launcher_id`` and
    the various ``puzhash`` fields are typed as ``bytes32`` for caller
    ergonomics.  Conversion to / from the storage layer's raw ``bytes``
    happens at the registry boundary so the storage layer stays
    independent of chia_rs types.
    """
    launcher_id: bytes32
    full_puzhash: bytes32
    p2_vault_puzhash: bytes32
    auth_type: int
    owner_pubkey: bytes
    owner_evm_address: Optional[str]
    spend_bundle_id: str
    pushed_at: float

    def to_stored(self) -> StoredVault:
        return StoredVault(
            launcher_id=bytes(self.launcher_id),
            full_puzhash=bytes(self.full_puzhash),
            p2_vault_puzhash=bytes(self.p2_vault_puzhash),
            auth_type=int(self.auth_type),
            owner_pubkey=bytes(self.owner_pubkey),
            owner_evm_address=self.owner_evm_address,
            spend_bundle_id=self.spend_bundle_id,
            pushed_at=float(self.pushed_at),
        )

    @classmethod
    def from_stored(cls, s: StoredVault) -> "VaultRecord":
        return cls(
            launcher_id=bytes32(s.launcher_id),
            full_puzhash=bytes32(s.full_puzhash),
            p2_vault_puzhash=bytes32(s.p2_vault_puzhash),
            auth_type=s.auth_type,
            owner_pubkey=s.owner_pubkey,
            owner_evm_address=s.owner_evm_address,
            spend_bundle_id=s.spend_bundle_id,
            pushed_at=s.pushed_at,
        )


class VaultRegistry:
    """Registry keyed by launcher_id with unique owner secondary indexes.

    The registry's full life cycle:
        1. ``open(path)`` to acquire a SQLite-backed store.
        2. ``record(rec)`` to insert / overwrite (idempotent).
        3. ``get(launcher_id)`` / owner lookups for read paths.
        4. ``remove(launcher_id)`` for explicit deregistration.
        5. ``close()`` from the FastAPI lifespan teardown.

    EVM addresses are stored case-insensitively (the underlying index
    uses ``COLLATE NOCASE``), so ``get_by_evm`` accepts any casing the
    caller has on hand without a normalization step.
    """

    def __init__(self, store: VaultStore) -> None:
        self._store = store

    @classmethod
    def open(cls, path: str | Path) -> "VaultRegistry":
        """Open or create a registry at ``path``."""
        return cls(VaultStore(path))

    def record(self, rec: VaultRecord) -> None:
        self._store.upsert(rec.to_stored())
        logger.info(
            "VaultRegistry recorded launcher=0x%s evm=%s spend_bundle=%s",
            rec.launcher_id.hex(),
            rec.owner_evm_address,
            rec.spend_bundle_id,
        )

    def get(self, launcher_id: bytes32) -> Optional[VaultRecord]:
        s = self._store.get_by_launcher(bytes(launcher_id))
        return VaultRecord.from_stored(s) if s else None

    def get_by_evm(self, address: str) -> Optional[VaultRecord]:
        s = self._store.get_by_evm(address)
        return VaultRecord.from_stored(s) if s else None

    def get_by_bls(self, pubkey: bytes) -> Optional[VaultRecord]:
        s = self._store.get_by_bls(bytes(pubkey))
        return VaultRecord.from_stored(s) if s else None

    def remove(self, launcher_id: bytes32) -> bool:
        return self._store.delete(bytes(launcher_id))

    def close(self) -> None:
        self._store.close()

    def __len__(self) -> int:
        return self._store.count()


# ── Process-wide singleton ────────────────────────────────────────────

_registry: Optional[VaultRegistry] = None


def get_registry() -> VaultRegistry:
    """Return the process-wide ``VaultRegistry`` singleton.

    Runtime settings resolve the generation namespace. Importing this module
    does not load settings; tests may still install an isolated memory store.
    """
    global _registry
    if _registry is None:
        from .config import get_settings
        _registry = VaultRegistry.open(get_settings().vault_registry_path)
    return _registry


def reset_registry_for_tests(path: Optional[str | Path] = None) -> VaultRegistry:
    """Replace the process-wide registry with a fresh one.

    Production code must NOT call this.  Pytest fixtures pass a
    ``tmp_path``-managed file (or ``":memory:"`` for ephemeral tests).
    """
    global _registry
    if _registry is not None:
        try:
            _registry.close()
        except Exception:
            pass
    if path is None:
        path = ":memory:"
    _registry = VaultRegistry.open(path)
    return _registry
