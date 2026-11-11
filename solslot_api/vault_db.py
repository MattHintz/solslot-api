"""SQLite-backed vault registry storage.

Purpose-built persistence for ``VaultRegistry``.  Not a generic key-value
store — this module knows about the vault schema directly, which keeps
the abstraction surface narrow and lets the schema enforce invariants
the application would otherwise have to police in Python.

Why SQLite + WAL instead of a JSON file:

  * **Concurrency**: WAL mode (``PRAGMA journal_mode=WAL``) lets readers
    proceed in parallel with a single writer.  No global mutex; no
    poll-spin lock files; no head-of-line blocking when one request is
    mid-write.
  * **I/O scaling**: an UPDATE rewrites only the changed pages.  With
    10 000 registered vaults a single update touches ≈ 4 KB of disk;
    the equivalent JSON-file approach rewrites the entire file
    (potentially megabytes) on every change.
  * **Indexed reverse lookup**: owner identities are real B-tree indexes;
    lookup is O(log N) regardless of registry size.  A JSON dict needs
    a parallel reverse index that the application has to keep in sync,
    introducing a class of consistency bugs we sidestep entirely.
  * **Crash safety**: WAL replay on open reconstructs any in-flight
    transaction.  No corrupt-file recovery branch needed; SQLite handles
    torn writes, kernel panics, and full-disk events at the storage
    layer.
  * **Schema versioning**: ``PRAGMA user_version`` plus an in-module
    migration table makes future changes routine instead of risky.
  * **Foreign data**: pure stdlib (``sqlite3``) — zero new dependencies.

Concurrency model
-----------------
A single ``VaultStore`` instance serializes its own writes via the
internal ``threading.Lock`` (because ``sqlite3.Connection`` objects
themselves aren't thread-safe by default).  Cross-process writers
serialize via SQLite's own file locking, which uses ``fcntl`` /
``LockFileEx`` rather than a sidecar lock file.  Cross-process readers
never block.

For the FastAPI use case (single-process async event loop) the
threading lock is uncontended; it's defensive cover for tests and for
future multi-worker deployments.
"""
from __future__ import annotations

from .generation_storage import connect_generation_sqlite

import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)


# Bumping this triggers ``_migrate`` on next ``VaultStore`` open.
SCHEMA_VERSION = 2

AUTH_TYPE_BLS = 1


@dataclass(frozen=True)
class StoredVault:
    """One row of the ``vaults`` table — wire-friendly, no chia_rs types.

    Bytes are stored as raw ``BLOB`` (32-byte launcher_id, full_puzhash,
    etc.); the caller converts to ``bytes32`` on the way out.
    """
    launcher_id: bytes
    full_puzhash: bytes
    p2_vault_puzhash: bytes
    auth_type: int
    owner_pubkey: bytes
    owner_evm_address: Optional[str]
    spend_bundle_id: str
    pushed_at: float


class VaultStore:
    """SQLite-backed persistent store for vault records.

    Open one instance per process.  ``close()`` is idempotent and
    automatically called at interpreter shutdown by the GC, but explicit
    ``.close()`` from the FastAPI lifespan teardown is recommended.

    Args:
        path: filesystem path to the database file.  Parent directories
            are created if missing.  The special value ``":memory:"``
            yields an in-process ephemeral database (useful for tests).
        timeout: ``connect_generation_sqlite(timeout=...)`` — how long the
            connection waits when another process holds an exclusive
            lock.  Five seconds is generous for the registry's write
            volume.

    Thread safety:
        ``VaultStore`` may be used from multiple threads concurrently;
        a re-entrant lock around every public method serializes access
        to the underlying connection.  For asyncio code this is a
        non-blocking guard since the event loop yields between awaits.
    """

    def __init__(self, path: str | Path, timeout: float = 5.0) -> None:
        self.path = str(path) if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        # ``check_same_thread=False`` is safe because we serialize via
        # ``self._lock``; SQLite itself is fine with cross-thread access
        # so long as concurrent operations are externally coordinated.
        self._conn = connect_generation_sqlite(
            self.path,
            timeout=timeout,
            isolation_level=None,            # explicit transactions
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()

        self._configure_pragmas()
        self._migrate()
        logger.info("VaultStore opened at %s (schema_version=%d)", self.path, SCHEMA_VERSION)

    # ── connection setup ───────────────────────────────────────────

    def _configure_pragmas(self) -> None:
        """Apply pragmas that govern durability + concurrency.

        WAL is the headline change vs the rollback journal: readers and
        a single writer proceed concurrently because the writer appends
        to a side log instead of mutating the main file in place.

        ``synchronous=NORMAL`` is the WAL-mode sweet spot: durable
        across process crashes (because WAL replay reconstructs the
        last committed transaction), with substantially fewer fsync
        calls than ``FULL``.  We accept that an OS-level power-loss
        could lose the last few transactions; that's acceptable for the
        registry's role (the chain is the source of truth, the registry
        is a discovery accelerator).
        """
        cur = self._conn.cursor()
        # In-memory databases don't support WAL.
        if self.path != ":memory:":
            cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA temp_store=MEMORY")

    def _migrate(self) -> None:
        """Apply schema migrations up to ``SCHEMA_VERSION``.

        Each ``_migrate_to_vN`` runs in its own transaction so a
        partial upgrade rolls back cleanly.  Adding a new version is a
        matter of:

          1. bump ``SCHEMA_VERSION``,
          2. add a ``_migrate_to_vN`` method,
          3. extend the dispatch loop below.
        """
        with self._lock, self._txn() as cur:
            current = cur.execute("PRAGMA user_version").fetchone()[0]
            if current >= SCHEMA_VERSION:
                return
            for v in range(current + 1, SCHEMA_VERSION + 1):
                method = getattr(self, f"_migrate_to_v{v}")
                method(cur)
                cur.execute(f"PRAGMA user_version = {v}")
                logger.info("VaultStore migrated to schema v%d", v)

    def _migrate_to_v1(self, cur: sqlite3.Cursor) -> None:
        """Initial schema: one ``vaults`` table with EVM reverse index."""
        cur.execute("""
            CREATE TABLE vaults (
                launcher_id        BLOB    PRIMARY KEY NOT NULL,
                full_puzhash       BLOB    NOT NULL,
                p2_vault_puzhash   BLOB    NOT NULL,
                auth_type          INTEGER NOT NULL,
                owner_pubkey       BLOB    NOT NULL,
                owner_evm_address  TEXT,
                spend_bundle_id    TEXT    NOT NULL,
                pushed_at          REAL    NOT NULL,
                CHECK (length(launcher_id)      = 32),
                CHECK (length(full_puzhash)     = 32),
                CHECK (length(p2_vault_puzhash) = 32),
                CHECK (auth_type IN (1, 2, 3))
            )
        """)
        # Partial index: only rows that actually carry an EVM address
        # consume index space.  COLLATE NOCASE makes the reverse lookup
        # case-insensitive without needing a second normalization step.
        cur.execute("""
            CREATE UNIQUE INDEX idx_vaults_evm
                ON vaults (owner_evm_address COLLATE NOCASE)
                WHERE owner_evm_address IS NOT NULL
        """)

    def _migrate_to_v2(self, cur: sqlite3.Cursor) -> None:
        """Add Chia BLS owner uniqueness for one-vault-per-owner parity."""
        cur.execute(
            """
            CREATE UNIQUE INDEX idx_vaults_bls_owner_pubkey
                ON vaults (owner_pubkey)
                WHERE auth_type = 1
            """
        )

    # ── transaction helper ─────────────────────────────────────────

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Cursor]:
        """Yield a cursor inside a transaction; commit on success, rollback on error.

        ``isolation_level=None`` disables the sqlite3 module's autocommit
        magic; we use explicit BEGIN/COMMIT here.  ``BEGIN IMMEDIATE``
        acquires the reserved lock right away — preferable for writers
        because it eliminates the deferred-promotion deadlock risk when
        multiple writers race for the same row.
        """
        cur = self._conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        finally:
            cur.close()

    # ── public API ─────────────────────────────────────────────────

    def upsert(self, rec: StoredVault) -> None:
        """Insert or replace a vault record.

        Uses ``INSERT ... ON CONFLICT(launcher_id) DO UPDATE`` so callers
        don't need to know whether a record already exists.  The unique
        constraints on owner identities mean re-using an EVM address or
        Chia BLS pubkey with a *different* launcher_id will fail loudly —
        that situation is a programming error (one owner key cannot own
        two vaults under different launcher IDs).
        """
        with self._lock, self._txn() as cur:
            cur.execute(
                """
                INSERT INTO vaults (
                    launcher_id, full_puzhash, p2_vault_puzhash,
                    auth_type, owner_pubkey, owner_evm_address,
                    spend_bundle_id, pushed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(launcher_id) DO UPDATE SET
                    full_puzhash      = excluded.full_puzhash,
                    p2_vault_puzhash  = excluded.p2_vault_puzhash,
                    auth_type         = excluded.auth_type,
                    owner_pubkey      = excluded.owner_pubkey,
                    owner_evm_address = excluded.owner_evm_address,
                    spend_bundle_id   = excluded.spend_bundle_id,
                    pushed_at         = excluded.pushed_at
                """,
                (
                    rec.launcher_id,
                    rec.full_puzhash,
                    rec.p2_vault_puzhash,
                    rec.auth_type,
                    rec.owner_pubkey,
                    rec.owner_evm_address,
                    rec.spend_bundle_id,
                    rec.pushed_at,
                ),
            )

    def get_by_launcher(self, launcher_id: bytes) -> Optional[StoredVault]:
        """Return the row with the given ``launcher_id`` or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vaults WHERE launcher_id = ?", (launcher_id,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def get_by_evm(self, address: str) -> Optional[StoredVault]:
        """Return the row whose ``owner_evm_address`` matches (case-insensitive).

        Hits the ``idx_vaults_evm`` partial index — lookup is O(log N)
        regardless of how many rows the table holds.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vaults WHERE owner_evm_address = ? COLLATE NOCASE",
                (address,),
            ).fetchone()
        return _row_to_record(row) if row else None

    def get_by_bls(self, pubkey: bytes) -> Optional[StoredVault]:
        """Return the BLS-owned row for ``pubkey`` or None.

        Hits the ``idx_vaults_bls_owner_pubkey`` partial index, matching
        the EVM registration invariant for Chia vault owners.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vaults WHERE auth_type = ? AND owner_pubkey = ?",
                (AUTH_TYPE_BLS, bytes(pubkey)),
            ).fetchone()
        return _row_to_record(row) if row else None

    def delete(self, launcher_id: bytes) -> bool:
        """Remove the row by ``launcher_id``.  Returns True if a row was deleted."""
        with self._lock, self._txn() as cur:
            cur.execute("DELETE FROM vaults WHERE launcher_id = ?", (launcher_id,))
            return cur.rowcount > 0

    def count(self) -> int:
        """Total number of registered vaults."""
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM vaults").fetchone()[0])

    def schema_version(self) -> int:
        """Current ``user_version`` value — exposed for diagnostics + migrations."""
        with self._lock:
            return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def close(self) -> None:
        """Close the SQLite connection.  Idempotent."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.ProgrammingError:
                pass

    def __enter__(self) -> "VaultStore":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


def _row_to_record(row: sqlite3.Row) -> StoredVault:
    return StoredVault(
        launcher_id=bytes(row["launcher_id"]),
        full_puzhash=bytes(row["full_puzhash"]),
        p2_vault_puzhash=bytes(row["p2_vault_puzhash"]),
        auth_type=int(row["auth_type"]),
        owner_pubkey=bytes(row["owner_pubkey"]),
        owner_evm_address=row["owner_evm_address"],
        spend_bundle_id=str(row["spend_bundle_id"]),
        pushed_at=float(row["pushed_at"]),
    )


__all__ = ["StoredVault", "VaultStore", "SCHEMA_VERSION"]
