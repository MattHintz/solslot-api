"""Append-only, one-active-governance-coin ledger for the KoS signer."""

from __future__ import annotations

from .generation_storage import connect_generation_sqlite

import sqlite3
import threading
import time
from pathlib import Path


SCHEMA_VERSION = 1


class KosMintExecuteLedgerConflict(RuntimeError):
    """A request would make the signer attest to a second governance action."""


class KosMintExecuteLedger:
    """Persist exact retries while refusing a different request for one coin."""

    def __init__(self, path: str | Path, timeout: float = 10.0) -> None:
        self.path = str(path) if path == ":memory:" else str(Path(path))
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = connect_generation_sqlite(
            self.path,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._configure()
        self._migrate()

    def _configure(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA busy_timeout = 10000")
            self._conn.execute("PRAGMA synchronous = FULL")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"KoS signer ledger schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version == SCHEMA_VERSION:
                return
            self._conn.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE mint_execute_signatures (
                    request_hash TEXT PRIMARY KEY,
                    canonical_request TEXT NOT NULL,
                    governance_coin_id TEXT NOT NULL UNIQUE,
                    proposal_hash TEXT NOT NULL,
                    artifact_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signed_at INTEGER NOT NULL
                );
                PRAGMA user_version = 1;
                COMMIT;
                """
            )

    def record_or_recover(
        self,
        *,
        request_hash: str,
        canonical_request: str,
        governance_coin_id: str,
        proposal_hash: str,
        artifact_hash: str,
        signature: str,
    ) -> str:
        """Persist a signature or return an exact idempotent retry.

        A tracker singleton coin can perform at most one successful state
        transition. Refusing a different signature request for that live coin
        gives the isolated signer the same one-action property before the
        chain confirms the spend.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    """
                    SELECT canonical_request, signature
                    FROM mint_execute_signatures
                    WHERE request_hash = ?
                    """,
                    (request_hash,),
                ).fetchone()
                if existing is not None:
                    if existing["canonical_request"] != canonical_request:
                        raise KosMintExecuteLedgerConflict(
                            "KoS request hash collides with different execution evidence."
                        )
                    self._conn.execute("COMMIT")
                    return str(existing["signature"])
                self._conn.execute(
                    """
                    INSERT INTO mint_execute_signatures(
                        request_hash, canonical_request, governance_coin_id,
                        proposal_hash, artifact_hash, signature, signed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_hash,
                        canonical_request,
                        governance_coin_id,
                        proposal_hash,
                        artifact_hash,
                        signature,
                        int(time.time()),
                    ),
                )
                self._conn.execute("COMMIT")
                return signature
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise KosMintExecuteLedgerConflict(
                    "KoS already signed a different request for this governance coin."
                ) from exc
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def healthcheck(self) -> bool:
        with self._lock:
            row = self._conn.execute("PRAGMA quick_check").fetchone()
        return bool(row and row[0] == "ok")

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["KosMintExecuteLedger", "KosMintExecuteLedgerConflict"]
