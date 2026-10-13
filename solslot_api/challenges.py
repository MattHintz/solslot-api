"""Short-lived challenge store for wallet login.

The backend issues a 32-byte random nonce + an EIP-712 typed data envelope.
The caller (frontend) signs the typed data with the user's wallet and sends
back (address, nonce, signature).  We re-derive the digest, ecrecover the
pubkey, and if (a) the address matches and (b) the nonce is still alive,
we accept it.

Nonces are single-use: every verification attempt consumes them. Production
uses a shared SQLite-WAL store so quotas and nonce consumption remain atomic
across workers and restarts; focused unit tests may use the in-memory backend.

Audit history:

- POP-CANON-006 / LD-1 (CANON_SOLSLOT_API_AUDIT_2026_04_26):
  ``pop()`` previously left the challenge entry in the store on validation
  failure (wrong address / wrong auth_type).  Now ALL pop attempts remove
  the entry — strict write-once-read-once.  This prevents an attacker from
  using validation failures to keep the store full.

- POP-CANON-003 / Strategy 7: ``issue()`` now respects ``max_pending`` and
  per-IP rate limits to bound memory growth under DoS.

- POP-CANON-002 / SIGCOV-1: ``Challenge`` now snapshots the EIP-712 message
  parameters (pool_launcher_id, auth_type, chia_network).  ``register_evm_vault``
  uses these snapshotted values (not current settings) to reconstruct the
  digest, so config drift between issuance and verification cannot cause
  signature mismatch or pool-substitution.
"""
from __future__ import annotations

from .generation_storage import connect_generation_sqlite

import secrets
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import get_settings


class ChallengeStoreFullError(Exception):
    """Raised when the in-memory challenge store has hit its max-pending cap.

    The endpoint should translate this into HTTP 429 so the client can
    back off; existing in-flight challenges remain valid.
    """


class RateLimitedError(Exception):
    """Raised when a single source IP has exceeded its per-minute quota."""


class RequestRateLimiter:
    """Count HTTP attempts before request-body validation.

    Challenge issuance limits alone do not count malformed payloads because
    FastAPI rejects those before entering the route. This limiter sits in the
    outer ASGI middleware and uses SQLite-WAL in deployed environments so all
    workers share one atomic quota.
    """

    def __init__(
        self,
        per_ip_per_minute: int,
        *,
        db_path: str | Path | None = None,
        namespace: str = "http_auth_challenge",
    ) -> None:
        self.per_ip_per_minute = per_ip_per_minute
        self.namespace = namespace
        self._db_path = Path(db_path) if db_path is not None else None
        self._ip_attempts: dict[str, deque[float]] = defaultdict(deque)
        if self._db_path is not None:
            self._init_db()

    def allow(self, source_ip: str) -> bool:
        now = time.time()
        if self._db_path is None:
            cutoff = now - 60.0
            attempts = self._ip_attempts[source_ip]
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            if len(attempts) >= self.per_ip_per_minute:
                return False
            attempts.append(now)
            return True

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with connect_generation_sqlite(self._db_path, timeout=5.0, isolation_level=None) as conn:
            try:
                conn.execute("PRAGMA busy_timeout = 5000")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "DELETE FROM request_rate_events "
                    "WHERE namespace = ? AND attempted_at < ?",
                    (self.namespace, now - 60.0),
                )
                count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM request_rate_events "
                        "WHERE namespace = ? AND source_ip = ? AND attempted_at >= ?",
                        (self.namespace, source_ip, now - 60.0),
                    ).fetchone()[0]
                )
                if count >= self.per_ip_per_minute:
                    conn.commit()
                    return False
                conn.execute(
                    "INSERT INTO request_rate_events(namespace, source_ip, attempted_at) "
                    "VALUES (?, ?, ?)",
                    (self.namespace, source_ip, now),
                )
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                raise

    def _init_db(self) -> None:
        if self._db_path is None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with connect_generation_sqlite(self._db_path, timeout=5.0) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS request_rate_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    namespace TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    attempted_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS request_rate_events_window_idx
                    ON request_rate_events(namespace, source_ip, attempted_at);
                """
            )


@dataclass
class Challenge:
    nonce: str  # 0x-prefixed 32-byte hex
    address: str
    auth_type: str  # "evm" | "chia_bls" | "passkey"
    issued_at: float
    expires_at: float

    # Snapshotted EIP-712 envelope params (POP-CANON-002 fix).
    # The user's signature commits to these exact values; the server uses
    # them at /vault/register/* to rebuild the digest, NOT current settings.
    pool_launcher_id_hex: str = "0x" + "00" * 32
    chia_network: str = "testnet11"


class ChallengeStore:
    """In-memory challenge store.  Thread-safe enough for asyncio single-loop use."""

    def __init__(
        self,
        ttl_seconds: int,
        max_pending: int = 50_000,
        per_ip_per_minute: int = 60,
        *,
        db_path: str | Path | None = None,
        namespace: str = "vault_registration",
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_pending = max_pending
        self.per_ip_per_minute = per_ip_per_minute
        self.namespace = namespace
        self._db_path = Path(db_path) if db_path is not None else None
        self._challenges: dict[str, Challenge] = {}
        # Per-IP issuance log: deque of timestamps within the last 60s.
        self._ip_issuance: dict[str, deque[float]] = defaultdict(deque)
        if self._db_path is not None:
            self._init_db()

    def issue(
        self,
        address: str,
        auth_type: str,
        pool_launcher_id_hex: str = "0x" + "00" * 32,
        chia_network: str = "testnet11",
        source_ip: Optional[str] = None,
    ) -> Challenge:
        """Issue a new challenge.

        Raises:
            RateLimitedError: source_ip has exceeded per-minute quota.
            ChallengeStoreFullError: the store has hit max_pending.
        """
        if self._db_path is not None:
            return self._issue_persistent(
                address=address,
                auth_type=auth_type,
                pool_launcher_id_hex=pool_launcher_id_hex,
                chia_network=chia_network,
                source_ip=source_ip,
            )

        now = time.time()
        self._gc(now)

        if source_ip is not None:
            self._enforce_per_ip_rate(source_ip, now)

        if len(self._challenges) >= self.max_pending:
            raise ChallengeStoreFullError(
                f"Challenge store is at capacity ({self.max_pending}); try again later"
            )

        nonce = "0x" + secrets.token_hex(32)
        ch = Challenge(
            nonce=nonce,
            address=address.lower() if auth_type == "evm" else address,
            auth_type=auth_type,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            pool_launcher_id_hex=pool_launcher_id_hex,
            chia_network=chia_network,
        )
        self._challenges[nonce] = ch
        if source_ip is not None:
            self._ip_issuance[source_ip].append(now)
        return ch

    def pop(self, nonce: str, address: str, auth_type: str) -> Optional[Challenge]:
        """Return and remove the challenge if it is valid for this caller.

        POP-CANON-006 fix: the entry is ALWAYS removed (write-once-read-once),
        whether validation succeeds or fails.  This prevents an attacker
        from filling the store with entries that are never garbage-collected
        because they're never matched by a legitimate caller.
        """
        if self._db_path is not None:
            ch = self._pop_persistent(nonce)
        else:
            ch = self._challenges.pop(nonce, None)
        if ch is None:
            return None
        now = time.time()
        if ch.expires_at < now:
            return None
        if ch.auth_type != auth_type:
            return None
        expected = address.lower() if auth_type == "evm" else address
        if ch.address != expected:
            return None
        return ch

    def _gc(self, now: float) -> None:
        stale = [n for n, c in self._challenges.items() if c.expires_at < now]
        for n in stale:
            self._challenges.pop(n, None)
        # Also prune per-IP issuance log of entries older than the window.
        cutoff = now - 60.0
        for ip, dq in list(self._ip_issuance.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                # Drop empty dicts so memory doesn't accumulate per-IP forever.
                self._ip_issuance.pop(ip, None)

    def _enforce_per_ip_rate(self, source_ip: str, now: float) -> None:
        cutoff = now - 60.0
        dq = self._ip_issuance[source_ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.per_ip_per_minute:
            raise RateLimitedError(
                f"IP {source_ip} exceeded {self.per_ip_per_minute} challenges/minute"
            )

    def __len__(self) -> int:
        if self._db_path is not None:
            now = time.time()
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "DELETE FROM challenges WHERE namespace = ? AND expires_at < ?",
                    (self.namespace, now),
                )
                count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM challenges WHERE namespace = ?",
                        (self.namespace,),
                    ).fetchone()[0]
                )
                conn.commit()
                return count
        return len(self._challenges)

    def _connect(self) -> sqlite3.Connection:
        if self._db_path is None:
            raise RuntimeError("Persistent challenge storage is not configured")
        conn = connect_generation_sqlite(self._db_path, timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_db(self) -> None:
        if self._db_path is None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS challenges (
                    namespace TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    address TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    pool_launcher_id_hex TEXT NOT NULL,
                    chia_network TEXT NOT NULL,
                    PRIMARY KEY(namespace, nonce)
                );
                CREATE INDEX IF NOT EXISTS challenges_expiry_idx
                    ON challenges(namespace, expires_at);
                CREATE TABLE IF NOT EXISTS challenge_issuance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    namespace TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    issued_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS challenge_issuance_window_idx
                    ON challenge_issuance(namespace, source_ip, issued_at);
                """
            )

    def _issue_persistent(
        self,
        *,
        address: str,
        auth_type: str,
        pool_launcher_id_hex: str,
        chia_network: str,
        source_ip: Optional[str],
    ) -> Challenge:
        now = time.time()
        challenge = Challenge(
            nonce="0x" + secrets.token_hex(32),
            address=address.lower() if auth_type == "evm" else address,
            auth_type=auth_type,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            pool_launcher_id_hex=pool_launcher_id_hex,
            chia_network=chia_network,
        )
        with self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "DELETE FROM challenges WHERE namespace = ? AND expires_at < ?",
                    (self.namespace, now),
                )
                conn.execute(
                    "DELETE FROM challenge_issuance WHERE namespace = ? AND issued_at < ?",
                    (self.namespace, now - 60.0),
                )
                if source_ip is not None:
                    issued = int(
                        conn.execute(
                            """
                            SELECT COUNT(*) FROM challenge_issuance
                            WHERE namespace = ? AND source_ip = ? AND issued_at >= ?
                            """,
                            (self.namespace, source_ip, now - 60.0),
                        ).fetchone()[0]
                    )
                    if issued >= self.per_ip_per_minute:
                        raise RateLimitedError(
                            f"IP {source_ip} exceeded "
                            f"{self.per_ip_per_minute} challenges/minute"
                        )
                pending = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM challenges WHERE namespace = ?",
                        (self.namespace,),
                    ).fetchone()[0]
                )
                if pending >= self.max_pending:
                    raise ChallengeStoreFullError(
                        f"Challenge store is at capacity ({self.max_pending}); "
                        "try again later"
                    )
                conn.execute(
                    """
                    INSERT INTO challenges(
                        namespace, nonce, address, auth_type, issued_at,
                        expires_at, pool_launcher_id_hex, chia_network
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.namespace,
                        challenge.nonce,
                        challenge.address,
                        challenge.auth_type,
                        challenge.issued_at,
                        challenge.expires_at,
                        challenge.pool_launcher_id_hex,
                        challenge.chia_network,
                    ),
                )
                if source_ip is not None:
                    conn.execute(
                        """
                        INSERT INTO challenge_issuance(namespace, source_ip, issued_at)
                        VALUES (?, ?, ?)
                        """,
                        (self.namespace, source_ip, now),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return challenge

    def _pop_persistent(self, nonce: str) -> Optional[Challenge]:
        with self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    """
                    SELECT nonce, address, auth_type, issued_at, expires_at,
                           pool_launcher_id_hex, chia_network
                    FROM challenges WHERE namespace = ? AND nonce = ?
                    """,
                    (self.namespace, nonce),
                ).fetchone()
                conn.execute(
                    "DELETE FROM challenges WHERE namespace = ? AND nonce = ?",
                    (self.namespace, nonce),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        if row is None:
            return None
        return Challenge(
            nonce=str(row["nonce"]),
            address=str(row["address"]),
            auth_type=str(row["auth_type"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
            pool_launcher_id_hex=str(row["pool_launcher_id_hex"]),
            chia_network=str(row["chia_network"]),
        )


_store: Optional[ChallengeStore] = None


def get_store() -> ChallengeStore:
    global _store
    if _store is None:
        s = get_settings()
        _store = ChallengeStore(
            ttl_seconds=s.challenge_ttl_seconds,
            max_pending=s.challenge_store_max_pending,
            per_ip_per_minute=s.challenge_per_ip_per_minute,
            db_path=(
                None if s.runtime_environment == "test" else s.challenge_store_path
            ),
            namespace="vault_registration",
        )
    return _store


def preflight_challenge_storage(settings: object) -> None:
    """Prove deployed challenge state is persistent and writable at boot.

    A relative default is convenient for development, but it is dangerous in
    an atomic release directory: a restart or rollback can silently reset the
    quota ledger.  Staging and production therefore require one absolute,
    writable SQLite path outside the release tree.  Initialising both stores
    here also turns a permissions or read-only-filesystem mistake into a
    failed deployment instead of a public 503 on the first challenge.
    """
    runtime_environment = str(getattr(settings, "runtime_environment", ""))
    if runtime_environment not in {"staging", "production"}:
        return

    configured_path = str(getattr(settings, "challenge_store_path", "")).strip()
    path = Path(configured_path)
    if not configured_path or not path.is_absolute():
        raise RuntimeError(
            "SOLSLOT_CHALLENGE_STORE_PATH must be an absolute shared-state "
            "path in staging/production."
        )

    try:
        RequestRateLimiter(
            int(getattr(settings, "challenge_per_ip_per_minute")),
            db_path=path,
        )
        ChallengeStore(
            ttl_seconds=int(getattr(settings, "challenge_ttl_seconds")),
            max_pending=int(getattr(settings, "challenge_store_max_pending")),
            per_ip_per_minute=int(
                getattr(settings, "challenge_per_ip_per_minute")
            ),
            db_path=path,
            namespace="vault_registration",
        )
    except (OSError, sqlite3.Error) as exc:
        raise RuntimeError(
            "SOLSLOT_CHALLENGE_STORE_PATH is not writable SQLite state: "
            f"{path}"
        ) from exc


def reset_store_for_tests() -> None:
    """Reset the module-level store (test-only helper)."""
    global _store
    _store = None
