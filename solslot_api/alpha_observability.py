from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from .config import Settings, get_settings
from .server_hardening import trusted_client_ip

router = APIRouter(prefix="/alpha", tags=["alpha-observability"])

# Public intake has a finite, separate storage budget. Existing records are
# retained at capacity; clearing or archiving them requires operator review.
_MAX_TELEMETRY_ROWS = 10_000
_MAX_BUG_REPORT_ROWS = 1_000
_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_RATE_WINDOW_SECONDS = 60
_MAX_GLOBAL_PER_WINDOW = 600
_MAX_SOURCE_PER_WINDOW = 60


class IntakeLimitExceeded(ValueError):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class AlphaTelemetryRequest(BaseModel):
    event: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    correlation_id: str = Field(min_length=8, max_length=128)
    release_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    artifact_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    rail: Optional[Literal["XCH", "BASE_USDC", "VOUCHER_USDC"]] = None
    wallet_type: Optional[Literal["chia", "evm", "google", "passkey"]] = None
    latency_ms: Optional[int] = Field(default=None, ge=0, le=600_000)
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def bounded_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("details exceed 4096 bytes")
        return value


class AlphaBugReportRequest(BaseModel):
    category: Literal["PAYMENT", "VOUCHER", "WALLET", "IDENTITY", "UI", "OTHER"]
    summary: str = Field(min_length=4, max_length=240)
    description: str = Field(min_length=4, max_length=4000)
    correlation_id: Optional[str] = Field(default=None, min_length=8, max_length=128)
    transaction_id: Optional[str] = Field(default=None, pattern=r"^0x[0-9a-fA-F]{64}$")
    contact: Optional[str] = Field(default=None, max_length=254)
    diagnostics_opt_in: bool = False
    diagnostics: dict[str, Any] = Field(default_factory=dict)

    @field_validator("diagnostics")
    @classmethod
    def bounded_diagnostics(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("diagnostics exceed 4096 bytes")
        return value


class AlphaObservabilityStore:
    def __init__(self, path: str, *, legacy_admin_path: str | None = None) -> None:
        self.path = ":memory:" if path == ":memory:" else str(Path(path))
        self.legacy_admin_path = legacy_admin_path
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        if self.path != ":memory:":
            # A long-lived reader must not allow an unbounded WAL to grow.
            self._conn.execute("PRAGMA journal_mode=DELETE")
        page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
        max_pages = _MAX_DATABASE_BYTES // page_size
        actual_limit = self._conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        if actual_limit > max_pages:
            self._conn.close()
            raise RuntimeError("observability storage exceeds its capacity")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alpha_telemetry_events (
                id TEXT PRIMARY KEY,
                occurred_at INTEGER NOT NULL,
                event TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                release_sha TEXT NOT NULL,
                artifact_hash TEXT NOT NULL,
                rail TEXT,
                wallet_type TEXT,
                latency_ms INTEGER,
                source_ip_hash TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alpha_telemetry_occurred_idx
                ON alpha_telemetry_events(occurred_at);
            CREATE TABLE IF NOT EXISTS alpha_bug_reports (
                id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                category TEXT NOT NULL,
                summary TEXT NOT NULL,
                description TEXT NOT NULL,
                correlation_id TEXT,
                transaction_id TEXT,
                contact TEXT,
                diagnostics_opt_in INTEGER NOT NULL,
                diagnostics_json TEXT NOT NULL,
                source_ip_hash TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alpha_bug_created_idx
                ON alpha_bug_reports(created_at);
            """
        )

    def _admit(self, table: str, source_hash: str, now: int) -> None:
        """Called within BEGIN IMMEDIATE so every writer shares the same cap."""
        caps = {"alpha_telemetry_events": _MAX_TELEMETRY_ROWS,
                "alpha_bug_reports": _MAX_BUG_REPORT_ROWS}
        if self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] >= caps[table]:
            raise IntakeLimitExceeded("observability storage is at capacity", 503)
        total, source_total = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(source_ip_hash = ?), 0) FROM ("
            "SELECT source_ip_hash FROM alpha_telemetry_events WHERE occurred_at >= ? "
            "UNION ALL SELECT source_ip_hash FROM alpha_bug_reports WHERE created_at >= ?)",
            (source_hash, now - _RATE_WINDOW_SECONDS, now - _RATE_WINDOW_SECONDS),
        ).fetchone()
        if total >= _MAX_GLOBAL_PER_WINDOW or source_total >= _MAX_SOURCE_PER_WINDOW:
            raise IntakeLimitExceeded("observability intake rate limit reached", 429)

    def aggregate_counts(self) -> dict[str, int]:
        """Read persisted totals without exposing report or event content."""
        with self._lock:
            row = self._conn.execute(
                "SELECT (SELECT COUNT(*) FROM alpha_telemetry_events) AS telemetry_event_count, "
                "(SELECT COUNT(*) FROM alpha_bug_reports) AS bug_report_count"
            ).fetchone()
            counts = dict(row)
        # Preserve historical totals without migrating, pruning or writing to
        # the administrator database. Public intake only writes the new store.
        if self.legacy_admin_path and Path(self.legacy_admin_path).exists():
            legacy = sqlite3.connect(Path(self.legacy_admin_path).as_uri() + "?mode=ro", uri=True)
            try:
                for table, key in (("alpha_telemetry_events", "telemetry_event_count"),
                                   ("alpha_bug_reports", "bug_report_count")):
                    if legacy.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                        counts[key] += legacy.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            finally:
                legacy.close()
        return counts

    def telemetry(self, payload: AlphaTelemetryRequest, source_ip: str) -> str:
        event_id = "evt_" + uuid.uuid4().hex
        now, source_hash = int(time.time()), _ip_hash(source_ip)
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._admit("alpha_telemetry_events", source_hash, now)
            self._conn.execute(
                """
                INSERT INTO alpha_telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id, now, payload.event, payload.correlation_id,
                    payload.release_sha, payload.artifact_hash.lower(), payload.rail,
                    payload.wallet_type, payload.latency_ms, source_hash,
                    json.dumps(payload.details, sort_keys=True, separators=(",", ":")),
                ),
            )
        return event_id

    def report(self, payload: AlphaBugReportRequest, source_ip: str) -> str:
        report_id = "bug_" + uuid.uuid4().hex
        diagnostics = payload.diagnostics if payload.diagnostics_opt_in else {}
        now, source_hash = int(time.time()), _ip_hash(source_ip)
        with self._lock, self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._admit("alpha_bug_reports", source_hash, now)
            self._conn.execute(
                """
                INSERT INTO alpha_bug_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id, now, payload.category, payload.summary.strip(),
                    payload.description.strip(), payload.correlation_id, payload.transaction_id,
                    payload.contact.strip() if payload.contact else None, int(payload.diagnostics_opt_in),
                    json.dumps(diagnostics, sort_keys=True, separators=(",", ":")),
                    source_hash, "OPEN",
                ),
            )
        return report_id


_store: Optional[AlphaObservabilityStore] = None


def get_alpha_observability_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> AlphaObservabilityStore:
    global _store
    try:
        if settings.admin_db_path == ":memory:":
            path = ":memory:"
            legacy_path = None
        else:
            admin_path = Path(settings.admin_db_path).resolve()
            candidate = Path(str(admin_path) + ".alpha-observability.db")
            if candidate.is_symlink() or (
                candidate.exists() and admin_path.exists() and os.path.samefile(candidate, admin_path)
            ):
                raise ValueError("observability storage must be separate from administrator storage")
            path = str(candidate)
            legacy_path = str(admin_path)
        if _store is None or _store.path != path:
            _store = AlphaObservabilityStore(path, legacy_admin_path=legacy_path)
    except (sqlite3.Error, OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="observability storage is unavailable") from exc
    return _store


def _ip_hash(source_ip: str) -> str:
    return hashlib.sha256(source_ip.encode("utf-8")).hexdigest()


@router.post("/telemetry", status_code=202)
def record_alpha_telemetry(
    payload: AlphaTelemetryRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[AlphaObservabilityStore, Depends(get_alpha_observability_store)],
) -> dict[str, str]:
    try:
        return {"id": store.telemetry(payload, trusted_client_ip(request.scope, settings))}
    except IntakeLimitExceeded as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc), headers={"Retry-After": "60"}) from exc
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail="telemetry is temporarily unavailable") from exc


@router.post("/bug-reports", status_code=201)
def submit_alpha_bug_report(
    payload: AlphaBugReportRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[AlphaObservabilityStore, Depends(get_alpha_observability_store)],
) -> dict[str, str]:
    try:
        report_id = store.report(payload, trusted_client_ip(request.scope, settings))
    except IntakeLimitExceeded as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc), headers={"Retry-After": "60"}) from exc
    except sqlite3.Error as exc:
        raise HTTPException(status_code=503, detail="bug reporting is temporarily unavailable") from exc
    return {"id": report_id, "status": "OPEN"}
