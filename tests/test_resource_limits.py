from __future__ import annotations

import concurrent.futures
import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from solslot_api import alpha_observability as obs
from solslot_api.collection_media import CollectionMediaPipeline, MediaVerificationError
from solslot_api.config import Settings


PNG = b"\x89PNG\r\n\x1a\n" + b"verified-test-image"
CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3w5h5m4rj5zv5q3n5dnm7q6ha"


def event():
    return obs.AlphaTelemetryRequest(
        event="PRACTICE_STARTED", correlation_id="synthetic-local-01",
        release_sha="a" * 40, artifact_hash="0x" + "b" * 64,
    )


def report():
    return obs.AlphaBugReportRequest(
        category="UI", summary="Synthetic report", description="Local resource regression",
    )


@pytest.mark.parametrize("kind", ["telemetry", "report"])
def test_storage_capacity_survives_restart_and_preserves_rows(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(obs, "_MAX_TELEMETRY_ROWS", 2, raising=False)
    monkeypatch.setattr(obs, "_MAX_BUG_REPORT_ROWS", 2, raising=False)
    path = str(tmp_path / "intake.db")
    store = obs.AlphaObservabilityStore(path)
    payload = event() if kind == "telemetry" else report()
    getattr(store, kind)(payload, "192.0.2.1")
    getattr(store, kind)(payload, "192.0.2.2")
    before = store.aggregate_counts()
    store._conn.close()
    reopened = obs.AlphaObservabilityStore(path)
    try:
        with pytest.raises(obs.IntakeLimitExceeded, match="capacity"):
            getattr(reopened, kind)(payload, "192.0.2.3")
        assert reopened.aggregate_counts() == before
        assert not reopened._conn.in_transaction
    finally:
        reopened._conn.close()


def test_two_connections_cannot_race_past_capacity(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_MAX_TELEMETRY_ROWS", 1, raising=False)
    path = str(tmp_path / "intake.db")
    stores = [obs.AlphaObservabilityStore(path), obs.AlphaObservabilityStore(path)]

    def submit(store):
        try:
            store.telemetry(event(), "192.0.2.1")
            return True
        except obs.IntakeLimitExceeded as exc:
            assert "capacity" in str(exc)
            return False

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            assert sum(pool.map(submit, stores)) == 1
        assert stores[0].aggregate_counts()["telemetry_event_count"] == 1
    finally:
        for store in stores:
            store._conn.close()


@pytest.mark.parametrize("budget", ["source", "global"])
def test_intake_budgets_span_both_tables_and_restart(tmp_path, monkeypatch, budget):
    monkeypatch.setattr(obs, "_MAX_SOURCE_PER_WINDOW", 2 if budget == "source" else 100, raising=False)
    monkeypatch.setattr(obs, "_MAX_GLOBAL_PER_WINDOW", 2 if budget == "global" else 100, raising=False)
    monkeypatch.setattr(obs.time, "time", lambda: 1000)
    path = str(tmp_path / "intake.db")
    store = obs.AlphaObservabilityStore(path)
    store.telemetry(event(), "192.0.2.1")
    store.report(report(), "192.0.2.1")
    store._conn.close()
    store = obs.AlphaObservabilityStore(path)
    try:
        with pytest.raises(obs.IntakeLimitExceeded, match="rate"):
            store.telemetry(event(), "192.0.2.1" if budget == "source" else "192.0.2.2")
        monkeypatch.setattr(obs.time, "time", lambda: 1061)
        store.telemetry(event(), "192.0.2.1")
        assert store.aggregate_counts() == {"telemetry_event_count": 2, "bug_report_count": 1}
    finally:
        store._conn.close()


def test_runtime_store_is_separate_and_admin_writes_survive_capacity(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_store", None)
    monkeypatch.setattr(obs, "_MAX_TELEMETRY_ROWS", 1, raising=False)
    admin_path = tmp_path / "admin.db"
    admin = sqlite3.connect(admin_path)
    admin.execute("CREATE TABLE administrator_records (value TEXT)")
    admin.commit()
    settings = Settings(runtime_environment="test", admin_db_path=str(admin_path), _env_file=None)
    store = obs.get_alpha_observability_store(settings)
    try:
        assert store.path != str(admin_path)
        store.telemetry(event(), "192.0.2.1")
        with pytest.raises(obs.IntakeLimitExceeded, match="capacity"):
            store.telemetry(event(), "192.0.2.1")
        admin.execute("INSERT INTO administrator_records VALUES ('still writable')")
        admin.commit()
        assert admin.execute("SELECT COUNT(*) FROM administrator_records").fetchone()[0] == 1
        assert not admin.execute("SELECT name FROM sqlite_master WHERE name LIKE 'alpha_%'").fetchall()
    finally:
        store._conn.close()
        admin.close()


@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_runtime_store_rejects_an_alias_of_admin_storage(tmp_path, monkeypatch, link):
    monkeypatch.setattr(obs, "_store", None)
    admin = tmp_path / "admin.db"
    admin.write_bytes(b"synthetic held original")
    intake = tmp_path / "admin.db.alpha-observability.db"
    if link == "symlink":
        intake.symlink_to(admin)
    else:
        intake.hardlink_to(admin)
    with pytest.raises(HTTPException) as rejected:
        obs.get_alpha_observability_store(Settings(runtime_environment="test", admin_db_path=str(admin), _env_file=None))
    assert rejected.value.status_code == 503
    assert admin.read_bytes() == b"synthetic held original"


def test_historical_metrics_are_read_without_mutating_held_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "_store", None)
    admin = tmp_path / "admin.db"
    legacy = obs.AlphaObservabilityStore(str(admin))
    legacy.telemetry(event(), "192.0.2.1")
    legacy.report(report(), "192.0.2.1")
    legacy._conn.close()
    before = admin.read_bytes()
    current = obs.get_alpha_observability_store(Settings(runtime_environment="test", admin_db_path=str(admin), _env_file=None))
    try:
        current.telemetry(event(), "192.0.2.2")
        assert current.aggregate_counts() == {"telemetry_event_count": 2, "bug_report_count": 1}
        assert admin.read_bytes() == before
        assert current._conn.execute("SELECT COUNT(*) FROM alpha_telemetry_events").fetchone()[0] == 1
    finally:
        current._conn.close()


def test_database_byte_cap_rejects_large_valid_unicode_records_without_deleting(tmp_path, monkeypatch):
    cap = 128 * 1024
    monkeypatch.setattr(obs, "_MAX_DATABASE_BYTES", cap)
    path = tmp_path / "intake.db"
    store = obs.AlphaObservabilityStore(str(path))
    large = obs.AlphaBugReportRequest(
        category="UI", summary="s" * 240, description="\U0001d494" * 4000,
        diagnostics_opt_in=True, diagnostics={"fixture": "x" * 4000},
    )
    try:
        with pytest.raises(sqlite3.OperationalError, match="full"):
            for _ in range(20):
                store.report(large, "192.0.2.1")
        before = store.aggregate_counts()
        assert before["bug_report_count"] > 0
        assert not store._conn.in_transaction
        assert path.stat().st_size <= cap
        assert not Path(str(path) + "-wal").exists()
    finally:
        store._conn.close()
    reopened = obs.AlphaObservabilityStore(str(path))
    try:
        assert reopened.aggregate_counts() == before
        with pytest.raises(sqlite3.OperationalError, match="full"):
            reopened.report(large, "192.0.2.1")
        assert reopened.aggregate_counts() == before
    finally:
        reopened._conn.close()


@pytest.mark.parametrize("kind", ["telemetry", "report"])
def test_public_routes_return_controlled_capacity_refusal(monkeypatch, kind):
    monkeypatch.setattr(obs, "_MAX_TELEMETRY_ROWS", 1, raising=False)
    monkeypatch.setattr(obs, "_MAX_BUG_REPORT_ROWS", 1, raising=False)
    store = obs.AlphaObservabilityStore(":memory:")
    payload = event() if kind == "telemetry" else report()
    route = obs.record_alpha_telemetry if kind == "telemetry" else obs.submit_alpha_bug_report
    request = Request({"type": "http", "client": ("192.0.2.1", 1), "headers": []})
    settings = Settings(runtime_environment="test", _env_file=None)
    try:
        assert route(payload, request, settings, store)["id"]
        with pytest.raises(HTTPException) as rejected:
            route(payload, request, settings, store)
        assert rejected.value.status_code == 503
    finally:
        store._conn.close()


class TrackedStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.reads = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


def pipeline_settings():
    return Settings(
        runtime_environment="test", _env_file=None,
        collection_asset_max_bytes=len(PNG),
        collection_s3_endpoint_url="https://s3.example.test",
        collection_s3_access_key_id="synthetic-access",
        collection_s3_secret_access_key="synthetic-secret",
        collection_s3_public_base_url="https://assets.example.test",
        collection_ipfs_api_url="https://ipfs-api.example.test",
        collection_ipfs_pinning_service_url="https://pins.example.test",
        collection_ipfs_pinning_token="synthetic-pin",
        collection_ipfs_gateway_url="https://gateway.example.test/ipfs/{cid}",
        collection_malware_scan_url="https://scanner.example.test/scan",
    )


async def run_pipeline(stage, stream, headers=None):
    target = {"public-upload": "s3.example.test", "private-upload": "s3.example.test",
              "public-mirror": "assets.example.test", "ipfs-mirror": "gateway.example.test"}[stage]

    def handler(request):
        if request.method == "GET":
            if request.url.host == target:
                return httpx.Response(200, stream=stream, headers=headers)
            return httpx.Response(200, content=PNG)
        if request.url.host == "scanner.example.test":
            return httpx.Response(200, json={"status": "CLEAN"})
        if request.url.host == "ipfs-api.example.test":
            return httpx.Response(200, text=json.dumps({"Hash": CID}))
        if request.url.host == "pins.example.test":
            return httpx.Response(200, json={"pin": {"cid": CID}})
        raise AssertionError("unexpected test destination")

    pipeline = CollectionMediaPipeline(pipeline_settings(), transport=httpx.MockTransport(handler))
    args = dict(expected_sha256=hashlib.sha256(PNG).hexdigest(),
                expected_mime_type="image/png", expected_byte_size=len(PNG))
    if stage == "private-upload":
        return await pipeline.verify_private_document(object_key="private/collections/test/file.png", **args)
    return await pipeline.verify_and_pin(object_key="collections/test/file.png", asset_name="test", **args)


STAGES = ["public-upload", "private-upload", "public-mirror", "ipfs-mirror"]


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("headers", [{}, {"Content-Length": "1"}])
async def test_oversized_download_stops_early_without_trusting_length(stage, headers):
    stream = TrackedStream([PNG, b"x", b"unread", b"unread"])
    with pytest.raises(MediaVerificationError):
        await run_pipeline(stage, stream, headers)
    assert stream.closed
    assert stream.reads <= 2


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", STAGES)
async def test_nonidentity_encoding_is_rejected_before_consumption(stage):
    stream = TrackedStream([b"not consumed"])
    with pytest.raises(MediaVerificationError, match="encoding"):
        await run_pipeline(stage, stream, {"Content-Encoding": "gzip"})
    assert stream.closed
    assert stream.reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", STAGES)
async def test_exact_limit_stream_preserves_valid_media(stage):
    stream = TrackedStream([PNG[:8], PNG[8:]])
    result = await run_pipeline(stage, stream)
    assert result.sha256 == hashlib.sha256(PNG).hexdigest()
    assert result.byte_size == len(PNG)
    assert stream.closed and stream.reads == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", STAGES)
async def test_short_stream_is_rejected_and_closed(stage):
    stream = TrackedStream([PNG[:-1]])
    with pytest.raises(MediaVerificationError):
        await run_pipeline(stage, stream)
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("length", ["-1", "invalid", "999999"])
async def test_invalid_or_oversized_headers_do_not_consume_body(stage, length):
    stream = TrackedStream([PNG])
    with pytest.raises(MediaVerificationError):
        await run_pipeline(stage, stream, {"Content-Length": length})
    assert stream.closed and stream.reads == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", STAGES)
async def test_cancelled_download_closes_response(stage):
    class CancelledStream(TrackedStream):
        async def __aiter__(self):
            yield PNG[:8]
            raise asyncio.CancelledError()

    stream = CancelledStream([])
    with pytest.raises(asyncio.CancelledError):
        await run_pipeline(stage, stream)
    assert stream.closed
