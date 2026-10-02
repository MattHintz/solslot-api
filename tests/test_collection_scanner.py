import asyncio
from datetime import datetime, timedelta, timezone
import struct

import pytest

from solslot_api.collection_media import MediaPipelineUnavailable, MediaVerificationError
from solslot_api.collection_scanner import scan_with_clamav
from solslot_api.config import Settings


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["clean", "infected", "error", "stale"])
async def test_scanner_requires_fresh_loaded_definitions_and_exact_clean(tmp_path, outcome):
    scanned = []
    socket = str(tmp_path / "clamd.sock")

    async def handler(reader, writer):
        try:
            command = await reader.readuntil(b"\0")
            if command == b"zVERSION\0":
                date = datetime.now(timezone.utc) - timedelta(days=3 if outcome == "stale" else 0)
                writer.write(("ClamAV 1.4.3/28141/" + date.strftime("%a %b %d %H:%M:%S %Y")).encode() + b"\0")
            else:
                assert command == b"zINSTREAM\0"
                payload = b""
                while size := struct.unpack("!I", await reader.readexactly(4))[0]:
                    payload += await reader.readexactly(size)
                scanned.append(payload)
                writer.write({"clean": b"stream: OK\0", "infected": b"stream: Eicar FOUND\0",
                              "error": b"INSTREAM size limit exceeded ERROR\0"}[outcome])
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(handler, path=socket)
    settings = Settings(runtime_environment="test", collection_clamav_socket=socket)
    try:
        if outcome == "clean":
            await scan_with_clamav(settings, b"synthetic")
            assert scanned == [b"synthetic"]
        else:
            with pytest.raises((MediaPipelineUnavailable, MediaVerificationError)):
                await scan_with_clamav(settings, b"synthetic")
            if outcome == "stale": assert not scanned
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_missing_scanner_stops_publication(tmp_path):
    with pytest.raises(MediaPipelineUnavailable):
        await scan_with_clamav(Settings(runtime_environment="test", collection_clamav_socket=str(tmp_path / "missing")), b"synthetic")


@pytest.mark.asyncio
async def test_scanner_rejects_policy_that_can_skip_scan_limits(tmp_path):
    policy = tmp_path / "clamd.conf"
    policy.write_text("ScanPDF true\nAlertEncrypted true\nHeuristicAlerts true\nAlertExceedsMax false\n")
    policy.chmod(0o600)
    with pytest.raises(MediaPipelineUnavailable):
        await scan_with_clamav(Settings(runtime_environment="test", collection_clamav_socket=str(tmp_path / "missing"),
                                      collection_clamav_policy_path=str(policy)), b"synthetic")
