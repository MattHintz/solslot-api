"""Fail-closed ClamAV INSTREAM client for the existing local daemon."""
from __future__ import annotations

import asyncio
import struct
from datetime import datetime, timezone
from pathlib import Path
import stat

from .collection_media import MediaPipelineUnavailable, MediaVerificationError
from .config import Settings


async def _command(path: str, command: bytes) -> bytes:
    reader, writer = await asyncio.open_unix_connection(path, limit=4096)
    try:
        writer.write(b"z" + command + b"\0")
        await writer.drain()
        return (await reader.readuntil(b"\0")).rstrip(b"\0")
    finally:
        writer.close()
        await writer.wait_closed()


async def scan_with_clamav(settings: Settings, payload: bytes) -> None:
    if not 0 < len(payload) <= min(settings.collection_asset_max_bytes, 20 * 1024 * 1024):
        raise MediaVerificationError("file exceeds the verified ClamAV stream limit")
    path = str(settings.collection_clamav_socket or "")
    if not path.startswith("/"):
        raise MediaPipelineUnavailable("ClamAV requires the reviewed local UNIX socket")
    try:
        if settings.collection_clamav_policy_path:
            def check_policy() -> None:
                source = Path(str(settings.collection_clamav_policy_path))
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
                    raise ValueError("scanner policy is not protected")
                pairs = [line.split(None, 1) for line in source.read_text().splitlines()
                         if line.strip() and not line.lstrip().startswith("#")]
                policy = dict(pair for pair in pairs if len(pair) == 2)
                if any(policy.get(key, "").strip().lower() != "true" for key in
                       ("AlertExceedsMax", "AlertEncrypted", "HeuristicAlerts", "ScanPDF")):
                    raise ValueError("scanner must alert on encrypted files and exceeded limits")
            await asyncio.to_thread(check_policy)
        elif settings.runtime_environment not in {"test", "development"}:
            raise MediaPipelineUnavailable("ClamAV policy must be verified before publication")
        async with asyncio.timeout(settings.collection_asset_verification_timeout_seconds):
            version = (await _command(path, b"VERSION")).decode("ascii")
            # Check the running daemon's loaded definitions, not just a timer
            # or freshclam's file timestamp. Stop publication if > 48h old.
            date = version.split("/", 2)[2]
            loaded = datetime.strptime(date.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - loaded).total_seconds()
            if not -3600 <= age <= 48 * 3600:
                raise MediaPipelineUnavailable("ClamAV loaded signatures are stale")
            reader, writer = await asyncio.open_unix_connection(path, limit=4096)
            try:
                writer.write(b"zINSTREAM\0")
                for offset in range(0, len(payload), 65536):
                    chunk = payload[offset:offset + 65536]
                    writer.write(struct.pack("!I", len(chunk)) + chunk)
                    await writer.drain()
                writer.write(b"\0\0\0\0")
                await writer.drain()
                result = (await reader.readuntil(b"\0")).rstrip(b"\0")
            finally:
                writer.close()
                await writer.wait_closed()
            if result.endswith(b" FOUND"):
                raise MediaVerificationError("local malware scan rejected the file")
            if result != b"stream: OK":
                raise MediaPipelineUnavailable("local malware scan could not finish the file")
    except MediaVerificationError:
        raise
    except (OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            UnicodeError, ValueError, IndexError) as exc:
        raise MediaPipelineUnavailable("ClamAV is unavailable or returned an unverified result") from exc
