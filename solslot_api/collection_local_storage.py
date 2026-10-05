"""Create-only local staging for the existing Solslot host.

Upload capabilities come only from the authenticated collection issuer. They
bind the exact bytes, type, size, destination, condition and expiration. Cookie
authentication is never used by this small, separately bounded ASGI surface.
"""
from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from starlette.responses import Response

from .config import Settings
from .collection_document_types import XLSX_MIME

PREFIX = "/collection-media"
KEY = re.compile(r"(?:private/)?collections/v2/[0-9a-f]{64}/[0-9a-f]{32}/asset(?:\.[a-z0-9]{1,12})?\Z")
OBJECT_ID = re.compile(r"[0-9a-f]{64}\Z")
MIMES = {"image/png", "image/jpeg", "image/webp", "image/gif", "application/pdf"}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class LocalStorage:
    def __init__(self, settings: Settings):
        self.settings = settings
        if settings.collection_storage_backend != "filesystem":
            raise ValueError("local collection storage is disabled")
        if (not settings.collection_local_root or not settings.collection_local_base_url
                or len(settings.admin_jwt_secret) < 32):
            raise ValueError("local collection storage requires a root, URL and admin signing secret")
        self.root = Path(settings.collection_local_root)
        if not self.root.is_absolute() or self.root.is_symlink():
            raise ValueError("collection storage root must be an absolute, nonsymlink path")
        self.signing_key = hmac.digest(settings.admin_jwt_secret.encode(),
                                      b"solslot.collection-media.capabilities.v1", "sha256")
        self.base_url = str(settings.collection_local_base_url).rstrip("/")

    @staticmethod
    def object_id(key: str) -> str:
        if not KEY.fullmatch(key):
            raise ValueError("invalid collection object key")
        return hashlib.sha256(key.encode()).hexdigest()

    def _directory(self, name: str) -> Path:
        # The deployment creates these directories; requests never create paths.
        path = self.root / name
        for parent in (self.root, path):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                raise ValueError("collection storage directory is not protected")
        return path

    def issue(self, method: str, key: str, ttl: int, *, digest: str = "", size: int = 0,
              mime: str = "") -> str:
        self.object_id(key)
        if method == "PUT" and (not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not 0 < size <= self.settings.collection_asset_max_bytes
                or (mime not in MIMES and not (mime == XLSX_MIME and key.startswith("private/")))):
            raise ValueError("local upload needs an exact hash, allowed type and bounded size")
        payload = _b64(json.dumps({"v": 1, "m": method, "k": key, "e": int(time.time()) + ttl,
                                  "h": digest, "n": size, "t": mime},
                                 sort_keys=True, separators=(",", ":")).encode())
        return payload + "." + _b64(hmac.digest(self.signing_key, payload.encode(), "sha256"))

    def authorize(self, token: str, method: str, key: str) -> dict[str, Any]:
        try:
            if len(token) > 2048:
                raise ValueError()
            payload, signature = token.split(".")
            expected = _b64(hmac.digest(self.signing_key, payload.encode(), "sha256"))
            if not hmac.compare_digest(expected, signature):
                raise ValueError()
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            self.object_id(key)
            if (claims["v"] != 1 or claims["m"] != method or claims["k"] != key
                    or not int(time.time()) < claims["e"] <= int(time.time()) + 3600):
                raise ValueError()
            return claims
        except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
            raise HTTPException(403, "Invalid or expired collection media authorization") from exc

    def read(self, key: str, expected_size: int) -> bytes:
        path = self._directory("quarantine") / (self.object_id(key) + ".blob")
        return self._read_file(path, expected_size)

    def _read_file(self, path: Path, expected_size: int | None = None) -> bytes:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_size > self.settings.collection_asset_max_bytes
                    or (expected_size is not None and info.st_size != expected_size)):
                raise ValueError("stored collection size differs or exceeds the cap")
            payload = stream.read(self.settings.collection_asset_max_bytes + 1)
            if len(payload) != info.st_size:
                raise ValueError("stored collection bytes changed")
            return payload

    def promote(self, key: str, digest: str) -> str:
        if key.startswith("private/"):
            raise ValueError("private originals cannot be published")
        object_id = self.object_id(key)
        source = self._directory("quarantine") / (object_id + ".blob")
        target = self._directory("public") / (object_id + ".blob")
        if hashlib.sha256(self._read_file(source)).hexdigest() != digest:
            raise ValueError("collection bytes changed before publication")
        try:
            os.link(source, target, follow_symlinks=False)
        except FileExistsError:
            if hashlib.sha256(self._read_file(target)).hexdigest() != digest:
                raise ValueError("public collection commitment differs")
        self._sync_directory(target.parent)
        return self.base_url + "/public/" + object_id

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    async def upload(self, request: Request, key: str, claims: dict[str, Any]) -> None:
        if request.headers.get("if-none-match") != "*":
            raise HTTPException(403, "Upload requires its signed create-only condition")
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != claims["t"]:
            raise HTTPException(422, "Upload type differs from authorization")
        if request.headers.get("content-encoding", "identity").lower() != "identity":
            raise HTTPException(422, "Compressed uploads are not supported")
        if int(request.headers.get("content-length", "-1")) != claims["n"]:
            raise HTTPException(413, "Upload length differs from authorization")
        directory = self._directory("quarantine")
        target = directory / (self.object_id(key) + ".blob")
        lock = os.open(self.root / "upload.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        temporary: Path | None = None
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise HTTPException(503, "Another upload is finishing; retry shortly", headers={"Retry-After": "2"}) from exc
            if target.exists() or target.is_symlink():
                raise HTTPException(412, "This upload has already been stored")
            used = sum(entry.stat(follow_symlinks=False).st_size for entry in os.scandir(directory))
            if (used + claims["n"] > self.settings.collection_local_quota_bytes
                    or shutil.disk_usage(self.root).free - claims["n"] < self.settings.collection_local_min_free_bytes):
                raise HTTPException(507, "Collection storage capacity is reserved; contact the administrator")
            descriptor, name = tempfile.mkstemp(prefix="pending-", dir=directory)
            temporary = Path(name)
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(descriptor, "wb") as stream:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > claims["n"]:
                        raise HTTPException(413, "Upload exceeds its authorized size")
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if size != claims["n"] or digest.hexdigest() != claims["h"]:
                raise HTTPException(422, "Upload bytes differ from the declared commitment")
            temporary.chmod(0o400)
            # link is atomic and create-only even if two workers race.
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise HTTPException(412, "This upload has already been stored") from exc
            self._sync_directory(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            os.close(lock)


def create_media_app(settings: Settings) -> Any:
    """Dedicated capability surface; mount outside cookie/XSRF JSON routes."""
    storage = LocalStorage(settings)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def origin_check(request: Request) -> None:
        from urllib.parse import urlsplit
        url = urlsplit(storage.base_url)
        if (request.headers.get("sec-fetch-site") == "cross-site"
                or request.headers.get("origin") not in (None, url.scheme + "://" + url.netloc)):
            raise HTTPException(403, "Cross-origin collection uploads are not allowed")

    @app.put(PREFIX + "/objects/{key:path}")
    async def upload(key: str, request: Request) -> Response:
        origin_check(request)
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        claims = storage.authorize(token, "PUT", key)
        try:
            await storage.upload(request, key, claims)
        except (ValueError, OSError) as exc:
            raise HTTPException(503, "Collection storage is unavailable") from exc
        return Response(status_code=201)

    @app.get(PREFIX + "/objects/{key:path}")
    async def private_read(key: str, request: Request) -> Response:
        storage.authorize(request.query_params.get("token", ""), "GET", key)
        return await read_bytes(key=key)

    @app.get(PREFIX + "/public/{object_id}")
    async def public_read(object_id: str) -> Response:
        if not OBJECT_ID.fullmatch(object_id):
            raise HTTPException(404)
        return await read_bytes(public_id=object_id)

    async def read_bytes(*, key: str | None = None, public_id: str | None = None) -> Response:
        from .collection_media import _detect_mime
        try:
            directory = storage._directory("public" if public_id else "quarantine")
            object_id = public_id or storage.object_id(str(key))
            payload = await asyncio.to_thread(storage._read_file, directory / (object_id + ".blob"))
            mime = _detect_mime(payload)
        except FileNotFoundError as exc:
            raise HTTPException(404, "Collection file is not published or available") from exc
        except (ValueError, OSError) as exc:
            raise HTTPException(503, "Collection storage is unavailable") from exc
        return Response(payload, media_type=mime, headers={
            "Cache-Control": "public, max-age=31536000, immutable" if public_id else "no-store",
            "Content-Disposition": "attachment" if mime == "application/pdf" or not public_id else "inline",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; sandbox", "X-Frame-Options": "DENY",
        })

    concurrency = asyncio.Semaphore(2)

    async def bounded_app(scope: Any, receive: Any, send: Any) -> None:
        async with concurrency:
            async with asyncio.timeout(60):
                await app(scope, receive, send)
    return bounded_app
