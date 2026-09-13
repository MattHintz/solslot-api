"""ASGI defense-in-depth controls for the public Solslot API."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from collections.abc import Awaitable, Callable
from typing import Any, Mapping

from starlette.exceptions import HTTPException

from .challenges import RequestRateLimiter
from .config import Settings


AsgiReceive = Callable[[], Awaitable[dict[str, Any]]]
AsgiSend = Callable[[dict[str, Any]], Awaitable[None]]


def documentation_urls(settings: Settings) -> dict[str, str | None]:
    enabled = settings.api_docs_enabled
    return {
        "docs_url": "/docs" if enabled else None,
        "redoc_url": "/redoc" if enabled else None,
        "openapi_url": "/openapi.json" if enabled else None,
    }


class ServerHardeningMiddleware:
    """Cap request work and attach browser-facing security headers.

    The reverse proxy remains the first line of defense. These checks make a
    proxy routing mistake bounded instead of turning it into an unprotected
    uvicorn listener.
    """

    def __init__(self, app: Any, *, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self._challenge_limiter: RequestRateLimiter | None = None
        self._chia_push_limiter: RequestRateLimiter | None = None
        self._genesis_store: Any | None = None

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def hardened_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
                if self.settings.security_headers_enabled:
                    message["headers"] = self._security_headers(
                        list(message.get("headers") or []),
                    )
            await send(message)

        if self._is_privileged_mutation(scope):
            try:
                if self._recovery_store().active_recovery_cases():
                    await self._json_error(
                        hardened_send,
                        status_code=423,
                        detail=(
                            "Administrator operations are temporarily locked "
                            "while a wallet change is pending. Open Security "
                            "& Access to finish or cancel it."
                        ),
                    )
                    return
            except Exception:
                await self._json_error(
                    hardened_send,
                    status_code=503,
                    detail=(
                        "Administrator recovery state is unavailable; "
                        "privileged changes are locked."
                    ),
                )
                return

        if self._is_public_challenge_request(scope):
            source_ip = self._source_ip(scope)
            try:
                allowed = self._get_challenge_limiter().allow(source_ip)
            except Exception:
                await self._json_error(
                    hardened_send,
                    status_code=503,
                    detail="Challenge rate limiter is unavailable.",
                )
                return
            if not allowed:
                await self._json_error(
                    hardened_send,
                    status_code=429,
                    detail="Too many challenge requests. Try again later.",
                )
                return

        if self._is_chia_push_request(scope):
            source_ip = self._source_ip(scope)
            try:
                allowed = self._get_chia_push_limiter().allow(source_ip)
            except Exception:
                await self._json_error(
                    hardened_send,
                    status_code=503,
                    detail="Chia transaction rate limiter is unavailable.",
                )
                return
            if not allowed:
                await self._json_error(
                    hardened_send,
                    status_code=429,
                    detail="Too many Chia transaction submissions. Try again later.",
                )
                return

        content_length = self._content_length(scope)
        if content_length is None:
            await self._json_error(
                hardened_send,
                status_code=400,
                detail="Invalid Content-Length header.",
            )
            return
        if content_length > self.settings.max_request_body_bytes:
            await self._json_error(
                hardened_send,
                status_code=413,
                detail="Request body exceeds the configured limit.",
            )
            return

        received_bytes = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body") or b"")
                if received_bytes > self.settings.max_request_body_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Request body exceeds the configured limit.",
                    )
            return message

        try:
            await asyncio.wait_for(
                self.app(scope, limited_receive, hardened_send),
                timeout=self.settings.request_timeout_seconds,
            )
        except TimeoutError:
            if not response_started:
                await self._json_error(
                    hardened_send,
                    status_code=504,
                    detail="Request processing timed out.",
                )

    def _recovery_store(self) -> Any:
        if self._genesis_store is None:
            from .genesis_store import GenesisStore

            self._genesis_store = GenesisStore(
                self.settings.genesis_db_path
            )
        return self._genesis_store

    @staticmethod
    def _is_privileged_mutation(scope: Mapping[str, Any]) -> bool:
        method = str(scope.get("method") or "").upper()
        path = str(scope.get("path") or "")
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return False
        if not path.startswith("/admin/"):
            return False
        if path.startswith("/admin/security/key-changes"):
            return False
        return path not in {
            "/admin/auth/challenge",
            "/admin/auth/login",
            "/admin/launch/auth/challenge",
            "/admin/launch/auth/login",
        }

    def _security_headers(
        self,
        headers: list[tuple[bytes, bytes]],
    ) -> list[tuple[bytes, bytes]]:
        values = {
            b"cache-control": b"no-store",
            b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
            b"referrer-policy": b"no-referrer",
            b"x-content-type-options": b"nosniff",
            b"x-frame-options": b"DENY",
        }
        if not self.settings.api_docs_enabled:
            values[b"content-security-policy"] = (
                b"default-src 'none'; frame-ancestors 'none'; "
                b"base-uri 'none'; form-action 'none'"
            )
        if (
            self.settings.hsts_enabled
            and self.settings.runtime_environment in {"staging", "production"}
        ):
            values[b"strict-transport-security"] = (
                b"max-age=31536000; includeSubDomains"
            )

        names = set(values)
        hardened = [(name, value) for name, value in headers if name.lower() not in names]
        hardened.extend(values.items())
        return hardened

    @staticmethod
    def _content_length(scope: dict[str, Any]) -> int | None:
        values = [
            value
            for name, value in scope.get("headers") or []
            if name.lower() == b"content-length"
        ]
        if not values:
            return 0
        if len(values) != 1:
            return None
        try:
            length = int(values[0].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return None
        return length if length >= 0 else None

    def _get_challenge_limiter(self) -> RequestRateLimiter:
        if self._challenge_limiter is None:
            self._challenge_limiter = RequestRateLimiter(
                self.settings.challenge_per_ip_per_minute,
                db_path=(
                    None
                    if self.settings.runtime_environment == "test"
                    else self.settings.challenge_store_path
                ),
            )
        return self._challenge_limiter

    def _get_chia_push_limiter(self) -> RequestRateLimiter:
        if self._chia_push_limiter is None:
            self._chia_push_limiter = RequestRateLimiter(
                self.settings.chia_push_per_ip_per_minute,
                db_path=(
                    None
                    if self.settings.runtime_environment == "test"
                    else self.settings.challenge_store_path
                ),
                namespace="http_chia_push_tx",
            )
        return self._chia_push_limiter

    @staticmethod
    def _is_public_challenge_request(scope: dict[str, Any]) -> bool:
        if str(scope.get("method", "")).upper() != "POST":
            return False
        path = str(scope.get("path", "")).rstrip("/")
        if path == "/auth/challenge":
            return True
        parts = path.split("/")
        # Count before route/path/body validation. Canonical ASGI paths are
        # already URL-decoded; a changed vault ID or trailing-slash redirect
        # must not create a new per-IP challenge budget.
        return (len(parts) == 6 and parts[1:3] == ["zkpassport", "enrollments"]
                and parts[4] in {"session", "relay"} and parts[5] == "challenge")

    @staticmethod
    def _is_chia_push_request(scope: dict[str, Any]) -> bool:
        return (
            str(scope.get("method", "")).upper() == "POST"
            and scope.get("path") == "/chia/push_tx"
        )

    def _source_ip(self, scope: dict[str, Any]) -> str:
        return trusted_client_ip(scope, self.settings)

    @staticmethod
    async def _json_error(
        send: AsgiSend,
        *,
        status_code: int,
        detail: str,
    ) -> None:
        body = json.dumps(
            {"detail": detail},
            separators=(",", ":"),
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def trusted_client_ip(scope: Mapping[str, Any], settings: Settings) -> str:
    """Resolve a client IP without accepting spoofable forwarding headers."""
    client = scope.get("client")
    peer = str(client[0]) if isinstance(client, (tuple, list)) and client else "unknown"
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        return peer

    trusted = False
    for value in settings.trusted_proxy_cidr_list():
        try:
            if peer_address in ipaddress.ip_network(value, strict=True):
                trusted = True
                break
        except ValueError:
            continue
    if not trusted:
        return peer_address.compressed

    forwarded = [
        value.decode("ascii", errors="ignore").strip()
        for name, value in scope.get("headers") or []
        if name.lower() == b"cf-connecting-ip"
    ]
    if len(forwarded) != 1:
        return peer_address.compressed
    try:
        return ipaddress.ip_address(forwarded[0]).compressed
    except ValueError:
        return peer_address.compressed


__all__ = [
    "ServerHardeningMiddleware",
    "documentation_urls",
    "trusted_client_ip",
]
