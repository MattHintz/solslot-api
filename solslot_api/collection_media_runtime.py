"""Compose the bounded capability surface without changing the XSRF boundary."""
from __future__ import annotations

from typing import Any

from .config import Settings


def with_local_collection_media(app: Any, settings: Settings) -> Any:
    if settings.collection_storage_backend != "filesystem":
        return app
    from .collection_local_storage import PREFIX, create_media_app

    media = create_media_app(settings)

    async def dispatch(scope: Any, receive: Any, send: Any) -> None:
        # Exact namespace only. All ordinary API/auth/chain writes continue
        # through the original reviewed browser XSRF boundary.
        if scope.get("type") == "http" and str(scope.get("path", "")).startswith(PREFIX + "/"):
            await media(scope, receive, send)
        else:
            await app(scope, receive, send)
    return dispatch
