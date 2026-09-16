"""Validated public build identity for one immutable API release."""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ReleaseMetadata(BaseModel):
    schemaVersion: int = 2
    protocolVersion: str = "solslot-v2"
    apiCommit: str
    protocolCommit: str
    builtAtUtc: str
    packageName: str
    appModule: str


@cache
def load_release_metadata(path_text: str) -> ReleaseMetadata | None:
    return read_release_metadata(path_text)


def read_release_metadata(path_text: str) -> ReleaseMetadata | None:
    """Read current identity across an authorization-to-use boundary."""
    path = Path(path_text)
    if not path.is_file():
        return None
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("release.json must contain an object")
    if raw.get("schemaVersion") != 2:
        raise ValueError("release.json schemaVersion must be 2")
    if raw.get("protocolVersion") != "solslot-v2":
        raise ValueError("release.json protocolVersion must be solslot-v2")
    api_commit = str(raw.get("api_commit", ""))
    protocol_commit = str(raw.get("protocol_commit", ""))
    if not _COMMIT_RE.fullmatch(api_commit):
        raise ValueError("release.json api_commit must be an exact commit SHA")
    if not _COMMIT_RE.fullmatch(protocol_commit):
        raise ValueError("release.json protocol_commit must be an exact commit SHA")
    return ReleaseMetadata(
        apiCommit=api_commit,
        protocolCommit=protocol_commit,
        builtAtUtc=str(raw.get("built_at_utc", "")),
        packageName=str(raw.get("package_name", "")),
        appModule=str(raw.get("app_module", "")),
    )


__all__ = ["ReleaseMetadata", "load_release_metadata", "read_release_metadata"]
