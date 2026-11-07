"""Restore the reviewed browser XSRF boundary around the RC28 identity API.

This operational factory composes two immutable, already-deployed components:
the current Solslot API and the reviewed HTTP boundary.  It does not alter
either component's source.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
from types import ModuleType
from typing import Any


BOUNDARY_SOURCE = Path(
    "/opt/solslot/http-boundary/releases/"
    "cefd6ce8edce82174bc47a87bc4890fe38640aef/solslot_http_boundary.py"
)
BOUNDARY_SHA256 = "074cc60cc6c1136e7f7cdd5b21abb364077614b7674538e6a2a605c846674e73"
EXPECTED_ARTIFACT_HASH = (
    "0xdd313bf4705dfda7f59e3fb8c24cc1862c6a50994ddd74547eaa30c7727c8140"
)
EXPECTED_NETWORK = "testnet11"


def _load_boundary_module() -> ModuleType:
    source = BOUNDARY_SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != BOUNDARY_SHA256:
        raise RuntimeError("reviewed HTTP boundary source hash changed")
    spec = importlib.util.spec_from_file_location("solslot_http_boundary_ae156", BOUNDARY_SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("reviewed HTTP boundary could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_app() -> Any:
    from solslot_api.app import app
    from solslot_api.config import get_settings
    from solslot_api.public_artifact import load_signed_public_artifact

    settings = get_settings()
    artifact = load_signed_public_artifact(settings)
    if settings.network != EXPECTED_NETWORK:
        raise RuntimeError("HTTP boundary network differs from the confirmed release")
    if artifact.get("artifactHash") != EXPECTED_ARTIFACT_HASH:
        raise RuntimeError("HTTP boundary artifact differs from the confirmed release")

    secret = os.environ.get("SOLSLOT_HTTP_BOUNDARY_SECRET", "").encode("utf-8")
    boundary = _load_boundary_module().BrowserXsrfBoundary
    return boundary(app, secret=secret)

