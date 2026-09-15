"""Test-suite-wide fixtures for solslot_api.

The module-level env masking forces all admin-related env vars to
empty strings (or absent for integer-typed ones) so the operator's
local ``.env`` — which may carry sign-in credentials for portal dev —
doesn't leak into test runs that deliberately exercise the
"admin desk disabled" path.

We mask at module-import time (rather than via an autouse fixture)
because per-test fixtures like ``fresh_settings`` use
``monkeypatch.delenv`` to remove specific keys.  ``delenv`` clears
the env, and Pydantic then falls back to ``.env``.  Pre-emptively
writing empty strings into ``os.environ`` masks ``.env`` even after
``delenv`` runs (because the original value is already empty).

Tests that WANT a specific admin env value still set it via
``monkeypatch.setenv`` — that takes precedence and reverts back to
the empty masked state at test end.
"""
from __future__ import annotations

import gc
import os
from contextlib import contextmanager
from functools import wraps

import pytest
from starlette.testclient import TestClient


# String-typed admin env vars.  Pre-emptively masked to "" so
# Pydantic ``.env`` fallback can't smuggle a value through any
# combination of ``delenv`` / ``setenv`` per-test setup.
_ADMIN_ENV_STR_KEYS = (
    "SOLSLOT_ADMIN_PUBKEY_ALLOWLIST",
    "SOLSLOT_ADMIN_JWT_SECRET",
    "SOLSLOT_ADMIN_RECORDS_PATH",
    "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_LAUNCHER_ID",
    "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_MIPS_ROOT_HASH",
    "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_ADMINS_HASH",
    "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_PENDING_OPS_HASH",
)

# Integer-typed admin env vars.  Removed entirely — empty string would
# fail Pydantic int validation, and Pydantic's model defaults are the
# correct "absence" semantics.
_ADMIN_ENV_INT_KEYS = (
    "SOLSLOT_ADMIN_JWT_TTL_SECONDS",
    "SOLSLOT_ADMIN_LOGIN_PER_IP_PER_MINUTE",
    "SOLSLOT_PROTOCOL_ADMIN_AUTHORITY_V2_VERSION",
)


# ── Module-level env mask (runs once per pytest session) ──────────────
# Apply BEFORE any test imports solslot_api.config so the empty values
# baseline persists across monkeypatch save/restore cycles.
for _key in _ADMIN_ENV_STR_KEYS:
    os.environ[_key] = ""
for _key in _ADMIN_ENV_INT_KEYS:
    os.environ.pop(_key, None)

# Security tests override this explicitly when exercising the launch lock.
# The rest of the historical endpoint suite runs inside an enabled testnet
# harness rather than silently depending on a production default.
os.environ["SOLSLOT_ALPHA_WRITES_ENABLED"] = "true"
os.environ["SOLSLOT_MINTING_ENABLED"] = "true"
os.environ["SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH"] = "0x" + "c1" * 32
os.environ["SOLSLOT_RUNTIME_ENVIRONMENT"] = "test"
os.environ["SOLSLOT_API_DOCS_ENABLED"] = "true"
os.environ["SOLSLOT_CORS_ORIGINS"] = "http://localhost:4200,http://localhost:5173"
# Historical endpoint tests isolate handler behavior. Brick 3 has dedicated
# tests with this enabled to prove deployed owner-plus-one enforcement.
os.environ["SOLSLOT_ADMIN_OPERATION_APPROVALS_ENABLED"] = "false"


@pytest.fixture(scope="session", autouse=True)
def _collect_before_test_client_portals():
    """Finalize prior test-thread CLVM cycles before any client starts a portal.

    A module-import heuristic misses helpers imported from other test modules.
    Cover both lifespan clients and requests made without a context manager;
    retain strict unraisable warnings so actual foreign-thread leaks still fail.
    """
    original_enter = TestClient.__enter__
    original_portal = TestClient._portal_factory

    @wraps(original_enter)
    def enter(client):
        gc.collect()
        return original_enter(client)

    @contextmanager
    @wraps(original_portal)
    def portal(client):
        if client.portal is None:
            gc.collect()
        with original_portal(client) as active:
            yield active

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(TestClient, "__enter__", enter)
        patch.setattr(TestClient, "_portal_factory", portal)
        yield


@pytest.fixture(autouse=True)
def _admin_state_reset():
    """Clear cached state between tests so per-test env changes
    actually re-flow through ``get_settings``.

    Without this, a previous test that set
    ``SOLSLOT_ADMIN_RECORDS_PATH`` (e.g. via monkeypatch) leaves a
    cached Settings instance pointing at the temp file even after
    monkeypatch rolls back — subsequent tests' TestClient lifespan
    sees a stale records_path and fails the boot validator.
    """
    # Clear the @lru_cache around get_settings so the next consumer
    # rebuilds Settings from current env.
    try:
        from solslot_api.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass

    # Drop the Phase 2.5 mtime-keyed records cache so a temp path
    # from a previous test doesn't survive into the next one.
    try:
        from solslot_api.admin_records import clear_admin_records_cache
        clear_admin_records_cache()
    except ImportError:
        pass
    try:
        from solslot_api.credential_ledger import reset_credential_ledgers_for_tests
        reset_credential_ledgers_for_tests()
    except ImportError:
        pass
    try:
        from solslot_api.collection_store import reset_collection_store_for_tests
        reset_collection_store_for_tests()
    except ImportError:
        pass
    yield

    try:
        from solslot_api.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass
    try:
        from solslot_api.admin_records import clear_admin_records_cache
        clear_admin_records_cache()
    except ImportError:
        pass
    try:
        from solslot_api.credential_ledger import reset_credential_ledgers_for_tests
        reset_credential_ledgers_for_tests()
    except ImportError:
        pass
    try:
        from solslot_api.collection_store import reset_collection_store_for_tests
        reset_collection_store_for_tests()
    except ImportError:
        pass
