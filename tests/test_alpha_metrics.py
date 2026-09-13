"""Tests for the Alpha operational metrics endpoint."""
from __future__ import annotations

from fastapi.routing import APIRoute

from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.alpha_metrics import alpha_metrics, router
from solslot_api.config import Settings


def _claims() -> AdminClaims:
    return AdminClaims(
        sub="0x" + "11" * 20,
        auth_type="evm",
        iat=1,
        exp=2_000_000_000,
    )


def test_metrics_route_declares_admin_authentication() -> None:
    route = next(
        route
        for route in router.routes
        if isinstance(route, APIRoute) and route.path == "/alpha/metrics"
    )
    dependencies = {dependency.call for dependency in route.dependant.dependencies}
    assert require_admin_jwt in dependencies


def test_metrics_returns_aggregate_snapshot() -> None:
    body = alpha_metrics(Settings(runtime_environment="test", admin_db_path=":memory:"), _claims())
    assert "timestamp" in body
    assert "flags" in body
    assert "presale" in body
    assert "telemetry" in body
    assert isinstance(body["flags"]["alpha_writes_enabled"], bool)
    assert isinstance(body["flags"]["minting_enabled"], bool)
    assert isinstance(body["flags"]["payment_omnichain_enabled"], bool)


def test_metrics_contains_no_secrets() -> None:
    body_str = str(alpha_metrics(Settings(runtime_environment="test", admin_db_path=":memory:"), _claims()))
    for sensitive in ["token", "secret", "password", "key", "jwt", "private"]:
        assert sensitive not in body_str.lower() or sensitive in ("telemetry_event_count",)
