from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter
from fastapi.routing import APIRoute

from solslot_api import admin, admin_auth, mint_endpoints
from solslot_api.app import app
from solslot_api.admin import require_admin_token
from solslot_api.admin_auth import require_admin_jwt


def _api_routes(router: APIRouter) -> list[APIRoute]:
    return [route for route in router.routes if isinstance(route, APIRoute)]


def _route_keys(router: APIRouter) -> set[tuple[str, str]]:
    return {
        (method, route.path)
        for route in _api_routes(router)
        for method in (route.methods or set())
        if method not in {"HEAD", "OPTIONS"}
    }


def _route(router: APIRouter, method: str, path: str) -> APIRoute:
    matches = [
        route
        for route in _api_routes(router)
        if route.path == path and method in (route.methods or set())
    ]
    assert len(matches) == 1
    return matches[0]


def _dependency_calls(route: APIRoute) -> set[Callable[..., object]]:
    calls: set[Callable[..., object]] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dependant = stack.pop()
        calls.add(dependant.call)
        stack.extend(dependant.dependencies)
    return calls


def test_mint_admin_routes_are_jwt_gated() -> None:
    expected = {
        ("POST", "/admin/mint/propose"),
        ("GET", "/admin/mint"),
        ("GET", "/admin/mint/{proposal_id}"),
        ("POST", "/admin/mint/{proposal_id}/cancel"),
        ("POST", "/admin/mint/{proposal_id}/publish"),
        ("POST", "/admin/mint/{proposal_id}/execute"),
    }

    actual = {
        key
        for key in _route_keys(mint_endpoints.router)
        if key[1].startswith("/admin/mint")
    }

    assert actual == expected
    for method, path in expected:
        calls = _dependency_calls(_route(mint_endpoints.router, method, path))
        assert require_admin_jwt in calls
        assert require_admin_token not in calls


def test_committee_route_auth_boundaries_are_explicit() -> None:
    public = {
        ("GET", "/admin/committee/proposals"),
        ("POST", "/admin/committee/vote"),
    }
    operator = {
        ("POST", "/admin/committee/propose"),
        ("POST", "/admin/committee/execute"),
    }

    actual = {
        key
        for key in _route_keys(mint_endpoints.router)
        if key[1].startswith("/admin/committee")
    }

    assert actual == public | operator
    for method, path in public:
        calls = _dependency_calls(_route(mint_endpoints.router, method, path))
        assert require_admin_jwt not in calls
        assert require_admin_token not in calls
    for method, path in operator:
        calls = _dependency_calls(_route(mint_endpoints.router, method, path))
        assert require_admin_jwt in calls
        assert require_admin_token not in calls


def test_admin_auth_private_reads_and_refresh_are_jwt_gated() -> None:
    assert _route_keys(admin_auth.router) == {
        ("POST", "/admin/auth/challenge"),
        ("POST", "/admin/auth/login"),
        ("GET", "/admin/auth/authority_v2"),
        ("POST", "/admin/auth/eip712/compute_leaf_hash"),
        ("POST", "/admin/auth/refresh"),
        ("GET", "/admin/auth/session"),
    }

    jwt_routes = {
        (method, path)
        for method, path in _route_keys(admin_auth.router)
        if require_admin_jwt in _dependency_calls(_route(admin_auth.router, method, path))
    }

    assert jwt_routes == {
        ("GET", "/admin/auth/authority_v2"),
        ("POST", "/admin/auth/refresh"),
        ("GET", "/admin/auth/session"),
    }


def test_protocol_operator_routes_have_explicit_authority_boundaries() -> None:
    chain_admin_routes = {
        ("POST", "/admin/zkpassport/bridge-pool/top-up"),
    }
    assert _route_keys(admin.router) == chain_admin_routes
    for method, path in chain_admin_routes:
        calls = _dependency_calls(_route(admin.router, method, path))
        assert require_admin_jwt in calls
        assert require_admin_token not in calls


def test_retired_bootstrap_routes_are_not_mounted() -> None:
    mounted = {
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
    }
    assert not any(path.startswith("/admin/bootstrap") for path in mounted)
    assert "/admin/deployment" not in mounted
    assert "/admin/protocol-config/finalize" not in mounted
