"""Two-person metadata approval must survive normal coordination delays."""

import pytest
from pydantic import ValidationError
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from chia_rs.sized_bytes import bytes32

from solslot_api import admin_operations as operations
from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.config import Settings, get_settings


def request_body(operation="collection.seal", seconds=86_400):
    return {"operation": operation, "revision": 14, "expiresInSeconds": seconds,
            "requestBinding": {"method": "POST", "path": "/admin/collections/TEST-EXAMPLE/seal",
                               "query": [], "body": {}, "ifMatch": '"14"'}}


@pytest.mark.parametrize("operation", sorted(operations.ALLOWED_OPERATIONS - {"collection.seal"}))
def test_other_operations_cannot_extend_their_signing_window(operation):
    with pytest.raises(ValidationError, match="only collection.seal"):
        operations.PrepareOperationRequest.model_validate(request_body(operation, 901))
    assert operations.PrepareOperationRequest.model_validate(request_body(operation, 900)).expires_in_seconds == 900


@pytest.mark.parametrize("seconds", [60, 600, 900, 86_400])
def test_seal_window_is_bounded_and_compatible_with_existing_requests(seconds):
    assert operations.PrepareOperationRequest.model_validate(request_body(seconds=seconds)).expires_in_seconds == seconds


@pytest.mark.parametrize("seconds", [59, 86_401])
def test_seal_window_rejects_out_of_bounds(seconds):
    with pytest.raises(ValidationError):
        operations.PrepareOperationRequest.model_validate(request_body(seconds=seconds))


def test_signed_seal_survives_delay_and_restart_but_never_expiry_or_replay(tmp_path, monkeypatch):
    accounts = [Account.from_key(bytes([i]) * 32) for i in (31, 32, 33)]
    roster = operations.AdminRoster(bytes32(b"\x11" * 32), tuple(
        keys.PrivateKey(bytes(a.key)).public_key.to_compressed_bytes() for a in accounts))
    monkeypatch.setattr(operations, "resolve_admin_roster", lambda _: roster)
    clock = [1_790_000_000]
    monkeypatch.setattr(operations.time, "time", lambda: clock[0])
    path = tmp_path / "admin.sqlite"
    store = [operations.OperationStore(path)]
    settings = Settings(runtime_environment="test", admin_operation_approvals_enabled=True,
                        admin_db_path=str(path), eip712_chain_id=11155111)
    subject = [accounts[0].address.lower()]
    app = FastAPI(); app.include_router(operations.router)
    app.dependency_overrides[require_admin_jwt] = lambda: AdminClaims(
        sub=subject[0], auth_type="evm", iat=clock[0] - 1, exp=clock[0] + 600)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[operations.get_operation_store] = lambda: store[0]

    @app.post("/admin/collections/TEST-EXAMPLE/seal", dependencies=[Depends(operations.require_admin_operation("collection.seal"))])
    async def seal():
        return {"sealed": True}

    client = TestClient(app)

    def prepare():
        response = client.post("/admin/auth/operations/prepare", json=request_body())
        assert response.status_code == 201, response.text
        return response.json()

    def sign(item, slot, signature=None):
        subject[0] = accounts[slot].address.lower()
        signature = signature or "0x" + accounts[slot].sign_message(
            encode_typed_data(full_message=item["typedData"])).signature.hex()
        return client.post(f"/admin/auth/operations/{item['operationId']}/sign", json={"signature": signature})

    item = prepare(); start = clock[0]
    assert item["expiresAt"] - item["createdAt"] == 86_400
    assert item["typedData"]["message"]["expiresAt"] == start + 86_400
    assert sign(item, 0).status_code == 200
    clock[0] = start + 3600
    store[0] = operations.OperationStore(path)
    active = client.get("/admin/auth/operations").json()["operations"]
    assert active[0]["signatures"][0]["adminIndex"] == 0
    assert sign(item, 1).json()["status"] == "approved"
    subject[0] = accounts[0].address.lower()
    headers = {"X-Solslot-Admin-Operation-Id": item["operationId"], "If-Match": '"15"'}
    assert client.post("/admin/collections/TEST-EXAMPLE/seal", json={}, headers=headers).status_code == 409
    headers["If-Match"] = '"14"'
    clock[0] = start + 86_399
    assert client.post("/admin/collections/TEST-EXAMPLE/seal", json={}, headers=headers).status_code == 200
    assert client.post("/admin/collections/TEST-EXAMPLE/seal", json={}, headers=headers).status_code == 409
    assert client.get("/admin/auth/operations", params={"status_filter": "all"}).json()["operations"][0]["status"] == "consumed"

    expired = prepare(); expired_start = clock[0]
    assert sign(expired, 0).status_code == 200
    clock[0] = expired_start + 86_400
    assert sign(expired, 1).status_code == 409
    headers["X-Solslot-Admin-Operation-Id"] = expired["operationId"]
    assert client.post("/admin/collections/TEST-EXAMPLE/seal", json={}, headers=headers).status_code == 409
    assert client.get("/admin/auth/operations").json()["count"] == 0
    recent = client.get("/admin/auth/operations", params={"status_filter": "all"}).json()["operations"]
    assert any(v["operationId"] == expired["operationId"] and len(v["signatures"]) == 1 for v in recent)
    subject[0] = accounts[0].address.lower()
    fresh = prepare()
    old_signature = "0x" + accounts[0].sign_message(encode_typed_data(full_message=expired["typedData"])).signature.hex()
    assert sign(fresh, 0, old_signature).status_code == 409
    assert fresh["operationId"] != expired["operationId"]
