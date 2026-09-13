"""HTTP boundary regressions with real vault-session JWT verification.

Chain/provider fixtures below test routing and authorization only; they are
not deployed bridge or governance proofs.
"""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from solslot_api.config import Settings, get_settings
from solslot_api.credential_auth import VerifiedOwner, issue_vault_session
from solslot_api.sols_capability_operations import CapabilityOperationStore
from solslot_api import sols_market
from solslot_puzzles.vault_driver import AUTH_TYPE_SECP256K1


def h(value: int, size: int = 32) -> str:
    return "0x" + (bytes([value]) * size).hex()


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, runtime_environment="test", network="testnet11",
                        alpha_writes_enabled=False, sols_bridge_enabled=False, sols_liquidity_enabled=False,
                        sols_capability_deployment_id="isolated", sols_capability_release_tag="candidate",
                        sols_capability_source_sha="ab"*20, sols_capability_operations_path=str(tmp_path / "operations.db"),
                        sols_capability_evm_rpc_url="https://rpc.example.invalid")
    record = SimpleNamespace(launcher_id=bytes.fromhex(h(1)[2:]), owner_evm_address=h(2,20), owner_pubkey=b"", auth_type=AUTH_TYPE_SECP256K1)
    monkeypatch.setattr("solslot_api.credential_auth.require_vault_record", lambda _vault: record)
    token, _ = issue_vault_session(settings, VerifiedOwner(owner_key=h(2,20), auth_type="evm", vault_record=record))
    governed = {"routeId": h(3), "active": True}
    receipt = {"schemaVersion": 1, "operationHash": h(4), "vaultLauncherId": h(1), "sourceAccount": h(2,20),
               "capability": "warp-cat-bridge", "network": "testnet11", "environment": "test", "deploymentId": "isolated",
               "releaseTag": "candidate", "sourceSha": "ab"*20, "releaseEvidenceSha256": "cd"*32,
               "governedRoot": h(5), "governedRecord": governed,
               "intent": {"adapterId": "warp-v1", "direction": "EVM_TO_CHIA"}}
    store = CapabilityOperationStore(settings.sols_capability_operations_path)
    store.prepare(receipt)
    store.close()
    evidence = SimpleNamespace(sha256="cd"*32, source_sha="ab"*20, release_tag="candidate", environment="test",
                               network="testnet11", deployment_id="isolated", adapter_descriptors=({"adapterId":"warp-v1", "recordId":h(3)},))
    statutes = {"routesRoot": h(5), "bridgeRoutes": [governed], "confirmedHeight": 10}
    reader = SimpleNamespace(snapshot=AsyncMock(return_value={"statutes":statutes}), provider=object())
    app = FastAPI()
    app.include_router(sols_market.router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[sols_market._reader] = lambda: reader
    monkeypatch.setattr(sols_market, "require_current_approved_vault", lambda *_args: None)
    return SimpleNamespace(settings=settings, record=record, token=token, receipt=receipt, evidence=evidence,
                           statutes=statutes, app=app, headers={"Authorization":"Bearer "+token},
                           path=f"/sols/vaults/{h(1)}/capability-operations/{h(4)}")


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["authorize", "observe", "references"])
async def test_private_operation_endpoints_require_authentication(boundary, endpoint):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path + "/" + endpoint, json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_vault_session_cannot_access_another_vault_operation(boundary):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path.replace(h(1), h(9)) + "/authorize", headers=boundary.headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_authorization_rechecks_canonical_vault_ownership(boundary):
    boundary.record.owner_evm_address = h(9,20)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path + "/authorize", headers=boundary.headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_authorization_rechecks_approved_vault_eligibility(boundary, monkeypatch):
    def revoked(*_args):
        raise HTTPException(status_code=403, detail="current verification revoked")
    monkeypatch.setattr(sols_market, "require_current_approved_vault", revoked)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path + "/authorize", headers=boundary.headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_closed_runtime_gates_reject_prepared_receipt_authorization(boundary):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path + "/authorize", headers=boundary.headers)
    assert response.status_code == 409
    readiness = response.json()["detail"]["readiness"]
    assert next(item["status"] for item in readiness if item["id"] == "operatorGate") == "WAITING"
    assert next(item["status"] for item in readiness if item["id"] == "confirmationObserver") == "WAITING"


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", [None, "record_removed", "record_disabled", "record_changed", "root", "evidence", "release", "source", "deployment", "submitted", "confirmed"])
async def test_authorization_binds_current_record_release_and_unsubmitted_status(boundary, monkeypatch, changed):
    statutes = deepcopy(boundary.statutes)
    records = statutes["bridgeRoutes"]
    if changed == "record_removed": records.clear()
    if changed == "record_disabled": records[0]["active"] = False
    if changed == "record_changed": records[0]["assetId"] = h(9)
    if changed == "root": statutes["routesRoot"] = h(9)
    if changed == "evidence": boundary.evidence.sha256 = "ef"*32
    if changed == "release": boundary.evidence.release_tag = "another"
    if changed == "source": boundary.evidence.source_sha = "ef"*20
    if changed == "deployment": boundary.evidence.deployment_id = "beta"
    if changed in {"submitted", "confirmed"}:
        store = CapabilityOperationStore(boundary.settings.sols_capability_operations_path)
        if changed == "submitted": store.record_hints(h(4), h(1), {"sourceTransactionId": h(9)})
        else: store.record_observation(h(4), h(1), {"operationHash":h(4), "status":"DESTINATION_CONFIRMED"})
        store.close()
    monkeypatch.setattr(sols_market, "_execution_context", AsyncMock(return_value=(statutes, records, boundary.evidence)))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path + "/authorize", headers=boundary.headers)
    if changed:
        assert response.status_code in {404,409}
    else:
        assert response.status_code == 200
        assert response.json()["operationHash"] == h(4)


@pytest.mark.asyncio
async def test_observation_is_available_with_write_gates_closed_without_granting_execution(boundary, monkeypatch):
    monkeypatch.setattr(sols_market, "load_sols_capability_evidence", lambda **_kw: boundary.evidence)
    observe = AsyncMock(return_value={"operationHash": h(4), "status": "AWAITING_SOURCE"})
    monkeypatch.setattr("solslot_api.sols_bridge_observer.WarpCatObserver.observe", observe)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        observed = await client.post(boundary.path + "/observe", json={}, headers=boundary.headers)
        authorized = await client.post(boundary.path + "/authorize", headers=boundary.headers)
    assert observed.status_code == 200
    assert observed.json()["status"] == "AWAITING_SOURCE"
    assert authorized.status_code == 409
    observe.assert_awaited_once()


@pytest.mark.asyncio
async def test_foreign_operation_hash_is_private_even_with_own_valid_session(boundary):
    store = CapabilityOperationStore(boundary.settings.sols_capability_operations_path)
    store.prepare({**boundary.receipt, "operationHash": h(8), "vaultLauncherId": h(9), "sourceAccount": h(10,20)})
    store.close()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=boundary.app), base_url="http://test") as client:
        response = await client.post(boundary.path.replace(h(4), h(8)) + "/references", json={"sourceTransactionId":h(11)}, headers=boundary.headers)
    assert response.status_code == 404
