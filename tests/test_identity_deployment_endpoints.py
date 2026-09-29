from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_operation_v1 import AdminOperationCoreV1

from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.admin_operations import (
    AdminRoster,
    OperationStore,
    canonical_request_binding,
    get_operation_store,
    request_binding_hash,
)
from solslot_api.config import Settings, get_settings
from solslot_api.identity_deployment_endpoints import _identity_action_wire, router
from solslot_api.protocol_submission import ProtocolSubmissionError


AMENDMENT = "0x" + "ab" * 32


def _claims() -> AdminClaims:
    return AdminClaims(
        sub="0x1111111111111111111111111111111111111111",
        auth_type="evm",
        exp=2**31,
        iat=1,
    )


def _approved_store(tmp_path, *, now: int = 1_700_000_000) -> tuple[OperationStore, str]:
    store = OperationStore(tmp_path / "admin.db")
    binding = canonical_request_binding(
        method="POST",
        path="/admin/identity-deployment/activate",
        query=[],
        body={"amendmentHash": AMENDMENT, "revision": 1},
        if_match=None,
    )
    core = AdminOperationCoreV1(
        authority_launcher_id=bytes32(b"\x11" * 32),
        network="testnet11",
        operation="identity.activate",
        payload_hash=request_binding_hash(binding),
        revision=1,
        nonce=bytes32(b"\x22" * 32),
        expires_at=now + 600,
    )
    value = store.create(core=core, binding=binding, created_by=_claims().sub, now=now)
    for slot, address in (
        (0, _claims().sub),
        (1, "0x2222222222222222222222222222222222222222"),
    ):
        store.add_signature(
            operation_id=value["operation_id"],
            admin_index=slot,
            signer_address=address,
            compressed_pubkey="0x" + (bytes([slot + 2]) * 33).hex(),
            signature="0x" + "11" * 65,
            chain_action_id="0x" + bytes([slot + 4]).hex() * 32,
            chain_signature="0x" + "22" * 64,
            now=now,
        )
    return store, value["operation_id"]


class _Bundle:
    def to_json_dict(self):
        return {"coin_spends": [], "aggregated_signature": "0x"}

    def name(self):
        return bytes32(b"\x99" * 32)


def test_identity_action_review_has_identity_specific_copy():
    action = SimpleNamespace(
        signer_slot=0,
        to_wire=lambda *, signed: {
            "title": "Owner approves proposal publication",
            "summary": "Approve this exact SGT allocation",
            "financialEffect": "No sale completes",
            "signed": signed,
        },
    )
    wire = _identity_action_wire(action)
    assert wire["title"] == "Owner approves identity verifier activation"
    assert "zkPassport verifier deployment" in wire["summary"]
    assert wire["financialEffect"] == "No funds or assets move in this approval."


def _client(tmp_path, monkeypatch, submitter):
    from solslot_api import admin_operations, identity_deployment_endpoints as endpoints

    now = 1_700_000_000
    store, operation_id = _approved_store(tmp_path, now=now)
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        admin_operation_approvals_enabled=True,
        protocol_fee_funding_enabled=True,
        admin_db_path=str(tmp_path / "admin.db"),
    )
    monkeypatch.setattr(
        admin_operations,
        "resolve_admin_roster",
        lambda _: AdminRoster(
            bytes32(b"\x11" * 32),
            (bytes([2]) * 33, bytes([3]) * 33, bytes([4]) * 33),
        ),
    )
    monkeypatch.setattr(admin_operations.time, "time", lambda: now)

    build = SimpleNamespace(
        request_body={"amendmentHash": AMENDMENT, "revision": 1},
        statement={"revision": 1},
        statement_hash=AMENDMENT,
    )

    async def prepare(**_kwargs):
        return build

    monkeypatch.setattr(endpoints, "prepare_identity_activation", prepare)
    monkeypatch.setattr(endpoints, "build_identity_activation_bundle", lambda *_: _Bundle())
    monkeypatch.setattr(endpoints, "ProtocolBundleSubmitter", type(submitter))
    monkeypatch.setattr(endpoints.time, "time", lambda: now)

    app = FastAPI()
    app.include_router(router)
    app.state.protocol_submitter = submitter
    app.dependency_overrides[require_admin_jwt] = _claims
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_operation_store] = lambda: store
    return TestClient(app), store, operation_id


def test_failed_submission_keeps_approval_recoverable(tmp_path, monkeypatch):
    class Submitter:
        funding_store = object()

        async def submit(self, *_args, **_kwargs):
            raise ProtocolSubmissionError("node unavailable", submission_attempted=True)

    client, store, operation_id = _client(tmp_path, monkeypatch, Submitter())
    response = client.post(
        "/admin/identity-deployment/activate",
        headers={"X-Solslot-Admin-Operation-Id": operation_id},
        json={"amendmentHash": AMENDMENT, "revision": 1},
    )
    assert response.status_code == 503
    assert store.get(operation_id)["status"] == "approved"


def test_successful_submission_consumes_exact_approval(tmp_path, monkeypatch):
    class Submitter:
        funding_store = object()

        async def submit(self, *_args, **_kwargs):
            return {
                "status": "MEMPOOL",
                "spendBundleId": "0x" + "99" * 32,
            }

    client, store, operation_id = _client(tmp_path, monkeypatch, Submitter())
    response = client.post(
        "/admin/identity-deployment/activate",
        headers={"X-Solslot-Admin-Operation-Id": operation_id},
        json={"amendmentHash": AMENDMENT, "revision": 1},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "MEMPOOL"
    assert response.json()["restartRequired"] is True
    assert client.app.state.identity_deployment_transition == {
        "amendmentHash": AMENDMENT,
        "revision": 1,
        "spendBundleId": "0x" + "99" * 32,
        "submittedAt": 1_700_000_000,
    }
    assert store.get(operation_id)["status"] == "consumed"
