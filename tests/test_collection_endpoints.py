from __future__ import annotations

import time
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from chia_rs.sized_bytes import bytes32

from solslot_api.admin_auth import AdminClaims, require_admin_jwt
from solslot_api.collection_endpoints import router
from solslot_api.collection_store import CollectionStore, get_collection_store
from solslot_api.config import Settings, get_settings


def _claims(subject: str = "0xowner") -> AdminClaims:
    now = int(time.time())
    return AdminClaims(sub=subject, auth_type="evm", iat=now, exp=now + 300)


def _client(tmp_path, *, enabled: bool = True) -> tuple[TestClient, CollectionStore, FastAPI]:
    settings = Settings(
        runtime_environment="test",
        collection_metadata_enabled=enabled,
        collection_minting_enabled=False,
        admin_db_path=str(tmp_path / "collections.db"),
    )
    store = CollectionStore(settings.admin_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_collection_store] = lambda: store
    app.dependency_overrides[require_admin_jwt] = lambda: _claims()
    return TestClient(app), store, app


def _draft(collection_id: str, revision: int, title: str = "17 Harbor Street") -> dict:
    return {
        "schemaVersion": "solslot.property-dossier.v1",
        "collectionId": collection_id,
        "revision": revision,
        "title": title,
        "property": {"address": {}},
        "media": [],
        "risks": [],
        "documents": [],
        "history": [],
        "disclosures": [],
        "dataSources": [],
        "deedAllocation": [],
    }


def test_feature_gate_and_revisioned_draft_round_trip(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("solslot_api.collection_recovery_health.read_receipt", lambda: {
        "checkedAt": time.time(), "restoredAt": time.time(),
    })
    client, store, _app = _client(tmp_path)
    try:
        flags = client.get("/admin/collections/feature-status")
        assert flags.status_code == 200
        assert flags.json()["metadataEnabled"] is True
        assert flags.json()["metadataConfigured"] is True
        assert flags.json()["recovery"]["healthy"] is True

        created = client.post(
            "/admin/collections",
            json={"collectionId": "HARBOR-17", "title": "17 Harbor Street"},
        )
        assert created.status_code == 201
        assert created.headers["etag"] == '"1"'

        updated = client.put(
            "/admin/collections/HARBOR-17",
            headers={"If-Match": '"1"'},
            json=_draft("HARBOR-17", 1, "Harbor Collection"),
        )
        assert updated.status_code == 200
        assert updated.json()["revision"] == 2
        assert updated.headers["etag"] == '"2"'

        conflict = client.put(
            "/admin/collections/HARBOR-17",
            headers={"If-Match": '"1"'},
            json=_draft("HARBOR-17", 1, "Stale browser"),
        )
        assert conflict.status_code == 409
        assert "current 2" in conflict.json()["detail"]
    finally:
        client.close()
        store.close()


def test_feature_status_pauses_authoring_when_recovery_is_unavailable(tmp_path, monkeypatch) -> None:
    def stale():
        raise ValueError("Recovery receipt is stale")
    monkeypatch.setattr("solslot_api.collection_recovery_health.read_receipt", stale)
    client, store, _app = _client(tmp_path)
    try:
        status = client.get("/admin/collections/feature-status").json()
        assert status["metadataConfigured"] is True
        assert status["metadataEnabled"] is False
        assert status["recovery"] == {"healthy": False, "checkedAt": None, "restoredAt": None}
        assert status["mintingEnabled"] is False
    finally:
        client.close()
        store.close()


def test_collection_identifier_is_generated_server_side(tmp_path) -> None:
    client, store, _app = _client(tmp_path)
    try:
        created = client.post(
            "/admin/collections",
            json={"title": "127 Eastmoreland Street"},
        )
        assert created.status_code == 201
        payload = created.json()
        assert payload["id"].startswith("COL-")
        assert len(payload["id"]) == 20
        assert payload["dossier"]["title"] == "127 Eastmoreland Street"
    finally:
        client.close()
        store.close()


def test_display_unit_conversion_derives_protocol_values_from_signed_sources(
    tmp_path, monkeypatch
) -> None:
    client, store, _app = _client(tmp_path)
    oracle_round = SimpleNamespace(
        network="testnet11",
        price_usd_minor_per_asset=200_000,
        asset_decimals=12,
        valid_until=int(time.time()) + 600,
        round_hash=bytes32(bytes.fromhex("42" * 32)),
    )
    monkeypatch.setattr(
        "solslot_api.collection_endpoints._signed_governance_threshold",
        lambda _settings: 500_000,
    )
    monkeypatch.setattr(
        "solslot_api.collection_endpoints.load_authorized_oracle_round",
        lambda _settings, **_kwargs: SimpleNamespace(round=oracle_round),
    )
    try:
        response = client.post(
            "/admin/collections/display-units/convert",
            json={
                "money": {
                    "marketValue": "825000.00",
                    "targetRaise": "500000.00",
                },
                "percentages": {
                    "technologyFee": "2.50",
                    "projectedReturn": "6.25",
                },
                "ownershipShares": {"deed.0": "60", "deed.1": "40"},
                "deriveXchPar": True,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["moneyMinor"]["targetRaise"] == "50000000"
        assert body["percentageBps"] == {
            "technologyFee": "250",
            "projectedReturn": "625",
        }
        assert body["ownershipPpm"] == {"deed.0": 600_000, "deed.1": 400_000}
        assert body["governanceQuorum"] == "500000"
        assert body["xchParMojos"] == {
            "collection": "250000000000000",
            "deeds": {
                "deed.0": "150000000000000",
                "deed.1": "100000000000000",
            },
        }
        assert body["xchOracle"]["roundHash"] == "0x" + "42" * 32
    finally:
        client.close()
        store.close()


def test_display_unit_conversion_fails_closed_on_bad_fee(tmp_path, monkeypatch) -> None:
    client, store, _app = _client(tmp_path)
    monkeypatch.setattr(
        "solslot_api.collection_endpoints._signed_governance_threshold",
        lambda _settings: 500_000,
    )
    try:
        response = client.post(
            "/admin/collections/display-units/convert",
            json={
                "money": {},
                "percentages": {"technologyFee": "10.01"},
                "ownershipShares": {},
                "deriveXchPar": False,
            },
        )
        assert response.status_code == 422
        assert "too large" in response.json()["detail"]
    finally:
        client.close()
        store.close()


def test_all_admins_can_comment_but_only_owner_can_seal(tmp_path) -> None:
    client, store, app = _client(tmp_path)
    try:
        client.post(
            "/admin/collections",
            json={"collectionId": "HARBOR-17", "title": "17 Harbor Street"},
        )
        app.dependency_overrides[require_admin_jwt] = lambda: _claims("0xreviewer")
        comment = client.post(
            "/admin/collections/HARBOR-17/comments",
            json={"section": "legal", "body": "Confirm the filing reference."},
        )
        assert comment.status_code == 201
        assert comment.json()["actorSubject"] == "0xreviewer"

        sealed = client.post(
            "/admin/collections/HARBOR-17/seal",
            headers={"If-Match": '"1"'},
            json={},
        )
        assert sealed.status_code == 403
        assert "owner" in sealed.json()["detail"]
    finally:
        client.close()
        store.close()


def test_metadata_feature_disabled_blocks_workspace_mutation(tmp_path) -> None:
    client, store, _app = _client(tmp_path, enabled=False)
    try:
        assert client.get("/admin/collections/feature-status").status_code == 200
        response = client.post(
            "/admin/collections",
            json={"collectionId": "HARBOR-17", "title": "17 Harbor Street"},
        )
        assert response.status_code == 503
    finally:
        client.close()
        store.close()


def test_public_endpoint_hides_unpublished_drafts(tmp_path) -> None:
    client, store, _app = _client(tmp_path)
    try:
        client.post(
            "/admin/collections",
            json={"collectionId": "HARBOR-17", "title": "17 Harbor Street"},
        )
        response = client.get("/public/collections/HARBOR-17")
        assert response.status_code == 404
    finally:
        client.close()
        store.close()
