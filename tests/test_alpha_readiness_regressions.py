"""Local HTTP/store contracts; these tests do not prove chain settlement."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
import httpx

from solslot_api import alpha_observability, funded_redemptions, presale_endpoints
from solslot_api.admin_auth import AdminClaims
from solslot_api.alpha_observability import (
    AlphaBugReportRequest, AlphaObservabilityStore, AlphaTelemetryRequest,
)
from solslot_api.config import Settings, get_settings
from solslot_api.governance_queue import GovernanceQueueStore
from tests.test_collection_store import verified_store


def _claims() -> AdminClaims:
    return AdminClaims(sub="0x" + "11" * 20, auth_type="evm", iat=1, exp=2_000_000_000)


@pytest.mark.parametrize("authorization", [None, "0x" + "22" * 65])
@pytest.mark.asyncio
async def test_redemption_http_body_reaches_context_for_both_wallet_types(
    authorization, monkeypatch, tmp_path,
) -> None:
    settings = Settings(
        runtime_environment="test", network="testnet11",
        funded_redemptions_enabled=True, alpha_writes_enabled=True,
        launch_control_enabled=False, admin_db_path=str(tmp_path / "redemptions.db"),
    )
    queue = GovernanceQueueStore(":memory:")
    observed = []

    async def unavailable_chain_context(**kwargs):
        observed.append(kwargs["owner_authorization"])
        raise HTTPException(503, "Isolated chain fixture is unavailable")

    monkeypatch.setattr(funded_redemptions, "verify_vault_session", lambda *_: object())
    monkeypatch.setattr(funded_redemptions, "_find_redemption", lambda *_: (object(), object()))
    monkeypatch.setattr(funded_redemptions, "_redemption_context", unavailable_chain_context)
    app = FastAPI()
    app.include_router(funded_redemptions.router)
    async def settings_override():
        return settings
    async def queue_override():
        return queue
    app.dependency_overrides[get_settings] = settings_override
    app.dependency_overrides[funded_redemptions.get_governance_queue_store] = queue_override
    body = {"operationHash": "0x" + "33" * 32}
    if authorization is None:
        body["aggregatedSignature"] = "0x" + "44" * 96
    else:
        body["vaultOwnerAuthorization"] = authorization
    ids = ["0x" + char * 64 for char in ("5", "6", "7")]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
        response = await client.post("/redemptions/vaults/" + "/".join(ids) + "/complete", json=body)
    assert response.status_code == 503, response.text
    assert response.json()["detail"] == "Isolated chain fixture is unavailable"
    assert observed == [authorization]


def test_redemption_reads_real_collection_projection_and_keeps_mint_gate() -> None:
    collections, collection = verified_store()
    queue = GovernanceQueueStore(":memory:")
    try:
        assert len(collections.get(collection["id"])["deeds"]) == 2
        with pytest.raises(HTTPException) as rejected:
            funded_redemptions.create_funded_redemption(
                funded_redemptions.CreateFundedRedemption(
                    collectionId=collection["id"], title="Test redemption", totalPaymentUsd="100.00",
                ),
                Settings(runtime_environment="test", funded_redemptions_enabled=True, sgt_allocations_enabled=True),
                _claims(), collections, SimpleNamespace(get=lambda _: None), queue,
            )
        assert rejected.value.status_code == 409
        assert rejected.value.detail == "Every SmartDeed must be minted before redemption."
        assert queue.list() == []
    finally:
        collections.close()


def test_metrics_reads_persisted_rows_and_distinguishes_storage_failure(monkeypatch, tmp_path) -> None:
    path = str(tmp_path / "operations.db")
    intake_path = path + ".alpha-observability.db"
    store = AlphaObservabilityStore(intake_path)
    store.telemetry(AlphaTelemetryRequest(
        event="PRACTICE_STARTED", correlation_id="synthetic-test-01",
        release_sha="a" * 40, artifact_hash="0x" + "b" * 64,
    ), "192.0.2.1")
    store.report(AlphaBugReportRequest(
        category="UI", summary="Synthetic local report", description="Local metrics integration fixture",
    ), "192.0.2.1")
    store._conn.close()
    reopened = AlphaObservabilityStore(intake_path)
    presale = presale_endpoints.PresaleStore(path)
    # Populate the actual current schema without a provider or payment call.
    with presale.txn() as cur:
        cur.execute(
            "INSERT INTO presale_series_v2 "
            "(terms_hash,series_singleton_id,collection_id,terms_json,state,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("0x" + "1" * 64, "0x" + "2" * 64, "synthetic-test", "{}", "PRESALE", 1, 1),
        )
        for serial, state in enumerate(("ESCROWED", "ESCROWED", "REFUNDED")):
            marker = f"synthetic-{serial}"
            cur.execute(
                "INSERT INTO voucher_records_v2 "
                "(terms_hash,serial,deed_launcher_id,payment_rail,payment_principal,"
                "base_price_minor,technology_fee_bps,technology_fee_minor,gross_price_minor,"
                "original_payer,vault_launcher_id,vault_p2_puzzle_hash,purchase_id,global_payment_id,"
                "commitment_hash,commitment_json,state,payment_evidence_id,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("0x" + "1" * 64, serial, marker, "STRIPE_USD", 100, 100, 0, 0, 100,
                 marker, marker, marker, marker, marker, marker, "{}", state, marker, 1, 1),
            )
    monkeypatch.setattr(alpha_observability, "_store", reopened)
    monkeypatch.setattr(presale_endpoints, "_store", presale)
    monkeypatch.setattr(presale_endpoints, "_store_path", path)
    from solslot_api.alpha_metrics import alpha_metrics
    settings = Settings(runtime_environment="test", admin_db_path=path)
    try:
        body = alpha_metrics(settings, _claims())
        assert body["telemetry"] == {"available": True, "telemetry_event_count": 1, "bug_report_count": 1}
        assert body["presale"] == {
            "available": True, "series_by_phase": {"PRESALE": 1},
            "vouchers_by_status": {"ESCROWED": 2, "REFUNDED": 1}, "active_voucher_count": 2,
        }
        reopened._conn.close()
        assert alpha_metrics(settings, _claims())["telemetry"] == {"available": False}
        presale._conn.close()
        assert alpha_metrics(settings, _claims())["presale"] == {"available": False}
    finally:
        presale._conn.close()


def test_metrics_uses_the_selected_store_and_reports_a_real_empty_count(monkeypatch, tmp_path):
    from solslot_api.alpha_metrics import alpha_metrics
    other = AlphaObservabilityStore(str(tmp_path / "other-environment.db"))
    other.telemetry(AlphaTelemetryRequest(
        event="PRACTICE_STARTED", correlation_id="synthetic-other-01",
        release_sha="a" * 40, artifact_hash="0x" + "b" * 64,
    ), "192.0.2.1")
    monkeypatch.setattr(alpha_observability, "_store", other)
    monkeypatch.setattr(presale_endpoints, "_store", None)
    monkeypatch.setattr(presale_endpoints, "_store_path", None)
    try:
        result = alpha_metrics(Settings(runtime_environment="test", admin_db_path=str(tmp_path / "selected.db")), _claims())
        assert result["telemetry"] == {"available": True, "telemetry_event_count": 0, "bug_report_count": 0}
        assert result["presale"] == {"available": True, "series_by_phase": {}, "vouchers_by_status": {}, "active_voucher_count": 0}
    finally:
        other._conn.close()
        alpha_observability._store._conn.close()
        presale_endpoints._store._conn.close()


def _executed_redemption(queue, number, settlement):
    marker = "0x" + f"{number:064x}"
    row = queue.create(kind="FUNDED_REDEMPTION", title="Synthetic redemption",
        bill={"settlementId": settlement}, bill_clvm_hex="0x80", proposal_hash=marker,
        actor="test-author", now=number)
    for target in ("READY", "ACTIVE", "EXECUTED"):
        row = queue.transition(proposal_id=row.id, expected_revision=row.revision,
            target=target, actor="test-reviewer", activation_bundle_id=marker,
            proposal_coin_id=marker, completion_bundle_id=marker, now=number)
    return row


def test_redemption_lookup_survives_queue_growth_and_restart_and_rejects_ambiguity(monkeypatch, tmp_path):
    from chia_rs.sized_bytes import bytes32
    path = str(tmp_path / "governance.db")
    queue = GovernanceQueueStore(path)
    settlement = "0x" + "ab" * 32
    deed = bytes32.fromhex("cd" * 32)
    allocation = SimpleNamespace(deed_launcher_id=deed)
    monkeypatch.setattr(funded_redemptions, "_funded_redemption_plan", lambda _: SimpleNamespace(allocations=[allocation]))
    for number in range(1, 106):
        _executed_redemption(queue, number, "0x" + f"{number:064x}")
    target = _executed_redemption(queue, 106, settlement)
    assert target.id not in {row.id for row in queue.list(public=True)}
    queue._conn.close()
    reopened = GovernanceQueueStore(path)
    try:
        found, found_allocation = funded_redemptions._find_redemption(reopened, settlement.upper().replace("0X", "0x"), "0x" + deed.hex())
        assert found.id == target.id
        assert found_allocation is allocation
        with pytest.raises(HTTPException) as missing:
            funded_redemptions._find_redemption(reopened, "0x" + "ef" * 32, "0x" + deed.hex())
        assert missing.value.status_code == 404
        _executed_redemption(reopened, 107, settlement)
        with pytest.raises(HTTPException) as ambiguous:
            funded_redemptions._find_redemption(reopened, settlement, "0x" + deed.hex())
        assert ambiguous.value.status_code == 404
    finally:
        reopened._conn.close()
