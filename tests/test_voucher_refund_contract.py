"""Real refund routes/models/stores, with synthetic auth and signing/dispatch seams.

These are customer contract tests, not proof of private quorum, wallet signatures,
provider refunds, campaign creation or public-chain inclusion.
"""
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from chia_rs.sized_bytes import bytes32
from solslot_api import presale_endpoints as p
from tests.test_presale_endpoints import approved_vault, stripe_escrowed_voucher, native_escrowed_voucher


def make_refund_contract(monkeypatch, rail="STRIPE_USD", state="PRESALE"):
    now = int(time.time())
    if rail == "STRIPE_USD":
        store, terms, _ = stripe_escrowed_voucher(now=now)
    else:
        store, terms, *_ = native_escrowed_voucher(now=now)
    key = str(terms["termsHash"])
    if state == "CANCELED":
        # A confirmed canceled campaign is the fixture input, not an executed
        # governance transition. Its original refund deadline has elapsed.
        store._conn.execute("UPDATE presale_series_v2 SET state='CANCELED' WHERE terms_hash=?", (key,))
        now = int(terms["refundDeadline"]) + 1
    elif state == "LIVE":
        store._conn.execute("UPDATE presale_series_v2 SET state='LIVE', launched_at=? WHERE terms_hash=?", (now - p.DELIVERY_WINDOW_SECONDS - 1, key))
        store._conn.execute("UPDATE voucher_records_v2 SET state='REDEEMING' WHERE terms_hash=?", (key,))
    calls = dict(approval=0, walletPreparation=0, dispatch=0)
    approved = replace(approved_vault(), current_coin_id="0x" + "55" * 32)
    settings = SimpleNamespace()
    monkeypatch.setattr(p.time, "time", lambda: now)
    monkeypatch.setattr(p, "require_presale_writes", lambda *_: None)
    monkeypatch.setattr(p, "require_operation_gate", lambda *_: None)
    monkeypatch.setattr(p, "verify_vault_session", lambda *_: SimpleNamespace(vault_launcher_id=approved.launcher_id))
    def approval(*args, expected_current_coin_id=None):
        calls["approval"] += 1
        if expected_current_coin_id is not None and expected_current_coin_id != approved.current_coin_id:
            raise HTTPException(409, "The reviewed owner coin changed.")
        return approved
    monkeypatch.setattr(p, "require_current_approved_vault", approval)
    spend = dict(coin=dict(parentCoinInfo="0x"+"88"*32, puzzleHash="0x"+"99"*32, amount=1),
                 puzzleReveal="0x01", solution="0x80")
    async def context(**kwargs):
        calls["walletPreparation"] += 1
        return (SimpleNamespace(name=lambda: bytes32.from_hexstr(approved.current_coin_id)),
                None, SimpleNamespace(auth_type=1), None, object(), None)
    monkeypatch.setattr(p, "_vault_refund_context", context)
    monkeypatch.setattr(p, "_coin_spend_json", lambda _: spend)
    original_complete = p._complete_voucher_refund_locked
    async def dispatch(terms_hash, serial, body, request, store, settings, voucher_json, session, approved):
        calls["dispatch"] += 1
        assert body.voucher_coin_id == voucher_json["voucherOutputCoinId"]
        assert body.series_coin_id == store.get(terms_hash)["chainState"]["currentCoinId"]
        assert body.current_timestamp == now
        assert body.owner_authorization == "0x" + "aa" * 96
        return p.CompleteVoucherRefundResponse(termsHash=key, serial=serial, transactionId="0x"+"bb"*32,
            status="MEMPOOL_ACCEPTED", signerIndices=[0, 1], voucher={**voucher_json, "state": "REFUNDING"})
    monkeypatch.setattr(p, "_complete_voucher_refund_locked", dispatch)
    app = FastAPI()
    app.include_router(p.router, prefix="/protocol-api")
    app.dependency_overrides[p.get_presale_store] = lambda: store
    app.dependency_overrides[p.get_settings] = lambda: settings
    return SimpleNamespace(app=app, store=store, terms=terms, key=key, calls=calls, now=now,
        voucher={**store.voucher(key, 0), "termsHash": key, "seriesState": state,
                 "refundDeadline": int(terms["refundDeadline"])}, original_complete=original_complete)


def completion(prepared):
    return {key: prepared[key] for key in ("vaultCoinId", "voucherCoinId", "seriesCoinId", "currentTimestamp")} | {
        "expectedPurchaseId": prepared["purchaseId"], "ownerAuthorization": "0x" + "aa" * 96}


@pytest.mark.asyncio
@pytest.mark.parametrize("rail", ["STRIPE_USD", "CHIA_XCH"])
@pytest.mark.parametrize("state", ["PRESALE", "CANCELED"])
async def test_generic_refund_contract_preserves_purchase_rail_and_canceled_recovery(monkeypatch, rail, state):
    c = make_refund_contract(monkeypatch, rail, state)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="https://solslot.test") as client:
            path = f"/protocol-api/presales/{c.key}/vouchers/0"
            response = await client.post(path + "/refund-request?contract=purchase-v1", json={})
            assert response.status_code == 200, response.text
            prepared = response.json()
            assert prepared["purchaseId"] == c.voucher["purchaseId"]
            assert prepared["paymentRail"] == rail
            assert prepared["action"] == ("REFUND_CANCELED" if state == "CANCELED" else "REFUND_PRESALE")
            assert "operationRevision" not in prepared
            result = await client.post(path + "/refund-complete", json=completion(prepared))
            assert result.status_code == 200, result.text
            assert result.json()["status"] == "MEMPOOL_ACCEPTED"
            assert c.calls["dispatch"] == 1
            assert c.store._conn.execute("SELECT lease_until FROM voucher_worker_series").fetchone()[0] == 0
    finally:
        c.store._conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation,expected", [("different", 409), ("uppercase", 200), ("omitted", 200), ("phantom_revision", 422)])
async def test_completion_checks_purchase_before_approval_or_lease_and_keeps_old_generic_clients(monkeypatch, mutation, expected):
    c = make_refund_contract(monkeypatch)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="https://solslot.test") as client:
            path = f"/protocol-api/presales/{c.key}/vouchers/0"
            response = await client.post(path + "/refund-request?contract=purchase-v1", json={})
            assert response.status_code == 200, response.text
            body = completion(response.json())
            if mutation == "different": body["expectedPurchaseId"] = "0x" + "ff" * 32
            elif mutation == "uppercase": body["expectedPurchaseId"] = "0x" + body["expectedPurchaseId"][2:].upper()
            elif mutation == "omitted": body.pop("expectedPurchaseId")
            else: body["expectedRevision"] = 8
            before = c.calls["approval"]
            result = await client.post(path + "/refund-complete", json=body)
            assert result.status_code == expected, result.text
            if expected != 200:
                assert c.calls["approval"] == before and c.calls["dispatch"] == 0
                assert c.store._conn.execute("SELECT COUNT(*) FROM voucher_worker_series").fetchone()[0] == 0
    finally:
        c.store._conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["voucherCoinId", "seriesCoinId"])
async def test_real_completion_rejects_changed_reviewed_coin_before_private_execution(monkeypatch, field):
    c = make_refund_contract(monkeypatch)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="https://solslot.test") as client:
            path = f"/protocol-api/presales/{c.key}/vouchers/0"
            response = await client.post(path + "/refund-request?contract=purchase-v1", json={})
            assert response.status_code == 200, response.text
            body = completion(response.json()); body[field] = "0x" + "fe" * 32
            monkeypatch.setattr(p, "_complete_voucher_refund_locked", c.original_complete)
            result = await client.post(path + "/refund-complete", json=body)
            assert result.status_code == 409 and "inputs changed" in result.text
            assert c.calls["dispatch"] == 0
            assert c.store._conn.execute("SELECT lease_until FROM voucher_worker_series").fetchone()[0] == 0
    finally:
        c.store._conn.close()


@pytest.mark.asyncio
async def test_launched_timeout_refund_does_not_request_an_owner_signature(monkeypatch):
    c = make_refund_contract(monkeypatch, state="LIVE")
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="https://solslot.test") as client:
            result = await client.post(f"/protocol-api/presales/{c.key}/vouchers/0/refund-request", json={})
            assert result.status_code == 409 and "automatically" in result.text
            assert c.calls["walletPreparation"] == 0 and c.calls["dispatch"] == 0
    finally:
        c.store._conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("rail", ["STRIPE_USD", "CHIA_XCH"])
async def test_legacy_preparation_omits_expanded_fields_and_unknown_contract_fails_early(monkeypatch, rail):
    c = make_refund_contract(monkeypatch, rail)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="https://solslot.test") as client:
            path = f"/protocol-api/presales/{c.key}/vouchers/0/refund-request"
            invalid = await client.post(path + "?contract=unsupported", json={})
            assert invalid.status_code == 422
            assert c.calls == dict(approval=0, walletPreparation=0, dispatch=0)
            response = await client.post(path, json={})
            assert response.status_code == 200, response.text
            assert "purchaseId" not in response.json() and "paymentRail" not in response.json()
            assert "typedData" in response.json()
            assert response.json()["action"] == "REFUND_PRESALE"
    finally:
        c.store._conn.close()
