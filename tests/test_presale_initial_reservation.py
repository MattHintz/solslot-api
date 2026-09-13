"""Reachable initial presale reservations; no extension or public-chain proof.

Real loader, route, independent validator verification, SQLite signature ledger
and signed CLVM. Authority, owner registry, node and fee transport are fixtures.
"""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from chia.wallet.wallet_spend_bundle import WalletSpendBundle

from solslot_api import native_purchases as native, presale_endpoints
from solslot_api import validator_service as validators
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_puzzles.payment_artifacts_v3 import PurchaseKind
from tests.test_inventory_buyer_handoff import handoff_case, reserve, assert_signed
from tests.test_inventory_timeout_recovery import record, hx, _b32
from tests.test_inventory_authorization_expiry import NOW
from tests.test_current_stripe_voucher_delivery import consensus, voucher_case


async def presale_case(tmp_path, monkeypatch, recovery, *, equal_deadlines=False):
    def presale(purchase):
        return replace(purchase, purchase_kind=PurchaseKind.PRESALE,
            presale_terms_hash=_b32(91),
            authorization_expires_at=purchase.quote_expires_at if equal_deadlines else purchase.authorization_expires_at)
    c = await handoff_case(tmp_path, monkeypatch, recovery, purchase_transform=presale)
    # Governed-series storage is the fixture boundary; this test does not claim
    # independent series governance or future extension eligibility validation.
    c.series = dict(state="PRESALE", termsHash=hx(c.fresh.presale_terms_hash),
        terms=dict(launchDeadline=NOW+10*86400))
    monkeypatch.setattr(presale_endpoints, "get_presale_store",
        lambda _: SimpleNamespace(get=lambda _: deepcopy(c.series)))
    return c


@pytest.mark.asyncio
@pytest.mark.parametrize("recovery", ["expiry", "timeout"])
@pytest.mark.parametrize("equal_deadlines", [False, True])
async def test_initial_presale_reserves_with_real_validator_and_confirms(tmp_path, monkeypatch, recovery, equal_deadlines):
    c = await presale_case(tmp_path, monkeypatch, recovery, equal_deadlines=equal_deadlines)
    try:
        await reserve(c)
        bundle = WalletSpendBundle.from_json_dict(c.submitter.submitted)
        assert_signed(bundle)
        error, message, conditions = consensus(bundle)
        assert error is None, (error, message)
        assert conditions.before_seconds_absolute == c.fresh.quote_expires_at
        assert conditions.seconds_absolute <= NOW < conditions.before_seconds_absolute
        stored = c.purchases.get(c.stored.purchase_id)
        assert stored.inventory_expires_at == min(c.fresh.quote_expires_at, c.fresh.authorization_expires_at)
        assert stored.inventory_expires_at < c.series["terms"]["launchDeadline"]
        assert c.claims[-1].reservation_expires_at == stored.inventory_expires_at
        for ledger in c.ledgers:
            assert ledger.active_inventory_authorization(hx(c.source.name()))["claim_hash"] == c.claims[-1].canonical_hash()
        (successor,) = bundle.additions()
        c.node.records[hx(c.source.name())] = record(c.source, 127 if recovery == "timeout" else 120, 133)
        c.node.records[hx(successor.name())] = record(successor, 133)
        await reserve(c)
        reopened = PaymentPurchaseStore(c.purchases.path).get(c.stored.purchase_id)
        assert reopened.inventory_state == "CONFIRMED"
        assert reopened.inventory_reserved_coin_id == hx(successor.name())
        assert reopened.inventory_bundle == stored.inventory_bundle
        assert reopened.purchase_artifact == stored.purchase_artifact
        assert c.purchases.inventory_status_snapshot(c.old.stored.purchase_id) == c.before
    finally:
        for ledger in c.ledgers:
            ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", ["expired_quote", "ended_series", "wrong_series", "expired_delivery", "paused", "unauthenticated"])
async def test_initial_presale_failure_keeps_inventory_unreserved(tmp_path, monkeypatch, problem):
    c = await presale_case(tmp_path, monkeypatch, "timeout")
    try:
        if problem == "expired_quote":
            monkeypatch.setattr(native.time, "time", lambda: c.fresh.quote_expires_at)
        elif problem == "ended_series":
            c.series["state"] = "CANCELLED"
        elif problem == "wrong_series":
            c.series["termsHash"] = hx(_b32(92))
        elif problem == "expired_delivery":
            c.series["terms"]["launchDeadline"] = NOW - 48*3600
        elif problem == "paused":
            c.settings.alpha_writes_enabled = False
        with pytest.raises(HTTPException):
            if problem == "unauthenticated":
                await native.reserve_smartdeed_inventory(native.InventoryReservationRequest(purchaseId=c.stored.purchase_id),
                    c.request, c.settings, None)
            else:
                await reserve(c)
        assert c.submitter.submitted is None
        assert not c.claims
        assert c.purchases.get(c.stored.purchase_id).inventory_state == "UNRESERVED"
        assert c.purchases.inventory_status_snapshot(c.old.stored.purchase_id) == c.before
    finally:
        for ledger in c.ledgers:
            ledger.close()


@pytest.mark.asyncio
async def test_validator_still_refuses_long_initial_presale_claim(tmp_path, monkeypatch):
    c = await presale_case(tmp_path, monkeypatch, "timeout")
    try:
        await reserve(c)
        claim = c.claims[-1].model_copy(update={"reservation_expires_at": c.series["terms"]["launchDeadline"]})
        before = [ledger.active_inventory_authorization(hx(c.source.name())) for ledger in c.ledgers]
        with pytest.raises(validators.ValidatorEvidenceError, match="outlives the quote or vault authorization"):
            validators.sign_inventory_reservation_claim(c.signer_settings[0], c.ledgers[0], claim, claim.canonical_hash())
        assert [ledger.active_inventory_authorization(hx(c.source.name())) for ledger in c.ledgers] == before
    finally:
        for ledger in c.ledgers:
            ledger.close()


@pytest.mark.asyncio
async def test_confirmed_presale_expiry_is_not_rewritten_by_initial_policy(tmp_path, monkeypatch):
    c = voucher_case(tmp_path, monkeypatch, after_authorization=True)
    before = c.purchases.inventory_status_snapshot(hx(c.purchase.purchase_id))
    group = await native._load_context_group(c.worker.settings, c.worker.provider,
        hx(c.purchase.purchase_id), require_live=False, allowed_rails=(c.purchase.rail,))
    assert group.contexts[0].reservation.expires_at == before[0].inventory_expires_at
    assert group.contexts[0].reservation.expires_at > c.purchase.authorization_expires_at
    assert c.purchases.inventory_status_snapshot(hx(c.purchase.purchase_id)) == before
