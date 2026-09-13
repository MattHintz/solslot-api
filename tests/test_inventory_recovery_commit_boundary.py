"""Offline canonical-chain doubles exercise the final authorization/CAS boundary."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from solslot_api import native_purchases as native
from solslot_api.config import Settings
from solslot_api.inventory_recovery import reconcile_timeout_release
from solslot_api.payment_purchase_store import PaymentPurchaseConflict
from tests.test_inventory_timeout_recovery import case


@pytest.mark.asyncio
async def test_timeout_gate_closing_during_proof_retains_inventory(tmp_path):
    c = case(tmp_path, state="SUBMITTED")
    settings = Settings(_env_file=None, network="testnet11", runtime_environment="test",
        alpha_writes_enabled=True, minting_enabled=True, launch_control_enabled=False,
        protocol_artifact_api_token="synthetic-recovery-token", payment_purchase_db_path=c.store.path)
    original = c.node.get_blockchain_state
    async def close_gate():
        result = await original()
        if c.node.tip_reads == 2:
            settings.alpha_writes_enabled = False
        return result
    c.node.get_blockchain_state = close_gate
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node)))
    with pytest.raises(HTTPException):
        await native.reconcile_inventory_timeout(native.InventoryReservationRequest(purchaseId=c.stored.purchase_id),
            request, settings, "Bearer synthetic-recovery-token")
    assert c.store.get(c.stored.purchase_id).inventory_state == "SUBMITTED"
    assert c.store.inventory_release_evidence(c.stored.purchase_id) is None


@pytest.mark.asyncio
async def test_confirmed_timeout_resume_rechecks_gate_without_signing_or_submission(tmp_path):
    from tests.test_inventory_timeout_submission import pending, advance
    from tests.test_inventory_timeout_recovery import hx, record
    c = pending(tmp_path)
    for release in c.releases:
        c.node.records[hx(release.spend.coin.name())] = record(release.spend.coin, 101, 104)
        c.node.records[hx(release.next_coin.name())] = record(release.next_coin, 104)
    allowed = True
    original = c.node.get_blockchain_state
    async def close_gate():
        nonlocal allowed
        result = await original()
        allowed = False
        return result
    c.node.get_blockchain_state = close_gate
    def authorize():
        if not allowed:
            raise PaymentPurchaseConflict("gate closed")
    with pytest.raises(PaymentPurchaseConflict, match="gate closed"):
        await advance(c, authorize=authorize)
    assert c.store.inventory_release_evidence(c.stored.purchase_id) is None
    assert c.submitter.preparations == 0 and c.submitter.pushed == []


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing_receipt", "invalid_json", "item_state", None])
async def test_terminal_timeout_resume_validates_receipt_without_rpc(tmp_path, damage):
    from tests.test_inventory_timeout_submission import pending, advance
    from tests.test_inventory_timeout_recovery import hx, record
    c = pending(tmp_path)
    for release in c.releases:
        c.node.records[hx(release.spend.coin.name())] = record(release.spend.coin, 101, 104)
        c.node.records[hx(release.next_coin.name())] = record(release.next_coin, 104)
    await reconcile_timeout_release(c.store, c.node, c.stored.purchase_id, "testnet11")
    with c.store._connect() as db:
        if damage == "missing_receipt": db.execute("DELETE FROM payment_inventory_releases")
        elif damage == "invalid_json": db.execute("UPDATE payment_inventory_releases SET evidence_json='{' ")
        elif damage == "item_state": db.execute("UPDATE payment_purchase_inventory_items SET state='CONFIRMED'")
    async def forbidden(*args, **kwargs):
        pytest.fail("terminal receipt must not read the network or dispatch")
    c.node.get_network_info = forbidden
    c.node.get_blockchain_state = forbidden
    c.submitter.submit = forbidden
    if damage:
        with pytest.raises(PaymentPurchaseConflict): await advance(c)
    else:
        assert (await advance(c))["state"] == "RELEASED"
    assert c.submitter.preparations == 0 and c.submitter.pushed == []


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["confirmation", "payment"])
async def test_timeout_cannot_commit_over_concurrent_confirmation(tmp_path, change):
    c = case(tmp_path, state="SUBMITTED")
    original = c.node.get_blockchain_state
    async def change_confirmation():
        result = await original()
        if c.node.tip_reads == 2:
            if change == "confirmation":
                c.store.record_inventory_confirmed(c.stored.purchase_id, confirmation_height=102)
            else:
                c.store.bind_external_message(c.stored.purchase_id, {
                    "globalPaymentId": "0x" + "ab" * 32,
                    "source": {"transactionHash": "0x" + "cd" * 32}})
        return result
    c.node.get_blockchain_state = change_confirmation
    with pytest.raises(PaymentPurchaseConflict):
        await reconcile_timeout_release(c.store, c.node, c.stored.purchase_id, "testnet11")
    if change == "confirmation":
        assert c.store.get(c.stored.purchase_id).inventory_confirmation_height == 102
    else:
        assert c.store.get(c.stored.purchase_id).external_message is not None
    assert c.store.inventory_release_evidence(c.stored.purchase_id) is None
