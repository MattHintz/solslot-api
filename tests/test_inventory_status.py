"""Retained receipt projection with SQLite and synthetic canonical commitments."""
import copy
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from solslot_api.bootstrap_manifest import content_hash
from solslot_api.config import Settings
from solslot_api.inventory_status import retained_inventory_status
from solslot_api.inventory_recovery import reconcile_timeout_release
from solslot_api.native_purchases import inventory_purchase_status
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from tests.test_inventory_timeout_recovery import case, hx, _b32


def complete_offer(c):
    stored = c.store.get(c.stored.purchase_id)
    raw = stored.purchase_artifact
    batch = raw.get("schema") == "solslot.purchase-batch.v1"
    child = raw["artifacts"][0] if batch else raw
    offer = dict(kind="solslot_protocol_offer", protocolVersion="solslot-v2", network="testnet11",
        genesisArtifactHash="sha256:" + "a1" * 32,
        poolLauncherId=hx(_b32(70)), protocolConfigLauncherId=hx(_b32(71)), vaultVersionRegistryLauncherId=hx(_b32(72)),
        protocol=dict(instanceId="staging-alpha", purchaseIntentId=stored.purchase_intent_id, rail=stored.rail,
            purchaseId=stored.purchase_id, purchaseArtifactHash=stored.artifact_hash,
            quantity=len(stored.deed_launcher_ids), deedLauncherIds=list(stored.deed_launcher_ids),
            vaultLauncherId=child["vaultLauncherId"]))
    offer["purchaseBatchV1" if batch else "purchaseArtifactV3"] = raw
    with c.store._connect() as db:
        db.execute("UPDATE payment_purchases SET offer_artifact_json=?,offer_artifact_hash=? WHERE purchase_id=?",
            (json.dumps(offer), content_hash(offer), stored.purchase_id))
    c.stored = c.store.get(stored.purchase_id)
    return c


def status(c):
    return retained_inventory_status(c.store.inventory_status_snapshot(c.stored.purchase_id),
        environment="staging-alpha", network="testnet11")


@pytest.mark.parametrize("state", ["UNRESERVED", "PREPARED", "SUBMITTED", "CONFIRMED"])
@pytest.mark.parametrize("quantity", [1, 2])
def test_retained_status_does_not_require_live_quote_or_credentials(tmp_path, state, quantity):
    c = complete_offer(case(tmp_path, quantity, state if state != "UNRESERVED" else "PREPARED"))
    if state == "UNRESERVED":
        old = c.stored
        c.store = PaymentPurchaseStore(str(tmp_path / "unreserved.db"))
        c.stored = c.store.save(purchase_intent_id=old.purchase_intent_id, rail=old.rail,
            offer_artifact_hash=old.offer_artifact_hash, offer_artifact=old.offer_artifact,
            purchase_artifact=old.purchase_artifact, created_at=1)
    result = status(c)
    assert result["state"] == state and result["quantity"] == quantity
    assert result["observerEnvironment"] == "staging-alpha"
    assert result["releaseIdentity"] == c.stored.offer_artifact["genesisArtifactHash"]
    assert result["recoveryReceipt"] is None
    assert "signature" not in json.dumps(result) and "releaseSpend" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["PREPARED", "SUBMITTED", "CONFIRMED"])
async def test_released_receipt_survives_refresh_and_later_successor_spend(tmp_path, state):
    c = complete_offer(case(tmp_path, 2, state))
    await reconcile_timeout_release(c.store, c.node, c.stored.purchase_id, "testnet11")
    result = status(c)
    assert result["state"] == "RELEASED"
    assert result["recoveryReceipt"] == {"kind": "timeout-release", "confirmationHeight": 104}
    c.node.records.clear()  # Historical receipt reads never consult current chain.
    c.store = PaymentPurchaseStore(c.store.path)
    assert status(c) == result


@pytest.mark.asyncio
async def test_expired_authorization_has_separate_receipt_not_a_refund(tmp_path, monkeypatch):
    from tests.test_inventory_authorization_expiry import expiry_case
    from solslot_api.inventory_authorization_expiry import reconcile_inventory_authorization_expiry
    c = expiry_case(tmp_path, monkeypatch)
    c = complete_offer(c)
    await reconcile_inventory_authorization_expiry(store=c.store, node=c.node, purchase_id=c.stored.purchase_id,
        artifact=c.artifact, environment="staging-alpha", authorize=lambda: None)
    result = status(c)
    assert result["state"] == "AUTHORIZATION_EXPIRED"
    assert result["recoveryReceipt"] == {"kind": "authorization-expiry", "confirmationHeight": None}
    assert result["externalPaymentRecorded"] is False
    assert "refund" not in result


@pytest.mark.parametrize("problem", ["child_id", "child_hash", "ordinal", "state", "confirmation", "missing_bundle", "offer_hash", "network"])
def test_malformed_snapshot_is_not_projected_as_success(tmp_path, problem):
    c = complete_offer(case(tmp_path))
    table = "payment_purchase_inventory_items"
    fields = {"child_id": ("child_purchase_id", hx(_b32(99))), "child_hash": ("child_artifact_hash", hx(_b32(99))),
              "ordinal": ("ordinal", 9), "state": ("state", "UNRESERVED")}
    if problem in fields:
        field, value = fields[problem]
    else:
        table = "payment_purchases"
        field, value = {"confirmation": ("inventory_confirmation_height", 0), "missing_bundle": ("inventory_bundle_json", None),
                        "offer_hash": ("offer_artifact_hash", "sha256:" + "99" * 32),
                        "network": ("offer_artifact_json", json.dumps({**c.stored.offer_artifact, "network": "mainnet"}))}[problem]
    with c.store._connect() as db:
        db.execute(f"UPDATE {table} SET {field}=? WHERE purchase_id=?", (value, c.stored.purchase_id))
    with pytest.raises(PaymentPurchaseConflict):
        status(c)


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", ["missing", "invalid_json", "empty", "network", "height", "coin", "nonce_size", "contradictory"])
async def test_terminal_status_requires_complete_matching_receipt(tmp_path, problem):
    c = complete_offer(case(tmp_path))
    await reconcile_timeout_release(c.store, c.node, c.stored.purchase_id, "testnet11")
    receipt = c.store.inventory_release_evidence(c.stored.purchase_id)
    if problem == "empty": receipt = {}
    elif problem == "network": receipt["network"] = "mainnet"
    elif problem == "height": receipt["items"][0]["confirmationHeight"] = True
    elif problem == "coin": receipt["items"][0]["availableCoinId"] = hx(_b32(99))
    elif problem == "nonce_size": receipt["items"][0]["releaseSpend"]["solution"] = "0x80"
    with c.store._connect() as db:
        if problem == "missing": db.execute("DELETE FROM payment_inventory_releases")
        elif problem == "contradictory": db.execute("INSERT INTO payment_inventory_expiries VALUES (?,?)", (c.stored.purchase_id, "{}"))
        else: db.execute("UPDATE payment_inventory_releases SET evidence_json=?", ("{" if problem == "invalid_json" else json.dumps(receipt),))
    with pytest.raises((PaymentPurchaseConflict, ValueError)):
        status(c)
    with pytest.raises((PaymentPurchaseConflict, ValueError)):
        await reconcile_timeout_release(c.store, c.node, c.stored.purchase_id, "testnet11")


@pytest.mark.asyncio
async def test_service_read_requires_token_but_not_open_sales(tmp_path):
    c = complete_offer(case(tmp_path))
    settings = Settings(_env_file=None, runtime_environment="test", alpha_writes_enabled=False,
        minting_enabled=False, protocol_artifact_api_token="synthetic-status-token", payment_purchase_db_path=c.store.path)
    with pytest.raises(HTTPException) as error:
        await inventory_purchase_status(c.stored.purchase_id, settings, "Bearer wrong")
    assert error.value.status_code in {401, 403}
    result = await inventory_purchase_status(c.stored.purchase_id, settings, "Bearer synthetic-status-token")
    assert result["state"] == "CONFIRMED"


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["artifactHash", "activation", "sourceCoin", "sourceConfirmationHeight",
    "peakHeight", "peakHash", "ancestors", "bad_link", "bad_source", "bad_activation"])
async def test_expiry_receipt_requires_activation_and_complete_chain_clock(tmp_path,monkeypatch,field):
    from tests.test_inventory_authorization_expiry import expiry_case
    from solslot_api.inventory_authorization_expiry import reconcile_inventory_authorization_expiry
    c=complete_offer(expiry_case(tmp_path,monkeypatch))
    kwargs=dict(store=c.store,node=c.node,purchase_id=c.stored.purchase_id,artifact=c.artifact,
                environment="staging-alpha",authorize=lambda:None)
    await reconcile_inventory_authorization_expiry(**kwargs)
    receipt=c.store.inventory_expiry_evidence(c.stored.purchase_id)
    if field in {"artifactHash","activation"}: del receipt[field]
    elif field=="bad_link": receipt["chainProofs"][0]["ancestors"][1]["headerHash"]=hx(_b32(99))
    elif field=="bad_source": receipt["chainProofs"][0]["sourceCoin"]["parent_coin_info"]=hx(_b32(99))
    elif field=="bad_activation": receipt["activation"]["network"]="mainnet"
    else: del receipt["chainProofs"][0][field]
    with c.store._connect() as db:
        db.execute("UPDATE payment_inventory_expiries SET evidence_json=?", (json.dumps(receipt),))
    with pytest.raises(PaymentPurchaseConflict): status(c)
    with pytest.raises(PaymentPurchaseConflict): await reconcile_inventory_authorization_expiry(**kwargs)
