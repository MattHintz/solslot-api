"""Plan preparation breaks the deployment cycle without weakening launch checks."""
import json
import sqlite3
import time

import httpx
import pytest
from chia_rs import AugSchemeMPL
from eth_account import Account

from solslot_api.authority_v3_roster import export_authority_v3_roster, AuthorityV3RosterError
from solslot_api.launch_control import _task_for
from tests.test_authority_v3_roster import _planned_database, CEREMONY_ID
from tests.test_admin_security import _app, CEREMONY_ID as SECURITY_CEREMONY_ID


def _set_payment_plan(path, chain):
    with sqlite3.connect(path) as db:
        plan = json.loads(db.execute("SELECT plan_json FROM ceremonies").fetchone()[0])
        plan.update(evmChainId=11155111, paymentChainId=chain)
        db.execute("UPDATE ceremonies SET plan_json=?", (json.dumps(plan),))


@pytest.mark.parametrize("chain", [8453, 84532])
def test_export_binds_payment_authority_without_changing_enrollment(tmp_path, chain):
    path, store, _ = _planned_database(tmp_path)
    before = store.get(CEREMONY_ID)["invitations"]
    kits = store.recovery_kits(CEREMONY_ID)
    _set_payment_plan(path, chain)
    evidence = export_authority_v3_roster(path, now=1000)
    assert evidence["schemaVersion"] == 3
    assert evidence["paymentChainId"] == chain
    assert evidence["evmChainId"] == 11155111
    assert store.get(CEREMONY_ID)["invitations"] == before
    assert store.recovery_kits(CEREMONY_ID) == kits


@pytest.mark.parametrize("chain", [True, "8453", None, 11155111, 1])
def test_export_rejects_unbound_authority_chain(tmp_path, chain):
    path, _, _ = _planned_database(tmp_path)
    _set_payment_plan(path, chain)
    with pytest.raises(AuthorityV3RosterError, match="chain"):
        export_authority_v3_roster(path, now=1000)


def _finding(name, status="Blocked"):
    return {"id": name, "title": name, "status": status, "impact": "pending",
            "assignedRole": "technical-coadmin", "action": name}


@pytest.mark.parametrize("state,action", [("roster_open", "freezeRoster"), ("roster_frozen", "buildPlan")])
def test_preplan_does_not_wait_for_contracts_that_need_plan_coordinates(state, action):
    record = {"state": state, "invitations": [{"consumed_at": 1}] * 3}
    readiness = [_finding("authorityV3Evm"), _finding("authorityV3Review")]
    original = json.dumps(readiness, sort_keys=True)
    assert _task_for(record, readiness)["action"] == action
    assert json.dumps(readiness, sort_keys=True) == original
    for real_blocker in ("release", "planInputs", "adminRecoveryKits", "funding"):
        assert _task_for(record, readiness + [_finding(real_blocker)])["action"] == real_blocker


@pytest.mark.parametrize("state", ["planned", "plan_approved", "locked"])
@pytest.mark.parametrize("dependency", ["authorityV3Evm", "authorityV3Review"])
def test_authority_remains_required_after_plan_creation(state, dependency):
    record = {"state": state, "invitations": [{"consumed_at": 1}] * 3,
              "plan_expires_at": int(time.time()) + 600}
    assert _task_for(record, [_finding(dependency)])["action"] == dependency


@pytest.mark.asyncio
async def test_new_recovery_drill_follows_plan_while_historical_enrollment_stays_intact(tmp_path):
    app, store = _app(tmp_path)
    original = store.get(SECURITY_CEREMONY_ID)["draft"]
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE ceremonies SET plan_json=? WHERE ceremony_id=?",
                   (json.dumps({"evmChainId": 11155111, "paymentChainId": 8453}), SECURITY_CEREMONY_ID))
    guardian = Account.create()
    sk = AugSchemeMPL.key_gen(b"test mixed network recovery" * 2)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/admin/security/recovery-kit/drill", json={
            "evmGuardian": guardian.address, "recoveryBlsPubkey": "0x" + bytes(sk.get_g1()).hex()})
    assert response.status_code == 200, response.text
    assert response.json()["evmTypedData"]["domain"]["chainId"] == 8453
    assert store.get(SECURITY_CEREMONY_ID)["draft"] == original
