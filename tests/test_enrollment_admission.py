"""Admission mitigation only; abandoned external authorizations remain reserved."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from solslot_api.credential_ledger import CredentialLedger, LedgerRateLimited, LedgerError
from tests.test_credential_ledger import _enrollment


def enrollment(seed):
    raw=_enrollment()
    raw.update(vaultLauncherId="0x"+bytes([seed]).hex()*32,
               bridgeCoinId="0x"+bytes([seed+40]).hex()*32,createdAt=1,updatedAt=1)
    return raw


def test_pending_limit_survives_restart_and_exact_retry(tmp_path):
    path=tmp_path/"ledger.db"
    ledger=CredentialLedger(path)
    try:
        for seed in (1,2,3): ledger.reserve_enrollment(record=enrollment(seed),owner_key="OWNER")
    finally: ledger.close()
    ledger=CredentialLedger(path)
    try:
        old,created=ledger.reserve_enrollment(record=enrollment(1),owner_key="owner")
        assert created is False and old==enrollment(1)
        with pytest.raises(LedgerRateLimited):
            ledger.reserve_enrollment(record=enrollment(4),owner_key="owner")
        assert ledger.get_enrollment(enrollment(4)["vaultLauncherId"]) is None
        assert ledger.enrollment_bridge_coin_ids()=={enrollment(i)["bridgeCoinId"] for i in (1,2,3)}
        assert ledger.reserve_enrollment(record=enrollment(4),owner_key="different-owner")[1]
    finally: ledger.close()


def test_admission_is_atomic_across_connections(tmp_path):
    path=tmp_path/"ledger.db"
    CredentialLedger(path).close()
    def claim(seed):
        ledger=CredentialLedger(path)
        try:
            try: return ledger.reserve_enrollment(record=enrollment(seed),owner_key="owner",max_pending_per_owner=1)[1]
            except LedgerRateLimited: return False
        finally: ledger.close()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(claim,range(1,9))) == 1
    ledger=CredentialLedger(path)
    try: assert len(ledger.enrollment_bridge_coin_ids())==1
    finally: ledger.close()


def test_proof_progress_reopens_admission_without_reusing_old_coin(tmp_path):
    ledger=CredentialLedger(tmp_path/"ledger.db")
    try:
        first=enrollment(1)
        ledger.reserve_enrollment(record=first,owner_key="owner",max_pending_per_owner=1)
        with pytest.raises(LedgerRateLimited): ledger.reserve_enrollment(record=enrollment(2),owner_key="owner",max_pending_per_owner=1)
        # Existing receipt lifecycle owns this transition; no coin binding changes.
        first["status"]="evm_confirmed"
        ledger.update_enrollment(first,expected_statuses=("reserved",))
        assert ledger.reserve_enrollment(record=enrollment(2),owner_key="owner",max_pending_per_owner=1)[1]
        assert len(ledger.enrollment_bridge_coin_ids())==2
    finally: ledger.close()


@pytest.mark.parametrize("value",[0,-1,21,True,1.5,"3"])
def test_invalid_admission_policy_cannot_disable_boundary(tmp_path,value):
    ledger=CredentialLedger(tmp_path/"ledger.db")
    try:
        with pytest.raises(LedgerError): ledger.reserve_enrollment(record=enrollment(1),owner_key="owner",max_pending_per_owner=value)
        assert ledger.enrollment_bridge_coin_ids()==set()
    finally: ledger.close()
