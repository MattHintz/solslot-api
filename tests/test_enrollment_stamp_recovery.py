"""Crash/retry checks reuse the signed EVM and BLS enrollment journeys."""
import asyncio
import json
from copy import deepcopy
import pytest
from fastapi import HTTPException
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_api import zkpassport_enrollments as enroll
from solslot_api.config import Settings
from solslot_api.credential_ledger import CredentialLedger, LedgerConflict, get_credential_ledger
from tests import test_zkpassport_enrollments as journeys

JOURNEYS = [journeys.test_evm_proof_builds_and_confirms_atomic_chia_vault_stamp,
    journeys.test_bls_proof_requires_wallet_signature_for_atomic_chia_vault_stamp]


@pytest.mark.parametrize('journey', JOURNEYS, ids=['evm','bls'])
@pytest.mark.parametrize('failure', ['timeout','rejected'])
def test_provider_failure_retains_exact_bytes_and_authenticated_resume(monkeypatch, tmp_path, journey, failure):
    original = enroll._push_chia_stamp_and_mark_pending
    interrupted = False

    async def intercept(settings, **kwargs):
        nonlocal interrupted
        if interrupted:
            return await original(settings, **kwargs)
        interrupted = True
        ledger = get_credential_ledger(settings)
        before = ledger.get_stamp_attempt(kwargs['key'])
        assert before and before['bundle_hex'] is None
        class Failure:
            async def push_tx(self, bundle):
                # Simulate another process reopening the durable database while
                # the remote provider has received the request but not replied.
                reopened = CredentialLedger(settings.zkpassport_ledger_db_path)
                try:
                    pending = reopened.get_enrollment(kwargs['key'])
                    attempt = reopened.get_stamp_attempt(kwargs['key'])
                    assert pending['status'] == 'stamp_pending'
                    assert SpendBundle.from_bytes(bytes.fromhex(attempt['bundle_hex'])).to_json_dict() == bundle
                    assert attempt['claim_json'] == before['claim_json']
                    assert attempt['dispatch_status'] == 'unknown'
                finally:
                    reopened.close()
                if failure == 'timeout': raise TimeoutError('synthetic provider timeout after receive')
                return {'success':False,'status':'FAILED'}
        with pytest.raises(HTTPException) as error:
            await original(settings, **{**kwargs, 'coinset':Failure()})
        assert error.value.status_code == 502
        attempt = ledger.get_stamp_attempt(kwargs['key'])
        assert attempt['dispatch_status'] == ('unknown' if failure == 'timeout' else 'rejected')
        retained = attempt['bundle_hex']
        result = await enroll.submit_evm_chia_stamp(kwargs['key'],
            enroll.SubmitChiaStampRequest(signature='0x00'), journeys._request(kwargs['coinset']))
        after = ledger.get_stamp_attempt(kwargs['key'])
        assert after['bundle_hex'] == retained and after['claim_json'] == before['claim_json']
        assert after['dispatch_status'] == 'submitted'
        assert after['dispatch_count'] == 2
        return result
    monkeypatch.setattr(enroll, '_push_chia_stamp_and_mark_pending', intercept)
    journey(monkeypatch, tmp_path)
    assert interrupted


@pytest.mark.parametrize('journey', JOURNEYS, ids=['evm','bls'])
def test_frozen_partial_quorum_rejects_new_clock_or_owner_claim(monkeypatch, tmp_path, journey):
    original = enroll._push_chia_stamp_and_mark_pending
    async def inspect(settings, **kwargs):
        ledger = get_credential_ledger(settings)
        attempt = ledger.get_stamp_attempt(kwargs['key'])
        claim, successor = json.loads(attempt['claim_json']), json.loads(attempt['expected_coin_json'])
        reopened = CredentialLedger(settings.zkpassport_ledger_db_path)
        try:
            reopened.reserve_stamp_attempt(claim=claim, expected_coin=successor)
            for field, value in [('current_timestamp', claim['current_timestamp']+1),
                                 ('owner_authorization','0x00'), ('artifact_hash','0x'+'ab'*32)]:
                changed = {**claim, field:value}
                with pytest.raises(LedgerConflict, match='already frozen'):
                    reopened.reserve_stamp_attempt(claim=changed, expected_coin=successor)
            assert reopened.get_stamp_attempt(kwargs['key'])['claim_json'] == attempt['claim_json']
        finally: reopened.close()
        return await original(settings, **kwargs)
    monkeypatch.setattr(enroll, '_push_chia_stamp_and_mark_pending', inspect)
    journey(monkeypatch, tmp_path)


@pytest.mark.parametrize('journey', JOURNEYS, ids=['evm','bls'])
def test_retained_bundle_cannot_be_replaced_and_expired_resume_does_not_push(monkeypatch, tmp_path, journey):
    original = enroll._push_chia_stamp_and_mark_pending
    async def inspect(settings, **kwargs):
        result = await original(settings, **kwargs)
        ledger = get_credential_ledger(settings)
        attempt = ledger.get_stamp_attempt(kwargs['key'])
        record_before = ledger.get_enrollment(kwargs['key'])
        bundle = SpendBundle.from_bytes(bytes.fromhex(attempt['bundle_hex']))
        changed = SpendBundle(list(reversed(bundle.coin_spends)), bundle.aggregated_signature)
        with pytest.raises(LedgerConflict, match='already retained'):
            ledger.persist_stamp_bundle(vault_launcher_id=kwargs['key'], bundle_hex=bytes(changed).hex())
        with monkeypatch.context() as later:
            later.setattr(enroll.time, 'time', lambda: json.loads(attempt['claim_json'])['current_timestamp']+91)
            with pytest.raises(HTTPException) as error:
                await enroll.submit_evm_chia_stamp(kwargs['key'], enroll.SubmitChiaStampRequest(signature='0x00'),
                    journeys._request(kwargs['coinset']))
            assert error.value.status_code == 409
        assert ledger.get_enrollment(kwargs['key']) == record_before
        assert ledger.get_stamp_attempt(kwargs['key'])['bundle_hex'] == attempt['bundle_hex']
        return result
    monkeypatch.setattr(enroll, '_push_chia_stamp_and_mark_pending', inspect)
    journey(monkeypatch, tmp_path)


@pytest.mark.parametrize('mutation', ['missing','parent','amount','puzzle','unspent','unconfirmed'])
def test_initial_vault_lineage_rejects_unbound_launcher_records(monkeypatch, mutation):
    launcher = journeys.LAUNCHER_COIN_A
    record = {'coin':launcher.to_json_dict(), 'confirmed_block_index':100,'spent_block_index':101}
    if mutation == 'missing': record = None
    elif mutation == 'unspent': record['spent_block_index'] = 0
    elif mutation == 'unconfirmed': record['confirmed_block_index'] = 0
    else:
        field = {'parent':'parent_coin_info','amount':'amount','puzzle':'puzzle_hash'}[mutation]
        record['coin'][field] = 3 if field == 'amount' else '0x'+'ee'*32
    monkeypatch.setattr(enroll, '_fetch_coin_record_by_name', lambda *_: record)
    vault = Coin(launcher.name(), bytes32(b'v'*32), uint64(1))
    with pytest.raises(HTTPException) as error:
        enroll._initial_vault_lineage(Settings(), vault, launcher.name())
    assert error.value.status_code == 409


def test_schema_one_upgrade_preserves_historical_rows_and_has_no_backfilled_attempt(tmp_path):
    path = tmp_path/'legacy.db'
    ledger = CredentialLedger(path)
    record = {'vaultLauncherId':journeys.VAULT_A,'network':'testnet11','policyVersion':2,
        'status':'reserved','bridgeCoinId':'0x'+'11'*32}
    ledger.reserve_enrollment(record=record, owner_key='legacy-owner')
    ledger._conn.execute('DROP TABLE enrollment_stamp_attempts')
    ledger._conn.execute('PRAGMA user_version=1')
    ledger.close()
    upgraded = CredentialLedger(path)
    try:
        assert upgraded.get_enrollment(journeys.VAULT_A) == record
        assert upgraded.get_stamp_attempt(journeys.VAULT_A) is None
        assert upgraded._conn.execute('PRAGMA user_version').fetchone()[0] == 4
        assert upgraded.get_enrollment_permit(journeys.VAULT_A) is None
        assert upgraded.get_relay_transaction(journeys.VAULT_A) is None
        assert upgraded.enrollment_bridge_coin_ids() == {record['bridgeCoinId']}
    finally: upgraded.close()
