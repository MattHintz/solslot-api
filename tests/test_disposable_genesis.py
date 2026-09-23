from copy import deepcopy
import hashlib

import pytest

from solslot_api.config import Settings
from solslot_api.disposable_genesis import (
    CLOSED_FLAGS, PROFILE, REVIEW_CLASS, require_scope, require_allowed_gate,
    scope_receipt, receipt_bytes, receipt_summary, validate_configuration,
)
from solslot_api.genesis import _authority_preflight
from solslot_api.genesis_store import GenesisConflict
from solslot_api.launch_control import _task_for

CID = '0x' + '78' * 32


def settings(**kw):
    return Settings(**{
        'runtime_environment': 'test', 'network': 'testnet11',
        'launch_genesis_review_class': REVIEW_CLASS,
        'disposable_genesis_ceremony_id': CID,
        **{key: False for key in CLOSED_FLAGS}, **kw,
    })


def record():
    return {
        'ceremony_id': CID, 'state': 'plan_approved',
        'draft': {'launchProfile': PROFILE, 'reviewClass': REVIEW_CLASS,
                  'network': 'testnet11', 'sourceShas': {'api': 'a'*40},
                  'releaseEvidenceHash': 'b'*64},
        'plan': {'network': 'testnet11'}, 'plan_hash': '0x' + 'ac'*32,
        'plan_input': {'adminRecoveryKits': [{'slot': slot, 'revision': 1} for slot in range(3)]},
        'invitations': [{'consumed_at': 1} for _ in range(3)],
        'plan_expires_at': 9999999999,
    }


@pytest.mark.parametrize('name', CLOSED_FLAGS)
def test_disposable_configuration_rejects_each_financial_capability(name):
    with pytest.raises(ValueError, match='closed capabilities'):
        validate_configuration(settings(**{name: True}))


@pytest.mark.parametrize('changes', [
    {'network': 'mainnet'}, {'launch_genesis_review_class': 'independent-release-review'},
    {'disposable_genesis_ceremony_id': '0x12'},
])
def test_disposable_rejects_wrong_network_review_or_id(changes):
    with pytest.raises(ValueError):
        require_scope(settings(**changes), record())


@pytest.mark.parametrize('mutation', ['other_ceremony', 'no_scope', 'independent', 'mainnet_plan', 'disabled_config'])
def test_scope_must_match_both_config_and_persisted_draft(mutation):
    r = record(); s = settings()
    if mutation == 'other_ceremony': r['ceremony_id'] = '0x' + 'ab'*32
    if mutation == 'no_scope': r['draft'].pop('launchProfile')
    if mutation == 'independent': r['draft']['reviewClass'] = 'independent-release-review'
    if mutation == 'mainnet_plan': r['plan']['network'] = 'mainnet'
    if mutation == 'disabled_config': s.disposable_genesis_ceremony_id = None
    with pytest.raises(ValueError): require_scope(s, r)


@pytest.mark.parametrize('gate', ['minting', 'presale', 'purchases', 'xchVouchers'])
def test_disposable_rejects_sales_windows_even_after_lock(gate):
    r=record(); r['state']='locked'
    with pytest.raises(ValueError, match='vaults and identity only'):
        require_allowed_gate(settings(), r, gate)
    require_allowed_gate(settings(), r, 'ceremonyBroadcast')


def test_scope_receipt_is_explicit_not_an_independent_approval():
    r = record(); receipt = scope_receipt(settings(), r)
    assert receipt['auditStatus'] == 'unaudited'
    assert receipt['replaceBeforeBridgeTesting'] is True
    assert receipt['kind'] == 'solslot-disposable-genesis-scope'
    assert receipt_summary(receipt)['fileSha256'] == hashlib.sha256(receipt_bytes(receipt)).hexdigest()
    altered = deepcopy(r); altered['plan_hash'] = '0x'+'ee'*32
    assert receipt_summary(scope_receipt(settings(), altered)) != receipt_summary(receipt)
    r['plan_input']['adminRecoveryKits'].pop()
    with pytest.raises(ValueError, match='three recovery kits'): scope_receipt(settings(), r)


@pytest.mark.asyncio
async def test_only_explicit_disposable_scope_defers_evm_evidence():
    receipt = await _authority_preflight(settings(), record())
    assert receipt['auditStatus'] == 'unaudited'
    normal = record(); normal['draft'].pop('launchProfile')
    with pytest.raises(GenesisConflict, match='Authority V3 launch approval failed'):
        await _authority_preflight(settings(disposable_genesis_ceremony_id=None), normal)


def test_deferred_payment_tasks_do_not_block_disposable_archive():
    r=record(); r['state']='locked'
    tasks=[{'id': 'railOwnership','status':'Blocked','blocksCeremony':False}]
    assert _task_for(r,tasks)['action'] == 'openOperations'
    r['state']='planned'
    tasks=[{'id':'authorityV3Evm','status':'Waiting','blocksCeremony':False}]
    assert _task_for(r,tasks)['action'] == 'signPlan'


def test_adoption_preserves_enrollment_recovery_funding_and_records_original(tmp_path):
    from tests.test_genesis_api import _client, _create_and_enroll, _source_shas
    client, store, s = _client(tmp_path)
    cid, _accounts = _create_and_enroll(client, store)
    before = store.get(cid); kits = store.recovery_kits(cid)
    s.disposable_genesis_ceremony_id = cid
    s.launch_genesis_review_class = REVIEW_CLASS
    for flag in CLOSED_FLAGS: setattr(s, flag, False)
    release = {'sourceShas': _source_shas(), 'releaseTag': 'test-disposable', 'fileSha256': 'cd'*32}
    after = store.adopt_disposable_release(s, cid, expected_draft=before['draft'], release=release, action_envelope_id='test-authorization')
    assert after['draft']['launchProfile'] == PROFILE
    assert after['invitations'] == before['invitations']
    assert after['roster_hash'] == before['roster_hash']
    assert store.recovery_kits(cid) == kits
    assert after['plan'] is None and not after['plan_signatures']
    with pytest.raises(GenesisConflict, match='exactly once'):
        store.adopt_disposable_release(s, cid, expected_draft=after['draft'], release=release, action_envelope_id='test-authorization')
    with store._connect() as connection:
        import json
        event=connection.execute("SELECT event_json FROM audit_events WHERE ceremony_id=? AND event_type='disposable_release_adopted'", (cid,)).fetchone()
        assert json.loads(event[0])['previousDraft'] == before['draft']
