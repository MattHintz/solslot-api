"""Real SQLite concurrency/restart/failure at the STAGED-only boundary.

Opaque retained issuer rows are synthetic. No signing/activation is implied;
native inventory/vault evidence is exercised in the companion simulator test.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import sqlite3
import pytest
from solslot_api.generation_customer_issuer import TestnetIssuerJournal as IssuerJournal,TestnetIssuerPolicy as LegacyPolicy
from solslot_api.generation_customer_issuer_lineage import (
    activate_collection_issuer_lineage, issuer_rows_snapshot, stage_collection_issuer_lineage,
)
from solslot_api.generation_customer_purchase_fee_lineage import FeeExposure,calculate_fee_lineage
from tests.test_current_collection_issuer_policy import make_policy
from tests.test_native_purchases import _b32


def h(n):return '0x'+format(n,'064x')

@pytest.fixture
def lineage(tmp_path):
    policy,_=make_policy();deeds=frozenset([*policy.deed_launchers,*[_b32(n) for n in range(100,124)]])
    assert len(deeds)==25
    next_policy=replace(policy,deed_launchers=deeds)
    old_deeds=frozenset(sorted(deeds)[:3])
    old=LegacyPolicy(policy.generation,policy.collection,policy.edition,policy.metadata_root,
        policy.proceeds_puzzle,policy.fee_puzzle,policy.issuer_public_key,old_deeds,_b32(90),
        policy.maximum_gross_mojos,3,1000,2000)
    path=tmp_path/'existing-validator.sqlite3';journal=IssuerJournal(path,old)
    rows=[]
    for n,deed in enumerate(sorted(old_deeds)[:2]):
        row=(h(1000+n),'0x'+deed.hex(),h(1010+n),h(1020+n),h(1030+n),'retained-message-'+str(n),'opaque-retained-signature-'+str(n),1100+n)
        journal.db.execute('INSERT INTO issuer_forwarding VALUES(?,?,?,?,?,?,?,?)',row);rows.append(row)
    amounts = [3_000_000, 3_500_000, 4_000_000, 5_000_000, 5_500_000, 6_000_000]
    exposures=[FeeExposure(h(2000+n),amount,'UNKNOWN' if n==0 else 'CONFIRMED') for n,amount in enumerate(amounts)]
    exposures.append(FeeExposure(h(2100), 1_000_000_000, 'PREPARED'))
    balance=calculate_fee_lineage(6_000_000_000,exposures)
    snapshot=issuer_rows_snapshot(journal.db)
    yield type('Fixture',(),dict(path=path,journal=journal,old=old,next_policy=next_policy,rows=rows,
        balance=balance,snapshot=snapshot,exposures=exposures))()
    journal.close()


def stage(f,db=None,**changed):
    args=dict(prior_policy=f.old,next_policy=f.next_policy,expected_rows_hash=f.snapshot[0],fee_balance=f.balance)
    args.update(changed)
    return stage_collection_issuer_lineage(db or f.journal.db,**args)


def test_concurrent_same_successor_survives_restart_without_activating_or_resetting_fees(lineage):
    f=lineage
    def attempt(_):
        db=sqlite3.connect(f.path,isolation_level=None,timeout=10)
        try:return stage(f,db)
        finally:db.close()
    with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(attempt,range(12)))
    assert len(set(results))==1 and results[0].state=='STAGED'
    assert results[0].fee_committed_mojos==27_000_000+1_000_000_000
    assert results[0].fee_limit_mojos==6_000_000_000
    reopened=IssuerJournal(f.path,f.old)
    try:
        assert issuer_rows_snapshot(reopened.db)==f.snapshot
        assert reopened.db.execute('SELECT commitment FROM issuer_policy').fetchone()[0]==f.old.commitment
        assert [tuple(x) for x in reopened.db.execute('SELECT * FROM issuer_forwarding ORDER BY artifact_hash')]==f.rows
        assert reopened.db.execute('SELECT count(*) FROM issuer_collection_lineage').fetchone()[0]==1
        assert stage(f,reopened.db)==results[0]
    finally:reopened.close()
    # STAGED must not silently make the wider authority usable by old signer.
    with pytest.raises((ValueError,AttributeError)):
        IssuerJournal(f.path,f.next_policy)


def test_no_fee_reset_or_limit_increase_on_replay(lineage):
    f=lineage;original=stage(f)
    for balance in (calculate_fee_lineage(6_000_000_000,[]),
                    calculate_fee_lineage(6_000_000_001,f.exposures),
                    calculate_fee_lineage(6_000_000_000,f.exposures+[FeeExposure(h(2999),1,'SIGNED')])):
        with pytest.raises(ValueError,match='ALREADY_STAGED'):stage(f,fee_balance=balance)
    assert stage(f)==original and issuer_rows_snapshot(f.journal.db)==f.snapshot


def test_activation_retry_keeps_existing_binding_and_refuses_another_closure(lineage):
    f = lineage
    arguments = dict(prior_policy=f.old, next_policy=f.next_policy,
                     expected_rows_hash=f.snapshot[0], fee_balance=f.balance)
    closure = h(998)

    def activate(_):
        with closing(sqlite3.connect(f.path, isolation_level=None, timeout=10)) as db:
            activate_collection_issuer_lineage(db, **arguments, closure_hash=closure)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(activate, range(8)))
    assert issuer_rows_snapshot(f.journal.db) == f.snapshot
    assert f.journal.db.execute('SELECT commitment FROM issuer_policy').fetchone()[0] == f.next_policy.commitment
    with pytest.raises(ValueError, match='ALREADY_ACTIVATED'):
        activate_collection_issuer_lineage(f.journal.db, **arguments, closure_hash=h(999))
    with pytest.raises(ValueError, match='JOURNAL_POLICY_CHANGED'):
        IssuerJournal(f.path, f.old)
    current = IssuerJournal(f.path, f.next_policy, cutover_hash=closure)
    current.close()


def test_injected_insert_failure_rolls_back_schema_and_preserves_old_journal(lineage):
    f=lineage
    def deny_insert(action,arg1,*_):
        return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT and arg1=='issuer_collection_lineage' else sqlite3.SQLITE_OK
    f.journal.db.set_authorizer(deny_insert)
    with pytest.raises(sqlite3.DatabaseError):stage(f)
    f.journal.db.set_authorizer(None)
    assert not f.journal.db.in_transaction
    assert not f.journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='issuer_collection_lineage'").fetchone()
    assert issuer_rows_snapshot(f.journal.db)==f.snapshot
    assert f.journal.db.execute('SELECT commitment FROM issuer_policy').fetchone()[0]==f.old.commitment
    assert stage(f).state=='STAGED'


def test_uncertain_signature_blocks_staging_and_does_not_free_fee_exposure(lineage):
    f=lineage;row=list(f.rows[0]);row[0]=h(3990);row[1]=h(3991);row[2]=h(3992);row[6]=None
    f.journal.db.execute('INSERT INTO issuer_forwarding VALUES(?,?,?,?,?,?,?,?)',row)
    digest,_=issuer_rows_snapshot(f.journal.db)
    with pytest.raises(ValueError,match='UNCERTAIN_SIGNATURE'):stage(f,expected_rows_hash=digest)
    assert not f.journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='issuer_collection_lineage'").fetchone()
    assert calculate_fee_lineage(6_000_000_000,f.exposures)==f.balance


def test_poststage_history_change_or_different_successor_is_fenced(lineage):
    f=lineage;original=stage(f)
    with pytest.raises(ValueError,match='SCOPE_CHANGED'):
        stage(f,next_policy=replace(f.next_policy,fee_puzzle=_b32(91)))
    with pytest.raises(ValueError,match='ALREADY_STAGED'):
        stage(f,next_policy=replace(f.next_policy,deed_launchers=f.next_policy.deed_launchers-{max(f.next_policy.deed_launchers)}))
    f.journal.db.execute('UPDATE issuer_forwarding SET message=? WHERE artifact_hash=?',('corrupted-or-new-history',f.rows[0][0]))
    with pytest.raises(ValueError,match='SNAPSHOT_CHANGED'):stage(f)
    with pytest.raises(ValueError,match='ALREADY_STAGED'):
        stage(f,expected_rows_hash=issuer_rows_snapshot(f.journal.db)[0])
    saved=f.journal.db.execute('SELECT prior_rows_hash,fee_committed_mojos,state FROM issuer_collection_lineage').fetchone()
    assert tuple(saved)==(original.prior_rows_hash,original.fee_committed_mojos,'STAGED')


def test_inherited_unknown_and_prepared_exposure_cannot_be_treated_as_released(lineage):
    f=lineage
    conflicting=[*f.exposures,FeeExposure(f.exposures[0].identity,0,'CONFIRMED')]
    with pytest.raises(ValueError,match='CONFLICTING_EXPOSURE'):calculate_fee_lineage(6_000_000_000,conflicting)
    with pytest.raises(ValueError,match='EXPOSURE_INVALID'):
        calculate_fee_lineage(6_000_000_000,[FeeExposure(f.exposures[-1].identity,0,'RELEASED')])
    with pytest.raises(ValueError,match='LIMIT_EXCEEDED'):
        calculate_fee_lineage(6_000_000_000,[*f.exposures,FeeExposure(h(2998),6_000_000_000,'SIGNED')])
