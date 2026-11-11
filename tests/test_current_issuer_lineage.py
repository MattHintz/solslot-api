import sqlite3
import pytest
from solslot_api.generation_customer_issuer_lineage import issuer_rows_snapshot,stage_collection_issuer_lineage
from solslot_api.generation_customer_purchase_fee_lineage import FeeExposure,calculate_fee_lineage
from tests.test_current_collection_issuer_policy import make_policy
from solslot_api.generation_customer_issuer import TestnetIssuerPolicy as LegacyPolicy
from tests.test_native_purchases import _b32


def h(n):return '0x'+format(n,'064x')


@pytest.fixture
def db():
    conn=sqlite3.connect(':memory:',isolation_level=None)
    conn.execute('CREATE TABLE issuer_policy (id INTEGER PRIMARY KEY, commitment TEXT NOT NULL)')
    conn.execute('INSERT INTO issuer_policy VALUES (1,?)',(prior().commitment,))
    conn.execute('''CREATE TABLE issuer_forwarding (artifact_hash TEXT PRIMARY KEY,deed_id TEXT UNIQUE,
        gross_coin_id TEXT UNIQUE,purchase_bundle_hash TEXT,spend_hash TEXT,message TEXT,signature TEXT,created_at INTEGER)''')
    yield conn
    conn.close()


def prior():
    p=make_policy()[0]
    return LegacyPolicy(p.generation,p.collection,p.edition,p.metadata_root,p.proceeds_puzzle,p.fee_puzzle,
        p.issuer_public_key,p.deed_launchers,_b32(21),p.maximum_gross_mojos,len(p.deed_launchers),1000,1100)


def stage(db,expected=None,balance=None,policy=None):
    return stage_collection_issuer_lineage(db,prior_policy=prior(),next_policy=policy or make_policy()[0],
        expected_rows_hash=expected or issuer_rows_snapshot(db)[0],
        fee_balance=balance or calculate_fee_lineage(1000,[FeeExposure(h(2),250,'CONFIRMED')]))


def test_transition_stages_once_without_rebinding_or_erasing_history(db):
    row=(h(3),h(4),h(5),h(6),h(7),'message','signature',10)
    db.execute('INSERT INTO issuer_forwarding VALUES (?,?,?,?,?,?,?,?)',row)
    original=issuer_rows_snapshot(db);result=stage(db)
    assert result.state=='STAGED' and result.prior_rows==1 and result.fee_committed_mojos==250
    assert stage(db)==result and issuer_rows_snapshot(db)==original
    assert tuple(db.execute('SELECT * FROM issuer_forwarding').fetchone())==row
    assert db.execute('SELECT commitment FROM issuer_policy').fetchone()[0]==prior().commitment
    with pytest.raises(ValueError,match='ALREADY_STAGED'):
        stage(db,balance=calculate_fee_lineage(1000,[FeeExposure(h(2),251,'CONFIRMED')]))


def test_stale_or_uncertain_history_never_stages(db):
    old=issuer_rows_snapshot(db)[0]
    db.execute('INSERT INTO issuer_forwarding VALUES (?,?,?,?,?,?,?,?)',(h(3),h(4),h(5),h(6),h(7),'message',None,10))
    with pytest.raises(ValueError,match='SNAPSHOT_CHANGED'):stage(db,expected=old)
    with pytest.raises(ValueError,match='UNCERTAIN_SIGNATURE'):stage(db)
    assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='issuer_collection_lineage'").fetchone()


def test_offline_activation_cas_preserves_rows_and_requires_exact_closure(db):
    from solslot_api.generation_customer_issuer_lineage import activate_collection_issuer_lineage
    from solslot_api.generation_customer_issuer import TestnetIssuerJournal
    from types import SimpleNamespace
    row=(h(3),h(4),h(5),h(6),h(7),'message','signature',10)
    db.execute('INSERT INTO issuer_forwarding VALUES (?,?,?,?,?,?,?,?)',row)
    snapshot=issuer_rows_snapshot(db)
    balance=calculate_fee_lineage(1000,[FeeExposure(h(2),250,'CONFIRMED')])
    args=dict(prior_policy=prior(),next_policy=make_policy()[0],expected_rows_hash=snapshot[0],fee_balance=balance)
    with pytest.raises(ValueError,match='CLOSURE_HASH_REQUIRED'):
        activate_collection_issuer_lineage(db,closure_hash=h(0),**args)
    activate_collection_issuer_lineage(db,closure_hash=h(9),**args)
    assert issuer_rows_snapshot(db)==snapshot and tuple(db.execute('SELECT * FROM issuer_forwarding').fetchone())==row
    assert db.execute('SELECT commitment FROM issuer_policy').fetchone()[0]==args['next_policy'].commitment
    assert db.execute('SELECT prior_commitment,closure_hash,state FROM issuer_collection_activation').fetchone()==(prior().commitment,h(9),'ACTIVE')
    old=SimpleNamespace(db=db,policy=prior())
    with pytest.raises(ValueError,match='JOURNAL_POLICY_CHANGED'):TestnetIssuerJournal._require_binding(old)
    activated=tuple(db.iterdump())
    activate_collection_issuer_lineage(db,closure_hash=h(9),**args)
    assert tuple(db.iterdump())==activated
    with pytest.raises(ValueError,match='CURRENT_ISSUER_LINEAGE_ALREADY_ACTIVATED'):
        activate_collection_issuer_lineage(db,closure_hash=h(8),**args)
    assert tuple(db.iterdump())==activated


def test_collection_journal_requires_matching_active_cutover(tmp_path):
    from solslot_api.generation_customer_issuer import TestnetIssuerJournal
    from solslot_api.generation_customer_issuer_lineage import activate_collection_issuer_lineage
    path=tmp_path/'guard.db';legacy=TestnetIssuerJournal(path,prior())
    balance=calculate_fee_lineage(1000,[])
    activate_collection_issuer_lineage(legacy.db,prior_policy=prior(),next_policy=make_policy()[0],
        expected_rows_hash=issuer_rows_snapshot(legacy.db)[0],fee_balance=balance,closure_hash=h(9))
    with pytest.raises(ValueError,match='POLICY_CHANGED'):legacy._require_binding()
    legacy.close()
    with pytest.raises(ValueError,match='ACTIVE_LINEAGE_REQUIRED'):
        TestnetIssuerJournal(path,make_policy()[0],cutover_hash=h(8))
    active=TestnetIssuerJournal(path,make_policy()[0],cutover_hash=h(9))
    active._require_binding()
    active.db.execute('UPDATE issuer_collection_activation SET closure_hash=?',(h(8),))
    with pytest.raises(ValueError,match='ACTIVE_LINEAGE_REQUIRED'):active._require_binding()
    active.close()
