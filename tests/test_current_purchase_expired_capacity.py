"""Capacity is reused only for an exact native expiry proof; journals persist."""
import json
from types import SimpleNamespace
import pytest
from tests.test_current_purchase_execution_recovery import recover
from tests.test_current_purchase_worker import expiry_prover, no_issuer
from tests.test_current_purchase_store import BROWSER
from solslot_api.generation_customer_purchase_worker import CurrentPurchaseWorker
from solslot_api.generation_customer_purchase_batch import reservation_from_json

@pytest.mark.asyncio
async def test_exact_expiry_proof_recycles_capacity_and_all_uncertain_states_retain_it(recover,monkeypatch):
    r=recover
    monkeypatch.setattr('solslot_api.generation_customer_purchase_worker.purchase_artifact_v3_from_json',lambda _:SimpleNamespace(quote_expires_at=200))
    monkeypatch.setattr('solslot_api.generation_customer_purchase_batch.artifacts',lambda _: (SimpleNamespace(quote_expires_at=200),))
    monkeypatch.setattr('solslot_api.protocol_admission.admission_conditions',lambda bundle,height,network:SimpleNamespace(before_seconds_absolute=200))
    expiry_prover(r);worker=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await worker.tick()
    with r.store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM current_customer_purchase_reviews WHERE intent_id=?',(r.identity,)).fetchone()
        claim=reservation_from_json(row['canonical_claim'])
        def admitted():
            try:r.store._purchase_capacity(db,'0x'+'ff'*32,claim,1);return True
            except ValueError as e:
                assert 'CAPACITY_EXHAUSTED' in str(e);return False
        assert admitted()
        proof=json.loads(db.execute('SELECT expiry_document FROM current_purchase_worker_jobs').fetchone()[0])
        for key,value in [('bundleId','0x'+'aa'*32),('absoluteExpiry',201),('inputIds',[]),('peakTimestamp',199),('allInputsUnspentAndClear',False)]:
            altered={**proof,key:value}
            db.execute('UPDATE current_purchase_worker_jobs SET expiry_document=?',(json.dumps(altered),));assert not admitted()
        db.execute('UPDATE current_purchase_worker_jobs SET expiry_document=?',(json.dumps({**proof,'padding':'x'*4097}),));assert not admitted()
        db.execute('UPDATE current_purchase_worker_jobs SET expiry_document=?,lease_token=?',(json.dumps(proof),'active'));assert not admitted()
        db.execute('UPDATE current_purchase_worker_jobs SET lease_token=NULL,state=?',('WAITING',));assert not admitted()
        db.execute('UPDATE current_purchase_worker_jobs SET state=?',('CLOSED',))
        db.execute("UPDATE current_purchase_worker_jobs SET issuer_document='{}'");assert not admitted()
        db.execute('UPDATE current_purchase_worker_jobs SET issuer_document=NULL')
        monkeypatch.setattr('solslot_api.protocol_admission.admission_conditions',lambda *args:SimpleNamespace(before_seconds_absolute=201));assert not admitted()
        monkeypatch.setattr('solslot_api.protocol_admission.admission_conditions',lambda *args:SimpleNamespace(before_seconds_absolute=200))
        db.execute("UPDATE current_purchase_executions SET funded_document='{}' WHERE phase='RESERVATION'");assert not admitted()
        db.execute("UPDATE current_purchase_executions SET funded_document=NULL,transaction_id=? WHERE phase='RESERVATION'",('0x'+'bb'*32,));assert not admitted()
        db.execute("UPDATE current_purchase_executions SET transaction_id=NULL WHERE phase='RESERVATION'")
        db.execute("INSERT INTO current_customer_purchase_signatures VALUES(?,?,?,?)",(r.identity,'delivery',0,'{}'));assert not admitted()
        db.execute("DELETE FROM current_customer_purchase_signatures WHERE phase='delivery'")
        db.execute('INSERT INTO current_customer_purchase_delivery VALUES(?,?,?,?)',(r.identity,'0x'+'dd'*32,'{}',200));assert not admitted()
        db.execute('DELETE FROM current_customer_purchase_delivery')
        assert admitted()
        assert db.execute('SELECT count(*) FROM current_purchase_executions').fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM current_customer_purchase_reviews').fetchone()[0]==1
        db.rollback()
