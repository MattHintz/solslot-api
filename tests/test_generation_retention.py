"""Atomic storage ceilings retain original evidence and reserve completion space."""
from types import SimpleNamespace
from dataclasses import replace
import sqlite3

import pytest
from solslot_api.generation_consents import GenerationConsentStore,ConsentRequest
from solslot_api.generation_holder_ballots import GenerationBallotStore,HolderBallotRequest
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_api.generation_storage import admit_retained_bytes,GenerationStorageError,GenerationRetentionFull
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from tests.test_generation_operations import operation,GENERATION


def test_capacity_requires_atomic_write_and_never_mutates_retained_state():
    db=sqlite3.connect(':memory:',isolation_level=None)
    with pytest.raises(GenerationStorageError):admit_retained_bytes(db,100,1,101)
    db.execute('BEGIN IMMEDIATE');admit_retained_bytes(db,100,1,101)
    for values in ((100,2,101),(100,1,100)):
        with pytest.raises(GenerationRetentionFull):admit_retained_bytes(db,*values)
    for values in ((True,0,100),(0,-1,100)):
        with pytest.raises(GenerationStorageError):admit_retained_bytes(db,*values)
    db.rollback();db.close()


@pytest.mark.parametrize('kind',['consent','ballot'])
def test_full_review_store_keeps_existing_exact_retry_and_original_bytes(tmp_path,kind):
    expected={k:'0x'+'51'*32 for k in ('registry','governance','holdings')}
    common={'generationId':GENERATION,'requestKey':'one','expectedInputs':expected,'feeCapMojos':1000}
    if kind=='consent':
        request=ConsentRequest.model_validate({**common,'kind':'PAUSE_NEW_OPERATIONS','coadministratorSlot':1,'scope':16})
        store=GenerationConsentStore(str(tmp_path/'reviews.db'),GENERATION)
    else:
        request=HolderBallotRequest.model_validate({**common,'kind':'CAST_VOTE','proposalId':'0x'+'52'*32,
            'selected':[{'coinId':'0x'+'53'*32,'vaultLauncherId':'0x'+'54'*32}]})
        store=GenerationBallotStore(str(tmp_path/'reviews.db'),GENERATION)
    def request_document(r):return r.document() if isinstance(r,ConsentRequest) else r.model_dump(mode='json',by_alias=True)
    doc={'generationId':GENERATION,'request':request_document(request),'createdAt':10}
    identity=store.save(request,doc,10)
    with store._db() as db:before=[tuple(r) for r in db.execute('SELECT * FROM '+('generation_consents' if kind=='consent' else 'generation_ballot_reviews'))]
    store.MAX_RETAINED_BYTES=1
    assert store.save(request,doc,10)==identity
    new=request.model_copy(update={'request_key':'two'});changed={**doc,'request':request_document(new)}
    with pytest.raises(GenerationRetentionFull):store.save(new,changed,10)
    with store._db() as db:after=[tuple(r) for r in db.execute('SELECT * FROM '+('generation_consents' if kind=='consent' else 'generation_ballot_reviews'))]
    assert before==after and store.document(identity)==doc


def test_operation_reserves_funding_capacity_and_exact_retry_survives_full_journal(tmp_path):
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    identity=journal.prepare(operation(),'first',1000,10)
    journal.MAX_RETAINED_BYTES=1
    assert journal.prepare(operation(),'first',1000,11)==identity
    original=operation().spends[0]
    changed=replace(operation(),spends=(make_spend(original.coin,Program.to(1),Program.to([[1,b'another exact intent']])),))
    with pytest.raises(GenerationRetentionFull):journal.prepare(changed,'another',1000,11)
    # Fee attachment uses the slot reserved by the original preparation and
    # does not need fresh capacity admission after coins were reserved.
    bundle=operation().bundle()
    prepared=SimpleNamespace(bundle=bundle,backing_mojos=0,fee_mojos=0,spend_bundle_id='0x'+bundle.name().hex(),
        to_json=lambda:{'spendBundle':bundle.to_json_dict(),'feeMojos':0})
    journal.save_funded(identity,prepared,12)
    assert journal.status(identity)['transactionId']==prepared.spend_bundle_id
    assert len(journal.recent())==1


def test_equivalent_operation_aliases_cannot_grow_without_bound(tmp_path):
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),GENERATION)
    digest='0x'+'51'*32
    identity=journal.prepare(operation(),'first',1000,10,request_digest=digest)
    journal.MAX_REVIEW_ALIASES=1
    assert journal.prepare(operation(),'first',1000,11,request_digest=digest)==identity
    with pytest.raises(GenerationRetentionFull):journal.prepare(operation(),'alias',1000,11,request_digest='0x'+'52'*32)
    with journal._db() as db:
        assert db.execute('SELECT count(*) FROM generation_operation_reviews').fetchone()[0]==1
    assert journal.request_status('alias') is None and journal.request_status('first')['operationId']==identity
