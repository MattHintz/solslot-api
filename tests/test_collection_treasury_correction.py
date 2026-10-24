from copy import deepcopy
from dataclasses import replace
import json
import sqlite3
import pytest
from chia_rs.sized_bytes import bytes32
from solslot_api.collection_store import CollectionStore, CollectionConflict, CollectionInvalidState, CollectionForbidden, CollectionNotReady
from solslot_api.collection_generation_mint import build_sealed_test_mint, MintTreasuryMismatch
from solslot_api.generation_mint_review_routes import _error
from solslot_api.test_collection_metadata import TestPropertyDraftV1
from tests.test_collection_generation_mint import prepared, review_and_seal


NEW='0x'+'b4'*32


def sealed(tmp_path):
    store,cid,settings,authorized,mint,parents=prepared(tmp_path)
    store.apply_test_pricing(cid,expected_revision=1,actor_subject='owner',authorized=authorized)
    before=review_and_seal(store,cid)
    store.mint_treasury=NEW;store.mint_authority_required=True
    return store,cid,settings,mint,parents,before


def test_mismatch_blocks_seal_and_correction_preserves_source_economics_and_price(tmp_path):
    store,cid,settings,mint,parents,before=sealed(tmp_path)
    assert 'MINT_TREASURY_MISMATCH' in {i['code'] for i in store.readiness(cid)['issues']}
    original=store._conn.execute('SELECT canonical_json,dossier_json FROM property_collections WHERE id=?',(cid,)).fetchone()
    args=dict(expected_revision=before['revision'],expected_metadata_root=before['metadataRoot'],treasury=NEW,actor_subject='owner')
    corrected=store.correct_unissued_test_treasury(cid,**args)
    assert corrected['state']=='DRAFT' and corrected['revision']==before['revision']+1
    assert corrected['metadataRoot'] is None and corrected['sealedAt'] is None
    expected=deepcopy(before['dossier']);expected['revision']+=1;expected['offering']['royaltyPuzhash']=NEW
    assert corrected['dossier']==expected
    archive=store._conn.execute('SELECT * FROM property_collection_seal_archives').fetchone()
    assert archive['canonical_json']==original['canonical_json'] and archive['dossier_json']==original['dossier_json']
    assert '0x'+archive['metadata_root'].hex()==before['metadataRoot']
    assert {'PREVIEW_REVIEW_REQUIRED','INDEPENDENT_REVIEW_REQUIRED'} <= {i['code'] for i in corrected['readiness']['issues']}
    assert 'PRICING_RECEIPT_REQUIRED' not in {i['code'] for i in corrected['readiness']['issues']}
    audit=store.audit_events(cid)
    for _ in range(3):assert store.correct_unissued_test_treasury(cid,**args)==corrected
    assert store.audit_events(cid)==audit
    with pytest.raises(CollectionNotReady):store.seal(cid,expected_revision=corrected['revision'],actor_subject='owner')
    for field,value in [('treasury','0x'+'c5'*32),('expected_metadata_root','0x'+'c6'*32)]:
        with pytest.raises(CollectionConflict):store.correct_unissued_test_treasury(cid,**{**args,field:value})
    with pytest.raises(CollectionForbidden):store.correct_unissued_test_treasury(cid,**{**args,'actor_subject':'other'})
    # Previously reviewed metadata is immutable across close/reopen and SQLite restore.
    backup=sqlite3.connect(tmp_path/'restored.db');store._conn.backup(backup);backup.close();store.close()
    restored=CollectionStore(tmp_path/'restored.db',generation_id=settings.deployment_generation_id)
    restored.mint_treasury=NEW;restored.mint_authority_required=True
    assert restored._conn.execute('SELECT canonical_json FROM property_collection_seal_archives').fetchone()[0]==original['canonical_json']
    current=restored.get(cid)
    assert current['retainedSeals'][0]['metadataRoot']==before['metadataRoot']
    restored.update_draft(cid,draft=TestPropertyDraftV1.model_validate(current['dossier']),
        expected_revision=current['revision'],actor_subject='owner',submit_for_review=True)
    restored.acknowledge_preview(cid,expected_revision=current['revision'],expected_draft_hash=current['draftHash'],actor_subject='owner')
    restored.submit_review(cid,reviewer_subject='other-admin',decision='APPROVED',note='Reviewed corrected destination.')
    after=restored.seal(cid,expected_revision=current['revision'],actor_subject='owner')
    assert after['metadataRoot']!=before['metadataRoot']
    edition=build_sealed_test_mint(restored,settings,replace(mint,treasury_puzzle_hash=bytes32.from_hexstr(NEW)),cid,parents)
    assert len(edition.rows)==25 and sum(r.base_usd_minor for r in edition.rows)==7500000
    assert len({i.coin.name() for i in replace(mint,treasury_puzzle_hash=bytes32.from_hexstr(NEW)).inventories(edition)})==25
    restored.close()


@pytest.mark.parametrize('fault',['published','locked','proposal','owner','generation','same','untrusted','root','revision','canonical','preview','review'])
def test_correction_rejects_issued_wrong_owner_and_changed_inputs(tmp_path,fault):
    store,cid,settings,mint,parents,before=sealed(tmp_path)
    args=dict(expected_revision=before['revision'],expected_metadata_root=before['metadataRoot'],treasury=NEW,actor_subject='owner')
    if fault=='published':store._conn.execute("UPDATE property_collections SET state='PUBLISHED',published_at=1 WHERE id=?",(cid,))
    elif fault=='locked':store._conn.execute('UPDATE property_collections SET allocation_locked=1 WHERE id=?',(cid,))
    elif fault=='proposal':store._conn.execute("UPDATE property_collection_deeds SET proposal_id='saved' WHERE collection_id=?",(cid,))
    elif fault=='owner':args['actor_subject']='other'
    elif fault=='generation':store.network='mainnet'
    elif fault=='same':args['treasury']=before['dossier']['offering']['royaltyPuzhash'];store.mint_treasury=args['treasury']
    elif fault=='untrusted':args['treasury']='0x'+'c5'*32
    elif fault=='root':args['expected_metadata_root']='0x'+'c5'*32
    elif fault=='revision':args['expected_revision']+=1
    elif fault=='canonical':
        raw=json.loads(store._conn.execute('SELECT canonical_json FROM property_collections').fetchone()[0])
        raw['summary']='Corrupt saved metadata'
        store._conn.execute('UPDATE property_collections SET canonical_json=?',(json.dumps(raw).encode(),))
    elif fault=='preview':store._conn.execute('DELETE FROM property_collection_previews')
    elif fault=='review':store._conn.execute('DELETE FROM property_collection_reviews')
    with pytest.raises((CollectionConflict,CollectionInvalidState,CollectionForbidden)):
        store.correct_unissued_test_treasury(cid,**args)
    assert store._conn.execute('SELECT count(*) FROM property_collection_seal_archives').fetchone()[0]==0
    store.close()


def test_mismatch_is_actionable_and_does_not_claim_a_saved_batch():
    err=_error(MintTreasuryMismatch('wrong destination'))
    assert err.status_code==409 and err.detail['code']=='GENERATION_MINT_TREASURY_MISMATCH'
    assert 'No mint batch or funding holds' in err.detail['message']


def test_readiness_without_verified_authority_blocks_sealing(tmp_path):
    store,cid,settings,authorized,mint,parents=prepared(tmp_path)
    store.mint_authority_required=True
    assert 'MINT_AUTHORITY_REQUIRED' in {i['code'] for i in store.readiness(cid)['issues']}
    store.close()
