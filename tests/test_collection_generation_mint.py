import json
import time
from dataclasses import replace

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.generation_mint import GenerationMint
from solslot_api.collection_generation_mint import build_sealed_test_mint
from solslot_api.collection_store import CollectionStore, CollectionConflict, CollectionInvalidState, CollectionForbidden
from solslot_api.config import Settings
from solslot_api.payment_quotes import parse_authorized_oracle_round, PaymentQuoteError
from solslot_api.test_collection_metadata import TestPropertyDraftV1
from tests.test_payment_quotes import _snapshot
from tests.test_testnet_collection_edition import edition, GEN


def prepared(tmp_path):
    payload = edition()
    store = CollectionStore(tmp_path/'collections.db', generation_id=GEN)
    store.create(collection_id=payload['collectionId'], title=payload['title'], owner_subject='owner',
        owner_auth_type='evm', initial_draft=TestPropertyDraftV1.model_validate(payload))
    keys, round_, raw = _snapshot(int(time.time()))
    settings = Settings(_env_file=None, runtime_environment='test', deployment_generation_id=GEN,
        payment_oracle_operator_pubkeys=['0x'+bytes(k.get_g1()).hex() for k in keys])
    authorized = parse_authorized_oracle_round(settings, raw['rounds'][0])
    mint = GenerationMint(bytes32.from_hexstr(GEN), *[bytes32(bytes([i])*32) for i in range(2,7)],
        bytes32.from_hexstr(payload['offering']['royaltyPuzhash']), bytes32(bytes([8])*32),
        tuple(bytes(k.get_g1()) for k in keys), bytes32(bytes([9])*32))
    parents = tuple(bytes32(bytes([i])*32) for i in range(20,45))
    return store, payload['collectionId'], settings, authorized, mint, parents


def review_and_seal(store, cid):
    collection = store.get(cid)
    store.update_draft(cid,draft=TestPropertyDraftV1.model_validate(collection['dossier']),
        expected_revision=collection['revision'],actor_subject='owner',submit_for_review=True)
    for kind, descriptors in [('MEDIA',collection['dossier']['media']),('DOCUMENT',collection['dossier']['documents'])]:
        for asset in descriptors:
            store.declare_asset(cid, asset_id=asset['assetId'], kind=kind, expected_sha256=asset['sha256'],
                expected_mime_type=asset['mimeType'],expected_byte_size=asset['byteSize'],actor_subject='owner')
            store.mark_asset_uploaded(cid,asset['assetId'],object_key='test/'+asset['assetId'],actor_subject='owner')
            store.mark_asset_verified(cid,asset['assetId'],actual_sha256=asset['sha256'],actual_mime_type=asset['mimeType'],
                actual_byte_size=asset['byteSize'],malware_status='CLEAN',verified_https_url=asset['uris'][0],
                ipfs_cid=asset['cid'],availability_status='HEALTHY',actor_subject='owner')
    store.acknowledge_preview(cid,expected_revision=collection['revision'],expected_draft_hash=collection['draftHash'],actor_subject='owner')
    store.submit_review(cid,reviewer_subject='other-admin',decision='APPROVED',note='Reviewed this exact synthetic edition.')
    assert store.readiness(cid)['ready'], store.readiness(cid)
    return store.seal(cid,expected_revision=collection['revision'],actor_subject='owner')


def test_saved_price_and_sealed_metadata_drive_exact_native_mint_after_restart(tmp_path, monkeypatch):
    store,cid,settings,authorized,mint,parents = prepared(tmp_path)
    priced = store.apply_test_pricing(cid,expected_revision=1,actor_subject='owner',authorized=authorized)
    again = store.apply_test_pricing(cid,expected_revision=priced['revision'],actor_subject='owner',authorized=authorized)
    assert again == priced
    sealed = review_and_seal(store,cid)
    before = store.audit_events(cid)
    built = build_sealed_test_mint(store,settings,mint,cid,parents)
    assert len(built.rows)==25 and all(r.base_usd_minor==300000 and r.share_ppm==40000 for r in built.rows)
    assert sum(r.sealed_par_mojos for r in built.rows)==int(sealed['dossier']['offering']['parValueMojos'])
    assert built.technology_fee_bps==100 and built.pricing_round==authorized.round.round_hash
    assert built.metadata_root==bytes32.from_hexstr(sealed['metadataRoot'])
    assert len({i.coin.name() for i in mint.inventories(built)})==25
    path=store.path;store.close();store=CollectionStore(path,generation_id=GEN)
    # The existing receipt was live when explicitly applied. Later display
    # prices and the mandatory governance delays must not silently reprice it.
    monkeypatch.setattr('time.time',lambda: authorized.round.valid_until+100000)
    assert build_sealed_test_mint(store,settings,mint,cid,parents)==built
    assert store.audit_events(cid)==before
    with pytest.raises(CollectionInvalidState,match='sealed pricing'):
        store.apply_test_pricing(cid,expected_revision=sealed['revision'],actor_subject='owner',authorized=authorized)
    with pytest.raises(ValueError,match='already minted'):
        build_sealed_test_mint(store,settings,mint.minted(built),cid,parents)
    store.close()


def test_pricing_is_explicit_and_material_changes_invalidate_review(tmp_path):
    store,cid,settings,authorized,mint,parents=prepared(tmp_path)
    with pytest.raises(CollectionForbidden):
        store.apply_test_pricing(cid,expected_revision=1,actor_subject='other',authorized=authorized)
    assert 'PRICING_RECEIPT_REQUIRED' in {i['code'] for i in store.readiness(cid)['issues']}
    priced=store.apply_test_pricing(cid,expected_revision=1,actor_subject='owner',authorized=authorized)
    store.update_draft(cid,draft=TestPropertyDraftV1.model_validate(priced['dossier']),
        expected_revision=priced['revision'],actor_subject='owner',submit_for_review=True)
    store.acknowledge_preview(cid,expected_revision=priced['revision'],expected_draft_hash=priced['draftHash'],actor_subject='owner')
    store.submit_review(cid,reviewer_subject='other',decision='APPROVED',note='Reviewed.')
    with pytest.raises(CollectionConflict):
        store.apply_test_pricing(cid,expected_revision=1,actor_subject='owner',authorized=authorized)
    payload=priced['dossier'];payload['offering']['targetRaiseMinor']='8000000'
    saved=store.update_draft(cid,draft=TestPropertyDraftV1.model_validate(payload),expected_revision=priced['revision'],actor_subject='owner')
    issues={i['code'] for i in saved['readiness']['issues']}
    assert {'PRICING_RECEIPT_REQUIRED','PREVIEW_REVIEW_REQUIRED','INDEPENDENT_REVIEW_REQUIRED'}<=issues
    with pytest.raises(CollectionInvalidState):build_sealed_test_mint(store,settings,mint,cid,parents)
    store.close()


@pytest.mark.parametrize('fault',['price-signature','generation','treasury','parents','canonical','preview','review'])
def test_mint_rejects_altered_or_cross_generation_evidence(tmp_path,fault):
    store,cid,settings,authorized,mint,parents=prepared(tmp_path)
    store.apply_test_pricing(cid,expected_revision=1,actor_subject='owner',authorized=authorized)
    review_and_seal(store,cid)
    if fault=='price-signature':
        # Deliberate persisted-evidence corruption, not an API-authorized edit.
        row=store._conn.execute('SELECT evidence_json FROM collection_pricing_receipts').fetchone()
        evidence=json.loads(row[0]);evidence['signatures'].pop()
        store._conn.execute('UPDATE collection_pricing_receipts SET evidence_json=?',(json.dumps(evidence),))
    if fault=='generation':settings=settings.model_copy(update={'deployment_generation_id':'0x'+'aa'*32})
    if fault=='treasury':mint=replace(mint,treasury_puzzle_hash=bytes32(bytes([90])*32))
    if fault=='parents':parents=parents[:-1]
    if fault=='canonical':
        row=store._conn.execute('SELECT canonical_json FROM property_collections').fetchone()
        payload=json.loads(row[0]);payload['summary']='Altered after sealing.'
        store._conn.execute('UPDATE property_collections SET canonical_json=?',(json.dumps(payload).encode(),))
    if fault=='preview':store._conn.execute('DELETE FROM property_collection_previews')
    if fault=='review':store._conn.execute('DELETE FROM property_collection_reviews')
    with pytest.raises((ValueError,PaymentQuoteError,CollectionConflict,CollectionInvalidState)):
        build_sealed_test_mint(store,settings,mint,cid,parents)
    store.close()
