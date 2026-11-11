"""Read-only predecessor recovery, with real SQLite and retained signed work."""
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace

from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from solslot_puzzles.payment_artifacts_v3 import (build_purchase_batch_v1,purchase_batch_to_json,
    purchase_artifact_v3_to_json)

from solslot_api import generation_customer_purchase_routes as routes
from solslot_api.config import get_settings
from solslot_api.generation_customer_issuer import TestnetIssuerPolicy as IssuerPolicy
from solslot_api.generation_customer_purchase_batch import CurrentReservationBatch,CurrentDeliveryBatch
from solslot_api.generation_customer_purchase_delivery import CurrentDeliveryClaim
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution,h
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from tests.test_current_purchase_execution_store import bundle
from tests.test_current_purchase_private_boundary import write_policy
from tests.test_current_purchase_store import BROWSER
from tests.test_native_purchases import _context,_b32

ORIGIN={'Origin':'https://solslot.com','Sec-Fetch-Site':'same-origin'}


@pytest.fixture(params=[1,2,3])
def retired(tmp_path,request):
    keys=tuple(AugSchemeMPL.key_gen(bytes([i])*32)for i in (51,52,53))
    contexts=[_context(AugSchemeMPL.key_gen(b'p'*32),keys,deed_parent_seed=i,now=100)[0]for i in (61,62,63)]
    first=contexts[0].purchase
    prior=IssuerPolicy(_b32(1),first.collection_id,first.metadata_anchor_id,first.metadata_root,
        contexts[0].terms.protocol_puzhash,first.protocol_treasury_puzzle_hash,bytes(keys[2].get_g1()),
        frozenset(c.purchase.deed_launcher_id for c in contexts),first.vault_launcher_id,10**14,3,90,800)
    current=replace(prior,issued_at=900,expires_at=1400)
    path,pin=write_policy(tmp_path,prior.public())
    purchases=sorted([c.purchase for c in contexts[:request.param]],key=lambda a:bytes(a.deed_launcher_id))
    children=tuple(CurrentReservationClaim(generationId=h(prior.generation),anchorHash=h(_b32(2)),
        issuerPolicyHash=prior.commitment,purchaseArtifact=purchase_artifact_v3_to_json(a),signedPrice={},
        availableCoinId=h(_b32(i+10)),currentVaultCoinId=h(_b32(5)),signerIndices=(0,1))
        for i,a in enumerate(purchases))
    claim=(children[0]if request.param==1 else CurrentReservationBatch(
        purchaseBatch=purchase_batch_to_json(build_purchase_batch_v1(batch_nonce=_b32(64),artifacts=purchases)),children=children))
    store=CurrentPurchaseExecutionStore(tmp_path/'retained.db',h(prior.generation))
    store.bind_execution_policy(prior.commitment,3,10);store.bind_execution_policy(current.commitment,3,10)
    identity=store.save_review(claim,browser_hash=BROWSER,request_key='old-browser-key',now=101)
    def reply(index=0):
        return {'claimHash':claim.digest(),'signerIndex':index,'validatorPubkey':h(keys[index].get_g1()),
            'signature':h(AugSchemeMPL.sign(keys[index],bytes.fromhex(claim.digest()[2:])))}
    store.save_signature(identity,'reservation',0,reply(),browser_hash=BROWSER)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=h(prior.generation),
        generation_chain_anchor_hash=h(_b32(2)),generation_customer_purchase_enabled=True,
        generation_customer_public_origin='https://solslot.com',
        generation_customer_purchase_prior_policy_path=str(path),generation_customer_purchase_prior_policy_hash=pin)
    service=object.__new__(CurrentNativePurchaseExecution)
    service.settings=settings;service.policy=current;service.store=store;service.fee_cap=10;service.clock=lambda:1000
    class NoPrivateOrNode:
        def __getattr__(self,name):raise AssertionError('Recovery reached private/node service: '+name)
    service.provider=NoPrivateOrNode();service.anchor=NoPrivateOrNode();service.submitter=None
    return SimpleNamespace(store=store,service=service,settings=settings,claim=claim,identity=identity,
        prior=prior,current=current,children=children,purchases=purchases,quantity=request.param,reply=reply)


def fingerprint(store):
    with store._connect()as db:
        return sha256('\n'.join(db.iterdump()).encode()).hexdigest()


def observe_only(store,monkeypatch):
    original=store._connect;connections=[]
    @contextmanager
    def checked():
        with original()as db:
            before=db.total_changes;statements=[];db.set_trace_callback(statements.append)
            try:yield db
            finally:
                assert db.total_changes==before==0
                assert not any(sql.lstrip().upper().startswith(('INSERT','UPDATE','DELETE','REPLACE','CREATE','ALTER','DROP'))for sql in statements)
                connections.append(statements)
    monkeypatch.setattr(store,'_connect',checked)
    return connections


def selected(r):return h(r.purchases[0].deed_launcher_id)if r.quantity==1 else [h(a.deed_launcher_id)for a in r.purchases]


@pytest.mark.asyncio
async def test_get_and_same_key_retry_restore_frozen_terminal_review_without_writes_or_network(retired,monkeypatch):
    r=retired;before=fingerprint(r.store);saved=r.store.saved(r.identity,browser_hash=BROWSER)
    connections=observe_only(r.store,monkeypatch)
    review=r.service.review(r.identity,browser_hash=BROWSER)
    assert review['quoteExpired']is True and review['reservationRequested']is False and review['payerAuthorizationSaved']is False
    assert 'reservation'not in review and 'delivery'not in review
    assert review['reservationClaimHash']==r.claim.digest()
    assert await r.service.quote('old-browser-key',selected(r),browser_hash=BROWSER)==review
    assert r.service.review(r.identity,browser_hash=BROWSER)==review
    assert r.store.saved(r.identity,browser_hash=BROWSER)==saved
    assert fingerprint(r.store)==before and connections
    assert any(statements[0]=='BEGIN'for statements in connections if statements)


def test_http_get_and_same_key_post_use_existing_terminal_contract(retired,monkeypatch):
    r=retired;app=FastAPI();app.include_router(routes.router)
    app.dependency_overrides[get_settings]=lambda:r.settings
    monkeypatch.setattr(routes,'context',lambda *a:(r.service,BROWSER,'evm'))
    before=fingerprint(r.store);observe_only(r.store,monkeypatch)
    target='/customer/purchases/'+h(r.prior.buyer_vault)
    selection={'deedLauncherId':selected(r)}if r.quantity==1 else {'deedLauncherIds':selected(r)}
    with TestClient(app)as client:
        read=client.get(target+'/'+r.identity)
        retry=client.post(target+'/quotes',headers=ORIGIN,json={
            'generationId':r.store.generation_id,'requestKey':'old-browser-key',**selection})
    assert read.status_code==retry.status_code==200 and read.json()==retry.json()
    assert read.headers['cache-control']==retry.headers['cache-control']=='no-store'
    assert read.json()['quoteExpired']and not read.json()['reservationRequested']and not read.json()['payerAuthorizationSaved']
    assert fingerprint(r.store)==before


@pytest.mark.asyncio
async def test_matching_retry_never_changes_selection_or_quantity(retired):
    r=retired
    other=h(_b32(99))if r.quantity==1 else [h(_b32(99)),*selected(r)[1:]]
    with pytest.raises(ValueError,match='REQUEST_KEY_DEED_CHANGED'):
        await r.service.quote('old-browser-key',other,browser_hash=BROWSER)
    if r.quantity>1:
        assert await r.service.quote('old-browser-key',list(reversed(selected(r))),browser_hash=BROWSER)==r.service.review(r.identity,browser_hash=BROWSER)
        with pytest.raises(ValueError,match='REQUEST_KEY_DEED_CHANGED'):
            await r.service.quote('old-browser-key',selected(r)[0],browser_hash=BROWSER)


@pytest.mark.asyncio
async def test_restored_history_cannot_reach_any_financial_saved_guard(retired):
    r=retired;before=fingerprint(r.store)
    for action in [lambda:r.service._saved(r.identity,BROWSER),
            lambda:r.service.request_reservation(r.identity,browser_hash=BROWSER)]:
        with pytest.raises(ValueError,match='SAVED_POLICY_CHANGED'):action()
    for action in [r.service.prepare_reservation(r.identity,browser_hash=BROWSER),
            r.service.payer_coins(r.identity,[],browser_hash=BROWSER),
            r.service.prepare_wallet(r.identity,None,browser_hash=BROWSER),
            r.service.accept_payer(r.identity,None,browser_hash=BROWSER),
            r.service.dispatch(r.identity,'RESERVATION',browser_hash=BROWSER)]:
        with pytest.raises(ValueError,match='SAVED_POLICY_CHANGED'):await action
    assert fingerprint(r.store)==before


@pytest.mark.parametrize('state',['queued','prepared','funded_unknown','delivery_execution','payer','delivery_signature','full_quorum'])
def test_inflight_payer_funded_or_complete_quorum_never_becomes_terminal(retired,state):
    r=retired
    if state=='queued':r.store.request_reservation(r.identity,browser_hash=BROWSER,now=200)
    elif state in ('prepared','funded_unknown','delivery_execution'):
        r.store.prepare_execution(r.identity,'RESERVATION',bundle(),browser_hash=BROWSER,
            claim_hash=r.claim.digest(),fee_cap=10,expires_at=400,now=200)
        if state!='prepared':
            with r.store._connect()as db:
                if state=='funded_unknown':db.execute("UPDATE current_purchase_executions SET stage='RECONCILING',funded_document='unknown' WHERE intent_id=?",(r.identity,))
                else:db.execute("UPDATE current_purchase_executions SET phase='DELIVERY' WHERE intent_id=?",(r.identity,))
    elif state=='payer':
        delivery=(CurrentDeliveryClaim(reservation=r.claim,reservedCoinId=h(_b32(77)),buyerOffer='offer1'+'a'*64)
            if r.quantity==1 else CurrentDeliveryBatch(reservation=r.claim,
                reservedCoinIds=tuple(h(_b32(77+i))for i in range(r.quantity)),buyerOffer='offer1'+'a'*64))
        r.store.save_delivery(r.identity,delivery,browser_hash=BROWSER,now=200)
    elif state=='delivery_signature':
        with r.store._connect()as db:
            db.execute('INSERT INTO current_customer_purchase_signatures VALUES(?,?,?,?)',
                (r.identity,'delivery',0,json.dumps(r.reply())))
    else:r.store.save_signature(r.identity,'reservation',1,r.reply(1),browser_hash=BROWSER)
    before=fingerprint(r.store)
    with pytest.raises(ValueError,match='REVIEW_RECOVERY_REQUIRED'):
        r.service.review(r.identity,browser_hash=BROWSER)
    assert fingerprint(r.store)==before


@pytest.mark.parametrize('fault',['owner','generation','anchor','no_pin','bad_pin','scope','not_expired'])
def test_terminal_recovery_does_not_weaken_owner_generation_pin_or_scope(retired,fault):
    r=retired;binding=BROWSER
    if fault=='owner':binding='cd'*32
    elif fault=='generation':r.settings.deployment_generation_id=h(_b32(99))
    elif fault=='anchor':r.settings.generation_chain_anchor_hash=h(_b32(99))
    elif fault=='no_pin':r.settings.generation_customer_purchase_prior_policy_path='';r.settings.generation_customer_purchase_prior_policy_hash=''
    elif fault=='bad_pin':r.settings.generation_customer_purchase_prior_policy_hash=h(_b32(99))
    elif fault=='scope':r.service.policy=replace(r.current,maximum_gross_mojos=r.current.maximum_gross_mojos+1)
    else:r.service.clock=lambda:750
    before=fingerprint(r.store)
    with pytest.raises(ValueError):r.service.review(r.identity,browser_hash=binding)
    assert fingerprint(r.store)==before


def test_corrupt_saved_hash_is_not_reclassified_as_a_retired_policy(retired,monkeypatch):
    r=retired
    with r.store._connect()as db:db.execute('UPDATE current_customer_purchase_reviews SET claim_hash=?',(h(_b32(99)),))
    def forbidden(*a,**kw):raise AssertionError('Unrelated history error reached retirement fallback')
    monkeypatch.setattr(r.store,'unstarted_review',forbidden)
    with pytest.raises(ValueError,match='SAVED_REVIEW_CHANGED'):r.service.review(r.identity,browser_hash=BROWSER)


@pytest.mark.asyncio
async def test_fresh_current_policy_quotes_still_enter_existing_native_pipeline(retired,monkeypatch):
    r=retired
    class FreshPipeline(Exception):pass
    async def inventory(**kw):raise FreshPipeline()
    monkeypatch.setattr('solslot_api.generation_customer_purchase_execution.resolve_current_primary_inventory',inventory)
    monkeypatch.setattr('solslot_api.generation_customer_purchase_batch_execution.resolve_current_primary_inventory',inventory)
    with pytest.raises(FreshPipeline):await r.service.quote('explicit-new-browser-key',selected(r),browser_hash=BROWSER)
