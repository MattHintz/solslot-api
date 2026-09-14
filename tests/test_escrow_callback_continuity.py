"""Late callback binding and bounded work; no live provider or chain writes."""
import asyncio
from copy import deepcopy
import json
import sqlite3
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from chia_rs.sized_bytes import bytes32

from solslot_api import protocol_artifacts as api, escrow_verification_work as work, stripe_deliveries
from solslot_api.config import get_settings
from solslot_api.payment_purchase_store import get_payment_purchase_store
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import build_sgt_purchase_artifact_v3, purchase_artifact_v3_to_json
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from tests.test_escrow_deposit import Chain, h

NOW=1_900_000_000
TOKEN='test-omnichain-callback-token-32-characters'


def callback_case(tmp_path,monkeypatch,seed=1):
    token='0x'+'13'*20;vault=bytes32.from_hexstr(h(71))
    p=build_sgt_purchase_artifact_v3(network='testnet11',sgt_asset_id=bytes32.from_hexstr(h(72)),
        sale_id=bytes32.from_hexstr(h(73)),sgt_amount=2500,base_usd_amount_minor=50_000,technology_fee_bps=100,
        protocol_treasury_puzzle_hash=bytes32.from_hexstr(h(74)),zkpassport_root=bytes32.from_hexstr(h(75)),
        rail=PaymentRail.EVM_TEST_USD,rail_chain_id=84532,
        rail_asset_id=bytes32(bytes(12)+bytes.fromhex(token[2:])),rail_asset_decimals=6,
        vault_launcher_id=vault,vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault),
        authorization_nonce=bytes32.from_hexstr(h(seed)),authorization_expires_at=NOW+600,quote_expires_at=NOW+100)
    raw=purchase_artifact_v3_to_json(p)
    settings=SimpleNamespace(payment_purchase_db_path=str(tmp_path/'purchases.db'),
        payment_evm_usdc_tokens={'84532':token},payment_omnichain_rpc_url='https://offline.invalid',
        payment_omnichain_ingest_token=TOKEN,protocol_artifact_service_token=TOKEN,
        stripe_delivery_db_path=str(tmp_path/'deliveries.db'),runtime_environment='test',
        alpha_writes_enabled=False,minting_enabled=False)
    store=get_payment_purchase_store(settings.payment_purchase_db_path)
    store.save(purchase_intent_id='internal-'+str(seed),rail='base_usdc',offer_artifact_hash='sha256:'+h(seed)[2:],
        offer_artifact={'purchaseArtifactV3':raw},purchase_artifact=raw,created_at=NOW-10)
    e=Chain().evidence
    e.update(purchaseId=raw['purchaseId'],artifactHash=raw['artifactHash'],amount=p.rail_amount,
             quantity=p.delivery_amount,collectionId=raw['deliveryContextHash'],deedLauncherId=raw['deliveryAssetId'],
             vaultLauncherId=raw['vaultLauncherId'],destinationPuzzle=raw['vaultP2PuzzleHash'])
    e['source']['transactionHash']=h(seed+100);e['globalPaymentId']=h(seed+150)
    chain=Chain(e)
    monkeypatch.setattr(api,'Web3',chain.web3)
    monkeypatch.setattr(api,'load_omnichain_evidence',lambda *a,**kw:SimpleNamespace(
        spoke_address=e['source']['spoke'],confirmations=12))
    payload=api.VerifyExternalEscrowWebhookRequest.model_validate(dict(
        escrowMessage={k:v for k,v in e.items() if k!='source'},source=e['source']))
    return SimpleNamespace(purchase=p,raw=raw,settings=settings,store=store,chain=chain,payload=payload,evidence=e)


@pytest.mark.asyncio
async def test_delayed_first_callback_binds_timely_payment_while_new_writes_paused(tmp_path,monkeypatch):
    c=callback_case(tmp_path,monkeypatch)
    monkeypatch.setattr(api.time,'time',lambda:NOW+1000)
    result=await api.receive_external_escrow_webhook(c.payload,c.settings,'Bearer '+TOKEN)
    assert result['escrow']['verified'] is True
    stored=c.store.get(c.raw['purchaseId'])
    assert stored.external_message==c.evidence
    assert stored.inventory_state=='UNRESERVED'
    assert stored.inventory_expires_at is None
    replay=await api.verify_external_escrow(c.payload,c.settings,'Bearer '+TOKEN)
    assert replay.verified and c.store.get(c.raw['purchaseId'])==stored
    # Verification records a payment, never a final settlement, fresh purchase
    # authorization or invented inventory extension.
    assert len([call for call in c.chain.calls if call[0]=='receipt'])==2


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['auth','amount','destination','quote','wrong_deployment','replay'])
async def test_invalid_or_replacement_callbacks_reject_before_rpc(tmp_path,monkeypatch,problem):
    c=callback_case(tmp_path,monkeypatch);body=c.payload.model_dump(mode='json',by_alias=True);auth='Bearer '+TOKEN
    if problem=='auth': auth='Bearer wrong'
    elif problem=='amount': body['escrowMessage']['amount']+=1
    elif problem=='destination': body['escrowMessage']['destinationPuzzle']=h(90)
    elif problem=='quote': body['source']['blockTimestamp']=NOW+100
    elif problem=='wrong_deployment': body['source']['spoke']='0x'+'ff'*20
    else:
        c.store.bind_external_message(c.raw['purchaseId'],c.evidence)
        body['escrowMessage']['globalPaymentId']=h(91)
    with pytest.raises(HTTPException) as exc:
        await api.verify_external_escrow(api.VerifyExternalEscrowWebhookRequest.model_validate(body),c.settings,auth)
    assert exc.value.status_code in (401,409)
    assert c.chain.calls==[]


@pytest.mark.asyncio
async def test_refunded_replay_keeps_original_receipt_and_never_rebinds(tmp_path,monkeypatch):
    c=callback_case(tmp_path,monkeypatch)
    await api.verify_external_escrow(c.payload,c.settings,'Bearer '+TOKEN)
    stored=c.store.get(c.raw['purchaseId']);c.chain.latest[18:]=[5,False]
    with pytest.raises(HTTPException) as exc:
        await api.verify_external_escrow(c.payload,c.settings,'Bearer '+TOKEN)
    assert exc.value.status_code==409 and 'eligible' in exc.value.detail
    assert c.store.get(c.raw['purchaseId'])==stored


@pytest.mark.asyncio
async def test_provider_outage_is_retryable_without_payment_or_inventory_mutation(tmp_path,monkeypatch):
    c=callback_case(tmp_path,monkeypatch);before=c.store.get(c.raw['purchaseId']);c.chain.fail='receipt'
    with pytest.raises(HTTPException) as exc:
        await api.verify_external_escrow(c.payload,c.settings,'Bearer '+TOKEN)
    assert exc.value.status_code==503 and exc.value.headers['Retry-After']=='5'
    assert c.store.get(c.raw['purchaseId'])==before
    calls=len(c.chain.calls)
    with pytest.raises(HTTPException) as exc:
        await api.verify_external_escrow(c.payload,c.settings,'Bearer '+TOKEN)
    assert exc.value.status_code==503 and 'cooling' in exc.value.detail
    assert len(c.chain.calls)==calls


async def spin_until(predicate):
    for _ in range(100):
        if predicate():return
        await asyncio.sleep(0.01)
    raise AssertionError('bounded worker did not reach expected state')


@pytest.mark.asyncio
async def test_callback_pressure_keeps_actual_recovery_status_responsive(tmp_path,monkeypatch):
    c=callback_case(tmp_path,monkeypatch)
    started=threading.Event();release=threading.Event();finished=threading.Event()
    def slow(*a,**kw):
        started.set()
        try:
            if not release.wait(3):raise RuntimeError('test worker timed out')
        finally:finished.set()
    monkeypatch.setattr(api,'_verify_external_escrow_chain_evidence',slow)
    app=FastAPI();app.include_router(api.router);app.include_router(stripe_deliveries.router)
    app.dependency_overrides[get_settings]=lambda:c.settings
    headers={'Authorization':'Bearer '+TOKEN}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://local') as client:
        request=asyncio.create_task(client.post('/protocol/external-payments/verify',
            json=c.payload.model_dump(mode='json',by_alias=True),headers=headers))
        try:
            await spin_until(started.is_set)
            start=time.monotonic()
            duplicates=await asyncio.gather(*[client.post('/protocol/external-payments/verify',
                json=c.payload.model_dump(mode='json',by_alias=True),headers=headers) for _ in range(24)])
            assert all(r.status_code==503 for r in duplicates)
            # An actual retained-settlement recovery route uses its own ledger,
            # not the deposit verification pool, even while writes are paused.
            recovery=await client.get('/protocol/stripe-deliveries/base-settlements/pending',headers=headers)
            assert recovery.status_code==200,recovery.text
            assert recovery.json()['authorizations']==[]
            assert time.monotonic()-start<1.0
            assert not finished.is_set()
        finally:
            release.set()
            assert (await request).status_code==200


@pytest.mark.asyncio
@pytest.mark.parametrize('stop',['cancel','timeout'])
async def test_abandoned_http_request_cannot_recycle_running_worker(tmp_path,monkeypatch,stop):
    c=callback_case(tmp_path,monkeypatch);started=threading.Event();release=threading.Event();finished=threading.Event()
    def slow():
        started.set()
        try: assert release.wait(3)
        finally: finished.set()
    if stop=='timeout':monkeypatch.setattr(work,'RESPONSE_DEADLINE_SECONDS',0.02)
    task=asyncio.create_task(work.run_deposit_verification(c.settings.payment_purchase_db_path,c.raw['purchaseId'],slow))
    try:
        await spin_until(started.is_set)
        if stop=='cancel':
            task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
        else:
            with pytest.raises(work.EscrowProviderUnavailable,match='timed out'): await task
        for _ in range(24):
            with pytest.raises(work.EscrowVerificationBusy):
                await work.run_deposit_verification(c.settings.payment_purchase_db_path,c.raw['purchaseId'],lambda:pytest.fail('overlap'))
        assert not finished.is_set()
        with sqlite3.connect(c.settings.payment_purchase_db_path) as db:
            assert db.execute('SELECT owner,lease_until FROM payment_escrow_verification_leases').fetchone()[1]>time.time()
    finally:
        release.set();await spin_until(finished.is_set)
        # Wait for the worker's own lease cleanup, not merely the provider return.
        await spin_until(lambda: _lease_finished(c))


def _lease_finished(c):
    with sqlite3.connect(c.settings.payment_purchase_db_path) as db:
        return db.execute('SELECT owner FROM payment_escrow_verification_leases').fetchone()[0] is None


def test_durable_capacity_and_owner_fencing_do_not_touch_recovery_leases(tmp_path,monkeypatch):
    cases=[callback_case(tmp_path,monkeypatch,i+1) for i in range(5)];path=cases[0].settings.payment_purchase_db_path
    for i,c in enumerate(cases[:4]):work.acquire(path,c.raw['purchaseId'],str(i),now=100)
    with pytest.raises(work.EscrowVerificationBusy,match='capacity'):work.acquire(path,cases[4].raw['purchaseId'],'fifth',now=100)
    work.finish(path,cases[0].raw['purchaseId'],'wrong-owner',now=100,succeeded=True)
    with pytest.raises(work.EscrowVerificationBusy):work.acquire(path,cases[4].raw['purchaseId'],'fifth',now=100)
    work.finish(path,cases[0].raw['purchaseId'],'0',now=100,succeeded=False)
    with pytest.raises(work.EscrowVerificationBusy,match='cooling'):work.acquire(path,cases[0].raw['purchaseId'],'retry',now=104)
    work.acquire(path,cases[4].raw['purchaseId'],'fifth',now=104)
    # Process-death lease expiry permits retry, but an old worker cannot release
    # the replacement owner. Inventory admission/recovery capacity is separate.
    work.acquire(path,cases[0].raw['purchaseId'],'new-owner',now=221)
    work.finish(path,cases[0].raw['purchaseId'],'0',now=222,succeeded=True)
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT owner FROM payment_escrow_verification_leases WHERE purchase_id=?',(cases[0].raw['purchaseId'],)).fetchone()[0]=='new-owner'
        assert db.execute('SELECT count(*) FROM payment_checkout_quorum_leases').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM payment_checkout_holds').fetchone()[0]==0


@pytest.mark.asyncio
async def test_distinct_payments_cannot_queue_more_than_four_workers(tmp_path,monkeypatch):
    cases=[callback_case(tmp_path,monkeypatch,i+1) for i in range(5)]
    releases=[threading.Event() for _ in range(4)];started=[threading.Event() for _ in range(4)]
    def slow(i):
        started[i].set()
        assert releases[i].wait(3)
    tasks=[asyncio.create_task(work.run_deposit_verification(c.settings.payment_purchase_db_path,
        c.raw['purchaseId'],lambda i=i:slow(i))) for i,c in enumerate(cases[:4])]
    try:
        await spin_until(lambda:all(e.is_set() for e in started))
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        for _ in range(24):
            with pytest.raises(work.EscrowVerificationBusy):
                await work.run_deposit_verification(cases[4].settings.payment_purchase_db_path,
                    cases[4].raw['purchaseId'],lambda:pytest.fail('executor queue must remain empty'))
        assert not any(e.is_set() for e in releases)
    finally:
        for e in releases:e.set()
        await spin_until(lambda:all(_lease_finished(c) for c in cases[:4]))


def test_lease_limit_is_shared_with_a_separate_process(tmp_path,monkeypatch):
    import subprocess
    import sys
    cases=[callback_case(tmp_path,monkeypatch,i+1) for i in range(5)]
    for i,c in enumerate(cases[:4]):work.acquire(c.settings.payment_purchase_db_path,c.raw['purchaseId'],str(i),now=time.time())
    result=subprocess.run([sys.executable,'-c',
        'import sys,time;from solslot_api.escrow_verification_work import acquire;acquire(sys.argv[1],sys.argv[2],"child",now=time.time())',
        cases[4].settings.payment_purchase_db_path,cases[4].raw['purchaseId']],text=True,capture_output=True,timeout=10)
    assert result.returncode!=0 and 'capacity is busy' in result.stderr


@pytest.mark.asyncio
async def test_relayer_retry_with_more_confirmations_preserves_first_receipt(tmp_path,monkeypatch):
    c=callback_case(tmp_path,monkeypatch)
    await api.verify_external_escrow(c.payload,c.settings,'Bearer '+TOKEN)
    first=c.store.get(c.raw['purchaseId'])
    body=c.payload.model_dump(mode='json',by_alias=True);body['source']['confirmations']=24
    c.chain.tip['number']+=12
    result=await api.verify_external_escrow(api.VerifyExternalEscrowWebhookRequest.model_validate(body),c.settings,'Bearer '+TOKEN)
    assert result.verified and result.fulfillment['source']['confirmations']==12
    assert c.store.get(c.raw['purchaseId'])==first
    assert len([q for q in c.chain.calls if q[0]=='receipt'])==2
    # Even a racing first callback retains the original immutable receipt.
    newer=deepcopy(c.evidence);newer['source']['confirmations']=24
    assert c.store.bind_external_message(c.raw['purchaseId'],newer)==first
    newer['source']['blockHash']='0x'+'ff'*32
    from solslot_api.payment_purchase_store import PaymentPurchaseConflict
    with pytest.raises(PaymentPurchaseConflict):c.store.bind_external_message(c.raw['purchaseId'],newer)
