"""Recover partial private holds without inventing an arm or payment authority.

Real private BLS and CLVM timeout proofs, with isolated Stripe/node fixtures.
"""
import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import httpx
import pytest
from chia_rs import AugSchemeMPL, G2Element

from solslot_api.inventory_extension_store import canonical
from solslot_api.inventory_payment_hold_claims import InventoryPaymentHoldAbortClaim, payment_hold_activation
from solslot_api.validator_inventory_payment_hold import sign_inventory_payment_hold_abort
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from solslot_api.validator_service import ValidatorEvidenceError
from solslot_api.validator_quorum import collect_inventory_payment_hold_quorum
from tests.test_inventory_payment_holds import hold_case, arm, close, returned, refunded, sibling, reserve_again
from tests.test_single_external_delivery_context import hx, _b32


def activate_abort(c):
    from solslot_api.purchase_admission import ADMISSION_POLICY
    value = dict(c.claim.activation, adapterVersion=2, validatorLedgerVersion=13,
                 partialCancelPolicy='canceled-unfunded-original-timeout-v1',**ADMISSION_POLICY)
    value.pop('releaseIdentity'); review=value.pop('reviewEvidenceSha256')
    value['releaseIdentity']=hashlib.sha256(canonical(value).encode()).hexdigest()
    value['reviewEvidenceSha256']=review
    c.genesis['inventoryPaymentHolds']=value
    c.claim=c.claim.model_copy(update={'activation':value})


def abort_claim(c):
    claim=returned(c)
    return InventoryPaymentHoldAbortClaim.model_validate({**claim.model_dump(mode='json'),
        'schema_version':'solslot.inventory-payment-hold-abort.v1'})


async def abort(c, claim, index=0):
    return await sign_inventory_payment_hold_abort(c.signers[index], c.ledgers[index], claim, claim.canonical_hash())


@pytest.mark.asyncio
@pytest.mark.parametrize('armed',[False,True])
async def test_partial_cancel_tombstone_survives_restart_and_late_writes(tmp_path,monkeypatch,armed):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        activate_abort(c)
        original=await arm(c) if armed else None
        claim=abort_claim(c); c.intent['status']='canceled'
        signature=await abort(c,claim)
        assert AugSchemeMPL.verify(c.keys[0].get_g1(),claim.signature_message(),G2Element.from_bytes(bytes.fromhex(signature[2:])))
        assert not AugSchemeMPL.verify(c.keys[0].get_g1(),c.claim.signature_message(),G2Element.from_bytes(bytes.fromhex(signature[2:])))
        c.ledgers[0].close();c.ledgers[0]=ValidatorLedger(tmp_path/'extension-signer-0.db')
        row=c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id))
        assert row['state']=='RELEASED' and row['signature']==original
        assert reserve_again(c)=='new signature'
        c.records[claim.available_coin_id].update(spent=True,spent_block_index=c.height)
        assert await abort(c,claim)==signature
        for kind in ('extension','single','batch','issuance','transition'):
            with pytest.raises(ValidatorLedgerConflict,match='abort tombstone'):
                sibling(c.ledgers[0],c,kind,pi=c.claim.payment_intent_id)
        with pytest.raises(ValidatorEvidenceError):await arm(c)
        with pytest.raises(ValidatorLedgerConflict,match='terminal payment abort'):
            c.ledgers[0].record_inventory_payment_hold(claim=c.claim,signature='late',
                purchase_id=hx(c.purchase.purchase_id),deed_launcher_id=hx(c.purchase.deed_launcher_id))
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['v1','refund','processing','funded','other_hold','source','expiry','puzzle',
    'unspent_source','immature','spent_successor','wrong_successor','extension','single','batch','issuance','transition'])
async def test_unarmed_abort_requires_exact_original_unfunded_terminal_return(tmp_path,monkeypatch,problem):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        if problem!='v1':activate_abort(c)
        if problem=='other_hold':
            await arm(c)
            c.claim=c.claim.model_copy(update={'payment_intent_id':'pi_other'})
        if problem in ('extension','single','batch','issuance','transition'):
            sibling(c.ledgers[0],c,problem,pi=c.claim.payment_intent_id)
        claim=abort_claim(c);c.intent['status']='canceled'
        if problem=='refund':refunded(c)
        elif problem=='processing':c.intent['status']='processing'
        elif problem=='funded':c.intent['amount_received']=1
        elif problem=='source':claim=claim.model_copy(update={'reserved_coin_id':hx(_b32(99))})
        elif problem=='expiry':claim=claim.model_copy(update={'reservation_expires_at':claim.reservation_expires_at+1})
        elif problem=='puzzle':claim=claim.model_copy(update={'hold':c.claim.model_copy(update={'reserved_puzzle_hash':hx(_b32(99))})})
        elif problem=='unspent_source':c.records[claim.reserved_coin_id].update(spent=False,spent_block_index=0)
        elif problem=='immature':c.height-=3
        elif problem=='spent_successor':c.records[claim.available_coin_id].update(spent=True,spent_block_index=c.height)
        elif problem=='wrong_successor':claim=claim.model_copy(update={'available_coin_id':hx(_b32(99))})
        with pytest.raises(ValidatorEvidenceError):await abort(c,claim)
        assert c.ledgers[0]._conn.execute('SELECT count(*) FROM inventory_payment_hold_aborts').fetchone()[0]==0
    finally:close(c)


@pytest.mark.asyncio
async def test_one_arm_and_one_unarmed_signer_recover_real_private_http_quorum(tmp_path,monkeypatch):
    from solslot_api.validator_app import create_validator_app
    c=await hold_case(tmp_path,monkeypatch)
    try:
        activate_abort(c);await arm(c,0)
        claim=abort_claim(c);c.intent['status']='canceled'
        apps=[create_validator_app(settings=s,ledger=l) for s,l in zip(c.signers,c.ledgers,strict=True)]
        for app,ledger in zip(apps,c.ledgers,strict=True):app.state.validator_ledger=ledger
        transports=[httpx.ASGITransport(app=app) for app in apps]
        c.settings.zkpassport_validator_urls=['http://validator-0','http://validator-1','http://validator-2']
        c.settings.zkpassport_validator_pubkeys=c.genesis['validatorSet']['pubkeys']
        c.settings.zkpassport_validator_threshold=2
        async def route(request):
            if request.url.host=='validator-2':return httpx.Response(503)
            return await transports[int(request.url.host[-1])].handle_async_request(request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
            quorum=await collect_inventory_payment_hold_quorum(c.settings,claim,client=client)
        assert quorum.signer_indices==(0,1)
        assert AugSchemeMPL.aggregate_verify([c.keys[i].get_g1() for i in (0,1)],
            [claim.signature_message()]*2,quorum.aggregated_signature)
        assert [l.inventory_payment_hold(hx(c.purchase.purchase_id))['state'] for l in c.ledgers]==['RELEASED']*2
        assert c.ledgers[1].inventory_payment_hold(hx(c.purchase.purchase_id))['signature'] is None
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['extension','single','batch','issuance','transition'])
async def test_abort_and_prior_payment_serialize_across_connections(tmp_path,monkeypatch,kind):
    c=await hold_case(tmp_path,monkeypatch);other=ValidatorLedger(tmp_path/'extension-signer-0.db')
    try:
        activate_abort(c);claim=abort_claim(c);barrier=Barrier(2)
        def run(which):
            barrier.wait()
            try:
                if which=='abort':c.ledgers[0].record_inventory_payment_hold_abort(claim=claim,signature='fixture',
                    purchase_id=hx(c.purchase.purchase_id),deed_launcher_id=hx(c.purchase.deed_launcher_id))
                else:sibling(other,c,kind,pi=c.claim.payment_intent_id)
                return which
            except ValidatorLedgerConflict:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,('abort','paid')))
        assert results.count('refused')==1
    finally:other.close();close(c)


@pytest.mark.asyncio
async def test_capability_v1_remains_readable_but_v2_is_exact(tmp_path,monkeypatch):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        assert payment_hold_activation(c.genesis,'staging-alpha')['adapterVersion']==1
        activate_abort(c)
        assert payment_hold_activation(c.genesis,'staging-alpha')['adapterVersion']==2
        for key,value in [('adapterVersion',2.0),('validatorLedgerVersion',12),('partialCancelPolicy','any'),('releaseIdentity','a'*64)]:
            old=c.genesis['inventoryPaymentHolds'][key];c.genesis['inventoryPaymentHolds'][key]=value
            with pytest.raises(ValueError):payment_hold_activation(c.genesis,'staging-alpha')
            c.genesis['inventoryPaymentHolds'][key]=old
    finally:close(c)
