"""A governed fee change cannot silently alter or mislabel an original offer."""
import time
from types import SimpleNamespace
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from solslot_api.config import get_settings
from solslot_api.generation_sols_batch_routes import router
from solslot_api.generation_sols_policy import REVIEWED_FEES,current_fee_policy,require_order_policy
from tests.test_generation_sols_orders import GEN,DEST,book,offer


@pytest.mark.parametrize('fault',['missing','stale','future','generation','changed','missing-policy'])
def test_new_orders_require_fresh_same_generation_exact_fee_review(tmp_path,fault):
    b=book(tmp_path);now=int(time.time())
    catalog={'generationId':GEN,'lastCheckedAt':now,'ready':True,'feePolicy':dict(REVIEWED_FEES)}
    if fault=='stale':catalog['lastCheckedAt']=now-46
    if fault=='future':catalog['lastCheckedAt']=now+1
    if fault=='generation':catalog['generationId']='0x'+'77'*32
    if fault=='changed':catalog['feePolicy']['feeBps']=200
    if fault=='missing-policy':catalog.pop('feePolicy')
    if fault=='generation':
        with pytest.raises(ValueError,match='BATCH_CATALOG_GENERATION_CHANGED'):b.save_catalog(catalog)
    elif fault!='missing':b.save_catalog(catalog)
    with pytest.raises(ValueError,match='SOLS_FEE_POLICY'):require_order_policy(b,now=now)
    app=FastAPI();app.include_router(router);app.state.generation_sols_orders=b
    settings=SimpleNamespace(network='testnet11',generation_sols_batch_enabled=True,deployment_generation_id=GEN)
    app.dependency_overrides[get_settings]=lambda:settings
    with TestClient(app) as client:assert client.get('/sols/batches/status').json()['enabled'] is False


def test_fresh_fee_capability_and_retained_receipt_survive_later_fee_change(tmp_path):
    b=book(tmp_path);now=int(time.time());key='0x'+'77'*32;source=offer(expires=now+1000)
    saved=b.place(source,payment_asset=None,destination=DEST,now=now,receipt_key=key)
    b.save_catalog({'generationId':GEN,'lastCheckedAt':now,'ready':True,
        'feePolicy':current_fee_policy((86400,600,100,70,30,86400))})
    assert require_order_policy(b,now=now)==REVIEWED_FEES
    b.save_catalog({'generationId':GEN,'lastCheckedAt':now,'ready':False,
        'feePolicy':current_fee_policy((86400,600,200,140,60,86400))})
    assert b.existing_receipt(source,key)==saved and b.status(saved['orderId'])==saved
    assert bytes(b.original(saved['orderId']))==bytes(source)
