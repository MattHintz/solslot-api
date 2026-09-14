"""Owner/quota gates precede canonical quote construction and private signing."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from solslot_api import protocol_artifacts as artifacts, native_purchases, vault_eligibility
from solslot_api.validator_quorum import ValidatorQuorumError
from tests.test_inventory_checkout_coordinator import coordinator
from tests.test_inventory_payment_holds import close
from tests.test_single_external_delivery_context import hx


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['legitimate','forged_owner','missing_owner','batch','long_quote','unauthenticated'])
async def test_quote_admission_precedes_construction_and_ignores_wallet_aliases(tmp_path,monkeypatch,problem):
    c=await coordinator(tmp_path,monkeypatch)
    class ReachedConstruction(Exception):pass
    try:
        with c.purchases._connect() as db:db.execute('DELETE FROM payment_purchase_admission')
        receipt=SimpleNamespace(identityAttestRoot='0x'+'b'*64,model_dump=lambda:dict(c.admission_receipt))
        monkeypatch.setattr(vault_eligibility,'require_current_approved_vault',lambda *a,**kw:
                            SimpleNamespace(enrollment=SimpleNamespace(receipt=receipt)))
        monkeypatch.setattr(artifacts,'load_signed_public_artifact',lambda _:c.genesis)
        monkeypatch.setattr(artifacts,'get_payment_purchase_store',lambda _:c.purchases)
        calls=[]
        def build(*a,**kw):calls.append('construction');raise ReachedConstruction()
        monkeypatch.setattr(artifacts,'_build_canonical_payment_artifact',build)
        body=dict(protocol_version='solslot-v2',network='testnet11',genesis_artifact_hash=c.genesis['artifactHash'],
            instance_id='staging-alpha',purchase_intent_id='new-quote',rail='stripe',property_id='fixture-property',
            collection_id='fixture-collection',vault_launcher_id=hx(c.purchase.vault_launcher_id),
            current_vault_coin_id='0x'+'a'*64,identity_attest_root='0x'+'b'*64,expires_at=c.clock[0]+900,
            payment_terms=dict(currency='USD',quantity=1),checkout_owner_auth_type=1,checkout_owner_key=hx(c.keys[0].get_g1()))
        if problem=='forged_owner':body['checkout_owner_key']=hx(c.keys[1].get_g1())
        elif problem=='missing_owner':body.pop('checkout_owner_key')
        elif problem=='batch':body['payment_terms']['quantity']=100
        elif problem=='long_quote':body['expires_at']+=1
        parsed=artifacts.BuildProtocolOfferArtifactRequest(**body)
        token=None if problem=='unauthenticated' else 'Bearer synthetic-extension-service-token'
        if problem=='legitimate':
            with pytest.raises(ReachedConstruction):await artifacts.build_protocol_offer_artifact(parsed,c.settings,token)
            with c.purchases._connect() as db:
                row=db.execute('SELECT * FROM payment_purchase_admission').fetchone()
                assert row['state']=='QUOTING' and row['owner_key']==body['checkout_owner_key']
            with pytest.raises(HTTPException) as duplicate:
                await artifacts.build_protocol_offer_artifact(parsed.model_copy(update={'purchase_intent_id':'spam-next'}),c.settings,token)
            assert duplicate.value.status_code==429 and len(calls)==1
        else:
            with pytest.raises(HTTPException):await artifacts.build_protocol_offer_artifact(parsed,c.settings,token)
            assert not calls
            with c.purchases._connect() as db:assert db.execute('SELECT count(*) FROM payment_purchase_admission').fetchone()[0]==0
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('admitted',[False,True])
async def test_reservation_pins_admission_before_first_private_request(tmp_path,monkeypatch,admitted):
    c=await coordinator(tmp_path,monkeypatch)
    try:
        with c.purchases._connect() as db:
            db.execute("UPDATE payment_purchases SET inventory_state='UNRESERVED'")
            if admitted:db.execute("UPDATE payment_purchase_admission SET state='QUOTING',purchase_id=NULL")
            else:db.execute('DELETE FROM payment_purchase_admission')
        first=SimpleNamespace(genesis_artifact=c.genesis,purchase=c.purchase,reservation=c.reservation,
            deed_coin=c.initial.coin_spends[0].coin,terms=c.terms,
            credential_owner_auth_type=1,credential_owner_key=bytes(c.keys[0].get_g1()),
            credential_receipt={**c.admission_receipt,'chiaVaultCoinId':'0x'+'a'*64,'identityAttestRoot':'0x'+'b'*64,
                'policyVersion':2,'bridgePolicyHash':'0x'+'c'*64})
        async def context(*a,**kw):return SimpleNamespace(contexts=[first])
        monkeypatch.setattr(native_purchases,'_load_context_group',context)
        called=[]
        async def collect(*a,**kw):
            with c.purchases._connect() as db:
                row=db.execute('SELECT * FROM payment_purchase_admission').fetchone()
                assert row['state']=='SIGNING' and row['purchase_id']==hx(c.purchase.purchase_id)
            called.append(True);raise ValidatorQuorumError('isolated unavailable quorum')
        monkeypatch.setattr(native_purchases,'collect_inventory_reservation_quorum',collect)
        request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node)))
        with pytest.raises(HTTPException) as rejected:
            await native_purchases.reserve_smartdeed_inventory(
                native_purchases.InventoryReservationRequest(purchaseId=hx(c.purchase.purchase_id)),request,c.settings,
                'Bearer synthetic-extension-service-token')
        assert called==([True] if admitted else [])
        assert rejected.value.status_code==(409 if admitted else 429)
    finally:close(c)
