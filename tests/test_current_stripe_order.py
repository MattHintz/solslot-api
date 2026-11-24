"""Current order discovery and independent native admission before Stripe payment."""
from dataclasses import replace
from secrets import token_urlsafe
from types import SimpleNamespace
from unittest.mock import AsyncMock

from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import Coin,G1Element,G2Element
from chia_rs.sized_bytes import bytes32
from fastapi import FastAPI
from httpx import ASGITransport,AsyncClient
import pytest

from solslot_puzzles.generation_mint import GenerationMint,MintRow,TestMintEdition
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1,purchase_batch_to_json
from solslot_puzzles.vault_driver import one_leaf_merkle_root,puzzle_hash_for_p2_vault
from solslot_api import credential_auth, generation_customer_portfolio_routes as portfolio
from solslot_api import generation_customer_stripe_order as order, generation_customer_stripe_routes as routes
from solslot_api.config import get_settings
from solslot_api.generation_customer_inventory import CurrentPrimaryItem,CurrentPrimaryInventory,h
from solslot_api.generation_customer_vault import CurrentCustomerVault
from solslot_api.payment_purchase_store import PaymentPurchaseStore


def b(seed):
    return bytes32(bytes([seed])*32)


def synthetic_mint():
    public = G1Element.generator()
    keys = tuple(map(bytes,(public,public+public,public+public+public)))
    genesis = GenerationMint(b(1),b(2),b(3),b(4),b(5),b(6),b(7),b(8),keys,b(9))
    edition = TestMintEdition(b(1),b(10),b(11),b(12),b(13),b(14),100,1,b'TEST',
        tuple(MintRow(b(i),125000,300000,10000) for i in range(15,23)))
    items = sorted(genesis.inventories(edition),key=lambda i:i.terms.deed_launcher_id)
    both = next(group[:2] for group in ([i for i in items if i.terms.deed_launcher_id[0]<128],
                                        [i for i in items if i.terms.deed_launcher_id[0]>=128]) if len(group)>=2)
    return genesis.generation,b(28),tuple(both)


def arrange(tmp_path,monkeypatch,source=None):
    generation, launcher, items = source or synthetic_mint()
    now=1_700_000_050
    nonce, batch_nonce=b(51),b(52)
    auth_expiry, quote_expiry=now+250,now+200
    owner_pk=bytes(G1Element.generator())
    root=b(29)
    inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=owner_pk,auth_type=1,
        members_merkle_root=one_leaf_merkle_root(owner_pk),pool_launcher_id=b(30),
        identity_attest_root=root,zkpassport_bridge_policy_hash=b(31))
    vault=CurrentCustomerVault(generation,launcher,Coin(b(32),puzzle_for_singleton(launcher,inner).get_tree_hash(),1),
        inner,root,120,b(33),b(34),110,None)
    batch=build_purchase_batch_v1(batch_nonce=batch_nonce,artifacts=tuple(
        order.stripe_artifact(i.terms,launcher,root,nonce,auth_expiry,quote_expiry) for i in items))
    first=items[0].terms
    offer = dict(schemaVersion=4,network='testnet11',kind='solslot_protocol_offer',protocolVersion='solslot-v2',
        genesisArtifactHash=h(b(43)),purchaseBatchV1=purchase_batch_to_json(batch),
        vaultCredentialReceipt=dict(vaultLauncherId=h(launcher),chiaVaultCoinId=h(vault.coin.name()),identityAttestRoot=h(root)),
        protocol=dict(purchaseIntentId='order_local',rail='stripe',quantity=2,vaultLauncherId=h(launcher),
            zkPassportRequired=True,collectionId=h(first.collection_id),purchaseId=h(batch.purchase_id),
            purchaseArtifactHash=h(batch.batch_hash),deedLauncherIds=[h(a.deed_launcher_id) for a in batch.artifacts]))
    scope=order.StripeOrderScope(b(35),generation,b(36),first.collection_id,first.metadata_anchor_id,
        first.metadata_root,launcher,batch.purchase_id,tuple(a.deed_launcher_id for a in batch.artifacts),
        tuple(i.coin.name() for i in items),now-1,auth_expiry,
        'order_local',order.content_hash(offer))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=h(generation),generation_chain_anchor_hash=h(scope.anchor_hash),
        stripe_mode='test',stripe_account_id='acct_demo',stripe_settlement_enabled=True,stripe_delivery_worker_enabled=True,
        protocol_fee_funding_enabled=True,vault_session_jwt_secret=token_urlsafe(32),vault_session_ttl_seconds=60)
    store=PaymentPurchaseStore(str(tmp_path/'purchase.sqlite'))
    store.save(purchase_intent_id='order_local',rail='stripe',offer_artifact_hash=order.content_hash(offer),
        offer_artifact=offer,purchase_artifact=purchase_batch_to_json(batch),created_at=now)
    clock=[now]
    service=order.CurrentStripeOrder(settings=settings,scope=scope,store=store,clock=lambda:clock[0])
    snapshot=dict(network='testnet11',vault=vault.public(),owner=h(owner_pk),authType='chia_bls',ownerPublicKey=h(owner_pk),
        generationId=h(generation),registrationId='one',p2VaultPuzzleHash=h(puzzle_hash_for_p2_vault(launcher)))
    authority=object()
    inventory=CurrentPrimaryInventory(generation,scope.collection,scope.edition,scope.metadata_root,b(39),b(40),
        tuple(CurrentPrimaryItem(i,i,None,100) for i in items),authority)
    monkeypatch.setattr(order,'resolve_current_primary_inventory',AsyncMock(return_value=inventory))
    monkeypatch.setattr(order,'read_generation_preparation',lambda _: object())
    monkeypatch.setattr(order,'customer_bindings_from_evidence',lambda *_:object())
    monkeypatch.setattr(order,'resolve_native_identity_vault',AsyncMock(return_value=vault))
    monkeypatch.setattr(order,'current_evidence_unchanged',AsyncMock(return_value=True))
    def record(coin,hgt,spent=0):
        return dict(coin=coin.to_json_dict(),confirmed_block_index=hgt,spent_block_index=spent,spent=bool(spent))
    records={h(vault.coin.name()):record(vault.coin,120),**{h(i.coin.name()):record(i.coin,100) for i in items}}
    spends={}
    primary=SimpleNamespace(get_mempool_items_by_coin_name=AsyncMock(return_value=[]))
    provider=SimpleNamespace(primary=primary,get_coin_record_by_name_primary=AsyncMock(side_effect=records.get),
        get_puzzle_and_solution_primary=AsyncMock(side_effect=lambda name,height:spends[name]))
    customers=SimpleNamespace(index=SimpleNamespace(anchor='local'),provider=provider,current_vault_snapshot=lambda _:snapshot)
    monkeypatch.setattr(portfolio,'_runtime',lambda *_:customers)
    customer=SimpleNamespace(launcher_id=launcher,owner_evm_address=None,auth_type=1,owner_pubkey=owner_pk)
    monkeypatch.setattr(credential_auth,'require_vault_record',lambda _:customer)
    session=credential_auth.VerifiedOwner(owner_key=h(owner_pk),auth_type='chia_bls',vault_record=customer)
    token,_=credential_auth.issue_vault_session(settings,session)
    recovery,_=credential_auth.issue_vault_session(settings,session,scope='relay_recovery')
    app=FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_settings]=lambda:settings
    app.state.generation_customer_stripe_order=service
    app.state.generation_customers=customers
    def confirm(transitions):
        manifest=[]
        for item,transition in zip(items,transitions,strict=True):
            coin,successor=item.coin,transition.reserved_coin
            records[h(coin.name())]=record(coin,100,121)
            records[h(successor.name())]=record(successor,121)
            spends[h(coin.name())]=transition.spend.to_json_dict()
            manifest.append(dict(deed_launcher_id=h(item.terms.deed_launcher_id),available_coin_id=h(coin.name()),
                reserved_coin_id=h(successor.name()),reserved_puzzle_hash=h(successor.puzzle_hash),expires_at=quote_expiry,
                signer_indices=(0,1),signature='synthetic ledger marker'))
        unsigned=WalletSpendBundle([t.spend for t in transitions],G2Element())
        store.record_inventory_batch_prepared(h(batch.purchase_id),items=tuple(manifest),bundle=unsigned.to_json_dict())
        store.record_inventory_submitted(h(batch.purchase_id),bundle_id=h(unsigned.name()),mempool_observed_at='synthetic')
        store.record_inventory_confirmed(h(batch.purchase_id),confirmation_height=121)
    def handoff(native, *, now):
        auth=dict(protocolVersion='solslot-v2',network='testnet11',genesisArtifactHash=h(b(43)),
            purchaseId=native.purchase_id,purchaseArtifactHash=native.batch_hash,offerArtifactHash=native.offer_artifact_hash,
            purchaseIntentId=native.purchase_intent_id,vaultLauncherId=native.vault_launcher_id,vaultP2PuzzleHash=native.destination_puzzle_hash,
            currentVaultCoinId=native.vault_coin_id,identityAttestRoot=native.credential_root,purchaseArtifact=purchase_batch_to_json(native.batch))
        intent=dict(id=native.purchase_intent_id,rail='stripe',vaultLauncherId=native.vault_launcher_id,quantity=2,
            zkPassportRequired=True,artifactHash=native.offer_artifact_hash)
        return dict(releaseId=native.release_id,readinessId=h(b(44)),checkedAt=now,validUntil=now+25,
            providerAccount='acct_demo',publishableKey='pk_test_local',mode='test',purchaseIntent=intent,authorization=auth)
    adapter=SimpleNamespace(review=AsyncMock(side_effect=handoff))
    app.state.generation_customer_stripe_handoff=adapter
    prepared_args=dict(authorization_nonce=nonce,batch_nonce=batch_nonce,authorization_expires_at=auth_expiry,
        quote_expires_at=quote_expiry,signer_indices=(0,1))
    url=f'/customer/purchases/{h(launcher)}/stripe/{h(scope.collection)}'
    return SimpleNamespace(**locals())


@pytest.mark.asyncio
async def test_private_order_requires_both_proved_reservations_and_live_credential(tmp_path,monkeypatch):
    r=arrange(tmp_path,monkeypatch)
    async with AsyncClient(transport=ASGITransport(app=r.app),base_url='https://test.invalid') as client:
        assert (await client.get(r.url)).status_code==401
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,r.recovery)
        assert (await client.get(r.url)).status_code==403
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,r.token)
        assert (await client.get(r.url)).json()['state']=='AWAITING_RESERVATION'
        assert r.adapter.review.await_count==0
        quote,transitions=await r.service.prepare_originals(r.customers,r.snapshot,**r.prepared_args)
        assert quote==r.batch
        r.confirm(transitions)
        result=await client.get(r.url)
        assert result.status_code==200 and result.headers['Cache-Control']=='private, no-store'
        assert result.json()['state']=='READY_FOR_STRIPE' and result.json()['totalAmountMinor']==606000
        native=await routes.current_stripe_native_again(r.app,r.settings,h(r.batch.purchase_id),now=r.now)
        assert native.reserved_coin_ids==tuple(h(t.reserved_coin.name()) for t in transitions)
        assert native.owner_key==r.snapshot['ownerPublicKey'] and native.owner_auth_type==1
        for_original=h(r.items[0].coin.name())
        saved=r.spends[for_original]
        r.spends[for_original]=r.spends[h(r.items[1].coin.name())]
        assert (await client.get(r.url)).status_code==503
        r.spends[for_original]=saved
        r.records[native.reserved_coin_ids[1]]['confirmed_block_index']+=1
        assert (await client.get(r.url)).status_code==503
        r.records[native.reserved_coin_ids[1]]['confirmed_block_index']-=1
        r.primary.get_mempool_items_by_coin_name.return_value=[{'pending':True}]
        assert (await client.get(r.url)).status_code==503
        r.primary.get_mempool_items_by_coin_name.return_value=[]
        r.settings.protocol_fee_funding_enabled=False
        inactive=(await client.get(r.url)).json()
        assert inactive['state']=='PAYMENT_UNAVAILABLE' and 'handoff' not in inactive
        r.settings.protocol_fee_funding_enabled=True
        r.snapshot['vault']['identityAttestRoot']=h(b(61))
        assert (await client.get(r.url)).status_code==503
        r.snapshot['vault']['identityAttestRoot']=native.credential_root
        r.snapshot['owner']='changed registered owner'
        assert (await client.get(r.url)).status_code==403
        r.snapshot['owner']=native.owner_account
        r.clock[0]=r.quote_expiry
        assert (await client.get(r.url)).json()['state']=='PAYMENT_UNAVAILABLE'
        with pytest.raises(ValueError):
            await routes.current_stripe_native_again(r.app,r.settings,native.purchase_id,now=r.clock[0])


@pytest.mark.asyncio
async def test_scope_and_provider_substitutions_never_authorize_payment(tmp_path,monkeypatch):
    r=arrange(tmp_path,monkeypatch)
    with pytest.raises(ValueError,match='one-order release'):
        await r.service.prepare_originals(r.customers,r.snapshot,**{**r.prepared_args,'batch_nonce':b(60)})
    _,transitions=await r.service.prepare_originals(r.customers,r.snapshot,**r.prepared_args)
    r.confirm(transitions)
    native=(await r.service.review(r.customers,r.snapshot)).native
    for key,value in [('currentVaultCoinId',h(b(60))),('identityAttestRoot',h(b(60))),
                      ('purchaseArtifactHash',h(b(60))),('purchaseArtifact',{})]:
        claim=r.handoff(native,now=r.now)
        claim['authorization'][key]=value
        assert not routes._available_handoff(claim,native,r.settings,r.now)
    for key,value in [('validUntil',r.now+31),('providerAccount','acct_other'),('releaseId',h(b(60)))]:
        assert not routes._available_handoff({**r.handoff(native,now=r.now),key:value},native,r.settings,r.now)
    r.service.scope=replace(r.scope,originals=tuple(reversed(r.scope.originals)))
    with pytest.raises(ValueError,match='reservation original'):
        await r.service.review(r.customers,r.snapshot)


@pytest.mark.asyncio
@pytest.mark.parametrize('changed', ['spent','wrong_deed','wrong_vault','wrong_network','expired_during_read',
                                    'changed_owner_key','timeout_in_progress','wrong_price','expired_authorization'])
async def test_native_admission_rejects_changed_last_read(tmp_path,monkeypatch,changed):
    r=arrange(tmp_path,monkeypatch)
    _,pairs=await r.service.prepare_originals(r.customers,r.snapshot,**r.prepared_args)
    r.confirm(pairs)
    if changed=='spent':
        row=r.records[h(pairs[1].reserved_coin.name())]
        row.update(spent=True,spent_block_index=122)
    elif changed=='wrong_deed':
        r.service.scope=replace(r.scope,launchers=(r.scope.launchers[0],bytes32(b'\xff'*32)))
    elif changed=='wrong_vault':
        r.snapshot['vault']['vaultLauncherId']=h(b(66))
    elif changed=='wrong_network':
        r.settings.network='mainnet'
    elif changed=='changed_owner_key':
        r.snapshot['ownerPublicKey']=h(bytes(G1Element.generator()+G1Element.generator()))
    elif changed=='timeout_in_progress':
        monkeypatch.setattr(r.store,'inventory_timeout_operations',lambda _: [{'state':'CLAIMED'}])
    elif changed=='wrong_price':
        discounted=tuple(replace(a,base_amount_minor=10000,technology_fee_minor=100,subtotal_minor=10100,
                                 rail_amount=10100) for a in r.batch.artifacts)
        forged=build_purchase_batch_v1(batch_nonce=r.batch_nonce,artifacts=discounted)
        offer={**r.offer,'purchaseBatchV1':purchase_batch_to_json(forged),'protocol':{**r.offer['protocol'],
            'purchaseIntentId':'other_order','purchaseId':h(forged.purchase_id),'purchaseArtifactHash':h(forged.batch_hash)}}
        r.store.save(purchase_intent_id='other_order',rail='stripe',offer_artifact_hash=order.content_hash(offer),
            offer_artifact=offer,purchase_artifact=purchase_batch_to_json(forged),created_at=r.now)
        r.service.scope=replace(r.scope,purchase_id=forged.purchase_id,purchase_intent_id='other_order',
                                offer_artifact_hash=order.content_hash(offer))
        with pytest.raises(ValueError,match='minted USD terms'):
            await r.service.review(r.customers,r.snapshot)
        return
    elif changed=='expired_authorization':
        with pytest.raises(ValueError,match='outside its release'):
            await r.service.prepare_originals(r.customers,r.snapshot,**{
                **r.prepared_args,'authorization_expires_at':r.now-1})
        return
    elif changed=='expired_during_read':
        async def tick(*args,**kwargs):
            r.clock[0]=r.quote_expiry
            return True
        monkeypatch.setattr(order,'current_evidence_unchanged',tick)
    with pytest.raises(ValueError):
        await routes.current_stripe_native_again(r.app,r.settings,h(r.batch.purchase_id),now=r.now)


@pytest.mark.asyncio
async def test_provision_preserves_the_exact_original_offer_and_is_idempotent(tmp_path,monkeypatch):
    r=arrange(tmp_path,monkeypatch)
    empty=PaymentPurchaseStore(str(tmp_path/'new-journal.sqlite'))
    r.service.store=empty
    with pytest.raises(ValueError,match='Unrecognized original'):
        await r.service.retain_original_offer(r.customers,r.snapshot,{**r.offer,'metadata':{}},signer_indices=(0,1))
    one=await r.service.retain_original_offer(r.customers,r.snapshot,r.offer,signer_indices=(0,1))
    two=await r.service.retain_original_offer(r.customers,r.snapshot,r.offer,signer_indices=(0,1))
    assert one==two and one[0]==r.batch
    retained=empty.inventory_status_snapshot(h(r.batch.purchase_id))
    assert retained[0].offer_artifact_hash==r.scope.offer_artifact_hash
    assert retained[0].inventory_state=='UNRESERVED' and len(retained[1])==2
    assert r.adapter.review.await_count==0
