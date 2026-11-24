"""Vault owner → two original reservations → exactly one Stripe-hosted card order."""
import asyncio
import hashlib
import json
import time
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL,PrivateKey
from fastapi import FastAPI
from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1,purchase_batch_to_json
from tests.test_current_stripe_order import arrange,b
from solslot_api import credential_auth
from solslot_api import vault_card_checkout as checkout,vault_card_native as native,vault_card_provider as provider
from solslot_api import vault_card_reservations as reservations
from solslot_api.validator_ledger import ValidatorLedger
from solslot_api.config import get_settings
from solslot_api.vault_card_store import VaultCardStore,h
from solslot_api.payment_purchase_store import PaymentPurchaseStore


def setup(tmp_path,monkeypatch,source=None):
    r=arrange(tmp_path,monkeypatch,source=source)
    now=int(time.time())
    scope=dict(schemaVersion='solslot.vault-card-release.v2',network='testnet11',mode='test',accountId='acct_card',
        generationId=h(r.generation),generationAnchorHash=h(r.scope.anchor_hash),technologyFeePuzzleHash=h(r.items[0].terms.protocol_treasury_puzzle_hash),
        primaryProceedsPuzzleHash=h(r.items[0].terms.protocol_puzhash),
        collectionId=h(r.scope.collection),editionId=h(r.scope.edition),metadataRoot=h(r.scope.metadata_root),
        vaultLauncherId=h(r.launcher),deedLauncherIds=list(map(h,r.scope.launchers)),originalCoinIds=list(map(h,r.scope.originals)),
        authorizationNonce=h(b(52)),batchNonce=h(b(53)),signerIndices=[0,1],validFrom=now-1,expiresAt=now+7200,
        credentialPolicyVersion=2,maximumFeePerStageMojos=400000000,maximumTotalFeeMojos=2000000000)
    release_file=tmp_path/'release.json'
    release_file.write_text(json.dumps(scope))
    release_file.chmod(0o600)
    webhook=tmp_path/'WH'
    webhook.write_text('whsec_'+'locallysimulated'*3)
    webhook.chmod(0o600)
    s=r.settings
    s.vault_card_release_file=str(release_file)
    s.vault_card_release_sha256=h(hashlib.sha256(release_file.read_bytes()).digest())
    s.stripe_account_id='acct_card'
    s.zkpassport_policy_version=2
    s.vault_card_webhook_key_file=str(webhook)
    s.vault_card_return_origin='https://buyer.invalid'
    s.generation_customer_public_origin=s.vault_card_return_origin
    s.allowed_origins=lambda:[s.vault_card_return_origin]
    s.stripe_settlement_enabled=False
    s.stripe_delivery_worker_enabled=False
    s.protocol_fee_funding_enabled=False
    s.vault_card_delivery_enabled=True
    s.vault_card_checkout_enabled=True
    s.stripe_api_url='https://api.stripe.com'
    s.payment_purchase_db_path=str(tmp_path/'native.db')
    s.stripe_delivery_db_path=str(tmp_path/'delivery.db')
    s.launch_control_enabled=False
    s.alpha_writes_enabled=s.minting_enabled=False
    s.generation_customer_enabled=True
    s.zkpassport_validator_urls=['https://one.invalid','https://two.invalid','https://three.invalid']
    s.zkpassport_validator_threshold=2
    s.zkpassport_validator_pubkeys=[h(k) for k in r.items[0].terms.validator_pubkeys]
    r.provider.get_network_info_primary=AsyncValue(dict(network_name='testnet11'))
    r.inventory=replace(r.inventory,evidence=SimpleNamespace(registry=SimpleNamespace(state=SimpleNamespace(pause_mask=0))))
    monkeypatch.setattr(native,'resolve_current_primary_inventory',AsyncValue(r.inventory))
    monkeypatch.setattr(native,'resolve_native_identity_vault',AsyncValue(r.vault))
    monkeypatch.setattr(native,'read_generation_preparation',lambda _:object())
    monkeypatch.setattr(native,'customer_bindings_from_evidence',lambda *_:SimpleNamespace(bridge_policy=b(31)))
    monkeypatch.setattr(native,'current_evidence_unchanged',AsyncValue(True))
    monkeypatch.setattr(native,'load_generation_read_anchor',lambda _:r.customers.index.anchor)
    n=native.VaultCardNative.configured(s)
    purchases=PaymentPurchaseStore(s.payment_purchase_db_path)
    store=VaultCardStore(s.payment_purchase_db_path)
    seen=[]
    external={}
    def remote(req):
        seen.append(req)
        if req.url.path=='/v1/account':
            return httpx.Response(200,json={'id':s.stripe_account_id,'object':'account','charges_enabled':True})
        if req.url.path=='/v1/checkout/sessions':
            assert req.method=='POST'
            body={k:v[0] for k,v in parse_qs(req.content.decode()).items()}
            sid='cs_'+s.stripe_mode+'_synthetic'
            obj=dict(object='checkout.session',id=sid,mode='payment',livemode=s.stripe_mode=='live',
                currency='usd',amount_total=sum(int(v) for k,v in body.items() if k.endswith('[unit_amount]')),
                client_reference_id=body['client_reference_id'],payment_method_types=['card'],status='open',
                payment_status='unpaid',payment_intent=None,url='https://checkout.stripe.com/c/pay/'+sid,
                expires_at=int(body['expires_at']),metadata={k[9:-1]:v for k,v in body.items() if k.startswith('metadata[')})
            if sid in external:
                assert obj==external[sid]
            external[sid]=obj
            return httpx.Response(200,json=obj)
        if req.url.path.startswith('/v1/checkout/sessions/'):
            return httpx.Response(200,json=external[req.url.path.split('/')[-1]])
        raise AssertionError(req.url)
    prov=provider.VaultCardProvider(s,transport=httpx.MockTransport(remote))
    monkeypatch.setattr(provider,'_stripe_restricted_key',lambda _:'synthetic-local-only')
    service=checkout.VaultCardCheckout(s,n,store,purchases,prov)
    app=FastAPI()
    app.include_router(checkout.router)
    app.state.generation_customers=r.customers
    app.state.vault_card_checkout=service
    app.state.stripe_delivery_worker=SimpleNamespace(settings=s,current_card_order=lambda:store.by_release(n.release_id),
        submitter=SimpleNamespace(funding_store=object(),policy=SimpleNamespace(enabled=True,maximum_mojos=400000000)))
    app.dependency_overrides[get_settings]=lambda:s
    client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://buyer.invalid')
    url='/customer/purchases/'+scope['vaultLauncherId']+'/card/'+scope['collectionId']
    ledgers=[ValidatorLedger(tmp_path/('signer'+str(i))) for i in range(2)]
    def signer_settings(index):
        return SimpleNamespace(**{**vars(s),'vault_card_reservations_enabled':True,'signer_index':index,
                                   'roster_pubkeys':s.zkpassport_validator_pubkeys})
    monkeypatch.setattr(reservations,'load_generation_read_anchor',lambda _:r.customers.index.anchor)
    monkeypatch.setattr(reservations,'load_validator_private_key',lambda ss:PrivateKey.from_bytes((ss.signer_index+1).to_bytes(32,'big')))
    async def signer_remote(req):
        idx=s.zkpassport_validator_urls.index('https://'+req.url.host)
        body=reservations.ReservationRequest.model_validate_json(req.content)
        res=await reservations.sign_reservation(signer_settings(idx),ledgers[idx],r.provider,body)
        return httpx.Response(200,json=res)
    monkeypatch.setattr(reservations,'_private_validator_client',lambda _:httpx.AsyncClient(transport=httpx.MockTransport(signer_remote)))
    async def submit(app,order,db,saved):
        bundle=WalletSpendBundle.from_json_dict(saved.inventory_bundle)
        return db.record_inventory_submitted(saved.purchase_id,bundle_id=h(bundle.name()),mempool_observed_at='simulated-primary')
    monkeypatch.setattr(reservations,'submit_reservation',submit)
    def confirm_chain(ev):
        for t in ev.transitions:
            coin=t.spend.coin
            r.records[h(coin.name())]=r.record(coin,100,121)
            r.records[h(t.reserved_coin.name())]=r.record(t.reserved_coin,121)
            r.spends[h(coin.name())]=t.spend.to_json_dict()
    covered=set()
    async def allocation(app,settings,order,*,now):
        assert purchases.get(order.purchase_id).inventory_state=='CONFIRMED'
        covered.add(order.purchase_id)
        return True
    async def coverage(app,settings,order,*,now):
        return order.purchase_id in covered
    monkeypatch.setattr(checkout,'allocate_current_card_coverage',allocation)
    monkeypatch.setattr(checkout,'current_card_coverage',coverage)
    return SimpleNamespace(**locals())


class AsyncValue:
    def __init__(self,value):
        self.value=value
    async def __call__(self,*args,**kwargs):
        return self.value


@pytest.mark.asyncio
async def test_normal_vault_checkout_preparation_and_recovery(tmp_path,monkeypatch):
    x=setup(tmp_path,monkeypatch)
    async with x.client as client:
        assert (await client.get(x.url)).status_code==401
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,x.r.recovery)
        assert (await client.get(x.url)).status_code==403
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,x.r.token)
        initial=(await client.get(x.url)).json()
        assert initial['state']=='AWAITING_RESERVATION' and initial['amountMinor']==606000
        assert len(initial['deedLauncherIds'])==2 and not initial['reservationRequested'] and not x.seen
        args=dict(purchaseId=initial['purchaseId'],batchHash=initial['batchHash'],intent='prepare')
        path=x.url+'/checkout'
        assert (await client.post(path,json=args)).status_code==403
        client.headers['Origin']=x.s.vault_card_return_origin
        assert (await client.post(path,json={**args,'purchaseId':h(b(98))})).status_code==409
        assert (await client.post(path,json={**args,'amount':1})).status_code==422
        early=await client.post(path,json={**args,'intent':'checkout'})
        assert early.json()['checkoutUrl'] is None and not x.store.by_release(x.n.release_id)
        made=await client.post(path,json=args)
        assert made.status_code==200,made.text
        assert made.json()['reservationRequested'] and made.json()['checkoutUrl'] is None and not x.seen
        evidence=await x.n.reconstruct(x.r.customers,x.r.snapshot)
        purchase=x.purchases.get(args['purchaseId'])
        assert purchase.inventory_state=='SUBMITTED' and purchase.offer_artifact['vaultCredentialReceipt']['ownerKey']==evidence.order.owner_key
        x.confirm_chain(evidence)
        assert (await client.get(x.url)).json()['state']=='AWAITING_RESERVATION'
        await x.service.advance(x.app,x.r.customers,x.r.snapshot,evidence.order)
        assert (await client.get(x.url)).json()['state']=='READY'
        assert (await client.post(path,json=args)).json()['checkoutUrl'] is None and not any(req.method=='POST' for req in x.seen)
        open_args={**args,'intent':'checkout'}
        first,second=await asyncio.gather(client.post(path,json=open_args),client.post(path,json=open_args))
        assert first.status_code==second.status_code==200,(first.text,second.text)
        assert first.json()['checkoutUrl']==second.json()['checkoutUrl']=='https://checkout.stripe.com/c/pay/cs_test_synthetic'
        assert len([r for r in x.seen if r.method=='POST'])==1
        assert 'checkoutUrl' not in (await client.get(x.url)).json()
        cancelled=await client.get(x.url,params={'purchase':args['purchaseId']})
        assert cancelled.json()['state']=='CHECKOUT_OPEN' and 'checkoutUrl' not in cancelled.json()
        old=x.store.get(args['purchaseId'])
        assert old.session_id=='cs_test_synthetic' and old.payment_intent_id is None
        assert x.store.dispatch(old.purchase_id)['params']['payment_intent_data[metadata][protocol_purchase_id]']==old.purchase_id
        assert x.store.dispatch(old.purchase_id)['params']['payment_intent_data[metadata][purchase_artifact_hash]']==old.batch_hash
        assert not x.store.fence_undispatched_order(old.purchase_id,now=old.expires_at+1)
        x.external[old.session_id].update(status='complete',payment_status='paid',url=None,payment_intent='pi_synthetic')
        assert (await client.get(x.url)).json()['state']=='PROCESSING'
        assert not (await client.get(x.url)).json()['paymentReceived']
        x.s.vault_card_checkout_enabled=False
        historical=(await client.get(x.url,params={'purchase':old.purchase_id})).json()
        assert historical['state']=='PROCESSING' and not historical['paymentReceived']
        assert (await client.get(x.url,params={'purchase':h(b(99))})).status_code==404
        assert (await client.get(x.url)).json()['purchaseId'] is None


@pytest.mark.asyncio
async def test_closed_or_substituted_custody_never_calls_stripe(tmp_path,monkeypatch):
    x=setup(tmp_path,monkeypatch)
    async with x.client as c:
        c.cookies.set(credential_auth.VAULT_SESSION_COOKIE,x.r.token)
        x.s.vault_card_delivery_enabled=False
        assert (await c.get(x.url)).json()['state']=='UNAVAILABLE'
        x.s.vault_card_delivery_enabled=True
        x.webhook.unlink()
        assert (await c.get(x.url)).json()['state']=='UNAVAILABLE'
        x.webhook.write_text('whsec_'+'synthetic'*6)
        x.webhook.chmod(0o600)
        x.r.snapshot['vault']['currentCoinId']=h(b(98))
        assert (await c.get(x.url)).status_code==503
        assert not x.seen


@pytest.mark.asyncio
@pytest.mark.parametrize('net,mode',[('testnet11','test'),('mainnet','live')])
async def test_network_bound_session_provider_and_persistent_replay(tmp_path,monkeypatch,net,mode):
    x=setup(tmp_path,monkeypatch)
    ev=await x.n.reconstruct(x.r.customers,x.r.snapshot)
    terms=[replace(item.terms,network=net,inventory_version=1,generation_batch_bindings=b'') for item in ev.items]
    artifacts=tuple(native.stripe_artifact(t,x.r.launcher,x.r.vault.root,b(52),x.scope['expiresAt'],x.scope['expiresAt']) for t in terms)
    batch=build_purchase_batch_v1(batch_nonce=b(53),artifacts=artifacts)
    order=replace(ev.order,network=net,mode=mode,purchase_id=h(batch.purchase_id),batch_hash=h(batch.batch_hash),batch=purchase_batch_to_json(batch))
    x.s.network,x.s.stripe_mode=net,mode
    x.store.save(order)
    at=int(time.time())
    params=provider.session_params(order,x.s.vault_card_return_origin,at)
    same=x.store.begin_dispatch(order,params,now=at)
    response=await x.prov.create_session(order,same)
    # Simulate the process losing a successful response before SQLite records it.
    assert x.store.get(order.purchase_id).session_id is None
    recovered=await x.prov.recover_session(order,VaultCardStore(x.s.payment_purchase_db_path),now=at+1)
    assert recovered.session_id==response['id']=='cs_'+mode+'_synthetic'
    requests=[r for r in x.seen if r.method=='POST']
    assert len(requests)==2 and requests[0].content==requests[1].content
    assert requests[0].headers['Idempotency-Key']==requests[1].headers['Idempotency-Key']
    with pytest.raises(ValueError):
        provider.checked_session(order,{**response,'amount_total':606001},expected_expiry=int(params['expires_at']))
    with pytest.raises(ValueError):
        await x.prov.recover_session(order,x.store,now=at+86401)
    with pytest.raises(ValueError):
        x.store.bind_session(order.purchase_id,'cs_'+mode+'_replacement')


@pytest.mark.asyncio
async def test_current_v4_expires_without_charge_then_recovers_exact_signed_originals(tmp_path,monkeypatch):
    from tests.test_inventory_timeout_recovery import Node
    from solslot_api.inventory_recovery import timeout_items
    from solslot_api.inventory_status import validated_recovery_receipt
    from solslot_api import vault_card_settlement
    x=setup(tmp_path,monkeypatch)
    evidence=await x.n.reconstruct(x.r.customers,x.r.snapshot)
    o=evidence.order
    x.store.save(o)
    await x.service.advance(x.app,x.r.customers,x.r.snapshot,o)
    items=timeout_items(x.purchases,o.purchase_id)
    assert tuple(h(i.release_spend.coin.name()) for i in items)==o.reserved_coin_ids
    # The two real compiled AVAILABLE puzzles are V4. Run their native timeout
    # branch and check both actual AVAILABLE successors before testing journal expiry.
    from chia.wallet.util.compute_additions import compute_additions
    assert all(compute_additions(i.release_spend)==[i.successor] for i in items)
    from solslot_api import inventory_expiry_clock
    monkeypatch.setattr(inventory_expiry_clock,'time',SimpleNamespace(time=lambda:o.expires_at+15,monotonic=time.monotonic))
    node=Node()
    node.records.update(x.r.records)
    for item in evidence.items:
        launcher=item.launcher_spend.coin
        node.records[h(launcher.name())]=x.r.record(launcher,99,100)
    blocks={h(b(80-i)):dict(height=110-i,header_hash=h(b(80-i)),prev_hash=h(b(79-i)),timestamp=o.expires_at+5-i)
            for i in range(3)}
    async def block(name):
        return {'success':True,'block_record':blocks.get(name)}
    node.get_block_record=block
    artifact=dict(network=o.network,artifactHash=o.generation_anchor_hash,validatorSet=dict(threshold=2,pubkeys=x.s.zkpassport_validator_pubkeys))
    monkeypatch.setattr(vault_card_settlement,'current_card_artifact',lambda *_:artifact)
    x.s.runtime_environment='staging'
    x.app.state.stripe_delivery_worker=SimpleNamespace(settings=x.s,current_card_order=lambda:o,submitter=SimpleNamespace(provider=SimpleNamespace(primary=node),
        funding_store=SimpleNamespace(cards=SimpleNamespace(get=lambda _:None))))
    assert not await reservations.recover_unallocated(x.app,x.s,o,now=o.expires_at-1)
    assert await reservations.recover_unallocated(x.app,x.s,o,now=o.expires_at+10)
    snap=x.purchases.inventory_status_snapshot(o.purchase_id)
    assert snap[0].inventory_state=='AUTHORIZATION_EXPIRED'
    assert validated_recovery_receipt(snap,network=o.network)['kind']=='authorization-expiry'
    assert await reservations.recover_unallocated(x.app,x.s,o,now=o.expires_at+20)
    assert not x.seen


@pytest.mark.asyncio
async def test_mainnet_owner_http_remains_closed_without_native_mainnet_issuance(tmp_path,monkeypatch):
    x=setup(tmp_path,monkeypatch)
    x.s.network='mainnet'
    x.s.stripe_mode='live'
    x.n.scope=x.n.scope.model_copy(update={'network':'mainnet','mode':'live'})
    x.r.snapshot['network']='mainnet'
    session,_=credential_auth.issue_vault_session(x.s,x.r.session)
    async with x.client as client:
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,session)
        response=await client.get(x.url)
        assert response.status_code==503 and not x.seen
        x.s.vault_card_checkout_enabled=False
        closed=(await client.get(x.url)).json()
        assert closed['network']=='mainnet' and closed['mode']=='live' and closed['state']=='UNAVAILABLE'


@pytest.mark.asyncio
async def test_release_digest_fee_ceiling_and_order_fence(tmp_path,monkeypatch):
    from pydantic import ValidationError
    x=setup(tmp_path,monkeypatch)
    with pytest.raises(ValidationError):
        native.VaultCardRelease.model_validate({**x.scope,'maximumTotalFeeMojos':1999999999})
    x.release_file.write_text(x.release_file.read_text()+' ')
    with pytest.raises(ValueError,match='digest'):
        native.VaultCardNative.configured(x.s)
    o=(await x.n.reconstruct(x.r.customers,x.r.snapshot)).order
    x.store.save(o)
    assert not x.store.fence_undispatched_order(o.purchase_id,now=o.expires_at-1)
    assert x.store.fence_undispatched_order(o.purchase_id,now=o.expires_at)
    with pytest.raises(ValueError,match='closed'):
        x.store.begin_dispatch(o,{'expires_at':str(o.expires_at-120)},now=o.expires_at-4000)
    assert x.store.expiring(o.expires_at)==(o,)


@pytest.mark.asyncio
async def test_signed_unspent_reserve_cannot_reselect_fee_when_mempool_drops(tmp_path,monkeypatch):
    x=setup(tmp_path,monkeypatch)
    ev=await x.n.reconstruct(x.r.customers,x.r.snapshot)
    o=ev.order
    x.store.save(o)
    await x.service.advance(x.app,x.r.customers,x.r.snapshot,o)
    previous=x.purchases.get(o.purchase_id)
    assert previous.inventory_state=='SUBMITTED'
    calls=[]
    async def recovered(app,order,store,saved):
        calls.append(saved.inventory_bundle)
        return saved
    monkeypatch.setattr(reservations,'submit_reservation',recovered)
    original=WalletSpendBundle.from_json_dict(previous.inventory_bundle)
    funding_value={'spendBundle':previous.inventory_bundle}
    submitter=SimpleNamespace(policy=SimpleNamespace(enabled=True,maximum_mojos=400000000),
        faucet=SimpleNamespace(address_hex=h(b(99))),funding_store=SimpleNamespace(
        lookup=lambda network,identifier,context: funding_value if identifier==h(original.name()) else None))
    x.app.state.stripe_delivery_worker=SimpleNamespace(settings=x.s,submitter=submitter,current_card_order=lambda:o)
    await x.service.advance(x.app,x.r.customers,x.r.snapshot,o)
    assert calls==[previous.inventory_bundle]
    funding_value.clear()
    with pytest.raises(ValueError,match='reconciliation'):
        await x.service.advance(x.app,x.r.customers,x.r.snapshot,o)
    assert calls==[previous.inventory_bundle]


@pytest.mark.asyncio
async def test_actual_generation_settings_keep_global_mint_locked(tmp_path,monkeypatch):
    from solslot_api.config import Settings
    x=setup(tmp_path,monkeypatch)
    fields=dict(network='testnet11',deployment_generation_id=x.s.deployment_generation_id,alpha_writes_enabled=False,minting_enabled=False,
        vault_card_delivery_enabled=True,
        generation_customer_enabled=True,generation_customer_identity_enabled=True,generation_customer_public_origin=x.s.vault_card_return_origin,
        generation_chain_anchor_hash=x.scope['generationAnchorHash'],generation_customer_purchase_enabled=True,
        generation_customer_purchase_policy_path='/synthetic/test-scope',generation_customer_purchase_policy_hash=h(b(98)),
        generation_customer_purchase_fee_authority_path='/synthetic/test-funding',generation_customer_purchase_fee_authority_hash=h(b(97)),
        vault_card_checkout_enabled=True,vault_card_release_file=x.s.vault_card_release_file,vault_card_release_sha256=x.s.vault_card_release_sha256,
        payment_purchase_db_path=str(tmp_path/'generation-purchases.db'),vault_card_webhook_key_file=str(x.webhook),
        stripe_settlement_enabled=False,stripe_delivery_worker_enabled=False,stripe_mode='test',stripe_account_id=x.s.stripe_account_id,
        protocol_fee_funding_enabled=False,vault_card_return_origin=x.s.vault_card_return_origin,cors_origins=x.s.vault_card_return_origin)
    settings=Settings(_env_file=None,**fields)
    from pathlib import Path
    Path(settings.payment_purchase_db_path).parent.mkdir(parents=True,exist_ok=True)
    runtime=checkout.VaultCardCheckout.configured(settings)
    assert runtime.integrations() and not settings.minting_enabled and not settings.alpha_writes_enabled
    assert runtime.native.scope.generationAnchorHash==settings.generation_chain_anchor_hash
    native_order=(await runtime.native.reconstruct(x.r.customers,x.r.snapshot)).order
    runtime.native.retain(runtime.purchases,await runtime.native.reconstruct(x.r.customers,x.r.snapshot),int(time.time()))
    stored=runtime.purchases.get(native_order.purchase_id)
    assert stored.offer_artifact['generationAnchorHash']==native_order.generation_anchor_hash
    assert 'genesisArtifactHash' not in stored.offer_artifact
    assert native_order.technology_fee_puzzle_hash!=native_order.primary_proceeds_puzzle_hash
    from solslot_api.native_purchases import _load_context_group
    from fastapi import HTTPException
    with pytest.raises(HTTPException,match='generation checkout'):
        await _load_context_group(settings,None,native_order.purchase_id,require_live=True,allowed_rails=())
    x.r.inventory.evidence.registry.state.pause_mask=8
    x.app.state.vault_card_checkout=x.service
    async with x.client as client:
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,x.r.token)
        assert (await client.get(x.url)).json()['state']=='UNAVAILABLE'


@pytest.mark.asyncio
async def test_registered_signer_accepts_only_independently_reconstructed_release(tmp_path,monkeypatch):
    from solslot_api.validator_app import create_validator_app
    x=setup(tmp_path,monkeypatch)
    ev=await x.n.reconstruct(x.r.customers,x.r.snapshot)
    settings=x.signer_settings(0)
    app=create_validator_app(settings=settings,ledger=x.ledgers[0])
    app.state.validator_ledger=x.ledgers[0]
    app.state.generation_provider=x.r.provider
    path='/v1/generation/vault-card/reservation'
    body=reservations.request_for(ev.order).model_dump()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://signer.invalid') as client:
        a=await client.post(path,json=body)
        assert a.status_code==200,a.text
        assert a.json()==(await client.post(path,json=body)).json()
        assert len(a.json()['signatures'])==2
        assert (await client.post(path,json={**body,'releaseId':h(b(91))})).status_code==409
        assert (await client.post(path,json={**body,'spendBytes':'untrusted'})).status_code==422
        settings.vault_card_reservations_enabled=False
        assert (await client.post(path,json=body)).status_code==404


@pytest.mark.asyncio
async def test_production_router_mount_uses_owner_cookie(tmp_path,monkeypatch):
    from solslot_api.app import app
    x=setup(tmp_path,monkeypatch)
    monkeypatch.setitem(app.dependency_overrides,get_settings,lambda:x.s)
    monkeypatch.setattr(app.state,'generation_customers',x.r.customers,raising=False)
    monkeypatch.setattr(app.state,'vault_card_checkout',x.service,raising=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://buyer.invalid') as client:
        assert (await client.get(x.url)).status_code==401
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE,x.r.token)
        resp=await client.get(x.url)
        assert resp.status_code==200,resp.text
        assert resp.json()['state']=='AWAITING_RESERVATION' and resp.json()['quantity']==2
