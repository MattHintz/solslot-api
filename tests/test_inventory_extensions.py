"""Real local BLS/CLVM, SQLite, independent verifier and current delivery loader.

Provider/account, signed-artifact authority, chain and fee transport are fixtures.
No customer-signed or public-chain outcome is claimed.
"""
import copy
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_api import inventory_extensions as extensions, validator_service, native_purchases
from solslot_api.inventory_extension_claims import COMPONENTS, InventoryExtensionClaim, extension_activation
from solslot_api.inventory_extension_store import canonical
from solslot_api.inventory_extension_chain import current_position, verify_signature
from solslot_api.payment_purchase_store import PaymentPurchaseConflict, PaymentPurchaseStore
from solslot_api.protocol_submission import PreparedProtocolBundle
from solslot_api.validator_inventory_extension import sign_inventory_extension_claim
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, build_inventory_reservation_spend, MAX_RESERVATION_EXTENSION_SECONDS
from tests.test_inventory_authorization_expiry import release_artifact
from tests.test_current_stripe_voucher_delivery import voucher_case, consensus, submit, prove_bundle, NOW
from tests.test_inventory_buyer_handoff import signature_pairs
from tests.test_single_external_delivery_context import hx, _b32, coin_record


def capability(artifact):
    artifact['sourceShas'] = {key: hashlib.sha1(key.encode()).hexdigest() for key in COMPONENTS}
    artifact['inventoryActivation']['sourceShas'] = copy.deepcopy(artifact['sourceShas'])
    a = artifact['inventoryActivation']
    value = dict(schema='solslot.inventory-extension.v1', environment='staging-alpha', network='testnet11',
        deploymentId=a['deploymentId'], sourceShas=artifact['sourceShas'], inventoryVersion=2, adapterVersion=1,
        validatorLedgerVersion=11, minConfirmations=3, availableModuleHash=a['availableModuleHash'],
        reservedModuleHash=a['reservedModuleHash'], maximumExtensionSeconds=MAX_RESERVATION_EXTENSION_SECONDS,
        renewalWindowSeconds=86400, paymentHoldPolicy='rc24-processing-through-terminal-v1',
        stripeAccountId='acct_test123', stripeMode='test')
    value['releaseIdentity'] = hashlib.sha256(canonical(value).encode()).hexdigest()
    value['reviewEvidenceSha256'] = 'ae'*32
    artifact['inventoryExtension'] = value
    assert extension_activation(artifact, 'staging-alpha') == value


async def extension_case(tmp_path, monkeypatch, method='card'):
    c = voucher_case(tmp_path, monkeypatch)
    artifact, _ = release_artifact()
    c.genesis.update(artifact)
    capability(c.genesis)
    c.settings = c.worker.settings
    c.settings.runtime_environment = 'staging'
    c.settings.alpha_writes_enabled = True
    c.settings.minting_enabled = True
    c.settings.launch_control_enabled = False
    c.settings.protocol_artifact_api_token = 'synthetic-extension-service-token'
    c.clock[0] = NOW+40
    c.payment = dict(payment_intent_id='pi_test123', payment_event_id='evt_start123',
        payment_started_at=NOW+30, payment_method=method)
    c.reservation = InventoryReservationV1(c.purchase, c.purchase.quote_expires_at)
    launcher = Coin.from_json_dict(c.records[hx(c.purchase.deed_launcher_id)]['coin'])
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
    from solslot_puzzles.stripe_settlement_v1_driver import make_inventory_available_inner
    available = Coin(c.purchase.deed_launcher_id, SINGLETON_MOD.curry(c.deed_struct, make_inventory_available_inner(c.terms)).get_tree_hash(), uint64(1))
    initial = build_inventory_reservation_spend(available_coin=available, deed_singleton_struct=c.deed_struct,
        lineage_proof=LineageProof(launcher.parent_coin_info, amount=uint64(1)),
        reservation=c.reservation, signer_indices=(0, 1), terms=c.terms)
    signatures = [AugSchemeMPL.sign(next(k for k in c.keys if k.get_g1()==pk), message) for pk, message in signature_pairs(initial.spend)]
    c.initial = SpendBundle([initial.spend], AugSchemeMPL.aggregate(signatures))
    assert consensus(c.initial)[0] is None
    c.reserved = initial.reserved_coin
    with c.purchases._connect() as db:
        db.execute('UPDATE payment_purchases SET inventory_bundle_json=?,inventory_signature=?,inventory_expires_at=?,inventory_reserved_coin_id=?,inventory_reserved_puzzle_hash=? WHERE purchase_id=?',
            (canonical(c.initial.to_json_dict()), hx(c.initial.aggregated_signature), c.reservation.expires_at, hx(c.reserved.name()), hx(c.reserved.puzzle_hash), hx(c.purchase.purchase_id)))
        db.execute('UPDATE payment_purchase_inventory_items SET signature=?,reserved_coin_id=?,reserved_puzzle_hash=? WHERE purchase_id=?',
            (hx(c.initial.aggregated_signature), hx(c.reserved.name()), hx(c.reserved.puzzle_hash), hx(c.purchase.purchase_id)))
    c.records[hx(available.name())] = coin_record(available, confirmed=120, spent=124)
    c.records[hx(c.reserved.name())] = coin_record(c.reserved, confirmed=124)
    c.spends = {(hx(available.name()),124): initial.spend.to_json_dict()}
    series = c.presales.get(c.current['termsHash'])
    current = Coin.from_json_dict(c.records[series['chainState']['currentCoinId']]['coin'])
    parent = await c.worker.provider.get_puzzle_and_solution(hx(current.parent_coin_info),201)
    c.spends[(hx(current.parent_coin_info),201)] = parent
    voucher_parent=c.issuance.voucher_launcher_spend
    c.spends[(hx(voucher_parent.coin.name()),200)] = voucher_parent.to_json_dict()
    c.height = 250
    c.node = c.worker.provider
    async def get_spend(name, height): return copy.deepcopy(c.spends.get((name, height)))
    async def network(): return dict(success=True, network_name='testnet11')
    async def peak(): return dict(success=True, blockchain_state=dict(peak=dict(height=c.height, header_hash=hx(_b32(88))), sync=dict(synced=True, sync_mode=False)))
    async def block(digest): return dict(success=True, block_record=dict(height=c.height, header_hash=digest, timestamp=c.clock[0]))
    c.node.get_puzzle_and_solution=get_spend; c.node.get_network_info=network; c.node.get_blockchain_state=peak; c.node.get_block_record=block
    c.intent = dict(id=c.payment['payment_intent_id'], livemode=False, amount=c.purchase.rail_amount, amount_received=c.purchase.rail_amount,
        currency='usd', status='processing' if method=='us_bank_account' else 'succeeded', created=NOW+20,
        metadata=dict(protocol_purchase_id=hx(c.purchase.purchase_id), purchase_artifact_hash=hx(c.purchase.artifact_hash)))
    c.charge = dict(id='ch_test123', payment_intent=c.intent['id'], livemode=False, currency='usd', amount=c.purchase.rail_amount,
        payment_method_details=dict(type=method), amount_refunded=0, refunded=False, disputed=False)
    c.intent['latest_charge']=c.charge
    c.event = dict(id=c.payment['payment_event_id'], type='payment_intent.'+c.intent['status'], livemode=False,
        created=c.payment['payment_started_at'], data=dict(object=copy.deepcopy(c.intent)))
    c.queries=[]
    def handler(request):
        c.queries.append((request.url.host,request.url.path))
        path=request.url.path
        if path=='/v1/account': value=dict(id='acct_test123')
        elif path=='/v1/payment_intents/'+c.intent['id']: value=c.intent
        elif path=='/v1/events/'+c.event['id']: value=c.event
        elif path=='/get_network_info': value=dict(success=True,network_name='testnet11')
        elif path=='/get_blockchain_state': value=dict(success=True,blockchain_state=dict(peak=dict(height=c.height,header_hash=hx(_b32(88))),sync=dict(synced=True,sync_mode=False)))
        else:
            body=json.loads(request.content)
            if path=='/get_coin_record_by_name': value=dict(success=True,coin_record=c.records.get(body['name']))
            elif path=='/get_puzzle_and_solution': value=dict(success=True,coin_solution=c.spends.get((body['coin_id'],body['height'])))
            else: raise AssertionError(path)
        return httpx.Response(200,json=copy.deepcopy(value))
    client=httpx.Client
    monkeypatch.setattr(httpx,'Client',lambda **kw: client(transport=httpx.MockTransport(handler),**kw))
    async_client=httpx.AsyncClient
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kw: async_client(transport=kw.pop('transport',httpx.MockTransport(handler)),**kw))
    monkeypatch.setattr(validator_service,'load_validator_artifact',lambda _: (copy.deepcopy(c.genesis),None))
    monkeypatch.setattr(validator_service,'load_validator_private_key',lambda settings:c.keys[settings.signer_index])
    monkeypatch.setattr(validator_service,'load_stripe_restricted_key',lambda _: 'synthetic-test-key')
    c.ledgers=[ValidatorLedger(tmp_path/f'extension-signer-{i}.db') for i in range(2)]
    c.signers=[SimpleNamespace(network='testnet11',deployment_environment='staging-alpha',signer_index=i,
        roster_pubkeys=c.genesis['validatorSet']['pubkeys'],coinset_base_url='https://independent-node.invalid',
        stripe_api_url='https://api.stripe.invalid',stripe_mode='test',stripe_account_id='acct_test123') for i in range(2)]
    c.extension_claims=[]; c.fail_after_quorum=False
    async def quorum(settings,claim):
        c.extension_claims.append(claim)
        signatures=[G2Element.from_bytes(bytes.fromhex((await sign_inventory_extension_claim(s,l,claim,claim.canonical_hash()))[2:]))
            for s,l in zip(c.signers,c.ledgers,strict=True)]
        if c.fail_after_quorum: raise OSError('response lost after quorum')
        return SimpleNamespace(signer_indices=(0,1),aggregated_signature=AugSchemeMPL.aggregate(signatures))
    monkeypatch.setattr(extensions,'collect_inventory_extension_quorum',quorum)
    c.funded=[]; c.extension_dispatches=[]; c.fail_push=False
    async def dispatch(prepared,before_push):
        await before_push()
        retained=c.purchases.pending_inventory_extension(hx(c.purchase.purchase_id))
        assert retained['prepared']==prepared
        c.extension_dispatches.append(copy.deepcopy(prepared))
        if c.fail_push: raise OSError('extension acknowledgment lost')
        return dict(spendBundleId=prepared['spendBundleId'])
    async def fund(raw,*,before_push):
        protocol=SpendBundle.from_json_dict(raw)
        fee_puzzle=Program.to((1,[[52,3]])); fee=Coin(_b32(90+len(c.funded)),fee_puzzle.get_tree_hash(),uint64(3))
        bundle=SpendBundle([*protocol.coin_spends,make_spend(fee,fee_puzzle,Program.to([]))],protocol.aggregated_signature)
        prepared=PreparedProtocolBundle(bundle,3,hx(fee.name()))
        c.funded.append(prepared.to_json())
        await before_push(prepared)
        return await dispatch(prepared.to_json(),lambda: before_push(prepared))
    c.submitter=SimpleNamespace(submit=fund,reconcile_reserved=lambda raw,*,before_push: dispatch(raw,before_push))
    c.request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node,protocol_submitter=c.submitter)))
    c.original=c.purchases.get(hx(c.purchase.purchase_id))
    return c


async def advance(c, **changes):
    return await extensions.advance_extension(store=c.purchases,node=c.node,submitter=c.submitter,settings=c.settings,
        presales=c.presales,purchase_id=hx(c.purchase.purchase_id),payment=c.payment,
        load_artifact=lambda:copy.deepcopy(c.genesis),authorize=lambda:None,**changes)


def confirm(c,height=252):
    bundle=SpendBundle.from_json_dict(c.funded[-1]['spendBundle'])
    assert consensus(bundle)[0] is None
    for spend in bundle.coin_spends:
        old=c.records.get(hx(spend.coin.name()),{}).get('confirmed_block_index',240)
        c.records[hx(spend.coin.name())]=coin_record(spend.coin,confirmed=old,spent=height)
        c.spends[(hx(spend.coin.name()),height)]=spend.to_json_dict()
    for coin in bundle.additions(): c.records[hx(coin.name())]=coin_record(coin,confirmed=height)
    c.height=height+3


@pytest.mark.asyncio
async def test_extension_independent_signers_confirmed_cursor_and_paid_delivery(tmp_path,monkeypatch):
    c=await extension_case(tmp_path,monkeypatch)
    try:
        result=await advance(c)
        assert result['extensionState']=='SUBMITTED'
        assert len(c.funded)==1
        assert {path for _,path in c.queries}>={'/v1/account','/v1/payment_intents/pi_test123','/v1/events/evt_start123'}
        with pytest.raises(Exception,match='unresolved'):
            await submit(c)
        confirm(c)
        result=await advance(c,observe_only=True)
        assert result['extensionState']=='CONFIRMED'
        stored=c.purchases.get(hx(c.purchase.purchase_id))
        assert stored.inventory_expires_at==c.original.inventory_expires_at
        assert stored.inventory_bundle==c.original.inventory_bundle
        assert stored.purchase_artifact==c.original.purchase_artifact
        assert len(stored.inventory_extension_receipts)==1
        position=current_position(stored,c.purchases.inventory_items(stored.purchase_id),c.genesis)
        assert position.reservation.expires_at==c.original.inventory_expires_at+MAX_RESERVATION_EXTENSION_SECONDS
        c.clock[0]=NOW+400
        assert await submit(c)
        prove_bundle(c)
        assert c.voucher_claims[-1].deed_coin_id==hx(position.coin.name())
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['quorum','push'])
async def test_crash_reopens_exact_claim_and_funded_bytes(tmp_path,monkeypatch,failure):
    c=await extension_case(tmp_path,monkeypatch)
    try:
        c.fail_after_quorum=failure=='quorum';c.fail_push=failure=='push'
        with pytest.raises(OSError): await advance(c)
        retained=c.purchases.pending_inventory_extension(hx(c.purchase.purchase_id))
        assert retained['state']==('PREPARING' if failure=='quorum' else 'PREPARED')
        c.purchases=PaymentPurchaseStore(c.purchases.path)
        for ledger in c.ledgers: ledger.close()
        c.ledgers=[ValidatorLedger(tmp_path/f'extension-signer-{i}.db') for i in range(2)]
        c.fail_after_quorum=False;c.fail_push=False
        await advance(c)
        assert len(c.funded)==1
        after=c.purchases.pending_inventory_extension(hx(c.purchase.purchase_id))
        assert after['claim']==retained['claim']
        if retained['prepared']: assert after['prepared']==retained['prepared']
        confirm(c)
        # Confirmation wins over an expired local clock and lost ACK.
        c.clock[0]=c.original.inventory_expires_at+10
        assert (await advance(c,observe_only=True))['extensionState']=='CONFIRMED'
        assert len(c.funded)==1
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['account','mode','amount','metadata','event','event_amount','method','canceled','refunded','source_spent','network','series','expired','too_early'])
async def test_extension_mismatch_never_funds_or_releases(tmp_path,monkeypatch,problem):
    c=await extension_case(tmp_path,monkeypatch)
    try:
        if problem=='account': c.signers[0].stripe_account_id='acct_other'
        elif problem=='mode': c.signers[0].stripe_mode='live'
        elif problem=='amount': c.intent['amount']+=1
        elif problem=='metadata': c.intent['metadata']['purchase_artifact_hash']=hx(_b32(99))
        elif problem=='event': c.event['data']['object']['id']='pi_other'
        elif problem=='event_amount': c.event['data']['object']['amount']+=1
        elif problem=='method': c.charge['payment_method_details']['type']='us_bank_account'
        elif problem=='canceled': c.intent['status']='canceled'
        elif problem=='refunded': c.charge.update(amount_refunded=c.purchase.rail_amount,refunded=True)
        elif problem=='source_spent': c.records[hx(c.reserved.name())].update(spent=True,spent_block_index=249)
        elif problem=='network': c.signers[0].network='mainnet'
        elif problem=='series':
            series=c.presales.get(c.current['termsHash']);c.records[series['chainState']['currentCoinId']]['coin']['puzzle_hash']=hx(_b32(99))[2:]
        elif problem=='expired': c.clock[0]=c.original.inventory_expires_at
        elif problem=='too_early': c.clock[0]=NOW+20
        with pytest.raises((ValueError,PaymentPurchaseConflict,validator_service.ValidatorEvidenceError)):
            await advance(c)
        assert not c.funded
        assert c.purchases.get(hx(c.purchase.purchase_id)).inventory_state=='CONFIRMED'
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
async def test_processing_ach_renewals_keep_hold_and_reuse_own_start_after_event_retention(tmp_path,monkeypatch):
    c=await extension_case(tmp_path,monkeypatch,method='us_bank_account')
    try:
        for index in range(4):
            before_events=sum(path.startswith('/v1/events/') for _,path in c.queries)
            result=await advance(c)
            assert result['paymentRetryAllowed'] is False and result['inventoryReusable'] is False
            assert len(c.funded)==index+1
            if index:
                assert result['state']=='REVIEW_REQUIRED'
                assert sum(path.startswith('/v1/events/') for _,path in c.queries)==before_events
            confirm(c,height=252+index*10)
            await advance(c,observe_only=True)
            latest=c.purchases.inventory_extension_operations(hx(c.purchase.purchase_id))[-1]
            c.clock[0]=latest['claim']['next_expires_at']-100
        assert len(c.purchases.get(hx(c.purchase.purchase_id)).inventory_extension_receipts)==4
        assert c.clock[0]>NOW+30*86400
        with pytest.raises(PaymentPurchaseConflict,match='authoritative terminal'):
            c.purchases.claim_inventory_timeout(hx(c.purchase.purchase_id),0,binding={},owner='timeout',now=c.clock[0])
        with pytest.raises(PaymentPurchaseConflict,match='authoritative terminal'):
            c.purchases.record_inventory_released(hx(c.purchase.purchase_id),evidence={})
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('change',['signature','fee','bundle_id','input','destination_height','fee_height'])
async def test_retained_tampering_cannot_advance_successor(tmp_path,monkeypatch,change):
    c=await extension_case(tmp_path,monkeypatch)
    try:
        await advance(c);confirm(c)
        pending=c.purchases.pending_inventory_extension(hx(c.purchase.purchase_id))
        if change in ('destination_height','fee_height'):
            bundle=SpendBundle.from_json_dict(pending['prepared']['spendBundle'])
            if change=='destination_height':
                c.records[hx(bundle.additions()[0].name())]['confirmed_block_index']+=1
            else: c.records[pending['prepared']['feeCoinId']]['spent_block_index']+=1
        else:
            prepared=pending['prepared']
            if change=='signature': prepared['spendBundle']['aggregated_signature']=bytes(G2Element()).hex()
            elif change=='fee': prepared['feeMojos']='4'
            elif change=='bundle_id': prepared['spendBundleId']=hx(_b32(99))
            elif change=='input': prepared['spendBundle']['coin_spends'][0]['coin']['parent_coin_info']=hx(_b32(99))[2:]
            with c.purchases._connect() as db:
                db.execute('UPDATE payment_inventory_extensions SET prepared_json=? WHERE sequence=?',(canonical(prepared),pending['sequence']))
        with pytest.raises(PaymentPurchaseConflict): await advance(c,observe_only=True)
        assert not c.purchases.get(hx(c.purchase.purchase_id)).inventory_extension_receipts
        assert c.purchases.get(hx(c.purchase.purchase_id)).inventory_reserved_coin_id==hx(c.reserved.name())
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
async def test_gate_pause_allows_observation_and_blocks_dispatch(tmp_path,monkeypatch):
    from fastapi import HTTPException
    c=await extension_case(tmp_path,monkeypatch)
    try:
        payload=native_purchases.InventoryExtensionRequest(purchaseId=hx(c.purchase.purchase_id),**{
            'paymentIntentId':c.payment['payment_intent_id'],'paymentEventId':c.payment['payment_event_id'],
            'paymentStartedAt':c.payment['payment_started_at'],'paymentMethod':c.payment['payment_method']})
        with pytest.raises(HTTPException): await native_purchases.extend_inventory(payload,c.request,c.settings,None)
        await advance(c);confirm(c)
        c.settings.alpha_writes_enabled=False
        result=await native_purchases.extend_inventory(payload.model_copy(update={'observe_only':True}),c.request,c.settings,'Bearer synthetic-extension-service-token')
        assert result['paymentHold']['extensionState']=='CONFIRMED'
        c.clock[0]=result['paymentHold']['currentExpiresAt']-100
        with pytest.raises(HTTPException): await native_purchases.extend_inventory(payload,c.request,c.settings,'Bearer synthetic-extension-service-token')
        assert len(c.funded)==1
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.parametrize('terminal_first',[False,True])
def test_two_connections_cannot_sign_extension_and_terminal_for_same_input(tmp_path,terminal_first):
    path=tmp_path/'shared-ledger.db';first=ValidatorLedger(path);second=ValidatorLedger(path)
    try:
        def extension(): return first.record_inventory_extension_or_recover(claim_hash='extension',canonical_claim='{}',purchase_id='purchase',reserved_coin_id='coin',signature='sig')
        def delivery(): return second.record_primary_purchase_or_recover(claim_hash='delivery',canonical_claim='{}',purchase_id='purchase',deed_coin_id='coin',signature='sig')
        winner,loser=(delivery,extension) if terminal_first else (extension,delivery)
        assert winner()=='sig'
        assert winner()=='sig'
        with pytest.raises(ValidatorLedgerConflict): loser()
    finally: first.close();second.close()


@pytest.mark.asyncio
async def test_replay_rechecks_refund_and_series_may_advance_without_changing_terms(tmp_path,monkeypatch):
    c=await extension_case(tmp_path,monkeypatch)
    try:
        c.fail_push=True
        with pytest.raises(OSError): await advance(c)
        c.fail_push=False
        before=copy.deepcopy(c.funded)
        c.charge.update(amount_refunded=c.purchase.rail_amount,refunded=True)
        with pytest.raises(validator_service.ValidatorEvidenceError): await advance(c)
        assert c.funded==before
        assert len(c.extension_dispatches)==1
        c.charge.update(amount_refunded=0,refunded=False)
        series=c.presales.get(c.current['termsHash'])
        c.records[series['chainState']['currentCoinId']].update(spent=True,spent_block_index=249)
        await advance(c)
        assert c.funded==before
        assert len(c.extension_dispatches)==2
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('responders',[1,2])
async def test_private_route_and_http_quorum_require_two_actual_signers(tmp_path,monkeypatch,responders):
    from solslot_api.validator_app import create_validator_app
    from solslot_api.validator_quorum import collect_inventory_extension_quorum, ValidatorQuorumError
    c=await extension_case(tmp_path,monkeypatch)
    try:
        c.fail_after_quorum=True
        with pytest.raises(OSError): await advance(c)
        claim=InventoryExtensionClaim.model_validate(c.purchases.pending_inventory_extension(hx(c.purchase.purchase_id))['claim'])
        c.settings.zkpassport_validator_pubkeys=c.genesis['validatorSet']['pubkeys']
        c.settings.zkpassport_validator_urls=[f'https://signer-{i}.invalid' for i in range(3)]
        c.settings.zkpassport_validator_threshold=2
        apps=[create_validator_app(settings=s,ledger=l) for s,l in zip(c.signers,c.ledgers,strict=True)]
        for app,ledger in zip(apps,c.ledgers,strict=True): app.state.validator_ledger=ledger
        async def transport(request):
            index=int(request.url.host.split('-')[1].split('.')[0])
            if index>=responders: return httpx.Response(503)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=apps[index]),base_url='http://private') as private:
                return await private.post(request.url.path,json=json.loads(request.content))
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
            if responders==1:
                with pytest.raises(ValidatorQuorumError): await collect_inventory_extension_quorum(c.settings,claim,client=client)
            else:
                result=await collect_inventory_extension_quorum(c.settings,claim,client=client)
                assert result.signer_indices==(0,1)
                assert result.claim_hash==claim.canonical_hash()
        assert not c.funded
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.parametrize('field,value',[('network','mainnet'),('environment','production-alpha'),('adapterVersion',2),
    ('validatorLedgerVersion',10),('stripeMode','live'),('sourceShas',{'api':'a'*40}),('reviewEvidenceSha256','0'*64)])
def test_capability_is_complete_and_exact(field,value):
    artifact,_=release_artifact();capability(artifact)
    artifact['inventoryExtension'][field]=value
    with pytest.raises(ValueError): extension_activation(artifact,'staging-alpha')


@pytest.mark.parametrize('terminal_kind',['stripe','stripe_batch','voucher','native_batch'])
@pytest.mark.parametrize('terminal_first',[False,True])
def test_signer_conflicts_cover_every_terminal_writer(tmp_path,terminal_kind,terminal_first):
    a=ValidatorLedger(tmp_path/'variants.db');b=ValidatorLedger(tmp_path/'variants.db')
    try:
        common=dict(claim_hash='terminal',canonical_claim='{}',signature='signed')
        if terminal_kind=='stripe':
            terminal=lambda:b.record_stripe_settlement_or_recover(**common,purchase_id='purchase',payment_intent_id='intent',receipt_coin_id='receipt',delivery_coin_id='coin')
        elif terminal_kind=='stripe_batch':
            terminal=lambda:b.record_stripe_settlement_batch_or_recover(**common,purchase_id='purchase',payment_intent_id='intent',receipt_coin_id='receipt',delivery_coin_ids=('other','coin'))
        elif terminal_kind=='voucher':
            terminal=lambda:b.record_voucher_transition_or_recover(**common,global_payment_id='payment',series_coin_id='series',voucher_coin_id='voucher',payment_coin_id='paymentcoin',deed_coin_id='coin')
        else:
            terminal=lambda:b.record_primary_purchase_batch_or_recover(claim_hashes=('other','terminal'),canonical_claims=('{}','{}'),purchase_ids=('other','purchase'),deed_coin_ids=('other','coin'),signatures=('signed','signed'))
        extension=lambda:a.record_inventory_extension_or_recover(claim_hash='extend',canonical_claim='{}',purchase_id='purchase',reserved_coin_id='coin',signature='signed')
        first,second=(terminal,extension) if terminal_first else (extension,terminal)
        first()
        with pytest.raises(ValidatorLedgerConflict): second()
        # A conflicting batch rolls back its unrelated first input too.
        if not terminal_first and terminal_kind=='native_batch':
            assert a.record_inventory_extension_or_recover(claim_hash='other-extension',canonical_claim='{}',purchase_id='other',reserved_coin_id='other',signature='signed')=='signed'
    finally: a.close();b.close()


@pytest.mark.asyncio
async def test_private_reservation_entry_refuses_reassignment_after_recorded_hold(tmp_path,monkeypatch):
    c=await extension_case(tmp_path,monkeypatch)
    try:
        await advance(c)
        monkeypatch.setattr(validator_service,'verify_inventory_reservation_claim',lambda *_:None)
        # The existing available-lineage verifier is a separate boundary. Once
        # it returns, even a valid new available coin cannot bypass the hold.
        claim=SimpleNamespace(purchase_artifact=c.original.purchase_artifact,available_coin_id=hx(_b32(95)),
            purchase_id=lambda:hx(_b32(94)),signature_message=lambda:b'new buyer',
            model_dump=lambda **_: {'newBuyer':True})
        for signer,ledger in zip(c.signers,c.ledgers,strict=True):
            with pytest.raises(validator_service.ValidatorEvidenceError,match='payment hold'):
                validator_service.sign_inventory_reservation_claim(signer,ledger,claim,hx(_b32(96)))
            assert ledger.active_inventory_authorization(claim.available_coin_id) is None
        # Other deeds preserve the ordinary reservation contract.
        assert c.ledgers[0].record_inventory_reservation_or_recover(claim_hash='unrelated',canonical_claim='{}',
            purchase_id='other',available_coin_id='other-coin',signature='sig',deed_launcher_id=hx(_b32(97)))=='sig'
    finally:
        for ledger in c.ledgers: ledger.close()
