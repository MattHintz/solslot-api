"""Private BLS hold/release boundaries with real CLVM timeout outcomes.

Stripe, node transport and release authority are isolated fixtures. These are
not public-chain receipts, wallet signatures, or deployment/activation evidence.
"""
import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import httpx
import pytest
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from solslot_puzzles.stripe_settlement_v1_driver import build_inventory_release_spend

from solslot_api import validator_service
from solslot_api.inventory_extension_store import canonical
from solslot_api.inventory_payment_hold_claims import (
    InventoryPaymentHoldClaim, InventoryPaymentHoldReleaseClaim, payment_hold_activation,
)
from solslot_api.validator_inventory_payment_hold import (
    sign_inventory_payment_hold, sign_inventory_payment_hold_release,
)
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from solslot_api.validator_quorum import collect_inventory_payment_hold_quorum, ValidatorQuorumError
from tests.test_inventory_extensions import extension_case, advance, confirm, current_position
from tests.test_current_stripe_voucher_delivery import consensus, NOW
from tests.test_single_external_delivery_context import hx, _b32, coin_record


def activate(c):
    extension = c.genesis['inventoryExtension']
    value = dict(schema='solslot.inventory-payment-holds.v1', environment='staging-alpha', network='testnet11',
        deploymentId=extension['deploymentId'], sourceShas=extension['sourceShas'], adapterVersion=1,
        validatorLedgerVersion=12, extensionReleaseIdentity=extension['releaseIdentity'],
        stripeAccountId=extension['stripeAccountId'], stripeMode='test', minConfirmations=3,
        paymentHoldPolicy=extension['paymentHoldPolicy'])
    value['releaseIdentity'] = hashlib.sha256(canonical(value).encode()).hexdigest()
    value['reviewEvidenceSha256'] = 'cb' * 32
    c.genesis['inventoryPaymentHolds'] = value
    return value


async def hold_case(tmp_path, monkeypatch, method='card'):
    c = await extension_case(tmp_path, monkeypatch, method)
    c.claim = InventoryPaymentHoldClaim(network='testnet11', genesis_artifact_hash=c.genesis['artifactHash'],
        activation=activate(c), purchase_artifact=c.original.purchase_artifact, smart_deed_inner_hash=hx(c.terms.smart_deed_inner_hash),
        reserved_coin_id=hx(c.reserved.name()), reserved_puzzle_hash=hx(c.reserved.puzzle_hash),
        reservation_expires_at=c.reservation.expires_at, payment_intent_id=c.payment['payment_intent_id'], payment_method=method)
    c.intent.update(status='requires_payment_method', payment_method=None, latest_charge=None, amount_received=0,
        payment_method_types=[method], capture_method='automatic',
        payment_method_options={method: {'request_three_d_secure':'any'} if method=='card' else {'verification_method':'instant'}})
    c.intent['metadata'].update(purchase_kind='PRESALE', processing_charge_minor='0',
        **({'card_3ds_policy':'any'} if method=='card' else {'bank_verification_policy':'instant'}))
    c.chain_clock = c.clock[0]
    c.refunds = dict(has_more=False, data=[])
    c.account = 'acct_test123'
    c.bad_tip = False
    def handler(request):
        path=request.url.path; c.queries.append((request.url.host,path))
        if path == '/v1/account': value=dict(id=c.account)
        elif path == '/v1/payment_intents/'+c.intent['id']: value=c.intent
        elif path == '/v1/charges/'+c.charge['id']: value=c.charge
        elif path == '/v1/refunds': value=c.refunds
        elif path == '/v1/events/'+c.event['id']: value=c.event
        elif path == '/get_network_info': value=dict(success=True,network_name='testnet11')
        elif path == '/get_blockchain_state':
            value=dict(success=True,blockchain_state=dict(peak=dict(height=c.height,header_hash=hx(_b32(88))),sync=dict(synced=True,sync_mode=False)))
        else:
            body=json.loads(request.content)
            if path == '/get_coin_record_by_name': value=dict(success=True,coin_record=c.records.get(body['name']))
            elif path == '/get_puzzle_and_solution': value=dict(success=True,coin_solution=c.spends.get((body['coin_id'],body['height'])))
            elif path == '/get_block_record':
                value=dict(success=True,block_record=dict(height=c.height,header_hash=hx(_b32(89)) if c.bad_tip else body['header_hash'],timestamp=c.chain_clock))
            else: raise AssertionError(path)
        return httpx.Response(200,json=copy.deepcopy(value))
    client=httpx.AsyncClient
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kw: client(transport=kw.pop('transport',httpx.MockTransport(handler)),**kw))
    return c


def close(c):
    for ledger in c.ledgers: ledger.close()


async def arm(c, index=0):
    return await sign_inventory_payment_hold(c.signers[index], c.ledgers[index], c.claim, c.claim.canonical_hash())


async def release(c, claim, index=0):
    return await sign_inventory_payment_hold_release(c.signers[index], c.ledgers[index], claim, claim.canonical_hash())


def paid(c):
    c.intent.update(status='succeeded', amount_received=c.purchase.rail_amount, latest_charge=c.charge, payment_method='pm_test123')
    c.charge.update(paid=True,status='succeeded',balance_transaction='txn_test123')


def refunded(c):
    paid(c)
    c.charge.update(refunded=True,amount_refunded=c.purchase.rail_amount)
    c.refunds['data']=[dict(id='re_test123',charge=c.charge['id'],payment_intent=c.intent['id'],currency='usd',
        status='succeeded',amount=c.purchase.rail_amount)]


def returned(c, position=None):
    coin=c.reserved if position is None else position.coin
    reservation=c.reservation if position is None else position.reservation
    creation=c.initial.coin_spends[0] if position is None else position.creation_spend
    result=build_inventory_release_spend(reserved_coin=coin, deed_singleton_struct=c.deed_struct,
        lineage_proof=lineage_proof_for_coinsol(creation), reservation=reservation, terms=c.terms, timed_out=True)
    bundle=SpendBundle([result.spend],G2Element())
    assert consensus(bundle)[0] is None
    assert bundle.additions()==[result.next_coin]
    height=c.height+2
    c.records[hx(coin.name())].update(spent=True,spent_block_index=height)
    c.records[hx(result.next_coin.name())]=coin_record(result.next_coin,confirmed=height)
    c.spends[(hx(coin.name()),height)]=result.spend.to_json_dict()
    c.height=height+3; c.clock[0]=reservation.expires_at+1
    return InventoryPaymentHoldReleaseClaim(hold=c.claim, reserved_coin_id=hx(coin.name()),
        reservation_expires_at=reservation.expires_at, available_coin_id=hx(result.next_coin.name()))


def reserve_again(c, ledger=None):
    ledger=ledger or c.ledgers[0]
    return ledger.record_inventory_reservation_or_recover(claim_hash=hx(_b32(80)),canonical_claim='new buyer',
        purchase_id=hx(_b32(81)),available_coin_id=hx(_b32(82)),deed_launcher_id=hx(c.purchase.deed_launcher_id),signature='new signature')


@pytest.mark.asyncio
@pytest.mark.parametrize('method',['card','us_bank_account'])
async def test_private_hold_persists_through_restart_unknown_confirmation_and_expiry(tmp_path,monkeypatch,method):
    c=await hold_case(tmp_path,monkeypatch,method)
    try:
        first=await arm(c)
        assert AugSchemeMPL.verify(c.keys[0].get_g1(),c.claim.signature_message(),G2Element.from_bytes(bytes.fromhex(first[2:])))
        assert not c.funded and not c.extension_dispatches
        c.ledgers[0].close(); c.ledgers[0]=ValidatorLedger(tmp_path/'extension-signer-0.db')
        c.intent.update(status='requires_action',payment_method='pm_test123')
        c.clock[0]=c.reservation.expires_at+10*86400
        assert await arm(c)==first
        with pytest.raises(ValidatorLedgerConflict,match='held before payment'): reserve_again(c)
        assert c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id))['state']=='ARMED'
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['missing_cap','environment','source','review','ledger','account','live','amount','metadata',
    'kind','policy','options','capture','missing_charge','method','charge','already_confirmed','expired','chain_expired','wrong_ancestor','spent','immature','puzzle','hash'])
async def test_arm_refuses_mismatches_before_any_acknowledgment(tmp_path,monkeypatch,problem):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        if problem=='missing_cap': del c.genesis['inventoryPaymentHolds']
        elif problem=='environment': c.signers[0].deployment_environment='production-alpha'
        elif problem=='source': c.genesis['inventoryPaymentHolds']['sourceShas']['api']='1'*40
        elif problem=='review': c.genesis['inventoryPaymentHolds']['reviewEvidenceSha256']='0'*64
        elif problem=='ledger': c.genesis['inventoryPaymentHolds']['validatorLedgerVersion']=11
        elif problem=='account': c.account='acct_other'
        elif problem=='live': c.intent['livemode']=True
        elif problem=='amount': c.intent['amount']+=1
        elif problem=='metadata': c.intent['metadata']['purchase_artifact_hash']=hx(_b32(99))
        elif problem=='kind': c.intent['metadata']['purchase_kind']='DIRECT'
        elif problem=='policy': c.intent['metadata']['card_3ds_policy']='automatic'
        elif problem=='options': c.intent['payment_method_options']={}
        elif problem=='capture': c.intent['capture_method']='manual'
        elif problem=='missing_charge': del c.intent['latest_charge']
        elif problem=='method': c.intent['payment_method_types']=['us_bank_account']
        elif problem=='charge': c.intent['latest_charge']=c.charge
        elif problem=='already_confirmed': c.intent.update(status='processing',payment_method='pm_test123')
        elif problem=='expired': c.clock[0]=c.reservation.expires_at
        elif problem=='chain_expired': c.chain_clock=c.reservation.expires_at
        elif problem=='wrong_ancestor': c.bad_tip=True
        elif problem=='spent': c.records[hx(c.reserved.name())].update(spent=True,spent_block_index=249)
        elif problem=='immature': c.records[hx(c.reserved.name())]['confirmed_block_index']=c.height
        elif problem=='puzzle': c.claim=c.claim.model_copy(update={'reserved_puzzle_hash':hx(_b32(99))})
        digest=hx(_b32(99)) if problem=='hash' else c.claim.canonical_hash()
        with pytest.raises(validator_service.ValidatorEvidenceError):
            await sign_inventory_payment_hold(c.signers[0],c.ledgers[0],c.claim,digest)
        assert c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id)) is None
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('terminal',['canceled','refund'])
async def test_terminal_provider_and_real_timeout_required_then_tombstones_survive(tmp_path,monkeypatch,terminal):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        await arm(c)
        claim=returned(c)
        if terminal=='refund': refunded(c)
        else: c.intent['status']='canceled'
        signature=await release(c,claim)
        assert AugSchemeMPL.verify(c.keys[0].get_g1(),claim.signature_message(),G2Element.from_bytes(bytes.fromhex(signature[2:])))
        assert not AugSchemeMPL.verify(c.keys[0].get_g1(),c.claim.signature_message(),G2Element.from_bytes(bytes.fromhex(signature[2:])))
        c.ledgers[0].close();c.ledgers[0]=ValidatorLedger(tmp_path/'extension-signer-0.db')
        assert reserve_again(c)=='new signature'
        c.records[claim.available_coin_id].update(spent=True,spent_block_index=c.height)
        assert await release(c,claim)==signature
        with pytest.raises(validator_service.ValidatorEvidenceError): await arm(c)
        assert c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id))['release_signature']==signature
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['unpaid_open','processing','partial','pending','failed','canceled_refund','requires_action',
    'duplicate','pagination','wrong_pi','wrong_charge','wrong_currency','disputed','false_unpaid','unspent_source','immature',
    'spent_successor','wrong_successor','changed_expiry','unknown_hold'])
async def test_terminal_release_failures_keep_deed_unavailable(tmp_path,monkeypatch,problem):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        if problem!='unknown_hold': await arm(c)
        claim=returned(c);refunded(c)
        if problem=='unpaid_open': c.intent.update(status='requires_payment_method',latest_charge=None,amount_received=0)
        elif problem=='processing': c.intent['status']='processing'
        elif problem=='partial': c.charge['amount_refunded']-=1;c.refunds['data'][0]['amount']-=1
        elif problem in ('pending','failed','canceled_refund','requires_action'): c.refunds['data'][0]['status']='canceled' if problem=='canceled_refund' else problem
        elif problem=='duplicate': c.refunds['data']*=2
        elif problem=='pagination': c.refunds['has_more']=True
        elif problem=='wrong_pi': c.refunds['data'][0]['payment_intent']='pi_other'
        elif problem=='wrong_charge': c.refunds['data'][0]['charge']='ch_other'
        elif problem=='wrong_currency': c.refunds['data'][0]['currency']='eur'
        elif problem=='disputed': c.charge['disputed']=True
        elif problem=='false_unpaid': c.intent.update(status='canceled',amount_received=0);c.charge.update(paid=True,status='succeeded')
        elif problem=='unspent_source': c.records[claim.reserved_coin_id].update(spent=False,spent_block_index=0)
        elif problem=='immature': c.height-=3
        elif problem=='spent_successor': c.records[claim.available_coin_id].update(spent=True,spent_block_index=c.height)
        elif problem=='wrong_successor': claim=claim.model_copy(update={'available_coin_id':hx(_b32(99))})
        elif problem=='changed_expiry': claim=claim.model_copy(update={'reservation_expires_at':claim.reservation_expires_at+1})
        with pytest.raises(validator_service.ValidatorEvidenceError): await release(c,claim)
        if problem!='unknown_hold':
            with pytest.raises(ValidatorLedgerConflict): reserve_again(c)
    finally: close(c)


@pytest.mark.asyncio
async def test_original_payment_hold_survives_extension_and_only_returned_current_coin_releases(tmp_path,monkeypatch):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        await arm(c,0);await arm(c,1);paid(c)
        await advance(c);confirm(c);await advance(c,observe_only=True)
        position=current_position(c.purchases.get(hx(c.purchase.purchase_id)),c.purchases.inventory_items(hx(c.purchase.purchase_id)),c.genesis)
        claim=returned(c,position);refunded(c)
        with pytest.raises(ValidatorLedgerConflict): reserve_again(c)
        for i in (0,1): await release(c,claim,i)
        assert reserve_again(c)=='new signature'
        c.clock[0]=position.reservation.expires_at-10
        with pytest.raises(validator_service.ValidatorEvidenceError): await arm(c)
        row=c.purchases.inventory_extension_operations(hx(c.purchase.purchase_id))[0]
        with pytest.raises(ValidatorLedgerConflict,match='released payment hold'):
            c.ledgers[0].record_inventory_extension_or_recover(claim_hash=c.extension_claims[0].canonical_hash(),canonical_claim=canonical(row['claim']),
                purchase_id=hx(c.purchase.purchase_id),reserved_coin_id=row['claim']['reserved_coin_id'],signature='ignored',deed_launcher_id=hx(c.purchase.deed_launcher_id))
    finally: close(c)


def sibling(ledger,c,kind,pi='pi_other'):
    common=dict(claim_hash=hx(_b32(71)),canonical_claim=canonical(dict(purchase_artifact=c.original.purchase_artifact,payment_intent_id=pi)),
        purchase_id=hx(c.purchase.purchase_id),payment_intent_id=pi,signature='test signature')
    if kind=='extension':
        common.pop('payment_intent_id');return ledger.record_inventory_extension_or_recover(**common,reserved_coin_id=hx(c.reserved.name()),deed_launcher_id=hx(c.purchase.deed_launcher_id))
    if kind=='single': return ledger.record_stripe_settlement_or_recover(**common,receipt_coin_id=hx(_b32(72)),delivery_coin_id=hx(c.reserved.name()))
    if kind=='batch': return ledger.record_stripe_settlement_batch_or_recover(**common,receipt_coin_id=hx(_b32(72)),delivery_coin_ids=[hx(c.reserved.name())])
    common['global_payment_id']=hx(_b32(73));common['series_coin_id']=hx(_b32(74))
    if kind=='issuance': return ledger.record_voucher_issuance_or_recover(**common,purchase_launcher_coin_id=hx(_b32(75)))
    return ledger.record_voucher_transition_or_recover(**common,voucher_coin_id=hx(_b32(76)),payment_coin_id=hx(_b32(77)),deed_coin_id=hx(c.reserved.name()))


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['extension','single','batch','issuance','transition'])
async def test_other_payment_cannot_take_held_purchase_and_same_payment_cannot_reopen_after_release(tmp_path,monkeypatch,kind):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        await arm(c)
        with pytest.raises(ValidatorLedgerConflict,match='different or released'): sibling(c.ledgers[0],c,kind)
        assert sibling(c.ledgers[0],c,kind,pi=c.claim.payment_intent_id)=='test signature'
        claim=returned(c);c.intent['status']='canceled';await release(c,claim)
        with pytest.raises(ValidatorLedgerConflict,match='different or released'): sibling(c.ledgers[0],c,kind,pi=c.claim.payment_intent_id)
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['extension','single','batch','issuance','transition'])
async def test_prior_signed_payment_cannot_be_rebound_to_a_new_preconfirmation_hold(tmp_path,monkeypatch,kind):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        sibling(c.ledgers[0],c,kind)
        with pytest.raises(validator_service.ValidatorEvidenceError,match='already has a signed'):
            await arm(c)
    finally: close(c)


@pytest.mark.asyncio
async def test_separate_sqlite_connections_serialize_competing_payment_and_hold(tmp_path,monkeypatch):
    c=await hold_case(tmp_path,monkeypatch)
    other=ValidatorLedger(tmp_path/'extension-signer-0.db')
    barrier=Barrier(2)
    try:
        def run(which):
            barrier.wait()
            try:
                if which=='hold': c.ledgers[0].record_inventory_payment_hold(claim=c.claim,signature='test signature',purchase_id=hx(c.purchase.purchase_id),deed_launcher_id=hx(c.purchase.deed_launcher_id))
                else: sibling(other,c,'issuance')
                return which
            except ValidatorLedgerConflict: return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(run,('hold','issuance')))
        assert results.count('refused')==1
        assert len(set(results))==2
    finally: other.close();close(c)


@pytest.mark.asyncio
async def test_real_private_http_quorum_binds_domain_and_fails_without_two_signers(tmp_path,monkeypatch):
    from solslot_api.validator_app import create_validator_app
    c=await hold_case(tmp_path,monkeypatch)
    try:
        apps=[create_validator_app(settings=s,ledger=l) for s,l in zip(c.signers,c.ledgers,strict=True)]
        for app,ledger in zip(apps,c.ledgers,strict=True): app.state.validator_ledger=ledger
        transports=[httpx.ASGITransport(app=app) for app in apps]
        c.settings.zkpassport_validator_urls=['https://signer0.invalid','https://signer1.invalid','https://signer2.invalid']
        c.settings.zkpassport_validator_pubkeys=c.genesis['validatorSet']['pubkeys']
        c.settings.zkpassport_validator_threshold=2
        offline=set([2])
        async def dispatch(request):
            index=int(request.url.host[6])
            if index in offline: return httpx.Response(503,json=dict(detail='offline'))
            return await transports[index].handle_async_request(request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as client:
            result=await collect_inventory_payment_hold_quorum(c.settings,c.claim,client=client)
            assert result.signer_indices==(0,1)
            assert AugSchemeMPL.aggregate_verify([c.keys[i].get_g1() for i in result.signer_indices],
                [c.claim.signature_message()]*2,result.aggregated_signature)
            release_claim=returned(c);c.intent['status']='canceled'
            released=await collect_inventory_payment_hold_quorum(c.settings,release_claim,client=client)
            assert released.claim_hash==release_claim.canonical_hash()
            offline.add(1)
            with pytest.raises(ValidatorQuorumError,match='quorum unavailable'):
                await collect_inventory_payment_hold_quorum(c.settings,release_claim,client=client)
    finally: close(c)


@pytest.mark.asyncio
async def test_v11_migration_preserves_prior_authorizations_and_absent_capability_stays_disabled(tmp_path,monkeypatch):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        sibling(c.ledgers[0],c,'issuance')
        before=c.ledgers[0]._conn.execute('SELECT * FROM voucher_issuance_signatures').fetchall()
        c.ledgers[0]._conn.executescript('DROP TABLE inventory_payment_holds; DROP TABLE base_inventory_holds; DROP TABLE base_lifecycle_observations; DROP TABLE base_lifecycle_terminals; DROP TABLE base_inventory_hold_generations; PRAGMA user_version=11;')
        c.ledgers[0].close();c.ledgers[0]=ValidatorLedger(tmp_path/'extension-signer-0.db')
        assert [tuple(r) for r in before]==[tuple(r) for r in c.ledgers[0]._conn.execute('SELECT * FROM voucher_issuance_signatures')]
        assert c.ledgers[0].healthcheck()
        with pytest.raises(validator_service.ValidatorEvidenceError): await arm(c)
        del c.genesis['inventoryPaymentHolds']
        assert payment_hold_activation(c.genesis,'staging-alpha',required=False) is None
        with pytest.raises(ValueError): payment_hold_activation(c.genesis,'staging-alpha')
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('collision',['same_purchase','same_deed','same_payment'])
async def test_hold_identity_is_one_time_and_cannot_move_between_purchases(tmp_path,monkeypatch,collision):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        await arm(c)
        original=c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id))
        purchase_id=hx(c.purchase.purchase_id) if collision=='same_purchase' else hx(_b32(91))
        launcher=hx(_b32(92)) if collision=='same_payment' else hx(c.purchase.deed_launcher_id)
        claim=c.claim.model_copy(update={'payment_intent_id':c.claim.payment_intent_id if collision=='same_payment' else 'pi_other',
            'reserved_coin_id':hx(_b32(93))})
        with pytest.raises(ValidatorLedgerConflict):
            c.ledgers[0].record_inventory_payment_hold(claim=claim,signature='cannot replace',purchase_id=purchase_id,deed_launcher_id=launcher)
        assert c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id))==original
    finally: close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['deadline','superseded'])
async def test_hold_rechecks_deadline_and_reservation_head_under_writer_lock(tmp_path,monkeypatch,problem):
    c=await hold_case(tmp_path,monkeypatch)
    try:
        if problem=='deadline': c.clock[0]=c.claim.reservation_expires_at
        else:
            c.ledgers[0].record_inventory_reservation_or_recover(claim_hash=hx(_b32(80)),
                canonical_claim=canonical(dict(purchase_artifact={**c.original.purchase_artifact,'purchaseId':hx(_b32(81))})),
                purchase_id=hx(_b32(81)),available_coin_id=hx(_b32(82)),
                deed_launcher_id=hx(c.purchase.deed_launcher_id),signature='prior reservation')
        with pytest.raises(ValidatorLedgerConflict,match='expired|superseded'):
            c.ledgers[0].record_inventory_payment_hold(claim=c.claim,signature='not acknowledged',
                purchase_id=hx(c.purchase.purchase_id),deed_launcher_id=hx(c.purchase.deed_launcher_id))
        assert c.ledgers[0].inventory_payment_hold(hx(c.purchase.purchase_id)) is None
    finally: close(c)
