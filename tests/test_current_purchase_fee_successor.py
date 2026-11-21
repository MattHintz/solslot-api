from contextlib import closing
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from solslot_api import generation_customer_purchase_fee_successor as successor
from solslot_api.generation_customer_purchase_cutover import activate_checkout_journal
from solslot_api.generation_customer_purchase_cutover_evidence import _open_read_only, checkout_journal_snapshots
from solslot_api.generation_customer_purchase_fees import CurrentPurchaseFeeAuthority
from tests.test_current_purchase_fee_guard import guarded
from tests.test_current_purchase_fee_renewal import pin, renewal, renewal_runtime


@pytest.fixture
def staged(tmp_path, renewal, renewal_runtime):
    rt = renewal_runtime
    activate_checkout_journal(rt.store.path, rt.funding.path, settings=rt.settings,
                              prior=renewal.prior, policy=renewal.policy)
    with closing(_open_read_only(rt.store.path)) as purchase, closing(_open_read_only(rt.funding.path)) as funding:
        snapshots = checkout_journal_snapshots(purchase, funding)
    data = dict(schema='solslot.testnet-checkout-fee-successor.v1',
                renewalHash=rt.settings.generation_customer_purchase_fee_renewal_hash,
                cutoverHash=rt.settings.generation_customer_purchase_cutover_hash,
                purchaseJournalSnapshot=snapshots[0], fundingJournalSnapshot=snapshots[1],
                priorFeeExposureMojos=rt.cutover.inherited_fee_mojos,
                authority={**renewal.data, 'issuedAt': 300, 'feeCoinIds': ['0x' + '84'*32, '0x' + '85'*32],
                           'maximumTotalFeeMojos': 20})

    def write():
        path, digest = pin(tmp_path/'successor.json', data)
        rt.settings.generation_customer_purchase_fee_successor_path = path
        rt.settings.generation_customer_purchase_fee_successor_hash = digest

    write()
    return SimpleNamespace(rt=rt, data=data, write=write, scope=dict(policy=renewal.policy, cutover=rt.cutover,
                           original=renewal.original, renewal=CurrentPurchaseFeeAuthority.model_validate(renewal.data)))


@pytest.mark.parametrize('change', ['unrelated_renewal','unrelated_cutover','old_coin','extra_coin',
                                     'other_wallet','increase_stage','looser_total','extend','understate','overdraw'])
def test_successor_rejects_changed_scope(staged, change):
    d = staged.data
    a = d['authority']
    if change == 'unrelated_renewal': d['renewalHash'] = '0x' + 'aa'*32
    if change == 'unrelated_cutover': d['cutoverHash'] = '0x' + 'aa'*32
    if change == 'old_coin': a['feeCoinIds'][0] = staged.scope['original'].fee_coin_ids[-1]
    if change == 'extra_coin': a['feeCoinIds'].append('0x' + 'cc'*32)
    if change == 'other_wallet': a['fundingPuzzleHash'] = '0x' + 'cc'*32
    if change == 'increase_stage': a['maximumStageFeeMojos'] += 1
    if change == 'looser_total': a['maximumTotalFeeMojos'] += 1
    if change == 'extend': a['expiresAt'] += 1
    if change == 'understate': d['priorFeeExposureMojos'] = 0
    if change == 'overdraw': d['priorFeeExposureMojos'] += 1
    staged.write()
    with pytest.raises(ValueError):
        successor.read_fee_successor(staged.rt.settings, **staged.scope)


@pytest.mark.asyncio
async def test_factory_requires_both_grant_bindings_and_preserves_input_history(staged, monkeypatch):
    rt, d = staged.rt, staged.data
    with pytest.raises(ValueError, match='BINDING_MISSING'):
        rt.start(300)
    assert rt.reads == []
    proof = {key: d[key] for key in ('purchaseJournalSnapshot','fundingJournalSnapshot','priorFeeExposureMojos')}
    verify = AsyncMock(return_value=proof)
    monkeypatch.setattr(successor, 'reconcile_fee_successor', verify)

    async def install():
        await successor.install_fee_successor(rt.settings, rt.store.path, rt.funding.path, **staged.scope,
                                              submitter=None, node=None, now=300)
    await install()
    coin = d['authority']['feeCoinIds'][0]
    assert rt.start(300).submitter.faucet.available_fee_ids() == set(d['authority']['feeCoinIds'])
    with rt.funding.db:
        rt.funding.db.execute('INSERT INTO funded_protocol_input_history VALUES (?,?,?)', ('testnet11',coin,'0x'+'ab'*32))
    assert rt.start(310).submitter.faucet.available_fee_ids() == {d['authority']['feeCoinIds'][1]}
    await install()
    assert verify.await_count == 1
    assert not rt.start(400).submitter.policy.enabled
    d['authority']['feeCoinIds'][0] = '0x' + '86'*32
    staged.write()
    with pytest.raises(ValueError, match='ALREADY_BOUND'):
        await install()
    with pytest.raises(ValueError, match='BINDING_MISSING'):
        rt.start(310)


@pytest.mark.asyncio
async def test_install_reconciles_old_grant_and_rejects_unsettled_orders(staged, monkeypatch):
    rt = staged.rt
    monkeypatch.setattr(successor, '_primary_peak', AsyncMock(return_value=(None, 12345, 300)))

    async def install():
        return await successor.install_fee_successor(rt.settings, rt.store.path, rt.funding.path, **staged.scope,
                                                     submitter=None, node=None, now=300)

    with pytest.raises(ValueError, match='PRIOR_GRANT_OPEN'):
        await install()
    with rt.funding.db:
        rt.funding.db.execute('INSERT INTO funded_protocol_input_history VALUES (?,?,?)',
                              ('testnet11', staged.scope['renewal'].fee_coin_ids[0], '0x'+'ab'*32))
    with pytest.raises(ValueError, match='ORPHAN_FUNDING'):
        await install()
    with rt.store._connect() as db:
        db.execute('INSERT INTO current_customer_reservation_requests VALUES (?,?)', (rt.saved_intent, 200))
        db.commit()
    with pytest.raises(ValueError, match='UNSETTLED_CHECKOUT'):
        await install()
    with pytest.raises(ValueError, match='BINDING_MISSING'):
        rt.start(300)


@pytest.mark.asyncio
async def test_both_fee_inputs_are_reserved_for_one_new_order(staged, monkeypatch):
    rt, data = staged.rt, staged.data
    evidence = {key: data[key] for key in ('purchaseJournalSnapshot','fundingJournalSnapshot','priorFeeExposureMojos')}
    monkeypatch.setattr(successor, 'reconcile_fee_successor', AsyncMock(return_value=evidence))
    await successor.install_fee_successor(rt.settings, rt.store.path, rt.funding.path, **staged.scope,
                                          submitter=None, node=None, now=300)
    digest = rt.settings.generation_customer_purchase_fee_successor_hash
    with rt.store._connect() as db:
        db.execute('INSERT INTO current_customer_reservation_requests VALUES (?,?)', (rt.saved_intent, 299))
        db.commit()
    with pytest.raises(ValueError, match='ORDER_CHANGED'):
        successor.claim_fee_successor_intent(rt.store, digest, rt.saved_intent, 'RESERVATION', 300)
    with rt.store._connect() as db:
        db.execute('UPDATE current_customer_reservation_requests SET requested_at=301 WHERE intent_id=?',(rt.saved_intent,))
        db.commit()
    with pytest.raises(ValueError, match='ORDER_CHANGED'):
        successor.claim_fee_successor_intent(rt.store, digest, rt.saved_intent, 'RELEASE', 300)
    for phase in ('RESERVATION','RESERVATION','DELIVERY'):
        successor.claim_fee_successor_intent(rt.store, digest, rt.saved_intent, phase, 300)
    with pytest.raises(ValueError, match='ORDER_CHANGED'):
        successor.claim_fee_successor_intent(rt.store, digest, '0x'+'99'*32, 'RESERVATION', 300)


@pytest.mark.asyncio
async def test_renew_consumed_grant_archives_old_binding_and_retries_exact_install(staged, monkeypatch):
    rt, data = staged.rt, staged.data
    evidence = {key: data[key] for key in ('purchaseJournalSnapshot','fundingJournalSnapshot','priorFeeExposureMojos')}
    verify = AsyncMock(return_value=evidence)
    monkeypatch.setattr(successor, 'reconcile_fee_successor', verify)
    async def install(raw=None):
        return await successor.install_fee_successor(rt.settings, rt.store.path, rt.funding.path, **staged.scope,
                                                    submitter=None, node=None, now=315, previous_bytes=raw)
    await install()
    prev_hash = rt.settings.generation_customer_purchase_fee_successor_hash
    from pathlib import Path
    prev_raw = Path(rt.settings.generation_customer_purchase_fee_successor_path).read_bytes()
    with rt.store._connect() as db:
        db.execute('INSERT INTO current_customer_reservation_requests VALUES (?,?)', (rt.saved_intent, 301))
        db.commit()
    successor.claim_fee_successor_intent(rt.store,prev_hash,rt.saved_intent,'RESERVATION',300)
    with closing(_open_read_only(rt.store.path)) as purchase, closing(_open_read_only(rt.funding.path)) as funding:
        evidence['purchaseJournalSnapshot'],evidence['fundingJournalSnapshot']=checkout_journal_snapshots(purchase,funding)
    data.update(evidence,schema='solslot.testnet-checkout-fee-successor.v2',previousSuccessorHash=prev_hash)
    data['authority'].update(issuedAt=310,feeCoinIds=['0x'+'90'*32,'0x'+'91'*32])
    staged.write()
    next_hash=rt.settings.generation_customer_purchase_fee_successor_hash
    with pytest.raises(ValueError,match='PREVIOUS_BYTES_CHANGED'):
        await install(b'{}')
    with pytest.raises(ValueError,match='BINDING_MISSING'):
        rt.start(315)
    await install(prev_raw)
    assert verify.await_args.kwargs['previous'].digest==prev_hash
    with rt.store._connect() as db:
        assert tuple(db.execute('SELECT grant_hash,intent_id,next_hash FROM current_purchase_fee_grant_history').fetchone())==(prev_hash,rt.saved_intent,next_hash)
        assert tuple(db.execute('SELECT grant_hash,intent_id FROM current_purchase_fee_successor').fetchone())==(next_hash,None)
    assert rt.start(315).submitter.faucet.available_fee_ids()==set(data['authority']['feeCoinIds'])
    await install(prev_raw)
    assert verify.await_count==2
    with pytest.raises(ValueError,match='ORDER_CHANGED'):
        successor.claim_fee_successor_intent(rt.store,next_hash,rt.saved_intent,'RESERVATION',310)


@pytest.mark.asyncio
async def test_reconciliation_rejects_reusing_predecessor_coins(staged,monkeypatch):
    rt,data=staged.rt,staged.data
    previous=successor.PreviousFeeGrant(rt.settings.generation_customer_purchase_fee_successor_hash,
                                       CurrentPurchaseFeeAuthority.model_validate(data['authority']))
    monkeypatch.setattr(successor,'_primary_peak',AsyncMock(return_value=(None,12345,315)))
    with closing(_open_read_only(rt.store.path)) as purchase, closing(_open_read_only(rt.funding.path)) as funding:
        with pytest.raises(ValueError,match='INPUT_USED'):
            await successor.reconcile_fee_successor(purchase,funding,submitter=None,node=None,cutover=rt.cutover,
                original=staged.scope['original'],renewal=staged.scope['renewal'],next_ids=previous.authority.fee_coin_ids,previous=previous)
