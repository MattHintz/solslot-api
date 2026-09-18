"""Actual signed refund renewal, retained claims and exact winner observation."""
from copy import deepcopy
import json
import sqlite3
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL, SpendBundle
from solslot_api import presale_endpoints as p, refund_continuation as recovery
from solslot_api.voucher_issuance_worker import VoucherIssuanceWorker, VoucherIssuanceWorkerConfig
from tests.test_voucher_refund_review import setup as prepare
from tests.test_alpha_fresh_lifecycle import sign_spends
from tests.test_sols_swap_execution import consensus

pytestmark = pytest.mark.asyncio


async def setup(monkeypatch,tmp_path):
    t = await prepare(monkeypatch,tmp_path)
    series = t.store.get(t.terms['termsHash']); voucher = t.store.voucher(t.terms['termsHash'],0)
    context = await p._load_refund_execution_context(request=t.request,settings=t.settings,approved=t.approved,
        voucher_json=voucher,series=series,series_coin_id=series['chainState']['currentCoinId'],
        voucher_coin_id=voucher['voucherOutputCoinId'],current_timestamp=t.prepared['currentTimestamp'])
    bundle = sign_spends([context.vault_spend,*context.provisional.coin_spends],
        [t.owner,*[AugSchemeMPL.key_gen(bytes([i])*32) for i in (1,2,3)]])
    consensus(bundle)
    terminal = context.provisional
    bindings = dict(action=1,spend_bundle_id=recovery.hx(bundle.name()),
        refund_output_coin_id=recovery.hx(terminal.settlement_coin.name()),terminal_voucher_coin_id=recovery.hx(terminal.terminal_voucher_coin.name()),
        series_input_coin_id=recovery.hx(context.series_coin.name()),series_output_coin_id=recovery.hx(terminal.next_series_coin.name()),
        vault_input_coin_id=recovery.hx(context.vault_coin.name()),
        vault_output_coin_id=next(recovery.hx(c.name()) for c in bundle.additions() if c.parent_coin_info==context.vault_coin.name()))
    execution = dict(kind='native_refund',spendBundle=bundle.to_json_dict(),bindings=bindings)
    t.store.retain_voucher_execution(series['termsHash'],0,execution)
    t.store.record_native_refund_submission(series['termsHash'],0,**bindings)
    worker = VoucherIssuanceWorker.__new__(VoucherIssuanceWorker)
    worker.presales=t.store;worker.coinset=t.request.app.state.coinset
    worker._require_dispatch=lambda:None
    async def validate(job,*,bundle,network):
        assert job=='swap_signature' and network=='testnet11'
        consensus(SpendBundle.from_bytes(bytes(bundle)))
    monkeypatch.setattr('solslot_api.wallet_offer_worker.run_offer_job',validate)
    t.now = t.prepared['currentTimestamp']; t.node.clock=t.now+121
    monkeypatch.setattr(recovery.time,'time',lambda:t.now+121)
    t.execution,t.bundle,t.worker,t.series = execution,bundle,worker,series
    return t


async def test_expired_owner_refund_renews_same_authorization_and_survives_restart_backup_and_original_settlement(monkeypatch,tmp_path):
    t=await setup(monkeypatch,tmp_path)
    try:
        voucher=t.store.voucher(t.terms['termsHash'],0)
        renewed=await recovery.renew_native_refund(t.worker,t.series,voucher,t.execution)
        new=SpendBundle.from_json_dict(renewed['spendBundle'])
        consensus(new)
        assert new.aggregated_signature==t.bundle.aggregated_signature
        assert new.removals()==t.bundle.removals() and new.additions()==t.bundle.additions()
        assert t.store.voucher(t.terms['termsHash'],0)['state']=='REFUNDING'
        with pytest.raises(ValueError,match='recovery'):
            t.store.claim_direct_voucher_work(t.terms['termsHash'],0,'competing-operation',t.now+130)
        backup=sqlite3.connect(tmp_path/'refund-backup.sqlite')
        t.store._conn.backup(backup);backup.close()
        reopened=p.PresaleStore(str(tmp_path/'refund-backup.sqlite'))
        assert reopened.native_refund_attempts(t.terms['termsHash'],0)==t.store.native_refund_attempts(t.terms['termsHash'],0)
        reopened._conn.close()
        # A prior authorized attempt can win a race. Match actual CoinSpends,
        # then bind the real winner before advancing series/vault state.
        t.node.include(t.bundle)
        assert await t.worker._confirm_refund_if_ready(t.series,t.store.voucher(t.terms['termsHash'],0))
        final=t.store.voucher(t.terms['termsHash'],0)
        assert final['refundBundleId']==recovery.hx(t.bundle.name()) and final['state']=='REFUNDED'
        assert len(t.store.native_refund_attempts(t.terms['termsHash'],0))==2
    finally:t.store._conn.close()


@pytest.mark.parametrize('change',['missing','spent','mempool','wrong_network','unsynced','immutable_deadline','paused','stale_cas'])
async def test_uncertain_chain_authority_or_stale_attempt_never_releases_claims(monkeypatch,tmp_path,change):
    t=await setup(monkeypatch,tmp_path)
    try:
        key=recovery.hx(t.bundle.coin_spends[0].coin.name())
        if change=='missing':t.node.records.pop(key)
        if change=='spent':t.node.records[key].update(spent=True,spent_block_index=100)
        if change=='mempool':t.node.pending=[{'other':'transaction'}]
        if change=='wrong_network':t.node.info['network_name']='mainnet'
        if change=='unsynced':t.node.state['blockchain_state']['sync']['synced']=False
        if change=='immutable_deadline':monkeypatch.setattr(recovery.time,'time',lambda:t.now+201);t.node.clock=t.now+201
        if change=='paused':
            def paused():raise ValueError('paused')
            t.worker._require_dispatch=paused
        if change=='stale_cas':
            await recovery.renew_native_refund(t.worker,t.series,t.store.voucher(t.terms['termsHash'],0),t.execution)
        before=t.store.pending_voucher_execution(t.terms['termsHash'],0)
        with pytest.raises((ValueError,RuntimeError)):
            await recovery.renew_native_refund(t.worker,t.series,t.store.voucher(t.terms['termsHash'],0),t.execution)
        assert t.store.pending_voucher_execution(t.terms['termsHash'],0)==before
        assert t.store.voucher(t.terms['termsHash'],0)['state']=='REFUNDING'
    finally:t.store._conn.close()


@pytest.mark.parametrize('offset',[-1,1])
async def test_public_timestamp_variant_settles_without_rewriting_retained_authorization(monkeypatch,tmp_path,offset):
    t=await setup(monkeypatch,tmp_path)
    try:
        unknown=SpendBundle([recovery._vault_at_timestamp(t.bundle.coin_spends[0],t.now+offset),*t.bundle.coin_spends[1:]],t.bundle.aggregated_signature)
        consensus(unknown)
        t.node.include(unknown)
        assert await t.worker._confirm_refund_if_ready(t.series,t.store.voucher(t.terms['termsHash'],0))
        assert t.store.voucher(t.terms['termsHash'],0)['state']=='REFUNDED'
        assert t.store.native_refund_attempts(t.terms['termsHash'],0)==[t.execution]
        evidence=t.store.refund_settlement(t.terms['termsHash'],0)
        assert evidence['kind']=='EQUIVALENT_VAULT_TIMESTAMP'
        assert evidence['authorizationBundleId']==recovery.hx(t.bundle.name())
        assert evidence['observedCoinSpends']==[s.to_json_dict() for s in unknown.coin_spends]
        backup=sqlite3.connect(tmp_path/'settled-refund.sqlite');t.store._conn.backup(backup);backup.close()
        restored=p.PresaleStore(str(tmp_path/'settled-refund.sqlite'))
        assert restored.refund_settlement(t.terms['termsHash'],0)==evidence
        assert restored.native_refund_attempts(t.terms['termsHash'],0)==[t.execution]
        restored._conn.close()
    finally:t.store._conn.close()


@pytest.mark.parametrize('role',range(4))
async def test_timestamp_equivalence_does_not_allow_other_solution_changes(monkeypatch,tmp_path,role):
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    t=await setup(monkeypatch,tmp_path)
    try:
        spends=list(t.bundle.coin_spends);before=spends[role]
        spends[role]=make_spend(before.coin,Program.from_bytes(bytes(before.puzzle_reveal)),Program.to(0))
        assert not recovery.same_refund_spends(t.bundle,spends)
        t.node.include(t.bundle);t.node.spends[recovery.hx(before.coin.name())]=spends[role].to_json_dict()
        with pytest.raises(ValueError,match='authorization or effects'):
            await t.worker._confirm_refund_if_ready(t.series,t.store.voucher(t.terms['termsHash'],0))
        assert t.store.refund_settlement(t.terms['termsHash'],0) is None
        assert t.store.voucher(t.terms['termsHash'],0)['state']=='REFUNDING'
    finally:t.store._conn.close()
