"""Real prepare/complete/worker/SQLite refund path with synthetic chain authority."""
from copy import deepcopy
from types import SimpleNamespace
import sqlite3

import pytest
from chia_rs import AugSchemeMPL,Coin,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from solslot_api import presale_endpoints as p, stripe_refund_continuation as recovery
from solslot_api.payment_purchase_store import StoredPaymentPurchase,PaymentPurchaseStore
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_api.voucher_issuance_worker import VoucherIssuanceWorker,VoucherIssuanceWorkerConfig
from solslot_api.stripe_voucher_execution import _prepared_from_json
from solslot_api.protocol_submission import ProtocolSubmissionError
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json,purchase_artifact_v3_to_json
from solslot_puzzles.payment_artifacts_v3 import stripe_receipt_from_json
from solslot_puzzles.voucher_presale_v2 import series_terms_from_json
from solslot_puzzles.voucher_presale_v2_driver import curry_series,curry_purchase_launcher,VoucherSeriesStateV2
from solslot_puzzles.voucher_presale_v3 import voucher_commitment_v3_from_json
from solslot_puzzles.voucher_presale_v3_driver import curry_stripe_voucher_receipt,build_stripe_voucher_issuance_spends
from tests.test_presale_endpoints import stripe_escrowed_voucher,create_series
from tests.test_alpha_fresh_lifecycle import sign_spends
from tests.test_sols_swap_execution import consensus

hx=lambda x:'0x'+bytes(x).hex()

def escrowed(now):
    original,terms,_=stripe_escrowed_voucher(now=now)
    saved=original.voucher(terms['termsHash'],0);original._conn.close()
    purchase=purchase_artifact_v3_from_json(saved['purchaseArtifact']);receipt=stripe_receipt_from_json(saved['settlementReceipt'])
    store=p.PresaleStore(':memory:');create_series(store,terms)
    stored=StoredPaymentPurchase(purchase_id=hx(purchase.purchase_id),artifact_hash=hx(purchase.artifact_hash),
        purchase_intent_id='synthetic-refund',rail='stripe',quote_expires_at=purchase.quote_expires_at,
        offer_artifact_hash='0x'+'55'*32,offer_artifact={},purchase_artifact=purchase_artifact_v3_to_json(purchase),external_message=None)
    store.ingest_stripe_payment(terms['termsHash'],artifact=purchase,receipt=receipt,evidence_id=receipt.evidence.event_id,issued_purchase=stored)
    voucher=voucher_commitment_v3_from_json(store.voucher(terms['termsHash'],0)['commitment'])
    program=series_terms_from_json(terms);initial=VoucherSeriesStateV2()
    series_coin=Coin(program.series_singleton_id,puzzle_for_singleton(program.series_singleton_id,curry_series(program,initial)).get_tree_hash(),1)
    receipt_puzzle=curry_stripe_voucher_receipt(terms=program,voucher=voucher,artifact=purchase)
    launcher_puzzle=curry_purchase_launcher(terms=program,voucher=voucher,payment_puzzle_hash=receipt_puzzle.get_tree_hash(),payment_amount=1)
    launcher=Coin(bytes32(b'L'*32),launcher_puzzle.get_tree_hash(),2)
    issuance=build_stripe_voucher_issuance_spends(terms=program,state=initial,series_coin=series_coin,
        series_lineage_proof=LineageProof(bytes32(b'S'*32),None,1),voucher=voucher,artifact=purchase,receipt=receipt,
        expected_original_payer=voucher.original_payer,smart_deed_inner_hash=voucher.smart_deed_inner_hash,purchase_launcher_coin=launcher,signer_indices=(0,1))
    bundle_id='0x'+'aa'*32
    store.record_issuance_funding(terms['termsHash'],0,funding_bundle_id=bundle_id,purchase_launcher_coin_id=hx(launcher.name()),purchase_launcher_puzzle_hash=hx(launcher.puzzle_hash))
    store.record_issuance_submission(terms['termsHash'],0,issuance_bundle_id=bundle_id,voucher_launcher_id=hx(issuance.voucher_launcher_id),
        voucher_output_coin_id=hx(issuance.voucher_coin.name()),payment_commitment_coin_id=hx(issuance.receipt_coin.name()),
        series_input_coin_id=hx(series_coin.name()),series_output_coin_id=hx(issuance.next_series_coin.name()),signer_indices=(0,1))
    store.confirm_issuance(terms['termsHash'],0,p.VoucherIssuanceChainEvidence(evidenceId='synthetic-issued-refund',spendBundleId=bundle_id,
        purchaseLauncherCoinId=hx(launcher.name()),voucherLauncherId=hx(issuance.voucher_launcher_id),voucherOutputCoinId=hx(issuance.voucher_coin.name()),
        paymentCommitmentCoinId=hx(issuance.receipt_coin.name()),seriesInputCoinId=hx(series_coin.name()),seriesInputParentCoinId=hx(series_coin.parent_coin_info),
        seriesOutputCoinId=hx(issuance.next_series_coin.name()),seriesOutputInnerPuzzleHash=hx(curry_series(program,issuance.next_series_state).get_tree_hash()),confirmedHeight=11))
    return store,terms,issuance,purchase


async def setup(monkeypatch,tmp_path,*,lose_reply=False):
    from tests.test_voucher_refund_review import setup as prepare
    t=await prepare(monkeypatch,tmp_path,stripe=True)
    keys=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (1,2,3)]
    async def quorum(settings,claim):
        sig=AugSchemeMPL.aggregate([AugSchemeMPL.sign(keys[i],message) for message in claim.signature_messages() for i in (0,1)])
        return ValidatorQuorumResult((0,1),sig,claim.canonical_hash())
    monkeypatch.setattr(p,'collect_voucher_transition_quorum',quorum)
    async def validate(job,*,bundle,network):
        assert job=='swap_signature';consensus(SpendBundle.from_bytes(bytes(bundle)))
    monkeypatch.setattr('solslot_api.wallet_offer_worker.run_offer_job',validate)
    dispatched=[]
    async def dispatch(request,prepared):
        consensus(prepared.bundle)
        assert t.store.voucher(t.terms['termsHash'],0)['terminalExactExecution']['prepared']==prepared.to_json()
        dispatched.append((request,prepared))
        if lose_reply:raise ProtocolSubmissionError('synthetic lost handoff response',submission_attempted=True)
        return {'accepted':True}
    t.request.app.state.kos_exact_executor=SimpleNamespace(dispatch=dispatch)
    from chia.types.coin_spend import CoinSpend
    signed=sign_spends([CoinSpend.from_json_dict(t.prepared['coinSpends'][0])],[t.owner])
    body=p.CompleteVoucherRefundRequest(vaultCoinId=t.prepared['vaultCoinId'],voucherCoinId=t.prepared['voucherCoinId'],
        seriesCoinId=t.prepared['seriesCoinId'],currentTimestamp=t.prepared['currentTimestamp'],ownerAuthorization=hx(signed.aggregated_signature),
        expectedPurchaseId=t.prepared['purchaseId'],fundingReservationHash=t.prepared['reviewEvidence']['fundingEvidence']['reservationHash'])
    if lose_reply:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:await p.complete_voucher_refund(t.terms['termsHash'],0,body,t.request,t.store,t.settings)
        assert exc.value.status_code==502
    else:await p.complete_voucher_refund(t.terms['termsHash'],0,body,t.request,t.store,t.settings)
    t.execution=t.store.voucher(t.terms['termsHash'],0)['terminalExactExecution'];t.dispatched=dispatched
    t.worker=VoucherIssuanceWorker(settings=t.settings,faucet=t.request.app.state.protocol_submitter.faucet,
        coinset=t.request.app.state.coinset,presales=t.store,purchases=PaymentPurchaseStore(t.settings.payment_purchase_db_path),
        submitter=t.request.app.state.protocol_submitter,exact_executor=t.request.app.state.kos_exact_executor,
        config=VoucherIssuanceWorkerConfig(enabled=True))
    return t


@pytest.mark.asyncio
@pytest.mark.parametrize('winner',['old','new','lost_reply'])
async def test_reserved_stripe_refund_real_routes_continue_and_confirm_exact_winner(monkeypatch,tmp_path,winner):
    t=await setup(monkeypatch,tmp_path,lose_reply=winner=='lost_reply')
    try:
        series=t.store.get(t.terms['termsHash']);old=_prepared_from_json(t.execution['prepared']).bundle
        t.node.clock=t.prepared['currentTimestamp']+121;monkeypatch.setattr(recovery.time,'time',lambda:t.node.clock)
        if winner=='lost_reply':
            t.node.include(old)
            assert await t.worker._resume_stripe_terminal_execution(series,t.store.voucher(t.terms['termsHash'],0))=='STRIPE_REFUND_AUTHORIZED'
            assert len(t.dispatched)==1
        else:
            status=await t.worker._resume_stripe_terminal_execution(series,t.store.voucher(t.terms['termsHash'],0))
            assert status=='STRIPE_REFUND_SUBMITTED'
            current=t.store.voucher(t.terms['termsHash'],0)['terminalExactExecution'];new=_prepared_from_json(current['prepared']).bundle
            assert old.removals()==new.removals() and old.additions()==new.additions() and old.name()!=new.name()
            assert current['prepared']['feeMojos']==t.execution['prepared']['feeMojos']
            assert current['request']['refundContinuation'][0]==hx(old.name())
            backup=sqlite3.connect(tmp_path/'backup.sqlite');t.store._conn.backup(backup);backup.close()
            restored=p.PresaleStore(str(tmp_path/'backup.sqlite'))
            assert restored.stripe_refund_attempts(t.terms['termsHash'],0)==t.store.stripe_refund_attempts(t.terms['termsHash'],0)
            restored._conn.close()
            t.node.include(old if winner=='old' else new)
            assert await t.worker._confirm_stripe_refund_if_ready(series,t.store.voucher(t.terms['termsHash'],0))
            assert t.store.voucher(t.terms['termsHash'],0)['refundBundleId']==hx((old if winner=='old' else new).name())
        assert t.store.voucher(t.terms['termsHash'],0)['refundConfirmedHeight']==100
        # REFUNDED is the voucher's terminal chain state. The separate fiat
        # authorization remains pending until its provider receipt arrives.
        assert t.store.voucher(t.terms['termsHash'],0)['state']=='REFUNDED'
        assert t.store.pending_stripe_refund_authorizations()
    finally:t.store._conn.close()

@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['fee_missing','fee_spent','pending','fee_cap','protocol_signature','immutable_deadline','paused','stale_cas'])
async def test_stripe_continuation_never_releases_claims_on_uncertain_state(monkeypatch,tmp_path,fault):
    t=await setup(monkeypatch,tmp_path)
    try:
        series=t.store.get(t.terms['termsHash']);voucher=t.store.voucher(t.terms['termsHash'],0)
        original=deepcopy(t.execution);fee_id=original['prepared']['feeCoinId']
        t.node.clock=t.prepared['currentTimestamp']+121;monkeypatch.setattr(recovery.time,'time',lambda:t.node.clock)
        if fault=='fee_missing':t.node.records.pop(fee_id)
        if fault=='fee_spent':t.node.records[fee_id].update(spent=True,spent_block_index=100)
        if fault=='pending':t.node.pending=[{'other':'transaction'}]
        if fault=='fee_cap':
            from dataclasses import replace
            t.worker.submitter.policy=replace(t.worker.submitter.policy,maximum_mojos=99)
        if fault=='protocol_signature':original['refundProtocolSignature']='0x'+'00'*96
        if fault=='immutable_deadline':t.node.clock=t.prepared['currentTimestamp']+201
        if fault=='paused':
            def paused():raise ValueError('paused')
            t.worker.authorize_dispatch=paused
        if fault=='stale_cas':await recovery.renew_stripe_refund(t.worker,series,voucher,original)
        before=t.store.voucher(t.terms['termsHash'],0)['terminalExactExecution']
        with pytest.raises((ValueError,RuntimeError)):
            await recovery.renew_stripe_refund(t.worker,series,voucher,original)
        after=t.store.voucher(t.terms['termsHash'],0)
        assert after['terminalExactExecution']==before and after['state']=='REFUNDING'
        assert fee_id in t.store.pending_stripe_terminal_fee_coin_ids()
    finally:t.store._conn.close()


@pytest.mark.asyncio
async def test_legacy_unexpired_fee_keeps_original_aggregate_signature():
    from tests.test_stripe_refund_fee_integration import execute,fixture
    data=fixture();(document,_),executor,_=await execute(data,fee=7)
    renewed=recovery.build_continuation(document,None,data['reviewVector']['intent']['currentTimestamp']+121,
        data['reviewVector']['selected']['refundDeadline'])
    old=_prepared_from_json(document['prepared']).bundle;new=_prepared_from_json(renewed['prepared']).bundle
    assert old.aggregated_signature==new.aggregated_signature
    assert old.removals()==new.removals() and old.additions()==new.additions()
    consensus(new)

@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['recipient','amount','input','deadline','signature','purpose'])
async def test_reserved_fee_signing_exception_allows_only_same_refund_deadline(monkeypatch,tmp_path,fault):
    from chia.types.blockchain_format.program import Program
    from chia_rs import G2Element
    from solslot_api.faucet import FaucetSelectionRestricted
    t=await setup(monkeypatch,tmp_path)
    try:
        old=_prepared_from_json(t.execution['prepared']).bundle
        now=t.prepared['currentTimestamp']+121
        candidate=recovery.build_continuation(t.execution,t.worker.submitter,now,t.terms['refundDeadline'])
        fee=_prepared_from_json(candidate['prepared']).bundle.coin_spends[-1]
        conditions=list(list(Program.from_bytes(bytes(fee.solution)).as_iter())[1].rest().as_iter())
        rows=[list(c.as_iter()) for c in conditions]
        if fault=='recipient':
            row=next(r for r in rows if r[0].as_int()==51);row[1]=Program.to(bytes32(b'X'*32))
        if fault=='amount':
            row=next(r for r in rows if r[0].as_int()==51);row[2]=Program.to(row[2].as_int()-1)
        if fault=='input':
            row=next(r for r in rows if r[0].as_int()==64);row[1]=Program.to(bytes32(b'X'*32))
        if fault=='deadline':
            row=next(r for r in rows if r[0].as_int()==85);row[1]=Program.to(now+121)
        signature=G2Element.from_bytes(bytes.fromhex(t.execution['refundProtocolSignature'][2:]))
        if fault=='signature':signature=G2Element()
        if fault=='purpose':t.worker.faucet.restrict_coin_selection_to('another-operation')
        with pytest.raises(FaucetSelectionRestricted):
            t.worker.faucet.sign_refund_fee_deadline(old,signature,t.execution['prepared']['feeCoinId'],Program.to([Program.to(r) for r in rows]),now)
        assert fee.coin.name() in t.worker.faucet.reserved_coin_ids()
        with pytest.raises(FaucetSelectionRestricted):t.worker.faucet.sign_delegated_spend(fee.coin,Program.to([]))
    finally:t.store._conn.close()


@pytest.mark.asyncio
async def test_public_stripe_timestamp_variant_preserves_fee_and_reaches_fiat_authorization(monkeypatch,tmp_path):
    from solslot_api.refund_continuation import retime_native_refund
    t=await setup(monkeypatch,tmp_path,lose_reply=True)
    try:
        old=_prepared_from_json(t.execution['prepared']).bundle
        protocol=SpendBundle(old.coin_spends[:4],old.aggregated_signature)
        variant=retime_native_refund(protocol,t.execution['bindings']['vaultInputCoinId'],t.prepared['currentTimestamp']+1)
        variant=SpendBundle([*variant.coin_spends,old.coin_spends[4]],old.aggregated_signature)
        consensus(variant)
        t.node.include(variant)
        series=t.store.get(t.terms['termsHash'])
        assert await t.worker._resume_stripe_terminal_execution(series,t.store.voucher(t.terms['termsHash'],0))=='STRIPE_REFUND_AUTHORIZED'
        assert t.store.pending_stripe_refund_authorizations()
        assert t.store.stripe_refund_attempts(t.terms['termsHash'],0)==[t.execution]
        evidence=t.store.refund_settlement(t.terms['termsHash'],0)
        assert evidence['kind']=='EQUIVALENT_VAULT_TIMESTAMP'
        assert evidence['authorizationBundleId']==hx(old.name())
        assert evidence['observedCoinSpends']==[s.to_json_dict() for s in variant.coin_spends]
    finally:t.store._conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('contract',[None,'purchase-v1','refund-review-v1'])
async def test_lost_refund_handoff_refuses_another_owner_preparation(monkeypatch,tmp_path,contract):
    from fastapi import HTTPException
    t=await setup(monkeypatch,tmp_path,lose_reply=True)
    try:
        original=t.store.voucher(t.terms['termsHash'],0)
        assert original['state']=='ESCROWED' and original['terminalExactExecution']
        async def unexpected_review(**kwargs):raise AssertionError('pending refund reached new funding review')
        monkeypatch.setattr('solslot_api.voucher_refund_review.prepare_refund_review',unexpected_review)
        with pytest.raises(HTTPException) as exc:
            await p.request_voucher_refund(t.terms['termsHash'],0,t.request,t.store,t.settings,contract)
        assert exc.value.status_code==409 and 'recovery' in str(exc.value.detail)
        assert t.store.voucher(t.terms['termsHash'],0)==original
        assert original['terminalFeeCoinId'] in t.store.pending_stripe_terminal_fee_coin_ids()
    finally:t.store._conn.close()
