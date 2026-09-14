"""Offline current-voucher outcomes from a confirmed inventory snapshot.

Real SQLite, group loader, lineage loader, CLVM builders, claim signatures and
exact-execution persistence. Authority/RPC/payment/fee/executor are synthetic.
These are not public-chain outcomes or proof of presale reservation extension.
"""
import asyncio
import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import sqlite3

import httpx
import pytest
from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program, INFINITE_COST
from chia.types.coin_spend import make_spend
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.full_node.bundle_tools import simple_solution_generator
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD, lineage_proof_for_coinsol, puzzle_for_singleton,
)
from chia_rs import AugSchemeMPL, SpendBundle, MEMPOOL_MODE, run_block_generator2, get_flags_for_height_and_constants
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import native_purchases, presale_endpoints, voucher_issuance_worker as delivery
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_api.presale_endpoints import PresaleStore, VoucherIssuanceChainEvidence, VoucherSeriesPhaseChainEvidence
from solslot_api.protocol_submission import PreparedProtocolBundle, ProtocolSubmissionError
from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v3 import PurchaseKind
from solslot_puzzles.voucher_presale_v2 import series_terms_from_json, DeedAllocationCommitmentV2, allocation_root
from solslot_puzzles.voucher_presale_v2_driver import (
    VoucherSeriesStateV2, SeriesTransition, build_voucher_series_phase_spend,
    curry_series, curry_purchase_launcher,
)
from solslot_puzzles.voucher_presale_v2 import voucher_commitment_from_json
from solslot_api.vault_eligibility import ApprovedVault
from solslot_api.presale_endpoints import VoucherIssuanceEvidenceRequest
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_puzzles.voucher_presale_v2_driver import (
    curry_external_receipt, build_voucher_issuance_spends,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from tests.test_single_external_delivery_context import delivery_case, coin_record, hx, _b32
from tests.test_presale_endpoints import terms as sample_terms, create_series

NOW = 1_900_000_000


def base_case(tmp_path, monkeypatch, inventory_version=2, *, after_authorization=False):
    # A pre-existing confirmed reservation is this worker's input. Long-lived
    # snapshot coverage does not claim the missing extension orchestrator works.
    current = sample_terms(NOW)

    def presale_purchase(purchase):
        row = dict(current["deeds"][0], deedLauncherId=hx(purchase.deed_launcher_id),
                   sharePpm=purchase.share_ppm, basePriceMinor=purchase.base_amount_minor,
                   technologyFeeMinor=purchase.technology_fee_minor, grossPriceMinor=purchase.subtotal_minor)
        other = dict(current["deeds"][1], sharePpm=1_000_000-purchase.share_ppm)
        current.update(collectionWorkspaceId="local-dossier", collectionId=hx(purchase.collection_id),
            metadataRoot=hx(purchase.metadata_root), metadataAnchorId=hx(purchase.metadata_anchor_id),
            trustedProtocolTreasury=hx(purchase.protocol_treasury_puzzle_hash),
            technologyFeeBps=purchase.technology_fee_bps, deeds=[row, other])
        current["allocationRoot"] = hx(allocation_root([
            DeedAllocationCommitmentV2(bytes32.from_hexstr(r["deedIdCanon"]), r["sharePpm"],
                r["parValueMojos"], bytes32.from_hexstr(r["deedLauncherId"])) for r in current["deeds"]]))
        current["termsHash"] = hx(series_terms_from_json(current).terms_hash)
        return replace(purchase, quote_expires_at=NOW+100, purchase_kind=PurchaseKind.PRESALE,
                       presale_terms_hash=bytes32.from_hexstr(current["termsHash"]))

    case = delivery_case(tmp_path, monkeypatch, rail="base_usdc", inventory_version=inventory_version,
        purchase_transform=presale_purchase,
        reservation_expires_at=NOW+1000,
        smart_deed_inner_hash=load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash())
    clock = [NOW + (800 if after_authorization else 400)]
    monkeypatch.setattr(delivery.time, "time", lambda: clock[0])
    store_path = str(tmp_path / "presales.db")
    store = PresaleStore(store_path)
    create_series(store, current)
    program = series_terms_from_json(current)
    deposit = dict(case.operation.evidence)
    deposit["source"] = dict(deposit["source"], transactionHash=hx(_b32(43)), confirmations=12, blockTimestamp=NOW+50, blockNumber=123, logIndex=2)
    deposit["gatewayProfile"] = "ccip"
    stored = case.purchases.bind_external_message(hx(case.purchase.purchase_id), deposit)
    payer = hx(bytes32(b"\x00"*12 + bytes.fromhex(deposit["depositor"][2:])))
    evidence = VoucherIssuanceEvidenceRequest(purchaseArtifact=stored.purchase_artifact,
        globalPaymentId=deposit["globalPaymentId"], originalPayer=payer, evidenceId=f"base:{hx(_b32(43))}:2",
        confirmedHeight=123, transactionIndex=0, outputIndex=2, confirmedAt=NOW+50)
    approved = ApprovedVault(launcher_id=hx(case.purchase.vault_launcher_id),
        p2_puzzle_hash=hx(case.purchase.vault_p2_puzzle_hash), current_coin_id=hx(_b32(41)),
        identity_attest_root=hx(_b32(42)), confirmed_block_index=100,
        enrollment=SimpleNamespace(receipt=SimpleNamespace(network="testnet11")))
    store.ingest_payment(current["termsHash"], evidence, approved_vault=approved,
        issued_purchase=stored, external_escrow_contract=_b32(99), now_seconds=NOW+51)
    voucher_json = store.voucher(current["termsHash"], 0)
    commitment = voucher_commitment_from_json(voucher_json["commitment"])
    receipt_puzzle = curry_external_receipt(terms=program, voucher=commitment)
    launcher_puzzle = curry_purchase_launcher(terms=program, voucher=commitment,
        payment_puzzle_hash=receipt_puzzle.get_tree_hash(), payment_amount=1)
    launcher = Coin(_b32(70), launcher_puzzle.get_tree_hash(), uint64(2))
    initial = VoucherSeriesStateV2()
    series_coin = Coin(program.series_singleton_id,
        puzzle_for_singleton(program.series_singleton_id, curry_series(program, initial)).get_tree_hash(), uint64(1))
    issuance = build_voucher_issuance_spends(terms=program, state=initial, series_coin=series_coin,
        series_lineage_proof=LineageProof(_b32(71), None, uint64(1)), voucher=commitment,
        payment_puzzle=receipt_puzzle, payment_amount=1, purchase_launcher_coin=launcher, signer_indices=(0, 1))
    store.record_issuance_funding(current["termsHash"], 0, funding_bundle_id=hx(_b32(72)),
        purchase_launcher_coin_id=hx(launcher.name()), purchase_launcher_puzzle_hash=hx(launcher.puzzle_hash))
    store.record_issuance_submission(current["termsHash"], 0, issuance_bundle_id=hx(_b32(73)),
        voucher_launcher_id=hx(issuance.voucher_launcher_id), voucher_output_coin_id=hx(issuance.voucher_coin.name()),
        payment_commitment_coin_id=hx(issuance.payment_coin.name()), series_input_coin_id=hx(series_coin.name()),
        series_output_coin_id=hx(issuance.next_series_coin.name()), signer_indices=(0, 1))
    store.confirm_issuance(current["termsHash"], 0, VoucherIssuanceChainEvidence(
        evidenceId="local-voucher-issuance", spendBundleId=hx(_b32(73)), purchaseLauncherCoinId=hx(launcher.name()),
        voucherLauncherId=hx(issuance.voucher_launcher_id), voucherOutputCoinId=hx(issuance.voucher_coin.name()),
        paymentCommitmentCoinId=hx(issuance.payment_coin.name()), seriesInputCoinId=hx(series_coin.name()),
        seriesInputParentCoinId=hx(series_coin.parent_coin_info), seriesOutputCoinId=hx(issuance.next_series_coin.name()),
        seriesOutputInnerPuzzleHash=hx(curry_series(program, issuance.next_series_state).get_tree_hash()), confirmedHeight=200))
    phase = build_voucher_series_phase_spend(terms=program, state=issuance.next_series_state,
        series_coin=issuance.next_series_coin, series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
        transition=SeriesTransition.LAUNCH, launch_anchor=program.sale_close, signer_indices=(0, 1))
    next_inner = curry_series(program, phase.next_series_state)
    store.record_phase_submission(current["termsHash"], target_state="LIVE", spend_bundle_id=hx(_b32(74)),
        series_input_coin_id=hx(issuance.next_series_coin.name()), series_output_coin_id=hx(phase.next_series_coin.name()),
        series_output_inner_puzzle_hash=hx(next_inner.get_tree_hash()), launch_anchor=program.sale_close,
        governance_execution_ids=[hx(_b32(75))])
    store.confirm_phase_transition(current["termsHash"], VoucherSeriesPhaseChainEvidence(
        evidenceId="local-voucher-live", spendBundleId=hx(_b32(74)), targetState="LIVE",
        seriesInputCoinId=hx(issuance.next_series_coin.name()),
        seriesInputParentCoinId=hx(issuance.next_series_coin.parent_coin_info),
        seriesOutputCoinId=hx(phase.next_series_coin.name()), seriesOutputInnerPuzzleHash=hx(next_inner.get_tree_hash()),
        launchAnchor=program.sale_close, confirmedHeight=201))
    records = case.records
    parents = [phase.series_spend, issuance.voucher_launcher_spend]
    for spend, child, height in ((parents[0], phase.next_series_coin, 201),
                                  (parents[1], issuance.voucher_coin, 200)):
        records[hx(spend.coin.name())] = coin_record(spend.coin, confirmed=199, spent=height)
        records[hx(child.name())] = coin_record(child, confirmed=height)
    records[hx(issuance.payment_coin.name())] = coin_record(issuance.payment_coin, confirmed=200)

    async def get_spend(coin_id, height):
        return next(s.to_json_dict() for s in parents if hx(s.coin.name()) == coin_id)

    case.worker.provider.get_puzzle_and_solution = get_spend
    monkeypatch.setattr(presale_endpoints, "get_presale_store", lambda _: PresaleStore(store_path))
    monkeypatch.setattr(delivery, "load_signed_public_artifact", lambda _: case.genesis)
    claims, dispatched, prepared_bundles = [], [], []

    async def quorum(_settings, claim):
        claims.append(claim)
        # Local signatures over the actual production claim messages. This is
        # not a claim that remote validator evidence collection was exercised.
        signatures = [AugSchemeMPL.sign(case.keys[i], message)
                      for message in claim.signature_messages() for i in (0, 1)]
        return SimpleNamespace(signer_indices=(0, 1), aggregated_signature=AugSchemeMPL.aggregate(signatures))

    monkeypatch.setattr(delivery, "collect_voucher_transition_quorum", quorum)
    fail = [False]

    async def push(raw):
        bundle = SpendBundle.from_json_dict(raw)
        persisted = PresaleStore(store_path).pending_voucher_execution(current["termsHash"], 0)
        assert persisted["spendBundle"] == raw
        dispatched.append(bundle)
        if fail[0]:
            raise RuntimeError("local provider response lost")
        return {"success": True, "status": "SUCCESS"}

    case.worker.provider.push_tx = push
    worker = delivery.VoucherIssuanceWorker(settings=case.worker.settings, faucet=case.worker.faucet,
        coinset=case.worker.provider, presales=store, purchases=PaymentPurchaseStore(case.purchases.path),
        config=delivery.VoucherIssuanceWorkerConfig(enabled=True))
    return SimpleNamespace(**vars(case), voucher_worker=worker, presales=store, presale_path=store_path,
        current=current, clock=clock, dispatched=dispatched, prepared_bundles=prepared_bundles,
        voucher_claims=claims, fail=fail, issuance=issuance)


async def submit(case):
    return await case.voucher_worker._submit_base_redemption(
        case.presales.get(case.current["termsHash"]), case.presales.voucher(case.current["termsHash"], 0))


def prove_bundle(case):
    (bundle,) = case.dispatched
    pairs = []
    for spend in bundle.coin_spends:
        assert Program.from_bytes(bytes(spend.puzzle_reveal)).get_tree_hash() == spend.coin.puzzle_hash
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, INFINITE_COST)
        pairs.extend(pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA["testnet11"]))
    assert AugSchemeMPL.aggregate_verify([pk for pk, _ in pairs], [m for _, m in pairs], bundle.aggregated_signature)
    destination = SINGLETON_MOD.curry(case.deed_struct, puzzle_for_p2_vault(case.purchase.vault_launcher_id)).get_tree_hash()
    voucher = case.presales.voucher(case.current["termsHash"], 0)
    outputs = bundle.additions()
    assert len([c for c in outputs if c.puzzle_hash == destination and c.amount == 1]) == 1
    assert hx(next(c for c in outputs if c.puzzle_hash == destination).name()) == voucher["redemptionDeedOutputCoinId"]
    assert sum(c.amount for c in bundle.removals()) - sum(c.amount for c in outputs) == 0
    error, message, conditions = consensus(bundle)
    assert error is None, (error, message)
    assert conditions.seconds_absolute <= case.clock[0] < conditions.before_seconds_absolute
    return bundle


def consensus(bundle):
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=AGG_SIG_ME_DATA["testnet11"])
    flags = MEMPOOL_MODE | get_flags_for_height_and_constants(10_000_000, constants)
    return run_block_generator2(bytes(simple_solution_generator(bundle).program), [],
        11_000_000_000, flags, bundle.aggregated_signature, None, constants)


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory_version", [1, 2])
@pytest.mark.parametrize("after_authorization", [False, True])
async def test_current_base_voucher_delivers_from_real_inventory(tmp_path, monkeypatch, inventory_version, after_authorization):
    case = base_case(tmp_path, monkeypatch, inventory_version, after_authorization=after_authorization)
    assert await submit(case)
    prove_bundle(case)
    assert len(case.voucher_claims) == 1
    assert case.voucher_claims[0].deed_coin_id == hx(case.reserved.name())
    assert case.voucher_claims[0].reservation_expires_at == NOW+1000


@pytest.mark.asyncio
async def test_expired_base_reservation_never_requests_signatures(tmp_path, monkeypatch):
    case = base_case(tmp_path, monkeypatch)
    case.clock[0] = NOW+1001
    with pytest.raises((HTTPException, RuntimeError)):
        await submit(case)
    assert case.voucher_claims == case.dispatched == []


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory_version", [1, 2])
async def test_base_restart_confirms_exact_delivery_and_authorizes_settlement(tmp_path, monkeypatch, inventory_version):
    from tests.test_current_stripe_voucher_delivery import confirm_records
    case = base_case(tmp_path, monkeypatch, inventory_version)
    case.fail[0] = True
    with pytest.raises(RuntimeError, match="response lost"):
        await submit(case)
    first = case.dispatched[0]
    store = case.voucher_worker.presales = PresaleStore(case.presale_path)
    case.voucher_worker.purchases = PaymentPurchaseStore(case.purchases.path)
    case.fail[0] = False
    case.clock[0] = NOW + 200_000
    series = store.get(case.current["termsHash"])
    voucher = store.voucher(case.current["termsHash"], 0)
    result = await case.voucher_worker._resume_retained_execution(series, voucher,
        store.pending_voucher_execution(case.current["termsHash"], 0))
    assert result["status"] == "BASE_REDEMPTION_CONFIRMING"
    assert bytes(case.dispatched[1]) == bytes(first) and len(case.voucher_claims) == 1
    confirm_records(case, first)
    confirmed = await case.voucher_worker.reconcile_once()
    assert confirmed[0]["status"] == "BASE_DELIVERY_AUTHORIZED"
    saved = store.voucher(case.current["termsHash"], 0)
    assert saved["state"] == "REDEEMED" and saved["redemptionConfirmedHeight"] == 220
    assert store.pending_voucher_execution(case.current["termsHash"], 0) is None
    (settlement,) = store.pending_base_settlement_authorizations()
    authorization = settlement["authorization"]
    assert authorization["outcome"] == "DELIVERED"
    assert authorization["purchaseId"] == hx(case.purchase.purchase_id)
    assert authorization["chia"]["deedInputCoinId"] == hx(case.reserved.name())
    assert authorization["chia"]["deedOutputCoinId"] == saved["redemptionDeedOutputCoinId"]
    assert authorization["payment"]["principal"] == case.purchase.rail_amount
    canonical = json.dumps(authorization, sort_keys=True, separators=(",", ":")).encode()
    assert settlement["authorizationId"] == "0x" + hashlib.sha256(canonical).hexdigest()
    evidence = presale_endpoints.BaseSettlementRelayEvidenceRequest(
        warpMessageId=hx(_b32(133)), baseTransactionHash=hx(_b32(134)),
        confirmedBlockNumber=123456, confirmedAt=NOW + 200_000,
    )
    acknowledged = store.record_base_settlement_relay_evidence(settlement["authorizationId"], evidence)
    assert acknowledged["state"] == "RELAYED"
    assert store.pending_base_settlement_authorizations() == []
    assert store.record_base_settlement_relay_evidence(settlement["authorizationId"], evidence) == acknowledged
    with pytest.raises(ValueError, match="different relay evidence"):
        store.record_base_settlement_relay_evidence(settlement["authorizationId"],
            evidence.model_copy(update={"warp_message_id": hx(_b32(135))}))
    assert await case.voucher_worker.reconcile_once() == []


@pytest.mark.asyncio
async def test_current_base_expired_refund_preserves_original_purchase(tmp_path, monkeypatch):
    case = base_case(tmp_path, monkeypatch)
    case.clock[0] = NOW + 200_000
    before = case.purchases.get(hx(case.purchase.purchase_id)).purchase_artifact
    await case.voucher_worker._submit_base_expired_refund(
        case.presales.get(case.current["termsHash"]), case.presales.voucher(case.current["termsHash"], 0))
    bundle = case.dispatched[0]
    error, message, _ = consensus(bundle)
    assert error is None, (error, message)
    assert case.purchases.get(hx(case.purchase.purchase_id)).purchase_artifact == before
    assert case.voucher_claims[0].reservation_expires_at is None
    assert not any(c.name() == case.reserved.name() for c in bundle.removals())


@pytest.mark.asyncio
@pytest.mark.parametrize('rail',['base_usdc','evm_usdc'])
async def test_finalization_and_callback_keep_base_presale_out_of_direct_delivery(tmp_path, monkeypatch, rail):
    from solslot_api import protocol_artifacts as artifacts, vault_eligibility
    c = base_case(tmp_path, monkeypatch)
    stored = c.purchases.get(hx(c.purchase.purchase_id))
    monkeypatch.setattr(artifacts, '_artifact_rejection_reasons', lambda *a,**k:[])
    monkeypatch.setattr(artifacts, '_payment_evidence_rejection_reasons', lambda *a,**k:[])
    monkeypatch.setattr(artifacts, 'load_omnichain_evidence', lambda *a,**k:SimpleNamespace(return_puzzle_hash=hx(_b32(48))))
    monkeypatch.setattr(presale_endpoints, '_external_escrow_contract', lambda *a:_b32(99))
    monkeypatch.setattr(vault_eligibility, 'require_current_approved_vault', lambda *a:ApprovedVault(
        launcher_id=hx(c.purchase.vault_launcher_id), p2_puzzle_hash=hx(c.purchase.vault_p2_puzzle_hash),
        current_coin_id=hx(_b32(41)), identity_attest_root=hx(c.purchase.zkpassport_root),
        confirmed_block_index=100, enrollment=SimpleNamespace(receipt=SimpleNamespace(network='testnet11'))))
    def no_direct(*args): raise AssertionError('a paid presale cannot queue direct delivery')
    monkeypatch.setattr('solslot_api.stripe_delivery_store.get_stripe_delivery_store', no_direct)
    event = artifacts._ingest_verified_presale_payment(
        SimpleNamespace(escrow_message=SimpleNamespace(purchase_id=stored.purchase_id)),
        SimpleNamespace(purchase_artifact=stored.purchase_artifact), c.worker.settings)
    assert event['voucher']['state'] == 'REDEEMING'
    assert event['voucher']['purchaseId'] == stored.purchase_id
    outer = {'protocol':{'purchaseIntentId':stored.purchase_intent_id,'rail':rail,'expiresAt':NOW+100},
        'purchaseArtifactV3':stored.purchase_artifact}
    result = await artifacts.verify_purchase_finalization(
        artifacts.VerifyPurchaseFinalizationRequest(artifact=outer, artifact_hash=stored.offer_artifact_hash,
            rail=rail, purchase_intent_id=stored.purchase_intent_id,
            payment_evidence={'global_payment_id':stored.external_message['globalPaymentId']}, now=NOW+50),
        c.worker.settings)
    assert result.verified, result.reasons
    assert result.delivery_state == 'REDEEMING'
    assert c.presales.voucher(c.current['termsHash'],0)['purchaseId'] == stored.purchase_id
