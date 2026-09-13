"""Offline current-voucher outcomes from a confirmed inventory snapshot.

Real SQLite, group loader, lineage loader, CLVM builders, claim signatures and
exact-execution persistence. Authority/RPC/payment/fee/executor are synthetic.
These are not public-chain outcomes or proof of presale reservation extension.
"""
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
from solslot_puzzles.voucher_presale_v3 import voucher_commitment_v3_from_json, voucher_commitment_v3_to_json
from solslot_puzzles.voucher_presale_v3_driver import (
    curry_stripe_voucher_receipt, build_stripe_voucher_issuance_spends,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from tests.test_single_external_delivery_context import delivery_case, coin_record, hx, _b32
from tests.test_presale_endpoints import terms as sample_terms, create_series

NOW = 1_900_000_000


def voucher_case(tmp_path, monkeypatch, inventory_version=2, *, after_authorization=False):
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

    case = delivery_case(tmp_path, monkeypatch, inventory_version=inventory_version,
        purchase_transform=presale_purchase,
        reservation_expires_at=NOW+1000,
        smart_deed_inner_hash=load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash())
    clock = [NOW + (800 if after_authorization else 400)]
    monkeypatch.setattr(delivery.time, "time", lambda: clock[0])
    store_path = str(tmp_path / "presales.db")
    store = PresaleStore(store_path)
    create_series(store, current)
    program = series_terms_from_json(current)
    stored = case.purchases.get(hx(case.purchase.purchase_id))
    store.ingest_stripe_payment(current["termsHash"], artifact=case.purchase,
        receipt=case.receipt, evidence_id=case.receipt.evidence.event_id, issued_purchase=stored)
    voucher_json = store.voucher(current["termsHash"], 0)
    commitment = voucher_commitment_v3_from_json(voucher_json["commitment"])
    receipt_puzzle = curry_stripe_voucher_receipt(terms=program, voucher=commitment, artifact=case.purchase)
    launcher_puzzle = curry_purchase_launcher(terms=program, voucher=commitment,
        payment_puzzle_hash=receipt_puzzle.get_tree_hash(), payment_amount=1)
    launcher = Coin(_b32(70), launcher_puzzle.get_tree_hash(), uint64(2))
    initial = VoucherSeriesStateV2()
    series_coin = Coin(program.series_singleton_id,
        puzzle_for_singleton(program.series_singleton_id, curry_series(program, initial)).get_tree_hash(), uint64(1))
    issuance = build_stripe_voucher_issuance_spends(terms=program, state=initial, series_coin=series_coin,
        series_lineage_proof=LineageProof(_b32(71), None, uint64(1)), voucher=commitment,
        artifact=case.purchase, receipt=case.receipt, expected_original_payer=commitment.original_payer,
        smart_deed_inner_hash=case.terms.smart_deed_inner_hash, purchase_launcher_coin=launcher, signer_indices=(0, 1))
    store.record_issuance_funding(current["termsHash"], 0, funding_bundle_id=hx(_b32(72)),
        purchase_launcher_coin_id=hx(launcher.name()), purchase_launcher_puzzle_hash=hx(launcher.puzzle_hash))
    store.record_issuance_submission(current["termsHash"], 0, issuance_bundle_id=hx(_b32(73)),
        voucher_launcher_id=hx(issuance.voucher_launcher_id), voucher_output_coin_id=hx(issuance.voucher_coin.name()),
        payment_commitment_coin_id=hx(issuance.receipt_coin.name()), series_input_coin_id=hx(series_coin.name()),
        series_output_coin_id=hx(issuance.next_series_coin.name()), signer_indices=(0, 1))
    store.confirm_issuance(current["termsHash"], 0, VoucherIssuanceChainEvidence(
        evidenceId="local-voucher-issuance", spendBundleId=hx(_b32(73)), purchaseLauncherCoinId=hx(launcher.name()),
        voucherLauncherId=hx(issuance.voucher_launcher_id), voucherOutputCoinId=hx(issuance.voucher_coin.name()),
        paymentCommitmentCoinId=hx(issuance.receipt_coin.name()), seriesInputCoinId=hx(series_coin.name()),
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
    records[hx(issuance.receipt_coin.name())] = coin_record(issuance.receipt_coin, confirmed=200)

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

    async def dispatch(request, prepared):
        persisted = PresaleStore(store_path).voucher(current["termsHash"], 0)["terminalExactExecution"]
        assert persisted["prepared"]["spendBundleId"] == hx(prepared.bundle.name())
        dispatched.append(prepared.bundle)
        if fail[0]:
            raise ProtocolSubmissionError("local executor response lost", submission_attempted=True)
        return {"accepted": True}

    async def prepare_and_dispatch(raw, callback):
        protocol = SpendBundle.from_json_dict(raw)
        fee_puzzle = Program.to((1, [[52, 3]]))
        fee_coin = Coin(_b32(80), fee_puzzle.get_tree_hash(), uint64(3))
        bundle = SpendBundle([*protocol.coin_spends, make_spend(fee_coin, fee_puzzle, Program.to([]))], protocol.aggregated_signature)
        prepared_bundles.append(bundle)
        prepared = PreparedProtocolBundle(bundle=bundle, fee_mojos=3, fee_coin_id=hx(fee_coin.name()))
        await callback(prepared)
        return {"spendBundleId": hx(bundle.name())}

    worker = delivery.VoucherIssuanceWorker(settings=case.worker.settings, faucet=case.worker.faucet,
        coinset=case.worker.provider, presales=store, purchases=PaymentPurchaseStore(case.purchases.path),
        submitter=SimpleNamespace(prepare_and_dispatch=prepare_and_dispatch),
        exact_executor=SimpleNamespace(dispatch=dispatch), config=delivery.VoucherIssuanceWorkerConfig(enabled=True))
    return SimpleNamespace(**vars(case), voucher_worker=worker, presales=store, presale_path=store_path,
        current=current, clock=clock, dispatched=dispatched, prepared_bundles=prepared_bundles,
        voucher_claims=claims, fail=fail, issuance=issuance)


async def submit(case):
    return await case.voucher_worker._submit_stripe_redemption(
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
    assert sum(c.amount for c in bundle.removals()) - sum(c.amount for c in outputs) == 3
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
async def test_current_stripe_voucher_delivers_from_real_inventory(tmp_path, monkeypatch, inventory_version, after_authorization):
    case = voucher_case(tmp_path, monkeypatch, inventory_version, after_authorization=after_authorization)
    assert await submit(case)
    prove_bundle(case)
    assert len(case.voucher_claims) == 1
    assert case.voucher_claims[0].deed_coin_id == hx(case.reserved.name())


def confirm_records(case, bundle):
    for coin in bundle.removals():
        case.records[hx(coin.name())] = coin_record(coin, confirmed=200, spent=220)
    # Includes offer intermediates; consumed additions are never reported unspent.
    removed = {coin.name() for coin in bundle.removals()}
    for coin in bundle.additions():
        case.records[hx(coin.name())] = coin_record(coin, confirmed=220, spent=220 if coin.name() in removed else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory_version", [1, 2])
async def test_restart_keeps_exact_signed_voucher_and_confirms_after_deadline(tmp_path, monkeypatch, inventory_version):
    case = voucher_case(tmp_path, monkeypatch, inventory_version)
    case.fail[0] = True
    with pytest.raises(ProtocolSubmissionError, match="response lost"):
        await submit(case)
    first = case.dispatched[0]
    case.voucher_worker.presales = PresaleStore(case.presale_path)
    case.voucher_worker.purchases = PaymentPurchaseStore(case.purchases.path)
    case.fail[0] = False
    case.clock[0] = NOW + 200_000  # read/retry does not authorize another purchase
    series = case.voucher_worker.presales.get(case.current["termsHash"])
    voucher = case.voucher_worker.presales.voucher(case.current["termsHash"], 0)
    assert await case.voucher_worker._resume_stripe_terminal_execution(series, voucher) == "STRIPE_REDEMPTION_SUBMITTED"
    assert len(case.prepared_bundles) == len(case.voucher_claims) == 1
    assert len(case.dispatched) == 2 and bytes(case.dispatched[1]) == bytes(first)
    pending = await case.voucher_worker.reconcile_once()
    assert pending[0]["status"] == "STRIPE_REDEMPTION_CONFIRMING"
    confirm_records(case, first)
    confirmed = await case.voucher_worker.reconcile_once()
    assert confirmed == [{"termsHash": case.current["termsHash"], "serial": 0, "status": "STRIPE_DEED_DELIVERED"}]
    saved = PresaleStore(case.presale_path).voucher(case.current["termsHash"], 0)
    assert saved["state"] == "REDEEMED" and saved["redemptionConfirmedHeight"] == 220
    assert saved["deliveryOutputCoinId"] == saved["redemptionDeedOutputCoinId"]
    assert await case.voucher_worker.reconcile_once() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_executor", [False, True])
async def test_confirmed_voucher_recovers_while_executor_stays_unavailable(tmp_path, monkeypatch, missing_executor):
    case = voucher_case(tmp_path, monkeypatch)
    case.fail[0] = True
    with pytest.raises(ProtocolSubmissionError, match="response lost"):
        await submit(case)
    confirm_records(case, case.dispatched[0])
    case.voucher_worker.presales = PresaleStore(case.presale_path)
    case.voucher_worker.purchases = PaymentPurchaseStore(case.purchases.path)
    if missing_executor:
        case.voucher_worker.exact_executor = None
    case.clock[0] = NOW + 200_000
    result = await case.voucher_worker.reconcile_once()
    assert result == [{"termsHash": case.current["termsHash"], "serial": 0, "status": "STRIPE_DEED_DELIVERED"}]
    assert len(case.dispatched) == len(case.prepared_bundles) == len(case.voucher_claims) == 1
    assert case.voucher_worker.presales.voucher(case.current["termsHash"], 0)["state"] == "REDEEMED"
    assert await case.voucher_worker.reconcile_once() == []


@pytest.mark.asyncio
async def test_node_outage_preserves_exact_executor_retry(tmp_path, monkeypatch):
    case = voucher_case(tmp_path, monkeypatch)
    case.fail[0] = True
    with pytest.raises(ProtocolSubmissionError, match="response lost"):
        await submit(case)
    async def unavailable(_coin_id):
        raise httpx.ConnectError("local node unavailable")
    monkeypatch.setattr(case.worker.provider, "get_coin_record_by_name", unavailable)
    case.fail[0] = False
    result = await case.voucher_worker._resume_stripe_terminal_execution(
        case.presales.get(case.current["termsHash"]), case.presales.voucher(case.current["termsHash"], 0))
    assert result == "STRIPE_REDEMPTION_SUBMITTED"
    assert len(case.dispatched) == 2 and bytes(case.dispatched[0]) == bytes(case.dispatched[1])
    assert len(case.prepared_bundles) == len(case.voucher_claims) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe", ["partial", "non_atomic"])
async def test_recovery_does_not_record_submission_from_incomplete_chain_evidence(tmp_path, monkeypatch, unsafe):
    case = voucher_case(tmp_path, monkeypatch)
    case.fail[0] = True
    with pytest.raises(ProtocolSubmissionError, match="response lost"):
        await submit(case)
    confirm_records(case, case.dispatched[0])
    role = case.presales.voucher(case.current["termsHash"], 0)["terminalExactExecution"]["outputRoles"]["deed"]
    if unsafe == "partial":
        case.records.pop(role)
    else:
        case.records[role]["confirmed_block_index"] = 221
    await case.voucher_worker.reconcile_once()
    saved = case.presales.voucher(case.current["termsHash"], 0)
    assert saved["state"] == "REDEEMING" and saved["redemptionBundleId"] is None
    assert case.presales.get(case.current["termsHash"])["chainState"]["redeemedCount"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["missing_item", "unconfirmed", "wrong_coin", "wrong_puzzle", "spent", "expired"])
async def test_voucher_bad_inventory_never_reaches_quorum_or_dispatch(tmp_path, monkeypatch, bad):
    case = voucher_case(tmp_path, monkeypatch)
    with sqlite3.connect(case.purchases.path) as db:
        if bad == "missing_item":
            db.execute("DELETE FROM payment_purchase_inventory_items")
        elif bad in {"unconfirmed", "wrong_coin", "wrong_puzzle"}:
            column, value = {"unconfirmed": ("state", "PREPARED"),
                             "wrong_coin": ("reserved_coin_id", hx(_b32(95))),
                             "wrong_puzzle": ("reserved_puzzle_hash", hx(_b32(96)))}[bad]
            db.execute(f"UPDATE payment_purchase_inventory_items SET {column}=?", (value,))
    if bad == "spent":
        case.records[hx(case.reserved.name())] = coin_record(case.reserved, spent=210)
    if bad == "expired":
        case.clock[0] = NOW + 1001
    with pytest.raises((HTTPException, RuntimeError, ValueError)):
        await submit(case)
    assert case.voucher_claims == case.dispatched == []


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["missing_execution", "bundle_id", "output_role", "wrong_did", "wrong_receipt", "not_atomic", "wrong_destination", "wrong_input"])
async def test_changed_confirmation_evidence_never_marks_redeemed(tmp_path, monkeypatch, bad):
    case = voucher_case(tmp_path, monkeypatch)
    assert await submit(case)
    bundle = case.dispatched[0]
    confirm_records(case, bundle)
    series = case.presales.get(case.current["termsHash"])
    voucher = deepcopy(case.presales.voucher(case.current["termsHash"], 0))
    if bad == "missing_execution":
        voucher.pop("terminalExactExecution")
    elif bad == "bundle_id":
        voucher["redemptionBundleId"] = hx(_b32(90))
    elif bad == "output_role":
        roles = voucher["terminalExactExecution"]["outputRoles"]
        roles["deed"], roles["coordination"] = roles["coordination"], roles["deed"]
    elif bad == "wrong_did":
        case.genesis["launcherIds"]["did"] = hx(_b32(91))
    elif bad == "wrong_receipt":
        voucher["externalSettlementEvidenceHash"] = hx(_b32(92))
    elif bad == "not_atomic":
        case.records[voucher["redemptionDeedOutputCoinId"]]["confirmed_block_index"] = 221
    elif bad == "wrong_destination":
        wrong = Coin(_b32(93), _b32(94), uint64(1))
        voucher["redemptionDeedOutputCoinId"] = hx(wrong.name())
        case.records[hx(wrong.name())] = coin_record(wrong, confirmed=220)
    elif bad == "wrong_input":
        wrong = Coin(_b32(93), case.reserved.puzzle_hash, uint64(1))
        voucher["redemptionDeedInputCoinId"] = hx(wrong.name())
        case.records[hx(wrong.name())] = coin_record(wrong, confirmed=200, spent=220)
    with pytest.raises((RuntimeError, ValueError)):
        await case.voucher_worker._confirm_redemption_if_ready(series, voucher, external_rail="STRIPE_USD")
    assert case.presales.voucher(case.current["termsHash"], 0)["state"] == "REDEEMING"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [(18, 0), (19, bytes32.zeros), (21, 1), (22, _b32(98)), (23, _b32(99))])
async def test_raw_v5_mode_and_paid_transition_mutations_fail_consensus(tmp_path, monkeypatch, field, value):
    case = voucher_case(tmp_path, monkeypatch)
    assert await submit(case)
    bundle = prove_bundle(case)
    spends = list(bundle.coin_spends)
    index = next(i for i, spend in enumerate(spends) if spend.coin == case.reserved)
    spend = spends[index]
    raw = Program.from_bytes(bytes(spend.solution)).as_python()
    raw[2][field] = value
    spends[index] = make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(raw))
    altered = SpendBundle(spends, bundle.aggregated_signature)
    error, _, result = consensus(altered)
    assert error is not None and result is None


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory_version", [1, 2])
async def test_direct_artifact_cannot_be_relabelled_as_voucher_in_raw_clvm(tmp_path, monkeypatch, inventory_version):
    case = delivery_case(tmp_path, monkeypatch, inventory_version=inventory_version)
    prepared = await case.worker._prepare_delivery(case.operation)
    bundle = SpendBundle.from_json_dict(prepared.delivery_bundle)
    spend = next(s for s in bundle.coin_spends if s.coin == case.reserved)
    puzzle = Program.from_bytes(bytes(spend.puzzle_reveal))
    puzzle.run_with_cost(INFINITE_COST, Program.from_bytes(bytes(spend.solution)))
    raw = Program.from_bytes(bytes(spend.solution)).as_python()
    raw[2][21] = 2  # VOUCHER, bypassing every Python offer-builder check
    raw[2][22], raw[2][23] = _b32(98), _b32(99)
    with pytest.raises(ValueError):
        puzzle.run_with_cost(INFINITE_COST, Program.to(raw))


def test_presale_reservation_requires_timely_signed_extension(tmp_path, monkeypatch):
    from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError
    from solslot_puzzles.stripe_settlement_v1_driver import (
        InventoryReservationV1, build_inventory_reservation_spend, build_inventory_extension_spend,
    )
    case = voucher_case(tmp_path, monkeypatch, inventory_version=2)
    initial = InventoryReservationV1(case.purchase, case.purchase.quote_expires_at)
    args = dict(available_coin=case.available, deed_singleton_struct=case.deed_struct,
                lineage_proof=LineageProof(_b32(22), amount=uint64(1)),
                signer_indices=(0, 1), terms=case.terms)
    with pytest.raises(PaymentArtifactError, match="initial reservation cannot outlive"):
        build_inventory_reservation_spend(**args, reservation=replace(initial, expires_at=NOW+1000))
    reserved = build_inventory_reservation_spend(**args, reservation=initial)
    raw = Program.from_bytes(bytes(reserved.spend.solution)).as_python()
    raw[2][20] = NOW+1000
    with pytest.raises(ValueError):
        Program.from_bytes(bytes(reserved.spend.puzzle_reveal)).run_with_cost(INFINITE_COST, Program.to(raw))
    extension = build_inventory_extension_spend(reserved_coin=reserved.reserved_coin,
        deed_singleton_struct=case.deed_struct, lineage_proof=lineage_proof_for_coinsol(reserved.spend),
        reservation=initial, next_expires_at=NOW+1000, signer_indices=(0, 1), terms=case.terms)
    for spend in (reserved.spend, extension.spend):
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, INFINITE_COST)
        pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA["testnet11"])
        signatures = [AugSchemeMPL.sign(next(k for k in case.keys if k.get_g1() == pk), message) for pk, message in pairs]
        bundle = SpendBundle([spend], AugSchemeMPL.aggregate(signatures))
        error, message, checked = consensus(bundle)
        assert error is None, (error, message)
        assert checked.before_seconds_absolute == initial.expires_at
        assert NOW+90 < checked.before_seconds_absolute < case.clock[0]
    assert extension.next_coin.parent_coin_info == reserved.reserved_coin.name()
    assert extension.next_coin.puzzle_hash == case.reserved.puzzle_hash
    assert extension.next_coin != case.reserved  # persisted successor/lineage must change


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["empty", "many", "batch", "different_purchase"])
async def test_single_voucher_rejects_unsupported_context_shapes(tmp_path, monkeypatch, shape):
    case = voucher_case(tmp_path, monkeypatch)
    group = await native_purchases._load_context_group(case.worker.settings, case.worker.provider,
        hx(case.purchase.purchase_id), require_live=False, allowed_rails=(case.purchase.rail,))
    context = group.contexts[0]
    contexts = {"empty": (), "many": (context, context), "batch": (context,),
        "different_purchase": (replace(context, purchase=replace(case.purchase, authorization_nonce=_b32(95))),)}[shape]
    async def unsupported(*_args, **_kwargs):
        return SimpleNamespace(batch=object() if shape == "batch" else None, contexts=contexts)
    monkeypatch.setattr(delivery, "_load_context_group", unsupported)
    with pytest.raises(RuntimeError, match="single canonical reservation"):
        await submit(case)
    assert case.voucher_claims == case.dispatched == []


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["purchase_artifact_hash", "deed_launcher_id", "smart_deed_inner_hash"])
async def test_paid_voucher_mismatch_never_requests_signatures(tmp_path, monkeypatch, field):
    case = voucher_case(tmp_path, monkeypatch)
    voucher = deepcopy(case.presales.voucher(case.current["termsHash"], 0))
    commitment = voucher_commitment_v3_from_json(voucher["commitment"])
    voucher["commitment"] = voucher_commitment_v3_to_json(replace(commitment, **{field: _b32(95)}))
    with pytest.raises(RuntimeError, match="paid commitments"):
        await case.voucher_worker._submit_stripe_redemption(case.presales.get(case.current["termsHash"]), voucher)
    assert case.voucher_claims == case.dispatched == []
