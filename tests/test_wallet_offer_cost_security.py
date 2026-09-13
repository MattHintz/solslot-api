"""Bounded synthetic regressions; no signing service or network writes."""
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.util.bech32m import bech32_encode, convertbits
from chia.wallet.util.puzzle_compression import compress_object_with_puzzles
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64


def encode_bundle(bundle, *, version=6):
    encoded = compress_object_with_puzzles(bytes(bundle), version)
    return bech32_encode("offer", convertbits(encoded, 8, 5))


def extra_input_bundle():
    puzzle = Program.to((1, []))
    return WalletSpendBundle([
        make_spend(Coin(bytes32(bytes([seed]) * 32), puzzle.get_tree_hash(), uint64(100)),
                   puzzle, Program.to([]))
        for seed in (11, 12)
    ], G2Element())


@pytest.mark.asyncio
async def test_native_completion_rejects_multiple_inputs_before_evaluation(monkeypatch):
    import solslot_api.native_purchases as native
    import chia.wallet.trading.offer as offer_module
    from solslot_api.config import Settings
    from solslot_puzzles.payment_artifacts_v2 import PaymentRail
    evaluations = []
    original = offer_module.compute_spend_hints_and_additions
    def observed(spend, **kwargs):
        evaluations.append(spend.coin.name())
        return original(spend, **kwargs)
    monkeypatch.setattr(offer_module, "compute_spend_hints_and_additions", observed)
    for name in ("require_minting_writes", "require_operation_gate", "_require_server_to_server_token"):
        monkeypatch.setattr(native, name, lambda *a, **k: None)
    async def context(*args):
        return SimpleNamespace(batch=None, quantity=1, contexts=[
            SimpleNamespace(reservation=object(), purchase=SimpleNamespace(
                rail=PaymentRail.CHIA_XCH, rail_asset_id=bytes32.zeros,
                deed_launcher_id=bytes32(b"d" * 32)),
                terms=None, deed_struct=None)
        ])
    monkeypatch.setattr(native, "_load_context_group", context)
    body = native.CompleteNativePurchaseRequest(
        purchaseId="0x" + "aa" * 32,
        buyerOffer=encode_bundle(extra_input_bundle()),
        aggregatedSignature="0x" + bytes(G2Element()).hex(),
    )
    try:
        await native.complete_native_purchase(
            body, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=None))),
            Settings(runtime_environment="test", network="testnet11"),
        )
    except (HTTPException, AttributeError):
        # The baseline reaches later context validation. The invariant under
        # test is that neither submitted puzzle was evaluated at all.
        pass
    assert evaluations == []


def prepared_payment(*, cat=False, change=True):
    from chia.wallet.cat_wallet.cat_utils import (
        CAT_MOD, SpendableCAT, construct_cat_puzzle,
        unsigned_spend_bundle_for_spendable_cats,
    )
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
        calculate_synthetic_secret_key, DEFAULT_HIDDEN_PUZZLE_HASH,
        puzzle_for_pk, solution_for_conditions,
    )
    from chia.wallet.trading.offer import Offer, OFFER_MOD_HASH
    from chia.wallet.puzzle_drivers import PuzzleInfo
    from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
    from chia_rs import AugSchemeMPL
    from solslot_api.faucet import AGG_SIG_ME_DATA
    key = AugSchemeMPL.key_gen(b"test-wallet-cost-fixture-key-0001")
    inner = puzzle_for_pk(key.get_g1())
    asset = bytes32(b"a" * 32) if cat else None
    puzzle = construct_cat_puzzle(CAT_MOD, asset, inner) if cat else inner
    parent = Coin(bytes32(b"p" * 32), puzzle.get_tree_hash(), uint64(200))
    coin = Coin(parent.name(), puzzle.get_tree_hash(), uint64(100))
    conditions = [[51, OFFER_MOD_HASH, 70 if change else 100]]
    if change:
        conditions.append([51, inner.get_tree_hash(), 30])
    solution = solution_for_conditions(conditions)
    if cat:
        unsigned = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [
            SpendableCAT(
                coin=coin, limitations_program_hash=asset,
                inner_puzzle=inner, inner_solution=solution,
                lineage_proof=LineageProof(parent.parent_coin_info, inner.get_tree_hash(), parent.amount),
            )
        ])
    else:
        unsigned = WalletSpendBundle([make_spend(coin, puzzle, solution)], G2Element())
    drivers = {} if asset is None else {asset: PuzzleInfo({"type": "CAT", "tail": "0x" + asset.hex()})}
    offer = Offer({}, unsigned, drivers)
    synthetic = calculate_synthetic_secret_key(key, DEFAULT_HIDDEN_PUZZLE_HASH)
    signatures = []
    for spend in unsigned.coin_spends:
        found = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 100_000_000)
        for public_key, message in pkm_pairs_for_conditions_dict(found, spend.coin, AGG_SIG_ME_DATA["testnet11"]):
            assert public_key == synthetic.get_g1()
            signatures.append(AugSchemeMPL.sign(synthetic, message))
    return offer, asset, "0x" + bytes(AugSchemeMPL.aggregate(signatures)).hex()


@pytest.mark.parametrize("cat", [False, True])
@pytest.mark.parametrize("change", [False, True])
@pytest.mark.asyncio
async def test_supported_payment_round_trip_in_worker(cat, change, monkeypatch):
    from chia.wallet.trading.offer import Offer
    from solslot_api.wallet_offer_worker import run_offer_job
    unsigned, asset, signature = prepared_payment(cat=cat, change=change)
    encoded = unsigned.to_bech32()
    expected_spends = tuple(bytes(spend) for spend in unsigned.coin_spends())
    # Private IPC must restore the already-evaluated object and its caches;
    # reconstruction cannot execute the Offer constructor on the API loop.
    def no_parent_constructor(self):
        raise AssertionError("Offer constructor ran in the API process")
    monkeypatch.setattr(Offer, "__post_init__", no_parent_constructor)
    result = await run_offer_job(
        "payment", encoded=encoded, signature_hex=signature,
        network="testnet11", dummy_spends=0, asset_id=asset,
    )
    assert type(result) is Offer
    assert tuple(bytes(spend) for spend in result.coin_spends()) == expected_spends
    assert bytes(result.aggregated_signature()).hex() == signature[2:]


def test_direct_admission_rejects_multi_input_before_any_evaluation(monkeypatch):
    from solslot_api.native_purchases import _parse_prepared_payment_offer
    import chia.wallet.util.compute_hints as hints
    import chia.wallet.trading.offer as offers
    def forbidden(*args, **kwargs):
        raise AssertionError("submitted puzzle was evaluated")
    monkeypatch.setattr(hints, "compute_spend_hints_and_additions", forbidden)
    monkeypatch.setattr(offers, "compute_spend_hints_and_additions", forbidden)
    with pytest.raises(ValueError, match="input"):
        _parse_prepared_payment_offer(
            encoded=encode_bundle(extra_input_bundle()),
            signature_hex="0x" + bytes(G2Element()).hex(),
            network="testnet11", dummy_spends=0, asset_id=None,
        )


@pytest.mark.parametrize("variant", ["delegate", "hidden", "dotted"])
def test_noncanonical_solution_rejected_without_execution(variant, monkeypatch):
    from solslot_api.wallet_offer_validation import decode_offer, validate_standard_payment
    offer, _, _ = prepared_payment()
    spend = offer.coin_spends()[0]
    solution = Program.from_serialized(spend.solution)
    fields = list(solution.as_iter())
    if variant == "delegate":
        fields[1] = Program.to(1)
        solution = Program.to(fields)
    elif variant == "hidden":
        fields[0] = Program.to(b"key")
        solution = Program.to(fields)
    else:
        solution = Program.to((fields[0], (fields[1], (fields[2], b"non-nil-tail"))))
    changed = WalletSpendBundle([make_spend(spend.coin, spend.puzzle_reveal, solution)], G2Element())
    def forbidden(*args, **kwargs):
        raise AssertionError("CLVM executed during structural validation")
    monkeypatch.setattr(Program, "run_with_cost", forbidden)
    decoded = decode_offer(encode_bundle(changed), real_spends=1, dummy_spends=0)
    with pytest.raises(ValueError):
        validate_standard_payment(decoded, asset_id=None)


@pytest.mark.parametrize("version", [0, 1, 6])
def test_supported_compression_versions_and_raw(version):
    from solslot_api.wallet_offer_validation import decode_offer
    offer, _, _ = prepared_payment()
    bundle = offer.to_spend_bundle()
    compressed = encode_bundle(bundle, version=version)
    assert decode_offer(compressed, real_spends=1, dummy_spends=0).raw == bytes(bundle)
    raw = bech32_encode("offer", convertbits(bytes(bundle), 8, 5))
    assert decode_offer(raw, real_spends=1, dummy_spends=0).raw == bytes(bundle)
    assert decode_offer(compressed.upper(), real_spends=1, dummy_spends=0).raw == bytes(bundle)


@pytest.mark.parametrize("variant", ["truncated", "trailing", "oversized", "wrong-prefix", "bad-hash"])
def test_malformed_encoding_and_binding_rejected(variant, monkeypatch):
    import solslot_api.wallet_offer_validation as validation
    offer, _, _ = prepared_payment()
    bundle = offer.to_spend_bundle()
    wire = compress_object_with_puzzles(bytes(bundle), 6)
    prefix = "offer"
    if variant == "truncated":
        wire = wire[:-1]
    elif variant == "trailing":
        wire += b"x"
    elif variant == "oversized":
        monkeypatch.setattr(validation, "MAX_RAW_OFFER", 64)
    elif variant == "wrong-prefix":
        prefix = "wallet"
    else:
        spend = bundle.coin_spends[0]
        coin = Coin(spend.coin.parent_coin_info, bytes32(b"x" * 32), spend.coin.amount)
        changed = WalletSpendBundle([make_spend(coin, spend.puzzle_reveal, spend.solution)], G2Element())
        wire = compress_object_with_puzzles(bytes(changed), 6)
    encoded = bech32_encode(prefix, convertbits(wire, 8, 5))
    with pytest.raises(ValueError):
        validation.decode_offer(encoded, real_spends=1, dummy_spends=0)


@pytest.mark.parametrize("failure", ["exception", "over-budget"])
def test_cost_failure_stops_before_offer_constructor(failure, monkeypatch):
    from solslot_api.native_purchases import _parse_prepared_payment_offer
    import chia.wallet.util.compute_hints as hints
    import chia.wallet.trading.offer as offers
    offer, _, signature = prepared_payment()
    encoded = offer.to_bech32()
    budgets = []
    def cost(spend, *, max_cost):
        budgets.append(max_cost)
        if failure == "exception":
            raise ValueError("synthetic cost failure")
        return {}, max_cost + 1
    def forbidden(*args, **kwargs):
        raise AssertionError("failed cost validation reached Offer")
    monkeypatch.setattr(hints, "compute_spend_hints_and_additions", cost)
    monkeypatch.setattr(offers.Offer, "from_spend_bundle", forbidden)
    with pytest.raises(ValueError):
        _parse_prepared_payment_offer(
            encoded=encoded, signature_hex=signature, network="testnet11",
            dummy_spends=0, asset_id=None,
        )
    assert budgets == [100_000_000]


@pytest.mark.asyncio
async def test_worker_timeout_reaps_process_and_keeps_loop_responsive(monkeypatch):
    import asyncio
    import sys
    import solslot_api.wallet_offer_worker as worker
    real_spawn = asyncio.create_subprocess_exec
    children = []
    async def stalled(*args, **kwargs):
        process = await real_spawn(
            sys.executable, "-c",
            "import sys,time; sys.stdin.buffer.read(); time.sleep(60)",
            **kwargs,
        )
        children.append(process)
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", stalled)
    monkeypatch.setattr(worker, "WORKER_TIMEOUT_SECONDS", 0.25)
    ticks = []
    async def heartbeat():
        for _ in range(5):
            await asyncio.sleep(0.02)
            ticks.append(True)
    with pytest.raises(ValueError, match="timed out"):
        await asyncio.gather(worker.run_offer_job("decode"), heartbeat())
    assert ticks and children and all(child.returncode is not None for child in children)


@pytest.mark.asyncio
async def test_worker_concurrency_and_outer_cancellation_reap_every_child(monkeypatch):
    import asyncio
    import sys
    import solslot_api.wallet_offer_worker as worker
    real_spawn = asyncio.create_subprocess_exec
    children = []
    async def stalled(*args, **kwargs):
        child = await real_spawn(
            sys.executable, "-c",
            "import sys,time; sys.stdin.buffer.read(); time.sleep(60)",
            **kwargs,
        )
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", stalled)
    jobs = [asyncio.create_task(worker.run_offer_job("decode")) for _ in range(3)]
    try:
        for _ in range(100):
            if len(children) == 2:
                break
            await asyncio.sleep(0.01)
        assert len(children) == worker.MAX_WORKERS == 2
        assert all(child.returncode is None for child in children)
    finally:
        for job in jobs:
            job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)
    assert len(children) == 2
    assert all(child.returncode is not None for child in children)

@pytest.mark.parametrize("quantity", [1, 2, 100])
@pytest.mark.parametrize("cat", [False, True])
@pytest.mark.asyncio
async def test_native_worker_preserves_supported_batch_and_cat(quantity, cat):
    import time
    from dataclasses import replace
    from tests.test_native_purchases import _context, _b32
    from solslot_api.native_purchases import NativePurchaseGroup
    from solslot_api.wallet_offer_worker import run_offer_job
    from solslot_puzzles.payment_artifacts_v2 import PaymentRail
    from solslot_puzzles.payment_artifacts_v3 import PurchaseBatchV1, purchase_batch_to_json
    from solslot_puzzles.stripe_settlement_v1_driver import (
        PrimaryMintTermsV3, InventoryReservationV1, make_inventory_available_inner,
        make_mint_offer_v5_inner, prepare_chia_buyer_offer_v3,
        prepare_chia_buyer_batch_offer_v3,
    )
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
        puzzle_for_pk, calculate_synthetic_secret_key, DEFAULT_HIDDEN_PUZZLE_HASH,
    )
    from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
    from chia_rs import AugSchemeMPL
    from solslot_api.faucet import AGG_SIG_ME_DATA
    key = AugSchemeMPL.key_gen(b"wallet-batch-cost-key-fixture0001")
    validators = tuple(AugSchemeMPL.key_gen(bytes([seed]) * 32) for seed in (51, 52, 53))
    now = int(time.time())
    asset = _b32(230) if cat else None
    contexts = []
    for index in range(quantity):
        context, _ = _context(key, validators, deed_parent_seed=100 + index, now=now)
        if cat:
            artifact = replace(context.purchase, rail=PaymentRail.CHIA_CAT, rail_asset_id=asset)
            prior = context.terms
            terms = PrimaryMintTermsV3.for_artifact(
                artifact=artifact, smart_deed_inner_hash=prior.smart_deed_inner_hash,
                deed_launcher_puzzle_hash=prior.deed_launcher_puzzle_hash,
                protocol_puzhash=prior.protocol_puzhash,
                validator_pubkeys=prior.validator_pubkeys, provider_id=prior.provider_id,
            )
            reservation = InventoryReservationV1(artifact=artifact, expires_at=now + 300)
            available_inner = make_inventory_available_inner(terms)
            available = Coin(artifact.deed_launcher_id,
                             SINGLETON_MOD.curry(context.deed_struct, available_inner).get_tree_hash(), uint64(1))
            deed = Coin(available.name(), SINGLETON_MOD.curry(
                context.deed_struct, make_mint_offer_v5_inner(terms, reservation)).get_tree_hash(), uint64(1))
            context = replace(
                context, purchase=artifact, terms=terms, reservation=reservation, deed_coin=deed,
                deed_lineage=LineageProof(available.parent_coin_info, available_inner.get_tree_hash(), uint64(1)),
            )
        contexts.append(context)
    contexts = tuple(sorted(contexts, key=lambda item: bytes(item.purchase.deed_launcher_id)))
    batch = None if quantity == 1 else PurchaseBatchV1(
        batch_nonce=_b32(229), artifacts=tuple(context.purchase for context in contexts),
    )
    parent = contexts[0].stored
    if batch is not None:
        parent = replace(parent, purchase_id="0x" + batch.purchase_id.hex(),
                         artifact_hash="0x" + batch.batch_hash.hex(),
                         purchase_artifact=purchase_batch_to_json(batch))
    group = NativePurchaseGroup(parent, contexts, batch)
    inner = puzzle_for_pk(key.get_g1())
    puzzle = inner if asset is None else construct_cat_puzzle(CAT_MOD, asset, inner)
    amount = group.total_rail_amount + 1000
    ancestor = Coin(_b32(228), puzzle.get_tree_hash(), uint64(amount))
    coin = Coin(ancestor.name(), puzzle.get_tree_hash(), uint64(amount))
    lineage = None if asset is None else LineageProof(ancestor.parent_coin_info, inner.get_tree_hash(), ancestor.amount)
    if batch is None:
        prepared = prepare_chia_buyer_offer_v3(
            payment_coin=coin, payment_public_key=bytes(key.get_g1()),
            artifact=contexts[0].purchase, terms=contexts[0].terms,
            deed_singleton_struct=contexts[0].deed_struct, cat_lineage_proof=lineage,
        )
    else:
        prepared = prepare_chia_buyer_batch_offer_v3(
            payment_coin=coin, payment_public_key=bytes(key.get_g1()), batch=batch,
            terms=tuple(item.terms for item in contexts),
            deed_singleton_structs=tuple(item.deed_struct for item in contexts),
            cat_lineage_proof=lineage,
        )
    spend = prepared.offer.coin_spends()[0]
    conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 100_000_000)
    synthetic = calculate_synthetic_secret_key(key, DEFAULT_HIDDEN_PUZZLE_HASH)
    pairs = pkm_pairs_for_conditions_dict(conditions, coin, AGG_SIG_ME_DATA["testnet11"])
    signature = AugSchemeMPL.aggregate([AugSchemeMPL.sign(synthetic, message) for _, message in pairs])
    encoded = prepared.offer.to_bech32()
    result = await run_offer_job(
        "native", group=group, encoded=encoded,
        signature_hex="0x" + bytes(signature).hex(), network="testnet11",
    )
    assert len(result.coin_spends()) == 1
    assert len(result.requested_payments) == quantity
    assert result.fees() == 0
    assert bytes(result.coin_spends()[0]) == bytes(spend)
    quorum_signature = AugSchemeMPL.aggregate([
        AugSchemeMPL.sign(
            validators[index],
            bytes(item.purchase.artifact_hash) + bytes(item.deed_coin.name())
            + AGG_SIG_ME_DATA["testnet11"],
        )
        for item in contexts for index in (0, 1)
    ])
    bundle, outputs = await run_offer_job(
        "native_bundle", group=group, buyer_offer=result,
        signer_indices=(0, 1), aggregated_signature=quorum_signature,
    )
    assert len(outputs) == quantity
    assert {entry.deed_launcher_id for entry in outputs} == {
        "0x" + item.purchase.deed_launcher_id.hex() for item in contexts
    }
    # Verify every signature and exact final holding, independently of the
    # delivery index returned by the worker. All keys/assets are synthetic.
    signed_pairs = []
    for item in bundle.coin_spends:
        conditions = conditions_dict_for_solution(item.puzzle_reveal, item.solution, 100_000_000)
        signed_pairs.extend(pkm_pairs_for_conditions_dict(conditions, item.coin, AGG_SIG_ME_DATA["testnet11"]))
    assert signed_pairs
    keys, messages = zip(*signed_pairs, strict=True)
    assert AugSchemeMPL.aggregate_verify(list(keys), list(messages), bundle.aggregated_signature)
    assert not AugSchemeMPL.aggregate_verify(list(keys), list(messages), G2Element())
    final = {"0x" + coin.name().hex(): coin for coin in bundle.additions()
             if coin.name() not in {spent.coin.name() for spent in bundle.coin_spends}}
    for output in outputs:
        assert output.coin_id in final
        assert final[output.coin_id].amount == 1
        assert "0x" + final[output.coin_id].puzzle_hash.hex() == output.puzzle_hash
    assert sum(coin.amount for coin in bundle.removals()) == sum(coin.amount for coin in bundle.additions())

@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.asyncio
async def test_swap_rejects_changed_solution_before_evaluation_or_submission(reverse, monkeypatch):
    import solslot_api.sols_swaps as swaps
    import chia.wallet.trading.offer as offer_module
    from solslot_api.wallet_offer_validation import decode_offer
    from tests.test_sols_swaps import (
        _fixture, _reverse_fixture, _request, _prepare, _settings,
        FakeNode, FakeProtocolSubmitter, VAULT_LAUNCHER, DEED_LAUNCHER, _hex32,
    )
    from solslot_api.faucet import Faucet
    faucet = Faucet.from_seed_hex("77" * 32, "testnet11")
    submitter = FakeProtocolSubmitter()
    request = _request(FakeNode(), submitter, faucet)
    if reverse:
        fixture = _reverse_fixture(faucet)
        async def load_context(**kwargs):
            return fixture
        monkeypatch.setattr(swaps, "_authorize_swap", lambda *a: None)
        monkeypatch.setattr(swaps, "_load_reverse_swap_context", load_context)
        prepared = await swaps.prepare_sols_swap(
            _hex32(VAULT_LAUNCHER),
            swaps.PrepareSolsSwapRequest(direction="DEED_TO_SOLS", deedLauncherId=_hex32(DEED_LAUNCHER)),
            request, _settings(),
        )
        expected = swaps._build_reverse_protocol_offer(fixture, signature_data=None).offer
    else:
        fixture = _fixture()
        prepared = await _prepare(monkeypatch, fixture, request)
        expected = swaps.prepare_vault_sols_buyer_offer(
            payment_coin=fixture.context.payment_coin,
            payment_lineage_proof=fixture.context.payment_lineage,
            receipt=fixture.context.receipt, config=fixture.context.config,
            vault_launcher_id=fixture.context.vault_record.launcher_id,
        ).offer
    raw_bundle = expected.to_spend_bundle()
    index = next(i for i, item in enumerate(raw_bundle.coin_spends)
                 if item.coin.parent_coin_info != bytes32.zeros)
    spend = raw_bundle.coin_spends[index]
    changed = make_spend(spend.coin, spend.puzzle_reveal, Program.to([]))
    spends = list(raw_bundle.coin_spends)
    spends[index] = changed
    bundle = WalletSpendBundle(spends, G2Element())
    observed = []
    original = offer_module.compute_spend_hints_and_additions
    def tracked(item, **kwargs):
        if bytes(item) == bytes(changed):
            observed.append(True)
        return original(item, **kwargs)
    monkeypatch.setattr(offer_module, "compute_spend_hints_and_additions", tracked)
    with pytest.raises(HTTPException) as error:
        await swaps.complete_sols_swap(
            _hex32(VAULT_LAUNCHER),
            swaps.CompleteSolsSwapRequest(
                direction="DEED_TO_SOLS" if reverse else "SOLS_TO_DEED",
                deedLauncherId=_hex32(DEED_LAUNCHER),
                operationHash=prepared.operation_hash,
                quoteExpiresAt=prepared.quote_expires_at,
                buyerOffer=encode_bundle(bundle),
                aggregatedSignature="0x" + bytes(G2Element()).hex(),
            ),
            request, _settings(),
        )
    assert error.value.status_code == 409
    assert "does not match live chain state" in error.value.detail
    assert observed == []
    assert submitter.submitted is None


@pytest.mark.asyncio
async def test_cancellation_during_spawn_still_reaps_child(monkeypatch):
    import asyncio
    import sys
    import solslot_api.wallet_offer_worker as worker
    actual_spawn = asyncio.create_subprocess_exec
    started = asyncio.Event()
    release = asyncio.Event()
    children = []
    async def delayed(*args, **kwargs):
        started.set()
        await release.wait()
        child = await actual_spawn(
            sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)", **kwargs,
        )
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed)
    task = asyncio.create_task(worker.run_offer_job("decode"))
    await started.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(children) == 1 and children[0].returncode is not None

@pytest.mark.asyncio
async def test_repeated_cancellation_during_spawn_keeps_cleanup_owned(monkeypatch):
    import asyncio
    import sys
    import solslot_api.wallet_offer_worker as worker
    actual_spawn = asyncio.create_subprocess_exec
    started = asyncio.Event()
    release = asyncio.Event()
    children = []
    async def delayed(*args, **kwargs):
        started.set()
        await release.wait()
        child = await actual_spawn(
            sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)", **kwargs,
        )
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed)
    monkeypatch.setattr(worker, "MAX_WORKERS", 1)
    task = asyncio.create_task(worker.run_offer_job("decode"))
    try:
        await started.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert worker._LIMITS[asyncio.get_running_loop()]().locked()
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        for _ in range(100):
            if children:
                break
            await asyncio.sleep(0.01)
        assert len(children) == 1
        assert children[0].returncode is not None
    finally:
        # The baseline intentionally exposes an orphan. Always clean it up.
        release.set()
        for child in children:
            if child.returncode is None:
                child.kill()
            await child.wait()


@pytest.mark.asyncio
async def test_worker_and_outer_deadlines_reap_delayed_spawn(monkeypatch):
    import asyncio
    import sys
    import solslot_api.wallet_offer_worker as worker
    actual_spawn = asyncio.create_subprocess_exec
    children = []
    async def delayed(*args, **kwargs):
        await asyncio.sleep(0.12)
        child = await actual_spawn(
            sys.executable, "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)", **kwargs,
        )
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed)
    monkeypatch.setattr(worker, "WORKER_TIMEOUT_SECONDS", 0.03)
    try:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(worker.run_offer_job("decode"), timeout=0.06)
        assert len(children) == 1
        assert children[0].returncode is not None
    finally:
        for child in children:
            if child.returncode is None:
                child.kill()
            await child.wait()
