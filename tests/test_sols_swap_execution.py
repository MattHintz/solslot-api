from __future__ import annotations

import asyncio
from dataclasses import replace
import sqlite3

import chia_rs
import pytest
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from eth_account.messages import encode_typed_data
from fastapi import HTTPException

from solslot_api.chia_provider import ChiaProviderError
from solslot_api.faucet import AGG_SIG_ME_DATA, Faucet
from solslot_api.faucet import FaucetSelectionRestricted
from solslot_api.faucet_worker import FaucetConsolidationWorker
from solslot_api.admin import _build_single_coin_create_bundle
from solslot_api.protocol_submission import PreparedProtocolBundle
from solslot_api.sols_swap_execution import execution_confirmed, validate_execution
from solslot_api.sols_swap_store import SolsSwapStore
from solslot_api.sols_swaps import (
    CompleteSolsSwapRequest, PrepareSolsSwapRequest, complete_sols_swap,
    prepare_sols_swap, sols_swap_status,
    _seal_swap_execution,
)
from tests.test_sols_swaps import (
    funding_runtime, DEED_LAUNCHER, VAULT_LAUNCHER, EVM_ACCOUNT, FakeNode, FakeProtocolSubmitter,
    _b32, _fixture, _hex32, _request, _reverse_fixture, _reverse_wallet_signature,
    _settings, _wallet_signature,
)


class Chain(FakeNode):
    def __init__(self):
        super().__init__()
        self.records = {}
        self.spends = {}
        self.peak_hash = _hex32(_b32(200))

    def include(self, bundle):
        for coin in bundle.additions():
            self.records[_hex32(coin.name())] = dict(
                coin=coin.to_json_dict(), confirmed_block_index=100,
                spent_block_index=0, spent=False,
            )
        for spend in bundle.coin_spends:
            self.records.setdefault(_hex32(spend.coin.name()), dict(
                coin=spend.coin.to_json_dict(), confirmed_block_index=1,
                spent_block_index=0, spent=False))
            self.records[_hex32(spend.coin.name())].update(spent_block_index=100, spent=True)
            self.spends[_hex32(spend.coin.name())] = spend.to_json_dict()

    async def get_coin_record_by_name_primary(self, coin_id):
        return self.records.get(coin_id)

    async def get_blockchain_state_primary(self):
        return dict(success=True, blockchain_state=dict(
            peak=dict(height=100, header_hash=self.peak_hash), sync=dict(synced=True, sync_mode=False)))

    async def get_puzzle_and_solution_primary(self, coin_id, height):
        assert height == 100
        return self.spends.get(coin_id)


async def signed_case(monkeypatch, tmp_path, *, reverse=False, evm=False):
    node = Chain()
    submitter = FakeProtocolSubmitter()
    faucet = Faucet.from_seed_hex("77" * 32, "testnet11")
    context = _reverse_fixture(faucet, evm=evm) if reverse else _fixture(evm=evm).context
    request = _request(node, submitter, faucet)
    path = str(tmp_path / "swaps.db")
    request.app.state.sols_swap_store = SolsSwapStore(path)
    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", lambda *_: None)
    monkeypatch.setattr("solslot_api.sols_swaps.verify_vault_session", lambda *_: None)
    async def context_loader(**_kwargs):
        return context
    loader = "_load_reverse_swap_context" if reverse else "_load_swap_context"
    monkeypatch.setattr("solslot_api.sols_swaps." + loader, context_loader)
    direction = "DEED_TO_SOLS" if reverse else "SOLS_TO_DEED"
    prepared = await prepare_sols_swap(_hex32(VAULT_LAUNCHER), PrepareSolsSwapRequest(
        direction=direction, deedLauncherId=_hex32(DEED_LAUNCHER)), request, _settings())
    if evm:
        auth = dict(vaultOwnerAuthorization="0x" + EVM_ACCOUNT.sign_message(
            encode_typed_data(full_message=prepared.vault_typed_data)).signature.hex())
    else:
        signature = (_reverse_wallet_signature(context) if reverse
                     else _wallet_signature(context, prepared.buyer_offer))
        auth = dict(aggregatedSignature="0x" + signature.hex())
    body = CompleteSolsSwapRequest(
        direction=direction, deedLauncherId=_hex32(DEED_LAUNCHER), operationHash=prepared.operation_hash,
        quoteExpiresAt=prepared.quote_expires_at, fundingReservationHash=prepared.funding_evidence["reservationHash"], buyerOffer=prepared.buyer_offer, **auth,
    )
    return request, body, path, loader


def consensus(bundle):
    chia_rs.validate_clvm_and_signature(
        bundle, 11_000_000_000,
        DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(AGG_SIG_ME_DATA["testnet11"])),
        chia_rs.MEMPOOL_MODE | chia_rs.ENABLE_SECP_OPS | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True], ids=["sols-to-deed", "deed-to-sols"])
@pytest.mark.parametrize("evm", [False, True], ids=["bls", "evm"])
@pytest.mark.parametrize("failure", ["timeout", "cancel", "receipt-write"])
async def test_restart_replays_exact_signed_funding_without_rebuilding(
    monkeypatch, tmp_path, reverse, evm, failure,
):
    request, body, path, loader = await signed_case(monkeypatch, tmp_path, reverse=reverse, evm=evm)
    state = request.app.state
    pushed = []

    async def push(bundle_json, **kwargs):
        bundle = SpendBundle.from_json_dict(bundle_json)
        consensus(bundle)
        # The durable file is independently readable before the first push.
        reopened = SolsSwapStore(path)
        retained = reopened.execution(body.operation_hash)
        assert bytes(SpendBundle.from_json_dict(retained["spendBundle"])) == bytes(bundle)
        assert retained["spendBundleId"] == kwargs["required_spend_bundle_id"]
        assert set(reopened.reserved_input_coin_ids()) == {_hex32(c.name()) for c in bundle.removals()}
        pushed.append(bytes(bundle))
        if len(pushed) == 1:
            if failure == "timeout":
                raise ChiaProviderError("primary response lost")
            if failure == "cancel":
                raise asyncio.CancelledError()
        return dict(provider="synthetic-primary", observed_at="2026-09-16T15:00:00Z", ambiguous_push=True)

    state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = push
    if failure == "receipt-write":
        def failed_receipt(*_args, **_kwargs):
            raise sqlite3.OperationalError("simulated post-push write failure")
        monkeypatch.setattr(state.sols_swap_store, "mark_submitted", failed_receipt)
    expected = {"timeout": HTTPException, "cancel": asyncio.CancelledError,
                "receipt-write": sqlite3.OperationalError}[failure]
    with pytest.raises(expected):
        await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    first = SolsSwapStore(path)
    record = first.get(body.operation_hash)
    assert record.status == "PREPARED" and record.transaction_id is not None
    assert record.mempool_observed_at is None and record.submission_provider is None
    retained = first.execution(body.operation_hash)

    # A new process/store/submitter/lock, changed fee target, expired quote,
    # missing owner signature and unavailable context must still replay bytes.
    state.sols_swap_store = SolsSwapStore(path)
    state.protocol_submitter = FakeProtocolSubmitter()
    state.protocol_submitter.policy = replace(state.protocol_submitter.policy, target_seconds=900)
    del state.sols_swap_lock
    state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = push
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("recovery must not reconstruct, estimate, select, or sign")
    monkeypatch.setattr("solslot_api.sols_swaps." + loader, forbidden)
    monkeypatch.setattr("solslot_api.sols_swaps.time", lambda: body.quote_expires_at + 10_000)
    monkeypatch.setattr(state.protocol_submitter, "_prepare_locked", forbidden)
    minimal = body.model_copy(update={"buyer_offer": None, "aggregated_signature": None,
                                     "vault_owner_authorization": None})
    recovered = await complete_sols_swap(_hex32(VAULT_LAUNCHER), minimal, request, _settings())
    assert recovered.status == "MEMPOOL" and recovered.transaction_id == retained["spendBundleId"]
    assert recovered.fee_target_seconds == 300
    assert recovered.fee_mojos == retained["feeMojos"]
    assert len(pushed) == 2 and pushed[0] == pushed[1]
    assert state.sols_swap_store.execution(body.operation_hash) == retained
    assert state.sols_swap_store.reserved_input_coin_ids()
    again = await complete_sols_swap(_hex32(VAULT_LAUNCHER), minimal, request, _settings())
    assert again == recovered and len(pushed) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("via_status", [False, True])
async def test_chain_confirmation_recovers_lost_push_without_inventing_mempool_receipt(monkeypatch, tmp_path, via_status):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path, evm=True)
    state = request.app.state
    async def included_then_lost(bundle_json, **_kwargs):
        state.coinset.include(SpendBundle.from_json_dict(bundle_json))
        raise ChiaProviderError("connection reset after inclusion")
    state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = included_then_lost
    with pytest.raises(HTTPException, match="retained transaction"):
        await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    state.sols_swap_store = SolsSwapStore(path)
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("included execution must not be pushed again")
    state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = forbidden
    if via_status:
        result = await sols_swap_status(body.operation_hash, request, _settings())
    else:
        result = await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    assert result.status == "CONFIRMED"
    assert result.submission_provider is None and result.mempool_observed_at is None
    assert not state.sols_swap_store.reserved_input_coin_ids()
    assert state.sols_swap_store.execution(body.operation_hash) is not None


@pytest.mark.asyncio
async def test_waiting_duplicate_rechecks_after_swap_lock(monkeypatch, tmp_path):
    request, body, _, _ = await signed_case(monkeypatch, tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []
    async def push(bundle_json, **_kwargs):
        calls.append(bundle_json)
        entered.set()
        await release.wait()
        return dict(provider="primary", observed_at="2026-09-16T15:00:00Z", ambiguous_push=False)
    request.app.state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = push
    first = asyncio.create_task(complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings()))
    await asyncio.wait_for(entered.wait(), 30)
    second = asyncio.create_task(complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings()))
    await asyncio.sleep(0)
    release.set()
    a, b = await asyncio.gather(first, second)
    assert a == b and len(calls) == 1


@pytest.mark.asyncio
async def test_failure_to_seal_prevents_any_push(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    def fail(*_args, **_kwargs):
        raise ValueError("disk failed before sealing")
    monkeypatch.setattr(request.app.state.sols_swap_store, "reserve_execution", fail)
    with pytest.raises(HTTPException, match="before sealing"):
        await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    assert not hasattr(request.app.state.protocol_submitter.provider, "pushed")
    assert SolsSwapStore(path).execution(body.operation_hash) is None


@pytest.mark.asyncio
async def test_resume_checks_current_authorization_before_replaying(monkeypatch, tmp_path):
    request, body, _, _ = await signed_case(monkeypatch, tmp_path)
    async def lost(*_args, **_kwargs):
        raise ChiaProviderError("lost")
    request.app.state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = lost
    with pytest.raises(HTTPException):
        await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    def denied(*_args):
        raise HTTPException(status_code=403, detail="session expired")
    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", denied)
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("unauthorized caller reached replay")
    request.app.state.protocol_submitter.provider.push_tx_confirmed_in_primary_mempool = forbidden
    with pytest.raises(HTTPException, match="session expired"):
        await complete_sols_swap(_hex32(VAULT_LAUNCHER), body, request, _settings())
    assert request.app.state.sols_swap_store.reserved_input_coin_ids()


@pytest.mark.asyncio
async def test_fee_signer_cannot_substitute_protocol_solution_even_when_conditions_are_equal(monkeypatch):
    execution, prepared = simple_execution()
    bundle = SpendBundle.from_json_dict(execution["spendBundle"])
    original = SpendBundle([bundle.coin_spends[0]], G2Element())
    changed = make_spend(bundle.coin_spends[0].coin,
                         Program.from_bytes(bytes(bundle.coin_spends[0].puzzle_reveal)), Program.to(1))
    substituted = SpendBundle([changed, bundle.coin_spends[1]], G2Element())
    assert substituted.additions() == bundle.additions()
    store = SolsSwapStore(":memory:")
    record = store.record_prepared(operation_hash=_hex32(_b32(1)), **prepared)
    request = _request(Chain(), FakeProtocolSubmitter())
    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", lambda *_: None)
    with pytest.raises(ValueError, match="authorized protocol transaction"):
        await _seal_swap_execution(request, _settings(), store, record, original)(
            PreparedProtocolBundle(substituted, 7, execution["feeCoinId"]))
    assert store.execution(record.operation_hash) is None


@pytest.mark.parametrize("sink", ["selection", "direct-signing", "consolidation", "bridge-top-up"])
def test_pending_reservation_blocks_sibling_faucet_sinks_and_preserves_unreserved_control(sink):
    faucet = Faucet.from_seed_hex("78" * 32, "testnet11")
    reserved = Coin(_b32(195), faucet.address_puzzle_hash, 1000)
    available = Coin(_b32(196), faucet.address_puzzle_hash, 2000)
    active = {_hex32(reserved.name())}
    faucet.add_coin_reservation_source(lambda: active)
    records = [dict(coin=c.to_json_dict(), confirmed_block_index=1, spent_block_index=0)
               for c in (reserved, available)]
    if sink == "selection":
        assert faucet.select_coin(records, 1) == available
        active.clear()
        assert faucet.select_coin(records, 1) == reserved
        return
    def sign():
        if sink == "direct-signing":
            return faucet.sign_delegated_spend(reserved, Program.to([[51, faucet.address_puzzle_hash, 1000]]))
        if sink == "bridge-top-up":
            return _build_single_coin_create_bundle(faucet=faucet, source_coin=reserved,
                outputs=[(faucet.address_puzzle_hash, 900)], change_puzzle_hash=faucet.address_puzzle_hash, fee=1)
        return FaucetConsolidationWorker(faucet, Chain())._build_consolidation_bundle(records, fee=1)
    with pytest.raises(FaucetSelectionRestricted, match="unresolved exact execution"):
        sign()
    active.clear()
    assert sign() is not None


def test_unavailable_reservations_block_selection_and_signing():
    faucet = Faucet.from_seed_hex("78" * 32, "testnet11")
    def unavailable():
        raise sqlite3.OperationalError("cannot read retained funding")
    faucet.add_coin_reservation_source(unavailable)
    with pytest.raises(FaucetSelectionRestricted, match="unavailable"):
        faucet.select_coin([], 1)
    with pytest.raises(FaucetSelectionRestricted, match="unavailable"):
        faucet.sign_delegated_spend(Coin(_b32(1), faucet.address_puzzle_hash, 1), Program.to([]))


@pytest.mark.asyncio
async def test_authorization_is_rechecked_after_funded_signature_worker(monkeypatch):
    execution, prepared = simple_execution()
    bundle = SpendBundle.from_json_dict(execution["spendBundle"])
    original = SpendBundle([bundle.coin_spends[0]], G2Element())
    store = SolsSwapStore(":memory:")
    record = store.record_prepared(operation_hash=_hex32(_b32(1)), **prepared)
    request = _request(Chain(), FakeProtocolSubmitter())
    closed = False
    def authorize(*_args):
        if closed:
            raise HTTPException(status_code=403, detail="session expired during validation")
    async def worker(*_args, **_kwargs):
        nonlocal closed
        await asyncio.sleep(0)
        closed = True
    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", authorize)
    monkeypatch.setattr("solslot_api.sols_swaps.run_offer_job", worker)
    with pytest.raises(HTTPException, match="expired during validation"):
        await _seal_swap_execution(request, _settings(), store, record, original)(
            PreparedProtocolBundle(bundle, 7, execution["feeCoinId"]))
    assert store.execution(record.operation_hash) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("sink", ["consolidation", "bridge-top-up"])
async def test_automatic_faucet_callers_skip_reserved_coin_and_use_available_inputs(monkeypatch, sink):
    from solslot_api import admin
    from solslot_api.faucet_worker import FaucetConsolidationConfig
    faucet = Faucet.from_seed_hex("78" * 32, "testnet11")
    coins = [Coin(_b32(seed), faucet.address_puzzle_hash, amount)
             for seed, amount in [(193, 1000), (194, 2000), (195, 3000)]]
    faucet.add_coin_reservation_source(lambda: {_hex32(coins[0].name())})
    class Node(Chain):
        pushed = None
        async def get_coin_records_by_puzzle_hash(self, *_args, **_kwargs):
            return [dict(coin=c.to_json_dict(), confirmed_block_index=1, spent_block_index=0) for c in coins]
        async def push_tx(self, bundle):
            self.pushed = SpendBundle.from_json_dict(bundle)
            return dict(success=True, status="SUCCESS")
    node = Node()
    if sink == "consolidation":
        await FaucetConsolidationWorker(faucet, node, FaucetConsolidationConfig(
            threshold=2, max_inputs_per_run=2)).maybe_consolidate()
        assert node.pushed is not None
        assert {c.name() for c in node.pushed.removals()} == {c.name() for c in coins[1:]}
    else:
        monkeypatch.setattr(admin, "_faucet_or_503", lambda: faucet)
        monkeypatch.setattr(admin, "_coinset_or_502", lambda: node)
        monkeypatch.setattr(admin, "load_signed_public_artifact", lambda _: dict(bridgePolicy=dict(policyHash=_hex32(_b32(5)))))
        result = await admin.top_up_zkpassport_bridge_pool(
            admin.BridgePoolTopUpRequest(count=1, start_amount=1, fee=1, dry_run=False), _settings())
        assert result.source_coin_id == _hex32(coins[1].name())
        assert node.pushed is not None and node.pushed.removals() == [coins[1]]


def test_runtime_loads_existing_swap_reservations_with_fee_funding_disabled(tmp_path):
    from solslot_api.app import _load_swap_store_for_runtime
    execution, prepared = simple_execution()
    path = str(tmp_path / "swaps.db")
    original = SolsSwapStore(path)
    original.record_prepared(operation_hash=_hex32(_b32(1)), **prepared)
    original.reserve_execution(_hex32(_b32(1)), execution)
    settings = _settings()
    settings.admin_db_path = path
    settings.protocol_fee_funding_enabled = False
    faucet = Faucet.from_seed_hex("78" * 32, "testnet11")
    loaded = _load_swap_store_for_runtime(settings, faucet)
    assert loaded.execution(_hex32(_b32(1))) == execution
    fee = SpendBundle.from_json_dict(execution["spendBundle"]).coin_spends[1].coin
    with pytest.raises(FaucetSelectionRestricted, match="unresolved exact execution"):
        faucet.require_unreserved_coin(fee)


def simple_execution():
    pool_puzzle = Program.to((1, [[51, _b32(30), 1]]))
    fee_puzzle = Program.to((1, [[51, _b32(31), 93]]))
    pool = Coin(_b32(32), pool_puzzle.get_tree_hash(), 1)
    fee = Coin(_b32(33), fee_puzzle.get_tree_hash(), 100)
    bundle = SpendBundle([make_spend(pool, pool_puzzle, Program.to([])),
                          make_spend(fee, fee_puzzle, Program.to([]))], G2Element())
    execution = dict(network="testnet11", feeTargetSeconds=300, spendBundle=bundle.to_json_dict(),
                     spendBundleId=_hex32(bundle.name()), feeCoinId=_hex32(fee.name()), feeMojos="7", backingMojos="0")
    output = next(coin for coin in bundle.additions() if coin.parent_coin_info == pool.name())
    return execution, dict(direction="SOLS_TO_DEED", vault_launcher_id=_hex32(VAULT_LAUNCHER),
                          deed_launcher_id=_hex32(DEED_LAUNCHER), quote_expires_at=1,
                          pool_input_coin_id=_hex32(pool.name()), expected_pool_output_coin_id=_hex32(output.name()),
                          destination_puzzle_hash=_hex32(_b32(30)))


def test_durable_claims_conflict_across_connections_and_rollback_atomically(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    execution, prepared = simple_execution()
    path = str(tmp_path / "swaps.db")
    a, b = SolsSwapStore(path), SolsSwapStore(path)
    a.record_prepared(operation_hash=_hex32(_b32(1)), **prepared)
    b.record_prepared(operation_hash=_hex32(_b32(2)), **prepared)
    def reserve(item):
        store, seed = item
        try:
            store.reserve_execution(_hex32(_b32(seed)), execution)
            return seed
        except ValueError as exc:
            assert "reserved by another" in str(exc)
            return None
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(reserve, [(a, 1), (b, 2)]))
    winner = next(seed for seed in results if seed is not None)
    assert results.count(None) == 1
    loser = 3 - winner
    assert b.execution(_hex32(_b32(loser))) is None
    assert b.get(_hex32(_b32(loser))).transaction_id is None
    assert a.reserved_input_coin_ids() == b.reserved_input_coin_ids()
    assert len(a.reserved_input_coin_ids()) == 2
    with sqlite3.connect(path) as connection:
        # Corrupting even one byte never unlocks funding for another operation.
        connection.execute("UPDATE sols_swap_executions SET execution_json=execution_json || ' '")
    with pytest.raises(ValueError, match="checksum"):
        a.execution(_hex32(_b32(winner)))
    assert len(b.reserved_input_coin_ids()) == 2


@pytest.mark.parametrize("field,value", [("feeMojos", "8"), ("feeMojos", "07"), ("feeMojos", True),
    ("backingMojos", "1"), ("network", "mainnet"), ("feeTargetSeconds", True),
    ("spendBundleId", "0x" + "ff" * 32), ("feeCoinId", "0x" + "ee" * 32)])
def test_execution_rejects_mutated_economic_metadata(field, value):
    execution, prepared = simple_execution()
    execution[field] = value
    with pytest.raises(ValueError, match="inconsistent"):
        validate_execution(execution, pool_input_id=prepared["pool_input_coin_id"],
                           pool_output_id=prepared["expected_pool_output_coin_id"])


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["funding-unspent", "missing-spend", "different-spend", "height", "coin", "anchor"])
async def test_pool_successor_alone_never_releases_funding(mutation):
    execution, prepared = simple_execution()
    bundle = SpendBundle.from_json_dict(execution["spendBundle"])
    node = Chain()
    node.include(bundle)
    fee_id = execution["feeCoinId"]
    if mutation == "funding-unspent":
        node.records[fee_id].update(spent=False, spent_block_index=0)
    elif mutation == "missing-spend":
        del node.spends[fee_id]
    elif mutation == "different-spend":
        node.spends[fee_id]["solution"] = "0x01"
    elif mutation == "height":
        node.records[fee_id]["spent_block_index"] = 101
        # Return the spend independently of the lookup height for this adversarial node.
        async def spend_at_any_height(coin_id, _height): return node.spends.get(coin_id)
        node.get_puzzle_and_solution_primary = spend_at_any_height
    elif mutation == "coin":
        node.records[fee_id]["coin"]["amount"] = 99
    elif mutation == "anchor":
        original = node.get_coin_record_by_name_primary
        count = 0
        async def disappearing_anchor(coin_id):
            nonlocal count
            if coin_id == prepared["expected_pool_output_coin_id"]:
                count += 1
                if count > 1: return None
            return await original(coin_id)
        node.get_coin_record_by_name_primary = disappearing_anchor
    if mutation in {"different-spend", "height", "coin"}:
        with pytest.raises(ValueError, match="retain funding"):
            await execution_confirmed(node, bundle, prepared["expected_pool_output_coin_id"])
    else:
        assert not await execution_confirmed(node, bundle, prepared["expected_pool_output_coin_id"])


@pytest.mark.asyncio
async def test_same_height_branch_change_retains_original_funding():
    execution, prepared = simple_execution()
    bundle = SpendBundle.from_json_dict(execution["spendBundle"])
    old_fee_spend = bundle.coin_spends[1]
    alternate_fee = Coin(_b32(199), old_fee_spend.coin.puzzle_hash, old_fee_spend.coin.amount)
    alternate = SpendBundle([bundle.coin_spends[0], make_spend(alternate_fee,
        Program.from_bytes(bytes(old_fee_spend.puzzle_reveal)), Program.from_bytes(bytes(old_fee_spend.solution)))], G2Element())
    consensus(bundle)
    consensus(alternate)
    node, branch = Chain(), Chain()
    node.include(bundle)
    branch.include(alternate)
    branch.records[execution["feeCoinId"]] = dict(coin=old_fee_spend.coin.to_json_dict(),
        confirmed_block_index=1, spent_block_index=0, spent=False)
    assert node.records[prepared["expected_pool_output_coin_id"]] == branch.records[prepared["expected_pool_output_coin_id"]]
    original = node.get_coin_record_by_name_primary
    anchors = 0
    async def switch_before_final_anchor(coin_id):
        nonlocal anchors
        if coin_id == prepared["expected_pool_output_coin_id"]:
            anchors += 1
            if anchors == 2:
                node.records, node.spends = branch.records, branch.spends
                node.peak_hash = _hex32(_b32(201))
        return await original(coin_id)
    node.get_coin_record_by_name_primary = switch_before_final_anchor
    assert not await execution_confirmed(node, bundle, prepared["expected_pool_output_coin_id"])
    assert node.records[execution["feeCoinId"]]["spent"] is False
