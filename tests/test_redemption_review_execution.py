"""Actual primary snapshots, fee holds, signed consensus and restart dispatch."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
from time import time
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.trading.offer import Offer
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import funded_redemption_review as review
from solslot_api import funded_redemptions as routes
from solslot_api.chia_provider import ChiaProviderError
from solslot_api.chia_snapshot import active_snapshot
from solslot_api.config import Settings
from solslot_api.faucet import Faucet
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from solslot_api.redemption_review_store import RedemptionReviewStore
from solslot_puzzles.funded_redemption_v1 import FundedRedemptionAllocation, FundedRedemptionPlanV1, build_direct_redemption_acceptance
from solslot_puzzles.vault_driver import compact_signature_from_evm
from tests.test_chia_snapshot import Node, provider
from tests.test_sols_swap_execution import consensus

pytestmark = pytest.mark.asyncio
FIXTURE = json.loads((Path(__file__).parent / "fixtures/redemption-review.json").read_text())


def decode(value):
    if isinstance(value, str) and value.startswith("0x"):
        raw = bytes.fromhex(value[2:])
        return bytes32(raw) if len(raw) == 32 else raw
    if isinstance(value, list): return tuple(decode(item) for item in value)
    if not isinstance(value, dict): return value
    kind, raw = value.get("kind"), value.get("value")
    if kind == "coin": return Coin.from_json_dict(raw)
    if kind == "lineage": return LineageProof(decode(raw[0]), decode(raw[1]), uint64(raw[2]))
    if kind == "program": return Program.from_bytes(bytes.fromhex(raw[2:]))
    if kind in ("FundedRedemptionAllocation", "FundedRedemptionPlanV1"):
        cls = FundedRedemptionAllocation if kind == "FundedRedemptionAllocation" else FundedRedemptionPlanV1
        return cls(**{key: decode(item) for key, item in raw.items()})
    return {key: decode(item) for key, item in value.items()}


class Primary(Node):
    def __init__(self):
        super().__init__()
        self.spends = {}

    async def get_puzzle_and_solution(self, name, height):
        return self.spends.get(name)

    def include(self, bundle):
        for coin in bundle.additions():
            self.records[review.hx(coin.name())] = dict(coin=coin.to_json_dict(), confirmed_block_index=100,
                spent_block_index=0, spent=False)
        for spend in bundle.coin_spends:
            name = review.hx(spend.coin.name())
            self.records.setdefault(name, dict(coin=spend.coin.to_json_dict(), confirmed_block_index=10))
            self.records[name].update(spent_block_index=100, spent=True)
            self.spends[name] = spend.to_json_dict()


async def setup(monkeypatch, tmp_path, evm, binding_artifact=None):
    vector = FIXTURE["vectors"][int(evm)]
    args = decode(vector["args"])
    maker = Offer.from_bytes(bytes.fromhex(vector["makerOffer"][2:]))
    node = Primary()
    p = provider(node)
    faucet = Faucet.from_seed_hex("77" * 32, "testnet11")
    submitter = ProtocolBundleSubmitter(provider=p, faucet=faucet,
        policy=ProtocolFeePolicy(enabled=True, minimum_mojos=1, maximum_mojos=10000))
    fee = Coin(bytes32(b"f" * 32), faucet.address_puzzle_hash, uint64(10000))
    for coin in [maker.coin_spends()[0].coin, args["vault_coin"], args["deed_coin"], fee]:
        node.records[review.hx(coin.name())] = dict(coin=coin.to_json_dict(), confirmed_block_index=10,
            spent_block_index=0, spent=False)
    async def select(*_args, **_kwargs): return fee
    monkeypatch.setattr(submitter, "_select_fee_coin", select)
    settings = Settings(admin_db_path=str(tmp_path / "review.db"))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=p, protocol_submitter=submitter, settings=settings)))
    record = SimpleNamespace(id="synthetic-governed-redemption")
    queue = SimpleNamespace(get=lambda _: record)
    async def context(**kwargs):
        signature = compact_signature_from_evm(kwargs["owner_authorization"]) if kwargs.get("owner_authorization") else None
        return SimpleNamespace(record=record, plan=args["plan"], allocation=args["allocation"],
            leaf_coin=maker.coin_spends()[0].coin, maker_offer=maker,
            acceptance=build_direct_redemption_acceptance(**args, signature_data=signature),
            vault_record=SimpleNamespace(launcher_id=args["vault_launcher_id"], auth_type=args["vault_auth_type"]))
    monkeypatch.setattr(routes, "_find_redemption", lambda *_: (record, args["allocation"]))
    monkeypatch.setattr(routes, "_redemption_context", context)
    binding = dict(vaultLauncherId=review.hx(args["vault_launcher_id"]), ownerKey=vector["ownerAddress"],
        authType="evm" if evm else "chia_bls", sessionFingerprint="0x"+"55"*32, sessionExpiresAt=int(time())+1800,
        network="testnet11", artifactHash="0x"+"66"*32, apiCommit="a"*40, protocolCommit="b"*40)
    if binding_artifact is not None: binding["artifactHash"] = review.digest(binding_artifact)
    monkeypatch.setattr(review, "authority", lambda _r, _s, _q, _c, terms: {**binding, "action": "FUNDED_REDEMPTION", "allocationHash": review.digest(terms)})
    monkeypatch.setattr(review, "verify_vault_session", lambda *_: None)
    async def validate(job, *, bundle, network):
        assert job == "swap_signature" and network == "testnet11"
        consensus(SpendBundle.from_bytes(bytes(bundle)))
    monkeypatch.setattr(review, "run_offer_job", validate)
    prepared = await review.prepare_review(binding["vaultLauncherId"], review.hx(args["plan"].settlement_id),
        review.hx(args["allocation"].deed_launcher_id), request, settings, queue)
    body = routes.CompleteRedemption(operationHash=prepared["operationHash"],
        fundingReservationHash=prepared["fundingEvidence"]["reservationHash"], **vector["authorization"])
    return SimpleNamespace(vector=vector, args=args, node=node, provider=p, request=request, settings=settings,
        queue=queue, binding=binding, prepared=prepared, body=body, submitter=submitter)


async def complete(t):
    return await review.complete_review(t.prepared["vaultLauncherId"], t.prepared["settlementId"], t.prepared["deedLauncherId"],
                                       t.body, t.request, t.settings, t.queue)


@pytest.mark.parametrize("evm", [False, True], ids=["bls", "evm"])
@pytest.mark.parametrize("failure", ["none", "lost-response", "cancelled", "receipt-write"])
async def test_exact_redemption_is_durable_before_dispatch_and_resumes(monkeypatch, tmp_path, evm, failure):
    t = await setup(monkeypatch, tmp_path, evm)
    assert [item["role"] for item in t.prepared["currentStateEvidence"]["inputs"]] == ["redemption_leaf", "vault", "held_deed", "fee"]
    private = RedemptionReviewStore(t.settings.admin_db_path).funding(t.body.operation_hash)
    assert private["fundingBundle"]["aggregated_signature"] not in json.dumps(t.prepared)
    pushed = []
    async def push(raw, **kwargs):
        assert active_snapshot() is None
        bundle = SpendBundle.from_json_dict(raw)
        consensus(bundle)
        reopened = RedemptionReviewStore(t.settings.admin_db_path)
        assert reopened.execution(t.body.operation_hash)["spendBundleId"] == kwargs["required_spend_bundle_id"]
        assert reopened.reserved_input_coin_ids() == tuple(sorted(review.hx(s.coin.name()) for s in bundle.coin_spends))
        pushed.append(bytes(bundle))
        if failure != "cancelled" or len(pushed) > 1: t.node.include(bundle)
        if len(pushed) == 1:
            if failure == "lost-response": raise ChiaProviderError("synthetic lost response")
            if failure == "cancelled": raise asyncio.CancelledError()
        return dict(provider="synthetic-primary", observed_at="2026-09-17T00:00:00Z")
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", push)
    if failure == "receipt-write":
        monkeypatch.setattr(t.request.app.state.redemption_review_store, "mark_submitted", lambda *_: (_ for _ in ()).throw(ValueError("synthetic receipt failure")))
    if failure == "none": assert (await complete(t))["status"] == "CONFIRMED"
    else:
        with pytest.raises((ChiaProviderError, review.ProtocolSubmissionError, asyncio.CancelledError, ValueError)):
            await complete(t)
        t.request.app.state.redemption_review_store = RedemptionReviewStore(t.settings.admin_db_path)
        # Restart needs neither an owner signature nor a new context/fee coin.
        t.body = routes.CompleteRedemption(operationHash=t.body.operation_hash)
        async def forbidden(**_): raise AssertionError("must resume stored execution")
        monkeypatch.setattr(routes, "_redemption_context", forbidden)
        monkeypatch.setattr(t.submitter, "_select_fee_coin", forbidden)
        resumed = await complete(t)
        assert resumed["status"] in {"SUBMITTED", "CONFIRMED"}
        assert (await review.resume_execution(t.body.operation_hash, t.request, t.settings))["status"] == "CONFIRMED"
    assert len(set(pushed)) == 1
    assert not t.provider.fallback.calls
    assert RedemptionReviewStore(t.settings.admin_db_path).reserved_input_coin_ids() == ()


@pytest.mark.parametrize("evm", [False, True])
@pytest.mark.parametrize("change", ["session", "reservation", "spent", "branch", "fee-policy"])
async def test_changed_redemption_authority_refuses_dispatch(monkeypatch, tmp_path, evm, change):
    t = await setup(monkeypatch, tmp_path, evm)
    async def forbidden(*_, **__): raise AssertionError("must not dispatch")
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", forbidden)
    if change == "session": t.binding["sessionFingerprint"] = "0x"+"88"*32
    elif change == "reservation": t.body.funding_reservation_hash = "0x"+"88"*32
    elif change == "spent": t.node.records[t.prepared["fundingCoinId"]].update(spent=True, spent_block_index=99)
    elif change == "fee-policy": t.submitter.policy = review.replace(t.submitter.policy, target_seconds=900)
    else:
        original = t.node.get_coin_record_by_name
        async def branch(name):
            t.node.state["blockchain_state"]["peak"]["height"] += 1
            return await original(name)
        monkeypatch.setattr(t.node, "get_coin_record_by_name", branch)
    with pytest.raises((ValueError, ChiaProviderError)):
        await complete(t)
    assert RedemptionReviewStore(t.settings.admin_db_path).execution(t.body.operation_hash) is None


@pytest.mark.parametrize("evm", [False, True])
async def test_expired_saved_redemption_reconciles_then_requires_fresh_review(monkeypatch, tmp_path, evm):
    t = await setup(monkeypatch, tmp_path, evm)
    async def interrupted(*_, **__): raise asyncio.CancelledError()
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", interrupted)
    with pytest.raises(asyncio.CancelledError): await complete(t)
    store = RedemptionReviewStore(t.settings.admin_db_path)
    original = store.execution(t.body.operation_hash)
    assert original and store.reserved_input_coin_ids()
    # Both the wall clock and canonical primary transaction clock pass the
    # signed fee deadline. Every persistent input is still exactly unspent.
    future = t.prepared["reviewExpiresAt"] + 1
    import time as clock_module
    monkeypatch.setattr(clock_module, "time", lambda: future)
    monkeypatch.setattr(review, "time", lambda: future)
    from solslot_api import redemption_review_store as store_module
    monkeypatch.setattr(store_module, "time", lambda: future)
    t.node.clock = future
    t.request.app.state.redemption_review_store = store
    t.body = routes.CompleteRedemption(operationHash=t.body.operation_hash)
    async def forbidden(*_, **__): raise AssertionError("must not replay expired bytes")
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", forbidden)
    result = await complete(t)
    assert result["status"] == "EXPIRED"
    assert not store.reserved_input_coin_ids()
    assert store.expired_execution(t.body.operation_hash)["execution"] == original
    assert (await review.resume_execution(t.body.operation_hash, t.request, t.settings))["status"] == "EXPIRED"
    prepared = await review.prepare_review(t.prepared["vaultLauncherId"], t.prepared["settlementId"], t.prepared["deedLauncherId"],
                                           t.request, t.settings, t.queue)
    assert prepared["reviewExpiresAt"] > t.prepared["reviewExpiresAt"]
    assert prepared["fundingEvidence"]["reservationHash"] != t.prepared["fundingEvidence"]["reservationHash"]
    # A prior replay request cannot authorize the newly reviewed fee envelope.
    with pytest.raises(ValueError): await complete(t)
    assert store.execution(t.body.operation_hash) is None
    assert store.expired_execution(t.body.operation_hash)["execution"] == original
    t.body = routes.CompleteRedemption(operationHash=prepared["operationHash"],
        fundingReservationHash=prepared["fundingEvidence"]["reservationHash"], **t.vector["authorization"])
    async def included(raw, **_):
        bundle = SpendBundle.from_json_dict(raw)
        consensus(bundle)
        assert review.hx(bundle.name()) != original["spendBundleId"]
        t.node.include(bundle)
        return dict(provider="synthetic-primary", observed_at="2026-09-17T00:00:00Z")
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", included)
    assert (await complete(t))["status"] == "CONFIRMED"
    assert store.expired_execution(t.body.operation_hash)["execution"] == original
    # SQLite recovery preserves the immutable abandoned attempt and the distinct
    # confirmed successor execution, with no resurrected reservations.
    from tests.test_genesis_recovery import backup
    restored_path = tmp_path / "restored-redemption.db"
    backup(t.settings.admin_db_path, restored_path)
    restored = RedemptionReviewStore(str(restored_path))
    assert restored.expired_execution(t.body.operation_hash) == store.expired_execution(t.body.operation_hash)
    assert restored.execution(t.body.operation_hash) == store.execution(t.body.operation_hash)
    assert not restored.reserved_input_coin_ids()


@pytest.mark.parametrize("change", ["chain-clock", "spent", "missing", "pending", "branch", "session", "stale-attempt"])
async def test_expiry_reconciliation_retains_claims_on_ambiguous_state(monkeypatch, tmp_path, change):
    t = await setup(monkeypatch, tmp_path, False)
    async def interrupted(*_, **__): raise asyncio.CancelledError()
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", interrupted)
    with pytest.raises(asyncio.CancelledError): await complete(t)
    store = t.request.app.state.redemption_review_store
    original, claims = store.execution(t.body.operation_hash), store.reserved_input_coin_ids()
    future = t.prepared["reviewExpiresAt"] + 1
    import time as clock_module
    from solslot_api import redemption_review_store as store_module
    monkeypatch.setattr(clock_module, "time", lambda: future)
    monkeypatch.setattr(review, "time", lambda: future)
    monkeypatch.setattr(store_module, "time", lambda: future)
    t.node.clock = future
    t.body = routes.CompleteRedemption(operationHash=t.body.operation_hash)
    if change == "chain-clock": t.node.clock = future - 2
    elif change == "spent": t.node.records[t.prepared["fundingCoinId"]].update(spent=True, spent_block_index=99)
    elif change == "missing": del t.node.records[t.prepared["fundingCoinId"]]
    elif change == "pending": t.node.pending = [{"spend": "unresolved"}]
    elif change == "session":
        monkeypatch.setattr(review, "verify_vault_session", lambda *_: (_ for _ in ()).throw(ValueError("owner changed")))
    elif change == "branch":
        original_read = t.node.get_coin_record_by_name
        async def changed_tip(name):
            if active_snapshot(): t.node.state["blockchain_state"]["peak"]["header_hash"] = "88"*32
            return await original_read(name)
        monkeypatch.setattr(t.node, "get_coin_record_by_name", changed_tip)
    elif change == "stale-attempt":
        retire = store.reconcile_expired
        def stale(op, tx, observation): retire(op, "0x"+"88"*32, observation)
        monkeypatch.setattr(store, "reconcile_expired", stale)
    async def forbidden(*_, **__): raise AssertionError("must not dispatch")
    monkeypatch.setattr(t.provider, "push_tx_confirmed_in_primary_mempool", forbidden)
    with pytest.raises((ValueError, ChiaProviderError)): await complete(t)
    assert store.execution(t.body.operation_hash) == original
    assert store.expired_execution(t.body.operation_hash) is None
    assert store.reserved_input_coin_ids() == claims
