"""Synthetic CLVM outputs + real SQLite and submitter dispatch/replay contract.

No real fee key, RPC endpoint, signature or customer network outcome is used.
"""
import asyncio
import copy
from types import SimpleNamespace

import pytest
from chia_rs import G2Element, SpendBundle
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs.sized_ints import uint64

from solslot_api.inventory_timeout_submission import advance_inventory_timeout
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_api.protocol_submission import (
    PreparedProtocolBundle, ProtocolBundleSubmitter, ProtocolFeePolicy, ProtocolSubmissionError,
)
from solslot_api.chia_provider import ChiaProviderError
from tests.test_inventory_timeout_recovery import case, hx, record
from tests.test_native_purchases import _b32


class SyntheticSubmitter(ProtocolBundleSubmitter):
    def __init__(self, c):
        self.c = c; self.preparations = 0; self.pushed = []; self.ambiguous = False
        self.pause = None; self.entered = asyncio.Event()
        super().__init__(provider=self, faucet=SimpleNamespace(network="testnet11", address_hex=hx(_b32(91))),
                         policy=ProtocolFeePolicy(enabled=True))

    async def _prepare_locked(self, raw, *, selection_purpose=None):
        self.preparations += 1
        bundle = SpendBundle.from_json_dict(raw)
        puzzle = Program.to((1, [[51, _b32(93), 9]]))
        fee = Coin(_b32(90 + self.preparations), puzzle.get_tree_hash(), uint64(10))
        return PreparedProtocolBundle(
            SpendBundle([*bundle.coin_spends, make_spend(fee, puzzle, Program.to([]))], G2Element()), 1, hx(fee.name()))

    async def push_tx_confirmed_in_primary_mempool(self, raw, **kwargs):
        operations = self.c.store.inventory_timeout_operations(self.c.stored.purchase_id)
        assert any(op["prepared"]["spendBundle"] == raw for op in operations if op["prepared"])
        assert kwargs["required_coin_id"] in self.c.store.pending_timeout_fee_coin_ids()
        self.pushed.append(copy.deepcopy(raw)); self.entered.set()
        if self.pause is not None:
            await self.pause.wait()
        if self.ambiguous:
            raise ChiaProviderError("synthetic lost response after dispatch")
        return dict(provider="synthetic-primary", observed_at="synthetic", ambiguous_push=False)


def pending(tmp_path, quantity=1, version=2, state="CONFIRMED"):
    c = case(tmp_path, quantity, state=state, inventory_version=version)
    for release in c.releases:
        c.node.records[hx(release.spend.coin.name())] = record(release.spend.coin, 101)
        del c.node.records[hx(release.next_coin.name())]
    c.timestamp = c.stored.inventory_expires_at
    async def block(digest):
        return dict(success=True, block_record=dict(height=c.node.height, header_hash=digest,
                                                     timestamp=c.timestamp, prev_hash=hx(_b32(79))))
    c.node.get_block_record = block
    c.binding = dict(network="testnet11", artifactHash=hx(_b32(70)), sourceShas={"api": "ab"*20},
                     protocolTreasuryPuzzleHash=hx(c.contexts[0].terms.protocol_treasury_puzzle_hash),
                     validatorPubkeys=[hx(k) for k in c.contexts[0].terms.validator_pubkeys],
                     environment="staging-alpha", adapterVersion=1)
    c.submitter = SyntheticSubmitter(c)
    return c


async def advance(c, **kwargs):
    return await advance_inventory_timeout(store=c.store, node=c.node, submitter=c.submitter,
        purchase_id=c.stored.purchase_id, network="testnet11", release_binding=c.binding,
        authorize=kwargs.pop("authorize", lambda: None), **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("quantity", [1, 2])
async def test_exact_funded_dispatch_restart_replay_then_confirm(tmp_path, version, quantity):
    c = pending(tmp_path, quantity, version)
    c.submitter.ambiguous = True
    with pytest.raises(ProtocolSubmissionError):
        await advance(c)
    first = copy.deepcopy(c.submitter.pushed[0])
    op = c.store.inventory_timeout_operations(c.stored.purchase_id)[0]
    assert op["state"] == "PREPARED" and op["prepared"]["spendBundle"] == first
    c.store = PaymentPurchaseStore(c.store.path)
    c.submitter.ambiguous = False
    result = await advance(c)
    assert result["state"] == "RECOVERY_PENDING"
    assert c.submitter.pushed[1] == first
    assert c.submitter.preparations == quantity
    assert c.store.get(c.stored.purchase_id).inventory_state == "CONFIRMED"
    for release in c.releases:
        c.node.records[hx(release.spend.coin.name())] = record(release.spend.coin, 101, 104)
        c.node.records[hx(release.next_coin.name())] = record(release.next_coin, 104)
    result = await advance(c)
    assert result["state"] == "RELEASED"
    assert c.store.get(c.stored.purchase_id).inventory_bundle == c.stored.inventory_bundle
    assert len(c.store.pending_timeout_fee_coin_ids()) == quantity
    assert (await advance(c))["state"] == "RELEASED"


@pytest.mark.asyncio
async def test_partial_external_release_does_not_force_a_replacement_bundle(tmp_path):
    c = pending(tmp_path, 2)
    release = c.releases[0]
    c.node.records[hx(release.spend.coin.name())] = record(release.spend.coin, 101, 104)
    c.node.records[hx(release.next_coin.name())] = record(release.next_coin, 104)
    result = await advance(c)
    assert [i["state"] for i in result["items"]] == ["CONFIRMED", "SUBMITTED"]
    assert c.submitter.preparations == 1
    assert c.store.inventory_release_evidence(c.stored.purchase_id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", ["early", "wrong_network", "missing", "changed_source", "tip_change",
                                     "immature", "spent_elsewhere", "future", "wrong_environment", "outage", "other_deployment"])
async def test_preflight_failure_holds_all_inputs_and_does_not_fund(tmp_path, problem):
    c = pending(tmp_path, 2)
    if problem == "early": c.timestamp -= 1
    elif problem == "wrong_network": c.node.network = "mainnet"
    elif problem == "missing": del c.node.records[hx(c.releases[1].spend.coin.name())]
    elif problem == "changed_source": c.node.spends[(hx(c.transitions[1].spend.coin.name()), 101)]["solution"] = "0x80"
    elif problem == "tip_change": c.node.change_tip = True
    elif problem == "immature": c.node.height = 102
    elif problem == "future": c.node.height = 100
    elif problem == "wrong_environment": c.binding["environment"] = "production-beta"
    elif problem == "other_deployment": c.binding["protocolTreasuryPuzzleHash"] = hx(_b32(72))
    elif problem == "outage":
        async def offline(*_): raise OSError("synthetic outage")
        c.node.get_block_record = offline
    else:
        c.node.records[hx(c.releases[0].spend.coin.name())] = record(c.releases[0].spend.coin, 101, 104)
        c.node.spends[(hx(c.releases[0].spend.coin.name()), 104)]["solution"] = "0x80"
    with pytest.raises((PaymentPurchaseConflict, OSError)):
        await advance(c)
    assert c.submitter.preparations == 0 and not c.submitter.pushed
    assert all(i.state == "CONFIRMED" for i in c.store.inventory_items(c.stored.purchase_id))


@pytest.mark.asyncio
async def test_persistence_failure_means_no_push(tmp_path, monkeypatch):
    c = pending(tmp_path)
    def fail(*args, **kwargs): raise OSError("synthetic database unavailable")
    monkeypatch.setattr(c.store, "preserve_inventory_timeout", fail)
    with pytest.raises(OSError): await advance(c)
    assert not c.submitter.pushed


@pytest.mark.asyncio
async def test_concurrent_duplicate_cannot_prepare_or_dispatch_replacement(tmp_path):
    c = pending(tmp_path); c.submitter.pause = asyncio.Event()
    first = asyncio.create_task(advance(c))
    await c.submitter.entered.wait()
    with pytest.raises(PaymentPurchaseConflict, match="already in progress"):
        await advance(c)
    c.submitter.pause.set(); await first
    assert c.submitter.preparations == 1 and len(c.submitter.pushed) == 1


@pytest.mark.asyncio
async def test_changed_release_cannot_resume_existing_bundle(tmp_path):
    c = pending(tmp_path); await advance(c)
    c.binding["artifactHash"] = hx(_b32(71))
    with pytest.raises(PaymentPurchaseConflict, match="binding changed"):
        await advance(c)
    assert c.submitter.preparations == 1 and len(c.submitter.pushed) == 1


@pytest.mark.asyncio
async def test_revalidate_gate_before_dispatch(tmp_path):
    c = pending(tmp_path); calls = 0
    def authorize():
        nonlocal calls
        calls += 1
        if calls > 1: raise PaymentPurchaseConflict("operation gate expired")
    with pytest.raises(PaymentPurchaseConflict, match="gate expired"):
        await advance(c, authorize=authorize)
    assert not c.submitter.pushed


@pytest.mark.asyncio
async def test_nontransaction_peak_uses_hash_linked_ancestor_time(tmp_path):
    c = pending(tmp_path)
    async def block(digest):
        is_peak = digest == hx(_b32(80))
        return dict(success=True, block_record=dict(height=110 if is_peak else 109, header_hash=digest,
            timestamp=None if is_peak else c.timestamp, prev_hash=hx(_b32(79))))
    c.node.get_block_record = block
    assert (await advance(c))["state"] == "RECOVERY_PENDING"


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["PREPARED", "SUBMITTED", "CONFIRMED"])
@pytest.mark.parametrize("quantity", [1, 2])
async def test_never_confirmed_reservation_retains_exact_locks_after_clock_and_restart(tmp_path, state, quantity):
    c = pending(tmp_path, quantity=quantity, state=state)
    original_items = c.store.inventory_items(c.stored.purchase_id)
    original_bundle = copy.deepcopy(c.stored.inventory_bundle)
    c.node.records.clear(); c.timestamp += 100_000
    for _ in range(2):
        c.store = PaymentPurchaseStore(c.store.path)
        with pytest.raises(PaymentPurchaseConflict):
            await advance(c)
        retained = c.store.get(c.stored.purchase_id)
        assert retained.inventory_state == state
        assert retained.inventory_bundle == original_bundle
        assert retained.inventory_confirmation_height == (101 if state == "CONFIRMED" else None)
        assert c.store.inventory_items(c.stored.purchase_id) == original_items
        assert c.store.inventory_release_evidence(c.stored.purchase_id) is None
        for item in original_items:
            assert c.store.latest_released_inventory(item.deed_launcher_id) is None
    assert not c.submitter.pushed and c.submitter.preparations == 0


@pytest.mark.asyncio
async def test_timeout_reaches_real_provider_and_replays_exactly_after_rpc_timeout(tmp_path):
    from solslot_api.chia_provider import ChiaProvider, ChiaProviderConfig
    c = pending(tmp_path)
    pushed = []
    ambiguous = True
    mempool = {}
    async def push(raw):
        nonlocal ambiguous
        pushed.append(copy.deepcopy(raw))
        assert c.store.inventory_timeout_operations(c.stored.purchase_id)[0]["prepared"]["spendBundle"] == raw
        if ambiguous:
            raise TimeoutError("synthetic unknown delivery")
        bundle = SpendBundle.from_json_dict(raw)
        for coin in bundle.removals():
            mempool[hx(coin.name())] = [{"spend_bundle_name": hx(bundle.name())}]
        return dict(success=True, status="SUCCESS")
    async def observe(coin_id): return mempool.get(coin_id, [])
    c.node.push_tx = push; c.node.get_mempool_items_by_coin_name = observe
    provider = ChiaProvider(c.node, c.node, ChiaProviderConfig(network="testnet11", primary_url="http://synthetic.invalid", fallback_url="http://unused.invalid"))
    await provider.start()
    c.submitter.provider = provider
    c.submitter.policy = ProtocolFeePolicy(enabled=True, mempool_timeout_seconds=0.01, mempool_poll_seconds=0.001)
    with pytest.raises(ProtocolSubmissionError): await advance(c)
    assert len(pushed) == 1
    c.store = PaymentPurchaseStore(c.store.path)
    ambiguous = False
    result = await advance(c)
    assert result["state"] == "RECOVERY_PENDING" and len(pushed) == 2 and pushed[0] == pushed[1]
    assert c.submitter.preparations == 1


@pytest.mark.asyncio
async def test_timeout_endpoint_enforces_service_token_write_gate_and_primary(tmp_path):
    from solslot_api.config import Settings
    from solslot_api import native_purchases as native
    from fastapi import HTTPException
    c = pending(tmp_path)
    settings = Settings(_env_file=None, network="testnet11", runtime_environment="test",
        alpha_writes_enabled=True, minting_enabled=True, protocol_artifact_api_token="synthetic-test-token",
        payment_purchase_db_path=c.store.path)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node)))
    payload = native.InventoryReservationRequest(purchaseId=c.stored.purchase_id)
    with pytest.raises(HTTPException) as exc:
        await native.resume_inventory_timeout(payload, request, settings, "Bearer wrong")
    assert exc.value.status_code in (401,403)
    settings.alpha_writes_enabled = False
    with pytest.raises(HTTPException):
        await native.resume_inventory_timeout(payload, request, settings, "Bearer synthetic-test-token")
    settings.alpha_writes_enabled = True
    with pytest.raises(HTTPException) as exc:
        await native.resume_inventory_timeout(payload, request, settings, "Bearer synthetic-test-token")
    assert exc.value.status_code == 503
    assert not c.submitter.pushed
