"""Original-puzzle two-deed card coverage with a local primary, till and two ephemeral signers."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from chia_rs import Coin, SpendBundle, G2Element
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from solslot_puzzles.payment_artifacts_v3 import (
    StripeSettlementEvidenceV1,
    StripeFundingType,
    StripeDisputeState,
    StripeRefundState,
    StripeMethodFamily,
    StripePaymentStatus,
    stripe_settlement_evidence_to_json,
)

from solslot_api import (
    vault_card_settlement as settlement,
    vault_stripe_protection as cover,
)
from solslot_api import generation_index, generation_preparation, credential_auth
from solslot_api.vault_card_funding_store import ROLES, hx
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from solslot_api.faucet import Faucet
from solslot_api.inventory_recovery import timeout_items
from solslot_api.stripe_delivery_store import get_stripe_delivery_store
from solslot_api.stripe_delivery_worker import (
    StripeDeliveryWorker,
    StripeDeliveryWorkerConfig,
)
from solslot_api.vault_card_events import queue_delivery
from solslot_api.vault_card_provider import metadata
from tests.test_current_stripe_order import b
from tests.test_vault_card_checkout import setup
from tests.test_inventory_timeout_recovery import Node, record


async def fixture(tmp_path, monkeypatch):
    from solslot_api import vault_card_reservations

    original_submit = vault_card_reservations.submit_reservation
    x = setup(tmp_path, monkeypatch)
    anchor = SimpleNamespace(issuance=SimpleNamespace(generation=x.r.generation))
    x.r.customers.index.anchor = anchor
    from solslot_api import vault_card_native

    monkeypatch.setattr(
        vault_card_native, "load_generation_read_anchor", lambda _: anchor
    )
    ev = await x.n.reconstruct(x.r.customers, x.r.snapshot)
    o = ev.order
    till = Faucet.from_seed_hex("21" * 32, "testnet11")
    fondos = ProtocolFundingStore(str(tmp_path / "fund.db"))
    p = x.r.provider
    node = Node()
    node.height = 139
    node.records = x.r.records
    node.get_puzzle_and_solution = AsyncMock(
        side_effect=lambda cid, hgt: x.r.spends.get(cid)
    )
    node.get_mempool_items_by_coin_name = AsyncMock(return_value=[])
    clock = [x.now]
    node.get_block_record = AsyncMock(
        side_effect=lambda digest: dict(
            success=True,
            block_record={
                "height": node.height,
                "header_hash": digest,
                "timestamp": clock[0],
            },
        )
    )
    p.primary = node
    coins = [Coin(b(i), till.address_puzzle_hash, 100 + i) for i in range(70, 76)]
    for coin in coins:
        node.records[hx(coin.name())] = record(coin, 115)
    p.get_coin_records_by_puzzle_hash = AsyncMock(
        side_effect=lambda *_a, **_kw: [node.records[hx(c.name())] for c in coins]
    )
    p.get_coin_record_by_name = p.get_coin_record_by_name_primary
    p.get_mempool_items_by_coin_name = node.get_mempool_items_by_coin_name
    p.get_fee_estimate = AsyncMock(
        side_effect=lambda **kw: {"target_times": kw["target_times"], "estimates": [7]}
    )
    p.push_tx_confirmed_in_primary_mempool = AsyncMock(
        return_value=dict(provider="local", observed_at="local", ambiguous_push=False)
    )
    sub = ProtocolBundleSubmitter(
        provider=p,
        faucet=till,
        policy=ProtocolFeePolicy(
            enabled=True, maximum_mojos=100, maximum_funding_coin_mojos=1000
        ),
        funding_store=fondos,
    )
    x.s.faucet_max_spend_mojos = 1000
    x.s.runtime_environment = "staging"
    x.s.vault_card_delivery_enabled = True
    x.s.stripe_settlement_enabled = x.s.stripe_delivery_worker_enabled = (
        x.s.protocol_fee_funding_enabled
    ) = False
    exact = SimpleNamespace(
        release_ready=AsyncMock(return_value=True),
        dispatch=AsyncMock(return_value={"accepted": True}),
    )
    worker = StripeDeliveryWorker(
        settings=x.s,
        faucet=till,
        provider=p,
        submitter=sub,
        exact_executor=exact,
        store=get_stripe_delivery_store(x.s.stripe_delivery_db_path),
        config=StripeDeliveryWorkerConfig(enabled=True),
    )
    monkeypatch.setattr(worker, "recent_stripe_queue_pass", lambda: True)
    x.app.state.stripe_delivery_worker = worker
    x.app.state.protocol_submitter = sub
    monkeypatch.setattr(
        generation_index, "load_generation_read_anchor", lambda _: anchor
    )
    monkeypatch.setattr(
        generation_preparation,
        "read_generation_preparation",
        lambda _: SimpleNamespace(
            generation_id=o.generation_id,
            source_commits={"keyOfSolomon": "01" * 20, "api": "02" * 20},
        ),
    )
    roster = x.s.zkpassport_validator_pubkeys
    artifact = dict(
        network=o.network,
        artifactHash=o.genesis_artifact_hash,
        sourceShas={"api": "01" * 20},
        validatorSet={"pubkeys": roster, "threshold": 2},
        puzzleHashes={
            "protocolTreasuryPuzzleHash": hx(
                ev.items[0].terms.protocol_treasury_puzzle_hash
            )
        },
    )
    valid = [True, True, False]

    def ready(request):
        i = ["one.invalid", "two.invalid", "three.invalid"].index(request.url.host)
        assert (
            request.method == "GET"
            and request.url.path == "/v1/generation/vault-card/ready"
        )
        return httpx.Response(
            200,
            json=dict(
                releaseId=o.release_id,
                purchaseId=o.purchase_id,
                batchHash=o.batch_hash,
                reservedCoinIds=list(o.reserved_coin_ids),
                network=o.network,
                signerIndex=i,
                validatorPubkey=roster[i],
            )
            if valid[i]
            else {},
        )

    monkeypatch.setattr(
        settlement,
        "_private_validator_client",
        lambda _: httpx.AsyncClient(transport=httpx.MockTransport(ready)),
    )
    monkeypatch.setattr(vault_card_reservations, "submit_reservation", original_submit)
    async with x.client as client:
        client.cookies.set(credential_auth.VAULT_SESSION_COOKIE, x.r.token)
        client.headers["Origin"] = x.s.vault_card_return_origin
        args = dict(purchaseId=o.purchase_id, batchHash=o.batch_hash, intent="prepare")
        assert (await client.post(x.url + "/checkout", json=args)).status_code == 200
    x.confirm_chain(ev)
    await x.service.advance(x.app, x.r.customers, x.r.snapshot, o)
    x.s.alpha_writes_enabled = x.s.minting_enabled = False
    p.push_tx_confirmed_in_primary_mempool.reset_mock()
    return SimpleNamespace(**locals())


def allocate(f):
    return cover.allocate_current_card_coverage(f.x.app, f.x.s, f.o, now=f.clock[0])


def paid(f):
    pid = "pi_isolated123"
    cover.bind_card_payment(f.x.app, f.o, pid)
    e = StripeSettlementEvidenceV1(
        stripe_account_id=f.o.account_id,
        livemode=False,
        payment_intent_id=pid,
        event_id="evt_isolated123",
        amount_minor=f.o.amount_minor,
        currency="usd",
        method_family=StripeMethodFamily.CARD,
        funding_type=StripeFundingType.CREDIT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=f.x.now,
    )
    op = queue_delivery(f.x.s, f.o, stripe_settlement_evidence_to_json(e))
    return pid, op


@pytest.mark.asyncio
async def test_precharge_validators_exact_inputs_and_pool_exclusion(
    tmp_path, monkeypatch
):
    f = await fixture(tmp_path, monkeypatch)

    async def ready():
        return await cover.current_card_coverage(f.x.app, f.x.s, f.o, now=f.x.now)

    assert not await ready()
    f.valid[1] = False
    with pytest.raises(ValueError, match="independent validators"):
        await allocate(f)
    assert not f.fondos.cards.get(f.o.purchase_id)
    f.valid[1] = True
    assert await allocate(f) and await ready()
    old = f.fondos.cards.get(f.o.purchase_id)
    assert (
        set(old["coins"]) == set(ROLES) | {"deed_0", "deed_1"}
        and len(f.fondos.reserved_coin_ids()) == 10
    )
    assert await allocate(f)
    for field, v in [
        ("owner_key", "0x12"),
        ("account_id", "acct_Other"),
        ("credential_root", hx(b(70))),
        ("amount_minor", 1),
        ("release_id", hx(b(71))),
        ("reserved_coin_ids", tuple(reversed(f.o.reserved_coin_ids))),
    ]:
        assert not await cover.current_card_coverage(
            f.x.app, f.x.s, replace(f.o, **{field: v}), now=f.x.now
        )
    assert not await cover.current_card_coverage(
        f.x.app, f.x.s, f.o, now=f.o.expires_at - 1919
    )
    f.node.get_mempool_items_by_coin_name.side_effect = lambda cid: (
        [{}] if cid == hx(old["coins"]["delivery_fee"].name()) else []
    )
    assert not await ready()
    f.node.get_mempool_items_by_coin_name.side_effect = None
    assert await ready()
    coin = old["coins"]["return_0"]
    protocol = SpendBundle(
        [make_spend(coin, f.till.key.puzzle, Program.to([]))], G2Element()
    )
    with pytest.raises(ValueError, match="active card"):
        f.fondos.reserve(
            f.o.network,
            hx(protocol.name()),
            {},
            dict(
                spendBundle=protocol.to_json_dict(), spendBundleId=hx(protocol.name())
            ),
        )
    contender = ProtocolFundingStore(f.fondos.path)

    def compete():
        contender.cards.allocate(
            {**old["binding"], "purchase_id": hx(b(78))},
            old["till"],
            old["cap"],
            {role: old["coins"][role] for role in ROLES},
            [old["coins"]["deed_0"], old["coins"]["deed_1"]],
        )

    with ThreadPoolExecutor(2) as executor:
        with pytest.raises(ValueError):
            executor.submit(compete).result()
    assert contender.cards.get(hx(b(78))) is None


@pytest.mark.asyncio
async def test_paid_native_receipt_and_exact_fee_replay(tmp_path, monkeypatch):
    f = await fixture(tmp_path, monkeypatch)
    await allocate(f)
    pid, op = paid(f)
    cover.bind_card_payment(f.x.app, f.o, pid)
    with pytest.raises(ValueError):
        cover.bind_card_payment(f.x.app, f.o, "pi_other123")
    op = await f.worker._advance(op)
    row = f.fondos.cards.get(f.o.purchase_id)
    assert op.receipt_funding_input_coin_id == hx(row["coins"]["receipt_parent"].name())
    a = await cover.prepare_stage(f.worker, f.o.purchase_id, "receipt_fee")
    assert a.fee_mojos == 7 and a.fee_coin_id == hx(row["coins"]["receipt_fee"].name())
    assert len(set(a.bundle.additions())) == len(a.bundle.additions())
    assert (
        sum(c.amount for c in a.bundle.removals())
        - sum(c.amount for c in a.bundle.additions())
        == 7
    )
    group = await settlement.group(f.worker, op)
    assert [hx(c.deed_coin.name()) for c in group.contexts] == list(
        f.o.reserved_coin_ids
    )
    f.sub.funding_store = ProtocolFundingStore(f.fondos.path)
    assert (
        await cover.prepare_stage(f.worker, f.o.purchase_id, "receipt_fee")
    ).to_json() == a.to_json()
    f.fondos.cards.transition(f.o.purchase_id, pid, {"PAID"}, "RETURNING")
    with pytest.raises(ValueError):
        await cover.prepare_stage(f.worker, f.o.purchase_id, "receipt_fee")


@pytest.mark.asyncio
@pytest.mark.parametrize("is_paid", [False, True])
async def test_expired_two_deed_chain_recovery_and_restart(
    tmp_path, monkeypatch, is_paid
):
    f = await fixture(tmp_path, monkeypatch)
    await allocate(f)
    row = f.fondos.cards.get(f.o.purchase_id)
    pid, _ = paid(f) if is_paid else (None, None)
    f.x.app.state.vault_card_checkout = None
    monkeypatch.setattr(f.worker, "current_card_order", lambda: None)

    async def recover():
        if is_paid:
            return await cover.prepare_card_refund(
                f.x.app, f.x.s, f.o, pid, now=f.clock[0]
            )
        return await cover.prepare_unpaid_release(
            f.x.app, f.x.s, f.o, now=f.clock[0], session_evidence=None
        )

    assert not await recover()
    f.clock[0] = f.o.expires_at
    f.node.get_mempool_items_by_coin_name.side_effect = lambda cid: (
        [{}] if cid == f.o.reserved_coin_ids[1] else []
    )
    assert not await recover()
    assert not f.p.push_tx_confirmed_in_primary_mempool.await_count
    f.node.get_mempool_items_by_coin_name.side_effect = None
    assert not await recover()
    ops = f.x.purchases.inventory_timeout_operations(f.o.purchase_id)
    assert len(ops) == 2 and {op["prepared"]["feeCoinId"] for op in ops} == {
        hx(row["coins"][k].name()) for k in ("return_0", "return_1")
    }
    assert f.fondos.cards.get(f.o.purchase_id)["state"] == (
        "RETURNING" if is_paid else "UNPAID_RETURNING"
    )
    if is_paid:
        with pytest.raises(ValueError):
            cover.mark_card_refunded(f.x.app, f.o, pid, "re_Early")
    items = timeout_items(f.x.purchases, f.o.purchase_id)
    f.sub.funding_store = ProtocolFundingStore(f.fondos.path)

    def confirm(item, height):
        coin = item.release_spend.coin
        f.node.records[hx(coin.name())] = record(coin, 121, height)
        f.node.records[hx(item.successor.name())] = record(item.successor, height)
        f.x.r.spends[hx(coin.name())] = item.release_spend.to_json_dict()

    confirm(items[0], 132)
    assert not await recover()
    confirm(items[1], 139)
    assert not await recover()
    f.node.height = 145
    assert await recover() and await recover()
    if is_paid:
        cover.mark_card_refunded(f.x.app, f.o, pid, "re_LocalRefund")
        cover.mark_card_refunded(f.x.app, f.o, pid, "re_LocalRefund")
        with pytest.raises(ValueError):
            f.fondos.cards.transition(
                f.o.purchase_id, pid, {"REFUNDED"}, "DELIVERED", {"height": 145}
            )
    else:
        with pytest.raises(ValueError):
            cover.bind_card_payment(f.x.app, f.o, "pi_tooLate")
    assert f.fondos.cards.get(f.o.purchase_id)["state"] == (
        "REFUNDED" if is_paid else "ABANDONED"
    )
    assert all(
        hx(row["coins"][r].name()) not in f.fondos.reserved_coin_ids()
        for r in ("receipt_parent", "receipt_fee", "delivery_fee")
    )


@pytest.mark.asyncio
async def test_scoped_worker_paid_delivery_and_terminal_refund_exclusion(
    tmp_path, monkeypatch
):
    import json
    from chia_rs import PrivateKey
    from solslot_api import validator_service as signer, validator_quorum as quorum
    from solslot_api.stripe_delivery_store import FINALIZED
    from solslot_puzzles.vault_driver import puzzle_for_p2_vault
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
        SINGLETON_MOD,
        SINGLETON_MOD_HASH,
    )

    f = await fixture(tmp_path, monkeypatch)
    await allocate(f)
    assert not f.worker._writes_are_open()
    foreign = f.worker.store.queue(
        purchase_id=hx(b(82)),
        evidence={"paymentIntentId": "pi_other123"},
        receipt_hash=hx(b(83)),
    )
    assert await f.worker.reconcile_once(foreign.purchase_id) is None
    assert f.worker.store.get(foreign.purchase_id).attempt_count == 0
    pid, op = paid(f)
    signed = []

    def provider_read(request):
        assert request.headers["stripe-version"] == "2026-02-25.clover"
        intent = dict(
            id=pid,
            amount=f.o.amount_minor,
            amount_received=f.o.amount_minor,
            currency="usd",
            created=f.x.now,
            livemode=False,
            status="succeeded",
            metadata=metadata(f.o),
            latest_charge=dict(
                payment_intent=pid,
                id="ch_Local",
                paid=True,
                livemode=False,
                status="succeeded",
                amount=f.o.amount_minor,
                currency="usd",
                refunded=False,
                disputed=False,
                amount_refunded=0,
                payment_method_details={"type": "card", "card": {"funding": "credit"}},
            ),
        )
        event = dict(
            id="evt_isolated123",
            livemode=False,
            type="payment_intent.succeeded",
            data={"object": {"id": pid}},
        )
        assert request.url.path in (
            "/v1/events/evt_isolated123",
            "/v1/payment_intents/" + pid,
        )
        return httpx.Response(
            200, json=intent if "payment_intents" in request.url.path else event
        )

    real_client = httpx.Client
    monkeypatch.setattr(
        signer.httpx,
        "Client",
        lambda **kw: real_client(**kw, transport=httpx.MockTransport(provider_read)),
    )
    monkeypatch.setattr(
        signer,
        "load_stripe_restricted_key",
        lambda _s, *, current_card: "simulated" if current_card else None,
    )
    monkeypatch.setattr(
        signer,
        "load_validator_private_key",
        lambda s: PrivateKey.from_bytes((s.signer_index + 1).to_bytes(32, "big")),
    )
    monkeypatch.setattr(signer, "_fetch_coin", lambda s, c, *a, **kw: f.node.records[c])

    async def signer_request(request):
        assert request.url.path == "/v1/generation/vault-card/settlement"
        i = ["one.invalid", "two.invalid", "three.invalid"].index(request.url.host)
        if i == 2:
            return httpx.Response(503)
        s = SimpleNamespace(
            **{
                **vars(f.x.s),
                "vault_card_settlement_enabled": True,
                "signer_index": i,
                "roster_pubkeys": f.roster,
                "bridge_policy_hash": f.o.bridge_policy_hash,
            }
        )
        raw = json.loads(request.content)
        claim = quorum.StripeSettlementClaim.model_validate(raw["claim"])
        proof = await settlement.validator_proof(s, f.p)
        with pytest.raises(ValueError):
            proof.require_claim(
                claim.model_copy(update={"credential_vault_coin_id": hx(b(17))})
            )
        proof = await proof.bind_receipt(claim, f.p)
        signature = signer.sign_stripe_settlement_claim(
            s, f.x.ledgers[i], claim, raw["claimHash"], current=proof
        )
        signed.append(i)
        return httpx.Response(
            200,
            json=dict(
                claimHash=raw["claimHash"],
                signerIndex=i,
                validatorPubkey=f.roster[i],
                signature=signature,
            ),
        )

    monkeypatch.setattr(
        quorum,
        "_private_validator_client",
        lambda _s: httpx.AsyncClient(transport=httpx.MockTransport(signer_request)),
    )

    def mined(bundle, height):
        for coin in bundle.additions():
            f.node.records[hx(coin.name())] = record(coin, height)
        for coin in bundle.removals():
            prior = f.node.records[hx(coin.name())]
            f.node.records[hx(coin.name())] = record(
                coin, prior["confirmed_block_index"], height
            )

    async def advance(expected):
        op = await f.worker.reconcile_once()
        assert op and op.state == expected, (op.state, op.last_error) if op else None
        return op

    op = await advance("RECEIPT_FUNDING_PREPARED")
    op = await advance("RECEIPT_FUNDING_SUBMITTED")
    mined(
        SpendBundle.from_json_dict(op.receipt_funding_exact_bundle["spendBundle"]), 140
    )
    op = await advance("RECEIPT_CONFIRMED")
    op = await advance("DELIVERY_PREPARED")
    assert signed == [0, 1]
    op = await advance("DELIVERY_SUBMITTED")
    saved = SpendBundle.from_json_dict(op.delivery_exact_bundle["spendBundle"])
    assert (
        len(set(op.expected_deed_output_coin_ids))
        == len(set(op.expected_treasury_output_coin_ids))
        == 2
    )
    outputs = {hx(c.name()): c for c in saved.additions()}
    assert len(outputs) == len(saved.additions())
    for item, cid in zip(f.ev.items, op.expected_deed_output_coin_ids, strict=True):
        terms = item.terms
        full = Program.to(
            (
                SINGLETON_MOD_HASH,
                (terms.deed_launcher_id, terms.deed_launcher_puzzle_hash),
            )
        )
        assert (
            outputs[cid].puzzle_hash
            == SINGLETON_MOD.curry(
                full, puzzle_for_p2_vault(f.x.r.launcher)
            ).get_tree_hash()
        )
        assert (
            outputs[cid].amount == 1
            and terms.protocol_treasury_puzzle_hash.hex()
            == f.o.technology_fee_puzzle_hash[2:]
        )
    assert all(
        outputs[c].puzzle_hash.hex() == f.o.primary_proceeds_puzzle_hash[2:]
        for c in op.expected_treasury_output_coin_ids
    )
    assert f.worker.exact_executor.dispatch.await_count == 2
    mined(saved, 145)
    op = await advance(FINALIZED)
    assert (
        op.confirmation_height == 145
        and f.fondos.cards.get(f.o.purchase_id)["state"] == "DELIVERED"
    )
    assert not await cover.prepare_card_refund(
        f.x.app, f.x.s, f.o, pid, now=f.o.expires_at + 1
    )
    assert f.worker.store.get(foreign.purchase_id).attempt_count == 0


@pytest.mark.asyncio
async def test_lost_dispatch_and_known_expired_session_are_distinct(
    tmp_path, monkeypatch
):
    from solslot_api.vault_card_provider import session_params

    f = await fixture(tmp_path, monkeypatch)
    await allocate(f)
    issued = f.x.store
    issued.begin_dispatch(
        f.o, session_params(f.o, f.x.s.vault_card_return_origin, f.x.now), now=f.x.now
    )
    unbound = issued.get(f.o.purchase_id)
    f.clock[0] = f.o.expires_at
    assert not await cover.prepare_unpaid_release(
        f.x.app, f.x.s, unbound, now=f.clock[0], session_evidence=None
    )
    recovered = issued.bind_session(
        f.o.purchase_id, "cs_test_Known0123", "pi_cancelled123"
    )
    session = dict(
        id=recovered.session_id,
        object="checkout.session",
        mode="payment",
        livemode=False,
        currency="usd",
        amount_total=recovered.amount_minor,
        client_reference_id=recovered.purchase_id,
        metadata=metadata(recovered),
        expires_at=recovered.session_expires_at,
        status="expired",
        payment_status="unpaid",
        payment_method_types=["card"],
        payment_intent=recovered.payment_intent_id,
    )
    intent = dict(
        id=recovered.payment_intent_id,
        object="payment_intent",
        status="canceled",
        amount_received=0,
        livemode=False,
        amount=recovered.amount_minor,
        currency="usd",
        metadata=metadata(recovered),
    )

    async def reclaim(s, i):
        return await cover.prepare_unpaid_release(
            f.x.app,
            f.x.s,
            recovered,
            now=f.clock[0],
            session_evidence={"session": s, "payment_intent": i},
        )

    assert not await reclaim({**session, "status": "open"}, intent)
    assert not await reclaim(session, None)
    assert not await reclaim(session, {**intent, "status": "processing"})
    assert not await reclaim(session, {**intent, "amount_received": 1})
    assert not f.p.push_tx_confirmed_in_primary_mempool.await_count
    assert not await reclaim(session, intent)
    assert f.p.push_tx_confirmed_in_primary_mempool.await_count == 2


@pytest.mark.asyncio
async def test_executor_pin_and_release_cap_fail_precharge(tmp_path, monkeypatch):
    f = await fixture(tmp_path, monkeypatch)
    f.exact.release_ready.return_value = False
    with pytest.raises(ValueError, match="executor"):
        await allocate(f)
    f.exact.release_ready.assert_awaited_with("01" * 20)
    assert not f.fondos.cards.get(f.o.purchase_id)
    f.exact.release_ready.return_value = True
    release = f.x.n.scope
    for wrong in (
        release.model_copy(update={"maximumFeePerStageMojos": 1}),
        release.model_copy(update={"maximumTotalFeeMojos": 405}),
    ):
        with pytest.raises(ValueError):
            cover.reservation_fee(f.worker, f.o, wrong)


@pytest.mark.asyncio
async def test_private_worker_construction_leaves_legacy_fee_and_queue_closed(
    tmp_path, monkeypatch
):
    from solslot_api.vault_card_runtime import build_worker
    from solslot_api.kos_exact_execution import KeyOfSolomonExactExecutor

    f = await fixture(tmp_path, monkeypatch)
    cfg = f.x.s
    private = tmp_path / "local-test-till"
    private.write_text("22" * 32)
    private.chmod(0o600)
    cfg.vault_card_fee_seed_file = str(private)
    cfg.vault_card_fee_puzzle_hash = Faucet.from_seed_hex(
        "22" * 32, "testnet11"
    ).address_hex
    cfg.chia_primary_url = "https://primary.invalid"
    cfg.protocol_maximum_fee_mojos = cfg.protocol_minimum_fee_mojos = 7
    cfg.protocol_medium_fee_target_seconds = 60
    cfg.protocol_fee_estimate_buffer_bps = 10000
    cfg.protocol_fee_native_admission_enabled = cfg.protocol_fee_cost_tiers_enabled = (
        False
    )
    cfg.protocol_mempool_timeout_seconds = 10
    cfg.protocol_mempool_poll_seconds = 0.1
    cfg.stripe_delivery_interval_seconds = 2
    cfg.stripe_delivery_lease_seconds = 120
    cfg.voucher_issuance_worker_enabled = False
    state = SimpleNamespace(
        faucet=None,
        protocol_funding_store=f.fondos,
        protocol_submitter=None,
        coinset=f.p,
    )
    app = SimpleNamespace(state=state)
    worker = build_worker(app, cfg, f.exact)
    assert state.protocol_submitter is None and state.faucet is None
    assert (
        worker.submitter.policy.maximum_mojos == 7
        and worker.current_card_order() == f.o
    )
    cfg.vault_card_fee_key_kind = "master"
    with pytest.raises(ValueError, match="funding address"):
        build_worker(app, cfg, f.exact)
    cfg.vault_card_fee_puzzle_hash = Faucet.from_master_private_key_hex("22" * 32, "testnet11").address_hex
    assert build_worker(app, cfg, f.exact).faucet.address_hex == cfg.vault_card_fee_puzzle_hash
    cfg.vault_card_fee_key_kind = "seed"
    with pytest.raises(ValueError, match="funding address"):
        build_worker(app, cfg, f.exact)
    cfg.vault_card_fee_puzzle_hash = worker.faucet.address_hex
    assert not worker._writes_are_open()
    assert not worker.recent_stripe_queue_pass()
    import asyncio

    await worker.start()
    try:
        for _ in range(20):
            if worker.recent_stripe_queue_pass():
                break
            await asyncio.sleep(0.02)
        assert worker.recent_stripe_queue_pass()
    finally:
        await worker.stop()
    assert not worker.recent_stripe_queue_pass()
    cfg.alpha_writes_enabled = True
    with pytest.raises(ValueError):
        build_worker(app, cfg, f.exact)
    cfg.alpha_writes_enabled = False
    cfg.vault_card_fee_puzzle_hash = hx(b(15))
    with pytest.raises(ValueError, match="funding address"):
        build_worker(app, cfg, f.exact)
    real = httpx.AsyncClient
    healthy = {
        "status": "ok",
        "releaseSha": "01" * 20,
        "executionMode": "exact-bundle-v2-only",
    }
    seen = []

    def remote(request):
        seen.append(request)
        return httpx.Response(200, json=healthy)

    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(remote))
    )
    executor = object.__new__(KeyOfSolomonExactExecutor)
    executor.url = "https://exact.invalid"
    executor.timeout_seconds = 1
    executor.verify = True
    executor.cert = None
    assert await executor.release_ready("01" * 20)
    assert not await executor.release_ready("02" * 20)
    healthy["executionMode"] = "other"
    assert not await executor.release_ready("01" * 20)
    assert len(seen) == 3 and all(
        req.method == "GET" and req.url.path == "/healthz" and not req.content
        for req in seen
    )
