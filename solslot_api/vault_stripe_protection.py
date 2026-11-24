"""Vault-owned card Testnet allocation, exact fee spending, and confirmed two-deed recovery."""

from dataclasses import asdict
import time

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle
from .protocol_submission import PreparedProtocolBundle
from .vault_card_funding_store import CardFundingJournal, ROLES, hx
from .inventory_recovery import timeout_items, release_peak
from .inventory_timeout_submission import (
    inspect_item,
    canonical_time,
    advance_inventory_timeout,
)
from .payment_purchase_store import get_payment_purchase_store
from .generation_coin_evidence import read_confirmed_coin


def check(condition, reason):
    if not condition:
        raise ValueError(reason)


def bound(order):
    order.check()
    doc = asdict(order)
    for key in ("session_id", "payment_intent_id", "session_expires_at", "batch"):
        doc.pop(key, None)
    for key in ("deed_launcher_ids", "reserved_coin_ids", "original_coin_ids"):
        doc[key] = list(doc[key])
    check(
        (order.network, order.mode) in {("testnet11", "test"), ("mainnet", "live")}
        and len(order.deed_launcher_ids) == 2
        and order.currency == "usd",
        "Approved private card order differs",
    )
    return doc


def work(app, order, *, recovery=False):
    from .vault_card_store import VaultCardStore

    worker = app.state.stripe_delivery_worker
    check(worker is not None, "Card worker is unavailable")
    settings = worker.settings
    if recovery:
        current = VaultCardStore(settings.payment_purchase_db_path).get(
            order.purchase_id
        )
        check(
            settings.vault_card_delivery_enabled
            and not settings.alpha_writes_enabled
            and not settings.minting_enabled
            and not settings.stripe_settlement_enabled
            and not settings.protocol_fee_funding_enabled
            and not settings.stripe_delivery_worker_enabled
            and (
                settings.network,
                settings.stripe_mode,
                settings.stripe_account_id,
                settings.deployment_generation_id,
                settings.generation_chain_anchor_hash,
            )
            == (
                order.network,
                order.mode,
                order.account_id,
                order.generation_id,
                order.generation_anchor_hash,
            ),
            "Retained card recovery belongs to another deployment",
        )
    else:
        current = worker.current_card_order()
    check(
        current
        and worker.settings.network == worker.faucet.network
        and bound(current) == bound(order)
        and worker.submitter.provider is worker.provider
        and worker.submitter.faucet is worker.faucet
        and worker.submitter.policy.enabled
        and worker.submitter.funding_store is not None
        and worker.exact_executor is not None,
        "Card execution is unavailable",
    )
    return worker


def card(worker, purchase):
    funds = getattr(worker.submitter, "funding_store", None)
    return (
        funds.cards.get(purchase)
        if isinstance(getattr(funds, "cards", None), CardFundingJournal)
        else None
    )


def records(worker):
    return get_payment_purchase_store(worker.settings.payment_purchase_db_path)


async def unspent(worker, coin):
    row = read_confirmed_coin(
        await worker.provider.get_coin_record_by_name_primary(hx(coin.name())),
        coin.name(),
    )
    check(
        row.coin == coin
        and not row.spent_height
        and await worker.provider.primary.get_mempool_items_by_coin_name(
            hx(coin.name())
        )
        == [],
        "Allocated coin is spent, pending, or changed",
    )


async def reservations(worker, order, now):
    # The native timeout and current-generation identity implementations support Testnet11 today.
    check(
        order.network == worker.settings.network == "testnet11"
        and order.generation_id == worker.settings.deployment_generation_id,
        "Current deployment has no approved two-deed recovery for this network",
    )
    store = records(worker)
    stored = store.get(order.purchase_id)
    items = timeout_items(store, order.purchase_id)
    check(
        stored.inventory_state == "CONFIRMED"
        and stored.purchase_artifact == order.batch
        and stored.inventory_expires_at == order.expires_at
        and not store.inventory_timeout_operations(order.purchase_id)
        and not store.inventory_extension_operations(order.purchase_id)
        and not store.checkout_hold(order.purchase_id)
        and not store.checkout_terminal(order.purchase_id)
        and tuple(i.launcher for i in items) == tuple(order.deed_launcher_ids)
        and tuple(hx(i.release_spend.coin.name()) for i in items)
        == tuple(order.reserved_coin_ids)
        and tuple(hx(i.reservation_spend.coin.name()) for i in items)
        == tuple(order.original_coin_ids),
        "Retained reservations differ from card order",
    )
    node = worker.provider.primary
    peak = await release_peak(node, order.network)
    check(
        max(now, await canonical_time(node, peak)) + 1920 < order.expires_at,
        "Card reservation window is too short",
    )
    for item in items:
        check(
            await inspect_item(node, stored, item, peak) == "UNSPENT"
            and await node.get_mempool_items_by_coin_name(
                hx(item.release_spend.coin.name())
            )
            == [],
            "Card reservation has changed",
        )
    check(
        await release_peak(node, order.network) == peak,
        "Canonical reservation observation changed",
    )
    return items


def reservation_fee(worker, order, scope):
    stored = records(worker).get(order.purchase_id)
    original = SpendBundle.from_json_dict(stored.inventory_bundle)
    context = dict(feeTill=worker.faucet.address_hex, purpose=None, backingMojos=0)
    saved = worker.submitter.funding_store.lookup(
        order.network, hx(original.name()), context
    )
    check(
        saved and saved.get("protocolSpendBundle") == original.to_json_dict(),
        "Exact original reservation funding is missing",
    )
    funded = SpendBundle.from_json_dict(saved["spendBundle"])
    fee = int(saved["feeMojos"])
    fees = [c for c in funded.removals() if hx(c.name()) == saved["feeCoinId"]]
    check(
        stored.inventory_bundle_id == saved["spendBundleId"] == hx(funded.name())
        and len(fees) == 1
        and fees[0].puzzle_hash == worker.faucet.address_puzzle_hash
        and set(original.coin_spends).issubset(funded.coin_spends)
        and len(funded.coin_spends) == len(original.coin_spends) + 1
        and {hx(c.name()) for c in original.removals()} == set(order.original_coin_ids)
        and int(saved["backingMojos"]) == 0
        and sum(c.amount for c in funded.removals())
        - sum(c.amount for c in funded.additions())
        == fee
        and 0 < fee <= scope.maximumFeePerStageMojos,
        "Reservation exceeds the order release or exact original funding",
    )
    cap = min(scope.maximumFeePerStageMojos, worker.submitter.policy.maximum_mojos)
    check(
        cap > 0 and fee + 4 * cap <= scope.maximumTotalFeeMojos,
        "Order release does not cover all five fee stages",
    )
    return cap


async def precharge_services(settings, worker, order):
    from .vault_card_settlement import current_card_artifact, validator_coverage

    artifact = current_card_artifact(settings, order)
    check(
        await worker.exact_executor.release_ready(
            artifact["sourceShas"]["keyOfSolomon"]
        ),
        "Pinned exact executor is unavailable",
    )
    await validator_coverage(settings, order)


async def allocate_current_card_coverage(app, settings, order, *, now):
    from .vault_card_settlement import check_release

    binding = bound(order)
    release = check_release(app, order)
    worker = work(app, order)
    await precharge_services(settings, worker, order)
    check(worker.recent_stripe_queue_pass(), "No recent complete delivery worker poll")
    journal = worker.submitter.funding_store.cards
    async with worker.submitter.funding_guard:
        items = await reservations(worker, order, now)
        cap = reservation_fee(worker, order, release)
        old = journal.get(order.purchase_id)
        if old:
            check(
                old["binding"] == binding
                and old["state"] == "ALLOCATED"
                and old["cap"] == cap
                and old["till"] == worker.faucet.address_hex,
                "Card allocation was already used or changed",
            )
            for role in ROLES:
                await unspent(worker, old["coins"][role])
            return True
        excluded = {bytes(i.release_spend.coin.name()) for i in items}
        coins = {"receipt_parent": await worker._select_faucet_coin(2)}
        for role in ROLES[1:]:
            excluded.update(bytes(c.name()) for c in coins.values())
            coins[role] = await worker.submitter._select_fee_coin(
                cap, excluded_coin_ids=excluded, selection_purpose=None
            )
        for coin in coins.values():
            await unspent(worker, coin)
        journal.allocate(
            binding,
            worker.faucet.address_hex,
            cap,
            coins,
            [i.release_spend.coin for i in items],
        )
        return True


async def current_card_coverage(app, settings, order, *, now):
    try:
        from .vault_card_settlement import check_release

        binding = bound(order)
        release = check_release(app, order)
        worker = work(app, order)
        await precharge_services(settings, worker, order)
        check(worker.recent_stripe_queue_pass(), "Worker observation is stale")
        old = card(worker, order.purchase_id)
        check(
            old
            and old["binding"] == binding
            and old["state"] == "ALLOCATED"
            and old["cap"] == reservation_fee(worker, order, release)
            and old["till"] == worker.faucet.address_hex,
            "Card funding differs",
        )
        await reservations(worker, order, now)
        for role in ROLES:
            await unspent(worker, old["coins"][role])
        return card(worker, order.purchase_id) == old
    except Exception:
        return False


def journal_for(app):
    worker = app.state.stripe_delivery_worker
    check(
        worker and getattr(worker.settings, "vault_card_delivery_enabled", False),
        "Private card worker is unavailable",
    )
    return worker.submitter.funding_store.cards


def bind_card_payment(app, order, payment_id):
    # Called after original Stripe evidence passes the owner/order/account checks.
    journal_for(app).payment(bound(order), payment_id)


def paid(worker, operation):
    row = card(worker, operation.purchase_id)
    if row:
        check(
            row["state"] == "PAID"
            and operation.payment_rail == "stripe"
            and row["payment"] == operation.evidence.get("paymentIntentId")
            and row["binding"]["account_id"]
            == operation.evidence.get(
                "stripeAccountId", operation.evidence.get("accountId")
            )
            and row["till"] == worker.faucet.address_hex
            and row["cap"] <= worker.submitter.policy.maximum_mojos,
            "Card delivery conflicts with the protected payment",
        )
    return row


async def signable(worker, row, role):
    coin = row["coins"][role]
    faucet = worker.faucet
    faucet.require_spend_purpose(None)
    check(
        coin.puzzle_hash == faucet.address_puzzle_hash
        and row["till"] == faucet.address_hex,
        "Card till changed",
    )
    # Other independent applications retain their exclusions, including mint and redemption.
    own = worker.submitter.funding_store.reserved_coin_ids
    for source in faucet._coin_reservation_sources:
        if source != own and hx(coin.name()) in {
            v if isinstance(v, str) else hx(v) for v in source()
        }:
            raise ValueError("Card coin is assigned to another application")
    await unspent(worker, coin)
    return coin


async def verify_paid_dispatch(worker, operation, prepared=None):
    from .generation_index import load_generation_read_anchor
    from .vault_card_native import VaultCardNative
    from .vault_card_settlement import confirmed, current_card_artifact

    row = paid(worker, operation)
    if not row:
        return
    order = worker.current_card_order()
    check(
        order
        and row["binding"] == bound(order)
        and int(time.time()) < order.expires_at,
        "Card delivery release has expired or changed",
    )
    if prepared is not None:
        executor_sha = current_card_artifact(worker.settings, order)["sourceShas"][
            "keyOfSolomon"
        ]
        check(
            await worker.exact_executor.release_ready(executor_sha),
            "Pinned exact executor is unavailable",
        )
        check(
            await worker.submitter._estimate_fee(prepared.bundle)
            <= prepared.fee_mojos
            <= row["cap"],
            "Exact fee is outside the current price or original ceiling",
        )
    evidence = await confirmed(
        VaultCardNative.configured(worker.settings),
        load_generation_read_anchor(worker.settings),
        worker.provider,
    )
    check(
        bound(evidence.order) == row["binding"] and paid(worker, operation) == row,
        "Current card release or inventory changed",
    )


async def card_receipt(worker, operation):
    from solslot_puzzles.stripe_settlement_v1_driver import (
        curry_purchase_batch_settlement_receipt,
    )

    await verify_paid_dispatch(worker, operation)
    row = paid(worker, operation)
    check(row is not None, "Unknown card reservation")
    batch, receipt, terms = worker._receipt_terms(operation)
    check(
        hx(batch.batch_hash) == row["binding"]["batch_hash"] and batch.quantity == 2,
        "Card receipt batch changed",
    )
    puzzle = curry_purchase_batch_settlement_receipt(terms).get_tree_hash()
    parent = await signable(worker, row, "receipt_parent")
    output = Coin(parent.name(), puzzle, 2)
    conditions = [[51, puzzle, 2, [receipt.receipt_hash]]]
    if parent.amount > 2:
        conditions.append(
            [51, worker.faucet.address_puzzle_hash, int(parent.amount) - 2]
        )
    program = Program.to(conditions)
    spend = make_spend(
        parent, worker.faucet.key.puzzle, Program.to([0, Program.to((1, program)), 0])
    )
    bundle = SpendBundle(
        [spend],
        G2Element.from_bytes(worker.faucet._delegated_signature(parent, program)),
    )
    return worker.store.record_receipt_prepared(
        operation.purchase_id,
        input_coin_id=hx(parent.name()),
        protocol_bundle=bundle.to_json_dict(),
        receipt_coin_id=hx(output.name()),
        receipt_puzzle_hash=hx(puzzle),
    )


def planned_bundle(worker, row, role):
    purchase = row["purchase"]
    if role in ("receipt_fee", "delivery_fee"):
        op = worker.store.get(purchase)
        paid(worker, op)
        raw = op.receipt_funding_bundle if role == "receipt_fee" else op.delivery_bundle
        protocol = SpendBundle.from_json_dict(raw)
        if role == "receipt_fee":
            check(
                [s.coin for s in protocol.coin_spends]
                == [row["coins"]["receipt_parent"]],
                "Unexpected receipt parent",
            )
        else:
            ids = {hx(c.name()) for c in protocol.removals()}
            check(
                set(row["binding"]["reserved_coin_ids"]) | {op.receipt_coin_id} <= ids,
                "Delivery inputs changed",
            )
        return protocol
    check(
        role in ("return_0", "return_1")
        and row["state"] in ("RETURNING", "UNPAID_RETURNING"),
        "Inventory return is unavailable",
    )
    items = timeout_items(records(worker), purchase)
    index = int(role[-1])
    check(
        len(items) == 2
        and hx(items[index].release_spend.coin.name())
        == row["binding"]["reserved_coin_ids"][index],
        "Return input differs",
    )
    return SpendBundle([items[index].release_spend], G2Element())


async def prepare_stage(worker, purchase, role):
    from .stripe_delivery_worker import _prepared_from_binding

    async with worker.submitter.funding_guard:
        row = card(worker, purchase)
        journal = worker.submitter.funding_store.cards
        protocol = planned_bundle(worker, row, role)
        durable = journal.saved_stage(purchase, role, hx(protocol.name()))
        if durable:
            return _prepared_from_binding(durable)
        coin = await signable(worker, row, role)
        check(
            sum(c.amount for c in protocol.removals())
            == sum(c.amount for c in protocol.additions()),
            "Card protocol carries an unexpected separate fee",
        )
        commit = worker.submitter._backing_conditions(
            protocol, require_announcements=False
        )
        fee = await worker.submitter._estimate_fee(protocol)
        for _ in range(3):
            check(
                0
                < fee
                <= min(
                    row["cap"], worker.submitter.policy.maximum_mojos, int(coin.amount)
                ),
                "Current price exceeds card funding",
            )
            conditions = [[52, fee], *commit]
            if coin.amount > fee:
                conditions.insert(
                    0, [51, worker.faucet.address_puzzle_hash, int(coin.amount) - fee]
                )
            fee_program = Program.to(conditions)
            spend = make_spend(
                coin,
                worker.faucet.key.puzzle,
                Program.to([0, Program.to((1, fee_program)), 0]),
            )
            subsidy = SpendBundle(
                [spend],
                G2Element.from_bytes(
                    worker.faucet._delegated_signature(coin, fee_program)
                ),
            )
            combined = SpendBundle.aggregate([protocol, subsidy])
            price = await worker.submitter._estimate_fee(combined)
            if price <= fee:
                result = PreparedProtocolBundle(combined, fee, hx(coin.name()))
                journal.save_stage(purchase, role, protocol, result)
                return result
            fee = price
        raise ValueError("Card fee pricing did not converge")


class ReturnSubmitter:
    def __init__(self, worker, row):
        self.worker, self.row = worker, row

    async def submit(self, raw, *, before_push):
        protocol = SpendBundle.from_json_dict(raw)
        coin = protocol.coin_spends[0].coin
        index = self.row["binding"]["reserved_coin_ids"].index(hx(coin.name()))
        role = "return_" + str(index)
        check(
            planned_bundle(self.worker, self.row, role) == protocol,
            "Return bundle changed",
        )
        prepared = await prepare_stage(self.worker, self.row["purchase"], role)
        return await self.worker.submitter.reconcile_reserved(
            prepared.to_json(), before_push=lambda: before_push(prepared)
        )

    async def reconcile_reserved(self, raw, *, before_push):
        fee = raw["feeCoinId"]
        role = next(
            r
            for r in ("return_0", "return_1")
            if hx(self.row["coins"][r].name()) == fee
        )
        prepared = await prepare_stage(self.worker, self.row["purchase"], role)
        check(prepared.to_json() == raw, "Stored return differs from allocated funding")
        return await self.worker.submitter.reconcile_reserved(
            raw, before_push=before_push
        )


async def prepare_card_refund(app, settings, order, payment_id, *, now):
    return await _return_inventory(
        app, settings, order, payment_id, now=now, unpaid=False
    )


async def prepare_unpaid_release(app, settings, order, *, now, session_evidence):
    from .vault_card_provider import checked_session, metadata
    from .vault_card_store import VaultCardStore

    src = VaultCardStore(settings.payment_purchase_db_path)
    if now < order.expires_at:
        return False
    # Losing a response to a provider call is never equivalent to no dispatch.
    if session_evidence is None:
        if not src.fence_undispatched_order(order.purchase_id, now=now):
            return False
        if journal_for(app).get(order.purchase_id) is None:
            from .vault_card_reservations import recover_unallocated

            return await recover_unallocated(app, settings, order, now=now)
    else:
        session = session_evidence["session"]
        intent = session_evidence.get("payment_intent")
        if (
            not order.session_id
            or session.get("id") != order.session_id
            or session.get("status") != "expired"
            or session.get("payment_status") != "unpaid"
        ):
            return False
        checked_session(order, session, expected_expiry=order.session_expires_at)
        pid = session.get("payment_intent")
        if isinstance(pid, dict):
            pid = pid.get("id")
        if pid is None:
            if intent is not None or order.payment_intent_id is not None:
                return False
        elif (
            not isinstance(intent, dict)
            or pid != intent.get("id")
            or order.payment_intent_id not in (None, pid)
            or intent.get("object") != "payment_intent"
            or intent.get("status") != "canceled"
            or intent.get("livemode") is not (order.mode == "live")
            or intent.get("metadata") != metadata(order)
            or type(intent.get("amount_received")) != int
            or intent["amount_received"] != 0
            or intent.get("amount") != order.amount_minor
            or intent.get("currency") != order.currency
        ):
            return False
    return await _return_inventory(app, settings, order, None, now=now, unpaid=True)


async def _return_inventory(app, settings, order, payment_id, *, now, unpaid):
    from .vault_card_settlement import current_card_artifact, card_return_binding

    worker = work(app, order, recovery=True)
    journal = worker.submitter.funding_store.cards
    row = card(worker, order.purchase_id)
    check(
        row and row["binding"] == bound(order) and row["payment"] == payment_id,
        "Card refund binding changed",
    )
    if row["state"] == "ABANDONED":
        return unpaid
    if row["state"] in ("DELIVERED", "REFUNDED"):
        return False
    returning = "UNPAID_RETURNING" if unpaid else "RETURNING"
    initial = "ALLOCATED" if unpaid else "PAID"
    check(
        row["state"] in (initial, returning, "RETURNED"), "Card recovery state differs"
    )
    primary = worker.provider.primary
    peak = await release_peak(primary, order.network)
    if await canonical_time(primary, peak) < order.expires_at:
        return False
    stored = records(worker)
    items = timeout_items(stored, order.purchase_id)
    check(
        len(items) == 2
        and tuple(hx(i.release_spend.coin.name()) for i in items)
        == tuple(order.reserved_coin_ids),
        "Protected return pair differs",
    )
    # Inspect the two actual parent spends even when a previous process marked the journal RELEASED.
    outcomes = [
        await inspect_item(primary, stored.get(order.purchase_id), item, peak)
        for item in items
    ]
    for item, status in zip(items, outcomes, strict=True):
        if status == "UNSPENT" and await primary.get_mempool_items_by_coin_name(
            hx(item.release_spend.coin.name())
        ):
            # It may be an in-flight delivery or an already-sent return. Wait for canonical evidence.
            return False
    check(
        await release_peak(primary, order.network) == peak,
        "Return chain observation changed",
    )
    if row["state"] == "RETURNED":
        return all(s == "CONFIRMED" for s in outcomes)
    if row["state"] == initial:
        journal.transition(order.purchase_id, payment_id, {initial}, returning)
    row = card(worker, order.purchase_id)
    artifact = current_card_artifact(settings, order)
    binding = card_return_binding(
        order, artifact, settings.runtime_environment + "-alpha"
    )

    def authorize():
        check(
            work(app, order, recovery=True) is worker
            and card(worker, order.purchase_id)["state"] == returning
            and current_card_artifact(settings, order) == artifact,
            "Return authority changed",
        )

    result = await advance_inventory_timeout(
        store=stored,
        node=primary,
        submitter=ReturnSubmitter(worker, row),
        purchase_id=order.purchase_id,
        network=order.network,
        release_binding=binding,
        authorize=authorize,
    )
    if result["state"] != "RELEASED" or outcomes != ["CONFIRMED", "CONFIRMED"]:
        return False
    evidence = result["releaseEvidence"]
    check(
        [x["reservedCoinId"] for x in evidence["items"]]
        == list(order.reserved_coin_ids),
        "Return receipt changed",
    )
    journal.transition(
        order.purchase_id,
        payment_id,
        {returning},
        "ABANDONED" if unpaid else "RETURNED",
        evidence,
    )
    return True


def mark_card_refunded(app, order, payment_id, refund_id):
    check(
        isinstance(refund_id, str) and refund_id.startswith("re_"),
        "Stripe refund required",
    )
    journal = journal_for(app)
    row = journal.get(order.purchase_id)
    check(row and row["binding"] == bound(order), "Card refund scope changed")
    journal.transition(
        order.purchase_id, payment_id, {"RETURNED"}, "REFUNDED", refund_id
    )
