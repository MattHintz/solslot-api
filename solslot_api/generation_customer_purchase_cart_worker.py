"""Resume a buyer-approved native purchase using its original signed offer."""
import asyncio
import logging
import time

from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding

from .generation_coin_evidence import read_confirmed_coin
from .generation_customer_purchase_atomic import purchase_inputs
from .generation_customer_collection_policy import approved_forwarding_asset
from .generation_customer_purchase_atomic_signing import verify_approval
from .generation_customer_purchase_batch import artifacts
from .generation_customer_purchase_holds import cart_inputs, saved_approval
from .generation_customer_purchase_quorum import collect_current_purchase_quorum
from .generation_customer_purchase_settlement_receipt import confirm_settlement, save_settlement
from .generation_customer_purchase_validators import prove_primary_expired_source
from .generation_operations import bundle_id, canonical
from .protocol_admission import (admission_conditions, mempool_fee_floor, primary_admission_state,
                                 require_absolute_admission, require_relative_admission)

logger = logging.getLogger(__name__)


def forwarding_spends(service, evidence, delivery):
    _, terms, _ = purchase_inputs(evidence)
    claim = evidence.claim
    fees = service._fees(evidence)
    return tuple(spend for artifact, term in zip(artifacts(claim), terms, strict=True)
                 for spend in build_testnet_primary_forwarding(bundle=delivery, artifact=artifact,
                     terms=term, issuer_public_key=service.policy.issuer_public_key, fees=fees,
                     approved_cat_asset=approved_forwarding_asset(service.policy, artifact, term)).operation.spends)


async def expire_approved_cart(store, identity, approval, provider, binding):
    """A signed checkout is terminal only after the primary chain proves the held inputs survived."""
    deadline = artifacts(approval.reservation)[0].quote_expires_at
    proofs = []
    for coin_id in cart_inputs(approval.reservation):
        coin = read_confirmed_coin(await provider.get_coin_record_by_name_primary(coin_id), bytes32.from_hexstr(coin_id))
        proofs.append(await prove_primary_expired_source(provider, coin.coin, deadline))
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        store._row(db, identity, binding)
        row = db.execute('SELECT approval_digest FROM current_native_cart_approvals WHERE intent_id=?',
                         (identity,)).fetchone()
        if row is None or row['approval_digest'] != approval.digest():
            raise ValueError('CURRENT_CHECKOUT_SAVED_APPROVAL_CHANGED')
        updated = db.execute("UPDATE current_native_carts SET state='EXPIRED' WHERE intent_id=? AND state='APPROVED'",
                             (identity,)).rowcount
        if updated:
            document = canonical(proofs)
            store._execution_capacity(db, len(document))
            db.execute('INSERT INTO current_native_expiries VALUES(?,?)', (identity, document))
            db.execute('UPDATE current_native_cart_items SET active=0 WHERE intent_id=?', (identity,))
        db.commit()


class NativeCartWorker:
    def __init__(self, service, issuer, *, collect_quorum=collect_current_purchase_quorum):
        self.service = service
        self.issuer = issuer
        self.collect_quorum = collect_quorum
        self.wake = asyncio.Event()
        self.last_tick = None

    def notify_work(self):
        self.wake.set()

    def healthy(self):
        return self.last_tick is not None and time.monotonic() - self.last_tick < 150

    def _saved_bundle(self, identity, binding):
        store = self.service.store
        with store._connect() as db:
            store._row(db, identity, binding)
            row = db.execute('SELECT signed_bundle,bundle_id FROM current_native_settlements WHERE intent_id=?',
                             (identity,)).fetchone()
        if row is None:
            return None
        bundle = SpendBundle.from_bytes(row['signed_bundle'])
        if bundle_id(bundle) != row['bundle_id']:
            raise ValueError('CURRENT_CHECKOUT_SAVED_SETTLEMENT_CHANGED')
        return bundle

    async def advance(self, identity, binding):
        service = self.service
        store, provider = service.store, service.provider
        approval = saved_approval(store, identity, browser_hash=binding)
        if approval is None:
            return
        bundle = self._saved_bundle(identity, binding)
        expired = int(service.clock()) >= artifacts(approval.reservation)[0].quote_expires_at
        if bundle is not None:
            try:
                observed = await provider.observe_exact_protocol_bundle(bundle.to_json_dict())
            except Exception:
                if not expired:
                    raise
                # Release an overdue hold only on affirmative chain evidence below.
                observed = None
            if observed is not None:
                if observed['status'] == 'MEMPOOL':
                    return
                if observed['status'] != 'CONFIRMED':
                    raise ValueError('CURRENT_CHECKOUT_CHAIN_OBSERVATION_UNAVAILABLE')
                await confirm_settlement(store, identity, browser_hash=binding, provider=provider)
                return
        if expired:
            await expire_approved_cart(store, identity, approval, provider, binding)
            return
        state = None
        if bundle is None:
            verified = await verify_approval(approval, **service._arguments())
            quorum = await self.collect_quorum(service.settings, verified)
            tx_id, signature = await self.issuer.atomic_signature(approval, quorum)
            forwards = forwarding_spends(service, verified.evidence, verified.purchase.delivery_bundle)
            bundle = SpendBundle(verified.purchase.bundle(forwards).coin_spends, signature)
            if tx_id != bundle_id(bundle):
                raise ValueError('CURRENT_CHECKOUT_ISSUER_SETTLEMENT_CHANGED')
            state = await provider.get_fee_estimate(spend_bundle=bundle.to_json_dict(), target_times=[60], require_primary=True)
            height, _, _, _ = primary_admission_state(state)
            save_settlement(store, identity, verified.purchase, browser_hash=binding, forwarding_spends=forwards,
                            signed=bundle, height=height, now=int(service.clock()))
        # A recovered bundle gets fresh admission evidence. A new one uses the
        # same synced-node reply collected immediately before its local checkpoint.
        if state is None:
            state = await provider.get_fee_estimate(spend_bundle=bundle.to_json_dict(), target_times=[60], require_primary=True)
        height, used, capacity, timestamp = primary_admission_state(state)
        conditions = admission_conditions(bundle, height, 'testnet11')
        require_absolute_admission(conditions, height=height, peak_time=timestamp)
        await require_relative_admission(conditions, bundle, provider=provider, height=height, peak_time=timestamp)
        if conditions.reserve_fee != approval.network_fee_mojos or approval.network_fee_mojos < mempool_fee_floor(conditions.cost, used, capacity):
            raise ValueError('CURRENT_CHECKOUT_FEE_BELOW_CURRENT_MINIMUM')
        await provider.push_tx_confirmed_in_primary_mempool(bundle.to_json_dict(), required_coin_id=approval.payment_coin_id,
            required_spend_bundle_id=bundle_id(bundle), timeout_seconds=8, poll_seconds=1)

    async def run(self, stop):
        cursor = ''
        while not stop.is_set():
            self.wake.clear()
            self.last_tick = time.monotonic()
            with self.service.store._connect() as db:
                rows = db.execute("""SELECT c.intent_id, r.browser_hash FROM current_native_carts c
                    JOIN current_customer_purchase_reviews r ON r.intent_id=c.intent_id
                    WHERE r.generation_id=? AND c.state='APPROVED' AND c.intent_id>?
                    ORDER BY c.intent_id LIMIT 4""", (self.service.store.generation_id, cursor)).fetchall()
            for row in rows:
                cursor = row['intent_id']
                self.last_tick = time.monotonic()
                try:
                    await self.advance(cursor, row['browser_hash'])
                except Exception as exc:
                    logger.warning('Native checkout awaiting reconciliation (%s)', type(exc).__name__)
            if len(rows) == 4:
                continue
            cursor = ''
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=8)
            except TimeoutError:
                pass
