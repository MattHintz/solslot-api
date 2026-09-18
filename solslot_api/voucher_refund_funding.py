"""Private exact Stripe refund fee reservations on the existing presale ledger."""
from dataclasses import asdict
import json
from time import time
from types import SimpleNamespace

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle

from .protocol_submission import PreparedProtocolBundle, ProtocolBundleSubmitter
from .sols_swap_funding import canonical, digest, estimate_swap_fee, funding_conditions, hx, public_spend, require_live_fee


class RefundFundingStore:
    def __init__(self, presales):
        self.presales = presales
        with presales.txn() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS voucher_owner_refund_fee_reviews (
                reservation_hash TEXT PRIMARY KEY, fee_coin_id TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL, payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL)''')

    def reserve(self, payload):
        review = payload['review']
        with self.presales.txn() as db:
            db.execute('DELETE FROM voucher_owner_refund_fee_reviews WHERE expires_at<=?', (time(),))
            db.execute('INSERT INTO voucher_owner_refund_fee_reviews VALUES (?,?,?,?,?)',
                (digest(review), review['fundingCoinSpend']['coinId'], review['expiresAt'], canonical(payload), digest(payload)))

    def get(self, reservation_hash):
        row = self.presales._conn.execute('SELECT * FROM voucher_owner_refund_fee_reviews WHERE reservation_hash=?', (reservation_hash,)).fetchone()
        if row is None or row['expires_at'] <= time():
            raise ValueError('Prepare a fresh exact Stripe refund fee review')
        payload = json.loads(row['payload_json'])
        if digest(payload) != row['payload_hash'] or digest(payload['review']) != reservation_hash:
            raise ValueError('Retained Stripe refund funding changed')
        return payload

    def reserved_coin_ids(self):
        # Persisted terminal executions remain independently reserved by the
        # presale ledger after this unsigned review expires or the process exits.
        return tuple(row[0] for row in self.presales._conn.execute(
            'SELECT fee_coin_id FROM voucher_owner_refund_fee_reviews WHERE expires_at>?', (time(),)))


def store_for(presales, submitter):
    store = getattr(presales, '_owner_refund_funding', None)
    if store is None:
        store = RefundFundingStore(presales)
        presales._owner_refund_funding = store
    submitter.add_fee_coin_reservation_source(store.reserved_coin_ids)
    submitter.faucet.add_coin_reservation_source(store.reserved_coin_ids)
    submitter.add_fee_coin_reservation_source(presales.pending_stripe_terminal_fee_coin_ids)
    submitter.faucet.add_coin_reservation_source(presales.pending_stripe_terminal_fee_coin_ids)
    return store


def fee_spend(submitter, context, coin, total_fee, deadline):
    # The protocol burns exactly one receipt mojo; the sponsor supplies the
    # remaining fee. All four protocol inputs and announcements bind the spend.
    evidence = SimpleNamespace(coin_spends=(context.vault_spend,*context.provisional.coin_spends),
        required_backing_mojos=0, vault_coin_id=context.vault_coin.name())
    conditions = funding_conditions(evidence, coin, total_fee-1, submitter.faucet.address_puzzle_hash, deadline)
    return make_spend(coin, submitter.faucet.key.puzzle, Program.to([0, Program.to((1,conditions)), Program.to(0)])), conditions


async def reserve_refund_funding(submitter, presales, context, evidence, binding, authorize):
    if not isinstance(submitter, ProtocolBundleSubmitter) or submitter.faucet.network != 'testnet11' or not submitter.policy.enabled:
        raise ValueError('Exact Stripe refund funding is unavailable')
    store = store_for(presales, submitter)
    deadline = min(binding['quoteExpiresAt']+30, context.terms.refund_deadline) if int(context.refund_action)==1 else binding['quoteExpiresAt']+30
    async with submitter.funding_guard:
        policy = asdict(submitter.policy)
        total = max(1, await estimate_swap_fee(submitter))
        coin = await submitter._select_fee_coin(total-1, excluded_coin_ids={bytes(s.coin.name()) for s in
            (context.vault_spend,*context.provisional.coin_spends)}, selection_purpose=None)
        await require_live_fee(submitter, coin)
        if authorize()!=binding or asdict(submitter.policy)!=policy or binding['quoteExpiresAt']<=time():
            raise ValueError('Stripe refund authority or fee policy changed')
        spend,conditions = fee_spend(submitter,context,coin,total,deadline)
        private = SpendBundle([spend],G2Element.from_bytes(submitter.faucet.sign_delegated_spend(coin,conditions)))
        review = dict(schemaVersion=1,action='VOUCHER_REFUND',status='FUNDING_RESERVED',consensusValidated=False,
            binding=binding,candidateHash=evidence['candidateHash'],expiresAt=binding['quoteExpiresAt'],executionDeadline=deadline,
            protocolFeeMojos='1',feeMojos=str(total),sponsorFeeMojos=str(total-1),feeTillPuzzleHash=hx(submitter.faucet.address_puzzle_hash),
            policy=policy,fundingCoinSpend=public_spend(spend))
        store.reserve(dict(review=review,fundingBundle=private.to_json_dict()))
        return {**review,'reservationHash':digest(review),'reservationReviewJson':canonical(review)}


async def prepare_reserved_refund(submitter, presales, context, evidence, binding, reservation_hash, protocol_bundle, authorize):
    """Caller holds the funding guard until exact persistence and KoS dispatch."""
    if not submitter.funding_guard.locked():
        raise ValueError('Stripe refund funding guard is required')
    payload = store_for(presales,submitter).get(reservation_hash)
    review = payload['review']
    if (review['binding']!=binding or review['candidateHash']!=evidence['candidateHash'] or
            review['policy']!=asdict(submitter.policy) or authorize()!=binding):
        raise ValueError('Stripe refund no longer matches its fee reservation')
    private = SpendBundle.from_json_dict(payload['fundingBundle'])
    if len(private.coin_spends)!=1 or private.aggregated_signature==G2Element():
        raise ValueError('Stripe refund private funding is incomplete')
    total = int(review['feeMojos'])
    expected,_ = fee_spend(submitter,context,private.coin_spends[0].coin,total,review['executionDeadline'])
    if expected!=private.coin_spends[0] or public_spend(expected)!=review['fundingCoinSpend']:
        raise ValueError('Stripe refund funding spend changed')
    await require_live_fee(submitter,expected.coin)
    if await estimate_swap_fee(submitter)>total or authorize()!=binding:
        raise ValueError('Stripe refund authority or fee changed before dispatch')
    aggregate = SpendBundle.aggregate([SpendBundle.from_bytes(bytes(protocol_bundle)),private])
    if sum(c.amount for c in aggregate.removals())-sum(c.amount for c in aggregate.additions())!=total:
        raise ValueError('Stripe refund total fee changed')
    from .wallet_offer_worker import run_offer_job
    from chia.wallet.wallet_spend_bundle import WalletSpendBundle
    await run_offer_job('swap_signature',bundle=WalletSpendBundle.from_bytes(bytes(aggregate)),network='testnet11')
    return PreparedProtocolBundle(aggregate,total,hx(expected.coin.name()))
