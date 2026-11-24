"""Unsigned Stripe batches must settle each deed and its separate treasury receipt."""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import Coin, G1Element, G2Element, get_conditions_from_spendbundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    STRIPE_PAYMENT_PROVIDER_ID,
    build_purchase_batch_settlement_receipt_v1,
    build_purchase_batch_v1,
    purchase_batch_to_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PurchaseBatchSettlementTermsV1,
    curry_purchase_batch_settlement_receipt,
    make_mint_offer_v5_inner,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault

from solslot_api import stripe_delivery_worker as worker_module
from solslot_api.governed_output_index import EvaluatedBundleOutputs
from solslot_api.stripe_delivery_store import PAYMENT_RAIL_STRIPE
from tests.test_native_purchases import _b32, _context


def _stripe_context(parent_seed):
    public = G1Element.generator()
    # The underlying native checkout fixture only needs public keys.
    holders = [Mock(get_g1=Mock(return_value=p)) for p in (public, public + public, public + public + public)]
    context, _ = _context(holders[0], holders, deed_parent_seed=parent_seed, now=1_700_000_000)
    artifact = replace(
        context.purchase,
        rail=PaymentRail.STRIPE,
        rail_asset_decimals=2,
        rail_amount=context.purchase.subtotal_minor,
        oracle_round_hash=bytes32.zeros,
        oracle_price_usd_minor_per_asset=0,
        source_evidence_root=bytes32.zeros,
    )
    reservation = InventoryReservationV1(artifact, artifact.quote_expires_at)
    reserved = SINGLETON_MOD.curry(context.deed_struct, make_mint_offer_v5_inner(context.terms, reservation))
    return replace(
        context, purchase=artifact, reservation=reservation,
        deed_coin=Coin(context.deed_coin.parent_coin_info, reserved.get_tree_hash(), 1),
        credential_receipt={**context.credential_receipt, 'identityAttestRoot': '0x' + artifact.zkpassport_root.hex()},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("parents", [(23,), (23, 27), (23, 27, 29)])
async def test_stripe_worker_prepares_distinct_receipt_outputs(monkeypatch, parents):
    contexts = tuple(sorted(
        (_stripe_context(parent) for parent in parents),
        key=lambda context: context.purchase.deed_launcher_id,
    ))
    batch = build_purchase_batch_v1(batch_nonce=_b32(32), artifacts=tuple(c.purchase for c in contexts))
    roster = contexts[0].terms.validator_pubkeys
    receipt = build_purchase_batch_settlement_receipt_v1(
        batch=batch, provider_id=STRIPE_PAYMENT_PROVIDER_ID, external_reference_hash=_b32(33),
        evidence_hash=_b32(34), observed_at=1_700_000_100, validator_pubkeys=roster,
        collected_amount_minor=batch.total_rail_amount,
    )
    terms = PurchaseBatchSettlementTermsV1(receipt, roster)
    receipt_coin = Coin(_b32(35), curry_purchase_batch_settlement_receipt(terms).get_tree_hash(), len(contexts))
    operation = SimpleNamespace(purchase_id='0x' + batch.purchase_id.hex(), payment_rail=PAYMENT_RAIL_STRIPE, evidence={})
    group = SimpleNamespace(contexts=contexts, batch=batch, stored=SimpleNamespace(purchase_artifact=purchase_batch_to_json(batch)))
    monkeypatch.setattr(worker_module, '_load_context_group', AsyncMock(return_value=group))
    # Quorum networking is outside this unsigned CLVM/worker regression.
    quorum = SimpleNamespace(signer_indices=(0, 1), aggregated_signature=G2Element())
    monkeypatch.setattr(worker_module, 'collect_stripe_settlement_quorum', AsyncMock(return_value=quorum))
    worker = Mock(settings=SimpleNamespace(network='testnet11'))
    await worker_module.StripeDeliveryWorker._prepare_smartdeed_batch_delivery(
        worker, operation=operation, batch=batch, receipt=receipt, receipt_terms=terms,
        receipt_coin=receipt_coin, expected_rail=PaymentRail.STRIPE,
    )
    saved = worker.store.record_delivery_prepared.call_args.kwargs
    bundle = WalletSpendBundle.from_json_dict(saved['protocol_bundle'])
    conditions = get_conditions_from_spendbundle(bundle, DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM, DEFAULT_CONSTANTS, 4_887_810)
    assert conditions.cost > 0 and bundle.aggregated_signature == G2Element()
    evaluated = EvaluatedBundleOutputs(bundle)
    assets = {coin.name(): coin for coin in evaluated.additions}
    assert len(assets) == len(evaluated.additions)
    expected_deeds = [
        evaluated.find_exact_descendant(
            ancestor_coin_id=c.deed_coin.name(),
            puzzle_hash=SINGLETON_MOD.curry(c.deed_struct, puzzle_for_p2_vault(batch.vault_launcher_id)).get_tree_hash(),
            amount=1, label='vault SmartDeed',
        ) for c in contexts
    ]
    assert saved['delivery_output_coin_ids'] == tuple('0x' + coin.name().hex() for coin in expected_deeds)
    outputs = tuple(assets[bytes32.from_hexstr(value)] for value in saved['treasury_output_coin_ids'])
    assert len({coin.parent_coin_info for coin in outputs}) == len(contexts)
    assert all(coin.puzzle_hash == contexts[0].terms.protocol_puzhash and coin.amount == 1 for coin in outputs)

    # These receipts share a destination and amount. Preserve the exact per-deed authorization.
    if len(contexts) > 1:
        with pytest.raises(worker_module.StripeDeliveryManualReview, match='exact deed payment'):
            worker_module._stripe_batch_treasury_outputs(receipt_coin, tuple(reversed(contexts)), bundle, evaluated)
    unrelated_receipt = Coin(_b32(36), receipt_coin.puzzle_hash, receipt_coin.amount)
    with pytest.raises(worker_module.StripeDeliveryManualReview, match='settlement link'):
        worker_module._stripe_batch_treasury_outputs(unrelated_receipt, contexts, bundle, evaluated)
