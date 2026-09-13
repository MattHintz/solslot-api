"""Local store/loader/builder integration, with synthetic provider and authority fixtures.

No customer credential, live validator, public chain, payment or broadcast is used.
The actual payment store and both native context loaders are deliberately unstubbed.
"""

from dataclasses import replace
from types import SimpleNamespace
import sqlite3

import pytest
from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import native_purchases, stripe_delivery_worker as delivery
from solslot_api.config import Settings
from solslot_api.faucet import Faucet, AGG_SIG_ME_DATA
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_api.stripe_delivery_store import (
    DELIVERY_PREPARED,
    RECEIPT_CONFIRMED,
    PAYMENT_RAIL_BASE_USDC,
    PAYMENT_RAIL_STRIPE,
    StripeDeliveryStore,
)
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_to_json,
    stripe_settlement_evidence_to_json,
)
from solslot_puzzles.primary_purchase_v2_driver import BASE_SEPOLIA_USDC_ASSET_ID
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PRIMARY_PURCHASE_PROVIDER_ID,
    PrimaryMintTermsV3,
    StripeSettlementTermsV1,
    curry_stripe_settlement_receipt,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault

# Reuse the existing canonical synthetic SmartDeed/launcher fixture; no loader mock.
from tests.test_native_purchases import _context, _b32


def hx(value):
    return "0x" + bytes(value).hex()


def coin_record(coin, *, confirmed=120, spent=0):
    return {
        "coin": coin.to_json_dict(),
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
        "spent": bool(spent),
    }


def delivery_case(tmp_path, monkeypatch, rail=PAYMENT_RAIL_STRIPE, inventory_version=1):
    keys = tuple(AugSchemeMPL.key_gen(bytes([n]) * 32) for n in (1, 2, 3))
    pubkeys = tuple(bytes(k.get_g1()) for k in keys)
    base, _ = _context(keys[0], keys, now=1_900_000_000)
    is_base = rail == PAYMENT_RAIL_BASE_USDC
    purchase = replace(
        base.purchase,
        collection_id=bytes32(canonicalise_property_id("local-collection")),
        delivery_context_hash=bytes32(canonicalise_property_id("local-collection")),
        rail=PaymentRail.EVM_TEST_USD if is_base else PaymentRail.STRIPE,
        rail_chain_id=84532 if is_base else 0,
        rail_asset_id=BASE_SEPOLIA_USDC_ASSET_ID if is_base else _b32(0),
        rail_asset_decimals=6 if is_base else 2,
        rail_amount=base.purchase.subtotal_minor * (10_000 if is_base else 1),
        oracle_round_hash=_b32(0),
        oracle_price_usd_minor_per_asset=0,
        source_evidence_root=_b32(0),
    )
    terms = PrimaryMintTermsV3.for_artifact(
        artifact=purchase,
        smart_deed_inner_hash=base.terms.smart_deed_inner_hash,
        inventory_version=inventory_version,
        deed_launcher_puzzle_hash=base.terms.deed_launcher_puzzle_hash,
        protocol_puzhash=purchase.protocol_treasury_puzzle_hash,
        validator_pubkeys=pubkeys,
        provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
    )
    reservation = InventoryReservationV1(
        artifact=purchase, expires_at=purchase.quote_expires_at
    )
    available_puzzle = SINGLETON_MOD.curry(
        base.deed_struct, make_inventory_available_inner(terms)
    )
    available = Coin(
        purchase.deed_launcher_id, available_puzzle.get_tree_hash(), uint64(1)
    )
    reserved_puzzle = SINGLETON_MOD.curry(
        base.deed_struct, make_mint_offer_v5_inner(terms, reservation)
    )
    reserved = Coin(available.name(), reserved_puzzle.get_tree_hash(), uint64(1))
    launcher = Coin(_b32(22), base.terms.deed_launcher_puzzle_hash, uint64(1))
    assert launcher.name() == purchase.deed_launcher_id
    settings = Settings(
        _env_file=None,
        network="testnet11",
        payment_purchase_db_path=str(tmp_path / "purchases.db"),
        zkpassport_policy_version=2,
        zkpassport_bridge_policy_hash=hx(_b32(26)),
        payment_evm_usdc_tokens={"84532": "0x036cbd53842c5426634e7929541ec2318f3dcf7e"},
    )
    purchases = PaymentPurchaseStore(settings.payment_purchase_db_path)
    stored = purchases.save(
        purchase_intent_id="pi_local",
        rail=rail,
        offer_artifact_hash="sha256:" + "21" * 32,
        offer_artifact={"protocol": {"collectionWorkspaceId": "local-dossier"}},
        purchase_artifact=purchase_artifact_v3_to_json(purchase),
        created_at=1_900_000_000,
    )
    purchases.record_inventory_prepared(
        stored.purchase_id,
        available_coin_id=hx(available.name()),
        reserved_coin_id=hx(reserved.name()),
        reserved_puzzle_hash=hx(reserved.puzzle_hash),
        expires_at=reservation.expires_at,
        bundle={"syntheticFixtureOnly": True},
        signer_indices=(0, 1),
        signature=bytes(G2Element()).hex(),
    )
    purchases.record_inventory_submitted(
        stored.purchase_id,
        bundle_id=hx(_b32(39)),
        mempool_observed_at="2030-03-17T17:46:40+00:00",
    )
    purchases.record_inventory_confirmed(stored.purchase_id, confirmation_height=124)

    receipt_data = dict(
        base.credential_receipt,
        vaultLauncherId=hx(purchase.vault_launcher_id),
        network="testnet11",
        confirmedBlockIndex=110,
        policyVersion=settings.zkpassport_policy_version,
        bridgePolicyHash=settings.zkpassport_bridge_policy_hash,
    )
    credential = SimpleNamespace(**receipt_data, model_dump=lambda: dict(receipt_data))
    monkeypatch.setattr(
        "solslot_api.zkpassport_enrollments._sync_chia_stamp",
        lambda *_: SimpleNamespace(status="chia_confirmed", receipt=credential),
    )
    monkeypatch.setattr(
        native_purchases,
        "get_registry",
        lambda: SimpleNamespace(
            get=lambda _: SimpleNamespace(auth_type=1, owner_pubkey=pubkeys[0])
        ),
    )
    deed = {
        "deedLauncherId": hx(purchase.deed_launcher_id),
        "deedId": "local-deed",
        "proposalId": "local-proposal",
        "confirmationHeight": 120,
        "outputCoinId": hx(available.name()),
    }
    proposal = SimpleNamespace(
        state="EXECUTED",
        executed_bundle_id=hx(_b32(40)),
        smart_deed_inner_puzhash=hx(terms.smart_deed_inner_hash),
        deed_launcher_id=bytes(purchase.deed_launcher_id),
        collection_id="local-collection",
        property_id="local-deed",
        share_ppm=purchase.share_ppm,
    )
    monkeypatch.setattr(
        native_purchases,
        "get_collection_store",
        lambda _: SimpleNamespace(get=lambda _: {"deeds": [deed]}),
    )
    monkeypatch.setattr(
        native_purchases,
        "get_mint_proposal_store",
        lambda _: SimpleNamespace(get=lambda _: proposal),
    )
    genesis = {
        "artifactHash": hx(_b32(23)),
        "launcherIds": {"did": hx(_b32(17))},
        "puzzleHashes": {
            "protocolTreasuryPuzzleHash": hx(purchase.protocol_treasury_puzzle_hash)
        },
    }
    monkeypatch.setattr(
        native_purchases, "load_signed_public_artifact", lambda _: genesis
    )
    for module in (native_purchases, delivery):
        monkeypatch.setattr(module, "configured_validator_pubkeys", lambda _: pubkeys)
    monkeypatch.setattr(
        delivery,
        "load_omnichain_evidence",
        lambda *_a, **_kw: SimpleNamespace(return_puzzle_hash=hx(_b32(48))),
    )

    if is_base:
        evidence = {
            "globalPaymentId": hx(_b32(41)),
            "depositor": "0x" + "42" * 20,
            "settlementToken": settings.payment_evm_usdc_tokens["84532"],
            "transactionHash": hx(_b32(43)),
            "blockNumber": 1234567,
            "blockHash": hx(_b32(44)),
            "logIndex": 2,
            "status": "CONFIRMED",
            "source": {
                "chainId": 84532,
                "spoke": "0x" + "41" * 20,
                "blockTimestamp": 1_900_000_100,
            },
        }
        result_hash = delivery.base_result_authorization_puzzle_hash(
            artifact=purchase, evidence=evidence, return_puzzle_hash=_b32(48)
        )
        receipt = delivery.build_base_settlement_receipt(
            artifact=purchase,
            evidence=evidence,
            result_authorization_puzzle_hash=result_hash,
        )
    else:
        evidence_value = StripeSettlementEvidenceV1(
            stripe_account_id="acct_test123",
            livemode=False,
            payment_intent_id="pi_test123",
            event_id="evt_test123",
            amount_minor=purchase.rail_amount,
            currency="usd",
            method_family=StripeMethodFamily.CARD,
            funding_type=StripeFundingType.CREDIT,
            processing_charge_minor=0,
            status=StripePaymentStatus.SUCCEEDED,
            refunded_minor=0,
            refund_state=StripeRefundState.NONE,
            dispute_state=StripeDisputeState.NONE,
            observed_at=1_900_000_100,
        )
        evidence = stripe_settlement_evidence_to_json(evidence_value)
        receipt = build_stripe_settlement_receipt_v1(
            artifact=purchase, evidence=evidence_value, validator_pubkeys=pubkeys
        )
    receipt_puzzle = curry_stripe_settlement_receipt(
        StripeSettlementTermsV1(receipt=receipt, validator_pubkeys=pubkeys)
    )
    receipt_coin = Coin(_b32(45), receipt_puzzle.get_tree_hash(), uint64(1))
    records = {hx(c.name()): coin_record(c) for c in (launcher, reserved, receipt_coin)}
    queried = []

    async def get_coin(coin_id):
        queried.append(coin_id)
        return records.get(coin_id.lower())

    provider = SimpleNamespace(get_coin_record_by_name=get_coin)
    store = StripeDeliveryStore(str(tmp_path / "delivery.db"))
    operation = store.queue(
        purchase_id=stored.purchase_id,
        evidence=evidence,
        receipt_hash=hx(receipt.receipt_hash),
        payment_rail=rail,
    )
    operation = store.record_receipt_prepared(
        stored.purchase_id,
        input_coin_id=hx(_b32(46)),
        protocol_bundle={
            "coin_spends": [],
            "aggregated_signature": bytes(G2Element()).hex(),
        },
        receipt_coin_id=hx(receipt_coin.name()),
        receipt_puzzle_hash=hx(receipt_coin.puzzle_hash),
    )
    operation = store.record_receipt_confirmed(stored.purchase_id)
    claims = []

    async def local_quorum(_settings, claim):
        claims.append(claim)
        messages = claim.signature_messages(pubkeys)
        assert len(messages) == 1
        signatures = [AugSchemeMPL.sign(keys[index], messages[0]) for index in (0, 1)]
        return SimpleNamespace(
            signer_indices=(0, 1),
            aggregated_signature=AugSchemeMPL.aggregate(signatures),
        )

    monkeypatch.setattr(delivery, "collect_stripe_settlement_quorum", local_quorum)
    worker = delivery.StripeDeliveryWorker(
        settings=settings,
        faucet=Faucet.from_seed_hex("01" * 32, "testnet11"),
        provider=provider,
        submitter=SimpleNamespace(),
        exact_executor=SimpleNamespace(),
        store=store,
        config=delivery.StripeDeliveryWorkerConfig(enabled=True),
    )
    return SimpleNamespace(
        worker=worker,
        operation=operation,
        purchases=purchases,
        purchase=purchase,
        reserved=reserved,
        receipt_coin=receipt_coin,
        receipt=receipt,
        records=records,
        queried=queried,
        claims=claims,
        deed_struct=base.deed_struct,
        store=store,
        rail=rail,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("rail", [PAYMENT_RAIL_STRIPE, PAYMENT_RAIL_BASE_USDC])
async def test_single_delivery_uses_real_confirmed_inventory_and_builds_exact_outputs(
    tmp_path, monkeypatch, rail
):
    case = delivery_case(tmp_path, monkeypatch, rail)
    # Reopen the database; no in-memory context injection can satisfy this test.
    reopened = PaymentPurchaseStore(case.purchases.path)
    (item,) = reopened.inventory_items(case.operation.purchase_id)
    assert item.state == "CONFIRMED" and item.reserved_coin_id == hx(
        case.reserved.name()
    )
    prepared = await case.worker._prepare_delivery(case.operation)
    assert prepared.state == DELIVERY_PREPARED
    assert len(case.claims) == 1
    assert case.claims[0].deed_coin_id == hx(case.reserved.name())
    assert hx(case.reserved.name()) in case.queried
    bundle = SpendBundle.from_json_dict(prepared.delivery_bundle)
    pairs = []
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal, spend.solution, INFINITE_COST
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions, spend.coin, AGG_SIG_ME_DATA["testnet11"]
            )
        )
    assert pairs
    assert AugSchemeMPL.aggregate_verify(
        [pk for pk, _ in pairs],
        [message for _, message in pairs],
        bundle.aggregated_signature,
    )
    destination = SINGLETON_MOD.curry(
        case.deed_struct, puzzle_for_p2_vault(case.purchase.vault_launcher_id)
    ).get_tree_hash()
    outputs = bundle.additions()
    deed_outputs = [
        c for c in outputs if c.puzzle_hash == destination and c.amount == 1
    ]
    assert len(deed_outputs) == 1
    assert hx(deed_outputs[0].name()) == prepared.expected_deed_output_coin_id
    treasury_hash = (
        case.receipt.result_authorization_puzzle_hash
        if rail == PAYMENT_RAIL_BASE_USDC
        else case.purchase.protocol_treasury_puzzle_hash
    )
    assert (
        len([c for c in outputs if c.puzzle_hash == treasury_hash and c.amount == 1])
        == 1
    )
    assert (
        StripeDeliveryStore(case.store.path)
        .get(case.operation.purchase_id)
        .delivery_bundle
        == prepared.delivery_bundle
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["PREPARED", "SUBMITTED"])
async def test_single_delivery_rejects_unconfirmed_inventory_before_quorum(
    tmp_path, monkeypatch, state
):
    case = delivery_case(tmp_path, monkeypatch)
    with sqlite3.connect(case.purchases.path) as connection:
        connection.execute("UPDATE payment_purchases SET inventory_state=?", (state,))
        connection.execute(
            "UPDATE payment_purchase_inventory_items SET state=?", (state,)
        )
    with pytest.raises(HTTPException, match="not yet confirmed"):
        await case.worker._prepare_delivery(case.operation)
    assert not case.claims
    assert case.store.get(case.operation.purchase_id).state == RECEIPT_CONFIRMED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "problem",
    [
        "missing_inventory",
        "other_deed",
        "missing_reserved_coin",
        "spent_reserved_coin",
        "wrong_reserved_puzzle",
    ],
)
async def test_single_delivery_retains_pending_state_when_reservation_cannot_be_verified(
    tmp_path, monkeypatch, problem
):
    case = delivery_case(tmp_path, monkeypatch)
    if problem in {"missing_inventory", "other_deed"}:
        with sqlite3.connect(case.purchases.path) as connection:
            if problem == "missing_inventory":
                connection.execute("DELETE FROM payment_purchase_inventory_items")
            else:
                connection.execute(
                    "UPDATE payment_purchase_inventory_items SET deed_launcher_id=?",
                    (hx(_b32(99)),),
                )
    elif problem == "missing_reserved_coin":
        case.records.pop(hx(case.reserved.name()))
    elif problem == "spent_reserved_coin":
        case.records[hx(case.reserved.name())] = coin_record(case.reserved, spent=125)
    else:
        with sqlite3.connect(case.purchases.path) as connection:
            connection.execute(
                "UPDATE payment_purchase_inventory_items SET reserved_puzzle_hash=?",
                (hx(_b32(99)),),
            )
    with pytest.raises(HTTPException) as failure:
        await case.worker._prepare_delivery(case.operation)
    assert failure.value.status_code == 409
    assert not case.claims
    assert case.store.get(case.operation.purchase_id).state == RECEIPT_CONFIRMED
    assert case.store.get(case.operation.purchase_id).delivery_bundle is None


@pytest.mark.asyncio
async def test_single_delivery_reprepare_after_database_reopen_preserves_exact_bundle(
    tmp_path, monkeypatch
):
    case = delivery_case(tmp_path, monkeypatch)
    prepared = await case.worker._prepare_delivery(case.operation)
    case.worker.store = StripeDeliveryStore(case.store.path)
    restored = case.worker.store.get(prepared.purchase_id)
    retried = await case.worker._prepare_delivery(restored)
    assert retried.state == DELIVERY_PREPARED
    assert retried.delivery_bundle == prepared.delivery_bundle
    assert retried.expected_deed_output_coin_id == prepared.expected_deed_output_coin_id
    assert (
        retried.expected_treasury_output_coin_id
        == prepared.expected_treasury_output_coin_id
    )
    assert len(case.claims) == 2
    assert case.claims[0] == case.claims[1]


@pytest.mark.asyncio
async def test_single_delivery_waits_for_receipt_confirmation_without_consuming_inventory(
    tmp_path, monkeypatch
):
    case = delivery_case(tmp_path, monkeypatch)
    case.records[hx(case.receipt_coin.name())] = coin_record(
        case.receipt_coin, confirmed=0
    )
    result = await case.worker._prepare_delivery(case.operation)
    assert result.state == RECEIPT_CONFIRMED
    assert result.delivery_bundle is None
    assert not case.claims
    assert (
        case.purchases.inventory_items(case.operation.purchase_id)[0].state
        == "CONFIRMED"
    )


@pytest.fixture(autouse=True, params=[1, 2])
def inventory_version_coverage(request, monkeypatch):
    import sys
    original = delivery_case
    def selected(*args, **kwargs):
        kwargs.setdefault("inventory_version", request.param)
        return original(*args, **kwargs)
    monkeypatch.setattr(sys.modules[__name__], "delivery_case", selected)
