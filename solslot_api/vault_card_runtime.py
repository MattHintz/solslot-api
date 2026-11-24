"""Construct an order-scoped Testnet worker without providing a public fee submitter."""

import os
import stat

from .faucet import Faucet
from .protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from .stripe_delivery_store import get_stripe_delivery_store
from .stripe_delivery_worker import StripeDeliveryWorker, StripeDeliveryWorkerConfig
from .vault_card_native import VaultCardNative


class CardPrimary:
    """Use the selected native primary for canonical inputs, outputs and mempool observations."""

    def __init__(self, provider):
        self.provider = provider
        self.primary = provider.primary

    async def get_coin_record_by_name(self, coin):
        return await self.provider.get_coin_record_by_name_primary(coin)

    async def get_coin_records_by_puzzle_hash(self, puzzle_hash, *, include_spent):
        return await self.provider.get_coin_records_by_puzzle_hash_primary(
            puzzle_hash, include_spent=include_spent
        )

    async def get_mempool_items_by_coin_name(self, coin):
        return await self.primary.get_mempool_items_by_coin_name(coin)

    def __getattr__(self, name):
        if name.endswith("_primary") or name in {
            "_primary_inputs_clear",
            "get_fee_estimate",
            "get_cost_fee_advice",
            "primary_expiry_input_evidence",
            "push_tx_confirmed_in_primary_mempool",
            "observe_exact_protocol_bundle",
        }:
            return getattr(self.provider, name)
        raise AttributeError(name)


def build_worker(app, settings, executor):
    from .payment_purchase_store import get_payment_purchase_store

    native = VaultCardNative.configured(settings)
    if (
        settings.network != "testnet11"
        or settings.stripe_mode != "test"
        or not settings.generation_customer_enabled
        or settings.stripe_settlement_enabled
        or not settings.chia_primary_url
        or settings.alpha_writes_enabled
        or settings.minting_enabled
        or settings.protocol_fee_funding_enabled
        or settings.stripe_delivery_worker_enabled
        or settings.voucher_issuance_worker_enabled
        or not settings.vault_card_fee_seed_file
    ):
        raise ValueError(
            "A separate current-generation Testnet card configuration is required"
        )
    with os.fdopen(
        os.open(
            settings.vault_card_fee_seed_file,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        ),
        "rb",
    ) as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o077
            or info.st_size > 128
        ):
            raise ValueError("Private operator card funding credential is unavailable")
        encoded_key = source.read(129).strip().decode("ascii")
        kind = getattr(settings, "vault_card_fee_key_kind", "seed")
        if kind == "master":
            till = Faucet.from_master_private_key_hex(encoded_key, settings.network)
        elif kind == "seed":
            till = Faucet.from_seed_hex(encoded_key, settings.network)
        else:
            raise ValueError("Unrecognized card funding credential format")
    if till.address_hex != settings.vault_card_fee_puzzle_hash:
        raise ValueError("Current card funding address differs")
    ordinary = getattr(app.state, "faucet", None)
    if ordinary and ordinary.address_hex == till.address_hex:
        raise ValueError("Card sponsor must be independently held")
    for name in (
        "stamp_funding_store",
        "redemption_review_store",
        "generation_operations",
        "generation_mint_reviews",
        "sols_swap_store",
    ):
        store = getattr(app.state, name, None)
        if store:
            source = (
                getattr(store, "reserved_input_coin_ids", None)
                or store.reserved_coin_ids
            )
            till.add_coin_reservation_source(source)
    db = get_payment_purchase_store(settings.payment_purchase_db_path)
    deliveries = get_stripe_delivery_store(settings.stripe_delivery_db_path)
    for source in (
        db.pending_timeout_fee_coin_ids,
        db.pending_extension_fee_coin_ids,
        deliveries.pending_exact_fee_coin_ids,
    ):
        till.add_coin_reservation_source(source)
    cap = min(native.scope.maximumFeePerStageMojos, settings.protocol_maximum_fee_mojos)
    if not 0 < settings.protocol_minimum_fee_mojos <= cap:
        raise ValueError("Card fee minimum exceeds approved cap")
    primary = CardPrimary(app.state.coinset)
    submitter = ProtocolBundleSubmitter(
        provider=primary,
        faucet=till,
        funding_store=app.state.protocol_funding_store,
        policy=ProtocolFeePolicy(
            enabled=True,
            minimum_mojos=settings.protocol_minimum_fee_mojos,
            maximum_mojos=cap,
            maximum_funding_coin_mojos=settings.faucet_max_spend_mojos,
            target_seconds=settings.protocol_medium_fee_target_seconds,
            estimate_buffer_bps=settings.protocol_fee_estimate_buffer_bps,
            native_admission_enabled=settings.protocol_fee_native_admission_enabled,
            cost_fee_tiers_enabled=settings.protocol_fee_cost_tiers_enabled,
            mempool_timeout_seconds=settings.protocol_mempool_timeout_seconds,
            mempool_poll_seconds=settings.protocol_mempool_poll_seconds,
        ),
    )
    return StripeDeliveryWorker(
        settings=settings,
        faucet=till,
        provider=primary,
        submitter=submitter,
        exact_executor=executor,
        store=deliveries,
        config=StripeDeliveryWorkerConfig(
            enabled=True,
            interval_seconds=settings.stripe_delivery_interval_seconds,
            lease_seconds=settings.stripe_delivery_lease_seconds,
        ),
    )
