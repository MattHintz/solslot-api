"""Independent, bounded Base payment observation and reservation renewal."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import threading
import time
from types import SimpleNamespace

import httpx
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, make_mint_offer_v5_inner, build_inventory_extension_spend
from solslot_puzzles.voucher_presale_v2 import series_terms_from_json, VoucherSeriesState
from solslot_puzzles.voucher_presale_v2_driver import VoucherSeriesStateV2, curry_series

from .base_lifecycle_claims import BaseInventoryExtensionClaim, BasePaymentStartClaim, validate_base_start
from .escrow_deposit import verify_escrow_deposit, same_deposit_message
from .inventory_extension_store import canonical
from .inventory_recovery import hx
from .inventory_timeout_submission import canonical_time
from .validator_inventory_extension import IndependentNode, require_timely_extension

PROOF_DEADLINE_SECONDS = 30
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='base-lifecycle-proof')
_rpc_slots = threading.BoundedSemaphore(2)
_proof_slots = threading.BoundedSemaphore(2)


@contextmanager
def proof_slot():
    if not _proof_slots.acquire(blocking=False):
        raise ValueError('Base lifecycle proof capacity is busy')
    try:
        yield
    finally:
        _proof_slots.release()


def deposit_proof(settings, claim):
    cap = claim.activation
    if (settings.network != 'testnet11' or settings.base_sepolia_spoke_address != cap['spoke']
            or settings.base_sepolia_usdc_address != cap['token']
            or settings.base_sepolia_min_confirmations < cap['minConfirmations']):
        raise ValueError('Base lifecycle RPC route differs from its reviewed deployment')
    return verify_escrow_deposit(rpc_url=settings.base_sepolia_rpc_url,
        evidence=claim.payment_evidence, chain_id=cap['chainId'], spoke=cap['spoke'], token=cap['token'],
        confirmations=settings.base_sepolia_min_confirmations)


async def bounded_deposit_proof(settings, claim):
    # A canceled coroutine never recycles occupied synchronous RPC capacity.
    if not _rpc_slots.acquire(blocking=False):
        raise ValueError('Base lifecycle RPC capacity is busy')
    def work():
        try:
            return deposit_proof(settings, claim)
        finally:
            _rpc_slots.release()
    try:
        future = _executor.submit(work)
    except BaseException:
        _rpc_slots.release()
        raise
    wrapped = asyncio.wrap_future(future)
    wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
    return await asyncio.wait_for(asyncio.shield(wrapped), 15)


def private_context(settings, ledger, claim, claim_hash, artifact):
    purchase, struct, terms = validate_base_start(claim, artifact, settings.deployment_environment)
    if (claim.canonical_hash() != claim_hash or settings.network != claim.network
            or settings.roster_pubkeys != artifact['validatorSet']['pubkeys']
            or len(settings.roster_pubkeys) != 3 or artifact['validatorSet']['threshold'] != 2
            or claim.payment_started_at > int(time.time())):
        raise ValueError('Base lifecycle validator, claim or source clock changed')
    held = ledger.base_inventory_hold(hx(purchase.purchase_id))
    if held is None or held['claim_json'] != canonical(claim.hold.model_dump(mode='json')):
        raise ValueError('Base lifecycle requires this validator\'s original hold')
    if held['payment_start_json'] is not None and not same_deposit_message(json.loads(held['payment_start_json']), claim.payment_evidence):
        raise ValueError('Base lifecycle changes this validator\'s original deposit')
    return purchase, struct, terms


async def sign_base_payment_start(settings, ledger, claim, claim_hash):
    from .validator_service import load_validator_artifact, load_validator_private_key, ValidatorEvidenceError
    try:
        with proof_slot():
            async with asyncio.timeout(PROOF_DEADLINE_SECONDS):
                artifact, _ = load_validator_artifact(settings)
                private_context(settings, ledger, claim, claim_hash, artifact)
                await bounded_deposit_proof(settings, claim)
                if load_validator_artifact(settings)[0] != artifact:
                    raise ValueError('Base lifecycle release changed during payment proof')
                private_context(settings, ledger, claim, claim_hash, artifact)
                signature = hx(AugSchemeMPL.sign(load_validator_private_key(settings), claim.signature_message()))
                return ledger.record_base_lifecycle_observation(claim, signature)
    except Exception as exc:
        raise ValidatorEvidenceError('Base payment start is not independently proven: ' + str(exc)) from exc


async def sign_base_extension(settings, ledger, claim: BaseInventoryExtensionClaim, claim_hash):
    from .validator_service import load_validator_artifact, load_validator_private_key, ValidatorEvidenceError
    try:
        with proof_slot():
            async with asyncio.timeout(PROOF_DEADLINE_SECONDS):
                artifact, _ = load_validator_artifact(settings)
                purchase, struct, terms = private_context(settings, ledger, claim, claim_hash, artifact)
                require_timely_extension(claim, int(time.time()))
                if claim.smart_deed_inner_hash != claim.hold.smart_deed_inner_hash:
                    raise ValueError('Base renewal changes its original SmartDeed implementation')
                series = series_terms_from_json(claim.series_terms)
                if (series.terms_hash != purchase.presale_terms_hash or series.collection_id != purchase.collection_id
                        or series.metadata_root != purchase.metadata_root or series.metadata_anchor_id != purchase.metadata_anchor_id
                        or series.trusted_protocol_treasury != purchase.protocol_treasury_puzzle_hash
                        or series.validator_pubkeys != terms.validator_pubkeys):
                    raise ValueError('Base renewal changes governed presale terms')
                state = VoucherSeriesStateV2(**{**claim.series_state, 'phase': VoucherSeriesState(claim.series_state['phase'])})
                reservation = InventoryReservationV1(purchase, claim.reservation_expires_at)
                async with httpx.AsyncClient(base_url=settings.coinset_base_url.rstrip('/'), timeout=20) as client:
                    node = IndependentNode(client)
                    peak = await node.peak()
                    clock = SimpleNamespace(get_block_record=lambda digest: node.call('get_block_record', {'header_hash': digest}))
                    chain_time = await canonical_time(clock, peak)
                    require_timely_extension(claim, chain_time)
                    coin, lineage = await node.current(claim.reserved_coin_id,
                        SINGLETON_MOD.curry(struct, make_mint_offer_v5_inner(terms, reservation)).get_tree_hash(), struct, peak)
                    if hx(coin.puzzle_hash) != claim.reserved_puzzle_hash:
                        raise ValueError('Base renewal changes its current reserved puzzle')
                    series_struct = singleton_struct(series.series_singleton_id)
                    await node.current(claim.series_coin_id,
                        SINGLETON_MOD.curry(series_struct, curry_series(series, state)).get_tree_hash(),
                        series_struct, peak, require_unspent=False)
                    await bounded_deposit_proof(settings, claim)
                    if await node.peak() != peak:
                        raise ValueError('Base renewal chain tip changed')
                indices = tuple(sorted((settings.signer_index, (settings.signer_index+1) % 3)))
                transition = build_inventory_extension_spend(reserved_coin=coin, deed_singleton_struct=struct,
                    lineage_proof=lineage, reservation=reservation, next_expires_at=claim.next_expires_at,
                    signer_indices=indices, terms=terms)
                if hx(transition.validator_message) != claim.validator_message or load_validator_artifact(settings)[0] != artifact:
                    raise ValueError('Base renewal message or reviewed deployment changed')
                require_timely_extension(claim, int(time.time()))
                private_context(settings, ledger, claim, claim_hash, artifact)
                # Retain verified source bytes before authorizing any renewal.
                start = BasePaymentStartClaim(network=claim.network, genesis_artifact_hash=claim.genesis_artifact_hash,
                    activation=claim.activation, purchase_artifact=claim.purchase_artifact,
                    hold=claim.hold, payment_evidence=claim.payment_evidence)
                key = load_validator_private_key(settings)
                ledger.record_base_lifecycle_observation(start, hx(AugSchemeMPL.sign(key, start.signature_message())))
                return ledger.record_inventory_extension_or_recover(claim_hash=claim_hash,
                    canonical_claim=canonical(claim.model_dump(mode='json')), purchase_id=hx(purchase.purchase_id),
                    reserved_coin_id=claim.reserved_coin_id, deed_launcher_id=hx(purchase.deed_launcher_id),
                    signature=hx(AugSchemeMPL.sign(key, claim.signature_message())))
    except Exception as exc:
        raise ValidatorEvidenceError('Base renewal is not independently proven: ' + str(exc)) from exc
