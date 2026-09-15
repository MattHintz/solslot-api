"""Independent terminal lane; provider/chain facts precede append-only tombstones."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import threading
from types import SimpleNamespace

import httpx
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL, SpendBundle
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, make_mint_offer_v5_inner, build_inventory_release_spend

from .base_inventory_hold import base_hold_coordinates
from .base_lifecycle_claims import BasePaymentStartClaim, lifecycle_artifact, hold_origin, validate_base_start
from .base_settlement_proof import verify_base_settlement
from .checkout_terminals import paid_output, general_coin_record
from .escrow_deposit import same_deposit_message
from .inventory_extension_chain import verify_signature
from .inventory_extension_store import canonical
from .inventory_recovery import hx, record_coin, decode_spend, equivalent_timeout_spend
from .validator_base_inventory_hold import verify_unfunded_base_timeout
from .validator_inventory_extension import IndependentNode

PROOF_DEADLINE_SECONDS = 30
_proof_slots = threading.BoundedSemaphore(2)
_rpc_slots = threading.BoundedSemaphore(2)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='base-terminal-proof')


def terminal_payment_proof(settings, claim):
    cap = claim.activation
    if (settings.network != 'testnet11' or settings.base_sepolia_spoke_address != cap['spoke']
            or settings.base_sepolia_usdc_address != cap['token']
            or settings.base_sepolia_min_confirmations < cap['minConfirmations']):
        raise ValueError('Base terminal RPC route differs from its reviewed deployment')
    if claim.payment_evidence is None:
        if claim.kind != 'RETURNED' or claim.settlement is not None:
            raise ValueError('unfunded observation cannot claim paid delivery')
        return verify_unfunded_base_timeout(settings, claim.hold)
    return verify_base_settlement(rpc_url=settings.base_sepolia_rpc_url, evidence=claim.payment_evidence,
        settlement=claim.settlement, chain_id=cap['chainId'], spoke=cap['spoke'], token=cap['token'],
        confirmations=settings.base_sepolia_min_confirmations,
        recipient=cap['payoutAddress'] if claim.kind == 'DELIVERED' else claim.hold.depositor,
        outcome='DELIVERED' if claim.kind == 'DELIVERED' else 'REFUNDED')


async def bounded_terminal_payment(settings, claim):
    return await bounded_terminal_rpc(lambda: terminal_payment_proof(settings, claim))


async def bounded_terminal_rpc(callback):
    if not _rpc_slots.acquire(blocking=False):
        raise ValueError('Base terminal RPC capacity is busy')
    def work():
        try:
            return callback()
        finally:
            _rpc_slots.release()
    try:
        future = asyncio.wrap_future(_executor.submit(work))
    except BaseException:
        _rpc_slots.release()
        raise
    future.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
    return await asyncio.wait_for(asyncio.shield(future), 15)


def terminal_context(claim, artifact, environment):
    authorized = lifecycle_artifact(claim.activation, claim.genesis_artifact_hash, artifact, environment)
    origin = hold_origin(claim.hold, authorized, environment)
    purchase, struct, terms = base_hold_coordinates(claim.hold, origin, environment)
    if claim.payment_evidence is not None:
        validate_base_start(BasePaymentStartClaim(network=claim.network, genesis_artifact_hash=claim.genesis_artifact_hash,
            activation=claim.activation, purchase_artifact=claim.hold.purchase_artifact,
            hold=claim.hold, payment_evidence=claim.payment_evidence), artifact, environment)
    elif claim.kind != 'RETURNED' or claim.settlement is not None:
        raise ValueError('Base paid disposition requires original deposit and settlement proof')
    return purchase, struct, terms


async def verify_terminal_chain(node, claim, purchase, struct, terms):
    peak = await node.peak()
    reservation = InventoryReservationV1(purchase, claim.reservation_expires_at)
    expected = SINGLETON_MOD.curry(struct, make_mint_offer_v5_inner(terms, reservation)).get_tree_hash()
    coin, lineage = await node.current(claim.reserved_coin_id, expected, struct, peak, require_unspent=False)
    raw, _ = await node.record(claim.reserved_coin_id)
    created, spent = record_coin(raw, coin)
    if spent != claim.confirmation_height or peak[0]-spent+1 < 3 or spent <= created:
        raise ValueError('Base terminal input is not its mature canonical spend')
    async def canonical_spend(spend):
        raw = (await node.call('get_puzzle_and_solution', {'coin_id':hx(spend.coin.name()), 'height':spent}))['coin_solution']
        if decode_spend(raw, spend.coin) != spend:
            raise ValueError('Base terminal differs from the canonical transaction')
    if claim.kind == 'RETURNED':
        if claim.spend_bundle is not None:
            raise ValueError('Base return cannot supply a paid bundle')
        returned = build_inventory_release_spend(reserved_coin=coin, deed_singleton_struct=struct,
            lineage_proof=lineage, reservation=reservation, terms=terms, timed_out=True)
        raw = (await node.call('get_puzzle_and_solution', {'coin_id':claim.reserved_coin_id, 'height':spent}))['coin_solution']
        if not equivalent_timeout_spend(decode_spend(raw, coin), returned.spend):
            raise ValueError('Base return is not the exact reservation timeout')
        output = returned.next_coin
        raw, _ = await node.record(hx(output.name()))
        confirmed, output_spent = record_coin(raw, output)
        if confirmed != spent or output_spent:
            raise ValueError('Base returned inventory is not atomically confirmed and available')
    else:
        bundle = SpendBundle.from_json_dict(claim.spend_bundle)
        if not 0 < len(bundle.coin_spends) <= 128 or sum(s.coin == coin for s in bundle.coin_spends) != 1:
            raise ValueError('Base delivery has another reserved input or unsupported bundle')
        verify_signature(bundle, 'testnet11')
        output = paid_output(SimpleNamespace(coin=coin, struct=struct, reservation=reservation), bundle)
        for spend in bundle.coin_spends:
            raw = (await node.call('get_coin_record_by_name', {'name':hx(spend.coin.name())}))['coin_record']
            _, height = general_coin_record(raw, spend.coin)
            if height != spent:
                raise ValueError('Base delivery inputs did not confirm atomically')
            await canonical_spend(spend)
        removed = {c.name() for c in bundle.removals()}
        for addition in bundle.additions():
            if addition.name() not in removed:
                raw = (await node.call('get_coin_record_by_name', {'name':hx(addition.name())}))['coin_record']
                height, _ = general_coin_record(raw, addition)
                if height != spent:
                    raise ValueError('Base delivery outputs did not confirm atomically')
    if hx(output.name()) != claim.output_coin_id or await node.peak() != peak:
        raise ValueError('Base terminal output or canonical tip changed')
    return peak


async def sign_base_terminal(settings, ledger, claim, claim_hash):
    from .validator_service import load_validator_artifact, load_validator_private_key, ValidatorEvidenceError
    if not _proof_slots.acquire(blocking=False):
        raise ValidatorEvidenceError('Base terminal proof capacity is busy')
    try:
        async with asyncio.timeout(PROOF_DEADLINE_SECONDS):
            artifact, _ = load_validator_artifact(settings)
            purchase, struct, terms = terminal_context(claim, artifact, settings.deployment_environment)
            if (claim.canonical_hash() != claim_hash or settings.network != claim.network
                    or settings.roster_pubkeys != artifact['validatorSet']['pubkeys']
                    or len(settings.roster_pubkeys) != 3 or artifact['validatorSet']['threshold'] != 2):
                raise ValueError('Base terminal validator or claim identity changed')
            old = ledger.base_lifecycle_terminal(hx(purchase.purchase_id))
            if old is not None:
                return ledger.record_base_lifecycle_terminal(claim, old['signature'])
            held = ledger.base_inventory_hold(hx(purchase.purchase_id))
            if held:
                if held['claim_json'] != canonical(claim.hold.model_dump(mode='json')):
                    raise ValueError('Base terminal changes the original private hold')
                if held['payment_start_json'] is not None and (claim.payment_evidence is None
                        or not same_deposit_message(json.loads(held['payment_start_json']), claim.payment_evidence)):
                    raise ValueError('Base terminal cannot erase or replace verified funding')
            await bounded_terminal_payment(settings, claim)
            async with httpx.AsyncClient(base_url=settings.coinset_base_url.rstrip('/'), timeout=20) as client:
                await verify_terminal_chain(IndependentNode(client), claim, purchase, struct, terms)
            if load_validator_artifact(settings)[0] != artifact:
                raise ValueError('Base terminal deployment changed during proof')
            return ledger.record_base_lifecycle_terminal(claim,
                hx(AugSchemeMPL.sign(load_validator_private_key(settings), claim.signature_message())))
    except Exception as exc:
        raise ValidatorEvidenceError('Base terminal is not independently proven: '+str(exc)) from exc
    finally:
        _proof_slots.release()
