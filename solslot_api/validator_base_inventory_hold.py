"""Independent, read-only Base and Chia proof before a durable private hold."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading
import time
from types import SimpleNamespace

import httpx
from eth_abi import encode
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL
from web3 import Web3
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, make_mint_offer_v5_inner

from .base_inventory_hold import base_hold_coordinates
from .escrow_deposit import RPC_TIMEOUT_SECONDS, PROOF_DEADLINE_SECONDS, EscrowProviderUnavailable, rpc_hex
from .inventory_recovery import hx
from .inventory_timeout_submission import canonical_time
from .validator_inventory_extension import IndependentNode

ABI = [dict(type='function', name=name, stateMutability='view', inputs=inputs, outputs=[dict(name='', type=kind)])
       for name, inputs, kind in [
           ('localChainSelector', [], 'uint64'), ('paused', [], 'bool'),
           ('globalPaymentForPurchase', [dict(name='purchaseId', type='bytes32')], 'bytes32')]]

_slots = threading.BoundedSemaphore(2)
_fresh_slots = threading.BoundedSemaphore(2)
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='base-hold-proof')


@contextmanager
def fresh_proof_slot():
    # Bound the entire proof, including async Chia reads after EVM completes.
    if not _fresh_slots.acquire(blocking=False):
        raise EscrowProviderUnavailable('Base prepayment proof capacity is busy')
    try:
        yield
    finally:
        _fresh_slots.release()


async def bounded_unfunded_proof(settings, claim):
    if not _slots.acquire(blocking=False):
        raise EscrowProviderUnavailable('Base prepayment proof capacity is busy')
    def work():
        try:
            return verify_unfunded_base_hold(settings, claim)
        finally:
            _slots.release()
    try:
        future = asyncio.wrap_future(_executor.submit(work))
    except BaseException:
        _slots.release()
        raise
    future.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
    # Request cancellation cannot recycle a slot while provider I/O is running.
    await asyncio.wait_for(asyncio.shield(future), 15)


def verify_unfunded_base_hold(settings, claim, *, web3_factory=Web3):
    active = claim.activation
    if (not settings.base_sepolia_rpc_url
            or settings.base_sepolia_spoke_address.lower() != active['spoke']
            or settings.base_sepolia_usdc_address.lower() != active['token']
            or settings.base_sepolia_min_confirmations < active['minConfirmations']):
        raise ValueError('Base hold RPC configuration differs from reviewed deployment')
    expected = Web3.keccak(encode(['uint8', 'uint64', 'address', 'address', 'bytes32', 'bytes32', 'bytes32'],
        [3, active['sourceChainSelector'], active['spoke'], active['token'],
         bytes.fromhex(claim.local_payment_id[2:]), bytes.fromhex(claim.purchase_artifact['purchaseId'][2:]),
         bytes.fromhex(claim.purchase_artifact['artifactHash'][2:])]))
    if hx(expected) != claim.global_payment_id:
        raise ValueError('Base global payment identity differs from the deployed codec')
    deadline = time.monotonic() + PROOF_DEADLINE_SECONDS
    def query(call):
        if time.monotonic() >= deadline:
            raise EscrowProviderUnavailable('Base hold verification deadline exceeded')
        try:
            result = call()
        except Exception as exc:
            raise EscrowProviderUnavailable('Base hold provider is unavailable') from exc
        if time.monotonic() >= deadline:
            raise EscrowProviderUnavailable('Base hold verification deadline exceeded')
        return result
    w3 = web3_factory(web3_factory.HTTPProvider(settings.base_sepolia_rpc_url,
        request_kwargs={'timeout': RPC_TIMEOUT_SECONDS}, exception_retry_configuration=None))
    if query(lambda: w3.eth.chain_id) != active['chainId']:
        raise ValueError('Base hold provider is on another network')
    tip = query(lambda: w3.eth.get_block('latest'))
    if (type(tip['number']) is not int or tip['number'] <= 0
            or type(tip['timestamp']) is not int or not 0 < tip['timestamp'] < claim.reservation_expires_at):
        raise ValueError('Base chain clock has expired the original reservation')
    contract = w3.eth.contract(address=Web3.to_checksum_address(active['spoke']), abi=ABI)
    if (query(lambda: contract.functions.localChainSelector().call(block_identifier=tip['number'])) != active['sourceChainSelector']
            or query(lambda: contract.functions.paused().call(block_identifier=tip['number'])) is not False):
        raise ValueError('Base escrow route is paused or differs from its reviewed deployment')
    lookup = contract.functions.globalPaymentForPurchase(claim.purchase_artifact['purchaseId'])
    # The contract has one deposit per purchase. Check current state twice and
    # retain a private exclusion even if a deposit races the final observation.
    if any(rpc_hex(query(lambda block=block: lookup.call(block_identifier=block))) != '0x'+'0'*64
           for block in (tip['number'], 'latest')):
        raise ValueError('Base purchase is already funded; recover its original payment')
    if rpc_hex(query(lambda: w3.eth.get_block(tip['number']))['hash']) != rpc_hex(tip['hash']):
        raise ValueError('Base canonical tip changed while arming')


async def sign_base_inventory_hold(settings, ledger, claim, claim_hash):
    from .validator_service import load_validator_artifact, load_validator_private_key, ValidatorEvidenceError
    try:
        artifact, _ = load_validator_artifact(settings)
        purchase, struct, terms = base_hold_coordinates(claim, artifact, settings.deployment_environment)
        if (claim_hash != claim.canonical_hash() or settings.network != claim.network
                or settings.roster_pubkeys != artifact['validatorSet']['pubkeys']
                or len(settings.roster_pubkeys) != 3 or artifact['validatorSet']['threshold'] != 2):
            raise ValueError('Base hold validator identity or claim changed')
        old = ledger.base_inventory_hold(hx(purchase.purchase_id))
        if old is not None:
            # No replacement, new deadline, or new payment permission on retry.
            return ledger.record_base_inventory_hold(claim, old['signature'])
        with fresh_proof_slot():
            purchase.assert_live(int(time.time()))
            if not 0 < claim.reservation_expires_at-int(time.time()) <= claim.activation['maxSoftQuoteSeconds']:
                raise ValueError('Base prepayment hold exceeds its reviewed soft quote window')
            await bounded_unfunded_proof(settings, claim)
            reservation = InventoryReservationV1(purchase, claim.reservation_expires_at)
            async with httpx.AsyncClient(base_url=settings.coinset_base_url.rstrip('/'), timeout=20) as client:
                node = IndependentNode(client)
                peak = await node.peak()
                clock_node = SimpleNamespace(get_block_record=lambda digest: node.call('get_block_record', {'header_hash': digest}))
                if await canonical_time(clock_node, peak) >= claim.reservation_expires_at:
                    raise ValueError('Chia reservation has expired')
                expected = SINGLETON_MOD.curry(struct, make_mint_offer_v5_inner(terms, reservation)).get_tree_hash()
                coin, _ = await node.current(claim.reserved_coin_id, expected, struct, peak)
                if hx(coin.puzzle_hash) != claim.reserved_puzzle_hash or await node.peak() != peak:
                    raise ValueError('Base reserved coin or Chia tip changed')
            if load_validator_artifact(settings)[0] != artifact or claim.canonical_hash() != claim_hash:
                raise ValueError('Base hold release changed during independent proof')
            purchase.assert_live(int(time.time()))
            return ledger.record_base_inventory_hold(claim,
                hx(AugSchemeMPL.sign(load_validator_private_key(settings), claim.signature_message())))
    except Exception as exc:
        raise ValidatorEvidenceError('Base prepayment hold is not independently proven') from exc
