"""Bounded canonical evidence for an expired authorization, not a local TTL.

The generator is shared by the API's async primary node and each validator's
independent synchronous node. Callers never accept an HTTP-supplied proof.
"""
from __future__ import annotations

import asyncio
import time
import httpx
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from typing import Any
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from .inventory_recovery import MIN_RELEASE_CONFIRMATIONS, hx, record_coin
from .payment_purchase_store import PaymentPurchaseConflict

MAX_CLOCK_HOPS = 128
PROOF_TIMEOUT_SECONDS = 15


def parse_peak(info: Any, state: Any, network: str) -> tuple[int, str]:
    try:
        chain = state['blockchain_state']; peak = chain['peak']
        if (info['success'] is not True or info['network_name'] != network
                or state['success'] is not True or chain['sync']['synced'] is not True
                or chain['sync']['sync_mode'] is not False
                or type(peak['height']) is not int or peak['height'] < MIN_RELEASE_CONFIRMATIONS):
            raise ValueError('unavailable peak')
        return peak['height'], hx(bytes32.fromhex(peak['header_hash'].removeprefix('0x')))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise PaymentPurchaseConflict('authorization expiry requires a synced primary node on the exact network') from exc


def expiry_queries(coin: Coin, expires_at: int, network: str):
    """Yield RPC reads; return evidence only after checking a stable mature tip."""
    if network != 'testnet11' or type(expires_at) is not int or not 0 < expires_at < 2**64:
        raise PaymentPurchaseConflict('authorization expiry network or deadline is invalid')
    info = yield 'get_network_info', {}
    state = yield 'get_blockchain_state', {}
    peak = parse_peak(info, state, network)
    height, digest = peak
    mature_height = peak[0] - MIN_RELEASE_CONFIRMATIONS + 1
    ancestors = []
    timestamp = None
    newer_timestamp = None
    for _ in range(MAX_CLOCK_HOPS):
        response = yield 'get_block_record', {'header_hash': digest}
        try:
            block = response['block_record']
            if (response['success'] is not True or type(block['height']) is not int
                    or block['height'] != height
                    or hx(bytes32.fromhex(block['header_hash'].removeprefix('0x'))) != digest):
                raise ValueError('wrong ancestor')
            previous = hx(bytes32.fromhex(block['prev_hash'].removeprefix('0x')))
            value = block['timestamp']
            if value is not None and (type(value) is not int or value <= 0):
                raise ValueError('invalid transaction clock')
            if value is not None:
                if (value > int(time.time()) + int(DEFAULT_CONSTANTS.MAX_FUTURE_TIME2)
                        or (newer_timestamp is not None and value >= newer_timestamp)):
                    raise ValueError('inconsistent or future transaction clock')
                newer_timestamp = value
            ancestors.append(dict(height=height, headerHash=digest, previousHash=previous, timestamp=value))
            if height <= mature_height and value is not None:
                timestamp = value
                break
            height -= 1; digest = previous
            if height < 0:
                raise ValueError('invalid ancestry')
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise PaymentPurchaseConflict('authorization expiry lacks exact hash-linked chain time') from exc
    if timestamp is None:
        raise PaymentPurchaseConflict('authorization expiry exceeds the bounded ancestry window')
    if timestamp < expires_at:
        raise PaymentPurchaseConflict('authorization has not expired at a mature canonical block')
    response = yield 'get_coin_record_by_name', {'name': hx(coin.name())}
    # Adapters normalize the API provider's unwrapped coin record to this shape.
    record = response.get('coin_record') if isinstance(response, dict) and response.get('success', True) is True else None
    created, spent = record_coin(record, coin)
    if spent or created > mature_height:
        raise PaymentPurchaseConflict('authorization source is spent, missing or immature')
    final_info = yield 'get_network_info', {}
    final_state = yield 'get_blockchain_state', {}
    if parse_peak(final_info, final_state, network) != peak:
        raise PaymentPurchaseConflict('chain tip changed during authorization expiry proof; reconcile again')
    return dict(schema='solslot.inventory-expiry-chain.v1', network=network,
        sourceCoin=coin.to_json_dict(), sourceCoinId=hx(coin.name()), sourceConfirmationHeight=created,
        expiresAt=expires_at, peakHeight=peak[0], peakHash=peak[1],
        matureTimestamp=timestamp, minConfirmations=MIN_RELEASE_CONFIRMATIONS, ancestors=ancestors)


async def prove_expired_unspent(node: Any, coin: Coin, expires_at: int, network: str) -> dict:
    queries = expiry_queries(coin, expires_at, network)
    async with asyncio.timeout(PROOF_TIMEOUT_SECONDS):
        response = None
        while True:
            try:
                method, args = queries.send(response)
            except StopIteration as done:
                return done.value
            if method == 'get_block_record':
                response = await node.get_block_record(args['header_hash'])
            elif method == 'get_coin_record_by_name':
                response = {'coin_record': await node.get_coin_record_by_name(args['name'])}
            else:
                response = await getattr(node, method)()


def prove_expired_unspent_sync(base_url: str, coin: Coin, expires_at: int, network: str) -> dict:
    """Each private signer reads its own configured node within one total budget."""
    queries = expiry_queries(coin, expires_at, network)
    deadline = time.monotonic() + PROOF_TIMEOUT_SECONDS
    with httpx.Client() as client:
        response = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('authorization expiry proof timed out')
            try:
                method, args = queries.send(response)
            except StopIteration as done:
                return done.value
            result = client.post(base_url.rstrip('/') + '/' + method, json=args,
                                 timeout=min(5.0, remaining))
            result.raise_for_status()
            response = result.json()


async def prove_expired_unspent_batch(node: Any, coins: list[Coin], expires_at: int, network: str) -> list[dict]:
    """Share one mature clock across a bounded batch; still check every input."""
    if not 1 <= len(coins) <= 100 or len({bytes(c.name()) for c in coins}) != len(coins):
        raise PaymentPurchaseConflict('expiry requires 1..100 distinct source coins')
    async with asyncio.timeout(PROOF_TIMEOUT_SECONDS):
        first = await prove_expired_unspent(node, coins[0], expires_at, network)
        result = [first]
        mature_height = first['peakHeight'] - MIN_RELEASE_CONFIRMATIONS + 1
        for coin in coins[1:]:
            created, spent = record_coin(await node.get_coin_record_by_name(hx(coin.name())), coin)
            if spent or created > mature_height:
                raise PaymentPurchaseConflict('authorization batch source is spent, missing or immature')
            result.append({**first, 'sourceCoin': coin.to_json_dict(), 'sourceCoinId': hx(coin.name()),
                           'sourceConfirmationHeight': created})
        if parse_peak(await node.get_network_info(), await node.get_blockchain_state(), network) != (first['peakHeight'], first['peakHash']):
            raise PaymentPurchaseConflict('chain tip changed across the expiry batch; reconcile again')
        return result
