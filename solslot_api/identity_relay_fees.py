"""Base sponsorship limits and fresh OP auxiliary-fee checks.

Execution fees are capped by the signed EIP-1559 transaction. OP's L1 and
operator fees are not capped by that field: the remaining reviewed allowance
is checked before every dispatch, and reserved conservatively in the ledger.
No fee bump, new nonce, token transfer, or automatic funding is authorized here.
"""
from __future__ import annotations

from typing import Any, Mapping
from web3 import Web3
from hexbytes import HexBytes

ORACLE = '0x420000000000000000000000000000000000000F'
ORACLE_ABI = [
    {'type': 'function', 'name': name, 'stateMutability': 'view',
     'inputs': [{'name': 'size' if name == 'getL1FeeUpperBound' else 'gas', 'type': 'uint256'}],
     'outputs': [{'name': '', 'type': 'uint256'}]}
    for name in ('getL1FeeUpperBound', 'getOperatorFee')
]
QUOTE_KEYS = {'schema', 'chainId', 'relayer', 'gas', 'maxFeePerGas',
              'maxPriorityFeePerGas', 'maximumSignedBytes', 'maximumFeeWei',
              'auxiliaryFeeBudgetWei', 'dailyFeeLimitWei', 'quotedBlock'}


class RelayFeeUnavailable(ValueError):
    """Static messages only: never expose provider payloads or proof data."""


def validate_quote(quote: Mapping[str, Any], tx: Mapping[str, Any]) -> None:
    if (set(quote) != QUOTE_KEYS or quote['schema'] != 'solslot.base-identity-relay-fee.v1'
            or quote['chainId'] != 8453 or tx['chainId'] != 8453
            or quote['relayer'] != str(tx['from']).lower() or tx.get('type') != 2
            or 'gasPrice' in tx or tx.get('accessList')):
        raise RelayFeeUnavailable('The Base sponsorship construction differs from its fee review.')
    if any(type(quote[field]) is not int for field in QUOTE_KEYS - {'schema', 'relayer'}):
        raise RelayFeeUnavailable('The Base sponsorship allowance must contain canonical integers.')
    for field in ('gas', 'maxFeePerGas', 'maxPriorityFeePerGas'):
        if type(quote[field]) is not int or quote[field] <= 0 or quote[field] != tx[field]:
            raise RelayFeeUnavailable('The Base transaction fee fields differ from their review.')
    if (not 0 < quote['gas'] <= 3_750_000 or
            quote['maxPriorityFeePerGas'] > quote['maxFeePerGas'] or
            not 0 < quote['maximumFeeWei'] <= 100_000_000_000_000 or
            not quote['maximumFeeWei'] <= quote['dailyFeeLimitWei'] <= 1_000_000_000_000_000 or
            quote['auxiliaryFeeBudgetWei'] != quote['maximumFeeWei'] - quote['gas'] * quote['maxFeePerGas'] or
            quote['auxiliaryFeeBudgetWei'] <= 0 or
            quote['maximumSignedBytes'] != len(HexBytes(tx['data'])) + 512 or
            not 0 < quote['maximumSignedBytes'] <= 1_000_000 or
            type(quote['quotedBlock']) is not int or quote['quotedBlock'] <= 0 or int(tx.get('value', -1)) != 0):
        raise RelayFeeUnavailable('The Base sponsorship allowance is invalid.')


def auxiliary_fee(w3: Any, *, maximum_signed_bytes: int, gas: int) -> int:
    oracle = w3.eth.contract(address=Web3.to_checksum_address(ORACLE), abi=ORACLE_ABI)
    value = (int(oracle.functions.getL1FeeUpperBound(maximum_signed_bytes).call()) +
             int(oracle.functions.getOperatorFee(gas).call()))
    if value < 0:
        raise RelayFeeUnavailable('The identity network returned an invalid auxiliary fee.')
    return value


def quote_base_transaction(settings: Any, w3: Any, transaction: Mapping[str, Any]):
    """Read-only quote; both owner modes use the same execution/auxiliary limits."""
    maximum = settings.zkpassport_base_relay_max_fee_wei
    daily = settings.zkpassport_base_relay_daily_fee_wei
    if not 0 < maximum <= daily:
        raise RelayFeeUnavailable('Sponsored Base identity submissions are awaiting an approved fee budget.')
    if int(w3.eth.chain_id) != 8453 or transaction['chainId'] != 8453:
        raise RelayFeeUnavailable('The identity fee RPC is on the wrong network.')
    tx = {k: v for k, v in transaction.items()
          if k not in ('gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'type', 'accessList')}
    block = w3.eth.get_block('latest')
    base_fee = int(block['baseFeePerGas'])
    priority = max(1_000_000, int(w3.eth.max_priority_fee))
    tx.update(type=2, maxPriorityFeePerGas=priority, maxFeePerGas=base_fee * 2 + priority)
    quote = dict(schema='solslot.base-identity-relay-fee.v1', chainId=8453,
        relayer=str(tx['from']).lower(), gas=tx['gas'], maxFeePerGas=tx['maxFeePerGas'],
        maxPriorityFeePerGas=priority, maximumSignedBytes=len(HexBytes(tx['data'])) + 512,
        maximumFeeWei=maximum, auxiliaryFeeBudgetWei=maximum - tx['gas'] * tx['maxFeePerGas'],
        dailyFeeLimitWei=daily, quotedBlock=int(block['number']))
    validate_quote(quote, tx)
    check_base_dispatch(settings, w3, quote)
    return tx, quote


def check_base_dispatch(settings: Any, w3: Any, quote: Mapping[str, Any]) -> None:
    """Recheck the original allowance; never modify retained signed bytes."""
    if (quote['chainId'] != 8453 or int(w3.eth.chain_id) != 8453 or
            quote['maximumFeeWei'] > settings.zkpassport_base_relay_max_fee_wei or
            quote['dailyFeeLimitWei'] > settings.zkpassport_base_relay_daily_fee_wei):
        raise RelayFeeUnavailable('The retained Base relay exceeds the current approved fee budget.')
    block = w3.eth.get_block('latest')
    if int(block['baseFeePerGas']) + quote['maxPriorityFeePerGas'] > quote['maxFeePerGas']:
        raise RelayFeeUnavailable('Network fees exceed the saved transaction limit. The original proof transaction is preserved.')
    if auxiliary_fee(w3, maximum_signed_bytes=quote['maximumSignedBytes'], gas=quote['gas']) > quote['auxiliaryFeeBudgetWei']:
        raise RelayFeeUnavailable('Network auxiliary fees exceed the reviewed allowance. The original proof transaction is preserved.')
    if int(w3.eth.get_balance(quote['relayer'], 'pending')) < quote['maximumFeeWei']:
        raise RelayFeeUnavailable('Solslot identity fee funding is low. The original proof transaction is preserved for retry.')
