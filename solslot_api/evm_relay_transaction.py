"""Canonical local relay transaction and receipt validation; no signing or RPC setup."""
from __future__ import annotations
from typing import Any, Mapping
from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction
from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TransactionNotFound


def signed_transaction_identity(raw: bytes, expected: Mapping[str, Any]) -> dict[str, Any]:
    """Reject unprotected, blob/authorization-list or noncanonical signed transactions."""
    if not isinstance(raw, bytes) or not raw or len(raw) > 1_000_000:
        raise ValueError('signed relay transaction is invalid or too large')
    if raw[0] in (1, 2):
        parsed = TypedTransaction.from_bytes(HexBytes(raw))
        values = parsed.as_dict()
        if parsed.encode() != raw:
            raise ValueError('signed relay transaction encoding is not canonical')
        chain_id = values['chainId']
    elif raw[0] >= 0xc0:
        parsed = Transaction.from_bytes(raw)
        values = parsed.as_dict()
        if values['v'] < 35:
            raise ValueError('relay transaction must be EIP-155 chain protected')
        chain_id = (values['v'] - 35) // 2
    else:
        raise ValueError('unsupported relay transaction type')
    if values.get('accessList'):
        raise ValueError('relay transaction must not introduce an access list')
    sender = Account.recover_transaction(raw).lower()
    identity = dict(chainId=int(chain_id), nonce=int(values['nonce']),
        to=Web3.to_hex(values['to']).lower(), value=int(values['value']),
        data=Web3.to_hex(values['data']).lower(), gas=int(values['gas']))
    observed = {**identity, 'from': sender}
    for field in ('chainId', 'nonce', 'to', 'value', 'data', 'gas', 'from'):
        target = expected[field]
        if field in ('to', 'from'): target = str(target).lower()
        if field == 'data': target = Web3.to_hex(HexBytes(target)).lower()
        if observed[field] != target:
            raise ValueError(f'signed relay transaction {field} does not match approved construction')
    for field in ('gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas'):
        if field in expected and int(values.get(field, -1)) != int(expected[field]):
            raise ValueError(f'signed relay transaction {field} changed')
    return dict(chain_id=int(chain_id), nonce=int(values['nonce']), relayer=sender,
        tx_hash=Web3.to_hex(Web3.keccak(raw)).lower())


def canonical_receipt(w3: Any, tx_hash: str, min_confirmations: int) -> Mapping[str, Any] | None:
    """None means absent/insufficient confirmations; provider errors remain errors.

    Check the canonical block and every log coordinate before a caller treats
    any successful event or revert as a transaction outcome.
    """
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except TransactionNotFound:
        return None
    if receipt is None:
        return None
    def h(value: Any) -> str:
        result = Web3.to_hex(HexBytes(value)).lower()
        if len(result) != 66: raise ValueError('receipt hash must be bytes32')
        return result
    if h(receipt.get('transactionHash')) != tx_hash.lower():
        raise ValueError('receipt transaction hash does not match retained transaction')
    number = receipt.get('blockNumber')
    if type(number) is not int or number <= 0 or (type(receipt.get('status')) is not int or receipt.get('status') not in (0, 1)):
        raise ValueError('receipt has invalid block or status')
    block = w3.eth.get_block(number)
    block_hash = h(receipt.get('blockHash'))
    if h(block.get('hash')) != block_hash or block.get('number') != number:
        raise ValueError('receipt block is no longer canonical')
    for log in receipt.get('logs', []):
        if (log.get('removed', False) is not False or log.get('blockNumber') != number
                or h(log.get('blockHash')) != block_hash or h(log.get('transactionHash')) != tx_hash.lower()):
            raise ValueError('receipt contains removed or mismatched event coordinates')
    if int(w3.eth.block_number) - number + 1 < min_confirmations:
        return None
    return receipt
