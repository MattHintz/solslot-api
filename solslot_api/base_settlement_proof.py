"""Terminal escrow proof, never accepted by the deposit/delivery signer.

Both the contract settlement event and the token's actual transfer must be in
the same canonical successful receipt. Refunds return the original principal
to the original payer; a failed result with funds still held is not a refund.
"""
from eth_abi import decode, encode
from web3 import Web3

from .escrow_deposit import _verify_deposit, _deposit, rpc_bytes, rpc_hex, EscrowDepositError

SETTLED_TOPIC = Web3.keccak(text='PaymentSettled(bytes32,address,address,uint256,bool,bool)')
TRANSFER_TOPIC = Web3.keccak(text='Transfer(address,address,uint256)')
SETTLED_TYPES = ['address', 'uint256', 'bool', 'bool']


def settlement_hint(*, rpc_url, transaction_hash, cap, global_payment_id, web3_factory=Web3):
    """Locate an event from a retained relay transaction; this is not proof."""
    if not rpc_url:
        raise EscrowDepositError('Base terminal RPC is not configured')
    w3 = web3_factory(web3_factory.HTTPProvider(rpc_url, request_kwargs={'timeout':2.0}, exception_retry_configuration=None))
    if w3.eth.chain_id != cap['chainId']:
        raise EscrowDepositError('Base terminal hint is on another chain')
    receipt = w3.eth.get_transaction_receipt(transaction_hash)
    logs = receipt.get('logs', [])
    if not isinstance(logs, list) or len(logs) > 4096:
        raise EscrowDepositError('Base terminal receipt is malformed or too large')
    matches = [log for log in logs if str(log.get('address','')).lower() == cap['spoke']
        and len(log.get('topics', [])) == 3
        and rpc_bytes(log['topics'][0]) == bytes(SETTLED_TOPIC)
        and rpc_hex(log['topics'][1]) == global_payment_id]
    if len(matches) != 1:
        raise EscrowDepositError('Base terminal hint is missing or ambiguous')
    return dict(transactionHash=transaction_hash, blockNumber=receipt['blockNumber'],
        blockHash=rpc_hex(receipt['blockHash']), logIndex=matches[0]['logIndex'])


def verify_base_settlement(*, rpc_url, evidence, settlement, chain_id, spoke, token,
                           confirmations, recipient, outcome, web3_factory=Web3):
    if outcome not in ('REFUNDED', 'DELIVERED'):
        raise EscrowDepositError('unknown Base terminal outcome')
    ctx = _verify_deposit(rpc_url=rpc_url, evidence=evidence, chain_id=chain_id, spoke=spoke,
        token=token, confirmations=confirmations, web3_factory=web3_factory,
        disposition='REFUNDED' if outcome == 'REFUNDED' else 'SETTLED_SUCCESS')
    query, w3, deposit = ctx['query'], ctx['web3'], ctx['deposit']
    try:
        if (set(settlement) != {'transactionHash', 'blockNumber', 'blockHash', 'logIndex'}
                or type(settlement['blockNumber']) is not int or settlement['blockNumber'] < evidence['source']['blockNumber']
                or type(settlement['logIndex']) is not int or settlement['logIndex'] < 0
                or (outcome == 'REFUNDED' and recipient != evidence['depositor'])):
            raise EscrowDepositError('Base settlement provenance or refund recipient changed')
        receipt = query(lambda: w3.eth.get_transaction_receipt(settlement['transactionHash']))
        block = query(lambda: w3.eth.get_block(settlement['blockNumber']))
        if (receipt.get('status') != 1 or rpc_hex(receipt['transactionHash']) != settlement['transactionHash']
                or receipt['blockNumber'] != settlement['blockNumber']
                or rpc_hex(receipt['blockHash']) != settlement['blockHash']
                or block['number'] != settlement['blockNumber'] or rpc_hex(block['hash']) != settlement['blockHash']
                or ctx['tip']['number'] - block['number'] + 1 < confirmations):
            raise EscrowDepositError('Base settlement is not mature and canonical')
        logs = [log for log in receipt.get('logs', [])
                if log.get('logIndex') == settlement['logIndex'] and str(log.get('address', '')).lower() == spoke]
        if len(logs) != 1:
            raise EscrowDepositError('Base settlement event is missing or ambiguous')
        event = logs[0]
        expected_topics = [bytes(SETTLED_TOPIC), rpc_bytes(evidence['globalPaymentId']), bytes(12)+rpc_bytes(recipient)]
        data = rpc_bytes(event['data'])
        values = decode(SETTLED_TYPES, data, strict=True)
        emergency = deposit['status'] == 5
        succeeded = outcome == 'DELIVERED'
        if (event.get('removed', False) is not False
                or [rpc_bytes(t) for t in event['topics']] != expected_topics
                or encode(SETTLED_TYPES, values) != data
                or values != (token, evidence['amount'], succeeded, emergency)):
            raise EscrowDepositError('Base settlement event differs from exact disposition')
        transfers = []
        for log in receipt.get('logs', []):
            if str(log.get('address', '')).lower() != token:
                continue
            topics = [rpc_bytes(t) for t in log.get('topics', [])]
            if topics != [bytes(TRANSFER_TOPIC), bytes(12)+rpc_bytes(spoke), bytes(12)+rpc_bytes(recipient)]:
                continue
            raw = rpc_bytes(log['data'])
            amount, = decode(['uint256'], raw, strict=True)
            if (log.get('removed', False) is not False or encode(['uint256'], [amount]) != raw
                    or amount != evidence['amount'] or type(log.get('logIndex')) is not int):
                raise EscrowDepositError('Base token transfer differs from principal')
            transfers.append(log)
        if len(transfers) != 1 or transfers[0]['logIndex'] >= settlement['logIndex']:
            raise EscrowDepositError('Base settlement lacks one exact preceding token transfer')
        at_settlement = _deposit(query(lambda: ctx['lookup'].call(block_identifier=block['number'])))
        if any(at_settlement[k] != deposit[k] for k in (*ctx['immutable'], 'status', 'succeeded', 'resultMessageId', 'warpNonce')):
            raise EscrowDepositError('Base settlement receipt differs from historical contract state')
        for pinned in (ctx['sourceBlock'], ctx['tip'], block):
            if rpc_hex(query(lambda pinned=pinned: w3.eth.get_block(pinned['number']))['hash']) != rpc_hex(pinned['hash']):
                raise EscrowDepositError('Base terminal proof changed canonical blocks')
        if _deposit(query(lambda: ctx['lookup'].call())) != deposit:
            raise EscrowDepositError('Base terminal state changed during verification')
        return dict(schema='solslot.base-settlement-confirmation.v1', outcome=outcome,
            globalPaymentId=evidence['globalPaymentId'], recipient=recipient, amount=evidence['amount'],
            chainId=chain_id, spoke=spoke, token=token, emergency=emergency,
            **settlement, peakHeight=ctx['tip']['number'], peakHash=rpc_hex(ctx['tip']['hash']))
    except EscrowDepositError:
        raise
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise EscrowDepositError('Base settlement evidence is malformed') from exc
