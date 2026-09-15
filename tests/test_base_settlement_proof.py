"""Real ABI/canonical receipt checks with an explicitly synthetic EVM provider."""
from copy import deepcopy

import pytest
from eth_abi import encode
from solslot_api.base_settlement_proof import verify_base_settlement, SETTLED_TOPIC, TRANSFER_TOPIC, SETTLED_TYPES
from solslot_api.escrow_deposit import EscrowDepositError
from tests.test_escrow_deposit import Chain, h


class SettledChain(Chain):
    def __init__(self, evidence=None, status=4):
        super().__init__(evidence)
        e = self.evidence
        self.status = status
        self.recipient = '0x'+'15'*20 if status == 3 else e['depositor']
        self.current[18:] = self.latest[18:] = [status, status == 3]
        self.current[10] = self.latest[10] = bytes.fromhex(h(31)[2:]) if status != 5 else bytes(32)
        self.current[11] = self.latest[11] = bytes.fromhex(h(32)[2:]) if status != 5 else bytes(32)
        self.settlement = dict(transactionHash=h(33), blockNumber=self.block['number']+2, blockHash=h(34), logIndex=2)
        self.settlement_block = dict(number=self.settlement['blockNumber'], hash=self.settlement['blockHash'], timestamp=self.block['timestamp']+10)
        transfer = dict(address=e['settlementToken'], logIndex=1, removed=False,
            topics=[TRANSFER_TOPIC, '0x'+'00'*12+e['source']['spoke'][2:], '0x'+'00'*12+self.recipient[2:]],
            data=encode(['uint256'], [e['amount']]))
        settled = dict(address=e['source']['spoke'], logIndex=2, removed=False,
            topics=[SETTLED_TOPIC, e['globalPaymentId'], '0x'+'00'*12+self.recipient[2:]],
            data=encode(SETTLED_TYPES, [e['settlementToken'], e['amount'], status == 3, status == 5]))
        self.settled_receipt = dict(status=1, **{k:v for k,v in self.settlement.items() if k != 'logIndex'}, logs=[transfer,settled])

    def get_block(self, height):
        if height == self.settlement['blockNumber']:
            return deepcopy(self.settlement_block)
        return super().get_block(height)

    def get_transaction_receipt(self, tx):
        if tx == self.settlement['transactionHash']:
            if self.fail == 'settlement':
                raise OSError('settlement provider unavailable')
            return deepcopy(self.settled_receipt)
        return super().get_transaction_receipt(tx)

    def terminal(self):
        e = self.evidence
        return verify_base_settlement(rpc_url='https://offline.invalid', evidence=e,
            settlement=self.settlement, chain_id=84532, spoke=e['source']['spoke'], token=e['settlementToken'],
            confirmations=3, recipient=self.recipient, outcome='DELIVERED' if self.status == 3 else 'REFUNDED',
            web3_factory=self.web3)


@pytest.mark.parametrize('status', [3,4,5])
def test_terminal_requires_actual_settlement_and_token_transfer(status):
    c = SettledChain(status=status)
    result = c.terminal()
    assert result['amount'] == c.evidence['amount'] and result['recipient'] == c.recipient
    assert result['emergency'] is (status == 5)
    # The existing deposit signer never accepts refunded terminal state.
    if status != 3:
        with pytest.raises(EscrowDepositError):
            c.verify()


@pytest.mark.parametrize('problem', ['failed_result','pending','late_change','missing_transfer','wrong_transfer_amount',
    'wrong_token','wrong_recipient','duplicate_transfer','removed_transfer','transfer_after_event',
    'wrong_event_amount','wrong_global','wrong_event_emitter','reverted','tx','block_hash',
    'unconfirmed','missing_event','duplicate_event','wrong_historical_status','provider'])
def test_terminal_mismatch_never_proves_release(problem):
    c = SettledChain()
    transfer, event = c.settled_receipt['logs']
    if problem == 'failed_result': c.current[18:] = c.latest[18:] = [2,False]
    elif problem == 'pending': c.current[18:] = c.latest[18:] = [1,False]
    elif problem == 'late_change': c.latest[12] += 1
    elif problem == 'missing_transfer': c.settled_receipt['logs'].remove(transfer)
    elif problem == 'wrong_transfer_amount': transfer['data'] = encode(['uint256'], [c.evidence['amount']-1])
    elif problem == 'wrong_token': transfer['address'] = '0x'+'ff'*20
    elif problem == 'wrong_recipient': transfer['topics'][2] = '0x'+'00'*12+'ff'*20
    elif problem == 'duplicate_transfer': c.settled_receipt['logs'].append(deepcopy(transfer))
    elif problem == 'removed_transfer': transfer['removed'] = True
    elif problem == 'transfer_after_event': transfer['logIndex'] = 3
    elif problem == 'wrong_event_amount': event['data'] = encode(SETTLED_TYPES, [c.evidence['settlementToken'],1,False,False])
    elif problem == 'wrong_global': event['topics'][1] = h(99)
    elif problem == 'wrong_event_emitter': event['address'] = '0x'+'ff'*20
    elif problem == 'reverted': c.settled_receipt['status'] = 0
    elif problem == 'tx': c.settled_receipt['transactionHash'] = h(99)
    elif problem == 'block_hash': c.settlement_block['hash'] = h(99)
    elif problem == 'unconfirmed': c.tip['number'] = c.settlement['blockNumber']+1
    elif problem == 'missing_event': c.settled_receipt['logs'].remove(event)
    elif problem == 'duplicate_event': c.settled_receipt['logs'].append(deepcopy(event))
    elif problem == 'wrong_historical_status':
        original = c.get_deposit
        def changed(identifier):
            call = original(identifier).call
            def read(**kw):
                value = call(**kw)
                if kw.get('block_identifier') == c.settlement['blockNumber']: value[18] = 2
                return value
            from types import SimpleNamespace
            return SimpleNamespace(call=read)
        c.get_deposit = changed
    elif problem == 'provider': c.fail = 'settlement'
    with pytest.raises(EscrowDepositError):
        c.terminal()
