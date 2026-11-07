import time
from copy import deepcopy

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle

from solslot_api.protocol_admission import admission_conditions, require_relative_admission
from solslot_api.protocol_submission import ProtocolSubmissionError
from solslot_api.faucet import Faucet
from tests.test_protocol_submission import FakeProvider, b32, submitter
from tests.test_approval_repair import admission_quote


def timed_bundle(conditions):
    puzzle = Program.to(1)
    coin = Coin(b32(31), puzzle.get_tree_hash(), 1)
    return SpendBundle([make_spend(coin, puzzle, Program.to([[51,b32(32),1], *conditions]))], G2Element())


class Node:
    def __init__(self, bundle, birth, height=100):
        self.record = {'coin':bundle.coin_spends[0].coin.to_json_dict(), 'timestamp':birth,
                       'confirmed_block_index':height,'spent_block_index':0,'spent':False}
        self.reads = 0; self.reorg = False
    async def get_network_info_primary(self): return {'network_name':'testnet11'}
    async def get_coin_record_by_name_primary(self, identity):
        self.reads += 1
        record = deepcopy(self.record)
        if self.reorg and self.reads == 2: record['timestamp'] += 1
        return record


@pytest.mark.asyncio
async def test_confirmed_birth_enforces_real_24h_and_rechecks_input():
    now = int(time.time()); bundle = timed_bundle([[80,86400]])
    conditions = admission_conditions(bundle,4_800_000,'testnet11')
    node = Node(bundle,now-86400+1)
    with pytest.raises(ProtocolSubmissionError) as failed:
        await require_relative_admission(conditions,bundle,provider=node,height=4_800_000,peak_time=now)
    assert failed.value.code == 'CHAIN_WAIT_REQUIRED'
    node.record['timestamp'] -= 1; node.reads=0
    await require_relative_admission(conditions,bundle,provider=node,height=4_800_000,peak_time=now)
    assert node.reads == 2
    node.reads=0; node.reorg=True
    with pytest.raises(ProtocolSubmissionError) as failed:
        await require_relative_admission(conditions,bundle,provider=node,height=4_800_000,peak_time=now)
    assert failed.value.code == 'INPUT_STATE_CHANGED'


@pytest.mark.asyncio
@pytest.mark.parametrize('conditions,birth,height,code', [
    ([[82,10]],1000,101,'CHAIN_WAIT_REQUIRED'),
    ([[84,100]],1000,100,'CHAIN_WINDOW_EXPIRED'),
    ([[86,10]],1000,100,'CHAIN_WINDOW_EXPIRED'),
    ([[75,999]],1000,100,'INPUT_STATE_CHANGED'),
    ([[74,99]],1000,100,'INPUT_STATE_CHANGED'),
])
async def test_height_expiry_and_birth_assertions(conditions,birth,height,code):
    bundle = timed_bundle(conditions); node=Node(bundle,birth,height)
    native = admission_conditions(bundle,4_800_000,'testnet11')
    with pytest.raises(ProtocolSubmissionError) as failed:
        await require_relative_admission(native,bundle,provider=node,height=110,peak_time=1100)
    assert failed.value.code == code


@pytest.mark.asyncio
async def test_early_activation_does_not_select_fee_input():
    faucet = Faucet.from_seed_hex('01'*32,'testnet11'); now=int(time.time())
    bundle=timed_bundle([[80,86400]])
    evidence=Node(bundle,now-100)
    class Primary(FakeProvider):
        async def get_fee_estimate(self, **kwargs): return admission_quote()
        async def get_network_info_primary(self): return await evidence.get_network_info_primary()
        async def get_coin_record_by_name_primary(self,identity): return await evidence.get_coin_record_by_name_primary(identity)
        async def get_coin_records_by_puzzle_hash(self,*args,**kwargs):
            raise AssertionError('Waiting must be checked before fee reservation')
    node=Primary(fee_coin=Coin(b32(8),faucet.address_puzzle_hash,100))
    service=submitter(node,faucet,native_admission_enabled=True)
    with pytest.raises(ProtocolSubmissionError) as failed:
        await service.submit(bundle.to_json_dict())
    assert failed.value.code=='CHAIN_WAIT_REQUIRED' and node.submitted is None
