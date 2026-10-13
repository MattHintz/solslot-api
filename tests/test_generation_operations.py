"""Durable operation state, paired with the actual native fee submitter."""
from dataclasses import replace
from pathlib import Path
import time

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin, G2Element, SpendBundle

from solslot_puzzles.generation_transactions import NativeOperation
from solslot_api.chia_provider import ChiaProviderError
from solslot_api.faucet import Faucet
from solslot_api.generation_operations import GenerationOperationJournal, submit_saved_operation, reconcile_saved_operation
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError
from tests.test_protocol_submission import FakeProvider, b32, submitter
from tests.test_approval_repair import admission_quote

GENERATION = '0x' + b32(71).hex()


def operation():
    # Storage/admission fixture; native governance semantics have separate
    # full-consensus builder tests. No signatures, credentials or live inputs.
    inner = Program.to(1)
    coin = Coin(b32(80), inner.get_tree_hash(), 10)
    spend = make_spend(coin, inner, Program.to([[51, b32(81), 10], [1, b32(71)]]))
    return NativeOperation(b32(71), 'FINALIZE_VOTE', (spend,), ())


class Node(FakeProvider):
    def __init__(self, faucet):
        super().__init__(fee_coin=Coin(b32(88), faucet.address_puzzle_hash, 100))
        self.pushes = 0; self.observation = None; self.lose_response = False; self.selection_count = 0
        self.network = 'testnet11'; self.before_push = None

    async def get_network_info_primary(self): return {'network_name': self.network}
    async def get_fee_estimate(self, **kwargs): return admission_quote()
    async def get_coin_records_by_puzzle_hash(self, *args, **kwargs):
        self.selection_count += 1
        return await super().get_coin_records_by_puzzle_hash(*args, **kwargs)
    async def observe_exact_protocol_bundle(self, value):
        assert self.submitted == value
        return self.observation
    async def push_tx_confirmed_in_primary_mempool(self, value, **kwargs):
        if self.before_push: self.before_push(value)
        self.pushes += 1
        result = await super().push_tx_confirmed_in_primary_mempool(value, **kwargs)
        if self.lose_response: raise ChiaProviderError('simulated lost response after acceptance')
        return {**result, 'status': 'MEMPOOL'}


def service(tmp_path, node, faucet):
    funding = ProtocolFundingStore(generation_path(str(tmp_path / 'fees.sqlite3'), GENERATION))
    return ProtocolBundleSubmitter(provider=node, faucet=faucet,
        policy=submitter(node, faucet, native_admission_enabled=True).policy, funding_store=funding)


def test_clean_prepare_is_idempotent_generation_bound_and_status_is_read_only(tmp_path):
    journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), GENERATION)
    op = operation(); identity = journal.prepare(op, 'finalize:one', 100, 1000)
    assert journal.prepare(op, 'finalize:one', 100, 9000) == identity
    assert journal.prepare(op, 'second-click', 100, 9001) == identity
    before = Path(journal.path).read_bytes()
    for _ in range(30):
        result = journal.status(identity)
        assert result['stage'] == 'PREPARED' and result['createdAt'] == result['updatedAt'] == 1000
        assert result['transactionId'] is None
    assert Path(journal.path).read_bytes() == before
    assert 'coin_spends' not in str(result) and 'signature' not in str(result)
    for bad in (replace(op, generation=b32(72)), replace(op, kind='ARBITRARY_TRANSACTION')):
        with pytest.raises(ValueError): journal.prepare(bad, 'finalize:one', 100, 1001)
    with pytest.raises(ValueError): journal.prepare(op, 'finalize:one', 101, 1001)
    other = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), '0x'+b32(72).hex())
    with pytest.raises(ValueError): other.status(identity)


@pytest.mark.parametrize('kind',['MINT_COLLECTION','ALLOCATE_SGT_GRANT','DELIVER_SGT_GRANT','GENESIS_CORE'])
def test_unintegrated_native_builders_cannot_be_saved_for_public_submission(tmp_path,kind):
    journal=GenerationOperationJournal(str(tmp_path/'ops.sqlite3'),GENERATION)
    with pytest.raises(ValueError):journal.prepare(replace(operation(),kind=kind),'future-action',100,1000)
    assert not journal.reserved_input_coin_ids()
    assert journal.request_status('future-action') is None
    with journal._db() as db:
        assert db.execute('SELECT count(*) FROM generation_operations').fetchone()[0]==0


@pytest.mark.asyncio
async def test_lost_response_restart_duplicate_clicks_reconcile_original_bytes(tmp_path):
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11'); node = Node(faucet)
    journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), GENERATION)
    identity = journal.prepare(operation(), 'finalize:one', 100, 1000)
    sender = service(tmp_path, node, faucet)
    def before(value):
        assert journal.status(identity)['stage'] == 'DISPATCHING'
        assert journal.saved_funding(identity)['spendBundle'] == value
    node.before_push = before; node.lose_response = True
    with pytest.raises(ProtocolSubmissionError):
        await submit_saved_operation(journal, identity, sender, clock=lambda: 1001)
    saved = journal.saved_funding(identity)
    assert journal.status(identity)['stage'] == 'RECONCILING'
    assert node.pushes == 1 and sender.funding_store.reserved_coin_ids()
    selection_count = node.selection_count
    sender.funding_store.close()
    journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), GENERATION)
    sender = service(tmp_path, node, faucet)
    node.observation = {'status':'CONFIRMED','provider':'local-full-node','observed_at':'test',
                        'ambiguous_push':True,'confirmed_height':501}
    status = await submit_saved_operation(journal, identity, sender, clock=lambda:1002)
    assert status['stage'] == 'CONFIRMED' and status['confirmedHeight'] == 501
    for _ in range(3): assert await submit_saved_operation(journal, identity, sender, clock=lambda:1003) == status
    assert node.pushes == 1 and node.selection_count == selection_count
    assert journal.saved_funding(identity) == saved
    journal.observed(identity, transaction_id=saved['spendBundleId'], status='MEMPOOL', now=1001)
    assert journal.status(identity) == status
    sender.funding_store.close()


@pytest.mark.asyncio
async def test_read_reconciliation_cannot_resubmit_and_missing_fee_journal_cannot_rebuild(tmp_path):
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11'); node = Node(faucet)
    journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), GENERATION)
    identity = journal.prepare(operation(), 'finalize:one', 100, 1000)
    sender = service(tmp_path, node, faucet)
    await submit_saved_operation(journal, identity, sender, clock=lambda:1001)
    assert journal.status(identity)['stage'] == 'SUBMITTED'
    for network in ('testnet11', 'mainnet'):
        node.network = network
        result = await reconcile_saved_operation(journal, identity, node, clock=lambda:1002)
        assert result['stage'] == 'RECONCILING' and result['transactionId']
    assert node.pushes == 1
    sender.funding_store.close()
    # Simulate only the operation DB being restored; absence of the original
    # fee reservation is a recovery issue, never permission to fund a new tx.
    sender.funding_store = ProtocolFundingStore(generation_path(str(tmp_path/'other-fees.sqlite3'), GENERATION))
    with pytest.raises(ValueError, match='original funding journal'):
        await submit_saved_operation(journal, identity, sender, clock=lambda:1003)
    assert node.pushes == 1
    sender.funding_store.close()


@pytest.mark.asyncio
async def test_cap_or_unbound_funding_refuses_before_any_selection(tmp_path):
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11'); node = Node(faucet)
    journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), GENERATION)
    identity = journal.prepare(operation(), 'finalize:one', 10, 1000)
    sender = service(tmp_path, node, faucet)
    with pytest.raises(ValueError): await submit_saved_operation(journal, identity, sender, clock=time.time)
    sender.policy = replace(sender.policy, maximum_mojos=10)
    sender.funding_store.close()
    sender.funding_store = ProtocolFundingStore(str(tmp_path/'legacy-fees.sqlite3'))
    with pytest.raises(ValueError): await submit_saved_operation(journal, identity, sender, clock=time.time)
    assert node.selection_count == node.pushes == 0
    sender.funding_store.close()
