"""Approval timing, cheap status reads and conservative admission/recovery."""
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode
from chia_rs import Coin, G2Element, SpendBundle

from solslot_api import governance_endpoints as endpoints
from solslot_api.protocol_submission import ProtocolSubmissionError, ProtocolBundleSubmitter
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_admission import admission_conditions, primary_admission_state
from tests.test_sgt_recipient_readiness import ready_expired
from tests.test_protocol_submission import FakeProvider, b32, submitter
from solslot_api.faucet import Faucet
from solslot_api.governance_queue import GovernanceQueueStore, GovernanceQueueConflict


def native_bundle(expiry=None, output=3):
    conditions = [[51, b32(output), 10]]
    if expiry is not None:
        conditions.append([ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE, expiry])
    puzzle = Program.to(1)
    return SpendBundle([make_spend(Coin(b32(1), puzzle.get_tree_hash(), 10), puzzle, Program.to(conditions))], G2Element())


def admission_quote(*, used=0, capacity=110_000_000_000, estimate=1, peak_time=None):
    now = int(time.time())
    return dict(target_times=[300], estimates=[estimate], full_node_synced=True, peak_height=4_800_000,
        mempool_size=used, mempool_max_size=capacity, last_peak_timestamp=peak_time or now, node_time_utc=now)


@pytest.mark.asyncio
async def test_busy_native_cost_prevents_funding_and_push_before_cap(tmp_path):
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11')
    class Node(FakeProvider):
        async def get_fee_estimate(self, **kwargs):
            assert kwargs['require_primary'] is True
            return admission_quote(used=110_000_000_000)
        async def get_coin_records_by_puzzle_hash(self, *args, **kwargs):
            raise AssertionError('An over-cap admission quote must precede funding selection')
    provider = Node(fee_coin=Coin(b32(8), faucet.address_puzzle_hash, 1_000_000_000))
    service = submitter(provider, faucet, native_admission_enabled=True, maximum_mojos=1000)
    service.funding_store = ProtocolFundingStore(tmp_path / 'funding.db')
    with pytest.raises(ProtocolSubmissionError, match='Network busy'):
        await service.submit(native_bundle().to_json_dict())
    assert provider.submitted is None
    assert not service.funding_store.reserved_coin_ids()


@pytest.mark.asyncio
async def test_admission_uses_complete_aggregate_cost_and_strict_floor():
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11')
    class Node(FakeProvider):
        async def get_fee_estimate(self, **kwargs):
            return admission_quote(used=110_000_000_000)
    provider = Node(fee_coin=Coin(b32(8), faucet.address_puzzle_hash, 1_000_000_000))
    service = submitter(provider, faucet, native_admission_enabled=True, maximum_mojos=1_000_000_000)
    first = native_bundle()
    puzzle = Program.to((1, [[51, b32(9), 20]]))
    second = SpendBundle([make_spend(Coin(b32(2), puzzle.get_tree_hash(),20), puzzle, Program.to(0))], G2Element())
    aggregate = SpendBundle.aggregate([first,second])
    cost = int(admission_conditions(aggregate, 4_800_000,'testnet11').cost)
    assert await service._estimate_fee(aggregate) == cost * 5 + 1
    assert await service._estimate_fee(first) < cost * 5 + 1


@pytest.mark.parametrize('mutation', [{'full_node_synced':False}, {'last_peak_timestamp':1}, {'node_time_utc':1}, {'mempool_size':True}, {'mempool_max_size':0}])
def test_invalid_or_stale_primary_admission_fails_closed(mutation):
    with pytest.raises(ProtocolSubmissionError):
        primary_admission_state({**admission_quote(),**mutation})


@pytest.mark.asyncio
@pytest.mark.parametrize('clear,expiry_offset', [(True,-10),(False,-10),(True,100)])
async def test_release_requires_native_chain_expiry_and_all_clear_inputs(tmp_path,clear,expiry_offset):
    faucet = Faucet.from_seed_hex('01'*32,'testnet11')
    class Node(FakeProvider):
        async def get_fee_estimate(self, **kwargs):
            return admission_quote()
        async def _primary_inputs_clear(self, bundle):
            return clear
    provider = Node(fee_coin=Coin(b32(8),faucet.address_puzzle_hash,100))
    store = ProtocolFundingStore(tmp_path / 'funding.db')
    bundle = native_bundle(int(time.time())+expiry_offset)
    original_id = '0x'+bundle.name().hex()
    document = {'spendBundle':bundle.to_json_dict(),'spendBundleId':original_id,
        'feeMojos':'0','feeCoinId':'0x'+bundle.removals()[0].name().hex(),'backingMojos':'0','protocolSpendBundle':bundle.to_json_dict()}
    context={'feeTill':faucet.address_hex,'purpose':None,'backingMojos':0}
    store.reserve('testnet11',original_id,context,document)
    service = ProtocolBundleSubmitter(provider=provider,faucet=faucet,policy=submitter(provider,faucet).policy,funding_store=store)
    if clear and expiry_offset<0:
        proof = await service.release_expired_saved(original_id)
        assert proof['absoluteExpiry']<proof['peakTimestamp']
        assert store.is_released('testnet11',original_id)
        assert not store.reserved_coin_ids()
        assert store.lookup('testnet11',original_id,context)==document
        # The old bundle remains immutable. A different, expired-safe action
        # can reserve the same input without deleting its predecessor.
        replacement=native_bundle(int(time.time())+100, output=4)
        next_id='0x'+replacement.name().hex()
        next_doc={**document,'spendBundle':replacement.to_json_dict(),'spendBundleId':next_id,'protocolSpendBundle':replacement.to_json_dict()}
        store.reserve('testnet11',next_id,context,next_doc)
        assert len(store.reserved_coin_ids())==1
        assert store.db.execute('SELECT COUNT(*) FROM funded_protocol_bundles').fetchone()[0]==2
    else:
        with pytest.raises(ProtocolSubmissionError):
            await service.release_expired_saved(original_id)
        assert store.reserved_coin_ids()
        assert not store.is_released('testnet11',original_id)
    assert provider.submitted is None


@pytest.mark.asyncio
async def test_signature_status_is_bounded_read_without_native_builder_or_renewal(tmp_path,monkeypatch):
    store=GovernanceQueueStore(str(tmp_path/'queue.db'))
    record=ready_expired(store)
    record=store.prepare_publication_approvals(proposal_id=record.id,expected_revision=record.revision,
        coadmin_slot=1,expires_at=86601,actor='owner',now=201,renew_expired=True)
    action='0x'+'aa'*32; other='0x'+'bb'*32
    store.add_signature(proposal_id=record.id,action_id=action,signer_slot=0,signer_public_key='key',message_hash='hash',signature='PRIVATE_TEST_SIGNATURE',actor='owner')
    monkeypatch.setattr(endpoints,'require_sgt_allocation_drafts',lambda _:None)
    def reject(*args,**kwargs): raise AssertionError('Status must not rebuild or mutate the package')
    monkeypatch.setattr(endpoints,'_publication_build',reject)
    monkeypatch.setattr(store,'prepare_publication_approvals',reject)
    value=await endpoints.publication_signature_status(record.id,None,store,SimpleNamespace(authority_slot=1),action,other)
    assert value['approvalExpiresAt']==86601 and value['votingDeadline'] is None
    assert value['signedActions']==[{'actionId':action,'signerSlot':0,'messageHash':'hash'}]
    assert 'PRIVATE_TEST_SIGNATURE' not in str(value)
    assert store.get(record.id).revision==record.revision


def test_dispatch_receipt_blocks_restart_until_exact_reconciliation(tmp_path):
    store=GovernanceQueueStore(str(tmp_path/'queue.db'))
    record=ready_expired(store)
    record=store.prepare_publication_approvals(proposal_id=record.id,expected_revision=record.revision,
        coadmin_slot=1,expires_at=86601,actor='owner',now=201,renew_expired=True)
    args=dict(proposal_id=record.id,expected_revision=record.revision,voting_deadline=600,
        original_id='original',bundle_id='funded',proposal_coin_id='coin',actor='owner',now=300)
    store.bind_publication_dispatch(**args)
    assert store.get(record.id).saved_publication
    with pytest.raises(GovernanceQueueConflict,match='saved submission'):
        store.prepare_publication_approvals(proposal_id=record.id,expected_revision=record.revision,
            coadmin_slot=1,expires_at=180000,actor='owner',now=90000,renew_expired=True)
    updated=store.reconcile_publication_dispatch(proposal_id=record.id,original_id='original',outcome='EXPIRED',actor='owner',now=610)
    assert not updated.saved_publication and updated.publication_voting_deadline is None
    assert updated.publication_approval_expires_at==86601
    assert updated.revision==record.revision


@pytest.mark.asyncio
async def test_expiry_reconciliation_retains_inputs_if_peak_changes(tmp_path):
    faucet=Faucet.from_seed_hex('01'*32,'testnet11')
    class Node(FakeProvider):
        quotes=0
        async def get_fee_estimate(self, **kwargs):
            self.quotes+=1
            return {**admission_quote(), 'peak_height':4_800_000+self.quotes}
        async def _primary_inputs_clear(self, bundle): return True
    provider=Node(fee_coin=Coin(b32(8),faucet.address_puzzle_hash,100))
    bundle=native_bundle(int(time.time())-10)
    original_id='0x'+bundle.name().hex()
    store=ProtocolFundingStore(tmp_path/'funding.db')
    store.reserve('testnet11',original_id,{'feeTill':faucet.address_hex,'purpose':None,'backingMojos':0},
        {'spendBundle':bundle.to_json_dict(),'spendBundleId':original_id,'protocolSpendBundle':bundle.to_json_dict()})
    service=ProtocolBundleSubmitter(provider=provider,faucet=faucet,policy=submitter(provider,faucet).policy,funding_store=store)
    with pytest.raises(ProtocolSubmissionError,match='Chain changed'):
        await service.release_expired_saved(original_id)
    assert store.reserved_coin_ids() and not store.is_released('testnet11',original_id)
    assert provider.submitted is None


@pytest.mark.asyncio
async def test_check_submission_closes_receipt_after_active_transition(tmp_path,monkeypatch):
    store=GovernanceQueueStore(str(tmp_path/'queue.db'))
    record=ready_expired(store)
    record=store.prepare_publication_approvals(proposal_id=record.id,expected_revision=record.revision,
        coadmin_slot=1,expires_at=86601,actor='owner',now=201,renew_expired=True)
    store.bind_publication_dispatch(proposal_id=record.id,expected_revision=record.revision,voting_deadline=600,
        original_id='original',bundle_id='0x'+'aa'*32,proposal_coin_id='0x'+'bb'*32,actor='owner',now=300)
    store.transition(proposal_id=record.id,expected_revision=record.revision,target='ACTIVE',actor='owner',
        activation_bundle_id='0x'+'aa'*32,proposal_coin_id='0x'+'bb'*32)
    monkeypatch.setattr(endpoints,'require_sgt_allocation_drafts',lambda _:None)
    # An already recorded exact activation needs no second node observation.
    value=await endpoints.check_publication_submission(record.id,None,None,store,SimpleNamespace(authority_slot=0,wallet='owner'))
    assert value['chainState']=='ACCEPTED' and not store.publication_dispatch(record.id)
