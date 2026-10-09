"""Primary-clock timelocks are checked before any funding reservation or push."""
from types import SimpleNamespace
import time

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode
from chia_rs import Coin, G2Element, SpendBundle
from fastapi import HTTPException

from solslot_api import governance_endpoints as endpoints
from solslot_api.faucet import Faucet
from solslot_api.protocol_admission import admission_conditions, require_absolute_admission
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolSubmissionError
from tests.test_protocol_submission import FakeProvider, b32, submitter
from tests.test_approval_repair import admission_quote


def timelocked_bundle(*conditions):
    puzzle = Program.to(1)
    solution = Program.to([[51, b32(3), 10], *conditions])
    return SpendBundle([make_spend(Coin(b32(1), puzzle.get_tree_hash(), 10), puzzle, solution)], G2Element())


@pytest.mark.parametrize('opcode,limit,accepted', [
    (ConditionOpcode.ASSERT_SECONDS_ABSOLUTE, 100, True),
    (ConditionOpcode.ASSERT_SECONDS_ABSOLUTE, 101, False),
    (ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE, 101, True),
    (ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE, 100, False),
    (ConditionOpcode.ASSERT_HEIGHT_ABSOLUTE, 4_800_000, True),
    (ConditionOpcode.ASSERT_HEIGHT_ABSOLUTE, 4_800_001, False),
    (ConditionOpcode.ASSERT_BEFORE_HEIGHT_ABSOLUTE, 4_800_001, True),
    (ConditionOpcode.ASSERT_BEFORE_HEIGHT_ABSOLUTE, 4_800_000, False),
])
def test_absolute_consensus_boundaries(opcode, limit, accepted):
    conditions = admission_conditions(timelocked_bundle([opcode, limit]), 4_800_000, 'testnet11')
    if accepted:
        require_absolute_admission(conditions, height=4_800_000, peak_time=100)
    else:
        with pytest.raises(ProtocolSubmissionError):
            require_absolute_admission(conditions, height=4_800_000, peak_time=100)


@pytest.mark.asyncio
async def test_future_start_never_selects_or_reserves_funding(tmp_path):
    now = int(time.time())
    faucet = Faucet.from_seed_hex('01'*32, 'testnet11')
    class Node(FakeProvider):
        async def get_fee_estimate(self, **kwargs):
            assert kwargs['require_primary'] is True
            return admission_quote(peak_time=now-90)
        async def get_coin_records_by_puzzle_hash(self, *args, **kwargs):
            raise AssertionError('A future timelock must be caught before selecting a fee coin')
    provider = Node(fee_coin=Coin(b32(8), faucet.address_puzzle_hash, 1_000_000_000))
    service = submitter(provider, faucet, native_admission_enabled=True)
    service.funding_store = ProtocolFundingStore(tmp_path/'funding.db')
    with pytest.raises(ProtocolSubmissionError, match='start time'):
        await service.submit(timelocked_bundle([ConditionOpcode.ASSERT_SECONDS_ABSOLUTE, now]).to_json_dict())
    assert not service.funding_store.reserved_coin_ids()
    assert provider.submitted is None


@pytest.mark.asyncio
async def test_stale_primary_clock_cannot_rebuild_or_submit(monkeypatch):
    class Node:
        async def get_fee_estimate(self, **kwargs):
            assert kwargs == {'target_times':[60], 'cost':1, 'require_primary':True}
            return admission_quote(peak_time=1)
    queue = SimpleNamespace(get=lambda _: SimpleNamespace(publication_approval_expires_at=int(time.time())+3600),
        publication_dispatch=lambda _:None)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=Node())))
    settings = SimpleNamespace(protocol_medium_fee_target_seconds=60)
    monkeypatch.setattr(endpoints, 'require_sgt_allocation_drafts', lambda _:None)
    def reject(*args, **kwargs):
        raise AssertionError('Invalid primary clock must precede building or submitting')
    monkeypatch.setattr(endpoints, '_publication_build', reject)
    with pytest.raises(HTTPException) as error:
        await endpoints.submit_publication('test', SimpleNamespace(coadmin_slot=1), request,
            settings, None, queue, SimpleNamespace(authority_slot=0))
    assert error.value.status_code == 503
    assert 'stale' in error.value.detail


@pytest.mark.asyncio
async def test_saved_dispatch_is_reported_without_expensive_clock_or_build(monkeypatch):
    monkeypatch.setattr(endpoints, 'require_sgt_allocation_drafts', lambda _:None)
    queue = SimpleNamespace(publication_dispatch=lambda _: {'bundle_id':'saved'})
    with pytest.raises(HTTPException) as error:
        await endpoints.submit_publication('test', SimpleNamespace(coadmin_slot=1), None,
            None, None, queue, SimpleNamespace(authority_slot=0))
    assert error.value.status_code == 409
    assert 'Check saved submission' in error.value.detail
