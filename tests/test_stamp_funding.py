import asyncio
import json
from dataclasses import replace
import pytest
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from chia.types.condition_opcodes import ConditionOpcode
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.program import INFINITE_COST
from solslot_api import zkpassport_enrollments as enroll
from solslot_api.stamp_funding import continue_stamp, stamp_timestamp, StampFundingStore, submit_funded_stamp
from solslot_api.credential_ledger import get_credential_ledger
from solslot_api.faucet import Faucet
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy, ProtocolSubmissionError
from tests import test_zkpassport_enrollments as journeys
from tests.test_protocol_submission import FakeProvider

@pytest.mark.parametrize('journey',[journeys.test_evm_proof_builds_and_confirms_atomic_chia_vault_stamp,
    journeys.test_bls_proof_requires_wallet_signature_for_atomic_chia_vault_stamp],ids=['evm','bls'])
def test_real_signed_stamp_fee_funding_and_immutable_recovery(monkeypatch,tmp_path,journey):
    original_push=enroll._push_chia_stamp_and_mark_pending
    observed=[]
    async def intercept(settings,**kwargs):
        original=kwargs['spend_bundle']; expected=kwargs['expected_vault_coin']
        ledger=get_credential_ledger(settings); before=ledger.get_stamp_attempt(kwargs['key'])
        vault_id=json.loads(before['claim_json'])['current_vault_coin_id']
        old=stamp_timestamp(original,vault_id)
        continued=continue_stamp(original,vault_id,old+600)
        assert continued.aggregated_signature==original.aggregated_signature
        assert continued.additions()==original.additions()
        assert continued.removals()==original.removals()
        assert stamp_timestamp(continued,vault_id)==old+600
        with pytest.raises(ValueError):continue_stamp(original,vault_id,old-1)
        assert bytes(original).hex()!=bytes(continued).hex()
        faucet=Faucet.from_seed_hex('21'*32,'testnet11')
        fee_coin=Coin(bytes32(b'F'*32),faucet.address_puzzle_hash,uint64(50_000_000))
        provider=FakeProvider(fee_coin=fee_coin,base_fee=10_000_000,aggregate_fee=12_000_000)
        submitter=ProtocolBundleSubmitter(provider=provider,faucet=faucet,policy=ProtocolFeePolicy(
            enabled=True,minimum_mojos=1_000_001,maximum_mojos=20_000_000,maximum_funding_coin_mojos=50_000_000,
            estimate_buffer_bps=12500,target_seconds=60))
        prepared=await submitter._prepare_locked(continued.to_json_dict(),expected_protocol_fee_mojos=1,
            bind_protocol=True,sponsor_deadline=old+720)
        assert prepared.fee_mojos==15_000_000
        assert prepared.bundle.coin_spends[:2]==continued.coin_spends
        assert sum(int(c.amount) for c in prepared.bundle.removals())-sum(int(c.amount) for c in prepared.bundle.additions())==15_000_000
        fee_spend=prepared.bundle.coin_spends[-1]
        conditions=conditions_dict_for_solution(fee_spend.puzzle_reveal,fee_spend.solution,INFINITE_COST)
        assert len(conditions[ConditionOpcode.ASSERT_CONCURRENT_SPEND])==2
        assert ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE in conditions
        from solslot_api.sols_swaps import _verify_aggregate_signature
        from chia.wallet.wallet_spend_bundle import WalletSpendBundle
        _verify_aggregate_signature(WalletSpendBundle.from_json_dict(prepared.bundle.to_json_dict()),'testnet11')
        store=StampFundingStore(tmp_path/'stamp-funding.sqlite3')
        document={**prepared.to_json(),'timestamp':old+600,'expiresAt':old+720}
        store.reserve(kwargs['key'],'0x'+original.name().hex(),document,None)
        store.event(prepared.spend_bundle_id,'uncertain','TRANSPORT_OR_TIMEOUT')
        store.db.close();store=StampFundingStore(tmp_path/'stamp-funding.sqlite3')
        assert json.loads(store.latest(kwargs['key'])['document'])==document
        assert prepared.fee_coin_id in store.reserved_coin_ids()
        with pytest.raises(ValueError):store.reserve(kwargs['key'],'0x'+original.name().hex(),document,None)
        assert ledger.get_stamp_attempt(kwargs['key'])==before
        store.db.close()
        result = await original_push(settings,**kwargs)
        frozen = ledger.get_stamp_attempt(kwargs['key'])
        from solslot_api import stamp_funding
        class Snapshot:
            def __init__(self,*args):self.transaction_time=old+1000
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
        monkeypatch.setattr(stamp_funding,'PrimaryReadSnapshot',Snapshot)
        class FundedProvider(FakeProvider):
            primary=None
            async def _primary_available(self):return True
            async def get_coin_record_by_name_primary(self,coin_id):
                for c in [*original.removals(),fee_coin]:
                    if '0x'+c.name().hex()==coin_id:
                        return {'coin':c.to_json_dict(),'confirmed_block_index':10,'spent_block_index':0}
                return None
            async def get_mempool_items_by_coin_name(self,coin_id):
                if self.submitted:return [{'spend_bundle_name':self.required_spend_bundle_id}]
                return []
        live=FundedProvider(fee_coin=fee_coin,aggregate_fee=12_000_000);live.primary=live
        submitter.provider=live
        store=StampFundingStore(tmp_path/'actual-funding.sqlite3')
        doc=await submit_funded_stamp(submitter=submitter,store=store,ledger=ledger,key=kwargs['key'],
            original=original,expected_coin=expected)
        assert len(live.submitted['coin_spends'])==3
        assert store.latest(kwargs['key'])['status']=='mempool'
        assert ledger.get_stamp_attempt(kwargs['key'])==frozen
        again=await submit_funded_stamp(submitter=submitter,store=store,ledger=ledger,key=kwargs['key'],
            original=original,expected_coin=expected)
        assert again==doc
        assert store.db.execute('select count(*) from stamp_submissions').fetchone()[0]==1
        store.db.close();observed.append(True)
        return result
    monkeypatch.setattr(enroll,'_push_chia_stamp_and_mark_pending',intercept)
    journey(monkeypatch,tmp_path)
    assert observed==[True]


def test_predictive_buffer_respects_cap_and_never_submits():
    faucet=Faucet.from_seed_hex('21'*32,'testnet11')
    coin=Coin(bytes32(b'F'*32),faucet.address_puzzle_hash,uint64(50_000_000))
    provider=FakeProvider(fee_coin=coin,base_fee=12_000_000)
    submitter=ProtocolBundleSubmitter(provider=provider,faucet=faucet,
        policy=ProtocolFeePolicy(enabled=True,maximum_mojos=13_000_000,estimate_buffer_bps=12500))
    from tests.test_protocol_submission import protocol_bundle
    with pytest.raises(ProtocolSubmissionError,match='exceeds configured cap'):
        asyncio.run(submitter.submit(protocol_bundle().to_json_dict()))
    assert provider.submitted is None
