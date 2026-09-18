"""Exact private fee reservations against real signed Stripe refund spends."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32

from solslot_api import voucher_refund_funding as funding
from solslot_api.presale_endpoints import PresaleStore
from solslot_api.faucet import Faucet
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from tests.test_stripe_refund_fee_integration import fixture
from tests.test_redemption_review_execution import Primary
from tests.test_chia_snapshot import provider
from tests.test_sols_swap_execution import consensus


async def setup(monkeypatch):
    data=fixture();vector=data['reviewVector'];intent=vector['intent'];evidence=intent['reviewEvidence']
    binding=deepcopy(evidence['fundingEvidence']['binding']);now=intent['currentTimestamp']
    monkeypatch.setattr(funding,'time',lambda:now)
    bundle=SpendBundle.from_json_dict(data['spendBundle'])
    context=SimpleNamespace(vault_spend=bundle.coin_spends[0],vault_coin=bundle.coin_spends[0].coin,
        provisional=SimpleNamespace(coin_spends=bundle.coin_spends[1:]),refund_action=1,
        terms=SimpleNamespace(refund_deadline=vector['selected']['refundDeadline']))
    faucet=Faucet.from_seed_hex('77'*32,'testnet11')
    fee=Coin(bytes32(bytes([80])*32),faucet.address_puzzle_hash,10000)
    node=Primary();node.clock=now
    for coin in [*bundle.removals(),fee]:
        node.records[funding.hx(coin.name())]=dict(coin=coin.to_json_dict(),confirmed_block_index=10,spent_block_index=0,spent=False)
    submitter=ProtocolBundleSubmitter(provider=provider(node),faucet=faucet,
        policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,maximum_mojos=10000))
    async def select(*args,**kwargs):return fee
    monkeypatch.setattr(submitter,'_select_fee_coin',select)
    async def validate(job,*,bundle,network):
        assert job=='swap_signature' and network=='testnet11'
        consensus(SpendBundle.from_bytes(bytes(bundle)))
    monkeypatch.setattr('solslot_api.wallet_offer_worker.run_offer_job',validate)
    store=PresaleStore(':memory:')
    review=await funding.reserve_refund_funding(submitter,store,context,evidence,binding,lambda:binding)
    return SimpleNamespace(data=data,vector=vector,context=context,evidence=evidence,binding=binding,node=node,
        submitter=submitter,store=store,review=review,bundle=bundle,fee=fee,now=now)


@pytest.mark.asyncio
async def test_exact_reserved_fee_is_private_and_full_consensus_valid(monkeypatch):
    t=await setup(monkeypatch)
    try:
        payload=funding.store_for(t.store,t.submitter).get(t.review['reservationHash'])
        assert payload['fundingBundle']['aggregated_signature'] not in funding.canonical(t.review)
        assert funding.hx(t.fee.name()) in funding.store_for(t.store,t.submitter).reserved_coin_ids()
        assert funding.hx(t.fee.name()) in {funding.hx(v) for v in t.submitter.reserved_funding_coin_ids()}
        async with t.submitter.funding_guard:
            prepared=await funding.prepare_reserved_refund(t.submitter,t.store,t.context,t.evidence,t.binding,
                t.review['reservationHash'],t.bundle,lambda:t.binding)
        consensus(prepared.bundle)
        assert prepared.fee_mojos==100
        assert prepared.bundle.coin_spends[-1]==SpendBundle.from_json_dict(payload['fundingBundle']).coin_spends[0]
        assert t.review['reservationHash']==funding.digest(payload['review'])
    finally:t.store._conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('change',['reservation','session','policy','spent','pending','fee_estimate','expired','private_bytes'])
async def test_changed_fee_or_authority_cannot_reach_exact_dispatch(monkeypatch,change):
    t=await setup(monkeypatch)
    try:
        reservation=t.review['reservationHash']
        if change=='reservation':reservation='0x'+'ef'*32
        if change=='session':t.binding['sessionFingerprint']='0x'+'ef'*32
        if change=='policy':t.submitter.policy=ProtocolFeePolicy(enabled=True,minimum_mojos=2,maximum_mojos=10000)
        if change=='spent':t.node.records[funding.hx(t.fee.name())]['spent_block_index']=100
        if change=='pending':t.node.pending=[{'spend':'other'}]
        if change=='fee_estimate':
            async def estimate(**kwargs):return dict(estimates=[101],target_times=kwargs['target_times'])
            t.node.get_fee_estimate=estimate
        if change=='expired':monkeypatch.setattr(funding,'time',lambda:t.now+91)
        if change=='private_bytes':
            t.store._conn.execute("UPDATE voucher_owner_refund_fee_reviews SET payload_json='{}'")
        with pytest.raises((ValueError,RuntimeError)):
            async with t.submitter.funding_guard:
                await funding.prepare_reserved_refund(t.submitter,t.store,t.context,t.evidence,t.binding,reservation,t.bundle,lambda:t.binding)
    finally:t.store._conn.close()
