"""Confirmed native funding -> exact review -> durable API preparation/retry."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia_rs import Coin,SpendBundle,G2Element
from chia_rs.sized_ints import uint64
from solslot_puzzles.funded_redemption_v1 import FundedRedemptionPlanV1,FundedRedemptionAllocation
from solslot_puzzles.generation_redemptions import TreasuryInput,treasury_inner,redemption_bill
from solslot_api.generation_chain_evidence import resolve_generation_chain,public_bill
from solslot_api.generation_execution import MaintenanceRequest,RedemptionIntent,prepare_maintenance
from solslot_api.generation_consents import ConsentRequest
from solslot_api.generation_consents import GenerationConsentStore,prepare_consent,sign_consent
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_api.generation_redemption_evidence import verified_redemption_source
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared
from tests.test_generation_execution import body,open_native,h
from tests.test_generation_genesis_core import core
from tests.test_generation_consents import initialized,request


async def funded_source(chain):
    sim,client,provider,anchor,_=chain
    acs=Program.to(1);await sim.farm_block(acs.get_tree_hash())
    origin=(await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[-1].coin
    tail=GENESIS_BY_ID_MOD.curry(origin.name())
    z=lambda n:bytes([n])*32
    plan=FundedRedemptionPlanV1(z(80),z(81),tail.get_tree_hash(),100001,(
        FundedRedemptionAllocation(z(21),z(31),500000,50001),
        FundedRedemptionAllocation(z(200),z(32),500000,50000)))
    launcher=z(91);inner=treasury_inner(anchor.governance,plan.payment_asset_id,launcher)
    eve=Coin(origin.name(),construct_cat_puzzle(CAT_MOD,plan.payment_asset_id,acs).get_tree_hash(),uint64(plan.total_payment_amount))
    funding=make_spend(origin,acs,Program.to([[51,eve.puzzle_hash,int(eve.amount)],
        [51,acs.get_tree_hash(),int(origin.amount)-int(eve.amount)]]))
    issued=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,plan.payment_asset_id,acs,
        Program.to([[51,inner.get_tree_hash(),int(eve.amount)],[51,[],-113,tail,[]]]),limitations_program_reveal=tail)])
    assert await client.push_tx(SpendBundle([funding,*issued.coin_spends],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    coin=Coin(eve.name(),construct_cat_puzzle(CAT_MOD,plan.payment_asset_id,inner).get_tree_hash(),eve.amount)
    source=TreasuryInput(coin,issued.coin_spends[0])
    bill=redemption_bill(anchor.governance,source,plan,launcher)
    return source,bill


@pytest.mark.asyncio
async def test_redemption_funding_has_exact_native_status_and_offline_retry(generation_chain,prepared,tmp_path):
    sim,client,provider,anchor,_=generation_chain
    source,bill=await funded_source(generation_chain)
    proposal,_=await open_native(generation_chain,prepared,lambda _:bill)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE'):
        e=await resolve_generation_chain(anchor,provider=provider)
        saved=await prepare_maintenance(body(anchor,e,kind),anchor=anchor,provider=provider,journal=journal)
        if kind=='FINALIZE_VOTE':sim.pass_time(uint64(3601));await sim.farm_block()
        assert await client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider)
    action=e.public_status(100)['approvedActions'][0]
    intent=action['redemption']
    assert intent==public_bill(bill)['redemption'] and intent['treasuryCoinId']==h(source.coin.name())
    req=body(anchor,e,'FUND_REDEMPTION',proposalId=h(proposal),redemption=intent)
    verified,records=await verified_redemption_source(req.redemption,governance=e.governance.state,provider=provider)
    assert verified==source and len(records)==2
    for fault in ('source','amount','destination','asset','order','proposal'):
        raw=deepcopy(req.document());raw['requestKey']=fault
        if fault=='source':raw['redemption']['treasuryCoinId']='0x'+'ff'*32
        elif fault=='amount':raw['redemption']['totalPaymentAmount']-=1
        elif fault=='destination':raw['redemption']['allocations'][0]['deedCommitment']='0x'+'ff'*32
        elif fault=='asset':raw['redemption']['paymentAssetId']='0x'+'ff'*32
        elif fault=='order':raw['redemption']['allocations'].reverse()
        elif fault=='proposal':raw['proposalId']='0x'+'ff'*32
        with pytest.raises(ValueError):
            await prepare_maintenance(MaintenanceRequest.model_validate(raw),anchor=anchor,provider=provider,journal=journal)
    saved=await prepare_maintenance(req,anchor=anchor,provider=provider,journal=journal)
    assert saved['review']['redemption']==intent
    bundle=journal.protocol_bundle(saved['operationId'])
    assert len(bundle.coin_spends)==3
    # A lost network response cannot cause a new funding build or signature.
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('retry must read the journal')))
    restored=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    assert await prepare_maintenance(req,anchor=anchor,provider=offline,journal=restored)==saved
    assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    updated=await resolve_generation_chain(anchor,provider=provider)
    assert not updated.public_status(101)['approvedActions']
    assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    with pytest.raises(ValueError,match='spent'):
        await verified_redemption_source(req.redemption,governance=updated.governance.state,provider=provider)


@pytest.mark.asyncio
async def test_redemption_typed_consent_rejects_opaque_or_conflicting_intent(generation_chain,prepared):
    _,bill=await funded_source(generation_chain)
    _,_,provider,anchor,_=generation_chain
    e=await resolve_generation_chain(anchor,provider=provider)
    intent=public_bill(bill)['redemption']
    raw=dict(generationId=h(anchor.issuance.generation),requestKey='redemption-publication',
        kind='PUBLICATION_APPROVAL',proposalKind='FUND_REDEMPTION',coadministratorSlot=1,
        feeCapMojos=1000,expectedInputs={name:h(getattr(e,name).current.coin.name())
            for name in ('registry','governance','holdings')},redemption=intent)
    assert ConsentRequest.model_validate(raw).document()['redemption']==intent
    for mutation in ('missing','zero','extra','shares','duplicate','wrong-kind'):
        value=deepcopy(raw)
        if mutation=='missing':value.pop('redemption')
        elif mutation=='zero':value['redemption']['paymentAssetId']='0x'+'00'*32
        elif mutation=='extra':value['redemption']['withdrawalPuzzleHash']='0x'+'ff'*32
        elif mutation=='shares':value['redemption']['allocations'][0]['sharePpm']-=1
        elif mutation=='duplicate':value['redemption']['allocations'][1]['deedLauncherId']=intent['allocations'][0]['deedLauncherId']
        elif mutation=='wrong-kind':value['proposalKind']='UPGRADE'
        with pytest.raises(ValueError):ConsentRequest.model_validate(value)


@pytest.mark.asyncio
async def test_redemption_review_uses_actual_administrator_signatures_and_retains_funding_evidence(core,tmp_path):
    from eth_keys import keys
    from chia_rs.sized_bytes import bytes32
    c=core;built,_=await initialized(c)
    source,bill=await funded_source((c.sim,c.client,c.provider,built.anchor,{}))
    chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    now=int(c.sim.timestamp)-1
    req=request(built.anchor,chain,proposalKind='FUND_REDEMPTION',upgrade=None,
        redemption=public_bill(bill)['redemption'])
    store=GenerationConsentStore(str(tmp_path/'consent.db'),c.prep.generation_id)
    review=await prepare_consent(req,anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    assert review['proposal']==public_bill(bill) and review['expiresAt']==now+86400
    document=store.document(review['packageId'])
    assert source.coin.to_json_dict() in [value['coin'] for value in document['confirmedInputs']]
    import os,json
    from pathlib import Path
    if target:=os.environ.get('GENERATION_REDEMPTION_CONSENT_VECTOR'):
        Path(target).write_text(json.dumps({'review':review,'request':req.document(),'billClvm':'0x'+bytes(bill).hex()},indent=2)+'\n')
    for challenge in review['challenges']:
        signature=keys.PrivateKey(bytes([challenge['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(challenge['digest'])).to_bytes()
        signed=await sign_consent(review['packageId'],challenge['slot'],signature,
            anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now+1)
    assert signed['stage']=='READY'
    execution=MaintenanceRequest.model_validate(dict(generationId=c.prep.generation_id,requestKey='no-fast-track',
        kind='FUND_REDEMPTION',proposalId=review['proposalId'],feeCapMojos=1000,
        expectedInputs=req.document()['expectedInputs'],redemption=req.document()['redemption']))
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    with pytest.raises(ValueError,match='unapproved'):
        await prepare_maintenance(execution,anchor=built.anchor,provider=c.provider,journal=journal)
    assert not journal.recent()
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('cached retry must not rebuild')))
    assert await prepare_consent(req,anchor=built.anchor,provider=offline,store=store,clock=lambda:now+10)==signed
