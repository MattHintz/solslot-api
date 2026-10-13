"""Actual funded epoch -> saved review -> confirmed fixed claim and safe retry."""
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
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_ballots import CurrentHoldings
from solslot_puzzles.generation_sgt import ledger_inner
from solslot_puzzles.generation_rewards import RewardCustody,RewardFeeInput,close_reward_epoch
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_execution import MaintenanceRequest,prepare_maintenance
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_api.generation_reward_evidence import verified_reward_inputs
from solslot_api.generation_coin_evidence import read_confirmed_coin
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared
from tests.test_generation_execution import h


async def funding(chain,*,native=False):
    sim,client,_,anchor,_=chain
    acs=Program.to(1);await sim.farm_block(acs.get_tree_hash())
    origin=(await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[-1].coin
    if native:
        custody=RewardCustody(anchor.issuance.bindings(),anchor.economic_components[1].launcher_id,bytes32.zeros)
        parent=make_spend(origin,acs,Program.to([[51,custody.full().get_tree_hash(),90],
            [51,acs.get_tree_hash(),int(origin.amount)-90]]))
        assert await client.push_tx(SpendBundle([parent],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        return custody,RewardFeeInput(Coin(origin.name(),custody.full().get_tree_hash(),uint64(90)),parent)
    tail=GENESIS_BY_ID_MOD.curry(origin.name())
    custody=RewardCustody(anchor.issuance.bindings(),anchor.economic_components[1].launcher_id,tail.get_tree_hash())
    eve=Coin(origin.name(),construct_cat_puzzle(CAT_MOD,custody.asset_id,acs).get_tree_hash(),uint64(90))
    funding=make_spend(origin,acs,Program.to([[51,eve.puzzle_hash,90],[51,acs.get_tree_hash(),int(origin.amount)-90]]))
    issued=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,custody.asset_id,acs,
        Program.to([[51,custody.inner().get_tree_hash(),90],[51,[],-113,tail,[]]]),limitations_program_reveal=tail)])
    assert await client.push_tx(SpendBundle([funding,*issued.coin_spends],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    return custody,RewardFeeInput(Coin(eve.name(),custody.full().get_tree_hash(),uint64(90)),issued.coin_spends[0])


def request(anchor,e,kind,**values):
    components={h(identity):h(history.current.coin.name()) for identity,history in e.economic_components.items()
        if kind=='CLOSE_REWARD_EPOCH' and h(identity)==values['rewardEpoch']['statutesComponentId']}
    return MaintenanceRequest.model_validate(dict(generationId=h(anchor.issuance.generation),requestKey=kind,kind=kind,
        expectedInputs={name:h(getattr(e,name).current.coin.name()) for name in ('registry','governance','holdings')}|
            {'components':components},feeCapMojos=1000,**values))


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[False,True])
async def test_reward_closure_claims_and_retries_use_exact_confirmed_epoch(generation_chain,prepared,tmp_path,native):
    sim,client,provider,anchor,_=generation_chain
    custody,fee=await funding(generation_chain,native=native)
    sim.pass_time(uint64(86401));await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider);state=anchor.economic_components[1]
    tree,seq=e.holdings.state
    intent=dict(assetId=h(custody.asset_id),statutesComponentId=h(state.component_id),statutesLauncherId=h(state.launcher_id),
        revision=state.revision,valuesHash=h(Program.to(list(state.values)).get_tree_hash()),
        holdingsRoot=h(tree.root.hash),eligibleSupply=tree.root.eligible,ledgerSequence=seq,feeCoinIds=[h(fee.coin.name())])
    req=request(anchor,e,'CLOSE_REWARD_EPOCH',rewardEpoch=intent)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    for fault in ('asset','root','supply','sequence','values','source','authority','extra'):
        raw=deepcopy(req.document());raw['requestKey']=fault
        field={'asset':'assetId','root':'holdingsRoot','values':'valuesHash','authority':'statutesLauncherId'}.get(fault)
        if field:raw['rewardEpoch'][field]='0x'+'ff'*32
        elif fault=='supply':raw['rewardEpoch']['eligibleSupply']+=1
        elif fault=='sequence':raw['rewardEpoch']['ledgerSequence']+=1
        elif fault=='source':raw['rewardEpoch']['feeCoinIds']=['0x'+'ff'*32]
        elif fault=='extra':raw['rewardEpoch']['destination']='0x'+'ff'*32
        with pytest.raises(ValueError):
            await prepare_maintenance(MaintenanceRequest.model_validate(raw),anchor=anchor,provider=provider,journal=journal)
    native=close_reward_epoch(custody,e.governance.state,e.registry.state,
        CurrentHoldings(custody.bindings,tree,seq,e.holdings.verified_tip(custody.bindings.ledger_launcher_id,ledger_inner(custody.bindings,tree,seq))),
        state,e.economic_components[state.component_id].verified_tip(state.launcher_id,state.inner()),(fee,))
    saved=await prepare_maintenance(req,anchor=anchor,provider=provider,journal=journal)
    assert saved['review']['rewardEpoch']==intent
    assert journal.protocol_bundle(saved['operationId'])==native.operation.bundle()
    assert await client.push_tx(native.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    current=await resolve_generation_chain(anchor,provider=provider)
    assert current.holdings.state[0].root==tree.root and current.holdings.state[1]==seq
    assert current.economic_components[state.component_id].state==state
    claim,source=native.claims[0]
    recipient=next(row for row in prepared[3].administrators if row.sgt_owner_puzzle_hash==h(claim.owner))
    claim_intent=dict(assetId=h(claim.asset_id),statutesLauncherId=h(state.launcher_id),epochId=h(claim.epoch_id),
        ownerPuzzleHash=h(claim.owner),amount=claim.amount,claimCoinId=h(source.coin.name()),vaultLauncherId=recipient.custody.launcher_id)
    claim_req=request(anchor,current,'CLAIM_SGT_REWARD',rewardClaim=claim_intent)
    inputs,records=await verified_reward_inputs((source.coin.name(),),provider=provider)
    assert inputs==(source,) and any(record.coin.amount==0 for record in records)
    for fault in ('owner','vault','amount','epoch','source','asset'):
        raw=deepcopy(claim_req.document());raw['requestKey']='claim-'+fault
        key={'owner':'ownerPuzzleHash','vault':'vaultLauncherId','epoch':'epochId','source':'claimCoinId','asset':'assetId'}.get(fault)
        if key:raw['rewardClaim'][key]='0x'+'ff'*32
        else:raw['rewardClaim']['amount']+=1
        with pytest.raises(ValueError):
            await prepare_maintenance(MaintenanceRequest.model_validate(raw),anchor=anchor,provider=provider,journal=journal)
    payment=await prepare_maintenance(claim_req,anchor=anchor,provider=provider,journal=journal)
    assert len(journal.protocol_bundle(payment['operationId']).coin_spends)==1
    assert await client.push_tx(journal.protocol_bundle(payment['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('saved retry must not contact node')))
    restored=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    for review,receipt in ((req,saved),(claim_req,payment)):
        assert await prepare_maintenance(review,anchor=anchor,provider=offline,journal=restored)==receipt
    with pytest.raises(ValueError,match='spent'):
        await verified_reward_inputs((source.coin.name(),),provider=provider)
    # Zero-valued epoch parents are an explicit exception, never spendable funding.
    zero=next(record for record in records if not record.coin.amount)
    raw=await provider.get_coin_record_by_name_primary(h(zero.coin.name()))
    with pytest.raises(ValueError):read_confirmed_coin(raw,zero.coin.name())
    assert read_confirmed_coin(raw,zero.coin.name(),allow_zero=True)==zero
