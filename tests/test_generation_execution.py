"""Exercise the API's explicit builder against actual native state transitions."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_ballots import CurrentHoldings,CustodyAuthorization,SGTInput,open_proposal
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.generation_registry import CodeChange,UpgradePlan
from solslot_puzzles.generation_sgt import build_initial_issuance,ledger_inner,transition_digest
from solslot_puzzles.generation_vault import signing_digest
from solslot_puzzles.holdings import HoldingKind
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_execution import MaintenanceRequest,prepare_maintenance
from solslot_api.generation_operations import GenerationOperationJournal
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared


def h(v):return '0x'+v.hex()


def body(anchor,evidence,kind,**kwargs):
    affected={change['componentId'] for change in kwargs.get('upgrade',{}).get('changes',[])}
    components={h(identity):h(history.current.coin.name()) for identity,history in evidence.economic_components.items()
        if (kind=='ACTIVATE_UPGRADE' and h(identity) in affected) or (kind=='APPLY_PARAMETERS' and h(identity)==kwargs['parameters']['componentId'])}
    return MaintenanceRequest.model_validate(dict(generationId=h(anchor.issuance.generation),requestKey=kind,
        kind=kind,feeCapMojos=1000,expectedInputs={name:h(getattr(evidence,name).current.coin.name())
            for name in ('registry','governance','holdings')}|{'components':components},**kwargs))


async def open_native(generation_chain,prepared,bill_factory=None):
    sim,client,provider,anchor,launches=generation_chain
    _,_,_,manifest,_,_=prepared
    sim.pass_time(uint64(1000));await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider)
    gov,reg=e.governance.state,e.registry.state
    gt=e.governance.verified_tip(reg.governance_id,gov.inner())
    rt=e.registry.verified_tip(reg.launcher_id,reg.inner())
    tree,seq=e.holdings.state
    current=CurrentHoldings(gov.sgt,tree,seq,e.holdings.verified_tip(gov.sgt.ledger_launcher_id,ledger_inner(gov.sgt,tree,seq)))
    authority=SingletonTip(reg.administrator_id,Program.to(1),compute_additions(launches['authority'])[0],launches['authority'])
    economic_changes=[]
    for state in anchor.economic_components:
        filename='generation_mint_logic_v1.clsp' if state.component_id==bytes32(b'm'*32) else 'generation_parameter_logic_v1.clsp'
        replacement=Program.to([2,(1,load_puzzle(filename)),1])
        economic_changes.append(CodeChange(state.component_id,state.logic_hash(),replacement.get_tree_hash(),2,1))
    plan=UpgradePlan(bytes32(b's'*32),(CodeChange(gov.component_id,gov.module_hash,
        load_puzzle('generation_extension_v2.clsp').get_tree_hash(),2,1),*economic_changes))
    bill=bill_factory(e) if bill_factory else Program.to([b'UPGRADE',0,plan.program()]);proposal=gov.proposal_id(bill,tree)
    issue=build_initial_issuance(anchor.issuance);authorizations=[]
    expires=int(sim.timestamp)+600
    for i in (0,1):
        a=manifest.administrators[i];launcher=bytes32.from_hexstr(a.custody.launcher_id)
        record=await client.get_coin_record_by_name(launcher)
        launch=await client.get_puzzle_and_solution(launcher,record.spent_block_index)
        vault=SingletonTip(launcher,manifest.custody_inner(a),compute_additions(launch)[0],launch)
        holding=SGTInput(issue.coins[i],issue.outputs[i],issue.eve_spend)
        locked=replace(holding.descriptor,kind=HoldingKind.LOCKED_HOLDER,lock_id=proposal)
        digest=transition_digest(gov.sgt,holding.coin,'LOCK',(locked,))
        signature=keys.PrivateKey(bytes([i+1])*32).sign_msg_hash(signing_digest(gov.sgt.generation,
            vault.coin.name(),holding.coin.name(),digest,expires)).to_bytes()[:64]
        authorizations.append(CustodyAuthorization(holding,vault,expires,signature))
    issued=int(sim.timestamp)-1
    message=Program.to([b'PUBLICATION_APPROVAL',gov.sgt.generation,proposal,issued,issued+86400]).get_tree_hash()
    approval=authority.spend(Program.to([[66,18,message,gt.coin.puzzle_hash],[51,authority.inner.get_tree_hash(),1]]))
    opened=open_proposal(gov,gt,reg,rt,current,bill,authority,(approval,),issued,tuple(authorizations))
    assert await client.push_tx(opened.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    return proposal,plan


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['economic'],indirect=True)
async def test_applies_only_ratified_parameters_and_recovers_exact_readable_review(generation_chain,prepared,tmp_path):
    sim,client,provider,anchor,_=generation_chain
    parameter=anchor.economic_components[1]
    values=(86400,300,100,70,30,86400)
    proposal,_=await open_native(generation_chain,prepared,lambda e:parameter.bill(values))
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE'):
        e=await resolve_generation_chain(anchor,provider=provider)
        saved=await prepare_maintenance(body(anchor,e,kind),anchor=anchor,provider=provider,journal=journal)
        bundle=journal.protocol_bundle(saved['operationId'])
        if kind=='FINALIZE_VOTE':
            assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
            sim.pass_time(uint64(3601));await sim.farm_block()
        assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
    e=await resolve_generation_chain(anchor,provider=provider)
    intent=e.public_status(100)['approvedActions'][0]['parameters']
    assert intent['values']==list(values)
    request=body(anchor,e,'APPLY_PARAMETERS',proposalId=h(proposal),parameters=intent)
    for mutation in ('fee','revision','input','proposal'):
        raw=request.model_dump(mode='json',by_alias=True);raw['requestKey']=mutation
        if mutation=='fee':raw['parameters']['values'][3:5]=[30,70]
        if mutation=='revision':raw['parameters']['revision']+=1
        if mutation=='input':raw['expectedInputs']['components']={}
        if mutation=='proposal':raw['proposalId']='0x'+'ff'*32
        with pytest.raises(ValueError):
            await prepare_maintenance(MaintenanceRequest.model_validate(raw),anchor=anchor,provider=provider,journal=journal)
    saved=await prepare_maintenance(request,anchor=anchor,provider=provider,journal=journal)
    assert saved['review']['parameters']==intent
    bundle=journal.protocol_bundle(saved['operationId'])
    assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    updated=await resolve_generation_chain(anchor,provider=provider)
    assert updated.economic_components[parameter.component_id].state.values==values
    assert updated.public_status(101)['exchangeFees']==dict(totalBps=100,protocolBps=70,sgtRewardsBps=30,
        authorityId=h(parameter.component_id),revision=1)
    assert not updated.public_status(101)['approvedActions']
    restored=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('must not rebuild')))
    assert await prepare_maintenance(request,anchor=anchor,provider=offline,journal=restored)==saved
    assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',[None,'economic'],indirect=True)
async def test_api_prepares_and_recovers_exact_native_upgrade_actions(generation_chain,prepared,tmp_path):
    sim,client,provider,anchor,_=generation_chain
    proposal,plan=await open_native(generation_chain,prepared)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    upgrade={'sourceManifestHash':h(plan.source_manifest_hash),'changes':[{
        'componentId':h(c.component_id),'oldModuleHash':h(c.old_module_hash),'newModuleHash':h(c.new_module_hash),
        'nextVersion':c.next_version,'compatibility':c.compatibility} for c in plan.changes]}
    supply_before=None
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE','RATIFY_UPGRADE','ACTIVATE_UPGRADE'):
        e=await resolve_generation_chain(anchor,provider=provider)
        status=e.public_status(1000)
        if kind=='RATIFY_UPGRADE':
            assert status['approvedActions'][0]['proposalId']==h(proposal)
            assert status['approvedActions'][0]['upgrade']['sourceManifestHash']==h(plan.source_manifest_hash)
        if kind=='ACTIVATE_UPGRADE':
            assert not status['approvedActions']
            assert status['pendingUpgrade']['proposalId']==h(proposal)
        extras={'upgrade':upgrade} if 'UPGRADE' in kind else {}
        if kind=='RATIFY_UPGRADE':extras['proposalId']=h(proposal)
        request=body(anchor,e,kind,**extras)
        saved=await prepare_maintenance(request,anchor=anchor,provider=provider,journal=journal,clock=lambda:1000)
        opid=saved['operationId'];bundle=journal.protocol_bundle(opid)
        assert saved['stage']=='PREPARED' and saved['transactionId'] is None
        # Timeout after saving, then restart: return the same bytes without
        # even contacting the node, much less reserving another input.
        restored=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
        offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('must not rebuild')))
        assert await prepare_maintenance(request,anchor=anchor,provider=offline,journal=restored,clock=lambda:1001)==saved
        assert restored.protocol_bundle(opid)==bundle
        if kind in ('FINALIZE_VOTE','ACTIVATE_UPGRADE'):
            result=await client.push_tx(bundle)
            assert result[0]!=MempoolInclusionStatus.SUCCESS
            expected='SECONDS_ABSOLUTE' if kind=='FINALIZE_VOTE' else 'SECONDS_RELATIVE'
            assert expected in result[1].name
            sim.pass_time(uint64(3601 if kind=='FINALIZE_VOTE' else 86401));await sim.farm_block()
        if kind=='ACTIVATE_UPGRADE':supply_before=e.holdings.state[0].root
        assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        # Saved review still recovers after its consumed inputs change.
        assert await prepare_maintenance(request,anchor=anchor,provider=provider,journal=journal,clock=lambda:1002)==saved
        altered=request.model_copy(update={'fee_cap_mojos':1001})
        with pytest.raises(ValueError,match='retry changes'):
            await prepare_maintenance(altered,anchor=anchor,provider=offline,journal=journal)
    final=await resolve_generation_chain(anchor,provider=provider)
    assert final.governance.state.version==2 and not final.registry.state.pending
    assert final.holdings.state[0].root==supply_before
    for initial in anchor.economic_components:
        current=final.economic_components[initial.component_id].state
        assert current.version==2 and current.state()==initial.state()
        assert current.launcher_id==initial.launcher_id
        assert current.component() in final.registry.state.components
    # Exercise the new instruction through the API's exact review, rather
    # than treating an increased version number as successful code execution.
    proof=final.public_status(1003)['stateProof']
    assert proof.pop('supported') is True
    request=body(anchor,final,'PROVE_STATE',proof=proof)
    before_state=final.governance.state.state();before_supply=final.holdings.state[0].root
    before_components=final.registry.state.components
    saved=await prepare_maintenance(request,anchor=anchor,provider=provider,journal=journal,clock=lambda:1003)
    bundle=journal.protocol_bundle(saved['operationId'])
    assert saved['review']['proof']==proof
    assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    proved=await resolve_generation_chain(anchor,provider=provider)
    assert proved.governance.state.state()==before_state and proved.holdings.state[0].root==before_supply
    assert proved.registry.state.components==before_components
    assert proved.governance.transitions[-1].action=='READ'
    assert await prepare_maintenance(request,anchor=anchor,provider=offline,journal=journal,clock=lambda:1004)==saved
    # A fresh review cannot claim another version, module or preserved state.
    current_proof=proved.public_status(1004)['stateProof'];current_proof.pop('supported')
    for field,value in [('version',3),('moduleHash','0x'+'12'*32),('stateHash','0x'+'13'*32),('componentId','0x'+'14'*32)]:
        altered=body(anchor,proved,'PROVE_STATE',proof={**current_proof,field:value})
        altered=altered.model_copy(update={'request_key':'changed-'+field})
        with pytest.raises(ValueError,match='state proof differs'):
            await prepare_maintenance(altered,anchor=anchor,provider=provider,journal=journal)



@pytest.mark.asyncio
async def test_prepare_rejects_stale_review_and_unratified_or_unsupported_actions(generation_chain,tmp_path):
    _,_,provider,anchor,_=generation_chain
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),h(anchor.issuance.generation))
    e=await resolve_generation_chain(anchor,provider=provider)
    for kind in ('ANCHOR_VOTE','FINALIZE_VOTE','REOPEN_OPERATIONS'):
        with pytest.raises(ValueError):await prepare_maintenance(body(anchor,e,kind),anchor=anchor,provider=provider,journal=journal)
    proof=e.public_status(1000)['stateProof'];assert proof.pop('supported') is False
    with pytest.raises(ValueError,match='activated reviewed'):
        await prepare_maintenance(body(anchor,e,'PROVE_STATE',proof=proof),anchor=anchor,provider=provider,journal=journal)
    # Direct construction cannot smuggle the v2 reveal into the v1 kernel.
    from solslot_puzzles.generation_registry import inner_solution
    from chia_rs import SpendBundle,G2Element
    gov=e.governance.state;tip=e.governance.verified_tip(gov.sgt.governance_launcher_id,gov.inner())
    direct=tip.spend(inner_solution('READ',tip.coin,[load_puzzle('generation_extension_v2.clsp'),b'PROVE_STATE']))
    assert (await generation_chain[1].push_tx(SpendBundle([direct],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    request=body(anchor,e,'FINALIZE_VOTE')
    raw=request.model_dump(mode='json',by_alias=True);raw['expectedInputs']['governance']='0x'+'12'*32
    with pytest.raises(ValueError,match='inputs changed'):
        await prepare_maintenance(MaintenanceRequest.model_validate(raw),anchor=anchor,provider=provider,journal=journal)
    assert journal.recent()==[]


@pytest.mark.parametrize('fault',['unknown_action','caller_bundle','scope_on_finalize','plan_missing','proposal_missing','fee_bool','fee_over_cap','duplicate_components','transition_change'])
def test_typed_request_rejects_ambiguous_or_unbounded_review(fault):
    h='0x'+'12'*32
    raw=dict(generationId=h,requestKey='test',kind='FINALIZE_VOTE',feeCapMojos=1000,
        expectedInputs=dict(registry=h,governance=h,holdings=h))
    if fault=='unknown_action':raw['kind']='ADMIN_PARAMETER_FAST_TRACK'
    if fault=='caller_bundle':raw['spendBundle']={}
    if fault=='scope_on_finalize':raw['scope']=1
    if fault=='plan_missing':raw['kind']='ACTIVATE_UPGRADE'
    if fault=='proposal_missing':raw['kind']='RATIFY_REOPENING';raw['scope']=1
    if fault=='fee_bool':raw['feeCapMojos']=True
    if fault=='fee_over_cap':raw['feeCapMojos']=1000000001
    if fault in ('duplicate_components','transition_change'):
        raw['kind']='ACTIVATE_UPGRADE'
        change=dict(componentId=h,oldModuleHash=h,newModuleHash='0x'+'13'*32,nextVersion=2,compatibility=1)
        if fault=='transition_change':change['transition']='REPLACE_STATE'
        raw['upgrade']=dict(sourceManifestHash=h,changes=[change,change] if fault=='duplicate_components' else [change])
    with pytest.raises(ValueError):MaintenanceRequest.model_validate(raw)
