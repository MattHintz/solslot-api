"""Saved reviews, real paired authority signatures and native pause/opening."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_admin_transactions import complete_administrator_action
from solslot_puzzles.generation_ballots import CurrentHoldings,CustodyAuthorization,SGTInput,open_proposal
from solslot_puzzles.generation_sgt import ledger_inner,transition_digest
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.generation_vault import signing_digest
from solslot_puzzles.holdings import HoldingKind
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_consents import (ConsentRequest,GenerationConsentStore,prepare_consent,sign_consent,
    restore_consent,prepare_scoped_pause)
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_api.generation_execution import MaintenanceRequest,prepare_maintenance
from tests.test_generation_genesis_core import core,assembly


def h(value):return '0x'+value.hex()


def request(anchor,chain,kind='PUBLICATION_APPROVAL',key='one',**kwargs):
    gov=chain.governance.state
    defaults={'proposalKind':'UPGRADE','upgrade':{'sourceManifestHash':'0x'+'51'*32,'changes':[{
        'componentId':h(gov.component_id),'oldModuleHash':h(gov.module_hash),
        'newModuleHash':h(load_puzzle('generation_extension_v2.clsp').get_tree_hash()),
        'nextVersion':gov.version+1,'compatibility':gov.compatibility}]}} if kind=='PUBLICATION_APPROVAL' else {'scope':31}
    return ConsentRequest.model_validate({'generationId':h(anchor.issuance.generation),'requestKey':key,
        'kind':kind,'coadministratorSlot':1,'feeCapMojos':1000,
        'expectedInputs':{name:h(getattr(chain,name).current.coin.name()) for name in ('registry','governance','holdings')},
        **defaults,**kwargs})


async def initialized(c):
    built=assembly(c)
    assert await c.client.push_tx(built.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    c.sim.pass_time(uint64(1000));await c.sim.farm_block()
    return built,await resolve_generation_chain(built.anchor,provider=c.provider)


@pytest.mark.asyncio
async def test_canonical_fact_review_uses_real_admin_signatures_without_bypassing_holder_vote(core,tmp_path):
    from solslot_puzzles.protocol_statutes_v1 import CollectionStatute
    from solslot_api.generation_chain_evidence import public_bill
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    state=built.anchor.economic_components[0]
    record=CollectionStatute(bytes32(b'f'*32),75_000_000_000,75_000_000_000,1,0,2**32,1)
    bill,_,_=state.record_change('COLLECTION',(),record)
    public=public_bill(bill)['statutes'];intent=public|{'currentRecords':[]}
    inputs={name:h(getattr(chain,name).current.coin.name()) for name in ('registry','governance','holdings')}
    inputs['components']={h(state.component_id):h(chain.economic_components[state.component_id].current.coin.name())}
    req=request(built.anchor,chain,proposalKind='STATUTES',upgrade=None,statutes=intent,expectedInputs=inputs)
    store=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    review=await prepare_consent(req,anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    assert review['proposal']==public_bill(bill) and review['expiresAt']==now+86400
    import os,json
    if target:=os.environ.get('GENERATION_STATUTES_CONSENT_VECTOR'):
        Path(target).write_text(json.dumps({'review':review,'request':req.document()},indent=2)+'\n')
    for challenge in review['challenges']:
        signature=keys.PrivateKey(bytes([challenge['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(challenge['digest'])).to_bytes()
        reviewed=await sign_consent(review['packageId'],challenge['slot'],signature,
            anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now+1)
    assert reviewed['stage']=='READY'
    execution=MaintenanceRequest.model_validate(dict(generationId=c.prep.generation_id,requestKey='cannot-fast-track',
        kind='APPLY_STATUTES',proposalId=review['proposalId'],feeCapMojos=1000,expectedInputs=inputs,statutes=intent))
    journal=GenerationOperationJournal(str(tmp_path/'ops.db'),c.prep.generation_id)
    with pytest.raises(ValueError):
        await prepare_maintenance(execution,anchor=built.anchor,provider=c.provider,journal=journal,clock=lambda:now+2)
    assert (await resolve_generation_chain(built.anchor,provider=c.provider)).economic_components[state.component_id].state.state()==state.state()


@pytest.mark.asyncio
async def test_saved_publication_survives_offline_refresh_and_real_native_opening(core,tmp_path):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    store=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    req=request(built.anchor,chain)
    prepared=await prepare_consent(req,anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    assert prepared['stage']=='AWAITING_APPROVALS' and prepared['expiresAt']==now+86400
    assert prepared['requiredVotes']==15000 and prepared['eligibleSupply']==30000
    assert prepared['proposal']['kind']=='UPGRADE'
    identity=prepared['packageId'];before=Path(store.path).read_bytes()
    # Public, synthetic native vector for the browser's independent intent
    # reconstruction. No test signing keys or stored signatures are exported.
    import os,json
    if target:=os.environ.get('GENERATION_CONSENT_VECTOR'):
        Path(target).write_text(json.dumps({'review':prepared,'request':req.document()},indent=2)+'\n')
    for _ in range(10):assert store.status(identity,now+100)==prepared
    assert Path(store.path).read_bytes()==before
    restored=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('cached retry must not touch node')))
    assert await prepare_consent(req,anchor=built.anchor,provider=offline,store=restored,clock=lambda:now+100)==prepared
    changed=req.model_copy(update={'fee_cap_mojos':1001})
    with pytest.raises(ValueError,match='original consent'):
        await prepare_consent(changed,anchor=built.anchor,provider=offline,store=store,clock=lambda:now)
    for ch in prepared['challenges']:
        slot=ch['slot'];private=keys.PrivateKey(bytes([slot+1])*32)
        signature=private.sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        with pytest.raises(ValueError):store.record_signature(identity,2,signature,now)
        wrong=keys.PrivateKey(bytes([9])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        with pytest.raises(ValueError):store.record_signature(identity,slot,wrong,now)
        status=await sign_consent(identity,slot,signature,anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now+10)
        assert store.record_signature(identity,slot,signature,now+20)==status # duplicate signature keeps original time
    assert status['stage']=='READY'
    assert store.status(identity,now+86400)['stage']=='EXPIRED'
    with pytest.raises(ValueError,match='window ended'):store.record_signature(identity,0,signature,now+86400)
    assert await prepare_consent(req,anchor=built.anchor,provider=offline,store=store,clock=lambda:now+86401)==store.status(identity,now+86401)
    document=store.document(identity);consent=restore_consent(document,built.authority)
    signed=complete_administrator_action(consent,{r['slot']:bytes.fromhex(r['signature'][2:]) for r in store.signatures(identity)})
    gov,registry=chain.governance.state,chain.registry.state
    gov_tip=chain.governance.verified_tip(registry.governance_id,gov.inner())
    reg_tip=chain.registry.verified_tip(registry.launcher_id,registry.inner())
    tree,seq=chain.holdings.state
    holdings=CurrentHoldings(gov.sgt,tree,seq,chain.holdings.verified_tip(gov.sgt.ledger_launcher_id,ledger_inner(gov.sgt,tree,seq)))
    sponsors=[]
    # One holder sponsors with its real complete 10k coin; publication itself
    # supplies no voting weight and does not make the 15k quorum pass.
    item=SGTInput(built.issuance.coins[0],built.issuance.outputs[0],built.issuance.eve_spend)
    row=c.evidence.recipients[0];record=await c.client.get_coin_record_by_name(row.coin_id)
    parent_record=await c.client.get_coin_record_by_name(record.coin.parent_coin_info)
    parent=await c.client.get_puzzle_and_solution(record.coin.parent_coin_info,parent_record.spent_block_index)
    vault=SingletonTip(row.launcher_id,c.prep.custody_inner(c.prep.administrators[0]),record.coin,parent)
    locked=replace(item.descriptor,kind=HoldingKind.LOCKED_HOLDER,lock_id=bytes32.from_hexstr(status['proposalId']))
    expiry=now+600;digest=transition_digest(gov.sgt,item.coin,'LOCK',(locked,))
    signature=keys.PrivateKey(bytes([1])*32).sign_msg_hash(signing_digest(gov.sgt.generation,vault.coin.name(),item.coin.name(),digest,expiry)).to_bytes()[:64]
    sponsors.append(CustodyAuthorization(item,vault,expiry,signature))
    plan=req.upgrade.plan();bill=Program.to([b'UPGRADE',registry.nonce,plan.program()])
    opened=open_proposal(gov,gov_tip,registry,reg_tip,holdings,bill,consent.administrator,signed.spends,now,tuple(sponsors))
    assert opened.governance.active.yes_weight==10000 and opened.governance.active.required_votes==15000
    assert await c.client.push_tx(opened.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    with pytest.raises(ValueError,match='input changed'):
        await sign_consent(identity,0,bytes.fromhex(store.signatures(identity)[0]['signature'][2:]),
            anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now+20)
    with pytest.raises(ValueError,match='holder sponsorship'):
        await prepare_scoped_pause(identity,anchor=built.anchor,provider=offline,store=store,journal=None,clock=lambda:now)


@pytest.mark.asyncio
async def test_exact_scoped_pause_two_roles_restart_and_explicit_native_preparation(core,tmp_path):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    store=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    review=await prepare_consent(request(built.anchor,chain,'PAUSE_NEW_OPERATIONS'),
        anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    identity=review['packageId'];assert review['scope']==31 and review['issuedAt']==0
    with pytest.raises(ValueError,match='both unexpired'):
        await prepare_scoped_pause(identity,anchor=built.anchor,provider=c.provider,store=store,journal=journal,clock=lambda:now)
    for ch in review['challenges']:
        signature=keys.PrivateKey(bytes([ch['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        await sign_consent(identity,ch['slot'],signature,anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    saved=await prepare_scoped_pause(identity,anchor=built.anchor,provider=c.provider,store=store,journal=journal,clock=lambda:now)
    assert saved['kind']=='PAUSE_NEW_OPERATIONS' and saved['review']['scope']==31 and saved['transactionId'] is None
    bundle=journal.protocol_bundle(saved['operationId'])
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    paused=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert paused.registry.state.pause_mask==31 and paused.public_status(123)['supply']['distributed']==30000
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('saved pause must not rebuild')))
    assert await prepare_scoped_pause(identity,anchor=built.anchor,provider=offline,store=store,journal=journal,clock=lambda:now+90000)==saved
    assert (await c.client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    # Changed commitments and corrupted stored signature bytes fail closed.
    with store._db(write=True) as db:
        db.execute('UPDATE generation_consent_signatures SET signature=? WHERE package_id=? AND slot=0',('0x'+'22'*64,identity))
    with pytest.raises(ValueError):store.status(identity,now)


@pytest.mark.asyncio
async def test_wrong_generation_stale_economics_and_bad_scope_never_create_a_review(core,tmp_path):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    store=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    req=request(built.anchor,chain)
    for field,value in [('generation_id','0x'+'55'*32),('expected_inputs',req.expected_inputs.model_copy(update={'governance':'0x'+'66'*32})),
                        ('upgrade',req.upgrade.model_copy(update={'changes':(req.upgrade.changes[0].model_copy(update={'next_version':3}),)}))]:
        with pytest.raises(ValueError):
            await prepare_consent(req.model_copy(update={field:value}),anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    assert store.recent(now)==[]
    for bad in (True,0,32):
        with pytest.raises(ValueError):request(built.anchor,chain,'PAUSE_NEW_OPERATIONS',scope=bad)
    for raw in ({'proposalKind':None},{'parameters':{'invalid':True}},{'scope':1},{'coadministratorSlot':True}):
        with pytest.raises(ValueError):request(built.anchor,chain,**raw)
