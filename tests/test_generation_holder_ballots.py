"""Native co-sponsorship, exact holder signatures and saved vote lifecycles."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH,launch_conditions_and_coinsol,puzzle_for_singleton
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys
from solslot_puzzles import load_puzzle

from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_consents import GenerationConsentStore,prepare_consent,sign_consent
from solslot_api.generation_holder_ballots import (HolderBallotRequest,GenerationBallotStore,
    prepare_holder_ballot,sign_holder_ballot,assemble_holder_ballot)
from solslot_api.generation_holder_evidence import HolderCustodyAnchor,preparation_custody_anchors,resolve_holder_custody
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_puzzles.generation_transactions import anchor_vote,finalize_vote
from solslot_puzzles.generation_vault import signing_digest,vault_inner,sgt_owner,authorization_solution,owner_solution
from solslot_puzzles.generation_sgt import transition_witness,transition_digest,ledger_inner
from solslot_puzzles.generation_ballots import SGTInput
from solslot_api.faucet import AGG_SIG_ME_DATA
from tests.test_generation_genesis_core import core
from tests.test_generation_consents import initialized,request as consent_request,h


@pytest.mark.asyncio
async def test_pause_new_proposals_preserves_native_holder_reopening_and_24_hour_delay(core,tmp_path):
    from solslot_api.generation_consents import prepare_scoped_pause
    from solslot_puzzles.generation_transactions import ratify_reopening,reopen_operations
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    consents=GenerationConsentStore(str(tmp_path/'consents.db'),c.prep.generation_id)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    async def approved(req):
        review=await prepare_consent(req,anchor=built.anchor,provider=c.provider,store=consents,clock=lambda:now)
        for ch in review['challenges']:
            sig=keys.PrivateKey(bytes([ch['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
            await sign_consent(review['packageId'],ch['slot'],sig,anchor=built.anchor,provider=c.provider,store=consents,clock=lambda:now)
        return review
    pause=await approved(consent_request(built.anchor,chain,kind='PAUSE_NEW_OPERATIONS',key='pause',scope=31))
    paused=await prepare_scoped_pause(pause['packageId'],anchor=built.anchor,provider=c.provider,store=consents,journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(paused['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert chain.registry.state.pause_mask==31
    with pytest.raises(ValueError,match='unblock proposal'):
        await prepare_consent(consent_request(built.anchor,chain,key='blocked-upgrade'),anchor=built.anchor,provider=c.provider,store=consents,clock=lambda:now)
    publication=await approved(consent_request(built.anchor,chain,key='reopen',proposalKind='REOPEN',upgrade=None,scope=31))
    store=GenerationBallotStore(str(tmp_path/'ballots.db'),c.prep.generation_id)
    req=request(c,chain,publication['proposalId'],[1,2],key='reopen-sponsors',consent_id=publication['packageId'])
    review=await prepare_holder_ballot(req,anchor=built.anchor,custodies=preparation_custody_anchors(c.prep),provider=c.provider,
        store=store,consents=consents,clock=lambda:now)
    await sign_all(c,review,store,now)
    opened=await assemble_holder_ballot(review['packageId'],anchor=built.anchor,provider=c.provider,store=store,consents=consents,journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(opened['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    gov=chain.governance.state;reg=chain.registry.state
    govtip=chain.governance.verified_tip(reg.governance_id,gov.inner())
    clock=await c.client.get_coin_record_by_name(gov.active.clock_id)
    anchored,_=anchor_vote(gov,govtip,clock.coin,int(clock.timestamp))
    assert await c.client.push_tx(anchored.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    c.sim.pass_time(uint64(3600));await c.sim.farm_block()
    gov=chain.governance.state;reg=chain.registry.state
    finalized,_=finalize_vote(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()))
    assert await c.client.push_tx(finalized.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    gov=chain.governance.state;reg=chain.registry.state
    ratified,_,_=ratify_reopening(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()),reg,
        chain.registry.verified_tip(reg.launcher_id,reg.inner()),bytes32.from_hexstr(publication['proposalId']),31)
    assert await c.client.push_tx(ratified.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    reg=chain.registry.state
    reopening,_=reopen_operations(reg,chain.registry.verified_tip(reg.launcher_id,reg.inner()),ratified.auxiliary_outputs[0])
    result,_=await c.client.push_tx(reopening.bundle());assert result!=MempoolInclusionStatus.SUCCESS
    c.sim.pass_time(uint64(86400));await c.sim.farm_block()
    assert await c.client.push_tx(reopening.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert chain.registry.state.pause_mask==0 and chain.holdings.state[0].root.eligible==30000


async def consent(c,built,chain,path,now):
    store=GenerationConsentStore(str(path/'consents.db'),c.prep.generation_id)
    review=await prepare_consent(consent_request(built.anchor,chain),anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    for ch in review['challenges']:
        sig=keys.PrivateKey(bytes([ch['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        await sign_consent(review['packageId'],ch['slot'],sig,anchor=built.anchor,provider=c.provider,store=store,clock=lambda:now)
    return store,review


def request(c,chain,proposal,slots,key='holder-opening',consent_id=None):
    return HolderBallotRequest.model_validate({'generationId':c.prep.generation_id,'requestKey':key,
        'kind':'OPEN_PROPOSAL' if consent_id else 'CAST_VOTE','proposalId':proposal,'consentPackageId':consent_id,
        'expectedInputs':{name:h(getattr(chain,name).current.coin.name()) for name in ('registry','governance','holdings')},
        'feeCapMojos':1000,'selected':[{'coinId':h(next(identity for identity,value in chain.holdings.state[0].holdings.items()
            if value.owner_hash==bytes32.from_hexstr(c.prep.administrators[slot-1].sgt_owner_puzzle_hash))),
            'vaultLauncherId':c.prep.administrators[slot-1].custody.launcher_id} for slot in slots]})


def sign(row,private):
    r=row['request'];digest=signing_digest(bytes32.from_hexstr(r['generationId']),bytes32.from_hexstr(r['vaultCoinId']),
        bytes32.from_hexstr(r['sgtCoinId']),bytes32.from_hexstr(row['transitionDigest']),r['expiresAt'])
    return private.sign_msg_hash(digest).to_bytes()


async def sign_all(c,review,store,now):
    for row in review['holders']:
        public=row['context']['owner']['publicKey']
        slot=next(a.slot for a in c.prep.administrators if a.custody_owner_public_key==public)
        await sign_holder_ballot(review['packageId'],row['request']['sgtCoinId'],sign(row,keys.PrivateKey(bytes([slot])*32)),
            provider=c.provider,store=store,clock=lambda:now)


@pytest.mark.asyncio
async def test_native_co_sponsors_keep_owners_and_saved_reviews_survive_offline_restart(core,tmp_path):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    consents,pub=await consent(c,built,chain,tmp_path,now)
    store=GenerationBallotStore(str(tmp_path/'ballots.db'),c.prep.generation_id)
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    anchors=preparation_custody_anchors(c.prep)
    req=request(c,chain,pub['proposalId'],[1,2],consent_id=pub['packageId'])
    review=await prepare_holder_ballot(req,anchor=built.anchor,custodies=anchors,provider=c.provider,store=store,consents=consents,clock=lambda:now)
    import os,json
    if target:=os.environ.get('GENERATION_HOLDER_VECTOR'):
        # Public synthetic intent only; private keys and signatures are not exported.
        Path(target).write_text(json.dumps({'review':review,'bindings':review['holders'][0]['context']['bindings']},indent=2)+'\n')
    assert review['stage']=='AWAITING_HOLDER_SIGNATURES' and review['selectedWeight']==20000
    assert review['eligibleSupply']==30000 and review['requiredVotes']==15000
    assert review['expiresAt']==pub['expiresAt'] and review['votingClosesAt'] is None
    assert {r['request']['outputs'][0]['owner'] for r in review['holders']}=={c.prep.administrators[i].sgt_owner_puzzle_hash for i in (0,1)}
    assert {r['context']['vault']['launcherId'] for r in review['holders']}=={c.prep.administrators[i].custody.launcher_id for i in (0,1)}
    from solslot_api.generation_ballot_routes import cached_holder_selection
    from unittest.mock import Mock
    index=SimpleNamespace(store=SimpleNamespace(status=Mock(return_value={'status':'READY','generationId':c.prep.generation_id,
        'lastCheckedAt':now,'snapshot':chain.public_status(now)})),verified=True,evidence=chain,anchor=built.anchor)
    catalog=cached_holder_selection(index,SimpleNamespace(preparation=c.prep),now)
    assert len(catalog['holdings'])==3 and sum(r['amount'] for r in catalog['holdings'])==30000
    assert catalog['eligibleSupply']==30000 and catalog['scope']=='FROZEN_GENESIS_ROSTER'
    assert {r['vaultLauncherId'] for r in catalog['holdings']}=={a.custody.launcher_id for a in c.prep.administrators}
    from solslot_api.generation_storage import GenerationRetentionFull
    store.MAX_RETAINED_BYTES=1
    new_request=req.model_copy(update={'request_key':'another-ballot'})
    changed=store.document(review['packageId']);changed['request']=new_request.model_dump(mode='json',by_alias=True)
    with pytest.raises(GenerationRetentionFull):store.save(new_request,changed,now)
    assert len(store.recent(now))==1
    before=Path(store.path).read_bytes()
    for _ in range(10):assert store.status(review['packageId'],now+10)==review
    assert Path(store.path).read_bytes()==before
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('saved retry cannot touch node')))
    restarted=GenerationBallotStore(str(tmp_path/'ballots.db'),c.prep.generation_id)
    assert await prepare_holder_ballot(req,anchor=built.anchor,custodies=(),provider=offline,store=restarted,consents=None,clock=lambda:now+100)==review
    with pytest.raises(ValueError,match='reviewed holder selection'):
        await prepare_holder_ballot(req.model_copy(update={'fee_cap_mojos':1001}),anchor=built.anchor,custodies=anchors,
            provider=offline,store=store,consents=consents,clock=lambda:now)
    with pytest.raises(ValueError,match='all selected holder signatures'):
        await assemble_holder_ballot(review['packageId'],anchor=built.anchor,provider=c.provider,store=store,consents=consents,journal=journal,clock=lambda:now)
    for row in review['holders']:
        wrong=sign(row,keys.PrivateKey(bytes([9])*32))
        with pytest.raises(ValueError):store.record_signature(review['packageId'],row['request']['sgtCoinId'],wrong,now)
    await sign_all(c,review,store,now)
    assert store.status(review['packageId'],now)['stage']=='READY'
    row=review['holders'][0];sig=sign(row,keys.PrivateKey(bytes([1])*32))
    first=store.record_signature(review['packageId'],row['request']['sgtCoinId'],sig,now)
    assert store.record_signature(review['packageId'],row['request']['sgtCoinId'],sig,now+10)==first
    saved=await assemble_holder_ballot(review['packageId'],anchor=built.anchor,provider=c.provider,store=store,consents=consents,journal=journal,clock=lambda:now)
    assert saved['stage']=='PREPARED' and saved['transactionId'] is None
    bundle=journal.protocol_bundle(saved['operationId'])
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    opened=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert opened.governance.state.active.yes_weight==20000
    assert opened.governance.state.active.required_votes==15000 and opened.holdings.state[0].root.eligible==30000
    for anchor in anchors[:2]:
        current=await resolve_holder_custody(anchor,provider=c.provider)
        assert current.state==anchor.inner
        assert current.current.coin.puzzle_hash==puzzle_for_singleton(anchor.launcher_id,anchor.inner).get_tree_hash()
        assert len(current.transitions)==1
    assert await assemble_holder_ballot(review['packageId'],anchor=built.anchor,provider=offline,store=restarted,consents=None,journal=journal,clock=lambda:now+90000)==saved
    assert (await c.client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    with pytest.raises(ValueError,match='input changed'):
        await sign_holder_ballot(review['packageId'],row['request']['sgtCoinId'],sig,provider=c.provider,store=store,clock=lambda:now)


@pytest.mark.asyncio
async def test_later_holder_vote_preserves_confirmed_one_hour_window_and_whole_input(core,tmp_path):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    consents,pub=await consent(c,built,chain,tmp_path,now);anchors=preparation_custody_anchors(c.prep)
    store=GenerationBallotStore(str(tmp_path/'ballots.db'),c.prep.generation_id);journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    review=await prepare_holder_ballot(request(c,chain,pub['proposalId'],[1],consent_id=pub['packageId']),
        anchor=built.anchor,custodies=anchors,provider=c.provider,store=store,consents=consents,clock=lambda:now)
    await sign_all(c,review,store,now)
    saved=await assemble_holder_ballot(review['packageId'],anchor=built.anchor,provider=c.provider,store=store,consents=consents,journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    gov=chain.governance.state;tip=chain.governance.verified_tip(chain.registry.state.governance_id,gov.inner())
    clock_coin=await c.client.get_coin_record_by_name(gov.active.clock_id)
    operation,_=anchor_vote(gov,tip,clock_coin.coin,int(clock_coin.timestamp))
    assert await c.client.push_tx(operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    deadline=chain.governance.state.active.voting_closes_at;opened_at=chain.governance.state.active.opened_at
    c.sim.pass_time(uint64(100));await c.sim.farm_block();now=int(c.sim.timestamp)-1
    vote=await prepare_holder_ballot(request(c,chain,pub['proposalId'],[2],key='later-vote'),
        anchor=built.anchor,custodies=anchors,provider=c.provider,store=store,consents=None,clock=lambda:now)
    assert vote['expiresAt']==deadline and vote['votingClosesAt']==deadline
    assert vote['selectedWeight']==10000 and vote['holders'][0]['request']['outputs'][0]['amount']==10000
    await sign_all(c,vote,store,now)
    saved=await assemble_holder_ballot(vote['packageId'],anchor=built.anchor,provider=c.provider,store=store,consents=None,journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();voted=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert voted.governance.state.active.yes_weight==20000
    assert voted.governance.state.active.opened_at==opened_at and voted.governance.state.active.voting_closes_at==deadline
    close,_=finalize_vote(voted.governance.state,voted.governance.verified_tip(voted.registry.state.governance_id,voted.governance.state.inner()))
    assert (await c.client.push_tx(close.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    with pytest.raises(ValueError,match='deadline'):
        await prepare_holder_ballot(request(c,voted,pub['proposalId'],[3],key='expired-vote'),anchor=built.anchor,
            custodies=anchors,provider=c.provider,store=store,consents=None,clock=lambda:deadline)
    assert store.status(vote['packageId'],deadline)['stage']=='EXPIRED'
    c.sim.pass_time(uint64(deadline-int(c.sim.timestamp)+1));await c.sim.farm_block()
    assert await c.client.push_tx(close.bundle())==(MempoolInclusionStatus.SUCCESS,None)


@pytest.mark.asyncio
async def test_reserve_stale_selection_wrong_generation_and_signature_never_save(core,tmp_path):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    consents,pub=await consent(c,built,chain,tmp_path,now);anchors=preparation_custody_anchors(c.prep)
    store=GenerationBallotStore(str(tmp_path/'ballots.db'),c.prep.generation_id)
    req=request(c,chain,pub['proposalId'],[1],consent_id=pub['packageId']);raw=req.model_dump(mode='json',by_alias=True)
    reserve=h(built.issuance.coins[-1].name())
    for change in ({'generationId':'0x'+'55'*32},{'proposalId':'0x'+'56'*32},
        {'feeCapMojos':1001},{'selected':[{'coinId':reserve,'vaultLauncherId':req.selected[0].vault_launcher_id}]},
        {'expectedInputs':{**raw['expectedInputs'],'holdings':'0x'+'57'*32}},
        {'selected':[{'coinId':req.selected[0].coin_id,'vaultLauncherId':c.prep.administrators[1].custody.launcher_id}]}):
        with pytest.raises(ValueError):
            await prepare_holder_ballot(HolderBallotRequest.model_validate({**raw,**change}),anchor=built.anchor,
                custodies=anchors,provider=c.provider,store=store,consents=consents,clock=lambda:now)
    assert store.recent(now)==[]
    for change in ({'selected':[raw['selected'][0]]*2},{'feeCapMojos':True},{'consentPackageId':None},{'spendBundle':{}}):
        with pytest.raises(ValueError):HolderBallotRequest.model_validate({**raw,**change})


@pytest.mark.asyncio
@pytest.mark.parametrize('policy_change',['NONE','STAMP','BLS_ROTATION','EVM_ROTATION'])
async def test_holder_current_policy_can_cosponsor_without_shared_custody(core,tmp_path,policy_change):
    c=core;built,chain=await initialized(c);now=int(c.sim.timestamp)-1
    acs=Program.to(1);origins=await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())
    origin=next(r.coin for r in origins if not r.spent)
    launcher=Coin(origin.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name()
    private=AugSchemeMPL.key_gen(bytes([87])*32);public=bytes(private.get_g1())
    pool=bytes32.from_hexstr(c.prep.coordinates['pool'].launcher_id)
    bridge=acs.get_tree_hash() if policy_change=='STAMP' else bytes32.from_hexstr(c.prep.bridge_policy_hash)
    inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=public,auth_type=1,
        members_merkle_root=Program.to(public).get_tree_hash(),pool_launcher_id=pool,zkpassport_bridge_policy_hash=bridge)
    conditions,launch=launch_conditions_and_coinsol(origin,inner,[],uint64(1))
    conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
    assert await c.client.push_tx(SpendBundle([make_spend(origin,acs,Program.to(conditions)),launch],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    anchors=preparation_custody_anchors(c.prep);bls=HolderCustodyAnchor(built.anchor.issuance.generation,launcher,inner,pool,bridge)
    custody=await resolve_holder_custody(anchors[0],provider=c.provider)
    tip=custody.verified_tip(anchors[0].launcher_id,anchors[0].inner)
    bindings=chain.governance.state.sgt;tree,seq=chain.holdings.state
    item=SGTInput(built.issuance.coins[0],built.issuance.outputs[0],built.issuance.eve_spend)
    output=replace(item.descriptor,owner=sgt_owner(bindings.generation,launcher).get_tree_hash())
    expiry=now+86400;digest=transition_digest(bindings,item.coin,'TRANSFER',(output,))
    signature=keys.PrivateKey(bytes([1])*32).sign_msg_hash(signing_digest(bindings.generation,tip.coin.name(),item.coin.name(),digest,expiry)).to_bytes()[:64]
    ledtip=chain.holdings.verified_tip(bindings.ledger_launcher_id,ledger_inner(bindings,tree,seq))
    witness,next_tree=transition_witness(bindings,tree,item.coin,item.descriptor,'TRANSFER',(output,))
    cat=SpendableCAT(coin=item.coin,limitations_program_hash=bindings.tail_hash,inner_puzzle=item.descriptor.inner(bindings),
        lineage_proof=item.validate(bindings),inner_solution=Program.to([b'TRANSFER',item.coin.name(),item.coin.amount,
            ledtip.inner.get_tree_hash(),sgt_owner(bindings.generation,tip.launcher_id),
            owner_solution(tip.coin,tip.inner,item.coin.name(),'TRANSFER',(output,),expiry),[],[output.descriptor()]]))
    cats=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
    transfer=SpendBundle([*cats.coin_spends,ledtip.spend(Program.to([b'UPDATE',[witness]])),
        tip.spend(authorization_solution(bindings.generation,tip.coin,tip.inner,item.coin.name(),digest,expiry,signature))],G2Element())
    assert await c.client.push_tx(transfer)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();chain=await resolve_generation_chain(built.anchor,provider=c.provider)
    old_private=private;current_inner=inner;evm_private=None
    if policy_change!='NONE':
        history=await resolve_holder_custody(bls,provider=c.provider);tip=history.verified_tip(launcher,history.state)
        when=int(c.sim.timestamp);module=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash()
        extras=[]
        if policy_change=='STAMP':
            from solslot_puzzles.zkpassport_attestation import compute_attestation_bridge_message
            identity_root=bytes32(b'V'*32)
            origins=await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())
            bridge_coin=next(r.coin for r in origins if not r.spent and r.coin.amount>1)
            message=compute_attestation_bridge_message(vault_launcher_id=launcher,attestation_root=identity_root,bridge_policy_hash=bridge)
            extras=[make_spend(bridge_coin,acs,Program.to([[60,b'S'+message],[51,acs.get_tree_hash(),int(bridge_coin.amount)]]))]
            action=b'z';arguments=[module,identity_root,bridge_coin.parent_coin_info,bridge_coin.amount,when,[]]
            digest=Program.to([action,identity_root,tip.coin.name()]).get_tree_hash()
            current_inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=public,auth_type=1,
                members_merkle_root=Program.to(public).get_tree_hash(),identity_attest_root=identity_root,
                pool_launcher_id=pool,zkpassport_bridge_policy_hash=bridge)
        else:
            evm_private=keys.PrivateKey(bytes([88])*32) if policy_change=='EVM_ROTATION' else None
            private=AugSchemeMPL.key_gen(bytes([88])*32) if evm_private is None else private
            new_key=evm_private.public_key.to_compressed_bytes() if evm_private else bytes(private.get_g1())
            kind=3 if evm_private else 1;members=Program.to(new_key).get_tree_hash()
            action=b'k';arguments=[module,new_key,kind,members,(0,[]),when,[]]
            digest=Program.to([action,new_key,kind,members,tip.coin.name()]).get_tree_hash()
            current_inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=new_key,auth_type=kind,
                members_merkle_root=members,pool_launcher_id=pool,zkpassport_bridge_policy_hash=bridge)
        changed=tip.spend(Program.to([tip.coin.name(),tip.inner.get_tree_hash(),1,action,arguments]))
        authorization=AugSchemeMPL.sign(old_private,bytes(digest)+tip.coin.name()+AGG_SIG_ME_DATA['testnet11'])
        assert await c.client.push_tx(SpendBundle([changed,*extras],authorization))==(MempoolInclusionStatus.SUCCESS,None)
        await c.sim.farm_block()
        current=await resolve_holder_custody(bls,provider=c.provider)
        assert current.state==current_inner and current.current.coin.parent_coin_info==changed.coin.name()
        assert current.transitions==(action.decode('ascii'),)
        assert bls.owner==output.owner # Same token owner and launcher, despite a new custody key/root.
        # A provider cannot substitute a new policy for the original frozen
        # launch anchor, or report a different confirmed continuation.
        from copy import deepcopy
        class WrongChild(type(c.provider)):
            async def get_coin_record_by_name_primary(self,name):
                raw=deepcopy(await super().get_coin_record_by_name_primary(name))
                if name==h(current.current.coin.name()):raw['coin']['puzzle_hash']=h(bytes32(b'X'*32))
                return raw
        with pytest.raises(ValueError):await resolve_holder_custody(bls,provider=WrongChild(c.client))
    consents,pub=await consent(c,built,chain,tmp_path,now)
    raw=request(c,chain,pub['proposalId'],[2],consent_id=pub['packageId']).model_dump(mode='json',by_alias=True)
    raw['selected'].append({'coinId':h(output.coin(bindings,item.coin.name()).name()),'vaultLauncherId':h(launcher)})
    req=HolderBallotRequest.model_validate(raw)
    store=GenerationBallotStore(str(tmp_path/'ballots.db'),c.prep.generation_id);journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    review=await prepare_holder_ballot(req,anchor=built.anchor,custodies=(*anchors,bls),provider=c.provider,store=store,consents=consents,clock=lambda:now)
    assert review['selectedWeight']==20000 and review['eligibleSupply']==30000
    import os,json
    if target:=os.environ.get('GENERATION_CUSTODY_VECTORS'):
        row=next(r for r in review['holders'] if r['context']['vault']['launcherId']==h(launcher))
        Path(target+'/'+policy_change+'.json').write_text(json.dumps(row,indent=2)+'\n')
    for row in review['holders']:
        if row['context']['owner']['authType']==1:
            r=row['request'];message=bytes32.from_hexstr(row['authorizationHash'])+bytes32.from_hexstr(r['vaultCoinId'])+AGG_SIG_ME_DATA['testnet11']
            signature=bytes(AugSchemeMPL.sign(private,message))
            wrong=bytes(AugSchemeMPL.sign(private,message[:-32]+AGG_SIG_ME_DATA['mainnet']))
            with pytest.raises(ValueError,match='exact Testnet11'):
                store.record_signature(review['packageId'],r['sgtCoinId'],wrong,now)
            if policy_change=='BLS_ROTATION':
                with pytest.raises(ValueError,match='exact Testnet11'):
                    store.record_signature(review['packageId'],r['sgtCoinId'],bytes(AugSchemeMPL.sign(old_private,message)),now)
            assert row['request']['vaultCoinSpend']['coin']['amount']==1
        else:
            signer=evm_private if row['context']['vault']['launcherId']==h(launcher) else keys.PrivateKey(bytes([2])*32)
            signature=sign(row,signer)
            if signer is evm_private:
                with pytest.raises(ValueError):store.record_signature(review['packageId'],row['request']['sgtCoinId'],sign(row,keys.PrivateKey(bytes([87])*32)),now)
        await sign_holder_ballot(review['packageId'],row['request']['sgtCoinId'],signature,provider=c.provider,store=store,clock=lambda:now)
    saved=await assemble_holder_ballot(review['packageId'],anchor=built.anchor,provider=c.provider,store=store,consents=consents,journal=journal,clock=lambda:now)
    bundle=journal.protocol_bundle(saved['operationId'])
    assert (bundle.aggregated_signature!=G2Element())==(policy_change!='EVM_ROTATION')
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();opened=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert opened.governance.state.active.yes_weight==20000
    assert (await resolve_holder_custody(bls,provider=c.provider)).state==current_inner
    assert opened.holdings.state[0].root.total==1000000
