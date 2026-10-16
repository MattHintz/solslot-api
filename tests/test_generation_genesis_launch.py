"""Whole economic launch uses real signed funding and native consensus.

Synthetic administrator keys and destinations only; no release/backup approval
or public dispatch is implied by an assembled or simulated bundle.
"""
from copy import deepcopy
from types import SimpleNamespace
import json
from hashlib import sha256

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL,G2Element,SpendBundle
from solslot_api.generation_genesis_core import GenerationLaunchArtifact,genesis_launch_funding_requests,assemble_genesis_launch
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_index import load_generation_read_anchor
from solslot_puzzles.generation_rewards import RewardCustody
from solslot_puzzles.generation_sols_reserve import reserve_inner
from tests.test_generation_genesis_core import core,standard_spend


async def initialize_and_upgrade(c,path,*,initialized=None):
    """Actual signatures and consensus; only the simulator clock is advanced."""
    from chia_rs.sized_ints import uint64
    from solslot_api.generation_holder_ballots import GenerationBallotStore,prepare_holder_ballot,assemble_holder_ballot
    from solslot_api.generation_holder_evidence import preparation_custody_anchors
    from solslot_api.generation_operations import GenerationOperationJournal
    from solslot_api.generation_execution import prepare_maintenance
    from tests.test_generation_holder_ballots import consent,request,sign_all
    from tests.test_generation_execution import body
    built=initialized if initialized is not None else complete(c)[2];anchor=built.anchor
    if initialized is None:
        assert await c.client.push_tx(built.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
        await c.sim.farm_block()
    c.sim.pass_time(uint64(1000));await c.sim.farm_block()
    chain=await resolve_generation_chain(anchor,provider=c.provider)
    before={identity:history.state.state() for identity,history in chain.economic_components.items()}
    pool=built.anchor.economic_components[2]
    token_ids=(anchor.issuance.tail().get_tree_hash(),pool.permanent.permanent_rules.sols_tail_hash)
    supply=chain.holdings.state[0].root
    now=int(c.sim.timestamp)-1
    store,review=await consent(c,built,chain,path,now)
    ballots=GenerationBallotStore(path/'ballots.db',c.prep.generation_id)
    journal=GenerationOperationJournal(path/'operations.db',c.prep.generation_id)
    ballot=await prepare_holder_ballot(request(c,chain,review['proposalId'],[1,2],key='upgrade-holder-opening',consent_id=review['packageId']),
        anchor=anchor,custodies=preparation_custody_anchors(c.prep),provider=c.provider,store=ballots,consents=store,clock=lambda:now)
    await sign_all(c,ballot,ballots,now)
    saved=await assemble_holder_ballot(ballot['packageId'],anchor=anchor,provider=c.provider,store=ballots,consents=store,
        journal=journal,clock=lambda:now)
    assert await c.client.push_tx(journal.protocol_bundle(saved['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    async def step(kind,**values):
        e=await resolve_generation_chain(anchor,provider=c.provider)
        if kind=='PROVE_STATE':
            proof=e.public_status(int(c.sim.timestamp))['stateProof'];values['proof']={k:v for k,v in proof.items() if k!='supported'}
        saved=await prepare_maintenance(body(anchor,e,kind,**values),anchor=anchor,provider=c.provider,journal=journal,clock=lambda:int(c.sim.timestamp))
        return journal.protocol_bundle(saved['operationId'])
    opening=await step('ANCHOR_VOTE')
    assert await c.client.push_tx(opening)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    close=await step('FINALIZE_VOTE')
    assert (await c.client.push_tx(close))[0]!=MempoolInclusionStatus.SUCCESS
    c.sim.pass_time(uint64(3601));await c.sim.farm_block()
    assert await c.client.push_tx(close)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    upgrade=review['proposal']['upgrade']
    ratify=await step('RATIFY_UPGRADE',proposalId=review['proposalId'],upgrade=upgrade)
    assert await c.client.push_tx(ratify)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    activate=await step('ACTIVATE_UPGRADE',upgrade=upgrade)
    assert (await c.client.push_tx(activate))[0]!=MempoolInclusionStatus.SUCCESS
    c.sim.pass_time(uint64(86401));await c.sim.farm_block()
    assert await c.client.push_tx(activate)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    prove=await step('PROVE_STATE')
    assert await c.client.push_tx(prove)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    chain=await resolve_generation_chain(anchor,provider=c.provider)
    assert chain.governance.state.version==2 and chain.public_status(now)['stateProof']['supported']
    assert chain.holdings.state[0].root.total==supply.total and chain.holdings.state[0].root.eligible==supply.eligible
    assert before=={identity:history.state.state() for identity,history in chain.economic_components.items()}
    assert token_ids==(anchor.issuance.tail().get_tree_hash(),chain.economic_components[pool.component_id].state.permanent.permanent_rules.sols_tail_hash)
    return built,chain


def launch_artifact(c):
    raw=c.artifact.model_dump(mode='json',by_alias=True);raw['purpose']='GENERATION_LAUNCH_PREPARATION'
    from solslot_puzzles.generation_revenue import CompanyRevenue, BackingCustody
    from chia_rs.sized_bytes import bytes32
    gen=bytes32.from_hexstr(c.prep.generation_id)
    raw.update(custodyPolicy='SEGREGATED_COMPANY_REVENUE_V1',
        treasuryPuzzleHash='0x'+BackingCustody(gen).inner().get_tree_hash().hex(),
        companyRevenuePuzzleHash='0x'+CompanyRevenue(gen,bytes32.from_hexstr(c.prep.coordinates['authority'].launcher_id)).inner().get_tree_hash().hex())
    return GenerationLaunchArtifact.model_validate(raw)


def complete(c):
    artifact=launch_artifact(c)
    coins=dict(c.funding,pool=next(coin for coin in c.parents if '0x'+coin.name().hex()==c.prep.coordinates['pool'].funding_coin_id))
    arguments=dict(preparation=c.prep,artifact=artifact,evidence=c.evidence,
        trusted_preparation_hash=c.prep.manifest_hash,trusted_artifact_hash=artifact.artifact_hash)
    requests=genesis_launch_funding_requests(**arguments,funding_coins=coins)
    spends={r.name:standard_spend(c.faucet,r.coin,r.conditions) for r in requests}
    signatures=[G2Element.from_bytes(c.faucet.sign_delegated_spend(r.coin,r.conditions,purpose='genesis')) for r in requests]
    return artifact,requests,assemble_genesis_launch(**arguments,funding_spends=spends,aggregated_signature=AugSchemeMPL.aggregate(signatures))


@pytest.mark.asyncio
async def test_launch_rejects_wallet_treasury_and_mixed_revenue_buckets(core):
    from chia_rs.sized_bytes import bytes32
    from solslot_puzzles.generation_revenue import CompanyRevenue, BackingCustody
    c=core;artifact=launch_artifact(c)
    gen=bytes32.from_hexstr(c.prep.generation_id)
    changed={
        'wallet_backing':dict(treasuryPuzzleHash='0x'+'43'*32),
        'wallet_revenue':dict(companyRevenuePuzzleHash='0x'+'43'*32),
        'backing_is_revenue':dict(treasuryPuzzleHash=artifact.company_revenue_puzzle_hash),
        'revenue_is_backing':dict(companyRevenuePuzzleHash=artifact.treasury_puzzle_hash),
        'another_generation':dict(companyRevenuePuzzleHash='0x'+CompanyRevenue(bytes32(bytes([77])*32),
            bytes32.from_hexstr(c.prep.coordinates['authority'].launcher_id)).inner().get_tree_hash().hex()),
        'another_authority':dict(companyRevenuePuzzleHash='0x'+CompanyRevenue(gen,bytes32(bytes([77])*32)).inner().get_tree_hash().hex()),
        'principal_is_revenue':dict(protocolPuzzleHash=artifact.company_revenue_puzzle_hash),
        'principal_is_backing':dict(protocolPuzzleHash=artifact.treasury_puzzle_hash),
    }
    coins=dict(c.funding,pool=next(coin for coin in c.parents if '0x'+coin.name().hex()==c.prep.coordinates['pool'].funding_coin_id))
    for name,fields in changed.items():
        raw=artifact.model_dump(mode='json',by_alias=True);raw.update(fields)
        altered=GenerationLaunchArtifact.model_validate(raw)
        with pytest.raises(ValueError,match='segregated'):
            genesis_launch_funding_requests(preparation=c.prep,artifact=altered,evidence=c.evidence,
                trusted_preparation_hash=c.prep.manifest_hash,trusted_artifact_hash=altered.artifact_hash,funding_coins=coins)


@pytest.mark.asyncio
async def test_full_atomic_launch_has_readable_pool_exact_rewards_and_conserved_grants(core,tmp_path):
    c=core;artifact,requests,built=complete(c);bundle=built.operation.bundle()
    assert len(requests)==8 and [r.name for r in requests][-1]=='pool'
    assert complete(c)[2].operation.bundle()==bundle
    initial_pool=built.anchor.economic_components[2];statutes=built.anchor.economic_components[0]
    assert initial_pool.permanent.sgt_rewards_puzzle_hash==RewardCustody(built.anchor.issuance.bindings(),
        statutes.launcher_id,statutes.permanent_rules.sols_tail_hash).inner().get_tree_hash()
    assert initial_pool.permanent.reserve_puzzle_hash==reserve_inner(generation=initial_pool.generation,
        registry_id=initial_pool.registry_id,pool_id=initial_pool.launcher_id,component_id=initial_pool.component_id,pool_kernel_version=2).get_tree_hash()
    assert sum(coin.amount for coin in bundle.removals())==sum(coin.amount for coin in bundle.additions())
    # Omission is rejected at consensus, not merely by the assembler.
    for i in range(len(bundle.coin_spends)):
        partial=SpendBundle([s for j,s in enumerate(bundle.coin_spends) if j!=i],bundle.aggregated_signature)
        assert (await c.client.push_tx(partial))[0]!=MempoolInclusionStatus.SUCCESS
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    e=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert e.holdings.state[0].root.eligible==30000 and e.holdings.state[0].root.total==1000000
    assert [coin.amount for coin in built.issuance.coins]==[10000,10000,10000,970000]
    pool=e.economic_components[initial_pool.component_id].state
    assert pool.economics.state_version==2 and pool.economics.economics.total_sols_mojos==1
    assert pool.economics.economics.reserve_sols_mojos==1
    assert pool.permanent==initial_pool.permanent and pool.component()==initial_pool.component()
    for tip in built.operation.successors:
        assert not (await c.client.get_coin_record_by_name(tip.coin.name())).spent
    assert (await c.client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    review=built.review()
    assert review['assemblyComplete'] and not review['launchComplete']
    assert review['remainingAssembly']==['FINAL_RELEASE_RECOVERY_AND_CONSENT']
    assert e.public_status(123)['rewardAuthorities']==[dict(assetId='0x'+statutes.permanent_rules.sols_tail_hash.hex(),
        statutesComponentId='0x'+statutes.component_id.hex(),statutesLauncherId='0x'+statutes.launcher_id.hex(),revision=0,
        valuesHash='0x'+Program.to(list(statutes.values)).get_tree_hash().hex(),epochSeconds=86400)]
    prep_file=tmp_path/'prep.json';prep_file.write_text(c.prep.model_dump_json(by_alias=True))
    anchor_file=tmp_path/'anchor.json';anchor_file.write_text(json.dumps(review['readAnchor']))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=c.prep.generation_id,
        generation_preparation_path=str(prep_file),generation_preparation_hash=c.prep.manifest_hash,
        generation_chain_anchor_path=str(anchor_file),generation_chain_anchor_hash='0x'+sha256(anchor_file.read_bytes()).hexdigest())
    read=load_generation_read_anchor(settings)
    assert read.registry.inner()==built.anchor.registry.inner()
    assert (await resolve_generation_chain(read,provider=c.provider)).economic_components[pool.component_id].state.inner()==pool.inner()


@pytest.mark.asyncio
async def test_full_genesis_requires_new_explicit_artifact_and_every_reserved_parent(core):
    c=core;artifact,requests,_=complete(c)
    coins={r.name:r.coin for r in requests}
    args=dict(preparation=c.prep,artifact=artifact,evidence=c.evidence,funding_coins=coins,
        trusted_preparation_hash=c.prep.manifest_hash,trusted_artifact_hash=artifact.artifact_hash)
    for changes in ({'artifact':c.artifact},{'trusted_artifact_hash':c.artifact.artifact_hash},
            {'funding_coins':c.funding},{'funding_coins':dict(coins,sgt=coins['pool'])}):
        with pytest.raises(ValueError):genesis_launch_funding_requests(**(args|changes))
    spends={r.name:standard_spend(c.faucet,r.coin,r.conditions) for r in requests}
    r=requests[-1];raw=deepcopy(r.conditions.as_python());raw[0][2]=2
    spends['pool']=standard_spend(c.faucet,r.coin,raw)
    args.pop('funding_coins')
    with pytest.raises(ValueError,match='funding conditions'):
        assemble_genesis_launch(**args,funding_spends=spends)
