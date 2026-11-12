from copy import deepcopy

import pytest
import pytest_asyncio
import asyncio
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol, lineage_proof_for_coinsol, puzzle_for_singleton, solution_for_singleton
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import SpendBundle, G2Element, AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.generation_chain_evidence import GenerationChainAnchor, resolve_generation_chain, current_evidence_unchanged
from solslot_api.generation_recipient_evidence import issuance_plan_from_recipients, verify_recipient_custody
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_registry import Registry, Component, inner_solution
from solslot_puzzles.generation_sgt import build_initial_issuance, ledger_inner
from tests.test_generation_recipient_evidence import prepared, Primary


@pytest_asyncio.fixture
async def generation_chain(prepared,request):
    sim,client,provider,m,sigs,origins=prepared
    evidence=await verify_recipient_custody(m,sigs,trusted_preparation_hash=m.manifest_hash,provider=provider)
    plan=issuance_plan_from_recipients(m,evidence);issue=build_initial_issuance(plan)
    coordinate=lambda name:bytes32.from_hexstr(m.coordinates[name].launcher_id)
    gov=Governance(plan.bindings(),coordinate('registry'),coordinate('authority'),coordinate('mint'),
        bytes32(b'g'*32),load_puzzle('generation_extension_v1.clsp').get_tree_hash())
    component=Component(gov.component_id,plan.governance_launcher_id,
        load_puzzle('generation_governance_v1.clsp').get_tree_hash(),gov.module_hash,1,1)
    economic=()
    if getattr(request,'param',None) in ('economic','pool','statutes','rewards'):
        from solslot_puzzles.generation_parameters import GenerationParameters
        from solslot_puzzles.generation_mint import GenerationMint
        economic=(GenerationMint(plan.generation,coordinate('registry'),coordinate('governance'),coordinate('mint'),
            bytes32(b'm'*32),coordinate('pool'),bytes32(b't'*32),bytes32(b'd'*32),
            tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (31,32,33)),bytes32(b'o'*32)),
            GenerationParameters(plan.generation,coordinate('registry'),coordinate('governance'),coordinate('parameters'),bytes32(b'p'*32)))
    if getattr(request,'param',None) in ('statutes','rewards'):
        from solslot_puzzles.generation_statutes import GenerationStatutes
        from solslot_puzzles.protocol_statutes_v1 import PermanentRules
        from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
        old=economic[1]
        statutes=GenerationStatutes(old.generation,old.registry_id,old.governance_id,old.launcher_id,old.component_id,
            pool_id=coordinate('pool'),permanent_rules=PermanentRules(plan.bindings().tail_hash,1_000_000,
                pool_token_tail_hash(coordinate('pool')),bytes32.from_hexstr(m.bridge_policy_hash),bytes32(b't'*32),plan.generation))
        economic=(economic[0],statutes)
    if getattr(request,'param',None)=='pool':
        from solslot_puzzles.generation_pool import GenerationPool
        from solslot_puzzles.generation_registry import singleton_struct
        from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
        from solslot_puzzles.sols_economics_v3 import SolsEconomicState
        from solslot_puzzles.sols_pool_v4 import SolsPoolStateV4
        from solslot_puzzles.pool_v4_driver import PoolV4Config
        from chia.wallet.cat_wallet.cat_utils import CAT_MOD
        from chia.wallet.trading.offer import OFFER_MOD_HASH
        from solslot_puzzles.protocol_statutes_driver import protocol_statutes_inner_mod_hash
        from solslot_puzzles.protocol_statutes_v1 import PermanentRules
        # Reader fixture, not whole economic/genesis admission. These pinned
        # legacy statutes witnesses cannot authorize new-generation swaps.
        rules=PermanentRules(plan.bindings().tail_hash,1_000_000,pool_token_tail_hash(coordinate('pool')),
            bytes32.from_hexstr(m.bridge_policy_hash),bytes32(b't'*32),plan.generation)
        config=PoolV4Config(coordinate('pool'),protocol_statutes_inner_mod_hash(),singleton_struct(bytes32(b's'*32)),
            singleton_struct(coordinate('governance')),rules,CAT_MOD.get_tree_hash(),OFFER_MOD_HASH,
            load_puzzle('p2_vault.clsp').get_tree_hash(),load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash(),
            load_puzzle('p2_pool_v2.clsp').get_tree_hash(),bytes32(b'd'*32),bytes32(b'r'*32),bytes32(b'w'*32))
        pool=GenerationPool(plan.generation,coordinate('registry'),bytes32(b'l'*32),config,
            SolsPoolStateV4(Program.to([]).get_tree_hash(),SolsEconomicState(False,0,0,0,0,1,1),1))
        economic=(*economic,pool)
    registry=Registry(plan.generation,coordinate('registry'),coordinate('governance'),coordinate('authority'),
        (component,*(s.component() for s in economic)))
    anchor=GenerationChainAnchor(plan,registry,gov,economic)
    acs=Program.to(1);origin=next(c for c in origins if '0x'+c.name().hex()==m.sgt_funding_coin_id)
    spends=[make_spend(origin,acs,Program.to([[51,issue.eve_coin.puzzle_hash,1000000],
        [51,acs.get_tree_hash(),int(origin.amount)-1000000]])),issue.eve_spend]
    launches={}
    economic_launches=[('mint',economic[0].inner()),('parameters',economic[1].inner())] if economic else []
    if len(economic)==3:economic_launches.append(('pool',economic[2].inner()))
    for name,inner in [('registry',registry.inner()),('governance',gov.inner()),('holdings',ledger_inner(plan.bindings(),issue.holdings,0)),('authority',acs),*economic_launches]:
        origin=next(c for c in origins if '0x'+c.name().hex()==m.coordinates[name].funding_coin_id)
        conditions,launch=launch_conditions_and_coinsol(origin,inner,[],uint64(1))
        conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
        spends.extend([make_spend(origin,acs,Program.to(conditions)),launch]);launches[name]=launch
        if name=='holdings':
            coin=compute_additions(launch)[0]
            spends.append(make_spend(coin,puzzle_for_singleton(coordinate(name),inner),
                solution_for_singleton(lineage_proof_for_coinsol(launch),uint64(1),issue.ledger_initialization())))
    assert await client.push_tx(SpendBundle(spends,G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    yield sim,client,provider,anchor,launches


@pytest.mark.asyncio
async def test_reconstructs_exact_initial_issuance_and_detects_new_spend(generation_chain):
    sim,client,provider,anchor,launches=generation_chain
    evidence=await resolve_generation_chain(anchor,provider=provider)
    view=evidence.public_status(1234)
    assert view['supply']['total']==1000000 and view['supply']['distributed']==30000
    assert view['supply']['reserve']==970000 and view['supply']['undeliveredEscrow']==0
    assert view['supply']['nextProposalQuorum']==15000 and view['proposal'] is None
    assert view['exchangeFees'] is None  # Never invent fees without chain evidence.
    assert not view['active'] and not evidence.snapshots
    assert len(evidence.holdings.state[0].holdings)==4
    assert await current_evidence_unchanged(evidence,provider=provider)
    reconstructed=evidence.governance.verified_tip(anchor.governance.sgt.governance_launcher_id,anchor.governance.inner())
    assert reconstructed.parent==launches['governance']
    ledger_tip=evidence.holdings.verified_tip(anchor.issuance.ledger_launcher_id,
        ledger_inner(anchor.issuance.bindings(),*evidence.holdings.state))
    assert ledger_tip.coin==evidence.holdings.current.coin
    coin=evidence.governance.current.coin
    read=make_spend(coin,puzzle_for_singleton(anchor.governance.sgt.governance_launcher_id,anchor.governance.inner()),
        solution_for_singleton(lineage_proof_for_coinsol(launches['governance']),uint64(1),
            inner_solution('READ',coin,[load_puzzle('generation_extension_v1.clsp'),b'VERSION'])))
    assert (await client.push_tx(SpendBundle([read],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    assert not await current_evidence_unchanged(evidence,provider=provider)
    current=await resolve_generation_chain(anchor,provider=provider)
    assert current.governance.current.coin!=coin
    assert current.governance.state.inner()==evidence.governance.state.inner()
    assert current.governance.verified_tip(anchor.governance.sgt.governance_launcher_id,
        current.governance.state.inner()).parent==read
    assert current.public_status(1235)['chainEvidence']['governance']['transitions']==1
    assert await current_evidence_unchanged(current,provider=provider)


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['network','missing','height','reveal','reorg'])
async def test_generation_index_rejects_incomplete_or_changed_chain(generation_chain,fault):
    _,client,_,anchor,_=generation_chain
    class Bad(Primary):
        def __init__(self,client):super().__init__(client);self.reads={}
        async def get_network_info_primary(self):return {'network_name':'mainnet' if fault=='network' else 'testnet11'}
        async def get_coin_record_by_name_primary(self,name):
            if fault=='missing':return None
            raw=deepcopy(await super().get_coin_record_by_name_primary(name))
            self.reads[name]=self.reads.get(name,0)+1
            if fault=='height' and not raw['spent_block_index']:raw['confirmed_block_index']+=1
            if fault=='reorg' and self.reads[name]>1:raw['confirmed_block_index']+=1
            return raw
        async def get_puzzle_and_solution_primary(self,name,height):
            raw=deepcopy(await super().get_puzzle_and_solution_primary(name,height))
            if fault=='reveal':raw['puzzle_reveal']=bytes(Program.to(1)).hex()
            return raw
    with pytest.raises(ValueError):await resolve_generation_chain(anchor,provider=Bad(client))


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['economic'],indirect=True)
async def test_reads_actual_economic_tips_and_detects_changed_state(generation_chain):
    _,_,provider,anchor,_=generation_chain
    e=await resolve_generation_chain(anchor,provider=provider)
    assert len(e.economic_components)==2 and len(e.current_records)==5
    assert len(e.public_status(123)['componentEvidence'])==2
    assert e.public_status(123)['exchangeFees']=={'totalBps':100,'protocolBps':70,'sgtRewardsBps':30,
        'authorityId':'0x'+anchor.economic_components[1].component_id.hex(),'revision':0}
    for state in anchor.economic_components:
        history=e.economic_components[state.component_id]
        assert history.state.inner()==state.inner()
        assert history.verified_tip(state.launcher_id,state.inner()).coin==history.current.coin
    from dataclasses import replace
    # A different initial treasury is valid source syntax, but cannot describe
    # this chain: its actual launcher creates the original frozen state.
    substituted=GenerationChainAnchor(anchor.issuance,anchor.registry,anchor.governance,
        (replace(anchor.economic_components[0],treasury_puzzle_hash=bytes32(b'X'*32)),))
    with pytest.raises(ValueError,match='frozen initial state'):
        await resolve_generation_chain(substituted,provider=provider)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['statutes'],indirect=True)
async def test_primary_verification_reads_are_parallel_bounded_and_still_detect_changed_evidence(generation_chain):
    _,client,_,anchor,_=generation_chain
    class Bounded(Primary):
        active=0;maximum=0;change=False
        async def get_coin_record_by_name_primary(self,name):
            self.active+=1;self.maximum=max(self.maximum,self.active)
            try:
                await asyncio.sleep(.001)
                value=await super().get_coin_record_by_name_primary(name)
                if self.change and value and not value['spent_block_index']:value['confirmed_block_index']+=1
                return value
            finally:self.active-=1
    provider=Bounded(client)
    e=await resolve_generation_chain(anchor,provider=provider)
    assert 2<=provider.maximum<=8 and provider.active==0
    assert await current_evidence_unchanged(e,provider=provider)
    provider.change=True
    assert not await current_evidence_unchanged(e,provider=provider)
