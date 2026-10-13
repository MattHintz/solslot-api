from copy import deepcopy
from dataclasses import replace

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol, lineage_proof_for_coinsol, puzzle_for_singleton, solution_for_singleton
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.generation_preparation import GenerationPreparation
from solslot_api.generation_recipient_evidence import verify_recipient_custody, issuance_plan_from_recipients
from solslot_api.generation_recipient_launch import build_recipient_launch
from solslot_puzzles.generation_sgt import build_initial_issuance, ledger_inner
from tests.test_generation_preparation import manifest, bind_custody, bind_identities, signatures, b32


class Primary:
    def __init__(self,client):self.client=client
    async def get_network_info_primary(self):return {'network_name':'testnet11'}
    async def get_coin_record_by_name_primary(self,name):
        record=await self.client.get_coin_record_by_name(bytes32.from_hexstr(name))
        return record.to_json_dict() if record else None
    async def get_puzzle_and_solution_primary(self,name,height):
        spend=await self.client.get_puzzle_and_solution(bytes32.from_hexstr(name),height)
        return spend.to_json_dict() if spend else None


@pytest_asyncio.fixture
async def prepared():
    async with SpendSim.managed(None,defaults=DEFAULT_CONSTANTS) as sim:
        client,acs=SimClient(sim),Program.to(1)
        for _ in range(6):await sim.farm_block(acs.get_tree_hash())
        origins=[r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        m,accounts=manifest();raw=m.model_dump(mode='json',by_alias=True)
        def reserve(coin):
            return {'fundingCoinId':'0x'+coin.name().hex(),
                'launcherId':'0x'+Coin(coin.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name().hex()}
        for i,k in enumerate(sorted(raw['coordinates'])):raw['coordinates'][k]=reserve(origins[i])
        offset=len(raw['coordinates'])
        for i,a in enumerate(raw['administrators']):a['custody']=reserve(origins[offset+i])
        raw['sgtFundingCoinId']='0x'+origins[offset+3].name().hex()
        bind_identities(raw);bind_custody(raw);m=GenerationPreparation.model_validate(raw)
        spends=[]
        for admin,origin in zip(m.administrators,origins[offset:offset+3]):
            conditions,launch=launch_conditions_and_coinsol(origin,m.custody_inner(admin),[],uint64(1))
            conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
            funding=make_spend(origin,acs,Program.to(conditions))
            operation=build_recipient_launch(m,admin.slot,funding,trusted_preparation_hash=m.manifest_hash)
            assert operation.spends==(funding,launch)
            spends.extend(operation.spends)
        assert (await client.push_tx(SpendBundle(spends,G2Element())))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        yield sim,client,Primary(client),m,signatures(m,accounts),origins


async def verify(p,provider=None):
    _,_,primary,m,sigs,_=p
    return await verify_recipient_custody(m,sigs,trusted_preparation_hash=m.manifest_hash,provider=provider or primary)


@pytest.mark.asyncio
async def test_three_native_confirmations_and_acknowledgements_bind_exact_genesis_outputs(prepared):
    sim,client,primary,m,sigs,origins=prepared
    evidence=await verify(prepared)
    assert evidence==await verify(prepared) # A read does not reserve/spend anything.
    plan=issuance_plan_from_recipients(m,evidence)
    issue=build_initial_issuance(plan)
    assert [c.amount for c in issue.coins]==[10000,10000,10000,970000]
    for recipient,output in zip(evidence.recipients,issue.outputs):
        assert recipient.owner_puzzle_hash==output.owner and recipient.confirmed_height>0
    li=ledger_inner(plan.bindings(),issue.holdings,0)
    ledger_origin=next(c for c in origins if '0x'+c.name().hex()==m.coordinates['holdings'].funding_coin_id)
    conditions,launch=launch_conditions_and_coinsol(ledger_origin,li,[],uint64(1))
    conditions.append(Program.to([51,Program.to(1).get_tree_hash(),int(ledger_origin.amount)-1]))
    ledger_coin=compute_additions(launch)[0]
    init=make_spend(ledger_coin,puzzle_for_singleton(plan.ledger_launcher_id,li),
        solution_for_singleton(lineage_proof_for_coinsol(launch),uint64(1),issue.ledger_initialization()))
    origin=next(c for c in origins if '0x'+c.name().hex()==m.sgt_funding_coin_id)
    funding=make_spend(origin,Program.to(1),Program.to([[51,issue.eve_coin.puzzle_hash,1_000_000],
        [51,Program.to(1).get_tree_hash(),int(origin.amount)-1_000_000]]))
    bundle=SpendBundle([funding,issue.eve_spend,make_spend(ledger_origin,Program.to(1),Program.to(conditions)),launch,init],G2Element())
    assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    for c in issue.coins:assert not (await client.get_coin_record_by_name(c.name())).spent
    assert issue.holdings.root.eligible==30000 and issue.holdings.root.total==1000000
    assert (await client.push_tx(bundle))[0]==MempoolInclusionStatus.FAILED
    raw=m.model_dump(mode='json',by_alias=True);raw['sourceCommits']['protocol']='34'*20
    with pytest.raises(ValueError,match='another frozen'):
        issuance_plan_from_recipients(GenerationPreparation.model_validate(raw),evidence)


@pytest.mark.asyncio
async def test_recipient_launch_cannot_redirect_change_reuse_another_slot_or_change_preparation(prepared):
    _,client,_,m,_,origins=prepared
    admin=m.administrators[0]
    origin=next(c for c in origins if '0x'+c.name().hex()==admin.custody.funding_coin_id)
    acs=Program.to(1)
    conditions,launcher=launch_conditions_and_coinsol(origin,m.custody_inner(admin),[],uint64(1))
    correct=conditions+[Program.to([51,acs.get_tree_hash(),int(origin.amount)-1])]
    spend=make_spend(origin,acs,Program.to(correct))
    operation=build_recipient_launch(m,1,spend,trusted_preparation_hash=m.manifest_hash)
    assert operation.successors[0].coin.name()==compute_additions(launcher)[0].name()
    for slot in (0,True,2,4):
        with pytest.raises(ValueError):build_recipient_launch(m,slot,spend,trusted_preparation_hash=m.manifest_hash)
    for altered in (
        conditions+[Program.to([51,bytes32(b'X'*32),int(origin.amount)-1])],
        conditions+[Program.to([51,acs.get_tree_hash(),int(origin.amount)-2])],
        [Program.to([51,acs.get_tree_hash(),int(origin.amount)])],
        correct+[Program.to([51,bytes32(b'X'*32),0])],
    ):
        with pytest.raises(ValueError):
            build_recipient_launch(m,1,make_spend(origin,acs,Program.to(altered)),trusted_preparation_hash=m.manifest_hash)
    raw=m.model_dump(mode='json',by_alias=True);raw['sourceCommits']['protocol']='34'*20
    with pytest.raises(ValueError,match='reviewed preparation'):
        build_recipient_launch(GenerationPreparation.model_validate(raw),1,spend,trusted_preparation_hash=m.manifest_hash)
    # Replaying a previously confirmed exact preparation cannot launch a
    # second vault or consume another parent.
    assert (await client.push_tx(operation.bundle()))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('attack',['mainnet','absent','unspent_launcher','spent_vault','wrong_spend','wrong_reveal','wrong_child','race','wrong_height'])
async def test_chain_evidence_rejects_unconfirmed_or_substituted_recipients(prepared,attack):
    _,client,_,m,_,_=prepared
    class Changed(Primary):
        seen={}
        async def get_network_info_primary(self):return {'network_name':'mainnet' if attack=='mainnet' else 'testnet11'}
        async def get_coin_record_by_name_primary(self,name):
            row=deepcopy(await super().get_coin_record_by_name_primary(name))
            if attack=='absent':return None
            is_launcher=row['coin']['puzzle_hash'].removeprefix('0x')==SINGLETON_LAUNCHER_HASH.hex()
            if attack=='unspent_launcher' and is_launcher:row.update(spent_block_index=0,spent=False)
            if attack=='spent_vault' and not is_launcher:row.update(spent_block_index=row['confirmed_block_index']+1,spent=True)
            if attack=='wrong_height' and not is_launcher:row['confirmed_block_index']+=1
            self.seen[name]=self.seen.get(name,0)+1
            if attack=='race' and self.seen[name]>1:row['confirmed_block_index']+=1
            return row
        async def get_puzzle_and_solution_primary(self,name,height):
            row=deepcopy(await super().get_puzzle_and_solution_primary(name,height))
            if attack=='wrong_spend':row['coin']['parent_coin_info']=b32(99)
            if attack=='wrong_reveal':row['puzzle_reveal']=bytes(Program.to(1)).hex()
            if attack=='wrong_child':row['solution']=bytes(Program.to([bytes32.from_hexstr(b32(99)),1,[]])).hex()
            return row
    with pytest.raises(ValueError):await verify(prepared,Changed(client))


@pytest.mark.asyncio
async def test_old_signatures_or_unreviewed_manifest_fail_before_node_reads(prepared):
    _,_,primary,m,sigs,_=prepared
    class NeverRead:
        async def get_network_info_primary(self):raise AssertionError('unreviewed preparation reached node')
    with pytest.raises(ValueError,match='locally frozen'):
        await verify_recipient_custody(m,sigs,trusted_preparation_hash=b32(99),provider=NeverRead())
    wrong=dict(sigs);wrong[1]=sigs[2]
    with pytest.raises(ValueError,match='acknowledgement'):
        await verify_recipient_custody(m,wrong,trusted_preparation_hash=m.manifest_hash,provider=NeverRead())
