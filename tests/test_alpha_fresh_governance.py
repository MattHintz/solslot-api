"""Fresh canonical genesis must fund executable governance, not just outputs."""
import pytest
from chia._tests.util.spend_sim import SpendSim,SimClient
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH,get_innerpuzzle_from_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import bill_sgt_grant,proposal_tracker_v2_inner_puzzle,sgt_free_inner_mod,sgt_locked_inner_mod
from solslot_puzzles.sgt_reserve_driver import build_reserve_lock_coin_spend
from solslot_puzzles.mint_publish_driver import build_tracker_propose_coin_spend
from tests.test_alpha_fresh_lifecycle import B,CONSTANTS,fresh_genesis,launch_and_enroll

async def live(client,puzzle_hash):
    records=await client.get_coin_records_by_puzzle_hash(puzzle_hash,include_spent_coins=False)
    assert len(records)==1
    return records[0].coin

async def parent_spend(client,coin):
    parent=await client.get_coin_record_by_name(coin.parent_coin_info)
    assert parent and parent.spent
    return await client.get_puzzle_and_solution(parent.coin.name(),parent.spent_block_index)

@pytest.mark.asyncio
@pytest.mark.parametrize('surface',['reserve','tracker'])
async def test_fresh_governance_first_vote_builders_are_executable(surface):
    async with SpendSim.managed(None,defaults=CONSTANTS) as sim:
        client=SimClient(sim);world=await fresh_genesis(sim,client)
        owner=await launch_and_enroll(world,sim,client,1)
        p=world.plan.protocol
        bill=bill_sgt_grant(grant_id=B(180),sgt_amount=600000,recipient_vault_launcher_id=owner.launcher_id,
            reason_hash=B(181),reserve_owner_inner_puzzle_hash=p.sgt_reserve_inner_puzzle_hash)
        deadline=int(sim.timestamp)+p.parameters.voting_window_seconds
        if surface=='reserve':
            coin=await live(client,p.sgt_full_puzzle_hash)
            parent=await parent_spend(client,coin)
            parent_puzzle=Program.from_bytes(bytes(parent.puzzle_reveal));module,_=parent_puzzle.uncurry()
            lineage=(LineageProof(parent.coin.parent_coin_info,get_innerpuzzle_from_puzzle(parent_puzzle).get_tree_hash(),parent.coin.amount)
                if module.get_tree_hash()==CAT_MOD_HASH else LineageProof())
            spend=build_reserve_lock_coin_spend(reserve_coin=coin,reserve_lineage_proof=lineage,
                proposal_tracker_struct=singleton_struct(p.governance_launcher_id),admin_authority_struct=singleton_struct(p.admin_authority_launcher_id),
                sgt_tail_hash=p.sgt_tail_hash,wusdc_b_asset_id=p.wusdc_b_asset_id,
                company_treasury_puzzle_hash=p.company_sgt_sale_treasury_puzzle_hash,bill=bill,deadline=deadline,
                admin_authority_inner_puzzle_hash=world.plan.admin_authority_v3.inner_puzzle.get_tree_hash())
        else:
            inner=proposal_tracker_v2_inner_puzzle(singleton_struct(p.governance_launcher_id),sgt_free_inner_mod().get_tree_hash(),
                sgt_locked_inner_mod().get_tree_hash(),CAT_MOD_HASH,p.sgt_tail_hash,p.did_full_puzzle_hash,
                singleton_struct(p.pool_launcher_id),singleton_struct(p.admin_authority_launcher_id),singleton_struct(p.statutes_launcher_id),
                p.parameters.quorum_bps,p.parameters.voting_window_seconds,p.permanent_rules.sgt_total_supply,p.parameters.min_proposal_stake,p.kos_mint_execute_pubkey)
            assert inner.get_tree_hash()==p.governance_inner_puzzle_hash
            coin=await live(client,p.governance_full_puzzle_hash)
            spend=build_tracker_propose_coin_spend(tracker_coin=coin,tracker_inner_puzzle=inner,tracker_launcher_id=p.governance_launcher_id,
                lineage_proof=lineage_proof_for_coinsol(await parent_spend(client,coin)),proposal_hash=bill.get_tree_hash(),
                bill_operation=bill,voter_inner_puzzle_hash=p.sgt_reserve_inner_puzzle_hash,first_vote_amount=p.permanent_rules.sgt_total_supply,voting_deadline=deadline,
                proposal_evidence=Program.to([world.plan.admin_authority_v3.inner_puzzle.get_tree_hash(),
                    p.statutes_inner_puzzle_hash,list(p.parameters.as_tuple())]))
        conditions=conditions_dict_for_solution(Program.from_bytes(bytes(spend.puzzle_reveal)),Program.from_bytes(bytes(spend.solution)),11_000_000_000)
        assert conditions


@pytest.mark.asyncio
async def test_every_selected_genesis_singleton_uses_its_planned_full_puzzle():
    async with SpendSim.managed(None,defaults=CONSTANTS) as sim:
        client=SimClient(sim);world=await fresh_genesis(sim,client);p=world.plan.protocol
        from solslot_puzzles.genesis_ceremony import SingletonSurface
        expected=[SingletonSurface(p.pool_launcher_id,p.pool_inner_puzzle_hash,p.pool_full_puzzle_hash),
            SingletonSurface(p.did_launcher_id,p.did_inner_puzzle_hash,p.did_full_puzzle_hash),
            SingletonSurface(p.governance_launcher_id,p.governance_inner_puzzle_hash,p.governance_full_puzzle_hash),
            world.plan.statutes,world.plan.protocol_config,world.plan.vault_version_registry,world.plan.property_registry,
            world.plan.admin_authority,*world.plan.admin_authority_v3.identity_vaults]
        for surface in expected:
            coin=await live(client,surface.full_puzzle_hash)
            assert coin.parent_coin_info==surface.launcher_id
            assert (await client.get_coin_record_by_name(surface.launcher_id)).spent
        from solslot_api.genesis_worker import _expected_outputs
        from chia_rs.sized_bytes import bytes32
        outputs = _expected_outputs(world.plan)
        assert len(outputs) == len(set(outputs)) == 45
        records = [await client.get_coin_record_by_name(bytes32.fromhex(value[2:])) for value in outputs]
        assert all(record and not record.spent for record in records)
        assert len({record.confirmed_block_index for record in records}) == 1
        # The seeded Sols anchor must be discoverable by the production swap
        # loader using the actual reserve reveal, not a hash-as-CLVM-atom.
        from solslot_api.sols_swaps import _load_reserve_cat, _confirmed_coin_and_lineage
        from solslot_puzzles.artifact_schema_v4 import build_public_artifact
        from solslot_puzzles.sols_swap_v4_driver import _pool_lineage
        from tests.test_alpha_governance_publisher import SimProvider
        artifact = build_public_artifact(plan=world.plan,
            spend_bundle_id=world.built.spend_bundle.name(),confirmed_block_index=int(sim.block_height))
        provider = SimProvider(client)
        reserve, lineage = await _load_reserve_cat(provider=provider,artifact=artifact,
            config=p.pool_config,pool_state=p.pool_state,reserve_inner_puzzle=world.faucet.key.puzzle)
        assert reserve.name() == p.sols_reserve_seed_coin_id and reserve.amount == 1
        assert lineage.parent_name is None
        pool = await live(client,p.pool_full_puzzle_hash)
        confirmed, proof = await _confirmed_coin_and_lineage(provider,'0x'+pool.name().hex(),'fresh pool')
        assert proof.inner_puzzle_hash is None
        _pool_lineage(proof,confirmed,p.pool_launcher_id)
