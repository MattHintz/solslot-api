"""Actual farmed genesis, administrator approval, SGT vote and grant execution.

All wallets are deterministic public test fixtures. No live chain or provider.
"""
import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import get_innerpuzzle_from_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    lineage_proof_for_coinsol, puzzle_for_singleton, solution_for_singleton,
)
from chia_rs import SpendBundle, G2Element
from chia_rs.sized_ints import uint64
from eth_keys import keys
from solslot_puzzles.admin_authority_v3_driver import (
    build_authority_operational_mips_spend, build_identity_operational_action,
    build_identity_operational_solution, build_operational_solution,
)
from solslot_puzzles.eip712_helpers import (
    build_eip712_member_solution, eip712_hash_to_sign,
    eip712_prefix_and_domain_separator, genesis_challenge_for_network,
)
from solslot_puzzles.mint_publish_driver import build_tracker_propose_coin_spend
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.protocol_statutes_driver import make_inner_puzzle, build_governance_evidence_spend
from solslot_puzzles.sgt_driver import (
    bill_sgt_grant, proposal_tracker_v2_inner_puzzle, sgt_free_inner_mod,
    sgt_locked_inner_mod, build_tracker_execute_coin_spend,
)
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from solslot_puzzles.sgt_reserve_driver import build_reserve_lock_coin_spend, build_reserve_execute_spends
from solslot_api.governance_publisher import _publication_delegated_puzzle
from tests.test_alpha_fresh_governance import live, parent_spend
from tests.test_alpha_fresh_lifecycle import B, CONSTANTS, fresh_genesis, launch_and_enroll, include


def tracker(world, bill=0, amount=0, deadline=0):
    p = world.plan.protocol
    return proposal_tracker_v2_inner_puzzle(singleton_struct(p.governance_launcher_id),
        sgt_free_inner_mod().get_tree_hash(), sgt_locked_inner_mod().get_tree_hash(), CAT_MOD_HASH,
        p.sgt_tail_hash, p.did_full_puzzle_hash, singleton_struct(p.pool_launcher_id),
        singleton_struct(p.admin_authority_launcher_id), singleton_struct(p.statutes_launcher_id),
        p.parameters.quorum_bps, p.parameters.voting_window_seconds, p.permanent_rules.sgt_total_supply,
        p.parameters.min_proposal_stake, p.kos_mint_execute_pubkey,
        bill.get_tree_hash() if bill else 0, bill, amount, deadline)


async def singleton_spend(client, coin, launcher, inner, solution):
    return make_spend(coin, puzzle_for_singleton(launcher, inner), solution_for_singleton(
        lineage_proof_for_coinsol(await parent_spend(client, coin)), uint64(coin.amount), solution))


async def cat_lineage(client, coin):
    parent = await parent_spend(client, coin)
    inner = get_innerpuzzle_from_puzzle(Program.from_bytes(bytes(parent.puzzle_reveal)))
    return LineageProof(parent.coin.parent_coin_info, inner.get_tree_hash(), parent.coin.amount)


async def approve(world, client, delegated):
    authority = world.plan.admin_authority_v3
    identities = authority.identity_vaults
    current = await live(client, world.plan.admin_authority.full_puzzle_hash)
    coins = [await live(client, identity.full_puzzle_hash) for identity in identities]
    mips = build_authority_operational_mips_spend(authority=authority,
        current_authority_inner_puzzle=authority.inner_puzzle, current_identities=identities,
        current_identity_coin_ids=tuple(coin.name() for coin in coins),
        authority_delegated_puzzle=delegated, coadmin_slot=1)
    solution = build_operational_solution(my_amount=int(current.amount), new_authority_version=2,
        mips_reveal=mips.reveal, mips_solution=mips.solution,
        authority_delegated_puzzle=delegated, identity_records=mips.identity_records)
    spends = [await singleton_spend(client, current, authority.authority_launcher_id, authority.inner_puzzle, solution)]
    for slot in mips.selected_slots:
        identity, coin = identities[slot], coins[slot]
        action = build_identity_operational_action(identity=identity,
            current_authority_inner_puzzle=authority.inner_puzzle, authority_delegated_puzzle=delegated)
        digest = eip712_hash_to_sign(eip712_prefix_and_domain_separator(
            genesis_challenge_for_network('testnet11')), coin.name(), action.get_tree_hash())
        signature = keys.PrivateKey(bytes([61 + slot]) * 32).sign_msg_hash(digest)
        member = build_eip712_member_solution(network='testnet11', coin_id=coin.name(),
            delegated_puzzle_hash=action.get_tree_hash(), compressed_pubkey=identity.daily_compressed_pubkey,
            signature=signature.r.to_bytes(32,'big') + signature.s.to_bytes(32,'big'))
        solution = build_identity_operational_solution(identity=identity,
            current_authority_inner_puzzle=authority.inner_puzzle, current_identity_coin_id=coin.name(),
            daily_member_solution=member, authority_delegated_puzzle=delegated)
        spends.append(await singleton_spend(client, coin, identity.launcher_id, identity.custody_reveal, solution))
    return spends


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_type', [1, 3], ids=['bls', 'evm'])
async def test_farmed_genesis_approved_vote_and_sgt_grant(auth_type):
    async with SpendSim.managed(None, defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim, client)
        owner = await launch_and_enroll(world, sim, client, auth_type)
        p = world.plan.protocol
        bill = bill_sgt_grant(grant_id=B(180), sgt_amount=100_000,
            recipient_vault_launcher_id=owner.launcher_id, reason_hash=B(181),
            reserve_owner_inner_puzzle_hash=p.sgt_reserve_inner_puzzle_hash)
        deadline = int(sim.timestamp) + p.parameters.voting_window_seconds
        current_tracker = await live(client, p.governance_full_puzzle_hash)
        reserve = await live(client, p.sgt_full_puzzle_hash)
        statutes = await live(client, p.statutes_full_puzzle_hash)
        inner = make_inner_puzzle(singleton_struct=singleton_struct(p.statutes_launcher_id),
            governance_singleton_struct=singleton_struct(p.governance_launcher_id),
            permanent_rules=p.permanent_rules, state=p.statutes_state)
        evidence = build_governance_evidence_spend(my_id=statutes.name(),
            my_inner_puzzle_hash=inner.get_tree_hash(), my_amount=int(statutes.amount), parameters=p.parameters)
        spends = await approve(world, client, _publication_delegated_puzzle(bill.get_tree_hash(), deadline))
        spends.append(await singleton_spend(client, statutes, p.statutes_launcher_id, inner, evidence.inner_solution))
        spends.append(build_tracker_propose_coin_spend(tracker_coin=current_tracker,
            tracker_inner_puzzle=tracker(world), tracker_launcher_id=p.governance_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(await parent_spend(client,current_tracker)),
            proposal_hash=bill.get_tree_hash(), bill_operation=bill,
            voter_inner_puzzle_hash=p.sgt_reserve_inner_puzzle_hash, first_vote_amount=int(reserve.amount),
            voting_deadline=deadline, proposal_evidence=Program.to([
                world.plan.admin_authority_v3.inner_puzzle.get_tree_hash(), inner.get_tree_hash(), list(p.parameters.as_tuple())])))
        spends.append(build_reserve_lock_coin_spend(reserve_coin=reserve,
            reserve_lineage_proof=await cat_lineage(client,reserve),
            proposal_tracker_struct=singleton_struct(p.governance_launcher_id),
            admin_authority_struct=singleton_struct(p.admin_authority_launcher_id),
            sgt_tail_hash=p.sgt_tail_hash, wusdc_b_asset_id=p.wusdc_b_asset_id,
            company_treasury_puzzle_hash=p.company_sgt_sale_treasury_puzzle_hash,
            bill=bill, deadline=deadline, admin_authority_inner_puzzle_hash=world.plan.admin_authority_v3.inner_puzzle.get_tree_hash()))
        publication = SpendBundle(spends,G2Element())
        await include(sim,client,publication)
        open_inner = tracker(world,bill,int(reserve.amount),deadline)
        open_coin = await live(client,puzzle_for_singleton(p.governance_launcher_id,open_inner).get_tree_hash())
        locked = next(coin for coin in publication.additions() if coin.parent_coin_info==reserve.name())
        sim.pass_time(uint64(p.parameters.voting_window_seconds + 1))
        await sim.farm_block()
        execution = [build_tracker_execute_coin_spend(tracker_coin=open_coin,tracker_inner_puzzle=open_inner,
            tracker_launcher_id=p.governance_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(await parent_spend(client,open_coin)))]
        execution.extend(build_reserve_execute_spends(locked_reserve_coin=locked,
            locked_reserve_lineage_proof=await cat_lineage(client,locked),
            proposal_tracker_struct=singleton_struct(p.governance_launcher_id),
            admin_authority_struct=singleton_struct(p.admin_authority_launcher_id),
            sgt_tail_hash=p.sgt_tail_hash,wusdc_b_asset_id=p.wusdc_b_asset_id,
            company_treasury_puzzle_hash=p.company_sgt_sale_treasury_puzzle_hash,
            bill=bill,voting_deadline=deadline,tracker_inner_puzzle_hash=open_inner.get_tree_hash()))
        await include(sim,client,SpendBundle(execution,G2Element()))
        assert (await live(client,p.sgt_full_puzzle_hash)).amount==900_000
        assert await live(client,p.governance_full_puzzle_hash)
