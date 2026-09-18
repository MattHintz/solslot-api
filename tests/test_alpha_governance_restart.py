"""Exercise the production publication builder against a freshly farmed chain."""
from types import SimpleNamespace

import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia_rs.sized_bytes import bytes32
from eth_keys import keys

from solslot_api import governance_publisher as publisher, governance_execution as execution
from chia_rs.sized_ints import uint64
from tests.test_alpha_fresh_lifecycle import launch_and_enroll
from tests.test_alpha_fresh_governance import live
from solslot_puzzles.artifact_schema_v4 import (
    build_public_artifact, INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
)
from solslot_puzzles.sgt_driver import bill_sgt_grant
from tests.test_alpha_fresh_lifecycle import B, CONSTANTS, fresh_genesis, include


from tests.test_alpha_governance_publisher import SimProvider


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_type", [1, 3], ids=["bls", "evm"])
@pytest.mark.parametrize("deadline_release", [False, True])
async def test_production_governance_can_resume_and_repeat(monkeypatch, auth_type, deadline_release):
    async with SpendSim.managed(None, defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim, client)
        owner = await launch_and_enroll(world, sim, client, auth_type)
        artifact = build_public_artifact(plan=world.plan,
            spend_bundle_id=world.built.spend_bundle.name(), confirmed_block_index=int(sim.block_height),
            review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS)

        async def evidence(_settings):
            return artifact, {}, None

        # Only the off-chain signed evidence and identity registry are fixtures.
        # All lineage, puzzle, statutes, signature and consensus checks run normally.
        monkeypatch.setattr(publisher, '_verified_evidence_context', evidence)
        monkeypatch.setattr(execution, '_verified_evidence_context', evidence)
        monkeypatch.setattr(publisher, '_current_identity_vaults',
            lambda **_: world.plan.admin_authority_v3.identity_vaults)
        for round_number in range(2):
            bill = bill_sgt_grant(grant_id=B(180 + round_number), sgt_amount=100_000,
                recipient_vault_launcher_id=owner.launcher_id, reason_hash=B(182),
                reserve_owner_inner_puzzle_hash=world.plan.protocol.sgt_reserve_inner_puzzle_hash)
            record = SimpleNamespace(state='READY', id='synthetic-publication', kind='SGT_GRANT',
                bill={'sgtAmount': 100_000}, bill_clvm_hex='0x'+bytes(bill).hex(),
                proposal_hash='0x'+bill.get_tree_hash().hex(), publication_coadmin_slot=1,
                publication_voting_deadline=int(sim.timestamp)+world.plan.protocol.parameters.voting_window_seconds)
            signatures = []
            arguments = dict(record=record, coadmin_slot=1,
                request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=SimProvider(client)))),
                settings=None, genesis_store=None,
                queue_store=SimpleNamespace(signatures=lambda _: signatures), actor='synthetic-test',
                now=int(sim.timestamp))
            unsigned = await publisher.build_governance_publication(**arguments)
            assert unsigned.bundle is None
            assert len(unsigned.actions) == 2
            for action in unsigned.actions:
                signature = keys.PrivateKey(bytes([61+action.signer_slot])*32).sign_msg_hash(
                    bytes.fromhex(action.message_hash.removeprefix('0x')))
                signatures.append(SimpleNamespace(action_id=action.action_id,
                    signature='0x'+(signature.r.to_bytes(32,'big')+signature.s.to_bytes(32,'big')).hex()))
            signed = await publisher.build_governance_publication(**arguments)
            assert signed.bundle is not None
            assert len(signed.bundle.coin_spends) == 6
            await include(sim, client, signed.bundle)
            proposal = await client.get_coin_record_by_name(bytes32.from_hexstr(signed.proposal_coin_id))
            assert proposal and not proposal.spent
            record.state = 'ACTIVE'
            record.proposal_coin_id = signed.proposal_coin_id
            # Reconstruct from a fresh provider/client after publication, then execute
            # from on-chain history instead of retaining builder state.
            request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=SimProvider(SimClient(sim)))))
            waiting = await execution.build_allocation_execution(record=record, request=request,
                settings=None, now=int(sim.timestamp))
            assert waiting.bundle is None and waiting.chain.state == 'VOTING'
            sim.pass_time(uint64(world.plan.protocol.parameters.voting_window_seconds + 1))
            await sim.farm_block()
            if deadline_release:
                from chia.types.blockchain_format.program import Program
                from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, unsigned_spend_bundle_for_spendable_cats, get_innerpuzzle_from_puzzle
                from solslot_puzzles.sgt_driver import sgt_locked_inner_puzzle, sgt_free_inner_mod
                from solslot_puzzles.protocol_deployment import singleton_struct
                from tests.test_alpha_governance_lifecycle import cat_lineage
                locked = next(coin for coin in signed.bundle.additions() if coin.parent_coin_info == signed.reserve_coin.name())
                locked_inner = sgt_locked_inner_puzzle(sgt_free_inner_mod().get_tree_hash(),
                    singleton_struct(world.plan.protocol.governance_launcher_id),
                    world.plan.protocol.sgt_reserve_inner_puzzle_hash, bill.get_tree_hash(), signed.deadline)
                release = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(
                    coin=locked, limitations_program_hash=world.plan.protocol.sgt_tail_hash,
                    inner_puzzle=locked_inner, inner_solution=Program.to([1, 0, locked.amount]),
                    lineage_proof=await cat_lineage(client, locked))])
                await include(sim, client, release)
            ready = await execution.build_allocation_execution(record=record, request=request,
                settings=None, now=int(sim.timestamp))
            assert ready.chain.state == 'AWAITING_EXECUTE' and ready.bundle is not None
            await include(sim, client, ready.bundle)
            done = await execution.build_allocation_execution(record=record, request=request,
                settings=None, now=int(sim.timestamp))
            assert done.chain.state == 'EXECUTED' and done.bundle is None
            assert (await live(client, world.plan.protocol.sgt_full_puzzle_hash)).amount == 1_000_000 - 100_000 * (round_number + 1)
