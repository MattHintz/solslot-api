"""Exercise the production publication builder against a freshly farmed chain."""
from types import SimpleNamespace

import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api import governance_publisher as publisher
from solslot_api.governance_queue import GovernanceQueueStore
from solslot_puzzles.artifact_schema_v4 import (
    build_public_artifact, INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
)
from solslot_puzzles.sgt_driver import bill_sgt_grant
from tests.test_alpha_fresh_lifecycle import B, CONSTANTS, fresh_genesis, include


class SimProvider:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def name(value):
        return bytes32.from_hexstr(value)

    async def get_coin_record_by_name(self, name):
        record = await self.client.get_coin_record_by_name(self.name(name))
        return record.to_json_dict() if record else None

    async def get_coin_records_by_parent_ids(self, names, *, include_spent):
        records = await self.client.get_coin_records_by_parent_ids(
            [self.name(name) for name in names], include_spent_coins=include_spent)
        return [record.to_json_dict() for record in records]

    async def get_coin_records_by_puzzle_hash(self, name, *, include_spent):
        records = await self.client.get_coin_records_by_puzzle_hash(
            self.name(name), include_spent_coins=include_spent)
        return [record.to_json_dict() for record in records]

    async def get_puzzle_and_solution(self, name, height):
        return (await self.client.get_puzzle_and_solution(self.name(name), height)).to_json_dict()


@pytest.mark.asyncio
@pytest.mark.parametrize("renewal", [False, True])
async def test_production_publisher_spends_fresh_issuance_and_statutes(monkeypatch, renewal, tmp_path):
    async with SpendSim.managed(None, defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim, client)
        artifact = build_public_artifact(plan=world.plan,
            spend_bundle_id=world.built.spend_bundle.name(), confirmed_block_index=int(sim.block_height),
            review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS)

        async def evidence(_settings):
            return artifact, {}, None

        # Only the off-chain signed evidence and identity registry are fixtures.
        # All lineage, puzzle, statutes, signature and consensus checks run normally.
        monkeypatch.setattr(publisher, '_verified_evidence_context', evidence)
        monkeypatch.setattr(publisher, '_current_identity_vaults',
            lambda **_: world.plan.admin_authority_v3.identity_vaults)
        bill = bill_sgt_grant(grant_id=B(180), sgt_amount=100_000,
            recipient_vault_launcher_id=B(181), reason_hash=B(182),
            reserve_owner_inner_puzzle_hash=world.plan.protocol.sgt_reserve_inner_puzzle_hash)
        store = GovernanceQueueStore(str(tmp_path / 'queue.db'))
        record = store.create(kind='SGT_GRANT', title='Synthetic native grant', bill={'sgtAmount':100_000},
            bill_clvm_hex='0x'+bytes(bill).hex(), proposal_hash='0x'+bill.get_tree_hash().hex(), actor='owner', now=int(sim.timestamp))
        record = store.transition(proposal_id=record.id, expected_revision=record.revision, target='READY', actor='reviewer', now=int(sim.timestamp))
        if renewal:
            record = store.bind_publication_coadmin(proposal_id=record.id, coadmin_slot=1,
                voting_deadline=int(sim.timestamp)+300, actor='owner', now=int(sim.timestamp))
        arguments = dict(record=record, coadmin_slot=1,
            request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=SimProvider(client)))),
            settings=None, genesis_store=None, queue_store=store, actor='owner', now=int(sim.timestamp))
        unsigned = await publisher.build_governance_publication(**arguments)
        assert unsigned.bundle is None
        assert len(unsigned.actions) == 2
        arguments['record'] = unsigned.record
        for action in unsigned.actions:
            signature = keys.PrivateKey(bytes([61+action.signer_slot])*32).sign_msg_hash(
                bytes.fromhex(action.message_hash.removeprefix('0x')))
            store.add_signature(proposal_id=record.id, action_id=action.action_id, signer_slot=action.signer_slot,
                signer_public_key=action.signer_public_key, message_hash=action.message_hash,
                signature='0x'+(signature.r.to_bytes(32,'big')+signature.s.to_bytes(32,'big')).hex(), actor='owner')
        if renewal:
            old_actions = unsigned.actions
            arguments['now'] = record.publication_voting_deadline + 1
            with pytest.raises(ValueError, match='deadline has expired'):
                await publisher.build_governance_publication(**arguments)
            renewed = await publisher.build_governance_publication(**arguments, renew_expired=True)
            arguments['record'] = renewed.record
            assert renewed.approval_expires_at == arguments['now'] + 86400
            assert renewed.record.publication_voting_deadline is None
            assert renewed.bundle is None
            assert {action.action_id for action in old_actions}.isdisjoint(action.action_id for action in renewed.actions)
            assert {action.message_hash for action in old_actions}.isdisjoint(action.message_hash for action in renewed.actions)
            for action in renewed.actions:
                sig = keys.PrivateKey(bytes([61+action.signer_slot])*32).sign_msg_hash(bytes.fromhex(action.message_hash[2:]))
                store.add_signature(proposal_id=record.id, action_id=action.action_id, signer_slot=action.signer_slot,
                    signer_public_key=action.signer_public_key, message_hash=action.message_hash,
                    signature='0x'+(sig.r.to_bytes(32,'big')+sig.s.to_bytes(32,'big')).hex(), actor='owner')
            sim.pass_time(uint64(arguments['now'] - int(sim.timestamp)))
            await sim.farm_block()
        # Waiting an hour for the second administrator cannot consume the vote.
        before_wait = await publisher.build_governance_publication(**arguments)
        arguments['now'] += 3600
        sim.pass_time(uint64(arguments['now'] - int(sim.timestamp)))
        await sim.farm_block()
        signed = await publisher.build_governance_publication(**arguments)
        assert signed.actions == before_wait.actions
        assert signed.deadline == arguments['now'] + world.plan.protocol.parameters.voting_window_seconds
        assert signed.record.publication_voting_deadline is None
        assert signed.approval_expires_at > signed.deadline
        assert signed.bundle is not None
        assert len(signed.bundle.coin_spends) == 6
        await include(sim, client, signed.bundle)
        proposal = await client.get_coin_record_by_name(bytes32.from_hexstr(signed.proposal_coin_id))
        assert proposal and not proposal.spent
