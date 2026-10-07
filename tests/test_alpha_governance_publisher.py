"""Exercise the production publication builder against a freshly farmed chain."""
from types import SimpleNamespace

import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api import governance_publisher as publisher
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
async def test_production_publisher_spends_fresh_issuance_and_statutes(monkeypatch, renewal):
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
        record = SimpleNamespace(state='READY', id='synthetic-publication', kind='SGT_GRANT',
            bill={'sgtAmount': 100_000}, bill_clvm_hex='0x'+bytes(bill).hex(),
            proposal_hash='0x'+bill.get_tree_hash().hex(), publication_coadmin_slot=1,
            publication_voting_deadline=int(sim.timestamp)+world.plan.protocol.parameters.voting_window_seconds)
        signatures = []
        def renew(**kwargs):
            assert kwargs['expected_deadline'] == record.publication_voting_deadline
            record.publication_voting_deadline = kwargs['voting_deadline']
            return record
        arguments = dict(record=record, coadmin_slot=1,
            request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=SimProvider(client)))),
            settings=None, genesis_store=None,
            queue_store=SimpleNamespace(signatures=lambda _: signatures, renew_expired_publication=renew), actor='synthetic-test',
            now=int(sim.timestamp))
        unsigned = await publisher.build_governance_publication(**arguments)
        assert unsigned.bundle is None
        assert len(unsigned.actions) == 2
        for action in unsigned.actions:
            signature = keys.PrivateKey(bytes([61+action.signer_slot])*32).sign_msg_hash(
                bytes.fromhex(action.message_hash.removeprefix('0x')))
            signatures.append(SimpleNamespace(action_id=action.action_id,
                signature='0x'+(signature.r.to_bytes(32,'big')+signature.s.to_bytes(32,'big')).hex()))
        if renewal:
            old_actions = unsigned.actions
            arguments['now'] = record.publication_voting_deadline + 1
            with pytest.raises(ValueError, match='deadline has expired'):
                await publisher.build_governance_publication(**arguments)
            renewed = await publisher.build_governance_publication(**arguments, renew_expired=True)
            assert renewed.bundle is None
            assert {action.action_id for action in old_actions}.isdisjoint(action.action_id for action in renewed.actions)
            assert {action.message_hash for action in old_actions}.isdisjoint(action.message_hash for action in renewed.actions)
            for action in renewed.actions:
                sig = keys.PrivateKey(bytes([61+action.signer_slot])*32).sign_msg_hash(bytes.fromhex(action.message_hash[2:]))
                signatures.append(SimpleNamespace(action_id=action.action_id,
                    signature='0x'+(sig.r.to_bytes(32,'big')+sig.s.to_bytes(32,'big')).hex()))
            sim.pass_time(uint64(arguments['now'] - int(sim.timestamp)))
            await sim.farm_block()
        signed = await publisher.build_governance_publication(**arguments)
        assert signed.bundle is not None
        assert len(signed.bundle.coin_spends) == 6
        await include(sim, client, signed.bundle)
        proposal = await client.get_coin_record_by_name(bytes32.from_hexstr(signed.proposal_coin_id))
        assert proposal and not proposal.spent
