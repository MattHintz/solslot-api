"""SGT custody and expired approvals, without relaxing purchase credentials."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from eth_keys import keys

from solslot_api import sgt_vault_eligibility as eligibility
from solslot_api import governance_endpoints as endpoints
from solslot_api.governance_queue import GovernanceQueueStore, GovernanceQueueConflict
from solslot_puzzles.vault_driver import DEFAULT_IDENTITY_ATTEST_ROOT, puzzle_hash_for_p2_vault
from solslot_api.vault_launcher import build_and_sign_launch
from tests.test_alpha_fresh_lifecycle import CONSTANTS, fresh_genesis, include
from tests.test_alpha_governance_publisher import SimProvider


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_type', [1, 3])
async def test_confirmed_unstamped_sgt_vault_uses_real_lineage_and_owner(monkeypatch, auth_type):
    async with SpendSim.managed(None, defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim, client)
        owner = AugSchemeMPL.key_gen(b'o' * 32)
        evm = keys.PrivateKey(b'e' * 32)
        public_key = bytes(owner.get_g1()) if auth_type == 1 else evm.public_key.to_compressed_bytes()
        launch = build_and_sign_launch(faucet=world.faucet,
            faucet_coin_json=world.origins[0].to_json_dict(), owner_pubkey=public_key,
            auth_type=auth_type, pool_launcher_id=world.plan.protocol.pool_launcher_id,
            zkpassport_bridge_policy_hash=world.plan.bridge_batch.policy_hash)
        vault = next(c for c in launch.spend_bundle.additions() if c.parent_coin_info == launch.vault_launcher_id)
        record = SimpleNamespace(launcher_id=launch.vault_launcher_id, owner_pubkey=public_key,
            auth_type=auth_type, full_puzhash=vault.puzzle_hash,
            p2_vault_puzhash=puzzle_hash_for_p2_vault(launch.vault_launcher_id))
        monkeypatch.setattr(eligibility, 'require_vault_record', lambda _: record)
        monkeypatch.setattr(eligibility, '_active_pool_launcher_id', lambda _: '0x' + world.plan.protocol.pool_launcher_id.hex())
        monkeypatch.setattr(eligibility, '_active_bridge_policy_hash', lambda _: '0x' + world.plan.bridge_batch.policy_hash.hex())
        def no_id(*_, **__):
            raise AssertionError('An unstamped SGT vault must not require a purchase credential')
        monkeypatch.setattr(eligibility, 'require_current_approved_vault', no_id)
        provider = SimProvider(client)
        with pytest.raises(HTTPException, match='confirmed, registered'):
            await eligibility.require_current_sgt_vault(None, '0x' + launch.vault_launcher_id.hex(), provider)
        await include(sim, client, launch.spend_bundle)
        verified = await eligibility.require_current_sgt_vault(None, '0x' + launch.vault_launcher_id.hex(), provider)
        assert verified.current_coin_id == '0x' + vault.name().hex()
        assert verified.identity_attest_root == '0x' + DEFAULT_IDENTITY_ATTEST_ROOT.hex()
        assert verified.confirmed_block_index > 0
        record.owner_pubkey = bytes(AugSchemeMPL.key_gen(b'x' * 32).get_g1()) if auth_type == 1 else keys.PrivateKey(b'x' * 32).public_key.to_compressed_bytes()
        with pytest.raises(HTTPException, match='active release and owner'):
            await eligibility.require_current_sgt_vault(None, verified.launcher_id, provider)


@pytest.mark.asyncio
async def test_grant_draft_can_use_confirmed_custody_but_sale_still_requires_id(monkeypatch, tmp_path):
    launcher = '0x' + '11' * 32
    confirmed = SimpleNamespace(launcher_id=launcher, p2_puzzle_hash='0x' + puzzle_hash_for_p2_vault(bytes32.from_hexstr(launcher)).hex(),
        identity_attest_root='0x' + DEFAULT_IDENTITY_ATTEST_ROOT.hex())
    async def sgt_only(*_):
        return confirmed
    monkeypatch.setattr(endpoints, 'require_current_sgt_vault', sgt_only)
    monkeypatch.setattr(endpoints, 'require_sgt_allocation_drafts', lambda _: None)
    monkeypatch.setattr(endpoints, '_reserve_owner', lambda _: bytes32.fromhex('22' * 32))
    def reject_id(*_):
        raise HTTPException(409, 'Purchase credential required')
    monkeypatch.setattr(endpoints, 'require_current_approved_vault', reject_id)
    body = endpoints.CreateGovernanceProposal(kind='SGT_GRANT', title='Synthetic unstamped grant', sgtAmount='10000',
        recipientVaultLauncherId=launcher, grantId='0x' + '33' * 32, reasonHash='0x' + '44' * 32)
    store = GovernanceQueueStore(str(tmp_path / 'queue.db'))
    value = await endpoints.create_proposal(body, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=None))),
        Response(), SimpleNamespace(sub='synthetic-owner'), None, store)
    assert value['bill']['recipientVaultLauncherId'] == launcher
    assert value['bill']['sgtAmount'] == '10000'
    assert value['state'] == 'DRAFT'
    sale = endpoints.CreateGovernanceProposal(kind='SGT_SALE', title='Synthetic sale', sgtAmount='10000',
        recipientVaultLauncherId=launcher, saleId='0x' + '55' * 32, paymentRail='XCH', paymentAmount='100', expiresAt=2_000_000_000)
    with pytest.raises(HTTPException, match='Purchase credential required'):
        endpoints._recipient_vault(sale, None)


def ready_expired(store):
    record = store.create(kind='SGT_GRANT', title='Synthetic grant', bill={'sgtAmount':'10000'},
        bill_clvm_hex='80', proposal_hash='0x' + '11' * 32, actor='owner', now=100)
    record = store.transition(proposal_id=record.id, expected_revision=record.revision, target='READY', actor='reviewer', now=101)
    return store.bind_publication_coadmin(proposal_id=record.id, coadmin_slot=1, voting_deadline=200, actor='owner', now=102)


def test_restart_retains_grant_and_signatures_and_rejects_stale_or_live_packages(tmp_path):
    store = GovernanceQueueStore(str(tmp_path / 'queue.db'))
    record = ready_expired(store)
    store.add_signature(proposal_id=record.id, action_id='old-action', signer_slot=0, signer_public_key='public',
        message_hash='digest', signature='synthetic-signature', actor='owner', now=110)
    args = dict(proposal_id=record.id, expected_deadline=200, coadmin_slot=1, voting_deadline=500, actor='owner')
    with pytest.raises(GovernanceQueueConflict, match='not expired'):
        store.renew_expired_publication(**args, now=199)
    renewed = store.renew_expired_publication(**args, now=201)
    assert renewed.id == record.id and renewed.bill == record.bill and renewed.proposal_hash == record.proposal_hash
    assert renewed.revision == record.revision + 1 and renewed.state == 'READY'
    assert renewed.publication_voting_deadline == 500
    assert len(store.signatures(record.id)) == 1
    with pytest.raises(GovernanceQueueConflict, match='publication changed'):
        store.renew_expired_publication(**args, now=202)
    active = store.transition(proposal_id=record.id, expected_revision=renewed.revision, target='ACTIVE',
        actor='owner', activation_bundle_id='submitted', proposal_coin_id='coin', now=203)
    with pytest.raises(GovernanceQueueConflict, match='unsubmitted'):
        store.renew_expired_publication(**{**args, 'expected_deadline':500, 'voting_deadline':900}, now=501)
    assert store.get(active.id).activation_bundle_id == 'submitted'


@pytest.mark.asyncio
async def test_restart_is_owner_only_before_any_builder_or_ledger_mutation(tmp_path):
    store = GovernanceQueueStore(str(tmp_path / 'queue.db'))
    record = ready_expired(store)
    with pytest.raises(ValueError, match='only the owner'):
        await endpoints._publication_build(proposal_id=record.id, coadmin_slot=1, request=None,
            settings=None, genesis_store=None, queue_store=store,
            actor=SimpleNamespace(authority_slot=1, wallet='coadministrator'), renew_expired=True)
    assert store.get(record.id).publication_voting_deadline == 200


@pytest.mark.asyncio
async def test_status_read_cannot_start_a_publication_window(monkeypatch, tmp_path):
    store = GovernanceQueueStore(str(tmp_path / 'queue.db'))
    record = store.create(kind='SGT_GRANT', title='Synthetic grant', bill={'sgtAmount':'10000'},
        bill_clvm_hex='80', proposal_hash='0x' + '11' * 32, actor='owner', now=100)
    store.transition(proposal_id=record.id, expected_revision=record.revision, target='READY', actor='reviewer', now=101)
    monkeypatch.setattr(endpoints, 'require_sgt_allocation_drafts', lambda _: None)
    with pytest.raises(HTTPException, match='prepare approvals'):
        await endpoints.publication_status(record.id, None, None, None, store,
            SimpleNamespace(authority_slot=0, wallet='owner'))
    assert store.get(record.id).publication_voting_deadline is None
    assert not store.signatures(record.id)
