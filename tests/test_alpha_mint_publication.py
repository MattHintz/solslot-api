"""Actual consensus: farmed genesis, enrollment, reserve grant, vault-funded MINT.

Only signed release metadata and off-chain enrollment records are fixtures.
Coins, lineage, signatures, puzzle execution and inclusion are real SpendSim.
"""
from types import SimpleNamespace

import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api import governance_publisher as publisher, governance_execution as execution
from solslot_api import mint_publication as mint, mint_stake, mint_endpoints
from solslot_api.mint_chain_validation import validate_publish_bundle
from solslot_api.mint_publish_validation import PublishProposalMetadata
from solslot_puzzles.eip712_helpers import compute_eip712_member_leaf_hash, eip712_prefix_and_domain_separator, eip712_type_hash, genesis_challenge_for_network
from tests.test_alpha_fresh_governance import live
from solslot_puzzles import load_puzzle, mint_proposal_v2_driver as proposal_driver
from solslot_puzzles.artifact_schema_v4 import build_public_artifact, INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS
from solslot_puzzles.mint_publish_driver import build_mint_publish_artifacts, build_proposal_eve_launch_spend, build_tracker_propose_coin_spend, deed_launcher_puzzle_hash
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import bill_sgt_grant
from solslot_puzzles.vault_v2_driver import signing_digest_for_sgt_lock
from tests.test_alpha_fresh_lifecycle import B, HX, CONSTANTS, fresh_genesis, launch_and_enroll, include, sign_spends
from tests.test_alpha_governance_publisher import SimProvider


class Provider(SimProvider):
    async def get_mempool_items_by_coin_name(self, _name):
        return []

    async def push_tx(self, raw):
        status, error = await self.client.push_tx(SpendBundle.from_json_dict(raw))
        return {'success': status is MempoolInclusionStatus.SUCCESS, 'status': str(status), 'error': str(error)}


async def grant_stake(world, sim, client, provider, owner, coadmin_slot, amount):
    bill = bill_sgt_grant(grant_id=B(180), sgt_amount=amount,
        recipient_vault_launcher_id=owner.launcher_id, reason_hash=B(182),
        reserve_owner_inner_puzzle_hash=world.plan.protocol.sgt_reserve_inner_puzzle_hash)
    record = SimpleNamespace(state='READY', id='synthetic-mint-starter', kind='SGT_GRANT',
        bill={'sgtAmount': amount}, bill_clvm_hex=HX(bytes(bill)), proposal_hash=HX(bill.get_tree_hash()),
        publication_coadmin_slot=coadmin_slot,
        publication_voting_deadline=int(sim.timestamp)+world.plan.protocol.parameters.voting_window_seconds)
    signatures = []
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=provider)))
    args = dict(record=record, coadmin_slot=coadmin_slot, request=request, settings=None,
        genesis_store=None, queue_store=SimpleNamespace(signatures=lambda _: signatures),
        actor='synthetic-test', now=int(sim.timestamp))
    unsigned = await publisher.build_governance_publication(**args)
    for action in unsigned.actions:
        signature = keys.PrivateKey(bytes([61+action.signer_slot])*32).sign_msg_hash(bytes.fromhex(action.message_hash[2:]))
        signatures.append(SimpleNamespace(action_id=action.action_id,
            signature=HX(signature.r.to_bytes(32,'big')+signature.s.to_bytes(32,'big'))))
    signed = await publisher.build_governance_publication(**args)
    await include(sim, client, signed.bundle)
    record.state, record.proposal_coin_id = 'ACTIVE', signed.proposal_coin_id
    sim.pass_time(uint64(world.plan.protocol.parameters.voting_window_seconds + 1))
    await sim.farm_block()
    ready = await execution.build_allocation_execution(record=record, request=request,
        settings=None, now=int(sim.timestamp))
    await include(sim, client, ready.bundle)


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_type', [1, 3], ids=['bls', 'evm'])
@pytest.mark.parametrize('coadmin_slot', [1, 2])
@pytest.mark.parametrize('inventory', [False, True], ids=['historical-deed', 'inventory-v2'])
async def test_fresh_grant_to_vault_then_owner_plus_one_mint(monkeypatch, tmp_path, auth_type, coadmin_slot, inventory):
    async with SpendSim.managed(None, defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim, client)
        owner = await launch_and_enroll(world, sim, client, auth_type)
        artifact = build_public_artifact(plan=world.plan, spend_bundle_id=world.built.spend_bundle.name(),
            confirmed_block_index=int(sim.block_height), review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS)
        if inventory:
            artifact['inventoryActivation'] = dict(schema='solslot.inventory-activation.v1',
                network='testnet11', environment='production-alpha',
                deploymentId=artifact['ceremony']['ceremonyId'], inventoryVersion=2, adapterVersion=1,
                sourceShas=artifact['sourceShas'], reviewEvidenceSha256='ab'*32,
                availableModuleHash=HX(load_puzzle('mint_offer_inventory_available_v2.clsp').get_tree_hash()),
                reservedModuleHash=HX(load_puzzle('mint_offer_delegate_v5.clsp').get_tree_hash()))
        async def evidence(_settings):
            return artifact, {}, None
        for module in (publisher, execution, mint):
            monkeypatch.setattr(module, '_verified_evidence_context', evidence)
        for module in (publisher, mint):
            monkeypatch.setattr(module, '_current_identity_vaults', lambda **_: world.plan.admin_authority_v3.identity_vaults)
        provider = Provider(client)
        fresh = await mint.load_mint_publication_context(provider=provider, settings=None, genesis_store=None)
        assert 'innerPuzzleHash' not in fresh.to_wire(deadline=int(sim.timestamp)+600)['lineageProof']
        amount = world.plan.protocol.parameters.min_proposal_stake
        await grant_stake(world, sim, client, provider, owner, coadmin_slot, amount)
        context = await mint.load_mint_publication_context(provider=Provider(SimClient(sim)), settings=None, genesis_store=None)
        assert context.commitment != fresh.commitment
        assert 'innerPuzzleHash' in context.to_wire(deadline=int(sim.timestamp)+600)['lineageProof']
        monkeypatch.setattr(mint_stake, 'require_current_approved_vault', lambda *_: SimpleNamespace(
            launcher_id=HX(owner.launcher_id), current_coin_id=HX(owner.vault.name()), identity_attest_root=HX(owner.root)))
        monkeypatch.setattr(mint_stake, 'require_vault_record', lambda _: SimpleNamespace(auth_type=auth_type, owner_pubkey=owner.owner_key))
        settings = SimpleNamespace(zkpassport_bridge_policy_hash=HX(world.plan.bridge_batch.policy_hash), network='testnet11')
        admin_key = keys.PrivateKey(bytes([61])*32).public_key
        member_hash = compute_eip712_member_leaf_hash(secp256k1_pubkey=admin_key.to_compressed_bytes(),
            prefix_and_domain_separator=eip712_prefix_and_domain_separator(genesis_challenge_for_network('testnet11')),
            type_hash=eip712_type_hash())
        protocol = world.plan.protocol
        parent = world.origins[1]
        governance_struct = singleton_struct(protocol.governance_launcher_id)
        did_struct = singleton_struct(protocol.did_launcher_id)
        from solslot_puzzles.mint_publish_driver import PrimaryPurchaseMintConfig
        from solslot_puzzles.stripe_settlement_v1_driver import PRIMARY_PURCHASE_PROVIDER_ID
        treasury = B(91) if inventory else B(190)
        purchase = PrimaryPurchaseMintConfig(network='testnet11', usd_amount_minor=101,
            technology_fee_bps=100, protocol_treasury_puzhash=treasury,
            validator_pubkeys=world.plan.validator_pubkeys, provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
            inventory_version=2) if inventory else None
        artifacts = build_mint_publish_artifacts(property_id_canon=canonicalise_property_id('SYNTHETIC-MINT'),
            collection_id_canon=canonicalise_property_id('SYNTHETIC-COLLECTION'), share_ppm=1_000_000,
            par_value_mojos=1_000_000, asset_class=1, jurisdiction=b'US', royalty_puzhash=treasury, royalty_bps=100,
            quorum_threshold=2, owner_member_hash=member_hash, gov_member_hash=B(0),
            deed_launcher_parent_coin_name=parent.name(), proposal_launcher_parent_coin_name=parent.name(),
            protocol_did_singleton_struct=did_struct, protocol_did_puzhash=protocol.did_full_puzzle_hash,
            protocol_did_inner_puzhash=protocol.did_inner_puzzle_hash, governance_singleton_struct=governance_struct,
            pool_singleton_launcher_id=protocol.pool_launcher_id, pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
            p2_pool_mod_hash=load_puzzle('p2_pool_v2.clsp').get_tree_hash(),
            p2_vault_mod_hash=load_puzzle('p2_vault.clsp').get_tree_hash(),
            property_registry_puzzle_hash=world.plan.property_registry.full_puzzle_hash,
            governance_tracker_version=2, primary_purchase=purchase,
            metadata_root=B(195) if inventory else None, metadata_anchor_id=B(196) if inventory else None)
        eve = proposal_driver.make_inner_puzzle(owner_member_hash=member_hash, gov_member_hash=B(0),
            proposal_data_hash=artifacts.proposal_data_hash, governance_singleton_struct=governance_struct,
            governance_proposal_hash=artifacts.proposal_hash, deed_launcher_id=artifacts.deed_launcher_id,
            did_inner_puzzle_hash=protocol.did_inner_puzzle_hash, deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            proposal_state=proposal_driver.STATE_DRAFT, state_version=0)
        launch = build_proposal_eve_launch_spend(parent_coin=parent, eve_inner_puzzle=eve)
        conditions = Program.to([*launch.parent_conditions,
            [51, deed_launcher_puzzle_hash(protocol_did_singleton_struct=did_struct), 1],
            [51, world.faucet.address_puzzle_hash, int(parent.amount)-2]])
        funding = make_spend(parent, world.faucet.key.puzzle, Program.to([0, (1, conditions), 0]))
        funding_sig = G2Element.from_bytes(world.faucet.sign_delegated_spend(parent, conditions))
        deadline = int(sim.timestamp)+context.statutes.parameters.voting_window_seconds
        stake_args = dict(context=context, provider=provider, settings=settings, vault_launcher_id=HX(owner.launcher_id),
            stake_amount=amount, proposal_hash=artifacts.proposal_hash, deadline=deadline)
        stake = await mint_stake.build_mint_stake(**stake_args)
        if auth_type == 3:
            sig = owner.evm.sign_msg_hash(signing_digest_for_sgt_lock(stake.operation_hash, stake.vault_coin_id))
            stake = await mint_stake.build_mint_stake(**stake_args,
                signature_data=sig.r.to_bytes(32,'big')+sig.s.to_bytes(32,'big'))
        tracker = build_tracker_propose_coin_spend(tracker_coin=context.tracker_context.coin,
            tracker_inner_puzzle=context.tracker_inner, tracker_launcher_id=context.tracker_launcher,
            lineage_proof=lineage_proof_for_coinsol(context.tracker_context.parent_spend),
            proposal_hash=artifacts.proposal_hash, bill_operation=artifacts.bill_op_program,
            voter_inner_puzzle_hash=stake.owner_inner_hash, first_vote_amount=amount,
            voting_deadline=deadline, proposal_evidence=context.evidence)
        base = sign_spends([launch.launcher_coin_spend, tracker, *stake.bundle.coin_spends], [owner.owner])
        base = SpendBundle([funding, *base.coin_spends], AugSchemeMPL.aggregate([funding_sig, base.aggregated_signature]))
        delegated, actions = mint.mint_authorization_actions(context, owner_bundle=base,
            proposal_hash=artifacts.proposal_hash, deadline=deadline)
        signatures = {}
        for slot in (0, coadmin_slot):
            sig = keys.PrivateKey(bytes([61+slot])*32).sign_msg_hash(bytes.fromhex(actions[slot].message_hash[2:]))
            signatures[slot] = {'action_id': actions[slot].action_id,
                'signature': HX(sig.r.to_bytes(32,'big')+sig.s.to_bytes(32,'big'))}
        with pytest.raises(ValueError, match='missing or stale'):
            mint.build_mint_authorization_spends(context, delegated=delegated, actions=actions,
                signatures={coadmin_slot: signatures[coadmin_slot]}, coadmin_slot=coadmin_slot)
        authorization = mint.build_mint_authorization_spends(context, delegated=delegated, actions=actions,
            signatures=signatures, coadmin_slot=coadmin_slot)
        bundle = SpendBundle([*base.coin_spends, *authorization], base.aggregated_signature)
        assert len(bundle.coin_spends) == 9
        registry = await live(client, world.plan.property_registry.full_puzzle_hash)
        metadata = PublishProposalMetadata(property_id='SYNTHETIC-MINT', collection_id='SYNTHETIC-COLLECTION',
            asset_class_name='RWA-RE-RES', property_id_canon=HX(canonicalise_property_id('SYNTHETIC-MINT')),
            collection_id_canon=HX(canonicalise_property_id('SYNTHETIC-COLLECTION')), share_ppm=1_000_000,
            property_registry_coin_id=HX(registry.name()), property_registry_puzzle_hash=HX(registry.puzzle_hash),
            par_value_mojos=1_000_000, asset_class=1, jurisdiction=HX(b'US'), royalty_puzhash=HX(treasury),
            royalty_bps=100, quorum_threshold=2, owner_member_hash=HX(member_hash), gov_member_hash=HX(B(0)),
            voting_deadline=deadline,
            **(dict(primary_purchase_usd_amount_minor=101, inventory_puzzle_version=2,
                    metadata_root=HX(B(195)), metadata_anchor_id=HX(B(196))) if inventory else {}))
        draft = SimpleNamespace(property_id=metadata.property_id, collection_id=metadata.collection_id,
            share_ppm=metadata.share_ppm, par_value=metadata.par_value_mojos, asset_class=metadata.asset_class_name,
            jurisdiction='US', royalty_puzhash=treasury, royalty_bps=100, quorum_required=2)
        validation = dict(metadata=metadata, proposal=draft, artifact=artifact,
            authenticated_owner=admin_key.to_checksum_address(), stake_vault_launcher_id=owner.launcher_id)
        reviewed = validate_publish_bundle(bundle=base, owner_package=True, **validation)
        assert reviewed.proposal_hash == artifacts.proposal_hash
        if inventory:
            assert len(list(artifacts.bill_op_program.as_iter())) == 4
            with pytest.raises(ValueError, match='re-derived full eve'):
                validate_publish_bundle(bundle=base, owner_package=True,
                    **{**validation, 'metadata': metadata.model_copy(update={'metadata_root': HX(B(197))})})
        monkeypatch.setattr(mint_endpoints, 'require_mint_writes', lambda _: None)
        monkeypatch.setattr(mint_endpoints, 'get_mint_proposal_store', lambda _: SimpleNamespace(get=lambda _: None))
        # Collection sealing is covered by its owning endpoint tests. Here the
        # entire wallet/chain authorization boundary uses confirmed real coins.
        monkeypatch.setattr(mint_endpoints, '_validate_collection_publish_context', lambda **_: None)
        binding = {'method': 'POST', 'path': '/admin/committee/propose', 'query': [],
            'body': {'proposal_id': 'synthetic-mint', 'spend_bundle': base.to_json_dict(),
                'proposal_metadata': metadata.model_dump(), 'stake_vault_launcher_id': HX(owner.launcher_id),
                'publication_context_hash': HX(context.commitment)}}
        prepared = await mint.prepare_mint_authorization(binding=binding, created_by=admin_key.to_checksum_address(),
            provider=provider, settings=settings, genesis_store=None, now=int(sim.timestamp))
        assert prepared.owner_bundle == base and prepared.canonical == reviewed
        assert prepared.actions == actions
        import copy
        stale = copy.deepcopy(binding)
        stale['body']['publication_context_hash'] = HX(fresh.commitment)
        with pytest.raises(ValueError, match='stale'):
            await mint.prepare_mint_authorization(binding=stale, created_by=admin_key.to_checksum_address(),
                provider=provider, settings=settings, genesis_store=None, now=int(sim.timestamp))
        with pytest.raises(ValueError, match='deadline'):
            await mint.prepare_mint_authorization(binding=binding, created_by=admin_key.to_checksum_address(),
                provider=provider, settings=settings, genesis_store=None, now=deadline+1)
        assert validate_publish_bundle(bundle=bundle, authorization_spends=authorization, **validation) == reviewed
        with pytest.raises(ValueError, match='exactly 9'):
            validate_publish_bundle(bundle=base, authorization_spends=authorization, **validation)
        with pytest.raises(ValueError, match='duplicate'):
            validate_publish_bundle(bundle=SpendBundle([*base.coin_spends[:-1], base.coin_spends[0]], base.aggregated_signature),
                owner_package=True, **validation)
        with pytest.raises(ValueError, match='authority|authoriz'):
            validate_publish_bundle(bundle=bundle, **validation)
        # Removing the authority/statutes package must fail actual consensus.
        status, _ = await client.push_tx(base)
        assert status is not MempoolInclusionStatus.SUCCESS
        from solslot_api import admin_operations
        from solslot_api.mint_proposals import MintProposalStore
        from solslot_api.admin_auth import AdminClaims
        monkeypatch.setattr(mint_endpoints, '_load_mint_artifact', lambda _: artifact)
        async def rebuild(_value, _request, _settings):
            return await mint.prepare_mint_authorization(binding=binding, created_by=admin_key.to_checksum_address(),
                provider=provider, settings=settings, genesis_store=None, now=int(sim.timestamp))
        monkeypatch.setattr(admin_operations, '_mint_build', rebuild)
        operation = {'chain_signatures': [dict(admin_index=slot, **signed) for slot, signed in signatures.items()]}
        request = SimpleNamespace(state=SimpleNamespace(admin_operation=operation))
        store = MintProposalStore(str(tmp_path/'mint.db'))
        claims = AdminClaims(sub=admin_key.to_checksum_address(), auth_type='evm', iat=1, exp=2_000_000_000)
        publish_args = dict(proposal_id='synthetic-mint', body=mint_endpoints.PublishMintBundleRequest.model_validate(binding['body']),
            claims=claims, settings=settings, store=store, coinset=provider, request=request)
        published = await mint_endpoints._publish_mint_bundle(**publish_args)
        assert published['pushed'] is True
        assert published['spend_bundle_id'] == HX(bundle.name())
        await sim.farm_block()
        assert (await client.get_coin_record_by_name(launch.eve_coin.name())).coin == launch.eve_coin
        assert store.get('synthetic-mint').state == 'PROPOSED'
        assert (await mint_endpoints._publish_mint_bundle(**publish_args))['status'] == 'ALREADY_RECORDED'
        store.close()
        with pytest.raises(ValueError):
            await mint.load_mint_publication_context(provider=Provider(SimClient(sim)), settings=None, genesis_store=None)
