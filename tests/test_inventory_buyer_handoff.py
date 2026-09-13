"""Offline buyer handoff through the real API loader, route and validator ledger.

Authority documents, enrollment/registry and RPC responses are synthetic. Local
fixture keys sign executed CLVM; these are not wallet or public-chain outcomes.
No loader, validator verifier, recovery helper or purchase store is replaced.
"""
import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, lineage_proof_for_coinsol
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, Coin, G2Element
from chia_rs.sized_ints import uint64

from solslot_api import native_purchases as native, validator_service as validators
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.inventory_authorization_expiry import reconcile_inventory_authorization_expiry
from solslot_api.inventory_recovery import reconcile_timeout_release
from solslot_api import payment_purchase_store as purchase_stores
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_api.validator_ledger import ValidatorLedger
from solslot_api.validator_quorum import InventoryReservationClaim, ValidatorQuorumResult
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import (
    build_inventory_reservation_spend, build_inventory_release_spend,
    inventory_reservation_message, make_inventory_available_inner,
)
from solslot_puzzles.vault_driver import (
    puzzle_for_p2_vault, puzzle_for_vault_full, one_leaf_merkle_root,
    DEFAULT_IDENTITY_ATTEST_ROOT,
)
from tests.test_inventory_authorization_expiry import release_artifact, NOW
from tests.test_inventory_timeout_recovery import Node, record, hx, _b32
from tests.test_native_purchases import FakeProtocolSubmitter
from tests.test_single_external_delivery_context import delivery_case


def signature_pairs(spend):
    conditions = conditions_dict_for_solution(
        Program.from_bytes(bytes(spend.puzzle_reveal)),
        Program.from_bytes(bytes(spend.solution)), 100_000_000)
    return pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA['testnet11'])


def assert_signed(bundle):
    pairs = [pair for spend in bundle.coin_spends for pair in signature_pairs(spend)]
    assert len(pairs) == 2
    assert AugSchemeMPL.aggregate_verify([pk for pk, _ in pairs], [msg for _, msg in pairs], bundle.aggregated_signature)


async def handoff_case(tmp_path, monkeypatch, recovery, *, purchase_transform=None):
    c = delivery_case(tmp_path, monkeypatch, inventory_version=2)
    c.settings = c.worker.settings
    old = (await native._load_context_group(c.settings, c.worker.provider, c.operation.purchase_id,
        require_live=False, allowed_rails=(PaymentRail.STRIPE,))).contexts[0]
    c.old = old
    c.artifact, c.keys = release_artifact()
    c.node = Node(); c.node.height = 132
    c.chain_state = dict(success=True, blockchain_state=dict(sync=dict(synced=True, sync_mode=False),
        peak=dict(height=132, header_hash=hx(_b32(80)))))
    async def chain_state():
        return copy.deepcopy(c.chain_state)
    c.node.get_blockchain_state = chain_state
    c.node.records = copy.deepcopy(c.records)
    c.node.blocks = {hx(_b32(80-n)): dict(height=132-n, header_hash=hx(_b32(80-n)),
        prev_hash=hx(_b32(79-n)), timestamp=NOW-n) for n in range(3)}
    async def block(digest):
        return dict(success=True, block_record=copy.deepcopy(c.node.blocks.get(digest)))
    c.node.get_block_record = block
    monkeypatch.setattr(native.time, 'time', lambda: NOW)
    c.settings.zkpassport_bridge_policy_hash = c.artifact['bridgePolicy']['policyHash']
    c.settings.runtime_environment = 'test'
    c.settings.alpha_writes_enabled = True
    c.settings.minting_enabled = True
    c.settings.launch_control_enabled = False
    c.settings.protocol_artifact_api_token = 'synthetic-handoff-service-token'
    monkeypatch.setattr(native, 'load_signed_public_artifact', lambda _: copy.deepcopy(c.artifact))
    monkeypatch.setattr(validators, 'load_validator_artifact', lambda _: (copy.deepcopy(c.artifact), None))
    monkeypatch.setattr(validators, 'load_validator_private_key', lambda settings: c.keys[settings.signer_index])
    # The authority-document checker is a separate trust-boundary suite. The
    # loader still checks quote time, current credential and governed deed data.
    monkeypatch.setattr(native, '_artifact_rejection_reasons', lambda *_a, **_kw: [])

    def credential(purchase, owner):
        def puzzle(root):
            return puzzle_for_vault_full(purchase.vault_launcher_id, bytes(owner.get_g1()), 1,
                one_leaf_merkle_root(bytes(owner.get_g1())), _b32(26), identity_attest_root=root,
                zkpassport_bridge_policy_hash=_b32(27))
        parent = Coin(purchase.vault_launcher_id, puzzle(DEFAULT_IDENTITY_ATTEST_ROOT).get_tree_hash(), uint64(1))
        current = Coin(parent.name(), puzzle(purchase.zkpassport_root).get_tree_hash(), uint64(1))
        c.node.records[hx(parent.name())] = record(parent, 105, 108)
        c.node.records[hx(current.name())] = record(current, 108)
        return dict(vaultLauncherId=hx(purchase.vault_launcher_id), network='testnet11', confirmedBlockIndex=108,
            chiaVaultCoinId=hx(current.name()), identityAttestRoot=hx(purchase.zkpassport_root),
            policyVersion=2, bridgePolicyHash=hx(_b32(27)))
    old_receipt = credential(old.purchase, c.keys[0])
    available = Coin(old.purchase.deed_launcher_id,
        SINGLETON_MOD.curry(old.deed_struct, make_inventory_available_inner(old.terms)).get_tree_hash(), uint64(1))
    launcher = Coin.from_json_dict(c.records[hx(old.purchase.deed_launcher_id)]['coin'])
    original = build_inventory_reservation_spend(available_coin=available, deed_singleton_struct=old.deed_struct,
        lineage_proof=LineageProof(launcher.parent_coin_info, amount=uint64(1)),
        reservation=old.reservation, signer_indices=(0,1), terms=old.terms)
    sigs = [AugSchemeMPL.sign(next(k for k in c.keys if k.get_g1() == pk), msg)
            for pk, msg in signature_pairs(original.spend)]
    old_bundle = WalletSpendBundle([original.spend], AugSchemeMPL.aggregate(sigs))
    assert_signed(old_bundle)
    # Replace only synthetic bootstrap records with executed, signed fixture bytes.
    with c.purchases._connect() as db:
        db.execute('UPDATE payment_purchases SET inventory_bundle_json=?, inventory_signature=? WHERE purchase_id=?',
            (json.dumps(old_bundle.to_json_dict()), hx(old_bundle.aggregated_signature), old.stored.purchase_id))
        db.execute('UPDATE payment_purchase_inventory_items SET signature=? WHERE purchase_id=?',
            (hx(old_bundle.aggregated_signature), old.stored.purchase_id))
        if recovery == 'expiry':
            db.execute("UPDATE payment_purchases SET inventory_state='PREPARED', inventory_confirmation_height=NULL, inventory_bundle_id=NULL, inventory_mempool_observed_at=NULL WHERE purchase_id=?", (old.stored.purchase_id,))
            db.execute("UPDATE payment_purchase_inventory_items SET state='PREPARED' WHERE purchase_id=?", (old.stored.purchase_id,))
    c.node.records[hx(available.name())] = record(available, 120, 0 if recovery == 'expiry' else 124)
    c.node.records[hx(launcher.name())] = record(launcher, 119, 120)
    if recovery == 'expiry':
        c.node.records.pop(hx(original.reserved_coin.name()), None)
        await reconcile_inventory_authorization_expiry(store=c.purchases, node=c.node,
            purchase_id=old.stored.purchase_id, artifact=c.artifact, environment='staging-alpha', authorize=lambda: None)
        c.source = available
    else:
        release = build_inventory_release_spend(reserved_coin=original.reserved_coin,
            deed_singleton_struct=old.deed_struct, lineage_proof=lineage_proof_for_coinsol(original.spend),
            reservation=old.reservation, terms=old.terms, timed_out=True)
        c.node.records[hx(original.reserved_coin.name())] = record(original.reserved_coin, 124, 127)
        c.node.records[hx(release.next_coin.name())] = record(release.next_coin, 127)
        c.node.spends[(hx(available.name()),124)] = original.spend.to_json_dict()
        c.node.spends[(hx(original.reserved_coin.name()),127)] = release.spend.to_json_dict()
        await reconcile_timeout_release(c.purchases, c.node, old.stored.purchase_id, 'testnet11')
        c.source = release.next_coin
    c.before = c.purchases.inventory_status_snapshot(old.stored.purchase_id)
    c.purchases = PaymentPurchaseStore(c.purchases.path)

    c.buyer = AugSchemeMPL.key_gen(bytes([61])*32)
    c.fresh = replace(old.purchase, vault_launcher_id=_b32(62),
        vault_p2_puzzle_hash=puzzle_for_p2_vault(_b32(62)).get_tree_hash(), zkpassport_root=_b32(63),
        authorization_nonce=_b32(64), quote_expires_at=NOW+300, authorization_expires_at=NOW+600)
    if purchase_transform is not None:
        c.fresh = purchase_transform(c.fresh)
    receipt = credential(c.fresh, c.buyer)
    monkeypatch.setattr('solslot_api.zkpassport_enrollments._sync_chia_stamp',
        lambda *_: SimpleNamespace(status='chia_confirmed', receipt=SimpleNamespace(**receipt, model_dump=lambda: dict(receipt))))
    monkeypatch.setattr(native, 'get_registry', lambda: SimpleNamespace(get=lambda _: SimpleNamespace(auth_type=1, owner_pubkey=bytes(c.buyer.get_g1()))))
    c.stored = c.purchases.save(purchase_intent_id='different-buyer', rail='stripe',
        offer_artifact_hash='sha256:'+'71'*32,
        offer_artifact={**old.stored.offer_artifact, 'vaultCredentialReceipt': receipt},
        purchase_artifact=purchase_artifact_v3_to_json(c.fresh), created_at=NOW)
    c.ledgers = [ValidatorLedger(tmp_path/f'validator-{i}.db') for i in range(2)]
    c.signer_settings = [SimpleNamespace(network='testnet11', deployment_environment='staging-alpha', signer_index=i,
        roster_pubkeys=c.artifact['validatorSet']['pubkeys'], coinset_base_url='https://validator-node.invalid') for i in range(2)]
    old_claim = InventoryReservationClaim(network='testnet11', genesis_artifact_hash=c.artifact['artifactHash'],
        purchase_artifact=purchase_artifact_v3_to_json(old.purchase), available_coin_id=hx(available.name()),
        available_puzzle_hash=hx(available.puzzle_hash), smart_deed_inner_hash=hx(old.terms.smart_deed_inner_hash),
        protocol_puzzle_hash=hx(old.terms.protocol_puzhash), reservation_expires_at=old.reservation.expires_at,
        validator_message=hx(inventory_reservation_message(available_coin=available, reservation=old.reservation)),
        credential_vault_coin_id=old_receipt['chiaVaultCoinId'], credential_identity_root=hx(old.purchase.zkpassport_root),
        credential_policy_version=2, credential_bridge_policy_hash=hx(_b32(27)), credential_owner_auth_type=1,
        credential_owner_key=hx(c.keys[0].get_g1()))
    c.old_claim = old_claim
    # A partial earlier quorum must not permanently monopolize the available coin.
    c.ledgers[0].record_inventory_reservation_or_recover(claim_hash=old_claim.canonical_hash(),
        canonical_claim=validators.canonical_inventory_reservation_claim_json(old_claim), purchase_id=old_claim.purchase_id(),
        available_coin_id=old_claim.available_coin_id, signature=hx(AugSchemeMPL.sign(c.keys[0], old_claim.signature_message())))
    c.rpc = []
    def handler(request):
        c.rpc.append(request.url.path)
        args = json.loads(request.content)
        path = request.url.path
        if path == '/get_coin_record_by_name': result = dict(success=True, coin_record=c.node.records.get(args['name']))
        elif path == '/get_puzzle_and_solution': result = dict(success=True, coin_solution=c.node.spends.get((args['coin_id'], args['height'])))
        elif path == '/get_network_info': result = dict(success=True, network_name='testnet11')
        elif path == '/get_blockchain_state': result = c.chain_state
        elif path == '/get_block_record': result = dict(success=True, block_record=c.node.blocks.get(args['header_hash']))
        else: raise AssertionError(path)
        return httpx.Response(200, json=copy.deepcopy(result))
    client = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kw: client(transport=httpx.MockTransport(handler), **kw))
    c.claims = []; c.quorums = []; c.interrupt = False
    async def collect(_settings, claim):
        c.claims.append(claim)
        signatures = [G2Element.from_bytes(bytes.fromhex(validators.sign_inventory_reservation_claim(
            settings, ledger, claim, claim.canonical_hash())[2:]))
            for settings, ledger in zip(c.signer_settings, c.ledgers, strict=True)]
        quorum = ValidatorQuorumResult(claim_hash=claim.canonical_hash(), signer_indices=(0,1), aggregated_signature=AugSchemeMPL.aggregate(signatures))
        c.quorums.append(quorum)
        if c.interrupt:
            c.interrupt = False
            raise OSError('synthetic interruption after quorum before API persistence')
        return quorum
    monkeypatch.setattr(native, 'collect_inventory_reservation_quorum', collect)
    c.submitter = FakeProtocolSubmitter()
    c.request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node, protocol_submitter=c.submitter)))
    return c


async def reserve(c, purchase_id=None):
    return await native.reserve_smartdeed_inventory(native.InventoryReservationRequest(purchaseId=purchase_id or c.stored.purchase_id),
        c.request, c.settings, 'Bearer synthetic-handoff-service-token')


@pytest.mark.asyncio
@pytest.mark.parametrize('recovery', ['expiry', 'timeout'])
@pytest.mark.parametrize('interrupted', [False, True])
async def test_different_buyer_reserves_after_recovery_through_real_loader_and_signers(tmp_path, monkeypatch, recovery, interrupted):
    c = await handoff_case(tmp_path, monkeypatch, recovery)
    try:
        c.interrupt = interrupted
        if interrupted:
            with pytest.raises(OSError, match='after quorum'):
                await reserve(c)
            assert c.purchases.get(c.stored.purchase_id).inventory_state == 'UNRESERVED'
            assert c.submitter.submitted is None
            retained = [ledger.active_inventory_authorization(hx(c.source.name())) for ledger in c.ledgers]
            assert all(row['claim_hash'] == c.claims[-1].canonical_hash() for row in retained)
            for ledger in c.ledgers: ledger.close()
            c.ledgers = [ValidatorLedger(tmp_path/f'validator-{i}.db') for i in range(2)]
            assert [ledger.active_inventory_authorization(hx(c.source.name())) for ledger in c.ledgers] == retained
            previous_route_store = native.get_payment_purchase_store(c.settings.payment_purchase_db_path)
            monkeypatch.setattr(purchase_stores, '_cached_store', None)
            monkeypatch.setattr(purchase_stores, '_cached_store_path', None)
            c.purchases = native.get_payment_purchase_store(c.settings.payment_purchase_db_path)
            assert c.purchases is not previous_route_store
            assert c.purchases.inventory_status_snapshot(c.old.stored.purchase_id) == c.before
        await reserve(c)
        bundle = WalletSpendBundle.from_json_dict(c.submitter.submitted)
        assert_signed(bundle)
        assert len(bundle.coin_spends) == 1 and bundle.coin_spends[0].coin == c.source
        (item,) = c.purchases.inventory_items(c.stored.purchase_id)
        additions = bundle.additions()
        assert len(additions) == 1 and hx(additions[0].name()) == item.reserved_coin_id
        assert c.claims[-1].credential_owner_key == hx(c.buyer.get_g1())
        assert c.fresh.vault_launcher_id != c.old.purchase.vault_launcher_id
        assert c.fresh.zkpassport_root != c.old.purchase.zkpassport_root
        if interrupted:
            assert c.quorums[0].aggregated_signature == c.quorums[1].aggregated_signature
            assert [ledger.active_inventory_authorization(hx(c.source.name())) for ledger in c.ledgers] == retained
        if recovery == 'expiry':
            assert '/get_block_record' in c.rpc
            assert c.ledgers[0].inventory_retirement(c.old_claim.canonical_hash()) is not None
        else:
            assert '/get_puzzle_and_solution' in c.rpc
        # Independently observed successor drives normal confirmation on retry.
        c.node.height = 136
        c.chain_state['blockchain_state']['peak'] = dict(height=136, header_hash=hx(_b32(84)))
        c.node.records[hx(c.source.name())] = record(c.source, 127 if recovery == 'timeout' else 120, 133)
        c.node.records[item.reserved_coin_id] = record(additions[0], 133)
        await reserve(c)
        assert c.purchases.get(c.stored.purchase_id).inventory_state == 'CONFIRMED'
        assert c.purchases.inventory_status_snapshot(c.old.stored.purchase_id) == c.before
        with pytest.raises(HTTPException) as ended:
            await reserve(c, c.old.stored.purchase_id)
        assert ended.value.status_code == 409
    finally:
        for ledger in c.ledgers: ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('recovery', ['expiry', 'timeout'])
@pytest.mark.parametrize('problem', ['wrong_owner', 'spent_source', 'stale_quote'])
async def test_handoff_rejects_unapproved_owner_spent_coin_and_expired_quote(tmp_path, monkeypatch, recovery, problem):
    c = await handoff_case(tmp_path, monkeypatch, recovery)
    try:
        if problem == 'wrong_owner':
            c.buyer = c.keys[1]  # Registry no longer agrees with the chain-committed owner.
        elif problem == 'spent_source':
            c.node.records[hx(c.source.name())].update(spent=True, spent_block_index=133)
        else:
            monkeypatch.setattr(native.time, 'time', lambda: NOW+301)
        with pytest.raises((HTTPException, validators.ValidatorEvidenceError)):
            await reserve(c)
        assert c.submitter.submitted is None
        assert c.purchases.get(c.stored.purchase_id).inventory_state == 'UNRESERVED'
        assert c.purchases.inventory_status_snapshot(c.old.stored.purchase_id) == c.before
        assert all(ledger.active_inventory_authorization(hx(c.source.name())) is None
                   or ledger.active_inventory_authorization(hx(c.source.name()))['claim_hash'] == c.old_claim.canonical_hash()
                   for ledger in c.ledgers)
    finally:
        for ledger in c.ledgers: ledger.close()
