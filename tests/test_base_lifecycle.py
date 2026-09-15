"""Offline Base lifecycle: actual BLS/CLVM/SQLite and provider codec verification.

Authority, owner registry, chain/provider transports and fee funding are fixtures.
These are not public-chain outcomes, deployment approval or native-device proof.
"""
import asyncio
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from solslot_puzzles.stripe_settlement_v1_driver import MAX_RESERVATION_EXTENSION_SECONDS

from solslot_api import inventory_extensions, payment_start, validator_base_lifecycle as private
from solslot_api.base_lifecycle_claims import ORIGIN_FIELDS, BasePaymentStartClaim, BaseInventoryExtensionClaim, base_lifecycle_activation, digest
from solslot_api.escrow_deposit import verify_escrow_deposit
from solslot_api.inventory_extension_chain import current_position
from solslot_api.inventory_extension_store import canonical
from solslot_api.purchase_admission import ADMISSION_POLICY
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from solslot_api.validator_service import ValidatorEvidenceError
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from tests.test_base_inventory_holds import base_case, arm, deposit
from tests.test_inventory_extensions import advance, confirm, consensus
from tests.test_inventory_payment_holds import close, reserve_again, sibling
from tests.test_escrow_deposit import Chain
from tests.test_single_external_delivery_context import hx, _b32
from tests.test_base_settlement_proof import SettledChain


def activate(c):
    origin = {k: deepcopy(c.genesis[k]) for k in ORIGIN_FIELDS}
    # Capability transition within the same source release. Authority V3 binds
    # genesis sources on chain; changing them requires a fresh deployment.
    c.genesis['artifactHash'] = hx(_b32(97))
    for k in ('baseInventoryHold', 'inventoryExtension', 'inventoryPaymentHolds', 'checkoutLifecycle'):
        c.genesis.pop(k, None)
    inv = c.genesis['inventoryActivation']
    value = dict(schema='solslot.base-reservation-lifecycle.v1', environment='staging-alpha', network='testnet11',
        deploymentId=inv['deploymentId'], sourceShas=c.genesis['sourceShas'], inventoryVersion=2, adapterVersion=1,
        validatorLedgerVersion=15, minConfirmations=3, payoutAddress='0x'+'15'*20,
        **{k: c.claim.activation[k] for k in ('chainId','spoke','token','sourceChainSelector')},
        availableModuleHash=inv['availableModuleHash'], reservedModuleHash=inv['reservedModuleHash'],
        maximumExtensionSeconds=MAX_RESERVATION_EXTENSION_SECONDS, renewalWindowSeconds=86400,
        privateProofDeadlineSeconds=30, advanceDeadlineSeconds=45, workerLeaseSeconds=60,
        recoveryLane='independent', holdOrigins=[origin], priorLifecycles=[], historicalDirectPaymentSha256=[], customerPaymentEnabled=False,
        policy='base-original-deposit-through-canonical-terminal-v1', **ADMISSION_POLICY)
    value['releaseIdentity'] = digest(value)
    value['reviewEvidenceSha256'] = 'fe'*32
    c.genesis['baseReservationLifecycle'] = value
    assert base_lifecycle_activation(c.genesis, 'staging-alpha') == value


async def lifecycle_case(tmp_path, monkeypatch, *, delivery=False, fresh=False, rail='base_usdc'):
    c = await base_case(tmp_path, monkeypatch)
    pid = c.claim.purchase_artifact['purchaseId']
    # Preserve the production-shaped original inventory journal from the parent
    # fixture and substitute the actual Base reservation's commitments/signature.
    with c.voucher_worker.purchases._connect() as old:
        row = dict(old.execute('SELECT * FROM payment_purchase_inventory_items').fetchone())
        purchase = dict(old.execute('SELECT * FROM payment_purchases').fetchone())
    row.update(purchase_id=pid, child_purchase_id=pid, child_artifact_hash=c.claim.purchase_artifact['artifactHash'],
        reserved_coin_id=hx(c.reserved.name()), reserved_puzzle_hash=hx(c.reserved.puzzle_hash),
        signature=hx(c.initial.aggregated_signature))
    with c.purchases._connect() as db:
        db.execute('UPDATE payment_purchase_inventory_items SET '+','.join(k+'=?' for k in row)+' WHERE purchase_id=?', (*row.values(), pid))
        fields = {k:v for k,v in purchase.items() if k.startswith('inventory_')}
        fields.update(inventory_bundle_json=canonical(c.initial.to_json_dict()), inventory_signature=hx(c.initial.aggregated_signature),
            inventory_expires_at=c.claim.reservation_expires_at, inventory_reserved_coin_id=hx(c.reserved.name()),
            inventory_reserved_puzzle_hash=hx(c.reserved.puzzle_hash))
        db.execute('UPDATE payment_purchases SET '+','.join(k+'=?' for k in fields)+' WHERE purchase_id=?', (*fields.values(),pid))
    c.original = c.purchases.get(pid)
    if delivery:
        await attach_base_delivery(c, tmp_path, monkeypatch)
    if not fresh:
        await arm(c)
    c.original_private = [deepcopy(l.base_inventory_hold(pid)) for l in c.ledgers]
    c.evidence = deposit(c)
    c.chain = Chain(c.evidence)
    if not fresh:
        c.purchases.bind_external_message(pid, c.evidence)
    activate(c)
    if fresh:
        # This variant begins before arming and represents admission to the
        # new release. No private hold/signature is deleted or rewritten.
        with c.purchases._connect() as db:
            db.execute('UPDATE payment_purchase_admission SET binding_json=?',(canonical(c.genesis['baseReservationLifecycle']),))
            original_offer = c.purchases.get(pid).offer_artifact
            original_offer['genesisArtifactHash'] = c.genesis['artifactHash']
            db.execute('UPDATE payment_purchases SET offer_artifact_json=?',(canonical(original_offer),))
    with c.purchases._connect() as db:
        db.execute('UPDATE payment_purchases SET rail=?',(rail,))
    c.payment = dict(hold=c.claim.model_dump(mode='json'), payment_evidence=c.evidence)
    from solslot_api import purchase_admission
    monkeypatch.setattr(purchase_admission, 'recheck_admitted_owner', lambda *_: None)
    def verify(settings, claim):
        cap = claim.activation
        if settings.network != 'testnet11' or settings.base_sepolia_spoke_address != cap['spoke']:
            raise ValueError('wrong fixture deployment')
        return verify_escrow_deposit(rpc_url=settings.base_sepolia_rpc_url, evidence=claim.payment_evidence,
            chain_id=cap['chainId'], spoke=cap['spoke'], token=cap['token'], confirmations=3, web3_factory=c.chain.web3)
    monkeypatch.setattr(private, 'deposit_proof', verify)
    async def quorum(settings, claim):
        c.extension_claims.append(claim)
        sigs = [G2Element.from_bytes(bytes.fromhex((await private.sign_base_extension(s,l,claim,claim.canonical_hash()))[2:]))
                for s,l in zip(c.signers,c.ledgers)]
        if c.fail_after_quorum:
            raise OSError('lost after independent signing')
        return SimpleNamespace(signer_indices=(0,1), aggregated_signature=AugSchemeMPL.aggregate(sigs))
    async def observation(settings, claim):
        sigs = [G2Element.from_bytes(bytes.fromhex((await private.sign_base_payment_start(s,l,claim,claim.canonical_hash()))[2:]))
                for s,l in zip(c.signers,c.ledgers)]
        return SimpleNamespace(signer_indices=(0,1), aggregated_signature=AugSchemeMPL.aggregate(sigs))
    monkeypatch.setattr(inventory_extensions, 'collect_inventory_extension_quorum', quorum)
    monkeypatch.setattr(payment_start, 'collect_payment_start_quorum', observation)
    c.original = c.purchases.get(pid)
    return c


async def attach_base_delivery(c, tmp_path, monkeypatch):
    """Use the same purchase, original hold and deposit across the two adapters."""
    from tests.test_current_base_voucher_delivery import base_case as delivery_case
    from solslot_api import native_purchases
    import time
    path = tmp_path/'base-delivery'
    path.mkdir()
    c.evidence = deposit(c)
    d = delivery_case(path, monkeypatch, inventory_version=2, payment_evidence=c.evidence)
    assert d.purchase == c.purchase
    original = dict(c.records)
    c.records.update(d.records)
    for coin in (c.initial.coin_spends[0].coin, c.reserved):
        c.records[hx(coin.name())] = original[hx(coin.name())]
    for coin_id, record in d.records.items():
        height = record['spent_block_index']
        if height in (200,201):
            try:
                c.spends[(coin_id,height)] = await d.worker.provider.get_puzzle_and_solution(coin_id,height)
            except (StopIteration, RuntimeError):
                pass
    d.genesis.clear()
    d.genesis.update(c.genesis)
    c.genesis = d.genesis
    c.genesis['launcherIds']['pool'] = hx(_b32(27))
    c.genesis['bridgePolicy'] = dict(policyHash=hx(_b32(26)))
    c.settings.payment_purchase_db_path = c.purchases.path
    d.voucher_worker.settings = c.settings
    d.voucher_worker.purchases = c.purchases
    c.node.push_tx = d.worker.provider.push_tx
    d.voucher_worker.coinset = c.node
    d.records = c.records
    c.presales = d.presales
    c.delivery = d
    c.clock[0] = 1_900_000_040
    monkeypatch.setattr(time, 'time', lambda:c.clock[0])
    monkeypatch.setattr(native_purchases, 'load_signed_public_artifact', lambda _:c.genesis)
    with c.purchases._connect() as db:
        db.execute('UPDATE payment_purchases SET offer_artifact_json=? WHERE purchase_id=?',
            (canonical(d.purchases.get(c.claim.purchase_artifact['purchaseId']).offer_artifact), c.claim.purchase_artifact['purchaseId']))


def use_private_voucher_signers(c, monkeypatch):
    from chia_rs import Coin
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    from solslot_puzzles.vault_driver import puzzle_for_vault_full, one_leaf_merkle_root
    from solslot_api import validator_service as service, voucher_issuance_worker, zkpassport_enrollments
    from tests.test_single_external_delivery_context import coin_record
    owner = bytes(c.keys[0].get_g1())
    puzzle = puzzle_for_vault_full(c.purchase.vault_launcher_id, owner, 1, one_leaf_merkle_root(owner), _b32(27),
        identity_attest_root=c.purchase.zkpassport_root, zkpassport_bridge_policy_hash=_b32(26))
    parent = Coin(c.purchase.vault_launcher_id, puzzle.get_tree_hash(), 1)
    vault = Coin(parent.name(), puzzle.get_tree_hash(), 1)
    c.records[hx(parent.name())] = coin_record(parent, confirmed=149, spent=150)
    c.records[hx(vault.name())] = coin_record(vault, confirmed=150)
    # Approved vault/identity ancestry is a synthetic registry fixture. The
    # reservation, renewal and voucher transaction spends are real CLVM.
    c.spends[(hx(parent.name()),150)] = make_spend(parent, puzzle, Program.to([])).to_json_dict()
    receipt = zkpassport_enrollments._sync_chia_stamp().receipt.model_dump()
    receipt['chiaVaultCoinId'] = hx(vault.name())
    credential = SimpleNamespace(**receipt, model_dump=lambda:deepcopy(receipt))
    monkeypatch.setattr(zkpassport_enrollments, '_sync_chia_stamp', lambda *_:SimpleNamespace(status='chia_confirmed',receipt=credential))
    for signer in c.signers:
        signer.claim_clock_skew_seconds = 60
    monkeypatch.setattr(service, 'Web3', c.chain.web3)
    async def quorum(settings, claim):
        c.delivery.voucher_claims.append(claim)
        signatures = [G2Element.from_bytes(bytes.fromhex(service.sign_voucher_transition_claim(s,l,claim,claim.canonical_hash())[2:]))
            for s,l in zip(c.signers,c.ledgers)]
        return SimpleNamespace(signer_indices=(0,1), aggregated_signature=AugSchemeMPL.aggregate(signatures))
    monkeypatch.setattr(voucher_issuance_worker, 'collect_voucher_transition_quorum', quorum)


@pytest.mark.asyncio
async def test_original_base_hold_upgrades_without_rewriting_and_renews_exactly(tmp_path, monkeypatch):
    c = await lifecycle_case(tmp_path, monkeypatch)
    try:
        result = await advance(c)
        assert result['extensionState'] == 'SUBMITTED'
        assert len(c.funded) == 1 and consensus(SpendBundle.from_json_dict(c.funded[0]['spendBundle']))[0] is None
        confirm(c)
        assert (await advance(c, observe_only=True))['extensionState'] == 'CONFIRMED'
        stored = c.purchases.get(c.original.purchase_id)
        position = current_position(stored, c.purchases.inventory_items(stored.purchase_id), c.genesis)
        assert position.reservation.expires_at == c.original.inventory_expires_at + MAX_RESERVATION_EXTENSION_SECONDS
        assert stored.inventory_bundle == c.original.inventory_bundle and stored.purchase_artifact == c.original.purchase_artifact
        for i,ledger in enumerate(c.ledgers):
            held = ledger.base_inventory_hold(stored.purchase_id)
            assert {k:v for k,v in held.items() if k != 'payment_start_json'} == {k:v for k,v in c.original_private[i].items() if k != 'payment_start_json'}
            assert json.loads(held['payment_start_json']) == c.evidence
        with pytest.raises(ValidatorLedgerConflict):
            reserve_again(c)
        assert c.genesis['baseReservationLifecycle']['customerPaymentEnabled'] is False
    finally:
        close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['quorum', 'push'])
async def test_base_renewal_restart_reuses_exact_signed_and_funded_bytes(tmp_path, monkeypatch, failure):
    c = await lifecycle_case(tmp_path, monkeypatch)
    try:
        c.fail_after_quorum = failure == 'quorum'
        c.fail_push = failure == 'push'
        with pytest.raises(OSError):
            await advance(c)
        retained = c.purchases.pending_inventory_extension(c.original.purchase_id)
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        close(c)
        c.ledgers = [ValidatorLedger(tmp_path/f'extension-signer-{i}.db') for i in range(2)]
        c.fail_after_quorum = c.fail_push = False
        await advance(c)
        after = c.purchases.pending_inventory_extension(c.original.purchase_id)
        assert after['claim'] == retained['claim']
        if retained['prepared']:
            assert after['prepared'] == retained['prepared']
        assert len(c.funded) == 1
        confirm(c)
        c.clock[0] = c.original.inventory_expires_at+100
        assert (await advance(c, observe_only=True))['extensionState'] == 'CONFIRMED'
    finally:
        close(c)


async def prepare_return(c, monkeypatch, *, renew=True, status=4):
    from solslot_api import base_checkout_terminals as terminals, validator_base_terminal as terminal_private
    from solslot_api.base_settlement_proof import verify_base_settlement
    from solslot_api.checkout_terminals import timeout
    from tests.test_single_external_delivery_context import coin_record
    if renew:
        await advance(c)
        confirm(c)
        await advance(c, observe_only=True)
    stored = c.purchases.get(c.original.purchase_id)
    position = current_position(stored, c.purchases.inventory_items(stored.purchase_id), c.genesis)
    c.clock[0] = c.chain_clock = position.reservation.expires_at+10
    returned = timeout(position)
    assert consensus(SpendBundle([returned.spend], G2Element()))[0] is None
    height = c.height+2
    c.records[hx(position.coin.name())] = coin_record(position.coin, confirmed=position.height, spent=height)
    c.spends[(hx(position.coin.name()),height)] = returned.spend.to_json_dict()
    c.records[hx(returned.next_coin.name())] = coin_record(returned.next_coin, confirmed=height)
    c.height = height+3
    c.chain = SettledChain(c.evidence, status=status)
    c.settings.payment_evm_usdc_tokens = {'84532':c.claim.activation['token']}
    c.settings.payment_omnichain_rpc_url = 'https://offline.invalid'
    def proof(settings, claim):
        cap = claim.activation
        return verify_base_settlement(rpc_url=settings.base_sepolia_rpc_url, evidence=claim.payment_evidence,
            settlement=claim.settlement, chain_id=84532, spoke=cap['spoke'], token=cap['token'],
            confirmations=3, recipient=claim.hold.depositor, outcome='REFUNDED', web3_factory=c.chain.web3)
    monkeypatch.setattr(terminal_private, 'terminal_payment_proof', proof)
    c.terminal_claims = []
    async def quorum(settings, claim, path):
        assert path == '/v1/base-checkout/terminal'
        c.terminal_claims.append(claim)
        sigs = [G2Element.from_bytes(bytes.fromhex((await terminal_private.sign_base_terminal(s,l,claim,claim.canonical_hash()))[2:]))
                for s,l in zip(c.signers,c.ledgers)]
        if getattr(c, 'lose_terminal_response', False):
            raise OSError('lost after independent terminal signatures')
        return SimpleNamespace(signer_indices=(0,1), aggregated_signature=AugSchemeMPL.aggregate(sigs))
    monkeypatch.setattr(terminals, '_collect_inventory_quorum', quorum)
    c.returned = returned
    return position


async def reconcile_return(c):
    from solslot_api.base_checkout_terminals import reconcile_base_terminal
    return await reconcile_base_terminal(store=c.purchases, node=c.node, settings=c.settings,
        purchase_id=c.original.purchase_id, load_artifact=lambda:deepcopy(c.genesis), settlement=c.chain.settlement)


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [4,5])
async def test_base_refund_and_exact_renewed_timeout_release_both_ledgers(tmp_path, monkeypatch, status):
    c = await lifecycle_case(tmp_path, monkeypatch)
    try:
        await prepare_return(c, monkeypatch, status=status)
        result = await reconcile_return(c)
        assert result['state'] == 'RETURNED' and result['capacityReleased']
        assert result['terminalReceipt']['claim']['output_coin_id'] == hx(c.returned.next_coin.name())
        stored = c.purchases.get(c.original.purchase_id)
        assert stored.inventory_state == 'RELEASED' and stored.inventory_bundle == c.original.inventory_bundle
        assert stored.purchase_artifact == c.original.purchase_artifact
        for ledger in c.ledgers:
            assert ledger.base_lifecycle_terminal(stored.purchase_id) is not None
            assert ledger.base_inventory_hold(stored.purchase_id)['claim_json'] == canonical(c.claim.model_dump(mode='json'))
            with pytest.raises(ValidatorLedgerConflict):
                ledger.retain_base_payment_start(stored.purchase_id, c.evidence)
            for kind in ('single', 'batch', 'issuance', 'transition'):
                with pytest.raises(ValidatorLedgerConflict):
                    sibling(ledger, c, kind, pi=c.claim.global_payment_id)
        # Only a new purchase may use the now-returned inventory; the original
        # hold, signature and terminal tombstone remain stored.
        reserve_again(c)
        c.chain.fail = 'receipt'
        assert await reconcile_return(c) == result
        assert c.purchases.checkout_admission_closed(stored.purchase_id, c.claim.activation)
    finally:
        close(c)


@pytest.mark.asyncio
async def test_lost_terminal_quorum_response_recovers_original_claim_and_tombstones(tmp_path, monkeypatch):
    c = await lifecycle_case(tmp_path, monkeypatch)
    try:
        await prepare_return(c, monkeypatch)
        c.lose_terminal_response = True
        with pytest.raises(OSError):
            await reconcile_return(c)
        old = c.purchases.base_terminal_attempt(c.original.purchase_id)
        assert old['quorum'] is None
        signatures = [l.base_lifecycle_terminal(c.original.purchase_id)['signature'] for l in c.ledgers]
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        close(c)
        c.ledgers = [ValidatorLedger(tmp_path/f'extension-signer-{i}.db') for i in range(2)]
        c.lose_terminal_response = False
        c.chain.fail = 'receipt'
        c.clock[0] += 6  # Retain the existing bounded recovery cooldown.
        assert (await reconcile_return(c))['state'] == 'RETURNED'
        assert [l.base_lifecycle_terminal(c.original.purchase_id)['signature'] for l in c.ledgers] == signatures
        assert c.purchases.base_terminal_attempt(c.original.purchase_id)['claim'] == old['claim']
    finally:
        close(c)


@pytest.mark.asyncio
async def test_one_base_purchase_reaches_actual_smartdeed_after_renewal(tmp_path, monkeypatch):
    from tests.test_current_base_voucher_delivery import submit, prove_bundle
    c = await lifecycle_case(tmp_path, monkeypatch, delivery=True)
    try:
        use_private_voucher_signers(c, monkeypatch)
        await advance(c)
        confirm(c)
        await advance(c, observe_only=True)
        stored = c.purchases.get(c.original.purchase_id)
        position = current_position(stored, c.purchases.inventory_items(stored.purchase_id), c.genesis)
        c.clock[0] = 1_900_000_400
        assert await submit(c.delivery)
        bundle = prove_bundle(c.delivery)
        assert c.delivery.voucher_claims[-1].deed_coin_id == hx(position.coin.name())
        assert c.delivery.voucher_claims[-1].reservation_expires_at == position.reservation.expires_at
        assert any(s.coin == position.coin for s in bundle.coin_spends)
        from tests.test_single_external_delivery_context import coin_record
        from solslot_api import base_checkout_terminals as terminals, validator_base_terminal as terminal_private
        from solslot_api.base_settlement_proof import verify_base_settlement
        height = c.height+2
        for spend in bundle.coin_spends:
            old = c.records.get(hx(spend.coin.name()))
            created = old['confirmed_block_index'] if old else height
            c.records[hx(spend.coin.name())] = coin_record(spend.coin, confirmed=created, spent=height)
            c.spends[(hx(spend.coin.name()),height)] = spend.to_json_dict()
        removed = {coin.name() for coin in bundle.removals()}
        for coin in bundle.additions():
            c.records[hx(coin.name())] = coin_record(coin, confirmed=height, spent=height if coin.name() in removed else 0)
        c.height = height+3
        outcomes = await c.delivery.voucher_worker.reconcile_once()
        assert outcomes[0]['status'] == 'BASE_DELIVERY_AUTHORIZED'
        voucher = c.presales.voucher_for_purchase(c.original.purchase_id)
        assert voucher['state'] == 'REDEEMED' and voucher['redemptionConfirmedHeight'] == height
        execution = c.presales.retained_voucher_execution(stored.purchase_artifact['presaleTermsHash'],voucher['serial'],'base_redemption')
        assert SpendBundle.from_json_dict(execution['spendBundle']) == bundle
        c.chain = SettledChain(c.evidence, status=3)
        c.settings.payment_evm_usdc_tokens = {'84532':c.claim.activation['token']}
        c.settings.payment_omnichain_rpc_url = 'https://offline.invalid'
        def proof(settings, claim):
            return verify_base_settlement(rpc_url=settings.base_sepolia_rpc_url, evidence=claim.payment_evidence,
                settlement=claim.settlement, chain_id=84532, spoke=claim.activation['spoke'], token=claim.activation['token'],
                confirmations=3, recipient=claim.activation['payoutAddress'], outcome='DELIVERED', web3_factory=c.chain.web3)
        monkeypatch.setattr(terminal_private, 'terminal_payment_proof', proof)
        async def quorum(settings, claim, path):
            assert path == '/v1/base-checkout/terminal'
            signatures = [G2Element.from_bytes(bytes.fromhex((await terminal_private.sign_base_terminal(s,l,claim,claim.canonical_hash()))[2:]))
                for s,l in zip(c.signers,c.ledgers)]
            return SimpleNamespace(signer_indices=(0,1), aggregated_signature=AugSchemeMPL.aggregate(signatures))
        monkeypatch.setattr(terminals, '_collect_inventory_quorum', quorum)
        result = await terminals.reconcile_base_terminal(store=c.purchases,node=c.node,settings=c.settings,
            purchase_id=c.original.purchase_id,load_artifact=lambda:deepcopy(c.genesis),
            settlement=c.chain.settlement,spend_bundle=bundle.to_json_dict())
        assert result['state'] == 'DELIVERED' and result['capacityReleased']
        assert result['terminalReceipt']['claim']['output_coin_id'] == voucher['redemptionDeedOutputCoinId']
        assert c.purchases.checkout_admission_closed(c.original.purchase_id,c.claim.activation)
        for ledger in c.ledgers:
            assert ledger.base_lifecycle_terminal(c.original.purchase_id) is not None
            with pytest.raises(ValidatorLedgerConflict):
                ledger.retain_base_payment_start(c.original.purchase_id,c.evidence)
    finally:
        close(c)


@pytest.mark.asyncio
async def test_new_release_prepare_pins_one_identity_before_quorum_and_recovers(tmp_path, monkeypatch):
    from solslot_api import base_checkout_prepare as prepare
    c = await lifecycle_case(tmp_path, monkeypatch, fresh=True)
    monkeypatch.setattr(prepare,'recheck_admitted_owner',lambda *_:None)
    args = dict(store=c.purchases,settings=c.settings,purchase_id=c.original.purchase_id,
        depositor=c.claim.depositor,load_artifact=lambda:deepcopy(c.genesis),authorize=lambda:None)
    try:
        c.lose_response = True
        with pytest.raises(OSError):
            await prepare.prepare_base_checkout(**args)
        original = c.purchases.base_checkout_hold(c.original.purchase_id)
        assert original['state'] == 'ARMING'
        assert original['claim']['schema_version'] == 'solslot.base-inventory-hold-claim.v2'
        c.clock[0] += 6
        c.lose_response = False
        c.purchases = PaymentPurchaseStore(c.purchases.path)
        args['store'] = c.purchases
        result = await prepare.prepare_base_checkout(**args)
        assert result['state'] == 'ARMED' and result['confirmationAllowed'] is False
        assert result['localPaymentId'] == original['claim']['local_payment_id']
        assert result['globalPaymentId'] == original['claim']['global_payment_id']
        assert result['genesisArtifactHash'] == c.genesis['artifactHash']
        assert await prepare.prepare_base_checkout(**args) == result
        with pytest.raises(PaymentPurchaseConflict):
            await prepare.prepare_base_checkout(**{**args,'depositor':'0x'+'f1'*20})
        assert c.purchases.base_checkout_hold(c.original.purchase_id)['claim'] == original['claim']
    finally:
        close(c)


@pytest.mark.asyncio
async def test_partial_old_hold_quorum_finishes_on_explicit_reviewed_origin(tmp_path, monkeypatch):
    from solslot_api.validator_base_inventory_hold import sign_base_inventory_hold
    c = await base_case(tmp_path,monkeypatch)
    try:
        first = await sign_base_inventory_hold(c.signers[0],c.ledgers[0],c.claim,c.claim.canonical_hash())
        # Coordinator retained exact intent before losing its partial response.
        c.purchases.claim_base_checkout(c.claim,snapshot=c.purchases.get(c.claim.purchase_artifact['purchaseId']),now=int(c.clock[0]))
        activate(c)
        assert await sign_base_inventory_hold(c.signers[0],c.ledgers[0],c.claim,c.claim.canonical_hash()) == first
        result = await arm(c)
        assert result['state'] == 'ARMED'
        assert c.ledgers[0].base_inventory_hold(c.claim.purchase_artifact['purchaseId'])['signature'] == first
        assert c.ledgers[1].base_inventory_hold(c.claim.purchase_artifact['purchaseId']) is not None
    finally:
        close(c)


@pytest.mark.asyncio
async def test_evm_usdc_alias_uses_same_private_lifecycle_and_terminal(tmp_path,monkeypatch):
    c = await lifecycle_case(tmp_path,monkeypatch,rail='evm_usdc')
    try:
        await prepare_return(c,monkeypatch)
        assert (await reconcile_return(c))['state'] == 'RETURNED'
        assert c.purchases.payment_start(c.original.purchase_id)['claim']['schema_version'] == 'solslot.base-payment-start.v1'
    finally:
        close(c)


def rebind_capability(c, **changes):
    cap=c.genesis['baseReservationLifecycle']
    cap.update(changes)
    cap['releaseIdentity']=digest({k:v for k,v in cap.items() if k not in ('releaseIdentity','reviewEvidenceSha256')})


@pytest.mark.asyncio
async def test_reviewed_release_upgrade_recovers_exact_pending_extension_and_terminal(tmp_path,monkeypatch):
    c=await lifecycle_case(tmp_path,monkeypatch)
    try:
        await advance(c)
        pending=deepcopy(c.purchases.pending_inventory_extension(c.original.purchase_id))
        old=deepcopy(c.genesis)
        c.genesis['artifactHash']=hx(_b32(98))
        rebind_capability(c,priorLifecycles=[dict(artifactHash=old['artifactHash'],
            capabilitySha256=digest(old['baseReservationLifecycle']),releaseIdentity=old['baseReservationLifecycle']['releaseIdentity'])])
        assert base_lifecycle_activation(c.genesis,'staging-alpha')
        confirm(c)
        assert (await advance(c,observe_only=True))['extensionState']=='CONFIRMED'
        assert c.purchases.inventory_extension_operations(c.original.purchase_id)[0]['claim']==pending['claim']
        await prepare_return(c,monkeypatch,renew=False)
        result=await reconcile_return(c)
        assert result['state']=='RETURNED'
        assert result['terminalReceipt']['claim']['hold']==c.claim.model_dump(mode='json')
    finally:close(c)


@pytest.mark.asyncio
async def test_worker_observes_payment_while_paused_and_terminal_has_its_own_lane(tmp_path,monkeypatch):
    from fastapi import HTTPException
    from tests.test_checkout_lifecycle import worker
    from solslot_api.base_checkout_lifecycle import advance_base_lifecycle
    from solslot_api import validator_base_terminal as terminal
    c=await lifecycle_case(tmp_path,monkeypatch)
    try:
        c.settings.checkout_lifecycle_worker_enabled=False
        c.settings.protocol_fee_funding_enabled=False
        w=worker(c)
        with pytest.raises(HTTPException):await advance_base_lifecycle(w,c.original.purchase_id,'renewal')
        assert c.purchases.payment_start(c.original.purchase_id) is not None
        assert not c.funded
        assert await advance_base_lifecycle(w,c.original.purchase_id,'terminal')==('WAITING_FOR_ESCROW_PROOF',False)
        await prepare_return(c,monkeypatch,renew=False)
        # Occupied renewal proof slots cannot consume terminal resources.
        assert private._proof_slots.acquire(False) and private._proof_slots.acquire(False)
        try:
            assert (await reconcile_return(c))['state']=='RETURNED'
        finally:
            private._proof_slots.release();private._proof_slots.release()
        assert await advance_base_lifecycle(w,c.original.purchase_id,'terminal')==('COMPLETE',True)
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['amount','payer','source','route','release','clock','spent'])
async def test_bad_base_lifecycle_input_never_funds_or_dispatches(tmp_path,monkeypatch,problem):
    c=await lifecycle_case(tmp_path,monkeypatch)
    try:
        if problem=='amount':c.chain.current[12]+=1
        elif problem=='payer':c.payment['payment_evidence']={**c.evidence,'depositor':'0x'+'ff'*20}
        elif problem=='source':c.chain.fail='receipt'
        elif problem=='route':c.signers[1].base_sepolia_spoke_address='0x'+'ff'*20
        elif problem=='release':c.genesis['baseReservationLifecycle']['sourceShas']={}
        elif problem=='clock':c.chain_clock=c.claim.reservation_expires_at
        else:c.records[hx(c.reserved.name())]['spent_block_index']=c.height;c.records[hx(c.reserved.name())]['spent']=True
        with pytest.raises((ValidatorEvidenceError,ValueError,PaymentPurchaseConflict)):
            await advance(c)
        assert not c.funded and not c.extension_dispatches
    finally:close(c)


@pytest.mark.asyncio
async def test_cancelled_rpc_keeps_slot_until_work_finishes(tmp_path,monkeypatch):
    import threading
    from solslot_api.validator_base_terminal import bounded_terminal_rpc
    entered=threading.Event();release=threading.Event()
    def delayed(settings,claim):entered.set();release.wait(3)
    monkeypatch.setattr(private,'deposit_proof',delayed)
    tasks=[asyncio.create_task(private.bounded_deposit_proof(None,None)) for _ in range(2)]
    try:
        for _ in range(100):
            if entered.is_set():break
            await asyncio.sleep(.01)
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        with pytest.raises(ValueError,match='capacity'):await private.bounded_deposit_proof(None,None)
        assert await bounded_terminal_rpc(lambda:'recovery')=='recovery'
    finally:
        release.set()
        # Await actual RPC completion to avoid cross-test capacity interference.
        for _ in range(100):
            if private._rpc_slots._value==2:break
            await asyncio.sleep(.01)
        assert private._rpc_slots._value==2


@pytest.mark.asyncio
async def test_historical_direct_v3_requires_exact_review_and_never_invents_hold(tmp_path,monkeypatch):
    from tests.test_current_base_voucher_delivery import submit, prove_bundle
    from solslot_api.base_lifecycle_claims import historical_direct_payment_digest
    c=await lifecycle_case(tmp_path,monkeypatch,delivery=True,fresh=True)
    try:
        c.purchases.bind_external_message(c.original.purchase_id,c.evidence)
        use_private_voucher_signers(c,monkeypatch)
        # The existing full voucher verifier has separate coverage; this
        # helper runs only after it and must not reinterpret historical funds.
        from solslot_api.validator_service import _retain_verified_base_hold_payment
        claim=SimpleNamespace(purchase_artifact=c.original.purchase_artifact,payment_evidence=c.evidence,
            voucher_commitment={'paymentRail':1},global_payment_id=lambda:c.evidence['globalPaymentId'])
        with pytest.raises(ValidatorEvidenceError):_retain_verified_base_hold_payment(c.signers[0],c.ledgers[0],claim)
        allowed=historical_direct_payment_digest(c.original.purchase_artifact,c.evidence)
        rebind_capability(c,historicalDirectPaymentSha256=[allowed])
        _retain_verified_base_hold_payment(c.signers[0],c.ledgers[0],claim)
        assert all(l.base_inventory_hold(c.original.purchase_id) is None for l in c.ledgers)
        changed=deepcopy(c.evidence);changed['source']['logIndex']+=1
        assert historical_direct_payment_digest(c.original.purchase_artifact,changed)!=allowed
    finally:close(c)


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['valid','immature_clock','funded','latest_funded','network','reorg'])
async def test_unfunded_expiry_requires_mature_empty_original_mapping(tmp_path,monkeypatch,problem):
    from solslot_api.validator_base_inventory_hold import verify_unfunded_base_timeout
    c=await base_case(tmp_path,monkeypatch)
    try:
        c.evm.paused=True # Protective observation is available with sales paused.
        c.evm.timestamp=c.claim.reservation_expires_at
        reads=[]
        def block(height):
            reads.append(height)
            return dict(number=125 if height=='latest' else height,timestamp=c.evm.timestamp,
                hash=hx(_b32(91)) if problem=='reorg' and len(reads)>2 else c.evm.tip_hash)
        c.evm.get_block=block
        if problem=='immature_clock':c.evm.timestamp-=1
        elif problem=='funded':c.evm.mapping=bytes.fromhex(c.claim.global_payment_id[2:])
        elif problem=='latest_funded':c.evm.latest_mapping=bytes.fromhex(c.claim.global_payment_id[2:])
        elif problem=='network':c.evm.chain_id=8453
        class Web3:
            def __init__(self,_):self.eth=c.evm
            @staticmethod
            def HTTPProvider(*a,**kw):return None
        if problem=='valid':
            verify_unfunded_base_timeout(c.signers[0],c.claim,web3_factory=Web3)
            assert reads[:2]==['latest',123]
        else:
            with pytest.raises(ValueError):verify_unfunded_base_timeout(c.signers[0],c.claim,web3_factory=Web3)
        assert c.ledgers[0].base_lifecycle_terminal(c.claim.purchase_artifact['purchaseId']) is None
    finally:close(c)


@pytest.mark.asyncio
async def test_base_prepare_endpoint_auth_concurrency_and_no_browser_chosen_id(tmp_path,monkeypatch):
    from fastapi import HTTPException
    from solslot_api import native_purchases, base_checkout_prepare
    from pydantic import ValidationError
    c=await lifecycle_case(tmp_path,monkeypatch,fresh=True)
    monkeypatch.setattr(base_checkout_prepare,'recheck_admitted_owner',lambda *_:None)
    monkeypatch.setattr(native_purchases,'get_payment_purchase_store',lambda _:c.purchases)
    monkeypatch.setattr(native_purchases,'load_signed_public_artifact',lambda _:deepcopy(c.genesis))
    try:
        raw=dict(purchaseId=c.original.purchase_id,depositor=c.claim.depositor)
        with pytest.raises(ValidationError):native_purchases.BaseCheckoutPrepareRequest(**raw,localPaymentId=hx(_b32(90)))
        body=native_purchases.BaseCheckoutPrepareRequest(**raw)
        with pytest.raises(HTTPException) as denied:await native_purchases.prepare_base_inventory_checkout(body,c.settings,None)
        assert denied.value.status_code==401 and c.purchases.base_checkout_hold(c.original.purchase_id) is None
        calls=[native_purchases.prepare_base_inventory_checkout(body,c.settings,'Bearer synthetic-extension-service-token') for _ in range(3)]
        results=await asyncio.gather(*calls,return_exceptions=True)
        successful=[r for r in results if isinstance(r,dict)]
        assert successful and all(r['localPaymentId']==successful[0]['localPaymentId'] for r in successful)
        held=c.purchases.base_checkout_hold(c.original.purchase_id)
        assert held['state']=='ARMED'
        for ledger in c.ledgers:
            assert ledger.base_inventory_hold(c.original.purchase_id)['claim_json']==canonical(held['claim'])
        c.settings.minting_enabled=False
        # Existing identity reads do not open payment, even when retrying.
        result=await native_purchases.prepare_base_inventory_checkout(body,c.settings,'Bearer synthetic-extension-service-token')
        assert result['globalPaymentId']==successful[0]['globalPaymentId'] and not result['confirmationAllowed']
    finally:close(c)


@pytest.mark.asyncio
async def test_schema14_upgrade_preserves_original_hold_and_first_deposit(tmp_path,monkeypatch):
    c=await base_case(tmp_path,monkeypatch)
    try:
        await arm(c)
        pid=c.claim.purchase_artifact['purchaseId']
        c.ledgers[0].retain_base_payment_start(pid,deposit(c))
        original=deepcopy(c.ledgers[0].base_inventory_hold(pid))
        c.ledgers[0]._conn.executescript('DROP TABLE base_lifecycle_observations; DROP TABLE base_lifecycle_terminals; DROP TABLE base_inventory_hold_generations; DROP TABLE voucher_series_phase_retry_signatures; DROP TABLE voucher_phase_expiry_observations; PRAGMA user_version=14;')
        c.ledgers[0].close();c.ledgers[0]=ValidatorLedger(tmp_path/'extension-signer-0.db')
        assert c.ledgers[0]._conn.execute('PRAGMA user_version').fetchone()[0]==16
        assert c.ledgers[0].base_inventory_hold(pid)==original
        assert c.ledgers[0].base_lifecycle_terminal(pid) is None
    finally:close(c)


@pytest.mark.asyncio
async def test_base_only_worker_passes_application_startup_capability_gate(tmp_path,monkeypatch):
    import importlib
    app_module=importlib.import_module('solslot_api.app')
    c=await lifecycle_case(tmp_path,monkeypatch)
    class ReachedHardening(Exception):pass
    try:
        c.settings.checkout_lifecycle_worker_enabled=True
        monkeypatch.setattr(app_module,'get_settings',lambda:c.settings)
        monkeypatch.setattr(app_module,'load_signed_public_artifact',lambda _:deepcopy(c.genesis))
        monkeypatch.setattr(app_module,'validate_runtime_environment_namespace',lambda:None)
        monkeypatch.setattr(app_module,'validate_secret_env_file_permissions',lambda:None)
        def hardened(_):raise ReachedHardening()
        monkeypatch.setattr(app_module,'validate_server_hardening_at_startup',hardened)
        with pytest.raises(ReachedHardening):
            async with app_module.lifespan(app_module.app):pass
    finally:close(c)


@pytest.mark.asyncio
async def test_owner_recovery_endpoint_uses_retained_funding_without_caller_hints(tmp_path,monkeypatch):
    from solslot_api import native_purchases, presale_endpoints
    c=await lifecycle_case(tmp_path,monkeypatch)
    try:
        monkeypatch.setattr(native_purchases,'get_payment_purchase_store',lambda _:c.purchases)
        monkeypatch.setattr(native_purchases,'load_signed_public_artifact',lambda _:deepcopy(c.genesis))
        monkeypatch.setattr(presale_endpoints,'get_presale_store',lambda _:c.presales)
        c.settings.minting_enabled=False;c.settings.checkout_lifecycle_worker_enabled=False
        request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node)))
        result=await native_purchases.reconcile_base_checkout_terminal(
            native_purchases.BaseTerminalRecoveryRequest(purchaseId=c.original.purchase_id),request,c.settings,
            'Bearer synthetic-extension-service-token')
        assert result==dict(purchaseId=c.original.purchase_id,observationState='WAITING_FOR_ESCROW_PROOF',complete=False)
        assert c.purchases.base_checkout_hold(c.original.purchase_id)['state']=='ARMED'
        assert c.purchases.checkout_terminal(c.original.purchase_id) is None
        assert not c.funded
    finally:close(c)
