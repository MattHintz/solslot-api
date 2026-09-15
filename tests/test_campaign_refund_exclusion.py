"""Historical native refund recovery, with actual BLS/CLVM and synthetic ancestry.

The existing voucher and approved vault are fixture inputs, not new XCH sales or
proof of deployment/identity enrollment. HTTP auth and release gates are fixtures.
"""
import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL, Coin, G2Element
from chia_rs.sized_bytes import bytes32
from chia.types.blockchain_format.program import Program, INFINITE_COST
from chia.types.coin_spend import make_spend
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from solslot_api import presale_endpoints as p
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_puzzles.payment_artifacts_v2 import purchase_artifact_to_json
from tests.test_presale_endpoints import native_escrowed_voucher, approved_vault
from tests.test_campaign_continuity import campaign, hx, worker, install_phase_signers
from solslot_api import validator_service as signer
from fastapi import HTTPException


@pytest.mark.parametrize('phase_first', [False, True])
def test_owner_refund_and_phase_are_exclusive_and_lost_refund_push_recovers(campaign, monkeypatch, phase_first):
    c = campaign
    now = 1_900_000_000
    store, terms, _, issuance, _, artifact = native_escrowed_voucher(now=now)
    c.store = store
    c.settings.payment_purchase_db_path = str(c.path / 'historical-purchases.sqlite')
    purchases = PaymentPurchaseStore(c.settings.payment_purchase_db_path)
    purchases.save(purchase_intent_id='historical-native-fixture', rail='chia_xch', offer_artifact_hash=hx(55),
                   offer_artifact={}, purchase_artifact=purchase_artifact_to_json(artifact), created_at=now)
    monkeypatch.setattr(p.time, 'time', lambda: now)
    monkeypatch.setattr(p, 'require_presale_writes', lambda _: None)
    monkeypatch.setattr(p, 'require_operation_gate', lambda *_: None)
    owner = AugSchemeMPL.key_gen(bytes([66] * 32))
    registered = SimpleNamespace(launcher_id=artifact.vault_launcher_id, owner_pubkey=bytes(owner.get_g1()), auth_type=1)
    monkeypatch.setattr(p, 'get_registry', lambda: SimpleNamespace(get=lambda _: registered))
    c.artifact.update(launcherIds={'pool': hx(27)}, bridgePolicy={'policyHash': hx(26)})
    identity = bytes32.from_hexstr(approved_vault().identity_attest_root)
    full = p.puzzle_for_vault_full(registered.launcher_id, registered.owner_pubkey, 1,
        p.one_leaf_merkle_root(registered.owner_pubkey), bytes32.from_hexstr(hx(27)),
        identity_attest_root=identity, zkpassport_bridge_policy_hash=bytes32.from_hexstr(hx(26)))
    parent = Coin(registered.launcher_id, full.get_tree_hash(), 1)
    vault = Coin(parent.name(), full.get_tree_hash(), 1)
    c.node.add(parent, 180)
    c.node.records['0x'+parent.name().hex()].update(spent=True, spent_block_index=181)
    c.node.spends['0x'+parent.name().hex(), 181] = make_spend(parent, full, Program.to([])).to_json_dict()
    c.node.add(vault, 181)
    approved = replace(approved_vault(), current_coin_id='0x'+vault.name().hex())
    monkeypatch.setattr(p, 'require_current_approved_vault', lambda *a, **k: approved)
    monkeypatch.setattr(p, 'verify_vault_session', lambda *a: SimpleNamespace(vault_launcher_id=approved.launcher_id))
    for spend in (issuance.series_spend, issuance.voucher_launcher_spend):
        c.node.add(spend.coin, 189)
        c.node.records['0x'+spend.coin.name().hex()].update(spent=True, spent_block_index=190)
        c.node.spends['0x'+spend.coin.name().hex(), 190] = spend.to_json_dict()
    for coin in (issuance.next_series_coin, issuance.voucher_coin, issuance.payment_coin):
        c.node.add(coin, 190)
    private = install_phase_signers(c, monkeypatch)
    requests = []
    async def competing_phase():
        await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=store,
            series=store.get(terms['termsHash']), transition=p.SeriesTransition.CANCEL)
    async def quorum(settings, claim):
        requests.append(claim)
        # The authenticated owner route has a durable series lease before the
        # first quorum call, so a concurrent admin cannot claim the same input.
        with pytest.raises(ValueError, match='unfinished voucher work'):
            await competing_phase()
        signatures = []
        for i, ledger in enumerate(private.ledgers):
            settings = private.settings(i)
            settings.claim_clock_skew_seconds = 90
            bad = claim.model_copy(update={'owner_authorization': '0x' + bytes(G2Element()).hex()})
            with pytest.raises(signer.ValidatorEvidenceError, match='BLS owner authorization'):
                signer.sign_voucher_transition_claim(settings, ledger, bad, bad.canonical_hash())
            encoded = signer.sign_voucher_transition_claim(settings, ledger, claim, claim.canonical_hash())
            signatures.append(G2Element.from_bytes(bytes.fromhex(encoded[2:])))
        return ValidatorQuorumResult((0,1), AugSchemeMPL.aggregate(signatures), claim.canonical_hash())
    monkeypatch.setattr(p, 'collect_voucher_transition_quorum', quorum)
    async def run():
        values = await p._vault_refund_context(request=c.request, settings=c.settings, approved=approved,
            voucher_launcher_id=issuance.voucher_launcher_id, voucher_coin_id=issuance.voucher_coin.name(), current_timestamp=now)
        spend = values[4]
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, INFINITE_COST)
        pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA['testnet11'])
        assert pairs and all(pk == owner.get_g1() for pk, _ in pairs)
        authorization = AugSchemeMPL.aggregate([AugSchemeMPL.sign(owner, message) for _, message in pairs])
        body = p.CompleteVoucherRefundRequest(vaultCoinId='0x'+vault.name().hex(),
            voucherCoinId='0x'+issuance.voucher_coin.name().hex(), seriesCoinId='0x'+issuance.next_series_coin.name().hex(),
            currentTimestamp=now, ownerAuthorization='0x'+bytes(authorization).hex())
        if phase_first:
            await competing_phase()
            retained = store.pending_campaign_operation(terms['termsHash'])
            assert retained is not None
            with pytest.raises(HTTPException) as rejected:
                await p.complete_voucher_refund(terms['collectionWorkspaceId'], 0, body, c.request, store, c.settings)
            assert rejected.value.status_code == 409 and 'Campaign phase' in str(rejected.value.detail)
            assert not requests and len(c.node.accepted) == 1
            assert store.voucher(terms['termsHash'], 0)['state'] == 'ESCROWED'
            assert not store.pending_voucher_execution(terms['termsHash'], 0)
            return
        # Bad owner authorization must release the series lease and never pin
        # or dispatch a transaction, so the legitimate retry can still proceed.
        bad_body = body.model_copy(update={'owner_authorization': '0x' + bytes(G2Element()).hex()})
        with pytest.raises(HTTPException) as rejected:
            await p.complete_voucher_refund(terms['collectionWorkspaceId'], 0, bad_body, c.request, store, c.settings)
        assert rejected.value.status_code == 409
        assert not c.node.accepted and not store.pending_voucher_execution(terms['termsHash'], 0)
        assert store._conn.execute('SELECT lease_until FROM voucher_worker_series').fetchone()[0] == 0
        c.node.lose_reply = True
        with pytest.raises(TimeoutError):
            await p.complete_voucher_refund(terms['collectionWorkspaceId'], 0, body, c.request, store, c.settings)
        execution = store.pending_voucher_execution(terms['termsHash'], 0)
        assert execution['spendBundle'] == c.node.accepted[0]
        assert store.voucher(terms['termsHash'], 0)['state'] == 'REFUNDING'
        with pytest.raises(ValueError, match='unfinished voucher work'):
            await competing_phase()
        w = worker(c)
        w.purchases = purchases
        outcome = await w.reconcile_once()
        assert outcome[0]['status'] == 'REFUND_CONFIRMING'
        assert c.node.accepted == [execution['spendBundle'], execution['spendBundle']]
        c.node.mine(execution['spendBundle'], 200)
        outcome = await w.reconcile_once()
        assert outcome[0]['status'] == 'REFUNDED'
        assert store.voucher(terms['termsHash'], 0)['state'] == 'REFUNDED'
        assert store.get(terms['termsHash'])['chainState']['refundedCount'] == 1
        assert len(requests) == 1
    try:
        asyncio.run(run())
    finally:
        store._conn.close()
        for ledger in private.ledgers:
            ledger.close()


def test_v1_evm_refund_stops_before_chain_lookup_or_wallet_preview(campaign, monkeypatch):
    c = campaign
    record = SimpleNamespace(auth_type=p.AUTH_TYPE_SECP256K1)
    monkeypatch.setattr(p, 'get_registry', lambda: SimpleNamespace(get=lambda _: record))
    async def forbidden(*args, **kwargs):
        pytest.fail('Unsupported V1 refund must stop before preparing a spend')
    monkeypatch.setattr(p, '_confirmed_coin_and_lineage', forbidden)
    with pytest.raises(ValueError, match='vault version cannot authorize'):
        asyncio.run(p._vault_refund_context(request=c.request, settings=c.settings,
            approved=approved_vault(), voucher_launcher_id=bytes32.from_hexstr(hx(2)),
            voucher_coin_id=bytes32.from_hexstr(hx(3)), current_timestamp=1900000000))
    assert not c.node.accepted


@pytest.mark.parametrize('first', ['phase','terminal','issuance'])
def test_private_signature_domains_cannot_authorize_competing_series_spends(first):
    ledger = ValidatorLedger(':memory:')
    methods = {
        'phase': lambda: ledger.record_voucher_series_phase_or_recover(claim_hash=hx(1),canonical_claim='{}',
            series_coin_id=hx(4),transition=2,signature='fixture-phase'),
        'terminal': lambda: ledger.record_voucher_transition_or_recover(claim_hash=hx(2),canonical_claim='{}',
            series_coin_id=hx(4),global_payment_id=hx(5),voucher_coin_id=hx(6),payment_coin_id=hx(7),signature='fixture-terminal'),
        'issuance': lambda: ledger.record_voucher_issuance_or_recover(claim_hash=hx(3),canonical_claim='{}',
            series_coin_id=hx(4),global_payment_id=hx(5),purchase_launcher_coin_id=hx(8),signature='fixture-issuance'),
    }
    try:
        original = methods[first]()
        assert methods[first]() == original
        for name, call in methods.items():
            if name != first:
                with pytest.raises(ValidatorLedgerConflict):
                    call()
    finally:
        ledger.close()
