"""Real current-context builders with synthetic chain ancestry and HTTP identity."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend

from solslot_api import presale_endpoints as p, voucher_refund_review as review, state
from solslot_api.payment_purchase_store import PaymentPurchaseStore
from solslot_puzzles.payment_artifacts_v2 import purchase_artifact_to_json
from tests.test_presale_endpoints import native_escrowed_voucher, approved_vault
from tests.test_redemption_review_execution import Primary
from tests.test_chia_snapshot import provider


async def setup(monkeypatch, tmp_path, *, stripe=False):
    now = 1_900_000_000
    monkeypatch.setattr(p.time, 'time', lambda: now)
    if stripe:
        from tests.test_stripe_refund_lifecycle import escrowed
        store,terms,issuance,purchase=escrowed(now)
    else:
        store, terms, _, issuance, _, purchase = native_escrowed_voucher(now=now)
    settings = SimpleNamespace(network='testnet11', zkpassport_validator_threshold=2,
        payment_purchase_db_path=str(tmp_path / 'purchases.sqlite'))
    from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
    PaymentPurchaseStore(settings.payment_purchase_db_path).save(purchase_intent_id='synthetic-refund', rail='stripe' if stripe else 'chia_xch',
        offer_artifact_hash='0x'+'55'*32, offer_artifact={}, purchase_artifact=(purchase_artifact_v3_to_json(purchase) if stripe else purchase_artifact_to_json(purchase)), created_at=now)
    owner = AugSchemeMPL.key_gen(bytes([66]*32))
    registered = SimpleNamespace(launcher_id=purchase.vault_launcher_id, owner_pubkey=bytes(owner.get_g1()), auth_type=1)
    monkeypatch.setattr(state, 'get_registry', lambda: SimpleNamespace(get=lambda _: registered))
    monkeypatch.setattr(p, 'get_registry', state.get_registry)
    hx = lambda n: '0x'+bytes([n]*32).hex()
    artifact = dict(artifactHash=hx(25),launcherIds={'pool':hx(27)}, bridgePolicy={'policyHash':hx(26)}, network='testnet11',
        validatorSet={'threshold':2, 'pubkeys':terms['validatorPubkeys']})
    monkeypatch.setattr(p, 'load_signed_public_artifact', lambda _: artifact)
    monkeypatch.setattr(review, 'load_signed_public_artifact', lambda _: artifact)
    identity = bytes32.from_hexstr(approved_vault().identity_attest_root)
    full = p.puzzle_for_vault_full(registered.launcher_id, registered.owner_pubkey, 1,
        p.one_leaf_merkle_root(registered.owner_pubkey), bytes32.from_hexstr(hx(27)),
        identity_attest_root=identity, zkpassport_bridge_policy_hash=bytes32.from_hexstr(hx(26)))
    parent = Coin(registered.launcher_id, full.get_tree_hash(), 1)
    vault = Coin(parent.name(), full.get_tree_hash(), 1)
    node = Primary()
    node.clock = now
    parent_spends = [make_spend(parent, full, Program.to([])), issuance.series_spend, issuance.voucher_launcher_spend]
    for spend in parent_spends:
        name = review.hx(spend.coin.name())
        node.records[name] = dict(coin=spend.coin.to_json_dict(), confirmed_block_index=10, spent_block_index=11, spent=True)
        node.spends[name] = spend.to_json_dict()
    for coin in (vault, issuance.next_series_coin, issuance.voucher_coin, issuance.receipt_coin if stripe else issuance.payment_coin):
        node.records[review.hx(coin.name())] = dict(coin=coin.to_json_dict(), confirmed_block_index=11, spent_block_index=0, spent=False)
    approved = replace(approved_vault(), current_coin_id=review.hx(vault.name()))
    monkeypatch.setattr(p, 'require_current_approved_vault', lambda *a, **k: approved)
    monkeypatch.setattr(review, 'require_current_approved_vault', p.require_current_approved_vault)
    session = SimpleNamespace(vault_launcher_id=approved.launcher_id, owner_key=review.hx(owner.get_g1()), auth_type='chia_bls',
        network='testnet11', session_id='synthetic-refund-session', expires_at=now+1800)
    monkeypatch.setattr(p, 'verify_vault_session', lambda *a: session)
    monkeypatch.setattr(review, 'verify_vault_session', p.verify_vault_session)
    monkeypatch.setattr(p, 'require_presale_writes', lambda *_: None)
    monkeypatch.setattr(p, 'require_operation_gate', lambda *_: None)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=provider(node))))
    if stripe:
        from solslot_api.faucet import Faucet
        from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
        faucet=Faucet.from_seed_hex('77'*32,'testnet11')
        fee=Coin(bytes32(bytes([80])*32),faucet.address_puzzle_hash,10000)
        node.records[review.hx(fee.name())]=dict(coin=fee.to_json_dict(),confirmed_block_index=10,spent_block_index=0,spent=False)
        async def fee_coins(*args,**kwargs):return [node.records[review.hx(fee.name())]]
        node.get_coin_records_by_puzzle_hash=fee_coins
        request.app.state.protocol_submitter=ProtocolBundleSubmitter(provider=request.app.state.coinset,faucet=faucet,
            policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,maximum_mojos=10000))
    prepared = await p.request_voucher_refund(terms['termsHash'], 0, request, store, settings, 'refund-review-v1')
    return SimpleNamespace(prepared=prepared.model_dump(by_alias=True, exclude_unset=True), store=store, node=node,
        settings=settings, request=request, session=session, artifact=artifact, owner=owner, vault=vault, terms=terms, approved=approved)


@pytest.mark.asyncio
async def test_native_review_has_all_exact_executable_inputs_and_no_owner_or_validator_signatures(monkeypatch, tmp_path):
    c = await setup(monkeypatch, tmp_path)
    try:
        evidence = c.prepared['reviewEvidence']
        assert [s['role'] for s in evidence['coinSpends']] == ['vault','series','voucher','payment']
        assert evidence['protocolFeeMojos'] == '0'
        assert evidence['consensusValidated'] is False
        assert evidence['currentStateEvidence']['binding']['sessionFingerprint'] == review.vault_session_fingerprint(c.session.session_id)
        assert len(evidence['currentStateEvidence']['inputs']) == 4
        assert len(c.prepared['coinSpends']) == 1
        assert 'aggregatedSignature' not in json.dumps(evidence)
    finally:
        c.store._conn.close()


if __name__ == '__main__':
    import asyncio, sys, tempfile
    from pathlib import Path
    async def export():
        with pytest.MonkeyPatch.context() as patch, tempfile.TemporaryDirectory() as folder:
            c = await setup(patch, Path(folder))
            selected = c.store.voucher(c.terms['termsHash'], 0)
            selected.update(termsHash=c.terms['termsHash'], seriesSingletonId=c.terms['seriesSingletonId'],
                collectionId=c.terms['collectionId'], seriesState='PRESALE', refundDeadline=c.terms['refundDeadline'])
            from solslot_puzzles.voucher_presale_v2_driver import series_mod, voucher_inner_mod, escrow_mod, burn_inner_hash, base_result_authorization_mod
            vector = dict(synthetic=True, intent=c.prepared, selected=selected, artifact=c.artifact,
                session=dict(authType='chia_bls', address=c.session.owner_key, vaultLauncherId=c.session.vault_launcher_id, network='testnet11'),
                vault=dict(confirmed=True,current_coin_id=review.hx(c.vault.name()),vault_full_puzhash=review.hx(c.vault.puzzle_hash),identity_attest_root=c.approved.identity_attest_root),
                modules=dict(series=review.hx(series_mod().get_tree_hash()), voucher=review.hx(voucher_inner_mod().get_tree_hash()),
                    payment=review.hx(escrow_mod().get_tree_hash()),burn=review.hx(burn_inner_hash()),baseResult=review.hx(base_result_authorization_mod().get_tree_hash())))
            Path(sys.argv[1]).write_text(json.dumps(vector, sort_keys=True, separators=(',',':'))+'\n')
            c.store._conn.close()
    asyncio.run(export())
