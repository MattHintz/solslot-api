"""Synthetic canonical spends and SQLite; no customer chain outcome is implied."""
import copy
from dataclasses import replace
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, lineage_proof_for_coinsol
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_ints import uint64

from solslot_api import native_purchases as native
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json, purchase_batch_to_json, PurchaseBatchV1
from solslot_puzzles.stripe_settlement_v1_driver import (
    make_inventory_available_inner, build_inventory_reservation_spend,
    build_inventory_release_spend, build_inventory_extension_spend,
)
from tests.test_native_purchases import _context, _b32


def hx(value):
    return "0x" + bytes(value).hex()


def record(coin, confirmed=101, spent=0):
    return dict(coin=coin.to_json_dict(), confirmed_block_index=confirmed,
                spent_block_index=spent, spent=bool(spent))


class Node:
    def __init__(self):
        self.records = {}; self.spends = {}; self.height = 110
        self.network = "testnet11"; self.tip_reads = 0; self.change_tip = False

    async def get_coin_record_by_name(self, coin_id):
        return self.records.get(coin_id)

    async def get_puzzle_and_solution(self, coin_id, height):
        return self.spends.get((coin_id, height))

    async def get_network_info(self):
        return dict(success=True, network_name=self.network)

    async def get_blockchain_state(self):
        self.tip_reads += 1
        return dict(success=True, blockchain_state=dict(sync=dict(synced=True, sync_mode=False),
            peak=dict(height=self.height, header_hash=hx(_b32(80 + int(self.change_tip and self.tip_reads > 1))))))


def case(tmp_path, quantity=1, state="CONFIRMED", inventory_version=1):
    keys = tuple(AugSchemeMPL.key_gen(bytes([i]) * 32) for i in (1, 2, 3))
    contexts = [_context(keys[0], keys, deed_parent_seed=22+i, now=1_900_000_000)[0] for i in range(quantity)]
    contexts = [replace(c, terms=replace(c.terms, inventory_version=inventory_version)) for c in contexts]
    contexts.sort(key=lambda c: (bytes(c.purchase.delivery_asset_id), bytes(c.purchase.artifact_hash)))
    store = PaymentPurchaseStore(str(tmp_path / "purchases.db"))
    raw = (purchase_artifact_v3_to_json(contexts[0].purchase) if quantity == 1 else
           purchase_batch_to_json(PurchaseBatchV1(batch_nonce=_b32(63), artifacts=tuple(c.purchase for c in contexts))))
    stored = store.save(purchase_intent_id="test-old", rail="chia_xch", offer_artifact_hash="sha256:" + "11"*32,
                        offer_artifact={"test": True}, purchase_artifact=raw, created_at=1)
    items=[]; transitions=[]; releases=[]; node=Node()
    for ctx in contexts:
        available = Coin(ctx.purchase.deed_launcher_id,
            SINGLETON_MOD.curry(ctx.deed_struct, make_inventory_available_inner(ctx.terms)).get_tree_hash(), uint64(1))
        launcher = next(Coin(_b32(i), ctx.terms.deed_launcher_puzzle_hash, uint64(1)) for i in range(22,22+quantity)
                        if Coin(_b32(i), ctx.terms.deed_launcher_puzzle_hash, uint64(1)).name() == ctx.purchase.deed_launcher_id)
        transition = build_inventory_reservation_spend(available_coin=available, deed_singleton_struct=ctx.deed_struct,
            lineage_proof=LineageProof(parent_name=launcher.parent_coin_info, amount=uint64(1)),
            reservation=ctx.reservation, signer_indices=(0,1), terms=ctx.terms)
        release = build_inventory_release_spend(reserved_coin=transition.reserved_coin, deed_singleton_struct=ctx.deed_struct,
            lineage_proof=lineage_proof_for_coinsol(transition.spend), reservation=ctx.reservation, terms=ctx.terms, timed_out=True)
        node.records[hx(available.name())] = record(available, 100, 101)
        node.records[hx(transition.reserved_coin.name())] = record(transition.reserved_coin, 101, 104)
        node.records[hx(release.next_coin.name())] = record(release.next_coin, 104)
        node.spends[(hx(available.name()),101)] = transition.spend.to_json_dict()
        node.spends[(hx(transition.reserved_coin.name()),104)] = release.spend.to_json_dict()
        items.append(dict(deed_launcher_id=hx(ctx.purchase.deed_launcher_id), available_coin_id=hx(available.name()),
            reserved_coin_id=hx(transition.reserved_coin.name()), reserved_puzzle_hash=hx(transition.reserved_coin.puzzle_hash),
            expires_at=ctx.reservation.expires_at, signer_indices=(0,1), signature="0x"+bytes(G2Element()).hex()))
        transitions.append(transition); releases.append(release)
    stored = store.record_inventory_batch_prepared(stored.purchase_id, items=tuple(items),
        bundle=WalletSpendBundle([t.spend for t in transitions], G2Element()).to_json_dict())
    if state != "PREPARED":
        stored = store.record_inventory_submitted(stored.purchase_id, bundle_id=hx(_b32(90)), mempool_observed_at="synthetic")
    if state == "CONFIRMED":
        stored = store.record_inventory_confirmed(stored.purchase_id, confirmation_height=101)
    return SimpleNamespace(store=store, stored=stored, node=node, contexts=contexts, transitions=transitions, releases=releases)


@pytest.mark.asyncio
async def test_baseline_spent_timeout_leaves_all_database_locks(tmp_path):
    """Retained baseline: the old confirmation path alone cannot recover a timeout."""
    c=case(tmp_path,2)
    with pytest.raises(HTTPException) as raised:
        await native._confirm_inventory_reservation(c.node,c.store,c.stored)
    assert raised.value.status_code == 409
    assert c.store.get(c.stored.purchase_id).inventory_state == "CONFIRMED"
    assert all(i.state == "CONFIRMED" for i in c.store.inventory_items(c.stored.purchase_id))


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["PREPARED", "SUBMITTED", "CONFIRMED"])
@pytest.mark.parametrize("quantity", [1,2])
@pytest.mark.parametrize("inventory_version", [1,2])
async def test_confirmed_timeout_is_atomic_durable_and_preserves_originals(tmp_path,state,quantity,inventory_version):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path,quantity,state,inventory_version)
    result=await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    assert result.inventory_state == "RELEASED"
    assert result.inventory_bundle == c.stored.inventory_bundle
    assert result.purchase_artifact == c.stored.purchase_artifact
    reopened=PaymentPurchaseStore(c.store.path)
    assert all(i.state == "RELEASED" for i in reopened.inventory_items(result.purchase_id))
    for ctx,release in zip(c.contexts,c.releases):
        cursor=reopened.latest_released_inventory(hx(ctx.purchase.deed_launcher_id))
        assert cursor["availableCoinId"] == hx(release.next_coin.name())
    assert await reconcile_timeout_release(reopened,c.node,result.purchase_id,"testnet11") == result


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", ["missing_reserved","missing_successor","missing_spend","wrong_spend","source_spend","source_height","pending","immature","wrong_network","tip_changed","already_used","child_height","spent_flag","second_item"])
async def test_incomplete_or_inconsistent_chain_evidence_retains_whole_batch(tmp_path,problem):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path,2)
    reserved=hx(c.releases[0].spend.coin.name()); child=hx(c.releases[0].next_coin.name())
    if problem == "missing_reserved": del c.node.records[reserved]
    elif problem == "missing_successor": del c.node.records[child]
    elif problem == "missing_spend": del c.node.spends[(reserved,104)]
    elif problem == "wrong_spend": c.node.spends[(reserved,104)]["solution"]="0x80"
    elif problem == "source_spend": c.node.spends[(hx(c.transitions[0].spend.coin.name()),101)]["solution"]="0x80"
    elif problem == "source_height": c.node.records[hx(c.transitions[0].spend.coin.name())]["spent_block_index"]=102
    elif problem == "pending": c.node.records[reserved].update(spent=False,spent_block_index=0)
    elif problem == "immature": c.node.height=105
    elif problem == "wrong_network": c.node.network="mainnet"
    elif problem == "tip_changed": c.node.change_tip=True
    elif problem == "already_used": c.node.records[child].update(spent=True,spent_block_index=105)
    elif problem == "child_height": c.node.records[child]["confirmed_block_index"]=103
    elif problem == "spent_flag": c.node.records[reserved]["spent"]=False
    else: del c.node.records[hx(c.releases[1].next_coin.name())]
    with pytest.raises(PaymentPurchaseConflict):
        await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    assert c.store.get(c.stored.purchase_id).inventory_state == "CONFIRMED"
    assert all(i.state == "CONFIRMED" for i in c.store.inventory_items(c.stored.purchase_id))
    assert c.store.inventory_release_evidence(c.stored.purchase_id) is None


@pytest.mark.asyncio
async def test_outage_preserves_locks(tmp_path):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path)
    async def offline(*_): raise OSError("synthetic outage")
    c.node.get_puzzle_and_solution=offline
    with pytest.raises(OSError): await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    assert c.store.get(c.stored.purchase_id).inventory_state == "CONFIRMED"


def test_validator_independently_accepts_only_canonical_timeout_lineage(tmp_path,monkeypatch):
    from solslot_api import validator_service as vs
    c=case(tmp_path)
    monkeypatch.setattr(vs,"_fetch_coin", lambda _,coin_id,*a,**k: c.node.records[coin_id])
    monkeypatch.setattr(vs,"_fetch_coin_spend", lambda *a: c.releases[0].spend)
    child=c.releases[0].next_coin; ctx=c.contexts[0]
    lineage=vs._verify_released_inventory_parent(None,c.node.records[hx(child.name())],child,ctx.deed_struct,ctx.terms)
    next_reservation=build_inventory_reservation_spend(available_coin=child,deed_singleton_struct=ctx.deed_struct,
        lineage_proof=lineage,reservation=ctx.reservation,signer_indices=(0,1),terms=ctx.terms)
    assert next_reservation.reserved_coin.parent_coin_info == child.name()
    # Actual reservation CLVM execution has a retained, failing release gate in
    # artifacts/validation/reservation-clvm-gate.py. Do not call it proven here.
    tampered=copy.deepcopy(c.node.records[hx(child.name())]); tampered["confirmed_block_index"]=103
    with pytest.raises(vs.ValidatorEvidenceError):
        vs._verify_released_inventory_parent(None,tampered,child,ctx.deed_struct,ctx.terms)


@pytest.mark.parametrize("mode", [5,6,1,3])
def test_release_successor_rejects_failure_extension_and_delivery_modes(tmp_path,mode):
    from solslot_api.inventory_recovery import timeout_successor_lineage
    c=case(tmp_path); spend=c.releases[0].spend; ctx=c.contexts[0]
    solution=Program.from_bytes(bytes(spend.solution)).as_python()
    solution[2][21]=mode
    altered=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(solution))
    with pytest.raises(PaymentPurchaseConflict):
        timeout_successor_lineage(parent_spend=altered,successor=c.releases[0].next_coin,
                                 deed_struct=ctx.deed_struct,terms=ctx.terms)


@pytest.mark.asyncio
async def test_released_cursor_allows_one_new_purchase_and_old_evidence_is_immutable(tmp_path):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path); await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    evidence=c.store.inventory_release_evidence(c.stored.purchase_id)
    changed=copy.deepcopy(evidence); changed["items"][0]["availableCoinId"]=hx(_b32(88))
    with pytest.raises(PaymentPurchaseConflict): c.store.record_inventory_released(c.stored.purchase_id,evidence=changed)
    ctx=c.contexts[0]; child=c.releases[0].next_coin
    from solslot_api.inventory_recovery import timeout_successor_lineage
    lineage=timeout_successor_lineage(parent_spend=c.releases[0].spend,successor=child,deed_struct=ctx.deed_struct,terms=ctx.terms)
    def claim(seed):
        # Build all chia_rs objects on their owning thread.
        fresh=replace(ctx.purchase,authorization_nonce=_b32(seed))
        from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1
        reservation=replace(ctx.reservation,artifact=fresh)
        transition=build_inventory_reservation_spend(available_coin=child,deed_singleton_struct=ctx.deed_struct,
            lineage_proof=lineage,reservation=reservation,signer_indices=(0,1),terms=ctx.terms)
        fresh_stored=c.store.save(purchase_intent_id=f"new-{seed}",rail="chia_xch",offer_artifact_hash="sha256:"+str(seed)*32,
            offer_artifact={},purchase_artifact=purchase_artifact_v3_to_json(fresh),created_at=2)
        return fresh_stored,transition
    a,ta=claim(66); b,tb=claim(67)
    def persist(stored,transition):
        return c.store.record_inventory_prepared(stored.purchase_id,available_coin_id=hx(child.name()),
            reserved_coin_id=hx(transition.reserved_coin.name()),reserved_puzzle_hash=hx(transition.reserved_coin.puzzle_hash),
            expires_at=ctx.reservation.expires_at,bundle=WalletSpendBundle([transition.spend],G2Element()).to_json_dict(),
            signer_indices=(0,1),signature="0x"+bytes(G2Element()).hex())
    assert persist(a,ta).inventory_state == "PREPARED"
    with pytest.raises(PaymentPurchaseConflict): persist(b,tb)


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory_version", [1,2])
async def test_api_context_advances_cursor_and_reserved_lineage_without_rewriting_publication(tmp_path,monkeypatch,inventory_version):
    import json
    from solslot_api.inventory_recovery import reconcile_timeout_release
    from solslot_puzzles.payment_artifacts_v2 import PaymentRail
    from tests.test_single_external_delivery_context import delivery_case
    c=delivery_case(tmp_path,monkeypatch,inventory_version=inventory_version)
    settings=c.worker.settings
    old=await native._load_context_group(settings,c.worker.provider,c.operation.purchase_id,
        require_live=False,allowed_rails=(PaymentRail.STRIPE,))
    ctx=old.contexts[0]
    available=Coin(ctx.purchase.deed_launcher_id,SINGLETON_MOD.curry(ctx.deed_struct,make_inventory_available_inner(ctx.terms)).get_tree_hash(),uint64(1))
    launcher=Coin.from_json_dict(c.records[hx(ctx.purchase.deed_launcher_id)]["coin"])
    original=build_inventory_reservation_spend(available_coin=available,deed_singleton_struct=ctx.deed_struct,
        lineage_proof=LineageProof(parent_name=launcher.parent_coin_info,amount=uint64(1)),
        reservation=ctx.reservation,signer_indices=(0,1),terms=ctx.terms)
    release=build_inventory_release_spend(reserved_coin=original.reserved_coin,deed_singleton_struct=ctx.deed_struct,
        lineage_proof=lineage_proof_for_coinsol(original.spend),reservation=ctx.reservation,terms=ctx.terms,timed_out=True)
    with c.purchases._connect() as db:
        db.execute("UPDATE payment_purchases SET inventory_bundle_json=? WHERE purchase_id=?",
            (json.dumps(WalletSpendBundle([original.spend],G2Element()).to_json_dict()),ctx.stored.purchase_id))
    node=Node(); node.height=132; node.records=copy.deepcopy(c.records)
    node.records[hx(available.name())]=record(available,120,124)
    node.records[hx(original.reserved_coin.name())]=record(original.reserved_coin,124,127)
    node.records[hx(release.next_coin.name())]=record(release.next_coin,127)
    node.spends[(hx(available.name()),124)]=original.spend.to_json_dict()
    node.spends[(hx(original.reserved_coin.name()),127)]=release.spend.to_json_dict()
    await reconcile_timeout_release(c.purchases,node,ctx.stored.purchase_id,"testnet11")
    fresh=replace(ctx.purchase,authorization_nonce=_b32(70))
    stored=c.purchases.save(purchase_intent_id="second-attempt",rail="stripe",offer_artifact_hash="sha256:"+"71"*32,
        offer_artifact=ctx.stored.offer_artifact,purchase_artifact=purchase_artifact_v3_to_json(fresh),created_at=1_900_000_101)
    next_group=await native._load_context_group(settings,node,stored.purchase_id,require_live=False,
        allowed_rails=(PaymentRail.STRIPE,),require_inventory_reservation=False)
    current=next_group.contexts[0]
    assert current.deed_coin == release.next_coin
    assert current.deed_lineage == lineage_proof_for_coinsol(release.spend)
    transition=build_inventory_reservation_spend(available_coin=current.deed_coin,deed_singleton_struct=current.deed_struct,
        lineage_proof=current.deed_lineage,reservation=current.reservation,signer_indices=(0,1),terms=current.terms)
    c.purchases.record_inventory_prepared(stored.purchase_id,available_coin_id=hx(current.deed_coin.name()),
        reserved_coin_id=hx(transition.reserved_coin.name()),reserved_puzzle_hash=hx(transition.reserved_coin.puzzle_hash),
        expires_at=current.reservation.expires_at,bundle=WalletSpendBundle([transition.spend],G2Element()).to_json_dict(),
        signer_indices=(0,1),signature="0x"+bytes(G2Element()).hex())
    c.purchases.record_inventory_submitted(stored.purchase_id,bundle_id=hx(_b32(73)),mempool_observed_at="synthetic")
    c.purchases.record_inventory_confirmed(stored.purchase_id,confirmation_height=130)
    node.records[hx(current.deed_coin.name())]=record(current.deed_coin,127,130)
    node.records[hx(transition.reserved_coin.name())]=record(transition.reserved_coin,130)
    node.spends[(hx(current.deed_coin.name()),130)]=transition.spend.to_json_dict()
    delivered=await native._load_context_group(settings,node,stored.purchase_id,require_live=False,allowed_rails=(PaymentRail.STRIPE,))
    assert delivered.contexts[0].deed_lineage == lineage_proof_for_coinsol(transition.spend)
    assert native.get_collection_store(settings).get("local-dossier")["deeds"][0]["outputCoinId"] == hx(available.name())


@pytest.mark.asyncio
async def test_recovery_endpoint_enforces_token_and_write_gates_and_reports_outage(tmp_path):
    from solslot_api.config import Settings
    c=case(tmp_path)
    settings=Settings(_env_file=None,network="testnet11",runtime_environment="test",alpha_writes_enabled=True,
        minting_enabled=True,protocol_artifact_api_token="synthetic-test-token",payment_purchase_db_path=c.store.path)
    payload=native.InventoryReservationRequest(purchaseId=c.stored.purchase_id)
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=c.node)))
    with pytest.raises(HTTPException) as bad_token:
        await native.reconcile_inventory_timeout(payload,request,settings,"Bearer wrong")
    assert bad_token.value.status_code in (401,403)
    settings.alpha_writes_enabled=False
    with pytest.raises(HTTPException):
        await native.reconcile_inventory_timeout(payload,request,settings,"Bearer synthetic-test-token")
    settings.alpha_writes_enabled=True
    async def offline(*_): raise OSError("synthetic provider outage")
    c.node.get_network_info=offline
    with pytest.raises(HTTPException) as outage:
        await native.reconcile_inventory_timeout(payload,request,settings,"Bearer synthetic-test-token")
    assert outage.value.status_code==503
    assert c.store.get(c.stored.purchase_id).inventory_state=="CONFIRMED"


@pytest.mark.asyncio
async def test_concurrent_reconciliation_and_second_item_failure_commit_no_partial_state(tmp_path):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path,2)
    await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    evidence=c.store.inventory_release_evidence(c.stored.purchase_id)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda _: PaymentPurchaseStore(c.store.path).record_inventory_released(c.stored.purchase_id,evidence=evidence).inventory_state,range(8)))
    assert results==["RELEASED"]*8


@pytest.mark.asyncio
@pytest.mark.parametrize("nonce", [bytes([99])*32, bytes([0xff])*32])
async def test_equivalent_permissionless_timeout_nonce_preserves_canonical_evidence(tmp_path,nonce):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path)
    spend=c.releases[0].spend
    solution=Program.from_bytes(bytes(spend.solution)).as_python(); solution[2][20]=nonce
    alternate=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(solution))
    def conditions(sp):
        return Program.from_bytes(bytes(sp.puzzle_reveal)).run_with_cost(11_000_000_000,Program.from_bytes(bytes(sp.solution)))[1]
    assert conditions(spend) == conditions(alternate)
    c.node.spends[(hx(spend.coin.name()),104)]=alternate.to_json_dict()
    result=await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    assert result.inventory_state=="RELEASED"
    assert c.store.inventory_release_evidence(result.purchase_id)["items"][0]["releaseSpend"]==alternate.to_json_dict()


@pytest.mark.asyncio
@pytest.mark.parametrize("position,value",[(20,b"short"),(21,b"\x05"),(19,bytes([77])*32),(30,b"\x01")])
async def test_timeout_equivalence_never_normalizes_committed_or_mode_fields(tmp_path,position,value):
    from solslot_api.inventory_recovery import reconcile_timeout_release
    c=case(tmp_path); spend=c.releases[0].spend
    solution=Program.from_bytes(bytes(spend.solution)).as_python();solution[2][position]=value
    c.node.spends[(hx(spend.coin.name()),104)]=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(solution)).to_json_dict()
    with pytest.raises(PaymentPurchaseConflict): await reconcile_timeout_release(c.store,c.node,c.stored.purchase_id,"testnet11")
    assert c.store.get(c.stored.purchase_id).inventory_state=="CONFIRMED"
