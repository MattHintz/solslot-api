"""Actual V2 CLVM and synthetic BLS/SQLite/node evidence; no network outcomes."""
import copy
import json
from dataclasses import asdict, replace
from types import SimpleNamespace
import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element, Coin
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api import inventory_expiry_clock as clock
from solslot_api.inventory_authorization_expiry import reconcile_inventory_authorization_expiry, expiry_conditions
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from tests.test_inventory_timeout_recovery import case, record, hx, _b32

NOW = 1_900_000_400


def release_artifact():
    keys = tuple(AugSchemeMPL.key_gen(bytes([i])*32) for i in (1,2,3))
    artifact = dict(network='testnet11', artifactHash=hx(_b32(70)), ceremony=dict(ceremonyId=hx(_b32(71))),
        sourceShas={'api':'a'*40, 'protocol':'b'*40}, launcherIds={'did':hx(_b32(17)), 'pool':hx(_b32(26))},
        bridgePolicy={'policyHash':hx(_b32(27))},
        puzzleHashes={'protocolTreasuryPuzzleHash':hx(_b32(19))},
        validatorSet={'pubkeys':[hx(k.get_g1()) for k in keys], 'threshold':2})
    artifact['inventoryActivation'] = dict(schema='solslot.inventory-activation.v1', network='testnet11',
        environment='staging-alpha', deploymentId=artifact['ceremony']['ceremonyId'], inventoryVersion=2, adapterVersion=1,
        sourceShas=copy.deepcopy(artifact['sourceShas']), reviewEvidenceSha256='ab'*32,
        availableModuleHash=hx(load_puzzle('mint_offer_inventory_available_v2.clsp').get_tree_hash()),
        reservedModuleHash=hx(load_puzzle('mint_offer_delegate_v5.clsp').get_tree_hash()))
    artifact['inventoryRecovery'] = dict(schema='solslot.inventory-recovery.v1', network='testnet11',
        environment='staging-alpha', deploymentId=artifact['ceremony']['ceremonyId'], inventoryVersion=2, adapterVersion=1,
        validatorLedgerVersion=10, minConfirmations=3, sourceShas=copy.deepcopy(artifact['sourceShas']),
        availableModuleHash=artifact['inventoryActivation']['availableModuleHash'], reviewEvidenceSha256='cd'*32,
        historicalArtifactHashes=[])
    return artifact, keys


def expiry_case(tmp_path, monkeypatch, quantity=1, state='PREPARED', inventory_version=2):
    c = case(tmp_path, quantity, state, inventory_version)
    c.artifact, c.keys = release_artifact()
    monkeypatch.setattr(clock.time, 'time', lambda: NOW)
    c.node.blocks = {}
    for n in range(3):
        digest = hx(_b32(80-n))
        c.node.blocks[digest] = dict(height=110-n, header_hash=digest, prev_hash=hx(_b32(79-n)),
            timestamp=c.stored.inventory_expires_at+12-n)
    async def block(digest):
        return dict(success=True, block_record=copy.deepcopy(c.node.blocks.get(digest)))
    c.node.get_block_record = block
    c.node.records.clear(); c.node.spends.clear()
    signatures = []
    for ctx, transition in zip(c.contexts, c.transitions, strict=True):
        spend = transition.spend
        c.node.records[hx(spend.coin.name())] = record(spend.coin, 100)
        launcher = next(Coin(_b32(i), ctx.terms.deed_launcher_puzzle_hash, uint64(1)) for i in range(22,22+quantity)
                        if Coin(_b32(i), ctx.terms.deed_launcher_puzzle_hash, uint64(1)).name() == ctx.purchase.deed_launcher_id)
        c.node.records[hx(launcher.name())] = record(launcher, 99, 100)
        if inventory_version == 1:
            # Historical V1 cannot execute this reservation fixture; the observer
            # must reject its module before relying on any signature or clock.
            signature = G2Element()
        else:
            conditions = conditions_dict_for_solution(Program.from_bytes(bytes(spend.puzzle_reveal)),
                Program.from_bytes(bytes(spend.solution)), 100_000_000)
            pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA['testnet11'])
            pks, msgs = [p[0] for p in pairs], [p[1] for p in pairs]
            signature = AugSchemeMPL.aggregate([AugSchemeMPL.sign(next(k for k in c.keys if k.get_g1()==pk), msg)
                                             for pk,msg in zip(pks,msgs,strict=True)])
        signatures.append(signature)
    bundle = WalletSpendBundle([t.spend for t in c.transitions], AugSchemeMPL.aggregate(signatures))
    # Populate only this synthetic fixture's scratch DB with real local signatures.
    with c.store._connect() as db:
        db.execute('UPDATE payment_purchases SET inventory_bundle_json=?,inventory_signature=? WHERE purchase_id=?',
                   (json.dumps(bundle.to_json_dict(),sort_keys=True,separators=(',',':')),hx(signatures[0]),c.stored.purchase_id))
        for n,sig in enumerate(signatures):
            db.execute('UPDATE payment_purchase_inventory_items SET signature=? WHERE purchase_id=? AND ordinal=?',
                       (hx(sig),c.stored.purchase_id,n))
    c.stored = c.store.get(c.stored.purchase_id)
    return c


async def expire(c, **kwargs):
    return await reconcile_inventory_authorization_expiry(store=c.store,node=c.node,
        purchase_id=c.stored.purchase_id,artifact=c.artifact,environment='staging-alpha',authorize=kwargs.get('authorize',lambda:None))


@pytest.mark.asyncio
@pytest.mark.parametrize('state,quantity',[('PREPARED',1),('PREPARED',2),('SUBMITTED',1),('SUBMITTED',2),('SUBMITTED',100)])
async def test_signed_expiry_is_durable_atomic_and_not_a_release(tmp_path,monkeypatch,quantity,state):
    c=expiry_case(tmp_path,monkeypatch,quantity,state)
    before=asdict(c.stored); items=c.store.inventory_items(c.stored.purchase_id)
    result=await expire(c)
    assert result.inventory_state=='AUTHORIZATION_EXPIRED'
    assert asdict(result)=={**before,'inventory_state':'AUTHORIZATION_EXPIRED'}
    reopened=PaymentPurchaseStore(c.store.path)
    assert all(row.state=='AUTHORIZATION_EXPIRED' for row in reopened.inventory_items(result.purchase_id))
    proof=reopened.inventory_expiry_evidence(result.purchase_id)
    assert len(proof['chainProofs'])==quantity
    assert proof['snapshot']==json.loads(json.dumps(before))
    assert proof['items']==json.loads(json.dumps([asdict(r) for r in items]))
    assert all(p['matureTimestamp']>=c.stored.inventory_expires_at for p in proof['chainProofs'])
    assert reopened.inventory_release_evidence(result.purchase_id) is None
    assert all(reopened.latest_released_inventory(hx(ctx.purchase.deed_launcher_id)) is None for ctx in c.contexts)
    c.store=reopened
    assert await expire(c)==result
    with pytest.raises(PaymentPurchaseConflict):
        reopened.record_inventory_submitted(result.purchase_id,bundle_id=hx(_b32(91)),mempool_observed_at='late')
    with pytest.raises(PaymentPurchaseConflict):
        reopened.record_inventory_confirmed(result.purchase_id,confirmation_height=101)
    # A fresh purchase can bind the same available coin, with a different quote/nonce.
    from solslot_puzzles.stripe_settlement_v1_driver import build_inventory_reservation_spend
    from chia.wallet.lineage_proof import LineageProof
    ctx=c.contexts[0]; old=c.transitions[0].spend.coin
    fresh=replace(ctx.purchase,authorization_nonce=_b32(65),quote_expires_at=NOW+300,authorization_expires_at=NOW+600)
    stored=reopened.save(purchase_intent_id='fresh',rail='chia_xch',offer_artifact_hash='sha256:'+'ef'*32,
                        offer_artifact={},purchase_artifact=purchase_artifact_v3_to_json(fresh),created_at=NOW)
    launcher=c.node.records[hx(old.parent_coin_info)]['coin']
    lineage=LineageProof(parent_name=_b32(int(launcher['parent_coin_info'].removeprefix('0x')[:2],16)),amount=uint64(1))
    transition=build_inventory_reservation_spend(available_coin=old,deed_singleton_struct=ctx.deed_struct,
        lineage_proof=lineage,reservation=replace(ctx.reservation,artifact=fresh,expires_at=NOW+300),signer_indices=(0,1),terms=ctx.terms)
    assert reopened.record_inventory_prepared(stored.purchase_id,available_coin_id=hx(old.name()),
        reserved_coin_id=hx(transition.reserved_coin.name()),reserved_puzzle_hash=hx(transition.reserved_coin.puzzle_hash),
        expires_at=NOW+300,bundle=WalletSpendBundle([transition.spend],G2Element()).to_json_dict(),
        signer_indices=(0,1),signature=hx(G2Element())).inventory_state=='PREPARED'
    assert reopened.inventory_expiry_evidence(result.purchase_id)==proof


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['spent','missing','immature','young_clock','future_clock','nonmonotonic',
    'wrong_hash','wrong_height','bool_height','wrong_prev','bool_time','wrong_network','unsynced','tip_change',
    'second_item','signature','item_signature','v1','environment','artifact','deployment','treasury','roster','did','confirmed'])
async def test_unsafe_evidence_preserves_every_lock(tmp_path,monkeypatch,problem):
    c=expiry_case(tmp_path,monkeypatch,2,inventory_version=1 if problem=='v1' else 2,
                  state='CONFIRMED' if problem=='confirmed' else 'PREPARED')
    coin_id=hx(c.transitions[0].spend.coin.name())
    block=c.node.blocks[hx(_b32(78))]
    if problem=='spent': c.node.records[coin_id].update(spent=True,spent_block_index=109)
    elif problem=='missing': del c.node.records[coin_id]
    elif problem=='immature': c.node.records[coin_id]['confirmed_block_index']=109
    elif problem=='young_clock': block['timestamp']=c.stored.inventory_expires_at-1
    elif problem=='future_clock': c.node.blocks[hx(_b32(80))]['timestamp']=NOW+121
    elif problem=='nonmonotonic': block['timestamp']=c.node.blocks[hx(_b32(79))]['timestamp']
    elif problem=='wrong_hash': block['header_hash']=hx(_b32(2))
    elif problem=='wrong_height': block['height']=107
    elif problem=='bool_height': block['height']=True
    elif problem=='wrong_prev': c.node.blocks[hx(_b32(79))]['prev_hash']=hx(_b32(2))
    elif problem=='bool_time': block['timestamp']=True
    elif problem=='wrong_network': c.node.network='mainnet'
    elif problem=='unsynced':
        original=c.node.get_blockchain_state
        async def state():
            value=await original(); value['blockchain_state']['sync']['synced']=False; return value
        c.node.get_blockchain_state=state
    elif problem=='tip_change': c.node.change_tip=True
    elif problem=='second_item': del c.node.records[hx(c.transitions[1].spend.coin.name())]
    elif problem in {'signature','item_signature'}:
        with c.store._connect() as db:
            if problem=='signature':
                bad={**c.stored.inventory_bundle,'aggregated_signature':hx(G2Element())}
                db.execute('UPDATE payment_purchases SET inventory_bundle_json=?',(json.dumps(bad),))
            else: db.execute('UPDATE payment_purchase_inventory_items SET signature=? WHERE ordinal=1',(hx(G2Element()),))
    elif problem=='environment': c.artifact['inventoryRecovery']['environment']='production-alpha'
    elif problem=='artifact': del c.artifact['inventoryRecovery']
    elif problem=='deployment': c.artifact['inventoryRecovery']['deploymentId']=hx(_b32(1))
    elif problem=='treasury': c.artifact['puzzleHashes']['protocolTreasuryPuzzleHash']=hx(_b32(1))
    elif problem=='roster': c.artifact['validatorSet']['pubkeys'].reverse()
    elif problem=='did': c.artifact['launcherIds']['did']=hx(_b32(1))
    before=c.store.get(c.stored.purchase_id); rows=c.store.inventory_items(c.stored.purchase_id)
    with pytest.raises(PaymentPurchaseConflict): await expire(c)
    assert c.store.get(before.purchase_id)==before
    assert c.store.inventory_items(before.purchase_id)==rows
    assert c.store.inventory_expiry_evidence(before.purchase_id) is None


@pytest.mark.asyncio
async def test_confirmation_race_and_gate_change_cannot_commit_stale_proof(tmp_path,monkeypatch):
    c=expiry_case(tmp_path,monkeypatch,state='SUBMITTED')
    calls=0
    def race():
        nonlocal calls
        calls+=1
        if calls==2: c.store.record_inventory_confirmed(c.stored.purchase_id,confirmation_height=101)
    with pytest.raises(PaymentPurchaseConflict,match='changed'): await expire(c,authorize=race)
    assert c.store.get(c.stored.purchase_id).inventory_state=='CONFIRMED'
    assert c.store.inventory_expiry_evidence(c.stored.purchase_id) is None


@pytest.mark.asyncio
async def test_provider_timeout_preserves_locks(tmp_path,monkeypatch):
    c=expiry_case(tmp_path,monkeypatch)
    async def unavailable(_): raise TimeoutError('synthetic provider timeout')
    c.node.get_block_record=unavailable
    with pytest.raises(TimeoutError): await expire(c)
    assert c.store.get(c.stored.purchase_id)==c.stored


@pytest.mark.asyncio
async def test_expired_bundle_is_never_dispatched(tmp_path,monkeypatch):
    from solslot_api.native_purchases import _submit_inventory_reservation
    from fastapi import HTTPException
    c=expiry_case(tmp_path,monkeypatch)
    with pytest.raises(HTTPException) as error:
        await _submit_inventory_reservation(SimpleNamespace(),SimpleNamespace(),c.store,c.stored)
    assert error.value.status_code==409
    assert c.store.get(c.stored.purchase_id)==c.stored


@pytest.mark.asyncio
async def test_endpoint_token_gates_exact_environment_and_no_client_proof(tmp_path,monkeypatch):
    from solslot_api.config import Settings
    from solslot_api import native_purchases as native
    from fastapi import HTTPException
    from pydantic import ValidationError
    c=expiry_case(tmp_path,monkeypatch)
    settings=Settings(_env_file=None, network='testnet11',runtime_environment='test',alpha_writes_enabled=True,
        minting_enabled=True,protocol_artifact_api_token='synthetic-test-token',payment_purchase_db_path=c.store.path)
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=SimpleNamespace(primary=c.node))))
    payload=native.InventoryReservationRequest(purchaseId=c.stored.purchase_id)
    with pytest.raises(ValidationError): native.InventoryReservationRequest(purchaseId=c.stored.purchase_id,chainProof={})
    with pytest.raises(HTTPException) as exc: await native.reconcile_inventory_expiry(payload,request,settings,'Bearer wrong')
    assert exc.value.status_code in (401,403)
    settings.alpha_writes_enabled=False
    with pytest.raises(HTTPException): await native.reconcile_inventory_expiry(payload,request,settings,'Bearer synthetic-test-token')
    settings.alpha_writes_enabled=True
    monkeypatch.setattr(native,'load_signed_public_artifact',lambda settings:copy.deepcopy(c.artifact))
    # Even synthetic authenticated content cannot activate the wrong runtime environment.
    with pytest.raises(HTTPException) as exc: await native.reconcile_inventory_expiry(payload,request,settings,'Bearer synthetic-test-token')
    assert exc.value.status_code==409
    settings.runtime_environment='staging'
    settings.launch_control_enabled=True
    settings.genesis_db_path=str(tmp_path/'gates.db')
    with pytest.raises(HTTPException): await native.reconcile_inventory_expiry(payload,request,settings,'Bearer synthetic-test-token')
    settings.launch_control_enabled=False  # synthetic environment-only fixture
    result=await native.reconcile_inventory_expiry(payload,request,settings,'Bearer synthetic-test-token')
    assert result['state']=='AUTHORIZATION_EXPIRED'
    assert result['expiryEvidence']['activation']['environment']=='staging-alpha'


@pytest.mark.asyncio
async def test_batch_clock_is_bounded_and_checks_all_hundred_inputs(tmp_path,monkeypatch):
    c=expiry_case(tmp_path,monkeypatch)
    coins=[c.transitions[0].spend.coin]
    for n in range(1,100):
        coin=Coin(_b32(n),_b32(200),uint64(1)); coins.append(coin)
        c.node.records[hx(coin.name())]=record(coin,100)
    reads=[]; original=c.node.get_block_record
    async def block(digest): reads.append(digest); return await original(digest)
    c.node.get_block_record=block
    proofs=await clock.prove_expired_unspent_batch(c.node,coins,c.stored.inventory_expires_at,'testnet11')
    assert len(proofs)==100 and len(reads)==3
    assert len({p['sourceCoinId'] for p in proofs})==100
    c.node.records[hx(coins[-1].name())].update(spent=True,spent_block_index=109)
    with pytest.raises(PaymentPurchaseConflict):
        await clock.prove_expired_unspent_batch(c.node,coins,c.stored.inventory_expires_at,'testnet11')


@pytest.mark.asyncio
async def test_nontransaction_tip_walks_to_mature_transaction_and_rejects_unbounded_history(tmp_path,monkeypatch):
    c=expiry_case(tmp_path,monkeypatch)
    c.node.blocks[hx(_b32(80))]['timestamp']=None
    c.node.blocks[hx(_b32(79))]['timestamp']=None
    assert (await expire(c)).inventory_state=='AUTHORIZATION_EXPIRED'
    # A separate proof with no transaction in the allowed ancestry window never authorizes reuse.
    c.node.blocks[hx(_b32(78))]['timestamp']=None
    monkeypatch.setattr(clock,'MAX_CLOCK_HOPS',3)
    with pytest.raises(PaymentPurchaseConflict,match='bounded'):
        await clock.prove_expired_unspent(c.node,c.transitions[0].spend.coin,c.stored.inventory_expires_at,'testnet11')


@pytest.mark.asyncio
async def test_external_payment_and_late_payment_evidence_keep_inventory_held(tmp_path,monkeypatch):
    c=expiry_case(tmp_path,monkeypatch)
    count=0
    def arrive():
        nonlocal count
        count+=1
        if count==2:
            with c.store._connect() as db:
                db.execute("UPDATE payment_purchases SET external_message_json='{}'")
    with pytest.raises(PaymentPurchaseConflict,match='changed'): await expire(c,authorize=arrive)
    assert c.store.get(c.stored.purchase_id).inventory_state=='PREPARED'
    with pytest.raises(PaymentPurchaseConflict,match='payment'): await expire(c)
    assert c.store.inventory_expiry_evidence(c.stored.purchase_id) is None
