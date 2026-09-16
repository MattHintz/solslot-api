"""Fresh signer requests, actual BLS/CLVM and synthetic independent node RPC."""
import asyncio
import copy
import json
import sqlite3
from dataclasses import replace
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import httpx
import pytest
from chia_rs import AugSchemeMPL, Coin, G2Element
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_ints import uint64
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import inventory_reservation_message
from solslot_puzzles.vault_driver import puzzle_for_vault_full, one_leaf_merkle_root, DEFAULT_IDENTITY_ATTEST_ROOT
from solslot_api import validator_service as service
from solslot_api.validator_quorum import InventoryReservationClaim
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from tests.test_inventory_authorization_expiry import expiry_case, NOW, hx, _b32, record


def signer_case(tmp_path,monkeypatch,inventory_version=2):
    c=expiry_case(tmp_path,monkeypatch,inventory_version=inventory_version)
    c.settings=SimpleNamespace(network='testnet11',deployment_environment='staging-alpha',signer_index=0,
        roster_pubkeys=c.artifact['validatorSet']['pubkeys'],coinset_base_url='https://validator-node.invalid')
    c.ledger=ValidatorLedger(tmp_path/'signatures.db')
    ctx=c.contexts[0]; coin=c.transitions[0].spend.coin
    launcher=Coin(_b32(65),SINGLETON_LAUNCHER_HASH,uint64(1))
    c.node.records[hx(launcher.name())]=record(launcher,98,99)
    from solslot_puzzles.vault_driver import puzzle_for_p2_vault
    ctx=replace(ctx,purchase=replace(ctx.purchase,vault_launcher_id=launcher.name(),
        vault_p2_puzzle_hash=puzzle_for_p2_vault(launcher.name()).get_tree_hash()))
    owner=bytes(c.keys[0].get_g1())
    def vault(root):
        return puzzle_for_vault_full(ctx.purchase.vault_launcher_id,owner,1,one_leaf_merkle_root(owner),_b32(26),
                                    identity_attest_root=root,zkpassport_bridge_policy_hash=_b32(27))
    parent=Coin(ctx.purchase.vault_launcher_id,vault(DEFAULT_IDENTITY_ATTEST_ROOT).get_tree_hash(),uint64(1))
    credential=Coin(parent.name(),vault(ctx.purchase.zkpassport_root).get_tree_hash(),uint64(1))
    c.node.records[hx(parent.name())]=record(parent,99,100)
    c.node.records[hx(credential.name())]=record(credential,100)
    def claim(purchase,expires):
        reservation=replace(ctx.reservation,artifact=purchase,expires_at=expires)
        return InventoryReservationClaim(network='testnet11',genesis_artifact_hash=c.artifact['artifactHash'],
            purchase_artifact=purchase_artifact_v3_to_json(purchase),available_coin_id=hx(coin.name()),available_puzzle_hash=hx(coin.puzzle_hash),
            smart_deed_inner_hash=hx(ctx.terms.smart_deed_inner_hash),protocol_puzzle_hash=hx(purchase.protocol_treasury_puzzle_hash),
            reservation_expires_at=expires,validator_message=hx(inventory_reservation_message(available_coin=coin,reservation=reservation)),
            credential_vault_coin_id=hx(credential.name()),credential_identity_root=hx(purchase.zkpassport_root),
            credential_policy_version=2,credential_bridge_policy_hash=hx(_b32(27)),credential_owner_auth_type=1,credential_owner_key=hx(owner))
    c.old=claim(ctx.purchase,ctx.reservation.expires_at)
    c.new=claim(replace(ctx.purchase,authorization_nonce=_b32(66),quote_expires_at=NOW+300,authorization_expires_at=NOW+600),NOW+300)
    c.old_kwargs=dict(claim_hash=c.old.canonical_hash(),canonical_claim=service.canonical_inventory_reservation_claim_json(c.old),
        purchase_id=c.old.purchase_id(),available_coin_id=c.old.available_coin_id,
        signature=hx(AugSchemeMPL.sign(c.keys[0],c.old.signature_message())))
    c.ledger.record_inventory_reservation_or_recover(**c.old_kwargs)
    # Authentication boundary is synthetic; the full verifier and its independent RPC parsing run below.
    monkeypatch.setattr(service,'load_validator_artifact',lambda settings:(copy.deepcopy(c.artifact),None))
    monkeypatch.setattr(service,'load_validator_private_key',lambda settings:c.keys[0])
    c.requests=[]
    def handler(request):
        assert str(request.url).startswith('https://validator-node.invalid/')
        c.requests.append(request.url.path)
        args=json.loads(request.content)
        if request.url.path=='/get_coin_record_by_name':
            value={'success':True,'coin_record':copy.deepcopy(c.node.records.get(args['name']))}
        elif request.url.path=='/get_network_info': value=asyncio.run(c.node.get_network_info())
        elif request.url.path=='/get_blockchain_state': value=asyncio.run(c.node.get_blockchain_state())
        elif request.url.path=='/get_block_record': value=asyncio.run(c.node.get_block_record(args['header_hash']))
        else: raise AssertionError(request.url.path)
        return httpx.Response(200,json=value)
    original=httpx.Client
    monkeypatch.setattr(httpx,'Client',lambda **kwargs:original(transport=httpx.MockTransport(handler),**kwargs))
    return c


def sign(c): return service.sign_inventory_reservation_claim(c.settings,c.ledger,c.new,c.new.canonical_hash())


def test_partial_quorum_can_retire_then_sign_fresh_claim_and_survive_restart(tmp_path,monkeypatch):
    c=signer_case(tmp_path,monkeypatch)
    # Only this validator had issued an old signature: no complete API receipt is needed.
    signature=sign(c)
    assert AugSchemeMPL.verify(c.keys[0].get_g1(),c.new.signature_message(),G2Element.from_bytes(bytes.fromhex(signature[2:])))
    assert '/get_block_record' in c.requests and '/get_network_info' in c.requests
    assert c.ledger.active_inventory_authorization(c.new.available_coin_id)['claim_hash']==c.new.canonical_hash()
    evidence=c.ledger.inventory_retirement(c.old.canonical_hash())
    assert evidence['replacement_claim_hash']==c.new.canonical_hash()
    assert json.loads(evidence['evidence_json'])['chainProof']['matureTimestamp']>=c.old.reservation_expires_at
    c.ledger.close(); c.ledger=ValidatorLedger(tmp_path/'signatures.db')
    assert sign(c)==signature
    assert c.ledger.inventory_retirement(c.old.canonical_hash())==evidence
    with pytest.raises(ValidatorLedgerConflict,match='retired'):
        c.ledger.record_inventory_reservation_or_recover(**c.old_kwargs)
    with pytest.raises(service.ValidatorEvidenceError):
        service.sign_inventory_reservation_claim(c.settings,c.ledger,c.old,c.old.canonical_hash())
    c.ledger.close()


@pytest.mark.parametrize('problem',['v1','young','spent','network','tip','environment','activation','history',
                                  'signature','canonical','old_message','old_deadline','treasury','roster','lineage','new_owner'])
def test_validator_independently_rejects_unsafe_retirement(tmp_path,monkeypatch,problem):
    c=signer_case(tmp_path,monkeypatch,inventory_version=1 if problem=='v1' else 2)
    if problem=='young': c.node.blocks[hx(_b32(78))]['timestamp']=c.old.reservation_expires_at-1
    elif problem=='spent': c.node.records[c.old.available_coin_id].update(spent=True,spent_block_index=101)
    elif problem=='network': c.node.network='mainnet'
    elif problem=='tip': c.node.change_tip=True
    elif problem=='environment': c.settings.deployment_environment='production-alpha'
    elif problem=='activation': del c.artifact['inventoryRecovery']
    elif problem=='history': c.artifact['artifactHash']=hx(_b32(99)); c.new=c.new.model_copy(update={'genesis_artifact_hash':c.artifact['artifactHash']})
    elif problem=='signature': c.ledger._conn.execute('UPDATE inventory_reservation_history SET signature=?',(hx(G2Element()),))
    elif problem=='canonical': c.ledger._conn.execute("UPDATE inventory_reservation_history SET canonical_claim='{}'")
    elif problem in {'old_message','old_deadline'}:
        raw=c.old.model_dump(); raw['validator_message' if problem=='old_message' else 'reservation_expires_at']=hx(_b32(1)) if problem=='old_message' else NOW+900
        c.ledger._conn.execute('UPDATE inventory_reservation_history SET canonical_claim=?',(json.dumps(raw,sort_keys=True,separators=(',',':')),))
    elif problem=='treasury': c.artifact['puzzleHashes']['protocolTreasuryPuzzleHash']=hx(_b32(1))
    elif problem=='roster': c.artifact['validatorSet']['pubkeys'].reverse()
    elif problem=='lineage': c.node.records[hx(c.contexts[0].purchase.deed_launcher_id)]['spent_block_index']=98
    elif problem=='new_owner': c.new=c.new.model_copy(update={'credential_owner_key':hx(c.keys[1].get_g1())})
    before=c.ledger.active_inventory_authorization(c.old.available_coin_id)
    with pytest.raises(service.ValidatorEvidenceError): sign(c)
    assert c.ledger.active_inventory_authorization(c.old.available_coin_id)==before
    assert c.ledger.inventory_retirement(c.old.canonical_hash()) is None
    c.ledger.close()


def test_reviewed_historical_artifact_is_explicit_not_implicit(tmp_path,monkeypatch):
    c=signer_case(tmp_path,monkeypatch)
    c.artifact['inventoryRecovery']['historicalArtifactHashes']=[c.old.genesis_artifact_hash]
    c.artifact['artifactHash']=hx(_b32(99))
    c.new=c.new.model_copy(update={'genesis_artifact_hash':c.artifact['artifactHash']})
    assert sign(c)
    c.ledger.close()


def test_v9_migration_preserves_exact_original_bytes_and_never_recycles_purchase(tmp_path):
    path=tmp_path/'old.db'
    original=('0x'+'11'*32,'{"old":"exact"}','0x'+'22'*32,'0x'+'33'*32,'0x'+'44'*96,123)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE inventory_reservation_signatures (claim_hash TEXT PRIMARY KEY, canonical_claim TEXT NOT NULL, purchase_id TEXT UNIQUE NOT NULL, available_coin_id TEXT UNIQUE NOT NULL, signature TEXT NOT NULL, signed_at INTEGER NOT NULL)')
        db.execute('INSERT INTO inventory_reservation_signatures VALUES (?,?,?,?,?,?)',original)
        db.execute('PRAGMA user_version=9')
    ledger=ValidatorLedger(path)
    assert tuple(ledger._conn.execute('SELECT * FROM inventory_reservation_signatures').fetchone())==original
    assert tuple(ledger._conn.execute('SELECT * FROM inventory_reservation_history').fetchone())==original
    assert ledger.active_inventory_authorization(original[3])['signature']==original[4]
    new=dict(claim_hash='0x'+'55'*32,canonical_claim='{"new":1}',purchase_id='0x'+'66'*32,available_coin_id=original[3],signature='0x'+'77'*96)
    evidence=dict(schema='solslot.validator-inventory-retirement.v1',claimHash=original[0],replacementClaimHash=new['claim_hash'],sourceCoinId=original[3])
    assert ledger.record_inventory_reservation_or_recover(**new,retire_claim_hash=original[0],retirement_evidence=evidence)==new['signature']
    with pytest.raises(ValidatorLedgerConflict):
        ledger.record_inventory_reservation_or_recover(**{**new,'claim_hash':'0x'+'88'*32,'purchase_id':original[2],'available_coin_id':'0x'+'99'*32})
    assert tuple(ledger._conn.execute('SELECT * FROM inventory_reservation_signatures').fetchone())==original
    ledger.close()


def test_concurrent_retirement_has_one_winner_and_stale_proof_rolls_back(tmp_path):
    path=tmp_path/'race.db'; first=ValidatorLedger(path)
    original=dict(claim_hash='old',canonical_claim='{}',purchase_id='purchase-old',available_coin_id='coin',signature='old-sig')
    first.record_inventory_reservation_or_recover(**original); first.close()
    def attempt(n):
        ledger=ValidatorLedger(path)
        try:
            new={**original,'claim_hash':f'new-{n}','purchase_id':f'purchase-{n}','signature':f'sig-{n}'}
            evidence=dict(schema='solslot.validator-inventory-retirement.v1',claimHash='old',replacementClaimHash=new['claim_hash'],sourceCoinId='coin')
            return ledger.record_inventory_reservation_or_recover(**new,retire_claim_hash='old',retirement_evidence=evidence)
        except ValidatorLedgerConflict: return 'conflict'
        finally: ledger.close()
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(attempt,[1,2]))
    assert results.count('conflict')==1
    ledger=ValidatorLedger(path)
    assert ledger._conn.execute('SELECT count(*) FROM inventory_reservation_history').fetchone()[0]==2
    assert ledger._conn.execute('SELECT count(*) FROM inventory_reservation_retirements').fetchone()[0]==1
    assert ledger.healthcheck()
    ledger.close()
