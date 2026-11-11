"""Real native expiry/BLS plus synthetic current evidence and primary node."""
from dataclasses import replace
import json
from time import time
from types import SimpleNamespace

from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL,Coin,G2Element
from chia_rs.sized_bytes import bytes32
import pytest
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,build_inventory_reservation_spend,make_inventory_available_inner)

from solslot_api.generation_customer_issuer import TestnetIssuerPolicy as IssuerPolicy,TestnetIssuerJournal as IssuerJournal
from solslot_api.generation_customer_purchase_policy import (
    validate_purchase_policy_renewal,selected_prior_purchase_policy,selected_purchase_policy)
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim,CurrentReservationEvidence
from solslot_api import generation_customer_purchase_validators as signing
from solslot_api.validator_ledger import ValidatorLedger
from scripts.renew_current_issuer_policy import observe,renew_unused_journal
from tests.test_chia_snapshot import Node,provider
from tests.test_native_purchases import _context,_b32
from tests.test_current_purchase_private_boundary import policy,write_policy


@pytest.fixture
def renewal(tmp_path,monkeypatch):
    now=int(time());keys=tuple(AugSchemeMPL.key_gen(bytes([n])*32)for n in (51,52,53))
    contexts=[_context(AugSchemeMPL.key_gen(b'p'*32),keys,now=now-330,deed_parent_seed=n)[0]for n in (22,23)]
    ctx=contexts[0]
    generation=_b32(1)
    terms_list=[replace(c.terms,inventory_version=4,
        generation_batch_bindings=bytes(Program.to([generation,*[_b32(2)]*7])))for c in contexts]
    terms=terms_list[0]
    old_policy=IssuerPolicy(generation,terms.collection_id,terms.metadata_anchor_id,terms.metadata_root,
        terms.protocol_puzhash,terms.protocol_treasury_puzzle_hash,bytes(keys[2].get_g1()),
        frozenset(t.deed_launcher_id for t in terms_list),ctx.purchase.vault_launcher_id,10**14,2,now-1200,now-20)
    current_policy=replace(old_policy,issued_at=now-10,expires_at=now+600)
    path,pin=write_policy(tmp_path,old_policy.public())
    settings=SimpleNamespace(generation_customer_purchase_enabled=True,deployment_generation_id='0x'+generation.hex(),
        signer_index=0,roster_pubkeys=['0x'+bytes(k.get_g1()).hex()for k in keys],
        generation_customer_purchase_prior_policy_path=str(path),generation_customer_purchase_prior_policy_hash=pin)
    sources=[Coin(t.deed_launcher_id,SINGLETON_MOD.curry(c.deed_struct,make_inventory_available_inner(t)).get_tree_hash(),1)
        for c,t in zip(contexts,terms_list,strict=True)]
    vault=Coin(_b32(61),_b32(62),1)
    def evidence(purchase,grant):
        index=next(i for i,c in enumerate(contexts)if c.purchase.deed_launcher_id==purchase.deed_launcher_id)
        source=sources[index];current_terms=terms_list[index];current_context=contexts[index]
        item=SimpleNamespace(original=SimpleNamespace(terms=current_terms),current=SimpleNamespace(coin=source),
            lineage=LineageProof(parent_name=_b32(22+index),amount=1))
        claim=CurrentReservationClaim(generationId='0x'+generation.hex(),anchorHash='0x'+'aa'*32,
            issuerPolicyHash=grant.commitment,purchaseArtifact=purchase_artifact_v3_to_json(purchase),signedPrice={},
            availableCoinId='0x'+source.name().hex(),currentVaultCoinId='0x'+vault.name().hex(),signerIndices=(0,1))
        reservation=InventoryReservationV1(purchase,purchase.quote_expires_at)
        transition=build_inventory_reservation_spend(available_coin=source,deed_singleton_struct=current_context.deed_struct,
            lineage_proof=item.lineage,reservation=reservation,signer_indices=claim.signer_indices,terms=current_terms)
        return CurrentReservationEvidence(claim,SimpleNamespace(evidence=object()),SimpleNamespace(coin=vault),
            item,reservation,transition,None)
    old=evidence(replace(ctx.purchase,authorization_expires_at=now-25),old_policy)
    fresh=evidence(replace(ctx.purchase,authorization_nonce=_b32(91),quote_expires_at=now+300,
        authorization_expires_at=now+500),current_policy)
    roster=tuple(bytes(k.get_g1())for k in keys)
    old_signature='0x'+bytes(AugSchemeMPL.sign(keys[0],signing.native_messages(old.claim,old.transition,terms,roster)[0])).hex()
    ledger=ValidatorLedger(tmp_path/'native-renewal.db')
    original=dict(claim_hash=old.claim.digest(),canonical_claim=old.claim.canonical(),
        purchase_id='0x'+old.reservation.artifact.purchase_id.hex(),available_coin_id=old.claim.available_coin_id,
        deed_launcher_id='0x'+terms.deed_launcher_id.hex(),signature=old_signature)
    ledger.record_inventory_reservation_or_recover(**original)
    node=Node();node.clock=now
    for coin in (*sources,vault):
        node.records['0x'+coin.name().hex()]={'coin':coin.to_json_dict(),'confirmed_block_index':10,
            'spent_block_index':0,'spent':False}
    transport=provider(node);loads=[]
    async def unchanged(*a,**kw):return True
    monkeypatch.setattr('solslot_api.generation_chain_evidence.current_evidence_unchanged',unchanged)
    def load():loads.append(0);return keys[0]
    async def sign():
        return await signing.sign_verified_current_reservation(fresh,settings=settings,provider=transport,
            ledger=ledger,issuer_policy=current_policy,clock=lambda:now,load_key=load)
    yield SimpleNamespace(now=now,keys=keys,old=old,fresh=fresh,prior=old_policy,current=current_policy,
        settings=settings,ledger=ledger,node=node,provider=transport,loads=loads,sign=sign,original=original,
        contexts=contexts,evidence=evidence)
    ledger.close()


@pytest.mark.asyncio
async def test_batch_signer_reuses_same_pinned_native_retirement_boundary(renewal,monkeypatch):
    from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1,purchase_batch_to_json
    from solslot_api.generation_customer_purchase_batch import CurrentReservationBatch
    from solslot_api import generation_customer_purchase_batch_signing as batches
    r=renewal
    second=replace(r.contexts[1].purchase,authorization_nonce=_b32(91),quote_expires_at=r.now+300,
        authorization_expires_at=r.now+500)
    batch=build_purchase_batch_v1(batch_nonce=_b32(93),artifacts=[r.fresh.reservation.artifact,second])
    children=tuple(r.evidence(a,r.current)for a in batch.artifacts)
    claim=CurrentReservationBatch(purchaseBatch=purchase_batch_to_json(batch),children=tuple(c.claim for c in children))
    async def verified(*a,**kw):return SimpleNamespace(claim=claim,children=children)
    async def fresh(*a,**kw):return None
    monkeypatch.setattr(batches,'verify_current_batch_reservation',verified)
    monkeypatch.setattr('solslot_api.generation_customer_purchase_batch.fresh_children',fresh)
    reply=await batches.sign_batch_reservation(claim,claim.digest(),settings=r.settings,anchor=None,provider=r.provider,
        ledger=r.ledger,issuer_policy=r.current,expected_issuer_policy_hash=r.current.commitment,
        clock=lambda:r.now,load_key=lambda:r.keys[0])
    messages=batches.batch_messages(SimpleNamespace(claim=claim,children=children),tuple(bytes(k.get_g1())for k in r.keys))[0]
    assert AugSchemeMPL.aggregate_verify([r.keys[0].get_g1()]*2,messages,G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
    assert r.ledger.inventory_retirement(r.old.claim.digest())is not None


@pytest.mark.asyncio
async def test_pinned_time_only_renewal_retires_native_signature_atomically_and_recovers(renewal):
    r=renewal;reply=await r.sign()
    message=signing.native_messages(r.fresh.claim,r.fresh.transition,r.fresh.item.original.terms,
        tuple(bytes(k.get_g1())for k in r.keys))[0]
    assert AugSchemeMPL.verify(r.keys[0].get_g1(),message,G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
    assert r.loads==[0]
    assert (await r.sign())==reply and r.loads==[0]
    retirement=json.loads(r.ledger.inventory_retirement(r.old.claim.digest())['evidence_json'])
    assert retirement['priorIssuerPolicyHash']==r.prior.commitment
    assert retirement['issuerPolicyHash']==r.current.commitment
    assert retirement['chainProof']['expiresAt']==r.old.reservation.expires_at
    assert retirement['chainProof']['transactionTimestamp']>=r.old.reservation.expires_at
    assert retirement['chainProof']['spentHeight']==0 and not r.provider.fallback.calls
    row=r.ledger._conn.execute('SELECT canonical_claim,signature FROM inventory_reservation_history WHERE claim_hash=?',
        (r.old.claim.digest(),)).fetchone()
    assert tuple(row)==(r.old.claim.canonical(),r.original['signature'])
    assert r.ledger._conn.execute('SELECT count(*) FROM inventory_reservation_history').fetchone()[0]==2


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['no_prior','bad_pin','wrong_prior','signature','premature','spent'])
async def test_renewal_cannot_bypass_pins_signature_or_native_primary_expiry(renewal,fault):
    r=renewal
    if fault=='no_prior':
        r.settings.generation_customer_purchase_prior_policy_path='';r.settings.generation_customer_purchase_prior_policy_hash=''
    elif fault=='bad_pin':r.settings.generation_customer_purchase_prior_policy_hash='0x'+'00'*32
    elif fault=='wrong_prior':
        path,pin=write_policy(__import__('pathlib').Path(r.settings.generation_customer_purchase_prior_policy_path).parent,
            replace(r.prior,issued_at=r.prior.issued_at-1).public())
        r.settings.generation_customer_purchase_prior_policy_hash=pin
    elif fault=='signature':
        r.ledger._conn.execute('UPDATE inventory_reservation_history SET signature=?',('0x'+bytes(G2Element()).hex(),))
    elif fault=='premature':r.node.clock=r.old.reservation.expires_at-1
    else:r.node.records[r.old.claim.available_coin_id].update(spent=True,spent_block_index=99)
    with pytest.raises(ValueError):await r.sign()
    assert r.loads==[] and r.ledger.inventory_retirement(r.old.claim.digest())is None
    assert r.ledger.active_inventory_authorization(r.old.claim.available_coin_id)['claim_hash']==r.old.claim.digest()


def test_unknown_retained_policy_hash_is_not_admitted_by_a_valid_prior_pin(renewal):
    r=renewal;previous=r.ledger.active_inventory_authorization(r.old.claim.available_coin_id)
    unknown=r.old.claim.model_copy(update={'issuer_policy_hash':'0x'+'ee'*32})
    previous.update(canonical_claim=unknown.canonical(),claim_hash=unknown.digest())
    with pytest.raises(ValueError,match='RETAINED_HISTORY_CHANGED'):
        signing.previous_transition(previous,r.fresh,issuer_policy=r.current,prior_policy=r.prior,now=r.now,
            roster=tuple(bytes(k.get_g1())for k in r.keys),signer_index=0)
    assert r.loads==[]


@pytest.mark.asyncio
async def test_expired_successor_cannot_retire_or_load_a_signing_key(renewal):
    r=renewal
    with pytest.raises(ValueError,match='RENEWAL_SCOPE_CHANGED'):
        await signing.sign_verified_current_reservation(r.fresh,settings=r.settings,provider=r.provider,
            ledger=r.ledger,issuer_policy=r.current,clock=lambda:r.current.expires_at,
            load_key=lambda:r.loads.append('forbidden'))
    assert r.loads==[] and r.ledger.inventory_retirement(r.old.claim.digest())is None


@pytest.mark.parametrize('change',[
    {'buyer_vault':_b32(99)},{'maximum_purchases':2},{'maximum_gross_mojos':10**12+1},
    {'fee_puzzle':_b32(99)},{'proceeds_puzzle':_b32(99)},{'test_usd_minor_per_txch':123},
    {'generation':_b32(99)},{'deed_launchers':frozenset([_b32(99)])},
])
def test_time_only_renewal_cannot_change_financial_scope(change):
    prior=policy();current=replace(prior,issued_at=2001,expires_at=2600,**change)
    with pytest.raises(ValueError):validate_purchase_policy_renewal(prior,current,now=2100)


@pytest.mark.parametrize('issued,expires,now',[(1999,2600,2100),(2001,174802,2100),(2001,2600,2600),(2200,2600,2100)])
def test_renewal_requires_expired_prior_live_current_and_48_hour_bound(issued,expires,now):
    with pytest.raises(ValueError):
        validate_purchase_policy_renewal(policy(),replace(policy(),issued_at=issued,expires_at=expires),now=now)


def test_prior_path_and_pin_must_both_be_present():
    for pair in [('/tmp/public-policy',''),('','0x'+'00'*32)]:
        with pytest.raises(ValueError,match='PIN_REQUIRED'):
            selected_prior_purchase_policy(SimpleNamespace(generation_customer_purchase_prior_policy_path=pair[0],
                generation_customer_purchase_prior_policy_hash=pair[1]),policy(),now=1100)


def test_expired_policy_loader_keeps_read_only_recovery_available(tmp_path):
    prior=policy();current=replace(prior,issued_at=2001,expires_at=2600)
    prior_dir=tmp_path/'prior';prior_dir.mkdir()
    prior_path,prior_pin=write_policy(prior_dir,prior.public())
    current_path,current_pin=write_policy(tmp_path,current.public())
    settings=SimpleNamespace(network='testnet11',generation_customer_purchase_enabled=True,
        deployment_generation_id='0x'+current.generation.hex(),
        generation_customer_purchase_policy_path=str(current_path),generation_customer_purchase_policy_hash=current_pin,
        generation_customer_purchase_prior_policy_path=str(prior_path),generation_customer_purchase_prior_policy_hash=prior_pin)
    assert selected_purchase_policy(settings)==current
    with pytest.raises(ValueError,match='RENEWAL_SCOPE_CHANGED'):
        selected_prior_purchase_policy(settings,current,now=current.expires_at)


@pytest.mark.parametrize('kind',['api','validator'])
@pytest.mark.parametrize('path,pin',[('/tmp/public-policy',''),('','0x'+'00'*32)])
def test_settings_require_a_complete_explicit_prior_pin(tmp_path,kind,path,pin):
    from solslot_api.config import Settings
    from solslot_api.validator_settings import ValidatorSettings
    from tests.test_validator_app import _settings
    from pydantic import ValidationError
    values={'generation_customer_purchase_prior_policy_path':path,'generation_customer_purchase_prior_policy_hash':pin}
    with pytest.raises(ValidationError,match='prior purchase policy requires both'):
        if kind=='api':Settings(_env_file=None,**values)
        else:ValidatorSettings(**{**_settings(tmp_path).model_dump(),**values})


@pytest.fixture
def unused_issuer(tmp_path):
    ledger=ValidatorLedger(tmp_path/'issuer.db');prior=policy();current=replace(prior,issued_at=2001,expires_at=2600)
    guard=IssuerJournal.in_validator_journal(ledger,prior);guard.close();ledger.close()
    return SimpleNamespace(path=tmp_path/'issuer.db',prior=prior,current=current)


def test_stopped_unused_issuer_rebind_preserves_all_other_rows_and_strict_app_binding(unused_issuer):
    r=unused_issuer;before=observe(r.path)
    receipt=renew_unused_journal(r.path,r.prior,r.current,expected_fingerprint=before['journalFingerprint'],
        action_envelope='AE369-test',stopped=lambda:True,now=2100)
    after=observe(r.path)
    assert before['journalFingerprint']==after['journalFingerprint']==receipt['journalFingerprint']
    assert after['commitment']==r.current.commitment and after['forwardingRows']==0
    ledger=ValidatorLedger(r.path)
    IssuerJournal.in_validator_journal(ledger,r.current).close()
    with pytest.raises(ValueError,match='POLICY_CHANGED'):IssuerJournal.in_validator_journal(ledger,r.prior)
    ledger.close()


@pytest.mark.parametrize('fault',['running','restarted','used','changed_fingerprint','wrong_binding','changed_scope'])
def test_unused_issuer_helper_fails_closed_and_keeps_original_binding(unused_issuer,fault):
    import sqlite3
    r=unused_issuer;before=observe(r.path);calls=[]
    def stopped():
        calls.append(1)
        return fault!='running'and not(fault=='restarted'and len(calls)>1)
    if fault=='used':
        with sqlite3.connect(r.path)as db:
            db.execute('INSERT INTO issuer_forwarding VALUES(?,?,?,?,?,?,?,?)',('a','d','c','b','s','m',None,1))
        before=observe(r.path)
    elif fault=='changed_fingerprint':before['journalFingerprint']='0x'+'00'*32
    elif fault=='wrong_binding':r.prior=replace(r.prior,issued_at=999)
    elif fault=='changed_scope':r.current=replace(r.current,maximum_gross_mojos=1_000_001)
    with pytest.raises(ValueError):
        renew_unused_journal(r.path,r.prior,r.current,expected_fingerprint=before['journalFingerprint'],
            action_envelope='AE369-test',stopped=stopped,now=2100)
    assert observe(r.path)['commitment']==policy().commitment
