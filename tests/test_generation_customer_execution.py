from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
import sqlite3
import time

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL, SpendBundle
from chia_rs.sized_bytes import bytes32
from eth_account import Account

from solslot_api.generation_customer_context import current_customer_launch_bindings
from solslot_api.generation_customer_execution import (
    prepare_customer_operation, review_document, saved_customer_operation,
    validate_customer_bundle, verify_customer_creation,
)
from solslot_api.generation_customer_launch import CustomerLaunchConsent
from solslot_api.generation_customer_store import GenerationCustomerStore
from solslot_api.generation_index import GenerationIndexReconciler, GenerationIndexStore
from solslot_api.generation_operations import GenerationOperationJournal, canonical
from solslot_api.protocol_submission import PreparedProtocolBundle
from solslot_api.singleton_launcher import launcher_coin_for_parent
from tests.test_generation_customer_launch import fixture, assemble, sign
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete


@pytest.mark.parametrize('auth',['evm','chia_bls'])
def test_review_requires_exact_owner_outputs_and_native_announcement(auth):
    data=fixture(auth);op=assemble(data);consent=data[3];sig=sign(consent,data[4])
    owner,_=consent.verified_owner(sig,1000)
    review=review_document(consent,sig,1000,owner,op.successors[0].coin,100)
    assert validate_customer_bundle(op.bundle(),review)[0]==consent
    for field,value in [('identityVerified',True),('requiresFreshIdCheck',False),
            ('generationId','0x'+'ab'*32),('createdVaultCoinId','0x'+'cd'*32),
            ('custodyPuzzleHash','0x'+'ef'*32),('authorizedAt',consent.expires_at)]:
        changed={**review,field:value}
        with pytest.raises(ValueError):validate_customer_bundle(op.bundle(),changed)
    with pytest.raises(ValueError):
        validate_customer_bundle(SpendBundle([op.spends[0]],op.aggregated_signature),review)
    raw=Program.from_bytes(bytes(op.spends[0].solution))
    conditions=list(raw.as_iter())[1].rest()
    stripped=Program.to([item for item in conditions.as_iter() if item.first().as_int()!=61])
    wrong=make_spend(op.spends[0].coin,Program.from_bytes(bytes(op.spends[0].puzzle_reveal)),
        Program.to([0,Program.to((1,stripped)),0]))
    with pytest.raises(ValueError,match='launcher commitment'):
        validate_customer_bundle(SpendBundle([wrong,op.spends[1]],op.aggregated_signature),review)


@pytest.mark.parametrize('auth',['evm','chia_bls'])
@pytest.mark.asyncio
async def test_native_durable_customer_preparation_confirmation_and_restart(core,tmp_path,monkeypatch,auth):
    c=core
    _,_,built=complete(c)
    assert await c.client.push_tx(built.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    prep=tmp_path/'preparation.json';prep.write_text(c.prep.model_dump_json(by_alias=True))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=c.prep.generation_id,
        generation_preparation_path=str(prep),generation_preparation_hash=c.prep.manifest_hash)
    cache=GenerationIndexStore(str(tmp_path/'index.db'),c.prep.generation_id,'0x'+'26'*32)
    index=GenerationIndexReconciler(built.anchor,cache,c.provider)
    await index.run_once();now=int(time.time())
    bindings=current_customer_launch_bindings(settings,index,now=now)
    funding=min((r.coin for r in await c.client.get_coin_records_by_puzzle_hash(c.faucet.address_puzzle_hash)
        if not r.spent and r.coin.amount>1),key=lambda coin:coin.name())
    key=AugSchemeMPL.key_gen(b'new customer execution test only!') if auth=='chia_bls' else Account.from_key(b'z'*32)
    owner='0x'+bytes(key.get_g1()).hex() if auth=='chia_bls' else key.address
    consent=CustomerLaunchConsent(bindings,bytes32(b'x'*32),owner,auth,funding.name(),launcher_coin_for_parent(funding).name(),now+200)
    store=GenerationCustomerStore(str(tmp_path/'customers.db'),c.prep.generation_id)
    reserved=store.reserve(consent,now=now);identity=reserved['registrationId']
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    args=dict(store=store,journal=journal,settings=settings,index=index,provider=c.provider,
        faucet=c.faucet,maximum_parent_amount=1_000_000_000,clock=lambda:now)
    with pytest.raises(ValueError,match='has not been signed'):
        await prepare_customer_operation(identity,100,**args)
    signature=sign(consent,key);store.accept_signature(identity,signature,now=now)
    prepared=await prepare_customer_operation(identity,100,**args)
    assert prepared['kind']=='CREATE_CUSTOMER_VAULT' and prepared['stage']=='PREPARED'
    bundle=journal.protocol_bundle(prepared['operationId']);original=bytes(bundle)
    with pytest.raises(ValueError,match='fee cap'):
        await prepare_customer_operation(identity,101,**args)
    # Cached progress and recovery of signed work need no node or new signing.
    def never_sign(*a,**k):raise AssertionError('retry must not sign or rebuild')
    monkeypatch.setattr(c.faucet,'sign_delegated_spend',never_sign)
    restarted=GenerationOperationJournal(str(tmp_path/'operations.db'),c.prep.generation_id)
    for _ in range(5):
        assert saved_customer_operation(store,restarted,identity)==prepared
    later={**args,'journal':restarted,'clock':lambda:now+5000}
    assert await prepare_customer_operation(identity,100,**later)==prepared
    assert bytes(restarted.protocol_bundle(prepared['operationId']))==original
    with pytest.raises(ValueError,match='not confirmed'):
        await verify_customer_creation(identity,store=store,journal=restarted,settings=settings,index=index,provider=c.provider)
    # Zero-fee SpendSim dispatch is local only. Production still requires its
    # separate bounded fee policy, native admission and approved submission.
    funded=PreparedProtocolBundle(bundle,0,'0x'+funding.name().hex())
    restarted.save_funded(prepared['operationId'],funded,now)
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    tip=await c.client.get_coin_record_by_name(bytes32.from_hexstr(prepared['review']['createdVaultCoinId']))
    restarted.observed(prepared['operationId'],transaction_id=funded.spend_bundle_id,status='CONFIRMED',confirmed_height=int(tip.confirmed_block_index),now=now+1)
    receipt=await verify_customer_creation(identity,store=store,journal=restarted,settings=settings,index=index,provider=c.provider)
    assert receipt.vault_launcher_id==consent.message()['vaultLauncherId']
    assert receipt.vault_coin_id==prepared['review']['createdVaultCoinId']
    assert receipt.generation_id==c.prep.generation_id
    assert (await c.client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    assert store.status(identity,now=now+2)['identityVerified'] is False
    # A changed stored review cannot become another owner or current account,
    # even if an attacker recomputes only the outer JSON integrity digest.
    changed=deepcopy(prepared['review']);changed['signatureHash']='0x'+'11'*32
    document=canonical(changed)
    with sqlite3.connect(restarted.path) as db:
        db.execute('UPDATE generation_review_documents SET document=?,request_digest=?',
            (document,'0x'+sha256(document.encode()).hexdigest()))
    with pytest.raises(ValueError,match='retained signed consent'):
        saved_customer_operation(store,restarted,identity)
