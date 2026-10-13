"""Durable lifecycle faults; native economics have a separate consensus suite."""
import asyncio
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin,G2Element
from solslot_puzzles.generation_transactions import NativeOperation
from solslot_api.generation_operations import GenerationOperationJournal,canonical,bundle_id,submit_saved_operation
from solslot_api.generation_sols_batch_routes import router
from solslot_api.generation_sols_batch_recovery import release_batch_quote
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy,PreparedProtocolBundle,ProtocolSubmissionError
from solslot_api.generation_storage import generation_path
from solslot_api.faucet import Faucet
from solslot_api.config import get_settings
from solslot_api.admin_auth import require_admin_jwt
from tests.test_generation_sols_orders import book,offer,h,GEN,DEST
from tests.test_approval_repair import admission_quote


def saved_batch(tmp_path,*,expiry=None,funded=False):
    now=int(time.time());expiry=expiry or now-10
    b=book(tmp_path);source=offer(expires=now+7200);key='0x'+'a1'*32
    order=b.place(source,payment_asset=None,destination=DEST,now=now,receipt_key=key)
    journal=GenerationOperationJournal(str(tmp_path/'ops.db'),GEN)
    puzzle=Program.to(1);coin=Coin(h(81),puzzle.get_tree_hash(),100)
    spend=make_spend(coin,puzzle,Program.to([[51,h(82),100],[85,expiry]]))
    native=NativeOperation(h(1),'PRIMARY_SOLS_BATCH',(spend,),tuple(Coin(h(83+i),h(90+i),1) for i in range(3)),(Coin(h(86),h(96),1),),G2Element())
    doc={'generationId':GEN,'kind':'PRIMARY_SOLS_BATCH','requestKey':'sols-batch:'+'ab'*32,'feeCapMojos':10,
        'batchCommitment':'0x'+h(6).hex(),'primaryCoinId':'0x'+coin.name().hex(),'primaryCoinIds':['0x'+coin.name().hex()],
        'orderIds':[order['orderId']],'buyers':[{'orderId':order['orderId'],'destinationInnerHash':order['destinationInnerHash'],
            'paymentAmount':order['paymentAmount'],'minimumSolsAmount':order['solsAmount']}],
        'backingCoinId':'0x'+native.auxiliary_outputs[0].name().hex(),'backingCoinIds':['0x'+native.auxiliary_outputs[0].name().hex()],
        'issuanceBackingMojos':'123','paymentAmount':'101','feeAllocations':['100','0','1'],'expiresAt':expiry,'priceRoundHash':'0x'+h(7).hex()}
    identity=journal.prepare(native,doc['requestKey'],10,now,request_digest='0x'+sha256(canonical(doc).encode()).hexdigest(),request_document=doc)
    b.repair_saved_links(journal)
    faucet=Faucet.from_seed_hex('01'*32,'testnet11')
    class Node:
        observation=None;inputs_known=True;pending=False;spent=False;matches=False;quotes=0;change_peak=False
        async def get_network_info_primary(self):return {'network_name':'testnet11'}
        async def get_fee_estimate(self,**kw):
            self.quotes+=1
            return {**admission_quote(),**({'peak_height':4_800_000+self.quotes} if self.change_peak else {})}
        async def primary_expiry_input_evidence(self,bundle,*,height):
            if not self.inputs_known or self.pending:return None
            return [{'coinId':'0x'+coin.name().hex(),'confirmedHeight':1,'spentHeight':2 if self.spent else 0,'matchesSavedSpend':self.matches}]
        async def observe_exact_protocol_bundle(self,_):return self.observation
        async def get_coin_record_by_name_primary(self,_):
            owner=source._bundle.coin_spends[0].coin
            return {'coin':owner.to_json_dict(),'confirmed_block_index':1,'spent_block_index':2 if self.spent else 0,'spent':self.spent}
    node=Node();store=ProtocolFundingStore(generation_path(str(tmp_path/'funding.db'),GEN))
    sender=ProtocolBundleSubmitter(provider=node,faucet=faucet,policy=ProtocolFeePolicy(enabled=True,native_admission_enabled=True,maximum_mojos=10,maximum_backing_mojos=123),funding_store=store)
    if funded:
        prepared=PreparedProtocolBundle(native.bundle(),0,'0x'+coin.name().hex(),123)
        store.reserve('testnet11',bundle_id(native.bundle()),{'feeTill':faucet.address_hex,'purpose':None,'backingMojos':123},
            {**prepared.to_json(),'protocolSpendBundle':native.bundle().to_json_dict()})
        # Deliberately omit journal.save_funded: recovery must hydrate the
        # original funding callback lost during a restart.
    return b,journal,identity,node,sender,key


@pytest.mark.asyncio
@pytest.mark.parametrize('funded',[False,True])
async def test_expired_quote_requeues_original_offer_and_preserves_both_journals(tmp_path,funded):
    b,j,identity,node,sender,_=saved_batch(tmp_path,funded=funded)
    original=j.protocol_bundle(identity);order=j.status(identity)['review']['orderIds'][0]
    raw=bytes(b.original(order))
    result=await release_batch_quote(b,j,identity,sender,clock=time.time)
    assert result['stage']=='EXPIRED_RECONCILED' and j.expiry_proof(identity)
    assert b.status(order)['stage']=='WAITING_FOR_MATCH' and b.status(order)['operationId'] is None
    assert bytes(b.original(order))==raw and j.protocol_bundle(identity)==original
    assert not j.reserved_input_coin_ids() and not sender.funding_store.reserved_coin_ids()
    assert await release_batch_quote(b,j,identity,sender,clock=time.time)==result
    with pytest.raises(ProtocolSubmissionError):await submit_saved_operation(j,identity,sender,clock=time.time)
    with b.db() as db:assert db.execute('SELECT count(*) FROM sols_order_settlement_history').fetchone()[0]==1
    sender.funding_store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['not_expired','pending','unknown','changing_peak','already_filled'])
async def test_no_release_from_clock_unknown_input_pending_or_confirmed_saved_spends(tmp_path,fault):
    b,j,identity,node,sender,_=saved_batch(tmp_path,expiry=int(time.time())+100 if fault=='not_expired' else None,funded=True)
    if fault=='pending':node.pending=True
    if fault=='unknown':node.inputs_known=False
    if fault=='changing_peak':node.change_peak=True
    if fault=='already_filled':node.spent=True;node.matches=True
    with pytest.raises(ProtocolSubmissionError):await release_batch_quote(b,j,identity,sender,clock=time.time)
    assert j.status(identity)['stage']=='DISPATCHING' and j.expiry_proof(identity) is None
    assert j.reserved_input_coin_ids() and sender.funding_store.reserved_coin_ids()
    assert b.status(j.status(identity)['review']['orderIds'][0])['operationId']==identity
    sender.funding_store.close()


@pytest.mark.asyncio
async def test_cancelled_original_offer_releases_expired_batch_without_claiming_it_filled(tmp_path):
    b,j,identity,node,sender,_=saved_batch(tmp_path,funded=True);node.spent=True
    assert (await release_batch_quote(b,j,identity,sender,clock=time.time))['stage']=='EXPIRED_RECONCILED'
    order=j.status(identity)['review']['orderIds'][0]
    assert b.status(order)['stage']=='INPUT_SPENT' and not b.status(order)['confirmedHeight']
    sender.funding_store.close()


def test_public_receipt_reads_need_private_key_and_cannot_build_sign_or_write(tmp_path):
    b,j,identity,node,sender,key=saved_batch(tmp_path)
    order=j.status(identity)['review']['orderIds'][0]
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=GEN,generation_sols_batch_enabled=True)
    app=FastAPI();app.include_router(router);app.state.generation_sols_orders=b;app.state.generation_operations=j
    app.state.coinset=node;app.state.generation_sols_guard=asyncio.Lock()
    app.dependency_overrides[get_settings]=lambda:settings
    before=Path(b.path).read_bytes(),Path(j.path).read_bytes()
    with TestClient(app) as client:
        for _ in range(10):
            r=client.get('/sols/batches/orders/'+order,headers={'X-Solslot-Order-Receipt':key})
            assert r.status_code==200 and r.json()['operationId']==identity
        assert client.get('/sols/batches/orders/'+order).status_code==422
        assert client.get('/sols/batches/orders/'+order,headers={'X-Solslot-Order-Receipt':'0x'+'bb'*32}).status_code==404
    assert before==(Path(b.path).read_bytes(),Path(j.path).read_bytes()) and node.quotes==0
    sender.funding_store.close()
