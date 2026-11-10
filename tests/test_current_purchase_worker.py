import asyncio
import json
from types import SimpleNamespace
import pytest
from solslot_api.generation_customer_purchase_worker import CurrentPurchaseWorker,expired_unsubmitted_reservation
from solslot_api.generation_operations import bundle_id
from tests.test_current_purchase_execution_recovery import recover
from tests.test_current_purchase_store import BROWSER
from tests.test_native_purchases import _context,_b32

async def no_issuer(_):raise AssertionError('No payer authorization permits an issuer call')

@pytest.fixture(autouse=True)
def fixture_artifact(monkeypatch):
 # Recovery fixtures deliberately contain an opaque claim. Native artifact,
 # signatures and exact delivery are exercised by the full consensus test.
 monkeypatch.setattr('solslot_api.generation_customer_purchase_worker.purchase_artifact_v3_from_json',
     lambda _:SimpleNamespace(quote_expires_at=200))

@pytest.mark.asyncio
async def test_expired_prepared_work_without_primary_proof_requires_review(recover):
 r=recover;w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['errors']==0 and h['examined']==1
 with r.store._connect()as db:assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='REVIEW_REQUIRED'
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False
 idle=await w.tick();assert idle['examined']==0 and idle['reviewRequiredCount']==1 and idle['status']=='DEGRADED'
 assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==0

def expiry_prover(r):
 calls=[];r.submitter.funding_guard=asyncio.Lock()
 async def prove(original):
  calls.append(bundle_id(original))
  return {'bundleId':bundle_id(original),'absoluteExpiry':200,'peakHeight':124,'peakTimestamp':210,
   'inputIds':sorted('0x'+coin.name().hex()for coin in original.removals()),'allInputsUnspentAndClear':True}
 r.submitter.prove_expired_bundle=prove
 return calls

@pytest.mark.asyncio
async def test_expired_unsigned_unfunded_work_closes_only_with_bound_native_proof(recover):
 r=recover;calls=expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 assert (await w.tick())['errors']==0
 assert calls==[bundle_id(r.protocol)]and expired_unsubmitted_reservation(r.service,r.identity,BROWSER)
 with r.store._connect()as db:
  row=db.execute('SELECT state,expiry_document FROM current_purchase_worker_jobs').fetchone()
  assert row['state']=='CLOSED'
  proof=json.loads(row['expiry_document']);assert proof['intentId']==r.identity
  assert proof['generationId']==r.store.generation_id and proof['bundleId']==bundle_id(r.protocol)
 assert r.node.observations==0 and r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==0

@pytest.mark.asyncio
async def test_existing_closed_prepared_work_gets_only_a_bounded_expiry_proof_audit(recover):
 r=recover;calls=expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 with r.store._connect()as db:
  db.execute("INSERT INTO current_purchase_worker_jobs(intent_id,state,attempts,error_code)VALUES(?,'CLOSED',5,?)",
   (r.identity,'CURRENT_PURCHASE_RESERVATION_DISPATCH_TIMED_OUT'))
 assert (await w.tick())['examined']==1 and calls==[bundle_id(r.protocol)]
 with r.store._connect()as db:
  row=db.execute('SELECT state,attempts,error_code FROM current_purchase_worker_jobs').fetchone()
  assert row['state']=='CLOSED'and row['attempts']==6
  assert row['error_code']=='CURRENT_PURCHASE_RESERVATION_DISPATCH_TIMED_OUT'
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)
 assert (await w.tick())['examined']==0

@pytest.mark.asyncio
async def test_closed_audit_never_reopens_financial_work_before_quote_expiry(recover):
 r=recover;r.clock[0]=120;calls=expiry_prover(r)
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 with r.store._connect()as db:
  db.execute("INSERT INTO current_purchase_worker_jobs(intent_id,state)VALUES(?,'CLOSED')",(r.identity,))
 assert (await w.tick())['errors']==0 and calls==[]
 with r.store._connect()as db:assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='REVIEW_REQUIRED'
 assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==0

@pytest.mark.asyncio
async def test_restart_after_proof_commit_recovers_exact_historical_proof(recover):
 r=recover;calls=expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 with r.store._connect()as db:
  original=db.execute('SELECT expiry_document FROM current_purchase_worker_jobs').fetchone()[0]
  db.execute("UPDATE current_purchase_worker_jobs SET state='WAITING'")
 r.clock[0]+=11
 assert (await w.tick())['errors']==0 and len(calls)==1
 with r.store._connect()as db:
  row=db.execute('SELECT state,expiry_document FROM current_purchase_worker_jobs').fetchone()
  assert row['state']=='CLOSED'and row['expiry_document']==original

def test_additive_worker_proof_schema_preserves_existing_job_history(recover):
 r=recover
 with r.store._connect()as db:
  db.execute('''CREATE TABLE current_purchase_worker_jobs(intent_id TEXT PRIMARY KEY,lease_token TEXT,
   lease_until INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,
   state TEXT NOT NULL DEFAULT 'WAITING',issuer_document TEXT,error_code TEXT)''')
  db.execute("INSERT INTO current_purchase_worker_jobs(intent_id,state,attempts,error_code)VALUES(?,'CLOSED',5,?)",
   (r.identity,'CURRENT_PURCHASE_RESERVATION_DISPATCH_TIMED_OUT'))
 CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 with r.store._connect()as db:
  row=db.execute('SELECT * FROM current_purchase_worker_jobs').fetchone()
  assert row['state']=='CLOSED'and row['attempts']==5 and row['expiry_document']is None
  assert row['error_code']=='CURRENT_PURCHASE_RESERVATION_DISPATCH_TIMED_OUT'

@pytest.mark.asyncio
async def test_terminal_proof_is_never_admitted_under_an_active_worker_lease(recover):
 r=recover;expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)
 with r.store._connect()as db:
  db.execute('UPDATE current_purchase_worker_jobs SET lease_token=?,lease_until=?',('in-flight',r.clock[0]+1))
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

@pytest.mark.asyncio
async def test_unavailable_funding_journal_never_proves_no_submission(recover):
 r=recover;expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 def unavailable(*args,**kwargs):raise RuntimeError('private storage details')
 r.funding.lookup=unavailable
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

@pytest.mark.asyncio
async def test_saved_authorization_or_foreign_owner_invalidates_terminal_proof(recover):
 r=recover;expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 assert expired_unsubmitted_reservation(r.service,r.identity,'cd'*32)is False
 saved=r.service._saved
 r.service._saved=lambda *args:{**saved(*args),'deliveryClaim':object()}
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['issuer','validator'])
async def test_any_retained_delivery_signature_prevents_unsubmitted_terminal_truth(recover,kind):
 r=recover;expiry_prover(r);w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 if kind=='issuer':
  with r.store._connect()as db:db.execute("UPDATE current_purchase_worker_jobs SET issuer_document='retained-delivery-signature'")
 else:
  saved=r.service._saved
  r.service._saved=lambda *args:{**saved(*args),'retainedSignatures':{'delivery':{0:'retained'}}}
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

@pytest.mark.asyncio
@pytest.mark.parametrize('field,value',[('bundleId','0x'+'ff'*32),('absoluteExpiry',201),('inputIds',[]),
 ('allInputsUnspentAndClear',False),('peakTimestamp',199)])
async def test_mismatched_or_incomplete_expiry_proof_retains_work(recover,field,value):
 r=recover;expiry_prover(r);original=r.submitter.prove_expired_bundle
 async def invalid(bundle):return {**await original(bundle),field:value}
 r.submitter.prove_expired_bundle=invalid
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 assert (await w.tick())['errors']==1
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False
 with r.store._connect()as db:assert db.execute('SELECT expiry_document FROM current_purchase_worker_jobs').fetchone()[0]is None

@pytest.mark.asyncio
async def test_oversized_primary_proof_is_not_retained(recover):
 r=recover;expiry_prover(r);original=r.submitter.prove_expired_bundle
 async def oversized(bundle):return {**await original(bundle),'unexpected':'x'*4096}
 r.submitter.prove_expired_bundle=oversized
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);assert (await w.tick())['errors']==1
 with r.store._connect()as db:
  row=db.execute('SELECT expiry_document,error_code FROM current_purchase_worker_jobs').fetchone()
  assert row['expiry_document']is None and row['error_code']=='CURRENT_PURCHASE_WORKER_RETENTION_FULL'
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

def test_worker_proof_and_issuer_documents_have_a_combined_fixed_retention_cap(recover):
 from solslot_api.generation_customer_purchase_worker import _worker_document_capacity
 r=recover;CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 with r.store._connect()as db:
  db.execute('INSERT INTO current_purchase_worker_jobs(intent_id,issuer_document)VALUES(?,?)',(r.identity,'x'*(128*2*4096)))
  with pytest.raises(ValueError,match='WORKER_RETENTION_FULL'):_worker_document_capacity(db,'{}')

@pytest.mark.asyncio
async def test_funding_commit_before_checkout_checkpoint_never_becomes_unsubmitted(recover):
 r=recover;calls=expiry_prover(r);r.retain();r.node.receipt=None
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 assert calls==[]and expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False
 assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER)is not None
 with r.store._connect()as db:assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='REVIEW_REQUIRED'

@pytest.mark.asyncio
async def test_funding_or_saved_authorization_appearing_during_proof_cannot_close(recover):
 r=recover;expiry_prover(r);original=r.submitter.prove_expired_bundle
 async def raced(bundle):
  proof=await original(bundle);r.retain();return proof
 r.submitter.prove_expired_bundle=raced
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);assert (await w.tick())['errors']==1
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

@pytest.mark.asyncio
async def test_primary_proof_that_outlives_worker_lease_is_not_saved(recover):
 r=recover;expiry_prover(r);original=r.submitter.prove_expired_bundle
 async def slow(bundle):
  proof=await original(bundle);r.clock[0]+=300;return proof
 r.submitter.prove_expired_bundle=slow
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);assert (await w.tick())['errors']==1
 assert expired_unsubmitted_reservation(r.service,r.identity,BROWSER)is False

@pytest.mark.asyncio
async def test_reservation_preparation_is_a_durable_cycle_before_dispatch(recover):
 r=recover;r.clock[0]=120;prepared=False;calls=[]
 r.service._funding_context=lambda:{}
 def existing(identity,phase,binding):return {'stage':'PREPARED'}if prepared and phase=='RESERVATION'else None
 async def prepare(*args,**kwargs):
  nonlocal prepared
  await asyncio.sleep(.12);prepared=True;calls.append('prepare')
 async def reconcile(*args,**kwargs):return {'stage':'PREPARED'}
 async def dispatch(*args,**kwargs):await asyncio.sleep(.12);calls.append('dispatch')
 r.service._existing=existing;r.service.prepare_reservation=prepare;r.service.reconcile=reconcile;r.service.dispatch=dispatch
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);w.ACTION_TIMEOUT_SECONDS=.2
 assert (await w.tick())['errors']==0 and calls==['prepare']
 r.clock[0]+=11
 assert (await w.tick())['errors']==0 and calls==['prepare','dispatch']

@pytest.mark.asyncio
async def test_stage_timeout_survives_later_proven_terminal_expiry(recover):
 r=recover;r.clock[0]=120;expiry_prover(r)
 async def timeout(*args,**kwargs):raise TimeoutError('private provider detail')
 r.service.dispatch=timeout
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);assert (await w.tick())['errors']==1
 with r.store._connect()as db:
  before=db.execute('SELECT state,error_code FROM current_purchase_worker_jobs').fetchone()
  assert before['error_code']=='CURRENT_PURCHASE_RESERVATION_DISPATCH_TIMED_OUT'
 r.clock[0]=300;assert (await w.tick())['errors']==0
 with r.store._connect()as db:
  after=db.execute('SELECT state,error_code FROM current_purchase_worker_jobs').fetchone()
  assert after['state']=='CLOSED'and after['error_code']==before['error_code']
 assert 'private provider detail'not in json.dumps(w.health())

@pytest.mark.asyncio
@pytest.mark.parametrize('inventory_version',[2,4])
async def test_existing_expiry_verifier_accepts_real_signed_fee_less_native_reservation(inventory_version):
 from time import time
 from dataclasses import replace
 from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
 from chia.types.blockchain_format.program import Program
 from chia.wallet.lineage_proof import LineageProof
 from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD,SINGLETON_MOD_HASH
 from chia_rs import AugSchemeMPL,Coin,SpendBundle
 from solslot_puzzles.stripe_settlement_v1_driver import (InventoryReservationV1,
  build_inventory_reservation_spend,make_inventory_available_inner)
 from solslot_api.faucet import AGG_SIG_ME_DATA
 from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
 now=int(time());validators=tuple(AugSchemeMPL.key_gen(bytes([n])*32)for n in (51,52,53))
 context,_=_context(AugSchemeMPL.key_gen(b'P'*32),validators,now=now-330)
 context=replace(context,terms=replace(context.terms,inventory_version=inventory_version,
  generation_batch_bindings=bytes(Program.to([_b32(1),*[_b32(2)]*7]))if inventory_version==4 else b''))
 structure=Program.to((SINGLETON_MOD_HASH,(context.terms.deed_launcher_id,context.terms.deed_launcher_puzzle_hash)))
 source=Coin(context.purchase.deed_launcher_id,
  SINGLETON_MOD.curry(structure,make_inventory_available_inner(context.terms)).get_tree_hash(),1)
 transition=build_inventory_reservation_spend(available_coin=source,deed_singleton_struct=structure,
  lineage_proof=LineageProof(parent_name=_b32(22),amount=1),
  reservation=InventoryReservationV1(context.purchase,context.purchase.quote_expires_at),
  signer_indices=(0,1),terms=context.terms)
 spend=transition.spend
 pairs=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),
  spend.coin,AGG_SIG_ME_DATA['testnet11'])
 keys={bytes(key.get_g1()):key for key in validators}
 signature=AugSchemeMPL.aggregate([AugSchemeMPL.sign(keys[bytes(public)],message)for public,message in pairs])
 native=SpendBundle([spend],signature)
 assert sum(coin.amount for coin in native.removals())==sum(coin.amount for coin in native.additions())
 calls=[]
 class Primary:
  async def get_network_info_primary(self):return {'network_name':'testnet11'}
  async def get_fee_estimate(self,**kwargs):
   calls.append(kwargs)
   return {'full_node_synced':True,'peak_height':5_000_000,'mempool_size':0,'mempool_max_size':100_000_000,
    'last_peak_timestamp':now-5,'node_time_utc':int(time())}
  async def _primary_inputs_clear(self,bundle):
   assert bundle==native.to_json_dict();return True
 submitter=object.__new__(ProtocolBundleSubmitter);submitter.provider=Primary()
 submitter.policy=ProtocolFeePolicy();submitter.faucet=SimpleNamespace(network='testnet11')
 proof=await submitter.prove_expired_bundle(native)
 assert proof['bundleId']==bundle_id(native)and proof['absoluteExpiry']==context.purchase.quote_expires_at
 assert proof['allInputsUnspentAndClear']is True and proof['inputIds']==['0x'+source.name().hex()]
 assert calls[0]['spend_bundle']==native.to_json_dict()and calls[1]['cost']>0
 assert all(call['require_primary']is True for call in calls)

@pytest.mark.asyncio
async def test_interrupted_reservation_is_reconciled_before_any_dispatch(recover):
 r=recover;r.retain();w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['errors']==0
 assert r.store.execution_status(r.identity,'RESERVATION',browser_hash=BROWSER)['stage']=='CONFIRMED'
 assert r.node.observations==1

@pytest.mark.asyncio
async def test_durable_lease_excludes_another_worker_and_recovers_after_restart(recover):
 r=recover;a=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);b=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 rows=a._claim();assert len(rows)==1 and b._claim()==[]
 r.clock[0]+=a.LEASE_SECONDS_PER_ACTION*a.batch_size+6
 assert len(b._claim())==1

@pytest.mark.asyncio
async def test_errors_back_off_durably_without_exposing_node_details(recover):
 r=recover;r.retain();r.node.network='mainnet';w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['errors']==1 and h['status']=='DEGRADED'
 assert (await w.tick())['examined']==0
 r.clock[0]+=11;r.node.network='testnet11'
 h=await CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]).tick()
 assert h['errors']==0 and r.node.observations==1 and 'mainnet'not in json.dumps(h)

@pytest.mark.asyncio
async def test_corrupt_retained_claim_stops_before_node_or_issuer(recover):
 r=recover;w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer)
 with r.store._connect()as db:db.execute('UPDATE current_customer_purchase_reviews SET claim_hash=?',('0x'+'ff'*32,))
 with pytest.raises(ValueError,match='SAVED_REVIEW_CHANGED'):await w.tick()
 assert r.node.reads==0 and w.health()is None

@pytest.mark.asyncio
async def test_cancellation_holds_lease_and_restarts_without_duplicate_action(recover):
 r=recover;r.retain();entered=asyncio.Event()
 async def pending(*a,**kw):entered.set();await asyncio.Event().wait()
 r.node.observe_exact_protocol_bundle=pending
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);task=asyncio.create_task(w.tick());await asyncio.wait_for(entered.wait(),2);task.cancel()
 with pytest.raises(asyncio.CancelledError):await task
 assert w.health()is None and not w.running
 assert CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])._claim()==[]

@pytest.mark.asyncio
async def test_stale_health_is_not_an_enabled_worker_claim(recover):
 r=recover;w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0]);await w.tick()
 r.clock[0]+=w.batch_size*w.LEASE_SECONDS_PER_ACTION+2*w.interval
 assert w.health()['status']=='DEGRADED'
 r.clock[0]+=1;assert w.health()['status']=='STALE'

@pytest.mark.asyncio
async def test_worker_health_keeps_one_bounded_anonymous_timing_sample_on_idle(recover):
 from solslot_api.generation_customer_purchase_timing import measured,STAGES
 r=recover;r.retain()
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 async def advance(identity,binding,token):
  async def read():return None
  await measured(r.service,identity,'confirmation_observation',read())
  return 'WAITING'
 w._advance=advance
 first=await w.tick();sample=first['lastWorkerTiming']
 assert sample['measurementScope']=='originating_process_worker_cycle'
 assert sample['sampledAt']==r.clock[0] and sample['outcome']=='success'
 assert set(sample['stagesMs'])==set(STAGES)
 assert sample['stagesMs']['confirmation_observation'] is not None and sample['stagesMs']['queue'] is None
 assert r.identity not in json.dumps(sample) and BROWSER not in json.dumps(sample)
 assert (await w.tick())['lastWorkerTiming']==sample
 assert w.health()['lastWorkerTiming']==sample
 with r.service.store._connect() as db:
  assert db.execute('SELECT count(*) FROM current_purchase_worker_health').fetchone()[0]==1
 r.clock[0]+=w.batch_size*w.LEASE_SECONDS_PER_ACTION+2*w.interval+1
 assert w.health()['status']=='STALE' and w.health()['lastWorkerTiming']['sampledAt']==sample['sampledAt']

@pytest.mark.asyncio
async def test_worker_health_instrumentation_failure_does_not_change_work(recover):
 r=recover;r.retain()
 class Broken:
  def attempt_marker(self,*args):raise RuntimeError('private timing failure')
  def attempt(self,*args):raise RuntimeError('private timing failure')
 r.service._checkout_timings=Broken()
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 async def advance(*args):return 'WAITING'
 w._advance=advance
 value=await w.tick()
 assert value['examined']==1 and value['errors']==0 and 'lastWorkerTiming' not in value
 assert 'private timing failure' not in json.dumps(value)

@pytest.mark.asyncio
async def test_confirmed_unpaid_reservation_is_selected_for_automatic_timeout(recover):
 r=recover;r.retain();await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
 r.clock[0]=210;r.service.policy=SimpleNamespace(expires_at=400,commitment=r.service.policy.commitment)
 calls=[]
 def funding():calls.append('funding')
 async def release(identity,*,browser_hash):calls.append(('release',identity,browser_hash))
 async def dispatch(identity,phase,*,browser_hash):calls.append(('dispatch',phase))
 r.service._funding_context=funding;r.service.prepare_timeout=release;r.service.dispatch=dispatch
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 h=await w.tick();assert h['examined']==1 and h['errors']==0
 assert calls==['funding',('release',r.identity,BROWSER),('dispatch','RELEASE')]

@pytest.mark.asyncio
async def test_saved_delivery_is_reconciled_before_timeout_even_after_quote_expiry(recover):
 r=recover;r.retain();await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
 r.clock[0]=210;r.service.policy=SimpleNamespace(expires_at=400,commitment=r.service.policy.commitment)
 original=r.service._existing
 r.service._existing=lambda identity,phase,binding:({'stage':'RECONCILING'}if phase=='DELIVERY'else original(identity,phase,binding))
 calls=[]
 async def reconcile(identity,phase,*,browser_hash):calls.append(phase);return {'stage':'CONFIRMED'}
 r.service.reconcile=reconcile
 w=CurrentPurchaseWorker(r.service,issuer_sign=no_issuer,clock=lambda:r.clock[0])
 assert (await w.tick())['errors']==0
 assert calls==['RESERVATION','DELIVERY']
 with r.store._connect()as db:assert db.execute('SELECT state FROM current_purchase_worker_jobs').fetchone()[0]=='COMPLETE'

@pytest.mark.parametrize('options',[{'issuer_sign':None},{'batch_size':0},{'batch_size':5},{'interval':4},{'interval':61}])
def test_worker_has_no_default_signer_or_unbounded_loop(recover,options):
 with pytest.raises(ValueError):CurrentPurchaseWorker(recover.service,**{'issuer_sign':no_issuer,**options})
