"""Interrupted-broadcast recovery with real journals and synthetic node receipts."""
from types import SimpleNamespace

from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_api.generation_customer_issuer import TestnetIssuerPolicy as IssuerPolicy
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.generation_operations import bundle_id
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import PreparedProtocolBundle, ProtocolFeePolicy
from tests.test_current_purchase_execution_store import bundle
from tests.test_current_purchase_store import BROWSER
from tests.test_generation_customer_purchase_reservation_claim import body


@pytest.fixture
def recover(tmp_path):
    b=lambda n:bytes32(bytes([n])*32)
    public=bytes(AugSchemeMPL.key_gen(b'x'*32).get_g1())
    policy=IssuerPolicy(b(1),b(2),b(3),b(4),b(5),b(6),public,frozenset([b(7)]),b(8),1000,1,100,200)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id='0x'+b(1).hex(),generation_customer_purchase_enabled=True)
    store=CurrentPurchaseExecutionStore(tmp_path/'payments.db',settings.deployment_generation_id)
    claim=CurrentReservationClaim.model_validate({**body(),'issuerPolicyHash':policy.commitment})
    identity=store.save_review(claim,browser_hash=BROWSER,request_key='recover-one',now=110)
    funding=ProtocolFundingStore(generation_path(str(tmp_path/'funding.db'),settings.deployment_generation_id))
    async def never_submit(*a,**kw):raise AssertionError('recovery must not submit or select a fee')
    submitter=SimpleNamespace(funding_store=funding,faucet=SimpleNamespace(network='testnet11',address_hex='0x'+b(9).hex()),
        policy=ProtocolFeePolicy(enabled=False,maximum_mojos=10,native_admission_enabled=True),submit=never_submit)
    node=SimpleNamespace(reads=0,observations=0,network='testnet11',receipt={'status':'CONFIRMED','confirmed_height':123})
    async def network():node.reads+=1;return {'network_name':node.network}
    async def observe(raw):node.observations+=1;return node.receipt
    node.get_network_info_primary=network;node.observe_exact_protocol_bundle=observe
    clock=[300]
    service=CurrentNativePurchaseExecution(settings=settings,anchor=SimpleNamespace(issuance=SimpleNamespace(generation=b(1))),
        provider=node,policy=policy,store=store,fee_cap=10,submitter=submitter,clock=lambda:clock[0])
    protocol=bundle()
    store.prepare_execution(identity,'RESERVATION',protocol,browser_hash=BROWSER,claim_hash=claim.digest(),fee_cap=10,expires_at=200,now=115)
    prepared=PreparedProtocolBundle(protocol,5,'0x'+b(10).hex())
    context={'feeTill':submitter.faucet.address_hex,'purpose':None,'backingMojos':0}
    def retain(**changes):
        document={**prepared.to_json(),'protocolSpendBundle':protocol.to_json_dict(),**changes}
        funding.reserve('testnet11',bundle_id(protocol),context,document)
    yield SimpleNamespace(service=service,store=store,identity=identity,protocol=protocol,prepared=prepared,
        funding=funding,node=node,retain=retain,clock=clock,submitter=submitter,settings=settings)
    funding.close()


@pytest.mark.asyncio
async def test_restart_after_fee_reservation_before_ui_checkpoint_recovers_expired_saved_bundle(recover):
    r=recover;r.retain()
    assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER) is None
    result=await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
    assert result['stage']=='CONFIRMED' and result['confirmedHeight']==123
    assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER)==r.prepared.to_json()
    assert (await r.service.dispatch(r.identity,'RESERVATION',browser_hash=BROWSER))['stage']=='CONFIRMED'
    assert r.node.reads==1 and r.node.observations==1


@pytest.mark.asyncio
async def test_unknown_submission_retains_one_funded_transaction_without_retrying(recover):
    r=recover;r.retain();r.node.receipt=None
    for _ in range(3):
        assert (await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER))['stage']=='RECONCILING'
    assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER)['spendBundleId']==r.prepared.spend_bundle_id
    assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==1


@pytest.mark.asyncio
async def test_explicit_retry_accepts_submitter_reconciled_status_without_changing_funded_bytes(recover):
    r=recover;r.retain();r.node.receipt=None;r.clock[0]=120
    r.submitter.policy=ProtocolFeePolicy(enabled=True,maximum_mojos=10,native_admission_enabled=True)
    calls=[]
    async def checked(saved,phase,protocol):
        assert phase=='RESERVATION' and bytes(protocol)==bytes(r.protocol)
    async def submit(raw,*,before_push):
        assert raw==r.protocol.to_json_dict()
        await before_push(r.prepared)
        calls.append(r.prepared.spend_bundle_id)
        return {'spendBundleId':r.prepared.spend_bundle_id,'status':'MEMPOOL_RECONCILED'}
    r.service._revalidate_prepared=checked;r.submitter.submit=submit
    result=await r.service.dispatch(r.identity,'RESERVATION',browser_hash=BROWSER)
    assert result['stage']=='MEMPOOL' and calls==[r.prepared.spend_bundle_id]
    assert r.funding.db.execute('SELECT count(*) FROM funded_protocol_bundles').fetchone()[0]==1


@pytest.mark.asyncio
async def test_old_browser_rejected_before_node_or_funding_read(recover):
    r=recover;r.retain()
    with pytest.raises(ValueError):await r.service.reconcile(r.identity,'RESERVATION',browser_hash='cd'*32)
    assert r.node.reads==r.node.observations==0


@pytest.mark.asyncio
async def test_wrong_primary_network_cannot_confirm_saved_payment(recover):
    r=recover;r.retain();r.node.network='mainnet'
    with pytest.raises(ValueError,match='PRIMARY_TESTNET_REQUIRED'):
        await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
    assert r.node.observations==0
    assert r.store.execution_status(r.identity,'RESERVATION',browser_hash=BROWSER)['stage']=='RECONCILING'


@pytest.mark.asyncio
async def test_expired_unfunded_work_cannot_select_or_submit(recover):
    r=recover;r.submitter.policy=ProtocolFeePolicy(enabled=True,maximum_mojos=10,native_admission_enabled=True)
    with pytest.raises(ValueError,match='DISPATCH_WINDOW_CLOSED'):
        await r.service.dispatch(r.identity,'RESERVATION',browser_hash=BROWSER)
    assert r.store.execution_funding(r.identity,'RESERVATION',browser_hash=BROWSER) is None
    assert r.node.observations==0


@pytest.mark.asyncio
@pytest.mark.parametrize('now,reason',[(120,'PURCHASE_WINDOW_ENDING'),(300,'PURCHASE_WINDOW_CLOSED')])
async def test_new_quote_rejects_insufficient_completion_window_before_any_node_call(recover,now,reason):
    r=recover;r.clock[0]=now
    with pytest.raises(ValueError,match=reason):
        await r.service.quote('new-quote','0x'+next(iter(r.service.policy.deed_launchers)).hex(),browser_hash=BROWSER)
    assert r.node.reads==0 and r.node.observations==0


@pytest.mark.asyncio
async def test_saved_fee_context_cannot_substitute_another_protocol_bundle(recover):
    r=recover;r.retain(protocolSpendBundle=bundle(2).to_json_dict())
    with pytest.raises(ValueError,match='ORIGINAL_FUNDING_CHANGED'):
        await r.service.reconcile(r.identity,'RESERVATION',browser_hash=BROWSER)
    assert r.node.reads==0
