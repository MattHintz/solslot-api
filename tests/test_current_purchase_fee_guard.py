"""Bounded native fee authority; never reads or signs with a real key."""
from types import SimpleNamespace
from hashlib import sha256
import json
from dataclasses import replace

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from pydantic import ValidationError
import pytest

from solslot_api.generation_customer_purchase_fees import CurrentPurchaseFeeAuthority,CurrentPurchaseFeeFaucet
from solslot_api.generation_customer_purchase_factory import configured_current_customer_purchase
from solslot_api.generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim
from solslot_api.generation_customer_issuer import TestnetIssuerPolicy as IssuerPolicy
from solslot_api.protocol_submission import ProtocolBundleSubmitter
from tests.test_current_purchase_store import BROWSER
from tests.test_generation_customer_purchase_reservation_claim import body
from tests.test_generation_genesis_core import core
from chia_rs import AugSchemeMPL


@pytest.fixture
def guarded(tmp_path):
    b=lambda n:bytes32(bytes([n])*32)
    policy=IssuerPolicy(b(1),b(2),b(3),b(4),b(5),b(6),
        bytes(AugSchemeMPL.key_gen(b'synthetic-issuer-fixture-key-00001').get_g1()),
        frozenset([b(7)]),b(8),1000000,1,100,200)
    puzzle=Program.to(1);coin=Coin(b(20),puzzle.get_tree_hash(),uint64(100))
    authority=CurrentPurchaseFeeAuthority.model_validate({'schema':'solslot.current-purchase-fee-authority.v1',
        'network':'testnet11','generationId':'0x'+b(1).hex(),'issuerPolicyHash':policy.commitment,
        'fundingPuzzleHash':'0x'+puzzle.get_tree_hash().hex(),'feeCoinIds':['0x'+coin.name().hex()],
        'maximumFeeParentMojos':100,'maximumStageFeeMojos':10,'maximumTotalFeeMojos':10,
        'issuedAt':100,'expiresAt':200})
    store=CurrentPurchaseExecutionStore(tmp_path/'payments.db',authority.generation_id)
    claim=CurrentReservationClaim.model_validate({**body(),'issuerPolicyHash':policy.commitment})
    intent=store.save_review(claim,browser_hash=BROWSER,request_key='guarded',now=110)
    store.bind_execution_policy(policy.commitment,1,10)
    protocol=SpendBundle([make_spend(Coin(b(21),puzzle.get_tree_hash(),uint64(100)),puzzle,
        Program.to([[60,b'exact-purchase']] ))],G2Element())
    store.prepare_execution(intent,'RESERVATION',protocol,browser_hash=BROWSER,
        claim_hash=claim.digest(),fee_cap=10,expires_at=190,now=110)
    calls=[];clock=[120]
    faucet=SimpleNamespace(network='testnet11',address_hex=authority.funding_puzzle_hash,
        address_puzzle_hash=puzzle.get_tree_hash(),key=SimpleNamespace(puzzle=puzzle),
        sign_delegated_spend=lambda *a,**kw:calls.append((a,kw))or 'synthetic-signature',
        select_coin=lambda records,**kw:records)
    guard=CurrentPurchaseFeeFaucet(faucet,authority,policy,store,clock=lambda:clock[0])
    backing=ProtocolBundleSubmitter._backing_conditions(protocol,require_announcements=True)
    conditions=Program.to([[51,coin.puzzle_hash,95],[52,5],*backing,[85,180]])
    return SimpleNamespace(guard=guard,authority=authority,policy=policy,store=store,coin=coin,
        conditions=conditions,calls=calls,clock=clock,backing=backing)


def test_exact_saved_purchase_fee_can_be_signed_once_within_finite_limits(guarded):
    g=guarded
    assert g.guard.sign_delegated_spend(g.coin,g.conditions)=='synthetic-signature'
    assert len(g.calls)==1


@pytest.mark.parametrize('fault',['fee','destination','deadline','announcement','purpose','input','expired'])
def test_fee_guard_rejects_unreviewed_spends_before_signing(guarded,fault):
    g=guarded;coin=g.coin;conditions=g.conditions;purpose=None
    if fault=='fee':conditions=Program.to([[51,coin.puzzle_hash,89],[52,11],*g.backing,[85,180]])
    elif fault=='destination':conditions=Program.to([[51,bytes32(b'z'*32),95],[52,5],*g.backing,[85,180]])
    elif fault=='deadline':conditions=Program.to([[51,coin.puzzle_hash,95],[52,5],*g.backing,[85,201]])
    elif fault=='announcement':conditions=Program.to([[51,coin.puzzle_hash,95],[52,5],[85,180]])
    elif fault=='purpose':purpose='other-action'
    elif fault=='input':coin=Coin(bytes32(b'z'*32),coin.puzzle_hash,coin.amount)
    else:g.clock[0]=201
    with pytest.raises(ValueError):g.guard.sign_delegated_spend(coin,conditions,purpose=purpose)
    assert not g.calls


def test_fee_change_never_becomes_another_budget_input(guarded):
    g=guarded;change=Coin(g.coin.name(),g.coin.puzzle_hash,uint64(95))
    records=[{'coin':coin.to_json_dict()}for coin in (g.coin,change)]
    assert g.guard.select_coin(records)==records[:1]
    raw=g.authority.model_dump(mode='json',by_alias=True)
    raw['feeCoinIds'].append('0x'+change.name().hex())
    with pytest.raises(ValidationError):CurrentPurchaseFeeAuthority.model_validate(raw)


def test_disabled_factory_never_reads_policy_key_or_database(monkeypatch):
    from solslot_api import generation_customer_purchase_factory as factory
    def forbidden(*a,**kw):raise AssertionError('disabled purchase runtime must have no setup side effects')
    monkeypatch.setattr(factory,'selected_purchase_policy',forbidden)
    monkeypatch.setattr(factory,'protected_customer_faucet',forbidden)
    assert configured_current_customer_purchase(SimpleNamespace(),customers=None,funding_store=None) is None


@pytest.mark.parametrize('changes',[
    {'generation_customer_purchase_enabled':False,'generation_customer_purchase_funding_enabled':True},
    {'network':'mainnet'},{'deployment_generation_id':None},{'alpha_writes_enabled':True},
    {'generation_customer_enabled':False},{'generation_customer_identity_enabled':False},
    {'generation_customer_purchase_policy_hash':''},
    {'generation_customer_purchase_funding_enabled':True,'generation_customer_purchase_fee_signer_key_path':''},
])
def test_configuration_cannot_enable_incomplete_or_legacy_purchase_context(changes):
    from solslot_api.config import Settings
    fields=dict(network='testnet11',deployment_generation_id='0x'+'01'*32,alpha_writes_enabled=False,
        generation_customer_enabled=True,generation_customer_identity_enabled=True,
        generation_customer_purchase_enabled=True,generation_customer_purchase_policy_path='/synthetic/issuer.json',
        generation_customer_purchase_policy_hash='0x'+'02'*32,
        generation_customer_purchase_fee_authority_path='/synthetic/fees.json',
        generation_customer_purchase_fee_authority_hash='0x'+'03'*32)
    assert Settings(_env_file=None,**fields).generation_customer_purchase_funding_enabled is False
    with pytest.raises(ValidationError):Settings(_env_file=None,**{**fields,**changes})


def test_factory_rejects_legacy_context_before_any_key_access(monkeypatch):
    from solslot_api import generation_customer_purchase_factory as factory
    def forbidden(*a,**kw):raise AssertionError('key access preceded current-generation admission')
    monkeypatch.setattr(factory,'protected_customer_faucet',forbidden)
    settings=SimpleNamespace(generation_customer_purchase_enabled=True,network='testnet11',alpha_writes_enabled=True)
    with pytest.raises(ValueError,match='CONFIGURED_RUNTIME_REQUIRED'):
        configured_current_customer_purchase(settings,customers=None,funding_store=None)


@pytest.mark.parametrize('funding_enabled,now,expected_key_reads',[(False,120,0),(True,201,0),(True,120,1)])
def test_factory_reopens_saved_journal_without_keys_when_funding_closed(guarded,tmp_path,monkeypatch,
        funding_enabled,now,expected_key_reads):
    from solslot_api import generation_customer_purchase_factory as factory
    from solslot_api.generation_customer_runtime import GenerationCustomerRuntime
    from solslot_api.protocol_funding_store import ProtocolFundingStore
    from solslot_api.generation_storage import generation_path
    g=guarded
    def pinned(name,value):
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        path=tmp_path/name;path.write_bytes(raw)
        return str(path),'0x'+sha256(raw).hexdigest()
    policy_path,policy_hash=pinned('issuer.json',g.policy.public())
    authority_path,authority_hash=pinned('fees.json',g.authority.model_dump(mode='json',by_alias=True))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=g.authority.generation_id,
        alpha_writes_enabled=False,generation_customer_purchase_enabled=True,
        generation_customer_purchase_funding_enabled=funding_enabled,
        generation_customer_purchase_policy_path=policy_path,generation_customer_purchase_policy_hash=policy_hash,
        generation_customer_purchase_fee_authority_path=authority_path,
        generation_customer_purchase_fee_authority_hash=authority_hash,
        generation_customer_purchase_fee_signer_key_path='/synthetic/test-only-key',payment_purchase_db_path=g.store.path)
    customers=object.__new__(GenerationCustomerRuntime)
    customers.settings=settings;customers.store=SimpleNamespace(generation_id=g.authority.generation_id,held_funding_ids=lambda:set())
    customers.journal=SimpleNamespace(reserved_input_coin_ids=lambda:set())
    customers.index=SimpleNamespace(anchor=SimpleNamespace(issuance=SimpleNamespace(generation=g.policy.generation)))
    customers.provider=SimpleNamespace()
    reads=[]
    def synthetic_key(path):
        reads.append(path);g.guard._faucet.add_coin_reservation_source=lambda source:None
        return g.guard._faucet
    monkeypatch.setattr(factory,'protected_customer_faucet',synthetic_key)
    funding=ProtocolFundingStore(generation_path(str(tmp_path/'native-funding.db'),settings.deployment_generation_id))
    try:
        service=configured_current_customer_purchase(settings,customers=customers,funding_store=funding,clock=lambda:now)
        assert len(reads)==expected_key_reads
        assert service.submitter.funding_store is funding and service.store.path==g.store.path
        assert service.submitter.policy.enabled is bool(expected_key_reads)
        if now>g.authority.expires_at:
            settings.payment_purchase_db_path=str(tmp_path/'missing-payments.db')
            with pytest.raises(ValueError,match='RECOVERY_JOURNAL_REQUIRED'):
                configured_current_customer_purchase(settings,customers=customers,funding_store=funding,clock=lambda:now)
            assert not (tmp_path/'generations'/g.authority.generation_id[2:]/'missing-payments.db').exists()
            settings.payment_purchase_db_path=g.store.path
            with g.store._connect() as db:
                db.execute('DELETE FROM current_purchase_execution_policies')
            with pytest.raises(ValueError,match='RECOVERY_POLICY_REQUIRED'):
                configured_current_customer_purchase(settings,customers=customers,funding_store=funding,clock=lambda:now)
            assert reads==[]
    finally:funding.close()


@pytest.mark.asyncio
async def test_native_fee_signature_is_atomic_with_saved_protocol_inputs(core,guarded,tmp_path):
    # This checks the actual fee coin and BLS spend in consensus. The full
    # native SmartDeed acquisition is covered by the checkout golden test.
    from chia.types.mempool_inclusion_status import MempoolInclusionStatus
    from solslot_api.faucet import AGG_SIG_ME_DATA
    c=core;g=guarded;c.sim.pass_time(uint64(1000));await c.sim.farm_block()
    now=int(c.sim.timestamp);acs=Program.to(1)
    source=next(r.coin for r in await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent)
    protocol=SpendBundle([make_spend(source,acs,Program.to([
        [51,acs.get_tree_hash(),int(source.amount)],[60,b'native-fee-atomicity']]))],G2Element())
    fee_coin=c.parents[0]
    policy=replace(g.policy,issued_at=now-1,expires_at=now+300)
    authority=CurrentPurchaseFeeAuthority.model_validate({**g.authority.model_dump(mode='json',by_alias=True),
        'issuerPolicyHash':policy.commitment,'fundingPuzzleHash':c.faucet.address_hex,
        'feeCoinIds':['0x'+fee_coin.name().hex()],'maximumFeeParentMojos':int(fee_coin.amount),
        'issuedAt':now-1,'expiresAt':now+300})
    store=CurrentPurchaseExecutionStore(tmp_path/'native-fee-payments.db',authority.generation_id)
    claim=CurrentReservationClaim.model_validate({**body(),'issuerPolicyHash':policy.commitment})
    intent=store.save_review(claim,browser_hash=BROWSER,request_key='native-fee',now=now)
    store.bind_execution_policy(policy.commitment,1,10)
    store.prepare_execution(intent,'RESERVATION',protocol,browser_hash=BROWSER,
        claim_hash=claim.digest(),fee_cap=10,expires_at=now+200,now=now)
    guard=CurrentPurchaseFeeFaucet(c.faucet,authority,policy,store,clock=lambda:now)
    backing=ProtocolBundleSubmitter._backing_conditions(protocol,require_announcements=True)
    conditions=Program.to([[51,fee_coin.puzzle_hash,int(fee_coin.amount)-5],[52,5],*backing,[85,now+100]])
    signature=G2Element.from_bytes(guard.sign_delegated_spend(fee_coin,conditions))
    spend=make_spend(fee_coin,c.faucet.key.puzzle,Program.to([0,Program.to((1,conditions)),0]))
    assert (await c.client.push_tx(SpendBundle([spend],signature)))[0]!=MempoolInclusionStatus.SUCCESS
    complete=SpendBundle([*protocol.coin_spends,spend],signature)
    assert await c.client.push_tx(complete)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    assert (await c.client.get_coin_record_by_name(fee_coin.name())).spent
    assert (await c.client.push_tx(complete))[0]!=MempoolInclusionStatus.SUCCESS
