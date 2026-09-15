"""Offline Base prepayment proof, actual BLS/CLVM and durable SQLite exclusions.

Authority, owner registry, Chia and EVM transports are isolated fixtures. This
is not activation, live payment, campaign continuity or native-device evidence.
"""
import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from eth_abi import encode
from web3 import Web3
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, G2Element, SpendBundle, Coin
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_puzzles.primary_purchase_v2_driver import BASE_SEPOLIA_USDC_ASSET_ID
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, build_inventory_reservation_spend

from solslot_api.base_inventory_hold import BaseInventoryHoldClaim, base_hold_activation, base_hold_coordinates
from solslot_api.base_inventory_hold_coordinator import arm_base_checkout, base_checkout_status
from solslot_api import base_inventory_hold_coordinator as coordinator, validator_base_inventory_hold as verifier
from solslot_api.inventory_extension_store import canonical
from solslot_api.inventory_payment_hold_store import assert_no_checkout_hold
from solslot_api.payment_purchase_store import PaymentPurchaseStore, PaymentPurchaseConflict
from solslot_api.validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from solslot_api.validator_service import ValidatorEvidenceError
from solslot_api.purchase_admission import ADMISSION_POLICY
from tests.test_inventory_payment_holds import hold_case, close, sibling, reserve_again
from tests.test_inventory_buyer_handoff import signature_pairs
from tests.test_single_external_delivery_context import hx, _b32, coin_record
from tests.test_purchase_admission import receipt
from tests.test_escrow_deposit import Chain


async def base_case(tmp_path, monkeypatch):
    c = await hold_case(tmp_path, monkeypatch)
    c.purchase = replace(c.purchase, rail=PaymentRail.EVM_TEST_USD, rail_chain_id=84532,
        rail_asset_id=BASE_SEPOLIA_USDC_ASSET_ID, rail_asset_decimals=6, rail_amount=c.purchase.subtotal_minor*10_000)
    raw = purchase_artifact_v3_to_json(c.purchase)
    inv = c.genesis['inventoryActivation']
    cap = dict(schema='solslot.base-inventory-hold.v1', environment='staging-alpha', network='testnet11',
        deploymentId=inv['deploymentId'], sourceShas=c.genesis['sourceShas'], inventoryVersion=2,
        adapterVersion=1, validatorLedgerVersion=14, chainId=84532, minConfirmations=3,
        spoke='0x'+'12'*20, token='0x'+bytes(BASE_SEPOLIA_USDC_ASSET_ID)[12:].hex(), sourceChainSelector=12345,
        availableModuleHash=inv['availableModuleHash'], reservedModuleHash=inv['reservedModuleHash'],
        paymentConfirmationEnabled=False, holdPolicy='base-prepayment-exclusion-v1', **ADMISSION_POLICY)
    cap['releaseIdentity'] = hashlib.sha256(canonical(cap).encode()).hexdigest()
    cap['reviewEvidenceSha256'] = 'eb'*32
    c.genesis['baseInventoryHold'] = cap
    local = hx(_b32(91))
    global_id = hx(Web3.keccak(encode(['uint8','uint64','address','address','bytes32','bytes32','bytes32'],
        [3,cap['sourceChainSelector'],cap['spoke'],cap['token'],bytes.fromhex(local[2:]),c.purchase.purchase_id,c.purchase.artifact_hash])))
    c.claim = BaseInventoryHoldClaim(network='testnet11', genesis_artifact_hash=c.genesis['artifactHash'], activation=cap,
        purchase_artifact=raw, smart_deed_inner_hash=hx(c.terms.smart_deed_inner_hash),
        reserved_coin_id=hx(c.reserved.name()), reserved_puzzle_hash=hx(c.reserved.puzzle_hash),
        reservation_expires_at=c.purchase.quote_expires_at, local_payment_id=local, global_payment_id=global_id,
        depositor='0x'+'14'*20)
    _,c.deed_struct,c.terms = base_hold_coordinates(c.claim,c.genesis,'staging-alpha')
    available=c.initial.coin_spends[0].coin
    launcher=Coin.from_json_dict(c.records[hx(c.purchase.deed_launcher_id)]['coin'])
    c.reservation=InventoryReservationV1(c.purchase,c.purchase.quote_expires_at)
    initial=build_inventory_reservation_spend(available_coin=available,deed_singleton_struct=c.deed_struct,
        lineage_proof=LineageProof(launcher.parent_coin_info,amount=1),reservation=c.reservation,signer_indices=(0,1),terms=c.terms)
    signatures=[AugSchemeMPL.sign(next(k for k in c.keys if k.get_g1()==pk),message) for pk,message in signature_pairs(initial.spend)]
    c.initial=SpendBundle([initial.spend],AugSchemeMPL.aggregate(signatures));c.reserved=initial.reserved_coin
    c.claim=c.claim.model_copy(update=dict(reserved_coin_id=hx(c.reserved.name()),reserved_puzzle_hash=hx(c.reserved.puzzle_hash)))
    c.records[hx(c.reserved.name())]=coin_record(c.reserved,confirmed=124)
    c.spends[(hx(available.name()),124)]=initial.spend.to_json_dict()
    old=c.original;c.purchases=PaymentPurchaseStore(str(tmp_path/'base-purchases.db'))
    c.purchases.save(purchase_intent_id='base-intent',rail='base_usdc',offer_artifact_hash='base-offer',
        offer_artifact=dict(purchaseArtifactV3=raw),purchase_artifact=raw,created_at=int(c.clock[0]))
    with c.purchases._connect() as db:
        db.execute("UPDATE payment_purchases SET inventory_state='CONFIRMED',inventory_reserved_coin_id=?,inventory_reserved_puzzle_hash=?,inventory_expires_at=? WHERE purchase_id=?",
            (c.claim.reserved_coin_id,c.claim.reserved_puzzle_hash,c.claim.reservation_expires_at,raw['purchaseId']))
    c.original=c.purchases.get(raw['purchaseId'])
    identity=receipt();identity['vaultLauncherId']=raw['vaultLauncherId'];owner=hx(c.keys[0].get_g1())
    c.purchases.admit_purchase(purchase_intent_id='base-intent',receipt=identity,activation=cap,
        now=int(c.clock[0]),owner_auth_type=1,owner_key=owner)
    c.purchases.begin_admitted_reservation(stored=c.original,receipt=identity,activation=cap,
        now=int(c.clock[0]),owner_auth_type=1,owner_key=owner)
    monkeypatch.setattr(coordinator,'recheck_admitted_owner',lambda store,pid:None)
    c.settings.zkpassport_validator_pubkeys=c.genesis['validatorSet']['pubkeys'];c.settings.zkpassport_validator_threshold=2
    c.settings.zkpassport_validator_urls=['https://signer0.invalid','https://signer1.invalid','https://signer2.invalid']
    for signer in c.signers:
        signer.base_sepolia_rpc_url='https://base.invalid';signer.base_sepolia_spoke_address=cap['spoke']
        signer.base_sepolia_usdc_address=cap['token'];signer.base_sepolia_min_confirmations=3
    c.evm=SimpleNamespace(chain_id=84532,paused=False,selector=12345,mapping=bytes(32),latest_mapping=bytes(32),
        timestamp=int(c.clock[0]),tip_hash=hx(_b32(92)),fail=False,queries=[])
    evm=c.evm
    class Call:
        def __init__(self,name):self.name=name
        def call(self,block_identifier):
            evm.queries.append((self.name,block_identifier))
            if evm.fail:raise OSError('offline')
            return {'localChainSelector':evm.selector,'paused':evm.paused,
                'mapping':evm.latest_mapping if block_identifier=='latest' else evm.mapping}[self.name]
    def contract(**kwargs):
        assert kwargs['address'].lower()==cap['spoke'] and kwargs['abi']==verifier.ABI
        return SimpleNamespace(functions=SimpleNamespace(localChainSelector=lambda:Call('localChainSelector'),
            paused=lambda:Call('paused'),globalPaymentForPurchase=lambda pid:Call('mapping')))
    evm.contract=contract
    evm.get_block=lambda height:dict(number=123,timestamp=evm.timestamp,hash=evm.tip_hash)
    class FakeWeb3:
        def __init__(self,_):self.eth=evm
        @staticmethod
        def HTTPProvider(url,request_kwargs,exception_retry_configuration):
            assert request_kwargs=={'timeout':2.0} and exception_retry_configuration is None
    original=verifier.verify_unfunded_base_hold
    monkeypatch.setattr(verifier,'verify_unfunded_base_hold',lambda settings,claim:original(settings,claim,web3_factory=FakeWeb3))
    async def quorum(settings,claim,path):
        assert path=='/v1/base-inventory-hold/sign'
        sigs=[G2Element.from_bytes(bytes.fromhex((await verifier.sign_base_inventory_hold(s,l,claim,claim.canonical_hash()))[2:]))
              for s,l in zip(c.signers,c.ledgers)]
        if getattr(c,'lose_response',False):raise OSError('lost after independent signing')
        return SimpleNamespace(signer_indices=(0,1),aggregated_signature=AugSchemeMPL.aggregate(sigs))
    monkeypatch.setattr(coordinator,'_collect_inventory_quorum',quorum)
    return c


async def arm(c):
    return await arm_base_checkout(store=c.purchases,settings=c.settings,claim=c.claim,
        load_artifact=lambda:deepcopy(c.genesis),authorize=lambda:None)


def deposit(c):
    raw=c.claim.purchase_artifact
    return dict(gatewayProfile='bse',globalPaymentId=c.claim.global_payment_id,localPaymentId=c.claim.local_payment_id,
        purchaseId=raw['purchaseId'],artifactHash=raw['artifactHash'],depositor=c.claim.depositor,
        settlementToken=c.claim.activation['token'],amount=c.purchase.rail_amount,quantity=1,
        collectionId=raw['collectionId'],deedLauncherId=raw['deedLauncherId'],vaultLauncherId=raw['vaultLauncherId'],
        destinationPuzzle=raw['vaultP2PuzzleHash'],quoteExpiresAt=c.purchase.quote_expires_at,
        source=dict(chainId=84532,spoke=c.claim.activation['spoke'],confirmations=12,transactionHash=hx(_b32(93)),
            blockNumber=123,blockHash=hx(_b32(94)),blockTimestamp=int(c.clock[0]),logIndex=2))


@pytest.mark.asyncio
async def test_real_hold_quorum_survives_loss_restart_expiry_and_blocks_reuse(tmp_path,monkeypatch):
    c=await base_case(tmp_path,monkeypatch)
    try:
        c.lose_response=True
        with pytest.raises(OSError):await arm(c)
        assert c.purchases.base_checkout_hold(c.claim.purchase_artifact['purchaseId'])['state']=='ARMING'
        first=c.ledgers[0].base_inventory_hold(c.claim.purchase_artifact['purchaseId'])
        assert AugSchemeMPL.verify(c.keys[0].get_g1(),c.claim.signature_message(),G2Element.from_bytes(bytes.fromhex(first['signature'][2:])))
        c.clock[0]=c.claim.reservation_expires_at+1000;c.evm.fail=True;c.lose_response=False
        c.ledgers[0].close();c.ledgers[0]=ValidatorLedger(tmp_path/'extension-signer-0.db')
        result=await arm(c)
        assert result['state']=='ARMED' and not result['confirmationAllowed'] and not result['inventoryReusable']
        assert c.ledgers[0].base_inventory_hold(c.claim.purchase_artifact['purchaseId'])==first
        with pytest.raises(ValidatorLedgerConflict,match='Base inventory'):reserve_again(c)
        with c.purchases._connect() as db,pytest.raises(PaymentPurchaseConflict,match='Base prepayment'):
            assert_no_checkout_hold(db,c.claim.purchase_artifact['purchaseId'])
        assert await arm(c)==result
    finally:close(c)


@pytest.mark.asyncio
async def test_bad_base_evidence_never_gets_private_signature_or_durable_hold(tmp_path,monkeypatch):
    c=await base_case(tmp_path,monkeypatch)
    original=c.claim
    try:
        mutations=[('global_payment_id',hx(_b32(90))),('depositor','0x'+'0'*40),('reserved_puzzle_hash',hx(_b32(90))),
            ('reservation_expires_at',c.claim.reservation_expires_at+1),('genesis_artifact_hash',hx(_b32(90)))]
        for field in ('deedLauncherId', 'purchaseId', 'artifactHash', 'railAssetId'):
            aliased = deepcopy(original.purchase_artifact)
            aliased[field] = '0x'+aliased[field][2:].upper()
            assert aliased != original.purchase_artifact
            mutations.append(('purchase_artifact', aliased))
        for key,value in mutations:
            claim=original.model_copy(update={key:value})
            with pytest.raises(ValidatorEvidenceError):
                await verifier.sign_base_inventory_hold(c.signers[0],c.ledgers[0],claim,claim.canonical_hash())
        for key,value in [('chain_id',1),('paused',True),('selector',3),('mapping',bytes.fromhex(hx(_b32(90))[2:])),
                          ('latest_mapping',bytes.fromhex(hx(_b32(90))[2:])),('timestamp',c.claim.reservation_expires_at),('fail',True)]:
            before=getattr(c.evm,key);setattr(c.evm,key,value)
            with pytest.raises(ValidatorEvidenceError):
                await verifier.sign_base_inventory_hold(c.signers[0],c.ledgers[0],original,original.canonical_hash())
            setattr(c.evm,key,before)
        assert c.ledgers[0].base_inventory_hold(original.purchase_artifact['purchaseId']) is None
    finally:close(c)


@pytest.mark.asyncio
async def test_base_provider_deposit_anchor_is_immutable_and_separate_from_stripe(tmp_path,monkeypatch):
    from solslot_api.escrow_deposit import verify_escrow_deposit
    c=await base_case(tmp_path,monkeypatch)
    try:
        await arm(c);e=deposit(c);chain=Chain(e)
        verify_escrow_deposit(rpc_url='https://offline.invalid',evidence=e,chain_id=84532,
            spoke=c.claim.activation['spoke'],token=c.claim.activation['token'],confirmations=3,web3_factory=chain.web3)
        pid=c.claim.purchase_artifact['purchaseId']
        c.purchases.bind_external_message(pid,e);c.ledgers[0].retain_base_payment_start(pid,e)
        old=c.ledgers[0].base_inventory_hold(pid)
        later=deepcopy(e);later['source']['confirmations']+=10
        c.ledgers[0].retain_base_payment_start(pid,later)
        assert c.ledgers[0].base_inventory_hold(pid)==old
        for key in ('globalPaymentId','localPaymentId','depositor'):
            altered=deepcopy(e);altered[key]='0x'+'19'*(20 if key=='depositor' else 32)
            with pytest.raises(ValueError):c.ledgers[0].retain_base_payment_start(pid,altered)
            with pytest.raises(ValueError):c.purchases.bind_external_message(pid,altered)
        for kind in ('single','batch','issuance','transition'):
            with pytest.raises(ValidatorLedgerConflict):sibling(c.ledgers[0],c,kind)
        assert c.ledgers[0].base_inventory_hold(pid)==old
    finally:close(c)


@pytest.mark.asyncio
async def test_exact_capability_and_false_payment_permission_are_required(tmp_path,monkeypatch):
    c=await base_case(tmp_path,monkeypatch)
    try:
        cap=deepcopy(c.genesis['baseInventoryHold'])
        for key,value in [('paymentConfirmationEnabled',True),('validatorLedgerVersion',13),('chainId',1),
                          ('reviewEvidenceSha256','0'*64),('environment','production-alpha'),('adapterVersion',2),
                          ('sourceChainSelector',True),('minConfirmations',1),('extra','ignored')]:
            c.genesis['baseInventoryHold']={**cap,key:value}
            with pytest.raises(ValueError):base_hold_activation(c.genesis,'staging-alpha')
        c.genesis['baseInventoryHold']=cap
        for deployment in (None, '0x'+'0'*64, 'unreviewed'):
            malformed=deepcopy(c.genesis)
            malformed['ceremony']['ceremonyId']=deployment
            malformed['inventoryActivation']['deploymentId']=deployment
            malformed['baseInventoryHold']['deploymentId']=deployment
            committed={k:v for k,v in malformed['baseInventoryHold'].items() if k not in ('releaseIdentity','reviewEvidenceSha256')}
            malformed['baseInventoryHold']['releaseIdentity']=hashlib.sha256(canonical(committed).encode()).hexdigest()
            with pytest.raises(ValueError):base_hold_activation(malformed,'staging-alpha')
        altered=c.claim.model_dump();altered['payment_intent_id']='pi_fake'
        with pytest.raises(ValueError):BaseInventoryHoldClaim.model_validate(altered)
        await arm(c)
        op=c.purchases.base_checkout_hold(c.claim.purchase_artifact['purchaseId']);op['receipt']['signature']=hx(G2Element())
        with pytest.raises(ValueError):base_checkout_status(op,c.genesis)
    finally:close(c)


@pytest.mark.asyncio
async def test_real_private_http_quorum_and_service_recovery_route(tmp_path,monkeypatch):
    from solslot_api.validator_app import create_validator_app
    from solslot_api.validator_quorum import _collect_inventory_quorum, ValidatorQuorumError
    from solslot_api import native_purchases
    c=await base_case(tmp_path,monkeypatch)
    try:
        apps=[create_validator_app(settings=s,ledger=l) for s,l in zip(c.signers,c.ledgers)]
        for app,ledger in zip(apps,c.ledgers):app.state.validator_ledger=ledger
        transports=[httpx.ASGITransport(app=app) for app in apps];offline={2}
        async def dispatch(request):
            index=int(request.url.host[6])
            if index in offline:return httpx.Response(503,json={'detail':'offline'})
            return await transports[index].handle_async_request(request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as client:
            async def quorum(settings,claim,path):
                return await _collect_inventory_quorum(settings,claim,path,client=client)
            monkeypatch.setattr(coordinator,'_collect_inventory_quorum',quorum)
            c.settings.payment_purchase_db_path=c.purchases.path
            monkeypatch.setattr(native_purchases,'load_signed_public_artifact',lambda _:deepcopy(c.genesis))
            auth='Bearer '+c.settings.protocol_artifact_api_token
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as denied:
                await native_purchases.arm_base_inventory_hold(c.claim,c.settings,None)
            assert denied.value.status_code==401
            result=await native_purchases.arm_base_inventory_hold(c.claim,c.settings,auth)
            assert result['state']=='ARMED' and result['confirmationAllowed'] is False
            c.settings.alpha_writes_enabled=False;c.clock[0]=c.claim.reservation_expires_at+5
            assert await native_purchases.arm_base_inventory_hold(c.claim,c.settings,auth)==result
            offline.add(1)
            with pytest.raises(ValidatorQuorumError):await quorum(c.settings,c.claim,'/v1/base-inventory-hold/sign')
    finally:close(c)


@pytest.mark.asyncio
async def test_atomic_base_hold_blocks_competing_payment_and_preserves_old_schema_bytes(tmp_path,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    c=await base_case(tmp_path,monkeypatch);other=ValidatorLedger(tmp_path/'extension-signer-0.db')
    try:
        barrier=Barrier(2)
        def race(kind):
            barrier.wait()
            try:
                if kind=='hold':c.ledgers[0].record_base_inventory_hold(c.claim,'fixture-signature')
                else:sibling(other,c,'issuance')
                return kind
            except ValidatorLedgerConflict:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(race,('hold','payment')))
        assert results.count('refused')==1
        # A genuine v13 fixture has no v14 table. Migration preserves old rows.
        c.ledgers[1]._conn.execute("INSERT INTO voucher_issuance_signatures VALUES (?,?,?,?,?,?,?)",
            ('original','original exact bytes','global','series','launcher','original signature',1))
        before=tuple(c.ledgers[1]._conn.execute('SELECT * FROM voucher_issuance_signatures').fetchone())
        c.ledgers[1]._conn.executescript('DROP TABLE base_inventory_holds; DROP TABLE base_lifecycle_observations; DROP TABLE base_lifecycle_terminals; DROP TABLE base_inventory_hold_generations; DROP TABLE voucher_series_phase_retry_signatures; DROP TABLE voucher_phase_expiry_observations; PRAGMA user_version=13;')
        c.ledgers[1].close();c.ledgers[1]=ValidatorLedger(tmp_path/'extension-signer-1.db')
        assert tuple(c.ledgers[1]._conn.execute('SELECT * FROM voucher_issuance_signatures').fetchone())==before
        assert c.ledgers[1].healthcheck()
    finally:other.close();close(c)


@pytest.mark.asyncio
async def test_canceled_private_rpc_keeps_bounded_capacity_and_loop_responsive(monkeypatch):
    import threading
    from solslot_api.escrow_deposit import EscrowProviderUnavailable
    entered=[threading.Event(),threading.Event()];release=threading.Event();count=[0];lock=threading.Lock()
    def blocking(settings,claim):
        with lock:i=count[0];count[0]+=1
        entered[i].set();release.wait(5)
    monkeypatch.setattr(verifier,'verify_unfunded_base_hold',blocking)
    tasks=[asyncio.create_task(verifier.bounded_unfunded_proof(None,None)) for _ in range(2)]
    try:
        for _ in range(200):
            if all(event.is_set() for event in entered):break
            await asyncio.sleep(.005)
        assert all(event.is_set() for event in entered)
        tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):await tasks[0]
        for _ in range(20):
            with pytest.raises(EscrowProviderUnavailable):await verifier.bounded_unfunded_proof(None,None)
        assert count==[2]
        assert await asyncio.wait_for(asyncio.sleep(0,result='recovery-responsive'),.1)=='recovery-responsive'
    finally:
        release.set();await asyncio.gather(*tasks,return_exceptions=True)
        for _ in range(200):
            if verifier._slots._value==2:break
            await asyncio.sleep(.005)
        assert verifier._slots._value==2


@pytest.mark.asyncio
async def test_disabled_lifecycle_retains_independent_start_before_key_access(tmp_path,monkeypatch):
    from solslot_api import validator_service as service
    from solslot_api.escrow_deposit import verify_escrow_deposit
    c=await base_case(tmp_path,monkeypatch)
    try:
        await arm(c);e=deposit(c);chain=Chain(e)
        verify_escrow_deposit(rpc_url='https://offline.invalid',evidence=e,chain_id=84532,
            spoke=c.claim.activation['spoke'],token=c.claim.activation['token'],confirmations=3,web3_factory=chain.web3)
        claim=SimpleNamespace(purchase_artifact=c.claim.purchase_artifact,voucher_commitment=dict(paymentRail=1),
            global_payment_id=lambda:c.claim.global_payment_id,payment_evidence=e)
        with pytest.raises(ValidatorEvidenceError):service._retain_verified_base_hold_payment(c.signers[0],c.ledgers[0],claim)
        assert json.loads(c.ledgers[0].base_inventory_hold(c.claim.purchase_artifact['purchaseId'])['payment_start_json'])==e
        for kind in ('extension','single','batch','issuance','transition'):
            with pytest.raises(ValidatorLedgerConflict):sibling(c.ledgers[0],c,kind,pi=c.claim.global_payment_id)
        assert not c.funded and not c.extension_dispatches
    finally:close(c)


@pytest.mark.asyncio
async def test_private_full_proof_budget_also_bounds_slow_chia_reads(tmp_path,monkeypatch):
    c=await base_case(tmp_path,monkeypatch);entered=asyncio.Event();release=asyncio.Event();count=[0]
    original=verifier.IndependentNode.current
    async def blocked(node,*args,**kwargs):
        count[0]+=1
        if count[0]==2:entered.set()
        await release.wait()
        return await original(node,*args,**kwargs)
    monkeypatch.setattr(verifier.IndependentNode,'current',blocked)
    tasks=[asyncio.create_task(verifier.sign_base_inventory_hold(c.signers[0],c.ledgers[0],c.claim,c.claim.canonical_hash())) for _ in range(2)]
    try:
        await asyncio.wait_for(entered.wait(),5)
        queries=len(c.evm.queries)
        for _ in range(10):
            with pytest.raises(ValidatorEvidenceError):
                await verifier.sign_base_inventory_hold(c.signers[0],c.ledgers[0],c.claim,c.claim.canonical_hash())
        assert len(c.evm.queries)==queries and count==[2]
    finally:
        release.set();results=await asyncio.gather(*tasks,return_exceptions=True)
        close(c)
    assert all(isinstance(result,str) for result in results) and results[0]==results[1]
