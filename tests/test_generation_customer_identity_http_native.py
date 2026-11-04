"""Website ID routes -> independent signers -> funded native confirmation.

All keys and property/generation facts are synthetic. The external passport
receipt is an explicit synthetic fixture; its real calldata/code checks have
their own adversarial suite. Native custody, signatures, fees and consensus
are real simulation, never a public-chain transaction.
"""
import asyncio
import contextvars
import json
import time
from hashlib import sha256
from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data
from solslot_api.generation_customer_store import read_consent
from solslot_api.generation_operations import reconcile_saved_operation
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.generation_customer_identity_factory import configured_current_customer_identity
from solslot_api.generation_customer_identity_routes import router as identity_router
from solslot_api.generation_customer_identity_validators import sign_current_identity
from solslot_api.validator_ledger import ValidatorLedger
from solslot_api.validator_settings import ValidatorSettings
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_api.config import Settings
from solslot_api.zkpassport_enrollments import IndexedEvmAttestation
from solslot_puzzles.zkpassport_attestation import (
    ZkPassportAttestation,compute_attestation_root,compute_attestation_bridge_message,compute_validator_bridge_message)
from tests.test_generation_customer_routes import customer,BASE
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete
from tests.test_generation_customer_launch import sign
from tests.test_generation_customer_purchase_native import real_synthetic_identity_policy
from tests.test_generation_customer_identity_context import profile
from tests.test_generation_customer_identity_orchestration import authority
from tests.test_validator_app import _settings as private_settings

ID='/protocol-api/next/customer/identity'


@pytest.mark.asyncio
async def test_current_id_http_requires_fresh_vault_preserves_work_and_confirms_native_stamp(customer,tmp_path,monkeypatch):
    p=customer;generation=p.settings.deployment_generation_id
    defaults=Settings(_env_file=None,runtime_environment='test',alpha_writes_enabled=False).model_dump()
    original=dict(vars(p.settings));p.settings.__dict__.update(defaults);p.settings.__dict__.update(original)
    p.settings.model_copy=lambda *,update:SimpleNamespace(**{**vars(p.settings),**update})
    p.settings.generation_customer_identity_enabled=True
    p.settings.zkpassport_validator_urls=[f'https://synthetic-validator-{i}.invalid' for i in range(3)]
    secret=Account.from_key(b'z'*32)
    review=await p.client.post(BASE+'/reviews',json={'generationId':generation,'owner':secret.address,'authType':'evm'})
    assert review.status_code==200,review.text
    saved=review.json();registration=saved['registrationId'];launcher=saved['vaultLauncherId'];path=BASE+'/reviews/'+registration
    authorized=await p.client.post(path+'/authorize',json={'generationId':generation,'signature':sign(read_consent(saved['review']),secret)})
    assert authorized.status_code==200,authorized.text
    submitted=await p.client.post(path+'/submit',json={'generationId':generation});assert submitted.status_code==200,submitted.text
    await p.c.sim.farm_block()
    operation=authorized.json()['operationId']
    await reconcile_saved_operation(p.journal,operation,p.node,clock=lambda:p.now[0]);await p.runtime.reconcile_once()
    connected=await p.client.post(path+'/connect',json={'generationId':generation});assert connected.status_code==200,connected.text
    # A dedicated fresh bridge is unrelated to any old enrollment reservation.
    acs=Program.to(1)
    origin=next(r.coin for r in await p.c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not r.spent)
    bridge=Coin(origin.name(),bytes32.from_hexstr(p.c.prep.bridge_policy_hash),uint64(1))
    setup=SpendBundle([make_spend(origin,acs,Program.to([[51,bridge.puzzle_hash,1],
        [51,acs.get_tree_hash(),int(origin.amount)-1]]))],G2Element())
    assert await p.c.client.push_tx(setup)==(MempoolInclusionStatus.SUCCESS,None);await p.c.sim.farm_block()
    await p.index.run_once()
    p.now[0]=int(time.time())
    from solslot_api.generation_customer_context import current_customer_launch_bindings
    bindings=current_customer_launch_bindings(p.settings,p.index,now=p.now[0])
    data,_=profile();data.update(generationId=generation,preparationManifest=p.c.prep.manifest_hash,
        poolLauncherId='0x'+bindings.pool_launcher.hex(),vaultModuleHash='0x'+bindings.vault_module.hex(),
        bridgePolicyHash=p.c.prep.bridge_policy_hash,bridgeCoins=[{'parentId':'0x'+bridge.parent_coin_info.hex(),'coinId':'0x'+bridge.name().hex()}])
    pins=CurrentCustomerIdentityProfile.model_validate(data).require_native(bindings)
    profile_path=tmp_path/'current-id.json';profile_path.write_text(pins.model_dump_json(by_alias=True))
    p.settings.generation_customer_identity_profile_path=str(profile_path)
    p.settings.generation_customer_identity_profile_hash='0x'+sha256(profile_path.read_bytes()).hexdigest()
    fees=[r.coin for r in await p.c.client.get_coin_records_by_puzzle_hash(p.c.faucet.address_puzzle_hash)
        if not r.spent and '0x'+r.coin.name().hex() not in p.runtime.policy.allowed_parent_ids|p.runtime.policy.allowed_fee_ids]
    policy=authority(pins,issuedAt=p.now[0]-1,expiresAt=p.now[0]+7200,
        fundingPuzzleHash=p.c.faucet.address_hex,feeCoinIds=['0x'+fees[0].name().hex()],
        maximumFeeParentMojos=int(fees[0].amount),maximumStampFeeMojos=100)
    policy_path=tmp_path/'current-id-authority.json';policy_path.write_text(policy.model_dump_json(by_alias=True))
    p.settings.generation_customer_identity_authority_path=str(policy_path)
    p.settings.generation_customer_identity_authority_hash='0x'+sha256(policy_path.read_bytes()).hexdigest()
    p.settings.generation_customer_identity_fee_signer_key_path=p.settings.generation_customer_signer_key_path
    p.settings.generation_customer_identity_funding_db_path=str(tmp_path/'identity-fees.db')
    import solslot_api.credential_auth as auth
    import solslot_api.zkpassport_enrollments as enroll
    import solslot_api.generation_customer_identity_runtime as runtime_module
    ledger=auth.get_credential_ledger(p.settings)
    for module in (enroll,runtime_module):monkeypatch.setattr(module,'get_credential_ledger',lambda _:ledger)
    monkeypatch.setattr(runtime_module,'read_current_identity_compatibility',lambda settings,pins,now:{
        'status':'READY','checkedAt':now,'profileHash':pins.commitment,
        'proofVersions':list(pins.accepted_proof_versions),'blockNumber':100})
    monkeypatch.setattr(enroll,'get_registry',lambda:p.registry)
    p.runtime.clock=time.time
    service=configured_current_customer_identity(p.settings,p.runtime,clock=time.time)
    app=next(r.app for r in p.app.routes if getattr(r,'path',None)=='/protocol-api/next')
    app.include_router(identity_router);app.state.generation_customer_identity=service;app.state.coinset=p.node
    async def observe_generation():
        while True:
            await p.index.run_once()
            await asyncio.sleep(2)
    observer=asyncio.create_task(observe_generation())
    try:
        current_path=ID+'/enrollments/'+launcher
        foreign=await p.client.post(current_path,json={'generationId':'0x'+'91'*32});assert foreign.status_code==409
        reserved=await p.client.post(current_path,json={'generationId':generation});assert reserved.status_code==200,reserved.text
        record=reserved.json();assert record['status']=='reserved' and record['bridgeCoinId']=='0x'+bridge.name().hex()
        assert record['identityDeployment']['generationId']==generation and record['receipt'] is None
        assert (await p.client.post(current_path,json={'generationId':generation})).json()==record
        reads_before=p.node.selections
        async def forbidden(*a,**kw):raise AssertionError('GET must not read a node or sign')
        with monkeypatch.context() as patch:
            patch.setattr(p.node,'get_coin_record_by_name_primary',forbidden)
            assert (await p.client.get(current_path)).json()==record
        assert p.node.selections==reads_before
        proof_time=int(time.time());att=ZkPassportAttestation(vault_launcher_id=bytes32.from_hexstr(launcher),
            scoped_nullifier=bytes32(b'n'*32),nullifier_type=1,service_scope_hash=bytes32(b's'*32),
            service_subscope_hash=bytes32(b'u'*32),proof_timestamp=proof_time,policy_version=2)
        root=compute_attestation_root([att.leaf_hash]);message=compute_attestation_bridge_message(
            vault_launcher_id=att.vault_launcher_id,attestation_root=root,bridge_policy_hash=bridge.puzzle_hash,policy_version=2)
        validator_message=compute_validator_bridge_message(vault_launcher_id=att.vault_launcher_id,
            attestation_root=root,bridge_policy_hash=bridge.puzzle_hash,bridge_coin_id=bridge.name(),bridge_message=message,
            attestation_leaf_hash=att.leaf_hash,scoped_nullifier=att.scoped_nullifier,nullifier_type=1,
            service_scope_hash=att.service_scope_hash,service_subscope_hash=att.service_subscope_hash,
            proof_timestamp=proof_time,policy_version=2)
        h=lambda value:'0x'+value.hex()
        event=IndexedEvmAttestation(sender=secret.address,vault_launcher_id=launcher,scoped_nullifier=h(att.scoped_nullifier),
            nullifier_type=1,service_scope_hash=h(att.service_scope_hash),service_subscope_hash=h(att.service_subscope_hash),
            proof_timestamp=proof_time,attestation_leaf_hash=h(att.leaf_hash),identity_attest_root=h(root),
            bridge_parent_id=h(bridge.parent_coin_info),bridge_amount=1,bridge_coin_id=h(bridge.name()),
            bridge_message=h(message),bridge_policy_hash=h(bridge.puzzle_hash),policy_version=2,
            validator_message=h(validator_message),transaction_hash='0x'+'71'*32,block_number=100)
        real_fetch=enroll._fetch_verified_evm_attestation
        def synthetic_external(settings,*,current_profile=None,transaction_hash,expected_vault_launcher_id,**kwargs):
            from solslot_api.generation_customer_identity_scope import current_identity_scope
            if current_identity_scope(settings) is not None:
                return real_fetch(settings,current_profile=current_profile,transaction_hash=transaction_hash,
                    expected_vault_launcher_id=expected_vault_launcher_id,**kwargs)
            assert current_profile==pins and transaction_hash==event.transaction_hash and expected_vault_launcher_id==launcher
            return event
        monkeypatch.setattr(enroll,'_fetch_verified_evm_attestation',synthetic_external)
        proof_body=dict(generationId=generation,vaultLauncherId=launcher,policyVersion=2,
            identityAttestRoot=h(root),attestationLeafHash=h(att.leaf_hash),attestationProof={'bitpath':0,'siblings':[]},
            bridgePolicyHash=h(bridge.puzzle_hash),bridgeParentId=h(bridge.parent_coin_info),bridgeAmount=1,
            bridgeCoinId=h(bridge.name()),bridgeMessage=h(message),validatorMessage=h(validator_message),evmTxHash=event.transaction_hash)
        proved=await p.client.post(current_path+'/proof',json=proof_body);assert proved.status_code==200,proved.text
        assert proved.json()['receipt']['generationId']==generation and proved.json()['receipt']['genesisArtifactHash'] is None
        assert (await p.client.post(current_path+'/proof',json=proof_body)).json()==proved.json()
        assert (await p.client.post(current_path+'/proof',json={**proof_body,'identityAttestRoot':'0x'+'92'*32})).status_code==409
        anchor=complete(p.c)[2].review()['readAnchor'];anchor_path=tmp_path/'native-anchor.json';anchor_path.write_text(json.dumps(anchor))
        signer_settings=[];signer_ledgers=[]
        addresses={c.role:c.address for c in pins.contracts}
        for index in (0,1):
            directory=tmp_path/f'signer-{index}';directory.mkdir()
            seed_settings=private_settings(directory)
            (directory/'validator.seed').write_text(bytes([31+index]).hex()*32+'\n');(directory/'validator.seed').chmod(0o600)
            raw=seed_settings.model_dump();raw.update(signer_index=index,evm_chain_id=8453,
                generation_customer_identity_enabled=True,generation_customer_identity_profile_path=str(profile_path),
                generation_customer_identity_profile_hash=p.settings.generation_customer_identity_profile_hash,
                deployment_generation_id=generation,generation_preparation_path=p.settings.generation_preparation_path,
                generation_preparation_hash=p.settings.generation_preparation_hash,generation_chain_anchor_path=str(anchor_path),
                generation_chain_anchor_hash='0x'+sha256(anchor_path.read_bytes()).hexdigest(),generation_primary_url='https://synthetic.invalid',
                evm_forwarder_address=addresses['forwarder'],evm_verifier_adapter_address=addresses['verifierAdapter'],
                evm_attestation_emitter_address=addresses['attestationEmitter'])
            signer_settings.append(ValidatorSettings(**raw));signer_ledgers.append(ValidatorLedger(':memory:'))
        async def quorum(settings,claim,**kwargs):
            # Real signer validation runs in clean private contexts, never
            # borrowing the coordinator's request-local evidence cache.
            tasks=[contextvars.Context().run(asyncio.create_task,sign_current_identity(config,led,claim,
                claim.canonical_hash(),provider=p.node)) for config,led in zip(signer_settings,signer_ledgers)]
            signed=await asyncio.gather(*tasks)
            return ValidatorQuorumResult((0,1),AugSchemeMPL.aggregate([
                G2Element.from_bytes(bytes.fromhex(row.signature[2:])) for row in signed]),claim.canonical_hash())
        monkeypatch.setattr(enroll,'collect_validator_quorum',quorum)
        # The exact primary clock reader is covered separately. Here the
        # simulator supplies its own authoritative transaction-block time.
        import solslot_api.stamp_funding as funding
        class Snapshot:
            def __init__(self,*args):self.transaction_time=int(p.c.sim.timestamp)
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
        monkeypatch.setattr(funding,'PrimaryReadSnapshot',Snapshot)
        p.node.primary=p.node
        async def available():return True
        p.node._primary_available=available
        original_estimate=p.node.get_fee_estimate
        async def estimated(**kwargs):
            quote=await original_estimate(**kwargs)
            return {**quote,'target_times':kwargs['target_times']}
        p.node.get_fee_estimate=estimated
        async def mempool_items(coin_id):
            return [{'spend_bundle_name':'0x'+item.name.hex()}
                for item in (await p.c.client.get_all_mempool_items()).values()
                if bytes32.from_hexstr(coin_id) in {coin.name() for coin in item.removals}]
        p.node.get_mempool_items_by_coin_name=mempool_items
        prepared=await p.client.post(current_path+'/stamp/prepare',json={'generationId':generation})
        assert prepared.status_code==200,prepared.text
        owner_signature='0x'+Account.sign_message(encode_typed_data(full_message=prepared.json()['typedData']),secret.key).signature.hex()
        p.c.sim.pass_time(max(0,int(time.time())-int(p.c.sim.timestamp)));await p.c.sim.farm_block()
        before_pushes=p.node.pushes
        posted=await p.client.post(current_path+'/stamp/submit',json={'generationId':generation,'signature':owner_signature})
        assert posted.status_code==200,posted.text
        txid=posted.json()['spendBundleId'];assert p.node.pushes==before_pushes+1
        repeated=await p.client.post(current_path+'/stamp/submit',json={'generationId':generation,'signature':owner_signature})
        assert repeated.status_code==200,repeated.text
        assert repeated.json()['spendBundleId']==txid and p.node.pushes==before_pushes+1
        await p.c.sim.farm_block();await p.index.run_once();p.now[0]=int(time.time())
        synced=await p.client.post(current_path+'/stamp/sync',json={'generationId':generation})
        assert synced.status_code==200,synced.text
        assert synced.json()['enrollment']['status']=='chia_confirmed'
        view=(await p.client.get('/protocol-api/next/customer/session/'+launcher)).json()
        assert view['vault']['identityVerified'] and view['vault']['identityAttestRoot']==h(root)
        assert (await p.client.get(current_path)).json()['status']=='chia_confirmed'
        for led in signer_ledgers:led.close()
    finally:
        observer.cancel()
        from contextlib import suppress
        with suppress(asyncio.CancelledError):await observer
        service.close()
