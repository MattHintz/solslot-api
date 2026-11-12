"""Public customer lifecycle against native Testnet consensus simulation.

All keys, state and coins are synthetic. No external RPC or live wallet is used.
"""
from types import SimpleNamespace
import time
import json
from hashlib import sha256

import httpx
import jwt
import pytest
import pytest_asyncio
from fastapi import FastAPI
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from eth_account import Account

from solslot_api.config import get_settings
from solslot_api.credential_auth import VAULT_SESSION_COOKIE
from solslot_api.generation_customer_routes import router,session_router
from solslot_api.generation_customer_runtime import CustomerCreationPolicy, GenerationCustomerRuntime
from solslot_api.generation_customer_store import GenerationCustomerStore, read_consent
from solslot_api.generation_index import GenerationIndexStore, GenerationIndexReconciler
from solslot_api.generation_operations import GenerationOperationJournal, reconcile_saved_operation
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from solslot_api.state import VaultRegistry
from tests.test_generation_customer_launch import sign
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete
from tests.test_generation_recipient_execution import Node

BASE = '/protocol-api/next/customer/registration'


@pytest_asyncio.fixture
async def customer(core, tmp_path, monkeypatch):
    c = core
    _, _, built = complete(c)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    prep = tmp_path / 'preparation.json'
    prep.write_text(c.prep.model_dump_json(by_alias=True))
    now = [int(time.time())]
    node = Node(c.client)
    index = GenerationIndexReconciler(built.anchor,
        GenerationIndexStore(str(tmp_path/'index.db'), c.prep.generation_id, '0x'+'26'*32), node)
    await index.run_once()
    now[0] = int(time.time())
    from solslot_api.generation_customer_context import current_customer_launch_bindings
    parents = [r.coin for r in await c.client.get_coin_records_by_puzzle_hash(c.faucet.address_puzzle_hash)
        if not r.spent and r.coin.amount > 1]
    settings = SimpleNamespace(network='testnet11', deployment_generation_id=c.prep.generation_id,
        generation_preparation_path=str(prep), generation_preparation_hash=c.prep.manifest_hash,
        generation_customer_enabled=True, generation_customer_public_origin='https://test',
        vault_session_ttl_seconds=900, vault_session_cookie_path='/protocol-api',
        vault_session_jwt_secret='synthetic customer session test secret only')
    current_customer_launch_bindings(settings,index,now=now[0])
    policy = CustomerCreationPolicy(c.prep.generation_id,
        frozenset('0x'+p.name().hex() for p in parents[:2]), 1_000_000_000, 100, now[0]-1, now[0]+7200,
        frozenset('0x'+p.name().hex() for p in parents[2:4]))
    journal = GenerationOperationJournal(str(tmp_path/'operations.db'), c.prep.generation_id)
    registry = VaultRegistry.open(generation_path(str(tmp_path/'vaults.db'), c.prep.generation_id))
    policy_file=tmp_path/'customer-policy.json'
    policy_file.write_text(json.dumps(dict(schema='solslot.customer-funding-policy.v1',
        generationId=c.prep.generation_id,fundingPuzzleHash=c.faucet.address_hex,
        creationParentIds=sorted(policy.allowed_parent_ids),feeParentIds=sorted(policy.allowed_fee_ids),
        maximumCreationParentMojos=policy.maximum_parent_mojos,maximumFeeParentMojos=policy.maximum_fee_parent_mojos,
        maximumFeeMojos=policy.fee_cap_mojos,issuedAt=policy.issued_at,expiresAt=policy.expires_at)))
    key_file=tmp_path/'synthetic-key'
    key_file.write_text(bytes(c.faucet.master_sk).hex())
    key_file.chmod(0o400)
    settings.generation_customer_policy_path=str(policy_file)
    settings.generation_customer_policy_hash='0x'+sha256(policy_file.read_bytes()).hexdigest()
    settings.generation_customer_signer_key_path=str(key_file)
    settings.generation_customer_db_path=generation_path(str(tmp_path/'customers.db'),c.prep.generation_id)
    settings.generation_customer_fee_db_path=generation_path(str(tmp_path/'fees.db'),c.prep.generation_id)
    from solslot_api.generation_customer_factory import configured_generation_customers
    runtime=configured_generation_customers(settings,index=index,provider=node,journal=journal,
        registry=registry,clock=lambda:now[0])
    store=runtime.store
    funding=runtime.submitter.funding_store
    app = FastAPI()
    app.include_router(router)
    app.include_router(session_router)
    import solslot_api.credential_auth as auth_module
    from solslot_api.credential_ledger import CredentialLedger
    credential_ledger=CredentialLedger(tmp_path/'credential.db',generation_id=c.prep.generation_id)
    monkeypatch.setattr(auth_module,'get_registry',lambda:registry)
    monkeypatch.setattr(auth_module,'get_credential_ledger',lambda _settings:credential_ledger)
    settings.zkpassport_owner_challenge_ttl_seconds=300
    settings.challenge_store_max_pending=100
    settings.eip712_name='Solslot Protocol'
    settings.eip712_version='2'
    settings.eip712_chain_id=11155111
    app.state.generation_customers = runtime
    app.dependency_overrides[get_settings] = lambda:settings
    root = FastAPI()
    root.mount('/protocol-api/next', app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=root), base_url='https://test',
            headers={'Origin':'https://test'}) as client:
        yield SimpleNamespace(c=c, node=node, index=index, runtime=runtime, store=store,
            journal=journal, registry=registry, funding=funding, client=client, app=root, now=now,
            settings=settings)
    runtime.close()
    registry.close()
    credential_ledger.close()


@pytest.mark.parametrize('auth', ['evm', 'chia_bls'])
@pytest.mark.parametrize('lost_response',[False,True])
@pytest.mark.asyncio
async def test_native_public_registration_and_restart_without_duplicate_transaction(customer, auth, lost_response, monkeypatch):
    p = customer
    secret = Account.from_key(b'z'*32) if auth == 'evm' else AugSchemeMPL.key_gen(b'fresh HTTP customer native tests!')
    owner = secret.address if auth == 'evm' else '0x'+bytes(secret.get_g1()).hex()
    generation = p.settings.deployment_generation_id
    body = {'generationId':generation, 'owner':owner, 'authType':auth}
    profile = (await p.client.get(BASE+'/profile')).json()
    assert profile['registrationEnabled'] and profile['earlierVaultsAdmitted'] is False
    # Old generation, cross-origin and cross-browser requests cannot hold or
    # authorize the current funding inputs.
    assert (await p.client.post(BASE+'/reviews', json={**body,'generationId':'0x'+'ab'*32})).status_code == 409
    assert (await p.client.post(BASE+'/reviews', json=body, headers={'Origin':'https://attacker'})).status_code == 403
    assert not p.store.held_funding_ids()
    review = await p.client.post(BASE+'/reviews', json=body)
    assert review.status_code == 200, review.text
    assert 'Secure' in review.headers['set-cookie'] and 'HttpOnly' in review.headers['set-cookie']
    saved = review.json()
    identity = saved['registrationId']
    path = BASE+'/reviews/'+identity
    assert saved['nextAction'] == 'APPROVE_CREATION_IN_WALLET'
    assert not saved['identityVerified'] and not saved['registrationConfirmed']
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app), base_url='https://test',
            headers={'Origin':'https://test'}) as stranger:
        assert (await stranger.get(path)).status_code == 401
        assert (await stranger.post(path+'/connect',json={'generationId':generation})).status_code == 401
    assert (await p.client.post(path+'/connect',json={'generationId':generation})).status_code == 409
    # One interrupted preparation preserves accepted authorization. Resuming
    # needs no new wallet signature, including after the original sign-by time.
    import solslot_api.generation_customer_runtime as module
    real_prepare = module.prepare_customer_operation
    async def interrupted(*args,**kwargs):raise OSError('synthetic loss before construction')
    monkeypatch.setattr(module,'prepare_customer_operation',interrupted)
    signature = sign(read_consent(saved['review']),secret)
    lost = await p.client.post(path+'/authorize',json={'generationId':generation,'signature':signature})
    assert lost.status_code == 503
    assert (await p.client.get(path)).json()['nextAction'] == 'RESUME_PREPARATION'
    monkeypatch.setattr(module,'prepare_customer_operation',real_prepare)
    prepared = await p.client.post(path+'/prepare',json={'generationId':generation})
    assert prepared.status_code == 200, prepared.text
    assert prepared.json()['nextAction'] == 'SUBMIT_REGISTRATION'
    operation = prepared.json()['operationId']
    original = bytes(p.journal.protocol_bundle(operation))
    # Native fees and the saved dispatch journal are exercised, not an HTTP
    # stub that merely claims submission succeeded.
    p.node.lose_response=lost_response
    submitted = await p.client.post(path+'/submit',json={'generationId':generation})
    if lost_response:
        assert submitted.status_code==503
        retained=(await p.client.get(path)).json()
        assert retained['stage']=='RECONCILING' and retained['transactionId']
        before=p.node.selections
        fee_path=p.funding.path
        p.funding.close()
        p.funding=ProtocolFundingStore(fee_path)
        p.runtime.submitter.funding_store=p.funding
        p.journal=GenerationOperationJournal(p.journal.path,generation)
        p.runtime.journal=p.journal
        submitted=await p.client.post(path+'/submit',json={'generationId':generation})
        assert submitted.status_code==200,submitted.text
        assert submitted.json()['transactionId']==retained['transactionId']
        assert p.node.selections==before
    assert submitted.status_code == 200, submitted.text
    assert p.node.pushes == 1
    txid = submitted.json()['transactionId']
    await p.c.sim.farm_block()
    await reconcile_saved_operation(p.journal,operation,p.node,clock=lambda:p.now[0])
    assert await p.runtime.reconcile_once() == 1
    assert await p.runtime.reconcile_once() == 0
    # A restart reopens the same saved state; status is safe even if every
    # signing, selection or node method is unavailable.
    p.runtime.store = GenerationCustomerStore(str(p.store.path),generation)
    p.runtime.journal = GenerationOperationJournal(str(p.journal.path),generation)
    def no_sign(*args,**kwargs):raise AssertionError('status must never sign')
    async def no_node(*args,**kwargs):raise AssertionError('status must never call the node')
    monkeypatch.setattr(p.runtime.faucet,'sign_delegated_spend',no_sign)
    real_node=p.node.get_coin_record_by_name_primary
    monkeypatch.setattr(p.node,'get_coin_record_by_name_primary',no_node)
    for _ in range(3):
        current = await p.client.get(path)
        assert current.status_code == 200, current.text
        assert current.json()['stage'] == 'VAULT_READY'
        assert current.json()['transactionId'] == txid
        assert not current.json()['identityVerified']
        assert VAULT_SESSION_COOKIE not in current.headers.get('set-cookie','')
    assert bytes(p.runtime.journal.protocol_bundle(operation)) == original
    assert (await p.client.post(path+'/submit',json={'generationId':generation})).status_code == 200
    assert p.node.pushes == 1
    monkeypatch.setattr(p.node,'get_coin_record_by_name_primary',real_node)
    async def reorganized(*args,**kwargs):return None
    monkeypatch.setattr(p.node,'get_coin_record_by_name_primary',reorganized)
    refused=await p.client.post(path+'/connect',json={'generationId':generation})
    assert refused.status_code==409 and VAULT_SESSION_COOKIE not in refused.headers.get('set-cookie','')
    monkeypatch.setattr(p.node,'get_coin_record_by_name_primary',real_node)
    connected = await p.client.post(path+'/connect',json={'generationId':generation})
    assert connected.status_code == 200, connected.text
    claims = jwt.decode(p.client.cookies.get(VAULT_SESSION_COOKIE),p.settings.vault_session_jwt_secret,
        algorithms=['HS256'],audience='solslot-credential-v2')
    assert claims['generationId'] == generation and claims['vaultLauncherId'] == saved['vaultLauncherId']
    assert 'identityVerified' not in claims
    # The same native projection feeds every UI surface. GET is read-only,
    # including when the signer/node are unavailable. It cannot hydrate an
    # old record or treat an altered stored receipt as a new ID stamp.
    session_path='/protocol-api/next/customer/session/'+saved['vaultLauncherId']
    monkeypatch.setattr(p.node,'get_coin_record_by_name_primary',no_node)
    snapshot=await p.client.get(session_path)
    assert snapshot.status_code==200,snapshot.text
    assert snapshot.json()['vault']['identityVerified'] is False
    assert snapshot.json()['owner'].lower()==owner.lower()
    assert snapshot.json()['ownerPublicKey']=='0x'+bytes(p.registry.get(
        bytes32.from_hexstr(saved['vaultLauncherId'])).owner_pubkey).hex()
    assert not snapshot.headers.get('set-cookie')
    identity_key=identity
    admitted=p.runtime.verified_observations.pop(identity_key)
    assert (await p.client.get(session_path)).status_code==409
    p.runtime.verified_observations[identity_key]=admitted
    with p.store._db(write=True) as db:
        observation=p.store.vault_observation(identity_key)
        document={**observation['vault'],'identityVerified':True,'identityStatus':'VERIFIED'}
        db.execute('UPDATE customer_vault_observations SET document=? WHERE registration_id=?',
            (json.dumps(document),identity_key))
    assert (await p.client.get(session_path)).status_code==409
    monkeypatch.setattr(p.node,'get_coin_record_by_name_primary',real_node)
    await p.runtime.observe_current_vault(identity_key)
    assert (await p.client.get(session_path)).json()['vault']['identityVerified'] is False
    # Returning owners use a new, exact generation-bound challenge; replay,
    # another owner's signature and a changed generation cannot reconnect.
    disconnect='/protocol-api/next/customer/session/disconnect'
    assert (await p.client.post(disconnect,json={'generationId':generation})).status_code==200
    assert (await p.client.get(session_path)).status_code==401
    challenge=await p.client.post(session_path+'/challenge',json={'generationId':generation})
    assert challenge.status_code==200,challenge.text
    challenge=challenge.json()
    if auth=='evm':
        from eth_account.messages import encode_typed_data
        login_signature='0x'+Account.sign_message(encode_typed_data(full_message=challenge['typedData']),secret.key).signature.hex()
        bad_signature='0x'+Account.sign_message(encode_typed_data(full_message=challenge['typedData']),b'q'*32).signature.hex()
    else:
        from chia.types.blockchain_format.program import Program
        digest=bytes(Program.to(('Chia Signed Message',bytes.fromhex(challenge['messageHex'][2:]))).get_tree_hash())
        login_signature='0x'+bytes(AugSchemeMPL.sign(secret,digest)).hex()
        bad_signature='0x'+bytes(AugSchemeMPL.sign(AugSchemeMPL.key_gen(b'q'*32),digest)).hex()
    login_body={'generationId':generation,'ownerAuth':{'challengeId':challenge['challengeId'],'signature':login_signature}}
    assert (await p.client.post(session_path+'/connect',json={**login_body,
        'generationId':'0x'+'ac'*32})).status_code==409
    wrong=await p.client.post(session_path+'/connect',json={**login_body,
        'ownerAuth':{**login_body['ownerAuth'],'signature':bad_signature}})
    assert wrong.status_code==403,wrong.text
    reconnected=await p.client.post(session_path+'/connect',json=login_body)
    assert reconnected.status_code==200,reconnected.text
    assert (await p.client.get(session_path)).status_code==200
    assert (await p.client.post(session_path+'/connect',json=login_body)).status_code==409
    assert p.node.pushes==1
    # Expired creation budgets cannot read a key or lock confirmed owners out
    # of the observer/session runtime after a restart.
    import solslot_api.generation_customer_factory as factory
    def forbidden_key(*args):raise AssertionError('expired policy must never read a financial key')
    monkeypatch.setattr(factory,'protected_customer_faucet',forbidden_key)
    read_runtime=factory.configured_generation_customers(p.settings,index=p.index,provider=p.node,
        journal=p.journal,registry=p.registry,clock=lambda:p.runtime.policy.expires_at+1)
    assert read_runtime is not None and read_runtime.faucet is None and read_runtime.submitter is None
    assert not read_runtime.verified_observations
    read_runtime.close()
    lookup = (await p.client.get(BASE+'/lookup',params={'owner':owner,'authType':auth})).json()['vault']
    assert lookup['identityStatus'] == 'CHECK_AFTER_SIGN_IN'
    assert 'identityVerified' not in lookup


@pytest.mark.asyncio
async def test_disabled_profile_creates_no_customer_storage(tmp_path):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda:SimpleNamespace(
        network='testnet11',deployment_generation_id='0x'+'ab'*32)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test') as client:
        result = await client.get('/customer/registration/profile')
        assert result.status_code == 200 and result.json()['status'] == 'DISABLED'
        assert 'set-cookie' not in result.headers
        assert not list(tmp_path.iterdir())
