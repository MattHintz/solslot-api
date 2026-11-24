"""The originally signed generation retains its source even when this one order runs R3."""
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from solslot_api import kos_exact_execution as kos, vault_card_settlement as settlement, vault_card_native as native
from solslot_api import vault_stripe_protection as protection
from solslot_api.vault_card_native import R3_PREPARATION_SENDER,R3_SENDER,VaultCardRelease

@pytest.fixture
def scope_doc(monkeypatch):
    # Isolate a synthetic enrollment and exercise the same native scope commitment and health checks.
    fields=('generationId','generationAnchorHash','technologyFeePuzzleHash','primaryProceedsPuzzleHash',
            'collectionId','editionId','metadataRoot','vaultLauncherId','authorizationNonce','batchNonce')
    digest=lambda n:'0x'+n.to_bytes(32,'big').hex()
    row={k:digest(n+1) for n,k in enumerate(fields)}
    row.update(schemaVersion='solslot.vault-card-release.v2',network='testnet11',mode='test',accountId='acct_synthetic',
        deedLauncherIds=[digest(24),digest(25)],originalCoinIds=[digest(26),digest(27)],signerIndices=[0,1],
        credentialPolicyVersion=2,maximumFeePerStageMojos=400000000,maximumTotalFeeMojos=2000000000)
    commitment=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    row.update(validFrom=1000,expiresAt=8200,senderSourceCommit=R3_SENDER)
    assert commitment!=native.R3_ORDER_SCOPE
    with pytest.raises(ValueError):VaultCardRelease(**row)
    monkeypatch.setattr(native,'R3_ORDER_SCOPE',commitment)
    return row


@pytest.mark.parametrize('change',[
    {'senderSourceCommit':'a'*40}, {'accountId':'acct_other'}, {'authorizationNonce':'0x'+'cd'*32},
    {'vaultLauncherId':'0x'+'24'*32},{'maximumFeePerStageMojos':399999999}, {'expiresAt':8201},
    {'network':'mainnet','mode':'live'}, {'signerIndices':[0,2]},
])
def test_sender_is_specific_to_approved_source_and_order(change,scope_doc):
    with pytest.raises(ValueError): VaultCardRelease(**{**scope_doc,**change})


@pytest.mark.asyncio
async def test_original_prep_protected_order_and_actual_health_response_must_agree(tmp_path,monkeypatch,scope_doc):
    raw=json.dumps(scope_doc).encode();path=tmp_path/'r3.json';path.write_bytes(raw);path.chmod(0o600)
    scope=VaultCardRelease.model_validate_json(raw);pin='0x'+hashlib.sha256(raw).hexdigest()
    s=SimpleNamespace(vault_card_release_file=str(path),vault_card_release_sha256=pin,network=scope.network,
        stripe_mode=scope.mode,stripe_account_id=scope.accountId,deployment_generation_id=scope.generationId,
        generation_chain_anchor_hash=scope.generationAnchorHash,zkpassport_policy_version=scope.credentialPolicyVersion)
    order=SimpleNamespace(release_id=pin)
    artifact={'sourceShas':{'keyOfSolomon':R3_PREPARATION_SENDER}}
    monkeypatch.setattr(settlement,'current_card_artifact',lambda *args:artifact)
    monkeypatch.setattr(settlement,'validator_coverage',AsyncMock())
    # Exercise the real HTTP health parser using a local HTTPS transport and no signing key or dispatch.
    observed={'status':'ok','releaseSha':R3_SENDER,'executionMode':'exact-bundle-v2-only'}
    requested=[]
    def respond(request):
        requested.append((request.method,request.url.path));return httpx.Response(200,json=dict(observed))
    client=httpx.AsyncClient
    monkeypatch.setattr(kos.httpx,'AsyncClient',lambda **kw:client(transport=httpx.MockTransport(respond),**kw))
    executor=kos.KeyOfSolomonExactExecutor.__new__(kos.KeyOfSolomonExactExecutor)
    executor.url='https://sender.invalid';executor.timeout_seconds=1;executor.cert=None;executor.verify=True
    worker=SimpleNamespace(exact_executor=executor)
    assert protection.executor_source(s,order)==R3_SENDER
    await protection.precharge_services(s,worker,order)
    assert artifact=={'sourceShas':{'keyOfSolomon':R3_PREPARATION_SENDER}}
    observed['releaseSha']=R3_PREPARATION_SENDER
    with pytest.raises(ValueError,match='Pinned'):await protection.precharge_services(s,worker,order)
    worker.settings=s
    worker.current_card_order=lambda:order
    order.expires_at=int(time.time())+120
    monkeypatch.setattr(protection,'paid',lambda *args:{'binding':'the-original-order'})
    monkeypatch.setattr(protection,'bound',lambda _:'the-original-order')
    with pytest.raises(ValueError,match='Pinned'):
        await protection.verify_paid_dispatch(worker,object(),prepared=object())
    artifact['sourceShas']['keyOfSolomon']='aa'*20
    with pytest.raises(ValueError,match='Historical'):await protection.precharge_services(s,worker,order)
    with pytest.raises(ValueError,match='original protected'):
        protection.executor_source(s,SimpleNamespace(release_id='0x'+'01'*32))
    assert requested==[('GET','/healthz')]*3
    prior=VaultCardRelease(**{k:v for k,v in json.loads(raw).items() if k!='senderSourceCommit'})
    assert prior.executor_source('ab'*20)=='ab'*20


@pytest.mark.asyncio
async def test_card_sponsor_requires_native_success_for_the_allocated_coin(monkeypatch):
    from chia_rs import Coin
    from chia_rs.sized_bytes import bytes32
    from solslot_api.coinset_client import CoinsetClient
    from tests.test_inventory_timeout_recovery import record

    coin=Coin(bytes32(b'a'*32),bytes32(b'b'*32),400000001)
    direct=CoinsetClient('https://primary.invalid')
    worker=SimpleNamespace(provider=SimpleNamespace(primary=direct,get_coin_record_by_name_primary=AsyncMock(return_value=record(coin,10))))
    rpc=AsyncMock();monkeypatch.setattr(direct,'_post',rpc)
    try:
        for failed in ({},{'success':True},{'success':False,'mempool_items':[]},{'success':True,'mempool_items':[{}]}):
            rpc.return_value=failed
            with pytest.raises(ValueError):await protection.unspent(worker,coin)
        rpc.return_value={'success':True,'mempool_items':[]}
        await protection.unspent(worker,coin)
        rpc.assert_awaited_with('/get_mempool_items_by_coin_name',{'coin_name':'0x'+coin.name().hex()})
    finally:await direct.close()
