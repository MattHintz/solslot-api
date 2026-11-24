import time
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from solslot_api import vault_card_pending_read as pending
from solslot_api.coinset_client import CoinsetClient
from solslot_api.generation_primary_reader import PRIMARY_READER_URL, PrimaryReadClient
from solslot_api.generation_primary_reader_app import create_primary_reader_app
from solslot_api.vault_card_native import VaultCardNative
from tests import test_vault_stripe_protection as suite


def digest(n):
    return "0x" + n.to_bytes(32, "big").hex()


def setup(monkeypatch, *, order=None):
    start = int(time.time()) - 1
    order = order or SimpleNamespace(release_id=digest(1), purchase_id=digest(2), expires_at=start+7200)
    lease = pending.ReadLease(order.release_id, order.purchase_id, order.expires_at-7200,
                              order.expires_at, order.expires_at+7200, [0,1])
    rpc = AsyncMock(return_value={"success": True, "mempool_items": []})
    context = SimpleNamespace(lease=lease, rpc=rpc, order=order)
    monkeypatch.setattr(pending, "installed_lease", lambda: context.lease)
    context.node = SimpleNamespace(primary=SimpleNamespace(_post=rpc),
        get_network_info_primary=AsyncMock(return_value={"network_name":"testnet11"}),
        get_blockchain_state_primary=AsyncMock(return_value={"blockchain_state":{"sync":{"synced":True}}}))
    context.app = create_primary_reader_app(provider=context.node)
    return context


@asynccontextmanager
async def peer(context, ip):
    client = PrimaryReadClient(PRIMARY_READER_URL)
    await client.close()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=context.app, client=(ip,41317)),
                                 base_url=PRIMARY_READER_URL) as transport:
        client._client = transport
        yield client


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["10.77.0.10", "10.77.0.11"])
async def test_same_reader_for_native_reservations_and_later_receipt(tmp_path, monkeypatch, ip):
    f = await suite.fixture(tmp_path, monkeypatch)
    c = setup(monkeypatch, order=f.o)
    async with peer(c,ip) as primary:
        provider = SimpleNamespace(primary=primary, get_coin_record_by_name_primary=f.p.get_coin_record_by_name_primary,
                                   get_puzzle_and_solution_primary=f.p.get_puzzle_and_solution_primary)
        assert (await VaultCardNative.stage(f.ev,provider))[0] == "CONFIRMED"
        ids = [args.args[1]["coin_name"] for args in c.rpc.await_args_list]
        assert ids == [f.o.vault_coin_id, *f.o.reserved_coin_ids]
        await suite.allocate(f)
        _, op = suite.paid(f)
        prepared = await suite.cover.card_receipt(f.worker,op)
        assert prepared.receipt_coin_id not in {*f.o.original_coin_ids,*ids}
        assert not await pending.card_coin_pending(primary,f.o,prepared.receipt_coin_id)
        c.rpc.return_value = {"success":True,"mempool_items":[{"spend_bundle":"PRIVATE_NATIVE_CONTENT"}]}
        assert await pending.card_coin_pending(primary,f.o,prepared.receipt_coin_id)
        answer = await primary.card_pending_read({"releaseId":f.o.release_id,"purchaseId":f.o.purchase_id,
                                                  "coinId":prepared.receipt_coin_id})
        assert "PRIVATE_NATIVE_CONTENT" not in repr(answer)
        assert set(answer)=={"schema","releaseId","purchaseId","coinId","pending","readUntil"}
        with pytest.raises(ValueError,match="PRIMARY_READER_METHOD_REJECTED"):
            await primary._post("/get_mempool_items_by_coin_name", {"coin_name":prepared.receipt_coin_id})


@pytest.mark.asyncio
async def test_closed_enrollment_wrong_peer_order_and_uncertain_data_fail_closed(monkeypatch):
    c=setup(monkeypatch)
    for ip in ["10.77.0.12","10.77.0.2","127.0.0.1"]:
        async with peer(c,ip) as p:
            with pytest.raises(ValueError):
                await pending.card_coin_pending(p,c.order,digest(6))
    async with peer(c,"10.77.0.10") as p:
        req={"releaseId":c.order.release_id,"purchaseId":c.order.purchase_id,"coinId":digest(6)}
        for changed in ({"releaseId":digest(7)},{"purchaseId":digest(8)},{"coinId":"*"},{'list':True}):
            with pytest.raises(ValueError): await p.card_pending_read({**req,**changed})
        for lease in (replace(c.lease,readUntil=c.lease.admissionEnds),replace(c.lease,signerIndices=[1,2]),None):
            saved=c.lease; c.lease=lease
            try:
                with pytest.raises(ValueError): await p.card_pending_read(req)
            finally: c.lease=saved
        assert not c.rpc.await_count
        for body in ({},{"success":True},{"success":True,"mempool_items":None},{"success":False,"mempool_items":[]}):
            c.rpc.return_value=body
            with pytest.raises(ValueError): await p.card_pending_read(req)
        c.node.get_network_info_primary.return_value={"network_name":"mainnet"}
        with pytest.raises(ValueError): await p.card_pending_read(req)


@pytest.mark.asyncio
async def test_followup_read_lives_beyond_admission_and_stops_at_lease_end(monkeypatch):
    c=setup(monkeypatch)
    now=int(time.time())
    c.lease=replace(c.lease,validFrom=now-7300,admissionEnds=now-100,readUntil=now+3600)
    c.order.expires_at=c.lease.admissionEnds
    async with peer(c,"10.77.0.11") as p:
        assert not await pending.card_coin_pending(p,c.order,digest(6))
        c.lease=replace(c.lease,readUntil=now-10)
        with pytest.raises(ValueError): await pending.card_coin_pending(p,c.order,digest(6))


@pytest.mark.asyncio
async def test_client_rejects_missing_stale_or_substituted_issuer_response(monkeypatch):
    c=setup(monkeypatch)
    async with peer(c,"10.77.0.11") as p:
        good=await p.card_pending_read({"releaseId":c.order.release_id,"purchaseId":c.order.purchase_id,"coinId":digest(6)})
        for wrong in ({},{**good,"coinId":digest(7)},{**good,"purchaseId":digest(9)},{**good,"pending":0},
                      {**good,"readUntil":c.order.expires_at},{**good,"mempool_items":[]}):
            monkeypatch.setattr(p,"card_pending_read",AsyncMock(return_value=wrong))
            with pytest.raises(ValueError): await pending.card_coin_pending(p,c.order,digest(6))


@pytest.mark.asyncio
async def test_owner_cannot_start_checkout_if_one_enrolled_read_fails(tmp_path,monkeypatch):
    from solslot_api import credential_auth, vault_card_checkout, vault_card_settlement

    f=await suite.fixture(tmp_path,monkeypatch)
    assert await suite.allocate(f)
    c=setup(monkeypatch,order=f.o)
    monkeypatch.setattr(vault_card_checkout,"current_card_coverage",suite.cover.current_card_coverage)
    failed=set()

    async def signer_response(request):
        i=["one.invalid","two.invalid","three.invalid"].index(request.url.host)
        if i==2: return httpx.Response(404)
        async with peer(c,"10.77.0."+str(10+i)) as primary:
            if i in failed:
                monkeypatch.setattr(primary,"card_pending_read",AsyncMock(side_effect=ValueError("Unavailable")))
            provider=SimpleNamespace(primary=primary,get_coin_record_by_name_primary=f.p.get_coin_record_by_name_primary,
                                     get_puzzle_and_solution_primary=f.p.get_puzzle_and_solution_primary)
            try: stage=await VaultCardNative.stage(f.ev,provider)
            except ValueError: return httpx.Response(409)
        assert stage[0]=="CONFIRMED"
        return httpx.Response(200,json={"releaseId":f.o.release_id,"purchaseId":f.o.purchase_id,
            "batchHash":f.o.batch_hash,"network":f.o.network,"reservedCoinIds":list(f.o.reserved_coin_ids),
            "signerIndex":i,"validatorPubkey":f.roster[i]})

    monkeypatch.setattr(vault_card_settlement,"_private_validator_client",
        lambda _:httpx.AsyncClient(transport=httpx.MockTransport(signer_response)))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=f.x.app),base_url=f.x.s.vault_card_return_origin,
                                 headers={"Origin":f.x.s.vault_card_return_origin}) as buyer:
        buyer.cookies.set(credential_auth.VAULT_SESSION_COOKIE,f.x.r.token)
        assert (await buyer.get(f.x.url)).json()["state"]=="READY"
        failed.add(1)
        assert (await buyer.get(f.x.url)).json()["state"]!="READY"
        clicked=await buyer.post(f.x.url+"/checkout",json={"purchaseId":f.o.purchase_id,
            "batchHash":f.o.batch_hash,"intent":"checkout"})
        assert clicked.status_code==200 and clicked.json()["checkoutUrl"] is None
    assert not any(req.method=="POST" for req in f.x.seen)
    assert f.x.store.dispatch(f.o.purchase_id) is None


@pytest.mark.asyncio
async def test_actual_direct_primary_class_rejects_missing_native_data(monkeypatch):
    c=setup(monkeypatch)
    primary=CoinsetClient("https://local-direct-primary.invalid")
    try:
        rpc=AsyncMock()
        monkeypatch.setattr(primary,"_post",rpc)
        for invalid in (None,{},{"success":True},{"success":False,"mempool_items":[]},{"success":True,"mempool_items":None}):
            rpc.return_value=invalid
            with pytest.raises(ValueError): await pending.card_coin_pending(primary,c.order,digest(2))
        for items in ([],[{}]):
            rpc.return_value={"success":True,"mempool_items":items}
            assert await pending.card_coin_pending(primary,c.order,digest(2)) is bool(items)
    finally:
        await primary.close()
