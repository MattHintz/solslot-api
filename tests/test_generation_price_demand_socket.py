"""Local collector boundary with fixed requests and bounded responses."""
import asyncio,json,os
import pytest
from solslot_api.generation_price_demand_socket import PriceDemandSocketCollector,MESSAGE,STATUS_MESSAGE,MAX_REPLY


async def socket_server(tmp_path,handler):
    directory=tmp_path/'price-socket';directory.mkdir(mode=0o750)
    path=directory/'input.sock'
    server=await asyncio.start_unix_server(handler,path=str(path))
    path.chmod(0o660)
    return server,path


def client(path):return PriceDemandSocketCollector(path,expected_uid=os.getuid(),expected_gid=os.getgid())


@pytest.mark.asyncio
async def test_socket_sends_only_fixed_message_and_accepts_fragmented_result(tmp_path):
    received=[]
    async def handle(reader,writer):
        received.append(await reader.read());data=json.dumps({'state':'SIGNED_PRICE_READY','sequence':7,'validUntil':9999}).encode()
        writer.write(data[:11]);await writer.drain();await asyncio.sleep(0.01)
        writer.write(data[11:]);await writer.drain();writer.close();await writer.wait_closed()
    server,path=await socket_server(tmp_path,handle)
    async with server:
        assert (await client(path)())['sequence']==7
    assert received==[MESSAGE]


@pytest.mark.asyncio
async def test_status_sends_only_read_request_without_triggering_refresh(tmp_path):
    received=[]
    async def handle(reader,writer):
        received.append(await reader.read());writer.write(b'{"schema":"solslot.price-refresh-status.v1"}')
        await writer.drain();writer.close();await writer.wait_closed()
    server,path=await socket_server(tmp_path,handle)
    async with server:
        assert (await client(path).status(now=1000,required_until=1300))['schema']=='solslot.price-refresh-status.v1'
    assert received==[STATUS_MESSAGE]


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['world_writable_directory','world_accessible_socket','wrong_owner','symlink'])
async def test_untrusted_socket_paths_fail_before_connection(tmp_path,problem):
    connected=[]
    async def handle(reader,writer):connected.append(True);writer.close();await writer.wait_closed()
    server,path=await socket_server(tmp_path,handle);target=path
    async with server:
        candidate=client(path)
        if problem=='world_writable_directory':path.parent.chmod(0o777)
        if problem=='world_accessible_socket':path.chmod(0o666)
        if problem=='wrong_owner':candidate=PriceDemandSocketCollector(path,expected_uid=os.getuid()+1,expected_gid=os.getgid())
        if problem=='symlink':
            target=path.parent/'other.sock';target.symlink_to(path);candidate=client(target)
        with pytest.raises(ValueError):await candidate()
        await asyncio.sleep(0)
    assert connected==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('reply',[b'{}',b'not-json',b'x'*(MAX_REPLY+1)])
async def test_invalid_and_oversized_responses_never_become_success(tmp_path,reply):
    async def handle(reader,writer):
        await reader.read();writer.write(reply);await writer.drain();writer.close();await writer.wait_closed()
    server,path=await socket_server(tmp_path,handle)
    async with server:
        with pytest.raises((ValueError,json.JSONDecodeError)):await client(path)()


@pytest.mark.asyncio
async def test_demand_worker_coalesces_authenticated_intent_and_rechecks_signed_status(tmp_path):
    from solslot_api.generation_customer_purchase_store import CurrentCustomerPurchaseStore
    from solslot_api.generation_price_demand import PriceDemandRuntime
    received=[];state={'ready':False}
    async def handle(reader,writer):
        data=await reader.read();received.append(data)
        if data==MESSAGE:
            state['ready']=True
            result={'state':'SIGNED_PRICE_READY','sequence':7,'validUntil':2000}
        else:
            result={'schema':'solslot.price-refresh-status.v1','network':'testnet11',
                'checkedAt':1000,'requiredUntil':1300,'canQuote':state['ready'],'canRefresh':True,
                'status':'READY' if state['ready'] else 'REFRESH_REQUIRED',
                'validUntil':2000 if state['ready'] else None,
                'sourceCount':2 if state['ready'] else 0,'signerCount':2 if state['ready'] else 0,
                'quota':{'status':'AVAILABLE','remainingRequests':20}}
        writer.write(json.dumps(result).encode());await writer.drain();writer.close();await writer.wait_closed()
    server,path=await socket_server(tmp_path,handle)
    store=CurrentCustomerPurchaseStore(tmp_path/'payments.db','0x'+'01'*32)
    collector=client(path)
    worker=PriceDemandRuntime(store=store,health=collector.status,collect=collector,enabled=True,clock=lambda:1000)
    async with server:
        await worker.status();await worker.status()
        assert MESSAGE not in received and store.price_refresh_job_status() is None
        await worker.request();await worker.request()
        assert MESSAGE not in received and store.price_refresh_job_status()['status']=='WAITING'
        assert await worker.run_once()=={'state':'READY','terminal':True}
        assert received.count(MESSAGE)==1 and (await worker.status())['price']['canQuote'] is True
