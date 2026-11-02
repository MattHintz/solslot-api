"""Restricted public-chain reads on the retained Testnet11 node host only.

Deployment binds TLS to WireGuard 10.77.0.10:9543 and permits only the three
private signer IPs. Full-node RPC credentials stay in this dedicated reader.
No signing key, submission method or coordinator database is available here.
"""
import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .generation_primary_reader import checked_read, decode_request

READER_IPS = frozenset(('10.77.0.10', '10.77.0.11', '10.77.0.12'))
HEALTH_IPS = READER_IPS | frozenset(('10.77.0.2',))


def create_primary_reader_app(*, provider):
    @asynccontextmanager
    async def lifespan(_app):
        await provider.start()
        try:
            yield
        finally:
            await provider.close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    active = asyncio.Semaphore(8)

    @app.get('/health')
    async def health(request: Request):
        if request.client is None or request.client.host not in HEALTH_IPS:
            raise HTTPException(403, detail='PRIVATE_PRIMARY_READER_ONLY')
        try:
            async with asyncio.timeout(10):
                network = await provider.get_network_info_primary()
                state = await provider.get_blockchain_state_primary()
            chain = state['blockchain_state']
            if network.get('network_name') != 'testnet11' or chain['sync']['synced'] is not True:
                raise ValueError('primary unavailable')
            return {'state': 'READY', 'network': 'testnet11',
                'height': chain['peak']['height'], 'readOnly': True}
        except Exception:
            raise HTTPException(503, detail='PRIVATE_PRIMARY_NODE_UNAVAILABLE') from None

    @app.post('/v1/generation/chain/{method}')
    async def read(method: str, request: Request):
        if request.client is None or request.client.host not in READER_IPS:
            raise HTTPException(403, detail='PRIVATE_PRIMARY_READER_ONLY')
        try:
            raw = b''
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    raw += chunk
                    if len(raw) > 512:
                        raise ValueError('PRIMARY_READER_REQUEST_TOO_LARGE')
            body = checked_read(method, decode_request(raw))
        except (ValueError, TimeoutError):
            raise HTTPException(400, detail='PRIVATE_PRIMARY_READ_REJECTED') from None
        try:
            async with asyncio.timeout(12):
                async with active:
                    # Do not call the provider's fallback or a dynamic method.
                    result = await provider.primary._post('/' + method, body)
            if not isinstance(result, dict) or len(json.dumps(result)) > 2 * 1024 * 1024:
                raise ValueError('primary response exceeds boundary')
            return JSONResponse(result, headers={'Cache-Control': 'no-store'})
        except Exception:
            raise HTTPException(503, detail='PRIVATE_PRIMARY_NODE_UNAVAILABLE') from None
    return app
