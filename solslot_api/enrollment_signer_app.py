"""Private transport surface. Run only through enrollment_signer_main."""
from __future__ import annotations

import asyncio
import hmac
import json

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from .enrollment_permit_remote import CAPABILITY, MAX_REQUEST_BYTES, SIGN_PATH
from .enrollment_signer_service import load_issuer_artifact, sign_enrollment_request
from .enrollment_signer_settings import EnrollmentSignerSettings

PEER_EXTENSION = 'solslot.enrollment_peer_sha256'


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field.')
        result[key] = value
    return result


def create_enrollment_signer_app(settings: EnrollmentSignerSettings) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    signing_lock = asyncio.Lock()

    @app.middleware('http')
    async def require_peer(request: Request, call_next):
        peer = request.scope.get('extensions', {}).get(PEER_EXTENSION, '')
        if (request.scope.get('scheme') != 'https' or not settings.tls_client_cert_sha256
                or not isinstance(peer, str) or not hmac.compare_digest(peer, settings.tls_client_cert_sha256)):
            return JSONResponse({'detail': 'Issuer client authentication required.'}, status_code=403)
        return await call_next(request)

    @app.get('/health')
    async def health():
        try:
            await asyncio.to_thread(load_issuer_artifact, settings)
        except Exception:
            return JSONResponse({'capability': CAPABILITY, 'configurationReady': False}, status_code=503)
        return {'capability': CAPABILITY, 'configurationReady': True}

    @app.post(SIGN_PATH)
    async def sign(request: Request):
        if request.url.query or request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            return JSONResponse({'detail': 'Invalid issuer request.'}, status_code=400)
        async def read_body():
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_REQUEST_BYTES:
                    raise ValueError('Request exceeds the limit.')
            return bytes(body)
        try:
            body = await asyncio.wait_for(read_body(), timeout=3)
            value = json.loads(body, object_pairs_hook=_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except Exception:
            return JSONResponse({'detail': 'Invalid issuer request.'}, status_code=400)
        # Bound concurrent Key Vault/IMDS calls; retries stay in Njalla's ledger.
        if signing_lock.locked():
            return JSONResponse({'detail': 'Enrollment issuer is busy.'}, status_code=503)
        try:
            async with signing_lock:
                return await asyncio.to_thread(sign_enrollment_request, settings, value)
        except ValueError:
            return JSONResponse({'detail': 'Permit is not valid for this issuer.'}, status_code=409)
        except Exception:
            return JSONResponse({'detail': 'Enrollment issuer is unavailable.'}, status_code=503)

    return app
