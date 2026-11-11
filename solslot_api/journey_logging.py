"""Operational request receipts, without paths, IPs, bodies or account identifiers."""
from __future__ import annotations
import logging
import time
import uuid

logger = logging.getLogger('solslot.journey')

def operation(path: str) -> str:
    if path.startswith('/alpha/'): return 'telemetry'
    if '/stamp/' in path: return 'identity_stamp'
    if '/session' in path or '/auth/' in path: return 'session'
    if path.startswith('/zkpassport/relay/'): return 'identity_relay'
    if path.startswith('/zkpassport/'): return 'identity_enrollment'
    if path.startswith('/admin/governance/'): return 'governance'
    if path.startswith('/admin/collections'): return 'collection'
    if path.startswith('/vaults') or path.startswith('/register'): return 'vault'
    if path.startswith('/redemptions') or path.startswith('/purchases'): return 'history'
    return 'other'

class JourneyRequestLogging:
    def __init__(self, app): self.app = app
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http': return await self.app(scope, receive, send)
        if scope.get('_solslot_journey_receipt'): return await self.app(scope, receive, send)
        scope = dict(scope, _solslot_journey_receipt=True)
        started = time.monotonic()
        request_id, flow_id = uuid.uuid4().hex, '-'
        # Headers are client claims; never infer a person from them.
        headers = dict(scope.get('headers', []))
        try: flow_id = str(uuid.UUID(headers.get(b'x-solslot-flow', b'').decode('ascii')))
        except (ValueError, UnicodeError): pass
        status = 500
        async def observe(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
                message = dict(message, headers=[*message.get('headers', []), (b'x-solslot-request-id', request_id.encode())])
            await send(message)
        try: await self.app(scope, receive, observe)
        finally:
            elapsed = round((time.monotonic() - started) * 1000)
            method = scope['method'] if scope['method'] in ('GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD') else 'OTHER'
            group = operation(scope.get('path', ''))
            # Quiet normal reads, absent enrollment/session discovery and telemetry.
            expected = scope['method'] == 'GET' and (status == 401 and group == 'session' or status == 404 and group in ('identity_enrollment', 'collection'))
            if group != 'telemetry' and not expected and (scope['method'] != 'GET' or status >= 400 or elapsed >= 5000):
                logger.info('journey_api request_id=%s flow_id=%s operation=%s method=%s status=%d latency_ms=%d',
                            request_id, flow_id, group, method, status, elapsed)
