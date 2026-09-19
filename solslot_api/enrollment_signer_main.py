"""Mandatory mTLS and exact peer-certificate pin, on a private issuer listener."""
from __future__ import annotations

import hashlib
import hmac
import ssl

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from .enrollment_signer_app import PEER_EXTENSION, create_enrollment_signer_app
from .enrollment_signer_settings import get_enrollment_signer_settings


def pinned_http_protocol(expected_sha256: str):
    """Derive peer identity from the TLS transport, never HTTP/proxy headers."""
    class IssuerH11Protocol(H11Protocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.peer_sha256 = ''
            self.original_app = self.app
            self.app = self.authenticated_app

        def connection_made(self, transport):
            super().connection_made(transport)
            try:
                tls = transport.get_extra_info('ssl_object')
                cert = tls.getpeercert(binary_form=True) if tls is not None else None
                fingerprint = hashlib.sha256(cert).hexdigest() if cert else ''
                if not cert or not hmac.compare_digest(fingerprint, expected_sha256):
                    transport.close()
                    return
                self.peer_sha256 = fingerprint
            except Exception:
                transport.close()

        def data_received(self, data):
            if self.peer_sha256:
                super().data_received(data)

        async def authenticated_app(self, scope, receive, send):
            scope = dict(scope)
            scope['extensions'] = {**scope.get('extensions', {}), PEER_EXTENSION: self.peer_sha256}
            await self.original_app(scope, receive, send)

    return IssuerH11Protocol


def main() -> None:
    settings = get_enrollment_signer_settings()
    cert, key, ca = settings.require_mtls_listener()
    uvicorn.run(create_enrollment_signer_app(settings), host=settings.bind_host, port=settings.bind_port,
        http=pinned_http_protocol(settings.tls_client_cert_sha256), ws='none', workers=1,
        proxy_headers=False, forwarded_allow_ips='', access_log=False, server_header=False,
        ssl_certfile=cert, ssl_keyfile=key, ssl_ca_certs=ca, ssl_cert_reqs=ssl.CERT_REQUIRED,
        limit_concurrency=8, timeout_keep_alive=2)


if __name__ == '__main__':
    main()
