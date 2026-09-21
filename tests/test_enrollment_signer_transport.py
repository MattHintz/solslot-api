"""Real loopback TLS proves dedicated CA plus exact leaf certificate binding."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import ValidationError

from solslot_api import enrollment_signer_app as surface
from solslot_api import enrollment_signer_main as entry
from solslot_api.config import Settings, validate_server_hardening_at_startup
from solslot_api.enrollment_permit_remote import CAPABILITY, SIGN_PATH, validate_remote_signer_config
from solslot_api.enrollment_signer_settings import EnrollmentSignerSettings, require_tls_file


@pytest.fixture
def certificates(tmp_path):
    now = datetime.now(timezone.utc)
    def issue(name, ca=None, usage=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = x509.CertificateBuilder().subject_name(subject).issuer_name(ca.cert.subject if ca else subject)
        builder = builder.public_key(key.public_key()).serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        builder = builder.add_extension(x509.BasicConstraints(ca=ca is None, path_length=None), critical=True)
        if usage:
            builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        if usage == ExtendedKeyUsageOID.SERVER_AUTH:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        cert = builder.sign(ca.key if ca else key, hashes.SHA256())
        cert_path, key_path = tmp_path / (name + '.crt'), tmp_path / (name + '.key')
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        return SimpleNamespace(key=key, cert=cert, cert_path=str(cert_path), key_path=str(key_path),
            fingerprint=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
    ca = issue('issuer-ca')
    foreign = issue('untrusted-ca')
    return SimpleNamespace(ca=ca, server=issue('server', ca, ExtendedKeyUsageOID.SERVER_AUTH),
        client=issue('coordinator', ca, ExtendedKeyUsageOID.CLIENT_AUTH),
        wrong=issue('another-validator', ca, ExtendedKeyUsageOID.CLIENT_AUTH),
        foreign=issue('foreign-client', foreign, ExtendedKeyUsageOID.CLIENT_AUTH))


def settings_for(certs):
    return EnrollmentSignerSettings(tls_cert_file=certs.server.cert_path, tls_key_file=certs.server.key_path,
        tls_client_ca_file=certs.ca.cert_path, tls_client_cert_sha256=certs.client.fingerprint)


def test_private_listener_and_complete_mtls_files_required(certificates, tmp_path):
    c = certificates
    for host in ('0.0.0.0', '::', '8.8.8.8', 'example.com', '169.254.169.254'):
        with pytest.raises(ValidationError):
            EnrollmentSignerSettings(bind_host=host)
    for host in ('127.0.0.1', '10.77.0.12', '::1'):
        assert EnrollmentSignerSettings(bind_host=host).bind_host == host
    with pytest.raises(ValidationError):
        EnrollmentSignerSettings(bind_port=443)
    with pytest.raises(ValueError):
        EnrollmentSignerSettings().require_mtls_listener()
    good = settings_for(c)
    assert good.require_mtls_listener() == (c.server.cert_path, c.server.key_path, c.ca.cert_path)
    good.tls_client_cert_sha256 = '0' * 64
    with pytest.raises(ValueError):
        good.require_mtls_listener()
    link = tmp_path / 'link.key'
    link.symlink_to(c.server.key_path)
    with pytest.raises(ValueError):
        require_tls_file(str(link), private=True)
    from pathlib import Path
    Path(c.server.key_path).chmod(0o640)
    with pytest.raises(ValueError):
        require_tls_file(c.server.key_path, private=True)


def test_coordinator_requires_explicit_remote_mode_and_exact_private_https(certificates):
    c = certificates
    values = dict(enrollment_permit_signer_mode='remote',
        enrollment_permit_remote_url='https://127.0.0.1:8793' + SIGN_PATH,
        enrollment_permit_remote_ca_file=c.ca.cert_path,
        enrollment_permit_remote_cert_file=c.client.cert_path, enrollment_permit_remote_key_file=c.client.key_path)
    tls = validate_remote_signer_config(SimpleNamespace(**values))
    assert tls.verify_mode == ssl.CERT_REQUIRED and tls.check_hostname
    for url in ('http://10.77.0.12:8793' + SIGN_PATH, 'https://8.8.8.8:8793' + SIGN_PATH,
            'https://10.77.0.12:8793/other', 'https://10.77.0.12:8793' + SIGN_PATH + '?key=other',
            'https://user@10.77.0.12:8793' + SIGN_PATH, 'https://10.77.0.12:443' + SIGN_PATH,
            'https://issuer.example:8793' + SIGN_PATH):
        with pytest.raises(ValueError):
            validate_remote_signer_config(SimpleNamespace(**{**values, 'enrollment_permit_remote_url': url}))
    for field in ('ca_file', 'cert_file', 'key_file'):
        with pytest.raises(ValueError):
            validate_remote_signer_config(SimpleNamespace(**{**values, 'enrollment_permit_remote_' + field: ''}))
    with pytest.raises(ValueError):
        validate_remote_signer_config(SimpleNamespace(**{**values, 'enrollment_permit_signer_mode': 'key_vault'}))
    assert validate_remote_signer_config(SimpleNamespace()) is None
    with pytest.raises(RuntimeError, match='Enrollment permit signer transport'):
        validate_server_hardening_at_startup(Settings(enrollment_permit_signer_mode='remote'))


def call_asgi(app, method='GET', path='/health', peer=None, **kwargs):
    async def wrapped(scope, receive, send):
        if peer is not None:
            scope = {**scope, 'extensions': {surface.PEER_EXTENSION: peer}}
        await app(scope, receive, send)
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped), base_url='https://issuer') as client:
            return await client.request(method, path, **kwargs)
    return asyncio.run(call())


def test_raw_asgi_or_spoofed_headers_cannot_authenticate(monkeypatch):
    pin = 'ab' * 32
    app = surface.create_enrollment_signer_app(EnrollmentSignerSettings(signing_enabled=True, tls_client_cert_sha256=pin))
    monkeypatch.setattr(surface, 'load_issuer_artifact', lambda _: pytest.fail('unauthenticated artifact read'))
    for peer in (None, 'cd' * 32):
        assert call_asgi(app, peer=peer, headers={'X-Client-Cert-SHA256': pin, 'X-Forwarded-Proto': 'https'}).status_code == 403


def test_disabled_health_has_no_fake_artifact_and_no_public_routes(monkeypatch):
    pin = 'ab' * 32
    app = surface.create_enrollment_signer_app(EnrollmentSignerSettings(tls_client_cert_sha256=pin))
    from solslot_api import enrollment_signer_service
    monkeypatch.setattr(enrollment_signer_service, 'verify_signed_public_artifact_file', lambda _: pytest.fail('disabled artifact read'))
    reply = call_asgi(app, peer=pin)
    assert reply.status_code == 503 and reply.json() == {'capability': CAPABILITY, 'configurationReady': False}
    for path in ('/docs', '/openapi.json', '/chia/push_tx', '/zkpassport/enrollments/reserve'):
        assert call_asgi(app, peer=pin, path=path).status_code == 404
    from solslot_api.app import app as public_app
    from solslot_api.validator_app import app as validator_app
    assert SIGN_PATH not in {getattr(r, 'path', '') for a in (public_app, validator_app) for r in a.routes}


@pytest.mark.parametrize('body', [b'{"capability":"a","capability":"b"}', b'{"x":NaN}', b'x' * 4097, b'[]', b'null'])
def test_bad_requests_reject_before_signing(monkeypatch, body):
    pin = 'ab' * 32
    app = surface.create_enrollment_signer_app(EnrollmentSignerSettings(tls_client_cert_sha256=pin))
    # Lists/null pass JSON parsing but fail the exact request schema in service.
    from solslot_api import enrollment_signer_service
    monkeypatch.setattr(enrollment_signer_service, 'sign_permit_with_key_vault', lambda *_: pytest.fail('invalid request signed'))
    response = call_asgi(app, method='POST', path=SIGN_PATH, peer=pin, content=body, headers={'Content-Type': 'application/json'})
    assert response.status_code in (400, 409)


def test_generic_service_errors_never_echo_provider_or_key(monkeypatch):
    pin = 'ab' * 32
    app = surface.create_enrollment_signer_app(EnrollmentSignerSettings(tls_client_cert_sha256=pin))
    monkeypatch.setattr(surface, 'sign_enrollment_request', lambda *_: (_ for _ in ()).throw(RuntimeError('sensitive-provider-token')))
    reply = call_asgi(app, method='POST', path=SIGN_PATH, peer=pin, json={})
    assert reply.status_code == 503 and 'sensitive-provider' not in reply.text


def test_entrypoint_uses_mandatory_private_mtls_no_proxy_headers(certificates, monkeypatch):
    config = settings_for(certificates)
    monkeypatch.setattr(entry, 'get_enrollment_signer_settings', lambda: config)
    seen = {}
    monkeypatch.setattr(entry.uvicorn, 'run', lambda app, **kw: seen.update(kw))
    entry.main()
    assert seen['ssl_cert_reqs'] == ssl.CERT_REQUIRED and seen['ssl_ca_certs'] == certificates.ca.cert_path
    assert seen['proxy_headers'] is False and seen['forwarded_allow_ips'] == ''
    assert seen['host'] == '127.0.0.1' and seen['port'] == 8793 and seen['workers'] == 1


def test_real_tls_rejects_wrong_same_ca_leaf_untrusted_and_missing_client(certificates):
    c = certificates
    settings = settings_for(c)
    app = surface.create_enrollment_signer_app(settings)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    config = uvicorn.Config(app, host='127.0.0.1', http=entry.pinned_http_protocol(c.client.fingerprint),
        ws='none', proxy_headers=False, access_log=False, log_level='critical', lifespan='off',
        ssl_certfile=c.server.cert_path, ssl_keyfile=c.server.key_path,
        ssl_ca_certs=c.ca.cert_path, ssl_cert_reqs=ssl.CERT_REQUIRED)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            thread.join(0.01)
        assert server.started
        def client(cert=None):
            context = ssl.create_default_context(cafile=c.ca.cert_path)
            if cert:
                context.load_cert_chain(cert.cert_path, cert.key_path)
            return httpx.Client(verify=context, timeout=2, trust_env=False)
        with client(c.client) as caller:
            response = caller.get(f'https://127.0.0.1:{port}/health')
            assert response.status_code == 503 and response.json()['configurationReady'] is False
        for cert in (c.wrong, c.foreign, None):
            with client(cert) as caller, pytest.raises(httpx.TransportError):
                caller.get(f'https://127.0.0.1:{port}/health', headers={'X-Client-Cert-SHA256': c.client.fingerprint})
        with httpx.Client(timeout=2, trust_env=False) as caller, pytest.raises(httpx.TransportError):
            caller.get(f'http://127.0.0.1:{port}/health')
    finally:
        server.should_exit = True
        thread.join(5)
        listener.close()
        assert not thread.is_alive()
