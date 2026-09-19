"""Narrow mTLS issuer client. Njalla retains the only enrollment ledger."""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx
from solslot_puzzles.enrollment_activation import activation_context
from solslot_puzzles.enrollment_permit import EnrollmentPermit

from .enrollment_permit_signing import PermitIssuerUnavailable, verify_permit_signature
from .enrollment_signer_settings import private_ip, require_tls_file

CAPABILITY = 'enrollment-permit-v1'
SIGN_PATH = '/v1/enrollment-permit/sign'
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 4096


def canonical_request(artifact_hash: str, wire: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(artifact_hash, str) or re.fullmatch(r'0x[0-9a-f]{64}', artifact_hash) is None or artifact_hash == '0x' + '00' * 32:
        raise ValueError('Invalid issuer artifact hash.')
    permit = EnrollmentPermit.from_wire(wire)
    return {'capability': CAPABILITY, 'artifactHash': artifact_hash, 'permit': permit.to_wire()}


def request_hash(request: Mapping[str, Any]) -> str:
    return '0x' + hashlib.sha256(json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def validate_live_permit(wire: Mapping[str, Any], activation: Mapping[str, Any], now: int) -> EnrollmentPermit:
    permit = EnrollmentPermit.from_wire(wire)
    if (permit.context_hash != activation_context(activation).context_hash
            or permit.expires_at - permit.issued_at != activation['permitLifetimeSeconds']):
        raise ValueError('Permit context or deadline differs from the configured deployment.')
    permit.require_live(now)
    return permit


def validate_remote_signer_config(settings: Any) -> ssl.SSLContext | None:
    mode = getattr(settings, 'enrollment_permit_signer_mode', 'key_vault')
    values = [getattr(settings, 'enrollment_permit_remote_' + field, '') for field in ('url', 'ca_file', 'cert_file', 'key_file')]
    if mode == 'key_vault':
        if any(values):
            raise ValueError('Remote issuer settings require explicit remote signer mode.')
        return None
    if mode != 'remote' or not all(values):
        raise ValueError('Remote issuer mode requires its exact URL and mutual TLS files.')
    url, ca, cert, key = values
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or not private_ip(parsed.hostname)
            or parsed.port != 8793 or parsed.path != SIGN_PATH or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None):
        raise ValueError('Remote issuer URL must be the private HTTPS permit endpoint on port 8793.')
    context = ssl.create_default_context(cafile=require_tls_file(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(require_tls_file(cert), require_tls_file(key, private=True))
    return context


def sign_permit_with_remote(settings: Any, activation: Mapping[str, Any], wire: Mapping[str, Any], *, artifact_hash: str) -> str:
    """Return only a signature over the original saved permit, never a replacement."""
    try:
        tls = validate_remote_signer_config(settings)
        if tls is None or not settings.alpha_writes_enabled or settings.network != 'testnet11':
            raise ValueError('Remote issuer is not selected for an enabled Testnet enrollment.')
        if (activation['environment'] != settings.runtime_environment + '-alpha'
                or activation['evmChainId'] != settings.zkpassport_evm_chain_id
                or activation['releaseIdentity'] != settings.enrollment_permit_release_identity
                or activation['issuerKeyRef'] != settings.enrollment_permit_issuer_key_ref
                or activation['issuerIdentityClientId'] != settings.enrollment_permit_identity_client_id):
            raise ValueError('Remote issuer metadata does not match the selected activation.')
        permit = validate_live_permit(wire, activation, int(time.time()))
        request = canonical_request(artifact_hash, wire)
        with httpx.Client(verify=tls, timeout=httpx.Timeout(15, connect=3), follow_redirects=False, trust_env=False) as client:
            with client.stream('POST', settings.enrollment_permit_remote_url, json=request) as response:
                if response.status_code != 200:
                    raise PermitIssuerUnavailable('Enrollment issuer is unavailable.')
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise PermitIssuerUnavailable('Enrollment issuer response exceeds the limit.')
                result = json.loads(body)
        if (not isinstance(result, dict) or set(result) != {'capability', 'requestHash', 'permitHash', 'issuer', 'signature'}
                or result['capability'] != CAPABILITY or result['requestHash'] != request_hash(request)
                or result['permitHash'] != '0x' + permit.permit_hash.hex() or result['issuer'] != activation['issuer']):
            raise ValueError('Remote issuer returned another request or deployment.')
        # The existing ledger verifies this again before recording first success.
        # A late valid response remains evidence; issuance.py checks expiry after
        # recording it and never replaces the original permit or deadline.
        return verify_permit_signature(wire, activation, result['signature'])
    except (httpx.HTTPError, OSError, ValueError, TypeError, KeyError, OverflowError):
        raise PermitIssuerUnavailable('Permit issuer could not complete; retry the saved reservation.') from None
