"""Stateless permit-only authority; local signed evidence selects every key input."""
from __future__ import annotations

from solslot_puzzles.enrollment_networks import enrollment_operational_chain_id

import time
from typing import Any, Mapping
from solslot_puzzles.enrollment_activation import activation_from_artifact

from .enrollment_permit_remote import CAPABILITY, canonical_request, request_hash, validate_live_permit
from .enrollment_permit_signing import PermitIssuerUnavailable, sign_permit_with_key_vault, verify_permit_signature
from .enrollment_signer_settings import EnrollmentSignerSettings
from .public_artifact import verify_signed_public_artifact_file
from .release_metadata import read_release_metadata


def load_issuer_artifact(settings: EnrollmentSignerSettings) -> tuple[dict[str, Any], dict[str, Any]]:
    if not settings.signing_enabled:
        raise PermitIssuerUnavailable('Enrollment issuer is disabled.')
    try:
        artifact = verify_signed_public_artifact_file(settings.public_artifact_path)
        activation = activation_from_artifact(artifact, required=True, environment=settings.runtime_environment + '-alpha')
        release = read_release_metadata(settings.release_metadata_path)
        if (release is None or artifact['artifactHash'] != settings.expected_artifact_hash
                or artifact['sourceShas']['api'] != release.apiCommit
                or artifact['sourceShas']['protocol'] != release.protocolCommit
                or artifact['network'] != settings.network or artifact['evmChainId'] != enrollment_operational_chain_id(activation)
                or activation['evmChainId'] != settings.zkpassport_evm_chain_id
                or activation['releaseIdentity'] != settings.enrollment_permit_release_identity
                or activation['issuerKeyRef'] != settings.enrollment_permit_issuer_key_ref
                or activation['issuerIdentityClientId'] != settings.enrollment_permit_identity_client_id
                or activation['contextHash'] != settings.expected_context_hash
                or activation['emitter'] != settings.expected_emitter
                or activation['issuer'] != settings.expected_issuer):
            raise ValueError('Issuer deployment pins differ.')
        return artifact, activation
    except (OSError, ValueError, TypeError, KeyError):
        raise PermitIssuerUnavailable('Enrollment issuer deployment evidence is not ready.') from None


def sign_enrollment_request(settings: EnrollmentSignerSettings, request: Mapping[str, Any]) -> dict[str, str]:
    """mTLS authenticates the coordinator; it does not authenticate a browser owner.

    Fresh vault/bridge and user-session checks remain on Njalla. Signing the
    exact same still-live saved permit on retry is intentional and stateless.
    No proof, private document, ledger, or arbitrary digest enters this role.
    """
    if not isinstance(request, dict) or set(request) != {'capability', 'artifactHash', 'permit'} or request['capability'] != CAPABILITY:
        raise ValueError('Unsupported enrollment issuer request.')
    canonical = canonical_request(request['artifactHash'], request['permit'])
    artifact, activation = load_issuer_artifact(settings)
    if canonical['artifactHash'] != artifact['artifactHash']:
        raise ValueError('Request does not name the configured signed artifact.')
    permit = validate_live_permit(canonical['permit'], activation, int(time.time()))
    signature = sign_permit_with_key_vault(settings, activation, canonical['permit'])
    verify_permit_signature(canonical['permit'], activation, signature)
    # Do not release a signature after an upstream call crosses the deadline.
    permit.require_live(int(time.time()))
    return {'capability': CAPABILITY, 'requestHash': request_hash(canonical),
        'permitHash': '0x' + permit.permit_hash.hex(), 'issuer': activation['issuer'], 'signature': signature}
