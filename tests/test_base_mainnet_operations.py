"""Base-mainnet operations are selected by versioned, authenticated evidence."""
import copy

import pytest

from solslot_api import enrollment_signer_service as issuer
from solslot_api.config import validate_server_hardening_at_startup
from solslot_api.enrollment_permit_remote import canonical_request
from solslot_api.enrollment_permit_signing import PermitIssuerUnavailable
from solslot_api.genesis_evm import GenesisEvmEvidenceError
from solslot_puzzles.artifact_schema_v4 import artifact_hash
from solslot_puzzles.enrollment_networks import BASE_MAINNET_ENROLLMENT_SCHEMA
from tests.test_enrollment_remote_signer import authority
from tests.test_genesis_permit_evm import deployment_setup, reseal, verify
from tests.test_server_hardening import _staging


@pytest.mark.parametrize("deployment_setup", [8453], indirect=True)
def test_selected_mainnet_deployment_matches_operational_and_identity_domains(deployment_setup):
    s = deployment_setup
    s.active["schema"] = BASE_MAINNET_ENROLLMENT_SCHEMA
    s.plan["evmChainId"] = 8453
    s.record["draft"]["evmChainId"] = 8453
    s.settings.eip712_chain_id = 8453
    reseal(s)
    assert verify(s)["chainId"] == 8453
    for target in (s.plan, s.record["draft"]):
        target["evmChainId"] = 84532
        with pytest.raises(GenesisEvmEvidenceError):
            verify(s)
        target["evmChainId"] = 8453
    s.settings.eip712_chain_id = 84532
    with pytest.raises(GenesisEvmEvidenceError):
        verify(s)


def test_issuer_accepts_explicit_mainnet_operations_and_rejects_chain_relabel(authority):
    a = authority
    a.artifact["enrollmentActivation"]["schema"] = BASE_MAINNET_ENROLLMENT_SCHEMA
    a.artifact["evmChainId"] = 8453
    a.artifact["genesisPlan"]["evmChainId"] = 8453
    a.artifact["genesisPlan"]["enrollmentActivation"] = copy.deepcopy(a.artifact["enrollmentActivation"])
    a.artifact["artifactHash"] = artifact_hash(a.artifact)
    a.settings.expected_artifact_hash = a.artifact["artifactHash"]
    a.request = canonical_request(a.artifact["artifactHash"], a.wire)
    result = issuer.sign_enrollment_request(a.settings, a.request)
    assert result["permitHash"] == a.wire["permitHash"]
    assert len(a.calls) == 1
    a.artifact["evmChainId"] = 84532
    with pytest.raises(PermitIssuerUnavailable):
        issuer.sign_enrollment_request(a.settings, a.request)
    assert len(a.calls) == 1


def test_mainnet_posture_requires_complete_identity_metadata():
    values = dict(
        eip712_chain_id=8453, zkpassport_evm_chain_id=8453,
        enrollment_permit_release_identity="0x" + "ab" * 32,
        enrollment_permit_issuer_key_ref="https://solslot-test.vault.azure.net/keys/permit-test/" + "ab" * 16,
        enrollment_permit_identity_client_id="12345678-1234-1234-1234-123456789abc",
    )
    validate_server_hardening_at_startup(_staging(**values))
    for field in ("enrollment_permit_issuer_key_ref", "enrollment_permit_identity_client_id"):
        with pytest.raises(RuntimeError):
            validate_server_hardening_at_startup(_staging(**{**values, field: ""}))
    with pytest.raises(RuntimeError):
        validate_server_hardening_at_startup(_staging(**{**values, "zkpassport_evm_chain_id": 84532}))
