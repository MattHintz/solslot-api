"""Retire the temporary exact-genesis fee adapter after its archive is sealed."""
from collections.abc import Mapping
from typing import Any

from .protocol_submission import ProtocolBundleSubmitter


def native_submitter_after_seal(
    submitter: Any,
    *,
    adapter_type: type,
    verified_artifact: Mapping[str, Any],
    ceremony: Mapping[str, Any],
    expected_artifact_hash: str,
    expected_ceremony_id: str,
) -> ProtocolBundleSubmitter:
    """Return the existing fee till without creating keys, reservations or spends.

    Callers load the archive through the signed-artifact verifier first. The
    temporary adapter remains installed for every unsealed or mismatched launch.
    The native object retains its funding store, coin exclusions and fee policy.
    """
    if (
        ceremony.get('state') != 'locked'
        or ceremony.get('ceremony_id') != expected_ceremony_id
        or ceremony.get('artifact_hash') != expected_artifact_hash
        or verified_artifact.get('artifactHash') != expected_artifact_hash
        or verified_artifact.get('network') != 'testnet11'
    ):
        raise RuntimeError('Native fee service requires the exact sealed testnet archive.')
    if type(submitter) is not adapter_type:
        raise RuntimeError('Unexpected genesis fee adapter; refusing to replace it.')
    base = submitter.base
    if not isinstance(base, ProtocolBundleSubmitter):
        raise RuntimeError('The existing native fee service is unavailable.')
    return base
