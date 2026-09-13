#!/usr/bin/env python3
"""Run the coordinator's exact live mTLS health gate without a ceremony."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from solslot_api.config import Settings
from solslot_api.validator_quorum import probe_validator_health


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-commit", required=True)
    parser.add_argument("--protocol-commit", required=True)
    parser.add_argument("--bridge-policy-hash", required=True)
    parser.add_argument("--forwarder", required=True)
    parser.add_argument("--verifier-adapter", required=True)
    parser.add_argument("--attestation-emitter", required=True)
    parser.add_argument("--enrollment-activation", type=Path,
        help="Exact reviewed activation JSON for selected Base Sepolia signers; this does not approve activation.")
    artifact = parser.add_mutually_exclusive_group()
    artifact.add_argument(
        "--require-artifact-hash",
        help="Require all three signers to load this finalized signed artifact.",
    )
    artifact.add_argument(
        "--require-no-artifact",
        action="store_true",
        help="Require a clean pre-genesis signer with no artifact installed.",
    )
    args = parser.parse_args()
    settings = Settings()
    health = await probe_validator_health(
        settings,
        expected_api_commit=args.api_commit,
        expected_protocol_commit=args.protocol_commit,
        expected_network=settings.network,
        expected_bridge_policy_hash=args.bridge_policy_hash.lower(),
        expected_evm_addresses={
            "forwarder": args.forwarder.lower(),
            "verifierAdapter": args.verifier_adapter.lower(),
            "attestationEmitter": args.attestation_emitter.lower(),
        },
        expected_artifact_ready=(
            True
            if args.require_artifact_hash
            else False
            if args.require_no_artifact
            else None
        ),
        expected_artifact_hash=args.require_artifact_hash,
        expected_enrollment_activation=(json.loads(args.enrollment_activation.read_text())
            if args.enrollment_activation else None),
    )
    print(json.dumps([item.model_dump(mode="json") for item in health], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
