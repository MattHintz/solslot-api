from __future__ import annotations

import json
import hashlib
import time
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from eth_abi import encode as abi_encode
from eth_utils import keccak
from fastapi import HTTPException
from fastapi.testclient import TestClient

from solslot_api.app import app
from solslot_api.config import get_settings, validate_server_hardening_at_startup
from solslot_api.payment_purchase_store import get_payment_purchase_store
from solslot_api.payment_quotes import SNAPSHOT_SCHEMA
from solslot_api.protocol_artifacts import (
    BuildProtocolOfferArtifactRequest,
    VerifyPurchaseFinalizationRequest,
    VerifyExternalEscrowWebhookRequest,
    _build_canonical_payment_artifact,
    _require_server_to_server_token,
    verify_external_escrow,
    verify_purchase_finalization,
)
from solslot_puzzles.payment_artifacts_v2 import (
    OracleObservationV1,
    PaymentArtifactError,
    PaymentRail,
    build_oracle_round,
    oracle_operator_set_root,
    oracle_round_signature_message,
    oracle_round_to_json,
    purchase_artifact_from_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    build_stripe_purchase_artifact_v3,
    build_sgt_purchase_artifact_v3,
    purchase_artifact_v3_to_json,
    purchase_artifact_v3_from_json,
    purchase_batch_from_json,
    stripe_settlement_evidence_to_json,
)
from solslot_api.zkpassport_enrollments import (
    AttestationProof,
    EnrollmentRecord,
    VaultCredentialReceipt,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


VAULT_ID = "0x" + "22" * 32
IDENTITY_ROOT = "0x" + "44" * 32
BRIDGE_POLICY = "0x" + "c1" * 32


def _active_genesis_artifact() -> dict:
    return {
        "artifactHash": "0x" + "d1" * 32,
        "puzzleHashes": {
            "protocolTreasuryPuzzleHash": "0x" + "42" * 32,
        },
        "launcherIds": {
            "pool": "0x" + "aa" * 32,
            "protocolConfig": "0x" + "bb" * 32,
            "vaultVersionRegistry": "0x" + "cc" * 32,
        },
        "bridgePolicy": {"policyHash": BRIDGE_POLICY},
        "retiredCoordinates": ["0x" + "e1" * 32],
    }


@pytest.fixture(autouse=True)
def isolate_protocol_artifact_env(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "SOLSLOT_DEPLOYMENT_MANIFEST_PATH",
        str(tmp_path / "missing.json"),
    )
    for name in (
        "SOLSLOT_ADMIN_PUBKEY_ALLOWLIST",
        "SOLSLOT_ADMIN_JWT_SECRET",
        "SOLSLOT_ADMIN_RECORDS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOLSLOT_POOL_LAUNCHER_ID", "0x" + "aa" * 32)
    monkeypatch.setenv("SOLSLOT_PROTOCOL_CONFIG_LAUNCHER_ID", "0x" + "bb" * 32)
    monkeypatch.setenv("SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID", "0x" + "cc" * 32)
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_BRIDGE_POLICY_HASH", BRIDGE_POLICY)
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_PURCHASE_DB_PATH",
        str(tmp_path / "payment-purchases.db"),
    )
    monkeypatch.setenv(
        "SOLSLOT_STRIPE_DELIVERY_DB_PATH",
        str(tmp_path / "stripe-deliveries.db"),
    )
    monkeypatch.setenv("SOLSLOT_COLLECTION_METADATA_ENABLED", "true")

    class Store:
        @staticmethod
        def get(collection_id):
            assert collection_id == "SOL-LOT-AUSTIN-ALPHA"
            return _published_collection()

    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.get_collection_store",
        lambda _settings: Store(),
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._verify_external_escrow_chain_evidence",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._active_presale_terms_for_deed",
        lambda _settings, _deed_launcher_id: None,
    )

    def confirmed_enrollment(_settings, vault_launcher_id):
        assert vault_launcher_id == VAULT_ID
        receipt = VaultCredentialReceipt(
            vaultLauncherId=VAULT_ID,
            network="testnet11",
            policyVersion=2,
            identityAttestRoot=IDENTITY_ROOT,
            attestationLeafHash=IDENTITY_ROOT,
            attestationProof=AttestationProof(bitpath=0, siblings=[]),
            bridgePolicyHash=BRIDGE_POLICY,
            bridgeParentId="0x" + "55" * 32,
            bridgeAmount=1,
            bridgeCoinId="0x" + "66" * 32,
            evmTxHash="0x" + "77" * 32,
            chiaVaultCoinId="0x" + "88" * 32,
            confirmedBlockIndex=12345,
            enrolledAt=int(time.time()) - 60,
        )
        now = int(time.time())
        return EnrollmentRecord(
            vaultLauncherId=VAULT_ID,
            network="testnet11",
            policyVersion=2,
            status="chia_confirmed",
            bridgePolicyHash=BRIDGE_POLICY,
            bridgeParentId=receipt.bridgeParentId,
            bridgeAmount=1,
            bridgeCoinId=receipt.bridgeCoinId,
            createdAt=now - 60,
            updatedAt=now,
            receipt=receipt,
        )

    monkeypatch.setattr(
        "solslot_api.zkpassport_enrollments._sync_chia_stamp",
        confirmed_enrollment,
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.load_signed_public_artifact",
        lambda _settings: _active_genesis_artifact(),
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _request(**overrides):
    base = {
        "protocol_version": "solslot-v2",
        "network": "testnet11",
        "genesis_artifact_hash": "0x" + "d1" * 32,
        "instance_id": "solslot-staging",
        "purchase_intent_id": "pi_test_001",
        "rail": "stripe",
        "deed_launcher_id": "0x" + "11" * 32,
        "property_id": "US-TX-AUSTIN-001",
        "collection_id": "SOL-LOT-AUSTIN-ALPHA",
        "share_ppm": 25_000,
        "vault_launcher_id": VAULT_ID,
        "current_vault_coin_id": "0x" + "88" * 32,
        "identity_attest_root": IDENTITY_ROOT,
        "expires_at": int(time.time()) + 3600,
        "payment_terms": {"currency": "USD", "quantity": 1},
        "authorization_nonce": "0x" + "14" * 32,
        "authorization_expires_at": int(time.time()) + 7200,
    }
    base.update(overrides)
    return base


def _published_collection(
    *,
    offering_currency: str = "USD",
    target_raise_minor: str = "5000000",
) -> dict:
    return {
        "id": "SOL-LOT-AUSTIN-ALPHA",
        "state": "PUBLISHED",
        "allocationLocked": True,
        "metadataRoot": "0x" + "12" * 32,
        "metadataAnchorId": "0x" + "13" * 32,
        "dossier": {
            "offering": {
                "currency": offering_currency,
                "targetRaiseMinor": target_raise_minor,
                "royaltyBps": "100",
                "royaltyPuzhash": "0x" + "42" * 32,
            },
            "deedAllocation": [
                {
                    "deedId": "US-TX-AUSTIN-001",
                    "sharePpm": 25_000,
                    "parValueMojos": "250000000000",
                },
                {
                    "deedId": "US-TX-AUSTIN-002",
                    "sharePpm": 25_000,
                    "parValueMojos": "250000000000",
                },
                {
                    "deedId": "US-TX-AUSTIN-003",
                    "sharePpm": 950_000,
                    "parValueMojos": "9500000000000",
                },
            ],
        },
        "deeds": [
            {
                "deedId": "US-TX-AUSTIN-001",
                "deedLauncherId": "0x" + "11" * 32,
                "sharePpm": 25_000,
                "parValueMojos": "250000000000",
                "executeBundleId": "0x" + "31" * 32,
                "confirmationHeight": 12346,
            },
            {
                "deedId": "US-TX-AUSTIN-002",
                "deedLauncherId": "0x" + "15" * 32,
                "sharePpm": 25_000,
                "parValueMojos": "250000000000",
                "executeBundleId": "0x" + "32" * 32,
                "confirmationHeight": 12347,
            },
        ],
    }


def _configure_native_quote(
    monkeypatch,
    tmp_path,
    now: int,
    *,
    offering_currency: str = "USD",
    target_raise_minor: str = "5000000",
) -> None:
    keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32)
        for seed in (81, 82, 83)
    )
    pubkeys = tuple(bytes(key.get_g1()) for key in keys)
    observations = tuple(
        OracleObservationV1(
            source_id=bytes32(bytes([index]) * 32),
            asset_id=bytes32.zeros,
            asset_decimals=12,
            price_usd_minor_per_asset=price,
            observed_at=now - 10 + index,
            valid_until=now + 300 + index,
            evidence_hash=bytes32(bytes([index + 20]) * 32),
        )
        for index, price in enumerate((2100, 2125, 2150), start=1)
    )
    round_ = build_oracle_round(
        network="testnet11",
        sequence=202,
        asset_id=bytes32.zeros,
        asset_decimals=12,
        operator_set_root=oracle_operator_set_root(pubkeys),
        observations=observations,
    )
    message = oracle_round_signature_message(round_.round_hash)
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "generatedAt": now,
        "rounds": [
            {
                "round": oracle_round_to_json(round_),
                "signatures": [
                    {
                        "signerIndex": index,
                        "signature": "0x"
                        + bytes(
                            AugSchemeMPL.sign(keys[index], message)
                        ).hex(),
                    }
                    for index in (0, 1)
                ],
            }
        ],
    }
    path = tmp_path / "native-quotes.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    monkeypatch.setenv("SOLSLOT_PAYMENT_ORACLE_ROUNDS_PATH", str(path))
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_ORACLE_OPERATOR_PUBKEYS",
        json.dumps(["0x" + value.hex() for value in pubkeys]),
    )
    monkeypatch.setenv("SOLSLOT_COLLECTION_METADATA_ENABLED", "true")

    class Store:
        @staticmethod
        def get(collection_id):
            assert collection_id == "SOL-LOT-AUSTIN-ALPHA"
            return _published_collection(
                offering_currency=offering_currency,
                target_raise_minor=target_raise_minor,
            )

    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.get_collection_store",
        lambda _settings: Store(),
    )
    get_settings.cache_clear()


def _configure_external_quote(
    monkeypatch,
    tmp_path,
    *,
    offering_currency: str = "USD",
    target_raise_minor: str = "5000000",
) -> None:
    monkeypatch.setenv("SOLSLOT_COLLECTION_METADATA_ENABLED", "true")
    runtime_code_hashes = {
        name: "0x" + value * 32
        for name, value in {
            "ccipRouter": "31",
            "gateway": "32",
            "spoke": "33",
            "usdc": "34",
            "governanceRootSafe": "35",
            "governanceTimelock": "36",
        }.items()
    }
    evidence = {
        "schemaVersion": 5,
        "protocolVersion": "solslot-v2",
        "rail": "ccip-warp-escrow",
        "sourceSha": "a" * 40,
        "network": "baseSepolia",
        "chainId": 84532,
        "chainSelector": "10344971235874465080",
        "confirmations": 12,
        "governanceArtifactHash": "0x" + "42" * 32,
        "samuelCoordinateArtifactHash": "0x" + "43" * 32,
        "warpPortalArtifactHash": "0x" + "44" * 32,
        "contracts": {
            "ccipRouter": "0x" + "11" * 20,
            "gateway": "0x" + "12" * 20,
            "spoke": "0x" + "13" * 20,
            "usdc": "0x" + "ab" * 20,
        },
        "configuration": {
            "hubChainSelector": "10344971235874465080",
            "callbackGas": "500000",
            "emergencyDelay": "604800",
            "payoutAddress": "0x" + "14" * 20,
            "governanceRootSafe": "0x" + "14" * 20,
            "governanceTimelock": "0x" + "15" * 20,
            "samuelSourceSha": "b" * 40,
            "predictedGatewayAddress": "0x" + "12" * 20,
            "ownershipAccepted": False,
        },
        "deploymentTransactions": {
            "gateway": {"hash": "0x" + "20" * 32, "blockNumber": 1},
            "spoke": {"hash": "0x" + "21" * 32, "blockNumber": 1},
            "gatewayOwnershipTransfer": {
                "hash": "0x" + "22" * 32,
                "blockNumber": 2,
            },
            "spokeOwnershipTransfer": {
                "hash": "0x" + "23" * 32,
                "blockNumber": 2,
            },
            "trustedSpokeUpdate": {
                "hash": "0x" + "24" * 32,
                "blockNumber": 2,
            },
        },
        "runtimeCodeHashes": runtime_code_hashes,
        "createdAt": "2026-07-20T00:00:00.000Z",
    }
    owner_safe = "0x" + "41" * 20
    coadmin_safe = "0x" + "42" * 20
    owner_address = "0x" + "51" * 20
    coadmin_addresses = ["0x" + value * 20 for value in ("52", "53")]
    guardian_address = "0x" + "54" * 20
    bls_guardian_pubkey = "0x" + "81" * 48
    governance = {
        "schemaVersion": 2,
        "kind": "solslot-alpha-owner-required-governance-deployment",
        "authorityRule": "slot0_and_one_of_slot1_slot2",
        "sourceSha": evidence["sourceSha"],
        "network": "baseSepolia",
        "chainId": 84532,
        "rosterArtifactHash": "0x" + "41" * 32,
        "administrators": [
            {"slot": 1, "address": owner_address},
            {"slot": 2, "address": coadmin_addresses[0]},
            {"slot": 3, "address": coadmin_addresses[1]},
        ],
        "safes": {
            "ownerIdentity": {
                "address": owner_safe,
                "owners": [owner_address],
                "threshold": 1,
                "guard": "0x" + "46" * 20,
            },
            "coadmin": {
                "address": coadmin_safe,
                "owners": coadmin_addresses,
                "threshold": 1,
                "guard": "0x" + "4a" * 20,
            },
            "root": {
                "address": evidence["configuration"]["governanceRootSafe"],
                "owners": [owner_safe, coadmin_safe],
                "threshold": 2,
                "guard": "0x" + "4b" * 20,
            },
        },
        "timelock": {
            "address": evidence["configuration"]["governanceTimelock"],
            "minimumDelaySeconds": "86400",
            "proposer": evidence["configuration"]["governanceRootSafe"],
            "executor": evidence["configuration"]["governanceRootSafe"],
            "canceller": evidence["configuration"]["governanceRootSafe"],
            "externalAdmin": "0x" + "00" * 20,
        },
        "payoutAddress": evidence["configuration"]["governanceRootSafe"],
        "recovery": {
            "address": "0x" + "45" * 20,
            "ownerGuard": "0x" + "46" * 20,
            "secp256k1Guardian": guardian_address,
            "blsGuardianPubkey": bls_guardian_pubkey,
            "blsGuardianCommitment": "0x" + keccak(
                bytes.fromhex(bls_guardian_pubkey[2:])
            ).hex(),
            "coadmins": coadmin_addresses,
            "delaySeconds": "604800",
            "replacementAcceptanceRequired": True,
        },
        "safeInfrastructure": {
            "safeVersion": "1.4.1",
            "compatibilityFallbackHandler": "0x" + "48" * 20,
            "signMessageLibrary": "0x" + "49" * 20,
            "ownerSetup": "0x" + "47" * 20,
        },
        "deploymentTransactions": {},
        "runtimeCodeHashes": {
            "ownerIdentitySafe": "0x" + "61" * 32,
            "coadminSafe": "0x" + "62" * 32,
            "rootSafe": runtime_code_hashes["governanceRootSafe"],
            "timelock": runtime_code_hashes["governanceTimelock"],
            "recovery": "0x" + "63" * 32,
            "ownerGuard": "0x" + "64" * 32,
            "coadminGuard": "0x" + "68" * 32,
            "rootGuard": "0x" + "69" * 32,
            "ownerSetup": "0x" + "65" * 32,
            "compatibilityFallbackHandler": "0x" + "66" * 32,
            "signMessageLibrary": "0x" + "67" * 32,
        },
        "createdAt": "2026-07-20T00:00:00.000Z",
    }
    governance_canonical = json.dumps(
        governance, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    governance["artifactHash"] = "0x" + hashlib.sha256(
        governance_canonical
    ).hexdigest()
    governance_path = tmp_path / "omnichain-governance-evidence.json"
    governance_path.write_text(json.dumps(governance), encoding="utf-8")
    evidence["governanceArtifactHash"] = governance["artifactHash"]

    validator_evm_addresses = [
        "0x" + value * 20 for value in ("71", "72", "73")
    ]
    samuel = {
        "schemaVersion": 3,
        "kind": "solslot-samuel-testnet-coordinates",
        "sourceSha": "b" * 40,
        "protocolSourceSha": "c" * 40,
        "validatorRosterArtifactHash": "0x" + "42" * 32,
        "testnet11": {
            "portalLauncherId": "0x" + "61" * 32,
            "bridgingPuzzleHash": "0x" + "62" * 32,
            "returnPuzzleHash": "0x" + "63" * 32,
            "resultAuthorizationModHash": "0x" + "64" * 32,
            "voucherBurnInnerHash": "0x" + "65" * 32,
        },
        "baseSepolia": {
            "chainId": 84532,
            "warpPortalAddress": "0x" + "16" * 20,
            "solomonGatewayAddress": evidence["contracts"]["gateway"],
        },
        "threshold": 2,
        "validatorPublicKeys": [
            "0x" + value * 48 for value in ("71", "72", "73")
        ],
        "validatorEvmAddresses": validator_evm_addresses,
        "returnRoute": {
            "destinationChain": "bse",
            "destinationAddress": evidence["contracts"]["gateway"],
        },
    }
    samuel_canonical = json.dumps(
        samuel, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    samuel["artifactHash"] = "0x" + hashlib.sha256(samuel_canonical).hexdigest()
    samuel_path = tmp_path / "omnichain-samuel-evidence.json"
    samuel_path.write_text(json.dumps(samuel), encoding="utf-8")
    evidence["samuelCoordinateArtifactHash"] = samuel["artifactHash"]

    warp_portal = {
        "schemaVersion": 1,
        "kind": "solslot-warp-base-sepolia-portal-deployment",
        "sourceSha": evidence["sourceSha"],
        "network": evidence["network"],
        "chainId": evidence["chainId"],
        "portal": {
            "address": samuel["baseSepolia"]["warpPortalAddress"],
            "owner": "0x" + "17" * 20,
            "signers": validator_evm_addresses,
            "signatureThreshold": 2,
            "messageTollWei": "0",
            "supportedChains": ["0x786368"],
            "initializedAtomically": True,
        },
        "proxy": {
            "implementation": "0x" + "18" * 20,
            "admin": "0x" + "19" * 20,
            "adminOwner": "0x" + "17" * 20,
            "standard": "openzeppelin-transparent-proxy-5.0.2",
        },
        "deploymentTransactions": {
            name: {
                "hash": "0x" + value * 32,
                "blockNumber": 1,
                "from": "0x" + "20" * 20,
                "dataHash": "0x" + value * 32,
            }
            for name, value in {
                "validatorSafe": "81",
                "portalImplementation": "82",
                "portalProxy": "83",
            }.items()
        },
        "runtimeCodeHashes": {
            "safe": "0x" + "38" * 32,
            "portal": "0x" + "37" * 32,
            "implementation": "0x" + "39" * 32,
            "proxyAdmin": "0x" + "3a" * 32,
        },
        "artifactRuntimeCodeHashes": {
            "portal": "0x" + "39" * 32,
            "transparentProxyTemplate": "0x" + "3b" * 32,
            "proxyAdmin": "0x" + "3a" * 32,
        },
        "createdAt": "2026-07-20T00:00:00.000Z",
    }
    warp_canonical = json.dumps(
        warp_portal, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    warp_portal["artifactHash"] = "0x" + hashlib.sha256(
        warp_canonical
    ).hexdigest()
    warp_path = tmp_path / "omnichain-warp-portal-evidence.json"
    warp_path.write_text(json.dumps(warp_portal), encoding="utf-8")
    evidence["warpPortalArtifactHash"] = warp_portal["artifactHash"]

    preflight = {
        "schemaVersion": 5,
        "kind": "solslot-omnichain-testnet-deployment-preflight",
        "sourceSha": evidence["sourceSha"],
        "network": evidence["network"],
        "chainId": evidence["chainId"],
        "chainSelector": evidence["chainSelector"],
        "hubName": "baseSepolia",
        "hubChainSelector": evidence["chainSelector"],
        "deploymentMode": "new_gateway_and_spoke",
        "governanceArtifactHash": evidence["governanceArtifactHash"],
        "samuelCoordinateArtifactHash": evidence[
            "samuelCoordinateArtifactHash"
        ],
        "warpPortalArtifactHash": evidence["warpPortalArtifactHash"],
        "settings": {
            "ccipRouter": evidence["contracts"]["ccipRouter"],
            "payout": evidence["configuration"]["payoutAddress"],
            "governance": evidence["configuration"]["governanceTimelock"],
            "rootSafe": evidence["configuration"]["governanceRootSafe"],
            "usdc": evidence["contracts"]["usdc"],
            "warpPortal": "0x" + "16" * 20,
            "protocolSourceSha": samuel["protocolSourceSha"],
            "samuelSourceSha": samuel["sourceSha"],
            "predictedGatewayAddress": evidence["contracts"]["gateway"],
            "voucherResultAuthorizationMod": samuel["testnet11"][
                "resultAuthorizationModHash"
            ],
            "voucherBurnInner": samuel["testnet11"][
                "voucherBurnInnerHash"
            ],
            "callbackGas": evidence["configuration"]["callbackGas"],
            "emergencyDelay": evidence["configuration"]["emergencyDelay"],
            "confirmations": evidence["confirmations"],
        },
        "inspection": {
            "tokenDecimals": {"usdc": 6},
            "runtimeCodeHashes": {
                evidence["contracts"]["ccipRouter"]: runtime_code_hashes[
                    "ccipRouter"
                ],
                evidence["contracts"]["usdc"]: runtime_code_hashes["usdc"],
                evidence["configuration"]["governanceRootSafe"]: runtime_code_hashes[
                    "governanceRootSafe"
                ],
                evidence["configuration"]["governanceTimelock"]: runtime_code_hashes[
                    "governanceTimelock"
                ],
                "0x" + "16" * 20: "0x" + "37" * 32,
            },
        },
        "checkedAt": "2026-07-20T00:00:00.000Z",
    }
    preflight_canonical = json.dumps(
        preflight, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    preflight["artifactHash"] = "0x" + hashlib.sha256(
        preflight_canonical
    ).hexdigest()
    preflight_path = tmp_path / "omnichain-preflight-evidence.json"
    preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
    evidence["preflightArtifactHash"] = preflight["artifactHash"]
    canonical = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    evidence["artifactHash"] = "0x" + hashlib.sha256(canonical).hexdigest()
    deployment_path = tmp_path / "omnichain-deployment-evidence.json"
    deployment_path.write_text(json.dumps(evidence), encoding="utf-8")
    ownership_targets = [
        evidence["contracts"]["gateway"],
        evidence["contracts"]["spoke"],
    ]
    ownership_values = [0, 0]
    ownership_payloads = [keccak(text="acceptOwnership()")[:4]] * 2
    ownership_predecessor = bytes(32)
    ownership_salt = bytes.fromhex("44" * 32)
    operation_id = "0x" + keccak(
        abi_encode(
            ["address[]", "uint256[]", "bytes[]", "bytes32", "bytes32"],
            [
                ownership_targets,
                ownership_values,
                ownership_payloads,
                ownership_predecessor,
                ownership_salt,
            ],
        )
    ).hex()
    schedule_data = "0x" + (
        keccak(
            text=(
                "scheduleBatch(address[],uint256[],bytes[],bytes32,bytes32,"
                "uint256)"
            )
        )[:4]
        + abi_encode(
            [
                "address[]",
                "uint256[]",
                "bytes[]",
                "bytes32",
                "bytes32",
                "uint256",
            ],
            [
                ownership_targets,
                ownership_values,
                ownership_payloads,
                ownership_predecessor,
                ownership_salt,
                86_400,
            ],
        )
    ).hex()
    execute_data = "0x" + (
        keccak(
            text="executeBatch(address[],uint256[],bytes[],bytes32,bytes32)"
        )[:4]
        + abi_encode(
            ["address[]", "uint256[]", "bytes[]", "bytes32", "bytes32"],
            [
                ownership_targets,
                ownership_values,
                ownership_payloads,
                ownership_predecessor,
                ownership_salt,
            ],
        )
    ).hex()
    ownership_intent = {
        "schemaVersion": 2,
        "kind": "solslot-omnichain-ownership-activation-intent",
        "deploymentArtifactHash": evidence["artifactHash"],
        "network": evidence["network"],
        "chainId": evidence["chainId"],
        "rootSafe": evidence["configuration"]["governanceRootSafe"],
        "timelock": evidence["configuration"]["governanceTimelock"],
        "operationId": operation_id,
        "minimumDelaySeconds": "86400",
        "scheduleTransaction": {
            "to": evidence["configuration"]["governanceTimelock"],
            "value": "0",
            "data": schedule_data,
        },
        "executeTransaction": {
            "to": evidence["configuration"]["governanceTimelock"],
            "value": "0",
            "data": execute_data,
        },
        "targets": [
            {
                "label": name,
                "address": evidence["contracts"][name],
                "currentOwner": "0x" + "20" * 20,
                "pendingOwner": evidence["configuration"]["governanceTimelock"],
                "runtimeCodeHash": evidence["runtimeCodeHashes"][name],
                "ownershipTransferTransactionHash": evidence[
                    "deploymentTransactions"
                ][f"{name}OwnershipTransfer"]["hash"],
            }
            for name in ("gateway", "spoke")
        ],
        "governanceArtifactHash": evidence["governanceArtifactHash"],
        "preparationSourceSha": "d" * 40,
        "preparationBlockNumber": 3,
        "createdAt": "2026-07-20T00:00:00.000Z",
    }
    ownership_canonical = json.dumps(
        ownership_intent,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    ownership_intent["artifactHash"] = "0x" + hashlib.sha256(
        ownership_canonical
    ).hexdigest()
    ownership_path = tmp_path / "omnichain-ownership-intent.json"
    ownership_path.write_text(json.dumps(ownership_intent), encoding="utf-8")
    activation = {
        "schemaVersion": 3,
        "kind": "ccip-warp-escrow-activation",
        "deploymentArtifactHash": evidence["artifactHash"],
        "ownershipOperationArtifactHash": ownership_intent["artifactHash"],
        "sourceSha": evidence["sourceSha"],
        "network": evidence["network"],
        "chainId": evidence["chainId"],
        "gatewayProfile": "bse",
        "contracts": {
            name: evidence["contracts"][name] for name in ("gateway", "spoke")
        },
        "runtimeCodeHashes": {
            name: evidence["runtimeCodeHashes"][name] for name in ("gateway", "spoke")
        },
        "governance": evidence["configuration"]["governanceTimelock"],
        "governanceRootSafe": evidence["configuration"]["governanceRootSafe"],
        "observedOwners": {
            name: evidence["configuration"]["governanceTimelock"]
            for name in ("gateway", "spoke")
        },
        "ownershipAccepted": True,
        "activatedAt": "2026-07-20T00:00:01.000Z",
    }
    activation_canonical = json.dumps(
        activation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    activation["artifactHash"] = "0x" + hashlib.sha256(activation_canonical).hexdigest()
    activation_path = tmp_path / "omnichain-activation-evidence.json"
    activation_path.write_text(json.dumps(activation), encoding="utf-8")
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "true")
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_OMNICHAIN_INGEST_TOKEN",
        "test-omnichain-callback-token-32-characters",
    )
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_OMNICHAIN_RPC_URL",
        "https://base-sepolia.example.invalid",
    )
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_PREFLIGHT_EVIDENCE_PATH", str(preflight_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_EVIDENCE_PATH", str(deployment_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ACTIVATION_EVIDENCE_PATH", str(activation_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_GOVERNANCE_EVIDENCE_PATH", str(governance_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_SAMUEL_EVIDENCE_PATH", str(samuel_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_WARP_PORTAL_EVIDENCE_PATH", str(warp_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_INTENT_EVIDENCE_PATH", str(ownership_path))
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_GATEWAY_PROFILE", "bse")
    monkeypatch.setenv(
        "SOLSLOT_PAYMENT_EVM_USDC_TOKENS",
        json.dumps(
            {
                "84532": "0x"
                + "ab" * 20,
            }
        ),
    )
    validator_pubkeys = [
        "0x" + bytes(
            AugSchemeMPL.key_gen(bytes([seed]) * 32).get_g1()
        ).hex()
        for seed in (91, 92, 93)
    ]
    monkeypatch.setenv(
        "SOLSLOT_ZKPASSPORT_VALIDATOR_PUBKEYS",
        json.dumps(validator_pubkeys),
    )
    monkeypatch.setenv(
        "SOLSLOT_ZKPASSPORT_VALIDATOR_URLS",
        json.dumps(
            [
                "https://validator-1.invalid",
                "https://validator-2.invalid",
                "https://validator-3.invalid",
            ]
        ),
    )

    class Store:
        @staticmethod
        def get(collection_id):
            assert collection_id == "SOL-LOT-AUSTIN-ALPHA"
            return _published_collection(
                offering_currency=offering_currency,
                target_raise_minor=target_raise_minor,
            )

    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.get_collection_store",
        lambda _settings: Store(),
    )
    get_settings.cache_clear()


def test_evm_offer_requires_reviewed_omnichain_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "false")
    get_settings.cache_clear()
    now = int(time.time())
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_omnichain_disabled",
                expires_at=now + 900,
                authorization_nonce="0x" + "18" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={"currency": "USDC", "quantity": 1, "chain_id": 84532},
            ),
        )
    assert response.status_code == 503
    assert "Omnichain payments are disabled" in response.text


def test_unverified_vault_cannot_obtain_a_purchase_artifact(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)

    def unverified(_settings, _vault_launcher_id):
        raise HTTPException(status_code=409, detail="No confirmed credential.")

    monkeypatch.setattr(
        "solslot_api.zkpassport_enrollments._sync_chia_stamp",
        unverified,
    )
    get_settings.cache_clear()
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_unverified",
                expires_at=int(time.time()) + 900,
                payment_terms={
                    "currency": "USDC",
                    "quantity": 1,
                    "chain_id": 84532,
                },
            ),
        )
    assert response.status_code == 409
    assert "not chain-confirmed" in response.text


def test_evm_offer_requires_omnichain_activation_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.delenv("SOLSLOT_PAYMENT_OMNICHAIN_ACTIVATION_EVIDENCE_PATH")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="activation evidence is not configured"):
        validate_server_hardening_at_startup(get_settings())


def test_evm_offer_requires_omnichain_preflight_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.delenv("SOLSLOT_PAYMENT_OMNICHAIN_PREFLIGHT_EVIDENCE_PATH")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="preflight evidence is not configured"):
        validate_server_hardening_at_startup(get_settings())


@pytest.mark.parametrize(
    ("environment_name", "label"),
    (
        ("SOLSLOT_PAYMENT_OMNICHAIN_GOVERNANCE_EVIDENCE_PATH", "governance"),
        ("SOLSLOT_PAYMENT_OMNICHAIN_SAMUEL_EVIDENCE_PATH", "samuel"),
        (
            "SOLSLOT_PAYMENT_OMNICHAIN_WARP_PORTAL_EVIDENCE_PATH",
            "warp_portal",
        ),
        (
            "SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_INTENT_EVIDENCE_PATH",
            "ownership_intent",
        ),
    ),
)
def test_evm_offer_requires_all_bound_evidence(
    monkeypatch, tmp_path, environment_name, label
):
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.delenv(environment_name)
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match=f"{label} evidence is not configured"):
        validate_server_hardening_at_startup(get_settings())


def _reseal_evidence(path, mutate):
    evidence = json.loads(path.read_text(encoding="utf-8"))
    mutate(evidence)
    evidence.pop("artifactHash")
    canonical = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    evidence["artifactHash"] = "0x" + hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(evidence), encoding="utf-8")


@pytest.mark.parametrize(
    ("filename", "mutate", "message"),
    (
        (
            "omnichain-samuel-evidence.json",
            lambda value: value["baseSepolia"].update(chainId=8453),
            "Samuel coordinates contain a mismatched payment chain",
        ),
        (
            "omnichain-samuel-evidence.json",
            lambda value: value.update(schemaVersion=1),
            "Samuel coordinates do not match the selected payment chain",
        ),
        (
            "omnichain-samuel-evidence.json",
            lambda value: value["validatorEvmAddresses"].__setitem__(
                1, value["validatorEvmAddresses"][0]
            ),
            "validatorEvmAddresses is invalid",
        ),
        (
            "omnichain-warp-portal-evidence.json",
            lambda value: value["portal"].update(signatureThreshold=1),
            "Warp portal evidence mismatches",
        ),
        (
            "omnichain-warp-portal-evidence.json",
            lambda value: value["runtimeCodeHashes"].update(
                implementation="0x" + "99" * 32
            ),
            "Warp portal evidence mismatches",
        ),
        (
            "omnichain-governance-evidence.json",
            lambda value: value["safes"]["coadmin"]["owners"].__setitem__(
                1, value["safes"]["coadmin"]["owners"][0]
            ),
            "governance evidence mismatches",
        ),
        (
            "omnichain-governance-evidence.json",
            lambda value: value.update(
                schemaVersion=1,
                kind="solslot-alpha-safe-timelock-deployment",
            ),
            "governance evidence mismatches",
        ),
        (
            "omnichain-governance-evidence.json",
            lambda value: value["recovery"].update(
                blsGuardianPubkey="0x" + "00" * 48
            ),
            "BLS recovery key is invalid",
        ),
        (
            "omnichain-governance-evidence.json",
            lambda value: value["timelock"].update(proposer="0x" + "99" * 20),
            "governance evidence mismatches",
        ),
        (
            "omnichain-governance-evidence.json",
            lambda value: value["runtimeCodeHashes"].update(
                timelock="0x" + "99" * 32
            ),
            "governance evidence mismatches",
        ),
        (
            "omnichain-activation-evidence.json",
            lambda value: value.update(ownershipAccepted=False),
            "activation evidence mismatches",
        ),
        (
            "omnichain-ownership-intent.json",
            lambda value: value["targets"][0].update(
                address="0x" + "99" * 20
            ),
            "ownership intent targets mismatch",
        ),
        (
            "omnichain-ownership-intent.json",
            lambda value: value.update(operationId="0x" + "99" * 32),
            "ownership intent operation ID mismatches",
        ),
        (
            "omnichain-ownership-intent.json",
            lambda value: value["scheduleTransaction"].update(
                data=value["executeTransaction"]["data"]
            ),
            "scheduleTransaction.data is invalid",
        ),
        (
            "omnichain-preflight-evidence.json",
            lambda value: value.update(
                warpPortalArtifactHash="0x" + "99" * 32
            ),
            "preflight evidence mismatches",
        ),
    ),
)
def test_evm_offer_rejects_invalid_authority_and_route_evidence(
    monkeypatch, tmp_path, filename, mutate, message
):
    _configure_external_quote(monkeypatch, tmp_path)
    _reseal_evidence(tmp_path / filename, mutate)
    if filename == "omnichain-ownership-intent.json":
        ownership_intent = json.loads(
            (tmp_path / filename).read_text(encoding="utf-8")
        )
        _reseal_evidence(
            tmp_path / "omnichain-activation-evidence.json",
            lambda value: value.update(
                {
                    "ownershipOperationArtifactHash": ownership_intent[
                        "artifactHash"
                    ]
                }
            ),
        )
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match=message):
        validate_server_hardening_at_startup(get_settings())


def test_evm_offer_rejects_preflight_with_changed_token_parameters(
    monkeypatch, tmp_path
):
    _configure_external_quote(monkeypatch, tmp_path)
    path = tmp_path / "omnichain-preflight-evidence.json"
    preflight = json.loads(path.read_text(encoding="utf-8"))
    preflight["inspection"]["tokenDecimals"]["usdc"] = 18
    preflight_without_hash = dict(preflight)
    preflight_without_hash.pop("artifactHash")
    canonical = json.dumps(
        preflight_without_hash,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    preflight["artifactHash"] = "0x" + hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(preflight), encoding="utf-8")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="preflight evidence mismatches"):
        validate_server_hardening_at_startup(get_settings())


def test_evm_offer_rejects_legacy_omnichain_schema(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    path = tmp_path / "omnichain-deployment-evidence.json"
    evidence = json.loads(path.read_text(encoding="utf-8"))
    evidence["schemaVersion"] = 3
    evidence_without_hash = dict(evidence)
    evidence_without_hash.pop("artifactHash")
    canonical = json.dumps(
        evidence_without_hash,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    evidence["artifactHash"] = "0x" + hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(evidence), encoding="utf-8")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="schema is unsupported"):
        validate_server_hardening_at_startup(get_settings())


def test_evm_offer_rejects_tampered_omnichain_evidence(monkeypatch, tmp_path):
    _configure_external_quote(monkeypatch, tmp_path)
    path = tmp_path / "omnichain-deployment-evidence.json"
    evidence = json.loads(path.read_text(encoding="utf-8"))
    evidence["sourceSha"] = "b" * 40
    path.write_text(json.dumps(evidence), encoding="utf-8")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="deployment evidence hash mismatches"):
        validate_server_hardening_at_startup(get_settings())


def test_builds_and_verifies_protocol_offer_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post("/protocol/offer-artifacts", json=_request())
        assert built.status_code == 200, built.text
        body = built.json()
        assert body["artifact_hash"].startswith("sha256:")
        assert body["protocol"]["zkPassportRequired"] is True
        assert body["protocol"]["artifactHash"] == body["artifact_hash"]

        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": body["artifact"],
                "artifact_hash": body["artifact_hash"],
            },
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True


@pytest.mark.parametrize(
    "legacy_field",
    (
        {"rail": "chia"},
        {"raw_offer": "offer1retired"},
    ),
)
def test_rejects_legacy_static_chia_offer_inputs(legacy_field):
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(**legacy_field),
        )
    assert response.status_code == 422


def test_builds_native_xch_offer_from_server_authorized_quote(
    monkeypatch,
    tmp_path,
):
    now = int(time.time())
    _configure_native_quote(monkeypatch, tmp_path, now)
    native_request = _request(
        rail="chia_xch",
        purchase_intent_id="pi_xch_native",
        expires_at=now + 240,
        payment_terms={
            "currency": "XCH",
            "quantity": 1,
        },
        authorization_nonce="0x" + "14" * 32,
        authorization_expires_at=now + 600,
    )
    native_request.pop("deed_launcher_id")
    native_request.pop("share_ppm")
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=native_request,
        )
        assert built.status_code == 200, built.text
        body = built.json()
        canonical = purchase_artifact_v3_from_json(
            body["purchase_artifact"]
        )
        assert canonical.base_usd_amount_minor == 125_000
        assert canonical.technology_fee_minor == 1_250
        assert canonical.gross_usd_amount_minor == 126_250
        assert canonical.rail_amount > 0
        assert body["purchase_artifact_hash"] == (
            "0x" + bytes(canonical.artifact_hash).hex()
        )
        assert body["purchase_id"] == (
            "0x" + bytes(canonical.purchase_id).hex()
        )
        assert body["protocol"]["purchaseArtifactHash"] == (
            body["purchase_artifact_hash"]
        )

        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": body["artifact"],
                "artifact_hash": body["artifact_hash"],
                "now": now,
            },
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True, verified.json()


def test_builds_one_canonical_native_batch_for_multiple_smartdeeds(
    monkeypatch,
    tmp_path,
):
    now = int(time.time())
    _configure_native_quote(monkeypatch, tmp_path, now)
    request = _request(
        rail="chia_xch",
        purchase_intent_id="pi_xch_batch",
        expires_at=now + 240,
        payment_terms={"currency": "XCH", "quantity": 2},
        authorization_nonce="0x" + "16" * 32,
        authorization_expires_at=now + 600,
    )
    request.pop("deed_launcher_id")
    request.pop("share_ppm")

    with TestClient(app) as client:
        built = client.post("/protocol/offer-artifacts", json=request)
        assert built.status_code == 200, built.text
        body = built.json()
        batch = purchase_batch_from_json(body["purchase_batch"])
        assert batch.quantity == 2
        assert len(batch.artifacts) == 2
        assert len({item.deed_launcher_id for item in batch.artifacts}) == 2
        assert body["protocol"]["quantity"] == 2
        assert body["protocol"]["deedLauncherIds"] == [
            "0x" + bytes(item.deed_launcher_id).hex()
            for item in batch.artifacts
        ]
        assert body["purchase_artifact_hash"] == (
            "0x" + bytes(batch.batch_hash).hex()
        )
        assert body["artifact"]["paymentTerms"]["amount"] == str(
            batch.total_rail_amount
        )

        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": body["artifact"],
                "artifact_hash": body["artifact_hash"],
                "now": now,
            },
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["valid"] is True, verified.json()


def test_multi_smartdeed_checkout_fails_when_equivalent_inventory_is_short():
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(payment_terms={"currency": "USD", "quantity": 3}),
        )
    assert response.status_code == 409
    assert "only 2 equivalent confirmed SmartDeeds" in response.text


def test_quote_price_uses_target_raise_share_not_chia_par_value(
    monkeypatch,
    tmp_path,
):
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="stripe",
                purchase_intent_id="pi_exact_dossier_price",
                expires_at=now + 900,
                authorization_nonce="0x" + "15" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={"currency": "USD", "quantity": 1},
            ),
        )
    assert built.status_code == 200, built.text
    purchase = built.json()["purchase_artifact"]
    assert purchase["baseAmountMinor"] == "125000"
    assert purchase["technologyFeeMinor"] == "1250"
    assert purchase["subtotalMinor"] == "126250"
    assert purchase["baseAmountMinor"] != "250000000000"


@pytest.mark.parametrize("rail,currency", [("stripe", "USD"), ("base_usdc", "USDC")])
def test_quote_for_active_presale_is_v3_and_window_bound(
    monkeypatch, tmp_path, rail, currency,
):
    _configure_external_quote(monkeypatch, tmp_path)
    get_settings().payment_evm_usdc_tokens["84532"] = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
    now = int(time.time())
    terms_hash = "0x" + "91" * 32
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._active_presale_terms_for_deed",
        lambda _settings, _deed_launcher_id: terms_hash,
    )

    class Presales:
        @staticmethod
        def get(value):
            assert value == terms_hash
            return {"terms": {"saleClose": now + 600}}

    monkeypatch.setattr(
        "solslot_api.presale_endpoints.get_presale_store",
        lambda _settings: Presales(),
    )
    body = BuildProtocolOfferArtifactRequest.model_validate(
        _request(
            rail=rail,
            purchase_intent_id="pi_stripe_presale_v3",
            expires_at=now + 900,
            authorization_nonce="0x" + "17" * 32,
            authorization_expires_at=now + 1200,
            payment_terms={"currency": currency, "quantity": 1},
        )
    )
    purchase, _oracle = _build_canonical_payment_artifact(
        body,
        get_settings(),
        vault_launcher_id=VAULT_ID,
        identity_attest_root=IDENTITY_ROOT,
        genesis_artifact=_active_genesis_artifact(),
    )

    assert purchase["schema"] == "solslot.purchase-artifact.v3"
    assert purchase["purchaseKind"] == 2
    assert purchase["presaleTermsHash"] == terms_hash
    assert purchase["quoteExpiresAt"] == str(now + 600)


@pytest.mark.asyncio
async def test_stripe_presale_finalization_dispatches_only_to_voucher_v3(
    monkeypatch,
    tmp_path,
) -> None:
    now = int(time.time())
    vault = bytes32.from_hexstr(VAULT_ID)
    purchase = build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=bytes32(bytes.fromhex("21" * 32)),
        deed_launcher_id=bytes32(bytes.fromhex("22" * 32)),
        metadata_root=bytes32(bytes.fromhex("23" * 32)),
        metadata_anchor_id=bytes32(bytes.fromhex("24" * 32)),
        share_ppm=25_000,
        base_usd_amount_minor=125_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=bytes32(bytes.fromhex("25" * 32)),
        zkpassport_root=bytes32.from_hexstr(IDENTITY_ROOT),
        vault_launcher_id=vault,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault),
        authorization_nonce=bytes32(bytes.fromhex("26" * 32)),
        authorization_expires_at=now + 1_200,
        quote_expires_at=now + 900,
        presale_terms_hash=bytes32(bytes.fromhex("27" * 32)),
    )
    purchase_json = purchase_artifact_v3_to_json(purchase)
    evidence = stripe_settlement_evidence_to_json(
        StripeSettlementEvidenceV1(
            stripe_account_id="acct_test_solslot",
            livemode=False,
            payment_intent_id="pi_presale_dispatch",
            event_id="evt_presale_dispatch",
            amount_minor=purchase.subtotal_minor,
            currency="usd",
            method_family=StripeMethodFamily.US_BANK_ACCOUNT,
            funding_type=StripeFundingType.BANK_ACCOUNT,
            processing_charge_minor=0,
            status=StripePaymentStatus.SUCCEEDED,
            refunded_minor=0,
            refund_state=StripeRefundState.NONE,
            dispute_state=StripeDisputeState.NONE,
            observed_at=now + 10,
        )
    )
    artifact_hash = "sha256:" + "28" * 32
    outer_artifact = {
        "protocol": {
            "purchaseIntentId": "pi_presale_dispatch",
            "rail": "stripe",
            "expiresAt": now + 900,
        },
        "purchaseArtifactV3": purchase_json,
    }
    stored = SimpleNamespace(
        purchase_intent_id="pi_presale_dispatch",
        artifact_hash=purchase_json["artifactHash"],
        offer_artifact_hash=artifact_hash,
        purchase_artifact=purchase_json,
    )
    observed = []

    class Purchases:
        @staticmethod
        def get(purchase_id):
            assert purchase_id == purchase_json["purchaseId"]
            return stored

    class Presales:
        @staticmethod
        def ingest_stripe_payment(terms_hash, **kwargs):
            observed.append((terms_hash, kwargs))
            return {"voucherState": "PENDING_ISSUANCE"}

    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._artifact_rejection_reasons",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._payment_evidence_rejection_reasons",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._verify_stripe_provider_evidence",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.get_payment_purchase_store",
        lambda *_args: Purchases(),
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.configured_validator_pubkeys",
        lambda *_args: tuple(
            bytes(AugSchemeMPL.key_gen(bytes([seed]) * 32).get_g1())
            for seed in (91, 92, 93)
        ),
    )
    monkeypatch.setattr(
        "solslot_api.presale_endpoints.get_presale_store",
        lambda *_args: Presales(),
    )
    result = await verify_purchase_finalization(
        VerifyPurchaseFinalizationRequest(
            artifact=outer_artifact,
            artifact_hash=artifact_hash,
            rail="stripe",
            purchase_intent_id="pi_presale_dispatch",
            payment_evidence=evidence,
            now=now + 10,
        ),
        get_settings(),
    )

    assert result.verified is True
    assert result.delivery_state == "PENDING_ISSUANCE"
    assert len(observed) == 1
    terms_hash, kwargs = observed[0]
    assert terms_hash == "0x" + "27" * 32
    assert kwargs["artifact"] == purchase
    assert kwargs["evidence_id"] == "evt_presale_dispatch"


def test_stripe_presale_rejects_unsupported_multi_deed_voucher_batch(
    monkeypatch,
    tmp_path,
) -> None:
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    terms_hash = "0x" + "29" * 32
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._active_presale_terms_for_deed",
        lambda _settings, _deed_launcher_id: terms_hash,
    )

    class Presales:
        @staticmethod
        def get(value):
            assert value == terms_hash
            return {"terms": {"saleClose": now + 600}}

    monkeypatch.setattr(
        "solslot_api.presale_endpoints.get_presale_store",
        lambda _settings: Presales(),
    )
    body = BuildProtocolOfferArtifactRequest.model_validate(
        _request(
            rail="stripe",
            purchase_intent_id="pi_stripe_presale_batch",
            expires_at=now + 900,
            authorization_nonce="0x" + "2a" * 32,
            authorization_expires_at=now + 1200,
            payment_terms={"currency": "USD", "quantity": 2},
        )
    )

    with pytest.raises(
        PaymentArtifactError,
        match="multi-deed checkout requires direct governed inventory",
    ):
        _build_canonical_payment_artifact(
            body,
            get_settings(),
            vault_launcher_id=VAULT_ID,
            identity_attest_root=IDENTITY_ROOT,
            genesis_artifact=_active_genesis_artifact(),
        )


@pytest.mark.parametrize(
    ("currency", "target_raise", "message"),
    (
        (
            "EUR",
            "5000000",
            "USD-denominated sealed target raise",
        ),
        (
            "USD",
            "5000001",
            "fractional USD minor units",
        ),
    ),
)
def test_quote_rejects_ambiguous_sealed_usd_price(
    monkeypatch,
    tmp_path,
    currency,
    target_raise,
    message,
):
    _configure_external_quote(
        monkeypatch,
        tmp_path,
        offering_currency=currency,
        target_raise_minor=target_raise,
    )
    now = int(time.time())
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="stripe",
                purchase_intent_id=f"pi_reject_{currency}_{target_raise}",
                expires_at=now + 900,
                authorization_nonce="0x" + "16" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={"currency": "USD", "quantity": 1},
            ),
        )
    assert response.status_code == 409
    assert message in response.text


def test_verify_rejects_tampered_or_expired_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(expires_at=now + 60),
        ).json()
        artifact = built["artifact"]
        artifact["protocol"]["sharePpm"] = 50_000
        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": artifact,
                "artifact_hash": built["artifact_hash"],
                "now": now + 61,
            },
        )
        assert verified.status_code == 200, verified.text
        reasons = verified.json()["reasons"]
        assert verified.json()["valid"] is False
        assert "artifact_hash_mismatch" in reasons
        assert "expired" in reasons


def test_evm_finalization_waits_for_authenticated_relay_message(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_base",
                expires_at=now + 900,
                authorization_nonce="0x" + "19" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={
                    "currency": "USDC",
                    "quantity": 1,
                    "chain_id": 84532,
                },
            ),
        )
        assert built.status_code == 200, built.text
        built = built.json()
        assert built["purchase_artifact"]["railAmount"] == "1262500000"
        finalization = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "base_usdc",
                "purchase_intent_id": "pi_base",
                "payment_evidence": {"tx_hash": "0x" + "ab" * 32},
            },
        )
        assert finalization.status_code == 200, finalization.text
        assert finalization.json()["verified"] is False
        assert "external_message_not_verified" in (
            finalization.json()["reasons"]
        )


def test_external_escrow_message_is_exactly_verified_and_bound(
    monkeypatch,
    tmp_path,
):
    _configure_external_quote(monkeypatch, tmp_path)
    now = int(time.time())
    with TestClient(app) as client:
        built_response = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="base_usdc",
                purchase_intent_id="pi_bridge_bound",
                expires_at=now + 900,
                authorization_nonce="0x" + "1b" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={
                    "currency": "USDC",
                    "quantity": 1,
                    "chain_id": 84532,
                },
            ),
        )
        assert built_response.status_code == 200, built_response.text
        purchase = built_response.json()["purchase_artifact"]
        message = {
            "gatewayProfile": "bse",
            "globalPaymentId": "0x" + "90" * 32,
            "localPaymentId": "0x" + "91" * 32,
            "depositor": "0x" + "80" * 20,
            "settlementToken": "0x" + "ab" * 20,
            "purchaseId": purchase["purchaseId"],
            "artifactHash": purchase["artifactHash"],
            "amount": purchase["railAmount"],
            "quantity": 1,
            "collectionId": purchase["collectionId"],
            "deedLauncherId": purchase["deedLauncherId"],
            "vaultLauncherId": purchase["vaultLauncherId"],
            "destinationPuzzle": purchase["vaultP2PuzzleHash"],
            "quoteExpiresAt": purchase["quoteExpiresAt"],
        }
        source = {
            "chainId": 84532,
            "spoke": "0x" + "13" * 20,
            "transactionHash": "0x" + "92" * 32,
            "blockNumber": 100,
            "blockHash": "0x" + "93" * 32,
            "blockTimestamp": now,
            "logIndex": 2,
            "confirmations": 12,
        }
        headers = {
            "Authorization": "Bearer test-omnichain-callback-token-32-characters"
        }
        unauthorized = client.post(
            "/protocol/purchase-intents/escrow-webhook",
            json={"escrowMessage": message, "source": source},
        )
        assert unauthorized.status_code == 401

        wrong_spoke = client.post(
            "/protocol/purchase-intents/escrow-webhook",
            json={
                "escrowMessage": message,
                "source": {**source, "spoke": "0x" + "ff" * 20},
            },
            headers=headers,
        )
        assert wrong_spoke.status_code == 409
        assert "provenance" in wrong_spoke.text

        underconfirmed = client.post(
            "/protocol/purchase-intents/escrow-webhook",
            json={
                "escrowMessage": message,
                "source": {**source, "confirmations": 11},
            },
            headers=headers,
        )
        assert underconfirmed.status_code == 422

        tampered = client.post(
            "/protocol/external-payments/verify",
            json={
                "escrowMessage": {
                    **message,
                    "amount": str(int(message["amount"]) - 1),
                },
                "source": source,
            },
            headers=headers,
        )
        assert tampered.status_code == 409
        assert "amount" in tampered.text

        redirected_vault = client.post(
            "/protocol/external-payments/verify",
            json={
                "escrowMessage": {
                    **message,
                    "vaultLauncherId": "0x" + "99" * 32,
                },
                "source": source,
            },
            headers=headers,
        )
        assert redirected_vault.status_code == 409
        assert "vaultLauncherId" in redirected_vault.text

        redirected_destination = client.post(
            "/protocol/external-payments/verify",
            json={
                "escrowMessage": {
                    **message,
                    "destinationPuzzle": "0x" + "98" * 32,
                },
                "source": source,
            },
            headers=headers,
        )
        assert redirected_destination.status_code == 409
        assert "destinationPuzzle" in redirected_destination.text

        verified = client.post(
            "/protocol/purchase-intents/escrow-webhook",
            json={"escrowMessage": message, "source": source},
            headers=headers,
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["escrow"]["verified"] is True
        assert verified.json()["verification"]["fulfillment"]["purchaseId"] == (
            purchase["purchaseId"]
        )
        built = built_response.json()
        finalized = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "base_usdc",
                "purchase_intent_id": "pi_bridge_bound",
                "payment_evidence": {
                    "tx_hash": "0x" + "ab" * 32,
                    "global_payment_id": message["globalPaymentId"],
                },
            },
        )
        assert finalized.status_code == 200, finalized.text
        assert finalized.json()["verified"] is True
        assert finalized.json()["delivery_state"] == "PAYMENT_VERIFIED"
        delivery = client.get(
            "/protocol/stripe-deliveries/" + purchase["purchaseId"]
        )
        assert delivery.status_code == 200, delivery.text
        assert delivery.json()["paymentRail"] == "base_usdc"
        assert delivery.json()["state"] == "PAYMENT_VERIFIED"

        monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "false")
        get_settings.cache_clear()
        disabled = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "base_usdc",
                "purchase_intent_id": "pi_bridge_bound",
                "payment_evidence": {
                    "tx_hash": "0x" + "ab" * 32,
                    "global_payment_id": message["globalPaymentId"],
                },
            },
        )
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["verified"] is False
        assert "external_escrow_evidence_unavailable" in disabled.json()["reasons"]

        monkeypatch.setenv("SOLSLOT_PAYMENT_OMNICHAIN_ENABLED", "true")
        get_settings.cache_clear()
        replay = client.post(
            "/protocol/external-payments/verify",
            json={
                "escrowMessage": {
                    **message,
                    "globalPaymentId": "0x" + "94" * 32,
                },
                "source": {**source, "transactionHash": "0x" + "95" * 32},
            },
            headers=headers,
        )
        assert replay.status_code == 409
        assert "another external payment" in replay.text


@pytest.mark.asyncio
async def test_base_escrow_verifier_binds_generic_sgt_delivery_commitment(
    monkeypatch,
    tmp_path,
):
    now = int(time.time())
    token = "0x" + "ab" * 20
    launcher = bytes32(b"\x71" * 32)
    purchase = build_sgt_purchase_artifact_v3(
        network="testnet11",
        sgt_asset_id=bytes32(b"\x72" * 32),
        sale_id=bytes32(b"\x73" * 32),
        sgt_amount=2_500,
        base_usd_amount_minor=50_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=bytes32(b"\x74" * 32),
        zkpassport_root=bytes32(b"\x75" * 32),
        rail=PaymentRail.EVM_TEST_USD,
        rail_chain_id=84532,
        rail_asset_id=bytes32(b"\x00" * 12 + bytes.fromhex(token[2:])),
        rail_asset_decimals=6,
        vault_launcher_id=launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(launcher),
        authorization_nonce=bytes32(b"\x76" * 32),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 600,
    )
    purchase_json = purchase_artifact_v3_to_json(purchase)
    settings = SimpleNamespace(
        payment_purchase_db_path=str(tmp_path / "sgt-base.db"),
        payment_evm_usdc_tokens={"84532": token},
    )
    get_payment_purchase_store(settings.payment_purchase_db_path).save(
        purchase_intent_id="pi_sgt_base_test",
        rail="base_usdc",
        offer_artifact_hash="sha256:" + "77" * 32,
        offer_artifact={"purchaseArtifactV3": purchase_json},
        purchase_artifact=purchase_json,
        created_at=now,
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._require_omnichain_ingest_token",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts.load_omnichain_evidence",
        lambda *_args, **_kwargs: SimpleNamespace(
            spoke_address="0x" + "78" * 20,
            confirmations=12,
        ),
    )
    payload = VerifyExternalEscrowWebhookRequest.model_validate(
        {
            "escrowMessage": {
                "gatewayProfile": "bse",
                "globalPaymentId": "0x" + "79" * 32,
                "localPaymentId": "0x" + "7a" * 32,
                "depositor": "0x" + "7b" * 20,
                "settlementToken": token,
                "purchaseId": purchase_json["purchaseId"],
                "artifactHash": purchase_json["artifactHash"],
                "amount": purchase.rail_amount,
                "quantity": purchase.delivery_amount,
                "collectionId": purchase_json["deliveryContextHash"],
                "deedLauncherId": purchase_json["deliveryAssetId"],
                "vaultLauncherId": purchase_json["vaultLauncherId"],
                "destinationPuzzle": purchase_json["vaultP2PuzzleHash"],
                "quoteExpiresAt": purchase.quote_expires_at,
            },
            "source": {
                "chainId": 84532,
                "spoke": "0x" + "78" * 20,
                "transactionHash": "0x" + "7c" * 32,
                "blockNumber": 456,
                "blockHash": "0x" + "7d" * 32,
                "blockTimestamp": now,
                "logIndex": 1,
                "confirmations": 12,
            },
        }
    )

    result = await verify_external_escrow(payload, settings, "Bearer callback")

    assert result.verified is True
    assert result.fulfillment["quantity"] == 2_500
    assert result.fulfillment["collectionId"] == purchase_json["deliveryContextHash"]
    assert result.fulfillment["deedLauncherId"] == purchase_json["deliveryAssetId"]


def test_finalization_accepts_exact_deliverable_stripe_settlement_evidence(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    _configure_external_quote(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "solslot_api.protocol_artifacts._verify_stripe_provider_evidence",
        lambda *_args, **_kwargs: None,
    )
    now = int(time.time())
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(
                rail="stripe",
                purchase_intent_id="pi_stripe",
                expires_at=now + 900,
                authorization_nonce="0x" + "1a" * 32,
                authorization_expires_at=now + 1200,
                payment_terms={
                    "currency": "USD",
                    "quantity": 1,
                },
            ),
        )
        assert built.status_code == 200, built.text
        built = built.json()
        assert built["purchase_artifact"]["railAmount"] == "126250"
        evidence = stripe_settlement_evidence_to_json(
            StripeSettlementEvidenceV1(
                stripe_account_id="acct_test_solslot",
                livemode=False,
                payment_intent_id="pi_test_123",
                event_id="evt_test_123",
                amount_minor=126_250,
                currency="usd",
                method_family=StripeMethodFamily.CARD,
                funding_type=StripeFundingType.CREDIT,
                processing_charge_minor=0,
                status=StripePaymentStatus.SUCCEEDED,
                refunded_minor=0,
                refund_state=StripeRefundState.NONE,
                dispute_state=StripeDisputeState.NONE,
                observed_at=now,
            )
        )
        finalization = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "stripe",
                "purchase_intent_id": "pi_stripe",
                "payment_evidence": evidence,
            },
        )
        assert finalization.status_code == 200, finalization.text
        assert finalization.json()["verified"] is True
        assert finalization.json()["finalized_state"] == "paid"
        assert finalization.json()["delivery_state"] == "PAYMENT_VERIFIED"
        delivery = client.get(
            "/protocol/stripe-deliveries/"
            + built["purchase_artifact"]["purchaseId"]
        )
        assert delivery.status_code == 200, delivery.text
        assert delivery.json()["state"] == "PAYMENT_VERIFIED"
        assert delivery.json()["purchaseId"] == built["purchase_artifact"]["purchaseId"]

        mismatched_evidence = stripe_settlement_evidence_to_json(
            StripeSettlementEvidenceV1(
                stripe_account_id="acct_test_solslot",
                livemode=False,
                payment_intent_id="pi_test_456",
                event_id="evt_test_456",
                amount_minor=124_999,
                currency="usd",
                method_family=StripeMethodFamily.CARD,
                funding_type=StripeFundingType.CREDIT,
                processing_charge_minor=0,
                status=StripePaymentStatus.SUCCEEDED,
                refunded_minor=0,
                refund_state=StripeRefundState.NONE,
                dispute_state=StripeDisputeState.NONE,
                observed_at=now,
            )
        )
        mismatched = client.post(
            "/protocol/purchase-finalizations/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
                "rail": "stripe",
                "purchase_intent_id": "pi_stripe",
                "payment_evidence": mismatched_evidence,
            },
        )
        assert mismatched.status_code == 200
        assert mismatched.json()["verified"] is False
        assert "stripe_amount_mismatch" in mismatched.json()["reasons"]


def test_build_and_finalization_can_require_server_token(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    monkeypatch.setenv("SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN", "server-only-token")
    get_settings.cache_clear()
    with TestClient(app) as client:
        assert client.post("/protocol/offer-artifacts", json=_request()).status_code == 401
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(),
            headers={"Authorization": "Bearer server-only-token"},
        )
        assert built.status_code == 200, built.text
    monkeypatch.delenv("SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN", raising=False)
    get_settings.cache_clear()


def test_production_protocol_service_fails_closed_without_token() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _require_server_to_server_token(
            get_settings().model_copy(
                update={
                    "runtime_environment": "production",
                    "protocol_artifact_api_token": None,
                }
            ),
            None,
        )

    assert exc_info.value.status_code == 503


def test_rejects_credential_markers_in_artifact_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("SOLSLOT_DEPLOYMENT_MANIFEST_PATH", str(tmp_path / "missing.json"))
    get_settings.cache_clear()
    with TestClient(app) as client:
        built = client.post(
            "/protocol/offer-artifacts",
            json=_request(metadata={"mandrill": "do-not-ship"}),
        )
        assert built.status_code == 400
        assert "mandrill" in built.text.lower()


def test_build_fails_closed_without_server_confirmed_receipt(monkeypatch):
    def missing_receipt(_settings, _vault_launcher_id):
        raise HTTPException(status_code=404, detail="Enrollment not found.")

    monkeypatch.setattr(
        "solslot_api.zkpassport_enrollments._sync_chia_stamp",
        missing_receipt,
    )
    with TestClient(app) as client:
        response = client.post("/protocol/offer-artifacts", json=_request())
    assert response.status_code == 409
    assert "not chain-confirmed" in response.text


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        (
            "current_vault_coin_id",
            "0x" + "99" * 32,
            "vault coin or identity root is no longer current",
        ),
        (
            "identity_attest_root",
            "0x" + "99" * 32,
            "vault coin or identity root is no longer current",
        ),
        (
            "genesis_artifact_hash",
            "0x" + "99" * 32,
            "genesis artifact is not the active signed artifact",
        ),
    ),
)
def test_build_rejects_stale_client_trust_context(field, value, message):
    with TestClient(app) as client:
        response = client.post(
            "/protocol/offer-artifacts",
            json=_request(**{field: value}),
        )
    assert response.status_code == 409
    assert message in response.text


def test_verify_rejects_receipt_that_is_no_longer_current(monkeypatch):
    with TestClient(app) as client:
        built = client.post("/protocol/offer-artifacts", json=_request()).json()

        def stale_enrollment(_settings, _vault_launcher_id):
            raise HTTPException(status_code=409, detail="Current vault coin changed.")

        monkeypatch.setattr(
            "solslot_api.zkpassport_enrollments._sync_chia_stamp",
            stale_enrollment,
        )
        verified = client.post(
            "/protocol/offer-artifacts/verify",
            json={
                "artifact": built["artifact"],
                "artifact_hash": built["artifact_hash"],
            },
        )
    assert verified.status_code == 200
    assert verified.json()["valid"] is False
    assert "credential_not_current_on_chia" in verified.json()["reasons"]


def test_active_presale_xch_quote_is_off_before_a_purchase_is_saved(monkeypatch, tmp_path):
    now=int(time.time())
    _configure_native_quote(monkeypatch,tmp_path,now)
    terms_hash='0x'+'91'*32
    monkeypatch.setattr('solslot_api.protocol_artifacts._active_presale_terms_for_deed',lambda *_:terms_hash)
    monkeypatch.setattr('solslot_api.presale_endpoints.get_presale_store',lambda _:SimpleNamespace(
        get=lambda _: {'terms':{'saleClose':now+600}}))
    payload=_request(rail='chia_xch',purchase_intent_id='pi_xch_presale_disabled',expires_at=now+240,
        payment_terms={'currency':'XCH','quantity':1},authorization_nonce='0x'+'14'*32,
        authorization_expires_at=now+600)
    payload.pop('deed_launcher_id');payload.pop('share_ppm')
    with TestClient(app) as client:
        result=client.post('/protocol/offer-artifacts',json=payload)
    assert result.status_code==503,result.text
    assert 'XCH voucher purchases are off' in result.json()['detail']
