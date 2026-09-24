"""Fail-closed binding for the separately deployed CCIP/Warp escrow rail."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from eth_utils import keccak

from .config import Settings
from .timelock_operation import (
    TimelockOperationError,
    decode_ownership_schedule,
    validate_ownership_execute,
)


MAX_EVIDENCE_BYTES = 128 * 1024
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class OmnichainEvidenceError(RuntimeError):
    """The external escrow rail is not safely configured for use."""


@dataclass(frozen=True)
class OmnichainEvidence:
    source_sha: str
    chain_id: int
    gateway_profile: str
    gateway_address: str
    spoke_address: str
    confirmations: int
    governance_root_safe: str
    governance_timelock: str
    return_puzzle_hash: str


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _require_address(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value.lower()


def _require_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value.lower()


def _require_selector(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.isdigit() or int(value) <= 0:
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return value


def _require_transaction(value: object, label: str) -> None:
    transaction = _require_mapping(value, label)
    _require_hash(transaction.get("hash"), f"{label}.hash")
    block_number = transaction.get("blockNumber")
    if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number <= 0:
        raise OmnichainEvidenceError(f"Omnichain evidence {label}.blockNumber is invalid")


def _require_deployment_transaction(value: object, label: str) -> None:
    transaction = _require_mapping(value, label)
    _require_transaction(transaction, label)
    _require_address(transaction.get("from"), f"{label}.from")
    _require_hash(transaction.get("dataHash"), f"{label}.dataHash")


def _require_address_list(
    value: object,
    label: str,
    *,
    length: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) != length:
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    normalized = [
        _require_address(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(set(normalized)) != length:
        raise OmnichainEvidenceError(f"Omnichain evidence {label} is invalid")
    return normalized


def _validate_ownership_calldata(
    *,
    schedule_data: object,
    execute_data: object,
    expected_targets: list[str],
    expected_operation_id: str,
) -> None:
    try:
        schedule = decode_ownership_schedule(
            schedule_data,
            expected_operation_id=expected_operation_id,
            label="Omnichain evidence ownershipIntent.scheduleTransaction.data",
        )
        normalized_expected = tuple(
            _require_address(target, "ownershipIntent.expectedTarget")
            for target in expected_targets
        )
        if tuple(target.lower() for target in schedule.targets) != tuple(
            target.lower() for target in normalized_expected
        ):
            raise OmnichainEvidenceError(
                "Omnichain ownership intent calldata mismatches"
            )
        validate_ownership_execute(
            execute_data,
            schedule=schedule,
            label="Omnichain evidence ownershipIntent.executeTransaction.data",
        )
    except TimelockOperationError as exc:
        raise OmnichainEvidenceError(str(exc)) from exc


def _preflight_runtime_hash(
    hashes: Mapping[str, Any], address: str, label: str
) -> str:
    normalized = _require_address(address, label)
    for candidate, code_hash in hashes.items():
        if _require_address(candidate, f"preflight.runtimeCodeHashes.{label}") == normalized:
            return _require_hash(code_hash, f"preflight.runtimeCodeHashes.{label}")
    raise OmnichainEvidenceError(
        f"Omnichain preflight evidence is missing {label} runtime code"
    )


def _load_evidence(path_value: str | None, label: str) -> dict[str, Any]:
    if not path_value:
        raise OmnichainEvidenceError(f"Omnichain {label} evidence is not configured")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise OmnichainEvidenceError(f"Omnichain {label} evidence is unavailable")
    try:
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_EVIDENCE_BYTES:
            raise OmnichainEvidenceError(f"Omnichain {label} evidence size is invalid")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OmnichainEvidenceError(f"Omnichain {label} evidence is invalid") from exc
    if not isinstance(raw, Mapping):
        raise OmnichainEvidenceError(f"Omnichain {label} evidence must be an object")
    evidence = dict(raw)
    declared_hash = _require_hash(evidence.pop("artifactHash", None), f"{label}.artifactHash")
    if declared_hash != _canonical_hash(evidence):
        raise OmnichainEvidenceError(f"Omnichain {label} evidence hash mismatches")
    evidence["artifactHash"] = declared_hash
    return evidence


def _selected_samuel_base(
    evidence: Mapping[str, Any], *, chain_id: int, chia_network: str,
) -> Mapping[str, Any]:
    """Select only the explicit coordinate schema for the configured route."""
    if chia_network != "testnet11" or type(chain_id) is not int:
        raise OmnichainEvidenceError("Samuel coordinates require the selected Testnet11 route")
    if (chain_id == 84532 and evidence.get("schemaVersion") == 3
            and "baseMainnet" not in evidence and "paymentChainId" not in evidence):
        selected = _require_mapping(evidence.get("baseSepolia"), "samuel.baseSepolia")
    elif (chain_id == 8453 and evidence.get("schemaVersion") == 4
            and type(evidence.get("paymentChainId")) is int
            and evidence.get("paymentChainId") == 8453
            and evidence.get("testOnly") is True
            and evidence.get("validatorIdentityDomain") == "solslot-alpha-native-bridge-testnet11-base-mainnet"
            and "baseSepolia" not in evidence):
        selected = _require_mapping(evidence.get("baseMainnet"), "samuel.baseMainnet")
    else:
        raise OmnichainEvidenceError("Samuel coordinates do not match the selected payment chain")
    if type(selected.get("chainId")) is not int or selected["chainId"] != chain_id:
        raise OmnichainEvidenceError("Samuel coordinates contain a mismatched payment chain")
    return selected


def load_omnichain_evidence(
    settings: Settings,
    *,
    chain_id: int,
    token_address: str,
    gateway_profile: str,
) -> OmnichainEvidence:
    """Load the reviewed deployment record required for one EVM rail request."""

    if not settings.payment_omnichain_enabled:
        raise OmnichainEvidenceError("Omnichain payments are disabled")
    if type(chain_id) is not int or chain_id != settings.payment_omnichain_chain_id:
        raise OmnichainEvidenceError("Omnichain request differs from the configured payment chain")
    payment_network = {8453: "baseMainnet", 84532: "baseSepolia"}[chain_id]
    source_sha = (settings.payment_omnichain_source_sha or "").lower()
    expected_profile = settings.payment_omnichain_gateway_profile
    if not _GIT_SHA_RE.fullmatch(source_sha) or not expected_profile:
        raise OmnichainEvidenceError("Omnichain deployment evidence is not configured")
    evidence = _load_evidence(settings.payment_omnichain_evidence_path, "deployment")
    declared_hash = str(evidence["artifactHash"])
    if evidence.get("schemaVersion") != 5 or evidence.get("rail") != "ccip-warp-escrow":
        raise OmnichainEvidenceError("Omnichain deployment evidence schema is unsupported")
    if evidence.get("protocolVersion") != "solslot-v2":
        raise OmnichainEvidenceError("Omnichain deployment evidence protocol is invalid")
    if evidence.get("sourceSha") != source_sha:
        raise OmnichainEvidenceError("Omnichain deployment evidence source SHA mismatches")
    if (type(evidence.get("chainId")) is not int
            or evidence.get("chainId") != chain_id
            or evidence.get("network") != payment_network):
        raise OmnichainEvidenceError("Omnichain deployment evidence chain mismatches")
    confirmations = evidence.get("confirmations")
    if (
        not isinstance(confirmations, int)
        or isinstance(confirmations, bool)
        or confirmations < 12
    ):
        raise OmnichainEvidenceError(
            "Omnichain deployment evidence confirmations are invalid"
        )
    governance_artifact_hash = _require_hash(
        evidence.get("governanceArtifactHash"), "governanceArtifactHash"
    )
    samuel_artifact_hash = _require_hash(
        evidence.get("samuelCoordinateArtifactHash"),
        "samuelCoordinateArtifactHash",
    )
    warp_portal_artifact_hash = _require_hash(
        evidence.get("warpPortalArtifactHash"),
        "warpPortalArtifactHash",
    )

    contracts = evidence.get("contracts")
    configuration = evidence.get("configuration")
    code_hashes = evidence.get("runtimeCodeHashes")
    if not isinstance(contracts, Mapping) or not isinstance(configuration, Mapping):
        raise OmnichainEvidenceError("Omnichain deployment evidence contracts are invalid")
    if not isinstance(code_hashes, Mapping):
        raise OmnichainEvidenceError("Omnichain deployment evidence code hashes are invalid")
    expected_token = _require_address(token_address, "configured token")
    if expected_token != _require_address(contracts.get("usdc"), "USDC"):
        raise OmnichainEvidenceError("Omnichain deployment evidence token mismatches")
    for name in ("ccipRouter", "gateway", "spoke", "usdc"):
        _require_address(contracts.get(name), name)
        _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}")
    governance_root_safe = _require_address(
        configuration.get("governanceRootSafe"), "configuration.governanceRootSafe"
    )
    governance_timelock = _require_address(
        configuration.get("governanceTimelock"),
        "configuration.governanceTimelock",
    )
    payout = _require_address(
        configuration.get("payoutAddress"), "configuration.payoutAddress"
    )
    if (
        payout != governance_root_safe
        or governance_root_safe == governance_timelock
        or configuration.get("ownershipAccepted") is not False
        or _require_selector(
            configuration.get("hubChainSelector"),
            "configuration.hubChainSelector",
        )
        != _require_selector(evidence.get("chainSelector"), "chainSelector")
    ):
        raise OmnichainEvidenceError("Omnichain governance configuration is invalid")
    for name in ("governanceRootSafe", "governanceTimelock"):
        _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}")
    deployment_transactions = _require_mapping(
        evidence.get("deploymentTransactions"), "deploymentTransactions"
    )
    for name in (
        "gateway",
        "spoke",
        "gatewayOwnershipTransfer",
        "spokeOwnershipTransfer",
        "trustedSpokeUpdate",
    ):
        _require_transaction(
            deployment_transactions.get(name), f"deploymentTransactions.{name}"
        )

    governance = _load_evidence(
        settings.payment_omnichain_governance_evidence_path, "governance"
    )
    if governance.get("schemaVersion") == 3:
        from .authority_v3_payment_evidence import validate_payment_governance_v3
        try:
            validate_payment_governance_v3(
                governance, chain_id=chain_id, source_sha=source_sha,
                artifact_hash=governance_artifact_hash, root_safe=governance_root_safe,
                timelock=governance_timelock, code_hashes=code_hashes,
            )
        except ValueError as exc:
            raise OmnichainEvidenceError(str(exc)) from exc
    else:
        if chain_id != 84532:
            raise OmnichainEvidenceError("Base payment rails require Authority V3")
        governance_safes = _require_mapping(governance.get("safes"), "governance.safes")
        owner_safe_record = _require_mapping(
            governance_safes.get("ownerIdentity"), "governance.safes.ownerIdentity"
        )
        coadmin_safe_record = _require_mapping(
            governance_safes.get("coadmin"), "governance.safes.coadmin"
        )
        root_safe_record = _require_mapping(
            governance_safes.get("root"), "governance.safes.root"
        )
        governance_timelock_record = _require_mapping(
            governance.get("timelock"), "governance.timelock"
        )
        governance_hashes = _require_mapping(
            governance.get("runtimeCodeHashes"), "governance.runtimeCodeHashes"
        )
        owner_safe_owners = owner_safe_record.get("owners")
        coadmin_safe_owners = coadmin_safe_record.get("owners")
        root_safe_owners = root_safe_record.get("owners")
        if not all(
            isinstance(owners, list)
            for owners in (owner_safe_owners, coadmin_safe_owners, root_safe_owners)
        ):
            raise OmnichainEvidenceError("Omnichain governance Safe owners are invalid")
        owner_safe = _require_address(
            owner_safe_record.get("address"), "governance.safes.ownerIdentity.address"
        )
        coadmin_safe = _require_address(
            coadmin_safe_record.get("address"), "governance.safes.coadmin.address"
        )
        root_safe = _require_address(
            root_safe_record.get("address"), "governance.safes.root.address"
        )
        owner_guard = _require_address(
            owner_safe_record.get("guard"), "governance.safes.ownerIdentity.guard"
        )
        coadmin_guard = _require_address(
            coadmin_safe_record.get("guard"), "governance.safes.coadmin.guard"
        )
        root_guard = _require_address(
            root_safe_record.get("guard"), "governance.safes.root.guard"
        )
        owner_address = _require_address(
            owner_safe_owners[0] if len(owner_safe_owners) == 1 else None,
            "governance.safes.ownerIdentity.owner",
        )
        coadmin_addresses = [
            _require_address(owner, "governance.safes.coadmin.owner")
            for owner in coadmin_safe_owners
        ]
        root_addresses = [
            _require_address(owner, "governance.safes.root.owner")
            for owner in root_safe_owners
        ]
        recovery = _require_mapping(governance.get("recovery"), "governance.recovery")
        infrastructure = _require_mapping(
            governance.get("safeInfrastructure"), "governance.safeInfrastructure"
        )
        secp_guardian = _require_address(
            recovery.get("secp256k1Guardian"), "governance.recovery.secp256k1Guardian"
        )
        bls_pubkey = recovery.get("blsGuardianPubkey")
        if (
            not isinstance(bls_pubkey, str)
            or not re.fullmatch(r"0x[0-9a-fA-F]{96}", bls_pubkey)
            or int(bls_pubkey, 16) == 0
        ):
            raise OmnichainEvidenceError("Omnichain governance BLS recovery key is invalid")
        bls_commitment = _require_hash(
            recovery.get("blsGuardianCommitment"),
            "governance.recovery.blsGuardianCommitment",
        )
        observed_bls_commitment = "0x" + keccak(bytes.fromhex(bls_pubkey[2:])).hex()
        administrator_records = governance.get("administrators")
        if not isinstance(administrator_records, list) or len(administrator_records) != 3:
            raise OmnichainEvidenceError("Omnichain governance administrators are invalid")
        administrator_slots = [record.get("slot") for record in administrator_records if isinstance(record, Mapping)]
        administrator_addresses = [
            _require_address(record.get("address"), "governance.administrator.address")
            for record in administrator_records
            if isinstance(record, Mapping)
        ]
        recovery_coadmins = recovery.get("coadmins")
        if not isinstance(recovery_coadmins, list):
            raise OmnichainEvidenceError("Omnichain governance recovery coadmins are invalid")
        normalized_recovery_coadmins = [
            _require_address(owner, "governance.recovery.coadmin")
            for owner in recovery_coadmins
        ]
        governance_contract_addresses = {
            "ownerIdentitySafe": owner_safe,
            "coadminSafe": coadmin_safe,
            "rootSafe": root_safe,
            "timelock": governance_timelock,
            "recovery": _require_address(
                recovery.get("address"), "governance.recovery.address"
            ),
            "ownerGuard": owner_guard,
            "coadminGuard": coadmin_guard,
            "rootGuard": root_guard,
            "ownerSetup": _require_address(
                infrastructure.get("ownerSetup"),
                "governance.safeInfrastructure.ownerSetup",
            ),
            "compatibilityFallbackHandler": _require_address(
                infrastructure.get("compatibilityFallbackHandler"),
                "governance.safeInfrastructure.compatibilityFallbackHandler",
            ),
            "signMessageLibrary": _require_address(
                infrastructure.get("signMessageLibrary"),
                "governance.safeInfrastructure.signMessageLibrary",
            ),
        }
        if secp_guardian in governance_contract_addresses.values():
            raise OmnichainEvidenceError(
                "Omnichain governance recovery guardian is not separate"
            )
        for name in governance_contract_addresses:
            _require_hash(
                governance_hashes.get(name),
                f"governance.runtimeCodeHashes.{name}",
            )
        if (
            governance.get("schemaVersion") != 2
            or governance.get("kind") != "solslot-alpha-owner-required-governance-deployment"
            or governance.get("authorityRule") != "slot0_and_one_of_slot1_slot2"
            or governance.get("sourceSha") != source_sha
            or governance.get("network") != "baseSepolia"
            or governance.get("chainId") != 84532
            or governance.get("artifactHash") != governance_artifact_hash
            or owner_safe_record.get("threshold") != 1
            or coadmin_safe_record.get("threshold") != 1
            or root_safe_record.get("threshold") != 2
            or len(coadmin_addresses) != 2
            or len(set((owner_address, *coadmin_addresses, secp_guardian))) != 4
            or administrator_slots != [1, 2, 3]
            or administrator_addresses != [owner_address, *coadmin_addresses]
            or len(root_addresses) != 2
            or set(root_addresses) != {owner_safe, coadmin_safe}
            or root_safe != governance_root_safe
            or len({owner_guard, coadmin_guard, root_guard}) != 3
            or _require_address(recovery.get("ownerGuard"), "governance.recovery.ownerGuard")
            != owner_guard
            or normalized_recovery_coadmins != coadmin_addresses
            or recovery.get("delaySeconds") != "604800"
            or recovery.get("replacementAcceptanceRequired") is not True
            or observed_bls_commitment != bls_commitment
            or infrastructure.get("safeVersion") != "1.4.1"
            or _require_address(governance.get("payoutAddress"), "governance.payoutAddress")
            != governance_root_safe
            or _require_address(governance_timelock_record.get("address"), "governance.timelock.address")
            != governance_timelock
            or governance_timelock_record.get("minimumDelaySeconds") != "86400"
            or _require_address(governance_timelock_record.get("proposer"), "governance.timelock.proposer")
            != governance_root_safe
            or _require_address(governance_timelock_record.get("executor"), "governance.timelock.executor")
            != governance_root_safe
            or _require_address(governance_timelock_record.get("canceller"), "governance.timelock.canceller")
            != governance_root_safe
            or governance_timelock_record.get("externalAdmin")
            != "0x0000000000000000000000000000000000000000"
            or _require_hash(governance_hashes.get("rootSafe"), "governance.runtimeCodeHashes.rootSafe")
            != _require_hash(code_hashes.get("governanceRootSafe"), "runtimeCodeHashes.governanceRootSafe")
            or _require_hash(governance_hashes.get("timelock"), "governance.runtimeCodeHashes.timelock")
            != _require_hash(code_hashes.get("governanceTimelock"), "runtimeCodeHashes.governanceTimelock")
        ):
            raise OmnichainEvidenceError("Omnichain governance evidence mismatches")

    samuel = _load_evidence(
        settings.payment_omnichain_samuel_evidence_path, "samuel"
    )
    samuel_testnet = _require_mapping(samuel.get("testnet11"), "samuel.testnet11")
    samuel_base = _selected_samuel_base(samuel, chain_id=chain_id, chia_network=settings.network)
    validator_keys = samuel.get("validatorPublicKeys")
    validator_evm_addresses = _require_address_list(
        samuel.get("validatorEvmAddresses"),
        "samuel.validatorEvmAddresses",
        length=3,
    )
    samuel_source_sha = str(samuel.get("sourceSha", "")).lower()
    protocol_source_sha = str(samuel.get("protocolSourceSha", "")).lower()
    if (
        samuel.get("kind") != "solslot-samuel-testnet-coordinates"
        or samuel.get("artifactHash") != samuel_artifact_hash
        or not _GIT_SHA_RE.fullmatch(samuel_source_sha)
        or not _GIT_SHA_RE.fullmatch(protocol_source_sha)
        or samuel_source_sha
        != str(configuration.get("samuelSourceSha", "")).lower()
        or not _HASH_RE.fullmatch(
            str(samuel.get("validatorRosterArtifactHash", ""))
        )
        or samuel.get("threshold") != 2
        or not isinstance(validator_keys, list)
        or len(validator_keys) != 3
        or len({str(key).lower() for key in validator_keys}) != 3
        or any(not re.fullmatch(r"0x[0-9a-fA-F]{96}", str(key)) for key in validator_keys)
        or samuel_base.get("chainId") != chain_id
        or _require_address(
            samuel_base.get("solomonGatewayAddress"),
            f"samuel.{payment_network}.solomonGatewayAddress",
        )
        != _require_address(contracts.get("gateway"), "gateway")
    ):
        raise OmnichainEvidenceError("Omnichain Samuel evidence mismatches")
    for name in (
        "portalLauncherId",
        "bridgingPuzzleHash",
        "returnPuzzleHash",
        "resultAuthorizationModHash",
        "voucherBurnInnerHash",
    ):
        _require_hash(samuel_testnet.get(name), f"samuel.testnet11.{name}")
    samuel_portal = _require_address(
        samuel_base.get("warpPortalAddress"), f"samuel.{payment_network}.warpPortalAddress"
    )
    return_route = _require_mapping(
        samuel.get("returnRoute"), "samuel.returnRoute"
    )
    if (
        return_route.get("destinationChain") != expected_profile
        or _require_address(
            return_route.get("destinationAddress"),
            "samuel.returnRoute.destinationAddress",
        )
        != _require_address(contracts.get("gateway"), "gateway")
    ):
        raise OmnichainEvidenceError("Omnichain Samuel return route mismatches")

    warp_portal = _load_evidence(
        settings.payment_omnichain_warp_portal_evidence_path,
        "warp_portal",
    )
    warp_portal_record = _require_mapping(
        warp_portal.get("portal"), "warp_portal.portal"
    )
    warp_proxy_record = _require_mapping(
        warp_portal.get("proxy"), "warp_portal.proxy"
    )
    warp_runtime_hashes = _require_mapping(
        warp_portal.get("runtimeCodeHashes"),
        "warp_portal.runtimeCodeHashes",
    )
    warp_artifact_hashes = _require_mapping(
        warp_portal.get("artifactRuntimeCodeHashes"),
        "warp_portal.artifactRuntimeCodeHashes",
    )
    warp_transactions = _require_mapping(
        warp_portal.get("deploymentTransactions"),
        "warp_portal.deploymentTransactions",
    )
    warp_signers = _require_address_list(
        warp_portal_record.get("signers"),
        "warp_portal.portal.signers",
        length=3,
    )
    warp_owner = _require_address(
        warp_portal_record.get("owner"), "warp_portal.portal.owner"
    )
    _require_address(
        warp_proxy_record.get("implementation"),
        "warp_portal.proxy.implementation",
    )
    _require_address(
        warp_proxy_record.get("admin"),
        "warp_portal.proxy.admin",
    )
    for name in ("validatorSafe", "portalImplementation", "portalProxy"):
        _require_deployment_transaction(
            warp_transactions.get(name),
            f"warp_portal.deploymentTransactions.{name}",
        )
    for name in ("safe", "portal", "implementation", "proxyAdmin"):
        _require_hash(
            warp_runtime_hashes.get(name),
            f"warp_portal.runtimeCodeHashes.{name}",
        )
    for name in ("portal", "transparentProxyTemplate", "proxyAdmin"):
        _require_hash(
            warp_artifact_hashes.get(name),
            f"warp_portal.artifactRuntimeCodeHashes.{name}",
        )
    if (
        warp_portal.get("schemaVersion") != (2 if chain_id == 8453 else 1)
        or warp_portal.get("kind")
        != ("solslot-native-bridge-base-mainnet-portal-deployment" if chain_id == 8453
            else "solslot-warp-base-sepolia-portal-deployment")
        or (chain_id == 8453 and (
            warp_portal.get("chiaNetwork") != "testnet11"
            or warp_portal.get("testOnly") is not True
            or warp_portal.get("validatorIdentityDomain") != "solslot-alpha-native-bridge-testnet11-base-mainnet"
        ))
        or warp_portal.get("artifactHash") != warp_portal_artifact_hash
        or warp_portal.get("sourceSha") != source_sha
        or warp_portal.get("network") != evidence.get("network")
        or warp_portal.get("chainId") != chain_id
        or _require_address(
            warp_portal_record.get("address"), "warp_portal.portal.address"
        )
        != samuel_portal
        or set(warp_signers) != set(validator_evm_addresses)
        or warp_owner in set(warp_signers)
        or warp_portal_record.get("signatureThreshold") != 2
        or warp_portal_record.get("messageTollWei") != "0"
        or warp_portal_record.get("supportedChains") != ["0x786368"]
        or warp_portal_record.get("initializedAtomically") is not True
        or _require_address(
            warp_proxy_record.get("adminOwner"),
            "warp_portal.proxy.adminOwner",
        )
        != warp_owner
        or warp_proxy_record.get("standard")
        != "openzeppelin-transparent-proxy-5.0.2"
        or _require_hash(
            warp_runtime_hashes.get("implementation"),
            "warp_portal.runtimeCodeHashes.implementation",
        )
        != _require_hash(
            warp_artifact_hashes.get("portal"),
            "warp_portal.artifactRuntimeCodeHashes.portal",
        )
        or _require_hash(
            warp_runtime_hashes.get("proxyAdmin"),
            "warp_portal.runtimeCodeHashes.proxyAdmin",
        )
        != _require_hash(
            warp_artifact_hashes.get("proxyAdmin"),
            "warp_portal.artifactRuntimeCodeHashes.proxyAdmin",
        )
    ):
        raise OmnichainEvidenceError("Omnichain Warp portal evidence mismatches")

    preflight = _load_evidence(
        settings.payment_omnichain_preflight_evidence_path, "preflight"
    )
    if (
        preflight.get("schemaVersion") != 5
        or preflight.get("kind")
        != "solslot-omnichain-testnet-deployment-preflight"
        or preflight.get("sourceSha") != source_sha
        or preflight.get("network") != evidence.get("network")
        or preflight.get("chainId") != chain_id
        or _require_selector(preflight.get("chainSelector"), "preflight.chainSelector")
        != _require_selector(evidence.get("chainSelector"), "chainSelector")
        or evidence.get("preflightArtifactHash") != preflight.get("artifactHash")
        or preflight.get("governanceArtifactHash") != governance_artifact_hash
        or preflight.get("samuelCoordinateArtifactHash") != samuel_artifact_hash
        or preflight.get("warpPortalArtifactHash")
        != warp_portal_artifact_hash
        or preflight.get("hubName") != payment_network
        or _require_selector(
            preflight.get("hubChainSelector"),
            "preflight.hubChainSelector",
        )
        != _require_selector(evidence.get("chainSelector"), "chainSelector")
        or preflight.get("deploymentMode") != "new_gateway_and_spoke"
    ):
        raise OmnichainEvidenceError("Omnichain preflight evidence mismatches")
    preflight_settings = _require_mapping(
        preflight.get("settings"), "preflight.settings"
    )
    preflight_inspection = _require_mapping(
        preflight.get("inspection"), "preflight.inspection"
    )
    if chain_id == 8453:
        asset = _load_evidence(settings.payment_omnichain_test_asset_evidence_path, "test_asset")
        if (settings.network != "testnet11" or asset.get("schemaVersion") != 1
                or asset.get("kind") != "solslot-test-asset-deployment"
                or asset.get("network") != "baseMainnet" or asset.get("chainId") != 8453
                or asset.get("chiaNetwork") != "testnet11" or asset.get("testOnly") is not True
                or asset.get("fixture") not in ("TEST-USDC", "TEST-SOLS") or asset.get("decimals") != 6
                or asset.get("sourceSha") != source_sha
                or _require_address(asset.get("address"), "test_asset.address") != expected_token
                or _require_hash(asset.get("runtimeCodeHash"), "test_asset.runtimeCodeHash")
                != _require_hash(code_hashes.get("usdc"), "runtimeCodeHashes.usdc")
                or asset["artifactHash"] != preflight_inspection.get("testAssetArtifactHash")):
            raise OmnichainEvidenceError("Base test payment asset differs from the reviewed preflight")
        _require_hash(asset.get("transactionHash"), "test_asset.transactionHash")
        _require_hash(asset.get("blockHash"), "test_asset.blockHash")
        if type(asset.get("blockNumber")) is not int or asset["blockNumber"] <= 0:
            raise OmnichainEvidenceError("test asset creation block is invalid")
        if asset["fixture"] == "TEST-SOLS":
            from solslot_puzzles.alpha_payment_profile import alpha_payment_profile
            profile = alpha_payment_profile()
            if (expected_token != profile["tokenAddress"]
                    or asset["runtimeCodeHash"] != profile["tokenRuntimeCodeHash"]):
                raise OmnichainEvidenceError("existing test payment token differs from the pinned alpha profile")
    preflight_decimals = _require_mapping(
        preflight_inspection.get("tokenDecimals"), "preflight.tokenDecimals"
    )
    preflight_hashes = _require_mapping(
        preflight_inspection.get("runtimeCodeHashes"),
        "preflight.runtimeCodeHashes",
    )
    expected_preflight_addresses = {
        "ccipRouter": contracts.get("ccipRouter"),
        "payout": payout,
        "governance": governance_timelock,
        "rootSafe": governance_root_safe,
        "usdc": contracts.get("usdc"),
    }
    for name, address in expected_preflight_addresses.items():
        if _require_address(preflight_settings.get(name), f"preflight.{name}") != _require_address(
            address, name
        ):
            raise OmnichainEvidenceError(
                "Omnichain preflight evidence contracts mismatch"
            )
    if (
        preflight_settings.get("callbackGas") != configuration.get("callbackGas")
        or preflight_settings.get("emergencyDelay")
        != configuration.get("emergencyDelay")
        or preflight_settings.get("confirmations") != evidence.get("confirmations")
        or preflight_decimals.get("usdc") != 6
        or _require_address(preflight_settings.get("warpPortal"), "preflight.warpPortal")
        != samuel_portal
        or preflight_settings.get("protocolSourceSha")
        != protocol_source_sha
        or preflight_settings.get("samuelSourceSha") != samuel_source_sha
        or _require_address(
            preflight_settings.get("predictedGatewayAddress"),
            "preflight.predictedGatewayAddress",
        )
        != _require_address(contracts.get("gateway"), "gateway")
        or _require_address(
            configuration.get("predictedGatewayAddress"),
            "configuration.predictedGatewayAddress",
        )
        != _require_address(contracts.get("gateway"), "gateway")
        or _require_hash(
            preflight_settings.get("voucherResultAuthorizationMod"),
            "preflight.voucherResultAuthorizationMod",
        )
        != _require_hash(
            samuel_testnet.get("resultAuthorizationModHash"),
            "samuel.testnet11.resultAuthorizationModHash",
        )
        or _require_hash(
            preflight_settings.get("voucherBurnInner"),
            "preflight.voucherBurnInner",
        )
        != _require_hash(
            samuel_testnet.get("voucherBurnInnerHash"),
            "samuel.testnet11.voucherBurnInnerHash",
        )
    ):
        raise OmnichainEvidenceError("Omnichain preflight evidence settings mismatch")
    for name in ("ccipRouter", "usdc"):
        if _preflight_runtime_hash(
            preflight_hashes, str(contracts.get(name)), name
        ) != _require_hash(code_hashes.get(name), f"runtimeCodeHashes.{name}"):
            raise OmnichainEvidenceError(
                "Omnichain preflight evidence runtime code mismatches"
            )
    if _preflight_runtime_hash(
        preflight_hashes,
        samuel_portal,
        "warpPortal",
    ) != _require_hash(
        warp_runtime_hashes.get("portal"),
        "warp_portal.runtimeCodeHashes.portal",
    ):
        raise OmnichainEvidenceError(
            "Omnichain preflight Warp portal runtime code mismatches"
        )
    for name, address in (
        ("governanceRootSafe", governance_root_safe),
        ("governanceTimelock", governance_timelock),
    ):
        if _preflight_runtime_hash(preflight_hashes, address, name) != _require_hash(
            code_hashes.get(name), f"runtimeCodeHashes.{name}"
        ):
            raise OmnichainEvidenceError(
                "Omnichain preflight evidence runtime code mismatches"
            )
    activation = _load_evidence(
        settings.payment_omnichain_activation_evidence_path, "activation"
    )
    if (
        activation.get("schemaVersion") != 3
        or activation.get("kind") != "ccip-warp-escrow-activation"
        or activation.get("deploymentArtifactHash") != declared_hash
        or activation.get("sourceSha") != source_sha
        or activation.get("network") != evidence.get("network")
        or activation.get("chainId") != chain_id
        or activation.get("gatewayProfile") != expected_profile
        or not _HASH_RE.fullmatch(
            str(activation.get("ownershipOperationArtifactHash", ""))
        )
        or activation.get("ownershipAccepted") is not True
    ):
        raise OmnichainEvidenceError("Omnichain activation evidence mismatches")
    if gateway_profile != expected_profile:
        raise OmnichainEvidenceError("Omnichain gateway profile is not enabled")
    activation_contracts = activation.get("contracts")
    activation_hashes = activation.get("runtimeCodeHashes")
    if not isinstance(activation_contracts, Mapping) or not isinstance(activation_hashes, Mapping):
        raise OmnichainEvidenceError("Omnichain activation evidence contracts are invalid")
    for name in ("gateway", "spoke"):
        if _require_address(activation_contracts.get(name), f"activation.{name}") != _require_address(
            contracts.get(name), name
        ) or _require_hash(activation_hashes.get(name), f"activation.runtimeCodeHashes.{name}") != _require_hash(
            code_hashes.get(name), f"runtimeCodeHashes.{name}"
        ):
            raise OmnichainEvidenceError("Omnichain activation evidence contract mismatches")
    if _require_address(
        activation.get("governance"), "activation.governance"
    ) != governance_timelock or _require_address(
        activation.get("governanceRootSafe"), "activation.governanceRootSafe"
    ) != governance_root_safe:
        raise OmnichainEvidenceError("Omnichain activation evidence governance mismatches")
    owners = activation.get("observedOwners")
    if not isinstance(owners, Mapping) or any(
        _require_address(owners.get(name), f"activation.observedOwners.{name}")
        != governance_timelock
        for name in ("gateway", "spoke")
    ):
        raise OmnichainEvidenceError("Omnichain governance ownership is not accepted")

    ownership_intent = _load_evidence(
        settings.payment_omnichain_ownership_intent_evidence_path,
        "ownership_intent",
    )
    ownership_targets = ownership_intent.get("targets")
    if not isinstance(ownership_targets, list) or len(ownership_targets) != 2:
        raise OmnichainEvidenceError(
            "Omnichain ownership intent targets are invalid"
        )
    expected_ownership_targets = {
        "gateway": (
            _require_address(contracts.get("gateway"), "gateway"),
            _require_hash(
                code_hashes.get("gateway"),
                "runtimeCodeHashes.gateway",
            ),
            _require_hash(
                deployment_transactions.get("gatewayOwnershipTransfer", {}).get(
                    "hash"
                ),
                "deploymentTransactions.gatewayOwnershipTransfer.hash",
            ),
        ),
        "spoke": (
            _require_address(contracts.get("spoke"), "spoke"),
            _require_hash(
                code_hashes.get("spoke"),
                "runtimeCodeHashes.spoke",
            ),
            _require_hash(
                deployment_transactions.get("spokeOwnershipTransfer", {}).get(
                    "hash"
                ),
                "deploymentTransactions.spokeOwnershipTransfer.hash",
            ),
        ),
    }
    observed_target_labels: set[str] = set()
    for target_value in ownership_targets:
        target = _require_mapping(target_value, "ownershipIntent.target")
        label = target.get("label")
        if not isinstance(label, str) or label not in expected_ownership_targets:
            raise OmnichainEvidenceError(
                "Omnichain ownership intent targets are invalid"
            )
        expected_address, expected_code_hash, expected_transfer_hash = (
            expected_ownership_targets[label]
        )
        if (
            label in observed_target_labels
            or _require_address(
                target.get("address"),
                f"ownershipIntent.targets.{label}.address",
            )
            != expected_address
            or _require_address(
                target.get("pendingOwner"),
                f"ownershipIntent.targets.{label}.pendingOwner",
            )
            != governance_timelock
            or _require_address(
                target.get("currentOwner"),
                f"ownershipIntent.targets.{label}.currentOwner",
            )
            == governance_timelock
            or _require_hash(
                target.get("runtimeCodeHash"),
                f"ownershipIntent.targets.{label}.runtimeCodeHash",
            )
            != expected_code_hash
            or _require_hash(
                target.get("ownershipTransferTransactionHash"),
                f"ownershipIntent.targets.{label}.ownershipTransferTransactionHash",
            )
            != expected_transfer_hash
        ):
            raise OmnichainEvidenceError(
                "Omnichain ownership intent targets mismatch"
            )
        observed_target_labels.add(label)
    schedule_transaction = _require_mapping(
        ownership_intent.get("scheduleTransaction"),
        "ownershipIntent.scheduleTransaction",
    )
    execute_transaction = _require_mapping(
        ownership_intent.get("executeTransaction"),
        "ownershipIntent.executeTransaction",
    )
    operation_id = _require_hash(
        ownership_intent.get("operationId"),
        "ownershipIntent.operationId",
    )
    if (
        ownership_intent.get("schemaVersion") != 2
        or ownership_intent.get("kind")
        != "solslot-omnichain-ownership-activation-intent"
        or ownership_intent.get("artifactHash")
        != activation.get("ownershipOperationArtifactHash")
        or ownership_intent.get("deploymentArtifactHash") != declared_hash
        or ownership_intent.get("network") != evidence.get("network")
        or ownership_intent.get("chainId") != chain_id
        or ownership_intent.get("minimumDelaySeconds") != "86400"
        or ownership_intent.get("governanceArtifactHash")
        != governance_artifact_hash
        or not _GIT_SHA_RE.fullmatch(
            str(ownership_intent.get("preparationSourceSha", "")).lower()
        )
        or not isinstance(
            ownership_intent.get("preparationBlockNumber"),
            int,
        )
        or isinstance(ownership_intent.get("preparationBlockNumber"), bool)
        or int(ownership_intent.get("preparationBlockNumber", 0)) <= 0
        or _require_address(ownership_intent.get("rootSafe"), "ownershipIntent.rootSafe")
        != governance_root_safe
        or _require_address(
            ownership_intent.get("timelock"), "ownershipIntent.timelock"
        )
        != governance_timelock
        or _require_address(
            schedule_transaction.get("to"),
            "ownershipIntent.scheduleTransaction.to",
        )
        != governance_timelock
        or schedule_transaction.get("value") != "0"
        or _require_address(
            execute_transaction.get("to"),
            "ownershipIntent.executeTransaction.to",
        )
        != governance_timelock
        or execute_transaction.get("value") != "0"
        or observed_target_labels != {"gateway", "spoke"}
    ):
        raise OmnichainEvidenceError("Omnichain ownership intent evidence mismatches")
    _validate_ownership_calldata(
        schedule_data=schedule_transaction.get("data"),
        execute_data=execute_transaction.get("data"),
        expected_targets=[
            expected_ownership_targets["gateway"][0],
            expected_ownership_targets["spoke"][0],
        ],
        expected_operation_id=operation_id,
    )

    return OmnichainEvidence(
        source_sha=source_sha,
        chain_id=chain_id,
        gateway_profile=gateway_profile,
        gateway_address=_require_address(contracts.get("gateway"), "gateway"),
        spoke_address=_require_address(contracts.get("spoke"), "spoke"),
        confirmations=confirmations,
        governance_root_safe=governance_root_safe,
        governance_timelock=governance_timelock,
        return_puzzle_hash=_require_hash(
            samuel_testnet.get("returnPuzzleHash"),
            "samuel.testnet11.returnPuzzleHash",
        ),
    )


__all__ = ["OmnichainEvidence", "OmnichainEvidenceError", "load_omnichain_evidence"]
