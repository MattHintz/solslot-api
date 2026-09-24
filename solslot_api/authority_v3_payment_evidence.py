"""Bind a payment deployment to the complete Authority V3 topology.

This checks sealed evidence structure. Live code, owners, guards, recovery and
timelock checks are also required by the deployment/activation preflight.
"""
from collections.abc import Mapping
import re

from eth_keys import keys
from eth_utils import keccak


def validate_payment_governance_v3(
    evidence, *, chain_id, source_sha, artifact_hash, root_safe, timelock, code_hashes,
):
    def require(condition):
        if not condition:
            raise ValueError("Omnichain Authority V3 governance evidence mismatches")

    def record(value):
        require(isinstance(value, Mapping))
        return value

    def address(value):
        require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is not None)
        require(int(value, 16) != 0)
        return value.lower()

    def digest(value):
        require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{64}", value) is not None)
        require(int(value, 16) != 0)
        return value.lower()

    def roster(value):
        require(isinstance(value, list) and len(value) == 3)
        require(all(isinstance(item, Mapping) for item in value))
        require([item.get("slot") for item in value] == [0, 1, 2])
        require(all(type(item.get("slot")) is int for item in value))
        return value

    require(type(chain_id) is int and chain_id in (8453, 84532))
    require(evidence.get("schemaVersion") == 3)
    require(evidence.get("kind") == "solslot-alpha-authority-v3-governance-deployment")
    require(evidence.get("authorityRule") == "slot0_and_one_of_slot1_slot2")
    require(evidence.get("chainId") == chain_id and type(evidence.get("chainId")) is int)
    require(evidence.get("network") == {8453: "baseMainnet", 84532: "baseSepolia"}[chain_id])
    require(evidence.get("sourceSha") == source_sha)
    require(digest(evidence.get("artifactHash")) == digest(artifact_hash))
    digest(evidence.get("rosterArtifactHash"))
    safes = record(evidence.get("safes"))
    identities = roster(safes.get("identities"))
    admins = roster(evidence.get("administrators"))
    recovery = record(evidence.get("recovery"))
    recovery_ids = roster(recovery.get("identities"))
    recovery_address = address(recovery.get("address"))
    require(recovery.get("routineDelaySeconds") == "86400")
    require(recovery.get("lostKeyDelaySeconds") == "604800")
    for flag in ("replacementAcceptanceRequired", "globalFreezeRequired",
                 "crossChainConvergenceRequired", "recoveryKitRotationSupported",
                 "rollbackRequiresChiaCancellationReceipt"):
        require(recovery.get(flag) is True)
    daily = []
    guardians = []
    identity_addresses = []
    contract_addresses = {"recovery": recovery_address}
    bls_keys = []
    for slot, (admin, identity, guardian) in enumerate(zip(admins, identities, recovery_ids)):
        signer = address(admin.get("address"))
        compressed = admin.get("compressedPubkey")
        require(isinstance(compressed, str) and re.fullmatch(r"0x0[23][0-9a-fA-F]{64}", compressed) is not None)
        try:
            require(keys.PublicKey.from_compressed_bytes(bytes.fromhex(compressed[2:])).to_checksum_address().lower() == signer)
        except Exception as exc:
            raise ValueError("Omnichain Authority V3 administrator key is invalid") from exc
        require(identity.get("owners") is not None and isinstance(identity["owners"], list))
        require([address(owner) for owner in identity["owners"]] == [signer])
        require(type(identity.get("threshold")) is int and identity["threshold"] == 1)
        require(address(identity.get("recoveryModule")) == recovery_address)
        identity_address = address(identity.get("address"))
        identity_addresses.append(identity_address)
        contract_addresses[f"identitySafe{slot}"] = identity_address
        contract_addresses[f"identityGuard{slot}"] = address(identity.get("guard"))
        daily.append(signer)
        guardians.append(address(guardian.get("evmGuardian")))
        bls = guardian.get("blsPubkey")
        require(isinstance(bls, str) and re.fullmatch(r"0x[0-9a-fA-F]{96}", bls) is not None and int(bls, 16) != 0)
        require(digest(guardian.get("blsCommitment")) == "0x" + keccak(bytes.fromhex(bls[2:])).hex())
        require(type(guardian.get("revision")) is int and guardian["revision"] > 0)
        require(isinstance(guardian.get("drillVerifiedAt"), str) and bool(guardian["drillVerifiedAt"]))
        bls_keys.append(bls.lower())
    require(len(set(daily + guardians)) == 6 and len(set(bls_keys)) == 3)
    coadmin = record(safes.get("coadmin"))
    root = record(safes.get("root"))
    for name, safe, threshold, owners in (
        ("coadmin", coadmin, 1, identity_addresses[1:]),
        ("root", root, 2, [identity_addresses[0], address(coadmin.get("address"))]),
    ):
        require(type(safe.get("threshold")) is int and safe["threshold"] == threshold)
        require(isinstance(safe.get("owners"), list) and len(safe["owners"]) == 2)
        require(set(address(owner) for owner in safe["owners"]) == set(owners))
        contract_addresses[name + "Safe"] = address(safe.get("address"))
        contract_addresses[name + "Guard"] = address(safe.get("guard"))
    require(address(root_safe) == contract_addresses["rootSafe"])
    require(address(evidence.get("payoutAddress")) == address(root_safe))
    lock = record(evidence.get("timelock"))
    contract_addresses["timelock"] = address(lock.get("address"))
    require(contract_addresses["timelock"] == address(timelock))
    require(lock.get("minimumDelaySeconds") == "86400")
    require(lock.get("externalAdmin") == "0x" + "00" * 20)
    for role in ("proposer", "executor", "canceller"):
        require(address(lock.get(role)) == address(root_safe))
    infrastructure = record(evidence.get("safeInfrastructure"))
    require(infrastructure.get("safeVersion") == "1.4.1")
    for name in ("identitySetup", "compatibilityFallbackHandler", "signMessageLibrary"):
        contract_addresses[name] = address(infrastructure.get(name))
    require(len(set(contract_addresses.values())) == len(contract_addresses))
    require(not set(contract_addresses.values()).intersection(daily + guardians))
    hashes = record(evidence.get("runtimeCodeHashes"))
    for name in contract_addresses:
        digest(hashes.get(name))
    for name in ("rootSafe", "timelock"):
        external_name = "governance" + name[0].upper() + name[1:]
        require(digest(hashes.get(name)) == digest(code_hashes.get(external_name)))
    chia = record(evidence.get("chiaAuthority"))
    require(chia.get("network") == "testnet11")
    digest(chia.get("sourceManifestHash"))
    launcher = digest(chia.get("authorityLauncherId"))
    launchers = chia.get("identityLauncherIds")
    require(isinstance(launchers, list) and len(launchers) == 3)
    require(len({launcher, *(digest(value) for value in launchers)}) == 4)
