"""Exact cross-chain key-change intents for Admin Authority V3."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Mapping, Optional

import httpx
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs import AugSchemeMPL, G1Element, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from solslot_puzzles.admin_authority_v3_driver import (
    AUTHORITY_LAUNCHER_AMOUNT,
    IDENTITY_LAUNCHER_AMOUNTS,
    PENDING_LOST,
    PENDING_RECOVERY_KIT,
    PENDING_ROUTINE,
    AdminAuthorityV3State,
    GenesisAdminAuthorityV3,
    IdentityVaultGenesis,
    IdentityVaultTransition,
    authority_puzzle_version_for_hash,
    build_admin_identity_vault,
    build_authority_prepare_mips_spend,
    build_cancel_solution,
    build_complete_solution,
    build_genesis_admin_authority_v3,
    build_identity_approval_action,
    build_identity_approval_solution,
    build_identity_cancel_solution,
    build_identity_finish_solution,
    build_identity_vault_transition,
    build_lost_recovery_identity_solution,
    build_prepare_solution,
    build_routine_identity_prepare_solution,
    make_inner_puzzle,
)
from solslot_puzzles.admin_authority_v2_driver import (
    singleton_full_puzzle_hash,
)
from solslot_puzzles.eip712_helpers import (
    build_eip712_member_solution,
    eip712_hash_to_sign,
    eip712_prefix_and_domain_separator,
    eip712_typed_data_for_coin_spend,
    genesis_challenge_for_network,
    normalize_eip712_member_signature,
)

from .admin_authority_v3 import (
    AdminAuthorityV3Snapshot,
    LiveSingletonContext,
    build_admin_authority_v3_snapshot,
    load_live_singleton_context,
)
from .admin_security import (
    AUTHORITY_EVM_CHAIN_ID,
    SecurityActor,
    _hex_value,
    require_security_actor,
)
from .admin_roster import (
    artifact_admins,
    artifact_ceremony_id,
    current_artifact_admins,
)
from .authority_v3_evidence import load_governance_evidence
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .genesis import get_genesis_store
from .genesis_store import (
    GenesisConflict,
    GenesisNotFound,
    GenesisStore,
    GenesisStoreError,
)
from .faucet import AGG_SIG_ME_DATA
from .protocol_submission import (
    ProtocolBundleSubmitter,
    ProtocolSubmissionError,
)
from .public_artifact import load_signed_public_artifact


router = APIRouter(
    prefix="/admin/security/key-changes",
    tags=["admin-key-changes"],
)

ROUTINE_DELAY_SECONDS = 86_400
LOST_DELAY_SECONDS = 604_800
EXECUTION_WINDOW_SECONDS = 604_800
ZERO_EVM_ADDRESS = "0x0000000000000000000000000000000000000000"
INTENT_TYPE_HASH = keccak(text="SolslotAdminKeyChangeIntentV1")
INTENT_TUPLE_ABI = (
    "(uint8,uint8,address,address,bytes,bytes,address,address,bytes,bytes,"
    "bytes32[3],address[3],"
    "bytes32,address,address,string,uint256,bytes32,uint256,uint64,uint64)"
)
CHANGE_KIND_VALUES = {"ROUTINE": 1, "LOST": 2, "RECOVERY_KIT": 3}
LOST_KEY_AUTHORIZATION_PRIMARY_TYPE = "SolslotLostKeyPrepare"
RECOVERY_GUARDIAN_ACTION_PRIMARY_TYPES = {
    "ACCEPT": "SolslotRecoveryGuardianAccept",
    "VETO": "SolslotRecoveryGuardianVeto",
}
LOST_KEY_AUTHORIZATION_DOMAIN = {
    "name": "Solslot Admin Recovery",
    "version": "1",
}
TERMINAL_CASE_STATES = {"COMPLETED", "CANCELLED", "FAILED"}
SAFE_TRANSACTION_FIELDS = [
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "data", "type": "bytes"},
    {"name": "operation", "type": "uint8"},
    {"name": "safeTxGas", "type": "uint256"},
    {"name": "baseGas", "type": "uint256"},
    {"name": "gasPrice", "type": "uint256"},
    {"name": "gasToken", "type": "address"},
    {"name": "refundReceiver", "type": "address"},
    {"name": "nonce", "type": "uint256"},
]
EVENT_TOPICS = {
    "prepared": "0x"
    + keccak(
        text=(
            "KeyChangePrepared(bytes32,uint8,uint8,address,address,uint64)"
        )
    ).hex(),
    "authorityApproved": "0x"
    + keccak(text="AuthorityApproved(bytes32,address)").hex(),
    "peerApproved": "0x"
    + keccak(text="PeerApproved(bytes32,uint8)").hex(),
    "replacementAccepted": "0x"
    + keccak(text="ReplacementAccepted(bytes32,address)").hex(),
    "recoveryGuardianAccepted": "0x"
    + keccak(text="RecoveryGuardianAccepted(bytes32,address)").hex(),
    "vetoed": "0x"
    + keccak(text="KeyChangeVetoed(bytes32,address)").hex(),
    "peerCancellation": "0x"
    + keccak(text="PeerCancellationRecorded(bytes32,uint8)").hex(),
    "evmChanged": "0x"
    + keccak(text="EvmKeyChanged(bytes32,uint8,address,address)").hex(),
    "converged": "0x"
    + keccak(text="CrossChainConverged(bytes32,bytes32,uint8)").hex(),
    "rolledBack": "0x"
    + keccak(text="EvmKeyChangeRolledBack(bytes32,uint8,address)").hex(),
    "rollbackApproved": "0x"
    + keccak(text="RollbackApproved(bytes32,address)").hex(),
    "recoveryKitChanged": "0x"
    + keccak(
        text=(
            "RecoveryKitChanged(bytes32,uint8,address,address,bytes32,"
            "bytes32,uint64)"
        )
    ).hex(),
    "chiaCancellationRecorded": "0x"
    + keccak(text="ChiaCancellationRecorded(bytes32,bytes32)").hex(),
}


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class AdminKeyChangeIntentV1(ApiModel):
    schema_version: Literal[1] = Field(1, alias="schemaVersion")
    slot: int = Field(ge=0, le=2)
    kind: Literal["ROUTINE", "LOST", "RECOVERY_KIT"]
    old_daily_evm_key: str = Field(alias="oldDailyEvmKey")
    new_daily_evm_key: str = Field(alias="newDailyEvmKey")
    old_daily_chia_key: str = Field(alias="oldDailyChiaKey")
    new_daily_chia_key: str = Field(alias="newDailyChiaKey")
    old_recovery_guardian: str = Field(alias="oldRecoveryGuardian")
    new_recovery_guardian: str = Field(alias="newRecoveryGuardian")
    old_recovery_bls_key: str = Field(alias="oldRecoveryBlsKey")
    new_recovery_bls_key: str = Field(alias="newRecoveryBlsKey")
    identity_launcher_ids: list[str] = Field(
        alias="identityLauncherIds",
        min_length=3,
        max_length=3,
    )
    identity_safes: list[str] = Field(
        alias="identitySafes",
        min_length=3,
        max_length=3,
    )
    authority_launcher_id: str = Field(alias="authorityLauncherId")
    coadmin_safe: str = Field(alias="coadminSafe")
    root_safe: str = Field(alias="rootSafe")
    chia_network: Literal["testnet11"] = Field(
        "testnet11",
        alias="chiaNetwork",
    )
    evm_chain_id: Literal[84532] = Field(
        AUTHORITY_EVM_CHAIN_ID,
        alias="evmChainId",
    )
    source_manifest_hash: str = Field(alias="sourceManifestHash")
    nonce: int = Field(ge=1)
    expires_at: int = Field(alias="expiresAt", ge=1)
    recovery_key_revision: int = Field(
        alias="recoveryKeyRevision",
        ge=1,
    )

    @field_validator(
        "old_daily_chia_key",
        "new_daily_chia_key",
    )
    @classmethod
    def validate_chia_daily_key(cls, value: str) -> str:
        return _hex_value(value, 66, "daily Chia key")

    @field_validator(
        "old_recovery_bls_key",
        "new_recovery_bls_key",
    )
    @classmethod
    def validate_recovery_bls_key(cls, value: str) -> str:
        normalized = _hex_value(value, 96, "recovery BLS key")
        try:
            G1Element.from_bytes(bytes.fromhex(normalized[2:]))
        except (TypeError, ValueError) as exc:
            raise ValueError("recovery BLS key is invalid") from exc
        return normalized

    @field_validator(
        "authority_launcher_id",
        "source_manifest_hash",
    )
    @classmethod
    def validate_bytes32(cls, value: str) -> str:
        return _hex_value(value, 64, "intent bytes32")

    @field_validator("identity_launcher_ids")
    @classmethod
    def validate_launcher_ids(cls, values: list[str]) -> list[str]:
        normalized = [
            _hex_value(value, 64, "identity launcher ID")
            for value in values
        ]
        if len(set(normalized)) != 3:
            raise ValueError("identity launcher IDs must be unique")
        return normalized

    @field_validator(
        "old_daily_evm_key",
        "new_daily_evm_key",
        "old_recovery_guardian",
        "new_recovery_guardian",
        "coadmin_safe",
        "root_safe",
    )
    @classmethod
    def validate_address(cls, value: str) -> str:
        return normalize_evm_address(value, "authority address")

    @field_validator("identity_safes")
    @classmethod
    def validate_identity_safes(cls, values: list[str]) -> list[str]:
        normalized = [
            normalize_evm_address(value, "identity Safe") for value in values
        ]
        if len({value.lower() for value in normalized}) != 3:
            raise ValueError("identity Safes must be unique")
        return normalized


class RoutinePrepareRequest(ApiModel):
    new_daily_compressed_pubkey: str = Field(
        alias="newDailyCompressedPubkey"
    )

    @field_validator("new_daily_compressed_pubkey")
    @classmethod
    def validate_new_key(cls, value: str) -> str:
        return _hex_value(value, 66, "newDailyCompressedPubkey")


class LostPrepareRequest(RoutinePrepareRequest):
    ceremony_id: str = Field(alias="ceremonyId")
    slot: int = Field(ge=0, le=2)
    evm_guardian: str = Field(alias="evmGuardian")
    recovery_bls_pubkey: str = Field(alias="recoveryBlsPubkey")

    @field_validator("ceremony_id")
    @classmethod
    def validate_ceremony_id(cls, value: str) -> str:
        return _hex_value(value, 64, "ceremonyId")

    @field_validator("evm_guardian")
    @classmethod
    def validate_guardian(cls, value: str) -> str:
        return normalize_evm_address(value, "evmGuardian")

    @field_validator("recovery_bls_pubkey")
    @classmethod
    def validate_recovery_key(cls, value: str) -> str:
        return _hex_value(value, 96, "recoveryBlsPubkey")


class RecoveryKitPrepareRequest(ApiModel):
    challenge_id: str = Field(alias="challengeId")

    @field_validator("challenge_id")
    @classmethod
    def validate_challenge_id(cls, value: str) -> str:
        return _hex_value(value, 64, "challengeId")


class PreparedKeyChange(ApiModel):
    intent: AdminKeyChangeIntentV1
    intent_hash: str = Field(alias="intentHash")
    coordinator: str
    prepare_transaction: dict[str, Any] = Field(alias="prepareTransaction")
    clear_signing: dict[str, Any] = Field(alias="clearSigning")
    recovery_bls_digest: Optional[str] = Field(
        None,
        alias="recoveryBlsDigest",
    )
    guardian_typed_data: Optional[dict[str, Any]] = Field(
        None,
        alias="guardianTypedData",
    )


class LostKeyAuthorizationRequest(ApiModel):
    intent: AdminKeyChangeIntentV1
    guardian_signature: str = Field(alias="guardianSignature")

    @field_validator("guardian_signature")
    @classmethod
    def validate_guardian_signature(cls, value: str) -> str:
        return _hex_value(value, 130, "guardianSignature")


class LostKeyAuthorizationResponse(ApiModel):
    intent_hash: str = Field(alias="intentHash")
    guardian_signer: str = Field(alias="guardianSigner")
    relay_transaction: dict[str, Any] = Field(alias="relayTransaction")


class RecoveryGuardianAuthorizationRequest(ApiModel):
    action: Literal["ACCEPT", "VETO"]
    guardian_signature: str = Field(alias="guardianSignature")

    @field_validator("guardian_signature")
    @classmethod
    def validate_guardian_signature(cls, value: str) -> str:
        return _hex_value(value, 130, "guardianSignature")


class RecoveryGuardianAuthorizationResponse(ApiModel):
    intent_hash: str = Field(alias="intentHash")
    action: Literal["ACCEPT", "VETO"]
    guardian_signer: str = Field(alias="guardianSigner")
    relay_transaction: dict[str, Any] = Field(alias="relayTransaction")


class PreparedTransactionSubmission(ApiModel):
    intent: AdminKeyChangeIntentV1
    transaction_hash: str = Field(alias="transactionHash")
    recovery_bls_signature: Optional[str] = Field(
        None,
        alias="recoveryBlsSignature",
    )
    guardian_signature: Optional[str] = Field(
        None,
        alias="guardianSignature",
    )

    @field_validator("transaction_hash")
    @classmethod
    def validate_transaction_hash(cls, value: str) -> str:
        return _hex_value(value, 64, "transactionHash")

    @field_validator("recovery_bls_signature")
    @classmethod
    def validate_recovery_signature(
        cls,
        value: str | None,
    ) -> str | None:
        return (
            _hex_value(value, 192, "recoveryBlsSignature")
            if value is not None
            else None
        )

    @field_validator("guardian_signature")
    @classmethod
    def validate_guardian_signature(
        cls,
        value: str | None,
    ) -> str | None:
        return (
            _hex_value(value, 130, "guardianSignature")
            if value is not None
            else None
        )


class EvmTransactionObservation(ApiModel):
    transaction_hash: str = Field(alias="transactionHash")

    @field_validator("transaction_hash")
    @classmethod
    def validate_transaction_hash(cls, value: str) -> str:
        return _hex_value(value, 64, "transactionHash")


class EvmSafeActionPackageRequest(ApiModel):
    action_id: str = Field(alias="actionId")
    coadmin_slot: Optional[int] = Field(
        None,
        alias="coadminSlot",
        ge=1,
        le=2,
    )

    @field_validator("action_id")
    @classmethod
    def validate_action_id(cls, value: str) -> str:
        normalized = value.strip().lower()
        if (
            not normalized
            or len(normalized) > 80
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                for character in normalized
            )
        ):
            raise ValueError("Safe action ID is invalid")
        return normalized


class EvmSafeActionSignatureSubmission(EvmSafeActionPackageRequest):
    package_hash: str = Field(alias="packageHash")
    signature: str

    @field_validator("package_hash")
    @classmethod
    def validate_package_hash(cls, value: str) -> str:
        return _hex_value(value, 64, "packageHash")

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        return _hex_value(value, 130, "Safe signature")


class EvmActionSubmission(EvmSafeActionPackageRequest):
    transaction_hash: str = Field(alias="transactionHash")

    @field_validator("transaction_hash")
    @classmethod
    def validate_transaction_hash(cls, value: str) -> str:
        return _hex_value(value, 64, "transactionHash")


class ChiaActionPackageRequest(ApiModel):
    phase: Literal["PREPARE", "CANCEL", "COMPLETE"]
    coadmin_slot: Optional[int] = Field(
        None,
        alias="coadminSlot",
        ge=1,
        le=2,
    )


class ChiaActionSignatureSubmission(ApiModel):
    phase: Literal["PREPARE", "CANCEL"]
    action_id: str = Field(alias="actionId")
    signature: str
    coadmin_slot: Optional[int] = Field(
        None,
        alias="coadminSlot",
        ge=1,
        le=2,
    )

    @field_validator("action_id")
    @classmethod
    def validate_action_id(cls, value: str) -> str:
        return _hex_value(value, 64, "actionId")

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        normalized = value.lower()
        if not normalized.startswith("0x"):
            normalized = "0x" + normalized
        try:
            raw = bytes.fromhex(normalized[2:])
        except ValueError as exc:
            raise ValueError("signature must be hexadecimal") from exc
        if len(raw) not in (64, 65, 96):
            raise ValueError(
                "signature must be a 64/65-byte EIP signature "
                "or 96-byte BLS signature"
            )
        return normalized


@dataclass(frozen=True)
class _ChiaSigningAction:
    phase: Literal["PREPARE", "CANCEL"]
    action_id: str
    signer_kind: Literal["EIP712_DAILY", "BLS_RECOVERY"]
    signer_slot: int
    signer_public_key: str
    message_hash: str
    title: str
    summary: str
    coin_id: Optional[str] = None
    delegated_puzzle_hash: Optional[str] = None
    typed_data: Optional[dict[str, Any]] = None
    bls_pairs: tuple[tuple[str, str], ...] = ()

    def to_wire(self, *, signed: bool) -> dict[str, Any]:
        return {
            "actionId": self.action_id,
            "phase": self.phase,
            "signerKind": self.signer_kind,
            "signerSlot": self.signer_slot,
            "signerPublicKey": self.signer_public_key,
            "messageHash": self.message_hash,
            "title": self.title,
            "summary": self.summary,
            "network": "Testnet11",
            "financialEffect": "No administrator or protocol funds move.",
            "coinId": self.coin_id,
            "delegatedPuzzleHash": self.delegated_puzzle_hash,
            "typedData": self.typed_data,
            "blsPairs": [
                {"publicKey": public_key, "message": message}
                for public_key, message in self.bls_pairs
            ],
            "signed": signed,
        }


@dataclass(frozen=True)
class _ChiaRecoveryBuild:
    artifact: Mapping[str, Any]
    evidence: Mapping[str, Any]
    case: Mapping[str, Any]
    intent: AdminKeyChangeIntentV1
    snapshot: AdminAuthorityV3Snapshot
    authority: GenesisAdminAuthorityV3
    current_authority_inner: Program
    current_identities: tuple[
        IdentityVaultGenesis,
        IdentityVaultGenesis,
        IdentityVaultGenesis,
    ]
    authority_context: LiveSingletonContext
    identity_contexts: tuple[
        LiveSingletonContext,
        LiveSingletonContext,
        LiveSingletonContext,
    ]
    transition: IdentityVaultTransition
    coadmin_slot: Optional[int]


def _current_administrators(
    artifact: Mapping[str, Any],
    store: GenesisStore,
) -> list[tuple[str, str]]:
    return current_artifact_admins(artifact, store)


def _current_recovery_identities(
    artifact: Mapping[str, Any],
    evidence: Mapping[str, Any],
    store: GenesisStore,
) -> list[dict[str, Any]]:
    records = evidence.get("recovery", {}).get("identities")
    if (
        not isinstance(records, list)
        or len(records) != 3
        or [item.get("slot") for item in records] != [0, 1, 2]
    ):
        raise ValueError("Authority V3 recovery roster is malformed")
    current = [
        {
            "slot": slot,
            "evmGuardian": normalize_evm_address(
                item.get("evmGuardian"),
                "recovery guardian",
            ),
            "blsPubkey": _hex_value(
                item.get("blsPubkey"),
                96,
                "recovery BLS key",
            ),
            "blsCommitment": _hex_value(
                item.get("blsCommitment"),
                64,
                "recovery BLS commitment",
            ),
            "revision": int(item.get("revision") or 0),
        }
        for slot, item in enumerate(records)
    ]
    if any(item["revision"] < 1 for item in current):
        raise ValueError("Authority V3 recovery revision is invalid")
    ceremony_id = artifact_ceremony_id(artifact)
    try:
        cases = reversed(store.recovery_cases(ceremony_id))
    except GenesisNotFound:
        return current
    for case in cases:
        if case["state"] != "COMPLETED":
            continue
        intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
        if intent.kind != "RECOVERY_KIT":
            continue
        commitment = "0x" + keccak(
            bytes.fromhex(intent.new_recovery_bls_key[2:])
        ).hex()
        current[intent.slot] = {
            "slot": intent.slot,
            "evmGuardian": intent.new_recovery_guardian,
            "blsPubkey": intent.new_recovery_bls_key,
            "blsCommitment": commitment,
            "revision": intent.recovery_key_revision + 1,
        }
    return current


def _bytes32_hex(value: object, label: str) -> bytes32:
    normalized = _hex_value(value, 64, label)
    return bytes32(bytes.fromhex(normalized[2:]))


def _hex32(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _action_id(payload: Mapping[str, Any]) -> str:
    return "0x" + hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _pending_kind_value(kind: str) -> int:
    try:
        return {
            "ROUTINE": PENDING_ROUTINE,
            "LOST": PENDING_LOST,
            "RECOVERY_KIT": PENDING_RECOVERY_KIT,
        }[kind]
    except KeyError as exc:
        raise ValueError("Authority V3 pending kind is unsupported") from exc


def _state_from_snapshot(
    snapshot: AdminAuthorityV3Snapshot,
) -> AdminAuthorityV3State:
    custody_hashes = tuple(
        _bytes32_hex(identity.custody_hash, "identity custody hash")
        for identity in snapshot.identities
    )
    if not snapshot.pending:
        return AdminAuthorityV3State(
            current_identity_custody_hashes=custody_hashes,  # type: ignore[arg-type]
            authority_version=snapshot.authority_version,
        )
    required = (
        snapshot.pending_slot,
        snapshot.pending_intent_hash,
        snapshot.pending_identity_coin_id,
        snapshot.pending_original_custody_hash,
        snapshot.pending_replacement_custody_hash,
        snapshot.pending_replacement_member_hash,
    )
    if any(value is None for value in required):
        raise ValueError("Authority V3 pending state is incomplete")
    return AdminAuthorityV3State(
        current_identity_custody_hashes=custody_hashes,  # type: ignore[arg-type]
        authority_version=snapshot.authority_version,
        pending_kind=_pending_kind_value(snapshot.pending_kind),
        pending_slot=int(snapshot.pending_slot),
        pending_intent_hash=_bytes32_hex(
            snapshot.pending_intent_hash,
            "pending intent hash",
        ),
        pending_identity_coin_id=_bytes32_hex(
            snapshot.pending_identity_coin_id,
            "pending identity coin id",
        ),
        pending_original_custody_hash=_bytes32_hex(
            snapshot.pending_original_custody_hash,
            "pending original custody hash",
        ),
        pending_replacement_custody_hash=_bytes32_hex(
            snapshot.pending_replacement_custody_hash,
            "pending replacement custody hash",
        ),
        pending_replacement_member_hash=_bytes32_hex(
            snapshot.pending_replacement_member_hash,
            "pending replacement member hash",
        ),
        pending_delay_seconds=snapshot.pending_delay_seconds,
    )


def _authority_inner_from_snapshot(
    snapshot: AdminAuthorityV3Snapshot,
) -> Program:
    return make_inner_puzzle(
        authority_puzzle_version=authority_puzzle_version_for_hash(
            _bytes32_hex(
                snapshot.evidence.get("authorityInnerModHash"),
                "authority inner module hash",
            )
        ),
        authority_launcher_id=_bytes32_hex(
            snapshot.launcher_id,
            "authority launcher id",
        ),
        operational_root_hash=_bytes32_hex(
            snapshot.operational_mips_root_hash,
            "operational MIPS root",
        ),
        lost_recovery_root_hashes=tuple(
            _bytes32_hex(value, "lost recovery MIPS root")
            for value in snapshot.lost_recovery_mips_root_hashes
        ),
        identity_launcher_ids=tuple(
            _bytes32_hex(identity.launcher_id, "identity launcher id")
            for identity in snapshot.identities
        ),
        source_manifest_hash=_bytes32_hex(
            snapshot.source_manifest_hash,
            "source manifest hash",
        ),
        state=_state_from_snapshot(snapshot),
        routine_delay_seconds=snapshot.routine_delay_seconds,
        lost_key_delay_seconds=snapshot.lost_key_delay_seconds,
    )


def _genesis_authority_from_artifact(
    artifact: Mapping[str, Any],
) -> GenesisAdminAuthorityV3:
    plan = artifact.get("genesisPlan")
    authority_record = artifact.get("adminAuthority")
    if not isinstance(plan, Mapping) or not isinstance(
        authority_record,
        Mapping,
    ):
        raise ValueError("Signed Authority V3 artifact is incomplete")
    funding = plan.get("fundingCoinIds")
    identities = authority_record.get("identityVaults")
    if not isinstance(funding, Mapping) or not isinstance(
        identities,
        list,
    ) or len(identities) != 3:
        raise ValueError("Signed Authority V3 genesis coordinates are incomplete")
    authority = build_genesis_admin_authority_v3(
        authority_puzzle_version=plan.get("authorityPuzzleVersion", 3),
        parent_coin_id=_bytes32_hex(
            funding.get("admin_authority"),
            "Authority V3 funding coin",
        ),
        network="testnet11",
        daily_compressed_pubkeys=tuple(
            bytes.fromhex(
                _hex_value(
                    identity.get("dailyCompressedPubkey"),
                    66,
                    "genesis daily key",
                )[2:]
            )
            for identity in identities
        ),
        recovery_bls_pubkeys=tuple(
            bytes.fromhex(
                _hex_value(
                    identity.get("recoveryBlsPubkey"),
                    96,
                    "genesis recovery key",
                )[2:]
            )
            for identity in identities
        ),
        source_manifest_hash=_bytes32_hex(
            authority_record.get("sourceManifestHash"),
            "Authority V3 source manifest",
        ),
    )
    expected_launcher = str(
        artifact.get("launcherIds", {}).get("adminAuthority")  # type: ignore[union-attr]
        or ""
    ).lower()
    if _hex32(authority.authority_launcher_id) != expected_launcher:
        raise ValueError("Authority V3 launcher does not reconstruct")
    if [
        _hex32(identity.launcher_id)
        for identity in authority.identity_vaults
    ] != [
        str(identity.get("launcherId") or "").lower()
        for identity in identities
    ]:
        raise ValueError("Authority V3 identity launchers do not reconstruct")
    return authority


def _current_identity_vaults(
    *,
    artifact: Mapping[str, Any],
    evidence: Mapping[str, Any],
    store: GenesisStore,
    authority: GenesisAdminAuthorityV3,
) -> tuple[
    IdentityVaultGenesis,
    IdentityVaultGenesis,
    IdentityVaultGenesis,
]:
    administrators = _current_administrators(artifact, store)
    recoveries = _current_recovery_identities(artifact, evidence, store)
    identities = tuple(
        build_admin_identity_vault(
            slot=slot,
            launcher_id=authority.identity_vaults[slot].launcher_id,
            authority_launcher_id=authority.authority_launcher_id,
            network="testnet11",
            daily_compressed_pubkey=bytes.fromhex(
                _hex_value(
                    administrators[slot][1],
                    66,
                    "current daily Chia key",
                )[2:]
            ),
            recovery_bls_pubkey=bytes.fromhex(
                _hex_value(
                    recoveries[slot]["blsPubkey"],
                    96,
                    "current recovery BLS key",
                )[2:]
            ),
        )
        for slot in range(3)
    )
    return identities  # type: ignore[return-value]


def _assert_full_puzzle_hash(
    *,
    context: LiveSingletonContext,
    launcher_id: bytes32,
    inner_puzzle: Program,
    label: str,
) -> None:
    expected = singleton_full_puzzle_hash(
        launcher_id,
        bytes32(inner_puzzle.get_tree_hash()),
    )
    if context.coin.puzzle_hash != expected:
        raise ValueError(f"{label} live puzzle does not match reconstructed state")


async def _chia_recovery_build(
    *,
    case: Mapping[str, Any],
    phase: Literal["PREPARE", "CANCEL", "COMPLETE"],
    coadmin_slot: int | None,
    request: Request,
    settings: Settings,
    store: GenesisStore,
) -> _ChiaRecoveryBuild:
    artifact, evidence, _coordinator = await _verified_evidence_context(
        settings
    )
    _validate_intent_bindings(
        intent=AdminKeyChangeIntentV1.model_validate(case["intent"]),
        artifact=artifact,
        evidence=evidence,
        store=store,
    )
    provider = getattr(request.app.state, "coinset", None)
    if provider is None:
        raise ValueError("Testnet11 Chia provider is unavailable")
    snapshot = await build_admin_authority_v3_snapshot(
        artifact=artifact,
        provider=provider,
    )
    if not snapshot.chain_verified or snapshot.current_coin_id is None:
        raise ValueError("Authority V3 is not confirmed on Testnet11")
    intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
    if case["state"] in TERMINAL_CASE_STATES:
        raise GenesisConflict("administrator recovery case is terminal")
    if phase == "PREPARE":
        if snapshot.pending:
            raise ValueError("another Authority V3 key change is already pending")
    else:
        if (
            not snapshot.pending
            or snapshot.pending_intent_hash != case["intentHash"]
            or snapshot.pending_kind != intent.kind
            or snapshot.pending_slot != intent.slot
        ):
            raise ValueError(
                "Testnet11 pending Authority V3 state differs from this case"
            )

    authority = _genesis_authority_from_artifact(artifact)
    current_identities = _current_identity_vaults(
        artifact=artifact,
        evidence=evidence,
        store=store,
        authority=authority,
    )
    for slot, identity in enumerate(current_identities):
        chain_custody = _bytes32_hex(
            snapshot.identities[slot].custody_hash,
            f"identity {slot} chain custody",
        )
        if snapshot.pending and slot == intent.slot:
            if identity.custody_hash != _bytes32_hex(
                snapshot.pending_original_custody_hash,
                "pending original custody",
            ):
                raise ValueError(
                    "pending identity original custody differs from key history"
                )
        elif identity.custody_hash != chain_custody:
            raise ValueError(
                f"identity {slot} custody differs from completed key history"
            )

    authority_context, identity_context_values = await asyncio.gather(
        load_live_singleton_context(
            provider=provider,
            launcher_id=snapshot.launcher_id,
        ),
        asyncio.gather(
            *(
                load_live_singleton_context(
                    provider=provider,
                    launcher_id=identity.launcher_id,
                )
                for identity in snapshot.identities
            )
        ),
    )
    identity_contexts = tuple(identity_context_values)
    current_authority_inner = _authority_inner_from_snapshot(snapshot)
    _assert_full_puzzle_hash(
        context=authority_context,
        launcher_id=authority.authority_launcher_id,
        inner_puzzle=current_authority_inner,
        label="Authority V3",
    )

    if phase == "PREPARE":
        prior_authority_inner = current_authority_inner
        current_identity_coin_id = bytes32(
            identity_contexts[intent.slot].coin.name()
        )
    else:
        prior_state = AdminAuthorityV3State(
            current_identity_custody_hashes=tuple(
                identity.custody_hash for identity in current_identities
            ),  # type: ignore[arg-type]
            authority_version=snapshot.authority_version - 1,
        )
        prior_authority_inner = make_inner_puzzle(
            authority_puzzle_version=authority.authority_puzzle_version,
            authority_launcher_id=authority.authority_launcher_id,
            operational_root_hash=authority.operational_root_hash,
            lost_recovery_root_hashes=authority.lost_recovery_root_hashes,
            identity_launcher_ids=tuple(
                identity.launcher_id for identity in current_identities
            ),
            source_manifest_hash=authority.source_manifest_hash,
            state=prior_state,
        )
        current_identity_coin_id = bytes32(
            identity_contexts[intent.slot].coin.parent_coin_info
        )

    transition = build_identity_vault_transition(
        identity=current_identities[intent.slot],
        authority_current_inner_puzzle=prior_authority_inner,
        network="testnet11",
        kind=_pending_kind_value(intent.kind),
        intent_hash=_bytes32_hex(case["intentHash"], "intent hash"),
        current_identity_coin_id=current_identity_coin_id,
        replacement_daily_compressed_pubkey=bytes.fromhex(
            intent.new_daily_chia_key[2:]
        ),
        replacement_recovery_bls_pubkey=(
            bytes.fromhex(intent.new_recovery_bls_key[2:])
            if intent.kind == "RECOVERY_KIT"
            else None
        ),
    )
    if phase != "PREPARE":
        if (
            transition.intermediate_identity_coin_id
            != bytes32(identity_contexts[intent.slot].coin.name())
            or transition.intermediate_custody_hash
            != _bytes32_hex(
                snapshot.identities[intent.slot].custody_hash,
                "pending identity custody",
            )
            or bytes32(transition.authority_pending_inner_puzzle.get_tree_hash())
            != bytes32(current_authority_inner.get_tree_hash())
        ):
            raise ValueError(
                "pending Authority V3 transition does not reconstruct exactly"
            )

    for slot, context in enumerate(identity_contexts):
        inner = (
            transition.intermediate_custody_reveal
            if snapshot.pending and slot == intent.slot
            else current_identities[slot].custody_reveal
        )
        _assert_full_puzzle_hash(
            context=context,
            launcher_id=current_identities[slot].launcher_id,
            inner_puzzle=inner,
            label=f"Identity vault {slot}",
        )

    if intent.kind != "ROUTINE" and intent.kind != "RECOVERY_KIT":
        if coadmin_slot is not None:
            raise ValueError("lost-key recovery does not select a coadministrator")
        resolved_coadmin = None
    elif intent.slot == 0:
        if coadmin_slot not in (1, 2):
            raise ValueError(
                "owner key change requires administrator 2 or 3"
            )
        resolved_coadmin = coadmin_slot
    else:
        if coadmin_slot is not None and coadmin_slot != intent.slot:
            raise ValueError(
                "coadministrator key change uses that slot with the owner"
            )
        resolved_coadmin = intent.slot

    return _ChiaRecoveryBuild(
        artifact=artifact,
        evidence=evidence,
        case=case,
        intent=intent,
        snapshot=snapshot,
        authority=authority,
        current_authority_inner=current_authority_inner,
        current_identities=current_identities,
        authority_context=authority_context,
        identity_contexts=identity_contexts,  # type: ignore[arg-type]
        transition=transition,
        coadmin_slot=resolved_coadmin,
    )


def hash_admin_key_change_intent(intent: AdminKeyChangeIntentV1) -> str:
    kind_value = CHANGE_KIND_VALUES[intent.kind]
    encoded = abi_encode(
        [
            "bytes32",
            "uint8",
            "uint8",
            "address",
            "address",
            "bytes32",
            "bytes32",
            "address",
            "address",
            "bytes32",
            "bytes32",
            "bytes32[3]",
            "address[3]",
            "bytes32",
            "address",
            "address",
            "bytes32",
            "uint256",
            "bytes32",
            "uint256",
            "uint64",
            "uint64",
        ],
        [
            INTENT_TYPE_HASH,
            intent.slot,
            kind_value,
            intent.old_daily_evm_key,
            intent.new_daily_evm_key,
            keccak(bytes.fromhex(intent.old_daily_chia_key[2:])),
            keccak(bytes.fromhex(intent.new_daily_chia_key[2:])),
            intent.old_recovery_guardian,
            intent.new_recovery_guardian,
            keccak(bytes.fromhex(intent.old_recovery_bls_key[2:])),
            keccak(bytes.fromhex(intent.new_recovery_bls_key[2:])),
            [bytes.fromhex(value[2:]) for value in intent.identity_launcher_ids],
            intent.identity_safes,
            bytes.fromhex(intent.authority_launcher_id[2:]),
            intent.coadmin_safe,
            intent.root_safe,
            keccak(text=intent.chia_network),
            intent.evm_chain_id,
            bytes.fromhex(intent.source_manifest_hash[2:]),
            intent.nonce,
            intent.expires_at,
            intent.recovery_key_revision,
        ],
    )
    return "0x" + keccak(encoded).hex()


def _intent_tuple(intent: AdminKeyChangeIntentV1) -> tuple[Any, ...]:
    return (
        intent.slot,
        CHANGE_KIND_VALUES[intent.kind],
        intent.old_daily_evm_key,
        intent.new_daily_evm_key,
        bytes.fromhex(intent.old_daily_chia_key[2:]),
        bytes.fromhex(intent.new_daily_chia_key[2:]),
        intent.old_recovery_guardian,
        intent.new_recovery_guardian,
        bytes.fromhex(intent.old_recovery_bls_key[2:]),
        bytes.fromhex(intent.new_recovery_bls_key[2:]),
        [bytes.fromhex(value[2:]) for value in intent.identity_launcher_ids],
        intent.identity_safes,
        bytes.fromhex(intent.authority_launcher_id[2:]),
        intent.coadmin_safe,
        intent.root_safe,
        intent.chia_network,
        intent.evm_chain_id,
        bytes.fromhex(intent.source_manifest_hash[2:]),
        intent.nonce,
        intent.expires_at,
        intent.recovery_key_revision,
    )


def _function_data(signature: str, abi_types: list[str], values: list[Any]) -> str:
    selector = keccak(text=signature)[:4]
    return "0x" + (selector + abi_encode(abi_types, values)).hex()


def prepare_key_change_calldata(intent: AdminKeyChangeIntentV1) -> str:
    function_name = (
        "prepareRoutine"
        if intent.kind == "ROUTINE"
        else (
            "prepareLostKey"
            if intent.kind == "LOST"
            else "prepareRecoveryKit"
        )
    )
    signature = f"{function_name}({INTENT_TUPLE_ABI})"
    return _function_data(
        signature,
        [INTENT_TUPLE_ABI],
        [_intent_tuple(intent)],
    )


def lost_key_authorization_typed_data(
    intent_hash: str,
    coordinator: str,
) -> dict[str, Any]:
    normalized_hash = _hex_value(intent_hash, 64, "intentHash")
    verifying_contract = normalize_evm_address(
        coordinator,
        "recovery coordinator",
    )
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            LOST_KEY_AUTHORIZATION_PRIMARY_TYPE: [
                {"name": "intentHash", "type": "bytes32"},
            ],
        },
        "primaryType": LOST_KEY_AUTHORIZATION_PRIMARY_TYPE,
        "domain": {
            **LOST_KEY_AUTHORIZATION_DOMAIN,
            "chainId": AUTHORITY_EVM_CHAIN_ID,
            "verifyingContract": verifying_contract,
        },
        "message": {"intentHash": normalized_hash},
    }


def prepare_lost_key_with_signature_calldata(
    intent: AdminKeyChangeIntentV1,
    guardian_signature: str,
) -> str:
    if intent.kind != "LOST":
        raise ValueError(
            "guardian relay authorization is only valid for lost-key recovery"
        )
    normalized_signature = _hex_value(
        guardian_signature,
        130,
        "guardianSignature",
    )
    return _function_data(
        f"prepareLostKeyWithSignature({INTENT_TUPLE_ABI},bytes)",
        [INTENT_TUPLE_ABI, "bytes"],
        [
            _intent_tuple(intent),
            bytes.fromhex(normalized_signature[2:]),
        ],
    )


def verify_lost_guardian_authorization(
    *,
    intent: AdminKeyChangeIntentV1,
    coordinator: str,
    guardian_signature: str,
) -> str:
    if intent.kind != "LOST":
        raise ValueError(
            "guardian authorization is only valid for lost-key recovery"
        )
    typed_data = lost_key_authorization_typed_data(
        hash_admin_key_change_intent(intent),
        coordinator,
    )
    recovered = recover_evm_signer(typed_data, guardian_signature)
    expected = normalize_evm_address(
        intent.old_recovery_guardian,
        "recovery guardian",
    )
    if recovered.address.lower() != expected.lower():
        raise ValueError(
            "lost-key authorization was not signed by the enrolled guardian"
        )
    return recovered.address


def recovery_guardian_action_typed_data(
    intent_hash: str,
    coordinator: str,
    action: Literal["ACCEPT", "VETO"],
) -> dict[str, Any]:
    normalized_hash = _hex_value(intent_hash, 64, "intentHash")
    verifying_contract = normalize_evm_address(
        coordinator,
        "recovery coordinator",
    )
    primary_type = RECOVERY_GUARDIAN_ACTION_PRIMARY_TYPES[action]
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            primary_type: [
                {"name": "intentHash", "type": "bytes32"},
            ],
        },
        "primaryType": primary_type,
        "domain": {
            **LOST_KEY_AUTHORIZATION_DOMAIN,
            "chainId": AUTHORITY_EVM_CHAIN_ID,
            "verifyingContract": verifying_contract,
        },
        "message": {"intentHash": normalized_hash},
    }


def verify_recovery_guardian_action_authorization(
    *,
    intent: AdminKeyChangeIntentV1,
    coordinator: str,
    action: Literal["ACCEPT", "VETO"],
    guardian_signature: str,
) -> str:
    if intent.kind != "RECOVERY_KIT":
        raise ValueError(
            "offline recovery-guardian actions require a recovery-kit change"
        )
    typed_data = recovery_guardian_action_typed_data(
        hash_admin_key_change_intent(intent),
        coordinator,
        action,
    )
    recovered = recover_evm_signer(typed_data, guardian_signature)
    expected = normalize_evm_address(
        (
            intent.new_recovery_guardian
            if action == "ACCEPT"
            else intent.old_recovery_guardian
        ),
        "recovery guardian",
    )
    if recovered.address.lower() != expected.lower():
        raise ValueError(
            "offline recovery-guardian authorization has the wrong signer"
        )
    return recovered.address


def recovery_guardian_action_with_signature_calldata(
    intent_hash: str,
    action: Literal["ACCEPT", "VETO"],
    guardian_signature: str,
) -> str:
    normalized_hash = _hex_value(intent_hash, 64, "intentHash")
    normalized_signature = _hex_value(
        guardian_signature,
        130,
        "guardianSignature",
    )
    function_name = (
        "acceptRecoveryGuardianWithSignature"
        if action == "ACCEPT"
        else "vetoByOldRecoveryGuardianWithSignature"
    )
    return _function_data(
        f"{function_name}(bytes32,bytes)",
        ["bytes32", "bytes"],
        [
            bytes.fromhex(normalized_hash[2:]),
            bytes.fromhex(normalized_signature[2:]),
        ],
    )


def _verify_recovery_guardian_transaction(
    *,
    transaction: Mapping[str, Any],
    intent: AdminKeyChangeIntentV1,
    coordinator: str,
    action: Literal["ACCEPT", "VETO"],
) -> tuple[str, str, str]:
    intent_hash = hash_admin_key_change_intent(intent)
    expected_guardian = normalize_evm_address(
        (
            intent.new_recovery_guardian
            if action == "ACCEPT"
            else intent.old_recovery_guardian
        ),
        "recovery guardian",
    )
    sender = normalize_evm_address(
        transaction.get("from"),
        "recovery action gas payer",
    )
    if (
        normalize_evm_address(
            transaction.get("to"),
            "recovery action destination",
        ).lower()
        != normalize_evm_address(
            coordinator,
            "recovery coordinator",
        ).lower()
        or _rpc_integer(
            transaction.get("value") or "0x0",
            "recovery action value",
        )
        != 0
    ):
        raise ValueError(
            "offline recovery-guardian transaction changed its destination or value"
        )
    transaction_data = str(
        transaction.get("input") or transaction.get("data") or ""
    ).lower()
    direct_function = (
        "acceptRecoveryGuardian"
        if action == "ACCEPT"
        else "vetoByOldRecoveryGuardian"
    )
    if transaction_data == _bytes32_calldata(
        direct_function,
        intent_hash,
    ).lower():
        if sender.lower() != expected_guardian.lower():
            raise ValueError(
                "direct recovery-guardian action was not sent by the guardian"
            )
        return expected_guardian, sender, "DIRECT_GUARDIAN"

    relay_function = (
        "acceptRecoveryGuardianWithSignature"
        if action == "ACCEPT"
        else "vetoByOldRecoveryGuardianWithSignature"
    )
    expected_selector = (
        "0x" + keccak(text=f"{relay_function}(bytes32,bytes)")[:4].hex()
    )
    if not transaction_data.startswith(expected_selector):
        raise ValueError(
            "offline recovery-guardian transaction uses an unknown function"
        )
    try:
        relayed_hash, raw_signature = abi_decode(
            ["bytes32", "bytes"],
            bytes.fromhex(transaction_data[10:]),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "offline recovery-guardian relay calldata is malformed"
        ) from exc
    if "0x" + bytes(relayed_hash).hex() != intent_hash:
        raise ValueError(
            "offline recovery-guardian relay targets a different intent"
        )
    guardian_signature = "0x" + bytes(raw_signature).hex()
    signer = verify_recovery_guardian_action_authorization(
        intent=intent,
        coordinator=coordinator,
        action=action,
        guardian_signature=guardian_signature,
    )
    if transaction_data != recovery_guardian_action_with_signature_calldata(
        intent_hash,
        action,
        guardian_signature,
    ).lower():
        raise ValueError(
            "offline recovery-guardian relay calldata is not canonical"
        )
    return signer, sender, "OFFLINE_GUARDIAN_RELAY"


def recovery_intent_bls_digest(intent_hash: str) -> bytes:
    intent = bytes.fromhex(_hex_value(intent_hash, 64, "intentHash")[2:])

    def atom_hash(value: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + value).digest()

    def pair_hash(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x02" + left + right).digest()

    message = pair_hash(
        atom_hash(b"SolslotAdminKeyChangeIntentV1"),
        atom_hash(intent),
    )
    return pair_hash(atom_hash(b"Chia Signed Message"), atom_hash(message))


async def _rpc(settings: Settings, method: str, params: list[Any]) -> Any:
    if not settings.authority_v3_evm_rpc_url:
        raise ValueError("Authority V3 Base Sepolia RPC is unavailable")
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            settings.authority_v3_evm_rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            },
        )
    response.raise_for_status()
    payload = response.json()
    if payload.get("error") or "result" not in payload:
        raise ValueError(f"Authority V3 RPC {method} failed")
    return payload["result"]


async def _call_uint(
    settings: Settings,
    contract: str,
    function_signature: str,
) -> int:
    result = await _rpc(
        settings,
        "eth_call",
        [
            {
                "to": contract,
                "data": "0x" + keccak(text=function_signature)[:4].hex(),
            },
            "latest",
        ],
    )
    return int(str(result), 16)


async def _verified_evidence_context(
    settings: Settings,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    artifact = load_signed_public_artifact(settings)
    evidence = load_governance_evidence(settings)
    authority = artifact["adminAuthority"]
    chia = evidence["chiaAuthority"]
    if (
        authority.get("version") != 3
        or str(chia.get("authorityLauncherId")).lower()
        != str(artifact["launcherIds"]["adminAuthority"]).lower()
        or str(chia.get("sourceManifestHash")).lower()
        != str(authority.get("sourceManifestHash")).lower()
        or [str(value).lower() for value in chia.get("identityLauncherIds", [])]
        != [
            str(item["launcherId"]).lower()
            for item in authority.get("identityVaults", [])
        ]
    ):
        raise ValueError("Authority V3 Chia and EVM evidence do not match")
    coordinator = normalize_evm_address(
        evidence["recovery"]["address"],
        "recovery coordinator",
    )
    expected_code_hash = str(evidence["runtimeCodeHashes"]["recovery"]).lower()
    code = await _rpc(settings, "eth_getCode", [coordinator, "latest"])
    if "0x" + keccak(bytes.fromhex(str(code)[2:])).hex() != expected_code_hash:
        raise ValueError("Authority V3 recovery runtime code hash changed")
    chain_id = int(str(await _rpc(settings, "eth_chainId", [])), 16)
    if chain_id != AUTHORITY_EVM_CHAIN_ID:
        raise ValueError("Authority V3 RPC is on the wrong EVM network")
    return artifact, evidence, coordinator


async def _verified_context(
    settings: Settings,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    artifact, evidence, coordinator = await _verified_evidence_context(
        settings
    )
    if await _call_uint(settings, coordinator, "isChangeActive()") != 0:
        raise GenesisConflict("another administrator key change is active")
    nonce = await _call_uint(settings, coordinator, "changeNonce()")
    return artifact, evidence, nonce


def _new_daily_identity(compressed: str) -> tuple[str, str]:
    from eth_keys import keys as eth_keys

    normalized = _hex_value(compressed, 66, "new daily key")
    try:
        address = eth_keys.PublicKey.from_compressed_bytes(
            bytes.fromhex(normalized[2:])
        ).to_checksum_address()
    except (TypeError, ValueError) as exc:
        raise ValueError("new daily key is invalid") from exc
    return normalized, address


def _build_intent(
    *,
    artifact: Mapping[str, Any],
    evidence: Mapping[str, Any],
    slot: int,
    kind: Literal["ROUTINE", "LOST", "RECOVERY_KIT"],
    new_daily_compressed_pubkey: str | None,
    nonce: int,
    now: int,
    administrators: list[tuple[str, str]] | None = None,
    recovery_identities: list[dict[str, Any]] | None = None,
    new_recovery_guardian: str | None = None,
    new_recovery_bls_key: str | None = None,
) -> AdminKeyChangeIntentV1:
    administrators = administrators or artifact_admins(artifact)
    old_evm, old_chia = administrators[slot]
    safes = evidence["safes"]
    recovery_records = (
        recovery_identities or evidence["recovery"]["identities"]
    )
    if (
        not isinstance(recovery_records, list)
        or len(recovery_records) != 3
        or [item.get("slot") for item in recovery_records] != [0, 1, 2]
    ):
        raise ValueError("Authority V3 recovery roster is malformed")
    recovery = recovery_records[slot]
    old_recovery_guardian = normalize_evm_address(
        recovery["evmGuardian"],
        "current recovery guardian",
    )
    old_recovery_bls_key = _hex_value(
        recovery["blsPubkey"],
        96,
        "current recovery BLS key",
    )
    if kind == "RECOVERY_KIT":
        new_evm = old_evm
        new_chia = old_chia
        if new_recovery_guardian is None or new_recovery_bls_key is None:
            raise ValueError("replacement recovery identities are required")
        next_guardian = normalize_evm_address(
            new_recovery_guardian,
            "replacement recovery guardian",
        )
        next_bls_key = _hex_value(
            new_recovery_bls_key,
            96,
            "replacement recovery BLS key",
        )
        if next_guardian.lower() == old_recovery_guardian.lower():
            raise ValueError("replacement recovery guardian must be new")
        if next_bls_key.lower() == old_recovery_bls_key.lower():
            raise ValueError("replacement recovery BLS key must be new")
        for administrator, _compressed in administrators:
            if next_guardian.lower() == administrator.lower():
                raise ValueError(
                    "recovery guardian must remain separate from daily wallets"
                )
        for record in recovery_records:
            if (
                int(record["slot"]) != slot
                and (
                    next_guardian.lower()
                    == str(record["evmGuardian"]).lower()
                    or next_bls_key.lower()
                    == str(record["blsPubkey"]).lower()
                )
            ):
                raise ValueError(
                    "replacement recovery identity is already assigned"
                )
    else:
        if new_daily_compressed_pubkey is None:
            raise ValueError("replacement daily key is required")
        new_chia, new_evm = _new_daily_identity(
            new_daily_compressed_pubkey
        )
        if new_evm.lower() in {
            address.lower() for address, _compressed in administrators
        }:
            raise ValueError(
                "replacement daily wallet is already an administrator"
            )
        next_guardian = old_recovery_guardian
        next_bls_key = old_recovery_bls_key
    delay = (
        LOST_DELAY_SECONDS
        if kind == "LOST"
        else ROUTINE_DELAY_SECONDS
    )
    return AdminKeyChangeIntentV1(
        slot=slot,
        kind=kind,
        oldDailyEvmKey=old_evm,
        newDailyEvmKey=new_evm,
        oldDailyChiaKey=old_chia,
        newDailyChiaKey=new_chia,
        oldRecoveryGuardian=old_recovery_guardian,
        newRecoveryGuardian=next_guardian,
        oldRecoveryBlsKey=old_recovery_bls_key,
        newRecoveryBlsKey=next_bls_key,
        identityLauncherIds=evidence["chiaAuthority"]["identityLauncherIds"],
        identitySafes=[
            item["address"] for item in safes["identities"]
        ],
        authorityLauncherId=evidence["chiaAuthority"]["authorityLauncherId"],
        coadminSafe=safes["coadmin"]["address"],
        rootSafe=safes["root"]["address"],
        sourceManifestHash=evidence["chiaAuthority"]["sourceManifestHash"],
        nonce=nonce + 1,
        expiresAt=now + delay + EXECUTION_WINDOW_SECONDS,
        recoveryKeyRevision=int(recovery["revision"]),
    )


def _prepared_response(
    intent: AdminKeyChangeIntentV1,
    evidence: Mapping[str, Any],
) -> PreparedKeyChange:
    intent_hash = hash_admin_key_change_intent(intent)
    coordinator = normalize_evm_address(
        evidence["recovery"]["address"],
        "recovery coordinator",
    )
    return PreparedKeyChange(
        intent=intent,
        intentHash=intent_hash,
        coordinator=coordinator,
        prepareTransaction={
            "chainId": AUTHORITY_EVM_CHAIN_ID,
            "to": coordinator,
            "value": "0x0",
            "data": prepare_key_change_calldata(intent),
        },
        clearSigning={
            "title": (
                "Rotate administrator wallet"
                if intent.kind == "ROUTINE"
                else (
                    "Recover lost administrator wallet"
                    if intent.kind == "LOST"
                    else "Replace administrator recovery kit"
                )
            ),
            "slot": intent.slot,
            "oldWallet": intent.old_daily_evm_key,
            "newWallet": intent.new_daily_evm_key,
            "oldRecoveryGuardian": intent.old_recovery_guardian,
            "newRecoveryGuardian": intent.new_recovery_guardian,
            "financialEffect": "No funds move.",
            "authorityEffect": (
                "The replacement controls this administrator identity only "
                "after both chains match."
            ),
            "delaySeconds": (
                LOST_DELAY_SECONDS
                if intent.kind == "LOST"
                else ROUTINE_DELAY_SECONDS
            ),
            "expiresAt": intent.expires_at,
            "operationsFreeze": True,
            "oldKeyCanVeto": True,
        },
        recoveryBlsDigest=(
            "0x" + recovery_intent_bls_digest(intent_hash).hex()
            if intent.kind == "LOST"
            else None
        ),
        guardianTypedData=(
            lost_key_authorization_typed_data(
                intent_hash,
                coordinator,
            )
            if intent.kind == "LOST"
            else None
        ),
    )


def _bytes32_calldata(function_name: str, value: str) -> str:
    normalized = _hex_value(value, 64, "intentHash")
    return _function_data(
        f"{function_name}(bytes32)",
        ["bytes32"],
        [bytes.fromhex(normalized[2:])],
    )


def _canonical_receipt_hash(receipt: Mapping[str, Any]) -> str:
    payload = json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(payload).hexdigest()


def _rpc_integer(value: object, label: str) -> int:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is malformed") from exc


async def _confirmed_evm_transaction(
    settings: Settings,
    transaction_hash: str,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    transaction_hash = _hex_value(
        transaction_hash,
        64,
        "transactionHash",
    )
    transaction = await _rpc(
        settings,
        "eth_getTransactionByHash",
        [transaction_hash],
    )
    receipt = await _rpc(
        settings,
        "eth_getTransactionReceipt",
        [transaction_hash],
    )
    if not isinstance(transaction, dict) or not isinstance(receipt, dict):
        raise ValueError(
            "Authority V3 transaction is not confirmed on Base Sepolia"
        )
    if _rpc_integer(receipt.get("status"), "transaction status") != 1:
        raise ValueError("Authority V3 transaction reverted")
    block_number = _rpc_integer(
        receipt.get("blockNumber"),
        "transaction block",
    )
    latest = _rpc_integer(
        await _rpc(settings, "eth_blockNumber", []),
        "latest EVM block",
    )
    confirmations = latest - block_number + 1
    if confirmations < settings.authority_v3_evm_min_confirmations:
        raise ValueError(
            "Authority V3 transaction is waiting for Base Sepolia confirmations"
        )
    return transaction, receipt, confirmations


def _receipt_event(
    receipt: Mapping[str, Any],
    *,
    coordinator: str,
    event_name: str,
    intent_hash: str,
) -> Mapping[str, Any]:
    expected_topic = EVENT_TOPICS[event_name]
    expected_intent = _hex_value(
        intent_hash,
        64,
        "intentHash",
    )
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise ValueError("Authority V3 receipt logs are malformed")
    matching = []
    for item in logs:
        if not isinstance(item, Mapping):
            continue
        topics = item.get("topics")
        if (
            str(item.get("address") or "").lower() != coordinator.lower()
            or not isinstance(topics, list)
            or len(topics) < 2
            or str(topics[0]).lower() != expected_topic
            or str(topics[1]).lower() != expected_intent
        ):
            continue
        matching.append(item)
    if len(matching) != 1:
        raise ValueError(
            f"Authority V3 {event_name} event is missing or ambiguous"
        )
    return matching[0]


async def _block_timestamp(
    settings: Settings,
    block_number: int,
) -> int:
    block = await _rpc(
        settings,
        "eth_getBlockByNumber",
        [hex(block_number), False],
    )
    if not isinstance(block, Mapping):
        raise ValueError("Authority V3 EVM block is unavailable")
    return _rpc_integer(block.get("timestamp"), "transaction timestamp")


def _validate_intent_bindings(
    *,
    intent: AdminKeyChangeIntentV1,
    artifact: Mapping[str, Any],
    evidence: Mapping[str, Any],
    store: GenesisStore,
) -> None:
    delay = (
        LOST_DELAY_SECONDS
        if intent.kind == "LOST"
        else ROUTINE_DELAY_SECONDS
    )
    prepared_at = (
        intent.expires_at - delay - EXECUTION_WINDOW_SECONDS
    )
    expected = _build_intent(
        artifact=artifact,
        evidence=evidence,
        slot=intent.slot,
        kind=intent.kind,
        new_daily_compressed_pubkey=(
            None
            if intent.kind == "RECOVERY_KIT"
            else intent.new_daily_chia_key
        ),
        nonce=intent.nonce - 1,
        now=prepared_at,
        administrators=_current_administrators(artifact, store),
        recovery_identities=_current_recovery_identities(
            artifact,
            evidence,
            store,
        ),
        new_recovery_guardian=(
            intent.new_recovery_guardian
            if intent.kind == "RECOVERY_KIT"
            else None
        ),
        new_recovery_bls_key=(
            intent.new_recovery_bls_key
            if intent.kind == "RECOVERY_KIT"
            else None
        ),
    )
    if expected.model_dump(by_alias=True) != intent.model_dump(by_alias=True):
        raise ValueError(
            "administrator key-change intent differs from live authority evidence"
        )


def _prepared_event_fields(
    event: Mapping[str, Any],
) -> tuple[int, int, str, str, int]:
    topics = event.get("topics")
    if not isinstance(topics, list) or len(topics) != 3:
        raise ValueError("Authority V3 prepared event topics are malformed")
    slot = _rpc_integer(topics[2], "prepared slot")
    try:
        kind, old_key, new_key, execute_after = abi_decode(
            ["uint8", "address", "address", "uint64"],
            bytes.fromhex(str(event.get("data") or "0x")[2:]),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Authority V3 prepared event data is malformed"
        ) from exc
    return (
        slot,
        int(kind),
        normalize_evm_address(old_key, "prepared old wallet"),
        normalize_evm_address(new_key, "prepared replacement wallet"),
        int(execute_after),
    )


def _notify_administrators(
    store: GenesisStore,
    ceremony_id: str,
    *,
    event_type: str,
    subject: str,
    body: str,
) -> None:
    for profile in store.profiles(ceremony_id).values():
        recipient = profile.get("email")
        if (
            recipient
            and profile.get("remindersEnabled")
            and isinstance(recipient, str)
        ):
            store.enqueue_admin_notification(
                ceremony_id,
                event_type=event_type,
                recipient=recipient,
                subject=subject,
                body=body,
            )


def _case_has_receipt(
    case: Mapping[str, Any],
    chain: str,
    phase: str,
) -> bool:
    return any(
        item["chain"] == chain and item["phase"] == phase
        for item in case["receipts"]
    )


def _case_has_approval(
    case: Mapping[str, Any],
    role: str,
    *,
    signer_slot: int | None = None,
) -> bool:
    return any(
        item["actorRole"] == role
        and (
            signer_slot is None
            or item.get("signerSlot") == signer_slot
        )
        for item in case["approvals"]
    )


def _required_peer_slots(slot: int) -> tuple[int, int]:
    return tuple(  # type: ignore[return-value]
        candidate for candidate in range(3) if candidate != slot
    )


def _approvals_complete(case: Mapping[str, Any]) -> bool:
    if not _case_has_approval(case, "REPLACEMENT"):
        return False
    if case["kind"] in {"ROUTINE", "RECOVERY_KIT"}:
        return _case_has_approval(case, "AUTHORITY")
    return all(
        _case_has_approval(case, "PEER", signer_slot=slot)
        for slot in _required_peer_slots(int(case["slot"]))
    )


def _refresh_case_state(
    store: GenesisStore,
    case: Mapping[str, Any],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    if case["state"] in TERMINAL_CASE_STATES or case["state"] == "PARTIAL":
        return dict(case)
    timestamp = int(time.time()) if now is None else now
    if timestamp > int(case["expiresAt"]):
        failed = store.update_recovery_case(
            str(case["caseId"]),
            state="FAILED",
            failure_reason="Administrator key-change intent expired.",
            now=timestamp,
        )
        if case["kind"] == "RECOVERY_KIT":
            candidate = store.pending_recovery_kit_candidate(
                str(case["ceremonyId"]),
                int(case["slot"]) + 1,
            )
            if candidate is not None:
                store.cancel_recovery_kit_candidate(
                    str(candidate["challengeId"]),
                    now=timestamp,
                )
        return failed
    chia_prepared = _case_has_receipt(case, "CHIA", "PREPARE")
    if (
        chia_prepared
        and _approvals_complete(case)
        and timestamp >= int(case["executeAfter"])
    ):
        state = "READY"
    elif chia_prepared or case.get("chiaTransactionId"):
        state = "SUBMITTED"
    else:
        state = "AWAITING_APPROVALS"
    if state == case["state"]:
        return dict(case)
    return store.update_recovery_case(
        str(case["caseId"]),
        state=state,
        now=timestamp,
    )


def _topic_address(value: object, label: str) -> str:
    normalized = str(value or "").lower()
    if not normalized.startswith("0x") or len(normalized) != 66:
        raise ValueError(f"{label} topic is malformed")
    return normalize_evm_address(
        "0x" + normalized[-40:],
        label,
    )


def _topic_uint(value: object, label: str) -> int:
    return _rpc_integer(value, label)


def _event_for_case(
    receipt: Mapping[str, Any],
    *,
    coordinator: str,
    intent_hash: str,
) -> tuple[str, Mapping[str, Any]]:
    found: list[tuple[str, Mapping[str, Any]]] = []
    for name in (
        "authorityApproved",
        "peerApproved",
        "replacementAccepted",
        "recoveryGuardianAccepted",
        "vetoed",
        "peerCancellation",
        "evmChanged",
        "converged",
        "rolledBack",
        "rollbackApproved",
        "recoveryKitChanged",
        "chiaCancellationRecorded",
    ):
        try:
            found.append(
                (
                    name,
                    _receipt_event(
                        receipt,
                        coordinator=coordinator,
                        event_name=name,
                        intent_hash=intent_hash,
                    ),
                )
            )
        except ValueError:
            continue
    terminal = [
        item
        for item in found
        if item[0]
        in {
            "vetoed",
            "evmChanged",
            "recoveryKitChanged",
            "converged",
            "rolledBack",
        }
    ]
    if len(terminal) == 1:
        return terminal[0]
    if {name for name, _event in found} == {
        "rollbackApproved",
        "chiaCancellationRecorded",
    }:
        return next(item for item in found if item[0] == "rollbackApproved")
    if len(found) != 1:
        raise ValueError(
            "transaction does not contain one recognized Authority V3 action"
        )
    return found[0]


def _record_receipt_once(
    store: GenesisStore,
    case: Mapping[str, Any],
    *,
    chain: str,
    phase: str,
    transaction_id: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    existing = next(
        (
            item
            for item in case["receipts"]
            if item["chain"] == chain and item["phase"] == phase
        ),
        None,
    )
    receipt_hash = _canonical_receipt_hash(receipt)
    if existing:
        if (
            existing["transactionId"].lower() != transaction_id.lower()
            or existing["receiptHash"].lower() != receipt_hash.lower()
        ):
            raise GenesisConflict(
                f"{chain} {phase.lower()} receipt conflicts with recorded evidence"
            )
        return dict(case)
    return store.add_recovery_receipt(
        str(case["caseId"]),
        chain=chain,
        phase=phase,
        transaction_id=transaction_id,
        receipt_hash=receipt_hash,
        receipt=receipt,
    )


def _record_approval_once(
    store: GenesisStore,
    case: Mapping[str, Any],
    *,
    role: str,
    actor_id: str,
    signer_slot: int | None,
    signer_address: str,
    transaction_hash: str,
) -> dict[str, Any]:
    existing = next(
        (
            item
            for item in case["approvals"]
            if item["actorRole"] == role and item["actorId"] == actor_id
        ),
        None,
    )
    if existing:
        if (
            existing["signerAddress"].lower() != signer_address.lower()
            or existing["messageHash"].lower()
            != str(case["intentHash"]).lower()
        ):
            raise GenesisConflict(
                "administrator approval conflicts with recorded evidence"
            )
        return dict(case)
    return store.add_recovery_approval(
        str(case["caseId"]),
        actor_role=role,
        actor_id=actor_id,
        signer_slot=signer_slot,
        signer_address=signer_address,
        signature=transaction_hash,
        message_hash=str(case["intentHash"]),
    )


def _case_actions(
    case: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if case["state"] in TERMINAL_CASE_STATES:
        return []
    intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
    coordinator = normalize_evm_address(
        evidence["recovery"]["address"],
        "recovery coordinator",
    )
    safes = evidence["safes"]
    actions: list[dict[str, Any]] = []

    def add(
        action_id: str,
        title: str,
        function_name: str,
        *,
        signer: str,
        execution: Literal[
            "WALLET",
            "SAFE",
            "PERMISSIONLESS",
            "OFFLINE_RELAY",
        ],
        typed_data: dict[str, Any] | None = None,
        authorization_action: Literal["ACCEPT", "VETO"] | None = None,
    ) -> None:
        actions.append(
            {
                "actionId": action_id,
                "title": title,
                "network": "Base Sepolia",
                "financialEffect": "No funds move.",
                "to": coordinator,
                "value": "0",
                "data": _bytes32_calldata(
                    function_name,
                    str(case["intentHash"]),
                ),
                "signer": signer,
                "execution": execution,
                "typedData": typed_data,
                "authorizationAction": authorization_action,
            }
        )

    if intent.kind in {"ROUTINE", "RECOVERY_KIT"} and not _case_has_approval(
        case,
        "AUTHORITY",
    ):
        add(
            "authority-approval",
            (
                "Approve this recovery-kit replacement"
                if intent.kind == "RECOVERY_KIT"
                else "Approve this wallet rotation"
            ),
            (
                "approveRecoveryKitByRoot"
                if intent.kind == "RECOVERY_KIT"
                else "approveRoutineByRoot"
            ),
            signer=safes["root"]["address"],
            execution="SAFE",
        )
    if intent.kind == "LOST":
        for peer_slot in _required_peer_slots(intent.slot):
            if not _case_has_approval(
                case,
                "PEER",
                signer_slot=peer_slot,
            ):
                add(
                    f"peer-{peer_slot}-approval",
                    f"Administrator {peer_slot + 1} approves recovery",
                    "approveLostKeyByPeer",
                    signer=safes["identities"][peer_slot]["address"],
                    execution="SAFE",
                )
    if not _case_has_approval(case, "REPLACEMENT"):
        if intent.kind == "RECOVERY_KIT":
            add(
                "replacement-acceptance",
                "Approve the new recovery kit offline",
                "acceptRecoveryGuardian",
                signer=intent.new_recovery_guardian,
                execution="OFFLINE_RELAY",
                typed_data=recovery_guardian_action_typed_data(
                    str(case["intentHash"]),
                    coordinator,
                    "ACCEPT",
                ),
                authorization_action="ACCEPT",
            )
        else:
            add(
                "replacement-acceptance",
                "Accept control with the replacement wallet",
                "acceptReplacement",
                signer=intent.new_daily_evm_key,
                execution="WALLET",
            )
    add(
        "old-key-veto",
        "Cancel with the current daily wallet",
        "vetoByOldKey",
        signer=intent.old_daily_evm_key,
        execution="WALLET",
    )
    if intent.kind == "RECOVERY_KIT":
        add(
            "old-recovery-veto",
            "Cancel with the current recovery kit",
            "vetoByOldRecoveryGuardian",
            signer=intent.old_recovery_guardian,
            execution="OFFLINE_RELAY",
            typed_data=recovery_guardian_action_typed_data(
                str(case["intentHash"]),
                coordinator,
                "VETO",
            ),
            authorization_action="VETO",
        )
    if intent.kind == "ROUTINE":
        add(
            "authority-cancel",
            "Cancel this rotation as the authority",
            "cancelRoutineByRoot",
            signer=safes["root"]["address"],
            execution="SAFE",
        )
    elif intent.kind == "LOST":
        for peer_slot in _required_peer_slots(intent.slot):
            add(
                f"peer-{peer_slot}-cancel",
                f"Administrator {peer_slot + 1} cancels recovery",
                "cancelLostKeyByPeer",
                signer=safes["identities"][peer_slot]["address"],
                execution="SAFE",
            )
    else:
        add(
            "authority-cancel",
            "Cancel this recovery-kit replacement",
            "cancelRecoveryKitByRoot",
            signer=safes["root"]["address"],
            execution="SAFE",
        )
    if (
        case["state"] == "READY"
        and not _case_has_receipt(case, "EVM", "EXECUTE")
    ):
        add(
            "execute-evm",
            "Apply the approved EVM wallet change",
            "executeEvmKeyChange",
            signer="Any wallet",
            execution="PERMISSIONLESS",
        )
    if (
        _case_has_receipt(case, "CHIA", "COMPLETE")
        and _case_has_receipt(case, "EVM", "EXECUTE")
        and not _case_has_receipt(case, "EVM", "COMPLETE")
    ):
        chia_receipt = next(
            item
            for item in case["receipts"]
            if item["chain"] == "CHIA" and item["phase"] == "COMPLETE"
        )
        actions.append(
            {
                "actionId": "confirm-convergence",
                "title": "Confirm both chains now match",
                "network": "Base Sepolia",
                "financialEffect": "No funds move.",
                "to": coordinator,
                "value": "0",
                "data": _function_data(
                    "confirmCrossChainConvergence(bytes32,bytes32)",
                    ["bytes32", "bytes32"],
                    [
                        bytes.fromhex(str(case["intentHash"])[2:]),
                        bytes.fromhex(chia_receipt["receiptHash"][2:]),
                    ],
                ),
                "signer": safes["root"]["address"],
                "execution": "SAFE",
            }
        )
    if (
        _case_has_receipt(case, "EVM", "EXECUTE")
        and _case_has_receipt(case, "CHIA", "CANCEL")
        and not _case_has_receipt(case, "EVM", "ROLLBACK")
    ):
        rollback_ids = {
            item["actorId"] for item in case["approvals"]
        }
        if "rollback-root" not in rollback_ids:
            chia_cancellation = next(
                item
                for item in case["receipts"]
                if item["chain"] == "CHIA"
                and item["phase"] == "CANCEL"
            )
            actions.append(
                {
                    "actionId": "rollback-authority-approval",
                    "title": "Approve restoring the previous EVM identity",
                    "network": "Base Sepolia",
                    "financialEffect": "No funds move.",
                    "to": coordinator,
                    "value": "0",
                    "data": _function_data(
                        "approveRollbackByRoot(bytes32,bytes32)",
                        ["bytes32", "bytes32"],
                        [
                            bytes.fromhex(str(case["intentHash"])[2:]),
                            bytes.fromhex(
                                str(chia_cancellation["receiptHash"])[2:]
                            ),
                        ],
                    ),
                    "signer": safes["root"]["address"],
                    "execution": "SAFE",
                }
            )
        if "rollback-root" in rollback_ids:
            add(
                "execute-rollback",
                "Restore the previous EVM wallet",
                "executeRollback",
                signer="Any wallet",
                execution="PERMISSIONLESS",
            )
    return actions


def _safe_typed_data_preimage(typed_data: Mapping[str, Any]) -> bytes:
    try:
        signable = encode_typed_data(full_message=dict(typed_data))
    except (TypeError, ValueError) as exc:
        raise ValueError("Authority V3 Safe signing data is invalid") from exc
    return b"\x19" + bytes(signable.version) + signable.header + signable.body


def _safe_typed_data_digest(typed_data: Mapping[str, Any]) -> str:
    return "0x" + keccak(_safe_typed_data_preimage(typed_data)).hex()


def _normalize_safe_eoa_signature(signature: str) -> bytes:
    normalized = _hex_value(signature, 130, "Safe signature")
    raw = bytearray.fromhex(normalized[2:])
    if raw[-1] in (0, 1):
        raw[-1] += 27
    if raw[-1] not in (27, 28):
        raise ValueError("Safe signature recovery byte must be 27 or 28")
    return bytes(raw)


def _encode_safe_signature_entries(
    entries: list[tuple[str, bytes, bool]],
) -> bytes:
    """Encode Safe EOA and EIP-1271 contract-owner signatures.

    Contract signatures are recursively usable. Authority V3 uses that property
    for ``Root Safe -> Coadmin Safe -> Identity Safe -> daily EOA`` without
    granting any API or relayer signing authority.
    """

    if not entries:
        raise ValueError("at least one Safe signature is required")
    normalized = [
        (
            normalize_evm_address(owner, "Safe signature owner"),
            bytes(signature),
            is_contract,
        )
        for owner, signature, is_contract in entries
    ]
    if len({owner.lower() for owner, _signature, _kind in normalized}) != len(
        normalized
    ):
        raise ValueError("Safe signature owners must be unique")
    normalized.sort(key=lambda item: int(item[0], 16))
    static_size = 65 * len(normalized)
    dynamic_offset = static_size
    static_parts: list[bytes] = []
    dynamic_parts: list[bytes] = []
    for owner, signature, is_contract in normalized:
        if not is_contract:
            if len(signature) != 65 or signature[-1] not in (27, 28):
                raise ValueError("direct Safe owner signature is invalid")
            static_parts.append(signature)
            continue
        padding = b"\x00" * ((32 - len(signature) % 32) % 32)
        dynamic = len(signature).to_bytes(32, "big") + signature + padding
        static_parts.append(
            int(owner, 16).to_bytes(32, "big")
            + dynamic_offset.to_bytes(32, "big")
            + b"\x00"
        )
        dynamic_parts.append(dynamic)
        dynamic_offset += len(dynamic)
    return b"".join(static_parts + dynamic_parts)


def _contract_owner_signature(owner: str, nested_signature: bytes) -> bytes:
    return _encode_safe_signature_entries([(owner, nested_signature, True)])


def _safe_transaction_typed_data(
    safe: str,
    transaction: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "domain": {
            "chainId": AUTHORITY_EVM_CHAIN_ID,
            "verifyingContract": safe,
        },
        "types": {"SafeTx": SAFE_TRANSACTION_FIELDS},
        "primaryType": "SafeTx",
        "message": {
            field: transaction[field]
            for field in (
                "to",
                "value",
                "data",
                "operation",
                "safeTxGas",
                "baseGas",
                "gasPrice",
                "gasToken",
                "refundReceiver",
                "nonce",
            )
        },
    }


def _safe_message_typed_data(
    identity_safe: str,
    transaction_data: str,
) -> dict[str, Any]:
    return {
        "domain": {
            "chainId": AUTHORITY_EVM_CHAIN_ID,
            "verifyingContract": identity_safe,
        },
        "types": {"SafeMessage": [{"name": "message", "type": "bytes"}]},
        "primaryType": "SafeMessage",
        "message": {"message": transaction_data},
    }


async def _safe_transaction_context(
    settings: Settings,
    *,
    safe: str,
    to: str,
    data: str,
    nonce_override: int | None = None,
) -> dict[str, Any]:
    safe = normalize_evm_address(safe, "execution Safe")
    to = normalize_evm_address(to, "Safe transaction target")
    data = str(data or "").lower()
    if (
        not data.startswith("0x")
        or len(data) <= 2
        or len(data) % 2 != 0
    ):
        raise ValueError("Safe transaction data must be non-empty 0x hex")
    try:
        raw_data = bytes.fromhex(data[2:])
    except ValueError as exc:
        raise ValueError("Safe transaction data must be valid hex") from exc
    if not any(raw_data):
        raise ValueError("Safe transaction data cannot be zero")
    if nonce_override is not None and (
        isinstance(nonce_override, bool)
        or nonce_override < 0
        or nonce_override >= 2**256
    ):
        raise ValueError("Safe transaction nonce is invalid")
    nonce = (
        await _call_uint(settings, safe, "nonce()")
        if nonce_override is None
        else nonce_override
    )
    transaction = {
        "to": to,
        "value": 0,
        "data": data,
        "operation": 0,
        "safeTxGas": 0,
        "baseGas": 0,
        "gasPrice": 0,
        "gasToken": ZERO_EVM_ADDRESS,
        "refundReceiver": ZERO_EVM_ADDRESS,
        "nonce": nonce,
    }
    local_data = _safe_typed_data_preimage(
        _safe_transaction_typed_data(safe, transaction)
    )
    local_hash = "0x" + keccak(local_data).hex()
    argument_types = [
        "address",
        "uint256",
        "bytes",
        "uint8",
        "uint256",
        "uint256",
        "uint256",
        "address",
        "address",
        "uint256",
    ]
    arguments = [
        to,
        0,
        raw_data,
        0,
        0,
        0,
        0,
        ZERO_EVM_ADDRESS,
        ZERO_EVM_ADDRESS,
        nonce,
    ]
    encoded_arguments = abi_encode(argument_types, arguments)

    async def call(function_signature: str) -> str:
        return str(
            await _rpc(
                settings,
                "eth_call",
                [
                    {
                        "to": safe,
                        "data": "0x"
                        + (
                            keccak(text=function_signature)[:4]
                            + encoded_arguments
                        ).hex(),
                    },
                    "latest",
                ],
            )
        )

    rpc_hash = _hex_value(
        await call(
            "getTransactionHash("
            "address,uint256,bytes,uint8,uint256,uint256,uint256,"
            "address,address,uint256)"
        ),
        64,
        "Safe transaction hash",
    )
    if rpc_hash != local_hash:
        raise ValueError("Safe transaction hash differs from the local EIP-712 action")
    encoded_result = await call(
        "encodeTransactionData("
        "address,uint256,bytes,uint8,uint256,uint256,uint256,"
        "address,address,uint256)"
    )
    # Compare the complete canonical ABI result. This also rejects malformed,
    # truncated and trailing data without parsing provider-controlled offsets.
    expected_result = "0x" + abi_encode(["bytes"], [local_data]).hex()
    if encoded_result.lower() != expected_result:
        raise ValueError("Safe transaction data differs from the local EIP-712 action")
    return {
        "safe": safe,
        "nonce": nonce,
        "transaction": transaction,
        "transactionHash": local_hash,
        "transactionData": "0x" + local_data.hex(),
    }


def _safe_exec_transaction(
    context: Mapping[str, Any],
    signatures: bytes,
) -> dict[str, Any]:
    transaction = context["transaction"]
    return {
        "chainId": AUTHORITY_EVM_CHAIN_ID,
        "to": context["safe"],
        "value": "0x0",
        "data": _function_data(
            (
                "execTransaction(address,uint256,bytes,uint8,uint256,"
                "uint256,uint256,address,address,bytes)"
            ),
            [
                "address",
                "uint256",
                "bytes",
                "uint8",
                "uint256",
                "uint256",
                "uint256",
                "address",
                "address",
                "bytes",
            ],
            [
                transaction["to"],
                transaction["value"],
                bytes.fromhex(str(transaction["data"])[2:]),
                transaction["operation"],
                transaction["safeTxGas"],
                transaction["baseGas"],
                transaction["gasPrice"],
                transaction["gasToken"],
                transaction["refundReceiver"],
                signatures,
            ],
        ),
    }


def _current_evm_owner_for_case(
    *,
    case: Mapping[str, Any],
    intent: AdminKeyChangeIntentV1,
    administrators: list[tuple[str, str]],
    slot: int,
) -> str:
    current = administrators[slot][0]
    if (
        slot == intent.slot
        and _case_has_receipt(case, "EVM", "EXECUTE")
        and not _case_has_receipt(case, "EVM", "ROLLBACK")
    ):
        current = intent.new_daily_evm_key
    return normalize_evm_address(current, "current Identity Safe owner")


def _safe_topology(
    evidence: Mapping[str, Any],
    intent: AdminKeyChangeIntentV1,
) -> dict[str, Any]:
    safes = evidence.get("safes")
    if not isinstance(safes, Mapping):
        raise ValueError("Authority V3 Safe topology is unavailable")
    identities_raw = safes.get("identities")
    coadmin_raw = safes.get("coadmin")
    root_raw = safes.get("root")
    if (
        not isinstance(identities_raw, list)
        or len(identities_raw) != 3
        or not isinstance(coadmin_raw, Mapping)
        or not isinstance(root_raw, Mapping)
    ):
        raise ValueError("Authority V3 Safe topology is incomplete")
    identities = [
        normalize_evm_address(item.get("address"), f"Identity Safe {slot}")
        for slot, item in enumerate(identities_raw)
        if isinstance(item, Mapping) and item.get("slot") == slot
    ]
    if len(identities) != 3:
        raise ValueError("Authority V3 Identity Safe order is invalid")
    coadmin = normalize_evm_address(coadmin_raw.get("address"), "coadmin Safe")
    root = normalize_evm_address(root_raw.get("address"), "root Safe")
    if (
        [value.lower() for value in identities]
        != [value.lower() for value in intent.identity_safes]
        or coadmin.lower() != intent.coadmin_safe.lower()
        or root.lower() != intent.root_safe.lower()
        or coadmin_raw.get("threshold") != 1
        or root_raw.get("threshold") != 2
        or {
            str(value).lower() for value in coadmin_raw.get("owners", [])
        }
        != {identities[1].lower(), identities[2].lower()}
        or {str(value).lower() for value in root_raw.get("owners", [])}
        != {identities[0].lower(), coadmin.lower()}
    ):
        raise ValueError("Authority V3 Safe topology differs from the intent")
    return {
        "identities": identities,
        "coadmin": coadmin,
        "root": root,
    }


async def _verify_safe_runtime_code(
    settings: Settings,
    evidence: Mapping[str, Any],
    addresses: list[tuple[str, str]],
) -> None:
    hashes = evidence.get("runtimeCodeHashes")
    if not isinstance(hashes, Mapping):
        raise ValueError("Authority V3 Safe runtime evidence is unavailable")
    checked: set[str] = set()
    for evidence_key, address in addresses:
        normalized = normalize_evm_address(address, evidence_key)
        if normalized.lower() in checked:
            continue
        expected_hash = _hex_value(
            hashes.get(evidence_key),
            64,
            f"{evidence_key} runtime hash",
        )
        code = str(await _rpc(settings, "eth_getCode", [normalized, "latest"]))
        if code == "0x" or "0x" + keccak(bytes.fromhex(code[2:])).hex() != expected_hash:
            raise ValueError(f"{evidence_key} runtime code changed")
        checked.add(normalized.lower())


async def _build_evm_safe_action_package(
    *,
    case: Mapping[str, Any],
    body: EvmSafeActionPackageRequest,
    settings: Settings,
    store: GenesisStore,
    approved_safe_nonce: int | None = None,
) -> dict[str, Any]:
    if case["state"] in TERMINAL_CASE_STATES:
        raise GenesisConflict("administrator recovery case is terminal")
    artifact, evidence, _coordinator = await _verified_evidence_context(settings)
    intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
    _validate_intent_bindings(
        intent=intent,
        artifact=artifact,
        evidence=evidence,
        store=store,
    )
    action = next(
        (
            value
            for value in _case_actions(case, evidence)
            if value["actionId"] == body.action_id
            and value["execution"] == "SAFE"
        ),
        None,
    )
    if action is None:
        raise GenesisConflict("this Safe action is complete, stale, or unavailable")
    topology = _safe_topology(evidence, intent)
    stored = store.recovery_evm_safe_signatures(
        str(case["caseId"]),
        action_id=body.action_id,
        include_signatures=True,
    )
    if approved_safe_nonce is not None:
        if not stored:
            raise GenesisConflict(
                "the approved Safe package is unavailable for this transaction"
            )
        if any(
            int(value["safeNonce"]) != approved_safe_nonce
            for value in stored
        ):
            raise GenesisConflict(
                "recorded Safe approvals disagree on the approved nonce"
            )
    stored_coadmin = (
        stored[0]["coadminSlot"] if stored else None
    )
    signer = normalize_evm_address(action["signer"], "action Safe")
    if signer.lower() == topology["root"].lower():
        selected_coadmin = stored_coadmin or body.coadmin_slot or 1
        if selected_coadmin not in (1, 2):
            raise ValueError("choose coadministrator slot 2 or 3")
        if (
            stored_coadmin is not None
            and body.coadmin_slot is not None
            and body.coadmin_slot != stored_coadmin
        ):
            raise GenesisConflict(
                "this action is already bound to the other coadministrator"
            )
        execution_safe = topology["root"]
        signer_slots = (0, selected_coadmin)
        signer_roles = ("OWNER", "COADMIN")
        signature_kind = "SAFE_MESSAGE"
        runtime_addresses = [
            ("rootSafe", topology["root"]),
            ("coadminSafe", topology["coadmin"]),
            ("identitySafe0", topology["identities"][0]),
            (
                f"identitySafe{selected_coadmin}",
                topology["identities"][selected_coadmin],
            ),
        ]
    else:
        try:
            peer_slot = next(
                slot
                for slot, address in enumerate(topology["identities"])
                if address.lower() == signer.lower()
            )
        except StopIteration as exc:
            raise ValueError("Safe action signer is outside Authority V3") from exc
        if body.coadmin_slot is not None:
            raise ValueError("peer Safe actions do not select a coadministrator")
        selected_coadmin = None
        execution_safe = topology["identities"][peer_slot]
        signer_slots = (peer_slot,)
        signer_roles = ("PEER",)
        signature_kind = "SAFE_TX"
        runtime_addresses = [
            (f"identitySafe{peer_slot}", execution_safe),
        ]
    await _verify_safe_runtime_code(
        settings,
        evidence,
        runtime_addresses,
    )
    context = await _safe_transaction_context(
        settings,
        safe=execution_safe,
        to=action["to"],
        data=action["data"],
        nonce_override=approved_safe_nonce,
    )
    administrators = _current_administrators(artifact, store)
    descriptors = []
    for slot, role in zip(signer_slots, signer_roles, strict=True):
        signer_address = _current_evm_owner_for_case(
            case=case,
            intent=intent,
            administrators=administrators,
            slot=slot,
        )
        typed_data = (
            _safe_message_typed_data(
                topology["identities"][slot],
                context["transactionData"],
            )
            if signature_kind == "SAFE_MESSAGE"
            else _safe_transaction_typed_data(
                execution_safe,
                context["transaction"],
            )
        )
        message_hash = _safe_typed_data_digest(typed_data)
        if (
            signature_kind == "SAFE_TX"
            and message_hash.lower()
            != str(context["transactionHash"]).lower()
        ):
            raise ValueError("Identity Safe transaction hash differs from EIP-712")
        descriptors.append(
            {
                "slot": slot,
                "role": role,
                "identitySafe": topology["identities"][slot],
                "signerAddress": signer_address,
                "signatureKind": signature_kind,
                "messageHash": message_hash,
                "typedData": typed_data,
            }
        )
    sealed = {
        "schemaVersion": 1,
        "kind": "solslot-authority-v3-safe-action",
        "caseId": case["caseId"],
        "actionId": body.action_id,
        "intentHash": case["intentHash"],
        "network": "baseSepolia",
        "chainId": AUTHORITY_EVM_CHAIN_ID,
        "executionSafe": execution_safe,
        "safeNonce": context["nonce"],
        "coadminSlot": selected_coadmin,
        "transaction": context["transaction"],
        "transactionHash": context["transactionHash"],
        "transactionData": context["transactionData"],
        "approvals": descriptors,
    }
    package_hash = _canonical_receipt_hash(sealed)
    current_signatures = store.recovery_evm_safe_signatures(
        str(case["caseId"]),
        action_id=body.action_id,
        package_hash=package_hash,
        include_signatures=True,
    )
    signed_by_slot = {
        int(value["signerSlot"]): value for value in current_signatures
    }
    approvals = [
        {
            **descriptor,
            "signed": descriptor["slot"] in signed_by_slot,
            "signedAt": (
                signed_by_slot[descriptor["slot"]]["submittedAt"]
                if descriptor["slot"] in signed_by_slot
                else None
            ),
        }
        for descriptor in descriptors
    ]
    ready = len(signed_by_slot) == len(descriptors)
    broadcast_transaction = None
    if ready:
        if signature_kind == "SAFE_TX":
            direct = _normalize_safe_eoa_signature(
                signed_by_slot[signer_slots[0]]["signature"]
            )
            safe_signatures = _encode_safe_signature_entries(
                [
                    (
                        signed_by_slot[signer_slots[0]]["signerAddress"],
                        direct,
                        False,
                    )
                ]
            )
        else:
            owner_signature = _normalize_safe_eoa_signature(
                signed_by_slot[0]["signature"]
            )
            coadmin_signature = _normalize_safe_eoa_signature(
                signed_by_slot[selected_coadmin]["signature"]
            )
            nested_coadmin = _contract_owner_signature(
                topology["identities"][selected_coadmin],
                coadmin_signature,
            )
            safe_signatures = _encode_safe_signature_entries(
                [
                    (
                        topology["identities"][0],
                        owner_signature,
                        True,
                    ),
                    (
                        topology["coadmin"],
                        nested_coadmin,
                        True,
                    ),
                ]
            )
        broadcast_transaction = _safe_exec_transaction(
            context,
            safe_signatures,
        )
    return {
        **sealed,
        "packageHash": package_hash,
        "title": action["title"],
        "financialEffect": action["financialEffect"],
        "authorityRule": (
            "Owner plus either coadministrator"
            if signature_kind == "SAFE_MESSAGE"
            else f"Administrator slot {signer_slots[0] + 1}"
        ),
        "approvals": approvals,
        "readyToBroadcast": ready,
        "broadcastTransaction": broadcast_transaction,
    }


async def _record_pending_evm_action(
    *,
    case: Mapping[str, Any],
    body: EvmActionSubmission,
    actor: SecurityActor,
    settings: Settings,
    store: GenesisStore,
) -> dict[str, Any]:
    artifact, evidence, _coordinator = await _verified_evidence_context(settings)
    intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
    _validate_intent_bindings(
        intent=intent,
        artifact=artifact,
        evidence=evidence,
        store=store,
    )
    action = next(
        (
            value
            for value in _case_actions(case, evidence)
            if value["actionId"] == body.action_id
        ),
        None,
    )
    if action is None:
        raise GenesisConflict("this Base Sepolia action is complete, stale, or unavailable")
    transaction = await _rpc(
        settings,
        "eth_getTransactionByHash",
        [body.transaction_hash],
    )
    if not isinstance(transaction, Mapping):
        raise ValueError(
            "Base Sepolia has not propagated this transaction yet; retry shortly"
        )
    transaction_hash = str(transaction.get("hash") or "").lower()
    sender = normalize_evm_address(
        transaction.get("from"),
        "Base Sepolia transaction sender",
    )
    transaction_to = normalize_evm_address(
        transaction.get("to"),
        "Base Sepolia transaction destination",
    )
    transaction_data = str(
        transaction.get("input") or transaction.get("data") or ""
    ).lower()
    if (
        transaction_hash != body.transaction_hash.lower()
        or _rpc_integer(
            transaction.get("value") or "0x0",
            "Base Sepolia transaction value",
        )
        != 0
    ):
        raise ValueError("Base Sepolia transaction differs from the reviewed action")
    if transaction.get("chainId") is not None and _rpc_integer(
        transaction.get("chainId"),
        "Base Sepolia transaction chain",
    ) != AUTHORITY_EVM_CHAIN_ID:
        raise ValueError("administrator action was submitted on the wrong EVM network")

    if action["execution"] == "SAFE":
        stored_approvals = store.recovery_evm_safe_signatures(
            str(case["caseId"]),
            action_id=body.action_id,
            include_signatures=True,
        )
        if not stored_approvals:
            raise GenesisConflict(
                "this Safe transaction has no recorded administrator approvals"
            )
        approved_nonces = {
            int(value["safeNonce"]) for value in stored_approvals
        }
        if len(approved_nonces) != 1:
            raise GenesisConflict(
                "recorded Safe approvals disagree on the approved nonce"
            )
        approved_coadmins = {
            value["coadminSlot"] for value in stored_approvals
        }
        if len(approved_coadmins) != 1:
            raise GenesisConflict(
                "recorded Safe approvals disagree on the coadministrator"
            )
        approved_coadmin = next(iter(approved_coadmins))
        if (
            body.coadmin_slot is not None
            and body.coadmin_slot != approved_coadmin
        ):
            raise GenesisConflict(
                "submitted Safe transaction uses the wrong coadministrator"
            )
        safe_package = await _build_evm_safe_action_package(
            case=case,
            body=EvmSafeActionPackageRequest(
                actionId=body.action_id,
                coadminSlot=approved_coadmin,
            ),
            settings=settings,
            store=store,
            approved_safe_nonce=next(iter(approved_nonces)),
        )
        expected = safe_package.get("broadcastTransaction")
        if (
            safe_package.get("readyToBroadcast") is not True
            or not isinstance(expected, Mapping)
            or transaction_to.lower() != str(expected.get("to")).lower()
            or transaction_data != str(expected.get("data")).lower()
            or sender.lower() != actor.wallet.lower()
        ):
            raise ValueError(
                "submitted Safe transaction differs from the exact approved package"
            )
    elif action["execution"] == "OFFLINE_RELAY":
        authorization_action = action.get("authorizationAction")
        if authorization_action not in {"ACCEPT", "VETO"}:
            raise ValueError("offline recovery action is malformed")
        _guardian, gas_payer, _mode = _verify_recovery_guardian_transaction(
            transaction=transaction,
            intent=intent,
            coordinator=normalize_evm_address(
                action["to"],
                "recovery coordinator",
            ),
            action=authorization_action,
        )
        if gas_payer.lower() != actor.wallet.lower():
            raise ValueError(
                "offline recovery action was not submitted by this administrator"
            )
    else:
        if (
            transaction_to.lower() != str(action["to"]).lower()
            or transaction_data != str(action["data"]).lower()
        ):
            raise ValueError(
                "Base Sepolia transaction differs from the exact administrator action"
            )
        expected_sender = (
            normalize_evm_address(action["signer"], "required action signer")
            if action["execution"] == "WALLET"
            else actor.wallet
        )
        if sender.lower() != expected_sender.lower():
            raise ValueError(
                "Base Sepolia action was submitted by the wrong wallet"
            )

    store.add_recovery_evm_submission(
        str(case["caseId"]),
        action_id=body.action_id,
        transaction_hash=body.transaction_hash,
        submitted_by=sender,
    )
    return await _case_view(
        case=store.recovery_case(str(case["caseId"])),
        settings=settings,
        evidence=evidence,
        store=store,
    )


def _eip_signing_action(
    *,
    phase: Literal["PREPARE", "CANCEL"],
    role: str,
    slot: int,
    public_key: bytes,
    coin_id: bytes32,
    delegated_puzzle_hash: bytes32,
    title: str,
    summary: str,
) -> _ChiaSigningAction:
    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network("testnet11")
    )
    digest = eip712_hash_to_sign(
        prefix,
        coin_id,
        delegated_puzzle_hash,
    )
    payload = {
        "schemaVersion": 1,
        "phase": phase,
        "role": role,
        "slot": slot,
        "publicKey": "0x" + public_key.hex(),
        "coinId": _hex32(coin_id),
        "delegatedPuzzleHash": _hex32(delegated_puzzle_hash),
        "messageHash": _hex32(digest),
    }
    return _ChiaSigningAction(
        phase=phase,
        action_id=_action_id(payload),
        signer_kind="EIP712_DAILY",
        signer_slot=slot,
        signer_public_key="0x" + public_key.hex(),
        message_hash=_hex32(digest),
        title=title,
        summary=summary,
        coin_id=_hex32(coin_id),
        delegated_puzzle_hash=_hex32(delegated_puzzle_hash),
        typed_data=eip712_typed_data_for_coin_spend(
            network="testnet11",
            coin_id=coin_id,
            delegated_puzzle_hash=delegated_puzzle_hash,
        ),
    )


def _prepare_eip_actions(
    build: _ChiaRecoveryBuild,
) -> tuple[Any, list[_ChiaSigningAction]]:
    mips = build_authority_prepare_mips_spend(
        authority=build.authority,
        transition=build.transition,
        current_identities=build.current_identities,
        current_identity_coin_ids=tuple(
            bytes32(context.coin.name())
            for context in build.identity_contexts
        ),
        coadmin_slot=build.coadmin_slot,
    )
    actions: list[_ChiaSigningAction] = []
    target_slot = build.intent.slot

    for slot in mips.selected_slots:
        if (
            slot == target_slot
            and build.intent.kind in {"ROUTINE", "RECOVERY_KIT"}
        ):
            delegated_hash = bytes32(
                build.transition.prepare_delegated_puzzle.get_tree_hash()
            )
            role = "target-current-wallet"
            title = "Approve the temporary recovery lock"
            summary = (
                "Your current wallet authorizes only this identity vault to "
                "enter its veto window. It cannot move protocol funds."
            )
        else:
            approval = build_identity_approval_action(
                identity=build.current_identities[slot],
                transition=build.transition,
            )
            delegated_hash = bytes32(approval.get_tree_hash())
            role = f"constitutional-approval-{slot}"
            title = f"Administrator {slot + 1} approves the key change"
            summary = (
                "This signature proves the fixed owner-plus-one authority "
                "rule for this exact replacement and no other operation."
            )
        actions.append(
            _eip_signing_action(
                phase="PREPARE",
                role=role,
                slot=slot,
                public_key=build.current_identities[
                    slot
                ].daily_compressed_pubkey,
                coin_id=bytes32(
                    build.identity_contexts[slot].coin.name()
                ),
                delegated_puzzle_hash=delegated_hash,
                title=title,
                summary=summary,
            )
        )

    replacement_slot = target_slot
    actions.append(
        _eip_signing_action(
            phase="PREPARE",
            role="replacement-acceptance",
            slot=replacement_slot,
            public_key=build.transition.replacement_daily_compressed_pubkey,
            coin_id=bytes32(build.authority_context.coin.name()),
            delegated_puzzle_hash=build.transition.prepare_binding_hash,
            title=(
                "Confirm the replacement recovery kit"
                if build.intent.kind == "RECOVERY_KIT"
                else "Accept the replacement administrator wallet"
            ),
            summary=(
                "The replacement key accepts this exact identity, network, "
                "manifest, delay, and recovery revision. No funds move."
            ),
        )
    )
    return mips, actions


def _cancel_eip_action(
    build: _ChiaRecoveryBuild,
) -> _ChiaSigningAction:
    slot = build.intent.slot
    return _eip_signing_action(
        phase="CANCEL",
        role="old-key-veto",
        slot=slot,
        public_key=build.current_identities[slot].daily_compressed_pubkey,
        coin_id=bytes32(build.identity_contexts[slot].coin.name()),
        delegated_puzzle_hash=(
            build.transition.cancel_identity_action_hash
        ),
        title="Cancel this administrator key change",
        summary=(
            "The current daily wallet restores the original identity custody. "
            "It cannot select a different key or move protocol funds."
        ),
    )


def _stored_chia_signatures(
    store: GenesisStore,
    case_id: str,
    phase: Literal["PREPARE", "CANCEL"],
) -> dict[str, dict[str, Any]]:
    return {
        item["actionId"]: item
        for item in store.recovery_chia_signatures(
            case_id,
            phase=phase,
            include_signatures=True,
        )
    }


def _stored_action_signature(
    action: _ChiaSigningAction,
    stored: Mapping[str, Mapping[str, Any]],
) -> Optional[bytes]:
    record = stored.get(action.action_id)
    if record is None:
        return None
    if (
        record["signerKind"] != action.signer_kind
        or record["signerSlot"] != action.signer_slot
        or str(record["signerPublicKey"]).lower()
        != action.signer_public_key.lower()
        or str(record["messageHash"]).lower()
        != action.message_hash.lower()
    ):
        raise GenesisConflict(
            "stored Chia signature differs from the reconstructed action"
        )
    return bytes.fromhex(str(record["signature"])[2:])


def _eip_member_solution_for_action(
    action: _ChiaSigningAction,
    stored: Mapping[str, Mapping[str, Any]],
) -> Program:
    signature = _stored_action_signature(action, stored)
    if signature is None:
        raise GenesisConflict("required Chia action is not signed")
    if action.coin_id is None or action.delegated_puzzle_hash is None:
        raise ValueError("EIP-712 action is missing its coin binding")
    return build_eip712_member_solution(
        network="testnet11",
        coin_id=_bytes32_hex(action.coin_id, "action coin id"),
        delegated_puzzle_hash=_bytes32_hex(
            action.delegated_puzzle_hash,
            "delegated puzzle hash",
        ),
        compressed_pubkey=bytes.fromhex(
            action.signer_public_key[2:]
        ),
        signature=signature,
    )


def _singleton_spend(
    *,
    context: LiveSingletonContext,
    inner_puzzle: Program,
    inner_solution: Program,
    amount: int,
) -> CoinSpend:
    if int(context.coin.amount) != amount:
        raise ValueError("singleton amount differs from Authority V3 rules")
    return make_spend(
        context.coin,
        puzzle_for_singleton(context.launcher_id, inner_puzzle),
        solution_for_singleton(
            lineage_proof_for_coinsol(context.parent_spend),
            uint64(amount),
            inner_solution,
        ),
    )


def _validate_protocol_bundle_inputs(bundle: SpendBundle) -> None:
    names = [bytes32(spend.coin.name()) for spend in bundle.coin_spends]
    if not names or len(names) != len(set(names)):
        raise ValueError("Authority V3 bundle has missing or duplicate inputs")


def _prepare_unsigned_bundle(
    *,
    build: _ChiaRecoveryBuild,
    store: GenesisStore,
) -> tuple[
    SpendBundle,
    list[_ChiaSigningAction],
    tuple[tuple[G1Element, bytes], ...],
]:
    mips, actions = _prepare_eip_actions(build)
    stored = _stored_chia_signatures(
        store,
        str(build.case["caseId"]),
        "PREPARE",
    )
    action_by_slot: dict[int, _ChiaSigningAction] = {}
    replacement_action = actions[-1]
    for action in actions[:-1]:
        action_by_slot[action.signer_slot] = action

    authority_solution = build_prepare_solution(
        transition=build.transition,
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=build.snapshot.authority_version + 1,
        mips_reveal=mips.reveal,
        mips_solution=mips.solution,
        replacement_member_solution=_eip_member_solution_for_action(
            replacement_action,
            stored,
        ),
        identity_records=mips.identity_records,
    )
    spends = [
        _singleton_spend(
            context=build.authority_context,
            inner_puzzle=build.current_authority_inner,
            inner_solution=authority_solution,
            amount=AUTHORITY_LAUNCHER_AMOUNT,
        )
    ]
    target_slot = build.intent.slot
    for slot in mips.selected_slots:
        if (
            slot == target_slot
            and build.intent.kind in {"ROUTINE", "RECOVERY_KIT"}
        ):
            identity_solution = build_routine_identity_prepare_solution(
                identity=build.current_identities[slot],
                transition=build.transition,
                daily_member_solution=_eip_member_solution_for_action(
                    action_by_slot[slot],
                    stored,
                ),
            )
        else:
            identity_solution = build_identity_approval_solution(
                identity=build.current_identities[slot],
                transition=build.transition,
                current_identity_coin_id=bytes32(
                    build.identity_contexts[slot].coin.name()
                ),
                daily_member_solution=_eip_member_solution_for_action(
                    action_by_slot[slot],
                    stored,
                ),
            )
        spends.append(
            _singleton_spend(
                context=build.identity_contexts[slot],
                inner_puzzle=build.current_identities[
                    slot
                ].custody_reveal,
                inner_solution=identity_solution,
                amount=IDENTITY_LAUNCHER_AMOUNTS[slot],
            )
        )

    if build.intent.kind == "LOST":
        target_solution = build_lost_recovery_identity_solution(
            identity=build.current_identities[target_slot],
            transition=build.transition,
        )
        spends.append(
            _singleton_spend(
                context=build.identity_contexts[target_slot],
                inner_puzzle=build.current_identities[
                    target_slot
                ].custody_reveal,
                inner_solution=target_solution,
                amount=IDENTITY_LAUNCHER_AMOUNTS[target_slot],
            )
        )

    unsigned = SpendBundle(spends, G2Element())
    _validate_protocol_bundle_inputs(unsigned)
    pairs: list[tuple[G1Element, bytes]] = []
    additional_data = AGG_SIG_ME_DATA["testnet11"]
    for spend in unsigned.coin_spends:
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                additional_data,
            )
        )
    if build.intent.kind == "LOST":
        expected_key = bytes.fromhex(
            build.intent.old_recovery_bls_key[2:]
        )
        if not pairs or any(
            bytes(public_key) != expected_key
            for public_key, _message in pairs
        ):
            raise ValueError(
                "lost-key bundle emits an unexpected BLS signing condition"
            )
    elif pairs:
        raise ValueError(
            "routine Authority V3 bundle unexpectedly requires BLS signing"
        )
    return unsigned, actions, tuple(pairs)


def _bls_recovery_action(
    build: _ChiaRecoveryBuild,
    pairs: tuple[tuple[G1Element, bytes], ...],
) -> _ChiaSigningAction:
    wire_pairs = tuple(
        ("0x" + bytes(public_key).hex(), "0x" + message.hex())
        for public_key, message in pairs
    )
    message_hash = _action_id(
        {
            "schemaVersion": 1,
            "kind": "AuthorityV3BlsMessages",
            "pairs": wire_pairs,
        }
    )
    payload = {
        "schemaVersion": 1,
        "phase": "PREPARE",
        "role": "lost-key-recovery",
        "slot": build.intent.slot,
        "publicKey": build.intent.old_recovery_bls_key,
        "messageHash": message_hash,
        "pairs": wire_pairs,
    }
    return _ChiaSigningAction(
        phase="PREPARE",
        action_id=_action_id(payload),
        signer_kind="BLS_RECOVERY",
        signer_slot=build.intent.slot,
        signer_public_key=build.intent.old_recovery_bls_key,
        message_hash=message_hash,
        title="Authorize lost-wallet recovery",
        summary=(
            "The offline recovery key authorizes only this exact identity "
            "transition. It cannot perform ordinary administrator actions."
        ),
        bls_pairs=wire_pairs,
    )


def _signed_prepare_bundle(
    *,
    build: _ChiaRecoveryBuild,
    store: GenesisStore,
) -> tuple[
    Optional[SpendBundle],
    list[_ChiaSigningAction],
]:
    _mips, eip_actions = _prepare_eip_actions(build)
    stored = _stored_chia_signatures(
        store,
        str(build.case["caseId"]),
        "PREPARE",
    )
    if any(
        _stored_action_signature(action, stored) is None
        for action in eip_actions
    ):
        return None, eip_actions
    unsigned, rebuilt_actions, pairs = _prepare_unsigned_bundle(
        build=build,
        store=store,
    )
    if build.intent.kind != "LOST":
        return unsigned, rebuilt_actions
    bls_action = _bls_recovery_action(build, pairs)
    signature_bytes = _stored_action_signature(bls_action, stored)
    actions = [*rebuilt_actions, bls_action]
    if signature_bytes is None:
        return None, actions
    try:
        signature = G2Element.from_bytes(signature_bytes)
    except (TypeError, ValueError) as exc:
        raise GenesisConflict("stored recovery BLS signature is malformed") from exc
    if not AugSchemeMPL.aggregate_verify(
        [public_key for public_key, _message in pairs],
        [message for _public_key, message in pairs],
        signature,
    ):
        raise GenesisConflict(
            "stored recovery BLS signature does not authorize this bundle"
        )
    return SpendBundle(unsigned.coin_spends, signature), actions


def _signed_cancel_bundle(
    *,
    build: _ChiaRecoveryBuild,
    store: GenesisStore,
) -> tuple[Optional[SpendBundle], list[_ChiaSigningAction]]:
    action = _cancel_eip_action(build)
    stored = _stored_chia_signatures(
        store,
        str(build.case["caseId"]),
        "CANCEL",
    )
    if _stored_action_signature(action, stored) is None:
        return None, [action]
    target_slot = build.intent.slot
    target_solution = build_identity_cancel_solution(
        identity=build.current_identities[target_slot],
        transition=build.transition,
        daily_member_solution=_eip_member_solution_for_action(
            action,
            stored,
        ),
    )
    authority_solution = build_cancel_solution(
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=build.snapshot.authority_version + 1,
    )
    bundle = SpendBundle(
        [
            _singleton_spend(
                context=build.authority_context,
                inner_puzzle=build.current_authority_inner,
                inner_solution=authority_solution,
                amount=AUTHORITY_LAUNCHER_AMOUNT,
            ),
            _singleton_spend(
                context=build.identity_contexts[target_slot],
                inner_puzzle=build.transition.intermediate_custody_reveal,
                inner_solution=target_solution,
                amount=IDENTITY_LAUNCHER_AMOUNTS[target_slot],
            ),
        ],
        G2Element(),
    )
    _validate_protocol_bundle_inputs(bundle)
    return bundle, [action]


def _complete_bundle(build: _ChiaRecoveryBuild) -> SpendBundle:
    target_slot = build.intent.slot
    authority_solution = build_complete_solution(
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=build.snapshot.authority_version + 1,
    )
    target_solution = build_identity_finish_solution(build.transition)
    bundle = SpendBundle(
        [
            _singleton_spend(
                context=build.authority_context,
                inner_puzzle=build.current_authority_inner,
                inner_solution=authority_solution,
                amount=AUTHORITY_LAUNCHER_AMOUNT,
            ),
            _singleton_spend(
                context=build.identity_contexts[target_slot],
                inner_puzzle=build.transition.intermediate_custody_reveal,
                inner_solution=target_solution,
                amount=IDENTITY_LAUNCHER_AMOUNTS[target_slot],
            ),
        ],
        G2Element(),
    )
    _validate_protocol_bundle_inputs(bundle)
    return bundle


def _action_is_signed(
    action: _ChiaSigningAction,
    store: GenesisStore,
    case_id: str,
) -> bool:
    stored = _stored_chia_signatures(store, case_id, action.phase)
    return _stored_action_signature(action, stored) is not None


def _chia_package_view(
    *,
    build: _ChiaRecoveryBuild,
    phase: Literal["PREPARE", "CANCEL", "COMPLETE"],
    bundle: Optional[SpendBundle],
    actions: list[_ChiaSigningAction],
    store: GenesisStore,
) -> dict[str, Any]:
    now = int(time.time())
    delay_complete = now >= int(build.case["executeAfter"])
    ready = bundle is not None and (
        phase != "COMPLETE" or delay_complete
    )
    return {
        "schemaVersion": 1,
        "caseId": build.case["caseId"],
        "intentHash": build.case["intentHash"],
        "phase": phase,
        "network": "testnet11",
        "authorityCoinId": _hex32(build.authority_context.coin.name()),
        "authorityVersion": build.snapshot.authority_version,
        "coadminSlot": build.coadmin_slot,
        "actions": [
            action.to_wire(
                signed=_action_is_signed(
                    action,
                    store,
                    str(build.case["caseId"]),
                )
            )
            for action in actions
        ],
        "delayComplete": delay_complete,
        "executeAfter": int(build.case["executeAfter"]),
        "readyToSubmit": ready,
        "spendBundleId": (
            _hex32(bundle.name()) if ready and bundle is not None else None
        ),
        "inputCoinIds": (
            [
                _hex32(spend.coin.name())
                for spend in bundle.coin_spends
            ]
            if ready and bundle is not None
            else []
        ),
        "clearSigning": {
            "title": {
                "PREPARE": "Start the protected wallet change",
                "CANCEL": "Cancel and restore the current wallet",
                "COMPLETE": "Finish the approved wallet change",
            }[phase],
            "financialEffect": "No administrator or protocol funds move.",
            "authorityRule": "Owner plus either coadministrator",
            "replacement": (
                build.intent.new_recovery_bls_key
                if build.intent.kind == "RECOVERY_KIT"
                else build.intent.new_daily_evm_key
            ),
            "reversible": phase == "PREPARE",
            "operationsFrozen": True,
        },
    }


async def _case_view(
    *,
    case: Mapping[str, Any],
    settings: Settings,
    evidence: Mapping[str, Any],
    store: GenesisStore,
) -> dict[str, Any]:
    refreshed = _refresh_case_state(store, case)
    return {
        **refreshed,
        "approvalsComplete": _approvals_complete(refreshed),
        "delayComplete": int(time.time()) >= int(refreshed["executeAfter"]),
        "actions": _case_actions(refreshed, evidence),
        "policy": {
            "operationsFrozen": refreshed["state"]
            not in TERMINAL_CASE_STATES,
            "crossChainConvergenceRequired": True,
            "oldKeyVetoUntilExecution": True,
            "totalLossBypass": False,
        },
    }


async def _record_prepared_case(
    *,
    submission: PreparedTransactionSubmission,
    settings: Settings,
    store: GenesisStore,
    actor: SecurityActor | None,
) -> dict[str, Any]:
    intent = submission.intent
    artifact, evidence, coordinator = await _verified_evidence_context(
        settings
    )
    _validate_intent_bindings(
        intent=intent,
        artifact=artifact,
        evidence=evidence,
        store=store,
    )
    if intent.kind == "RECOVERY_KIT":
        candidate = store.pending_recovery_kit_candidate(
            artifact_ceremony_id(artifact),
            intent.slot + 1,
        )
        if (
            candidate is None
            or str(candidate["evmGuardian"]).lower()
            != intent.new_recovery_guardian.lower()
            or str(candidate["recoveryBlsPubkey"]).lower()
            != intent.new_recovery_bls_key.lower()
            or int(candidate["revision"])
            != intent.recovery_key_revision + 1
        ):
            raise ValueError(
                "recovery-kit intent is not backed by the tested replacement"
            )
    if intent.kind != "LOST" and submission.guardian_signature is not None:
        raise ValueError(
            "guardian relay authorization is only valid for lost-key recovery"
        )
    intent_hash = hash_admin_key_change_intent(intent)
    relayed_guardian: str | None = None
    expected_calldata = prepare_key_change_calldata(intent)
    if intent.kind == "LOST" and submission.guardian_signature is not None:
        relayed_guardian = verify_lost_guardian_authorization(
            intent=intent,
            coordinator=coordinator,
            guardian_signature=submission.guardian_signature,
        )
        expected_calldata = prepare_lost_key_with_signature_calldata(
            intent,
            submission.guardian_signature,
        )
    transaction, receipt, confirmations = (
        await _confirmed_evm_transaction(
            settings,
            submission.transaction_hash,
        )
    )
    if (
        str(transaction.get("to") or "").lower() != coordinator.lower()
        or _rpc_integer(
            transaction.get("value") or "0x0",
            "transaction value",
        )
        != 0
        or str(
            transaction.get("input")
            or transaction.get("data")
            or ""
        ).lower()
        != expected_calldata.lower()
    ):
        raise ValueError(
            "Authority V3 prepare transaction differs from the exact intent"
        )
    event = _receipt_event(
        receipt,
        coordinator=coordinator,
        event_name="prepared",
        intent_hash=intent_hash,
    )
    slot, kind, old_key, new_key, execute_after = _prepared_event_fields(
        event
    )
    expected_kind = CHANGE_KIND_VALUES[intent.kind]
    sender = normalize_evm_address(
        transaction.get("from"),
        "prepare transaction sender",
    )
    expected_sender = intent.old_daily_evm_key
    ceremony_id = artifact_ceremony_id(artifact)
    if intent.kind in {"ROUTINE", "RECOVERY_KIT"}:
        if (
            actor is None
            or actor.ceremony_id != ceremony_id
            or actor.authority_slot != intent.slot
            or actor.wallet.lower() != expected_sender.lower()
        ):
            raise ValueError(
                "administrator change was not prepared by the current slot wallet"
            )
    else:
        kit = store.recovery_kit(ceremony_id, intent.slot + 1)
        enrolled_guardian = normalize_evm_address(
            kit["evmGuardian"],
            "recovery guardian",
        )
        if enrolled_guardian.lower() != intent.old_recovery_guardian.lower():
            raise ValueError(
                "lost-key intent guardian differs from the enrolled recovery kit"
            )
        if relayed_guardian is None:
            expected_sender = enrolled_guardian
        if not submission.recovery_bls_signature:
            raise ValueError("lost-key recovery BLS proof is required")
        verify_lost_recovery_bls_signature(
            intent=intent,
            recovery_bls_pubkey=str(kit["recoveryBlsPubkey"]),
            signature=submission.recovery_bls_signature,
        )
    if (
        (
            relayed_guardian is None
            and sender.lower() != expected_sender.lower()
        )
        or slot != intent.slot
        or kind != expected_kind
        or old_key.lower() != intent.old_daily_evm_key.lower()
        or new_key.lower() != intent.new_daily_evm_key.lower()
    ):
        raise ValueError(
            "Authority V3 prepared event differs from the reviewed intent"
        )
    block_number = _rpc_integer(
        receipt.get("blockNumber"),
        "transaction block",
    )
    if execute_after != (
        await _block_timestamp(settings, block_number)
    ) + (
        LOST_DELAY_SECONDS
        if intent.kind == "LOST"
        else ROUTINE_DELAY_SECONDS
    ):
        raise ValueError("Authority V3 recovery delay changed")
    if intent.expires_at <= execute_after:
        raise ValueError("Authority V3 recovery execution window is invalid")
    if await _call_uint(settings, coordinator, "changeNonce()") != intent.nonce:
        raise ValueError("Authority V3 change nonce differs from the intent")
    case_id = "recovery-" + intent_hash[2:]
    case = store.create_recovery_case(
        ceremony_id,
        case_id=case_id,
        authority_slot=intent.slot,
        kind=intent.kind,
        intent_hash=intent_hash,
        intent=intent.model_dump(by_alias=True),
        execute_after=execute_after,
        expires_at=intent.expires_at,
        prepared_by=sender,
        now=await _block_timestamp(settings, block_number),
    )
    receipt_record = {
        "schemaVersion": 1,
        "event": "KeyChangePrepared",
        "blockNumber": block_number,
        "confirmations": confirmations,
        "transactionHash": submission.transaction_hash,
        "intentHash": intent_hash,
        "authorizationMode": (
            "OFFLINE_GUARDIAN_RELAY"
            if relayed_guardian is not None
            else "DIRECT_WALLET"
        ),
        "guardianSigner": relayed_guardian,
        "gasPayer": sender,
    }
    case = store.add_recovery_receipt(
        case_id,
        chain="EVM",
        phase="PREPARE",
        transaction_id=submission.transaction_hash,
        receipt_hash=_canonical_receipt_hash(receipt_record),
        receipt=receipt_record,
    )
    case = store.add_recovery_approval(
        case_id,
        actor_role=(
            "RECOVERY_GUARDIAN"
            if intent.kind == "LOST"
            else "PREPARER"
        ),
        actor_id=(
            intent.old_recovery_guardian
            if intent.kind == "LOST"
            else sender
        ),
        signer_slot=(
            intent.slot
            if intent.kind in {"ROUTINE", "RECOVERY_KIT", "LOST"}
            else None
        ),
        signer_address=(
            intent.old_recovery_guardian
            if intent.kind == "LOST"
            else sender
        ),
        signature=(
            submission.guardian_signature
            or submission.recovery_bls_signature
            or submission.transaction_hash
        ),
        message_hash=intent_hash,
    )
    _notify_administrators(
        store,
        ceremony_id,
        event_type="admin_key_change_prepared",
        subject="Administrator wallet change prepared",
        body=(
            f"A {intent.kind.lower()} wallet change was prepared for "
            f"administrator slot {intent.slot + 1}. No funds moved. "
            "Open Security & Access to review it."
        ),
    )
    return case


async def _observe_evm_case(
    *,
    case_id: str,
    transaction_hash: str,
    settings: Settings,
    store: GenesisStore,
) -> dict[str, Any]:
    case = store.recovery_case(case_id)
    if case["state"] in TERMINAL_CASE_STATES:
        raise GenesisConflict("administrator recovery case is terminal")
    _artifact, evidence, coordinator = (
        await _verified_evidence_context(settings)
    )
    transaction, receipt, confirmations = (
        await _confirmed_evm_transaction(
            settings,
            transaction_hash,
        )
    )
    event_name, event = _event_for_case(
        receipt,
        coordinator=coordinator,
        intent_hash=str(case["intentHash"]),
    )
    intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
    topics = event["topics"]
    receipt_record = {
        "schemaVersion": 1,
        "event": event_name,
        "blockNumber": _rpc_integer(
            receipt.get("blockNumber"),
            "transaction block",
        ),
        "confirmations": confirmations,
        "transactionHash": transaction_hash,
        "intentHash": case["intentHash"],
    }
    safes = evidence["safes"]

    if event_name == "authorityApproved":
        signer = _topic_address(topics[2], "authority")
        expected = normalize_evm_address(
            safes["root"]["address"],
            "root Safe",
        )
        if (
            intent.kind not in {"ROUTINE", "RECOVERY_KIT"}
            or signer.lower() != expected.lower()
        ):
            raise ValueError("administrator authority approval is invalid")
        case = _record_approval_once(
            store,
            case,
            role="AUTHORITY",
            actor_id="root-safe",
            signer_slot=0,
            signer_address=signer,
            transaction_hash=transaction_hash,
        )
    elif event_name == "peerApproved":
        peer_slot = _topic_uint(topics[2], "peer slot")
        if (
            intent.kind != "LOST"
            or peer_slot not in _required_peer_slots(intent.slot)
        ):
            raise ValueError("lost-key peer approval is invalid")
        signer = normalize_evm_address(
            safes["identities"][peer_slot]["address"],
            "peer Identity Safe",
        )
        case = _record_approval_once(
            store,
            case,
            role="PEER",
            actor_id=f"slot-{peer_slot}",
            signer_slot=peer_slot,
            signer_address=signer,
            transaction_hash=transaction_hash,
        )
    elif event_name == "replacementAccepted":
        signer = _topic_address(topics[2], "replacement")
        if signer.lower() != intent.new_daily_evm_key.lower():
            raise ValueError("replacement acceptance came from the wrong wallet")
        case = _record_approval_once(
            store,
            case,
            role="REPLACEMENT",
            actor_id="replacement",
            signer_slot=intent.slot,
            signer_address=signer,
            transaction_hash=transaction_hash,
        )
    elif event_name == "recoveryGuardianAccepted":
        signer = _topic_address(topics[2], "recovery guardian")
        if (
            intent.kind != "RECOVERY_KIT"
            or signer.lower() != intent.new_recovery_guardian.lower()
        ):
            raise ValueError(
                "recovery-kit acceptance came from the wrong guardian"
            )
        authorized_guardian, gas_payer, authorization_mode = (
            _verify_recovery_guardian_transaction(
                transaction=transaction,
                intent=intent,
                coordinator=coordinator,
                action="ACCEPT",
            )
        )
        if authorized_guardian.lower() != signer.lower():
            raise ValueError(
                "recovery-kit acceptance event differs from its authorization"
            )
        receipt_record.update(
            {
                "authorizationMode": authorization_mode,
                "guardianSigner": authorized_guardian,
                "gasPayer": gas_payer,
            }
        )
        case = _record_approval_once(
            store,
            case,
            role="REPLACEMENT",
            actor_id="replacement",
            signer_slot=intent.slot,
            signer_address=signer,
            transaction_hash=transaction_hash,
        )
    elif event_name == "peerCancellation":
        peer_slot = _topic_uint(topics[2], "peer cancellation slot")
        if (
            intent.kind != "LOST"
            or peer_slot not in _required_peer_slots(intent.slot)
        ):
            raise ValueError("lost-key peer cancellation is invalid")
        signer = normalize_evm_address(
            safes["identities"][peer_slot]["address"],
            "peer Identity Safe",
        )
        case = _record_approval_once(
            store,
            case,
            role="OLD_KEY_VETO",
            actor_id=f"cancel-slot-{peer_slot}",
            signer_slot=peer_slot,
            signer_address=signer,
            transaction_hash=transaction_hash,
        )
    elif event_name == "rollbackApproved":
        actor = _topic_address(topics[2], "rollback approver")
        root_safe = str(safes["root"]["address"]).lower()
        if actor.lower() == root_safe:
            role = "AUTHORITY"
            actor_id = "rollback-root"
            signer_slot = 0
        else:
            raise ValueError("rollback approval came from the wrong authority")
        cancellation_event = _receipt_event(
            receipt,
            coordinator=coordinator,
            event_name="chiaCancellationRecorded",
            intent_hash=str(case["intentHash"]),
        )
        cancellation_topics = cancellation_event.get("topics")
        chia_cancellation = next(
            (
                item
                for item in case["receipts"]
                if item["chain"] == "CHIA"
                and item["phase"] == "CANCEL"
            ),
            None,
        )
        if (
            not isinstance(cancellation_topics, list)
            or len(cancellation_topics) != 3
            or chia_cancellation is None
            or str(cancellation_topics[2]).lower()
            != str(chia_cancellation["receiptHash"]).lower()
        ):
            raise ValueError(
                "rollback approval is not bound to the Chia cancellation"
            )
        case = _record_approval_once(
            store,
            case,
            role=role,
            actor_id=actor_id,
            signer_slot=signer_slot,
            signer_address=actor,
            transaction_hash=transaction_hash,
        )
    elif event_name == "evmChanged":
        if intent.kind == "RECOVERY_KIT":
            raise ValueError("recovery-kit rotation emitted a wallet-change event")
        changed_slot = _topic_uint(topics[2], "changed slot")
        try:
            old_key, new_key = abi_decode(
                ["address", "address"],
                bytes.fromhex(str(event.get("data") or "0x")[2:]),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("EVM key-change event is malformed") from exc
        if (
            changed_slot != intent.slot
            or str(old_key).lower() != intent.old_daily_evm_key.lower()
            or str(new_key).lower() != intent.new_daily_evm_key.lower()
        ):
            raise ValueError("EVM key-change event differs from the intent")
        case = _record_receipt_once(
            store,
            case,
            chain="EVM",
            phase="EXECUTE",
            transaction_id=transaction_hash,
            receipt=receipt_record,
        )
        case = store.update_recovery_case(
            case_id,
            state="PARTIAL",
            evm_transaction_hash=transaction_hash,
        )
        _notify_administrators(
            store,
            str(case["ceremonyId"]),
            event_type="admin_key_change_partial",
            subject="Administrator recovery is waiting for Chia",
            body=(
                "The EVM identity changed. Privileged operations remain "
                "frozen until the matching Chia identity is confirmed."
            ),
        )
    elif event_name == "recoveryKitChanged":
        changed_slot = _topic_uint(topics[2], "recovery-kit slot")
        try:
            (
                old_guardian,
                new_guardian,
                old_bls_commitment,
                new_bls_commitment,
                new_revision,
            ) = abi_decode(
                ["address", "address", "bytes32", "bytes32", "uint64"],
                bytes.fromhex(str(event.get("data") or "0x")[2:]),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "EVM recovery-kit event is malformed"
            ) from exc
        expected_old_commitment = keccak(
            bytes.fromhex(intent.old_recovery_bls_key[2:])
        )
        expected_new_commitment = keccak(
            bytes.fromhex(intent.new_recovery_bls_key[2:])
        )
        if (
            intent.kind != "RECOVERY_KIT"
            or changed_slot != intent.slot
            or str(old_guardian).lower()
            != intent.old_recovery_guardian.lower()
            or str(new_guardian).lower()
            != intent.new_recovery_guardian.lower()
            or bytes(old_bls_commitment) != expected_old_commitment
            or bytes(new_bls_commitment) != expected_new_commitment
            or int(new_revision) != intent.recovery_key_revision + 1
        ):
            raise ValueError(
                "EVM recovery-kit event differs from the intent"
            )
        case = _record_receipt_once(
            store,
            case,
            chain="EVM",
            phase="EXECUTE",
            transaction_id=transaction_hash,
            receipt=receipt_record,
        )
        case = store.update_recovery_case(
            case_id,
            state="PARTIAL",
            evm_transaction_hash=transaction_hash,
        )
    elif event_name == "vetoed":
        actor = _topic_address(topics[2], "veto actor")
        allowed = {
            intent.old_daily_evm_key.lower(),
            intent.old_recovery_guardian.lower(),
            str(safes["root"]["address"]).lower(),
            *{
                str(item["address"]).lower()
                for item in safes["identities"]
            },
        }
        if actor.lower() not in allowed:
            raise ValueError("Authority V3 veto actor is invalid")
        if (
            intent.kind == "RECOVERY_KIT"
            and actor.lower() == intent.old_recovery_guardian.lower()
        ):
            authorized_guardian, gas_payer, authorization_mode = (
                _verify_recovery_guardian_transaction(
                    transaction=transaction,
                    intent=intent,
                    coordinator=coordinator,
                    action="VETO",
                )
            )
            if authorized_guardian.lower() != actor.lower():
                raise ValueError(
                    "recovery-kit veto event differs from its authorization"
                )
            receipt_record.update(
                {
                    "authorizationMode": authorization_mode,
                    "guardianSigner": authorized_guardian,
                    "gasPayer": gas_payer,
                }
            )
        case = _record_receipt_once(
            store,
            case,
            chain="EVM",
            phase="CANCEL",
            transaction_id=transaction_hash,
            receipt=receipt_record,
        )
        cancellation_complete = (
            not _case_has_receipt(case, "CHIA", "PREPARE")
            or _case_has_receipt(case, "CHIA", "CANCEL")
        )
        case = store.update_recovery_case(
            case_id,
            state="CANCELLED" if cancellation_complete else "PARTIAL",
            evm_transaction_hash=transaction_hash,
        )
        if cancellation_complete and intent.kind == "RECOVERY_KIT":
            candidate = store.pending_recovery_kit_candidate(
                str(case["ceremonyId"]),
                intent.slot + 1,
            )
            if candidate is not None:
                store.cancel_recovery_kit_candidate(
                    str(candidate["challengeId"])
                )
        _notify_administrators(
            store,
            str(case["ceremonyId"]),
            event_type="admin_key_change_cancelled",
            subject="Administrator wallet change canceled",
            body=(
                f"The wallet change for administrator slot "
                f"{intent.slot + 1} was canceled. No authority was changed."
            ),
        )
    elif event_name == "rolledBack":
        changed_slot = _topic_uint(topics[2], "rollback slot")
        try:
            (restored_key,) = abi_decode(
                ["address"],
                bytes.fromhex(str(event.get("data") or "0x")[2:]),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Authority V3 rollback event is malformed") from exc
        if (
            changed_slot != intent.slot
            or str(restored_key).lower()
            != intent.old_daily_evm_key.lower()
        ):
            raise ValueError("Authority V3 rollback differs from the intent")
        case = _record_receipt_once(
            store,
            case,
            chain="EVM",
            phase="ROLLBACK",
            transaction_id=transaction_hash,
            receipt=receipt_record,
        )
        cancellation_complete = _case_has_receipt(
            case,
            "CHIA",
            "CANCEL",
        )
        case = store.update_recovery_case(
            case_id,
            state="CANCELLED" if cancellation_complete else "PARTIAL",
            evm_transaction_hash=transaction_hash,
        )
        if cancellation_complete and intent.kind == "RECOVERY_KIT":
            candidate = store.pending_recovery_kit_candidate(
                str(case["ceremonyId"]),
                intent.slot + 1,
            )
            if candidate is not None:
                store.cancel_recovery_kit_candidate(
                    str(candidate["challengeId"])
                )
    elif event_name == "converged":
        if not isinstance(topics, list) or len(topics) != 4:
            raise ValueError("cross-chain convergence event is malformed")
        chia_receipt_hash = str(topics[2]).lower()
        changed_slot = _topic_uint(topics[3], "converged slot")
        expected_chia = next(
            (
                item
                for item in case["receipts"]
                if item["chain"] == "CHIA"
                and item["phase"] == "COMPLETE"
            ),
            None,
        )
        if (
            changed_slot != intent.slot
            or expected_chia is None
            or chia_receipt_hash
            != str(expected_chia["receiptHash"]).lower()
        ):
            raise ValueError(
                "cross-chain convergence does not match the Chia receipt"
            )
        case = _record_receipt_once(
            store,
            case,
            chain="EVM",
            phase="COMPLETE",
            transaction_id=transaction_hash,
            receipt=receipt_record,
        )
        case = store.update_recovery_case(
            case_id,
            state="COMPLETED",
            evm_transaction_hash=transaction_hash,
            evm_receipt_hash=_canonical_receipt_hash(receipt_record),
            chia_receipt_hash=str(expected_chia["receiptHash"]),
        )
        if intent.kind == "RECOVERY_KIT":
            candidate = store.pending_recovery_kit_candidate(
                str(case["ceremonyId"]),
                intent.slot + 1,
            )
            if (
                candidate is None
                or str(candidate["evmGuardian"]).lower()
                != intent.new_recovery_guardian.lower()
                or str(candidate["recoveryBlsPubkey"]).lower()
                != intent.new_recovery_bls_key.lower()
            ):
                raise ValueError(
                    "confirmed recovery-kit transition has no tested candidate"
                )
            store.activate_recovery_kit_candidate(
                str(candidate["challengeId"])
            )
        _notify_administrators(
            store,
            str(case["ceremonyId"]),
            event_type="admin_key_change_completed",
            subject="Administrator wallet change completed",
            body=(
                f"Administrator slot {intent.slot + 1} now uses the "
                "approved replacement wallet on both chains."
            ),
        )
    else:
        raise ValueError("Authority V3 action is unsupported")

    if event_name in {
        "authorityApproved",
        "peerApproved",
        "replacementAccepted",
        "recoveryGuardianAccepted",
        "peerCancellation",
        "rollbackApproved",
    }:
        case = _refresh_case_state(store, case)
    del transaction
    return await _case_view(
        case=case,
        settings=settings,
        evidence=evidence,
        store=store,
    )


async def _observe_chia_case(
    *,
    case_id: str,
    request: Request,
    settings: Settings,
    store: GenesisStore,
) -> dict[str, Any]:
    case = store.recovery_case(case_id)
    if case["state"] in TERMINAL_CASE_STATES:
        raise GenesisConflict("administrator recovery case is terminal")
    artifact, evidence, _coordinator = (
        await _verified_evidence_context(settings)
    )
    provider = getattr(request.app.state, "coinset", None)
    if provider is None:
        raise ValueError("Testnet11 Chia provider is unavailable")
    snapshot = await build_admin_authority_v3_snapshot(
        artifact=artifact,
        provider=provider,
    )
    if not snapshot.chain_verified or not snapshot.current_coin_id:
        raise ValueError("Authority V3 is not confirmed on Testnet11")
    intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
    latest_spend = str(snapshot.evidence.get("latestSpend") or "")

    if snapshot.pending:
        expected_chia_kind = (
            "ROUTINE"
            if intent.kind == "RECOVERY_KIT"
            else intent.kind
        )
        if (
            snapshot.pending_intent_hash != case["intentHash"]
            or snapshot.pending_kind != expected_chia_kind
            or snapshot.pending_slot != intent.slot
        ):
            raise ValueError(
                "Testnet11 has a different administrator key change pending"
            )
        receipt_record = {
            "schemaVersion": 1,
            "event": (
                "PREPARE_ROUTINE"
                if intent.kind in {"ROUTINE", "RECOVERY_KIT"}
                else "PREPARE_LOST"
            ),
            "network": "testnet11",
            "intentHash": case["intentHash"],
            "authorityCoinId": snapshot.current_coin_id,
            "authorityVersion": snapshot.authority_version,
            "pendingIdentityCoinId": snapshot.pending_identity_coin_id,
            "confirmedHeight": snapshot.confirmed_height,
        }
        case = _record_receipt_once(
            store,
            case,
            chain="CHIA",
            phase="PREPARE",
            transaction_id=snapshot.current_coin_id,
            receipt=receipt_record,
        )
        case = store.update_recovery_case(
            case_id,
            state="SUBMITTED",
            chia_transaction_id=snapshot.current_coin_id,
        )
        case = _refresh_case_state(store, case)
    else:
        prepared = next(
            (
                item
                for item in case["receipts"]
                if item["chain"] == "CHIA"
                and item["phase"] == "PREPARE"
            ),
            None,
        )
        if prepared is None:
            raise ValueError(
                "Testnet11 does not show this key-change preparation"
            )
        prepared_version = int(
            prepared["receipt"]["authorityVersion"]
        )
        if snapshot.authority_version != prepared_version + 1:
            raise ValueError(
                "Authority V3 version does not match one exact transition"
            )
        if latest_spend not in {"COMPLETE", "CANCEL"}:
            raise ValueError(
                "Authority V3 latest Testnet11 transition is unsupported"
            )
        phase = "COMPLETE" if latest_spend == "COMPLETE" else "CANCEL"
        receipt_record = {
            "schemaVersion": 1,
            "event": latest_spend,
            "network": "testnet11",
            "intentHash": case["intentHash"],
            "authorityCoinId": snapshot.current_coin_id,
            "authorityVersion": snapshot.authority_version,
            "confirmedHeight": snapshot.confirmed_height,
        }
        case = _record_receipt_once(
            store,
            case,
            chain="CHIA",
            phase=phase,
            transaction_id=snapshot.current_coin_id,
            receipt=receipt_record,
        )
        if phase == "COMPLETE":
            case = store.update_recovery_case(
                case_id,
                state="PARTIAL",
                chia_transaction_id=snapshot.current_coin_id,
                chia_receipt_hash=_canonical_receipt_hash(
                    receipt_record
                ),
            )
            _notify_administrators(
                store,
                str(case["ceremonyId"]),
                event_type="admin_key_change_partial",
                subject="Administrator recovery is waiting for EVM",
                body=(
                    "The Chia identity changed. Privileged operations remain "
                    "frozen until the matching EVM identity is confirmed."
                ),
            )
        else:
            evm_cancelled = (
                _case_has_receipt(case, "EVM", "CANCEL")
                or _case_has_receipt(case, "EVM", "ROLLBACK")
            )
            case = store.update_recovery_case(
                case_id,
                state="CANCELLED" if evm_cancelled else "PARTIAL",
                chia_transaction_id=snapshot.current_coin_id,
            )
            if evm_cancelled and intent.kind == "RECOVERY_KIT":
                candidate = store.pending_recovery_kit_candidate(
                    str(case["ceremonyId"]),
                    intent.slot + 1,
                )
                if candidate is not None:
                    store.cancel_recovery_kit_candidate(
                        str(candidate["challengeId"])
                    )
    return await _case_view(
        case=case,
        settings=settings,
        evidence=evidence,
        store=store,
    )


@router.post("/routine/prepare", response_model=PreparedKeyChange)
async def prepare_routine_key_change(
    body: RoutinePrepareRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> PreparedKeyChange:
    try:
        artifact, evidence, nonce = await _verified_context(settings)
        intent = _build_intent(
            artifact=artifact,
            evidence=evidence,
            slot=actor.authority_slot,
            kind="ROUTINE",
            new_daily_compressed_pubkey=body.new_daily_compressed_pubkey,
            nonce=nonce,
            now=int(time.time()),
            administrators=_current_administrators(artifact, store),
            recovery_identities=_current_recovery_identities(
                artifact,
                evidence,
                store,
            ),
        )
        if intent.old_daily_evm_key.lower() != actor.wallet.lower():
            raise ValueError("connected wallet is not the current slot wallet")
        return _prepared_response(intent, evidence)
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/lost/prepare", response_model=PreparedKeyChange)
async def prepare_lost_key_change(
    body: LostPrepareRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> PreparedKeyChange:
    try:
        artifact, evidence, nonce = await _verified_context(settings)
        if artifact_ceremony_id(artifact) != body.ceremony_id:
            raise ValueError("recovery ceremony does not match the live authority")
        kit = store.recovery_kit(body.ceremony_id, body.slot + 1)
        if (
            str(kit["evmGuardian"]).lower() != body.evm_guardian.lower()
            or str(kit["recoveryBlsPubkey"]).lower()
            != body.recovery_bls_pubkey.lower()
        ):
            raise ValueError("recovery kit does not match the enrolled slot")
        intent = _build_intent(
            artifact=artifact,
            evidence=evidence,
            slot=body.slot,
            kind="LOST",
            new_daily_compressed_pubkey=body.new_daily_compressed_pubkey,
            nonce=nonce,
            now=int(time.time()),
            administrators=_current_administrators(artifact, store),
            recovery_identities=_current_recovery_identities(
                artifact,
                evidence,
                store,
            ),
        )
        return _prepared_response(intent, evidence)
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/lost/authorize",
    response_model=LostKeyAuthorizationResponse,
)
async def authorize_lost_key_change(
    body: LostKeyAuthorizationRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> LostKeyAuthorizationResponse:
    """Turn an offline guardian signature into an exact relay transaction.

    This endpoint never signs or submits. The replacement wallet may pay gas,
    while the coordinator contract independently verifies that the offline
    guardian authorized this exact intent on this chain and contract.
    """

    try:
        if body.intent.kind != "LOST":
            raise ValueError(
                "lost-key authorization requires a lost-key intent"
            )
        artifact, evidence, nonce = await _verified_context(settings)
        if body.intent.nonce != nonce + 1:
            raise ValueError(
                "lost-key authorization nonce is no longer current"
            )
        now = int(time.time())
        prepared_at = (
            body.intent.expires_at
            - LOST_DELAY_SECONDS
            - EXECUTION_WINDOW_SECONDS
        )
        if prepared_at > now or body.intent.expires_at <= now:
            raise ValueError(
                "lost-key authorization is not currently valid"
            )
        _validate_intent_bindings(
            intent=body.intent,
            artifact=artifact,
            evidence=evidence,
            store=store,
        )
        coordinator = normalize_evm_address(
            evidence["recovery"]["address"],
            "recovery coordinator",
        )
        signer = verify_lost_guardian_authorization(
            intent=body.intent,
            coordinator=coordinator,
            guardian_signature=body.guardian_signature,
        )
        intent_hash = hash_admin_key_change_intent(body.intent)
        return LostKeyAuthorizationResponse(
            intentHash=intent_hash,
            guardianSigner=signer,
            relayTransaction={
                "chainId": AUTHORITY_EVM_CHAIN_ID,
                "to": coordinator,
                "value": "0x0",
                "data": prepare_lost_key_with_signature_calldata(
                    body.intent,
                    body.guardian_signature,
                ),
            },
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/recovery-kit/prepare", response_model=PreparedKeyChange)
async def prepare_recovery_kit_change(
    body: RecoveryKitPrepareRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> PreparedKeyChange:
    try:
        artifact, evidence, nonce = await _verified_context(settings)
        candidate = store.recovery_kit_candidate(body.challenge_id)
        if (
            candidate["ceremonyId"] != actor.ceremony_id
            or int(candidate["slot"]) != actor.authority_slot
            or candidate["state"] != "PENDING"
        ):
            raise ValueError(
                "tested recovery-kit replacement is not available for this slot"
            )
        recoveries = _current_recovery_identities(
            artifact,
            evidence,
            store,
        )
        if int(candidate["revision"]) != int(
            recoveries[actor.authority_slot]["revision"]
        ) + 1:
            raise ValueError("replacement recovery-kit revision is stale")
        intent = _build_intent(
            artifact=artifact,
            evidence=evidence,
            slot=actor.authority_slot,
            kind="RECOVERY_KIT",
            new_daily_compressed_pubkey=None,
            nonce=nonce,
            now=int(time.time()),
            administrators=_current_administrators(artifact, store),
            recovery_identities=recoveries,
            new_recovery_guardian=str(candidate["evmGuardian"]),
            new_recovery_bls_key=str(candidate["recoveryBlsPubkey"]),
        )
        if intent.old_daily_evm_key.lower() != actor.wallet.lower():
            raise ValueError("connected wallet is not the current slot wallet")
        return _prepared_response(intent, evidence)
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/{case_id}/recovery-guardian/authorize",
    response_model=RecoveryGuardianAuthorizationResponse,
)
async def authorize_recovery_guardian_action(
    case_id: str,
    body: RecoveryGuardianAuthorizationRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> RecoveryGuardianAuthorizationResponse:
    """Create a zero-value relay for one exact offline guardian action."""

    try:
        case = store.recovery_case(case_id)
        if (
            str(case["ceremonyId"]) != actor.ceremony_id
            or case["state"] in TERMINAL_CASE_STATES
            or _case_has_receipt(case, "EVM", "EXECUTE")
        ):
            raise GenesisConflict(
                "recovery-guardian action is not available for this case"
            )
        intent = AdminKeyChangeIntentV1.model_validate(case["intent"])
        if intent.kind != "RECOVERY_KIT":
            raise ValueError(
                "offline recovery-guardian actions require a recovery-kit change"
            )
        if (
            body.action == "ACCEPT"
            and _case_has_approval(case, "REPLACEMENT")
        ):
            raise GenesisConflict(
                "the replacement recovery guardian already accepted this case"
            )
        artifact, evidence, coordinator = (
            await _verified_evidence_context(settings)
        )
        _validate_intent_bindings(
            intent=intent,
            artifact=artifact,
            evidence=evidence,
            store=store,
        )
        signer = verify_recovery_guardian_action_authorization(
            intent=intent,
            coordinator=coordinator,
            action=body.action,
            guardian_signature=body.guardian_signature,
        )
        return RecoveryGuardianAuthorizationResponse(
            intentHash=str(case["intentHash"]),
            action=body.action,
            guardianSigner=signer,
            relayTransaction={
                "chainId": AUTHORITY_EVM_CHAIN_ID,
                "to": coordinator,
                "value": "0x0",
                "data": recovery_guardian_action_with_signature_calldata(
                    str(case["intentHash"]),
                    body.action,
                    body.guardian_signature,
                ),
            },
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/routine/submit")
async def submit_routine_key_change(
    body: PreparedTransactionSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    if body.intent.kind != "ROUTINE":
        raise HTTPException(
            status_code=422,
            detail="Routine submission requires a routine intent.",
        )
    try:
        return await _record_prepared_case(
            submission=body,
            settings=settings,
            store=store,
            actor=actor,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/lost/submit")
async def submit_lost_key_change(
    body: PreparedTransactionSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    if body.intent.kind != "LOST":
        raise HTTPException(
            status_code=422,
            detail="Lost-key submission requires a lost-key intent.",
        )
    try:
        return await _record_prepared_case(
            submission=body,
            settings=settings,
            store=store,
            actor=None,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/recovery-kit/submit")
async def submit_recovery_kit_change(
    body: PreparedTransactionSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    if body.intent.kind != "RECOVERY_KIT":
        raise HTTPException(
            status_code=422,
            detail="Recovery-kit submission requires a recovery-kit intent.",
        )
    try:
        return await _record_prepared_case(
            submission=body,
            settings=settings,
            store=store,
            actor=actor,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("")
async def list_key_changes(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        _artifact, evidence, _coordinator = (
            await _verified_evidence_context(settings)
        )
        cases = [
            await _case_view(
                case=case,
                settings=settings,
                evidence=evidence,
                store=store,
            )
            for case in store.recovery_cases(actor.ceremony_id)
        ]
        return {"schemaVersion": 1, "cases": cases}
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{case_id}")
async def get_key_change(
    case_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        _artifact, evidence, _coordinator = (
            await _verified_evidence_context(settings)
        )
        return await _case_view(
            case=case,
            settings=settings,
            evidence=evidence,
            store=store,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/evm/safe/package")
async def get_key_change_evm_safe_package(
    case_id: str,
    body: EvmSafeActionPackageRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        return await _build_evm_safe_action_package(
            case=case,
            body=body,
            settings=settings,
            store=store,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/evm/safe/signatures")
async def submit_key_change_evm_safe_signature(
    case_id: str,
    body: EvmSafeActionSignatureSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    """Verify and persist one exact leaf signature for a nested Safe action.

    The signature itself is authorization. This allows a newly accepted
    replacement wallet to finish cross-chain convergence before its old
    administrator session is rotated, without granting a relayer authority.
    """

    try:
        case = store.recovery_case(case_id)
        request = EvmSafeActionPackageRequest(
            actionId=body.action_id,
            coadminSlot=body.coadmin_slot,
        )
        package = await _build_evm_safe_action_package(
            case=case,
            body=request,
            settings=settings,
            store=store,
        )
        if package["packageHash"].lower() != body.package_hash.lower():
            raise GenesisConflict(
                "Safe package changed; discard the old signature and review again"
            )
        matching: list[tuple[Mapping[str, Any], Any]] = []
        for descriptor in package["approvals"]:
            recovered = recover_evm_signer(
                descriptor["typedData"],
                body.signature,
            )
            if (
                recovered.address.lower()
                == str(descriptor["signerAddress"]).lower()
                and "0x" + recovered.digest.hex()
                == str(descriptor["messageHash"]).lower()
            ):
                matching.append((descriptor, recovered))
        if len(matching) != 1:
            raise ValueError(
                "Safe signature does not match one required administrator"
            )
        descriptor, recovered = matching[0]
        _normalize_safe_eoa_signature(body.signature)
        store.add_recovery_evm_safe_signature(
            case_id,
            action_id=body.action_id,
            package_hash=body.package_hash,
            safe_nonce=int(package["safeNonce"]),
            coadmin_slot=package["coadminSlot"],
            signer_slot=int(descriptor["slot"]),
            signer_role=str(descriptor["role"]),
            signer_address=recovered.address,
            signature=body.signature,
            message_hash=str(descriptor["messageHash"]),
        )
        return await _build_evm_safe_action_package(
            case=store.recovery_case(case_id),
            body=request,
            settings=settings,
            store=store,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/evm/submissions")
async def record_key_change_evm_submission(
    case_id: str,
    body: EvmActionSubmission,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    """Persist one propagated, exact transaction before confirmation.

    The transaction is re-derived from the active case and its recorded Safe
    approvals, including the exact approved nonce.
    Recording it grants no authority; it only makes confirmation monitoring
    resumable after a browser or API restart.
    """

    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        return await _record_pending_evm_action(
            case=case,
            body=body,
            actor=actor,
            settings=settings,
            store=store,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/evm/observe")
async def observe_key_change_evm_transaction(
    case_id: str,
    body: EvmTransactionObservation,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        result = await _observe_evm_case(
            case_id=case_id,
            transaction_hash=body.transaction_hash,
            settings=settings,
            store=store,
        )
        store.confirm_recovery_evm_submission(
            case_id,
            transaction_hash=body.transaction_hash,
        )
        result["evmSubmissions"] = store.recovery_evm_submissions(case_id)
        return result
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/chia/observe")
async def observe_key_change_chia_transaction(
    case_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        return await _observe_chia_case(
            case_id=case_id,
            request=request,
            settings=settings,
            store=store,
        )
    except (GenesisStoreError, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


async def _build_chia_package(
    *,
    case: Mapping[str, Any],
    body: ChiaActionPackageRequest,
    request: Request,
    settings: Settings,
    store: GenesisStore,
) -> tuple[_ChiaRecoveryBuild, Optional[SpendBundle], list[_ChiaSigningAction]]:
    build = await _chia_recovery_build(
        case=case,
        phase=body.phase,
        coadmin_slot=body.coadmin_slot,
        request=request,
        settings=settings,
        store=store,
    )
    if body.phase == "PREPARE":
        bundle, actions = _signed_prepare_bundle(
            build=build,
            store=store,
        )
    elif body.phase == "CANCEL":
        bundle, actions = _signed_cancel_bundle(
            build=build,
            store=store,
        )
    else:
        bundle = _complete_bundle(build)
        actions = []
    return build, bundle, actions


@router.post("/{case_id}/chia/package")
async def get_key_change_chia_package(
    case_id: str,
    body: ChiaActionPackageRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        build, bundle, actions = await _build_chia_package(
            case=case,
            body=body,
            request=request,
            settings=settings,
            store=store,
        )
        return _chia_package_view(
            build=build,
            phase=body.phase,
            bundle=bundle,
            actions=actions,
            store=store,
        )
    except (
        GenesisStoreError,
        ProtocolSubmissionError,
        ValueError,
        httpx.HTTPError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/chia/signatures")
async def submit_key_change_chia_signature(
    case_id: str,
    body: ChiaActionSignatureSubmission,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
) -> dict[str, Any]:
    """Verify one exact wallet signature.

    The replacement or offline recovery wallet is not yet an enrolled
    administrator. Its valid signature over the immutable action is therefore
    the authorization for this endpoint; package inspection and broadcast
    still require an administrator session.
    """

    try:
        case = store.recovery_case(case_id)
        package_request = ChiaActionPackageRequest(
            phase=body.phase,
            coadminSlot=body.coadmin_slot,
        )
        build, _bundle, actions = await _build_chia_package(
            case=case,
            body=package_request,
            request=request,
            settings=settings,
            store=store,
        )
        action = next(
            (
                candidate
                for candidate in actions
                if candidate.action_id == body.action_id
            ),
            None,
        )
        if action is None:
            raise ValueError(
                "signature action is stale or not yet available"
            )
        raw_signature = bytes.fromhex(body.signature[2:])
        if action.signer_kind == "EIP712_DAILY":
            normalize_eip712_member_signature(
                signature=raw_signature,
                digest=_bytes32_hex(
                    action.message_hash,
                    "action message hash",
                ),
                compressed_pubkey=bytes.fromhex(
                    action.signer_public_key[2:]
                ),
            )
        else:
            if len(raw_signature) != 96:
                raise ValueError(
                    "lost-key recovery requires a 96-byte BLS signature"
                )
            try:
                signature = G2Element.from_bytes(raw_signature)
                public_keys = [
                    G1Element.from_bytes(bytes.fromhex(public_key[2:]))
                    for public_key, _message in action.bls_pairs
                ]
                messages = [
                    bytes.fromhex(message[2:])
                    for _public_key, message in action.bls_pairs
                ]
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "lost-key recovery signature is malformed"
                ) from exc
            if not public_keys or not AugSchemeMPL.aggregate_verify(
                public_keys,
                messages,
                signature,
            ):
                raise ValueError(
                    "lost-key recovery signature does not authorize "
                    "the exact Testnet11 bundle"
                )
        store.add_recovery_chia_signature(
            case_id,
            phase=body.phase,
            action_id=action.action_id,
            signer_kind=action.signer_kind,
            signer_slot=action.signer_slot,
            signer_public_key=action.signer_public_key,
            signature=body.signature,
            message_hash=action.message_hash,
        )
        refreshed_build, refreshed_bundle, refreshed_actions = (
            await _build_chia_package(
                case=store.recovery_case(case_id),
                body=package_request,
                request=request,
                settings=settings,
                store=store,
            )
        )
        return _chia_package_view(
            build=refreshed_build,
            phase=body.phase,
            bundle=refreshed_bundle,
            actions=refreshed_actions,
            store=store,
        )
    except (
        GenesisStoreError,
        ProtocolSubmissionError,
        ValueError,
        httpx.HTTPError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{case_id}/chia/submit")
async def submit_key_change_chia_package(
    case_id: str,
    body: ChiaActionPackageRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[GenesisStore, Depends(get_genesis_store)],
    actor: Annotated[SecurityActor, Depends(require_security_actor)],
) -> dict[str, Any]:
    try:
        case = store.recovery_case(case_id)
        if case["ceremonyId"] != actor.ceremony_id:
            raise GenesisNotFound("administrator recovery case not found")
        build, bundle, actions = await _build_chia_package(
            case=case,
            body=body,
            request=request,
            settings=settings,
            store=store,
        )
        package = _chia_package_view(
            build=build,
            phase=body.phase,
            bundle=bundle,
            actions=actions,
            store=store,
        )
        if bundle is None or package["readyToSubmit"] is not True:
            raise GenesisConflict(
                "all required signatures and delays are not complete"
            )
        provider = getattr(request.app.state, "coinset", None)
        if provider is None:
            raise ValueError("Testnet11 Chia provider is unavailable")
        for spend in bundle.coin_spends:
            pending = await provider.get_mempool_items_by_coin_name(
                _hex32(spend.coin.name())
            )
            if pending:
                raise GenesisConflict(
                    "this Authority V3 transition is already pending "
                    "in the local mempool"
                )
        submitter = getattr(
            request.app.state,
            "protocol_submitter",
            None,
        )
        if not isinstance(submitter, ProtocolBundleSubmitter):
            raise ProtocolSubmissionError(
                "protocol fee-till submission is unavailable"
            )
        submission = await submitter.submit(bundle.to_json_dict())
        store.update_recovery_case(
            case_id,
            state="SUBMITTED",
            chia_transaction_id=str(submission["spendBundleId"]),
        )
        return {
            **package,
            "submission": {
                key: submission[key]
                for key in (
                    "status",
                    "network",
                    "spendBundleId",
                    "feeMojos",
                    "feeTargetSeconds",
                    "submissionProvider",
                    "mempoolObservedAt",
                    "ambiguousPushRecovered",
                )
            },
        }
    except (
        GenesisStoreError,
        ProtocolSubmissionError,
        ValueError,
        httpx.HTTPError,
    ) as exc:
        status_code = (
            503
            if isinstance(exc, ProtocolSubmissionError)
            and not isinstance(exc, GenesisConflict)
            else 409
        )
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


def verify_lost_recovery_bls_signature(
    *,
    intent: AdminKeyChangeIntentV1,
    recovery_bls_pubkey: str,
    signature: str,
) -> None:
    if intent.kind != "LOST":
        raise ValueError("recovery BLS proof is only valid for lost-key recovery")
    try:
        public_key = G1Element.from_bytes(
            bytes.fromhex(_hex_value(recovery_bls_pubkey, 96, "recovery key")[2:])
        )
        parsed_signature = G2Element.from_bytes(
            bytes.fromhex(_hex_value(signature, 192, "recovery signature")[2:])
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("recovery BLS proof is malformed") from exc
    if not AugSchemeMPL.verify(
        public_key,
        recovery_intent_bls_digest(hash_admin_key_change_intent(intent)),
        parsed_signature,
    ):
        raise ValueError("recovery BLS proof is invalid")


__all__ = [
    "AdminKeyChangeIntentV1",
    "EvmTransactionObservation",
    "LostKeyAuthorizationRequest",
    "LostKeyAuthorizationResponse",
    "PreparedKeyChange",
    "RecoveryGuardianAuthorizationRequest",
    "RecoveryGuardianAuthorizationResponse",
    "hash_admin_key_change_intent",
    "lost_key_authorization_typed_data",
    "prepare_key_change_calldata",
    "prepare_lost_key_with_signature_calldata",
    "recovery_guardian_action_typed_data",
    "recovery_guardian_action_with_signature_calldata",
    "recovery_intent_bls_digest",
    "router",
    "verify_lost_guardian_authorization",
    "verify_lost_recovery_bls_signature",
    "verify_recovery_guardian_action_authorization",
]
