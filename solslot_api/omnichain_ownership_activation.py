"""Administrator signing surface for the sealed Base ownership handoff.

The two stored approvals are the actual nested Safe ``SafeMessage`` signatures.
There is no second Solslot-specific approval envelope and the API never holds a
relayer or administrator private key. Any connected administrator may pay gas
for the byte-exact Root Safe transaction after both required signatures exist.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Mapping, Optional

from eth_abi import encode
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from web3 import Web3
from web3.exceptions import TransactionNotFound

from .admin_auth import require_admin_jwt
from .config import Settings, get_settings
from .evm_auth import normalize_evm_address, recover_evm_signer
from .timelock_operation import (
    TimelockOperationError,
    decode_ownership_schedule,
    encode_ownership_execute,
    validate_ownership_execute,
)


MAX_OPERATION_BYTES = 128 * 1024
PAYMENT_NETWORKS = {8453: "baseMainnet", 84532: "baseSepolia"}
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
REQUIRED_ROLES = ("owner_identity", "coadmin")
_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")

_SAFE_ABI = [
    {
        "type": "function",
        "name": "nonce",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "getTransactionHash",
        "stateMutability": "view",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "data", "type": "bytes"},
            {"name": "operation", "type": "uint8"},
            {"name": "safeTxGas", "type": "uint256"},
            {"name": "baseGas", "type": "uint256"},
            {"name": "gasPrice", "type": "uint256"},
            {"name": "gasToken", "type": "address"},
            {"name": "refundReceiver", "type": "address"},
            {"name": "_nonce", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "encodeTransactionData",
        "stateMutability": "view",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "data", "type": "bytes"},
            {"name": "operation", "type": "uint8"},
            {"name": "safeTxGas", "type": "uint256"},
            {"name": "baseGas", "type": "uint256"},
            {"name": "gasPrice", "type": "uint256"},
            {"name": "gasToken", "type": "address"},
            {"name": "refundReceiver", "type": "address"},
            {"name": "_nonce", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bytes"}],
    },
]
_TIMELOCK_ABI = [
    {
        "type": "function",
        "name": "isOperation",
        "stateMutability": "view",
        "inputs": [{"name": "id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isOperationReady",
        "stateMutability": "view",
        "inputs": [{"name": "id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "isOperationDone",
        "stateMutability": "view",
        "inputs": [{"name": "id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "getTimestamp",
        "stateMutability": "view",
        "inputs": [{"name": "id", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]


class OwnershipActivationError(RuntimeError):
    """The sealed handoff package or live chain state failed validation."""


class SignatureRequest(BaseModel):
    signature: str = Field(min_length=132, max_length=132)


class BroadcastRequest(BaseModel):
    transaction_hash: str = Field(alias="transactionHash", min_length=66, max_length=66)


@dataclass(frozen=True)
class ChainState:
    operation_exists: bool
    operation_ready: bool
    operation_done: bool
    operation_timestamp: int
    live_nonce: int
    live_transaction_hash: str
    latest_block: int

    @property
    def package_is_current(self) -> bool:
        return not self.operation_exists


class OwnershipActivationStore:
    """Small append-only approval ledger in the existing admin SQLite store."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _ensure_schema(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS omnichain_safe_approvals (
                    package_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    signer_address TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signed_at INTEGER NOT NULL,
                    PRIMARY KEY (package_hash, role)
                );
                CREATE TABLE IF NOT EXISTS omnichain_safe_broadcasts (
                    package_hash TEXT PRIMARY KEY,
                    transaction_hash TEXT NOT NULL UNIQUE,
                    submitted_by TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    confirmed_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS omnichain_safe_submissions (
                    package_hash TEXT PRIMARY KEY,
                    transaction_hash TEXT NOT NULL UNIQUE,
                    submitted_by TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS omnichain_safe_derived_packages (
                    parent_package_hash TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    package_hash TEXT NOT NULL UNIQUE,
                    package_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (parent_package_hash, phase)
                );
                """
            )

    def approvals(self, package_hash: str) -> dict[str, dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT role, signer_address, signature, signed_at
                FROM omnichain_safe_approvals
                WHERE package_hash = ?
                ORDER BY role
                """,
                (package_hash,),
            ).fetchall()
        return {
            row["role"]: {
                "role": row["role"],
                "signerAddress": row["signer_address"],
                "signature": row["signature"],
                "signedAt": int(row["signed_at"]),
            }
            for row in rows
        }

    def add_approval(
        self,
        *,
        package_hash: str,
        role: str,
        signer_address: str,
        signature: str,
        now: int,
    ) -> None:
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                """
                SELECT signer_address, signature
                FROM omnichain_safe_approvals
                WHERE package_hash = ? AND role = ?
                """,
                (package_hash, role),
            ).fetchone()
            if existing:
                if (
                    existing["signer_address"].lower() == signer_address.lower()
                    and existing["signature"].lower() == signature.lower()
                ):
                    return
                raise ValueError(f"{role} approval is already sealed")
            connection.execute(
                """
                INSERT INTO omnichain_safe_approvals
                    (package_hash, role, signer_address, signature, signed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (package_hash, role, signer_address, signature, now),
            )

    def broadcast(self, package_hash: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT transaction_hash, submitted_by, submitted_at,
                       block_number, confirmed_at
                FROM omnichain_safe_broadcasts
                WHERE package_hash = ?
                """,
                (package_hash,),
            ).fetchone()
        if not row:
            return None
        return {
            "transactionHash": row["transaction_hash"],
            "submittedBy": row["submitted_by"],
            "submittedAt": int(row["submitted_at"]),
            "blockNumber": int(row["block_number"]),
            "confirmedAt": (
                int(row["confirmed_at"]) if row["confirmed_at"] is not None else None
            ),
        }

    def record_broadcast(
        self,
        *,
        package_hash: str,
        transaction_hash: str,
        submitted_by: str,
        block_number: int,
        confirmations: int,
        minimum_confirmations: int,
        now: int,
    ) -> None:
        confirmed_at = now if confirmations >= minimum_confirmations else None
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                """
                SELECT transaction_hash
                FROM omnichain_safe_broadcasts
                WHERE package_hash = ?
                """,
                (package_hash,),
            ).fetchone()
            if existing and existing["transaction_hash"].lower() != transaction_hash.lower():
                raise ValueError("a different ownership transaction is already recorded")
            connection.execute(
                """
                INSERT INTO omnichain_safe_broadcasts
                    (package_hash, transaction_hash, submitted_by, submitted_at,
                     block_number, confirmed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(package_hash) DO UPDATE SET
                    confirmed_at = COALESCE(
                        omnichain_safe_broadcasts.confirmed_at,
                        excluded.confirmed_at
                    )
                """,
                (
                    package_hash,
                    transaction_hash,
                    submitted_by,
                    now,
                    block_number,
                    confirmed_at,
                ),
            )

    def submission(self, package_hash: str) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT transaction_hash, submitted_by, submitted_at
                FROM omnichain_safe_submissions
                WHERE package_hash = ?
                """,
                (package_hash,),
            ).fetchone()
        if not row:
            return None
        return {
            "transactionHash": row["transaction_hash"],
            "submittedBy": row["submitted_by"],
            "submittedAt": int(row["submitted_at"]),
        }

    def record_submission(
        self,
        *,
        package_hash: str,
        transaction_hash: str,
        submitted_by: str,
        now: int,
    ) -> None:
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                """
                SELECT transaction_hash
                FROM omnichain_safe_submissions
                WHERE package_hash = ?
                """,
                (package_hash,),
            ).fetchone()
            if existing and existing["transaction_hash"].lower() != transaction_hash.lower():
                raise ValueError("a different ownership transaction is already submitted")
            connection.execute(
                """
                INSERT INTO omnichain_safe_submissions
                    (package_hash, transaction_hash, submitted_by, submitted_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(package_hash) DO NOTHING
                """,
                (package_hash, transaction_hash, submitted_by, now),
            )

    def derived_package(
        self, *, parent_package_hash: str, phase: str
    ) -> Optional[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT package_hash, package_json
                FROM omnichain_safe_derived_packages
                WHERE parent_package_hash = ? AND phase = ?
                """,
                (parent_package_hash, phase),
            ).fetchone()
        if not row:
            return None
        try:
            package = json.loads(row["package_json"])
        except json.JSONDecodeError as exc:
            raise OwnershipActivationError(
                "stored ownership execute package is invalid"
            ) from exc
        if (
            not isinstance(package, dict)
            or package.get("artifactHash") != row["package_hash"]
        ):
            raise OwnershipActivationError(
                "stored ownership execute package hash mismatches"
            )
        return package

    def record_derived_package(
        self,
        *,
        parent_package_hash: str,
        phase: str,
        package: Mapping[str, Any],
        now: int,
    ) -> None:
        package_hash = _require_hash(
            package.get("artifactHash"), "derived package artifactHash"
        )
        encoded = json.dumps(
            dict(package),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with self._lock, self._connect() as connection:
            existing = connection.execute(
                """
                SELECT package_hash, package_json
                FROM omnichain_safe_derived_packages
                WHERE parent_package_hash = ? AND phase = ?
                """,
                (parent_package_hash, phase),
            ).fetchone()
            if existing:
                if (
                    existing["package_hash"] == package_hash
                    and existing["package_json"] == encoded
                ):
                    return
                raise ValueError(
                    "a different ownership execute package is already sealed"
                )
            connection.execute(
                """
                INSERT INTO omnichain_safe_derived_packages
                    (parent_package_hash, phase, package_hash, package_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (parent_package_hash, phase, package_hash, encoded, now),
            )


_store: OwnershipActivationStore | None = None
_store_path: str | None = None


def get_ownership_activation_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> OwnershipActivationStore:
    global _store, _store_path
    if _store is None or _store_path != settings.admin_db_path:
        _store = OwnershipActivationStore(settings.admin_db_path)
        _store_path = settings.admin_db_path
    return _store


def _canonical_hash(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()


def _require_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise OwnershipActivationError(f"{label} must be a 32-byte hash")
    return value.lower()


def _require_address(value: object, label: str) -> str:
    try:
        return normalize_evm_address(str(value), label)
    except ValueError as exc:
        raise OwnershipActivationError(str(exc)) from exc


def _require_decimal(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.isdigit():
        raise OwnershipActivationError(f"{label} must be an unsigned decimal string")
    return int(value)


def _require_hex_bytes(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise OwnershipActivationError(f"{label} must be even-length 0x hex")
    return value.lower()


def _typed_data_digest(typed_data: Mapping[str, Any]) -> str:
    try:
        signable = encode_typed_data(full_message=dict(typed_data))
    except (TypeError, ValueError) as exc:
        raise OwnershipActivationError("SafeMessage typed data is invalid") from exc
    return "0x" + keccak(
        b"\x19" + bytes(signable.version) + signable.header + signable.body
    ).hex()


def _validate_approval(
    value: object,
    *,
    chain_id: int,
    transaction_data: str,
    schema_version: int = 1,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OwnershipActivationError("Safe approval descriptor must be an object")
    role = value.get("role")
    if role not in REQUIRED_ROLES:
        raise OwnershipActivationError("Safe approval role is unsupported")
    safe = _require_address(value.get("safe"), f"{role}.safe")
    parent = value.get("parentSafe")
    if schema_version == 2 and role == "coadmin":
        parent = _require_address(parent, "coadmin.parentSafe")
        if parent.lower() in (safe.lower(), ZERO_ADDRESS):
            raise OwnershipActivationError("coadministrator parent Safe is invalid")
        transaction_data = _safe_message_data(chain_id, parent, transaction_data)
    elif parent is not None:
        raise OwnershipActivationError("unexpected parent Safe in approval")
    allowed_raw = value.get("allowedSigners")
    if not isinstance(allowed_raw, list) or not allowed_raw:
        raise OwnershipActivationError(f"{role}.allowedSigners must not be empty")
    allowed = [_require_address(item, f"{role}.allowedSigners") for item in allowed_raw]
    if len({item.lower() for item in allowed}) != len(allowed):
        raise OwnershipActivationError(f"{role}.allowedSigners contains duplicates")
    if schema_version == 2 and len(allowed) != 1:
        raise OwnershipActivationError("each Authority V3 identity has exactly one daily signer")
    typed_data = value.get("typedData")
    if not isinstance(typed_data, Mapping) or set(typed_data) != {
        "domain",
        "types",
        "primaryType",
        "message",
    }:
        raise OwnershipActivationError(f"{role}.typedData shape is invalid")
    expected_typed_data = {
        "domain": {"chainId": chain_id, "verifyingContract": safe},
        "types": {"SafeMessage": [{"name": "message", "type": "bytes"}]},
        "primaryType": "SafeMessage",
        "message": {"message": transaction_data},
    }
    if json.dumps(typed_data, sort_keys=True).lower() != json.dumps(
        expected_typed_data, sort_keys=True
    ).lower():
        raise OwnershipActivationError(f"{role}.typedData changed after sealing")
    message_hash = _require_hash(value.get("messageHash"), f"{role}.messageHash")
    if _typed_data_digest(typed_data) != message_hash:
        raise OwnershipActivationError(f"{role}.messageHash mismatches typed data")
    return {
        "role": role,
        "safe": safe,
        "allowedSigners": allowed,
        "messageHash": message_hash,
        "typedData": dict(typed_data),
        **({"parentSafe": parent} if parent else {}),
    }


def _safe_message_data(chain_id: int, safe: str, message: str) -> str:
    """Safe CompatibilityFallbackHandler's encodeMessageDataForSafe bytes."""
    encoded = encode_typed_data(full_message={
        "domain": {"chainId": chain_id, "verifyingContract": safe},
        "types": {"SafeMessage": [{"name": "message", "type": "bytes"}]},
        "primaryType": "SafeMessage", "message": {"message": message},
    })
    return "0x" + (b"\x19" + encoded.version + encoded.header + encoded.body).hex()


def _validate_v3_approval_topology(settings: Settings, package: Mapping[str, Any], approvals: list[dict[str, Any]]) -> None:
    from .authority_v3_evidence import load_governance_evidence

    try:
        governance = load_governance_evidence(settings)
        identities = governance["safes"]["identities"]
        owner = next(a for a in approvals if a["role"] == "owner_identity")
        coadmin = next(a for a in approvals if a["role"] == "coadmin")
        selected = next(s for s in identities[1:] if s["address"].lower() == coadmin["safe"].lower())
        if (
            governance["artifactHash"] != package["governanceArtifactHash"]
            or governance["safes"]["root"]["address"].lower() != package["rootSafe"].lower()
            or governance["timelock"]["address"].lower() != package["timelock"].lower()
            or owner["safe"].lower() != identities[0]["address"].lower()
            or owner.get("parentSafe") is not None
            or coadmin["parentSafe"].lower() != governance["safes"]["coadmin"]["address"].lower()
            or [x.lower() for x in owner["allowedSigners"]] != [x.lower() for x in identities[0]["owners"]]
            or [x.lower() for x in coadmin["allowedSigners"]] != [x.lower() for x in selected["owners"]]
        ):
            raise ValueError("mismatch")
    except (ValueError, KeyError, TypeError, StopIteration, AttributeError) as exc:
        raise OwnershipActivationError("Authority V3 approvals differ from the sealed governance topology") from exc


def load_authority_operation(
    settings: Settings, *, phase: str = "schedule"
) -> dict[str, Any]:
    """Load and strictly validate one immutable Safe operation package."""

    if phase == "schedule":
        path_value = settings.payment_omnichain_ownership_safe_operation_path
        expected_hash = settings.payment_omnichain_ownership_safe_operation_hash
    elif phase == "execute":
        path_value = settings.payment_omnichain_ownership_execute_operation_path
        expected_hash = settings.payment_omnichain_ownership_execute_operation_hash
    else:
        raise OwnershipActivationError("ownership activation phase is unsupported")
    if not path_value or not expected_hash:
        raise OwnershipActivationError("ownership activation package is not configured")
    expected_hash = _require_hash(expected_hash, "configured package hash")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise OwnershipActivationError("ownership activation package is unavailable")
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_OPERATION_BYTES:
            raise OwnershipActivationError("ownership activation package size is invalid")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OwnershipActivationError("ownership activation package is invalid") from exc
    if not isinstance(raw, Mapping):
        raise OwnershipActivationError("ownership activation package must be an object")
    package = dict(raw)
    declared_hash = _require_hash(
        package.pop("artifactHash", None), "ownership activation artifactHash"
    )
    if declared_hash != expected_hash or _canonical_hash(package) != declared_hash:
        raise OwnershipActivationError("ownership activation package hash mismatches")
    package["artifactHash"] = declared_hash
    if (
        package.get("schemaVersion") not in (1, 2)
        or package.get("kind") != "solslot-safe-authority-operation"
        or package.get("network") != PAYMENT_NETWORKS[settings.payment_omnichain_chain_id]
        or type(package.get("chainId")) is not int
        or package.get("chainId") != settings.payment_omnichain_chain_id
        or package.get("phase") != phase
        or not isinstance(package.get("sourceSha"), str)
        or not _SHA_RE.fullmatch(package["sourceSha"])
    ):
        raise OwnershipActivationError("ownership activation package schema is unsupported")
    for field in (
        "deploymentArtifactHash",
        "ownershipIntentArtifactHash",
        "governanceArtifactHash",
        "operationId",
    ):
        package[field] = _require_hash(package.get(field), field)
    package["rootSafe"] = _require_address(package.get("rootSafe"), "rootSafe")
    package["timelock"] = _require_address(package.get("timelock"), "timelock")
    authority = package.get("authorityOperation")
    if not isinstance(authority, Mapping):
        raise OwnershipActivationError("authorityOperation is invalid")
    if (
        authority.get("phase") != phase
        or _require_address(authority.get("rootSafe"), "authorityOperation.rootSafe").lower()
        != package["rootSafe"].lower()
    ):
        raise OwnershipActivationError("authorityOperation root Safe changed")
    transaction = authority.get("transaction")
    if not isinstance(transaction, Mapping):
        raise OwnershipActivationError("authorityOperation.transaction is invalid")
    validated_transaction = {
        "to": _require_address(transaction.get("to"), "transaction.to"),
        "value": str(_require_decimal(transaction.get("value"), "transaction.value")),
        "data": _require_hex_bytes(transaction.get("data"), "transaction.data"),
        "operation": transaction.get("operation"),
        "safeTxGas": str(
            _require_decimal(transaction.get("safeTxGas"), "transaction.safeTxGas")
        ),
        "baseGas": str(_require_decimal(transaction.get("baseGas"), "transaction.baseGas")),
        "gasPrice": str(
            _require_decimal(transaction.get("gasPrice"), "transaction.gasPrice")
        ),
        "gasToken": _require_address(transaction.get("gasToken"), "transaction.gasToken"),
        "refundReceiver": _require_address(
            transaction.get("refundReceiver"), "transaction.refundReceiver"
        ),
        "nonce": str(_require_decimal(transaction.get("nonce"), "transaction.nonce")),
    }
    if (
        validated_transaction["to"].lower() != package["timelock"].lower()
        or validated_transaction["value"] != "0"
        or validated_transaction["operation"] != 0
        or validated_transaction["safeTxGas"] != "0"
        or validated_transaction["baseGas"] != "0"
        or validated_transaction["gasPrice"] != "0"
        or validated_transaction["gasToken"].lower() != ZERO_ADDRESS
        or validated_transaction["refundReceiver"].lower() != ZERO_ADDRESS
    ):
        raise OwnershipActivationError("Root Safe transaction terms are not alpha-safe")
    transaction_data = _require_hex_bytes(
        authority.get("transactionData"), "authorityOperation.transactionData"
    )
    transaction_hash = _require_hash(
        authority.get("transactionHash"), "authorityOperation.transactionHash"
    )
    try:
        if phase == "schedule":
            schedule = decode_ownership_schedule(
                validated_transaction["data"],
                expected_operation_id=package["operationId"],
            )
        else:
            schedule_package = load_authority_operation(settings, phase="schedule")
            if (
                schedule_package["operationId"] != package["operationId"]
                or schedule_package["rootSafe"].lower() != package["rootSafe"].lower()
                or schedule_package["timelock"].lower() != package["timelock"].lower()
            ):
                raise OwnershipActivationError(
                    "ownership execute package does not match the reviewed schedule"
                )
            schedule = decode_ownership_schedule(
                schedule_package["authorityOperation"]["transaction"]["data"],
                expected_operation_id=package["operationId"],
            )
            validate_ownership_execute(
                validated_transaction["data"],
                schedule=schedule,
            )
    except TimelockOperationError as exc:
        raise OwnershipActivationError(str(exc)) from exc
    approvals_raw = authority.get("approvals")
    if not isinstance(approvals_raw, list) or len(approvals_raw) != 2:
        raise OwnershipActivationError("exactly two nested Safe approvals are required")
    approvals = [
        _validate_approval(
            value,
            chain_id=package["chainId"],
            transaction_data=transaction_data,
            schema_version=package["schemaVersion"],
        )
        for value in approvals_raw
    ]
    if {value["role"] for value in approvals} != set(REQUIRED_ROLES):
        raise OwnershipActivationError("owner identity and coadmin approvals are required")
    child_safes = [value.get("parentSafe", value["safe"]).lower() for value in approvals]
    if len(set(child_safes)) != 2:
        raise OwnershipActivationError("nested Safe approval domains must be unique")
    if package["schemaVersion"] == 2:
        _validate_v3_approval_topology(settings, package, approvals)
    authority = dict(authority)
    authority["transaction"] = validated_transaction
    authority["transactionData"] = transaction_data
    authority["transactionHash"] = transaction_hash
    authority["approvals"] = approvals
    authority["review"] = {
        "action": "acceptOwnership" if phase == "schedule" else "executeAcceptOwnership",
        "targets": list(schedule.targets),
        "delaySeconds": schedule.delay_seconds,
        "operationId": schedule.operation_id,
    }
    package["authorityOperation"] = authority
    return package


def _transaction_arguments(package: Mapping[str, Any]) -> list[Any]:
    transaction = package["authorityOperation"]["transaction"]
    return [
        transaction["to"],
        int(transaction["value"]),
        bytes.fromhex(transaction["data"][2:]),
        int(transaction["operation"]),
        int(transaction["safeTxGas"]),
        int(transaction["baseGas"]),
        int(transaction["gasPrice"]),
        transaction["gasToken"],
        transaction["refundReceiver"],
        int(transaction["nonce"]),
    ]


def _web3(settings: Settings) -> Web3:
    rpc_url = settings.payment_omnichain_rpc_url
    if not rpc_url or not rpc_url.startswith("https://"):
        raise OwnershipActivationError("Payment-chain HTTPS RPC is not configured")
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20.0}))
    try:
        chain_id = w3.eth.chain_id
    except Exception as exc:
        raise OwnershipActivationError("Payment RPC chain could not be verified") from exc
    if chain_id != settings.payment_omnichain_chain_id:
        raise OwnershipActivationError("Payment RPC is on the wrong EVM network")
    return w3


def _chain_state(settings: Settings, package: Mapping[str, Any]) -> ChainState:
    w3 = _web3(settings)
    try:
        root_safe = w3.eth.contract(
            address=Web3.to_checksum_address(package["rootSafe"]),
            abi=_SAFE_ABI,
        )
        timelock = w3.eth.contract(
            address=Web3.to_checksum_address(package["timelock"]),
            abi=_TIMELOCK_ABI,
        )
        operation_id = package["operationId"]
        operation_exists = bool(timelock.functions.isOperation(operation_id).call())
        operation_ready = bool(timelock.functions.isOperationReady(operation_id).call())
        operation_done = bool(timelock.functions.isOperationDone(operation_id).call())
        operation_timestamp = int(timelock.functions.getTimestamp(operation_id).call())
        live_nonce = int(root_safe.functions.nonce().call())
        live_hash = root_safe.functions.getTransactionHash(
            *_transaction_arguments(package)
        ).call()
        latest_block = int(w3.eth.block_number)
    except Exception as exc:  # noqa: BLE001
        raise OwnershipActivationError(
            "Payment-chain Safe/timelock state could not be independently verified"
        ) from exc
    live_hash_hex = Web3.to_hex(live_hash).lower()
    should_validate_package = (
        package["phase"] == "schedule" and not operation_exists
    ) or (
        package["phase"] == "execute" and operation_exists and not operation_done
    )
    if should_validate_package and (
        live_nonce != int(package["authorityOperation"]["transaction"]["nonce"])
        or live_hash_hex != package["authorityOperation"]["transactionHash"]
    ):
        raise OwnershipActivationError(
            "Root Safe nonce or transaction hash changed after package review"
        )
    return ChainState(
        operation_exists=operation_exists,
        operation_ready=operation_ready,
        operation_done=operation_done,
        operation_timestamp=operation_timestamp,
        live_nonce=live_nonce,
        live_transaction_hash=live_hash_hex,
        latest_block=latest_block,
    )


def _validate_derived_execute_package(
    package_value: Mapping[str, Any],
    *,
    schedule_package: Mapping[str, Any],
) -> dict[str, Any]:
    package = dict(package_value)
    declared_hash = _require_hash(
        package.pop("artifactHash", None), "ownership execution artifactHash"
    )
    if _canonical_hash(package) != declared_hash:
        raise OwnershipActivationError(
            "stored ownership execute package hash mismatches"
        )
    package["artifactHash"] = declared_hash
    matching_fields = (
        "schemaVersion",
        "kind",
        "deploymentArtifactHash",
        "ownershipIntentArtifactHash",
        "governanceArtifactHash",
        "sourceSha",
        "network",
        "chainId",
        "operationId",
        "rootSafe",
        "timelock",
    )
    if (
        package.get("phase") != "execute"
        or package.get("derivedFromScheduleArtifactHash")
        != schedule_package["artifactHash"]
        or any(package.get(field) != schedule_package.get(field) for field in matching_fields)
    ):
        raise OwnershipActivationError(
            "stored ownership execute package does not match the reviewed schedule"
        )
    schedule = decode_ownership_schedule(
        schedule_package["authorityOperation"]["transaction"]["data"],
        expected_operation_id=schedule_package["operationId"],
    )
    authority = package.get("authorityOperation")
    if not isinstance(authority, Mapping):
        raise OwnershipActivationError("authorityOperation is invalid")
    transaction = authority.get("transaction")
    if not isinstance(transaction, Mapping):
        raise OwnershipActivationError("authorityOperation.transaction is invalid")
    validated_transaction = {
        "to": _require_address(transaction.get("to"), "transaction.to"),
        "value": str(_require_decimal(transaction.get("value"), "transaction.value")),
        "data": _require_hex_bytes(transaction.get("data"), "transaction.data"),
        "operation": transaction.get("operation"),
        "safeTxGas": str(
            _require_decimal(transaction.get("safeTxGas"), "transaction.safeTxGas")
        ),
        "baseGas": str(_require_decimal(transaction.get("baseGas"), "transaction.baseGas")),
        "gasPrice": str(
            _require_decimal(transaction.get("gasPrice"), "transaction.gasPrice")
        ),
        "gasToken": _require_address(transaction.get("gasToken"), "transaction.gasToken"),
        "refundReceiver": _require_address(
            transaction.get("refundReceiver"), "transaction.refundReceiver"
        ),
        "nonce": str(_require_decimal(transaction.get("nonce"), "transaction.nonce")),
    }
    if (
        authority.get("phase") != "execute"
        or _require_address(
            authority.get("rootSafe"), "authorityOperation.rootSafe"
        ).lower()
        != str(package["rootSafe"]).lower()
        or validated_transaction["to"].lower() != str(package["timelock"]).lower()
        or validated_transaction["value"] != "0"
        or validated_transaction["operation"] != 0
        or validated_transaction["safeTxGas"] != "0"
        or validated_transaction["baseGas"] != "0"
        or validated_transaction["gasPrice"] != "0"
        or validated_transaction["gasToken"].lower() != ZERO_ADDRESS
        or validated_transaction["refundReceiver"].lower() != ZERO_ADDRESS
    ):
        raise OwnershipActivationError("Root Safe transaction terms are not alpha-safe")
    try:
        validate_ownership_execute(validated_transaction["data"], schedule=schedule)
    except TimelockOperationError as exc:
        raise OwnershipActivationError(str(exc)) from exc
    transaction_data = _require_hex_bytes(
        authority.get("transactionData"), "authorityOperation.transactionData"
    )
    transaction_hash = _require_hash(
        authority.get("transactionHash"), "authorityOperation.transactionHash"
    )
    approvals_raw = authority.get("approvals")
    if not isinstance(approvals_raw, list) or len(approvals_raw) != 2:
        raise OwnershipActivationError("exactly two nested Safe approvals are required")
    approvals = [
        _validate_approval(
            value,
            chain_id=package["chainId"],
            transaction_data=transaction_data,
            schema_version=package["schemaVersion"],
        )
        for value in approvals_raw
    ]
    if {value["role"] for value in approvals} != set(REQUIRED_ROLES):
        raise OwnershipActivationError("owner identity and coadmin approvals are required")
    schedule_approvals = {
        value["role"]: value
        for value in schedule_package["authorityOperation"]["approvals"]
    }
    for approval in approvals:
        expected = schedule_approvals.get(approval["role"])
        if (
            expected is None
            or approval["safe"].lower() != expected["safe"].lower()
            or approval.get("parentSafe", "").lower() != expected.get("parentSafe", "").lower()
            or [value.lower() for value in approval["allowedSigners"]]
            != [value.lower() for value in expected["allowedSigners"]]
        ):
            raise OwnershipActivationError(
                "ownership execute signer authority changed after scheduling"
            )
    authority = dict(authority)
    authority["transaction"] = validated_transaction
    authority["transactionData"] = transaction_data
    authority["transactionHash"] = transaction_hash
    authority["approvals"] = approvals
    authority["review"] = {
        "action": "executeAcceptOwnership",
        "targets": list(schedule.targets),
        "delaySeconds": schedule.delay_seconds,
        "operationId": schedule.operation_id,
    }
    package["authorityOperation"] = authority
    return package


def _build_derived_execute_package(
    settings: Settings,
    *,
    schedule_package: Mapping[str, Any],
) -> dict[str, Any]:
    chain = _chain_state(settings, schedule_package)
    if not chain.operation_exists:
        raise OwnershipActivationError(
            "ownership execution will be prepared after the schedule confirms"
        )
    if chain.operation_done:
        raise OwnershipActivationError(
            "ownership execution completed outside the reviewed administrator flow"
        )
    schedule = decode_ownership_schedule(
        schedule_package["authorityOperation"]["transaction"]["data"],
        expected_operation_id=schedule_package["operationId"],
    )
    transaction = {
        "to": schedule_package["timelock"],
        "value": "0",
        "data": encode_ownership_execute(schedule),
        "operation": 0,
        "safeTxGas": "0",
        "baseGas": "0",
        "gasPrice": "0",
        "gasToken": ZERO_ADDRESS,
        "refundReceiver": ZERO_ADDRESS,
        "nonce": str(chain.live_nonce),
    }
    w3 = _web3(settings)
    try:
        root_safe = w3.eth.contract(
            address=Web3.to_checksum_address(schedule_package["rootSafe"]),
            abi=_SAFE_ABI,
        )
        arguments = [
            transaction["to"],
            0,
            bytes.fromhex(transaction["data"][2:]),
            0,
            0,
            0,
            0,
            ZERO_ADDRESS,
            ZERO_ADDRESS,
            chain.live_nonce,
        ]
        transaction_hash = Web3.to_hex(
            root_safe.functions.getTransactionHash(*arguments).call()
        ).lower()
        transaction_data = Web3.to_hex(
            root_safe.functions.encodeTransactionData(*arguments).call()
        ).lower()
    except Exception as exc:  # noqa: BLE001
        raise OwnershipActivationError(
            "the reviewed Root Safe execution could not be prepared"
        ) from exc
    approvals = []
    for descriptor in schedule_package["authorityOperation"]["approvals"]:
        typed_data = {
            "domain": {
                "chainId": schedule_package["chainId"],
                "verifyingContract": descriptor["safe"],
            },
            "types": {"SafeMessage": [{"name": "message", "type": "bytes"}]},
            "primaryType": "SafeMessage",
            "message": {"message": _safe_message_data(schedule_package["chainId"], descriptor["parentSafe"], transaction_data)
                        if descriptor.get("parentSafe") else transaction_data},
        }
        approvals.append(
            {
                "role": descriptor["role"],
                "safe": descriptor["safe"],
                "allowedSigners": list(descriptor["allowedSigners"]),
                **({"parentSafe": descriptor["parentSafe"]} if descriptor.get("parentSafe") else {}),
                "messageHash": _typed_data_digest(typed_data),
                "typedData": typed_data,
            }
        )
    package = {
        **{
            field: schedule_package[field]
            for field in (
                "schemaVersion",
                "kind",
                "deploymentArtifactHash",
                "ownershipIntentArtifactHash",
                "governanceArtifactHash",
                "sourceSha",
                "network",
                "chainId",
                "operationId",
                "rootSafe",
                "timelock",
            )
        },
        "phase": "execute",
        "derivedFromScheduleArtifactHash": schedule_package["artifactHash"],
        "authorityOperation": {
            "phase": "execute",
            "rootSafe": schedule_package["rootSafe"],
            "transaction": transaction,
            "transactionHash": transaction_hash,
            "transactionData": transaction_data,
            "approvals": approvals,
        },
    }
    package["artifactHash"] = _canonical_hash(package)
    _validate_derived_execute_package(
        package,
        schedule_package=schedule_package,
    )
    return package


def load_execution_authority_operation(
    settings: Settings,
    store: OwnershipActivationStore,
) -> dict[str, Any]:
    """Load release evidence or seal the canonical live-nonce execute action."""

    configured_path = settings.payment_omnichain_ownership_execute_operation_path
    configured_hash = settings.payment_omnichain_ownership_execute_operation_hash
    if bool(configured_path) != bool(configured_hash):
        raise OwnershipActivationError(
            "ownership execution package configuration is incomplete"
        )
    if configured_path and configured_hash:
        return load_authority_operation(settings, phase="execute")

    schedule_package = load_authority_operation(settings, phase="schedule")
    stored = store.derived_package(
        parent_package_hash=schedule_package["artifactHash"],
        phase="execute",
    )
    if stored is not None:
        return _validate_derived_execute_package(
            stored,
            schedule_package=schedule_package,
        )
    package = _build_derived_execute_package(
        settings,
        schedule_package=schedule_package,
    )
    store.record_derived_package(
        parent_package_hash=schedule_package["artifactHash"],
        phase="execute",
        package=package,
        now=int(time.time()),
    )
    return _validate_derived_execute_package(
        package,
        schedule_package=schedule_package,
    )


def _normalize_signature(signature: str) -> bytes:
    if (
        not isinstance(signature, str)
        or len(signature) != 132
        or not _HEX_RE.fullmatch(signature)
    ):
        raise ValueError("SafeMessage signature must be exactly 65 bytes")
    raw = bytes.fromhex(signature[2:])
    if raw[-1] not in (27, 28):
        raise ValueError("SafeMessage signature recovery byte must be 27 or 28")
    return raw


def _encode_contract_signatures(
    package: Mapping[str, Any],
    approvals: Mapping[str, Mapping[str, Any]],
) -> bytes:
    descriptors = {
        value["role"]: value for value in package["authorityOperation"]["approvals"]
    }
    entries: list[tuple[str, bytes]] = []
    for role in REQUIRED_ROLES:
        if role not in approvals:
            raise ValueError(f"{role} administrator signature is missing")
        descriptor = descriptors[role]
        signature = _normalize_signature(str(approvals[role]["signature"]))
        if descriptor.get("parentSafe"):
            signature = _encode_signature_entries([(descriptor["safe"], signature)])
        entries.append((descriptor.get("parentSafe", descriptor["safe"]), signature))
    return _encode_signature_entries(entries)


def _encode_signature_entries(entries: list[tuple[str, bytes]]) -> bytes:
    entries.sort(key=lambda item: int(item[0], 16))
    static_size = 65 * len(entries)
    dynamic_offset = static_size
    static_parts: list[bytes] = []
    dynamic_parts: list[bytes] = []
    for owner, signature in entries:
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


def _build_exec_transaction(
    package: Mapping[str, Any],
    approvals: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    transaction = package["authorityOperation"]["transaction"]
    signatures = _encode_contract_signatures(package, approvals)
    function_signature = (
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,"
        "address,address,bytes)"
    )
    selector = keccak(text=function_signature)[:4]
    arguments = encode(
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
            int(transaction["value"]),
            bytes.fromhex(transaction["data"][2:]),
            int(transaction["operation"]),
            int(transaction["safeTxGas"]),
            int(transaction["baseGas"]),
            int(transaction["gasPrice"]),
            transaction["gasToken"],
            transaction["refundReceiver"],
            signatures,
        ],
    )
    return {
        "chainId": str(package["chainId"]),
        "to": package["rootSafe"],
        "value": "0x0",
        "data": "0x" + (selector + arguments).hex(),
    }


def _verify_broadcast(
    *,
    settings: Settings,
    package: Mapping[str, Any],
    approvals: Mapping[str, Mapping[str, Any]],
    transaction_hash: str,
) -> tuple[int, int, str]:
    transaction_hash = _require_hash(transaction_hash, "transactionHash")
    expected = _build_exec_transaction(package, approvals)
    w3 = _web3(settings)
    try:
        transaction = w3.eth.get_transaction(transaction_hash)
    except Exception as exc:  # noqa: BLE001
        raise OwnershipActivationError(
            "ownership broadcast is not yet available from the payment chain"
        ) from exc
    input_data = transaction.get("input") or transaction.get("data") or "0x"
    input_hex = (
        _require_hex_bytes(input_data, "broadcast transaction input")
        if isinstance(input_data, str)
        else Web3.to_hex(input_data).lower()
    )
    if (
        str(transaction.get("to") or "").lower() != expected["to"].lower()
        or int(transaction.get("value") or 0) != 0
        or input_hex != expected["data"].lower()
    ):
        raise OwnershipActivationError(
            "ownership broadcast does not match the sealed Root Safe transaction"
        )
    submitted_by = _require_address(
        transaction.get("from"),
        "broadcast transaction sender",
    )
    try:
        receipt = w3.eth.get_transaction_receipt(transaction_hash)
    except TransactionNotFound as exc:
        raise OwnershipActivationError(
            "ownership broadcast is waiting for Base Sepolia confirmation"
        ) from exc
    latest_block = int(w3.eth.block_number)
    block_number = int(receipt.get("blockNumber") or 0)
    if int(receipt.get("status") or 0) != 1 or block_number <= 0:
        raise OwnershipActivationError(
            "ownership broadcast does not match the sealed Root Safe transaction"
        )
    return block_number, max(0, latest_block - block_number + 1), submitted_by


def _verify_submission(
    *,
    settings: Settings,
    package: Mapping[str, Any],
    approvals: Mapping[str, Mapping[str, Any]],
    transaction_hash: str,
) -> str:
    """Verify the exact Root Safe transaction while it is still in the mempool."""

    transaction_hash = _require_hash(transaction_hash, "transactionHash")
    expected = _build_exec_transaction(package, approvals)
    w3 = _web3(settings)
    try:
        transaction = w3.eth.get_transaction(transaction_hash)
    except Exception as exc:  # noqa: BLE001
        raise OwnershipActivationError(
            "ownership transaction is not yet visible on Base Sepolia"
        ) from exc
    input_data = transaction.get("input") or transaction.get("data") or "0x"
    input_hex = (
        _require_hex_bytes(input_data, "submitted transaction input")
        if isinstance(input_data, str)
        else Web3.to_hex(input_data).lower()
    )
    if (
        str(transaction.get("to") or "").lower() != expected["to"].lower()
        or int(transaction.get("value") or 0) != 0
        or input_hex != expected["data"].lower()
    ):
        raise OwnershipActivationError(
            "submitted transaction does not match the sealed Root Safe transaction"
        )
    return _require_address(transaction.get("from"), "submitted transaction sender")


def _require_enabled(settings: Settings) -> None:
    if not settings.payment_omnichain_ownership_activation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Base Sepolia ownership activation is disabled",
        )


def _public_status(
    *,
    settings: Settings,
    package: Mapping[str, Any],
    store: OwnershipActivationStore,
) -> dict[str, Any]:
    stored = store.approvals(package["artifactHash"])
    descriptors = package["authorityOperation"]["approvals"]
    complete = all(role in stored for role in REQUIRED_ROLES)
    submission = store.submission(package["artifactHash"])
    broadcast = store.broadcast(package["artifactHash"])
    if complete and submission and not broadcast:
        try:
            block_number, confirmations, submitted_by = _verify_broadcast(
                settings=settings,
                package=package,
                approvals=stored,
                transaction_hash=submission["transactionHash"],
            )
        except OwnershipActivationError as exc:
            if "waiting for Base Sepolia confirmation" not in str(exc):
                raise
        else:
            observed = _chain_state(settings, package)
            if package["phase"] == "schedule":
                valid_result = observed.operation_exists and observed.operation_timestamp > 0
            else:
                valid_result = observed.operation_done
            if not valid_result:
                raise OwnershipActivationError(
                    "confirmed Root Safe transaction did not produce the expected timelock state"
                )
            store.record_broadcast(
                package_hash=package["artifactHash"],
                transaction_hash=submission["transactionHash"],
                submitted_by=submitted_by,
                block_number=block_number,
                confirmations=confirmations,
                minimum_confirmations=settings.payment_omnichain_ownership_min_confirmations,
                now=int(time.time()),
            )
            broadcast = store.broadcast(package["artifactHash"])

    chain = _chain_state(settings, package)
    approvals = [
        {
            "role": descriptor["role"],
            "safe": descriptor["safe"],
            "allowedSigners": descriptor["allowedSigners"],
            "messageHash": descriptor["messageHash"],
            "typedData": descriptor["typedData"],
            "signed": descriptor["role"] in stored,
            "signerAddress": (
                stored[descriptor["role"]]["signerAddress"]
                if descriptor["role"] in stored
                else None
            ),
            "signedAt": (
                stored[descriptor["role"]]["signedAt"]
                if descriptor["role"] in stored
                else None
            ),
        }
        for descriptor in descriptors
    ]
    if broadcast:
        broadcast["confirmations"] = max(
            0, chain.latest_block - int(broadcast["blockNumber"]) + 1
        )
        broadcast["minimumConfirmations"] = (
            settings.payment_omnichain_ownership_min_confirmations
        )
        if (
            broadcast["confirmedAt"] is None
            and broadcast["confirmations"] >= broadcast["minimumConfirmations"]
        ):
            store.record_broadcast(
                package_hash=package["artifactHash"],
                transaction_hash=broadcast["transactionHash"],
                submitted_by=broadcast["submittedBy"],
                block_number=int(broadcast["blockNumber"]),
                confirmations=int(broadcast["confirmations"]),
                minimum_confirmations=int(broadcast["minimumConfirmations"]),
                now=int(time.time()),
            )
            broadcast = store.broadcast(package["artifactHash"])
            assert broadcast is not None
            broadcast["confirmations"] = max(
                0, chain.latest_block - int(broadcast["blockNumber"]) + 1
            )
            broadcast["minimumConfirmations"] = (
                settings.payment_omnichain_ownership_min_confirmations
            )
    if (
        chain.operation_done
        and broadcast
        and broadcast["confirmations"] >= broadcast["minimumConfirmations"]
    ):
        state = "DONE"
    elif chain.operation_done:
        state = "CONFIRMING"
    elif submission and not broadcast:
        state = "BROADCAST_PENDING"
    elif package["phase"] == "execute":
        if not chain.operation_exists:
            state = "WAITING_FOR_SCHEDULE"
        elif not chain.operation_ready:
            state = "WAITING_FOR_DELAY"
        elif complete:
            state = "READY_TO_BROADCAST"
        else:
            state = "AWAITING_APPROVALS"
    elif chain.operation_ready:
        state = "READY_TO_EXECUTE"
    elif chain.operation_exists:
        state = "SCHEDULED"
    elif complete:
        state = "READY_TO_BROADCAST"
    else:
        state = "AWAITING_APPROVALS"
    return {
        "schemaVersion": 2,
        "state": state,
        "packageHash": package["artifactHash"],
        "sourceSha": package["sourceSha"],
        "network": package["network"],
        "chainId": package["chainId"],
        "phase": package["phase"],
        "operationId": package["operationId"],
        "rootSafe": package["rootSafe"],
        "timelock": package["timelock"],
        "rootSafeTransactionHash": package["authorityOperation"]["transactionHash"],
        "deploymentArtifactHash": package["deploymentArtifactHash"],
        "ownershipIntentArtifactHash": package["ownershipIntentArtifactHash"],
        "governanceArtifactHash": package["governanceArtifactHash"],
        "review": package["authorityOperation"]["review"],
        "scheduledFor": chain.operation_timestamp or None,
        "approvals": approvals,
        "broadcastTransaction": (
            _build_exec_transaction(package, stored)
            if complete
            and (
                (package["phase"] == "schedule" and not chain.operation_exists)
                or (
                    package["phase"] == "execute"
                    and chain.operation_ready
                    and not chain.operation_done
                )
            )
            else None
        ),
        "broadcast": broadcast,
        "submission": submission,
    }


router = APIRouter(
    prefix="/admin/omnichain/ownership-activation",
    tags=["admin-omnichain-ownership"],
    dependencies=[Depends(require_admin_jwt)],
)


@router.get("")
def get_ownership_activation(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
) -> dict[str, Any]:
    _require_enabled(settings)
    try:
        package = load_authority_operation(settings)
        return _public_status(settings=settings, package=package, store=store)
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/sign")
def sign_ownership_activation(
    body: SignatureRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
) -> dict[str, Any]:
    _require_enabled(settings)
    try:
        package = load_authority_operation(settings)
        chain = _chain_state(settings, package)
        if not chain.package_is_current:
            raise ValueError("ownership operation is already scheduled")
        matching: list[tuple[Mapping[str, Any], Any]] = []
        for descriptor in package["authorityOperation"]["approvals"]:
            recovered = recover_evm_signer(descriptor["typedData"], body.signature)
            if any(
                signer.lower() == recovered.address.lower()
                for signer in descriptor["allowedSigners"]
            ):
                matching.append((descriptor, recovered))
        if len(matching) != 1:
            raise ValueError(
                "SafeMessage signature does not match one unique authorized Safe role"
            )
        descriptor, recovered = matching[0]
        if "0x" + recovered.digest.hex() != descriptor["messageHash"]:
            raise ValueError("SafeMessage digest changed after package review")
        _normalize_signature(body.signature)
        store.add_approval(
            package_hash=package["artifactHash"],
            role=descriptor["role"],
            signer_address=recovered.address,
            signature=body.signature,
            now=int(time.time()),
        )
        return _public_status(settings=settings, package=package, store=store)
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/broadcast")
def record_ownership_activation_broadcast(
    body: BroadcastRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
) -> dict[str, Any]:
    _require_enabled(settings)
    try:
        package = load_authority_operation(settings)
        approvals = store.approvals(package["artifactHash"])
        if any(role not in approvals for role in REQUIRED_ROLES):
            raise ValueError("both Safe administrator approvals are required")
        try:
            block_number, confirmations, submitted_by = _verify_broadcast(
                settings=settings,
                package=package,
                approvals=approvals,
                transaction_hash=body.transaction_hash,
            )
        except OwnershipActivationError as exc:
            if "waiting for Base Sepolia confirmation" not in str(exc):
                raise
            submitted_by = _verify_submission(
                settings=settings,
                package=package,
                approvals=approvals,
                transaction_hash=body.transaction_hash,
            )
            store.record_submission(
                package_hash=package["artifactHash"],
                transaction_hash=body.transaction_hash.lower(),
                submitted_by=submitted_by,
                now=int(time.time()),
            )
            return _public_status(settings=settings, package=package, store=store)
        chain = _chain_state(settings, package)
        if not chain.operation_exists or chain.operation_timestamp <= 0:
            raise ValueError("timelock did not record the sealed ownership schedule")
        store.record_submission(
            package_hash=package["artifactHash"],
            transaction_hash=body.transaction_hash.lower(),
            submitted_by=submitted_by,
            now=int(time.time()),
        )
        store.record_broadcast(
            package_hash=package["artifactHash"],
            transaction_hash=body.transaction_hash.lower(),
            submitted_by=submitted_by,
            block_number=block_number,
            confirmations=confirmations,
            minimum_confirmations=settings.payment_omnichain_ownership_min_confirmations,
            now=int(time.time()),
        )
        return _public_status(settings=settings, package=package, store=store)
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/execute")
def get_ownership_execution(
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
) -> dict[str, Any]:
    _require_enabled(settings)
    try:
        package = load_execution_authority_operation(settings, store)
        return _public_status(settings=settings, package=package, store=store)
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/execute/sign")
def sign_ownership_execution(
    body: SignatureRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
) -> dict[str, Any]:
    _require_enabled(settings)
    try:
        package = load_execution_authority_operation(settings, store)
        chain = _chain_state(settings, package)
        if not chain.operation_exists:
            raise ValueError("ownership schedule is not on Base Sepolia")
        if not chain.operation_ready:
            raise ValueError("the 24-hour ownership delay has not finished")
        if chain.operation_done:
            raise ValueError("ownership execution is already complete")
        matching: list[tuple[Mapping[str, Any], Any]] = []
        for descriptor in package["authorityOperation"]["approvals"]:
            recovered = recover_evm_signer(descriptor["typedData"], body.signature)
            if any(
                signer.lower() == recovered.address.lower()
                for signer in descriptor["allowedSigners"]
            ):
                matching.append((descriptor, recovered))
        if len(matching) != 1:
            raise ValueError(
                "SafeMessage signature does not match one unique authorized Safe role"
            )
        descriptor, recovered = matching[0]
        if "0x" + recovered.digest.hex() != descriptor["messageHash"]:
            raise ValueError("SafeMessage digest changed after package review")
        _normalize_signature(body.signature)
        store.add_approval(
            package_hash=package["artifactHash"],
            role=descriptor["role"],
            signer_address=recovered.address,
            signature=body.signature,
            now=int(time.time()),
        )
        return _public_status(settings=settings, package=package, store=store)
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/execute/broadcast")
def record_ownership_execution_broadcast(
    body: BroadcastRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[
        OwnershipActivationStore, Depends(get_ownership_activation_store)
    ],
) -> dict[str, Any]:
    _require_enabled(settings)
    try:
        package = load_execution_authority_operation(settings, store)
        approvals = store.approvals(package["artifactHash"])
        if any(role not in approvals for role in REQUIRED_ROLES):
            raise ValueError("fresh owner and coadministrator signatures are required")
        before = _chain_state(settings, package)
        if not before.operation_ready or before.operation_done:
            raise ValueError("ownership operation is not ready for execution")
        try:
            block_number, confirmations, submitted_by = _verify_broadcast(
                settings=settings,
                package=package,
                approvals=approvals,
                transaction_hash=body.transaction_hash,
            )
        except OwnershipActivationError as exc:
            if "waiting for Base Sepolia confirmation" not in str(exc):
                raise
            submitted_by = _verify_submission(
                settings=settings,
                package=package,
                approvals=approvals,
                transaction_hash=body.transaction_hash,
            )
            store.record_submission(
                package_hash=package["artifactHash"],
                transaction_hash=body.transaction_hash.lower(),
                submitted_by=submitted_by,
                now=int(time.time()),
            )
            return _public_status(settings=settings, package=package, store=store)
        after = _chain_state(settings, package)
        if not after.operation_done:
            raise ValueError("timelock execution did not complete ownership acceptance")
        store.record_submission(
            package_hash=package["artifactHash"],
            transaction_hash=body.transaction_hash.lower(),
            submitted_by=submitted_by,
            now=int(time.time()),
        )
        store.record_broadcast(
            package_hash=package["artifactHash"],
            transaction_hash=body.transaction_hash.lower(),
            submitted_by=submitted_by,
            block_number=block_number,
            confirmations=confirmations,
            minimum_confirmations=settings.payment_omnichain_ownership_min_confirmations,
            now=int(time.time()),
        )
        return _public_status(settings=settings, package=package, store=store)
    except OwnershipActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
