"""Persistent owner-plus-one approvals for consequential admin mutations."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Iterator, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from chia_rs.sized_bytes import bytes32
from solslot_puzzles.admin_operation_v1 import AdminOperationCoreV1, canonical_json

from .admin_auth import AdminClaims, require_admin_jwt
from .admin_records import get_admin_records_for_settings
from .admin_roster import current_signed_admins
from .config import Settings, get_settings
from .evm_auth import recover_evm_signer
from .public_artifact import load_signed_public_artifact


router = APIRouter(prefix="/admin/auth/operations", tags=["admin-auth"])
ALLOWED_OPERATIONS = frozenset(
    {
        "bridge.top-up",
        "collection.amend",
        "collection.seal",
        "mint.cancel",
        "mint.execute",
        "mint.publish",
        "sgt.allocate",
        "presale.create",
        "presale.cancel",
        "presale.launch",
    }
)


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def _parse_hex32(value: str, field: str) -> bytes32:
    normalized = value.lower().removeprefix("0x")
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be 32-byte hex") from exc
    if len(raw) != 32:
        raise ValueError(f"{field} must be 32-byte hex")
    return bytes32(raw)


def canonical_request_binding(
    *,
    method: str,
    path: str,
    query: list[tuple[str, str]],
    body: Any,
    if_match: str | None,
) -> dict[str, Any]:
    method_value = method.upper()
    if method_value not in {"POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("admin operation method must be POST, PUT, PATCH, or DELETE")
    is_admin_path = path.startswith("/admin/")
    is_presale_path = path == "/presales" or path.startswith("/presales/")
    if (not is_admin_path and not is_presale_path) or "?" in path or "#" in path:
        raise ValueError(
            "admin operation path must be an authoritative /admin/ or /presales API path"
        )
    normalized_query = sorted([[str(key), str(value)] for key, value in query])
    return {
        "schemaVersion": 1,
        "method": method_value,
        "path": path,
        "query": normalized_query,
        "ifMatch": if_match or "",
        "body": body,
    }


def request_binding_hash(binding: dict[str, Any]) -> bytes32:
    return bytes32(hashlib.sha256(canonical_json(binding)).digest())


@dataclass(frozen=True)
class AdminRoster:
    launcher_id: bytes32
    compressed_pubkeys: tuple[bytes, bytes, bytes]


def resolve_admin_roster(settings: Settings) -> AdminRoster:
    if settings.runtime_environment == "test" and settings.effective_admin_records_path():
        records = get_admin_records_for_settings(settings)
        if records is None or len(records.admin_records) != 3:
            raise ValueError("test admin records must contain exactly three slots")
        ordered = sorted(records.admin_records, key=lambda item: item.admin_idx)
        if [item.admin_idx for item in ordered] != [0, 1, 2]:
            raise ValueError("admin records must contain canonical slots 0, 1, and 2")
        keys: list[bytes] = []
        for record in ordered:
            if len(record.leaves) != 1:
                raise ValueError("each alpha admin slot must contain one EIP-712 key")
            keys.append(record.leaves[0].secp256k1_pubkey)
        return AdminRoster(records.launcher_id, tuple(keys))  # type: ignore[arg-type]

    artifact = load_signed_public_artifact(settings)
    launcher = _parse_hex32(
        str(artifact["launcherIds"]["adminAuthority"]),
        "admin authority launcher",
    )
    values = current_signed_admins(settings)
    if len(values) != 3:
        raise ValueError("current signed roster must contain exactly three admin keys")
    keys = tuple(bytes.fromhex(value[1].removeprefix("0x")) for value in values)
    if any(len(value) != 33 for value in keys):
        raise ValueError("current signed roster contains malformed admin key")
    return AdminRoster(launcher, keys)  # type: ignore[arg-type]


class OperationStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    def _migrate(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS admin_operations (
                    operation_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL,
                    authority_launcher_id TEXT NOT NULL,
                    network TEXT NOT NULL,
                    request_binding_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    approved_at INTEGER,
                    consumed_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS admin_operation_signatures (
                    operation_id TEXT NOT NULL,
                    admin_index INTEGER NOT NULL CHECK(admin_index BETWEEN 0 AND 2),
                    signer_address TEXT NOT NULL,
                    compressed_pubkey TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    signed_at INTEGER NOT NULL,
                    PRIMARY KEY(operation_id, admin_index),
                    FOREIGN KEY(operation_id) REFERENCES admin_operations(operation_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS admin_operation_chain_signatures (
                    operation_id TEXT NOT NULL,
                    admin_index INTEGER NOT NULL CHECK(admin_index BETWEEN 0 AND 2),
                    action_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    PRIMARY KEY(operation_id,admin_index),
                    FOREIGN KEY(operation_id,admin_index)
                        REFERENCES admin_operation_signatures(operation_id,admin_index)
                );
                """
            )

    def create(
        self,
        *,
        core: AdminOperationCoreV1,
        binding: dict[str, Any],
        created_by: str,
        now: int,
    ) -> dict[str, Any]:
        operation_id = _hex32(core.envelope_hash)
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO admin_operations(operation_id,operation,payload_hash,revision,"
                "nonce,expires_at,authority_launcher_id,network,request_binding_json,created_by,"
                "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    operation_id,
                    core.operation,
                    _hex32(core.payload_hash),
                    core.revision,
                    _hex32(core.nonce),
                    core.expires_at,
                    _hex32(core.authority_launcher_id),
                    core.network,
                    canonical_json(binding).decode("ascii"),
                    created_by.lower(),
                    now,
                ),
            )
        return self.get(operation_id)

    def get(self, operation_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM admin_operations WHERE operation_id=?", (operation_id.lower(),)
            ).fetchone()
            if row is None:
                raise KeyError("admin operation not found")
            signatures = connection.execute(
                "SELECT admin_index,signer_address,compressed_pubkey,signature,signed_at "
                "FROM admin_operation_signatures WHERE operation_id=? ORDER BY admin_index",
                (operation_id.lower(),),
            ).fetchall()
            chain_signatures = connection.execute(
                "SELECT admin_index,action_id,signature FROM admin_operation_chain_signatures "
                "WHERE operation_id=? ORDER BY admin_index", (operation_id.lower(),),
            ).fetchall()
        value = dict(row)
        value["request_binding"] = json.loads(value.pop("request_binding_json"))
        value["signatures"] = [dict(item) for item in signatures]
        value["chain_signatures"] = [dict(item) for item in chain_signatures]
        slots = {int(item["admin_index"]) for item in signatures}
        value["status"] = (
            "consumed"
            if value["consumed_at"] is not None
            else "approved"
            if 0 in slots and bool(slots & {1, 2})
            else "pending"
        )
        return value

    def list(
        self,
        *,
        status_filter: str = "active",
        limit: int = 100,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        if status_filter not in {"active", "pending", "approved", "consumed", "all"}:
            raise ValueError("unsupported admin operation status filter")
        current = int(time.time()) if now is None else now
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT operation_id FROM admin_operations "
                "ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            ).fetchall()
        values = [self.get(str(row["operation_id"])) for row in rows]
        if status_filter == "active":
            return [
                value
                for value in values
                if value["status"] in {"pending", "approved"}
                and int(value["expires_at"]) >= current
            ]
        if status_filter == "all":
            return values
        return [value for value in values if value["status"] == status_filter]

    def add_signature(
        self,
        *,
        operation_id: str,
        admin_index: int,
        signer_address: str,
        compressed_pubkey: str,
        signature: str,
        now: int,
        chain_action_id: str | None = None,
        chain_signature: str | None = None,
    ) -> dict[str, Any]:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT expires_at,consumed_at FROM admin_operations WHERE operation_id=?",
                (operation_id.lower(),),
            ).fetchone()
            if row is None:
                raise KeyError("admin operation not found")
            if row["consumed_at"] is not None:
                raise ValueError("admin operation is already consumed")
            if int(row["expires_at"]) < now:
                raise ValueError("admin operation is expired")
            try:
                connection.execute(
                    "INSERT INTO admin_operation_signatures(operation_id,admin_index,"
                    "signer_address,compressed_pubkey,signature,signed_at) VALUES(?,?,?,?,?,?)",
                    (
                        operation_id.lower(),
                        admin_index,
                        signer_address.lower(),
                        compressed_pubkey.lower(),
                        signature.lower(),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("admin slot already signed this operation") from exc
            if (chain_action_id is None) != (chain_signature is None):
                raise ValueError('chain signature requires its exact action identifier')
            if chain_action_id is not None:
                connection.execute(
                    "INSERT INTO admin_operation_chain_signatures(operation_id,admin_index,action_id,signature) "
                    "VALUES(?,?,?,?)", (operation_id.lower(), admin_index, chain_action_id, chain_signature))
            slots = {
                int(item["admin_index"])
                for item in connection.execute(
                    "SELECT admin_index FROM admin_operation_signatures WHERE operation_id=?",
                    (operation_id.lower(),),
                ).fetchall()
            }
            if 0 in slots and bool(slots & {1, 2}):
                connection.execute(
                    "UPDATE admin_operations SET approved_at=COALESCE(approved_at,?) "
                    "WHERE operation_id=?",
                    (now, operation_id.lower()),
                )
        return self.get(operation_id)

    def consume(
        self,
        *,
        operation_id: str,
        expected_operation: str,
        expected_payload_hash: bytes32,
        caller: str,
        now: int,
    ) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT operation,payload_hash,expires_at,approved_at,consumed_at FROM "
                "admin_operations WHERE operation_id=?",
                (operation_id.lower(),),
            ).fetchone()
            if row is None:
                raise KeyError("admin operation not found")
            if row["consumed_at"] is not None:
                raise ValueError("admin operation is already consumed")
            if int(row["expires_at"]) < now:
                raise ValueError("admin operation is expired")
            if row["approved_at"] is None:
                raise ValueError("admin operation lacks slot 0 plus one coadmin")
            if row["operation"] != expected_operation:
                raise ValueError("admin operation type does not match this endpoint")
            if row["payload_hash"] != _hex32(expected_payload_hash):
                raise ValueError("admin operation payload does not match this request")
            signer = connection.execute(
                "SELECT 1 FROM admin_operation_signatures WHERE operation_id=? "
                "AND signer_address=?",
                (operation_id.lower(), caller.lower()),
            ).fetchone()
            if signer is None:
                raise ValueError("calling JWT subject did not sign this operation")
            connection.execute(
                "UPDATE admin_operations SET consumed_at=? WHERE operation_id=?",
                (now, operation_id.lower()),
            )


_store: OperationStore | None = None
_store_path: str | None = None


def get_operation_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> OperationStore:
    global _store, _store_path
    if _store is None or _store_path != settings.admin_db_path:
        _store = OperationStore(settings.admin_db_path)
        _store_path = settings.admin_db_path
    return _store


class RequestBindingV1(BaseModel):
    method: Literal["POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(..., min_length=8, max_length=512)
    query: list[tuple[str, str]] = Field(default_factory=list, max_length=32)
    body: Any = None
    if_match: Optional[str] = Field(None, max_length=128, alias="ifMatch")


class PrepareOperationRequest(BaseModel):
    operation: str
    revision: int = Field(..., ge=0)
    expires_in_seconds: int = Field(600, ge=60, le=900, alias="expiresInSeconds")
    request_binding: RequestBindingV1 = Field(..., alias="requestBinding")

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, value: str) -> str:
        if value not in ALLOWED_OPERATIONS:
            raise ValueError("unsupported admin operation")
        return value


class SignOperationRequest(BaseModel):
    signature: str = Field(..., min_length=132, max_length=132)
    chain_action_id: str | None = Field(None, alias="chainActionId", pattern=r"^0x[0-9a-fA-F]{64}$")
    chain_signature: str | None = Field(None, alias="chainSignature", pattern=r"^0x(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{130})$")


async def _mint_build(value, request: Request, settings: Settings):
    if value['operation'] != 'mint.publish':
        return None
    from .genesis import get_genesis_store
    from .mint_publication import prepare_mint_authorization
    provider = getattr(request.app.state, 'coinset', None)
    if provider is None:
        raise ValueError('Testnet11 Chia provider is unavailable')
    return await prepare_mint_authorization(binding=value['request_binding'],
        created_by=value['created_by'], provider=provider, settings=settings,
        genesis_store=get_genesis_store(settings))


def _with_mint_actions(public, build, value):
    if build is None:
        return public
    signed = {item['action_id'] for item in value.get('chain_signatures', [])}
    public['chainActions'] = [{**action.to_wire(signed=action.action_id in signed),
        'summary': 'Approve this exact mint proposal, vault stake, deadline and current protocol inputs.',
        'financialEffect': 'The chosen vault SGT is locked until the voting deadline. No deed is issued at publication.'}
        for action in build.actions]
    return public


def _public_operation(
    value: dict[str, Any], core: AdminOperationCoreV1, *, chain_id: int
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "operationId": value["operation_id"],
        "status": value["status"],
        "operation": value["operation"],
        "payloadHash": value["payload_hash"],
        "revision": value["revision"],
        "expiresAt": value["expires_at"],
        "authorityLauncherId": value["authority_launcher_id"],
        "network": value["network"],
        "nonce": value["nonce"],
        "requestBinding": value["request_binding"],
        "createdBy": value["created_by"],
        "createdAt": value["created_at"],
        "approvedAt": value["approved_at"],
        "consumedAt": value["consumed_at"],
        "signatures": [
            {
                "adminIndex": item["admin_index"],
                "signerAddress": item["signer_address"],
                "signedAt": item["signed_at"],
            }
            for item in value["signatures"]
        ],
        "typedData": core.eip712_typed_data(chain_id=chain_id),
    }


def _core_from_record(value: dict[str, Any]) -> AdminOperationCoreV1:
    return AdminOperationCoreV1(
        authority_launcher_id=_parse_hex32(value["authority_launcher_id"], "launcher"),
        network=value["network"],
        operation=value["operation"],
        payload_hash=_parse_hex32(value["payload_hash"], "payload hash"),
        revision=int(value["revision"]),
        nonce=_parse_hex32(value["nonce"], "nonce"),
        expires_at=int(value["expires_at"]),
    )


@router.post("/prepare", status_code=201)
async def prepare_operation(
    body: PrepareOperationRequest,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[OperationStore, Depends(get_operation_store)],
) -> dict[str, Any]:
    if not settings.admin_operation_approvals_enabled:
        raise HTTPException(status_code=503, detail="owner-plus-one approvals are disabled")
    try:
        roster = resolve_admin_roster(settings)
        binding = canonical_request_binding(
            method=body.request_binding.method,
            path=body.request_binding.path,
            query=body.request_binding.query,
            body=body.request_binding.body,
            if_match=body.request_binding.if_match,
        )
        now = int(time.time())
        core = AdminOperationCoreV1(
            authority_launcher_id=roster.launcher_id,
            network=settings.network,
            operation=body.operation,
            payload_hash=request_binding_hash(binding),
            revision=body.revision,
            nonce=bytes32(secrets.token_bytes(32)),
            expires_at=now + body.expires_in_seconds,
        )
        build = await _mint_build({'operation': body.operation, 'request_binding': binding,
            'created_by': claims.sub}, request, settings)
        value = store.create(core=core, binding=binding, created_by=claims.sub, now=now)
        return _with_mint_actions(_public_operation(value, core, chain_id=settings.eip712_chain_id), build, value)
    except (KeyError, TypeError, ValueError, sqlite3.IntegrityError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("")
def list_operations(
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[OperationStore, Depends(get_operation_store)],
    status_filter: Literal["active", "pending", "approved", "consumed", "all"] = "active",
    limit: int = 100,
) -> dict[str, Any]:
    try:
        values = store.list(status_filter=status_filter, limit=limit)
        operations = [
            _public_operation(
                value,
                _core_from_record(value),
                chain_id=settings.eip712_chain_id,
            )
            for value in values
        ]
        return {"operations": operations, "count": len(operations)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{operation_id}")
async def get_operation(
    operation_id: str,
    request: Request,
    _claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[OperationStore, Depends(get_operation_store)],
) -> dict[str, Any]:
    try:
        value = store.get(operation_id)
        public = _public_operation(
            value,
            _core_from_record(value),
            chain_id=settings.eip712_chain_id,
        )
        if value['status'] != 'consumed':
            public = _with_mint_actions(public, await _mint_build(value, request, settings), value)
        return public
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{operation_id}/sign")
async def sign_operation(
    operation_id: str,
    body: SignOperationRequest,
    request: Request,
    claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
    settings: Annotated[Settings, Depends(get_settings)],
    store: Annotated[OperationStore, Depends(get_operation_store)],
) -> dict[str, Any]:
    try:
        value = store.get(operation_id)
        core = _core_from_record(value)
        recovered = recover_evm_signer(
            core.eip712_typed_data(chain_id=settings.eip712_chain_id),
            body.signature,
        )
        if recovered.address.lower() != claims.sub.lower():
            raise ValueError("signature does not match the authenticated administrator")
        roster = resolve_admin_roster(settings)
        if core.authority_launcher_id != roster.launcher_id:
            raise ValueError("admin operation is bound to a stale authority launcher")
        try:
            admin_index = roster.compressed_pubkeys.index(recovered.compressed_pubkey)
        except ValueError as exc:
            raise ValueError("signature key is not in the active admin roster") from exc
        build = await _mint_build(value, request, settings)
        chain_signature = None
        if build is not None:
            from solslot_puzzles.eip712_helpers import normalize_eip712_member_signature
            action = build.actions[admin_index]
            if body.chain_action_id != action.action_id or body.chain_signature is None:
                raise ValueError('mint approval requires this administrator\'s exact current chain action')
            chain_signature = '0x' + normalize_eip712_member_signature(
                signature=bytes.fromhex(body.chain_signature[2:]),
                digest=_parse_hex32(action.message_hash, 'identity action hash'),
                compressed_pubkey=bytes.fromhex(action.signer_public_key[2:])).hex()
        elif body.chain_action_id is not None or body.chain_signature is not None:
            raise ValueError('this HTTP operation does not accept a chain signature')
        value = store.add_signature(
            operation_id=operation_id,
            admin_index=admin_index,
            signer_address=recovered.address,
            compressed_pubkey=recovered.compressed_pubkey_hex,
            signature=body.signature,
            now=int(time.time()),
            chain_action_id=body.chain_action_id,
            chain_signature=chain_signature,
        )
        return _with_mint_actions(_public_operation(value, core, chain_id=settings.eip712_chain_id), build, value)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def require_admin_operation(expected_operation: str):
    if expected_operation not in ALLOWED_OPERATIONS:
        raise ValueError(f"unsupported admin operation {expected_operation}")

    async def dependency(
        request: Request,
        claims: Annotated[AdminClaims, Depends(require_admin_jwt)],
        settings: Annotated[Settings, Depends(get_settings)],
        store: Annotated[OperationStore, Depends(get_operation_store)],
        operation_id: Annotated[
            Optional[str], Header(alias="X-Solslot-Admin-Operation-Id")
        ] = None,
    ) -> AdminClaims:
        if not settings.admin_operation_approvals_enabled:
            if settings.runtime_environment in {"development", "test"}:
                return claims
            raise HTTPException(
                status_code=503,
                detail="owner-plus-one admin approvals cannot be disabled in deployment",
            )
        if operation_id is None:
            raise HTTPException(
                status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                detail="X-Solslot-Admin-Operation-Id is required",
            )
        raw_body = await request.body()
        if raw_body:
            try:
                parsed_body = json.loads(raw_body)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="request body must be JSON") from exc
        else:
            parsed_body = None
        try:
            binding = canonical_request_binding(
                method=request.method,
                path=request.url.path,
                query=list(request.query_params.multi_items()),
                body=parsed_body,
                if_match=request.headers.get("if-match"),
            )
            value = store.get(operation_id)
            core = _core_from_record(value)
            if expected_operation == 'mint.publish' and claims.sub.lower() != value['created_by'].lower():
                raise HTTPException(status_code=403, detail='Only the original proposer may publish')
            roster = resolve_admin_roster(settings)
            if core.authority_launcher_id != roster.launcher_id:
                raise ValueError("admin operation is bound to a stale authority launcher")
            required_signatures = {
                int(item["admin_index"]): bytes.fromhex(
                    str(item["compressed_pubkey"]).removeprefix("0x")
                )
                for item in value["signatures"]
                if int(item["admin_index"]) in {0, 1, 2}
            }
            if required_signatures.get(0) != roster.compressed_pubkeys[0] or not any(
                required_signatures.get(index) == roster.compressed_pubkeys[index]
                for index in (1, 2)
            ):
                raise ValueError("admin operation signatures are stale for the active roster")
            store.consume(
                operation_id=operation_id,
                expected_operation=expected_operation,
                expected_payload_hash=request_binding_hash(binding),
                caller=claims.sub,
                now=int(time.time()),
            )
            request.state.admin_operation = value
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return claims

    setattr(dependency, "__solslot_admin_operation__", expected_operation)
    return dependency


__all__ = [
    "ALLOWED_OPERATIONS",
    "OperationStore",
    "canonical_request_binding",
    "get_operation_store",
    "request_binding_hash",
    "require_admin_operation",
    "resolve_admin_roster",
    "router",
]
