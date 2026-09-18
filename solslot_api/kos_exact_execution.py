"""Signed exact-bundle handoff to the Key of Solomon executor."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
from pathlib import Path
import stat
from typing import Any

import httpx
from chia_rs import AugSchemeMPL, PrivateKey
from chia_rs.sized_bytes import bytes32

from .protocol_submission import PreparedProtocolBundle, ProtocolSubmissionError


_DOMAIN = b"SOLSLOT_KOS_EXACT_EXECUTION_V2"
MAX_EXACT_INPUTS = 102
MAX_EXACT_OUTPUTS = 200


class ExactExecutionAction(IntEnum):
    RESERVE = 1
    DELIVER = 2
    RELEASE = 3
    RECEIPT = 4
    EXTEND_PROCESSING = 5
    EXTEND_SETTLEMENT = 6
    VOUCHER_TERMINAL = 7


@dataclass(frozen=True)
class ExactExecutionOutput:
    coin_id: bytes32
    puzzle_hash: bytes32
    amount: int


@dataclass(frozen=True)
class ExactExecutionRequest:
    action: ExactExecutionAction
    purchase_id: bytes32
    artifact_hash: bytes32
    claim_hash: bytes32
    expected_outputs: tuple[ExactExecutionOutput, ...]
    refund_continuation: tuple[bytes32, bytes32, bytes32] | None = None


class KeyOfSolomonExactExecutor:
    def __init__(
        self,
        *,
        url: str,
        private_key_file: str,
        expected_public_key: str,
        timeout_seconds: float,
        mtls_ca_path: str | None = None,
        mtls_cert_path: str | None = None,
        mtls_key_path: str | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.private_key = _load_private_key(private_key_file)
        expected = _hex_bytes(
            expected_public_key,
            48,
            "SOLSLOT_PAYMENT_KOS_EXECUTOR_PUBLIC_KEY",
        )
        if bytes(self.private_key.get_g1()) != expected:
            raise RuntimeError(
                "KoS exact-execution request key does not match its configured "
                "public key"
            )
        mtls = (mtls_ca_path, mtls_cert_path, mtls_key_path)
        if any(mtls) and not all(mtls):
            raise RuntimeError(
                "KoS exact executor mTLS requires CA, certificate, and key"
            )
        self.timeout_seconds = timeout_seconds
        self.verify: bool | str = mtls_ca_path or True
        self.cert: tuple[str, str] | None = (
            (str(mtls_cert_path), str(mtls_key_path))
            if mtls_cert_path and mtls_key_path
            else None
        )

    async def dispatch(
        self,
        request: ExactExecutionRequest,
        prepared: PreparedProtocolBundle,
    ) -> dict[str, Any]:
        inputs = tuple(
            sorted(
                (bytes32(coin.name()) for coin in prepared.bundle.removals()),
                key=bytes,
            )
        )
        outputs = _canonical_outputs(request.expected_outputs)
        bundle_id = bytes32(prepared.bundle.name())
        operation_reference = _hex32(request.purchase_id)
        digest = exact_execution_digest(
            operation_reference=operation_reference,
            action=request.action,
            purchase_id=request.purchase_id,
            artifact_hash=request.artifact_hash,
            claim_hash=request.claim_hash,
            spend_bundle_id=bundle_id,
            required_input_coin_ids=inputs,
            expected_outputs=outputs,
            fee_mojos=prepared.fee_mojos,
        )
        if request.refund_continuation is not None:
            if request.action != ExactExecutionAction.VOUCHER_TERMINAL:
                raise ValueError('Only an owner refund can continue its exact execution')
            digest = refund_continuation_digest(digest,request.refund_continuation)
        signature = AugSchemeMPL.sign(self.private_key, digest)
        payload = {
            "payment_intent": operation_reference,
            "kind": {
                "ProtocolExecute": {
                    "action": request.action.name,
                    "purchase_id": operation_reference,
                    "artifact_hash": _hex32(request.artifact_hash),
                    "claim_hash": _hex32(request.claim_hash),
                    "spend_bundle_id": _hex32(bundle_id),
                    "required_input_coin_ids": [
                        _hex32(value) for value in inputs
                    ],
                    "expected_outputs": [
                        {
                            "coin_id": _hex32(output.coin_id),
                            "puzzle_hash": _hex32(output.puzzle_hash),
                            "amount": output.amount,
                        }
                        for output in outputs
                    ],
                    "fee_mojos": prepared.fee_mojos,
                    "spend_bundle": prepared.bundle.to_json_dict(),
                }
            },
            "signature": "0x" + bytes(signature).hex(),
        }
        if request.refund_continuation is not None:
            previous,vault,fee = request.refund_continuation
            payload['kind'] = {'ProtocolContinueRefund':dict(execution=payload['kind']['ProtocolExecute'],
                previous_bundle_id=_hex32(previous),vault_coin_id=_hex32(vault),fee_coin_id=_hex32(fee))}
        try:
            async with httpx.AsyncClient(
                verify=self.verify,
                cert=self.cert,
                timeout=self.timeout_seconds,
            ) as client:
                response = await client.post(self.url + "/submit", json=payload)
        except httpx.HTTPError as exc:
            raise ProtocolSubmissionError(
                "Key of Solomon exact executor is unavailable",
                submission_attempted=True,
            ) from exc
        if response.status_code // 100 != 2:
            detail = response.text.strip()[:512]
            raise ProtocolSubmissionError(
                "Key of Solomon rejected the exact execution"
                + (f": {detail}" if detail else ""),
                submission_attempted=True,
            )
        return {
            "executor": self.url,
            "accepted": True,
            "httpStatus": response.status_code,
        }


def refund_continuation_digest(exact_digest: bytes, continuation: tuple[bytes32, bytes32, bytes32]) -> bytes:
    if len(exact_digest)!=32 or len(continuation)!=3 or any(len(v)!=32 for v in continuation):
        raise ValueError('Refund continuation digest requires exact 32-byte bindings')
    return hashlib.sha256(b'SOLSLOT_KOS_REFUND_CONTINUATION_V1'+exact_digest+b''.join(continuation)).digest()


def exact_execution_digest(
    *,
    operation_reference: str,
    action: ExactExecutionAction,
    purchase_id: bytes32,
    artifact_hash: bytes32,
    claim_hash: bytes32,
    spend_bundle_id: bytes32,
    required_input_coin_ids: tuple[bytes32, ...],
    expected_outputs: tuple[ExactExecutionOutput, ...],
    fee_mojos: int,
) -> bytes:
    if (
        not required_input_coin_ids
        or len(required_input_coin_ids) > MAX_EXACT_INPUTS
    ):
        raise ValueError("exact execution requires 1..102 input coins")
    if len(set(required_input_coin_ids)) != len(required_input_coin_ids):
        raise ValueError("exact execution input coin IDs must be unique")
    if tuple(sorted(required_input_coin_ids, key=bytes)) != required_input_coin_ids:
        raise ValueError("exact execution input coin IDs must be canonical")
    outputs = _canonical_outputs(expected_outputs)
    if outputs != expected_outputs:
        raise ValueError("exact execution outputs must be canonical")
    if fee_mojos < 0 or fee_mojos > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("exact execution fee must be uint64")
    digest = hashlib.sha256()
    digest.update(hashlib.sha256(operation_reference.encode("utf-8")).digest())
    digest.update(_DOMAIN)
    digest.update(bytes([int(action)]))
    digest.update(bytes(purchase_id))
    digest.update(bytes(artifact_hash))
    digest.update(bytes(claim_hash))
    digest.update(bytes(spend_bundle_id))
    digest.update(len(required_input_coin_ids).to_bytes(8, "big"))
    for coin_id in required_input_coin_ids:
        digest.update(bytes(coin_id))
    digest.update(len(outputs).to_bytes(8, "big"))
    for output in outputs:
        digest.update(bytes(output.coin_id))
        digest.update(bytes(output.puzzle_hash))
        digest.update(output.amount.to_bytes(8, "big"))
    digest.update(fee_mojos.to_bytes(8, "big"))
    return digest.digest()


def _canonical_outputs(
    outputs: tuple[ExactExecutionOutput, ...],
) -> tuple[ExactExecutionOutput, ...]:
    if not outputs or len(outputs) > MAX_EXACT_OUTPUTS:
        raise ValueError("exact execution requires 1..200 expected outputs")
    if len({output.coin_id for output in outputs}) != len(outputs):
        raise ValueError("exact execution output coin IDs must be unique")
    for output in outputs:
        if output.amount < 1 or output.amount > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("exact execution output amount must be uint64")
    return tuple(sorted(outputs, key=lambda output: bytes(output.coin_id)))


def _load_private_key(path_value: str) -> PrivateKey:
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("KoS exact-execution request key file is missing")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError(
            "KoS exact-execution request key file must have mode 0600"
        )
    value = path.read_bytes().strip()
    if len(value) != 32:
        try:
            value = bytes.fromhex(value.decode("ascii").removeprefix("0x"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError(
                "KoS exact-execution request key must be 32 raw bytes or hex"
            ) from exc
    if len(value) != 32:
        raise RuntimeError(
            "KoS exact-execution request key must be exactly 32 bytes"
        )
    try:
        return PrivateKey.from_bytes(value)
    except ValueError as exc:
        raise RuntimeError("KoS exact-execution request key is invalid") from exc


def _hex_bytes(value: str, size: int, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except (AttributeError, ValueError) as exc:
        raise RuntimeError(f"{field} is not valid hex") from exc
    if len(raw) != size:
        raise RuntimeError(f"{field} must be {size} bytes")
    return raw


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


__all__ = [
    "ExactExecutionAction",
    "ExactExecutionOutput",
    "ExactExecutionRequest",
    "KeyOfSolomonExactExecutor",
    "exact_execution_digest",
]
