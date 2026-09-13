"""zkPassport gasless relayer — FastAPI router (ERC-2771 meta-transactions).

Endpoint:
  POST /zkpassport/relay — submit a user-signed ForwardRequest to the
       SolslotForwarder, paying the gas on the user's behalf.

Why this exists
---------------
Alpha testers shouldn't need Testnet ETH to complete on-chain verification.
The user still signs an EIP-712 ``ForwardRequest`` in their wallet (a gasless
signature — no transaction), and this service relays it through the ERC-2771
forwarder while paying the gas.  The forwarder verifies the user's signature +
nonce on-chain, and the emitter attributes the event to the user via
``_msgSender()`` — so the relayer is never the logical author.

Security model
--------------
  - ``to`` is pinned to the configured emitter; any other target is rejected,
    so the funded key can only drive the selected enrollment function.
  - Canonical calldata must match the saved legacy or permit enrollment exactly.
  - The forwarder ``verify()`` (signature/nonce/deadline) AND the full
    ``execute()`` are simulated via ``eth_call`` before any gas is spent, so
    invalid proofs, expired signatures, and replays cost nothing.
  - SQLite-WAL budgets, nonce locks, bridge-coin uniqueness, and a circuit
    breaker protect the sponsored key across restarts and API workers.
  - Returns 503 when ``SOLSLOT_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX`` is unset.
"""
from __future__ import annotations

import hashlib
import json
import time
from functools import cache
import re

from eth_abi import decode as abi_decode, encode as abi_encode
from eth_account import Account
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Literal, Any
from web3 import Web3
from web3.exceptions import ContractLogicError

from .config import Settings
from .credential_auth import OwnerAuth, verify_owner_auth, verify_vault_session, require_alpha_writes
from .credential_ledger import (
    LedgerCircuitOpen,
    LedgerConflict,
    LedgerRateLimited,
    get_credential_ledger,
)
from .server_hardening import trusted_client_ip
from .zkpassport_enrollments import _record_permit, _require_enrollment_bridge_policy, _active_genesis_artifact, _fetch_verified_evm_attestation
from .evm_relay_transaction import canonical_receipt

router = APIRouter(prefix="/zkpassport", tags=["zkpassport"])

# First 4 bytes of keccak256("verifyAndEmit((bytes32,bytes32,uint64),bytes)").
_VERIFY_AND_EMIT_SELECTOR = "0xd33b3d83"
_ENROLLMENT_BINDING_ABI = "(bytes32,bytes32,uint64)"
_REVERT_SELECTOR_RE = re.compile(r"0x[0-9a-fA-F]{8}")
_KNOWN_REVERT_SELECTORS = {
    "0xd6bda275": (
        "OpenZeppelin FailedCall(): the trusted forwarder accepted the request, "
        "but the emitter call reverted. Refresh the enrollment and QR; if it "
        "persists, the proof domain/scope or bridge coin fields do not match "
        "the deployed emitter."
    ),
    "0xd611c318": "ProofVerificationFailed(): zkPassport verifier rejected the proof.",
    "0xa54999ed": "ScopeMismatch(): zkPassport proof scope does not match this vault.",
    "0x8c7f1d8f": "InvalidZkPassportProof(): emitter rejected the zkPassport proof.",
    "0x4db028fe": "InvalidBridgeCoinId(): bridge parent, amount, or policy hash mismatch.",
}

# verifyAndEmit measures ~1.05M gas; cap the forwarded gas to leave headroom
# without letting a caller drain the relayer through an oversized inner call.
_MAX_INNER_GAS = 3_000_000
# Bound the replay window: reject ForwardRequests whose deadline is further out.
_MAX_DEADLINE_WINDOW_SECONDS = 3600

_FORWARD_REQUEST_COMPONENTS = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "gas", "type": "uint256"},
    {"name": "deadline", "type": "uint48"},
    {"name": "data", "type": "bytes"},
    {"name": "signature", "type": "bytes"},
]
_FORWARDER_ABI = [
    {
        "type": "function",
        "name": "execute",
        "stateMutability": "payable",
        "inputs": [{"name": "request", "type": "tuple", "components": _FORWARD_REQUEST_COMPONENTS}],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "verify",
        "stateMutability": "view",
        "inputs": [{"name": "request", "type": "tuple", "components": _FORWARD_REQUEST_COMPONENTS}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "nonces",
        "stateMutability": "view",
        "inputs": [{"name": "owner", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]
_EMITTER_SECURITY_ABI = [
    {
        "type": "function",
        "name": "bridgePolicyHash",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "isTrustedForwarder",
        "stateMutability": "view",
        "inputs": [{"name": "forwarder", "type": "address"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "trustedDirectRelayer",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
]


def _load_settings() -> Settings:
    return Settings()


@cache
def _w3(rpc_url: str) -> Web3:
    return Web3(Web3.HTTPProvider(rpc_url))


# ── Request / response models ────────────────────────────────────────────────
class RelayRequest(BaseModel):
    """A user-signed OpenZeppelin ERC2771Forwarder ForwardRequestData."""

    model_config = {"populate_by_name": True}

    from_address: str = Field(alias="from")
    to: str
    value: str = "0"
    gas: str
    deadline: int
    data: str
    signature: str


class RelayResponse(BaseModel):
    tx_hash: str
    relayer: str
    signer: str
    submission_status: Literal["submitted", "unknown", "confirmed", "reverted", "expired"] = "submitted"


class BlsRelayRequest(BaseModel):
    """Canonical emitter calldata authorized by the owning Chia BLS key."""

    data: str = Field(..., min_length=10)
    ownerAuth: OwnerAuth


def _decode_enrollment_calldata(data: bytes) -> tuple[str, str, int]:
    from .enrollment_permit_runtime import decode_enrollment
    parsed = decode_enrollment(data)
    return parsed.vault, parsed.parent, parsed.amount


def _validate_relay_permit(settings, enrollment, session, data: bytes, *, live=False):
    from .enrollment_permit_runtime import require_calldata_record
    selected = bool(settings.enrollment_permit_release_identity or enrollment.get("enrollmentPermit"))
    permit = _record_permit(settings, enrollment, owner_auth_type=session.vault_record.auth_type,
        owner_key=session.owner_key, now=int(time.time()) if live else None) if selected else None
    try:
        require_calldata_record(data, enrollment, permit)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return permit


def _require_relayer_account(settings: Settings):
    key = settings.zkpassport_relayer_private_key_hex
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport relayer is not configured (SOLSLOT_ZKPASSPORT_RELAYER_PRIVATE_KEY_HEX unset).",
        )
    try:
        return Account.from_key(key)
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean 503
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="zkPassport relayer key is invalid.",
        ) from exc


def _describe_revert(exc: BaseException) -> str:
    text = str(exc)
    selectors = []
    for match in _REVERT_SELECTOR_RE.findall(text):
        selector = match.lower()
        if selector not in selectors:
            selectors.append(selector)
    if not selectors:
        return text
    decoded = [
        _KNOWN_REVERT_SELECTORS.get(selector, f"Unknown EVM revert selector {selector}.")
        for selector in selectors
    ]
    return f"{'; '.join(decoded)} Raw error: {text}"


def _simulate_forwarded_inner_call(
    w3: Web3,
    *,
    forwarder_address: str,
    emitter_address: str,
    signer_address: str,
    data: bytes,
) -> str:
    """Simulate the ERC-2771 target call to expose its real revert data.

    OpenZeppelin's forwarder wraps a target revert in ``FailedCall()``.  A
    direct ``eth_call`` from the trusted forwarder with the original signer
    appended reproduces the exact calldata seen by ``ERC2771Context`` and
    preserves the emitter/verifier custom error for operator diagnostics.
    """
    forwarded_data = data + Web3.to_bytes(hexstr=signer_address)
    try:
        w3.eth.call(
            {
                "from": forwarder_address,
                "to": emitter_address,
                "value": 0,
                "data": forwarded_data,
            }
        )
    except Exception as exc:  # noqa: BLE001 - the RPC provider controls the exception type
        return _describe_revert(exc)
    return "The emitter simulation succeeded; the failure is in the forwarder execution path."


def _verify_emitter_deployment(
    w3: Web3,
    settings: Settings,
    emitter_address: str,
    *,
    expected_forwarder: str | None = None,
    expected_direct_relayer: str | None = None,
) -> None:
    if settings.enrollment_permit_release_identity:
        from .enrollment_permit_runtime import verify_selected_emitter
        artifact = _active_genesis_artifact(settings)
        if emitter_address.lower() != artifact["evmAddresses"]["attestationEmitter"].lower():
            raise HTTPException(status_code=503, detail="Permit emitter target differs from the signed release.")
        try:
            verify_selected_emitter(w3, artifact, expected_direct_relayer=expected_direct_relayer)
        except ValueError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    expected_policy = str(settings.zkpassport_bridge_policy_hash or "").lower()
    if re.fullmatch(r"0x[0-9a-f]{64}", expected_policy) is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The canonical zkPassport bridge policy is not configured.",
        )
    emitter = w3.eth.contract(address=emitter_address, abi=_EMITTER_SECURITY_ABI)
    deployed_policy = Web3.to_hex(emitter.functions.bridgePolicyHash().call()).lower()
    if deployed_policy != expected_policy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured emitter does not use the canonical Chia bridge policy.",
        )
    if expected_forwarder and not emitter.functions.isTrustedForwarder(
        expected_forwarder
    ).call():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured emitter does not trust the canonical Solslot forwarder.",
        )
    if expected_direct_relayer:
        deployed_relayer = Web3.to_checksum_address(
            emitter.functions.trustedDirectRelayer().call()
        )
        if deployed_relayer != Web3.to_checksum_address(expected_direct_relayer):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Configured emitter does not trust this BLS relayer account.",
            )


class RelayRecoveryResponse(BaseModel):
    vaultLauncherId: str
    status: Literal['not_started','incomplete','pending','confirmed','reverted','expired']
    txHash: str | None = None
    canResubmit: bool = False
    proof: dict[str, Any] | None = None


def _relay_context(settings, enrollment, session):
    # The full authenticated artifact is bound, including additive activation
    # evidence. No mutable environment value can substitute for its identity.
    artifact = _active_genesis_artifact(settings)
    return dict(environment=settings.runtime_environment, network=settings.network,
        chainId=settings.zkpassport_evm_chain_id, emitter=settings.zkpassport_emitter_address.lower(),
        forwarder=(settings.zkpassport_forwarder_address or '').lower(),
        artifactBinding=hashlib.sha256(json.dumps(artifact,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),
        vaultLauncherId=enrollment['vaultLauncherId'],bridgeCoinId=enrollment['bridgeCoinId'],
        bridgePolicyHash=enrollment['bridgePolicyHash'],owner=session.owner_key.lower(),mode=session.auth_type)


def _normalized_request(req):
    if isinstance(req, BlsRelayRequest):
        return dict(mode='chia_bls',data=req.data.lower())
    return dict(mode='evm',**{'from':req.from_address.lower()},to=req.to.lower(),value=str(int(req.value)),
        gas=str(int(req.gas)),deadline=req.deadline,data=req.data.lower(),signature=req.signature.lower())


def _saved_relay(settings, enrollment, session, request_payload=None):
    ledger = get_credential_ledger(settings)
    attempt = ledger.get_relay_attempt(enrollment['vaultLauncherId'])
    if attempt is None:
        return None
    if attempt['owner_key'].lower() != session.owner_key.lower():
        raise HTTPException(status_code=403, detail='The retained relay belongs to a different vault owner.')
    saved = ledger.get_relay_transaction(enrollment['vaultLauncherId'])
    if saved is None:
        raise HTTPException(status_code=409, detail='An earlier relay reservation has no recoverable signed transaction. Contact support with this vault; do not start another proof.')
    if json.loads(saved['context_json']) != _relay_context(settings,enrollment,session):
        raise HTTPException(status_code=409, detail='The retained transaction belongs to a different owner, network or release. Contact support to reconcile it.')
    if request_payload is not None and json.loads(saved['request_json']) != request_payload:
        raise HTTPException(status_code=409, detail='A different proof or authorization is already reserved. Resume the original transaction.')
    return saved


def _check_saved_deployment(w3, settings, saved):
    context = json.loads(saved['context_json'])
    if int(w3.eth.chain_id) != saved['chain_id'] or saved['chain_id'] != settings.zkpassport_evm_chain_id:
        raise HTTPException(status_code=503, detail='The relay RPC is on a different network from the retained transaction.')
    emitter = Web3.to_checksum_address(context['emitter'])
    forwarder = Web3.to_checksum_address(context['forwarder']) if context['forwarder'] else None
    if not w3.eth.get_code(emitter) or (context['mode']=='evm' and (not forwarder or not w3.eth.get_code(forwarder))):
        raise HTTPException(status_code=503, detail='The retained relay deployment is unavailable.')
    _verify_emitter_deployment(w3,settings,emitter,
        expected_forwarder=forwarder if context['mode']=='evm' else None,
        expected_direct_relayer=saved['relayer'] if context['mode']=='chia_bls' else None)


def _relay_receipt_state(w3, settings, saved, enrollment, session):
    try:
        receipt = canonical_receipt(w3,saved['tx_hash'],settings.zkpassport_evm_min_confirmations)
    except ValueError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502,detail='Could not check the retained transaction receipt. Your original transaction is preserved.') from exc
    if receipt is None:
        return None
    if receipt['status']==0:
        return RelayRecoveryResponse(vaultLauncherId=enrollment['vaultLauncherId'],status='reverted',txHash=saved['tx_hash'])
    event = _fetch_verified_evm_attestation(settings,transaction_hash=saved['tx_hash'],expected_vault_launcher_id=enrollment['vaultLauncherId'])
    expected_sender = session.owner_key if session.auth_type=='evm' else saved['relayer']
    if (event.sender.lower()!=expected_sender.lower() or event.bridge_coin_id!=enrollment['bridgeCoinId']
            or event.bridge_parent_id!=enrollment['bridgeParentId'] or event.bridge_amount!=enrollment['bridgeAmount']
            or event.bridge_policy_hash!=enrollment['bridgePolicyHash']):
        raise HTTPException(status_code=409,detail='The confirmed transaction does not match the retained owner and bridge reservation.')
    get_credential_ledger(settings).require_submitted_relay(transaction_hash=saved['tx_hash'],vault_launcher_id=enrollment['vaultLauncherId'],
        owner_key=session.owner_key,bridge_coin_id=event.bridge_coin_id)
    return RelayRecoveryResponse(vaultLauncherId=enrollment['vaultLauncherId'],status='confirmed',txHash=saved['tx_hash'],proof=dict(
        txHash=saved['tx_hash'],vaultLauncherId=event.vault_launcher_id,policyVersion=event.policy_version,
        identityAttestRoot=event.identity_attest_root,attestationLeafHash=event.attestation_leaf_hash,
        attestationProof=dict(bitpath=0,siblings=[]),bridgePolicyHash=event.bridge_policy_hash,
        bridgeParentId=event.bridge_parent_id,bridgeAmount=event.bridge_amount,bridgeCoinId=event.bridge_coin_id,
        bridgeMessage=event.bridge_message,validatorMessage=event.validator_message))


def _dispatch_saved(w3,settings,saved,session):
    require_alpha_writes(settings)
    if getattr(session, 'scope', 'vault') != 'vault':
        raise HTTPException(status_code=403, detail='Reconnect for full vault authorization before resubmitting the retained transaction.')
    ledger=get_credential_ledger(settings)
    enrollment=ledger.get_enrollment(saved['vault_launcher_id'])
    if enrollment is None:
        raise HTTPException(status_code=409,detail='The retained enrollment is unavailable.')
    _require_enrollment_bridge_policy(settings,enrollment,execution=True)
    request_payload = json.loads(saved['request_json'])
    _validate_relay_permit(settings, enrollment, session,
        Web3.to_bytes(hexstr=request_payload['data']), live=True)
    try:
        saved=ledger.begin_relay_dispatch(saved['request_digest'])
    except LedgerRateLimited as exc:
        raise HTTPException(status_code=429,detail=str(exc)) from exc
    except LedgerCircuitOpen as exc:
        raise HTTPException(status_code=503,detail=str(exc)) from exc
    except LedgerConflict as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    accepted=False
    try:
        observed=Web3.to_hex(w3.eth.send_raw_transaction(bytes.fromhex(saved['raw_transaction_hex']))).lower()
        accepted=observed==saved['tx_hash']
    except Exception:
        # Acceptance is unknown, never a reason to discard a signed identity.
        pass
    ledger.finish_relay_dispatch(request_digest=saved['request_digest'],accepted=accepted,
        failure_threshold=settings.zkpassport_relay_circuit_failure_threshold,
        cooldown_seconds=settings.zkpassport_relay_circuit_cooldown_seconds)
    return RelayResponse(tx_hash=saved['tx_hash'],relayer=saved['relayer'],signer=session.owner_key,
        submission_status='submitted' if accepted else 'unknown')


def _resume_saved(settings,enrollment,session,saved,*,dispatch):
    w3=_w3(settings.zkpassport_evm_rpc_url)
    _check_saved_deployment(w3,settings,saved)
    outcome=_relay_receipt_state(w3,settings,saved,enrollment,session)
    if outcome is not None:return outcome
    now=int(time.time())
    if now>=saved['retry_until']:
        return RelayRecoveryResponse(vaultLauncherId=enrollment['vaultLauncherId'],status='expired',txHash=saved['tx_hash'])
    if dispatch:
        if enrollment['status']!='reserved':
            raise HTTPException(status_code=409,detail='Enrollment has advanced; check its receipt without submitting again.')
        _dispatch_saved(w3,settings,saved,session)
    return RelayRecoveryResponse(vaultLauncherId=enrollment['vaultLauncherId'],status='pending',txHash=saved['tx_hash'],
        canResubmit=enrollment['status']=='reserved' and settings.alpha_writes_enabled)


def _recovery_inputs(settings,request,vault_launcher_id):
    if re.fullmatch(r'0x[0-9a-fA-F]{64}',vault_launcher_id) is None:
        raise HTTPException(status_code=422,detail='Invalid vault launcher ID.')
    key=vault_launcher_id.lower()
    session=verify_vault_session(settings,request,key,allow_recovery=True)
    enrollment=get_credential_ledger(settings).get_enrollment(key)
    if not enrollment:raise HTTPException(status_code=404,detail='Enrollment not found.')
    _require_enrollment_bridge_policy(settings,enrollment)
    return enrollment,session


@router.get('/relay/{vault_launcher_id}',response_model=RelayRecoveryResponse)
def get_relay_recovery(vault_launcher_id: str,request: Request):
    settings=_load_settings()
    enrollment,session=_recovery_inputs(settings,request,vault_launcher_id)
    ledger=get_credential_ledger(settings)
    attempt=ledger.get_relay_attempt(enrollment['vaultLauncherId'])
    if attempt is None:
        return RelayRecoveryResponse(vaultLauncherId=enrollment['vaultLauncherId'],status='not_started')
    if attempt['owner_key'].lower()!=session.owner_key.lower():
        raise HTTPException(status_code=403,detail='The retained relay belongs to a different vault owner.')
    if ledger.get_relay_transaction(enrollment['vaultLauncherId']) is None:
        return RelayRecoveryResponse(vaultLauncherId=enrollment['vaultLauncherId'],status='incomplete',txHash=attempt['tx_hash'])
    return _resume_saved(settings,enrollment,session,_saved_relay(settings,enrollment,session),dispatch=False)


@router.post('/relay/{vault_launcher_id}/resume',response_model=RelayRecoveryResponse)
def resume_relay(vault_launcher_id: str,request: Request):
    settings=_load_settings()
    enrollment,session=_recovery_inputs(settings,request,vault_launcher_id)
    saved=_saved_relay(settings,enrollment,session)
    if saved is None:raise HTTPException(status_code=404,detail='No retained relay transaction exists.')
    return _resume_saved(settings,enrollment,session,saved,dispatch=True)


def _existing_response(settings,enrollment,session,payload):
    saved=_saved_relay(settings,enrollment,session,payload)
    if saved is None:return None
    outcome=_resume_saved(settings,enrollment,session,saved,dispatch=True)
    return RelayResponse(tx_hash=saved['tx_hash'],relayer=saved['relayer'],signer=session.owner_key,
        submission_status={'pending':'unknown','confirmed':'confirmed','reverted':'reverted','expired':'expired'}[outcome.status])


@router.post(
    "/relay",
    response_model=RelayResponse,
    summary="Relay a user-signed ForwardRequest, sponsoring the gas",
)
def relay(req: RelayRequest, request: Request) -> RelayResponse:
    settings = _load_settings()

    if not settings.zkpassport_forwarder_address or not settings.zkpassport_emitter_address:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Fresh Solslot V2 forwarder and emitter addresses are not configured.",
        )

    # ── Pin addresses; the client cannot redirect the relayer ──
    try:
        to = Web3.to_checksum_address(req.to)
        signer = Web3.to_checksum_address(req.from_address)
        forwarder_addr = Web3.to_checksum_address(settings.zkpassport_forwarder_address)
        emitter_addr = Web3.to_checksum_address(settings.zkpassport_emitter_address)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Invalid address: {exc}") from exc

    if to != emitter_addr:
        raise HTTPException(status_code=400, detail="request.to must be the configured emitter.")
    from .enrollment_permit_runtime import PERMIT_SELECTOR
    if not req.data.lower().startswith((_VERIFY_AND_EMIT_SELECTOR, "0x" + PERMIT_SELECTOR.hex())):
        raise HTTPException(status_code=400, detail="request.data must call a supported enrollment function.")

    try:
        data_bytes = Web3.to_bytes(hexstr=req.data)
        sig_bytes = Web3.to_bytes(hexstr=req.signature)
        vault_launcher_id, bridge_parent_id, bridge_amount = _decode_enrollment_calldata(
            data_bytes
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=422,
            detail=f"request.data is not canonical Solslot V2 enrollment calldata: {exc}",
        ) from exc

    try:
        auth_payload = _normalized_request(req)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="value and gas must be integer strings.") from exc
    verified_owner = verify_vault_session(settings, request, vault_launcher_id)
    if verified_owner.auth_type != 'evm':
        raise HTTPException(status_code=409, detail='Chia vaults must use the BLS relay path.')
    if verified_owner.vault_record.owner_evm_address and (
        verified_owner.vault_record.owner_evm_address.lower() != signer.lower()
    ):
        raise HTTPException(
            status_code=403,
            detail="ForwardRequest signer is not the registered EVM vault owner.",
        )

    ledger = get_credential_ledger(settings)
    enrollment = ledger.get_enrollment(vault_launcher_id.lower())
    if not enrollment:
        raise HTTPException(status_code=404, detail="Enrollment not found for relay binding.")
    _require_enrollment_bridge_policy(settings,enrollment, execution=True)
    _validate_relay_permit(settings, enrollment, verified_owner, data_bytes)
    existing=_existing_response(settings,enrollment,verified_owner,auth_payload)
    if existing is not None:return existing
    permit = _validate_relay_permit(settings, enrollment, verified_owner, data_bytes, live=True)
    if permit is not None and req.deadline > permit.expires_at:
        raise HTTPException(status_code=409, detail="ForwardRequest outlives the saved permit.")
    if str(enrollment.get("status")) != "reserved":
        raise HTTPException(status_code=409, detail="Enrollment is not awaiting an EVM proof.")
    _require_enrollment_bridge_policy(settings, enrollment, execution=True)
    if (
        str(enrollment.get("bridgeParentId", "")).lower() != bridge_parent_id.lower()
        or int(enrollment.get("bridgeAmount", 0)) != bridge_amount
    ):
        raise HTTPException(
            status_code=409,
            detail="Relay binding does not match the reserved Chia bridge coin.",
        )

    try:
        value = int(req.value)
        gas = int(req.gas)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="value and gas must be integer strings.") from exc

    if value != 0:
        raise HTTPException(status_code=400, detail="request.value must be 0.")
    if gas <= 0 or gas > _MAX_INNER_GAS:
        raise HTTPException(status_code=400, detail=f"request.gas must be in (0, {_MAX_INNER_GAS}].")

    now = int(time.time())
    if req.deadline <= now:
        raise HTTPException(status_code=400, detail="request.deadline has already passed.")
    if req.deadline > now + _MAX_DEADLINE_WINDOW_SECONDS:
        raise HTTPException(status_code=400, detail="request.deadline is too far in the future.")

    request_tuple = (signer, to, value, gas, req.deadline, data_bytes, sig_bytes)

    require_alpha_writes(settings)
    account = _require_relayer_account(settings)
    context = _relay_context(settings,enrollment,verified_owner)
    w3 = _w3(settings.zkpassport_evm_rpc_url)
    try:
        observed_chain_id = int(w3.eth.chain_id)
        if observed_chain_id != settings.zkpassport_evm_chain_id:
            raise HTTPException(
                status_code=503,
                detail="Configured zkPassport RPC is on the wrong EVM chain.",
            )
        if not w3.eth.get_code(forwarder_addr) or not w3.eth.get_code(emitter_addr):
            raise HTTPException(
                status_code=503,
                detail="Fresh Solslot V2 forwarder or emitter bytecode is missing.",
            )
        _verify_emitter_deployment(
            w3,
            settings,
            emitter_addr,
            expected_forwarder=forwarder_addr,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC deployment check failed: {exc}") from exc
    forwarder = w3.eth.contract(address=forwarder_addr, abi=_FORWARDER_ABI)

    # ── Free pre-checks: signature/nonce/deadline, then full inner simulation ──
    try:
        valid = forwarder.functions.verify(request_tuple).call()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC verify() failed: {exc}") from exc
    if not valid:
        raise HTTPException(status_code=400, detail="ForwardRequest signature/nonce/deadline is invalid.")

    try:
        forwarder.functions.execute(request_tuple).call({"from": account.address, "value": 0})
    except ContractLogicError as exc:
        inner_detail = _simulate_forwarded_inner_call(
            w3,
            forwarder_address=forwarder_addr,
            emitter_address=to,
            signer_address=signer,
            data=data_bytes,
        )
        raise HTTPException(
            status_code=400,
            detail=(
                f"Simulation reverted: {_describe_revert(exc)} "
                f"Inner emitter simulation: {inner_detail}"
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC simulation failed: {exc}") from exc

    try:
        forwarder_nonce = int(forwarder.functions.nonces(signer).call())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC nonce lookup failed: {exc}") from exc
    request_digest = "0x" + hashlib.sha256(
        json.dumps(auth_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    source_ip = trusted_client_ip(request.scope, settings)
    try:
        ledger.reserve_relay(
            request_digest=request_digest,
            vault_launcher_id=vault_launcher_id,
            owner_key=verified_owner.owner_key,
            source_ip=source_ip,
            bridge_coin_id=str(enrollment["bridgeCoinId"]),
            forwarder_nonce=forwarder_nonce,
            inner_gas=gas,
            per_ip_per_minute=settings.zkpassport_relay_per_ip_per_minute,
            per_owner_per_minute=settings.zkpassport_relay_per_owner_per_minute,
            per_vault_per_hour=settings.zkpassport_relay_per_vault_per_hour,
            global_gas_per_day=settings.zkpassport_relay_global_gas_per_day,
        )
    except LedgerRateLimited as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except LedgerCircuitOpen as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # ── Build, sign, and broadcast the sponsored transaction ──
    try:
        estimated = forwarder.functions.execute(request_tuple).estimate_gas(
            {"from": account.address, "value": 0}
        )
        tx = forwarder.functions.execute(request_tuple).build_transaction(
            {
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                "value": 0,
                "chainId": settings.zkpassport_evm_chain_id,
                "gas": int(estimated * 1.25),
            }
        )
        saved=ledger.prepare_relay_transaction(request_digest=request_digest,context=context,request=auth_payload,
            transaction=tx,sign_transaction=account.sign_transaction,retry_until=req.deadline)
    except Exception as exc:
        # Nothing may be sent unless the exact signed bytes committed first.
        raise HTTPException(status_code=502,detail='Relay transaction preparation failed. Check the retained reservation before retrying.') from exc
    return _dispatch_saved(w3,settings,saved,verified_owner)


@router.post(
    "/relay/bls",
    response_model=RelayResponse,
    summary="Relay a Chia-owner-authorized zkPassport proof",
)
def relay_bls(req: BlsRelayRequest, request: Request) -> RelayResponse:
    """Sponsor a direct emitter call for a BLS-owned vault.

    A Chia owner cannot sign an ERC-2771 ``ForwardRequest``. Instead, the
    owner signs a one-use CHIP-0002 challenge over the exact canonical
    emitter calldata. The relayer is the EVM event sender, while the later
    Chia stamp and validator claim remain authorized by the canonical BLS
    vault owner.
    """

    settings = _load_settings()
    if not settings.zkpassport_emitter_address:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Fresh Solslot V2 emitter address is not configured.",
        )
    try:
        emitter_addr = Web3.to_checksum_address(settings.zkpassport_emitter_address)
        data_bytes = Web3.to_bytes(hexstr=req.data)
        vault_launcher_id, bridge_parent_id, bridge_amount = _decode_enrollment_calldata(
            data_bytes
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=422,
            detail=f"request.data is not canonical Solslot V2 enrollment calldata: {exc}",
        ) from exc

    session = verify_vault_session(settings, request, vault_launcher_id)
    if session.auth_type != "chia_bls":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="EVM vaults must use a signed ForwardRequest.",
        )
    ledger=get_credential_ledger(settings)
    enrollment=ledger.get_enrollment(vault_launcher_id.lower())
    if not enrollment:raise HTTPException(status_code=404,detail='Enrollment not found for relay binding.')
    _require_enrollment_bridge_policy(settings,enrollment, execution=True)
    payload=_normalized_request(req)
    _validate_relay_permit(settings, enrollment, session, data_bytes)
    existing=_existing_response(settings,enrollment,session,payload)
    if existing is not None:return existing
    context=_relay_context(settings,enrollment,session)
    permit = _validate_relay_permit(settings, enrollment, session, data_bytes, live=True)
    retry_until=min(int(time.time())+900, permit.expires_at) if permit is not None else int(time.time())+900
    account=_require_relayer_account(settings)
    verified_owner = verify_owner_auth(
        settings,
        vault_launcher_id=vault_launcher_id,
        action="relay",
        payload={"data": req.data.lower()},
        owner_auth=req.ownerAuth,
    )
    if (
        verified_owner.auth_type != "chia_bls"
        or verified_owner.owner_key.lower() != session.owner_key.lower()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The relay authorization does not match the vault session owner.",
        )

    ledger = get_credential_ledger(settings)
    enrollment = ledger.get_enrollment(vault_launcher_id.lower())
    if not enrollment:
        raise HTTPException(status_code=404, detail="Enrollment not found for relay binding.")
    if str(enrollment.get("status")) != "reserved":
        raise HTTPException(status_code=409, detail="Enrollment is not awaiting an EVM proof.")
    _require_enrollment_bridge_policy(settings, enrollment, execution=True)
    if (
        str(enrollment.get("bridgeParentId", "")).lower() != bridge_parent_id.lower()
        or int(enrollment.get("bridgeAmount", 0)) != bridge_amount
    ):
        raise HTTPException(
            status_code=409,
            detail="Relay binding does not match the reserved Chia bridge coin.",
        )

    w3 = _w3(settings.zkpassport_evm_rpc_url)
    try:
        if int(w3.eth.chain_id) != settings.zkpassport_evm_chain_id:
            raise HTTPException(
                status_code=503,
                detail="Configured zkPassport RPC is on the wrong EVM chain.",
            )
        if not w3.eth.get_code(emitter_addr):
            raise HTTPException(
                status_code=503,
                detail="Fresh Solslot V2 emitter bytecode is missing.",
            )
        _verify_emitter_deployment(
            w3,
            settings,
            emitter_addr,
            expected_direct_relayer=account.address,
        )
        transaction = {
            "from": account.address,
            "to": emitter_addr,
            "value": 0,
            "data": data_bytes,
        }
        w3.eth.call(transaction)
        estimated = int(w3.eth.estimate_gas(transaction))
    except HTTPException:
        raise
    except ContractLogicError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Emitter simulation reverted: {_describe_revert(exc)}",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"RPC simulation failed: {exc}") from exc
    if estimated <= 0 or estimated > _MAX_INNER_GAS:
        raise HTTPException(
            status_code=400,
            detail=f"Estimated emitter gas must be in (0, {_MAX_INNER_GAS}].",
        )

    relayer_nonce = int(w3.eth.get_transaction_count(account.address, "pending"))
    request_digest = "0x" + hashlib.sha256(
        json.dumps(
            {
                "mode": "chia_bls",
                "vaultLauncherId": vault_launcher_id,
                "data": req.data.lower(),
                "owner": session.owner_key.lower(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    source_ip = trusted_client_ip(request.scope, settings)
    try:
        ledger.reserve_relay(
            request_digest=request_digest,
            vault_launcher_id=vault_launcher_id,
            owner_key=session.owner_key,
            source_ip=source_ip,
            bridge_coin_id=str(enrollment["bridgeCoinId"]),
            forwarder_nonce=relayer_nonce,
            inner_gas=estimated,
            per_ip_per_minute=settings.zkpassport_relay_per_ip_per_minute,
            per_owner_per_minute=settings.zkpassport_relay_per_owner_per_minute,
            per_vault_per_hour=settings.zkpassport_relay_per_vault_per_hour,
            global_gas_per_day=settings.zkpassport_relay_global_gas_per_day,
        )
    except LedgerRateLimited as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except LedgerCircuitOpen as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except LedgerConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    try:
        tx = {
            "from": account.address,
            "to": emitter_addr,
            "value": 0,
            "data": data_bytes,
            "nonce": relayer_nonce,
            "chainId": settings.zkpassport_evm_chain_id,
            "gas": int(estimated * 1.25),
            "gasPrice": int(w3.eth.gas_price),
        }
        saved=ledger.prepare_relay_transaction(request_digest=request_digest,context=context,request=payload,
            transaction=tx,sign_transaction=account.sign_transaction,retry_until=retry_until)
    except Exception as exc:
        raise HTTPException(status_code=502,detail='Relay transaction preparation failed. Check the retained reservation before retrying.') from exc
    return _dispatch_saved(w3,settings,saved,session)
