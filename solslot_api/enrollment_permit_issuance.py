"""Owner-authenticated fresh-vault permit reservation and immutable issuance."""
from __future__ import annotations
import asyncio
import json
import secrets
import time
from typing import Any, Callable
from fastapi import HTTPException
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.enrollment_activation import activation_from_artifact,activation_context
from solslot_puzzles.enrollment_permit import EnrollmentPermit,permit_owner_from_native
from .credential_auth import require_alpha_writes
from .credential_ledger import LedgerConflict,LedgerRateLimited,get_credential_ledger
from .enrollment_permit_signing import sign_permit_with_key_vault
from .enrollment_permit_remote import sign_permit_with_remote


def _require_unspent(settings: Any, coin: Any) -> None:
    from . import zkpassport_enrollments as enroll
    row=enroll._fetch_coin_record_by_name(settings,'0x'+coin.name().hex())
    if (not isinstance(row,dict) or type(row.get('confirmed_block_index')) is not int
            or row['confirmed_block_index']<=0 or (row.get('spent') is not False and row.get('spent') is not None)
            or type(row.get('spent_block_index')) is not int or row['spent_block_index']!=0
            or not isinstance(row.get('coin'),dict) or type(row['coin'].get('amount')) is not int
            or row['coin']['amount']!=1):
        raise HTTPException(status_code=409,detail='Permit issuance requires a confirmed unspent one-mojo input.')
    try:actual=enroll._coin_from_record(row,'permitInput')
    except (TypeError,ValueError):raise HTTPException(status_code=409,detail='Permit input record is invalid.') from None
    if actual!=coin:
        raise HTTPException(status_code=409,detail='Permit input does not match its canonical coin record.')


def _fresh_vault(settings: Any, session: Any) -> Any:
    from . import zkpassport_enrollments as enroll
    coin=enroll._find_initial_vault_coin(settings,session.vault_launcher_id)
    expected=enroll._expected_stamped_vault_puzzle_hash(settings,
        vault_launcher_id=session.vault_launcher_id,identity_attest_root=enroll._EMPTY_ATTEST_ROOT)
    if '0x'+coin.puzzle_hash.hex()!=expected or session.vault_record.full_puzhash!=coin.puzzle_hash:
        raise HTTPException(status_code=409,detail='This vault was not created with the selected permit policy and owner.')
    _require_unspent(settings,coin)
    enroll._initial_vault_lineage(settings,coin,bytes32.from_hexstr(session.vault_launcher_id))
    return coin


async def reserve_and_issue_permit(settings: Any, session: Any, artifact: dict[str,Any], policy: Any,
        *, signer: Callable[...,str] | None = None) -> dict[str,Any]:
    from . import zkpassport_enrollments as enroll
    require_alpha_writes(settings)
    if getattr(session,'scope','vault')!='vault':
        raise HTTPException(status_code=403,detail='Permit issuance requires full vault-owner authentication.')
    activation=activation_from_artifact(artifact,required=True,environment=settings.runtime_environment+'-alpha')
    if (settings.network!='testnet11' or settings.zkpassport_evm_chain_id!=activation['evmChainId']
            or settings.enrollment_permit_release_identity!=activation['releaseIdentity']
            or settings.enrollment_permit_issuer_key_ref!=activation['issuerKeyRef']
            or settings.enrollment_permit_identity_client_id!=activation['issuerIdentityClientId']):
        raise HTTPException(status_code=503,detail='Permit issuer metadata does not match this release.')
    vault=session.vault_launcher_id;ledger=get_credential_ledger(settings)
    # Native EVM pubkeys are compressed curve points; the permit hashes the
    # authenticated 20-byte address. BLS binds its authenticated 48-byte key.
    try:
        auth_type,owner_hash=permit_owner_from_native(session.vault_record.auth_type,
            bytes.fromhex(session.owner_key.removeprefix('0x')))
    except ValueError as exc:raise HTTPException(status_code=409,detail=str(exc)) from exc
    binding=dict(artifactHash=artifact['artifactHash'],activation=activation,owner=session.owner_key.lower())
    existing=ledger.get_enrollment(vault)
    if existing:
        saved=ledger.get_enrollment_permit(vault)
        if saved is None or json.loads(saved['context_json'])!=binding:
            raise HTTPException(status_code=409,detail='The existing enrollment belongs to its original release. It cannot be upgraded or renewed.')
        if existing['status']!='reserved':return existing
        wire=json.loads(saved['permit_json']);permit=EnrollmentPermit.from_wire(wire)
        if permit.owner_auth_type!=auth_type or permit.owner_key_hash!=owner_hash:
            raise HTTPException(status_code=403,detail='The saved permit belongs to another owner.')
        if saved['issuer_signature']:return existing
        coin=_fresh_vault(settings,session)
        if coin.name()!=permit.current_vault_coin_id:
            raise HTTPException(status_code=409,detail='The saved permit binds another vault input.')
    else:
        coin=_fresh_vault(settings,session)
        candidates=enroll._bridge_coin_candidates(settings,bridge_policy_hash=policy.policy_hash,policy=policy)
        used=ledger.enrollment_bridge_coin_ids()
        for candidate in candidates:
            if candidate.coin_id in used:continue
            now=int(time.time())
            permit=EnrollmentPermit(permit_id=bytes32(secrets.token_bytes(32)),context_hash=activation_context(activation).context_hash,
                vault_launcher_id=bytes32.from_hexstr(vault),current_vault_coin_id=coin.name(),owner_auth_type=auth_type,
                owner_key_hash=owner_hash,bridge_coin_id=bytes32.from_hexstr(candidate.coin_id),issued_at=now,
                expires_at=now+activation['permitLifetimeSeconds'])
            wire=permit.to_wire()
            record=enroll.EnrollmentRecord(vaultLauncherId=vault,network=settings.network,policyVersion=2,status='reserved',
                bridgePolicyHash=policy.policy_hash,bridgeParentId=candidate.parent_id,bridgeAmount=1,
                bridgeCoinId=candidate.coin_id,createdAt=now,updatedAt=now).model_dump()
            try:
                existing,_=ledger.reserve_enrollment(record=record,owner_key=session.owner_key,
                    max_pending_per_owner=settings.zkpassport_enrollment_max_pending_per_owner,
                    permit_context=binding,permit_wire=wire)
                saved=ledger.get_enrollment_permit(vault);wire=json.loads(saved['permit_json']);permit=EnrollmentPermit.from_wire(wire)
                break
            except LedgerRateLimited as exc:raise HTTPException(status_code=429,detail=str(exc)) from exc
            except LedgerConflict:
                if ledger.get_enrollment(vault):
                    raise HTTPException(status_code=409,detail='An enrollment was reserved concurrently. Check its saved status.') from None
        else:
            raise HTTPException(status_code=409 if candidates else 503,detail='No unreserved confirmed permit bridge input is available.')
    # Recheck both exact inputs before any external signing request.
    try:permit.require_live(int(time.time()))
    except ValueError:raise HTTPException(status_code=409,detail='The saved enrollment permit expired; it cannot be renewed.') from None
    from chia_rs import Coin
    from chia_rs.sized_ints import uint64
    bridge=Coin(bytes32.from_hexstr(existing['bridgeParentId']),bytes32.from_hexstr(existing['bridgePolicyHash']),uint64(1))
    policy.require_coin(policy_hash=existing['bridgePolicyHash'],parent_id=existing['bridgeParentId'],amount=1,coin_id=existing['bridgeCoinId'])
    _require_unspent(settings,bridge)
    try:attempt=ledger.begin_permit_issuance(vault,binding)
    except LedgerRateLimited as exc:raise HTTPException(status_code=429,detail=str(exc)) from exc
    except (LedgerConflict,ValueError) as exc:raise HTTPException(status_code=409,detail=str(exc)) from exc
    if attempt is None:return ledger.get_enrollment(vault)
    try:
        if signer is not None:
            signature = await asyncio.to_thread(signer, settings, activation, wire)
        elif settings.enrollment_permit_signer_mode == 'remote':
            signature = await asyncio.to_thread(sign_permit_with_remote, settings, activation, wire,
                artifact_hash=artifact['artifactHash'])
        elif settings.enrollment_permit_signer_mode == 'key_vault':
            signature = await asyncio.to_thread(sign_permit_with_key_vault, settings, activation, wire)
        else:
            raise ValueError('Unsupported permit signer mode.')
    except Exception:
        ledger.finish_permit_issuance(vault,binding,attempt,failure='unavailable')
        raise HTTPException(status_code=503,detail='Permit signing is interrupted. The original reservation and deadline are preserved; retry its status.') from None
    try:result=ledger.finish_permit_issuance(vault,binding,attempt,signature=signature)
    except ValueError:
        ledger.finish_permit_issuance(vault,binding,attempt,failure='invalid')
        raise HTTPException(status_code=503,detail='The issuer response did not match the saved permit.') from None
    # A delayed response is still retained, but never renews authorization.
    try:permit.require_live(int(time.time()))
    except ValueError:raise HTTPException(status_code=409,detail='The issuer response arrived after the saved permit expired. Its evidence is retained.') from None
    return result
