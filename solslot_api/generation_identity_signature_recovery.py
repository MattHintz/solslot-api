"""Signature-only primitive for exact current-generation ID recovery.

This is not a route, signer, journal update, native-evidence check or
submission. Callers must independently verify current custody, Base event,
owner authorization, all native conditions and fee authority. It is disabled
only through a separately gated, independently revalidated recovery route.
"""
from dataclasses import dataclass
from chia_rs import AugSchemeMPL,G1Element,G2Element
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from .validator_quorum import CurrentIdentityClaim,ValidatorSignatureResponse


@dataclass(frozen=True)
class RecoveredSignatureEvidence:
    original_claim_hash:str
    refreshed_claim_hash:str
    signer_indices:tuple[int,...]
    aggregated_signature:G2Element


def require_matching_recovery_subject(*,original,refreshed,now):
    """Compare all claim fields except the new spend clock, with no I/O."""
    if (not isinstance(original,CurrentIdentityClaim) or not isinstance(refreshed,CurrentIdentityClaim)
            or original.network!='testnet11' or original.owner_auth_type!=3
            or type(now)is not int or not 0<=now-refreshed.current_timestamp<=60
            or refreshed.current_timestamp<=original.current_timestamp):
        raise ValueError('IDENTITY_RECOVERY_CLOCK_OR_SCOPE_INVALID')
    old=original.model_dump(mode='json');new=refreshed.model_dump(mode='json')
    old.pop('current_timestamp');new.pop('current_timestamp')
    if old!=new or original.signature_message()!=refreshed.signature_message():
        raise ValueError('IDENTITY_RECOVERY_SUBJECT_CHANGED')


def verify_recovered_signatures_only(*,original,refreshed,responses,validator_pubkeys,now):
    """Verify retained 2-of-3 signatures; chain/owner checks remain mandatory."""
    require_matching_recovery_subject(original=original,refreshed=refreshed,now=now)
    if (not isinstance(validator_pubkeys,(tuple,list)) or len(validator_pubkeys)!=3
            or any(not isinstance(key,bytes) or len(key)!=48 for key in validator_pubkeys)
            or len(set(validator_pubkeys))!=3 or not isinstance(responses,(tuple,list))
            or not 2<=len(responses)<=3):
        raise ValueError('IDENTITY_RECOVERY_ROSTER_INVALID')
    if '0x'+make_bridge_policy_hash(validator_pubkeys,2).hex()!=original.bridge_policy_hash:
        raise ValueError('IDENTITY_RECOVERY_ROSTER_CHANGED')
    original_hash=original.canonical_hash();selected={}
    for value in responses:
        try:
            if not isinstance(value,dict) or type(value.get('signerIndex'))is not int:
                raise ValueError('IDENTITY_RECOVERY_RESPONSE_CHANGED')
            response=ValidatorSignatureResponse.model_validate(value)
            slot=response.signerIndex
            if (slot not in (0,1,2) or slot in selected or response.claimHash!=original_hash
                    or bytes.fromhex(response.validatorPubkey.removeprefix('0x'))!=validator_pubkeys[slot]):
                raise ValueError('IDENTITY_RECOVERY_RESPONSE_CHANGED')
            signature=G2Element.from_bytes(bytes.fromhex(response.signature.removeprefix('0x')))
            public=G1Element.from_bytes(validator_pubkeys[slot])
            if not AugSchemeMPL.verify(public,original.signature_message(),signature):
                raise ValueError('IDENTITY_RECOVERY_SIGNATURE_INVALID')
            selected[slot]=signature
        except (ValueError,TypeError) as exc:
            raise ValueError('IDENTITY_RECOVERY_RESPONSE_INVALID') from exc
    indices=tuple(sorted(selected)[:2])
    return RecoveredSignatureEvidence(original_hash,refreshed.canonical_hash(),indices,
        AugSchemeMPL.aggregate([selected[index] for index in indices]))
