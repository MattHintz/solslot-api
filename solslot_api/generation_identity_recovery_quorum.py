"""Testnet-only retrieval of independently revalidated saved signatures."""
import asyncio
import time
from chia_rs import AugSchemeMPL,G1Element,G2Element
from .generation_identity_signature_recovery import require_matching_recovery_subject,verify_recovered_signatures_only
from .validator_quorum import (_private_validator_client,configured_validator_pubkeys,
    ValidatorQuorumError,ValidatorSignatureResponse)


async def collect_retained_identity_quorum(settings,original,refreshed,*,client=None,clock=time.time):
    """Only an explicitly enabled caller may use this; never signs or submits."""
    require_matching_recovery_subject(original=original,refreshed=refreshed,now=int(clock()))
    pubkeys=configured_validator_pubkeys(settings)
    owned=client is None
    if owned:client=_private_validator_client(settings)
    async def get(index,url):
        try:
            response=await client.post(url.rstrip('/')+'/v1/generation/identity/recover',timeout=55,
                json={'originalClaimHash':original.canonical_hash(),'claimHash':refreshed.canonical_hash(),
                      'claim':refreshed.model_dump(mode='json')})
            response.raise_for_status();value=ValidatorSignatureResponse.model_validate(response.json())
            if (value.signerIndex!=index or value.claimHash!=original.canonical_hash()
                    or bytes.fromhex(value.validatorPubkey.removeprefix('0x'))!=pubkeys[index]):return None
            signature=G2Element.from_bytes(bytes.fromhex(value.signature.removeprefix('0x')))
            if not AugSchemeMPL.verify(G1Element.from_bytes(pubkeys[index]),original.signature_message(),signature):return None
            return value.model_dump()
        except Exception:return None
    try:
        results=await asyncio.gather(*(get(i,url) for i,url in enumerate(settings.zkpassport_validator_urls)))
    finally:
        if owned:await client.aclose()
    valid=[row for row in results if row is not None]
    if len(valid)<2:raise ValidatorQuorumError('retained identity quorum unavailable')
    return verify_recovered_signatures_only(original=original,refreshed=refreshed,responses=valid,
        validator_pubkeys=pubkeys,now=int(clock()))
