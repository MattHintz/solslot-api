"""Narrow independent delivery authorization for the native primary batch."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
from chia_rs import AugSchemeMPL,G1Element,G2Element,SpendBundle
from .generation_sols_batch_execution import PrimaryBatchClaim,resolve_batch,delivery_messages
from .generation_index import load_generation_read_anchor
from .validator_quorum import _private_validator_client,configured_validator_pubkeys,ValidatorSignatureResponse
from .validator_service import load_validator_private_key


def generation_settings(settings):
    return SimpleNamespace(network=settings.network,deployment_generation_id=settings.deployment_generation_id,
        generation_preparation_path=settings.generation_preparation_path,generation_preparation_hash=settings.generation_preparation_hash,
        generation_chain_anchor_path=settings.generation_chain_anchor_path,generation_chain_anchor_hash=settings.generation_chain_anchor_hash)


async def sign_primary_batch(claim,*,settings,provider,ledger,clock):
    if not settings.generation_sols_batch_enabled or settings.signer_index not in claim.signer_indices:
        raise ValueError('BATCH_DELIVERY_SIGNER_NOT_ENABLED')
    bound=generation_settings(settings);anchor=load_generation_read_anchor(bound)
    result,_=await resolve_batch(claim,settings=bound,anchor=anchor,provider=provider,clock=clock)
    private=load_validator_private_key(settings);public=bytes(private.get_g1())
    if public!=bytes.fromhex(settings.roster_pubkeys[settings.signer_index].removeprefix('0x')):
        raise ValueError('BATCH_SIGNER_ROSTER_CHANGED')
    # Verify every minted source's immutable roster, not the coordinator's key.
    from chia.types.blockchain_format.program import Program
    for spend in result.primary_spends:
        inner=list(Program.from_bytes(bytes(spend.puzzle_reveal)).uncurry()[1].as_iter())[1]
        roster=tuple(v.as_atom() for v in list(inner.uncurry()[1].as_iter())[21].as_iter())
        if roster!=tuple(bytes.fromhex(k.removeprefix('0x')) for k in settings.roster_pubkeys):
            raise ValueError('BATCH_MINTED_DELIVERY_ROSTER_CHANGED')
    messages=delivery_messages(result)[settings.signer_index]
    if len(messages)!=len(result.primary_spends):raise ValueError('BATCH_DELIVERY_MESSAGES_INCOMPLETE')
    signature=AugSchemeMPL.aggregate([AugSchemeMPL.sign(private,message) for message in messages])
    encoded='0x'+bytes(signature).hex()
    # The ledger retains exact signed evidence. Conflicting still-live source
    # authorizations cannot overlap; expired signatures need fresh chain proof.
    from .protocol_admission import primary_admission_state
    _,_,_,chain_time=primary_admission_state(await provider.get_fee_estimate(target_times=[30],cost=1_000_000,require_primary=True))
    if chain_time>=claim.expires_at:raise ValueError('BATCH_PRICE_REVIEW_EXPIRED_ON_CHAIN')
    ledger.record_generation_batch(claim=claim,signature=encoded,now=chain_time)
    return ValidatorSignatureResponse(claimHash=claim.digest(),signerIndex=settings.signer_index,
        validatorPubkey='0x'+public.hex(),signature=encoded)


async def collect_primary_batch(settings,claim,settlement,*,client=None):
    pubkeys=configured_validator_pubkeys(settings);messages=delivery_messages(settlement)
    owned=client is None;client=client or _private_validator_client(settings)
    async def collect(index):
        async with asyncio.timeout(15):
            response=await client.post(settings.zkpassport_validator_urls[index].rstrip('/')+'/v1/generation/primary-sols/sign',
                json={'claim':claim.model_dump(mode='json',by_alias=True),'claimHash':claim.digest()})
            response.raise_for_status();value=ValidatorSignatureResponse.model_validate(response.json())
            signature=G2Element.from_bytes(bytes.fromhex(value.signature.removeprefix('0x')))
            if (value.claimHash!=claim.digest() or value.signerIndex!=index
                    or bytes.fromhex(value.validatorPubkey.removeprefix('0x'))!=pubkeys[index]
                    or not messages[index]
                    or not AugSchemeMPL.aggregate_verify([G1Element.from_bytes(pubkeys[index])]*len(messages[index]),messages[index],signature)):
                raise ValueError('BATCH_DELIVERY_SIGNATURE_INVALID')
            return signature
    try:signatures=await asyncio.gather(*(collect(index) for index in claim.signer_indices))
    finally:
        if owned:await client.aclose()
    signature=AugSchemeMPL.aggregate(signatures)
    return replace(settlement,bundle=SpendBundle(settlement.bundle.coin_spends,
        AugSchemeMPL.aggregate([settlement.bundle.aggregated_signature,signature])))
