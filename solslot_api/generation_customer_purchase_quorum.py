"""Current native purchase quorum transport; retain valid partial work.

No transaction preparation, fee selection or broadcast. Private signatures are
checked against independently reconstructed native conditions, never a message
supplied in an HTTP response. A retry may supply already retained responses;
all are reverified before reuse.
"""
import asyncio
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL,G1Element,G2Element
from .generation_customer_purchase_reservation import CurrentReservationEvidence
from .generation_customer_purchase_delivery import CurrentDeliveryEvidence
from .generation_customer_purchase_validators import native_messages
from .validator_quorum import _private_validator_client,configured_validator_pubkeys,ValidatorSignatureResponse
from .faucet import AGG_SIG_ME_DATA


async def collect_current_purchase_quorum(settings,evidence,*,client=None,retained=None,on_signature=None):
    roster=configured_validator_pubkeys(settings)
    if isinstance(evidence,CurrentReservationEvidence):
        claim=evidence.claim;indices=claim.signer_indices
        messages=native_messages(claim,evidence.transition,evidence.item.original.terms,roster)
        route='/v1/generation/purchase/reservation/sign'
    elif isinstance(evidence,CurrentDeliveryEvidence):
        claim=evidence.claim;indices=claim.reservation.signer_indices
        terms=evidence.item.original.terms
        if tuple(roster)!=terms.validator_pubkeys:raise ValueError('CURRENT_QUORUM_MINTED_ROSTER_CHANGED')
        spend=evidence.purchase.deed_spend
        pairs=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if len(pairs)!=2 or {bytes(k)for k,_ in pairs}!={roster[i]for i in indices}:
            raise ValueError('CURRENT_QUORUM_DELIVERY_MESSAGES_CHANGED')
        messages={roster.index(bytes(k)):bytes(m)for k,m in pairs};route='/v1/generation/purchase/delivery/sign'
    else:raise ValueError('CURRENT_QUORUM_VERIFIED_EVIDENCE_REQUIRED')
    if retained is not None and (not isinstance(retained,dict)or any(type(i)is not int or i not in indices for i in retained)):
        raise ValueError('CURRENT_QUORUM_RETAINED_SIGNER_CHANGED')
    def checked(index,raw):
        reply=ValidatorSignatureResponse.model_validate(raw)
        signature=G2Element.from_bytes(bytes.fromhex(reply.signature.removeprefix('0x')))
        if (reply.claimHash!=claim.digest()or reply.signerIndex!=index or reply.validatorPubkey!='0x'+roster[index].hex()
                or not AugSchemeMPL.verify(G1Element.from_bytes(roster[index]),messages[index],signature)):
            raise ValueError('CURRENT_QUORUM_SIGNATURE_INVALID')
        return reply,signature
    kept={i:checked(i,value)[1]for i,value in (retained or {}).items()}
    owned=client is None;client=client or _private_validator_client(settings)
    async def collect(index):
        if index in kept:return kept[index]
        async with asyncio.timeout(50):
            r=await client.post(settings.zkpassport_validator_urls[index].rstrip('/')+route,
                json={'claim':claim.model_dump(mode='json',by_alias=True),'claimHash':claim.digest()},timeout=50)
            r.raise_for_status();reply,signature=checked(index,r.json())
            if on_signature is not None:on_signature(index,reply.model_dump(mode='json'))
            return signature
    tasks=[asyncio.create_task(collect(i))for i in indices]
    try:
        values=await asyncio.gather(*tasks)
        return AugSchemeMPL.aggregate(values)
    finally:
        # End every local request task on failure. A remote signer may have
        # saved work before disconnection; the same claim recovers it on retry.
        for task in tasks:
            if not task.done():task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        if owned:await client.aclose()
