"""Native multi-message checks around the existing private signer and ledger."""
from hashlib import sha256
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL,G1Element,G2Element
from .faucet import AGG_SIG_ME_DATA
from .validator_quorum import ValidatorSignatureResponse
from .generation_customer_purchase_batch import (CurrentReservationBatch,CurrentDeliveryBatch,
    verify_current_batch_reservation,verify_current_batch_delivery,artifacts,h)


def batch_messages(evidence,roster):
    from .generation_customer_purchase_validators import native_messages
    claim=evidence.claim
    reservation=claim.reservation if isinstance(claim,CurrentDeliveryBatch)else claim
    messages={i:[]for i in reservation.signer_indices}
    for index,child in enumerate(evidence.children):
        if tuple(child.item.original.terms.validator_pubkeys)!=tuple(roster):
            raise ValueError('CURRENT_QUORUM_MINTED_ROSTER_CHANGED')
        if isinstance(claim,CurrentReservationBatch):
            current=native_messages(child.claim,child.transition,child.item.original.terms,roster)
        else:
            spend=evidence.purchase.deed_spends[index]
            pairs=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])
            if len(pairs)!=2 or {bytes(k)for k,_ in pairs}!={roster[i]for i in reservation.signer_indices}:
                raise ValueError('CURRENT_QUORUM_DELIVERY_MESSAGES_CHANGED')
            current={roster.index(bytes(k)):bytes(m)for k,m in pairs}
        for i,message in current.items():messages[i].append(message)
    return messages


async def sign_batch_reservation(claim,claim_hash,**arguments):
    settings=arguments['settings'];policy=arguments['issuer_policy']
    if (not settings.generation_customer_purchase_enabled or claim.digest()!=claim_hash
            or settings.signer_index not in claim.signer_indices or policy.maximum_purchases!=len(policy.deed_launchers)):
        raise ValueError('CURRENT_RESERVATION_SIGNER_NOT_ENABLED')
    native={k:v for k,v in arguments.items()if k not in ('ledger','load_key')}
    evidence=await verify_current_batch_reservation(claim,**native)
    from .generation_customer_purchase_validators import sign_verified_current_reservation
    from .generation_customer_purchase_batch import fresh_children
    signatures=[]
    for child in evidence.children:
        reply=await sign_verified_current_reservation(child,**{k:arguments[k]for k in
            ('settings','provider','ledger','issuer_policy','clock','load_key')})
        signatures.append(G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
    await fresh_children(evidence.children,arguments['provider'])
    if int(arguments['clock']())>=min(artifacts(claim)[0].quote_expires_at,policy.expires_at):
        raise ValueError('CURRENT_RESERVATION_REVIEW_EXPIRED')
    roster=tuple(bytes.fromhex(k.removeprefix('0x'))for k in settings.roster_pubkeys)
    signature=AugSchemeMPL.aggregate(signatures);messages=batch_messages(evidence,roster)[settings.signer_index]
    if not AugSchemeMPL.aggregate_verify([G1Element.from_bytes(roster[settings.signer_index])]*len(messages),messages,signature):
        raise ValueError('CURRENT_QUORUM_SIGNATURE_INVALID')
    return ValidatorSignatureResponse(claimHash=claim_hash,signerIndex=settings.signer_index,
        validatorPubkey=h(roster[settings.signer_index]),signature=h(signature))


async def sign_batch_delivery(claim,claim_hash,**arguments):
    settings=arguments['settings'];policy=arguments['issuer_policy'];ledger=arguments['ledger']
    if (not settings.generation_customer_purchase_enabled or claim.digest()!=claim_hash
            or settings.signer_index not in claim.reservation.signer_indices or policy.maximum_purchases!=len(policy.deed_launchers)):
        raise ValueError('CURRENT_DELIVERY_SIGNER_NOT_ENABLED')
    native={k:v for k,v in arguments.items()if k not in ('ledger','load_key')}
    evidence=await verify_current_batch_delivery(claim,**native)
    roster=tuple(bytes.fromhex(k.removeprefix('0x'))for k in settings.roster_pubkeys)
    index=settings.signer_index;messages=batch_messages(evidence,roster)[index]
    hashes=['0x'+sha256(bytes.fromhex(claim_hash[2:])+bytes.fromhex(coin[2:])).hexdigest()for coin in claim.reserved_coin_ids]
    signatures=[];private=None
    for digest,message in zip(hashes,messages,strict=True):
        old=ledger.primary_purchase_authorization(digest)
        if old is not None:
            if old['canonical_claim']!=claim.canonical():raise ValueError('CURRENT_DELIVERY_SAVED_CLAIM_CHANGED')
            signature=G2Element.from_bytes(bytes.fromhex(old['signature'][2:]))
        else:
            if private is None:
                if int(arguments['clock']())>=min(evidence.batch.artifacts[0].quote_expires_at,policy.expires_at):
                    raise ValueError('CURRENT_DELIVERY_REVIEW_EXPIRED')
                if arguments.get('load_key')is None:
                    from .validator_service import load_validator_private_key
                    private=load_validator_private_key(settings)
                else:private=arguments['load_key']()
                if bytes(private.get_g1())!=roster[index]:raise ValueError('CURRENT_DELIVERY_PRIVATE_ROSTER_CHANGED')
            signature=AugSchemeMPL.sign(private,message)
        if not AugSchemeMPL.verify(G1Element.from_bytes(roster[index]),message,signature):
            raise ValueError('CURRENT_DELIVERY_SAVED_SIGNATURE_CHANGED')
        signatures.append(h(signature))
    # The existing batch ledger commits all child replay protections together.
    retained=ledger.record_primary_purchase_batch_or_recover(claim_hashes=hashes,
        canonical_claims=[claim.canonical()]*len(hashes),purchase_ids=[h(a.purchase_id)for a in evidence.batch.artifacts],
        deed_coin_ids=claim.reserved_coin_ids,signatures=signatures)
    signature=AugSchemeMPL.aggregate([G2Element.from_bytes(bytes.fromhex(s[2:]))for s in retained])
    if not AugSchemeMPL.aggregate_verify([G1Element.from_bytes(roster[index])]*len(messages),messages,signature):
        raise ValueError('CURRENT_DELIVERY_SAVED_SIGNATURE_CHANGED')
    return ValidatorSignatureResponse(claimHash=claim_hash,signerIndex=index,validatorPubkey=h(roster[index]),signature=h(signature))
