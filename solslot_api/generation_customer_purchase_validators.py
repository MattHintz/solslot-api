"""R1 private native reservation signing; no HTTP route or live authority.

Reuses current-generation ancestry/ID/price reconstruction and the existing
append-only reservation ledger. A request cannot supply messages, retirement
proofs, keys, fee estimates or a legacy deployment artifact.
"""
from hashlib import sha256
import json,time
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs import AugSchemeMPL,G1Element,G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json,purchase_artifact_v3_to_json
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1,build_inventory_reservation_spend
from .generation_customer_purchase_reservation import CurrentReservationClaim,verify_current_reservation
from .generation_sols_batch_execution import unspent
from .validator_quorum import ValidatorSignatureResponse
from .faucet import AGG_SIG_ME_DATA
from .chia_snapshot import PrimaryReadSnapshot


def native_messages(claim,transition,terms,roster):
    if (tuple(terms.validator_pubkeys)!=tuple(roster) or len(roster)!=3 or len(set(roster))!=3
            or terms.inventory_version!=4 or terms.network!='testnet11'
            or transition.spend.coin.name()!=bytes32.from_hexstr(claim.available_coin_id)):
        raise ValueError('CURRENT_RESERVATION_MINTED_ROSTER_CHANGED')
    reveal=Program.from_bytes(bytes(transition.spend.puzzle_reveal))
    if reveal.get_tree_hash()!=transition.spend.coin.puzzle_hash:raise ValueError('CURRENT_RESERVATION_PUZZLE_CHANGED')
    conditions=conditions_dict_for_solution(reveal,Program.from_bytes(bytes(transition.spend.solution)),100_000_000)
    deadlines=conditions.get(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE,[])
    if len(deadlines)!=1 or Program.to(deadlines[0].vars[0]).as_int()!=transition.reservation.expires_at:
        raise ValueError('CURRENT_RESERVATION_NATIVE_EXPIRY_CHANGED')
    pairs=pkm_pairs_for_conditions_dict(conditions,transition.spend.coin,AGG_SIG_ME_DATA['testnet11'])
    selected={roster[i]for i in claim.signer_indices}
    if len(pairs)!=2 or {bytes(pk)for pk,_ in pairs}!=selected:
        raise ValueError('CURRENT_RESERVATION_NATIVE_QUORUM_CHANGED')
    return {roster.index(bytes(pk)):bytes(message)for pk,message in pairs}


async def prove_primary_expired_source(provider,coin,expires_at):
    """Clock and unspent source on one unchanged primary peak, no fallback.

    This is a trusted primary-node observation, not an SPV proof. No mempool
    or fee API is required: the old native ASSERT_BEFORE deadline itself makes
    the earlier authorization invalid on the observed later transaction block.
    """
    if type(expires_at)is not int or expires_at<=0:raise ValueError('CURRENT_RESERVATION_EXPIRY_INVALID')
    async with PrimaryReadSnapshot(provider,'testnet11')as snapshot:
        if snapshot.transaction_time<expires_at:raise ValueError('CURRENT_RESERVATION_NOT_EXPIRED_ON_CHAIN')
        record=await unspent(provider,coin)
        if record.confirmed_height>snapshot.peak['height']:raise ValueError('CURRENT_RESERVATION_SOURCE_AHEAD_OF_PEAK')
        if await snapshot._peak()!=snapshot.peak:raise ValueError('CURRENT_RESERVATION_PRIMARY_PEAK_CHANGED')
        return {'schema':'solslot.current-reservation-primary-expiry.v1','network':'testnet11',
            'authority':'CONFIGURED_PRIMARY_FULL_NODE','consensusInclusionProven':False,
            'peak':dict(snapshot.peak),'transactionTimestamp':snapshot.transaction_time,
            'sourceCoinId':'0x'+coin.name().hex(),'confirmedHeight':record.confirmed_height,
            'spentHeight':0,'expiresAt':expires_at}


def previous_transition(previous,current,*,issuer_policy,roster,signer_index,prior_policy=None,now=None):
    old=CurrentReservationClaim.model_validate_json(previous['canonical_claim'])
    purchase=purchase_artifact_v3_from_json(old.purchase_artifact)
    history_policy=issuer_policy
    if old.issuer_policy_hash!=issuer_policy.commitment and prior_policy is not None:
        from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
        if isinstance(issuer_policy,TestnetCollectionIssuerPolicy):
            # Recheck the predecessor scope even after pinned selection.
            from .generation_customer_issuer import TestnetIssuerPolicy
            fields=('generation','collection','edition','metadata_root','proceeds_puzzle','fee_puzzle',
                'issuer_public_key','maximum_gross_mojos','test_usd_minor_per_txch')
            if (not isinstance(prior_policy,TestnetIssuerPolicy)
                    or any(getattr(prior_policy,k)!=getattr(issuer_policy,k) for k in fields)
                    or not prior_policy.deed_launchers.issubset(issuer_policy.deed_launchers)):
                raise ValueError('CURRENT_RESERVATION_PRIOR_POLICY_SCOPE_CHANGED')
            history_policy=prior_policy
        else:
            from .generation_customer_purchase_policy import validate_purchase_policy_renewal
            if type(now)is not int:raise ValueError('CURRENT_PURCHASE_RENEWAL_SCOPE_CHANGED')
            history_policy=validate_purchase_policy_renewal(prior_policy,issuer_policy,now=now)
    if (old.canonical()!=previous['canonical_claim'] or old.digest()!=previous['claim_hash']
            or old.available_coin_id!=previous['available_coin_id']
            or '0x'+purchase.purchase_id.hex()!=previous['purchase_id']
            or old.generation_id!=current.claim.generation_id or old.anchor_hash!=current.claim.anchor_hash
            or old.issuer_policy_hash!=history_policy.commitment
            or old.available_coin_id!=current.claim.available_coin_id
            or signer_index not in old.signer_indices
            or purchase_artifact_v3_to_json(purchase)!=old.purchase_artifact):
        raise ValueError('CURRENT_RESERVATION_RETAINED_HISTORY_CHANGED')
    terms=current.item.original.terms
    history_policy.require_terms(terms,now=getattr(history_policy,'issued_at',now))
    if hasattr(history_policy,'buyer_vault') and purchase.vault_launcher_id!=history_policy.buyer_vault:raise ValueError('CURRENT_RESERVATION_PRIOR_RECEIVER_CHANGED')
    struct=Program.to((SINGLETON_MOD_HASH,(terms.deed_launcher_id,terms.deed_launcher_puzzle_hash)))
    transition=build_inventory_reservation_spend(available_coin=current.item.current.coin,
        deed_singleton_struct=struct,lineage_proof=current.item.lineage,
        reservation=InventoryReservationV1(purchase,purchase.quote_expires_at),
        signer_indices=old.signer_indices,terms=terms)
    message=native_messages(old,transition,terms,roster)[signer_index]
    signature=G2Element.from_bytes(bytes.fromhex(previous['signature'].removeprefix('0x')))
    if not AugSchemeMPL.verify(G1Element.from_bytes(roster[signer_index]),message,signature):
        raise ValueError('CURRENT_RESERVATION_RETAINED_SIGNATURE_CHANGED')
    return old,transition


async def sign_current_reservation(claim,claim_hash,*,settings,anchor,provider,ledger,
        issuer_policy,expected_issuer_policy_hash,clock=time.time,load_key=None):
    from .generation_customer_purchase_batch import CurrentReservationBatch
    from .generation_customer_purchase_batch_signing import sign_batch_reservation
    if isinstance(claim,CurrentReservationBatch):
        return await sign_batch_reservation(claim,claim_hash,settings=settings,anchor=anchor,provider=provider,ledger=ledger,
            issuer_policy=issuer_policy,expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock,load_key=load_key)
    if (getattr(settings,'generation_customer_purchase_enabled',False)is not True
            or not isinstance(claim,CurrentReservationClaim)or claim.digest()!=claim_hash
            or settings.signer_index not in claim.signer_indices
            or (hasattr(issuer_policy,'maximum_purchases') and issuer_policy.maximum_purchases!=len(issuer_policy.deed_launchers))):
        raise ValueError('CURRENT_RESERVATION_SIGNER_NOT_ENABLED')
    evidence=await verify_current_reservation(claim,settings=settings,anchor=anchor,provider=provider,
        issuer_policy=issuer_policy,expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock)
    return await sign_verified_current_reservation(evidence,settings=settings,provider=provider,ledger=ledger,
        issuer_policy=issuer_policy,clock=clock,load_key=load_key)


async def sign_verified_current_reservation(evidence,*,settings,provider,ledger,issuer_policy,clock,load_key):
    """Internal batch reuse of an independently reconstructed child snapshot."""
    from .generation_customer_purchase_reservation import CurrentReservationEvidence
    if not isinstance(evidence,CurrentReservationEvidence):raise ValueError('CURRENT_RESERVATION_NATIVE_EVIDENCE_REQUIRED')
    claim=evidence.claim;claim_hash=claim.digest()
    if (claim.issuer_policy_hash!=issuer_policy.commitment or settings.signer_index not in claim.signer_indices
            or claim.generation_id!=settings.deployment_generation_id or not settings.generation_customer_purchase_enabled):
        raise ValueError('CURRENT_RESERVATION_SIGNER_NOT_ENABLED')
    roster=tuple(bytes.fromhex(k.removeprefix('0x'))for k in settings.roster_pubkeys)
    messages=native_messages(claim,evidence.transition,evidence.item.original.terms,roster)
    index=settings.signer_index;retirement=None
    previous=ledger.active_inventory_authorization(claim.available_coin_id)
    if previous is not None and previous['claim_hash']!=claim_hash:
        from .generation_customer_purchase_policy import selected_prior_purchase_policy
        prior=selected_prior_purchase_policy(settings,issuer_policy,now=int(clock()))
        old,transition=previous_transition(previous,evidence,issuer_policy=issuer_policy,roster=roster,signer_index=index,
            prior_policy=prior,now=int(clock()))
        proof=await prove_primary_expired_source(provider,transition.spend.coin,transition.reservation.expires_at)
        retirement={'schema':'solslot.validator-inventory-retirement.v1','claimHash':old.digest(),
            'replacementClaimHash':claim_hash,'sourceCoinId':claim.available_coin_id,
            'generationId':claim.generation_id,'issuerPolicyHash':issuer_policy.commitment,
            'priorIssuerPolicyHash':old.issuer_policy_hash,'chainProof':proof}
    if previous is not None and previous['claim_hash']==claim_hash:
        if previous['canonical_claim']!=claim.canonical():raise ValueError('CURRENT_RESERVATION_SAVED_CLAIM_CHANGED')
        signature=G2Element.from_bytes(bytes.fromhex(previous['signature'].removeprefix('0x')))
        if not AugSchemeMPL.verify(G1Element.from_bytes(roster[index]),messages[index],signature):
            raise ValueError('CURRENT_RESERVATION_SAVED_SIGNATURE_CHANGED')
        encoded=previous['signature']
    else:
        # Recheck mutable custody and all immutable authority after any clock
        # proof, immediately before loading a credential. No request chooses it.
        from .generation_chain_evidence import current_evidence_unchanged
        if not await current_evidence_unchanged(evidence.inventory.evidence,provider=provider):
            raise ValueError('CURRENT_RESERVATION_AUTHORITY_CHANGED_BEFORE_SIGNATURE')
        await unspent(provider,evidence.item.current.coin);await unspent(provider,evidence.vault.coin)
        now=int(clock())
        if now>=min(evidence.reservation.expires_at,getattr(issuer_policy,'expires_at',evidence.reservation.expires_at)):raise ValueError('CURRENT_RESERVATION_REVIEW_EXPIRED')
        if load_key is None:
            from .validator_service import load_validator_private_key
            private=load_validator_private_key(settings)
        else:private=load_key()
        if bytes(private.get_g1())!=roster[index]:raise ValueError('CURRENT_RESERVATION_PRIVATE_ROSTER_CHANGED')
        encoded='0x'+bytes(AugSchemeMPL.sign(private,messages[index])).hex()
    encoded=ledger.record_inventory_reservation_or_recover(claim_hash=claim_hash,canonical_claim=claim.canonical(),
        purchase_id='0x'+evidence.reservation.artifact.purchase_id.hex(),available_coin_id=claim.available_coin_id,
        deed_launcher_id='0x'+evidence.reservation.artifact.deed_launcher_id.hex(),signature=encoded,
        retire_claim_hash=previous['claim_hash']if retirement is not None else None,retirement_evidence=retirement)
    return ValidatorSignatureResponse(claimHash=claim_hash,signerIndex=index,
        validatorPubkey='0x'+roster[index].hex(),signature=encoded)
