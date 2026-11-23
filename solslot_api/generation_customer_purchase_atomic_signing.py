"""Independent Testnet verification for a buyer-approved, single-bundle checkout."""
from dataclasses import dataclass
from hashlib import sha256
import time
from typing import Literal

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.wallet.trading.offer import Offer
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from pydantic import Field, StrictInt

from .faucet import AGG_SIG_ME_DATA
from .generation_coin_evidence import read_confirmed_coin
from .generation_execution import Hash, Model
from .generation_operations import canonical
from .generation_customer_purchase_atomic import assemble_purchase, purchase_inputs
from .generation_customer_collection_policy import approved_forwarding_asset
from .generation_customer_purchase_batch import CurrentReservationBatch, artifacts, fresh_children, h, verify_current_batch_reservation
from .generation_customer_purchase_reservation import CurrentReservationClaim, verify_current_reservation
from .generation_customer_purchase_validators import native_messages, sign_verified_current_reservation
from .generation_sols_batch_execution import unspent
from .validator_quorum import ValidatorSignatureResponse
from .wallet_offer_validation import decode_offer, validate_standard_payment_spend


class AtomicBuyerApproval(Model):
    schema_version: Literal['solslot.buyer-paid-settlement.v1'] = Field(alias='schema', default='solslot.buyer-paid-settlement.v1')
    reservation: CurrentReservationClaim | CurrentReservationBatch
    payment_coin_id: Hash = Field(alias='paymentCoinId')
    payment_public_key: str = Field(alias='paymentPublicKey', pattern=r'^0x[0-9a-f]{96}$')
    payment_public_key_kind: Literal['raw','synthetic'] = Field(alias='paymentPublicKeyKind')
    fee_coin_id: Hash | None = Field(default=None, alias='feeCoinId')
    fee_public_key: str | None = Field(default=None, alias='feePublicKey', pattern=r'^0x[0-9a-f]{96}$')
    network_fee_mojos: StrictInt = Field(alias='networkFeeMojos', ge=0, lt=2**64)
    buyer_offer: str = Field(alias='buyerOffer', min_length=16, max_length=2_000_000)

    def canonical(self):
        document = self.model_dump(mode='json', by_alias=True)
        for name in ('feeCoinId','feePublicKey'):
            if document[name] is None:
                del document[name]
        return canonical(document)

    def digest(self):
        return '0x'+sha256(self.canonical().encode()).hexdigest()


@dataclass(frozen=True)
class ApprovedSettlement:
    claim: AtomicBuyerApproval
    evidence: object
    purchase: object
    payer_coin: object
    fee_coin: object = None


async def cat_wallet_inputs(provider, payer_coin, payment_key, key_kind, asset, fee_coin_id, fee_public_key):
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk, puzzle_for_synthetic_public_key
    from solslot_puzzles.stripe_settlement_v1_driver import CatNetworkFeeInput
    from .cat_lineage import confirmed_cat_receipt_lineage
    if asset == bytes32.zeros:
        if fee_coin_id is not None or fee_public_key is not None:
            raise ValueError('A native payment uses its own fee input')
        return {}
    key = G1Element.from_bytes(payment_key)
    owner = puzzle_for_pk(key) if key_kind == 'raw' else puzzle_for_synthetic_public_key(key)
    lineage = await confirmed_cat_receipt_lineage(provider=provider, coin=payer_coin,
        expected_inner_hash=owner.get_tree_hash(), expected_tail_hash=asset, primary_only=True)
    if fee_coin_id is None and fee_public_key is None:
        return {'cat_lineage_proof': lineage}
    if not fee_coin_id or not fee_public_key:
        raise ValueError('CAT checkout requires the native fee coin and its key together')
    record = read_confirmed_coin(await provider.get_coin_record_by_name_primary(fee_coin_id), bytes32.from_hexstr(fee_coin_id))
    fee_key = G1Element.from_bytes(bytes.fromhex(fee_public_key[2:]))
    if key_kind == 'raw':
        from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import calculate_synthetic_public_key, DEFAULT_HIDDEN_PUZZLE_HASH
        fee_key = calculate_synthetic_public_key(fee_key, DEFAULT_HIDDEN_PUZZLE_HASH)
    if record.spent_height or record.coin.puzzle_hash != puzzle_for_synthetic_public_key(fee_key).get_tree_hash():
        raise ValueError('Native fee coin does not belong to the selected public key')
    return {'cat_lineage_proof': lineage, 'fee_input': CatNetworkFeeInput(record.coin, fee_key)}


async def verify_approval(claim, *, settings, anchor, provider, issuer_policy, expected_issuer_policy_hash, clock=time.time):
    if not isinstance(claim, AtomicBuyerApproval) or settings.network!='testnet11':
        raise ValueError('Testnet buyer approval required')
    inputs = artifacts(claim.reservation)
    args = dict(settings=settings, anchor=anchor, provider=provider, issuer_policy=issuer_policy,
                expected_issuer_policy_hash=expected_issuer_policy_hash, clock=clock)
    verifier = verify_current_batch_reservation if isinstance(claim.reservation,CurrentReservationBatch) else verify_current_reservation
    evidence = await verifier(claim.reservation, **args)
    asset = inputs[0].rail_asset_id
    separate_fee = asset != bytes32.zeros and claim.network_fee_mojos > 0
    if separate_fee != (claim.fee_coin_id is not None) or separate_fee != (claim.fee_public_key is not None):
        raise ValueError('Fee input differs from the selected asset and network fee')
    decoded = decode_offer(claim.buyer_offer, real_spends=2 if separate_fee else 1, dummy_spends=len(inputs),
        expected_assets=frozenset(a.deed_launcher_id for a in inputs), allow_signed=True)
    validate_standard_payment_spend(decoded.real_spends[0], asset_id=asset if asset != bytes32.zeros else None)
    if separate_fee:
        validate_standard_payment_spend(decoded.real_spends[1], asset_id=None)
    offer=Offer.from_spend_bundle(decoded.bundle)
    payer=read_confirmed_coin(await provider.get_coin_record_by_name_primary(claim.payment_coin_id), bytes32.from_hexstr(claim.payment_coin_id))
    if payer.spent_height:
        raise ValueError('Selected payer coin is no longer available')
    extra = await cat_wallet_inputs(provider,payer.coin,bytes.fromhex(claim.payment_public_key[2:]),
        claim.payment_public_key_kind,asset,claim.fee_coin_id,claim.fee_public_key)
    purchase=assemble_purchase(evidence, buyer_signature=offer.aggregated_signature(), payment_coin=payer.coin,
        payment_public_key=bytes.fromhex(claim.payment_public_key[2:]), payment_public_key_kind=claim.payment_public_key_kind,
        network_fee_mojos=claim.network_fee_mojos,**extra)
    if bytes(purchase.buyer_offer.to_spend_bundle())!=bytes(decoded.bundle):
        raise ValueError('Signed offer differs from the independently rebuilt purchase')
    await fresh_children(purchase_inputs(evidence)[0],provider)
    await unspent(provider,payer.coin)
    fee_coin = extra['fee_input'].coin if separate_fee else None
    if fee_coin:
        await unspent(provider, fee_coin)
    if int(clock()) >= min(a.quote_expires_at for a in inputs):
        raise ValueError('Buyer approval expired during verification')
    return ApprovedSettlement(claim,evidence,purchase,payer.coin,fee_coin)


def settlement_messages(verified, roster):
    children, terms, _ = purchase_inputs(verified.evidence)
    indices = verified.claim.reservation.signer_indices
    selected = {roster[i] for i in indices}
    by_coin = {s.coin.name():s for s in verified.purchase.delivery_bundle.coin_spends}
    messages = {i:[] for i in indices}
    for child, term in zip(children,terms,strict=True):
        if tuple(term.validator_pubkeys)!=roster:
            raise ValueError('Minted signer roster changed')
        parent = native_messages(child.claim,child.transition,term,roster)
        spend = by_coin[child.transition.reserved_coin.name()]
        pairs = pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),
                                             spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if len(pairs)!=2 or {bytes(k) for k,_ in pairs}!=selected:
            raise ValueError('Delivery requires the minted quorum')
        delivery = {roster.index(bytes(k)):bytes(message) for k,message in pairs}
        for index in indices:
            messages[index].append((parent[index], delivery[index]))
    return messages


async def sign_atomic_purchase(claim, claim_hash, *, settings, anchor, provider, ledger, issuer_policy,
                               expected_issuer_policy_hash, clock=time.time, load_key=None):
    if (not getattr(settings,'generation_customer_purchase_atomic_enabled',False)
            or not settings.generation_customer_purchase_enabled or claim.digest()!=claim_hash
            or settings.signer_index not in claim.reservation.signer_indices):
        raise ValueError('Buyer-paid settlement signing is disabled or mismatched')
    verified=await verify_approval(claim,settings=settings,anchor=anchor,provider=provider,issuer_policy=issuer_policy,
                                   expected_issuer_policy_hash=expected_issuer_policy_hash,clock=clock)
    index=settings.signer_index
    roster=tuple(bytes.fromhex(v.removeprefix('0x')) for v in settings.roster_pubkeys)
    pairs=settlement_messages(verified,roster)[index]
    children,_,_=purchase_inputs(verified.evidence)
    reservations=[]
    for child in children:
        reply=await sign_verified_current_reservation(child,settings=settings,provider=provider,ledger=ledger,
                                                     issuer_policy=issuer_policy,clock=clock,load_key=load_key)
        reservations.append(G2Element.from_bytes(bytes.fromhex(reply.signature[2:])))
    ids=[h(child.transition.reserved_coin.name()) for child in children]
    hashes=['0x'+sha256(bytes.fromhex(claim_hash[2:])+bytes.fromhex(cid[2:])).hexdigest() for cid in ids]
    private=None
    signatures=[]
    await fresh_children(children,provider)
    await unspent(provider,verified.payer_coin)
    if verified.fee_coin is not None:
        await unspent(provider, verified.fee_coin)
    for digest, (_,message) in zip(hashes,pairs,strict=True):
        old=ledger.primary_purchase_authorization(digest)
        if old is not None:
            if old['canonical_claim']!=claim.canonical():
                raise ValueError('Retained settlement approval differs')
            sig=G2Element.from_bytes(bytes.fromhex(old['signature'][2:]))
        else:
            if int(clock())>=min(artifacts(claim.reservation)[0].quote_expires_at,getattr(issuer_policy,'expires_at',2**64)):
                raise ValueError('Expired settlement approval')
            if private is None:
                from .validator_service import load_validator_private_key
                private=load_key() if load_key else load_validator_private_key(settings)
                if bytes(private.get_g1())!=roster[index]:
                    raise ValueError('Signer key differs from the minted roster')
            sig=AugSchemeMPL.sign(private,message)
        if not AugSchemeMPL.verify(G1Element.from_bytes(roster[index]),message,sig):
            raise ValueError('Invalid delivery signature')
        signatures.append(h(sig))
    purchases = [h(a.purchase_id) for a in artifacts(claim.reservation)]
    if len(children) == 1:
        retained = (ledger.record_primary_purchase_or_recover(claim_hash=hashes[0], canonical_claim=claim.canonical(),
                    purchase_id=purchases[0], deed_coin_id=ids[0], signature=signatures[0]),)
    else:
        retained = ledger.record_primary_purchase_batch_or_recover(claim_hashes=hashes, canonical_claims=[claim.canonical()]*len(children),
                    purchase_ids=purchases, deed_coin_ids=ids, signatures=signatures)
    combined=AugSchemeMPL.aggregate([*reservations,*(G2Element.from_bytes(bytes.fromhex(v[2:])) for v in retained)])
    messages=[message for pair in pairs for message in pair]
    if not AugSchemeMPL.aggregate_verify([G1Element.from_bytes(roster[index])]*len(messages),messages,combined):
        raise ValueError('Settlement quorum reply differs')
    return ValidatorSignatureResponse(claimHash=claim_hash,signerIndex=index,validatorPubkey=h(roster[index]),signature=h(combined))


async def sign_atomic_issuer(claim, claim_hash, quorum_signature, *, settings, anchor, provider, journal,
                             journal_lock, load_key, clock=time.time):
    """Independently rebuild the approved settlement and authorize its fixed proceeds outputs."""
    from solslot_puzzles.generation_revenue import CompanyRevenue, PrimaryFeeSplitter
    from solslot_puzzles.generation_statutes import GenerationStatutes
    from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
    from chia_rs import SpendBundle
    from .generation_customer_issuer import TestnetIssuerJournal
    if (not isinstance(journal,TestnetIssuerJournal) or not getattr(settings,'generation_customer_purchase_atomic_enabled',False)
            or not settings.generation_customer_purchase_issuer_enabled or settings.signer_index!=2
            or not isinstance(quorum_signature,G2Element) or claim.digest()!=claim_hash):
        raise ValueError('Testnet settlement issuer authority required')
    policy=journal.policy
    verified=await verify_approval(claim,settings=settings,anchor=anchor,provider=provider,issuer_policy=policy,
                                   expected_issuer_policy_hash=policy.commitment,clock=clock)
    roster=tuple(bytes.fromhex(v.removeprefix('0x')) for v in settings.roster_pubkeys)
    pairs=settlement_messages(verified,roster)
    messages=[(G1Element.from_bytes(roster[i]),m) for i,rows in pairs.items() for pair in rows for m in pair]
    if not AugSchemeMPL.aggregate_verify([p for p,_ in messages],[m for _,m in messages],quorum_signature):
        raise ValueError('Both inventory and delivery quorum approvals are required')
    purchase=verified.purchase
    base=purchase.bundle()
    approved=SpendBundle(base.coin_spends,AugSchemeMPL.aggregate([base.aggregated_signature,quorum_signature]))
    chain=verified.evidence.inventory.evidence
    statutes=[c.state for c in chain.economic_components.values() if isinstance(c.state,GenerationStatutes)]
    if len(statutes)!=1 or statutes[0].generation!=policy.generation:
        raise ValueError('Current fee statute required')
    fees=PrimaryFeeSplitter(chain.governance.state.sgt,statutes[0].launcher_id,
                            CompanyRevenue(policy.generation,chain.registry.state.administrator_id))
    children,terms,_=purchase_inputs(verified.evidence)
    items=artifacts(claim.reservation)
    companions=[build_testnet_primary_forwarding(bundle=approved,artifact=a,terms=t,
                issuer_public_key=policy.issuer_public_key,fees=fees,
                approved_cat_asset=approved_forwarding_asset(policy,a,t)) for a,t in zip(items,terms,strict=True)]
    permitted=set()
    for companion in companions:
        spend=companion.issuer_signature_spend
        messages=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),
                                               spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if len(messages)!=1 or bytes(messages[0][0])!=policy.issuer_public_key:
            raise ValueError('Fixed issuer output binding changed')
        permitted.add(bytes(messages[0][1]))
    await fresh_children(children,provider)
    await unspent(provider,verified.payer_coin)
    if verified.fee_coin is not None:
        await unspent(provider, verified.fee_coin)
    private=None
    def sign_proceeds(message):
        nonlocal private
        if message not in permitted or int(clock())>=min(items[0].quote_expires_at,getattr(policy,'expires_at',2**64)):
            raise ValueError('Issuer proceeds approval expired or changed')
        if private is None:
            private=load_key()
            if bytes(private.get_g1())!=policy.issuer_public_key:
                raise ValueError('Configured issuer key changed')
        return AugSchemeMPL.sign(private,message)
    with journal_lock:
        args = dict(bundle=approved, fees=fees, now=int(clock()), sign_message=sign_proceeds)
        if len(items) == 1:
            final = journal.authorize(artifact=items[0], terms=terms[0], **args)
        else:
            final = journal.authorize_batch(artifacts=items, terms=terms, **args)
    expected=purchase.bundle([s for companion in companions for s in companion.operation.spends])
    if final.coin_spends!=expected.coin_spends:
        raise ValueError('Issuer returned different settlement spends')
    return final
