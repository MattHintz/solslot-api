"""Reuse current order checkpoints with one canonical multi-deed review."""
import secrets
from types import SimpleNamespace
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL,SpendBundle,G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1,purchase_batch_to_json,purchase_artifact_v3_to_json,purchase_batch_from_json
from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
from .generation_customer_purchase_batch import CurrentReservationBatch,artifacts,verify_current_batch_reservation
from .generation_customer_purchase_reservation import CurrentReservationClaim
from .generation_customer_purchase_delivery import verify_current_delivery
from .generation_customer_purchase_quorum import collect_current_purchase_quorum
from .generation_customer_inventory import resolve_current_primary_inventory
from .generation_customer_context import customer_bindings_from_evidence
from .generation_customer_vault import resolve_native_identity_vault
from .generation_customer_quote import current_customer_xch_quote
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_customer_purchase_scope import quote_deadline
from .generation_customer_test_conversion import configured_price
from .generation_preparation import read_generation_preparation
from .generation_customer_purchase_timing import measured, start, record
from .faucet import AGG_SIG_ME_DATA


def h(v):return '0x'+bytes(v).hex()


async def quote_batch(s,request_key,deeds,browser_hash,receiving_launcher=None,receiving_owner=None):
    if (not isinstance(deeds,(list,tuple))or not 2<=len(deeds)<=25
            or len(set(deeds))!=len(deeds)):
        raise ValueError('CURRENT_PURCHASE_BATCH_QUANTITY_INVALID')
    ordered=tuple(sorted(bytes32.from_hexstr(d)for d in deeds))
    collection = isinstance(s.policy, TestnetCollectionIssuerPolicy)
    if collection and (not isinstance(receiving_launcher, bytes32) or receiving_launcher == bytes32.zeros
            or not isinstance(receiving_owner, str) or not receiving_owner):
        raise ValueError('CURRENT_EXECUTION_RECEIVING_VAULT_REQUIRED')
    prior=s.store.review_for_request(request_key,browser_hash=browser_hash)
    if prior is not None:
        claim=s._review_saved(prior['intentId'],browser_hash)['reservationClaim']
        if not isinstance(claim,CurrentReservationBatch) or tuple(a.deed_launcher_id for a in artifacts(claim))!=ordered:
            raise ValueError('CURRENT_EXECUTION_REQUEST_KEY_DEED_CHANGED')
        if isinstance(s.policy,TestnetCollectionIssuerPolicy) and any(a.vault_launcher_id!=receiving_launcher for a in artifacts(claim)):
            raise ValueError('CURRENT_EXECUTION_RECEIVING_VAULT_CHANGED')
        return s.review(prior['intentId'],browser_hash=browser_hash)
    now=int(s.clock());expires=now+300
    if isinstance(s.policy,TestnetIssuerPolicy):
        if not s.policy.issued_at<=now<expires<=s.policy.expires_at:
            raise ValueError('CURRENT_EXECUTION_PURCHASE_WINDOW_CLOSED')
        launcher=s.policy.buyer_vault
        if receiving_launcher is not None and receiving_launcher!=launcher:
            raise ValueError('CURRENT_EXECUTION_RECEIVING_VAULT_CHANGED')
    elif isinstance(s.policy,TestnetCollectionIssuerPolicy) and isinstance(receiving_launcher,bytes32) and receiving_launcher!=bytes32.zeros:
        launcher=receiving_launcher
        s._funding_context(until=expires)
    else:raise ValueError('CURRENT_EXECUTION_RECEIVING_VAULT_REQUIRED')
    if any(d not in s.policy.deed_launchers for d in ordered):
        raise ValueError('CURRENT_EXECUTION_DEED_OUTSIDE_REVIEWED_POLICY')
    if collection:
        inventory = await s.inventory_snapshot()
    else:
        inventory = await resolve_current_primary_inventory(settings=s.settings, anchor=s.anchor, provider=s.provider,
            collection=s.policy.collection, edition_hash=s.policy.edition, metadata_root=s.policy.metadata_root)
    bindings=customer_bindings_from_evidence(read_generation_preparation(s.settings),s.anchor,inventory.evidence)
    vault=await resolve_native_identity_vault(bindings=bindings,launcher=launcher,provider=s.provider)
    if isinstance(s.policy, TestnetCollectionIssuerPolicy):
        s.policy.require_verified_vault(vault, launcher=launcher, auth_type='chia_bls', owner_key=receiving_owner)
    price,evidence=configured_price(s.settings,s.policy,now=now,expires_at=expires)
    nonce=bytes32(secrets.token_bytes(32));children=[];purchases=[]
    for deed in ordered:
        purchase=current_customer_xch_quote(inventory=inventory,vault=vault,deed_launcher=deed,
            price=price,nonce=nonce,now=now,expires_at=expires,forwarding_policy=s.policy)
        purchases.append(purchase)
        children.append(CurrentReservationClaim(generationId=s.store.generation_id,
            anchorHash=s.settings.generation_chain_anchor_hash,issuerPolicyHash=s.policy.commitment,
            purchaseArtifact=purchase_artifact_v3_to_json(purchase),signedPrice=evidence,
            availableCoinId=h(inventory.require_available(deed).current.coin.name()),
            currentVaultCoinId=h(vault.coin.name()),signerIndices=(0,1)))
    batch=build_purchase_batch_v1(batch_nonce=bytes32(secrets.token_bytes(32)),artifacts=purchases)
    claim=CurrentReservationBatch(purchaseBatch=purchase_batch_to_json(batch),children=tuple(children))
    quote_started=start()
    await verify_current_batch_reservation(claim,**s._arguments())
    quote_finished=start()
    try:identity=s.store.save_review(claim,browser_hash=browser_hash,request_key=request_key,now=int(s.clock()))
    except ValueError as exc:
        if str(exc)!='CURRENT_CHECKOUT_RETRY_CHANGES_REVIEW':raise
        return await quote_batch(s,request_key,deeds,browser_hash,
            receiving_launcher=receiving_launcher,receiving_owner=receiving_owner)
    if quote_finished is not None:record(s,identity,'quote_verification',quote_started,quote_finished)
    return s.review(identity,browser_hash=browser_hash)


def review_batch(s,identity,saved,binding):
    claim=saved['reservationClaim'];batch=purchase_batch_from_json(claim.purchase_batch);first=batch.artifacts[0]
    existing=s._existing(identity,'RESERVATION',binding)
    fee_cap = s.review_fee_cap(identity, binding)
    return {'schema':'solslot.current-primary-checkout-batch.v1','intentId':identity,'generationId':s.store.generation_id,
        'network':'testnet11','receivingVaultLauncherId':h(first.vault_launcher_id),'rail':'CHIA_XCH',
        'purchaseBatch':claim.purchase_batch,'quantity':len(batch.artifacts),
        'deedLauncherIds':[h(a.deed_launcher_id)for a in batch.artifacts],
        'purchaseId':h(batch.purchase_id),'purchaseArtifactHash':h(batch.batch_hash),
        'amountMojos':str(batch.total_rail_amount),'baseAmountUsdMinor':str(batch.total_base_amount_minor),
        'technologyFeeUsdMinor':str(batch.total_technology_fee_minor),'totalAmountUsdMinor':str(batch.total_subtotal_minor),
        'quoteExpiresAt':first.quote_expires_at,'feeCapMojosPerStage':str(fee_cap),'maximumNetworkFeeMojos':str(2*fee_cap),
        'quoteExpired':int(s.clock())>=first.quote_expires_at,'reservationClaimHash':claim.digest(),
        'currentVaultCoinId':claim.children[0].current_vault_coin_id,
        'reservationRequested':s.store.reservation_request(identity,browser_hash=binding)is not None,
        'reservedCoinIds':list(reserved_coins(s,identity,binding,claim=claim))if existing is not None else None,
        'payerAuthorizationSaved':saved['deliveryClaim']is not None}


def request_reservation(s,identity,binding):
    return s.request_reservation(identity,browser_hash=binding)


async def prepare_reservation(s,identity,binding):
    saved=s._saved(identity,binding);old=s._existing(identity,'RESERVATION',binding)
    if old is not None:return old
    checked=await measured(s,identity,'reservation_verification',
        verify_current_batch_reservation(saved['reservationClaim'],**s._arguments()))
    def retain(index,reply):s.store.save_signature(identity,'reservation',index,reply,browser_hash=binding)
    signature=await measured(s,identity,'validator_quorum',
        collect_current_purchase_quorum(s.settings,checked,
            retained=saved['retainedSignatures']['reservation'],on_signature=retain))
    fresh=await measured(s,identity,'freshness_verification',
        verify_current_batch_reservation(saved['reservationClaim'],**s._arguments()))
    if [bytes(c.transition.spend)for c in fresh.children]!=[bytes(c.transition.spend)for c in checked.children]:
        raise ValueError('CURRENT_EXECUTION_RESERVATION_CHANGED_DURING_QUORUM')
    return s.store.prepare_execution(identity,'RESERVATION',SpendBundle([c.transition.spend for c in fresh.children],signature),
        browser_hash=binding,claim_hash=saved['reservationClaim'].digest(),fee_cap=s.fee_cap,
        expires_at=quote_deadline(s.policy,artifacts(saved['reservationClaim'])[0].quote_expires_at),now=int(s.clock()))


def reserved_coins(s,identity,binding,*,claim=None):
    if claim is None:
        claim = s._saved(identity,binding)['reservationClaim']
    bundle=s.store.execution_bundle(identity,'RESERVATION',browser_hash=binding)
    byinput={h(spend.coin.name()):spend for spend in bundle.coin_spends}
    if set(byinput)!={c.available_coin_id for c in claim.children}:
        raise ValueError('CURRENT_EXECUTION_EXACT_RESERVATION_SPEND_REQUIRED')
    result=[]
    for child in claim.children:
        odd=[c for c in compute_additions(byinput[child.available_coin_id])if c.amount%2]
        if len(odd)!=1 or odd[0].amount!=1:raise ValueError('CURRENT_EXECUTION_RESERVATION_OUTPUT_CHANGED')
        result.append(h(odd[0].name()))
    return tuple(result)


def forwardings(s,evidence,bundle):
    companions=tuple(build_testnet_primary_forwarding(bundle=bundle,artifact=artifact,
        terms=child.item.original.terms,issuer_public_key=s.policy.issuer_public_key,fees=s._fees(evidence))
        for child,artifact in zip(evidence.children,evidence.batch.artifacts,strict=True))
    spends=tuple(spend for companion in companions for spend in companion.operation.spends)
    if len({spend.coin.name()for spend in spends})!=len(spends):
        raise ValueError('CURRENT_EXECUTION_BATCH_FORWARDING_INPUT_REPEATED')
    issuer_spends=tuple(c.issuer_signature_spend for c in companions)
    pairs=[]
    for spend in issuer_spends:
        current=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if len(current)!=1:raise ValueError('CURRENT_EXECUTION_ONE_EXACT_ISSUER_SIGNATURE_REQUIRED')
        pairs.extend(current)
    return SimpleNamespace(operation=SimpleNamespace(spends=spends),issuer_signature_spends=issuer_spends),tuple(pairs)


async def issuer_review(s,identity,claim,binding):
    await s.accept_payer(identity,claim,browser_hash=binding)
    saved=s._saved(identity,binding);checked=await verify_current_delivery(claim,**s._arguments())
    def retain(index,reply):s.store.save_signature(identity,'delivery',index,reply,browser_hash=binding)
    signature=await collect_current_purchase_quorum(s.settings,checked,
        retained=saved['retainedSignatures']['delivery'],on_signature=retain)
    fresh=await verify_current_delivery(claim,**s._arguments())
    if bytes(checked.bundle)!=bytes(fresh.bundle):raise ValueError('CURRENT_EXECUTION_DELIVERY_CHANGED_DURING_QUORUM')
    signed=SpendBundle(fresh.bundle.coin_spends,AugSchemeMPL.aggregate([fresh.bundle.aggregated_signature,signature]))
    companion,pairs=forwardings(s,fresh,signed)
    return fresh,signed,companion,pairs


async def prepare_delivery(s,identity,claim,signature,binding):
    old=s._existing(identity,'DELIVERY',binding)
    if old is not None:
        saved=s._saved(identity,binding)
        if saved['deliveryClaim']is None or saved['deliveryClaim'].canonical()!=claim.canonical():
            raise ValueError('CURRENT_EXECUTION_SAVED_DELIVERY_CHANGED')
        return old
    if not isinstance(signature,G2Element):raise ValueError('CURRENT_EXECUTION_TYPED_ISSUER_SIGNATURE_REQUIRED')
    evidence,signed,companion,pairs=await issuer_review(s,identity,claim,binding)
    return await save_reviewed_delivery(s,identity,claim,signature,binding,evidence,signed,companion,pairs)


async def save_reviewed_delivery(s,identity,claim,signature,binding,evidence,signed,companion,pairs):
    """Checkpoint this invocation's verified review without repeating quorum.

    The private issuer has independently rebuilt it. Recheck all mutable
    inputs after that call; dispatch still independently reconstructs the exact
    saved bundle before funding. No HTTP request can supply these objects.
    """
    from .generation_customer_purchase_batch import CurrentBatchEvidence,fresh_children
    from .generation_sols_batch_execution import unspent
    if (not isinstance(evidence,CurrentBatchEvidence)or evidence.claim.canonical()!=claim.canonical()
            or [bytes(x)for x in signed.coin_spends]!=[bytes(x)for x in evidence.bundle.coin_spends]):
        raise ValueError('CURRENT_EXECUTION_DELIVERY_REVIEW_CHANGED')
    expected,expected_pairs=forwardings(s,evidence,signed)
    if ([bytes(x)for x in expected.operation.spends]!=[bytes(x)for x in companion.operation.spends]
            or expected_pairs!=pairs):raise ValueError('CURRENT_EXECUTION_ISSUER_REVIEW_CHANGED')
    if not AugSchemeMPL.aggregate_verify([p[0]for p in pairs],[p[1]for p in pairs],signature):
        raise ValueError('CURRENT_EXECUTION_ISSUER_SIGNATURE_INVALID')
    messages=[p for spend in signed.coin_spends for p in pkm_pairs_for_conditions_dict(
        conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])]
    if not AugSchemeMPL.aggregate_verify([p[0]for p in messages],[p[1]for p in messages],signed.aggregated_signature):
        raise ValueError('CURRENT_EXECUTION_NATIVE_SIGNATURE_INVALID')
    await fresh_children(evidence.children,s.provider);await unspent(s.provider,evidence.payment_coin)
    if int(s.clock())>=quote_deadline(s.policy,evidence.batch.artifacts[0].quote_expires_at):
        raise ValueError('CURRENT_EXECUTION_DISPATCH_WINDOW_CLOSED')
    bundle=SpendBundle([*signed.coin_spends,*companion.operation.spends],AugSchemeMPL.aggregate([signed.aggregated_signature,signature]))
    return s.store.prepare_execution(identity,'DELIVERY',bundle,browser_hash=binding,claim_hash=claim.digest(),
        fee_cap=s.fee_cap,expires_at=quote_deadline(s.policy,evidence.batch.artifacts[0].quote_expires_at),now=int(s.clock()))


async def expected_spends(s,saved,phase):
    if phase=='RESERVATION':
        evidence=await verify_current_batch_reservation(saved['reservationClaim'],**s._arguments())
        return [c.transition.spend for c in evidence.children]
    if phase=='RELEASE':
        from .generation_customer_purchase_timeout import verify_current_timeout
        bundles=[await verify_current_timeout(child,None,**s._arguments())for child in saved['reservationClaim'].children]
        return [spend for bundle in bundles for spend in bundle.coin_spends]
    if saved['deliveryClaim']is None:raise ValueError('CURRENT_EXECUTION_SAVED_PAYER_REQUIRED')
    evidence=await verify_current_delivery(saved['deliveryClaim'],**s._arguments())
    companion,_=forwardings(s,evidence,evidence.bundle)
    return [*evidence.bundle.coin_spends,*companion.operation.spends]
