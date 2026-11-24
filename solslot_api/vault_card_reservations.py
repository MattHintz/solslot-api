"""Private validator endorsement of exact primary-mint Stripe inventory reservations."""
import asyncio
import hashlib
import time

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G1Element, G2Element
from pydantic import BaseModel, ConfigDict

from .faucet import AGG_SIG_ME_DATA
from .generation_index import load_generation_read_anchor
from .protocol_submission import ProtocolBundleSubmitter
from .validator_quorum import _private_validator_client, configured_validator_pubkeys
from .validator_service import load_validator_private_key
from .vault_card_native import Hash, VaultCardNative
from .vault_card_store import canonical, h


class ReservationRequest(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    purchaseId: Hash
    batchHash: Hash
    releaseId: Hash


def request_for(order):
    return ReservationRequest(purchaseId=order.purchase_id,batchHash=order.batch_hash,releaseId=order.release_id)


def signing_messages(evidence,indices,roster):
    order=evidence.order
    if tuple(roster)!=tuple(evidence.items[0].terms.validator_pubkeys):
        raise ValueError('Validator roster differs from the original mint')
    rows=[]
    for t in evidence.transitions:
        spend=t.spend
        if Program.from_bytes(bytes(spend.puzzle_reveal)).get_tree_hash()!=spend.coin.puzzle_hash:
            raise ValueError('Reservation puzzle is not the original')
        conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
        deadlines={int.from_bytes(c.vars[0],'big',signed=True) for c in conditions.get(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE,[])}
        if deadlines!={order.expires_at}:
            raise ValueError('Native reservation deadline changed')
        pairs=pkm_pairs_for_conditions_dict(conditions,spend.coin,AGG_SIG_ME_DATA[order.network])
        if len(pairs)!=2 or {bytes(k) for k,_ in pairs}!={roster[i] for i in indices}:
            raise ValueError('Native signature requirements changed')
        rows.append({roster.index(bytes(k)):bytes(m) for k,m in pairs})
    return rows


async def sign_reservation(settings,ledger,provider,body,*,clock=time.time):
    if not settings.vault_card_reservations_enabled or provider is None:
        raise ValueError('Card reservation signing unavailable')
    native=VaultCardNative.configured(settings)
    indices=native.scope.signerIndices
    index=settings.signer_index
    if index not in indices or not native.scope.validFrom<=int(clock())<native.scope.expiresAt-1950:
        raise ValueError('Signer or reservation window unavailable')
    evidence=await native.from_primary(load_generation_read_anchor(settings),provider)
    if evidence.inventory.evidence.registry.state.pause_mask & 8:
        raise ValueError('Current generation purchases paused')
    if request_for(evidence.order)!=body or await native.stage(evidence,provider)!=('AVAILABLE',None):
        raise ValueError('Original card reservation is unavailable')
    roster=tuple(bytes.fromhex(k.removeprefix('0x')) for k in settings.roster_pubkeys)
    messages=signing_messages(evidence,indices,roster)
    key=load_validator_private_key(settings)
    if bytes(key.get_g1())!=roster[index] or not native.scope.validFrom<=int(clock())<native.scope.expiresAt-1950:
        raise ValueError('Validated signer or reservation deadline differs')
    signatures=[]
    for pos,row in enumerate(messages):
        artifact=evidence.transitions[pos].reservation.artifact
        claim=dict(**body.model_dump(),deedLauncherId=h(artifact.deed_launcher_id),
                   availableCoinId=evidence.order.original_coin_ids[pos],expiresAt=evidence.order.expires_at)
        encoded=canonical(claim)
        result=ledger.record_inventory_reservation_or_recover(claim_hash=h(hashlib.sha256(encoded.encode()).digest()),
            canonical_claim=encoded,purchase_id=h(artifact.purchase_id),available_coin_id=claim['availableCoinId'],
            deed_launcher_id=claim['deedLauncherId'],signature=h(bytes(AugSchemeMPL.sign(key,row[index]))))
        signatures.append(result)
    return dict(**body.model_dump(),signerIndex=index,signatures=signatures)


async def collect(settings,native,evidence,*,client=None):
    roster=configured_validator_pubkeys(settings)
    indices=native.scope.signerIndices
    rows=signing_messages(evidence,indices,roster)
    body=request_for(evidence.order).model_dump()
    owned=client is None
    if owned:
        client=_private_validator_client(settings)
    async def one(index):
        result=await client.post(settings.zkpassport_validator_urls[index].rstrip('/')+'/v1/generation/vault-card/reservation',
                                 json=body,timeout=50)
        result.raise_for_status()
        reply=result.json()
        if (reply!={**body,'signerIndex':index,'signatures':reply.get('signatures')}
                or not isinstance(reply['signatures'],list) or len(reply['signatures'])!=len(rows)):
            raise ValueError('Private signer returned a different claim')
        sigs=[G2Element.from_bytes(bytes.fromhex(s.removeprefix('0x'))) for s in reply['signatures']]
        for row,sig in zip(rows,sigs,strict=True):
            if not AugSchemeMPL.verify(G1Element.from_bytes(roster[index]),row[index],sig):
                raise ValueError('Invalid private reservation signature')
        return sigs
    try:
        results=await asyncio.gather(*(one(i) for i in indices),return_exceptions=True)
        for result in results:
            if isinstance(result,BaseException):
                raise result
    finally:
        if owned:
            await client.aclose()
    return tuple(AugSchemeMPL.aggregate(list(pair)) for pair in zip(*results,strict=True))


def card_submitter(app,order):
    worker=getattr(app.state,'stripe_delivery_worker',None)
    if worker is None:
        raise ValueError('Scoped current card sponsor unavailable')
    current=worker.current_card_order()
    if (not current or current.release_id!=order.release_id or current.purchase_id!=order.purchase_id
            or current.batch_hash!=order.batch_hash or not worker.settings.vault_card_delivery_enabled
            or worker.settings.alpha_writes_enabled or worker.settings.minting_enabled
            or worker.settings.stripe_settlement_enabled or worker.settings.protocol_fee_funding_enabled or worker.settings.stripe_delivery_worker_enabled):
        raise ValueError('Current scoped sponsor release differs')
    return worker.submitter


async def submit_reservation(app,order,purchases,saved):
    submitter=card_submitter(app,order)
    if (not isinstance(submitter,ProtocolBundleSubmitter) or submitter.funding_store is None
            or not submitter.policy.enabled or submitter.faucet.network!=order.network
            or not 0 < submitter.policy.maximum_mojos <= order.maximum_fee_per_stage_mojos):
        raise ValueError('Original reservation fee ceiling or durable funding unavailable')
    def check(prepared):
        if (not 0 <= prepared.fee_mojos <= order.maximum_fee_per_stage_mojos or prepared.backing_mojos!=0
                or not prepared.fee_coin_id or int(time.time())>=order.expires_at-1950):
            raise ValueError('Original reservation fee, backing or deadline differs')
    result=await submitter.submit(saved.inventory_bundle,before_push=check)
    return purchases.record_inventory_submitted(order.purchase_id,bundle_id=result['spendBundleId'],
                                                mempool_observed_at=result['mempoolObservedAt'])


async def reserve(request,settings,native,evidence,purchases,stage):
    o=evidence.order
    native.check_profile()
    if (not settings.vault_card_checkout_enabled or settings.alpha_writes_enabled
            or not settings.generation_customer_enabled or evidence.inventory.evidence.registry.state.pause_mask & 8
            or o.release_id!=native.release_id or o.generation_anchor_hash!=settings.generation_chain_anchor_hash):
        raise ValueError('Current generation card purchase is closed')
    sponsor=card_submitter(request.app,o)
    if (sponsor.funding_store is None or not sponsor.policy.enabled or
            not 0<sponsor.policy.maximum_mojos<=o.maximum_fee_per_stage_mojos):
        raise ValueError('Current reservation fee budget unavailable')
    saved=purchases.get(o.purchase_id)
    state,height=stage
    if state=='CONFIRMED':
        if saved.inventory_state=='PREPARED':
            # A coordinator crash may precede the mempool journal write. Primary
            # confirmation of every exact spend is stronger than mempool presence.
            bundle=WalletSpendBundle.from_json_dict(saved.inventory_bundle)
            submitter=card_submitter(request.app,o)
            funding=submitter.funding_store.lookup(o.network,h(bundle.name()),
                dict(feeTill=submitter.faucet.address_hex,purpose=None,backingMojos=0))
            if (not funding or funding.get('protocolSpendBundle')!=saved.inventory_bundle
                    or funding['spendBundleId']!=h(WalletSpendBundle.from_json_dict(funding['spendBundle']).name())
                    or not 0<=int(funding['feeMojos'])<=o.maximum_fee_per_stage_mojos or int(funding['backingMojos'])!=0):
                raise ValueError('Exact sponsored reservation proof missing')
            saved=purchases.record_inventory_submitted(o.purchase_id,bundle_id=funding['spendBundleId'],
                mempool_observed_at='exact-primary-confirmation')
        if saved.inventory_state=='SUBMITTED':
            return purchases.record_inventory_confirmed(o.purchase_id,confirmation_height=height)
        if saved.inventory_state=='CONFIRMED' and saved.inventory_confirmation_height==height:
            return saved
        raise ValueError('Native journal and confirmed reservations differ')
    if state!='AVAILABLE':
        return saved
    if saved.inventory_state=='UNRESERVED':
        sigs=await collect(settings,native,evidence)
        items=[]
        for t,sig in zip(evidence.transitions,sigs,strict=True):
            items.append(dict(deed_launcher_id=h(t.reservation.artifact.deed_launcher_id),
                available_coin_id=h(t.spend.coin.name()),reserved_coin_id=h(t.reserved_coin.name()),
                reserved_puzzle_hash=h(t.reserved_coin.puzzle_hash),expires_at=o.expires_at,
                signer_indices=native.scope.signerIndices,signature=h(bytes(sig))))
        bundle=WalletSpendBundle([t.spend for t in evidence.transitions],AugSchemeMPL.aggregate(list(sigs)))
        saved=purchases.record_inventory_batch_prepared(o.purchase_id,items=tuple(items),bundle=bundle.to_json_dict())
    if saved.inventory_state=='SUBMITTED':
        # No mempool conflict and both originals remain unspent. Recover precisely
        # the persisted sponsor bundle (including its fee coin and amount).
        submitter=card_submitter(request.app,o)
        journal=getattr(submitter,'funding_store',None)
        if journal is None:
            return saved
        raw=WalletSpendBundle.from_json_dict(saved.inventory_bundle)
        funded=journal.lookup(o.network,h(raw.name()),
            dict(feeTill=submitter.faucet.address_hex,purpose=None,backingMojos=0))
        if not funded or h(WalletSpendBundle.from_json_dict(funded['spendBundle']).name())!=saved.inventory_bundle_id:
            raise ValueError('Original funded reservation requires reconciliation')
    if saved.inventory_state in ('PREPARED','SUBMITTED'):
        return await submit_reservation(request.app,o,purchases,saved)
    raise ValueError('Original reservation is no longer active')


async def recover_unallocated(app,settings,order,*,now):
    """Recover an expired buyer-requested reservation that never became payable."""
    from chia_rs.sized_bytes import bytes32
    from .generation_coin_evidence import read_confirmed_coin
    from .inventory_authorization_expiry import reconcile_inventory_authorization_expiry
    from .inventory_expiry_clock import prove_expired_unspent_batch
    from .inventory_timeout_submission import advance_inventory_timeout
    from .payment_purchase_store import PaymentPurchaseNotFound,get_payment_purchase_store
    from .vault_card_settlement import current_card_artifact,card_return_binding
    from .vault_card_events import CardInbox
    from .vault_card_store import VaultCardStore

    if not (order.network==settings.network and order.mode==settings.stripe_mode and order.account_id==settings.stripe_account_id
            and order.generation_id==settings.deployment_generation_id and now>=order.expires_at):
        return False
    orders=VaultCardStore(settings.payment_purchase_db_path)
    inbox=CardInbox(settings.payment_purchase_db_path)
    submitter=card_submitter(app,order)
    if submitter.funding_store is None:
        return False
    journal=submitter.funding_store.cards
    purchases=get_payment_purchase_store(settings.payment_purchase_db_path)
    node=submitter.provider.primary
    def fenced():
        if (orders.get(order.purchase_id)!=order or not orders.fence_undispatched_order(order.purchase_id,now=now)
                or journal.get(order.purchase_id) is not None or inbox.settlement(order.purchase_id)
                or inbox.review(order.purchase_id)):
            raise ValueError('Unallocated return no longer owns this order')
    fenced()
    records=[read_confirmed_coin(await node.get_coin_record_by_name(coin),bytes32.from_hexstr(coin))
             for coin in order.original_coin_ids]
    try:
        saved=purchases.get(order.purchase_id)
    except PaymentPurchaseNotFound:
        saved=None
    if saved is not None and (saved.purchase_artifact!=order.batch or saved.artifact_hash!=order.batch_hash
                              or saved.external_message is not None):
        return False
    if saved is None or saved.inventory_state=='UNRESERVED':
        await prove_expired_unspent_batch(node,[r.coin for r in records],order.expires_at,order.network)
        fenced()
        return True
    artifact=current_card_artifact(settings,order)
    if artifact['artifactHash']!=order.generation_anchor_hash or artifact['network']!=order.network:
        raise ValueError('Original return release differs')
    env=settings.runtime_environment+'-alpha'
    if not any(r.spent_height for r in records):
        return await retire_card_authorization(purchases,node,order,artifact,fenced)
    if not all(r.spent_height for r in records):
        return False
    items=purchases.inventory_items(order.purchase_id)
    if (tuple(row.available_coin_id for row in items)!=order.original_coin_ids
            or tuple(row.reserved_coin_id for row in items)!=order.reserved_coin_ids):
        return False
    binding=card_return_binding(order,artifact,env)
    def authorize():
        fenced()
        if settings.alpha_writes_enabled or not settings.generation_customer_enabled:
            raise ValueError('Current generation recovery unavailable')
        if (not settings.vault_card_delivery_enabled or settings.protocol_fee_funding_enabled or not submitter.policy.enabled
                or not 0<submitter.policy.maximum_mojos<=order.maximum_fee_per_stage_mojos
                or current_card_artifact(settings,order)['artifactHash']!=binding['artifactHash']):
            raise ValueError('Authorized inventory return funding unavailable')
    result=await advance_inventory_timeout(store=purchases,node=node,submitter=submitter,purchase_id=order.purchase_id,
        network=order.network,release_binding=binding,authorize=authorize)
    if result['state']!='RELEASED':
        return False
    rows=result['releaseEvidence']['items']
    return tuple(row['reservedCoinId'] for row in rows)==order.reserved_coin_ids

async def retire_card_authorization(purchases,node,order,artifact,authorize):
    from dataclasses import asdict
    from .inventory_recovery import timeout_items
    from .inventory_expiry_clock import prove_expired_unspent_batch
    from .inventory_status import validated_recovery_receipt
    authorize()
    snapshot=purchases.inventory_status_snapshot(order.purchase_id)
    stored,rows,_,_=snapshot
    if stored.inventory_state=='AUTHORIZATION_EXPIRED':
        validated_recovery_receipt(snapshot,network=order.network)
        return True
    if (stored.inventory_state not in ('PREPARED','SUBMITTED') or stored.inventory_confirmation_height is not None
            or stored.external_message is not None or stored.offer_artifact.get('vaultCardReleaseId')!=order.release_id
            or stored.purchase_artifact!=order.batch or artifact['artifactHash']!=order.generation_anchor_hash
            or artifact['network']!=order.network or artifact['validatorSet']['threshold']!=2):
        raise ValueError('Signed unused authorization differs from original vault release')
    reconstructed=timeout_items(purchases,order.purchase_id)
    roster=tuple(bytes.fromhex(k.removeprefix('0x')) for k in artifact['validatorSet']['pubkeys'])
    pubkeys,messages=[],[]
    bundle=WalletSpendBundle.from_json_dict(stored.inventory_bundle)
    for item,row,coin_id,reserved in zip(reconstructed,rows,order.original_coin_ids,order.reserved_coin_ids,strict=True):
        spend=item.reservation_spend
        if (h(spend.coin.name())!=coin_id or h(item.release_spend.coin.name())!=reserved
                or stored.inventory_expires_at!=order.expires_at or row.deed_launcher_id!=item.launcher):
            raise ValueError('Signed unused inventory differs')
        conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
        if [v.vars[0] for v in conditions.get(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE,[])]!=[Program.to(order.expires_at).as_atom()]:
            raise ValueError('Unused native signature expiry differs')
        pairs=pkm_pairs_for_conditions_dict(conditions,spend.coin,AGG_SIG_ME_DATA[order.network])
        if len(pairs)!=2 or {bytes(pk) for pk,_ in pairs}!={roster[i] for i in row.signer_indices}:
            raise ValueError('Unused native reservation signers differ')
        keys,msgs=zip(*pairs,strict=True)
        sig=G2Element.from_bytes(bytes.fromhex(row.signature.removeprefix('0x')))
        if not AugSchemeMPL.aggregate_verify(list(keys),list(msgs),sig):
            raise ValueError('Invalid original reservation signature')
        pubkeys.extend(keys)
        messages.extend(msgs)
    if not AugSchemeMPL.aggregate_verify(pubkeys,messages,bundle.aggregated_signature):
        raise ValueError('Invalid original reservation bundle signature')
    proofs=await prove_expired_unspent_batch(node,[i.reservation_spend.coin for i in reconstructed],order.expires_at,order.network)
    authorize()
    evidence=dict(schema='solslot.inventory-authorization-expiry.v1',purchaseId=order.purchase_id,
        artifactHash=order.generation_anchor_hash,activation={'schema':'solslot.vault-card-unused-authorization.v1',
        'releaseId':order.release_id,'generationId':order.generation_id,'generationAnchorHash':order.generation_anchor_hash,
        'network':order.network},
        snapshot=asdict(stored),items=[asdict(row) for row in rows],chainProofs=proofs)
    return purchases.record_inventory_authorization_expired(order.purchase_id,evidence=evidence).inventory_state=='AUTHORIZATION_EXPIRED'
