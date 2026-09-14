"""Independent pre-confirmation exclusion and terminal inventory-return proof."""
from __future__ import annotations
import re
import time
from typing import Mapping
import httpx
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL
from solslot_puzzles.stripe_settlement_v1_driver import InventoryReservationV1, make_mint_offer_v5_inner, build_inventory_release_spend
from .inventory_payment_hold_claims import payment_hold_activation
from .validator_inventory_extension import extension_coordinates, IndependentNode
from .inventory_recovery import hx, record_coin, decode_spend, equivalent_timeout_spend


async def payment_provider(settings, hold):
    from .validator_service import load_stripe_restricted_key
    from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json
    purchase=purchase_artifact_v3_from_json(hold.purchase_artifact)
    if settings.stripe_mode!='test' or settings.stripe_account_id!=hold.activation['stripeAccountId']:
        raise ValueError('payment hold account or mode changed')
    async with httpx.AsyncClient(base_url=settings.stripe_api_url.rstrip('/'),timeout=20,
            headers={'authorization':'Bearer '+load_stripe_restricted_key(settings),'stripe-version':'2024-06-20'}) as client:
        async def get(path,**kwargs):
            r=await client.get(path,**kwargs);r.raise_for_status();value=r.json()
            if not isinstance(value,Mapping):raise ValueError('malformed provider response')
            return value
        account=await get('/v1/account')
        intent=await get('/v1/payment_intents/'+hold.payment_intent_id,params={'expand[]':'latest_charge'})
        charge=intent.get('latest_charge')
        if isinstance(charge,str):
            if not re.fullmatch(r'ch_[A-Za-z0-9]{1,200}',charge):raise ValueError('invalid charge reference')
            charge=await get('/v1/charges/'+charge)
        refunds=None
        if isinstance(charge,Mapping) and charge.get('refunded') is True:
            refunds=await get('/v1/refunds',params={'charge':charge['id'],'limit':100})
    meta=intent.get('metadata')
    if (account.get('id')!=settings.stripe_account_id or intent.get('id')!=hold.payment_intent_id
            or intent.get('livemode') is not False or intent.get('currency')!='usd'
            or type(intent.get('amount')) is not int or intent['amount']!=purchase.rail_amount
            or type(intent.get('created')) is not int or not 0<intent['created']<purchase.quote_expires_at
            or not isinstance(meta,Mapping) or meta.get('protocol_purchase_id')!=hx(purchase.purchase_id)
            or meta.get('purchase_artifact_hash')!=hx(purchase.artifact_hash)
            or meta.get('purchase_kind')!='PRESALE' or meta.get('processing_charge_minor')!='0'
            or intent.get('payment_method_types')!=[hold.payment_method]
            or 'payment_method' not in intent or 'latest_charge' not in intent
            or intent.get('capture_method')!='automatic'):
        raise ValueError('provider intent differs from the held canonical purchase')
    expected_policy={'card_3ds_policy':'any'} if hold.payment_method=='card' else {'bank_verification_policy':'instant'}
    if any(meta.get(k)!=v for k,v in expected_policy.items()):raise ValueError('payment risk policy differs')
    options=intent.get('payment_method_options')
    method_options=options.get(hold.payment_method) if isinstance(options,Mapping) else None
    option,expected=('request_three_d_secure','any') if hold.payment_method=='card' else ('verification_method','instant')
    if not isinstance(method_options,Mapping) or method_options.get(option)!=expected:
        raise ValueError('provider payment method options differ from the reviewed risk policy')
    received=intent.get('amount_received')
    if type(received) is not int or not 0<=received<=purchase.rail_amount:
        raise ValueError('received payment amount is inconsistent')
    terminal=None
    if charge is not None:
        if (not isinstance(charge,Mapping) or not re.fullmatch(r'ch_[A-Za-z0-9]{1,200}',str(charge.get('id'))) or charge.get('payment_intent')!=hold.payment_intent_id
                or charge.get('livemode') is not False or charge.get('currency')!='usd'
                or type(charge.get('amount')) is not int or charge['amount']!=purchase.rail_amount
                or not isinstance(charge.get('payment_method_details'),Mapping)
                or charge['payment_method_details'].get('type')!=hold.payment_method
                or type(charge.get('disputed')) is not bool):
            raise ValueError('charge differs from the held purchase')
        if charge['disputed']:raise ValueError('disputed payment requires review and remains held')
    if intent.get('status')=='canceled' and received==0:
        if (charge is None or (charge.get('paid') is False and charge.get('status')=='failed'
                and charge.get('balance_transaction') is None and type(charge.get('amount_refunded')) is int and charge['amount_refunded']==0)):
            terminal='CANCELED_UNPAID'
    if (intent.get('status')=='succeeded' and received==purchase.rail_amount and isinstance(charge,Mapping)
            and charge.get('paid') is True and charge.get('status')=='succeeded'
            and charge.get('refunded') is True and type(charge.get('amount_refunded')) is int
            and charge['amount_refunded']==received and isinstance(refunds,Mapping)
            and refunds.get('has_more') is False and isinstance(refunds.get('data'),list)
            and 0<len(refunds['data'])<=100):
        rows=refunds['data'];ids=set();total=0
        for refund in rows:
            if (not isinstance(refund,Mapping) or not re.fullmatch(r're_[A-Za-z0-9]{1,200}',str(refund.get('id'))) or refund['id'] in ids
                    or refund.get('payment_intent')!=hold.payment_intent_id or refund.get('charge')!=charge['id']
                    or refund.get('currency')!='usd' or refund.get('status')!='succeeded'
                    or type(refund.get('amount')) is not int or refund['amount']<=0):
                raise ValueError('full refund is not independently settled')
            ids.add(refund['id']);total+=refund['amount']
        if total==received:terminal='REFUNDED'
    return dict(intent=intent,charge=charge,terminal=terminal)


def active_hold(settings,hold):
    from .validator_service import load_validator_artifact
    artifact,_=load_validator_artifact(settings)
    active=payment_hold_activation(artifact,settings.deployment_environment)
    if (hold.activation!=active or hold.genesis_artifact_hash!=artifact['artifactHash']
            or settings.network!=hold.network or settings.roster_pubkeys!=artifact['validatorSet']['pubkeys']
            or artifact['validatorSet']['threshold']!=2):
        raise ValueError('payment hold does not bind the active signed deployment')
    return artifact


async def sign_inventory_payment_hold(settings,ledger,claim,claim_hash):
    from .validator_service import load_validator_private_key,ValidatorEvidenceError
    try:
        if claim.canonical_hash()!=claim_hash:raise ValueError('payment hold claim hash changed')
        artifact=active_hold(settings,claim)
        purchase,struct,terms=extension_coordinates(claim,artifact)
        old=ledger.inventory_payment_hold(hx(purchase.purchase_id))
        if old and (old['claim_hash']!=claim_hash or old['state']=='RELEASED'):
            raise ValueError('payment hold was replaced or released')
        provider=await payment_provider(settings,claim)
        intent=provider['intent']
        if provider['terminal']:raise ValueError('terminal payment cannot arm checkout')
        if old is None:
            if (intent.get('status')!='requires_payment_method' or intent.get('payment_method') is not None
                    or provider['charge'] is not None or intent['amount_received']!=0):
                raise ValueError('hold must be armed before payment can be confirmed')
            now=int(time.time());purchase.assert_live(now)
            if claim.reservation_expires_at!=min(purchase.quote_expires_at,purchase.authorization_expires_at):
                raise ValueError('pre-payment hold changes the initial soft reservation')
            if claim.reservation_expires_at<=now:raise ValueError('pre-payment reservation already expired')
            reservation=InventoryReservationV1(purchase,claim.reservation_expires_at)
            async with httpx.AsyncClient(base_url=settings.coinset_base_url.rstrip('/'),timeout=20) as client:
                node=IndependentNode(client);peak=await node.peak()
                from .inventory_timeout_submission import canonical_time
                from types import SimpleNamespace
                clock_node=SimpleNamespace(get_block_record=lambda digest: node.call('get_block_record', {'header_hash':digest}))
                if await canonical_time(clock_node,peak)>=claim.reservation_expires_at:
                    raise ValueError('canonical chain clock has already expired this reservation')
                expected=SINGLETON_MOD.curry(struct,make_mint_offer_v5_inner(terms,reservation)).get_tree_hash()
                coin,_=await node.current(claim.reserved_coin_id,expected,struct,peak)
                if hx(coin.puzzle_hash)!=claim.reserved_puzzle_hash:raise ValueError('reserved puzzle changed')
                if await node.peak()!=peak:raise ValueError('chain tip changed while arming')
            if claim.reservation_expires_at<=int(time.time()):raise ValueError('reservation expired while arming')
        if active_hold(settings,claim)['artifactHash']!=artifact['artifactHash']:raise ValueError('release changed while arming')
        if claim.canonical_hash()!=claim_hash:raise ValueError('payment claim changed during independent verification')
        signature=hx(AugSchemeMPL.sign(load_validator_private_key(settings),claim.signature_message()))
        return ledger.record_inventory_payment_hold(claim=claim,signature=signature,
            purchase_id=hx(purchase.purchase_id),deed_launcher_id=hx(purchase.deed_launcher_id))
    except Exception as exc:
        if isinstance(exc,ValidatorEvidenceError):raise
        raise ValidatorEvidenceError('payment hold is not independently proven: '+str(exc)) from exc


async def sign_inventory_payment_hold_release(settings,ledger,claim,claim_hash):
    from .validator_service import load_validator_private_key,ValidatorEvidenceError
    try:
        hold=claim.hold
        if claim.canonical_hash()!=claim_hash:raise ValueError('payment release hash changed')
        artifact=active_hold(settings,hold);purchase,struct,terms=extension_coordinates(hold,artifact)
        old=ledger.inventory_payment_hold(hx(purchase.purchase_id))
        if old is None or old['claim_hash']!=hold.canonical_hash():raise ValueError('release lacks its private hold')
        if claim.reservation_expires_at<hold.reservation_expires_at:raise ValueError('release shortens reservation')
        provider=await payment_provider(settings,hold)
        if provider['terminal'] is None:raise ValueError('payment is not terminally canceled or fully refunded')
        reservation=InventoryReservationV1(purchase,claim.reservation_expires_at)
        async with httpx.AsyncClient(base_url=settings.coinset_base_url.rstrip('/'),timeout=20) as client:
            node=IndependentNode(client);peak=await node.peak()
            expected=SINGLETON_MOD.curry(struct,make_mint_offer_v5_inner(terms,reservation)).get_tree_hash()
            coin,lineage=await node.current(claim.reserved_coin_id,expected,struct,peak,require_unspent=False)
            raw,_=await node.record(claim.reserved_coin_id);_,spent=record_coin(raw,coin)
            if not spent or peak[0]-spent+1<3:raise ValueError('inventory timeout is not confirmed')
            release=build_inventory_release_spend(reserved_coin=coin,deed_singleton_struct=struct,lineage_proof=lineage,
                reservation=reservation,terms=terms,timed_out=True)
            actual=decode_spend((await node.call('get_puzzle_and_solution',{'coin_id':claim.reserved_coin_id,'height':spent}))['coin_solution'],coin)
            if not equivalent_timeout_spend(actual,release.spend) or hx(release.next_coin.name())!=claim.available_coin_id:
                raise ValueError('inventory did not return through the exact timeout')
            out,_=await node.record(claim.available_coin_id);created,out_spent=record_coin(out,release.next_coin)
            if created!=spent or (out_spent and old['state']!='RELEASED'):
                raise ValueError('returned inventory is not the exact unspent successor')
            if await node.peak()!=peak:raise ValueError('chain tip changed during refund recovery')
        if active_hold(settings,hold)['artifactHash']!=artifact['artifactHash']:raise ValueError('release changed during recovery')
        if claim.canonical_hash()!=claim_hash:raise ValueError('payment claim changed during independent verification')
        signature=hx(AugSchemeMPL.sign(load_validator_private_key(settings),claim.signature_message()))
        return ledger.record_inventory_payment_hold_release(claim=claim,signature=signature,purchase_id=hx(purchase.purchase_id))
    except Exception as exc:
        if isinstance(exc,ValidatorEvidenceError):raise
        raise ValidatorEvidenceError('payment hold release is not independently proven: '+str(exc)) from exc
