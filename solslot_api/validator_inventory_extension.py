"""Independent hold verification. No processing evidence can authorize delivery."""
from __future__ import annotations

import re
import time
from typing import Mapping
import httpx
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json, PurchaseKind, PurchaseDeliveryKind, PaymentRail
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.mint_publish_driver import deed_launcher_puzzle_hash, deed_singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import (
    PrimaryMintTermsV3, InventoryReservationV1, PRIMARY_PURCHASE_PROVIDER_ID,
    MAX_RESERVATION_EXTENSION_SECONDS, build_inventory_extension_spend, make_mint_offer_v5_inner,
)
from solslot_puzzles.voucher_presale_v2 import series_terms_from_json, VoucherSeriesState
from solslot_puzzles.voucher_presale_v2_driver import VoucherSeriesStateV2, curry_series
from .inventory_extension_claims import InventoryExtensionClaim, extension_activation, RENEWAL_WINDOW_SECONDS
from .inventory_extension_store import canonical
from .inventory_recovery import hx, record_coin, decode_spend


def extension_coordinates(claim, artifact):
    purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
    if (purchase.network != 'testnet11' or purchase.rail != PaymentRail.STRIPE
            or purchase.purchase_kind != PurchaseKind.PRESALE
            or purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED
            or hx(purchase.protocol_treasury_puzzle_hash) != artifact['puzzleHashes']['protocolTreasuryPuzzleHash']):
        raise ValueError('extension supports only the exact current Stripe presale SmartDeed')
    did = singleton_struct(bytes32.fromhex(artifact['launcherIds']['did'].removeprefix('0x')))
    struct = deed_singleton_struct(deed_launcher_id=purchase.deed_launcher_id, protocol_did_singleton_struct=did)
    terms = PrimaryMintTermsV3.for_artifact(artifact=purchase,
        smart_deed_inner_hash=bytes32.fromhex(claim.smart_deed_inner_hash[2:]), inventory_version=2,
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(protocol_did_singleton_struct=did),
        protocol_puzhash=purchase.protocol_treasury_puzzle_hash,
        validator_pubkeys=tuple(bytes.fromhex(k.removeprefix('0x')) for k in artifact['validatorSet']['pubkeys']),
        provider_id=PRIMARY_PURCHASE_PROVIDER_ID)
    return purchase, struct, terms


def require_timely_extension(claim, now):
    if (not 0 < claim.reservation_expires_at-now <= RENEWAL_WINDOW_SECONDS
            or claim.next_expires_at != claim.reservation_expires_at+MAX_RESERVATION_EXTENSION_SECONDS
            or claim.payment_started_at > now):
        raise ValueError('extension is outside its current expiry, renewal window or bounded increment')


async def provider_hold(settings, claim, anchor=None):
    """Retrieve account, original start event, current intent and charge independently."""
    from .validator_service import load_stripe_restricted_key
    purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
    if settings.stripe_mode != 'test' or settings.stripe_account_id != claim.activation['stripeAccountId']:
        raise ValueError('extension payment account/mode differs from the reviewed capability')
    async with httpx.AsyncClient(base_url=settings.stripe_api_url.rstrip('/'), timeout=20,
            headers={'authorization': 'Bearer '+load_stripe_restricted_key(settings), 'stripe-version':'2024-06-20'}) as client:
        async def get(path, **kwargs):
            response=await client.get(path, **kwargs);response.raise_for_status();value=response.json()
            if not isinstance(value, Mapping): raise ValueError('malformed Stripe hold evidence')
            return value
        account=await get('/v1/account')
        intent=await get('/v1/payment_intents/'+claim.payment_intent_id, params={'expand[]':'latest_charge'})
        event=await get('/v1/events/'+claim.payment_event_id) if anchor is None else None
        charge=intent.get('latest_charge')
        if isinstance(charge,str) and re.fullmatch(r'ch_[A-Za-z0-9]{1,200}',charge): charge=await get('/v1/charges/'+charge)
    metadata={'protocol_purchase_id':hx(purchase.purchase_id),'purchase_artifact_hash':hx(purchase.artifact_hash)}
    def bound(value):
        return (isinstance(value,Mapping) and isinstance(value.get('metadata'),Mapping)
            and all(value['metadata'].get(k)==v for k,v in metadata.items())
            and value.get('id')==claim.payment_intent_id and value.get('livemode') is False
            and value.get('currency')=='usd' and type(value.get('amount')) is int
            and value['amount']==purchase.rail_amount)
    if anchor is None:
        obj=event.get('data',{}).get('object') if isinstance(event.get('data'),Mapping) else None
        event_type={'payment_intent.processing':'processing','payment_intent.succeeded':'succeeded'}.get(event.get('type'))
        if (not bound(obj) or not event_type or obj.get('status')!=event_type
                or (claim.payment_method=='card' and event_type!='succeeded')
                or event.get('livemode') is not False or event.get('id')!=claim.payment_event_id
                or type(event.get('created')) is not int or event['created']!=claim.payment_started_at):
            raise ValueError('Stripe start event differs from the exact purchase')
    else:
        import json
        original=InventoryExtensionClaim.model_validate(json.loads(anchor['canonical_claim']))
        fields=('activation','purchase_artifact','payment_intent_id','payment_event_id','payment_started_at','payment_method')
        if original.canonical_hash()!=anchor['claim_hash'] or any(getattr(original,k)!=getattr(claim,k) for k in fields):
            raise ValueError("payment start differs from this validator's independently verified anchor")
    if (account.get('id') != settings.stripe_account_id or not bound(intent)
            or intent.get('status') not in ('processing','succeeded')
            or (claim.payment_method=='card' and intent.get('status')!='succeeded')
            or type(intent.get('created')) is not int
            or not 0 < intent['created'] <= claim.payment_started_at < purchase.quote_expires_at
            or not isinstance(charge,Mapping) or charge.get('payment_intent')!=claim.payment_intent_id
            or charge.get('livemode') is not False or charge.get('currency')!='usd'
            or type(charge.get('amount')) is not int or charge['amount']!=purchase.rail_amount
            or not isinstance(charge.get('payment_method_details'),Mapping)
            or charge['payment_method_details'].get('type')!=claim.payment_method):
        raise ValueError('Stripe account or current hold differs from the exact purchase')
    refunded=charge.get('amount_refunded')
    if (type(refunded) is not int or not 0 <= refunded < purchase.rail_amount
            or type(charge.get('refunded')) is not bool or charge['refunded'] is not False
            or type(charge.get('disputed')) is not bool
            or (intent['status']=='succeeded' and (type(intent.get('amount_received')) is not int
                or intent['amount_received']!=purchase.rail_amount))):
        raise ValueError('payment is terminally refunded or hold evidence is inconsistent')
    # Disputes/partial refunds keep inventory held; they never authorize delivery.
    return dict(status=intent['status'], reviewRequired=bool(refunded or charge['disputed']))


class IndependentNode:
    def __init__(self, client): self.client=client

    async def call(self, method, body=None):
        r=await self.client.post('/'+method,json=body or {});r.raise_for_status();value=r.json()
        if not isinstance(value,Mapping) or value.get('success') is not True: raise ValueError('independent node evidence unavailable')
        return value

    async def peak(self):
        info=await self.call('get_network_info');state=(await self.call('get_blockchain_state'))['blockchain_state'];peak=state['peak']
        if (info.get('network_name')!='testnet11' or state['sync']['synced'] is not True
                or state['sync'].get('sync_mode') is not False or type(peak['height']) is not int or peak['height']<=0):
            raise ValueError('independent node is not synced on testnet11')
        return peak['height'], hx(bytes32.fromhex(peak['header_hash'].removeprefix('0x')))

    async def record(self, name):
        value=(await self.call('get_coin_record_by_name',{'name':name}))['coin_record']
        coin=Coin.from_json_dict(value['coin'])
        if hx(coin.name())!=name: raise ValueError('node returned another input')
        record_coin(value,coin)
        return value,coin

    async def current(self, name, expected_hash, struct, peak, *, require_unspent=True):
        record,coin=await self.record(name);created,spent=record_coin(record,coin)
        if (require_unspent and spent) or peak[0]-created+1<3 or coin.puzzle_hash!=expected_hash: raise ValueError('current inventory or series is not mature and unspent')
        parent_record,parent=await self.record(hx(coin.parent_coin_info));_,height=record_coin(parent_record,parent)
        if height!=created: raise ValueError('current source lineage is not atomic')
        raw=(await self.call('get_puzzle_and_solution',{'coin_id':hx(parent.name()),'height':height}))['coin_solution']
        spend=decode_spend(raw,parent);reveal=Program.from_bytes(bytes(spend.puzzle_reveal));mod,args=reveal.uncurry()
        values=list(args.as_iter())
        # A canonical singleton parent authenticates current unspent lineage.
        # A series eve coin may instead descend from its exact launcher.
        launcher_id=bytes32(struct.rest().first().as_atom())
        launcher_hash=bytes32(struct.rest().rest().as_atom())
        if parent.name()==launcher_id:
            if parent.puzzle_hash!=launcher_hash: raise ValueError('wrong singleton launcher')
        elif mod!=SINGLETON_MOD or len(values)!=2 or values[0]!=struct:
            raise ValueError('current coin lacks a canonical singleton parent')
        if sum(c==coin for c in SpendBundle([spend],G2Element()).additions())!=1:
            raise ValueError('canonical parent did not create the claimed successor')
        return coin,lineage_proof_for_coinsol(spend)


async def verify_inventory_extension_claim(settings, claim: InventoryExtensionClaim, claim_hash, *, ledger=None):
    from .validator_service import load_validator_artifact, ValidatorEvidenceError
    try:
        if claim.canonical_hash()!=claim_hash: raise ValueError('extension claim hash changed')
        artifact,_=load_validator_artifact(settings)
        active=extension_activation(artifact,settings.deployment_environment)
        if (claim.activation!=active or claim.genesis_artifact_hash!=artifact['artifactHash']
                or settings.network!=claim.network or settings.roster_pubkeys!=artifact['validatorSet']['pubkeys']
                or artifact['validatorSet']['threshold']!=2): raise ValueError('extension does not bind the active signed deployment')
        require_timely_extension(claim,int(time.time()))
        purchase,struct,terms=extension_coordinates(claim,artifact)
        reservation=InventoryReservationV1(purchase,claim.reservation_expires_at)
        series=series_terms_from_json(claim.series_terms)
        if (series.terms_hash!=purchase.presale_terms_hash or series.collection_id!=purchase.collection_id
                or series.metadata_root!=purchase.metadata_root or series.metadata_anchor_id!=purchase.metadata_anchor_id
                or series.trusted_protocol_treasury!=purchase.protocol_treasury_puzzle_hash
                or series.validator_pubkeys!=terms.validator_pubkeys): raise ValueError('extension changes governed presale terms')
        state=VoucherSeriesStateV2(**{**claim.series_state,'phase':VoucherSeriesState(claim.series_state['phase'])})
        async with httpx.AsyncClient(base_url=settings.coinset_base_url.rstrip('/'),timeout=20) as client:
            node=IndependentNode(client);peak=await node.peak()
            coin,lineage=await node.current(claim.reserved_coin_id,SINGLETON_MOD.curry(struct,make_mint_offer_v5_inner(terms,reservation)).get_tree_hash(),struct,peak)
            if hx(coin.puzzle_hash)!=claim.reserved_puzzle_hash: raise ValueError('reserved puzzle commitment changed')
            series_struct=singleton_struct(series.series_singleton_id)
            await node.current(claim.series_coin_id,SINGLETON_MOD.curry(series_struct,curry_series(series,state)).get_tree_hash(),series_struct,peak,require_unspent=False)
            anchor = ledger.inventory_extension_payment_anchor(hx(purchase.purchase_id)) if ledger is not None else None
            await provider_hold(settings,claim,anchor)
            if await node.peak()!=peak: raise ValueError('chain tip changed during extension authorization')
        indices=tuple(sorted((settings.signer_index,(settings.signer_index+1)%3)))
        transition=build_inventory_extension_spend(reserved_coin=coin,deed_singleton_struct=struct,
            lineage_proof=lineage,reservation=reservation,next_expires_at=claim.next_expires_at,signer_indices=indices,terms=terms)
        if hx(transition.validator_message)!=claim.validator_message: raise ValueError('extension message changed')
        current,_=load_validator_artifact(settings)
        if current['artifactHash']!=artifact['artifactHash'] or extension_activation(current,settings.deployment_environment)!=active:
            raise ValueError('signed deployment changed during extension authorization')
        require_timely_extension(claim,int(time.time()))
    except (KeyError, TypeError, ValueError, RuntimeError, httpx.HTTPError, OSError) as exc:
        raise ValidatorEvidenceError('inventory extension is not independently proven: '+str(exc)) from exc


async def sign_inventory_extension_claim(settings,ledger,claim,claim_hash):
    from .validator_service import load_validator_private_key, ValidatorEvidenceError
    from .validator_ledger import ValidatorLedgerConflict
    await verify_inventory_extension_claim(settings,claim,claim_hash,ledger=ledger)
    signature=hx(AugSchemeMPL.sign(load_validator_private_key(settings),claim.signature_message()))
    try:
        return ledger.record_inventory_extension_or_recover(claim_hash=claim_hash,
            canonical_claim=canonical(claim.model_dump(mode='json')),
            purchase_id=hx(purchase_artifact_v3_from_json(claim.purchase_artifact).purchase_id),
            reserved_coin_id=claim.reserved_coin_id,signature=signature)
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc
