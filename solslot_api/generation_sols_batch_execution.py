"""Source-scoped primary batch preparation; no indexer-selected authority.

Coordinator and independent validators use the same deterministic builder,
with independent primary-node reads of the frozen generation and every input.
Client requests contain original offers and price attestations, never spends,
private keys, arbitrary modules or a preassembled transaction to authorize.
"""
import asyncio
from dataclasses import replace
from hashlib import sha256
import time
from pydantic import Field,model_validator
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.trading.offer import Offer
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs import G2Element,AugSchemeMPL,G1Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_statutes import GenerationStatutes,RECORDS
from solslot_puzzles.generation_sols_reserve import reserve_inner
from solslot_puzzles.generation_batch_settlement import build_primary_batches
from solslot_puzzles.generation_batch_orders import inspect_buyer_offer
from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
from solslot_puzzles.payment_artifacts_v2 import oracle_round_from_json
from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
from .generation_execution import Model,Hash
from .generation_operations import canonical
from .generation_chain_evidence import resolve_generation_chain,current_evidence_unchanged
from .generation_coin_evidence import read_confirmed_coin
from .generation_registry_evidence import _spend
from .generation_sols_batches import external_inputs,verify_order_signature,TESTNET11_SIGNATURE_DATA,parse_signed_order


def h(v):return '0x'+v.hex()


class BatchBuyer(Model):
    offer:str=Field(min_length=10,max_length=2_000_000)
    destination:Hash
    payment_asset:Hash|None=Field(default=None,alias='paymentAsset')


class PrimaryBatchClaim(Model):
    generation_id:Hash=Field(alias='generationId')
    anchor_hash:Hash=Field(alias='anchorHash')
    primary_coin_ids:tuple[Hash,...]=Field(alias='primaryCoinIds',min_length=1,max_length=8)
    buyers:tuple[BatchBuyer,...]=Field(min_length=1,max_length=32)
    signed_price:dict=Field(alias='signedPrice')
    expires_at:int=Field(alias='expiresAt',strict=True,gt=0)
    signer_indices:tuple[int,int]=Field(alias='signerIndices')
    registry_coin_id:Hash=Field(alias='registryCoinId')
    pool_coin_id:Hash=Field(alias='poolCoinId')
    statutes_coin_id:Hash=Field(alias='statutesCoinId')

    @model_validator(mode='after')
    def bounded(self):
        if len(set(self.primary_coin_ids))!=len(self.primary_coin_ids) or self.signer_indices not in ((0,1),(0,2),(1,2)):
            raise ValueError('primary sources and exact signer pair must be distinct and canonical')
        if len(self.canonical().encode())>4_000_000:raise ValueError('batch claim exceeds its native evidence bound')
        return self

    def canonical(self):return canonical(self.model_dump(mode='json',by_alias=True))
    def digest(self):return h(sha256(self.canonical().encode()).digest())


class PrimaryBatchSelection(Model):
    generation_id:Hash=Field(alias='generationId')
    anchor_hash:Hash=Field(alias='anchorHash')
    primary_coin_ids:tuple[Hash,...]=Field(alias='primaryCoinIds',min_length=1,max_length=8)
    signed_price:dict=Field(alias='signedPrice')
    expires_at:int=Field(alias='expiresAt',strict=True,gt=0)
    signer_indices:tuple[int,int]=Field(alias='signerIndices')
    registry_coin_id:Hash=Field(alias='registryCoinId')
    pool_coin_id:Hash=Field(alias='poolCoinId')
    statutes_coin_id:Hash=Field(alias='statutesCoinId')

    def with_buyers(self,buyers):
        return PrimaryBatchClaim.model_validate({**self.model_dump(mode='json',by_alias=True),'buyers':buyers})


def signed_price(value):
    if not isinstance(value,dict) or set(value) not in ({'round','signatures'},{'schema','round','signatures'}):
        raise ValueError('batch price evidence fields changed')
    raw=value['signatures']
    if not isinstance(raw,list) or len(raw)!=2 or any(set(r)!={'signerIndex','signature'} for r in raw):
        raise ValueError('exactly two distinct price signatures are required')
    return SignedPrimaryPrice(oracle_round_from_json(value['round']),tuple((r['signerIndex'],bytes.fromhex(r['signature'].removeprefix('0x'))) for r in raw))


async def unspent(provider,coin):
    record=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(coin.name())),coin.name())
    if record.coin!=coin or record.spent_height:raise ValueError('BATCH_INPUT_CHANGED')
    return record


async def current_inventory(item,provider):
    """Follow confirmed singleton successors, including reservation returns."""
    coin,parent=item.coin,item.launcher_spend
    for _ in range(64):
        record=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(coin.name())),coin.name())
        if record.coin!=coin:raise ValueError('PRIMARY_INVENTORY_EVIDENCE_CHANGED')
        if not record.spent_height:
            if coin.puzzle_hash!=item.coin.puzzle_hash:raise ValueError('PRIMARY_INVENTORY_NOT_AVAILABLE')
            if parent.coin.name()==item.launcher_spend.coin.name():
                lineage=LineageProof(parent.coin.parent_coin_info,amount=parent.coin.amount)
            else:
                reveal=Program.from_bytes(bytes(parent.puzzle_reveal));mod,args=reveal.uncurry()
                values=list(args.as_iter())
                if mod.get_tree_hash()!=SINGLETON_MOD_HASH or len(values)!=2:raise ValueError('PRIMARY_LINEAGE_CHANGED')
                lineage=LineageProof(parent.coin.parent_coin_info,values[1].get_tree_hash(),parent.coin.amount)
            return replace(item,coin=coin),lineage,record
        parent=_spend(await provider.get_puzzle_and_solution_primary(h(coin.name()),record.spent_height),coin)
        outputs,_=compute_additions_with_cost(parent,max_cost=100_000_000)
        children=[output for output in outputs if output.amount%2]
        if len(children)!=1 or children[0].amount!=1:raise ValueError('PRIMARY_INVENTORY_NO_CONTINUATION')
        coin=children[0]
    raise ValueError('PRIMARY_INVENTORY_HISTORY_LIMIT')


async def resolve_batch(claim,*,settings,anchor,provider,clock=time.time,signature_data=TESTNET11_SIGNATURE_DATA):
    claim=PrimaryBatchClaim.model_validate_json(claim.model_dump_json(by_alias=True))
    if (settings.network!='testnet11' or claim.generation_id!=settings.deployment_generation_id
            or claim.anchor_hash!=settings.generation_chain_anchor_hash
            or bytes32.from_hexstr(claim.generation_id)!=anchor.issuance.generation):
        raise ValueError('BATCH_GENERATION_BINDING_CHANGED')
    if (await provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('BATCH_NETWORK_CHANGED')
    now=int(clock());price=signed_price(claim.signed_price)
    if not now<claim.expires_at<=price.round.valid_until or price.round.valid_from>now:
        raise ValueError('BATCH_PRICE_REVIEW_EXPIRED')
    evidence=await resolve_generation_chain(anchor,provider=provider)
    pools=[row for row in evidence.economic_components.values() if isinstance(row.state,GenerationPool)]
    statutes=[row for row in evidence.economic_components.values() if isinstance(row.state,GenerationStatutes)]
    mints=[row for row in evidence.economic_components.values() if isinstance(row.state,GenerationMint)]
    if len(pools)!=1 or len(statutes)!=1 or len(mints)!=1:raise ValueError('BATCH_AUTHORITIES_INCOMPLETE')
    ph,sh,mh=pools[0],statutes[0],mints[0];pool=ph.state;statute=sh.state;registry=evidence.registry.state
    if (h(ph.current.coin.name())!=claim.pool_coin_id or h(sh.current.coin.name())!=claim.statutes_coin_id
            or h(evidence.registry.current.coin.name())!=claim.registry_coin_id):raise ValueError('BATCH_REVIEW_INPUTS_CHANGED')
    records={kind:() for kind in RECORDS}
    for transition in sh.transitions:
        if transition.statute_kind:records[transition.statute_kind]=transition.statute_records
    approved=frozenset(r.asset_id for r in records['ROUTE'] if r.active==1 and r.source_chain_id==pool.generation
        and r.destination_chain_id==pool.generation and r.asset_id==r.remote_asset_id)
    orders=[];inputs=[]
    for buyer in claim.buyers:
        asset=bytes32.from_hexstr(buyer.payment_asset) if buyer.payment_asset else None
        offer=parse_signed_order(buyer.offer)
        order=inspect_buyer_offer(offer,generation=pool.generation,sols_asset=pool.permanent.permanent_rules.sols_tail_hash,
            sols_driver=chia_cat_driver(pool.permanent.permanent_rules.sols_tail_hash),payment_asset=asset,
            destination_inner_hash=bytes32.from_hexstr(buyer.destination),approved_payment_assets=approved)
        verify_order_signature(offer,additional_data=signature_data)
        for coin in external_inputs(offer):inputs.append(await unspent(provider,coin))
        orders.append(order)
    wanted={bytes32.from_hexstr(v) for v in claim.primary_coin_ids};items=[];lineages=[]
    for transition in mh.transitions:
        if transition.edition is None:continue
        for original in transition.before.inventories(transition.edition):
            # Source selection uses the initial coin or a returned available
            # successor. Missing/sold/reserved sources cannot be selected.
            if original.coin.name() not in wanted:continue
            current,lineage,record=await current_inventory(original,provider)
            items.append(current);lineages.append(lineage);inputs.append(record)
    if len(items)!=len(wanted):raise ValueError('PRIMARY_SOURCE_NOT_IN_CONFIRMED_MINT')
    paired=sorted(zip(items,lineages),key=lambda row:claim.primary_coin_ids.index(h(row[0].coin.name())) if h(row[0].coin.name()) in claim.primary_coin_ids else claim.primary_coin_ids.index(h(next(o.coin.name() for t in mh.transitions if t.edition for o in t.before.inventories(t.edition) if o.terms.deed_launcher_id==row[0].terms.deed_launcher_id))))
    items,lineages=tuple(r[0] for r in paired),tuple(r[1] for r in paired)
    inventory=()
    for transition in ph.transitions:
        if transition.inventory is not None:inventory=transition.inventory
    pool.economics.validate(inventory)
    custody=reserve_inner(generation=pool.generation,registry_id=pool.registry_id,pool_id=pool.launcher_id,component_id=pool.component_id)
    reserve_ph=construct_cat_puzzle(CAT_MOD,pool.permanent.permanent_rules.sols_tail_hash,custody).get_tree_hash()
    raw=await provider.get_coin_records_by_puzzle_hash_primary(h(reserve_ph),include_spent=False)
    if len(raw)!=1:raise ValueError('SOLS_RESERVE_NEEDS_REVIEWED_CONSOLIDATION')
    from chia.types.blockchain_format.coin import Coin
    reserve=read_confirmed_coin(raw[0],Coin.from_json_dict(raw[0]['coin']).name())
    if reserve.spent_height or reserve.coin.puzzle_hash!=reserve_ph or reserve.coin.amount!=pool.economics.economics.reserve_sols_mojos:
        raise ValueError('SOLS_RESERVE_BALANCE_CHANGED')
    parent=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(reserve.coin.parent_coin_info)),reserve.coin.parent_coin_info)
    if parent.spent_height!=reserve.confirmed_height:raise ValueError('SOLS_RESERVE_LINEAGE_CHANGED')
    spend=_spend(await provider.get_puzzle_and_solution_primary(h(parent.coin.name()),parent.spent_height),parent.coin)
    mod,args=Program.from_bytes(bytes(spend.puzzle_reveal)).uncurry();values=list(args.as_iter())
    if mod!=CAT_MOD or len(values)!=3 or values[1].as_atom()!=pool.permanent.permanent_rules.sols_tail_hash:raise ValueError('SOLS_RESERVE_ASSET_CHANGED')
    if reserve.coin not in compute_additions_with_cost(spend,max_cost=100_000_000)[0]:raise ValueError('SOLS_RESERVE_PARENT_CHANGED')
    inputs.append(reserve)
    result=build_primary_batches(orders=tuple(orders),inventory_items=items,inventory_lineages=lineages,
        pool=pool,pool_tip=ph.verified_tip(pool.launcher_id,pool.inner()),statutes=statute,
        statutes_tip=sh.verified_tip(statute.launcher_id,statute.inner()),registry=registry,
        registry_tip=evidence.registry.verified_tip(registry.launcher_id,registry.inner()),sgt_bindings=anchor.issuance.bindings(),
        collections=records['COLLECTION'],oracles=records['ORACLE'],routes=records['ROUTE'],inventory=inventory,
        reserve_coin=reserve.coin,reserve_lineage=LineageProof(parent.coin.parent_coin_info,values[2].get_tree_hash(),parent.coin.amount),
        decimals=price.round.asset_decimals,expires_at=claim.expires_at,signer_indices=claim.signer_indices,signed_price=price)
    if not await current_evidence_unchanged(evidence,provider=provider):raise ValueError('BATCH_AUTHORITIES_CHANGED')
    for record in inputs:
        if await unspent(provider,record.coin)!=record:raise ValueError('BATCH_INPUT_CHANGED')
    if int(clock())>=claim.expires_at:raise ValueError('BATCH_PRICE_REVIEW_EXPIRED')
    return result,evidence


def delivery_messages(settlement,*,additional_data=TESTNET11_SIGNATURE_DATA):
    """Read only the independently rebuilt sources' exact BLS conditions."""
    from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
    messages={0:[],1:[],2:[]}
    for spend in settlement.primary_spends:
        from chia.types.condition_opcodes import ConditionOpcode
        all_conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
        conditions={ConditionOpcode.AGG_SIG_ME:all_conditions.get(ConditionOpcode.AGG_SIG_ME,[])}
        inner=list(Program.from_bytes(bytes(spend.puzzle_reveal)).uncurry()[1].as_iter())[1]
        fields=list(inner.uncurry()[1].as_iter());validators=tuple(v.as_atom() for v in fields[21].as_iter())
        # Native inventory curry validator roster is at immutable args 21.
        for key,message in pkm_pairs_for_conditions_dict(conditions,spend.coin,additional_data):
            for i,public in enumerate(validators):
                if bytes(key)==public:messages[i].append(message)
    return messages
