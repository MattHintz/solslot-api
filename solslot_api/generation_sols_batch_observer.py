"""Cached catalogue and receipt reconciliation; this worker cannot submit."""
import asyncio
import time
import logging
import sqlite3
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_statutes import GenerationStatutes,RECORDS
from .generation_sols_batch_execution import current_inventory,h
from .payment_quotes import load_authorized_oracle_round
from chia_rs.sized_bytes import bytes32
logger=logging.getLogger(__name__)


class GenerationSolsBatchObserver:
    def __init__(self,book,index,journal,provider,settings,*,clock=time.time):
        self.book,self.index,self.journal,self.provider,self.settings,self.clock=book,index,journal,provider,settings,clock
        self.cursor=0

    async def run_once(self):
        now=int(self.clock());active=False
        self.book.repair_saved_links(self.journal)
        from .protocol_admission import primary_admission_state
        height,_,_,chain_time=primary_admission_state(await self.provider.get_fee_estimate(target_times=[30],cost=1_000_000,require_primary=True))
        self.book.reconcile_timelocks(height=height,chain_time=chain_time,now=now)
        # Bound work and rotate across every retained waiting or pending order.
        with self.book.db() as db:
            ids=[row[0] for row in db.execute("SELECT order_id FROM sols_orders WHERE stage NOT IN ('FILLED','REMOVED_FROM_MATCHING','EXPIRED','INPUT_SPENT') ORDER BY order_id")]
        selected=(ids[self.cursor:self.cursor+32] if self.cursor<len(ids) else ids[:32])
        self.cursor=(self.cursor+len(selected))%len(ids) if ids else 0
        for identity in selected:
            try:
                async with asyncio.timeout(8):
                    result=await self.book.check_inputs(identity,provider=self.provider,journal=self.journal,now=now)
                    active=active or bool(result['operationId'] and result['stage']!='FILLED')
            except (ValueError,KeyError,TypeError,OSError,RuntimeError,TimeoutError):
                # Keep the saved stage. An unavailable read is not cancellation
                # or permission to replace a retained transaction.
                continue
        evidence=self.index.evidence if self.index.verified else None
        if evidence is None:
            self.book.save_catalog({'generationId':self.book.generation_id,'ready':False,'lastCheckedAt':now,
                'errorCode':'GENERATION_CHAIN_NOT_READY','inventory':[]});return active
        pools=[history for history in evidence.economic_components.values() if isinstance(history.state,GenerationPool)]
        statutes=[history for history in evidence.economic_components.values() if isinstance(history.state,GenerationStatutes)]
        mints=[history for history in evidence.economic_components.values() if isinstance(history.state,GenerationMint)]
        if len(pools)!=1 or len(statutes)!=1 or len(mints)!=1:raise ValueError('batch economic bindings incomplete')
        records={kind:() for kind in RECORDS}
        for transition in statutes[0].transitions:
            if transition.statute_kind:records[transition.statute_kind]=transition.statute_records
        rows=[];first_source=None
        for transition in mints[0].transitions:
            if transition.edition is None:continue
            for original in transition.before.inventories(transition.edition):
                if len(rows)>=100:break
                try:
                    current,_,_=await current_inventory(original,self.provider)
                    if first_source is None:first_source=current
                    terms=current.terms
                    rows.append({'inventoryId':h(original.coin.name()),'currentCoinId':h(current.coin.name()),
                        'deedLauncherId':h(terms.deed_launcher_id),'collectionId':h(terms.collection_id),
                        'baseUsdMinor':str(terms.base_amount_minor),'subtotalUsdMinor':str(terms.subtotal_minor)})
                except ValueError:continue
        price=None;error=None
        try:
            value=load_authorized_oracle_round(self.settings,asset_id=bytes32.zeros,now=now)
            # The native source checks its frozen roster again at preparation.
            raw=value.public_evidence();raw['signatures']=raw['signatures'][:2];price=raw
            if first_source is not None:
                from .generation_sols_batch_execution import signed_price
                from chia.types.blockchain_format.program import Program
                bindings=list(first_source.inner.uncurry()[1].as_iter())[-1]
                keys=tuple(v.as_atom() for v in bindings.at('rrrrrrrf').as_iter())
                signed_price(raw).verify(keys,asset=bytes32.zeros,decimals=12,
                    expires_at=value.round.valid_until,maximum_age=statutes[0].state.values[1])
        except (ValueError,OSError,RuntimeError):price=None;error='SOLS_LIVE_PRICE_UNAVAILABLE'
        reg=evidence.registry
        from .generation_sols_policy import current_fee_policy,REVIEWED_FEES
        fees=current_fee_policy(statutes[0].state.values)
        if fees!=REVIEWED_FEES:error='SOLS_FEE_POLICY_REVIEW_REQUIRED'
        matches=[]
        if price and not error:
            from .generation_sols_matching import suggest_matches
            matches=suggest_matches(self.book.waiting(512),rows,price,limit=1)
        self.book.save_catalog({'generationId':self.book.generation_id,'ready':bool(rows and price and not error and not reg.state.pause_mask&12),
            'feePolicy':fees,
            'lastCheckedAt':now,'errorCode':error,'inventory':rows,'signedPrice':price,'suggestedMatches':matches,
            'anchorHash':self.settings.generation_chain_anchor_hash,'registryCoinId':h(reg.current.coin.name()),
            'poolCoinId':h(pools[0].current.coin.name()),'statutesCoinId':h(statutes[0].current.coin.name()),
            'approvedPaymentAssets':[{'assetId':h(r.asset_id),'decimals':r.decimals} for r in records['ROUTE']
                if r.active==1 and r.source_chain_id==r.destination_chain_id==pools[0].state.generation
                and r.asset_id==r.remote_asset_id and r.asset_id in self.book.approved_assets]})
        return active

    async def run(self):
        while True:
            interval=30
            try:
                async with asyncio.timeout(60):interval=5 if await self.run_once() else 30
            except (ValueError,KeyError,TypeError,OSError,RuntimeError,TimeoutError,sqlite3.Error) as exc:
                logger.warning('Sols batch observer unavailable (%s)',type(exc).__name__)
                try:
                    self.book.save_catalog({'generationId':self.book.generation_id,'ready':False,
                        'lastCheckedAt':int(self.clock()),'errorCode':'SOLS_CATALOG_RECONCILING','inventory':[]})
                except (ValueError,OSError,RuntimeError,sqlite3.Error):
                    logger.warning('Sols batch observation journal unavailable')
            await asyncio.sleep(interval)
