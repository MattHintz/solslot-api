"""Exact voted-source execution and read-only confirmation evidence."""
import asyncio
from hashlib import sha256
import time

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from pydantic import Field

from .generation_execution import Model, Hash, ExpectedInputs
from .generation_operations import canonical
from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged, public_bill
from .generation_coin_evidence import read_confirmed_coin
from .generation_mint_reviews import h, revalidate_mint_review, reviewed_mint_edition
from .generation_mint_checks import checked_mint_chain_cache


def mint_request_key(identity):return 'mint:'+identity


class MintExecutionRequest(Model):
    generation_id:Hash=Field(alias='generationId')
    source_review_id:Hash=Field(alias='sourceReviewId')
    proposal_id:Hash=Field(alias='proposalId')
    expected_inputs:ExpectedInputs=Field(alias='expectedInputs')
    fee_cap_mojos:int=Field(alias='feeCapMojos',strict=True,ge=0,le=1_000_000_000)

    def document(self,source):
        edition=reviewed_mint_edition(source)
        return {**self.model_dump(mode='json',by_alias=True),'kind':'MINT_COLLECTION',
            'requestKey':mint_request_key(self.source_review_id),'collectionId':source['request']['collectionId'],'mintBill':public_bill(edition.bill()),
            'metadataRoot':source['request']['metadataRoot'],'previewHash':source['request']['previewHash'],
            'funding':[{key:r[key] for key in ('coinId','launcherId','inventoryCoinId')} for r in source['funding']]}


async def prepare_mint_execution(body, *, settings, collections, reviews, journal, anchor, provider,
                                 faucet, funding_guard, clock=time.time, index=None):
    body=MintExecutionRequest.model_validate_json(body.model_dump_json(by_alias=True))
    if (settings.network!='testnet11' or body.generation_id!=settings.deployment_generation_id
            or body.generation_id!=reviews.generation_id or body.generation_id!=journal.generation_id
            or bytes32.from_hexstr(body.generation_id)!=anchor.issuance.generation):
        raise ValueError('mint execution belongs to another generation')
    key=mint_request_key(body.source_review_id)
    source=reviews.status(body.source_review_id);document=body.document(source)
    digest=h(sha256(canonical(document).encode()).digest())
    saved=journal.reviewed_request(key,digest)
    if saved:
        reviews.record_execution(body.source_review_id,saved['operationId'])
        return saved  # Recover even after the input is spent, without a signer.
    async with asyncio.timeout(50), funding_guard:
        saved=journal.reviewed_request(key,digest)
        if saved:
            reviews.record_execution(body.source_review_id,saved['operationId']);return saved
        chain=await checked_mint_chain_cache(anchor,provider=provider,index=index)
        if chain is None:chain=await resolve_generation_chain(anchor,provider=provider)
        for name in ('registry','governance','holdings'):
            if h(getattr(chain,name).current.coin.name())!=getattr(body.expected_inputs,name):
                raise ValueError('confirmed mint inputs changed')
        review,edition,_=await revalidate_mint_review(body.source_review_id,settings=settings,
            collections=collections,store=reviews,chain=chain,provider=provider,publication=False)
        expected={review['mintAuthority']['componentId']:review['mintAuthority']['coinId']}
        if body.expected_inputs.components!=expected:raise ValueError('exact mint authority must be reviewed')
        gov=chain.governance.state;proposal=bytes32.from_hexstr(body.proposal_id)
        if gov.active or gov.action_key(proposal,edition.bill()) not in gov.approved.keys:
            raise ValueError('mint requires its exact confirmed, closed holder approval')
        if not await current_evidence_unchanged(chain,provider=provider):raise ValueError('mint inputs changed during preparation')
        # Recheck source and parents after the final external await. No new
        # transaction or fee input is selected by this revalidation.
        final,_,_=await revalidate_mint_review(body.source_review_id,settings=settings,
            collections=collections,store=reviews,chain=chain,provider=provider,publication=False)
        if final!=review:raise ValueError('saved mint source changed')
        if not await current_evidence_unchanged(chain,provider=provider):raise ValueError('mint inputs changed before signing')
        operation=faucet.sign_generation_mint(body.source_review_id,chain=chain,proposal=proposal)
        if body.document(review)!=document:raise ValueError('saved source differs from the reviewed execution')
        identity=journal.prepare(operation,key,body.fee_cap_mojos,int(clock()),request_digest=digest,request_document=document)
        # Separate databases may crash between these two durable writes. An
        # exact retry recovers the journal first and repairs only this link.
        reviews.record_execution(body.source_review_id,identity)
        return journal.status(identity)


async def verify_mint_inventory(source, operation, bundle, *, provider, clock=time.time):
    """Prove initial issuance from saved bytes; never construct or submit."""
    edition=reviewed_mint_edition(source)
    if (operation['stage']!='CONFIRMED' or operation['kind']!='MINT_COLLECTION'
            or operation['generationId']!=source['generationId']
            or operation['review']['sourceReviewId']!=source['packageId']):raise ValueError('inventory requires its exact confirmed operation')
    raw={k:v for k,v in operation['review'].items() if k not in ('kind','requestKey','collectionId','mintBill','metadataRoot','previewHash','funding')}
    if MintExecutionRequest.model_validate(raw).document(source)!=operation['review']:
        raise ValueError('mint operation differs from its immutable source')
    height=operation['confirmedHeight'];spends={h(s.coin.name()):s for s in bundle.coin_spends};rows=[]
    if (await provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('inventory proof requires primary Testnet11')
    for row in source['funding']:
        spend=spends.get(row['launcherId'])
        if spend is None:raise ValueError('saved mint lacks its exact launcher')
        additions,_=compute_additions_with_cost(spend,max_cost=100_000_000)
        if len(additions)!=1 or h(additions[0].name())!=row['inventoryCoinId'] or additions[0].amount!=1:
            raise ValueError('saved launcher does not create the exact inventory')
        inventory=additions[0]
        launch=read_confirmed_coin(await provider.get_coin_record_by_name_primary(row['launcherId']),spend.coin.name())
        actual=read_confirmed_coin(await provider.get_coin_record_by_name_primary(row['inventoryCoinId']),inventory.name())
        if launch.coin!=spend.coin or launch.confirmed_height!=height or launch.spent_height!=height or actual.coin!=inventory or actual.confirmed_height!=height:
            raise ValueError('initial inventory lacks same-block confirmed issuance')
        observed=await provider.get_puzzle_and_solution_primary(row['launcherId'],height)
        from .generation_registry_evidence import _spend
        if bytes(_spend(observed,spend.coin))!=bytes(spend):raise ValueError('confirmed launcher differs from saved bytes')
        rows.append({'launcherId':row['launcherId'],'coinId':row['inventoryCoinId'],'coin':inventory.to_json_dict()})
    return {'schemaVersion':1,'generationId':source['generationId'],'network':'testnet11','purpose':'TEST_ONLY',
        'sourceReviewId':source['packageId'],'operationId':operation['operationId'],'transactionId':operation['transactionId'],
        'confirmedHeight':height,'observedAt':int(clock()),'metadataRoot':h(edition.metadata_root),
        'editionHash':h(edition.commitment),'deedCount':len(rows),'inventory':rows}


class GenerationMintObserver:
    """Observe saved operations and exact inventory; has no faucet/submitter."""
    def __init__(self,store,journal,provider,*,clock=time.time):
        self.store,self.journal,self.provider,self.clock=store,journal,provider,clock

    async def run_once(self):
        active=False
        for identity,operation_id in self.store.pending_inventory_checks():
            now=int(self.clock())
            try:
                operation=self.journal.status(operation_id)
                if operation['stage']!='CONFIRMED':
                    self.store.inventory_check(identity,now,None)
                    active=active or bool(operation['transactionId']);continue
                active=True
                async with asyncio.timeout(30):
                    source=self.store.status(identity)
                    receipt=await verify_mint_inventory(source,operation,self.journal.protocol_bundle(operation_id),provider=self.provider,clock=self.clock)
                self.store.record_inventory_confirmation(identity,receipt)
            except (ValueError,KeyError,TypeError):self.store.inventory_check(identity,now,'MINT_INVENTORY_NOT_CONFIRMED')
            except (OSError,TimeoutError,RuntimeError):self.store.inventory_check(identity,now,'PRIMARY_NODE_UNAVAILABLE')
        return active
