"""Sealed native batch -> exact admin consent -> holder sponsorship -> vote.

Only synthetic simulator records and test signing keys are used. There is no
mint dispatch endpoint and no claim that simulated time is live acceptance.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
import json
import os

import pytest
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api.generation_consents import ConsentRequest, GenerationConsentStore, prepare_consent, sign_consent
from solslot_api.generation_holder_ballots import GenerationBallotStore, prepare_holder_ballot, assemble_holder_ballot
from solslot_api.generation_holder_evidence import preparation_custody_anchors
from solslot_api.generation_mint_reviews import prepare_mint_review, reviewed_mint_edition, h
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_puzzles.generation_transactions import anchor_vote, finalize_vote
from tests.test_generation_genesis_core import core
from tests.test_generation_mint_reviews import context
from tests.test_generation_holder_ballots import request as holder_request, sign_all


def publication(ctx, source, key='mint-publication', **changes):
    return ConsentRequest.model_validate({'generationId':source['generationId'], 'requestKey':key,
        'kind':'PUBLICATION_APPROVAL', 'proposalKind':'MINT_TEST_ONLY', 'mintReviewId':source['packageId'],
        'coadministratorSlot':1, 'feeCapMojos':1000,
        'expectedInputs':{**{name:h(getattr(ctx.chain,name).current.coin.name()) for name in ('registry','governance','holdings')},
            'components':{source['mintAuthority']['componentId']:source['mintAuthority']['coinId']}}, **changes})


def consent_kwargs(ctx,c,store,now):
    return dict(anchor=ctx.kwargs['anchor'], provider=c.provider, store=store, clock=lambda:now,
        settings=ctx.settings, collections=ctx.collections, mint_reviews=ctx.store)


@pytest.mark.asyncio
async def test_exact_native_mint_publication_and_holder_vote_preserve_the_source(core,tmp_path):
    c=core;ctx=await context(c,tmp_path);now=int(c.sim.timestamp)-1
    source=await prepare_mint_review(ctx.request,**{**ctx.kwargs,'clock':lambda:now})
    original=reviewed_mint_edition(source)
    consents=GenerationConsentStore(tmp_path/'consents.db',c.prep.generation_id)
    req=publication(ctx,source)
    review=await prepare_consent(req,**consent_kwargs(ctx,c,consents,now))
    assert review['proposal']['kind']=='MINT_TEST_ONLY' and review['proposal']['testMint']['deedCount']==25
    assert review['billHash']==source['billHash'] and review['mintSource']==source
    assert review['expiresAt']==now+86400 and review['requiredVotes']==15000
    assert req.document()['mintReviewId']==source['packageId']
    if target:=os.environ.get('GENERATION_MINT_CONSENT_VECTOR'):
        Path(target).write_text(json.dumps(review,indent=2)+'\n')
    original_holds=ctx.store.reserved_input_coin_ids()
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('cached retry cannot touch node')))
    assert await prepare_consent(req,**{**consent_kwargs(ctx,c,consents,now+10),'provider':offline,
        'settings':None,'collections':None,'mint_reviews':None})==review
    for ch in review['challenges']:
        sig=keys.PrivateKey(bytes([ch['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
        signed=await sign_consent(review['packageId'],ch['slot'],sig,anchor=ctx.kwargs['anchor'],
            provider=c.provider,store=consents,clock=lambda:now)
    assert signed['stage']=='READY'
    ballots=GenerationBallotStore(tmp_path/'ballots.db',c.prep.generation_id)
    journal=GenerationOperationJournal(tmp_path/'operations.db',c.prep.generation_id)
    ballot=await prepare_holder_ballot(holder_request(c,ctx.chain,review['proposalId'],[1,2],consent_id=review['packageId']),
        anchor=ctx.kwargs['anchor'],custodies=preparation_custody_anchors(c.prep),provider=c.provider,
        store=ballots,consents=consents,clock=lambda:now)
    assert ballot['proposal']==review['proposal'] and ballot['selectedWeight']==20000
    await sign_all(c,ballot,ballots,now)
    operation=await assemble_holder_ballot(ballot['packageId'],anchor=ctx.kwargs['anchor'],provider=c.provider,
        store=ballots,consents=consents,journal=journal,clock=lambda:now)
    assert operation['kind']=='OPEN_PROPOSAL' and operation['transactionId'] is None
    assert await c.client.push_tx(journal.protocol_bundle(operation['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider)
    gov,reg=chain.governance.state,chain.registry.state
    assert gov.active.bill==original.bill() and gov.active.yes_weight==20000 and gov.active.required_votes==15000
    clock=await c.client.get_coin_record_by_name(gov.active.clock_id)
    anchored,_=anchor_vote(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()),clock.coin,int(clock.timestamp))
    assert await c.client.push_tx(anchored.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider)
    gov,reg=chain.governance.state,chain.registry.state
    finalized,_=finalize_vote(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()))
    assert (await c.client.push_tx(finalized.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    c.sim.pass_time(uint64(3600));await c.sim.farm_block()
    assert await c.client.push_tx(finalized.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    chain=await resolve_generation_chain(ctx.kwargs['anchor'],provider=c.provider)
    gov=chain.governance.state
    assert gov.active is None and bytes32.from_hexstr(review['proposalId']) in gov.closed.keys
    assert gov.action_key(bytes32.from_hexstr(review['proposalId']),original.bill()) in gov.approved.keys
    ctx.chain=chain
    with pytest.raises(ValueError,match='approved test edition awaits execution'):
        await prepare_consent(publication(ctx,source,key='duplicate-approved-mint'),**consent_kwargs(ctx,c,consents,int(c.sim.timestamp)-1))
    assert ctx.store.status(source['packageId'])==source and ctx.store.reserved_input_coin_ids()==original_holds
    for parent in original_holds:assert not (await c.client.get_coin_record_by_name(bytes32.from_hexstr(parent))).spent
    ctx.collections.close()


@pytest.mark.asyncio
async def test_mint_consent_rejects_substitution_stale_authority_and_spent_parents(core,tmp_path):
    c=core;ctx=await context(c,tmp_path);now=int(c.sim.timestamp)-1
    source=await prepare_mint_review(ctx.request,**{**ctx.kwargs,'clock':lambda:now})
    consents=GenerationConsentStore(tmp_path/'consents.db',c.prep.generation_id)
    req=publication(ctx,source)
    kwargs=consent_kwargs(ctx,c,consents,now)
    for bad in ({'mintReviewId':None},{'proposalKind':'UPGRADE'}, {'editionProgram':source['editionProgram']},
                {'scope':2},{'upgrade':{'sourceManifestHash':'0x'+'99'*32}}):
        with pytest.raises(ValueError):publication(ctx,source,**bad)
    with pytest.raises(ValueError):await prepare_consent(publication(ctx,source,mintReviewId='0x'+'99'*32),**kwargs)
    with pytest.raises(ValueError):await prepare_consent(publication(ctx,source,mintReviewId='0x'+'00'*32),**kwargs)
    changed=deepcopy(req.document());changed['expectedInputs']['components'][source['mintAuthority']['componentId']]='0x'+'99'*32
    with pytest.raises(ValueError,match='authority input changed'):
        await prepare_consent(ConsentRequest.model_validate(changed),**kwargs)
    with pytest.raises(ValueError,match='not configured'):
        await prepare_consent(req,**{**kwargs,'mint_reviews':None})
    for field in ('editionHash','billHash','collectionCommitment'):
        altered=deepcopy(source);altered[field]='0x'+'99'*32
        with pytest.raises(ValueError,match='source package changed'):reviewed_mint_edition(altered)
    assert consents.recent(now)==[]
    review=await prepare_consent(req,**kwargs)
    # Primary admission changing after review must stop even a valid signature.
    original=c.provider.get_coin_record_by_name_primary;target=source['funding'][0]['coinId']
    async def spent(identity):
        raw=deepcopy(await original(identity))
        if identity==target:raw['spent']=True;raw['spent_block_index']=raw['confirmed_block_index']+1
        return raw
    c.provider.get_coin_record_by_name_primary=spent
    ch=review['challenges'][0]
    sig=keys.PrivateKey(bytes([1])*32).sign_msg_hash(bytes32.from_hexstr(ch['digest'])).to_bytes()
    with pytest.raises(ValueError,match='input changed'):
        await sign_consent(review['packageId'],0,sig,anchor=ctx.kwargs['anchor'],provider=c.provider,store=consents,clock=lambda:now)
    assert consents.status(review['packageId'],now)['signatures']==[]
    with pytest.raises(ValueError,match='funding'):
        await prepare_consent(publication(ctx,source,key='spent-parent'),**kwargs)
    ctx.collections.close()
