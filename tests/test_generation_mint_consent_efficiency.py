"""Native mint consent keeps all authority checks without replaying proven history."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock

import pytest
from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from eth_keys import keys

from solslot_api import generation_consents as consents
from solslot_api.generation_admission import GenerationAdmission
from solslot_api.generation_index import GenerationIndexReconciler,GenerationIndexStore
from solslot_api.generation_mint_checks import checked_mint_administrators
from solslot_api.generation_consent_routes import _failure
from tests.test_generation_genesis_core import core
from tests.test_generation_mint_reviews import context
from tests.test_generation_mint_publication import publication,consent_kwargs


async def native_context(c,tmp_path):
    ctx=await context(c,tmp_path)
    admission=GenerationAdmission(ctx.settings,ctx.kwargs['anchor'],c.provider)
    await admission.refresh()
    index=GenerationIndexReconciler(ctx.kwargs['anchor'],GenerationIndexStore(tmp_path/'index.db',c.prep.generation_id,'0x'+'11'*32),c.provider)
    await index.run_once();assert index.verified
    return ctx,admission,index


@pytest.mark.asyncio
async def test_native_cached_authority_prepares_and_both_real_signatures_remain_required(core,tmp_path,monkeypatch):
    c=core;ctx,admission,index=await native_context(c,tmp_path);now=int(c.sim.timestamp)-1
    from solslot_api.generation_mint_reviews import prepare_mint_review
    source=await prepare_mint_review(ctx.request,**ctx.kwargs,index=index)
    store=consents.GenerationConsentStore(tmp_path/'consents.db',c.prep.generation_id)
    async def forbidden(*a,**k):raise AssertionError('fresh native authority must not replay history')
    monkeypatch.setattr(consents,'resolve_generation_administrators',forbidden)
    result=await consents.prepare_consent(publication(ctx,source),**consent_kwargs(ctx,c,store,now),index=index,admission=admission)
    assert result['billHash']==source['billHash'] and result['mintSource']==source
    assert result['expiresAt']-result['createdAt']==86400 and result['requiredVotes']==15000
    for challenge in result['challenges']:
        signature=keys.PrivateKey(bytes([challenge['slot']+1])*32).sign_msg_hash(bytes32.from_hexstr(challenge['digest'])).to_bytes()
        signed=await consents.sign_consent(result['packageId'],challenge['slot'],signature,
            anchor=ctx.kwargs['anchor'],provider=c.provider,store=store,clock=lambda:now)
        assert signed['stage']==('READY' if len(signed['signatures'])==2 else 'AWAITING_APPROVALS')
    assert len(ctx.store.reserved_input_coin_ids())==25
    offline=SimpleNamespace(get_network_info_primary=AsyncMock(side_effect=AssertionError('saved retry must remain offline')))
    recovered=await consents.prepare_consent(publication(ctx,source),**{**consent_kwargs(ctx,c,store,now),'provider':offline})
    assert recovered==signed
    ctx.collections.close()


@pytest.mark.asyncio
async def test_only_fresh_same_generation_native_admission_can_supply_proof(core,tmp_path,monkeypatch):
    c=core;ctx,admission,index=await native_context(c,tmp_path);anchor=ctx.kwargs['anchor']
    async def checked(value=admission,**kw):
        return await checked_mint_administrators(anchor,settings=ctx.settings,provider=c.provider,admission=value,**kw)
    assert await checked() is admission.evidence
    # The index and admission may load structurally equal anchors separately.
    assert await checked_mint_administrators(replace(anchor),settings=ctx.settings,provider=c.provider,admission=admission) is admission.evidence
    # The five-second observer may refresh its receipt during this request.
    # That is safe only while the native proof and exact roster stay the same.
    with monkeypatch.context() as p:
        original=c.provider.get_network_info_primary
        async def refreshed():
            value=await original()
            p.setattr(admission,'snapshot',replace(admission.snapshot,checked=admission.clock()))
            return value
        p.setattr(c.provider,'get_network_info_primary',refreshed)
        assert await checked() is admission.evidence
    with monkeypatch.context() as p:
        original=c.provider.get_network_info_primary
        async def different_roster():
            value=await original()
            p.setattr(admission,'snapshot',replace(admission.snapshot,slots=()))
            return value
        p.setattr(c.provider,'get_network_info_primary',different_roster)
        assert await checked() is None
    assert await checked(SimpleNamespace(snapshot=admission.snapshot,evidence=admission.evidence)) is None
    with monkeypatch.context() as p:
        p.setattr(admission,'clock',lambda:admission.snapshot.checked+30)
        assert await checked() is None
    with monkeypatch.context() as p:
        p.setattr(admission,'provider',object());assert await checked() is None
    with monkeypatch.context() as p:
        p.setattr(admission,'anchor',object());assert await checked() is None
    with monkeypatch.context() as p:
        p.setattr(admission,'snapshot',None);assert await checked() is None
    with monkeypatch.context() as p:
        p.setattr(c.provider,'get_network_info_primary',AsyncMock(side_effect=OSError('synthetic primary unavailable')))
        with pytest.raises(OSError):await checked()
    with monkeypatch.context() as p:
        original=c.provider.get_coin_record_by_name_primary
        async def changed(identity):
            value=dict(await original(identity));value['spent']=True;value['spent_block_index']=int(c.sim.block_height)+1
            return value
        p.setattr(c.provider,'get_coin_record_by_name_primary',changed)
        assert await checked() is None
    ctx.collections.close()


@pytest.mark.asyncio
async def test_mint_input_rechecks_keep_every_record_with_at_most_five_primary_reads():
    records=[]
    for i in range(205):
        coin=Coin(bytes32(i.to_bytes(32,'big')),bytes32(b'p'*32),1)
        records.append({'coin':coin.to_json_dict(),'confirmed_block_index':1,'spent_block_index':0,'spent':False})
    catalog={'0x'+Coin.from_json_dict(r['coin']).name().hex():r for r in records};active=0;peak=0;seen=[]
    async def read(identity):
        nonlocal active,peak
        active+=1;peak=max(peak,active)
        try:await asyncio.sleep(0);seen.append(identity);return catalog[identity]
        finally:active-=1
    provider=SimpleNamespace(get_network_info_primary=AsyncMock(return_value={'network_name':'testnet11'}),get_coin_record_by_name_primary=read)
    document={'request':{'proposalKind':'MINT_TEST_ONLY'},'confirmedInputs':records+[records[0]]}
    await consents.consent_inputs_unchanged(document,provider)
    assert len(seen)==205 and len(set(seen))==205 and 1<peak<=5 and active==0
    catalog[next(iter(catalog))]={**records[0],'spent':True,'spent_block_index':2}
    with pytest.raises(ValueError,match='reviewed input changed'):await consents.consent_inputs_unchanged(document,provider)
    async def unavailable(identity):raise OSError('synthetic primary unavailable')
    provider.get_coin_record_by_name_primary=unavailable
    with pytest.raises(OSError):await consents.consent_inputs_unchanged(document,provider)


@pytest.mark.asyncio
async def test_mint_deadline_is_typed_before_the_actual_45_second_gateway(monkeypatch):
    generation='0x'+'11'*32
    request=consents.ConsentRequest.model_validate({'generationId':generation,'requestKey':'timeout','kind':'PUBLICATION_APPROVAL',
        'proposalKind':'MINT_TEST_ONLY','mintReviewId':'0x'+'22'*32,'coadministratorSlot':1,'feeCapMojos':1000,
        'expectedInputs':{**{k:'0x'+'33'*32 for k in ('registry','governance','holdings')},'components':{'0x'+'44'*32:'0x'+'55'*32}}})
    store=SimpleNamespace(generation_id=generation,reviewed_request=Mock(return_value=None),save=Mock())
    anchor=SimpleNamespace(issuance=SimpleNamespace(generation=bytes32.from_hexstr(generation)),administrator=object())
    async def blocked(*a,**k):await asyncio.Future()
    monkeypatch.setattr(consents,'checked_mint_chain_cache',blocked)
    original=asyncio.timeout;limits=[]
    def deadline(seconds):limits.append(seconds);return original(.001)
    monkeypatch.setattr(consents.asyncio,'timeout',deadline)
    with pytest.raises(consents.MintConsentTimeout) as error:
        await consents.prepare_consent(request,anchor=anchor,provider=object(),store=store)
    assert limits==[40] and error.value.stage=='VERIFYING_CHAIN';store.save.assert_not_called()
    result=_failure(error.value)
    assert result.status_code==503 and result.detail['stage']=='VERIFYING_CHAIN' and result.headers=={'Retry-After':'5'}
