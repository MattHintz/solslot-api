"""Assembly reuses only verified native evidence, never a coordinator assertion."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import pytest
from chia_rs.sized_bytes import bytes32
from solslot_api.generation_holder_ballots import assemble_holder_ballot
from solslot_api.generation_index import GenerationIndexReconciler
from solslot_api.generation_mint_checks import checked_mint_chain_cache


@pytest.mark.asyncio
async def test_unverified_foreign_stale_or_replaced_cache_cannot_supply_authority(monkeypatch):
    gen=bytes32(b'g'*32);anchor=SimpleNamespace(issuance=SimpleNamespace(generation=gen));provider=object()
    evidence=SimpleNamespace(registry=SimpleNamespace(state=SimpleNamespace(generation=gen)))
    state={'status':'READY','network':'testnet11','generationId':'0x'+gen.hex()}
    index=GenerationIndexReconciler(anchor,SimpleNamespace(status=Mock(return_value=state)),provider)
    index.evidence=evidence;index.verified=True
    check=AsyncMock(return_value=True)
    monkeypatch.setattr('solslot_api.generation_mint_checks.current_evidence_unchanged',check)
    assert await checked_mint_chain_cache(anchor,provider=provider,index=index) is evidence
    assert await checked_mint_chain_cache(anchor,provider=provider,index=SimpleNamespace(**index.__dict__)) is None
    for field,bad in [('verified',False),('provider',object()),('anchor',object()),('evidence',None)]:
        with monkeypatch.context() as p:
            p.setattr(index,field,bad)
            assert await checked_mint_chain_cache(anchor,provider=provider,index=index) is None
    for bad in [{'status':'RECONCILING'},{'generationId':'0x'+'ff'*32},{'network':'mainnet'}]:
        index.store.status.return_value={**state,**bad}
        assert await checked_mint_chain_cache(anchor,provider=provider,index=index) is None
    index.store.status.return_value=state
    check.return_value=False
    assert await checked_mint_chain_cache(anchor,provider=provider,index=index) is None
    async def replace_during_primary(*args,**kwargs):index.evidence=object();return True
    check.side_effect=replace_during_primary
    assert await checked_mint_chain_cache(anchor,provider=provider,index=index) is None


@pytest.mark.asyncio
async def test_assembly_timeout_is_bounded_before_gateway_without_saving(monkeypatch):
    gen='0x'+'11'*32
    req={'generationId':gen,'requestKey':'timeout','kind':'OPEN_PROPOSAL','proposalId':'0x'+'12'*32,
        'consentPackageId':'0x'+'13'*32,'expectedInputs':{k:'0x'+'14'*32 for k in ('registry','governance','holdings')},
        'feeCapMojos':1000,'selected':[{'coinId':'0x'+'15'*32,'vaultLauncherId':'0x'+'16'*32}]}
    doc={'request':req,'review':{'selectedWeight':10000,'snapshotRoot':'0x'+'17'*32,'eligibleSupply':30000,'requiredVotes':15000,'votingClosesAt':None}}
    store=SimpleNamespace(generation_id=gen,document=Mock(return_value=doc),status=Mock(return_value={'stage':'READY'}))
    journal=SimpleNamespace(generation_id=gen,reviewed_request=Mock(return_value=None),prepare=Mock())
    anchor=SimpleNamespace(issuance=SimpleNamespace(generation=bytes32.from_hexstr(gen)))
    async def blocked(*a,**k):await asyncio.Future()
    monkeypatch.setattr('solslot_api.generation_holder_ballots.ballot_inputs_unchanged',blocked)
    original=asyncio.timeout;limits=[]
    def deadline(seconds):limits.append(seconds);return original(.001)
    monkeypatch.setattr('solslot_api.generation_holder_ballots.asyncio.timeout',deadline)
    with pytest.raises(TimeoutError):
        await assemble_holder_ballot('0x'+'18'*32,anchor=anchor,provider=object(),store=store,consents=None,journal=journal)
    assert limits==[40];journal.prepare.assert_not_called()
