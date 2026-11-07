"""Demand-mode collection reuses exact verified rounds and bounded inputs."""
import argparse,asyncio,io,json,sys
from dataclasses import replace
from datetime import datetime,timezone
from pathlib import Path
import pytest
from solslot_api import xch_price_feed_runner as runner
from solslot_api.xch_price_feed import PriceFeedError,publish_snapshot
from tests.test_xch_price_feed import NOW,authorized,evidence,settings


@pytest.fixture
def demand(tmp_path,monkeypatch):
    pubkeys,signed=authorized();config=settings(tmp_path,pubkeys)
    roster={'schema':'solslot.xch-price-roster.v1','network':'testnet11',
        'operatorPubkeys':config.payment_oracle_operator_pubkeys}
    policy,usage=tmp_path/'policy.json',tmp_path/'usage.json'
    policy.write_text(json.dumps({'schema':'solslot.xch-price-test-window.v1','network':'testnet11','notBefore':NOW-1,'expiresAt':NOW+3600}))
    usage.write_text(json.dumps({'month':datetime.fromtimestamp(NOW,timezone.utc).strftime('%Y-%m'),'calls':2}))
    args=argparse.Namespace(roster=tmp_path/'roster',snapshot=Path(config.payment_oracle_rounds_path),
        usage_state=usage,policy=policy,attestors=tmp_path/'attestors')
    monkeypatch.setattr(runner,'read_roster',lambda p:(roster,pubkeys))
    monkeypatch.setattr(runner,'_check_config_owner',lambda p:None)
    monkeypatch.setattr(runner.time,'time',lambda:NOW)
    return config,signed,args


@pytest.mark.asyncio
async def test_current_signed_round_avoids_another_provider_call(demand,monkeypatch):
    config,signed,args=demand;publish_snapshot(config,signed,now=NOW)
    async def forbidden(*a,**k):raise AssertionError('existing round must be reused')
    monkeypatch.setattr(runner,'collect',forbidden)
    assert await runner.collect_on_demand(args)=={'state':'SIGNED_PRICE_READY','sequence':1,
        'validUntil':int(signed['round']['validUntil']),'providerCalls':0}


@pytest.mark.asyncio
async def test_missing_round_collects_once_then_revalidates_signed_evidence(demand,monkeypatch):
    config,signed,args=demand;calls=[]
    async def synthetic(actual,*,minimum_validity):
        calls.append(minimum_validity);publish_snapshot(config,signed,now=NOW)
    monkeypatch.setattr(runner,'collect',synthetic)
    assert (await runner.collect_on_demand(args))['state']=='SIGNED_PRICE_READY'
    assert calls==[300]


@pytest.mark.asyncio
async def test_closed_window_or_exhausted_quota_never_calls_provider(demand,monkeypatch):
    config,signed,args=demand
    async def forbidden(*a,**k):raise AssertionError('closed demand must not call provider')
    monkeypatch.setattr(runner,'collect',forbidden)
    state=json.loads(args.usage_state.read_text());state['calls']=3000;args.usage_state.write_text(json.dumps(state))
    with pytest.raises(PriceFeedError,match='unavailable'):await runner.collect_on_demand(args)
    state['calls']=0;args.usage_state.write_text(json.dumps(state))
    policy=json.loads(args.policy.read_text());policy['expiresAt']=NOW;args.policy.write_text(json.dumps(policy))
    with pytest.raises(PriceFeedError,match='unavailable'):await runner.collect_on_demand(args)


@pytest.mark.asyncio
async def test_insufficient_source_validity_stops_before_attestors(demand,monkeypatch):
    config,signed,args=demand
    args.attestors.write_text(json.dumps([['attestor-a'],['attestor-b']]))
    old=evidence()[2];short=(replace(old[0],valid_until=NOW+200),old[1])
    async def observations(*a,**k):return short
    async def forbidden(*a,**k):raise AssertionError('short round must not reach attestors')
    monkeypatch.setattr(runner,'permitted_observations',observations)
    monkeypatch.setattr(asyncio,'create_subprocess_exec',forbidden)
    with pytest.raises(PriceFeedError,match='quote window'):
        await runner.collect(args,minimum_validity=300)
    assert not args.snapshot.exists()


@pytest.mark.parametrize('wire',[b'',b'{"op":"refresh","url":"https://example.com"}',b'X'*34])
def test_cli_rejects_unfixed_request_before_lock_or_work(demand,monkeypatch,wire,capsys):
    config,signed,args=demand
    monkeypatch.setattr(sys,'stdin',argparse.Namespace(buffer=io.BytesIO(wire)))
    monkeypatch.setattr(sys,'argv',['runner','demand','--roster',str(args.roster),'--snapshot',str(args.snapshot),
        '--lock',str(args.snapshot.parent/'lock'),'--attestors',str(args.attestors),'--policy',str(args.policy),
        '--usage-state',str(args.usage_state),'--provider-credentials',str(args.snapshot.parent/'credential')])
    assert runner.main()==1
    assert not(args.snapshot.parent/'lock').exists()
    assert json.loads(capsys.readouterr().out)['healthy']is False


def test_cli_status_reads_without_lock_provider_or_signer(demand,monkeypatch,capsys):
    config,signed,args=demand
    monkeypatch.setattr(sys,'stdin',argparse.Namespace(buffer=io.BytesIO(b'{"op":"status"}')))
    monkeypatch.setattr(sys,'argv',['runner','demand','--roster',str(args.roster),'--snapshot',str(args.snapshot),
        '--lock',str(args.snapshot.parent/'lock'),'--attestors',str(args.attestors),'--policy',str(args.policy),
        '--usage-state',str(args.usage_state),'--provider-credentials',str(args.snapshot.parent/'credential')])
    def forbidden(*a,**k):raise AssertionError('status must not read credentials or call the collector')
    monkeypatch.setattr(runner,'read_provider_credentials',forbidden)
    monkeypatch.setattr(runner,'read_key',forbidden)
    monkeypatch.setattr(runner,'collect',forbidden)
    assert runner.main()==0
    assert not(args.snapshot.parent/'lock').exists()
    assert json.loads(capsys.readouterr().out)['status']=='REFRESH_REQUIRED'
