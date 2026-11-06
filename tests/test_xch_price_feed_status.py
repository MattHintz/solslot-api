"""Demand refresh decisions use signed evidence and never consume quota."""
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
from solslot_api import xch_price_feed_runner as runner
from solslot_api.xch_price_feed import publish_snapshot
from solslot_api.xch_price_feed_status import price_refresh_status
from tests.test_xch_price_feed import NOW, authorized, settings


@pytest.fixture
def feed(tmp_path, monkeypatch):
    pubkeys, signed = authorized()
    config = settings(tmp_path, pubkeys)
    snapshot = Path(config.payment_oracle_rounds_path)
    policy, usage = tmp_path/'policy.json', tmp_path/'usage.json'
    policy.write_text(json.dumps({'schema':'solslot.xch-price-test-window.v1',
        'network':'testnet11','notBefore':NOW-1,'expiresAt':NOW+3600}))
    usage.write_text(json.dumps({'month':datetime.fromtimestamp(NOW,timezone.utc).strftime('%Y-%m'),'calls':20}))
    monkeypatch.setattr(runner,'_check_config_owner',lambda path:None)
    return config,signed,dict(snapshot=snapshot,policy=policy,usage=usage,now=NOW,required_until=NOW+120)


def test_live_verified_round_is_reused_without_writes_or_provider_calls(feed, monkeypatch):
    config,signed,args=feed
    publish_snapshot(config,signed,now=NOW)
    before={k:v.read_bytes() for k,v in args.items() if isinstance(v,Path)}
    def forbidden(*a,**kw):raise AssertionError('status must not refresh or read a key')
    for name in ('read_provider_credentials','read_key','fetch_observations','_atomic_public_json'):
        monkeypatch.setattr(runner,name,forbidden)
    for _ in range(3):
        result=price_refresh_status(config,**args)
        assert result['status']=='READY' and result['canQuote'] and not result['refreshRequired']
        assert result['sourceCount']==2 and result['signerCount']==2
        assert result['quota']['remainingRequests']==2980
    assert {k:v.read_bytes() for k,v in args.items() if isinstance(v,Path)}==before


def test_missing_snapshot_requests_refresh_without_constructing_price(feed):
    config,signed,args=feed
    result=price_refresh_status(config,**args)
    assert result['status']=='REFRESH_REQUIRED' and result['canRefresh'] and not result['canQuote']
    assert result['sequence'] is None and not args['snapshot'].exists()


def test_round_must_cover_complete_new_quote_deadline(feed):
    config,signed,args=feed
    publish_snapshot(config,signed,now=NOW)
    expiry=int(signed['round']['validUntil'])
    result=price_refresh_status(config,**{**args,'now':expiry-50,'required_until':expiry+20})
    assert result['status']=='REFRESH_REQUIRED' and not result['canQuote']
    assert result['lastSuccessfulAt']==NOW and result['sequence']==1


def test_expired_snapshot_is_sequence_evidence_only(feed):
    config,signed,args=feed
    publish_snapshot(config,signed,now=NOW)
    expiry=int(signed['round']['validUntil'])
    original=args['snapshot'].read_bytes()
    result=price_refresh_status(config,**{**args,'now':expiry,'required_until':expiry+120})
    assert not result['canQuote'] and result['canRefresh'] and result['sequence']==1
    assert args['snapshot'].read_bytes()==original


def test_quota_exhaustion_blocks_refresh_but_does_not_invalidate_live_signed_round(feed):
    config,signed,args=feed
    state=json.loads(args['usage'].read_text());state['calls']=3000
    args['usage'].write_text(json.dumps(state))
    result=price_refresh_status(config,**args)
    assert result['status']=='REFRESH_UNAVAILABLE' and not result['canRefresh']
    assert result['quota']['status']=='EXHAUSTED'
    publish_snapshot(config,signed,now=NOW)
    result=price_refresh_status(config,**args)
    assert result['status']=='READY' and result['canQuote'] and not result['canRefresh']


@pytest.mark.parametrize('value',[{}, {'month':'2099-01','calls':0}, {'month':'2026-10','calls':True}])
def test_invalid_or_future_usage_is_never_reset(feed,value):
    config,signed,args=feed
    args['usage'].write_text(json.dumps(value));before=args['usage'].read_bytes()
    result=price_refresh_status(config,**args)
    assert not result['canRefresh'] and result['quota']['status']=='INVALID'
    assert args['usage'].read_bytes()==before


def test_prior_month_effective_counter_is_read_only(feed):
    config,signed,args=feed
    args['usage'].write_text(json.dumps({'month':'2026-09','calls':3000}));before=args['usage'].read_bytes()
    result=price_refresh_status(config,**args)
    assert result['quota']['remainingRequests']==3000 and result['canRefresh']
    assert args['usage'].read_bytes()==before


def test_corrupt_snapshot_stops_refresh_instead_of_replacing_sequence_evidence(feed):
    config,signed,args=feed
    args['snapshot'].write_text('{}');before=args['snapshot'].read_bytes()
    result=price_refresh_status(config,**args)
    assert result['code']=='PRICE_SNAPSHOT_INVALID' and not result['canRefresh']
    assert args['snapshot'].read_bytes()==before


def test_closed_policy_stops_quote_and_refresh_even_with_live_price(feed):
    config,signed,args=feed
    publish_snapshot(config,signed,now=NOW)
    policy=json.loads(args['policy'].read_text());policy['expiresAt']=NOW
    args['policy'].write_text(json.dumps(policy))
    result=price_refresh_status(config,**args)
    assert result['status']=='POLICY_CLOSED' and not result['canQuote'] and not result['canRefresh']
