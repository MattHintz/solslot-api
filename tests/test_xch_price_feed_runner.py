from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import sys
from pathlib import Path

import pytest
from chia_rs import PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from solslot_api import admin_auth, xch_price_feed_runner as runner
from solslot_api.collection_endpoints import router
from solslot_api.config import get_settings
from solslot_api.xch_price_feed import PriceFeedError
from tests.test_xch_price_feed import NOW, authorized, evidence, settings


def test_credentials_are_local_owned_private_binary_and_not_symlinks(tmp_path):
    keys, _, _ = evidence()
    path = tmp_path / 'test-only-key'
    path.write_bytes(bytes(keys[0]))
    path.chmod(0o600)
    assert runner.read_key(path) == keys[0]
    path.chmod(0o640)
    with pytest.raises(PriceFeedError, match='mode'):
        runner.read_key(path)
    path.chmod(0o600)
    link = tmp_path / 'symlink'
    link.symlink_to(path)
    with pytest.raises(OSError):
        runner.read_key(link)
    path.write_bytes(bytes(keys[0]) + b'extra')
    with pytest.raises(PriceFeedError, match='32 binary'):
        runner.read_key(path)


def test_operator_cannot_replace_deployment_roster(tmp_path):
    path = tmp_path / 'roster.json'
    path.write_text('{}')
    path.chmod(0o666)
    with pytest.raises(PriceFeedError, match='root-owned'):
        runner.read_roster(path)


@pytest.mark.asyncio
async def test_collection_joins_actual_bounded_attestor_processes_then_verifies_snapshot(tmp_path, monkeypatch):
    pubkeys, signed = authorized(NOW)
    config = settings(tmp_path, pubkeys)
    roster = {'schema':'solslot.xch-price-roster.v1', 'network':'testnet11', 'operatorPubkeys':config.payment_oracle_operator_pubkeys}
    roster_path, commands_path = tmp_path / 'roster.json', tmp_path / 'attestors.json'
    roster_path.write_text(json.dumps(roster))
    commands = []
    for sig in signed['signatures']:
        script = "import sys,json; c=json.load(sys.stdin); assert c == " + repr(signed['round']) + "; print(" + repr(json.dumps(sig)) + ")"
        commands.append([sys.executable, '-c', script])
    commands_path.write_text(json.dumps(commands))
    # Only deployment ownership is simulated; subprocess IO, quorum, hashes,
    # atomic output and the unchanged consuming verifier execute normally.
    monkeypatch.setattr(runner, '_check_config_owner', lambda path: None)
    monkeypatch.setattr(runner.time, 'time', lambda: NOW)
    async def fetch(**kwargs): return evidence()[2]
    monkeypatch.setattr(runner, 'permitted_observations', lambda args, **kwargs: fetch(**kwargs))
    args = argparse.Namespace(roster=roster_path, snapshot=Path(config.payment_oracle_rounds_path), attestors=commands_path)
    assert (await runner.collect(args))['published'] is True
    original = args.snapshot.read_bytes()
    commands_path.write_text(json.dumps([[sys.executable, '-c', "print('x' * 32769)"], commands[1]]))
    with pytest.raises(PriceFeedError, match='output bound'):
        await runner.collect(args)
    assert args.snapshot.read_bytes() == original


@pytest.mark.asyncio
async def test_signer_persists_monotonic_state_and_does_not_release_conflicting_signature(tmp_path, monkeypatch):
    keys, pubkeys, obs = evidence()
    _, signed = authorized(7)
    roster = {'schema':'solslot.xch-price-roster.v1', 'network':'testnet11', 'operatorPubkeys':['0x'+x.hex() for x in pubkeys]}
    key_path, state = tmp_path/'test-only-key', tmp_path/'attested.json'
    key_path.write_bytes(bytes(keys[0])); key_path.chmod(0o600)
    monkeypatch.setattr(runner, 'read_roster', lambda path: (roster, pubkeys))
    monkeypatch.setattr(runner.time, 'time', lambda: NOW)
    async def fetch(**kwargs): return obs
    monkeypatch.setattr(runner, 'permitted_observations', lambda args, **kwargs: fetch(**kwargs))
    def stdin(): monkeypatch.setattr(runner.sys, 'stdin', argparse.Namespace(buffer=io.BytesIO(json.dumps(signed['round']).encode())))
    args=argparse.Namespace(roster=tmp_path/'roster', key=key_path, state=state, index=0)
    stdin()
    assert await runner.sign(args) == signed['signatures'][0]
    recorded=json.loads(state.read_text())
    assert recorded['sequence'] == 7
    state.write_text(json.dumps({'sequence':8,'roundHash':recorded['roundHash']}))
    before=state.read_bytes(); stdin()
    with pytest.raises(PriceFeedError, match='sequence'):
        await runner.sign(args)
    assert state.read_bytes() == before


def test_price_status_route_keeps_real_authentication_and_feature_gates(tmp_path, monkeypatch):
    pubkeys, _ = authorized()
    config=settings(tmp_path,pubkeys).model_copy(update={'collection_metadata_enabled':True,'admin_jwt_secret':'test-only-authorization-secret-never-live'})
    subject='0x'+'ab'*20
    monkeypatch.setattr(admin_auth,'_effective_admin_allowlist',lambda settings:{subject})
    app=FastAPI(); app.include_router(router)
    app.dependency_overrides[get_settings]=lambda:config
    client=TestClient(app)
    assert client.get('/admin/collections/pricing/xch').status_code == 401
    assert client.get('/admin/collections/pricing/xch',headers={'Authorization':'Bearer invalid'}).status_code == 403
    token,_=admin_auth.issue_jwt(sub=subject,auth_type='evm',settings=config)
    headers={'Authorization':'Bearer '+token}
    response=client.get('/admin/collections/pricing/xch',headers=headers)
    assert response.status_code == 200 and response.json()['status'] == 'unavailable'
    assert response.headers['cache-control'] == 'no-store'
    config.collection_metadata_enabled=False
    assert client.get('/admin/collections/pricing/xch',headers=headers).status_code == 503


def test_test_window_and_free_quota_never_silently_extend_or_reset(tmp_path, monkeypatch):
    path, usage = tmp_path / 'test-policy.json', tmp_path / 'usage.json'
    monkeypatch.setattr(runner, '_check_config_owner', lambda path: None)
    policy = {'schema':'solslot.xch-price-test-window.v1', 'network':'testnet11', 'notBefore':NOW, 'expiresAt':NOW+172800}
    path.write_text(json.dumps(policy))
    runner.validate_test_window(path, now=NOW)
    for now in (NOW-1, NOW+172800):
        with pytest.raises(PriceFeedError, match='window'):
            runner.validate_test_window(path, now=now)
    policy['expiresAt'] += 1; path.write_text(json.dumps(policy))
    with pytest.raises(PriceFeedError, match='window'):
        runner.validate_test_window(path, now=NOW)
    runner.reserve_provider_call(usage, now=NOW)
    state = json.loads(usage.read_text())
    assert state['calls'] == 1
    state['calls'] = 3000; usage.write_text(json.dumps(state))
    with pytest.raises(PriceFeedError, match='budget'):
        runner.reserve_provider_call(usage, now=NOW)
    state['month'] = '2099-01'; usage.write_text(json.dumps(state))
    with pytest.raises(PriceFeedError, match='ledger'):
        runner.reserve_provider_call(usage, now=NOW)
    usage.write_text('{}')
    with pytest.raises(PriceFeedError, match='ledger'):
        runner.reserve_provider_call(usage, now=NOW)


def test_provider_credentials_reject_public_file_and_symlink_without_echoing_key(tmp_path):
    path = tmp_path/'test-provider-keys'
    dummy = {'coingecko':'test-only-coingecko-key', 'livecoinwatch':'test-only-livecoinwatch-key'}
    path.write_text(json.dumps(dummy)); path.chmod(0o600)
    assert runner.read_provider_credentials(path) == dummy
    path.chmod(0o640)
    with pytest.raises(PriceFeedError, match='mode') as error:
        runner.read_provider_credentials(path)
    assert dummy['coingecko'] not in str(error.value)
    path.chmod(0o600)
    link = tmp_path/'link'; link.symlink_to(path)
    with pytest.raises(OSError): runner.read_provider_credentials(link)
    path.write_text(json.dumps({**dummy, 'coingecko':'invalid\nheader'}))
    with pytest.raises(PriceFeedError, match='credential'):
        runner.read_provider_credentials(path)


@pytest.mark.asyncio
async def test_expired_test_window_never_reads_key_or_calls_market(tmp_path, monkeypatch):
    policy = tmp_path/'policy.json'
    policy.write_text(json.dumps({'schema':'solslot.xch-price-test-window.v1','network':'testnet11','notBefore':NOW-172800,'expiresAt':NOW}))
    monkeypatch.setattr(runner, '_check_config_owner', lambda path: None)
    args = argparse.Namespace(policy=policy, provider_credentials=tmp_path/'missing',usage_state=tmp_path/'usage')
    with pytest.raises(PriceFeedError, match='window'):
        await runner.permitted_observations(args, now=NOW)
    assert not args.usage_state.exists()


@pytest.mark.asyncio
async def test_permitted_observation_cannot_outlive_the_approved_test_window(tmp_path, monkeypatch):
    policy = tmp_path/'policy.json'
    policy.write_text(json.dumps({'schema':'solslot.xch-price-test-window.v1','network':'testnet11','notBefore':NOW-100,'expiresAt':NOW+150}))
    credentials = tmp_path/'provider-keys'
    credentials.write_text(json.dumps({'coingecko':'test-only-coingecko-key','livecoinwatch':'test-only-livecoinwatch-key'})); credentials.chmod(0o600)
    monkeypatch.setattr(runner, '_check_config_owner', lambda path: None)
    async def fetch(**kwargs): return evidence()[2]
    monkeypatch.setattr(runner, 'fetch_observations', fetch)
    args = argparse.Namespace(policy=policy, provider_credentials=credentials,usage_state=tmp_path/'usage.json')
    observations = await runner.permitted_observations(args, now=NOW)
    assert all(item.valid_until == NOW+150 for item in observations)
    assert json.loads(args.usage_state.read_text())['calls'] == 1
