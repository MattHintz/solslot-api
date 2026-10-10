from __future__ import annotations

import copy
import json
from decimal import Decimal

import httpx
import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from fastapi import Response

from solslot_api.collection_endpoints import collection_xch_pricing
from solslot_api.config import Settings
from solslot_api.payment_quotes import PaymentQuoteError, load_authorized_oracle_round
from solslot_api.xch_price_feed import (
    OBSERVATION_TTL, PriceFeedError, attest_candidate, candidate_round,
    decode_source, fetch_observations, parse_observation, publish_snapshot,
)

NOW = 1_791_604_200


def responses():
    return {
        "coingecko": {"chia": {"usd": Decimal("1.52"), "last_updated_at": NOW - 5}},
        "livecoinwatch": {"code": "XCH", "history": [{"date": (NOW - 120) * 1000, "rate": "1.523", "volume": 150000}]},
    }


def evidence():
    keys = tuple(AugSchemeMPL.key_gen(bytes([n]) * 32) for n in (181, 182, 183))
    pubkeys = tuple(bytes(key.get_g1()) for key in keys)
    obs = tuple(parse_observation(source, payload, now=NOW) for source, payload in responses().items())
    return keys, pubkeys, obs


def authorized(sequence: int = 1):
    keys, pubkeys, obs = evidence()
    candidate = candidate_round(observations=obs, pubkeys=pubkeys, sequence=sequence, now=NOW)
    signatures = [attest_candidate(candidate, observations=obs, pubkeys=pubkeys, key=keys[i], signer_index=i, now=NOW) for i in (0, 1)]
    return pubkeys, {"round": candidate, "signatures": signatures}


def settings(tmp_path, pubkeys):
    return Settings(_env_file=None, network="testnet11", payment_oracle_rounds_path=str(tmp_path / "oracle.json"), payment_oracle_operator_pubkeys=["0x" + key.hex() for key in pubkeys])


def test_provider_time_and_decimal_price_are_committed_without_float_rounding():
    item = parse_observation("coingecko", {"chia": {"usd": Decimal("1.525"), "last_updated_at": NOW - 5}}, now=NOW)
    assert item.price_usd_minor_per_asset == 153
    assert item.observed_at == NOW - 5
    assert item.valid_until == NOW - 5 + OBSERVATION_TTL
    assert item.asset_decimals == 12 and item.asset_id == bytes32.zeros
    changed = parse_observation("coingecko", {"chia": {"usd": Decimal("1.5251"), "last_updated_at": NOW - 5}}, now=NOW)
    assert item.evidence_hash != changed.evidence_hash


@pytest.mark.parametrize("price", [True, None, "NaN", "Infinity", "-1", "0", "1000001", "0.004", 1.52])
def test_bad_prices_are_not_replaced_with_a_fixed_fallback(price):
    with pytest.raises(PriceFeedError):
        parse_observation("coingecko", {"chia": {"usd": price, "last_updated_at": NOW}}, now=NOW)


@pytest.mark.parametrize("timestamp", [None, True, NOW + 1, NOW - OBSERVATION_TTL, NOW - 481])
def test_missing_future_and_stale_provider_time_is_rejected(timestamp):
    with pytest.raises(PriceFeedError):
        parse_observation("coingecko", {"chia": {"usd": "1.52", "last_updated_at": timestamp}}, now=NOW)


def test_dated_history_uses_usd_and_commits_provider_point():
    payload = responses()["livecoinwatch"]
    payload["history"][0]["rate"] = "1.375"
    obs = parse_observation("livecoinwatch", payload, now=NOW)
    assert obs.price_usd_minor_per_asset == 138
    assert obs.observed_at == NOW - 120
    payload["history"][0]["rate"] = "1.3751"
    other = parse_observation("livecoinwatch", payload, now=NOW)
    assert obs.evidence_hash != other.evidence_hash


@pytest.mark.parametrize("mutation", ["empty", "wrong_coin", "missing_time", "stale", "duplicate", "fractional", "future", "invalid_rate"])
def test_undated_ambiguous_wrong_coin_and_stale_history_cannot_renew_price(mutation):
    payload = responses()["livecoinwatch"]
    row = payload["history"][0]
    if mutation == "empty": payload["history"] = []
    elif mutation == "wrong_coin": payload["code"] = "BTC"
    elif mutation == "missing_time": del row["date"]
    elif mutation == "stale": row["date"] = (NOW - 600) * 1000
    elif mutation == "duplicate": payload["history"].append(copy.deepcopy(row))
    elif mutation == "fractional": row["date"] += 1
    elif mutation == "future": row["date"] = (NOW + 1) * 1000
    elif mutation == "invalid_rate": row["rate"] = "NaN"
    with pytest.raises(PriceFeedError):
        parse_observation("livecoinwatch", payload, now=NOW)


@pytest.mark.parametrize("raw", [b'{"chia":1,"chia":2}', b'{"chia":NaN}', b'\xff', b'x' * 65_537])
def test_ambiguous_or_oversize_json_is_rejected(raw):
    with pytest.raises(PriceFeedError):
        decode_source(raw)


def test_spread_over_three_percent_blocks_candidate():
    _keys, pubkeys, obs = evidence()
    other = responses()["livecoinwatch"]
    other["history"][0]["rate"] = "1.57"
    bad = (obs[0], parse_observation("livecoinwatch", other, now=NOW))
    with pytest.raises(PriceFeedError, match="dispersion"):
        candidate_round(observations=bad, pubkeys=pubkeys, sequence=1, now=NOW)


def test_operator_reconstructs_evidence_and_rejects_mutation_and_wrong_key():
    keys, pubkeys, obs = evidence()
    proposed = candidate_round(observations=obs, pubkeys=pubkeys, sequence=1, now=NOW)
    with pytest.raises(PriceFeedError, match="key"):
        attest_candidate(proposed, observations=obs, pubkeys=pubkeys, key=keys[1], signer_index=0, now=NOW)
    altered = copy.deepcopy(proposed)
    altered["network"] = "mainnet"
    with pytest.raises(PriceFeedError):
        attest_candidate(altered, observations=obs, pubkeys=pubkeys, key=keys[0], signer_index=0, now=NOW)
    other = responses()["coingecko"]
    other["chia"]["usd"] = Decimal("1.53")
    fresh = (parse_observation("coingecko", other, now=NOW), obs[1])
    with pytest.raises(PriceFeedError, match="independent"):
        attest_candidate(proposed, observations=fresh, pubkeys=pubkeys, key=keys[0], signer_index=0, now=NOW)


def test_operator_replay_and_conflicting_sequence_are_rejected():
    keys, pubkeys, obs = evidence()
    proposed = candidate_round(observations=obs, pubkeys=pubkeys, sequence=3, now=NOW)
    for sequence, old_hash in ((4, None), (3, "0x" + "ab" * 32)):
        with pytest.raises(PriceFeedError, match="sequence"):
            attest_candidate(proposed, observations=obs, pubkeys=pubkeys, key=keys[0], signer_index=0, now=NOW, last_sequence=sequence, last_hash=old_hash)


def test_quorum_snapshot_is_atomic_idempotent_and_preserves_previous(tmp_path):
    pubkeys, signed = authorized(1)
    config = settings(tmp_path, pubkeys)
    assert publish_snapshot(config, signed, now=NOW)["published"] is True
    path = tmp_path / "oracle.json"
    first = path.read_bytes()
    assert publish_snapshot(config, signed, now=NOW)["published"] is False
    assert first == path.read_bytes()
    _pubkeys, signed2 = authorized(2)
    assert publish_snapshot(config, signed2, now=NOW)["published"] is True
    assert (tmp_path / "oracle.json.previous").read_bytes() == first
    with pytest.raises(PriceFeedError, match="regressed"):
        publish_snapshot(config, signed, now=NOW)
    assert load_authorized_oracle_round(config, asset_id=bytes32.zeros, now=NOW).round.sequence == 2


def test_insufficient_signatures_and_expiry_never_overwrite_snapshot(tmp_path):
    pubkeys, signed = authorized(1)
    config = settings(tmp_path, pubkeys)
    publish_snapshot(config, signed, now=NOW)
    path = tmp_path / "oracle.json"
    first = path.read_bytes()
    _pubkeys, bad = authorized(2)
    bad["signatures"].pop()
    with pytest.raises(PriceFeedError, match="two independent"):
        publish_snapshot(config, bad, now=NOW)
    assert first == path.read_bytes()
    with pytest.raises(PaymentQuoteError, match="no live"):
        load_authorized_oracle_round(config, asset_id=bytes32.zeros, now=NOW + 600)


@pytest.mark.asyncio
async def test_fetch_is_bounded_and_does_not_follow_redirects():
    requests = []
    def handler(request):
        requests.append(request)
        if request.url.host == "api.coingecko.com":
            return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})
        return httpx.Response(200, json=responses()["livecoinwatch"])
    with pytest.raises(PriceFeedError, match="HTTP 302"):
        await fetch_observations(now=NOW, credentials={"coingecko": "test-only-coingecko-key", "livecoinwatch": "test-only-livecoinwatch-key"}, transport=httpx.MockTransport(handler))
    assert all(request.url.scheme == "https" and request.url.host != "127.0.0.1" for request in requests)


@pytest.mark.asyncio
async def test_verified_price_status_is_read_only_and_expires(tmp_path, monkeypatch):
    pubkeys, signed = authorized()
    config = settings(tmp_path, pubkeys)
    publish_snapshot(config, signed, now=NOW)
    from solslot_api import collection_endpoints
    monkeypatch.setattr(collection_endpoints.time, "time", lambda: NOW)
    response = Response()
    status = await collection_xch_pricing(response, config)
    assert status["status"] == "available"
    assert status["quote"]["sourceCount"] == 2 and status["quote"]["signerCount"] == 2
    assert status["quote"]["observedAt"] == NOW - 120
    assert response.headers["cache-control"] == "no-store"
    monkeypatch.setattr(collection_endpoints.time, "time", lambda: NOW + 600)
    assert (await collection_xch_pricing(Response(), config))["quote"] is None


@pytest.mark.asyncio
async def test_free_provider_credentials_are_sent_only_to_their_own_https_origin():
    requests = []
    credentials = {"coingecko": "test-only-coingecko-key", "livecoinwatch": "test-only-livecoinwatch-key"}
    def handler(request):
        requests.append(request)
        source = "coingecko" if request.url.host == "api.coingecko.com" else "livecoinwatch"
        return httpx.Response(200, content=json.dumps(responses()[source], default=str), headers={"content-type": "application/json"})
    obs = await fetch_observations(now=NOW, credentials=credentials, transport=httpx.MockTransport(handler))
    assert len(obs) == 2 and len(requests) == 2
    for request in requests:
        assert not request.url.query.find(b'key') >= 0
        if request.url.host == "api.coingecko.com":
            assert request.method == "GET" and request.headers['x-cg-demo-api-key'] == credentials['coingecko']
            assert 'x-api-key' not in request.headers
        else:
            assert request.method == "POST" and request.headers['x-api-key'] == credentials['livecoinwatch']
            assert 'x-cg-demo-api-key' not in request.headers
            body = json.loads(request.content)
            assert body == {"currency":"USD", "code":"XCH", "start":NOW // 300 * 300 * 1000 - 300000, "end":NOW // 300 * 300 * 1000, "meta":False}
    with pytest.raises(PriceFeedError, match="both free-provider"):
        await fetch_observations(now=NOW, credentials={}, transport=httpx.MockTransport(handler))
