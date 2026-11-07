"""Timestamped XCH/USD observations and quorum-verified snapshot production.

Market requests use fixed public URLs. Each operator fetches the sources itself
before attesting; the publisher never owns the operator private keys.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Mapping, Sequence

import httpx
from chia_rs import AugSchemeMPL, PrivateKey
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    OracleObservationV1,
    PaymentArtifactError,
    build_oracle_round,
    oracle_operator_set_root,
    oracle_round_from_json,
    oracle_round_signature_message,
    oracle_round_to_json,
)

from .config import Settings
from .payment_quotes import (
    MAX_SNAPSHOT_BYTES,
    SNAPSHOT_SCHEMA,
    PaymentQuoteError,
    AuthorizedOracleRound,
    load_authorized_oracle_round,
    parse_authorized_oracle_round,
)

SOURCE_URLS = {
    "coingecko": "https://api.coingecko.com/api/v3/simple/price?ids=chia&vs_currencies=usd&include_last_updated_at=true",
    "livecoinwatch": "https://api.livecoinwatch.com/coins/single/history",
}
OBSERVATION_SOURCES = ("coingecko", "livecoinwatch")
MAX_RESPONSE_BYTES = 65_536
OBSERVATION_TTL = 600
MIN_REMAINING_SECONDS = 120
MAX_PRICE_USD = Decimal("1000000")
EVIDENCE_SCHEMA = "solslot.xch-usd-observation.v1"


class PriceFeedError(RuntimeError):
    """A source, operator or publication failed the feed's fixed policy."""


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PriceFeedError(f"{label} must be a positive integer")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PriceFeedError("source JSON contains duplicate keys")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise PriceFeedError("source JSON contains a non-finite number")


def decode_source(body: bytes) -> Any:
    if not body or len(body) > MAX_RESPONSE_BYTES:
        raise PriceFeedError("source response size is invalid")
    try:
        return json.loads(
            body.decode("utf-8"), parse_float=Decimal,
            parse_constant=_invalid_constant, object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PriceFeedError("source response is not valid JSON") from exc


def _decimal(value: Any, label: str, *, allow_zero: bool = False, maximum: Decimal = MAX_PRICE_USD) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise PriceFeedError(f"{label} is not a decimal amount")
    try:
        result = Decimal(value)
        if not result.is_finite() or result < 0 or (not allow_zero and result == 0) or result > maximum:
            raise PriceFeedError(f"{label} is outside the supported range")
        return result
    except InvalidOperation as exc:
        raise PriceFeedError(f"{label} is not a decimal amount") from exc


def _livecoinwatch_usd(payload: Any, *, now: int) -> tuple[Decimal, int, dict[str, Any]]:
    """Use the provider's dated USD history point, never the fetch clock."""
    try:
        rows = payload["history"]
        if payload["code"] != "XCH" or not isinstance(rows, list) or not 1 <= len(rows) <= 301:
            raise PriceFeedError("Live Coin Watch coin or history is invalid")
        points: dict[int, Decimal] = {}
        for row in rows:
            date = _integer(row["date"], "Live Coin Watch timestamp")
            if date % 1000:
                raise PriceFeedError("Live Coin Watch timestamp must use whole seconds")
            timestamp = date // 1000
            if timestamp in points or timestamp > now:
                raise PriceFeedError("Live Coin Watch timestamp is duplicated or from the future")
            points[timestamp] = _decimal(row["rate"], "Live Coin Watch USD price")
        observed_at = max(points)
        return points[observed_at], observed_at, {
            "basis": "provider-dated-USD-history", "coin": "XCH", "currency": "USD",
            "url": SOURCE_URLS["livecoinwatch"],
        }
    except (KeyError, TypeError, IndexError) as exc:
        raise PriceFeedError("Live Coin Watch history fields are missing") from exc


def _provider_key(value: Any) -> str:
    if not isinstance(value, str) or not 16 <= len(value) <= 256 or not value.isascii() or any(
        not (character.isalnum() or character in "_-.") for character in value
    ):
        raise PriceFeedError("provider credential is invalid")
    return value


def parse_observation(source: str, payload: Any, *, now: int) -> OracleObservationV1:
    """Bind normalized source facts, including provider time, to CLVM evidence."""
    _integer(now, "now")
    if source not in OBSERVATION_SOURCES:
        raise PriceFeedError("source is not allowlisted")
    components: dict[str, Any]
    try:
        if source == "coingecko":
            item = payload["chia"]
            price_value = item["usd"]
            observed_at = _integer(item["last_updated_at"], "provider timestamp")
            components = {"basis": "provider-USD-aggregate", "url": SOURCE_URLS[source]}
        else:
            price_value, observed_at, components = _livecoinwatch_usd(payload, now=now)
    except (KeyError, TypeError, IndexError) as exc:
        raise PriceFeedError("source price or provider timestamp is missing") from exc
    # Never turn fetch time into market time or extend an old observation's life.
    if observed_at > now or observed_at + OBSERVATION_TTL - now < MIN_REMAINING_SECONDS:
        raise PriceFeedError("source observation is stale or from the future")
    price = _decimal(price_value, "source USD price")
    try:
        minor = int((price * 100).to_integral_value(rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError) as exc:
        raise PriceFeedError("source price is not a decimal USD amount") from exc
    if minor <= 0:
        raise PriceFeedError("source price is below the protocol's cent precision")
    facts = {
        "schema": EVIDENCE_SCHEMA, "source": source, "pair": "XCH/USD",
        "priceUsd": format(price.normalize(), "f"), "observedAt": observed_at,
        "components": components,
    }
    evidence = json.dumps(facts, sort_keys=True, separators=(",", ":")).encode()
    return OracleObservationV1(
        source_id=bytes32(hashlib.sha256((EVIDENCE_SCHEMA + ":" + source).encode()).digest()),
        asset_id=bytes32.zeros, asset_decimals=12,
        price_usd_minor_per_asset=minor, observed_at=observed_at,
        valid_until=observed_at + OBSERVATION_TTL,
        evidence_hash=bytes32(hashlib.sha256(evidence).digest()),
    )


async def fetch_observations(*, now: int, credentials: Mapping[str, str], transport: httpx.AsyncBaseTransport | None = None) -> tuple[OracleObservationV1, ...]:
    if set(credentials) != set(OBSERVATION_SOURCES):
        raise PriceFeedError("both free-provider credentials must be provisioned")
    credential_values = {source: _provider_key(value) for source, value in credentials.items()}
    async with httpx.AsyncClient(
        transport=transport, timeout=httpx.Timeout(10, connect=5),
        follow_redirects=False, trust_env=False,
        headers={"Accept": "application/json", "User-Agent": "SolslotXchPriceFeed/1"},
    ) as client:
        async def fetch(source: str, url: str) -> Any:
            try:
                if source == "coingecko":
                    method, options = "GET", {"headers": {"x-cg-demo-api-key": credential_values[source]}}
                else:
                    # Metadata supplies the coin code checked by the strict parser.
                    # Fixed short history window gives each operator a dated point.
                    # Do not mistake the undated /coins/single rate for fresh evidence.
                    end = now // 300 * 300 * 1000
                    method, options = "POST", {
                        "headers": {"x-api-key": credential_values[source]},
                        "json": {"currency": "USD", "code": "XCH", "start": end - 300_000, "end": end, "meta": True},
                    }
                async with client.stream(method, url, **options) as response:
                    if response.status_code != 200:
                        raise PriceFeedError(f"{source} returned HTTP {response.status_code}")
                    if "application/json" not in response.headers.get("content-type", "").lower():
                        raise PriceFeedError(f"{source} returned a non-JSON response")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise PriceFeedError(f"{source} response exceeded its bound")
                return decode_source(bytes(body))
            except httpx.HTTPError as exc:
                # Do not log remote response bodies, headers or credential values.
                raise PriceFeedError(f"{source} request failed") from exc
        values = await asyncio.gather(*(fetch(source, url) for source, url in SOURCE_URLS.items()))
        payloads = dict(zip(SOURCE_URLS, values, strict=True))
        observations = (
            parse_observation("coingecko", payloads["coingecko"], now=now),
            parse_observation("livecoinwatch", payloads["livecoinwatch"], now=now),
        )
        return tuple(sorted(observations, key=lambda item: bytes(item.source_id)))


def candidate_round(*, observations: Sequence[OracleObservationV1], pubkeys: Sequence[bytes], sequence: int, now: int) -> dict[str, Any]:
    try:
        round_ = build_oracle_round(
            network="testnet11", sequence=sequence, asset_id=bytes32.zeros,
            asset_decimals=12, operator_set_root=oracle_operator_set_root(pubkeys),
            observations=observations,
        )
        round_.assert_live(now)
    except PaymentArtifactError as exc:
        raise PriceFeedError(str(exc)) from exc
    if round_.valid_until - now < MIN_REMAINING_SECONDS:
        raise PriceFeedError("candidate does not have enough validity remaining")
    return oracle_round_to_json(round_)


def attest_candidate(candidate: Mapping[str, Any], *, observations: Sequence[OracleObservationV1], pubkeys: Sequence[bytes], key: PrivateKey, signer_index: int, now: int, last_sequence: int = 0, last_hash: str | None = None) -> dict[str, Any]:
    """Only attest the exact candidate reconstructed from this operator's fetches."""
    if isinstance(signer_index, bool) or signer_index not in range(3):
        raise PriceFeedError("signer index is invalid")
    try:
        proposed = oracle_round_from_json(candidate)
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise PriceFeedError("candidate is invalid") from exc
    expected = candidate_round(observations=observations, pubkeys=pubkeys, sequence=proposed.sequence, now=now)
    if dict(candidate) != expected or bytes(key.get_g1()) != pubkeys[signer_index]:
        raise PriceFeedError("candidate or key does not match independent operator evidence")
    round_hash = "0x" + proposed.round_hash.hex()
    if proposed.sequence < last_sequence or (proposed.sequence == last_sequence and round_hash != last_hash):
        raise PriceFeedError("candidate replays or conflicts with an attested sequence")
    message = oracle_round_signature_message(proposed.round_hash)
    return {"signerIndex": signer_index, "signature": "0x" + bytes(AugSchemeMPL.sign(key, message)).hex()}


def _atomic_public_json(path: Path, value: Any) -> None:
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise PriceFeedError("output path must be a provisioned regular directory")
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise PriceFeedError("output exceeds the snapshot bound")
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".oracle-", dir=path.parent)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o640)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def read_prior_snapshot(settings: Settings, path: Path) -> tuple[dict[str, Any], AuthorizedOracleRound] | None:
    """Expired public evidence remains a sequence anchor, never a live quote."""
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise PriceFeedError("prior snapshot is invalid")
    try:
        prior = json.loads(path.read_text(), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if (not isinstance(prior, dict) or set(prior) != {"schema", "generatedAt", "rounds"}
                or prior["schema"] != SNAPSHOT_SCHEMA or not isinstance(prior["rounds"], list)
                or len(prior["rounds"]) != 1):
            raise PriceFeedError("prior snapshot is invalid")
        _integer(prior["generatedAt"], "prior generatedAt")
        old = parse_authorized_oracle_round(settings, prior["rounds"][0])
        if old.round.network != settings.network or old.round.asset_id != bytes32.zeros or old.round.asset_decimals != 12:
            raise PriceFeedError("prior snapshot has a different asset or network")
        return prior, old
    except (OSError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, PaymentQuoteError) as exc:
        raise PriceFeedError("prior snapshot cannot be verified") from exc


def publish_snapshot(settings: Settings, authorized: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    """Validate quorum and monotonic state before an atomic, public-only replace.

    The caller must hold the single-writer process lock. Invalid or expired
    input leaves the existing snapshot unchanged; consumers still check expiry.
    """
    try:
        current = parse_authorized_oracle_round(settings, authorized)
        current.round.assert_live(now)
    except (PaymentQuoteError, PaymentArtifactError) as exc:
        raise PriceFeedError(str(exc)) from exc
    if current.round.network != settings.network or settings.network != "testnet11":
        raise PriceFeedError("feed is restricted to the approved Testnet11 network")
    if current.round.asset_id != bytes32.zeros or current.round.asset_decimals != 12:
        raise PriceFeedError("feed can only publish native XCH prices")
    if current.round.valid_until - now < MIN_REMAINING_SECONDS:
        raise PriceFeedError("authorized round is about to expire")
    if not settings.payment_oracle_rounds_path:
        raise PriceFeedError("snapshot path is not configured")
    path = Path(settings.payment_oracle_rounds_path)
    previous = read_prior_snapshot(settings, path)
    if previous is not None:
        # Even expired snapshots establish the monotonic sequence. Never silently
        # overwrite corrupt or untrusted state with a newly numbered candidate.
        prior, old = previous
        if current.round.sequence < old.round.sequence:
            raise PriceFeedError("snapshot sequence regressed")
        if current.round.sequence == old.round.sequence:
            if current.round != old.round:
                raise PriceFeedError("snapshot sequence conflicts")
            return {"published": False, "sequence": old.round.sequence, "roundHash": "0x" + old.round.round_hash.hex()}
        _atomic_public_json(path.with_name(path.name + ".previous"), prior)
    snapshot = {"schema": SNAPSHOT_SCHEMA, "generatedAt": now, "rounds": [current.public_evidence()]}
    _atomic_public_json(path, snapshot)
    usable = load_authorized_oracle_round(settings, asset_id=bytes32.zeros, now=now)
    return {"published": True, "sequence": usable.round.sequence, "roundHash": "0x" + usable.round.round_hash.hex(), "validUntil": usable.round.valid_until}
