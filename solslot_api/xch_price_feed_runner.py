"""Fixed-policy, Testnet11-only price feed commands for approved existing hosts.

Configuration and credentials are provisioned separately after deployment
approval. Only public evidence and bounded error codes are written to stdout.
"""
from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import stat
import socket
import sys
import time
from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path
from typing import Any

from chia_rs import PrivateKey
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v2 import oracle_round_from_json

from .config import Settings
from .payment_quotes import load_authorized_oracle_round
from .xch_price_feed import (
    PriceFeedError, _atomic_public_json, attest_candidate, candidate_round,
    decode_source, fetch_observations, publish_snapshot, read_prior_snapshot,
)

MAX_INPUT_BYTES = 32_768
MAX_TEST_WINDOW_SECONDS = 172_800
MONTHLY_CALLS_PER_ROLE = 3_000


def read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise PriceFeedError("configuration or state file is invalid")
    return json.loads(path.read_text())


def read_roster(path: Path) -> tuple[dict[str, Any], tuple[bytes, ...]]:
    _check_config_owner(path)
    value = read_json(path)
    if not isinstance(value, dict) or set(value) != {"schema", "network", "operatorPubkeys"}:
        raise PriceFeedError("roster fields are invalid")
    if value["schema"] != "solslot.xch-price-roster.v1" or value["network"] != "testnet11":
        raise PriceFeedError("only the approved Testnet11 roster is supported")
    keys = tuple(bytes.fromhex(v.removeprefix("0x")) for v in value["operatorPubkeys"])
    from solslot_puzzles.payment_artifacts_v2 import oracle_operator_set_root
    oracle_operator_set_root(keys)
    return value, keys


def _check_config_owner(path: Path) -> None:
    info = path.stat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise PriceFeedError("deployment configuration must be root-owned and not writable by operators")


def read_key(path: Path) -> PrivateKey:
    # A systemd credential or dedicated operator file. Never print this value.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PriceFeedError("operator credential ownership or mode is invalid")
        raw = os.read(descriptor, 65)
        if len(raw) != 32:
            raise PriceFeedError("operator credential must contain 32 binary bytes")
        return PrivateKey.from_bytes(raw)
    finally:
        os.close(descriptor)


def read_provider_credentials(path: Path) -> dict[str, str]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PriceFeedError("provider credential ownership or mode is invalid")
        raw = os.read(descriptor, 4097)
        if len(raw) > 4096:
            raise PriceFeedError("provider credential exceeded its bound")
        value = decode_source(raw)
        from .xch_price_feed import OBSERVATION_SOURCES, _provider_key
        if not isinstance(value, dict) or set(value) != set(OBSERVATION_SOURCES):
            raise PriceFeedError("provider credential fields are invalid")
        return {source: _provider_key(key) for source, key in value.items()}
    finally:
        os.close(descriptor)


def validate_test_window(path: Path, *, now: int) -> int:
    _check_config_owner(path)
    value = read_json(path)
    if not isinstance(value, dict) or set(value) != {"schema", "network", "notBefore", "expiresAt"}:
        raise PriceFeedError("test pricing policy fields are invalid")
    if value["schema"] != "solslot.xch-price-test-window.v1" or value["network"] != "testnet11":
        raise PriceFeedError("only the approved Testnet11 pricing policy is supported")
    start, end = value["notBefore"], value["expiresAt"]
    if any(isinstance(t, bool) or not isinstance(t, int) or t <= 0 for t in (start, end)):
        raise PriceFeedError("test pricing policy times are invalid")
    if not 0 < end - start <= MAX_TEST_WINDOW_SECONDS or not start <= now < end:
        raise PriceFeedError("test pricing window is not active")
    return end


def reserve_provider_call(path: Path, *, now: int) -> None:
    """Count attempts before requesting; three roles stay below Demo's 10k cap.

    Requires the enclosing process lock. Never reset a corrupt or future ledger.
    """
    month = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m")
    value = read_json(path) if path.exists() else {"month": month, "calls": 0}
    if not isinstance(value, dict) or set(value) != {"month", "calls"}:
        raise PriceFeedError("provider usage ledger is invalid")
    previous, count = value["month"], value["calls"]
    try:
        valid_month = datetime.strptime(previous, "%Y-%m").strftime("%Y-%m") == previous
    except (TypeError, ValueError):
        valid_month = False
    if not valid_month or previous > month or isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise PriceFeedError("provider usage ledger is invalid")
    if previous != month:
        count = 0
    if count >= MONTHLY_CALLS_PER_ROLE:
        raise PriceFeedError("free provider monthly request budget is exhausted")
    _atomic_public_json(path, {"month": month, "calls": count + 1})


async def permitted_observations(args: argparse.Namespace, *, now: int):
    expiry = validate_test_window(args.policy, now=now)
    if expiry - now < 120:
        raise PriceFeedError("test pricing window is ending")
    credentials = read_provider_credentials(args.provider_credentials)
    reserve_provider_call(args.usage_state, now=now)
    observations = await fetch_observations(now=now, credentials=credentials)
    return tuple(replace(item, valid_until=min(item.valid_until, expiry)) for item in observations)


def settings_for(roster: dict[str, Any], snapshot: Path) -> Settings:
    return Settings(
        _env_file=None, network="testnet11",
        payment_oracle_operator_pubkeys=roster["operatorPubkeys"],
        payment_oracle_rounds_path=str(snapshot),
    )


def _prior_sequence(settings: Settings) -> int:
    path = Path(settings.payment_oracle_rounds_path or "")
    prior = read_prior_snapshot(settings, path)
    return prior[1].round.sequence if prior else 0


async def collect(args: argparse.Namespace) -> dict[str, Any]:
    roster, keys = read_roster(args.roster)
    settings = settings_for(roster, args.snapshot)
    _check_config_owner(args.attestors)
    commands = read_json(args.attestors)
    if not isinstance(commands, list) or len(commands) != 2:
        raise PriceFeedError("two independently provisioned attestor commands are required")
    if any(not isinstance(c, list) or not c or any(not isinstance(a, str) for a in c) for c in commands):
        raise PriceFeedError("attestor command arguments are invalid")
    # These argv lists are root-owned deployment configuration, never request input.
    now = int(time.time())
    prior_sequence = _prior_sequence(settings)
    observations = await permitted_observations(args, now=now)
    sequence = max(prior_sequence + 1, now)
    candidate = candidate_round(observations=observations, pubkeys=keys, sequence=sequence, now=now)
    encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"))

    async def attest(command: list[str]) -> dict[str, Any]:
        # Output is a signature only. No shell evaluation or remote URLs in input.
        child = await asyncio.create_subprocess_exec(
            *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=MAX_INPUT_BYTES,
        )
        async def exchange() -> bytes:
            assert child.stdin is not None and child.stdout is not None
            child.stdin.write(encoded.encode())
            await child.stdin.drain()
            child.stdin.close()
            output = bytearray()
            while True:
                part = await child.stdout.read(4096)
                if not part:
                    break
                output.extend(part)
                if len(output) > MAX_INPUT_BYTES:
                    raise PriceFeedError("operator attestation exceeded its output bound")
            if await child.wait() != 0:
                raise PriceFeedError("operator did not attest the candidate")
            return bytes(output)
        try:
            output = await asyncio.wait_for(exchange(), timeout=35)
            return json.loads(output)
        except asyncio.TimeoutError:
            raise PriceFeedError("operator attestation timed out") from None
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    signatures = await asyncio.gather(*(attest(command) for command in commands))
    return publish_snapshot(settings, {"round": candidate, "signatures": signatures}, now=int(time.time()))


async def sign(args: argparse.Namespace) -> dict[str, Any]:
    _roster, keys = read_roster(args.roster)
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise PriceFeedError("candidate exceeded its input bound")
    candidate = json.loads(raw)
    prior = read_json(args.state) if args.state.exists() else {"sequence": 0, "roundHash": None}
    now = int(time.time())
    observations = await permitted_observations(args, now=now)
    attestation = attest_candidate(
        candidate, observations=observations, pubkeys=keys, key=read_key(args.key),
        signer_index=args.index, now=now, last_sequence=prior["sequence"], last_hash=prior["roundHash"],
    )
    round_ = oracle_round_from_json(candidate)
    # Record monotonic state before releasing the attestation to its publisher.
    _atomic_public_json(args.state, {"sequence": round_.sequence, "roundHash": "0x" + round_.round_hash.hex()})
    return attestation


def bridge() -> dict[str, Any]:
    """Forward only bounded public candidates to the fixed local attestor socket.

    A forced SSH command can run this without access to signing credentials.
    The socket service performs independent evidence and sequence validation.
    """
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise PriceFeedError("candidate input size is invalid")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect("/run/solslot-price-attestor/input.sock")
        connection.sendall(raw)
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > MAX_INPUT_BYTES:
                raise PriceFeedError("attestation response exceeded its bound")
    return json.loads(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bridge")
    for name in ("collect", "sign", "health"):
        command = commands.add_parser(name)
        command.add_argument("--roster", type=Path, required=True)
        command.add_argument("--lock", type=Path, required=True)
        if name == "sign":
            command.add_argument("--state", type=Path, required=True)
            command.add_argument("--key", type=Path, required=True)
            command.add_argument("--index", type=int, required=True, choices=(0, 1, 2))
        else:
            command.add_argument("--snapshot", type=Path, required=True)
        if name == "collect":
            command.add_argument("--attestors", type=Path, required=True)
        if name in ("collect", "sign"):
            command.add_argument("--policy", type=Path, required=True)
            command.add_argument("--provider-credentials", type=Path, required=True)
            command.add_argument("--usage-state", type=Path, required=True)
    args = parser.parse_args()
    descriptor: int | None = None
    try:
        if args.command == "bridge":
            result = bridge()
        else:
            descriptor = os.open(args.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "collect":
            result = asyncio.run(collect(args))
        elif args.command == "sign":
            result = asyncio.run(sign(args))
        elif args.command == "health":
            roster, _keys = read_roster(args.roster)
            usable = load_authorized_oracle_round(settings_for(roster, args.snapshot), asset_id=bytes32.zeros, now=int(time.time()))
            result = {"healthy": True, "sequence": usable.round.sequence, "validUntil": usable.round.valid_until}
        print(json.dumps(result, sort_keys=True))
        return 0
    except PriceFeedError as exc:
        print(json.dumps({"healthy": False, "errorCode": "price_feed_unavailable", "command": args.command, "detail": str(exc)[:200]}))
        return 1
    except Exception:
        # Journals must not contain credentials, source bodies or arbitrary stderr.
        print(json.dumps({"healthy": False, "errorCode": "price_feed_unavailable", "command": args.command}))
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
