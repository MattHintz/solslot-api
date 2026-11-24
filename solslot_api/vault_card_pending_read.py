"""One Testnet card order's pending-spend observation on the private node."""
import asyncio
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .coinset_client import CoinsetClient
from .generation_primary_reader import HEX32, PrimaryReadClient, decode_request

SCOPE_FILE = Path("/etc/solslot-validator/vault-card-pending-read.json")
SCHEMA = "solslot.vault-card-pending-read.v1"
ROUTE = "/v1/generation/chain/vault-card/pending"


async def native_coin_pending(primary, coin_id):
    if not isinstance(coin_id, str) or not HEX32.fullmatch(coin_id):
        raise ValueError("Invalid named coin")
    reply = await primary._post("/get_mempool_items_by_coin_name", {"coin_name": coin_id})
    if (type(reply) is not dict or reply.get("success") is not True
            or type(reply.get("mempool_items")) is not list):
        raise ValueError("Primary pending observation unavailable")
    return bool(reply["mempool_items"])


@dataclass(frozen=True)
class ReadLease:
    releaseId: str
    purchaseId: str
    validFrom: int
    admissionEnds: int
    readUntil: int
    signerIndices: list[int]

    def check(self):
        if (not all(isinstance(v, str) and HEX32.fullmatch(v) for v in (self.releaseId, self.purchaseId))
                or any(type(v) is not int for v in (self.validFrom, self.admissionEnds, self.readUntil))
                or self.validFrom <= 0 or self.admissionEnds - self.validFrom != 7200
                or not self.admissionEnds < self.readUntil <= self.validFrom + 86400
                or self.signerIndices != [0, 1] or any(type(i) is not int for i in self.signerIndices)):
            raise ValueError("Invalid private Testnet card read lease")
        return self


def installed_lease():
    for parent in SCOPE_FILE.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unprotected private reader policy directory")
    with os.fdopen(os.open(SCOPE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        info = os.fstat(f.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not 0 < info.st_size <= 1024):
            raise ValueError("Unprotected private reader policy")
        return ReadLease(**json.loads(f.read(1025))).check()


def register(app, provider, slots, *, lease=None, clock=time.time):
    lease = installed_lease if lease is None else lease
    @app.post(ROUTE)
    async def card_coin_pending(request: Request):
        host = request.client.host if request.client else None
        if host not in ("10.77.0.10", "10.77.0.11"):
            raise HTTPException(403, "Named card reader not enrolled")
        try:
            policy = lease()
            if not isinstance(policy, ReadLease):
                raise ValueError
            policy.check()
            if host not in {f"10.77.0.{10+i}" for i in policy.signerIndices} or not policy.validFrom <= clock() < policy.readUntil:
                raise ValueError
        except (OSError, ValueError, TypeError, KeyError):
            raise HTTPException(403, "Card read lease unavailable") from None
        try:
            raw = bytearray()
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > 512:
                        raise ValueError
                    raw.extend(chunk)
            body = decode_request(bytes(raw))
            if (type(body) is not dict or set(body) != {"releaseId", "purchaseId", "coinId"}
                    or body["releaseId"] != policy.releaseId or body["purchaseId"] != policy.purchaseId
                    or not isinstance(body["coinId"], str) or not HEX32.fullmatch(body["coinId"])):
                raise ValueError
        except (TypeError, ValueError, TimeoutError):
            raise HTTPException(400, "Invalid named card read") from None
        try:
            async with asyncio.timeout(12), slots:
                network, state = await asyncio.gather(provider.get_network_info_primary(), provider.get_blockchain_state_primary())
                if network.get("network_name") != "testnet11" or state["blockchain_state"]["sync"]["synced"] is not True:
                    raise ValueError
                # Read the native envelope before any adapter can normalize missing data into an empty list.
                pending = await native_coin_pending(provider.primary, body["coinId"])
            if lease().check() != policy or not policy.validFrom <= clock() < policy.readUntil:
                raise ValueError
            return JSONResponse({"schema": SCHEMA, **body, "pending": pending,
                                 "readUntil": policy.readUntil}, headers={"Cache-Control": "no-store"})
        except Exception:
            raise HTTPException(503, "Primary card observation unavailable") from None


async def card_coin_pending(primary, order, coin_id):
    if not isinstance(primary, PrimaryReadClient):
        if isinstance(primary, CoinsetClient):
            return await native_coin_pending(primary, coin_id)
        rows = await primary.get_mempool_items_by_coin_name(coin_id)
        if type(rows) is not list:
            raise ValueError("Primary pending observation unavailable")
        return bool(rows)
    request = {"releaseId": order.release_id, "purchaseId": order.purchase_id, "coinId": coin_id}
    response = await primary.card_pending_read(request)
    if (type(response) is not dict or set(response) != {"schema", *request, "pending", "readUntil"}
            or response["schema"] != SCHEMA or any(response[k] != v for k, v in request.items())
            or type(response["pending"]) is not bool or type(response["readUntil"]) is not int
            or response["readUntil"] <= max(order.expires_at, time.time())):
        raise ValueError("Invalid private card pending observation")
    return response["pending"]
