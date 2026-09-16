"""Ceremony and post-genesis operator endpoints for Solslot API.

Run-once ceremony routes use ``SOLSLOT_ADMIN_TOKEN`` while the bootstrap is
unlocked. Post-genesis mutation routes require a short-lived JWT derived from
the current chain-bound admin records.

The active post-genesis surface is limited to authenticated bridge-pool
replenishment. Genesis coordinates are immutable and come only from the
threshold-signed V2 public artifact.
"""
from __future__ import annotations

import logging
import time
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from .admin_operations import require_admin_operation
from .config import Settings, get_settings
from .credential_auth import require_alpha_writes
from .public_artifact import PublicArtifactError, load_signed_public_artifact


# Heavy chia/CLVM imports are deferred to inside the request handlers
# to avoid binding chia_rs LazyNode instances to the import thread.  The
# admin endpoints are async and may be dispatched on different threads;
# touching these modules at import time triggered `LazyNode is unsendable`
# panics under starlette's TestClient + lifespan + dependency_overrides.
#
# DO NOT move these imports back to the top level.


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


_CREATE_COIN = 51
_RESERVE_FEE = 52


# ── Auth dependency ──────────────────────────────────────────────────────────
def require_admin_token(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[Optional[str], Header()] = None,
) -> None:
    """Guard for every admin endpoint.

    Returns 503 when no token is configured (admin disabled by default).
    Returns 401 when the Authorization header is missing or malformed.
    Returns 403 when the token doesn't match.
    """
    if not settings.ceremony_mode_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The one-time ceremony operator surface is disabled.",
        )
    if not settings.admin_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin endpoints are disabled (SOLSLOT_ADMIN_TOKEN unset).",
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header (expected 'Bearer <token>').",
        )
    presented = authorization.split(None, 1)[1].strip()
    # Constant-time compare
    import hmac
    if not hmac.compare_digest(presented, settings.admin_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin token.",
        )


# ── Helpers for app-state plumbing ───────────────────────────────────────────
def _get_app_state(name: str):
    """Lazy lookup of FastAPI app state attributes (faucet, coinset, etc.).

    We can't use Depends() here because admin needs the same app.state-bound
    objects that the rest of the app does (faucet, coinset).  Importing the
    app module at top-level would create a circular import; resolve it
    lazily via the request's app reference instead.
    """
    from .app import app  # local import: app.py imports admin.py
    return getattr(app.state, name, None)


def _faucet_or_503():
    f = _get_app_state("faucet")
    if f is None:
        raise HTTPException(
            status_code=503,
            detail="Faucet not configured — set SOLSLOT_FAUCET_* to enable deployment.",
        )
    return f


def _coinset_or_502():
    c = _get_app_state("coinset")
    if c is None:
        raise HTTPException(status_code=502, detail="Coinset client not initialised.")
    return c


def _spend_bundle_to_json(bundle) -> dict[str, Any]:
    if hasattr(bundle, "to_json_dict"):
        return bundle.to_json_dict()
    return {
        "coin_spends": [
            {
                "coin": {
                    "parent_coin_info": "0x" + bytes(cs.coin.parent_coin_info).hex(),
                    "puzzle_hash": "0x" + bytes(cs.coin.puzzle_hash).hex(),
                    "amount": cs.coin.amount,
                },
                "puzzle_reveal": "0x" + bytes(cs.puzzle_reveal).hex(),
                "solution": "0x" + bytes(cs.solution).hex(),
            }
            for cs in bundle.coin_spends
        ],
        "aggregated_signature": "0x" + bytes(bundle.aggregated_signature).hex(),
    }


def _coin_from_record(rec: dict):
    """Convert a coinset.org coin record into a chia ``Coin``.

    Imports lazily — see top-of-file note about LazyNode threading.
    """
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64

    payload = rec.get("coin") or rec
    return Coin(
        parent_coin_info=bytes32.fromhex(payload["parent_coin_info"].removeprefix("0x")),
        puzzle_hash=bytes32.fromhex(payload["puzzle_hash"].removeprefix("0x")),
        amount=uint64(int(payload["amount"])),
    )


# ── Schemas ──────────────────────────────────────────────────────────────────
class BridgePoolTopUpRequest(BaseModel):
    count: int = Field(6, ge=1, le=50)
    start_amount: int = Field(1, ge=1)
    fee: int = Field(0, ge=0)
    dry_run: bool = False
    source_coin_id: Optional[str] = None


class BridgePoolCoin(BaseModel):
    parentId: str
    bridgeAmount: int
    bridgeCoinId: str


class BridgePoolTopUpResponse(BaseModel):
    pushed: bool
    spend_bundle_id: Optional[str]
    source_coin_id: str
    bridgePolicyHash: str
    coins: list[BridgePoolCoin]
    push_status: Optional[Any] = None


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post(
    "/zkpassport/bridge-pool/top-up",
    response_model=BridgePoolTopUpResponse,
    dependencies=[Depends(require_admin_operation("bridge.top-up"))],
)
async def top_up_zkpassport_bridge_pool(
    body: BridgePoolTopUpRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> BridgePoolTopUpResponse:
    """Create a batch of Chia bridge coins for zkPassport enrollments.

    Each bridge coin is created at the configured bridge policy hash with a
    distinct positive amount.  The amount is part of the coin id and EVM
    attestation, so this lets a single faucet parent safely create many
    enrollable bridge coins without parent-id collisions.
    """
    if not body.dry_run:
        require_alpha_writes(settings)
    faucet = _faucet_or_503()
    coinset = _coinset_or_502()
    try:
        artifact = load_signed_public_artifact(settings)
        bridge_policy_hash = _normalize_32_byte_hex(
            artifact["bridgePolicy"]["policyHash"],
            "signed bridge policy hash",
        )
    except (KeyError, TypeError, PublicArtifactError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A valid signed V2 artifact is required for bridge replenishment.",
        ) from exc

    amounts = [body.start_amount + offset for offset in range(body.count)]
    total_required = sum(amounts) + body.fee
    coin_records = await coinset.get_coin_records_by_puzzle_hash(
        "0x" + faucet.address_puzzle_hash.hex(), include_spent=False
    )
    unspent = [
        _coin_from_record(rec)
        for rec in coin_records
        if rec.get("spent_block_index") in (0, None)
    ]
    if body.source_coin_id is None:
        reserved = faucet.reserved_coin_ids()
        unspent = [coin for coin in unspent if coin.name() not in reserved]

    if body.source_coin_id is None and settings.faucet_max_spend_mojos > 0:
        unspent = [coin for coin in unspent if int(coin.amount) <= settings.faucet_max_spend_mojos]

    source_coin = _select_coin_by_id(
        unspent,
        body.source_coin_id,
        total_required,
        "bridge_pool_source_coin",
    )
    faucet.require_unreserved_coin(source_coin)
    bridge_policy_b32 = _bytes32_from_hex(bridge_policy_hash)
    coins = [
        BridgePoolCoin(
            parentId="0x" + bytes(source_coin.name()).hex(),
            bridgeAmount=amount,
            bridgeCoinId=_coin_id_from_fields(source_coin.name(), bridge_policy_b32, amount),
        )
        for amount in amounts
    ]

    if body.dry_run:
        return BridgePoolTopUpResponse(
            pushed=False,
            spend_bundle_id=None,
            source_coin_id="0x" + bytes(source_coin.name()).hex(),
            bridgePolicyHash=bridge_policy_hash,
            coins=coins,
        )

    spend_bundle = _build_single_coin_create_bundle(
        faucet=faucet,
        source_coin=source_coin,
        outputs=[(bridge_policy_b32, amount) for amount in amounts],
        change_puzzle_hash=faucet.address_puzzle_hash,
        fee=body.fee,
    )
    try:
        push_result = await coinset.push_tx(_spend_bundle_to_json(spend_bundle))
    except Exception as exc:
        logger.exception("zkPassport bridge pool push_tx failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail=f"Bridge pool top-up was rejected by Coinset: {exc}",
        ) from exc

    if not push_result.get("success"):
        status_msg = push_result.get("status") or push_result.get("error") or push_result
        logger.warning("Bridge pool top-up push_tx returned non-success: %s", status_msg)
        raise HTTPException(
            status_code=502,
            detail=f"Bridge pool top-up bundle was rejected: {status_msg}",
        )

    return BridgePoolTopUpResponse(
        pushed=True,
        spend_bundle_id="0x" + bytes(spend_bundle.name()).hex(),
        source_coin_id="0x" + bytes(source_coin.name()).hex(),
        bridgePolicyHash=bridge_policy_hash,
        coins=coins,
        push_status=push_result,
    )


def _normalize_32_byte_hex(value: str, label: str) -> str:
    raw = value.strip()
    if raw.startswith("0X"):
        raw = "0x" + raw[2:]
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 64:
        raise HTTPException(status_code=400, detail=f"{label} must be a 32-byte hex string.")
    try:
        bytes.fromhex(raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"{label} must be hex.") from e
    return "0x" + raw.lower()


def _select_coin_by_id(
    candidates: list, coin_id: Optional[str], min_amount: int, label: str
):
    """Pick a coin from ``candidates`` by name (if ``coin_id`` is given) or
    smallest-amount-that-meets-min_amount otherwise.

    Removes the selected coin from ``candidates`` (in-place) so the caller
    doesn't pick the same coin twice across multiple invocations.
    """
    from chia_rs.sized_bytes import bytes32

    if coin_id is not None:
        target = bytes32.fromhex(coin_id.removeprefix("0x"))
        for i, c in enumerate(candidates):
            if c.name() == target:
                if c.amount < min_amount:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"{label}: coin {coin_id} has amount {c.amount} < "
                            f"required {min_amount}"
                        ),
                    )
                candidates.pop(i)
                return c
        raise HTTPException(
            status_code=404,
            detail=f"{label}: coin {coin_id} is not an unspent faucet coin.",
        )

    # Smallest-coin-that-fits selection
    fitting = sorted(
        (c for c in candidates if c.amount >= min_amount),
        key=lambda c: c.amount,
    )
    if not fitting:
        raise HTTPException(
            status_code=503,
            detail=(
                f"{label}: no unspent faucet coin with amount ≥ {min_amount}. "
                "Top up the faucet from a testnet11 faucet or specify "
                f"{label}_id explicitly."
            ),
        )
    chosen = fitting[0]
    candidates.remove(chosen)
    return chosen


def _bytes32_from_hex(value: str):
    from chia_rs.sized_bytes import bytes32

    return bytes32.fromhex(value.removeprefix("0x"))


def _coin_id_from_fields(parent_id, puzzle_hash, amount: int) -> str:
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64

    parent = bytes32(parent_id) if isinstance(parent_id, (bytes, bytearray)) else parent_id
    puzzle = bytes32(puzzle_hash) if isinstance(puzzle_hash, (bytes, bytearray)) else puzzle_hash
    coin = Coin(parent_coin_info=parent, puzzle_hash=puzzle, amount=uint64(amount))
    return "0x" + bytes(coin.name()).hex()


def _build_single_coin_create_bundle(
    *,
    faucet,
    source_coin,
    outputs: list[tuple[object, int]],
    change_puzzle_hash,
    fee: int,
):
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    from chia_rs import G2Element, SpendBundle

    faucet.require_spend_purpose("bridge-top-up")

    total_outputs = sum(int(amount) for _, amount in outputs)
    change = int(source_coin.amount) - total_outputs - fee
    if change < 0:
        raise HTTPException(
            status_code=400,
            detail="bridge_pool_source_coin does not have enough mojo for outputs and fee.",
        )

    conditions_list = [
        Program.to([_CREATE_COIN, puzzle_hash, int(amount)])
        for puzzle_hash, amount in outputs
    ]
    if change > 0:
        conditions_list.append(Program.to([_CREATE_COIN, change_puzzle_hash, change]))
    if fee > 0:
        conditions_list.append(Program.to([_RESERVE_FEE, fee]))

    conditions = Program.to(conditions_list)
    delegated_puzzle = Program.to((1, conditions))
    solution = Program.to([0, delegated_puzzle, Program.to(0)])
    coin_spend = make_spend(source_coin, faucet.key.puzzle, solution)
    signature = G2Element.from_bytes(faucet.sign_delegated_spend(
        source_coin, conditions, purpose="bridge-top-up",
    ))
    return SpendBundle([coin_spend], signature)


__all__ = ["router", "require_admin_token"]
