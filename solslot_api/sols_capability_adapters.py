"""Reviewed transaction builders for governed Sols bridge and liquidity routes.

The protocol statutes decide which route or venue is trusted.  The signed
release evidence supplies the chain-specific execution coordinates.  These
builders deliberately accept neither contracts nor fee recipients from the
browser.
"""
from __future__ import annotations

from dataclasses import dataclass
from time import time
from typing import Any, Literal, Mapping, Sequence

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address


MAX_UINT256 = (1 << 256) - 1
MAX_DEADLINE_SECONDS = 30 * 60
BridgeDirection = Literal["CHIA_TO_EVM", "EVM_TO_CHIA"]
LiquidityAction = Literal["ADD", "REMOVE", "COLLECT"]


class SolsCapabilityAdapterError(ValueError):
    """Raised when an intent cannot be bound to reviewed adapter evidence."""


@dataclass(frozen=True)
class EvmTransaction:
    chain_id: int
    to: str
    value: str
    data: str
    purpose: str

    def as_dict(self) -> dict[str, str | int]:
        return {
            "chainId": self.chain_id,
            "to": self.to,
            "value": self.value,
            "data": self.data,
            "purpose": self.purpose,
        }


@dataclass(frozen=True)
class WalletOfferAsset:
    asset_id: str | None
    amount: str

    def as_dict(self) -> dict[str, str | None]:
        return {"assetId": self.asset_id, "amount": self.amount}


def build_warp_bridge_intent(
    *,
    descriptor: Mapping[str, Any],
    direction: BridgeDirection,
    amount_mojos: str,
    destination: str,
) -> dict[str, Any]:
    """Build the stable Warp surface without copying its validator protocol.

    EVM-to-Chia is a direct call to the immutable WrappedCAT contract.  The
    Chia-to-EVM leg uses a wallet offer and the official Warp completion
    surface because the locker, security coin, portal message, and validator
    relay must remain the reviewed Warp implementation.
    """

    _require_kind(descriptor, "WARP_CAT")
    amount = _positive_decimal(amount_mojos, "amountMojos")
    adapter_id = _nonempty(descriptor.get("adapterId"), "adapterId")
    explorer_template = _https_template(
        descriptor.get("explorerUrlTemplate"),
        "explorerUrlTemplate",
        required_token="{operationId}",
    )

    transfer_preview: dict[str, Any] = {}
    confirmation = descriptor.get("confirmation")
    if isinstance(confirmation, Mapping):
        tip_bps = _positive_int(confirmation.get("tipBps"), "tipBps")
        ratio = _positive_int(confirmation.get("mojoToTokenRatio"), "mojoToTokenRatio")
        destination_amount = amount if direction == "EVM_TO_CHIA" else amount * ratio
        tip = destination_amount * tip_bps // 10_000
        if direction == "EVM_TO_CHIA":
            tip = max(1, tip)
        if tip <= 0 or destination_amount <= tip:
            raise SolsCapabilityAdapterError("bridge amount is below the transfer-tip minimum")
        transfer_preview = {
            "expectedReceivedMinor": str(destination_amount - tip),
            "transferTipMinor": str(tip),
            "destinationDecimals": 3 if direction == "EVM_TO_CHIA" else 18,
        }

    if direction == "EVM_TO_CHIA":
        receiver = _bytes32(destination, "destination puzzle hash")
        chain_id = _positive_int(descriptor.get("evmChainId"), "evmChainId")
        wrapped_cat = _address(descriptor.get("wrappedCat"), "wrappedCat")
        message_toll = _nonnegative_decimal(
            descriptor.get("messageTollWei"),
            "messageTollWei",
        )
        data = _calldata(
            "bridgeBack(bytes32,uint256)",
            ["bytes32", "uint256"],
            [bytes.fromhex(receiver[2:]), amount],
        )
        return {
            "schemaVersion": 1,
            "adapterId": adapter_id,
            "direction": direction,
            **transfer_preview,
            "executionMode": "EVM_TRANSACTION",
            "amountMojos": str(amount),
            "destination": receiver,
            "transactions": [
                EvmTransaction(
                    chain_id=chain_id,
                    to=wrapped_cat,
                    value=str(message_toll),
                    data=data,
                    purpose="Burn wSOLS and request the exact Sols payout on Chia.",
                ).as_dict()
            ],
            "explorerUrlTemplate": explorer_template,
        }

    if direction != "CHIA_TO_EVM":
        raise SolsCapabilityAdapterError("unsupported Warp bridge direction")
    destination_address = _address(destination, "destination EVM address")
    toll_mojos = _positive_decimal(
        descriptor.get("chiaMessageTollMojos"),
        "chiaMessageTollMojos",
    )
    sols_asset_id = _bytes32(descriptor.get("solsAssetId"), "solsAssetId")
    handoff_template = _https_template(
        descriptor.get("officialHandoffUrlTemplate"),
        "officialHandoffUrlTemplate",
        required_token="{destination}",
    )
    handoff_url = (
        handoff_template.replace("{destination}", destination_address)
        .replace("{amountMojos}", str(amount))
        .replace("{assetId}", sols_asset_id)
    )
    return {
        "schemaVersion": 1,
        "adapterId": adapter_id,
        "direction": direction,
        **transfer_preview,
        "executionMode": "OFFICIAL_WARP_OFFER",
        "amountMojos": str(amount),
        "destination": destination_address,
        "walletOffer": {
            "offer": [
                WalletOfferAsset(
                    asset_id=sols_asset_id,
                    amount=str(amount),
                ).as_dict(),
                WalletOfferAsset(
                    asset_id=None,
                    amount=str(toll_mojos),
                ).as_dict(),
            ],
            "request": [],
            "feeIsSeparate": True,
        },
        "handoffUrl": handoff_url,
        "explorerUrlTemplate": explorer_template,
    }


def build_aerodrome_liquidity_intent(
    *,
    descriptor: Mapping[str, Any],
    action: LiquidityAction,
    account: str,
    amount_a: str,
    amount_b: str,
    liquidity: str,
    min_a: str,
    min_b: str,
    deadline_seconds: int,
) -> dict[str, Any]:
    """Build exact Aerodrome Router approval and liquidity transactions."""

    _require_kind(descriptor, "AERODROME_V1")
    chain_id = _positive_int(descriptor.get("evmChainId"), "evmChainId")
    router = _address(descriptor.get("router"), "router")
    factory = _address(descriptor.get("factory"), "factory")
    token_a = _address(descriptor.get("tokenA"), "tokenA")
    token_b = _address(descriptor.get("tokenB"), "tokenB")
    pool = _address(descriptor.get("pool"), "pool")
    recipient = _address(account, "account")
    stable = _strict_bool(descriptor.get("stable"), "stable")
    deadline = int(time()) + _deadline_duration(deadline_seconds)
    amount_a_value = _nonnegative_decimal(amount_a, "amountA")
    amount_b_value = _nonnegative_decimal(amount_b, "amountB")
    liquidity_value = _nonnegative_decimal(liquidity, "liquidity")
    min_a_value = _nonnegative_decimal(min_a, "minimum amount A")
    min_b_value = _nonnegative_decimal(min_b, "minimum amount B")

    transactions: list[EvmTransaction]
    if action == "ADD":
        if amount_a_value <= 0 or amount_b_value <= 0:
            raise SolsCapabilityAdapterError("both deposit amounts must be positive")
        transactions = [
            _approval(chain_id, token_a, router, amount_a_value, "Approve token A."),
            _approval(chain_id, token_b, router, amount_b_value, "Approve token B."),
            EvmTransaction(
                chain_id=chain_id,
                to=router,
                value="0",
                data=_calldata(
                    "addLiquidity(address,address,bool,uint256,uint256,uint256,uint256,address,uint256)",
                    [
                        "address",
                        "address",
                        "bool",
                        "uint256",
                        "uint256",
                        "uint256",
                        "uint256",
                        "address",
                        "uint256",
                    ],
                    [
                        token_a,
                        token_b,
                        stable,
                        amount_a_value,
                        amount_b_value,
                        min_a_value,
                        min_b_value,
                        recipient,
                        deadline,
                    ],
                ),
                purpose="Add the reviewed token pair to the governed Aerodrome pool.",
            ),
        ]
    elif action == "REMOVE":
        if liquidity_value <= 0:
            raise SolsCapabilityAdapterError("liquidity amount must be positive")
        transactions = [
            _approval(chain_id, pool, router, liquidity_value, "Approve LP tokens."),
            EvmTransaction(
                chain_id=chain_id,
                to=router,
                value="0",
                data=_calldata(
                    "removeLiquidity(address,address,bool,uint256,uint256,uint256,address,uint256)",
                    [
                        "address",
                        "address",
                        "bool",
                        "uint256",
                        "uint256",
                        "uint256",
                        "address",
                        "uint256",
                    ],
                    [
                        token_a,
                        token_b,
                        stable,
                        liquidity_value,
                        min_a_value,
                        min_b_value,
                        recipient,
                        deadline,
                    ],
                ),
                purpose="Remove liquidity from the exact governed Aerodrome pool.",
            ),
        ]
    elif action == "COLLECT":
        raise SolsCapabilityAdapterError(
            "Aerodrome V1 fees accrue into the fungible LP position; "
            "there is no separate collect transaction"
        )
    else:
        raise SolsCapabilityAdapterError("unsupported Aerodrome action")

    return _liquidity_result(descriptor, action, transactions, factory, pool)


def build_uniswap_v3_liquidity_intent(
    *,
    descriptor: Mapping[str, Any],
    action: LiquidityAction,
    account: str,
    amount_a: str,
    amount_b: str,
    liquidity: str,
    min_a: str,
    min_b: str,
    token_id: str | None,
    tick_lower: int | None,
    tick_upper: int | None,
    deadline_seconds: int,
) -> dict[str, Any]:
    """Build exact Uniswap V3 position-manager transactions."""

    _require_kind(descriptor, "UNISWAP_V3")
    chain_id = _positive_int(descriptor.get("evmChainId"), "evmChainId")
    manager = _address(descriptor.get("positionManager"), "positionManager")
    factory = _address(descriptor.get("factory"), "factory")
    token_a = _address(descriptor.get("tokenA"), "tokenA")
    token_b = _address(descriptor.get("tokenB"), "tokenB")
    pool = _address(descriptor.get("pool"), "pool")
    recipient = _address(account, "account")
    fee = _bounded_int(descriptor.get("fee"), "fee", 1, 1_000_000)
    tick_spacing = _bounded_int(
        descriptor.get("tickSpacing"),
        "tickSpacing",
        1,
        1_000_000,
    )
    deadline = int(time()) + _deadline_duration(deadline_seconds)
    amount_a_value = _nonnegative_decimal(amount_a, "amountA")
    amount_b_value = _nonnegative_decimal(amount_b, "amountB")
    min_a_value = _nonnegative_decimal(min_a, "minimum amount A")
    min_b_value = _nonnegative_decimal(min_b, "minimum amount B")

    if action == "ADD":
        if amount_a_value <= 0 or amount_b_value <= 0:
            raise SolsCapabilityAdapterError("both deposit amounts must be positive")
        if tick_lower is None or tick_upper is None:
            raise SolsCapabilityAdapterError("a reviewed price range is required")
        if (
            tick_lower >= tick_upper
            or tick_lower % tick_spacing != 0
            or tick_upper % tick_spacing != 0
        ):
            raise SolsCapabilityAdapterError(
                "price range does not match the governed pool tick spacing"
            )
        token0, token1, amount0, amount1, minimum0, minimum1 = _sort_pair(
            token_a,
            token_b,
            amount_a_value,
            amount_b_value,
            min_a_value,
            min_b_value,
        )
        mint_tuple = (
            token0,
            token1,
            fee,
            tick_lower,
            tick_upper,
            amount0,
            amount1,
            minimum0,
            minimum1,
            recipient,
            deadline,
        )
        transactions = [
            _approval(chain_id, token_a, manager, amount_a_value, "Approve token A."),
            _approval(chain_id, token_b, manager, amount_b_value, "Approve token B."),
            EvmTransaction(
                chain_id=chain_id,
                to=manager,
                value="0",
                data=_calldata(
                    "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
                    [
                        "(address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256)"
                    ],
                    [mint_tuple],
                ),
                purpose="Mint a position in the exact governed Uniswap V3 pool.",
            ),
        ]
    elif action == "REMOVE":
        position_id = _positive_decimal(token_id, "tokenId")
        liquidity_value = _positive_decimal(liquidity, "liquidity")
        _, _, _, _, minimum0, minimum1 = _sort_pair(
            token_a,
            token_b,
            0,
            0,
            min_a_value,
            min_b_value,
        )
        transactions = [
            EvmTransaction(
                chain_id=chain_id,
                to=manager,
                value="0",
                data=_calldata(
                    "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
                    ["(uint256,uint128,uint256,uint256,uint256)"],
                    [
                        (
                            position_id,
                            liquidity_value,
                            minimum0,
                            minimum1,
                            deadline,
                        )
                    ],
                ),
                purpose="Remove liquidity from the selected governed position.",
            ),
            _uniswap_collect(chain_id, manager, position_id, recipient),
        ]
    elif action == "COLLECT":
        position_id = _positive_decimal(token_id, "tokenId")
        transactions = [_uniswap_collect(chain_id, manager, position_id, recipient)]
    else:
        raise SolsCapabilityAdapterError("unsupported Uniswap action")

    return _liquidity_result(descriptor, action, transactions, factory, pool)


def build_tibetswap_liquidity_intent(
    *,
    descriptor: Mapping[str, Any],
    action: LiquidityAction,
    amount_xch_mojos: str,
    amount_cat_mojos: str,
    liquidity_mojos: str,
) -> dict[str, Any]:
    """Describe the exact TibetSwap offer a connected Chia wallet must make."""

    _require_kind(descriptor, "TIBETSWAP_V2")
    if action not in {"ADD", "REMOVE"}:
        raise SolsCapabilityAdapterError(
            "TibetSwap fees accrue into the LP CAT; there is no collect action"
        )
    pair_id = _bytes32(descriptor.get("pairLauncherId"), "pairLauncherId")
    cat_asset_id = _bytes32(descriptor.get("tokenA"), "tokenA")
    liquidity_asset_id = _bytes32(
        descriptor.get("liquidityAssetId"),
        "liquidityAssetId",
    )
    api_origin = _https_origin(descriptor.get("officialApiOrigin"), "officialApiOrigin")
    xch = _positive_decimal(amount_xch_mojos, "amountXchMojos")
    cat = _positive_decimal(amount_cat_mojos, "amountCatMojos")
    lp = _positive_decimal(liquidity_mojos, "liquidityMojos")
    xch_asset = WalletOfferAsset(asset_id=None, amount=str(xch)).as_dict()
    cat_asset = WalletOfferAsset(asset_id=cat_asset_id, amount=str(cat)).as_dict()
    lp_asset = WalletOfferAsset(asset_id=liquidity_asset_id, amount=str(lp)).as_dict()
    if action == "ADD":
        offer, request = [xch_asset, cat_asset], [lp_asset]
        tibet_action = "ADD_LIQUIDITY"
    else:
        offer, request = [lp_asset], [xch_asset, cat_asset]
        tibet_action = "REMOVE_LIQUIDITY"
    return {
        "schemaVersion": 1,
        "adapterId": _nonempty(descriptor.get("adapterId"), "adapterId"),
        "venueId": _bytes32(descriptor.get("recordId"), "recordId"),
        "action": action,
        "executionMode": "CHIA_WALLET_OFFER",
        "pairLauncherId": pair_id,
        "walletOffer": {"offer": offer, "request": request},
        "submission": {
            "method": "POST",
            "url": f"{api_origin}/offer/{pair_id[2:]}",
            "action": tibet_action,
            "donationAmount": "0",
        },
    }


def descriptor_for_record(
    descriptors: Sequence[Mapping[str, Any]],
    *,
    record_id: str,
) -> Mapping[str, Any]:
    normalized = _bytes32(record_id, "recordId")
    matches = [
        value
        for value in descriptors
        if _bytes32(value.get("recordId"), "adapter recordId") == normalized
    ]
    if len(matches) != 1:
        raise SolsCapabilityAdapterError(
            "exactly one reviewed adapter must match the governed record"
        )
    return matches[0]


def validate_adapter_descriptor(descriptor: Mapping[str, Any]) -> None:
    """Exercise every supported path with bounded fixture values.

    This runs while release evidence is loaded so a malformed descriptor can
    never pass readiness and fail only after a customer starts an action.
    """

    kind = descriptor.get("kind")
    if kind == "WARP_CAT":
        _address(descriptor.get("warpPortal"), "warpPortal")
        _address(descriptor.get("assetRegistry"), "assetRegistry")
        _runtime_code_hashes(
            descriptor,
            ("wrappedCat", "warpPortal", "assetRegistry"),
        )
        build_warp_bridge_intent(
            descriptor=descriptor,
            direction="CHIA_TO_EVM",
            amount_mojos="10000",
            destination="0x1111111111111111111111111111111111111111",
        )
        build_warp_bridge_intent(
            descriptor=descriptor,
            direction="EVM_TO_CHIA",
            amount_mojos="10000",
            destination="0x" + "11" * 32,
        )
    elif kind == "AERODROME_V1":
        _runtime_code_hashes(
            descriptor,
            ("router", "factory", "pool", "tokenA", "tokenB"),
        )
        build_aerodrome_liquidity_intent(
            descriptor=descriptor,
            action="ADD",
            account="0x1111111111111111111111111111111111111111",
            amount_a="1",
            amount_b="1",
            liquidity="0",
            min_a="0",
            min_b="0",
            deadline_seconds=60,
        )
    elif kind == "UNISWAP_V3":
        _runtime_code_hashes(
            descriptor,
            ("positionManager", "factory", "pool", "tokenA", "tokenB"),
        )
        build_uniswap_v3_liquidity_intent(
            descriptor=descriptor,
            action="COLLECT",
            account="0x1111111111111111111111111111111111111111",
            amount_a="0",
            amount_b="0",
            liquidity="0",
            min_a="0",
            min_b="0",
            token_id="1",
            tick_lower=None,
            tick_upper=None,
            deadline_seconds=60,
        )
    elif kind == "TIBETSWAP_V2":
        _runtime_code_hashes(descriptor, ("pair",))
        build_tibetswap_liquidity_intent(
            descriptor=descriptor,
            action="ADD",
            amount_xch_mojos="1",
            amount_cat_mojos="1",
            liquidity_mojos="1",
        )
    else:
        raise SolsCapabilityAdapterError(
            "reviewed adapter kind is not supported by this release"
        )
    public_adapter_profile(descriptor)


def validate_adapter_governance_binding(
    descriptor: Mapping[str, Any],
    governed_record: Mapping[str, Any],
) -> None:
    """Bind runtime execution coordinates to the exact statutes record."""

    record_id = str(
        governed_record.get("routeId") or governed_record.get("venueId") or ""
    )
    if _bytes32(descriptor.get("recordId"), "adapter recordId") != _bytes32(
        record_id,
        "governed record ID",
    ):
        raise SolsCapabilityAdapterError(
            "runtime adapter targets a different governed record"
        )

    kind = descriptor.get("kind")
    if kind == "WARP_CAT":
        expected = {
            "sourceChainId": _bytes32(descriptor.get("chiaChainId"), "chiaChainId"),
            "destinationChainId": _chain_id32(
                descriptor.get("evmChainId"),
                "evmChainId",
            ),
            "assetId": _bytes32(descriptor.get("solsAssetId"), "solsAssetId"),
            "remoteAssetId": _identifier32(
                descriptor.get("wrappedCat"),
                "wrappedCat",
            ),
        }
        for key, value in expected.items():
            if _bytes32(governed_record.get(key), key) != value:
                raise SolsCapabilityAdapterError(
                    f"runtime adapter {key} does not match governance"
                )
        if _bounded_int(
            governed_record.get("decimals"),
            "governed decimals",
            0,
            18,
        ) != _display_decimals(descriptor.get("assetDecimals"), "assetDecimals"):
            raise SolsCapabilityAdapterError(
                "runtime adapter decimals do not match governance"
            )
        return

    chain_id = (
        _bytes32(descriptor.get("chiaChainId"), "chiaChainId")
        if kind == "TIBETSWAP_V2"
        else _chain_id32(descriptor.get("evmChainId"), "evmChainId")
    )
    if _bytes32(governed_record.get("chainId"), "chainId") != chain_id:
        raise SolsCapabilityAdapterError(
            "runtime adapter chain does not match governance"
        )

    if kind in {"AERODROME_V1", "UNISWAP_V3"}:
        factory = _identifier32(descriptor.get("factory"), "factory")
        pool = _identifier32(descriptor.get("pool"), "pool")
        base_asset = _identifier32(descriptor.get("tokenA"), "tokenA")
        quote_asset = _identifier32(descriptor.get("tokenB"), "tokenB")
    elif kind == "TIBETSWAP_V2":
        factory = _bytes32(descriptor.get("factoryId"), "factoryId")
        pool = _bytes32(descriptor.get("pairLauncherId"), "pairLauncherId")
        base_asset = _bytes32(descriptor.get("tokenA"), "tokenA")
        quote_asset = _bytes32(descriptor.get("quoteAssetId"), "quoteAssetId")
    else:
        raise SolsCapabilityAdapterError(
            "reviewed liquidity adapter kind is unsupported"
        )

    for key, value in (
        ("factoryId", factory),
        ("poolId", pool),
        ("baseAssetId", base_asset),
        ("quoteAssetId", quote_asset),
    ):
        if _bytes32(governed_record.get(key), key) != value:
            raise SolsCapabilityAdapterError(
                f"runtime adapter {key} does not match governance"
            )
    pool_code_hash = _runtime_code_hashes(
        descriptor,
        (
            ("pair",)
            if kind == "TIBETSWAP_V2"
            else ("pool",)
        ),
    )["pair" if kind == "TIBETSWAP_V2" else "pool"]
    if _bytes32(
        governed_record.get("poolCodeHash"),
        "poolCodeHash",
    ) != pool_code_hash:
        raise SolsCapabilityAdapterError(
            "runtime adapter pool code hash does not match governance"
        )


def public_adapter_profile(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    """Return only display metadata needed for ordinary-unit customer forms."""

    kind = _nonempty(descriptor.get("kind"), "kind")
    profile: dict[str, Any] = {
        "adapterKind": kind,
        "networkLabel": _nonempty(
            descriptor.get("networkLabel"),
            "networkLabel",
        ),
    }
    if kind == "WARP_CAT":
        profile.update(
            {
                "assetSymbol": _asset_symbol(
                    descriptor.get("assetSymbol"),
                    "assetSymbol",
                ),
                "assetDecimals": _display_decimals(
                    descriptor.get("assetDecimals"),
                    "assetDecimals",
                ),
                "supportedDirections": ["CHIA_TO_EVM", "EVM_TO_CHIA"],
            }
        )
        return profile
    profile.update(
        {
            "baseSymbol": _asset_symbol(
                descriptor.get("baseSymbol"),
                "baseSymbol",
            ),
            "baseDecimals": _display_decimals(
                descriptor.get("baseDecimals"),
                "baseDecimals",
            ),
            "quoteSymbol": _asset_symbol(
                descriptor.get("quoteSymbol"),
                "quoteSymbol",
            ),
            "quoteDecimals": _display_decimals(
                descriptor.get("quoteDecimals"),
                "quoteDecimals",
            ),
            "liquidityDecimals": _display_decimals(
                descriptor.get("liquidityDecimals"),
                "liquidityDecimals",
            ),
            "supportedActions": (
                ["ADD", "REMOVE", "COLLECT"]
                if kind == "UNISWAP_V3"
                else ["ADD", "REMOVE"]
            ),
        }
    )
    return profile


def _liquidity_result(
    descriptor: Mapping[str, Any],
    action: LiquidityAction,
    transactions: Sequence[EvmTransaction],
    factory: str,
    pool: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "adapterId": _nonempty(descriptor.get("adapterId"), "adapterId"),
        "venueId": _bytes32(descriptor.get("recordId"), "recordId"),
        "action": action,
        "executionMode": "EVM_TRANSACTIONS",
        "factory": factory,
        "pool": pool,
        "transactions": [item.as_dict() for item in transactions],
    }


def _uniswap_collect(
    chain_id: int,
    manager: str,
    token_id: int,
    recipient: str,
) -> EvmTransaction:
    return EvmTransaction(
        chain_id=chain_id,
        to=manager,
        value="0",
        data=_calldata(
            "collect((uint256,address,uint128,uint128))",
            ["(uint256,address,uint128,uint128)"],
            [(token_id, recipient, (1 << 128) - 1, (1 << 128) - 1)],
        ),
        purpose="Collect the position's currently earned token fees.",
    )


def _approval(
    chain_id: int,
    token: str,
    spender: str,
    amount: int,
    purpose: str,
) -> EvmTransaction:
    return EvmTransaction(
        chain_id=chain_id,
        to=token,
        value="0",
        data=_calldata(
            "approve(address,uint256)",
            ["address", "uint256"],
            [spender, amount],
        ),
        purpose=purpose,
    )


def _calldata(signature: str, types: list[str], values: list[Any]) -> str:
    return "0x" + (keccak(text=signature)[:4] + abi_encode(types, values)).hex()


def _sort_pair(
    token_a: str,
    token_b: str,
    amount_a: int,
    amount_b: int,
    min_a: int,
    min_b: int,
) -> tuple[str, str, int, int, int, int]:
    if int(token_a, 16) < int(token_b, 16):
        return token_a, token_b, amount_a, amount_b, min_a, min_b
    return token_b, token_a, amount_b, amount_a, min_b, min_a


def _deadline_duration(seconds: int) -> int:
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise SolsCapabilityAdapterError("deadlineSeconds must be an integer")
    if seconds <= 0 or seconds > MAX_DEADLINE_SECONDS:
        raise SolsCapabilityAdapterError(
            f"deadlineSeconds must be between 1 and {MAX_DEADLINE_SECONDS}"
        )
    return seconds


def _require_kind(value: Mapping[str, Any], expected: str) -> None:
    if value.get("kind") != expected:
        raise SolsCapabilityAdapterError(
            f"reviewed adapter kind must be {expected}"
        )


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise SolsCapabilityAdapterError(f"{label} must be a boolean")
    return value


def _positive_int(value: object, label: str) -> int:
    parsed = _bounded_int(value, label, 1, MAX_UINT256)
    return parsed


def _bounded_int(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool):
        raise SolsCapabilityAdapterError(f"{label} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SolsCapabilityAdapterError(f"{label} must be an integer") from exc
    if str(parsed) != str(value) and not isinstance(value, int):
        raise SolsCapabilityAdapterError(f"{label} must be canonical decimal")
    if parsed < lower or parsed > upper:
        raise SolsCapabilityAdapterError(
            f"{label} must be between {lower} and {upper}"
        )
    return parsed


def _positive_decimal(value: object, label: str) -> int:
    parsed = _nonnegative_decimal(value, label)
    if parsed <= 0:
        raise SolsCapabilityAdapterError(f"{label} must be positive")
    return parsed


def _nonnegative_decimal(value: object, label: str) -> int:
    if not isinstance(value, str) or not value or not value.isdigit():
        raise SolsCapabilityAdapterError(f"{label} must be a decimal string")
    if len(value) > 1 and value.startswith("0"):
        raise SolsCapabilityAdapterError(f"{label} must be canonical decimal")
    parsed = int(value)
    if parsed > MAX_UINT256:
        raise SolsCapabilityAdapterError(f"{label} exceeds uint256")
    return parsed


def _address(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SolsCapabilityAdapterError(f"{label} must be an EVM address")
    try:
        return to_checksum_address(value)
    except (TypeError, ValueError) as exc:
        raise SolsCapabilityAdapterError(
            f"{label} must be a 20-byte EVM address"
        ) from exc


def _bytes32(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SolsCapabilityAdapterError(f"{label} must be 32-byte hex")
    normalized = value.removeprefix("0x").lower()
    if len(normalized) != 64:
        raise SolsCapabilityAdapterError(f"{label} must be 32-byte hex")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise SolsCapabilityAdapterError(f"{label} must be 32-byte hex") from exc
    return "0x" + normalized


def _chain_id32(value: object, label: str) -> str:
    return "0x" + _positive_int(value, label).to_bytes(32, "big").hex()


def _identifier32(value: object, label: str) -> str:
    if isinstance(value, str) and len(value.removeprefix("0x")) == 40:
        return "0x" + "00" * 12 + _address(value, label)[2:].lower()
    return _bytes32(value, label)


def _display_decimals(value: object, label: str) -> int:
    return _bounded_int(value, label, 0, 18)


def _runtime_code_hashes(
    descriptor: Mapping[str, Any],
    required_keys: Sequence[str],
) -> dict[str, str]:
    value = descriptor.get("runtimeCodeHashes")
    if not isinstance(value, Mapping):
        raise SolsCapabilityAdapterError(
            "runtimeCodeHashes must be an object"
        )
    return {
        key: _bytes32(value.get(key), f"runtimeCodeHashes.{key}")
        for key in required_keys
    }


def _asset_symbol(value: object, label: str) -> str:
    symbol = _nonempty(value, label)
    if len(symbol) > 12 or not all(
        character.isalnum() or character in {".", "-"}
        for character in symbol
    ):
        raise SolsCapabilityAdapterError(
            f"{label} must be a short asset symbol"
        )
    return symbol


def _https_origin(value: object, label: str) -> str:
    text = _nonempty(value, label).rstrip("/")
    if not text.startswith("https://") or "/" in text[8:]:
        raise SolsCapabilityAdapterError(f"{label} must be an HTTPS origin")
    return text


def _https_template(
    value: object,
    label: str,
    *,
    required_token: str,
) -> str:
    text = _nonempty(value, label)
    if not text.startswith("https://") or required_token not in text:
        raise SolsCapabilityAdapterError(
            f"{label} must be an HTTPS template containing {required_token}"
        )
    return text


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SolsCapabilityAdapterError(f"{label} must be a non-empty string")
    return value.strip()


__all__ = [
    "BridgeDirection",
    "LiquidityAction",
    "SolsCapabilityAdapterError",
    "build_aerodrome_liquidity_intent",
    "build_tibetswap_liquidity_intent",
    "build_uniswap_v3_liquidity_intent",
    "build_warp_bridge_intent",
    "descriptor_for_record",
]
