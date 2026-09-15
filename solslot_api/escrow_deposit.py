"""Independent deposit proof, distinct from later delivery/result settlement.

Both coordinator ingestion and private voucher signing use this boundary. All
RPC reads are read-only and pinned to canonical blocks; no callback field is
accepted as proof of a payment. Callers supply independently reviewed routing
and must compare the message to the immutable purchase/voucher commitments.
"""
from __future__ import annotations

import time
from typing import Any, Mapping

from eth_abi import decode, encode
from eth_abi.exceptions import DecodingError, EncodingError
from web3 import Web3


RPC_TIMEOUT_SECONDS = 2.0
PROOF_DEADLINE_SECONDS = 12.0
DEPOSIT_TOPIC = Web3.keccak(text=(
    "PaymentDeposited(bytes32,bytes32,address,address,uint256,uint64,"
    "address,bytes32,uint256)"
))
EVENT_TYPES = ["address", "uint256", "uint64", "address", "bytes32", "uint256"]
DEPOSIT_FIELDS = [
    ("depositor", "address"), ("settlementToken", "address"),
    ("localPaymentId", "bytes32"), ("purchaseId", "bytes32"),
    ("artifactHash", "bytes32"), ("collectionId", "bytes32"),
    ("deedLauncherId", "bytes32"), ("vaultLauncherId", "bytes32"),
    ("destinationPuzzle", "bytes32"), ("requestMessageId", "bytes32"),
    ("resultMessageId", "bytes32"), ("warpNonce", "bytes32"),
    ("amount", "uint256"), ("quantity", "uint256"),
    ("hubChainSelector", "uint64"), ("hubGateway", "address"),
    ("createdAt", "uint64"), ("quoteExpiresAt", "uint64"),
    ("status", "uint8"), ("succeeded", "bool"),
]
ESCROW_DEPOSIT_ABI = [{
    "inputs": [{"name": "globalPaymentId", "type": "bytes32"}],
    "name": "getDeposit", "outputs": [{"components": [
        {"name": name, "type": kind} for name, kind in DEPOSIT_FIELDS
    ], "name": "", "type": "tuple"}],
    "stateMutability": "view", "type": "function",
}]


class EscrowDepositError(ValueError):
    pass


class EscrowProviderUnavailable(EscrowDepositError):
    pass


def rpc_bytes(value: Any) -> bytes:
    if isinstance(value, str):
        return bytes.fromhex(value.removeprefix("0x"))
    if not isinstance(value, (bytes, bytearray)):
        raise EscrowDepositError("EVM escrow byte value is malformed")
    return bytes(value)


def rpc_hex(value: Any) -> str:
    return "0x" + rpc_bytes(value).hex()


def same_deposit_message(original: Mapping[str, Any], incoming: Mapping[str, Any]) -> bool:
    """Same immutable event, possibly observed with more confirmations later.

    The first receipt remains authoritative. This comparison authorizes neither
    skipping current provider verification nor replacing stored evidence.
    """
    try:
        old_source, new_source = dict(original["source"]), dict(incoming["source"])
        old_count, new_count = old_source.pop("confirmations"), new_source.pop("confirmations")
        return (type(old_count) is int and type(new_count) is int and 0 < old_count <= new_count
                and {**original, "source": old_source} == {**incoming, "source": new_source})
    except (KeyError, TypeError, ValueError):
        return False


def _deposit(values: Any) -> dict[str, Any]:
    if len(values) != len(DEPOSIT_FIELDS):
        raise EscrowDepositError("EVM escrow deposit tuple is malformed")
    result = {}
    for (name, kind), value in zip(DEPOSIT_FIELDS, values, strict=True):
        if kind == "address":
            result[name] = str(value).lower()
        elif kind == "bytes32":
            result[name] = rpc_hex(value)
        else:
            result[name] = value
    return result


def _eligible(deposit: Mapping[str, Any]) -> None:
    # A deposit is not a settlement receipt. Failed/refunded/emergency outcomes
    # are terminal and may never authorize delivery from an earlier event.
    if (deposit["status"] not in (1, 2, 3)
            or deposit["succeeded"] is not (deposit["status"] != 1)):
        raise EscrowDepositError("EVM escrow deposit is not eligible")


def verify_escrow_deposit(
    *, rpc_url: str, evidence: Mapping[str, Any], chain_id: int,
    spoke: str, token: str, confirmations: int, web3_factory=Web3,
) -> None:
    _verify_deposit(rpc_url=rpc_url, evidence=evidence, chain_id=chain_id, spoke=spoke,
        token=token, confirmations=confirmations, web3_factory=web3_factory, disposition='ELIGIBLE')


def _verify_deposit(*, rpc_url, evidence, chain_id, spoke, token, confirmations,
                    web3_factory, disposition):
    """Shared authenticated origin; only trusted wrappers choose current policy."""
    if disposition not in ('ELIGIBLE', 'REFUNDED', 'SETTLED_SUCCESS'):
        raise EscrowDepositError('unknown escrow disposition policy')
    def current_policy(deposit):
        if disposition == 'ELIGIBLE':
            _eligible(deposit)
        elif disposition == 'REFUNDED':
            if type(deposit['status']) is not int or deposit['status'] not in (4, 5) or deposit['succeeded'] is not False:
                raise EscrowDepositError('EVM escrow refund is not settled')
        elif type(deposit['status']) is not int or deposit['status'] != 3 or deposit['succeeded'] is not True:
            raise EscrowDepositError('EVM escrow success is not settled')
    if not rpc_url:
        raise EscrowProviderUnavailable("EVM escrow RPC is not configured")
    deadline = time.monotonic() + PROOF_DEADLINE_SECONDS

    def query(call):
        if time.monotonic() >= deadline:
            raise EscrowProviderUnavailable("EVM escrow verification deadline exceeded")
        try:
            value = call()
        except Exception as exc:
            raise EscrowProviderUnavailable("EVM escrow provider is unavailable") from exc
        if time.monotonic() >= deadline:
            raise EscrowProviderUnavailable("EVM escrow verification deadline exceeded")
        return value

    try:
        source = evidence["source"]
        spoke, token = spoke.lower(), token.lower()
        if (source["chainId"] != chain_id or source["spoke"] != spoke
                or evidence["settlementToken"] != token
                or source["confirmations"] < confirmations):
            raise EscrowDepositError("EVM escrow source route is invalid")
        w3 = web3_factory(web3_factory.HTTPProvider(
            rpc_url, request_kwargs={"timeout": RPC_TIMEOUT_SECONDS},
            exception_retry_configuration=None,
        ))
        if query(lambda: w3.eth.chain_id) != chain_id:
            raise EscrowDepositError("EVM escrow RPC chain does not match reviewed deployment")
        receipt = query(lambda: w3.eth.get_transaction_receipt(source["transactionHash"]))
        block = query(lambda: w3.eth.get_block(source["blockNumber"]))
        tip = query(lambda: w3.eth.get_block("latest"))
        block_number = int(receipt.get("blockNumber") or 0)
        if (int(receipt.get("status") or 0) != 1
                or rpc_hex(receipt.get("transactionHash")) != source["transactionHash"]
                or block_number != source["blockNumber"]
                or rpc_hex(receipt.get("blockHash")) != source["blockHash"]
                or rpc_hex(block.get("hash")) != source["blockHash"]
                or int(block.get("number") or 0) != block_number
                or int(block.get("timestamp") or 0) != source["blockTimestamp"]
                or int(tip["number"]) - block_number + 1 < max(confirmations, source["confirmations"])):
            raise EscrowDepositError("EVM escrow receipt provenance changed")
        # Contract-wallet calls may have a wallet/multicall as receipt.to. The
        # authenticated emitting contract, exact log and storage bind the spoke.
        logs = [log for log in receipt.get("logs", [])
                if log.get("logIndex") == source["logIndex"]
                and str(log.get("address") or "").lower() == spoke]
        if len(logs) != 1:
            raise EscrowDepositError("EVM deposit log is missing or ambiguous")
        log = logs[0]
        expected_topics = [bytes(DEPOSIT_TOPIC), rpc_bytes(evidence["globalPaymentId"]),
                           rpc_bytes(evidence["localPaymentId"]),
                           bytes(12) + rpc_bytes(evidence["depositor"])]
        if (log.get("removed", False) is not False
                or [rpc_bytes(v) for v in log.get("topics", [])] != expected_topics):
            raise EscrowDepositError("EVM deposit log commitments differ")
        data = rpc_bytes(log["data"])
        event = decode(EVENT_TYPES, data, strict=True)
        if encode(EVENT_TYPES, event) != data:
            raise EscrowDepositError("EVM deposit event encoding is not canonical")
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(spoke), abi=ESCROW_DEPOSIT_ABI,
        )
        # The global ID is the authenticated event topic AND the mapping key;
        # getDeposit deliberately does not return it as a member of the tuple.
        lookup = contract.functions.getDeposit(evidence["globalPaymentId"])
        historical = _deposit(query(lambda: lookup.call(block_identifier=block_number)))
        current = _deposit(query(lambda: lookup.call(block_identifier=int(tip["number"]))))
        expected = {name: evidence[name] for name in (
            "depositor", "settlementToken", "localPaymentId", "purchaseId",
            "artifactHash", "collectionId", "deedLauncherId", "vaultLauncherId",
            "destinationPuzzle", "amount", "quantity", "quoteExpiresAt",
        )}
        for deposit in (historical, current):
            if any(deposit[name] != value for name, value in expected.items()):
                raise EscrowDepositError("EVM escrow deposit differs from payment commitments")
        _eligible(historical)
        current_policy(current)
        immutable = [name for name, _ in DEPOSIT_FIELDS
                     if name not in ("status", "succeeded", "resultMessageId", "warpNonce")]
        if (any(historical[name] != current[name] for name in immutable)
                or current["status"] < historical["status"]):
            raise EscrowDepositError("EVM escrow deposit history changed")
        if (historical["createdAt"] != source["blockTimestamp"]
                or not 0 < historical["createdAt"] < historical["quoteExpiresAt"]
                or historical["quoteExpiresAt"] - historical["createdAt"] > 1800
                or event[:5] != (token, evidence["amount"], historical["hubChainSelector"],
                                  historical["hubGateway"], rpc_bytes(historical["requestMessageId"]))):
            raise EscrowDepositError("EVM deposit event or payment time differs from storage")
        # Re-read both pinned heights after storage reads. A advancing tip is
        # fine; replacing either block is not. A refund at the new tip is also
        # rejected rather than using the earlier eligible snapshot.
        final_block = query(lambda: w3.eth.get_block(block_number))
        final_tip = query(lambda: w3.eth.get_block(int(tip["number"])))
        latest_deposit = _deposit(query(lambda: lookup.call()))
        if (rpc_hex(final_block["hash"]) != source["blockHash"]
                or rpc_hex(final_tip["hash"]) != rpc_hex(tip["hash"])):
            raise EscrowDepositError("EVM escrow canonical blocks changed during verification")
        current_policy(latest_deposit)
        if (any(latest_deposit[name] != current[name] for name in immutable)
                or latest_deposit["status"] < current["status"]):
            raise EscrowDepositError("EVM escrow current deposit changed")
        return dict(query=query, web3=w3, deposit=latest_deposit, lookup=lookup,
                    sourceBlock=block, tip=tip, immutable=immutable)
    except EscrowDepositError:
        raise
    except (KeyError, IndexError, TypeError, ValueError, OverflowError, DecodingError, EncodingError) as exc:
        raise EscrowDepositError("EVM escrow evidence is malformed") from exc
