"""Read-only Warp CAT observation using actual Portal events and Chia spends.

Event ABI: Samuel's pinned Portal/WrappedCAT artifacts. Chia solution layouts:
Samuel's wrapped_cats.py, locker.clsp and unlocker.clsp. No Samuel payment-row,
explorer response, or browser status is accepted as customer bridge finality.
"""
from __future__ import annotations

from typing import Any, Mapping

from eth_abi import decode
from eth_utils import keccak, to_checksum_address
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64


SENT = keccak(text="MessageSent(bytes32,address,bytes3,bytes32,bytes32[])")
RECEIVED = keccak(text="MessageReceived(bytes32,bytes3,bytes32,address,bytes32[])")
TRANSFER = keccak(text="Transfer(address,address,uint256)")


def raw(value: Any) -> bytes:
    return bytes.fromhex(value.removeprefix("0x")) if isinstance(value, str) else bytes(value)


def hex32(value: Any) -> str:
    result = raw(value)
    if len(result) != 32:
        raise ValueError("expected 32-byte chain identifier")
    return "0x" + result.hex()


def coin(record: Mapping[str, Any]) -> Coin:
    value = record["coin"]
    return Coin(bytes32(raw(value["parent_coin_info"])), bytes32(raw(value["puzzle_hash"])), uint64(int(value["amount"])))


def validate_observer_descriptor(descriptor: Mapping[str, Any]) -> None:
    c = descriptor.get("confirmation")
    if not isinstance(c, Mapping) or c.get("observerVersion") != 1:
        raise ValueError("reviewed Warp confirmation observer version is missing")
    for field in ("chiaLockerPuzzleHash", "chiaUnlockerPuzzleHash", "chiaBridgePuzzleHash", "chiaLockedAssetPuzzleHash"):
        hex32(c[field])
    for field in ("chiaSourceChain", "evmSourceChain"):
        if len(raw(c[field])) != 3:
            raise ValueError("Warp source chain must be bytes3")
    if raw(c["chiaSourceChain"]) != b"xch":
        raise ValueError("customer bridge must use the Chia Warp source chain")
    for field in ("requiredChiaConfirmations", "requiredEvmConfirmations", "mojoToTokenRatio"):
        if type(c.get(field)) is not int or c[field] < 1:
            raise ValueError(f"{field} must be a positive integer")
    if type(c.get("tipBps")) is not int or not 1 <= c["tipBps"] <= 1000:
        raise ValueError("Warp tip must match the reviewed immutable contract")


class WarpCatObserver:
    """One bounded observation; callers schedule retries and persist results.

    ``evm`` is AsyncWeb3, ``chia`` is the configured ChiaProvider. Neither URL
    comes from a request. Discovery references are untrusted transaction hashes
    (EVM) or coin IDs (Chia) and are verified against the exact reviewed intent.
    """
    def __init__(self, evm: Any, chia: Any):
        self.evm, self.chia = evm, chia

    async def observe(self, receipt: Mapping[str, Any], descriptor: Mapping[str, Any], hints: Mapping[str, str]) -> dict[str, Any]:
        validate_observer_descriptor(descriptor)
        c = descriptor["confirmation"]
        if await self.evm.eth.chain_id != descriptor["evmChainId"]:
            raise ValueError("EVM provider returned the wrong network")
        if (await self.chia.get_network_info()).get("network_name") != receipt["network"]:
            raise ValueError("Chia provider returned the wrong network")
        if receipt["intent"]["adapterId"] != descriptor["adapterId"]:
            raise ValueError("operation adapter does not match reviewed evidence")
        for field in ("environment", "deploymentId", "network"):
            if receipt.get(field) != descriptor.get(field):
                raise ValueError("operation deployment does not match reviewed evidence")
        result: dict[str, Any] = {"operationHash": receipt["operationHash"], "status": "AWAITING_SOURCE"}
        source = hints.get("sourceTransactionId")
        if not source:
            return result
        intent = receipt["intent"]
        if intent["direction"] == "EVM_TO_CHIA":
            proof = await self._evm_source(source, intent, descriptor, receipt.get("sourceAccount"))
        elif intent["direction"] == "CHIA_TO_EVM":
            public_proof = await self._chia_source(source, intent, descriptor)
            if public_proof:
                # The locker solution authenticates receiver/amount, not the
                # funding wallet. A public coin reference cannot associate this
                # transfer with the API session or consume a global nonce.
                return {
                    **result,
                    "status": "SOURCE_ASSOCIATION_UNVERIFIED",
                    "publicChainObservation": public_proof,
                    "detail": "The public Chia transfer matches these terms, but reviewed funding-to-vault association is unavailable. This receipt cannot establish ownership or completion.",
                }
            return result
        else:
            raise ValueError("unsupported bridge direction")
        if not proof:
            return result
        result.update(status="SOURCE_CONFIRMED", source=proof,
                      replayKey=f'{receipt["environment"]}:{receipt["network"]}:{receipt["deploymentId"]}:{descriptor["warpPortal"].lower()}:{intent["direction"]}:{proof["nonce"]}')
        destination = hints.get("destinationTransactionId")
        if not destination:
            return result
        completed = (await self._chia_destination(destination, proof, intent, descriptor)
                     if intent["direction"] == "EVM_TO_CHIA"
                     else await self._evm_destination(destination, proof, intent, descriptor))
        if completed:
            result.update(status="DESTINATION_CONFIRMED", destination=completed)
        return result

    async def _evm_receipt(self, tx_id: str, descriptor: Mapping[str, Any]) -> Mapping[str, Any] | None:
        from web3.exceptions import TransactionNotFound
        try:
            receipt = await self.evm.eth.get_transaction_receipt(tx_id)
        except TransactionNotFound:
            return None
        if hex32(receipt["transactionHash"]) != hex32(tx_id):
            raise ValueError("provider receipt does not match requested transaction")
        block = await self.evm.eth.get_block(receipt["blockNumber"])
        if raw(block["hash"]) != raw(receipt["blockHash"]):
            return None
        # On rollups an L2 head count is insufficient; require the finalized
        # marker as well as the reviewed minimum depth.
        final = await self.evm.eth.get_block("finalized")
        if int(final["number"]) < int(receipt["blockNumber"]) + descriptor["confirmation"]["requiredEvmConfirmations"] - 1:
            return None
        if int(receipt["status"]) != 1:
            raise ValueError("source or destination transaction reverted")
        for key in ("wrappedCat", "warpPortal", "assetRegistry"):
            code = await self.evm.eth.get_code(to_checksum_address(descriptor[key]), block_identifier=receipt["blockNumber"])
            if keccak(bytes(code)) != raw(descriptor["runtimeCodeHashes"][key]):
                raise ValueError("bridge runtime code differs from reviewed deployment")
        return receipt

    def _events(self, receipt: Mapping[str, Any], address: str, signature: bytes) -> list[Mapping[str, Any]]:
        return [log for log in receipt["logs"] if str(log["address"]).lower() == address.lower()
                and log["topics"] and raw(log["topics"][0]) == signature and not log.get("removed", False)]

    async def _evm_source(self, tx_id: str, intent: Mapping[str, Any], d: Mapping[str, Any], source_account: str | None = None) -> dict[str, Any] | None:
        receipt = await self._evm_receipt(tx_id, d)
        if receipt is None:
            return None
        tx = await self.evm.eth.get_transaction(tx_id)
        prepared = intent["transactions"][0]
        if not source_account or str(tx.get("from", "")).lower() != source_account.lower():
            raise ValueError("source transaction signer does not match the reviewed vault owner")
        if str(tx["to"]).lower() != prepared["to"].lower() or raw(tx["input"]) != raw(prepared["data"]) or int(tx["value"]) != int(prepared["value"]):
            raise ValueError("source transaction does not match reviewed bridge call")
        matches = []
        amount = int(intent["amountMojos"])
        after_tip = amount - max(1, amount * d["confirmation"]["tipBps"] // 10_000)
        for log in self._events(receipt, d["warpPortal"], SENT):
            sender, chain, target, contents = decode(["address", "bytes3", "bytes32", "bytes32[]"], raw(log["data"]))
            if sender.lower() == d["wrappedCat"].lower() and chain == raw(d["confirmation"]["chiaSourceChain"]) and target == raw(d["confirmation"]["chiaUnlockerPuzzleHash"]):
                if len(contents) == 2 and contents[0] == raw(intent["destination"]) and int.from_bytes(contents[1], "big") == after_tip:
                    matches.append({"nonce": hex32(log["topics"][1]), "amountMojos": str(after_tip), "transactionId": tx_id, "height": receipt["blockNumber"]})
        if len(matches) != 1:
            raise ValueError("source transaction has no unique matching WrappedCAT message")
        return matches[0]

    async def _evm_destination(self, tx_id: str, proof: Mapping[str, Any], intent: Mapping[str, Any], d: Mapping[str, Any]) -> dict[str, Any] | None:
        receipt = await self._evm_receipt(tx_id, d)
        if receipt is None:
            return None
        matches = []
        for log in self._events(receipt, d["warpPortal"], RECEIVED):
            chain, source, target, contents = decode(["bytes3", "bytes32", "address", "bytes32[]"], raw(log["data"]))
            if hex32(log["topics"][1]) == proof["nonce"] and chain == raw(d["confirmation"]["chiaSourceChain"]) and source == raw(d["confirmation"]["chiaLockerPuzzleHash"]) and target.lower() == d["wrappedCat"].lower():
                if len(contents) == 2 and contents[0] == raw(intent["destination"]).rjust(32, b"\0") and int.from_bytes(contents[1], "big") == int(intent["amountMojos"]):
                    matches.append(log)
        amount = int(intent["amountMojos"]) * d["confirmation"]["mojoToTokenRatio"]
        received = amount - amount * d["confirmation"]["tipBps"] // 10_000
        mints = [log for log in self._events(receipt, d["wrappedCat"], TRANSFER)
                 if len(log["topics"]) == 3 and raw(log["topics"][1]) == bytes(32)
                 and raw(log["topics"][2]) == raw(intent["destination"]).rjust(32, b"\0")
                 and int.from_bytes(raw(log["data"]), "big") == received]
        if len(matches) != 1 or len(mints) != 1:
            raise ValueError("destination lacks the matching Warp message and exact mint")
        return {"transactionId": tx_id, "height": receipt["blockNumber"], "receivedTokenUnits": str(received)}

    async def _chia_spent(self, coin_id: str, expected_puzzle: str, confirmations: int) -> tuple[Mapping[str, Any], list[Program]] | None:
        record = await self.chia.get_coin_record_by_name(coin_id)
        if not record or not record.get("spent_block_index"):
            return None
        if coin(record).name() != raw(coin_id) or raw(record["coin"]["puzzle_hash"]) != raw(expected_puzzle):
            raise ValueError("Chia coin does not match reviewed puzzle or requested ID")
        state = await self.chia.get_blockchain_state()
        state = state.get("blockchain_state", state)
        if not state.get("sync", {}).get("synced") or int(state["peak"]["height"]) < int(record["spent_block_index"]) + confirmations - 1:
            return None
        spend = await self.chia.get_puzzle_and_solution(coin_id, record["spent_block_index"])
        if not spend:
            return None
        puzzle = Program.from_bytes(raw(spend["puzzle_reveal"]))
        if puzzle.get_tree_hash() != raw(expected_puzzle):
            raise ValueError("Chia puzzle reveal does not match reviewed code")
        return record, list(Program.from_bytes(raw(spend["solution"])).as_iter())

    async def _chia_source(self, bridge_coin_id: str, intent: Mapping[str, Any], d: Mapping[str, Any]) -> dict[str, Any] | None:
        bridge = await self.chia.get_coin_record_by_name(bridge_coin_id)
        if not bridge:
            return None
        if coin(bridge).name() != raw(bridge_coin_id) or raw(bridge["coin"]["puzzle_hash"]) != raw(d["confirmation"]["chiaBridgePuzzleHash"]):
            raise ValueError("Chia source reference is not a Warp bridging coin")
        parent_id = hex32(bridge["coin"]["parent_coin_info"])
        result = await self._chia_spent(parent_id, d["confirmation"]["chiaLockerPuzzleHash"], d["confirmation"]["requiredChiaConfirmations"])
        if result is None:
            return None
        parent, fields = result
        if len(fields) != 4 or fields[1].as_atom() != raw(parent_id) or fields[2].as_int() != int(intent["amountMojos"]) or fields[3].as_atom() != raw(intent["destination"]):
            raise ValueError("Chia locker spend does not match reviewed receiver and amount")
        if int(bridge["confirmed_block_index"]) != int(parent["spent_block_index"]) or fields[0].as_int() != int(bridge["coin"]["amount"]):
            raise ValueError("Chia bridging child is not the confirmed locker output")
        return {"nonce": hex32(bridge_coin_id), "amountMojos": intent["amountMojos"], "transactionId": bridge_coin_id, "height": parent["spent_block_index"]}

    async def _chia_destination(self, unlocker_id: str, proof: Mapping[str, Any], intent: Mapping[str, Any], d: Mapping[str, Any]) -> dict[str, Any] | None:
        result = await self._chia_spent(unlocker_id, d["confirmation"]["chiaUnlockerPuzzleHash"], d["confirmation"]["requiredChiaConfirmations"])
        if result is None:
            return None
        record, fields = result
        if len(fields) != 7 or fields[1].as_atom() != Program.to(raw(proof["nonce"])).get_tree_hash() or fields[2].as_atom() != raw(intent["destination"]) or fields[3].as_atom() != int(proof["amountMojos"]).to_bytes(32, "big") or fields[5].as_atom() != raw(unlocker_id):
            raise ValueError("unlocker spend does not consume the exact bridge nonce, receiver and amount")
        # Unlocker's reviewed CLVM asserts every locked coin and notarizes the
        # payout from the last one. Reconstruct that output and verify its CAT.
        proofs = list(fields[6].as_iter())
        if not proofs:
            raise ValueError("unlocker lacks locked CAT proofs")
        # Discover children only under locked coins at the same confirmed spend
        # height, then verify the destination CAT inner puzzle and exact amount.
        # A puzzle hash cannot be curried as a reveal; use the protocol's hash
        # derivation helper with the destination inner puzzle hash instead.
        from chia.wallet.util.curry_and_treehash import calculate_hash_of_quoted_mod_hash, curry_and_treehash, shatree_atom
        cat_hash = CAT_MOD.get_tree_hash()
        payout_hash = curry_and_treehash(calculate_hash_of_quoted_mod_hash(cat_hash), shatree_atom(cat_hash), shatree_atom(raw(d["solsAssetId"])), bytes32(raw(intent["destination"])))
        candidates = await self.chia.get_coin_records_by_puzzle_hash(hex32(payout_hash), include_spent=True, start_height=record["spent_block_index"], end_height=record["spent_block_index"] + 1)
        matched = []
        for output in candidates:
            if int(output["coin"]["amount"]) != int(proof["amountMojos"]) or int(output["confirmed_block_index"]) != int(record["spent_block_index"]):
                continue
            parent = await self.chia.get_coin_record_by_name(hex32(output["coin"]["parent_coin_info"]))
            last = proofs[-1]
            if parent and raw(parent["coin"]["puzzle_hash"]) == raw(d["confirmation"]["chiaLockedAssetPuzzleHash"]) and coin(parent).name() == raw(output["coin"]["parent_coin_info"]) and int(parent["spent_block_index"]) == int(record["spent_block_index"]) and raw(parent["coin"]["parent_coin_info"]) == last.first().as_atom() and int(parent["coin"]["amount"]) == last.rest().as_int():
                matched.append(output)
        if len(matched) != 1:
            raise ValueError("destination lacks a unique exact CAT payout from the unlocked coins")
        return {"transactionId": unlocker_id, "height": record["spent_block_index"], "receivedMojos": proof["amountMojos"], "coinId": hex32(coin(matched[0]).name())}
