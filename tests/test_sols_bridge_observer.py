from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from eth_abi import encode
from eth_utils import keccak
from chia.types.blockchain_format.program import Program

from solslot_api.sols_bridge_observer import WarpCatObserver, SENT, RECEIVED, TRANSFER, coin, hex32
from solslot_api.sols_capability_operations import CapabilityOperationConflict, CapabilityOperationStore


def h(n: int, size: int = 32) -> str:
    return "0x" + bytes([n] * size).hex()


def setup_evm():
    d = {
        "adapterId": "warp-cat-v1", "environment": "test", "network": "testnet11", "deploymentId": "isolated-alpha",
        "evmChainId": 84532, "wrappedCat": h(1, 20), "warpPortal": h(2, 20), "assetRegistry": h(3, 20),
        "runtimeCodeHashes": {k: hex32(keccak(b"reviewed-code")) for k in ("wrappedCat", "warpPortal", "assetRegistry")},
        "confirmation": {"observerVersion": 1, "chiaLockerPuzzleHash": h(4), "chiaUnlockerPuzzleHash": h(5), "chiaBridgePuzzleHash": h(6), "chiaLockedAssetPuzzleHash": h(7), "chiaSourceChain": "0x786368", "evmSourceChain": "0x627365", "requiredChiaConfirmations": 3, "requiredEvmConfirmations": 3, "mojoToTokenRatio": 10**15, "tipBps": 30},
        "solsAssetId": h(8),
    }
    receipt = {"operationHash": h(9), "environment": "test", "network": "testnet11", "deploymentId": "isolated-alpha", "vaultLauncherId": h(11), "sourceAccount": h(25,20), "intent": {"adapterId": "warp-cat-v1", "direction": "EVM_TO_CHIA", "destination": h(10), "amountMojos": "10000", "transactions": [{"to": d["wrappedCat"], "data": "0x12345678", "value": "1"}]}}
    log = {"address": d["warpPortal"], "topics": [SENT, bytes.fromhex(h(12)[2:])], "data": encode(["address", "bytes3", "bytes32", "bytes32[]"], [d["wrappedCat"], b"xch", bytes.fromhex(h(5)[2:]), [bytes.fromhex(h(10)[2:]), (9970).to_bytes(32, "big")]])}
    chain_receipt = {"transactionHash": h(13), "blockNumber": 10, "blockHash": h(14), "status": 1, "logs": [log]}
    class Eth:
        @property
        async def chain_id(self):
            return 84532
    eth = Eth()
    eth.get_transaction_receipt = AsyncMock(return_value=chain_receipt)
    eth.get_block = AsyncMock(side_effect=lambda number: {"hash": h(14), "number": 20 if number == "finalized" else number})
    eth.get_code = AsyncMock(return_value=b"reviewed-code")
    eth.get_transaction = AsyncMock(return_value={"to": d["wrappedCat"], "input": "0x12345678", "value": 1, "from": h(25,20)})
    chia = SimpleNamespace(get_network_info=AsyncMock(return_value={"network_name": "testnet11"}), get_coin_record_by_name=AsyncMock(return_value=None))
    return WarpCatObserver(SimpleNamespace(eth=eth), chia), d, receipt, chain_receipt


@pytest.mark.asyncio
async def test_source_confirmation_does_not_claim_destination_completion():
    observer, descriptor, receipt, _ = setup_evm()
    result = await observer.observe(receipt, descriptor, {"sourceTransactionId": h(13)})
    assert result["status"] == "SOURCE_CONFIRMED"
    assert result["source"]["amountMojos"] == "9970"
    assert result["source"]["nonce"] == h(12)
    assert result["replayKey"].endswith(h(12))


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["wrong_network", "wrong_deployment", "wrong_code", "wrong_to", "wrong_calldata", "wrong_value", "wrong_receiver", "wrong_portal", "duplicate_message", "reverted"])
async def test_observation_rejects_substituted_or_failed_evm_evidence(failure):
    observer, d, receipt, chain_receipt = setup_evm()
    if failure == "wrong_network": observer.chia.get_network_info.return_value = {"network_name": "mainnet"}
    if failure == "wrong_deployment": receipt["deploymentId"] = "production"
    if failure == "wrong_code": observer.evm.eth.get_code.return_value = b"other-code"
    if failure == "wrong_to": observer.evm.eth.get_transaction.return_value["to"] = h(19, 20)
    if failure == "wrong_calldata": observer.evm.eth.get_transaction.return_value["input"] = "0xdeadbeef"
    if failure == "wrong_value": observer.evm.eth.get_transaction.return_value["value"] = 2
    if failure == "wrong_receiver": receipt["intent"]["destination"] = h(19)
    if failure == "wrong_portal": chain_receipt["logs"][0]["address"] = h(19, 20)
    if failure == "duplicate_message": chain_receipt["logs"].append(deepcopy(chain_receipt["logs"][0]))
    if failure == "reverted": chain_receipt["status"] = 0
    with pytest.raises(ValueError):
        await observer.observe(receipt, d, {"sourceTransactionId": h(13)})


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [{"hash": h(19), "number": 20}, {"hash": h(14), "number": 11}])
async def test_reorg_or_insufficient_finality_keeps_source_pending(block):
    observer, d, receipt, _ = setup_evm()
    observer.evm.eth.get_block.side_effect = None
    observer.evm.eth.get_block.return_value = block
    assert (await observer.observe(receipt, d, {"sourceTransactionId": h(13)}))["status"] == "AWAITING_SOURCE"


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", [None, "nonce", "mint", "source", "duplicate"])
async def test_evm_destination_requires_exact_message_and_post_tip_mint(tamper):
    observer, d, receipt, chain_receipt = setup_evm()
    intent = receipt["intent"]
    intent.update(direction="CHIA_TO_EVM", destination=h(20, 20))
    amount = 10000 * 10**15
    mint = amount - amount * 30 // 10000
    received = {"address": d["warpPortal"], "topics": [RECEIVED, bytes.fromhex(h(12)[2:])], "data": encode(["bytes3", "bytes32", "address", "bytes32[]"], [b"xch", bytes.fromhex(h(4)[2:]), d["wrappedCat"], [bytes.fromhex(h(20,20)[2:]).rjust(32,b"\0"), (10000).to_bytes(32,"big")]])}
    transfer = {"address": d["wrappedCat"], "topics": [TRANSFER, bytes(32), bytes.fromhex(h(20,20)[2:]).rjust(32,b"\0")], "data": mint.to_bytes(32,"big")}
    chain_receipt["logs"] = [received, transfer]
    proof = {"nonce": h(12)}
    if tamper == "nonce": proof["nonce"] = h(21)
    if tamper == "mint": transfer["data"] = (mint + 1).to_bytes(32,"big")
    if tamper == "source": d["confirmation"]["chiaLockerPuzzleHash"] = h(21)
    if tamper == "duplicate": chain_receipt["logs"].append(deepcopy(received))
    if tamper:
        with pytest.raises(ValueError): await observer._evm_destination(h(13), proof, intent, d)
    else:
        result = await observer._evm_destination(h(13), proof, intent, d)
        assert result["receivedTokenUnits"] == str(mint)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", [None, "receiver", "amount", "height", "puzzle", "confirmations"])
async def test_chia_source_derives_nonce_from_confirmed_locker_child(tamper):
    observer, d, receipt, _ = setup_evm()
    # Fixtures use a pinned program hash; successful chain spend is supplied by
    # the provider fixture. These are parser/binding tests, not external E2E.
    puzzle = Program.to(1)
    d["confirmation"]["chiaLockerPuzzleHash"] = hex32(puzzle.get_tree_hash())
    parent = {"coin": {"parent_coin_info": h(22), "puzzle_hash": d["confirmation"]["chiaLockerPuzzleHash"], "amount": 1}, "spent_block_index": 10, "confirmed_block_index": 5}
    parent_id = hex32(coin(parent).name())
    bridge = {"coin": {"parent_coin_info": parent_id, "puzzle_hash": d["confirmation"]["chiaBridgePuzzleHash"], "amount": 1}, "spent_block_index": 0, "confirmed_block_index": 10}
    bridge_id = hex32(coin(bridge).name())
    receipt["intent"].update(direction="CHIA_TO_EVM", destination=h(20,20))
    solution = Program.to([1, bytes.fromhex(parent_id[2:]), 10000, bytes.fromhex(h(20,20)[2:])])
    observer.chia.get_coin_record_by_name.side_effect = lambda name: bridge if name == bridge_id else parent
    observer.chia.get_blockchain_state = AsyncMock(return_value={"blockchain_state": {"sync": {"synced": True}, "peak": {"height": 20}}})
    observer.chia.get_puzzle_and_solution = AsyncMock(return_value={"puzzle_reveal": bytes(puzzle).hex(), "solution": bytes(solution).hex()})
    if tamper == "receiver": receipt["intent"]["destination"] = h(21,20)
    if tamper == "amount": receipt["intent"]["amountMojos"] = "10001"
    if tamper == "height": bridge["confirmed_block_index"] = 11
    if tamper == "puzzle": d["confirmation"]["chiaLockerPuzzleHash"] = h(21)
    if tamper == "confirmations": observer.chia.get_blockchain_state.return_value["blockchain_state"]["peak"]["height"] = 10
    if tamper and tamper != "confirmations":
        with pytest.raises(ValueError): await observer.observe(receipt, d, {"sourceTransactionId": bridge_id})
    else:
        result = await observer.observe(receipt, d, {"sourceTransactionId": bridge_id})
        assert result["status"] == ("AWAITING_SOURCE" if tamper else "SOURCE_ASSOCIATION_UNVERIFIED")


def test_durable_resume_private_scope_and_source_nonce_replay(tmp_path):
    path = str(tmp_path / "operations.db")
    _, _, receipt, _ = setup_evm()
    store = CapabilityOperationStore(path)
    store.prepare(receipt)
    store.record_hints(receipt["operationHash"], receipt["vaultLauncherId"], {"sourceTransactionId": h(13)})
    store.close()
    store = CapabilityOperationStore(path)
    assert store.get(h(9), h(11))["status"] == "AWAITING_SOURCE"
    with pytest.raises(KeyError): store.get(h(9), h(21))
    with pytest.raises(CapabilityOperationConflict): store.prepare({**receipt, "network": "mainnet"})
    proof = {"operationHash": h(9), "status": "SOURCE_CONFIRMED", "replayKey": "network:portal:nonce"}
    store.record_observation(h(9), h(11), proof)
    second = {**receipt, "operationHash": h(22)}
    store.prepare(second)
    with pytest.raises(CapabilityOperationConflict):
        store.record_observation(h(22), h(11), {**proof, "operationHash": h(22)})
    assert store.get(h(22), h(11))["status"] == "PREPARED"
    store.close()


def test_browser_hints_cannot_assert_finality(tmp_path):
    _, _, receipt, _ = setup_evm()
    store = CapabilityOperationStore(str(tmp_path / "operations.db"))
    store.prepare(receipt)
    with pytest.raises(ValueError):
        store.record_hints(h(9), h(11), {"status": "DESTINATION_CONFIRMED"})
    assert store.get(h(9), h(11))["status"] == "PREPARED"
    store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", [None, "nonce", "receiver", "amount", "payout_amount", "payout_parent", "locked_puzzle", "unconfirmed"])
async def test_chia_destination_requires_nonce_bound_unlocker_and_exact_cat_payout(tamper):
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD
    from chia.wallet.util.curry_and_treehash import calculate_hash_of_quoted_mod_hash, curry_and_treehash, shatree_atom
    from chia_rs.sized_bytes import bytes32
    observer, d, receipt, _ = setup_evm()
    puzzle = Program.to(1)
    d["confirmation"]["chiaUnlockerPuzzleHash"] = hex32(puzzle.get_tree_hash())
    unlocker = {"coin": {"parent_coin_info": h(26), "puzzle_hash": d["confirmation"]["chiaUnlockerPuzzleHash"], "amount": 1}, "spent_block_index": 15, "confirmed_block_index": 10}
    unlocker_id = hex32(coin(unlocker).name())
    locked = {"coin": {"parent_coin_info": h(27), "puzzle_hash": d["confirmation"]["chiaLockedAssetPuzzleHash"], "amount": 12000}, "spent_block_index": 15, "confirmed_block_index": 10}
    locked_id = hex32(coin(locked).name())
    cat_hash = CAT_MOD.get_tree_hash()
    payout_hash = curry_and_treehash(calculate_hash_of_quoted_mod_hash(cat_hash), shatree_atom(cat_hash), shatree_atom(bytes.fromhex(d["solsAssetId"][2:])), bytes32(bytes.fromhex(receipt["intent"]["destination"][2:])))
    payout = {"coin": {"parent_coin_info": locked_id, "puzzle_hash": hex32(payout_hash), "amount": 9970}, "spent_block_index": 0, "confirmed_block_index": 15}
    nonce = Program.to(bytes.fromhex(h(12)[2:])).get_tree_hash()
    fields = [bytes.fromhex(h(28)[2:]), nonce, bytes.fromhex(receipt["intent"]["destination"][2:]), (9970).to_bytes(32,"big"), puzzle.get_tree_hash(), bytes.fromhex(unlocker_id[2:]), [(bytes.fromhex(h(27)[2:]), 12000)]]
    if tamper == "nonce": fields[1] = bytes.fromhex(h(29)[2:])
    if tamper == "receiver": fields[2] = bytes.fromhex(h(29)[2:])
    if tamper == "amount": fields[3] = (9971).to_bytes(32,"big")
    if tamper == "payout_amount": payout["coin"]["amount"] = 9971
    if tamper == "payout_parent": locked["coin"]["parent_coin_info"] = h(29)
    if tamper == "locked_puzzle": locked["coin"]["puzzle_hash"] = h(29)
    if tamper == "unconfirmed": unlocker["spent_block_index"] = 0
    observer.chia.get_coin_record_by_name.side_effect = lambda name: unlocker if name == unlocker_id else locked
    observer.chia.get_blockchain_state = AsyncMock(return_value={"blockchain_state": {"sync": {"synced": True}, "peak": {"height": 20}}})
    observer.chia.get_puzzle_and_solution = AsyncMock(return_value={"puzzle_reveal": bytes(puzzle).hex(), "solution": bytes(Program.to(fields)).hex()})
    observer.chia.get_coin_records_by_puzzle_hash = AsyncMock(return_value=[payout])
    if tamper and tamper != "unconfirmed":
        with pytest.raises(ValueError):
            await observer._chia_destination(unlocker_id, {"nonce": h(12), "amountMojos": "9970"}, receipt["intent"], d)
    else:
        result = await observer._chia_destination(unlocker_id, {"nonce": h(12), "amountMojos": "9970"}, receipt["intent"], d)
        if tamper:
            assert result is None
        else:
            assert result["receivedMojos"] == "9970"
            assert result["coinId"] == hex32(coin(payout).name())


@pytest.mark.asyncio
async def test_complete_observation_can_resume_from_durable_hints_without_resubmission(tmp_path):
    observer, descriptor, receipt, _ = setup_evm()
    store = CapabilityOperationStore(str(tmp_path / "resume.db"))
    store.prepare(receipt)
    store.record_hints(h(9), h(11), {"sourceTransactionId": h(13), "destinationTransactionId": h(26)})
    observer._chia_destination = AsyncMock(return_value={"transactionId": h(26), "receivedMojos": "9970", "height": 30})
    operation = store.get(h(9), h(11))
    result = await observer.observe(operation["receipt"], descriptor, operation["hints"])
    store.record_observation(h(9), h(11), result)
    store.close()
    store = CapabilityOperationStore(str(tmp_path / "resume.db"))
    assert store.get(h(9), h(11))["status"] == "DESTINATION_CONFIRMED"
    observer._chia_destination.return_value = None
    result = await observer.observe(receipt, descriptor, operation["hints"])
    store.record_observation(h(9), h(11), result)
    assert store.get(h(9), h(11))["status"] == "SOURCE_CONFIRMED"
    store.close()



@pytest.mark.asyncio
async def test_public_chia_transfer_cannot_associate_distinct_vaults_or_reserve_nonce(tmp_path):
    observer, descriptor, receipt, _ = setup_evm()
    receipt["intent"].update(direction="CHIA_TO_EVM", destination=h(20,20))
    second = deepcopy(receipt)
    second.update(operationHash=h(40), vaultLauncherId=h(41), sourceAccount=h(42,20))
    public_proof = {"nonce": h(12), "amountMojos": "10000", "transactionId": h(13), "height": 10}
    observer._chia_source = AsyncMock(return_value=public_proof)
    observer._evm_destination = AsyncMock(return_value={"receivedTokenUnits": "9970000000000000000"})
    store = CapabilityOperationStore(str(tmp_path / "public-proof.db"))
    for operation in (second, receipt):
        store.prepare(operation)
        result = await observer.observe(operation, descriptor, {"sourceTransactionId": h(13), "destinationTransactionId": h(26)})
        assert result["status"] == "SOURCE_ASSOCIATION_UNVERIFIED"
        assert "replayKey" not in result
        assert "source" not in result
        store.record_observation(operation["operationHash"], operation["vaultLauncherId"], result)
    observer._evm_destination.assert_not_awaited()
    assert store.connection.execute("SELECT count(*) FROM capability_messages").fetchone()[0] == 0
    assert store.get(h(9),h(11))["status"] == "SOURCE_ASSOCIATION_UNVERIFIED"
    assert store.get(h(40),h(41))["status"] == "SOURCE_ASSOCIATION_UNVERIFIED"
    store.close()


@pytest.mark.parametrize("status,replay", [("SOURCE_CONFIRMED", None), ("DESTINATION_CONFIRMED", None), ("SOURCE_ASSOCIATION_UNVERIFIED", "public:nonce")])
def test_store_itself_rejects_chia_owner_confirmation_and_nonce_reservation(tmp_path, status, replay):
    _, _, receipt, _ = setup_evm()
    receipt["intent"]["direction"] = "CHIA_TO_EVM"
    store = CapabilityOperationStore(str(tmp_path / "guard.db"))
    store.prepare(receipt)
    observation = {"operationHash": h(9), "status": status}
    if replay: observation["replayKey"] = replay
    with pytest.raises(CapabilityOperationConflict, match="funding association"):
        store.record_observation(h(9), h(11), observation)
    assert store.connection.execute("SELECT count(*) FROM capability_messages").fetchone()[0] == 0
    assert store.get(h(9), h(11))["status"] == "PREPARED"
    store.close()


@pytest.mark.asyncio
async def test_evm_source_signer_cannot_be_substituted():
    observer, descriptor, receipt, _ = setup_evm()
    receipt["sourceAccount"] = h(42,20)
    with pytest.raises(ValueError, match="signer does not match"):
        await observer.observe(receipt, descriptor, {"sourceTransactionId": h(13)})
