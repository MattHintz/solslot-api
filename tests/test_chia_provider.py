from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from chia_rs import G2Element, SpendBundle

from solslot_api.chia_provider import (
    ChiaProvider,
    ChiaProviderConfig,
    ChiaProviderError,
    _input_coin_ids,
)
from solslot_api.chia_proxy import router as chia_proxy_router


@pytest.mark.parametrize("amount", [0, 1, 127, 128, 255, 256, 10_000_000, 2**63, 2**64-1])
def test_input_ids_match_consensus_coin_names(amount):
    from chia_rs import Coin
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64
    coin = Coin(bytes32(b"\x11"*32), bytes32(b"\x22"*32), uint64(amount))
    assert _input_coin_ids({"coin_spends": [{"coin": coin.to_json_dict()}]}) == ["0x"+coin.name().hex()]


@pytest.mark.parametrize("amount", [True, 1.5, -1, 2**64, "1.5"])
def test_input_ids_reject_non_uint64_amounts(amount):
    assert _input_coin_ids({"coin_spends": [{"coin": {
        "parent_coin_info": "11"*32, "puzzle_hash": "22"*32, "amount": amount}}]}) == []


class FakeRpc:
    def __init__(
        self,
        *,
        network: str = "testnet11",
        synced: bool = True,
        read_result: Any = None,
        read_error: Exception | None = None,
        push_result: dict[str, Any] | None = None,
        push_error: Exception | None = None,
        mempool: dict[str, list[dict[str, Any]]] | None = None,
        fee_estimate: int = 0,
    ) -> None:
        self.network = network
        self.synced = synced
        self.read_result = read_result
        self.read_error = read_error
        self.push_result = push_result or {"success": True, "status": "SUCCESS"}
        self.push_error = push_error
        self.mempool = mempool or {}
        self.fee_estimate = fee_estimate
        self.calls: list[tuple[str, Any]] = []
        self.closed = False

    async def get_network_info(self) -> dict[str, Any]:
        self.calls.append(("get_network_info", None))
        if self.read_error:
            raise self.read_error
        return {"success": True, "network_name": self.network}

    async def get_blockchain_state(self) -> dict[str, Any]:
        self.calls.append(("get_blockchain_state", None))
        if self.read_error:
            raise self.read_error
        return {
            "success": True,
            "blockchain_state": {
                "sync": {"synced": self.synced},
                "peak": {"height": 123},
            },
        }

    async def get_coin_record_by_name(self, coin_id: str) -> dict[str, Any] | None:
        self.calls.append(("get_coin_record_by_name", coin_id))
        if self.read_error:
            raise self.read_error
        return self.read_result

    async def get_coin_records_by_puzzle_hash(
        self, puzzle_hash: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.calls.append(("get_coin_records_by_puzzle_hash", (puzzle_hash, kwargs)))
        if self.read_error:
            raise self.read_error
        return self.read_result or []

    async def get_coin_records_by_puzzle_hashes(
        self, puzzle_hashes: list[str], **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.calls.append(
            ("get_coin_records_by_puzzle_hashes", (puzzle_hashes, kwargs))
        )
        if self.read_error:
            raise self.read_error
        return self.read_result or []

    async def get_coin_records_by_hint(
        self, hint: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.calls.append(("get_coin_records_by_hint", (hint, kwargs)))
        if self.read_error:
            raise self.read_error
        return self.read_result or []

    async def get_coin_records_by_parent_ids(
        self, parent_ids: list[str], **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.calls.append(("get_coin_records_by_parent_ids", (parent_ids, kwargs)))
        if self.read_error:
            raise self.read_error
        return self.read_result or []

    async def get_puzzle_and_solution(
        self, coin_id: str, height: int
    ) -> dict[str, Any] | None:
        self.calls.append(("get_puzzle_and_solution", (coin_id, height)))
        if self.read_error:
            raise self.read_error
        return self.read_result

    async def push_tx(self, bundle: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("push_tx", bundle))
        if self.push_error:
            raise self.push_error
        return self.push_result

    async def get_mempool_items_by_coin_name(
        self, coin_id: str
    ) -> list[dict[str, Any]]:
        self.calls.append(("get_mempool_items_by_coin_name", coin_id))
        if self.read_error:
            raise self.read_error
        return self.mempool.get(coin_id, [])

    async def get_fee_estimate(
        self,
        *,
        target_times: list[int],
        spend_bundle: dict[str, Any] | None = None,
        cost: int | None = None,
    ) -> dict[str, Any]:
        self.calls.append(
            ("get_fee_estimate", (target_times, spend_bundle, cost))
        )
        if self.read_error:
            raise self.read_error
        return {
            "success": True,
            "target_times": target_times,
            "estimates": [self.fee_estimate for _ in target_times],
        }

    async def close(self) -> None:
        self.closed = True


def config(**updates: Any) -> ChiaProviderConfig:
    values = {
        "network": "testnet11",
        "primary_url": "https://127.0.0.1:8555",
        "fallback_url": "https://testnet11.api.coinset.org",
        "primary_retry_count": 0,
        "recovery_probe_seconds": 30.0,
    }
    values.update(updates)
    return ChiaProviderConfig(**values)


def spend_bundle() -> dict[str, Any]:
    return {
        "coin_spends": [
            {
                "coin": {
                    "parent_coin_info": "0x" + "11" * 32,
                    "puzzle_hash": "0x" + "22" * 32,
                    "amount": 530,
                },
                "puzzle_reveal": "0x80",
                "solution": "0x80",
            }
        ],
        "aggregated_signature": "0x" + bytes(G2Element()).hex(),
    }


def spend_bundle_id(bundle: dict[str, Any]) -> str:
    return "0x" + SpendBundle.from_json_dict(bundle).name().hex()


@pytest.mark.asyncio
async def test_healthy_primary_is_used_and_validated() -> None:
    primary = FakeRpc(read_result={"coin": "primary"})
    fallback = FakeRpc(read_result={"coin": "fallback"})
    provider = ChiaProvider(primary, fallback, config())

    await provider.start()
    result = await provider.get_coin_record_by_name("0x" + "33" * 32)

    assert result == {"coin": "primary"}
    assert not any(call[0] == "get_coin_record_by_name" for call in fallback.calls)
    assert provider.status()["activeProvider"] == "local-full-node"


@pytest.mark.asyncio
async def test_primary_failure_opens_circuit_and_uses_fallback() -> None:
    primary = FakeRpc(read_error=TimeoutError("primary unavailable"))
    fallback = FakeRpc(read_result={"coin": "fallback"})
    provider = ChiaProvider(primary, fallback, config())

    await provider.start()
    first = await provider.get_coin_record_by_name("0x" + "44" * 32)
    second = await provider.get_coin_record_by_name("0x" + "55" * 32)

    assert first == second == {"coin": "fallback"}
    assert provider.status()["fallbackActive"] is True
    assert sum(call[0] == "get_network_info" for call in primary.calls) == 1


@pytest.mark.asyncio
async def test_open_circuit_recovers_only_after_a_fresh_sync_probe() -> None:
    clock = [100.0]
    primary = FakeRpc(read_error=TimeoutError("offline"))
    fallback = FakeRpc(read_result={"coin": "fallback"})
    provider = ChiaProvider(
        primary,
        fallback,
        config(recovery_probe_seconds=30.0),
        monotonic=lambda: clock[0],
    )
    await provider.start()

    clock[0] = 129.0
    assert await provider.get_coin_record_by_name("0x" + "66" * 32) == {
        "coin": "fallback"
    }

    primary.read_error = None
    primary.read_result = {"coin": "primary"}
    clock[0] = 130.0
    assert await provider.get_coin_record_by_name("0x" + "77" * 32) == {
        "coin": "primary"
    }
    assert provider.status()["fallbackActive"] is False


@pytest.mark.asyncio
async def test_required_primary_rejects_wrong_network_and_unsynced_node() -> None:
    wrong_network = ChiaProvider(
        FakeRpc(network="mainnet"),
        FakeRpc(),
        config(primary_required=True),
    )
    with pytest.raises(ChiaProviderError, match="network mismatch"):
        await wrong_network.start()

    unsynced = ChiaProvider(
        FakeRpc(synced=False),
        FakeRpc(),
        config(primary_required=True),
    )
    with pytest.raises(ChiaProviderError, match="not synced"):
        await unsynced.start()


@pytest.mark.asyncio
async def test_required_primary_rejects_missing_configuration() -> None:
    provider = ChiaProvider(
        None,
        FakeRpc(),
        config(primary_url=None, primary_required=True),
    )
    with pytest.raises(ChiaProviderError, match="needs a primary URL"):
        await provider.start()


@pytest.mark.asyncio
async def test_genesis_primary_proof_never_falls_back_after_read_failure() -> None:
    primary = FakeRpc(read_result={"coin": "primary"})
    fallback = FakeRpc(read_result={"coin": "fallback"})
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()
    primary.read_error = TimeoutError("local proof failed")

    with pytest.raises(ChiaProviderError, match="genesis coin-record proof"):
        await provider.get_coin_record_by_name_primary("0x" + "33" * 32)

    assert not any(
        call[0] == "get_coin_record_by_name" for call in fallback.calls
    )


@pytest.mark.asyncio
async def test_genesis_spend_and_peak_proofs_use_synced_primary_only() -> None:
    primary = FakeRpc(read_result={"proof": "primary"})
    fallback = FakeRpc(read_result={"proof": "fallback"})
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()

    spend = await provider.get_puzzle_and_solution_primary(
        "0x" + "44" * 32, 123
    )
    peak = await provider.get_blockchain_state_primary()

    assert spend == {"proof": "primary"}
    assert peak["blockchain_state"]["peak"]["height"] == 123
    assert not any(
        call[0] in {"get_puzzle_and_solution", "get_blockchain_state"}
        for call in fallback.calls
    )


@pytest.mark.asyncio
async def test_ambiguous_push_checks_each_input_before_fallback_submission() -> None:
    bundle = spend_bundle()
    [coin_id] = _input_coin_ids(bundle)
    primary = FakeRpc(push_error=TimeoutError("connection reset"))
    fallback = FakeRpc(
        mempool={coin_id: [{"spend_bundle_name": spend_bundle_id(bundle)}]}
    )
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()

    result = await provider.push_tx(bundle)

    assert result == {
        "success": True,
        "status": "PENDING",
        "already_submitted": True,
    }
    assert ("get_mempool_items_by_coin_name", coin_id) in fallback.calls
    assert not any(call[0] == "push_tx" for call in fallback.calls)


@pytest.mark.asyncio
async def test_ambiguous_push_submits_exactly_once_to_fallback_when_unobserved() -> None:
    bundle = spend_bundle()
    primary = FakeRpc(push_error=TimeoutError("connection reset"))
    fallback = FakeRpc()
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()

    result = await provider.push_tx(bundle)

    assert result["success"] is True
    assert sum(call[0] == "push_tx" for call in fallback.calls) == 1
    assert next(call[1] for call in fallback.calls if call[0] == "push_tx") == bundle


@pytest.mark.asyncio
async def test_ambiguous_push_ignores_different_bundle_using_same_coin() -> None:
    bundle = spend_bundle()
    [coin_id] = _input_coin_ids(bundle)
    primary = FakeRpc(push_error=TimeoutError("connection reset"))
    fallback = FakeRpc(
        mempool={coin_id: [{"spend_bundle_name": "0x" + "99" * 32}]}
    )
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()

    result = await provider.push_tx(bundle)

    assert result["success"] is True
    assert sum(call[0] == "push_tx" for call in fallback.calls) == 1


@pytest.mark.asyncio
async def test_protocol_push_requires_primary_mempool_observation() -> None:
    bundle = spend_bundle()
    [coin_id] = _input_coin_ids(bundle)
    bundle_id = spend_bundle_id(bundle)
    primary = FakeRpc(mempool={coin_id: [{"spend_bundle_name": bundle_id}]})
    fallback = FakeRpc()
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()

    result = await provider.push_tx_confirmed_in_primary_mempool(
        bundle,
        required_coin_id=coin_id,
        required_spend_bundle_id=bundle_id,
        timeout_seconds=1,
        poll_seconds=0.01,
    )

    assert result["status"] == "MEMPOOL"
    assert result["provider"] == "local-full-node"
    assert any(call[0] == "push_tx" for call in primary.calls)
    assert not any(call[0] == "push_tx" for call in fallback.calls)


@pytest.mark.asyncio
async def test_protocol_push_rejects_wrong_required_bundle_id() -> None:
    bundle = spend_bundle()
    [coin_id] = _input_coin_ids(bundle)
    provider = ChiaProvider(FakeRpc(), FakeRpc(), config())
    await provider.start()

    with pytest.raises(ChiaProviderError, match="does not match"):
        await provider.push_tx_confirmed_in_primary_mempool(
            bundle,
            required_coin_id=coin_id,
            required_spend_bundle_id="0x" + "99" * 32,
            timeout_seconds=0,
            poll_seconds=0.01,
        )


@pytest.mark.asyncio
async def test_protocol_fee_estimate_fails_closed_without_primary() -> None:
    provider = ChiaProvider(None, FakeRpc(fee_estimate=5), config(primary_url=None))

    with pytest.raises(ChiaProviderError, match="local Chia full node"):
        await provider.get_fee_estimate(
            target_times=[300],
            spend_bundle=spend_bundle(),
            require_primary=True,
        )


@pytest.mark.asyncio
async def test_unsigned_cost_fee_estimate_uses_only_synchronized_primary() -> None:
    primary, fallback = FakeRpc(fee_estimate=7), FakeRpc(fee_estimate=1)
    provider = ChiaProvider(primary, fallback, config())
    await provider.start()
    result = await provider.get_fee_estimate(target_times=[300], cost=11_000_000_000, require_primary=True)
    assert result['estimates'] == [7]
    assert ('get_fee_estimate', ([300], None, 11_000_000_000)) in primary.calls
    assert not any(name == 'get_fee_estimate' for name, _ in fallback.calls)
    unavailable = ChiaProvider(None, fallback, config(primary_url=None))
    with pytest.raises(ChiaProviderError, match='local Chia full node'):
        await unavailable.get_fee_estimate(target_times=[300], cost=11_000_000_000, require_primary=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('kwargs', [dict(cost=True), dict(cost=0), dict(cost=-1),
    dict(cost=11_000_000_001), dict(cost=1.5), {}, dict(cost=1, spend_bundle={})])
async def test_fee_estimate_rejects_ambiguous_or_invalid_cost_before_rpc(kwargs) -> None:
    primary = FakeRpc()
    provider = ChiaProvider(primary, None, config())
    with pytest.raises(ValueError):
        await provider.get_fee_estimate(target_times=[300], require_primary=True, **kwargs)
    assert primary.calls == []


@pytest.mark.asyncio
async def test_protocol_push_rejection_or_missing_mempool_evidence_fails_closed() -> None:
    bundle = spend_bundle()
    [coin_id] = _input_coin_ids(bundle)
    rejected = ChiaProvider(
        FakeRpc(push_result={"success": False, "status": "FAILED", "error": "bad"}),
        FakeRpc(),
        config(),
    )
    await rejected.start()
    with pytest.raises(ChiaProviderError, match="rejected protocol bundle"):
        await rejected.push_tx_confirmed_in_primary_mempool(
            bundle,
            required_coin_id=coin_id,
            required_spend_bundle_id=spend_bundle_id(bundle),
            timeout_seconds=0,
            poll_seconds=0.01,
        )

    absent = ChiaProvider(FakeRpc(), FakeRpc(), config())
    await absent.start()
    with pytest.raises(ChiaProviderError, match="not observed"):
        await absent.push_tx_confirmed_in_primary_mempool(
            bundle,
            required_coin_id=coin_id,
            required_spend_bundle_id=spend_bundle_id(bundle),
            timeout_seconds=0,
            poll_seconds=0.01,
        )
    assert not any(call[0] == "push_tx" for call in absent.fallback.calls)


@pytest.mark.asyncio
async def test_both_read_providers_failing_is_explicit() -> None:
    provider = ChiaProvider(
        FakeRpc(read_error=TimeoutError("primary")),
        FakeRpc(read_error=TimeoutError("fallback")),
        config(),
    )
    await provider.start()

    with pytest.raises(ChiaProviderError, match="primary and fallback"):
        await provider.get_coin_record_by_name("0x" + "88" * 32)


def test_input_coin_ids_supports_chia_camel_case_json() -> None:
    bundle = spend_bundle()
    coin = bundle["coin_spends"][0]["coin"]
    camel = {
        "coinSpends": [
            {
                "coin": {
                    "parentCoinInfo": coin["parent_coin_info"],
                    "puzzleHash": coin["puzzle_hash"],
                    "amount": coin["amount"],
                }
            }
        ]
    }

    assert _input_coin_ids(camel) == _input_coin_ids(bundle)


def test_browser_proxy_is_allowlisted_and_normalizes_coinset_wire_shapes() -> None:
    record = {
        "coin": {
            "parent_coin_info": "11" * 32,
            "puzzle_hash": "22" * 32,
            "amount": 1,
        }
    }
    fallback = FakeRpc(read_result=record)
    provider = ChiaProvider(
        None,
        fallback,
        config(primary_url=None),
    )
    proxy = FastAPI()
    proxy.state.coinset = provider
    proxy.include_router(chia_proxy_router)

    with TestClient(proxy) as client:
        response = client.post(
            "/chia/get_coin_record_by_name",
            json={"name": "AB" * 32},
        )
        assert response.status_code == 200
        assert response.json() == {"success": True, "coin_record": record}
        assert fallback.calls[-1] == (
            "get_coin_record_by_name",
            "0x" + "ab" * 32,
        )

        assert client.post("/chia/get_connections", json={}).status_code == 404
        assert (
            client.post(
                "/chia/get_coin_record_by_name", json={"name": "not-a-coin"}
            ).status_code
            == 422
        )


def test_browser_proxy_accepts_height_alias_and_rejects_unbounded_bundles() -> None:
    fallback = FakeRpc(read_result={"coin_solution": "value"})
    provider = ChiaProvider(None, fallback, config(primary_url=None))
    proxy = FastAPI()
    proxy.state.coinset = provider
    proxy.include_router(chia_proxy_router)

    with TestClient(proxy) as client:
        solution = client.post(
            "/chia/get_puzzle_and_solution",
            json={"coin_id": "0x" + "12" * 32, "height_at_spend": 44},
        )
        assert solution.status_code == 200
        assert fallback.calls[-1] == (
            "get_puzzle_and_solution",
            ("0x" + "12" * 32, 44),
        )

        oversized = spend_bundle()
        oversized["coin_spends"] = oversized["coin_spends"] * 101
        assert (
            client.post("/chia/push_tx", json={"spend_bundle": oversized}).status_code
            == 422
        )


@pytest.mark.asyncio
async def test_bounded_retry_is_exact_and_journaled_after_unspent_check(tmp_path):
    import sqlite3
    from tests.test_protocol_submission import protocol_bundle
    bundle=protocol_bundle().to_json_dict()
    coin=SpendBundle.from_json_dict(bundle).removals()[0]
    coin_id='0x'+coin.name().hex();bundle_id='0x'+SpendBundle.from_json_dict(bundle).name().hex()
    class RetryRpc(FakeRpc):
        sends=0
        async def push_tx(self,value):
            self.calls.append(('push_tx',value));self.sends+=1
            if self.sends==1:raise TimeoutError('synthetic timeout')
            self.mempool[coin_id]=[{'spend_bundle_name':bundle_id}]
            return {'success':True,'status':'SUCCESS'}
    rpc=RetryRpc(read_result={'coin':coin.to_json_dict(),'confirmed_block_index':10,'spent_block_index':0})
    journal=tmp_path/'submissions.sqlite3'
    provider=ChiaProvider(rpc,FakeRpc(),config(submission_retry_count=2,submission_journal_path=str(journal)))
    result=await provider.push_tx_confirmed_in_primary_mempool(bundle,required_coin_id=coin_id,
        required_spend_bundle_id=bundle_id,timeout_seconds=0,poll_seconds=.01)
    assert result['status']=='MEMPOOL'
    assert [v for op,v in rpc.calls if op=='push_tx']==[bundle,bundle]
    assert ('get_coin_record_by_name',coin_id) in rpc.calls
    db=sqlite3.connect(journal)
    assert db.execute('select event from protocol_submission_events order by id').fetchall()==[('dispatching',),('uncertain',),('dispatching',),('accepted',)]
    db.close()


@pytest.mark.asyncio
async def test_fee_rejection_records_reason_without_repeated_identical_push(tmp_path):
    import sqlite3
    from tests.test_protocol_submission import protocol_bundle
    bundle=protocol_bundle().to_json_dict();coin_id=_input_coin_ids(bundle)[0]
    rpc=FakeRpc(push_result={'success':False,'status':'FAILED','error':'INVALID_FEE_TOO_CLOSE_TO_ZERO'})
    journal=tmp_path/'errors.sqlite3'
    provider=ChiaProvider(rpc,FakeRpc(),config(submission_retry_count=2,submission_journal_path=str(journal)))
    with pytest.raises(ChiaProviderError,match='INVALID_FEE_TOO_CLOSE_TO_ZERO'):
        await provider.push_tx_confirmed_in_primary_mempool(bundle,required_coin_id=coin_id,timeout_seconds=0,poll_seconds=.01)
    assert len([c for c in rpc.calls if c[0]=='push_tx'])==1
    db=sqlite3.connect(journal)
    assert db.execute("select error_code from protocol_submission_events where event='rejected'").fetchone()[0]=='INVALID_FEE_TOO_CLOSE_TO_ZERO'
    db.close()
