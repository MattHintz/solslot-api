from __future__ import annotations

import json
import sqlite3
import stat

import pytest
from chia_rs import Coin, G2Element, SpendBundle

from solslot_api.chia_provider import ChiaProvider, ChiaProviderError
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError
from solslot_api.faucet import Faucet
from tests.test_protocol_submission import FakeProvider, b32, coin_record, protocol_bundle, submitter
from tests.test_chia_provider import FakeRpc, config


@pytest.mark.asyncio
async def test_timeout_restart_reuses_exact_funding_without_new_quote(tmp_path):
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(8), faucet.address_puzzle_hash, 100)
    path = tmp_path / "new" / "funding.sqlite3"
    store = ProtocolFundingStore(path)
    original = protocol_bundle().to_json_dict()
    saved_id = "0x" + protocol_bundle().name().hex()
    pushed = []

    class Provider(FakeProvider):
        async def push_tx_confirmed_in_primary_mempool(self, bundle, **kwargs):
            # The immutable reservation must already be committed before RPC.
            other = ProtocolFundingStore(path)
            row = other.db.execute("SELECT document FROM funded_protocol_bundles").fetchone()
            other.close()
            assert json.loads(row[0])["spendBundle"] == bundle
            pushed.append(bundle)
            if len(pushed) == 1:
                raise ChiaProviderError("timeout containing private transport details")
            return await super().push_tx_confirmed_in_primary_mempool(bundle, **kwargs)

        async def observe_exact_protocol_bundle(self, bundle):
            assert bundle == pushed[0]
            return None

    provider = Provider(fee_coin=fee_coin)
    first = ProtocolBundleSubmitter(provider=provider, faucet=faucet,
        policy=submitter(provider, faucet).policy, funding_store=store)
    with pytest.raises(ProtocolSubmissionError):
        await first.submit(original)
    assert len(store.reserved_coin_ids()) == 2
    store.close()
    store = ProtocolFundingStore(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    provider.base_fee = provider.aggregate_fee = 99
    quote_count = len(provider.estimates)
    restarted = ProtocolBundleSubmitter(provider=provider, faucet=faucet,
        policy=first.policy, funding_store=store)
    result = await restarted.submit(original)
    assert pushed[0] == pushed[1] == result["spendBundle"]
    assert len(provider.estimates) == quote_count
    with pytest.raises(ProtocolSubmissionError, match="reconciled"):
        await restarted.submit(original, selection_purpose="different-purpose")
    events = list(store.db.execute("SELECT error_code FROM funded_protocol_events"))
    assert any(row[0] == "TRANSPORT_OR_TIMEOUT" for row in events)
    assert not any("private transport" in str(tuple(row)) for row in events)
    assert store.db.execute("SELECT original_id FROM funded_protocol_bundles").fetchone()[0] == saved_id
    store.close()


@pytest.mark.asyncio
async def test_reservation_failure_prevents_rpc_and_changed_bundle_cannot_reuse_inputs(tmp_path):
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(fee_coin=Coin(b32(8), faucet.address_puzzle_hash, 100))
    store = ProtocolFundingStore(tmp_path / "funding.sqlite3")
    service = ProtocolBundleSubmitter(provider=provider, faucet=faucet,
        policy=submitter(provider, faucet).policy, funding_store=store)
    async def reject(_):
        raise ValueError("caller persistence failed")
    with pytest.raises(ValueError, match="persistence"):
        await service.submit(protocol_bundle().to_json_dict(), before_push=reject)
    assert provider.submitted is None
    row = json.loads(store.db.execute("SELECT document FROM funded_protocol_bundles").fetchone()[0])
    with pytest.raises(sqlite3.IntegrityError):
        store.reserve("testnet11", "0x" + "91" * 32, {}, row)
    assert store.db.execute("SELECT COUNT(*) FROM funded_protocol_bundles").fetchone()[0] == 1
    store.close()


class ObservationRpc(FakeRpc):
    def __init__(self, bundle, *, spent=50, changed_spend=False, changing_tip=False, pending=False):
        super().__init__()
        self.bundle = bundle
        self.spent = spent
        self.changed_spend = changed_spend
        self.changing_tip = changing_tip
        self.pending = pending
        self.peaks = 0

    async def get_blockchain_state(self):
        self.peaks += 1
        response = await super().get_blockchain_state()
        response["blockchain_state"]["peak"]["header_hash"] = "0x" + ("33" if self.changing_tip and self.peaks > 2 else "22") * 32
        return response

    async def get_coin_record_by_name(self, coin_id):
        for coin in self.bundle.removals():
            if "0x" + coin.name().hex() == coin_id:
                return {**coin_record(coin), "spent_block_index": self.spent}
        return None

    async def get_puzzle_and_solution(self, coin_id, height):
        spend = next(s for s in self.bundle.coin_spends if "0x" + s.coin.name().hex() == coin_id)
        result = spend.to_json_dict()
        if self.changed_spend:
            result["solution"] = "0x01"
        return result

    async def get_mempool_items_by_coin_name(self, coin_id):
        return [{"name": "0x" + self.bundle.name().hex()}] if self.pending else []


@pytest.mark.asyncio
@pytest.mark.parametrize("spent,pending,status", [(50, False, "CONFIRMED"), (0, True, "MEMPOOL"), (0, False, None)])
async def test_primary_exact_observation_requires_chain_evidence(spent, pending, status):
    bundle = protocol_bundle()
    node = ObservationRpc(bundle, spent=spent, pending=pending)
    provider = ChiaProvider(node, FakeRpc(), config())
    result = await provider.observe_exact_protocol_bundle(bundle.to_json_dict())
    assert (result["status"] if result else None) == status
    assert not any(name == "push_tx" for name, _ in node.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [{"changed_spend": True}, {"changing_tip": True}, {"spent": 50, "pending": True}])
async def test_spent_input_or_reorg_is_not_success(kwargs):
    bundle = protocol_bundle()
    node = ObservationRpc(bundle, **kwargs)
    provider = ChiaProvider(node, FakeRpc(), config())
    with pytest.raises(ChiaProviderError):
        await provider.observe_exact_protocol_bundle(bundle.to_json_dict())


@pytest.mark.asyncio
async def test_confirmed_saved_submission_does_not_broadcast_again(tmp_path):
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    class Confirmed(FakeProvider):
        async def observe_exact_protocol_bundle(self, bundle):
            return {"status": "CONFIRMED", "provider": "local-full-node", "observed_at": "now",
                    "ambiguous_push": True, "confirmed_height": 50}
    provider = Confirmed(fee_coin=Coin(b32(8), faucet.address_puzzle_hash, 100))
    store = ProtocolFundingStore(tmp_path / "funding.sqlite3")
    service = ProtocolBundleSubmitter(provider=provider, faucet=faucet,
        policy=submitter(provider, faucet).policy, funding_store=store)
    await service.submit(protocol_bundle().to_json_dict())
    provider.submitted = None
    result = await service.submit(protocol_bundle().to_json_dict())
    assert result["status"] == "CONFIRMED" and result["confirmedHeight"] == 50
    assert provider.submitted is None
    store.close()
