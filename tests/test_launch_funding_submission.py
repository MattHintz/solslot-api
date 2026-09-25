"""Exercise the guided fan-out with the real fee builder and durable journal."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request
from chia_rs import Coin, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_api.chia_provider import ChiaProviderError
from solslot_api.faucet import Faucet
from solslot_api.genesis_funding import plan_genesis_funding_fanout
from solslot_api.launch_control import LaunchSession, execute_fixed_funding
from solslot_api.protocol_funding_store import ProtocolFundingStore
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
from tests.test_protocol_submission import FakeProvider, b32, coin_record


class CeremonyStore:
    def __init__(self, plan):
        self.receipt = {"plan": plan.plan, "planHash": plan.digest,
                        "state": "approved", "spendBundleId": None, "response": None}
        self.approved = True

    def funding_receipt(self, ceremony_id):
        return deepcopy(self.receipt)

    def action_approvals(self, *args, **kwargs):
        return {"approved": self.approved}

    def set_funding_receipt(self, ceremony_id, **receipt):
        assert receipt["plan"] == self.receipt["plan"]
        assert receipt["plan_hash"] == self.receipt["planHash"]
        self.receipt.update(state=receipt["state"], spendBundleId=receipt["spend_bundle_id"],
                            response=receipt["response"])
        return deepcopy(self.receipt)


@pytest.fixture
def funding(tmp_path):
    faucet = Faucet.from_seed_hex("25" * 32, "testnet11")
    faucet.restrict_coin_selection_to("genesis")
    source = Coin(b32(21), faucet.address_puzzle_hash, uint64(2_000_000_000))
    fee_coin = Coin(b32(22), faucet.address_puzzle_hash, uint64(10_000_000_000))
    plan = plan_genesis_funding_fanout(source_coin=source,
        faucet_puzzle_hash=faucet.address_puzzle_hash, network="testnet11")
    store = CeremonyStore(plan)
    journal = ProtocolFundingStore(str(tmp_path / "funding.sqlite"))

    class Provider(FakeProvider):
        source_spent = False
        ambiguous = False
        saved = None
        pushes = 0

        async def get_coin_record_by_name(self, coin_id):
            assert coin_id == "0x" + source.name().hex()
            return {**coin_record(source), "spent_block_index": 100 if self.source_spent else 0}

        async def get_coin_records_by_puzzle_hash(self, *args, **kwargs):
            return [coin_record(source), coin_record(fee_coin)]

        async def push_tx_confirmed_in_primary_mempool(self, bundle_json, **kwargs):
            self.pushes += 1
            self.saved = bundle_json
            bundle_id = "0x" + SpendBundle.from_json_dict(bundle_json).name().hex()
            assert store.receipt["state"] == "ambiguous"
            assert store.receipt["spendBundleId"] == bundle_id
            assert len(journal.reserved_coin_ids()) == 2
            if self.ambiguous:
                raise ChiaProviderError("provider response was ambiguous")
            return await super().push_tx_confirmed_in_primary_mempool(bundle_json, **kwargs)

        async def observe_exact_protocol_bundle(self, bundle_json):
            assert bundle_json == self.saved
            return {"status": "CONFIRMED", "provider": "local-full-node", "observed_at": "2026-09-25T00:00:00Z",
                    "ambiguous_push": True, "confirmed_height": 100}

    provider = Provider(fee_coin=fee_coin, base_fee=100_000_000, aggregate_fee=150_000_000)
    policy = ProtocolFeePolicy(enabled=True, minimum_mojos=100_000_000,
        maximum_mojos=1_000_000_000, maximum_funding_coin_mojos=20_000_000_000,
        target_seconds=60, estimate_buffer_bps=12_500)
    submitter = ProtocolBundleSubmitter(provider=provider, faucet=faucet, policy=policy, funding_store=journal)
    app = SimpleNamespace(state=SimpleNamespace(faucet=faucet, coinset=provider, protocol_submitter=submitter))
    values = SimpleNamespace(request=Request({"type": "http", "app": app}),
        settings=SimpleNamespace(alpha_writes_enabled=True, ceremony_mode_enabled=True),
        session=LaunchSession("test-funding-ceremony", 1, "0x"+"12"*20, False, 2_000_000_000),
        store=store, journal=journal, provider=provider, faucet=faucet, source=source, fee_coin=fee_coin, policy=policy)
    yield values
    journal.close()


async def execute(funding):
    return await execute_fixed_funding(funding.request, funding.settings, funding.store, funding.session)


@pytest.mark.asyncio
async def test_guided_funding_sponsors_fee_without_changing_approved_outputs(funding):
    result = await execute(funding)
    bundle = SpendBundle.from_json_dict(funding.provider.saved)
    additions = {"0x" + c.name().hex(): int(c.amount) for c in bundle.additions()}
    assert all(additions[o["coinId"]] == o["amount"] for o in result["plan"]["outputs"])
    assert len(result["plan"]["outputs"]) == 9
    assert result["response"]["feeMojos"] == "187500000"
    assert result["response"]["feeCoinId"] == "0x" + funding.fee_coin.name().hex()
    assert result["state"] == "broadcast"
    assert result["spendBundleId"] == "0x" + bundle.name().hex()
    assert "spendBundle" not in result["response"]
    assert funding.provider.pushes == 1


@pytest.mark.asyncio
async def test_timeout_then_restart_reconciles_same_funding_even_after_input_spent(funding):
    funding.provider.ambiguous = True
    with pytest.raises(HTTPException) as error:
        await execute(funding)
    assert error.value.status_code == 503
    assert funding.store.receipt["state"] == "ambiguous"
    saved_id = funding.store.receipt["spendBundleId"]
    funding.provider.source_spent = True
    funding.journal.close()
    funding.journal = ProtocolFundingStore(funding.journal.path)
    funding.faucet = Faucet.from_seed_hex("25" * 32, "testnet11")
    funding.faucet.restrict_coin_selection_to("genesis")
    funding.request.app.state.faucet = funding.faucet
    # Fresh process objects and reopened SQLite journal simulate a restart.
    funding.request.app.state.protocol_submitter = ProtocolBundleSubmitter(
        provider=funding.provider, faucet=funding.faucet, policy=funding.policy, funding_store=funding.journal)
    try:
        result = await execute(funding)
        assert result["spendBundleId"] == saved_id
        assert result["response"]["status"] == "CONFIRMED"
        assert funding.provider.pushes == 1
        assert len(funding.provider.estimates) == 3  # No new fee quote on retry.
    finally:
        funding.journal.close()


@pytest.mark.asyncio
async def test_fee_over_cap_never_submits(funding):
    funding.provider.base_fee = 2_000_000_000
    with pytest.raises(HTTPException) as error:
        await execute(funding)
    assert error.value.status_code == 503
    assert funding.provider.pushes == 0
    assert funding.store.receipt["spendBundleId"] is None


@pytest.mark.asyncio
async def test_unapproved_funding_never_selects_fee_or_submits(funding):
    funding.store.approved = False
    with pytest.raises(HTTPException) as error:
        await execute(funding)
    assert error.value.status_code == 409
    assert funding.provider.pushes == 0
    assert funding.provider.estimates == []


@pytest.mark.asyncio
async def test_spent_source_without_saved_funding_is_not_resubmitted(funding):
    funding.provider.source_spent = True
    with pytest.raises(HTTPException) as error:
        await execute(funding)
    assert error.value.status_code == 409
    assert funding.provider.pushes == 0


@pytest.mark.asyncio
async def test_funding_requires_a_durable_fee_journal(funding):
    funding.request.app.state.protocol_submitter.funding_store = None
    with pytest.raises(HTTPException) as error:
        await execute(funding)
    assert error.value.status_code == 409
    assert funding.provider.pushes == 0


@pytest.mark.asyncio
async def test_changed_funded_id_is_not_replaced(funding):
    funding.store.receipt["spendBundleId"] = "0x" + "99" * 32
    with pytest.raises(HTTPException) as error:
        await execute(funding)
    assert error.value.status_code == 409
    assert funding.provider.pushes == 0
