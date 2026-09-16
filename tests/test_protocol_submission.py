from __future__ import annotations

from typing import Any

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.faucet import Faucet, FaucetSelectionRestricted
from solslot_api.config import Settings, validate_server_hardening_at_startup
from solslot_api.protocol_submission import (
    PreparedProtocolBundle,
    ProtocolBundleSubmitter,
    ProtocolFeePolicy,
    ProtocolSubmissionError,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def coin_record(coin: Coin) -> dict[str, Any]:
    return {
        "coin": {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": 10,
        "spent_block_index": 0,
    }


def protocol_bundle(amount: int = 10) -> SpendBundle:
    coin = Coin(b32(1), b32(2), uint64(amount))
    output = b32(3)
    puzzle = Program.to((1, [[51, output, amount]]))
    return SpendBundle(
        [make_spend(coin, puzzle, Program.to(0))],
        G2Element(),
    )


class FakeProvider:
    def __init__(
        self,
        *,
        fee_coin: Coin,
        base_fee: int = 4,
        aggregate_fee: int = 7,
        pending: bool = False,
    ) -> None:
        self.fee_coin = fee_coin
        self.base_fee = base_fee
        self.aggregate_fee = aggregate_fee
        self.pending = pending
        self.estimates: list[dict[str, Any]] = []
        self.submitted: dict[str, Any] | None = None
        self.required_spend_bundle_id: str | None = None

    async def get_fee_estimate(
        self,
        *,
        target_times: list[int],
        spend_bundle: dict[str, Any],
        require_primary: bool,
    ) -> dict[str, Any]:
        self.estimates.append(spend_bundle)
        count = len(spend_bundle["coin_spends"])
        estimate = self.base_fee if count == 1 else self.aggregate_fee
        return {"target_times": target_times, "estimates": [estimate]}

    async def get_coin_records_by_puzzle_hash(
        self, puzzle_hash: str, *, include_spent: bool
    ) -> list[dict[str, Any]]:
        return [coin_record(self.fee_coin)]

    async def get_mempool_items_by_coin_name(
        self, coin_id: str
    ) -> list[dict[str, Any]]:
        return [{"name": "pending"}] if self.pending else []

    async def push_tx_confirmed_in_primary_mempool(
        self,
        spend_bundle_json: dict[str, Any],
        *,
        required_coin_id: str,
        required_spend_bundle_id: str,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> dict[str, Any]:
        self.submitted = spend_bundle_json
        self.required_spend_bundle_id = required_spend_bundle_id
        assert required_spend_bundle_id == "0x" + SpendBundle.from_json_dict(
            spend_bundle_json
        ).name().hex()
        return {
            "provider": "local-full-node",
            "observed_at": "2026-07-27T12:00:00+00:00",
            "ambiguous_push": False,
        }


def submitter(
    provider: FakeProvider,
    faucet: Faucet,
    **updates: Any,
) -> ProtocolBundleSubmitter:
    values = {
        "enabled": True,
        "target_seconds": 300,
        "minimum_mojos": 1,
        "maximum_mojos": 100,
        "maximum_funding_coin_mojos": 1000,
        "mempool_timeout_seconds": 2,
        "mempool_poll_seconds": 0.1,
    }
    values.update(updates)
    return ProtocolBundleSubmitter(
        provider=provider,  # type: ignore[arg-type]
        faucet=faucet,
        policy=ProtocolFeePolicy(**values),
    )


def test_ceremony_faucet_exclusivity_blocks_every_other_selection_purpose() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    coin = Coin(b32(46), faucet.address_puzzle_hash, uint64(100))
    records = [coin_record(coin)]
    faucet.restrict_coin_selection_to("genesis")

    with pytest.raises(RuntimeError, match="reserved for genesis"):
        faucet.select_coin(records, 1)
    with pytest.raises(RuntimeError, match="reserved for genesis"):
        faucet.select_coin(records, 1, purpose="vault-launch")

    selected = faucet.select_coin(records, 1, purpose="genesis")
    assert selected is not None
    assert selected.name() == coin.name()
    with pytest.raises(FaucetSelectionRestricted, match="reserved for genesis"):
        faucet.sign_delegated_spend(coin, Program.to([]))
    assert len(
        faucet.sign_delegated_spend(
            coin,
            Program.to([]),
            purpose="genesis",
        )
    ) == 96


@pytest.mark.asyncio
async def test_medium_fee_is_added_from_till_without_changing_protocol_outputs() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(4), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    original = protocol_bundle()

    receipt = await submitter(provider, faucet).submit(original.to_json_dict())

    assert receipt["status"] == "MEMPOOL"
    assert receipt["feeMojos"] == "7"
    assert receipt["feeTargetSeconds"] == 300
    assert receipt["submissionProvider"] == "local-full-node"
    assert provider.submitted is not None
    final = SpendBundle.from_json_dict(provider.submitted)
    assert len(final.coin_spends) == 2
    assert sum(int(coin.amount) for coin in final.removals()) - sum(
        int(coin.amount) for coin in final.additions()
    ) == 7
    assert compute_additions(final.coin_spends[0]) == compute_additions(
        original.coin_spends[0]
    )
    fee_additions = compute_additions(final.coin_spends[1])
    assert len(fee_additions) == 1
    assert fee_additions[0].puzzle_hash == faucet.address_puzzle_hash
    assert int(fee_additions[0].amount) == 93


@pytest.mark.asyncio
async def test_before_push_receives_exact_prepared_bundle_before_provider_push() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(42), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    observed: list[PreparedProtocolBundle] = []

    async def before_push(prepared: PreparedProtocolBundle) -> None:
        assert provider.submitted is None
        assert prepared.spend_bundle_id == "0x" + prepared.bundle.name().hex()
        assert prepared.to_json()["spendBundle"] == prepared.bundle.to_json_dict()
        observed.append(prepared)

    receipt = await submitter(provider, faucet).submit(
        protocol_bundle().to_json_dict(),
        before_push=before_push,
    )

    assert len(observed) == 1
    assert provider.submitted == observed[0].bundle.to_json_dict()
    assert receipt["spendBundleId"] == observed[0].spend_bundle_id


@pytest.mark.asyncio
async def test_sync_before_push_rejection_prevents_provider_push() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(43), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    observed_ids: list[str] = []

    def before_push(prepared: PreparedProtocolBundle) -> None:
        observed_ids.append(prepared.spend_bundle_id)
        raise RuntimeError("durable reservation rejected")

    with pytest.raises(RuntimeError, match="durable reservation rejected"):
        await submitter(provider, faucet).submit(
            protocol_bundle().to_json_dict(),
            before_push=before_push,
        )

    assert len(observed_ids) == 1
    assert provider.submitted is None


@pytest.mark.asyncio
async def test_reserved_replay_revalidates_inside_lock_and_pushes_exact_bundle() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(44), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    service = submitter(provider, faucet)
    reservation = await service.submit(protocol_bundle().to_json_dict())
    provider.submitted = None
    callback_observations: list[bool] = []

    def before_push() -> None:
        callback_observations.append(service._lock.locked())
        assert provider.submitted is None

    receipt = await service.reconcile_reserved(
        reservation,
        before_push=before_push,
    )

    assert callback_observations == [True]
    assert receipt["status"] == "MEMPOOL_RECONCILED"
    assert receipt["spendBundleId"] == reservation["spendBundleId"]
    assert provider.required_spend_bundle_id == reservation["spendBundleId"]
    assert provider.submitted == reservation["spendBundle"]


@pytest.mark.asyncio
async def test_reserved_replay_rejects_changed_bundle_id_before_push() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(45), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    service = submitter(provider, faucet)
    reservation = await service.submit(protocol_bundle().to_json_dict())
    provider.submitted = None
    changed = {**reservation, "spendBundleId": "0x" + "99" * 32}

    with pytest.raises(ProtocolSubmissionError, match="changed its bundle id"):
        await service.reconcile_reserved(changed)

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_exact_dispatch_hands_off_funded_bundle_without_direct_push() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(41), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    dispatched: list[PreparedProtocolBundle] = []

    async def dispatcher(prepared: PreparedProtocolBundle) -> dict[str, bool]:
        dispatched.append(prepared)
        return {"accepted": True}

    receipt = await submitter(provider, faucet).prepare_and_dispatch(
        protocol_bundle().to_json_dict(),
        dispatcher,
    )

    assert receipt["status"] == "DISPATCHED"
    assert receipt["feeMojos"] == "7"
    assert receipt["dispatchResult"] == {"accepted": True}
    assert provider.submitted is None
    assert len(dispatched) == 1
    assert receipt["spendBundleId"] == "0x" + dispatched[0].bundle.name().hex()
    assert receipt["feeCoinId"] == "0x" + fee_coin.name().hex()


@pytest.mark.asyncio
async def test_529_mojo_ceremony_input_keeps_its_full_output_value() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(40), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    ceremony = protocol_bundle(529)

    receipt = await submitter(provider, faucet).submit(ceremony.to_json_dict())

    assert receipt["feeMojos"] == "7"
    assert provider.submitted is not None
    final = SpendBundle.from_json_dict(provider.submitted)
    assert int(final.removals()[0].amount) == 529
    assert sum(
        int(coin.amount) for coin in compute_additions(final.coin_spends[0])
    ) == 529
    assert bytes(final.removals()[1].name()) == bytes(fee_coin.name())


@pytest.mark.asyncio
async def test_fee_above_cap_fails_before_submission() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(5), faucet.address_puzzle_hash, uint64(100)),
        base_fee=101,
        aggregate_fee=101,
    )

    with pytest.raises(ProtocolSubmissionError, match="exceeds configured cap"):
        await submitter(provider, faucet).submit(protocol_bundle().to_json_dict())

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_pending_or_insufficient_till_coin_fails_closed() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    pending = FakeProvider(
        fee_coin=Coin(b32(6), faucet.address_puzzle_hash, uint64(100)),
        pending=True,
    )
    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await submitter(pending, faucet).submit(protocol_bundle().to_json_dict())

    small = FakeProvider(
        fee_coin=Coin(b32(7), faucet.address_puzzle_hash, uint64(3)),
        base_fee=4,
    )
    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await submitter(small, faucet).submit(protocol_bundle().to_json_dict())


@pytest.mark.asyncio
async def test_fee_coin_cannot_duplicate_a_protocol_input() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    shared_coin = Coin(b32(70), faucet.address_puzzle_hash, uint64(100))
    protocol_spend = SpendBundle(
        [
            make_spend(
                shared_coin,
                Program.to((1, [[51, b32(71), 100]])),
                Program.to(0),
            )
        ],
        G2Element(),
    )
    provider = FakeProvider(fee_coin=shared_coin)

    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await submitter(provider, faucet).submit(protocol_spend.to_json_dict())

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_durable_exact_execution_reserves_its_fee_coin() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    fee_coin = Coin(b32(72), faucet.address_puzzle_hash, uint64(100))
    provider = FakeProvider(fee_coin=fee_coin)
    service = submitter(provider, faucet)
    service.add_fee_coin_reservation_source(
        lambda: {"0x" + fee_coin.name().hex()}
    )

    with pytest.raises(ProtocolSubmissionError, match="no eligible"):
        await service.submit(protocol_bundle().to_json_dict())

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_malformed_durable_fee_reservation_fails_closed() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(73), faucet.address_puzzle_hash, uint64(100))
    )
    service = submitter(provider, faucet)
    service.add_fee_coin_reservation_source(lambda: {"not-a-coin-id"})

    with pytest.raises(ProtocolSubmissionError, match="reservation is malformed"):
        await service.submit(protocol_bundle().to_json_dict())

    assert provider.submitted is None


@pytest.mark.asyncio
async def test_protocol_fee_funding_is_fail_closed_by_default() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(8), faucet.address_puzzle_hash, uint64(100))
    )
    service = ProtocolBundleSubmitter(
        provider=provider,  # type: ignore[arg-type]
        faucet=faucet,
        policy=ProtocolFeePolicy(),
    )

    with pytest.raises(ProtocolSubmissionError, match="disabled"):
        await service.submit(protocol_bundle().to_json_dict())


@pytest.mark.asyncio
async def test_existing_user_fee_is_rejected_instead_of_double_charged() -> None:
    faucet = Faucet.from_seed_hex("01" * 32, "testnet11")
    provider = FakeProvider(
        fee_coin=Coin(b32(9), faucet.address_puzzle_hash, uint64(100))
    )
    base_coin = Coin(b32(10), b32(11), uint64(10))
    fee_bearing = SpendBundle(
        [
            make_spend(
                base_coin,
                Program.to((1, [[51, b32(12), 9], [52, 1]])),
                Program.to(0),
            )
        ],
        G2Element(),
    )

    with pytest.raises(ProtocolSubmissionError, match="user-funded fee"):
        await submitter(provider, faucet).submit(fee_bearing.to_json_dict())

    assert provider.submitted is None


def test_fee_till_configuration_requires_local_node_and_existing_key() -> None:
    with pytest.raises(RuntimeError, match="SOLSLOT_CHIA_PRIMARY_URL"):
        validate_server_hardening_at_startup(
            Settings(protocol_fee_funding_enabled=True)
        )

    with pytest.raises(RuntimeError, match="SOLSLOT_FAUCET"):
        validate_server_hardening_at_startup(
            Settings(
                protocol_fee_funding_enabled=True,
                chia_primary_url="https://127.0.0.1:18555",
            )
        )

    validate_server_hardening_at_startup(
        Settings(
            runtime_environment="test",
            protocol_fee_funding_enabled=True,
            chia_primary_url="https://127.0.0.1:18555",
            faucet_seed_hex="01" * 32,
        )
    )


def test_voucher_worker_requires_fee_funding_and_exact_kos_executor() -> None:
    with pytest.raises(RuntimeError, match="PROTOCOL_FEE_FUNDING_ENABLED"):
        validate_server_hardening_at_startup(
            Settings(
                presale_enabled=True,
                voucher_issuance_worker_enabled=True,
            )
        )

    with pytest.raises(RuntimeError, match="exact Key of Solomon executor"):
        validate_server_hardening_at_startup(
            Settings(
                presale_enabled=True,
                voucher_issuance_worker_enabled=True,
                protocol_fee_funding_enabled=True,
                chia_primary_url="https://127.0.0.1:18555",
                faucet_seed_hex="01" * 32,
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize('backing,cap,coin_amount,allowed', [
    (20,20,100,True), (0,20,100,False), (19,20,100,False),
    (21,20,100,False), (20,0,100,False), (20,20,23,False),
    (True,20,100,False), (-1,20,100,False),
])
async def test_issuance_backing_is_exact_bounded_and_separate_from_reserved_fee(backing,cap,coin_amount,allowed):
    from chia_rs import AugSchemeMPL
    from chia.consensus.default_constants import DEFAULT_CONSTANTS
    import chia_rs
    faucet = Faucet.from_seed_hex('01' * 32, 'testnet11')
    coin = Coin(b32(191), faucet.address_puzzle_hash, uint64(coin_amount))
    provider = FakeProvider(fee_coin=coin)
    # A synthetic protocol issuance has an independently specified 20 mojo deficit.
    puzzle = Program.to((1, [[51,b32(192),30],[60,b"synthetic-issuance"]]))
    original = SpendBundle([make_spend(Coin(b32(193),puzzle.get_tree_hash(),uint64(10)),puzzle,Program.to(0))],G2Element())
    if allowed:
        small = Coin(b32(194), faucet.address_puzzle_hash, uint64(23))
        async def records(*_args, **_kwargs):
            return [coin_record(small),coin_record(coin)]
        provider.get_coin_records_by_puzzle_hash = records
    actual = submitter(provider,faucet,maximum_backing_mojos=cap)
    if not allowed:
        with pytest.raises(ProtocolSubmissionError):
            await actual.submit(original.to_json_dict(),expected_backing_mojos=backing)
        assert provider.submitted is None
        return
    result = await actual.submit(original.to_json_dict(),expected_backing_mojos=backing)
    final = SpendBundle.from_json_dict(provider.submitted)
    assert result['feeCoinId'] == "0x" + coin.name().hex()
    assert result['backingMojos'] == '20'
    assert result['feeMojos'] == '7'
    assert sum(c.amount for c in final.removals()) - sum(c.amount for c in final.additions()) == 7
    assert int(compute_additions(final.coin_spends[-1])[0].amount) == 73
    detached = SpendBundle([final.coin_spends[-1]], final.aggregated_signature)
    with pytest.raises(ValueError):
        chia_rs.validate_clvm_and_signature(detached,11_000_000_000,DEFAULT_CONSTANTS,chia_rs.MEMPOOL_MODE)
    chia_rs.validate_clvm_and_signature(final,11_000_000_000,DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(
        __import__("solslot_api.faucet",fromlist=["AGG_SIG_ME_DATA"]).AGG_SIG_ME_DATA["testnet11"])),chia_rs.MEMPOOL_MODE)
