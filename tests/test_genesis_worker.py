from __future__ import annotations

from types import SimpleNamespace

from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.genesis_worker import _expected_outputs
from solslot_puzzles.protocol_deployment import cat2_puzzle_hash_for_sgt


def _surface(seed: int) -> SimpleNamespace:
    return SimpleNamespace(
        launcher_id=bytes32(bytes([seed]) * 32),
        full_puzzle_hash=bytes32(bytes([seed + 1]) * 32),
    )


def test_expected_outputs_include_property_registry_current_coin() -> None:
    pool = _surface(10)
    did = _surface(20)
    governance = _surface(30)
    property_registry = _surface(80)
    plan = SimpleNamespace(
        funding=SimpleNamespace(sgt=bytes32(b"s" * 32)),
        protocol=SimpleNamespace(
            permanent_rules=SimpleNamespace(sgt_total_supply=1_000_000),
            sgt_reserve_inner_puzzle_hash=bytes32(b"v" * 32),
            sgt_full_puzzle_hash=cat2_puzzle_hash_for_sgt(
                governance.launcher_id, bytes32(b"s" * 32), bytes32(b"v" * 32),
            ),
            pool_launcher_id=pool.launcher_id,
            pool_full_puzzle_hash=pool.full_puzzle_hash,
            did_launcher_id=did.launcher_id,
            did_full_puzzle_hash=did.full_puzzle_hash,
            governance_launcher_id=governance.launcher_id,
            governance_full_puzzle_hash=governance.full_puzzle_hash,
            sols_reserve_seed_coin_id=bytes32(b"r" * 32),
        ),
        statutes=_surface(40),
        protocol_config=_surface(50),
        admin_authority=_surface(60),
        admin_authority_v3=SimpleNamespace(
            identity_vaults=tuple(
                SimpleNamespace(
                    launcher_id=bytes32(bytes([90 + index]) * 32),
                    full_puzzle_hash=bytes32(
                        bytes([100 + index]) * 32
                    ),
                    launcher_amount=amount,
                )
                for index, amount in enumerate((3, 5, 7))
            )
        ),
        vault_version_registry=_surface(70),
        property_registry=property_registry,
        bridge_batch=SimpleNamespace(
            bridge_coins=tuple(
                Coin(
                    bytes32(bytes([index]) * 32),
                    bytes32(bytes([index + 32]) * 32),
                    uint64(1),
                )
                for index in range(1, 33)
            )
        ),
    )

    coin_ids = _expected_outputs(plan)
    property_registry_coin_id = "0x" + bytes(
        Coin(
            property_registry.launcher_id,
            property_registry.full_puzzle_hash,
            uint64(1),
        ).name()
    ).hex()

    assert property_registry_coin_id in coin_ids
    assert len(coin_ids) == 45
