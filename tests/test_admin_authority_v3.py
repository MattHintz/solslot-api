from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    puzzle_for_singleton,
)
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api.admin_authority_v3 import (
    _state_after_solution,
    build_admin_authority_v3_snapshot,
)
from solslot_api.admin_key_changes import (
    _authority_inner_from_snapshot,
    _genesis_authority_from_artifact,
)
from solslot_puzzles.admin_authority_v3_driver import (
    AUTHORITY_LAUNCHER_AMOUNT,
    PENDING_RECOVERY_KIT,
    SPEND_COMPLETE,
    SPEND_OPERATIONAL,
    SPEND_PREPARE_KIT,
    admin_authority_v3_inner_mod_hash,
    build_complete_solution,
    build_genesis_admin_authority_v3,
    build_identity_vault_transition,
    build_prepare_solution,
    make_inner_puzzle,
)


PARENT_ID = bytes32(b"\x71" * 32)
SOURCE_MANIFEST_HASH = bytes32(b"\x72" * 32)
DAILY_KEYS = tuple(
    keys.PrivateKey(bytes([index]) * 32).public_key.to_compressed_bytes()
    for index in (1, 2, 3)
)
RECOVERY_KEYS = tuple(
    bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
    for index in (4, 5, 6)
)


def _artifact(*, authority_puzzle_version: int = 3) -> tuple[dict, object]:
    authority = build_genesis_admin_authority_v3(
        authority_puzzle_version=authority_puzzle_version,
        parent_coin_id=PARENT_ID,
        network="testnet11",
        daily_compressed_pubkeys=DAILY_KEYS,
        recovery_bls_pubkeys=RECOVERY_KEYS,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    artifact = {
        "network": "testnet11",
        "genesisPlan": {
            "fundingCoinIds": {"admin_authority": "0x" + PARENT_ID.hex()},
            **(
                {"authorityPuzzleVersion": authority_puzzle_version}
                if authority_puzzle_version != 3 else {}
            ),
        },
        "launcherIds": {
            "adminAuthority": "0x" + authority.authority_launcher_id.hex(),
        },
        "puzzleHashes": {
            "adminAuthorityInnerMod": (
                "0x"
                + admin_authority_v3_inner_mod_hash(authority_puzzle_version).hex()
            ),
            "adminAuthorityFull": "0x" + authority.full_puzzle_hash.hex(),
        },
        "adminAuthority": {
            "version": 3,
            "sourceManifestHash": "0x" + SOURCE_MANIFEST_HASH.hex(),
            "operationalMipsRootHash": (
                "0x" + authority.operational_root_hash.hex()
            ),
            "lostRecoveryMipsRootHashes": [
                "0x" + value.hex()
                for value in authority.lost_recovery_root_hashes
            ],
            "routineDelaySeconds": 86_400,
            "lostKeyDelaySeconds": 604_800,
            "identityVaults": [
                {
                    "slot": identity.slot,
                    "launcherId": "0x" + identity.launcher_id.hex(),
                    "dailyCompressedPubkey": (
                        "0x" + identity.daily_compressed_pubkey.hex()
                    ),
                    "recoveryBlsPubkey": (
                        "0x" + identity.recovery_bls_pubkey.hex()
                    ),
                    "recoveryMemberHash": (
                        "0x" + identity.recovery_member_hash.hex()
                    ),
                    "custodyHash": "0x" + identity.custody_hash.hex(),
                    "fullPuzzleHash": "0x" + identity.full_puzzle_hash.hex(),
                }
                for identity in authority.identity_vaults
            ],
        },
    }
    return artifact, authority


def _record(coin: Coin, *, confirmed: int, spent: int = 0) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
    }


class _GenesisProvider:
    def __init__(self, authority) -> None:
        launchers = [
            Coin(
                PARENT_ID,
                bytes32(SINGLETON_LAUNCHER_HASH),
                uint64(1),
            ),
            *[
                Coin(
                    PARENT_ID,
                    bytes32(SINGLETON_LAUNCHER_HASH),
                    uint64(identity.launcher_amount),
                )
                for identity in authority.identity_vaults
            ],
        ]
        children = [
            Coin(
                bytes32(launchers[0].name()),
                authority.full_puzzle_hash,
                uint64(1),
            ),
            *[
                Coin(
                    bytes32(launcher.name()),
                    identity.full_puzzle_hash,
                    uint64(identity.launcher_amount),
                )
                for launcher, identity in zip(
                    launchers[1:],
                    authority.identity_vaults,
                    strict=True,
                )
            ],
        ]
        self.records = {
            "0x" + coin.name().hex(): _record(coin, confirmed=100, spent=101)
            for coin in launchers
        }
        self.records.update(
            {
                "0x" + coin.name().hex(): _record(coin, confirmed=101)
                for coin in children
            }
        )

    async def get_coin_record_by_name(self, coin_id: str):
        return self.records.get(coin_id.lower())

    async def get_coin_records_by_parent_ids(
        self,
        parent_ids: list[str],
        *,
        include_spent: bool,
    ):
        del include_spent
        parents = {value.lower() for value in parent_ids}
        return [
            record
            for record in self.records.values()
            if str(record["coin"]["parent_coin_info"]).lower() in parents
        ]

    async def get_puzzle_and_solution(self, coin_id: str, height: int):
        raise AssertionError(
            f"genesis-only fixture should not request {coin_id} at {height}"
        )


@pytest.mark.asyncio
async def test_artifact_snapshot_is_honest_before_chain_launch() -> None:
    artifact, _authority = _artifact()
    snapshot = await build_admin_authority_v3_snapshot(artifact=artifact)
    assert snapshot.enabled is True
    assert snapshot.chain_verified is False
    assert snapshot.authority_rule == "slot0_and_one_of_slot1_slot2"
    assert snapshot.pending is False
    assert snapshot.authority_version == 1
    assert len(snapshot.identities) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_puzzle_version", (3, 4))
async def test_genesis_lineage_verifies_all_four_singletons(
    authority_puzzle_version: int,
) -> None:
    artifact, authority = _artifact(authority_puzzle_version=authority_puzzle_version)
    snapshot = await build_admin_authority_v3_snapshot(
        artifact=artifact,
        provider=_GenesisProvider(authority),  # type: ignore[arg-type]
    )
    assert snapshot.chain_verified is True
    assert snapshot.current_coin_id is not None
    assert snapshot.evidence["lineageDepth"] == 1
    assert all(identity.live_coin_id for identity in snapshot.identities)
    assert _authority_inner_from_snapshot(snapshot) == authority.inner_puzzle
    assert _genesis_authority_from_artifact(artifact) == authority

    for module_hash in (None, "0x" + "ff" * 32):
        unsupported = replace(snapshot, evidence={"authorityInnerModHash": module_hash})
        with pytest.raises(ValueError):
            _authority_inner_from_snapshot(unsupported)


@pytest.mark.asyncio
async def test_chain_puzzle_mismatch_fails_closed() -> None:
    artifact, authority = _artifact()
    provider = _GenesisProvider(authority)
    authority_child = next(
        record
        for record in provider.records.values()
        if record["coin"]["parent_coin_info"]
        == "0x" + authority.authority_launcher_id.hex()
    )
    authority_child["coin"]["puzzle_hash"] = "0x" + "ff" * 32
    with pytest.raises(ValueError, match="genesis puzzle hash mismatches"):
        await build_admin_authority_v3_snapshot(
            artifact=deepcopy(artifact),
            provider=provider,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_puzzle_version", (3, 4))
async def test_lineage_replay_preserves_authority_module(
    authority_puzzle_version: int,
) -> None:
    artifact, authority = _artifact(authority_puzzle_version=authority_puzzle_version)
    provider = _GenesisProvider(authority)
    coin = Coin(authority.authority_launcher_id, authority.full_puzzle_hash, uint64(1))
    # The reader interprets confirmed spend fields. Package tests separately
    # submit signed bundles to the simulator for consensus validation.
    solution = _outer_solution(Program.to([SPEND_OPERATIONAL, 1, 2, None]))
    parsed, state, _tag = _state_after_solution(authority.inner_puzzle, solution)
    next_inner = make_inner_puzzle(
        authority_puzzle_version=authority_puzzle_version,
        authority_launcher_id=parsed.authority_launcher_id,
        operational_root_hash=parsed.operational_root_hash,
        lost_recovery_root_hashes=parsed.lost_recovery_root_hashes,
        identity_launcher_ids=parsed.identity_launcher_ids,
        source_manifest_hash=parsed.source_manifest_hash,
        state=state,
    )
    next_full = puzzle_for_singleton(authority.authority_launcher_id, next_inner)
    child = Coin(bytes32(coin.name()), bytes32(next_full.get_tree_hash()), uint64(1))
    provider.records["0x" + coin.name().hex()]["spent_block_index"] = 102
    provider.records["0x" + child.name().hex()] = _record(child, confirmed=102)
    provider.get_puzzle_and_solution = AsyncMock(return_value={
        "puzzle_reveal": bytes(puzzle_for_singleton(
            authority.authority_launcher_id, authority.inner_puzzle
        )).hex(),
        "solution": bytes(solution).hex(),
    })

    snapshot = await build_admin_authority_v3_snapshot(
        artifact=artifact,
        provider=provider,  # type: ignore[arg-type]
    )
    assert snapshot.chain_verified and not snapshot.pending
    assert snapshot.authority_version == 2
    assert snapshot.evidence["lineageDepth"] == 2
    assert _authority_inner_from_snapshot(snapshot) == next_inner


def _outer_solution(inner_solution: Program) -> Program:
    return Program.to([None, AUTHORITY_LAUNCHER_AMOUNT, inner_solution])


def test_reader_tracks_recovery_kit_prepare_and_completed_custody() -> None:
    _artifact_payload, authority = _artifact()
    target = authority.identity_vaults[1]
    replacement_recovery = bytes(
        AugSchemeMPL.key_gen(b"replacement recovery key" * 2).get_g1()
    )
    transition = build_identity_vault_transition(
        identity=target,
        authority_current_inner_puzzle=authority.inner_puzzle,
        network="testnet11",
        kind=PENDING_RECOVERY_KIT,
        intent_hash=bytes32(b"\x81" * 32),
        current_identity_coin_id=bytes32(b"\x82" * 32),
        replacement_daily_compressed_pubkey=(
            target.daily_compressed_pubkey
        ),
        replacement_recovery_bls_pubkey=replacement_recovery,
    )
    identity_coin_ids = tuple(
        bytes32(bytes([0x90 + slot]) * 32) for slot in range(3)
    )
    prepare = build_prepare_solution(
        transition=transition,
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=2,
        mips_reveal=Program.to(1),
        mips_solution=Program.to(None),
        replacement_member_solution=Program.to(None),
        identity_records=((0, identity_coin_ids[0]), (1, identity_coin_ids[1])),
    )

    _parsed, pending, spend_tag = _state_after_solution(
        authority.inner_puzzle,
        _outer_solution(prepare),
    )
    assert spend_tag == SPEND_PREPARE_KIT
    assert pending.pending_kind == PENDING_RECOVERY_KIT
    assert pending.pending_slot == 1
    assert pending.pending_original_custody_hash == target.custody_hash
    assert (
        pending.pending_replacement_custody_hash
        == transition.final_custody_hash
    )
    assert pending.current_identity_custody_hashes == (
        authority.identity_vaults[0].custody_hash,
        transition.intermediate_custody_hash,
        authority.identity_vaults[2].custody_hash,
    )

    complete = build_complete_solution(
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=3,
    )
    _pending_parsed, completed, completion_tag = _state_after_solution(
        transition.authority_pending_inner_puzzle,
        _outer_solution(complete),
    )
    assert completion_tag == SPEND_COMPLETE
    assert completed.pending_kind == 0
    assert completed.authority_version == 3
    assert completed.current_identity_custody_hashes[1] == (
        transition.final_custody_hash
    )
    assert completed.current_identity_custody_hashes[0] == (
        authority.identity_vaults[0].custody_hash
    )
    assert completed.current_identity_custody_hashes[2] == (
        authority.identity_vaults[2].custody_hash
    )
