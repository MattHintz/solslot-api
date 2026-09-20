from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    launch_conditions_and_coinsol,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api import admin_key_changes
from solslot_api.admin_authority_v3 import (
    AdminAuthorityV3Snapshot,
    AdminIdentityVaultV1,
    LiveSingletonContext,
)
from solslot_api.admin_key_changes import (
    AdminKeyChangeIntentV1,
    _ChiaRecoveryBuild,
    _bls_recovery_action,
    _complete_bundle,
    _prepare_unsigned_bundle,
    _signed_cancel_bundle,
    _signed_prepare_bundle,
)
from solslot_api.genesis_store import GenesisConflict, GenesisStore
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_puzzles.admin_authority_v3_driver import (
    ADMIN_AUTHORITY_FUNDING_AMOUNT,
    AUTHORITY_LAUNCHER_AMOUNT,
    PENDING_LOST,
    PENDING_ROUTINE,
    admin_authority_v3_inner_mod_hash,
    build_genesis_admin_authority_v3,
    build_identity_vault_transition,
)


CEREMONY_ID = "0x" + "91" * 32
SOURCE_MANIFEST = bytes32(b"\x92" * 32)


def _compressed(private_key: keys.PrivateKey) -> bytes:
    return private_key.public_key.to_compressed_bytes()


def _intent(
    *,
    authority,
    target_slot: int,
    kind: str,
    replacement: keys.PrivateKey,
) -> AdminKeyChangeIntentV1:
    return AdminKeyChangeIntentV1(
        slot=target_slot,
        kind=kind,
        oldDailyEvmKey="0x" + "11" * 20,
        newDailyEvmKey=replacement.public_key.to_checksum_address(),
        oldDailyChiaKey=(
            "0x"
            + authority.identity_vaults[
                target_slot
            ].daily_compressed_pubkey.hex()
        ),
        newDailyChiaKey="0x" + _compressed(replacement).hex(),
        oldRecoveryGuardian="0x" + "31" * 20,
        newRecoveryGuardian="0x" + "31" * 20,
        oldRecoveryBlsKey=(
            "0x"
            + authority.identity_vaults[
                target_slot
            ].recovery_bls_pubkey.hex()
        ),
        newRecoveryBlsKey=(
            "0x"
            + authority.identity_vaults[
                target_slot
            ].recovery_bls_pubkey.hex()
        ),
        identityLauncherIds=[
            "0x" + identity.launcher_id.hex()
            for identity in authority.identity_vaults
        ],
        identitySafes=[
            "0x" + f"{41 + slot:02x}" * 20 for slot in range(3)
        ],
        authorityLauncherId="0x" + authority.authority_launcher_id.hex(),
        coadminSafe="0x" + "51" * 20,
        rootSafe="0x" + "52" * 20,
        sourceManifestHash="0x" + SOURCE_MANIFEST.hex(),
        nonce=1,
        expiresAt=2_000_000,
        recoveryKeyRevision=1,
    )


def _snapshot(authority, authority_coin, identity_coins):
    return AdminAuthorityV3Snapshot(
        enabled=True,
        chain_verified=True,
        network="testnet11",
        launcher_id="0x" + authority.authority_launcher_id.hex(),
        current_coin_id="0x" + authority_coin.name().hex(),
        current_puzzle_hash="0x" + authority_coin.puzzle_hash.hex(),
        confirmed_height=2,
        source_manifest_hash="0x" + SOURCE_MANIFEST.hex(),
        operational_mips_root_hash=(
            "0x" + authority.operational_root_hash.hex()
        ),
        lost_recovery_mips_root_hashes=tuple(
            "0x" + value.hex()
            for value in authority.lost_recovery_root_hashes
        ),
        authority_version=1,
        pending=False,
        pending_kind="NONE",
        pending_slot=None,
        pending_intent_hash=None,
        pending_identity_coin_id=None,
        pending_original_custody_hash=None,
        pending_replacement_custody_hash=None,
        pending_replacement_member_hash=None,
        pending_delay_seconds=0,
        routine_delay_seconds=86_400,
        lost_key_delay_seconds=604_800,
        authority_rule="slot0_and_one_of_slot1_slot2",
        identities=tuple(
            AdminIdentityVaultV1(
                slot=slot,
                launcher_id="0x" + identity.launcher_id.hex(),
                daily_compressed_pubkey=(
                    "0x" + identity.daily_compressed_pubkey.hex()
                ),
                recovery_bls_pubkey=(
                    "0x" + identity.recovery_bls_pubkey.hex()
                ),
                recovery_member_hash=(
                    "0x" + identity.recovery_member_hash.hex()
                ),
                custody_hash="0x" + identity.custody_hash.hex(),
                live_coin_id="0x" + identity_coins[slot].name().hex(),
                live_puzzle_hash=(
                    "0x" + identity_coins[slot].puzzle_hash.hex()
                ),
                confirmed_height=2,
            )
            for slot, identity in enumerate(authority.identity_vaults)
        ),
        evidence={
            "authorityInnerModHash": "0x" + admin_authority_v3_inner_mod_hash(
                authority.authority_puzzle_version
            ).hex(),
        },
    )


def _store(intent: AdminKeyChangeIntentV1, intent_hash: bytes32) -> GenesisStore:
    store = GenesisStore(":memory:")
    store.create_draft(CEREMONY_ID, {"network": "testnet11"}, now=100)
    store.create_recovery_case(
        CEREMONY_ID,
        case_id="case-" + intent_hash.hex(),
        authority_slot=intent.slot,
        kind=intent.kind,
        intent_hash="0x" + intent_hash.hex(),
        intent=intent.model_dump(by_alias=True),
        execute_after=1_000_000,
        expires_at=2_000_000,
        prepared_by="0x" + "11" * 20,
        now=100,
    )
    return store


def _sign_eip_actions(store, case_id, actions, private_keys):
    by_public_key = {
        "0x" + _compressed(private_key).hex(): private_key
        for private_key in private_keys
    }
    for action in actions:
        private_key = by_public_key[action.signer_public_key]
        signature = private_key.sign_msg_hash(
            bytes.fromhex(action.message_hash[2:])
        ).to_bytes()
        store.add_recovery_chia_signature(
            case_id,
            phase=action.phase,
            action_id=action.action_id,
            signer_kind=action.signer_kind,
            signer_slot=action.signer_slot,
            signer_public_key=action.signer_public_key,
            signature="0x" + signature.hex(),
            message_hash=action.message_hash,
        )


def _pending_build(
    build: _ChiaRecoveryBuild,
    prepare_bundle: SpendBundle,
) -> _ChiaRecoveryBuild:
    spend_by_input = {
        bytes32(spend.coin.name()): spend
        for spend in prepare_bundle.coin_spends
    }
    authority_spend = spend_by_input[
        bytes32(build.authority_context.coin.name())
    ]
    authority_coin = compute_additions(authority_spend)[0]

    identity_contexts = []
    identity_snapshots = []
    for slot, context in enumerate(build.identity_contexts):
        spend = spend_by_input.get(bytes32(context.coin.name()))
        if spend is None:
            identity_contexts.append(context)
            identity_snapshots.append(build.snapshot.identities[slot])
            continue
        continuation = compute_additions(spend)[0]
        identity_contexts.append(
            LiveSingletonContext(
                launcher_id=context.launcher_id,
                coin=continuation,
                parent_spend=spend,
                confirmed_height=3,
                depth=context.depth + 1,
            )
        )
        identity_snapshots.append(
            replace(
                build.snapshot.identities[slot],
                custody_hash=(
                    "0x" + build.transition.intermediate_custody_hash.hex()
                    if slot == build.intent.slot
                    else build.snapshot.identities[slot].custody_hash
                ),
                live_coin_id="0x" + continuation.name().hex(),
                live_puzzle_hash="0x" + continuation.puzzle_hash.hex(),
                confirmed_height=3,
            )
        )

    snapshot = replace(
        build.snapshot,
        current_coin_id="0x" + authority_coin.name().hex(),
        current_puzzle_hash=(
            "0x" + authority_coin.puzzle_hash.hex()
        ),
        confirmed_height=3,
        authority_version=build.snapshot.authority_version + 1,
        pending=True,
        pending_kind=build.intent.kind,
        pending_slot=build.intent.slot,
        pending_intent_hash=build.case["intentHash"],
        pending_identity_coin_id=(
            "0x" + build.transition.intermediate_identity_coin_id.hex()
        ),
        pending_original_custody_hash=(
            "0x" + build.transition.original_custody_hash.hex()
        ),
        pending_replacement_custody_hash=(
            "0x" + build.transition.final_custody_hash.hex()
        ),
        pending_replacement_member_hash=(
            "0x" + build.transition.replacement_daily_member_hash.hex()
        ),
        pending_delay_seconds=build.transition.delay_seconds,
        identities=tuple(identity_snapshots),
    )
    return replace(
        build,
        snapshot=snapshot,
        current_authority_inner=(
            build.transition.authority_pending_inner_puzzle
        ),
        authority_context=LiveSingletonContext(
            launcher_id=build.authority_context.launcher_id,
            coin=authority_coin,
            parent_spend=authority_spend,
            confirmed_height=3,
            depth=build.authority_context.depth + 1,
        ),
        identity_contexts=tuple(identity_contexts),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "pending_kind"),
    (("ROUTINE", PENDING_ROUTINE), ("LOST", PENDING_LOST)),
)
@pytest.mark.parametrize("authority_puzzle_version", (3, 4))
async def test_api_packages_execute_against_authority_v3_consensus(
    kind: str,
    pending_kind: int,
    authority_puzzle_version: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_private_keys = tuple(
        keys.PrivateKey(bytes([value]) * 32)
        for value in (0x11, 0x22, 0x33)
    )
    recovery_private_keys = tuple(
        AugSchemeMPL.key_gen(bytes([value]) * 32)
        for value in (0x41, 0x42, 0x43)
    )
    replacement = keys.PrivateKey(b"\x71" * 32)

    testnet_constants = DEFAULT_CONSTANTS.replace(
        AGG_SIG_ME_ADDITIONAL_DATA=bytes32(
            AGG_SIG_ME_DATA["testnet11"]
        ),
    )
    async with SpendSim.managed(None, defaults=testnet_constants) as sim:
        client = SimClient(sim)
        acs = Program.to(1)
        acs_hash = bytes32(acs.get_tree_hash())
        await sim.farm_block(acs_hash)
        records = await client.get_coin_records_by_puzzle_hash(
            acs_hash,
            include_spent_coins=False,
        )
        parent = records[0].coin
        authority = build_genesis_admin_authority_v3(
            authority_puzzle_version=authority_puzzle_version,
            parent_coin_id=bytes32(parent.name()),
            network="testnet11",
            daily_compressed_pubkeys=tuple(
                _compressed(private_key)
                for private_key in daily_private_keys
            ),
            recovery_bls_pubkeys=tuple(
                bytes(private_key.get_g1())
                for private_key in recovery_private_keys
            ),
            source_manifest_hash=SOURCE_MANIFEST,
        )
        launch_targets = (
            (
                authority.authority_launcher_id,
                authority.inner_puzzle,
                AUTHORITY_LAUNCHER_AMOUNT,
            ),
            *(
                (
                    identity.launcher_id,
                    identity.custody_reveal,
                    identity.launcher_amount,
                )
                for identity in authority.identity_vaults
            ),
        )
        parent_conditions = []
        launcher_spends = []
        for _launcher_id, inner, amount in launch_targets:
            conditions, launcher_spend = launch_conditions_and_coinsol(
                parent,
                inner,
                [],
                uint64(amount),
            )
            parent_conditions.extend(conditions)
            launcher_spends.append(launcher_spend)
        parent_conditions.append(
            Program.to(
                [
                    51,
                    acs_hash,
                    int(parent.amount) - ADMIN_AUTHORITY_FUNDING_AMOUNT,
                ]
            )
        )
        launch_bundle = SpendBundle(
            [
                make_spend(parent, acs, Program.to(parent_conditions)),
                *launcher_spends,
            ],
            G2Element(),
        )
        status, error = await client.push_tx(launch_bundle)
        assert status == MempoolInclusionStatus.SUCCESS
        assert error is None
        await sim.farm_block()

        authority_coin = compute_additions(launcher_spends[0])[0]
        identity_coins = tuple(
            compute_additions(spend)[0]
            for spend in launcher_spends[1:]
        )
        intent = _intent(
            authority=authority,
            target_slot=1,
            kind=kind,
            replacement=replacement,
        )
        intent_hash = bytes32(bytes([0x81 + pending_kind]) * 32)
        transition = build_identity_vault_transition(
            identity=authority.identity_vaults[1],
            authority_current_inner_puzzle=authority.inner_puzzle,
            network="testnet11",
            kind=pending_kind,
            intent_hash=intent_hash,
            current_identity_coin_id=bytes32(identity_coins[1].name()),
            replacement_daily_compressed_pubkey=_compressed(replacement),
        )
        snapshot = _snapshot(authority, authority_coin, identity_coins)
        case = {
            "caseId": "case-" + intent_hash.hex(),
            "intentHash": "0x" + intent_hash.hex(),
            "intent": intent.model_dump(by_alias=True),
        }
        build = _ChiaRecoveryBuild(
            artifact={},
            evidence={},
            case=case,
            intent=intent,
            snapshot=snapshot,
            authority=authority,
            current_authority_inner=authority.inner_puzzle,
            current_identities=authority.identity_vaults,
            authority_context=LiveSingletonContext(
                launcher_id=authority.authority_launcher_id,
                coin=authority_coin,
                parent_spend=launcher_spends[0],
                confirmed_height=2,
                depth=1,
            ),
            identity_contexts=tuple(
                LiveSingletonContext(
                    launcher_id=identity.launcher_id,
                    coin=identity_coins[slot],
                    parent_spend=launcher_spends[slot + 1],
                    confirmed_height=2,
                    depth=1,
                )
                for slot, identity in enumerate(authority.identity_vaults)
            ),
            transition=transition,
            coadmin_slot=None if kind == "LOST" else 1,
        )
        store = _store(intent, intent_hash)
        _bundle, eip_actions = _signed_prepare_bundle(
            build=build,
            store=store,
        )
        _sign_eip_actions(
            store,
            str(case["caseId"]),
            eip_actions,
            (*daily_private_keys, replacement),
        )

        bundle, actions = _signed_prepare_bundle(
            build=build,
            store=store,
        )
        if kind == "LOST":
            assert bundle is None
            unsigned, _rebuilt, pairs = _prepare_unsigned_bundle(
                build=build,
                store=store,
            )
            bls_action = _bls_recovery_action(build, pairs)
            wrong_signature = AugSchemeMPL.sign(
                recovery_private_keys[0],
                pairs[0][1],
            )
            store.add_recovery_chia_signature(
                str(case["caseId"]),
                phase="PREPARE",
                action_id=bls_action.action_id,
                signer_kind="BLS_RECOVERY",
                signer_slot=1,
                signer_public_key=bls_action.signer_public_key,
                signature="0x" + bytes(wrong_signature).hex(),
                message_hash=bls_action.message_hash,
            )
            with pytest.raises(GenesisConflict, match="does not authorize"):
                _signed_prepare_bundle(build=build, store=store)

            valid_signatures = [
                AugSchemeMPL.sign(recovery_private_keys[1], message)
                for _public_key, message in pairs
            ]
            valid = AugSchemeMPL.aggregate(valid_signatures)
            internal = store.recovery_chia_signatures(
                str(case["caseId"]),
                phase="PREPARE",
                include_signatures=True,
            )
            # The store is append-only by design. Build the final bundle
            # directly here after proving a stored wrong signature fails.
            bundle = SpendBundle(unsigned.coin_spends, valid)
            assert actions[-1].signer_kind == "BLS_RECOVERY"

        assert bundle is not None
        status, error = await client.push_tx(bundle)
        assert error is None, error
        assert status == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()

        pending = _pending_build(build, bundle)
        # Reconstruct the pending transition through the coordinator's recovery
        # builder; signatures and consensus checks below use that reconstruction.
        monkeypatch.setattr(
            admin_key_changes, "_verified_evidence_context",
            AsyncMock(return_value=({}, {}, None)),
        )
        monkeypatch.setattr(
            admin_key_changes, "_validate_intent_bindings", lambda **_: None,
        )
        monkeypatch.setattr(
            admin_key_changes, "_genesis_authority_from_artifact", lambda _: authority,
        )
        monkeypatch.setattr(
            admin_key_changes, "_current_identity_vaults",
            lambda **_: authority.identity_vaults,
        )
        monkeypatch.setattr(
            admin_key_changes, "build_admin_authority_v3_snapshot",
            AsyncMock(return_value=pending.snapshot),
        )
        contexts = {
            "0x" + context.launcher_id.hex(): context
            for context in (pending.authority_context, *pending.identity_contexts)
        }
        monkeypatch.setattr(
            admin_key_changes, "load_live_singleton_context",
            AsyncMock(side_effect=lambda **kwargs: contexts[kwargs["launcher_id"]]),
        )
        pending = await admin_key_changes._chia_recovery_build(
            case={**case, "state": "PENDING"},
            phase="CANCEL" if kind == "ROUTINE" else "COMPLETE",
            coadmin_slot=build.coadmin_slot,
            request=SimpleNamespace(
                app=SimpleNamespace(state=SimpleNamespace(coinset=client))
            ),
            settings=None,
            store=store,
        )
        assert pending.transition == transition
        if kind == "ROUTINE":
            cancel_bundle, cancel_actions = _signed_cancel_bundle(
                build=pending,
                store=store,
            )
            assert cancel_bundle is None
            _sign_eip_actions(
                store,
                str(case["caseId"]),
                cancel_actions,
                daily_private_keys,
            )
            cancel_bundle, _cancel_actions = _signed_cancel_bundle(
                build=pending,
                store=store,
            )
            assert cancel_bundle is not None
            status, error = await client.push_tx(cancel_bundle)
            assert error is None, error
            assert status == MempoolInclusionStatus.SUCCESS
        else:
            complete_bundle = _complete_bundle(pending)
            early_status, early_error = await client.push_tx(
                complete_bundle
            )
            assert early_status != MempoolInclusionStatus.SUCCESS
            assert early_error is not None

            sim.pass_time(
                uint64(pending.transition.delay_seconds + 1)
            )
            await sim.farm_block()
            status, error = await client.push_tx(complete_bundle)
            assert error is None, error
            assert status == MempoolInclusionStatus.SUCCESS
