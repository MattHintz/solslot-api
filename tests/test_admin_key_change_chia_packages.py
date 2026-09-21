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
    build_admin_authority_v3_snapshot,
    load_live_singleton_context,
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
    PENDING_RECOVERY_KIT,
    PENDING_ROUTINE,
    admin_authority_v3_inner_mod_hash,
    build_authority_operational_mips_spend,
    build_genesis_admin_authority_v3,
    build_identity_operational_action,
    build_identity_operational_solution,
    build_identity_vault_transition,
    build_operational_solution,
)
from solslot_puzzles.eip712_helpers import (
    TESTNET11_GENESIS_CHALLENGE,
    build_eip712_member_solution,
    eip712_hash_to_sign,
    eip712_prefix_and_domain_separator,
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
    identity = authority.identity_vaults[target_slot]
    old_evm_key = keys.PublicKey.from_compressed_bytes(
        identity.daily_compressed_pubkey
    ).to_checksum_address()
    recovery_kit = kind == "RECOVERY_KIT"
    return AdminKeyChangeIntentV1(
        slot=target_slot,
        kind=kind,
        oldDailyEvmKey=old_evm_key,
        newDailyEvmKey=(
            old_evm_key if recovery_kit
            else replacement.public_key.to_checksum_address()
        ),
        oldDailyChiaKey="0x" + identity.daily_compressed_pubkey.hex(),
        newDailyChiaKey="0x" + (
            identity.daily_compressed_pubkey if recovery_kit
            else _compressed(replacement)
        ).hex(),
        oldRecoveryGuardian="0x" + "31" * 20,
        newRecoveryGuardian="0x" + ("32" if recovery_kit else "31") * 20,
        oldRecoveryBlsKey="0x" + identity.recovery_bls_pubkey.hex(),
        newRecoveryBlsKey=(
            "0x"
            + (
                bytes(AugSchemeMPL.key_gen(b"\x78" * 32).get_g1())
                if recovery_kit else identity.recovery_bls_pubkey
            ).hex()
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
        expiresAt=4_000_000_000,
        recoveryKeyRevision=1,
    )


def _artifact(authority, parent_coin_id):
    return {
        "network": "testnet11",
        "genesisPlan": {
            "fundingCoinIds": {"admin_authority": "0x" + parent_coin_id.hex()},
            "authorityPuzzleVersion": authority.authority_puzzle_version,
        },
        "launcherIds": {
            "adminAuthority": "0x" + authority.authority_launcher_id.hex(),
        },
        "puzzleHashes": {
            "adminAuthorityInnerMod": "0x" + admin_authority_v3_inner_mod_hash(
                authority.authority_puzzle_version
            ).hex(),
            "adminAuthorityFull": "0x" + authority.full_puzzle_hash.hex(),
        },
        "adminAuthority": {
            "version": 3,
            "sourceManifestHash": "0x" + SOURCE_MANIFEST.hex(),
            "operationalMipsRootHash": "0x" + authority.operational_root_hash.hex(),
            "lostRecoveryMipsRootHashes": [
                "0x" + value.hex() for value in authority.lost_recovery_root_hashes
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
                    "recoveryBlsPubkey": "0x" + identity.recovery_bls_pubkey.hex(),
                    "recoveryMemberHash": "0x" + identity.recovery_member_hash.hex(),
                    "custodyHash": "0x" + identity.custody_hash.hex(),
                    "fullPuzzleHash": "0x" + identity.full_puzzle_hash.hex(),
                }
                for identity in authority.identity_vaults
            ],
        },
    }


class _SimProvider:
    """Adapt simulator results to the production provider's JSON interface."""

    def __init__(self, client):
        self.client = client

    async def get_coin_record_by_name(self, coin_id):
        record = await self.client.get_coin_record_by_name(
            bytes32.from_hexstr(coin_id)
        )
        return None if record is None else record.to_json_dict()

    async def get_coin_records_by_parent_ids(self, parent_ids, *, include_spent):
        records = await self.client.get_coin_records_by_parent_ids(
            [bytes32.from_hexstr(value) for value in parent_ids],
            include_spent_coins=include_spent,
        )
        return [record.to_json_dict() for record in records]

    async def get_puzzle_and_solution(self, coin_id, height):
        spend = await self.client.get_puzzle_and_solution(
            bytes32.from_hexstr(coin_id), height
        )
        return spend.to_json_dict()


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
        expires_at=intent.expires_at,
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "pending_kind"),
    (
        ("ROUTINE", PENDING_ROUTINE),
        ("LOST", PENDING_LOST),
        ("RECOVERY_KIT", PENDING_RECOVERY_KIT),
    ),
)
@pytest.mark.parametrize("authority_puzzle_version", (3, 4))
@pytest.mark.parametrize("terminal_phase", ("CANCEL", "COMPLETE"))
async def test_api_packages_execute_against_authority_v3_consensus(
    kind: str,
    pending_kind: int,
    authority_puzzle_version: int,
    monkeypatch: pytest.MonkeyPatch,
    terminal_phase: str,
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
        artifact = _artifact(authority, parent.name())
        provider = _SimProvider(client)
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(coinset=provider))
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
            replacement_daily_compressed_pubkey=bytes.fromhex(
                intent.new_daily_chia_key[2:]
            ),
            replacement_recovery_bls_pubkey=(
                bytes.fromhex(intent.new_recovery_bls_key[2:])
                if kind == "RECOVERY_KIT" else None
            ),
        )
        snapshot = await build_admin_authority_v3_snapshot(
            artifact=artifact, provider=provider,
        )
        case = {
            "caseId": "case-" + intent_hash.hex(),
            "intentHash": "0x" + intent_hash.hex(),
            "intent": intent.model_dump(by_alias=True),
        }
        build = _ChiaRecoveryBuild(
            artifact=artifact,
            evidence={},
            case=case,
            intent=intent,
            snapshot=snapshot,
            authority=authority,
            current_authority_inner=authority.inner_puzzle,
            current_identities=authority.identity_vaults,
            authority_context=await load_live_singleton_context(
                provider=provider, launcher_id=snapshot.launcher_id,
            ),
            identity_contexts=tuple(
                [
                    await load_live_singleton_context(
                        provider=provider, launcher_id=identity.launcher_id,
                    )
                    for identity in snapshot.identities
                ]
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
            # The store is append-only by design. Build the final bundle
            # directly here after proving a stored wrong signature fails.
            bundle = SpendBundle(unsigned.coin_spends, valid)
            assert actions[-1].signer_kind == "BLS_RECOVERY"

        assert bundle is not None
        status, error = await client.push_tx(bundle)
        assert error is None, error
        assert status == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()

        # Use fixture evidence and key history; exercise real Chia state,
        # lineage, and receipts from confirmed simulator spends.
        monkeypatch.setattr(
            admin_key_changes, "_verified_evidence_context",
            AsyncMock(return_value=(artifact, {}, None)),
        )
        monkeypatch.setattr(
            admin_key_changes, "_validate_intent_bindings", lambda **_: None,
        )
        monkeypatch.setattr(
            admin_key_changes, "_current_identity_vaults",
            lambda **_: authority.identity_vaults,
        )

        async def case_view(**kwargs):
            return kwargs["case"]

        monkeypatch.setattr(
            admin_key_changes, "_case_view", case_view,
        )
        pending_snapshot = await build_admin_authority_v3_snapshot(
            artifact=artifact, provider=provider,
        )
        for mismatch in (
            {"pending_intent_hash": "0x" + "ff" * 32},
            {"pending_slot": 0},
            {"pending_kind": "ROUTINE" if kind != "ROUTINE" else "LOST"},
        ):
            with monkeypatch.context() as context:
                context.setattr(
                    admin_key_changes, "build_admin_authority_v3_snapshot",
                    AsyncMock(return_value=replace(pending_snapshot, **mismatch)),
                )
                with pytest.raises(
                    ValueError, match="different administrator key change"
                ):
                    await admin_key_changes._observe_chia_case(
                        case_id=case["caseId"], request=request,
                        settings=None, store=store,
                    )
            assert store.recovery_case(case["caseId"])["receipts"] == []

        observed = await admin_key_changes._observe_chia_case(
            case_id=case["caseId"], request=request, settings=None, store=store,
        )
        [receipt] = observed["receipts"]
        assert receipt["phase"] == "PREPARE" and receipt["chain"] == "CHIA"
        assert receipt["receipt"]["event"] == "PREPARE_" + kind
        repeated = await admin_key_changes._observe_chia_case(
            case_id=case["caseId"], request=request, settings=None, store=store,
        )
        assert repeated["receipts"] == observed["receipts"]

        pending = await admin_key_changes._chia_recovery_build(
            case=observed,
            phase=terminal_phase,
            coadmin_slot=build.coadmin_slot,
            request=request,
            settings=None,
            store=store,
        )
        assert pending.transition == transition
        if terminal_phase == "CANCEL":
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

        await sim.farm_block()
        final_snapshot = await build_admin_authority_v3_snapshot(
            artifact=artifact, provider=provider,
        )
        assert final_snapshot.chain_verified and not final_snapshot.pending
        assert final_snapshot.authority_version == 3
        assert final_snapshot.evidence["latestSpend"] == terminal_phase
        assert final_snapshot.identities[1].custody_hash == "0x" + (
            transition.original_custody_hash if terminal_phase == "CANCEL"
            else transition.final_custody_hash
        ).hex()
        observed = await admin_key_changes._observe_chia_case(
            case_id=case["caseId"], request=request, settings=None, store=store,
        )
        assert [item["phase"] for item in observed["receipts"]] == [
            "PREPARE", terminal_phase,
        ]
        assert observed["state"] == "PARTIAL"  # EVM confirmation is still required.

        if terminal_phase == "CANCEL":
            contexts = [
                await load_live_singleton_context(
                    provider=provider, launcher_id=launcher,
                )
                for launcher in (
                    final_snapshot.launcher_id,
                    *(identity.launcher_id for identity in final_snapshot.identities),
                )
            ]
            current_inner = admin_key_changes._authority_inner_from_snapshot(
                final_snapshot
            )
            delegated = Program.to((1, [[60, b"operation after cancellation"]]))
            mips = build_authority_operational_mips_spend(
                authority=authority,
                current_authority_inner_puzzle=current_inner,
                current_identities=authority.identity_vaults,
                current_identity_coin_ids=tuple(
                    context.coin.name() for context in contexts[1:]
                ),
                authority_delegated_puzzle=delegated,
                coadmin_slot=1,
            )
            solution = build_operational_solution(
                my_amount=AUTHORITY_LAUNCHER_AMOUNT,
                new_authority_version=4,
                mips_reveal=mips.reveal,
                mips_solution=mips.solution,
                authority_delegated_puzzle=delegated,
                identity_records=mips.identity_records,
            )
            spends = [admin_key_changes._singleton_spend(
                context=contexts[0],
                inner_puzzle=current_inner,
                inner_solution=solution,
                amount=AUTHORITY_LAUNCHER_AMOUNT,
            )]
            prefix = eip712_prefix_and_domain_separator(
                TESTNET11_GENESIS_CHALLENGE
            )
            for slot in mips.selected_slots:
                identity = authority.identity_vaults[slot]
                coin_id = contexts[slot + 1].coin.name()
                action_hash = build_identity_operational_action(
                    identity=identity,
                    current_authority_inner_puzzle=current_inner,
                    authority_delegated_puzzle=delegated,
                ).get_tree_hash()
                member_solution = build_eip712_member_solution(
                    network="testnet11",
                    coin_id=coin_id,
                    delegated_puzzle_hash=action_hash,
                    compressed_pubkey=identity.daily_compressed_pubkey,
                    signature=daily_private_keys[slot].sign_msg_hash(
                        eip712_hash_to_sign(prefix, coin_id, action_hash)
                    ).to_bytes(),
                )
                spends.append(admin_key_changes._singleton_spend(
                    context=contexts[slot + 1],
                    inner_puzzle=identity.custody_reveal,
                    amount=identity.launcher_amount,
                    inner_solution=build_identity_operational_solution(
                        identity=identity,
                        current_authority_inner_puzzle=current_inner,
                        authority_delegated_puzzle=delegated,
                        current_identity_coin_id=coin_id,
                        daily_member_solution=member_solution,
                    ),
                ))
            status, error = await client.push_tx(SpendBundle(spends, G2Element()))
            assert error is None and status == MempoolInclusionStatus.SUCCESS
            await sim.farm_block()
            resumed = await build_admin_authority_v3_snapshot(
                artifact=artifact, provider=provider,
            )
            assert resumed.chain_verified and not resumed.pending
            assert resumed.authority_version == 4
            assert resumed.evidence["latestSpend"] == "OPERATIONAL"
