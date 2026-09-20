"""One-shot process worker for thread-affine Chia genesis operations.

The Chia Python bindings contain Rust-backed lazy nodes that must not move from
the thread where they were created. FastAPI request handlers therefore invoke
this module in a fresh interpreter and exchange canonical JSON over stdio.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping, Sequence


def _hex(value: bytes) -> str:
    return "0x" + bytes(value).hex()


def _hex_bytes(value: str, length: int, field: str, *, nonzero: bool = True) -> bytes:
    normalized = value.removeprefix("0x")
    if len(normalized) != length * 2:
        raise ValueError(f"{field} must be {length} bytes")
    try:
        raw = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be valid hex") from exc
    if nonzero and raw == b"\x00" * length:
        raise ValueError(f"{field} must be nonzero")
    return raw


def _admin_pubkeys(ceremony: Mapping[str, Any]) -> list[bytes]:
    invitations = ceremony.get("invitations")
    if not isinstance(invitations, list) or len(invitations) != 3:
        raise ValueError("three enrolled administrators are required")
    ordered = sorted(invitations, key=lambda item: int(item["slot"]))
    if [int(item["slot"]) for item in ordered] != [1, 2, 3]:
        raise ValueError("administrator roster slots are incomplete")
    return [
        _hex_bytes(str(item["compressed_pubkey"]), 33, "administrator pubkey")
        for item in ordered
    ]


def _build_plan(
    ceremony: Mapping[str, Any], body: Mapping[str, Any], expires_at: int
) -> Any:
    from chia_rs.sized_bytes import bytes32
    from solslot_puzzles.genesis_ceremony_rc23 import (
        RC23GenesisFundingCoinIds,
        build_rc23_genesis_ceremony_plan,
    )
    from solslot_puzzles.protocol_statutes_v1 import ProtocolParameters

    funding = body["fundingCoinIds"]
    parameters = body["protocolParameters"]
    recovery_kits = body.get("adminRecoveryKits")
    if not isinstance(recovery_kits, list) or len(recovery_kits) != 3:
        raise ValueError(
            "three server-verified administrator recovery kits are required"
        )
    ordered_kits = sorted(
        recovery_kits,
        key=lambda item: int(item["slot"]),
    )
    if [int(item["slot"]) for item in ordered_kits] != [0, 1, 2]:
        raise ValueError("administrator recovery-kit slots are incomplete")
    ids = RC23GenesisFundingCoinIds(
        sgt=bytes32(_hex_bytes(funding["sgt"], 32, "fundingCoinIds.sgt")),
        pool=bytes32(_hex_bytes(funding["pool"], 32, "fundingCoinIds.pool")),
        did=bytes32(_hex_bytes(funding["did"], 32, "fundingCoinIds.did")),
        governance=bytes32(
            _hex_bytes(funding["governance"], 32, "fundingCoinIds.governance")
        ),
        statutes=bytes32(
            _hex_bytes(funding["statutes"], 32, "fundingCoinIds.statutes")
        ),
        protocol_config=bytes32(
            _hex_bytes(
                funding["protocolConfig"], 32, "fundingCoinIds.protocolConfig"
            )
        ),
        admin_authority=bytes32(
            _hex_bytes(
                funding["adminAuthority"], 32, "fundingCoinIds.adminAuthority"
            )
        ),
        vault_version_registry=bytes32(
            _hex_bytes(
                funding["vaultVersionRegistry"],
                32,
                "fundingCoinIds.vaultVersionRegistry",
            )
        ),
        bridge_batch=bytes32(
            _hex_bytes(funding["bridgeBatch"], 32, "fundingCoinIds.bridgeBatch")
        ),
    )
    return build_rc23_genesis_ceremony_plan(
        enrollment_activation=body.get("enrollmentActivation"),
        evm_chain_id=ceremony['draft'].get('evmChainId',11155111),
        ceremony_id=bytes32(
            _hex_bytes(str(ceremony["ceremony_id"]), 32, "ceremonyId")
        ),
        expires_at=expires_at,
        source_shas=ceremony["draft"]["sourceShas"],
        evm_addresses=body["evmAddresses"],
        funding=ids,
        faucet_puzzle_hash=bytes32(
            _hex_bytes(body["faucetPuzzleHash"], 32, "faucetPuzzleHash")
        ),
        governance_bls_pubkey=_hex_bytes(
            body["governanceBlsPubkey"], 48, "governanceBlsPubkey"
        ),
        kos_mint_execute_pubkey=_hex_bytes(
            body["kosMintExecutePubkey"], 48, "kosMintExecutePubkey"
        ),
        admin_compressed_pubkeys=_admin_pubkeys(ceremony),
        admin_recovery_bls_pubkeys=[
            _hex_bytes(
                str(item["recoveryBlsPubkey"]),
                48,
                "adminRecoveryKits.recoveryBlsPubkey",
            )
            for item in ordered_kits
        ],
        admin_recovery_evm_guardians=[
            str(item["evmGuardian"]) for item in ordered_kits
        ],
        admin_recovery_revisions=[
            int(item["revision"]) for item in ordered_kits
        ],
        admin_recovery_drill_hashes=[
            bytes32(
                _hex_bytes(
                    str(item["drillChallengeHash"]),
                    32,
                    "adminRecoveryKits.drillChallengeHash",
                )
            )
            for item in ordered_kits
        ],
        validator_pubkeys=[
            _hex_bytes(value, 48, "validatorPubkey")
            for value in body["validatorPubkeys"]
        ],
        trusted_treasury_reserve_puzzle_hash=bytes32(
            _hex_bytes(
                body["trustedTreasuryReservePuzzleHash"],
                32,
                "trustedTreasuryReservePuzzleHash",
            )
        ),
        trusted_protocol_treasury_puzzle_hash=bytes32(
            _hex_bytes(
                body["trustedProtocolTreasuryPuzzleHash"],
                32,
                "trustedProtocolTreasuryPuzzleHash",
            )
        ),
        company_sgt_sale_treasury_puzzle_hash=bytes32(
            _hex_bytes(
                body["companySgtSaleTreasuryPuzzleHash"],
                32,
                "companySgtSaleTreasuryPuzzleHash",
            )
        ),
        wusdc_b_asset_id=bytes32(
            _hex_bytes(
                body["wusdcBAssetId"],
                32,
                "wusdcBAssetId",
            )
        ),
        trusted_governance_rewards_puzzle_hash=bytes32(
            _hex_bytes(
                body["trustedGovernanceRewardsPuzzleHash"],
                32,
                "trustedGovernanceRewardsPuzzleHash",
            )
        ),
        trusted_governance_rewards_root=bytes32(
            _hex_bytes(
                body["trustedGovernanceRewardsRoot"],
                32,
                "trustedGovernanceRewardsRoot",
            )
        ),
        retired_coordinates=[
            bytes32(_hex_bytes(value, 32, "retiredCoordinate"))
            for value in body["retiredCoordinates"]
        ],
        parameters=ProtocolParameters(
            voting_window_seconds=int(parameters["votingWindowSeconds"]),
            quorum_bps=int(parameters["quorumBps"]),
            min_proposal_stake=int(parameters["minProposalStake"]),
            nav_validity_seconds=int(parameters["navValiditySeconds"]),
            oracle_max_age_seconds=int(parameters["oracleMaxAgeSeconds"]),
            exchange_fee_bps=int(parameters["exchangeFeeBps"]),
            protocol_fee_bps=int(parameters["protocolFeeBps"]),
            sgt_rewards_fee_bps=int(parameters["sgtRewardsFeeBps"]),
            reward_epoch_seconds=int(parameters["rewardEpochSeconds"]),
        ),
    )


def _coin(value: Mapping[str, Any], field: str) -> Any:
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_bytes import bytes32
    from chia_rs.sized_ints import uint64

    coin = Coin(
        bytes32(
            _hex_bytes(
                str(value["parentCoinInfo"]), 32, f"{field}.parentCoinInfo", nonzero=False
            )
        ),
        bytes32(
            _hex_bytes(
                str(value["puzzleHash"]), 32, f"{field}.puzzleHash", nonzero=False
            )
        ),
        uint64(int(value["amount"])),
    )
    expected = str(value.get("expectedCoinId", "")).lower()
    if expected and _hex(coin.name()).lower() != expected:
        raise ValueError(f"{field} record does not match its expected coin id")
    return coin


def _funding_coins(values: Mapping[str, Mapping[str, Any]]) -> Any:
    from solslot_puzzles.genesis_ceremony_rc23 import (
        RC23GenesisFundingCoins,
    )

    return RC23GenesisFundingCoins(
        sgt=_coin(values["sgt"], "sgt"),
        pool=_coin(values["pool"], "pool"),
        did=_coin(values["did"], "did"),
        governance=_coin(values["governance"], "governance"),
        statutes=_coin(values["statutes"], "statutes"),
        protocol_config=_coin(values["protocolConfig"], "protocolConfig"),
        admin_authority=_coin(values["adminAuthority"], "adminAuthority"),
        vault_version_registry=_coin(
            values["vaultVersionRegistry"], "vaultVersionRegistry"
        ),
        bridge_batch=_coin(values["bridgeBatch"], "bridgeBatch"),
    )


def _expected_outputs(plan: Any) -> list[str]:
    from chia.types.blockchain_format.coin import Coin
    from chia_rs.sized_ints import uint64
    from solslot_puzzles.genesis_ceremony_rc23 import build_rc23_sgt_issuance

    outputs = [_hex(build_rc23_sgt_issuance(plan).reserve_coin.name())]
    surfaces = [
        (
            plan.protocol.pool_launcher_id,
            plan.protocol.pool_full_puzzle_hash,
            1,
        ),
        (
            plan.protocol.did_launcher_id,
            plan.protocol.did_full_puzzle_hash,
            1,
        ),
        (
            plan.protocol.governance_launcher_id,
            plan.protocol.governance_full_puzzle_hash,
            1,
        ),
        (plan.statutes.launcher_id, plan.statutes.full_puzzle_hash, 1),
        (
            plan.protocol_config.launcher_id,
            plan.protocol_config.full_puzzle_hash,
            1,
        ),
        (
            plan.admin_authority.launcher_id,
            plan.admin_authority.full_puzzle_hash,
            1,
        ),
        (
            plan.vault_version_registry.launcher_id,
            plan.vault_version_registry.full_puzzle_hash,
            1,
        ),
        (
            plan.property_registry.launcher_id,
            plan.property_registry.full_puzzle_hash,
            1,
        ),
    ]
    surfaces.extend(
        (
            identity.launcher_id,
            identity.full_puzzle_hash,
            identity.launcher_amount,
        )
        for identity in plan.admin_authority_v3.identity_vaults
    )
    outputs.extend(
        _hex(Coin(parent, puzzle_hash, uint64(amount)).name())
        for parent, puzzle_hash, amount in surfaces
    )
    outputs.append(_hex(plan.protocol.sols_reserve_seed_coin_id))
    outputs.extend(_hex(coin.name()) for coin in plan.bridge_batch.bridge_coins)
    return outputs


def _verify_artifact(artifact: Mapping[str, Any]) -> None:
    from solslot_puzzles.artifact_schema_v4 import (
        artifact_signing_typed_data,
        verify_public_artifact,
    )

    from .evm_auth import recover_evm_signer

    def verify_signature(
        payload: Mapping[str, Any], index: int, pubkey: bytes, signature: bytes
    ) -> bool:
        del index
        try:
            recovered = recover_evm_signer(
                artifact_signing_typed_data(payload), "0x" + signature.hex()
            )
        except (ValueError, TypeError):
            return False
        return recovered.compressed_pubkey == pubkey

    verify_public_artifact(artifact, signature_verifier=verify_signature)


def execute(payload: Mapping[str, Any]) -> dict[str, Any]:
    operation = payload.get("operation")
    if operation == "authorityV3Inventory":
        from solslot_puzzles.admin_authority_v3_driver import (
            admin_authority_v3_inner_mod_hash,
        )

        return {
            "protocolVersion": "solslot-v2-rc23",
            "adminAuthorityInnerModHash": _hex(
                admin_authority_v3_inner_mod_hash(4)
            ),
        }
    if operation == "roster":
        from solslot_puzzles.admin_authority_v2_driver import (
            build_genesis_eip712_admin_quorum,
        )

        quorum = build_genesis_eip712_admin_quorum(
            network="testnet11",
            compressed_pubkeys=[
                _hex_bytes(str(value), 33, "administrator pubkey")
                for value in payload["compressedPubkeys"]
            ],
        )
        return {
            "adminsHash": _hex(quorum.admins_hash),
            "mipsRootHash": _hex(quorum.mips_root_hash),
        }

    if operation not in {"plan", "bundle", "outputs", "artifact"}:
        if operation == "verifyArtifact":
            _verify_artifact(payload["artifact"])
            return {"verified": True}
        raise ValueError("unsupported genesis worker operation")

    plan = _build_plan(
        payload["ceremony"], payload["planInput"], int(payload["expiresAt"])
    )
    canonical_plan = plan.canonical_payload()
    if operation == "plan":
        return {"plan": canonical_plan, "planHash": _hex(plan.plan_hash)}
    if operation == "outputs":
        return {
            "plan": canonical_plan,
            "planHash": _hex(plan.plan_hash),
            "coinIds": _expected_outputs(plan),
        }
    if operation == "artifact":
        from solslot_puzzles.artifact_schema_v4 import build_public_artifact

        artifact = build_public_artifact(
            plan=plan,
            spend_bundle_id=str(payload["spendBundleId"]),
            confirmed_block_index=int(payload["confirmedBlockIndex"]),
            build_timestamp=payload.get("buildTimestamp"),
            review_class=str(
                payload["ceremony"]["draft"].get(
                    "reviewClass", "independent-release-review"
                )
            ),
        )
        return {"plan": canonical_plan, "artifact": artifact}

    from solslot_puzzles.genesis_ceremony_rc23 import (
        build_rc23_genesis_ceremony_bundle,
    )

    from .faucet import Faucet

    faucet = Faucet.from_master_private_key_hex(
        str(payload["faucetMasterPrivateKey"]), str(payload["network"])
    )
    funding = _funding_coins(payload["fundingCoins"])
    bundle = build_rc23_genesis_ceremony_bundle(
        plan=plan, faucet=faucet, funding_coins=funding
    )
    return {
        "plan": canonical_plan,
        "planHash": _hex(plan.plan_hash),
        "spendBundle": bundle.spend_bundle.to_json_dict(),
        "spendBundleId": bundle.spend_bundle_id,
        "spendCount": len(bundle.spend_bundle.coin_spends),
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        result = execute(payload)
    except Exception as exc:
        json.dump(
            {"error": str(exc), "errorType": type(exc).__name__},
            sys.stderr,
            sort_keys=True,
        )
        sys.stderr.write("\n")
        return 1
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["execute", "main"]
