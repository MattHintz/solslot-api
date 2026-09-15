"""Independent evidence verification for a private validator signer."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import httpx
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD,
    lineage_proof_for_coinsol,
)
from chia.wallet.util.compute_additions import compute_additions
from chia.wallet.trading.offer import Offer
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element, PrivateKey
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from web3 import Web3

from solslot_puzzles.voucher_purchase import voucher_purchase_from_json, validate_base_voucher_purchase
from solslot_puzzles.base_voucher_v5 import (
    prepare_base_voucher_redemption_offer_v5, build_base_voucher_primary_offer_v5,
)
from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    build_vault_receive_spend,
    compact_signature_from_evm,
    eip712_typed_data_for_vault_spend,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
    puzzle_hash_for_p2_vault,
)
from solslot_puzzles.mint_publish_driver import (
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
)
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
    purchase_artifact_from_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3,
    PurchaseDeliveryKind,
    PurchaseKind,
    STRIPE_PAYMENT_PROVIDER_ID,
    StripeFundingType,
    StripeMethodFamily,
    build_purchase_batch_settlement_receipt_v1,
    build_stripe_settlement_receipt_v1,
    purchase_artifact_v3_from_json,
    purchase_batch_from_json,
    stripe_settlement_evidence_from_json,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.primary_purchase_v2_driver import (
    PrimaryMintTermsV2,
    PrimaryPurchaseMode,
    build_universal_primary_offer_v4,
    make_mint_offer_v4_inner,
    prepare_base_voucher_redemption_offer,
    prepare_xch_voucher_redemption_offer,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    PRIMARY_PURCHASE_PROVIDER_ID,
    InventoryReservationV1,
    PrimaryMintTermsV3,
    PurchaseBatchSettlementTermsV1,
    StripeSettlementTermsV1,
    curry_purchase_batch_settlement_receipt,
    curry_stripe_settlement_receipt,
    inventory_reservation_message,
    inventory_terms_for_puzzle_hash,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
    validate_chia_buyer_batch_offer_v3,
    validate_chia_buyer_offer_v3,
)
from solslot_puzzles.sgt_driver import (
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
)
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    sgt_cat_puzzle,
    sgt_reserve_inner_puzzle,
    sgt_sale_inner_puzzle,
    sgt_sale_terms_from_bill,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    DeedAllocationCommitmentV2,
    VoucherPaymentRail,
    VoucherSeriesState,
    VoucherV2Error,
    allocation_root,
    series_terms_from_json,
    validate_purchase,
    voucher_commitment_from_json,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    SeriesTransition,
    VoucherAction,
    VoucherSeriesStateV2,
    build_base_voucher_terminal_spends,
    build_xch_voucher_terminal_spends,
    build_voucher_issuance_spends,
    build_voucher_series_phase_spend,
    curry_external_receipt,
    curry_xch_escrow,
    external_receipt_evidence_message,
    validate_xch_voucher_offer,
)
from solslot_puzzles.voucher_presale_v3 import (
    VoucherPaymentRailV3,
    VoucherV3Error,
    stripe_original_payer,
    validate_stripe_voucher_purchase,
    voucher_commitment_v3_from_json,
)
from solslot_puzzles.voucher_presale_v3_driver import (
    build_stripe_voucher_issuance_spends,
    build_stripe_voucher_primary_offer_v5,
    build_stripe_voucher_terminal_spends,
    prepare_stripe_voucher_redemption_offer,
    stripe_voucher_evidence_message,
)

from .config import Settings
from .evm_auth import recover_evm_signer
from .external_settlement import (
    base_result_authorization_puzzle_hash,
    build_base_batch_settlement_receipt,
    build_base_settlement_receipt,
)
from .faucet import AGG_SIG_ME_DATA
from .public_artifact import (
    PublicArtifactError,
    verify_signed_public_artifact_file,
)
from .release_metadata import ReleaseMetadata, load_release_metadata
from .validator_ledger import ValidatorLedger, ValidatorLedgerConflict
from .validator_quorum import (
    InventoryReservationClaim,
    PrimaryPurchaseClaim,
    StripeSettlementClaim,
    ValidatorClaim,
    PermitValidatorClaim,
    VoucherIssuanceClaim,
    VoucherSeriesPhaseClaim,
    VoucherTransitionClaim,
    base_settlement_evidence_hash,
)
from .validator_settings import ValidatorSettings
from .zkpassport_enrollments import _fetch_verified_evm_attestation
from .bridge_coin_policy import BridgeCoinPolicy


class ValidatorEvidenceError(RuntimeError):
    """The coordinator claim is not independently provable."""


_PROTECTED_SYSTEMD_CREDENTIAL_NAMES = frozenset(
    {"stripe-read-key", "validator-seed"}
)


def _is_protected_systemd_credential(
    path: Path,
    mode: int,
    *,
    expected_name: str,
) -> bool:
    """Recognize systemd's read-only credential mount across supported hosts."""
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if (
        not credentials_directory
        or expected_name not in _PROTECTED_SYSTEMD_CREDENTIAL_NAMES
        or path.name != expected_name
    ):
        return False
    try:
        directory = Path(credentials_directory)
        directory_stat = directory.stat()
        path_stat = path.stat()
        if path.parent.resolve(strict=True) != directory.resolve(strict=True):
            return False
    except OSError:
        return False

    # Ubuntu's id-mapped credential mount reports 0440/root:root to the
    # service while Amazon Linux reports 0400 owned by the service account.
    # In both cases the mount and credential are immutable to the signer.
    forbidden_file_bits = (
        stat.S_IWUSR | stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO
    )
    forbidden_directory_bits = stat.S_IWGRP | stat.S_IRWXO
    return (
        bool(mode & stat.S_IRUSR)
        and not mode & forbidden_file_bits
        and not stat.S_IMODE(directory_stat.st_mode) & forbidden_directory_bits
        and path_stat.st_uid == directory_stat.st_uid
        and path_stat.st_gid == directory_stat.st_gid
    )


def canonical_claim_json(claim: ValidatorClaim) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def load_validator_private_key(settings: ValidatorSettings) -> PrivateKey:
    """Load a BLS seed from a protected file and bind it to the roster."""
    path = Path(settings.seed_file)
    if path.is_symlink() or not path.is_file():
        raise ValidatorEvidenceError("validator seed file is missing or is a symlink")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO) and not _is_protected_systemd_credential(
        path,
        mode,
        expected_name="validator-seed",
    ):
        raise ValidatorEvidenceError("validator seed file must not be accessible by group/other")
    try:
        seed = bytes.fromhex(path.read_text(encoding="ascii").strip().removeprefix("0x"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValidatorEvidenceError("validator seed file is unreadable or invalid") from exc
    if len(seed) != 32:
        raise ValidatorEvidenceError("validator seed file must contain exactly 32 bytes of hex")
    private_key = AugSchemeMPL.key_gen(seed)
    expected = bytes.fromhex(
        settings.roster_pubkeys[settings.signer_index].removeprefix("0x")
    )
    if bytes(private_key.get_g1()) != expected:
        raise ValidatorEvidenceError("validator seed does not match its configured roster slot")
    return private_key


def load_validator_artifact(
    settings: ValidatorSettings,
) -> tuple[dict[str, Any], ReleaseMetadata]:
    try:
        artifact = verify_signed_public_artifact_file(settings.public_artifact_path)
    except PublicArtifactError as exc:
        raise ValidatorEvidenceError(str(exc)) from exc
    try:
        release = load_release_metadata(settings.release_metadata_path)
    except (OSError, ValueError) as exc:
        raise ValidatorEvidenceError("validator release metadata is invalid") from exc
    if release is None:
        raise ValidatorEvidenceError("validator release metadata is missing")

    source_shas = artifact.get("sourceShas")
    bridge = artifact.get("bridgePolicy")
    validators = artifact.get("validatorSet")
    addresses = artifact.get("evmAddresses")
    if not all(
        isinstance(value, Mapping)
        for value in (source_shas, bridge, validators, addresses)
    ):
        raise ValidatorEvidenceError("signed artifact runtime bindings are incomplete")
    checks = (
        (artifact.get("network"), settings.network, "network"),
        (artifact.get("evmChainId"), settings.evm_chain_id, "EVM chain"),
        (source_shas.get("api"), release.apiCommit, "API commit"),
        (source_shas.get("protocol"), release.protocolCommit, "protocol commit"),
        (bridge.get("policyHash"), settings.bridge_policy_hash, "bridge policy"),
        (validators.get("threshold"), 2, "validator threshold"),
        (validators.get("pubkeys"), settings.roster_pubkeys, "validator roster"),
        (
            str(addresses.get("forwarder", "")).lower(),
            settings.evm_forwarder_address,
            "forwarder",
        ),
        (
            str(addresses.get("verifierAdapter", "")).lower(),
            settings.evm_verifier_adapter_address,
            "verifier adapter",
        ),
        (
            str(addresses.get("attestationEmitter", "")).lower(),
            settings.evm_attestation_emitter_address,
            "attestation emitter",
        ),
    )
    for observed, expected, label in checks:
        if observed != expected:
            raise ValidatorEvidenceError(f"signed artifact {label} does not match signer config")
    from solslot_puzzles.enrollment_activation import activation_from_artifact
    try:
        from .inventory_extension_claims import extension_activation
        extension_activation(artifact, settings.deployment_environment, required=False)
        from .inventory_payment_hold_claims import payment_hold_activation
        payment_hold_activation(artifact, settings.deployment_environment, required=False)
        from .base_inventory_hold import base_hold_activation
        base_hold_activation(artifact, settings.deployment_environment, required=False)
        if 'checkoutLifecycle' in artifact:
            from .checkout_lifecycle import lifecycle_activation
            lifecycle_activation(artifact, settings.deployment_environment)
        activation = activation_from_artifact(artifact, environment=settings.deployment_environment)
    except ValueError as exc:
        raise ValidatorEvidenceError(str(exc)) from exc
    if activation != settings.enrollment_activation:
        raise ValidatorEvidenceError("signed enrollment activation differs from signer configuration")
    return artifact, release


def _coin_from_record(record: Mapping[str, Any], field: str) -> Coin:
    coin = record.get("coin")
    if not isinstance(coin, Mapping):
        raise ValidatorEvidenceError(f"{field} record has no coin")
    try:
        return Coin(
            bytes32.fromhex(str(coin["parent_coin_info"]).removeprefix("0x")),
            bytes32.fromhex(str(coin["puzzle_hash"]).removeprefix("0x")),
            uint64(int(coin["amount"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(f"{field} record is malformed") from exc


def _fetch_coin(
    settings: ValidatorSettings,
    coin_id: str,
    field: str,
    *,
    require_unspent: bool = True,
) -> Mapping[str, Any]:
    try:
        with httpx.Client(
            base_url=settings.coinset_base_url.rstrip("/"),
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post("/get_coin_record_by_name", json={"name": coin_id})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(f"Coinset could not verify {field}") from exc
    record = payload.get("coin_record") if isinstance(payload, Mapping) else None
    if not isinstance(record, Mapping):
        raise ValidatorEvidenceError(f"{field} is not confirmed on Chia")
    if int(record.get("confirmed_block_index") or 0) <= 0:
        raise ValidatorEvidenceError(f"{field} is not confirmed on Chia")
    if require_unspent and (
        bool(record.get("spent"))
        or int(record.get("spent_block_index") or 0) != 0
    ):
        raise ValidatorEvidenceError(f"{field} is already spent")
    return record


def _fetch_coin_spend(
    settings: ValidatorSettings,
    coin: Coin,
    spent_height: int,
    field: str,
):
    if spent_height <= 0:
        raise ValidatorEvidenceError(f"{field} is not spent on Chia")
    try:
        with httpx.Client(
            base_url=settings.coinset_base_url.rstrip("/"),
            timeout=20.0,
            headers={"content-type": "application/json"},
        ) as client:
            response = client.post(
                "/get_puzzle_and_solution",
                json={
                    "coin_id": "0x" + bytes(coin.name()).hex(),
                    "height": spent_height,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(f"Coinset could not verify {field}") from exc
    solution = payload.get("coin_solution") if isinstance(payload, Mapping) else None
    if not isinstance(solution, Mapping):
        raise ValidatorEvidenceError(f"{field} puzzle solution is unavailable")
    try:
        puzzle_reveal = Program.from_bytes(
            bytes.fromhex(str(solution["puzzle_reveal"]).removeprefix("0x"))
        )
        puzzle_solution = Program.from_bytes(
            bytes.fromhex(str(solution["solution"]).removeprefix("0x"))
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(f"{field} puzzle solution is malformed") from exc
    if puzzle_reveal.get_tree_hash() != coin.puzzle_hash:
        raise ValidatorEvidenceError(f"{field} puzzle reveal does not match its coin")
    return make_spend(coin, puzzle_reveal, puzzle_solution)


def _verify_vault_and_owner(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    claim: ValidatorClaim,
) -> None:
    if claim.owner_auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1):
        raise ValidatorEvidenceError("vault authorization type is not supported for V2 stamps")
    if (
        claim.current_timestamp < 1
        or abs(int(time.time()) - claim.current_timestamp)
        > settings.claim_clock_skew_seconds
    ):
        raise ValidatorEvidenceError("vault action timestamp is stale or in the future")

    coin_record = _fetch_coin(settings, claim.current_vault_coin_id, "current vault coin")
    coin = _coin_from_record(coin_record, "current vault coin")
    if "0x" + bytes(coin.name()).hex() != claim.current_vault_coin_id:
        raise ValidatorEvidenceError("current vault coin id does not match Coinset fields")
    launcher = bytes32.fromhex(claim.vault_launcher_id.removeprefix("0x"))
    if coin.parent_coin_info != launcher or int(coin.amount) != 1:
        raise ValidatorEvidenceError("current vault coin is not the unstamped singleton successor")

    try:
        authorization = bytes.fromhex(claim.owner_authorization.removeprefix("0x"))
    except ValueError as exc:
        raise ValidatorEvidenceError("owner authorization is not hex") from exc
    if "0x" + hashlib.sha256(authorization).hexdigest() != claim.owner_authorization_hash:
        raise ValidatorEvidenceError("owner authorization hash does not match signature bytes")

    owner_pubkey: bytes
    if claim.owner_auth_type == AUTH_TYPE_SECP256K1:
        typed_data = eip712_typed_data_for_vault_spend(
            b"z",
            bytes32.fromhex(claim.identity_attest_root.removeprefix("0x")),
            coin.name(),
        )
        try:
            recovered = recover_evm_signer(typed_data, claim.owner_authorization)
        except ValueError as exc:
            raise ValidatorEvidenceError("EVM owner authorization is invalid") from exc
        if (
            claim.owner_key.lower() != recovered.address.lower()
        ):
            raise ValidatorEvidenceError("EVM owner authorization does not belong to this vault")
        owner_pubkey = recovered.compressed_pubkey
    else:
        try:
            signature = G2Element.from_bytes(authorization)
            owner_pubkey = bytes.fromhex(claim.owner_key.removeprefix("0x"))
            public_key = G1Element.from_bytes(owner_pubkey)
        except ValueError as exc:
            raise ValidatorEvidenceError("BLS owner authorization is malformed") from exc
        owner_inner_message = bytes(
            Program.to(
                [
                    b"z",
                    bytes32.fromhex(claim.identity_attest_root.removeprefix("0x")),
                    coin.name(),
                ]
            ).get_tree_hash()
        )
        owner_message = owner_inner_message + bytes(coin.name()) + AGG_SIG_ME_DATA[settings.network]
        if not AugSchemeMPL.verify(public_key, owner_message, signature):
            raise ValidatorEvidenceError("BLS owner authorization does not belong to this vault")

    try:
        pool_launcher = bytes32.fromhex(
            str(artifact["launcherIds"]["pool"]).removeprefix("0x")
        )
        bridge_policy_hash = bytes32.fromhex(
            claim.bridge_policy_hash.removeprefix("0x")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError("artifact vault trust coordinates are invalid") from exc
    expected_puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        claim.owner_auth_type,
        one_leaf_merkle_root(owner_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    if coin.puzzle_hash != bytes32(expected_puzzle.get_tree_hash()):
        raise ValidatorEvidenceError(
            "owner authorization does not reconstruct the current unstamped vault coin"
        )


def _verify_bridge_coin(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    claim: ValidatorClaim,
) -> None:
    try:
        BridgeCoinPolicy.from_artifact(artifact).require_coin(
            policy_hash=claim.bridge_policy_hash, parent_id=claim.bridge_parent_id,
            amount=claim.bridge_amount, coin_id=claim.bridge_coin_id,
        )
    except ValueError as exc:
        raise ValidatorEvidenceError(str(exc)) from exc
    record = _fetch_coin(settings, claim.bridge_coin_id, "bridge coin")
    coin = _coin_from_record(record, "bridge coin")
    expected = Coin(
        bytes32.fromhex(claim.bridge_parent_id.removeprefix("0x")),
        bytes32.fromhex(claim.bridge_policy_hash.removeprefix("0x")),
        uint64(claim.bridge_amount),
    )
    if coin != expected or "0x" + bytes(coin.name()).hex() != claim.bridge_coin_id:
        raise ValidatorEvidenceError("bridge coin fields or lineage do not match the claim")


def _coordinator_settings(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
) -> Settings:
    return Settings(
        runtime_environment="test",
        network=settings.network,
        coinset_base_url=settings.coinset_base_url,
        public_artifact_path=settings.public_artifact_path,
        release_metadata_path=settings.release_metadata_path,
        zkpassport_evm_rpc_url=settings.evm_rpc_url,
        zkpassport_evm_chain_id=settings.evm_chain_id,
        zkpassport_evm_min_confirmations=settings.evm_min_confirmations,
        zkpassport_validator_threshold=2,
        zkpassport_validator_pubkeys=list(settings.roster_pubkeys),
        zkpassport_bridge_policy_hash=settings.bridge_policy_hash,
        zkpassport_forwarder_address=settings.evm_forwarder_address,
        zkpassport_emitter_address=settings.evm_attestation_emitter_address,
        pool_launcher_id=str(artifact["launcherIds"]["pool"]),
    )


def verify_validator_claim(
    settings: ValidatorSettings,
    claim: ValidatorClaim,
    claim_hash: str,
) -> tuple[dict[str, Any], ReleaseMetadata]:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError("claim hash does not match canonical evidence")
    artifact, release = load_validator_artifact(settings)
    from solslot_puzzles.enrollment_activation import activation_from_artifact
    from .enrollment_permit_runtime import validate_record_permit
    try:
        activation = activation_from_artifact(artifact, environment=settings.deployment_environment)
        if (activation is not None) != isinstance(claim, PermitValidatorClaim):
            raise ValueError("claim version differs from the signed enrollment deployment")
        permit_record = None
        if isinstance(claim, PermitValidatorClaim):
            permit_record = dict(enrollmentPermit=claim.enrollment_permit,
                permitIssuerSignature=claim.permit_issuer_signature, permitIssuanceStatus="issued",
                vaultLauncherId=claim.vault_launcher_id, bridgeCoinId=claim.bridge_coin_id,
                bridgePolicyHash=claim.bridge_policy_hash, network=claim.network, policyVersion=claim.policy_version)
            permit = validate_record_permit(permit_record, artifact, owner_auth_type=claim.owner_auth_type,
                owner_key=claim.owner_key, current_vault_coin_id=claim.current_vault_coin_id, now=int(time.time()))
            permit.require_live(claim.current_timestamp)
    except (ValueError, TypeError) as exc:
        raise ValidatorEvidenceError(str(exc)) from exc
    if claim.network != settings.network:
        raise ValidatorEvidenceError("claim network does not match signer")
    if claim.artifact_hash != str(artifact.get("artifactHash", "")).lower():
        raise ValidatorEvidenceError("claim artifact hash is not the active signed artifact")
    if claim.bridge_policy_hash != settings.bridge_policy_hash:
        raise ValidatorEvidenceError("claim bridge policy does not match signer")
    if claim.emitter_address.lower() != settings.evm_attestation_emitter_address:
        raise ValidatorEvidenceError("claim emitter is not the signed attestation emitter")

    event = _fetch_verified_evm_attestation(
        _coordinator_settings(settings, artifact),
        transaction_hash=claim.evm_transaction_hash,
        expected_vault_launcher_id=claim.vault_launcher_id,
        **(dict(authenticated_artifact=artifact, permit_record=permit_record) if activation is not None else {}),
    )
    event_fields = {
        "vault_launcher_id": claim.vault_launcher_id,
        "transaction_hash": claim.evm_transaction_hash,
        "block_number": claim.evm_block_number,
        "policy_version": claim.policy_version,
        "identity_attest_root": claim.identity_attest_root,
        "attestation_leaf_hash": claim.attestation_leaf_hash,
        "scoped_nullifier": claim.scoped_nullifier,
        "nullifier_type": claim.nullifier_type,
        "service_scope_hash": claim.service_scope_hash,
        "service_subscope_hash": claim.service_subscope_hash,
        "proof_timestamp": claim.proof_timestamp,
        "bridge_policy_hash": claim.bridge_policy_hash,
        "bridge_parent_id": claim.bridge_parent_id,
        "bridge_amount": claim.bridge_amount,
        "bridge_coin_id": claim.bridge_coin_id,
        "validator_message": claim.validator_message,
    }
    for field, expected in event_fields.items():
        if getattr(event, field) != expected:
            raise ValidatorEvidenceError(f"canonical EVM event {field} does not match claim")
    now = int(time.time())
    if claim.proof_timestamp > now or now - claim.proof_timestamp > settings.proof_max_age_seconds:
        raise ValidatorEvidenceError("zkPassport proof timestamp is stale or in the future")
    if claim.scoped_nullifier == "0x" + "00" * 32:
        raise ValidatorEvidenceError("scoped nullifier must be nonzero")
    if claim.service_scope_hash == "0x" + "00" * 32 or claim.service_subscope_hash == "0x" + "00" * 32:
        raise ValidatorEvidenceError("zkPassport scope commitments must be nonzero")

    _verify_vault_and_owner(settings, artifact, claim)
    if claim.owner_auth_type == AUTH_TYPE_SECP256K1 and event.sender.lower() != claim.owner_key.lower():
        raise ValidatorEvidenceError("EVM attestation sender is not the EVM vault owner")
    _verify_bridge_coin(settings, artifact, claim)
    return artifact, release


def sign_validator_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: ValidatorClaim,
    claim_hash: str,
) -> str:
    verify_validator_claim(settings, claim, claim_hash)
    private_key = load_validator_private_key(settings)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(private_key, claim.signature_message())
    ).hex()
    try:
        return ledger.record_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_claim_json(claim),
            scoped_nullifier=claim.scoped_nullifier,
            bridge_coin_id=claim.bridge_coin_id,
            vault_action=(
                f"{claim.vault_launcher_id}:{claim.current_vault_coin_id}:"
                f"{claim.identity_attest_root}:update_identity"
            ),
            evm_transaction_hash=claim.evm_transaction_hash,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_primary_purchase_claim_json(
    claim: PrimaryPurchaseClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def canonical_inventory_reservation_claim_json(
    claim: InventoryReservationClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def verify_inventory_reservation_claim(
    settings: ValidatorSettings,
    claim: InventoryReservationClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "reservation claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash", "")).lower()
    ):
        raise ValidatorEvidenceError(
            "reservation does not reference the active network artifact"
        )
    try:
        purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
        purchase.assert_live(int(time.time()))
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "reservation purchase artifact is invalid or expired"
        ) from exc
    if purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED:
        raise ValidatorEvidenceError("only SmartDeeds use inventory reservations")
    if claim.purchase_id() != "0x" + purchase.purchase_id.hex():
        raise ValidatorEvidenceError("reservation purchase ID is not canonical")
    if claim.reservation_expires_at > min(
        purchase.quote_expires_at,
        purchase.authorization_expires_at,
    ):
        raise ValidatorEvidenceError(
            "reservation outlives the quote or vault authorization"
        )

    bridge = artifact.get("bridgePolicy")
    validator_set = artifact.get("validatorSet")
    launchers = artifact.get("launcherIds")
    puzzle_hashes = artifact.get("puzzleHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (bridge, validator_set, launchers, puzzle_hashes)
    ):
        raise ValidatorEvidenceError(
            "signed artifact reservation coordinates are incomplete"
        )
    if (
        claim.credential_policy_version != 2
        or claim.credential_bridge_policy_hash
        != str(bridge.get("policyHash", "")).lower()
        or claim.credential_identity_root
        == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
        or "0x" + purchase.zkpassport_root.hex()
        != claim.credential_identity_root
    ):
        raise ValidatorEvidenceError(
            "reservation has no matching current zkPassport credential"
        )
    credential_record = _fetch_coin(
        settings,
        claim.credential_vault_coin_id,
        "reservation credential vault coin",
    )
    credential_coin = _coin_from_record(
        credential_record,
        "reservation credential vault coin",
    )
    credential_parent = _coin_from_record(
        _fetch_coin(
            settings,
            "0x" + credential_coin.parent_coin_info.hex(),
            "reservation pre-credential vault coin",
            require_unspent=False,
        ),
        "reservation pre-credential vault coin",
    )
    if (
        credential_parent.parent_coin_info != purchase.vault_launcher_id
        or int(credential_parent.amount) != 1
        or int(credential_coin.amount) != 1
    ):
        raise ValidatorEvidenceError(
            "reservation credential is not the approved vault successor"
        )
    try:
        owner_key = bytes.fromhex(claim.credential_owner_key.removeprefix("0x"))
        pool_launcher = bytes32.fromhex(
            str(launchers["pool"]).removeprefix("0x")
        )
        bridge_policy_hash = bytes32.fromhex(
            claim.credential_bridge_policy_hash.removeprefix("0x")
        )
        member_root = one_leaf_merkle_root(owner_key)
        unstamped_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            member_root,
            pool_launcher,
            identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        stamped_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            member_root,
            pool_launcher,
            identity_attest_root=bytes32.fromhex(
                claim.credential_identity_root.removeprefix("0x")
            ),
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "reservation vault ownership data is malformed"
        ) from exc
    if (
        credential_parent.puzzle_hash != unstamped_puzzle.get_tree_hash()
        or credential_coin.puzzle_hash != stamped_puzzle.get_tree_hash()
    ):
        raise ValidatorEvidenceError(
            "reservation credential root is not committed by the vault"
        )

    raw_pubkeys = validator_set.get("pubkeys")
    if (
        validator_set.get("threshold") != 2
        or not isinstance(raw_pubkeys, list)
        or raw_pubkeys != settings.roster_pubkeys
        or claim.protocol_puzzle_hash
        != str(puzzle_hashes.get("protocolTreasuryPuzzleHash", "")).lower()
        or purchase.protocol_treasury_puzzle_hash
        != bytes32.fromhex(claim.protocol_puzzle_hash.removeprefix("0x"))
    ):
        raise ValidatorEvidenceError(
            "reservation differs from signed treasury or validator roster"
        )
    try:
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        terms = PrimaryMintTermsV3.for_artifact(
            artifact=purchase,
            smart_deed_inner_hash=bytes32.fromhex(
                claim.smart_deed_inner_hash.removeprefix("0x")
            ),
            deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(
                protocol_did_singleton_struct=did_struct
            ),
            protocol_puzhash=purchase.protocol_treasury_puzzle_hash,
            validator_pubkeys=tuple(
                bytes.fromhex(str(value).removeprefix("0x"))
                for value in raw_pubkeys
            ),
            provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
        )
        deed_struct = deed_singleton_struct(
            deed_launcher_id=purchase.deed_launcher_id,
            protocol_did_singleton_struct=did_struct,
        )
        available_puzzle = SINGLETON_MOD.curry(
            deed_struct,
            make_inventory_available_inner(terms),
        )
        available_record = _fetch_coin(
                settings,
                claim.available_coin_id,
                "available SmartDeed coin",
            )
        available_coin = _coin_from_record(available_record, "available SmartDeed coin")
        terms = inventory_terms_for_puzzle_hash(terms, deed_struct, available_coin.puzzle_hash)
        available_puzzle = SINGLETON_MOD.curry(deed_struct, make_inventory_available_inner(terms))
        reservation = InventoryReservationV1(
            artifact=purchase,
            expires_at=claim.reservation_expires_at,
        )
        expected_message = inventory_reservation_message(
            available_coin=available_coin,
            reservation=reservation,
        )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "reservation mint terms cannot be reconstructed"
        ) from exc
    if (
        "0x" + available_coin.name().hex() != claim.available_coin_id
        or int(available_coin.amount) != 1
        or available_coin.puzzle_hash != available_puzzle.get_tree_hash()
        or claim.available_puzzle_hash
        != "0x" + available_puzzle.get_tree_hash().hex()
        or claim.validator_message != "0x" + expected_message.hex()
    ):
        raise ValidatorEvidenceError(
            "reservation does not spend the exact available governed SmartDeed"
        )
    if available_coin.parent_coin_info != purchase.deed_launcher_id:
        _verify_released_inventory_parent(settings, available_record, available_coin, deed_struct, terms)


def _verify_released_inventory_parent(settings, record, coin, deed_struct, terms):
    """Independent canonical lineage verification; never trust the API cursor."""
    from .inventory_recovery import record_coin, timeout_successor_lineage
    from .payment_purchase_store import PaymentPurchaseConflict
    parent_id = "0x" + coin.parent_coin_info.hex()
    parent_record = _fetch_coin(settings, parent_id, "inventory timeout parent", require_unspent=False)
    parent = _coin_from_record(parent_record, "inventory timeout parent")
    try:
        child_height, child_spent = record_coin(record, coin)
        _, spent_height = record_coin(parent_record, parent)
        if parent.name() != coin.parent_coin_info or child_spent or not spent_height or spent_height != child_height:
            raise PaymentPurchaseConflict("inventory timeout lineage is not atomic")
        spend = _fetch_coin_spend(settings, parent, spent_height, "inventory timeout parent")
        return timeout_successor_lineage(parent_spend=spend, successor=coin,
                                         deed_struct=deed_struct, terms=terms)
    except PaymentPurchaseConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def sign_inventory_reservation_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: InventoryReservationClaim,
    claim_hash: str,
) -> str:
    verify_inventory_reservation_claim(settings, claim, claim_hash)
    retirement = None
    old = ledger.active_inventory_authorization(claim.available_coin_id)
    if old is not None and old['claim_hash'] != claim_hash.lower():
        from .validator_inventory_expiry import prove_inventory_retirement
        retirement = prove_inventory_retirement(settings, old, claim)
        # A quote may expire during independent node reads. Recheck before signing.
        try:
            purchase_artifact_v3_from_json(claim.purchase_artifact).assert_live(int(time.time()))
        except (PaymentArtifactError, ValueError) as exc:
            raise ValidatorEvidenceError('replacement purchase expired during proof') from exc
        if claim.reservation_expires_at <= int(time.time()):
            raise ValidatorEvidenceError('replacement authorization expired during proof')
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_inventory_reservation_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_inventory_reservation_claim_json(claim),
            purchase_id=claim.purchase_id(),
            available_coin_id=claim.available_coin_id,
            deed_launcher_id="0x" + purchase_artifact_v3_from_json(claim.purchase_artifact).deed_launcher_id.hex(),
            signature=signature,
            retire_claim_hash=old['claim_hash'] if retirement is not None else None,
            retirement_evidence=retirement,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def verify_primary_purchase_claim(
    settings: ValidatorSettings,
    claim: PrimaryPurchaseClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "purchase claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if claim.network != settings.network:
        raise ValidatorEvidenceError("purchase network does not match signer")
    if claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "purchase does not reference the active signed artifact"
        )
    try:
        if claim.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
            batch = purchase_batch_from_json(claim.purchase_artifact)
            batch.assert_live(int(time.time()))
            purchases = batch.artifacts
            if "0x" + bytes(batch.batch_hash).hex() != (
                claim.purchase_artifact_hash()
            ):
                raise PaymentArtifactError("purchase batch hash is not canonical")
        else:
            batch = None
            purchase = purchase_artifact_v3_from_json(
                claim.purchase_artifact
            )
            purchase.assert_live(int(time.time()))
            purchases = (purchase,)
            if "0x" + bytes(purchase.artifact_hash).hex() != (
                claim.purchase_artifact_hash()
            ):
                raise PaymentArtifactError("purchase artifact hash is not canonical")
        purchase = purchases[0]
        deed_items = claim.delivery_items()
        if len(deed_items) != len(purchases):
            raise PaymentArtifactError(
                "purchase deed evidence does not match the canonical quantity"
            )
        if any(
            item.deed_launcher_id
            != "0x" + bytes(child.deed_launcher_id).hex()
            for child, item in zip(purchases, deed_items, strict=True)
        ):
            raise PaymentArtifactError(
                "purchase deed evidence changes the canonical launcher order"
            )
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "purchase artifact is invalid or expired"
        ) from exc
    if any(
        item.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT)
        for item in purchases
    ):
        raise ValidatorEvidenceError("purchase is not a native Chia rail")

    bridge = artifact.get("bridgePolicy")
    validator_set = artifact.get("validatorSet")
    launchers = artifact.get("launcherIds")
    puzzle_hashes = artifact.get("puzzleHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (bridge, validator_set, launchers, puzzle_hashes)
    ):
        raise ValidatorEvidenceError(
            "signed artifact purchase coordinates are incomplete"
        )
    if (
        claim.credential_policy_version != 2
        or claim.credential_bridge_policy_hash
        != str(bridge.get("policyHash", "")).lower()
        or claim.credential_identity_root
        == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
    ):
        raise ValidatorEvidenceError(
            "purchase has no current zkPassport credential"
        )
    if (
        "0x" + bytes(purchase.zkpassport_root).hex()
        != claim.credential_identity_root
    ):
        raise ValidatorEvidenceError(
            "purchase does not bind the current zkPassport root"
        )
    credential_record = _fetch_coin(
        settings,
        claim.credential_vault_coin_id,
        "credential vault coin",
    )
    credential_coin = _coin_from_record(
        credential_record,
        "credential vault coin",
    )
    credential_parent_record = _fetch_coin(
        settings,
        "0x" + bytes(credential_coin.parent_coin_info).hex(),
        "pre-credential vault coin",
        require_unspent=False,
    )
    credential_parent = _coin_from_record(
        credential_parent_record,
        "pre-credential vault coin",
    )
    if (
        credential_parent.parent_coin_info != purchase.vault_launcher_id
        or int(credential_parent.amount) != 1
        or int(credential_coin.amount) != 1
    ):
        raise ValidatorEvidenceError(
            "credential coin is not the stamped successor of this vault"
        )

    try:
        owner_key = bytes.fromhex(claim.credential_owner_key.removeprefix("0x"))
        pool_launcher = bytes32.fromhex(
            str(launchers["pool"]).removeprefix("0x")
        )
        bridge_policy_hash = bytes32.fromhex(
            claim.credential_bridge_policy_hash.removeprefix("0x")
        )
        member_root = one_leaf_merkle_root(owner_key)
        unstamped_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            member_root,
            pool_launcher,
            identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        stamped_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            member_root,
            pool_launcher,
            identity_attest_root=bytes32.fromhex(
                claim.credential_identity_root.removeprefix("0x")
            ),
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "credential vault ownership data is malformed"
        ) from exc
    if (
        credential_parent.puzzle_hash != unstamped_puzzle.get_tree_hash()
        or credential_coin.puzzle_hash != stamped_puzzle.get_tree_hash()
    ):
        raise ValidatorEvidenceError(
            "credential root is not committed by the current vault puzzle"
        )

    raw_pubkeys = validator_set.get("pubkeys")
    if (
        validator_set.get("threshold") != 2
        or not isinstance(raw_pubkeys, list)
        or raw_pubkeys != settings.roster_pubkeys
    ):
        raise ValidatorEvidenceError(
            "signed artifact validator roster is inconsistent"
        )
    try:
        validator_pubkeys = tuple(
            bytes.fromhex(str(value).removeprefix("0x"))
            for value in raw_pubkeys
        )
        protocol_puzhash = bytes32.fromhex(
            claim.protocol_puzzle_hash.removeprefix("0x")
        )
        did_launcher = bytes32.fromhex(
            str(launchers["did"]).removeprefix("0x")
        )
        did_struct = singleton_struct(did_launcher)
        terms_list = []
        deed_structs = []
        for child, item in zip(purchases, deed_items, strict=True):
            terms = PrimaryMintTermsV3.for_artifact(
                artifact=child,
                smart_deed_inner_hash=bytes32.fromhex(
                    item.smart_deed_inner_hash.removeprefix("0x")
                ),
                deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(
                    protocol_did_singleton_struct=did_struct
                ),
                protocol_puzhash=protocol_puzhash,
                validator_pubkeys=validator_pubkeys,
                provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
            )
            deed_struct = deed_singleton_struct(
                deed_launcher_id=child.deed_launcher_id,
                protocol_did_singleton_struct=did_struct,
            )
            deed_structs.append(deed_struct)
            reservation = InventoryReservationV1(
                artifact=child,
                expires_at=item.reservation_expires_at,
            )
            if reservation.expires_at > min(
                child.quote_expires_at,
                child.authorization_expires_at,
            ):
                raise ValueError("reservation outlives purchase authorization")
            terms = inventory_terms_for_puzzle_hash(
                terms, deed_struct, bytes32.fromhex(item.deed_puzzle_hash.removeprefix("0x")),
                reservation=reservation,
            )
            expected_puzzle = SINGLETON_MOD.curry(
                deed_struct,
                make_mint_offer_v5_inner(terms, reservation),
            )
            if (
                claim.protocol_puzzle_hash
                != str(
                    puzzle_hashes.get("protocolTreasuryPuzzleHash", "")
                ).lower()
                or "0x" + bytes(child.protocol_treasury_puzzle_hash).hex()
                != claim.protocol_puzzle_hash
                or item.deed_puzzle_hash
                != "0x" + bytes(expected_puzzle.get_tree_hash()).hex()
            ):
                raise ValueError(
                    "purchase puzzle does not match the signed mint coordinates"
                )
            deed_record = _fetch_coin(
                settings,
                item.deed_coin_id,
                "primary SmartDeed coin",
            )
            deed_coin = _coin_from_record(
                deed_record,
                "primary SmartDeed coin",
            )
            if (
                int(deed_coin.amount) != 1
                or deed_coin.puzzle_hash != expected_puzzle.get_tree_hash()
                or "0x" + bytes(deed_coin.name()).hex()
                != item.deed_coin_id
            ):
                raise ValueError(
                    "primary SmartDeed coin does not match the governed mint"
                )
            terms_list.append(terms)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "purchase mint terms cannot be reconstructed"
        ) from exc

    try:
        buyer_offer = Offer.from_bech32(claim.buyer_offer)
        if batch is None:
            validate_chia_buyer_offer_v3(
                buyer_offer=buyer_offer,
                artifact=purchase,
                terms=terms_list[0],
                deed_singleton_struct=deed_structs[0],
            )
        else:
            validate_chia_buyer_batch_offer_v3(
                buyer_offer=buyer_offer,
                batch=batch,
                terms=tuple(terms_list),
                deed_singleton_structs=tuple(deed_structs),
            )
        if len(buyer_offer.coin_spends()) != 1 or buyer_offer.fees() != 0:
            raise ValueError("buyer offer must use one zero-fee payment coin")
        pairs: list[tuple[G1Element, bytes]] = []
        for spend in buyer_offer.coin_spends():
            conditions = conditions_dict_for_solution(
                spend.puzzle_reveal,
                spend.solution,
                INFINITE_COST,
            )
            pairs.extend(
                pkm_pairs_for_conditions_dict(
                    conditions,
                    spend.coin,
                    AGG_SIG_ME_DATA[settings.network],
                )
            )
        if not pairs or not AugSchemeMPL.aggregate_verify(
            [pair[0] for pair in pairs],
            [pair[1] for pair in pairs],
            buyer_offer.aggregated_signature(),
        ):
            raise ValueError("buyer offer signature is invalid")
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "wallet-signed buyer offer is invalid"
        ) from exc


def sign_primary_purchase_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: PrimaryPurchaseClaim,
    claim_hash: str,
) -> str:
    verify_primary_purchase_claim(settings, claim, claim_hash)
    private_key = load_validator_private_key(settings)
    messages = claim.signature_messages()
    item_signatures = tuple(
        AugSchemeMPL.sign(private_key, message) for message in messages
    )
    signature = "0x" + bytes(AugSchemeMPL.aggregate(item_signatures)).hex()
    try:
        if len(item_signatures) > 1:
            items = claim.delivery_items()
            batch = purchase_batch_from_json(claim.purchase_artifact)
            canonical_claim = canonical_primary_purchase_claim_json(claim)
            parent_hash = bytes.fromhex(claim_hash.removeprefix("0x"))
            recovered = ledger.record_primary_purchase_batch_or_recover(
                claim_hashes=tuple(
                    "0x"
                    + hashlib.sha256(
                        parent_hash + index.to_bytes(4, "big")
                    ).hexdigest()
                    for index in range(len(items))
                ),
                canonical_claims=tuple(
                    json.dumps(
                        {
                            "batchClaim": json.loads(canonical_claim),
                            "itemIndex": index,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    )
                    for index in range(len(items))
                ),
                purchase_ids=tuple(
                    "0x" + bytes(artifact.purchase_id).hex()
                    for artifact in batch.artifacts
                ),
                deed_coin_ids=tuple(item.deed_coin_id for item in items),
                signatures=tuple(
                    "0x" + bytes(item_signature).hex()
                    for item_signature in item_signatures
                ),
            )
            return "0x" + bytes(
                AugSchemeMPL.aggregate(
                    [
                        G2Element.from_bytes(
                            bytes.fromhex(value.removeprefix("0x"))
                        )
                        for value in recovered
                    ]
                )
            ).hex()
        return ledger.record_primary_purchase_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_primary_purchase_claim_json(claim),
            purchase_id=claim.purchase_id(),
            deed_coin_id=claim.delivery_coin_id(),
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_stripe_settlement_claim_json(
    claim: StripeSettlementClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def load_stripe_restricted_key(settings: ValidatorSettings) -> str:
    if not settings.stripe_settlement_enabled:
        raise ValidatorEvidenceError("Stripe settlement signing is disabled")
    path = Path(settings.stripe_restricted_key_file)
    if path.is_symlink() or not path.is_file():
        raise ValidatorEvidenceError("Stripe restricted key file is missing")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO) and not _is_protected_systemd_credential(
        path,
        mode,
        expected_name="stripe-read-key",
    ):
        raise ValidatorEvidenceError(
            "Stripe restricted key file must not be accessible by group/other"
        )
    try:
        key = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValidatorEvidenceError("Stripe restricted key is unreadable") from exc
    expected_prefix = "rk_test_" if settings.stripe_mode == "test" else "rk_live_"
    if not key.startswith(expected_prefix) or len(key) < len(expected_prefix) + 16:
        raise ValidatorEvidenceError(
            "Stripe restricted key does not match the configured mode"
        )
    return key


def _verify_stripe_provider_evidence(
    settings: ValidatorSettings,
    claim: StripeSettlementClaim,
) -> None:
    evidence = stripe_settlement_evidence_from_json(claim.stripe_evidence)
    if (
        evidence.stripe_account_id != settings.stripe_account_id
        or (settings.stripe_mode == "live") != evidence.livemode
    ):
        raise ValidatorEvidenceError(
            "Stripe evidence does not match this validator's account and mode"
        )
    headers = {
        "authorization": f"Bearer {load_stripe_restricted_key(settings)}",
        "stripe-version": "2024-06-20",
    }
    try:
        with httpx.Client(
            base_url=settings.stripe_api_url.rstrip("/"),
            headers=headers,
            timeout=20.0,
        ) as client:
            intent_response = client.get(
                f"/v1/payment_intents/{evidence.payment_intent_id}",
                params={"expand[]": "latest_charge"},
            )
            intent_response.raise_for_status()
            event_response = client.get(f"/v1/events/{evidence.event_id}")
            event_response.raise_for_status()
            intent = intent_response.json()
            event = event_response.json()
            charge = intent.get("latest_charge")
            if isinstance(charge, str):
                charge_response = client.get(f"/v1/charges/{charge}")
                charge_response.raise_for_status()
                charge = charge_response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe could not independently verify the paid purchase"
        ) from exc
    if not isinstance(intent, Mapping) or not isinstance(event, Mapping):
        raise ValidatorEvidenceError("Stripe returned malformed payment evidence")
    event_object = event.get("data", {}).get("object") if isinstance(
        event.get("data"), Mapping
    ) else None
    metadata = intent.get("metadata")
    if claim.purchase_artifact.get("schema") == "solslot.purchase-batch.v1":
        purchase_document = purchase_batch_from_json(claim.purchase_artifact)
        purchase_id = purchase_document.purchase_id
        purchase_hash = purchase_document.batch_hash
        quote_expires_at = purchase_document.quote_expires_at
    else:
        purchase_document = purchase_artifact_v3_from_json(
            claim.purchase_artifact
        )
        purchase_id = purchase_document.purchase_id
        purchase_hash = purchase_document.artifact_hash
        quote_expires_at = purchase_document.quote_expires_at
    expected_live = settings.stripe_mode == "live"
    if (
        intent.get("id") != evidence.payment_intent_id
        or bool(intent.get("livemode")) != expected_live
        or intent.get("status") != "succeeded"
        or int(intent.get("created") or 0) <= 0
        or int(intent.get("created") or 0) >= quote_expires_at
        or intent.get("currency") != "usd"
        or int(intent.get("amount_received") or 0) != evidence.amount_minor
        or event.get("id") != evidence.event_id
        or event.get("type") != "payment_intent.succeeded"
        or bool(event.get("livemode")) != expected_live
        or not isinstance(event_object, Mapping)
        or event_object.get("id") != evidence.payment_intent_id
        or not isinstance(metadata, Mapping)
        or str(metadata.get("protocol_purchase_id") or "").lower()
        != "0x" + purchase_id.hex()
        or str(metadata.get("purchase_artifact_hash") or "").lower()
        != "0x" + purchase_hash.hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe PaymentIntent or event differs from the purchase receipt"
        )
    if not isinstance(charge, Mapping):
        raise ValidatorEvidenceError("Stripe payment has no retrievable charge")
    method_details = charge.get("payment_method_details")
    if not isinstance(method_details, Mapping):
        raise ValidatorEvidenceError("Stripe payment method evidence is unavailable")
    method_type = str(method_details.get("type") or "")
    expected_method = (
        "card"
        if evidence.method_family == StripeMethodFamily.CARD
        else "us_bank_account"
    )
    card = method_details.get("card")
    observed_funding = (
        str(card.get("funding") or "unknown")
        if isinstance(card, Mapping)
        else "not_applicable"
    )
    expected_funding = {
        StripeFundingType.CREDIT: "credit",
        StripeFundingType.DEBIT: "debit",
        StripeFundingType.PREPAID: "prepaid",
        StripeFundingType.UNKNOWN: "unknown",
        StripeFundingType.BANK_ACCOUNT: "not_applicable",
    }[evidence.funding_type]
    if (
        method_type != expected_method
        or observed_funding != expected_funding
        or bool(charge.get("refunded"))
        or int(charge.get("amount_refunded") or 0) != 0
        or bool(charge.get("disputed"))
    ):
        raise ValidatorEvidenceError(
            "Stripe funding, refund, or dispute state differs from the receipt"
        )


def _verify_stripe_sgt_sale(
    settings: ValidatorSettings,
    artifact: Mapping[str, Any],
    claim: StripeSettlementClaim,
    purchase: Any,
) -> None:
    """Reconstruct an external SGT sale from signed release and Chia state."""

    if None in {
        claim.sgt_sale_coin_id,
        claim.sgt_sale_puzzle_hash,
        claim.governance_bill_clvm_hex,
    }:
        raise ValidatorEvidenceError("Stripe SGT sale evidence is incomplete")
    try:
        plan_value = artifact.get("genesisPlan", artifact)
        if not isinstance(plan_value, Mapping):
            raise TypeError
        launchers = plan_value["launcherIds"]
        puzzles = plan_value["puzzleHashes"]
        trusted_assets = plan_value["trustedAssets"]
        destinations = plan_value["trustedDestinations"]
        permanent_rules = plan_value.get("permanentRules", {})
        if not all(
            isinstance(value, Mapping)
            for value in (
                launchers,
                puzzles,
                trusted_assets,
                destinations,
                permanent_rules,
            )
        ):
            raise TypeError
        tracker_struct = singleton_struct(
            bytes32.fromhex(str(launchers["governance"]).removeprefix("0x"))
        )
        admin_struct = singleton_struct(
            bytes32.fromhex(str(launchers["adminAuthority"]).removeprefix("0x"))
        )
        sgt_tail = bytes32.fromhex(
            str(
                artifact.get("sgtTailHash")
                or permanent_rules["sgtTailHash"]
            ).removeprefix("0x")
        )
        company_treasury = bytes32.fromhex(
            str(
                destinations["companySgtSaleTreasuryPuzzleHash"]
            ).removeprefix("0x")
        )
        wusdc_b_asset_id = bytes32.fromhex(
            str(trusted_assets["wusdcBAssetId"]).removeprefix("0x")
        )
        reserve_inner = sgt_reserve_inner_puzzle(
            proposal_tracker_struct=tracker_struct,
            admin_authority_struct=admin_struct,
            sgt_tail_hash=sgt_tail,
            wusdc_b_asset_id=wusdc_b_asset_id,
            company_treasury_puzzle_hash=company_treasury,
        )
        reserve_owner = bytes32(reserve_inner.get_tree_hash())
        if reserve_owner != bytes32.fromhex(
            str(puzzles["sgtReserveInner"]).removeprefix("0x")
        ):
            raise ValueError("signed SGT reserve hash changed")
        bill = Program.from_bytes(
            bytes.fromhex(
                str(claim.governance_bill_clvm_hex).removeprefix("0x")
            )
        )
        terms = sgt_sale_terms_from_bill(
            bill,
            reserve_owner_inner_hash=reserve_owner,
        )
        sale_inner = sgt_sale_inner_puzzle(
            reserve_owner_inner_hash=reserve_owner,
            sgt_tail_hash=sgt_tail,
            terms=terms,
        )
        sale_full = sgt_cat_puzzle(
            proposal_tracker_struct=tracker_struct,
            sgt_tail_hash=sgt_tail,
            owner_inner_puzzle=sale_inner,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe SGT sale cannot be reconstructed from signed evidence"
        ) from exc

    expected_sale_rail = (
        SGTAllocationRail.STRIPE
        if purchase.rail == PaymentRail.STRIPE
        else SGTAllocationRail.BASE_USDC
    )
    if (
        purchase.delivery_kind != PurchaseDeliveryKind.SGT
        or purchase.rail not in {PaymentRail.STRIPE, PaymentRail.EVM_TEST_USD}
        or purchase.delivery_asset_id != sgt_tail
        or purchase.delivery_amount != terms.sgt_amount
        or purchase.delivery_context_hash != terms.sale_id
        or purchase.vault_launcher_id != terms.recipient_vault_launcher_id
        or purchase.vault_p2_puzzle_hash
        != puzzle_hash_for_p2_vault(terms.recipient_vault_launcher_id)
        or purchase.artifact_hash != terms.purchase_artifact_hash
        or purchase.rail_amount != terms.payment_amount
        or terms.payment_rail != expected_sale_rail
        or terms.company_treasury_puzzle_hash != company_treasury
        or int(time.time()) >= terms.expires_at
        or claim.sgt_sale_puzzle_hash
        != "0x" + sale_full.get_tree_hash().hex()
    ):
        raise ValidatorEvidenceError(
            "Stripe SGT purchase differs from its governed sale"
        )

    sale_record = _fetch_coin(
        settings,
        str(claim.sgt_sale_coin_id),
        "Stripe SGT sale coin",
    )
    sale_coin = _coin_from_record(sale_record, "Stripe SGT sale coin")
    if (
        sale_coin.puzzle_hash != sale_full.get_tree_hash()
        or int(sale_coin.amount) != terms.sgt_amount
        or "0x" + sale_coin.name().hex() != claim.sgt_sale_coin_id
    ):
        raise ValidatorEvidenceError(
            "Stripe SGT sale coin is not the governed allocation"
        )
    parent_record = _fetch_coin(
        settings,
        "0x" + sale_coin.parent_coin_info.hex(),
        "Stripe SGT reserve parent",
        require_unspent=False,
    )
    parent_coin = _coin_from_record(parent_record, "Stripe SGT reserve parent")
    reserve_free = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        reserve_owner,
    )
    reserve_full = construct_cat_puzzle(CAT_MOD, sgt_tail, reserve_free)
    if (
        parent_coin.puzzle_hash != reserve_full.get_tree_hash()
        or int(parent_coin.amount) < terms.sgt_amount
        or int(parent_record.get("spent_block_index") or 0) <= 0
    ):
        raise ValidatorEvidenceError(
            "Stripe SGT sale is not descended from the governed reserve"
        )


def verify_stripe_settlement_claim(
    settings: ValidatorSettings,
    claim: StripeSettlementClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "Stripe claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if claim.network != settings.network or claim.genesis_artifact_hash != str(
        artifact.get("artifactHash", "")
    ).lower():
        raise ValidatorEvidenceError(
            "Stripe delivery does not reference the active Testnet11 artifact"
        )
    try:
        batch = (
            purchase_batch_from_json(claim.purchase_artifact)
            if claim.purchase_artifact.get("schema")
            == "solslot.purchase-batch.v1"
            else None
        )
        purchases = (
            batch.artifacts
            if batch is not None
            else (purchase_artifact_v3_from_json(claim.purchase_artifact),)
        )
        purchase = purchases[0]
        if purchase.rail == PaymentRail.STRIPE:
            if claim.stripe_evidence is None:
                raise PaymentArtifactError("Stripe evidence is missing")
            evidence = stripe_settlement_evidence_from_json(
                claim.stripe_evidence
            )
            validator_pubkeys = tuple(
                bytes.fromhex(value.removeprefix("0x"))
                for value in settings.roster_pubkeys
            )
            receipt = (
                build_purchase_batch_settlement_receipt_v1(
                    batch=batch,
                    provider_id=STRIPE_PAYMENT_PROVIDER_ID,
                    external_reference_hash=evidence.payment_reference_hash,
                    evidence_hash=evidence.evidence_hash,
                    observed_at=evidence.observed_at,
                    validator_pubkeys=validator_pubkeys,  # type: ignore[arg-type]
                    collected_amount_minor=evidence.amount_minor,
                    processing_charge_minor=evidence.processing_charge_minor,
                )
                if batch is not None
                else build_stripe_settlement_receipt_v1(
                    artifact=purchase,
                    evidence=evidence,
                    validator_pubkeys=validator_pubkeys,  # type: ignore[arg-type]
                )
            )
        elif purchase.rail == PaymentRail.EVM_TEST_USD:
            if claim.base_evidence is None:
                raise PaymentArtifactError("Base evidence is missing")
            receipt = (
                build_base_batch_settlement_receipt(
                    batch=batch,
                    evidence=claim.base_evidence,
                    validator_pubkeys=tuple(
                        bytes.fromhex(value.removeprefix("0x"))
                        for value in settings.roster_pubkeys
                    ),  # type: ignore[arg-type]
                    result_authorization_puzzle_hash=bytes32.from_hexstr(
                        str(claim.base_result_authorization_puzzle_hash)
                    ),
                )
                if batch is not None
                else build_base_settlement_receipt(
                    artifact=purchase,
                    evidence=claim.base_evidence,
                    result_authorization_puzzle_hash=bytes32.from_hexstr(
                        str(claim.base_result_authorization_puzzle_hash)
                    ),
                )
            )
        else:
            raise PaymentArtifactError("unsupported external payment rail")
    except (PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe purchase or receipt evidence is invalid"
        ) from exc
    base_result_puzzle_hash = bytes32.zeros
    if purchase.rail == PaymentRail.STRIPE:
        _verify_stripe_provider_evidence(settings, claim)
    else:
        assert claim.base_evidence is not None
        depositor = str(claim.base_evidence.get("depositor") or "").lower()
        if not depositor.startswith("0x") or len(depositor) != 42:
            raise ValidatorEvidenceError("Base depositor is invalid")
        try:
            payer = bytes32(bytes(12) + bytes.fromhex(depositor[2:]))
            global_payment = bytes32.from_hexstr(
                str(claim.base_evidence.get("globalPaymentId") or "")
            )
        except ValueError as exc:
            raise ValidatorEvidenceError("Base payment identifiers are invalid") from exc
        _verify_base_voucher_payment(
            settings,
            claim.base_evidence,
            purchase=(batch if batch is not None else purchase),
            voucher=SimpleNamespace(
                original_payer=payer,
                global_payment_id=global_payment,
                payment_principal=(
                    batch.total_rail_amount
                    if batch is not None
                    else purchase.rail_amount
                ),
                collection_id=purchase.collection_id,
                deed_launcher_id=purchase.deed_launcher_id,
                approved_vault_launcher_id=purchase.vault_launcher_id,
                approved_vault_p2_puzzle_hash=purchase.vault_p2_puzzle_hash,
                quantity=(batch.quantity if batch is not None else 1),
            ),
        )
        if not settings.base_return_puzzle_hash:
            raise ValidatorEvidenceError(
                "reviewed Base return puzzle hash is unavailable"
            )
        try:
            base_result_puzzle_hash = (
                base_result_authorization_puzzle_hash(
                    artifact=(batch if batch is not None else purchase),
                    evidence=claim.base_evidence,
                    return_puzzle_hash=bytes32.from_hexstr(
                        settings.base_return_puzzle_hash
                    ),
                )
            )
        except (PaymentArtifactError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "Base result authorization cannot be reconstructed"
            ) from exc
        if claim.base_result_authorization_puzzle_hash != (
            "0x" + base_result_puzzle_hash.hex()
        ):
            raise ValidatorEvidenceError(
                "Base result authorization puzzle hash changed"
            )

    validator_set = artifact.get("validatorSet")
    launchers = artifact.get("launcherIds")
    puzzle_hashes = artifact.get("puzzleHashes")
    if not all(
        isinstance(value, Mapping)
        for value in (validator_set, launchers, puzzle_hashes)
    ):
        raise ValidatorEvidenceError(
            "signed artifact purchase coordinates are incomplete"
        )
    raw_pubkeys = validator_set.get("pubkeys")
    if (
        validator_set.get("threshold") != 2
        or raw_pubkeys != settings.roster_pubkeys
        or claim.protocol_puzzle_hash
        != str(puzzle_hashes.get("protocolTreasuryPuzzleHash", "")).lower()
        or purchase.protocol_treasury_puzzle_hash
        != bytes32.fromhex(claim.protocol_puzzle_hash.removeprefix("0x"))
    ):
        raise ValidatorEvidenceError(
            "Stripe delivery differs from the signed treasury or validator roster"
        )

    if (
        purchase.zkpassport_root
        != bytes32.fromhex(claim.credential_identity_root.removeprefix("0x"))
        or claim.credential_identity_root
        == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
        or claim.credential_policy_version != 2
        or claim.credential_bridge_policy_hash != settings.bridge_policy_hash
    ):
        raise ValidatorEvidenceError(
            "Stripe delivery has no matching zkPassport-approved vault root"
        )
    credential_record = _fetch_coin(
        settings,
        claim.credential_vault_coin_id,
        "Stripe credential vault coin",
    )
    credential_coin = _coin_from_record(
        credential_record,
        "Stripe credential vault coin",
    )
    credential_parent_record = _fetch_coin(
        settings,
        "0x" + credential_coin.parent_coin_info.hex(),
        "Stripe credential parent coin",
        require_unspent=False,
    )
    credential_parent = _coin_from_record(
        credential_parent_record,
        "Stripe credential parent coin",
    )
    owner_key = bytes.fromhex(claim.credential_owner_key.removeprefix("0x"))
    try:
        pool_launcher = bytes32.fromhex(
            str(launchers["pool"]).removeprefix("0x")
        )
        expected_credential_puzzle = puzzle_for_vault_full(
            purchase.vault_launcher_id,
            owner_key,
            claim.credential_owner_auth_type,
            one_leaf_merkle_root(owner_key),
            pool_launcher,
            identity_attest_root=purchase.zkpassport_root,
            zkpassport_bridge_policy_hash=bytes32.fromhex(
                claim.credential_bridge_policy_hash.removeprefix("0x")
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe vault ownership evidence is malformed"
        ) from exc
    if (
        credential_parent.parent_coin_info != purchase.vault_launcher_id
        or int(credential_parent.amount) != 1
        or int(credential_coin.amount) != 1
        or credential_coin.puzzle_hash != expected_credential_puzzle.get_tree_hash()
    ):
        raise ValidatorEvidenceError(
            "Stripe vault credential is not the approved singleton state"
        )

    try:
        validator_pubkeys = tuple(
            bytes.fromhex(str(value).removeprefix("0x"))
            for value in raw_pubkeys
        )
        receipt_terms = (
            PurchaseBatchSettlementTermsV1(
                receipt=receipt,
                validator_pubkeys=validator_pubkeys,  # type: ignore[arg-type]
            )
            if batch is not None
            else StripeSettlementTermsV1(
                receipt=receipt,
                validator_pubkeys=validator_pubkeys,  # type: ignore[arg-type]
            )
        )
        if receipt.result_authorization_puzzle_hash != (
            base_result_puzzle_hash
        ):
            raise PaymentArtifactError(
                "external receipt result authorization changed"
            )
        receipt_puzzle = (
            curry_purchase_batch_settlement_receipt(receipt_terms)
            if batch is not None
            else curry_stripe_settlement_receipt(receipt_terms)
        )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe receipt puzzle cannot be reconstructed"
        ) from exc
    if claim.receipt_puzzle_hash != "0x" + receipt_puzzle.get_tree_hash().hex():
        raise ValidatorEvidenceError("Stripe receipt puzzle hash changed")
    receipt_record = _fetch_coin(
        settings,
        claim.receipt_coin_id,
        "Stripe settlement receipt coin",
    )
    receipt_coin = _coin_from_record(
        receipt_record,
        "Stripe settlement receipt coin",
    )
    if (
        receipt_coin.puzzle_hash != receipt_puzzle.get_tree_hash()
        or int(receipt_coin.amount) != (
            batch.quantity if batch is not None else 1
        )
        or "0x" + receipt_coin.name().hex() != claim.receipt_coin_id
    ):
        raise ValidatorEvidenceError(
            "Stripe settlement receipt coin is not exact and unspent"
        )

    if purchase.delivery_kind == PurchaseDeliveryKind.SGT:
        if batch is not None:
            raise ValidatorEvidenceError("SGT cannot use a SmartDeed batch receipt")
        _verify_stripe_sgt_sale(settings, artifact, claim, purchase)
        return
    deed_items = claim.delivery_items()
    if (
        purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED
        or len(deed_items) != len(purchases)
    ):
        raise ValidatorEvidenceError("Stripe delivery kind is unsupported")

    try:
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        for child, item in zip(purchases, deed_items, strict=True):
            deed_struct = deed_singleton_struct(
                deed_launcher_id=child.deed_launcher_id,
                protocol_did_singleton_struct=did_struct,
            )
            mint_terms = PrimaryMintTermsV3.for_artifact(
                artifact=child,
                smart_deed_inner_hash=bytes32.fromhex(
                    item.smart_deed_inner_hash.removeprefix("0x")
                ),
                deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(
                    protocol_did_singleton_struct=did_struct
                ),
                protocol_puzhash=child.protocol_treasury_puzzle_hash,
                validator_pubkeys=validator_pubkeys,  # type: ignore[arg-type]
                provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
            )
            reservation = InventoryReservationV1(
                artifact=child,
                expires_at=item.reservation_expires_at,
            )
            if reservation.expires_at > min(
                child.quote_expires_at,
                child.authorization_expires_at,
            ):
                raise PaymentArtifactError(
                    "reservation outlives purchase authorization"
                )
            mint_terms = inventory_terms_for_puzzle_hash(
                mint_terms, deed_struct, bytes32.fromhex(item.deed_puzzle_hash.removeprefix("0x")),
                reservation=reservation,
            )
            expected_deed_puzzle = SINGLETON_MOD.curry(
                deed_struct,
                make_mint_offer_v5_inner(mint_terms, reservation),
            )
            if item.deed_puzzle_hash != (
                "0x" + expected_deed_puzzle.get_tree_hash().hex()
            ):
                raise PaymentArtifactError("SmartDeed puzzle hash changed")
            deed_record = _fetch_coin(
                settings,
                item.deed_coin_id,
                "Stripe SmartDeed coin",
            )
            deed_coin = _coin_from_record(
                deed_record,
                "Stripe SmartDeed coin",
            )
            if (
                deed_coin.puzzle_hash != expected_deed_puzzle.get_tree_hash()
                or int(deed_coin.amount) != 1
                or "0x" + deed_coin.name().hex() != item.deed_coin_id
            ):
                raise PaymentArtifactError(
                    "receipt or governed SmartDeed coin is not exact and unspent"
                )
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "Stripe governed deed set cannot be reconstructed"
        ) from exc


def sign_stripe_settlement_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: StripeSettlementClaim,
    claim_hash: str,
) -> str:
    verify_stripe_settlement_claim(settings, claim, claim_hash)
    pubkeys = tuple(
        bytes.fromhex(value.removeprefix("0x"))
        for value in settings.roster_pubkeys
    )
    private_key = load_validator_private_key(settings)
    signature = "0x" + bytes(
        AugSchemeMPL.aggregate(
            [
                AugSchemeMPL.sign(private_key, message)
                for message in claim.signature_messages(pubkeys)  # type: ignore[arg-type]
            ]
        )
    ).hex()
    batch = (
        purchase_batch_from_json(claim.purchase_artifact)
        if claim.purchase_artifact.get("schema") == "solslot.purchase-batch.v1"
        else None
    )
    purchase = (
        batch.artifacts[0]
        if batch is not None
        else purchase_artifact_v3_from_json(claim.purchase_artifact)
    )
    if purchase.rail == PaymentRail.STRIPE:
        assert claim.stripe_evidence is not None
        evidence = stripe_settlement_evidence_from_json(claim.stripe_evidence)
        external_payment_id = evidence.payment_intent_id
    else:
        assert claim.base_evidence is not None
        external_payment_id = str(claim.base_evidence["globalPaymentId"]).lower()
    try:
        if batch is not None:
            return ledger.record_stripe_settlement_batch_or_recover(
                claim_hash=claim_hash.lower(),
                canonical_claim=canonical_stripe_settlement_claim_json(claim),
                purchase_id=claim.purchase_id(),
                payment_intent_id=external_payment_id,
                receipt_coin_id=claim.receipt_coin_id,
                delivery_coin_ids=tuple(
                    item.deed_coin_id for item in claim.delivery_items()
                ),
                signature=signature,
            )
        return ledger.record_stripe_settlement_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_stripe_settlement_claim_json(claim),
            purchase_id=claim.purchase_id(),
            payment_intent_id=external_payment_id,
            receipt_coin_id=claim.receipt_coin_id,
            delivery_coin_id=claim.delivery_coin_id(),
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_voucher_issuance_claim_json(
    claim: VoucherIssuanceClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _verify_base_voucher_payment(
    settings: ValidatorSettings,
    evidence: Mapping[str, Any],
    *,
    purchase: Any,
    voucher: Any,
) -> None:
    source = evidence.get("source")
    if not isinstance(source, Mapping):
        raise ValidatorEvidenceError("Base voucher has no chain provenance")
    if (
        not settings.base_sepolia_rpc_url
        or not settings.base_sepolia_spoke_address
        or not settings.base_sepolia_usdc_address
    ):
        raise ValidatorEvidenceError("Base Sepolia validator rail is not configured")
    spoke = settings.base_sepolia_spoke_address.lower()
    usdc = settings.base_sepolia_usdc_address.lower()
    expected_payer = "0x" + bytes(voucher.original_payer)[-20:].hex()
    expected = {
        "globalPaymentId": "0x" + bytes(voucher.global_payment_id).hex(),
        "purchaseId": "0x" + bytes(purchase.purchase_id).hex(),
        "artifactHash": "0x" + bytes(
            purchase.batch_hash
            if hasattr(purchase, "batch_hash")
            else purchase.artifact_hash
        ).hex(),
        "amount": int(voucher.payment_principal),
        "quantity": int(getattr(voucher, "quantity", 1)),
        "collectionId": "0x" + bytes(voucher.collection_id).hex(),
        "deedLauncherId": "0x" + bytes(voucher.deed_launcher_id).hex(),
        "vaultLauncherId": "0x" + bytes(voucher.approved_vault_launcher_id).hex(),
        "destinationPuzzle": "0x" + bytes(voucher.approved_vault_p2_puzzle_hash).hex(),
        "depositor": expected_payer,
        "settlementToken": usdc,
    }
    for field, expected_value in expected.items():
        observed = evidence.get(field)
        if isinstance(expected_value, str):
            observed = str(observed or "").lower()
        if observed != expected_value:
            raise ValidatorEvidenceError(
                f"Base voucher payment {field} does not match commitments"
            )
    if (
        int(source.get("chainId") or 0) != 84532
        or str(source.get("spoke") or "").lower() != spoke
        or int(source.get("confirmations") or 0)
        < settings.base_sepolia_min_confirmations
    ):
        raise ValidatorEvidenceError("Base voucher source route is invalid")

    # Quote and vault authorization must have been valid when funds were
    # deposited. Current reservation/series/owner checks remain in each signer.
    from .escrow_deposit import EscrowDepositError, verify_escrow_deposit
    try:
        purchase.assert_live(int(source["blockTimestamp"]))
        if int(evidence["quoteExpiresAt"]) != int(purchase.quote_expires_at):
            raise ValidatorEvidenceError("Base voucher quote expiry differs from purchase")
        verify_escrow_deposit(
            rpc_url=settings.base_sepolia_rpc_url, evidence=evidence,
            chain_id=84532, spoke=spoke, token=usdc,
            confirmations=settings.base_sepolia_min_confirmations, web3_factory=Web3,
        )
    except (EscrowDepositError, PaymentArtifactError, KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def verify_voucher_issuance_claim(
    settings: ValidatorSettings,
    claim: VoucherIssuanceClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "voucher claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash") or "").lower()
    ):
        raise ValidatorEvidenceError("voucher claim does not match active genesis")
    is_stripe = (
        claim.voucher_commitment.get("schema")
        == "solslot.voucher-commitment.v3"
    )
    try:
        terms = series_terms_from_json(claim.series_terms)
        if is_stripe:
            voucher = voucher_commitment_v3_from_json(
                claim.voucher_commitment
            )
            purchase = purchase_artifact_v3_from_json(
                claim.purchase_artifact
            )
            evidence = stripe_settlement_evidence_from_json(
                claim.payment_evidence
            )
            validator_pubkeys = tuple(
                bytes.fromhex(value.removeprefix("0x"))
                for value in settings.roster_pubkeys
            )
            receipt = build_stripe_settlement_receipt_v1(
                artifact=purchase,
                evidence=evidence,
                validator_pubkeys=validator_pubkeys,  # type: ignore[arg-type]
            )
            if (
                voucher.payment_rail != VoucherPaymentRailV3.STRIPE_USD
                or purchase.rail != PaymentRail.STRIPE
                or purchase.purchase_kind != PurchaseKind.PRESALE
            ):
                raise ValueError("Stripe voucher payment rail is inconsistent")
            authorization_time = evidence.observed_at
            validate_stripe_voucher_purchase(
                series=terms,
                voucher=voucher,
                artifact=purchase,
                receipt=receipt,
                expected_original_payer=stripe_original_payer(purchase),
                expected_smart_deed_inner_hash=bytes32(
                    load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
                ),
                now_seconds=authorization_time,
            )
        else:
            voucher = voucher_commitment_from_json(
                claim.voucher_commitment
            )
            purchase = voucher_purchase_from_json(claim.purchase_artifact)
            if voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC:
                validate_base_voucher_purchase(voucher, purchase, terms)
                payment_source = claim.payment_evidence.get("source")
                if not isinstance(payment_source, Mapping):
                    raise ValueError("voucher payment source is missing")
                authorization_time = int(
                    payment_source.get("blockTimestamp") or 0
                )
                if authorization_time <= 0:
                    raise ValueError(
                        "voucher payment confirmation time is missing"
                    )
            elif voucher.payment_rail == VoucherPaymentRail.CHIA_XCH:
                from .voucher_rail_policy import require_xch_voucher_issuance_release
                require_xch_voucher_issuance_release()
                authorization_time = int(time.time())
            else:
                raise ValueError("voucher payment rail is unsupported")
            purchase.assert_live(authorization_time)
            validate_purchase(
                series=terms,
                voucher=voucher,
                now_seconds=authorization_time,
            )
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        TypeError,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError("voucher issuance commitments are invalid") from exc
    raw_pubkeys = artifact.get("validatorSet", {}).get("pubkeys")
    treasury = artifact.get("puzzleHashes", {}).get("protocolTreasuryPuzzleHash")
    if (
        raw_pubkeys != settings.roster_pubkeys
        or tuple(bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys)
        != terms.validator_pubkeys
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
        or purchase.artifact_hash != voucher.purchase_artifact_hash
        or purchase.collection_id != voucher.collection_id
        or purchase.deed_launcher_id != voucher.deed_launcher_id
        or purchase.vault_launcher_id != voucher.approved_vault_launcher_id
        or purchase.vault_p2_puzzle_hash != voucher.approved_vault_p2_puzzle_hash
    ):
        raise ValidatorEvidenceError("voucher issuance differs from governed terms")

    series_record = _fetch_coin(settings, claim.series_coin_id, "voucher series coin")
    series_coin = _coin_from_record(series_record, "voucher series coin")
    if "0x" + bytes(series_coin.name()).hex() != claim.series_coin_id:
        raise ValidatorEvidenceError("voucher issuance coin IDs are not canonical")
    parent_record = _fetch_coin(
        settings,
        "0x" + bytes(series_coin.parent_coin_info).hex(),
        "voucher series parent",
        require_unspent=False,
    )
    parent_coin = _coin_from_record(parent_record, "voucher series parent")
    series_height = int(series_record.get("confirmed_block_index") or 0)
    parent_spent_height = int(parent_record.get("spent_block_index") or 0)
    if (
        parent_coin.name() != series_coin.parent_coin_info
        or parent_spent_height != series_height
    ):
        raise ValidatorEvidenceError(
            "voucher series parent did not create the current series coin"
        )
    parent_spend = _fetch_coin_spend(
        settings,
        parent_coin,
        parent_spent_height,
        "voucher series parent",
    )
    series_lineage = lineage_proof_for_coinsol(parent_spend)
    if is_stripe:
        purchase_record = _fetch_coin(
            settings,
            claim.purchase_launcher_coin_id,
            "Stripe voucher purchase launcher",
        )
        purchase_coin = _coin_from_record(
            purchase_record, "Stripe voucher purchase launcher"
        )
        if (
            "0x" + bytes(purchase_coin.name()).hex()
            != claim.purchase_launcher_coin_id
        ):
            raise ValidatorEvidenceError(
                "Stripe voucher purchase launcher ID is not canonical"
            )
        _verify_stripe_provider_evidence(
            settings,
            SimpleNamespace(
                stripe_evidence=claim.payment_evidence,
                purchase_artifact=claim.purchase_artifact,
            ),
        )
    elif voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC:
        if purchase.rail != PaymentRail.EVM_TEST_USD:
            raise ValidatorEvidenceError("Base voucher purchase rail is inconsistent")
        purchase_record = _fetch_coin(
            settings, claim.purchase_launcher_coin_id, "voucher purchase launcher"
        )
        purchase_coin = _coin_from_record(purchase_record, "voucher purchase launcher")
        if (
            "0x" + bytes(purchase_coin.name()).hex()
            != claim.purchase_launcher_coin_id
        ):
            raise ValidatorEvidenceError("voucher purchase launcher ID is not canonical")
        payment_puzzle = curry_external_receipt(terms=terms, voucher=voucher)
        payment_amount = 1
        _verify_base_voucher_payment(
            settings, claim.payment_evidence, purchase=purchase, voucher=voucher
        )
    elif voucher.payment_rail == VoucherPaymentRail.CHIA_XCH:
        if purchase.rail != PaymentRail.CHIA_XCH or claim.buyer_offer is None:
            raise ValidatorEvidenceError("native voucher offer evidence is missing")
        source = claim.payment_evidence.get("source")
        try:
            buyer_offer = Offer.from_bech32(claim.buyer_offer)
            purchase_coin = validate_xch_voucher_offer(
                buyer_offer=buyer_offer,
                terms=terms,
                state=state,
                series_coin=series_coin,
                voucher=voucher,
                purchase=purchase,
            )
            if (
                "0x" + bytes(purchase_coin.name()).hex()
                != claim.purchase_launcher_coin_id
                or not isinstance(source, Mapping)
                or source.get("chain") != "chia"
            ):
                raise ValueError("native voucher launcher evidence changed")
            payment_spends = buyer_offer.coin_spends()
            if len(payment_spends) != 1:
                raise ValueError("native voucher must use one payment coin")
            payment_coin = payment_spends[0].coin
            payment_coin_id = "0x" + bytes(payment_coin.name()).hex()
            if (
                str(source.get("paymentCoinId") or "").lower() != payment_coin_id
                or payment_coin.puzzle_hash != voucher.original_payer
            ):
                raise ValueError("native voucher payer evidence changed")
            payment_record = _fetch_coin(
                settings,
                payment_coin_id,
                "native voucher payment coin",
            )
            if _coin_from_record(payment_record, "native voucher payment coin") != payment_coin:
                raise ValueError("native voucher payment coin record changed")
            pairs: list[tuple[G1Element, bytes]] = []
            for spend in payment_spends:
                conditions = conditions_dict_for_solution(
                    spend.puzzle_reveal,
                    spend.solution,
                    INFINITE_COST,
                )
                pairs.extend(
                    pkm_pairs_for_conditions_dict(
                        conditions,
                        spend.coin,
                        AGG_SIG_ME_DATA[settings.network],
                    )
                )
            if not pairs or not AugSchemeMPL.aggregate_verify(
                [pair[0] for pair in pairs],
                [pair[1] for pair in pairs],
                buyer_offer.aggregated_signature(),
            ):
                raise ValueError("native voucher wallet signature is invalid")
        except (PaymentArtifactError, VoucherV2Error, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError("native voucher offer is invalid") from exc
        payment_puzzle = curry_xch_escrow(
            terms=terms,
            voucher=voucher,
            purchase=purchase,
        )
        payment_amount = int(voucher.payment_principal)
    else:
        raise ValidatorEvidenceError("voucher payment rail is unsupported")
    try:
        if is_stripe:
            issuance = build_stripe_voucher_issuance_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                artifact=purchase,
                receipt=receipt,
                expected_original_payer=stripe_original_payer(purchase),
                smart_deed_inner_hash=voucher.smart_deed_inner_hash,
                purchase_launcher_coin=purchase_coin,
                signer_indices=(0, 1),
            )
        else:
            issuance = build_voucher_issuance_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase_launcher_coin=purchase_coin,
                payment_puzzle=payment_puzzle,
                payment_amount=payment_amount,
                signer_indices=(0, 1),
            )
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError("voucher issuance bundle cannot be re-derived") from exc
    if "0x" + bytes(issuance.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError("voucher validator message changed on re-derivation")


def _voucher_payment_hold_binding(claim) -> tuple[str | None, str | None]:
    # Called only after the complete independent voucher verifier. Native/Base
    # artifacts have different commitments and cannot reinterpret a held V3 PI.
    if claim.voucher_commitment.get("schema") != "solslot.voucher-commitment.v3":
        if (claim.purchase_artifact.get('schema') == 'solslot.purchase-artifact.v3'
                and claim.voucher_commitment.get('paymentRail') == 1):
            purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
            return "0x"+bytes(purchase.purchase_id).hex(), claim.global_payment_id()
        return None, None
    purchase = purchase_artifact_v3_from_json(claim.purchase_artifact)
    evidence = stripe_settlement_evidence_from_json(claim.payment_evidence)
    return "0x" + bytes(purchase.purchase_id).hex(), evidence.payment_intent_id


def _retain_verified_base_hold_payment(settings, ledger, claim):
    # Runs after the full independent voucher verifier and before key access.
    purchase_id, payment_id = _voucher_payment_hold_binding(claim)
    if not purchase_id or not payment_id or not payment_id.startswith('0x'):
        return
    held = ledger.base_inventory_hold(purchase_id)
    artifact, _ = load_validator_artifact(settings)
    if held is None and 'baseInventoryHold' not in artifact:
        return  # Historical recovery does not invent a prepayment acknowledgment.
    try:
        from .base_inventory_hold import BaseInventoryHoldClaim, base_hold_coordinates
        if held is None:
            raise ValueError('Base payment has no original private hold')
        hold = BaseInventoryHoldClaim.model_validate_json(held['claim_json'])
        base_hold_coordinates(hold, artifact, settings.deployment_environment)
        if hold.purchase_artifact != claim.purchase_artifact:
            raise ValueError('Base payment changes the held purchase')
        ledger.retain_base_payment_start(purchase_id, claim.payment_evidence)
        if hold.activation['paymentConfirmationEnabled'] is not True:
            raise ValueError('Base lifecycle remains unavailable; retain this verified payment for recovery')
    except (ValueError, ValidatorLedgerConflict) as exc:
        raise ValidatorEvidenceError('Base payment start does not match its independent prepayment hold') from exc


def sign_voucher_issuance_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: VoucherIssuanceClaim,
    claim_hash: str,
) -> str:
    verify_voucher_issuance_claim(settings, claim, claim_hash)
    _retain_verified_base_hold_payment(settings, ledger, claim)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    purchase_id, payment_intent_id = _voucher_payment_hold_binding(claim)
    try:
        return ledger.record_voucher_issuance_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_voucher_issuance_claim_json(claim),
            global_payment_id=claim.global_payment_id(),
            series_coin_id=claim.series_coin_id,
            purchase_launcher_coin_id=claim.purchase_launcher_coin_id,
            signature=signature,
            purchase_id=purchase_id,
            payment_intent_id=payment_intent_id,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_voucher_series_phase_claim_json(
    claim: VoucherSeriesPhaseClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _verify_governed_deed_launchers(
    settings: ValidatorSettings,
    claim: VoucherSeriesPhaseClaim,
    terms: Any,
    artifact: Mapping[str, Any],
) -> None:
    raw_deeds = claim.series_terms.get("deeds")
    if not isinstance(raw_deeds, list) or len(raw_deeds) != terms.inventory_cap:
        raise ValidatorEvidenceError("series deed allocation evidence is incomplete")
    try:
        ordered = sorted(raw_deeds, key=lambda item: int(item["ordinal"]))
        if [int(item["ordinal"]) for item in ordered] != list(
            range(terms.inventory_cap)
        ):
            raise ValueError("deed ordinals are not contiguous")
        rows = tuple(
            DeedAllocationCommitmentV2(
                deed_id=bytes32.fromhex(
                    str(item["deedIdCanon"]).removeprefix("0x")
                ),
                share_ppm=int(item["sharePpm"]),
                par_value_mojos=int(item["parValueMojos"]),
                deed_launcher_id=bytes32.fromhex(
                    str(item["deedLauncherId"]).removeprefix("0x")
                ),
            )
            for item in ordered
        )
        if any(
            row.deed_id != canonicalise_property_id(str(item["deedId"]))
            for row, item in zip(rows, ordered, strict=True)
        ):
            raise ValueError("canonical deed ID changed")
    except (KeyError, TypeError, ValueError, VoucherV2Error) as exc:
        raise ValidatorEvidenceError("series deed allocation is malformed") from exc
    if allocation_root(rows) != terms.allocation_root:
        raise ValidatorEvidenceError("series deed allocation root changed")
    expected_launchers = [
        "0x" + bytes(row.deed_launcher_id).hex() for row in rows
    ]
    if claim.deed_launcher_ids != expected_launchers:
        raise ValidatorEvidenceError("governed deed launcher order changed")
    if len(claim.governed_deed_puzzle_hashes) != len(expected_launchers):
        raise ValidatorEvidenceError("governed deed puzzle evidence is incomplete")
    try:
        launchers = artifact.get("launcherIds")
        if not isinstance(launchers, Mapping):
            raise ValueError("launcher coordinates are unavailable")
        did_struct = singleton_struct(
            bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
        )
        expected_launcher_puzzle_hash = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=did_struct
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorEvidenceError(
            "signed artifact lacks the governed deed launcher coordinates"
        ) from exc

    for ordinal, launcher_id in enumerate(claim.deed_launcher_ids):
        record = _fetch_coin(
            settings,
            launcher_id,
            f"governed deed launcher {ordinal}",
            require_unspent=False,
        )
        launcher = _coin_from_record(record, f"governed deed launcher {ordinal}")
        spent_height = int(record.get("spent_block_index") or 0)
        if (
            "0x" + bytes(launcher.name()).hex() != launcher_id
            or launcher.puzzle_hash != expected_launcher_puzzle_hash
            or int(launcher.amount) != 1
            or spent_height <= 0
        ):
            raise ValidatorEvidenceError(
                f"governed deed launcher {ordinal} is not the DID-bound deployment launcher"
            )
        spend = _fetch_coin_spend(
            settings,
            launcher,
            spent_height,
            f"governed deed launcher {ordinal}",
        )
        additions = compute_additions(spend)
        if (
            len(additions) != 1
            or additions[0].parent_coin_info != launcher.name()
            or int(additions[0].amount) != 1
            or "0x" + bytes(additions[0].puzzle_hash).hex()
            != claim.governed_deed_puzzle_hashes[ordinal]
        ):
            raise ValidatorEvidenceError(
                f"governed deed launcher {ordinal} did not create the executed proposal child"
            )


def verify_voucher_series_phase_claim(
    settings: ValidatorSettings,
    claim: VoucherSeriesPhaseClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "series phase claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash") or "").lower()
    ):
        raise ValidatorEvidenceError("series phase does not match active genesis")
    try:
        terms = series_terms_from_json(claim.series_terms)
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        transition = SeriesTransition(claim.transition)
    except (TypeError, ValueError, VoucherV2Error) as exc:
        raise ValidatorEvidenceError("series phase commitments are invalid") from exc
    if state.phase != VoucherSeriesState.PRESALE or state.launched_at != 0:
        raise ValidatorEvidenceError("only a presale series can change phase")
    raw_pubkeys = artifact.get("validatorSet", {}).get("pubkeys")
    treasury = artifact.get("puzzleHashes", {}).get("protocolTreasuryPuzzleHash")
    if (
        raw_pubkeys != settings.roster_pubkeys
        or tuple(bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys)
        != terms.validator_pubkeys
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
    ):
        raise ValidatorEvidenceError("series phase trust coordinates changed")
    if transition == SeriesTransition.LAUNCH:
        if abs(int(time.time()) - claim.launch_anchor) > 90:
            raise ValidatorEvidenceError("series launch anchor is stale")
        _verify_governed_deed_launchers(settings, claim, terms, artifact)
    elif claim.deed_launcher_ids or claim.governed_deed_puzzle_hashes:
        raise ValidatorEvidenceError("series cancellation carried launch evidence")

    series_coin, lineage = _confirmed_coin_and_lineage(
        settings,
        claim.series_coin_id,
        "voucher series coin",
    )
    try:
        phase = build_voucher_series_phase_spend(
            terms=terms,
            state=state,
            series_coin=series_coin,
            series_lineage_proof=lineage,
            transition=transition,
            launch_anchor=claim.launch_anchor,
            signer_indices=(0, 1),
        )
    except (TypeError, ValueError, VoucherV2Error) as exc:
        raise ValidatorEvidenceError("series phase spend cannot be re-derived") from exc
    if "0x" + bytes(phase.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError(
            "series phase validator message changed on re-derivation"
        )


def sign_voucher_series_phase_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: VoucherSeriesPhaseClaim,
    claim_hash: str,
) -> str:
    verify_voucher_series_phase_claim(settings, claim, claim_hash)
    signature = "0x" + bytes(
        AugSchemeMPL.sign(
            load_validator_private_key(settings),
            claim.signature_message(),
        )
    ).hex()
    try:
        return ledger.record_voucher_series_phase_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_voucher_series_phase_claim_json(claim),
            series_coin_id=claim.series_coin_id,
            transition=claim.transition,
            signature=signature,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


def canonical_voucher_transition_claim_json(
    claim: VoucherTransitionClaim,
) -> str:
    return json.dumps(
        claim.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _confirmed_coin_and_lineage(
    settings: ValidatorSettings,
    coin_id: str,
    field: str,
) -> tuple[Coin, LineageProof]:
    record = _fetch_coin(settings, coin_id, field)
    coin = _coin_from_record(record, field)
    if "0x" + bytes(coin.name()).hex() != coin_id:
        raise ValidatorEvidenceError(f"{field} ID is not canonical")
    parent_id = "0x" + bytes(coin.parent_coin_info).hex()
    parent_record = _fetch_coin(
        settings,
        parent_id,
        f"{field} parent",
        require_unspent=False,
    )
    parent_coin = _coin_from_record(parent_record, f"{field} parent")
    child_height = int(record.get("confirmed_block_index") or 0)
    parent_spent_height = int(parent_record.get("spent_block_index") or 0)
    if parent_coin.name() != coin.parent_coin_info or parent_spent_height != child_height:
        raise ValidatorEvidenceError(f"{field} lineage is not atomic")
    parent_spend = _fetch_coin_spend(
        settings,
        parent_coin,
        parent_spent_height,
        f"{field} parent",
    )
    return coin, lineage_proof_for_coinsol(parent_spend)


def verify_voucher_transition_claim(
    settings: ValidatorSettings,
    claim: VoucherTransitionClaim,
    claim_hash: str,
) -> None:
    if claim.canonical_hash() != claim_hash.lower():
        raise ValidatorEvidenceError(
            "voucher transition claim hash does not match canonical evidence"
        )
    artifact, _release = load_validator_artifact(settings)
    if (
        claim.network != settings.network
        or claim.genesis_artifact_hash
        != str(artifact.get("artifactHash") or "").lower()
    ):
        raise ValidatorEvidenceError("voucher transition does not match active genesis")
    if abs(int(time.time()) - claim.current_timestamp) > settings.claim_clock_skew_seconds:
        raise ValidatorEvidenceError("voucher owner authorization timestamp is stale")
    is_stripe = (
        claim.voucher_commitment.get("schema")
        == "solslot.voucher-commitment.v3"
    )
    try:
        terms = series_terms_from_json(claim.series_terms)
        if is_stripe:
            voucher = voucher_commitment_v3_from_json(
                claim.voucher_commitment
            )
            purchase = purchase_artifact_v3_from_json(
                claim.purchase_artifact
            )
            if claim.payment_evidence is None:
                raise ValueError("Stripe terminal evidence is missing")
            stripe_evidence = stripe_settlement_evidence_from_json(
                claim.payment_evidence
            )
            receipt = build_stripe_settlement_receipt_v1(
                artifact=purchase,
                evidence=stripe_evidence,
                validator_pubkeys=tuple(
                    bytes.fromhex(value.removeprefix("0x"))
                    for value in settings.roster_pubkeys
                ),  # type: ignore[arg-type]
            )
        else:
            voucher = voucher_commitment_from_json(
                claim.voucher_commitment
            )
            purchase = voucher_purchase_from_json(
                claim.purchase_artifact
            )
        if not is_stripe and voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC:
            validate_base_voucher_purchase(voucher, purchase, terms)
        state = VoucherSeriesStateV2(
            sold_count=claim.series_sold_count,
            redeemed_count=claim.series_redeemed_count,
            refunded_count=claim.series_refunded_count,
            phase=VoucherSeriesState(claim.series_phase),
            launched_at=claim.series_launched_at,
        )
        action = VoucherAction(claim.action)
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        TypeError,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError("voucher transition commitments are invalid") from exc
    is_base = (
        not is_stripe
        and
        voucher.payment_rail == VoucherPaymentRail.BASE_SEPOLIA_USDC
        and purchase.rail == PaymentRail.EVM_TEST_USD
    )
    is_current_base = is_base and isinstance(purchase, PurchaseArtifactV3)
    if is_current_base and action == VoucherAction.REDEEM:
        if claim.reservation_expires_at is None or int(time.time()) >= claim.reservation_expires_at:
            raise ValidatorEvidenceError("Base voucher inventory reservation has expired or is missing")
        if (claim.smart_deed_inner_hash != "0x" + bytes(voucher.smart_deed_inner_hash).hex()
            or claim.vault_identity_attest_root != "0x" + bytes(purchase.zkpassport_root).hex()):
            raise ValidatorEvidenceError("Base voucher deed or credential differs from paid commitments")
    is_native = (
        not is_stripe
        and
        voucher.payment_rail == VoucherPaymentRail.CHIA_XCH
        and purchase.rail == PaymentRail.CHIA_XCH
    )
    if is_stripe and (
        voucher.payment_rail != VoucherPaymentRailV3.STRIPE_USD
        or purchase.rail != PaymentRail.STRIPE
        or purchase.purchase_kind != PurchaseKind.PRESALE
        or receipt.artifact != purchase
    ):
        raise ValidatorEvidenceError(
            "Stripe voucher transition payment rail is inconsistent"
        )
    if not is_base and not is_native and not is_stripe:
        raise ValidatorEvidenceError("voucher transition payment rail is inconsistent")
    if is_stripe:
        if (
            claim.external_settlement_evidence_hash is None
            or claim.external_validator_message is None
        ):
            raise ValidatorEvidenceError(
                "Stripe voucher transition has no authenticated payment evidence"
            )
        expected_evidence_hash = "0x" + bytes(
            stripe_evidence.evidence_hash
        ).hex()
        if claim.external_settlement_evidence_hash != expected_evidence_hash:
            raise ValidatorEvidenceError(
                "Stripe voucher settlement evidence hash changed"
            )
        expected_validator_message = stripe_voucher_evidence_message(
            terms=terms,
            voucher=voucher,
            artifact=purchase,
            action=action,
            terminal_evidence_hash=stripe_evidence.evidence_hash,
        )
        if claim.external_validator_message != "0x" + bytes(
            expected_validator_message
        ).hex():
            raise ValidatorEvidenceError(
                "Stripe voucher settlement validator message changed"
            )
        _verify_stripe_provider_evidence(
            settings,
            SimpleNamespace(
                stripe_evidence=claim.payment_evidence,
                purchase_artifact=claim.purchase_artifact,
            ),
        )
    elif is_base:
        if (
            claim.payment_evidence is None
            or claim.external_settlement_evidence_hash is None
            or claim.external_validator_message is None
        ):
            raise ValidatorEvidenceError(
                "Base voucher transition has no authenticated payment evidence"
            )
        expected_evidence_hash = base_settlement_evidence_hash(
            claim.payment_evidence
        )
        if claim.external_settlement_evidence_hash != expected_evidence_hash:
            raise ValidatorEvidenceError(
                "Base voucher settlement evidence hash changed"
            )
        try:
            expected_validator_message = external_receipt_evidence_message(
                voucher=voucher,
                action=action,
                external_settlement_evidence_hash=bytes32.fromhex(
                    expected_evidence_hash.removeprefix("0x")
                ),
            )
        except (TypeError, ValueError, VoucherV2Error) as exc:
            raise ValidatorEvidenceError(
                "Base voucher settlement message cannot be reconstructed"
            ) from exc
        if (
            claim.external_validator_message
            != "0x" + bytes(expected_validator_message).hex()
        ):
            raise ValidatorEvidenceError(
                "Base voucher settlement validator message changed"
            )
        _verify_base_voucher_payment(
            settings,
            claim.payment_evidence,
            purchase=purchase,
            voucher=voucher,
        )
    if (
        claim.vault_launcher_id
        != "0x" + bytes(voucher.approved_vault_launcher_id).hex()
        or purchase.artifact_hash != voucher.purchase_artifact_hash
    ):
        raise ValidatorEvidenceError("voucher transition vault or purchase binding changed")
    now = int(time.time())
    delivery_deadline = (
        state.launched_at + DELIVERY_WINDOW_SECONDS
        if state.phase == VoucherSeriesState.LIVE
        else 0
    )
    if action == VoucherAction.REFUND_PRESALE and now >= terms.refund_deadline:
        raise ValidatorEvidenceError("presale refund deadline has passed")
    if action == VoucherAction.REFUND_EXPIRED and now < delivery_deadline:
        raise ValidatorEvidenceError("voucher delivery window has not expired")
    if action == VoucherAction.REDEEM and now >= delivery_deadline:
        raise ValidatorEvidenceError("voucher delivery window has expired")

    raw_pubkeys = artifact.get("validatorSet", {}).get("pubkeys")
    treasury = artifact.get("puzzleHashes", {}).get("protocolTreasuryPuzzleHash")
    if (
        raw_pubkeys != settings.roster_pubkeys
        or tuple(bytes.fromhex(item.removeprefix("0x")) for item in raw_pubkeys)
        != terms.validator_pubkeys
        or str(treasury or "").lower()
        != "0x" + bytes(terms.trusted_protocol_treasury).hex()
    ):
        raise ValidatorEvidenceError("voucher transition trust coordinates changed")

    series_coin, series_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.series_coin_id,
        "voucher series coin",
    )
    voucher_coin, voucher_lineage = _confirmed_coin_and_lineage(
        settings,
        claim.voucher_coin_id,
        "voucher coin",
    )
    payment_record = _fetch_coin(settings, claim.payment_coin_id, "voucher payment coin")
    payment_coin = _coin_from_record(payment_record, "voucher payment coin")
    if "0x" + bytes(payment_coin.name()).hex() != claim.payment_coin_id:
        raise ValidatorEvidenceError("voucher payment coin ID is not canonical")
    if voucher_coin.parent_coin_info != bytes32.fromhex(
        claim.voucher_launcher_id.removeprefix("0x")
    ):
        raise ValidatorEvidenceError("voucher singleton launcher lineage changed")

    vault_coin_id = bytes32.zeros
    vault_inner_puzzle_hash = bytes32.zeros
    if action != VoucherAction.REFUND_EXPIRED:
        if (
            claim.vault_coin_id is None
            or claim.vault_identity_attest_root is None
            or claim.vault_owner_auth_type is None
            or claim.vault_owner_key is None
            or claim.vault_identity_attest_root
            == "0x" + bytes(DEFAULT_IDENTITY_ATTEST_ROOT).hex()
        ):
            raise ValidatorEvidenceError(
                "voucher transition has no current approved-vault evidence"
            )
        vault_coin, vault_lineage = _confirmed_coin_and_lineage(
            settings,
            claim.vault_coin_id,
            "approved vault coin",
        )
        try:
            owner_key = bytes.fromhex(claim.vault_owner_key.removeprefix("0x"))
            launcher = bytes32.fromhex(claim.vault_launcher_id.removeprefix("0x"))
            identity_root = bytes32.fromhex(
                claim.vault_identity_attest_root.removeprefix("0x")
            )
            pool_launcher = bytes32.fromhex(
                str(artifact["launcherIds"]["pool"]).removeprefix("0x")
            )
            bridge_policy_hash = bytes32.fromhex(
                str(artifact["bridgePolicy"]["policyHash"]).removeprefix("0x")
            )
            expected_vault = puzzle_for_vault_full(
                launcher,
                owner_key,
                claim.vault_owner_auth_type,
                one_leaf_merkle_root(owner_key),
                pool_launcher,
                identity_attest_root=identity_root,
                zkpassport_bridge_policy_hash=bridge_policy_hash,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "approved vault ownership evidence is malformed"
            ) from exc
        if (
            vault_coin.puzzle_hash != expected_vault.get_tree_hash()
            or int(vault_coin.amount) != 1
        ):
            raise ValidatorEvidenceError(
                "approved vault coin does not match its owner"
            )

    if action in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_CANCELED,
    }:
        try:
            owner_authorization = bytes.fromhex(
                claim.owner_authorization.removeprefix("0x")
            )
        except ValueError as exc:
            raise ValidatorEvidenceError(
                "voucher owner authorization is malformed"
            ) from exc
        signature_data: bytes | None = None
        if claim.vault_owner_auth_type == AUTH_TYPE_SECP256K1:
            typed_data = eip712_typed_data_for_vault_spend(
                b"i",
                bytes32.fromhex(claim.voucher_launcher_id.removeprefix("0x")),
                vault_coin.name(),
            )
            try:
                recovered = recover_evm_signer(
                    typed_data, claim.owner_authorization
                )
                if recovered.compressed_pubkey != owner_key:
                    raise ValueError(
                        "EVM signature does not belong to the vault owner"
                    )
                signature_data = compact_signature_from_evm(
                    claim.owner_authorization
                )
            except ValueError as exc:
                raise ValidatorEvidenceError(
                    "voucher EVM owner authorization is invalid"
                ) from exc
        vault_spend = build_vault_receive_spend(
            vault_coin=vault_coin,
            vault_launcher_id=launcher,
            owner_pubkey_bytes=owner_key,
            auth_type=claim.vault_owner_auth_type,
            members_merkle_root=one_leaf_merkle_root(owner_key),
            pool_launcher_id=pool_launcher,
            deed_launcher_id=bytes32.fromhex(
                claim.voucher_launcher_id.removeprefix("0x")
            ),
            p2_vault_coin_id=voucher_coin.name(),
            current_timestamp=claim.current_timestamp,
            lineage_proof=vault_lineage,
            signature_data=signature_data,
            identity_attest_root=identity_root,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        if claim.vault_owner_auth_type == AUTH_TYPE_BLS:
            try:
                signature = G2Element.from_bytes(owner_authorization)
                conditions = conditions_dict_for_solution(
                    vault_spend.puzzle_reveal,
                    vault_spend.solution,
                    INFINITE_COST,
                )
                pairs = pkm_pairs_for_conditions_dict(
                    conditions,
                    vault_spend.coin,
                    AGG_SIG_ME_DATA[settings.network],
                )
                if not pairs or not AugSchemeMPL.aggregate_verify(
                    [pair[0] for pair in pairs],
                    [pair[1] for pair in pairs],
                    signature,
                ):
                    raise ValueError(
                        "BLS signature does not authorize the vault spend"
                    )
            except ValueError as exc:
                raise ValidatorEvidenceError(
                    "voucher BLS owner authorization is invalid"
                ) from exc

        uncurried_vault = expected_vault.uncurry()
        if uncurried_vault is None:
            raise ValidatorEvidenceError(
                "approved vault puzzle is not a curried singleton"
            )
        try:
            vault_args = list(uncurried_vault[1].as_iter())
        except ValueError as exc:
            raise ValidatorEvidenceError(
                "approved vault curry arguments are malformed"
            ) from exc
        if len(vault_args) != 2:
            raise ValidatorEvidenceError(
                "approved vault singleton shape is invalid"
            )
        vault_coin_id = vault_coin.name()
        vault_inner_puzzle_hash = bytes32(vault_args[1].get_tree_hash())

    try:
        if is_stripe:
            assert claim.external_settlement_evidence_hash is not None
            transition = build_stripe_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                artifact=purchase,
                voucher_launcher_id=bytes32.fromhex(
                    claim.voucher_launcher_id.removeprefix("0x")
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                receipt_coin=payment_coin,
                vault_coin_id=(
                    vault_coin_id
                    if action
                    in {
                        VoucherAction.REFUND_PRESALE,
                        VoucherAction.REFUND_CANCELED,
                    }
                    else bytes32.zeros
                ),
                vault_inner_puzzle_hash=(
                    vault_inner_puzzle_hash
                    if action
                    in {
                        VoucherAction.REFUND_PRESALE,
                        VoucherAction.REFUND_CANCELED,
                    }
                    else bytes32.zeros
                ),
                action=action,
                terminal_evidence_hash=bytes32.fromhex(
                    claim.external_settlement_evidence_hash.removeprefix("0x")
                ),
                signer_indices=(0, 1),
            )
        elif is_base:
            assert claim.external_settlement_evidence_hash is not None
            transition = build_base_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase=purchase,
                voucher_launcher_id=bytes32.fromhex(
                    claim.voucher_launcher_id.removeprefix("0x")
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                receipt_coin=payment_coin,
                vault_coin_id=(
                    vault_coin_id
                    if action
                    in {
                        VoucherAction.REFUND_PRESALE,
                        VoucherAction.REFUND_CANCELED,
                    }
                    else bytes32.zeros
                ),
                vault_inner_puzzle_hash=(
                    vault_inner_puzzle_hash
                    if action
                    in {
                        VoucherAction.REFUND_PRESALE,
                        VoucherAction.REFUND_CANCELED,
                    }
                    else bytes32.zeros
                ),
                action=action,
                external_settlement_evidence_hash=bytes32.fromhex(
                    claim.external_settlement_evidence_hash.removeprefix("0x")
                ),
                signer_indices=(0, 1),
            )
        else:
            transition = build_xch_voucher_terminal_spends(
                terms=terms,
                state=state,
                series_coin=series_coin,
                series_lineage_proof=series_lineage,
                voucher=voucher,
                purchase=purchase,
                voucher_launcher_id=bytes32.fromhex(
                    claim.voucher_launcher_id.removeprefix("0x")
                ),
                voucher_coin=voucher_coin,
                voucher_lineage_proof=voucher_lineage,
                payment_coin=payment_coin,
                vault_coin_id=vault_coin_id,
                vault_inner_puzzle_hash=vault_inner_puzzle_hash,
                action=action,
                signer_indices=(0, 1),
            )
    except (
        PaymentArtifactError,
        VoucherV2Error,
        VoucherV3Error,
        TypeError,
        ValueError,
    ) as exc:
        raise ValidatorEvidenceError("voucher terminal spends cannot be re-derived") from exc
    if "0x" + bytes(transition.validator_message).hex() != claim.validator_message:
        raise ValidatorEvidenceError("voucher transition validator message changed")

    if action == VoucherAction.REDEEM:
        if not all(
            isinstance(value, str)
            for value in (
                claim.deed_coin_id,
                claim.deed_puzzle_hash,
                claim.smart_deed_inner_hash,
                claim.protocol_puzzle_hash,
                claim.buyer_offer,
            )
        ):
            raise ValidatorEvidenceError(
                "voucher redemption deed evidence is incomplete"
            )
        try:
            did_struct = singleton_struct(
                bytes32.fromhex(
                    str(artifact["launcherIds"]["did"]).removeprefix("0x")
                )
            )
            deed_struct = deed_singleton_struct(
                deed_launcher_id=purchase.deed_launcher_id,
                protocol_did_singleton_struct=did_struct,
            )
            if is_stripe or is_current_base:
                assert claim.reservation_expires_at is not None
                mint_terms = PrimaryMintTermsV3.for_artifact(
                    artifact=purchase,
                    smart_deed_inner_hash=bytes32.fromhex(
                        claim.smart_deed_inner_hash.removeprefix("0x")  # type: ignore[union-attr]
                    ),
                    deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(
                        protocol_did_singleton_struct=did_struct
                    ),
                    protocol_puzhash=bytes32.fromhex(
                        claim.protocol_puzzle_hash.removeprefix("0x")  # type: ignore[union-attr]
                    ),
                    validator_pubkeys=terms.validator_pubkeys,
                    provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
                )
                reservation = InventoryReservationV1(
                    artifact=purchase,
                    expires_at=claim.reservation_expires_at,
                )
                mint_terms = inventory_terms_for_puzzle_hash(
                    mint_terms, deed_struct, bytes32.fromhex(claim.deed_puzzle_hash.removeprefix("0x")),
                    reservation=reservation,
                )
                expected_deed_puzzle = SINGLETON_MOD.curry(
                    deed_struct,
                    make_mint_offer_v5_inner(mint_terms, reservation),
                )
            else:
                mint_terms = PrimaryMintTermsV2(
                    network=purchase.network,
                    smart_deed_inner_hash=bytes32.fromhex(
                        claim.smart_deed_inner_hash.removeprefix("0x")  # type: ignore[union-attr]
                    ),
                    deed_launcher_id=purchase.deed_launcher_id,
                    collection_id=purchase.collection_id,
                    metadata_root=purchase.metadata_root,
                    metadata_anchor_id=purchase.metadata_anchor_id,
                    share_ppm=purchase.share_ppm,
                    usd_amount_minor=purchase.usd_amount_minor,
                    protocol_puzhash=bytes32.fromhex(
                        claim.protocol_puzzle_hash.removeprefix("0x")  # type: ignore[union-attr]
                    ),
                    validator_pubkeys=terms.validator_pubkeys,
                    provider_id=PRIMARY_PURCHASE_PROVIDER_ID,
                )
                reservation = None
                expected_deed_puzzle = SINGLETON_MOD.curry(
                    deed_struct,
                    make_mint_offer_v4_inner(mint_terms),
                )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "voucher redemption mint terms cannot be reconstructed"
            ) from exc
        if (
            claim.protocol_puzzle_hash != str(treasury).lower()
            or claim.deed_puzzle_hash
            != "0x" + bytes(expected_deed_puzzle.get_tree_hash()).hex()
        ):
            raise ValidatorEvidenceError(
                "voucher redemption puzzle differs from governed mint"
            )
        deed_coin, deed_lineage = _confirmed_coin_and_lineage(
            settings,
            claim.deed_coin_id,  # type: ignore[arg-type]
            "voucher redemption SmartDeed coin",
        )
        if (
            (not (is_stripe or is_current_base) and deed_coin.parent_coin_info != purchase.deed_launcher_id)
            or deed_coin.puzzle_hash != expected_deed_puzzle.get_tree_hash()
            or int(deed_coin.amount) != 1
        ):
            raise ValidatorEvidenceError(
                "voucher redemption SmartDeed is not the governed coin"
            )
        try:
            expected_buyer_offer = (
                prepare_stripe_voucher_redemption_offer(
                    terminal=transition,
                    receipt_coin=payment_coin,
                    artifact=purchase,
                    terms=mint_terms,
                    deed_singleton_struct=deed_struct,
                )
                if is_stripe
                else prepare_base_voucher_redemption_offer_v5(
                    terminal=transition, receipt_coin=payment_coin, artifact=purchase,
                    terms=mint_terms, deed_singleton_struct=deed_struct,
                )
                if is_current_base
                else prepare_base_voucher_redemption_offer(
                    terminal_coin_spends=transition.coin_spends,
                    receipt_coin=payment_coin,
                    artifact=purchase,
                    terms=mint_terms,
                )
                if is_base
                else prepare_xch_voucher_redemption_offer(
                    terminal_coin_spends=transition.coin_spends,
                    payment_coin=payment_coin,
                    artifact=purchase,
                    terms=mint_terms,
                )
            )
            claimed_buyer_offer = Offer.from_bech32(
                claim.buyer_offer  # type: ignore[arg-type]
            )
            if (
                claimed_buyer_offer.aggregated_signature() != G2Element()
                or claimed_buyer_offer.to_bech32()
                != expected_buyer_offer.to_bech32()
            ):
                raise ValueError("voucher buyer offer differs from terminal spends")
            primary = (
                build_stripe_voucher_primary_offer_v5(
                    voucher_offer=claimed_buyer_offer,
                    terminal=transition,
                    receipt_coin=payment_coin,
                    receipt=receipt,
                    deed_coin=deed_coin,
                    deed_singleton_struct=deed_struct,
                    lineage_proof=deed_lineage,
                    signer_indices=(0, 1),
                    terms=mint_terms,
                    reservation=reservation,
                )
                if is_stripe
                else build_base_voucher_primary_offer_v5(
                    voucher_offer=claimed_buyer_offer, terminal=transition,
                    receipt_coin=payment_coin, artifact=purchase, deed_coin=deed_coin,
                    deed_singleton_struct=deed_struct, lineage_proof=deed_lineage,
                    signer_indices=(0, 1), terms=mint_terms, reservation=reservation,
                )
                if is_current_base
                else build_universal_primary_offer_v4(
                    buyer_offer=claimed_buyer_offer,
                    deed_coin=deed_coin,
                    deed_singleton_struct=deed_struct,
                    lineage_proof=deed_lineage,
                    artifact=purchase,
                    signer_indices=(0, 1),
                    terms=mint_terms,
                    purchase_mode=PrimaryPurchaseMode.VOUCHER,
                    voucher_coin_id=voucher_coin.name(),
                    voucher_transition_message=transition.validator_message,
                    external_receipt_coin=payment_coin,
                    external_settlement_evidence_hash=bytes32.fromhex(
                        claim.external_settlement_evidence_hash.removeprefix("0x")  # type: ignore[union-attr]
                    ),
                )
                if is_base
                else build_universal_primary_offer_v4(
                    buyer_offer=claimed_buyer_offer,
                    deed_coin=deed_coin,
                    deed_singleton_struct=deed_struct,
                    lineage_proof=deed_lineage,
                    artifact=purchase,
                    signer_indices=(0, 1),
                    terms=mint_terms,
                    purchase_mode=PrimaryPurchaseMode.VOUCHER,
                    voucher_coin_id=voucher_coin.name(),
                    voucher_transition_message=transition.validator_message,
                )
            )
            if not primary.aggregate_offer.is_valid():
                raise ValueError("voucher redemption offer does not balance")
        except (PaymentArtifactError, TypeError, ValueError) as exc:
            raise ValidatorEvidenceError(
                "voucher redemption offer cannot be re-derived"
            ) from exc


def sign_voucher_transition_claim(
    settings: ValidatorSettings,
    ledger: ValidatorLedger,
    claim: VoucherTransitionClaim,
    claim_hash: str,
) -> str:
    verify_voucher_transition_claim(settings, claim, claim_hash)
    _retain_verified_base_hold_payment(settings, ledger, claim)
    private_key = load_validator_private_key(settings)
    signature = "0x" + bytes(
        AugSchemeMPL.aggregate(
            [
                AugSchemeMPL.sign(private_key, message)
                for message in claim.signature_messages()
            ]
        )
    ).hex()
    purchase_id, payment_intent_id = _voucher_payment_hold_binding(claim)
    try:
        return ledger.record_voucher_transition_or_recover(
            claim_hash=claim_hash.lower(),
            canonical_claim=canonical_voucher_transition_claim_json(claim),
            global_payment_id=claim.global_payment_id(),
            series_coin_id=claim.series_coin_id,
            voucher_coin_id=claim.voucher_coin_id,
            payment_coin_id=claim.payment_coin_id,
            deed_coin_id=claim.deed_coin_id,
            signature=signature,
            purchase_id=purchase_id,
            payment_intent_id=payment_intent_id,
        )
    except ValidatorLedgerConflict as exc:
        raise ValidatorEvidenceError(str(exc)) from exc


__all__ = [
    "ValidatorEvidenceError",
    "canonical_claim_json",
    "canonical_primary_purchase_claim_json",
    "canonical_stripe_settlement_claim_json",
    "canonical_voucher_issuance_claim_json",
    "canonical_voucher_transition_claim_json",
    "load_validator_artifact",
    "load_validator_private_key",
    "load_stripe_restricted_key",
    "sign_validator_claim",
    "sign_primary_purchase_claim",
    "sign_stripe_settlement_claim",
    "sign_voucher_issuance_claim",
    "sign_voucher_transition_claim",
    "verify_validator_claim",
    "verify_primary_purchase_claim",
    "verify_stripe_settlement_claim",
    "verify_voucher_issuance_claim",
    "verify_voucher_transition_claim",
]
