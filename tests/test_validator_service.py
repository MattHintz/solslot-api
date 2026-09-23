from __future__ import annotations

import hashlib
import time
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data

from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.release_metadata import ReleaseMetadata
from solslot_api.validator_quorum import ValidatorClaim
from solslot_api.validator_service import (
    ValidatorEvidenceError,
    _fetch_coin,
    _verify_bridge_coin,
    _verify_vault_and_owner,
    verify_validator_claim,
)
from solslot_api.validator_settings import ValidatorSettings
from solslot_api.zkpassport_enrollments import IndexedEvmAttestation
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    eip712_typed_data_for_vault_spend,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
)
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash


def _settings() -> ValidatorSettings:
    validators = [AugSchemeMPL.key_gen(bytes([index]) * 32) for index in (41, 42, 43)]
    pubkeys = ["0x" + bytes(key.get_g1()).hex() for key in validators]
    policy = make_bridge_policy_hash([bytes(key.get_g1()) for key in validators], 2)
    return ValidatorSettings(
        signer_index=0,
        seed_file="/unread-in-this-test",
        evm_rpc_url="https://sepolia.example.invalid",
        bridge_policy_hash="0x" + bytes(policy).hex(),
        roster_pubkeys=pubkeys,
        evm_forwarder_address="0x" + "11" * 20,
        evm_verifier_adapter_address="0x" + "22" * 20,
        evm_attestation_emitter_address="0x" + "33" * 20,
    )


def _claim(
    settings: ValidatorSettings,
    *,
    coin: Coin,
    owner_key: str,
    owner_auth_type: int,
    owner_authorization: str,
    launcher: bytes32,
    identity_root: bytes32,
    bridge_parent: bytes32 | None = None,
) -> ValidatorClaim:
    authorization = bytes.fromhex(owner_authorization.removeprefix("0x"))
    parent = bridge_parent or bytes32(b"b" * 32)
    bridge_coin = Coin(
        parent,
        bytes32.fromhex(settings.bridge_policy_hash.removeprefix("0x")),
        uint64(1),
    )
    return ValidatorClaim(
        network="testnet11",
        artifact_hash="0x" + "a1" * 32,
        vault_launcher_id="0x" + bytes(launcher).hex(),
        current_vault_coin_id="0x" + bytes(coin.name()).hex(),
        owner_key=owner_key,
        owner_auth_type=owner_auth_type,
        owner_authorization=owner_authorization,
        owner_authorization_hash="0x" + hashlib.sha256(authorization).hexdigest(),
        current_timestamp=int(time.time()),
        evm_transaction_hash="0x" + "e1" * 32,
        evm_block_number=123,
        emitter_address=settings.evm_attestation_emitter_address,
        policy_version=2,
        identity_attest_root="0x" + bytes(identity_root).hex(),
        attestation_leaf_hash="0x" + "a2" * 32,
        scoped_nullifier="0x" + "a3" * 32,
        nullifier_type=1,
        service_scope_hash="0x" + "a4" * 32,
        service_subscope_hash="0x" + "a5" * 32,
        proof_timestamp=int(time.time()) - 30,
        bridge_policy_hash=settings.bridge_policy_hash,
        bridge_parent_id="0x" + bytes(parent).hex(),
        bridge_amount=1,
        bridge_coin_id="0x" + bytes(bridge_coin.name()).hex(),
        validator_message="0x" + "a6" * 32,
    )


def _coin_record(coin: Coin, *, spent: bool = False) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + bytes(coin.parent_coin_info).hex(),
            "puzzle_hash": "0x" + bytes(coin.puzzle_hash).hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": 100,
        "spent": spent,
        "spent_block_index": 101 if spent else 0,
    }


def _artifact(pool_launcher: bytes32, claim: ValidatorClaim) -> dict:
    return {
        "artifactHash": claim.artifact_hash,
        "launcherIds": {"pool": "0x" + bytes(pool_launcher).hex()},
        "bridgePolicy": {
            "policyHash": claim.bridge_policy_hash,
            "parentCoinIds": [claim.bridge_parent_id],
            "bridgeCoinIds": [claim.bridge_coin_id],
        },
    }


def test_evm_owner_signature_reconstructs_current_unstamped_vault(monkeypatch) -> None:
    settings = _settings()
    launcher = bytes32(b"l" * 32)
    pool_launcher = bytes32(b"p" * 32)
    identity_root = bytes32(b"i" * 32)
    account = Account.from_key(bytes.fromhex("44" * 32))
    provisional = Coin(launcher, bytes32(b"x" * 32), uint64(1))
    typed_data = eip712_typed_data_for_vault_spend(
        b"z", identity_root, provisional.name()
    )

    # The typed data must bind the final coin ID, so derive a stable coin first.
    from solslot_api.evm_auth import recover_evm_signer

    provisional_signature = account.sign_message(
        encode_typed_data(full_message=typed_data)
    ).signature
    recovered = recover_evm_signer(typed_data, "0x" + provisional_signature.hex())
    puzzle = puzzle_for_vault_full(
        launcher,
        recovered.compressed_pubkey,
        AUTH_TYPE_SECP256K1,
        one_leaf_merkle_root(recovered.compressed_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            settings.bridge_policy_hash.removeprefix("0x")
        ),
    )
    coin = Coin(launcher, bytes32(puzzle.get_tree_hash()), uint64(1))
    typed_data = eip712_typed_data_for_vault_spend(b"z", identity_root, coin.name())
    signature = account.sign_message(encode_typed_data(full_message=typed_data)).signature
    claim = _claim(
        settings,
        coin=coin,
        owner_key=account.address,
        owner_auth_type=AUTH_TYPE_SECP256K1,
        owner_authorization="0x" + signature.hex(),
        launcher=launcher,
        identity_root=identity_root,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_coin",
        lambda *_args, **_kwargs: _coin_record(coin),
    )

    _verify_vault_and_owner(settings, _artifact(pool_launcher, claim), claim)


def test_evm_authorization_for_another_owner_cannot_reconstruct_vault(monkeypatch) -> None:
    settings = _settings()
    launcher = bytes32(b"l" * 32)
    pool_launcher = bytes32(b"p" * 32)
    identity_root = bytes32(b"i" * 32)
    original = Account.from_key(bytes.fromhex("45" * 32))
    other = Account.from_key(bytes.fromhex("46" * 32))
    from solslot_api.evm_auth import recover_evm_signer

    placeholder = Coin(launcher, bytes32(b"x" * 32), uint64(1))
    seed_typed = eip712_typed_data_for_vault_spend(b"z", identity_root, placeholder.name())
    seed_sig = original.sign_message(encode_typed_data(full_message=seed_typed)).signature
    owner = recover_evm_signer(seed_typed, "0x" + seed_sig.hex())
    puzzle = puzzle_for_vault_full(
        launcher,
        owner.compressed_pubkey,
        AUTH_TYPE_SECP256K1,
        one_leaf_merkle_root(owner.compressed_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            settings.bridge_policy_hash.removeprefix("0x")
        ),
    )
    coin = Coin(launcher, bytes32(puzzle.get_tree_hash()), uint64(1))
    typed_data = eip712_typed_data_for_vault_spend(b"z", identity_root, coin.name())
    signature = other.sign_message(encode_typed_data(full_message=typed_data)).signature
    claim = _claim(
        settings,
        coin=coin,
        owner_key=other.address,
        owner_auth_type=AUTH_TYPE_SECP256K1,
        owner_authorization="0x" + signature.hex(),
        launcher=launcher,
        identity_root=identity_root,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_coin",
        lambda *_args, **_kwargs: _coin_record(coin),
    )

    with pytest.raises(ValidatorEvidenceError, match="does not reconstruct"):
        _verify_vault_and_owner(settings, _artifact(pool_launcher, claim), claim)


def test_bls_owner_signature_reconstructs_current_unstamped_vault(monkeypatch) -> None:
    settings = _settings()
    launcher = bytes32(b"l" * 32)
    pool_launcher = bytes32(b"p" * 32)
    identity_root = bytes32(b"i" * 32)
    owner_private_key = AugSchemeMPL.key_gen(bytes.fromhex("47" * 32))
    owner_pubkey = bytes(owner_private_key.get_g1())
    puzzle = puzzle_for_vault_full(
        launcher,
        owner_pubkey,
        AUTH_TYPE_BLS,
        one_leaf_merkle_root(owner_pubkey),
        pool_launcher,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bytes32.fromhex(
            settings.bridge_policy_hash.removeprefix("0x")
        ),
    )
    coin = Coin(launcher, bytes32(puzzle.get_tree_hash()), uint64(1))
    inner_message = bytes(Program.to([b"z", identity_root, coin.name()]).get_tree_hash())
    signature = AugSchemeMPL.sign(
        owner_private_key,
        inner_message + bytes(coin.name()) + AGG_SIG_ME_DATA[settings.network],
    )
    claim = _claim(
        settings,
        coin=coin,
        owner_key="0x" + owner_pubkey.hex(),
        owner_auth_type=AUTH_TYPE_BLS,
        owner_authorization="0x" + bytes(signature).hex(),
        launcher=launcher,
        identity_root=identity_root,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_coin",
        lambda *_args, **_kwargs: _coin_record(coin),
    )

    _verify_vault_and_owner(settings, _artifact(pool_launcher, claim), claim)


def test_owner_check_rejects_stale_action_before_coin_lookup(monkeypatch) -> None:
    settings = _settings()
    coin = Coin(bytes32(b"l" * 32), bytes32(b"p" * 32), uint64(1))
    claim = _claim(
        settings,
        coin=coin,
        owner_key="0x" + "11" * 20,
        owner_auth_type=AUTH_TYPE_SECP256K1,
        owner_authorization="0x" + "22" * 65,
        launcher=coin.parent_coin_info,
        identity_root=bytes32(b"i" * 32),
    ).model_copy(update={"current_timestamp": int(time.time()) - 301})
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_coin",
        lambda *_args, **_kwargs: pytest.fail("stale claim reached Coinset"),
    )

    with pytest.raises(ValidatorEvidenceError, match="timestamp"):
        _verify_vault_and_owner(settings, {"launcherIds": {"pool": "0x" + "33" * 32}}, claim)


def test_bridge_coin_must_be_committed_and_match_lineage(monkeypatch) -> None:
    settings = _settings()
    parent = bytes32(b"b" * 32)
    policy = bytes32.fromhex(settings.bridge_policy_hash.removeprefix("0x"))
    bridge_coin = Coin(parent, policy, uint64(1))
    vault_coin = Coin(bytes32(b"l" * 32), bytes32(b"v" * 32), uint64(1))
    claim = _claim(
        settings,
        coin=vault_coin,
        owner_key="0x" + "11" * 20,
        owner_auth_type=AUTH_TYPE_SECP256K1,
        owner_authorization="0x" + "22" * 65,
        launcher=vault_coin.parent_coin_info,
        identity_root=bytes32(b"i" * 32),
        bridge_parent=parent,
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_coin",
        lambda *_args, **_kwargs: _coin_record(bridge_coin),
    )
    artifact = _artifact(bytes32(b"p" * 32), claim)
    _verify_bridge_coin(settings, artifact, claim)

    artifact["bridgePolicy"]["parentCoinIds"] = []
    with pytest.raises(ValidatorEvidenceError, match="not committed"):
        _verify_bridge_coin(settings, artifact, claim)


def test_coinset_record_must_be_confirmed_and_unspent(monkeypatch) -> None:
    settings = _settings()
    coin = Coin(bytes32(b"p" * 32), bytes32(b"h" * 32), uint64(1))

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"coin_record": _coin_record(coin, spent=True)}

    class Client:
        def __init__(self, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def post(self, *_args, **_kwargs) -> Response:
            return Response()

    monkeypatch.setattr("solslot_api.validator_service.httpx.Client", Client)
    with pytest.raises(ValidatorEvidenceError, match="already spent"):
        _fetch_coin(settings, "0x" + bytes(coin.name()).hex(), "bridge coin")


def _event_for_claim(claim: ValidatorClaim) -> IndexedEvmAttestation:
    return IndexedEvmAttestation(
        sender=claim.owner_key,
        vault_launcher_id=claim.vault_launcher_id,
        scoped_nullifier=claim.scoped_nullifier,
        nullifier_type=claim.nullifier_type,
        service_scope_hash=claim.service_scope_hash,
        service_subscope_hash=claim.service_subscope_hash,
        proof_timestamp=claim.proof_timestamp,
        attestation_leaf_hash=claim.attestation_leaf_hash,
        identity_attest_root=claim.identity_attest_root,
        bridge_parent_id=claim.bridge_parent_id,
        bridge_amount=claim.bridge_amount,
        bridge_coin_id=claim.bridge_coin_id,
        bridge_message="0x" + "b1" * 32,
        bridge_policy_hash=claim.bridge_policy_hash,
        policy_version=claim.policy_version,
        validator_message=claim.validator_message,
        transaction_hash=claim.evm_transaction_hash,
        block_number=claim.evm_block_number,
    )


def test_signer_rejects_event_mismatch_zero_scope_and_stale_proof(monkeypatch) -> None:
    settings = _settings()
    launcher = bytes32(b"l" * 32)
    coin = Coin(launcher, bytes32(b"v" * 32), uint64(1))
    claim = _claim(
        settings,
        coin=coin,
        owner_key="0x" + "11" * 20,
        owner_auth_type=AUTH_TYPE_SECP256K1,
        owner_authorization="0x" + "22" * 65,
        launcher=launcher,
        identity_root=bytes32(b"i" * 32),
    )
    artifact = _artifact(bytes32(b"p" * 32), claim)
    release = ReleaseMetadata(
        apiCommit="a" * 40,
        protocolCommit="b" * 40,
        builtAtUtc="2026-07-14T00:00:00Z",
        packageName="solslot-api",
        appModule="solslot_api.app:app",
    )
    monkeypatch.setattr(
        "solslot_api.validator_service.load_validator_artifact",
        lambda _settings: (artifact, release),
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._verify_vault_and_owner", lambda *_args: None
    )
    monkeypatch.setattr(
        "solslot_api.validator_service._verify_bridge_coin", lambda *_args: None
    )
    event = _event_for_claim(claim)
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_verified_evm_attestation",
        lambda *_args, **_kwargs: replace(event, identity_attest_root="0x" + "ff" * 32),
    )
    with pytest.raises(ValidatorEvidenceError, match="identity_attest_root"):
        verify_validator_claim(settings, claim, claim.canonical_hash())

    zero_scope = claim.model_copy(update={"service_scope_hash": "0x" + "00" * 32})
    zero_event = _event_for_claim(zero_scope)
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_verified_evm_attestation",
        lambda *_args, **_kwargs: zero_event,
    )
    with pytest.raises(ValidatorEvidenceError, match="scope commitments"):
        verify_validator_claim(settings, zero_scope, zero_scope.canonical_hash())

    stale = claim.model_copy(
        update={"proof_timestamp": int(time.time()) - settings.proof_max_age_seconds - 1}
    )
    stale_event = _event_for_claim(stale)
    monkeypatch.setattr(
        "solslot_api.validator_service._fetch_verified_evm_attestation",
        lambda *_args, **_kwargs: stale_event,
    )
    with pytest.raises(ValidatorEvidenceError, match="proof timestamp"):
        verify_validator_claim(settings, stale, stale.canonical_hash())


def test_signer_rejects_wrong_claim_hash_artifact_and_emitter(monkeypatch) -> None:
    settings = _settings()
    launcher = bytes32(b"l" * 32)
    coin = Coin(launcher, bytes32(b"v" * 32), uint64(1))
    claim = _claim(
        settings,
        coin=coin,
        owner_key="0x" + "11" * 20,
        owner_auth_type=AUTH_TYPE_SECP256K1,
        owner_authorization="0x" + "22" * 65,
        launcher=launcher,
        identity_root=bytes32(b"i" * 32),
    )
    with pytest.raises(ValidatorEvidenceError, match="claim hash"):
        verify_validator_claim(settings, claim, "0x" + "00" * 32)

    artifact = _artifact(bytes32(b"p" * 32), claim)
    artifact["artifactHash"] = "0x" + "ff" * 32
    release = ReleaseMetadata(
        apiCommit="a" * 40,
        protocolCommit="b" * 40,
        builtAtUtc="2026-07-14T00:00:00Z",
        packageName="solslot-api",
        appModule="solslot_api.app:app",
    )
    monkeypatch.setattr(
        "solslot_api.validator_service.load_validator_artifact",
        lambda _settings: (artifact, release),
    )
    with pytest.raises(ValidatorEvidenceError, match="active signed artifact"):
        verify_validator_claim(settings, claim, claim.canonical_hash())

    artifact["artifactHash"] = claim.artifact_hash
    wrong_emitter = claim.model_copy(update={"emitter_address": "0x" + "ff" * 20})
    with pytest.raises(ValidatorEvidenceError, match="signed attestation emitter"):
        verify_validator_claim(settings, wrong_emitter, wrong_emitter.canonical_hash())


def test_receipt_adapter_preserves_all_signed_evm_bindings(monkeypatch, tmp_path) -> None:
    from solslot_api.validator_service import _coordinator_settings
    from solslot_api.public_artifact import _verify_runtime_bindings, PublicArtifactError

    settings = _settings().model_copy(update={"release_metadata_path": str(tmp_path / "absent.json")})
    artifact = {
        "network": "testnet11", "evmChainId": settings.evm_chain_id,
        "launcherIds": {"pool": "0x" + "11" * 32},
        "bridgePolicy": {"policyHash": settings.bridge_policy_hash, "policyVersion": 2},
        "validatorSet": {"threshold": 2, "pubkeys": settings.roster_pubkeys},
        "evmAddresses": {"forwarder": settings.evm_forwarder_address,
            "verifierAdapter": settings.evm_verifier_adapter_address,
            "attestationEmitter": settings.evm_attestation_emitter_address},
    }
    # The adapter must pass the signer config explicitly, even if a conflicting
    # coordinator-style environment variable is inherited by the process.
    monkeypatch.setenv("SOLSLOT_ZKPASSPORT_VERIFIER_ADAPTER_ADDRESS", "0x" + "ff" * 20)
    adapted = _coordinator_settings(settings, artifact)
    _verify_runtime_bindings(adapted, artifact)
    for field in ("zkpassport_forwarder_address", "zkpassport_verifier_adapter_address", "zkpassport_emitter_address"):
        with pytest.raises(PublicArtifactError, match="does not match signed artifact"):
            _verify_runtime_bindings(adapted.model_copy(update={field: "0x" + "ee" * 20}), artifact)
