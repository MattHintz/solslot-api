from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from eth_utils import keccak

import solslot_api.genesis as genesis_module
import solslot_api.genesis_store as genesis_store_module
from solslot_api.config import Settings, get_settings
from solslot_api.genesis import get_genesis_store, router
from solslot_api.genesis_store import GenesisConflict, GenesisStore


ADMIN_TOKEN = "test-ceremony-operator-token"
SOURCE_NAMES = (
    "protocol",
    "evm",
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
    "customerWeb",
    "adminPortal",
)


def test_global_finalization_lock_rejects_a_concurrent_writer(tmp_path) -> None:
    lock_path = tmp_path / "bootstrap-lock.json"

    with genesis_module._exclusive_finalization_lock(lock_path):
        with pytest.raises(GenesisConflict, match="already active"):
            with genesis_module._exclusive_finalization_lock(lock_path):
                pass


def _source_shas() -> dict[str, str]:
    return {
        name: f"{index:x}" * 40
        for index, name in enumerate(SOURCE_NAMES, start=1)
    }


def _signature(account, typed_data: dict) -> str:
    signed = account.sign_message(encode_typed_data(full_message=typed_data))
    return "0x" + bytes(signed.signature).hex()


def _client(tmp_path) -> tuple[TestClient, GenesisStore, Settings]:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        minting_enabled=False,
        ceremony_mode_enabled=True,
        admin_token=ADMIN_TOKEN,
        genesis_db_path=str(tmp_path / "genesis.db"),
        genesis_output_dir=str(tmp_path / "ceremonies"),
        genesis_audit_approval_path=str(tmp_path / "approval.json"),
        public_artifact_path=str(tmp_path / "public-artifact.json"),
        bootstrap_manifest_path=str(tmp_path / "bootstrap-lock.json"),
        cors_origins="",
    )
    store = GenesisStore(settings.genesis_db_path)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_genesis_store] = lambda: store
    return TestClient(app), store, settings


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _open_broadcast_gate(store: GenesisStore, ceremony_id: str, settings) -> None:
    from tests.launch_authority_fixtures import open_signed_gate
    now = int(time.time())
    open_signed_gate(
        store, settings, ceremony_id, "ceremonyBroadcast",
        opens_at=now - 60,
        closes_at=now + 3600,
        payload_hash="0x" + "ef" * 32,
        now=now,
    )


def _install_recovery_kits(
    store: GenesisStore,
    ceremony_id: str,
) -> None:
    for slot in (1, 2, 3):
        recovery_key = AugSchemeMPL.key_gen(bytes([slot + 40]) * 32)
        recovery_pubkey = bytes(recovery_key.get_g1())
        challenge_hash = "0x" + bytes([slot + 60] * 32).hex()
        challenge_id = "0x" + bytes([slot + 70] * 32).hex()
        store.create_recovery_drill(
            ceremony_id,
            challenge_id=challenge_id,
            slot=slot,
            challenge_hash=challenge_hash,
            public_payload={
                "revision": 1,
                "evmGuardian": "0x"
                + bytes([slot + 80] * 20).hex(),
                "recoveryBlsPubkey": "0x" + recovery_pubkey.hex(),
                "recoveryBlsCommitment": "0x"
                + keccak(recovery_pubkey).hex(),
            },
            expires_at=2_000_000_000,
            now=1_900_000_000,
        )
        store.complete_recovery_drill(
            challenge_id,
            expected_challenge_hash=challenge_hash,
            backup_status="NOT_CONFIGURED",
            backup_revision=None,
            backup_ciphertext_hash=None,
            now=1_900_000_001,
        )


def _create_and_enroll(
    client: TestClient,
    store: GenesisStore,
) -> tuple[str, list]:
    commits = _source_shas()
    response = client.post(
        "/admin/genesis/drafts",
        json={
            "sourceShas": commits,
            "reviewClass": "internal-engineering-testnet",
        },
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    ceremony_id = response.json()["ceremony_id"]
    assert response.json()["draft"]["reviewClass"] == "internal-engineering-testnet"
    assert response.json()["draft"]["sourceManifestVersion"] == 4
    accounts = [Account.create(f"admin-{slot}") for slot in (1, 2, 3)]
    for slot, account in enumerate(accounts, start=1):
        issued = client.post(
            f"/admin/genesis/{ceremony_id}/invitations/{slot}",
            headers=_headers(),
        )
        assert issued.status_code == 200, issued.text
        token = issued.json()["invitationFragment"].split("=", 1)[1]
        prepared = client.post(
            "/admin/genesis/invitations/prepare",
            json={"token": token, "wallet": account.address},
        )
        assert prepared.status_code == 200, prepared.text
        accepted = client.post(
            "/admin/genesis/invitations/accept",
            json={
                "token": token,
                "wallet": account.address,
                "signature": _signature(account, prepared.json()["typedData"]),
            },
        )
        assert accepted.status_code == 200, accepted.text
    frozen = client.post(
        f"/admin/genesis/{ceremony_id}/roster/freeze", headers=_headers()
    )
    assert frozen.status_code == 200, frozen.text
    assert frozen.json()["state"] == "roster_frozen"
    _install_recovery_kits(store, ceremony_id)
    return ceremony_id, accounts


def _plan_body() -> dict:
    funding_names = (
        "sgt",
        "pool",
        "did",
        "governance",
        "statutes",
        "protocolConfig",
        "adminAuthority",
        "vaultVersionRegistry",
        "bridgeBatch",
    )
    validators = [
        bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1()).hex()
        for index in (21, 22, 23)
    ]
    governance = bytes(AugSchemeMPL.key_gen(b"g" * 32).get_g1()).hex()
    kos_mint_execute = bytes(AugSchemeMPL.key_gen(b"k" * 32).get_g1()).hex()
    return {
        "evmAddresses": {
            "forwarder": "0x" + "a1" * 20,
            "verifierAdapter": "0x" + "a2" * 20,
            "attestationEmitter": "0x" + "a3" * 20,
        },
        "fundingCoinIds": {
            name: "0x" + f"{index:02x}" * 32
            for index, name in enumerate(funding_names, start=1)
        },
        "faucetPuzzleHash": "0x" + "31" * 32,
        "governanceBlsPubkey": "0x" + governance,
        "kosMintExecutePubkey": "0x" + kos_mint_execute,
        "validatorPubkeys": ["0x" + value for value in validators],
        "trustedTreasuryReservePuzzleHash": "0x" + "41" * 32,
        "trustedProtocolTreasuryPuzzleHash": "0x" + "42" * 32,
        "companySgtSaleTreasuryPuzzleHash": "0x" + "45" * 32,
        "wusdcBAssetId": "0x" + "46" * 32,
        "trustedGovernanceRewardsPuzzleHash": "0x" + "43" * 32,
        "trustedGovernanceRewardsRoot": "0x" + "44" * 32,
        "retiredCoordinates": ["0x" + "51" * 32],
        "protocolParameters": {
            "votingWindowSeconds": 300,
            "quorumBps": 5000,
            "minProposalStake": 10_000,
            "navValiditySeconds": 86_400,
            "oracleMaxAgeSeconds": 600,
            "exchangeFeeBps": 100,
            "protocolFeeBps": 30,
            "sgtRewardsFeeBps": 70,
            "rewardEpochSeconds": 86_400,
        },
    }


def _approve_plan(
    client: TestClient,
    ceremony_id: str,
    accounts: list,
) -> None:
    created = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=_plan_body(),
        headers=_headers(),
    )
    assert created.status_code == 200, created.text
    typed_data = created.json()["typedData"]
    assert typed_data["primaryType"] == "SolslotGenesisPlan"
    for slot, account in enumerate(accounts[:2], start=1):
        prepared = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures/prepare",
            json={"slot": slot},
        )
        assert prepared.status_code == 200, prepared.text
        assert prepared.json()["typedData"] == typed_data
        assert prepared.json()["slot"] == slot
        signed = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures",
            json={
                "slot": slot,
                "signature": _signature(account, prepared.json()["typedData"]),
            },
        )
        assert signed.status_code == 200, signed.text


def _stub_deterministic_plan_worker(monkeypatch) -> None:
    async def fake_worker(payload: dict) -> dict:
        if payload["operation"] == "roster":
            return {
                "adminsHash": "0x" + "90" * 32,
                "mipsRootHash": "0x" + "91" * 32,
            }
        assert payload["operation"] == "plan"
        ceremony = payload["ceremony"]
        plan_input = payload["planInput"]
        plan = {
            "schema": "solslot-genesis-plan-test",
            "ceremonyId": ceremony["ceremony_id"],
            "network": "testnet11",
            "expiresAt": payload["expiresAt"],
            "sourceShas": ceremony["draft"]["sourceShas"],
            "evmAddresses": plan_input["evmAddresses"],
            "fundingCoinIds": plan_input["fundingCoinIds"],
            "launcherIds": {
                "adminAuthority": "0x" + "92" * 32,
                "adminIdentity0": "0x" + "93" * 32,
                "adminIdentity1": "0x" + "94" * 32,
                "adminIdentity2": "0x" + "95" * 32,
            },
            "adminAuthority": {
                "adminsHash": ceremony["roster_hash"],
                "sourceManifestHash": "0x" + "96" * 32,
            },
            "adminRecoveryKits": plan_input["adminRecoveryKits"],
        }
        encoded = json.dumps(
            plan, sort_keys=True, separators=(",", ":")
        ).encode()
        plan_hash = "0x" + hashlib.sha256(encoded).hexdigest()
        plan["planHash"] = plan_hash
        return {"plan": plan, "planHash": plan_hash}

    monkeypatch.setattr(genesis_module, "_run_worker", fake_worker)


def _expired_approved_store(tmp_path) -> tuple[GenesisStore, Settings, str]:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
        minting_enabled=False,
        ceremony_mode_enabled=True,
        admin_token=ADMIN_TOKEN,
        genesis_db_path=str(tmp_path / "renew-genesis.db"),
        genesis_output_dir=str(tmp_path / "renew-ceremonies"),
        public_artifact_path=str(tmp_path / "renew-public-artifact.json"),
        bootstrap_manifest_path=str(tmp_path / "renew-bootstrap-lock.json"),
        cors_origins="",
    )
    store = GenesisStore(settings.genesis_db_path)
    ceremony_id = "0x" + "80" * 32
    source_shas = _source_shas()
    store.create_draft(ceremony_id, {"sourceShas": source_shas}, now=100)
    for slot in (1, 2, 3):
        token_hash = f"renew-token-{slot}"
        store.issue_invitation(
            ceremony_id,
            slot=slot,
            token_hash=token_hash,
            nonce=f"renew-nonce-{slot}",
            expires_at=1000,
            now=101,
        )
        store.consume_invitation(
            token_hash=token_hash,
            wallet_address="0x" + f"{slot:02x}" * 20,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=102,
        )
    roster_hash = "0x" + "90" * 32
    store.freeze_roster(ceremony_id, roster_hash, now=103)
    plan_input = {
        "evmAddresses": _plan_body()["evmAddresses"],
        "fundingCoinIds": _plan_body()["fundingCoinIds"],
        "adminRecoveryKits": [],
    }
    plan_hash = "0x" + "81" * 32
    plan = {
        "schema": "solslot-genesis-plan-test",
        "ceremonyId": ceremony_id,
        "network": "testnet11",
        "expiresAt": 1000,
        "sourceShas": source_shas,
        "evmAddresses": plan_input["evmAddresses"],
        "fundingCoinIds": plan_input["fundingCoinIds"],
        "launcherIds": {
            "adminAuthority": "0x" + "92" * 32,
            "adminIdentity0": "0x" + "93" * 32,
            "adminIdentity1": "0x" + "94" * 32,
            "adminIdentity2": "0x" + "95" * 32,
        },
        "adminAuthority": {
            "adminsHash": roster_hash,
            "sourceManifestHash": "0x" + "96" * 32,
        },
        "adminRecoveryKits": [],
        "planHash": plan_hash,
    }
    store.set_plan(
        ceremony_id,
        plan_input=plan_input,
        plan=plan,
        plan_hash=plan_hash,
        expires_at=1000,
        now=104,
    )
    for slot in (1, 2):
        store.add_plan_signature(
            ceremony_id,
            slot=slot,
            plan_hash=plan_hash,
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
            now=105 + slot,
        )
    return store, settings, ceremony_id


def _direct_broadcast_fixture(tmp_path, monkeypatch, label: str):
    store, settings, ceremony_id = _expired_approved_store(tmp_path)
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET plan_expires_at=? WHERE ceremony_id=?",
            (int(time.time()) + 3600, ceremony_id),
        )
    _open_broadcast_gate(store, ceremony_id, settings)
    review_receipt = b'{"review":"authority-v3"}\n'
    review_path = tmp_path / f"{label}-authority-v3-review.json"
    review_path.write_bytes(review_receipt)
    review_sha256 = hashlib.sha256(review_receipt).hexdigest()
    settings.authority_v3_independent_review_path = str(review_path)
    settings.authority_v3_independent_review_sha256 = review_sha256
    protocol_bundle = {
        "coin_spends": [{"coin": {"amount": 530}}],
        "aggregated_signature": "0xc0",
    }
    prepared_bundle = {
        "coin_spends": [
            *protocol_bundle["coin_spends"],
            {"coin": {"amount": 100}},
        ],
        "aggregated_signature": "0xc1",
    }

    async def fake_prepare_bundle(_settings, record):
        return (
            record["plan"],
            {
                "spendBundleId": "0x" + "aa" * 32,
                "spendCount": 49,
                "spendBundle": protocol_bundle,
            },
            {
                "reviewClass": "internal-engineering-testnet",
                "authorityV3Review": {
                    "fileSha256": "0x" + review_sha256,
                },
            },
            (),
        )

    class PreparedBundle:
        spend_bundle_id = "0x" + "bb" * 32
        fee_coin_id = "0x" + "cc" * 32
        fee_mojos = 7

        def to_json(self):
            return {
                "spendBundleId": self.spend_bundle_id,
                "feeMojos": "7",
                "feeCoinId": self.fee_coin_id,
                "spendBundle": prepared_bundle,
            }

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    return (
        store,
        settings,
        ceremony_id,
        protocol_bundle,
        prepared_bundle,
        PreparedBundle,
    )


def _confirmation_fixture(tmp_path, monkeypatch, *, reserved: bool):
    store, settings, ceremony_id = _expired_approved_store(tmp_path)
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET plan_expires_at=? WHERE ceremony_id=?",
            (int(time.time()) + 3600, ceremony_id),
        )
    coins = (
        Coin(bytes32(b"\x01" * 32), bytes32(b"\x11" * 32), uint64(100)),
        Coin(bytes32(b"\x02" * 32), bytes32(b"\x12" * 32), uint64(100)),
    )
    spends = [
        make_spend(
            coin,
            Program.to((1, [[51, bytes32(bytes([index + 40]) * 32), 100]])),
            Program.to(0),
        )
        for index, coin in enumerate(coins)
    ]
    bundle = SpendBundle(spends, G2Element())
    bundle_id = "0x" + bundle.name().hex()
    input_ids = ["0x" + coin.name().hex() for coin in coins]
    output_ids = ["0x" + "71" * 32, "0x" + "72" * 32]
    evidence = {
        "auditApproval": {"approved": True},
        "authorityV3ReviewBase64": "e30K",
        "validatorHealth": {"checkedAt": 100, "signers": []},
    }
    store.reserve_broadcast(
        ceremony_id,
        expected_plan_hash=str(store.get(ceremony_id)["plan_hash"]),
        spend_bundle_id=bundle_id,
        spend_bundle=bundle.to_json_dict(),
        fee_coin_id=input_ids[0],
        fee_mojos=7,
        ceremony_evidence=evidence,
        now=int(time.time()),
    )
    if not reserved:
        store.mark_broadcast(
            ceremony_id,
            spend_bundle_id=bundle_id,
            response={
                "schemaVersion": 1,
                "status": "MEMPOOL",
                "network": "testnet11",
                "spendBundleId": bundle_id,
                "feeMojos": "7",
                "feeCoinId": input_ids[0],
                "spendBundle": bundle.to_json_dict(),
                "submissionProvider": "local-full-node",
            },
            now=int(time.time()),
        )

    class ExactPrimaryProvider:
        def __init__(self) -> None:
            self.input_heights = {coin_id: 500 for coin_id in input_ids}
            self.output_heights = {coin_id: 500 for coin_id in output_ids}
            self.solution_overrides: dict[str, str] = {}
            self.peak = 502

        async def get_coin_record_by_name_primary(self, coin_id: str):
            if coin_id in self.input_heights:
                coin = coins[input_ids.index(coin_id)]
                return {
                    "coin": coin.to_json_dict(),
                    "confirmed_block_index": 100,
                    "spent_block_index": self.input_heights[coin_id],
                    "spent": True,
                }
            if coin_id in self.output_heights:
                return {
                    "confirmed_block_index": self.output_heights[coin_id],
                    "spent_block_index": 0,
                    "spent": False,
                }
            return None

        async def get_puzzle_and_solution_primary(
            self, coin_id: str, height: int
        ):
            spend = spends[input_ids.index(coin_id)]
            return {
                "puzzle_reveal": "0x" + bytes(spend.puzzle_reveal).hex(),
                "solution": self.solution_overrides.get(
                    coin_id, "0x" + bytes(spend.solution).hex()
                ),
            }

        async def get_blockchain_state_primary(self):
            return {"blockchain_state": {"peak": {"height": self.peak}}}

    provider = ExactPrimaryProvider()

    async def fake_worker(_payload):
        record = store.get(ceremony_id)
        return {
            "plan": record["plan"],
            "planHash": record["plan_hash"],
            "coinIds": output_ids,
        }

    monkeypatch.setattr(genesis_module, "_coinset", lambda: provider)
    monkeypatch.setattr(genesis_module, "_run_worker", fake_worker)
    return (
        store,
        settings,
        ceremony_id,
        provider,
        input_ids,
        output_ids,
    )


async def _finalization_fixture(tmp_path, monkeypatch):
    store, settings, ceremony_id, _provider, _inputs, _outputs = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=False)
    )
    await genesis_module.confirm(ceremony_id, settings, store)
    artifact = {
        "schemaVersion": 4,
        "sourceManifestVersion": 4,
        "protocolVersion": "solslot-v2-rc23",
        "reviewClass": "internal-engineering-testnet",
        "testOnly": True,
        "auditStatus": "unaudited",
        "artifactHash": "0x" + "a5" * 32,
    }
    store.set_artifact(
        ceremony_id,
        artifact=artifact,
        artifact_hash=artifact["artifactHash"],
        now=600,
    )
    enrolled = {
        int(item["slot"]): item for item in store.get(ceremony_id)["invitations"]
    }
    for slot in (1, 2):
        store.add_artifact_signature(
            ceremony_id,
            slot=slot,
            artifact_hash=artifact["artifactHash"],
            compressed_pubkey=str(enrolled[slot]["compressed_pubkey"]),
            signature="0x" + f"{slot:02x}" * 65,
            now=600 + slot,
        )
    signed_artifact = {
        **artifact,
        "signatures": [
            {
                "adminIndex": slot - 1,
                "compressedPubkey": str(enrolled[slot]["compressed_pubkey"]),
                "signature": "0x" + f"{slot:02x}" * 65,
            }
            for slot in (1, 2)
        ],
    }
    settings.public_artifact_path = str(tmp_path / "public-artifact.json")
    settings.bootstrap_manifest_path = str(tmp_path / "bootstrap-lock.json")
    return store, settings, ceremony_id, signed_artifact


def test_three_admin_http_flow_reaches_plan_approval(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client, store)
    _approve_plan(client, ceremony_id, accounts)
    final = store.get(ceremony_id)
    assert final["state"] == "plan_approved"
    assert len(final["plan_signatures"]) == 2
    assert final["plan"]["schema"] == "solslot-genesis-plan-v4"
    assert final["plan"]["protocolVersion"] == "solslot-v2-rc23"
    assert len(final["plan"]["adminRecoveryKits"]) == 3
    assert "statutes" in final["plan"]["launcherIds"]
    assert "navRegistry" not in final["plan"]["launcherIds"]
    assert final["plan"]["bridgeBatch"]["fundingAmount"] == 530


@pytest.mark.asyncio
async def test_expired_plan_renews_exact_bindings_and_clears_signatures(
    tmp_path, monkeypatch
) -> None:
    _stub_deterministic_plan_worker(monkeypatch)
    store, settings, ceremony_id = _expired_approved_store(tmp_path)
    before = store.get(ceremony_id)

    response = await genesis_module.renew_plan(
        ceremony_id,
        settings,
        store,
    )

    assert response["ceremony"]["state"] == "planned"
    renewed = store.get(ceremony_id)
    assert renewed["state"] == "planned"
    assert renewed["plan_hash"] != before["plan_hash"]
    assert renewed["plan_signatures"] == []
    assert renewed["plan_input"] == before["plan_input"]
    before_binding = {
        key: value
        for key, value in before["plan"].items()
        if key not in {"expiresAt", "planHash"}
    }
    renewed_binding = {
        key: value
        for key, value in renewed["plan"].items()
        if key not in {"expiresAt", "planHash"}
    }
    assert renewed_binding == before_binding
    for slot in (1, 2):
        store.add_plan_signature(
            ceremony_id,
            slot=slot,
            plan_hash=str(renewed["plan_hash"]),
            compressed_pubkey="0x" + f"{slot:02x}" * 33,
            signature="0x" + f"{slot:02x}" * 65,
        )
    assert store.get(ceremony_id)["state"] == "plan_approved"


@pytest.mark.asyncio
async def test_expired_plan_never_reaches_preflight_or_submitter(
    tmp_path, monkeypatch
) -> None:
    store, settings, ceremony_id = _expired_approved_store(tmp_path)

    async def forbidden_prepare(*_args, **_kwargs):
        raise AssertionError("expired plan reached bundle preparation")

    class ForbiddenSubmitter:
        async def submit(self, _bundle):
            raise AssertionError("expired plan reached chain submitter")

    monkeypatch.setattr(genesis_module, "_prepare_bundle", forbidden_prepare)
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(protocol_submitter=ForbiddenSubmitter())
        )
    )

    with pytest.raises(HTTPException) as preflight_error:
        await genesis_module.preflight(ceremony_id, settings, store)
    with pytest.raises(HTTPException) as broadcast_error:
        await genesis_module.broadcast(ceremony_id, request, settings, store)

    assert preflight_error.value.status_code == 410
    assert "expired" in str(preflight_error.value.detail)
    assert broadcast_error.value.status_code == 410
    assert "expired" in str(broadcast_error.value.detail)


def test_plan_rejects_retired_nav_registry_and_rc21_parameters(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, _ = _create_and_enroll(client, store)
    body = _plan_body()
    body["fundingCoinIds"]["navRegistry"] = body["fundingCoinIds"].pop(
        "statutes"
    )
    body["protocolParameters"]["minNavRegistryVersion"] = 1

    response = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=body,
        headers=_headers(),
    )

    assert response.status_code == 422
    assert "statutes" in response.text
    assert "navRegistry" in response.text


@pytest.mark.asyncio
async def test_broadcast_reserves_exact_prepared_bundle_before_provider_push(
    tmp_path,
    monkeypatch,
) -> None:
    (
        store,
        settings,
        ceremony_id,
        protocol_bundle,
        prepared_bundle,
        PreparedBundle,
    ) = _direct_broadcast_fixture(tmp_path, monkeypatch, "reserved-before-push")

    class RecordingSubmitter:
        pushed = False
        reserved_before_push = False

        async def submit(self, bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            assert bundle == protocol_bundle
            assert store.get(ceremony_id)["state"] == "plan_approved"
            prepared = PreparedBundle()
            before_push(prepared)
            reservation = store.get(ceremony_id)["broadcast"]
            self.reserved_before_push = (
                reservation["reservationState"] == "RESERVED"
                and reservation["spendBundleId"] == prepared.spend_bundle_id
                and reservation["spendBundle"] == prepared_bundle
                and reservation["feeCoinId"] == prepared.fee_coin_id
            )
            self.pushed = True
            return {
                "schemaVersion": 1,
                "status": "MEMPOOL",
                "network": "testnet11",
                **prepared.to_json(),
                "submissionProvider": "local-full-node",
                "mempoolObservedAt": "2026-08-22T12:00:00+00:00",
            }

    submitter = RecordingSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=submitter))
    )

    result = await genesis_module._broadcast_ceremony(
        ceremony_id,
        request,
        settings,
        store,
        gate_authorization=None,
    )

    persisted = store.get(ceremony_id)
    assert submitter.reserved_before_push is True
    assert submitter.pushed is True
    assert result["state"] == "broadcast"
    assert persisted["broadcast"]["reservationState"] == "FINALIZED"
    assert persisted["broadcast"]["spendBundle"] == prepared_bundle


@pytest.mark.parametrize(
    "target_setting",
    ("public_artifact_path", "bootstrap_manifest_path"),
)
@pytest.mark.asyncio
async def test_fresh_broadcast_rejects_existing_global_finalization_target(
    tmp_path,
    monkeypatch,
    target_setting,
) -> None:
    store, settings, ceremony_id, *_unused = _direct_broadcast_fixture(
        tmp_path,
        monkeypatch,
        "global-finalization-target",
    )
    Path(getattr(settings, target_setting)).write_text(
        "stale\n",
        encoding="ascii",
    )

    class ForbiddenSubmitter:
        async def submit(self, *_args, **_kwargs):
            raise AssertionError("unsafe finalization path reached provider push")

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(protocol_submitter=ForbiddenSubmitter())
        )
    )

    with pytest.raises(GenesisConflict, match="target must not exist"):
        await genesis_module._broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=None,
        )

    assert store.get(ceremony_id)["state"] == "plan_approved"


@pytest.mark.asyncio
async def test_finalization_target_is_rechecked_at_provider_push_boundary(
    tmp_path,
    monkeypatch,
) -> None:
    (
        store,
        settings,
        ceremony_id,
        _protocol_bundle,
        _prepared_bundle,
        PreparedBundle,
    ) = _direct_broadcast_fixture(tmp_path, monkeypatch, "target-boundary-race")

    class RacingSubmitter:
        callback_invoked = False
        pushed = False

        async def submit(self, _bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            Path(settings.public_artifact_path).write_text(
                "raced\n",
                encoding="ascii",
            )
            self.callback_invoked = True
            before_push(PreparedBundle())
            self.pushed = True
            raise AssertionError("unsafe finalization target reached provider push")

    submitter = RacingSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=submitter))
    )

    with pytest.raises(GenesisConflict, match="target must not exist"):
        await genesis_module._broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=None,
        )

    assert submitter.callback_invoked is True
    assert submitter.pushed is False
    assert store.get(ceremony_id)["state"] == "plan_approved"


@pytest.mark.asyncio
async def test_ambiguous_push_retains_exact_reserved_bundle_for_reconciliation(
    tmp_path,
    monkeypatch,
) -> None:
    (
        store,
        settings,
        ceremony_id,
        _protocol_bundle,
        prepared_bundle,
        PreparedBundle,
    ) = _direct_broadcast_fixture(tmp_path, monkeypatch, "ambiguous-push")

    class AmbiguousSubmitter:
        push_attempted = False

        async def submit(self, _bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            prepared = PreparedBundle()
            before_push(prepared)
            self.push_attempted = True
            raise genesis_module.ProtocolSubmissionError(
                "local mempool result is unknown",
                submission_attempted=True,
            )

    submitter = AmbiguousSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=submitter))
    )

    with pytest.raises(HTTPException) as error:
        await genesis_module.broadcast(ceremony_id, request, settings, store)

    persisted = store.get(ceremony_id)
    assert error.value.status_code == 409
    assert "remains reserved for reconciliation" in str(error.value.detail)
    assert submitter.push_attempted is True
    assert persisted["state"] == "broadcast"
    assert persisted["broadcast"]["reservationState"] == "RESERVED"
    assert persisted["broadcast"]["spendBundle"] == prepared_bundle


@pytest.mark.asyncio
async def test_reserved_replay_rechecks_gate_inside_submitter_boundary(
    tmp_path,
    monkeypatch,
) -> None:
    (
        store,
        settings,
        ceremony_id,
        _protocol_bundle,
        prepared_bundle,
        PreparedBundle,
    ) = _direct_broadcast_fixture(tmp_path, monkeypatch, "replay-gate")
    prepared = PreparedBundle()
    now = int(time.time())
    closes_at = now + 60
    from tests.launch_authority_fixtures import open_signed_gate
    open_signed_gate(
        store, settings, ceremony_id, "ceremonyBroadcast",
        opens_at=now - 60,
        closes_at=closes_at,
        payload_hash="0x" + "ef" * 32,
        now=now,
    )
    gate_authorization = genesis_module._ceremony_broadcast_gate_authorization(
        settings, store, ceremony_id
    )
    store.reserve_broadcast(
        ceremony_id,
        expected_plan_hash=str(store.get(ceremony_id)["plan_hash"]),
        spend_bundle_id=prepared.spend_bundle_id,
        spend_bundle=prepared_bundle,
        fee_coin_id=prepared.fee_coin_id,
        fee_mojos=prepared.fee_mojos,
        ceremony_evidence={
            "auditApproval": {"approved": True},
            "authorityV3ReviewBase64": "e30K",
            "validatorHealth": {"checkedAt": now, "signers": []},
        },
        gate_authorization=gate_authorization,
        now=now,
    )

    class ClosingReplaySubmitter:
        callback_invoked = False
        pushed = False

        async def reconcile_reserved(self, _reservation, *, before_push):
            self.callback_invoked = True
            monkeypatch.setattr(
                genesis_store_module.time,
                "time",
                lambda: closes_at,
            )
            before_push()
            self.pushed = True
            raise AssertionError("exact replay must not run after gate close")

    submitter = ClosingReplaySubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=submitter))
    )

    with pytest.raises(GenesisConflict, match="gate is closed"):
        await genesis_module._broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=gate_authorization,
        )

    persisted = store.get(ceremony_id)
    assert submitter.callback_invoked is True
    assert submitter.pushed is False
    assert persisted["state"] == "broadcast"
    assert persisted["broadcast"]["reservationState"] == "RESERVED"


@pytest.mark.asyncio
async def test_reserved_replay_rejects_stale_finalization_target_before_push(
    tmp_path,
    monkeypatch,
) -> None:
    (
        store,
        settings,
        ceremony_id,
        _protocol_bundle,
        _prepared_bundle,
        PreparedBundle,
    ) = _direct_broadcast_fixture(tmp_path, monkeypatch, "replay-target")
    gate_authorization = genesis_module._ceremony_broadcast_gate_authorization(
        settings,
        store,
        ceremony_id,
    )

    class AmbiguousSubmitter:
        async def submit(self, _bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            before_push(PreparedBundle())
            raise genesis_module.ProtocolSubmissionError(
                "unknown provider result",
                submission_attempted=True,
            )

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(protocol_submitter=AmbiguousSubmitter())
        )
    )
    with pytest.raises(GenesisConflict, match="remains reserved for reconciliation"):
        await genesis_module._broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=gate_authorization,
        )
    assert store.get(ceremony_id)["broadcast"]["reservationState"] == "RESERVED"

    Path(settings.bootstrap_manifest_path).write_text(
        "stale\n",
        encoding="ascii",
    )

    class ForbiddenReplaySubmitter:
        async def reconcile_reserved(self, *_args, **_kwargs):
            raise AssertionError("stale target reached exact provider replay")

    request.app.state.protocol_submitter = ForbiddenReplaySubmitter()
    with pytest.raises(GenesisConflict, match="target must not exist"):
        await genesis_module._broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=gate_authorization,
        )

    assert store.get(ceremony_id)["broadcast"]["reservationState"] == "RESERVED"


@pytest.mark.asyncio
async def test_finalized_broadcast_rematerializes_without_new_signed_gate(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, _provider, _inputs, _outputs = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=False)
    )
    now = int(time.time())
    store.upsert_gate(
        ceremony_id,
        gate_name="ceremonyBroadcast",
        opens_at=now - 120,
        closes_at=now - 60,
        payload_hash="0x" + "ef" * 32,
        state="closed",
        now=now,
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))

    result = await genesis_module.broadcast(
        ceremony_id,
        request,
        settings,
        store,
    )

    assert result["state"] == "broadcast"
    output = (
        tmp_path / "renew-ceremonies" / ceremony_id.removeprefix("0x")
    )
    assert (output / "spend_bundle.json").is_file()


@pytest.mark.asyncio
async def test_confirmation_proves_every_exact_reserved_spend_and_output(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, _provider, input_ids, output_ids = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=False)
    )

    result = await genesis_module.confirm(ceremony_id, settings, store)

    persisted = store.get(ceremony_id)
    evidence = persisted["broadcast"]["chainConfirmation"]
    assert result["state"] == "confirmed"
    assert evidence["exactReservedCoinSpends"] is True
    assert evidence["inputCoinIds"] == sorted(input_ids)
    assert evidence["outputCoinIds"] == output_ids
    assert evidence["confirmedBlockIndex"] == 500
    assert evidence["confirmations"] == 3
    assert evidence["source"] == "exact-mempool-receipt-and-chain"
    output = (
        tmp_path / "renew-ceremonies" / ceremony_id.removeprefix("0x")
    )
    assert json.loads(
        (output / "chain_confirmation.json").read_text(encoding="utf-8")
    ) == evidence


@pytest.mark.asyncio
async def test_confirmation_rejects_changed_solution_and_preserves_broadcast(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, provider, input_ids, _output_ids = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=False)
    )
    provider.solution_overrides[input_ids[1]] = "0x01"

    with pytest.raises(HTTPException) as error:
        await genesis_module.confirm(ceremony_id, settings, store)

    assert error.value.status_code == 409
    assert "differs from the reserved spend" in str(error.value.detail)
    assert store.get(ceremony_id)["state"] == "broadcast"


@pytest.mark.asyncio
async def test_confirmation_rejects_bundle_bytes_changed_under_stored_id(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, _provider, _input_ids, _output_ids = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=False)
    )
    record = store.get(ceremony_id)
    corrupted = json.loads(json.dumps(record["broadcast"]))
    corrupted["spendBundle"]["coin_spends"][0]["coin"]["amount"] = 101
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET broadcast_json=? WHERE ceremony_id=?",
            (
                json.dumps(
                    corrupted,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                ceremony_id,
            ),
        )

    with pytest.raises(HTTPException) as error:
        await genesis_module.confirm(ceremony_id, settings, store)

    assert error.value.status_code == 409
    assert "does not match its bytes" in str(error.value.detail)
    assert store.get(ceremony_id)["state"] == "broadcast"


@pytest.mark.asyncio
async def test_confirmation_rejects_split_input_heights_and_output_mismatch(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, provider, input_ids, output_ids = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=False)
    )
    provider.input_heights[input_ids[1]] = 501

    with pytest.raises(HTTPException) as split_error:
        await genesis_module.confirm(ceremony_id, settings, store)

    assert split_error.value.status_code == 409
    assert "one transaction block" in str(split_error.value.detail)
    assert store.get(ceremony_id)["state"] == "broadcast"

    provider.input_heights[input_ids[1]] = 500
    provider.output_heights[output_ids[0]] = 501
    with pytest.raises(HTTPException) as output_error:
        await genesis_module.confirm(ceremony_id, settings, store)

    assert output_error.value.status_code == 409
    assert "not created with the reserved spends" in str(output_error.value.detail)
    assert store.get(ceremony_id)["state"] == "broadcast"


@pytest.mark.asyncio
async def test_reserved_chain_reconciliation_is_atomic_and_disk_retry_is_exact(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, _provider, _input_ids, _output_ids = (
        _confirmation_fixture(tmp_path, monkeypatch, reserved=True)
    )
    original_write = genesis_module._write_exact_evidence
    failed = False

    def fail_once_on_confirmation(path, payload, *, mode):
        nonlocal failed
        if path.name == "chain_confirmation.json" and not failed:
            failed = True
            raise OSError("simulated evidence-volume interruption")
        original_write(path, payload, mode=mode)

    monkeypatch.setattr(
        genesis_module,
        "_write_exact_evidence",
        fail_once_on_confirmation,
    )
    with pytest.raises(OSError, match="evidence-volume interruption"):
        await genesis_module.confirm(ceremony_id, settings, store)

    persisted = store.get(ceremony_id)
    assert persisted["state"] == "confirmed"
    assert persisted["broadcast"]["reservationState"] == "FINALIZED"
    assert persisted["broadcast"]["status"] == "CHAIN_RECONCILED"
    assert persisted["broadcast"]["chainConfirmation"]["source"] == (
        "exact-chain-reconciliation"
    )

    monkeypatch.setattr(
        genesis_module,
        "_write_exact_evidence",
        original_write,
    )
    retry = await genesis_module.confirm(ceremony_id, settings, store)
    output = (
        tmp_path / "renew-ceremonies" / ceremony_id.removeprefix("0x")
    )
    assert retry["state"] == "confirmed"
    assert (output / "chain_confirmation.json").is_file()
    assert json.loads(
        (output / "chain_confirmation.json").read_text(encoding="utf-8")
    ) == persisted["broadcast"]["chainConfirmation"]


@pytest.mark.asyncio
async def test_finalization_recovers_exactly_after_publication_crash(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, artifact = await _finalization_fixture(
        tmp_path, monkeypatch
    )
    original_write = genesis_module._write_exact_evidence
    failed = False

    def fail_once_before_bootstrap_lock(path, payload, *, mode):
        nonlocal failed
        if Path(path) == Path(settings.bootstrap_manifest_path) and not failed:
            failed = True
            raise OSError("simulated bootstrap publication interruption")
        original_write(path, payload, mode=mode)

    monkeypatch.setattr(
        genesis_module,
        "_write_exact_evidence",
        fail_once_before_bootstrap_lock,
    )
    with pytest.raises(OSError, match="bootstrap publication interruption"):
        genesis_module._commit_finalization(
            ceremony_id=ceremony_id,
            settings=settings,
            store=store,
            record=store.get(ceremony_id),
            artifact=artifact,
        )

    assert store.get(ceremony_id)["state"] == "artifact_signed"
    publication = store.finalization_publication(ceremony_id)
    assert publication is not None
    assert Path(settings.public_artifact_path).is_file()
    assert not Path(settings.bootstrap_manifest_path).exists()

    monkeypatch.setattr(
        genesis_module,
        "_write_exact_evidence",
        original_write,
    )
    recovered = genesis_module._commit_finalization(
        ceremony_id=ceremony_id,
        settings=settings,
        store=store,
        record=store.get(ceremony_id),
        artifact=artifact,
    )
    assert recovered["ceremony"]["state"] == "locked"
    assert json.loads(
        Path(settings.bootstrap_manifest_path).read_text(encoding="utf-8")
    ) == publication["bootstrapLock"]


@pytest.mark.asyncio
async def test_schema10_partial_finalization_adopts_existing_exact_lock(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, artifact = await _finalization_fixture(
        tmp_path,
        monkeypatch,
    )
    record = store.get(ceremony_id)
    bootstrap_lock = {
        **genesis_module._expected_bootstrap_lock(
            ceremony_id=ceremony_id,
            record=record,
            artifact=artifact,
        ),
        "lockedAt": 650,
    }
    assert store.reserve_finalization(ceremony_id, now=640) is None
    Path(settings.public_artifact_path).write_bytes(
        genesis_module._pretty_json_bytes(artifact)
    )
    Path(settings.bootstrap_manifest_path).write_bytes(
        genesis_module._pretty_json_bytes(bootstrap_lock)
    )

    result = genesis_module._commit_finalization(
        ceremony_id=ceremony_id,
        settings=settings,
        store=store,
        record=record,
        artifact=artifact,
    )

    assert result["ceremony"]["state"] == "locked"
    publication = store.finalization_publication(ceremony_id)
    assert publication is not None
    assert publication["bootstrapLock"] == bootstrap_lock
    assert json.loads(
        Path(settings.bootstrap_manifest_path).read_text(encoding="ascii")
    ) == bootstrap_lock

    repeated = genesis_module._commit_finalization(
        ceremony_id=ceremony_id,
        settings=settings,
        store=store,
        record=store.get(ceremony_id),
        artifact=artifact,
    )
    assert repeated["ceremony"]["state"] == "locked"


@pytest.mark.asyncio
async def test_finalization_cleans_known_temp_and_recreates_missing_evidence(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, artifact = await _finalization_fixture(
        tmp_path, monkeypatch
    )
    output = (
        tmp_path / "renew-ceremonies" / ceremony_id.removeprefix("0x")
    )
    stale_temp = output / "plan.json.tmp"
    stale_temp.write_bytes(b"partial")
    (output / "validator_health.json").unlink()

    result = genesis_module._commit_finalization(
        ceremony_id=ceremony_id,
        settings=settings,
        store=store,
        record=store.get(ceremony_id),
        artifact=artifact,
    )

    assert result["ceremony"]["state"] == "locked"
    assert not stale_temp.exists()
    assert (output / "validator_health.json").is_file()


@pytest.mark.asyncio
async def test_finalization_rejects_mutated_db_bound_evidence(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, artifact = await _finalization_fixture(
        tmp_path, monkeypatch
    )
    output = (
        tmp_path / "renew-ceremonies" / ceremony_id.removeprefix("0x")
    )
    (output / "plan.json").write_text("{}\n", encoding="ascii")

    with pytest.raises(GenesisConflict, match="evidence changed: plan.json"):
        genesis_module._commit_finalization(
            ceremony_id=ceremony_id,
            settings=settings,
            store=store,
            record=store.get(ceremony_id),
            artifact=artifact,
        )

    assert store.get(ceremony_id)["state"] == "artifact_signed"


@pytest.mark.asyncio
async def test_finalization_freezes_signature_set_before_external_writes(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, artifact = await _finalization_fixture(
        tmp_path, monkeypatch
    )

    def stop_after_publication_reservation(**_kwargs):
        raise OSError("simulated evidence volume outage")

    monkeypatch.setattr(
        genesis_module,
        "_materialize_broadcast_evidence",
        stop_after_publication_reservation,
    )
    with pytest.raises(OSError, match="evidence volume outage"):
        genesis_module._commit_finalization(
            ceremony_id=ceremony_id,
            settings=settings,
            store=store,
            record=store.get(ceremony_id),
            artifact=artifact,
        )

    assert store.finalization_publication(ceremony_id) is not None
    slot_three = store.get(ceremony_id)["invitations"][2]
    with pytest.raises(GenesisConflict, match="signatures are frozen"):
        store.add_artifact_signature(
            ceremony_id,
            slot=3,
            artifact_hash=artifact["artifactHash"],
            compressed_pubkey=str(slot_three["compressed_pubkey"]),
            signature="0x" + "03" * 65,
        )


@pytest.mark.asyncio
async def test_finalization_rejects_stale_signature_snapshot_then_retries(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id, stale_artifact = await _finalization_fixture(
        tmp_path, monkeypatch
    )
    slot_three = store.get(ceremony_id)["invitations"][2]
    store.add_artifact_signature(
        ceremony_id,
        slot=3,
        artifact_hash=stale_artifact["artifactHash"],
        compressed_pubkey=str(slot_three["compressed_pubkey"]),
        signature="0x" + "03" * 65,
    )

    with pytest.raises(GenesisConflict, match="signature set changed"):
        genesis_module._commit_finalization(
            ceremony_id=ceremony_id,
            settings=settings,
            store=store,
            record=store.get(ceremony_id),
            artifact=stale_artifact,
        )

    assert store.finalization_publication(ceremony_id) is None
    current_artifact = {
        **stale_artifact,
        "signatures": [
            *stale_artifact["signatures"],
            {
                "adminIndex": 2,
                "compressedPubkey": str(slot_three["compressed_pubkey"]),
                "signature": "0x" + "03" * 65,
            },
        ],
    }
    result = genesis_module._commit_finalization(
        ceremony_id=ceremony_id,
        settings=settings,
        store=store,
        record=store.get(ceremony_id),
        artifact=current_artifact,
    )
    assert result["ceremony"]["state"] == "locked"


def test_irreversible_broadcast_rejects_unsafe_empty_evidence_paths(
    tmp_path,
) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(GenesisConflict, match="directory is unsafe"):
        genesis_module._require_empty_evidence_output(symlink)

    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "missing", target_is_directory=True)
    with pytest.raises(GenesisConflict, match="directory is unsafe"):
        genesis_module._require_empty_evidence_output(dangling)
    with pytest.raises(GenesisConflict, match="directory is unsafe"):
        genesis_module._require_safe_evidence_directory(dangling, create=True)

    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    with pytest.raises(GenesisConflict, match="mode 0700"):
        genesis_module._require_empty_evidence_output(loose)


@pytest.mark.parametrize(
    ("race", "expected_status"),
    (("expiry", 410), ("renewal", 409)),
)
@pytest.mark.asyncio
async def test_broadcast_boundary_blocks_plan_expiry_and_renewal_races(
    tmp_path,
    monkeypatch,
    race: str,
    expected_status: int,
) -> None:
    store, settings, ceremony_id = _expired_approved_store(tmp_path)
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET plan_expires_at=? WHERE ceremony_id=?",
            (int(time.time()) + 3600, ceremony_id),
        )
    _open_broadcast_gate(store, ceremony_id, settings)
    review_receipt = b'{"review":"authority-v3"}\n'
    review_path = tmp_path / f"{race}-authority-v3-review.json"
    review_path.write_bytes(review_receipt)
    review_sha256 = hashlib.sha256(review_receipt).hexdigest()
    settings.authority_v3_independent_review_path = str(review_path)
    settings.authority_v3_independent_review_sha256 = review_sha256
    protocol_bundle = {
        "coin_spends": [{"coin": {"amount": 530}}],
        "aggregated_signature": "0xc0",
    }
    prepared_bundle = {
        "coin_spends": [
            *protocol_bundle["coin_spends"],
            {"coin": {"amount": 100}},
        ],
        "aggregated_signature": "0xc1",
    }

    async def fake_prepare_bundle(_settings, record):
        return (
            record["plan"],
            {
                "spendBundleId": "0x" + "aa" * 32,
                "spendCount": 49,
                "spendBundle": protocol_bundle,
            },
            {
                "reviewClass": "internal-engineering-testnet",
                "authorityV3Review": {
                    "fileSha256": "0x" + review_sha256,
                },
            },
            (),
        )

    class PreparedBundle:
        spend_bundle_id = "0x" + "bb" * 32
        fee_coin_id = "0x" + "cc" * 32
        fee_mojos = 7

        def to_json(self):
            return {
                "spendBundleId": self.spend_bundle_id,
                "feeMojos": "7",
                "feeCoinId": self.fee_coin_id,
                "spendBundle": prepared_bundle,
            }

    class RacingSubmitter:
        callback_invoked = False
        pushed = False

        async def submit(self, _bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            now = int(time.time())
            with store._transaction() as connection:
                connection.execute(
                    "UPDATE ceremonies SET plan_expires_at=? WHERE ceremony_id=?",
                    (now, ceremony_id),
                )
            if race == "renewal":
                current = store.get(ceremony_id)
                renewed_hash = "0x" + "de" * 32
                renewed_plan = dict(current["plan"])
                renewed_plan["expiresAt"] = now + 3600
                renewed_plan["planHash"] = renewed_hash
                store.renew_expired_plan(
                    ceremony_id,
                    expected_plan_hash=str(current["plan_hash"]),
                    plan=renewed_plan,
                    plan_hash=renewed_hash,
                    expires_at=now + 3600,
                    now=now,
                )
            self.callback_invoked = True
            before_push(PreparedBundle())
            self.pushed = True
            raise AssertionError("provider push must not run after a plan race")

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    submitter = RacingSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=submitter))
    )

    with pytest.raises(HTTPException) as error:
        await genesis_module.broadcast(ceremony_id, request, settings, store)

    assert error.value.status_code == expected_status
    assert submitter.callback_invoked is True
    assert submitter.pushed is False
    assert store.get(ceremony_id)["spend_bundle_id"] is None


@pytest.mark.asyncio
async def test_guided_gate_closing_before_push_prevents_provider_submission(
    tmp_path,
    monkeypatch,
) -> None:
    store, settings, ceremony_id = _expired_approved_store(tmp_path)
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET plan_expires_at=? WHERE ceremony_id=?",
            (int(time.time()) + 3600, ceremony_id),
        )
    review_receipt = b'{"review":"authority-v3"}\n'
    review_path = tmp_path / "gate-authority-v3-review.json"
    review_path.write_bytes(review_receipt)
    review_sha256 = hashlib.sha256(review_receipt).hexdigest()
    settings.authority_v3_independent_review_path = str(review_path)
    settings.authority_v3_independent_review_sha256 = review_sha256
    protocol_bundle = {
        "coin_spends": [{"coin": {"amount": 530}}],
        "aggregated_signature": "0xc0",
    }
    prepared_bundle = {
        "coin_spends": [
            *protocol_bundle["coin_spends"],
            {"coin": {"amount": 100}},
        ],
        "aggregated_signature": "0xc1",
    }
    now = int(time.time())
    closes_at = now + 60
    store.upsert_gate(
        ceremony_id,
        gate_name="ceremonyBroadcast",
        opens_at=now - 60,
        closes_at=closes_at,
        payload_hash="0x" + "ef" * 32,
        state="open",
        now=now,
    )
    gate = store.gates(ceremony_id, now=now)["ceremonyBroadcast"]
    gate_authorization = {
        "gate": "ceremonyBroadcast",
        "payloadHash": gate["payloadHash"],
        "opensAt": gate["opensAt"],
        "closesAt": gate["closesAt"],
        "configuredState": gate["configuredState"],
        "state": gate["state"],
        "approved": True,
    }

    async def fake_prepare_bundle(_settings, record):
        return (
            record["plan"],
            {
                "spendBundleId": "0x" + "aa" * 32,
                "spendCount": 49,
                "spendBundle": protocol_bundle,
            },
            {
                "reviewClass": "internal-engineering-testnet",
                "authorityV3Review": {
                    "fileSha256": "0x" + review_sha256,
                },
            },
            (),
        )

    class PreparedBundle:
        spend_bundle_id = "0x" + "bb" * 32
        fee_coin_id = "0x" + "cc" * 32
        fee_mojos = 7

        def to_json(self):
            return {
                "spendBundleId": self.spend_bundle_id,
                "feeMojos": "7",
                "feeCoinId": self.fee_coin_id,
                "spendBundle": prepared_bundle,
            }

    class ClosingGateSubmitter:
        callback_invoked = False
        pushed = False

        async def submit(self, _bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            self.callback_invoked = True
            monkeypatch.setattr(
                genesis_store_module.time,
                "time",
                lambda: closes_at,
            )
            before_push(PreparedBundle())
            self.pushed = True
            raise AssertionError("provider push must not run after gate close")

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    submitter = ClosingGateSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=submitter))
    )

    with pytest.raises(GenesisConflict, match="gate is closed"):
        await genesis_module._broadcast_ceremony(
            ceremony_id,
            request,
            settings,
            store,
            gate_authorization=gate_authorization,
        )

    assert submitter.callback_invoked is True
    assert submitter.pushed is False
    assert store.get(ceremony_id)["state"] == "plan_approved"


def test_broadcast_requires_fee_funded_local_mempool_submission(
    tmp_path, monkeypatch
) -> None:
    client, store, settings = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client, store)
    _approve_plan(client, ceremony_id, accounts)
    _open_broadcast_gate(store, ceremony_id, settings)
    review_receipt = b'{"review":"authority-v3"}\n'
    review_path = tmp_path / "authority-v3-review.json"
    review_path.write_bytes(review_receipt)
    review_sha256 = hashlib.sha256(review_receipt).hexdigest()
    settings.authority_v3_independent_review_path = str(review_path)
    settings.authority_v3_independent_review_sha256 = review_sha256
    protocol_bundle = {
        "coin_spends": [{"coin": {"amount": 530}}],
        "aggregated_signature": "0xc0",
    }

    async def fake_prepare_bundle(_settings, record):
        return (
            record["plan"],
            {
                "spendBundleId": "0x" + "aa" * 32,
                "spendCount": 49,
                "spendBundle": protocol_bundle,
            },
            {
                "reviewClass": "internal-engineering-testnet",
                "authorityV3Review": {
                    "fileSha256": "0x" + review_sha256,
                },
            },
            (),
        )

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    missing = client.post(
        f"/admin/genesis/{ceremony_id}/broadcast",
        headers=_headers(),
    )
    assert missing.status_code == 409
    assert "local-node medium-fee funding" in missing.text
    assert store.get(ceremony_id)["state"] == "plan_approved"

    final_bundle = {
        "coin_spends": [
            *protocol_bundle["coin_spends"],
            {"coin": {"amount": 100}},
        ],
        "aggregated_signature": "0xc1",
    }

    class FakePreparedBundle:
        spend_bundle_id = "0x" + "bb" * 32
        fee_coin_id = "0x" + "cc" * 32
        fee_mojos = 7

        def to_json(self):
            return {
                "spendBundleId": self.spend_bundle_id,
                "feeMojos": "7",
                "feeCoinId": self.fee_coin_id,
                "spendBundle": final_bundle,
            }

    class FakeSubmitter:
        submitted: dict | None = None
        pushed = False
        reserved_before_push = False

        async def submit(self, bundle, *, before_push, selection_purpose=None):
            assert selection_purpose == "genesis"
            self.submitted = bundle
            prepared = FakePreparedBundle()
            before_push(prepared)
            reserved = store.get(ceremony_id)
            self.reserved_before_push = (
                reserved["state"] == "broadcast"
                and reserved["spend_bundle_id"] == prepared.spend_bundle_id
                and reserved["broadcast"]["reservationState"] == "RESERVED"
                and reserved["broadcast"]["spendBundle"] == final_bundle
            )
            self.pushed = True
            return {
                "schemaVersion": 1,
                "status": "MEMPOOL",
                "network": "testnet11",
                "spendBundleId": prepared.spend_bundle_id,
                "feeMojos": "7",
                "feeTargetSeconds": 300,
                "feeCoinId": prepared.fee_coin_id,
                "feeTillPuzzleHash": "0x" + "dd" * 32,
                "submissionProvider": "local-full-node",
                "mempoolObservedAt": "2026-07-27T12:00:00+00:00",
                "ambiguousPushRecovered": False,
                "spendBundle": final_bundle,
            }

    submitter = FakeSubmitter()
    client.app.state.protocol_submitter = submitter
    accepted = client.post(
        f"/admin/genesis/{ceremony_id}/broadcast",
        headers=_headers(),
    )

    assert accepted.status_code == 200, accepted.text
    assert submitter.submitted == protocol_bundle
    assert submitter.reserved_before_push is True
    assert submitter.pushed is True
    assert accepted.json()["state"] == "broadcast"
    assert accepted.json()["spend_bundle_id"] == "0x" + "bb" * 32
    assert "spendBundle" not in accepted.json()["broadcast"]
    assert store.get(ceremony_id)["broadcast"]["spendBundle"]
    output = (
        tmp_path
        / "ceremonies"
        / ceremony_id.removeprefix("0x")
    )
    archived_bundle = json.loads(
        (output / "spend_bundle.json").read_text(encoding="utf-8")
    )
    assert len(archived_bundle["coin_spends"]) == 2
    fee_receipt = json.loads(
        (output / "fee_receipt.json").read_text(encoding="utf-8")
    )
    assert fee_receipt["feeMojos"] == "7"
    assert "spendBundle" not in fee_receipt
    assert (
        output / "authority_v3_review.json"
    ).read_bytes() == review_receipt


def test_preflight_returns_canonical_review_approval_for_offline_gate(
    tmp_path, monkeypatch
) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client, store)
    created = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=_plan_body(),
        headers=_headers(),
    )
    assert created.status_code == 200, created.text
    for slot, account in enumerate(accounts[:2], start=1):
        prepared = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures/prepare",
            json={"slot": slot},
        )
        signed = client.post(
            f"/admin/genesis/{ceremony_id}/plan/signatures",
            json={
                "slot": slot,
                "signature": _signature(account, prepared.json()["typedData"]),
            },
        )
        assert signed.status_code == 200, signed.text

    approval = {
        "schemaVersion": 2,
        "sourceManifestVersion": 4,
        "reviewClass": "internal-engineering-testnet",
        "auditStatus": "unaudited",
        "testOnly": True,
        "ceremonyId": ceremony_id,
    }
    spend_bundle_id = "0x" + "ab" * 32

    async def fake_prepare_bundle(settings, record):
        del settings
        return (
            record["plan"],
            {"spendBundleId": spend_bundle_id, "spendCount": 9},
            approval,
            (),
        )

    monkeypatch.setattr(genesis_module, "_prepare_bundle", fake_prepare_bundle)
    response = client.post(
        f"/admin/genesis/{ceremony_id}/preflight",
        headers=_headers(),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ready"] is True
    assert body["reviewApproval"] == approval
    assert body["auditApprovalHash"] == "0x" + hashlib.sha256(
        json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _independent_audit_fixture(tmp_path):
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        genesis_audit_approval_path=str(tmp_path / "independent-approval.json"),
        cors_origins="",
    )
    ceremony_id = "0x" + "a1" * 32
    plan_hash = "0x" + "a2" * 32
    spend_bundle_id = "0x" + "a3" * 32
    addresses = {
        "forwarder": "0x" + "11" * 20,
        "verifierAdapter": "0x" + "22" * 20,
        "attestationEmitter": "0x" + "33" * 20,
    }
    contracts = {
        name: {
            "address": address,
            "bytecodeHash": "0x" + bytes([index]).hex() * 32,
            "confirmations": 12,
        }
        for index, (name, address) in enumerate(addresses.items(), start=1)
    }
    validator_keys = ["0x" + f"{index:02x}" * 48 for index in (1, 2, 3)]
    record = {
        "ceremony_id": ceremony_id,
        "plan_hash": plan_hash,
        "draft": {
            "reviewClass": "independent-release-review",
            "sourceShas": _source_shas(),
        },
    }
    plan = {
        "evmAddresses": addresses,
        "validatorSet": {"pubkeys": validator_keys},
    }
    approval = {
        "schemaVersion": 2,
        "sourceManifestVersion": 4,
        "reviewClass": "independent-release-review",
        "ceremonyId": ceremony_id,
        "planHash": plan_hash,
        "sourceShas": _source_shas(),
        "consensusSimulationBundleId": spend_bundle_id,
        "approvals": [
            {
                "lane": lane,
                "approved": True,
                "reviewer": f"independent-{index}",
                "evidenceHash": "0x" + bytes([index + 10]).hex() * 32,
            }
            for index, lane in enumerate(genesis_module.REQUIRED_AUDIT_LANES)
        ],
        "evmContracts": contracts,
        "validators": {"threshold": 2, "pubkeys": validator_keys},
    }
    evm_evidence = {"contracts": contracts}
    return settings, record, plan, spend_bundle_id, approval, evm_evidence


def test_independent_audit_is_strictly_plan_and_live_deployment_bound(
    tmp_path,
) -> None:
    settings, record, plan, spend_bundle_id, approval, evm_evidence = (
        _independent_audit_fixture(tmp_path)
    )
    Path(settings.genesis_audit_approval_path).write_text(
        json.dumps(approval), encoding="utf-8"
    )

    validated = genesis_module._validate_audit_approval(
        settings, record, plan, spend_bundle_id, evm_evidence
    )

    assert validated == approval

    approval["planHash"] = "0x" + "ff" * 32
    Path(settings.genesis_audit_approval_path).write_text(
        json.dumps(approval), encoding="utf-8"
    )
    with pytest.raises(GenesisConflict, match="planHash does not match"):
        genesis_module._validate_audit_approval(
            settings, record, plan, spend_bundle_id, evm_evidence
        )


def test_independent_audit_rejects_missing_or_live_mismatched_evidence(
    tmp_path,
) -> None:
    settings, record, plan, spend_bundle_id, approval, evm_evidence = (
        _independent_audit_fixture(tmp_path)
    )

    with pytest.raises(GenesisConflict, match="approval file is missing"):
        genesis_module._validate_audit_approval(
            settings, record, plan, spend_bundle_id, evm_evidence
        )

    Path(settings.genesis_audit_approval_path).write_text(
        json.dumps(approval), encoding="utf-8"
    )
    evm_evidence["contracts"]["forwarder"]["bytecodeHash"] = "0x" + "ee" * 32
    with pytest.raises(GenesisConflict, match="does not match live evidence"):
        genesis_module._validate_audit_approval(
            settings, record, plan, spend_bundle_id, evm_evidence
        )


def test_wrong_admin_cannot_sign_frozen_plan(tmp_path) -> None:
    client, store, _ = _client(tmp_path)
    ceremony_id, _ = _create_and_enroll(client, store)
    created = client.post(
        f"/admin/genesis/{ceremony_id}/plan",
        json=_plan_body(),
        headers=_headers(),
    )
    typed_data = created.json()["typedData"]
    attacker = Account.create("not-an-admin")
    response = client.post(
        f"/admin/genesis/{ceremony_id}/plan/signatures",
        json={"slot": 1, "signature": _signature(attacker, typed_data)},
    )
    assert response.status_code == 403


def test_operator_routes_require_ceremony_token(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    response = client.post(
        "/admin/genesis/drafts",
        json={
            "sourceShas": _source_shas()
        },
    )
    assert response.status_code == 401


def test_draft_rejects_unknown_review_class(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    response = client.post(
        "/admin/genesis/drafts",
        json={
            "sourceShas": _source_shas(),
            "reviewClass": "self-approved-mainnet",
        },
        headers=_headers(),
    )
    assert response.status_code == 422


def test_draft_rejects_retired_six_repository_source_set(tmp_path) -> None:
    client, _, _ = _client(tmp_path)
    retired = {
        key: value
        for key, value in _source_shas().items()
        if key not in {"omnichain", "keyOfSolomon", "samuel"}
    }
    response = client.post(
        "/admin/genesis/drafts",
        json={"sourceShas": retired},
        headers=_headers(),
    )
    assert response.status_code == 422
    assert "all nine frozen release commits" in response.text
