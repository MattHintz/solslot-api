from __future__ import annotations

from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import FastAPI
from chia_rs import AugSchemeMPL
import httpx
import pytest

from solslot_api.admin_security import (
    SecurityActor,
    require_security_actor,
    router,
)
from solslot_api.config import Settings, get_settings
from solslot_api.genesis import get_genesis_store
from solslot_api.genesis_store import GenesisStore


CEREMONY_ID = "0x" + "11" * 32
DAILY_WALLET = "0x" + "22" * 20


def _app(tmp_path, operations_chain=84532) -> tuple[FastAPI, GenesisStore]:
    settings = Settings(
        _env_file=None,
        runtime_environment="test",
        network="testnet11",
        public_artifact_path=str(tmp_path / "not-launched.json"),
        genesis_db_path=str(tmp_path / "genesis.db"),
    )
    store = GenesisStore(settings.genesis_db_path)
    draft = {"network": "testnet11"}
    if operations_chain == 8453:
        draft.update(evmChainId=8453, enrollmentActivation={
            "schema": "solslot.enrollment-activation.v2", "evmChainId": 8453,
        })
    store.create_draft(CEREMONY_ID, draft)
    app = FastAPI()
    app.include_router(router)

    async def settings_override() -> Settings:
        return settings

    async def store_override() -> GenesisStore:
        return store

    async def actor_override() -> SecurityActor:
        return SecurityActor(
            ceremony_id=CEREMONY_ID,
            ceremony_slot=1,
            authority_slot=0,
            wallet=DAILY_WALLET,
            source="launch_session",
        )

    app.dependency_overrides[get_settings] = settings_override
    app.dependency_overrides[get_genesis_store] = store_override
    app.dependency_overrides[require_security_actor] = actor_override
    return app, store


@pytest.mark.asyncio
@pytest.mark.parametrize("operations_chain", [84532, 8453])
async def test_dual_key_drill_enrolls_public_recovery_evidence(
    tmp_path, operations_chain,
) -> None:
    app, store = _app(tmp_path, operations_chain)
    guardian = Account.create()
    recovery_sk = AugSchemeMPL.key_gen(b"recovery drill seed" * 2)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        prepared = await client.post(
            "/admin/security/recovery-kit/drill",
            json={
                "evmGuardian": guardian.address,
                "recoveryBlsPubkey": "0x" + bytes(recovery_sk.get_g1()).hex(),
            },
        )
        assert prepared.status_code == 200, prepared.text
        challenge = prepared.json()
        assert challenge["evmTypedData"]["domain"]["chainId"] == operations_chain
        evm_signature = guardian.sign_message(
            encode_typed_data(full_message=challenge["evmTypedData"])
        ).signature
        bls_signature = AugSchemeMPL.sign(
            recovery_sk,
            bytes.fromhex(challenge["blsSigningDigest"][2:]),
        )

        completed = await client.post(
            "/admin/security/recovery-kit/drill/complete",
            json={
                "challengeId": challenge["challengeId"],
                "evmSignature": "0x" + bytes(evm_signature).hex(),
                "blsSignature": "0x" + bytes(bls_signature).hex(),
                "offlineCopyConfirmed": True,
                "secondDeviceConfirmed": True,
                "backup": {
                    "status": "VERIFIED",
                    "revision": 1,
                    "ciphertextHash": "0x" + "33" * 32,
                },
            },
        )
        assert completed.status_code == 200, completed.text
        body = completed.json()
        assert body["verified"] is True
        assert body["recoveryKit"]["slot"] == 0
        assert body["recoveryKit"]["backupStatus"] == "VERIFIED"
        assert len(store.recovery_kits(CEREMONY_ID)) == 1

        status = await client.get("/admin/security/status")
        assert status.status_code == 200, status.text
        assert status.json()["recoveryReady"] is False
        assert status.json()["authority"] is None
        assert "after genesis" in status.json()["authorityNotice"]


@pytest.mark.asyncio
async def test_wrong_recovery_signature_and_unperformed_drill_fail_closed(
    tmp_path,
) -> None:
    app, store = _app(tmp_path)
    guardian = Account.create()
    recovery_sk = AugSchemeMPL.key_gen(b"correct recovery seed" * 2)
    attacker_sk = AugSchemeMPL.key_gen(b"attacker recovery seed" * 2)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        challenge = (
            await client.post(
                "/admin/security/recovery-kit/drill",
                json={
                    "evmGuardian": guardian.address,
                    "recoveryBlsPubkey": (
                        "0x" + bytes(recovery_sk.get_g1()).hex()
                    ),
                },
            )
        ).json()
        evm_signature = guardian.sign_message(
            encode_typed_data(full_message=challenge["evmTypedData"])
        ).signature
        wrong_bls_signature = AugSchemeMPL.sign(
            attacker_sk,
            bytes.fromhex(challenge["blsSigningDigest"][2:]),
        )

        not_drilled = await client.post(
            "/admin/security/recovery-kit/drill/complete",
            json={
                "challengeId": challenge["challengeId"],
                "evmSignature": "0x" + bytes(evm_signature).hex(),
                "blsSignature": "0x" + bytes(wrong_bls_signature).hex(),
                "offlineCopyConfirmed": True,
                "secondDeviceConfirmed": False,
                "backup": {"status": "NOT_CONFIGURED"},
            },
        )
        assert not_drilled.status_code == 409

        wrong_signature = await client.post(
            "/admin/security/recovery-kit/drill/complete",
            json={
                "challengeId": challenge["challengeId"],
                "evmSignature": "0x" + bytes(evm_signature).hex(),
                "blsSignature": "0x" + bytes(wrong_bls_signature).hex(),
                "offlineCopyConfirmed": True,
                "secondDeviceConfirmed": True,
                "backup": {"status": "NOT_CONFIGURED"},
            },
        )
        assert wrong_signature.status_code == 409
        assert "BLS recovery drill signature is invalid" in wrong_signature.text
        assert store.recovery_kits(CEREMONY_ID) == []


@pytest.mark.asyncio
async def test_recovery_guardian_cannot_equal_daily_wallet(tmp_path) -> None:
    app, _store = _app(tmp_path)
    recovery_sk = AugSchemeMPL.key_gen(b"another recovery seed" * 2)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/admin/security/recovery-kit/drill",
            json={
                "evmGuardian": DAILY_WALLET,
                "recoveryBlsPubkey": "0x" + bytes(recovery_sk.get_g1()).hex(),
            },
        )
    # The draft fixture has no enrolled invitation, so the actor's own wallet
    # is still enforced explicitly by the API dependency.
    assert response.status_code == 409
