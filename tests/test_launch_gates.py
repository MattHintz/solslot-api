from __future__ import annotations

import time

import pytest
from eth_account import Account
from tests.launch_authority_fixtures import install_signed_authority, open_signed_gate
from fastapi import HTTPException

from solslot_api.config import Settings
from solslot_api.genesis_store import GenesisStore
from solslot_api.launch_gates import require_operation_gate
from solslot_api.launch_rehearsal import persist_evidence


CEREMONY_ID = "0x" + "71" * 32
CONFIG_HASH = "0x" + "72" * 32


def _settings(tmp_path) -> Settings:
    settings = Settings(
        runtime_environment="test",
        network="testnet11",
        launch_control_enabled=True,
        genesis_db_path=str(tmp_path / "genesis.db"),
        launch_settlement_rehearsal_path=str(tmp_path / "settlement.json"),
        launch_rehearsal_config_hash=CONFIG_HASH,
    )

    install_signed_authority(settings, CEREMONY_ID, [Account.from_key(index.to_bytes(32, "big")) for index in (501, 502, 503)])
    return settings


def _evidence(settings: Settings) -> dict:
    def lane(seed: int, *, delivery: bool) -> dict:
        coin = lambda offset: "0x" + f"{seed + offset:02x}" * 32
        roles = (
            {
                "coordination": coin(20),
                "deed": coin(21),
                "series": coin(22),
                "terminalVoucher": coin(23),
            }
            if delivery
            else {
                "series": coin(22),
                "terminalVoucher": coin(23),
                "vault": coin(24),
            }
        )
        result = {
            "success": True,
            "purchaseId": coin(1),
            "artifactHash": coin(2),
            "paymentIntentId": f"pi_gate_rehearsal_{seed}",
            "eventId": f"evt_gate_rehearsal_{seed}",
            "baseAmountMinor": "10000",
            "technologyFeeMinor": "100",
            "processingChargeMinor": "0",
            "amountMinor": "10100",
            "approvedVaultLauncherId": coin(3),
            "deedLauncherId": coin(4),
            "zkPassportRoot": coin(5),
            "settlementReceiptHash": coin(6),
            "signerIndices": [0, 1],
            "voucher": {
                "serial": seed,
                "signerIndices": [0, 1],
                "issuanceBundleId": coin(7),
                "voucherCoinId": coin(8),
                "paymentCommitmentCoinId": coin(9),
                "issuanceConfirmedHeight": 400 + seed,
            },
            "execution": {
                "schema": "solslot.stripe-voucher-terminal-execution.v1",
                "mode": "REDEEM" if delivery else "REFUND_OWNER",
                "action": 7,
                "spendBundleId": coin(10),
                "feeCoinId": coin(11),
                "feeMojos": "42",
                "mempoolObservedAt": 1785844800,
                "outputRoles": roles,
            },
            "chain": (
                {
                    "confirmationHeight": 500 + seed,
                    "deedOutputCoinId": roles["deed"],
                    "seriesOutputCoinId": roles["series"],
                    "terminalVoucherCoinId": roles["terminalVoucher"],
                    "coordinationCoinId": roles["coordination"],
                }
                if delivery
                else {
                    "confirmationHeight": 500 + seed,
                    "seriesOutputCoinId": roles["series"],
                    "terminalVoucherCoinId": roles["terminalVoucher"],
                    "vaultOutputCoinId": roles["vault"],
                }
            ),
        }
        if not delivery:
            result.update(
                {
                    "exactRefund": True,
                    "stripeRefund": {
                        "refundId": f"re_gate_rehearsal_{seed}",
                        "refundedMinor": "10100",
                        "currency": "usd",
                        "livemode": False,
                        "observedAt": 1_775_000_000 + seed,
                    },
                }
            )
        return result

    return {
        "schemaVersion": 3,
        "kind": "solslot-rc27-stripe-voucher-rehearsal",
        "releaseTag": settings.launch_release_tag,
        "configHash": CONFIG_HASH,
        "network": "testnet11",
        "stripe": {
            "accountId": "acct_testnet_alpha",
            "mode": "test",
            "livemode": False,
            "apiVersion": "2026-07-29.clover",
        },
        "success": True,
        "validatorThreshold": 2,
        "validators": [
            {"id": "validator-1"},
            {"id": "validator-2"},
            {"id": "validator-3"},
        ],
        "lanes": {
            "delivery": lane(1, delivery=True),
            "refund": lane(40, delivery=False),
        },
    }


def _open_gate(store: GenesisStore, gate_name: str, settings) -> None:
    now = int(time.time())
    open_signed_gate(
        store, settings, CEREMONY_ID, gate_name,
        opens_at=now - 1,
        closes_at=now + 600,
        payload_hash="0x" + "73" * 32,
        now=now,
    )


def _lock(store: GenesisStore) -> None:
    with store._transaction() as connection:
        connection.execute(
            "UPDATE ceremonies SET state='locked' WHERE ceremony_id=?",
            (CEREMONY_ID,),
        )


def test_operational_windows_require_completed_genesis(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = GenesisStore(settings.genesis_db_path)
    store.create_draft(CEREMONY_ID, {}, now=100)
    _open_gate(store, "minting", settings)

    with pytest.raises(HTTPException, match="signed alpha launch is not complete"):
        require_operation_gate(settings, "minting")

    _lock(store)
    require_operation_gate(settings, "minting")


def test_purchase_windows_require_write_once_settlement_proof(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = GenesisStore(settings.genesis_db_path)
    store.create_draft(CEREMONY_ID, {}, now=100)
    _lock(store)
    _open_gate(store, "purchases", settings)

    with pytest.raises(HTTPException, match="settlement rehearsal is not started"):
        require_operation_gate(settings, "purchases")

    evidence = _evidence(settings)
    digest = persist_evidence(settings, evidence)
    store.set_settlement_rehearsal(
        CEREMONY_ID,
        job_id="rehearsal_job_0001",
        config_hash=CONFIG_HASH,
        state="SUCCEEDED",
        payload={"evidenceDigest": digest},
        now=101,
    )
    require_operation_gate(settings, "purchases")
