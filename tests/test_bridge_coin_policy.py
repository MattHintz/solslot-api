"""Synthetic enrollment selection against the signed bridge coin policy."""
import copy
from types import SimpleNamespace
import time
import pytest
from fastapi import HTTPException

from solslot_api import zkpassport_enrollments as enrollments
from solslot_api.credential_ledger import CredentialLedger, get_credential_ledger
from tests.test_zkpassport_enrollments import (
    _client, _bridge_record, _coin_id, _install_signed_artifact,
    VAULT_A, PARENT_A, PARENT_B, POLICY_HASH,
)


def committed_artifact(monkeypatch):
    artifact = _install_signed_artifact(monkeypatch)
    artifact["bridgePolicy"].update(
        parentCoinIds=[PARENT_A, PARENT_B],
        bridgeCoinIds=[_coin_id(parent, POLICY_HASH) for parent in (PARENT_A, PARENT_B)],
    )
    return artifact


def test_attacker_coin_sorted_before_committed_coin_is_skipped(monkeypatch, tmp_path):
    records = [_bridge_record("0x" + "01" * 32), _bridge_record(PARENT_A)]
    with _client(monkeypatch, tmp_path, bridge_records=records) as client:
        committed_artifact(monkeypatch)
        result = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
    assert result.status_code == 200
    assert result.json()["bridgeParentId"] == PARENT_A


def test_committed_one_mojo_reservation_is_stable_on_retry(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        committed_artifact(monkeypatch)
        first = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        again = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
    assert first.status_code == again.status_code == 200
    assert first.json() == again.json()
    assert first.json()["bridgeAmount"] == 1


@pytest.mark.parametrize("variant", ["amount2", "overflow", "negative", "boolean", "float", "parent", "coin_id", "policy", "unconfirmed", "bad_height", "spent", "spent_flag", "bad_coin", "bad_parent", "bad_amount"])
def test_ineligible_records_are_skipped_before_reservation(monkeypatch, tmp_path, variant):
    bad = _bridge_record(PARENT_A)
    if variant in {"amount2", "overflow", "negative", "boolean", "float"}:
        bad["coin"]["amount"] = {"amount2": 2, "overflow": 2**256, "negative": -1, "boolean": True, "float": 1.0}[variant]
    elif variant == "parent":
        bad["coin"]["parent_coin_info"] = "0x" + "01" * 32
    elif variant == "policy":
        bad["coin"]["puzzle_hash"] = "0x" + "02" * 32
    elif variant == "unconfirmed":
        bad["confirmed_block_index"] = 0
    elif variant == "bad_height":
        bad["confirmed_block_index"] = "invalid"
    elif variant == "spent":
        bad["spent_block_index"] = 10
    elif variant == "spent_flag":
        bad["spent"] = True
    elif variant == "bad_coin":
        bad["coin"] = None
    elif variant == "bad_parent":
        bad["coin"]["parent_coin_info"] = "0xabc"
    elif variant == "bad_amount":
        bad["coin"]["amount"] = "not-an-integer"
    with _client(monkeypatch, tmp_path, bridge_records=[bad, _bridge_record(PARENT_B)]) as client:
        artifact = committed_artifact(monkeypatch)
        if variant == "coin_id":
            artifact["bridgePolicy"]["bridgeCoinIds"].remove(_coin_id(PARENT_A, POLICY_HASH))
        result = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
    assert result.status_code == 200
    assert result.json()["bridgeParentId"] == PARENT_B


@pytest.mark.parametrize("field,value", [("parentCoinIds", None), ("bridgeCoinIds", "not-a-list"), ("policyHash", "0x1234"), ("bridgeCoinIds", ["0xwrong"])])
def test_malformed_policy_fails_before_reserving(monkeypatch, tmp_path, field, value):
    with _client(monkeypatch, tmp_path) as client:
        artifact = committed_artifact(monkeypatch)
        artifact["bridgePolicy"][field] = value
        result = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A})
        assert result.status_code == 503
        assert get_credential_ledger(enrollments._settings()).get_enrollment(VAULT_A) is None


def test_valid_existing_reservation_survives_discovery_outage_and_restart(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        committed_artifact(monkeypatch)
        created = client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json()
        monkeypatch.setattr(enrollments, "_fetch_bridge_coin_records", lambda *_args: pytest.fail("existing reservation must not rediscover coins"))
        assert client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}).json() == created
        assert client.get(f"/zkpassport/enrollments/{VAULT_A}").json() == created
        reopened = CredentialLedger(tmp_path / "credential.db")
        try:
            assert reopened.get_enrollment(VAULT_A) == created
            assert reopened.enrollment_bridge_coin_ids() == {created["bridgeCoinId"]}
        finally:
            reopened.close()


def test_ambiguous_historical_reservation_is_preserved_with_repair_error(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        committed_artifact(monkeypatch)
        parent = "0x" + "01" * 32
        old = {"vaultLauncherId": VAULT_A, "network": "testnet11", "policyVersion": 2,
               "status": "reserved", "bridgePolicyHash": POLICY_HASH, "bridgeParentId": parent,
               "bridgeAmount": 1, "bridgeCoinId": _coin_id(parent, POLICY_HASH),
               "createdAt": 100, "updatedAt": 100, "receipt": None}
        ledger = get_credential_ledger(enrollments._settings())
        ledger.reserve_enrollment(record=old, owner_key="synthetic-owner")
        for result in (client.post("/zkpassport/enrollments", json={"vaultLauncherId": VAULT_A}),
                       client.get(f"/zkpassport/enrollments/{VAULT_A}")):
            assert result.status_code == 409
            assert "reconcile" in result.json()["detail"]
        # Missing local receipt/relay data cannot rule out an externally signed
        # ForwardRequest. Neither JSON nor indexed coin identity is replaced.
        assert ledger.get_enrollment(VAULT_A) == old
        assert ledger.enrollment_bridge_coin_ids() == {old["bridgeCoinId"]}


def test_duplicate_and_hex_case_representations_preserve_one_coin(monkeypatch, tmp_path):
    first = _bridge_record(PARENT_A)
    equivalent = copy.deepcopy(first)
    equivalent["coin"]["parent_coin_info"] = "0x" + PARENT_A[2:].upper()
    equivalent["coin"]["puzzle_hash"] = "0x" + POLICY_HASH[2:].upper()
    equivalent["coin"]["amount"] = "1"
    with _client(monkeypatch, tmp_path, bridge_records=[first, equivalent, _bridge_record(PARENT_B)]):
        committed_artifact(monkeypatch)
        selected = enrollments._bridge_coin_candidates(enrollments._settings(), bridge_policy_hash=POLICY_HASH)
    assert [value.parent_id for value in selected] == [PARENT_A, PARENT_B]


def test_validator_and_api_share_exact_policy_and_coin_identity(monkeypatch):
    from solslot_api.bridge_coin_policy import BridgeCoinPolicy
    from solslot_api.validator_service import _verify_bridge_coin, ValidatorEvidenceError
    artifact = committed_artifact(monkeypatch)
    policy = BridgeCoinPolicy.from_artifact(artifact)
    claim = SimpleNamespace(bridge_parent_id=PARENT_A, bridge_policy_hash=POLICY_HASH,
                            bridge_amount=1, bridge_coin_id=_coin_id(PARENT_A, POLICY_HASH))
    monkeypatch.setattr("solslot_api.validator_service._fetch_coin", lambda *_args: _bridge_record(PARENT_A))
    _verify_bridge_coin(object(), artifact, claim)
    policy.require_coin(parent_id=claim.bridge_parent_id, policy_hash=claim.bridge_policy_hash,
                        amount=claim.bridge_amount, coin_id=claim.bridge_coin_id)
    claim.bridge_coin_id = _coin_id(PARENT_B, POLICY_HASH)
    with pytest.raises(ValidatorEvidenceError, match="coin fields"):
        _verify_bridge_coin(object(), artifact, claim)


@pytest.mark.parametrize("kind", ["evm", "bls"])
def test_ineligible_existing_coin_cannot_reach_either_sponsored_relay(monkeypatch, kind):
    from solslot_api import zkpassport_relay as relay
    from tests.test_zkpassport_relay import _request, _bls_request, _relay_settings, FORWARDER, EMITTER, SIGNER
    settings = _relay_settings()
    settings.zkpassport_forwarder_address = FORWARDER
    committed_artifact(monkeypatch)
    owner = SimpleNamespace(auth_type="chia_bls" if kind == "bls" else "evm", owner_key="synthetic-owner",
                            vault_record=SimpleNamespace(owner_evm_address=None if kind == "bls" else SIGNER))
    old = {"status": "reserved", "bridgePolicyHash": POLICY_HASH, "bridgeParentId": "0x" + "22" * 32,
           "bridgeAmount": 1, "bridgeCoinId": _coin_id("0x" + "22" * 32, POLICY_HASH)}
    monkeypatch.setattr(relay, "_load_settings", lambda: settings)
    monkeypatch.setattr(relay, "_require_relayer_account", lambda *_: SimpleNamespace(address=SIGNER))
    monkeypatch.setattr(relay, "verify_vault_session", lambda *_: owner)
    monkeypatch.setattr(relay, "verify_owner_auth", lambda *_, **__: owner)
    monkeypatch.setattr(relay, "get_credential_ledger", lambda *_: SimpleNamespace(get_enrollment=lambda *_: old))
    monkeypatch.setattr(relay, "_w3", lambda *_: pytest.fail("ineligible coin reached relay RPC"))
    bls = _bls_request()
    if kind == "bls":
        invoke = lambda: relay.relay_bls(bls, _request())
    else:
        req = relay.RelayRequest(**{"from": SIGNER, "to": EMITTER, "value": "0", "gas": "1000000",
                                    "deadline": int(time.time()) + 300, "data": bls.data, "signature": "0x" + "11" * 65})
        invoke = lambda: relay.relay(req, _request())
    with pytest.raises(HTTPException) as error:
        invoke()
    assert error.value.status_code == 409
    assert "reconcile" in error.value.detail


def test_ineligible_bls_record_cannot_issue_a_new_relay_challenge(monkeypatch):
    from tests.test_zkpassport_relay import _request
    committed_artifact(monkeypatch)
    monkeypatch.setattr(enrollments, "_settings", lambda: object())
    monkeypatch.setattr(enrollments, "verify_vault_session", lambda *_: SimpleNamespace(auth_type="chia_bls"))
    monkeypatch.setattr(enrollments, "get_credential_ledger", lambda *_: SimpleNamespace(get_enrollment=lambda *_: {
        "bridgePolicyHash": POLICY_HASH, "bridgeParentId": "0x" + "01" * 32,
        "bridgeAmount": 1, "bridgeCoinId": _coin_id("0x" + "01" * 32, POLICY_HASH),
    }))
    monkeypatch.setattr(enrollments, "issue_owner_challenge", lambda *_, **__: pytest.fail("ineligible coin reached signing challenge"))
    with pytest.raises(HTTPException) as error:
        enrollments.create_bls_relay_challenge(VAULT_A, enrollments.RelayChallengeRequest(data="0x12345678"), _request())
    assert error.value.status_code == 409


@pytest.mark.parametrize("entry", ["context", "request", "imported-helper"])
def test_client_portal_finalizes_prior_program_cycles_on_owner_thread(monkeypatch, tmp_path, entry):
    """An imported helper must preserve the same thread boundary as direct clients."""
    import gc
    import threading
    import weakref
    from chia.types.blockchain_format.program import Program
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    class Cycle:
        pass

    owner = threading.get_ident()
    finalized = []
    gc.collect()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        cycle = Cycle()
        cycle.program = Program.from_bytes(b"\xff\x01\x80")
        cycle.self = cycle
        reference = weakref.ref(cycle)
        weakref.finalize(cycle, lambda: finalized.append(threading.get_ident()))
        del cycle
        if entry == "imported-helper":
            client = _client(monkeypatch, tmp_path)
        else:
            test_app = FastAPI()
            @test_app.get('/thread')
            async def thread():
                return {'id': threading.get_ident()}
            client = TestClient(test_app)
        if entry == "request":
            try:
                response = client.get('/thread')
                assert response.status_code == 200 and response.json()['id'] != owner
            finally:
                client.close()
        else:
            with client:
                assert client.portal is not None
        assert reference() is None
        assert finalized == [owner]
    finally:
        # Even a failed regression cleans up on its owning test thread.
        gc.collect()
        if was_enabled:
            gc.enable()
