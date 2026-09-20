"""Mainnet authority signatures cannot reuse historical network approvals."""
import json

import pytest
from chia_rs import AugSchemeMPL
from eth_account import Account
from eth_account.messages import encode_typed_data

from solslot_api import admin_security as security
from solslot_api import admin_key_changes as changes
from solslot_api.authority_network import authority_chain_id, validate_authority_network
from solslot_api.authority_v3_evidence import _canonical_hash, load_governance_evidence
from solslot_api.evm_auth import recover_evm_signer
from tests.test_authority_v3_evidence import _evidence, _settings
from tests.test_admin_key_changes import FIXTURE
from solslot_puzzles.enrollment_networks import BASE_MAINNET_ENROLLMENT_SCHEMA


def mainnet_document():
    return {"evmChainId": 8453, "enrollmentActivation": {
        "schema": BASE_MAINNET_ENROLLMENT_SCHEMA, "evmChainId": 8453,
    }}


def test_authority_mainnet_requires_explicit_profile():
    document = mainnet_document()
    assert authority_chain_id(document) == 8453
    assert authority_chain_id({}) == 84532
    for changed in ({"evmChainId": 8453}, {**document, "evmChainId": 84532},
                    {**document, "evmChainId": "8453"}):
        with pytest.raises(ValueError):
            authority_chain_id(changed)
    for chain in (84532, "8453", 1, True):
        with pytest.raises(ValueError):
            validate_authority_network({"network": "baseMainnet", "chainId": chain}, 8453)


def test_mainnet_governance_evidence_matches_server_selection(tmp_path):
    evidence = _evidence()
    evidence.update(network="baseMainnet", chainId=8453)
    evidence["artifactHash"] = _canonical_hash(evidence)
    settings = _settings(tmp_path, evidence)
    with pytest.raises(ValueError, match="network"):
        load_governance_evidence(settings)
    settings.eip712_chain_id = 8453
    assert load_governance_evidence(settings)["chainId"] == 8453
    evidence["network"] = "baseSepolia"
    evidence["artifactHash"] = _canonical_hash(evidence)
    settings = _settings(tmp_path, evidence)
    settings.eip712_chain_id = 8453
    with pytest.raises(ValueError, match="network"):
        load_governance_evidence(settings)


def drill_payload(chain_id=8453):
    return security._drill_payload(
        actor=security.SecurityActor(ceremony_id="0x"+"11"*32, ceremony_slot=1,
            authority_slot=0, wallet="0x"+"22"*20, source="launch_session"),
        guardian=Account.from_key("0x"+"73"*32).address,
        recovery_bls_pubkey="0x"+"44"*48, revision=1,
        nonce="0x"+"55"*32, expires_at=2_000_000_000, evm_chain_id=chain_id,
    )


def test_recovery_drill_changes_both_signing_domains_and_payload_hash():
    mainnet, historical = drill_payload(), drill_payload(84532)
    typed = security._drill_typed_data(mainnet)
    assert typed["domain"] == {"name": "Solslot Admin Recovery", "version": "2", "chainId": 8453}
    assert security._drill_typed_data(historical)["domain"]["version"] == "1"
    assert "evmChainId" not in historical
    assert security._drill_bls_digest(mainnet) != security._drill_bls_digest(historical)
    assert security._canonical_hash(mainnet) != security._canonical_hash(historical)
    guardian = Account.from_key("0x"+"73"*32)
    signature = "0x" + guardian.sign_message(encode_typed_data(full_message=typed)).signature.hex()
    assert recover_evm_signer(typed, signature).address.lower() == guardian.address.lower()
    assert recover_evm_signer(security._drill_typed_data(historical), signature).address.lower() != guardian.address.lower()
    for changed in ({**mainnet, "evmChainId": 84532}, {**mainnet, "schemaVersion": 1}):
        with pytest.raises(ValueError):
            security._drill_typed_data(changed)


def test_lost_key_authorization_is_bound_to_mainnet_intent():
    raw = json.loads(FIXTURE.read_text())["intent"]
    guardian = Account.from_key("0x"+"73"*32)
    raw.update(kind="LOST", evmChainId=8453, oldRecoveryGuardian=guardian.address,
               newRecoveryGuardian=guardian.address)
    intent = changes.AdminKeyChangeIntentV1.model_validate(raw)
    coordinator = "0x"+"84"*20
    intent_hash = changes.hash_admin_key_change_intent(intent)
    for chain in (8453, 84532):
        typed = changes.lost_key_authorization_typed_data(intent_hash, coordinator, chain_id=chain)
        signature = "0x" + guardian.sign_message(encode_typed_data(full_message=typed)).signature.hex()
        args = dict(intent=intent, coordinator=coordinator, guardian_signature=signature)
        if chain == 8453:
            assert changes.verify_lost_guardian_authorization(**args).lower() == guardian.address.lower()
        else:
            with pytest.raises(ValueError, match="guardian"):
                changes.verify_lost_guardian_authorization(**args)
    assert intent_hash != changes.hash_admin_key_change_intent(intent.model_copy(update={"evm_chain_id": 84532}))


@pytest.mark.parametrize("action", ["ACCEPT", "VETO"])
def test_recovery_kit_guardian_mainnet_signature(action):
    raw = json.loads(FIXTURE.read_text())["intent"]
    old, new = Account.from_key("0x"+"73"*32), Account.from_key("0x"+"74"*32)
    raw.update(kind="RECOVERY_KIT", evmChainId=8453, oldRecoveryGuardian=old.address,
        newRecoveryGuardian=new.address, newDailyEvmKey=raw["oldDailyEvmKey"],
        newDailyChiaKey=raw["oldDailyChiaKey"], newRecoveryBlsKey="0x"+bytes(AugSchemeMPL.key_gen(b"mainnet recovery fixture"*2).get_g1()).hex())
    intent = changes.AdminKeyChangeIntentV1.model_validate(raw)
    guardian = new if action == "ACCEPT" else old
    coordinator = "0x"+"84"*20
    intent_hash = changes.hash_admin_key_change_intent(intent)
    for chain in (8453, 84532):
        typed = changes.recovery_guardian_action_typed_data(intent_hash, coordinator, action, chain_id=chain)
        signature = "0x" + guardian.sign_message(encode_typed_data(full_message=typed)).signature.hex()
        args = dict(intent=intent, coordinator=coordinator, action=action, guardian_signature=signature)
        if chain == 8453:
            assert changes.verify_recovery_guardian_action_authorization(**args).lower() == guardian.address.lower()
        else:
            with pytest.raises(ValueError, match="signer"):
                changes.verify_recovery_guardian_action_authorization(**args)


def test_mainnet_safe_messages_have_distinct_digest_and_broadcast_chain():
    from tests.test_safe_rpc_binding import standard_transaction
    tx = standard_transaction()
    safe = "0x"+"51"*20
    mainnet = changes._safe_transaction_typed_data(safe, tx, chain_id=8453)
    historical = changes._safe_transaction_typed_data(safe, tx)
    assert changes._safe_typed_data_digest(mainnet) != changes._safe_typed_data_digest(historical)
    assert changes._safe_message_typed_data(safe, "0x1234", chain_id=8453)["domain"]["chainId"] == 8453
    assert changes._safe_exec_transaction({"safe": safe, "chainId": 8453, "transaction": tx}, b"")["chainId"] == 8453


@pytest.mark.asyncio
@pytest.mark.parametrize("rpc_chain", [8453, 84532])
async def test_authenticated_authority_context_rejects_wrong_rpc(monkeypatch, rpc_chain):
    from eth_utils import keccak
    artifact = {**mainnet_document(), "adminAuthority": {
        "version": 3, "sourceManifestHash": "0x"+"ab"*32,
        "identityVaults": [{"launcherId": "0x"+f"{i+1:02x}"*32} for i in range(3)],
    }, "launcherIds": {"adminAuthority": "0x"+"cd"*32}}
    evidence = {"network": "baseMainnet", "chainId": 8453, "chiaAuthority": {
        "authorityLauncherId": artifact["launcherIds"]["adminAuthority"],
        "sourceManifestHash": artifact["adminAuthority"]["sourceManifestHash"],
        "identityLauncherIds": [x["launcherId"] for x in artifact["adminAuthority"]["identityVaults"]],
    }, "recovery": {"address": "0x"+"12"*20},
        "runtimeCodeHashes": {"recovery": "0x"+keccak(bytes.fromhex("1234")).hex()}}
    monkeypatch.setattr(changes, "load_signed_public_artifact", lambda _: artifact)
    monkeypatch.setattr(changes, "load_governance_evidence", lambda _: evidence)
    calls = []
    async def rpc(_settings, method, _params):
        calls.append(method)
        return {"eth_getCode": "0x1234", "eth_chainId": hex(rpc_chain)}[method]
    monkeypatch.setattr(changes, "_rpc", rpc)
    if rpc_chain == 8453:
        result = await changes._verified_evidence_context(object())
        assert result[1]["chainId"] == 8453
    else:
        with pytest.raises(ValueError, match="wrong EVM network"):
            await changes._verified_evidence_context(object())
    calls.clear()
    evidence["chainId"] = 84532
    evidence["network"] = "baseSepolia"
    with pytest.raises(ValueError, match="wrong EVM network"):
        await changes._verified_evidence_context(object())
    assert calls == []
