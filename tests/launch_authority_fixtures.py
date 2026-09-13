"""Local authority fixtures; never used by the application."""

from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_typed_data

from solslot_api.admin_roster import current_launch_authority
from solslot_api.config import Settings
from solslot_api.genesis_store import launch_gate_action_id
from solslot_api.launch_control import _action_typed_data


def bootstrap_settings(store):
    root = Path(store.path).parent
    return Settings(_env_file=None, runtime_environment="test", network="testnet11",
                    genesis_db_path=store.path, public_artifact_path=str(root / "not-published.json"),
                    bootstrap_manifest_path=str(root / "not-locked.json"))


def install_signed_authority(settings, ceremony_id, accounts):
    # Imported lazily because the complete artifact fixture uses the genesis
    # plan fixture. Signatures go through the real artifact verifier.
    from tests.test_public_artifact import _settings, _signed_artifact
    accounts = [*accounts]
    while len(accounts) < 3:
        accounts.append(Account.create())
    artifact = _signed_artifact(accounts=accounts, ceremony_id=ceremony_id, signed_slots=(0, 1))
    evidence = _settings(Path(settings.genesis_db_path).parent, artifact)
    for name in (
        "public_artifact_path", "release_metadata_path", "pool_launcher_id",
        "governance_launcher_id", "protocol_config_launcher_id", "vault_version_registry_launcher_id",
        "zkpassport_bridge_policy_hash", "zkpassport_forwarder_address",
        "zkpassport_verifier_adapter_address", "zkpassport_emitter_address", "zkpassport_validator_pubkeys",
    ):
        setattr(settings, name, getattr(evidence, name))
    return accounts


def open_signed_gate(store, settings, ceremony_id, gate_name, *, now, opens_at, closes_at,
                     payload_hash, accounts=()):
    store.upsert_gate(ceremony_id, gate_name=gate_name, opens_at=opens_at, closes_at=closes_at,
                      payload_hash=payload_hash, state="pending", now=now)
    action_id = launch_gate_action_id(ceremony_id, gate_name, payload_hash)
    authority = current_launch_authority(settings, store, ceremony_id)
    available = {account.address.lower(): account for account in accounts}
    approved_slots = store.action_approvals(ceremony_id, action_id, settings=settings, now=now)["slots"]
    for slot in (1, 2):
        if slot in approved_slots:
            continue
        wallet = authority.wallets[slot]
        typed = _action_typed_data(ceremony_id=ceremony_id, action_type=f"gate:{gate_name}",
            action_id=action_id, payload_hash=payload_hash, expires_at=now + 600)
        # Store-level fixtures may supply an already-verified opaque signature;
        # request/signature verification is exercised by endpoint tests.
        signature = ("0x" + bytes(available[wallet].sign_message(encode_typed_data(full_message=typed)).signature).hex()
                     if wallet in available else "0x" + f"{slot:02x}" * 65)
        store.add_action_approval(ceremony_id, settings=settings, action_id=action_id,
            action_type=f"gate:{gate_name}", payload_hash=payload_hash, slot=slot,
            signer_address=wallet, signature=signature, expires_at=now + 600, now=now)
    return store.upsert_gate(ceremony_id, settings=settings, gate_name=gate_name,
                            opens_at=opens_at, closes_at=closes_at, payload_hash=payload_hash,
                            state="open", now=now)
