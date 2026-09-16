from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException

from solslot_api import validator_service, zkpassport_enrollments as enroll
from solslot_api.config import Settings
from solslot_api.vault_chain_evidence import (
    resolve_enrolled_vault_tip, verify_enrolled_vault_tip, VaultHistoryError,
)
from solslot_api.vault_eligibility import require_current_approved_vault

FIXTURES = json.loads((Path(__file__).parent / 'fixtures/vault-history-v1.json').read_text())


def b(value):
    return bytes32.fromhex(value.removeprefix('0x'))


def kwargs(f):
    return dict(launcher_id=b(f['launcherId']),
                unstamped_puzzle_hash=b(f['unstampedHash']),
                stamped_puzzle_hash=b(f['stampedHash']),
                fetch_coin=lambda coin_id: f['records'].get('0x' + coin_id.hex()))


@pytest.mark.parametrize('source', FIXTURES, ids=['bls', 'evm'])
def test_stamp_and_two_continuations_share_api_and_private_validator_proof(source, monkeypatch):
    f = deepcopy(source)
    for tip_id in [f['stampId'], f['firstId'], f['tipId']]:
        stage = deepcopy(f)
        stage['records'][tip_id].update(spent=False, spent_block_index=0)
        tip, stamp = resolve_enrolled_vault_tip(stamp_id=b(f['stampId']), **kwargs(stage))
        assert tip.coin.name() == b(tip_id)
        assert stamp == b(f['stampId'])
        monkeypatch.setattr(validator_service, '_fetch_coin',
            lambda _settings, coin_id, _field, **_kw: stage['records'].get(coin_id))
        # These are the actual common boundary invoked by all three validators.
        class Puzzle:
            def __init__(self, value): self.value = b(value)
            def get_tree_hash(self): return self.value
        verified = validator_service._verify_purchase_vault_history(
            None, SimpleNamespace(credential_vault_coin_id=tip_id), b(f['launcherId']),
            Puzzle(f['unstampedHash']), Puzzle(f['stampedHash']))
        assert verified == (tip, stamp)


@pytest.mark.parametrize('mutation', ['spent_tip', 'spent_flag', 'height', 'bool_height',
    'coin_alias', 'foreign_launcher', 'changed_owner', 'missing_parent', 'wrong_stamp', 'depth'])
def test_unrelated_stale_and_inconsistent_histories_fail_closed(mutation, monkeypatch):
    f = deepcopy(FIXTURES[0]); args = kwargs(f); stamp = b(f['stampId'])
    tip = f['records'][f['tipId']]
    if mutation == 'spent_tip': tip.update(spent=True, spent_block_index=14)
    elif mutation == 'spent_flag': tip['spent'] = True
    elif mutation == 'height': tip['confirmed_block_index'] += 1
    elif mutation == 'bool_height': tip['confirmed_block_index'] = True
    elif mutation == 'coin_alias': tip['coin']['parent_coin_info'] = f['launcherId']
    elif mutation == 'foreign_launcher': args['launcher_id'] = bytes32.zeros
    elif mutation == 'changed_owner': args['stamped_puzzle_hash'] = bytes32.zeros
    elif mutation == 'missing_parent': del f['records'][f['firstId']]
    elif mutation == 'wrong_stamp': stamp = b(f['firstId'])
    elif mutation == 'depth': monkeypatch.setattr('solslot_api.vault_chain_evidence.MAX_VAULT_HISTORY', 2)
    with pytest.raises(VaultHistoryError):
        resolve_enrolled_vault_tip(stamp_id=stamp, **args)


def test_tip_is_rechecked_after_ancestry_verification():
    f = deepcopy(FIXTURES[0]); args = kwargs(f); reads = 0
    def fetch(coin_id):
        nonlocal reads
        row = deepcopy(f['records'].get('0x' + coin_id.hex()))
        if coin_id == b(f['tipId']):
            reads += 1
            if reads > 1: row.update(spent=True, spent_block_index=14)
        return row
    args['fetch_coin'] = fetch
    with pytest.raises(VaultHistoryError, match='changed during'):
        verify_enrolled_vault_tip(tip_id=b(f['tipId']), **args)


@pytest.mark.parametrize('source', FIXTURES, ids=['bls', 'evm'])
def test_receipt_sync_preserves_stamp_and_advances_current_eligibility(source, monkeypatch):
    f = deepcopy(source)
    artifact_hash = '0x' + 'ee' * 32
    settings = Settings(network='testnet11', zkpassport_policy_version=2,
                        zkpassport_bridge_policy_hash=f['coordinates']['bridgePolicyHash'])
    receipt = dict(vaultLauncherId=f['launcherId'], network='testnet11', policyVersion=2,
        identityAttestRoot=f['identityRoot'], attestationLeafHash=f['identityRoot'],
        attestationProof=dict(bitpath=0,siblings=[]), bridgePolicyHash=f['coordinates']['bridgePolicyHash'],
        bridgeParentId='0x'+'aa'*32, bridgeAmount=1, bridgeCoinId='0x'+'bb'*32,
        evmTxHash='0x'+'cc'*32, chiaVaultCoinId=f['stampId'], chiaSpendBundleId='0x'+'dd'*32, enrolledAt=1)
    raw = dict(vaultLauncherId=f['launcherId'], network='testnet11', policyVersion=2,
        status='stamp_pending', bridgePolicyHash=receipt['bridgePolicyHash'],
        bridgeParentId=receipt['bridgeParentId'], bridgeAmount=1, bridgeCoinId=receipt['bridgeCoinId'],
        createdAt=1, updatedAt=1, receipt=receipt)
    class Ledger:
        def get_enrollment(self, _key): return deepcopy(raw)
        def update_enrollment(self, updated, *, expected_statuses):
            assert raw['status'] in expected_statuses
            raw.clear(); raw.update(deepcopy(updated))
    from solslot_api.state import VaultRecord
    vault = VaultRecord(launcher_id=b(f['launcherId']), full_puzhash=b(f['unstampedHash']),
        p2_vault_puzhash=bytes32.zeros, auth_type=f['owner']['authType'],
        owner_pubkey=bytes.fromhex(f['owner']['publicKey'][2:]), owner_evm_address=None,
        spend_bundle_id='synthetic-launch', pushed_at=1)
    monkeypatch.setattr(enroll, 'get_credential_ledger', lambda _settings: Ledger())
    monkeypatch.setattr(enroll, 'get_registry', lambda: SimpleNamespace(get=lambda _id: vault, record=lambda _v: None))
    monkeypatch.setattr(enroll, '_active_pool_launcher_id', lambda _: f['coordinates']['poolLauncherId'])
    monkeypatch.setattr(enroll, '_active_bridge_policy_hash', lambda _: f['coordinates']['bridgePolicyHash'])
    monkeypatch.setattr(enroll, '_active_artifact_hash', lambda _: artifact_hash)
    monkeypatch.setattr(enroll, '_fetch_coin_record_by_name', lambda _, name: f['records'].get(name))
    missing_stamp = f['records'].pop(f['stampId'])
    pending = enroll._sync_chia_stamp(settings, f['launcherId'])
    assert pending.status == 'stamp_pending'
    assert pending.receipt.chiaVaultCoinId == f['stampId']
    f['records'][f['stampId']] = missing_stamp
    stages = [(f['stampId'], 12), (f['firstId'], 13), (f['tipId'], 13)]
    for current, height in stages:
        previous = deepcopy(f['records'][current])
        f['records'][current].update(spent=False, spent_block_index=0)
        approved = require_current_approved_vault(settings, f['launcherId'], expected_current_coin_id=current)
        assert approved.current_coin_id == current
        assert approved.confirmed_block_index == height
        assert approved.enrollment.receipt.chiaStampCoinId == f['stampId']
        assert approved.enrollment.receipt.chiaSpendBundleId == receipt['chiaSpendBundleId']
        f['records'][current] = previous
    # The original stamp is never accepted as a current tip after progression.
    with pytest.raises(HTTPException, match='no longer current'):
        require_current_approved_vault(settings, f['launcherId'], expected_current_coin_id=f['stampId'])
    raw['receipt']['genesisArtifactHash'] = '0x' + 'ff' * 32
    with pytest.raises(HTTPException):
        require_current_approved_vault(settings, f['launcherId'])
    assert raw['status'] == 'receipt_syncing'
