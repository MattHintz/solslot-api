"""Synthetic relayer credentials; no user wallet, live secret or signature."""
import os
import pytest
from eth_account import Account
from solslot_api.generation_customer_identity_credentials import current_relayer_account


@pytest.fixture
def credential(tmp_path):
    value = '13' * 32
    path = tmp_path / 'synthetic.key'; path.write_text(value); path.chmod(0o400)
    return path, Account.from_key(value).address


def test_matches_exact_reviewed_public_identity(credential):
    path, address = credential
    assert current_relayer_account(path, address).address == address


@pytest.mark.parametrize('mode', [0o444, 0o644, 0o460, 0o407])
def test_weak_file_permissions_are_rejected(credential, mode):
    path, address = credential; path.chmod(mode)
    with pytest.raises(ValueError, match='FILE_REJECTED'): current_relayer_account(path, address)


def test_rejects_symlink_and_hardlink(credential, tmp_path):
    path, address = credential
    symbolic = tmp_path / 'link'; symbolic.symlink_to(path)
    with pytest.raises(OSError): current_relayer_account(symbolic, address)
    hard = tmp_path / 'hard'; os.link(path, hard)
    with pytest.raises(ValueError): current_relayer_account(path, address)


def test_rejects_different_wallet_without_exposing_material(credential):
    path, _ = credential
    with pytest.raises(ValueError, match='PUBLIC_BINDING_CHANGED') as error:
        current_relayer_account(path, '0x' + '11' * 20)
    assert path.read_text() not in str(error.value)


@pytest.mark.parametrize('raw', ['00' * 32, 'not-a-key', ' 13' * 64, '0x' + 'q' * 64])
def test_invalid_material_is_not_in_error(credential, raw):
    path, address = credential; path.chmod(0o600); path.write_text(raw); path.chmod(0o400)
    with pytest.raises(ValueError) as error: current_relayer_account(path, address)
    assert raw not in str(error.value)
