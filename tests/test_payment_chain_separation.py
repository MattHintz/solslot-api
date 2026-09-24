"""Payment Safe domains are explicit and independent of identity enrollment."""
import json
from types import SimpleNamespace

import pytest
from eth_account import Account
from pydantic import ValidationError

from solslot_api.config import Settings
from solslot_api import omnichain_ownership_activation as ownership
from tests.test_omnichain_ownership_activation import (
    _write_package, _write_execute_package, _signature,
)


def seal(path, package, chain):
    package['chainId'] = chain
    package['network'] = {8453: 'baseMainnet', 84532: 'baseSepolia'}[chain]
    for approval in package['authorityOperation']['approvals']:
        approval['typedData']['domain']['chainId'] = chain
        approval['messageHash'] = ownership._typed_data_digest(approval['typedData'])
    package.pop('artifactHash', None)
    package['artifactHash'] = ownership._canonical_hash(package)
    path.write_text(json.dumps(package))
    return package


@pytest.fixture(params=[8453, 84532])
def payment_case(tmp_path, request):
    owner, coadmin = Account.create(), Account.create()
    path = tmp_path / 'schedule.json'
    package = seal(path, _write_package(path, owner_address=owner.address,
                   coadmin_addresses=[coadmin.address]), request.param)
    settings = Settings(payment_omnichain_chain_id=request.param,
                        payment_omnichain_ownership_safe_operation_path=str(path),
                        payment_omnichain_ownership_safe_operation_hash=package['artifactHash'])
    return settings, package, owner, coadmin


def test_schedule_and_execute_keep_selected_payment_chain(payment_case, tmp_path):
    settings, package, owner, coadmin = payment_case
    assert settings.zkpassport_evm_chain_id == 11155111
    assert settings.eip712_chain_id == 11155111
    assert ownership.load_authority_operation(settings)['chainId'] == settings.payment_omnichain_chain_id
    path = tmp_path / 'execute.json'
    execute = seal(path, _write_execute_package(path, schedule=package,
                   owner_address=owner.address, coadmin_addresses=[coadmin.address]), package['chainId'])
    settings.payment_omnichain_ownership_execute_operation_path = str(path)
    settings.payment_omnichain_ownership_execute_operation_hash = execute['artifactHash']
    loaded = ownership.load_authority_operation(settings, phase='execute')
    approvals = {a['role']: {'signature': _signature(account, a['typedData'])}
                 for a, account in zip(loaded['authorityOperation']['approvals'], [owner, coadmin])}
    assert ownership._build_exec_transaction(loaded, approvals)['chainId'] == str(package['chainId'])
    execute['derivedFromScheduleArtifactHash'] = package['artifactHash']
    execute = seal(path, execute, package['chainId'])
    assert ownership._validate_derived_execute_package(execute, schedule_package=package)['chainId'] == package['chainId']


def test_other_network_package_is_rejected(payment_case):
    settings, package, *_ = payment_case
    settings.payment_omnichain_chain_id = 84532 if package['chainId'] == 8453 else 8453
    with pytest.raises(ownership.OwnershipActivationError, match='schema'):
        ownership.load_authority_operation(settings)


def test_resealed_cross_chain_approval_is_rejected(payment_case):
    settings, package, *_ = payment_case
    approval = package['authorityOperation']['approvals'][0]
    approval['typedData']['domain']['chainId'] = 84532 if package['chainId'] == 8453 else 8453
    approval['messageHash'] = ownership._typed_data_digest(approval['typedData'])
    package.pop('artifactHash')
    package['artifactHash'] = ownership._canonical_hash(package)
    from pathlib import Path
    Path(settings.payment_omnichain_ownership_safe_operation_path).write_text(json.dumps(package))
    settings.payment_omnichain_ownership_safe_operation_hash = package['artifactHash']
    with pytest.raises(ownership.OwnershipActivationError):
        ownership.load_authority_operation(settings)


@pytest.mark.parametrize('selected', [8453, 84532])
def test_rpc_network_checked_before_use(monkeypatch, selected):
    settings = Settings(payment_omnichain_chain_id=selected, payment_omnichain_rpc_url='https://rpc.invalid')
    fake = SimpleNamespace(eth=SimpleNamespace(chain_id=selected))
    class Factory:
        HTTPProvider = staticmethod(lambda *args, **kwargs: None)
        def __new__(cls, provider):
            return fake
    monkeypatch.setattr(ownership, 'Web3', Factory)
    assert ownership._web3(settings) is fake
    fake.eth.chain_id = 84532 if selected == 8453 else 8453
    with pytest.raises(ownership.OwnershipActivationError, match='wrong EVM network'):
        ownership._web3(settings)


@pytest.mark.parametrize('chain', [1, 11155111, True, 0])
def test_unsupported_payment_network_rejected(chain):
    with pytest.raises(ValidationError):
        Settings(payment_omnichain_chain_id=chain)
