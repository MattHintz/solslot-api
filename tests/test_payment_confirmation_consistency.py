from types import SimpleNamespace

import pytest
from eth_account import Account
from fastapi import HTTPException

import solslot_api.launch_control as launch
import solslot_api.omnichain_ownership_activation as ownership
from solslot_api.config import Settings
from tests.test_omnichain_ownership_activation import (
    ROOT_SAFE, TIMELOCK, _scheduled_chain_state, _signature, _write_package,
)


@pytest.mark.parametrize('mined', [False, True])
def test_chain_observation_cannot_mix_pre_and_post_inclusion_blocks(tmp_path, monkeypatch, mined):
    owner, coadmin = Account.create(), Account.create()
    package = _write_package(tmp_path / 'package.json', owner_address=owner.address,
                             coadmin_addresses=[coadmin.address])
    calls = []
    observed_block = 101 if mined else 100

    class Function:
        def __init__(self, name):
            self.name = name

        def call(self, *, block_identifier):
            calls.append((self.name, block_identifier))
            included = block_identifier >= 101
            return {
                'isOperation': included, 'isOperationReady': False,
                'isOperationDone': False, 'getTimestamp': 2_000_000_000 if included else 0,
                'nonce': 1 if included else 0,
                'getTransactionHash': bytes.fromhex(package['authorityOperation']['transactionHash'][2:]),
            }[self.name]

    functions = SimpleNamespace(**{name: (lambda *args, name=name: Function(name)) for name in
        ('isOperation', 'isOperationReady', 'isOperationDone', 'getTimestamp', 'nonce', 'getTransactionHash')})
    eth = SimpleNamespace(block_number=observed_block,
        contract=lambda **kwargs: SimpleNamespace(functions=functions))
    monkeypatch.setattr(ownership, '_web3', lambda _: SimpleNamespace(eth=eth))
    state = ownership._chain_state(Settings(_env_file=None), package)
    assert state.operation_exists is mined
    assert state.live_nonce == int(mined)
    assert state.latest_block == observed_block
    assert len(calls) == 6 and {block for _, block in calls} == {observed_block}


@pytest.mark.parametrize('missing_approval', [False, True])
def test_guided_recorder_reconciles_mined_schedule_before_display_phase_advances(
    tmp_path, monkeypatch, missing_approval,
):
    owner, coadmin = Account.create(), Account.create()
    path = tmp_path / 'operation.json'
    raw = _write_package(path, owner_address=owner.address, coadmin_addresses=[coadmin.address])
    settings = Settings(_env_file=None, runtime_environment='test',
        payment_omnichain_ownership_activation_enabled=True,
        payment_omnichain_ownership_safe_operation_path=str(path),
        payment_omnichain_ownership_safe_operation_hash=raw['artifactHash'],
        admin_db_path=str(tmp_path / 'admin.db'))
    store = ownership.OwnershipActivationStore(settings.admin_db_path)
    descriptors = {d['role']: d for d in raw['authorityOperation']['approvals']}
    for role, account in [('owner_identity', owner), ('coadmin', coadmin)]:
        if missing_approval and role == 'coadmin':
            continue
        store.add_approval(package_hash=raw['artifactHash'], role=role,
            signer_address=account.address, signature=_signature(account, descriptors[role]['typedData']), now=1)
    monkeypatch.setattr(ownership, '_chain_state', lambda *_: _scheduled_chain_state())
    monkeypatch.setattr(ownership, '_verify_broadcast', lambda **_: (101, 12, owner.address))
    # This is precisely the advanced display state that must not reject the
    # earlier submitted schedule before the native receipt verifier runs.
    monkeypatch.setattr(launch, '_rail_phase_status', lambda *_: {'phase': 'execute'})
    session = launch.LaunchSession('ceremony', 0, owner.address, False, 2_000_000_000)
    body = launch.RailBroadcastSubmission(phase='schedule', transactionHash='0x' + '99' * 32)
    if missing_approval:
        with pytest.raises(HTTPException) as error:
            launch.guided_record_rail_broadcast(body, settings, store, session)
        assert error.value.status_code == 409
        assert store.broadcast(raw['artifactHash']) is None
    else:
        result = launch.guided_record_rail_broadcast(body, settings, store, session)
        assert result['status']['state'] == 'SCHEDULED'
        assert store.broadcast(raw['artifactHash'])['transactionHash'] == body.transaction_hash


def test_guided_recorder_still_requires_enrolled_wallet_session():
    session = launch.LaunchSession('ceremony', 0, None, True, 2_000_000_000)
    body = launch.RailBroadcastSubmission(phase='schedule', transactionHash='0x' + '99' * 32)
    with pytest.raises(HTTPException) as error:
        launch.guided_record_rail_broadcast(body, None, None, session)
    assert error.value.status_code == 401
