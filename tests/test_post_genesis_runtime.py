from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from solslot_api.post_genesis_runtime import native_submitter_after_seal
from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy


class TemporaryGenesisAdapter:
    def __init__(self, base):
        self.base = base


def activate(adapter, **overrides):
    values = dict(
        adapter_type=TemporaryGenesisAdapter,
        verified_artifact={'artifactHash': 'sealed', 'network': 'testnet11'},
        ceremony={'state': 'locked', 'ceremony_id': 'ceremony', 'artifact_hash': 'sealed'},
        expected_artifact_hash='sealed', expected_ceremony_id='ceremony',
    )
    values.update(overrides)
    return native_submitter_after_seal(adapter, **values)


def test_preserves_native_fee_policy_and_existing_reservation_store():
    # The repaired path must keep the original instance: replacing it with a
    # newly constructed submitter would lose live reservation providers.
    base = object.__new__(ProtocolBundleSubmitter)
    base.policy = ProtocolFeePolicy(minimum_mojos=100_000_000, maximum_mojos=1_000_000_000)
    base.funding_store = object()
    result = activate(TemporaryGenesisAdapter(base))
    assert result is base
    assert result.policy.maximum_mojos == 1_000_000_000
    assert result.funding_store is base.funding_store


@pytest.mark.parametrize('state', ['planned', 'broadcast', 'confirmed', 'artifact_signed'])
def test_never_retires_adapter_before_archive_is_locked(state):
    with pytest.raises(RuntimeError, match='exact sealed'):
        activate(TemporaryGenesisAdapter(object.__new__(ProtocolBundleSubmitter)),
                 ceremony={'state': state, 'ceremony_id': 'ceremony', 'artifact_hash': 'sealed'})


@pytest.mark.parametrize('override', [
    {'verified_artifact': {'artifactHash': 'different', 'network': 'testnet11'}},
    {'verified_artifact': {'artifactHash': 'sealed', 'network': 'mainnet'}},
    {'expected_ceremony_id': 'other'},
    {'expected_artifact_hash': 'other'},
])
def test_rejects_other_launch_or_network(override):
    with pytest.raises(RuntimeError, match='exact sealed'):
        activate(TemporaryGenesisAdapter(object.__new__(ProtocolBundleSubmitter)), **override)


def test_rejects_unknown_adapter_or_non_native_fee_service():
    with pytest.raises(RuntimeError, match='Unexpected genesis'):
        activate(SimpleNamespace(base=object.__new__(ProtocolBundleSubmitter)))
    with pytest.raises(RuntimeError, match='native fee service is unavailable'):
        activate(TemporaryGenesisAdapter(object()))


@pytest.mark.asyncio
async def test_vault_route_uses_same_native_funded_submission(monkeypatch):
    import solslot_api.app as module
    base = object.__new__(ProtocolBundleSubmitter)
    funded = SimpleNamespace(to_json_dict=lambda: {'funded': True})
    async def submit(bundle, *, before_push):
        assert bundle == {'original': True}
        before_push(SimpleNamespace(bundle=funded))
    base.submit = AsyncMock(side_effect=submit)
    restored = activate(TemporaryGenesisAdapter(base))
    monkeypatch.setattr(module.app.state, 'protocol_submitter', restored, raising=False)
    launched = SimpleNamespace(spend_bundle=SimpleNamespace(to_json_dict=lambda: {'original': True}))
    result = await module._push_vault_launch(None, launched, SimpleNamespace(protocol_fee_funding_enabled=True))
    assert result == (True, 'MEMPOOL')
    assert launched.spend_bundle is funded
    base.submit.assert_awaited_once()
