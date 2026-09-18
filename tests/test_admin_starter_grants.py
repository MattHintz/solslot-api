from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from solslot_api import governance_endpoints as endpoints
from solslot_api.governance_queue import GovernanceQueueStore


@pytest.mark.asyncio
async def test_starter_preview_uses_current_stake_and_three_explicit_vaults(monkeypatch, tmp_path):
    vaults = ['0x' + bytes([i]).hex() * 32 for i in (1, 2, 3)]
    artifact = {'genesisPlan': {'launcherIds': {'statutes': '0x'+'11'*32, 'adminAuthority': '0x'+'22'*32}}}
    monkeypatch.setattr(endpoints, 'require_sgt_allocation_drafts', lambda _: None)
    monkeypatch.setattr(endpoints, 'load_signed_public_artifact', lambda _: artifact)
    monkeypatch.setattr(endpoints, 'require_current_approved_vault', lambda _, value: SimpleNamespace(launcher_id=value))
    async def tip(*_): return {}
    async def statutes(*_):
        return SimpleNamespace(parameters=SimpleNamespace(min_proposal_stake=15000), live_coin_id='0x'+'33'*32)
    monkeypatch.setattr('solslot_api.sols_swaps._required_singleton_tip', tip)
    monkeypatch.setattr('solslot_api.sols_market._statutes_snapshot', statutes)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(coinset=object())))
    body = endpoints.StarterGrantRecipients(vaultLauncherIds=vaults)
    preview = await endpoints.preview_starter_grants(body, request, None, None)
    assert preview['amountPerAdministrator'] == '15000'
    assert preview['totalAmount'] == '45000'
    assert [item['recipientVaultLauncherId'] for item in preview['proposals']] == vaults
    assert all(item['kind'] == 'SGT_GRANT' for item in preview['proposals'])
    assert len({item['grantId'] for item in preview['proposals']}) == 3
    assert await endpoints.preview_starter_grants(body, request, None, None) == preview
    # Preview never creates a queue row or grants an approval.
    store = GovernanceQueueStore(str(tmp_path / 'queue.db'))
    assert store.list() == []
    store.close()
    def denied(*_): raise ValueError('vault enrollment is not current')
    monkeypatch.setattr(endpoints, 'require_current_approved_vault', denied)
    with pytest.raises(HTTPException, match='409'):
        await endpoints.preview_starter_grants(body, request, None, None)


@pytest.mark.parametrize('vaults', [[], ['0x'+'01'*32]*3, ['0x'+'00'*32, '0x'+'01'*32, '0x'+'02'*32]])
def test_starter_recipients_require_three_distinct_nonzero_vaults(vaults):
    with pytest.raises(ValueError):
        endpoints.StarterGrantRecipients(vaultLauncherIds=vaults)
