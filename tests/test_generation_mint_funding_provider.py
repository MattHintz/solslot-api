"""Primary-only funding catalog must never use Coinset advisory fallback."""
import pytest
from solslot_api.chia_provider import ChiaProvider, ChiaProviderError
from tests.test_chia_provider import FakeRpc, config


@pytest.mark.asyncio
async def test_confirmed_catalog_reads_only_synced_primary():
    primary=FakeRpc(read_result=[{'coin':'primary'}]);fallback=FakeRpc(read_result=[{'coin':'fallback'}])
    provider=ChiaProvider(primary,fallback,config())
    assert await provider.get_coin_records_by_puzzle_hash_primary('0x'+'01'*32)==[{'coin':'primary'}]
    assert not fallback.calls


@pytest.mark.asyncio
@pytest.mark.parametrize('primary',[None,FakeRpc(read_error=TimeoutError()),FakeRpc(network='mainnet'),FakeRpc(synced=False)])
async def test_unavailable_wrong_network_or_unsynced_catalog_never_falls_back(primary):
    fallback=FakeRpc(read_result=[{'coin':'fallback'}]);provider=ChiaProvider(primary,fallback,config())
    with pytest.raises(ChiaProviderError):await provider.get_coin_records_by_puzzle_hash_primary('0x'+'01'*32)
    assert not fallback.calls
