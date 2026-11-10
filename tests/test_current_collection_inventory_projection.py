import asyncio
from dataclasses import replace
from types import SimpleNamespace
import pytest
from tests.test_current_collection_issuer_policy import make_policy
from tests.test_native_purchases import _b32
from solslot_api.generation_customer_purchase_execution import CurrentNativePurchaseExecution


@pytest.mark.asyncio
async def test_collection_inventory_uses_session_launcher_and_stays_unavailable_until_runtime_enabled(monkeypatch):
    policy,terms=make_policy();service=CurrentNativePurchaseExecution.__new__(CurrentNativePurchaseExecution)
    service.policy=policy;service.settings=object();service.anchor=object();service.provider=object();service.clock=lambda:1234
    service.submitter=None
    service._readiness_lock=asyncio.Lock()
    service._last_readiness=None
    item=SimpleNamespace(available=True,original=SimpleNamespace(terms=terms))
    chain=SimpleNamespace(registry=SimpleNamespace(state=SimpleNamespace(pause_mask=0)))
    inventory=SimpleNamespace(items=(item,),evidence=chain,public=lambda:{'schema':'solslot.current-primary-inventory.v1',
        'generationId':'0x'+policy.generation.hex(),'network':'testnet11','items':[{'status':'AVAILABLE'}]})
    async def resolve(**_):return inventory
    monkeypatch.setattr('solslot_api.generation_customer_purchase_execution.resolve_current_primary_inventory',resolve)
    result=await service.inventory(receiving_launcher=_b32(9))
    assert result['schema']=='solslot.current-primary-inventory.v2'
    assert result['receivingVaultLauncherId']=='0x'+_b32(9).hex()
    assert result['items']==[{'status':'AVAILABLE','deedLauncherPuzzleHash':'0x'+terms.deed_launcher_puzzle_hash.hex(),
        'smartDeedInnerHash':'0x'+terms.smart_deed_inner_hash.hex()}]
    assert result['execution']=={'status':'UNAVAILABLE','code':'CURRENT_EXECUTION_OPERATIONAL_PAUSED','checkedAt':1234}
    assert 'withinTestPolicy' not in result['items'][0] and 'purchaseWindowOpen' not in result
    with pytest.raises(ValueError,match='RECEIVING_VAULT_REQUIRED'):await service.inventory()


@pytest.mark.asyncio
@pytest.mark.parametrize('state,count,status', [
    ('READY', 25, 'OPEN'), ('PAUSED', 25, 'NOT_OPEN'),
    ('UNAVAILABLE', 25, 'UNAVAILABLE'), ('READY', 0, 'NOT_OPEN'),
])
async def test_public_sale_uses_collection_inventory_and_actual_readiness(state,count,status):
    from solslot_api.generation_public_catalog import _collection_sale

    policy = replace(make_policy()[0], test_usd_minor_per_txch=3_000_000)
    async def inventory():
        return SimpleNamespace(edition=policy.edition, metadata_root=policy.metadata_root,
            items=tuple(SimpleNamespace(available=index < count) for index in range(25)))
    async def readiness(_):
        return {'status': state}
    service = SimpleNamespace(policy=policy, clock=lambda:1234, inventory_snapshot=inventory,
        collection_readiness=readiness, store=SimpleNamespace(generation_id='0x'+policy.generation.hex()))
    result = await _collection_sale(service, None, True)
    sale = result['sale']
    assert sale['schema'] == 'solslot.current-primary-sale.v2'
    assert sale['status'] == status and sale['availableDeeds'] == count
    assert sale['paymentRails'] == (['CHIA_XCH'] if status == 'OPEN' else [])
    assert not {'limitedTest', 'expiresAt'} & sale.keys()
