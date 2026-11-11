"""Primary-only expired authorization proof; no credentials or endpoint changes."""
from time import time
import pytest
from solslot_api.chia_provider import ChiaProviderError
from solslot_api.generation_customer_purchase_validators import prove_primary_expired_source
from tests.test_chia_snapshot import Node,provider,COIN,HX

pytestmark=pytest.mark.asyncio

async def test_expired_source_uses_real_snapshot_clock_and_no_fee_or_mempool_api():
 node=Node();p=provider(node)
 async def unsupported(*a,**kw):raise AssertionError('read-only gateway must not need this method')
 node.get_fee_estimate=unsupported;node.get_mempool_items_by_coin_name=unsupported
 expiry=node.clock-1
 result=await prove_primary_expired_source(p,COIN,expiry)
 assert result['sourceCoinId']==HX and result['expiresAt']==expiry
 assert result['transactionTimestamp']>=expiry and result['spentHeight']==0
 assert result['authority']=='CONFIGURED_PRIMARY_FULL_NODE' and result['consensusInclusionProven']is False
 assert not p.fallback.calls

async def test_local_time_cannot_expire_authorization_ahead_of_primary_block_time():
 node=Node();p=provider(node)
 with pytest.raises(ValueError,match='NOT_EXPIRED_ON_CHAIN'):
  await prove_primary_expired_source(p,COIN,node.clock+1)
 assert not node.calls and not p.fallback.calls

@pytest.mark.parametrize('changed',['spent','missing','wrong_coin','stale_clock','wrong_network','not_synced','changed_peak','future_height'])
async def test_bad_current_primary_evidence_cannot_retire_a_signature(changed):
 node=Node();p=provider(node);expiry=int(time())-1
 if changed=='spent':node.records[HX].update(spent=True,spent_block_index=99)
 elif changed=='missing':node.records.pop(HX)
 elif changed=='wrong_coin':node.records[HX]['coin']['amount']+=1
 elif changed=='stale_clock':node.clock-=400
 elif changed=='future_height':node.records[HX]['confirmed_block_index']=101
 elif changed=='wrong_network':node.info['network_name']='mainnet'
 elif changed=='not_synced':node.state['blockchain_state']['sync']['synced']=False
 else:
  old=node.get_coin_record_by_name
  async def mutate(name):
   result=await old(name);node.state['blockchain_state']['peak']['header_hash']='44'*32;return result
  node.get_coin_record_by_name=mutate
 with pytest.raises((ValueError,ChiaProviderError)):
  await prove_primary_expired_source(p,COIN,expiry)
 assert not p.fallback.calls
