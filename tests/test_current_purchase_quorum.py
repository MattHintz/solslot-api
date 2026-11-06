"""Partial private delivery responses survive interruption, with real BLS checks."""
import asyncio
from types import SimpleNamespace
import pytest
from chia_rs import AugSchemeMPL,G2Element
from solslot_api.generation_customer_purchase_reservation import CurrentReservationClaim,CurrentReservationEvidence
from solslot_api.generation_customer_purchase_quorum import collect_current_purchase_quorum
from solslot_api import generation_customer_purchase_quorum as quorum
from tests.test_generation_customer_purchase_reservation_claim import body


def fixture(monkeypatch):
 keys=[AugSchemeMPL.key_gen(bytes([n])*32)for n in(31,32,33)]
 roster=[bytes(k.get_g1())for k in keys];claim=CurrentReservationClaim.model_validate(body());messages={i:b'synthetic-native-reservation-'+bytes([i])for i in(0,1)}
 settings=SimpleNamespace(zkpassport_validator_pubkeys=['0x'+p.hex()for p in roster],zkpassport_validator_threshold=2,
  zkpassport_validator_urls=['https://private-'+str(i)+'.invalid'for i in range(3)])
 evidence=CurrentReservationEvidence(claim,None,None,SimpleNamespace(original=SimpleNamespace(terms=None)),None,None,None)
 monkeypatch.setattr(quorum,'native_messages',lambda *args:messages)
 replies={i:{'claimHash':claim.digest(),'signerIndex':i,'validatorPubkey':'0x'+roster[i].hex(),
  'signature':'0x'+bytes(AugSchemeMPL.sign(keys[i],messages[i])).hex()}for i in(0,1)}
 return settings,evidence,replies

class Client:
 def __init__(self,replies,fail=False):self.replies=replies;self.fail=fail;self.calls=[]
 async def post(self,url,*,json,timeout):
  index=0 if 'private-0.'in url else 1;self.calls.append(index)
  assert url.endswith('/v1/generation/purchase/reservation/sign')and timeout==50
  if index==1 and self.fail:await asyncio.sleep(0.01);raise OSError('synthetic lost response')
  return SimpleNamespace(raise_for_status=lambda:None,json=lambda:self.replies[index])

@pytest.mark.asyncio
async def test_partial_reply_is_saved_then_retry_requests_only_missing_peer(monkeypatch):
 settings,evidence,replies=fixture(monkeypatch);retained={};first=Client(replies,True)
 with pytest.raises(OSError):await collect_current_purchase_quorum(settings,evidence,client=first,on_signature=lambda i,r:retained.__setitem__(i,r))
 assert set(retained)=={0}
 retry=Client(replies)
 got=await collect_current_purchase_quorum(settings,evidence,client=retry,retained=retained,on_signature=lambda i,r:retained.__setitem__(i,r))
 assert retry.calls==[1]and set(retained)=={0,1}
 expected=AugSchemeMPL.aggregate([G2Element.from_bytes(bytes.fromhex(replies[i]['signature'][2:]))for i in(0,1)])
 assert got==expected
 idle=Client(replies)
 assert await collect_current_purchase_quorum(settings,evidence,client=idle,retained=retained)==got and idle.calls==[]

@pytest.mark.asyncio
@pytest.mark.parametrize('change',[{'claimHash':'0x'+'99'*32},{'signerIndex':2},{'validatorPubkey':'0x'+'00'*48},{'signature':'0x'+bytes(G2Element()).hex()}])
async def test_wrong_private_reply_cannot_join_a_native_quorum(monkeypatch,change):
 settings,evidence,replies=fixture(monkeypatch);replies[0]={**replies[0],**change}
 with pytest.raises(ValueError):await collect_current_purchase_quorum(settings,evidence,client=Client(replies))

@pytest.mark.asyncio
@pytest.mark.parametrize('retained',[{'0':{}},{2:{}},{True:{}}])
async def test_noncanonical_saved_signer_indices_stop_before_network(monkeypatch,retained):
 settings,evidence,replies=fixture(monkeypatch);client=Client(replies)
 with pytest.raises(ValueError):await collect_current_purchase_quorum(settings,evidence,client=client,retained=retained)
 assert not client.calls
