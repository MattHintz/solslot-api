"""Private endpoint opt-in, policy pins and safe rejection, no real keys/network."""
from hashlib import sha256
from pathlib import Path
import json
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from solslot_api.generation_customer_issuer import TestnetIssuerPolicy as IssuerPolicy
from solslot_api.generation_customer_purchase_policy import read_current_issuer_policy
from solslot_api.generation_customer_purchase_delivery import CurrentDeliveryClaim
from solslot_api.validator_app import create_validator_app
from solslot_api.validator_ledger import ValidatorLedger
from tests.test_validator_app import _settings
from tests.test_generation_customer_purchase_reservation_claim import body


def policy():
 def b(n):return bytes32(bytes([n])*32)
 return IssuerPolicy(b(1),b(2),b(3),b(4),b(5),b(6),bytes(AugSchemeMPL.key_gen(b'k'*32).get_g1()),frozenset([b(7)]),b(8),10**12,1,1000,2000)

def write_policy(tmp_path,document):
 p=tmp_path/'policy.json';p.write_text(json.dumps(document,sort_keys=True));return p,'0x'+sha256(p.read_bytes()).hexdigest()

def test_exact_public_policy_roundtrips_and_mismatch_cannot_enable_it(tmp_path):
 p,pin=write_policy(tmp_path,policy().public())
 assert read_current_issuer_policy(p,pin)==policy()
 with pytest.raises(ValueError,match='FILE_CHANGED'):read_current_issuer_policy(p,'0x'+'00'*32)

@pytest.mark.parametrize('change',[{'network':'mainnet'},{'masterKeyExportAuthorized':True},{'technologyFeeBps':200},
 {'maximumGrossMojos':'000123'},{'deedLauncherIds':['0x'+'07'*32,'0x'+'07'*32]},{'scope':'WALLET_WITHDRAWAL'},{'issuerPrivateKey':'secret'}])
def test_policy_does_not_admit_broader_key_or_money_scope(tmp_path,change):
 p,pin=write_policy(tmp_path,{**policy().public(),**change})
 with pytest.raises(ValueError):read_current_issuer_policy(p,pin)

@pytest.mark.parametrize('route',['reservation','delivery'])
def test_identity_opt_in_alone_never_opens_purchase_signing(tmp_path,route):
 settings=_settings(tmp_path).model_copy(update={'generation_customer_identity_enabled':True})
 app=create_validator_app(settings=settings)
 c=TestClient(app)
 payload=body()if route=='reservation'else{'reservation':body(),'reservedCoinId':'0x'+'09'*32,'buyerOffer':'offer1'+'x'*16}
 # No lifespan: this tests only private ASGI routing, with no seed loading.
 response=c.post('/v1/generation/purchase/'+route+'/sign',json={'claim':payload,'claimHash':'0x'+'08'*32})
 assert response.status_code==404



def test_public_get_cannot_enter_private_signature_actions(tmp_path):
 settings=_settings(tmp_path).model_copy(update={'generation_customer_identity_enabled':True,'generation_customer_purchase_enabled':True})
 app=create_validator_app(settings=settings);c=TestClient(app)
 assert c.get('/v1/generation/purchase/reservation/sign').status_code==404
 assert c.post('/v1/inventory-reservation/sign',json={}).status_code==404


def test_private_rejection_hides_provider_and_proof_details(tmp_path,monkeypatch):
 from solslot_api import generation_customer_purchase_policy as policies,generation_customer_purchase_validators as signing,generation_index
 settings=_settings(tmp_path).model_copy(update={'generation_customer_identity_enabled':True,'generation_customer_purchase_enabled':True})
 app=create_validator_app(settings=settings);app.state.generation_provider=object();app.state.validator_ledger=ValidatorLedger(':memory:')
 monkeypatch.setattr(policies,'selected_purchase_policy',lambda s:policy())
 monkeypatch.setattr(generation_index,'load_generation_read_anchor',lambda s:object())
 async def rejected(*args,**kwargs):raise ValueError('private-proof-or-provider-payload-never-public')
 monkeypatch.setattr(signing,'sign_current_reservation',rejected)
 try:
  r=TestClient(app).post('/v1/generation/purchase/reservation/sign',json={'claim':body(),'claimHash':'0x'+'08'*32})
  assert r.status_code==409 and 'private-proof'not in r.text
  assert r.json()['detail']=='CURRENT_PURCHASE_INDEPENDENT_EVIDENCE_REJECTED'
 finally:app.state.validator_ledger.close()


@pytest.mark.parametrize('change',[{'reservedCoinId':'0x'+'AA'*32},{'buyerOffer':'x'*2_000_001},
 {'coinSpends':[]},{'ownerPrivateKey':'synthetic-forbidden'},{'network':'mainnet'}])
def test_delivery_payload_cannot_supply_unbounded_or_legacy_authority(change):
 from pydantic import ValidationError
 raw={'reservation':body(),'reservedCoinId':'0x'+'09'*32,'buyerOffer':'offer1'+'x'*16}
 with pytest.raises(ValidationError):CurrentDeliveryClaim.model_validate({**raw,**change})
