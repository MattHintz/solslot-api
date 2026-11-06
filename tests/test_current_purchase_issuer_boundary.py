from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
import json
import pytest
from chia_rs import AugSchemeMPL
from fastapi.testclient import TestClient
from solslot_api.generation_customer_issuer import TestnetIssuerJournal as IssuerJournal
from solslot_api.generation_customer_purchase_issuer import CurrentIssuerRequest,load_fixed_issuer_key
from solslot_api.validator_app import create_validator_app
from solslot_api.validator_ledger import ValidatorLedger
from tests.test_current_purchase_private_boundary import policy
from tests.test_generation_customer_purchase_reservation_claim import body
from tests.test_validator_app import _settings


def request():
 p=policy()
 return {'generationId':'0x'+p.generation.hex(),'policyHash':p.commitment,
  'claim':{'reservation':body(),'reservedCoinId':'0x'+'09'*32,'buyerOffer':'offer1'+'x'*16},
  'claimHash':'0x'+'08'*32,'purchaseBundle':{},'issuerCoinSpend':{},
  'issuerPublicKey':'0x'+p.issuer_public_key.hex(),'message':'0x'+'01'*96}


def test_issuer_uses_the_existing_recovered_journal_without_rebinding_or_resetting_it(tmp_path):
 ledger=ValidatorLedger(tmp_path/'existing-signer.db');version=ledger._conn.execute('PRAGMA user_version').fetchone()[0]
 guard=IssuerJournal.in_validator_journal(ledger,policy())
 assert guard.path==ledger.path and guard.db is ledger._conn and guard._lock is ledger._lock
 assert ledger._conn.execute('PRAGMA user_version').fetchone()[0]==version
 assert ledger._conn.execute("SELECT 1 FROM sqlite_master WHERE name='deployment_generation_binding'").fetchone()is None
 guard.close();assert ledger.healthcheck()
 with pytest.raises(ValueError,match='POLICY_CHANGED'):IssuerJournal.in_validator_journal(ledger,replace(policy(),expires_at=2001))
 assert ledger.healthcheck();ledger.close()


def test_fixed_issuer_key_protection_and_public_match_do_not_export_it(tmp_path):
 key=AugSchemeMPL.key_gen(b'synthetic-test-key-not-a-customer'*2)
 p=tmp_path/'fixed-issuer';p.write_text(bytes(key).hex());p.chmod(0o600)
 settings=SimpleNamespace(generation_customer_purchase_issuer_key_path=str(p))
 assert load_fixed_issuer_key(settings).get_g1()==key.get_g1()
 p.chmod(0o644)
 with pytest.raises(ValueError,match='PROTECTED'):load_fixed_issuer_key(settings)
 p.chmod(0o600);link=tmp_path/'link';link.symlink_to(p)
 with pytest.raises(ValueError,match='PROTECTED'):load_fixed_issuer_key(SimpleNamespace(generation_customer_purchase_issuer_key_path=str(link)))


@pytest.mark.parametrize('patch',[{'privateKey':'forbidden'},{'message':'arbitrary text'},{'issuerPublicKey':'0x'+'00'*20}])
def test_issuer_request_cannot_choose_a_private_key_or_untyped_message(patch):
 from pydantic import ValidationError
 with pytest.raises(ValidationError):CurrentIssuerRequest.model_validate({**request(),**patch})


@pytest.mark.parametrize('enabled,index',[(False,2),(True,0)])
def test_private_issuer_is_default_closed_and_cannot_run_on_another_signer(tmp_path,enabled,index):
 settings=_settings(tmp_path).model_copy(update={'generation_customer_identity_enabled':True,
  'generation_customer_purchase_enabled':True,'generation_customer_purchase_issuer_enabled':enabled,'signer_index':index})
 app=create_validator_app(settings=settings);client=TestClient(app)
 assert client.post('/v1/generation/purchase/issuer/sign',json=request()).status_code==404
 assert client.get('/v1/generation/purchase/issuer/status').status_code==404


def test_private_issuer_rejection_does_not_expose_proofs_or_credentials(tmp_path,monkeypatch):
 from solslot_api import generation_customer_purchase_issuer as issuer,generation_index
 settings=_settings(tmp_path).model_copy(update={'generation_customer_identity_enabled':True,'signer_index':2,
  'generation_customer_purchase_enabled':True,'generation_customer_purchase_issuer_enabled':True})
 app=create_validator_app(settings=settings);ledger=ValidatorLedger(tmp_path/'signer.db')
 app.state.current_issuer=object();app.state.generation_provider=object();app.state.validator_ledger=ledger
 monkeypatch.setattr(generation_index,'load_generation_read_anchor',lambda *_:object())
 async def reject(*a,**kw):raise ValueError('synthetic-private-provider-or-key-detail')
 monkeypatch.setattr(issuer,'sign_current_issuer',reject)
 try:
  response=TestClient(app).post('/v1/generation/purchase/issuer/sign',json=request())
  assert response.status_code==409 and 'synthetic-private'not in response.text
 finally:ledger.close()
