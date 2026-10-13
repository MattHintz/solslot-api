import time
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import HTTPException, Request

from solslot_api.config import Settings
from solslot_api.credential_auth import (credential_typed_data, credential_bls_signing_digest,
    issue_vault_session, verify_vault_session, VerifiedOwner, VAULT_SESSION_COOKIE)
from solslot_api.credential_ledger import OwnerChallenge
from solslot_api.launch_control import _issue_session, _decode_session, _resume_typed_data, _action_typed_data
from tests.test_credential_ledger import _record, VAULT

GEN = '0x' + 'ab'*32
OTHER = '0x' + 'cd'*32


def config(generation):
    return Settings(runtime_environment='test', deployment_generation_id=generation)


def test_bls_and_evm_credential_signatures_cannot_cross_generations():
    c = OwnerChallenge('fixture', VAULT, 'session_login', '0x'+'33'*32, '0x'+'44'*32, 'evm', int(time.time())+300)
    account = Account.create()
    typed = credential_typed_data(config(GEN), c)
    sig = account.sign_message(encode_typed_data(full_message=typed)).signature
    sk = AugSchemeMPL.key_gen(b'fixture-only-generation-auth-key!')
    bls = AugSchemeMPL.sign(sk, credential_bls_signing_digest(config(GEN), c))
    for gen in [GEN, OTHER, None]:
        recovered = Account.recover_message(encode_typed_data(full_message=credential_typed_data(config(gen), c)), signature=sig)
        assert (recovered == account.address) == (gen == GEN)
        assert AugSchemeMPL.verify(sk.get_g1(), credential_bls_signing_digest(config(gen), c), bls) == (gen == GEN)


def test_existing_customer_cookie_is_rejected_before_loading_vault_from_another_generation(monkeypatch):
    account = Account.create()
    record = _record(owner_pubkey=b'fixture', auth_type=3, evm_address=account.address)
    owner = VerifiedOwner(account.address.lower(), 'evm', record)
    token, public = issue_vault_session(config(GEN), owner)
    assert public.generationId == GEN
    request = Request({'type': 'http', 'headers': [(b'cookie', f'{VAULT_SESSION_COOKIE}={token}'.encode())]})
    reads = []
    def load(vault): reads.append(vault); return record
    monkeypatch.setattr('solslot_api.credential_auth.require_vault_record', load)
    for gen in [None, OTHER]:
        with pytest.raises(HTTPException) as err:
            verify_vault_session(config(gen), request, VAULT)
        assert err.value.status_code == 403
    assert reads == []
    assert verify_vault_session(config(GEN), request, VAULT).owner_key == owner.owner_key


def test_launch_session_and_review_signatures_are_generation_bound():
    settings = config(GEN)
    account = Account.create()
    token, _ = _issue_session(settings, ceremony_id='0x'+'12'*32, slot=1, wallet=account.address, setup=False)
    assert _decode_session(token, settings).generation_id == GEN
    for gen in [None, OTHER]:
        with pytest.raises(HTTPException, match='another deployment'):
            _decode_session(token, config(gen))
    for builder, fields in [
        (_resume_typed_data, dict(slot=1, wallet=account.address, nonce='0x'+'34'*32)),
        (_action_typed_data, dict(action_type='publication', action_id='0x'+'34'*32, payload_hash='0x'+'56'*32)),
    ]:
        args = dict(ceremony_id='0x'+'12'*32, expires_at=int(time.time())+300, **fields)
        sig = account.sign_message(encode_typed_data(full_message=builder(**args, generation_id=GEN))).signature
        for gen in [GEN, OTHER, None]:
            who = Account.recover_message(encode_typed_data(full_message=builder(**args, generation_id=gen)), signature=sig)
            assert (who == account.address) == (gen == GEN)


@pytest.mark.parametrize('kind', ['enrollment', 'plan'])
def test_genesis_ceremony_signatures_are_generation_bound(kind):
    from solslot_puzzles.genesis_signing import genesis_admin_enrollment_typed_data, genesis_plan_signing_typed_data
    account=Account.create()
    common=dict(ceremony_id='0x'+'11'*32, expires_at=int(time.time())+86400)
    if kind=='enrollment':
        builder=genesis_admin_enrollment_typed_data
        common.update(slot=1,wallet=account.address,nonce='0x'+'22'*32)
    else:
        builder=genesis_plan_signing_typed_data
        common.update(roster_hash='0x'+'22'*32,plan_hash='0x'+'33'*32)
    typed=builder(**common,generation_id=GEN)
    signature=account.sign_message(encode_typed_data(full_message=typed)).signature
    for generation in (GEN,OTHER,None):
        recovered=Account.recover_message(encode_typed_data(full_message=builder(**common,generation_id=generation)),signature=signature)
        assert (recovered==account.address)==(generation==GEN)
    for invalid in ('0x'+'00'*32,'broken'):
        with pytest.raises(ValueError):builder(**common,generation_id=invalid)
    assert 'salt' not in builder(**common)['domain']
    assert len(builder(**common)['types']['EIP712Domain'])==3


def test_generation_ceremony_namespace_supplies_the_signed_domain(tmp_path):
    from solslot_api.genesis_store import GenesisStore, GenesisConflict
    from solslot_api.genesis import _invitation_typed_data, _plan_typed_data, _token_hash
    from solslot_api.launch_control import _ceremony_binding
    ceremony='0x'+'11'*32
    store=GenesisStore(tmp_path/'ceremony.db',generation_id=GEN)
    raw={'evmChainId':84532,'network':'testnet11'}
    record=store.create_draft(ceremony,raw)
    assert 'generationId' not in raw
    assert record['draft']['generationId']==GEN
    assert _ceremony_binding(record)['generationId']==GEN
    store.issue_invitation(ceremony,slot=1,token_hash=_token_hash('fixture-invitation'),nonce='0x'+'22'*32,expires_at=int(time.time())+3600)
    _,enrollment=_invitation_typed_data(store,'fixture-invitation',Account.create().address)
    assert enrollment['domain']['salt']==GEN
    record.update(roster_hash='0x'+'33'*32,plan_hash='0x'+'44'*32,plan_expires_at=int(time.time())+86400)
    assert _plan_typed_data(record)['domain']['salt']==GEN
    with pytest.raises(GenesisConflict,match='another deployment'):
        store.create_draft('0x'+'55'*32,{**raw,'generationId':OTHER})
    with pytest.raises(GenesisConflict,match='another deployment'):
        GenesisStore(tmp_path/'legacy.db').create_draft(ceremony,{**raw,'generationId':GEN})
    with store._connect() as con:
        con.execute("UPDATE ceremonies SET draft_json=? WHERE ceremony_id=?", ('{}',ceremony))
    with pytest.raises(GenesisConflict,match='another deployment'):store.get(ceremony)
