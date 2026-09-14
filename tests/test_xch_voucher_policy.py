"""New-sale policy boundaries; no provider, customer signature or chain use."""
from types import SimpleNamespace
import time

import pytest
from fastapi import HTTPException

from solslot_api import presale_endpoints as presale
from solslot_api.config import Settings


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['prepare_native_voucher', 'complete_native_voucher'])
async def test_native_initial_calls_stop_before_quote_or_wallet_work(monkeypatch, name):
    def forbidden(**kwargs):
        pytest.fail('disabled XCH reached quote/wallet work')
    monkeypatch.setattr(presale, '_load_native_voucher_context', forbidden)
    monkeypatch.setattr(presale, 'require_presale_writes', lambda _: None)
    monkeypatch.setattr(presale, 'require_operation_gate', lambda *_: None)
    with pytest.raises(HTTPException) as caught:
        await getattr(presale, name)('0x'+'11'*32, SimpleNamespace(), SimpleNamespace(),
                                    Settings(_env_file=None), SimpleNamespace(), None)
    assert caught.value.status_code == 503
    assert 'XCH voucher purchases are off' in caught.value.detail


def test_default_and_operator_setting_cannot_override_unready_release():
    from solslot_api.voucher_rail_policy import require_xch_voucher_sales, xch_voucher_control
    settings=Settings(_env_file=None)
    assert settings.presale_xch_enabled is False
    assert xch_voucher_control(settings)['defaultEnabled'] is False
    settings.presale_xch_enabled=True
    settings.presale_enabled=True
    settings.alpha_writes_enabled=True
    settings.collection_minting_enabled=True
    settings.launch_control_enabled=True
    with pytest.raises(HTTPException):require_xch_voucher_sales(settings)
    assert not xch_voucher_control(settings)['canOpen']
    assert not xch_voucher_control(settings)['releaseReady']


def test_isolated_signer_refuses_new_native_voucher_before_rpc_or_key(monkeypatch):
    from solslot_api import validator_service as validator
    from solslot_api.validator_quorum import VoucherIssuanceClaim
    from solslot_puzzles.payment_artifacts_v2 import purchase_artifact_to_json
    from tests.test_presale_endpoints import native_escrowed_voucher, hex32
    from tests.test_validator_service import _settings
    now=int(time.time())
    store, terms, _, issuance, commitment, purchase=native_escrowed_voucher(now=now)
    claim=VoucherIssuanceClaim(network='testnet11',genesis_artifact_hash=hex32(21),
        series_terms=terms,voucher_commitment=presale._voucher_commitment_json(commitment),
        purchase_artifact=purchase_artifact_to_json(purchase),series_coin_id=hex32(issuance.series_spend.coin.name()),
        series_sold_count=0,series_redeemed_count=0,series_refunded_count=0,series_phase=1,
        series_launched_at=0,purchase_launcher_coin_id=hex32(issuance.purchase_launcher_spend.coin.name()),
        payment_evidence={},validator_message=hex32(issuance.validator_message))
    monkeypatch.setattr(validator,'load_validator_artifact',lambda _:({'artifactHash':hex32(21)},{}))
    monkeypatch.setattr(validator,'_fetch_coin',lambda *_:pytest.fail('disabled issuer reached RPC'))
    monkeypatch.setattr(validator,'load_validator_private_key',lambda *_:pytest.fail('disabled issuer read a key'))
    with pytest.raises(validator.ValidatorEvidenceError,match='voucher issuance commitments are invalid'):
        validator.sign_voucher_issuance_claim(_settings(),SimpleNamespace(),claim,claim.canonical_hash())
    # This flag is scoped to issuance: no existing record was erased or rewritten.
    assert store.voucher(terms['termsHash'],0)['state']=='ESCROWED'


def test_admin_cannot_propose_or_activate_unready_xch_window(tmp_path):
    from tests.test_launch_control import _client,_claim_and_enroll_owner
    client,store,settings=_client(tmp_path)
    _claim_and_enroll_owner(client)
    response=client.post('/admin/launch/gates/propose',json={'gate':'xchVouchers','durationSeconds':1800})
    assert response.status_code==409,response.text
    assert 'XCH voucher purchases are off' in response.json()['detail']
    response=client.post('/admin/launch/gates/xchVouchers/activate')
    assert response.status_code==409,response.text
    assert 'XCH voucher purchases are off' in response.json()['detail']
    assert all('xchVouchers' not in store.gates(row['ceremony_id']) for row in store.list_ceremonies())


def test_admin_off_is_authenticated_and_invalidates_previous_gate(tmp_path):
    from tests.test_launch_control import _client,_claim_and_enroll_owner
    client,store,settings=_client(tmp_path)
    assert client.post('/admin/launch/gates/xchVouchers/close').status_code==401
    _claim_and_enroll_owner(client)
    row=store.list_ceremonies()[0];cid=row['ceremony_id'];now=int(time.time())
    old='0x'+'31'*32
    store.upsert_gate(cid,gate_name='xchVouchers',opens_at=now,closes_at=now+1800,payload_hash=old,state='pending')
    response=client.post('/admin/launch/gates/xchVouchers/close')
    assert response.status_code==200,response.text
    closed=store.gates(cid)['xchVouchers']
    assert closed['state']=='closed' and closed['payloadHash']!=old
    with pytest.raises(Exception,match='closed'):
        store.authorized_gate(settings,cid,'xchVouchers')
