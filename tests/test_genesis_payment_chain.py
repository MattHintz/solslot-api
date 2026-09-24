"""Existing enrolled administrators can approve an explicit payment domain."""
from tests.test_genesis_api import _client, _create_and_enroll, _plan_body, _headers, _signature


def test_mainnet_payment_plan_preserves_enrollment_and_identity_domain(tmp_path):
    client, store, settings = _client(tmp_path)
    ceremony_id, accounts = _create_and_enroll(client, store)
    before = store.get(ceremony_id)
    settings.payment_omnichain_chain_id = 8453
    body = {**_plan_body(), 'paymentChainId': 8453}
    response = client.post(f'/admin/genesis/{ceremony_id}/plan', json=body, headers=_headers())
    assert response.status_code == 200, response.text
    typed = response.json()['typedData']
    assert typed['domain']['chainId'] == 11155111
    current = store.get(ceremony_id)
    assert current['plan']['paymentChainId'] == 8453
    assert current['plan']['evmChainId'] == 11155111
    assert current['invitations'] == before['invitations']
    for slot, account in enumerate(accounts[:2], start=1):
        response = client.post(f'/admin/genesis/{ceremony_id}/plan/signatures',
                               json={'slot':slot, 'signature':_signature(account, typed)})
        assert response.status_code == 200, response.text
    assert store.get(ceremony_id)['state'] == 'plan_approved'


def test_plan_payment_chain_must_match_operator_configuration(tmp_path):
    client, store, _ = _client(tmp_path)
    ceremony_id, _ = _create_and_enroll(client, store)
    response = client.post(f'/admin/genesis/{ceremony_id}/plan',
         json={**_plan_body(), 'paymentChainId':8453}, headers=_headers())
    assert response.status_code == 400, response.text
    assert 'configured payment network' in response.text
    assert store.get(ceremony_id)['state'] == 'roster_frozen'
