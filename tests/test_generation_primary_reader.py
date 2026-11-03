"""Private read transport boundaries; no real credential or cloud calls."""
import json
from types import SimpleNamespace

import httpx
import pytest

from solslot_api.generation_primary_reader import (
    PRIMARY_READER_URL, PrimaryReadClient, ReadOnlyChiaProvider,
    checked_read, decode_request, private_primary_reader)
from solslot_api.generation_primary_reader_app import create_primary_reader_app
from solslot_api.chia_provider import ChiaProviderConfig, ChiaProviderError


class Primary:
    def __init__(self): self.calls = []; self.fail = False
    async def _post(self, method, body):
        self.calls.append((method, body))
        if self.fail: raise RuntimeError('provider-private-value-must-not-leak')
        return {'success': True, 'coin_record': {'confirmed_block_index': 100}}


class Node:
    def __init__(self): self.primary = Primary(); self.started = self.closed = False
    async def start(self): self.started = True
    async def close(self): self.closed = True
    async def get_network_info_primary(self): return {'network_name': 'testnet11'}
    async def get_blockchain_state_primary(self):
        return {'blockchain_state': {'sync': {'synced': True}, 'peak': {'height': 100}}}


@pytest.mark.asyncio
@pytest.mark.parametrize('peer', ['10.77.0.10', '10.77.0.11', '10.77.0.12'])
async def test_reader_returns_exact_primary_response_without_reinterpreting_it(peer):
    node = Node(); app = create_primary_reader_app(provider=node)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 1234)), base_url='https://node') as client:
            body = {'name': '0x' + '11' * 32}
            response = await client.post('/v1/generation/chain/get_coin_record_by_name', json=body)
            assert response.status_code == 200 and response.json()['coin_record']['confirmed_block_index'] == 100
            assert node.primary.calls == [('/get_coin_record_by_name', body)]
            assert response.headers['cache-control'] == 'no-store'
            assert (await client.get('/health')).json()['readOnly'] is True
    assert node.started and node.closed


@pytest.mark.asyncio
@pytest.mark.parametrize('peer', ['10.77.0.2', '10.77.0.1', '127.0.0.1', '192.0.2.1'])
async def test_coordinator_and_other_hosts_cannot_use_peer_reader(peer):
    node = Node(); app = create_primary_reader_app(provider=node)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 1)), base_url='https://node') as client:
        response = await client.post('/v1/generation/chain/get_network_info', json={})
        assert response.status_code == 403 and not node.primary.calls


@pytest.mark.asyncio
@pytest.mark.parametrize('method,body', [
    ('push_tx', {'spend_bundle': {}}), ('stop_node', {}), ('get_private_key', {}),
    ('get_connections', {}), ('get_coin_records_by_puzzle_hash', {'puzzle_hash': '0x' + '11' * 32}),
    ('get_network_info', {'url': 'https://arbitrary.invalid'}),
    ('get_coin_record_by_name', {'name': '0x' + '11' * 32, 'include_spent': True}),
    ('get_puzzle_and_solution', {'coin_id': '0x' + '11' * 32, 'height': True}),
    ('get_puzzle_and_solution', {'coin_id': '0x' + '11' * 32, 'height': 1.0}),
    ('get_puzzle_and_solution', {'coin_id': '0x' + '11' * 32, 'height': '1'}),
    ('get_coin_record_by_name', {'name': 'http://localhost/secret'}),
    ('get_coin_record_by_name', {'name': '0x' + 'AA' * 32})])
async def test_method_and_parameter_allowlist_rejects_before_node_io(method, body):
    node = Node(); app = create_primary_reader_app(provider=node)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('10.77.0.11', 1)), base_url='https://node') as client:
        response = await client.post('/v1/generation/chain/' + method, json=body)
        assert response.status_code == 400 and not node.primary.calls


@pytest.mark.asyncio
@pytest.mark.parametrize('raw', [b'{', b'[]', b'{"name":"first","name":"second"}', b' ' * 513])
async def test_malformed_ambiguous_or_large_requests_are_bounded(raw):
    node = Node(); app = create_primary_reader_app(provider=node)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('10.77.0.11', 1)), base_url='https://node') as client:
        response = await client.post('/v1/generation/chain/get_coin_record_by_name', content=raw)
        assert response.status_code == 400 and not node.primary.calls


@pytest.mark.asyncio
async def test_native_failure_is_actionable_without_raw_provider_error():
    node = Node(); node.primary.fail = True
    app = create_primary_reader_app(provider=node)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('10.77.0.11', 1)), base_url='https://node') as client:
        response = await client.post('/v1/generation/chain/get_network_info', json={})
        assert response.status_code == 503
        assert response.json()['detail'] == 'PRIVATE_PRIMARY_NODE_UNAVAILABLE'
        assert 'private-value' not in response.text


@pytest.mark.asyncio
async def test_primary_client_passes_reader_route_and_never_arbitrary_method():
    calls = []
    def handle(request):
        calls.append((str(request.url), json.loads(request.content)))
        return httpx.Response(200, json={'success': True, 'coin_record': None})
    client = PrimaryReadClient(PRIMARY_READER_URL)
    await client._client.aclose()
    client._client = httpx.AsyncClient(base_url=PRIMARY_READER_URL, transport=httpx.MockTransport(handle))
    try:
        assert await client.get_coin_record_by_name('11' * 32) is None
        assert calls[0] == (PRIMARY_READER_URL + '/get_coin_record_by_name', {'name': '0x' + '11' * 32})
        with pytest.raises(ValueError): await client.push_tx({})
        assert len(calls) == 1
    finally: await client.close()


@pytest.mark.asyncio
async def test_readonly_provider_has_no_broadcast_or_fallback_path():
    class NoIO:
        def __getattr__(self, _): raise AssertionError('broadcast must fail before I/O')
    provider = ReadOnlyChiaProvider(NoIO(), NoIO(), ChiaProviderConfig(
        network='testnet11', primary_url=PRIMARY_READER_URL, fallback_url=PRIMARY_READER_URL))
    for fn in (provider.push_tx, provider.push_tx_confirmed_in_primary_mempool):
        with pytest.raises(ChiaProviderError, match='CANNOT_BROADCAST'): await fn({})


@pytest.mark.parametrize('changes', [
    {'network': 'mainnet'}, {'generation_primary_url': 'https://10.77.0.2:9543/v1/generation/chain'},
    {'generation_primary_ca_cert_path': None}, {'generation_primary_client_key_path': '/key'},
    {'generation_primary_client_cert_path': '/cert'}])
def test_primary_reader_requires_exact_tls_server_and_no_replicated_client_key(changes):
    data = dict(network='testnet11', generation_primary_url=PRIMARY_READER_URL,
        generation_primary_ca_cert_path='/ca', generation_primary_client_key_path=None,
        generation_primary_client_cert_path=None)
    with pytest.raises(ValueError): private_primary_reader(SimpleNamespace(**{**data, **changes}))


def test_server_certificate_hostname_validation_is_not_disabled(monkeypatch):
    class Context: check_hostname = True; verify_mode = 2
    context = Context(); calls = []
    import solslot_api.generation_primary_reader as module
    monkeypatch.setattr(module.ssl, 'create_default_context', lambda *, cafile: calls.append(cafile) or context)
    monkeypatch.setattr(module, 'PrimaryReadClient', lambda *a, **kw: SimpleNamespace(context=kw['ssl_context']))
    p = private_primary_reader(SimpleNamespace(network='testnet11', generation_primary_url=PRIMARY_READER_URL,
        generation_primary_ca_cert_path='/ca', generation_primary_client_key_path=None,
        generation_primary_client_cert_path=None))
    assert calls == ['/ca'] and p.primary.context.check_hostname is True and p.primary.context.verify_mode == 2


@pytest.mark.asyncio
async def test_current_signer_cannot_expose_legacy_signing_routes_without_reading_key():
    from solslot_api.validator_app import create_validator_app
    app = create_validator_app(settings=SimpleNamespace(generation_customer_identity_enabled=True))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://signer') as client:
        for path in ('/v1/zkpassport/sign', '/v1/generation/primary-sols/sign', '/docs', '/openapi.json'):
            response = await client.post(path, json={})
            assert response.status_code == 404 and response.json()['detail'] == 'CURRENT_SIGNER_ACTION_DISABLED'


@pytest.mark.parametrize('endpoint', [
    'https://10.77.0.10:9543/v1/generation/chain',
    'https://10.77.0.10:19543/v1/generation/chain',
    'https://10.77.0.11:19544/v1/generation/chain',
    'http://10.77.0.10:19544/v1/generation/chain',
])
def test_retired_conflicting_or_unbound_reader_endpoint_is_rejected(endpoint):
    settings=SimpleNamespace(network='testnet11',generation_primary_url=endpoint,
        generation_primary_ca_cert_path='/ca',generation_primary_client_key_path=None,
        generation_primary_client_cert_path=None)
    with pytest.raises(ValueError,match='EXACT_PRIVATE'):private_primary_reader(settings)


def test_dedicated_reader_endpoint_is_exact_and_stays_private():
    assert PRIMARY_READER_URL=='https://10.77.0.10:19544/v1/generation/chain'
